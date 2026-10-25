//! Async counterparts of the device-class traits.
//!
//! [`AsyncBlockDevice`], [`AsyncSerialPort`] and [`AsyncNetDevice`] mirror
//! [`BlockDevice`], [`SerialPort`] and [`NetDevice`], but their operations
//! return futures, so a task on an executor such as `osmium-exec`'s can wait
//! for a device without spinning. Nothing here depends on an executor: the
//! futures use only [`core::task`], and a driver that completes from an
//! interrupt stores the task's waker (an `osmium_exec::AtomicWaker`, say)
//! and wakes it from the handler.
//!
//! The traits are not `Send`-bounded: the target executors are single-core or
//! pin tasks to a CPU, and requiring `Send` would forbid futures that hold
//! device registers.
//!
//! Two adapters turn the blocking traits into async ones without driver
//! changes:
//!
//! - [`Blocking`] runs each operation to completion inside one poll. Right
//!   for devices whose blocking calls already finish quickly (RAM disks,
//!   polled virtio queues).
//! - [`Polled`] retries operations that report "not ready" (`None` from
//!   [`SerialPort::read_byte`], [`NetError::WouldBlock`]) once per executor
//!   pass, yielding in between. It burns CPU while waiting but lets other
//!   tasks run.
//!
//! [`BlockDevice`]: crate::block::BlockDevice
//! [`SerialPort`]: crate::serial::SerialPort
//! [`NetDevice`]: crate::net::NetDevice

use crate::block::{BlockDevice, BlockError};
use crate::net::{MacAddress, NetDevice, NetError};
use crate::serial::SerialPort;
use core::future::poll_fn;
use core::task::Poll;

/// Async [`BlockDevice`].
#[allow(async_fn_in_trait)] // Deliberately not `Send`-bounded; see the module docs.
pub trait AsyncBlockDevice {
    /// Bytes per block.
    fn block_size(&self) -> usize;

    /// Number of blocks.
    fn num_blocks(&self) -> u64;

    /// Reads `buf.len() / block_size()` blocks starting at `lba`.
    async fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError>;

    /// Writes `buf.len() / block_size()` blocks starting at `lba`.
    async fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError>;

    /// Makes previous writes durable.
    async fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }
}

/// Async [`SerialPort`].
#[allow(async_fn_in_trait)] // Deliberately not `Send`-bounded; see the module docs.
pub trait AsyncSerialPort {
    /// Writes one byte, waiting for room in the transmitter.
    async fn write_byte(&mut self, byte: u8);

    /// Waits for and reads one byte.
    async fn read_byte(&mut self) -> u8;

    /// Writes all of `bytes`.
    async fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b).await;
        }
    }
}

/// Async [`NetDevice`].
#[allow(async_fn_in_trait)] // Deliberately not `Send`-bounded; see the module docs.
pub trait AsyncNetDevice {
    /// The interface's MAC address.
    fn mac_address(&self) -> MacAddress;

    /// Largest frame in bytes, including the 14-byte Ethernet header.
    fn max_frame_len(&self) -> usize {
        1514
    }

    /// Waits for room in the transmit queue and queues `frame`. Errors other
    /// than [`NetError::WouldBlock`] (which is awaited out) are returned.
    async fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError>;

    /// Waits for a frame, copies it into `buf` and returns its length.
    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError>;
}

/// Runs a blocking device to completion inside each call; see the
/// [module docs](self).
#[derive(Debug, Default)]
pub struct Blocking<T>(pub T);

impl<T: BlockDevice> AsyncBlockDevice for Blocking<T> {
    fn block_size(&self) -> usize {
        self.0.block_size()
    }

    fn num_blocks(&self) -> u64 {
        self.0.num_blocks()
    }

    async fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.0.read_blocks(lba, buf)
    }

    async fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.0.write_blocks(lba, buf)
    }

    async fn flush(&mut self) -> Result<(), BlockError> {
        self.0.flush()
    }
}

/// Retries a blocking device's "not ready" results once per executor pass;
/// see the [module docs](self).
#[derive(Debug, Default)]
pub struct Polled<T>(pub T);

/// Calls `attempt` until it returns `Some`, yielding to the executor between
/// tries (the task wakes itself, so it runs again on the next pass).
async fn until_ready<R>(mut attempt: impl FnMut() -> Option<R>) -> R {
    poll_fn(|cx| match attempt() {
        Some(r) => Poll::Ready(r),
        None => {
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}

impl<T: SerialPort> AsyncSerialPort for Polled<T> {
    async fn write_byte(&mut self, byte: u8) {
        // `SerialPort::write_byte` already waits for room.
        self.0.write_byte(byte);
    }

    async fn read_byte(&mut self) -> u8 {
        until_ready(|| self.0.read_byte()).await
    }
}

impl<T: NetDevice> AsyncNetDevice for Polled<T> {
    fn mac_address(&self) -> MacAddress {
        self.0.mac_address()
    }

    fn max_frame_len(&self) -> usize {
        self.0.max_frame_len()
    }

    async fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        until_ready(|| match self.0.transmit(frame) {
            Err(NetError::WouldBlock) => None,
            other => Some(other),
        })
        .await
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        until_ready(|| match self.0.receive(buf) {
            Err(NetError::WouldBlock) => None,
            other => Some(other),
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Waker};
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// Polls `fut` to completion, counting how many times it returned pending.
    fn block_on<F: Future>(fut: F) -> (F::Output, usize) {
        let mut fut = pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        let mut pending = 0;
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return (v, pending),
                Poll::Pending => pending += 1,
            }
            assert!(pending < 1000, "future never completed");
        }
    }

    struct Ram(Vec<u8>);

    impl BlockDevice for Ram {
        fn block_size(&self) -> usize {
            4
        }
        fn num_blocks(&self) -> u64 {
            (self.0.len() / 4) as u64
        }
        fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            let n = self.check_range(lba, buf.len())? as usize;
            let start = lba as usize * 4;
            buf.copy_from_slice(self.0.get(start..start + n * 4).ok_or(BlockError::Io)?);
            Ok(())
        }
        fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
            let n = self.check_range(lba, buf.len())? as usize;
            let start = lba as usize * 4;
            self.0.get_mut(start..start + n * 4).ok_or(BlockError::Io)?.copy_from_slice(buf);
            Ok(())
        }
    }

    #[test]
    fn blocking_adapter_completes_in_one_poll() {
        let mut d = Blocking(Ram(std::vec![0; 16]));
        let (r, pending) = block_on(async {
            d.write_blocks(1, &[1, 2, 3, 4]).await?;
            let mut b = [0; 8];
            d.read_blocks(0, &mut b).await?;
            d.flush().await?;
            Ok::<_, BlockError>(b)
        });
        assert_eq!((r, pending), (Ok([0, 0, 0, 0, 1, 2, 3, 4]), 0));
        assert_eq!(d.num_blocks(), 4);
        assert_eq!(block_on(d.read_blocks(4, &mut [0; 4])).0, Err(BlockError::OutOfRange));
    }

    /// A UART that has data only after `delay` empty polls.
    struct Uart {
        delay: usize,
        rx: VecDeque<u8>,
        tx: Vec<u8>,
    }

    impl SerialPort for Uart {
        fn write_byte(&mut self, byte: u8) {
            self.tx.push(byte);
        }
        fn read_byte(&mut self) -> Option<u8> {
            if self.delay > 0 {
                self.delay -= 1;
                return None;
            }
            self.rx.pop_front()
        }
    }

    #[test]
    fn polled_serial_yields_until_a_byte_arrives() {
        let mut u = Polled(Uart { delay: 3, rx: VecDeque::from(*b"x"), tx: Vec::new() });
        let (b, pending) = block_on(u.read_byte());
        assert_eq!((b, pending), (b'x', 3));
        let ((), pending) = block_on(u.write_bytes(b"hi"));
        assert_eq!((u.0.tx.as_slice(), pending), (&b"hi"[..], 0));
    }

    struct Nic {
        full_for: usize,
        rx_after: usize,
        sent: Vec<Vec<u8>>,
    }

    impl NetDevice for Nic {
        fn mac_address(&self) -> MacAddress {
            MacAddress([2, 0, 0, 0, 0, 1])
        }
        fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
            if self.full_for > 0 {
                self.full_for -= 1;
                return Err(NetError::WouldBlock);
            }
            if frame.len() > 1514 {
                return Err(NetError::TooLarge);
            }
            self.sent.push(frame.to_vec());
            Ok(())
        }
        fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
            if self.rx_after > 0 {
                self.rx_after -= 1;
                return Err(NetError::WouldBlock);
            }
            buf.get_mut(..3).ok_or(NetError::TooLarge)?.copy_from_slice(&[7, 8, 9]);
            Ok(3)
        }
        fn can_receive(&self) -> bool {
            self.rx_after == 0
        }
        fn can_transmit(&self) -> bool {
            self.full_for == 0
        }
    }

    #[test]
    fn polled_net_waits_out_would_block_but_not_errors() {
        let mut n = Polled(Nic { full_for: 2, rx_after: 4, sent: Vec::new() });
        assert_eq!(n.mac_address(), MacAddress([2, 0, 0, 0, 0, 1]));
        assert_eq!(block_on(n.transmit(&[1, 2])), (Ok(()), 2));
        assert_eq!(n.0.sent, [std::vec![1, 2]]);
        assert_eq!(block_on(n.transmit(&[0; 2000])), (Err(NetError::TooLarge), 0));
        let mut buf = [0; 8];
        assert_eq!(block_on(n.receive(&mut buf)), (Ok(3), 4));
        assert_eq!(buf[..3], [7, 8, 9]);
        assert_eq!(block_on(n.receive(&mut [0; 2])), (Err(NetError::TooLarge), 0));
    }
}
