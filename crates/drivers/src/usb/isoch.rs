//! Streaming helpers for isochronous endpoints, generic over any
//! [`IsochHost`].
//!
//! An isochronous endpoint moves one chunk per service interval and never
//! retries, so a stream needs several transfers queued ahead to survive a
//! late caller. [`IsochIn`] keeps that many receives outstanding and hands
//! out each as it completes; [`IsochOut`] queues sends. Both schedule with
//! [`IsochStart::Next`], so successive chunks land in successive intervals.
//!
//! A class driver (audio, video) selects the alternate setting that gives the
//! endpoint bandwidth with `SET_INTERFACE`, enables it with
//! [`UsbHost::configure_endpoints`](osmium_hal::usb::UsbHost::configure_endpoints),
//! and builds one of these on it.

use osmium_hal::usb::{DeviceId, IsochHost, IsochStart, UsbError};

/// An isochronous IN stream.
pub struct IsochIn<H: IsochHost> {
    host: H,
    dev: DeviceId,
    endpoint: u8,
    len: usize,
    /// Intervals that completed with an error (a missed service interval, say).
    errors: u64,
}

impl<H: IsochHost> IsochIn<H> {
    /// Starts receiving `len` bytes per interval (at most the endpoint's
    /// bytes per interval) from `endpoint`, keeping `depth` transfers queued.
    pub fn new(mut host: H, dev: DeviceId, endpoint: u8, len: usize, depth: usize) -> Result<Self, UsbError> {
        for _ in 0..depth {
            host.isoch_submit_in(dev, endpoint, len, IsochStart::Next)?;
        }
        Ok(Self { host, dev, endpoint, len, errors: 0 })
    }

    /// Collects the next completed interval into `buf`, returning the bytes
    /// received (possibly 0 if the device sent nothing), and queues a
    /// replacement. `None` if the oldest is still in flight. An interval
    /// the schedule spoiled counts in [`errors`](Self::errors) and reads as
    /// no data.
    pub fn read(&mut self, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
        let result = match self.host.isoch_poll(self.dev, self.endpoint, buf)? {
            Err(UsbError::Transaction) => {
                self.errors = self.errors.saturating_add(1);
                Ok(0)
            }
            other => other,
        };
        if let Err(e) = self.host.isoch_submit_in(self.dev, self.endpoint, self.len, IsochStart::Next) {
            return Some(Err(e));
        }
        Some(result)
    }

    /// Intervals lost to scheduling or transfer errors.
    pub fn errors(&self) -> u64 {
        self.errors
    }

    /// Gives the host back.
    pub fn into_host(self) -> H {
        self.host
    }
}

/// An isochronous OUT stream.
pub struct IsochOut<H: IsochHost> {
    host: H,
    dev: DeviceId,
    endpoint: u8,
    queued: usize,
    /// Intervals that completed with an error (the ring ran dry, say).
    errors: u64,
}

impl<H: IsochHost> IsochOut<H> {
    /// A stream to `endpoint`.
    pub fn new(host: H, dev: DeviceId, endpoint: u8) -> Self {
        Self { host, dev, endpoint, queued: 0, errors: 0 }
    }

    /// Collects every finished interval, freeing queue space.
    pub fn reap(&mut self) {
        while self.queued > 0 {
            match self.host.isoch_poll(self.dev, self.endpoint, &mut []) {
                None => break,
                Some(Ok(_)) => self.queued -= 1,
                Some(Err(UsbError::BadEndpoint)) => {
                    self.queued = 0;
                }
                Some(Err(_)) => {
                    self.queued -= 1;
                    self.errors = self.errors.saturating_add(1);
                }
            }
        }
    }

    /// Queues `data` (one interval's worth) to follow the previous chunk.
    /// Fails with [`UsbError::Busy`] if the endpoint's queue is full: try
    /// again after the next interval completes.
    pub fn write(&mut self, data: &[u8]) -> Result<(), UsbError> {
        self.reap();
        self.host.isoch_submit_out(self.dev, self.endpoint, data, IsochStart::Next)?;
        self.queued += 1;
        Ok(())
    }

    /// Chunks queued and not yet collected.
    pub fn queued(&self) -> usize {
        self.queued
    }

    /// Intervals lost to errors.
    pub fn errors(&self) -> u64 {
        self.errors
    }

    /// Gives the host back.
    pub fn into_host(self) -> H {
        self.host
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osmium_hal::usb::{EndpointDescriptor, PortStatus, SetupPacket, UsbHost};
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// Queues up to four transfers per endpoint and completes them when told.
    #[derive(Default)]
    struct FakeIsoch {
        queue: VecDeque<(usize, Option<Vec<u8>>)>,
        /// Completions released so far: bytes, or an error.
        done: VecDeque<Result<usize, UsbError>>,
        starts: Vec<IsochStart>,
        sent: Vec<Vec<u8>>,
    }

    impl UsbHost for FakeIsoch {
        fn num_ports(&self) -> u8 {
            0
        }
        fn port_status(&self, _: u8) -> PortStatus {
            panic!("not used by this test")
        }
        fn attach(&mut self, _: u8) -> Result<DeviceId, UsbError> {
            panic!("not used by this test")
        }
        fn detach(&mut self, _: DeviceId) {}
        fn configure_endpoints(&mut self, _: DeviceId, _: &[EndpointDescriptor]) -> Result<(), UsbError> {
            Ok(())
        }
        fn control_in(&mut self, _: DeviceId, _: SetupPacket, _: &mut [u8]) -> Result<usize, UsbError> {
            panic!("not used by this test")
        }
        fn control_out(&mut self, _: DeviceId, _: SetupPacket, _: &[u8]) -> Result<(), UsbError> {
            panic!("not used by this test")
        }
        fn transfer_in(&mut self, _: DeviceId, _: u8, _: &mut [u8]) -> Result<usize, UsbError> {
            panic!("not used by this test")
        }
        fn transfer_out(&mut self, _: DeviceId, _: u8, _: &[u8]) -> Result<(), UsbError> {
            panic!("not used by this test")
        }
        fn submit_in(&mut self, _: DeviceId, _: u8, _: usize) -> Result<(), UsbError> {
            panic!("not used by this test")
        }
        fn poll_in(&mut self, _: DeviceId, _: u8, _: &mut [u8]) -> Option<Result<usize, UsbError>> {
            panic!("not used by this test")
        }
    }

    impl IsochHost for FakeIsoch {
        fn isoch_frame(&self) -> u16 {
            0
        }
        fn isoch_submit_in(&mut self, _: DeviceId, _: u8, len: usize, start: IsochStart) -> Result<(), UsbError> {
            if self.queue.len() == 4 {
                return Err(UsbError::Busy);
            }
            self.starts.push(start);
            self.queue.push_back((len, None));
            Ok(())
        }
        fn isoch_submit_out(&mut self, _: DeviceId, _: u8, data: &[u8], start: IsochStart) -> Result<(), UsbError> {
            if self.queue.len() == 4 {
                return Err(UsbError::Busy);
            }
            self.starts.push(start);
            self.queue.push_back((data.len(), Some(data.to_vec())));
            Ok(())
        }
        fn isoch_poll(&mut self, _: DeviceId, _: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
            if self.queue.is_empty() {
                return Some(Err(UsbError::BadEndpoint));
            }
            let result = self.done.pop_front()?;
            let (_, data) = self.queue.pop_front().unwrap();
            if let (Ok(n), None) = (result, &data) {
                buf[..n].fill(0xaa);
            }
            if let Some(d) = data {
                self.sent.push(d);
            }
            Some(result)
        }
    }

    #[test]
    fn in_stream_keeps_the_queue_full_and_counts_lost_intervals() {
        let mut host = FakeIsoch::default();
        let mut s = IsochIn::new(&mut host, DeviceId(1), 0x81, 192, 3).unwrap();
        let mut buf = [0u8; 192];
        assert!(s.read(&mut buf).is_none(), "nothing has completed");
        s.host.done.extend([Ok(192), Err(UsbError::Transaction), Ok(96)]);
        assert_eq!(s.read(&mut buf), Some(Ok(192)));
        assert_eq!(buf[0], 0xaa);
        assert_eq!(s.read(&mut buf), Some(Ok(0)), "a missed interval reads as silence");
        assert_eq!(s.read(&mut buf), Some(Ok(96)));
        assert_eq!(s.errors(), 1);
        assert_eq!(s.host.queue.len(), 3, "each read queued a replacement");
        assert!(s.host.starts.iter().all(|&st| st == IsochStart::Next));
    }

    #[test]
    fn out_stream_backs_off_when_full() {
        let mut host = FakeIsoch::default();
        let mut s = IsochOut::new(&mut host, DeviceId(1), 0x02);
        for i in 0..4u8 {
            s.write(&[i; 4]).unwrap();
        }
        assert_eq!(s.write(&[9; 4]), Err(UsbError::Busy));
        s.host.done.extend([Ok(4), Err(UsbError::Transaction)]);
        s.write(&[5; 4]).unwrap();
        assert_eq!((s.queued(), s.errors()), (3, 1));
        assert_eq!(s.host.sent.len(), 2);
    }
}
