//! virtio-console (device ID 3) with a single port and no control queue.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;

use super::{DeviceCtx, VirtioDevice};

const RX: usize = 0;
const TX: usize = 1;

type Output = Box<dyn FnMut(&[u8]) + Send>;

/// A virtio console: bytes the guest writes go to a callback, and bytes
/// queued with [`push_input`](Self::push_input) are delivered as the guest
/// posts receive buffers.
///
/// ```ignore
/// let con = VirtioMmio::new(VirtioConsole::new(|b| print!("{}", b as char)), mem, irq);
/// con.with_device(|c, ctx| c.push_input(b"root\n", ctx));
/// ```
pub struct VirtioConsole {
    output: Output,
    input: VecDeque<u8>,
}

impl VirtioConsole {
    /// Creates the device; `output` receives every chunk the guest sends.
    pub fn new(output: impl FnMut(&[u8]) + Send + 'static) -> Self {
        Self { output: Box::new(output), input: VecDeque::new() }
    }

    /// Queues bytes for the guest and delivers as many as it has buffers for.
    pub fn push_input(&mut self, bytes: &[u8], ctx: &mut DeviceCtx<'_>) {
        self.input.extend(bytes);
        self.fill_rx(ctx);
    }

    fn fill_rx(&mut self, ctx: &mut DeviceCtx<'_>) {
        while !self.input.is_empty() && ctx.ready(RX) {
            let Some(chain) = ctx.pop(RX) else { break };
            let Ok(chain) = chain else { continue };
            let n = chain.writable_len().min(self.input.len());
            let bytes: vec::Vec<u8> = self.input.iter().take(n).copied().collect();
            let written = chain.write(ctx.mem(), 0, &bytes).unwrap_or(0);
            self.input.drain(..written);
            let _ = ctx.add_used(RX, chain.head, written as u32);
        }
    }

    fn drain_tx(&mut self, ctx: &mut DeviceCtx<'_>) {
        while let Some(chain) = ctx.pop(TX) {
            let Ok(chain) = chain else { continue };
            let mut buf = vec![0u8; chain.readable_len()];
            if let Ok(n) = chain.read(ctx.mem(), 0, &mut buf) {
                (self.output)(&buf[..n]);
            }
            let _ = ctx.add_used(TX, chain.head, 0);
        }
    }
}

impl VirtioDevice for VirtioConsole {
    fn device_id(&self) -> u32 {
        super::device_id::CONSOLE
    }

    fn num_queues(&self) -> usize {
        2
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // cols, rows (u16 each), max_nr_ports (u32), emerg_wr (u32): 80x25, 1 port.
        let cfg: [u8; 12] = [80, 0, 25, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        for (i, d) in data.iter_mut().enumerate() {
            *d = cfg.get(offset as usize + i).copied().unwrap_or(0);
        }
    }

    fn notify(&mut self, queue: usize, ctx: &mut DeviceCtx<'_>) {
        match queue {
            RX => self.fill_rx(ctx),
            TX => self.drain_tx(ctx),
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.input.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::BusDevice;
    use crate::memory::{GuestMemory, GuestPhysAddr};
    use crate::virtio::VirtioMmio;
    use crate::virtio::mmio::tests::{ack, bring_up, notify};
    use crate::virtio::queue::tests::{DATA, Driver, guest};
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};
    use osmium_sync::IrqSpinLock;

    const RXQ: u64 = 0x0000;
    const TXQ: u64 = 0x8000;

    #[test]
    fn transmit_and_receive() {
        let mut ram = vec![0u8; 0x20000];
        let mem = Arc::new(guest(&mut ram));
        let out = Arc::new(IrqSpinLock::new(Vec::new()));
        let line = Arc::new(AtomicBool::new(false));
        let (o, l) = (out.clone(), line.clone());
        let con = VirtioMmio::new(
            VirtioConsole::new(move |b| o.lock().extend_from_slice(b)),
            mem.clone(),
            move |lvl| l.store(lvl, Ordering::SeqCst),
        );
        bring_up(&con, &[(0, RXQ), (1, TXQ)]);
        let mut cfg = [0u8; 2];
        con.read(0x100, &mut cfg);
        assert_eq!(u16::from_le_bytes(cfg), 80);

        // Transmit: the guest posts a readable buffer on queue 1.
        let mut tx = Driver::new(8);
        mem.write(GuestPhysAddr(TXQ + DATA), b"hi host").unwrap();
        rebase(&mem, &mut tx, TXQ, &[(TXQ + DATA, 7, false)]);
        notify(&con, 1);
        assert_eq!(&out.lock()[..], b"hi host");
        assert!(line.load(Ordering::SeqCst));
        ack(&con);
        assert!(!line.load(Ordering::SeqCst));

        // Receive: input waits until the guest posts a buffer.
        con.with_device(|c, ctx| c.push_input(b"typed", ctx));
        assert!(!line.load(Ordering::SeqCst));
        let mut rx = Driver::new(8);
        rebase(&mem, &mut rx, RXQ, &[(DATA, 3, true)]);
        notify(&con, 0);
        assert_eq!(rx_used(&mem, &rx, RXQ, 0), 3);
        rebase(&mem, &mut rx, RXQ, &[(DATA + 0x100, 16, true)]);
        notify(&con, 0);
        assert_eq!(rx_used(&mem, &rx, RXQ, 1), 2);
        let mut got = [0u8; 5];
        mem.read(GuestPhysAddr(DATA), &mut got[..3]).unwrap();
        mem.read(GuestPhysAddr(DATA + 0x100), &mut got[3..]).unwrap();
        assert_eq!(&got, b"typed");
        assert!(line.load(Ordering::SeqCst));
    }

    /// Posts on a queue whose rings sit at `base` rather than 0.
    fn rebase(mem: &GuestMemory, drv: &mut Driver, base: u64, bufs: &[(u64, u32, bool)]) {
        // The helper writes rings at fixed offsets; give it a view shifted by `base`.
        let mut view = GuestMemory::new();
        let host = mem.host_ptr(GuestPhysAddr(base), 0x8000).unwrap();
        // SAFETY: a sub-window of `mem`'s region, alive for this call.
        unsafe { view.add_region(GuestPhysAddr(0), host, 0x8000) };
        drv.post(&view, bufs);
    }

    fn rx_used(mem: &GuestMemory, drv: &Driver, base: u64, n: u16) -> u32 {
        let mut view = GuestMemory::new();
        let host = mem.host_ptr(GuestPhysAddr(base), 0x8000).unwrap();
        // SAFETY: as in `rebase`.
        unsafe { view.add_region(GuestPhysAddr(0), host, 0x8000) };
        drv.used(&view, n).1
    }
}
