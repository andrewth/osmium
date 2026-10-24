//! virtio-net (device ID 1): frames to and from a pluggable backend.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use osmium_hal::virtio::net::{CONFIG_MAC, CONFIG_STATUS, F_MAC, F_STATUS, STATUS_LINK_UP, header_len};

use super::{DeviceCtx, VirtioDevice, device_id};

const RX: usize = osmium_hal::virtio::net::RX_QUEUE as usize;
const TX: usize = osmium_hal::virtio::net::TX_QUEUE as usize;
/// The modern (VERSION_1) header, which the transport always negotiates.
const HEADER: usize = header_len(true, false);
/// Frames waiting for receive buffers, at most; older ones are dropped.
const RX_BACKLOG: usize = 64;
/// The longest frame a driver may send without GSO or an MTU feature,
/// neither of which is offered: 1500 bytes of payload, an Ethernet header
/// and a VLAN tag.
const MAX_FRAME: usize = 1518;

/// Where a [`VirtioNetDevice`]'s transmitted frames go: a host NIC, a
/// software switch, another guest, or a responder in the hypervisor.
pub trait NetBackend: Send {
    /// Handles a frame the guest sent. Frames passed to `reply` are
    /// delivered back to this guest.
    fn transmit(&mut self, frame: &[u8], reply: &mut dyn FnMut(&[u8]));
}

impl<F: FnMut(&[u8], &mut dyn FnMut(&[u8])) + Send> NetBackend for F {
    fn transmit(&mut self, frame: &[u8], reply: &mut dyn FnMut(&[u8])) {
        self(frame, reply)
    }
}

/// A virtio network card with a fixed MAC address and the link always up.
/// No offloads or mergeable buffers are offered, so every frame travels
/// with a zeroed 12-byte header in a single buffer.
pub struct VirtioNetDevice {
    mac: [u8; 6],
    backend: Box<dyn NetBackend>,
    rx_backlog: VecDeque<Vec<u8>>,
}

impl VirtioNetDevice {
    /// A card with address `mac` whose transmitted frames go to `backend`.
    pub fn new(mac: [u8; 6], backend: impl NetBackend + 'static) -> Self {
        Self { mac, backend: Box::new(backend), rx_backlog: VecDeque::new() }
    }

    /// Delivers `frame` to the guest, now if it has posted a receive buffer,
    /// otherwise when it does.
    pub fn receive(&mut self, frame: &[u8], ctx: &mut DeviceCtx<'_>) {
        if self.rx_backlog.len() == RX_BACKLOG {
            self.rx_backlog.pop_front();
        }
        self.rx_backlog.push_back(frame.to_vec());
        self.fill_rx(ctx);
    }

    fn fill_rx(&mut self, ctx: &mut DeviceCtx<'_>) {
        while !self.rx_backlog.is_empty() && ctx.ready(RX) {
            let Some(chain) = ctx.pop(RX) else { break };
            let Ok(chain) = chain else { continue };
            let Some(frame) = self.rx_backlog.pop_front() else { break };
            let mut hdr = [0u8; HEADER];
            hdr[10] = 1; // num_buffers
            let mem = ctx.mem();
            let len = if chain.writable_len() >= HEADER + frame.len() {
                let _ = chain.write(mem, 0, &hdr);
                chain.write(mem, HEADER, &frame).map_or(0, |n| HEADER + n)
            } else {
                0 // too small: return it empty, the frame is lost
            };
            let _ = ctx.add_used(RX, chain.head, len as u32);
        }
    }

    fn drain_tx(&mut self, ctx: &mut DeviceCtx<'_>) {
        while let Some(chain) = ctx.pop(TX) {
            let Ok(chain) = chain else { continue };
            // A frame longer than any valid one is dropped unread, so the
            // guest's lengths never size more than one frame's allocation.
            let len = chain.readable_len();
            if len > HEADER + MAX_FRAME {
                let _ = ctx.add_used(TX, chain.head, 0);
                continue;
            }
            let mut buf = vec![0u8; len];
            if let Ok(n) = chain.read(ctx.mem(), 0, &mut buf)
                && n > HEADER
            {
                let backlog = &mut self.rx_backlog;
                self.backend.transmit(buf.get(HEADER..n).unwrap_or_default(), &mut |f| {
                    if backlog.len() < RX_BACKLOG {
                        backlog.push_back(f.to_vec());
                    }
                });
            }
            let _ = ctx.add_used(TX, chain.head, 0);
        }
        self.fill_rx(ctx);
    }
}

impl VirtioDevice for VirtioNetDevice {
    fn device_id(&self) -> u32 {
        device_id::NET
    }

    fn features(&self) -> u64 {
        F_MAC | F_STATUS
    }

    fn num_queues(&self) -> usize {
        2
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let mut cfg = [0u8; 8];
        cfg[CONFIG_MAC..CONFIG_MAC + 6].copy_from_slice(&self.mac);
        cfg[CONFIG_STATUS..CONFIG_STATUS + 2].copy_from_slice(&STATUS_LINK_UP.to_le_bytes());
        for (i, d) in data.iter_mut().enumerate() {
            let at = usize::try_from(offset).ok().and_then(|o| o.checked_add(i));
            *d = at.and_then(|at| cfg.get(at)).copied().unwrap_or(0);
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
        self.rx_backlog.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::BusDevice;
    use crate::memory::{GuestMemory, GuestPhysAddr};
    use crate::virtio::VirtioMmio;
    use crate::virtio::mmio::tests::{bring_up, notify};
    use crate::virtio::queue::tests::{DATA, Driver, guest};
    use alloc::sync::Arc;
    use osmium_sync::IrqSpinLock;

    const RXQ: u64 = 0x0000;
    const TXQ: u64 = 0x8000;

    /// Posts on a queue whose rings sit at `base`.
    fn post(mem: &GuestMemory, drv: &mut Driver, base: u64, bufs: &[(u64, u32, bool)]) {
        let mut view = GuestMemory::new();
        let host = mem.host_ptr(GuestPhysAddr(base), 0x8000).unwrap();
        // SAFETY: a sub-window of `mem`'s region, alive for this call.
        unsafe { view.add_region(GuestPhysAddr(0), host, 0x8000) };
        drv.post(&view, bufs);
    }

    fn used_len(mem: &GuestMemory, drv: &Driver, base: u64, n: u16) -> u32 {
        let mut view = GuestMemory::new();
        let host = mem.host_ptr(GuestPhysAddr(base), 0x8000).unwrap();
        // SAFETY: as in `post`.
        unsafe { view.add_region(GuestPhysAddr(0), host, 0x8000) };
        drv.used(&view, n).1
    }

    #[test]
    fn echo_backend_and_host_frames() {
        let mut ram = vec![0u8; 0x20000];
        let mem = Arc::new(guest(&mut ram));
        let sent = Arc::new(IrqSpinLock::new(Vec::new()));
        let s = sent.clone();
        // Records what the guest sends and echoes it back reversed.
        let backend = move |f: &[u8], reply: &mut dyn FnMut(&[u8])| {
            s.lock().push(f.to_vec());
            let mut r = f.to_vec();
            r.reverse();
            reply(&r);
        };
        let net = VirtioMmio::new(VirtioNetDevice::new([2, 0, 0, 0, 0, 9], backend), mem.clone(), |_| {});
        bring_up(&net, &[(0, RXQ), (1, TXQ)]);
        let mut mac = [0u8; 6];
        net.read(0x100, &mut mac);
        assert_eq!(mac, [2, 0, 0, 0, 0, 9]);
        let mut st = [0u8; 2];
        net.read(0x100 + 6, &mut st);
        assert_eq!(u16::from_le_bytes(st), STATUS_LINK_UP);

        // Transmit before any receive buffer: the echo waits in the backlog.
        let mut tx = Driver::new(8);
        mem.write(GuestPhysAddr(TXQ + DATA), &[0; HEADER]).unwrap();
        mem.write(GuestPhysAddr(TXQ + DATA + HEADER as u64), b"frame").unwrap();
        post(&mem, &mut tx, TXQ, &[(TXQ + DATA, (HEADER + 5) as u32, false)]);
        notify(&net, 1);
        assert_eq!(sent.lock()[0], b"frame");

        let mut rx = Driver::new(8);
        post(&mem, &mut rx, RXQ, &[(DATA, 2048, true)]);
        notify(&net, 0);
        assert_eq!(used_len(&mem, &rx, RXQ, 0), (HEADER + 5) as u32);
        let mut got = [0u8; HEADER + 5];
        mem.read(GuestPhysAddr(DATA), &mut got).unwrap();
        assert_eq!(got[10], 1, "num_buffers");
        assert_eq!(&got[HEADER..], b"emarf");

        // A frame from the host side.
        post(&mem, &mut rx, RXQ, &[(DATA + 0x1000, 2048, true)]);
        net.with_device(|d, ctx| d.receive(b"hello", ctx));
        assert_eq!(used_len(&mem, &rx, RXQ, 1), (HEADER + 5) as u32);
        let mut got = [0u8; 5];
        mem.read(GuestPhysAddr(DATA + 0x1000 + HEADER as u64), &mut got).unwrap();
        assert_eq!(&got, b"hello");

        // A frame longer than any valid one is returned unread.
        post(&mem, &mut tx, TXQ, &[(TXQ + DATA, u32::MAX, false)]);
        notify(&net, 1);
        assert_eq!(sent.lock().len(), 1);
        assert_eq!(used_len(&mem, &tx, TXQ, 1), 0);
    }
}
