//! virtio-net.
//!
//! Each queue entry owns one fixed slot of [`SLOT_LEN`] bytes in a DMA
//! region per direction, indexed by the entry's descriptor head, holding the
//! virtio-net header followed by the frame in a single descriptor. No
//! offloads are negotiated, so the header is all zeros on transmit and
//! ignored on receive.

use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::net::{MacAddress, NetDevice, NetError};
use osmium_hal::virtio::net;

use super::queue::{Segment, VirtQueue};
use core::mem::ManuallyDrop;

use super::{DeviceType, Transport, VirtioError, driver_ok, feature, negotiate, reset};

const RX: u16 = net::RX_QUEUE;
const TX: u16 = net::TX_QUEUE;

/// Bytes per buffer slot: the largest header plus a 1514-byte frame,
/// rounded up.
pub const SLOT_LEN: usize = 2048;

/// Entries used per queue, at most (fewer if the device offers fewer).
pub const MAX_QUEUE_SIZE: u16 = 64;

const MAX_FRAME: usize = 1514;

/// A virtio network card. Dropping it resets the device and frees its memory.
pub struct VirtioNet<'d, T: Transport, D: DmaAllocator + ?Sized> {
    transport: T,
    // Freed in `drop` only once the device has acknowledged its reset.
    rx: ManuallyDrop<VirtQueue<'d, D>>,
    tx: ManuallyDrop<VirtQueue<'d, D>>,
    rx_slots: ManuallyDrop<OwnedDma<'d, D>>,
    tx_slots: ManuallyDrop<OwnedDma<'d, D>>,
    mac: MacAddress,
    header_len: usize,
    has_status: bool,
}

impl<'d, T: Transport, D: DmaAllocator + ?Sized> VirtioNet<'d, T, D> {
    /// Initializes the device behind `transport`, allocating its queues and
    /// buffers from `dma`, and fills the receive queue.
    ///
    /// Devices without a MAC address in configuration space get a fixed,
    /// locally administered one (`02:00:00:00:00:01`); override it with
    /// [`set_mac_address`](Self::set_mac_address) if several share a link.
    pub fn new(transport: T, dma: &'d D) -> Result<Self, VirtioError> {
        if transport.device_type() != DeviceType::Net {
            return Err(VirtioError::WrongDevice);
        }
        // A legacy device must accept header and frame in one descriptor.
        let required = if transport.is_legacy() { feature::ANY_LAYOUT } else { 0 };
        let features = negotiate(&transport, required, net::F_MAC | net::F_STATUS)?;

        let size = |q| match transport.max_queue_size(q).min(MAX_QUEUE_SIZE) {
            0 => Err(VirtioError::BadQueue),
            // Split queues come in powers of two.
            n => Ok(1 << n.ilog2()),
        };
        let (rx_size, tx_size) = (size(RX)?, size(TX)?);
        let slots = |n: u16| OwnedDma::new(dma, n as usize * SLOT_LEN).ok_or(VirtioError::NoMemory);

        let mac = if features & net::F_MAC != 0 {
            MacAddress(core::array::from_fn(|i| transport.config_read8(net::CONFIG_MAC + i)))
        } else {
            MacAddress([0x02, 0, 0, 0, 0, 1])
        };
        // Plain values until all succeed, so a failure frees the others.
        let (rx, tx) = (VirtQueue::new(dma, RX, rx_size)?, VirtQueue::new(dma, TX, tx_size)?);
        let (rx_slots, tx_slots) = (slots(rx_size)?, slots(tx_size)?);
        let mut net = Self {
            rx: ManuallyDrop::new(rx),
            tx: ManuallyDrop::new(tx),
            rx_slots: ManuallyDrop::new(rx_slots),
            tx_slots: ManuallyDrop::new(tx_slots),
            mac,
            header_len: net::header_len(features & feature::VERSION_1 != 0, false),
            has_status: features & net::F_STATUS != 0,
            transport,
        };

        net.transport.setup_queue(RX, rx_size, net.rx.addrs());
        net.transport.setup_queue(TX, tx_size, net.tx.addrs());
        // Transmit completions are reaped lazily; don't interrupt for them.
        net.tx.set_interrupts(false);
        while net.rx.next_head().is_some() {
            net.post_rx();
        }
        driver_ok(&net.transport);
        net.transport.notify(RX);
        Ok(net)
    }

    /// Replaces the MAC address reported by [`NetDevice::mac_address`]. The
    /// device itself is not told (that needs the control queue); with no
    /// filtering negotiated it delivers every frame anyway.
    pub fn set_mac_address(&mut self, mac: MacAddress) {
        self.mac = mac;
    }

    /// The transport, for interrupt acknowledgement
    /// ([`Transport::ack_interrupt`]) from the driver's IRQ handler.
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Asks the device to interrupt (or not) when frames arrive.
    pub fn set_rx_interrupts(&self, enabled: bool) {
        self.rx.set_interrupts(enabled);
    }

    fn slot(slots: &DmaBuffer, head: u16) -> Segment {
        Segment {
            addr: slots.device_addr() + head as u64 * SLOT_LEN as u64,
            len: SLOT_LEN as u32,
            device_writes: false,
        }
    }

    /// Hands the next free receive slot to the device (no notification).
    fn post_rx(&mut self) {
        let head = self.rx.next_head().expect("receive queue full");
        let seg = Segment { device_writes: true, ..Self::slot(&self.rx_slots, head) };
        let got = self.rx.add(&[seg]).expect("receive queue full");
        debug_assert_eq!(got, head);
    }

    fn reap_tx(&mut self) {
        while self.tx.pop_used().is_some() {}
    }
}

impl<T: Transport, D: DmaAllocator + ?Sized> NetDevice for VirtioNet<'_, T, D> {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn max_frame_len(&self) -> usize {
        MAX_FRAME
    }

    fn link_up(&self) -> bool {
        !self.has_status || self.transport.config_read16(net::CONFIG_STATUS) & net::STATUS_LINK_UP != 0
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        if frame.len() > MAX_FRAME {
            return Err(NetError::TooLarge);
        }
        self.reap_tx();
        let head = self.tx.next_head().ok_or(NetError::WouldBlock)?;
        let off = head as usize * SLOT_LEN;
        self.tx_slots.write(off, &[0; 12][..self.header_len]);
        self.tx_slots.write(off + self.header_len, frame);
        let seg = Segment { len: (self.header_len + frame.len()) as u32, ..Self::slot(&self.tx_slots, head) };
        self.tx.add(&[seg]).map_err(|_| NetError::WouldBlock)?;
        if self.tx.needs_notify() {
            self.transport.notify(TX);
        }
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        let (head, len) = self.rx.pop_used().ok_or(NetError::WouldBlock)?;
        let frame_len = (len as usize).saturating_sub(self.header_len).min(SLOT_LEN - self.header_len);
        let result = match buf.get_mut(..frame_len) {
            Some(dst) => {
                self.rx_slots.read(head as usize * SLOT_LEN + self.header_len, dst);
                Ok(frame_len)
            }
            None => Err(NetError::TooLarge),
        };
        // Popping freed exactly this one descriptor, so it is the next head.
        self.post_rx();
        if self.rx.needs_notify() {
            self.transport.notify(RX);
        }
        result
    }

    fn can_receive(&self) -> bool {
        self.rx.has_used()
    }

    fn can_transmit(&self) -> bool {
        self.tx.num_free() > 0 || self.tx.has_used()
    }
}

impl<T: Transport, D: DmaAllocator + ?Sized> Drop for VirtioNet<'_, T, D> {
    fn drop(&mut self) {
        // Stop the device before freeing memory it may still be writing; if
        // it never stops, leak the memory instead.
        if reset(&self.transport) {
            // SAFETY: dropped once, here; the device is reset.
            unsafe {
                ManuallyDrop::drop(&mut self.rx);
                ManuallyDrop::drop(&mut self.tx);
                ManuallyDrop::drop(&mut self.rx_slots);
                ManuallyDrop::drop(&mut self.tx_slots);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::queue::tests::DeviceSide;
    use crate::virtio::status;
    use crate::virtio::testing::{FakeTransport, HostDma};

    const MAC: [u8; 8] = [0x52, 0x54, 0, 0x12, 0x34, 0x56, 1, 0]; // + status: link up

    fn device(modern: bool) -> FakeTransport {
        let version = if modern { feature::VERSION_1 } else { feature::ANY_LAYOUT };
        let mut t = FakeTransport::new(DeviceType::Net, version | net::F_MAC | net::F_STATUS, &MAC);
        t.max_queue = 8;
        t
    }

    fn mem(addr: u64, len: usize) -> &'static mut [u8] {
        // SAFETY: test DMA memory is identity-mapped and outlives the call.
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) }
    }

    #[test]
    fn init_and_receive() {
        let dma = HostDma::default();
        let mut net = VirtioNet::new(device(true), &dma).unwrap();
        let t = net.transport();
        assert_eq!(net.mac_address(), MacAddress([0x52, 0x54, 0, 0x12, 0x34, 0x56]));
        assert!(net.link_up());
        assert_eq!(t.status() & status::DRIVER_OK, status::DRIVER_OK);
        assert_eq!(*t.notified.borrow(), [RX]);
        let (size, addrs) = t.queue(RX);
        assert_eq!(size, 8);

        let mut dev = DeviceSide::new(size, addrs);
        let mut posted = std::vec::Vec::new();
        while let Some((head, chain)) = dev.pop_avail() {
            assert_eq!(chain.len(), 1);
            assert_eq!(chain[0].1 as usize, SLOT_LEN);
            posted.push((head, chain[0].0));
        }
        assert_eq!(posted.len(), 8, "every slot posted for receive");

        assert_eq!(net.receive(&mut [0; 64]), Err(NetError::WouldBlock));
        let (head, addr) = posted[3];
        mem(addr, 12 + 5).copy_from_slice(b"\0\0\0\0\0\0\0\0\0\0\0\0hello");
        dev.push_used(head, 12 + 5);
        assert!(net.can_receive());
        let mut buf = [0u8; 64];
        assert_eq!(net.receive(&mut buf), Ok(5));
        assert_eq!(&buf[..5], b"hello");
        let (again, _) = dev.pop_avail().expect("slot reposted");
        assert_eq!(again, head);

        dev.push_used(again, 12 + 100);
        assert_eq!(net.receive(&mut buf[..50]), Err(NetError::TooLarge));
        assert!(dev.pop_avail().is_some(), "reposted even when dropped");
    }

    #[test]
    fn transmit_until_full_then_reap() {
        let dma = HostDma::default();
        let mut net = VirtioNet::new(device(false), &dma).unwrap();
        let (size, addrs) = net.transport().queue(TX);
        let mut dev = DeviceSide::new(size, addrs);

        let frame = [0xabu8; 60];
        for _ in 0..8 {
            net.transmit(&frame).unwrap();
        }
        assert!(!net.can_transmit());
        assert_eq!(net.transmit(&frame), Err(NetError::WouldBlock));
        assert_eq!(net.transmit(&[0; 1515]), Err(NetError::TooLarge));

        let (head, chain) = dev.pop_avail().unwrap();
        let (addr, len, _) = chain[0];
        assert_eq!(len, 10 + 60, "legacy header is 10 bytes");
        let sent = mem(addr, len as usize);
        assert_eq!(&sent[..10], &[0; 10]);
        assert_eq!(&sent[10..], &frame);
        assert_eq!(net.transport().notified.borrow().iter().filter(|&&q| q == TX).count(), 8);

        dev.push_used(head, 0);
        assert!(net.can_transmit());
        net.transmit(&frame).unwrap();
    }

    #[test]
    fn drop_resets_and_frees() {
        let dma = HostDma::default();
        let net = VirtioNet::new(device(true), &dma).unwrap();
        assert_eq!(dma.live.get(), 4);
        drop(net);
        assert_eq!(dma.live.get(), 0);

        let mut no_queue = device(true);
        no_queue.max_queue = 0;
        assert_eq!(VirtioNet::new(no_queue, &dma).err(), Some(VirtioError::BadQueue));
        let legacy_strict = FakeTransport::new(DeviceType::Net, 0, &MAC);
        assert_eq!(VirtioNet::new(legacy_strict, &dma).err(), Some(VirtioError::Unsupported));
        let block = FakeTransport::new(DeviceType::Block, feature::VERSION_1, &[]);
        assert_eq!(VirtioNet::new(block, &dma).err(), Some(VirtioError::WrongDevice));
        assert_eq!(dma.live.get(), 0, "failed probes leak nothing");
    }
}
