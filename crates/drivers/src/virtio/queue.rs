//! Split virtqueues (virtio 1.x §2.7, legacy §2.4).
//!
//! The queue lives in one page-aligned DMA buffer in the legacy layout
//! (descriptor table, available ring, then the used ring on the next page
//! boundary), which modern devices accept too since they take the three
//! addresses separately.
//!
//! Free descriptors are chained through their own `next` fields, as in
//! Linux; the device never writes the descriptor table, so the chain is safe
//! there. The head index returned by [`VirtQueue::add`] identifies the
//! request when it comes back from [`VirtQueue::pop_used`].

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::mmio::RegValue;
use osmium_hal::virtio::queue::*;
use osmium_mm::PhysAddr;

use super::{QueueAddrs, VirtioError};

/// One buffer of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Device address.
    pub addr: PhysAddr,
    /// Length in bytes.
    pub len: u32,
    /// True if the device writes it (device-to-driver), false if it reads it.
    pub device_writes: bool,
}

/// A split virtqueue. Its memory is freed on drop; reset the device first.
pub struct VirtQueue<'d, D: DmaAllocator + ?Sized> {
    mem: OwnedDma<'d, D>,
    index: u16,
    size: u16,
    free_head: u16,
    num_free: u16,
    // Our copy of avail.idx, and how far we have consumed used.idx.
    avail_idx: u16,
    last_used: u16,
}

impl<'d, D: DmaAllocator + ?Sized> VirtQueue<'d, D> {
    /// Bytes of DMA memory a queue of `size` entries occupies.
    pub const fn mem_size(size: u16) -> usize {
        legacy_size(size)
    }

    const fn avail_offset(size: u16) -> usize {
        legacy_avail_offset(size)
    }

    const fn used_offset(size: u16) -> usize {
        legacy_used_offset(size)
    }

    /// Allocates queue `index` with `size` entries (1–32768).
    pub fn new(dma: &'d D, index: u16, size: u16) -> Result<Self, VirtioError> {
        if size == 0 || size > 32768 {
            return Err(VirtioError::BadQueue);
        }
        let mem = OwnedDma::new(dma, Self::mem_size(size)).ok_or(VirtioError::NoMemory)?;
        if !mem.device_addr().is_aligned(LEGACY_ALIGN as u64)
            || !(mem.cpu_ptr().as_ptr() as usize).is_multiple_of(LEGACY_ALIGN)
        {
            return Err(VirtioError::NoMemory);
        }
        let q = Self { mem, index, size, free_head: 0, num_free: size, avail_idx: 0, last_used: 0 };
        for i in 0..size {
            q.write_desc(i, PhysAddr::new(0), 0, 0, i.wrapping_add(1));
        }
        Ok(q)
    }

    /// The queue's index on its device.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Number of entries.
    pub fn size(&self) -> u16 {
        self.size
    }

    /// Descriptors not in use.
    pub fn num_free(&self) -> u16 {
        self.num_free
    }

    /// The head index the next [`add`](Self::add) will return, if any
    /// descriptor is free. Drivers that tie a buffer slot to each head use it
    /// to fill the slot before publishing it.
    pub fn next_head(&self) -> Option<u16> {
        (self.num_free > 0).then_some(self.free_head)
    }

    /// Device addresses of the queue's parts, for [`Transport::setup_queue`].
    ///
    /// [`Transport::setup_queue`]: super::Transport::setup_queue
    pub fn addrs(&self) -> QueueAddrs {
        let base = self.mem.device_addr();
        QueueAddrs {
            desc: base,
            avail: base + Self::avail_offset(self.size) as u64,
            used: base + Self::used_offset(self.size) as u64,
        }
    }

    fn read<T: RegValue>(&self, offset: usize) -> T {
        self.mem.load(offset)
    }

    fn write<T: RegValue>(&self, offset: usize, value: T) {
        self.mem.store(offset, value)
    }

    fn write_desc(&self, i: u16, addr: PhysAddr, len: u32, flags: u16, next: u16) {
        let d = DESC_SIZE * i as usize;
        self.write(d, addr.as_u64().to_le());
        self.write(d + 8, len.to_le());
        self.write(d + 12, flags.to_le());
        self.write(d + 14, next.to_le());
    }

    fn desc_flags(&self, i: u16) -> u16 {
        u16::from_le(self.read(DESC_SIZE * i as usize + 12))
    }

    fn desc_next(&self, i: u16) -> u16 {
        u16::from_le(self.read(DESC_SIZE * i as usize + 14))
    }

    /// Makes a request of `segments` available to the device and returns its
    /// head index. Device-readable segments must come before device-writable
    /// ones. Call [`Transport::notify`] afterwards if
    /// [`needs_notify`](Self::needs_notify) says so.
    ///
    /// [`Transport::notify`]: super::Transport::notify
    pub fn add(&mut self, segments: &[Segment]) -> Result<u16, VirtioError> {
        let n = segments.len();
        if n == 0 || n > self.num_free as usize {
            return Err(VirtioError::QueueFull);
        }
        let head = self.free_head;
        let mut i = head;
        for (k, s) in segments.iter().enumerate() {
            let next = self.desc_next(i);
            let mut flags = if s.device_writes { DESC_F_WRITE } else { 0 };
            let last = k + 1 == n;
            if !last {
                flags |= DESC_F_NEXT;
            }
            self.write_desc(i, s.addr, s.len, flags, next);
            if last {
                self.free_head = next;
            } else {
                i = next;
            }
        }
        self.num_free -= n as u16;

        let avail = Self::avail_offset(self.size);
        self.write(avail + avail_entry(self.avail_idx % self.size), head.to_le());
        // The ring entry and descriptors must be visible before the index.
        barrier::dma_wmb();
        self.avail_idx = self.avail_idx.wrapping_add(1);
        self.write(avail + 2, self.avail_idx.to_le());
        // And the index before the caller's doorbell write (or our read of
        // the device's NO_NOTIFY flag).
        barrier::mb();
        Ok(head)
    }

    /// True unless the device asked not to be notified of new buffers.
    pub fn needs_notify(&self) -> bool {
        let used = Self::used_offset(self.size);
        u16::from_le(self.read::<u16>(used)) & USED_F_NO_NOTIFY == 0
    }

    /// Asks the device to interrupt (or not) when it uses buffers. Advisory:
    /// the device may interrupt anyway.
    pub fn set_interrupts(&self, enabled: bool) {
        let flags = if enabled { 0 } else { AVAIL_F_NO_INTERRUPT };
        self.write(Self::avail_offset(self.size), flags.to_le());
    }

    /// True if the device has returned requests not yet popped.
    pub fn has_used(&self) -> bool {
        let used = Self::used_offset(self.size);
        u16::from_le(self.read::<u16>(used + 2)) != self.last_used
    }

    /// Takes the next completed request: its head index and the number of
    /// bytes the device wrote. Its descriptors return to the free list.
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        if !self.has_used() {
            return None;
        }
        // Read the entry only after seeing the index that covers it.
        barrier::dma_rmb();
        let used = Self::used_offset(self.size);
        let entry = used + used_entry(self.last_used % self.size);
        let head = u32::from_le(self.read::<u32>(entry)) as u16;
        let len = u32::from_le(self.read::<u32>(entry + 4));
        self.last_used = self.last_used.wrapping_add(1);
        assert!(head < self.size, "virtio device returned descriptor {head}");

        let mut tail = head;
        let mut count = 1;
        while self.desc_flags(tail) & DESC_F_NEXT != 0 {
            tail = self.desc_next(tail);
            count += 1;
        }
        let d = DESC_SIZE * tail as usize;
        self.write(d + 12, 0u16);
        self.write(d + 14, self.free_head.to_le());
        self.free_head = head;
        self.num_free += count;
        Some((head, len))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::virtio::testing::HostDma;

    /// A descriptor as the device sees it: (address, length, flags).
    pub type RawDesc = (u64, u32, u16);

    /// The device's view of a queue, for tests that play the device.
    pub struct DeviceSide {
        addrs: QueueAddrs,
        size: u16,
        last_avail: u16,
        used_idx: u16,
    }

    impl DeviceSide {
        pub fn new(size: u16, addrs: QueueAddrs) -> Self {
            Self { addrs, size, last_avail: 0, used_idx: 0 }
        }

        fn p<T>(a: PhysAddr) -> *mut T {
            a.as_u64() as *mut T
        }

        /// Takes the next available request as (head, [(addr, len, flags)]).
        pub fn pop_avail(&mut self) -> Option<(u16, std::vec::Vec<RawDesc>)> {
            // SAFETY: test memory is identity-mapped (HostDma).
            unsafe {
                let idx = Self::p::<u16>(self.addrs.avail + 2).read_volatile();
                if idx == self.last_avail {
                    return None;
                }
                let slot = (self.last_avail % self.size) as u64;
                let head = Self::p::<u16>(self.addrs.avail + 4 + 2 * slot).read_volatile();
                self.last_avail = self.last_avail.wrapping_add(1);
                let mut chain = std::vec::Vec::new();
                let mut i = head;
                loop {
                    let d = self.addrs.desc + 16 * i as u64;
                    let addr = Self::p::<u64>(d).read_volatile();
                    let len = Self::p::<u32>(d + 8).read_volatile();
                    let flags = Self::p::<u16>(d + 12).read_volatile();
                    chain.push((addr, len, flags));
                    if flags & DESC_F_NEXT == 0 {
                        break;
                    }
                    i = Self::p::<u16>(d + 14).read_volatile();
                }
                Some((head, chain))
            }
        }

        /// Returns request `head` having written `len` bytes.
        pub fn push_used(&mut self, head: u16, len: u32) {
            let slot = (self.used_idx % self.size) as u64;
            // SAFETY: as above.
            unsafe {
                Self::p::<u32>(self.addrs.used + 4 + 8 * slot).write_volatile(head as u32);
                Self::p::<u32>(self.addrs.used + 8 + 8 * slot).write_volatile(len);
                self.used_idx = self.used_idx.wrapping_add(1);
                Self::p::<u16>(self.addrs.used + 2).write_volatile(self.used_idx);
            }
        }

        pub fn set_no_notify(&self, on: bool) {
            // SAFETY: as above.
            unsafe { Self::p::<u16>(self.addrs.used).write_volatile(on as u16) }
        }
    }

    #[test]
    fn layout() {
        assert_eq!(VirtQueue::<HostDma>::mem_size(256), 4096 + 4096 + 6 + 8 * 256);
        let dma = HostDma::default();
        let q = VirtQueue::new(&dma, 0, 8).unwrap();
        let a = q.addrs();
        assert_eq!(a.avail - a.desc, 128);
        assert_eq!(a.used - a.desc, 4096);
        drop(q);
        assert_eq!(dma.live.get(), 0);
        assert_eq!(VirtQueue::new(&dma, 0, 0).err(), Some(VirtioError::BadQueue));
    }

    #[test]
    fn requests_round_trip_and_wrap() {
        let dma = HostDma::default();
        let mut q = VirtQueue::new(&dma, 1, 4).unwrap();
        let mut dev = DeviceSide::new(4, q.addrs());
        let seg = |a: u64, w| Segment { addr: PhysAddr::new(a), len: 10, device_writes: w };

        let h = q.add(&[seg(0x1000, false), seg(0x2000, true)]).unwrap();
        assert_eq!(q.num_free(), 2);
        let (head, chain) = dev.pop_avail().unwrap();
        assert_eq!(head, h);
        assert_eq!(chain, [(0x1000, 10, DESC_F_NEXT), (0x2000, 10, DESC_F_WRITE)]);
        assert!(q.add(&[seg(0, false); 3]).is_err(), "only two free");
        assert!(!q.has_used());
        dev.push_used(head, 7);
        assert_eq!(q.pop_used(), Some((h, 7)));
        assert_eq!(q.num_free(), 4);
        assert_eq!(q.pop_used(), None);

        // Many more requests than entries, so both rings and indices wrap.
        for n in 0..1000u64 {
            let h = q.add(&[seg(n, true)]).unwrap();
            assert_eq!(dev.pop_avail().unwrap().1, [(n, 10, DESC_F_WRITE)]);
            dev.push_used(h, n as u32);
            assert_eq!(q.pop_used(), Some((h, n as u32)));
        }
        assert_eq!(q.num_free(), 4);

        assert!(q.needs_notify());
        dev.set_no_notify(true);
        assert!(!q.needs_notify());
    }
}
