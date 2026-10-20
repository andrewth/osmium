//! Split virtqueues (virtio 1.x §2.7), read from and written to guest memory.

use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

use crate::memory::{GuestMemory, GuestPhysAddr, OutOfBounds};

use osmium_hal::virtio::queue::{AVAIL_F_NO_INTERRUPT, DESC_F_INDIRECT, DESC_F_NEXT, DESC_F_WRITE, DESC_SIZE, avail_entry, used_entry};

/// Why a descriptor chain could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    /// A ring or descriptor lies outside guest memory.
    OutOfBounds(GuestPhysAddr),
    /// A descriptor index is past the end of the table.
    BadIndex(u16),
    /// The chain is longer than the queue, so it loops.
    Loop,
    /// An indirect descriptor; the transport does not offer them.
    Indirect,
}

impl From<OutOfBounds> for QueueError {
    fn from(e: OutOfBounds) -> Self {
        Self::OutOfBounds(e.0)
    }
}

/// One buffer in a descriptor chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Desc {
    /// Guest-physical address of the buffer.
    pub addr: GuestPhysAddr,
    /// Length in bytes.
    pub len: u32,
    /// True if the device writes the buffer, false if it reads it.
    pub write: bool,
}

/// A request popped from the available ring: device-readable buffers
/// followed by device-writable ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescChain {
    /// Index of the first descriptor; hand it back to
    /// [`SplitQueue::add_used`].
    pub head: u16,
    /// The buffers, in chain order.
    pub descs: Vec<Desc>,
}

impl DescChain {
    /// Total length of the device-readable buffers.
    pub fn readable_len(&self) -> usize {
        self.descs.iter().filter(|d| !d.write).map(|d| d.len as usize).sum()
    }

    /// Total length of the device-writable buffers.
    pub fn writable_len(&self) -> usize {
        self.descs.iter().filter(|d| d.write).map(|d| d.len as usize).sum()
    }

    /// Copies the readable buffers, starting `offset` bytes in, into `buf`.
    /// Returns the number of bytes copied.
    pub fn read(&self, mem: &GuestMemory, offset: usize, buf: &mut [u8]) -> Result<usize, QueueError> {
        let mut done = 0;
        Self::walk(self.descs.iter().filter(|d| !d.write), offset, buf.len(), |gpa, at, n| {
            mem.read(gpa, &mut buf[at..at + n])?;
            done += n;
            Ok(())
        })?;
        Ok(done)
    }

    /// Copies `buf` into the writable buffers, starting `offset` bytes in.
    /// Returns the number of bytes copied.
    pub fn write(&self, mem: &GuestMemory, offset: usize, buf: &[u8]) -> Result<usize, QueueError> {
        let mut done = 0;
        Self::walk(self.descs.iter().filter(|d| d.write), offset, buf.len(), |gpa, at, n| {
            mem.write(gpa, &buf[at..at + n])?;
            done += n;
            Ok(())
        })?;
        Ok(done)
    }

    /// Calls `f(gpa, buf_offset, len)` for each piece of `[offset, offset + len)`
    /// across `descs`.
    fn walk<'a>(
        descs: impl Iterator<Item = &'a Desc>,
        mut offset: usize,
        len: usize,
        mut f: impl FnMut(GuestPhysAddr, usize, usize) -> Result<(), OutOfBounds>,
    ) -> Result<(), QueueError> {
        let mut at = 0;
        for d in descs {
            if at == len {
                break;
            }
            let dlen = d.len as usize;
            if offset >= dlen {
                offset -= dlen;
                continue;
            }
            let n = (dlen - offset).min(len - at);
            f(GuestPhysAddr(d.addr.0 + offset as u64), at, n)?;
            at += n;
            offset = 0;
        }
        Ok(())
    }
}

/// The device side of one split virtqueue. The driver programs the size and
/// ring addresses through the transport, then sets it ready.
#[derive(Clone, Debug, Default)]
pub struct SplitQueue {
    /// Number of descriptors.
    pub size: u16,
    /// Whether the driver has enabled the queue.
    pub ready: bool,
    /// Descriptor table.
    pub desc: GuestPhysAddr,
    /// Available (driver) ring.
    pub avail: GuestPhysAddr,
    /// Used (device) ring.
    pub used: GuestPhysAddr,
    last_avail: u16,
    next_used: u16,
}

impl SplitQueue {
    /// A disabled queue with `size` descriptors.
    pub fn new(size: u16) -> Self {
        Self { size, ..Self::default() }
    }

    /// Returns the queue to its post-reset state, keeping `size`.
    pub fn reset(&mut self, size: u16) {
        *self = Self::new(size);
    }

    /// Pops the next available chain, or `None` if the driver has posted
    /// nothing new. A malformed chain is consumed and reported as an error.
    pub fn pop(&mut self, mem: &GuestMemory) -> Option<Result<DescChain, QueueError>> {
        if !self.ready || self.size == 0 {
            return None;
        }
        let avail_idx = match mem.read_obj::<u16>(GuestPhysAddr(self.avail.0 + 2)) {
            Ok(i) => i,
            Err(e) => return Some(Err(e.into())),
        };
        if avail_idx == self.last_avail {
            return None;
        }
        // Read the ring entry only after seeing the index that covers it.
        fence(Ordering::Acquire);
        let slot = self.last_avail % self.size;
        self.last_avail = self.last_avail.wrapping_add(1);
        Some(
            mem.read_obj::<u16>(GuestPhysAddr(self.avail.0 + avail_entry(slot) as u64))
                .map_err(QueueError::from)
                .and_then(|head| self.chain(mem, head)),
        )
    }

    fn chain(&self, mem: &GuestMemory, head: u16) -> Result<DescChain, QueueError> {
        let mut descs = Vec::new();
        let mut i = head;
        loop {
            if i >= self.size {
                return Err(QueueError::BadIndex(i));
            }
            if descs.len() == self.size as usize {
                return Err(QueueError::Loop);
            }
            let raw = mem.read_obj::<[u8; DESC_SIZE]>(GuestPhysAddr(self.desc.0 + (DESC_SIZE * i as usize) as u64))?;
            let addr = u64::from_le_bytes(raw[0..8].try_into().unwrap());
            let len = u32::from_le_bytes(raw[8..12].try_into().unwrap());
            let flags = u16::from_le_bytes([raw[12], raw[13]]);
            let next = u16::from_le_bytes([raw[14], raw[15]]);
            if flags & DESC_F_INDIRECT != 0 {
                return Err(QueueError::Indirect);
            }
            descs.push(Desc { addr: GuestPhysAddr(addr), len, write: flags & DESC_F_WRITE != 0 });
            if flags & DESC_F_NEXT == 0 {
                return Ok(DescChain { head, descs });
            }
            i = next;
        }
    }

    /// Returns chain `head` to the driver, recording that the device wrote
    /// `len` bytes into it. Returns true if the driver wants an interrupt.
    pub fn add_used(&mut self, mem: &GuestMemory, head: u16, len: u32) -> Result<bool, QueueError> {
        let slot = self.next_used % self.size;
        let elem = (head as u64) | (len as u64) << 32;
        mem.write_obj(GuestPhysAddr(self.used.0 + used_entry(slot) as u64), elem.to_le())?;
        self.next_used = self.next_used.wrapping_add(1);
        // Publish the element before the index that exposes it.
        fence(Ordering::Release);
        mem.write_obj(GuestPhysAddr(self.used.0 + 2), self.next_used.to_le())?;
        fence(Ordering::SeqCst);
        let flags = mem.read_obj::<u16>(self.avail)?;
        Ok(flags & AVAIL_F_NO_INTERRUPT == 0)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec;

    pub(crate) const DESC: u64 = 0x0;
    pub(crate) const AVAIL: u64 = 0x1000;
    pub(crate) const USED: u64 = 0x2000;
    pub(crate) const DATA: u64 = 0x3000;

    /// A driver-side helper that lays out rings in guest memory.
    pub(crate) struct Driver {
        pub size: u16,
        pub next_desc: u16,
        pub avail_idx: u16,
    }

    impl Driver {
        pub fn new(size: u16) -> Self {
            Self { size, next_desc: 0, avail_idx: 0 }
        }

        /// Posts a chain of `(gpa, len, write)` buffers; returns its head.
        pub fn post(&mut self, mem: &GuestMemory, bufs: &[(u64, u32, bool)]) -> u16 {
            let head = self.next_desc;
            for (n, &(addr, len, write)) in bufs.iter().enumerate() {
                // Requests complete before the next is posted, so slots can be reused.
                let i = self.next_desc;
                self.next_desc = (i + 1) % self.size;
                let last = n + 1 == bufs.len();
                let flags = if write { DESC_F_WRITE } else { 0 } | if last { 0 } else { DESC_F_NEXT };
                let mut raw = [0u8; 16];
                raw[0..8].copy_from_slice(&addr.to_le_bytes());
                raw[8..12].copy_from_slice(&len.to_le_bytes());
                raw[12..14].copy_from_slice(&flags.to_le_bytes());
                raw[14..16].copy_from_slice(&self.next_desc.to_le_bytes());
                mem.write_obj(GuestPhysAddr(DESC + 16 * i as u64), raw).unwrap();
            }
            let slot = self.avail_idx % self.size;
            mem.write_obj(GuestPhysAddr(AVAIL + 4 + 2 * slot as u64), head).unwrap();
            self.avail_idx += 1;
            mem.write_obj(GuestPhysAddr(AVAIL + 2), self.avail_idx).unwrap();
            head
        }

        pub fn used(&self, mem: &GuestMemory, n: u16) -> (u32, u32) {
            let e: u64 = mem.read_obj(GuestPhysAddr(USED + 4 + 8 * (n % self.size) as u64)).unwrap();
            (e as u32, (e >> 32) as u32)
        }
    }

    pub(crate) fn guest(ram: &mut [u8]) -> GuestMemory {
        let mut mem = GuestMemory::new();
        // SAFETY: the caller keeps `ram` alive and untouched while `mem` exists.
        unsafe { mem.add_region(GuestPhysAddr(0), ram.as_mut_ptr(), ram.len() as u64) };
        mem
    }

    fn ready_queue(size: u16) -> SplitQueue {
        SplitQueue {
            ready: true,
            desc: GuestPhysAddr(DESC),
            avail: GuestPhysAddr(AVAIL),
            used: GuestPhysAddr(USED),
            ..SplitQueue::new(size)
        }
    }

    #[test]
    fn pop_read_write_and_complete() {
        let mut ram = vec![0u8; 0x8000];
        let mem = guest(&mut ram);
        let mut drv = Driver::new(8);
        let mut q = ready_queue(8);
        assert!(q.pop(&mem).is_none());

        mem.write(GuestPhysAddr(DATA), b"hello ").unwrap();
        mem.write(GuestPhysAddr(DATA + 0x100), b"world").unwrap();
        let head = drv.post(&mem, &[(DATA, 6, false), (DATA + 0x100, 5, false), (DATA + 0x200, 4, true), (DATA + 0x300, 8, true)]);

        let c = q.pop(&mem).unwrap().unwrap();
        assert_eq!(c.head, head);
        assert_eq!((c.readable_len(), c.writable_len()), (11, 12));
        let mut buf = [0u8; 16];
        assert_eq!(c.read(&mem, 3, &mut buf).unwrap(), 8);
        assert_eq!(&buf[..8], b"lo world");
        assert_eq!(c.write(&mem, 2, b"0123456789abcdef").unwrap(), 10);
        assert_eq!(&ram_at(&mem, DATA + 0x200, 4), b"\0\x0001");
        assert_eq!(&ram_at(&mem, DATA + 0x300, 8), b"23456789");

        assert!(q.add_used(&mem, c.head, 10).unwrap());
        assert_eq!(mem.read_obj::<u16>(GuestPhysAddr(USED + 2)), Ok(1));
        assert_eq!(drv.used(&mem, 0), (head as u32, 10));
        assert!(q.pop(&mem).is_none());

        // NO_INTERRUPT suppresses the notification.
        mem.write_obj(GuestPhysAddr(AVAIL), AVAIL_F_NO_INTERRUPT).unwrap();
        let h = drv.post(&mem, &[(DATA, 1, false)]);
        let c = q.pop(&mem).unwrap().unwrap();
        assert!(!q.add_used(&mem, h, 0).unwrap());
        assert_eq!(c.head, h);
    }

    #[test]
    fn malformed_chains() {
        let mut ram = vec![0u8; 0x8000];
        let mem = guest(&mut ram);
        let mut q = ready_queue(4);

        // Descriptor 0 points at itself.
        let mut raw = [0u8; 16];
        raw[12..14].copy_from_slice(&DESC_F_NEXT.to_le_bytes());
        mem.write_obj(GuestPhysAddr(DESC), raw).unwrap();
        mem.write_obj(GuestPhysAddr(AVAIL + 4), 0u16).unwrap();
        mem.write_obj(GuestPhysAddr(AVAIL + 2), 1u16).unwrap();
        assert_eq!(q.pop(&mem), Some(Err(QueueError::Loop)));

        // Head index past the table.
        mem.write_obj(GuestPhysAddr(AVAIL + 6), 9u16).unwrap();
        mem.write_obj(GuestPhysAddr(AVAIL + 2), 2u16).unwrap();
        assert_eq!(q.pop(&mem), Some(Err(QueueError::BadIndex(9))));
        assert!(q.pop(&mem).is_none(), "bad chains are consumed");
    }

    fn ram_at(mem: &GuestMemory, gpa: u64, n: usize) -> Vec<u8> {
        let mut v = vec![0; n];
        mem.read(GuestPhysAddr(gpa), &mut v).unwrap();
        v
    }
}
