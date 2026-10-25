use core::sync::atomic::{AtomicU32, Ordering};

use super::{FrameAllocator, FrameKind, PhysMapper};
use crate::addr::{PAGE_SIZE, PhysAddr};

const NIL: u64 = u64::MAX;
const NOT_HEAD: u8 = 0xff;
const MAX_ZONES: usize = 16;
/// Bytes of metadata per managed frame: the order byte at offset 0, the kind
/// byte at `KIND`, two spare bytes, then the reference count at `REFS`.
const SLOT: u64 = 8;
const KIND: usize = 1;
const REFS: usize = 4;

/// Link stored in the first frame of every free block.
#[repr(C)]
struct FreeNode {
    next: u64,
    prev: u64,
}

#[derive(Clone, Copy)]
struct Zone {
    /// First managed frame number.
    first: u64,
    /// One past the last managed frame number.
    end: u64,
    /// One `SLOT` per managed frame: the order of the free block that starts
    /// there (or `NOT_HEAD`), the frame's kind and its reference count.
    meta: PhysAddr,
}

/// A binary buddy allocator over up to 16 discontiguous physical regions.
///
/// Blocks of `2^k` frames (`k < ORDERS`) are aligned to their size in
/// physical address space, so order 9 blocks back 2 MiB pages and order 18
/// blocks back 1 GiB pages. Free lists are intrusive (stored in the free
/// frames themselves through `M`); per-frame metadata takes eight bytes per
/// frame (its order, kind and reference count), carved from the start of
/// each region.
pub struct BuddyAllocator<M: PhysMapper, const ORDERS: usize = 19> {
    mapper: M,
    heads: [u64; ORDERS],
    zones: [Zone; MAX_ZONES],
    nzones: usize,
    free: usize,
}

// SAFETY: the allocator exclusively owns the RAM it manages; moving it to
// another thread moves that ownership.
unsafe impl<M: PhysMapper + Send, const ORDERS: usize> Send for BuddyAllocator<M, ORDERS> {}

impl<M: PhysMapper, const ORDERS: usize> BuddyAllocator<M, ORDERS> {
    /// Creates an allocator that manages nothing yet.
    pub const fn new(mapper: M) -> Self {
        Self {
            mapper,
            heads: [NIL; ORDERS],
            zones: [Zone { first: 0, end: 0, meta: PhysAddr::ZERO }; MAX_ZONES],
            nzones: 0,
            free: 0,
        }
    }

    /// Hands `[start, end)` to the allocator. The range is shrunk to page
    /// boundaries; its first frames hold the metadata. Returns false if the
    /// zone table is full or the range is too small to be worth managing.
    ///
    /// # Safety
    /// The range must be unused RAM, reachable through the mapper, and must
    /// not overlap any range given before.
    pub unsafe fn add_region(&mut self, start: PhysAddr, end: PhysAddr) -> bool {
        let Some(start) = start.checked_align_up(PAGE_SIZE as u64) else { return false };
        let start_pfn = start.0 / PAGE_SIZE as u64;
        let end_pfn = end.align_down(PAGE_SIZE as u64).0 / PAGE_SIZE as u64;
        if self.nzones == MAX_ZONES || end_pfn <= start_pfn {
            return false;
        }
        let frames = end_pfn - start_pfn;
        // `m` metadata frames hold `m * PAGE_SIZE / SLOT` slots, and `frames - m` of them are needed.
        let meta_frames = frames.div_ceil(PAGE_SIZE as u64 / SLOT + 1);
        if frames <= meta_frames {
            return false;
        }
        let zone =
            Zone { first: start_pfn + meta_frames, end: end_pfn, meta: PhysAddr::new(start_pfn * PAGE_SIZE as u64) };
        for i in 0..zone.end - zone.first {
            let slot = self.mapper.phys_to_virt(zone.meta + i * SLOT);
            // SAFETY: the metadata frames are part of the caller-provided free range,
            // and hold a slot for every managed frame.
            unsafe {
                slot.write(NOT_HEAD);
                slot.add(KIND).write(FrameKind::Free as u8);
                slot.add(REFS).cast::<u32>().write(0);
            }
        }
        let Some(slot) = self.zones.get_mut(self.nzones) else { return false };
        *slot = zone;
        self.nzones += 1;

        // Carve the range into maximal aligned blocks.
        let mut pfn = zone.first;
        while pfn < zone.end {
            let mut k = (ORDERS - 1) as u32;
            while k > 0 && (!pfn.is_multiple_of(1 << k) || pfn + (1 << k) > zone.end) {
                k -= 1;
            }
            self.push(pfn, k);
            self.free += 1 << k;
            pfn += 1 << k;
        }
        true
    }

    fn zone_of(&self, pfn: u64) -> Option<Zone> {
        self.zones.iter().take(self.nzones).find(|z| (z.first..z.end).contains(&pfn)).copied()
    }

    /// The metadata slot of `pfn`, or `None` if the frame is not managed.
    /// Its first byte is the order byte.
    fn meta(&self, pfn: u64) -> Option<*mut u8> {
        let z = self.zone_of(pfn)?;
        Some(self.mapper.phys_to_virt(z.meta + (pfn - z.first) * SLOT))
    }

    fn kind_at(&self, pfn: u64) -> Option<FrameKind> {
        // SAFETY: `meta` only returns pointers to the metadata of managed frames.
        FrameKind::from_u8(unsafe { *self.meta(pfn)?.add(KIND) })
    }

    fn set_kind_at(&mut self, pfn: u64, kind: FrameKind) -> bool {
        match self.meta(pfn) {
            Some(m) => {
                // SAFETY: `meta` only returns pointers to the metadata of managed frames.
                unsafe { *m.add(KIND) = kind as u8 };
                true
            }
            None => false,
        }
    }

    fn refs_at(&self, pfn: u64) -> Option<&AtomicU32> {
        // SAFETY: `meta` only returns pointers to the metadata of managed frames. The
        // count is 4-byte aligned and only ever accessed atomically.
        self.meta(pfn).map(|m| unsafe { &*m.add(REFS).cast::<AtomicU32>() })
    }

    /// Reads the metadata byte of `pfn`; `NOT_HEAD` for an unmanaged frame.
    fn meta_get(&self, pfn: u64) -> u8 {
        // SAFETY: `meta` only returns pointers to the metadata of managed frames.
        self.meta(pfn).map_or(NOT_HEAD, |m| unsafe { *m })
    }

    fn meta_set(&mut self, pfn: u64, v: u8) {
        if let Some(m) = self.meta(pfn) {
            // SAFETY: `meta` only returns pointers to the metadata of managed frames.
            unsafe { *m = v };
        }
    }

    fn head(&self, k: u32) -> u64 {
        self.heads.get(k as usize).copied().unwrap_or(NIL)
    }

    fn set_head(&mut self, k: u32, pfn: u64) {
        if let Some(h) = self.heads.get_mut(k as usize) {
            *h = pfn;
        }
    }

    /// Whether the block of order `k` at `pfn` is already free, in full or
    /// in part: its first frame heads a free block of any order, or a larger
    /// free block contains it.
    fn is_free(&self, zone: Zone, pfn: u64, k: u32) -> bool {
        if self.meta_get(pfn) != NOT_HEAD {
            return true;
        }
        (k + 1..ORDERS as u32).any(|j| {
            let head = pfn & !((1 << j) - 1);
            head >= zone.first && self.meta_get(head) == j as u8
        })
    }

    fn node(&self, pfn: u64) -> *mut FreeNode {
        self.mapper.phys_to_virt(PhysAddr::new(pfn * PAGE_SIZE as u64)).cast()
    }

    fn push(&mut self, pfn: u64, k: u32) {
        let head = self.head(k);
        // SAFETY: `pfn` heads a free block we own; `head`, if any, too.
        unsafe {
            self.node(pfn).write(FreeNode { next: head, prev: NIL });
            if head != NIL {
                (*self.node(head)).prev = pfn;
            }
        }
        self.meta_set(pfn, k as u8);
        self.set_head(k, pfn);
    }

    fn remove(&mut self, pfn: u64, k: u32) {
        // SAFETY: `pfn` heads a free block of order `k`, and its neighbours in
        // the list are free blocks too.
        unsafe {
            let FreeNode { next, prev } = self.node(pfn).read();
            if prev == NIL {
                self.set_head(k, next);
            } else {
                (*self.node(prev)).next = next;
            }
            if next != NIL {
                (*self.node(next)).prev = prev;
            }
        }
        self.meta_set(pfn, NOT_HEAD);
    }
}

// SAFETY: a block is either on exactly one free list (and marked in the
// metadata) or allocated; `alloc` removes it from its list before returning,
// and `dealloc` panics rather than list a block that is already free.
unsafe impl<M: PhysMapper, const ORDERS: usize> FrameAllocator for BuddyAllocator<M, ORDERS> {
    fn alloc(&mut self, order: u32) -> Option<PhysAddr> {
        let mut k = (order as usize..ORDERS).find(|&k| self.head(k as u32) != NIL)? as u32;
        let pfn = self.head(k);
        self.remove(pfn, k);
        while k > order {
            k -= 1;
            self.push(pfn + (1 << k), k);
        }
        self.free -= 1 << order;
        for f in pfn..pfn + (1 << order) {
            self.set_kind_at(f, FrameKind::Allocated);
        }
        Some(PhysAddr::new(pfn * PAGE_SIZE as u64))
    }

    /// Ignores frames this allocator does not manage. Panics, in release
    /// builds too, on a double free (the block, or a larger free block
    /// around it, is already free) and on a block misaligned for `order`
    /// (kernel bugs, never reachable from outside input). Listing a
    /// free block a second time would hand the same frames out twice, so
    /// stopping is the safer choice: the caller's ownership tracking is
    /// already broken, and something may still be using the memory. A block
    /// that is only partly free (a smaller free block inside it, not at its
    /// start) is not detected.
    unsafe fn dealloc(&mut self, pa: PhysAddr, order: u32) {
        let mut pfn = pa.0 / PAGE_SIZE as u64;
        let Some(zone) = self.zone_of(pfn) else {
            // Not ours: nothing to give back.
            return;
        };
        assert!((order as usize) < ORDERS, "free of {pa:?} with the wrong order {order}");
        assert!(
            pa.is_aligned(PAGE_SIZE as u64) && pfn.is_multiple_of(1 << order) && pfn + (1 << order) <= zone.end,
            "free of {pa:?} with the wrong order {order}"
        );
        assert!(!self.is_free(zone, pfn, order), "double free of {pa:?} (order {order})");
        for f in pfn..pfn + (1 << order) {
            assert!(self.refs_at(f).is_some_and(|r| r.load(Ordering::Acquire) == 0), "free of {pa:?} while referenced");
            self.set_kind_at(f, FrameKind::Free);
        }
        let mut k = order;
        while (k as usize) + 1 < ORDERS {
            let buddy = pfn ^ (1 << k);
            if buddy < zone.first || buddy + (1 << k) > zone.end {
                break;
            }
            if self.meta_get(buddy) != k as u8 {
                break;
            }
            self.remove(buddy, k);
            pfn = pfn.min(buddy);
            k += 1;
        }
        self.push(pfn, k);
        self.free += 1 << order;
    }

    fn free_frames(&self) -> usize {
        self.free
    }

    fn kind(&self, pa: PhysAddr) -> Option<FrameKind> {
        self.kind_at(pa.0 / PAGE_SIZE as u64)
    }

    fn set_kind(&mut self, pa: PhysAddr, kind: FrameKind) -> bool {
        self.set_kind_at(pa.0 / PAGE_SIZE as u64, kind)
    }

    fn refs(&self, pa: PhysAddr) -> Option<u32> {
        self.refs_at(pa.0 / PAGE_SIZE as u64).map(|r| r.load(Ordering::Acquire))
    }

    fn claim(&self, pa: PhysAddr) -> bool {
        self.refs_at(pa.0 / PAGE_SIZE as u64)
            .is_some_and(|r| r.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok())
    }

    fn retain(&self, pa: PhysAddr) -> Option<u32> {
        step_refs(self.refs_at(pa.0 / PAGE_SIZE as u64)?, |n| if n == 0 { None } else { n.checked_add(1) })
    }

    fn release(&self, pa: PhysAddr) -> Option<u32> {
        step_refs(self.refs_at(pa.0 / PAGE_SIZE as u64)?, |n| n.checked_sub(1))
    }
}

/// Moves a reference count to `next(count)` atomically, returning the new count, or `None` if `next` refuses.
fn step_refs(refs: &AtomicU32, next: impl Fn(u32) -> Option<u32>) -> Option<u32> {
    let mut n = refs.load(Ordering::Acquire);
    loop {
        let to = next(n)?;
        match refs.compare_exchange_weak(n, to, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(to),
            Err(now) => n = now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::testmem::SimRam;
    use std::vec::Vec;

    #[test]
    fn split_and_coalesce() {
        let ram = SimRam::new(0x8000_0000, 4 << 20);
        let mut b: BuddyAllocator<_, 12> = BuddyAllocator::new(&ram);
        // SAFETY: simulated RAM, owned by this test.
        assert!(unsafe { b.add_region(ram.base, ram.end()) });
        let initial = b.free_frames();
        assert_eq!(initial, 1024 - 2, "two metadata frames: 8 bytes of metadata per frame");

        let a = b.alloc(0).unwrap();
        let c = b.alloc(4).unwrap();
        assert!(c.is_aligned(16 * 4096));
        assert_ne!(a, c);
        assert_eq!(b.free_frames(), initial - 17);
        // SAFETY: returning our allocations.
        unsafe {
            b.dealloc(a, 0);
            b.dealloc(c, 4);
        }
        assert_eq!(b.free_frames(), initial);
        // Everything coalesced back: a 2 MiB block is available again.
        let big = b.alloc(9).unwrap();
        assert!(big.is_aligned(2 << 20));
    }

    #[test]
    #[should_panic(expected = "double free")]
    fn double_free_is_caught() {
        let ram = SimRam::new(0x8000_0000, 1 << 20);
        let mut b: BuddyAllocator<_, 12> = BuddyAllocator::new(&ram);
        // SAFETY: simulated RAM, owned by this test.
        unsafe { b.add_region(ram.base, ram.end()) };
        let a = b.alloc(0).unwrap();
        // SAFETY: the first free is legitimate; the second is the bug under test.
        unsafe {
            b.dealloc(a, 0);
            b.dealloc(a, 0);
        }
    }

    #[test]
    #[should_panic(expected = "double free")]
    fn double_free_after_coalescing_is_caught() {
        let ram = SimRam::new(0x8000_0000, 1 << 20);
        let mut b: BuddyAllocator<_, 12> = BuddyAllocator::new(&ram);
        // SAFETY: simulated RAM, owned by this test.
        unsafe { b.add_region(ram.base, ram.end()) };
        let a = b.alloc(0).unwrap();
        let c = b.alloc(0).unwrap();
        // SAFETY: `a` and `c` are buddies and merge into one free block, which
        // the second free of `c` falls inside: the bug under test.
        unsafe {
            b.dealloc(a, 0);
            b.dealloc(c, 0);
            b.dealloc(c, 0);
        }
    }

    #[test]
    fn exhaust_and_refill() {
        let ram = SimRam::new(0x4000_0000, 1 << 20);
        let mut b: BuddyAllocator<_> = BuddyAllocator::new(&ram);
        // SAFETY: simulated RAM, owned by this test.
        unsafe { b.add_region(ram.base + 0x3000, ram.end()) };
        let mut got = Vec::new();
        while let Some(f) = b.alloc(0) {
            // Each frame is writable and distinct.
            // SAFETY: the frame is ours.
            unsafe { ram.phys_to_virt(f).write_bytes(0xab, PAGE_SIZE) };
            got.push(f);
        }
        let n = got.len();
        got.sort();
        got.dedup();
        assert_eq!(got.len(), n);
        assert_eq!(b.free_frames(), 0);
        for f in got.iter().rev() {
            // SAFETY: returning our allocations.
            unsafe { b.dealloc(*f, 0) };
        }
        assert_eq!(b.free_frames(), n);
    }

    #[test]
    fn references_count_up_and_down() {
        let ram = SimRam::new(0x8000_0000, 1 << 20);
        let mut b: BuddyAllocator<_, 12> = BuddyAllocator::new(&ram);
        // SAFETY: simulated RAM, owned by this test.
        unsafe { b.add_region(ram.base, ram.end()) };
        let a = b.alloc(0).unwrap();
        assert_eq!(b.refs(a), Some(0), "allocated, not yet referenced");
        assert_eq!(b.retain(a), None, "only a claimed frame can gain references");
        assert!(b.claim(a));
        assert!(!b.claim(a), "the first reference is taken once");
        assert_eq!(b.retain(a), Some(2));
        assert_eq!(b.release(a), Some(1));
        assert_eq!(b.release(a), Some(0), "the frame stays allocated at zero");
        assert_eq!(b.release(a), None, "nothing left to drop");
        assert_eq!(b.refs(PhysAddr::new(0x1234_0000)), None, "not managed");
        // SAFETY: returning our allocation, which has no references.
        unsafe { b.dealloc(a, 0) };
    }

    #[test]
    fn kinds_follow_allocation() {
        let ram = SimRam::new(0x8000_0000, 1 << 20);
        let mut b: BuddyAllocator<_, 12> = BuddyAllocator::new(&ram);
        // SAFETY: simulated RAM, owned by this test.
        unsafe { b.add_region(ram.base, ram.end()) };
        let a = b.alloc(2).unwrap();
        for i in 0..4 {
            assert_eq!(b.kind(a + i * PAGE_SIZE as u64), Some(FrameKind::Allocated));
        }
        assert!(b.set_kind(a, FrameKind::Table));
        assert_eq!(b.kind(a), Some(FrameKind::Table));
        // SAFETY: returning our allocation, which has no references.
        unsafe { b.dealloc(a, 2) };
        assert_eq!(b.kind(a), Some(FrameKind::Free));
        assert!(!b.set_kind(PhysAddr::new(0x1234_0000), FrameKind::User), "not managed");
    }

    #[test]
    #[should_panic(expected = "while referenced")]
    fn freeing_a_referenced_frame_is_caught() {
        let ram = SimRam::new(0x8000_0000, 1 << 20);
        let mut b: BuddyAllocator<_, 12> = BuddyAllocator::new(&ram);
        // SAFETY: simulated RAM, owned by this test.
        unsafe { b.add_region(ram.base, ram.end()) };
        let a = b.alloc(0).unwrap();
        assert!(b.claim(a));
        // SAFETY: the bug under test: the frame still has a reference.
        unsafe { b.dealloc(a, 0) };
    }
}
