//! The address range `mmap` hands out, and which parts of it are free.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::ops::Range;

use osmium_fs::Errno;
use osmium_sync::arc::ArcTree;
use osmium_sync::fallible::{OutOfMemory, try_arc};
use osmium_sync::intrusive::{Adapter, KeyAdapter, Shared, TreeLink};

/// One free part of the area: `start..end`. The tree that holds it is
/// ordered by `start`, which changes only to a larger value that is still
/// below the next range's start, so the order holds.
pub(crate) struct FreeRange {
    start: UnsafeCell<u64>,
    end: UnsafeCell<u64>,
    link: Shared<TreeLink>,
}

// SAFETY: the fields are only read or written by the `MmapArea` that holds
// the range (or by whoever holds a range that no area holds yet), under the
// lock around the area.
unsafe impl Sync for FreeRange {}

impl FreeRange {
    /// A range that is not in any area yet, for [`MmapArea::release`] to use
    /// if it needs one. Allocated by the caller, where running out of memory
    /// can still be reported.
    pub(crate) fn spare() -> Result<Arc<Self>, OutOfMemory> {
        Self::new(0, 0)
    }

    fn new(start: u64, end: u64) -> Result<Arc<Self>, OutOfMemory> {
        try_arc(Self { start: UnsafeCell::new(start), end: UnsafeCell::new(end), link: Shared::new(TreeLink::new()) })
    }

    fn start(&self) -> u64 {
        // SAFETY: see the `Sync` impl.
        unsafe { *self.start.get() }
    }

    fn end(&self) -> u64 {
        // SAFETY: as above.
        unsafe { *self.end.get() }
    }

    fn set(&self, start: u64, end: u64) {
        // SAFETY: as above.
        unsafe {
            *self.start.get() = start;
            *self.end.get() = end;
        }
    }

    fn len(&self) -> u64 {
        self.end().saturating_sub(self.start())
    }
}

struct ByStart;

// SAFETY: `offset_of!` of a `Shared<TreeLink>`, which is a `TreeLink`.
unsafe impl Adapter<TreeLink> for ByStart {
    type Value = FreeRange;
    const OFFSET: usize = offset_of!(FreeRange, link);
}

impl KeyAdapter<TreeLink> for ByStart {
    type Key = u64;

    fn key(range: &FreeRange) -> &u64 {
        // SAFETY: see the `Sync` impl; the reference is only used to compare.
        unsafe { &*range.start.get() }
    }
}

/// The `mmap` area: a range of addresses and the free parts of it, as
/// non-adjacent ranges. Allocation is first fit; freeing merges neighbours,
/// so mapping and unmapping can go on for ever.
///
/// Allocating never allocates memory. Freeing needs a range of its own only
/// when it leaves a new gap, and takes the spare that the caller made
/// beforehand (see [`FreeRange::spare`]), so it cannot fail either.
pub(crate) struct MmapArea {
    start: u64,
    end: u64,
    free: ArcTree<ByStart>,
    /// Bytes in the free ranges.
    free_bytes: u64,
    /// Most bytes of the area that may be in use at once.
    pub(crate) limit: u64,
}

impl MmapArea {
    pub(crate) fn new(range: Range<u64>) -> Result<Self, OutOfMemory> {
        let mut free = ArcTree::new();
        let mut free_bytes = 0;
        // An empty or inverted range is an area with no addresses.
        let range = if range.start < range.end { range } else { 0..0 };
        if range.start < range.end {
            let r = FreeRange::new(range.start, range.end)?;
            // The tree is empty, so the insert cannot find a duplicate key.
            let _ = free.insert(r);
            free_bytes = range.end - range.start;
        }
        Ok(Self { start: range.start, end: range.end, free, free_bytes, limit: u64::MAX })
    }

    /// A copy for a forked process.
    pub(crate) fn try_clone(&self) -> Result<Self, OutOfMemory> {
        let mut free = ArcTree::new();
        for r in self.free.iter() {
            // The source tree holds distinct starts, so the insert cannot find a duplicate key.
            let _ = free.insert(FreeRange::new(r.start(), r.end())?);
        }
        Ok(Self { start: self.start, end: self.end, free, free_bytes: self.free_bytes, limit: self.limit })
    }

    /// Bytes of the area in use.
    fn used(&self) -> u64 {
        (self.end - self.start).saturating_sub(self.free_bytes)
    }

    /// Takes the first free range that holds `len` bytes.
    pub(crate) fn alloc(&mut self, len: u64) -> Result<u64, Errno> {
        if self.used().checked_add(len).is_none_or(|u| u > self.limit) {
            return Err(Errno::ENOMEM);
        }
        let (s, exact) = {
            let r = self.free.iter().find(|r| r.len() >= len).ok_or(Errno::ENOMEM)?;
            (r.start(), r.len() == len)
        };
        if exact {
            // Nothing is left of it. Its memory is freed here, which is
            // allowed under the area's lock.
            drop(self.free.take_key(&s));
        } else if let Some(r) = self.free.find(&s) {
            r.set(s + len, r.end());
        }
        self.free_bytes = self.free_bytes.saturating_sub(len);
        Ok(s)
    }

    /// Returns `from..to` (clipped to the area) to the free ranges. Parts
    /// that are already free stay so. `spare` becomes the new range if the
    /// parts do not merge with an existing one.
    pub(crate) fn release(&mut self, from: u64, to: u64, spare: Arc<FreeRange>) {
        let (mut from, mut to) = (from.max(self.start), to.min(self.end));
        if from >= to {
            return;
        }
        // Existing free bytes the new range absorbs.
        let mut absorbed = 0;
        let mut node = None;
        // Merge with a free range that touches or overlaps on the left...
        if let Some((s, e)) = self.free.floor(&from).map(|r| (r.start(), r.end()))
            && e >= from
        {
            node = self.free.take_key(&s);
            absorbed += e - s;
            from = s;
            to = to.max(e);
        }
        // ...and with every one that starts inside or right at the end.
        while let Some((s, e)) = self.free.lower_bound(&from).map(|r| (r.start(), r.end()))
            && s <= to
        {
            let taken = self.free.take_key(&s);
            node = node.or(taken);
            absorbed += e - s;
            to = to.max(e);
        }
        let node = node.unwrap_or(spare);
        node.set(from, to);
        // Every range with a start inside `from..=to` was taken out above, so the key is free.
        let _ = self.free.insert(node);
        self.free_bytes = self.free_bytes.saturating_add((to - from).saturating_sub(absorbed));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const P: u64 = 0x1000;

    fn area(pages: u64) -> MmapArea {
        MmapArea::new(0x10_0000..0x10_0000 + pages * P).unwrap()
    }

    fn free(a: &MmapArea) -> Vec<(u64, u64)> {
        a.free.iter().map(|r| (r.start(), r.end())).collect()
    }

    fn release(a: &mut MmapArea, from: u64, to: u64) {
        a.release(from, to, FreeRange::spare().unwrap());
    }

    #[test]
    fn allocation_is_first_fit_and_exact_fits_use_the_range_up() {
        let mut a = area(8);
        let (x, y, z) = (a.alloc(2 * P).unwrap(), a.alloc(P).unwrap(), a.alloc(3 * P).unwrap());
        assert_eq!((x, y, z), (0x10_0000, 0x10_2000, 0x10_3000));
        assert_eq!(free(&a), [(0x10_6000, 0x10_8000)]);
        assert_eq!(a.alloc(3 * P), Err(Errno::ENOMEM), "not enough contiguous space");
        assert_eq!(a.alloc(2 * P), Ok(0x10_6000));
        assert!(free(&a).is_empty());
        assert_eq!(a.alloc(P), Err(Errno::ENOMEM));
    }

    #[test]
    fn freeing_merges_neighbours_on_both_sides() {
        let mut a = area(8);
        let base = a.alloc(8 * P).unwrap();
        release(&mut a, base + P, base + 2 * P);
        release(&mut a, base + 5 * P, base + 6 * P);
        assert_eq!(free(&a), [(base + P, base + 2 * P), (base + 5 * P, base + 6 * P)]);
        release(&mut a, base + 2 * P, base + 5 * P);
        assert_eq!(free(&a), [(base + P, base + 6 * P)], "one range again");
        // Overlapping what is already free changes nothing but the edges.
        release(&mut a, base, base + 7 * P);
        assert_eq!(free(&a), [(base, base + 7 * P)]);
        assert_eq!(a.used(), P);
        // Outside the area is ignored.
        release(&mut a, 0, 0x1000);
        release(&mut a, base + 7 * P, base + 100 * P);
        assert_eq!(free(&a), [(base, base + 8 * P)]);
        assert_eq!(a.used(), 0);
    }

    #[test]
    fn the_limit_counts_what_is_in_use() {
        let mut a = area(8);
        a.limit = 3 * P;
        let x = a.alloc(2 * P).unwrap();
        assert_eq!(a.alloc(2 * P), Err(Errno::ENOMEM));
        release(&mut a, x, x + 2 * P);
        assert!(a.alloc(3 * P).is_ok());
    }

    #[test]
    fn a_clone_is_independent() {
        let mut a = area(4);
        a.alloc(P).unwrap();
        let mut b = a.try_clone().unwrap();
        assert_eq!(free(&a), free(&b));
        b.alloc(P).unwrap();
        assert_ne!(free(&a), free(&b));
        assert_eq!(a.used(), P);
        assert_eq!(b.used(), 2 * P);
    }

    #[test]
    fn an_empty_area_has_nothing_to_give() {
        let mut a = MmapArea::new(0..0).unwrap();
        assert_eq!(a.alloc(P), Err(Errno::ENOMEM));
        release(&mut a, 0, P);
        assert!(free(&a).is_empty());
    }
}
