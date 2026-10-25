//! Virtual memory areas: the address ranges of a space that are reserved for
//! something, and with which permissions.
//!
//! A [`VmaTree`] is an ordered set of non-overlapping `start..end` ranges
//! with [`MapFlags`]. It records what *may* be mapped, separately from what
//! the page table maps right now, which is what makes demand paging
//! possible: a page fault inside an area that has no page yet is the cue to
//! make one, and a fault outside every area is a real error.
//!
//! Nodes are `Arc`s allocated with [`try_arc`], so running out of memory is
//! an error value, never a panic. Operations that can need a node (a split,
//! or a new area that does not extend a neighbour) either allocate before
//! they change anything, or take a node the caller allocated earlier
//! ([`VmaSpare`]) and so cannot fail; see each method.
//!
//! The tree does not know about page tables or frames. The owner of a space
//! keeps the two in step: [`VmaTree::remove`] after unmapping pages,
//! [`VmaTree::protect`] along with `PageTable::protect`.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::mem::offset_of;

use osmium_sync::arc::ArcTree;
use osmium_sync::fallible::{OutOfMemory, try_arc};
use osmium_sync::intrusive::{Adapter, KeyAdapter, Shared, TreeLink};

use crate::paging::MapFlags;

/// One area in a [`VmaTree`]. Ordered by `start`, which only ever changes to
/// a value that is still above the previous area's end and below the next
/// area's start, so the order holds.
struct Vma {
    start: UnsafeCell<u64>,
    end: UnsafeCell<u64>,
    flags: UnsafeCell<MapFlags>,
    link: Shared<TreeLink>,
}

// SAFETY: the fields are only read or written through the `VmaTree` that
// holds the node (which needs `&mut` to write), or by whoever holds a node
// that no tree holds yet.
unsafe impl Sync for Vma {}

impl Vma {
    fn new(start: u64, end: u64, flags: MapFlags) -> Result<Arc<Self>, OutOfMemory> {
        try_arc(Self {
            start: UnsafeCell::new(start),
            end: UnsafeCell::new(end),
            flags: UnsafeCell::new(flags),
            link: Shared::new(TreeLink::new()),
        })
    }

    fn start(&self) -> u64 {
        // SAFETY: see the `Sync` impl.
        unsafe { *self.start.get() }
    }

    fn end(&self) -> u64 {
        // SAFETY: as above.
        unsafe { *self.end.get() }
    }

    fn flags(&self) -> MapFlags {
        // SAFETY: as above.
        unsafe { *self.flags.get() }
    }

    fn set(&self, start: u64, end: u64, flags: MapFlags) {
        // SAFETY: as above; callers hold the tree mutably or own the node.
        unsafe {
            *self.start.get() = start;
            *self.end.get() = end;
            *self.flags.get() = flags;
        }
    }

    fn info(&self) -> VmaInfo {
        VmaInfo { start: self.start(), end: self.end(), flags: self.flags() }
    }
}

struct ByStart;

// SAFETY: `offset_of!` of a `Shared<TreeLink>`, which is a `TreeLink`.
unsafe impl Adapter<TreeLink> for ByStart {
    type Value = Vma;
    const OFFSET: usize = offset_of!(Vma, link);
}

impl KeyAdapter<TreeLink> for ByStart {
    type Key = u64;

    fn key(vma: &Vma) -> &u64 {
        // SAFETY: see the `Sync` impl; the reference is only used to compare.
        unsafe { &*vma.start.get() }
    }
}

/// A copy of one area's description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmaInfo {
    /// First address of the area.
    pub start: u64,
    /// First address past the area.
    pub end: u64,
    /// The permissions of its pages.
    pub flags: MapFlags,
}

impl VmaInfo {
    /// Whether the area holds `addr`.
    pub const fn contains(&self, addr: u64) -> bool {
        self.start <= addr && addr < self.end
    }
}

/// Why a [`VmaTree`] operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmaError {
    /// The range is empty or inverted.
    Invalid,
    /// The range overlaps an existing area.
    Overlap,
    /// Part of the range is in no area.
    Unmapped,
    /// A node could not be allocated; the tree is unchanged.
    OutOfMemory,
}

impl From<OutOfMemory> for VmaError {
    fn from(_: OutOfMemory) -> Self {
        Self::OutOfMemory
    }
}

/// A node allocated ahead of time, for an operation that must not fail
/// ([`VmaTree::remove`]).
pub struct VmaSpare(Arc<Vma>);

impl VmaSpare {
    /// Allocates one.
    pub fn new() -> Result<Self, OutOfMemory> {
        Vma::new(0, 0, MapFlags::NONE).map(Self)
    }
}

/// The areas of one address space.
#[derive(Default)]
pub struct VmaTree {
    tree: ArcTree<ByStart>,
}

impl VmaTree {
    /// An empty tree.
    pub const fn new() -> Self {
        Self { tree: ArcTree::new() }
    }

    /// Number of areas. Adjacent areas with equal flags are merged by
    /// [`insert`](Self::insert) but not by [`protect`](Self::protect).
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Whether there are no areas.
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// The areas in address order.
    pub fn iter(&self) -> impl Iterator<Item = VmaInfo> + '_ {
        self.tree.iter().map(Vma::info)
    }

    /// The area that holds `addr`.
    pub fn find(&self, addr: u64) -> Option<VmaInfo> {
        self.tree.floor(&addr).map(Vma::info).filter(|v| v.contains(addr))
    }

    /// The first area (lowest address) that overlaps `from..end`.
    pub fn first_overlap(&self, from: u64, end: u64) -> Option<VmaInfo> {
        if from >= end {
            return None;
        }
        let below = self.tree.floor(&from).map(Vma::info).filter(|v| v.end > from);
        below.or_else(|| self.tree.lower_bound(&from).map(Vma::info)).filter(|v| v.start < end)
    }

    /// Whether any area overlaps `start..end`.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.first_overlap(start, end).is_some()
    }

    /// The lowest address in `lo..hi` where `len` bytes fit between areas
    /// (first fit). `len` is not rounded; callers pass a page multiple.
    pub fn find_gap(&self, len: u64, lo: u64, hi: u64) -> Option<u64> {
        let mut at = lo;
        loop {
            let end = at.checked_add(len).filter(|&e| e <= hi)?;
            match self.first_overlap(at, end) {
                None => return Some(at),
                Some(v) => at = v.end,
            }
        }
    }

    /// A copy, for a forked space.
    pub fn try_clone(&self) -> Result<Self, OutOfMemory> {
        let mut copy = Self::new();
        for v in self.tree.iter() {
            // The source holds distinct starts, so the insert cannot find a duplicate.
            let _ = copy.tree.insert(Vma::new(v.start(), v.end(), v.flags())?);
        }
        Ok(copy)
    }

    /// Adds the area `start..end`. An area next to it with the same flags is
    /// extended instead of a node being added, so merging never allocates;
    /// otherwise one node is allocated, before anything changes.
    pub fn insert(&mut self, start: u64, end: u64, flags: MapFlags) -> Result<(), VmaError> {
        if start >= end {
            return Err(VmaError::Invalid);
        }
        if self.overlaps(start, end) {
            return Err(VmaError::Overlap);
        }
        let left = self.tree.floor(&start).filter(|v| v.end() == start && v.flags() == flags).map(Vma::start);
        let right = self.tree.find(&end).filter(|v| v.flags() == flags).map(Vma::end);
        match (left, right) {
            (Some(l), Some(r)) => {
                // Absorb the right area into the left one.
                drop(self.tree.take_key(&end));
                if let Some(v) = self.tree.find(&l) {
                    v.set(l, r, flags);
                }
            }
            (Some(l), None) => {
                if let Some(v) = self.tree.find(&l) {
                    v.set(l, end, flags);
                }
            }
            (None, Some(r)) => {
                // Moving the start down keeps the order: nothing lies in between.
                if let Some(v) = self.tree.find(&end) {
                    v.set(start, r, flags);
                }
            }
            (None, None) => {
                // The range overlaps nothing, so the start is free.
                let _ = self.tree.insert(Vma::new(start, end, flags)?);
            }
        }
        Ok(())
    }

    /// Splits the area that has `addr` strictly inside it into two, using
    /// `spare` for the upper half. Without a spare the upper half is
    /// forgotten. Returns false only in that case.
    fn split_at(&mut self, addr: u64, spare: Option<VmaSpare>) -> bool {
        let Some(v) = self.tree.floor(&addr).filter(|v| v.start() < addr && addr < v.end()) else { return true };
        let (end, flags) = (v.end(), v.flags());
        v.set(v.start(), addr, flags);
        match spare {
            Some(VmaSpare(node)) => {
                node.set(addr, end, flags);
                // The key `addr` was inside the old area, so no area starts there.
                let _ = self.tree.insert(node);
                true
            }
            None => false,
        }
    }

    /// Whether [`remove`](Self::remove) of `start..end` needs a spare: when
    /// one area extends both below `start` and above `end`.
    pub fn needs_spare(&self, start: u64, end: u64) -> bool {
        self.tree.floor(&start).is_some_and(|v| v.start() < start && end < v.end())
    }

    /// Removes `start..end` from the areas, trimming or splitting the ones
    /// it cuts into. Never fails. A split needs `spare` (see
    /// [`needs_spare`](Self::needs_spare)); without one, the part of the
    /// split area above `end` is forgotten too, and this returns false.
    pub fn remove(&mut self, start: u64, end: u64, spare: Option<VmaSpare>) -> bool {
        if start >= end {
            return true;
        }
        let whole = if self.needs_spare(start, end) { self.split_at(end, spare) } else { true };
        // No area straddles both edges now. Each one left overlapping is
        // deleted, or loses the part inside the range.
        while let Some(v) = self.first_overlap(start, end) {
            if v.start >= start && v.end <= end {
                drop(self.tree.take_key(&v.start));
            } else if let Some(n) = self.tree.find(&v.start) {
                if v.start < start {
                    n.set(v.start, start, v.flags);
                } else {
                    // Its start moves up to `end`, still below the next area.
                    n.set(end, v.end, v.flags);
                }
            }
        }
        whole
    }

    /// Gives every part of `start..end` the flags `flags`, splitting the
    /// areas at its edges. The whole range must be in areas. Nodes for the
    /// splits are allocated before anything changes.
    pub fn protect(&mut self, start: u64, end: u64, flags: MapFlags) -> Result<(), VmaError> {
        if start >= end {
            return Err(VmaError::Invalid);
        }
        // Covered without a gap?
        let mut at = start;
        while at < end {
            match self.find(at) {
                Some(v) => at = v.end,
                None => return Err(VmaError::Unmapped),
            }
        }
        let lower = self.tree.floor(&start).is_some_and(|v| v.start() < start);
        let upper = self.tree.floor(&(end - 1)).is_some_and(|v| v.end() > end);
        let a = if lower { Some(VmaSpare::new()?) } else { None };
        let b = if upper { Some(VmaSpare::new()?) } else { None };
        self.split_at(start, a);
        self.split_at(end, b);
        let mut at = start;
        while let Some(v) = self.first_overlap(at, end) {
            if let Some(n) = self.tree.find(&v.start) {
                n.set(v.start, v.end, flags);
            }
            at = v.end;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const R: MapFlags = MapFlags::READ;
    const RW: MapFlags = MapFlags::RW;
    const N: MapFlags = MapFlags::NONE;

    fn dump(t: &VmaTree) -> Vec<(u64, u64, MapFlags)> {
        t.iter().map(|v| (v.start, v.end, v.flags)).collect()
    }

    #[test]
    fn insert_find_and_overlap() {
        let mut t = VmaTree::new();
        t.insert(0x1000, 0x3000, RW).unwrap();
        t.insert(0x5000, 0x6000, R).unwrap();
        assert_eq!(t.find(0x1000).unwrap().flags, RW);
        assert_eq!(t.find(0x2fff).unwrap().end, 0x3000);
        assert_eq!(t.find(0x3000), None);
        assert_eq!(t.find(0x5000).unwrap().flags, R);
        assert_eq!(t.insert(0x2000, 0x4000, R), Err(VmaError::Overlap));
        assert_eq!(t.insert(0x4000, 0x5001, R), Err(VmaError::Overlap));
        assert_eq!(t.insert(0x4000, 0x4000, R), Err(VmaError::Invalid));
        assert_eq!(t.first_overlap(0x3000, 0x5000), None);
        assert_eq!(t.first_overlap(0x2000, 0x9000).unwrap().start, 0x1000);
        assert_eq!(t.first_overlap(0x3000, 0x9000).unwrap().start, 0x5000);
        assert!(t.overlaps(0, u64::MAX));
        assert!(!t.overlaps(0, 0x1000));
    }

    #[test]
    fn equal_neighbours_merge() {
        let mut t = VmaTree::new();
        t.insert(0x1000, 0x2000, RW).unwrap();
        t.insert(0x3000, 0x4000, RW).unwrap();
        t.insert(0x2000, 0x3000, RW).unwrap();
        assert_eq!(dump(&t), [(0x1000, 0x4000, RW)]);
        t.insert(0x4000, 0x5000, R).unwrap();
        t.insert(0x0, 0x1000, R).unwrap();
        assert_eq!(dump(&t), [(0, 0x1000, R), (0x1000, 0x4000, RW), (0x4000, 0x5000, R)]);
        // Extending a right neighbour downwards.
        t.insert(0x7000, 0x8000, R).unwrap();
        t.insert(0x6000, 0x7000, R).unwrap();
        assert_eq!(t.find(0x6800).unwrap().start, 0x6000);
        assert_eq!(t.len(), 4);
    }

    #[test]
    fn remove_trims_splits_and_deletes() {
        let mut t = VmaTree::new();
        t.insert(0x1000, 0x9000, RW).unwrap();
        assert!(t.needs_spare(0x3000, 0x4000));
        assert!(t.remove(0x3000, 0x4000, Some(VmaSpare::new().unwrap())));
        assert_eq!(dump(&t), [(0x1000, 0x3000, RW), (0x4000, 0x9000, RW)]);
        assert!(!t.needs_spare(0x1000, 0x2000));
        assert!(t.remove(0x0, 0x2000, None), "trims the front");
        assert!(t.remove(0x8000, 0xa000, None), "trims the back");
        assert_eq!(dump(&t), [(0x2000, 0x3000, RW), (0x4000, 0x8000, RW)]);
        // Spanning several areas.
        assert!(t.remove(0x2800, 0x5000, None));
        assert_eq!(dump(&t), [(0x2000, 0x2800, RW), (0x5000, 0x8000, RW)]);
        assert!(t.remove(0, u64::MAX, None));
        assert!(t.is_empty());
    }

    #[test]
    fn remove_without_a_spare_forgets_the_upper_part() {
        let mut t = VmaTree::new();
        t.insert(0x1000, 0x9000, RW).unwrap();
        assert!(!t.remove(0x3000, 0x4000, None));
        assert_eq!(dump(&t), [(0x1000, 0x3000, RW)]);
    }

    #[test]
    fn protect_splits_at_both_edges() {
        let mut t = VmaTree::new();
        t.insert(0x1000, 0x9000, RW).unwrap();
        t.protect(0x3000, 0x5000, R).unwrap();
        assert_eq!(dump(&t), [(0x1000, 0x3000, RW), (0x3000, 0x5000, R), (0x5000, 0x9000, RW)]);
        // Across areas, ending at an existing edge.
        t.protect(0x2000, 0x5000, N).unwrap();
        assert_eq!(dump(&t), [(0x1000, 0x2000, RW), (0x2000, 0x3000, N), (0x3000, 0x5000, N), (0x5000, 0x9000, RW)]);
        assert_eq!(t.protect(0x8000, 0xa000, R), Err(VmaError::Unmapped));
        t.remove(0x4000, 0x5000, Some(VmaSpare::new().unwrap()));
        assert_eq!(t.protect(0x3000, 0x6000, R), Err(VmaError::Unmapped), "a hole");
        assert_eq!(t.protect(0x1000, 0x1000, R), Err(VmaError::Invalid));
    }

    #[test]
    fn gaps_and_clones() {
        let mut t = VmaTree::new();
        t.insert(0x2000, 0x4000, R).unwrap();
        t.insert(0x5000, 0x6000, RW).unwrap();
        assert_eq!(t.find_gap(0x1000, 0x2000, 0x10000), Some(0x4000));
        assert_eq!(t.find_gap(0x2000, 0x2000, 0x10000), Some(0x6000));
        assert_eq!(t.find_gap(0x2000, 0x2000, 0x7000), None);
        assert_eq!(t.find_gap(0x1000, 0, 0x2000), Some(0));
        let mut c = t.try_clone().unwrap();
        c.remove(0, u64::MAX, None);
        assert_eq!(t.len(), 2);
        assert!(c.is_empty());
    }

    #[test]
    fn a_random_workout_keeps_the_areas_disjoint_and_sorted() {
        let mut t = VmaTree::new();
        let mut x = 0x1234_5678u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..2000 {
            let a = (next() % 64) * 0x1000;
            let b = a + (next() % 8 + 1) * 0x1000;
            let flags = [R, RW, N][(next() % 3) as usize];
            match next() % 3 {
                0 => {
                    let _ = t.insert(a, b, flags);
                }
                1 => {
                    t.remove(a, b, VmaSpare::new().ok());
                }
                _ => {
                    let _ = t.protect(a, b, flags);
                }
            }
            let v = dump(&t);
            for w in v.windows(2) {
                assert!(w[0].1 <= w[1].0, "{v:x?}");
            }
            assert!(v.iter().all(|&(s, e, _)| s < e));
        }
    }
}
