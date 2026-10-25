//! Physical frame allocation.

mod bitmap;
mod buddy;

pub use bitmap::BitmapAllocator;
pub use buddy::BuddyAllocator;

use core::fmt;

use crate::addr::{PAGE_SIZE, PhysAddr};
use crate::paging::TableAlloc;

/// Turns physical addresses into pointers the CPU can dereference.
///
/// # Safety
/// For every physical address the OS hands to code using this mapper, the
/// returned pointer must be valid for reads and writes of RAM at that
/// address (for example through an identity map or a direct-map window).
pub unsafe trait PhysMapper {
    /// Returns a pointer to the byte at `pa`.
    fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8;

    /// Inverse of [`PhysMapper::phys_to_virt`], if the mapper can compute it.
    fn virt_to_phys(&self, _ptr: *const u8) -> Option<PhysAddr> {
        None
    }
}

/// Maps physical address `pa` to virtual address `pa + offset`.
///
/// An offset of 0 is an identity map, which is what firmware and early boot
/// code usually run with. Kernels with a direct map use its base.
#[derive(Clone, Copy, Debug)]
pub struct OffsetMapper(usize);

impl OffsetMapper {
    /// Creates the mapper.
    ///
    /// # Safety
    /// All RAM must be mapped readable and writable at `pa + offset`.
    pub const unsafe fn new(offset: usize) -> Self {
        Self(offset)
    }
}

// SAFETY: the constructor's contract.
unsafe impl PhysMapper for OffsetMapper {
    fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
        (pa.as_usize()).wrapping_add(self.0) as *mut u8
    }

    fn virt_to_phys(&self, ptr: *const u8) -> Option<PhysAddr> {
        Some(PhysAddr::new((ptr as usize).wrapping_sub(self.0) as u64))
    }
}

// SAFETY: forwards to `M`.
unsafe impl<M: PhysMapper + ?Sized> PhysMapper for &M {
    fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
        (**self).phys_to_virt(pa)
    }

    fn virt_to_phys(&self, ptr: *const u8) -> Option<PhysAddr> {
        (**self).virt_to_phys(ptr)
    }
}

/// An allocator of physically contiguous, naturally aligned blocks of
/// `2^order` frames.
///
/// # Safety
/// `alloc` must only return blocks that are unused RAM, are not returned
/// again until freed, and are aligned to their size.
pub unsafe trait FrameAllocator {
    /// Allocates `2^order` contiguous frames.
    fn alloc(&mut self, order: u32) -> Option<PhysAddr>;

    /// Frees a block from [`FrameAllocator::alloc`].
    ///
    /// # Safety
    /// `pa` and `order` must match an earlier allocation that is no longer in use.
    unsafe fn dealloc(&mut self, pa: PhysAddr, order: u32);

    /// Number of free frames.
    fn free_frames(&self) -> usize;

    /// Allocates one frame.
    fn alloc_frame(&mut self) -> Option<PhysAddr> {
        self.alloc(0)
    }

    /// The kind recorded for the frame at `pa`, or `None` if this allocator
    /// does not keep per-frame metadata or does not manage the frame.
    fn kind(&self, _pa: PhysAddr) -> Option<FrameKind> {
        None
    }

    /// Records the kind of the frame at `pa`. Returns false if this allocator
    /// keeps no per-frame metadata or does not manage the frame.
    fn set_kind(&mut self, _pa: PhysAddr, _kind: FrameKind) -> bool {
        false
    }

    /// The number of references to the frame at `pa`, or `None` if this
    /// allocator keeps no per-frame metadata or does not manage the frame.
    fn refs(&self, _pa: PhysAddr) -> Option<u32> {
        None
    }

    /// Takes the first reference to the allocated frame at `pa`, moving its
    /// count from zero to one. Returns false if the frame already has one, or
    /// this allocator keeps no per-frame metadata or does not manage it.
    fn claim(&self, _pa: PhysAddr) -> bool {
        false
    }

    /// Adds a reference to a frame that has one. Returns the new count, or
    /// `None` if the frame has none (free, or never claimed).
    fn retain(&self, _pa: PhysAddr) -> Option<u32> {
        None
    }

    /// Drops a reference. Returns the remaining count, or `None` if the frame
    /// had none. The frame is not freed here: the caller frees it at zero.
    fn release(&self, _pa: PhysAddr) -> Option<u32> {
        None
    }
}

/// One reference to a user frame. A page table that owns its leaves holds one
/// for each mapping, and a kernel path can hold one to keep a frame alive past
/// its mapping. The frame is freed when the last reference is dropped.
pub struct OwnedFrame<A: TableAlloc> {
    pa: PhysAddr,
    alloc: A,
}

impl<A: TableAlloc> fmt::Debug for OwnedFrame<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedFrame").field("pa", &self.pa).finish_non_exhaustive()
    }
}

impl<A: TableAlloc> OwnedFrame<A> {
    /// Takes the first reference to `pa`, a frame that `alloc` just returned
    /// from `alloc_table`. If `alloc` does not count references, the frame is
    /// freed and `None` returned.
    pub fn claim(alloc: A, pa: PhysAddr) -> Option<Self> {
        if alloc.claim_frame(pa) {
            Some(Self { pa, alloc })
        } else {
            // SAFETY: `pa` came from `alloc_table` and was never mapped, so nothing refers to it.
            unsafe { alloc.free_table(pa) };
            None
        }
    }

    /// The frame's physical address.
    pub fn pa(&self) -> PhysAddr {
        self.pa
    }

    /// Wraps a reference that a table already holds for `pa`.
    pub(crate) fn adopt(alloc: A, pa: PhysAddr) -> Self {
        Self { pa, alloc }
    }

    /// Gives up this handle without releasing its reference, returning the
    /// frame's address. The reference now belongs to whoever mapped it.
    pub(crate) fn leak(self) -> PhysAddr {
        let this = core::mem::ManuallyDrop::new(self);
        // SAFETY: `this` is never dropped, so its allocator handle is moved out exactly once here.
        drop(unsafe { core::ptr::read(&this.alloc) });
        this.pa
    }
}

impl<A: TableAlloc + Clone> OwnedFrame<A> {
    /// Takes another reference to the same frame, if the allocator counts them.
    pub fn share(&self) -> Option<Self> {
        self.alloc.retain_frame(self.pa).then(|| Self { pa: self.pa, alloc: self.alloc.clone() })
    }
}

impl<A: TableAlloc> Drop for OwnedFrame<A> {
    fn drop(&mut self) {
        // SAFETY: this handle held a reference, which it now gives up; the frame is no longer mapped
        // through it (a table that maps it holds a reference of its own).
        unsafe { self.alloc.release_frame(self.pa) };
    }
}

/// What a frame is used for, as recorded in the allocator's per-frame metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// On a free list.
    Free = 0,
    /// Allocated, and not yet given a use.
    Allocated = 1,
    /// A page-table page.
    Table = 2,
    /// A user page, which address spaces map and reference.
    User = 3,
}

impl FrameKind {
    /// Decodes a stored kind byte; `None` for a byte no kind was stored as.
    pub(crate) const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Free),
            1 => Some(Self::Allocated),
            2 => Some(Self::Table),
            3 => Some(Self::User),
            _ => None,
        }
    }
}

/// The smallest order whose block holds `bytes`.
pub const fn order_for(bytes: usize) -> u32 {
    let frames = bytes.div_ceil(PAGE_SIZE);
    if frames <= 1 { 0 } else { usize::BITS - (frames - 1).leading_zeros() }
}

#[cfg(test)]
pub(crate) mod testmem {
    //! Simulated physical memory for host tests.
    use super::*;
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    /// A heap block standing in for RAM at physical address `base`.
    pub struct SimRam {
        pub base: PhysAddr,
        ptr: *mut u8,
        layout: Layout,
    }

    impl SimRam {
        pub fn new(base: u64, bytes: usize) -> Self {
            let layout = Layout::from_size_align(bytes, 1 << 21).unwrap();
            // SAFETY: non-zero size.
            let ptr = unsafe { alloc_zeroed(layout) };
            assert!(!ptr.is_null());
            Self { base: PhysAddr::new(base), ptr, layout }
        }

        pub fn end(&self) -> PhysAddr {
            self.base + self.layout.size() as u64
        }
    }

    // SAFETY: the block is plain memory; tests coordinate access through allocators.
    unsafe impl Sync for SimRam {}
    // SAFETY: as above.
    unsafe impl Send for SimRam {}

    impl Drop for SimRam {
        fn drop(&mut self) {
            // SAFETY: allocated in `new` with this layout.
            unsafe { dealloc(self.ptr, self.layout) }
        }
    }

    // SAFETY: every address in [base, end) maps into the owned heap block.
    unsafe impl PhysMapper for SimRam {
        fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
            assert!(pa >= self.base && pa < self.end(), "{pa:?} outside simulated RAM");
            // SAFETY: in bounds, checked above.
            unsafe { self.ptr.add((pa - self.base) as usize) }
        }

        fn virt_to_phys(&self, ptr: *const u8) -> Option<PhysAddr> {
            let off = (ptr as usize).checked_sub(self.ptr as usize)?;
            (off < self.layout.size()).then(|| self.base + off as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn order_for_sizes() {
        assert_eq!(super::order_for(1), 0);
        assert_eq!(super::order_for(4096), 0);
        assert_eq!(super::order_for(4097), 1);
        assert_eq!(super::order_for(5 * 4096), 3);
    }
}

/// A frame allocator behind an IRQ-safe lock, paired with the mapper for
/// the frames it hands out. Implements [`crate::paging::TableAlloc`] and
/// [`crate::heap::PageSource`], so one instance can feed page tables and
/// the kernel heap.
pub struct LockedFrames<A, M> {
    alloc: osmium_sync::IrqSpinLock<A>,
    mapper: M,
}

impl<A: FrameAllocator, M: PhysMapper> LockedFrames<A, M> {
    /// Wraps `alloc`.
    ///
    /// # Safety
    /// `mapper` must map every frame that `alloc` can return.
    pub const unsafe fn new(alloc: A, mapper: M) -> Self {
        Self { alloc: osmium_sync::IrqSpinLock::new(alloc), mapper }
    }

    /// Locks the allocator, for adding regions or allocating directly.
    pub fn lock(&self) -> osmium_sync::SpinLockGuard<'_, A, osmium_sync::IrqDisabled> {
        self.alloc.lock()
    }
}

// SAFETY: forwards to the mapper, which covers all frames per `new`'s contract.
unsafe impl<A, M: PhysMapper> PhysMapper for LockedFrames<A, M> {
    fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
        self.mapper.phys_to_virt(pa)
    }

    fn virt_to_phys(&self, ptr: *const u8) -> Option<PhysAddr> {
        self.mapper.virt_to_phys(ptr)
    }
}

// SAFETY: frames come from a `FrameAllocator` (exclusive, aligned) and are
// mapped by `mapper` per `new`'s contract.
unsafe impl<A: FrameAllocator, M: PhysMapper> crate::paging::TableAlloc for LockedFrames<A, M> {
    fn alloc_table(&self) -> Option<PhysAddr> {
        let mut alloc = self.alloc.lock();
        let pa = alloc.alloc(0)?;
        alloc.set_kind(pa, FrameKind::Table);
        Some(pa)
    }

    fn claim_frame(&self, pa: PhysAddr) -> bool {
        let mut alloc = self.alloc.lock();
        let claimed = alloc.claim(pa);
        if claimed {
            alloc.set_kind(pa, FrameKind::User);
        }
        claimed
    }

    fn retain_frame(&self, pa: PhysAddr) -> bool {
        self.alloc.lock().retain(pa).is_some()
    }

    unsafe fn release_frame(&self, pa: PhysAddr) {
        let mut alloc = self.alloc.lock();
        if alloc.release(pa) == Some(0) {
            // SAFETY: the last reference is gone, and the frame came from `alloc`.
            unsafe { alloc.dealloc(pa, 0) };
        }
    }

    fn frame_refs(&self, pa: PhysAddr) -> Option<u32> {
        self.alloc.lock().refs(pa)
    }

    unsafe fn free_table(&self, pa: PhysAddr) {
        // SAFETY: forwarded contract.
        unsafe { self.alloc.lock().dealloc(pa, 0) }
    }

    fn alloc_root(&self, pages: usize) -> Option<PhysAddr> {
        // Blocks of 2^order frames are aligned to their size.
        pages.is_power_of_two().then(|| self.alloc.lock().alloc(pages.trailing_zeros()))?
    }

    unsafe fn free_root(&self, pa: PhysAddr, pages: usize) {
        // SAFETY: forwarded contract; allocated above with this order.
        unsafe { self.alloc.lock().dealloc(pa, pages.trailing_zeros()) }
    }
}
