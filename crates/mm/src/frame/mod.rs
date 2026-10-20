//! Physical frame allocation.

mod bitmap;
mod buddy;

pub use bitmap::BitmapAllocator;
pub use buddy::BuddyAllocator;

use crate::addr::{PAGE_SIZE, PhysAddr};

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
        self.alloc.lock().alloc(0)
    }

    unsafe fn free_table(&self, pa: PhysAddr) {
        // SAFETY: forwarded contract.
        unsafe { self.alloc.lock().dealloc(pa, 0) }
    }
}
