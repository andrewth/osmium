//! A kernel heap usable as `#[global_allocator]`.
//!
//! Requests of up to 2 KiB are served from eight power-of-two size classes,
//! each a free list carved from whole pages. Larger requests go straight to
//! the [`PageSource`]. Pages taken for size classes are kept for reuse
//! within that class.
//!
//! ```ignore
//! static ARENA: StaticArena<1024> = StaticArena::new();   // 4 MiB, in .bss
//! #[global_allocator]
//! static HEAP: LockedHeap<&StaticArena<1024>> = LockedHeap::new();
//!
//! fn init() { HEAP.init(&ARENA); }
//! ```

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};

use osmium_sync::{IrqSpinLock, Once};

use crate::addr::PAGE_SIZE;
use crate::frame::{FrameAllocator, LockedFrames, PhysMapper, order_for};

const MIN_CLASS_SHIFT: usize = 4;
const CLASSES: usize = 8; // 16 B ..= 2 KiB
const MAX_CLASS: usize = 1 << (MIN_CLASS_SHIFT + CLASSES - 1);

/// Supplies page-granular memory to the heap.
///
/// # Safety
/// `alloc_pages` must return memory that is exclusively owned, writable,
/// `count * PAGE_SIZE` bytes long and aligned to `align` (a power of two of
/// at least `PAGE_SIZE`).
pub unsafe trait PageSource {
    /// Allocates `count` pages aligned to `align` bytes.
    fn alloc_pages(&self, count: usize, align: usize) -> Option<NonNull<u8>>;
    /// Returns pages from `alloc_pages`.
    ///
    /// # Safety
    /// `ptr` and `count` must match an earlier allocation no longer in use.
    unsafe fn free_pages(&self, ptr: NonNull<u8>, count: usize);
}

// SAFETY: forwards to `S`.
unsafe impl<S: PageSource + ?Sized> PageSource for &S {
    fn alloc_pages(&self, count: usize, align: usize) -> Option<NonNull<u8>> {
        (**self).alloc_pages(count, align)
    }
    unsafe fn free_pages(&self, ptr: NonNull<u8>, count: usize) {
        // SAFETY: forwarded contract.
        unsafe { (**self).free_pages(ptr, count) }
    }
}

// SAFETY: blocks come from the frame allocator, which returns exclusive,
// naturally aligned blocks; the mapper makes them addressable.
unsafe impl<A: FrameAllocator, M: PhysMapper> PageSource for LockedFrames<A, M> {
    fn alloc_pages(&self, count: usize, align: usize) -> Option<NonNull<u8>> {
        let order = order_for(count.max(align / PAGE_SIZE) * PAGE_SIZE);
        let pa = self.lock().alloc(order)?;
        NonNull::new(self.phys_to_virt(pa))
    }

    unsafe fn free_pages(&self, ptr: NonNull<u8>, count: usize) {
        // Without an inverse mapping the block cannot be identified, so it is
        // leaked rather than corrupting the allocator.
        if let Some(pa) = self.virt_to_phys(ptr.as_ptr()) {
            // SAFETY: the block came from `alloc_pages(count, ..)`, which used
            // this order (alignment does not change the order for frees,
            // because `alloc` rounded to at least `count` pages).
            unsafe { self.lock().dealloc(pa, order_for(count * PAGE_SIZE)) }
        }
    }
}

#[repr(C, align(4096))]
struct Page([u8; PAGE_SIZE]);

/// A fixed pool of `PAGES` pages that can live in `.bss`, for firmware or
/// for a kernel's early heap.
pub struct StaticArena<const PAGES: usize> {
    pages: UnsafeCell<[MaybeUninit<Page>; PAGES]>,
    used: IrqSpinLock<[bool; PAGES]>,
}

// SAFETY: page ownership is tracked under `used`'s lock.
unsafe impl<const PAGES: usize> Sync for StaticArena<PAGES> {}

impl<const PAGES: usize> StaticArena<PAGES> {
    /// Creates an arena with all pages free.
    pub const fn new() -> Self {
        Self { pages: UnsafeCell::new([const { MaybeUninit::uninit() }; PAGES]), used: IrqSpinLock::new([false; PAGES]) }
    }

    fn base(&self) -> *mut u8 {
        self.pages.get().cast()
    }
}

impl<const PAGES: usize> Default for StaticArena<PAGES> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: runs are marked used before being returned; the arena is
// page-aligned, so aligned indices give aligned addresses.
unsafe impl<const PAGES: usize> PageSource for StaticArena<PAGES> {
    fn alloc_pages(&self, count: usize, align: usize) -> Option<NonNull<u8>> {
        let step = (align / PAGE_SIZE).max(1);
        let base_addr = self.base() as usize;
        let mut used = self.used.lock();
        let mut i = (base_addr.next_multiple_of(align) - base_addr) / PAGE_SIZE;
        while i + count <= PAGES {
            match used[i..i + count].iter().rposition(|&u| u) {
                None => {
                    used[i..i + count].fill(true);
                    // SAFETY: in bounds of the arena.
                    return NonNull::new(unsafe { self.base().add(i * PAGE_SIZE) });
                }
                // Skip past the used page, keeping alignment.
                Some(j) => i = (i + j + 1).next_multiple_of(step),
            }
        }
        None
    }

    unsafe fn free_pages(&self, ptr: NonNull<u8>, count: usize) {
        let i = (ptr.as_ptr() as usize - self.base() as usize) / PAGE_SIZE;
        self.used.lock()[i..i + count].fill(false);
    }
}

struct State {
    /// Head of each size class's free list (0 = empty). Stored as `usize` so
    /// the state is `Send`.
    free: [usize; CLASSES],
    stats: HeapStats,
}

/// Heap usage counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HeapStats {
    /// Bytes handed out to callers, rounded up to their size class.
    pub allocated: usize,
    /// Bytes obtained from the page source.
    pub reserved: usize,
    /// Successful allocations.
    pub allocs: usize,
    /// Failed allocations.
    pub failures: usize,
}

/// The heap, behind an IRQ-safe lock. Returns null until [`LockedHeap::init`].
pub struct LockedHeap<S> {
    source: Once<S>,
    state: IrqSpinLock<State>,
}

impl<S: PageSource> LockedHeap<S> {
    /// Creates an uninitialized heap.
    pub const fn new() -> Self {
        Self { source: Once::new(), state: IrqSpinLock::new(State { free: [0; CLASSES], stats: HeapStats { allocated: 0, reserved: 0, allocs: 0, failures: 0 } }) }
    }

    /// Supplies the page source. Panics if called twice.
    pub fn init(&self, source: S) {
        assert!(self.source.set(source).is_ok(), "heap initialized twice");
    }

    /// Returns usage counters.
    pub fn stats(&self) -> HeapStats {
        self.state.lock().stats
    }

    fn class_of(layout: &Layout) -> Option<usize> {
        let size = layout.size().max(layout.align()).max(1 << MIN_CLASS_SHIFT);
        (size <= MAX_CLASS).then(|| size.next_power_of_two().trailing_zeros() as usize - MIN_CLASS_SHIFT)
    }
}

impl<S: PageSource> Default for LockedHeap<S> {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: small blocks come from pages exclusively owned by one class and are
// handed out at most once at a time; large blocks come straight from the
// page source, which guarantees exclusivity and alignment.
unsafe impl<S: PageSource + Sync + Send> GlobalAlloc for LockedHeap<S> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some(source) = self.source.get() else { return ptr::null_mut() };
        let mut st = self.state.lock();
        let result = match Self::class_of(&layout) {
            Some(c) => {
                let size = 1 << (c + MIN_CLASS_SHIFT);
                if st.free[c] == 0 {
                    // Carve a fresh page into blocks of this class.
                    if let Some(page) = source.alloc_pages(1, PAGE_SIZE) {
                        st.stats.reserved += PAGE_SIZE;
                        let base = page.as_ptr();
                        for off in (0..PAGE_SIZE).step_by(size).rev() {
                            // SAFETY: the page is ours; each block can hold a pointer.
                            unsafe { base.add(off).cast::<usize>().write(st.free[c]) };
                            st.free[c] = base as usize + off;
                        }
                    }
                }
                let block = st.free[c];
                if block != 0 {
                    // SAFETY: free blocks store the next pointer in their first word.
                    st.free[c] = unsafe { (block as *const usize).read() };
                    st.stats.allocated += size;
                }
                block as *mut u8
            }
            None => {
                let pages = layout.size().div_ceil(PAGE_SIZE);
                match source.alloc_pages(pages, layout.align().max(PAGE_SIZE)) {
                    Some(p) => {
                        st.stats.allocated += pages * PAGE_SIZE;
                        st.stats.reserved += pages * PAGE_SIZE;
                        p.as_ptr()
                    }
                    None => ptr::null_mut(),
                }
            }
        };
        if result.is_null() {
            st.stats.failures += 1;
        } else {
            st.stats.allocs += 1;
        }
        result
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut st = self.state.lock();
        match Self::class_of(&layout) {
            Some(c) => {
                // SAFETY: the block belongs to class `c` and is no longer used.
                unsafe { ptr.cast::<usize>().write(st.free[c]) };
                st.free[c] = ptr as usize;
                st.stats.allocated -= 1 << (c + MIN_CLASS_SHIFT);
            }
            None => {
                let pages = layout.size().div_ceil(PAGE_SIZE);
                st.stats.allocated -= pages * PAGE_SIZE;
                st.stats.reserved -= pages * PAGE_SIZE;
                drop(st);
                let source = self.source.get().expect("dealloc before init");
                // SAFETY: the block came from `alloc_pages(pages, ..)`.
                unsafe { source.free_pages(NonNull::new_unchecked(ptr), pages) };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn arena_alignment_and_reuse() {
        static ARENA: StaticArena<64> = StaticArena::new();
        let arena = &ARENA;
        let a = arena.alloc_pages(1, PAGE_SIZE).unwrap();
        let b = arena.alloc_pages(4, 4 * PAGE_SIZE).unwrap();
        assert_eq!(b.as_ptr() as usize % (4 * PAGE_SIZE), 0);
        assert_ne!(a, b);
        // SAFETY: returning our pages.
        unsafe { arena.free_pages(a, 1) };
        assert_eq!(arena.alloc_pages(1, PAGE_SIZE), Some(a));
        assert!(arena.alloc_pages(65, PAGE_SIZE).is_none());
    }

    #[test]
    fn small_and_large_allocations() {
        static ARENA: StaticArena<256> = StaticArena::new();
        let arena = &ARENA;
        let heap: LockedHeap<&StaticArena<256>> = LockedHeap::new();
        // SAFETY: uninitialized heap returns null.
        assert!(unsafe { heap.alloc(Layout::new::<u64>()) }.is_null());
        heap.init(arena);

        let mut ptrs = Vec::new();
        for size in [1usize, 8, 24, 100, 700, 2048, 3000, 20_000] {
            for align in [1usize, 8, 64, 4096] {
                let layout = Layout::from_size_align(size, align).unwrap();
                // SAFETY: non-zero size.
                let p = unsafe { heap.alloc(layout) };
                assert!(!p.is_null(), "{layout:?}");
                assert_eq!(p as usize % align, 0, "{layout:?}");
                // SAFETY: the block is ours and `size` bytes long.
                unsafe { p.write_bytes(0x5a, size) };
                ptrs.push((p, layout));
            }
        }
        let mut sorted: Vec<_> = ptrs.iter().map(|(p, _)| *p as usize).collect();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ptrs.len(), "distinct blocks");
        for (p, layout) in ptrs {
            // SAFETY: freeing what we allocated with the same layout.
            unsafe { heap.dealloc(p, layout) };
        }
        let st = heap.stats();
        assert_eq!(st.allocated, 0);
        assert_eq!(st.failures, 0);
        assert_eq!(st.allocs, 32);
    }
}

#[cfg(test)]
mod frame_source_tests {
    use super::*;
    use crate::frame::testmem::SimRam;
    use crate::frame::{BuddyAllocator, LockedFrames};

    #[test]
    fn heap_on_frame_allocator_returns_large_blocks() {
        let ram: &'static SimRam = std::boxed::Box::leak(std::boxed::Box::new(SimRam::new(0x8000_0000, 1 << 20)));
        let mut buddy = BuddyAllocator::<_, 12>::new(ram);
        // SAFETY: simulated RAM owned by the test.
        unsafe { buddy.add_region(ram.base, ram.end()) };
        // SAFETY: `ram` maps every frame the buddy returns.
        let frames: &'static _ = std::boxed::Box::leak(std::boxed::Box::new(unsafe { LockedFrames::new(buddy, ram) }));
        let heap = LockedHeap::new();
        heap.init(frames);
        let free = frames.lock().free_frames();
        let layout = Layout::from_size_align(5 * PAGE_SIZE, 8).unwrap();
        // SAFETY: non-zero size; freed with the same layout.
        unsafe {
            let p = heap.alloc(layout);
            assert!(!p.is_null());
            assert_eq!(frames.lock().free_frames(), free - 8, "rounded up to order 3");
            heap.dealloc(p, layout);
        }
        assert_eq!(frames.lock().free_frames(), free);
    }
}
