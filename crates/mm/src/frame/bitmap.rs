use super::FrameAllocator;
use crate::addr::{PAGE_SIZE, PhysAddr};

/// A frame allocator with one bit per frame over a single contiguous range.
///
/// Small and predictable, which suits firmware and early boot. Allocation is
/// a linear scan from a rotating hint.
pub struct BitmapAllocator<'a> {
    base: PhysAddr,
    frames: usize,
    /// Bit set = frame free.
    bits: &'a mut [u64],
    free: usize,
    hint: usize,
}

impl<'a> BitmapAllocator<'a> {
    /// Words of storage needed to track `frames` frames.
    pub const fn storage_words(frames: usize) -> usize {
        frames.div_ceil(64)
    }

    /// Creates an allocator for `[base, base + frames * PAGE_SIZE)`, with all
    /// frames initially in use. Free frames with [`BitmapAllocator::add_free`].
    ///
    /// Panics if `bits` is too small or `base` is not page aligned.
    pub fn new(base: PhysAddr, frames: usize, bits: &'a mut [u64]) -> Self {
        assert!(base.is_aligned(PAGE_SIZE as u64));
        assert!(bits.len() >= Self::storage_words(frames), "bitmap storage too small");
        bits.fill(0);
        Self { base, frames, bits, free: 0, hint: 0 }
    }

    /// Marks `[start, end)` free; the range is clamped to the managed range
    /// and shrunk to page boundaries.
    ///
    /// # Safety
    /// The range must be unused RAM.
    pub unsafe fn add_free(&mut self, start: PhysAddr, end: PhysAddr) {
        let lo = start.align_up(PAGE_SIZE as u64).max(self.base);
        let hi = end.align_down(PAGE_SIZE as u64).min(self.base + (self.frames * PAGE_SIZE) as u64);
        let mut f = self.index(lo);
        while lo < hi && f < self.index(hi) {
            if !self.is_free(f) {
                self.set(f, true);
                self.free += 1;
            }
            f += 1;
        }
    }

    fn index(&self, pa: PhysAddr) -> usize {
        ((pa - self.base) as usize) / PAGE_SIZE
    }

    fn is_free(&self, f: usize) -> bool {
        self.bits[f / 64] & (1 << (f % 64)) != 0
    }

    fn set(&mut self, f: usize, free: bool) {
        if free {
            self.bits[f / 64] |= 1 << (f % 64);
        } else {
            self.bits[f / 64] &= !(1 << (f % 64));
        }
    }

    fn run_free(&self, start: usize, count: usize) -> bool {
        (start..start + count).all(|f| self.is_free(f))
    }
}

// SAFETY: frames are only handed out while their bit is set, and the bit is
// cleared before returning; alignment is checked against absolute addresses.
unsafe impl FrameAllocator for BitmapAllocator<'_> {
    fn alloc(&mut self, order: u32) -> Option<PhysAddr> {
        let count = 1usize << order;
        let align = count as u64 * PAGE_SIZE as u64;
        if count > self.free {
            return None;
        }
        // Frame indices whose absolute address is suitably aligned.
        let first_aligned = self.index(self.base.align_up(align));
        let candidates = (first_aligned..self.frames.saturating_sub(count - 1)).step_by(count);
        let n = candidates.len();
        let start_at = (self.hint.saturating_sub(first_aligned) / count).min(n);
        let order_iter = candidates.clone().skip(start_at).chain(candidates.take(start_at));
        for f in order_iter {
            if self.run_free(f, count) {
                for i in f..f + count {
                    self.set(i, false);
                }
                self.free -= count;
                self.hint = f + count;
                return Some(self.base + (f * PAGE_SIZE) as u64);
            }
        }
        None
    }

    unsafe fn dealloc(&mut self, pa: PhysAddr, order: u32) {
        let f = self.index(pa);
        for i in f..f + (1 << order) {
            debug_assert!(!self.is_free(i), "double free of frame {i}");
            self.set(i, true);
        }
        self.free += 1 << order;
    }

    fn free_frames(&self) -> usize {
        self.free
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_free_aligned() {
        let mut bits = [0u64; 2];
        let mut a = BitmapAllocator::new(PhysAddr::new(0x10_0000), 100, &mut bits);
        // SAFETY: test allocator over nothing real.
        unsafe { a.add_free(PhysAddr::new(0x10_1000), PhysAddr::new(0x10_0000 + 100 * 4096)) };
        assert_eq!(a.free_frames(), 99);
        let f = a.alloc(0).unwrap();
        assert_eq!(f, PhysAddr::new(0x10_1000));
        let big = a.alloc(3).unwrap();
        assert!(big.is_aligned(8 * 4096));
        assert_eq!(a.free_frames(), 99 - 9);
        // SAFETY: returning what we allocated.
        unsafe {
            a.dealloc(big, 3);
            a.dealloc(f, 0);
        }
        assert_eq!(a.free_frames(), 99);
        assert!(a.alloc(7).is_none(), "128 frames cannot fit in 100");
    }
}
