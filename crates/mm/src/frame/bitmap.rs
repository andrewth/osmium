use super::FrameAllocator;
use crate::addr::{PAGE_SIZE, PhysAddr};

/// A frame allocator with one bit per frame over a single contiguous range.
///
/// Small and predictable, which suits firmware and early boot. Allocation is
/// a linear scan from a rotating hint.
pub struct BitmapAllocator<'bits> {
    base: PhysAddr,
    frames: usize,
    /// Bit set = frame free.
    bits: &'bits mut [u64],
    free: usize,
    hint: usize,
}

impl<'bits> BitmapAllocator<'bits> {
    /// Words of storage needed to track `frames` frames.
    pub const fn storage_words(frames: usize) -> usize {
        frames.div_ceil(64)
    }

    /// Creates an allocator for `[base, base + frames * PAGE_SIZE)`, with all
    /// frames initially in use. Free frames with [`BitmapAllocator::add_free`].
    ///
    /// A `base` that is not page aligned is rounded up, and `frames` is
    /// clamped to what `bits` can track (and to the address space), so a
    /// bad argument shrinks the managed range instead of failing.
    pub fn new(base: PhysAddr, frames: usize, bits: &'bits mut [u64]) -> Self {
        bits.fill(0);
        let (base, lost) = match base.checked_align_up(PAGE_SIZE as u64) {
            Some(aligned) => (aligned, usize::from(aligned != base)),
            None => (base, frames),
        };
        let mut frames = frames.saturating_sub(lost).min(bits.len().saturating_mul(64));
        // Keep the end of the range inside the address space.
        let room = (u64::MAX - base.as_u64()) / PAGE_SIZE as u64;
        frames = frames.min(usize::try_from(room).unwrap_or(usize::MAX));
        Self { base, frames, bits, free: 0, hint: 0 }
    }

    /// Marks `[start, end)` free; the range is clamped to the managed range
    /// and shrunk to page boundaries.
    ///
    /// # Safety
    /// The range must be unused RAM.
    pub unsafe fn add_free(&mut self, start: PhysAddr, end: PhysAddr) {
        // A start in the last page of the address space leaves nothing.
        let Some(lo) = start.checked_align_up(PAGE_SIZE as u64) else { return };
        let lo = lo.max(self.base);
        let hi = end.align_down(PAGE_SIZE as u64).min(self.base + (self.frames * PAGE_SIZE) as u64);
        if lo >= hi {
            return;
        }
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
        self.bits.get(f / 64).is_some_and(|w| w & (1 << (f % 64)) != 0)
    }

    fn set(&mut self, f: usize, free: bool) {
        if let Some(w) = self.bits.get_mut(f / 64) {
            if free {
                *w |= 1 << (f % 64);
            } else {
                *w &= !(1 << (f % 64));
            }
        }
    }

    fn run_free(&self, start: usize, count: usize) -> bool {
        start.checked_add(count).is_some_and(|end| (start..end).all(|f| self.is_free(f)))
    }
}

// SAFETY: frames are only handed out while their bit is set, and the bit is
// cleared before returning; alignment is checked against absolute addresses.
unsafe impl FrameAllocator for BitmapAllocator<'_> {
    fn alloc(&mut self, order: u32) -> Option<PhysAddr> {
        let count = 1usize.checked_shl(order)?;
        let align = (count as u64).checked_mul(PAGE_SIZE as u64)?;
        if count > self.free {
            return None;
        }
        // Frame indices whose absolute address is suitably aligned.
        let first_aligned = self.index(self.base.checked_align_up(align)?);
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

    /// Panics on a double free (any frame of the block already free), in
    /// release builds too: carrying on would hand the frames out twice.
    unsafe fn dealloc(&mut self, pa: PhysAddr, order: u32) {
        let Some(count) = 1usize.checked_shl(order) else { return };
        if pa < self.base || self.index(pa).checked_add(count).is_none_or(|end| end > self.frames) {
            // Not ours: nothing to give back.
            return;
        }
        let f = self.index(pa);
        assert!((f..f + count).all(|i| !self.is_free(i)), "double free of {pa:?} (order {order})");
        for i in f..f + count {
            self.set(i, true);
        }
        self.free += count;
    }

    fn free_frames(&self) -> usize {
        self.free
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_arguments_do_not_panic() {
        let mut bits = [0u64; 1];
        // Unaligned base, too many frames for the storage, and a range at the top of memory.
        let mut a = BitmapAllocator::new(PhysAddr::new(0x10_0001), usize::MAX, &mut bits);
        // SAFETY: test allocator over nothing real.
        unsafe { a.add_free(PhysAddr::new(0), PhysAddr::new(u64::MAX)) };
        assert!(a.free_frames() <= 64);
        assert!(a.alloc(u32::MAX).is_none());
        assert!(a.alloc(64).is_none());
        // SAFETY: frees of memory that was never ours are ignored.
        unsafe {
            a.dealloc(PhysAddr::new(0), 0);
            a.dealloc(PhysAddr::new(!0xfff), 70);
        }
        let mut none = [0u64; 0];
        let mut b = BitmapAllocator::new(PhysAddr::new(u64::MAX), 5, &mut none);
        // SAFETY: nothing is managed.
        unsafe { b.add_free(PhysAddr::new(0), PhysAddr::new(u64::MAX)) };
        assert!(b.alloc(0).is_none());
    }

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

    #[test]
    #[should_panic(expected = "double free")]
    fn double_free_is_caught() {
        let mut bits = [0u64; 1];
        let mut a = BitmapAllocator::new(PhysAddr::new(0x10_0000), 16, &mut bits);
        // SAFETY: test allocator over nothing real.
        unsafe { a.add_free(PhysAddr::new(0x10_0000), PhysAddr::new(0x11_0000)) };
        let f = a.alloc(0).unwrap();
        // SAFETY: the first free is legitimate; the second is the bug under test.
        unsafe {
            a.dealloc(f, 0);
            a.dealloc(f, 0);
        }
    }
}
