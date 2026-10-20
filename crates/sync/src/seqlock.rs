use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering, fence};

use osmium_arch::cpu::spin_hint;

use crate::guard::{Guardian, IrqDisabled};

/// A type whose every byte is always initialized: no padding, no
/// `MaybeUninit` or union fields. [`SeqLock`] copies its value byte by byte
/// with atomics, and loading an uninitialized byte as a `u8` is undefined
/// behavior.
///
/// Implemented for the primitive integers, floats, `bool`, `char`, `()` and
/// arrays of these. Implement it for your own `#[repr(C)]` (or
/// `#[repr(transparent)]`) structs whose fields are all `NoPadding` and leave
/// no gaps between them or at the end.
///
/// A byte-wise copy does not carry pointer provenance, so do not implement
/// this for types holding pointers or references.
///
/// # Safety
/// Every byte of every value of the type must be initialized.
pub unsafe trait NoPadding: Copy {}

macro_rules! no_padding {
    ($($t:ty),*) => {
        // SAFETY: primitives have no padding, and every byte of every value
        // is initialized.
        $(unsafe impl NoPadding for $t {})*
    };
}
no_padding!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64, bool, char, ());

// SAFETY: array elements are laid out contiguously with no gaps (the element
// size is a multiple of its alignment), and each element has no padding.
unsafe impl<T: NoPadding, const N: usize> NoPadding for [T; N] {}

/// A sequence lock: one writer at a time, readers that never block it.
///
/// Readers copy the value and retry if a write overlapped the copy, which
/// suits small, frequently read and rarely written data such as a clock's
/// calibration or a timestamp updated from an interrupt. Writers serialize
/// on the sequence counter and run with interrupts masked (the default
/// guardian), so a reader on the same CPU can never spin on a half-finished
/// write that it interrupted.
///
/// The value is copied with byte-wise atomic loads and stores, so a read
/// that races with a write is not a data race in Rust's memory model. That
/// is why `T` must be [`NoPadding`]: every byte read must be initialized.
pub struct SeqLock<T: NoPadding, G: Guardian = IrqDisabled> {
    seq: AtomicUsize,
    data: UnsafeCell<T>,
    _guard: core::marker::PhantomData<fn() -> G>,
}

// SAFETY: all access to `data` goes through byte-wise atomics, writers are
// serialized by `seq`, and `T: Copy` has no drop glue or interior references.
unsafe impl<T: NoPadding + Send, G: Guardian> Sync for SeqLock<T, G> {}

impl<T: NoPadding, G: Guardian> SeqLock<T, G> {
    /// Creates the lock holding `value`.
    pub const fn new(value: T) -> Self {
        Self { seq: AtomicUsize::new(0), data: UnsafeCell::new(value), _guard: core::marker::PhantomData }
    }

    fn bytes(&self) -> &[AtomicU8] {
        // SAFETY: `AtomicU8` has the size and alignment of `u8`; every access
        // to the bytes of `data` is through these atomics, and `T: NoPadding`
        // means each of those bytes is initialized.
        unsafe { core::slice::from_raw_parts(self.data.get().cast::<AtomicU8>(), size_of::<T>()) }
    }

    /// Returns a consistent copy of the value.
    pub fn read(&self) -> T {
        loop {
            let start = self.seq.load(Ordering::Acquire);
            if start & 1 != 0 {
                spin_hint();
                continue;
            }
            let mut out = MaybeUninit::<T>::uninit();
            let dst = out.as_mut_ptr().cast::<u8>();
            for (i, b) in self.bytes().iter().enumerate() {
                // SAFETY: `i` is within the `size_of::<T>()` bytes of `out`.
                unsafe { dst.add(i).write(b.load(Ordering::Relaxed)) };
            }
            fence(Ordering::Acquire);
            if self.seq.load(Ordering::Relaxed) == start {
                // SAFETY: no write overlapped the copy (the counter did not
                // move), so these are the bytes of one valid `T`.
                return unsafe { out.assume_init() };
            }
        }
    }

    /// Replaces the value.
    pub fn write(&self, value: T) {
        self.update(|v| *v = value);
    }

    /// Modifies the value in place; readers see either the old or the new
    /// value, never a mix.
    ///
    /// If `f` panics and the panic unwinds, the lock is released (the
    /// sequence becomes even again and the guardian's exit runs) with the
    /// value unchanged: `f` works on a copy that is only stored on success.
    pub fn update(&self, f: impl FnOnce(&mut T)) {
        let state = G::enter();
        // Take the write side: make the counter odd.
        let mut seq = self.seq.load(Ordering::Relaxed);
        loop {
            if seq & 1 == 0 {
                match self.seq.compare_exchange_weak(seq, seq + 1, Ordering::Acquire, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(now) => seq = now,
                }
            } else {
                spin_hint();
                seq = self.seq.load(Ordering::Relaxed);
            }
        }
        fence(Ordering::Release);
        // From here on, dropping `release` (normally or on unwind) ends the
        // write: without it a panic in `f` would leave the counter odd and
        // every later reader and writer spinning forever.
        let release = WriteRelease::<G> { seq: &self.seq, next: seq + 2, state: Some(state) };
        let mut value = self.read_unchecked();
        f(&mut value);
        let src = (&raw const value).cast::<u8>();
        for (i, b) in self.bytes().iter().enumerate() {
            // SAFETY: `i` is within the bytes of `value`, all initialized
            // because `T: NoPadding`.
            b.store(unsafe { src.add(i).read() }, Ordering::Relaxed);
        }
        drop(release);
    }

    /// Copies the value while holding the write side (no concurrent writer).
    fn read_unchecked(&self) -> T {
        let mut out = MaybeUninit::<T>::uninit();
        let dst = out.as_mut_ptr().cast::<u8>();
        for (i, b) in self.bytes().iter().enumerate() {
            // SAFETY: in bounds of `out`.
            unsafe { dst.add(i).write(b.load(Ordering::Relaxed)) };
        }
        // SAFETY: the writer holds the lock, so the bytes form a valid `T`.
        unsafe { out.assume_init() }
    }
}

/// Ends a [`SeqLock`] write when dropped, including during unwinding.
struct WriteRelease<'a, G: Guardian> {
    seq: &'a AtomicUsize,
    /// The even sequence number that marks the write as finished.
    next: usize,
    state: Option<G::State>,
}

impl<G: Guardian> Drop for WriteRelease<'_, G> {
    fn drop(&mut self) {
        self.seq.store(self.next, Ordering::Release);
        if let Some(state) = self.state.take() {
            G::exit(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoGuard;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    #[derive(Clone, Copy, Debug, PartialEq)]
    #[repr(C)]
    struct Pair {
        a: u64,
        b: u64,
    }

    // SAFETY: two `u64`s in `repr(C)` leave no gaps.
    unsafe impl NoPadding for Pair {}

    #[test]
    fn readers_never_see_a_torn_value() {
        let lock = Arc::new(SeqLock::<Pair, NoGuard>::new(Pair { a: 0, b: 0 }));
        let stop = Arc::new(AtomicBool::new(false));
        // All four threads start together, so readers overlap the writes.
        let start = Arc::new(std::sync::Barrier::new(4));
        let writer = {
            let (lock, stop, start) = (lock.clone(), stop.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                for i in 1..=200_000u64 {
                    lock.write(Pair { a: i, b: i.wrapping_mul(3) });
                }
                stop.store(true, Ordering::Release);
            })
        };
        let readers: std::vec::Vec<_> = (0..3)
            .map(|_| {
                let (lock, stop, start) = (lock.clone(), stop.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    let mut reads = 0u64;
                    loop {
                        let p = lock.read();
                        assert_eq!(p.b, p.a.wrapping_mul(3), "torn read: {p:?}");
                        reads += 1;
                        if stop.load(Ordering::Acquire) {
                            break;
                        }
                    }
                    reads
                })
            })
            .collect();
        writer.join().unwrap();
        for r in readers {
            assert!(r.join().unwrap() > 0);
        }
        assert_eq!(lock.read(), Pair { a: 200_000, b: 600_000 });
    }

    #[test]
    fn update_in_place() {
        let lock: SeqLock<[u32; 3]> = SeqLock::new([1, 2, 3]);
        lock.update(|v| v[1] = 20);
        assert_eq!(lock.read(), [1, 20, 3]);
    }

    #[test]
    fn panicking_update_releases_the_lock() {
        let lock: SeqLock<[u32; 2], NoGuard> = SeqLock::new([1, 2]);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            lock.update(|v| {
                v[0] = 10;
                panic!("in update");
            })
        }));
        assert!(r.is_err());
        // The counter is even again: reads and writes do not spin forever,
        // and the half-done update was never stored.
        assert_eq!(lock.read(), [1, 2]);
        lock.write([3, 4]);
        assert_eq!(lock.read(), [3, 4]);
    }
}
