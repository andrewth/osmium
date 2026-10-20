use core::cell::{Cell, UnsafeCell};
use core::mem::MaybeUninit;
use core::ops::Deref;
use core::sync::atomic::{AtomicU8, Ordering};

use osmium_arch::cpu::spin_hint;

const EMPTY: u8 = 0;
const RUNNING: u8 = 1;
const READY: u8 = 2;

/// A cell initialized at most once.
///
/// Contexts that race to initialize spin until the winner finishes. If the
/// initializer panics, later callers spin forever; kernels normally abort on
/// panic, so this is not handled.
pub struct Once<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: the value is written once before READY is published with Release,
// and only read after READY is observed with Acquire.
unsafe impl<T: Send + Sync> Sync for Once<T> {}
// SAFETY: moving the cell moves `T`.
unsafe impl<T: Send> Send for Once<T> {}

impl<T> Once<T> {
    /// Creates an empty cell.
    pub const fn new() -> Self {
        Self { state: AtomicU8::new(EMPTY), value: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    /// Returns the value, running `init` first if no one has.
    pub fn call_once(&self, init: impl FnOnce() -> T) -> &T {
        match self.state.compare_exchange(EMPTY, RUNNING, Ordering::Acquire, Ordering::Acquire) {
            Ok(_) => {
                // SAFETY: winning the EMPTY -> RUNNING transition gives exclusive access.
                unsafe { (*self.value.get()).write(init()) };
                self.state.store(READY, Ordering::Release);
            }
            Err(_) => {
                while self.state.load(Ordering::Acquire) != READY {
                    spin_hint();
                }
            }
        }
        // SAFETY: the state is READY.
        unsafe { (*self.value.get()).assume_init_ref() }
    }

    /// Stores `value` if the cell is empty; otherwise hands it back.
    pub fn set(&self, value: T) -> Result<(), T> {
        let mut value = Some(value);
        self.call_once(|| value.take().expect("call_once runs its closure at most once"));
        match value {
            None => Ok(()),
            Some(v) => Err(v),
        }
    }

    /// Returns the value if initialization has finished.
    pub fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) == READY {
            // SAFETY: the state is READY.
            Some(unsafe { (*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }

    /// Returns true if the value is ready.
    pub fn is_completed(&self) -> bool {
        self.state.load(Ordering::Acquire) == READY
    }
}

impl<T> Default for Once<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for Once<T> {
    fn drop(&mut self) {
        if *self.state.get_mut() == READY {
            // SAFETY: the value was initialized and is dropped exactly once.
            unsafe { self.value.get_mut().assume_init_drop() }
        }
    }
}

/// A value computed on first access.
pub struct Lazy<T, F = fn() -> T> {
    once: Once<T>,
    init: Cell<Option<F>>,
}

// SAFETY: `init` is taken only by the context that wins the `Once`, which
// excludes all others, so sharing needs `F: Send`, not `F: Sync`.
unsafe impl<T: Send + Sync, F: Send> Sync for Lazy<T, F> {}

impl<T, F: FnOnce() -> T> Lazy<T, F> {
    /// Creates a lazily initialized value.
    pub const fn new(init: F) -> Self {
        Self { once: Once::new(), init: Cell::new(Some(init)) }
    }

    /// Forces initialization and returns the value.
    pub fn force(this: &Self) -> &T {
        this.once.call_once(|| (this.init.take().expect("Lazy initializer already used"))())
    }
}

impl<T, F: FnOnce() -> T> Deref for Lazy<T, F> {
    type Target = T;
    fn deref(&self) -> &T {
        Self::force(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicUsize;

    #[test]
    fn once_runs_once() {
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        static CELL: Once<u32> = Once::new();
        let threads: std::vec::Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    *CELL.call_once(|| {
                        CALLS.fetch_add(1, Ordering::SeqCst);
                        42
                    })
                })
            })
            .collect();
        for t in threads {
            assert_eq!(t.join().unwrap(), 42);
        }
        assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(CELL.set(1), Err(1));
    }

    #[test]
    fn lazy_static() {
        static TABLE: Lazy<[u8; 4]> = Lazy::new(|| [1, 2, 3, 4]);
        assert_eq!(TABLE[2], 3);
    }
}
