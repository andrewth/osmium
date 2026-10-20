use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

/// Storage for a value created at run time but living forever, handed out
/// once as `&'static mut`. Typical use: a task's future in a `static`.
pub struct StaticCell<T> {
    taken: AtomicBool,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: the value is handed out at most once, as an exclusive reference.
unsafe impl<T: Send> Sync for StaticCell<T> {}

impl<T> StaticCell<T> {
    /// Creates an empty cell.
    pub const fn new() -> Self {
        Self { taken: AtomicBool::new(false), value: UnsafeCell::new(MaybeUninit::uninit()) }
    }

    /// Stores `value` and returns the only reference to it. Panics if called twice.
    // Handing out `&mut` from `&self` is the point of this type; the
    // `taken` flag guarantees it happens at most once.
    #[allow(clippy::mut_from_ref)]
    pub fn init(&'static self, value: T) -> &'static mut T {
        assert!(!self.taken.swap(true, Ordering::AcqRel), "StaticCell initialized twice");
        // SAFETY: the flag guarantees this runs once, so the reference is unique.
        unsafe { (*self.value.get()).write(value) }
    }
}

impl<T> Default for StaticCell<T> {
    fn default() -> Self {
        Self::new()
    }
}
