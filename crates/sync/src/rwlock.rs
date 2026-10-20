use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicUsize, Ordering};

use osmium_arch::cpu::spin_hint;

use crate::guard::{Guardian, PreemptDisabled};

const WRITER: usize = 1 << (usize::BITS - 1);
const WAITING: usize = 1 << (usize::BITS - 2);
const READERS: usize = !(WRITER | WAITING);

/// A reader/writer spin lock. A waiting writer blocks new readers, so
/// writers cannot be starved.
pub struct RwSpinLock<T: ?Sized, G: Guardian = PreemptDisabled> {
    state: AtomicUsize,
    _guard: PhantomData<fn() -> G>,
    data: UnsafeCell<T>,
}

// SAFETY: readers share `&T` across threads (needs `Sync`); writers move
// exclusive access between threads (needs `Send`).
unsafe impl<T: ?Sized + Send + Sync, G: Guardian> Sync for RwSpinLock<T, G> {}
// SAFETY: moving the lock moves `T`.
unsafe impl<T: ?Sized + Send, G: Guardian> Send for RwSpinLock<T, G> {}

impl<T, G: Guardian> RwSpinLock<T, G> {
    /// Creates an unlocked lock.
    pub const fn new(data: T) -> Self {
        Self { state: AtomicUsize::new(0), _guard: PhantomData, data: UnsafeCell::new(data) }
    }
}

impl<T: ?Sized, G: Guardian> RwSpinLock<T, G> {
    /// Acquires shared access.
    pub fn read(&self) -> RwSpinLockReadGuard<'_, T, G> {
        let state = G::enter();
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & (WRITER | WAITING) == 0 {
                assert!(s & READERS != READERS, "too many readers");
                if self.state.compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    return RwSpinLockReadGuard { lock: self, state: Some(state), _not_send: PhantomData };
                }
            }
            spin_hint();
        }
    }

    /// Acquires exclusive access.
    pub fn write(&self) -> RwSpinLockWriteGuard<'_, T, G> {
        let state = G::enter();
        loop {
            let s = self.state.load(Ordering::Relaxed);
            if s & !WAITING == 0 {
                if self.state.compare_exchange_weak(s, WRITER, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    return RwSpinLockWriteGuard { lock: self, state: Some(state), _not_send: PhantomData };
                }
            } else if s & WAITING == 0 {
                self.state.fetch_or(WAITING, Ordering::Relaxed);
            }
            spin_hint();
        }
    }

    /// Returns the data without locking; the `&mut` proves exclusivity.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

impl<T: Default, G: Guardian> Default for RwSpinLock<T, G> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

/// Shared access to a [`RwSpinLock`].
#[must_use]
pub struct RwSpinLockReadGuard<'a, T: ?Sized, G: Guardian = PreemptDisabled> {
    lock: &'a RwSpinLock<T, G>,
    state: Option<G::State>,
    _not_send: PhantomData<*const ()>,
}

/// Exclusive access to a [`RwSpinLock`].
#[must_use]
pub struct RwSpinLockWriteGuard<'a, T: ?Sized, G: Guardian = PreemptDisabled> {
    lock: &'a RwSpinLock<T, G>,
    state: Option<G::State>,
    _not_send: PhantomData<*const ()>,
}

impl<T: ?Sized, G: Guardian> Deref for RwSpinLockReadGuard<'_, T, G> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: a read guard excludes writers.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized, G: Guardian> Drop for RwSpinLockReadGuard<'_, T, G> {
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::Release);
        if let Some(s) = self.state.take() {
            G::exit(s);
        }
    }
}

impl<T: ?Sized, G: Guardian> Deref for RwSpinLockWriteGuard<'_, T, G> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: a write guard is exclusive.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized, G: Guardian> DerefMut for RwSpinLockWriteGuard<'_, T, G> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: a write guard is exclusive.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized, G: Guardian> Drop for RwSpinLockWriteGuard<'_, T, G> {
    fn drop(&mut self) {
        // Also clears WAITING; other waiting writers set it again.
        self.lock.state.store(0, Ordering::Release);
        if let Some(s) = self.state.take() {
            G::exit(s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NoGuard;
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn readers_share_writers_exclude() {
        let lock = Arc::new(RwSpinLock::<_, NoGuard>::new(0u64));
        {
            let a = lock.read();
            let b = lock.read();
            assert_eq!(*a + *b, 0);
        }
        let threads: Vec<_> = (0..4)
            .map(|i| {
                let lock = lock.clone();
                std::thread::spawn(move || {
                    for _ in 0..5_000 {
                        if i % 2 == 0 {
                            *lock.write() += 1;
                        } else {
                            let _ = *lock.read();
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(*lock.read(), 10_000);
    }
}
