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
///
/// Writer preference has a cost: a context that already holds a read guard
/// and takes a second one with [`RwSpinLock::read`] deadlocks if a writer
/// starts waiting in between. Do not nest read sections; use
/// [`RwSpinLock::try_read`] where nesting cannot be ruled out.
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

    /// Acquires shared access without waiting, or returns `None` if a writer holds the lock or is waiting
    /// for it (a waiting writer blocks new readers here as it does in [`RwSpinLock::read`]).
    pub fn try_read(&self) -> Option<RwSpinLockReadGuard<'_, T, G>> {
        let state = G::enter();
        let mut s = self.state.load(Ordering::Relaxed);
        // Retry only while other readers race us on the count; any writer means failure.
        while s & (WRITER | WAITING) == 0 && s & READERS != READERS {
            match self.state.compare_exchange_weak(s, s + 1, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => return Some(RwSpinLockReadGuard { lock: self, state: Some(state), _not_send: PhantomData }),
                Err(now) => s = now,
            }
        }
        G::exit(state);
        None
    }

    /// Acquires exclusive access without waiting, or returns `None` if any reader or writer holds the lock.
    /// Unlike [`RwSpinLock::write`], a failed attempt does not announce itself, so it does not hold off new
    /// readers.
    pub fn try_write(&self) -> Option<RwSpinLockWriteGuard<'_, T, G>> {
        let state = G::enter();
        let mut s = self.state.load(Ordering::Relaxed);
        // While the lock is free only WAITING (set by a spinning writer) can change under us.
        while s & !WAITING == 0 {
            match self.state.compare_exchange_weak(s, WRITER, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => return Some(RwSpinLockWriteGuard { lock: self, state: Some(state), _not_send: PhantomData }),
                Err(now) => s = now,
            }
        }
        G::exit(state);
        None
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
pub struct RwSpinLockReadGuard<'lock, T: ?Sized, G: Guardian = PreemptDisabled> {
    lock: &'lock RwSpinLock<T, G>,
    state: Option<G::State>,
    _not_send: PhantomData<*const ()>,
}

/// Exclusive access to a [`RwSpinLock`].
#[must_use]
pub struct RwSpinLockWriteGuard<'lock, T: ?Sized, G: Guardian = PreemptDisabled> {
    lock: &'lock RwSpinLock<T, G>,
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

    #[test]
    fn try_read_and_try_write_fail_instead_of_waiting() {
        let lock = RwSpinLock::<_, NoGuard>::new(1u32);
        {
            let r = lock.try_read().expect("free lock");
            let r2 = lock.try_read().expect("readers share");
            assert!(lock.try_write().is_none(), "readers exclude a writer");
            assert_eq!(*r + *r2, 2);
        }
        {
            let mut w = lock.try_write().expect("free lock");
            *w = 5;
            assert!(lock.try_read().is_none(), "a writer excludes readers");
            assert!(lock.try_write().is_none(), "a writer excludes writers");
        }
        assert_eq!(*lock.try_read().expect("released"), 5);
    }

    #[test]
    fn waiting_writer_blocks_new_readers() {
        let lock = Arc::new(RwSpinLock::<_, NoGuard>::new(0u32));
        let r = lock.read();
        let l2 = lock.clone();
        let writer = std::thread::spawn(move || *l2.write() = 7);
        // The writer announces itself (WAITING) while the read guard is held; from then on new readers fail.
        while lock.state.load(Ordering::Relaxed) & WAITING == 0 {
            std::thread::yield_now();
        }
        assert!(lock.try_read().is_none(), "a waiting writer holds off new readers");
        drop(r);
        writer.join().unwrap();
        assert_eq!(*lock.read(), 7);
        assert_eq!(lock.state.load(Ordering::Relaxed), 0, "all released, WAITING cleared");
    }
}
