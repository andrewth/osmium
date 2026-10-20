use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU32, Ordering};

use osmium_arch::cpu::spin_hint;

use crate::guard::{Guardian, IrqDisabled, NoGuard, PreemptDisabled};

/// A fair (FIFO) ticket spin lock.
///
/// `G` decides what happens around the critical section; see [`Guardian`].
pub struct SpinLock<T: ?Sized, G: Guardian = PreemptDisabled> {
    next: AtomicU32,
    serving: AtomicU32,
    _guard: PhantomData<fn() -> G>,
    data: UnsafeCell<T>,
}

/// A spin lock that masks local interrupts while held.
pub type IrqSpinLock<T> = SpinLock<T, IrqDisabled>;

/// A spin lock with no guardian.
pub type RawSpinLock<T> = SpinLock<T, NoGuard>;

// SAFETY: the lock serializes all access to `data`, so sharing the lock only
// requires that `T` may be sent between threads.
unsafe impl<T: ?Sized + Send, G: Guardian> Sync for SpinLock<T, G> {}
// SAFETY: moving the lock moves `T`.
unsafe impl<T: ?Sized + Send, G: Guardian> Send for SpinLock<T, G> {}

impl<T, G: Guardian> SpinLock<T, G> {
    /// Creates an unlocked lock.
    pub const fn new(data: T) -> Self {
        Self {
            next: AtomicU32::new(0),
            serving: AtomicU32::new(0),
            _guard: PhantomData,
            data: UnsafeCell::new(data),
        }
    }

    /// Consumes the lock and returns the data.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

impl<T: ?Sized, G: Guardian> SpinLock<T, G> {
    /// Spins until the lock is acquired.
    pub fn lock(&self) -> SpinLockGuard<'_, T, G> {
        let state = G::enter();
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        while self.serving.load(Ordering::Acquire) != ticket {
            spin_hint();
        }
        SpinLockGuard { lock: self, state: Some(state), _not_send: PhantomData }
    }

    /// Acquires the lock if it is free.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T, G>> {
        let state = G::enter();
        let serving = self.serving.load(Ordering::Relaxed);
        if self
            .next
            .compare_exchange(serving, serving.wrapping_add(1), Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard { lock: self, state: Some(state), _not_send: PhantomData })
        } else {
            G::exit(state);
            None
        }
    }

    /// Returns true if some context holds or is waiting for the lock.
    pub fn is_locked(&self) -> bool {
        self.next.load(Ordering::Relaxed) != self.serving.load(Ordering::Relaxed)
    }

    /// Returns the data without locking; the `&mut` proves exclusivity.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }

    /// Releases a lock whose guard was leaked with [`core::mem::forget`].
    ///
    /// The guardian's exit action is not run.
    ///
    /// # Safety
    /// The lock must be held, and no guard for it may be live.
    pub unsafe fn force_unlock(&self) {
        self.serving.fetch_add(1, Ordering::Release);
    }
}

impl<T: Default, G: Guardian> Default for SpinLock<T, G> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized + fmt::Debug, G: Guardian> fmt::Debug for SpinLock<T, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_lock() {
            Some(g) => f.debug_struct("SpinLock").field("data", &&*g).finish(),
            None => f.write_str("SpinLock { <locked> }"),
        }
    }
}

/// Grants access to the data of a held [`SpinLock`]; releases it on drop.
#[must_use = "the lock is released immediately if the guard is not used"]
pub struct SpinLockGuard<'a, T: ?Sized, G: Guardian = PreemptDisabled> {
    lock: &'a SpinLock<T, G>,
    state: Option<G::State>,
    // The guardian state (IRQ flag, preempt count) belongs to this CPU.
    _not_send: PhantomData<*const ()>,
}

// SAFETY: a shared guard only hands out `&T`.
unsafe impl<T: ?Sized + Sync, G: Guardian> Sync for SpinLockGuard<'_, T, G> {}

impl<T: ?Sized, G: Guardian> Deref for SpinLockGuard<'_, T, G> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves the lock is held.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized, G: Guardian> DerefMut for SpinLockGuard<'_, T, G> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard proves the lock is held, and `&mut self` that this
        // is the only live reference.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized, G: Guardian> Drop for SpinLockGuard<'_, T, G> {
    fn drop(&mut self) {
        self.lock.serving.fetch_add(1, Ordering::Release);
        if let Some(state) = self.state.take() {
            G::exit(state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn mutual_exclusion() {
        let lock = Arc::new(RawSpinLock::new(0u64));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let lock = lock.clone();
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        *lock.lock() += 1;
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(*lock.lock(), 40_000);
    }

    #[test]
    fn try_lock_fails_while_held() {
        let lock: SpinLock<i32> = SpinLock::new(1);
        let g = lock.lock();
        assert!(lock.try_lock().is_none());
        drop(g);
        assert_eq!(*lock.try_lock().unwrap(), 1);
    }

    #[test]
    fn irq_lock_masks_and_restores() {
        use osmium_arch::irq;
        irq::enable();
        let lock = IrqSpinLock::new(());
        {
            let _g = lock.lock();
            assert!(!irq::are_enabled());
        }
        assert!(irq::are_enabled());
    }

    #[test]
    fn default_lock_disables_preemption() {
        // A CPU id no other test uses, so the per-CPU counter is ours alone.
        // SAFETY: host simulation; only this thread uses id 7.
        unsafe { osmium_arch::cpu::set_current_id(7) };
        let lock: SpinLock<()> = SpinLock::new(());
        let before = crate::preempt::count();
        let g = lock.lock();
        assert_eq!(crate::preempt::count(), before + 1);
        drop(g);
        assert_eq!(crate::preempt::count(), before);
    }
}
