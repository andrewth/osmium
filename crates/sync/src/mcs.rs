use core::cell::UnsafeCell;
use core::fmt;
use core::marker::PhantomData;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use osmium_arch::cpu::spin_hint;

use crate::guard::{Guardian, IrqDisabled, NoGuard, PreemptDisabled};

/// An MCS queued spin lock.
///
/// Each waiter spins on a flag in its own queue node (which lives on the
/// waiter's stack for the duration of the call), so contended handoff touches
/// one cache line per waiter instead of the single line a ticket lock
/// ([`SpinLock`](crate::SpinLock)) makes every waiter poll. Waiters are served
/// in FIFO order.
///
/// Because a queue node must stay at a fixed address for as long as the lock
/// may point at it, access is closure-based ([`with`](Self::with)); there is no
/// guard that could be moved or leaked while still queued.
///
/// `G` decides what happens around the critical section; see [`Guardian`].
///
/// ```
/// use osmium_sync::McsLock;
///
/// let lock: McsLock<u32> = McsLock::new(0);
/// lock.with(|n| *n += 1);
/// assert_eq!(lock.with(|n| *n), 1);
/// ```
///
/// # Lock ordering
/// Like any spin lock, nest `McsLock`s in one global order. The closure runs
/// with the lock held and the guardian entered, so it must not sleep.
pub struct McsLock<T: ?Sized, G: Guardian = PreemptDisabled> {
    /// The last queued node, or null when the lock is free.
    tail: AtomicPtr<McsNode>,
    _guard: PhantomData<fn() -> G>,
    data: UnsafeCell<T>,
}

/// An MCS lock that masks local interrupts while held.
pub type IrqMcsLock<T> = McsLock<T, IrqDisabled>;

/// An MCS lock with no guardian.
pub type RawMcsLock<T> = McsLock<T, NoGuard>;

/// A waiter's queue node.
struct McsNode {
    /// The node queued behind this one, once it has linked itself in.
    next: AtomicPtr<McsNode>,
    /// True while this node's owner must keep waiting.
    locked: AtomicBool,
}

// SAFETY: the lock serializes all access to `data`, so sharing the lock only
// requires that `T` may be sent between threads. Queue nodes are only
// reached through atomics.
unsafe impl<T: ?Sized + Send, G: Guardian> Sync for McsLock<T, G> {}
// SAFETY: moving the lock moves `T`.
unsafe impl<T: ?Sized + Send, G: Guardian> Send for McsLock<T, G> {}

impl<T, G: Guardian> McsLock<T, G> {
    /// Creates an unlocked lock.
    pub const fn new(data: T) -> Self {
        Self { tail: AtomicPtr::new(ptr::null_mut()), _guard: PhantomData, data: UnsafeCell::new(data) }
    }

    /// Consumes the lock and returns the data.
    pub fn into_inner(self) -> T {
        self.data.into_inner()
    }
}

/// Releases the lock (and runs the guardian's exit) on drop, including when
/// the critical section unwinds.
struct Held<'lock, T: ?Sized, G: Guardian> {
    lock: &'lock McsLock<T, G>,
    node: &'lock McsNode,
    state: Option<G::State>,
}

impl<T: ?Sized, G: Guardian> Drop for Held<'_, T, G> {
    fn drop(&mut self) {
        let node = ptr::from_ref(self.node).cast_mut();
        let mut next = self.node.next.load(Ordering::Acquire);
        if next.is_null() {
            // No visible successor: try to mark the lock free. Release publishes the critical section to the
            // next locker, whose `swap` on `tail` acquires it.
            if self.lock.tail.compare_exchange(node, ptr::null_mut(), Ordering::Release, Ordering::Relaxed).is_ok() {
                if let Some(state) = self.state.take() {
                    G::exit(state);
                }
                return;
            }
            // A successor swapped itself into `tail` but has not linked itself behind us yet; wait for the link.
            loop {
                next = self.node.next.load(Ordering::Acquire);
                if !next.is_null() {
                    break;
                }
                spin_hint();
            }
        }
        // SAFETY: the successor is spinning in `with` on its own node, which stays alive until it observes
        // `locked == false`; we have not cleared that yet.
        // Release hands the critical section's writes to the successor's Acquire load of `locked`.
        unsafe { (*next).locked.store(false, Ordering::Release) };
        if let Some(state) = self.state.take() {
            G::exit(state);
        }
    }
}

impl<T: ?Sized, G: Guardian> McsLock<T, G> {
    /// Spins until the lock is acquired, runs `f` on the data and releases the lock.
    ///
    /// If `f` panics (on a host with unwinding), the lock is still released.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let node = McsNode { next: AtomicPtr::new(ptr::null_mut()), locked: AtomicBool::new(true) };
        let state = G::enter();
        let node_ptr = ptr::from_ref(&node).cast_mut();
        // AcqRel: Acquire pairs with the previous holder's Release (when we find the lock free); Release
        // publishes our initialized node to the successor that will swap after us.
        let prev = self.tail.swap(node_ptr, Ordering::AcqRel);
        if !prev.is_null() {
            // SAFETY: `prev` is queued, and its owner cannot leave `with` before it has linked a successor
            // (it waits for `next` when `tail != prev`), so the node is still alive.
            // Release makes our node's initialization visible to the predecessor that follows this link.
            unsafe { (*prev).next.store(node_ptr, Ordering::Release) };
            // Acquire pairs with the predecessor's Release store of `false`, ordering its critical section
            // before ours.
            while node.locked.load(Ordering::Acquire) {
                spin_hint();
            }
        }
        let _held = Held { lock: self, node: &node, state: Some(state) };
        // SAFETY: we hold the lock until `_held` drops, so no other reference to the data exists.
        f(unsafe { &mut *self.data.get() })
    }

    /// Acquires the lock if it is free and runs `f`; returns `None` if the lock is held or contended.
    pub fn try_with<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let node = McsNode { next: AtomicPtr::new(ptr::null_mut()), locked: AtomicBool::new(false) };
        let state = G::enter();
        let node_ptr = ptr::from_ref(&node).cast_mut();
        // Acquire pairs with the Release of the previous unlock; failure takes nothing.
        if self.tail.compare_exchange(ptr::null_mut(), node_ptr, Ordering::Acquire, Ordering::Relaxed).is_err() {
            G::exit(state);
            return None;
        }
        let _held = Held { lock: self, node: &node, state: Some(state) };
        // SAFETY: as in `with`; the successful CAS made us the holder.
        Some(f(unsafe { &mut *self.data.get() }))
    }

    /// Returns true if some context holds or is waiting for the lock.
    pub fn is_locked(&self) -> bool {
        !self.tail.load(Ordering::Relaxed).is_null()
    }

    /// Returns the data without locking; the `&mut` proves exclusivity.
    pub fn get_mut(&mut self) -> &mut T {
        self.data.get_mut()
    }
}

impl<T: Default, G: Guardian> Default for McsLock<T, G> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized + fmt::Debug, G: Guardian> fmt::Debug for McsLock<T, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_with(|d| f.debug_struct("McsLock").field("data", &&*d).finish()) {
            Some(r) => r,
            None => f.write_str("McsLock { <locked> }"),
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
        let lock = Arc::new(RawMcsLock::new(0u64));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let lock = lock.clone();
                std::thread::spawn(move || {
                    for _ in 0..20_000 {
                        lock.with(|n| *n += 1);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(lock.with(|n| *n), 160_000);
        assert!(!lock.is_locked());
    }

    #[test]
    fn non_atomic_state_is_protected() {
        // Two fields updated non-atomically must always be observed equal.
        let lock = Arc::new(McsLock::<(u64, u64)>::new((0, 0)));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let lock = lock.clone();
                std::thread::spawn(move || {
                    for _ in 0..5_000 {
                        lock.with(|(a, b)| {
                            assert_eq!(*a, *b);
                            *a += 1;
                            std::thread::yield_now();
                            *b += 1;
                        });
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(lock.with(|d| *d), (20_000, 20_000));
    }

    #[test]
    fn try_with_fails_while_held() {
        let lock: McsLock<i32> = McsLock::new(1);
        lock.with(|_| {
            assert!(lock.try_with(|_| ()).is_none());
            assert!(lock.is_locked());
        });
        assert_eq!(lock.try_with(|n| *n), Some(1));
        assert!(!lock.is_locked());
    }

    #[test]
    fn released_after_panic() {
        let lock = Arc::new(McsLock::<i32>::new(0));
        let l = lock.clone();
        let r = std::thread::spawn(move || l.with(|_| panic!("boom"))).join();
        assert!(r.is_err());
        assert_eq!(lock.try_with(|n| *n), Some(0));
    }

    #[test]
    fn irq_lock_masks_and_restores() {
        use osmium_arch::irq;
        irq::enable();
        let lock = IrqMcsLock::new(());
        lock.with(|_| assert!(!irq::are_enabled()));
        assert!(irq::are_enabled());
    }

    #[test]
    fn default_lock_disables_preemption() {
        // SAFETY: host simulation; only this thread uses id 9.
        unsafe { osmium_arch::cpu::set_current_id(9) };
        let lock: McsLock<()> = McsLock::new(());
        let before = crate::preempt::count();
        lock.with(|_| assert_eq!(crate::preempt::count(), before + 1));
        assert_eq!(crate::preempt::count(), before);
    }
}
