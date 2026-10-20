//! Blocking synchronization built on the scheduler.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use osmium_sync::IrqSpinLock;

use crate::core_sched::{block_current, current, wake};
use crate::task::{Task, TaskState};

/// A queue of tasks waiting for a condition.
///
/// [`WaitQueue::wait_until`] evaluates the condition with the queue locked,
/// and wakers lock the queue after making the condition true, so a wake-up
/// can never fall between the check and going to sleep.
pub struct WaitQueue {
    waiters: IrqSpinLock<VecDeque<Arc<Task>>>,
}

impl WaitQueue {
    /// Creates an empty queue.
    pub const fn new() -> Self {
        Self { waiters: IrqSpinLock::new(VecDeque::new()) }
    }

    /// Blocks until `cond` returns `Some`, and returns that value.
    ///
    /// `cond` runs with the queue's spin lock held and interrupts masked, so
    /// it must be short and must not block.
    pub fn wait_until<R>(&self, mut cond: impl FnMut() -> Option<R>) -> R {
        loop {
            {
                let mut waiters = self.waiters.lock();
                if let Some(r) = cond() {
                    return r;
                }
                let me = current();
                me.state.store(TaskState::Blocked as u8, Ordering::Release);
                waiters.push_back(me);
            }
            block_current();
        }
    }

    /// Wakes the longest-waiting task. Returns false if none was waiting.
    pub fn wake_one(&self) -> bool {
        loop {
            let Some(t) = self.waiters.lock().pop_front() else { return false };
            if wake(t) {
                return true;
            }
        }
    }

    /// Wakes every waiting task; returns how many were woken.
    pub fn wake_all(&self) -> usize {
        let waiters = core::mem::take(&mut *self.waiters.lock());
        waiters.into_iter().filter(|t| wake(t.clone())).count()
    }

    /// Number of queued waiters (some may already have been woken elsewhere).
    pub fn len(&self) -> usize {
        self.waiters.lock().len()
    }

    /// Returns true if nobody is waiting.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// A sleeping mutual-exclusion lock. Waiters block instead of spinning.
pub struct Mutex<T: ?Sized> {
    locked: AtomicBool,
    waiters: WaitQueue,
    data: UnsafeCell<T>,
}

// SAFETY: the lock serializes access to `data`.
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}
// SAFETY: moving the mutex moves `T`.
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

impl<T> Mutex<T> {
    /// Creates an unlocked mutex.
    pub const fn new(data: T) -> Self {
        Self { locked: AtomicBool::new(false), waiters: WaitQueue::new(), data: UnsafeCell::new(data) }
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Acquires the lock, blocking while another task holds it.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        match self.try_lock() {
            Some(g) => g,
            None => self.waiters.wait_until(|| self.try_lock()),
        }
    }

    /// Acquires the lock if it is free.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
            .then(|| MutexGuard { mutex: self })
    }
}

/// Access to the data of a locked [`Mutex`].
#[must_use]
pub struct MutexGuard<'a, T: ?Sized> {
    mutex: &'a Mutex<T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves the lock is held.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard proves the lock is held, exclusively.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
        self.mutex.waiters.wake_one();
    }
}

/// A counting semaphore.
pub struct Semaphore {
    count: AtomicUsize,
    waiters: WaitQueue,
}

impl Semaphore {
    /// Creates a semaphore with `permits` available.
    pub const fn new(permits: usize) -> Self {
        Self { count: AtomicUsize::new(permits), waiters: WaitQueue::new() }
    }

    /// Takes a permit if one is available.
    pub fn try_acquire(&self) -> bool {
        let mut c = self.count.load(Ordering::Relaxed);
        while c > 0 {
            match self.count.compare_exchange_weak(c, c - 1, Ordering::Acquire, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(now) => c = now,
            }
        }
        false
    }

    /// Takes a permit, blocking until one is available.
    pub fn acquire(&self) {
        self.waiters.wait_until(|| self.try_acquire().then_some(()));
    }

    /// Returns a permit.
    pub fn release(&self) {
        self.count.fetch_add(1, Ordering::Release);
        self.waiters.wake_one();
    }

    /// Permits currently available.
    pub fn available(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}
