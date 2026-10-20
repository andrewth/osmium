//! Deadline-ordered timer callbacks.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use osmium_sync::IrqSpinLock;

use crate::sync::WaitQueue;

/// Identifies a pending timer, for [`TimerQueue::cancel`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimerId {
    deadline: u64,
    seq: u64,
}

type Callback = Box<dyn FnOnce() + Send>;

/// Callbacks keyed by deadline. The time unit is whatever the caller uses
/// consistently (nanoseconds or raw ticks).
///
/// Drive it from the timer interrupt: call [`TimerQueue::process`] with the
/// current time, then program the hardware for [`TimerQueue::next_deadline`].
pub struct TimerQueue {
    timers: IrqSpinLock<BTreeMap<TimerId, Callback>>,
    seq: AtomicU64,
}

impl TimerQueue {
    /// Creates an empty queue.
    pub const fn new() -> Self {
        Self { timers: IrqSpinLock::new(BTreeMap::new()), seq: AtomicU64::new(0) }
    }

    /// Runs `callback` once `process` is called with a time of at least `deadline`.
    pub fn add(&self, deadline: u64, callback: impl FnOnce() + Send + 'static) -> TimerId {
        let id = TimerId { deadline, seq: self.seq.fetch_add(1, Ordering::Relaxed) };
        self.timers.lock().insert(id, Box::new(callback));
        id
    }

    /// Cancels a pending timer. Returns false if it already fired.
    pub fn cancel(&self, id: TimerId) -> bool {
        self.timers.lock().remove(&id).is_some()
    }

    /// The earliest pending deadline.
    pub fn next_deadline(&self) -> Option<u64> {
        self.timers.lock().keys().next().map(|k| k.deadline)
    }

    /// Runs every callback whose deadline is at or before `now`, in deadline
    /// order, without holding the lock. Returns how many ran.
    pub fn process(&self, now: u64) -> usize {
        let mut n = 0;
        loop {
            let due = {
                let mut timers = self.timers.lock();
                match timers.first_key_value() {
                    Some((k, _)) if k.deadline <= now => timers.pop_first(),
                    _ => None,
                }
            };
            match due {
                Some((_, cb)) => {
                    cb();
                    n += 1;
                }
                None => return n,
            }
        }
    }

    /// Blocks the calling task until `process` has seen time `deadline`.
    pub fn sleep_until(&self, deadline: u64) {
        let fired = Arc::new((AtomicBool::new(false), WaitQueue::new()));
        let f = fired.clone();
        self.add(deadline, move || {
            f.0.store(true, Ordering::Release);
            f.1.wake_all();
        });
        fired.1.wait_until(|| fired.0.load(Ordering::Acquire).then_some(()));
    }
}

impl Default for TimerQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::vec::Vec;

    #[test]
    fn ordered_and_cancellable() {
        let q = TimerQueue::new();
        let log = Arc::new(Mutex::new(Vec::new()));
        for (d, tag) in [(30, 'c'), (10, 'a'), (20, 'b'), (10, 'A')] {
            let log = log.clone();
            q.add(d, move || log.lock().unwrap().push(tag));
        }
        let gone = q.add(15, || panic!("cancelled timer ran"));
        assert!(q.cancel(gone));
        assert_eq!(q.next_deadline(), Some(10));
        assert_eq!(q.process(20), 3);
        assert_eq!(*log.lock().unwrap(), ['a', 'A', 'b']);
        assert_eq!(q.next_deadline(), Some(30));
    }
}
