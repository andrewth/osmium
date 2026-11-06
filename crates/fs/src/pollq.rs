// SPDX-License-Identifier: GPL-2.0-only
//! Readiness notification: the queue of wakers a file tells when what its
//! [`File::poll`](crate::File::poll) reports may have changed.
//!
//! A file that can change readiness on its own (a pipe, a socket) keeps a
//! [`PollQueue`] and returns it from
//! [`File::poll_queue`](crate::File::poll_queue). A waiter (`poll`, `select`,
//! `epoll`, or a blocking read) registers a [`Waker`] in the queue of each
//! file it watches, checks [`File::poll`](crate::File::poll), and sleeps; the
//! file calls [`PollQueue::notify`] after each change, which wakes only the
//! waiters registered with it. A file with no queue of its own (the default)
//! is watched through whatever global fallback the waiter's layer has.

use alloc::vec::Vec;
use core::task::Waker;

use osmium_sync::IrqSpinLock;

use crate::Errno;

struct Inner {
    /// The token the next registration gets.
    next: u64,
    wakers: Vec<(u64, Waker)>,
}

/// The wakers to tell when a file's readiness may have changed.
///
/// Wakers run under the queue's lock, with interrupts disabled: they must
/// only make their task runnable (or tell another queue), never register in
/// or unregister from this queue, and never take a lock that is held while
/// [`notify`](Self::notify) is called.
pub struct PollQueue {
    inner: IrqSpinLock<Inner>,
}

impl Default for PollQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for PollQueue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PollQueue").field("wakers", &self.inner.lock().wakers.len()).finish()
    }
}

impl PollQueue {
    /// An empty queue.
    pub const fn new() -> Self {
        Self { inner: IrqSpinLock::new(Inner { next: 0, wakers: Vec::new() }) }
    }

    /// Adds `waker` for as long as the returned registration lives. `ENOMEM`
    /// if there is no memory to record it.
    pub fn register(&self, waker: &Waker) -> Result<PollRegistration<'_>, Errno> {
        let token = self.register_token(waker)?;
        Ok(PollRegistration { queue: self, token })
    }

    /// Adds `waker` until [`unregister`](Self::unregister) is called with
    /// the returned token, for a registration that outlives any borrow of
    /// the queue (an `epoll` interest list's). `ENOMEM` if there is no
    /// memory to record it.
    pub fn register_token(&self, waker: &Waker) -> Result<u64, Errno> {
        let mut g = self.inner.lock();
        g.wakers.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let token = g.next;
        g.next = g.next.wrapping_add(1);
        g.wakers.push((token, waker.clone()));
        Ok(token)
    }

    /// Removes the waker [`register_token`](Self::register_token) returned
    /// `token` for; nothing if it is not registered.
    pub fn unregister(&self, token: u64) {
        let mut g = self.inner.lock();
        if let Some(i) = g.wakers.iter().position(|&(t, _)| t == token) {
            // Dropped under the lock: dropping a waker only releases a reference.
            g.wakers.swap_remove(i);
        }
    }

    /// Wakes every registered waker (they stay registered). Call it after a
    /// change to what the file's `poll` reports, without holding a lock that
    /// `poll` takes.
    pub fn notify(&self) {
        let g = self.inner.lock();
        for (_, w) in &g.wakers {
            w.wake_by_ref();
        }
    }

    /// How many wakers are registered.
    pub fn len(&self) -> usize {
        self.inner.lock().wakers.len()
    }

    /// Whether no waker is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A waker registered in a [`PollQueue`], removed when this is dropped.
#[derive(Debug)]
pub struct PollRegistration<'queue> {
    queue: &'queue PollQueue,
    token: u64,
}

impl PollRegistration<'_> {
    /// Whether this registration is in `queue`.
    pub fn is_in(&self, queue: &PollQueue) -> bool {
        core::ptr::eq(self.queue, queue)
    }
}

impl Drop for PollRegistration<'_> {
    fn drop(&mut self) {
        self.queue.unregister(self.token);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use alloc::sync::Arc;
    use alloc::task::Wake;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Default)]
    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn notify_wakes_only_registered_wakers_until_they_go() {
        let (a, b) = (Arc::new(Count::default()), Arc::new(Count::default()));
        let (wa, wb) = (Waker::from(a.clone()), Waker::from(b.clone()));
        let (q, other) = (PollQueue::new(), PollQueue::new());
        let ra = q.register(&wa).unwrap();
        let token = other.register_token(&wb).unwrap();
        assert!(ra.is_in(&q) && !ra.is_in(&other));
        q.notify();
        q.notify();
        assert_eq!((a.0.load(Ordering::SeqCst), b.0.load(Ordering::SeqCst)), (2, 0));
        other.notify();
        assert_eq!(b.0.load(Ordering::SeqCst), 1);
        drop(ra);
        other.unregister(token);
        assert!(q.is_empty() && other.is_empty());
        q.notify();
        other.notify();
        assert_eq!((a.0.load(Ordering::SeqCst), b.0.load(Ordering::SeqCst)), (2, 1), "unregistered");
        other.unregister(token);
    }
}
