//! Waiting for readiness: `poll`, `ppoll`, `select` and `pselect6`, and the
//! wait queue that `epoll` shares with them.
//!
//! A file reports its readiness through [`osmium_fs::File::poll`], and says
//! when that may have changed through its [`osmium_fs::File::poll_queue`]. A
//! call that has to wait registers with the queue of each file it watches
//! and sleeps until one of them is notified, so a change to one file wakes
//! only the calls watching it: a pipe and each Unix socket have a queue of
//! their own, and the network stack's sockets share the
//! [`NetStack`](crate::net::NetStack)'s, which it notifies whenever it runs.
//! A file without a queue (a device, say) is watched through a global one,
//! which only [`tick`] (and the network stack, as it runs) notifies. A signal
//! or the end of a process wakes only the threads it concerns, wherever they
//! sleep (`signal::wait_on`).
//!
//! # Timeouts
//!
//! A timeout needs a clock: the kernel's [`set_clock`], or failing that the
//! network stack's. Without either, a call with a positive timeout waits for
//! readiness alone (a zero timeout still returns at once). A sleeping call
//! notices its deadline only when [`tick`] runs (or one of its files changes),
//! so the kernel should call [`tick`] from its timer (polling the network
//! stack does it too).
//!
//! `ppoll`, `pselect6` and `epoll_pwait` install their signal mask for the
//! wait, atomically with it, as Linux does: a signal the new mask lets in
//! interrupts the wait (`EINTR`), and its handler runs with the new mask
//! still in place; the caller's own mask comes back when the handler
//! returns, or when the call returns if no handler runs. The remaining time
//! is not written back.

use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::Waker;

use osmium_fs::{Errno, File, POLLERR, POLLHUP, POLLIN, POLLOUT, PollQueue, PollRegistration};
use osmium_sched::WaitQueue;
use osmium_sync::Once;
use osmium_sync::fallible::{try_arc, try_zeroed};

use crate::fd::{MAX_FDS, OpenFile};
use crate::net::stack;
use crate::process::Process;
use crate::thread::Thread;

type SysResult = Result<u64, Errno>;

/// Reported for a descriptor that is not open.
const POLLNVAL: u32 = 0x20;
/// Most descriptors `select` takes (`FD_SETSIZE`).
const FD_SETSIZE: u64 = 1024;
/// `sizeof(struct pollfd)`.
const POLLFD_LEN: usize = 8;

/// The queue of the files that have none of their own, and of timed waits:
/// [`tick`] notifies it.
static GLOBAL: PollQueue = PollQueue::new();
static CLOCK: Once<fn() -> u64> = Once::new();

/// Sets the monotonic clock (nanoseconds) that timeouts of `poll`, `select`
/// and `epoll_wait` count by. Without one, the network stack's clock is used,
/// if there is a stack. Panics if called twice.
pub fn set_clock(now_ns: fn() -> u64) {
    assert!(CLOCK.set(now_ns).is_ok(), "poll clock already set");
}

/// Wakes the tasks waiting in `poll`, `select`, `epoll_wait` or a blocking
/// read or write that have a deadline, or watch a file with no
/// [`poll_queue`](osmium_fs::File::poll_queue) of its own, so each rechecks
/// its files and its deadline. Call it from a timer.
pub fn tick() {
    GLOBAL.notify();
}

/// The queue that tells waiters `f` may have changed: its own, or the global one.
pub(crate) fn queue_of(f: &dyn File) -> &PollQueue {
    f.poll_queue().unwrap_or(&GLOBAL)
}

/// What a waiting call sleeps in; the files' queues wake it through a
/// [`Waker`], which sets `woken` first.
struct Sleeper {
    woken: AtomicBool,
    queue: WaitQueue,
}

impl Wake for Sleeper {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::SeqCst);
        self.queue.wake_all();
    }
}

fn now() -> Option<u64> {
    match CLOCK.get() {
        Some(f) => Some(f()),
        None => stack().map(|s| s.clock_ns()),
    }
}

/// Runs `scan` until it returns `Some`, sleeping between attempts until one
/// of `queues` is notified (or, with a timeout, [`tick`] runs), and returns
/// that; returns `None` once `timeout_ns` (`None` for no limit) has passed.
/// `EINTR` if the calling thread is interrupted by a signal or its process
/// is ending, with nothing ready (see [`crate::signal::current_interrupted`]).
/// `ENOMEM` if there is no memory to register with the queues.
///
/// `scan` runs with no lock of the wait's held: a file may notify its queue
/// with its own lock held, and `scan` may take any lock that is not held
/// around a [`PollQueue::notify`].
pub(crate) fn wait<'q, R>(
    queues: impl IntoIterator<Item = &'q PollQueue>,
    timeout_ns: Option<u64>,
    mut scan: impl FnMut() -> Option<R>,
) -> Result<Option<R>, Errno> {
    if let Some(r) = scan() {
        return Ok(Some(r));
    }
    if timeout_ns == Some(0) {
        return Ok(None);
    }
    let deadline = timeout_ns.and_then(|t| now().map(|n| n.saturating_add(t)));
    let sleeper = try_arc(Sleeper { woken: AtomicBool::new(false), queue: WaitQueue::new() }).map_err(crate::oom)?;
    let waker = Waker::from(sleeper.clone());
    let mut regs: Vec<PollRegistration<'q>> = Vec::new();
    let timed = deadline.is_some().then_some(&GLOBAL);
    for q in queues.into_iter().chain(timed) {
        // Files often share a queue (a pipe's two ends, the network's sockets).
        if !regs.iter().any(|r| r.is_in(q)) {
            regs.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            regs.push(q.register(&waker)?);
        }
    }
    let expired = || deadline.is_some_and(|d| now().is_some_and(|n| n >= d));
    let r = loop {
        // Cleared before the scan: a change after it sets the flag again.
        sleeper.woken.store(false, Ordering::SeqCst);
        if let Some(r) = scan() {
            break Ok(Some(r));
        }
        if crate::signal::current_interrupted() {
            break Err(Errno::EINTR);
        }
        if expired() {
            break Ok(None);
        }
        crate::signal::wait_on(&sleeper.queue, || {
            (sleeper.woken.load(Ordering::SeqCst) || crate::signal::current_interrupted() || expired()).then_some(())
        });
    };
    drop(regs);
    r
}

/// `user + n`, or `EFAULT` if it wraps.
pub(crate) fn user_add(va: u64, n: u64) -> Result<u64, Errno> {
    va.checked_add(n).ok_or(Errno::EFAULT)
}

/// A `struct timespec` (`nanos_per` of 1) or `struct timeval` (1000) at `va`
/// as nanoseconds; `None` for a null pointer, which means no timeout.
fn user_timeout(p: &Process, va: u64, usec: bool) -> Result<Option<u64>, Errno> {
    if va == 0 {
        return Ok(None);
    }
    let mut b = [0u8; 16];
    p.memory().read(va, &mut b)?;
    let sec = crate::bytes::i64_at(&b, 0)?;
    let frac = crate::bytes::i64_at(&b, 8)?;
    let (unit, limit) = if usec { (1_000, 1_000_000) } else { (1, 1_000_000_000) };
    if sec < 0 || !(0..limit).contains(&frac) {
        return Err(Errno::EINVAL);
    }
    let ns = (sec as u64).checked_mul(1_000_000_000).and_then(|s| s.checked_add(frac as u64 * unit));
    // Longer than 584 years is for ever.
    Ok(Some(ns.unwrap_or(u64::MAX)))
}

/// Reads the `sigset_t` pointer and size that `ppoll` and `epoll_pwait`
/// take: `None` for a null pointer, which leaves the mask alone.
pub(crate) fn user_sigmask(p: &Process, mask: u64, size: u64) -> Result<Option<u64>, Errno> {
    if mask == 0 {
        return Ok(None);
    }
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    let mut b = [0u8; 8];
    p.memory().read(mask, &mut b)?;
    Ok(Some(u64::from_ne_bytes(b)))
}

/// One `struct pollfd` of a `poll` call.
struct Watch {
    events: u32,
    /// `None` for a negative descriptor (ignored) or one not open.
    file: Option<Arc<OpenFile>>,
    invalid: bool,
}

fn do_poll(p: &Process, fds: u64, nfds: u64, timeout: Option<u64>) -> SysResult {
    if nfds > MAX_FDS as u64 {
        return Err(Errno::EINVAL);
    }
    let n = nfds as usize;
    // Everything the wait needs is made first, so waiting allocates nothing.
    let mut raw = try_zeroed(n * POLLFD_LEN).map_err(crate::oom)?;
    let mut watches: Vec<Watch> = Vec::new();
    watches.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
    let mut revents: Vec<u32> = Vec::new();
    revents.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
    revents.resize(n, 0);
    p.memory().read(fds, &mut raw)?;
    {
        let files = p.files().lock();
        for c in raw.as_chunks::<POLLFD_LEN>().0 {
            let fd = crate::bytes::i32_at(c, 0)?;
            let events = u32::from(crate::bytes::u16_at(c, 4)?);
            watches.push(match files.get(fd) {
                _ if fd < 0 => Watch { events, file: None, invalid: false },
                Ok(f) => Watch { events, file: Some(f), invalid: false },
                Err(_) => Watch { events, file: None, invalid: true },
            });
        }
    }
    let scan = || {
        let mut any = false;
        for (w, r) in watches.iter().zip(revents.iter_mut()) {
            *r = match &w.file {
                Some(f) => f.file().poll() & (w.events | POLLERR | POLLHUP),
                None if w.invalid => POLLNVAL,
                None => 0,
            };
            any |= *r != 0;
        }
        any.then_some(())
    };
    let queues = watches.iter().filter_map(|w| w.file.as_ref()).map(|f| queue_of(&**f.file()));
    // On a timeout the last scan found nothing, so every revent is 0.
    wait(queues, timeout, scan)?;
    let ready = revents.iter().filter(|&&r| r != 0).count();
    for (c, &r) in raw.as_chunks_mut::<POLLFD_LEN>().0.iter_mut().zip(&revents) {
        crate::bytes::put(c, 6, &(r as u16).to_ne_bytes())?;
    }
    p.memory().write(fds, &raw)?;
    Ok(ready as u64)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn poll(p: &Process, fds: u64, nfds: u64, timeout_ms: u64) -> SysResult {
    let ms = timeout_ms as i32;
    let timeout = (ms >= 0).then(|| u64::from(ms as u32) * 1_000_000);
    do_poll(p, fds, nfds, timeout)
}

pub(crate) fn ppoll(p: &Process, th: &Thread, fds: u64, nfds: u64, ts: u64, mask: u64, size: u64) -> SysResult {
    let timeout = user_timeout(p, ts, false)?;
    let mask = user_sigmask(p, mask, size)?;
    th.sig.with_mask(th, mask, || do_poll(p, fds, nfds, timeout))
}

/// The three `fd_set`s of a `select` call.
struct Sets {
    user: [u64; 3],
    bits: [Vec<u8>; 3],
}

fn bit(set: &[u8], fd: usize) -> bool {
    set.get(fd / 8).is_some_and(|b| b & (1 << (fd % 8)) != 0)
}

/// Three bit sets of `len` bytes.
fn three_sets(len: usize) -> Result<[Vec<u8>; 3], Errno> {
    let one = || try_zeroed(len).map_err(crate::oom);
    Ok([one()?, one()?, one()?])
}

fn do_select(p: &Process, nfds: u64, sets: [u64; 3], timeout: Option<u64>) -> SysResult {
    if nfds > FD_SETSIZE {
        return Err(Errno::EINVAL);
    }
    let n = nfds as usize;
    // fd_set is an array of longs, so Linux transfers whole 8-byte words.
    let len = n.div_ceil(64) * 8;
    // Everything the wait needs is made first, so waiting allocates nothing.
    let mut s = Sets { user: sets, bits: three_sets(len)? };
    let mut out = three_sets(len)?;
    let mut watched: Vec<(usize, Arc<OpenFile>)> = Vec::new();
    watched.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
    for (va, bits) in s.user.iter().zip(s.bits.iter_mut()) {
        if *va != 0 {
            p.memory().read(*va, bits)?;
        }
    }
    {
        let files = p.files().lock();
        for fd in (0..n).filter(|&fd| s.bits.iter().any(|b| bit(b, fd))) {
            watched.push((fd, files.get(fd as i32)?));
        }
    }
    let mut count = 0u64;
    let scan = || {
        for set in out.iter_mut() {
            set.fill(0);
        }
        count = 0;
        for (fd, f) in &watched {
            let ready = f.file().poll();
            let hit = [ready & (POLLIN | POLLHUP | POLLERR) != 0, ready & (POLLOUT | POLLERR) != 0, false];
            for ((&h, want), got) in hit.iter().zip(&s.bits).zip(out.iter_mut()) {
                if h && bit(want, *fd) {
                    if let Some(byte) = got.get_mut(fd / 8) {
                        *byte |= 1 << (fd % 8);
                    }
                    count += 1;
                }
            }
        }
        (count > 0).then_some(())
    };
    let queues = watched.iter().map(|(_, f)| queue_of(&**f.file()));
    // On a timeout the last scan found nothing, so the sets are all clear.
    wait(queues, timeout, scan)?;
    for (va, bits) in s.user.iter().zip(out.iter()) {
        if *va != 0 {
            p.memory().write(*va, bits)?;
        }
    }
    Ok(count)
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn select(p: &Process, nfds: u64, r: u64, w: u64, e: u64, tv: u64) -> SysResult {
    do_select(p, nfds, [r, w, e], user_timeout(p, tv, true)?)
}

#[allow(clippy::too_many_arguments)] // the system call's own six, and the thread.
pub(crate) fn pselect6(p: &Process, th: &Thread, nfds: u64, r: u64, w: u64, e: u64, ts: u64, sig: u64) -> SysResult {
    let timeout = user_timeout(p, ts, false)?;
    let mask = if sig != 0 {
        // struct { const sigset_t *mask; size_t size; }
        let mut b = [0u8; 16];
        p.memory().read(sig, &mut b)?;
        let mask = crate::bytes::u64_at(&b, 0)?;
        let size = crate::bytes::u64_at(&b, 8)?;
        user_sigmask(p, mask, size)?
    } else {
        None
    };
    th.sig.with_mask(th, mask, || do_select(p, nfds, [r, w, e], timeout))
}
