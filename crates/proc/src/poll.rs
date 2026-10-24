//! Waiting for readiness: `poll`, `ppoll`, `select` and `pselect6`, and the
//! wait queue that `epoll` shares with them.
//!
//! A file reports its readiness through [`osmium_fs::File::poll`]. A call that has to
//! wait sleeps on one global queue, which every source of readiness wakes
//! after it changes: the [`NetStack`](crate::net::NetStack) whenever it runs,
//! and the in-memory socket pairs whenever they move data.
//!
//! # Timeouts
//!
//! A timeout needs a clock: the kernel's [`set_clock`], or failing that the
//! network stack's. Without either, a call with a positive timeout waits for
//! readiness alone (a zero timeout still returns at once). A sleeping call
//! notices its deadline only when something wakes the queue, so the kernel
//! should call [`tick`] from its timer (polling the network stack does it
//! too).
//!
//! The signal mask arguments of `ppoll`, `pselect6` and `epoll_pwait` are
//! validated and ignored, and the remaining time is not written back.

use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_fs::{Errno, POLLERR, POLLHUP, POLLIN, POLLOUT};
use osmium_sched::WaitQueue;
use osmium_sync::Once;
use osmium_sync::fallible::try_zeroed;

use crate::fd::{MAX_FDS, OpenFile};
use crate::net::stack;
use crate::process::Process;

type SysResult = Result<u64, Errno>;

/// Reported for a descriptor that is not open.
const POLLNVAL: u32 = 0x20;
/// Most descriptors `select` takes (`FD_SETSIZE`).
const FD_SETSIZE: u64 = 1024;
/// `sizeof(struct pollfd)`.
const POLLFD_LEN: usize = 8;

static READY: WaitQueue = WaitQueue::new();
static CLOCK: Once<fn() -> u64> = Once::new();

/// Sets the monotonic clock (nanoseconds) that timeouts of `poll`, `select`
/// and `epoll_wait` count by. Without one, the network stack's clock is used,
/// if there is a stack. Panics if called twice.
pub fn set_clock(now_ns: fn() -> u64) {
    assert!(CLOCK.set(now_ns).is_ok(), "poll clock already set");
}

/// Wakes every task waiting in `poll`, `select` or `epoll_wait`, so each
/// rechecks its files and its deadline. Call it from a timer.
pub fn tick() {
    notify();
}

/// Wakes the waiters after something became ready (or stopped being so).
/// Never call it with a lock held that [`osmium_fs::File::poll`] takes.
pub(crate) fn notify() {
    READY.wake_all();
}

fn now() -> Option<u64> {
    match CLOCK.get() {
        Some(f) => Some(f()),
        None => stack().map(|s| s.clock_ns()),
    }
}

/// Runs `scan` until it returns `Some`, sleeping between attempts, and
/// returns that; returns `None` once `timeout_ns` (`None` for no limit) has
/// passed. `EINTR` if the calling thread is interrupted by a signal or its
/// process is ending, with nothing ready (see
/// [`crate::signal::current_interrupted`]).
pub(crate) fn wait<R>(timeout_ns: Option<u64>, mut scan: impl FnMut() -> Option<R>) -> Result<Option<R>, Errno> {
    if let Some(r) = scan() {
        return Ok(Some(r));
    }
    if timeout_ns == Some(0) {
        return Ok(None);
    }
    let deadline = timeout_ns.and_then(|t| now().map(|n| n.saturating_add(t)));
    READY.wait_until(|| match scan() {
        Some(r) => Some(Ok(Some(r))),
        None if crate::signal::current_interrupted() => Some(Err(Errno::EINTR)),
        None if deadline.is_some_and(|d| now().is_some_and(|n| n >= d)) => Some(Ok(None)),
        None => None,
    })
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

/// Checks the `sigset_t` pointer and size that `ppoll` and `epoll_pwait` take.
pub(crate) fn check_sigmask(p: &Process, mask: u64, size: u64) -> Result<(), Errno> {
    if mask == 0 {
        return Ok(());
    }
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    p.memory().read(mask, &mut [0u8; 8])
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
    // On a timeout the last scan found nothing, so every revent is 0.
    wait(timeout, scan)?;
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

pub(crate) fn ppoll(p: &Process, fds: u64, nfds: u64, ts: u64, mask: u64, size: u64) -> SysResult {
    let timeout = user_timeout(p, ts, false)?;
    check_sigmask(p, mask, size)?;
    do_poll(p, fds, nfds, timeout)
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
    // On a timeout the last scan found nothing, so the sets are all clear.
    wait(timeout, scan)?;
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

pub(crate) fn pselect6(p: &Process, nfds: u64, r: u64, w: u64, e: u64, ts: u64, sig: u64) -> SysResult {
    let timeout = user_timeout(p, ts, false)?;
    if sig != 0 {
        // struct { const sigset_t *mask; size_t size; }
        let mut b = [0u8; 16];
        p.memory().read(sig, &mut b)?;
        let mask = crate::bytes::u64_at(&b, 0)?;
        let size = crate::bytes::u64_at(&b, 8)?;
        check_sigmask(p, mask, size)?;
    }
    do_select(p, nfds, [r, w, e], timeout)
}
