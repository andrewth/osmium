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
use alloc::vec;
use alloc::vec::Vec;

use osmium_fs::{Errno, POLLERR, POLLHUP, POLLIN, POLLOUT};
use osmium_sched::WaitQueue;
use osmium_sync::Once;

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
/// passed.
pub(crate) fn wait<R>(timeout_ns: Option<u64>, mut scan: impl FnMut() -> Option<R>) -> Option<R> {
    if let Some(r) = scan() {
        return Some(r);
    }
    if timeout_ns == Some(0) {
        return None;
    }
    let deadline = timeout_ns.and_then(|t| now().map(|n| n.saturating_add(t)));
    READY.wait_until(|| match scan() {
        Some(r) => Some(Some(r)),
        None if deadline.is_some_and(|d| now().is_some_and(|n| n >= d)) => Some(None),
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
    let sec = i64::from_ne_bytes(b[..8].try_into().expect("8 bytes"));
    let frac = i64::from_ne_bytes(b[8..].try_into().expect("8 bytes"));
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
    let mut raw = vec![0u8; n * POLLFD_LEN];
    p.memory().read(fds, &mut raw)?;
    let watches: Vec<Watch> = {
        let files = p.files().lock();
        raw.as_chunks::<POLLFD_LEN>().0.iter()
            .map(|c| {
                let fd = i32::from_ne_bytes(c[..4].try_into().expect("4 bytes"));
                let events = u32::from(u16::from_ne_bytes([c[4], c[5]]));
                match files.get(fd) {
                    _ if fd < 0 => Watch { events, file: None, invalid: false },
                    Ok(f) => Watch { events, file: Some(f), invalid: false },
                    Err(_) => Watch { events, file: None, invalid: true },
                }
            })
            .collect()
    };
    let scan = || {
        let revents: Vec<u32> = watches
            .iter()
            .map(|w| match &w.file {
                Some(f) => f.file().poll() & (w.events | POLLERR | POLLHUP),
                None if w.invalid => POLLNVAL,
                None => 0,
            })
            .collect();
        revents.iter().any(|&r| r != 0).then_some(revents)
    };
    let revents = wait(timeout, scan);
    let ready = revents.as_ref().map_or(0, |r| r.iter().filter(|&&r| r != 0).count());
    for (i, c) in raw.as_chunks_mut::<POLLFD_LEN>().0.iter_mut().enumerate() {
        let r = revents.as_ref().map_or(0, |r| r[i]) as u16;
        c[6..8].copy_from_slice(&r.to_ne_bytes());
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

fn do_select(p: &Process, nfds: u64, sets: [u64; 3], timeout: Option<u64>) -> SysResult {
    if nfds > FD_SETSIZE {
        return Err(Errno::EINVAL);
    }
    let n = nfds as usize;
    // fd_set is an array of longs, so Linux transfers whole 8-byte words.
    let len = n.div_ceil(64) * 8;
    let mut s = Sets { user: sets, bits: [vec![0; len], vec![0; len], vec![0; len]] };
    for (va, bits) in s.user.iter().zip(s.bits.iter_mut()) {
        if *va != 0 {
            p.memory().read(*va, bits)?;
        }
    }
    let watched: Vec<(usize, Arc<OpenFile>)> = {
        let files = p.files().lock();
        let mut v = Vec::new();
        for fd in (0..n).filter(|&fd| s.bits.iter().any(|b| bit(b, fd))) {
            v.push((fd, files.get(fd as i32)?));
        }
        v
    };
    let scan = || {
        let mut out = [vec![0u8; len], vec![0u8; len], vec![0u8; len]];
        let mut count = 0u64;
        for (fd, f) in &watched {
            let ready = f.file().poll();
            let hit = [ready & (POLLIN | POLLHUP | POLLERR) != 0, ready & (POLLOUT | POLLERR) != 0, false];
            for (k, &h) in hit.iter().enumerate() {
                if h && bit(&s.bits[k], *fd) {
                    out[k][fd / 8] |= 1 << (fd % 8);
                    count += 1;
                }
            }
        }
        (count > 0).then_some((out, count))
    };
    let (out, count) = wait(timeout, scan).unwrap_or(([vec![0; len], vec![0; len], vec![0; len]], 0));
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
        let mask = u64::from_ne_bytes(b[..8].try_into().expect("8 bytes"));
        let size = u64::from_ne_bytes(b[8..].try_into().expect("8 bytes"));
        check_sigmask(p, mask, size)?;
    }
    do_select(p, nfds, [r, w, e], timeout)
}
