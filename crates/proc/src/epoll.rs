//! `epoll`: an interest list of open files that reports which are ready.
//!
//! The list holds files weakly, so closing every descriptor of a file drops
//! it from the list, as on Linux. Level-triggered by default; `EPOLLET`
//! reports a condition when it newly appears since the last time the file
//! was checked, and `EPOLLONESHOT` disarms an entry after one report. An
//! epoll descriptor may be watched by another, to one level of nesting.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use osmium_fs::{Errno, File, FileKind, POLLERR, POLLHUP, POLLIN, Stat};
use osmium_sync::IrqSpinLock;

use crate::fd::{Access, OpenFile};
use crate::poll::{check_sigmask, notify, user_add, wait};
use crate::process::Process;

type SysResult = Result<u64, Errno>;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
const EPOLL_CLOEXEC: u64 = 0o2000000;
const EPOLLET: u32 = 1 << 31;
const EPOLLONESHOT: u32 = 1 << 30;
/// Most events one `epoll_wait` returns.
const MAX_EVENTS: usize = 1024;
/// Most descriptors one epoll instance watches.
const MAX_WATCHES: usize = 4096;

/// `struct epoll_event` is packed on x86_64 only.
#[cfg(target_arch = "x86_64")]
const EVENT_LEN: usize = 12;
#[cfg(not(target_arch = "x86_64"))]
const EVENT_LEN: usize = 16;
#[cfg(target_arch = "x86_64")]
const DATA_OFF: usize = 4;
#[cfg(not(target_arch = "x86_64"))]
const DATA_OFF: usize = 8;

/// Most levels of epoll instances watching epoll instances.
const MAX_NEST: usize = 5;

/// Serialises the loop check and insert of an epoll instance into another.
static NEST: IrqSpinLock<()> = IrqSpinLock::new(());

/// One reported event, with the state it consumed.
struct Ready {
    fd: i32,
    mask: u32,
    data: u64,
    prev_last: u32,
}

struct Watch {
    file: Weak<OpenFile>,
    events: u32,
    data: u64,
    /// Conditions seen at the last check, for edge triggering.
    last: u32,
    /// A one-shot entry that has reported.
    disarmed: bool,
}

/// An epoll instance, as a file in the descriptor table.
#[derive(Default)]
pub struct EpollFile {
    watches: IrqSpinLock<BTreeMap<i32, Watch>>,
}

impl EpollFile {
    /// The ready events, at most `max`. Each carries what it changed, so
    /// [`Self::restore`] can undo it if the events cannot be delivered.
    fn collect(&self, max: usize) -> Vec<Ready> {
        let mut out = Vec::new();
        let mut watches = self.watches.lock();
        watches.retain(|_, w| w.file.strong_count() > 0);
        for (&fd, w) in watches.iter_mut() {
            if out.len() == max {
                break;
            }
            let Some(f) = w.file.upgrade() else { continue };
            if w.disarmed {
                continue;
            }
            let ready = Self::bits(&f, false) & (w.events | POLLERR | POLLHUP);
            let fire = if w.events & EPOLLET != 0 { ready & !w.last } else { ready };
            let prev_last = w.last;
            w.last = ready;
            if fire != 0 {
                if w.events & EPOLLONESHOT != 0 {
                    w.disarmed = true;
                }
                out.push(Ready { fd, mask: fire, data: w.data, prev_last });
            }
        }
        out
    }

    /// Undoes the edge and one-shot state that `collect` consumed for `ready`.
    fn restore(&self, ready: &[Ready]) {
        let mut watches = self.watches.lock();
        for r in ready {
            if let Some(w) = watches.get_mut(&r.fd).filter(|w| w.data == r.data) {
                w.last = r.prev_last;
                w.disarmed = false;
            }
        }
    }

    /// Whether `goal` is this instance or is watched, directly or through
    /// other instances, by it. Too deep a nesting counts as reachable.
    fn reaches(&self, goal: &EpollFile, depth: usize) -> bool {
        if core::ptr::eq(self, goal) {
            return true;
        }
        if depth >= MAX_NEST {
            return true;
        }
        let files: Vec<Arc<OpenFile>> = self.watches.lock().values().filter_map(|w| w.file.upgrade()).collect();
        files.iter().any(|f| {
            f.file().as_any().and_then(|a| a.downcast_ref::<EpollFile>()).is_some_and(|e| e.reaches(goal, depth + 1))
        })
    }

    /// `f`'s readiness; a nested epoll is looked into only when `shallow`
    /// is false, which bounds the recursion.
    fn bits(f: &Arc<OpenFile>, shallow: bool) -> u32 {
        match f.file().as_any().and_then(|a| a.downcast_ref::<EpollFile>()) {
            Some(_) if shallow => 0,
            Some(e) => e.any_ready(),
            None => f.file().poll(),
        }
    }

    fn any_ready(&self) -> u32 {
        let watches = self.watches.lock();
        let ready = watches.values().any(|w| {
            !w.disarmed && w.file.upgrade().is_some_and(|f| Self::bits(&f, true) & (w.events | POLLERR | POLLHUP) != 0)
        });
        if ready { POLLIN } else { 0 }
    }
}

impl File for EpollFile {
    fn stat(&self) -> Stat {
        Stat { kind: FileKind::Fifo, mode: 0o600, nlink: 1, ..Stat::default() }
    }

    fn poll(&self) -> u32 {
        self.any_ready()
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

pub(crate) fn create1(p: &Process, flags: u64) -> SysResult {
    if flags & !EPOLL_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    let open = OpenFile::new(Arc::new(EpollFile::default()), Access::RW);
    p.files().lock().insert_from(0, open, flags & EPOLL_CLOEXEC != 0).map(|fd| fd as u64)
}

/// The legacy `epoll_create(size)`: `size` only has to be positive.
#[cfg(target_arch = "x86_64")]
pub(crate) fn create(p: &Process, size: u64) -> SysResult {
    if size as i32 <= 0 {
        return Err(Errno::EINVAL);
    }
    create1(p, 0)
}

pub(crate) fn ctl(p: &Process, epfd: i32, op: u64, fd: i32, event: u64) -> SysResult {
    let (ep_file, target) = {
        let files = p.files().lock();
        (files.get(epfd)?, files.get(fd)?)
    };
    let ep = ep_file.file().as_any().and_then(|a| a.downcast_ref::<EpollFile>()).ok_or(Errno::EINVAL)?;
    if epfd == fd || Arc::ptr_eq(&ep_file, &target) {
        return Err(Errno::EINVAL);
    }
    let (events, data) = if op == EPOLL_CTL_DEL {
        (0, 0)
    } else {
        let mut b = [0u8; EVENT_LEN];
        p.memory().read(event, &mut b)?;
        let events = u32::from_ne_bytes(b[..4].try_into().expect("4 bytes"));
        let data = u64::from_ne_bytes(b[DATA_OFF..DATA_OFF + 8].try_into().expect("8 bytes"));
        (events, data)
    };
    // Adding an instance to another must not close a loop (collecting would
    // lock instances in a cycle); `NEST` makes the check and insert one step.
    let nest_guard =
        (op == EPOLL_CTL_ADD && target.file().as_any().is_some_and(|a| a.is::<EpollFile>())).then(|| NEST.lock());
    if nest_guard.is_some() {
        let inner = target.file().as_any().and_then(|a| a.downcast_ref::<EpollFile>()).expect("checked above");
        if inner.reaches(ep, 0) {
            return Err(Errno::ELOOP);
        }
    }
    let mut watches = ep.watches.lock();
    match op {
        EPOLL_CTL_ADD => {
            // Like Linux, refuse files that are always ready.
            if matches!(target.file().stat().kind, FileKind::Regular | FileKind::Directory | FileKind::Symlink) {
                return Err(Errno::EPERM);
            }
            if watches.get(&fd).is_some_and(|w| w.file.strong_count() > 0) {
                return Err(Errno::EEXIST);
            }
            if watches.len() >= MAX_WATCHES {
                return Err(Errno::ENOSPC);
            }
            watches.insert(fd, Watch { file: Arc::downgrade(&target), events, data, last: 0, disarmed: false });
        }
        EPOLL_CTL_MOD => {
            let w = watches.get_mut(&fd).ok_or(Errno::ENOENT)?;
            *w = Watch { file: w.file.clone(), events, data, last: 0, disarmed: false };
        }
        EPOLL_CTL_DEL => {
            watches.remove(&fd).ok_or(Errno::ENOENT)?;
        }
        _ => return Err(Errno::EINVAL),
    }
    drop(watches);
    drop(nest_guard);
    notify();
    Ok(0)
}

pub(crate) fn wait_events(p: &Process, epfd: i32, events: u64, max: u64, timeout_ms: u64) -> SysResult {
    let max = max as i32;
    if max <= 0 {
        return Err(Errno::EINVAL);
    }
    let max = (max as usize).min(MAX_EVENTS);
    let ep_file = p.files().lock().get(epfd)?;
    let ep = ep_file.file().as_any().and_then(|a| a.downcast_ref::<EpollFile>()).ok_or(Errno::EINVAL)?;
    // Check the buffer is writable before consuming one-shot or edge events.
    user_add(events, (max * EVENT_LEN) as u64)?;
    let ms = timeout_ms as i32;
    let timeout = (ms >= 0).then(|| u64::from(ms as u32) * 1_000_000);
    let ready = wait(timeout, || {
        let v = ep.collect(max);
        (!v.is_empty()).then_some(v)
    })?
    .unwrap_or_default();
    let mut out = alloc::vec![0u8; ready.len() * EVENT_LEN];
    for (c, r) in out.as_chunks_mut::<EVENT_LEN>().0.iter_mut().zip(&ready) {
        c[..4].copy_from_slice(&r.mask.to_ne_bytes());
        c[DATA_OFF..DATA_OFF + 8].copy_from_slice(&r.data.to_ne_bytes());
    }
    if let Err(e) = p.memory().write(events, &out) {
        // Nothing was delivered, so the events must stay pending.
        ep.restore(&ready);
        return Err(e);
    }
    Ok(ready.len() as u64)
}

pub(crate) fn pwait(p: &Process, epfd: i32, events: u64, max: u64, timeout_ms: u64, mask: u64, size: u64) -> SysResult {
    check_sigmask(p, mask, size)?;
    wait_events(p, epfd, events, max, timeout_ms)
}
