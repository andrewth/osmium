//! `epoll`: an interest list of open files that reports which are ready.
//!
//! The list holds files weakly, so closing every descriptor of a file drops
//! it from the list, as on Linux. Level-triggered by default; `EPOLLET`
//! reports a condition when it newly appears since the last time the file
//! was checked, and `EPOLLONESHOT` disarms an entry after one report. An
//! epoll descriptor may be watched by another, to one level of nesting.
//!
//! Each watch registers the instance with its file's
//! [`poll_queue`](osmium_fs::File::poll_queue) (the global one, for a file
//! without), so a change to a watched file wakes the instance's waiters,
//! and nothing else does.

use alloc::sync::{Arc, Weak};
use alloc::task::Wake;
use alloc::vec::Vec;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::task::Waker;

use osmium_fs::{Errno, File, FileKind, POLLERR, POLLHUP, POLLIN, PollQueue, Stat};
use osmium_sync::IrqSpinLock;
use osmium_sync::arc::ArcTree;
use osmium_sync::fallible::{try_arc, try_zeroed};
use osmium_sync::intrusive::{Adapter, KeyAdapter, Shared, TreeLink};

use crate::bytes;
use crate::fd::{Access, OpenFile};
use crate::poll::{queue_of, user_add, user_sigmask, wait};
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

/// One entry of the interest list, linked into its instance by descriptor.
/// The fields change only under the lock around the instance's list.
struct Watch {
    fd: i32,
    file: Weak<OpenFile>,
    events: AtomicU32,
    data: AtomicU64,
    /// Conditions seen at the last check, for edge triggering.
    last: AtomicU32,
    /// A one-shot entry that has reported.
    disarmed: AtomicBool,
    link: Shared<TreeLink>,
    /// The file whose queue the instance is registered with, and the token.
    queued: Weak<dyn File>,
    token: u64,
}

impl Watch {
    /// A watch of `target`, registering `waker` (the instance's) with its queue.
    fn new(fd: i32, target: &Arc<OpenFile>, events: u32, data: u64, waker: &Waker) -> Result<Arc<Self>, Errno> {
        let file = target.file();
        let token = queue_of(&**file).register_token(waker)?;
        try_arc(Self {
            fd,
            file: Arc::downgrade(target),
            events: AtomicU32::new(events),
            data: AtomicU64::new(data),
            last: AtomicU32::new(0),
            disarmed: AtomicBool::new(false),
            link: Shared::new(TreeLink::new()),
            queued: Arc::downgrade(file),
            token,
        })
        .map_err(|e| {
            queue_of(&**file).unregister(token);
            crate::oom(e)
        })
    }

    /// `MOD`: new interest, new data, and a fresh edge and one-shot state.
    fn rearm(&self, events: u32, data: u64) {
        self.events.store(events, Ordering::Relaxed);
        self.data.store(data, Ordering::Relaxed);
        self.last.store(0, Ordering::Relaxed);
        self.disarmed.store(false, Ordering::Relaxed);
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        // A file that is gone took its queue, and the registration, with it.
        if let Some(f) = self.queued.upgrade() {
            queue_of(&*f).unregister(self.token);
        }
    }
}

struct ByFd;

// SAFETY: `offset_of!` of a `Shared<TreeLink>`, which is a `TreeLink`.
unsafe impl Adapter<TreeLink> for ByFd {
    type Value = Watch;
    const OFFSET: usize = offset_of!(Watch, link);
}

impl KeyAdapter<TreeLink> for ByFd {
    type Key = i32;

    fn key(w: &Watch) -> &i32 {
        &w.fd
    }
}

/// What the watched files' queues wake: the instance's own queue, which its
/// waiters (and instances watching it) are registered with.
struct EpollWake {
    queue: PollQueue,
}

impl Wake for EpollWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.queue.notify();
    }
}

/// An epoll instance, as a file in the descriptor table.
pub struct EpollFile {
    watches: IrqSpinLock<ArcTree<ByFd>>,
    wake: Arc<EpollWake>,
}

impl EpollFile {
    fn try_new() -> Result<Self, Errno> {
        let wake = try_arc(EpollWake { queue: PollQueue::new() }).map_err(crate::oom)?;
        Ok(Self { watches: IrqSpinLock::new(ArcTree::new()), wake })
    }

    /// The ready events, at most `max`. Each carries what it changed, so
    /// [`Self::restore`] can undo it if the events cannot be delivered.
    ///
    /// Appends to `out`, which has room for `max` more: nothing here
    /// allocates.
    fn collect_into(&self, out: &mut Vec<Ready>, max: usize) {
        let mut watches = self.watches.lock();
        while let Some(dead) = watches.remove_first_where(|w| w.file.strong_count() == 0) {
            drop(dead);
        }
        for w in watches.iter() {
            if out.len() == max {
                break;
            }
            let Some(f) = w.file.upgrade() else { continue };
            if w.disarmed.load(Ordering::Relaxed) {
                continue;
            }
            let events = w.events.load(Ordering::Relaxed);
            let last = w.last.load(Ordering::Relaxed);
            let ready = Self::bits(&f, false) & (events | POLLERR | POLLHUP);
            let fire = if events & EPOLLET != 0 { ready & !last } else { ready };
            w.last.store(ready, Ordering::Relaxed);
            if fire != 0 {
                if events & EPOLLONESHOT != 0 {
                    w.disarmed.store(true, Ordering::Relaxed);
                }
                debug_assert!(out.len() < out.capacity());
                out.push(Ready { fd: w.fd, mask: fire, data: w.data.load(Ordering::Relaxed), prev_last: last });
            }
        }
    }

    /// Undoes the edge and one-shot state that `collect` consumed for `ready`.
    fn restore(&self, ready: &[Ready]) {
        let watches = self.watches.lock();
        for r in ready {
            if let Some(w) = watches.find(&r.fd).filter(|w| w.data.load(Ordering::Relaxed) == r.data) {
                w.last.store(r.prev_last, Ordering::Relaxed);
                w.disarmed.store(false, Ordering::Relaxed);
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
        // One watch at a time, so the lock is not held while recursing.
        let mut next = 0;
        loop {
            let file = {
                let watches = self.watches.lock();
                let Some(w) = watches.lower_bound(&next) else { return false };
                next = w.fd + 1;
                w.file.upgrade()
            };
            let nested = file.as_ref().and_then(|f| f.file().as_any()?.downcast_ref::<EpollFile>());
            if nested.is_some_and(|e| e.reaches(goal, depth + 1)) {
                return true;
            }
        }
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
        let ready = watches.iter().any(|w| {
            !w.disarmed.load(Ordering::Relaxed)
                && w.file
                    .upgrade()
                    .is_some_and(|f| Self::bits(&f, true) & (w.events.load(Ordering::Relaxed) | POLLERR | POLLHUP) != 0)
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

    fn poll_queue(&self) -> Option<&PollQueue> {
        Some(&self.wake.queue)
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

pub(crate) fn create1(p: &Process, flags: u64) -> SysResult {
    if flags & !EPOLL_CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    let file = try_arc(EpollFile::try_new()?).map_err(crate::oom)?;
    let open = OpenFile::try_new(file, Access::RW)?;
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
        let events = bytes::u32_at(&b, 0)?;
        let data = bytes::u64_at(&b, DATA_OFF)?;
        (events, data)
    };
    // Adding an instance to another must not close a loop (collecting would
    // lock instances in a cycle); `NEST` makes the check and insert one step.
    let nest_guard =
        (op == EPOLL_CTL_ADD && target.file().as_any().is_some_and(|a| a.is::<EpollFile>())).then(|| NEST.lock());
    if nest_guard.is_some() {
        let inner = target.file().as_any().and_then(|a| a.downcast_ref::<EpollFile>()).ok_or(Errno::EINVAL)?;
        if inner.reaches(ep, 0) {
            return Err(Errno::ELOOP);
        }
    }
    // Made before the lock is taken, where memory running out is an error.
    let waker = Waker::from(ep.wake.clone());
    let node = if op == EPOLL_CTL_ADD { Some(Watch::new(fd, &target, events, data, &waker)?) } else { None };
    // Looked up before the lock: a stat may do file I/O.
    let always_ready = op == EPOLL_CTL_ADD
        && matches!(target.file().try_stat()?.kind, FileKind::Regular | FileKind::Directory | FileKind::Symlink);
    let mut watches = ep.watches.lock();
    match op {
        EPOLL_CTL_ADD => {
            // Like Linux, refuse files that are always ready.
            if always_ready {
                return Err(Errno::EPERM);
            }
            if watches.find(&fd).is_some_and(|w| w.file.strong_count() > 0) {
                return Err(Errno::EEXIST);
            }
            // A watch whose file is gone is replaced.
            drop(watches.take_key(&fd));
            if watches.len() >= MAX_WATCHES {
                return Err(Errno::ENOSPC);
            }
            // `node` was made above for ADD, and the descriptor's slot was just emptied.
            let node = node.ok_or(Errno::EINVAL)?;
            if watches.insert(node).is_err() {
                return Err(Errno::EEXIST);
            }
        }
        EPOLL_CTL_MOD => watches.find(&fd).ok_or(Errno::ENOENT)?.rearm(events, data),
        EPOLL_CTL_DEL => drop(watches.take_key(&fd).ok_or(Errno::ENOENT)?),
        _ => return Err(Errno::EINVAL),
    }
    drop(watches);
    drop(nest_guard);
    // The waiters look at the new interest list.
    ep.wake.queue.notify();
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
    // Everything the wait needs is made first, where memory running out is an
    // error: it cannot be once events have been consumed.
    let mut ready: Vec<Ready> = Vec::new();
    ready.try_reserve_exact(max).map_err(|_| Errno::ENOMEM)?;
    let mut out = try_zeroed(max * EVENT_LEN).map_err(crate::oom)?;
    wait([&ep.wake.queue], timeout, || {
        ep.collect_into(&mut ready, max);
        (!ready.is_empty()).then_some(())
    })?;
    let filled = out.as_chunks_mut::<EVENT_LEN>().0.iter_mut().zip(&ready).try_for_each(|(c, r)| {
        bytes::put(c, 0, &r.mask.to_ne_bytes())?;
        bytes::put(c, DATA_OFF, &r.data.to_ne_bytes())
    });
    let delivered = filled.and_then(|()| out.get(..ready.len() * EVENT_LEN).ok_or(Errno::EINVAL));
    if let Err(e) = delivered.and_then(|d| p.memory().write(events, d)) {
        // Nothing was delivered, so the events must stay pending.
        ep.restore(&ready);
        return Err(e);
    }
    Ok(ready.len() as u64)
}

#[allow(clippy::too_many_arguments)] // the system call's own six, and the thread.
pub(crate) fn pwait(
    p: &Process,
    th: &crate::thread::Thread,
    epfd: i32,
    events: u64,
    max: u64,
    timeout_ms: u64,
    mask: u64,
    size: u64,
) -> SysResult {
    let mask = user_sigmask(p, mask, size)?;
    th.sig.with_mask(th, mask, || wait_events(p, epfd, events, max, timeout_ms))
}
