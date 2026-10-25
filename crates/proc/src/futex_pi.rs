//! Priority-inheritance futexes: `FUTEX_LOCK_PI`, `FUTEX_LOCK_PI2`,
//! `FUTEX_UNLOCK_PI` and `FUTEX_TRYLOCK_PI`.
//!
//! The futex word holds the owner's thread id (plus `FUTEX_WAITERS` and
//! `FUTEX_OWNER_DIED`), and userspace takes an uncontended lock by itself
//! with a compare-and-swap of 0 to its tid. A contended `LOCK_PI` queues the
//! caller here and sets `FUTEX_WAITERS`; `UNLOCK_PI` hands the lock to the
//! waiter with the highest priority (oldest first among equals), writing its
//! tid into the word, so the lock never becomes free for a third party to
//! steal.
//!
//! While a thread owns a lock that higher-priority threads wait for, its task
//! runs at the highest of their priorities, transitively: if the owner is
//! itself waiting on a priority-inheritance futex, its owner is boosted too.
//! A lock cycle is refused with `EDEADLK`. The boost is recomputed from the
//! waiters left whenever one leaves (unlock, timeout, signal), and the task
//! goes back to its own priority when none is left. Priorities are the
//! scheduler's (`osmium_sched::Task::priority`), which takes effect the next
//! time the task is queued.
//!
//! A thread that dies holding a lock on its robust list hands it to the top
//! waiter with `FUTEX_OWNER_DIED` set in the word.
//!
//! Not implemented: `FUTEX_WAIT_REQUEUE_PI` / `FUTEX_CMP_REQUEUE_PI`, and
//! handing over locks of a thread that dies without a robust list.

use alloc::sync::Arc;
use core::marker::PhantomPinned;
use core::mem::offset_of;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use osmium_fs::Errno;
use osmium_sched::Task;
use osmium_sync::IrqSpinLock;
use osmium_sync::intrusive::{Adapter, Link, List};

use crate::futex::{OWNER_DIED, SLEEPERS, TID_MASK, WAITERS_BIT, read_u32};
use crate::process::{Pid, Process};
use crate::thread::Thread;

const EDEADLK: Errno = Errno(35);
/// Longest lock chain followed for boosting and deadlock detection.
const CHAIN_MAX: usize = 32;

/// A thread queued for a lock. It lives on the waiting thread's stack,
/// pinned, and unlinks itself on drop.
struct PiWaiter {
    link: Link,
    pid: Pid,
    addr: u64,
    tid: u32,
    /// The waiter's task, whose priority orders the queue and is lent to the owner.
    task: Option<Arc<Task>>,
    /// Set when the lock has been handed to this waiter.
    granted: AtomicBool,
    _pinned: PhantomPinned,
}

struct ByLink;

// SAFETY: `offset_of!` of the `Link` field of `PiWaiter`.
unsafe impl Adapter<Link> for ByLink {
    type Value = PiWaiter;
    const OFFSET: usize = offset_of!(PiWaiter, link);
}

/// The queued waiters of all locks, in arrival order.
struct PiList(List<ByLink>);

// SAFETY: only used under the lock around it; linked waiters are alive
// because `PiWaiter` unlinks itself under that lock before it goes away.
unsafe impl Send for PiList {}

static PI: IrqSpinLock<PiList> = IrqSpinLock::new(PiList(List::new()));

impl PiWaiter {
    fn prio(&self) -> u8 {
        self.task.as_ref().map_or(0, |t| t.priority())
    }

    fn dequeue(&self) {
        // SAFETY: if the waiter is linked, it is in `PI`.
        unsafe { PI.lock().0.remove(NonNull::from(self)) };
    }
}

impl Drop for PiWaiter {
    fn drop(&mut self) {
        self.dequeue();
    }
}

/// The thread id in the word at `addr`, 0 if there is none or it cannot be read.
fn owner_tid(p: &Process, addr: u64) -> u32 {
    read_u32(p, addr).map_or(0, |v| v & TID_MASK)
}

fn write_word(p: &Process, addr: u64, v: u32) -> Result<(), Errno> {
    p.memory().write(addr, &v.to_ne_bytes())
}

/// Recomputes the priority of thread `tid` as the highest of its own and its
/// waiters', then does the same for the owner of the lock `tid` is itself
/// waiting for, and so on up the chain.
fn recompute(p: &Process, pi: &PiList, mut tid: u32) {
    for _ in 0..CHAIN_MAX {
        let Some(th) = p.group.find(tid) else { return };
        let mut want = th.ext.base();
        for w in pi.0.iter().filter(|w| w.pid == p.pid()) {
            if owner_tid(p, w.addr) == tid {
                want = want.max(w.prio());
            }
        }
        th.ext.boost_to(want);
        let Some(next) = pi.0.iter().find(|w| w.pid == p.pid() && w.tid == tid).map(|w| owner_tid(p, w.addr)) else {
            return;
        };
        if next == 0 || next == tid {
            return;
        }
        tid = next;
    }
}

/// Whether making `me` wait for the lock owned by `owner` closes a cycle.
fn deadlocks(p: &Process, pi: &PiList, me: u32, mut owner: u32) -> bool {
    for _ in 0..CHAIN_MAX {
        if owner == me {
            return true;
        }
        match pi.0.iter().find(|w| w.pid == p.pid() && w.tid == owner) {
            Some(w) => owner = owner_tid(p, w.addr),
            None => return false,
        }
        if owner == 0 {
            return false;
        }
    }
    // A chain this long is treated as a cycle.
    true
}

/// The waiter to hand the lock at `addr` to: highest priority, oldest first.
fn top_waiter(pi: &PiList, pid: Pid, addr: u64) -> Option<NonNull<PiWaiter>> {
    let mut best: Option<(NonNull<PiWaiter>, u8)> = None;
    for w in pi.0.iter().filter(|w| w.pid == pid && w.addr == addr) {
        if best.is_none_or(|(_, p)| w.prio() > p) {
            best = Some((NonNull::from(w), w.prio()));
        }
    }
    best.map(|(w, _)| w)
}

fn has_waiters(pi: &PiList, pid: Pid, addr: u64) -> bool {
    pi.0.iter().any(|w| w.pid == pid && w.addr == addr)
}

/// Takes the lock for `tid` if the word allows it without waiting: free, or
/// left by an owner that died. Returns whether it did.
fn try_acquire(p: &Process, pi: &PiList, addr: u64, tid: u32, cur: u32) -> Result<bool, Errno> {
    if cur & TID_MASK != 0 {
        return Ok(false);
    }
    let mut v = tid | (cur & OWNER_DIED);
    if has_waiters(pi, p.pid(), addr) {
        v |= WAITERS_BIT;
    }
    write_word(p, addr, v)?;
    Ok(true)
}

/// `FUTEX_TRYLOCK_PI`.
pub(crate) fn trylock(p: &Process, th: &Thread, addr: u64) -> Result<u64, Errno> {
    let tid = th.tid();
    let pi = PI.lock();
    let cur = read_u32(p, addr)?;
    if cur & TID_MASK == tid {
        return Err(EDEADLK);
    }
    if try_acquire(p, &pi, addr, tid, cur)? { Ok(0) } else { Err(Errno::EAGAIN) }
}

/// `FUTEX_LOCK_PI`: takes the lock, waiting for its owner, until the
/// absolute `deadline` on the kernel's clock if there is one.
pub(crate) fn lock(p: &Process, th: &Thread, addr: u64, deadline: Option<u64>) -> Result<u64, Errno> {
    let tid = th.tid();
    let w = core::pin::pin!(PiWaiter {
        link: Link::new(),
        pid: p.pid(),
        addr,
        tid,
        task: th.ext.task(),
        granted: AtomicBool::new(false),
        _pinned: PhantomPinned,
    });
    let owner = {
        let mut pi = PI.lock();
        let cur = read_u32(p, addr)?;
        if cur & TID_MASK == tid {
            return Err(EDEADLK);
        }
        if try_acquire(p, &pi, addr, tid, cur)? {
            return Ok(0);
        }
        let owner = cur & TID_MASK;
        if p.group.find(owner).is_none() {
            return Err(crate::thread::ESRCH);
        }
        if deadlocks(p, &pi, tid, owner) {
            return Err(EDEADLK);
        }
        if cur & WAITERS_BIT == 0 {
            write_word(p, addr, cur | WAITERS_BIT)?;
        }
        // SAFETY: the waiter is pinned, and its `Drop` unlinks it (under
        // this lock) before its memory can be reused.
        unsafe { pi.0.push_back(NonNull::from(Pin::get_ref(w.as_ref()))) };
        recompute(p, &pi, owner);
        owner
    };
    let r = crate::futex::sleep_on(p, th, deadline, || w.granted.load(Ordering::SeqCst));
    if r.is_err() {
        w.dequeue();
        if w.granted.load(Ordering::SeqCst) {
            // The hand-over raced with the interruption and won.
            return Ok(0);
        }
        // The owner no longer has this waiter's priority.
        let pi = PI.lock();
        recompute(p, &pi, owner);
        let now = owner_tid(p, addr);
        if now != owner && now != 0 {
            recompute(p, &pi, now);
        }
        return r.map(|()| 0);
    }
    Ok(0)
}

/// `FUTEX_UNLOCK_PI`: hands the lock to the best waiter, or frees it.
pub(crate) fn unlock(p: &Process, th: &Thread, addr: u64) -> Result<u64, Errno> {
    let tid = th.tid();
    let mut pi = PI.lock();
    let cur = read_u32(p, addr)?;
    if cur & TID_MASK != tid {
        return Err(Errno::EPERM);
    }
    hand_over(p, &mut pi, addr, tid, 0);
    drop(pi);
    SLEEPERS.wake_all();
    Ok(0)
}

/// Gives the lock at `addr`, owned by `from`, to its top waiter, with
/// `extra` flags in the word, or frees it if there is none. Then fixes the
/// priorities of the old and the new owner.
fn hand_over(p: &Process, pi: &mut PiList, addr: u64, from: u32, extra: u32) {
    let Some(next) = top_waiter(pi, p.pid(), addr) else {
        let _ = write_word(p, addr, extra);
        recompute(p, pi, from);
        return;
    };
    // SAFETY: a linked waiter is alive: it unlinks itself under this lock
    // before it goes away, and the lock is held.
    let new_tid = unsafe { next.as_ref().tid };
    // SAFETY: as above; the waiter is in `PI`.
    unsafe { pi.0.remove(next) };
    let mut v = new_tid | extra;
    if has_waiters(pi, p.pid(), addr) {
        v |= WAITERS_BIT;
    }
    let _ = write_word(p, addr, v);
    // SAFETY: the waiter cannot be dropped yet: its `Drop` takes the lock we hold.
    unsafe { next.as_ref().granted.store(true, Ordering::SeqCst) };
    recompute(p, pi, from);
    recompute(p, pi, new_tid);
}

/// A thread died holding the lock at `addr` (its robust list says so): hands
/// it to the top waiter with `FUTEX_OWNER_DIED` set. Returns whether there
/// was a priority-inheritance waiter to take it.
pub(crate) fn owner_died(p: &Process, tid: u32, addr: u64) -> bool {
    let mut pi = PI.lock();
    if !has_waiters(&pi, p.pid(), addr) || owner_tid(p, addr) != tid {
        return false;
    }
    hand_over(p, &mut pi, addr, tid, OWNER_DIED);
    drop(pi);
    SLEEPERS.wake_all();
    true
}

#[cfg(test)]
pub(crate) fn queued(pid: Pid, addr: u64) -> usize {
    PI.lock().0.iter().filter(|w| w.pid == pid && w.addr == addr).count()
}
