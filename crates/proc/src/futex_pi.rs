//! Priority-inheritance futexes: `FUTEX_LOCK_PI`, `FUTEX_LOCK_PI2`,
//! `FUTEX_UNLOCK_PI` and `FUTEX_TRYLOCK_PI`.
//!
//! The futex word holds the owner's thread id (plus `FUTEX_WAITERS` and
//! `FUTEX_OWNER_DIED`), and userspace takes an uncontended lock by itself
//! with a compare-and-swap of 0 to its tid. A contended `LOCK_PI` queues the
//! caller here and sets `FUTEX_WAITERS`; `UNLOCK_PI` hands the lock to the
//! waiter with the highest priority (oldest first among equals), writing its
//! tid into the word, so the lock never becomes free for a third party to
//! steal. Locks are keyed as other futexes are (see `crate::futex`), so a
//! lock in shared memory works between processes, and thread ids are
//! global, so its owner may be a thread of another process.
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
//! The kernel remembers which thread each waiter waits for, so the chain is
//! followed without reading user memory. The word itself is only touched
//! with [`crate::futex::Ctx::word`], which cannot fault under the lock here;
//! an operation whose page is not ready starts again after faulting it in.
//! Changes to the word are compare-and-swaps, so a racing user store makes
//! the operation look again rather than be lost.
//!
//! A thread that dies holding a lock on its robust list hands it to the top
//! waiter with `FUTEX_OWNER_DIED` set in the word.
//!
//! Not implemented: `FUTEX_WAIT_REQUEUE_PI` / `FUTEX_CMP_REQUEUE_PI`, and
//! handing over locks of a thread that dies without a robust list.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::marker::PhantomPinned;
use core::mem::offset_of;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use osmium_fs::Errno;
use osmium_sched::Task;
use osmium_sync::IrqSpinLock;
use osmium_sync::intrusive::{Adapter, Link, List};

use crate::futex::{Ctx, Key, OWNER_DIED, Step, TID_MASK, WAITERS_BIT, bucket_of, wake_bucket};
#[cfg(test)]
use crate::process::Pid;
use crate::process::Process;
use crate::thread::Thread;

const EDEADLK: Errno = Errno(35);
/// Longest lock chain followed for boosting and deadlock detection.
const CHAIN_MAX: usize = 32;

/// The thread a waiter waits for: its id and the thread itself.
type Owner = (u32, Arc<Thread>);

/// A thread queued for a lock. It lives on the waiting thread's stack,
/// pinned, and unlinks itself on drop.
struct PiWaiter {
    link: Link,
    key: Key,
    tid: u32,
    /// The waiting thread, which becomes the owner when the lock is handed to it.
    me: Arc<Thread>,
    /// The lock's owner. Only touched under [`PI`]: set when the waiter is
    /// queued and by each hand-over to another waiter.
    owner: UnsafeCell<Option<Owner>>,
    /// The waiter's task, whose priority orders the queue and is lent to the owner.
    task: Option<Arc<Task>>,
    /// Set when the lock has been handed to this waiter.
    granted: AtomicBool,
    #[cfg(test)]
    pid: Pid,
    #[cfg(test)]
    addr: u64,
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
// because `PiWaiter` unlinks itself under that lock before it goes away, and
// their `owner` cells are only touched under it.
unsafe impl Send for PiList {}

static PI: IrqSpinLock<PiList> = IrqSpinLock::new(PiList(List::new()));

impl PiWaiter {
    fn prio(&self) -> u8 {
        self.task.as_ref().map_or(0, |t| t.priority())
    }

    /// The owner it waits for. Only with [`PI`] held (`_pi` shows it is).
    fn owner<'pi>(&'pi self, _pi: &'pi PiList) -> Option<&'pi Owner> {
        // SAFETY: the cell is only written under `PI`, which the caller
        // holds for as long as the reference lives.
        unsafe { (*self.owner.get()).as_ref() }
    }

    fn owner_tid(&self, pi: &PiList) -> u32 {
        self.owner(pi).map_or(0, |o| o.0)
    }

    /// Makes the waiter wait for `owner`.
    ///
    /// # Safety
    /// [`PI`] is held (`_pi` is its list), and no reference that
    /// [`PiWaiter::owner`] returned for this waiter is alive.
    unsafe fn set_owner(&self, _pi: &PiList, owner: Owner) {
        // SAFETY: the caller's contract: the cell is ours alone.
        unsafe { *self.owner.get() = Some(owner) };
    }
}

impl Drop for PiWaiter {
    fn drop(&mut self) {
        // SAFETY: if the waiter is linked, it is in `PI`.
        unsafe { PI.lock().0.remove(NonNull::from(&*self)) };
    }
}

/// Recomputes the priority of thread `th` as the highest of its own and its
/// waiters', then does the same for the owner of the lock `th` is itself
/// waiting for, and so on up the chain.
fn recompute<'a>(pi: &'a PiList, mut th: &'a Thread) {
    for _ in 0..CHAIN_MAX {
        let tid = th.tid();
        let mut want = th.ext.base();
        for w in pi.0.iter().filter(|w| w.owner_tid(pi) == tid) {
            want = want.max(w.prio());
        }
        th.ext.boost_to(want);
        let Some((next, owner)) = pi.0.iter().find(|w| w.tid == tid).and_then(|w| w.owner(pi)) else { return };
        if *next == 0 || *next == tid {
            return;
        }
        th = owner;
    }
}

/// Whether making `me` wait for the lock owned by `owner` closes a cycle.
fn deadlocks(pi: &PiList, me: u32, mut owner: u32) -> bool {
    for _ in 0..CHAIN_MAX {
        if owner == me {
            return true;
        }
        match pi.0.iter().find(|w| w.tid == owner) {
            Some(w) => owner = w.owner_tid(pi),
            None => return false,
        }
        if owner == 0 {
            return false;
        }
    }
    // A chain this long is treated as a cycle.
    true
}

/// The waiter to hand the lock `key` to: highest priority, oldest first.
fn top_waiter(pi: &PiList, key: Key) -> Option<NonNull<PiWaiter>> {
    let mut best: Option<(NonNull<PiWaiter>, u8)> = None;
    for w in pi.0.iter().filter(|w| w.key == key) {
        if best.is_none_or(|(_, p)| w.prio() > p) {
            best = Some((NonNull::from(w), w.prio()));
        }
    }
    best.map(|(w, _)| w)
}

fn waiters(pi: &PiList, key: Key) -> usize {
    pi.0.iter().filter(|w| w.key == key).count()
}

/// The word for `tid` taking a lock whose word is `cur`, if it can without
/// waiting: free, or left by an owner that died.
fn acquired(pi: &PiList, key: Key, tid: u32, cur: u32) -> Option<u32> {
    if cur & TID_MASK != 0 {
        return None;
    }
    let mut v = tid | (cur & OWNER_DIED);
    if waiters(pi, key) != 0 {
        v |= WAITERS_BIT;
    }
    Some(v)
}

/// `FUTEX_TRYLOCK_PI`.
pub(crate) fn trylock(p: &Process, th: &Thread, addr: u64, private: bool) -> Result<u64, Errno> {
    let tid = th.tid();
    let ctx = Ctx::new(p, private);
    ctx.retry(|| {
        let Some(key) = ctx.key(addr)? else { return Ok(Step::Fault(addr, true)) };
        let pi = PI.lock();
        let r = ctx.word(addr, true, key, |w| {
            let cur = w.load(Ordering::SeqCst);
            if cur & TID_MASK == tid {
                return Err(EDEADLK);
            }
            let v = acquired(&pi, key, tid, cur).ok_or(Errno::EAGAIN)?;
            Ok(w.compare_exchange(cur, v, Ordering::SeqCst, Ordering::SeqCst).is_ok())
        })?;
        match r {
            None => Ok(Step::Fault(addr, true)),
            Some(Ok(true)) => Ok(Step::Done(0)),
            Some(Ok(false)) => Ok(Step::Again),
            Some(Err(e)) => Err(e),
        }
    })
}

/// What `lock` found under the lock.
enum Found {
    /// The lock was taken.
    Taken,
    /// The owner is `tid`; it must be looked up before the caller can wait.
    Owner(u32),
    /// `FUTEX_WAITERS` is set and the caller may queue: the owner is the one looked up.
    Queue,
}

/// `FUTEX_LOCK_PI`: takes the lock, waiting for its owner, until the
/// absolute `deadline` on the kernel's clock if there is one.
pub(crate) fn lock(p: &Process, th: &Thread, addr: u64, deadline: Option<u64>, private: bool) -> Result<u64, Errno> {
    let tid = th.tid();
    let ctx = Ctx::new(p, private);
    let me = p.group.find(tid).ok_or(crate::thread::ESRCH)?;
    // The owner, looked up with no lock held (a process must not be dropped
    // under a spin lock: that closes its files), and kept until we are done.
    let mut looked_up: Option<(Arc<Process>, Arc<Thread>)> = None;
    let mut w = core::pin::pin!(PiWaiter {
        link: Link::new(),
        key: Key::default(),
        tid,
        me,
        owner: UnsafeCell::new(None),
        task: th.ext.task(),
        granted: AtomicBool::new(false),
        #[cfg(test)]
        pid: p.pid(),
        #[cfg(test)]
        addr,
        _pinned: PhantomPinned,
    });
    let key = ctx.retry(|| {
        let Some(key) = ctx.key(addr)? else { return Ok(Step::Fault(addr, true)) };
        let mut pi = PI.lock();
        let known = looked_up.as_ref().map(|(_, t)| t.tid());
        let step = |w: &AtomicU32| {
            let cur = w.load(Ordering::SeqCst);
            let owner = cur & TID_MASK;
            if owner == tid {
                return Err(EDEADLK);
            }
            if let Some(v) = acquired(&pi, key, tid, cur) {
                return Ok(w
                    .compare_exchange(cur, v, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                    .then_some(Found::Taken));
            }
            if known != Some(owner) {
                return Ok(Some(Found::Owner(owner)));
            }
            if deadlocks(&pi, tid, owner) {
                return Err(EDEADLK);
            }
            let set = w.compare_exchange(cur, cur | WAITERS_BIT, Ordering::SeqCst, Ordering::SeqCst);
            Ok(set.is_ok().then_some(Found::Queue))
        };
        let found = match ctx.word(addr, true, key, step)? {
            None => return Ok(Step::Fault(addr, true)),
            Some(r) => r?,
        };
        match found {
            None => Ok(Step::Again),
            Some(Found::Taken) => Ok(Step::Done(None)),
            Some(Found::Owner(owner)) => {
                drop(pi);
                looked_up = Some(crate::thread::find(owner).ok_or(crate::thread::ESRCH)?);
                Ok(Step::Again)
            }
            Some(Found::Queue) => {
                let Some((_, owner)) = &looked_up else { return Ok(Step::Again) };
                // SAFETY: not linked yet, so nothing else can see the waiter,
                // and assigning a field does not move it.
                unsafe { Pin::get_unchecked_mut(w.as_mut()) }.key = key;
                // SAFETY: `PI` is held, and nothing borrows the waiter's owner.
                unsafe { w.set_owner(&pi, (owner.tid(), owner.clone())) };
                // SAFETY: the waiter is pinned, and its `Drop` unlinks it (under
                // this lock) before its memory can be reused.
                unsafe { pi.0.push_back(NonNull::from(Pin::get_ref(w.as_ref()))) };
                recompute(&pi, owner);
                Ok(Step::Done(Some(key)))
            }
        }
    })?;
    let Some(key) = key else { return Ok(0) };
    let b = bucket_of(key);
    let r = crate::futex::sleep_on(p, th, deadline, &|| b, &|| w.granted.load(Ordering::SeqCst));
    if r.is_err() {
        let mut pi = PI.lock();
        // SAFETY: the waiter is linked, if at all, in `PI`.
        unsafe { pi.0.remove(NonNull::from(Pin::get_ref(w.as_ref()))) };
        if w.granted.load(Ordering::SeqCst) {
            // The hand-over raced with the interruption and won.
            return Ok(0);
        }
        // The owner no longer has this waiter's priority.
        if let Some((_, owner)) = w.owner(&pi) {
            recompute(&pi, owner);
        }
        return r.map(|()| 0);
    }
    Ok(0)
}

/// `FUTEX_UNLOCK_PI`: hands the lock to the best waiter, or frees it.
pub(crate) fn unlock(p: &Process, th: &Thread, addr: u64, private: bool) -> Result<u64, Errno> {
    let ctx = Ctx::new(p, private);
    let key = ctx.retry(|| {
        let Some(key) = ctx.key(addr)? else { return Ok(Step::Fault(addr, true)) };
        let mut pi = PI.lock();
        match hand_over(&ctx, &mut pi, addr, key, th, 0)? {
            Handed::NotOwner => Err(Errno::EPERM),
            Handed::Done => Ok(Step::Done(key)),
            Handed::Fault => Ok(Step::Fault(addr, true)),
            Handed::Again => Ok(Step::Again),
        }
    })?;
    wake_bucket(bucket_of(key));
    Ok(0)
}

/// What [`hand_over`] did.
enum Handed {
    /// Handed the lock over, or freed it.
    Done,
    /// Nothing: `from` does not own the lock.
    NotOwner,
    /// Nothing: the page must be faulted in, and the operation start again.
    Fault,
    /// Nothing: the word changed under it; the operation starts again.
    Again,
}

/// Gives the lock `key` at `addr`, if owned by `from`, to its top waiter
/// with `extra` flags in the word, or frees it if there is none. Then fixes
/// the priorities of the old and the new owner.
fn hand_over(ctx: &Ctx, pi: &mut PiList, addr: u64, key: Key, from: &Thread, extra: u32) -> Result<Handed, Errno> {
    let next = top_waiter(pi, key);
    // SAFETY: a linked waiter is alive: it unlinks itself under this lock
    // before it goes away, and the lock is held.
    let new = next.map(|n| unsafe { n.as_ref() });
    let v = match new {
        Some(n) => n.tid | extra | if waiters(pi, key) > 1 { WAITERS_BIT } else { 0 },
        None => extra,
    };
    let tid = from.tid();
    let set = |w: &AtomicU32| {
        let cur = w.load(Ordering::SeqCst);
        if cur & TID_MASK != tid {
            return None;
        }
        Some(w.compare_exchange(cur, v, Ordering::SeqCst, Ordering::SeqCst).is_ok())
    };
    match ctx.word(addr, true, key, set)? {
        None => return Ok(Handed::Fault),
        Some(None) => return Ok(Handed::NotOwner),
        Some(Some(false)) => return Ok(Handed::Again),
        Some(Some(true)) => {}
    }
    let Some((next, new)) = next.zip(new) else {
        recompute(pi, from);
        return Ok(Handed::Done);
    };
    // SAFETY: the waiter is in `PI`.
    unsafe { pi.0.remove(next) };
    let owner = (new.tid, new.me.clone());
    for w in pi.0.iter().filter(|w| w.key == key) {
        // SAFETY: `PI` is held, and no reference from `PiWaiter::owner` is alive.
        unsafe { w.set_owner(pi, owner.clone()) };
    }
    // The waiter cannot be dropped yet: its `Drop` takes the lock we hold.
    new.granted.store(true, Ordering::SeqCst);
    recompute(pi, from);
    recompute(pi, &new.me);
    Ok(Handed::Done)
}

/// A thread died holding the lock at `addr` (its robust list says so): hands
/// it to the top waiter with `FUTEX_OWNER_DIED` set. Returns whether there
/// was a priority-inheritance waiter to take it.
pub(crate) fn owner_died(p: &Process, tid: u32, addr: u64) -> bool {
    let ctx = Ctx::new(p, false);
    let Some(from) = p.group.find(tid) else { return false };
    let r = ctx.retry(|| {
        let Some(key) = ctx.key(addr)? else { return Ok(Step::Fault(addr, true)) };
        let mut pi = PI.lock();
        if waiters(&pi, key) == 0 {
            return Ok(Step::Done(None));
        }
        match hand_over(&ctx, &mut pi, addr, key, &from, OWNER_DIED)? {
            Handed::NotOwner => Ok(Step::Done(None)),
            Handed::Done => Ok(Step::Done(Some(key))),
            Handed::Fault => Ok(Step::Fault(addr, true)),
            Handed::Again => Ok(Step::Again),
        }
    });
    match r {
        Ok(Some(key)) => {
            wake_bucket(bucket_of(key));
            true
        }
        _ => false,
    }
}

#[cfg(test)]
pub(crate) fn queued(pid: Pid, addr: u64) -> usize {
    PI.lock().0.iter().filter(|w| w.pid == pid && w.addr == addr).count()
}
