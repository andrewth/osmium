//! `futex`: wait, wake, requeue, `WAKE_OP`, bitsets, timeouts and robust
//! lists. Enough for `pthread_join`, mutexes and condition variables.
//!
//! # Keys
//!
//! A futex is known by a key, as in Linux. With `FUTEX_PRIVATE_FLAG` the key
//! is the address space and the user address, so threads of one process
//! meet whatever the memory is. Without it, a word in a `MAP_SHARED` mapping
//! is keyed by its physical address, so processes that share the frame (a
//! parent and the children it forked with the mapping) meet there even
//! though each has its own space; any other word (private memory, which a
//! `fork` copies on write) is keyed as a private one. A shared key names a
//! frame, not a file: there is no page cache across unrelated spaces (see
//! `memory::filemap`), so they share no frames and no futexes either. A
//! frame freed and reused while a thread waits on it can only cause a
//! spurious wake-up, which callers of `FUTEX_WAIT` must expect anyway.
//!
//! # Locking and user memory
//!
//! Waiters are hashed by key into 64 buckets, each with its own
//! spin lock and its own wait queue, so a wake locks and wakes one bucket.
//! The futex word is read and written under that lock (or the
//! priority-inheritance lock, see `crate::futex_pi`) only through
//! [`UserMemory::with_word`]: an atomic access through the physical mapping
//! under the space's lock, which never faults, allocates, does file I/O or
//! shoots down other CPUs. When the page is not ready (not loaded, or
//! copy-on-write for a store) every lock is dropped, the page is faulted in
//! with [`UserMemory::prefault`], and the whole operation starts again,
//! including the key, since a `fork`, `munmap` or `mprotect` may have
//! changed the mapping in between. The lock order is: futex bucket(s), in
//! index order, or the priority-inheritance lock; then the address space.
//!
//! `WAKE_OP` changes the word with one atomic instruction, so it is atomic
//! against the program's own atomics too.
//!
//! # Sleeping
//!
//! A waiting thread is woken by a wake, interrupted (`EINTR`) by a signal it
//! would act on, or by its process ending. Signals and process exit wake
//! every bucket, since any thread may be the one they are for.
//!
//! Timeouts need a clock: a kernel supplies one with [`set_clock`] and calls
//! [`tick`] from its timer interrupt so deadlines are noticed. Without a
//! clock a timed wait fails with `ENOSYS`. `CLOCK_REALTIME` and
//! `CLOCK_MONOTONIC` both read that clock. A timed sleeper registers its
//! deadline, and [`tick`] wakes only the buckets of the sleepers whose
//! deadline has passed; with none due it reads one atomic.
//!
//! Priority-inheritance futexes (`LOCK_PI` and friends) are in
//! `crate::futex_pi`. A timed or untimed `FUTEX_WAIT` that a signal handler
//! interrupts fails with `EINTR`; if no handler runs it continues through
//! `restart_syscall` (see `crate::restart`).
//!
//! Robust lists (`set_robust_list`): when a thread exits, each futex it
//! still owns is marked `FUTEX_OWNER_DIED` and one waiter is woken.

use alloc::sync::Arc;
use core::marker::PhantomPinned;
use core::mem::offset_of;
use core::pin::Pin;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use osmium_fs::Errno;
use osmium_sched::WaitQueue;
use osmium_sync::intrusive::{Adapter, Link, List};
use osmium_sync::{IrqDisabled, IrqSpinLock, Once, SpinLockGuard};

use crate::memory::{UserMemory, WordAt};
use crate::process::Process;
use crate::thread::Thread;

const WAIT: u64 = 0;
const WAKE: u64 = 1;
const REQUEUE: u64 = 3;
const CMP_REQUEUE: u64 = 4;
const WAKE_OP: u64 = 5;
const LOCK_PI: u64 = 6;
const UNLOCK_PI: u64 = 7;
const TRYLOCK_PI: u64 = 8;
const WAIT_BITSET: u64 = 9;
const WAKE_BITSET: u64 = 10;
const LOCK_PI2: u64 = 13;
/// `FUTEX_CLOCK_REALTIME`.
const CLOCK_REALTIME: u64 = 256;
/// `FUTEX_PRIVATE_FLAG`.
const PRIVATE: u64 = 128;
const BITSET_ANY: u32 = u32::MAX;

/// A futex word's bits: the owner's thread id, and the two flags.
pub(crate) const TID_MASK: u32 = 0x3fff_ffff;
pub(crate) const OWNER_DIED: u32 = 0x4000_0000;
pub(crate) const WAITERS_BIT: u32 = 0x8000_0000;

/// The size of the kernel's `robust_list_head`: list, offset, pending.
const ROBUST_HEAD_LEN: u64 = 24;
/// Most entries walked, so a corrupt (circular) list ends.
const ROBUST_LIMIT: usize = 2048;

/// How many times an operation starts again because the word's page was not
/// ready, before it gives up with `EFAULT`. Each retry first faults the page
/// in, so only a page that cannot be made ready (or a mapping that keeps
/// changing) gets that far.
const RETRIES: usize = 64;

/// What a futex is known by: an address space and a user address for a
/// private futex, or (`space` 0) the physical address of a word in shared
/// memory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Key {
    space: u64,
    addr: u64,
}

/// How a futex call reaches user memory: the caller's space, and whether
/// the call was `FUTEX_PRIVATE_FLAG`.
pub(crate) struct Ctx {
    mem: Arc<dyn UserMemory>,
    /// Identifies the space while it lives (its address; never 0).
    space: u64,
    private: bool,
}

/// The result of one attempt at an operation on a futex word.
pub(crate) enum Step<R> {
    /// It is done.
    Done(R),
    /// Fault in the word at this address (for a store if `true`), then try again.
    Fault(u64, bool),
    /// Something moved under it (the word changed between two looks): try again.
    Again,
}

impl Ctx {
    pub(crate) fn new(p: &Process, private: bool) -> Self {
        let mem = p.memory();
        let space = Arc::as_ptr(&mem).cast::<u8>() as u64;
        Self { mem, space, private }
    }

    fn key_at(&self, addr: u64, at: WordAt) -> Key {
        if !self.private && at.shared { Key { space: 0, addr: at.pa.0 } } else { Key { space: self.space, addr } }
    }

    /// The key of the futex at `addr`, or `None` if its page has to be
    /// faulted in first. Locks nothing but the space, briefly.
    pub(crate) fn key(&self, addr: u64) -> Result<Option<Key>, Errno> {
        if self.private {
            return Ok(Some(Key { space: self.space, addr }));
        }
        let mut key = None;
        let ready = self.mem.with_word(addr, false, &mut |_, at| key = Some(self.key_at(addr, at)))?;
        Ok(key.filter(|_| ready))
    }

    /// Runs `f` on the word at `addr` if its page is ready for the access
    /// (a store if `write`) and the word still has `key`; `None` if not, and
    /// the operation must fault the page in and start again. Never faults or
    /// blocks: see [`UserMemory::with_word`].
    pub(crate) fn word<R>(
        &self,
        addr: u64,
        write: bool,
        key: Key,
        f: impl FnOnce(&AtomicU32) -> R,
    ) -> Result<Option<R>, Errno> {
        let mut f = Some(f);
        let mut out = None;
        self.mem.with_word(addr, write, &mut |w, at| {
            if self.key_at(addr, at) == key
                && let Some(f) = f.take()
            {
                out = Some(f(w));
            }
        })?;
        Ok(out)
    }

    /// Runs `attempt` until it is done, faulting pages in (with no lock
    /// held) between attempts as it asks.
    pub(crate) fn retry<R>(&self, mut attempt: impl FnMut() -> Result<Step<R>, Errno>) -> Result<R, Errno> {
        for _ in 0..RETRIES {
            match attempt()? {
                Step::Done(r) => return Ok(r),
                Step::Fault(addr, write) => self.mem.prefault(addr, 4, write)?,
                Step::Again => {}
            }
        }
        Err(Errno::EFAULT)
    }
}

/// A thread waiting on a futex. It is linked into its bucket's list through
/// its own `link`, so waiting never allocates: the waiting thread keeps the
/// `Waiter` on its stack, pinned, and it unlinks itself when dropped.
pub(crate) struct Waiter {
    link: Link,
    /// The key, set before the waiter is queued and changed only by a
    /// requeue that holds the locks of the old and the new bucket. Read
    /// under the lock of the bucket the waiter is in.
    space: AtomicU64,
    addr: AtomicU64,
    /// The bucket of the key: the waiter is in that bucket's list, if in any.
    bucket: AtomicUsize,
    bitset: u32,
    pub(crate) woken: AtomicBool,
    _pinned: PhantomPinned,
}

struct ByLink;

// SAFETY: `offset_of!` of the `Link` field of `Waiter`.
unsafe impl Adapter<Link> for ByLink {
    type Value = Waiter;
    const OFFSET: usize = offset_of!(Waiter, link);
}

/// The waiters of one bucket in the order they arrived. Linked waiters are
/// alive: `Waiter` unlinks itself before it goes away, under the same lock.
struct WaiterList(List<ByLink>);

// SAFETY: the list is only used under the lock around it, and the waiters it
// links are `Sync` (atomics and an intrusive link used only under that lock).
unsafe impl Send for WaiterList {}

/// How many buckets futexes hash into: a power of two no larger than 64, so
/// a set of them fits a `u64`.
const BUCKETS: usize = 64;

/// A bucket's waiters, and the queue its sleeping threads wait in.
struct Bucket {
    waiters: IrqSpinLock<WaiterList>,
    sleepers: WaitQueue,
}

static TABLE: [Bucket; BUCKETS] =
    [const { Bucket { waiters: IrqSpinLock::new(WaiterList(List::new())), sleepers: WaitQueue::new() } }; BUCKETS];

type Guard = SpinLockGuard<'static, WaiterList, IrqDisabled>;

fn bucket(i: usize) -> &'static Bucket {
    let [first, ..] = &TABLE;
    TABLE.get(i).unwrap_or(first)
}

/// The bucket `key` hashes into.
pub(crate) fn bucket_of(key: Key) -> usize {
    let h = (key.space ^ key.addr.rotate_left(29) ^ (key.addr >> 2)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    (h >> (64 - BUCKETS.trailing_zeros())) as usize
}

/// Wakes the threads sleeping in bucket `i`, which look at their waiters again.
pub(crate) fn wake_bucket(i: usize) {
    bucket(i).sleepers.wake_all();
}

/// The locks of the buckets of two keys, taken in index order (once if
/// they are the same).
struct Pair {
    // Declared first so it is released first: the guards restore the
    // interrupt state in the reverse order they were taken.
    second: Option<Guard>,
    first: Guard,
    lo: usize,
}

impl Pair {
    fn lock(a: usize, b: usize) -> Self {
        let (lo, hi) = (a.min(b), a.max(b));
        let first = bucket(lo).waiters.lock();
        let second = (hi != lo).then(|| bucket(hi).waiters.lock());
        Self { second, first, lo }
    }

    /// The list of bucket `a`, and that of `b` if it is another one.
    fn lists(&mut self, a: usize) -> (&mut WaiterList, Option<&mut WaiterList>) {
        match &mut self.second {
            None => (&mut self.first, None),
            Some(second) if a == self.lo => (&mut self.first, Some(second)),
            Some(second) => (second, Some(&mut self.first)),
        }
    }
}

impl Waiter {
    pub(crate) fn new(bitset: u32) -> Self {
        Self {
            link: Link::new(),
            space: AtomicU64::new(0),
            addr: AtomicU64::new(0),
            bucket: AtomicUsize::new(0),
            bitset,
            woken: AtomicBool::new(false),
            _pinned: PhantomPinned,
        }
    }

    fn key(&self) -> Key {
        Key { space: self.space.load(Ordering::SeqCst), addr: self.addr.load(Ordering::SeqCst) }
    }

    /// Gives the waiter `key`, whose bucket is `b`. Only with the locks of
    /// the bucket it is in (if any) and of `b` held.
    fn set_key(&self, key: Key, b: usize) {
        self.space.store(key.space, Ordering::SeqCst);
        self.addr.store(key.addr, Ordering::SeqCst);
        self.bucket.store(b, Ordering::SeqCst);
    }

    /// Queues the waiter at the futex at `uaddr` if the word there still
    /// holds `val`: the check and the queueing cannot be separated by a wake.
    pub(crate) fn enqueue(self: Pin<&Self>, ctx: &Ctx, uaddr: u64, val: u32) -> Result<(), Errno> {
        ctx.retry(|| {
            let Some(key) = ctx.key(uaddr)? else { return Ok(Step::Fault(uaddr, false)) };
            let b = bucket_of(key);
            let mut list = bucket(b).waiters.lock();
            let Some(cur) = ctx.word(uaddr, false, key, |w| w.load(Ordering::SeqCst))? else {
                return Ok(Step::Fault(uaddr, false));
            };
            if cur != val {
                return Err(Errno::EAGAIN);
            }
            // Not queued anywhere yet, and `b`'s lock is held.
            self.set_key(key, b);
            // SAFETY: the waiter is pinned, and its `Drop` unlinks it (under
            // this lock, which `bucket` names) before its memory can be reused.
            unsafe { list.0.push_back(NonNull::from(self.get_ref())) };
            Ok(Step::Done(()))
        })
    }

    /// Takes the waiter out of its bucket, if a wake has not already.
    fn dequeue(&self) {
        loop {
            let b = self.bucket.load(Ordering::SeqCst);
            let mut list = bucket(b).waiters.lock();
            // A requeue moves the waiter with both locks held: if it is still
            // in `b`, it stays there while we hold `b`'s lock.
            if self.bucket.load(Ordering::SeqCst) == b {
                // SAFETY: if the waiter is linked, it is in bucket `b`'s list.
                unsafe { list.0.remove(NonNull::from(self)) };
                return;
            }
        }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        self.dequeue();
    }
}

static CLOCK: Once<fn() -> u64> = Once::new();

/// Sets the monotonic clock, in nanoseconds, that futex timeouts read. Only
/// the first call has an effect.
pub fn set_clock(now_ns: fn() -> u64) {
    let _ = CLOCK.set(now_ns);
}

/// The deadline of a timed sleeper, linked into [`TIMERS`] while it sleeps.
pub(crate) struct Timer {
    link: Link,
    deadline: u64,
    /// The bucket whose queue the sleeper is in, for [`tick`] to wake.
    bucket: AtomicUsize,
    /// Set by [`tick`] once the deadline has passed.
    fired: AtomicBool,
    armed: bool,
    _pinned: PhantomPinned,
}

struct ByTimerLink;

// SAFETY: `offset_of!` of the `Link` field of `Timer`.
unsafe impl Adapter<Link> for ByTimerLink {
    type Value = Timer;
    const OFFSET: usize = offset_of!(Timer, link);
}

struct TimerList(List<ByTimerLink>);

// SAFETY: as for `WaiterList`: used only under its lock, and linked timers
// unlink themselves under it before they go away.
unsafe impl Send for TimerList {}

static TIMERS: IrqSpinLock<TimerList> = IrqSpinLock::new(TimerList(List::new()));
/// No timer in [`TIMERS`] is due before this: [`tick`] looks no further
/// while the clock is behind it.
static EARLIEST: AtomicU64 = AtomicU64::new(u64::MAX);

impl Timer {
    fn new(deadline: Option<u64>) -> Self {
        Self {
            link: Link::new(),
            deadline: deadline.unwrap_or(u64::MAX),
            bucket: AtomicUsize::new(0),
            fired: AtomicBool::new(false),
            armed: deadline.is_some(),
            _pinned: PhantomPinned,
        }
    }

    fn arm(self: Pin<&Self>) {
        if !self.armed {
            return;
        }
        let mut timers = TIMERS.lock();
        // SAFETY: the timer is pinned, and its `Drop` unlinks it under this
        // lock before its memory can be reused.
        unsafe { timers.0.push_back(NonNull::from(self.get_ref())) };
        EARLIEST.fetch_min(self.deadline, Ordering::SeqCst);
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        if self.armed {
            // SAFETY: if the timer is linked, it is in `TIMERS`.
            unsafe { TIMERS.lock().0.remove(NonNull::from(&*self)) };
        }
    }
}

/// Fires the timers due at `now`, and returns the set of buckets whose
/// sleepers must look again.
fn expire(now: u64) -> u64 {
    if now < EARLIEST.load(Ordering::SeqCst) {
        return 0;
    }
    let mut timers = TIMERS.lock();
    let (mut due, mut next) = (0u64, u64::MAX);
    timers.0.retain(|t| {
        if t.deadline <= now {
            t.fired.store(true, Ordering::SeqCst);
            due |= 1u64.wrapping_shl(t.bucket.load(Ordering::SeqCst) as u32);
            false
        } else {
            next = next.min(t.deadline);
            true
        }
    });
    EARLIEST.store(next, Ordering::SeqCst);
    due
}

/// Notices the futex deadlines that have passed: call it from the timer
/// interrupt (or any periodic task), or a timeout only fires when something
/// else wakes the waiter. Only the buckets of sleepers whose deadline has
/// passed are woken.
pub fn tick() {
    let Some(now) = CLOCK.get() else { return };
    let mut due = expire(now());
    while due != 0 {
        wake_bucket(due.trailing_zeros() as usize);
        due &= due - 1;
    }
}

/// Makes every sleeping thread look again: for signals and process exit.
pub(crate) fn interrupt() {
    for b in &TABLE {
        b.sleepers.wake_all();
    }
}

/// Wakes up to `n` threads waiting on `key` whose bitset meets `mask`,
/// oldest first, with their bucket's list locked. The caller then wakes the
/// bucket's sleepers.
fn wake_locked(waiters: &mut WaiterList, key: Key, n: u32, mask: u32) -> u32 {
    let mut woken = 0;
    waiters.0.retain(|w| {
        if woken < n && w.key() == key && w.bitset & mask != 0 {
            w.woken.store(true, Ordering::SeqCst);
            woken += 1;
            false
        } else {
            true
        }
    });
    woken
}

/// Wakes up to `n` threads waiting at `addr` in `p`, oldest first, as a
/// process-shared futex (for `CLONE_CHILD_CLEARTID`), and returns how many.
pub(crate) fn wake(p: &Process, addr: u64, n: u32) -> u32 {
    wake_bits(&Ctx::new(p, false), addr, n, BITSET_ANY).unwrap_or(0)
}

fn wake_bits(ctx: &Ctx, addr: u64, n: u32, mask: u32) -> Result<u32, Errno> {
    let key = ctx.retry(|| Ok(ctx.key(addr)?.map_or(Step::Fault(addr, false), Step::Done)))?;
    let b = bucket_of(key);
    let woken = wake_locked(&mut bucket(b).waiters.lock(), key, n, mask);
    if woken != 0 {
        wake_bucket(b);
    }
    Ok(woken)
}

/// A waiter at `addr`, queued if it still holds `val`, for a test to wake.
#[cfg(test)]
pub(crate) fn enqueue(p: &Process, addr: u64, val: u32) -> Result<Pin<alloc::boxed::Box<Waiter>>, Errno> {
    enqueue_bits(p, addr, val, BITSET_ANY)
}

/// [`enqueue`] with a bitset.
#[cfg(test)]
pub(crate) fn enqueue_bits(
    p: &Process,
    addr: u64,
    val: u32,
    bitset: u32,
) -> Result<Pin<alloc::boxed::Box<Waiter>>, Errno> {
    let w = alloc::boxed::Box::pin(Waiter::new(bitset));
    w.as_ref().enqueue(&Ctx::new(p, false), addr, val)?;
    Ok(w)
}

/// Blocks until `ready` holds, the thread is interrupted (`EINTR`), or the
/// clock reaches `deadline` (`ETIMEDOUT`). `ready` is checked first. The
/// thread sleeps in the queue of bucket `home()`, and moves when that
/// changes (a requeue wakes the old bucket after changing it).
pub(crate) fn sleep_on(
    p: &Process,
    th: &Thread,
    deadline: Option<u64>,
    home: &dyn Fn() -> usize,
    ready: &dyn Fn() -> bool,
) -> Result<(), Errno> {
    let now = CLOCK.get().copied();
    let timer = core::pin::pin!(Timer::new(deadline.filter(|_| now.is_some())));
    timer.as_ref().arm();
    loop {
        let b = home();
        // Before the deadline is checked below: `expire` sets `fired` before
        // it reads this, so it either wakes `b` or we see `fired`.
        timer.bucket.store(b, Ordering::SeqCst);
        let r = bucket(b).sleepers.wait_until(|| {
            if ready() {
                Some(Some(Ok(())))
            } else if crate::signal::interrupted(p, th) {
                Some(Some(Err(Errno::EINTR)))
            } else if timer.fired.load(Ordering::SeqCst) || deadline.is_some_and(|d| now.is_some_and(|now| now() >= d))
            {
                Some(Some(Err(Errno::ETIMEDOUT)))
            } else if home() != b {
                Some(None)
            } else {
                None
            }
        });
        if let Some(r) = r {
            return r;
        }
    }
}

/// Blocks until `w` is woken, the thread is interrupted, or the clock
/// reaches `deadline` (`ETIMEDOUT`).
fn sleep_until(p: &Process, th: &Thread, w: &Waiter, deadline: Option<u64>) -> Result<(), Errno> {
    let r = sleep_on(p, th, deadline, &|| w.bucket.load(Ordering::SeqCst), &|| w.woken.load(Ordering::SeqCst));
    if r.is_err() {
        w.dequeue();
        // A wake that raced with the interruption still counts.
        if w.woken.load(Ordering::SeqCst) {
            return Ok(());
        }
    }
    r
}

/// Whether futex operation `op` is `FUTEX_LOCK_PI` or `FUTEX_LOCK_PI2`.
pub(crate) fn is_lock_pi(op: u64) -> bool {
    matches!(op & !(PRIVATE | CLOCK_REALTIME), LOCK_PI | LOCK_PI2)
}

/// Whether futex operation `op` is a wait that `restart_syscall` continues.
pub(crate) fn is_wait(op: u64) -> bool {
    matches!(op & !(PRIVATE | CLOCK_REALTIME), WAIT | WAIT_BITSET)
}

/// Waits at `uaddr` while it holds `val`, until woken or `deadline`; a
/// private futex if `private`. If a signal interrupts it, the thread's
/// restart block lets `restart_syscall` continue it with the same deadline.
pub(crate) fn wait(
    p: &Process,
    th: &Thread,
    uaddr: u64,
    val: u32,
    bitset: u32,
    deadline: Option<u64>,
    private: bool,
) -> Result<u64, Errno> {
    *th.ext.restart.lock() = None;
    let w = core::pin::pin!(Waiter::new(bitset));
    w.as_ref().enqueue(&Ctx::new(p, private), uaddr, val)?;
    let r = sleep_until(p, th, &w, deadline);
    if r == Err(Errno::EINTR) {
        *th.ext.restart.lock() = Some(crate::restart::Block::FutexWait { uaddr, val, bitset, deadline, private });
    }
    r.map(|()| 0)
}

/// Reads a `struct timespec` at `addr` as nanoseconds.
fn read_timespec(p: &Process, addr: u64) -> Result<u64, Errno> {
    let mut b = [0; 16];
    p.memory().read(addr, &mut b)?;
    let sec = crate::bytes::i64_at(&b, 0)?;
    let nsec = crate::bytes::i64_at(&b, 8)?;
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(Errno::EINVAL);
    }
    Ok((sec as u64).saturating_mul(1_000_000_000).saturating_add(nsec as u64))
}

/// A wait's deadline on the kernel's clock: relative for `FUTEX_WAIT`,
/// absolute for `FUTEX_WAIT_BITSET`.
fn deadline(p: &Process, timeout: u64, absolute: bool) -> Result<Option<u64>, Errno> {
    if timeout == 0 {
        return Ok(None);
    }
    let now = CLOCK.get().ok_or(Errno::ENOSYS)?;
    let t = read_timespec(p, timeout)?;
    Ok(Some(if absolute { t } else { now().saturating_add(t) }))
}

/// The keys of `uaddr` and `uaddr2`, or (`Err`) the address whose page must
/// be faulted in first.
fn keys(ctx: &Ctx, uaddr: u64, uaddr2: u64) -> Result<Result<(Key, Key), u64>, Errno> {
    let Some(k1) = ctx.key(uaddr)? else { return Ok(Err(uaddr)) };
    let Some(k2) = ctx.key(uaddr2)? else { return Ok(Err(uaddr2)) };
    Ok(Ok((k1, k2)))
}

/// `FUTEX_REQUEUE` / `FUTEX_CMP_REQUEUE`: wakes up to `nr_wake` waiters at
/// `uaddr` and moves up to `nr_requeue` more to `uaddr2`. With `expect`, the
/// word at `uaddr` must hold it (`EAGAIN`). Returns woken plus requeued.
fn requeue(
    ctx: &Ctx,
    [uaddr, uaddr2]: [u64; 2],
    [nr_wake, nr_requeue]: [u32; 2],
    expect: Option<u32>,
) -> Result<u64, Errno> {
    if !uaddr2.is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }
    let (woken, moved, b1, b2) = ctx.retry(|| {
        let (k1, k2) = match keys(ctx, uaddr, uaddr2)? {
            Ok(k) => k,
            Err(addr) => return Ok(Step::Fault(addr, false)),
        };
        let (b1, b2) = (bucket_of(k1), bucket_of(k2));
        let mut pair = Pair::lock(b1, b2);
        if let Some(v) = expect {
            let Some(cur) = ctx.word(uaddr, false, k1, |w| w.load(Ordering::SeqCst))? else {
                return Ok(Step::Fault(uaddr, false));
            };
            if cur != v {
                return Err(Errno::EAGAIN);
            }
        }
        let (from, mut to) = pair.lists(b1);
        let woken = wake_locked(from, k1, nr_wake, BITSET_ANY);
        if k1 == k2 {
            // Requeued onto itself: the waiters stay, and count as moved.
            let moved = nr_requeue.min(from.0.iter().filter(|w| w.key() == k1).count() as u32);
            return Ok(Step::Done((woken, moved, b1, b2)));
        }
        let mut moved = 0;
        while moved < nr_requeue {
            let Some(w) = from.0.find_ptr(|w| w.key() == k1) else { break };
            moved += 1;
            match to.as_deref_mut() {
                // SAFETY: `w` is linked in `from`, and both buckets are locked,
                // so the waiter cannot unlink itself meanwhile.
                Some(to) => unsafe {
                    from.0.remove(w);
                    w.as_ref().set_key(k2, b2);
                    to.0.push_back(w);
                },
                // SAFETY: as above; it stays in the same bucket.
                None => unsafe { w.as_ref() }.set_key(k2, b2),
            }
        }
        Ok(Step::Done((woken, moved, b1, b2)))
    })?;
    if woken != 0 || (moved != 0 && b1 != b2) {
        // The moved waiters sleep in `b1`'s queue until they look again.
        wake_bucket(b1);
    }
    Ok(woken as u64 + moved as u64)
}

/// `FUTEX_WAKE_OP`: applies the operation encoded in `val3` to the word at
/// `uaddr2` (atomically), wakes up to `nr_wake` waiters at `uaddr`, and, if
/// the old value of the word passes the encoded comparison, up to
/// `nr_wake2` at `uaddr2`.
fn wake_op(ctx: &Ctx, [uaddr, uaddr2]: [u64; 2], [nr_wake, nr_wake2]: [u32; 2], val3: u32) -> Result<u64, Errno> {
    if !uaddr2.is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }
    let sext = |v: u32| ((v << 20) as i32) >> 20;
    let (op, cmp) = ((val3 >> 28) & 7, (val3 >> 24) & 15);
    let mut oparg = sext((val3 >> 12) & 0xfff);
    let cmparg = sext(val3 & 0xfff);
    if val3 >> 31 != 0 {
        // OPARG_SHIFT: the argument is a bit number.
        oparg = u32::try_from(oparg).ok().and_then(|n| 1i32.checked_shl(n)).ok_or(Errno::EINVAL)?;
    }
    if op > 4 || cmp > 5 {
        return Err(Errno::ENOSYS);
    }
    let arg = oparg as u32;
    let (woken, b1, b2) = ctx.retry(|| {
        let (k1, k2) = match keys(ctx, uaddr, uaddr2)? {
            Ok(k) => k,
            Err(addr) => return Ok(Step::Fault(addr, false)),
        };
        let (b1, b2) = (bucket_of(k1), bucket_of(k2));
        let mut pair = Pair::lock(b1, b2);
        let apply = |w: &AtomicU32| match op {
            0 => w.swap(arg, Ordering::SeqCst),
            1 => w.fetch_add(arg, Ordering::SeqCst),
            2 => w.fetch_or(arg, Ordering::SeqCst),
            3 => w.fetch_and(!arg, Ordering::SeqCst),
            _ => w.fetch_xor(arg, Ordering::SeqCst),
        };
        let Some(old) = ctx.word(uaddr2, true, k2, apply)? else { return Ok(Step::Fault(uaddr2, true)) };
        let old = old as i32;
        let hit = match cmp {
            0 => old == cmparg,
            1 => old != cmparg,
            2 => old < cmparg,
            3 => old <= cmparg,
            4 => old > cmparg,
            _ => old >= cmparg,
        };
        let (l1, l2) = pair.lists(b1);
        let mut woken = [wake_locked(l1, k1, nr_wake, BITSET_ANY), 0];
        if hit {
            woken[1] = wake_locked(l2.unwrap_or(l1), k2, nr_wake2, BITSET_ANY);
        }
        Ok(Step::Done((woken, b1, b2)))
    })?;
    if woken[0] != 0 {
        wake_bucket(b1);
    }
    if woken[1] != 0 && b2 != b1 {
        wake_bucket(b2);
    }
    Ok(woken[0] as u64 + woken[1] as u64)
}

/// `futex(uaddr, op, val, timeout, uaddr2, val3)`; `a` holds the six
/// arguments.
pub(crate) fn futex(p: &Process, th: &Thread, a: [u64; 6]) -> Result<u64, Errno> {
    let [uaddr, op, val, timeout, uaddr2, val3] = a;
    if !uaddr.is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }
    let count = |v: u64| (v as i32).max(0) as u32;
    let cmd = op & !(PRIVATE | CLOCK_REALTIME);
    let private = op & PRIVATE != 0;
    if op & CLOCK_REALTIME != 0 && cmd != WAIT_BITSET && cmd != LOCK_PI2 {
        return Err(Errno::ENOSYS);
    }
    match cmd {
        WAIT | WAIT_BITSET => {
            let bitset = if cmd == WAIT_BITSET { val3 as u32 } else { BITSET_ANY };
            if bitset == 0 {
                return Err(Errno::EINVAL);
            }
            let deadline = deadline(p, timeout, cmd == WAIT_BITSET)?;
            wait(p, th, uaddr, val as u32, bitset, deadline, private)
        }
        // The timeout is absolute.
        LOCK_PI | LOCK_PI2 => crate::futex_pi::lock(p, th, uaddr, deadline(p, timeout, true)?, private),
        UNLOCK_PI => crate::futex_pi::unlock(p, th, uaddr, private),
        TRYLOCK_PI => crate::futex_pi::trylock(p, th, uaddr, private),
        WAKE | WAKE_BITSET => {
            let mask = if cmd == WAKE_BITSET { val3 as u32 } else { BITSET_ANY };
            if mask == 0 {
                return Err(Errno::EINVAL);
            }
            Ok(wake_bits(&Ctx::new(p, private), uaddr, count(val), mask)? as u64)
        }
        // The fourth argument is the requeue count here, not a timeout.
        REQUEUE => requeue(&Ctx::new(p, private), [uaddr, uaddr2], [count(val), count(timeout)], None),
        CMP_REQUEUE => requeue(&Ctx::new(p, private), [uaddr, uaddr2], [count(val), count(timeout)], Some(val3 as u32)),
        WAKE_OP => wake_op(&Ctx::new(p, private), [uaddr, uaddr2], [count(val), count(timeout)], val3 as u32),
        // The requeue-PI operations (11, 12) and the rest.
        _ => Err(Errno::ENOSYS),
    }
}

/// `set_robust_list(head, len)`.
pub(crate) fn set_robust_list(th: &Thread, head: u64, len: u64) -> Result<u64, Errno> {
    if len != ROBUST_HEAD_LEN {
        return Err(Errno::EINVAL);
    }
    th.set_robust_list(head);
    Ok(0)
}

/// `get_robust_list(tid, head_ptr, len_ptr)`; `tid` 0 is the caller. Only
/// threads of the caller's own process can be asked about.
pub(crate) fn get_robust_list(p: &Process, th: &Thread, tid: u64, head_ptr: u64, len_ptr: u64) -> Result<u64, Errno> {
    let head = if tid == 0 || tid == th.tid() as u64 {
        th.robust_list()
    } else {
        let tid = u32::try_from(tid).map_err(|_| crate::thread::ESRCH)?;
        p.group.find(tid).ok_or(crate::thread::ESRCH)?.robust_list()
    };
    p.memory().write(head_ptr, &head.to_ne_bytes())?;
    p.memory().write(len_ptr, &ROBUST_HEAD_LEN.to_ne_bytes())?;
    Ok(0)
}

/// A dying thread's robust futexes: every word it owns gets `OWNER_DIED`,
/// and one waiter on each is woken.
pub(crate) fn exit_robust_list(p: &Process, th: &Thread) {
    let head = th.robust_list();
    if head == 0 {
        return;
    }
    th.set_robust_list(0);
    let read = |addr: u64| -> Option<u64> {
        let mut b = [0; 8];
        p.memory().read(addr, &mut b).ok()?;
        Some(u64::from_ne_bytes(b))
    };
    let (Some(first), Some(offset), Some(pending)) =
        (read(head), read(head.wrapping_add(8)), read(head.wrapping_add(16)))
    else {
        return;
    };
    let offset = offset as i64;
    let handle = |entry: u64| {
        let Some(addr) = entry.checked_add_signed(offset) else { return };
        if addr.is_multiple_of(4) {
            owner_died(p, th.tid(), addr);
        }
    };
    let mut entry = first;
    let mut n = 0;
    while entry != head && n < ROBUST_LIMIT {
        let Some(next) = read(entry) else { break };
        if entry != pending {
            handle(entry);
        }
        entry = next;
        n += 1;
    }
    // The entry being locked or unlocked when the thread died.
    if pending != 0 {
        handle(pending);
    }
}

/// Thread `tid` died owning the robust futex at `addr`: marks it
/// `OWNER_DIED` and wakes one waiter, as a process-shared futex (as Linux does).
fn owner_died(p: &Process, tid: u32, addr: u64) {
    if crate::futex_pi::owner_died(p, tid, addr) {
        return;
    }
    let ctx = Ctx::new(p, false);
    let woke = ctx.retry(|| {
        let Some(key) = ctx.key(addr)? else { return Ok(Step::Fault(addr, true)) };
        let b = bucket_of(key);
        let mut list = bucket(b).waiters.lock();
        let mark = |w: &AtomicU32| {
            let v = w.load(Ordering::SeqCst);
            if v & TID_MASK != tid {
                return Some(0);
            }
            let new = (v & WAITERS_BIT) | OWNER_DIED;
            w.compare_exchange(v, new, Ordering::SeqCst, Ordering::SeqCst).ok()
        };
        match ctx.word(addr, true, key, mark)? {
            None => Ok(Step::Fault(addr, true)),
            // The word changed under us: look again.
            Some(None) => Ok(Step::Again),
            Some(Some(v)) if v & WAITERS_BIT != 0 => {
                Ok(Step::Done((wake_locked(&mut list, key, 1, BITSET_ANY) != 0).then_some(b)))
            }
            // Not its futex (`v` reads as 0 then), or nobody waits.
            Some(Some(_)) => Ok(Step::Done(None)),
        }
    });
    if let Ok(Some(b)) = woke {
        wake_bucket(b);
    }
}

/// The set of buckets that timers due at `now` would wake, firing them.
#[cfg(test)]
pub(crate) fn expire_for_test(now: u64) -> u64 {
    expire(now)
}

/// A timer for bucket `b` with `deadline`, armed, for a test.
#[cfg(test)]
pub(crate) fn timer_for_test(deadline: u64, b: usize) -> Pin<alloc::boxed::Box<Timer>> {
    let t = alloc::boxed::Box::pin(Timer::new(Some(deadline)));
    t.bucket.store(b, Ordering::SeqCst);
    t.as_ref().arm();
    t
}

#[cfg(test)]
impl Timer {
    pub(crate) fn has_fired(&self) -> bool {
        self.fired.load(Ordering::SeqCst)
    }
}

/// The key a call by `p` would use for `addr`, for tests.
#[cfg(test)]
pub(crate) fn key_for_test(p: &Process, addr: u64, private: bool) -> Key {
    let ctx = Ctx::new(p, private);
    ctx.retry(|| Ok(ctx.key(addr)?.map_or(Step::Fault(addr, false), Step::Done))).expect("a valid address")
}
