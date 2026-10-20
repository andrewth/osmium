//! `futex`: wait, wake, requeue, `WAKE_OP`, bitsets, timeouts and robust
//! lists. Enough for `pthread_join`, mutexes and condition variables.
//!
//! Futexes are keyed by (process, address): memory is never shared between
//! processes, so `FUTEX_PRIVATE_FLAG` makes no difference. A waiting thread
//! is woken by a wake, or interrupted (`EINTR`) by a signal it would act on,
//! or when its process is ending.
//!
//! Timeouts need a clock: a kernel supplies one with [`set_clock`] and calls
//! [`tick`] from its timer interrupt so deadlines are noticed. Without a
//! clock a timed wait fails with `ENOSYS`. `CLOCK_REALTIME` and
//! `CLOCK_MONOTONIC` both read that clock.
//!
//! Priority-inheritance futexes (`LOCK_PI` and friends) are not implemented
//! and fail with `ENOSYS`. `WAKE_OP` and the requeue operations compare and
//! modify user memory under the futex lock, which orders them against other
//! futex calls but not against the program's own atomic instructions.
//!
//! Robust lists (`set_robust_list`): when a thread exits, each futex it
//! still owns is marked `FUTEX_OWNER_DIED` and one waiter is woken.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use osmium_fs::Errno;
use osmium_sched::WaitQueue;
use osmium_sync::{IrqSpinLock, Once};

use crate::process::{Pid, Process};
use crate::thread::Thread;

const WAIT: u64 = 0;
const WAKE: u64 = 1;
const REQUEUE: u64 = 3;
const CMP_REQUEUE: u64 = 4;
const WAKE_OP: u64 = 5;
const WAIT_BITSET: u64 = 9;
const WAKE_BITSET: u64 = 10;
/// `FUTEX_CLOCK_REALTIME`.
const CLOCK_REALTIME: u64 = 256;
/// `FUTEX_PRIVATE_FLAG`.
const PRIVATE: u64 = 128;
const BITSET_ANY: u32 = u32::MAX;

/// A futex word's bits: the owner's thread id, and the two flags.
const TID_MASK: u32 = 0x3fff_ffff;
const OWNER_DIED: u32 = 0x4000_0000;
const WAITERS_BIT: u32 = 0x8000_0000;

/// The size of the kernel's `robust_list_head`: list, offset, pending.
const ROBUST_HEAD_LEN: u64 = 24;
/// Most entries walked, so a corrupt (circular) list ends.
const ROBUST_LIMIT: usize = 2048;

pub(crate) struct Waiter {
    pid: Pid,
    addr: AtomicU64,
    bitset: u32,
    pub(crate) woken: AtomicBool,
}

static WAITERS: IrqSpinLock<Vec<Arc<Waiter>>> = IrqSpinLock::new(Vec::new());
/// Every sleeping thread waits here and checks its own waiter; wakes are
/// rare enough that waking the lot is simpler than a queue per address.
static SLEEPERS: WaitQueue = WaitQueue::new();
static CLOCK: Once<fn() -> u64> = Once::new();

/// Sets the monotonic clock, in nanoseconds, that futex timeouts read. Only
/// the first call has an effect.
pub fn set_clock(now_ns: fn() -> u64) {
    let _ = CLOCK.set(now_ns);
}

/// Makes timed waits look at the clock again: call it from the timer
/// interrupt (or any periodic task), or a timeout only fires when something
/// else wakes the waiter.
pub fn tick() {
    SLEEPERS.wake_all();
}

/// Makes every sleeping thread look again: for signals and process exit.
pub(crate) fn interrupt() {
    SLEEPERS.wake_all();
}

/// Wakes up to `n` threads of `pid` waiting at `addr` whose bitset meets
/// `mask`, oldest first, with the waiter list already locked.
fn wake_locked(waiters: &mut Vec<Arc<Waiter>>, pid: Pid, addr: u64, n: u32, mask: u32) -> u32 {
    let mut woken = 0;
    waiters.retain(|w| {
        if woken < n && w.pid == pid && w.addr.load(Ordering::SeqCst) == addr && w.bitset & mask != 0 {
            w.woken.store(true, Ordering::SeqCst);
            woken += 1;
            false
        } else {
            true
        }
    });
    woken
}

/// Wakes up to `n` threads of `pid` waiting at `addr`, oldest first, and
/// returns how many.
pub(crate) fn wake(pid: Pid, addr: u64, n: u32) -> u32 {
    wake_bits(pid, addr, n, BITSET_ANY)
}

fn wake_bits(pid: Pid, addr: u64, n: u32, mask: u32) -> u32 {
    let woken = wake_locked(&mut WAITERS.lock(), pid, addr, n, mask);
    if woken != 0 {
        SLEEPERS.wake_all();
    }
    woken
}

fn read_u32(p: &Process, addr: u64) -> Result<u32, Errno> {
    let mut cur = [0; 4];
    p.memory().read(addr, &mut cur)?;
    Ok(u32::from_ne_bytes(cur))
}

/// Registers a waiter at `addr` if it still holds `val`: the check and the
/// registration cannot be separated by a wake.
#[cfg(test)]
pub(crate) fn enqueue(p: &Process, addr: u64, val: u32) -> Result<Arc<Waiter>, Errno> {
    enqueue_bits(p, addr, val, BITSET_ANY)
}

pub(crate) fn enqueue_bits(p: &Process, addr: u64, val: u32, bitset: u32) -> Result<Arc<Waiter>, Errno> {
    let mut waiters = WAITERS.lock();
    if read_u32(p, addr)? != val {
        return Err(Errno::EAGAIN);
    }
    let w = Arc::new(Waiter { pid: p.pid(), addr: AtomicU64::new(addr), bitset, woken: AtomicBool::new(false) });
    waiters.push(w.clone());
    Ok(w)
}

/// Blocks until `w` is woken, the thread is interrupted, or the clock
/// reaches `deadline` (`ETIMEDOUT`).
fn sleep_until(p: &Process, th: &Thread, w: &Arc<Waiter>, deadline: Option<u64>) -> Result<(), Errno> {
    let now = CLOCK.get().copied();
    let r = SLEEPERS.wait_until(|| {
        if w.woken.load(Ordering::SeqCst) {
            Some(Ok(()))
        } else if crate::signal::interrupted(p, th) {
            Some(Err(Errno::EINTR))
        } else if deadline.is_some_and(|d| now.is_some_and(|now| now() >= d)) {
            Some(Err(Errno::ETIMEDOUT))
        } else {
            None
        }
    });
    if r.is_err() {
        WAITERS.lock().retain(|x| !Arc::ptr_eq(x, w));
        // A wake that raced with the interruption still counts.
        if w.woken.load(Ordering::SeqCst) {
            return Ok(());
        }
    }
    r
}

/// Reads a `struct timespec` at `addr` as nanoseconds.
fn read_timespec(p: &Process, addr: u64) -> Result<u64, Errno> {
    let mut b = [0; 16];
    p.memory().read(addr, &mut b)?;
    let sec = i64::from_ne_bytes(b[..8].try_into().expect("8 bytes"));
    let nsec = i64::from_ne_bytes(b[8..].try_into().expect("8 bytes"));
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

/// `FUTEX_REQUEUE` / `FUTEX_CMP_REQUEUE`: wakes up to `nr_wake` waiters at
/// `uaddr` and moves up to `nr_requeue` more to `uaddr2`. With `expect`, the
/// word at `uaddr` must hold it (`EAGAIN`). Returns woken plus requeued.
fn requeue(
    p: &Process,
    [uaddr, uaddr2]: [u64; 2],
    [nr_wake, nr_requeue]: [u32; 2],
    expect: Option<u32>,
) -> Result<u64, Errno> {
    if !uaddr2.is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }
    let pid = p.pid();
    let mut waiters = WAITERS.lock();
    if let Some(v) = expect
        && read_u32(p, uaddr)? != v
    {
        return Err(Errno::EAGAIN);
    }
    let woken = wake_locked(&mut waiters, pid, uaddr, nr_wake, BITSET_ANY);
    let mut moved = 0;
    for w in waiters.iter() {
        if moved == nr_requeue {
            break;
        }
        if w.pid == pid && w.addr.load(Ordering::SeqCst) == uaddr {
            w.addr.store(uaddr2, Ordering::SeqCst);
            moved += 1;
        }
    }
    drop(waiters);
    if woken != 0 {
        SLEEPERS.wake_all();
    }
    Ok(woken as u64 + moved as u64)
}

/// `FUTEX_WAKE_OP`: applies the operation encoded in `val3` to the word at
/// `uaddr2`, wakes up to `nr_wake` waiters at `uaddr`, and, if the old value
/// of the word passes the encoded comparison, up to `nr_wake2` at `uaddr2`.
fn wake_op(p: &Process, [uaddr, uaddr2]: [u64; 2], [nr_wake, nr_wake2]: [u32; 2], val3: u32) -> Result<u64, Errno> {
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
    let pid = p.pid();
    let mut waiters = WAITERS.lock();
    let old = read_u32(p, uaddr2)? as i32;
    let new = match op {
        0 => oparg,
        1 => old.wrapping_add(oparg),
        2 => old | oparg,
        3 => old & !oparg,
        4 => old ^ oparg,
        _ => return Err(Errno::ENOSYS),
    };
    let hit = match cmp {
        0 => old == cmparg,
        1 => old != cmparg,
        2 => old < cmparg,
        3 => old <= cmparg,
        4 => old > cmparg,
        5 => old >= cmparg,
        _ => return Err(Errno::ENOSYS),
    };
    p.memory().write(uaddr2, &new.to_ne_bytes())?;
    let mut woken = wake_locked(&mut waiters, pid, uaddr, nr_wake, BITSET_ANY);
    if hit {
        woken += wake_locked(&mut waiters, pid, uaddr2, nr_wake2, BITSET_ANY);
    }
    drop(waiters);
    if woken != 0 {
        SLEEPERS.wake_all();
    }
    Ok(woken as u64)
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
    if op & CLOCK_REALTIME != 0 && cmd != WAIT_BITSET {
        return Err(Errno::ENOSYS);
    }
    match cmd {
        WAIT | WAIT_BITSET => {
            let bitset = if cmd == WAIT_BITSET { val3 as u32 } else { BITSET_ANY };
            if bitset == 0 {
                return Err(Errno::EINVAL);
            }
            let deadline = deadline(p, timeout, cmd == WAIT_BITSET)?;
            let w = enqueue_bits(p, uaddr, val as u32, bitset)?;
            sleep_until(p, th, &w, deadline).map(|()| 0)
        }
        WAKE | WAKE_BITSET => {
            let mask = if cmd == WAKE_BITSET { val3 as u32 } else { BITSET_ANY };
            if mask == 0 {
                return Err(Errno::EINVAL);
            }
            Ok(wake_bits(p.pid(), uaddr, count(val), mask) as u64)
        }
        // The fourth argument is the requeue count here, not a timeout.
        REQUEUE => requeue(p, [uaddr, uaddr2], [count(val), count(timeout)], None),
        CMP_REQUEUE => requeue(p, [uaddr, uaddr2], [count(val), count(timeout)], Some(val3 as u32)),
        WAKE_OP => wake_op(p, [uaddr, uaddr2], [count(val), count(timeout)], val3 as u32),
        // Priority-inheritance futexes (6, 7, 8, 11, 12, 13) and the rest.
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

fn owner_died(p: &Process, tid: u32, addr: u64) {
    let mut waiters = WAITERS.lock();
    let Ok(v) = read_u32(p, addr) else { return };
    if v & TID_MASK != tid {
        return;
    }
    let _ = p.memory().write(addr, &((v & WAITERS_BIT) | OWNER_DIED).to_ne_bytes());
    if v & WAITERS_BIT != 0 {
        wake_locked(&mut waiters, p.pid(), addr, 1, BITSET_ANY);
        drop(waiters);
        SLEEPERS.wake_all();
    }
}
