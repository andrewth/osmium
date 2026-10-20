//! A minimal `futex`: `FUTEX_WAIT` and `FUTEX_WAKE`, enough for
//! `pthread_join` and simple locks.
//!
//! Futexes are keyed by (process, address): memory is never shared between
//! processes. Waits take no timeout (`ENOSYS`); the requeue operations are
//! not implemented. A waiting thread is woken by a wake, or interrupted
//! (`EINTR`) by a signal it would act on, or when its process is ending.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use osmium_fs::Errno;
use osmium_sched::WaitQueue;
use osmium_sync::IrqSpinLock;

use crate::process::{Pid, Process};
use crate::thread::Thread;

const WAIT: u64 = 0;
const WAKE: u64 = 1;
const WAIT_BITSET: u64 = 9;
const WAKE_BITSET: u64 = 10;
/// `FUTEX_PRIVATE_FLAG` and `FUTEX_CLOCK_REALTIME`.
const FLAGS: u64 = 128 | 256;

pub(crate) struct Waiter {
    pid: Pid,
    addr: u64,
    pub(crate) woken: AtomicBool,
}

static WAITERS: IrqSpinLock<Vec<Arc<Waiter>>> = IrqSpinLock::new(Vec::new());
/// Every sleeping thread waits here and checks its own waiter; wakes are
/// rare enough that waking the lot is simpler than a queue per address.
static SLEEPERS: WaitQueue = WaitQueue::new();

/// Makes every sleeping thread look again: for signals and process exit.
pub(crate) fn interrupt() {
    SLEEPERS.wake_all();
}

/// Wakes up to `n` threads of `pid` waiting at `addr`, oldest first, and
/// returns how many.
pub(crate) fn wake(pid: Pid, addr: u64, n: u32) -> u32 {
    let mut woken = 0;
    {
        let mut waiters = WAITERS.lock();
        waiters.retain(|w| {
            if woken < n && w.pid == pid && w.addr == addr {
                w.woken.store(true, Ordering::SeqCst);
                woken += 1;
                false
            } else {
                true
            }
        });
    }
    if woken != 0 {
        SLEEPERS.wake_all();
    }
    woken
}

/// Registers a waiter at `addr` if it still holds `val`: the check and the
/// registration cannot be separated by a wake.
pub(crate) fn enqueue(p: &Process, addr: u64, val: u32) -> Result<Arc<Waiter>, Errno> {
    let mut waiters = WAITERS.lock();
    let mut cur = [0; 4];
    p.memory().read(addr, &mut cur)?;
    if u32::from_ne_bytes(cur) != val {
        return Err(Errno::EAGAIN);
    }
    let w = Arc::new(Waiter { pid: p.pid(), addr, woken: AtomicBool::new(false) });
    waiters.push(w.clone());
    Ok(w)
}

/// Blocks until `w` is woken, or the thread is interrupted.
pub(crate) fn sleep(p: &Process, th: &Thread, w: &Arc<Waiter>) -> Result<(), Errno> {
    let r = SLEEPERS.wait_until(|| {
        if w.woken.load(Ordering::SeqCst) {
            Some(Ok(()))
        } else if crate::signal::interrupted(p, th) {
            Some(Err(Errno::EINTR))
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

/// `futex(uaddr, op, val, timeout, uaddr2, val3)`.
pub(crate) fn futex(p: &Process, th: &Thread, uaddr: u64, op: u64, val: u64, timeout: u64) -> Result<u64, Errno> {
    if !uaddr.is_multiple_of(4) {
        return Err(Errno::EINVAL);
    }
    match op & !FLAGS {
        WAIT | WAIT_BITSET => {
            if timeout != 0 {
                return Err(Errno::ENOSYS);
            }
            let w = enqueue(p, uaddr, val as u32)?;
            sleep(p, th, &w).map(|()| 0)
        }
        WAKE | WAKE_BITSET => Ok(wake(p.pid(), uaddr, (val as i32).max(0) as u32) as u64),
        _ => Err(Errno::ENOSYS),
    }
}
