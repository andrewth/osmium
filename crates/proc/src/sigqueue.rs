//! Queued signals (`rt_sigqueueinfo`, and real-time signals from `kill`),
//! the alternate signal stack (`sigaltstack`) and `rt_sigsuspend`.
//!
//! A real-time signal (32 and up) is queued once per send, each with its own
//! `siginfo`, and delivered in order, lowest number first. A standard signal
//! sent with `rt_sigqueueinfo` keeps the `siginfo` of the send that made it
//! pending; further sends while it is pending are dropped, as for `kill`.
//! The pending bit of a signal stays set while a queue holds an entry for it.
//! At most [`QUEUE_MAX`] entries wait per process and per thread; beyond that
//! `rt_sigqueueinfo` fails with `EAGAIN`, while `kill` of a real-time signal
//! sets the pending bit without an entry, so it is never lost.

#![cfg_attr(
    not(any(test, target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64"))),
    allow(dead_code)
)]

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use osmium_fs::Errno;
use osmium_sync::IrqSpinLock;

use crate::bytes::{i32_at, put, u32_at, u64_at};
use crate::process::{Pid, Process};
use crate::signal::{NSIG, UNBLOCKABLE};
use crate::thread::Thread;

/// Entries that may wait in one queue.
pub(crate) const QUEUE_MAX: usize = 128;

/// The first real-time signal.
pub(crate) const SIGRTMIN: u8 = 32;

/// `si_code` values.
pub(crate) mod code {
    /// Sent by `kill`.
    pub const SI_USER: i32 = 0;
    /// Sent by `sigqueue`.
    #[allow(dead_code)] // user programs send it; the kernel only passes it on
    pub const SI_QUEUE: i32 = -1;
    /// Sent by `tkill` or `tgkill`.
    pub const SI_TKILL: i32 = -6;
}

/// The part of a `siginfo` that a send carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Info {
    pub code: i32,
    pub pid: u32,
    /// `si_value`: the integer or pointer that `sigqueue` passed.
    pub value: u64,
}

/// Signals waiting with their `siginfo`, oldest first.
pub(crate) struct SigQueue {
    items: IrqSpinLock<Vec<(u8, Info)>>,
}

impl SigQueue {
    pub(crate) const fn new() -> Self {
        Self { items: IrqSpinLock::new(Vec::new()) }
    }

    /// Queues one entry: `EAGAIN` if the queue is full, `ENOMEM` if memory
    /// ran out.
    pub(crate) fn push(&self, sig: u8, info: Info) -> Result<(), Errno> {
        let mut items = self.items.lock();
        if items.len() >= QUEUE_MAX {
            return Err(Errno::EAGAIN);
        }
        items.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        items.push((sig, info));
        Ok(())
    }

    /// Takes the oldest entry for `sig`, and says whether more remain.
    pub(crate) fn pop(&self, sig: u8) -> (Option<Info>, bool) {
        let mut items = self.items.lock();
        let first = items.iter().position(|&(s, _)| s == sig);
        let info = first.map(|i| items.remove(i).1);
        (info, items.iter().any(|&(s, _)| s == sig))
    }

    /// Drops every entry whose signal is in `mask`.
    pub(crate) fn discard(&self, mask: u64) {
        self.items.lock().retain(|&(s, _)| crate::signal::bit(s) & mask == 0);
    }
}

/// `sigaltstack` flags.
const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;
/// The smallest alternate stack `sigaltstack` accepts.
pub(crate) const MINSIGSTKSZ: u64 = 2048;

/// A thread's alternate signal stack.
#[derive(Clone, Copy, Default)]
pub(crate) struct AltStack {
    sp: u64,
    size: u64,
}

impl AltStack {
    fn enabled(&self) -> bool {
        self.size != 0
    }

    /// Whether `sp` is on the stack (its top included, as a full descending stack).
    fn contains(&self, sp: u64) -> bool {
        self.enabled() && sp > self.sp && sp - self.sp <= self.size
    }
}

/// Per-thread state of this module.
pub(crate) struct ThreadSig {
    /// Signals sent to this thread only (`tkill`, `rt_tgsigqueueinfo`).
    pub(crate) queue: SigQueue,
    alt: IrqSpinLock<AltStack>,
    /// The user stack pointer at the last system call, for `sigaltstack`'s
    /// "am I on it" (the portable dispatch has no registers).
    entry_sp: AtomicU64,
    /// The mask `sigsuspend` replaced, to restore when it returns.
    saved_mask: IrqSpinLock<Option<u64>>,
}

impl ThreadSig {
    pub(crate) const fn new() -> Self {
        Self {
            queue: SigQueue::new(),
            alt: IrqSpinLock::new(AltStack { sp: 0, size: 0 }),
            entry_sp: AtomicU64::new(0),
            saved_mask: IrqSpinLock::new(None),
        }
    }

    /// Records the user stack pointer a system call came in with.
    pub(crate) fn set_entry_sp(&self, sp: u64) {
        self.entry_sp.store(sp, Ordering::Relaxed);
    }

    /// `fork`: the child's thread starts with the caller's alternate stack.
    pub(crate) fn inherit_alt(&self, from: &ThreadSig) {
        *self.alt.lock() = *from.alt.lock();
    }

    /// `execve`: the old image's alternate stack is gone.
    pub(crate) fn reset_on_exec(&self) {
        *self.alt.lock() = AltStack::default();
    }

    /// Where a handler for `act_flags` starts its frame given user stack
    /// pointer `sp`: the top of the alternate stack, if the action asks for
    /// it and `sp` is not on it already.
    pub(crate) fn alt_top(&self, act_flags: u64, sp: u64) -> Option<(u64, u64)> {
        let alt = *self.alt.lock();
        (act_flags & crate::signal::sa::ONSTACK != 0 && alt.enabled() && !alt.contains(sp))
            .then(|| (alt.sp.saturating_add(alt.size), alt.sp))
    }

    pub(crate) fn take_saved_mask(&self) -> Option<u64> {
        self.saved_mask.lock().take()
    }
}

/// `sigaltstack(ss, oss)`.
pub(crate) fn sigaltstack(p: &Process, th: &Thread, ss: u64, oss: u64) -> Result<u64, Errno> {
    // struct stack_t: ss_sp, ss_flags (+ padding), ss_size.
    let mut raw = [0u8; 24];
    let new = if ss != 0 {
        p.memory().read(ss, &mut raw)?;
        Some((u64_at(&raw, 0)?, i32_at(&raw, 8)?, u64_at(&raw, 16)?))
    } else {
        None
    };
    let cur = *th.sig.alt.lock();
    let on_stack = cur.contains(th.sig.entry_sp.load(Ordering::Relaxed));
    if oss != 0 {
        let flags = if on_stack {
            SS_ONSTACK
        } else if cur.enabled() {
            0
        } else {
            SS_DISABLE
        };
        let mut out = [0u8; 24];
        put(&mut out, 0, &cur.sp.to_ne_bytes())?;
        put(&mut out, 8, &flags.to_ne_bytes())?;
        put(&mut out, 16, &cur.size.to_ne_bytes())?;
        p.memory().write(oss, &out)?;
    }
    if let Some((sp, flags, size)) = new {
        if on_stack {
            return Err(Errno::EPERM);
        }
        *th.sig.alt.lock() = if flags == SS_DISABLE {
            AltStack::default()
        } else if flags != 0 {
            return Err(Errno::EINVAL);
        } else if size < MINSIGSTKSZ {
            return Err(Errno::ENOMEM);
        } else if sp.checked_add(size).is_none() {
            return Err(Errno::EINVAL);
        } else {
            AltStack { sp, size }
        };
    }
    Ok(0)
}

/// `rt_sigsuspend(mask, sigsetsize)`: replaces the thread's mask and waits
/// for a signal to act on, then fails with `EINTR`. The old mask comes back
/// when the handler (if any) returns.
pub(crate) fn sigsuspend(p: &Process, th: &Thread, set: u64, size: u64) -> Result<u64, Errno> {
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    let mut b = [0u8; 8];
    p.memory().read(set, &mut b)?;
    let new = u64::from_ne_bytes(b) & !UNBLOCKABLE;
    {
        let mut saved = th.sig.saved_mask.lock();
        if saved.is_none() {
            *saved = Some(th.mask.load(Ordering::SeqCst));
        }
    }
    th.mask.store(new, Ordering::SeqCst);
    crate::jobctl::park_until(|| crate::signal::interrupted(p, th).then_some(()));
    Err(Errno::EINTR)
}

/// Reads the `siginfo` that `rt_sigqueueinfo` and `rt_tgsigqueueinfo` take.
fn read_info(p: &Process, va: u64) -> Result<Info, Errno> {
    // si_signo, si_errno, si_code, (pad), si_pid, si_uid, si_value.
    let mut raw = [0u8; 32];
    p.memory().read(va, &mut raw)?;
    Ok(Info { code: i32_at(&raw, 8)?, pid: u32_at(&raw, 16)?, value: u64_at(&raw, 24)? })
}

/// Whether the caller may send `info` to `target`: as on Linux, only the
/// process itself may forge `SI_USER` and `SI_TKILL`.
fn allowed(p: &Process, target: &Process, info: &Info) -> Result<(), Errno> {
    if (info.code >= 0 || info.code == code::SI_TKILL) && p.pid() != target.pid() {
        return Err(Errno::EPERM);
    }
    Ok(())
}

fn signo(sig: u64) -> Result<u8, Errno> {
    u8::try_from(sig).ok().filter(|&s| s as usize <= NSIG).ok_or(Errno::EINVAL)
}

/// `rt_sigqueueinfo(tgid, sig, uinfo)`.
pub(crate) fn rt_sigqueueinfo(p: &Process, tgid: i32, sig: u64, uinfo: u64) -> Result<u64, Errno> {
    let sig = signo(sig)?;
    let info = read_info(p, uinfo)?;
    let target = u32::try_from(tgid).ok().and_then(|t| Process::find(Pid(t))).ok_or(crate::thread::ESRCH)?;
    allowed(p, &target, &info)?;
    crate::signal::post(&target, None, sig, Pid(info.pid), Some(info), true).map(|()| 0)
}

/// `rt_tgsigqueueinfo(tgid, tid, sig, uinfo)`.
pub(crate) fn rt_tgsigqueueinfo(p: &Process, tgid: i32, tid: i32, sig: u64, uinfo: u64) -> Result<u64, Errno> {
    let sig = signo(sig)?;
    let info = read_info(p, uinfo)?;
    let (target, th) = u32::try_from(tid).ok().and_then(crate::thread::find).ok_or(crate::thread::ESRCH)?;
    if target.pid().0 as i32 != tgid {
        return Err(crate::thread::ESRCH);
    }
    allowed(p, &target, &info)?;
    crate::signal::post(&target, Some(&th), sig, Pid(info.pid), Some(info), true).map(|()| 0)
}
