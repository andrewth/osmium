//! POSIX signals: dispositions, masks, pending sets, and delivery to a user
//! handler on a signal frame.
//!
//! Signals do not queue: each signal number is pending or not. Process-wide
//! state (dispositions, the process-directed pending set) lives in
//! `Signals`; each thread has a mask and a pending set of its own
//! ([`crate::thread::Thread`]). Delivery happens when a thread returns to
//! user mode, which is when `deliver` (after every system call, in
//! `syscall::handle`) or a kernel's own call to it runs.
//!
//! The signal frame is Osmium's own layout, not Linux's `ucontext`: 128 bytes
//! of `siginfo` (`si_signo`, `si_code`, and `si_pid` or `si_addr` where
//! Linux has them), then the saved signal mask, then the saved user
//! registers. Handlers get `(signo, &siginfo, &frame_tail)` in the first three
//! argument registers, and return through a trampoline that calls
//! `rt_sigreturn`: the one the caller names with `SA_RESTORER` (x86_64), or a
//! page the kernel maps in the process's `mmap` area.
//!
//! Not implemented: queued real-time signals, `sigaltstack`, `sigsuspend`,
//! stopping and continuing (stop signals are ignored), and restarting
//! interrupted system calls (`SA_RESTART`): a blocked `futex` wait fails with
//! `EINTR`; other blocking calls are not interrupted.
#![cfg_attr(
    not(any(test, target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64"))),
    allow(dead_code)
)]

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use osmium_fs::Errno;
use osmium_mm::addr::PAGE_SIZE;
use osmium_mm::paging::MapFlags;
use osmium_sync::IrqSpinLock;

use crate::process::{ExitStatus, Pid, Process};
use crate::thread::Thread;
use crate::uregs::{NREGS, UserRegs};

/// The signals' numbers on Linux, for the architectures Osmium has.
#[allow(missing_docs)]
pub mod sig {
    pub const SIGHUP: u8 = 1;
    pub const SIGINT: u8 = 2;
    pub const SIGQUIT: u8 = 3;
    pub const SIGILL: u8 = 4;
    pub const SIGTRAP: u8 = 5;
    pub const SIGABRT: u8 = 6;
    pub const SIGBUS: u8 = 7;
    pub const SIGFPE: u8 = 8;
    pub const SIGKILL: u8 = 9;
    pub const SIGUSR1: u8 = 10;
    pub const SIGSEGV: u8 = 11;
    pub const SIGUSR2: u8 = 12;
    pub const SIGPIPE: u8 = 13;
    pub const SIGALRM: u8 = 14;
    pub const SIGTERM: u8 = 15;
    pub const SIGCHLD: u8 = 17;
    pub const SIGCONT: u8 = 18;
    pub const SIGSTOP: u8 = 19;
    pub const SIGTSTP: u8 = 20;
    pub const SIGTTIN: u8 = 21;
    pub const SIGTTOU: u8 = 22;
    pub const SIGURG: u8 = 23;
    pub const SIGWINCH: u8 = 28;
}
use sig::*;

/// The highest signal number.
pub const NSIG: usize = 64;
/// The default disposition.
pub const SIG_DFL: u64 = 0;
/// Ignore the signal.
pub const SIG_IGN: u64 = 1;

/// `sa_flags` bits.
#[allow(missing_docs)]
pub mod sa {
    pub const NOCLDSTOP: u64 = 0x1;
    pub const NOCLDWAIT: u64 = 0x2;
    pub const SIGINFO: u64 = 0x4;
    pub const RESTORER: u64 = 0x0400_0000;
    pub const ONSTACK: u64 = 0x0800_0000;
    pub const RESTART: u64 = 0x1000_0000;
    pub const NODEFER: u64 = 0x4000_0000;
    pub const RESETHAND: u64 = 0x8000_0000;
}

const SI_USER: i32 = 0;
const SI_KERNEL: i32 = 0x80;
const SEGV_MAPERR: i32 = 1;

fn bit(sig: u8) -> u64 {
    1 << (sig - 1)
}

/// Signals that cannot be blocked, caught or ignored.
const UNBLOCKABLE: u64 = 1 << (SIGKILL - 1) | 1 << (SIGSTOP - 1);

/// Whether the default action discards the signal (stopping is not
/// implemented, so stop signals count).
fn default_ignored(sig: u8) -> bool {
    matches!(sig, SIGCHLD | SIGCONT | SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU | SIGURG | SIGWINCH)
}

/// What to do on a signal, as `rt_sigaction` sets it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigAction {
    /// [`SIG_DFL`], [`SIG_IGN`] or the handler's address.
    pub handler: u64,
    /// [`sa`] bits.
    pub flags: u64,
    /// The `SA_RESTORER` trampoline (x86_64 only).
    pub restorer: u64,
    /// Signals blocked while the handler runs.
    pub mask: u64,
}

/// A process's dispositions and process-directed pending signals.
pub(crate) struct Signals {
    actions: IrqSpinLock<[SigAction; NSIG]>,
    pending: AtomicU64,
    /// Signals whose disposition discards them (`SIG_IGN`, or `SIG_DFL` of
    /// an ignoring signal).
    ignored: AtomicU64,
    senders: [AtomicU32; NSIG],
    /// Address of the kernel's `rt_sigreturn` trampoline page, or 0.
    trampoline: AtomicU64,
}

fn default_ignored_set() -> u64 {
    (1..=NSIG as u8).filter(|&s| default_ignored(s)).fold(0, |m, s| m | bit(s))
}

impl Signals {
    pub(crate) fn new() -> Self {
        Self {
            actions: IrqSpinLock::new([SigAction::default(); NSIG]),
            pending: AtomicU64::new(0),
            ignored: AtomicU64::new(default_ignored_set()),
            senders: [const { AtomicU32::new(0) }; NSIG],
            trampoline: AtomicU64::new(0),
        }
    }

    fn action(&self, sig: u8) -> SigAction {
        self.actions.lock()[sig as usize - 1]
    }

    fn set_action(&self, sig: u8, act: SigAction) {
        let discards = act.handler == SIG_IGN || act.handler == SIG_DFL && default_ignored(sig);
        self.actions.lock()[sig as usize - 1] = act;
        if discards {
            self.ignored.fetch_or(bit(sig), Ordering::SeqCst);
            // Setting a signal to be ignored discards it from the pending set.
            self.pending.fetch_and(!bit(sig), Ordering::SeqCst);
        } else {
            self.ignored.fetch_and(!bit(sig), Ordering::SeqCst);
        }
    }

    /// `fork`: the child starts with the parent's dispositions and no
    /// pending signals.
    pub(crate) fn inherit_from(&self, parent: &Signals) {
        *self.actions.lock() = *parent.actions.lock();
        self.ignored.store(parent.ignored.load(Ordering::SeqCst), Ordering::SeqCst);
        self.trampoline.store(parent.trampoline.load(Ordering::SeqCst), Ordering::SeqCst);
    }

    /// `execve`: handlers go back to the default, ignored signals stay
    /// ignored, and the trampoline page is gone with the old image.
    pub(crate) fn reset_on_exec(&self) {
        let mut actions = self.actions.lock();
        for (i, a) in actions.iter_mut().enumerate() {
            if a.handler != SIG_IGN {
                *a = SigAction::default();
            }
            let sig = i as u8 + 1;
            if a.handler == SIG_IGN || default_ignored(sig) {
                self.ignored.fetch_or(bit(sig), Ordering::SeqCst);
            } else {
                self.ignored.fetch_and(!bit(sig), Ordering::SeqCst);
            }
        }
        self.trampoline.store(0, Ordering::SeqCst);
    }
}

/// Wakes everything a signal may have to interrupt: futex waiters, and a
/// parent in `wait4`.
fn poke(p: &Process) {
    crate::futex::interrupt();
    p.child_exited.wake_all();
}

/// Sends `sig` to the process as a whole (`kill`): any thread that does not
/// block it may take it. Signal 0 only checks that the process exists.
pub fn send(p: &Process, sig: u8, from: Pid) -> Result<(), Errno> {
    check(p, sig)?;
    if sig == 0 {
        return Ok(());
    }
    if sig == SIGKILL {
        kill_group(p, ExitStatus::Signal(SIGKILL));
        return Ok(());
    }
    if p.signals.ignored.load(Ordering::SeqCst) & bit(sig) != 0 {
        return Ok(());
    }
    p.signals.senders[sig as usize - 1].store(from.0, Ordering::SeqCst);
    p.signals.pending.fetch_or(bit(sig), Ordering::SeqCst);
    poke(p);
    Ok(())
}

/// Sends `sig` to one thread (`tkill`).
pub fn send_to_thread(p: &Process, th: &Thread, sig: u8, from: Pid) -> Result<(), Errno> {
    check(p, sig)?;
    if sig == 0 {
        return Ok(());
    }
    if sig == SIGKILL {
        kill_group(p, ExitStatus::Signal(SIGKILL));
        return Ok(());
    }
    if p.signals.ignored.load(Ordering::SeqCst) & bit(sig) != 0 {
        return Ok(());
    }
    p.signals.senders[sig as usize - 1].store(from.0, Ordering::SeqCst);
    th.pending.fetch_or(bit(sig), Ordering::SeqCst);
    poke(p);
    Ok(())
}

fn check(p: &Process, sig: u8) -> Result<(), Errno> {
    if sig as usize > NSIG {
        return Err(Errno::EINVAL);
    }
    if p.exit_status().is_some() {
        return Err(crate::thread::ESRCH);
    }
    Ok(())
}

/// Ends every thread of the process, as `status`: each one stops the next
/// time it is in the kernel.
pub(crate) fn kill_group(p: &Process, status: ExitStatus) {
    let _ = p.group.exiting.set(status);
    poke(p);
}

/// Wakes a parent's blocking calls and queues `SIGCHLD` for it.
pub(crate) fn child_exited(parent: &Process, child: Pid) {
    let _ = send(parent, SIGCHLD, child);
}

/// Whether `th` has a signal that a blocked call should be interrupted for,
/// or the process is ending.
pub(crate) fn interrupted(p: &Process, th: &Thread) -> bool {
    if p.group.exiting.get().is_some() {
        return true;
    }
    (th.pending.load(Ordering::SeqCst) | p.signals.pending.load(Ordering::SeqCst))
        & !th.mask.load(Ordering::SeqCst)
        & !p.signals.ignored.load(Ordering::SeqCst)
        != 0
}

/// Takes the lowest-numbered pending signal `th` does not block.
fn take_next(p: &Process, th: &Thread) -> Option<(u8, SigAction)> {
    loop {
        let (mine, shared) = (th.pending.load(Ordering::SeqCst), p.signals.pending.load(Ordering::SeqCst));
        let ready = (mine | shared) & !th.mask.load(Ordering::SeqCst);
        if ready == 0 {
            return None;
        }
        let sig = ready.trailing_zeros() as u8 + 1;
        let b = bit(sig);
        let taken = if mine & b != 0 { &th.pending } else { &p.signals.pending };
        if taken.fetch_and(!b, Ordering::SeqCst) & b != 0 {
            return Some((sig, p.signals.action(sig)));
        }
    }
}

const FRAME_SIZE: usize = (128 + 8 + NREGS * 8).next_multiple_of(16);
const FRAME_MASK: usize = 128;
const FRAME_REGS: usize = 136;

/// Delivers one pending, unblocked signal to `th` if there is one that does
/// something: runs the default action, or redirects `regs` to the handler on
/// a signal frame below the user stack. Returns `Some` if the process must
/// end, as that status.
pub(crate) fn deliver_to<R: UserRegs>(p: &Process, th: &Thread, regs: &mut R) -> Option<ExitStatus> {
    loop {
        if let Some(status) = p.group.exiting.get() {
            return Some(*status);
        }
        let (sig, act) = take_next(p, th)?;
        match act.handler {
            SIG_IGN => continue,
            SIG_DFL if default_ignored(sig) => continue,
            SIG_DFL => {
                let status = ExitStatus::Signal(sig);
                kill_group(p, status);
                return Some(status);
            }
            _ => {}
        }
        if push_frame(p, th, regs, sig, act).is_err() {
            // No usable stack or trampoline: the program cannot continue.
            let status = ExitStatus::Signal(SIGSEGV);
            kill_group(p, status);
            return Some(status);
        }
        return None;
    }
}

fn push_frame<R: UserRegs>(p: &Process, th: &Thread, regs: &mut R, sig: u8, act: SigAction) -> Result<(), Errno> {
    let ra = if act.flags & sa::RESTORER != 0 && act.restorer != 0 {
        act.restorer
    } else {
        p.signals.trampoline.load(Ordering::SeqCst)
    };
    if ra == 0 {
        return Err(Errno::EFAULT);
    }
    let (code, value) = match th.take_fault(sig) {
        Some(addr) => (SEGV_MAPERR, addr),
        None => {
            let from = p.signals.senders[sig as usize - 1].load(Ordering::SeqCst);
            if from == 0 { (SI_KERNEL, 0) } else { (SI_USER, from as u64) }
        }
    };
    let mut buf = [0u8; FRAME_SIZE];
    buf[0..4].copy_from_slice(&(sig as i32).to_ne_bytes());
    buf[8..12].copy_from_slice(&code.to_ne_bytes());
    buf[16..24].copy_from_slice(&value.to_ne_bytes());
    buf[FRAME_MASK..FRAME_MASK + 8].copy_from_slice(&th.mask.load(Ordering::SeqCst).to_ne_bytes());
    for (i, w) in regs.save_user().iter().enumerate() {
        buf[FRAME_REGS + i * 8..FRAME_REGS + i * 8 + 8].copy_from_slice(&w.to_ne_bytes());
    }
    let base = regs
        .user_sp()
        .checked_sub(R::RED_ZONE + FRAME_SIZE as u64)
        .map(|sp| sp & !15)
        .filter(|&sp| sp != 0)
        .ok_or(Errno::EFAULT)?;
    p.memory().write(base, &buf)?;
    let sp = if R::RET_ON_STACK {
        p.memory().write(base - 8, &ra.to_ne_bytes())?;
        base - 8
    } else {
        base
    };
    let mut blocked = th.mask.load(Ordering::SeqCst) | act.mask;
    if act.flags & sa::NODEFER == 0 {
        blocked |= bit(sig);
    }
    th.mask.store(blocked & !UNBLOCKABLE, Ordering::SeqCst);
    if act.flags & sa::RESETHAND != 0 {
        p.signals.set_action(sig, SigAction::default());
    }
    regs.enter_handler(act.handler, sp, ra, [sig as u64, base, base + FRAME_MASK as u64]);
    Ok(())
}

/// `rt_sigreturn`: restores the registers and mask saved on the signal frame
/// at the stack pointer, where the handler's return left it. Only
/// unprivileged registers can be restored, so a forged frame is no more
/// than the program could do anyway.
pub(crate) fn sigreturn<R: UserRegs>(p: &Process, th: &Thread, regs: &mut R) -> Option<ExitStatus> {
    let mut buf = [0u8; FRAME_SIZE];
    if p.memory().read(regs.user_sp(), &mut buf).is_err() {
        let status = ExitStatus::Signal(SIGSEGV);
        kill_group(p, status);
        return Some(status);
    }
    let word = |off: usize| u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap());
    th.mask.store(word(FRAME_MASK) & !UNBLOCKABLE, Ordering::SeqCst);
    let mut saved = [0; NREGS];
    for (i, w) in saved.iter_mut().enumerate() {
        *w = word(FRAME_REGS + i * 8);
    }
    regs.restore_user(&saved);
    None
}

/// A fault in user mode: forces `sig` (normally `SIGSEGV`) on `th`, which
/// reports `addr`. If the thread blocks or ignores it, or is already in its
/// handler, the default action ends the process.
pub(crate) fn fault_to<R: UserRegs>(p: &Process, th: &Thread, regs: &mut R, sig: u8, addr: u64) -> Option<ExitStatus> {
    let blocked = th.mask.load(Ordering::SeqCst) & bit(sig) != 0;
    let act = p.signals.action(sig);
    if blocked || act.handler == SIG_IGN {
        p.signals.set_action(sig, SigAction::default());
        th.mask.fetch_and(!bit(sig), Ordering::SeqCst);
    }
    th.set_fault(sig, addr);
    th.pending.fetch_or(bit(sig), Ordering::SeqCst);
    deliver_to(p, th, regs)
}

/// `rt_sigaction(sig, act, oldact, sigsetsize)`.
pub(crate) fn sigaction(p: &Process, sig: u64, act: u64, old: u64, size: u64) -> Result<u64, Errno> {
    if size != 8 || sig == 0 || sig > NSIG as u64 {
        return Err(Errno::EINVAL);
    }
    let sig = sig as u8;
    let new = if act != 0 { Some(read_action(p, act)?) } else { None };
    if new.is_some() && bit(sig) & UNBLOCKABLE != 0 {
        return Err(Errno::EINVAL);
    }
    if old != 0 {
        write_action(p, old, &p.signals.action(sig))?;
    }
    if let Some(mut new) = new {
        new.mask &= !UNBLOCKABLE;
        if !matches!(new.handler, SIG_DFL | SIG_IGN) && (new.flags & sa::RESTORER == 0 || !cfg!(target_arch = "x86_64"))
        {
            ensure_trampoline(p)?;
        }
        p.signals.set_action(sig, new);
    }
    Ok(0)
}

/// `struct sigaction` as the kernel has it: x86_64 adds a restorer.
#[cfg(target_arch = "x86_64")]
const ACTION_WORDS: usize = 4;
#[cfg(not(target_arch = "x86_64"))]
const ACTION_WORDS: usize = 3;

fn read_action(p: &Process, va: u64) -> Result<SigAction, Errno> {
    let mut b = [0u8; ACTION_WORDS * 8];
    p.memory().read(va, &mut b)?;
    let w = |i: usize| u64::from_ne_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    Ok(if cfg!(target_arch = "x86_64") {
        SigAction { handler: w(0), flags: w(1), restorer: w(2), mask: w(3) }
    } else {
        SigAction { handler: w(0), flags: w(1), restorer: 0, mask: w(2) }
    })
}

fn write_action(p: &Process, va: u64, a: &SigAction) -> Result<(), Errno> {
    let words = if cfg!(target_arch = "x86_64") {
        [a.handler, a.flags, a.restorer, a.mask]
    } else {
        [a.handler, a.flags, a.mask, 0]
    };
    let mut b = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        b[i * 8..i * 8 + 8].copy_from_slice(&w.to_ne_bytes());
    }
    p.memory().write(va, &b[..ACTION_WORDS * 8])
}

/// `rt_sigreturn` as code: load the number, make the call.
#[cfg(target_arch = "x86_64")]
const TRAMPOLINE: &[u8] = &[0xb8, 15, 0, 0, 0, 0x0f, 0x05];
#[cfg(target_arch = "aarch64")]
const TRAMPOLINE: &[u8] = &[0x68, 0x11, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4];
#[cfg(target_arch = "riscv64")]
const TRAMPOLINE: &[u8] = &[0x93, 0x08, 0xb0, 0x08, 0x73, 0x00, 0x00, 0x00];

/// Maps the page that handlers return through, once per image.
fn ensure_trampoline(p: &Process) -> Result<(), Errno> {
    if p.signals.trampoline.load(Ordering::SeqCst) != 0 {
        return Ok(());
    }
    let va = p.mmap_anon(PAGE_SIZE as u64, MapFlags::NONE)?;
    p.memory().map_code(va, TRAMPOLINE)?;
    p.signals.trampoline.store(va, Ordering::SeqCst);
    Ok(())
}

/// `rt_sigprocmask(how, set, oldset, sigsetsize)` for `th`.
pub(crate) fn sigprocmask(p: &Process, th: &Thread, how: u64, set: u64, old: u64, size: u64) -> Result<u64, Errno> {
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    let cur = th.mask.load(Ordering::SeqCst);
    let new = if set != 0 {
        let mut b = [0u8; 8];
        p.memory().read(set, &mut b)?;
        let s = u64::from_ne_bytes(b);
        Some(match how {
            0 => cur | s,
            1 => cur & !s,
            2 => s,
            _ => return Err(Errno::EINVAL),
        })
    } else {
        None
    };
    if old != 0 {
        p.memory().write(old, &cur.to_ne_bytes())?;
    }
    if let Some(m) = new {
        th.mask.store(m & !UNBLOCKABLE, Ordering::SeqCst);
    }
    Ok(0)
}

/// `rt_sigpending(set, sigsetsize)`.
pub(crate) fn sigpending(p: &Process, th: &Thread, set: u64, size: u64) -> Result<u64, Errno> {
    if size != 8 {
        return Err(Errno::EINVAL);
    }
    let pending =
        (th.pending.load(Ordering::SeqCst) | p.signals.pending.load(Ordering::SeqCst)) & th.mask.load(Ordering::SeqCst);
    p.memory().write(set, &pending.to_ne_bytes())?;
    Ok(0)
}

fn signo(sig: u64) -> Result<u8, Errno> {
    u8::try_from(sig).ok().filter(|&s| s as usize <= NSIG).ok_or(Errno::EINVAL)
}

/// `kill(pid, sig)`: `pid` 0 means the caller's own process; there are no
/// process groups, so negative pids fail.
pub(crate) fn kill(p: &Process, pid: i32, sig: u64) -> Result<u64, Errno> {
    let sig = signo(sig)?;
    let target = match pid {
        0 => Process::find(p.pid()),
        1.. => Process::find(Pid(pid as u32)),
        _ => None,
    };
    send(&*target.ok_or(crate::thread::ESRCH)?, sig, p.pid()).map(|()| 0)
}

/// `tkill(tid, sig)`.
pub(crate) fn tkill(p: &Process, tid: i32, sig: u64) -> Result<u64, Errno> {
    let sig = signo(sig)?;
    let (target, th) = u32::try_from(tid).ok().and_then(crate::thread::find).ok_or(crate::thread::ESRCH)?;
    send_to_thread(&target, &th, sig, p.pid()).map(|()| 0)
}

/// `tgkill(tgid, tid, sig)`: like `tkill`, but the thread must be in `tgid`.
pub(crate) fn tgkill(p: &Process, tgid: i32, tid: i32, sig: u64) -> Result<u64, Errno> {
    let sig = signo(sig)?;
    let (target, th) = u32::try_from(tid).ok().and_then(crate::thread::find).ok_or(crate::thread::ESRCH)?;
    if target.pid().0 as i32 != tgid {
        return Err(crate::thread::ESRCH);
    }
    send_to_thread(&target, &th, sig, p.pid()).map(|()| 0)
}

/// After `execve`: dispositions reset, and the thread-pointer register clear.
pub(crate) fn on_exec(p: &Process) {
    p.signals.reset_on_exec();
    p.group.reset_on_exec();
}

#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64")))]
use osmium_arch::trap::TrapFrame;

/// Delivers a pending signal to the current thread, for a trap taken from
/// user mode (other than a system call, which `syscall::handle` covers).
/// Call it when about to return to user mode, for example after a
/// timer interrupt: this is also where a process ended by a signal or
/// `exit_group` stops its other threads. Returns `Some` if the process must
/// end, as that status: call [`crate::exit`] with it.
#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64")))]
pub fn deliver(frame: &mut TrapFrame) -> Option<ExitStatus> {
    let p = crate::current()?;
    let th = crate::thread::current_thread(&p);
    deliver_to(&p, &th, frame)
}

/// A fault in user mode, such as a page fault at `addr`: raises `sig`
/// (usually [`sig::SIGSEGV`]) in the current thread and delivers it. Returns
/// `Some` if the process has no handler and must end, as that status: log
/// it and call [`crate::exit`]. Returns `None` if `frame` now runs the
/// program's handler.
#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64")))]
pub fn user_fault(frame: &mut TrapFrame, sig: u8, addr: usize) -> Option<ExitStatus> {
    let Some(p) = crate::current() else { return Some(ExitStatus::Signal(sig)) };
    let th = crate::thread::current_thread(&p);
    fault_to(&p, &th, frame, sig, addr as u64)
}

#[cfg(test)]
impl Signals {
    pub(crate) fn action_for_test(&self, sig: u8) -> SigAction {
        self.action(sig)
    }
}
