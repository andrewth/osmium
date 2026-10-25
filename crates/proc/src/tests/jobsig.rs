#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Queued signals, the alternate signal stack, `sigsuspend`, and stopping and
//! continuing. The first group needs no scheduler; the rest run tasks on the
//! real one, as `blocked.rs` does.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use osmium_sched::TaskBuilder;

use super::blocked::become_cpu;
use super::*;
use crate::signal::{self, sa, sig::*};
use crate::sigqueue::code::{SI_QUEUE, SI_TKILL};
use crate::thread::Thread;
use crate::uregs::{NREGS, UserRegs};

const EINVAL: i64 = -(Errno::EINVAL.0 as i64);
const EAGAIN: i64 = -(Errno::EAGAIN.0 as i64);
const EINTR: i64 = -(Errno::EINTR.0 as i64);
const EPERM: i64 = -(Errno::EPERM.0 as i64);
const ENOMEM: i64 = -(Errno::ENOMEM.0 as i64);
const EFAULT: i64 = -(Errno::EFAULT.0 as i64);
const ESRCH: i64 = -3;

const STACK: u64 = DATA + 0x3000;
const ALT: u64 = DATA + 0x1000;
const ALT_SIZE: u64 = 0x1000;
const HANDLER: u64 = 0x40_1234;
const SIGRT1: u8 = 33;
const SIGRT2: u8 = 34;

/// A register file that returns through the stack, like x86_64.
struct Regs {
    sp: u64,
    pc: u64,
    ra: u64,
    args: [u64; 3],
    gp: [u64; NREGS],
}

impl Regs {
    fn new() -> Self {
        Self { sp: STACK, pc: 0x40_0000, ra: 0, args: [0; 3], gp: [7; NREGS] }
    }
}

impl UserRegs for Regs {
    const RED_ZONE: u64 = 128;
    const RET_ON_STACK: bool = true;

    fn user_pc(&self) -> u64 {
        self.pc
    }
    fn valid_pc(pc: u64) -> bool {
        pc >> 47 == 0
    }
    fn user_sp(&self) -> u64 {
        self.sp
    }
    fn set_user_sp(&mut self, sp: u64) {
        self.sp = sp;
    }
    fn set_ret(&mut self, _: u64) {}
    fn set_tls(&mut self, _: u64) {}
    fn save_user(&self) -> [u64; NREGS] {
        let mut s = self.gp;
        (s[0], s[1]) = (self.pc, self.sp);
        s
    }
    fn restore_user(&mut self, s: &[u64; NREGS]) {
        self.gp = *s;
        (self.pc, self.sp) = (s[0], s[1]);
    }
    fn enter_handler(&mut self, pc: u64, sp: u64, ra: u64, args: [u64; 3]) {
        (self.pc, self.sp, self.ra, self.args) = (pc, sp, ra, args);
    }
}

fn bit(sig: u8) -> u64 {
    1 << (sig - 1)
}

fn sigaction(p: &Process, sig: u8, flags: u64) -> i64 {
    let words =
        if cfg!(target_arch = "x86_64") { alloc::vec![HANDLER, flags, 0, 0] } else { alloc::vec![HANDLER, flags, 0] };
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    put(p, DATA + 0x800, &bytes);
    call(p, Sys::RtSigaction, &[sig as u64, DATA + 0x800, 0, 8])
}

fn setmask(p: &Process, mask: u64) {
    put(p, DATA + 0x700, &mask.to_ne_bytes());
    assert_eq!(call(p, Sys::RtSigprocmask, &[2, DATA + 0x700, 0, 8]), 0);
}

/// `rt_sigqueueinfo(pid, sig, {si_code: code, si_pid: caller, si_value: value})`.
fn queue(p: &Process, pid: u32, sig: u8, code: i32, value: u64) -> i64 {
    let mut b = [0u8; 128];
    b[..4].copy_from_slice(&(sig as i32).to_ne_bytes());
    b[8..12].copy_from_slice(&code.to_ne_bytes());
    b[16..20].copy_from_slice(&p.pid().0.to_ne_bytes());
    b[24..32].copy_from_slice(&value.to_ne_bytes());
    put(p, DATA + 0x600, &b);
    call(p, Sys::RtSigqueueinfo, &[pid as u64, sig as u64, DATA + 0x600])
}

/// What a handler sees: (signo, si_code, si_pid, si_value).
type Seen = (i32, i32, u64, u64);

/// Delivers the next signal, if any reaches a handler, reads its `siginfo`
/// off the frame and returns through the trampoline.
fn next(p: &Process, th: &Thread, regs: &mut Regs) -> Option<Seen> {
    regs.pc = 0x40_0000;
    assert_eq!(signal::deliver_to(p, th, regs), None);
    if regs.pc != HANDLER {
        return None;
    }
    let b = get(p, regs.args[1], 32);
    let seen = (
        i32::from_ne_bytes(b[..4].try_into().unwrap()),
        i32::from_ne_bytes(b[8..12].try_into().unwrap()),
        u64::from_ne_bytes(b[16..24].try_into().unwrap()),
        u64::from_ne_bytes(b[24..32].try_into().unwrap()),
    );
    assert_eq!(regs.args[0], seen.0 as u64);
    // The handler's `ret` pops the trampoline's address.
    regs.sp += 8;
    assert_eq!(signal::sigreturn(p, th, regs), None);
    Some(seen)
}

#[test]
fn realtime_signals_queue_with_their_siginfo_in_order() {
    let (p, _) = process("rt-queue");
    let th = p.leader();
    let mut regs = Regs::new();
    for s in [SIGUSR1, SIGRT1, SIGRT2] {
        assert_eq!(sigaction(&p, s, sa::SIGINFO), 0);
    }
    setmask(&p, bit(SIGUSR1) | bit(SIGRT1) | bit(SIGRT2));
    let pid = p.pid().0;
    for (s, v) in [(SIGRT2, 1), (SIGRT1, 2), (SIGRT2, 3), (SIGUSR1, 4), (SIGUSR1, 5)] {
        assert_eq!(queue(&p, pid, s, SI_QUEUE, v), 0);
    }
    assert_eq!(next(&p, &th, &mut regs), None, "all blocked");
    setmask(&p, 0);
    let me = pid as u64;
    // Lowest number first. A real-time signal queues once per send; a standard one coalesces
    // and keeps the first send's value.
    assert_eq!(next(&p, &th, &mut regs), Some((SIGUSR1 as i32, SI_QUEUE, me, 4)));
    assert_eq!(next(&p, &th, &mut regs), Some((SIGRT1 as i32, SI_QUEUE, me, 2)));
    assert_eq!(next(&p, &th, &mut regs), Some((SIGRT2 as i32, SI_QUEUE, me, 1)));
    assert_eq!(next(&p, &th, &mut regs), Some((SIGRT2 as i32, SI_QUEUE, me, 3)));
    assert_eq!(next(&p, &th, &mut regs), None);
    assert_eq!(p.signals.pending_for_test(), 0);
}

#[test]
fn kill_queues_realtime_signals_and_a_full_queue_pushes_back() {
    let (p, _) = process("rt-full");
    let th = p.leader();
    let mut regs = Regs::new();
    assert_eq!(sigaction(&p, SIGRT1, sa::SIGINFO), 0);
    setmask(&p, bit(SIGRT1));
    let pid = p.pid().0 as u64;
    for _ in 0..2 {
        assert_eq!(call(&p, Sys::Kill, &[pid, SIGRT1 as u64]), 0);
    }
    for i in 0..crate::sigqueue::QUEUE_MAX as u64 - 2 {
        assert_eq!(queue(&p, p.pid().0, SIGRT1, SI_QUEUE, i), 0);
    }
    assert_eq!(queue(&p, p.pid().0, SIGRT1, SI_QUEUE, 99), EAGAIN);
    // `kill` still leaves the signal pending, without an entry of its own.
    assert_eq!(call(&p, Sys::Kill, &[pid, SIGRT1 as u64]), 0);
    setmask(&p, 0);
    let first = next(&p, &th, &mut regs).unwrap();
    assert_eq!((first.1, first.2), (0, pid), "kill's entries come first, as SI_USER from the sender");
    let mut n = 1;
    while next(&p, &th, &mut regs).is_some() {
        n += 1;
    }
    assert_eq!(n, crate::sigqueue::QUEUE_MAX, "the queue held that many; the last kill had no entry");
}

#[test]
fn thread_directed_signals_queue_per_thread() {
    let (p, _) = process("rt-tg");
    let th = p.leader();
    let mut regs = Regs::new();
    assert_eq!(sigaction(&p, SIGRT1, sa::SIGINFO), 0);
    let mut b = [0u8; 128];
    b[8..12].copy_from_slice(&SI_QUEUE.to_ne_bytes());
    b[24..32].copy_from_slice(&77u64.to_ne_bytes());
    put(&p, DATA + 0x600, &b);
    let pid = p.pid().0 as u64;
    assert_eq!(call(&p, Sys::RtTgsigqueueinfo, &[pid, pid, SIGRT1 as u64, DATA + 0x600]), 0);
    assert_eq!(call(&p, Sys::RtTgsigqueueinfo, &[pid + 1, pid, SIGRT1 as u64, DATA + 0x600]), ESRCH);
    assert_eq!(p.signals.pending_for_test(), 0, "not process-directed");
    assert_eq!(next(&p, &th, &mut regs).map(|s| s.3), Some(77));
}

#[test]
fn sigqueueinfo_checks_its_arguments() {
    let (p, _) = process("rt-args");
    let other = p.fork().unwrap();
    let pid = p.pid().0;
    assert_eq!(queue(&p, pid, 65, SI_QUEUE, 0), EINVAL);
    assert_eq!(call(&p, Sys::RtSigqueueinfo, &[pid as u64, SIGRT1 as u64, 0x0123_4567_8000]), EFAULT);
    assert_eq!(queue(&p, 999_999, SIGRT1, SI_QUEUE, 0), ESRCH);
    // Forging a `kill` or `tkill` is for the process itself only.
    assert_eq!(queue(&p, other.pid().0, SIGRT1, 0, 0), EPERM);
    assert_eq!(queue(&p, other.pid().0, SIGRT1, SI_TKILL, 0), EPERM);
    assert_eq!(queue(&p, other.pid().0, SIGRT1, SI_QUEUE, 0), 0);
    assert_eq!(queue(&p, pid, SIGRT1, 0, 0), 0);
    // An ignored signal is dropped, not queued.
    let mut ign = [0u8; 32];
    ign[0] = 1;
    put(&p, DATA + 0x900, &ign);
    assert_eq!(call(&p, Sys::RtSigaction, &[SIGRT2 as u64, DATA + 0x900, 0, 8]), 0);
    assert_eq!(queue(&p, pid, SIGRT2, SI_QUEUE, 0), 0);
    assert_eq!(p.signals.pending_for_test() & bit(SIGRT2), 0);
}

fn set_alt(p: &Process, sp: u64, flags: i32, size: u64) -> i64 {
    let mut b = [0u8; 24];
    b[..8].copy_from_slice(&sp.to_ne_bytes());
    b[8..12].copy_from_slice(&flags.to_ne_bytes());
    b[16..].copy_from_slice(&size.to_ne_bytes());
    put(p, DATA + 0xa00, &b);
    call(p, Sys::Sigaltstack, &[DATA + 0xa00, 0])
}

fn get_alt(p: &Process) -> (u64, i32, u64) {
    assert_eq!(call(p, Sys::Sigaltstack, &[0, DATA + 0xa40]), 0);
    let b = get(p, DATA + 0xa40, 24);
    (
        u64::from_ne_bytes(b[..8].try_into().unwrap()),
        i32::from_ne_bytes(b[8..12].try_into().unwrap()),
        u64::from_ne_bytes(b[16..].try_into().unwrap()),
    )
}

#[test]
fn sigaltstack_is_set_read_and_validated() {
    let (p, _) = process("altstack");
    assert_eq!(get_alt(&p), (0, 2, 0), "disabled to begin with");
    assert_eq!(set_alt(&p, ALT, 0, 100), ENOMEM, "too small");
    assert_eq!(set_alt(&p, ALT, 4, ALT_SIZE), EINVAL, "unknown flag");
    assert_eq!(set_alt(&p, u64::MAX - 10, 0, ALT_SIZE), EINVAL, "wraps");
    assert_eq!(call(&p, Sys::Sigaltstack, &[0x0123_4567_8000, 0]), EFAULT);
    assert_eq!(set_alt(&p, ALT, 0, ALT_SIZE), 0);
    assert_eq!(get_alt(&p), (ALT, 0, ALT_SIZE));
    // Running on it: reported, and it cannot be changed from there.
    let th = p.leader();
    th.sig.set_entry_sp(ALT + 0x800);
    assert_eq!(get_alt(&p), (ALT, 1, ALT_SIZE));
    assert_eq!(set_alt(&p, ALT, 2, 0), EPERM);
    th.sig.set_entry_sp(STACK);
    assert_eq!(set_alt(&p, 0, 2, 0), 0);
    assert_eq!(get_alt(&p), (0, 2, 0));
}

#[test]
fn onstack_handlers_run_on_the_alternate_stack() {
    let (p, _) = process("altstack-handler");
    let th = p.leader();
    let mut regs = Regs::new();
    assert_eq!(sigaction(&p, SIGUSR1, sa::ONSTACK | sa::NODEFER), 0);
    assert_eq!(sigaction(&p, SIGUSR2, 0), 0);
    let pid = p.pid().0 as u64;
    // No alternate stack yet: the handler uses the user stack, below its red zone.
    call(&p, Sys::Kill, &[pid, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert!(regs.sp < STACK - 128 && regs.sp > STACK - 1024, "{:#x}", regs.sp);
    regs.sp += 8;
    assert_eq!(signal::sigreturn(&p, &th, &mut regs), None);
    assert_eq!(regs.sp, STACK);

    assert_eq!(set_alt(&p, ALT, 0, ALT_SIZE), 0);
    call(&p, Sys::Kill, &[pid, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(regs.pc, HANDLER);
    assert!(regs.sp > ALT && regs.sp <= ALT + ALT_SIZE, "on the alternate stack: {:#x}", regs.sp);
    let on_alt = regs.sp;
    // A handler that is entered on the alternate stack stays on it, below the interrupted frame,
    // even if it asks for the alternate stack too.
    th.sig.set_entry_sp(regs.sp);
    for sig in [SIGUSR2, SIGUSR1] {
        regs.sp = on_alt;
        call(&p, Sys::Kill, &[pid, sig as u64]);
        assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
        assert!(regs.sp < on_alt - 128 && regs.sp > ALT, "nested on the same stack: {:#x}", regs.sp);
        regs.sp += 8;
        assert_eq!(signal::sigreturn(&p, &th, &mut regs), None);
        assert_eq!(regs.sp, on_alt);
    }
    // Returning from the outer handler restores the program's own stack pointer.
    regs.sp = on_alt + 8;
    assert_eq!(signal::sigreturn(&p, &th, &mut regs), None);
    assert_eq!(regs.sp, STACK);
    // A new program has none.
    th.sig.reset_on_exec();
    assert_eq!(get_alt(&p), (0, 2, 0));
}

#[test]
fn an_unusable_alternate_stack_ends_the_program() {
    let (p, _) = process("altstack-tiny");
    let th = p.leader();
    let mut regs = Regs::new();
    assert_eq!(sigaction(&p, SIGUSR1, sa::ONSTACK), 0);
    // An alternate stack in unmapped memory: the frame cannot be written.
    assert_eq!(set_alt(&p, 0x6000_0000, 0, crate::sigqueue::MINSIGSTKSZ), 0);
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), Some(ExitStatus::Signal(SIGSEGV)));
}

#[test]
fn fork_inherits_the_alternate_stack() {
    let (p, _) = process("altstack-fork");
    assert_eq!(set_alt(&p, ALT, 0, ALT_SIZE), 0);
    let child = fork_child(&p);
    assert_eq!(get_alt(&child), (ALT, 0, ALT_SIZE));
}

#[test]
fn stop_signals_and_sigcont_cancel_each_other_when_sent() {
    let (p, _) = process("job-cancel");
    let pid = p.pid().0 as u64;
    assert_eq!(sigaction(&p, SIGCONT, 0), 0);
    setmask(&p, bit(SIGCONT) | bit(SIGTSTP));
    call(&p, Sys::Kill, &[pid, SIGCONT as u64]);
    call(&p, Sys::Kill, &[pid, SIGTSTP as u64]);
    assert_eq!(p.signals.pending_for_test(), bit(SIGTSTP), "the stop signal cancelled SIGCONT");
    call(&p, Sys::Kill, &[pid, SIGCONT as u64]);
    assert_eq!(p.signals.pending_for_test(), bit(SIGCONT), "SIGCONT cancelled the stop signal");
}

// The tests below run tasks on the real scheduler.

const PENDING: i64 = i64::MIN;

fn run_task(
    p: &Arc<Process>,
    body: impl FnOnce(&Arc<Process>) -> i64 + Send + 'static,
) -> (Arc<osmium_sched::Task>, Arc<AtomicI64>) {
    let result = Arc::new(AtomicI64::new(PENDING));
    let (q, r) = (p.clone(), result.clone());
    let builder = TaskBuilder::new("job").stack_size(256 * 1024).cpu(osmium_arch::cpu::current_id());
    let task = p.spawn(builder, move || r.store(body(&q), Ordering::SeqCst));
    osmium_sched::yield_now();
    (task, result)
}

fn idle() {
    for _ in 0..5 {
        osmium_sched::yield_now();
    }
}

#[test]
fn sigsuspend_waits_for_an_unblocked_signal_and_restores_the_mask() {
    become_cpu();
    let (p, _) = process("suspend");
    assert_eq!(sigaction(&p, SIGUSR1, 0), 0);
    assert_eq!(sigaction(&p, SIGUSR2, 0), 0);
    let original = bit(SIGUSR1) | bit(SIGUSR2);
    setmask(&p, original);
    // Suspend with SIGUSR2 let through and SIGUSR1 still blocked.
    put(&p, DATA + 0xb00, &bit(SIGUSR1).to_ne_bytes());
    let seen = Arc::new(AtomicU64::new(0));
    let s = seen.clone();
    let (task, result) = run_task(&p, move |p| {
        let r = call(p, Sys::RtSigsuspend, &[DATA + 0xb00, 8]);
        let th = p.leader();
        let mut regs = Regs::new();
        // `syscall::handle` delivers after the call.
        assert_eq!(signal::deliver_to(p, &th, &mut regs), None);
        assert_eq!(regs.pc, HANDLER, "the handler runs before the program sees sigsuspend return");
        // The frame carries the mask from before the call, not the temporary one.
        s.store(u64::from_ne_bytes(get(p, regs.args[2], 8).try_into().unwrap()), Ordering::SeqCst);
        assert_eq!(th.signal_mask(), bit(SIGUSR1) | bit(SIGUSR2), "SIGUSR1 as before plus the handler's own");
        r
    });
    assert_eq!(result.load(Ordering::SeqCst), PENDING, "blocked");
    signal::send(&p, SIGUSR1, p.pid()).unwrap();
    idle();
    assert_eq!(result.load(Ordering::SeqCst), PENDING, "a signal the temporary mask blocks does not wake it");
    signal::send(&p, SIGUSR2, p.pid()).unwrap();
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), EINTR);
    assert_eq!(seen.load(Ordering::SeqCst), original);
}

#[test]
fn sigsuspend_ends_at_once_for_a_pending_signal_and_checks_its_arguments() {
    become_cpu();
    let (p, _) = process("suspend-pending");
    assert_eq!(sigaction(&p, SIGUSR1, 0), 0);
    setmask(&p, bit(SIGUSR1));
    put(&p, DATA + 0xb00, &0u64.to_ne_bytes());
    signal::send(&p, SIGUSR1, p.pid()).unwrap();
    let (task, result) = run_task(&p, move |p| {
        let r = call(p, Sys::RtSigsuspend, &[DATA + 0xb00, 8]);
        let th = p.leader();
        let mut regs = Regs::new();
        assert_eq!(signal::deliver_to(p, &th, &mut regs), None);
        assert_eq!(regs.pc, HANDLER);
        r
    });
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), EINTR);
    assert_eq!(call(&p, Sys::RtSigsuspend, &[DATA + 0xb00, 4]), EINVAL);
    assert_eq!(call(&p, Sys::RtSigsuspend, &[0x0123_4567_8000, 8]), EFAULT);
}

#[test]
fn sigsuspend_ends_the_process_on_a_fatal_signal() {
    become_cpu();
    let (p, _) = process("suspend-fatal");
    put(&p, DATA + 0xb00, &0u64.to_ne_bytes());
    let (task, result) = run_task(&p, move |p| call(p, Sys::RtSigsuspend, &[DATA + 0xb00, 8]));
    assert_eq!(result.load(Ordering::SeqCst), PENDING);
    signal::send(&p, SIGTERM, p.pid()).unwrap();
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), EINTR);
    let th = p.leader();
    assert_eq!(signal::deliver_to(&p, &th, &mut Regs::new()), Some(ExitStatus::Signal(SIGTERM)));
}

/// Starts `child`'s only thread as a task that behaves like a program being
/// interrupted by a timer: it calls `deliver_to` over and over, as the trap
/// handler would, and counts the rounds. It ends the process when
/// `deliver_to` says so.
fn spin_child(child: &Arc<Process>, ticks: &Arc<AtomicU64>, handled: &Arc<AtomicBool>) -> Arc<osmium_sched::Task> {
    let (c, t, h) = (child.clone(), ticks.clone(), handled.clone());
    let builder = TaskBuilder::new("child").stack_size(256 * 1024).cpu(osmium_arch::cpu::current_id());
    child.spawn(builder, move || {
        let th = c.leader();
        let mut regs = Regs::new();
        loop {
            if let Some(status) = signal::deliver_to(&c, &th, &mut regs) {
                c.set_exited(status);
                return;
            }
            if regs.pc == HANDLER {
                h.store(true, Ordering::SeqCst);
                regs.pc = 0x40_0000;
            }
            t.fetch_add(1, Ordering::SeqCst);
            osmium_sched::yield_now();
        }
    })
}

fn wait4(p: &Process, pid: u32, options: u64) -> (i64, i32) {
    put(p, DATA + 0xc00, &0i32.to_ne_bytes());
    let r = call(p, Sys::Wait4, &[pid as u64, DATA + 0xc00, options, 0]);
    (r, i32::from_ne_bytes(get(p, DATA + 0xc00, 4).try_into().unwrap()))
}

const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;
const WCONTINUED: u64 = 8;

fn settle(ticks: &AtomicU64) -> u64 {
    idle();
    ticks.load(Ordering::SeqCst)
}

fn stop_and_continue(stop: u8) {
    become_cpu();
    let (p, _) = process("job-parent");
    let child = p.fork().unwrap();
    assert_eq!(sigaction(&child, SIGCONT, 0), 0);
    // The parent hears of stops through SIGCHLD.
    assert_eq!(sigaction(&p, SIGCHLD, 0), 0);
    let (ticks, handled) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicBool::new(false)));
    let task = spin_child(&child, &ticks, &handled);
    assert!(settle(&ticks) > 0, "the child runs");

    signal::send(&child, stop, p.pid()).unwrap();
    let (r, status) = wait4(&p, child.pid().0, WUNTRACED);
    assert_eq!(r, child.pid().0 as i64);
    assert_eq!(status, (stop as i32) << 8 | 0x7f, "WIFSTOPPED, WSTOPSIG");
    assert!(child.signals.job.stopped());
    assert_ne!(p.signals.pending_for_test() & bit(SIGCHLD), 0, "SIGCHLD for the stop");
    assert_eq!(wait4(&p, child.pid().0, WUNTRACED | WNOHANG).0, 0, "reported once");
    assert_eq!(wait4(&p, child.pid().0, WCONTINUED | WNOHANG).0, 0, "no continue yet");
    // It does not run while stopped.
    let frozen = settle(&ticks);
    assert_eq!(settle(&ticks), frozen);
    // A plain wait does not see a stop.
    assert_eq!(wait4(&p, child.pid().0, WNOHANG).0, 0);

    signal::send(&child, SIGCONT, p.pid()).unwrap();
    let (r, status) = wait4(&p, child.pid().0, WCONTINUED);
    assert_eq!((r, status), (child.pid().0 as i64, 0xffff), "WIFCONTINUED");
    assert!(!child.signals.job.stopped());
    assert!(settle(&ticks) > frozen, "running again");
    assert!(handled.load(Ordering::SeqCst), "SIGCONT's handler ran as well");
    assert_eq!(wait4(&p, child.pid().0, WCONTINUED | WNOHANG).0, 0, "reported once");

    // A stopped process is still killed by SIGKILL, and then reaped with its signal.
    signal::send(&child, SIGSTOP, p.pid()).unwrap();
    assert_eq!(wait4(&p, child.pid().0, WUNTRACED).1 >> 8, SIGSTOP as i32);
    signal::send(&child, SIGKILL, p.pid()).unwrap();
    task.join();
    let (r, status) = wait4(&p, child.pid().0, WUNTRACED);
    assert_eq!((r, status), (child.pid().0 as i64, SIGKILL as i32));
}

#[test]
fn sigstop_stops_a_process_until_sigcont_and_wait4_reports_both() {
    stop_and_continue(SIGSTOP);
}

#[test]
fn sigtstp_stops_by_default() {
    stop_and_continue(SIGTSTP);
}

#[test]
fn sigttin_stops_by_default() {
    stop_and_continue(SIGTTIN);
}

#[test]
fn a_caught_sigtstp_runs_its_handler_instead_of_stopping() {
    become_cpu();
    let (p, _) = process("job-caught");
    let child = p.fork().unwrap();
    assert_eq!(sigaction(&child, SIGTSTP, 0), 0);
    let (ticks, handled) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicBool::new(false)));
    let task = spin_child(&child, &ticks, &handled);
    signal::send(&child, SIGTSTP, p.pid()).unwrap();
    settle(&ticks);
    assert!(handled.load(Ordering::SeqCst));
    assert!(!child.signals.job.stopped());
    assert_eq!(wait4(&p, child.pid().0, WUNTRACED | WNOHANG).0, 0);
    signal::send(&child, SIGKILL, p.pid()).unwrap();
    task.join();
}

#[test]
fn nocldstop_keeps_sigchld_quiet_but_wait4_still_reports() {
    become_cpu();
    let (p, _) = process("job-nocldstop");
    assert_eq!(sigaction(&p, SIGCHLD, sa::NOCLDSTOP), 0);
    let child = p.fork().unwrap();
    let (ticks, handled) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicBool::new(false)));
    let task = spin_child(&child, &ticks, &handled);
    signal::send(&child, SIGSTOP, p.pid()).unwrap();
    assert_eq!(wait4(&p, child.pid().0, WUNTRACED).0, child.pid().0 as i64);
    assert_eq!(p.signals.pending_for_test() & bit(SIGCHLD), 0);
    signal::send(&child, SIGKILL, p.pid()).unwrap();
    task.join();
}

#[test]
fn a_thread_blocked_in_a_call_is_interrupted_by_the_stop_and_parks() {
    become_cpu();
    let (q, _) = process("job-blocked");
    assert_eq!(call(&q, Sys::Pipe2, &[DATA, 0]), 0);
    let r = u32::from_ne_bytes(get(&q, DATA, 4).try_into().unwrap()) as u64;
    let (task, result) = run_task(&q, move |q| {
        let r = call(q, Sys::Read, &[r, DATA + 0x100, 8]);
        let mut regs = Regs::new();
        assert_eq!(signal::deliver_to(q, &q.leader(), &mut regs), None);
        r
    });
    assert_eq!(result.load(Ordering::SeqCst), PENDING);
    signal::send(&q, SIGSTOP, q.pid()).unwrap();
    idle();
    assert!(q.signals.job.stopped());
    assert_eq!(result.load(Ordering::SeqCst), PENDING, "parked in deliver_to");
    // After the continue the call has already been interrupted: restarting is not implemented.
    signal::send(&q, SIGCONT, q.pid()).unwrap();
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), EINTR);
}
