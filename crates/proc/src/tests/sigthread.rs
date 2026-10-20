//! Signals, threads and futexes, driven without a scheduler: threads are
//! registered by `clone` and exited by hand.

use core::sync::atomic::Ordering;

use super::*;
use crate::futex;
use crate::signal::{self, SIG_IGN, SigAction, sa, sig::*};
use crate::thread::{self, Thread};
use crate::uregs::{NREGS, UserRegs};

const EINVAL: i64 = -(Errno::EINVAL.0 as i64);
const ESRCH: i64 = -3;
const EAGAIN: i64 = -(Errno::EAGAIN.0 as i64);
const EINTR: i64 = -(Errno::EINTR.0 as i64);

const STACK: u64 = DATA + 0x3000;
const HANDLER: u64 = 0x40_1234;

/// A register file with the user-visible state of a trap frame.
#[allow(dead_code)]
struct Regs<const ON_STACK: bool> {
    sp: u64,
    pc: u64,
    ra: u64,
    args: [u64; 3],
    ret: u64,
    tls: u64,
    gp: [u64; NREGS],
}

impl<const S: bool> Regs<S> {
    fn new() -> Self {
        let mut gp = [0; NREGS];
        for (i, r) in gp.iter_mut().enumerate() {
            *r = 0x1000 + i as u64;
        }
        Self { sp: STACK, pc: 0x40_0000, ra: 0, args: [0; 3], ret: 0, tls: 0, gp }
    }
}

impl<const S: bool> UserRegs for Regs<S> {
    const RED_ZONE: u64 = if S { 128 } else { 0 };
    const RET_ON_STACK: bool = S;

    fn user_sp(&self) -> u64 {
        self.sp
    }
    fn set_user_sp(&mut self, sp: u64) {
        self.sp = sp;
    }
    fn set_ret(&mut self, v: u64) {
        self.ret = v;
    }
    fn set_tls(&mut self, tls: u64) {
        self.tls = tls;
    }
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

fn callt(p: &Process, th: &Thread, sys: Sys, args: &[u64]) -> i64 {
    let mut a = [0; 6];
    a[..args.len()].copy_from_slice(args);
    match dispatch_as(p, th, sys.number(), a) {
        Outcome::Return(v) => v,
        o => panic!("unexpected {o:?}"),
    }
}

/// Installs `act` for `sig` with `rt_sigaction`, through a user buffer.
fn sigaction(p: &Process, sig: u8, act: SigAction) -> i64 {
    let words = if cfg!(target_arch = "x86_64") {
        alloc::vec![act.handler, act.flags, act.restorer, act.mask]
    } else {
        alloc::vec![act.handler, act.flags, act.mask]
    };
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    put(p, DATA + 0x800, &bytes);
    call(p, Sys::RtSigaction, &[sig as u64, DATA + 0x800, 0, 8])
}

fn handler(flags: u64, mask: u64) -> SigAction {
    SigAction { handler: HANDLER, flags, restorer: 0, mask }
}

fn bit(sig: u8) -> u64 {
    1 << (sig - 1)
}

#[test]
fn default_actions_terminate_or_ignore() {
    let (p, _) = process("sig-default");
    let th = p.leader();
    let mut regs = Regs::<true>::new();
    // SIGCHLD, SIGURG and SIGCONT are discarded when sent.
    for s in [SIGCHLD, SIGURG, SIGCONT, SIGWINCH] {
        assert_eq!(call(&p, Sys::Kill, &[p.pid().0 as u64, s as u64]), 0);
    }
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(call(&p, Sys::Kill, &[p.pid().0 as u64, 0]), 0, "signal 0 only checks");
    assert_eq!(call(&p, Sys::Kill, &[p.pid().0 as u64, 65]), EINVAL);
    assert_eq!(call(&p, Sys::Kill, &[9999, SIGTERM as u64]), ESRCH);

    // An explicitly ignored SIGTERM is dropped; a default one ends the process.
    assert_eq!(sigaction(&p, SIGTERM, SigAction { handler: SIG_IGN, ..Default::default() }), 0);
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGTERM as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(sigaction(&p, SIGTERM, SigAction::default()), 0);
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGTERM as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), Some(ExitStatus::Signal(15)));
    assert_eq!(call(&p, Sys::Kill, &[p.pid().0 as u64, SIGKILL as u64]), 0);

    // SIGKILL and SIGSTOP cannot be caught.
    assert_eq!(sigaction(&p, SIGKILL, handler(0, 0)), EINVAL);
    assert_eq!(sigaction(&p, SIGSTOP, SigAction { handler: SIG_IGN, ..Default::default() }), EINVAL);
    assert_eq!(call(&p, Sys::RtSigaction, &[0, 0, 0, 8]), EINVAL);
    assert_eq!(call(&p, Sys::RtSigaction, &[SIGUSR1 as u64, 0, 0, 4]), EINVAL);
}

#[test]
fn blocked_signals_stay_pending_until_unblocked() {
    let (p, _) = process("sig-mask");
    let th = p.leader();
    let mut regs = Regs::<true>::new();
    assert_eq!(sigaction(&p, SIGUSR1, handler(0, 0)), 0);
    put(&p, DATA + 0x100, &(bit(SIGUSR1) | bit(SIGKILL)).to_ne_bytes());
    assert_eq!(call(&p, Sys::RtSigprocmask, &[0, DATA + 0x100, DATA + 0x108, 8]), 0);
    assert_eq!(get(&p, DATA + 0x108, 8), 0u64.to_ne_bytes());
    assert_eq!(th.signal_mask(), bit(SIGUSR1), "SIGKILL cannot be blocked");

    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(regs.pc, 0x40_0000, "blocked: no handler yet");
    assert_eq!(call(&p, Sys::RtSigpending, &[DATA + 0x110, 8]), 0);
    assert_eq!(get(&p, DATA + 0x110, 8), bit(SIGUSR1).to_ne_bytes());

    assert_eq!(call(&p, Sys::RtSigprocmask, &[1, DATA + 0x100, 0, 8]), 0);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(regs.pc, HANDLER);
    assert_eq!(call(&p, Sys::RtSigprocmask, &[7, DATA + 0x100, 0, 8]), EINVAL);
}

fn handler_runs_and_returns<const S: bool>() {
    let (p, _) = process("sig-handler");
    let th = p.leader();
    let mut regs = Regs::<S>::new();
    assert_eq!(sigaction(&p, SIGUSR1, handler(sa::SIGINFO, bit(SIGUSR2))), 0);
    // The kernel maps a return trampoline in the mmap area.
    let mut old = [0u8; 32];
    assert_eq!(call(&p, Sys::RtSigaction, &[SIGUSR1 as u64, 0, DATA + 0x900, 8]), 0);
    p.memory().read(DATA + 0x900, &mut old).unwrap();
    assert_eq!(u64::from_ne_bytes(old[..8].try_into().unwrap()), HANDLER, "the old action reads back");

    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(regs.pc, HANDLER);
    let base = regs.args[1];
    assert_eq!(regs.args[0], SIGUSR1 as u64);
    assert_eq!(regs.args[2], base + 128);
    assert_eq!(base % 16, 0);
    assert!(base < STACK - if S { 128 } else { 0 }, "below the red zone");
    assert_eq!(regs.sp, if S { base - 8 } else { base });
    assert_eq!(th.signal_mask(), bit(SIGUSR1) | bit(SIGUSR2), "the signal and the action's mask are blocked");
    let siginfo = get(&p, base, 24);
    assert_eq!(i32::from_ne_bytes(siginfo[..4].try_into().unwrap()), SIGUSR1 as i32);
    assert_eq!(u64::from_ne_bytes(siginfo[16..24].try_into().unwrap()), p.pid().0 as u64, "si_pid");
    let tramp = if S { word(&p, base - 8) } else { regs.ra };
    assert!((0x100_0000..0x110_0000).contains(&tramp), "the return address is the trampoline in the mmap area");
}

#[test]
fn a_handler_runs_on_a_signal_frame() {
    handler_runs_and_returns::<true>();
    handler_runs_and_returns::<false>();
}

#[test]
fn sigreturn_restores_registers_and_mask() {
    let (p, _) = process("sig-return");
    let th = p.leader();
    let mut regs = Regs::<true>::new();
    let before = regs.save_user();
    assert_eq!(sigaction(&p, SIGUSR1, handler(0, 0)), 0);
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    let tramp = regs.ra;
    assert_eq!(get(&p, tramp, 1).len(), 1, "the trampoline is readable");
    assert!((0x100_0000..0x110_0000).contains(&tramp), "it lives in the mmap area");

    // A second SIGUSR1 while the handler runs stays pending...
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(regs.pc, HANDLER);
    // ...clobber what the handler may, return through the trampoline...
    regs.gp[5] = 0xdead;
    regs.sp += 8;
    let frame_sp = regs.sp;
    assert_eq!(signal::sigreturn(&p, &th, &mut regs), None);
    // ...and the interrupted code sees its registers again, with the old mask.
    assert_eq!(regs.save_user(), before);
    assert_eq!(regs.sp, STACK);
    assert_eq!(th.signal_mask(), 0);
    assert_ne!(frame_sp, STACK);
    // The pending one is delivered once the mask allows it.
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(regs.pc, HANDLER);
    assert_eq!(th.signal_mask(), bit(SIGUSR1));

    // A frame that cannot be read ends the program.
    regs.sp = 0x7000_0000;
    assert_eq!(signal::sigreturn(&p, &th, &mut regs), Some(ExitStatus::Signal(11)));
}

#[test]
fn resethand_and_nodefer() {
    let (p, _) = process("sig-flags");
    let th = p.leader();
    let mut regs = Regs::<false>::new();
    assert_eq!(sigaction(&p, SIGUSR1, handler(sa::RESETHAND | sa::NODEFER, 0)), 0);
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(th.signal_mask(), 0, "NODEFER");
    // Back to the default, which ends the process.
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), Some(ExitStatus::Signal(10)));
}

#[test]
fn a_handler_without_a_stack_ends_the_process() {
    let (p, _) = process("sig-badstack");
    let th = p.leader();
    let mut regs = Regs::<true>::new();
    regs.sp = 0x10;
    assert_eq!(sigaction(&p, SIGUSR1, handler(0, 0)), 0);
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), Some(ExitStatus::Signal(11)));
}

#[test]
fn faults_raise_sigsegv_with_the_address() {
    let (p, _) = process("sig-fault");
    let th = p.leader();
    let mut regs = Regs::<true>::new();
    // No handler: the process ends.
    assert_eq!(signal::fault_to(&p, &th, &mut regs, SIGSEGV, 0xbad0), Some(ExitStatus::Signal(11)));

    let (p, _) = process("sig-fault2");
    let th = p.leader();
    assert_eq!(sigaction(&p, SIGSEGV, handler(0, 0)), 0);
    let mut regs = Regs::<true>::new();
    assert_eq!(signal::fault_to(&p, &th, &mut regs, SIGSEGV, 0xbad0), None);
    assert_eq!(regs.pc, HANDLER);
    let info = get(&p, regs.args[1], 24);
    assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), 1, "SEGV_MAPERR");
    assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), 0xbad0, "si_addr");
    // Faulting again inside the handler (SIGSEGV is blocked there) is fatal.
    assert_eq!(signal::fault_to(&p, &th, &mut regs, SIGSEGV, 0xbad8), Some(ExitStatus::Signal(11)));

    // An ignored SIGSEGV does not let the program run on.
    let (p, _) = process("sig-fault3");
    let th = p.leader();
    assert_eq!(sigaction(&p, SIGSEGV, SigAction { handler: SIG_IGN, ..Default::default() }), 0);
    let mut regs = Regs::<true>::new();
    assert_eq!(signal::fault_to(&p, &th, &mut regs, SIGSEGV, 0), Some(ExitStatus::Signal(11)));
}

#[test]
fn sigchld_reaches_the_parent_when_a_child_exits() {
    platform();
    let (p, _) = process("sig-chld");
    let th = p.leader();
    let mut regs = Regs::<true>::new();
    assert_eq!(sigaction(&p, SIGCHLD, handler(0, 0)), 0);
    let Outcome::Fork { child, .. } = dispatch(&p, Sys::Fork.number(), [0; 6]) else { panic!("no fork") };
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(regs.pc, 0x40_0000, "nothing yet");
    let c = Process::find(child).unwrap();
    assert_eq!(c.signals_inherited_handler(SIGCHLD), HANDLER, "the child inherits dispositions");
    c.set_exited(ExitStatus::Code(0));
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!((regs.pc, regs.args[0]), (HANDLER, SIGCHLD as u64));
    let info = get(&p, regs.args[1], 24);
    assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), child.0 as u64, "si_pid is the child");
    assert_eq!(call(&p, Sys::Wait4, &[child.0 as u64, 0, 0, 0]), child.0 as i64);
}

impl Process {
    fn signals_inherited_handler(&self, sig: u8) -> u64 {
        self.signals.action_for_test(sig).handler
    }
}

fn clone_flags() -> u64 {
    // VM | FS | FILES | SIGHAND | THREAD | SYSVSEM | SETTLS | PARENT_SETTID | CHILD_CLEARTID
    0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x10_0000 | 0x20_0000
}

fn clone_thread(p: &Process, th: &Thread, flags: u64, stack: u64, ptid: u64, ctid: u64, tls: u64) -> Outcome {
    let a = if cfg!(target_arch = "x86_64") {
        [flags, stack, ptid, ctid, tls, 0]
    } else {
        [flags, stack, ptid, tls, ctid, 0]
    };
    dispatch_as(p, th, Sys::Clone.number(), a)
}

#[test]
fn clone_makes_threads_with_their_own_ids() {
    platform();
    let (p, _) = process("threads");
    let main = p.leader();
    assert_eq!(callt(&p, &main, Sys::Gettid, &[]), p.pid().0 as i64);
    let Outcome::Thread { tid, stack, tls } =
        clone_thread(&p, &main, clone_flags(), STACK, DATA + 0x10, DATA + 0x20, 0x5000)
    else {
        panic!("no thread")
    };
    assert_eq!((stack, tls), (STACK, 0x5000));
    assert_ne!(tid, p.pid().0);
    assert_eq!(get(&p, DATA + 0x10, 4), tid.to_ne_bytes(), "CLONE_PARENT_SETTID");
    assert_eq!(p.threads(), alloc::vec![p.pid().0, tid]);
    let th = p.group.find(tid).unwrap();
    assert_eq!(th.tls(), 0x5000);
    assert_eq!(callt(&p, &th, Sys::Gettid, &[]), tid as i64);
    assert_eq!(callt(&p, &th, Sys::Getpid, &[]), p.pid().0 as i64, "same process");
    assert_eq!(thread::find(tid).map(|(q, t)| (q.pid(), t.tid())), Some((p.pid(), tid)));

    // Bad combinations.
    for flags in [0x100 | 0x1_0000, clone_flags() & !0x800, clone_flags() | 17, clone_flags() | 0x4000_0000] {
        let Outcome::Return(r) = clone_thread(&p, &main, flags, STACK, DATA + 0x10, DATA + 0x20, 0) else { panic!() };
        assert_eq!(r, EINVAL, "{flags:#x}");
    }
    let Outcome::Return(r) = clone_thread(&p, &main, clone_flags(), 0, DATA + 0x10, DATA + 0x20, 0) else { panic!() };
    assert_eq!(r, EINVAL, "a thread needs a stack");
    let Outcome::Return(r) = clone_thread(&p, &main, clone_flags(), STACK, 0xdead_0000, DATA + 0x20, 0) else {
        panic!()
    };
    assert_eq!(r, -(Errno::EFAULT.0 as i64));
    assert_eq!(p.threads().len(), 2, "failed clones leave nothing behind");

    // A thread inherits the signal mask; the others' are separate.
    put(&p, DATA + 0x100, &bit(SIGUSR2).to_ne_bytes());
    callt(&p, &main, Sys::RtSigprocmask, &[0, DATA + 0x100, 0, 8]);
    let Outcome::Thread { tid: t2, .. } =
        clone_thread(&p, &main, clone_flags(), STACK - 0x400, DATA + 0x10, DATA + 0x24, 0)
    else {
        panic!()
    };
    assert_eq!(p.group.find(t2).unwrap().signal_mask(), bit(SIGUSR2));
    assert_eq!(th.signal_mask(), 0);
}

#[test]
fn a_thread_exit_ends_only_the_thread_and_wakes_its_joiner() {
    platform();
    let (p, _) = process("thread-exit");
    let main = p.leader();
    let ctid = DATA + 0x20;
    let Outcome::Thread { tid, .. } = clone_thread(&p, &main, clone_flags(), STACK, DATA + 0x10, ctid, 0) else {
        panic!()
    };
    let th = p.group.find(tid).unwrap();
    // pthread_join: wait while *ctid == tid. (CLONE_CHILD_CLEARTID only
    // clears; the value is the tid because the creator stored it.)
    put(&p, ctid, &tid.to_ne_bytes());
    let w = futex::enqueue(&p, ctid, tid).unwrap();
    assert_eq!(callt(&p, &main, Sys::Futex, &[ctid, 128, tid as u64 + 1, 0]), EAGAIN, "value changed: no wait");

    thread::exit_thread(&p, &th, ExitStatus::Code(3));
    assert!(w.woken.load(Ordering::SeqCst), "the exiting thread woke the joiner");
    assert_eq!(get(&p, ctid, 4), 0u32.to_ne_bytes(), "CLONE_CHILD_CLEARTID");
    assert_eq!(p.exit_status(), None, "the process lives on");
    assert_eq!(p.threads(), alloc::vec![p.pid().0]);
    assert!(thread::find(tid).is_none());
    assert_eq!(call(&p, Sys::Kill, &[p.pid().0 as u64, 0]), 0);
    assert_eq!(callt(&p, &main, Sys::Tkill, &[tid as u64, 0]), ESRCH, "gone");

    // The process ends with its last thread.
    thread::exit_thread(&p, &main, ExitStatus::Code(0));
    assert_eq!(p.exit_status(), Some(ExitStatus::Code(0)));
}

#[test]
fn exit_group_and_fatal_signals_end_every_thread() {
    platform();
    let (p, _) = process("exit-group");
    let main = p.leader();
    let Outcome::Thread { tid, .. } = clone_thread(&p, &main, clone_flags(), STACK, DATA + 0x10, DATA + 0x20, 0) else {
        panic!()
    };
    let th = p.group.find(tid).unwrap();
    let mut regs = Regs::<true>::new();
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    // The worker calls exit_group(5): the leader sees it at its next trap.
    assert_eq!(dispatch_as(&p, &th, Sys::ExitGroup.number(), [5, 0, 0, 0, 0, 0]), Outcome::Exit(ExitStatus::Code(5)));
    assert_eq!(signal::deliver_to(&p, &main, &mut regs), Some(ExitStatus::Code(5)));
    assert!(signal::interrupted(&p, &main), "blocked calls give up");
    thread::exit_thread(&p, &th, ExitStatus::Code(5));
    assert_eq!(p.exit_status(), None);
    thread::exit_thread(&p, &main, ExitStatus::Code(5));
    assert_eq!(p.exit_status(), Some(ExitStatus::Code(5)));

    // A plain exit by a thread does not.
    let (p, _) = process("exit-one");
    let main = p.leader();
    let Outcome::Thread { tid, .. } = clone_thread(&p, &main, clone_flags(), STACK, DATA + 0x10, DATA + 0x20, 0) else {
        panic!()
    };
    let th = p.group.find(tid).unwrap();
    assert_eq!(dispatch_as(&p, &th, Sys::Exit.number(), [1, 0, 0, 0, 0, 0]), Outcome::Exit(ExitStatus::Code(1)));
    thread::exit_thread(&p, &th, ExitStatus::Code(1));
    assert_eq!(signal::deliver_to(&p, &main, &mut Regs::<true>::new()), None);
    assert_eq!(p.exit_status(), None);

    // A fatal signal anywhere takes the whole process: status is the signal.
    let (p, _) = process("fatal");
    let main = p.leader();
    let Outcome::Thread { tid, .. } = clone_thread(&p, &main, clone_flags(), STACK, DATA + 0x10, DATA + 0x20, 0) else {
        panic!()
    };
    assert_eq!(callt(&p, &main, Sys::Tkill, &[tid as u64, SIGTERM as u64]), 0);
    let th = p.group.find(tid).unwrap();
    assert_eq!(signal::deliver_to(&p, &main, &mut Regs::<true>::new()), None, "thread-directed: not the leader's");
    assert_eq!(signal::deliver_to(&p, &th, &mut Regs::<true>::new()), Some(ExitStatus::Signal(15)));
    assert_eq!(signal::deliver_to(&p, &main, &mut Regs::<true>::new()), Some(ExitStatus::Signal(15)));
    thread::exit_thread(&p, &th, ExitStatus::Signal(15));
    thread::exit_thread(&p, &main, ExitStatus::Signal(15));
    assert_eq!(p.exit_status(), Some(ExitStatus::Signal(15)));
    assert_eq!(call(&p, Sys::Kill, &[p.pid().0 as u64, 0]), ESRCH, "zombies take no signals");
}

#[test]
fn process_directed_signals_go_to_a_thread_that_does_not_block_them() {
    platform();
    let (p, _) = process("directed");
    let main = p.leader();
    let Outcome::Thread { tid, .. } = clone_thread(&p, &main, clone_flags(), STACK, DATA + 0x10, DATA + 0x20, 0) else {
        panic!()
    };
    let th = p.group.find(tid).unwrap();
    assert_eq!(sigaction(&p, SIGUSR1, handler(0, 0)), 0);
    put(&p, DATA + 0x100, &bit(SIGUSR1).to_ne_bytes());
    callt(&p, &main, Sys::RtSigprocmask, &[0, DATA + 0x100, 0, 8]);
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    let mut regs = Regs::<true>::new();
    assert_eq!(signal::deliver_to(&p, &main, &mut regs), None);
    assert_eq!(regs.pc, 0x40_0000, "the leader blocks it");
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(regs.pc, HANDLER, "the other thread takes it");
    assert_eq!(callt(&p, &main, Sys::Tgkill, &[p.pid().0 as u64, tid as u64, SIGUSR1 as u64]), 0);
    assert_eq!(callt(&p, &main, Sys::Tgkill, &[p.pid().0 as u64 + 1000, tid as u64, 0]), ESRCH, "wrong group");
}

#[test]
fn futex_wait_and_wake() {
    let (p, _) = process("futex");
    let th = p.leader();
    let addr = DATA + 0x40;
    put(&p, addr, &7u32.to_ne_bytes());
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 0, 8, 0]), EAGAIN);
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr + 1, 0, 7, 0]), EINVAL, "unaligned");
    assert_eq!(callt(&p, &th, Sys::Futex, &[0xdead_0000, 0, 7, 0]), -(Errno::EFAULT.0 as i64));
    for pi in [6, 7, 8, 11, 12, 13] {
        assert_eq!(callt(&p, &th, Sys::Futex, &[addr, pi, 0, 0]), -(Errno::ENOSYS.0 as i64), "PI futex {pi}");
    }
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 9, 7, 0, 0, 0]), EINVAL, "an empty bitset");
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 10, 1, 0, 0, 0]), EINVAL, "an empty bitset");

    let a = futex::enqueue(&p, addr, 7).unwrap();
    let b = futex::enqueue(&p, addr, 7).unwrap();
    let other = futex::enqueue(&p, addr + 4, 0).unwrap();
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 1 | 128, 1, 0]), 1);
    assert!(a.woken.load(Ordering::SeqCst) && !b.woken.load(Ordering::SeqCst), "oldest first");
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 1, 100, 0]), 1);
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 1, 100, 0]), 0);
    assert!(b.woken.load(Ordering::SeqCst) && !other.woken.load(Ordering::SeqCst), "by address");
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr + 4, 1, 1, 0]), 1);

    // A pending handled signal interrupts a wait; an ignored one does not.
    assert_eq!(sigaction(&p, SIGUSR1, handler(0, 0)), 0);
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 0, 7, 0]), EINTR);
    assert!(futex::wake(p.pid(), addr, 10) == 0, "an interrupted waiter leaves the queue");
}

#[test]
fn exec_resets_handlers_but_not_ignores() {
    let (p, _) = process("exec-reset");
    assert_eq!(sigaction(&p, SIGUSR1, handler(0, 0)), 0);
    assert_eq!(sigaction(&p, SIGUSR2, SigAction { handler: SIG_IGN, ..Default::default() }), 0);
    signal::on_exec(&p);
    assert_eq!(p.signals.action_for_test(SIGUSR1).handler, 0);
    assert_eq!(p.signals.action_for_test(SIGUSR2).handler, SIG_IGN);
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR2 as u64]);
    assert_eq!(signal::deliver_to(&p, &p.leader(), &mut Regs::<true>::new()), None);
}

#[cfg(target_arch = "x86_64")]
#[test]
fn arch_prctl_sets_the_thread_pointer() {
    let (p, _) = process("tls");
    let th = p.leader();
    assert_eq!(callt(&p, &th, Sys::ArchPrctl, &[0x1002, 0x7000_1000]), 0);
    assert_eq!(callt(&p, &th, Sys::ArchPrctl, &[0x1003, DATA]), 0);
    assert_eq!(get(&p, DATA, 8), 0x7000_1000u64.to_ne_bytes());
    assert_eq!(callt(&p, &th, Sys::ArchPrctl, &[0x1002, 1 << 62]), -(Errno::EPERM.0 as i64));
    assert_eq!(callt(&p, &th, Sys::ArchPrctl, &[0x9999, 0]), EINVAL);
    assert_eq!(callt(&p, &th, Sys::SetTidAddress, &[DATA + 8]), p.pid().0 as i64);
}

#[test]
fn a_signal_frame_on_a_shared_stack_copies_the_page_first() {
    platform();
    let (p, frames) = process("sig-cow");
    let th = p.leader();
    put(&p, STACK - 0x100, b"parent stack");
    assert_eq!(sigaction(&p, SIGUSR1, handler(0, 0)), 0);
    let Outcome::Fork { child, .. } = dispatch(&p, Sys::Fork.number(), [0; 6]) else { panic!("no fork") };
    let c = Process::find(child).unwrap();
    let shared = frames.live();

    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    let mut regs = Regs::<true>::new();
    assert_eq!(signal::deliver_to(&p, &th, &mut regs), None);
    assert_eq!(regs.pc, HANDLER);
    assert_eq!(frames.live(), shared + 1, "writing the frame broke the sharing of the stack page");
    // The child's stack is untouched, and it can run a handler of its own.
    assert_eq!(get(&c, STACK - 0x100, 12), b"parent stack");
    assert_eq!(get(&c, regs.args[1], 4), [0; 4], "no siginfo in the child's copy");
    assert_eq!(get(&p, regs.args[1], 4), (SIGUSR1 as i32).to_ne_bytes());
    call(&c, Sys::Kill, &[c.pid().0 as u64, SIGUSR1 as u64]);
    let mut cregs = Regs::<true>::new();
    assert_eq!(signal::deliver_to(&c, &c.leader(), &mut cregs), None);
    assert_eq!(cregs.pc, HANDLER, "the child inherited the handler");
    assert_eq!(get(&c, cregs.args[1], 4), (SIGUSR1 as i32).to_ne_bytes());
}

fn futex_call(p: &Process, th: &Thread, a: [u64; 6]) -> i64 {
    callt(p, th, Sys::Futex, &a)
}

#[test]
fn futex_bitsets_requeue_and_wake_op() {
    let (p, _) = process("futex-ops");
    let th = p.leader();
    let (a1, a2) = (DATA + 0x400, DATA + 0x404);
    put(&p, a1, &1u32.to_ne_bytes());
    put(&p, a2, &5u32.to_ne_bytes());

    // Bitsets: a wake only reaches waiters that share a bit.
    let w = |addr, bits| {
        let cur = u32::from_ne_bytes(get(&p, addr, 4).try_into().unwrap());
        futex::enqueue_bits(&p, addr, cur, bits).unwrap()
    };
    let (x, y) = (w(a1, 0b01), w(a1, 0b10));
    assert_eq!(futex_call(&p, &th, [a1, 10, 10, 0, 0, 0b100]), 0);
    assert_eq!(futex_call(&p, &th, [a1, 10 | 128, 10, 0, 0, 0b10]), 1);
    assert!(y.woken.load(Ordering::SeqCst) && !x.woken.load(Ordering::SeqCst));
    assert_eq!(futex_call(&p, &th, [a1, 1, 10, 0, 0, 0]), 1);

    // CMP_REQUEUE: one woken, the rest move to a2.
    let ws: alloc::vec::Vec<_> = (0..4).map(|_| w(a1, u32::MAX)).collect();
    assert_eq!(futex_call(&p, &th, [a1, 4, 1, 2, a2, 9]), EAGAIN, "the word is not 9");
    assert_eq!(futex_call(&p, &th, [a1, 4, 1, 2, a2 + 1, 1]), EINVAL, "unaligned");
    assert_eq!(futex_call(&p, &th, [a1, 4, 1, 2, a2, 1]), 3, "1 woken + 2 requeued");
    assert!(ws[0].woken.load(Ordering::SeqCst) && !ws[1].woken.load(Ordering::SeqCst));
    assert_eq!(futex_call(&p, &th, [a1, 1, 10, 0, 0, 0]), 1, "one stayed behind");
    assert_eq!(futex_call(&p, &th, [a2, 1, 1, 0, 0, 0]), 1, "wakes a requeued one");
    assert_eq!(futex_call(&p, &th, [a2, 3, 0, 10, a1, 0]), 1, "REQUEUE moves the last one back");
    assert_eq!(futex_call(&p, &th, [a1, 1, 10, 0, 0, 0]), 1);

    // WAKE_OP: *a2 += 1 and wake a1; if the old value was 5, wake a2 too.
    let (p1, p2) = (w(a1, u32::MAX), w(a2, u32::MAX));
    let val3 = (1 << 28) | (1 << 12) | 5;
    assert_eq!(futex_call(&p, &th, [a1, 5, 1, 1, a2, val3]), 2);
    assert!(p1.woken.load(Ordering::SeqCst) && p2.woken.load(Ordering::SeqCst));
    assert_eq!(get(&p, a2, 4), 6u32.to_ne_bytes());
    let p3 = w(a2, u32::MAX);
    assert_eq!(futex_call(&p, &th, [a1, 5, 1, 1, a2, val3]), 0, "the old value is 6 now");
    assert!(!p3.woken.load(Ordering::SeqCst));
    // OPARG_SHIFT | OR 1<<3, compare >= 6 (always true for the old value 7).
    let val3 = (1 << 31) | (2 << 28) | (5 << 24) | (3 << 12) | 6;
    assert_eq!(futex_call(&p, &th, [a1, 5, 0, 1, a2, val3]), 1);
    assert_eq!(get(&p, a2, 4), 15u32.to_ne_bytes());
    assert_eq!(futex_call(&p, &th, [a1, 5, 0, 1, a2, 7 << 28]), -(Errno::ENOSYS.0 as i64), "bad op");
}

#[test]
fn futex_timeouts_use_the_kernel_clock() {
    use core::sync::atomic::AtomicU64;
    static NOW: AtomicU64 = AtomicU64::new(5_000);
    let (p, _) = process("futex-time");
    let th = p.leader();
    let addr = DATA + 0x440;
    put(&p, addr, &1u32.to_ne_bytes());
    futex::set_clock(|| NOW.load(Ordering::SeqCst));
    let ts = |sec: i64, nsec: i64| [sec.to_ne_bytes(), nsec.to_ne_bytes()].concat();
    put(&p, DATA + 0x460, &ts(0, 1_000));
    put(&p, DATA + 0x480, &ts(0, 1_000_000_000));
    put(&p, DATA + 0x4a0, &ts(-1, 0));
    // Absolute deadline (FUTEX_WAIT_BITSET) already behind the clock.
    assert_eq!(futex_call(&p, &th, [addr, 9 | 128, 1, DATA + 0x460, 0, u32::MAX as u64]), -(Errno::ETIMEDOUT.0 as i64));
    let einval = -(Errno::EINVAL.0 as i64);
    assert_eq!(futex_call(&p, &th, [addr, 0, 1, DATA + 0x480, 0, 0]), einval, "tv_nsec out of range");
    assert_eq!(futex_call(&p, &th, [addr, 0, 1, DATA + 0x4a0, 0, 0]), einval, "negative time");
    assert_eq!(futex_call(&p, &th, [addr, 0, 2, DATA + 0x460, 0, 0]), EAGAIN, "the value is checked first");
}

#[test]
fn robust_lists_mark_owned_futexes_when_a_thread_dies() {
    platform();
    let (p, _) = process("robust");
    let main = p.leader();
    let Outcome::Thread { tid, .. } = clone_thread(&p, &main, clone_flags(), STACK, DATA + 0x10, DATA + 0x20, 0) else {
        panic!()
    };
    let th = p.group.find(tid).unwrap();
    let head = DATA + 0x500;
    let (e1, e2, pending) = (DATA + 0x540, DATA + 0x560, DATA + 0x580);
    // The futex word sits 8 bytes after its list entry.
    let word = |e: u64| e + 8;
    let q = |v: u64| v.to_ne_bytes();
    put(&p, head, &q(e1));
    put(&p, head + 8, &8u64.to_ne_bytes());
    put(&p, head + 16, &q(pending));
    put(&p, e1, &q(e2));
    put(&p, e2, &q(head));
    put(&p, word(e1), &(tid | 0x8000_0000).to_ne_bytes());
    put(&p, word(e2), &(main.tid() | 0x8000_0000).to_ne_bytes());
    put(&p, word(pending), &tid.to_ne_bytes());

    assert_eq!(callt(&p, &th, Sys::SetRobustList, &[head, 16]), EINVAL, "wrong size");
    assert_eq!(callt(&p, &th, Sys::SetRobustList, &[head, 24]), 0);
    assert_eq!(callt(&p, &th, Sys::GetRobustList, &[0, DATA + 0x600, DATA + 0x608]), 0);
    assert_eq!(get(&p, DATA + 0x600, 8), head.to_ne_bytes());
    assert_eq!(get(&p, DATA + 0x608, 8), 24u64.to_ne_bytes());
    assert_eq!(callt(&p, &main, Sys::GetRobustList, &[tid as u64, DATA + 0x600, DATA + 0x608]), 0);
    assert_eq!(callt(&p, &main, Sys::GetRobustList, &[tid as u64 + 77, DATA + 0x600, DATA + 0x608]), ESRCH);

    let w = futex::enqueue(&p, word(e1), tid | 0x8000_0000).unwrap();
    thread::exit_thread(&p, &th, ExitStatus::Code(0));
    assert!(w.woken.load(Ordering::SeqCst), "a waiter on an owned futex is woken");
    assert_eq!(get(&p, word(e1), 4), 0xc000_0000u32.to_ne_bytes(), "OWNER_DIED, WAITERS kept");
    assert_eq!(get(&p, word(e2), 4), (main.tid() | 0x8000_0000).to_ne_bytes(), "someone else's is left alone");
    assert_eq!(get(&p, word(pending), 4), 0x4000_0000u32.to_ne_bytes(), "the pending entry too");
}

#[test]
fn exec_from_a_non_leader_thread_ends_the_others_and_takes_over_the_pid() {
    platform();
    let (p, _) = process("exec-thread");
    let main = p.leader();
    let flags = clone_flags();
    let Outcome::Thread { tid: t1, .. } = clone_thread(&p, &main, flags, STACK, DATA + 0x10, DATA + 0x20, 0) else {
        panic!()
    };
    let Outcome::Thread { tid: t2, .. } = clone_thread(&p, &main, flags, STACK - 0x400, DATA + 0x10, DATA + 0x24, 0)
    else {
        panic!()
    };
    let (th1, th2) = (p.group.find(t1).unwrap(), p.group.find(t2).unwrap());
    assert!(thread::doom_others(&p, &th1));
    assert!(main.doomed.load(Ordering::SeqCst) && th2.doomed.load(Ordering::SeqCst));
    assert!(!th1.doomed.load(Ordering::SeqCst));
    assert!(!thread::doom_others(&p, &th2), "a doomed thread cannot exec");
    let mut regs = Regs::<true>::new();
    let status = signal::deliver_to(&p, &main, &mut regs).expect("the doomed leader stops");
    thread::exit_thread(&p, &main, status);
    let status = signal::deliver_to(&p, &th2, &mut regs).expect("the doomed thread stops");
    thread::exit_thread(&p, &th2, status);
    assert_eq!(p.exit_status(), None, "the exec'ing thread keeps the process alive");
    assert_eq!(p.group.live(), 1);

    thread::promote(&p, &th1);
    assert_eq!(th1.tid(), p.pid().0, "it takes the process id");
    assert_eq!(p.threads(), alloc::vec![p.pid().0]);
    assert_eq!(p.leader().tid(), p.pid().0);
    assert_eq!(callt(&p, &th1, Sys::Gettid, &[]), p.pid().0 as i64);
    assert!(thread::find(t1).is_none(), "the old thread id is gone");
    assert_eq!(thread::find(p.pid().0).map(|(_, t)| t.tid()), Some(p.pid().0));
    thread::exit_thread(&p, &th1, ExitStatus::Code(0));
    assert_eq!(p.exit_status(), Some(ExitStatus::Code(0)));
}

#[test]
fn wait4_sees_a_process_only_when_its_last_thread_is_gone() {
    platform();
    let (parent, _) = process("wait-parent");
    let pmain = parent.leader();
    let Outcome::Fork { child, .. } = dispatch_as(&parent, &pmain, Sys::Fork.number(), [0; 6]) else { panic!() };
    let c = Process::find(child).expect("a child");
    let cmain = c.leader();
    let Outcome::Thread { tid, .. } = clone_thread(&c, &cmain, clone_flags(), STACK, DATA + 0x10, DATA + 0x20, 0)
    else {
        panic!()
    };
    let th = c.group.find(tid).unwrap();
    // The leader exits first (pthread_exit from main): not a zombie yet.
    thread::exit_thread(&c, &cmain, ExitStatus::Code(1));
    assert_eq!(callt(&parent, &pmain, Sys::Wait4, &[child.0 as u64, 0, 1, 0]), 0, "WNOHANG: still running");
    assert_eq!(callt(&parent, &pmain, Sys::Wait4, &[tid as u64, 0, 1, 0]), -(Errno::ECHILD.0 as i64), "not a child");
    thread::exit_thread(&c, &th, ExitStatus::Code(2));
    assert_eq!(callt(&parent, &pmain, Sys::Wait4, &[child.0 as u64, DATA + 0x700, 1, 0]), child.0 as i64);
    assert_eq!(get(&parent, DATA + 0x700, 4), (2i32 << 8).to_ne_bytes(), "the last thread's status");
}
