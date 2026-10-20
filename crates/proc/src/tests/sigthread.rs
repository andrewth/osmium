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

    // exec needs a single thread.
    put(&p, DATA + 0x200, b"/bin/prog\0");
    assert_eq!(callt(&p, &main, Sys::Execve, &[DATA + 0x200, 0, 0]), -(Errno::EBUSY.0 as i64));
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
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 0, 7, DATA]), -(Errno::ENOSYS.0 as i64), "no timeouts yet");
    assert_eq!(callt(&p, &th, Sys::Futex, &[0xdead_0000, 0, 7, 0]), -(Errno::EFAULT.0 as i64));
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 3, 7, 0]), -(Errno::ENOSYS.0 as i64), "requeue");

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
