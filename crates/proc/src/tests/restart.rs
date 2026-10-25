#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Restartable system calls (`SA_RESTART`, `restart_syscall`) and
//! priority-inheritance futexes.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use osmium_sched::{Task, TaskBuilder};

use super::blocked::{become_cpu, block_in};
use super::sigthread::{HANDLER, Regs, STACK, bit, callt, clone_flags, clone_thread, handler, sigaction};
use super::*;
use crate::restart::{self, Block};
use crate::signal::{self, SigAction, sa, sig::*};
use crate::thread::Thread;

const EINTR: i64 = -(Errno::EINTR.0 as i64);
const EAGAIN: i64 = -(Errno::EAGAIN.0 as i64);
const EPERM: i64 = -(Errno::EPERM.0 as i64);
const EDEADLK: i64 = -35;

const LOCK_PI: u64 = 6;
const UNLOCK_PI: u64 = 7;
const TRYLOCK_PI: u64 = 8;
const WAITERS: u32 = 0x8000_0000;
const OWNER_DIED: u32 = 0x4000_0000;

const READ_ARGS: [u64; 6] = [3, DATA, 8, 0, 0, 0];

fn kill_self(p: &Process, sig: u8) {
    assert_eq!(call(p, Sys::Kill, &[p.pid().0 as u64, sig as u64]), 0);
}

/// Runs `deliver_with` for a `read` that failed with `EINTR`, as `handle` does.
fn deliver_read<const S: bool>(p: &Process, th: &Thread, regs: &mut Regs<S>) -> Option<crate::ExitStatus> {
    let plan = restart::plan(th, Sys::Read.number(), &READ_ARGS);
    signal::deliver_with(p, th, regs, plan)
}

fn restarts_after_handler<const S: bool>() {
    let width = if S { 2 } else { 4 };
    for (flags, restarts) in [(sa::RESTART, true), (0, false)] {
        let (p, _) = process("sa-restart");
        let th = p.leader();
        assert_eq!(sigaction(&p, SIGUSR1, handler(flags, 0)), 0);
        let mut regs = Regs::<S>::new();
        let pc = regs.pc;
        kill_self(&p, SIGUSR1);
        assert_eq!(deliver_read(&p, &th, &mut regs), None);
        assert_eq!(regs.pc, HANDLER, "the handler runs");
        assert_eq!(regs.restarted, restarts.then(|| (Sys::Read.number(), 3)), "flags {flags:#x}");
        // Returning from the handler lands on the call again, or after it with EINTR.
        if S {
            regs.sp += 8; // the trampoline's return pops the address
        }
        assert_eq!(signal::sigreturn(&p, &th, &mut regs), None);
        assert_eq!(regs.pc, if restarts { pc - width } else { pc });
    }
}

#[test]
fn sa_restart_reissues_the_call_after_the_handler() {
    restarts_after_handler::<true>();
    restarts_after_handler::<false>();
}

#[test]
fn a_call_restarts_when_no_handler_runs() {
    let (p, _) = process("restart-nohandler");
    let th = p.leader();
    let mut regs = Regs::<true>::new();
    // The signal that interrupted the call was ignored or taken elsewhere.
    assert_eq!(deliver_read(&p, &th, &mut regs), None);
    assert_eq!(regs.restarted, Some((Sys::Read.number(), 3)));
    assert_eq!(regs.pc, 0x40_0000 - 2);

    // A signal that is ignored when it is taken does not stop the restart.
    let mut regs = Regs::<true>::new();
    kill_self(&p, SIGCHLD);
    assert_eq!(deliver_read(&p, &th, &mut regs), None);
    assert_eq!(regs.restarted, Some((Sys::Read.number(), 3)));
}

#[test]
fn calls_that_never_restart_are_not_planned() {
    let (p, _) = process("restart-never");
    let th = p.leader();
    for sys in [Sys::Ppoll, Sys::Pselect6, Sys::EpollPwait, Sys::Connect, Sys::Getpid, Sys::Close] {
        assert!(restart::plan(&th, sys.number(), &READ_ARGS).is_none(), "{sys:?}");
    }
    for sys in [Sys::Read, Sys::Write, Sys::Readv, Sys::Writev, Sys::Wait4, Sys::Accept, Sys::Recvfrom, Sys::Sendmsg] {
        assert!(restart::plan(&th, sys.number(), &READ_ARGS).is_some(), "{sys:?}");
    }
    // A futex wait only plans a restart once a wait was interrupted.
    let wait = [DATA, 0, 0, 0, 0, 0];
    assert!(restart::plan(&th, Sys::Futex.number(), &wait).is_none());
    // Fatal signals are not softened by a restart.
    let mut regs = Regs::<true>::new();
    kill_self(&p, SIGTERM);
    assert_eq!(deliver_read(&p, &th, &mut regs), Some(crate::ExitStatus::Signal(SIGTERM)));
    assert_eq!(regs.restarted, None);
}

#[test]
fn futex_wait_continues_through_restart_syscall() {
    let (p, _) = process("restart-futex");
    let th = p.leader();
    let addr = DATA + 0x40;
    put(&p, addr, &7u32.to_ne_bytes());
    assert_eq!(sigaction(&p, SIGUSR1, handler(sa::RESTART, 0)), 0);
    kill_self(&p, SIGUSR1);
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 0, 7, 0]), EINTR);
    assert_eq!(
        *th.ext.restart.lock(),
        Some(Block::FutexWait { uaddr: addr, val: 7, bitset: u32::MAX, deadline: None })
    );

    // With a handler, even SA_RESTART gives EINTR: the wait is a restart-block call.
    let wait = [addr, 0, 7, 0, 0, 0];
    let mut regs = Regs::<true>::new();
    let plan = restart::plan(&th, Sys::Futex.number(), &wait);
    assert_eq!(signal::deliver_with(&p, &th, &mut regs, plan), None);
    assert_eq!(regs.pc, HANDLER);
    assert_eq!(regs.restarted, None);
    assert_eq!(*th.ext.restart.lock(), None, "the handler ends the restart block");
    regs.sp += 8;
    assert_eq!(signal::sigreturn(&p, &th, &mut regs), None);

    // Without a handler it goes through restart_syscall.
    kill_self(&p, SIGUSR1);
    assert_eq!(callt(&p, &th, Sys::Futex, &[addr, 0, 7, 0]), EINTR);
    let mut regs = Regs::<true>::new();
    // Taken by nobody: block the signal so that no handler runs.
    put(&p, DATA + 0x100, &bit(SIGUSR1).to_ne_bytes());
    assert_eq!(callt(&p, &th, Sys::RtSigprocmask, &[0, DATA + 0x100, 0, 8]), 0);
    let plan = restart::plan(&th, Sys::Futex.number(), &wait);
    assert_eq!(signal::deliver_with(&p, &th, &mut regs, plan), None);
    assert_eq!(regs.restarted, Some((Sys::RestartSyscall.number(), addr)));

    // restart_syscall waits again, with the same value check...
    put(&p, addr, &8u32.to_ne_bytes());
    assert_eq!(callt(&p, &th, Sys::RestartSyscall, &[]), EAGAIN);
    // ...and there is only one restart per interruption.
    assert_eq!(callt(&p, &th, Sys::RestartSyscall, &[]), EINTR);
}

/// A thread of `p` whose task has `prio`, bound for priority inheritance.
fn thread_at(p: &Process, main: &Thread, slot: u64, prio: u8) -> (Arc<Thread>, Arc<Task>) {
    let Outcome::Thread { tid, .. } =
        clone_thread(p, main, clone_flags(), STACK - 0x400 * slot, DATA + 0x10 * slot, DATA + 0x400 + 0x10 * slot, 0)
    else {
        panic!("no thread")
    };
    let th = p.group.find(tid).unwrap();
    let task = TaskBuilder::new("pi").priority(prio).build(|| {});
    th.ext.bind(&task);
    (th, task)
}

fn word(p: &Process, addr: u64) -> u32 {
    u32::from_ne_bytes(get(p, addr, 4).try_into().unwrap())
}

fn lock_in(p: &Arc<Process>, th: &Arc<Thread>, addr: u64) -> (Arc<Task>, Arc<core::sync::atomic::AtomicI64>) {
    let th = th.clone();
    block_in(p, move |p| callt(p, &th, Sys::Futex, &[addr, LOCK_PI, 0, 0]))
}

fn op(p: &Process, th: &Thread, addr: u64, op: u64) -> i64 {
    callt(p, th, Sys::Futex, &[addr, op, 0, 0])
}

#[test]
fn trylock_and_unlock_follow_the_word() {
    platform();
    let (p, _) = process("pi-basic");
    let (a, _) = thread_at(&p, &p.leader(), 1, 1);
    let (b, _) = thread_at(&p, &p.leader(), 2, 1);
    let addr = DATA + 0x80;
    assert_eq!(op(&p, &a, addr, TRYLOCK_PI), 0);
    assert_eq!(word(&p, addr), a.tid(), "the owner's tid");
    assert_eq!(op(&p, &a, addr, TRYLOCK_PI), EDEADLK, "already the owner");
    assert_eq!(op(&p, &a, addr, LOCK_PI), EDEADLK, "would wait for itself");
    assert_eq!(op(&p, &b, addr, TRYLOCK_PI), EAGAIN, "held");
    assert_eq!(op(&p, &b, addr, UNLOCK_PI), EPERM, "not the owner");
    assert_eq!(op(&p, &a, addr, UNLOCK_PI), 0);
    assert_eq!(word(&p, addr), 0);
    assert_eq!(op(&p, &b, addr, LOCK_PI), 0, "a free lock is taken without waiting");
    assert_eq!(word(&p, addr), b.tid());

    // A lock whose owner died is taken, keeping the flag.
    put(&p, addr, &OWNER_DIED.to_ne_bytes());
    assert_eq!(op(&p, &a, addr, TRYLOCK_PI), 0);
    assert_eq!(word(&p, addr), a.tid() | OWNER_DIED);
    // An owner that is no thread of the process.
    put(&p, addr, &9999u32.to_ne_bytes());
    assert_eq!(op(&p, &b, addr, LOCK_PI), -3, "ESRCH");
}

#[test]
fn a_waiter_lends_its_priority_to_the_owner_and_gets_the_lock() {
    become_cpu();
    platform();
    let (p, _) = process("pi-boost");
    let (low, low_task) = thread_at(&p, &p.leader(), 1, 1);
    let (high, high_task) = thread_at(&p, &p.leader(), 2, 9);
    let addr = DATA + 0x80;
    assert_eq!(op(&p, &low, addr, TRYLOCK_PI), 0);

    let (task, result) = lock_in(&p, &high, addr);
    assert_eq!(word(&p, addr), low.tid() | WAITERS, "the waiters bit is set");
    assert_eq!(low_task.priority(), 9, "the owner runs at the waiter's priority");
    assert_eq!(high_task.priority(), 9);

    assert_eq!(op(&p, &low, addr, UNLOCK_PI), 0);
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), 0);
    assert_eq!(word(&p, addr), high.tid(), "handed over, no waiters left");
    assert_eq!(low_task.priority(), 1, "the boost ends with the lock");
    assert_eq!(op(&p, &high, addr, UNLOCK_PI), 0);
    assert_eq!(word(&p, addr), 0);
    assert_eq!(crate::futex_pi::queued(p.pid(), addr), 0);
}

#[test]
fn the_highest_priority_waiter_gets_the_lock() {
    become_cpu();
    platform();
    let (p, _) = process("pi-order");
    let (owner, owner_task) = thread_at(&p, &p.leader(), 1, 1);
    let (mid, _mid_task) = thread_at(&p, &p.leader(), 2, 5);
    let (high, _high_task) = thread_at(&p, &p.leader(), 3, 9);
    let addr = DATA + 0x80;
    assert_eq!(op(&p, &owner, addr, TRYLOCK_PI), 0);
    let (t_mid, r_mid) = lock_in(&p, &mid, addr);
    assert_eq!(owner_task.priority(), 5);
    let (t_high, r_high) = lock_in(&p, &high, addr);
    assert_eq!(owner_task.priority(), 9);

    assert_eq!(op(&p, &owner, addr, UNLOCK_PI), 0);
    t_high.join();
    assert_eq!(r_high.load(Ordering::SeqCst), 0);
    assert_eq!(word(&p, addr), high.tid() | WAITERS, "the lower waiter still waits");
    assert_eq!(owner_task.priority(), 1);
    assert_eq!(op(&p, &high, addr, UNLOCK_PI), 0);
    t_mid.join();
    assert_eq!(r_mid.load(Ordering::SeqCst), 0);
    assert_eq!(word(&p, addr), mid.tid());
}

#[test]
fn boosts_follow_lock_chains_and_end_when_a_waiter_gives_up() {
    become_cpu();
    platform();
    let (p, _) = process("pi-chain");
    let (low, low_task) = thread_at(&p, &p.leader(), 1, 1);
    let (mid, mid_task) = thread_at(&p, &p.leader(), 2, 5);
    let (high, _high_task) = thread_at(&p, &p.leader(), 3, 9);
    let (a, b) = (DATA + 0x80, DATA + 0x90);
    assert_eq!(op(&p, &mid, a, TRYLOCK_PI), 0);
    assert_eq!(op(&p, &low, b, TRYLOCK_PI), 0);
    assert_eq!(sigaction(&p, SIGUSR1, handler(0, 0)), 0);

    // mid waits for low's lock B, high for mid's lock A.
    let (t_mid, r_mid) = lock_in(&p, &mid, b);
    assert_eq!(low_task.priority(), 5);
    let (t_high, r_high) = lock_in(&p, &high, a);
    assert_eq!(mid_task.priority(), 9);
    assert_eq!(low_task.priority(), 9, "the boost passes down the chain");
    assert_eq!(op(&p, &low, a, LOCK_PI), EDEADLK, "low waiting for A would close the cycle");

    // high gives up: both drop back to what mid's own wait implies.
    signal::send_to_thread(&p, &high, SIGUSR1, p.pid()).unwrap();
    t_high.join();
    assert_eq!(r_high.load(Ordering::SeqCst), EINTR);
    assert_eq!(mid_task.priority(), 5);
    assert_eq!(low_task.priority(), 5);
    assert_eq!(crate::futex_pi::queued(p.pid(), a), 0, "an interrupted waiter leaves the queue");

    assert_eq!(op(&p, &low, b, UNLOCK_PI), 0);
    t_mid.join();
    assert_eq!(r_mid.load(Ordering::SeqCst), 0);
    assert_eq!(low_task.priority(), 1);
    assert_eq!(mid_task.priority(), 5);
    assert_eq!(word(&p, b), mid.tid());
}

#[test]
fn a_dead_owner_hands_the_lock_over_with_owner_died() {
    become_cpu();
    platform();
    let (p, _) = process("pi-died");
    let (owner, owner_task) = thread_at(&p, &p.leader(), 1, 1);
    let (high, _high_task) = thread_at(&p, &p.leader(), 2, 9);
    let addr = DATA + 0x80;
    assert_eq!(op(&p, &owner, addr, TRYLOCK_PI), 0);
    let (task, result) = lock_in(&p, &high, addr);
    assert!(crate::futex_pi::owner_died(&p, owner.tid(), addr));
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), 0);
    assert_eq!(word(&p, addr), high.tid() | OWNER_DIED);
    assert_eq!(owner_task.priority(), 1);
    assert!(!crate::futex_pi::owner_died(&p, owner.tid(), addr), "nobody is left to take it");
}

#[test]
fn pi_operations_reject_bad_arguments() {
    platform();
    let (p, _) = process("pi-bad");
    let th = p.leader();
    assert_eq!(callt(&p, &th, Sys::Futex, &[DATA + 0x81, LOCK_PI, 0, 0]), -(Errno::EINVAL.0 as i64), "unaligned");
    assert_eq!(callt(&p, &th, Sys::Futex, &[0xdead_0000, TRYLOCK_PI, 0, 0]), -(Errno::EFAULT.0 as i64));
    // FUTEX_CLOCK_REALTIME only means something to LOCK_PI2 and WAIT_BITSET.
    assert_eq!(callt(&p, &th, Sys::Futex, &[DATA, LOCK_PI | 256, 0, 0]), -(Errno::ENOSYS.0 as i64));
    let _ = SigAction::default();
}
