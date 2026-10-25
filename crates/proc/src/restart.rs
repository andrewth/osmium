//! Restartable system calls.
//!
//! A blocked call that a signal interrupts fails with `EINTR` inside the
//! kernel. What the program sees depends on how the call and the signal's
//! handler are set up, as on Linux:
//!
//! - Calls that may be restarted ([`Kind::Sys`]: `read`, `write`, `wait4`,
//!   `accept`, `send*`, `recv*` and friends) run again, transparently, after
//!   a handler installed with `SA_RESTART`. Without the flag the call fails
//!   with `EINTR`. The restart is done by rewinding the program counter to
//!   the system-call instruction, so the handler returns into the call.
//! - `FUTEX_LOCK_PI` ([`Kind::Always`]) is restarted whatever the flags.
//! - `FUTEX_WAIT` ([`Kind::Block`]) never restarts after a handler (`EINTR`),
//!   but if the signal was taken by another thread or ignored, it continues
//!   through `restart_syscall`, with the timeout's original deadline kept in
//!   the thread's restart block.
//! - `poll`, `select`, `epoll_wait` and `connect` always fail with `EINTR`.
#![cfg_attr(
    not(any(test, target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64"))),
    allow(dead_code)
)]

use osmium_fs::Errno;

use crate::futex;
use crate::process::Process;
use crate::syscall::Sys;
use crate::thread::Thread;

/// How a call interrupted by a signal is continued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Restarted after a handler that has `SA_RESTART`, and when no handler runs.
    Sys,
    /// Restarted after any handler, as well as when none runs.
    Always,
    /// Continued through `restart_syscall` when no handler runs; `EINTR`
    /// after a handler.
    Block,
}

/// A call to resume after a signal, planned when the call returned `EINTR`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Restart {
    /// The system-call number to issue again.
    pub(crate) nr: u64,
    /// The first argument, which the result overwrote on some architectures.
    pub(crate) arg0: u64,
    pub(crate) kind: Kind,
}

impl Restart {
    /// Whether a handler with `sa_flags` lets the call restart.
    pub(crate) fn after_handler(&self, sa_flags: u64) -> bool {
        match self.kind {
            Kind::Always => true,
            Kind::Sys => sa_flags & crate::signal::sa::RESTART != 0,
            Kind::Block => false,
        }
    }
}

/// The calls that continue where they left off, as the thread's restart
/// block remembers them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Block {
    /// `FUTEX_WAIT` or `FUTEX_WAIT_BITSET`, with its absolute deadline.
    FutexWait { uaddr: u64, val: u32, bitset: u32, deadline: Option<u64> },
}

/// Plans the continuation of system call `nr` with arguments `a` that just
/// returned `EINTR`, if it has one.
pub(crate) fn plan(th: &Thread, nr: u64, a: &[u64; 6]) -> Option<Restart> {
    let (kind, reissue) = match Sys::from_number(nr)? {
        Sys::Read
        | Sys::Write
        | Sys::Readv
        | Sys::Writev
        | Sys::Wait4
        | Sys::Accept
        | Sys::Accept4
        | Sys::Sendto
        | Sys::Recvfrom
        | Sys::Sendmsg
        | Sys::Recvmsg => (Kind::Sys, nr),
        Sys::Futex if futex::is_lock_pi(a[1]) => (Kind::Always, nr),
        Sys::Futex if futex::is_wait(a[1]) && th.ext.restart.lock().is_some() => {
            (Kind::Block, Sys::RestartSyscall.number())
        }
        _ => return None,
    };
    Some(Restart { nr: reissue, arg0: a[0], kind })
}

/// `restart_syscall`: continues the call the thread's restart block names,
/// or fails with `EINTR` if there is none.
pub(crate) fn restart_syscall(p: &Process, th: &Thread) -> Result<u64, Errno> {
    let block = th.ext.restart.lock().take();
    match block {
        Some(Block::FutexWait { uaddr, val, bitset, deadline }) => futex::wait(p, th, uaddr, val, bitset, deadline),
        None => Err(Errno::EINTR),
    }
}
