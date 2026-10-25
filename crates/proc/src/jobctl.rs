//! Job control: stopping a process with `SIGSTOP`, `SIGTSTP`, `SIGTTIN` or
//! `SIGTTOU`, continuing it with `SIGCONT`, and reporting both to a parent in
//! `wait4` (`WUNTRACED`, `WCONTINUED`).
//!
//! A stop is a property of the whole process. A thread takes the stop when it
//! dequeues the signal (its default action) and parks in [`hold`], and every
//! other thread parks there the next time it returns to user mode, so a
//! thread spinning in user mode without ever entering the kernel is not
//! stopped until a timer interrupt runs `signal::deliver`. A thread blocked
//! in a system call is interrupted (`EINTR`) by a pending stop signal and
//! parks as it returns. `SIGCONT` acts when it is sent, even if blocked or
//! ignored, as on Linux: it discards pending stop signals and resumes the
//! process; a stop signal discards a pending `SIGCONT`.
//!
//! There are no process groups or controlling terminals, so `SIGTTIN` and
//! `SIGTTOU` only arise from `kill`, and a stopped process is never orphaned.
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use osmium_sched::WaitQueue;

use crate::process::{ExitStatus, Process};
use crate::signal::sig::*;
use crate::signal::{bit, sa};
use crate::thread::Thread;

/// Threads parked by a stop or by `sigsuspend` wait here; everything that
/// changes what they wait for ([`crate::signal::wake_blocked`]) wakes them to
/// look again.
static PARKED: WaitQueue = WaitQueue::new();

/// Wakes the parked threads of every process.
pub(crate) fn wake() {
    PARKED.wake_all();
}

/// Waits until `cond` holds. For the parked threads' wake-ups.
pub(crate) fn park_until<R>(cond: impl FnMut() -> Option<R>) -> R {
    PARKED.wait_until(cond)
}

/// Whether `sig` stops a process by default.
pub(crate) fn is_stop(sig: u8) -> bool {
    matches!(sig, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

/// The stop signals as a mask.
const STOP_MASK: u64 = 1 << (SIGSTOP - 1) | 1 << (SIGTSTP - 1) | 1 << (SIGTTIN - 1) | 1 << (SIGTTOU - 1);

/// What `wait4` reports about a child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitEvent {
    /// It ended.
    Exited(ExitStatus),
    /// A stop signal (this one) stopped it.
    Stopped(u8),
    /// `SIGCONT` resumed it.
    Continued,
}

impl WaitEvent {
    /// The status word `wait4` stores: [`ExitStatus::wait_status`], or
    /// `signal << 8 | 0x7f` for a stop, or `0xffff` for a continue.
    pub(crate) fn wait_status(self) -> i32 {
        match self {
            WaitEvent::Exited(s) => s.wait_status(),
            WaitEvent::Stopped(sig) => i32::from(sig) << 8 | 0x7f,
            WaitEvent::Continued => 0xffff,
        }
    }
}

/// A process's stop state.
pub(crate) struct JobCtl {
    stopped: AtomicBool,
    stop_sig: AtomicU8,
    /// The stop has not been reported to a `WUNTRACED` wait yet.
    stop_report: AtomicBool,
    /// The continue has not been reported to a `WCONTINUED` wait yet.
    cont_report: AtomicBool,
}

impl JobCtl {
    pub(crate) const fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            stop_sig: AtomicU8::new(0),
            stop_report: AtomicBool::new(false),
            cont_report: AtomicBool::new(false),
        }
    }

    /// Whether the process is stopped.
    pub(crate) fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Takes the stop or continue that the wait is asking for, if one has
    /// not been reported yet.
    pub(crate) fn take_report(&self, untraced: bool, continued: bool) -> Option<WaitEvent> {
        if untraced && self.stop_report.swap(false, Ordering::SeqCst) {
            return Some(WaitEvent::Stopped(self.stop_sig.load(Ordering::SeqCst)));
        }
        if continued && self.cont_report.swap(false, Ordering::SeqCst) {
            return Some(WaitEvent::Continued);
        }
        None
    }
}

/// Queues `SIGCHLD` for the parent of `p`, unless it asked not to hear of
/// stops (`SA_NOCLDSTOP`), and wakes its `wait4`.
fn tell_parent(p: &Process) {
    let Some(parent) = p.parent().and_then(Process::find) else { return };
    if parent.signals.action(SIGCHLD).flags & sa::NOCLDSTOP == 0 {
        crate::signal::child_exited(&parent, p.pid());
    }
    parent.child_exited.wake_all();
}

/// The side effects of sending `sig` to `p` that happen at once, whatever
/// the disposition: `SIGCONT` resumes the process and discards pending stop
/// signals, and a stop signal discards a pending `SIGCONT`.
pub(crate) fn prepare(p: &Process, sig: u8) {
    if sig == SIGCONT {
        p.signals.discard_pending(STOP_MASK);
        p.group.each(|t| t.discard_pending(STOP_MASK));
        if p.signals.job.stopped.swap(false, Ordering::SeqCst) {
            p.signals.job.stop_report.store(false, Ordering::SeqCst);
            p.signals.job.cont_report.store(true, Ordering::SeqCst);
            wake();
            tell_parent(p);
        }
    } else if is_stop(sig) {
        p.signals.discard_pending(bit(SIGCONT));
        p.group.each(|t| t.discard_pending(bit(SIGCONT)));
    }
}

/// The default action of a stop signal, taken by a thread that dequeued it:
/// the process stops, once (a stop signal to a stopped process changes
/// nothing), and the parent hears of it.
pub(crate) fn stop_group(p: &Process, sig: u8) {
    let job = &p.signals.job;
    if job.stopped.swap(true, Ordering::SeqCst) {
        return;
    }
    job.stop_sig.store(sig, Ordering::SeqCst);
    job.cont_report.store(false, Ordering::SeqCst);
    job.stop_report.store(true, Ordering::SeqCst);
    tell_parent(p);
}

/// Parks `th` while its process is stopped. Returns at once if it is not,
/// and when the process is continued, ending or replacing its program.
pub(crate) fn hold(p: &Process, th: &Thread) {
    if !p.signals.job.stopped() {
        return;
    }
    park_until(|| {
        (!p.signals.job.stopped() || p.group.exiting.get().is_some() || th.doomed.load(Ordering::SeqCst)).then_some(())
    });
}
