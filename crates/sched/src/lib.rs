//! Tasks, context switching and pluggable scheduling.
//!
//! The crate provides the *mechanism*: [`Task`]s with their own stacks, the
//! per-arch context switch, the current-task pointer, blocking and waking,
//! exit and tick-driven preemption. The *policy* is any [`Scheduler`]
//! implementation, injected once with [`inject_scheduler`]. Two policies are
//! included: [`FifoScheduler`] (round-robin) and [`PriorityScheduler`].
//!
//! ```ignore
//! static SCHED: FifoScheduler = FifoScheduler::new(10);
//!
//! fn kernel_main() {
//!     osmium_sched::inject_scheduler(&SCHED);
//!     // SAFETY: called once per CPU, after setting its CPU id.
//!     unsafe { osmium_sched::init_cpu() };
//!     let t = TaskBuilder::new("worker").spawn(|| { /* ... */ });
//!     t.join();
//! }
//! ```
//!
//! # Integration points
//!
//! - Call [`tick`] from the timer interrupt and [`preempt_if_needed`] on the
//!   way out of every interrupt, so long-running tasks are time-sliced.
//! - Blocking primitives ([`WaitQueue`], [`Mutex`], [`Semaphore`]) must not
//!   be used while a spin lock is held or from interrupt context.
//! - Each CPU runs an idle task that waits for interrupts when nothing is
//!   runnable.
//!
//! The scheduler keeps tasks on their CPU; wake-ups go to the task's last
//! CPU, and [`Task::set_cpu`] migrates a task the next time it is queued.
//! Register [`set_remote_wake_hook`] to send an IPI when work is queued on
//! another CPU; without it, that CPU notices at its next timer tick.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod context;
mod core_sched;
mod policy;
mod sync;
mod task;
pub mod timer;

pub use core_sched::{
    EnqueueReason, Scheduler, current, exit, init_cpu, inject_scheduler, preempt_if_needed, set_remote_wake_hook, spawn, tick,
    yield_now,
};
pub use policy::{FifoScheduler, PriorityScheduler};
pub use sync::{Mutex, MutexGuard, Semaphore, WaitQueue};
pub use task::{Task, TaskBuilder, TaskId, TaskState};
