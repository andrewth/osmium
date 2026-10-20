//! Synchronization primitives for kernels, firmware and hypervisors.
//!
//! - [`SpinLock`]: a fair ticket lock, generic over a [`Guardian`] that runs
//!   on acquire and release. The default [`PreemptDisabled`] stops the
//!   scheduler from switching tasks while the lock is held; [`IrqDisabled`]
//!   additionally masks local interrupts, which a lock shared with an
//!   interrupt handler needs.
//! - [`RwSpinLock`]: a writer-preferring reader/writer spin lock.
//! - [`SeqLock`]: a sequence lock; readers retry instead of blocking the writer.
//! - [`Once`] and [`Lazy`]: one-time initialization.
//! - [`PerCpu`] and [`PerCpuCell`]: per-CPU storage indexed by
//!   `osmium_arch::cpu::current_id`.
//! - [`SpscRing`]: a lock-free single-producer, single-consumer ring.
//!
//! Sleeping locks (`Mutex`, `WaitQueue`) need a scheduler and live in
//! `osmium-sched`.
#![no_std]

#[cfg(test)]
extern crate std;

mod guard;
mod once;
mod percpu;
pub mod preempt;
mod ring;
mod rwlock;
mod seqlock;
mod spin;

pub use guard::{Guardian, IrqDisabled, NoGuard, PreemptDisabled};
pub use once::{Lazy, Once};
pub use percpu::{PerCpu, PerCpuCell};
pub use ring::{Consumer, Producer, SpscRing};
pub use rwlock::{RwSpinLock, RwSpinLockReadGuard, RwSpinLockWriteGuard};
pub use seqlock::SeqLock;
pub use spin::{IrqSpinLock, RawSpinLock, SpinLock, SpinLockGuard};
