//! Synchronization primitives for kernels, firmware and hypervisors.
//!
//! - [`SpinLock`]: a fair ticket lock, generic over a [`Guardian`] that runs
//!   on acquire and release. The default [`PreemptDisabled`] stops the
//!   scheduler from switching tasks while the lock is held; [`IrqDisabled`]
//!   additionally masks local interrupts, which a lock shared with an
//!   interrupt handler needs.
//! - [`McsLock`]: an MCS queued spin lock; each waiter spins on its own cache line.
//! - [`Rcu`] and `RcuCell` (feature `alloc`): sleepable read-copy-update.
//! - [`RwSpinLock`]: a writer-preferring reader/writer spin lock.
//! - [`SeqLock`]: a sequence lock; readers retry instead of blocking the writer.
//! - [`Once`] and [`Lazy`]: one-time initialization.
//! - [`PerCpu`] and [`PerCpuCell`]: per-CPU storage indexed by
//!   `osmium_arch::cpu::current_id`.
//! - [`SpscRing`]: a lock-free single-producer, single-consumer ring.
//! - `arc` (feature `alloc`): intrusive lists and trees that own their `Arc` elements.
//! - `fallible` (feature `alloc`): allocation that returns an error instead of panicking.
//! - [`intrusive`]: allocation-free linked lists and red-black / AVL trees whose
//!   links live inside the elements.
//!
//! Sleeping locks (`Mutex`, `WaitQueue`) need a scheduler and live in
//! `osmium-sched`.
#![no_std]
#![cfg_attr(feature = "alloc", feature(allocator_ext))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(test)]
extern crate std;

#[cfg(feature = "alloc")]
pub mod arc;
#[cfg(feature = "alloc")]
pub mod fallible;
mod guard;
pub mod intrusive;
mod mcs;
mod once;
mod percpu;
pub mod preempt;
mod rcu;
mod ring;
mod rwlock;
mod seqlock;
mod spin;

pub use guard::{Guardian, IrqDisabled, NoGuard, PreemptDisabled};
pub use mcs::{IrqMcsLock, McsLock, RawMcsLock};
pub use once::{Lazy, Once};
pub use percpu::{PerCpu, PerCpuCell};
#[cfg(feature = "alloc")]
pub use rcu::RcuCell;
pub use rcu::{Rcu, RcuReadGuard};
pub use ring::{Consumer, Producer, SpscRing};
pub use rwlock::{RwSpinLock, RwSpinLockReadGuard, RwSpinLockWriteGuard};
pub use seqlock::{NoPadding, SeqLock};
pub use spin::{IrqSpinLock, RawSpinLock, SpinLock, SpinLockGuard};
