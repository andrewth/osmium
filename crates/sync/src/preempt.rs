//! The per-CPU preemption counter.
//!
//! A scheduler may only switch tasks involuntarily on a CPU whose count is
//! zero. [`crate::SpinLock`] raises the count while it is held.

use core::sync::atomic::{AtomicU32, Ordering};

use osmium_arch::{MAX_CPUS, cpu, irq};

static COUNT: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];

/// Disables preemption on this CPU. Calls nest.
#[inline]
pub fn disable() {
    // IRQs are masked so the task cannot migrate between reading the CPU id
    // and updating that CPU's counter.
    irq::without(|| COUNT[cpu::current_id()].fetch_add(1, Ordering::Relaxed));
}

/// Re-enables preemption after a matching [`disable`].
#[inline]
pub fn enable() {
    let prev = irq::without(|| COUNT[cpu::current_id()].fetch_sub(1, Ordering::Relaxed));
    debug_assert!(prev > 0, "preempt::enable without matching disable");
}

/// Returns this CPU's preemption-disable depth.
#[inline]
pub fn count() -> u32 {
    COUNT[cpu::current_id()].load(Ordering::Relaxed)
}

/// Returns true if the scheduler may preempt the current task.
#[inline]
pub fn is_preemptible() -> bool {
    count() == 0 && irq::are_enabled()
}

/// Disables preemption until the returned guard is dropped.
pub fn guard() -> PreemptGuard {
    disable();
    PreemptGuard(core::marker::PhantomData)
}

/// Keeps preemption disabled while alive. Not `Send`: it belongs to this CPU.
#[must_use]
pub struct PreemptGuard(core::marker::PhantomData<*const ()>);

impl Drop for PreemptGuard {
    fn drop(&mut self) {
        enable();
    }
}
