//! Which user address space each CPU may have loaded, so that none is freed
//! while a CPU's MMU can still walk its tables.
//!
//! A CPU's page-table root register is written by the kernel's switch hook
//! (with the root [`crate::switch_root`] or [`crate::root_for`] returns) and
//! by `execve` on the calling CPU (`Platform::activate`). Each CPU keeps a
//! reference to the space it was last told to load, and to the one before
//! it, which the hook may not have replaced in the register yet when it
//! asks about the next task. A space is therefore freed only once every CPU
//! has moved on from it by two switches, or by one `execve` there, even if
//! its process has gone: an `execve` in a multi-threaded process may replace
//! the image while another thread, doomed but still in the kernel on
//! another CPU, has the old table loaded. The references only ever delay a
//! free, so a CPU that never switches again keeps the last space it ran
//! alive, which is harmless.
//!
//! The kernel's hook must also make sure that, once a CPU has loaded another
//! root, it no longer uses TLB entries of the old one: the example kernels
//! flush on every change of root; a kernel that tags entries with ASIDs must
//! invalidate a table's ASID before reusing it for another table.

use alloc::sync::Arc;

use osmium_arch::{MAX_CPUS, irq};
use osmium_sync::{IrqSpinLock, PerCpu};

use crate::memory::UserMemory;

/// What one CPU may have loaded.
struct Slot {
    /// The space the CPU was last told to load; `None` for a kernel-only
    /// table.
    loaded: Option<Arc<dyn UserMemory>>,
    /// The one before it: the register may still hold it until the switch
    /// hook that replaced `loaded` returns.
    retired: Option<Arc<dyn UserMemory>>,
    /// The task the hook last asked about, by address: a second question
    /// about the same task is the same switch (the scheduler never switches
    /// to the task already running, so two switches in a row name two
    /// different tasks).
    last: usize,
}

static SLOTS: PerCpu<IrqSpinLock<Slot>> =
    PerCpu::new([const { IrqSpinLock::new(Slot { loaded: None, retired: None, last: 0 }) }; MAX_CPUS]);

/// The switch hook is about to load `memory` (`None`: a kernel-only table)
/// on this CPU for `next`. What the register held before the previous
/// switch can no longer be in it, and is let go.
pub(crate) fn switching_to(next: &osmium_sched::Task, memory: Option<Arc<dyn UserMemory>>) {
    let task = core::ptr::from_ref(next).addr();
    let released = irq::without(|| {
        let mut slot = SLOTS.get().lock();
        if slot.last == task {
            // Asked twice in one switch: nothing has been loaded since.
            return memory;
        }
        slot.last = task;
        let previous = core::mem::replace(&mut slot.loaded, memory);
        core::mem::replace(&mut slot.retired, previous)
    });
    // Dropped with no lock held: it may free a whole address space.
    drop(released);
}

/// `memory` has just been loaded on this CPU (by `execve`): nothing that was
/// loaded here before is in the register any more.
pub(crate) fn loaded_here(memory: Arc<dyn UserMemory>) {
    let released = irq::without(|| {
        let mut slot = SLOTS.get().lock();
        (slot.loaded.replace(memory), slot.retired.take())
    });
    drop(released);
}

/// Whether CPU `cpu` may still have `memory` loaded.
#[cfg(test)]
pub(crate) fn holds(cpu: usize, memory: &Arc<dyn UserMemory>) -> bool {
    let slot = SLOTS.for_cpu(cpu).lock();
    let is = |m: &Option<Arc<dyn UserMemory>>| {
        m.as_ref().is_some_and(|m| core::ptr::addr_eq(Arc::as_ptr(m), Arc::as_ptr(memory)))
    };
    is(&slot.loaded) || is(&slot.retired)
}
