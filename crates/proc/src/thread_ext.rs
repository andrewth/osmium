//! Per-thread state for restartable system calls and priority inheritance,
//! kept apart from [`crate::thread::Thread`] proper.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU16, Ordering};

use osmium_sched::Task;
use osmium_sync::{IrqSpinLock, Once};

use crate::restart::Block;

/// `base_prio` when the task's priority is not boosted.
const NOT_BOOSTED: u16 = u16::MAX;

/// A thread's restart block and priority-inheritance bookkeeping.
pub(crate) struct ThreadExt {
    /// What `restart_syscall` resumes, set by a call that was interrupted
    /// but may be continued.
    pub(crate) restart: IrqSpinLock<Option<Block>>,
    /// The task's own priority while a priority-inheritance futex boosts it.
    base_prio: AtomicU16,
    /// The thread's task, for boosting its priority.
    task: Once<Weak<Task>>,
}

impl ThreadExt {
    pub(crate) const fn new() -> Self {
        Self { restart: IrqSpinLock::new(None), base_prio: AtomicU16::new(NOT_BOOSTED), task: Once::new() }
    }

    /// Records the task that runs the thread; the first call wins.
    pub(crate) fn bind(&self, task: &Arc<Task>) {
        if self.task.get().is_none() {
            let _ = self.task.set(Arc::downgrade(task));
        }
    }

    pub(crate) fn task(&self) -> Option<Arc<Task>> {
        self.task.get()?.upgrade()
    }

    /// The thread's current (possibly boosted) priority; 0 if its task is unknown.
    pub(crate) fn priority(&self) -> u8 {
        self.task().map_or(0, |t| t.priority())
    }

    /// The priority the thread has without any boost.
    pub(crate) fn base(&self) -> u8 {
        match u8::try_from(self.base_prio.load(Ordering::SeqCst)) {
            Ok(b) => b,
            Err(_) => self.priority(),
        }
    }

    /// Makes the thread run at the higher of its own priority and `want`.
    /// The new priority takes effect the next time the task is queued.
    pub(crate) fn boost_to(&self, want: u8) {
        let Some(task) = self.task() else { return };
        let base = self.base();
        if want > base {
            self.base_prio.store(u16::from(base), Ordering::SeqCst);
            task.set_priority(want);
        } else {
            self.base_prio.store(NOT_BOOSTED, Ordering::SeqCst);
            task.set_priority(base);
        }
    }
}
