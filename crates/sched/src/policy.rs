//! Ready-made scheduling policies.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use osmium_arch::MAX_CPUS;
use osmium_sync::{IrqSpinLock, PerCpu};

use crate::core_sched::{EnqueueReason, Scheduler};
use crate::task::Task;

/// Round-robin with a fixed time slice and one run queue per CPU.
pub struct FifoScheduler {
    queues: PerCpu<IrqSpinLock<VecDeque<Arc<Task>>>>,
    slice: u32,
}

impl FifoScheduler {
    /// Creates the policy; a task runs for up to `slice_ticks` ticks while
    /// others wait.
    pub const fn new(slice_ticks: u32) -> Self {
        Self { queues: PerCpu::new([const { IrqSpinLock::new(VecDeque::new()) }; MAX_CPUS]), slice: slice_ticks }
    }

    /// Number of tasks waiting on `cpu`.
    pub fn queued(&self, cpu: usize) -> usize {
        self.queues.get_for(cpu).lock().len()
    }
}

impl Scheduler for FifoScheduler {
    fn enqueue(&self, task: Arc<Task>, _reason: EnqueueReason) {
        task.slice_left.store(self.slice, Ordering::Relaxed);
        self.queues.get_for(task.cpu()).lock().push_back(task);
    }

    fn pick_next(&self, cpu: usize) -> Option<Arc<Task>> {
        self.queues.get_for(cpu).lock().pop_front()
    }

    fn tick(&self, cpu: usize, current: &Task) -> bool {
        let left = current.slice_left.load(Ordering::Relaxed).saturating_sub(1);
        current.slice_left.store(left, Ordering::Relaxed);
        left == 0 && !self.queues.get_for(cpu).lock().is_empty()
    }
}

const LEVELS: usize = 64;

struct PrioQueue {
    /// Bit `p` set = level `p` is non-empty.
    bitmap: u64,
    levels: [VecDeque<Arc<Task>>; LEVELS],
}

impl PrioQueue {
    const fn new() -> Self {
        Self { bitmap: 0, levels: [const { VecDeque::new() }; LEVELS] }
    }

    fn highest(&self) -> Option<u8> {
        (self.bitmap != 0).then(|| 63 - self.bitmap.leading_zeros() as u8)
    }
}

/// Fixed-priority preemptive scheduling with 64 levels (63 is highest),
/// round-robin within a level, and O(1) selection.
pub struct PriorityScheduler {
    queues: PerCpu<IrqSpinLock<PrioQueue>>,
    slice: u32,
}

impl PriorityScheduler {
    /// Creates the policy; equal-priority tasks share the CPU in slices of
    /// `slice_ticks` ticks.
    pub const fn new(slice_ticks: u32) -> Self {
        Self { queues: PerCpu::new([const { IrqSpinLock::new(PrioQueue::new()) }; MAX_CPUS]), slice: slice_ticks }
    }
}

impl Scheduler for PriorityScheduler {
    fn enqueue(&self, task: Arc<Task>, _reason: EnqueueReason) {
        task.slice_left.store(self.slice, Ordering::Relaxed);
        let p = task.priority() as usize;
        let mut q = self.queues.get_for(task.cpu()).lock();
        q.levels[p].push_back(task);
        q.bitmap |= 1 << p;
    }

    fn pick_next(&self, cpu: usize) -> Option<Arc<Task>> {
        let mut q = self.queues.get_for(cpu).lock();
        let p = q.highest()? as usize;
        let t = q.levels[p].pop_front();
        if q.levels[p].is_empty() {
            q.bitmap &= !(1 << p);
        }
        t
    }

    fn tick(&self, cpu: usize, current: &Task) -> bool {
        let left = current.slice_left.load(Ordering::Relaxed).saturating_sub(1);
        current.slice_left.store(left, Ordering::Relaxed);
        match self.queues.get_for(cpu).lock().highest() {
            Some(p) if p > current.priority() => true,
            Some(p) => p == current.priority() && left == 0,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TaskBuilder;

    #[test]
    fn priority_order_and_preemption() {
        let s = PriorityScheduler::new(2);
        let low = TaskBuilder::new("low").priority(1).cpu(40).build(|| {});
        let high = TaskBuilder::new("high").priority(9).cpu(40).build(|| {});
        let high2 = TaskBuilder::new("high2").priority(9).cpu(40).build(|| {});
        s.enqueue(low.clone(), EnqueueReason::Spawned);
        assert!(!s.tick(40, &low), "nothing higher queued");
        s.enqueue(high.clone(), EnqueueReason::Spawned);
        assert!(s.tick(40, &low), "higher priority preempts");
        s.enqueue(high2.clone(), EnqueueReason::Spawned);
        assert_eq!(s.pick_next(40).unwrap().name(), "high");
        // `high` runs; `high2` is equal priority, so it waits for the slice.
        assert!(!s.tick(40, &high));
        assert!(s.tick(40, &high));
        assert_eq!(s.pick_next(40).unwrap().name(), "high2");
        assert_eq!(s.pick_next(40).unwrap().name(), "low");
        assert!(s.pick_next(40).is_none());
    }

    #[test]
    fn fifo_slices() {
        let s = FifoScheduler::new(3);
        let a = TaskBuilder::new("a").cpu(41).build(|| {});
        let b = TaskBuilder::new("b").cpu(41).build(|| {});
        s.enqueue(a.clone(), EnqueueReason::Spawned);
        let a = s.pick_next(41).unwrap();
        assert!(!s.tick(41, &a) && !s.tick(41, &a) && !s.tick(41, &a), "alone: never preempted");
        s.enqueue(b, EnqueueReason::Spawned);
        assert!(s.tick(41, &a), "slice spent and someone is waiting");
        assert_eq!(s.queued(41), 1);
    }
}
