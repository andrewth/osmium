//! Ready-made scheduling policies.
//!
//! # Lock order
//!
//! Every policy keeps one run queue per CPU behind its own lock, and never
//! holds two of them at once: `pick_next` releases the local queue before
//! `steal_for` locks a victim's, and `steal_for` locks one victim at a time.
//! Run-queue locks are leaves, so no other lock is taken while one is held.
//!
//! The queues are intrusive (see [`crate::queue`]): queueing a task, which a
//! wake-up or a preemption does where no error can be reported, never
//! allocates.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use osmium_arch::MAX_CPUS;
use osmium_sync::{IrqSpinLock, PerCpu};

use crate::core_sched::{EnqueueReason, Scheduler};
use crate::queue::{TaskList, TaskTree};
use crate::task::Task;

/// Round-robin with a fixed time slice and one run queue per CPU.
///
/// With [`FifoScheduler::with_stealing`], a CPU whose queue is empty takes
/// work from other CPUs: the most recently queued task it is allowed to run
/// (see [`Task::can_run_on`]). Pinned tasks are never moved.
pub struct FifoScheduler {
    queues: PerCpu<IrqSpinLock<TaskList>>,
    slice: u32,
    steal: bool,
    steals: AtomicUsize,
}

impl FifoScheduler {
    /// Creates the policy; a task runs for up to `slice_ticks` ticks while
    /// others wait.
    pub const fn new(slice_ticks: u32) -> Self {
        Self {
            queues: PerCpu::new([const { IrqSpinLock::new(TaskList::new()) }; MAX_CPUS]),
            slice: slice_ticks,
            steal: false,
            steals: AtomicUsize::new(0),
        }
    }

    /// Enables work stealing between CPUs.
    pub const fn with_stealing(mut self) -> Self {
        self.steal = true;
        self
    }

    /// Tasks moved between CPUs by stealing so far.
    pub fn steals(&self) -> usize {
        self.steals.load(Ordering::Relaxed)
    }

    /// Takes a task `cpu` may run from another CPU's queue.
    fn steal_for(&self, cpu: usize) -> Option<Arc<Task>> {
        for off in 1..MAX_CPUS {
            let victim = (cpu + off) % MAX_CPUS;
            let mut q = self.queues.for_cpu(victim).lock();
            if let Some(t) = q.remove_last_where(|t| t.stealable_by(cpu)) {
                self.steals.fetch_add(1, Ordering::Relaxed);
                return Some(t);
            }
        }
        None
    }

    /// Number of tasks waiting on `cpu`.
    pub fn queued(&self, cpu: usize) -> usize {
        self.queues.for_cpu(cpu).lock().len()
    }
}

impl Scheduler for FifoScheduler {
    fn enqueue(&self, task: Arc<Task>, _reason: EnqueueReason) {
        task.slice_left.store(self.slice, Ordering::Relaxed);
        self.queues.for_cpu(task.cpu()).lock().push_back(task);
    }

    fn pick_next(&self, cpu: usize) -> Option<Arc<Task>> {
        let local = self.queues.for_cpu(cpu).lock().pop_front();
        if local.is_none() && self.steal { self.steal_for(cpu) } else { local }
    }

    fn tick(&self, cpu: usize, current: &Task) -> bool {
        let left = current.slice_left.load(Ordering::Relaxed).saturating_sub(1);
        current.slice_left.store(left, Ordering::Relaxed);
        left == 0 && !self.queues.for_cpu(cpu).lock().is_empty()
    }

    fn balances(&self) -> bool {
        self.steal
    }
}

const LEVELS: usize = 64;

struct PrioQueue {
    /// Bit `p` set = level `p` is non-empty.
    bitmap: u64,
    levels: [TaskList; LEVELS],
}

impl PrioQueue {
    const fn new() -> Self {
        Self { bitmap: 0, levels: [const { TaskList::new() }; LEVELS] }
    }

    /// The list for level `p`; a level past the last names level 0 (priorities are clamped to 63, so none is).
    fn level(&mut self, p: usize) -> &mut TaskList {
        let [first, rest @ ..] = &mut self.levels;
        match p.checked_sub(1) {
            Some(i) => rest.get_mut(i).unwrap_or(first),
            None => first,
        }
    }

    fn highest(&self) -> Option<u8> {
        (self.bitmap != 0).then(|| 63 - self.bitmap.leading_zeros() as u8)
    }
}

/// Fixed-priority preemptive scheduling with 64 levels (63 is highest),
/// round-robin within a level, and O(1) selection.
///
/// With [`PriorityScheduler::with_stealing`], an idle CPU takes the
/// highest-priority task it may run from another CPU's queue.
pub struct PriorityScheduler {
    queues: PerCpu<IrqSpinLock<PrioQueue>>,
    slice: u32,
    steal: bool,
    steals: AtomicUsize,
}

impl PriorityScheduler {
    /// Creates the policy; equal-priority tasks share the CPU in slices of
    /// `slice_ticks` ticks.
    pub const fn new(slice_ticks: u32) -> Self {
        Self {
            queues: PerCpu::new([const { IrqSpinLock::new(PrioQueue::new()) }; MAX_CPUS]),
            slice: slice_ticks,
            steal: false,
            steals: AtomicUsize::new(0),
        }
    }

    /// Enables work stealing between CPUs.
    pub const fn with_stealing(mut self) -> Self {
        self.steal = true;
        self
    }

    /// Tasks moved between CPUs by stealing so far.
    pub fn steals(&self) -> usize {
        self.steals.load(Ordering::Relaxed)
    }

    fn steal_for(&self, cpu: usize) -> Option<Arc<Task>> {
        for off in 1..MAX_CPUS {
            let victim = (cpu + off) % MAX_CPUS;
            let mut q = self.queues.for_cpu(victim).lock();
            let mut bits = q.bitmap;
            while bits != 0 {
                let p = 63 - bits.leading_zeros() as usize;
                bits &= !(1 << p);
                if let Some(t) = q.level(p).remove_last_where(|t| t.stealable_by(cpu)) {
                    if q.level(p).is_empty() {
                        q.bitmap &= !(1 << p);
                    }
                    self.steals.fetch_add(1, Ordering::Relaxed);
                    return Some(t);
                }
            }
        }
        None
    }
}

impl Scheduler for PriorityScheduler {
    fn enqueue(&self, task: Arc<Task>, _reason: EnqueueReason) {
        task.slice_left.store(self.slice, Ordering::Relaxed);
        let p = task.priority() as usize;
        let mut q = self.queues.for_cpu(task.cpu()).lock();
        q.level(p).push_back(task);
        q.bitmap |= 1 << p;
    }

    fn pick_next(&self, cpu: usize) -> Option<Arc<Task>> {
        let local = {
            let mut q = self.queues.for_cpu(cpu).lock();
            q.highest().and_then(|p| {
                let p = p as usize;
                let t = q.level(p).pop_front();
                if q.level(p).is_empty() {
                    q.bitmap &= !(1 << p);
                }
                t
            })
        };
        if local.is_none() && self.steal { self.steal_for(cpu) } else { local }
    }

    fn tick(&self, cpu: usize, current: &Task) -> bool {
        let left = current.slice_left.load(Ordering::Relaxed).saturating_sub(1);
        current.slice_left.store(left, Ordering::Relaxed);
        match self.queues.for_cpu(cpu).lock().highest() {
            Some(p) if p > current.priority() => true,
            Some(p) => p == current.priority() && left == 0,
            None => false,
        }
    }

    fn balances(&self) -> bool {
        self.steal
    }
}

/// Run queue ordered by absolute deadline, then arrival.
struct EdfQueue {
    seq: u64,
    tasks: TaskTree,
}

/// Earliest-deadline-first scheduling.
///
/// Time is counted in ticks. A task with a relative deadline
/// ([`Task::set_deadline`]) gets the absolute deadline `release + deadline`
/// when it is spawned or woken; the release time is the wake-up time, except
/// that a periodic task ([`Task::set_period`]) released again before its next
/// period starts is released at the start of that period. The task with the
/// earliest absolute deadline runs first, and a tick preempts the running task
/// as soon as a queued one has an earlier deadline. Tasks without a deadline
/// run after all that have one, round-robin in slices of `slice_ticks`; ties
/// are served in arrival order. A task keeps its deadline across yields and
/// preemptions.
///
/// The tick count is advanced by the first CPU that calls [`Scheduler::tick`]
/// (override with [`EdfScheduler::with_clock`]). With
/// [`EdfScheduler::with_stealing`], an idle CPU takes the earliest-deadline
/// task it may run from another CPU's queue.
pub struct EdfScheduler {
    queues: PerCpu<IrqSpinLock<EdfQueue>>,
    slice: u32,
    steal: bool,
    steals: AtomicUsize,
    ticks: AtomicU64,
    /// CPU id + 1 of the CPU that advances `ticks`; 0 until the first tick.
    keeper: AtomicUsize,
    clock: Option<fn() -> u64>,
}

impl EdfScheduler {
    /// Creates the policy; tasks without a deadline share the CPU in slices
    /// of `slice_ticks` ticks.
    pub const fn new(slice_ticks: u32) -> Self {
        Self {
            queues: PerCpu::new([const { IrqSpinLock::new(EdfQueue { seq: 0, tasks: TaskTree::new() }) }; MAX_CPUS]),
            slice: slice_ticks,
            steal: false,
            steals: AtomicUsize::new(0),
            ticks: AtomicU64::new(0),
            keeper: AtomicUsize::new(0),
            clock: None,
        }
    }

    /// Enables work stealing between CPUs.
    pub const fn with_stealing(mut self) -> Self {
        self.steal = true;
        self
    }

    /// Takes the current time from `clock` instead of counting ticks.
    pub const fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Tasks moved between CPUs by stealing so far.
    pub fn steals(&self) -> usize {
        self.steals.load(Ordering::Relaxed)
    }

    /// Number of tasks waiting on `cpu`.
    pub fn queued(&self, cpu: usize) -> usize {
        self.queues.for_cpu(cpu).lock().tasks.len()
    }

    fn now(&self) -> u64 {
        match self.clock {
            Some(c) => c(),
            None => self.ticks.load(Ordering::Relaxed),
        }
    }

    fn release(&self, task: &Task) {
        let now = self.now();
        let rel = task.deadline();
        let period = task.period();
        let mut release = now;
        let last = task.release.load(Ordering::Relaxed);
        if period != 0 && last != u64::MAX {
            let next = last.saturating_add(period);
            if next > now {
                release = next;
            }
        }
        task.release.store(release, Ordering::Relaxed);
        let abs = if rel == 0 { u64::MAX } else { release.saturating_add(rel) };
        task.abs_deadline.store(abs, Ordering::Relaxed);
    }

    fn steal_for(&self, cpu: usize) -> Option<Arc<Task>> {
        for off in 1..MAX_CPUS {
            let victim = (cpu + off) % MAX_CPUS;
            let mut q = self.queues.for_cpu(victim).lock();
            if let Some(t) = q.tasks.remove_first_where(|t| t.stealable_by(cpu)) {
                self.steals.fetch_add(1, Ordering::Relaxed);
                return Some(t);
            }
        }
        None
    }
}

impl Scheduler for EdfScheduler {
    fn enqueue(&self, task: Arc<Task>, reason: EnqueueReason) {
        if matches!(reason, EnqueueReason::Spawned | EnqueueReason::Woken) {
            self.release(&task);
        }
        task.slice_left.store(self.slice, Ordering::Relaxed);
        let abs = task.abs_deadline.load(Ordering::Relaxed);
        let mut q = self.queues.for_cpu(task.cpu()).lock();
        q.seq += 1;
        let seq = q.seq;
        q.tasks.insert(task, (abs, seq));
    }

    fn pick_next(&self, cpu: usize) -> Option<Arc<Task>> {
        let local = self.queues.for_cpu(cpu).lock().tasks.pop_first();
        if local.is_none() && self.steal { self.steal_for(cpu) } else { local }
    }

    fn tick(&self, cpu: usize, current: &Task) -> bool {
        if self.clock.is_none() {
            let me = cpu + 1;
            let k = self.keeper.load(Ordering::Relaxed);
            if k == me || (k == 0 && self.keeper.compare_exchange(0, me, Ordering::Relaxed, Ordering::Relaxed).is_ok())
            {
                self.ticks.fetch_add(1, Ordering::Relaxed);
            }
        }
        let left = current.slice_left.load(Ordering::Relaxed).saturating_sub(1);
        current.slice_left.store(left, Ordering::Relaxed);
        let mine = current.abs_deadline.load(Ordering::Relaxed);
        match self.queues.for_cpu(cpu).lock().tasks.first_key() {
            Some((abs, _)) => abs < mine || (abs == mine && left == 0),
            None => false,
        }
    }

    fn balances(&self) -> bool {
        self.steal
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
    fn stealing_respects_affinity() {
        let s = FifoScheduler::new(3).with_stealing();
        let pinned = TaskBuilder::new("pinned").cpu(42).build(|| {});
        let free = TaskBuilder::new("free").cpu(42).build(|| {});
        free.set_affinity(crate::ALL_CPUS);
        s.enqueue(pinned.clone(), EnqueueReason::Spawned);
        s.enqueue(free.clone(), EnqueueReason::Spawned);
        assert_eq!(s.pick_next(43).unwrap().name(), "free", "the unpinned task moves");
        assert!(s.pick_next(43).is_none(), "the pinned one stays");
        assert_eq!(s.steals(), 1);
        assert_eq!(s.pick_next(42).unwrap().name(), "pinned");

        let p = PriorityScheduler::new(2).with_stealing();
        let low = TaskBuilder::new("low").priority(1).affinity(1 << 44 | 1 << 45).build(|| {});
        let high = TaskBuilder::new("high").priority(9).affinity(1 << 44 | 1 << 45).build(|| {});
        low.set_cpu(44);
        high.set_cpu(44);
        p.enqueue(low, EnqueueReason::Spawned);
        p.enqueue(high, EnqueueReason::Spawned);
        assert_eq!(p.pick_next(45).unwrap().name(), "high", "steals the highest priority");
        assert_eq!(p.pick_next(46).map(|t| t.name()), None, "not allowed on CPU 46");
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

    #[test]
    fn edf_order_and_preemption() {
        let s = EdfScheduler::new(2);
        let late = TaskBuilder::new("late").deadline(50).cpu(50).build(|| {});
        let soon = TaskBuilder::new("soon").deadline(5).cpu(50).build(|| {});
        let none = TaskBuilder::new("none").cpu(50).build(|| {});
        s.enqueue(none.clone(), EnqueueReason::Spawned);
        s.enqueue(late.clone(), EnqueueReason::Spawned);
        assert!(s.tick(50, &none), "a deadline beats none");
        assert_eq!(s.pick_next(50).unwrap().name(), "late");
        assert!(!s.tick(50, &late), "only best-effort waits");
        s.enqueue(soon.clone(), EnqueueReason::Woken);
        assert!(s.tick(50, &late), "earlier deadline woken: preempt");
        assert_eq!(s.pick_next(50).unwrap().name(), "soon");
        s.enqueue(late.clone(), EnqueueReason::Preempted);
        assert_eq!(s.pick_next(50).unwrap().name(), "late");
        assert_eq!(s.pick_next(50).unwrap().name(), "none");
        assert!(s.pick_next(50).is_none());
    }

    #[test]
    fn edf_deadlines_follow_the_clock_and_period() {
        let s = EdfScheduler::new(2);
        let idle = TaskBuilder::new("cur").cpu(51).build(|| {});
        let p = TaskBuilder::new("p").deadline(10).period(100).cpu(51).build(|| {});
        s.enqueue(p.clone(), EnqueueReason::Spawned);
        assert_eq!(p.abs_deadline.load(Ordering::Relaxed), 10);
        let p = s.pick_next(51).unwrap();
        for _ in 0..30 {
            s.tick(51, &idle);
        }
        s.enqueue(p.clone(), EnqueueReason::Woken);
        assert_eq!(p.abs_deadline.load(Ordering::Relaxed), 110, "released at the next period start");
        let q = TaskBuilder::new("q").deadline(20).cpu(51).build(|| {});
        s.enqueue(q, EnqueueReason::Spawned);
        assert_eq!(s.pick_next(51).unwrap().name(), "q", "deadline 50 before 110");
    }

    #[test]
    fn edf_equal_deadlines_are_fifo_and_sliced() {
        let s = EdfScheduler::new(2);
        let a = TaskBuilder::new("a").deadline(9).cpu(52).build(|| {});
        let b = TaskBuilder::new("b").deadline(9).cpu(52).build(|| {});
        s.enqueue(a.clone(), EnqueueReason::Spawned);
        s.enqueue(b, EnqueueReason::Spawned);
        let a = s.pick_next(52).unwrap();
        assert_eq!(a.name(), "a");
        assert!(!s.tick(52, &a));
        assert!(s.tick(52, &a), "slice spent, equal deadline waiting");
    }

    #[test]
    fn edf_stealing_respects_affinity() {
        let s = EdfScheduler::new(2).with_stealing();
        let pinned = TaskBuilder::new("pinned").deadline(1).cpu(53).build(|| {});
        let far = TaskBuilder::new("far").deadline(90).affinity(1 << 53 | 1 << 54).build(|| {});
        let near = TaskBuilder::new("near").deadline(20).affinity(1 << 53 | 1 << 54).build(|| {});
        for t in [&pinned, &far, &near] {
            t.set_cpu_unpinned(53);
        }
        s.enqueue(pinned, EnqueueReason::Spawned);
        s.enqueue(far, EnqueueReason::Spawned);
        s.enqueue(near, EnqueueReason::Spawned);
        assert_eq!(s.pick_next(54).unwrap().name(), "near", "earliest movable deadline");
        assert_eq!(s.pick_next(54).unwrap().name(), "far");
        assert!(s.pick_next(54).is_none(), "pinned stays");
        assert_eq!(s.steals(), 2);
        assert_eq!(s.pick_next(53).unwrap().name(), "pinned");
    }

    #[test]
    fn edf_smp_hammer() {
        use std::sync::Arc as StdArc;
        let s = StdArc::new(EdfScheduler::new(2).with_stealing());
        let total = 400usize;
        for i in 0..total {
            let t = TaskBuilder::new("w")
                .deadline(1 + (i as u64 * 7) % 50)
                .affinity(1 << 56 | 1 << 57 | 1 << 58)
                .build(|| {});
            t.set_cpu_unpinned(56 + i % 3);
            s.enqueue(t, EnqueueReason::Spawned);
        }
        let done = StdArc::new(AtomicUsize::new(0));
        let hs: std::vec::Vec<_> = (0..3)
            .map(|n| {
                let (s, done) = (s.clone(), done.clone());
                std::thread::spawn(move || {
                    let mut idle = 0;
                    while idle < 1000 {
                        match s.pick_next(56 + n) {
                            Some(t) => {
                                idle = 0;
                                done.fetch_add(1, Ordering::Relaxed);
                                drop(t);
                            }
                            None => idle += 1,
                        }
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(done.load(Ordering::Relaxed), total, "every task taken exactly once");
    }
}
