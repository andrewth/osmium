use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;
use core::cell::UnsafeCell;
use core::fmt;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use osmium_arch::fp::{FpState, SveState};
pub use osmium_sync::fallible::OutOfMemory;
use osmium_sync::fallible::{try_arc, try_box, try_uninit_slice};

use osmium_sync::intrusive::{Link, TreeLink};

use crate::context::Context;
use crate::queue::EdfKey;
use crate::sync::WaitQueue;

/// Affinity mask allowing every CPU.
pub const ALL_CPUS: u64 = u64::MAX;

/// A task's unique id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaskId(pub u64);

/// Lifecycle state of a task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    /// Runnable and waiting in a run queue.
    Ready = 0,
    /// Running on a CPU.
    Running = 1,
    /// Waiting for a wake-up.
    Blocked = 2,
    /// Finished; its stack is freed when the last reference goes.
    Exited = 3,
}

impl TaskState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Ready,
            1 => Self::Running,
            2 => Self::Blocked,
            _ => Self::Exited,
        }
    }
}

type Entry = Box<dyn FnOnce() + Send>;

/// Supplies task stacks, for kernels that want guard pages or stacks in a
/// dedicated virtual region. Without one, stacks come from the heap.
///
/// # Safety
/// `alloc` must return memory that is exclusively owned, writable, 16-byte
/// aligned and at least `size` bytes long, until passed to `free`.
pub unsafe trait StackAllocator: Sync {
    /// Allocates a stack of at least `size` bytes; returns its lowest
    /// usable address and its usable length.
    fn alloc(&self, size: usize) -> Option<(NonNull<u8>, usize)>;
    /// Frees a stack returned by `alloc`.
    ///
    /// # Safety
    /// `base` and `len` must come from `alloc`, and nothing may run on the
    /// stack any more.
    unsafe fn free(&self, base: NonNull<u8>, len: usize);
}

static STACK_ALLOCATOR: osmium_sync::Once<&'static dyn StackAllocator> = osmium_sync::Once::new();

/// Installs the stack allocator used for tasks created from now on. Panics
/// if called twice.
pub fn set_stack_allocator(alloc: &'static dyn StackAllocator) {
    assert!(STACK_ALLOCATOR.set(alloc).is_ok(), "stack allocator already set");
}

enum Stack {
    Heap(Box<[MaybeUninit<u128>]>),
    Custom { base: NonNull<u8>, len: usize, alloc: &'static dyn StackAllocator },
}

impl Stack {
    fn try_new(size: usize) -> Result<Self, OutOfMemory> {
        match STACK_ALLOCATOR.get() {
            Some(a) => {
                let (base, len) = a.alloc(size).ok_or(OutOfMemory)?;
                Ok(Stack::Custom { base, len, alloc: *a })
            }
            None => Ok(Stack::Heap(try_uninit_slice(size.div_ceil(16))?)),
        }
    }

    /// Lowest usable byte.
    fn bottom(&self) -> usize {
        match self {
            Stack::Heap(s) => s.as_ptr() as usize,
            Stack::Custom { base, .. } => base.as_ptr() as usize,
        }
    }

    /// One past the highest usable byte, 16-byte aligned.
    fn top(&self) -> usize {
        match self {
            Stack::Heap(s) => s.as_ptr() as usize + s.len() * 16,
            Stack::Custom { base, len, .. } => (base.as_ptr() as usize + len) & !15,
        }
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        if let Stack::Custom { base, len, alloc } = *self {
            // SAFETY: the stack came from this allocator, and the task that
            // used it has exited (its last reference is gone).
            unsafe { alloc.free(base, len) }
        }
    }
}

/// A schedulable thread of execution with its own kernel stack.
pub struct Task {
    id: TaskId,
    name: &'static str,
    pub(crate) ctx: UnsafeCell<Context>,
    pub(crate) state: AtomicU8,
    /// True from the moment a CPU switches to the task until another task on
    /// that CPU has finished saving its registers. A CPU that picks the task
    /// spins until it is false.
    pub(crate) on_cpu: AtomicBool,
    pub(crate) is_idle: bool,
    priority: AtomicU8,
    cpu: AtomicUsize,
    /// CPUs the task may run on (bit `n` = CPU `n`); policies that move
    /// tasks between CPUs respect it.
    affinity: AtomicU64,
    /// Remaining ticks of the current time slice; policies use it.
    pub(crate) slice_left: AtomicU32,
    /// Relative deadline in ticks (0 = none); see [`crate::EdfScheduler`].
    rel_deadline: AtomicU64,
    /// Period in ticks (0 = aperiodic).
    period: AtomicU64,
    /// Absolute deadline and release time, kept by [`crate::EdfScheduler`].
    pub(crate) abs_deadline: AtomicU64,
    pub(crate) release: AtomicU64,
    pub(crate) entry: UnsafeCell<Option<Entry>>,
    /// Links the task into a wait queue or (except under EDF) a run queue.
    /// Used by one at a time: see [`crate::queue`].
    pub(crate) link: Link,
    /// Links the task into an EDF run queue, ordered by `edf_key`.
    pub(crate) tree: TreeLink,
    pub(crate) edf_key: EdfKey,
    _stack: Option<Stack>,
    pub(crate) exit_waiters: WaitQueue,
    data: osmium_sync::Once<Box<dyn Any + Send + Sync>>,
    /// FP/SIMD registers, saved while the task is switched out; see
    /// [`TaskBuilder::fp_state`].
    pub(crate) fp: Option<Box<UnsafeCell<FpState>>>,
    /// SVE registers, used instead of `fp` by tasks that have them; see
    /// [`TaskBuilder::sve_state`].
    pub(crate) sve: Option<Box<UnsafeCell<SveState>>>,
}

// SAFETY: `ctx` and `fp` are only touched by the CPU switching the task in
// or out, serialized by `on_cpu`; `entry` is taken once by the task itself.
unsafe impl Sync for Task {}
// SAFETY: as above.
unsafe impl Send for Task {}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// The affinity-mask bit of `cpu`, or 0 for a CPU number beyond the mask.
fn cpu_bit(cpu: usize) -> u64 {
    u32::try_from(cpu).ok().and_then(|c| 1u64.checked_shl(c)).unwrap_or(0)
}

impl Task {
    /// The task's id.
    pub fn id(&self) -> TaskId {
        self.id
    }

    /// The task's name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Current lifecycle state.
    pub fn state(&self) -> TaskState {
        TaskState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// Scheduling priority (0–63, higher runs first under [`crate::PriorityScheduler`]).
    pub fn priority(&self) -> u8 {
        self.priority.load(Ordering::Relaxed)
    }

    /// Changes the priority; takes effect the next time the task is queued.
    pub fn set_priority(&self, p: u8) {
        self.priority.store(p.min(63), Ordering::Relaxed);
    }

    /// Relative deadline in ticks, 0 if none; used by [`crate::EdfScheduler`].
    pub fn deadline(&self) -> u64 {
        self.rel_deadline.load(Ordering::Relaxed)
    }

    /// Sets the relative deadline in ticks (0 = none, scheduled after every
    /// task that has one); takes effect the next time the task is released.
    pub fn set_deadline(&self, ticks: u64) {
        self.rel_deadline.store(ticks, Ordering::Relaxed);
    }

    /// Period in ticks, 0 if the task is not periodic.
    pub fn period(&self) -> u64 {
        self.period.load(Ordering::Relaxed)
    }

    /// Sets the period in ticks (0 = aperiodic); see [`crate::EdfScheduler`].
    pub fn set_period(&self, ticks: u64) {
        self.period.store(ticks, Ordering::Relaxed);
    }

    /// The CPU the task last ran on or is assigned to.
    pub fn cpu(&self) -> usize {
        self.cpu.load(Ordering::Relaxed)
    }

    /// Moves the task to `cpu`'s run queue the next time it is queued. A
    /// task pinned to one CPU stays pinned, to the new one.
    ///
    /// Does nothing if `cpu` is not below [`osmium_arch::MAX_CPUS`], or the
    /// task's affinity does not allow it (the scheduler could never run it
    /// there).
    pub fn set_cpu(&self, cpu: usize) {
        if cpu >= osmium_arch::MAX_CPUS || (self.affinity().count_ones() != 1 && !self.can_run_on(cpu)) {
            return;
        }
        if self.affinity().count_ones() == 1 {
            self.affinity.store(cpu_bit(cpu), Ordering::Relaxed);
        }
        self.cpu.store(cpu, Ordering::Relaxed);
    }

    /// Pins the task to `cpu`: it moves there the next time it is queued
    /// and no policy moves it elsewhere.
    ///
    /// Does nothing if `cpu` is not below [`osmium_arch::MAX_CPUS`].
    pub fn pin(&self, cpu: usize) {
        if cpu >= osmium_arch::MAX_CPUS {
            return;
        }
        self.affinity.store(cpu_bit(cpu), Ordering::Relaxed);
        self.cpu.store(cpu, Ordering::Relaxed);
    }

    /// Moves the task to `cpu` without changing its affinity; the core uses
    /// it to place an unpinned task, which `cpu` is already allowed to run.
    pub(crate) fn set_cpu_unpinned(&self, cpu: usize) {
        self.cpu.store(cpu, Ordering::Relaxed);
    }

    /// The CPUs the task may run on (bit `n` = CPU `n`).
    ///
    pub fn affinity(&self) -> u64 {
        self.affinity.load(Ordering::Relaxed)
    }

    /// Restricts the task to the CPUs in `mask`. If its current CPU is not
    /// among them, it moves to the lowest one the next time it is queued.
    ///
    /// An empty `mask` is ignored: a task must be allowed on some CPU.
    pub fn set_affinity(&self, mask: u64) {
        if mask == 0 {
            return;
        }
        self.affinity.store(mask, Ordering::Relaxed);
        if mask & cpu_bit(self.cpu()) == 0 {
            self.cpu.store(mask.trailing_zeros() as usize, Ordering::Relaxed);
        }
    }

    /// Returns true if the task may run on `cpu`.
    pub fn can_run_on(&self, cpu: usize) -> bool {
        self.affinity() & cpu_bit(cpu) != 0
    }

    /// Returns true if `cpu` may take the task from another CPU's queue now.
    /// A task still saving its registers on its old CPU is skipped: two CPUs
    /// that each steal the other's just-requeued task would wait on each
    /// other forever.
    pub(crate) fn stealable_by(&self, cpu: usize) -> bool {
        self.can_run_on(cpu) && !self.on_cpu.load(Ordering::Acquire)
    }

    /// One past the top of the task's kernel stack, if it owns one (the
    /// per-CPU boot tasks run on stacks the kernel set up itself).
    pub fn kernel_stack_top(&self) -> Option<usize> {
        self._stack.as_ref().map(Stack::top)
    }

    /// The task's kernel stack, lowest to one past the highest usable
    /// address, if it owns one. Trap paths use the bottom to detect overflow.
    pub fn kernel_stack_range(&self) -> Option<core::ops::Range<usize>> {
        self._stack.as_ref().map(|s| s.bottom()..s.top())
    }

    /// Attaches kernel-defined data (an address space, credentials, a file
    /// table, ...). Each task holds at most one value; returns it back if
    /// one is already set.
    pub fn set_data<T: Any + Send + Sync>(&self, value: T) -> Result<(), T> {
        let mut value = Some(value);
        // The closure runs at most once; if it somehow did not, `value` stays `Some` and is handed back.
        self.data.call_once(|| {
            let boxed: Box<dyn Any + Send + Sync> = match value.take() {
                Some(v) => Box::new(v),
                None => Box::new(()),
            };
            boxed
        });
        match value {
            None => Ok(()),
            Some(v) => Err(v),
        }
    }

    /// The data attached with [`Task::set_data`] or [`TaskBuilder::data`],
    /// if it is a `T`.
    pub fn data<T: Any>(&self) -> Option<&T> {
        self.data.get()?.downcast_ref()
    }

    /// Returns true if this is a CPU's idle task.
    pub fn is_idle(&self) -> bool {
        self.is_idle
    }

    /// Blocks the calling task until this one exits.
    pub fn join(&self) {
        self.exit_waiters.wait_until(|| (self.state() == TaskState::Exited).then_some(()));
    }

    #[allow(clippy::expect_used)] // invariant: with no stack to allocate, `raw` cannot fail.
    pub(crate) fn bootstrap(cpu: usize) -> Self {
        let t = Self::raw("boot", None, None, cpu, false).expect("no stack to allocate");
        // It runs on this CPU's boot stack (on hosted builds, a thread's own
        // stack): never let another CPU steal it.
        t.affinity.store(cpu_bit(cpu), Ordering::Relaxed);
        t
    }

    #[allow(clippy::expect_used)] // boot-time integrator path (`init_cpu`); the `try_` APIs are for runtime.
    pub(crate) fn idle(cpu: usize, stack_size: usize) -> Arc<Self> {
        let t = Self::raw("idle", Some(stack_size), None, cpu, true).expect("out of memory for an idle task");
        Arc::new(t)
    }

    fn raw(
        name: &'static str,
        stack_size: Option<usize>,
        entry: Option<Entry>,
        cpu: usize,
        is_idle: bool,
    ) -> Result<Self, OutOfMemory> {
        let stack = stack_size.map(Stack::try_new).transpose()?;
        let ctx = match &stack {
            Some(s) => {
                let top = s.top();
                let entry_fn = if is_idle { crate::core_sched::idle_entry } else { crate::core_sched::task_entry };
                // SAFETY: the stack is owned by the task and outlives its context.
                unsafe { Context::new(top, entry_fn) }
            }
            None => Context::default(),
        };
        Ok(Self {
            id: TaskId(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            name,
            ctx: UnsafeCell::new(ctx),
            state: AtomicU8::new(if stack.is_none() { TaskState::Running as u8 } else { TaskState::Ready as u8 }),
            on_cpu: AtomicBool::new(stack.is_none()),
            is_idle,
            priority: AtomicU8::new(0),
            cpu: AtomicUsize::new(cpu),
            affinity: AtomicU64::new(ALL_CPUS),
            slice_left: AtomicU32::new(0),
            rel_deadline: AtomicU64::new(0),
            period: AtomicU64::new(0),
            abs_deadline: AtomicU64::new(u64::MAX),
            release: AtomicU64::new(u64::MAX),
            entry: UnsafeCell::new(entry),
            link: Link::new(),
            tree: TreeLink::new(),
            edf_key: UnsafeCell::new((0, 0)),
            _stack: stack,
            exit_waiters: WaitQueue::new(),
            data: osmium_sync::Once::new(),
            fp: None,
            sve: None,
        })
    }
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task").field("id", &self.id).field("name", &self.name).field("state", &self.state()).finish()
    }
}

/// Configures and creates a [`Task`].
pub struct TaskBuilder {
    name: &'static str,
    stack_size: usize,
    priority: u8,
    cpu: Option<usize>,
    affinity: u64,
    deadline: u64,
    period: u64,
    data: Option<Box<dyn Any + Send + Sync>>,
    fp: Option<FpState>,
    sve: bool,
}

impl fmt::Debug for TaskBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskBuilder").field("name", &self.name).field("cpu", &self.cpu).finish_non_exhaustive()
    }
}

impl TaskBuilder {
    /// Default kernel stack size.
    pub const DEFAULT_STACK: usize = 64 * 1024;

    /// Starts building a task called `name`.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            stack_size: Self::DEFAULT_STACK,
            priority: 0,
            cpu: None,
            affinity: ALL_CPUS,
            deadline: 0,
            period: 0,
            data: None,
            fp: None,
            sve: false,
        }
    }

    /// Sets the stack size in bytes.
    pub fn stack_size(mut self, bytes: usize) -> Self {
        self.stack_size = bytes;
        self
    }

    /// Sets the priority (0–63).
    pub fn priority(mut self, p: u8) -> Self {
        self.priority = p.min(63);
        self
    }

    /// Pins the task to `cpu`. By default it starts on the spawning CPU and
    /// load-balancing policies may move it.
    ///
    /// A `cpu` that is not below [`osmium_arch::MAX_CPUS`] is ignored.
    pub fn cpu(mut self, cpu: usize) -> Self {
        if cpu < osmium_arch::MAX_CPUS {
            self.cpu = Some(cpu);
            self.affinity = cpu_bit(cpu);
        }
        self
    }

    /// Restricts the task to the CPUs in `mask` (bit `n` = CPU `n`).
    ///
    /// An empty `mask` is ignored: a task must be allowed on some CPU.
    pub fn affinity(mut self, mask: u64) -> Self {
        if mask != 0 {
            self.affinity = mask;
        }
        self
    }

    /// Sets the relative deadline in ticks for [`crate::EdfScheduler`].
    pub fn deadline(mut self, ticks: u64) -> Self {
        self.deadline = ticks;
        self
    }

    /// Sets the period in ticks for [`crate::EdfScheduler`].
    pub fn period(mut self, ticks: u64) -> Self {
        self.period = ticks;
        self
    }

    /// Attaches data before the task first runs, so a switch hook sees it
    /// on the very first switch; see [`Task::data`].
    ///
    /// # Panics
    /// If memory runs out: [`TaskBuilder::try_data`] reports that instead.
    #[allow(clippy::expect_used)] // documented `# Panics` on OOM; `try_data` is the fallible form.
    pub fn data<T: Any + Send + Sync>(self, value: T) -> Self {
        self.try_data(value).expect("out of memory for task data")
    }

    /// [`TaskBuilder::data`], failing instead of panicking if memory runs out.
    pub fn try_data<T: Any + Send + Sync>(mut self, value: T) -> Result<Self, OutOfMemory> {
        let data: Box<dyn Any + Send + Sync> = try_box(value)?;
        self.data = Some(data);
        Ok(self)
    }

    /// Gives the task its own FP/SIMD registers, starting as `state`: the
    /// context switch saves them when the task leaves a CPU and loads them
    /// when it arrives. For tasks that run user code that may use FP; every
    /// CPU that runs the task must have had [`osmium_arch::fp::enable`]
    /// succeed. Tasks without one leave the registers as they find them.
    pub fn fp_state(mut self, state: FpState) -> Self {
        self.fp = Some(state);
        self
    }

    /// Gives the task its own SVE registers (all zero to start), switched in
    /// place of the FP/SIMD registers [`TaskBuilder::fp_state`] would give:
    /// SVE's `z` registers contain `q0`..`q31`. For tasks that run user code
    /// that may use SVE; every CPU that runs the task must have had
    /// [`osmium_arch::fp::sve::enable`] return `Some` (with the same vector
    /// length). Overrides `fp_state`.
    pub fn sve_state(mut self) -> Self {
        self.sve = true;
        self
    }

    /// Creates the task without making it runnable; see [`crate::spawn`].
    ///
    /// # Panics
    /// If memory runs out: [`TaskBuilder::try_build`] reports that instead.
    #[allow(clippy::expect_used)] // documented `# Panics` on OOM; `try_build` is the fallible form.
    pub fn build(self, f: impl FnOnce() + Send + 'static) -> Arc<Task> {
        self.try_build(f).expect("out of memory for a task")
    }

    /// [`TaskBuilder::build`], failing instead of panicking if memory runs
    /// out (for the stack, the entry closure, the FP registers or the task
    /// itself). Nothing is left allocated on failure.
    pub fn try_build(self, f: impl FnOnce() + Send + 'static) -> Result<Arc<Task>, OutOfMemory> {
        let mut cpu = self.cpu.unwrap_or_else(osmium_arch::cpu::current_id);
        if self.affinity & cpu_bit(cpu) == 0 {
            cpu = self.affinity.trailing_zeros() as usize;
        }
        let entry: Entry = try_box(f)?;
        let mut t = Task::raw(self.name, Some(self.stack_size), Some(entry), cpu, false)?;
        if self.sve {
            t.sve = Some(try_box(UnsafeCell::new(SveState::new()))?);
        } else {
            t.fp = self.fp.map(|s| try_box(UnsafeCell::new(s))).transpose()?;
        }
        t.priority.store(self.priority, Ordering::Relaxed);
        t.affinity.store(self.affinity, Ordering::Relaxed);
        t.rel_deadline.store(self.deadline, Ordering::Relaxed);
        t.period.store(self.period, Ordering::Relaxed);
        if let Some(d) = self.data {
            t.data.call_once(|| d);
        }
        try_arc(t)
    }

    /// Creates the task and makes it runnable.
    ///
    /// # Panics
    /// If memory runs out: [`TaskBuilder::try_spawn`] reports that instead.
    #[allow(clippy::expect_used)] // documented `# Panics` on OOM; `try_spawn` is the fallible form.
    pub fn spawn(self, f: impl FnOnce() + Send + 'static) -> Arc<Task> {
        self.try_spawn(f).expect("out of memory for a task")
    }

    /// [`TaskBuilder::spawn`], failing instead of panicking if memory runs
    /// out. The task exists and is queued only on success.
    pub fn try_spawn(self, f: impl FnOnce() + Send + 'static) -> Result<Arc<Task>, OutOfMemory> {
        let t = self.try_build(f)?;
        crate::spawn(t.clone());
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_cpu_and_affinity_are_ignored() {
        let t = TaskBuilder::new("t").affinity(1 << 2 | 1 << 3).cpu(usize::MAX).affinity(0).build(|| {});
        let before = (t.cpu(), t.affinity());
        t.set_cpu(5);
        t.set_cpu(usize::MAX);
        t.pin(64);
        t.pin(usize::MAX);
        t.set_affinity(0);
        assert_eq!((t.cpu(), t.affinity()), before);
        assert!(!t.can_run_on(usize::MAX));
    }

    #[test]
    fn set_cpu_inside_affinity() {
        let t = TaskBuilder::new("t").affinity(1 << 2 | 1 << 3).build(|| {});
        t.set_cpu(3);
        assert_eq!(t.cpu(), 3);
    }
}
