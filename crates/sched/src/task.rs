use alloc::boxed::Box;
use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::fmt;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::context::Context;
use crate::sync::WaitQueue;

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
    /// Remaining ticks of the current time slice; policies use it.
    pub(crate) slice_left: AtomicU32,
    pub(crate) entry: UnsafeCell<Option<Entry>>,
    _stack: Option<Box<[MaybeUninit<u128>]>>,
    pub(crate) exit_waiters: WaitQueue,
}

// SAFETY: `ctx` is only touched by the CPU switching the task in or out,
// serialized by `on_cpu`; `entry` is taken once by the task itself.
unsafe impl Sync for Task {}
// SAFETY: as above.
unsafe impl Send for Task {}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

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

    /// The CPU the task last ran on or is assigned to.
    pub fn cpu(&self) -> usize {
        self.cpu.load(Ordering::Relaxed)
    }

    /// Moves the task to `cpu`'s run queue the next time it is queued.
    pub fn set_cpu(&self, cpu: usize) {
        assert!(cpu < osmium_arch::MAX_CPUS);
        self.cpu.store(cpu, Ordering::Relaxed);
    }

    /// Returns true if this is a CPU's idle task.
    pub fn is_idle(&self) -> bool {
        self.is_idle
    }

    /// Blocks the calling task until this one exits.
    pub fn join(&self) {
        self.exit_waiters.wait_until(|| (self.state() == TaskState::Exited).then_some(()));
    }

    pub(crate) fn bootstrap(cpu: usize) -> Self {
        Self::raw("boot", None, None, cpu, false)
    }

    pub(crate) fn idle(cpu: usize, stack_size: usize) -> Arc<Self> {
        let t = Self::raw("idle", Some(stack_size), None, cpu, true);
        Arc::new(t)
    }

    fn raw(name: &'static str, stack_size: Option<usize>, entry: Option<Entry>, cpu: usize, is_idle: bool) -> Self {
        let stack = stack_size.map(|s| Box::new_uninit_slice(s.div_ceil(16)));
        let ctx = match &stack {
            Some(s) => {
                let top = s.as_ptr() as usize + s.len() * 16;
                let entry_fn = if is_idle { crate::core_sched::idle_entry } else { crate::core_sched::task_entry };
                // SAFETY: the stack is owned by the task and outlives its context.
                unsafe { Context::new(top, entry_fn) }
            }
            None => Context::default(),
        };
        Self {
            id: TaskId(NEXT_ID.fetch_add(1, Ordering::Relaxed)),
            name,
            ctx: UnsafeCell::new(ctx),
            state: AtomicU8::new(if stack.is_none() { TaskState::Running as u8 } else { TaskState::Ready as u8 }),
            on_cpu: AtomicBool::new(stack.is_none()),
            is_idle,
            priority: AtomicU8::new(0),
            cpu: AtomicUsize::new(cpu),
            slice_left: AtomicU32::new(0),
            entry: UnsafeCell::new(entry),
            _stack: stack,
            exit_waiters: WaitQueue::new(),
        }
    }
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task").field("id", &self.id).field("name", &self.name).field("state", &self.state()).finish()
    }
}

/// Configures and creates a [`Task`].
#[derive(Clone, Debug)]
pub struct TaskBuilder {
    name: &'static str,
    stack_size: usize,
    priority: u8,
    cpu: Option<usize>,
}

impl TaskBuilder {
    /// Default kernel stack size.
    pub const DEFAULT_STACK: usize = 64 * 1024;

    /// Starts building a task called `name`.
    pub fn new(name: &'static str) -> Self {
        Self { name, stack_size: Self::DEFAULT_STACK, priority: 0, cpu: None }
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

    /// Places the task on `cpu` (default: the spawning CPU).
    pub fn cpu(mut self, cpu: usize) -> Self {
        self.cpu = Some(cpu);
        self
    }

    /// Creates the task without making it runnable; see [`crate::spawn`].
    pub fn build(self, f: impl FnOnce() + Send + 'static) -> Arc<Task> {
        let cpu = self.cpu.unwrap_or_else(osmium_arch::cpu::current_id);
        let t = Task::raw(self.name, Some(self.stack_size), Some(Box::new(f)), cpu, false);
        t.priority.store(self.priority, Ordering::Relaxed);
        Arc::new(t)
    }

    /// Creates the task and makes it runnable.
    pub fn spawn(self, f: impl FnOnce() + Send + 'static) -> Arc<Task> {
        let t = self.build(f);
        crate::spawn(t.clone());
        t
    }
}
