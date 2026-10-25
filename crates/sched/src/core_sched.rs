use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use osmium_arch::fp::{self, FpState};
use osmium_arch::{MAX_CPUS, cpu, irq};
use osmium_sync::{Once, PerCpu, PerCpuCell, preempt};

use crate::context;
use crate::task::{Task, TaskState};

/// Why a task is being put on a run queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueReason {
    /// Newly spawned.
    Spawned,
    /// Gave up the CPU voluntarily.
    Yielded,
    /// Its time slice ran out.
    Preempted,
    /// Was blocked and has been woken.
    Woken,
}

/// A scheduling policy.
///
/// All methods are called with local interrupts disabled. Implementations
/// own the run queues; the core owns the current task and the context
/// switch.
pub trait Scheduler: Sync {
    /// Makes `task` runnable. Normally it goes to `task.cpu()`'s queue.
    fn enqueue(&self, task: Arc<Task>, reason: EnqueueReason);

    /// Removes and returns the task `cpu` should run next, if any.
    fn pick_next(&self, cpu: usize) -> Option<Arc<Task>>;

    /// Called on each timer tick on `cpu` while `current` runs. Returns true
    /// to request that `current` be preempted.
    fn tick(&self, cpu: usize, current: &Task) -> bool;

    /// Returns true if the policy moves unpinned tasks between CPUs (by
    /// stealing in [`Scheduler::pick_next`]). The core then places woken
    /// tasks on idle CPUs and kicks idle CPUs, through the remote-wake
    /// hook, when work they could steal is queued.
    fn balances(&self) -> bool {
        false
    }
}

static SCHEDULER: Once<&'static dyn Scheduler> = Once::new();
static REMOTE_WAKE: Once<fn(usize)> = Once::new();
static SWITCH_HOOK: Once<fn(&Task)> = Once::new();

/// Registers `hook`, called with the incoming task just before every
/// context switch, with interrupts disabled. Kernels use it for per-task
/// CPU state: the x86 TSS kernel stack ([`Task::kernel_stack_top`]), the
/// address space, or FPU state. Panics if called twice.
pub fn set_switch_hook(hook: fn(&Task)) {
    assert!(SWITCH_HOOK.set(hook).is_ok(), "switch hook already set");
}

/// Installs the scheduling policy. Panics if called twice.
pub fn inject_scheduler(scheduler: &'static dyn Scheduler) {
    assert!(SCHEDULER.set(scheduler).is_ok(), "scheduler already injected");
}

/// Unwraps state that `init_cpu` or `inject_scheduler` set up.
///
/// Panics if the integrator skipped that call; no input from outside can do so.
#[allow(clippy::expect_used)] // invariant: integrator calls `init_cpu` / `inject_scheduler` before scheduling.
fn initialized<T>(value: Option<T>) -> T {
    value.expect("init_cpu has not run on this CPU, or no scheduler was injected")
}

fn scheduler() -> &'static dyn Scheduler {
    *initialized(SCHEDULER.get())
}

/// Registers `hook`, called with a CPU id whenever a task is queued on a CPU
/// other than the calling one. Kernels use it to send an inter-processor
/// interrupt so an idle CPU notices new work at once instead of at its next
/// timer tick. The hook runs with interrupts disabled. Panics if called twice.
pub fn set_remote_wake_hook(hook: fn(usize)) {
    assert!(REMOTE_WAKE.set(hook).is_ok(), "remote wake hook already set");
}

/// Bit `n` is set while CPU `n` has nothing to run (its idle task is chosen).
static IDLE_CPUS: AtomicU64 = AtomicU64::new(0);

/// Queues `task` and notifies its CPU if that is not this one. IRQs must be off.
///
/// With a balancing policy, a new or woken task whose CPU is busy goes to an
/// idle CPU it may use instead (pinned tasks have no other CPU to go to).
fn enqueue(task: Arc<Task>, reason: EnqueueReason) {
    let sched = scheduler();
    if sched.balances() && matches!(reason, EnqueueReason::Spawned | EnqueueReason::Woken) {
        let idle = IDLE_CPUS.load(Ordering::Relaxed) & task.affinity();
        if idle != 0 && idle & (1 << task.cpu()) == 0 {
            task.set_cpu_unpinned(idle.trailing_zeros() as usize);
        }
    }
    let target = task.cpu();
    sched.enqueue(task, reason);
    if target != cpu::current_id()
        && let Some(hook) = REMOTE_WAKE.get()
    {
        hook(target);
    }
}

struct CpuState {
    current: Option<Arc<Task>>,
    /// The task switched away from, until the next task has finished the
    /// switch and released it.
    prev: Option<Arc<Task>>,
    idle: Option<Arc<Task>>,
    /// Whether this CPU's FP/SIMD registers hold `current`'s values. Only
    /// then does a switch away have to save them.
    fp_loaded: bool,
}

static CPUS: PerCpuCell<CpuState> =
    PerCpuCell::new([const { CpuState { current: None, prev: None, idle: None, fp_loaded: false } }; MAX_CPUS]);
static NEED_RESCHED: PerCpu<AtomicBool> = PerCpu::new([const { AtomicBool::new(false) }; MAX_CPUS]);

const IDLE_STACK: usize = 16 * 1024;
/// How long `schedule` waits for a task to finish saving its registers.
const SPIN_LIMIT: u32 = 1 << 20;

/// Turns the calling flow of execution into this CPU's first task and
/// creates the CPU's idle task. Call once per CPU, after its CPU id is set
/// and before using any other function in this crate on it.
pub fn init_cpu() {
    fp::set_lazy_load(load_fp_trap);
    let cpu = cpu::current_id();
    let boot = Arc::new(Task::bootstrap(cpu));
    let idle = Task::idle(cpu, IDLE_STACK);
    CPUS.with(|st| {
        assert!(st.current.is_none(), "init_cpu called twice on CPU {cpu}");
        st.current = Some(boot);
        st.idle = Some(idle);
    });
}

/// Returns the running task.
pub fn current() -> Arc<Task> {
    CPUS.with(|st| initialized(st.current.clone()))
}

/// Makes a task built with [`crate::TaskBuilder::build`] runnable.
pub fn spawn(task: Arc<Task>) {
    task.state.store(TaskState::Ready as u8, Ordering::Release);
    irq::without(|| enqueue(task, EnqueueReason::Spawned));
}

/// Gives up the CPU to another runnable task, if there is one.
pub fn yield_now() {
    schedule(Some(EnqueueReason::Yielded));
}

/// Ends the calling task. Its stack is freed once no references remain.
pub fn exit() -> ! {
    irq::disable();
    // SAFETY: IRQs are off and the current task outlives this function (the
    // CPU state holds a reference until the next task finishes switching).
    // No `Arc` is kept in this frame, which never returns.
    let cur = unsafe { &*current_ptr() };
    assert!(!cur.is_idle, "the idle task cannot exit");
    cur.state.store(TaskState::Exited as u8, Ordering::Release);
    cur.exit_waiters.wake_all();
    schedule(None);
    // An exited task is never resumed.
    cpu::halt_forever()
}

/// Accounts a timer tick to the running task. Call from the timer interrupt.
pub fn tick() {
    irq::without(|| {
        let cpu = cpu::current_id();
        // SAFETY: IRQs are off; only this CPU uses its state.
        let cur = unsafe { &*current_ptr() };
        if !cur.is_idle && scheduler().tick(cpu, cur) {
            NEED_RESCHED.for_cpu(cpu).store(true, Ordering::Relaxed);
        }
    });
}

/// Switches tasks if a tick asked for it and preemption is enabled. Call on
/// the way out of interrupt handlers.
pub fn preempt_if_needed() {
    if preempt::count() == 0 && NEED_RESCHED.get().swap(false, Ordering::Relaxed) {
        schedule(Some(EnqueueReason::Preempted));
    }
}

/// Wakes a blocked task. Returns false if it was not blocked.
pub(crate) fn wake(task: Arc<Task>) -> bool {
    if task
        .state
        .compare_exchange(TaskState::Blocked as u8, TaskState::Ready as u8, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    irq::without(|| enqueue(task, EnqueueReason::Woken));
    true
}

/// Switches away from a task that has marked itself blocked. Returns at
/// once if it has already been woken and resumed.
pub(crate) fn block_current() {
    schedule(None);
}

/// Must be called with IRQs disabled.
fn current_ptr() -> *const Task {
    // SAFETY: the caller has IRQs disabled; we only read the pointer.
    let st = unsafe { &*CPUS.as_ptr() };
    Arc::as_ptr(initialized(st.current.as_ref()))
}

/// The core of the scheduler: optionally requeue the current task, pick the
/// next one and switch to it.
fn schedule(requeue: Option<EnqueueReason>) {
    assert_eq!(preempt::count(), 0, "scheduling while holding a spin lock");
    let irq_state = irq::save_and_disable();
    let cpu = cpu::current_id();
    let sched = scheduler();
    let st = CPUS.as_ptr();
    // SAFETY: IRQs are off, so nothing else on this CPU touches its state;
    // the current task stays alive while referenced by that state.
    let cur = unsafe { &*current_ptr() };

    match requeue {
        Some(reason) if !cur.is_idle => {
            // Only a running task is requeued: a task preempted while about
            // to block, or already woken, must not be queued twice.
            if cur
                .state
                .compare_exchange(TaskState::Running as u8, TaskState::Ready as u8, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // SAFETY: as above.
                if let Some(me) = unsafe { (*st).current.clone() } {
                    enqueue(me, reason);
                }
            }
        }
        None if !cur.is_idle && cur.state() == TaskState::Running => {
            // Woken and resumed (for example by preemption) before getting here.
            irq::restore(irq_state);
            return;
        }
        _ => {}
    }

    let mut retries = 0;
    let next = loop {
        // SAFETY: as above.
        let next = sched.pick_next(cpu).unwrap_or_else(|| initialized(unsafe { (*st).idle.clone() }));
        if ptr::eq(Arc::as_ptr(&next), cur) {
            IDLE_CPUS.fetch_and(!(1 << cpu), Ordering::Relaxed);
            if cur.is_idle {
                IDLE_CPUS.fetch_or(1 << cpu, Ordering::Relaxed);
            }
            cur.state.store(TaskState::Running as u8, Ordering::Release);
            irq::restore(irq_state);
            return;
        }
        // A task re-pinned or re-targeted while queued here may no longer be
        // allowed on this CPU; its `cpu()` was updated, so requeue it there.
        if !next.is_idle && !next.can_run_on(cpu) {
            enqueue(next, EnqueueReason::Yielded);
            continue;
        }
        // The task may still be saving its registers on the CPU that last
        // ran it. Wait briefly; if that CPU is itself waiting for one of our
        // tasks, give the task back and run something else meanwhile.
        let mut spins = 0u32;
        while next.on_cpu.load(Ordering::Acquire) && spins < SPIN_LIMIT {
            cpu::spin_hint();
            spins += 1;
        }
        if !next.on_cpu.load(Ordering::Acquire) {
            break next;
        }
        retries += 1;
        let idle = next.is_idle;
        if !idle {
            // Not `Woken`: this is not a new release, so deadlines and periods must not restart.
            sched.enqueue(next, EnqueueReason::Yielded);
        }
        if retries >= 3 || idle {
            // SAFETY: as above.
            break initialized(unsafe { (*st).idle.clone() });
        }
    };
    if next.is_idle {
        IDLE_CPUS.fetch_or(1 << cpu, Ordering::Relaxed);
    } else {
        IDLE_CPUS.fetch_and(!(1 << cpu), Ordering::Relaxed);
    }
    next.on_cpu.store(true, Ordering::Relaxed);
    // Record the CPU without touching affinity: pin()/set_affinity() may have changed it while queued.
    next.set_cpu_unpinned(cpu);
    next.state.store(TaskState::Running as u8, Ordering::Release);
    NEED_RESCHED.for_cpu(cpu).store(false, Ordering::Relaxed);
    // The kernel never uses FP, so the registers hold the values of the task
    // that loaded them last. `finish_switch` publishes the saved copy
    // (`on_cpu`) before another CPU may load it.
    // SAFETY: IRQs are off and only the CPU switching a task touches its
    // `fp` and `sve`. If FP is off on this CPU (`fp_state` misused), the
    // instructions trap; they cannot touch other memory.
    unsafe {
        fp_switch_out(st, cur);
        if let Some(sve) = &cur.sve {
            (*sve.get()).save();
        }
        fp_switch_in(st, &next);
    }
    if let Some(hook) = SWITCH_HOOK.get() {
        hook(&next);
    }

    let from = cur.ctx.get();
    let to = next.ctx.get();
    // SAFETY: IRQs are off. Moving `next` into the CPU state leaves no `Arc`
    // in this frame, so an exiting task that never resumes leaks nothing.
    unsafe { (*st).prev = (*st).current.replace(next) };
    // SAFETY: `from` is ours; `to` was saved by `switch` or built by
    // `Context::new`, and its stack is owned by the task we hold.
    unsafe { context::switch(from, to) };

    // Resumed: possibly much later, on this or another CPU.
    finish_switch();
    irq::restore(irq_state);
}

/// Saves the outgoing task's FP/SIMD registers if they are loaded on this
/// CPU. A task that never used them after its last switch has nothing to save.
///
/// # Safety
/// IRQs must be off, and `st` must be this CPU's state.
unsafe fn fp_switch_out(st: *mut CpuState, cur: &Task) {
    // SAFETY: as above.
    unsafe {
        if (*st).fp_loaded {
            (*st).fp_loaded = false;
            if let Some(fp) = &cur.fp {
                (*fp.get()).save();
            }
        }
    }
}

/// Makes the incoming task's FP/SIMD registers ready. A lazy build arms the
/// trap and loads them at the task's first FP/SIMD instruction; an eager one
/// loads them now.
///
/// # Safety
/// As for [`fp_switch_out`], which must have run first.
unsafe fn fp_switch_in(st: *mut CpuState, next: &Task) {
    // SAFETY: as above.
    unsafe {
        if let Some(sve) = &next.sve {
            // The SVE registers include the FP ones, which must not trap.
            (*sve.get()).restore();
            fp::disarm_lazy();
            (*st).fp_loaded = false;
        } else if !fp::enabled() {
            (*st).fp_loaded = false;
        } else if fp::LAZY {
            fp::arm_lazy();
            (*st).fp_loaded = false;
        } else if let Some(fp) = &next.fp {
            (*fp.get()).restore();
            (*st).fp_loaded = true;
        } else {
            (*st).fp_loaded = false;
        }
    }
}

/// The lazy FP trap's loader: gives the running task its FP/SIMD registers.
/// Runs in trap context with IRQs off, on the CPU the task runs on.
fn load_fp_trap() {
    let st = CPUS.as_ptr();
    // SAFETY: IRQs are off in trap context, so nothing else on this CPU
    // touches its state; the current task stays alive while referenced there.
    let cur = unsafe { &*current_ptr() };
    // SAFETY: the trap was armed on a CPU where `fp::enable` ran. Disarming
    // comes first, since the restore is made of FP/SIMD instructions.
    unsafe {
        fp::disarm_lazy();
        match &cur.fp {
            Some(fp) => (*fp.get()).restore(),
            None => FpState::new().restore(),
        }
        (*st).fp_loaded = true;
    }
}

/// The calling task's FP/SIMD registers, as a `fork` child starts with them.
pub fn current_fp_state() -> FpState {
    if !fp::enabled() {
        return FpState::new();
    }
    irq::without(|| {
        let st = CPUS.as_ptr();
        // SAFETY: IRQs are off, so the task stays on this CPU.
        let cur = unsafe { &*current_ptr() };
        // SAFETY: as above; `capture` is valid because FP is enabled.
        unsafe {
            if (*st).fp_loaded {
                FpState::capture()
            } else {
                cur.fp.as_ref().map_or_else(FpState::new, |fp| (*fp.get()).clone())
            }
        }
    })
}

/// Clears the calling task's FP/SIMD registers, as a new program starts with
/// them.
pub fn reset_current_fp() {
    if !fp::enabled() {
        return;
    }
    irq::without(|| {
        let st = CPUS.as_ptr();
        // SAFETY: IRQs are off, so the task stays on this CPU.
        let cur = unsafe { &*current_ptr() };
        let fresh = FpState::new();
        // SAFETY: as above; the task is running here, so no other CPU touches its `fp`.
        unsafe {
            if let Some(fp) = &cur.fp {
                *fp.get() = fresh.clone();
            }
            if fp::LAZY {
                // Whatever the registers hold is discarded; the next FP/SIMD instruction loads `fresh`.
                (*st).fp_loaded = false;
                fp::arm_lazy();
            } else {
                fresh.restore();
                (*st).fp_loaded = cur.fp.is_some();
            }
        }
    })
}

/// Releases the task we switched away from. Runs first thing after every
/// switch, on the new task's stack, with IRQs disabled.
fn finish_switch() {
    // SAFETY: IRQs are disabled across every switch.
    let prev = unsafe { (*CPUS.as_ptr()).prev.take() };
    if let Some(prev) = prev {
        // Its registers are saved: other CPUs may now run it.
        prev.on_cpu.store(false, Ordering::Release);
    }
}

/// First code run by every new task.
pub(crate) extern "C" fn task_entry() -> ! {
    finish_switch();
    irq::enable();
    // SAFETY: the entry is taken once, by the task itself, with IRQs off.
    let entry = irq::without(|| unsafe { (*(*current_ptr()).entry.get()).take() });
    if let Some(f) = entry {
        f();
    }
    exit()
}

/// Body of each CPU's idle task.
pub(crate) extern "C" fn idle_entry() -> ! {
    finish_switch();
    loop {
        // IRQs stay off between finding nothing to run and waiting, so a
        // wake-up from an interrupt cannot slip in between.
        irq::disable();
        schedule(Some(EnqueueReason::Yielded));
        irq::enable_and_wait();
    }
}
