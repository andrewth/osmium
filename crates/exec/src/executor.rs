use core::future::Future;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use osmium_arch::irq;
use osmium_sync::IrqSpinLock;

type TaskRef = Pin<&'static mut (dyn Future<Output = ()> + Send)>;

/// One task slot. A waker is just a pointer to its slot.
struct Slot {
    ready: AtomicBool,
    /// True from the moment `spawn` claims the slot until its task has
    /// finished and been removed. `spawn` and `tasks` read this instead of
    /// `task`, which is empty while `poll_once` runs the task (so a task can
    /// spawn, or count tasks, without touching its own slot).
    occupied: AtomicBool,
    /// The owning executor's wake state, recorded at spawn (a `const`
    /// executor cannot point into itself at construction).
    owner: AtomicPtr<Shared>,
    /// Holds the task while it is idle. `poll_once` takes it out for the
    /// duration of the poll, so the lock is not held while the future runs.
    task: IrqSpinLock<Option<TaskRef>>,
}

/// What a wake-up touches: the executor's non-generic part.
struct Shared {
    /// Set by every wake-up of one of the executor's tasks.
    pending: AtomicBool,
    /// 0, or a `fn()` that makes the executor's CPU leave its wait.
    hook: AtomicUsize,
}

impl Slot {
    fn wake(&self) {
        self.ready.store(true, Ordering::Release);
        let owner = self.owner.load(Ordering::Acquire);
        if !owner.is_null() {
            // SAFETY: `owner` points into the 'static executor holding this slot.
            let shared = unsafe { &*owner };
            // Only the first wake since the executor last looked needs to
            // kick its CPU.
            if !shared.pending.swap(true, Ordering::AcqRel) {
                let hook = shared.hook.load(Ordering::Acquire);
                if hook != 0 {
                    // SAFETY: only `set_wake_hook` stores here, and it stores a `fn()`.
                    let hook: fn() = unsafe { core::mem::transmute(hook) };
                    hook();
                }
            }
        }
    }
}

/// No free slot: the executor already holds `N` tasks.
#[derive(Debug, PartialEq, Eq)]
pub struct SpawnError;

/// Runs up to `N` tasks on the calling CPU.
pub struct Executor<const N: usize> {
    slots: [Slot; N],
    shared: Shared,
}

impl<const N: usize> Executor<N> {
    /// Creates an executor with no tasks.
    pub const fn new() -> Self {
        Self {
            slots: [const {
                Slot {
                    ready: AtomicBool::new(false),
                    occupied: AtomicBool::new(false),
                    owner: AtomicPtr::new(ptr::null_mut()),
                    task: IrqSpinLock::new(None),
                }
            }; N],
            shared: Shared { pending: AtomicBool::new(false), hook: AtomicUsize::new(0) },
        }
    }

    /// Registers `hook`, called after a task of this executor is woken while
    /// the executor was not already flagged as having work. A wake from
    /// another CPU cannot end this CPU's `hlt`/`wfi` by itself: the hook
    /// should send that CPU an IPI (it may run on any CPU, in any context,
    /// and may be called when the executor's own CPU is the caller, in which
    /// case it should do nothing). Without one, such a wake-up is noticed
    /// only at the executor CPU's next interrupt (a timer tick, say).
    pub fn set_wake_hook(&self, hook: fn()) {
        self.shared.hook.store(hook as usize, Ordering::Release);
    }

    /// Adds a task; it is polled on the next pass. May be called from any
    /// context, including other tasks and interrupt handlers.
    pub fn spawn(&'static self, task: TaskRef) -> Result<(), SpawnError> {
        for slot in &self.slots {
            // Claim a free slot without touching any lock: a busy slot's lock
            // may be held by `poll_once` for the very task calling us.
            if slot.occupied.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
                continue;
            }
            // The slot is ours now. Its lock can only be held briefly, by a
            // `poll_once` on another CPU that found it empty (IRQs are masked
            // while it is held, so never by code this call interrupted).
            *slot.task.lock() = Some(task);
            slot.owner.store((&raw const self.shared).cast_mut(), Ordering::Release);
            slot.wake();
            return Ok(());
        }
        Err(SpawnError)
    }

    /// Number of tasks that have not finished. Lock-free, so tasks may call it.
    pub fn tasks(&self) -> usize {
        self.slots.iter().filter(|s| s.occupied.load(Ordering::Acquire)).count()
    }

    /// Polls every ready task once. Returns how many were polled.
    ///
    /// A task is polled with no lock held and interrupts as the caller left
    /// them; its slot is empty meanwhile. An executor belongs to one CPU:
    /// do not call this from two at once.
    pub fn poll_once(&'static self) -> usize {
        self.shared.pending.store(false, Ordering::Release);
        let mut polled = 0;
        for slot in &self.slots {
            if !slot.ready.swap(false, Ordering::AcqRel) {
                continue;
            }
            // Take the task out so the lock is not held (nor IRQs masked)
            // while the future runs. The slot stays `occupied`, so `spawn`
            // cannot reuse it meanwhile.
            let Some(mut task) = slot.task.lock().take() else { continue };
            // SAFETY: the slot is 'static and the vtable treats data as `*const Slot`.
            let waker = unsafe { Waker::from_raw(RawWaker::new(ptr::from_ref(slot).cast(), &VTABLE)) };
            polled += 1;
            if task.as_mut().poll(&mut Context::from_waker(&waker)).is_ready() {
                // Only now may `spawn` reuse the slot (and `tasks` stop
                // counting it): the finished task is out of it.
                slot.occupied.store(false, Ordering::Release);
            } else {
                *slot.task.lock() = Some(task);
            }
        }
        polled
    }

    /// Polls until no task is ready, then returns. For tests, and for
    /// firmware with other work in its main loop.
    pub fn run_until_idle(&'static self) {
        while self.poll_once() > 0 {}
    }

    /// Spawns `tasks`, which may live on the caller's stack, and runs
    /// forever. This is how heap-free code runs `async fn`s, whose future
    /// types cannot be named in a `static`: pin them in place with
    /// `core::pin::pin!` and pass them here.
    ///
    /// Panics if the tasks do not fit.
    ///
    /// # Safety
    ///
    /// Panics must abort (`panic = "abort"`): an unwinding panic, from this
    /// call or from a task, would free the caller's frame while the slots
    /// still point into it, and a later poll would use freed memory.
    #[allow(clippy::expect_used)] // integrator misuse at construction: the executor is sized for its fixed task set.
    pub unsafe fn run_with(&'static self, tasks: &mut [Pin<&mut (dyn Future<Output = ()> + Send)>]) -> ! {
        for task in tasks.iter_mut() {
            // SAFETY: this function never returns, so the caller's frame
            // (where the futures live) outlives every poll; with
            // panic = "abort" it is never unwound either.
            let task: TaskRef = unsafe { core::mem::transmute(task.as_mut()) };
            self.spawn(task).expect("too many tasks for the executor");
        }
        self.run()
    }

    /// Like [`Executor::run_with`], but returns once every task in the
    /// executor has finished, so firmware can go on (for example, hand off
    /// to an OS). Sound because no slot can still refer to the caller's
    /// futures when it returns.
    ///
    /// # Safety
    ///
    /// Panics must abort (`panic = "abort"`): unwinding out of this call (a
    /// full executor, a panicking task) would free the caller's frame while
    /// unfinished slots still point into it.
    #[allow(clippy::expect_used)] // integrator misuse at construction: the executor is sized for its fixed task set.
    pub unsafe fn run_to_completion(&'static self, tasks: &mut [Pin<&mut (dyn Future<Output = ()> + Send)>]) {
        for task in tasks.iter_mut() {
            // SAFETY: we return only when all slots are empty (every task
            // completed and was dropped from its slot), so the extended
            // lifetime never outlives the caller's futures.
            let task: TaskRef = unsafe { core::mem::transmute(task.as_mut()) };
            self.spawn(task).expect("too many tasks for the executor");
        }
        self.run_until(|| self.tasks() == 0);
    }

    /// Runs tasks forever, waiting for an interrupt whenever none is ready.
    pub fn run(&'static self) -> ! {
        loop {
            // `run_until` with an always-false condition never returns; the loop is only for the type.
            self.run_until(|| false);
        }
    }

    /// Runs tasks, waiting for interrupts when none is ready, until `done`
    /// returns true after a pass. Firmware uses this to finish its work and
    /// then hand off (to an OS, for example).
    pub fn run_until(&'static self, done: impl Fn() -> bool) {
        loop {
            self.run_until_idle();
            if done() {
                return;
            }
            // Check with interrupts masked, then wait atomically: a wake-up
            // from an interrupt after the check still ends the wait.
            irq::disable();
            if self.shared.pending.load(Ordering::Acquire) {
                irq::enable();
            } else {
                irq::enable_and_wait();
            }
        }
    }
}

impl<const N: usize> Default for Executor<N> {
    fn default() -> Self {
        Self::new()
    }
}

static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, drop_waker);

unsafe fn clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &VTABLE)
}

unsafe fn wake(data: *const ()) {
    // SAFETY: wakers are only created from 'static slots.
    unsafe { &*data.cast::<Slot>() }.wake();
}

unsafe fn drop_waker(_: *const ()) {}

/// Yields once, letting other ready tasks run.
pub async fn yield_now() {
    let mut yielded = false;
    core::future::poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}
