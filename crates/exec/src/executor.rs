use core::future::Future;
use core::pin::Pin;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use osmium_arch::irq;
use osmium_sync::IrqSpinLock;

type TaskRef = Pin<&'static mut (dyn Future<Output = ()> + Send)>;

/// One task slot. A waker is just a pointer to its slot.
struct Slot {
    ready: AtomicBool,
    /// True from the moment `spawn` claims the slot until its task has
    /// finished and been removed. `spawn` and `tasks` read this instead of
    /// `task`'s lock, which `poll_once` holds while the task runs (so a task
    /// can spawn, or count tasks, without locking its own slot).
    occupied: AtomicBool,
    /// The owning executor's `pending` flag, recorded at spawn (a `const`
    /// executor cannot point into itself at construction).
    owner: AtomicPtr<AtomicBool>,
    task: IrqSpinLock<Option<TaskRef>>,
}

impl Slot {
    fn wake(&self) {
        self.ready.store(true, Ordering::Release);
        let owner = self.owner.load(Ordering::Acquire);
        if !owner.is_null() {
            // SAFETY: `owner` points into the 'static executor holding this slot.
            unsafe { &*owner }.store(true, Ordering::Release);
        }
    }
}

/// No free slot: the executor already holds `N` tasks.
#[derive(Debug, PartialEq, Eq)]
pub struct SpawnError;

/// Runs up to `N` tasks on the calling CPU.
pub struct Executor<const N: usize> {
    slots: [Slot; N],
    /// Set by every wake-up of one of this executor's tasks.
    pending: AtomicBool,
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
            pending: AtomicBool::new(false),
        }
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
            slot.owner.store((&raw const self.pending).cast_mut(), Ordering::Release);
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
    /// Each task is polled with its slot locked, so with interrupts masked
    /// on this CPU; a task must not block or spin waiting for an interrupt.
    pub fn poll_once(&'static self) -> usize {
        self.pending.store(false, Ordering::Release);
        let mut polled = 0;
        for slot in &self.slots {
            if !slot.ready.swap(false, Ordering::AcqRel) {
                continue;
            }
            let mut guard = slot.task.lock();
            let Some(task) = guard.as_mut() else { continue };
            // SAFETY: the slot is 'static and the vtable treats data as `*const Slot`.
            let waker = unsafe { Waker::from_raw(RawWaker::new(ptr::from_ref(slot).cast(), &VTABLE)) };
            polled += 1;
            // The slot stays locked (IRQs masked) while its task runs. Nothing
            // the task can call re-enters the lock: wakers only touch atomics,
            // and `spawn` and `tasks` skip occupied slots without locking.
            if task.as_mut().poll(&mut Context::from_waker(&waker)).is_ready() {
                *guard = None;
                drop(guard);
                // Only now may `spawn` reuse the slot (and `tasks` stop
                // counting it): the finished task is out of it.
                slot.occupied.store(false, Ordering::Release);
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
            if self.pending.load(Ordering::Acquire) {
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
