use core::future::poll_fn;
use core::task::{Poll, Waker};

use osmium_sync::IrqSpinLock;

/// Holds one task's waker so another context (typically an interrupt
/// handler) can wake it.
pub struct AtomicWaker {
    waker: IrqSpinLock<Option<Waker>>,
}

impl AtomicWaker {
    /// Creates an empty registration.
    pub const fn new() -> Self {
        Self { waker: IrqSpinLock::new(None) }
    }

    /// Records the waker to call on the next [`AtomicWaker::wake`].
    pub fn register(&self, waker: &Waker) {
        let mut w = self.waker.lock();
        match &*w {
            Some(old) if old.will_wake(waker) => {}
            _ => *w = Some(waker.clone()),
        }
    }

    /// Wakes the registered task, if any.
    pub fn wake(&self) {
        if let Some(w) = self.waker.lock().take() {
            w.wake();
        }
    }
}

impl Default for AtomicWaker {
    fn default() -> Self {
        Self::new()
    }
}

/// A single-slot channel: `signal` stores a value (replacing any unread
/// one) and wakes the task in `wait`. Safe to signal from interrupt handlers.
pub struct Signal<T> {
    state: IrqSpinLock<Option<T>>,
    waker: AtomicWaker,
}

impl<T: Send> Signal<T> {
    /// Creates an empty signal.
    pub const fn new() -> Self {
        Self { state: IrqSpinLock::new(None), waker: AtomicWaker::new() }
    }

    /// Stores `value` and wakes the waiter.
    pub fn signal(&self, value: T) {
        *self.state.lock() = Some(value);
        self.waker.wake();
    }

    /// Takes the value if one is present.
    pub fn try_take(&self) -> Option<T> {
        self.state.lock().take()
    }

    /// Waits for and takes the next value.
    pub async fn wait(&self) -> T {
        poll_fn(|cx| {
            // Register before checking, so a signal between the check and
            // the registration still wakes us.
            self.waker.register(cx.waker());
            match self.try_take() {
                Some(v) => Poll::Ready(v),
                None => Poll::Pending,
            }
        })
        .await
    }
}

impl<T: Send> Default for Signal<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Executor, Signal, StaticCell, yield_now};
    use core::future::Future;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicU32, Ordering};

    type Fut = dyn Future<Output = ()> + Send;

    #[test]
    fn interleaving_and_signals() {
        static EXEC: Executor<3> = Executor::new();
        static SIG: Signal<u32> = Signal::new();
        static LOG: osmium_sync::IrqSpinLock<std::vec::Vec<&str>> = osmium_sync::IrqSpinLock::new(std::vec::Vec::new());
        static A: StaticCell<Pin<std::boxed::Box<Fut>>> = StaticCell::new();
        static B: StaticCell<Pin<std::boxed::Box<Fut>>> = StaticCell::new();
        static GOT: AtomicU32 = AtomicU32::new(0);

        let a = A.init(std::boxed::Box::pin(async {
            for _ in 0..2 {
                LOG.lock().push("a");
                yield_now().await;
            }
        }));
        let b = B.init(std::boxed::Box::pin(async {
            LOG.lock().push("b waits");
            GOT.store(SIG.wait().await, Ordering::SeqCst);
            LOG.lock().push("b got");
        }));
        EXEC.spawn(a.as_mut()).unwrap();
        EXEC.spawn(b.as_mut()).unwrap();
        EXEC.run_until_idle();
        assert_eq!(*LOG.lock(), ["a", "b waits", "a"]);
        assert_eq!(EXEC.tasks(), 1, "b is blocked on the signal");

        // As an interrupt handler would.
        SIG.signal(7);
        EXEC.run_until_idle();
        assert_eq!(GOT.load(Ordering::SeqCst), 7);
        assert_eq!(EXEC.tasks(), 0);
        assert_eq!(LOG.lock().last(), Some(&"b got"));
    }

    #[test]
    fn full_executor_rejects_spawn() {
        static EXEC: Executor<1> = Executor::new();
        static A: StaticCell<Pin<std::boxed::Box<Fut>>> = StaticCell::new();
        static B: StaticCell<Pin<std::boxed::Box<Fut>>> = StaticCell::new();
        let a = A.init(std::boxed::Box::pin(core::future::pending()));
        let b = B.init(std::boxed::Box::pin(async {}));
        EXEC.spawn(a.as_mut()).unwrap();
        assert!(EXEC.spawn(b.as_mut()).is_err());
    }

    #[test]
    fn wake_from_another_thread() {
        static EXEC: Executor<1> = Executor::new();
        static SIG: Signal<&'static str> = Signal::new();
        static A: StaticCell<Pin<std::boxed::Box<Fut>>> = StaticCell::new();
        static DONE: AtomicU32 = AtomicU32::new(0);
        let a = A.init(std::boxed::Box::pin(async {
            assert_eq!(SIG.wait().await, "irq");
            DONE.store(1, Ordering::SeqCst);
        }));
        EXEC.spawn(a.as_mut()).unwrap();
        EXEC.run_until_idle();
        let t = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(20));
            SIG.signal("irq");
        });
        while DONE.load(Ordering::SeqCst) == 0 {
            EXEC.run_until_idle();
        }
        t.join().unwrap();
    }
}
