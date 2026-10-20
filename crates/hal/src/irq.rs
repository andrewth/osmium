//! Interrupt controllers and handler dispatch.

use osmium_sync::{IrqDisabled, RwSpinLock};

/// An interrupt controller (PLIC, GIC, IO-APIC + local APIC, ...).
///
/// Methods take `&self` because the controller is shared by all CPUs and
/// used from interrupt context; implementations use per-register volatile
/// accesses, which the hardware serializes.
pub trait InterruptController: Sync {
    /// Unmasks `irq`, routing it to the current CPU where that applies.
    fn enable(&self, irq: u32);

    /// Masks `irq`.
    fn disable(&self, irq: u32);

    /// Acknowledges the highest-priority pending interrupt for this CPU.
    fn claim(&self) -> Option<u32>;

    /// Signals end of interrupt for a claimed `irq`.
    fn complete(&self, irq: u32);

    /// Sets the priority of `irq`; higher is more urgent. Optional.
    fn set_priority(&self, _irq: u32, _priority: u8) {}
}

/// Code run for an interrupt.
pub trait IrqHandler: Sync {
    /// Handles `irq`. Runs with interrupts masked on this CPU.
    fn handle(&self, irq: u32);
}

impl<F: Fn(u32) + Sync> IrqHandler for F {
    fn handle(&self, irq: u32) {
        self(irq)
    }
}

/// Why a handler could not be registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// The number is not below the table size.
    OutOfRange,
    /// Another handler owns the number.
    Busy,
}

/// Most interrupts [`IrqTable::handle_pending`] handles in one call.
///
/// Large enough that ordinary bursts (every line of a controller firing at
/// once) drain in one trap, small enough that a storm returns to the
/// interrupted code within a bounded time.
pub const MAX_CLAIMS_PER_CALL: usize = 64;

/// Maps interrupt numbers below `N` to handlers.
///
/// Registration takes a write lock; dispatch takes a read lock, so CPUs
/// dispatch in parallel.
pub struct IrqTable<const N: usize> {
    handlers: RwSpinLock<[Option<&'static dyn IrqHandler>; N], IrqDisabled>,
}

impl<const N: usize> IrqTable<N> {
    /// Creates an empty table.
    pub const fn new() -> Self {
        Self { handlers: RwSpinLock::new([None; N]) }
    }

    /// Installs `handler` for `irq`.
    pub fn register(&self, irq: u32, handler: &'static dyn IrqHandler) -> Result<(), RegisterError> {
        let mut h = self.handlers.write();
        let slot = h.get_mut(irq as usize).ok_or(RegisterError::OutOfRange)?;
        if slot.is_some() {
            return Err(RegisterError::Busy);
        }
        *slot = Some(handler);
        Ok(())
    }

    /// Removes the handler for `irq`, returning it.
    pub fn unregister(&self, irq: u32) -> Option<&'static dyn IrqHandler> {
        self.handlers.write().get_mut(irq as usize)?.take()
    }

    /// Runs the handler for `irq`. Returns false if none is registered.
    pub fn dispatch(&self, irq: u32) -> bool {
        let handler = self.handlers.read().get(irq as usize).copied().flatten();
        match handler {
            Some(h) => {
                h.handle(irq);
                true
            }
            None => false,
        }
    }

    /// Claims, dispatches and completes interrupts from `ctrl` until none
    /// are pending, or until [`MAX_CLAIMS_PER_CALL`] have been handled.
    /// Returns how many were handled. Call this from the external-interrupt
    /// trap path.
    ///
    /// The bound keeps an interrupt storm (a line that re-asserts as fast as
    /// it is completed) from livelocking the caller: interrupts still pending
    /// stay asserted at the controller, so the trap is taken again once the
    /// caller has returned and made progress.
    pub fn handle_pending(&self, ctrl: &dyn InterruptController) -> usize {
        let mut n = 0;
        while n < MAX_CLAIMS_PER_CALL {
            let Some(irq) = ctrl.claim() else { break };
            self.dispatch(irq);
            ctrl.complete(irq);
            n += 1;
        }
        n
    }
}

impl<const N: usize> Default for IrqTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};
    use osmium_sync::RawSpinLock;
    use std::vec::Vec;

    static HITS: AtomicU32 = AtomicU32::new(0);

    fn bump(irq: u32) {
        HITS.fetch_add(irq, Ordering::SeqCst);
    }

    struct FakeCtrl {
        pending: RawSpinLock<Vec<u32>>,
        completed: RawSpinLock<Vec<u32>>,
    }

    impl InterruptController for FakeCtrl {
        fn enable(&self, _: u32) {}
        fn disable(&self, _: u32) {}
        fn claim(&self) -> Option<u32> {
            self.pending.lock().pop()
        }
        fn complete(&self, irq: u32) {
            self.completed.lock().push(irq);
        }
    }

    #[test]
    fn register_dispatch_complete() {
        static TABLE: IrqTable<16> = IrqTable::new();
        TABLE.register(3, &bump).unwrap();
        TABLE.register(5, &bump).unwrap();
        assert_eq!(TABLE.register(3, &bump), Err(RegisterError::Busy));
        assert_eq!(TABLE.register(16, &bump), Err(RegisterError::OutOfRange));

        let ctrl = FakeCtrl { pending: RawSpinLock::new(std::vec![3, 5, 9]), completed: RawSpinLock::new(Vec::new()) };
        assert_eq!(TABLE.handle_pending(&ctrl), 3);
        assert_eq!(HITS.load(Ordering::SeqCst), 8);
        assert_eq!(*ctrl.completed.lock(), [9, 5, 3], "spurious IRQs are completed too");
        assert!(TABLE.unregister(3).is_some());
        assert!(!TABLE.dispatch(3));
    }

    /// A controller with one line that is pending again as soon as it is
    /// completed.
    struct Storm;

    impl InterruptController for Storm {
        fn enable(&self, _: u32) {}
        fn disable(&self, _: u32) {}
        fn claim(&self) -> Option<u32> {
            Some(1)
        }
        fn complete(&self, _: u32) {}
    }

    #[test]
    fn storm_is_bounded() {
        static TABLE: IrqTable<4> = IrqTable::new();
        assert_eq!(TABLE.handle_pending(&Storm), MAX_CLAIMS_PER_CALL);
    }
}
