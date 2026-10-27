use osmium_arch::irq::{self, IrqState};

use crate::preempt;

/// Work done around a critical section: entered before a lock is acquired
/// and exited after it is released.
pub trait Guardian {
    /// What `enter` saves for `exit`.
    type State;
    /// Called before acquiring the lock.
    fn enter() -> Self::State;
    /// Called after releasing the lock.
    fn exit(state: Self::State);
}

/// Does nothing. Use only where preemption and interrupts cannot occur, such
/// as single-threaded firmware or code that already runs with IRQs masked.
pub struct NoGuard;

impl Guardian for NoGuard {
    type State = ();
    fn enter() {}
    fn exit(_: ()) {}
}

/// Disables preemption while the lock is held (the default).
pub struct PreemptDisabled;

impl Guardian for PreemptDisabled {
    type State = ();
    fn enter() {
        preempt::disable();
    }
    fn exit(_: ()) {
        preempt::enable();
    }
}

/// Disables local interrupts while the lock is held, and restores the
/// previous state afterwards. Required for data shared with IRQ handlers.
///
/// It also raises the preemption count, so a holder that tries to block or
/// yield trips the scheduler's "scheduling while atomic" assertion.
pub struct IrqDisabled;

impl Guardian for IrqDisabled {
    type State = IrqState;
    fn enter() -> IrqState {
        let state = irq::save_and_disable();
        preempt::disable();
        state
    }
    fn exit(state: IrqState) {
        preempt::enable();
        irq::restore(state);
    }
}
