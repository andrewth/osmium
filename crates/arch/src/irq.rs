//! Local interrupt-flag control.
//!
//! These functions affect only the calling CPU. They are safe: enabling
//! interrupts at the wrong moment can deadlock, but it cannot break memory
//! safety on its own.

/// Whether local interrupts were enabled, as captured by [`save_and_disable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "pass the state to `restore`"]
pub struct IrqState(bool);

impl IrqState {
    /// Returns true if interrupts were enabled when the state was saved.
    pub fn was_enabled(self) -> bool {
        self.0
    }
}

/// Disables local interrupts and returns the previous state.
#[inline]
pub fn save_and_disable() -> IrqState {
    let state = IrqState(are_enabled());
    disable();
    state
}

/// Restores the interrupt state returned by [`save_and_disable`].
#[inline]
pub fn restore(state: IrqState) {
    if state.0 {
        enable();
    }
}

/// Runs `f` with local interrupts disabled.
#[inline]
pub fn without<R>(f: impl FnOnce() -> R) -> R {
    let state = save_and_disable();
    let r = f();
    restore(state);
    r
}

pub use imp::{are_enabled, disable, enable, enable_and_wait};

#[cfg(all(bare, target_arch = "x86_64"))]
mod imp {
    use core::arch::asm;

    /// Enables local interrupts.
    #[inline]
    pub fn enable() {
        // SAFETY: `sti` only sets RFLAGS.IF. No `nomem`: it must also act as a compiler barrier.
        unsafe { asm!("sti", options(nostack)) }
    }

    /// Disables local interrupts.
    #[inline]
    pub fn disable() {
        // SAFETY: `cli` only clears RFLAGS.IF; it is a compiler barrier as above.
        unsafe { asm!("cli", options(nostack)) }
    }

    /// Returns true if local interrupts are enabled.
    #[inline]
    pub fn are_enabled() -> bool {
        let flags: u64;
        // SAFETY: reads RFLAGS through the stack.
        unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem, preserves_flags)) }
        flags & (1 << 9) != 0
    }

    /// Enables interrupts and halts until one arrives, without a window in
    /// which an interrupt could be missed. Returns with interrupts enabled.
    #[inline]
    pub fn enable_and_wait() {
        // SAFETY: the `sti` shadow guarantees `hlt` executes before any interrupt is taken.
        unsafe { asm!("sti", "hlt", options(nostack)) }
    }
}

#[cfg(all(bare, target_arch = "aarch64"))]
mod imp {
    use core::arch::asm;

    /// Enables local interrupts.
    #[inline]
    pub fn enable() {
        // SAFETY: clears the I bit in DAIF.
        unsafe { asm!("msr daifclr, #2", options(nostack)) }
    }

    /// Disables local interrupts.
    #[inline]
    pub fn disable() {
        // SAFETY: sets the I bit in DAIF.
        unsafe { asm!("msr daifset, #2", options(nostack)) }
    }

    /// Returns true if local interrupts are enabled.
    #[inline]
    pub fn are_enabled() -> bool {
        let daif: u64;
        // SAFETY: reads DAIF.
        unsafe { asm!("mrs {}, daif", out(reg) daif, options(nomem, nostack)) }
        daif & (1 << 7) == 0
    }

    /// Waits for an interrupt, then enables interrupts so it is taken.
    #[inline]
    pub fn enable_and_wait() {
        // SAFETY: `wfi` wakes on a pending interrupt even while it is masked,
        // so nothing can be lost between the two instructions.
        unsafe { asm!("wfi", "msr daifclr, #2", options(nostack)) }
    }
}

#[cfg(all(bare, target_arch = "riscv64"))]
mod imp {
    use core::arch::asm;

    #[cfg(not(feature = "riscv-m-mode"))]
    macro_rules! status {
        ($op:literal) => {
            concat!($op, " sstatus, 2")
        };
    }
    #[cfg(feature = "riscv-m-mode")]
    macro_rules! status {
        ($op:literal) => {
            concat!($op, " mstatus, 8")
        };
    }

    /// Enables local interrupts.
    #[inline]
    pub fn enable() {
        // SAFETY: sets SIE (or MIE).
        unsafe { asm!(status!("csrsi"), options(nostack)) }
    }

    /// Disables local interrupts.
    #[inline]
    pub fn disable() {
        // SAFETY: clears SIE (or MIE).
        unsafe { asm!(status!("csrci"), options(nostack)) }
    }

    /// Returns true if local interrupts are enabled.
    #[inline]
    pub fn are_enabled() -> bool {
        let status: usize;
        #[cfg(not(feature = "riscv-m-mode"))]
        // SAFETY: reads sstatus.
        unsafe {
            asm!("csrr {}, sstatus", out(reg) status, options(nomem, nostack))
        };
        #[cfg(feature = "riscv-m-mode")]
        // SAFETY: reads mstatus.
        unsafe {
            asm!("csrr {}, mstatus", out(reg) status, options(nomem, nostack))
        };
        #[cfg(not(feature = "riscv-m-mode"))]
        return status & 2 != 0;
        #[cfg(feature = "riscv-m-mode")]
        return status & 8 != 0;
    }

    /// Waits for an interrupt, then enables interrupts so it is taken.
    #[inline]
    pub fn enable_and_wait() {
        // SAFETY: `wfi` resumes on a locally pending interrupt regardless of
        // the global enable bit, so nothing is lost between the instructions.
        unsafe { asm!("wfi", status!("csrsi"), options(nostack)) }
    }
}

#[cfg(not(bare))]
mod imp {
    use core::cell::Cell;

    std::thread_local! {
        static ENABLED: Cell<bool> = const { Cell::new(true) };
    }

    /// Enables (simulated) local interrupts.
    pub fn enable() {
        ENABLED.with(|e| e.set(true));
    }

    /// Disables (simulated) local interrupts.
    pub fn disable() {
        ENABLED.with(|e| e.set(false));
    }

    /// Returns true if (simulated) local interrupts are enabled.
    pub fn are_enabled() -> bool {
        ENABLED.with(|e| e.get())
    }

    /// Enables interrupts and yields the host thread in place of halting.
    pub fn enable_and_wait() {
        enable();
        std::thread::yield_now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_restore_nests() {
        enable();
        let outer = save_and_disable();
        assert!(!are_enabled());
        let inner = save_and_disable();
        restore(inner);
        assert!(!are_enabled(), "inner restore must not re-enable");
        restore(outer);
        assert!(are_enabled());
        assert!(without(|| !are_enabled()));
    }
}
