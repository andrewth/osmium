//! Trap (exception and interrupt) entry.
//!
//! [`install`] points the CPU's trap vector at an entry stub that saves the
//! complete register state in a [`TrapFrame`] on the current stack, calls the
//! handler registered with [`set_handler`], and resumes from the (possibly
//! modified) frame. [`TrapFrame::cause`] decodes the architecture's cause
//! registers into a portable [`Trap`].
//!
//! Traps are taken on the current kernel stack, so a handler may switch tasks
//! (for example `osmium_sched::preempt_if_needed`): the frame stays on the
//! preempted task's stack until it resumes. User mode is not supported yet.
//!
//! Supported: RISC-V 64 (S-mode, or M-mode with `riscv-m-mode`) and AArch64
//! (EL1, or EL2 with `aarch64-el2`). On hosted targets a simulation lets
//! tests drive handlers with [`simulate`].

use core::sync::atomic::{AtomicUsize, Ordering};

/// How a faulting access touched memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// A load.
    Read,
    /// A store.
    Write,
    /// An instruction fetch.
    Execute,
}

/// Which interrupt line fired, as far as the CPU itself can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interrupt {
    /// The CPU-local timer (RISC-V only; on AArch64 the timer arrives through
    /// the interrupt controller as [`Interrupt::External`]).
    Timer,
    /// An inter-processor (software) interrupt (RISC-V only).
    Software,
    /// An interrupt from the platform interrupt controller; claim it there.
    External,
}

/// A decoded trap cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trap {
    /// An asynchronous interrupt.
    Interrupt(Interrupt),
    /// A translation or permission fault at `addr`.
    PageFault {
        /// The faulting address.
        addr: usize,
        /// The kind of access.
        access: Access,
    },
    /// An environment or supervisor call (`ecall`, `svc`, `hvc`).
    Syscall,
    /// A breakpoint instruction.
    Breakpoint,
    /// An undefined or illegal instruction.
    IllegalInstruction,
    /// A misaligned access or program counter.
    Misaligned {
        /// The faulting address.
        addr: usize,
    },
    /// Anything else, with the raw cause value.
    Other {
        /// Architecture-specific cause (`scause`, or `ESR` plus vector kind).
        raw: u64,
    },
}

/// Code run for every trap.
pub type Handler = fn(&mut TrapFrame);

static HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Registers the trap handler, replacing any previous one.
pub fn set_handler(handler: Handler) {
    HANDLER.store(handler as usize, Ordering::Release);
}

// Unused on bare-metal x86_64 until it has a trap backend.
#[cfg_attr(all(bare, target_arch = "x86_64"), allow(dead_code))]
fn dispatch(frame: &mut TrapFrame) {
    match HANDLER.load(Ordering::Acquire) {
        0 => panic!("unhandled trap {:?} at pc {:#x} (no handler registered)", frame.cause(), frame.pc()),
        h => {
            // SAFETY: only `set_handler` stores non-zero values, and it stores `Handler`s.
            let h: Handler = unsafe { core::mem::transmute::<usize, Handler>(h) };
            h(frame);
        }
    }
}

#[cfg(all(bare, any(target_arch = "riscv64", target_arch = "aarch64")))]
#[unsafe(no_mangle)]
extern "C" fn osmium_trap_dispatch(frame: &mut TrapFrame) {
    dispatch(frame);
}

#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "riscv64")]
pub use riscv64::{TrapFrame, install};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::{TrapFrame, VectorKind, install};

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
mod host;
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64")))]
pub use host::{TrapFrame, install};

/// Runs the registered handler on a synthetic frame carrying `trap`, as if
/// the CPU had trapped. For testing handlers on hosted targets.
#[cfg(not(bare))]
pub fn simulate(trap: Trap, pc: usize) -> TrapFrame {
    let mut frame = TrapFrame::simulated(trap, pc);
    dispatch(&mut frame);
    frame
}

#[cfg(all(test, not(bare), not(any(target_arch = "riscv64", target_arch = "aarch64"))))]
mod tests {
    use super::*;

    #[test]
    fn handler_sees_cause_and_can_redirect() {
        fn handler(f: &mut TrapFrame) {
            if f.cause() == Trap::Breakpoint {
                f.set_pc(f.pc() + 4);
            }
        }
        set_handler(handler);
        let f = simulate(Trap::Breakpoint, 0x1000);
        assert_eq!(f.pc(), 0x1004);
        let f = simulate(Trap::Interrupt(Interrupt::Timer), 0x2000);
        assert_eq!(f.pc(), 0x2000);
    }
}
