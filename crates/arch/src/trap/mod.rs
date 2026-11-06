//! Trap (exception and interrupt) entry.
//!
//! [`install`] points the CPU's trap vector at an entry stub that saves the
//! complete register state in a [`TrapFrame`] on the current stack, calls the
//! handler registered with [`set_handler`], and resumes from the (possibly
//! modified) frame. [`TrapFrame::cause`] decodes the architecture's cause
//! registers into a portable [`Trap`].
//!
//! Traps from kernel mode are taken on the current kernel stack, so a handler
//! may switch tasks (for example `osmium_sched::preempt_if_needed`): the frame
//! stays on the preempted task's stack until it resumes. Traps from user mode
//! are taken on the running task's kernel stack (see below). If the
//! interrupted kernel stack has overflowed, RISC-V and AArch64 switch to a
//! per-CPU emergency stack (`TrapCpu::set_exception_stack`); x86_64 uses an
//! IST stack for the vectors given to `set_ist`.
//!
//! Supported: RISC-V 64 (S-mode, or M-mode with `riscv-m-mode`), AArch64
//! (EL1, EL2 with `aarch64-el2`, or EL2 under VHE with the EL1 vectors and
//! `aarch64-vhe`) and x86_64 (an IDT of interrupt gates, with optional IST
//! stacks and an optional `syscall` entry). On hosted targets a simulation
//! lets tests drive handlers with [`simulate`].
//!
//! # User mode
//!
//! Each architecture enters user mode with its own `enter_user` and resumes a
//! saved user frame with `resume_user`; their signatures differ because each
//! CPU finds the kernel stack for traps from user mode differently:
//!
//! | Arch | Entry | Kernel stack for traps from user mode |
//! |------|-------|---------------------------------------|
//! | RISC-V (S-mode) | `riscv64::enter_user(entry, user_sp)`, `resume_user(frame)` | `TrapCpu::set_kernel_stack`, read by the stub; update it on every switch to a user task |
//! | AArch64 (EL1) | `aarch64::enter_user(entry, user_sp, kernel_sp)`, `resume_user(frame, kernel_sp)` | `SP_EL1`, loaded from `kernel_sp`; `TrapCpu::set_kernel_stack` is not consulted |
//! | x86_64 | `x86_64::enter_user(entry, stack_top)`, `resume_user(frame)` | the TSS's `rsp[0]` (`x86_64::CpuTables`), also used by the `syscall` stub |
//!
//! There is no `enter_user` in RISC-V M-mode (`riscv-m-mode`) or AArch64 EL2
//! (`aarch64-el2`) builds. The argument types also differ (`usize` on
//! RISC-V, `u64` elsewhere). `TrapFrame::syscall_args` returns eight
//! registers on RISC-V and AArch64 and seven values on x86_64; its docs on
//! each frame say where the call number is.

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
        /// The faulting address. x86_64 `#AC` does not report the data
        /// address, so there this is the faulting instruction's address.
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

#[allow(clippy::panic)] // invariant: integrator misuse; a trap with no registered handler cannot be recovered.
fn dispatch(frame: &mut TrapFrame) {
    if crate::fp::handle_lazy_trap(frame) {
        return;
    }
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

#[cfg(all(bare, target_arch = "x86_64"))]
#[unsafe(no_mangle)]
extern "C" fn osmium_trap_dispatch(frame: &mut TrapFrame) {
    frame.on_entry();
    dispatch(frame);
    fault_bad_user_return(frame);
}

/// Before returning to ring 3, makes sure `iretq` will not fault in the
/// kernel: a user `syscall` in the last bytes below the canonical hole saves
/// a non-canonical return address, and `iretq` to it is a #GP at CPL 0. Such
/// a frame is handed to the handler again as a general-protection fault
/// from user mode, which kernels treat like any other user fault.
#[cfg(all(bare, target_arch = "x86_64"))]
pub(crate) fn fault_bad_user_return(frame: &mut TrapFrame) {
    if frame.from_user() && !x86_64::is_canonical(frame.rip) {
        (frame.vector, frame.error_code) = (13, 0);
        dispatch(frame);
        if !x86_64::is_canonical(frame.rip) {
            // The handler left the bad address in place. Resume at address 0
            // instead, which is canonical and unmapped: the program takes a
            // page fault there, in user mode, which the handler deals with.
            frame.rip = 0;
        }
    }
}

/// A minimal once-flag usable from `osmium-arch`, which sits below
/// `osmium-sync`.
#[allow(dead_code)]
pub(crate) struct OnceFlag(core::sync::atomic::AtomicU8);

#[allow(dead_code)]
impl OnceFlag {
    pub(crate) const fn new() -> Self {
        Self(core::sync::atomic::AtomicU8::new(0))
    }

    /// Runs `f` exactly once; concurrent callers wait until it finishes.
    ///
    /// If `f` unwinds (hosted builds only; kernels abort on panic), the flag
    /// goes back to unset, so a waiting or later caller runs its own `f`
    /// instead of spinning forever.
    pub(crate) fn call_once(&self, f: impl FnOnce()) {
        use core::sync::atomic::{AtomicU8, Ordering};
        /// Puts the flag back to unset unless forgotten after `f` returns.
        struct Reset<'flag>(&'flag AtomicU8);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.0.store(0, Ordering::Release);
            }
        }
        loop {
            match self.0.compare_exchange(0, 1, Ordering::Acquire, Ordering::Acquire) {
                Ok(_) => {
                    let reset = Reset(&self.0);
                    f();
                    core::mem::forget(reset);
                    self.0.store(2, Ordering::Release);
                    return;
                }
                Err(2) => return,
                Err(_) => {
                    while self.0.load(Ordering::Acquire) == 1 {
                        core::hint::spin_loop();
                    }
                }
            }
        }
    }
}

#[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
mod cpu;
#[cfg(any(target_arch = "riscv64", target_arch = "aarch64"))]
pub use cpu::{TrapCpu, offsets};

#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "riscv64")]
pub use riscv64::{TrapFrame, install};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
pub use aarch64::{TrapFrame, VectorKind, install};

#[cfg(all(bare, target_arch = "x86_64"))]
mod x86_64;
// Hosted x86_64 test builds compile the x86_64 frame (without its entry stubs
// or IDT) so its decoding is unit-tested; the hosted `TrapFrame` stays `host`'s.
#[cfg(all(test, not(bare), target_arch = "x86_64"))]
#[allow(dead_code, clippy::wrong_self_convention)] // `from_user` names the trap's origin, as on every frame.
mod x86_64;
#[cfg(all(bare, target_arch = "x86_64"))]
pub use x86_64::{SYSCALL_VECTOR, TrapFrame, allow_from_user, install, set_ist};

#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", all(bare, target_arch = "x86_64"))))]
mod host;
#[cfg(not(any(target_arch = "riscv64", target_arch = "aarch64", all(bare, target_arch = "x86_64"))))]
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

    #[test]
    fn once_flag_runs_once_and_survives_an_unwinding_initializer() {
        use core::sync::atomic::AtomicUsize;
        static FLAG: OnceFlag = OnceFlag::new();
        static RUNS: AtomicUsize = AtomicUsize::new(0);
        let r = std::panic::catch_unwind(|| FLAG.call_once(|| panic!("initializer failed")));
        assert!(r.is_err());
        // Without the reset this would spin forever; instead the next caller initializes.
        FLAG.call_once(|| {
            RUNS.fetch_add(1, Ordering::Relaxed);
        });
        FLAG.call_once(|| {
            RUNS.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(RUNS.load(Ordering::Relaxed), 1);
    }
}
