//! Per-CPU trap-entry state shared by the RISC-V and AArch64 stubs.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::MAX_CPUS;

/// Offsets into [`TrapCpu`], shared with the entry stub (and with
/// hypervisor entry paths built on it).
pub mod offsets {
    /// One GPR save slot for the stub (`t0`).
    pub const SCRATCH: usize = 0x00;
    /// Top of the stack for traps from U-mode (or a guest).
    pub const KERNEL_SP: usize = 0x08;
    /// Top of the emergency stack used when the interrupted stack overflowed.
    pub const EXCEPTION_SP: usize = 0x10;
    /// Lowest valid address of the current kernel stack (0 = no check).
    pub const STACK_LO: usize = 0x18;
    /// Reserved for the hypervisor: `*mut` guest GPRs, null when no vCPU runs.
    pub const GUEST: usize = 0x20;
    /// Reserved for the hypervisor.
    pub const RESERVED: usize = 0x28;
    /// A second GPR save slot for the stub (`t1`).
    pub const SCRATCH2: usize = 0x30;
    /// Lowest address of the exception stack, so traps taken while already
    /// on it nest there instead of being mistaken for another overflow.
    pub const EXCEPTION_LO: usize = 0x38;
}

/// Per-CPU state the trap entry consults before saving a frame.
///
/// RISC-V finds it through `sscratch` (`mscratch`); AArch64 indexes
/// `OSMIUM_TRAP_CPUS` by the CPU id in `TPIDR_EL1` (`TPIDR_EL2`). The stub
/// picks the stack for the frame: [`TrapCpu::set_kernel_stack`]'s stack for
/// traps from user mode (RISC-V), the [`TrapCpu::set_exception_stack`] stack
/// if the interrupted kernel stack would go below
/// [`TrapCpu::set_stack_limit`], and otherwise the interrupted stack itself.
#[repr(C, align(64))]
pub struct TrapCpu {
    scratch: AtomicU64,
    kernel_sp: AtomicU64,
    pub(super) exception_sp: AtomicU64,
    pub(super) stack_lo: AtomicU64,
    guest: AtomicU64,
    reserved: AtomicU64,
    scratch2: AtomicU64,
    pub(super) exception_lo: AtomicU64,
}

const _: () = {
    assert!(core::mem::offset_of!(TrapCpu, kernel_sp) == offsets::KERNEL_SP);
    assert!(core::mem::offset_of!(TrapCpu, exception_sp) == offsets::EXCEPTION_SP);
    assert!(core::mem::offset_of!(TrapCpu, stack_lo) == offsets::STACK_LO);
    assert!(core::mem::offset_of!(TrapCpu, guest) == offsets::GUEST);
    assert!(core::mem::offset_of!(TrapCpu, reserved) == offsets::RESERVED);
    assert!(core::mem::offset_of!(TrapCpu, scratch2) == offsets::SCRATCH2);
    assert!(core::mem::offset_of!(TrapCpu, exception_lo) == offsets::EXCEPTION_LO);
};

#[unsafe(no_mangle)]
static OSMIUM_TRAP_CPUS: [TrapCpu; MAX_CPUS] = [const {
    TrapCpu {
        scratch: AtomicU64::new(0),
        kernel_sp: AtomicU64::new(0),
        exception_sp: AtomicU64::new(0),
        stack_lo: AtomicU64::new(0),
        guest: AtomicU64::new(0),
        reserved: AtomicU64::new(0),
        scratch2: AtomicU64::new(0),
        exception_lo: AtomicU64::new(0),
    }
}; MAX_CPUS];

impl TrapCpu {
    /// The calling CPU's state (by `osmium_arch::cpu::current_id`).
    pub fn current() -> &'static TrapCpu {
        &OSMIUM_TRAP_CPUS[crate::cpu::current_id()]
    }

    /// Sets the stack (top address) used for traps from U-mode. Update it
    /// on every switch to a task that runs user code.
    pub fn set_kernel_stack(&self, top: usize) {
        self.kernel_sp.store(top as u64, Ordering::Relaxed);
    }

    /// Sets the emergency stack used when the interrupted kernel stack has
    /// overflowed: `stack` runs from its lowest address to one past its top.
    /// Traps taken while already on it nest on it.
    pub fn set_exception_stack(&self, stack: core::ops::Range<usize>) {
        self.exception_lo.store(stack.start as u64, Ordering::Relaxed);
        self.exception_sp.store((stack.end & !15) as u64, Ordering::Relaxed);
    }

    /// Sets the lowest valid address of the kernel stack about to run.
    /// Update it on every context switch.
    ///
    /// 0 disables the check. Without it, an overflow into an unmapped guard
    /// page faults again while saving the frame, before `sscratch` is
    /// restored, and the CPU loops in the entry stub instead of reporting it.
    pub fn set_stack_limit(&self, lo: usize) {
        self.stack_lo.store(lo as u64, Ordering::Relaxed);
    }

    /// Address of this structure (what RISC-V keeps in `sscratch`).
    pub fn as_ptr(&self) -> *const TrapCpu {
        self
    }
}

const _: () = assert!(size_of::<TrapCpu>() == 64, "AArch64 stubs index the array with `lsl #6`");
