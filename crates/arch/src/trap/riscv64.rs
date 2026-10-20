use core::sync::atomic::{AtomicU64, Ordering};

use super::{Access, Interrupt, Trap};
use crate::MAX_CPUS;

#[cfg(all(bare, not(feature = "riscv-m-mode")))]
core::arch::global_asm!(include_str!("riscv64_s.S"));
#[cfg(all(bare, feature = "riscv-m-mode"))]
core::arch::global_asm!(include_str!("riscv64_m.S"));

/// Registers saved on trap entry.
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct TrapFrame {
    /// `x0`..=`x31`, indexed by register number (`x[0]` is unused, `x[2]` is
    /// the stack pointer at the time of the trap).
    pub x: [u64; 32],
    /// Program counter to resume at (`sepc`/`mepc`).
    pub epc: u64,
    /// `sstatus`/`mstatus` to restore.
    pub status: u64,
    /// `scause`/`mcause`.
    pub cause: u64,
    /// `stval`/`mtval`.
    pub tval: u64,
}

const _: () = assert!(size_of::<TrapFrame>() == 288);

impl TrapFrame {
    /// The program counter the trap will return to.
    pub fn pc(&self) -> usize {
        self.epc as usize
    }

    /// Changes where the trap returns to (for example past an `ecall`).
    pub fn set_pc(&mut self, pc: usize) {
        self.epc = pc as u64;
    }

    /// The stack pointer at the time of the trap.
    pub fn sp(&self) -> usize {
        self.x[2] as usize
    }

    /// System-call argument registers `a0`..=`a7`.
    pub fn syscall_args(&self) -> [u64; 8] {
        self.x[10..18].try_into().unwrap()
    }

    /// Sets the return value register `a0`.
    pub fn set_return(&mut self, v: u64) {
        self.x[10] = v;
    }

    /// Decodes the cause.
    pub fn cause(&self) -> Trap {
        let interrupt = self.cause >> 63 != 0;
        let code = self.cause & !(1 << 63);
        let addr = self.tval as usize;
        if interrupt {
            return match code {
                1 | 3 => Trap::Interrupt(Interrupt::Software),
                5 | 7 => Trap::Interrupt(Interrupt::Timer),
                9 | 11 => Trap::Interrupt(Interrupt::External),
                _ => Trap::Other { raw: self.cause },
            };
        }
        match code {
            0 | 4 | 6 => Trap::Misaligned { addr },
            2 => Trap::IllegalInstruction,
            3 => Trap::Breakpoint,
            8 | 9 | 11 => Trap::Syscall,
            12 => Trap::PageFault { addr, access: Access::Execute },
            13 => Trap::PageFault { addr, access: Access::Read },
            15 => Trap::PageFault { addr, access: Access::Write },
            _ => Trap::Other { raw: self.cause },
        }
    }

    #[cfg(not(bare))]
    pub(super) fn simulated(trap: Trap, pc: usize) -> Self {
        let (cause, tval) = match trap {
            Trap::Interrupt(Interrupt::Software) => (1 << 63 | 1, 0),
            Trap::Interrupt(Interrupt::Timer) => (1 << 63 | 5, 0),
            Trap::Interrupt(Interrupt::External) => (1 << 63 | 9, 0),
            Trap::Misaligned { addr } => (4, addr),
            Trap::IllegalInstruction => (2, 0),
            Trap::Breakpoint => (3, 0),
            Trap::Syscall => (8, 0),
            Trap::PageFault { addr, access: Access::Execute } => (12, addr),
            Trap::PageFault { addr, access: Access::Read } => (13, addr),
            Trap::PageFault { addr, access: Access::Write } => (15, addr),
            Trap::Other { raw } => (raw, 0),
        };
        Self { epc: pc as u64, cause, tval: tval as u64, ..Self::default() }
    }
}

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

/// Per-CPU state the trap entry finds through `sscratch` (`mscratch`), which
/// always points here once [`install`] has run.
///
/// On entry the stub swaps `sp` with `sscratch` and picks the stack for the
/// frame: [`TrapCpu::set_kernel_stack`]'s stack for traps from U-mode, the
/// [`TrapCpu::set_exception_stack`] stack if the interrupted kernel stack
/// would go below [`TrapCpu::set_stack_limit`], and otherwise the interrupted
/// stack itself.
#[repr(C, align(64))]
pub struct TrapCpu {
    scratch: AtomicU64,
    kernel_sp: AtomicU64,
    exception_sp: AtomicU64,
    stack_lo: AtomicU64,
    guest: AtomicU64,
    reserved: AtomicU64,
    scratch2: AtomicU64,
    exception_lo: AtomicU64,
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

static TRAP_CPUS: [TrapCpu; MAX_CPUS] = [const {
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
        &TRAP_CPUS[crate::cpu::current_id()]
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

    /// Returns true if `frame` was taken because its stack overflowed, i.e.
    /// it was saved on the exception stack.
    pub fn overflowed(&self, frame: &TrapFrame) -> bool {
        let lo = self.stack_lo.load(Ordering::Relaxed);
        let sp = frame.x[2];
        let on_exception_stack =
            (self.exception_lo.load(Ordering::Relaxed)..=self.exception_sp.load(Ordering::Relaxed)).contains(&sp);
        frame.status & SPP_OR_MPP != 0
            && !on_exception_stack
            && lo != 0
            && sp.wrapping_sub(size_of::<TrapFrame>() as u64) < lo
    }

    /// Address of this structure, as kept in `sscratch`.
    pub fn as_ptr(&self) -> *const TrapCpu {
        self
    }
}

#[cfg(not(feature = "riscv-m-mode"))]
const SPP_OR_MPP: u64 = 1 << 8;
#[cfg(feature = "riscv-m-mode")]
const SPP_OR_MPP: u64 = 0b11 << 11;

/// Points this CPU's trap vector at the Osmium entry stub and `sscratch`
/// (`mscratch`) at its [`TrapCpu`]. Call on every CPU, after
/// `osmium_arch::cpu::set_current_id`.
///
/// # Safety
/// Replaces the current trap vector and scratch register, which must not be
/// used for anything else from now on. Kernel-mode traps are handled on the
/// interrupted stack, which must be valid unless the overflow check (see
/// [`TrapCpu`]) catches it.
pub unsafe fn install() {
    #[cfg(bare)]
    {
        unsafe extern "C" {
            fn osmium_trap_entry();
        }
        let entry = osmium_trap_entry as *const () as usize;
        let cpu = TrapCpu::current().as_ptr() as usize;
        // SAFETY: the entry stub is 4-byte aligned (direct mode), and the
        // scratch register must point at TrapCpu before the first trap.
        #[cfg(not(feature = "riscv-m-mode"))]
        unsafe {
            core::arch::asm!("csrw sscratch, {}", "csrw stvec, {}", in(reg) cpu, in(reg) entry)
        };
        // SAFETY: as above.
        #[cfg(feature = "riscv-m-mode")]
        unsafe {
            core::arch::asm!("csrw mscratch, {}", "csrw mtvec, {}", in(reg) cpu, in(reg) entry)
        };
    }
}
