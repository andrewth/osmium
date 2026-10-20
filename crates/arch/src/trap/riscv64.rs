use core::sync::atomic::Ordering;

use super::{Access, Interrupt, Trap, TrapCpu};

#[cfg(all(bare, not(feature = "riscv-m-mode"), not(feature = "riscv64-hs")))]
core::arch::global_asm!(".set OSMIUM_RISCV_HS, 0", include_str!("riscv64_s.S"));
#[cfg(all(bare, not(feature = "riscv-m-mode"), feature = "riscv64-hs"))]
core::arch::global_asm!(".set OSMIUM_RISCV_HS, 1", include_str!("riscv64_s.S"));
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

    /// Returns true if the trap came from user mode (U-mode).
    pub fn from_user(&self) -> bool {
        self.status & SPP_OR_MPP == 0
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

impl TrapCpu {
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
