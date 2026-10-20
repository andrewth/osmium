use super::{Access, Interrupt, Trap};

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

/// Points this CPU's trap vector at the Osmium entry stub. Call on every CPU.
///
/// # Safety
/// Replaces the current trap vector. Traps are handled on the current stack,
/// which must be a valid kernel stack whenever a trap can occur.
pub unsafe fn install() {
    #[cfg(bare)]
    {
        unsafe extern "C" {
            fn osmium_trap_entry();
        }
        let entry = osmium_trap_entry as *const () as usize;
        // SAFETY: the entry stub is 4-byte aligned; direct mode.
        #[cfg(not(feature = "riscv-m-mode"))]
        unsafe {
            core::arch::asm!("csrw stvec, {}", in(reg) entry)
        };
        // SAFETY: as above.
        #[cfg(feature = "riscv-m-mode")]
        unsafe {
            core::arch::asm!("csrw mtvec, {}", in(reg) entry)
        };
    }
}
