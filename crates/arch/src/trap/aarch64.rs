use super::{Access, Interrupt, Trap};

#[cfg(all(bare, not(feature = "aarch64-el2")))]
core::arch::global_asm!(include_str!("aarch64_el1.S"));
#[cfg(all(bare, feature = "aarch64-el2"))]
core::arch::global_asm!(include_str!("aarch64_el2.S"));

/// Which of the 16 exception vectors was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VectorKind(pub u64);

impl VectorKind {
    /// Synchronous exception (vector offset `0x000`, `0x200`, ...).
    pub fn is_sync(self) -> bool {
        self.0 % 4 == 0
    }
    /// IRQ.
    pub fn is_irq(self) -> bool {
        self.0 % 4 == 1
    }
    /// FIQ.
    pub fn is_fiq(self) -> bool {
        self.0 % 4 == 2
    }
    /// SError.
    pub fn is_serror(self) -> bool {
        self.0 % 4 == 3
    }
    /// Taken from a lower exception level (user mode or a guest).
    pub fn from_lower_el(self) -> bool {
        self.0 >= 8
    }
}

/// Registers saved on exception entry.
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct TrapFrame {
    /// `x0`..=`x30`.
    pub x: [u64; 31],
    /// Stack pointer at the time of the exception.
    pub sp: u64,
    /// `ELR_ELx`: where to resume.
    pub elr: u64,
    /// `SPSR_ELx`: state to restore.
    pub spsr: u64,
    /// `ESR_ELx`: syndrome.
    pub esr: u64,
    /// `FAR_ELx`: faulting address.
    pub far: u64,
    /// Vector index (0–15).
    pub kind: u64,
    _pad: u64,
}

const _: () = assert!(size_of::<TrapFrame>() == 304);

impl TrapFrame {
    /// The program counter the exception will return to.
    pub fn pc(&self) -> usize {
        self.elr as usize
    }

    /// Changes where the exception returns to.
    pub fn set_pc(&mut self, pc: usize) {
        self.elr = pc as u64;
    }

    /// The stack pointer at the time of the exception.
    pub fn sp(&self) -> usize {
        self.sp as usize
    }

    /// Which vector was taken.
    pub fn vector(&self) -> VectorKind {
        VectorKind(self.kind)
    }

    /// System-call argument registers `x0`..=`x7`.
    pub fn syscall_args(&self) -> [u64; 8] {
        self.x[..8].try_into().unwrap()
    }

    /// Sets the return value register `x0`.
    pub fn set_return(&mut self, v: u64) {
        self.x[0] = v;
    }

    /// Decodes the cause.
    pub fn cause(&self) -> Trap {
        let v = self.vector();
        if v.is_irq() || v.is_fiq() {
            return Trap::Interrupt(Interrupt::External);
        }
        if v.is_serror() {
            return Trap::Other { raw: self.esr | self.kind << 32 };
        }
        let ec = (self.esr >> 26) & 0x3f;
        let addr = self.far as usize;
        match ec {
            0x00 => Trap::IllegalInstruction,
            0x15 | 0x16 | 0x17 => Trap::Syscall,
            0x3c => Trap::Breakpoint,
            0x20 | 0x21 => Trap::PageFault { addr, access: Access::Execute },
            0x24 | 0x25 => {
                let write = self.esr & (1 << 6) != 0;
                Trap::PageFault { addr, access: if write { Access::Write } else { Access::Read } }
            }
            0x22 | 0x26 => Trap::Misaligned { addr },
            _ => Trap::Other { raw: self.esr },
        }
    }

    #[cfg(not(bare))]
    pub(super) fn simulated(trap: Trap, pc: usize) -> Self {
        let (kind, esr, far) = match trap {
            Trap::Interrupt(_) => (5, 0, 0),
            Trap::IllegalInstruction => (4, 0, 0),
            Trap::Syscall => (4, 0x15 << 26, 0),
            Trap::Breakpoint => (4, 0x3c << 26, 0),
            Trap::PageFault { addr, access: Access::Execute } => (4, 0x21 << 26, addr),
            Trap::PageFault { addr, access: Access::Read } => (4, 0x25 << 26, addr),
            Trap::PageFault { addr, access: Access::Write } => (4, 0x25 << 26 | 1 << 6, addr),
            Trap::Misaligned { addr } => (4, 0x26 << 26, addr),
            Trap::Other { raw } => (4, raw, 0),
        };
        Self { elr: pc as u64, kind, esr, far: far as u64, ..Self::default() }
    }
}

/// Points this CPU's vector base (`VBAR_EL1`, or `VBAR_EL2` with
/// `aarch64-el2`) at the Osmium vector table. Call on every CPU.
///
/// # Safety
/// Replaces the current vectors. Exceptions are handled on the current stack
/// (`SP_ELx`), which must be valid whenever one can occur.
pub unsafe fn install() {
    #[cfg(bare)]
    {
        unsafe extern "C" {
            fn osmium_trap_vectors();
        }
        let base = osmium_trap_vectors as *const () as usize;
        // SAFETY: the table is 2 KiB aligned.
        #[cfg(not(feature = "aarch64-el2"))]
        unsafe {
            core::arch::asm!("msr vbar_el1, {}", "isb", in(reg) base)
        };
        // SAFETY: as above.
        #[cfg(feature = "aarch64-el2")]
        unsafe {
            core::arch::asm!("msr vbar_el2, {}", "isb", in(reg) base)
        };
    }
}
