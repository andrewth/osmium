use super::Trap;

/// A simulated trap frame for hosted builds of architectures without a
/// trap backend.
#[derive(Clone, Debug)]
pub struct TrapFrame {
    pc: usize,
    trap: Trap,
    /// General-purpose registers, for handlers that read or write them.
    pub regs: [u64; 32],
}

impl TrapFrame {
    /// The program counter the trap will return to.
    pub fn pc(&self) -> usize {
        self.pc
    }

    /// Changes where the trap returns to.
    pub fn set_pc(&mut self, pc: usize) {
        self.pc = pc;
    }

    /// Decodes the cause.
    pub fn cause(&self) -> Trap {
        self.trap
    }

    #[cfg(not(bare))]
    pub(super) fn simulated(trap: Trap, pc: usize) -> Self {
        Self { pc, trap, regs: [0; 32] }
    }
}

/// No-op: hosted builds have no trap vector to install.
///
/// # Safety
/// None; `unsafe` only to match the bare-metal signature.
pub unsafe fn install() {}
