//! RISC-V Core-Local Interruptor (CLINT / ACLINT MTIMER + MSWI): the
//! machine-mode timer and software interrupts, for M-mode firmware.

use osmium_hal::mmio::IoMem;

const MSIP: usize = 0x0000;
const MTIMECMP: usize = 0x4000;
const MTIME: usize = 0xbff8;

/// A CLINT. Methods take a hart id; on most systems it equals the hart's
/// position in the CLINT (true for QEMU `virt` and SiFive cores).
pub struct Clint {
    io: IoMem,
}

impl Clint {
    /// Wraps the 64 KiB register window.
    pub fn new(io: IoMem) -> Self {
        Self { io }
    }

    /// The free-running machine timer.
    pub fn mtime(&self) -> u64 {
        self.io.read(MTIME).expect("CLINT window too small")
    }

    /// Raises the machine timer interrupt for `hart` once `mtime` reaches
    /// `deadline`. Writing a future deadline also clears a pending one.
    pub fn set_deadline(&self, hart: usize, deadline: u64) {
        let _ = self.io.write(MTIMECMP + 8 * hart, deadline);
    }

    /// Raises (`true`) or clears the machine software interrupt of `hart`.
    pub fn set_soft_interrupt(&self, hart: usize, pending: bool) {
        let _ = self.io.write(MSIP + 4 * hart, pending as u32);
    }
}

#[cfg(test)]
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn register_offsets() {
        let mut regs = vec![0u64; 0x10000 / 8];
        regs[MTIME / 8] = 12345;
        // SAFETY: the window covers a local buffer.
        let clint = Clint::new(unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x10000) });
        assert_eq!(clint.mtime(), 12345);
        clint.set_deadline(1, 99_999);
        clint.set_soft_interrupt(1, true);
        drop(clint);
        assert_eq!(regs[(MTIMECMP + 8) / 8], 99_999);
        assert_eq!(regs[0] >> 32, 1, "msip for hart 1 at offset 4");
    }
}
