//! RISC-V Core-Local Interruptor (CLINT / ACLINT MTIMER + MSWI): the
//! machine-mode timer and software interrupts, for M-mode firmware.

use crate::ioext::IoMemExt;
use osmium_hal::mmio::IoMem;

const MSIP: usize = 0x0000;
const MTIMECMP: usize = 0x4000;
const MTIME: usize = 0xbff8;
/// The register layout has room for 4095 harts: one more `mtimecmp` would
/// be `mtime`, and one more `msip` would be hart 0's `mtimecmp`.
const MAX_HARTS: usize = 4095;

/// A CLINT. Methods take a hart id; on most systems it equals the hart's
/// position in the CLINT (true for QEMU `virt` and SiFive cores).
///
/// Methods ignore a hart outside the layout's 4095 or outside the window
/// given to [`Clint::new`].
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
        self.io.rd(MTIME)
    }

    /// Raises the machine timer interrupt for `hart` once `mtime` reaches
    /// `deadline`. Writing a future deadline also clears a pending one.
    pub fn set_deadline(&self, hart: usize, deadline: u64) {
        if hart < MAX_HARTS {
            // Out-of-window offsets are rejected by `IoMem`.
            let _ = self.io.write(MTIMECMP + 8 * hart, deadline);
        }
    }

    /// Raises (`true`) or clears the machine software interrupt of `hart`.
    pub fn set_soft_interrupt(&self, hart: usize, pending: bool) {
        if hart < MAX_HARTS {
            let _ = self.io.write(MSIP + 4 * hart, pending as u32);
        }
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

    #[test]
    fn out_of_range_harts_are_ignored() {
        let mut regs = vec![0u64; 0x10000 / 8];
        // SAFETY: the window covers a local buffer.
        let clint = Clint::new(unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x10000) });
        clint.set_deadline(4095, 1); // would be mtime
        clint.set_soft_interrupt(4096, true); // would be hart 0's mtimecmp
        clint.set_deadline(usize::MAX, 1);
        clint.set_soft_interrupt(usize::MAX / 2, true);
        clint.set_deadline(4094, 7);
        drop(clint);
        assert_eq!(regs[MTIME / 8], 0);
        assert_eq!(regs[MTIMECMP / 8], 0);
        assert_eq!(regs[(MTIMECMP + 8 * 4094) / 8], 7);

        // A smaller window bounds the harts further.
        // SAFETY: as above.
        let clint = Clint::new(unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x4010) });
        clint.set_deadline(2, 9);
        drop(clint);
        assert_eq!(regs[(MTIMECMP + 16) / 8], 0);
    }
}
