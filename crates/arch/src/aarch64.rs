//! AArch64 system registers and memory-attribute conventions.
//!
//! Reads and writes of EL1/EL2 registers trap when executed at EL0.

use core::arch::asm;

/// `MAIR_ELx` value matching the attribute indices used by `osmium-mm`:
/// index 0 is Normal write-back read/write-allocate, index 1 is Device-nGnRE.
pub const MAIR_VALUE: u64 = 0xff | (0x04 << 8);

macro_rules! sysreg {
    ($(#[$m:meta])* $read:ident, $write:ident, $reg:literal) => {
        $(#[$m])*
        #[doc = concat!("Reads `", $reg, "`.")]
        #[inline]
        pub fn $read() -> u64 {
            let v: u64;
            // SAFETY: reading a system register has no side effects.
            unsafe { asm!(concat!("mrs {}, ", $reg), out(reg) v, options(nomem, nostack, preserves_flags)) }
            v
        }

        #[doc = concat!("Writes `", $reg, "` and synchronizes the context.")]
        ///
        /// # Safety
        /// The register controls translation or exception behaviour; the new
        /// value must keep the running code mapped and correct.
        #[inline]
        pub unsafe fn $write(v: u64) {
            // SAFETY: the caller upholds the contract.
            unsafe { asm!(concat!("msr ", $reg, ", {}"), "isb", in(reg) v, options(nostack, preserves_flags)) }
        }
    };
}

sysreg!(read_ttbr0_el1, write_ttbr0_el1, "ttbr0_el1");
sysreg!(read_ttbr1_el1, write_ttbr1_el1, "ttbr1_el1");
sysreg!(read_tcr_el1, write_tcr_el1, "tcr_el1");
sysreg!(read_mair_el1, write_mair_el1, "mair_el1");
sysreg!(read_sctlr_el1, write_sctlr_el1, "sctlr_el1");
sysreg!(read_vbar_el1, write_vbar_el1, "vbar_el1");
sysreg!(read_vttbr_el2, write_vttbr_el2, "vttbr_el2");
sysreg!(read_vtcr_el2, write_vtcr_el2, "vtcr_el2");
sysreg!(read_hcr_el2, write_hcr_el2, "hcr_el2");

/// Returns the current exception level (0–3).
#[inline]
pub fn current_el() -> u8 {
    let v: u64;
    // SAFETY: CurrentEL is readable at EL1 and above.
    unsafe { asm!("mrs {}, CurrentEL", out(reg) v, options(nomem, nostack, preserves_flags)) }
    ((v >> 2) & 3) as u8
}

/// Returns the generic timer frequency in Hz (`CNTFRQ_EL0`).
#[inline]
pub fn counter_frequency() -> u64 {
    let v: u64;
    // SAFETY: CNTFRQ_EL0 is readable at all ELs.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack, preserves_flags)) }
    v
}
