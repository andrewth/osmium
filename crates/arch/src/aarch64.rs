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
sysreg!(read_ttbr0_el2, write_ttbr0_el2, "ttbr0_el2");
sysreg!(read_tcr_el2, write_tcr_el2, "tcr_el2");
sysreg!(read_mair_el2, write_mair_el2, "mair_el2");
sysreg!(read_sctlr_el2, write_sctlr_el2, "sctlr_el2");
sysreg!(read_cnthctl_el2, write_cnthctl_el2, "cnthctl_el2");
sysreg!(read_cntvoff_el2, write_cntvoff_el2, "cntvoff_el2");
sysreg!(read_cntv_ctl_el0, write_cntv_ctl_el0, "cntv_ctl_el0");
sysreg!(read_cntv_tval_el0, write_cntv_tval_el0, "cntv_tval_el0");
sysreg!(read_cntv_cval_el0, write_cntv_cval_el0, "cntv_cval_el0");
sysreg!(read_cntp_ctl_el0, write_cntp_ctl_el0, "cntp_ctl_el0");
sysreg!(read_cntp_tval_el0, write_cntp_tval_el0, "cntp_tval_el0");

/// Reads `ID_AA64MMFR0_EL1` (memory model features; `PARange` in bits 3:0).
#[inline]
pub fn read_id_aa64mmfr0_el1() -> u64 {
    let v: u64;
    // SAFETY: reading an ID register has no side effects.
    unsafe { asm!("mrs {}, id_aa64mmfr0_el1", out(reg) v, options(nomem, nostack, preserves_flags)) }
    v
}

/// Reads `MPIDR_EL1`, the CPU's affinity (hardware id).
#[inline]
pub fn read_mpidr_el1() -> u64 {
    let v: u64;
    // SAFETY: reading an ID register has no side effects.
    unsafe { asm!("mrs {}, mpidr_el1", out(reg) v, options(nomem, nostack, preserves_flags)) }
    v
}

/// Drops to user mode (EL0, using `SP_EL0`) at `entry` with stack
/// `user_sp`, interrupts enabled. Exceptions from EL0 then arrive on
/// `kernel_sp` (`SP_EL1`), which should be the top of the task's kernel
/// stack. General-purpose registers are cleared. Does not return.
///
/// # Safety
/// The Osmium vectors (EL1 build) must be installed, `kernel_sp` must be a
/// valid kernel stack, and `entry`/`user_sp` must be mapped EL0-accessible.
#[cfg(not(feature = "aarch64-el2"))]
pub unsafe fn enter_user(entry: u64, user_sp: u64, kernel_sp: u64) -> ! {
    // SAFETY: the caller upholds the contract. IRQs are masked before ELR/
    // SPSR are written so no exception can overwrite them; eret unmasks
    // them by restoring SPSR (EL0t, DAIF clear).
    unsafe {
        asm!(
            "msr daifset, #0xf",
            "msr sp_el0, {usp}",
            "msr elr_el1, {entry}",
            "msr spsr_el1, xzr",
            "mov sp, {ksp}",
            "mov x0, xzr", "mov x1, xzr", "mov x2, xzr", "mov x3, xzr", "mov x4, xzr",
            "mov x5, xzr", "mov x6, xzr", "mov x7, xzr", "mov x8, xzr", "mov x9, xzr",
            "mov x10, xzr", "mov x11, xzr", "mov x12, xzr", "mov x13, xzr", "mov x14, xzr",
            "mov x15, xzr", "mov x16, xzr", "mov x17, xzr", "mov x18, xzr", "mov x19, xzr",
            "mov x20, xzr", "mov x21, xzr", "mov x22, xzr", "mov x23, xzr", "mov x24, xzr",
            "mov x25, xzr", "mov x26, xzr", "mov x27, xzr", "mov x28, xzr", "mov x29, xzr",
            "mov x30, xzr",
            "eret",
            usp = in(reg) user_sp,
            entry = in(reg) entry,
            ksp = in(reg) kernel_sp,
            options(noreturn),
        )
    }
}

/// Power State Coordination Interface: CPU power control through firmware
/// or the hypervisor.
pub mod psci {
    use core::arch::asm;

    /// How PSCI calls reach the implementation (the device tree's
    /// `/psci` `method` property).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Conduit {
        /// `hvc #0`: implemented by a hypervisor (QEMU without EL2/EL3).
        Hvc,
        /// `smc #0`: implemented by secure firmware.
        Smc,
    }

    impl Conduit {
        /// Parses the device tree `method` string.
        pub fn from_method(method: &str) -> Option<Self> {
            match method {
                "hvc" => Some(Self::Hvc),
                "smc" => Some(Self::Smc),
                _ => None,
            }
        }
    }

    const CPU_ON: u64 = 0xc400_0003;
    const SYSTEM_OFF: u64 = 0x8400_0008;
    const SYSTEM_RESET: u64 = 0x8400_0009;

    /// Performs a raw PSCI call and returns `x0`.
    ///
    /// # Safety
    /// PSCI calls start and stop CPUs and power the machine off.
    pub unsafe fn call(conduit: Conduit, fid: u64, a1: u64, a2: u64, a3: u64) -> i64 {
        let ret: i64;
        // SAFETY: the SMC Calling Convention preserves x4-x30 and sp.
        unsafe {
            match conduit {
                Conduit::Hvc => asm!("hvc #0", inlateout("x0") fid as i64 => ret, inlateout("x1") a1 => _,
                    inlateout("x2") a2 => _, inlateout("x3") a3 => _, options(nostack)),
                Conduit::Smc => asm!("smc #0", inlateout("x0") fid as i64 => ret, inlateout("x1") a1 => _,
                    inlateout("x2") a2 => _, inlateout("x3") a3 => _, options(nostack)),
            }
        }
        ret
    }

    /// Starts the CPU with affinity `mpidr` at physical address `entry`,
    /// with `context` in `x0`. Returns the PSCI status (0 on success).
    ///
    /// # Safety
    /// `entry` must be code that sets up its own stack, with the MMU off.
    pub unsafe fn cpu_on(conduit: Conduit, mpidr: u64, entry: u64, context: u64) -> i64 {
        // SAFETY: forwarded contract.
        unsafe { call(conduit, CPU_ON, mpidr, entry, context) }
    }

    /// Powers the system off.
    pub fn system_off(conduit: Conduit) -> ! {
        // SAFETY: SYSTEM_OFF does not return on success.
        unsafe { call(conduit, SYSTEM_OFF, 0, 0, 0) };
        crate::cpu::halt_forever()
    }

    /// Resets the system.
    pub fn system_reset(conduit: Conduit) -> ! {
        // SAFETY: SYSTEM_RESET does not return on success.
        unsafe { call(conduit, SYSTEM_RESET, 0, 0, 0) };
        crate::cpu::halt_forever()
    }
}

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
