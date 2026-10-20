//! Per-task floating-point and SIMD registers.
//!
//! Osmium's kernel targets are soft-float, so the kernel never touches the
//! FP/SIMD registers: while a task runs, they hold its user program's values,
//! even inside a system call or interrupt. A kernel that lets user programs
//! use FP turns it on with [`enable`] on every CPU and gives each user task
//! an [`FpState`] (see `osmium_sched::TaskBuilder::fp_state`); the context
//! switch then saves the outgoing task's registers and loads the incoming
//! task's.
//!
//! What is switched:
//! - x86_64: x87, MMX and SSE (`FXSAVE` format, 512 bytes). AVX stays off
//!   (`CR4.OSXSAVE` clear), so AVX instructions raise `#UD`.
//! - AArch64: `q0`..`q31`, `FPCR` and `FPSR`. SVE and SME are not enabled.
//! - RISC-V: `f0`..`f31` and `fcsr` (the D extension).
//!
//! On hosted targets a per-thread variable stands in for the registers.

use core::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Returns true once [`enable`] has succeeded on some CPU: tasks that run
/// user code should then get an [`FpState`].
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// One task's FP/SIMD registers, saved while the task is switched out.
#[cfg(all(bare, target_arch = "x86_64"))]
#[repr(C, align(16))]
#[derive(Clone)]
pub struct FpState([u8; 512]);

/// One task's FP/SIMD registers, saved while the task is switched out.
#[cfg(all(bare, target_arch = "aarch64"))]
#[repr(C, align(16))]
#[derive(Clone)]
pub struct FpState {
    q: [u128; 32],
    fpcr: u64,
    fpsr: u64,
}

/// One task's FP/SIMD registers, saved while the task is switched out.
#[cfg(all(bare, target_arch = "riscv64"))]
#[repr(C)]
#[derive(Clone)]
pub struct FpState {
    f: [u64; 32],
    fcsr: u64,
}

/// One task's FP/SIMD registers, saved while the task is switched out.
#[cfg(not(bare))]
#[derive(Clone)]
pub struct FpState(u64);

impl Default for FpState {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for FpState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FpState").finish_non_exhaustive()
    }
}

impl FpState {
    /// The registers a new program starts with: all zero, default rounding,
    /// and on x86 every exception masked (`FCW` 0x37f, `MXCSR` 0x1f80).
    pub const fn new() -> Self {
        #[cfg(all(bare, target_arch = "x86_64"))]
        {
            let mut b = [0; 512];
            b[0] = 0x7f;
            b[1] = 0x03;
            b[24] = 0x80;
            b[25] = 0x1f;
            Self(b)
        }
        #[cfg(all(bare, target_arch = "aarch64"))]
        {
            Self { q: [0; 32], fpcr: 0, fpsr: 0 }
        }
        #[cfg(all(bare, target_arch = "riscv64"))]
        {
            Self { f: [0; 32], fcsr: 0 }
        }
        #[cfg(not(bare))]
        {
            Self(0)
        }
    }

    /// The registers live on this CPU now: what a forked child inherits.
    ///
    /// # Safety
    /// As for [`FpState::save`].
    pub unsafe fn capture() -> Self {
        let mut s = Self::new();
        // SAFETY: the caller upholds the contract.
        unsafe { s.save() };
        s
    }

    /// Stores this CPU's FP/SIMD registers into `self`.
    ///
    /// # Safety
    /// [`enable`] must have returned true on this CPU.
    pub unsafe fn save(&mut self) {
        #[cfg(all(bare, target_arch = "x86_64"))]
        // SAFETY: FP is on (the caller's contract); writes only `self`, which
        // is 512 bytes and 16-byte aligned.
        unsafe {
            core::arch::asm!("fxsave64 [{}]", in(reg) self.0.as_mut_ptr(), options(nostack))
        }
        #[cfg(all(bare, target_arch = "aarch64"))]
        // SAFETY: FP is on (the caller's contract); writes only `self`.
        unsafe {
            core::arch::asm!(
                ".arch_extension fp",
                ".arch_extension simd",
                "stp q0, q1, [{p}, #0]", "stp q2, q3, [{p}, #32]", "stp q4, q5, [{p}, #64]", "stp q6, q7, [{p}, #96]",
                "stp q8, q9, [{p}, #128]", "stp q10, q11, [{p}, #160]", "stp q12, q13, [{p}, #192]", "stp q14, q15, [{p}, #224]",
                "stp q16, q17, [{p}, #256]", "stp q18, q19, [{p}, #288]", "stp q20, q21, [{p}, #320]", "stp q22, q23, [{p}, #352]",
                "stp q24, q25, [{p}, #384]", "stp q26, q27, [{p}, #416]", "stp q28, q29, [{p}, #448]", "stp q30, q31, [{p}, #480]",
                "mrs {t}, fpcr",
                "str {t}, [{p}, #512]",
                "mrs {t}, fpsr",
                "str {t}, [{p}, #520]",
                p = in(reg) self as *mut Self,
                t = out(reg) _,
                options(nostack),
            )
        }
        #[cfg(all(bare, target_arch = "riscv64"))]
        // SAFETY: FP is on (the caller's contract); writes only `self`.
        unsafe {
            core::arch::asm!(
                ".option push",
                ".option arch, +d",
                "fsd f0, 0({p})", "fsd f1, 8({p})", "fsd f2, 16({p})", "fsd f3, 24({p})",
                "fsd f4, 32({p})", "fsd f5, 40({p})", "fsd f6, 48({p})", "fsd f7, 56({p})",
                "fsd f8, 64({p})", "fsd f9, 72({p})", "fsd f10, 80({p})", "fsd f11, 88({p})",
                "fsd f12, 96({p})", "fsd f13, 104({p})", "fsd f14, 112({p})", "fsd f15, 120({p})",
                "fsd f16, 128({p})", "fsd f17, 136({p})", "fsd f18, 144({p})", "fsd f19, 152({p})",
                "fsd f20, 160({p})", "fsd f21, 168({p})", "fsd f22, 176({p})", "fsd f23, 184({p})",
                "fsd f24, 192({p})", "fsd f25, 200({p})", "fsd f26, 208({p})", "fsd f27, 216({p})",
                "fsd f28, 224({p})", "fsd f29, 232({p})", "fsd f30, 240({p})", "fsd f31, 248({p})",
                "frcsr {t}",
                "sd {t}, 256({p})",
                ".option pop",
                p = in(reg) self as *mut Self,
                t = out(reg) _,
                options(nostack),
            )
        }
        #[cfg(not(bare))]
        {
            self.0 = host::live();
        }
    }

    /// Loads `self` into this CPU's FP/SIMD registers, replacing whatever
    /// they held.
    ///
    /// # Safety
    /// [`enable`] must have returned true on this CPU, and whoever owned the
    /// registers must have saved them or no longer need them.
    pub unsafe fn restore(&self) {
        #[cfg(all(bare, target_arch = "x86_64"))]
        // SAFETY: FP is on (the caller's contract). `self` came from `new`
        // or `fxsave64` (its fields are private), so MXCSR has no reserved
        // bits set and `fxrstor64` cannot fault.
        unsafe {
            core::arch::asm!("fxrstor64 [{}]", in(reg) self.0.as_ptr(), options(nostack, readonly))
        }
        #[cfg(all(bare, target_arch = "aarch64"))]
        // SAFETY: FP is on (the caller's contract); reads only `self`.
        unsafe {
            core::arch::asm!(
                ".arch_extension fp",
                ".arch_extension simd",
                "ldp q0, q1, [{p}, #0]", "ldp q2, q3, [{p}, #32]", "ldp q4, q5, [{p}, #64]", "ldp q6, q7, [{p}, #96]",
                "ldp q8, q9, [{p}, #128]", "ldp q10, q11, [{p}, #160]", "ldp q12, q13, [{p}, #192]", "ldp q14, q15, [{p}, #224]",
                "ldp q16, q17, [{p}, #256]", "ldp q18, q19, [{p}, #288]", "ldp q20, q21, [{p}, #320]", "ldp q22, q23, [{p}, #352]",
                "ldp q24, q25, [{p}, #384]", "ldp q26, q27, [{p}, #416]", "ldp q28, q29, [{p}, #448]", "ldp q30, q31, [{p}, #480]",
                "ldr {t}, [{p}, #512]",
                "msr fpcr, {t}",
                "ldr {t}, [{p}, #520]",
                "msr fpsr, {t}",
                p = in(reg) self as *const Self,
                t = out(reg) _,
                options(nostack, readonly),
            )
        }
        #[cfg(all(bare, target_arch = "riscv64"))]
        // SAFETY: FP is on (the caller's contract); reads only `self`.
        unsafe {
            core::arch::asm!(
                ".option push",
                ".option arch, +d",
                "fld f0, 0({p})", "fld f1, 8({p})", "fld f2, 16({p})", "fld f3, 24({p})",
                "fld f4, 32({p})", "fld f5, 40({p})", "fld f6, 48({p})", "fld f7, 56({p})",
                "fld f8, 64({p})", "fld f9, 72({p})", "fld f10, 80({p})", "fld f11, 88({p})",
                "fld f12, 96({p})", "fld f13, 104({p})", "fld f14, 112({p})", "fld f15, 120({p})",
                "fld f16, 128({p})", "fld f17, 136({p})", "fld f18, 144({p})", "fld f19, 152({p})",
                "fld f20, 160({p})", "fld f21, 168({p})", "fld f22, 176({p})", "fld f23, 184({p})",
                "fld f24, 192({p})", "fld f25, 200({p})", "fld f26, 208({p})", "fld f27, 216({p})",
                "fld f28, 224({p})", "fld f29, 232({p})", "fld f30, 240({p})", "fld f31, 248({p})",
                "ld {t}, 256({p})",
                "fscsr {t}",
                ".option pop",
                p = in(reg) self as *const Self,
                t = out(reg) _,
                options(nostack, readonly),
            )
        }
        #[cfg(not(bare))]
        host::set_live(self.0);
    }
}

#[cfg(all(bare, target_arch = "aarch64"))]
const _: () = assert!(core::mem::offset_of!(FpState, fpcr) == 512 && core::mem::offset_of!(FpState, fpsr) == 520);
#[cfg(all(bare, target_arch = "riscv64"))]
const _: () = assert!(core::mem::offset_of!(FpState, fcsr) == 256);

/// Turns FP/SIMD on for the kernel and user mode on this CPU, undoing any
/// earlier `trap_fp`, and returns true; false if this CPU or build has no FP
/// to switch (RISC-V without F, M-mode builds, AArch64 EL2 builds). Call it
/// on every CPU before running tasks that have an [`FpState`].
///
/// # Safety
/// The kernel must not use FP/SIMD registers itself (Osmium's soft-float
/// targets do not), or it would corrupt user programs' values. On RISC-V the
/// CPU must have the D extension if it has F (`riscv,isa` lists `d`).
pub unsafe fn enable() -> bool {
    #[cfg(all(bare, target_arch = "x86_64"))]
    let on = {
        // SAFETY: the caller upholds the contract. CR0: MP and NE set, EM and
        // TS clear; CR4: OSFXSR and OSXMMEXCPT. Every x86_64 CPU has SSE2.
        unsafe {
            core::arch::asm!(
                "mov {t}, cr0",
                "and {t}, ~0xc",
                "or {t}, 0x22",
                "mov cr0, {t}",
                "mov {t}, cr4",
                "or {t}, 0x600",
                "mov cr4, {t}",
                t = out(reg) _,
                options(nomem, nostack, preserves_flags),
            )
        };
        true
    };
    #[cfg(all(bare, target_arch = "aarch64", not(feature = "aarch64-el2")))]
    let on = {
        // SAFETY: the caller upholds the contract. CPACR_EL1.FPEN = 0b11: no
        // traps at EL0 or EL1.
        unsafe {
            crate::aarch64::write_cpacr_el1(crate::aarch64::read_cpacr_el1() | 0b11 << 20);
            core::arch::asm!("isb", options(nostack, preserves_flags));
        }
        true
    };
    #[cfg(all(bare, target_arch = "aarch64", feature = "aarch64-el2"))]
    let on = false;
    #[cfg(all(bare, target_arch = "riscv64", not(feature = "riscv-m-mode")))]
    let on = {
        const FS: usize = 0x6000;
        // SAFETY: the caller upholds the contract. FS = Initial; it reads
        // back as Off on a CPU without F.
        unsafe { core::arch::asm!("csrs sstatus, {}", in(reg) 0x2000, options(nostack)) };
        crate::riscv64::read_sstatus() & FS != 0
    };
    #[cfg(all(bare, target_arch = "riscv64", feature = "riscv-m-mode"))]
    let on = false;
    #[cfg(not(bare))]
    let on = true;
    if on {
        ENABLED.store(true, Ordering::Relaxed);
    }
    on
}

/// The simulated FP registers of hosted builds: one value per thread.
#[cfg(not(bare))]
pub mod host {
    use core::cell::Cell;

    std::thread_local! {
        static LIVE: Cell<u64> = const { Cell::new(0) };
    }

    /// The calling thread's simulated FP registers.
    pub fn live() -> u64 {
        LIVE.with(Cell::get)
    }

    /// Sets the calling thread's simulated FP registers.
    pub fn set_live(v: u64) {
        LIVE.with(|l| l.set(v));
    }
}

#[cfg(all(test, not(bare)))]
mod tests {
    use super::*;

    #[test]
    fn save_and_restore_round_trip() {
        // SAFETY: hosted; the registers are simulated.
        assert!(unsafe { enable() });
        assert!(enabled());
        host::set_live(7);
        // SAFETY: as above.
        let saved = unsafe { FpState::capture() };
        host::set_live(9);
        // SAFETY: as above.
        unsafe { FpState::new().restore() };
        assert_eq!(host::live(), 0);
        // SAFETY: as above.
        unsafe { saved.restore() };
        assert_eq!(host::live(), 7);
    }
}
