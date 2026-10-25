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
//! - x86_64: x87, MMX and SSE (`FXSAVE` format). When the CPU has XSAVE and
//!   AVX, [`enable`] also turns on `CR4.OSXSAVE` and `XCR0` x87|SSE|AVX, and
//!   the switch uses `XSAVE`/`XRSTOR` so the upper halves of `ymm0`..`ymm15`
//!   are kept too ([`avx_enabled`]). Without them AVX instructions raise
//!   `#UD`. AVX-512, MPX, PKRU and AMX stay off (`XCR0` bits clear).
//! - AArch64: `q0`..`q31`, `FPCR` and `FPSR`. For tasks that use SVE, see
//!   [`SveState`], which replaces `FpState` for that task. SME is not enabled.
//! - RISC-V: `f0`..`f31` and `fcsr` (the D extension).
//!
//! On hosted targets a per-thread variable stands in for the registers.

use core::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);
/// x86_64: the switch uses XSAVE/XRSTOR (set by [`enable`]).
static XSAVE_ON: AtomicBool = AtomicBool::new(false);

/// Returns true if [`enable`] turned on AVX (`XCR0.YMM`) and the context
/// switch therefore keeps the upper halves of the `ymm` registers. Always
/// false off x86_64 and on hosted builds.
pub fn avx_enabled() -> bool {
    XSAVE_ON.load(Ordering::Relaxed)
}

/// Bytes of an x86_64 [`FpState`]: the XSAVE area for x87|SSE|AVX is 832
/// (512 legacy + 64 header + 256 for `ymm_hi128`), rounded up.
#[cfg(all(bare, target_arch = "x86_64"))]
const XSAVE_AREA: usize = 1024;

/// Returns true once [`enable`] has succeeded on some CPU: tasks that run
/// user code should then get an [`FpState`].
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// One task's FP/SIMD registers, saved while the task is switched out.
#[cfg(all(bare, target_arch = "x86_64"))]
#[repr(C, align(64))]
#[derive(Clone)]
pub struct FpState([u8; XSAVE_AREA]);

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
            let mut b = [0; XSAVE_AREA];
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
        // is 64-byte aligned and larger than the XSAVE area `enable` checked
        // (XSAVE's requested-feature mask is EDX:EAX & XCR0, so all ones
        // saves exactly the enabled components).
        unsafe {
            if XSAVE_ON.load(Ordering::Relaxed) {
                core::arch::asm!("xsave64 [{}]", in(reg) self.0.as_mut_ptr(), in("eax") !0u32, in("edx") !0u32, options(nostack))
            } else {
                core::arch::asm!("fxsave64 [{}]", in(reg) self.0.as_mut_ptr(), options(nostack))
            }
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
        // or `fxsave64`/`xsave64` (its field is private), so MXCSR has no
        // reserved bits set, the XSAVE header is in standard (non-compacted)
        // form with no reserved bits, and the restore cannot fault.
        unsafe {
            if XSAVE_ON.load(Ordering::Relaxed) {
                core::arch::asm!("xrstor64 [{}]", in(reg) self.0.as_ptr(), in("eax") !0u32, in("edx") !0u32, options(nostack, readonly))
            } else {
                core::arch::asm!("fxrstor64 [{}]", in(reg) self.0.as_ptr(), options(nostack, readonly))
            }
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
        enable_xsave();
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

/// The longest SVE vector the architecture allows, in bytes (2048 bits).
const SVE_MAX_VL: usize = 256;

/// One task's SVE registers (`z0`..`z31`, `p0`..`p15`, `FFR`, `FPCR`,
/// `FPSR`), for tasks that use SVE. It replaces [`FpState`] for that task,
/// since `q0`..`q31` are the low 128 bits of `z0`..`z31`; give the scheduler
/// one or the other (`osmium_sched::TaskBuilder::sve_state`).
///
/// It is large (about 8.7 KiB, sized for the longest vector), so build it
/// once and move it into the heap. The vector length is whatever
/// [`sve::enable`] set on every CPU (the CPUs must agree). Only AArch64
/// EL1 bare-metal builds have registers to switch; elsewhere the type exists
/// and does nothing, and [`sve::enable`] returns `None`.
#[repr(C, align(16))]
#[derive(Clone)]
pub struct SveState {
    /// `z0`..`z31`, each `vl` bytes, back to back.
    z: [u8; 32 * SVE_MAX_VL],
    /// `p0`..`p15` then `FFR`, each `vl / 8` bytes, back to back.
    p: [u8; 17 * SVE_MAX_VL / 8],
    fpcr: u64,
    fpsr: u64,
}

impl Default for SveState {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for SveState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SveState").finish_non_exhaustive()
    }
}

impl SveState {
    /// The registers a new program starts with: all zero, default rounding.
    pub const fn new() -> Self {
        Self { z: [0; 32 * SVE_MAX_VL], p: [0; 17 * SVE_MAX_VL / 8], fpcr: 0, fpsr: 0 }
    }

    /// Stores this CPU's SVE registers into `self`.
    ///
    /// # Safety
    /// [`sve::enable`] must have returned `Some` on this CPU.
    pub unsafe fn save(&mut self) {
        #[cfg(all(bare, target_arch = "aarch64", not(feature = "aarch64-el2")))]
        // SAFETY: SVE is on (the caller's contract). The Z area is 32 * 256
        // bytes and the P area 17 * 32, enough for any vector length, and
        // `vl`-scaled offsets stay inside them. `rdffr` clobbers only p0,
        // which is stored first.
        unsafe {
            core::arch::asm!(
                ".arch_extension sve",
                "str z0, [{z}, #0, mul vl]", "str z1, [{z}, #1, mul vl]", "str z2, [{z}, #2, mul vl]", "str z3, [{z}, #3, mul vl]",
                "str z4, [{z}, #4, mul vl]", "str z5, [{z}, #5, mul vl]", "str z6, [{z}, #6, mul vl]", "str z7, [{z}, #7, mul vl]",
                "str z8, [{z}, #8, mul vl]", "str z9, [{z}, #9, mul vl]", "str z10, [{z}, #10, mul vl]", "str z11, [{z}, #11, mul vl]",
                "str z12, [{z}, #12, mul vl]", "str z13, [{z}, #13, mul vl]", "str z14, [{z}, #14, mul vl]", "str z15, [{z}, #15, mul vl]",
                "str z16, [{z}, #16, mul vl]", "str z17, [{z}, #17, mul vl]", "str z18, [{z}, #18, mul vl]", "str z19, [{z}, #19, mul vl]",
                "str z20, [{z}, #20, mul vl]", "str z21, [{z}, #21, mul vl]", "str z22, [{z}, #22, mul vl]", "str z23, [{z}, #23, mul vl]",
                "str z24, [{z}, #24, mul vl]", "str z25, [{z}, #25, mul vl]", "str z26, [{z}, #26, mul vl]", "str z27, [{z}, #27, mul vl]",
                "str z28, [{z}, #28, mul vl]", "str z29, [{z}, #29, mul vl]", "str z30, [{z}, #30, mul vl]", "str z31, [{z}, #31, mul vl]",
                "str p0, [{p}, #0, mul vl]", "str p1, [{p}, #1, mul vl]", "str p2, [{p}, #2, mul vl]", "str p3, [{p}, #3, mul vl]",
                "str p4, [{p}, #4, mul vl]", "str p5, [{p}, #5, mul vl]", "str p6, [{p}, #6, mul vl]", "str p7, [{p}, #7, mul vl]",
                "str p8, [{p}, #8, mul vl]", "str p9, [{p}, #9, mul vl]", "str p10, [{p}, #10, mul vl]", "str p11, [{p}, #11, mul vl]",
                "str p12, [{p}, #12, mul vl]", "str p13, [{p}, #13, mul vl]", "str p14, [{p}, #14, mul vl]", "str p15, [{p}, #15, mul vl]",
                "rdffr p0.b",
                "str p0, [{p}, #16, mul vl]",
                "mrs {t}, fpcr",
                "str {t}, [{c}]",
                "mrs {t}, fpsr",
                "str {t}, [{c}, #8]",
                z = in(reg) self.z.as_mut_ptr(),
                p = in(reg) self.p.as_mut_ptr(),
                c = in(reg) &raw mut self.fpcr,
                t = out(reg) _,
                options(nostack),
            )
        }
        #[cfg(not(all(bare, target_arch = "aarch64", not(feature = "aarch64-el2"))))]
        {
            self.fpcr = 0;
        }
    }

    /// Loads `self` into this CPU's SVE registers, replacing whatever they
    /// held.
    ///
    /// # Safety
    /// [`sve::enable`] must have returned `Some` on this CPU, and whoever
    /// owned the registers must have saved them or no longer need them.
    pub unsafe fn restore(&self) {
        #[cfg(all(bare, target_arch = "aarch64", not(feature = "aarch64-el2")))]
        // SAFETY: SVE is on (the caller's contract); reads only `self`, within
        // the same bounds as `save`. FFR is loaded through p0 before p0 itself.
        unsafe {
            core::arch::asm!(
                ".arch_extension sve",
                "ldr p0, [{p}, #16, mul vl]",
                "wrffr p0.b",
                "ldr p0, [{p}, #0, mul vl]", "ldr p1, [{p}, #1, mul vl]", "ldr p2, [{p}, #2, mul vl]", "ldr p3, [{p}, #3, mul vl]",
                "ldr p4, [{p}, #4, mul vl]", "ldr p5, [{p}, #5, mul vl]", "ldr p6, [{p}, #6, mul vl]", "ldr p7, [{p}, #7, mul vl]",
                "ldr p8, [{p}, #8, mul vl]", "ldr p9, [{p}, #9, mul vl]", "ldr p10, [{p}, #10, mul vl]", "ldr p11, [{p}, #11, mul vl]",
                "ldr p12, [{p}, #12, mul vl]", "ldr p13, [{p}, #13, mul vl]", "ldr p14, [{p}, #14, mul vl]", "ldr p15, [{p}, #15, mul vl]",
                "ldr z0, [{z}, #0, mul vl]", "ldr z1, [{z}, #1, mul vl]", "ldr z2, [{z}, #2, mul vl]", "ldr z3, [{z}, #3, mul vl]",
                "ldr z4, [{z}, #4, mul vl]", "ldr z5, [{z}, #5, mul vl]", "ldr z6, [{z}, #6, mul vl]", "ldr z7, [{z}, #7, mul vl]",
                "ldr z8, [{z}, #8, mul vl]", "ldr z9, [{z}, #9, mul vl]", "ldr z10, [{z}, #10, mul vl]", "ldr z11, [{z}, #11, mul vl]",
                "ldr z12, [{z}, #12, mul vl]", "ldr z13, [{z}, #13, mul vl]", "ldr z14, [{z}, #14, mul vl]", "ldr z15, [{z}, #15, mul vl]",
                "ldr z16, [{z}, #16, mul vl]", "ldr z17, [{z}, #17, mul vl]", "ldr z18, [{z}, #18, mul vl]", "ldr z19, [{z}, #19, mul vl]",
                "ldr z20, [{z}, #20, mul vl]", "ldr z21, [{z}, #21, mul vl]", "ldr z22, [{z}, #22, mul vl]", "ldr z23, [{z}, #23, mul vl]",
                "ldr z24, [{z}, #24, mul vl]", "ldr z25, [{z}, #25, mul vl]", "ldr z26, [{z}, #26, mul vl]", "ldr z27, [{z}, #27, mul vl]",
                "ldr z28, [{z}, #28, mul vl]", "ldr z29, [{z}, #29, mul vl]", "ldr z30, [{z}, #30, mul vl]", "ldr z31, [{z}, #31, mul vl]",
                "ldr {t}, [{c}]",
                "msr fpcr, {t}",
                "ldr {t}, [{c}, #8]",
                "msr fpsr, {t}",
                z = in(reg) self.z.as_ptr(),
                p = in(reg) self.p.as_ptr(),
                c = in(reg) &raw const self.fpcr,
                t = out(reg) _,
                options(nostack, readonly),
            )
        }
    }
}

/// SVE (Scalable Vector Extension) control.
pub mod sve {
    /// Turns SVE on for EL0 and EL1 on this CPU at the longest vector length
    /// the CPU supports, and returns that length in bytes; `None` if the CPU
    /// has no SVE or this is not an AArch64 EL1 bare-metal build. Call on
    /// every CPU, after [`super::enable`], before running tasks that have an
    /// [`super::SveState`]. The returned length must be the same on every CPU.
    ///
    /// # Safety
    /// As for [`super::enable`]: the kernel must not use SVE registers itself.
    pub unsafe fn enable() -> Option<usize> {
        #[cfg(all(bare, target_arch = "aarch64", not(feature = "aarch64-el2")))]
        {
            let pfr0: u64;
            // SAFETY: reading an ID register has no side effects.
            unsafe {
                core::arch::asm!("mrs {}, id_aa64pfr0_el1", out(reg) pfr0, options(nomem, nostack, preserves_flags))
            };
            if (pfr0 >> 32) & 0xf == 0 {
                return None;
            }
            let vl: usize;
            // SAFETY: SVE is implemented. CPACR_EL1.ZEN = 0b11 allows SVE at
            // EL0 and EL1; ZCR_EL1.LEN = 15 requests the longest vector, which
            // the CPU clamps to its maximum, and `rdvl` reads the result.
            unsafe {
                crate::aarch64::write_cpacr_el1(crate::aarch64::read_cpacr_el1() | 0b11 << 16);
                core::arch::asm!(
                    ".arch_extension sve",
                    "msr s3_0_c1_c2_0, {t}", // ZCR_EL1
                    "isb",
                    "rdvl {vl}, #1",
                    t = in(reg) 15u64,
                    vl = out(reg) vl,
                    options(nostack),
                );
            }
            Some(vl)
        }
        #[cfg(not(all(bare, target_arch = "aarch64", not(feature = "aarch64-el2"))))]
        None
    }
}

/// Turns on `CR4.OSXSAVE` and `XCR0` = x87|SSE|AVX if the CPU has XSAVE and
/// AVX and the resulting save area fits [`FpState`]; otherwise leaves the
/// FXSAVE path in use.
#[cfg(all(bare, target_arch = "x86_64"))]
fn enable_xsave() {
    use crate::x86_64::cpuid;
    const XSAVE: u32 = 1 << 26;
    const AVX: u32 = 1 << 28;
    let c1 = cpuid(1, 0).ecx;
    if c1 & XSAVE == 0 || c1 & AVX == 0 || cpuid(0xd, 0).eax & 7 != 7 {
        return;
    }
    // SAFETY: XSAVE is present, so CR4.OSXSAVE and XSETBV exist. XCR0 = 7
    // (x87, SSE, AVX) is a valid value: bit 0 set, and AVX (bit 2) needs
    // SSE (bit 1), which CPUID.0Dh reported as supported.
    unsafe {
        core::arch::asm!(
            "mov {t}, cr4",
            "or {t}, 0x40000",
            "mov cr4, {t}",
            "xor ecx, ecx",
            "xsetbv",
            t = out(reg) _,
            in("eax") 7u32,
            in("edx") 0u32,
            out("ecx") _,
            options(nomem, nostack),
        )
    };
    // With XCR0 = 7, EBX is the size of the area `xsave` writes.
    if cpuid(0xd, 0).ebx as usize <= XSAVE_AREA {
        XSAVE_ON.store(true, Ordering::Relaxed);
    } else {
        // SAFETY: as above, XCR0 = 3 (x87|SSE) is valid; AVX goes back off.
        unsafe {
            core::arch::asm!("xor ecx, ecx", "xsetbv", in("eax") 3u32, in("edx") 0u32, out("ecx") _, options(nomem, nostack))
        };
    }
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
