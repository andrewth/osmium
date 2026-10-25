//! The world switch and EL2 controls (aarch64 with `aarch64-el2`).
//!
//! `osmium_el2_run` saves the host's callee-saved registers and sp in
//! [`GuestState`], points `TrapCpu::guest` at it, loads the guest's
//! registers and `eret`s to EL1. Every exception from the guest enters the
//! EL2 vector table's lower-EL slots, whose hook branches to
//! `osmium_el2_guest_exit` with x0 = &GuestState, x1 = the vector, and the
//! guest's x0/x1 on the (host) stack. The exit path saves the guest's
//! registers and syndrome, clears `TrapCpu::guest` and returns from
//! `osmium_el2_run`. The EL1 system registers are switched in Rust around
//! the call, with interrupts masked.

use core::arch::{asm, global_asm};
use core::mem::offset_of;

use osmium_arch::trap::offsets;

use super::{Aarch64Vcpu, El1Regs, FpState, GuestState, VgicLink};

global_asm!(
    r#"
    .section .text.osmium_el2, "ax"
    .balign 4
    .globl osmium_el2_run
osmium_el2_run:
    stp x19, x20, [x0, #{host} + 0]
    stp x21, x22, [x0, #{host} + 16]
    stp x23, x24, [x0, #{host} + 32]
    stp x25, x26, [x0, #{host} + 48]
    stp x27, x28, [x0, #{host} + 64]
    stp x29, x30, [x0, #{host} + 80]
    mov x2, sp
    str x2, [x0, #{host} + 96]
    // Publish the guest in this CPU's TrapCpu.
    mrs x2, tpidr_el2
    adrp x3, OSMIUM_TRAP_CPUS
    add x3, x3, :lo12:OSMIUM_TRAP_CPUS
    add x2, x3, x2, lsl #6
    str x0, [x2, #{guest}]
    ldr x2, [x0, #{pc}]
    msr elr_el2, x2
    ldr x2, [x0, #{pstate}]
    msr spsr_el2, x2
    ldp x2, x3, [x0, #16]
    ldp x4, x5, [x0, #32]
    ldp x6, x7, [x0, #48]
    ldp x8, x9, [x0, #64]
    ldp x10, x11, [x0, #80]
    ldp x12, x13, [x0, #96]
    ldp x14, x15, [x0, #112]
    ldp x16, x17, [x0, #128]
    ldp x18, x19, [x0, #144]
    ldp x20, x21, [x0, #160]
    ldp x22, x23, [x0, #176]
    ldp x24, x25, [x0, #192]
    ldp x26, x27, [x0, #208]
    ldp x28, x29, [x0, #224]
    ldr x30, [x0, #240]
    ldp x0, x1, [x0, #0]
    eret

    .globl osmium_el2_guest_exit
osmium_el2_guest_exit:
    stp x2, x3, [x0, #16]
    stp x4, x5, [x0, #32]
    stp x6, x7, [x0, #48]
    stp x8, x9, [x0, #64]
    stp x10, x11, [x0, #80]
    stp x12, x13, [x0, #96]
    stp x14, x15, [x0, #112]
    stp x16, x17, [x0, #128]
    stp x18, x19, [x0, #144]
    stp x20, x21, [x0, #160]
    stp x22, x23, [x0, #176]
    stp x24, x25, [x0, #192]
    stp x26, x27, [x0, #208]
    stp x28, x29, [x0, #224]
    str x30, [x0, #240]
    ldp x2, x3, [sp], #16           // the guest's x0, x1
    stp x2, x3, [x0, #0]
    str x1, [x0, #{vector}]
    mrs x2, elr_el2
    str x2, [x0, #{pc}]
    mrs x2, spsr_el2
    str x2, [x0, #{pstate}]
    mrs x2, esr_el2
    str x2, [x0, #{esr}]
    mrs x2, far_el2
    str x2, [x0, #{far}]
    mrs x2, hpfar_el2
    str x2, [x0, #{hpfar}]
    mrs x2, tpidr_el2
    adrp x3, OSMIUM_TRAP_CPUS
    add x3, x3, :lo12:OSMIUM_TRAP_CPUS
    add x2, x3, x2, lsl #6
    str xzr, [x2, #{guest}]
    ldp x19, x20, [x0, #{host} + 0]
    ldp x21, x22, [x0, #{host} + 16]
    ldp x23, x24, [x0, #{host} + 32]
    ldp x25, x26, [x0, #{host} + 48]
    ldp x27, x28, [x0, #{host} + 64]
    ldp x29, x30, [x0, #{host} + 80]
    ldr x2, [x0, #{host} + 96]
    mov sp, x2
    ret
"#,
    host = const offset_of!(GuestState, host),
    pc = const offset_of!(GuestState, pc),
    pstate = const offset_of!(GuestState, pstate),
    esr = const offset_of!(GuestState, esr),
    far = const offset_of!(GuestState, far),
    hpfar = const offset_of!(GuestState, hpfar),
    vector = const offset_of!(GuestState, vector),
    guest = const offsets::GUEST,
);

const _: () = assert!(offset_of!(GuestState, x) == 0, "the stubs address x[i] as 8*i");
const _: () = assert!(size_of::<osmium_arch::trap::TrapCpu>() == 64, "the stubs index TrapCpu with lsl #6");

unsafe extern "C" {
    fn osmium_el2_run(state: *mut GuestState);
}

macro_rules! mrs {
    ($r:literal) => {{
        let v: u64;
        // SAFETY: reading a system register at EL2 has no side effects.
        unsafe { asm!(concat!("mrs {}, ", $r), out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }};
}

macro_rules! msr {
    ($r:literal, $v:expr) => {
        // SAFETY: the hypervisor owns the EL1 context and the EL2 controls.
        unsafe { asm!(concat!("msr ", $r, ", {}"), in(reg) $v, options(nomem, nostack, preserves_flags)) }
    };
}

/// `ICH_HCR_EL2.En`: the virtual CPU interface is on. `UIE` asks for a
/// maintenance interrupt once at most one list register is still in use.
const ICH_HCR_EN: u64 = 1;
const ICH_HCR_UIE: u64 = 1 << 1;

/// The virtual GIC CPU interface registers (by encoding, as the assembler
/// accepts them without the GICv3 name set): `ICH_HCR_EL2`, `ICH_VTR_EL2`,
/// `ICH_VMCR_EL2`, `ICH_AP0R0_EL2`, `ICH_AP1R0_EL2`.
macro_rules! ich {
    (hcr) => {
        "S3_4_C12_C11_0"
    };
    (vtr) => {
        "S3_4_C12_C11_1"
    };
    (vmcr) => {
        "S3_4_C12_C11_7"
    };
    (ap0r0) => {
        "S3_4_C12_C8_0"
    };
    (ap1r0) => {
        "S3_4_C12_C9_0"
    };
}

/// Generates `read_lr(n)` and `write_lr(n, v)` over `ICH_LR<n>_EL2`, whose
/// encodings are `S3_4_C12_C(12 + n/8)_(n%8)`.
macro_rules! list_registers {
    ($($n:literal => $crm:literal, $op2:literal;)*) => {
        fn read_lr(n: usize) -> u64 {
            match n {
                $($n => {
                    let v: u64;
                    // SAFETY: reading a list register at EL2 has no side effects.
                    unsafe { asm!(concat!("mrs {}, S3_4_C12_C", $crm, "_", $op2), out(reg) v, options(nomem, nostack, preserves_flags)) };
                    v
                })*
                _ => 0,
            }
        }

        fn write_lr(n: usize, v: u64) {
            match n {
                // SAFETY: the hypervisor owns the virtual CPU interface.
                $($n => unsafe { asm!(concat!("msr S3_4_C12_C", $crm, "_", $op2, ", {}"), in(reg) v, options(nomem, nostack, preserves_flags)) },)*
                _ => {}
            }
        }
    };
}

list_registers! {
    0 => 12, 0; 1 => 12, 1; 2 => 12, 2; 3 => 12, 3; 4 => 12, 4; 5 => 12, 5; 6 => 12, 6; 7 => 12, 7;
    8 => 13, 0; 9 => 13, 1; 10 => 13, 2; 11 => 13, 3; 12 => 13, 4; 13 => 13, 5; 14 => 13, 6; 15 => 13, 7;
}

/// How many list registers this CPU implements (`ICH_VTR_EL2.ListRegs` + 1).
pub(super) fn list_registers() -> usize {
    let vtr: u64;
    // SAFETY: reading an ID register at EL2 has no side effects.
    unsafe { asm!(concat!("mrs {}, ", ich!(vtr)), out(reg) vtr, options(nomem, nostack, preserves_flags)) };
    (vtr & 0x1f) as usize + 1
}

fn load_vgic(l: &VgicLink) {
    // SAFETY: the hypervisor owns the virtual CPU interface; it is off while the host runs.
    unsafe {
        asm!(concat!("msr ", ich!(vmcr), ", {}"), in(reg) l.vmcr, options(nomem, nostack, preserves_flags));
        asm!(concat!("msr ", ich!(ap0r0), ", {}"), in(reg) l.ap0r0, options(nomem, nostack, preserves_flags));
        asm!(concat!("msr ", ich!(ap1r0), ", {}"), in(reg) l.ap1r0, options(nomem, nostack, preserves_flags));
    }
    for (n, &v) in l.lr.iter().enumerate().take(l.nlr) {
        write_lr(n, v);
    }
    let hcr = ICH_HCR_EN | if l.overflow { ICH_HCR_UIE } else { 0 };
    // SAFETY: as above.
    unsafe { asm!(concat!("msr ", ich!(hcr), ", {}"), in(reg) hcr, options(nomem, nostack, preserves_flags)) };
}

fn save_vgic(l: &mut VgicLink) {
    let (vmcr, ap0, ap1): (u64, u64, u64);
    // SAFETY: reads the virtual CPU interface and then switches it off for the host.
    unsafe {
        asm!(concat!("mrs {}, ", ich!(vmcr)), out(reg) vmcr, options(nomem, nostack, preserves_flags));
        asm!(concat!("mrs {}, ", ich!(ap0r0)), out(reg) ap0, options(nomem, nostack, preserves_flags));
        asm!(concat!("mrs {}, ", ich!(ap1r0)), out(reg) ap1, options(nomem, nostack, preserves_flags));
        asm!(concat!("msr ", ich!(hcr), ", {}"), in(reg) 0u64, options(nomem, nostack, preserves_flags));
    }
    (l.vmcr, l.ap0r0, l.ap1r0) = (vmcr, ap0, ap1);
    for (n, v) in l.lr.iter_mut().enumerate().take(l.nlr) {
        *v = read_lr(n);
    }
}

/// `HCR_EL2` while a guest runs: stage 2 on (VM), set/way invalidation
/// upgraded (SWIO), physical IRQ/FIQ/SError to EL2 (IMO, FMO, AMO), WFI and
/// SMC trapped (TWI, TSC), IMPLEMENTATION DEFINED and auxiliary control
/// registers trapped (TIDCP, TACR), and an AArch64 EL1 (RW). FB (bit 9)
/// forces the guest's TLB and instruction-cache maintenance to broadcast:
/// the vCPUs of a VM share a VMID and may run on other CPUs, so a "local"
/// invalidation by the guest must reach every CPU that can hold its entries.
pub const HCR_GUEST: u64 =
    1 << 0 | 1 << 1 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 9 | 1 << 13 | 1 << 19 | 1 << 20 | 1 << 21 | 1 << 31;
/// `HCR_EL2.VI`: a virtual IRQ is pending for the guest.
pub const HCR_VI: u64 = 1 << 7;

/// `VTCR_EL2` for [`Stage2Table`](crate::stage2::Stage2Table): 48-bit IPA
/// (T0SZ 16) starting at level 0, 4 KiB granule, write-back cacheable,
/// inner shareable walks, 48-bit output.
pub const VTCR_48: u64 = 16 | 2 << 6 | 1 << 8 | 1 << 10 | 3 << 12 | 5 << 16 | 1 << 31;

/// Prepares this CPU to run guests: stage-2 geometry, EL1 access to the
/// physical counter and timer, and a zero virtual-counter offset. Running a
/// vCPU does this itself on a CPU that has not been prepared, so calling it
/// is optional.
pub fn init_cpu() {
    msr!("vtcr_el2", VTCR_48);
    // EL1 may read the physical counter (EL1PCTEN) but not use the
    // physical timer, which is the host's: guests get the virtual one.
    msr!("cnthctl_el2", 1u64);
    // PMU and debug registers trap (TPM, TPMCR, TDA, TDOSA, TDRA), so no
    // counter or breakpoint state passes between VMs and the host; HPMN
    // keeps every implemented counter for EL2.
    let counters = (mrs!("pmcr_el0") >> 11) & 0x1f;
    msr!("mdcr_el2", counters | 1 << 5 | 1 << 6 | 1 << 9 | 1 << 10 | 1 << 11);
    msr!("cntvoff_el2", 0u64);
    // FP/SIMD untrapped (TFP = 0) so guests can use it and the switch can
    // move it; SVE still traps (TZ). The other bits are RES1.
    msr!("cptr_el2", 0x33ffu64);
    // SAFETY: only orders the writes above.
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
}

fn load_el1(r: &El1Regs) {
    msr!("sctlr_el1", r.sctlr);
    msr!("ttbr0_el1", r.ttbr0);
    msr!("ttbr1_el1", r.ttbr1);
    msr!("tcr_el1", r.tcr);
    msr!("mair_el1", r.mair);
    msr!("amair_el1", r.amair);
    msr!("afsr0_el1", r.afsr0);
    msr!("afsr1_el1", r.afsr1);
    msr!("csselr_el1", r.csselr);
    msr!("vbar_el1", r.vbar);
    msr!("contextidr_el1", r.contextidr);
    msr!("esr_el1", r.esr);
    msr!("far_el1", r.far);
    msr!("par_el1", r.par);
    msr!("sp_el1", r.sp_el1);
    msr!("elr_el1", r.elr);
    msr!("spsr_el1", r.spsr);
    msr!("sp_el0", r.sp_el0);
    msr!("tpidr_el0", r.tpidr_el0);
    msr!("tpidrro_el0", r.tpidrro_el0);
    msr!("tpidr_el1", r.tpidr_el1);
    msr!("cpacr_el1", r.cpacr);
    msr!("cntkctl_el1", r.cntkctl);
    msr!("cntv_cval_el0", r.cntv_cval);
    msr!("cntv_ctl_el0", r.cntv_ctl);
}

fn save_el1(r: &mut El1Regs) {
    // SP_EL0 and TPIDRRO_EL0 first: the host's current-EL vectors use them
    // as scratch (interrupts are still masked here).
    r.sp_el0 = mrs!("sp_el0");
    r.tpidrro_el0 = mrs!("tpidrro_el0");
    r.sctlr = mrs!("sctlr_el1");
    r.ttbr0 = mrs!("ttbr0_el1");
    r.ttbr1 = mrs!("ttbr1_el1");
    r.tcr = mrs!("tcr_el1");
    r.mair = mrs!("mair_el1");
    r.amair = mrs!("amair_el1");
    r.afsr0 = mrs!("afsr0_el1");
    r.afsr1 = mrs!("afsr1_el1");
    r.csselr = mrs!("csselr_el1");
    r.vbar = mrs!("vbar_el1");
    r.contextidr = mrs!("contextidr_el1");
    r.esr = mrs!("esr_el1");
    r.far = mrs!("far_el1");
    r.par = mrs!("par_el1");
    r.sp_el1 = mrs!("sp_el1");
    r.elr = mrs!("elr_el1");
    r.spsr = mrs!("spsr_el1");
    r.tpidr_el0 = mrs!("tpidr_el0");
    r.tpidr_el1 = mrs!("tpidr_el1");
    r.cpacr = mrs!("cpacr_el1");
    r.cntkctl = mrs!("cntkctl_el1");
    r.cntv_cval = mrs!("cntv_cval_el0");
    r.cntv_ctl = mrs!("cntv_ctl_el0");
}

fn load_fp(fp: &FpState) {
    // SAFETY: reads only `fp`; the host kernel keeps no FP/SIMD state.
    unsafe {
        asm!(
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
            p = in(reg) fp as *const FpState,
            t = out(reg) _,
            options(nostack, readonly),
        )
    }
}

fn save_fp(fp: &mut FpState) {
    // SAFETY: writes only `fp`.
    unsafe {
        asm!(
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
            p = in(reg) fp as *mut FpState,
            t = out(reg) _,
            options(nostack),
        )
    }
}

const _: () = assert!(offset_of!(FpState, fpcr) == 512 && offset_of!(FpState, fpsr) == 520);

/// The vCPU each CPU last ran (by [`Aarch64Vcpu::id`](super::Aarch64Vcpu)).
static LAST_VCPU: [core::sync::atomic::AtomicU64; osmium_arch::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; osmium_arch::MAX_CPUS];

/// Enters the guest and returns at its next exit.
pub(super) fn run(v: &mut Aarch64Vcpu) {
    let daif = mrs!("daif");
    // SAFETY: masks interrupts for the switch; restored below.
    unsafe { asm!("msr daifset, #0xf", options(nomem, nostack, preserves_flags)) };
    // The vCPU's task may have moved to a CPU that never ran a guest.
    if mrs!("vtcr_el2") != VTCR_48 {
        init_cpu();
    }
    // A GICv3 guest's interrupts come from the list registers instead.
    let vi = v.vgic.is_none() && v.irq.load(core::sync::atomic::Ordering::Acquire);
    let hcr = HCR_GUEST | if vi { HCR_VI } else { 0 };
    msr!("hcr_el2", hcr);
    if let Some(m) = v.vmpidr {
        msr!("vmpidr_el2", m);
    }
    // A different vCPU than this CPU last ran (or a new VM that reuses an
    // old one's VMID and root): install its VTTBR and flush.
    let cpu = osmium_arch::cpu::current_id();
    let last = LAST_VCPU.get(cpu).map_or(0, |l| l.swap(v.id, core::sync::atomic::Ordering::Relaxed));
    // Also a vCPU that last ran on another CPU: entries of its VMID cached
    // here may predate invalidations done while it ran there.
    let last_cpu = core::mem::replace(&mut v.last_cpu, cpu);
    let switched = crate::vcpu::tlb_may_be_stale(last, v.id, last_cpu, cpu);
    // `flush_stage2` was called since the last entry: the tables changed.
    let stale = core::mem::take(&mut v.flush);
    if switched || mrs!("vttbr_el2") != v.vttbr {
        msr!("vttbr_el2", v.vttbr);
        // SAFETY: TLB maintenance for the new stage-2 tables (all VMIDs is
        // coarse but correct).
        unsafe { asm!("isb", "tlbi alle1is", "dsb ish", "isb", options(nostack, preserves_flags)) };
    } else if stale {
        // SAFETY: invalidates this VMID's stage 1 and 2 entries (VTTBR_EL2
        // is current), broadcast to the inner shareable domain.
        unsafe { asm!("tlbi vmalls12e1is", "dsb ish", "isb", options(nostack, preserves_flags)) };
    }
    load_el1(&v.el1);
    load_fp(&v.fp);
    if let Some(l) = &v.vgic {
        load_vgic(l);
    }
    // SAFETY: orders the context writes before entering the guest.
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
    // SAFETY: `state` stays valid and exclusively borrowed for the guest run;
    // the assembly saves and restores every callee-saved host register.
    unsafe { osmium_el2_run(&mut v.state) };
    save_el1(&mut v.el1);
    save_fp(&mut v.fp);
    if let Some(l) = &mut v.vgic {
        save_vgic(l);
    }
    // The guest's timer must not fire while the host runs; its level is
    // recomputed in software before the next entry.
    msr!("cntv_ctl_el0", 0u64);
    // Back to the host's stage-1 only: no stage 2, nothing routed.
    msr!("hcr_el2", 1u64 << 31);
    // SAFETY: restores the caller's interrupt mask.
    unsafe { asm!("msr daif, {}", in(reg) daif, options(nomem, nostack, preserves_flags)) };
}

/// The physical counter, which the guest's virtual counter equals.
pub fn counter() -> u64 {
    mrs!("cntpct_el0")
}
