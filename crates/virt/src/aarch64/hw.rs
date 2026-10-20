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

use super::{Aarch64Vcpu, El1Regs, GuestState};

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

/// `HCR_EL2` while a guest runs: stage 2 on (VM), set/way invalidation
/// upgraded (SWIO), physical IRQ/FIQ/SError to EL2 (IMO, FMO, AMO), WFI and
/// SMC trapped (TWI, TSC), and an AArch64 EL1 (RW).
pub const HCR_GUEST: u64 = 1 << 0 | 1 << 1 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 13 | 1 << 19 | 1 << 31;
/// `HCR_EL2.VI`: a virtual IRQ is pending for the guest.
pub const HCR_VI: u64 = 1 << 7;

/// `VTCR_EL2` for [`Stage2Table`](crate::stage2::Stage2Table): 48-bit IPA
/// (T0SZ 16) starting at level 0, 4 KiB granule, write-back cacheable,
/// inner shareable walks, 48-bit output.
pub const VTCR_48: u64 = 16 | 2 << 6 | 1 << 8 | 1 << 10 | 3 << 12 | 5 << 16 | 1 << 31;

/// Prepares this CPU to run guests: stage-2 geometry, EL1 access to the
/// physical counter and timer, and a zero virtual-counter offset. Call
/// once per CPU at EL2.
pub fn init_cpu() {
    msr!("vtcr_el2", VTCR_48);
    msr!("cnthctl_el2", 3u64); // EL1PCTEN | EL1PCEN
    msr!("cntvoff_el2", 0u64);
    // SAFETY: only orders the writes above.
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
}

fn load_el1(r: &El1Regs) {
    msr!("sctlr_el1", r.sctlr);
    msr!("ttbr0_el1", r.ttbr0);
    msr!("ttbr1_el1", r.ttbr1);
    msr!("tcr_el1", r.tcr);
    msr!("mair_el1", r.mair);
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

/// Enters the guest and returns at its next exit.
pub(super) fn run(v: &mut Aarch64Vcpu) {
    let daif = mrs!("daif");
    // SAFETY: masks interrupts for the switch; restored below.
    unsafe { asm!("msr daifset, #0xf", options(nomem, nostack, preserves_flags)) };
    let hcr = HCR_GUEST | if v.irq.load(core::sync::atomic::Ordering::Acquire) { HCR_VI } else { 0 };
    msr!("hcr_el2", hcr);
    if mrs!("vttbr_el2") != v.vttbr {
        msr!("vttbr_el2", v.vttbr);
        // SAFETY: TLB maintenance for the new stage-2 tables (all VMIDs is
        // coarse but correct).
        unsafe { asm!("isb", "tlbi alle1is", "dsb ish", "isb", options(nostack, preserves_flags)) };
    }
    load_el1(&v.el1);
    // SAFETY: orders the context writes before entering the guest.
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
    // SAFETY: `state` stays valid and exclusively borrowed for the guest run;
    // the assembly saves and restores every callee-saved host register.
    unsafe { osmium_el2_run(&mut v.state) };
    save_el1(&mut v.el1);
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
