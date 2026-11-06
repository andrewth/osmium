// SPDX-License-Identifier: GPL-2.0-only
//! The world switch and EL2 controls (aarch64 with `aarch64-el2` or
//! `aarch64-vhe`).
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
//!
//! # VHE hosts (`aarch64-vhe`)
//!
//! The assembly is the same for a host that runs at EL2 with
//! `HCR_EL2.E2H` = 1: its hook is in the EL1 build's lower-EL vectors
//! (`osmium-arch` with `aarch64-vhe`), which a VHE host shares with its own
//! user-mode traps. What differs is around it. The guest's EL1 registers are
//! reached through their `_EL12` and `_EL02` names, since the `_EL1` names
//! are the host's own EL2 registers. `HCR_EL2` keeps `E2H` and drops `TGE`
//! for the guest, and the host's `HCR_EL2`, `CPTR_EL2` and `MDCR_EL2`, and
//! its FP/SIMD registers if they were in use, `TPIDR_EL0`, `PAR_EL1` and
//! `CSSELR_EL1` (which VHE does not redirect), are put back on exit.

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
    ($r:expr) => {{
        let v: u64;
        // SAFETY: reading a system register at EL2 has no side effects.
        unsafe { asm!(concat!("mrs {}, ", $r), out(reg) v, options(nomem, nostack, preserves_flags)) };
        v
    }};
}

macro_rules! msr {
    ($r:expr, $v:expr) => {
        // SAFETY: the hypervisor owns the EL1 context and the EL2 controls.
        unsafe { asm!(concat!("msr ", $r, ", {}"), in(reg) $v, options(nomem, nostack, preserves_flags)) }
    };
}

/// The name of the guest's EL1 register `$r`: `<r>_el1` without VHE, where
/// the host does not use EL1, and `<r>_el12` with it, where `<r>_el1` is the
/// host's own (redirected to EL2). The `_el12` names are spelled by
/// encoding (`op1` 5 in place of the EL1 register's 0), since the
/// assembler accepts them only with the `vh` target feature.
#[cfg(not(aarch64_vhe))]
macro_rules! el1 {
    ($r:literal) => {
        concat!($r, "_el1")
    };
}
#[cfg(aarch64_vhe)]
macro_rules! el1 {
    ("sctlr") => {
        "S3_5_C1_C0_0"
    };
    ("cpacr") => {
        "S3_5_C1_C0_2"
    };
    ("ttbr0") => {
        "S3_5_C2_C0_0"
    };
    ("ttbr1") => {
        "S3_5_C2_C0_1"
    };
    ("tcr") => {
        "S3_5_C2_C0_2"
    };
    ("spsr") => {
        "S3_5_C4_C0_0"
    };
    ("elr") => {
        "S3_5_C4_C0_1"
    };
    ("afsr0") => {
        "S3_5_C5_C1_0"
    };
    ("afsr1") => {
        "S3_5_C5_C1_1"
    };
    ("esr") => {
        "S3_5_C5_C2_0"
    };
    ("far") => {
        "S3_5_C6_C0_0"
    };
    ("mair") => {
        "S3_5_C10_C2_0"
    };
    ("amair") => {
        "S3_5_C10_C3_0"
    };
    ("vbar") => {
        "S3_5_C12_C0_0"
    };
    ("contextidr") => {
        "S3_5_C13_C0_1"
    };
    ("cntkctl") => {
        "S3_5_C14_C1_0"
    };
}

/// The guest's virtual timer register `$r`: `<r>_el0`, or `<r>_el02` with
/// VHE (by encoding, as for `el1!`).
#[cfg(not(aarch64_vhe))]
macro_rules! el0 {
    ($r:literal) => {
        concat!($r, "_el0")
    };
}
#[cfg(aarch64_vhe)]
macro_rules! el0 {
    ("cntv_ctl") => {
        "S3_5_C14_C3_1"
    };
    ("cntv_cval") => {
        "S3_5_C14_C3_2"
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
/// registers trapped (TIDCP, TACR), the ID registers trapped (TID3, so
/// the guest reads them through [`Aarch64Vcpu::emulate_sysreg`] with the
/// features whose state is not switched hidden), and an AArch64 EL1 (RW).
/// FB (bit 9) forces the guest's TLB and instruction-cache maintenance to
/// broadcast: the vCPUs of a VM share a VMID and may run on other CPUs, so a
/// "local" invalidation by the guest must reach every CPU that can hold its
/// entries.
pub const HCR_GUEST: u64 =
    1 << 0 | 1 << 1 | 1 << 3 | 1 << 4 | 1 << 5 | 1 << 9 | 1 << 13 | 1 << 18 | 1 << 19 | 1 << 20 | 1 << 21 | 1 << 31;

/// Reads the host's ID register `S3_0_C0_C<crm>_<op2>` (`crm` 1..=7, the
/// space `HCR_EL2.TID3` traps); unallocated encodings there read as zero.
pub(super) fn id_register(crm: u64, op2: u64) -> u64 {
    macro_rules! id_regs {
        ($($crm:literal: $($op2:literal)*;)*) => {
            match (crm, op2) {
                $($(($crm, $op2) => mrs!(concat!("S3_0_C0_C", $crm, "_", $op2)),)*)*
                _ => 0,
            }
        };
    }
    id_regs! {
        1: 0 1 2 3 4 5 6 7;
        2: 0 1 2 3 4 5 6 7;
        3: 0 1 2 3 4 5 6 7;
        4: 0 1 2 3 4 5 6 7;
        5: 0 1 2 3 4 5 6 7;
        6: 0 1 2 3 4 5 6 7;
        7: 0 1 2 3 4 5 6 7;
    }
}
/// `HCR_EL2.VI`: a virtual IRQ is pending for the guest.
pub const HCR_VI: u64 = 1 << 7;
/// `HCR_EL2.TGE`: a VHE host's own EL0 traps to EL2. Set while a VHE host
/// runs, clear while its guest does.
pub const HCR_TGE: u64 = 1 << 27;
/// `HCR_EL2.E2H`: the host is VHE. Set throughout on a VHE host, while its
/// guests run too.
pub const HCR_E2H: u64 = 1 << 34;
/// `HCR_EL2` while a guest of this build runs ([`HCR_GUEST`], plus
/// [`HCR_E2H`] with `aarch64-vhe`).
const HCR_RUN: u64 = HCR_GUEST | if cfg!(aarch64_vhe) { HCR_E2H } else { 0 };

/// `VTCR_EL2` for [`Stage2Table`](crate::stage2::Stage2Table): 48-bit IPA
/// (T0SZ 16) starting at level 0, 4 KiB granule, write-back cacheable,
/// inner shareable walks, 48-bit output.
pub const VTCR_48: u64 = 16 | 2 << 6 | 1 << 8 | 1 << 10 | 3 << 12 | 5 << 16 | 1 << 31;

/// Prepares this CPU to run guests: stage-2 geometry, EL1 access to the
/// physical counter and timer, and a zero virtual-counter offset. Running a
/// vCPU does this itself on a CPU that has not been prepared, so calling it
/// is optional.
#[cfg(not(aarch64_vhe))]
pub fn init_cpu() {
    msr!("vtcr_el2", VTCR_48);
    // Guests read the host's MIDR_EL1 as their own.
    let midr = mrs!("midr_el1");
    msr!("vpidr_el2", midr);
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

/// Prepares this CPU to run guests: stage-2 geometry, the guest's
/// `MIDR_EL1`, and a zero virtual-counter offset. Running a vCPU does this
/// itself on a CPU that has not been prepared, so calling it is optional.
/// The host's `HCR_EL2` must already have `E2H` set.
///
/// The controls a VHE host shares with its guests (`CPTR_EL2`, `MDCR_EL2`
/// and the EL1 bits of `CNTHCTL_EL2`, which the host's `CPACR_EL1` and
/// `CNTKCTL_EL1` writes reach) are set on every entry instead.
#[cfg(aarch64_vhe)]
pub fn init_cpu() {
    msr!("vtcr_el2", VTCR_48);
    let midr = mrs!("midr_el1");
    msr!("vpidr_el2", midr);
    msr!("cntvoff_el2", 0u64);
    // SAFETY: only orders the writes above.
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
}

/// The host's EL2 controls that a VHE guest run changes, put back on exit.
#[cfg(aarch64_vhe)]
struct HostControls {
    hcr: u64,
    cptr: u64,
    mdcr: u64,
    tpidr_el0: u64,
    par: u64,
    csselr: u64,
    /// The host's FP/SIMD registers, if `CPTR_EL2.FPEN` let it use them.
    fp: Option<FpState>,
}

/// `CPTR_EL2` (E2H layout) `FPEN`, `ZEN` and `SMEN` fields.
#[cfg(aarch64_vhe)]
const CPTR_FPEN: u64 = 3 << 20;
#[cfg(aarch64_vhe)]
const CPTR_ZEN: u64 = 3 << 16;
#[cfg(aarch64_vhe)]
const CPTR_SMEN: u64 = 3 << 24;

/// Saves the host's controls and sets the guest's: FP/SIMD untrapped so
/// the guest can use it and the switch can move it (SVE and SME trap), the
/// PMU and debug registers trapped as in [`init_cpu`] without VHE, and EL1
/// access to the physical counter but not to the physical timer (the
/// host's).
#[cfg(aarch64_vhe)]
fn enter_vhe() -> HostControls {
    let cptr = mrs!("cptr_el2");
    let mut host = HostControls {
        hcr: mrs!("hcr_el2"),
        cptr,
        mdcr: mrs!("mdcr_el2"),
        tpidr_el0: mrs!("tpidr_el0"),
        par: mrs!("par_el1"),
        csselr: mrs!("csselr_el1"),
        fp: None,
    };
    msr!("cptr_el2", (cptr & !(CPTR_ZEN | CPTR_SMEN)) | CPTR_FPEN);
    // SAFETY: FP/SIMD is on before the host's registers are read below.
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
    if cptr & CPTR_FPEN == CPTR_FPEN {
        let mut fp = FpState::default();
        save_fp(&mut fp);
        host.fp = Some(fp);
    }
    let counters = (mrs!("pmcr_el0") >> 11) & 0x1f;
    msr!("mdcr_el2", counters | 1 << 5 | 1 << 6 | 1 << 9 | 1 << 10 | 1 << 11);
    // CNTHCTL_EL2 with E2H: EL1PCTEN is bit 10, EL1PTEN bit 11. The EL0
    // bits are the host's (its CNTKCTL_EL1).
    let cnthctl = mrs!("cnthctl_el2");
    msr!("cnthctl_el2", (cnthctl | 1 << 10) & !(1 << 11));
    host
}

/// Puts back what [`enter_vhe`] saved, `HCR_EL2.TGE` included.
#[cfg(aarch64_vhe)]
fn exit_vhe(host: &HostControls) {
    msr!("tpidr_el0", host.tpidr_el0);
    msr!("par_el1", host.par);
    msr!("csselr_el1", host.csselr);
    if let Some(fp) = &host.fp {
        load_fp(fp);
    }
    msr!("mdcr_el2", host.mdcr);
    msr!("cptr_el2", host.cptr);
    msr!("hcr_el2", host.hcr);
    // SAFETY: the host's regime is back before its own code relies on it.
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
}

fn load_el1(r: &El1Regs) {
    msr!(el1!("sctlr"), r.sctlr);
    msr!(el1!("ttbr0"), r.ttbr0);
    msr!(el1!("ttbr1"), r.ttbr1);
    msr!(el1!("tcr"), r.tcr);
    msr!(el1!("mair"), r.mair);
    msr!(el1!("amair"), r.amair);
    msr!(el1!("afsr0"), r.afsr0);
    msr!(el1!("afsr1"), r.afsr1);
    msr!("csselr_el1", r.csselr);
    msr!(el1!("vbar"), r.vbar);
    msr!(el1!("contextidr"), r.contextidr);
    msr!(el1!("esr"), r.esr);
    msr!(el1!("far"), r.far);
    msr!("par_el1", r.par);
    msr!("sp_el1", r.sp_el1);
    msr!(el1!("elr"), r.elr);
    msr!(el1!("spsr"), r.spsr);
    msr!("sp_el0", r.sp_el0);
    msr!("tpidr_el0", r.tpidr_el0);
    msr!("tpidrro_el0", r.tpidrro_el0);
    msr!("tpidr_el1", r.tpidr_el1);
    msr!(el1!("cpacr"), r.cpacr);
    msr!(el1!("cntkctl"), r.cntkctl);
    msr!(el0!("cntv_cval"), r.cntv_cval);
    msr!(el0!("cntv_ctl"), r.cntv_ctl);
}

fn save_el1(r: &mut El1Regs) {
    // SP_EL0 and TPIDRRO_EL0 first: the host's current-EL vectors use them
    // as scratch (interrupts are still masked here).
    r.sp_el0 = mrs!("sp_el0");
    r.tpidrro_el0 = mrs!("tpidrro_el0");
    r.sctlr = mrs!(el1!("sctlr"));
    r.ttbr0 = mrs!(el1!("ttbr0"));
    r.ttbr1 = mrs!(el1!("ttbr1"));
    r.tcr = mrs!(el1!("tcr"));
    r.mair = mrs!(el1!("mair"));
    r.amair = mrs!(el1!("amair"));
    r.afsr0 = mrs!(el1!("afsr0"));
    r.afsr1 = mrs!(el1!("afsr1"));
    r.csselr = mrs!("csselr_el1");
    r.vbar = mrs!(el1!("vbar"));
    r.contextidr = mrs!(el1!("contextidr"));
    r.esr = mrs!(el1!("esr"));
    r.far = mrs!(el1!("far"));
    r.par = mrs!("par_el1");
    r.sp_el1 = mrs!("sp_el1");
    r.elr = mrs!(el1!("elr"));
    r.spsr = mrs!(el1!("spsr"));
    r.tpidr_el0 = mrs!("tpidr_el0");
    r.tpidr_el1 = mrs!("tpidr_el1");
    r.cpacr = mrs!(el1!("cpacr"));
    r.cntkctl = mrs!(el1!("cntkctl"));
    r.cntv_cval = mrs!(el0!("cntv_cval"));
    r.cntv_ctl = mrs!(el0!("cntv_ctl"));
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
    #[cfg(aarch64_vhe)]
    let host = enter_vhe();
    // A GICv3 guest's interrupts come from the list registers instead.
    let vi = v.vgic.is_none() && v.irq.load(core::sync::atomic::Ordering::Acquire);
    let hcr = HCR_RUN | if vi { HCR_VI } else { 0 };
    msr!("hcr_el2", hcr);
    // SAFETY: only orders the write above: the TLB maintenance below must
    // see the guest's HCR_EL2 (on a VHE host, TGE clear: the `E1`
    // operations then mean the EL1&0 regime rather than the host's EL2&0).
    unsafe { asm!("isb", options(nomem, nostack, preserves_flags)) };
    // Always written: a vCPU without its own value must not see the one
    // the previous guest on this CPU left behind.
    let vmpidr = v.vmpidr.unwrap_or_else(|| mrs!("mpidr_el1"));
    msr!("vmpidr_el2", vmpidr);
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
    msr!(el0!("cntv_ctl"), 0u64);
    // Back to the host's stage-1 only: no stage 2, nothing routed.
    #[cfg(not(aarch64_vhe))]
    msr!("hcr_el2", 1u64 << 31);
    // Back to the VHE host's controls, with TGE set again.
    #[cfg(aarch64_vhe)]
    exit_vhe(&host);
    // SAFETY: restores the caller's interrupt mask.
    unsafe { asm!("msr daif, {}", in(reg) daif, options(nomem, nostack, preserves_flags)) };
}

/// The physical counter, which the guest's virtual counter equals.
pub fn counter() -> u64 {
    mrs!("cntpct_el0")
}
