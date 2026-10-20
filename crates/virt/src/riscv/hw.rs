//! The world switch and hypervisor CSRs (riscv64 with `riscv64-hs`).
//!
//! `osmium_hs_run` saves the host's callee-saved registers in
//! [`GuestState`], points `TrapCpu::guest` at it, loads the guest's
//! registers and `sret`s into VS-mode. Every trap from the guest enters the
//! normal trap stub, whose hook sees `hstatus.SPV` and jumps to
//! `osmium_hs_exit` with `sp` = &TrapCpu and the interrupted (guest) `sp` in
//! `sscratch`. The exit path saves the guest's registers and the trap CSRs,
//! restores `sscratch` and the host registers, and returns from
//! `osmium_hs_run`.

use core::arch::{asm, global_asm};
use core::mem::offset_of;

use osmium_arch::trap::offsets;

use super::{FpState, GuestState, RiscvVcpu, VsCsrs};

global_asm!(
    r#"
    .section .text.osmium_hs, "ax", @progbits
    .balign 4
    .globl osmium_hs_run
osmium_hs_run:
    sd ra, {host}+0(a0)
    sd sp, {host}+8(a0)
    sd gp, {host}+16(a0)
    sd tp, {host}+24(a0)
    sd s0, {host}+32(a0)
    sd s1, {host}+40(a0)
    sd s2, {host}+48(a0)
    sd s3, {host}+56(a0)
    sd s4, {host}+64(a0)
    sd s5, {host}+72(a0)
    sd s6, {host}+80(a0)
    sd s7, {host}+88(a0)
    sd s8, {host}+96(a0)
    sd s9, {host}+104(a0)
    sd s10, {host}+112(a0)
    sd s11, {host}+120(a0)
    // Host sstatus, restored on exit. For the guest: interrupts off until
    // sret, SPP = the guest's privilege.
    csrr t0, sstatus
    sd t0, {host}+128(a0)
    li t1, -0x123        // ~(SPP | SPIE | SIE)
    and t0, t0, t1
    ld t1, {sstatus}(a0)
    andi t1, t1, 0x100
    or t0, t0, t1
    csrw sstatus, t0
    csrr t0, sscratch    // this CPU's TrapCpu
    // TrapCpu.guest stays non-null from here until osmium_hs_exit clears
    // it: the trap entry's hook only looks at hstatus.SPV when it is set.
    sd a0, {guest}(t0)
    ld t0, {hstatus}(a0)
    csrw 0x600, t0
    ld t0, {pc}(a0)
    csrw sepc, t0
    ld x1, 8(a0)
    ld x2, 16(a0)
    ld x3, 24(a0)
    ld x4, 32(a0)
    ld x5, 40(a0)
    ld x6, 48(a0)
    ld x7, 56(a0)
    ld x8, 64(a0)
    ld x9, 72(a0)
    ld x11, 88(a0)
    ld x12, 96(a0)
    ld x13, 104(a0)
    ld x14, 112(a0)
    ld x15, 120(a0)
    ld x16, 128(a0)
    ld x17, 136(a0)
    ld x18, 144(a0)
    ld x19, 152(a0)
    ld x20, 160(a0)
    ld x21, 168(a0)
    ld x22, 176(a0)
    ld x23, 184(a0)
    ld x24, 192(a0)
    ld x25, 200(a0)
    ld x26, 208(a0)
    ld x27, 216(a0)
    ld x28, 224(a0)
    ld x29, 232(a0)
    ld x30, 240(a0)
    ld x31, 248(a0)
    ld x10, 80(a0)
    sret

    // From the trap stub's hook: sp = &TrapCpu, sscratch = guest sp, guest
    // t0/t1 in TrapCpu's scratch slots.
    .globl osmium_hs_exit
osmium_hs_exit:
    ld t0, {guest}(sp)
    sd x1, 8(t0)
    sd x3, 24(t0)
    sd x4, 32(t0)
    sd x7, 56(t0)
    sd x8, 64(t0)
    sd x9, 72(t0)
    sd x10, 80(t0)
    sd x11, 88(t0)
    sd x12, 96(t0)
    sd x13, 104(t0)
    sd x14, 112(t0)
    sd x15, 120(t0)
    sd x16, 128(t0)
    sd x17, 136(t0)
    sd x18, 144(t0)
    sd x19, 152(t0)
    sd x20, 160(t0)
    sd x21, 168(t0)
    sd x22, 176(t0)
    sd x23, 184(t0)
    sd x24, 192(t0)
    sd x25, 200(t0)
    sd x26, 208(t0)
    sd x27, 216(t0)
    sd x28, 224(t0)
    sd x29, 232(t0)
    sd x30, 240(t0)
    sd x31, 248(t0)
    ld t1, {scratch}(sp)
    sd t1, 40(t0)
    ld t1, {scratch2}(sp)
    sd t1, 48(t0)
    csrr t1, sscratch
    sd t1, 16(t0)
    csrw sscratch, sp
    sd zero, {guest}(sp) // back in the host for good: see the sret path
    csrr t1, sepc
    sd t1, {pc}(t0)
    csrr t1, sstatus
    sd t1, {sstatus}(t0)
    csrr t1, 0x600       // hstatus
    sd t1, {hstatus}(t0)
    csrr t1, scause
    sd t1, {scause}(t0)
    csrr t1, stval
    sd t1, {stval}(t0)
    csrr t1, 0x643       // htval
    sd t1, {htval}(t0)
    csrr t1, 0x64a       // htinst
    sd t1, {htinst}(t0)
    ld ra, {host}+0(t0)
    ld sp, {host}+8(t0)
    ld gp, {host}+16(t0)
    ld tp, {host}+24(t0)
    ld s0, {host}+32(t0)
    ld s1, {host}+40(t0)
    ld s2, {host}+48(t0)
    ld s3, {host}+56(t0)
    ld s4, {host}+64(t0)
    ld s5, {host}+72(t0)
    ld s6, {host}+80(t0)
    ld s7, {host}+88(t0)
    ld s8, {host}+96(t0)
    ld s9, {host}+104(t0)
    ld s10, {host}+112(t0)
    ld s11, {host}+120(t0)
    ld t1, {host}+128(t0)
    csrw sstatus, t1
    ret
"#,
    host = const offset_of!(GuestState, host),
    pc = const offset_of!(GuestState, pc),
    sstatus = const offset_of!(GuestState, sstatus),
    hstatus = const offset_of!(GuestState, hstatus),
    scause = const offset_of!(GuestState, scause),
    stval = const offset_of!(GuestState, stval),
    htval = const offset_of!(GuestState, htval),
    htinst = const offset_of!(GuestState, htinst),
    guest = const offsets::GUEST,
    scratch = const offsets::SCRATCH,
    scratch2 = const offsets::SCRATCH2,
);

const _: () = assert!(offset_of!(GuestState, x) == 0, "the stub addresses x[i] as 8*i");

unsafe extern "C" {
    fn osmium_hs_run(state: *mut GuestState);
}

macro_rules! csr_read {
    ($csr:literal) => {{
        let v: u64;
        // SAFETY: reading a hypervisor CSR has no side effects.
        unsafe { asm!(concat!("csrr {}, ", $csr), out(reg) v, options(nomem, nostack)) };
        v
    }};
}

macro_rules! csr_write {
    ($csr:literal, $v:expr) => {
        // SAFETY: the caller is the hypervisor, which owns these CSRs.
        unsafe { asm!(concat!("csrw ", $csr, ", {}"), in(reg) $v, options(nomem, nostack)) }
    };
}

const HIDELEG: u64 = super::hvip::VSSIP | super::hvip::VSTIP | super::hvip::VSEIP;

macro_rules! csr_set {
    ($csr:literal, $v:expr) => {
        // SAFETY: the hypervisor owns this hart's FS field around a run.
        unsafe { asm!(concat!("csrs ", $csr, ", {}"), in(reg) $v, options(nomem, nostack)) }
    };
}

macro_rules! csr_clear {
    ($csr:literal, $v:expr) => {
        // SAFETY: as above.
        unsafe { asm!(concat!("csrc ", $csr, ", {}"), in(reg) $v, options(nomem, nostack)) }
    };
}

/// Prepares this hart to run guests: delegates the guest's own exceptions
/// and VS-level interrupts to it, lets it read the counters, and enables
/// `vstimecmp` (Sstc). Running a vCPU does this itself on a hart that has
/// not been prepared (e.g. after its task migrated), so calling it is
/// optional.
pub fn init_cpu() {
    // Misaligned/access/page faults, illegal instruction, breakpoint, and
    // ecall from VU-mode go straight to the guest kernel.
    let hedeleg: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7)
        | (1 << 8) | (1 << 12) | (1 << 13) | (1 << 15);
    csr_write!("0x602", hedeleg);
    csr_write!("0x603", HIDELEG);
    csr_write!("0x606", 0xffff_ffffu64); // hcounteren
    csr_write!("0x60a", 1u64 << 63); // henvcfg.STCE
    csr_write!("0x605", 0u64); // htimedelta
    csr_write!("0x645", 0u64); // hvip
    csr_write!("0x680", 0u64); // hgatp
}

/// The `time` CSR, the clock `vstimecmp` compares against.
pub fn time() -> u64 {
    let t: u64;
    // SAFETY: reading the time counter has no side effects.
    unsafe { asm!("rdtime {}", out(reg) t, options(nomem, nostack)) };
    t
}

fn load_vs(c: &VsCsrs) {
    csr_write!("0x200", c.vsstatus);
    csr_write!("0x204", c.vsie);
    csr_write!("0x205", c.vstvec);
    csr_write!("0x240", c.vsscratch);
    csr_write!("0x241", c.vsepc);
    csr_write!("0x242", c.vscause);
    csr_write!("0x243", c.vstval);
    csr_write!("0x280", c.vsatp);
    csr_write!("0x645", c.hvip);
    csr_write!("0x24d", c.vstimecmp);
}

fn save_vs(c: &mut VsCsrs) {
    c.vsstatus = csr_read!("0x200");
    c.vsie = csr_read!("0x204");
    c.vstvec = csr_read!("0x205");
    c.vsscratch = csr_read!("0x240");
    c.vsepc = csr_read!("0x241");
    c.vscause = csr_read!("0x242");
    c.vstval = csr_read!("0x243");
    c.vsatp = csr_read!("0x280");
    c.hvip = csr_read!("0x645");
    c.vstimecmp = csr_read!("0x24d");
}

/// Executes a remote fence requested of this hart: `fence.i`, then
/// `hfence.vvma` for all guest addresses of the VM whose `hgatp` is given
/// (it applies to the VMID currently in `hgatp`, so install it first).
pub(super) fn fence_guest(hgatp: u64) {
    csr_write!("0x680", hgatp);
    // SAFETY: instruction-cache and guest-TLB maintenance only.
    unsafe { asm!("fence.i", ".insn r 0x73, 0, 0x11, x0, x0, x0", options(nostack)) };
}

const SSTATUS_FS: u64 = 3 << 13;

/// Loads `fp` into the FP registers. `sstatus.FS` must be on.
fn load_fp(fp: &FpState) {
    // SAFETY: reads only `fp`; the host kernel keeps no FP state.
    unsafe {
        asm!(
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
            p = in(reg) fp as *const FpState,
            t = out(reg) _,
            options(nostack, readonly),
        )
    }
}

/// Saves the FP registers into `fp`. `sstatus.FS` must be on.
fn save_fp(fp: &mut FpState) {
    // SAFETY: writes only `fp`.
    unsafe {
        asm!(
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
            p = in(reg) fp as *mut FpState,
            t = out(reg) _,
            options(nostack),
        )
    }
}

/// Enters the guest and returns at its next exit.
pub(super) fn run(v: &mut RiscvVcpu) {
    // FP works in a guest only while the host's sstatus.FS is on too, so it
    // is on across every run. The vCPU's registers are always loaded (no
    // values leak from another vCPU) and saved if the guest had FP on.
    csr_set!("sstatus", SSTATUS_FS);
    load_fp(&v.fp);
    // The vCPU's task may have moved to a hart that never ran a guest.
    if csr_read!("0x603") != HIDELEG {
        init_cpu();
    }
    if csr_read!("0x680") != v.hgatp {
        csr_write!("0x680", v.hgatp);
        // SAFETY: hfence.gvma and hfence.vvma (all addresses, all VMIDs)
        // only invalidate TLB entries.
        unsafe {
            asm!(".insn r 0x73, 0, 0x31, x0, x0, x0", ".insn r 0x73, 0, 0x11, x0, x0, x0", options(nostack))
        };
    }
    load_vs(&v.csrs);
    // SAFETY: `state` stays valid and exclusively borrowed for the guest run;
    // the assembly saves and restores every callee-saved host register.
    unsafe { osmium_hs_run(&mut v.state) };
    save_vs(&mut v.csrs);
    if v.csrs.vsstatus & SSTATUS_FS != 0 {
        save_fp(&mut v.fp);
    }
    csr_clear!("sstatus", SSTATUS_FS);
}

/// Reads the guest instruction at guest-virtual `pc` with `hlvx.hu`, using
/// the guest's own translation. Only called right after the guest executed
/// it, so its page is mapped.
pub(super) fn fetch(pc: u64) -> Option<u32> {
    let hlvx = |addr: u64| {
        let v: u64;
        // SAFETY: a hypervisor load from guest memory with the guest's privilege.
        unsafe { asm!(".insn r 0x73, 4, 0x32, {0}, {1}, x3", out(reg) v, in(reg) addr, options(nostack, readonly)) };
        v & 0xffff
    };
    let lo = hlvx(pc);
    if lo & 3 != 3 {
        return Some(lo as u32);
    }
    Some((lo | hlvx(pc + 2) << 16) as u32)
}
