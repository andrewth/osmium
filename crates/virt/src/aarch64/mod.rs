//! An AArch64 EL2 vCPU (non-VHE: the host kernel runs at EL2 with
//! `HCR_EL2.E2H` = 0, the guest at EL1/EL0 under stage-2 translation).
//!
//! Exits are decoded from `ESR_EL2` into a [`VmExit`]:
//!
//! | Exception | Exit |
//! |---|---|
//! | Stage-2 translation fault on a data access from EL1/EL0 with a valid syndrome (ISV), not in a stage-1 walk | [`VmExit::MmioRead`] / [`VmExit::MmioWrite`], address from `HPFAR_EL2` and `FAR_EL2` |
//! | `HVC` (or a trapped `SMC`) | [`VmExit::Hypercall`]: `nr` = `x0` (the SMCCC function ID), `args` = `x1`..`x6` |
//! | Trapped `WFI` (`HCR_EL2.TWI`) | [`VmExit::Halt`] |
//! | IRQ or FIQ taken while the guest ran | [`VmExit::ExternalInterrupt`] |
//! | Anything else | [`VmExit::Unhandled`] with the raw `ESR_EL2` |
//!
//! [`psci`] answers the PSCI calls a single-vCPU guest makes.
//!
//! # Virtual GICv3
//!
//! [`Aarch64Vcpu::with_vgic_v3`] attaches the vCPU to a
//! [`VirtualGicV3`]. The guest then uses the host's virtual CPU interface
//! (`ICV_*`, via `HCR_EL2.IMO` and `ICH_HCR_EL2.En`), which needs a GICv3 host
//! with `ICC_SRE_EL2.Enable` set. Around every guest run the vCPU copies
//! pending interrupts from the model into the list registers and the
//! acknowledged or completed state back (`ICH_LR<n>_EL2`, `ICH_VMCR_EL2`,
//! `ICH_AP*R0_EL2` are part of the world switch). The guest's writes to
//! `ICC_SGI1R_EL1` trap to EL2 and are forwarded to the model. A vCPU with a
//! GICv3 sees `MPIDR_EL1` = [`vcpu_mpidr`](crate::devices::vcpu_mpidr), which
//! is how a guest finds its redistributor.

pub mod fdt;
pub mod psci;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(all(target_arch = "aarch64", feature = "aarch64-el2"))]
mod hw;
#[cfg(all(target_arch = "aarch64", feature = "aarch64-el2"))]
pub use hw::{HCR_GUEST, VTCR_48, counter, init_cpu};

use crate::devices::VirtualGicV3;
use crate::memory::GuestPhysAddr;
use crate::vcpu::{Vcpu, VmExit};

/// The most list registers a GICv3 implements.
pub const MAX_LIST_REGISTERS: usize = 16;

/// The list registers modeled by the host-side tests, which have no hardware.
#[cfg(not(all(target_arch = "aarch64", feature = "aarch64-el2")))]
#[cfg_attr(not(test), allow(dead_code))]
const SIMULATED_LIST_REGISTERS: usize = 4;

/// A vCPU's virtual CPU interface state and its link to the GIC model.
#[cfg_attr(not(all(target_arch = "aarch64", feature = "aarch64-el2")), allow(dead_code))]
struct VgicLink {
    gic: Arc<VirtualGicV3>,
    cpu: usize,
    /// `ICH_LR<n>_EL2` images, `nlr` of them valid.
    lr: [u64; MAX_LIST_REGISTERS],
    nlr: usize,
    /// More interrupts were pending than list registers: ask for a
    /// maintenance interrupt when the guest has consumed them.
    overflow: bool,
    /// `ICH_VMCR_EL2` (the guest's `ICC_PMR`, `ICC_BPR` and group enables).
    vmcr: u64,
    ap0r0: u64,
    ap1r0: u64,
}

/// Exception classes (`ESR_EL2.EC`).
mod ec {
    pub const WFX: u64 = 0x01;
    pub const HVC64: u64 = 0x16;
    pub const SMC64: u64 = 0x17;
    pub const DABT_LOWER: u64 = 0x24;
    /// MSR/MRS/system instruction trapped (TIDCP, TACR, TPM, TDA, ...).
    pub const SYSREG: u64 = 0x18;
}

/// Lower-EL vector offsets / 0x80 that the exit stub records.
pub mod vector {
    /// Synchronous exception from a lower EL (AArch64).
    pub const SYNC: u64 = 8;
    /// IRQ from a lower EL (AArch64).
    pub const IRQ: u64 = 9;
    /// FIQ from a lower EL (AArch64).
    pub const FIQ: u64 = 10;
    /// SError from a lower EL (AArch64).
    pub const SERROR: u64 = 11;
}

/// Guest registers and exit information, shared with the world-switch
/// assembly.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct GuestState {
    /// `x0`..`x30`.
    pub x: [u64; 31],
    /// Guest program counter (`ELR_EL2`).
    pub pc: u64,
    /// Guest PSTATE (`SPSR_EL2`).
    pub pstate: u64,
    /// `ESR_EL2` at the last exit.
    pub esr: u64,
    /// `FAR_EL2` at the last exit.
    pub far: u64,
    /// `HPFAR_EL2` at the last exit.
    pub hpfar: u64,
    /// Which lower-EL vector the last exit came through ([`vector`]).
    pub vector: u64,
    /// Host x19-x30 and sp, saved across the guest run.
    pub(crate) host: [u64; 13],
}

/// PSTATE for a guest starting at EL1h with DAIF masked.
pub const PSTATE_EL1H: u64 = 0x3c5;

/// A pending emulated load: destination register and how to extend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Load {
    reg: u8,
    size: u8,
    sign: bool,
    wide: bool,
    /// Instruction length (ESR.IL: 4, or 2 for a 16-bit T32 instruction).
    len: u64,
}

/// The guest's EL1 (and EL0) system registers, switched on every entry
/// and exit.
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub struct El1Regs {
    pub sctlr: u64,
    pub ttbr0: u64,
    pub ttbr1: u64,
    pub tcr: u64,
    pub mair: u64,
    pub amair: u64,
    pub afsr0: u64,
    pub afsr1: u64,
    pub csselr: u64,
    pub vbar: u64,
    pub contextidr: u64,
    pub esr: u64,
    pub far: u64,
    pub par: u64,
    pub sp_el1: u64,
    pub elr: u64,
    pub spsr: u64,
    pub sp_el0: u64,
    pub tpidr_el0: u64,
    pub tpidrro_el0: u64,
    pub tpidr_el1: u64,
    /// `CPACR_EL1` (the guest's own FP/SIMD enable).
    pub cpacr: u64,
    pub cntkctl: u64,
    pub cntv_cval: u64,
    pub cntv_ctl: u64,
}

impl Default for El1Regs {
    fn default() -> Self {
        Self {
            // MMU and caches off; the RES1 bits set.
            sctlr: 0x30d0_0800,
            ttbr0: 0,
            ttbr1: 0,
            tcr: 0,
            mair: 0,
            amair: 0,
            afsr0: 0,
            afsr1: 0,
            csselr: 0,
            vbar: 0,
            contextidr: 0,
            esr: 0,
            far: 0,
            par: 0,
            sp_el1: 0,
            elr: 0,
            spsr: 0,
            sp_el0: 0,
            tpidr_el0: 0,
            tpidrro_el0: 0,
            tpidr_el1: 0,
            cpacr: 0,
            cntkctl: 0,
            cntv_cval: 0,
            cntv_ctl: 0,
        }
    }
}

/// The guest's FP/SIMD registers.
#[repr(C, align(16))]
#[derive(Clone, Debug, Default)]
pub struct FpState {
    /// `q0`..`q31`.
    pub q: [u128; 32],
    /// `FPCR`.
    pub fpcr: u64,
    /// `FPSR`.
    pub fpsr: u64,
}

/// A virtual CPU running AArch64 code at EL1.
pub struct Aarch64Vcpu {
    /// Registers and exit state.
    pub state: GuestState,
    /// EL1 system registers.
    pub el1: El1Regs,
    /// FP/SIMD registers, loaded before every run and saved after it (the
    /// host kernel is soft-float and keeps none).
    pub fp: FpState,
    /// `VTTBR_EL2` (stage-2 root and VMID).
    pub vttbr: u64,
    irq: Arc<AtomicBool>,
    timer: Option<Box<dyn Fn(bool) + Send + Sync>>,
    pending: Option<Load>,
    vgic: Option<VgicLink>,
    /// `VMPIDR_EL2`, if the vCPU sets one (what the guest reads as `MPIDR_EL1`).
    #[cfg_attr(not(all(target_arch = "aarch64", feature = "aarch64-el2")), allow(dead_code))]
    vmpidr: Option<u64>,
    pub(crate) running: Option<Arc<core::sync::atomic::AtomicUsize>>,
    /// See [`new_vcpu_id`](crate::vcpu::new_vcpu_id).
    #[cfg_attr(not(all(target_arch = "aarch64", feature = "aarch64-el2")), allow(dead_code))]
    pub(crate) id: u64,
    /// The stage-2 tables changed: invalidate the VMID before the next entry.
    #[cfg_attr(not(all(target_arch = "aarch64", feature = "aarch64-el2")), allow(dead_code))]
    pub(crate) flush: bool,
    /// The CPU this vCPU last ran on ([`NO_CPU`](crate::vcpu::NO_CPU) before the first run).
    #[cfg_attr(not(all(target_arch = "aarch64", feature = "aarch64-el2")), allow(dead_code))]
    pub(crate) last_cpu: usize,
}

impl Aarch64Vcpu {
    /// Arranges for the guest's cached stage-2 translations to be
    /// invalidated (`tlbi vmalls12e1is` for its VMID) before this vCPU next
    /// enters the guest. Call it after the hypervisor edits the guest's
    /// stage-2 tables (unmapping or changing permissions of a page): the CPU
    /// caches translations across entries and only flushes when the vCPU or
    /// its `VTTBR_EL2` changes.
    pub fn flush_stage2(&mut self) {
        self.flush = true;
    }

    /// A vCPU that starts at EL1h at `entry` with `x0` = `arg` (the device
    /// tree, by the Linux boot convention), translating through the stage-2
    /// table encoded in `vttbr` (see [`vttbr`](crate::stage2::vttbr)).
    pub fn new(entry: GuestPhysAddr, arg: u64, vttbr: u64) -> Self {
        let mut x = [0; 31];
        x[0] = arg;
        let state =
            GuestState { x, pc: entry.0, pstate: PSTATE_EL1H, esr: 0, far: 0, hpfar: 0, vector: 0, host: [0; 13] };
        Self {
            state,
            el1: El1Regs::default(),
            fp: FpState::default(),
            vttbr,
            id: crate::vcpu::new_vcpu_id(),
            irq: Arc::new(AtomicBool::new(false)),
            timer: None,
            pending: None,
            vgic: None,
            vmpidr: None,
            running: None,
            flush: false,
            last_cpu: crate::vcpu::NO_CPU,
        }
    }

    /// The vCPU's IRQ line, for an interrupt controller (a
    /// [`VirtualGicV2`](crate::devices::VirtualGicV2) output) to drive. Its
    /// level becomes `HCR_EL2.VI` at the next entry.
    pub fn irq_line(&self) -> Arc<AtomicBool> {
        self.irq.clone()
    }

    /// Uses `line` as the IRQ line, for a controller created before the vCPU.
    pub fn with_irq_line(mut self, line: Arc<AtomicBool>) -> Self {
        self.irq = line;
        self
    }

    /// Attaches the vCPU, as CPU `cpu` of `gic`, to a virtual GICv3: see the
    /// module documentation. Also gives the guest `MPIDR_EL1` =
    /// [`vcpu_mpidr`](crate::devices::vcpu_mpidr)`(cpu)`. Interrupt delivery
    /// goes through the GIC's list registers, so the vCPU's IRQ line (see
    /// [`irq_line`](Self::irq_line)) only reports, for `interrupt_pending`,
    /// whether the guest has something to take; wire the GIC's output to it.
    pub fn with_vgic_v3(mut self, gic: Arc<VirtualGicV3>, cpu: usize) -> Self {
        self.vgic = Some(VgicLink {
            gic,
            cpu,
            lr: [0; MAX_LIST_REGISTERS],
            nlr: 0,
            overflow: false,
            vmcr: 0,
            ap0r0: 0,
            ap1r0: 0,
        });
        self.vmpidr = Some(crate::devices::vcpu_mpidr(cpu));
        self
    }

    /// Loads the list registers for the next entry from the GIC model.
    #[cfg_attr(not(all(target_arch = "aarch64", feature = "aarch64-el2")), allow(dead_code))]
    fn vgic_fill(&mut self) {
        let Some(l) = &mut self.vgic else { return };
        #[cfg(all(target_arch = "aarch64", feature = "aarch64-el2"))]
        let n = hw::list_registers();
        #[cfg(not(all(target_arch = "aarch64", feature = "aarch64-el2")))]
        let n = SIMULATED_LIST_REGISTERS;
        l.nlr = n.min(MAX_LIST_REGISTERS);
        if let Some(regs) = l.lr.get_mut(..l.nlr) {
            l.overflow = l.gic.fill_list_registers(l.cpu, regs);
        }
    }

    /// Hands the list registers the guest left back to the GIC model.
    #[cfg_attr(not(all(target_arch = "aarch64", feature = "aarch64-el2")), allow(dead_code))]
    fn vgic_sync(&mut self) {
        let Some(l) = &mut self.vgic else { return };
        if let Some(regs) = l.lr.get(..l.nlr) {
            l.gic.sync_list_registers(l.cpu, regs, l.vmcr);
        }
    }

    /// Connects the guest's virtual timer to an interrupt line (usually the
    /// GIC's PPI 27): before every entry, `line` receives the timer's
    /// level. The hardware timer is disabled while the host runs, and its
    /// expiry during a guest run forces an exit (`HCR_EL2.IMO`), provided
    /// the host's GIC has the PPI enabled. While the level is high the host
    /// should disable that PPI in its own GIC (and re-enable it when the
    /// level drops), or the still-firing timer exits the guest again before
    /// it can handle the virtual interrupt.
    pub fn connect_timer(&mut self, line: impl Fn(bool) + Send + Sync + 'static) {
        self.timer = Some(Box::new(line));
    }

    /// Whether the guest's virtual timer condition is met at counter `now`
    /// (enabled, not masked, compare value reached).
    pub fn timer_level(&self, now: u64) -> bool {
        let ctl = self.el1.cntv_ctl;
        ctl & 1 != 0 && ctl & 2 == 0 && now >= self.el1.cntv_cval
    }

    /// Whether a vCPU halted in `wfi` has a reason to run again at counter
    /// `now`: its IRQ line is up or its timer is due.
    pub fn interrupt_pending(&self, now: u64) -> bool {
        self.irq.load(Ordering::Acquire) || self.timer_level(now)
    }

    /// Feeds the timer line before an entry.
    #[cfg_attr(not(all(target_arch = "aarch64", feature = "aarch64-el2")), allow(dead_code))]
    fn sync_timer(&self, now: u64) {
        if let Some(line) = &self.timer {
            line(self.timer_level(now));
        }
    }

    /// Completes a trapped system-register access (IMPLEMENTATION DEFINED,
    /// auxiliary control, PMU, debug and physical-timer registers, which
    /// `HCR_EL2`, `MDCR_EL2` and `CNTHCTL_EL2` trap) as read-as-zero,
    /// write-ignored, and steps past it. Returns whether the exit was one.
    pub fn emulate_sysreg(&mut self) -> bool {
        let s = &mut self.state;
        if s.vector != vector::SYNC || s.esr >> 26 != ec::SYSREG {
            return false;
        }
        // ISS: Direction (bit 0, 1 = read), Rt (bits 9:5).
        let rt = ((s.esr >> 5) & 31) as usize;
        // ICC_SGI1R_EL1, ICC_ASGI1R_EL1 and ICC_SGI0R_EL1 (Op0 3, Op1 0, CRn 12, CRm 11, Op2 5-7) write: an
        // SGI request for the virtual GIC.
        let (op0, op2, op1, crn, crm) =
            ((s.esr >> 20) & 3, (s.esr >> 17) & 7, (s.esr >> 14) & 7, (s.esr >> 10) & 15, (s.esr >> 1) & 15);
        if s.esr & 1 == 0
            && (op0, op1, crn, crm) == (3, 0, 12, 11)
            && (5..=7).contains(&op2)
            && let Some(l) = &self.vgic
        {
            let v = s.x.get(rt).copied().unwrap_or(0);
            l.gic.send_sgi(l.cpu, v);
            s.pc = s.pc.wrapping_add(4);
            return true;
        }
        if s.esr & 1 != 0
            && let Some(r) = s.x.get_mut(rt)
        {
            *r = 0;
        }
        s.pc = s.pc.wrapping_add(4);
        true
    }

    /// Turns the exception recorded in `state` into an exit.
    pub fn classify(&mut self) -> VmExit {
        let s = &mut self.state;
        match s.vector {
            vector::IRQ | vector::FIQ => return VmExit::ExternalInterrupt,
            vector::SYNC => {}
            _ => return VmExit::Unhandled { reason: s.esr },
        }
        let esr = s.esr;
        let insn_len = if esr & (1 << 25) != 0 { 4 } else { 2 };
        match esr >> 26 {
            ec::WFX if esr & 1 == 0 => {
                s.pc = s.pc.wrapping_add(insn_len);
                VmExit::Halt
            }
            // HVC returns to the next instruction; a trapped SMC to itself.
            ec::HVC64 | ec::SMC64 => {
                if esr >> 26 == ec::SMC64 {
                    s.pc = s.pc.wrapping_add(4);
                }
                VmExit::Hypercall { nr: s.x[0], args: [s.x[1], s.x[2], s.x[3], s.x[4], s.x[5], s.x[6]] }
            }
            // Only a translation fault (DFSC 0b0001xx) on the instruction's own
            // access is an unbacked address. A permission or access-flag fault
            // is on a page that is mapped, and S1PTW marks a fault in the
            // walk of the guest's stage-1 tables: neither is MMIO.
            ec::DABT_LOWER if esr & (1 << 24) != 0 && esr & (1 << 7) == 0 && esr & 0x3c == 0x04 => {
                // ISV: SAS[23:22], SSE[21], SRT[20:16], SF[15], WnR[6].
                let size = 1u8 << ((esr >> 22) & 3);
                let reg = ((esr >> 16) & 31) as u8;
                let addr = GuestPhysAddr((s.hpfar & 0x0fff_ffff_fff0) << 8 | (s.far & 0xfff));
                if esr & (1 << 6) != 0 {
                    let data = s.x.get(reg as usize).copied().unwrap_or(0); // xzr (31) reads as zero
                    let data = data & crate::x86::size_mask(size);
                    s.pc = s.pc.wrapping_add(insn_len);
                    VmExit::MmioWrite { addr, size, data }
                } else {
                    self.pending =
                        Some(Load { reg, size, sign: esr & (1 << 21) != 0, wide: esr & (1 << 15) != 0, len: insn_len });
                    VmExit::MmioRead { addr, size }
                }
            }
            _ => VmExit::Unhandled { reason: esr },
        }
    }
}

impl Vcpu for Aarch64Vcpu {
    #[cfg(all(target_arch = "aarch64", feature = "aarch64-el2"))]
    fn run(&mut self) -> VmExit {
        if let Some(r) = &self.running {
            r.store(osmium_arch::cpu::current_id(), Ordering::Release);
        }
        let exit = loop {
            self.sync_timer(hw::counter());
            self.vgic_fill();
            hw::run(self);
            self.vgic_sync();
            if !self.emulate_sysreg() {
                break self.classify();
            }
        };
        if let Some(r) = &self.running {
            r.store(crate::smp::NOT_RUNNING, Ordering::Release);
        }
        exit
    }

    #[cfg(not(all(target_arch = "aarch64", feature = "aarch64-el2")))]
    fn run(&mut self) -> VmExit {
        // AArch64 guests need an aarch64 build with the aarch64-el2 feature; report an exit nothing handles.
        VmExit::Unhandled { reason: u64::MAX }
    }

    fn complete_read(&mut self, value: u64) {
        let Some(l) = self.pending.take() else { return };
        let mask = crate::x86::size_mask(l.size);
        let mut v = value & mask;
        if l.sign && v & (mask ^ (mask >> 1)) != 0 {
            v |= !mask;
        }
        if !l.wide {
            v &= 0xffff_ffff;
        }
        if let Some(r) = self.state.x.get_mut(l.reg as usize) {
            *r = v; // xzr (31) discards it
        }
        self.state.pc = self.state.pc.wrapping_add(l.len);
    }

    fn complete_hypercall(&mut self, ret: u64) {
        self.state.x[0] = ret;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(v: &mut Aarch64Vcpu, vector: u64, esr: u64, far: u64, hpfar: u64) -> VmExit {
        v.state.vector = vector;
        v.state.esr = esr;
        v.state.far = far;
        v.state.hpfar = hpfar;
        v.classify()
    }

    const IL: u64 = 1 << 25;
    const ISV: u64 = 1 << 24;
    /// DFSC: translation fault, level 3.
    const TRANS: u64 = 0b000111;
    const S1PTW: u64 = 1 << 7;

    #[test]
    fn trapped_sysregs_read_as_zero() {
        let mut v = Aarch64Vcpu::new(GuestPhysAddr(0x4000_0000), 0, 0);
        v.state.x[3] = 0xdead;
        // MRS x3, PMCCNTR_EL0 trapped by MDCR_EL2.TPM: EC 0x18, read, Rt 3.
        v.state.vector = vector::SYNC;
        v.state.esr = ec::SYSREG << 26 | 1 << 25 | 3 << 5 | 1;
        assert!(v.emulate_sysreg());
        assert_eq!((v.state.x[3], v.state.pc), (0, 0x4000_0004));
        // A write is ignored; other exits are not this.
        v.state.esr = ec::SYSREG << 26 | 1 << 25 | 3 << 5;
        v.state.x[3] = 7;
        assert!(v.emulate_sysreg());
        assert_eq!(v.state.x[3], 7);
        v.state.esr = ec::HVC64 << 26;
        assert!(!v.emulate_sysreg());
    }

    #[test]
    fn vgic_v3_sgi_trap_and_list_registers() {
        use crate::devices::VirtualGicV3;
        use core::sync::atomic::AtomicBool;

        let lines = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);
        let l = lines.clone();
        let gic = Arc::new(VirtualGicV3::new(2, 64, move |cpu, v| {
            if let Some(x) = l.get(cpu) {
                x.store(v, Ordering::SeqCst)
            }
        }));
        let (d, r) = (gic.distributor(), gic.redistributors());
        // Bring both redistributors up as a guest would; enable SGI 3 on vCPU 1.
        for cpu in 0..2u64 {
            r.write(cpu * 0x2_0000 + 0x14, &0u32.to_le_bytes());
            r.write(cpu * 0x2_0000 + 0x1_0000 + 0x100, &(1u32 << 3).to_le_bytes());
        }
        d.write(0, &0x13u32.to_le_bytes());
        let mut v0 = Aarch64Vcpu::new(GuestPhysAddr(0x4000_0000), 0, 0).with_vgic_v3(gic.clone(), 0);
        let mut v1 = Aarch64Vcpu::new(GuestPhysAddr(0x4000_0000), 0, 0).with_vgic_v3(gic.clone(), 1);
        assert_eq!(v1.vmpidr, Some(1 << 31 | 1));
        v1.vgic_fill();
        v1.vgic.as_mut().unwrap().vmcr = 0xf8 << 24 | 2;
        v1.vgic_sync();

        // MSR ICC_SGI1R_EL1, x4 at vCPU 0: Op0 3, Op1 0, CRn 12, CRm 11, Op2 5.
        let iss = 3 << 20 | 5 << 17 | 12 << 10 | 4 << 5 | 11 << 1;
        v0.state.vector = vector::SYNC;
        v0.state.esr = ec::SYSREG << 26 | 1 << 25 | iss;
        v0.state.x[4] = 3 << 24 | 0b10; // SGI 3 to Aff0 = 1
        assert!(v0.emulate_sysreg());
        assert_eq!(v0.state.pc, 0x4000_0004);
        assert!(lines[1].load(Ordering::SeqCst), "vCPU 1 has an interrupt to take");
        assert!(!lines[0].load(Ordering::SeqCst));

        // Entry loads it into a list register as pending.
        v1.vgic_fill();
        let l = v1.vgic.as_mut().unwrap();
        assert_eq!(l.lr[0] >> 62, 1);
        assert_eq!(l.lr[0] as u32, 3);
        // The guest acknowledges and completes it (hardware edits the register).
        l.lr[0] = 0;
        v1.vgic_sync();
        assert!(!lines[1].load(Ordering::SeqCst));
        // A read of the same register is not an SGI request.
        v0.state.esr = ec::SYSREG << 26 | 1 << 25 | iss | 1;
        v0.state.x[4] = 0x55;
        assert!(v0.emulate_sysreg());
        assert_eq!(v0.state.x[4], 0);
        v1.vgic_fill();
        assert_eq!(v1.vgic.as_ref().unwrap().lr[0], 0);
    }

    #[test]
    fn mmio() {
        let mut v = Aarch64Vcpu::new(GuestPhysAddr(0x4000_0000), 0, 0);
        // strb w1, [x0] to 0x0900_0000.
        v.state.x[1] = 0x1234_5641;
        let esr = ec::DABT_LOWER << 26 | IL | ISV | 1 << 16 | 1 << 6 | TRANS;
        let e = exit(&mut v, vector::SYNC, esr, 0x0900_0000, 0x0900_0000 >> 8);
        assert_eq!(e, VmExit::MmioWrite { addr: GuestPhysAddr(0x0900_0000), size: 1, data: 0x41 });
        assert_eq!(v.state.pc, 0x4000_0004);

        // ldrsh x3, [x0, #0x18]: 2 bytes, sign-extended into a 64-bit register.
        let esr = ec::DABT_LOWER << 26 | IL | ISV | 1 << 22 | 1 << 21 | 3 << 16 | 1 << 15 | TRANS;
        let e = exit(&mut v, vector::SYNC, esr, 0x0900_0018, 0x0900_0000 >> 8);
        assert_eq!(e, VmExit::MmioRead { addr: GuestPhysAddr(0x0900_0018), size: 2 });
        v.complete_read(0x8001);
        assert_eq!((v.state.x[3], v.state.pc), (0xffff_ffff_ffff_8001, 0x4000_0008));

        // ldr w4, [...]: 32-bit destination.
        let esr = ec::DABT_LOWER << 26 | IL | ISV | 2 << 22 | 4 << 16 | TRANS;
        exit(&mut v, vector::SYNC, esr, 0x100, 0x0900_0000 >> 8);
        v.complete_read(0xffff_ffff_dead_beef);
        assert_eq!(v.state.x[4], 0xdead_beef);

        // A permission fault (DFSC 0b0011xx) on a mapped page, an access-flag
        // fault, and a fault in the guest's own stage-1 walk are not MMIO.
        let ok = ec::DABT_LOWER << 26 | IL | ISV | 1 << 16 | 1 << 6;
        for bad in [ok | 0b001111, ok | 0b001011, ok | TRANS | S1PTW] {
            assert_eq!(
                exit(&mut v, vector::SYNC, bad, 0x0900_0000, 0x0900_0000 >> 8),
                VmExit::Unhandled { reason: bad }
            );
        }

        // No syndrome (e.g. a load pair): not emulated.
        let esr = ec::DABT_LOWER << 26 | IL;
        assert_eq!(exit(&mut v, vector::SYNC, esr, 0, 0), VmExit::Unhandled { reason: esr });
    }

    #[test]
    fn hvc_wfi_irq() {
        let mut v = Aarch64Vcpu::new(GuestPhysAddr(0x4000_0000), 0, 0);
        v.state.x[0] = psci::SYSTEM_OFF;
        v.state.pc = 0x4000_0104; // ELR after HVC
        let e = exit(&mut v, vector::SYNC, ec::HVC64 << 26 | IL, 0, 0);
        assert_eq!(e, VmExit::Hypercall { nr: psci::SYSTEM_OFF, args: [0; 6] });
        assert_eq!(v.state.pc, 0x4000_0104, "HVC already points past itself");
        v.complete_hypercall(7);
        assert_eq!(v.state.x[0], 7);

        assert_eq!(exit(&mut v, vector::SYNC, ec::WFX << 26 | IL, 0, 0), VmExit::Halt);
        assert_eq!(v.state.pc, 0x4000_0108);
        assert_eq!(exit(&mut v, vector::IRQ, 0, 0, 0), VmExit::ExternalInterrupt);
        assert_eq!(exit(&mut v, vector::SERROR, 0xbf00_0000, 0, 0), VmExit::Unhandled { reason: 0xbf00_0000 });
    }

    #[test]
    fn timer_and_irq_line() {
        let mut v = Aarch64Vcpu::new(GuestPhysAddr(0), 0, 0);
        let seen = Arc::new(AtomicBool::new(false));
        let s = seen.clone();
        v.connect_timer(move |l| s.store(l, Ordering::SeqCst));
        v.el1.cntv_cval = 1000;
        v.el1.cntv_ctl = 1;
        v.sync_timer(999);
        assert!(!seen.load(Ordering::SeqCst) && !v.interrupt_pending(999));
        v.sync_timer(1000);
        assert!(seen.load(Ordering::SeqCst) && v.interrupt_pending(1000));
        v.el1.cntv_ctl = 3; // masked
        assert!(!v.timer_level(2000));
        v.irq_line().store(true, Ordering::SeqCst);
        assert!(v.interrupt_pending(0));
    }
}
