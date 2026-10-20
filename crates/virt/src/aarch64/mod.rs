//! An AArch64 EL2 vCPU (non-VHE: the host kernel runs at EL2 with
//! `HCR_EL2.E2H` = 0, the guest at EL1/EL0 under stage-2 translation).
//!
//! Exits are decoded from `ESR_EL2` into a [`VmExit`]:
//!
//! | Exception | Exit |
//! |---|---|
//! | Data abort from EL1/EL0 with a valid syndrome (ISV) | [`VmExit::MmioRead`] / [`VmExit::MmioWrite`], address from `HPFAR_EL2` and `FAR_EL2` |
//! | `HVC` (or a trapped `SMC`) | [`VmExit::Hypercall`]: `nr` = `x0` (the SMCCC function ID), `args` = `x1`..`x6` |
//! | Trapped `WFI` (`HCR_EL2.TWI`) | [`VmExit::Halt`] |
//! | IRQ or FIQ taken while the guest ran | [`VmExit::ExternalInterrupt`] |
//! | Anything else | [`VmExit::Unhandled`] with the raw `ESR_EL2` |
//!
//! [`psci`] answers the PSCI calls a single-vCPU guest makes.

pub mod fdt;
pub mod psci;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(all(target_arch = "aarch64", feature = "aarch64-el2"))]
mod hw;
#[cfg(all(target_arch = "aarch64", feature = "aarch64-el2"))]
pub use hw::{HCR_GUEST, VTCR_48, counter, init_cpu};

use crate::memory::GuestPhysAddr;
use crate::vcpu::{Vcpu, VmExit};

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
    pub(crate) running: Option<Arc<core::sync::atomic::AtomicUsize>>,
    /// See [`new_vcpu_id`](crate::vcpu::new_vcpu_id).
    #[cfg_attr(not(all(target_arch = "aarch64", feature = "aarch64-el2")), allow(dead_code))]
    pub(crate) id: u64,
}

impl Aarch64Vcpu {
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
            running: None,
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
        if s.esr & 1 != 0 && rt != 31 {
            s.x[rt] = 0;
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
            ec::DABT_LOWER if esr & (1 << 24) != 0 => {
                // ISV: SAS[23:22], SSE[21], SRT[20:16], SF[15], WnR[6].
                let size = 1u8 << ((esr >> 22) & 3);
                let reg = ((esr >> 16) & 31) as u8;
                let addr = GuestPhysAddr((s.hpfar & 0x0fff_ffff_fff0) << 8 | (s.far & 0xfff));
                if esr & (1 << 6) != 0 {
                    let data = if reg == 31 { 0 } else { s.x[reg as usize] };
                    let data = if size == 8 { data } else { data & ((1 << (8 * size)) - 1) };
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
            hw::run(self);
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
        unimplemented!("AArch64 guests need an aarch64 build with the aarch64-el2 feature")
    }

    fn complete_read(&mut self, value: u64) {
        let Some(l) = self.pending.take() else { return };
        let bits = 8 * l.size as u32;
        let mut v = if bits == 64 { value } else { value & ((1 << bits) - 1) };
        if l.sign && bits < 64 && v >> (bits - 1) & 1 != 0 {
            v |= !((1 << bits) - 1);
        }
        if !l.wide {
            v &= 0xffff_ffff;
        }
        if l.reg != 31 {
            self.state.x[l.reg as usize] = v;
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
    fn mmio() {
        let mut v = Aarch64Vcpu::new(GuestPhysAddr(0x4000_0000), 0, 0);
        // strb w1, [x0] to 0x0900_0000.
        v.state.x[1] = 0x1234_5641;
        let esr = ec::DABT_LOWER << 26 | IL | ISV | 1 << 16 | 1 << 6;
        let e = exit(&mut v, vector::SYNC, esr, 0x0900_0000, 0x0900_0000 >> 8);
        assert_eq!(e, VmExit::MmioWrite { addr: GuestPhysAddr(0x0900_0000), size: 1, data: 0x41 });
        assert_eq!(v.state.pc, 0x4000_0004);

        // ldrsh x3, [x0, #0x18]: 2 bytes, sign-extended into a 64-bit register.
        let esr = ec::DABT_LOWER << 26 | IL | ISV | 1 << 22 | 1 << 21 | 3 << 16 | 1 << 15;
        let e = exit(&mut v, vector::SYNC, esr, 0x0900_0018, 0x0900_0000 >> 8);
        assert_eq!(e, VmExit::MmioRead { addr: GuestPhysAddr(0x0900_0018), size: 2 });
        v.complete_read(0x8001);
        assert_eq!((v.state.x[3], v.state.pc), (0xffff_ffff_ffff_8001, 0x4000_0008));

        // ldr w4, [...]: 32-bit destination.
        let esr = ec::DABT_LOWER << 26 | IL | ISV | 2 << 22 | 4 << 16;
        exit(&mut v, vector::SYNC, esr, 0x100, 0x0900_0000 >> 8);
        v.complete_read(0xffff_ffff_dead_beef);
        assert_eq!(v.state.x[4], 0xdead_beef);

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
