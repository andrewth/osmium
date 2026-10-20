//! A RISC-V hypervisor-extension (H) vCPU.
//!
//! [`RiscvVcpu`] runs a guest in VS-mode under an HS-mode host kernel. Its
//! [`Vcpu::run`] enters the guest with `sret` and comes back through the
//! trap entry's guest-exit hook (`osmium-arch` feature `riscv64-hs`), then
//! turns the trap into a [`VmExit`]:
//!
//! | Trap | Exit |
//! |---|---|
//! | Load/store guest-page fault | [`VmExit::MmioRead`] / [`VmExit::MmioWrite`], decoded from `htinst` or the faulting instruction |
//! | `ecall` from VS-mode | [`VmExit::Hypercall`]: `nr` = EID (`a7`) in the low 32 bits, FID (`a6`) in the high 32; `args` = `a0`..`a5` |
//! | Virtual-instruction trap on `wfi` (`hstatus.VTW`) | [`VmExit::Halt`] |
//! | Host interrupt | [`VmExit::ExternalInterrupt`] |
//! | Anything else | [`VmExit::Unhandled`] with `scause` |
//!
//! [`sbi`] answers the common SBI calls on top of this. The guest's timer
//! uses `vstimecmp`, so the CPU needs the Sstc extension. The guest's
//! floating-point state is not switched, so `sstatus.FS` stays off while it
//! runs and guest FP instructions trap to the guest.

pub mod fdt;
pub mod harts;
pub mod insn;
pub mod sbi;

#[cfg(all(target_arch = "riscv64", feature = "riscv64-hs"))]
mod hw;
#[cfg(all(target_arch = "riscv64", feature = "riscv64-hs"))]
pub use hw::{init_cpu, time};

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::memory::GuestPhysAddr;
use crate::vcpu::{Vcpu, VmExit};
use insn::MemOp;

/// `hstatus` bits.
pub mod hstatus {
    /// The trap came from a guest (V=1); `sret` enters one.
    pub const SPV: u64 = 1 << 7;
    /// Guest privilege for `sret` and hypervisor loads: 1 = VS-mode.
    pub const SPVP: u64 = 1 << 8;
    /// `wfi` in VS-mode raises a virtual-instruction trap.
    pub const VTW: u64 = 1 << 21;
}

const SSTATUS_SPP: u64 = 1 << 8;
const WFI: u64 = 0x1050_0073;
const INTERRUPT: u64 = 1 << 63;

/// Guest registers and exit information, shared with the world-switch
/// assembly. The layout is fixed; see the offset constants in `hw`.
#[repr(C)]
#[derive(Clone, Debug)]
pub struct GuestState {
    /// General-purpose registers; `x[0]` is ignored.
    pub x: [u64; 32],
    /// Guest program counter (`sepc` on entry and exit).
    pub pc: u64,
    /// Guest `sstatus` at exit; only `SPP` (the guest's privilege) is used on entry.
    pub sstatus: u64,
    /// `hstatus` for entry, and its value at the last exit.
    pub hstatus: u64,
    /// `scause` at the last exit.
    pub scause: u64,
    /// `stval` at the last exit.
    pub stval: u64,
    /// `htval` at the last exit (guest-physical address >> 2).
    pub htval: u64,
    /// `htinst` at the last exit.
    pub htinst: u64,
    /// Host ra, sp, gp, tp, s0-s11 and sstatus, saved across the guest run.
    pub(crate) host: [u64; 17],
}

/// The guest's VS-mode CSRs, swapped in on every entry and out on every
/// exit, so several vCPUs can share a hart.
#[derive(Clone, Debug)]
pub struct VsCsrs {
    /// `vsstatus`.
    pub vsstatus: u64,
    /// `vsie`.
    pub vsie: u64,
    /// `vstvec`.
    pub vstvec: u64,
    /// `vsscratch`.
    pub vsscratch: u64,
    /// `vsepc`.
    pub vsepc: u64,
    /// `vscause`.
    pub vscause: u64,
    /// `vstval`.
    pub vstval: u64,
    /// `vsatp`.
    pub vsatp: u64,
    /// `hvip`: virtual interrupts the host injects (VSSIP, VSTIP, VSEIP).
    pub hvip: u64,
    /// `vstimecmp` (Sstc).
    pub vstimecmp: u64,
}

impl Default for VsCsrs {
    fn default() -> Self {
        Self {
            vsstatus: 0,
            vsie: 0,
            vstvec: 0,
            vsscratch: 0,
            vsepc: 0,
            vscause: 0,
            vstval: 0,
            vsatp: 0,
            hvip: 0,
            vstimecmp: u64::MAX,
        }
    }
}

/// A virtual hart.
pub struct RiscvVcpu {
    /// Registers and exit state.
    pub state: GuestState,
    /// VS-mode CSRs.
    pub csrs: VsCsrs,
    hgatp: u64,
    pending: Option<MemOp>,
    external: Arc<AtomicBool>,
    ipi: Option<Arc<AtomicBool>>,
}

/// SBI virtual-interrupt bits in `hvip`.
pub mod hvip {
    /// Supervisor software interrupt (IPI).
    pub const VSSIP: u64 = 1 << 2;
    /// Supervisor timer interrupt.
    pub const VSTIP: u64 = 1 << 6;
    /// Supervisor external interrupt.
    pub const VSEIP: u64 = 1 << 10;
}

impl RiscvVcpu {
    /// A vCPU that starts in VS-mode at `entry` with `a0` = `hartid` and
    /// `a1` = `arg` (the device tree, by the Linux boot convention), using
    /// the G-stage table encoded in `hgatp` (see
    /// [`hgatp_sv39x4`](crate::stage2::hgatp_sv39x4)).
    pub fn new(entry: GuestPhysAddr, hartid: u64, arg: u64, hgatp: u64) -> Self {
        let mut x = [0; 32];
        x[10] = hartid;
        x[11] = arg;
        let state = GuestState {
            x,
            pc: entry.0,
            sstatus: SSTATUS_SPP,
            hstatus: hstatus::SPV | hstatus::SPVP | hstatus::VTW,
            scause: 0,
            stval: 0,
            htval: 0,
            htinst: 0,
            host: [0; 17],
        };
        Self { state, csrs: VsCsrs::default(), hgatp, pending: None, external: Arc::new(AtomicBool::new(false)), ipi: None }
    }

    /// The vCPU's supervisor external-interrupt line, for an interrupt
    /// controller (a [`VirtualPlic`](crate::devices::VirtualPlic) context
    /// output) to drive. Its level becomes `hvip.VSEIP` at the next entry.
    pub fn external_irq(&self) -> Arc<AtomicBool> {
        self.external.clone()
    }

    /// Connects the vCPU's software-interrupt line (from
    /// [`GuestHarts::ipi_line`](harts::GuestHarts::ipi_line)): a raised
    /// line becomes `hvip.VSSIP` at the next entry, and the guest clears it
    /// by clearing `sip.SSIP`.
    pub fn connect_ipi(&mut self, line: Arc<AtomicBool>) {
        self.ipi = Some(line);
    }

    /// Copies the interrupt lines into `hvip` before entering the guest.
    #[cfg_attr(not(all(target_arch = "riscv64", feature = "riscv64-hs")), allow(dead_code))]
    fn sync_lines(&mut self) {
        if self.external.load(Ordering::Acquire) {
            self.csrs.hvip |= hvip::VSEIP;
        } else {
            self.csrs.hvip &= !hvip::VSEIP;
        }
        if self.ipi.as_ref().is_some_and(|l| l.swap(false, Ordering::AcqRel)) {
            self.csrs.hvip |= hvip::VSSIP;
        }
    }

    /// Whether an interrupt the guest has enabled is pending at time `now`
    /// (the `time` CSR), i.e. whether a vCPU halted in `wfi` should run again.
    pub fn interrupt_pending(&self, now: u64) -> bool {
        // vsie uses the S-level bit positions: SSIE 1, STIE 5, SEIE 9.
        let vsie = self.csrs.vsie;
        (vsie & (1 << 9) != 0 && self.external.load(Ordering::Acquire))
            || (vsie & (1 << 5) != 0 && now >= self.csrs.vstimecmp)
            || (vsie & (1 << 1) != 0
                && (self.csrs.hvip & hvip::VSSIP != 0 || self.ipi.as_ref().is_some_and(|l| l.load(Ordering::Acquire))))
    }

    /// The `hgatp` value this vCPU runs with.
    pub fn hgatp(&self) -> u64 {
        self.hgatp
    }

    /// Completes an SBI call with the two-register SBI return convention.
    pub fn complete_sbi(&mut self, error: i64, value: u64) {
        self.state.x[10] = error as u64;
        self.state.x[11] = value;
    }

    /// Turns the trap recorded in `state` into an exit. `fetch` reads the
    /// guest instruction at a guest-virtual PC when `htinst` does not
    /// describe it.
    pub fn classify(&mut self, fetch: impl FnOnce(u64) -> Option<u32>) -> VmExit {
        let s = &mut self.state;
        let cause = s.scause;
        if cause & INTERRUPT != 0 {
            return VmExit::ExternalInterrupt;
        }
        match cause {
            // Environment call from VS-mode.
            10 => {
                s.pc += 4;
                VmExit::Hypercall {
                    nr: (s.x[17] & 0xffff_ffff) | s.x[16] << 32,
                    args: [s.x[10], s.x[11], s.x[12], s.x[13], s.x[14], s.x[15]],
                }
            }
            // Load or store guest-page fault: emulate as MMIO.
            21 | 23 => {
                let addr = GuestPhysAddr(s.htval << 2 | (s.stval & 3));
                let op = insn::decode_transformed(s.htinst).or_else(|| fetch(s.pc).and_then(insn::decode));
                match op {
                    Some(op) if op.store && cause == 23 => {
                        let data = if op.reg == 0 { 0 } else { s.x[op.reg as usize] };
                        let data = if op.size == 8 { data } else { data & ((1 << (8 * op.size)) - 1) };
                        s.pc += op.len as u64;
                        VmExit::MmioWrite { addr, size: op.size, data }
                    }
                    Some(op) if !op.store && cause == 21 => {
                        self.pending = Some(op);
                        VmExit::MmioRead { addr, size: op.size }
                    }
                    _ => VmExit::Unhandled { reason: cause },
                }
            }
            // Virtual instruction: `wfi` with hstatus.VTW set.
            22 => {
                let insn = if s.stval != 0 { Some(s.stval as u32) } else { fetch(s.pc) };
                if insn == Some(WFI as u32) {
                    s.pc += 4;
                    VmExit::Halt
                } else {
                    VmExit::Unhandled { reason: cause }
                }
            }
            _ => VmExit::Unhandled { reason: cause },
        }
    }
}

impl Vcpu for RiscvVcpu {
    #[cfg(all(target_arch = "riscv64", feature = "riscv64-hs"))]
    fn run(&mut self) -> VmExit {
        self.sync_lines();
        hw::run(self);
        self.classify(|pc| hw::fetch(pc))
    }

    #[cfg(not(all(target_arch = "riscv64", feature = "riscv64-hs")))]
    fn run(&mut self) -> VmExit {
        unimplemented!("RISC-V guests need a riscv64 build with the riscv64-hs feature")
    }

    fn complete_read(&mut self, value: u64) {
        if let Some(op) = self.pending.take() {
            if op.reg != 0 {
                self.state.x[op.reg as usize] = op.extend(value);
            }
            self.state.pc += op.len as u64;
        }
    }

    fn complete_hypercall(&mut self, ret: u64) {
        self.complete_sbi(0, ret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(v: &mut RiscvVcpu, scause: u64, stval: u64, htval: u64, htinst: u64) -> VmExit {
        v.state.scause = scause;
        v.state.stval = stval;
        v.state.htval = htval;
        v.state.htinst = htinst;
        v.classify(|_| None)
    }

    #[test]
    fn mmio_load_and_store() {
        let mut v = RiscvVcpu::new(GuestPhysAddr(0x8000_0000), 0, 0, 0);
        // lbu t0, 5(a0) at 0x1000_0005, described by htinst.
        let e = exit(&mut v, 21, 0x1000_0005, 0x1000_0005 >> 2, 0x0000_4283);
        assert_eq!(e, VmExit::MmioRead { addr: GuestPhysAddr(0x1000_0005), size: 1 });
        assert_eq!(v.state.pc, 0x8000_0000, "advanced on completion");
        v.complete_read(0x1_ff);
        assert_eq!((v.state.x[5], v.state.pc), (0xff, 0x8000_0004));

        // c.sw a5, 0(a0), fetched because htinst is zero.
        v.state.x[15] = 0xdead_beef_1234_5678;
        v.state.scause = 23;
        v.state.htval = 0x1000_0000 >> 2;
        v.state.stval = 0;
        v.state.htinst = 0;
        let e = v.classify(|pc| (pc == 0x8000_0004).then_some(0xc11c));
        assert_eq!(e, VmExit::MmioWrite { addr: GuestPhysAddr(0x1000_0000), size: 4, data: 0x1234_5678 });
        assert_eq!(v.state.pc, 0x8000_0006);

        // A fault on an instruction we cannot decode.
        assert_eq!(exit(&mut v, 21, 0, 0, 0), VmExit::Unhandled { reason: 21 });
    }

    #[test]
    fn ecall_wfi_interrupt() {
        let mut v = RiscvVcpu::new(GuestPhysAddr(0x8000_0000), 0, 0, 0);
        v.state.x[17] = 0x4442_434e; // DBCN
        v.state.x[16] = 2;
        v.state.x[10] = b'x' as u64;
        let e = exit(&mut v, 10, 0, 0, 0);
        assert_eq!(e, VmExit::Hypercall { nr: 0x2_4442_434e, args: [b'x' as u64, 0, 0, 0, 0, 0] });
        assert_eq!(v.state.pc, 0x8000_0004);
        v.complete_sbi(-2, 7);
        assert_eq!((v.state.x[10], v.state.x[11]), (-2i64 as u64, 7));

        assert_eq!(exit(&mut v, 22, WFI, 0, 0), VmExit::Halt);
        assert_eq!(v.state.pc, 0x8000_0008);
        assert_eq!(exit(&mut v, 22, 0x1234_5073, 0, 0), VmExit::Unhandled { reason: 22 });
        assert_eq!(exit(&mut v, INTERRUPT | 5, 0, 0, 0), VmExit::ExternalInterrupt);
    }

    #[test]
    fn interrupt_lines() {
        let mut v = RiscvVcpu::new(GuestPhysAddr(0x8000_0000), 0, 0, 0);
        let line = v.external_irq();
        line.store(true, Ordering::SeqCst);
        v.sync_lines();
        assert_eq!(v.csrs.hvip, hvip::VSEIP);
        assert!(!v.interrupt_pending(0), "SEIE clear");
        v.csrs.vsie = 1 << 9;
        assert!(v.interrupt_pending(0));
        line.store(false, Ordering::SeqCst);
        v.sync_lines();
        assert_eq!(v.csrs.hvip, 0);
        assert!(!v.interrupt_pending(0));
        v.csrs.vsie |= 1 << 5;
        v.csrs.vstimecmp = 100;
        assert!(!v.interrupt_pending(99));
        assert!(v.interrupt_pending(100));
    }
}
