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
//! floating-point registers ([`FpState`], D extension) are loaded before
//! every run and saved after it if the guest has FP enabled
//! (`vsstatus.FS`); the host kernel itself is expected not to use FP.

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

use crate::memory::{GuestMemory, GuestPhysAddr};
use crate::stage2::Hgatp;
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

/// The guest's floating-point registers (D extension).
#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct FpState {
    /// `f0`..`f31`.
    pub f: [u64; 32],
    /// `fcsr`.
    pub fcsr: u64,
}

/// A virtual hart.
pub struct RiscvVcpu {
    /// Registers and exit state.
    pub state: GuestState,
    /// VS-mode CSRs.
    pub csrs: VsCsrs,
    /// Floating-point registers.
    pub fp: FpState,
    hgatp: Hgatp,
    pending: Option<MemOp>,
    external: Arc<AtomicBool>,
    ipi: Option<Arc<AtomicBool>>,
    pub(crate) running: Option<Arc<core::sync::atomic::AtomicUsize>>,
    /// Guest memory, for fetching faulting instructions in software.
    mem: Option<Arc<GuestMemory>>,
    /// See [`new_vcpu_id`](crate::vcpu::new_vcpu_id).
    #[cfg_attr(not(all(target_arch = "riscv64", feature = "riscv64-hs")), allow(dead_code))]
    pub(crate) id: u64,
    pub(crate) fence: Option<Arc<AtomicBool>>,
    /// The G-stage tables changed: `hfence.gvma` before the next entry.
    #[cfg_attr(not(all(target_arch = "riscv64", feature = "riscv64-hs")), allow(dead_code))]
    pub(crate) flush: bool,
    /// The hart this vCPU last ran on ([`NO_CPU`](crate::vcpu::NO_CPU) before the first run).
    #[cfg_attr(not(all(target_arch = "riscv64", feature = "riscv64-hs")), allow(dead_code))]
    pub(crate) last_cpu: usize,
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

/// A hart ID, as the guest sees it in `a0` at boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HartId(pub u64);

impl RiscvVcpu {
    /// Arranges for the hart's cached G-stage translations (`hfence.gvma`)
    /// to be flushed before this vCPU next enters the guest. Call it after
    /// the hypervisor edits the guest's G-stage tables (unmapping or
    /// changing permissions of a page): the hart caches translations across
    /// entries and only flushes when the vCPU or its `hgatp` changes. The
    /// flush is local to the hart that runs the vCPU, so call it on every
    /// vCPU of the guest.
    pub fn flush_stage2(&mut self) {
        self.flush = true;
    }

    /// A vCPU that starts in VS-mode at `entry` with `a0` = `hartid` and
    /// `a1` = `arg` (the device tree, by the Linux boot convention), using
    /// the G-stage table encoded in `hgatp` (see
    /// [`hgatp_sv39x4`](crate::stage2::hgatp_sv39x4)).
    pub fn new(entry: GuestPhysAddr, hartid: HartId, arg: u64, hgatp: Hgatp) -> Self {
        let mut x = [0; 32];
        x[10] = hartid.0;
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
        Self {
            state,
            csrs: VsCsrs::default(),
            fp: FpState::default(),
            hgatp,
            pending: None,
            external: Arc::new(AtomicBool::new(false)),
            ipi: None,
            running: None,
            fence: None,
            flush: false,
            last_cpu: crate::vcpu::NO_CPU,
            id: crate::vcpu::new_vcpu_id(),
            mem: None,
        }
    }

    /// The vCPU's supervisor external-interrupt line, for an interrupt
    /// controller (a [`VirtualPlic`](crate::devices::VirtualPlic) context
    /// output) to drive. Its level becomes `hvip.VSEIP` at the next entry.
    pub fn external_irq(&self) -> Arc<AtomicBool> {
        self.external.clone()
    }

    /// Gives the vCPU its guest memory: an instruction the hardware does not
    /// report (`htinst` = 0) is then fetched by walking the guest's VS-stage
    /// tables in software, instead of with `hlvx` in HS-mode, which traps
    /// into the host if another vCPU changes the mapping meanwhile.
    pub fn with_memory(mut self, mem: Arc<GuestMemory>) -> Self {
        self.mem = Some(mem);
        self
    }

    /// Uses `line` as the external-interrupt line instead, for an
    /// interrupt controller built before the vCPU.
    pub fn with_external_irq(mut self, line: Arc<AtomicBool>) -> Self {
        self.external = line;
        self
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
    pub fn hgatp(&self) -> Hgatp {
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
                s.pc = s.pc.wrapping_add(4);
                VmExit::Hypercall {
                    nr: (s.x[17] & 0xffff_ffff) | s.x[16] << 32,
                    args: [s.x[10], s.x[11], s.x[12], s.x[13], s.x[14], s.x[15]],
                }
            }
            // Load or store guest-page fault: emulate as MMIO.
            21 | 23 => {
                let addr = GuestPhysAddr(s.htval << 2 | (s.stval & 3));
                // A fault in the walk of the guest's own VS-stage tables
                // reports a pseudo-instruction (non-zero, bit 0 clear): the
                // instruction at `sepc` did not make this access.
                if s.htinst != 0 && s.htinst & 1 == 0 {
                    return VmExit::Unhandled { reason: cause };
                }
                // A fault on memory the guest owns (a permission fault on a
                // mapped page) is not MMIO either.
                if self.mem.as_ref().is_some_and(|m| m.host_ptr(addr, 1).is_some()) {
                    return VmExit::Unhandled { reason: cause };
                }
                let op = insn::decode_transformed(s.htinst).or_else(|| fetch(s.pc).and_then(insn::decode));
                match op {
                    Some(op) if op.store && cause == 23 => {
                        let data = if op.reg == 0 { 0 } else { s.x[op.reg as usize] };
                        let data = if op.size == 8 { data } else { data & ((1 << (8 * op.size)) - 1) };
                        s.pc = s.pc.wrapping_add(op.len as u64);
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
                    s.pc = s.pc.wrapping_add(4);
                    VmExit::Halt
                } else {
                    VmExit::Unhandled { reason: cause }
                }
            }
            _ => VmExit::Unhandled { reason: cause },
        }
    }
}

/// Translates guest-virtual `va` through the VS-stage tables `vsatp` names
/// (Bare, Sv39, Sv48 or Sv57), reading them from `mem`: the guest-physical
/// address, if a valid leaf maps it.
pub fn translate_vs(mem: &GuestMemory, vsatp: u64, va: u64) -> Option<u64> {
    let levels = match vsatp >> 60 {
        0 => return Some(va),
        8 => 3,
        9 => 4,
        10 => 5,
        _ => return None,
    };
    let mut table = (vsatp & ((1 << 44) - 1)) << 12;
    for level in (0..levels).rev() {
        let index = (va >> (12 + 9 * level)) & 0x1ff;
        let pte: u64 = mem.read_obj(GuestPhysAddr(table.checked_add(index * 8)?)).ok()?;
        if pte & 1 == 0 {
            return None;
        }
        let ppn = (pte >> 10) & ((1 << 44) - 1);
        if pte & 0b1010 != 0 {
            // A leaf (R or X): the low VPNs of a superpage come from `va`.
            let span = 12 + 9 * level;
            return Some((ppn << 12) & !((1 << span) - 1) | va & ((1 << span) - 1));
        }
        table = ppn << 12;
    }
    None
}

/// Fetches the (possibly compressed) instruction at guest-virtual `pc` in
/// software, as `hlvx.hu` would.
#[cfg_attr(not(all(target_arch = "riscv64", feature = "riscv64-hs")), allow(dead_code))]
fn fetch_soft(mem: &GuestMemory, vsatp: u64, pc: u64) -> Option<u32> {
    let half = |va: u64| mem.read_obj::<u16>(GuestPhysAddr(translate_vs(mem, vsatp, va)?)).ok();
    let lo = half(pc)? as u32;
    if lo & 3 != 3 {
        return Some(lo);
    }
    Some(lo | (half(pc.wrapping_add(2))? as u32) << 16)
}

impl Vcpu for RiscvVcpu {
    #[cfg(all(target_arch = "riscv64", feature = "riscv64-hs"))]
    fn run(&mut self) -> VmExit {
        if let Some(r) = &self.running {
            r.store(osmium_arch::cpu::current_id(), Ordering::Release);
        }
        self.sync_lines();
        if self.fence.as_ref().is_some_and(|f| f.swap(false, Ordering::AcqRel)) {
            hw::fence_guest(self.hgatp.0);
        }
        hw::run(self);
        if let Some(r) = &self.running {
            r.store(crate::smp::NOT_RUNNING, Ordering::Release);
        }
        match self.mem.clone() {
            Some(mem) => {
                let vsatp = self.csrs.vsatp;
                self.classify(|pc| fetch_soft(&mem, vsatp, pc))
            }
            None => self.classify(hw::fetch),
        }
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
            self.state.pc = self.state.pc.wrapping_add(op.len as u64);
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
    fn walks_vs_stage_tables() {
        let mut ram = alloc::vec![0u8; 0x10000];
        let mut mem = GuestMemory::new();
        // SAFETY: `ram` outlives `mem`.
        unsafe { mem.add_region(GuestPhysAddr(0), ram.as_mut_ptr(), 0x10000) };
        let pte = |a: u64, ppn: u64, flags: u64| mem.write_obj(GuestPhysAddr(a), ppn << 10 | flags).unwrap();
        // Sv39, root 0x1000: VPN2 2 -> table 0x2000; VPN1 0 -> table 0x3000;
        // VPN0 1 -> page 0x5000 (R X). VPN1 1 -> a 2 MiB leaf at 0x20_0000.
        pte(0x1000 + 2 * 8, 2, 1);
        pte(0x2000, 3, 1);
        pte(0x3000 + 8, 5, 0b1011);
        pte(0x2000 + 8, 0x200, 0b1011);
        let vsatp = 8 << 60 | 1;
        assert_eq!(translate_vs(&mem, vsatp, 0x8000_1234), Some(0x5234));
        assert_eq!(translate_vs(&mem, vsatp, 0x8020_1234), Some(0x20_1234), "superpage");
        assert_eq!(translate_vs(&mem, vsatp, 0x8000_2000), None, "unmapped");
        assert_eq!(translate_vs(&mem, 0, 0x1234), Some(0x1234), "Bare");
        // A compressed and a full instruction.
        mem.write(GuestPhysAddr(0x5000), &[0x82, 0x80, 0x13, 0x05, 0x10, 0x00]).unwrap();
        assert_eq!(fetch_soft(&mem, vsatp, 0x8000_1000), Some(0x8082), "c.ret");
        assert_eq!(fetch_soft(&mem, vsatp, 0x8000_1002), Some(0x0010_0513), "li a0, 1");
    }

    #[test]
    fn mmio_load_and_store() {
        let mut v = RiscvVcpu::new(GuestPhysAddr(0x8000_0000), HartId(0), 0, Hgatp(0));
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

        // A fault in the guest's own page-table walk: the pseudo-instruction
        // for an implicit read (0x2000) or write (0x2020).
        assert_eq!(exit(&mut v, 21, 0, 0x1000_0000 >> 2, 0x2000), VmExit::Unhandled { reason: 21 });
        assert_eq!(exit(&mut v, 23, 0, 0x1000_0000 >> 2, 0x2020), VmExit::Unhandled { reason: 23 });

        // A fault on a page the guest has mapped is not MMIO.
        let mut ram = alloc::vec![0u8; 0x1000];
        let mut mem = GuestMemory::new();
        // SAFETY: `ram` outlives `mem`.
        unsafe { mem.add_region(GuestPhysAddr(0x9000_0000), ram.as_mut_ptr(), 0x1000) };
        let mut w = RiscvVcpu::new(GuestPhysAddr(0x8000_0000), HartId(0), 0, Hgatp(0)).with_memory(Arc::new(mem));
        assert_eq!(exit(&mut w, 23, 0x9000_0010, 0x9000_0010 >> 2, 0x0000_4283), VmExit::Unhandled { reason: 23 });
        assert!(matches!(exit(&mut w, 21, 0x1000_0005, 0x1000_0005 >> 2, 0x0000_4283), VmExit::MmioRead { .. }));
        drop(w);
        drop(ram);

        // A fault on an instruction we cannot decode.
        assert_eq!(exit(&mut v, 21, 0, 0, 0), VmExit::Unhandled { reason: 21 });
    }

    #[test]
    fn ecall_wfi_interrupt() {
        let mut v = RiscvVcpu::new(GuestPhysAddr(0x8000_0000), HartId(0), 0, Hgatp(0));
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
        let mut v = RiscvVcpu::new(GuestPhysAddr(0x8000_0000), HartId(0), 0, Hgatp(0));
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
