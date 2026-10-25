//! Arm Generic Interrupt Controller, version 3, with affinity routing.
//!
//! A GICv3 has a memory-mapped distributor (shared peripheral interrupts,
//! SPIs), one memory-mapped redistributor per CPU (private peripheral
//! interrupts and software-generated interrupts, PPIs and SGIs) and a CPU
//! interface reached through the `ICC_*` system registers. The system
//! registers sit behind the [`CpuInterface`] trait so the driver can be
//! tested on the host against a simulation; `SysRegs` is the real thing on
//! bare-metal AArch64.
//!
//! Not implemented: the interrupt translation service (ITS) and LPIs, group 0
//! and secure-state configuration, and GICv4 virtual interrupts. The driver
//! assumes it runs in the non-secure state at EL1 (or higher).

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use osmium_arch::MAX_CPUS;
use osmium_hal::irq::InterruptController;
use osmium_hal::mmio::IoMem;
use osmium_sync::PerCpu;

const GICD_CTLR: usize = 0x0000;
const GICD_TYPER: usize = 0x0004;
const GICD_IGROUPR: usize = 0x0080;
const GICD_ISENABLER: usize = 0x0100;
const GICD_ICENABLER: usize = 0x0180;
const GICD_ISPENDR: usize = 0x0200;
const GICD_ICPENDR: usize = 0x0280;
const GICD_IPRIORITYR: usize = 0x0400;
const GICD_ICFGR: usize = 0x0c00;
const GICD_IROUTER: usize = 0x6000;

/// `GICD_CTLR.EnableGrp1NS`.
const GICD_CTLR_ENABLE_GRP1_NS: u32 = 1 << 1;
/// `GICD_CTLR.ARE_NS`: non-secure affinity routing.
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
/// `GICD_CTLR.DS`: single security state, so group registers are accessible.
const GICD_CTLR_DS: u32 = 1 << 6;
/// `GICD_CTLR.RWP`: a register write is still propagating.
const GICD_CTLR_RWP: u32 = 1 << 31;

const GICR_TYPER: usize = 0x08;
const GICR_WAKER: usize = 0x14;
/// Offset of the SGI/PPI frame within a redistributor.
const GICR_SGI_FRAME: usize = 0x1_0000;
/// Size of a redistributor with the RD and SGI frames only.
const GICR_STRIDE: usize = 0x2_0000;
/// Size of a redistributor that also has the VLPI frames.
const GICR_STRIDE_V4: usize = 0x4_0000;

const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;
const GICR_TYPER_VLPIS: u64 = 1 << 1;
const GICR_TYPER_LAST: u64 = 1 << 4;

/// `ICC_CTLR_EL1.EOImode`.
const ICC_CTLR_EOIMODE: u64 = 1 << 1;

const FIRST_SPI: u32 = 32;
/// Interrupt ids 1020–1023 are special, so no distributor implements more
/// than 1020 lines (LPIs start at 8192 and are not handled here).
const MAX_IRQS: u32 = 1020;

/// Polls of a status bit before giving up on hardware that never answers.
const SPIN_LIMIT: u32 = 1_000_000;

const NO_REDIST: usize = usize::MAX;

/// How an interrupt is ended (`ICC_CTLR_EL1.EOImode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EoiMode {
    /// Writing `ICC_EOIR1_EL1` drops the running priority and deactivates.
    Combined,
    /// `ICC_EOIR1_EL1` only drops the priority; `ICC_DIR_EL1` deactivates
    /// later, so a handler can hand the active interrupt to a thread.
    Split,
}

/// The `ICC_*` system registers of the CPU the caller runs on.
pub trait CpuInterface: Sync {
    /// This CPU's `MPIDR_EL1`.
    fn mpidr(&self) -> u64;
    /// Enables the system-register interface (`ICC_SRE_EL1.SRE`); returns
    /// whether it reads back as set.
    fn enable_sre(&self) -> bool;
    /// Reads `ICC_CTLR_EL1`.
    fn ctlr(&self) -> u64;
    /// Writes `ICC_CTLR_EL1`.
    fn set_ctlr(&self, value: u64);
    /// Writes `ICC_PMR_EL1`, the priority mask.
    fn set_pmr(&self, value: u8);
    /// Writes `ICC_BPR1_EL1`, the group 1 binary point.
    fn set_bpr1(&self, value: u8);
    /// Writes `ICC_IGRPEN1_EL1`, enabling or disabling group 1 interrupts.
    fn set_group1_enabled(&self, enabled: bool);
    /// Reads `ICC_IAR1_EL1`, acknowledging an interrupt.
    fn iar1(&self) -> u32;
    /// Writes `ICC_EOIR1_EL1`.
    fn eoir1(&self, intid: u32);
    /// Writes `ICC_DIR_EL1`.
    fn dir(&self, intid: u32);
    /// Writes `ICC_SGI1R_EL1`, generating SGIs.
    fn sgi1r(&self, value: u64);
}

/// The real CPU interface, through system registers.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct SysRegs;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
mod sysregs {
    use super::{CpuInterface, SysRegs};
    use core::arch::asm;

    macro_rules! read {
        ($enc:literal) => {{
            let v: u64;
            // SAFETY: reading a GIC CPU-interface register of this CPU; IAR is
            // the only one with a side effect and that is its purpose.
            unsafe { asm!(concat!("mrs {}, ", $enc), out(reg) v, options(nomem, nostack, preserves_flags)) };
            v
        }};
    }
    macro_rules! write {
        ($enc:literal, $v:expr) => {{
            let v: u64 = $v;
            // SAFETY: writing a GIC CPU-interface register of this CPU, which
            // only changes interrupt delivery, as the caller asked.
            unsafe { asm!(concat!("msr ", $enc, ", {}"), "isb", in(reg) v, options(nostack, preserves_flags)) };
        }};
    }

    impl SysRegs {
        /// The system-register CPU interface.
        pub const fn new() -> Self {
            SysRegs
        }
    }

    impl CpuInterface for SysRegs {
        fn mpidr(&self) -> u64 {
            osmium_arch::aarch64::read_mpidr_el1()
        }
        fn enable_sre(&self) -> bool {
            let sre = read!("s3_0_c12_c12_5"); // ICC_SRE_EL1
            write!("s3_0_c12_c12_5", sre | 1);
            read!("s3_0_c12_c12_5") & 1 != 0
        }
        fn ctlr(&self) -> u64 {
            read!("s3_0_c12_c12_4") // ICC_CTLR_EL1
        }
        fn set_ctlr(&self, value: u64) {
            write!("s3_0_c12_c12_4", value);
        }
        fn set_pmr(&self, value: u8) {
            write!("s3_0_c4_c6_0", value as u64); // ICC_PMR_EL1
        }
        fn set_bpr1(&self, value: u8) {
            write!("s3_0_c12_c12_3", value as u64); // ICC_BPR1_EL1
        }
        fn set_group1_enabled(&self, enabled: bool) {
            write!("s3_0_c12_c12_7", enabled as u64); // ICC_IGRPEN1_EL1
        }
        fn iar1(&self) -> u32 {
            read!("s3_0_c12_c12_0") as u32 // ICC_IAR1_EL1
        }
        fn eoir1(&self, intid: u32) {
            write!("s3_0_c12_c12_1", intid as u64); // ICC_EOIR1_EL1
        }
        fn dir(&self, intid: u32) {
            write!("s3_0_c12_c11_1", intid as u64); // ICC_DIR_EL1
        }
        fn sgi1r(&self, value: u64) {
            write!("s3_0_c12_c11_5", value); // ICC_SGI1R_EL1
        }
    }
}

/// The affinity fields (Aff3.Aff2.Aff1.Aff0) of an `MPIDR_EL1` value, packed
/// the way `GICR_TYPER[63:32]` and `GICD_IROUTER` order them.
pub const fn affinity(mpidr: u64) -> u64 {
    mpidr & 0xff_00ff_ffff
}

/// Builds the `ICC_SGI1R_EL1` value that sends SGI `sgi` to the CPU whose
/// affinity is `mpidr`. Returns `None` if `sgi` is above 15 or Aff0 is above
/// 15, which a target list cannot name.
pub const fn sgi1r_value(mpidr: u64, sgi: u32) -> Option<u64> {
    let aff0 = mpidr & 0xff;
    if sgi >= 16 || aff0 >= 16 {
        return None;
    }
    let aff1 = (mpidr >> 8) & 0xff;
    let aff2 = (mpidr >> 16) & 0xff;
    let aff3 = (mpidr >> 32) & 0xff;
    Some(aff3 << 48 | aff2 << 32 | (sgi as u64) << 24 | aff1 << 16 | 1 << aff0)
}

/// A GICv3 with affinity routing: distributor, redistributors and a CPU
/// interface.
///
/// Logical CPU numbers (as in [`osmium_arch::cpu::current_id`]) are mapped to
/// affinities by [`GicV3::register_cpu`]; [`GicV3::init_cpu`] does that for
/// the calling CPU.
pub struct GicV3<C: CpuInterface> {
    gicd: IoMem,
    /// The whole redistributor region, all CPUs' frames back to back.
    gicr: IoMem,
    cpu_if: C,
    /// Byte offset of each CPU's redistributor, or `NO_REDIST`.
    redist: PerCpu<AtomicUsize>,
    /// Each CPU's affinity, valid once its `redist` is set.
    affinity: PerCpu<AtomicU64>,
    eoi_split: AtomicBool,
}

impl<C: CpuInterface> GicV3<C> {
    /// Wraps the distributor window, the redistributor region (all frames)
    /// and the CPU interface.
    pub fn new(gicd: IoMem, gicr: IoMem, cpu_if: C) -> Self {
        Self {
            gicd,
            gicr,
            cpu_if,
            redist: PerCpu::new([const { AtomicUsize::new(NO_REDIST) }; MAX_CPUS]),
            affinity: PerCpu::new([const { AtomicU64::new(0) }; MAX_CPUS]),
            eoi_split: AtomicBool::new(false),
        }
    }

    /// The CPU interface.
    pub fn cpu_interface(&self) -> &C {
        &self.cpu_if
    }

    /// Enables affinity routing and group 1 interrupts in the distributor.
    /// Call once, on the boot CPU, before [`GicV3::init_cpu`].
    pub fn init_distributor(&self) {
        let _ = self.gicd.write(GICD_CTLR, GICD_CTLR_ARE_NS);
        self.wait_rwp();
        let _ = self.gicd.write(GICD_CTLR, GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS);
        self.wait_rwp();
    }

    fn wait_rwp(&self) {
        for _ in 0..SPIN_LIMIT {
            if self.gicd.read::<u32>(GICD_CTLR).is_ok_and(|v| v & GICD_CTLR_RWP != 0) {
                core::hint::spin_loop();
            } else {
                return;
            }
        }
    }

    /// Number of interrupt lines the distributor implements (at most 1020).
    pub fn num_irqs(&self) -> u32 {
        let typer: u32 = self.gicd.read(GICD_TYPER).unwrap_or(0);
        (((typer & 0x1f) + 1) * 32).min(MAX_IRQS)
    }

    /// Finds the redistributor frame whose affinity is `aff`.
    fn find_redist(&self, aff: u64) -> Option<usize> {
        let mut off = 0usize;
        loop {
            let typer: u64 = self.gicr.read(off.checked_add(GICR_TYPER)?).ok()?;
            if typer >> 32 == aff {
                return Some(off);
            }
            if typer & GICR_TYPER_LAST != 0 {
                return None;
            }
            off = off.checked_add(if typer & GICR_TYPER_VLPIS != 0 { GICR_STRIDE_V4 } else { GICR_STRIDE })?;
        }
    }

    /// Records that logical CPU `cpu` has `mpidr` and finds its
    /// redistributor. Returns false if there is none.
    ///
    /// The boot CPU can call this for the others (from the device tree) so
    /// [`GicV3::send_sgi`] can reach them before they are up.
    pub fn register_cpu(&self, cpu: usize, mpidr: u64) -> bool {
        let aff = affinity(mpidr);
        let Some(off) = self.find_redist(aff) else { return false };
        self.affinity.for_cpu(cpu).store(aff, Ordering::Relaxed);
        self.redist.for_cpu(cpu).store(off, Ordering::Release);
        true
    }

    /// Wakes this CPU's redistributor, enables the system-register interface
    /// and group 1 interrupts, and unmasks all priorities. Call on each CPU,
    /// after [`GicV3::init_distributor`] on the boot CPU. Returns false if the
    /// CPU has no redistributor, it does not wake, or the system-register
    /// interface cannot be enabled.
    pub fn init_cpu(&self) -> bool {
        if !self.cpu_if.enable_sre() || !self.register_cpu(osmium_arch::cpu::current_id(), self.cpu_if.mpidr()) {
            return false;
        }
        let Some(rd) = self.my_redist() else { return false };
        // Wake the redistributor: clear ProcessorSleep, wait for ChildrenAsleep to clear.
        let waker: u32 = self.gicr.read(rd + GICR_WAKER).unwrap_or(0);
        let _ = self.gicr.write(rd + GICR_WAKER, waker & !GICR_WAKER_PROCESSOR_SLEEP);
        let awake = (0..SPIN_LIMIT).any(|_| {
            let asleep = self.gicr.read::<u32>(rd + GICR_WAKER).is_ok_and(|v| v & GICR_WAKER_CHILDREN_ASLEEP != 0);
            if asleep {
                core::hint::spin_loop();
            }
            !asleep
        });
        if !awake {
            return false;
        }
        // Private interrupts start as group 1 (when the group register is
        // reachable) and disabled; the caller enables the ones it uses.
        let sgi = rd + GICR_SGI_FRAME;
        if self.gicd.read::<u32>(GICD_CTLR).is_ok_and(|v| v & GICD_CTLR_DS != 0) {
            let _ = self.gicr.write(sgi + GICD_IGROUPR, u32::MAX);
        }
        let _ = self.gicr.write(sgi + GICD_ICENABLER, u32::MAX);
        self.cpu_if.set_pmr(0xff);
        self.cpu_if.set_bpr1(0);
        self.apply_eoi_mode();
        self.cpu_if.set_group1_enabled(true);
        true
    }

    fn apply_eoi_mode(&self) {
        let ctlr = self.cpu_if.ctlr() & !ICC_CTLR_EOIMODE;
        let split = if self.eoi_split.load(Ordering::Relaxed) { ICC_CTLR_EOIMODE } else { 0 };
        self.cpu_if.set_ctlr(ctlr | split);
    }

    /// Chooses combined or split priority drop and deactivation. It applies
    /// to the calling CPU now and to any CPU at its [`GicV3::init_cpu`].
    pub fn set_eoi_mode(&self, mode: EoiMode) {
        self.eoi_split.store(mode == EoiMode::Split, Ordering::Relaxed);
        self.apply_eoi_mode();
    }

    /// The current end-of-interrupt mode.
    pub fn eoi_mode(&self) -> EoiMode {
        if self.eoi_split.load(Ordering::Relaxed) { EoiMode::Split } else { EoiMode::Combined }
    }

    /// Deactivates `irq` (`ICC_DIR_EL1`); needed after
    /// [`InterruptController::complete`] in [`EoiMode::Split`].
    pub fn deactivate(&self, irq: u32) {
        if irq < MAX_IRQS {
            self.cpu_if.dir(irq);
        }
    }

    fn my_redist(&self) -> Option<usize> {
        let off = self.redist.get().load(Ordering::Acquire);
        (off != NO_REDIST).then_some(off)
    }

    /// Returns true if `irq` names a line the controller implements.
    fn valid(&self, irq: u32) -> bool {
        irq < FIRST_SPI || irq < self.num_irqs()
    }

    /// The window and offset of the register word holding `irq`'s bit in a
    /// one-bit-per-interrupt bank at `bank`: the redistributor's SGI frame
    /// for private lines, else the distributor. `None` for an unimplemented
    /// line or a CPU with no redistributor.
    fn bit_reg(&self, bank: usize, irq: u32) -> Option<(&IoMem, usize)> {
        if !self.valid(irq) {
            return None;
        }
        let word = (irq as usize / 32) * 4;
        if irq < FIRST_SPI {
            Some((&self.gicr, self.my_redist()?.checked_add(GICR_SGI_FRAME)?.checked_add(bank)?.checked_add(word)?))
        } else {
            Some((&self.gicd, bank.checked_add(word)?))
        }
    }

    fn set_bit(&self, bank: usize, irq: u32) {
        if let Some((m, off)) = self.bit_reg(bank, irq) {
            let _ = m.write(off, 1u32 << (irq % 32));
        }
    }

    /// Sets the trigger of `irq`: edge-triggered if `edge`, else level.
    /// SGIs are always edge, so 0–15 are ignored.
    pub fn set_trigger(&self, irq: u32, edge: bool) {
        if irq < 16 || !self.valid(irq) {
            return;
        }
        let word = (irq as usize / 16) * 4;
        let (m, off) = if irq < FIRST_SPI {
            let Some(rd) = self.my_redist() else { return };
            (&self.gicr, rd + GICR_SGI_FRAME + GICD_ICFGR + word)
        } else {
            (&self.gicd, GICD_ICFGR + word)
        };
        let bit = 1u32 << ((irq % 16) * 2 + 1);
        if let Ok(v) = m.read::<u32>(off) {
            let _ = m.write(off, if edge { v | bit } else { v & !bit });
        }
    }

    /// Routes SPI `irq` to the CPU with affinity `mpidr`. Ignores private
    /// interrupts and lines the distributor lacks.
    pub fn route(&self, irq: u32, mpidr: u64) {
        if irq >= FIRST_SPI && self.valid(irq) {
            let _ = self.gicd.write(GICD_IROUTER + irq as usize * 8, affinity(mpidr));
        }
    }

    /// Makes `irq` pending in software (for SGIs and PPIs, on this CPU).
    pub fn set_pending(&self, irq: u32) {
        self.set_bit(GICD_ISPENDR, irq);
    }

    /// Clears `irq`'s pending state.
    pub fn clear_pending(&self, irq: u32) {
        self.set_bit(GICD_ICPENDR, irq);
    }

    /// Whether `irq` is pending.
    pub fn is_pending(&self, irq: u32) -> bool {
        self.bit_reg(GICD_ISPENDR, irq)
            .and_then(|(m, off)| m.read::<u32>(off).ok())
            .is_some_and(|v| v & (1 << (irq % 32)) != 0)
    }

    /// Whether `irq` is enabled.
    pub fn is_enabled(&self, irq: u32) -> bool {
        self.bit_reg(GICD_ISENABLER, irq)
            .and_then(|(m, off)| m.read::<u32>(off).ok())
            .is_some_and(|v| v & (1 << (irq % 32)) != 0)
    }

    /// Sends SGI `sgi` (0–15) to every logical CPU whose bit is set in
    /// `targets`. CPUs not registered, and those with Aff0 above 15, are
    /// skipped; returns how many SGIs were generated.
    pub fn send_sgi(&self, targets: u32, sgi: u32) -> u32 {
        let mut sent = 0;
        for cpu in 0..MAX_CPUS.min(32) {
            if targets & (1 << cpu) == 0 || self.redist.for_cpu(cpu).load(Ordering::Acquire) == NO_REDIST {
                continue;
            }
            if let Some(v) = sgi1r_value(self.affinity.for_cpu(cpu).load(Ordering::Relaxed), sgi) {
                self.cpu_if.sgi1r(v);
                sent += 1;
            }
        }
        sent
    }
}

impl<C: CpuInterface> InterruptController for GicV3<C> {
    /// Enables `irq`; shared peripheral interrupts are also routed to the
    /// current CPU. Does nothing if the controller lacks `irq`.
    fn enable(&self, irq: u32) {
        if !self.valid(irq) {
            return;
        }
        if irq >= FIRST_SPI {
            self.route(irq, self.cpu_if.mpidr());
        }
        self.set_bit(GICD_ISENABLER, irq);
    }

    /// Does nothing if the controller lacks `irq`.
    fn disable(&self, irq: u32) {
        self.set_bit(GICD_ICENABLER, irq);
    }

    /// Acknowledges an interrupt. 1020–1023 (spurious, reserved) and LPI ids
    /// give `None`.
    fn claim(&self) -> Option<u32> {
        let id = self.cpu_if.iar1() & 0xff_ffff;
        (id < MAX_IRQS).then_some(id)
    }

    /// Drops the running priority (and deactivates, in [`EoiMode::Combined`]).
    /// Ignores ids [`InterruptController::claim`] never returns.
    fn complete(&self, irq: u32) {
        if irq < MAX_IRQS {
            self.cpu_if.eoir1(irq);
        }
    }

    /// Higher `priority` is more urgent (the GIC encodes the inverse). Does
    /// nothing if the controller lacks `irq`.
    fn set_priority(&self, irq: u32, priority: u8) {
        if !self.valid(irq) {
            return;
        }
        let value = 0xff - priority;
        if irq < FIRST_SPI {
            if let Some(rd) = self.my_redist() {
                let _ = self.gicr.write(rd + GICR_SGI_FRAME + GICD_IPRIORITYR + irq as usize, value);
            }
        } else {
            let _ = self.gicd.write(GICD_IPRIORITYR + irq as usize, value);
        }
    }
}

#[cfg(test)]
// Tests drop drivers explicitly to end their use of the fake register memory
// before inspecting it.
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;
    use std::sync::Mutex;
    use std::vec::Vec;

    /// A simulated CPU interface.
    struct FakeCpu {
        mpidr: u64,
        iar: AtomicU32,
        eoir: Mutex<Vec<u32>>,
        dirs: Mutex<Vec<u32>>,
        sgis: Mutex<Vec<u64>>,
        pmr: AtomicU32,
        grp1: AtomicU32,
        ctlr: AtomicU64,
    }

    impl FakeCpu {
        fn new(mpidr: u64) -> Self {
            Self {
                mpidr,
                iar: AtomicU32::new(1023),
                eoir: Mutex::new(Vec::new()),
                dirs: Mutex::new(Vec::new()),
                sgis: Mutex::new(Vec::new()),
                pmr: AtomicU32::new(0),
                grp1: AtomicU32::new(0),
                ctlr: AtomicU64::new(0),
            }
        }
    }

    impl CpuInterface for &FakeCpu {
        fn mpidr(&self) -> u64 {
            self.mpidr
        }
        fn enable_sre(&self) -> bool {
            true
        }
        fn ctlr(&self) -> u64 {
            self.ctlr.load(Ordering::Relaxed)
        }
        fn set_ctlr(&self, value: u64) {
            self.ctlr.store(value, Ordering::Relaxed)
        }
        fn set_pmr(&self, value: u8) {
            self.pmr.store(value as u32, Ordering::Relaxed)
        }
        fn set_bpr1(&self, _: u8) {}
        fn set_group1_enabled(&self, enabled: bool) {
            self.grp1.store(enabled as u32, Ordering::Relaxed)
        }
        fn iar1(&self) -> u32 {
            self.iar.load(Ordering::Relaxed)
        }
        fn eoir1(&self, intid: u32) {
            self.eoir.lock().unwrap().push(intid)
        }
        fn dir(&self, intid: u32) {
            self.dirs.lock().unwrap().push(intid)
        }
        fn sgi1r(&self, value: u64) {
            self.sgis.lock().unwrap().push(value)
        }
    }

    /// Two redistributors (affinities 0 and 1) and a 96-line distributor.
    struct Fake {
        d: Vec<u32>,
        r: Vec<u32>,
    }

    impl Fake {
        fn new() -> Self {
            let mut d = std::vec![0u32; 0x10000 / 4];
            d[GICD_TYPER / 4] = 2; // 96 lines
            let mut r = std::vec![0u32; 2 * GICR_STRIDE / 4];
            // GICR_TYPER high word is the affinity; the second is Last.
            r[(GICR_STRIDE + GICR_TYPER) / 4 + 1] = 1;
            r[(GICR_STRIDE + GICR_TYPER) / 4] = GICR_TYPER_LAST as u32;
            // Both start asleep; ChildrenAsleep reads clear, as if the wake were instant.
            r[GICR_WAKER / 4] = GICR_WAKER_PROCESSOR_SLEEP;
            r[(GICR_STRIDE + GICR_WAKER) / 4] = GICR_WAKER_PROCESSOR_SLEEP;
            Self { d, r }
        }

        fn gic<'a>(&mut self, cpu: &'a FakeCpu) -> GicV3<&'a FakeCpu> {
            // SAFETY: the windows cover the vectors, which outlive the driver in each test.
            unsafe {
                GicV3::new(
                    IoMem::new(self.d.as_mut_ptr().cast(), self.d.len() * 4),
                    IoMem::new(self.r.as_mut_ptr().cast(), self.r.len() * 4),
                    cpu,
                )
            }
        }
    }

    #[test]
    fn distributor_init_sets_affinity_routing() {
        let (mut f, cpu) = (Fake::new(), FakeCpu::new(0));
        let gic = f.gic(&cpu);
        gic.init_distributor();
        assert_eq!(gic.num_irqs(), 96);
        drop(gic);
        assert_eq!(f.d[GICD_CTLR / 4], GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1_NS);
    }

    #[test]
    fn spi_enable_route_priority_claim_complete() {
        // MPIDR bit 31 (RES1) must not reach the router; Aff0 = 1.
        let (mut f, cpu) = (Fake::new(), FakeCpu::new(0x8000_0001));
        cpu.iar.store(33, Ordering::Relaxed);
        let gic = f.gic(&cpu);
        gic.init_distributor();
        assert!(gic.init_cpu());
        gic.enable(33);
        gic.set_priority(33, 0xff);
        gic.set_trigger(33, true);
        assert_eq!(gic.claim(), Some(33));
        gic.complete(33);
        assert!(gic.is_enabled(33));
        drop(gic);
        assert_eq!(f.d[GICD_ISENABLER / 4 + 1], 1 << 1);
        assert_eq!(f.d[GICD_IROUTER / 4 + 33 * 2], 1);
        assert_eq!(f.d[GICD_IPRIORITYR / 4 + 8] >> 8 & 0xff, 0);
        assert_eq!(f.d[GICD_ICFGR / 4 + 2] >> 3 & 1, 1, "edge");
        assert_eq!(*cpu.eoir.lock().unwrap(), [33]);
        assert_eq!(cpu.pmr.load(Ordering::Relaxed), 0xff);
        assert_eq!(cpu.grp1.load(Ordering::Relaxed), 1);
        assert_eq!(f.r[(GICR_STRIDE + GICR_WAKER) / 4] & GICR_WAKER_PROCESSOR_SLEEP, 0, "CPU 1 woken");
        assert_ne!(f.r[GICR_WAKER / 4] & GICR_WAKER_PROCESSOR_SLEEP, 0, "CPU 0 left asleep");
    }

    #[test]
    fn private_interrupts_use_the_redistributor_of_the_cpu() {
        let (mut f, cpu) = (Fake::new(), FakeCpu::new(1));
        let gic = f.gic(&cpu);
        assert!(gic.init_cpu());
        gic.enable(27);
        gic.set_priority(27, 0x80);
        gic.set_pending(3);
        assert!(gic.is_pending(3));
        gic.clear_pending(3);
        gic.set_trigger(27, false);
        drop(gic);
        let sgi = (GICR_STRIDE + GICR_SGI_FRAME) / 4;
        assert_eq!(f.r[sgi + GICD_ISENABLER / 4], 1 << 27);
        assert_eq!(f.r[sgi + GICD_IPRIORITYR / 4 + 6] >> 24, 0x7f);
        assert_eq!(f.r[sgi + GICD_ICPENDR / 4], 1 << 3);
        assert_eq!(f.r[GICR_SGI_FRAME / 4 + GICD_ISENABLER / 4], 0, "CPU 0's redistributor untouched");
    }

    #[test]
    fn cpu_without_redistributor_fails_init() {
        let (mut f, cpu) = (Fake::new(), FakeCpu::new(5));
        let gic = f.gic(&cpu);
        assert!(!gic.init_cpu());
        gic.enable(27); // no redistributor: ignored
        gic.set_priority(27, 1);
        assert!(!gic.register_cpu(1, 0x102));
        drop(gic);
        assert!(f.r.iter().enumerate().all(|(i, &v)| v == 0 || i * 4 == GICR_WAKER || i * 4 >= GICR_STRIDE));
    }

    #[test]
    fn sgi_encoding_and_send() {
        assert_eq!(sgi1r_value(0x0000_0102, 3), Some(3 << 24 | 1 << 16 | 1 << 2));
        assert_eq!(sgi1r_value(0x1_0002_0301, 15), Some(1 << 48 | 2 << 32 | 15 << 24 | 3 << 16 | 1 << 1));
        assert_eq!(sgi1r_value(0, 16), None);
        assert_eq!(sgi1r_value(16, 0), None);
        let (mut f, cpu) = (Fake::new(), FakeCpu::new(0));
        let gic = f.gic(&cpu);
        assert!(gic.register_cpu(0, 0));
        assert!(gic.register_cpu(1, 1));
        assert_eq!(gic.send_sgi(0b110, 2), 1, "CPU 2 is not registered");
        assert_eq!(gic.send_sgi(0b11, 16), 0);
        drop(gic);
        assert_eq!(*cpu.sgis.lock().unwrap(), [2 << 24 | 1 << 1]);
    }

    #[test]
    fn split_eoi_mode() {
        let (mut f, cpu) = (Fake::new(), FakeCpu::new(0));
        let gic = f.gic(&cpu);
        assert_eq!(gic.eoi_mode(), EoiMode::Combined);
        gic.set_eoi_mode(EoiMode::Split);
        assert_eq!(gic.eoi_mode(), EoiMode::Split);
        assert_eq!(cpu.ctlr.load(Ordering::Relaxed) & 2, 2);
        gic.complete(30);
        gic.deactivate(30);
        gic.deactivate(1023);
        gic.set_eoi_mode(EoiMode::Combined);
        assert_eq!(cpu.ctlr.load(Ordering::Relaxed) & 2, 0);
        drop(gic);
        assert_eq!(*cpu.eoir.lock().unwrap(), [30]);
        assert_eq!(*cpu.dirs.lock().unwrap(), [30]);
    }

    #[test]
    fn spurious_and_out_of_range_are_ignored() {
        let (mut f, cpu) = (Fake::new(), FakeCpu::new(0));
        let gic = f.gic(&cpu);
        assert_eq!(gic.claim(), None);
        cpu.iar.store(8192, Ordering::Relaxed);
        assert_eq!(gic.claim(), None, "LPIs are not supported");
        gic.enable(96);
        gic.enable(1024 + 32);
        gic.disable(u32::MAX);
        gic.set_priority(96, 1);
        gic.route(96, 1);
        gic.complete(1023);
        drop(gic);
        assert!(cpu.eoir.lock().unwrap().is_empty());
        assert!(f.d.iter().enumerate().all(|(i, &v)| i == GICD_TYPER / 4 || v == 0));
    }

    #[test]
    fn redistributor_stride_follows_vlpis() {
        let (mut f, cpu) = (Fake::new(), FakeCpu::new(0));
        // The first redistributor has VLPI frames, so the second sits 256 KiB in.
        let second: Vec<u32> = f.r[GICR_STRIDE / 4..].to_vec();
        f.r[GICR_STRIDE / 4..].fill(0);
        f.r.resize(2 * GICR_STRIDE_V4 / 4, 0);
        f.r[GICR_STRIDE_V4 / 4..GICR_STRIDE_V4 / 4 + second.len()].copy_from_slice(&second);
        f.r[GICR_TYPER / 4] = GICR_TYPER_VLPIS as u32;
        let gic = f.gic(&cpu);
        assert!(gic.register_cpu(1, 1));
        assert_eq!(gic.redist.for_cpu(1).load(Ordering::Relaxed), GICR_STRIDE_V4);
    }
}
