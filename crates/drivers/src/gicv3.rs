//! Arm Generic Interrupt Controller, version 3 (affinity routing, system
//! register CPU interface, no ITS or LPIs).

use core::sync::atomic::{AtomicUsize, Ordering};

use osmium_arch::MAX_CPUS;
use osmium_hal::irq::InterruptController;
use osmium_hal::mmio::IoMem;
use osmium_sync::PerCpu;

const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_IGROUPR: usize = 0x080;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_IROUTER: usize = 0x6000;

/// Enable Group 0 and 1 and affinity routing: bit 4 is `ARE_NS` with two
/// security states and `ARE` with one, bits 1:0 the group enables.
const GICD_CTLR_ENABLE: u32 = 0x13;
/// Register write pending.
const GICD_CTLR_RWP: u32 = 1 << 31;

const GICR_TYPER: usize = 0x008;
const GICR_WAKER: usize = 0x014;
const GICR_STRIDE: usize = 0x2_0000;
const GICR_SGI: usize = 0x1_0000;
const GICR_IGROUPR0: usize = GICR_SGI + 0x080;
const GICR_ISENABLER0: usize = GICR_SGI + 0x100;
const GICR_ICENABLER0: usize = GICR_SGI + 0x180;
const GICR_IPRIORITYR0: usize = GICR_SGI + 0x400;
const WAKER_ASLEEP: u32 = 1 << 2;
const TYPER_LAST: u64 = 1 << 4;

const FIRST_SPI: u32 = 32;
/// Interrupt ids 1020–1023 are special (spurious and reserved).
const MAX_IRQS: u32 = 1020;

/// Spin limit for the register-write-pending and wake handshakes.
const SPIN: u32 = 1_000_000;

/// The CPU interface system registers (`ICC_*`). Off AArch64 they read as
/// zero and ignore writes, so the memory-mapped side can be tested on a host.
#[cfg(target_arch = "aarch64")]
mod icc {
    use core::arch::asm;

    macro_rules! reg {
        ($read:ident, $write:ident, $enc:literal) => {
            #[allow(dead_code)]
            pub fn $read() -> u64 {
                let v: u64;
                // SAFETY: reads a GIC CPU interface register, which has no side effects other
                // than the documented acknowledge for `iar1`; the driver is used on GICv3 CPUs.
                unsafe { asm!(concat!("mrs {}, ", $enc), out(reg) v, options(nomem, nostack, preserves_flags)) };
                v
            }

            #[allow(dead_code)]
            pub fn $write(v: u64) {
                // SAFETY: writes a GIC CPU interface register; the driver is used on GICv3 CPUs.
                unsafe { asm!(concat!("msr ", $enc, ", {}"), "isb", in(reg) v, options(nomem, nostack, preserves_flags)) };
            }
        };
    }

    reg!(sre_el1, set_sre_el1, "S3_0_C12_C12_5");
    reg!(sre_el2, set_sre_el2, "S3_4_C12_C9_5");
    reg!(pmr, set_pmr, "S3_0_C4_C6_0");
    reg!(ctlr, set_ctlr, "S3_0_C12_C12_4");
    reg!(bpr1, set_bpr1, "S3_0_C12_C12_3");
    reg!(igrpen1, set_igrpen1, "S3_0_C12_C12_7");
    reg!(iar1, set_iar1, "S3_0_C12_C12_0");
    reg!(eoir1, set_eoir1, "S3_0_C12_C12_1");
    reg!(sgi1r, set_sgi1r, "S3_0_C12_C11_5");

    pub fn mpidr() -> u64 {
        osmium_arch::aarch64::read_mpidr_el1()
    }

    pub fn dsb() {
        // SAFETY: a barrier.
        unsafe { asm!("dsb sy", options(nostack, preserves_flags)) };
    }
}

#[cfg(not(target_arch = "aarch64"))]
mod icc {
    macro_rules! reg {
        ($read:ident, $write:ident) => {
            #[allow(dead_code)]
            pub fn $read() -> u64 {
                0
            }
            #[allow(dead_code)]
            pub fn $write(_: u64) {}
        };
    }
    reg!(sre_el1, set_sre_el1);
    reg!(sre_el2, set_sre_el2);
    reg!(pmr, set_pmr);
    reg!(ctlr, set_ctlr);
    reg!(bpr1, set_bpr1);
    reg!(igrpen1, set_igrpen1);
    reg!(iar1, set_iar1);
    reg!(eoir1, set_eoir1);
    reg!(sgi1r, set_sgi1r);
    pub fn mpidr() -> u64 {
        0
    }
    pub fn dsb() {}
}

/// `MPIDR_EL1` as the affinity value `Aff3.Aff2.Aff1.Aff0` that
/// `GICR_TYPER[63:32]` uses.
fn affinity(mpidr: u64) -> u64 {
    (mpidr >> 32 & 0xff) << 24 | (mpidr & 0xff_ffff)
}

/// A GICv3: a distributor, one redistributor per CPU, and the system
/// register CPU interface of the calling CPU.
///
/// Logical CPU numbers (`osmium_arch::cpu::current_id`, SGI targets) are
/// assumed to map to affinities as on QEMU's `virt` machine: Aff0 =
/// `cpu % 16`, Aff1 = `cpu / 16`.
pub struct GicV3 {
    gicd: IoMem,
    gicr: IoMem,
    /// Offset in `gicr` of each CPU's redistributor, +1 (0 = not found yet).
    redist: PerCpu<AtomicUsize>,
}

impl GicV3 {
    /// Wraps the distributor window and the redistributor region (all
    /// redistributors, back to back).
    pub fn new(gicd: IoMem, gicr: IoMem) -> Self {
        Self { gicd, gicr, redist: PerCpu::new([const { AtomicUsize::new(0) }; MAX_CPUS]) }
    }

    /// Enables the distributor with affinity routing. Call once, on the boot CPU.
    pub fn init_distributor(&self) {
        let _ = self.gicd.write(GICD_CTLR, 0u32);
        self.wait_rwp();
        // Everything Group 1; SPIs masked.
        for w in 1..self.num_irqs() as usize / 32 {
            let _ = self.gicd.write(GICD_IGROUPR + w * 4, !0u32);
            let _ = self.gicd.write(GICD_ICENABLER + w * 4, !0u32);
        }
        self.wait_rwp();
        let _ = self.gicd.write(GICD_CTLR, GICD_CTLR_ENABLE);
        self.wait_rwp();
    }

    fn wait_rwp(&self) {
        for _ in 0..SPIN {
            if self.gicd.read::<u32>(GICD_CTLR).is_ok_and(|v| v & GICD_CTLR_RWP == 0) {
                return;
            }
            core::hint::spin_loop();
        }
    }

    /// Finds the calling CPU's redistributor (by `MPIDR_EL1`), wakes it,
    /// and enables this CPU's interface for Group 1 with all priorities
    /// unmasked. `el2` is true when the CPU runs at EL2 (a hypervisor),
    /// where `ICC_SRE_EL2` must also let EL1 use the system registers.
    /// Call on each CPU. Returns false if no redistributor matches.
    pub fn init_cpu(&self, el2: bool) -> bool {
        let Some(base) = self.find_redistributor(affinity(icc::mpidr())) else { return false };
        self.redist.get().store(base + 1, Ordering::Relaxed);
        // Wake it: clear ProcessorSleep, wait for ChildrenAsleep to clear.
        let _ = self.gicr.write(base + GICR_WAKER, 0u32);
        for _ in 0..SPIN {
            if self.gicr.read::<u32>(base + GICR_WAKER).is_ok_and(|v| v & WAKER_ASLEEP == 0) {
                break;
            }
            core::hint::spin_loop();
        }
        // SGIs and PPIs: Group 1, all disabled until a driver enables them.
        let _ = self.gicr.write(base + GICR_IGROUPR0, !0u32);
        let _ = self.gicr.write(base + GICR_ICENABLER0, !0u32);
        if el2 {
            // SRE | DFB | DIB | Enable: the guest at EL1 may use the system registers.
            icc::set_sre_el2(icc::sre_el2() | 0xf);
        } else {
            icc::set_sre_el1(icc::sre_el1() | 1);
        }
        icc::set_ctlr(0); // EOImode 0: EOIR drops priority and deactivates
        icc::set_pmr(0xff);
        icc::set_bpr1(0);
        icc::set_igrpen1(1);
        true
    }

    /// The offset in the redistributor region of the redistributor with
    /// affinity `aff`.
    fn find_redistributor(&self, aff: u64) -> Option<usize> {
        let mut base = 0;
        while base + GICR_STRIDE <= self.gicr.len() {
            let typer: u64 = self.gicr.read(base + GICR_TYPER).ok()?;
            if typer >> 32 == aff {
                return Some(base);
            }
            if typer & TYPER_LAST != 0 {
                return None;
            }
            base += GICR_STRIDE;
        }
        None
    }

    /// Number of interrupt lines the distributor implements (at most 1020).
    pub fn num_irqs(&self) -> u32 {
        let typer: u32 = self.gicd.read(GICD_TYPER).unwrap_or(0);
        (((typer & 0x1f) + 1) * 32).min(MAX_IRQS)
    }

    fn valid(&self, irq: u32) -> bool {
        irq < self.num_irqs()
    }

    /// This CPU's redistributor, if [`init_cpu`](Self::init_cpu) found it.
    fn this_redistributor(&self) -> Option<usize> {
        self.redist.get().load(Ordering::Relaxed).checked_sub(1)
    }

    /// Sends software-generated interrupt `sgi` (0–15) to every logical CPU
    /// whose bit is set in `targets` (CPUs 0–63).
    ///
    /// An `sgi` of 16 or more is ignored.
    pub fn send_sgi(&self, targets: u64, sgi: u32) {
        if sgi >= 16 {
            return;
        }
        icc::dsb();
        for cluster in 0..4u64 {
            let list = (targets >> (cluster * 16)) & 0xffff;
            if list != 0 {
                icc::set_sgi1r(list | cluster << 16 | u64::from(sgi) << 24);
            }
        }
    }
}

impl InterruptController for GicV3 {
    /// Enables `irq`; shared peripheral interrupts are also routed to the
    /// current CPU. Does nothing if the distributor lacks `irq`.
    fn enable(&self, irq: u32) {
        if !self.valid(irq) {
            return;
        }
        if irq < FIRST_SPI {
            if let Some(base) = self.this_redistributor() {
                let _ = self.gicr.write(base + GICR_ISENABLER0, 1u32 << irq);
            }
            return;
        }
        let cpu = osmium_arch::cpu::current_id() as u64;
        let aff = ((cpu / 16) << 8) | (cpu % 16);
        let _ = self.gicd.write(GICD_IROUTER + irq as usize * 8, aff);
        let _ = self.gicd.write(GICD_ISENABLER + (irq as usize / 32) * 4, 1u32 << (irq % 32));
    }

    /// Does nothing if the distributor lacks `irq`.
    fn disable(&self, irq: u32) {
        if !self.valid(irq) {
            return;
        }
        if irq < FIRST_SPI {
            if let Some(base) = self.this_redistributor() {
                let _ = self.gicr.write(base + GICR_ICENABLER0, 1u32 << irq);
            }
            return;
        }
        let _ = self.gicd.write(GICD_ICENABLER + (irq as usize / 32) * 4, 1u32 << (irq % 32));
    }

    fn claim(&self) -> Option<u32> {
        let id = (icc::iar1() & 0xff_ffff) as u32;
        // 1020–1023 are spurious or reserved; LPIs (8192 and up) are not enabled here.
        (id < MAX_IRQS).then_some(id)
    }

    /// Ignores ids [`InterruptController::claim`] never returns.
    fn complete(&self, irq: u32) {
        if irq < MAX_IRQS {
            icc::set_eoir1(u64::from(irq));
        }
    }

    /// Higher `priority` is more urgent (the GIC encodes the inverse). Does
    /// nothing if the distributor lacks `irq`.
    fn set_priority(&self, irq: u32, priority: u8) {
        if !self.valid(irq) {
            return;
        }
        if irq < FIRST_SPI {
            if let Some(base) = self.this_redistributor() {
                let _ = self.gicr.write(base + GICR_IPRIORITYR0 + irq as usize, 0xff - priority);
            }
        } else {
            let _ = self.gicd.write(GICD_IPRIORITYR + irq as usize, 0xff - priority);
        }
    }
}

#[cfg(test)]
// Tests drop drivers explicitly to end their use of the fake register memory
// before inspecting it.
#[allow(clippy::drop_non_drop, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const FRAMES: usize = 2;
    const D_WORDS: usize = 0x1_0000 / 4;
    const R_WORDS: usize = FRAMES * GICR_STRIDE / 4;

    /// Fake distributor (96 lines) and two redistributors in memory; the
    /// second is flagged Last. Host builds read MPIDR as 0, so affinity 0 is "this CPU".
    fn regs(affinities: [u32; 2]) -> (std::vec::Vec<u32>, std::vec::Vec<u32>) {
        let mut d = std::vec![0u32; D_WORDS];
        let mut r = std::vec![0u32; R_WORDS];
        d[GICD_TYPER / 4] = 2;
        r[(GICR_TYPER + 4) / 4] = affinities[0];
        r[GICR_STRIDE / 4 + (GICR_TYPER + 4) / 4] = affinities[1];
        r[GICR_STRIDE / 4 + GICR_TYPER / 4] = TYPER_LAST as u32;
        (d, r)
    }

    fn driver(d: &mut [u32], r: &mut [u32]) -> GicV3 {
        // SAFETY: the windows cover the arrays, which outlive the driver.
        unsafe {
            GicV3::new(IoMem::new(d.as_mut_ptr().cast(), D_WORDS * 4), IoMem::new(r.as_mut_ptr().cast(), R_WORDS * 4))
        }
    }

    #[test]
    fn init_enable_and_route() {
        let (mut d, mut r) = regs([0, 1]);
        let gic = driver(&mut d, &mut r);
        gic.init_distributor();
        assert!(gic.init_cpu(false), "finds redistributor 0 by affinity");
        assert_eq!(gic.num_irqs(), 96);
        gic.enable(27);
        gic.enable(33);
        gic.set_priority(27, 0xff);
        gic.set_priority(33, 0xf0);
        gic.enable(96); // past the end
        drop(gic);
        assert_eq!(d[GICD_CTLR / 4], GICD_CTLR_ENABLE);
        assert_eq!(d[GICD_IGROUPR / 4 + 1], !0, "SPIs in Group 1");
        assert_eq!(d[GICD_ISENABLER / 4 + 1], 1 << 1);
        assert_eq!(d[GICD_ISENABLER / 4 + 3], 0);
        assert_eq!(d[GICD_IROUTER / 4 + 66], 0, "routed to affinity 0.0");
        assert_eq!(d[GICD_IPRIORITYR / 4 + 8] >> 8 & 0xff, 0x0f);
        assert_eq!(r[GICR_ISENABLER0 / 4], 1 << 27, "PPI 27 enabled in this CPU's redistributor");
        assert_eq!(r[GICR_IPRIORITYR0 / 4 + 6] >> 24, 0, "priority 0xff is the least urgent: encoded 0x00");
        assert_eq!(r[GICR_WAKER / 4], 0);
        assert_eq!(r[GICR_IGROUPR0 / 4], !0);
        assert_eq!(r[GICR_STRIDE / 4 + GICR_ISENABLER0 / 4], 0, "the other CPU's is untouched");
    }

    #[test]
    fn missing_redistributor_and_bad_sgi() {
        // No redistributor with this CPU's affinity (0).
        let (mut d, mut r) = regs([5, 6]);
        let gic = driver(&mut d, &mut r);
        assert!(!gic.init_cpu(false));
        gic.enable(27); // no redistributor: ignored
        gic.send_sgi(1, 16);
        drop(gic);
        assert_eq!(r[GICR_ISENABLER0 / 4], 0);
    }
}
