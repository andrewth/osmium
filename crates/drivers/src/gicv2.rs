//! Arm Generic Interrupt Controller, version 2.

use core::sync::atomic::{AtomicU32, Ordering};

use osmium_arch::MAX_CPUS;
use osmium_hal::irq::InterruptController;
use osmium_hal::mmio::IoMem;
use osmium_sync::PerCpu;

const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_SGIR: usize = 0xf00;

const GICC_CTLR: usize = 0x00;
const GICC_PMR: usize = 0x04;
const GICC_IAR: usize = 0x0c;
const GICC_EOIR: usize = 0x10;

const FIRST_SPI: u32 = 32;
/// Interrupt ids 1020–1023 are special (spurious and reserved), so no
/// distributor implements more than 1020 lines.
const MAX_IRQS: u32 = 1020;

/// A GICv2: one distributor shared by all CPUs plus a banked CPU interface.
///
/// CPU interface numbers (used for routing and SGI targets) are assumed to
/// equal `osmium_arch::cpu::current_id`, as on QEMU and most single-cluster
/// systems.
pub struct GicV2 {
    gicd: IoMem,
    gicc: IoMem,
    /// Source-CPU bits of the SGI each CPU last claimed; GICv2 requires them
    /// in the matching end-of-interrupt write.
    sgi_source: PerCpu<AtomicU32>,
}

impl GicV2 {
    /// Wraps the distributor and CPU-interface windows.
    pub fn new(gicd: IoMem, gicc: IoMem) -> Self {
        Self { gicd, gicc, sgi_source: PerCpu::new([const { AtomicU32::new(0) }; MAX_CPUS]) }
    }

    /// Sends software-generated interrupt `sgi` (0–15) to every CPU whose
    /// bit is set in `targets`.
    ///
    /// An `sgi` of 16 or more is ignored.
    pub fn send_sgi(&self, targets: u8, sgi: u32) {
        if sgi >= 16 {
            return;
        }
        let _ = self.gicd.write(GICD_SGIR, (targets as u32) << 16 | sgi);
    }

    /// Enables the distributor. Call once, on the boot CPU.
    pub fn init_distributor(&self) {
        let _ = self.gicd.write(GICD_CTLR, 1u32);
    }

    /// Enables this CPU's interface and unmasks all priorities. Call on each CPU.
    pub fn init_cpu(&self) {
        let _ = self.gicc.write(GICC_PMR, 0xffu32);
        let _ = self.gicc.write(GICC_CTLR, 1u32);
    }

    /// Number of interrupt lines the distributor implements (at most 1020).
    pub fn num_irqs(&self) -> u32 {
        let typer: u32 = self.gicd.read(GICD_TYPER).unwrap_or(0);
        (((typer & 0x1f) + 1) * 32).min(MAX_IRQS)
    }

    /// Returns true if `irq` names a line the distributor implements. The
    /// per-interrupt operations ignore any other number, which would
    /// otherwise land in a neighbouring register bank.
    fn valid(&self, irq: u32) -> bool {
        irq < self.num_irqs()
    }

    fn set_byte(&self, base: usize, irq: u32, value: u8) {
        let _ = self.gicd.write(base + irq as usize, value);
    }
}

impl InterruptController for GicV2 {
    /// Enables `irq`; shared peripheral interrupts are also routed to the
    /// current CPU. Does nothing if the distributor lacks `irq`.
    fn enable(&self, irq: u32) {
        if !self.valid(irq) {
            return;
        }
        if irq >= FIRST_SPI {
            let cpu = osmium_arch::cpu::current_id() % 8;
            self.set_byte(GICD_ITARGETSR, irq, 1 << cpu);
        }
        let _ = self.gicd.write(GICD_ISENABLER + (irq as usize / 32) * 4, 1u32 << (irq % 32));
    }

    /// Does nothing if the distributor lacks `irq`.
    fn disable(&self, irq: u32) {
        if !self.valid(irq) {
            return;
        }
        let _ = self.gicd.write(GICD_ICENABLER + (irq as usize / 32) * 4, 1u32 << (irq % 32));
    }

    /// Returns the interrupt id. For SGIs the source CPU is remembered for
    /// [`InterruptController::complete`].
    fn claim(&self) -> Option<u32> {
        let iar: u32 = self.gicc.read(GICC_IAR).ok()?;
        let id = iar & 0x3ff;
        if id < 16 {
            self.sgi_source.get().store(iar & 0x1c00, Ordering::Relaxed);
        }
        // 1020–1023 are not interrupts: 1023 is spurious, and the others
        // are only returned to secure software or reserved.
        (id < MAX_IRQS).then_some(id)
    }

    /// Ignores ids [`InterruptController::claim`] never returns.
    fn complete(&self, irq: u32) {
        if irq >= MAX_IRQS {
            return;
        }
        let source = if irq < 16 { self.sgi_source.get().load(Ordering::Relaxed) } else { 0 };
        let _ = self.gicc.write(GICC_EOIR, irq | source);
    }

    /// Higher `priority` is more urgent (the GIC encodes the inverse). Does
    /// nothing if the distributor lacks `irq`.
    fn set_priority(&self, irq: u32, priority: u8) {
        if !self.valid(irq) {
            return;
        }
        self.set_byte(GICD_IPRIORITYR, irq, 0xff - priority);
    }
}

#[cfg(test)]
// Tests drop drivers explicitly to end their use of the fake register memory
// before inspecting it.
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;

    #[test]
    fn enable_route_claim() {
        let mut d = [0u32; 0x1000 / 4];
        let mut c = [0u32; 0x100 / 4];
        d[GICD_TYPER / 4] = 2; // 96 lines
        c[GICC_IAR / 4] = 33;
        // SAFETY: the windows cover local arrays.
        let gic =
            unsafe { GicV2::new(IoMem::new(d.as_mut_ptr().cast(), 0x1000), IoMem::new(c.as_mut_ptr().cast(), 0x100)) };
        gic.init_distributor();
        gic.init_cpu();
        assert_eq!(gic.num_irqs(), 96);
        gic.enable(33);
        gic.set_priority(33, 0xff);
        assert_eq!(gic.claim(), Some(33));
        gic.complete(33);
        drop(gic);
        assert_eq!(d[GICD_ISENABLER / 4 + 1], 1 << 1);
        assert_eq!(d[GICD_ITARGETSR / 4 + 8] >> 8 & 0xff, 1, "routed to CPU 0");
        assert_eq!(d[GICD_IPRIORITYR / 4 + 8] >> 8 & 0xff, 0);
        assert_eq!(c[GICC_EOIR / 4], 33);
        assert_eq!(c[GICC_PMR / 4], 0xff);
    }

    #[test]
    fn sgi_send_and_source_in_eoi() {
        let mut d = [0u32; 0x1000 / 4];
        let mut c = [0u32; 0x100 / 4];
        // SGI 1 from CPU 2.
        c[GICC_IAR / 4] = 2 << 10 | 1;
        // SAFETY: the windows cover local arrays.
        let gic =
            unsafe { GicV2::new(IoMem::new(d.as_mut_ptr().cast(), 0x1000), IoMem::new(c.as_mut_ptr().cast(), 0x100)) };
        gic.send_sgi(0b1010, 1);
        assert_eq!(gic.claim(), Some(1));
        gic.complete(1);
        drop(gic);
        assert_eq!(d[GICD_SGIR / 4], 0b1010 << 16 | 1);
        assert_eq!(c[GICC_EOIR / 4], 2 << 10 | 1, "EOI carries the source CPU");
    }

    #[test]
    fn out_of_range_irqs_are_ignored() {
        let mut d = [0u32; 0x1000 / 4];
        let mut c = [0u32; 0x100 / 4];
        d[GICD_TYPER / 4] = 2; // 96 lines
        c[GICC_IAR / 4] = 1022;
        // SAFETY: the windows cover local arrays.
        let gic =
            unsafe { GicV2::new(IoMem::new(d.as_mut_ptr().cast(), 0x1000), IoMem::new(c.as_mut_ptr().cast(), 0x100)) };
        // Line 1024 + 32 would be an ICENABLER write; 96 is past the end.
        gic.enable(1024 + 32);
        gic.enable(96);
        gic.disable(u32::MAX);
        gic.set_priority(96, 1);
        assert_eq!(gic.claim(), None, "1022 is not an interrupt");
        gic.complete(1023);
        drop(gic);
        assert!(d.iter().enumerate().all(|(i, &v)| i == GICD_TYPER / 4 || v == 0));
        assert_eq!(c[GICC_EOIR / 4], 0);
    }
}
