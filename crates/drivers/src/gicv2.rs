//! Arm Generic Interrupt Controller, version 2.

use osmium_hal::irq::InterruptController;
use osmium_hal::mmio::IoMem;

const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;

const GICC_CTLR: usize = 0x00;
const GICC_PMR: usize = 0x04;
const GICC_IAR: usize = 0x0c;
const GICC_EOIR: usize = 0x10;

const SPURIOUS: u32 = 1023;
const FIRST_SPI: u32 = 32;

/// A GICv2: one distributor shared by all CPUs plus a banked CPU interface.
pub struct GicV2 {
    gicd: IoMem,
    gicc: IoMem,
}

impl GicV2 {
    /// Wraps the distributor and CPU-interface windows.
    pub fn new(gicd: IoMem, gicc: IoMem) -> Self {
        Self { gicd, gicc }
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

    /// Number of interrupt lines the distributor implements.
    pub fn num_irqs(&self) -> u32 {
        let typer: u32 = self.gicd.read(GICD_TYPER).unwrap_or(0);
        ((typer & 0x1f) + 1) * 32
    }

    fn set_byte(&self, base: usize, irq: u32, value: u8) {
        let _ = self.gicd.write(base + irq as usize, value);
    }
}

impl InterruptController for GicV2 {
    /// Enables `irq`; shared peripheral interrupts are also routed to the
    /// current CPU.
    fn enable(&self, irq: u32) {
        if irq >= FIRST_SPI {
            let cpu = osmium_arch::cpu::current_id() % 8;
            self.set_byte(GICD_ITARGETSR, irq, 1 << cpu);
        }
        let _ = self.gicd.write(GICD_ISENABLER + (irq as usize / 32) * 4, 1u32 << (irq % 32));
    }

    fn disable(&self, irq: u32) {
        let _ = self.gicd.write(GICD_ICENABLER + (irq as usize / 32) * 4, 1u32 << (irq % 32));
    }

    /// Returns the interrupt id. For SGIs the source-CPU field is dropped.
    fn claim(&self) -> Option<u32> {
        let iar: u32 = self.gicc.read(GICC_IAR).ok()?;
        let id = iar & 0x3ff;
        (id != SPURIOUS).then_some(id)
    }

    fn complete(&self, irq: u32) {
        let _ = self.gicc.write(GICC_EOIR, irq);
    }

    /// Higher `priority` is more urgent (the GIC encodes the inverse).
    fn set_priority(&self, irq: u32, priority: u8) {
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
        let gic = unsafe { GicV2::new(IoMem::new(d.as_mut_ptr().cast(), 0x1000), IoMem::new(c.as_mut_ptr().cast(), 0x100)) };
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
}
