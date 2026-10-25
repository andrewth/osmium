//! Device trees for AArch64 guests.

use alloc::format;
use alloc::vec::Vec;

use osmium_boot::fdt::FdtWriter;

/// An AArch64 guest's machine, described in the layout Linux and
/// `osmium-boot` expect from QEMU `virt`: CPUs started with PSCI over `hvc`,
/// a GICv2 or GICv3, the architected timer, PL011 UARTs and virtio-mmio devices.
/// Interrupts are given as SPI numbers (INTID - 32).
pub struct ArmMachine<'src> {
    /// Number of CPUs (MPIDR affinity 0 = 0, 1, ...).
    pub cpus: u32,
    /// RAM as (base, size).
    pub memory: &'src [(u64, u64)],
    /// The interrupt controller.
    pub gic: ArmGic,
    /// PL011 UARTs as (base, SPI); the first is the console.
    pub uarts: &'src [(u64, u32)],
    /// virtio-mmio devices as (base, SPI).
    pub virtio: &'src [(u64, u32)],
    /// Kernel command line.
    pub bootargs: &'src str,
}

/// The interrupt controller an [`ArmMachine`] describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmGic {
    /// A GICv2: distributor and CPU interface bases (64 KiB each).
    V2 {
        /// Distributor base.
        distributor: u64,
        /// CPU interface base.
        cpu_interface: u64,
    },
    /// A GICv3 (no ITS): distributor base (64 KiB) and the base and size of
    /// the redistributor region (128 KiB per CPU).
    V3 {
        /// Distributor base.
        distributor: u64,
        /// Redistributor region base.
        redistributors: u64,
        /// Redistributor region size.
        redistributors_size: u64,
    },
}

const GIC_PHANDLE: u32 = 1;
const CLOCK_PHANDLE: u32 = 2;
/// GIC interrupt specifier types.
const SPI: u32 = 0;
const PPI: u32 = 1;
/// Level-high, and (for PPIs) routed to every CPU.
const LEVEL_HIGH: u32 = 4;

impl ArmMachine<'_> {
    /// Encodes the device tree blob.
    pub fn to_dtb(&self) -> Vec<u8> {
        let mut w = FdtWriter::new();
        let cells = |v: u64| [(v >> 32) as u32, v as u32];
        let reg = |a: u64, s: u64| [cells(a), cells(s)].concat();
        // GICv2 PPI specifiers carry a CPU mask in bits 15:8; GICv3's do not.
        let ppi_cpus = if matches!(self.gic, ArmGic::V2 { .. }) { ((1u32 << self.cpus) - 1) << 8 } else { 0 };

        w.begin_node("");
        w.property_u32("#address-cells", 2);
        w.property_u32("#size-cells", 2);
        w.property_string("compatible", "osmium,virt");
        w.property_string("model", "osmium virtual machine");
        w.property_u32("interrupt-parent", GIC_PHANDLE);

        w.begin_node("chosen");
        w.property_string("bootargs", self.bootargs);
        if let Some(&(base, _)) = self.uarts.first() {
            w.property_string("stdout-path", &format!("/pl011@{base:x}"));
        }
        w.end_node();

        w.begin_node("psci");
        w.property_string_list("compatible", &["arm,psci-1.0", "arm,psci-0.2", "arm,psci"]);
        w.property_string("method", "hvc");
        w.end_node();

        w.begin_node("cpus");
        w.property_u32("#address-cells", 1);
        w.property_u32("#size-cells", 0);
        for c in 0..self.cpus {
            w.begin_node(&format!("cpu@{c}"));
            w.property_string("device_type", "cpu");
            w.property_string("compatible", "arm,armv8");
            w.property_u32("reg", c);
            w.property_string("enable-method", "psci");
            w.end_node();
        }
        w.end_node();

        for &(base, size) in self.memory {
            w.begin_node(&format!("memory@{base:x}"));
            w.property_string("device_type", "memory");
            w.property_cells("reg", &reg(base, size));
            w.end_node();
        }

        let (ArmGic::V2 { distributor: gicd, .. } | ArmGic::V3 { distributor: gicd, .. }) = self.gic;
        w.begin_node(&format!("intc@{gicd:x}"));
        match self.gic {
            ArmGic::V2 { distributor, cpu_interface } => {
                w.property_string_list("compatible", &["arm,cortex-a15-gic"]);
                w.property_cells("reg", &[reg(distributor, 0x1_0000), reg(cpu_interface, 0x1_0000)].concat());
            }
            ArmGic::V3 { distributor, redistributors, redistributors_size } => {
                w.property_string_list("compatible", &["arm,gic-v3"]);
                w.property_cells(
                    "reg",
                    &[reg(distributor, 0x1_0000), reg(redistributors, redistributors_size)].concat(),
                );
            }
        }
        w.property_u32("#interrupt-cells", 3);
        w.property_u32("#address-cells", 0);
        w.property_empty("interrupt-controller");
        w.property_u32("phandle", GIC_PHANDLE);
        w.end_node();

        // Secure physical, non-secure physical, virtual and hypervisor
        // timers: PPIs 13, 14, 11 and 10 (INTIDs 29, 30, 27, 26).
        w.begin_node("timer");
        w.property_string_list("compatible", &["arm,armv8-timer", "arm,armv7-timer"]);
        let timer: Vec<u32> = [13, 14, 11, 10].iter().flat_map(|&p| [PPI, p, ppi_cpus | LEVEL_HIGH]).collect();
        w.property_cells("interrupts", &timer);
        w.property_empty("always-on");
        w.end_node();

        w.begin_node("apb-pclk");
        w.property_string("compatible", "fixed-clock");
        w.property_u32("#clock-cells", 0);
        w.property_u32("clock-frequency", 24_000_000);
        w.property_u32("phandle", CLOCK_PHANDLE);
        w.end_node();

        for &(base, spi) in self.uarts {
            w.begin_node(&format!("pl011@{base:x}"));
            w.property_string_list("compatible", &["arm,pl011", "arm,primecell"]);
            w.property_cells("reg", &reg(base, 0x1000));
            w.property_cells("interrupts", &[SPI, spi, LEVEL_HIGH]);
            w.property_cells("clocks", &[CLOCK_PHANDLE, CLOCK_PHANDLE]);
            w.property_string_list("clock-names", &["uartclk", "apb_pclk"]);
            w.end_node();
        }
        for &(base, spi) in self.virtio {
            w.begin_node(&format!("virtio_mmio@{base:x}"));
            w.property_string("compatible", "virtio,mmio");
            w.property_cells("reg", &reg(base, crate::virtio::MMIO_SIZE));
            w.property_cells("interrupts", &[SPI, spi, 1]); // edge-rising, as QEMU
            w.end_node();
        }

        w.end_node();
        w.finish(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osmium_boot::fdt::Fdt;

    #[test]
    fn parses_back() {
        let m = ArmMachine {
            cpus: 2,
            memory: &[(0x4000_0000, 0x400_0000)],
            gic: ArmGic::V2 { distributor: 0x0800_0000, cpu_interface: 0x0801_0000 },
            uarts: &[(0x0900_0000, 1)],
            virtio: &[(0x0a00_0000, 16)],
            bootargs: "console=ttyAMA0",
        };
        let dtb = m.to_dtb();
        let fdt = Fdt::new(&dtb).unwrap();
        assert_eq!(fdt.bootargs(), Some("console=ttyAMA0"));
        assert_eq!(fdt.memory().next(), Some((0x4000_0000, 0x400_0000)));
        let psci = fdt.find_node("/psci").unwrap();
        assert_eq!(psci.property("method").and_then(|p| p.as_str()), Some("hvc"));
        let gic = fdt.find_compatible(&["arm,cortex-a15-gic"]).unwrap();
        let regs: Vec<_> = gic.reg().collect();
        assert_eq!(regs, [(0x0800_0000, Some(0x1_0000)), (0x0801_0000, Some(0x1_0000))]);
        // The virtual timer is the third triple: PPI 11 = INTID 27.
        let timer = fdt.find_compatible(&["arm,armv8-timer"]).unwrap();
        assert_eq!(timer.interrupts().nth(2 * 3 + 1), Some(11));
        let uart = fdt.find_compatible(&["arm,pl011"]).unwrap();
        assert_eq!(uart.reg().next(), Some((0x0900_0000, Some(0x1000))));
        assert_eq!(fdt.all_nodes().filter(|n| n.compatible().any(|c| c == "virtio,mmio")).count(), 1);
        assert_eq!(fdt.find_node("/cpus").unwrap().children().count(), 2);
    }

    #[test]
    fn gicv3_node() {
        let m = ArmMachine {
            cpus: 4,
            memory: &[(0x4000_0000, 0x400_0000)],
            gic: ArmGic::V3 {
                distributor: 0x0800_0000,
                redistributors: 0x080a_0000,
                redistributors_size: 4 * 0x2_0000,
            },
            uarts: &[],
            virtio: &[],
            bootargs: "",
        };
        let dtb = m.to_dtb();
        let fdt = Fdt::new(&dtb).unwrap();
        assert!(fdt.find_compatible(&["arm,cortex-a15-gic"]).is_none());
        let gic = fdt.find_compatible(&["arm,gic-v3"]).unwrap();
        let regs: Vec<_> = gic.reg().collect();
        assert_eq!(regs, [(0x0800_0000, Some(0x1_0000)), (0x080a_0000, Some(0x8_0000))]);
        let timer = fdt.find_compatible(&["arm,armv8-timer"]).unwrap();
        assert_eq!(timer.interrupts().nth(2 * 3 + 2), Some(4), "level-high, no CPU mask");
    }
}
