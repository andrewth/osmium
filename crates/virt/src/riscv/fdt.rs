//! Device trees for RISC-V guests.

use alloc::format;
use alloc::vec::Vec;

use osmium_boot::fdt::FdtWriter;

/// A RISC-V guest's machine, described in the layout Linux and
/// `osmium-boot` expect from QEMU `virt`: one `riscv,cpu-intc` per hart, a
/// PLIC with an M and an S context per hart (the M contexts are left
/// unconnected), 16550 UARTs and virtio-mmio devices.
pub struct GuestMachine<'src> {
    /// Number of harts.
    pub harts: u32,
    /// `riscv,isa` string, e.g. `"rv64imac"`.
    pub isa: &'src str,
    /// Timer frequency in Hz (QEMU `virt`: 10 MHz).
    pub timebase: u32,
    /// RAM as (base, size).
    pub memory: &'src [(u64, u64)],
    /// PLIC as (base, number of sources).
    pub plic: Option<(u64, u32)>,
    /// 16550 UARTs as (base, PLIC source); the first is the console.
    pub uarts: &'src [(u64, u32)],
    /// virtio-mmio devices as (base, PLIC source).
    pub virtio: &'src [(u64, u32)],
    /// Kernel command line.
    pub bootargs: &'src str,
}

const CPU_INTC_PHANDLE: u32 = 1;
const PLIC_PHANDLE: u32 = 0x100;
/// Interrupt cause numbers on the local interrupt controller.
const IRQ_S_EXT: u32 = 9;

impl GuestMachine<'_> {
    /// Encodes the device tree blob.
    pub fn to_dtb(&self) -> Vec<u8> {
        let mut w = FdtWriter::new();
        let cells = |v: u64| [(v >> 32) as u32, v as u32];
        let reg = |a: u64, s: u64| [cells(a), cells(s)].concat();

        w.begin_node("");
        w.property_u32("#address-cells", 2);
        w.property_u32("#size-cells", 2);
        w.property_string("compatible", "osmium,virt");
        w.property_string("model", "osmium virtual machine");

        w.begin_node("chosen");
        w.property_string("bootargs", self.bootargs);
        if let Some(&(base, _)) = self.uarts.first() {
            w.property_string("stdout-path", &format!("/soc/serial@{base:x}"));
        }
        w.end_node();

        w.begin_node("cpus");
        w.property_u32("#address-cells", 1);
        w.property_u32("#size-cells", 0);
        w.property_u32("timebase-frequency", self.timebase);
        for h in 0..self.harts {
            w.begin_node(&format!("cpu@{h}"));
            w.property_string("device_type", "cpu");
            w.property_u32("reg", h);
            w.property_string("compatible", "riscv");
            w.property_string("riscv,isa", self.isa);
            w.property_string("mmu-type", "riscv,sv39");
            w.property_string("status", "okay");
            w.begin_node("interrupt-controller");
            w.property_u32("#interrupt-cells", 1);
            w.property_empty("interrupt-controller");
            w.property_string("compatible", "riscv,cpu-intc");
            w.property_u32("phandle", CPU_INTC_PHANDLE + h);
            w.end_node();
            w.end_node();
        }
        w.end_node();

        for &(base, size) in self.memory {
            w.begin_node(&format!("memory@{base:x}"));
            w.property_string("device_type", "memory");
            w.property_cells("reg", &reg(base, size));
            w.end_node();
        }

        w.begin_node("soc");
        w.property_u32("#address-cells", 2);
        w.property_u32("#size-cells", 2);
        w.property_string("compatible", "simple-bus");
        w.property_empty("ranges");
        if let Some((base, sources)) = self.plic {
            w.begin_node(&format!("plic@{base:x}"));
            w.property_string_list("compatible", &["sifive,plic-1.0.0", "riscv,plic0"]);
            let size = crate::devices::VirtualPlic::mmio_size(2 * self.harts as usize);
            w.property_cells("reg", &reg(base, size));
            // Per hart: the M context (unconnected: cause -1), then the S context.
            let ext: Vec<u32> = (0..self.harts)
                .flat_map(|h| [CPU_INTC_PHANDLE + h, u32::MAX, CPU_INTC_PHANDLE + h, IRQ_S_EXT])
                .collect();
            w.property_cells("interrupts-extended", &ext);
            w.property_u32("riscv,ndev", sources - 1);
            w.property_u32("#interrupt-cells", 1);
            w.property_u32("#address-cells", 0);
            w.property_empty("interrupt-controller");
            w.property_u32("phandle", PLIC_PHANDLE);
            w.end_node();
        }
        for &(base, irq) in self.uarts {
            w.begin_node(&format!("serial@{base:x}"));
            w.property_string("compatible", "ns16550a");
            w.property_cells("reg", &reg(base, 0x100));
            w.property_u32("clock-frequency", 3_686_400);
            w.property_u32("interrupts", irq);
            w.property_u32("interrupt-parent", PLIC_PHANDLE);
            w.end_node();
        }
        for &(base, irq) in self.virtio {
            w.begin_node(&format!("virtio_mmio@{base:x}"));
            w.property_string("compatible", "virtio,mmio");
            w.property_cells("reg", &reg(base, crate::virtio::MMIO_SIZE));
            w.property_u32("interrupts", irq);
            w.property_u32("interrupt-parent", PLIC_PHANDLE);
            w.end_node();
        }
        w.end_node();

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
        let m = GuestMachine {
            harts: 2,
            isa: "rv64imac",
            timebase: 10_000_000,
            memory: &[(0x8000_0000, 0x400_0000)],
            plic: Some((0xc00_0000, 32)),
            uarts: &[(0x1000_0000, 10)],
            virtio: &[(0x1000_1000, 1), (0x1000_2000, 2)],
            bootargs: "console=ttyS0",
        };
        let dtb = m.to_dtb();
        let fdt = Fdt::new(&dtb).unwrap();
        assert_eq!(fdt.bootargs(), Some("console=ttyS0"));
        assert_eq!(fdt.memory().collect::<Vec<_>>(), [(0x8000_0000, 0x400_0000)]);
        let uart = fdt.find_compatible(&["ns16550a"]).unwrap();
        assert_eq!(uart.reg().next(), Some((0x1000_0000, Some(0x100))));
        assert_eq!(uart.interrupts().collect::<Vec<_>>(), [10]);
        let plic = fdt.find_compatible(&["riscv,plic0"]).unwrap();
        assert_eq!(plic.reg().next().unwrap().0, 0xc00_0000);
        let ext: Vec<u32> = plic.property("interrupts-extended").unwrap().as_u32_cells().collect();
        assert_eq!(ext, [1, u32::MAX, 1, 9, 2, u32::MAX, 2, 9]);
        let virtio: Vec<_> = fdt.all_nodes().filter(|n| n.is_compatible("virtio,mmio")).collect();
        assert_eq!(virtio.len(), 2);
        assert_eq!(fdt.find_node("/cpus").unwrap().children().count(), 2);
        assert_eq!(fdt.chosen().unwrap().property("stdout-path").unwrap().as_str(), Some("/soc/serial@10000000"));
    }
}
