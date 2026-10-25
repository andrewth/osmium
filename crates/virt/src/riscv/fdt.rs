//! Device trees for RISC-V guests.

use alloc::format;
use alloc::vec::Vec;

use osmium_boot::fdt::FdtWriter;

/// A RISC-V guest's machine, described in the layout Linux and
/// `osmium-boot` expect from QEMU `virt`: one `riscv,cpu-intc` per hart, a
/// PLIC with an M and an S context per hart (the M contexts are left
/// unconnected) or, with [`aia`](Self::aia), an APLIC in MSI mode and one
/// IMSIC interrupt file per hart, 16550 UARTs and virtio-mmio devices.
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
    /// An APLIC and IMSIC instead of the PLIC (use one or the other). The
    /// devices' interrupt numbers are then APLIC source numbers.
    pub aia: Option<Aia>,
    /// 16550 UARTs as (base, PLIC or APLIC source); the first is the console.
    pub uarts: &'src [(u64, u32)],
    /// virtio-mmio devices as (base, PLIC or APLIC source).
    pub virtio: &'src [(u64, u32)],
    /// Kernel command line.
    pub bootargs: &'src str,
}

/// The Advanced Interrupt Architecture controllers of a guest: an APLIC
/// delivering message-signaled interrupts to one IMSIC file per hart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aia {
    /// APLIC base.
    pub aplic: u64,
    /// Number of APLIC sources.
    pub sources: u32,
    /// Base of the IMSIC files (one 4 KiB page per hart, back to back).
    pub imsic: u64,
    /// The highest interrupt identity of an IMSIC file (63, 127, 255, ...).
    pub ids: u32,
}

const APLIC_PHANDLE: u32 = 0x101;
const IMSIC_PHANDLE: u32 = 0x102;
/// Level-high, the second interrupt cell of an APLIC source.
const APLIC_LEVEL_HIGH: u32 = 4;
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
        if let Some(aia) = self.aia {
            w.begin_node(&format!("imsics@{:x}", aia.imsic));
            w.property_string("compatible", "riscv,imsics");
            w.property_cells("reg", &reg(aia.imsic, crate::devices::IMSIC_FILE_SIZE * u64::from(self.harts)));
            let ext: Vec<u32> = (0..self.harts).flat_map(|h| [CPU_INTC_PHANDLE + h, IRQ_S_EXT]).collect();
            w.property_cells("interrupts-extended", &ext);
            w.property_empty("interrupt-controller");
            w.property_u32("#interrupt-cells", 0);
            w.property_empty("msi-controller");
            w.property_u32("#msi-cells", 0);
            w.property_u32("riscv,num-ids", aia.ids);
            w.property_u32("phandle", IMSIC_PHANDLE);
            w.end_node();
            w.begin_node(&format!("aplic@{:x}", aia.aplic));
            w.property_string("compatible", "riscv,aplic");
            w.property_cells("reg", &reg(aia.aplic, crate::devices::VirtualAplic::mmio_size(0)));
            w.property_u32("msi-parent", IMSIC_PHANDLE);
            w.property_empty("interrupt-controller");
            w.property_u32("#interrupt-cells", 2);
            w.property_u32("riscv,num-sources", aia.sources);
            w.property_u32("phandle", APLIC_PHANDLE);
            w.end_node();
        }
        // The devices' interrupts: PLIC sources (one cell) or APLIC sources and a trigger type.
        let parent = if self.aia.is_some() { APLIC_PHANDLE } else { PLIC_PHANDLE };
        let irq_cells =
            |irq: u32| if self.aia.is_some() { alloc::vec![irq, APLIC_LEVEL_HIGH] } else { alloc::vec![irq] };
        for &(base, irq) in self.uarts {
            w.begin_node(&format!("serial@{base:x}"));
            w.property_string("compatible", "ns16550a");
            w.property_cells("reg", &reg(base, 0x100));
            w.property_u32("clock-frequency", 3_686_400);
            w.property_cells("interrupts", &irq_cells(irq));
            w.property_u32("interrupt-parent", parent);
            w.end_node();
        }
        for &(base, irq) in self.virtio {
            w.begin_node(&format!("virtio_mmio@{base:x}"));
            w.property_string("compatible", "virtio,mmio");
            w.property_cells("reg", &reg(base, crate::virtio::MMIO_SIZE));
            w.property_cells("interrupts", &irq_cells(irq));
            w.property_u32("interrupt-parent", parent);
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
            aia: None,
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

    #[test]
    fn aia_nodes() {
        let m = GuestMachine {
            harts: 2,
            isa: "rv64imac_ssaia",
            timebase: 10_000_000,
            memory: &[(0x8000_0000, 0x400_0000)],
            plic: None,
            aia: Some(Aia { aplic: 0xd00_0000, sources: 32, imsic: 0x2800_0000, ids: 255 }),
            uarts: &[(0x1000_0000, 10)],
            virtio: &[],
            bootargs: "",
        };
        let dtb = m.to_dtb();
        let fdt = Fdt::new(&dtb).unwrap();
        assert!(fdt.find_compatible(&["riscv,plic0"]).is_none());
        let imsic = fdt.find_compatible(&["riscv,imsics"]).unwrap();
        assert_eq!(imsic.reg().next(), Some((0x2800_0000, Some(0x2000))));
        let ext: Vec<u32> = imsic.property("interrupts-extended").unwrap().as_u32_cells().collect();
        assert_eq!(ext, [1, 9, 2, 9], "one S-level external line per hart");
        let aplic = fdt.find_compatible(&["riscv,aplic"]).unwrap();
        assert_eq!(aplic.reg().next(), Some((0xd00_0000, Some(0x4000))));
        assert_eq!(aplic.property("msi-parent").unwrap().as_u32_cells().collect::<Vec<_>>(), [IMSIC_PHANDLE]);
        let uart = fdt.find_compatible(&["ns16550a"]).unwrap();
        assert_eq!(uart.property("interrupts").unwrap().as_u32_cells().collect::<Vec<_>>(), [10, 4]);
        assert_eq!(uart.property("interrupt-parent").unwrap().as_u32_cells().collect::<Vec<_>>(), [APLIC_PHANDLE]);
    }
}
