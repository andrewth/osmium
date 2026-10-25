//! Reference device drivers built on `osmium-hal`.
//!
//! | Driver | Device | Implements |
//! |---|---|---|
//! | [`uart16550::Uart16550`] | NS16550A UART (MMIO or x86 port I/O) | `SerialPort` |
//! | [`pl011::Pl011`] | Arm PrimeCell UART | `SerialPort` |
//! | [`plic::Plic`] | RISC-V Platform-Level Interrupt Controller | `InterruptController` |
//! | [`gicv2::GicV2`] | Arm Generic Interrupt Controller v2 | `InterruptController` |
//! | [`lapic::LocalApic`] | x86 local APIC (xAPIC MMIO) | EOI, IPIs, timer, MSI messages |
//! | [`fwcfg::FwCfg`] | QEMU `fw_cfg` (ports or MMIO, optional DMA) | named blobs: tables, kernel, ramfb |
//! | [`pit::Pit`] | Intel 8254 PIT | calibration delays |
//! | [`clint::Clint`] | RISC-V CLINT (M-mode timer, software IRQs) | firmware timers |
//! | [`ioapic::IoApic`] | x86 I/O APIC | GSI routing |
//! | [`ramdisk::RamDisk`] | Memory-backed disk | `BlockDevice` |
//! | [`nvme::Nvme`] | NVM Express SSD (PCI, polled) | `BlockDevice` |
//! | [`virtio::gpu::VirtioGpu`] | virtio GPU, 2D (MMIO, or PCI as `virtio-gpu-pci` and `virtio-vga`) | `Display` |
//! | [`display::bochs::BochsVbe`] | Bochs DISPI: QEMU std VGA, `bochs-display`, `virtio-vga` in VGA mode | `Display` |
//! | [`display::vbe::Vbe`] | VESA BIOS Extensions through a [`display::vbe::VideoBios`] | mode list and mode setting |
//! | [`ahci::AhciDisk`] | SATA disk on an AHCI HBA (PCI, polled) | `BlockDevice` per port |
//! | [`iommu::vtd::Vtd`] | Intel VT-d DMA remapping unit | `Iommu` |
//! | [`iommu::amdvi::AmdVi`] | AMD-Vi (AMD IOMMU) unit | `Iommu` |
//! | [`iommu::smmuv3::Smmuv3`] | Arm SMMUv3 | `Iommu` |
//! | [`iommu::riscv::RiscvIommu`] | RISC-V IOMMU | `Iommu` |
//!
//! Every driver is constructed from an [`osmium_hal::mmio::IoMem`] (or a
//! port base), so it works the same under any memory map and can be tested
//! against ordinary memory.
#![no_std]

#[cfg(any(test, feature = "testing"))]
extern crate std;

pub mod ahci;
pub mod clint;
pub mod display;
pub mod fwcfg;
pub mod gicv2;
pub mod ioapic;
pub mod iommu;
pub mod lapic;
pub mod nvme;
pub mod pit;
pub mod pl011;
pub mod plic;
pub mod ramdisk;
pub mod uart16550;
pub mod virtio;

/// Panic-free register access for drivers: an access outside the window
/// reads as all ones and a write is dropped, as on a bus with no device.
pub(crate) mod ioext {
    use osmium_hal::mmio::{IoMem, RegValue};

    /// A register value with an all-ones pattern.
    pub trait Ones {
        /// All bits set.
        const ONES: Self;
    }
    impl Ones for u8 {
        const ONES: Self = u8::MAX;
    }
    impl Ones for u16 {
        const ONES: Self = u16::MAX;
    }
    impl Ones for u32 {
        const ONES: Self = u32::MAX;
    }
    impl Ones for u64 {
        const ONES: Self = u64::MAX;
    }

    /// Infallible register access.
    pub trait IoMemExt {
        /// Reads a register, or all ones if it lies outside the window.
        fn rd<T: RegValue + Ones>(&self, offset: usize) -> T;
        /// Writes a register; a write outside the window is ignored.
        fn wr<T: RegValue>(&self, offset: usize, value: T);
    }

    impl IoMemExt for IoMem {
        fn rd<T: RegValue + Ones>(&self, offset: usize) -> T {
            // The barrier keeps the load a plain `mov`: left alone, the compiler folds a volatile
            // read into the next operation (`or reg, [mem]`), which a hypervisor that emulates
            // MMIO by decoding the faulting instruction may not support.
            core::hint::black_box(self.read(offset).unwrap_or(T::ONES))
        }
        fn wr<T: RegValue>(&self, offset: usize, value: T) {
            let _ = self.write(offset, value);
        }
    }
}
