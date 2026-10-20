//! Reference device drivers built on `osmium-hal`.
//!
//! | Driver | Device | Implements |
//! |---|---|---|
//! | [`uart16550::Uart16550`] | NS16550A UART (MMIO or x86 port I/O) | `SerialPort` |
//! | [`pl011::Pl011`] | Arm PrimeCell UART | `SerialPort` |
//! | [`plic::Plic`] | RISC-V Platform-Level Interrupt Controller | `InterruptController` |
//! | [`gicv2::GicV2`] | Arm Generic Interrupt Controller v2 | `InterruptController` |
//! | [`lapic::LocalApic`] | x86 local APIC (xAPIC MMIO) | EOI, IPIs, timer, MSI messages |
//! | [`pit::Pit`] | Intel 8254 PIT | calibration delays |
//! | [`clint::Clint`] | RISC-V CLINT (M-mode timer, software IRQs) | firmware timers |
//! | [`ioapic::IoApic`] | x86 I/O APIC | GSI routing |
//! | [`ramdisk::RamDisk`] | Memory-backed disk | `BlockDevice` |
//! | [`virtio::net::VirtioNet`] | virtio network card (MMIO, legacy and 1.x) | `NetDevice` |
//! | [`xhci::Xhci`] | xHCI USB host controller | `UsbHost` |
//! | [`mlx4::Mlx4`] | Mellanox ConnectX-2/-3 Ethernet (PCI, polled) | `NetDevice` per port |
//! | [`nvme::Nvme`] | NVM Express SSD (PCI, polled) | `BlockDevice` |
//! | [`virtio::gpu::VirtioGpu`] | virtio GPU, 2D (MMIO, or PCI as `virtio-gpu-pci` and `virtio-vga`) | `Display` |
//! | [`display::bochs::BochsVbe`] | Bochs DISPI: QEMU std VGA, `bochs-display`, `virtio-vga` in VGA mode | `Display` |
//! | [`display::vbe::Vbe`] | VESA BIOS Extensions through a [`display::vbe::VideoBios`] | mode list and mode setting |
//! | [`ahci::AhciDisk`] | SATA disk on an AHCI HBA (PCI, polled) | `BlockDevice` per port |
//! | [`usb::storage::UsbStorage`] | USB mass storage (SCSI, Bulk-Only) on any `UsbHost` | `BlockDevice` |
//! | [`usb::hid::BootKeyboard`] | USB keyboard (HID boot protocol) on any `UsbHost` | key events |
//! | [`usb::ecm::UsbEthernet`] | USB Ethernet (CDC-ECM) on any `UsbHost` | `NetDevice` |
//! | [`iommu::vtd::Vtd`] | Intel VT-d DMA remapping unit | `Iommu` |
//! | [`iommu::amdvi::AmdVi`] | AMD-Vi (AMD IOMMU) unit | `Iommu` |
//! | [`iommu::smmuv3::Smmuv3`] | Arm SMMUv3 | `Iommu` |
//! | [`iommu::riscv::RiscvIommu`] | RISC-V IOMMU | `Iommu` |
//!
//! Every driver is constructed from an [`osmium_hal::mmio::IoMem`] (or a
//! port base), so it works the same under any memory map and can be tested
//! against ordinary memory.
#![no_std]

#[cfg(test)]
extern crate std;

pub mod ahci;
pub mod clint;
pub mod display;
pub mod gicv2;
pub mod ioapic;
pub mod iommu;
pub mod lapic;
pub mod mlx4;
pub mod nvme;
pub mod pit;
pub mod pl011;
pub mod plic;
pub mod ramdisk;
pub mod uart16550;
pub mod usb;
pub mod virtio;
pub mod xhci;
