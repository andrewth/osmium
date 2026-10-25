//! System device drivers built on `osmium-hal`: UARTs, interrupt controllers, timers, firmware interfaces and IOMMUs.
//!
//! | Driver | Device | Implements |
//! |---|---|---|
//! | [`uart16550::Uart16550`] | NS16550A UART (MMIO or x86 port I/O) | `SerialPort` |
//! | [`pl011::Pl011`] | Arm PrimeCell UART | `SerialPort` |
//! | [`fwcfg::FwCfg`] | QEMU `fw_cfg` (ports or MMIO, optional DMA) | named blobs: tables, kernel, ramfb |
//! | [`pit::Pit`] | Intel 8254 PIT | calibration delays |
//! | [`plic::Plic`] | RISC-V Platform-Level Interrupt Controller | `InterruptController` |
//! | [`gicv2::GicV2`] | Arm Generic Interrupt Controller v2 | `InterruptController` |
//! | [`lapic::LocalApic`] | x86 local APIC (xAPIC MMIO) | EOI, IPIs, timer, MSI messages |
//! | [`ioapic::IoApic`] | x86 I/O APIC | GSI routing |
//! | [`clint::Clint`] | RISC-V CLINT (M-mode timer, software IRQs) | firmware timers |
//! | [`iommu::vtd::Vtd`] | Intel VT-d DMA remapping unit | `Iommu` |
//! | [`iommu::amdvi::AmdVi`] | AMD-Vi (AMD IOMMU) unit | `Iommu` |
//! | [`iommu::smmuv3::Smmuv3`] | Arm SMMUv3 | `Iommu` |
//! | [`iommu::riscv::RiscvIommu`] | RISC-V IOMMU | `Iommu` |
//!
//! Every driver is constructed from an [`osmium_hal::mmio::IoMem`], so it works the same under any
//! memory map and can be tested against ordinary memory.
#![no_std]

#[cfg(test)]
extern crate std;

pub mod clint;
pub mod fwcfg;
pub mod gicv2;
pub mod ioapic;
pub mod iommu;
pub mod lapic;
pub mod pit;
pub mod pl011;
pub mod plic;
pub mod uart16550;
