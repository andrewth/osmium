//! Reference device drivers built on `osmium-hal`.
//!
//! | Driver | Device | Implements |
//! |---|---|---|
//! | [`uart16550::Uart16550`] | NS16550A UART (MMIO or x86 port I/O) | `SerialPort` |
//! | [`pl011::Pl011`] | Arm PrimeCell UART | `SerialPort` |
//! | [`plic::Plic`] | RISC-V Platform-Level Interrupt Controller | `InterruptController` |
//! | [`gicv2::GicV2`] | Arm Generic Interrupt Controller v2 | `InterruptController` |
//! | [`lapic::LocalApic`] | x86 local APIC (xAPIC MMIO) | EOI, IPIs, timer |
//! | [`pit::Pit`] | Intel 8254 PIT | calibration delays |
//! | [`ioapic::IoApic`] | x86 I/O APIC | GSI routing |
//! | [`ramdisk::RamDisk`] | Memory-backed disk | `BlockDevice` |
//! | [`virtio::net::VirtioNet`] | virtio network card (MMIO, legacy and 1.x) | `NetDevice` |
//! | [`xhci::Xhci`] | xHCI USB host controller | `UsbHost` |
//!
//! Every driver is constructed from an [`osmium_hal::mmio::IoMem`] (or a
//! port base), so it works the same under any memory map and can be tested
//! against ordinary memory.
#![no_std]

#[cfg(test)]
extern crate std;

pub mod gicv2;
pub mod ioapic;
pub mod lapic;
pub mod pit;
pub mod pl011;
pub mod plic;
pub mod ramdisk;
pub mod uart16550;
pub mod virtio;
pub mod xhci;
