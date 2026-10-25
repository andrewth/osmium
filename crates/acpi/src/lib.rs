//! ACPI: reading the firmware's description of the machine and driving its power management.
//!
//! - [`aml`]: an AML interpreter. It loads the DSDT and SSDTs into a namespace, runs control methods
//!   (`_STA`, `_INI`, `_CRS`, `_PRT`, `_S5_` and the rest) and reaches operation regions through a
//!   [`Host`](aml::Host) the kernel supplies.
//! - [`fadt`]: the Fixed ACPI Description Table, which says where the power-management registers are.
//! - [`resource`]: resource descriptors, the buffers `_CRS`, `_PRS` and `_SRS` pass around.
//! - [`pci`]: PCI interrupt routing from `_PRT`.
//! - [`pm`]: entering ACPI mode, sleep states and power off, reset, and the SCI: fixed events and GPEs.
//!
//! The static tables (RSDP, MADT, MCFG, ...) are read by `osmium_boot::acpi`, which this crate builds on.
//! It needs `alloc` but defines no allocator, panic handler or global state; the kernel owns the
//! [`Interpreter`](aml::Interpreter).
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod aml;
pub mod fadt;
pub mod pci;
pub mod pm;
pub mod resource;
