//! Hypervisor building blocks.
//!
//! - [`memory`]: [`GuestMemory`], the map from guest-physical addresses to
//!   host memory, with bounds-checked access and a [`Pod`] marker for typed
//!   reads and writes (in the spirit of rust-vmm's `vm-memory`).
//! - [`stage2`]: second-stage page tables (Intel EPT, Arm stage 2) built on
//!   `osmium_mm::PageTable`, and helpers to encode EPTP and VTTBR.
//! - [`bus`]: MMIO and port-I/O buses that route guest accesses to emulated
//!   devices (as in rust-vmm's `vm-device`).
//! - [`vcpu`]: a normalized [`VmExit`], the [`Vcpu`] trait that hardware
//!   backends implement, and [`run_vcpu`], a loop that services device exits.
//! - [`devices`]: emulated devices.
//! - [`virtio`]: virtio device models behind the virtio-mmio transport.
//!
//! Hardware backends (VMX, SVM, Arm EL2, RISC-V H) implement [`Vcpu`]; they
//! are on the roadmap.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod bus;
pub mod devices;
pub mod memory;
pub mod stage2;
pub mod vcpu;
pub mod virtio;

pub use bus::{Bus, BusDevice, BusError};
pub use memory::{GuestMemory, GuestPhysAddr, Pod};
pub use vcpu::{Vcpu, VmExit, run_vcpu};
