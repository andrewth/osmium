//! Hypervisor building blocks.
//!
//! - [`memory`]: [`GuestMemory`], the map from guest-physical addresses to
//!   host memory, with bounds-checked access and a [`Pod`] marker for typed
//!   reads and writes (in the spirit of rust-vmm's `vm-memory`).
//! - [`stage2`]: second-stage page tables (Intel EPT, Arm stage 2, RISC-V
//!   G-stage) built on
//!   `osmium_mm::PageTable`, and helpers to encode EPTP, VTTBR and hgatp.
//! - [`bus`]: MMIO and port-I/O buses that route guest accesses to emulated
//!   devices (as in rust-vmm's `vm-device`).
//! - [`vcpu`]: a normalized [`VmExit`], the [`Vcpu`] trait that hardware
//!   backends implement, and [`run_vcpu`], a loop that services device exits.
//! - [`devices`]: emulated devices.
//! - [`riscv`]: a RISC-V H-extension vCPU and a minimal SBI for guests.
//! - [`smp`]: start/stop state, IPIs and kicks for multi-vCPU guests.
//! - [`aarch64`]: an AArch64 EL2 (non-VHE) vCPU and PSCI for guests.
//! - [`x86`]: AMD SVM and Intel VMX vCPUs with nested paging.
//! - [`virtio`]: virtio device models behind the virtio-mmio transport.
//!
//! Hardware backends implement [`Vcpu`]: RISC-V H ([`riscv::RiscvVcpu`]),
//! AArch64 EL2 ([`aarch64::Aarch64Vcpu`]) and AMD SVM ([`x86::svm::SvmVcpu`])
//! and Intel VMX ([`x86::vmx::VmxVcpu`]). `docs/HYPERVISOR.md` shows how the pieces
//! fit together.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod aarch64;
pub mod bus;
pub mod devices;
pub mod memory;
pub mod smp;
pub mod riscv;
pub mod stage2;
pub mod vcpu;
pub mod virtio;
pub mod x86;

pub use bus::{Bus, BusDevice, BusError};
pub use memory::{GuestMemory, GuestPhysAddr, Pod};
pub use vcpu::{Vcpu, VmExit, run_vcpu};
