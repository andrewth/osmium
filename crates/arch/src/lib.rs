//! CPU primitives for x86_64, AArch64 and RISC-V 64.
//!
//! This is the lowest Osmium layer. It wraps the handful of instructions that
//! every other component needs: interrupt-flag control, CPU identity, waiting
//! for interrupts, a monotonic counter, TLB maintenance and DMA memory
//! barriers. Architecture specific registers live in the `x86_64`, `aarch64`
//! and `riscv64` modules (each compiled only for its own architecture).
//!
//! On freestanding targets (`target_os = "none"` or `"uefi"`) the functions
//! execute the real instructions. On hosted targets they fall back to a
//! simulation: the IRQ flag and CPU id are per-thread variables and TLB
//! maintenance is a no-op. That lets every crate above this one be unit-tested
//! as an ordinary program.
#![no_std]

#[cfg(not(bare))]
extern crate std;

pub mod barrier;
pub mod cpu;
pub mod fp;
pub mod irq;
pub mod mmu;
pub mod trap;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "riscv64")]
pub mod riscv64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

/// The largest number of CPUs that per-CPU data structures size themselves for.
pub const MAX_CPUS: usize = 64;

/// Size of the smallest page on every supported architecture.
pub const PAGE_SIZE: usize = 4096;
