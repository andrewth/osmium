//! IOMMU drivers: [`vtd`] (Intel VT-d), [`amdvi`] (AMD-Vi), [`smmuv3`] (Arm
//! SMMUv3) and [`riscv`] (RISC-V IOMMU).
//!
//! Each implements [`osmium_hal::iommu::Iommu`] over its unit's registers, so
//! a kernel treats them alike: build an
//! [`IoDomain`](osmium_hal::iommu::IoDomain), attach devices and hand their
//! drivers an [`IommuDma`](osmium_hal::iommu::IommuDma) allocator.
//!
//! What all four share:
//!
//! - Translation is switched on when the first device attaches, and from then
//!   on a device that is not attached has its DMA blocked. Attach every device
//!   that does DMA on the unit (including the one holding the root file
//!   system) before the first attach finishes, or accept that it stops.
//! - Tables the hardware reads (device tables, queues) come from a
//!   [`DmaAllocator`](osmium_hal::dma::DmaAllocator) that hands out physical
//!   addresses the IOMMU can use directly, page-aligned and zeroed. Units
//!   that report non-coherent table walks are refused.
//! - Every wait is bounded by a [`Clock`]. If the
//!   hardware stops answering, calls fail with
//!   [`IommuError::Timeout`] and
//!   dropping the driver leaks its tables instead of freeing memory the unit
//!   might still read.
//! - Interrupt remapping is not configured. Devices that raise MSIs through
//!   an interrupt controller's doorbell address may need that address mapped
//!   in their domain (SMMUv3, RISC-V IOMMU) or reserved out of the IOVA
//!   window (x86 `0xfee0_0000..0xfef0_0000`).

pub mod amdvi;
pub mod riscv;
pub mod smmuv3;
pub mod vtd;

#[cfg(test)]
mod testing;

use osmium_hal::iommu::IommuError;
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;

/// Default bound, in nanoseconds, on waiting for the hardware to acknowledge
/// a command or state change.
pub const DEFAULT_TIMEOUT_NS: u64 = 1_000_000_000;

/// A register window with checked, infallible-looking accessors: the window
/// length is verified once at construction, so reads and writes inside the
/// registers a driver uses cannot fail.
pub(crate) struct Regs(IoMem);

impl Regs {
    /// Wraps `io` if it holds at least `min_len` bytes.
    pub(crate) fn new(io: IoMem, min_len: usize) -> Result<Self, IommuError> {
        if io.len() < min_len { Err(IommuError::BadRegisters) } else { Ok(Self(io)) }
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn r32(&self, off: usize) -> u32 {
        self.0.read(off).expect("register inside the checked window")
    }

    pub(crate) fn r64(&self, off: usize) -> u64 {
        self.0.read(off).expect("register inside the checked window")
    }

    pub(crate) fn w32(&self, off: usize, v: u32) {
        self.0.write(off, v).expect("register inside the checked window")
    }

    pub(crate) fn w64(&self, off: usize, v: u64) {
        self.0.write(off, v).expect("register inside the checked window")
    }
}

/// Polls `done` until it returns true or `timeout_ns` passes.
pub(crate) fn wait_until(clock: &dyn Clock, timeout_ns: u64, mut done: impl FnMut() -> bool) -> Result<(), IommuError> {
    let deadline = clock.now_ns().saturating_add(timeout_ns);
    loop {
        if done() {
            return Ok(());
        }
        if clock.now_ns() > deadline {
            return Err(IommuError::Timeout);
        }
        osmium_arch::cpu::spin_hint();
    }
}
