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

use core::ptr::NonNull;

use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::iommu::IommuError;
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;
use osmium_mm::PhysAddr;

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

/// A sparse set of 4 KiB table pages, indexed by the slot the hardware
/// directory links them from.
///
/// Drivers keep these instead of an array of buffers: a kernel boot stack is
/// small, and the array would be several kilobytes. The index itself lives in
/// DMA memory (that no device reads): per slot, the CPU pointer and device
/// address of its page.
pub(crate) struct Pages<'d, D: DmaAllocator + ?Sized> {
    dma: &'d D,
    index: OwnedDma<'d, D>,
    slots: usize,
}

const PAGE_LEN: usize = 4096;
/// Bytes per slot in the index: CPU pointer, device address.
const SLOT_LEN: usize = 16;

impl<'d, D: DmaAllocator + ?Sized> Pages<'d, D> {
    /// An empty set of `slots` slots.
    pub(crate) fn new(dma: &'d D, slots: usize) -> Result<Self, IommuError> {
        let index = OwnedDma::new(dma, slots * SLOT_LEN).ok_or(IommuError::OutOfMemory)?;
        Ok(Self { dma, index, slots })
    }

    /// The page in slot `slot`, if one was allocated.
    pub(crate) fn get(&self, slot: usize) -> Option<DmaBuffer> {
        assert!(slot < self.slots);
        let cpu = NonNull::new(self.index.load::<u64>(slot * SLOT_LEN) as *mut u8)?;
        let device = PhysAddr::new(self.index.load::<u64>(slot * SLOT_LEN + 8));
        // SAFETY: recorded by `get_or_alloc` from a buffer this set owns and
        // has not freed; callers use it like the original.
        Some(unsafe { DmaBuffer::new(cpu, device, PAGE_LEN) })
    }

    /// The page in slot `slot`, allocating a zeroed one if the slot is empty.
    /// The flag says whether it is new, so the caller links it.
    pub(crate) fn get_or_alloc(&self, slot: usize) -> Result<(DmaBuffer, bool), IommuError> {
        if let Some(page) = self.get(slot) {
            return Ok((page, false));
        }
        let page = self.dma.alloc_coherent(PAGE_LEN).ok_or(IommuError::OutOfMemory)?;
        self.index.store::<u64>(slot * SLOT_LEN, page.cpu_ptr().as_ptr() as u64);
        self.index.store::<u64>(slot * SLOT_LEN + 8, page.device_addr().as_u64());
        Ok((page, true))
    }
}

impl<D: DmaAllocator + ?Sized> Drop for Pages<'_, D> {
    fn drop(&mut self) {
        for slot in 0..self.slots {
            if let Some(page) = self.get(slot) {
                // SAFETY: allocated from `dma` in `get_or_alloc`, and the
                // owner stopped the hardware before dropping the set.
                unsafe { self.dma.free_coherent(page) };
            }
        }
    }
}
