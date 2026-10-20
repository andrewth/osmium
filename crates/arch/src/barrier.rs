//! Memory barriers for sharing memory with devices.
//!
//! Drivers that build descriptor rings in RAM need two orderings the
//! compiler and CPU do not give them for free: ring contents must be visible
//! to the device before the index or doorbell that publishes them, and a
//! completion index read from RAM must not be satisfied before the entries
//! it covers. These are Linux's `dma_wmb`, `dma_rmb` and `mb`.
//!
//! On hosted targets they are ordinary atomic fences, which is all the
//! simulated devices in tests need.

pub use imp::{dma_rmb, dma_wmb, mb};

#[cfg(all(bare, target_arch = "aarch64"))]
mod imp {
    use core::arch::asm;

    /// Orders earlier stores to DMA memory before later stores to DMA memory.
    #[inline]
    pub fn dma_wmb() {
        // SAFETY: a barrier has no other effect.
        unsafe { asm!("dmb oshst", options(nostack, preserves_flags)) }
    }

    /// Orders earlier loads from DMA memory before later loads.
    #[inline]
    pub fn dma_rmb() {
        // SAFETY: a barrier has no other effect.
        unsafe { asm!("dmb oshld", options(nostack, preserves_flags)) }
    }

    /// Orders all earlier memory and MMIO accesses before all later ones
    /// (for example, a ring update before the doorbell write).
    #[inline]
    pub fn mb() {
        // SAFETY: a barrier has no other effect.
        unsafe { asm!("dsb sy", options(nostack, preserves_flags)) }
    }
}

#[cfg(all(bare, target_arch = "riscv64"))]
mod imp {
    use core::arch::asm;

    /// Orders earlier stores to DMA memory before later stores to DMA memory.
    #[inline]
    pub fn dma_wmb() {
        // SAFETY: a barrier has no other effect.
        unsafe { asm!("fence w, w", options(nostack, preserves_flags)) }
    }

    /// Orders earlier loads from DMA memory before later loads.
    #[inline]
    pub fn dma_rmb() {
        // SAFETY: a barrier has no other effect.
        unsafe { asm!("fence r, r", options(nostack, preserves_flags)) }
    }

    /// Orders all earlier memory and MMIO accesses before all later ones
    /// (for example, a ring update before the doorbell write).
    #[inline]
    pub fn mb() {
        // SAFETY: a barrier has no other effect.
        unsafe { asm!("fence iorw, iorw", options(nostack, preserves_flags)) }
    }
}

#[cfg(all(bare, target_arch = "x86_64"))]
mod imp {
    use core::sync::atomic::{Ordering, compiler_fence, fence};

    /// Orders earlier stores to DMA memory before later stores to DMA memory.
    /// x86 keeps stores to write-back memory in order already.
    #[inline]
    pub fn dma_wmb() {
        compiler_fence(Ordering::Release);
    }

    /// Orders earlier loads from DMA memory before later loads.
    #[inline]
    pub fn dma_rmb() {
        compiler_fence(Ordering::Acquire);
    }

    /// Orders all earlier memory and MMIO accesses before all later ones
    /// (for example, a ring update before the doorbell write).
    #[inline]
    pub fn mb() {
        fence(Ordering::SeqCst);
    }
}

#[cfg(not(bare))]
mod imp {
    use core::sync::atomic::{Ordering, fence};

    /// Orders earlier stores to DMA memory before later stores to DMA memory.
    #[inline]
    pub fn dma_wmb() {
        fence(Ordering::Release);
    }

    /// Orders earlier loads from DMA memory before later loads.
    #[inline]
    pub fn dma_rmb() {
        fence(Ordering::Acquire);
    }

    /// Orders all earlier memory and MMIO accesses before all later ones.
    #[inline]
    pub fn mb() {
        fence(Ordering::SeqCst);
    }
}
