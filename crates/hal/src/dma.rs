//! DMA buffers.

use core::ptr::NonNull;

use osmium_mm::PhysAddr;

/// A buffer visible to both the CPU and a device.
///
/// The CPU and the device may access the memory concurrently, so the buffer
/// offers only volatile, copying accessors rather than slices.
#[derive(Debug)]
pub struct DmaBuffer {
    cpu: NonNull<u8>,
    device: PhysAddr,
    len: usize,
}

// SAFETY: the buffer is exclusively owned memory; all access is volatile.
unsafe impl Send for DmaBuffer {}

impl DmaBuffer {
    /// Describes `len` bytes at CPU pointer `cpu` and device address `device`.
    ///
    /// # Safety
    /// The memory must be exclusively owned by the buffer, valid for `len`
    /// bytes, and appear at `device` in the device's address space
    /// (accounting for any IOMMU or bus offset).
    pub const unsafe fn new(cpu: NonNull<u8>, device: PhysAddr, len: usize) -> Self {
        Self { cpu, device, len }
    }

    /// Address to program into the device.
    pub fn device_addr(&self) -> PhysAddr {
        self.device
    }

    /// CPU pointer, for code that needs to build structures in place.
    pub fn cpu_ptr(&self) -> NonNull<u8> {
        self.cpu
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copies `src` into the buffer at `offset`. Panics if out of bounds.
    pub fn write(&self, offset: usize, src: &[u8]) {
        assert!(offset.checked_add(src.len()).is_some_and(|e| e <= self.len));
        for (i, &b) in src.iter().enumerate() {
            // SAFETY: in bounds (checked above).
            unsafe { self.cpu.as_ptr().add(offset + i).write_volatile(b) };
        }
    }

    /// Copies from the buffer at `offset` into `dst`. Panics if out of bounds.
    pub fn read(&self, offset: usize, dst: &mut [u8]) {
        assert!(offset.checked_add(dst.len()).is_some_and(|e| e <= self.len));
        for (i, b) in dst.iter_mut().enumerate() {
            // SAFETY: in bounds (checked above).
            *b = unsafe { self.cpu.as_ptr().add(offset + i).read_volatile() };
        }
    }
}

/// Allocates DMA-capable memory.
pub trait DmaAllocator {
    /// Allocates a zeroed, cache-coherent buffer of at least `len` bytes.
    fn alloc_coherent(&self, len: usize) -> Option<DmaBuffer>;

    /// Frees a buffer from `alloc_coherent`.
    fn free_coherent(&self, buf: DmaBuffer);
}
