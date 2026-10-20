//! DMA buffers.

use core::mem::ManuallyDrop;
use core::ops::Deref;
use core::ptr::NonNull;

use osmium_mm::frame::order_for;
use osmium_mm::{FrameAllocator, LockedFrames, PhysAddr, PhysMapper};

use crate::mmio::RegValue;

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

    fn typed<T: RegValue>(&self, offset: usize) -> *mut T {
        let size = core::mem::size_of::<T>();
        assert!(offset.checked_add(size).is_some_and(|e| e <= self.len), "DMA access out of bounds");
        let p = self.cpu.as_ptr().wrapping_add(offset);
        assert!((p as usize).is_multiple_of(size), "misaligned DMA access");
        p.cast()
    }

    /// Volatile load of the little-endian integer at `offset`, which must be
    /// in bounds and naturally aligned (else this panics).
    #[inline]
    pub fn load<T: RegValue>(&self, offset: usize) -> T {
        // SAFETY: in bounds and aligned (checked).
        unsafe { self.typed::<T>(offset).read_volatile() }
    }

    /// Volatile store of an integer at `offset`, under the same conditions
    /// as [`load`](Self::load).
    #[inline]
    pub fn store<T: RegValue>(&self, offset: usize, value: T) {
        // SAFETY: in bounds and aligned (checked).
        unsafe { self.typed::<T>(offset).write_volatile(value) }
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

/// A [`DmaBuffer`] that returns itself to its allocator when dropped.
///
/// Drivers hold their rings and buffers this way so that every exit path,
/// including a failed initialization, frees them. A driver must stop the
/// device (reset it) before its `OwnedDma` fields drop.
pub struct OwnedDma<'a, A: DmaAllocator + ?Sized> {
    buf: ManuallyDrop<DmaBuffer>,
    alloc: &'a A,
}

impl<'a, A: DmaAllocator + ?Sized> OwnedDma<'a, A> {
    /// Allocates a zeroed, coherent buffer of `len` bytes from `alloc`.
    pub fn new(alloc: &'a A, len: usize) -> Option<Self> {
        alloc.alloc_coherent(len).map(|buf| Self { buf: ManuallyDrop::new(buf), alloc })
    }
}

impl<A: DmaAllocator + ?Sized> Deref for OwnedDma<'_, A> {
    type Target = DmaBuffer;

    fn deref(&self) -> &DmaBuffer {
        &self.buf
    }
}

impl<A: DmaAllocator + ?Sized> Drop for OwnedDma<'_, A> {
    fn drop(&mut self) {
        // SAFETY: `buf` is not used again.
        self.alloc.free_coherent(unsafe { ManuallyDrop::take(&mut self.buf) });
    }
}

impl<A: DmaAllocator + ?Sized> core::fmt::Debug for OwnedDma<'_, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&*self.buf, f)
    }
}

/// DMA memory straight from a frame allocator, for systems where devices
/// see physical addresses unchanged (no IOMMU or bus offset) and DMA is
/// cache-coherent: QEMU's `virt` machines and PCs, among others.
impl<A: FrameAllocator, M: PhysMapper> DmaAllocator for LockedFrames<A, M> {
    fn alloc_coherent(&self, len: usize) -> Option<DmaBuffer> {
        let order = order_for(len.max(1));
        let pa = self.lock().alloc(order)?;
        let Some(cpu) = NonNull::new(self.phys_to_virt(pa)) else {
            // SAFETY: just allocated with this order, and unused.
            unsafe { self.lock().dealloc(pa, order) };
            return None;
        };
        // SAFETY: freshly allocated frames, at least `len` bytes, mapped at
        // `cpu`; devices see them at `pa` per this impl's stated conditions.
        let buf = unsafe { DmaBuffer::new(cpu, pa, len) };
        // SAFETY: the frames are ours and at least `len` bytes long.
        unsafe { core::ptr::write_bytes(cpu.as_ptr(), 0, len) };
        Some(buf)
    }

    fn free_coherent(&self, buf: DmaBuffer) {
        let order = order_for(buf.len().max(1));
        // SAFETY: allocated by `alloc_coherent` with the same order.
        unsafe { self.lock().dealloc(buf.device_addr(), order) };
    }
}
