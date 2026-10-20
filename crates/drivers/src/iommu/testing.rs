//! Host-test support shared by the IOMMU drivers: heap-backed DMA and table
//! memory whose "physical" addresses are host addresses, register windows
//! over plain memory, and a thread that plays the hardware.

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use osmium_hal::dma::{DmaAllocator, DmaBuffer};
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;
use osmium_mm::paging::TableAlloc;
use osmium_mm::{PhysAddr, PhysMapper};

/// Page-aligned heap memory whose device address is its host address.
#[derive(Default)]
pub struct HostDma {
    pub live: AtomicUsize,
}

impl HostDma {
    pub fn live(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }
}

fn layout(len: usize) -> Layout {
    Layout::from_size_align(len.max(1).next_multiple_of(4096), 4096).unwrap()
}

impl DmaAllocator for HostDma {
    fn alloc_coherent(&self, len: usize) -> Option<DmaBuffer> {
        // SAFETY: non-zero size.
        let p = NonNull::new(unsafe { alloc_zeroed(layout(len)) })?;
        self.live.fetch_add(1, Ordering::SeqCst);
        // SAFETY: fresh, exclusively owned memory; identity "physical" address.
        Some(unsafe { DmaBuffer::new(p, PhysAddr::new(p.as_ptr() as u64), len) })
    }

    unsafe fn free_coherent(&self, buf: DmaBuffer) {
        self.live.fetch_sub(1, Ordering::SeqCst);
        // SAFETY: allocated above with this layout.
        unsafe { dealloc(buf.cpu_ptr().as_ptr(), layout(buf.len())) }
    }
}

/// Page-table pages from the host heap; physical = host address.
#[derive(Default)]
pub struct HostTables {
    pub live: AtomicUsize,
}

// SAFETY: identity mapping of host heap memory.
unsafe impl PhysMapper for HostTables {
    fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
        pa.as_u64() as *mut u8
    }
}

// SAFETY: zeroed, size-aligned heap blocks, mapped by identity.
unsafe impl TableAlloc for HostTables {
    fn alloc_table(&self) -> Option<PhysAddr> {
        self.alloc_root(1)
    }

    unsafe fn free_table(&self, pa: PhysAddr) {
        // SAFETY: forwarded contract.
        unsafe { self.free_root(pa, 1) }
    }

    fn alloc_root(&self, pages: usize) -> Option<PhysAddr> {
        let l = Layout::from_size_align(pages * 4096, pages * 4096).ok()?;
        // SAFETY: non-zero size.
        let p = unsafe { alloc_zeroed(l) };
        self.live.fetch_add(pages, Ordering::SeqCst);
        (!p.is_null()).then(|| PhysAddr::new(p as u64))
    }

    unsafe fn free_root(&self, pa: PhysAddr, pages: usize) {
        self.live.fetch_sub(pages, Ordering::SeqCst);
        // SAFETY: from `alloc_root` with the same page count.
        unsafe { dealloc(pa.as_u64() as *mut u8, Layout::from_size_align(pages * 4096, pages * 4096).unwrap()) }
    }
}

/// Real time.
pub struct StdClock(Instant);

impl Default for StdClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl Clock for StdClock {
    fn now_ns(&self) -> u64 {
        self.0.elapsed().as_nanos() as u64
    }
}

/// A zeroed block of "device registers" shared between the driver (through
/// an [`IoMem`]) and a fake-hardware thread.
#[derive(Clone)]
pub struct HostRegs {
    ptr: *mut u8,
    len: usize,
    _owner: Arc<RegsOwner>,
}

struct RegsOwner(*mut u8, usize);

impl Drop for RegsOwner {
    fn drop(&mut self) {
        // SAFETY: allocated in `HostRegs::new` with this layout.
        unsafe { dealloc(self.0, layout(self.1)) }
    }
}

// SAFETY: plain memory, accessed with volatile loads and stores.
unsafe impl Send for HostRegs {}
// SAFETY: as above.
unsafe impl Sync for HostRegs {}
// SAFETY: as above.
unsafe impl Send for RegsOwner {}
// SAFETY: as above.
unsafe impl Sync for RegsOwner {}

impl HostRegs {
    pub fn new(len: usize) -> Self {
        // SAFETY: non-zero size.
        let ptr = unsafe { alloc_zeroed(layout(len)) };
        assert!(!ptr.is_null());
        Self { ptr, len, _owner: Arc::new(RegsOwner(ptr, len)) }
    }

    pub fn io(&self) -> IoMem {
        // SAFETY: the block is owned by `self` (and clones) and is not Rust data
        // the driver could alias; it outlives the `IoMem` in every test.
        unsafe { IoMem::new(self.ptr, self.len) }
    }

    pub fn r32(&self, off: usize) -> u32 {
        assert!(off + 4 <= self.len);
        // SAFETY: in bounds, aligned by the callers' register offsets.
        unsafe { self.ptr.add(off).cast::<u32>().read_volatile() }
    }

    pub fn r64(&self, off: usize) -> u64 {
        assert!(off + 8 <= self.len);
        // SAFETY: as above.
        unsafe { self.ptr.add(off).cast::<u64>().read_volatile() }
    }

    pub fn w32(&self, off: usize, v: u32) {
        assert!(off + 4 <= self.len);
        // SAFETY: as above.
        unsafe { self.ptr.add(off).cast::<u32>().write_volatile(v) }
    }

    pub fn w64(&self, off: usize, v: u64) {
        assert!(off + 8 <= self.len);
        // SAFETY: as above.
        unsafe { self.ptr.add(off).cast::<u64>().write_volatile(v) }
    }
}

/// Reads host memory at a "physical" address from [`HostDma`] or
/// [`HostTables`].
pub fn mem64(pa: u64) -> u64 {
    // SAFETY: tests pass addresses inside live host allocations.
    unsafe { (pa as *const u64).read_volatile() }
}

/// Reads a 32-bit word of host memory at a "physical" address.
pub fn mem32(pa: u64) -> u32 {
    // SAFETY: as for `mem64`.
    unsafe { (pa as *const u32).read_volatile() }
}

/// Writes host memory at a "physical" address.
pub fn set_mem64(pa: u64, v: u64) {
    // SAFETY: as for `mem64`.
    unsafe { (pa as *mut u64).write_volatile(v) }
}

/// A thread that calls `step` in a loop, playing the hardware, until dropped.
pub struct Pump {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Pump {
    pub fn start(mut step: impl FnMut() + Send + 'static) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                step();
                std::thread::sleep(Duration::from_micros(20));
            }
        });
        Self { stop, thread: Some(thread) }
    }
}

impl Drop for Pump {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            // Propagate a panic in the fake (a spec violation it detected).
            if let Err(e) = t.join()
                && !std::thread::panicking()
            {
                std::panic::resume_unwind(e);
            }
        }
    }
}
