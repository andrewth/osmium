//! I/O memory management units.
//!
//! An IOMMU translates and filters the addresses that devices put on the bus,
//! so a device can reach only the memory its owner mapped for it. The four
//! hardware families differ in their registers and in-memory tables, but
//! share a model that this module captures:
//!
//! - a device ([`DeviceId`]) is attached to a protection domain
//!   ([`DomainId`]);
//! - the domain's translation is a page table in the IOMMU's own format
//!   ([`Iommu::Format`]) mapping I/O virtual addresses (IOVAs) to physical
//!   addresses;
//! - after changing the table the IOTLB is invalidated ([`Iommu::invalidate`]).
//!
//! The drivers (in `osmium-sysdrv`) implement [`Iommu`] for AMD-Vi, Intel
//! VT-d, Arm SMMUv3 and the RISC-V IOMMU. [`IoDomain`] owns a table and keeps
//! it consistent with the hardware, and [`IommuDma`] is a [`DmaAllocator`]
//! whose buffers are visible to a device only at an IOVA, which is what a
//! driver programs into its device in place of a physical address.
//!
//! Page-table memory is assumed to be read coherently by the IOMMU; drivers
//! refuse hardware that reports otherwise.

use core::mem::ManuallyDrop;
use core::ops::Range;

use osmium_mm::paging::{MapError, MapFlags, PageSize, PageTable, PageTableFormat, TableAlloc, UnmapError};
use osmium_mm::{PAGE_SIZE, PhysAddr, VirtAddr};
use osmium_sync::IrqSpinLock;

use crate::dma::{DmaAllocator, DmaBuffer};
use crate::pci::Address;

/// A PCI function as an IOMMU sees it: segment and bus/device/function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(u32);

impl DeviceId {
    /// Function `addr` in PCI segment `segment`.
    pub const fn new(segment: u16, addr: Address) -> Self {
        Self((segment as u32) << 16 | (addr.bus as u32) << 8 | (addr.device as u32) << 3 | addr.function as u32)
    }

    /// The 16-bit requester ID (bus, device, function).
    pub const fn bdf(self) -> u16 {
        self.0 as u16
    }

    /// The PCI segment (domain) number.
    pub const fn segment(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// The bus number.
    pub const fn bus(self) -> u8 {
        (self.0 >> 8) as u8
    }
}

/// A protection domain: devices attached to the same domain share one
/// translation and IOTLB tag. Zero is a valid number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(pub u16);

/// Why an IOMMU operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IommuError {
    /// The register window is too small or nothing answers in it.
    BadRegisters,
    /// The hardware lacks something the driver needs (a table format,
    /// coherent table walks, a large enough device ID space).
    Unsupported,
    /// The hardware did not acknowledge a command in time.
    Timeout,
    /// The hardware rejected a command or reported an internal error.
    Hardware,
    /// The device is outside what the IOMMU covers.
    InvalidDevice,
    /// An address does not fit the IOMMU's input range.
    OutOfRange,
    /// No memory for a table, or no free IOVA space.
    OutOfMemory,
    /// The device is attached already, or the domain's table is.
    Busy,
    /// The device is not attached.
    NotAttached,
    /// A page-table mapping failed.
    Map(MapError),
    /// A page-table unmapping failed.
    Unmap(UnmapError),
}

impl From<MapError> for IommuError {
    fn from(e: MapError) -> Self {
        match e {
            MapError::OutOfMemory => Self::OutOfMemory,
            MapError::InvalidAddress => Self::OutOfRange,
            e => Self::Map(e),
        }
    }
}

impl From<UnmapError> for IommuError {
    fn from(e: UnmapError) -> Self {
        match e {
            UnmapError::InvalidAddress => Self::OutOfRange,
            e => Self::Unmap(e),
        }
    }
}

/// A blocked DMA access, as the hardware logged it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault {
    /// The device that made the access.
    pub device: DeviceId,
    /// The I/O virtual address it used.
    pub iova: u64,
    /// True for a write, false for a read (or when the hardware did not say).
    pub write: bool,
    /// The hardware's own code for the reason (an AMD-Vi event type, a VT-d
    /// fault reason, an SMMUv3 event ID, a RISC-V IOMMU cause).
    pub reason: u32,
}

/// An IOMMU unit.
pub trait Iommu: Sync {
    /// The page-table format this IOMMU walks.
    type Format: PageTableFormat;

    /// Exclusive upper bound of the IOVAs it translates.
    fn iova_limit(&self) -> u64;

    /// Routes `device`'s DMA through the table at `root`, in `domain`.
    ///
    /// # Safety
    /// `root` must be the root of a table in [`Self::Format`] that stays
    /// allocated, and is changed only by whole-entry stores, until the device
    /// is detached. Otherwise the device reads page-table memory that has
    /// been reused. Use [`IoDomain`], which keeps this promise.
    unsafe fn attach(&self, device: DeviceId, domain: DomainId, root: PhysAddr) -> Result<(), IommuError>;

    /// Blocks all of `device`'s DMA and drops the IOMMU's cached state for
    /// it. On success nothing the device does refers to its old table.
    fn detach(&self, device: DeviceId) -> Result<(), IommuError>;

    /// Invalidates every cached translation of `domain`. Returns once the
    /// hardware has finished.
    fn invalidate(&self, domain: DomainId) -> Result<(), IommuError>;

    /// Removes and returns the oldest logged fault, if any. Hardware logs are
    /// finite: poll this regularly or later faults are dropped.
    fn take_fault(&self) -> Option<Fault>;
}

/// The most devices one [`IoDomain`] tracks.
pub const MAX_DOMAIN_DEVICES: usize = 8;

/// A protection domain: a page table plus the devices attached to it.
///
/// Dropping the domain detaches its devices first. If one will not detach,
/// the table is leaked rather than freed under a device that may still read
/// it.
pub struct IoDomain<'iommu, I: Iommu, A: TableAlloc> {
    iommu: &'iommu I,
    id: DomainId,
    table: ManuallyDrop<PageTable<I::Format, A>>,
    attached: [Option<DeviceId>; MAX_DOMAIN_DEVICES],
}

impl<'iommu, I: Iommu, A: TableAlloc> IoDomain<'iommu, I, A> {
    /// Creates an empty domain numbered `id`, with table pages from `alloc`.
    pub fn new(iommu: &'iommu I, id: DomainId, alloc: A) -> Result<Self, IommuError> {
        let table = PageTable::new(alloc)?;
        Ok(Self { iommu, id, table: ManuallyDrop::new(table), attached: [None; MAX_DOMAIN_DEVICES] })
    }

    /// The domain's number.
    pub fn id(&self) -> DomainId {
        self.id
    }

    /// Lets `device` use this domain's mappings.
    pub fn attach(&mut self, device: DeviceId) -> Result<(), IommuError> {
        if self.attached.contains(&Some(device)) {
            return Err(IommuError::Busy);
        }
        let slot = self.attached.iter_mut().find(|s| s.is_none()).ok_or(IommuError::OutOfMemory)?;
        // SAFETY: the table lives as long as the domain, which detaches the
        // device before freeing it, and changes entries only by whole stores.
        unsafe { self.iommu.attach(device, self.id, self.table.root())? };
        *slot = Some(device);
        Ok(())
    }

    /// Blocks `device`'s DMA.
    pub fn detach(&mut self, device: DeviceId) -> Result<(), IommuError> {
        let slot = self.attached.iter_mut().find(|d| **d == Some(device)).ok_or(IommuError::NotAttached)?;
        self.iommu.detach(device)?;
        *slot = None;
        Ok(())
    }

    /// Maps `len` bytes (a page multiple) at IOVA `iova` to physical `pa`,
    /// page by page, then flushes the IOTLB. On failure nothing stays mapped.
    pub fn map(&mut self, iova: u64, pa: PhysAddr, len: u64, flags: MapFlags) -> Result<(), IommuError> {
        iova.checked_add(len).filter(|&e| e <= self.iommu.iova_limit()).ok_or(IommuError::OutOfRange)?;
        let page = PAGE_SIZE as u64;
        if !len.is_multiple_of(page) {
            return Err(MapError::Misaligned.into());
        }
        let mut done = 0;
        let result = loop {
            if done == len {
                break Ok(());
            }
            let step = self.table.map(VirtAddr::new(iova + done), pa + done, PageSize::Size4K, flags);
            match step {
                Ok(flush) => flush.ignore(),
                Err(e) => break Err(IommuError::from(e)),
            }
            done += page;
        };
        if result.is_err() {
            for off in (0..done).step_by(PAGE_SIZE) {
                if let Ok((_, flush)) = self.table.unmap(VirtAddr::new(iova + off)) {
                    flush.ignore();
                }
            }
        }
        // A device may have cached "not present" for these pages.
        self.iommu.invalidate(self.id)?;
        result
    }

    /// Unmaps `len` bytes (a page multiple) at `iova` and flushes the IOTLB.
    /// Pages that are not mapped are skipped.
    pub fn unmap(&mut self, iova: u64, len: u64) -> Result<(), IommuError> {
        if !len.is_multiple_of(PAGE_SIZE as u64) || iova.checked_add(len).is_none_or(|e| e > self.iommu.iova_limit()) {
            return Err(IommuError::OutOfRange);
        }
        for off in (0..len).step_by(PAGE_SIZE) {
            if let Ok((_, flush)) = self.table.unmap(VirtAddr::new(iova + off)) {
                flush.ignore();
            }
        }
        self.iommu.invalidate(self.id)
    }

    /// The physical address `iova` translates to.
    pub fn translate(&self, iova: u64) -> Option<PhysAddr> {
        self.table.translate(VirtAddr::new(iova)).map(|t| t.pa)
    }
}

impl<I: Iommu, A: TableAlloc> Drop for IoDomain<'_, I, A> {
    fn drop(&mut self) {
        let mut clean = true;
        for device in self.attached.iter_mut().filter_map(Option::take) {
            clean &= self.iommu.detach(device).is_ok();
        }
        if clean {
            // SAFETY: not used again, and no device refers to the table.
            unsafe { ManuallyDrop::drop(&mut self.table) };
        }
    }
}

/// Maximum free extents an [`IovaAllocator`] remembers.
const FREE_EXTENTS: usize = 32;

/// A first-fit allocator of page-granular IOVA ranges.
///
/// It remembers at most 32 free extents, coalescing neighbours as they are
/// returned. If fragmentation exceeds that, the smallest piece is forgotten
/// (its IOVAs are lost, which wastes address space but is always safe).
#[derive(Debug)]
pub struct IovaAllocator {
    /// Free `[start, end)` extents, sorted, non-adjacent; `len` are used.
    free: [(u64, u64); FREE_EXTENTS],
    len: usize,
}

impl IovaAllocator {
    /// An allocator over `window`, trimmed to whole pages.
    pub fn new(window: Range<u64>) -> Self {
        let page = PAGE_SIZE as u64;
        // Round inwards to whole pages (a no-op for aligned windows).
        let window = window.start.checked_next_multiple_of(page).unwrap_or(u64::MAX)..window.end / page * page;
        let mut free = [(0, 0); FREE_EXTENTS];
        let len = usize::from(window.start < window.end);
        free[0] = (window.start, window.end);
        Self { free, len }
    }

    /// The used extents.
    fn live(&self) -> &[(u64, u64)] {
        self.free.get(..self.len).unwrap_or(&self.free)
    }

    /// Drops extent `i`, shifting the later ones down.
    fn remove(&mut self, i: usize) {
        if i < self.len {
            self.free.copy_within(i + 1..self.len, i);
            self.len -= 1;
        }
    }

    /// Allocates `pages` contiguous pages, returning the first IOVA.
    pub fn alloc(&mut self, pages: usize) -> Option<u64> {
        let bytes = (pages as u64).checked_mul(PAGE_SIZE as u64).filter(|&b| b != 0)?;
        let i = self.live().iter().position(|&(s, e)| e.saturating_sub(s) >= bytes)?;
        let (start, end) = *self.free.get(i)?;
        let next = start.checked_add(bytes)?;
        if next == end {
            self.remove(i);
        } else {
            self.free.get_mut(i)?.0 = next;
        }
        Some(start)
    }

    /// Returns `pages` pages at `iova`, from [`alloc`](Self::alloc).
    pub fn free(&mut self, iova: u64, pages: usize) {
        let end = (pages as u64).saturating_mul(PAGE_SIZE as u64).saturating_add(iova);
        let i = self.live().partition_point(|&(s, _)| s < iova);
        let prev = i.checked_sub(1).filter(|&p| self.free.get(p).is_some_and(|e| e.1 == iova));
        let next = Some(i).filter(|&n| n < self.len && self.free.get(n).is_some_and(|e| e.0 == end));
        match (prev, next) {
            (Some(p), Some(n)) => {
                let after = self.free.get(n).map_or(end, |e| e.1);
                if let Some(e) = self.free.get_mut(p) {
                    e.1 = after;
                }
                self.remove(n);
            }
            (Some(p), None) => {
                if let Some(e) = self.free.get_mut(p) {
                    e.1 = end;
                }
            }
            (None, Some(n)) => {
                if let Some(e) = self.free.get_mut(n) {
                    e.0 = iova;
                }
            }
            (None, None) => {
                if self.len == FREE_EXTENTS {
                    // Forget the smallest extent, or this one if it is.
                    let Some((small, size)) = self
                        .free
                        .iter()
                        .enumerate()
                        .map(|(j, &(s, e))| (j, e.saturating_sub(s)))
                        .min_by_key(|&(_, n)| n)
                    else {
                        return;
                    };
                    if size >= end.saturating_sub(iova) {
                        return;
                    }
                    self.remove(small);
                    return self.free(iova, pages);
                }
                if i < self.len {
                    self.free.copy_within(i..self.len, i + 1);
                }
                if let Some(e) = self.free.get_mut(i) {
                    *e = (iova, end);
                    self.len += 1;
                }
            }
        }
    }
}

struct DmaState<'iommu, I: Iommu, A: TableAlloc> {
    domain: IoDomain<'iommu, I, A>,
    iovas: IovaAllocator,
}

/// A [`DmaAllocator`] whose buffers a device reaches only through an IOMMU.
///
/// Memory comes from `backing` (which hands out physical addresses); each
/// buffer is mapped read-write at a fresh IOVA in the window, and
/// [`DmaBuffer::device_addr`] is that IOVA. Devices attached to the domain
/// can touch these buffers and nothing else. Freeing unmaps the buffer and
/// flushes the IOTLB before the memory returns to `backing`.
pub struct IommuDma<'iommu, I: Iommu, A: TableAlloc, B: DmaAllocator> {
    state: IrqSpinLock<DmaState<'iommu, I, A>>,
    backing: &'iommu B,
}

impl<'iommu, I: Iommu, A: TableAlloc, B: DmaAllocator> IommuDma<'iommu, I, A, B> {
    /// Allocates buffers from `backing` into `domain`, at IOVAs in `window`.
    ///
    /// Choose a window below [`Iommu::iova_limit`] that avoids the platform's
    /// reserved ranges (x86 reserves `0xfee0_0000..0xfef0_0000` for MSIs) and
    /// the first page. Returns [`IommuError::OutOfRange`] if the window is
    /// above the limit or not page-aligned.
    pub fn new(domain: IoDomain<'iommu, I, A>, backing: &'iommu B, window: Range<u64>) -> Result<Self, IommuError> {
        let page = PAGE_SIZE as u64;
        if window.end > domain.iommu.iova_limit()
            || !window.start.is_multiple_of(page)
            || !window.end.is_multiple_of(page)
        {
            return Err(IommuError::OutOfRange);
        }
        let iovas = IovaAllocator::new(window);
        Ok(Self { state: IrqSpinLock::new(DmaState { domain, iovas }), backing })
    }

    /// Runs `f` on the domain, to attach devices or inspect mappings.
    pub fn with_domain<R>(&self, f: impl FnOnce(&mut IoDomain<'iommu, I, A>) -> R) -> R {
        f(&mut self.state.lock().domain)
    }
}

impl<I: Iommu, A: TableAlloc, B: DmaAllocator> DmaAllocator for IommuDma<'_, I, A, B> {
    fn alloc_coherent(&self, len: usize) -> Option<DmaBuffer> {
        let buf = self.backing.alloc_coherent(len)?;
        let bytes = len.max(1).next_multiple_of(PAGE_SIZE);
        let pages = bytes / PAGE_SIZE;
        let mut st = self.state.lock();
        let mapped = st.iovas.alloc(pages).and_then(|iova| {
            match st.domain.map(iova, buf.device_addr(), bytes as u64, MapFlags::RW) {
                Ok(()) => Some(iova),
                Err(_) => {
                    st.iovas.free(iova, pages);
                    None
                }
            }
        });
        drop(st);
        let Some(iova) = mapped else {
            // SAFETY: from `backing`, and no device ever saw it.
            unsafe { self.backing.free_coherent(buf) };
            return None;
        };
        // SAFETY: same memory as `buf`, which we consume; the device sees it
        // at `iova` through the mapping just made.
        Some(unsafe { DmaBuffer::new(buf.cpu_ptr(), PhysAddr::new(iova), len) })
    }

    unsafe fn free_coherent(&self, buf: DmaBuffer) {
        let iova = buf.device_addr().as_u64();
        let bytes = buf.len().max(1).next_multiple_of(PAGE_SIZE);
        let mut st = self.state.lock();
        // A buffer we did not map has nothing to release.
        let Some(pa) = st.domain.translate(iova) else { return };
        // A failed flush means a device might still reach the memory: keep
        // the IOVA and the memory out of circulation instead of reusing them.
        let flushed = st.domain.unmap(iova, bytes as u64).is_ok();
        if flushed {
            st.iovas.free(iova, bytes / PAGE_SIZE);
        }
        drop(st);
        if flushed {
            let cpu = buf.cpu_ptr();
            // SAFETY: the original buffer's memory, no longer reachable by
            // any device now the mapping is gone and the IOTLB flushed.
            unsafe { self.backing.free_coherent(DmaBuffer::new(cpu, pa, buf.len())) };
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::cell::Cell;
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::vec::Vec;

    use osmium_mm::PhysMapper;
    use osmium_mm::paging::formats::Ept;

    use super::*;
    use core::ptr::NonNull;

    /// Page-table memory from the host heap; physical = host address.
    #[derive(Default)]
    struct HostTables {
        live: Cell<usize>,
    }

    // SAFETY: identity mapping of host heap memory.
    unsafe impl PhysMapper for HostTables {
        fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
            pa.as_u64() as *mut u8
        }
    }

    // SAFETY: page-aligned zeroed heap blocks, mapped by identity.
    unsafe impl TableAlloc for HostTables {
        fn alloc_table(&self) -> Option<PhysAddr> {
            self.live.set(self.live.get() + 1);
            // SAFETY: non-zero size.
            Some(PhysAddr::new(unsafe { alloc_zeroed(Layout::from_size_align(4096, 4096).ok()?) } as u64))
        }
        unsafe fn free_table(&self, pa: PhysAddr) {
            self.live.set(self.live.get() - 1);
            // SAFETY: from `alloc_table`.
            unsafe { dealloc(pa.as_u64() as *mut u8, Layout::from_size_align(4096, 4096).unwrap()) }
        }
    }

    #[derive(Default)]
    struct HostDma {
        live: Cell<usize>,
    }

    impl DmaAllocator for HostDma {
        fn alloc_coherent(&self, len: usize) -> Option<DmaBuffer> {
            let layout = Layout::from_size_align(len.max(1).next_multiple_of(4096), 4096).ok()?;
            // SAFETY: non-zero size.
            let p = NonNull::new(unsafe { alloc_zeroed(layout) })?;
            self.live.set(self.live.get() + 1);
            // SAFETY: fresh memory, identity "physical" address.
            Some(unsafe { DmaBuffer::new(p, PhysAddr::new(p.as_ptr() as u64), len) })
        }
        unsafe fn free_coherent(&self, buf: DmaBuffer) {
            self.live.set(self.live.get() - 1);
            let layout = Layout::from_size_align(buf.len().max(1).next_multiple_of(4096), 4096).unwrap();
            // SAFETY: allocated above.
            unsafe { dealloc(buf.cpu_ptr().as_ptr(), layout) }
        }
    }

    #[derive(Default)]
    struct FakeIommu {
        events: std::sync::Mutex<Vec<std::string::String>>,
        fail_detach: bool,
    }

    impl Iommu for FakeIommu {
        type Format = Ept;
        fn iova_limit(&self) -> u64 {
            1 << 32
        }
        unsafe fn attach(&self, device: DeviceId, domain: DomainId, _root: PhysAddr) -> Result<(), IommuError> {
            self.events.lock().unwrap().push(std::format!("attach {:#x} {}", device.bdf(), domain.0));
            Ok(())
        }
        fn detach(&self, device: DeviceId) -> Result<(), IommuError> {
            self.events.lock().unwrap().push(std::format!("detach {:#x}", device.bdf()));
            if self.fail_detach { Err(IommuError::Timeout) } else { Ok(()) }
        }
        fn take_fault(&self) -> Option<Fault> {
            None
        }
        fn invalidate(&self, domain: DomainId) -> Result<(), IommuError> {
            self.events.lock().unwrap().push(std::format!("invalidate {}", domain.0));
            Ok(())
        }
    }

    const NIC: DeviceId = DeviceId::new(0, Address::new(0, 3, 1));

    #[test]
    fn device_id_fields() {
        let id = DeviceId::new(2, Address::new(0x12, 0x1f, 7));
        assert_eq!((id.segment(), id.bus(), id.bdf()), (2, 0x12, 0x12ff));
    }

    #[test]
    fn iova_allocator_coalesces() {
        let mut a = IovaAllocator::new(0x10000..0x20000);
        let x = a.alloc(4).unwrap();
        let y = a.alloc(4).unwrap();
        let z = a.alloc(8).unwrap();
        assert_eq!((x, y, z), (0x10000, 0x14000, 0x18000));
        assert_eq!(a.alloc(1), None, "window exhausted");
        a.free(y, 4);
        a.free(x, 4);
        assert_eq!(a.len, 1, "x and y coalesced");
        a.free(z, 8);
        assert_eq!((a.len, a.free[0]), (1, (0x10000, 0x20000)));
        assert_eq!(a.alloc(16), Some(0x10000));
    }

    #[test]
    fn iova_allocator_fragmentation_never_overlaps() {
        let mut a = IovaAllocator::new(0x1000..0x1000 + 200 * 4096);
        let all: Vec<u64> = (0..200).map(|_| a.alloc(1).unwrap()).collect();
        // Free every other page: 100 extents, far above the 32 remembered.
        for &p in all.iter().step_by(2) {
            a.free(p, 1);
        }
        let mut got = Vec::new();
        while let Some(p) = a.alloc(1) {
            assert!(all.iter().step_by(2).any(|&f| f == p), "only freed pages come back");
            assert!(!got.contains(&p));
            got.push(p);
        }
        assert!(!got.is_empty() && got.len() <= 100);
    }

    #[test]
    fn domain_maps_and_unmaps() {
        let (iommu, tables) = (FakeIommu::default(), HostTables::default());
        {
            let mut d = IoDomain::new(&iommu, DomainId(5), &tables).unwrap();
            d.attach(NIC).unwrap();
            assert_eq!(d.attach(NIC), Err(IommuError::Busy));
            d.map(0x10_0000, PhysAddr::new(0x7000_0000), 0x3000, MapFlags::RW).unwrap();
            assert_eq!(d.translate(0x10_1008), Some(PhysAddr::new(0x7000_1008)));
            assert_eq!(
                d.map(0x10_2000, PhysAddr::new(0x9000), 0x2000, MapFlags::RW),
                Err(MapError::AlreadyMapped.into())
            );
            assert!(d.translate(0x10_3000).is_none(), "failed map leaves nothing behind");
            assert!(d.translate(0x10_2000).is_some(), "earlier mapping untouched");
            assert_eq!(d.map(1 << 32, PhysAddr::new(0), 0x1000, MapFlags::RW), Err(IommuError::OutOfRange));
            d.unmap(0x10_0000, 0x3000).unwrap();
            assert!(d.translate(0x10_0000).is_none());
            d.detach(NIC).unwrap();
            assert_eq!(d.detach(NIC), Err(IommuError::NotAttached));
        }
        assert_eq!(tables.live.get(), 0, "tables freed");
        let ev = iommu.events.lock().unwrap();
        assert_eq!(ev[0], "attach 0x19 5");
        assert!(ev.iter().filter(|e| *e == "invalidate 5").count() >= 3);
    }

    #[test]
    fn drop_detaches_and_leaks_on_failure() {
        let tables = HostTables::default();
        let iommu = FakeIommu::default();
        let mut d = IoDomain::new(&iommu, DomainId(1), &tables).unwrap();
        d.attach(NIC).unwrap();
        drop(d);
        assert!(iommu.events.lock().unwrap().contains(&"detach 0x19".into()));
        assert_eq!(tables.live.get(), 0);

        let stuck = FakeIommu { fail_detach: true, ..Default::default() };
        let mut d = IoDomain::new(&stuck, DomainId(1), &tables).unwrap();
        d.map(0x1000, PhysAddr::new(0x2000), 0x1000, MapFlags::RW).unwrap();
        d.attach(NIC).unwrap();
        drop(d);
        assert_ne!(tables.live.get(), 0, "tables kept: the device may still walk them");
    }

    #[test]
    fn dma_window_must_be_page_aligned() {
        let (iommu, tables, backing) = (FakeIommu::default(), HostTables::default(), HostDma::default());
        let domain = IoDomain::new(&iommu, DomainId(2), &tables).unwrap();
        assert_eq!(IommuDma::new(domain, &backing, 0x10_0010..0x20_0000).err(), Some(IommuError::OutOfRange));
    }

    #[test]
    fn dma_allocator_hands_out_iovas() {
        let (iommu, tables, backing) = (FakeIommu::default(), HostTables::default(), HostDma::default());
        let dma = {
            let domain = IoDomain::new(&iommu, DomainId(2), &tables).unwrap();
            IommuDma::new(domain, &backing, 0x10_0000..0x20_0000).unwrap()
        };
        dma.with_domain(|d| d.attach(NIC)).unwrap();
        let a = dma.alloc_coherent(100).unwrap();
        let b = dma.alloc_coherent(5000).unwrap();
        assert_eq!(a.device_addr().as_u64(), 0x10_0000);
        assert_eq!(b.device_addr().as_u64(), 0x10_1000);
        a.store::<u32>(0, 0xfeed);
        let pa = dma.with_domain(|d| d.translate(a.device_addr().as_u64())).unwrap();
        // The IOVA is not the physical address, and translates to the memory.
        assert_ne!(pa, a.device_addr());
        // SAFETY: identity "physical" address of a live host allocation.
        assert_eq!(unsafe { (pa.as_u64() as *const u32).read() }, 0xfeed);
        assert_eq!(b.len(), 5000);
        // SAFETY: from this allocator; no device is running.
        unsafe { dma.free_coherent(a) };
        assert_eq!(backing.live.get(), 1);
        let c = dma.alloc_coherent(64).unwrap();
        assert_eq!(c.device_addr().as_u64(), 0x10_0000, "freed IOVA is reused");
        // SAFETY: as above.
        unsafe {
            dma.free_coherent(b);
            dma.free_coherent(c);
        }
        assert_eq!(backing.live.get(), 0);
        // Exhaustion fails cleanly without leaking backing memory.
        let big = dma.alloc_coherent(0x20_0000);
        assert!(big.is_none());
        assert_eq!(backing.live.get(), 0);
        dma.with_domain(|d| d.detach(NIC)).unwrap();
    }
}
