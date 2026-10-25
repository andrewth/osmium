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
//!
//! Large mappings: [`IoDomain::map`] uses 2 MiB and 1 GiB block entries when
//! the IOVA, the physical address and the remaining length are aligned to
//! them and the unit allows them ([`Iommu::max_leaf_size`]); [`IoDomain::unmap`]
//! splits a block when only part of it goes.
//!
//! Process address spaces and device TLBs: a unit that implements the
//! optional [`Iommu::bind_pasid`] lets a device use a domain's table for DMA
//! tagged with a [`Pasid`], and one that implements
//! [`Iommu::invalidate_device_tlb`] can tell an ATS-capable device to drop
//! cached translations, which [`IoDomain`] does whenever it unmaps for a
//! device it was told ([`IoDomain::enable_ats`]) has ATS on. The PCI side is
//! [`Function::ats`](crate::pci::Function::ats) and
//! [`Function::pasid`](crate::pci::Function::pasid).

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

/// A process address space ID: the tag a device puts on DMA to pick one of
/// several address spaces (PCIe PASID, SMMUv3 substream ID). At most 20 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pasid(u32);

impl Pasid {
    /// The largest PASID width PCIe defines.
    pub const MAX_BITS: u32 = 20;

    /// `value`, or `None` if it does not fit in 20 bits.
    pub const fn new(value: u32) -> Option<Self> {
        if value < 1 << Self::MAX_BITS { Some(Self(value)) } else { None }
    }

    /// The number.
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// The naturally aligned power-of-two span an ATS Invalidate Request must
/// use to cover `[iova, iova + len)`: its base and its size in pages as a
/// power of two (0 is one 4 KiB page). A zero `len` means the whole address
/// space. `None` if the range wraps.
pub fn ats_span(iova: u64, len: u64) -> Option<(u64, u32)> {
    if len == 0 {
        return Some((0, 52));
    }
    let last = iova.checked_add(len - 1)?;
    let (first_page, last_page) = (iova >> 12, last >> 12);
    let log2 = u64::BITS - (first_page ^ last_page).leading_zeros();
    // `log2` is below 52: page numbers have 52 bits.
    let base = first_page >> log2 << log2 << 12;
    Some((base, log2))
}

/// The address field of an ATS Invalidate Request (and of the IOMMU
/// descriptors that carry one) for a span from [`ats_span`], and whether the
/// "S" bit is set. A span of more than a page sets S and encodes its size in
/// the position of the lowest zero bit above bit 11: ones in bits
/// `12..12 + log2 - 1`.
pub fn ats_address(base: u64, log2_pages: u32) -> (u64, bool) {
    if log2_pages == 0 {
        return (base & !0xfff, false);
    }
    let ones = (1u64 << (11 + log2_pages).min(63)) - 1;
    ((base | ones) & !0xfff, true)
}

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

    /// The largest block entry the unit's walker accepts in its tables
    /// ([`PageSize::Size2M`] and [`PageSize::Size1G`] need hardware support,
    /// such as VT-d's `CAP.SLLPS`). The default is 4 KiB pages only.
    fn max_leaf_size(&self) -> PageSize {
        PageSize::Size4K
    }

    /// How many bits of [`Pasid`] the unit accepts; 0 (the default) if it
    /// does not do PASIDs, or this driver does not configure them.
    fn max_pasid_bits(&self) -> u32 {
        0
    }

    /// Makes DMA from `device` tagged `pasid` use the table at `root`, in
    /// `domain`. The device must be attached already. The default reports
    /// [`IommuError::Unsupported`].
    ///
    /// # Safety
    /// As for [`attach`](Self::attach): `root` stays allocated, and is changed
    /// only by whole-entry stores, until [`unbind_pasid`](Self::unbind_pasid)
    /// succeeds or the device is detached.
    unsafe fn bind_pasid(
        &self,
        _device: DeviceId,
        _pasid: Pasid,
        _domain: DomainId,
        _root: PhysAddr,
    ) -> Result<(), IommuError> {
        Err(IommuError::Unsupported)
    }

    /// Stops `device`'s DMA tagged `pasid` and drops the unit's cached state
    /// for it. The default reports [`IommuError::Unsupported`].
    fn unbind_pasid(&self, _device: DeviceId, _pasid: Pasid) -> Result<(), IommuError> {
        Err(IommuError::Unsupported)
    }

    /// True if the unit can answer a device's translation requests and
    /// invalidate the device's translation cache (ATS).
    fn supports_ats(&self) -> bool {
        false
    }

    /// Tells `device` to drop cached translations for `[iova, iova + len)`
    /// (the whole address space if `len` is 0), for `pasid` if given and
    /// otherwise for its untagged requests, and waits for it to confirm. See
    /// [`ats_span`] for how a range becomes a request. The default reports
    /// [`IommuError::Unsupported`].
    fn invalidate_device_tlb(
        &self,
        _device: DeviceId,
        _pasid: Option<Pasid>,
        _iova: u64,
        _len: u64,
    ) -> Result<(), IommuError> {
        Err(IommuError::Unsupported)
    }
}

/// The most devices one [`IoDomain`] tracks.
pub const MAX_DOMAIN_DEVICES: usize = 8;

/// The most (device, PASID) bindings one [`IoDomain`] tracks.
pub const MAX_DOMAIN_PASIDS: usize = 8;

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
    /// Devices with ATS on, whose caches an unmap must invalidate.
    ats: [Option<DeviceId>; MAX_DOMAIN_DEVICES],
    /// Devices using this table for tagged DMA.
    pasids: [Option<(DeviceId, Pasid)>; MAX_DOMAIN_PASIDS],
}

impl<'iommu, I: Iommu, A: TableAlloc> IoDomain<'iommu, I, A> {
    /// Creates an empty domain numbered `id`, with table pages from `alloc`.
    pub fn new(iommu: &'iommu I, id: DomainId, alloc: A) -> Result<Self, IommuError> {
        let table = PageTable::new(alloc)?;
        Ok(Self {
            iommu,
            id,
            table: ManuallyDrop::new(table),
            attached: [None; MAX_DOMAIN_DEVICES],
            ats: [None; MAX_DOMAIN_DEVICES],
            pasids: [None; MAX_DOMAIN_PASIDS],
        })
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

    /// Blocks `device`'s DMA. Turn ATS off first ([`disable_ats`](Self::disable_ats)):
    /// returns [`IommuError::Busy`] while the device has it on. PASIDs bound
    /// to the device are unbound.
    pub fn detach(&mut self, device: DeviceId) -> Result<(), IommuError> {
        let slot = self.attached.iter().position(|d| *d == Some(device)).ok_or(IommuError::NotAttached)?;
        if self.ats.contains(&Some(device)) {
            return Err(IommuError::Busy);
        }
        let bound: [Option<Pasid>; MAX_DOMAIN_PASIDS] = core::array::from_fn(|i| match self.pasids.get(i) {
            Some(Some((d, p))) if *d == device => Some(*p),
            _ => None,
        });
        for pasid in bound.into_iter().flatten() {
            self.unbind_pasid(device, pasid)?;
        }
        self.iommu.detach(device)?;
        if let Some(s) = self.attached.get_mut(slot) {
            *s = None;
        }
        Ok(())
    }

    /// The largest block entry this domain uses: what the unit accepts and
    /// the table format can hold.
    pub fn max_leaf_size(&self) -> PageSize {
        let format = <I::Format as PageTableFormat>::MAX_LEAF_LEVEL.min(<I::Format as PageTableFormat>::LEVELS - 1);
        let level = self.iommu.max_leaf_size().level().min(format);
        [PageSize::Size1G, PageSize::Size2M, PageSize::Size4K]
            .into_iter()
            .find(|s| s.level() <= level)
            .unwrap_or(PageSize::Size4K)
    }

    /// Maps `len` bytes (a page multiple) at IOVA `iova` to physical `pa`,
    /// then flushes the IOTLB. Uses 2 MiB and 1 GiB blocks wherever `iova`,
    /// `pa` and what remains are aligned to them and
    /// [`max_leaf_size`](Self::max_leaf_size) allows, else 4 KiB pages. On
    /// failure nothing stays mapped.
    pub fn map(&mut self, iova: u64, pa: PhysAddr, len: u64, flags: MapFlags) -> Result<(), IommuError> {
        iova.checked_add(len).filter(|&e| e <= self.iommu.iova_limit()).ok_or(IommuError::OutOfRange)?;
        pa.as_u64().checked_add(len).ok_or(IommuError::OutOfRange)?;
        let page = PAGE_SIZE as u64;
        if !len.is_multiple_of(page) {
            return Err(MapError::Misaligned.into());
        }
        let mut done = 0;
        let result = self.map_run(iova, pa, len, flags, &mut done);
        if result.is_err() {
            let mut off = 0;
            while off < done {
                off += match self.table.unmap(VirtAddr::new(iova + off)) {
                    Ok((t, flush)) => {
                        flush.ignore();
                        t.size.bytes()
                    }
                    Err(_) => page,
                };
            }
        }
        // A device may have cached "not present" for these pages.
        self.iommu.invalidate(self.id)?;
        result
    }

    /// Maps the range in the largest blocks that fit, counting bytes done.
    fn map_run(
        &mut self,
        iova: u64,
        pa: PhysAddr,
        len: u64,
        flags: MapFlags,
        done: &mut u64,
    ) -> Result<(), IommuError> {
        let max = self.max_leaf_size();
        while *done < len {
            // Cannot overflow: both sums were checked against `len` by the caller.
            let (v, p) = (iova + *done, pa + *done);
            let left = len - *done;
            let size = [PageSize::Size1G, PageSize::Size2M]
                .into_iter()
                .find(|s| {
                    s.level() <= max.level()
                        && v.is_multiple_of(s.bytes())
                        && p.is_aligned(s.bytes())
                        && left >= s.bytes()
                })
                .unwrap_or(PageSize::Size4K);
            let step = match self.table.map(VirtAddr::new(v), p, size, flags) {
                Ok(flush) => {
                    flush.ignore();
                    size
                }
                // Something is mapped inside the block's range: fill in around it.
                Err(MapError::AlreadyMapped | MapError::HugePageConflict) if size != PageSize::Size4K => {
                    self.table.map(VirtAddr::new(v), p, PageSize::Size4K, flags)?.ignore();
                    PageSize::Size4K
                }
                Err(e) => return Err(e.into()),
            };
            *done += step.bytes();
        }
        Ok(())
    }

    /// Unmaps `len` bytes (a page multiple) at `iova` and flushes the IOTLB
    /// and the caches of devices with ATS on. Pages that are not mapped are
    /// skipped. A block entry that the range covers only in part is split
    /// into smaller entries first, so the rest of it stays mapped (see
    /// [`PageTable::split_with`] for what that does to a live mapping: on
    /// Arm stage 2 the block is briefly absent, and DMA to it faults).
    pub fn unmap(&mut self, iova: u64, len: u64) -> Result<(), IommuError> {
        if !len.is_multiple_of(PAGE_SIZE as u64) || iova.checked_add(len).is_none_or(|e| e > self.iommu.iova_limit()) {
            return Err(IommuError::OutOfRange);
        }
        let page = PAGE_SIZE as u64;
        let mut off = 0;
        let mut result = Ok(());
        while off < len {
            let va = VirtAddr::new(iova + off);
            let Some(t) = self.table.translate(va) else {
                off += page;
                continue;
            };
            let block = t.size.bytes();
            let whole = (iova + off).is_multiple_of(block) && len - off >= block;
            if t.size != PageSize::Size4K && !whole {
                match self.split_block(va) {
                    Ok(()) => continue,
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
            }
            if let Ok((t, flush)) = self.table.unmap(va) {
                flush.ignore();
                off += t.size.bytes();
            } else {
                off += page;
            }
        }
        // Flush even after a failed split: the earlier unmaps happened.
        let flushed = self.iommu.invalidate(self.id).and_then(|()| self.invalidate_device_tlbs(iova, len));
        result.and(flushed)
    }

    /// Replaces the block entry mapping `va` with the next smaller size.
    fn split_block(&mut self, va: VirtAddr) -> Result<(), IommuError> {
        let (iommu, id) = (self.iommu, self.id);
        let mut flushed = Ok(());
        self.table.split_with(va, |_| flushed = iommu.invalidate(id))?;
        flushed
    }

    /// Tells every ATS device and PASID binding of this domain to drop
    /// translations for the range.
    fn invalidate_device_tlbs(&self, iova: u64, len: u64) -> Result<(), IommuError> {
        for &device in self.ats.iter().flatten() {
            self.iommu.invalidate_device_tlb(device, None, iova, len)?;
            for &(d, pasid) in self.pasids.iter().flatten() {
                if d == device {
                    self.iommu.invalidate_device_tlb(device, Some(pasid), iova, len)?;
                }
            }
        }
        Ok(())
    }

    /// Lets `device` (attached already) use this domain's table for DMA
    /// tagged `pasid`. Fails with [`IommuError::Unsupported`] if the unit
    /// does not do PASIDs and [`IommuError::OutOfRange`] if `pasid` is wider
    /// than [`Iommu::max_pasid_bits`]. Enable the device's PASID capability
    /// ([`PasidCap::enable`](crate::pci::PasidCap::enable)) afterwards.
    pub fn bind_pasid(&mut self, device: DeviceId, pasid: Pasid) -> Result<(), IommuError> {
        let bits = self.iommu.max_pasid_bits();
        if bits == 0 {
            return Err(IommuError::Unsupported);
        }
        if pasid.value() >> bits.min(Pasid::MAX_BITS) != 0 {
            return Err(IommuError::OutOfRange);
        }
        if !self.attached.contains(&Some(device)) {
            return Err(IommuError::NotAttached);
        }
        if self.pasids.contains(&Some((device, pasid))) {
            return Err(IommuError::Busy);
        }
        let slot = self.pasids.iter_mut().find(|s| s.is_none()).ok_or(IommuError::OutOfMemory)?;
        // SAFETY: as for `attach`: the table outlives the binding, because
        // the domain unbinds before detaching and before freeing the table.
        unsafe { self.iommu.bind_pasid(device, pasid, self.id, self.table.root())? };
        *slot = Some((device, pasid));
        Ok(())
    }

    /// Stops `device`'s DMA tagged `pasid`, and has the device drop what it
    /// cached for it if it has ATS on.
    pub fn unbind_pasid(&mut self, device: DeviceId, pasid: Pasid) -> Result<(), IommuError> {
        let slot = self.pasids.iter().position(|s| *s == Some((device, pasid))).ok_or(IommuError::NotAttached)?;
        self.iommu.unbind_pasid(device, pasid)?;
        if self.ats.contains(&Some(device)) {
            self.iommu.invalidate_device_tlb(device, Some(pasid), 0, 0)?;
        }
        if let Some(s) = self.pasids.get_mut(slot) {
            *s = None;
        }
        Ok(())
    }

    /// Records that `device` (attached already) is about to use ATS, so
    /// unmapping flushes its translation cache. Call this before enabling
    /// ATS on the device ([`Ats::enable`](crate::pci::Ats::enable)).
    /// [`IommuError::Unsupported`] if the unit does no ATS.
    pub fn enable_ats(&mut self, device: DeviceId) -> Result<(), IommuError> {
        if !self.iommu.supports_ats() {
            return Err(IommuError::Unsupported);
        }
        if !self.attached.contains(&Some(device)) {
            return Err(IommuError::NotAttached);
        }
        if self.ats.contains(&Some(device)) {
            return Err(IommuError::Busy);
        }
        let slot = self.ats.iter_mut().find(|s| s.is_none()).ok_or(IommuError::OutOfMemory)?;
        *slot = Some(device);
        Ok(())
    }

    /// Records that ATS is off on `device` (turn it off on the device first,
    /// with [`Ats::disable`](crate::pci::Ats::disable)), after having it drop
    /// everything it cached.
    pub fn disable_ats(&mut self, device: DeviceId) -> Result<(), IommuError> {
        let slot = self.ats.iter().position(|s| *s == Some(device)).ok_or(IommuError::NotAttached)?;
        self.iommu.invalidate_device_tlb(device, None, 0, 0)?;
        if let Some(s) = self.ats.get_mut(slot) {
            *s = None;
        }
        Ok(())
    }

    /// Has `device` drop what it cached for `[iova, iova + len)` (all of it if
    /// `len` is 0), for `pasid` if given. For callers that change the table
    /// behind the domain's back.
    pub fn invalidate_device_tlb(
        &self,
        device: DeviceId,
        pasid: Option<Pasid>,
        iova: u64,
        len: u64,
    ) -> Result<(), IommuError> {
        self.iommu.invalidate_device_tlb(device, pasid, iova, len)
    }

    /// The physical address `iova` translates to.
    pub fn translate(&self, iova: u64) -> Option<PhysAddr> {
        self.table.translate(VirtAddr::new(iova)).map(|t| t.pa)
    }
}

impl<I: Iommu, A: TableAlloc> Drop for IoDomain<'_, I, A> {
    fn drop(&mut self) {
        let mut clean = true;
        for (device, pasid) in self.pasids.iter_mut().filter_map(Option::take) {
            clean &= self.iommu.unbind_pasid(device, pasid).is_ok();
        }
        for device in self.attached.iter_mut().filter_map(Option::take) {
            clean &= self.iommu.detach(device).is_ok();
        }
        // A device with ATS still on can reach memory through what it cached.
        for device in self.ats.iter_mut().filter_map(Option::take) {
            clean &= self.iommu.invalidate_device_tlb(device, None, 0, 0).is_ok();
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
        self.alloc_aligned(pages, PAGE_SIZE as u64)
    }

    /// Like [`alloc`](Self::alloc), but the first IOVA is a multiple of
    /// `align` bytes (a power of two; less than a page means a page), so
    /// that a mapping can use 2 MiB or 1 GiB blocks. The skipped space stays
    /// free. If the extent table is full when an allocation would split an
    /// extent in two, the upper remainder is forgotten (safe, but wasteful).
    pub fn alloc_aligned(&mut self, pages: usize, align: u64) -> Option<u64> {
        let bytes = (pages as u64).checked_mul(PAGE_SIZE as u64).filter(|&b| b != 0)?;
        let align = align.max(PAGE_SIZE as u64);
        if !align.is_power_of_two() {
            return None;
        }
        let (i, start) = self.live().iter().enumerate().find_map(|(i, &(s, e))| {
            let a = s.checked_next_multiple_of(align)?;
            (a.checked_add(bytes)? <= e).then_some((i, a))
        })?;
        let (s, e) = *self.free.get(i)?;
        let end = start + bytes;
        match (start > s, end < e) {
            (false, false) => self.remove(i),
            (false, true) => self.free.get_mut(i)?.0 = end,
            (true, false) => self.free.get_mut(i)?.1 = start,
            (true, true) => {
                self.free.get_mut(i)?.1 = start;
                if self.len < FREE_EXTENTS {
                    self.free.copy_within(i + 1..self.len, i + 2);
                    *self.free.get_mut(i + 1)? = (end, e);
                    self.len += 1;
                }
            }
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
        // Line the IOVA up with the buffer's physical address so that a big
        // enough buffer maps with 2 MiB or 1 GiB blocks, where the unit has them.
        let max = st.domain.max_leaf_size();
        let pa = buf.device_addr().as_u64();
        let align = [PageSize::Size1G, PageSize::Size2M]
            .into_iter()
            .filter(|s| s.level() <= max.level())
            .map(PageSize::bytes)
            .find(|&a| bytes as u64 >= a && pa.is_multiple_of(a))
            .unwrap_or(PAGE_SIZE as u64);
        let found = st.iovas.alloc_aligned(pages, align).or_else(|| st.iovas.alloc(pages));
        let mapped = found.and_then(|iova| match st.domain.map(iova, buf.device_addr(), bytes as u64, MapFlags::RW) {
            Ok(()) => Some(iova),
            Err(_) => {
                st.iovas.free(iova, pages);
                None
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
        /// Accepts 2 MiB and 1 GiB blocks.
        huge: bool,
        /// Does ATS.
        ats: bool,
        /// PASID width it reports.
        pasid_bits: u32,
    }

    impl FakeIommu {
        fn log(&self, line: std::string::String) {
            self.events.lock().unwrap().push(line);
        }
        fn count(&self, prefix: &str) -> usize {
            self.events.lock().unwrap().iter().filter(|e| e.starts_with(prefix)).count()
        }
    }

    impl Iommu for FakeIommu {
        type Format = Ept;
        fn max_leaf_size(&self) -> PageSize {
            if self.huge { PageSize::Size1G } else { PageSize::Size4K }
        }
        fn max_pasid_bits(&self) -> u32 {
            self.pasid_bits
        }
        unsafe fn bind_pasid(
            &self,
            device: DeviceId,
            pasid: Pasid,
            domain: DomainId,
            _root: PhysAddr,
        ) -> Result<(), IommuError> {
            self.log(std::format!("bind {:#x} {} {}", device.bdf(), pasid.value(), domain.0));
            Ok(())
        }
        fn unbind_pasid(&self, device: DeviceId, pasid: Pasid) -> Result<(), IommuError> {
            self.log(std::format!("unbind {:#x} {}", device.bdf(), pasid.value()));
            Ok(())
        }
        fn supports_ats(&self) -> bool {
            self.ats
        }
        fn invalidate_device_tlb(
            &self,
            device: DeviceId,
            pasid: Option<Pasid>,
            iova: u64,
            len: u64,
        ) -> Result<(), IommuError> {
            self.log(std::format!("atc {:#x} {:?} {:#x} {:#x}", device.bdf(), pasid.map(Pasid::value), iova, len));
            Ok(())
        }
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

    const MIB2: u64 = 2 << 20;
    const GIB: u64 = 1 << 30;

    fn size_at<I: Iommu, A: TableAlloc>(d: &IoDomain<'_, I, A>, iova: u64) -> Option<PageSize> {
        d.table.translate(VirtAddr::new(iova)).map(|t| t.size)
    }

    #[test]
    fn maps_blocks_where_aligned() {
        let (iommu, tables) = (FakeIommu { huge: true, ..Default::default() }, HostTables::default());
        let mut d = IoDomain::new(&iommu, DomainId(1), &tables).unwrap();
        assert_eq!(d.max_leaf_size(), PageSize::Size1G);
        // Pages up to the 2 MiB boundary, a 2 MiB block, then a page.
        let base = GIB;
        let (iova, pa) = (base - 0x2000, 4 * GIB - 0x2000);
        let len = 0x2000 + MIB2 + 0x1000;
        d.map(iova, PhysAddr::new(pa), len, MapFlags::RW).unwrap();
        assert_eq!(size_at(&d, iova), Some(PageSize::Size4K));
        assert_eq!(size_at(&d, base), Some(PageSize::Size2M));
        assert_eq!(size_at(&d, base + MIB2), Some(PageSize::Size4K));
        assert_eq!(d.translate(base + 0x1234), Some(PhysAddr::new(4 * GIB + 0x1234)));
        d.unmap(iova, len).unwrap();
        assert_eq!(size_at(&d, base), None);

        // Aligned on both sides: a 1 GiB block, then 2 MiB blocks.
        d.map(2 * GIB, PhysAddr::new(8 * GIB), GIB + 2 * MIB2, MapFlags::RW).unwrap();
        assert_eq!(size_at(&d, 2 * GIB), Some(PageSize::Size1G));
        assert_eq!(size_at(&d, 3 * GIB), Some(PageSize::Size2M));
        assert_eq!(size_at(&d, 3 * GIB + MIB2), Some(PageSize::Size2M));
        assert_eq!(d.translate(3 * GIB + MIB2 + 8), Some(PhysAddr::new(9 * GIB + MIB2 + 8)));
        // A physical address misaligned relative to the IOVA forces pages.
        d.map(GIB, PhysAddr::new(16 * GIB + 0x1000), MIB2, MapFlags::RW).unwrap();
        assert_eq!(size_at(&d, GIB), Some(PageSize::Size4K));
    }

    #[test]
    fn no_blocks_without_hardware_support() {
        let (iommu, tables) = (FakeIommu::default(), HostTables::default());
        let mut d = IoDomain::new(&iommu, DomainId(1), &tables).unwrap();
        assert_eq!(d.max_leaf_size(), PageSize::Size4K);
        d.map(GIB, PhysAddr::new(4 * GIB), MIB2, MapFlags::RW).unwrap();
        assert_eq!(size_at(&d, GIB), Some(PageSize::Size4K));
    }

    #[test]
    fn partial_unmap_splits_blocks() {
        let (iommu, tables) = (FakeIommu { huge: true, ..Default::default() }, HostTables::default());
        let mut d = IoDomain::new(&iommu, DomainId(1), &tables).unwrap();
        let (iova, pa) = (2 * GIB, PhysAddr::new(8 * GIB));
        d.map(iova, pa, GIB, MapFlags::RW).unwrap();
        assert_eq!(size_at(&d, iova), Some(PageSize::Size1G));
        // One page in the middle of the 1 GiB block goes: block -> 2 MiB -> 4 KiB.
        let hole = iova + 5 * MIB2 + 0x3000;
        d.unmap(hole, 0x1000).unwrap();
        assert_eq!(d.translate(hole), None);
        assert_eq!(size_at(&d, iova), Some(PageSize::Size2M), "the rest stays in 2 MiB blocks");
        assert_eq!(size_at(&d, iova + 5 * MIB2), Some(PageSize::Size4K), "only the damaged block is pages");
        assert_eq!(d.translate(hole - 0x1000).map(|p| p.as_u64()), Some(8 * GIB + 5 * MIB2 + 0x2000));
        assert_eq!(d.translate(hole + 0x1000).map(|p| p.as_u64()), Some(8 * GIB + 5 * MIB2 + 0x4000));
        assert_eq!(d.translate(iova + GIB - 8).map(|p| p.as_u64()), Some(9 * GIB - 8));
        // A whole 2 MiB block needs no split: one flush.
        let before = iommu.count("invalidate");
        d.unmap(iova + 6 * MIB2, MIB2).unwrap();
        assert_eq!(iommu.count("invalidate") - before, 1);
        assert_eq!(d.translate(iova + 6 * MIB2), None);
        // A range straddling two blocks splits each at its edge.
        d.unmap(iova + 8 * MIB2 - 0x1000, 0x2000).unwrap();
        assert_eq!(d.translate(iova + 8 * MIB2 - 0x1000), None);
        assert_eq!(d.translate(iova + 8 * MIB2), None);
        assert!(d.translate(iova + 8 * MIB2 - 0x2000).is_some());
        assert!(d.translate(iova + 8 * MIB2 + 0x1000).is_some());
        // Everything else unmaps cleanly, and the tables are freed with the domain.
        d.unmap(iova, GIB).unwrap();
        assert_eq!(d.translate(iova + 7 * MIB2), None);
        drop(d);
        assert_eq!(tables.live.get(), 0);
    }

    #[test]
    fn failed_block_map_leaves_nothing() {
        let (iommu, tables) = (FakeIommu { huge: true, ..Default::default() }, HostTables::default());
        let mut d = IoDomain::new(&iommu, DomainId(1), &tables).unwrap();
        // A page already mapped inside the second 2 MiB block.
        d.map(GIB + MIB2 + 0x5000, PhysAddr::new(0x1000), 0x1000, MapFlags::RW).unwrap();
        assert_eq!(d.map(GIB, PhysAddr::new(4 * GIB), 3 * MIB2, MapFlags::RW), Err(MapError::AlreadyMapped.into()));
        assert_eq!(d.translate(GIB), None, "the first block was rolled back");
        assert_eq!(d.translate(GIB + MIB2 + 0x4000), None);
        assert_eq!(d.translate(GIB + MIB2 + 0x5000), Some(PhysAddr::new(0x1000)), "the old mapping survives");
        assert_eq!(d.translate(GIB + 2 * MIB2), None);
    }

    #[test]
    fn iova_allocator_aligns() {
        let mut a = IovaAllocator::new(0x1000..0x1000_0000);
        assert_eq!(a.alloc_aligned(1, MIB2), Some(MIB2));
        // The gap below stays usable.
        assert_eq!(a.alloc(2), Some(0x1000));
        assert_eq!(a.alloc_aligned(512, MIB2), Some(2 * MIB2));
        assert_eq!(a.alloc_aligned(1, 0x3000), None, "not a power of two");
        a.free(MIB2, 1);
        a.free(2 * MIB2, 512);
        assert_eq!(a.alloc_aligned(513, MIB2), Some(MIB2), "freed neighbours coalesced");
        let mut b = IovaAllocator::new(0x1000..0x20_0000);
        assert_eq!(b.alloc_aligned(1, MIB2), None, "no aligned room");
        assert_eq!(b.alloc(1), Some(0x1000));
    }

    #[test]
    fn dma_allocator_falls_back_to_pages() {
        let (iommu, tables, backing) =
            (FakeIommu { huge: true, ..Default::default() }, HostTables::default(), HostDma::default());
        let dma = {
            let domain = IoDomain::new(&iommu, DomainId(2), &tables).unwrap();
            IommuDma::new(domain, &backing, 0x10_0000..0x4000_0000).unwrap()
        };
        // Host allocations are only page-aligned, so the buffer gets no block;
        // the IOVA is still handed out and freed as usual.
        let a = dma.alloc_coherent(3 * MIB2 as usize).unwrap();
        assert_eq!(dma.with_domain(|d| size_at(d, a.device_addr().as_u64())), Some(PageSize::Size4K));
        // SAFETY: from this allocator; no device is running.
        unsafe { dma.free_coherent(a) };
        assert_eq!(backing.live.get(), 0);
    }

    #[test]
    fn span_encoding() {
        assert_eq!(ats_span(0x5000, 0x1000), Some((0x5000, 0)));
        assert_eq!(ats_span(0x5800, 0x100), Some((0x5000, 0)));
        // Pages 5 and 6 straddle a power-of-two boundary: pages 4..8.
        assert_eq!(ats_span(0x5000, 0x2000), Some((0x4000, 2)));
        assert_eq!(ats_span(0x4000, 0x2000), Some((0x4000, 1)));
        assert_eq!(ats_span(MIB2, MIB2), Some((MIB2, 9)));
        assert_eq!(ats_span(u64::MAX - 5, 100), None);
        assert_eq!(ats_span(0x1234, 0), Some((0, 52)));
        assert_eq!(ats_address(0x5000, 0), (0x5000, false));
        // S set; the span's size is read from the lowest zero bit above bit 11.
        assert_eq!(ats_address(0x4000, 1), (0x4000, true));
        assert_eq!(ats_address(0x4000, 2), (0x5000, true));
        assert_eq!(ats_address(MIB2, 9), (MIB2 | 0xff000, true));
        assert_eq!(ats_address(0, 52), (0x7fff_ffff_ffff_f000, true));
    }

    const GPU: DeviceId = DeviceId::new(0, Address::new(0, 4, 0));

    #[test]
    fn pasid_binding() {
        let (iommu, tables) = (FakeIommu { pasid_bits: 8, ..Default::default() }, HostTables::default());
        let none = FakeIommu::default();
        let mut d = IoDomain::new(&iommu, DomainId(3), &tables).unwrap();
        let p = |n| Pasid::new(n).unwrap();
        assert_eq!(Pasid::new(1 << 20), None);
        assert_eq!(d.bind_pasid(GPU, p(1)), Err(IommuError::NotAttached));
        d.attach(GPU).unwrap();
        d.bind_pasid(GPU, p(1)).unwrap();
        assert_eq!(d.bind_pasid(GPU, p(1)), Err(IommuError::Busy));
        assert_eq!(d.bind_pasid(GPU, p(256)), Err(IommuError::OutOfRange));
        d.bind_pasid(GPU, p(255)).unwrap();
        d.unbind_pasid(GPU, p(1)).unwrap();
        assert_eq!(d.unbind_pasid(GPU, p(1)), Err(IommuError::NotAttached));
        // Detaching unbinds what is left, before the unit forgets the device.
        d.detach(GPU).unwrap();
        let ev = iommu.events.lock().unwrap().clone();
        assert_eq!(ev[1], "bind 0x20 1 3");
        assert_eq!(&ev[ev.len() - 2..], ["unbind 0x20 255", "detach 0x20"]);
        let mut d2 = IoDomain::new(&none, DomainId(3), &tables).unwrap();
        d2.attach(GPU).unwrap();
        assert_eq!(d2.bind_pasid(GPU, p(1)), Err(IommuError::Unsupported));
        assert_eq!(d2.enable_ats(GPU), Err(IommuError::Unsupported));
    }

    #[test]
    fn unmap_invalidates_device_tlbs() {
        let iommu = FakeIommu { ats: true, pasid_bits: 8, huge: true, ..Default::default() };
        let tables = HostTables::default();
        let mut d = IoDomain::new(&iommu, DomainId(3), &tables).unwrap();
        let p = Pasid::new(7).unwrap();
        assert_eq!(d.enable_ats(GPU), Err(IommuError::NotAttached));
        d.attach(GPU).unwrap();
        d.attach(NIC).unwrap();
        d.enable_ats(GPU).unwrap();
        assert_eq!(d.enable_ats(GPU), Err(IommuError::Busy));
        d.bind_pasid(GPU, p).unwrap();
        d.map(0x10_0000, PhysAddr::new(0x7000_0000), 0x4000, MapFlags::RW).unwrap();
        assert_eq!(iommu.count("atc"), 0, "new mappings need no device flush");
        d.unmap(0x10_1000, 0x2000).unwrap();
        let ev = iommu.events.lock().unwrap().clone();
        let atc: Vec<_> = ev.iter().filter(|e| e.starts_with("atc")).collect();
        assert_eq!(atc, ["atc 0x20 None 0x101000 0x2000", "atc 0x20 Some(7) 0x101000 0x2000"]);
        // The IOTLB goes first.
        let first_atc = ev.iter().position(|e| e.starts_with("atc")).unwrap();
        assert!(ev[first_atc - 1].starts_with("invalidate"));
        // ATS must be off before the device detaches.
        assert_eq!(d.detach(GPU), Err(IommuError::Busy));
        d.disable_ats(GPU).unwrap();
        assert_eq!(d.disable_ats(GPU), Err(IommuError::NotAttached));
        d.detach(GPU).unwrap();
        // Dropping a domain flushes a device that still has ATS on.
        let mut d = IoDomain::new(&iommu, DomainId(4), &tables).unwrap();
        d.attach(GPU).unwrap();
        d.enable_ats(GPU).unwrap();
        let before = iommu.count("atc");
        drop(d);
        assert_eq!(iommu.count("atc") - before, 1);
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
