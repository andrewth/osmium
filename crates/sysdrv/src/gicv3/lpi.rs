// SPDX-License-Identifier: GPL-2.0-only
//! Locality-specific peripheral interrupts (LPIs): the tables a GICv3 keeps
//! them in.
//!
//! LPIs (interrupt IDs 8192 and up) have no distributor registers. Their
//! configuration, a byte per LPI holding the priority and an enable bit,
//! lives in one *property table* in memory that every redistributor reads
//! (`GICR_PROPBASER`); their pending state lives in a *pending table* per
//! redistributor (`GICR_PENDBASER`), one bit per interrupt ID. A redistributor
//! may cache the property table, so a change to it only takes effect after
//! an invalidation: the ITS's `INV` (or `INVALL`) command, see
//! [`Its`](super::its::Its).
//!
//! [`LpiTables`] owns the property table, the pending tables of the CPUs
//! that [`GicV3::enable_lpis`](super::GicV3::enable_lpis) was called on, and an
//! allocator for the LPI IDs themselves. LPIs are only ever generated through
//! an ITS (or, on GICv4.1 and DirectLPI redistributors, `GICR_SETLPIR`, which
//! this driver does not use).

use osmium_arch::MAX_CPUS;
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_mm::PhysAddr;
use osmium_sync::IrqSpinLock;

use super::FIRST_LPI;

/// The fewest interrupt-ID bits that leave room for any LPI (8192 is 2^13).
pub const MIN_LPI_ID_BITS: u32 = 14;
/// The most interrupt-ID bits [`LpiTables`] uses: 57344 LPIs, a 56 KiB
/// property table and 8 KiB pending tables.
pub const MAX_LPI_ID_BITS: u32 = 16;

/// Property-table byte bit 1, RES1.
const PROP_RES1: u8 = 1 << 1;
/// Property-table byte bit 0: the LPI is enabled.
const PROP_ENABLE: u8 = 1 << 0;
/// The first 1 KiB of a pending table is implementation defined and must be
/// zero when handed over; the whole table is, and `PENDBASER.PTZ` says so.
const PENDING_ALIGN: usize = 0x1_0000;

/// Why an LPI operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LpiError {
    /// The distributor does not support LPIs (`GICD_TYPER.LPIS` clear), or
    /// the redistributor of this CPU does not (`GICR_TYPER.PLPIS`).
    Unsupported,
    /// The requested number of ID bits is outside
    /// [`MIN_LPI_ID_BITS`]`..=`[`MAX_LPI_ID_BITS`] or above what the
    /// distributor implements.
    BadIdBits,
    /// Out of memory for a table.
    NoMemory,
    /// The calling CPU has no redistributor (see
    /// [`GicV3::init_cpu`](super::GicV3::init_cpu)).
    NoRedistributor,
    /// The redistributor did not take the table: its shareability reads
    /// back as non-shareable, so it would not see the CPU's cached writes
    /// and this driver has no cache maintenance to make up for it.
    NotCoherent,
    /// The ID is not an LPI these tables cover.
    BadLpi,
}

/// A DMA buffer with an address aligned more strictly than the 4 KiB
/// [`DmaAllocator`] guarantees: the buffer is over-allocated and used from
/// the first aligned offset.
pub(crate) struct AlignedDma<'d, D: DmaAllocator + ?Sized> {
    buf: OwnedDma<'d, D>,
    offset: usize,
    len: usize,
}

impl<'d, D: DmaAllocator + ?Sized> AlignedDma<'d, D> {
    /// `len` zeroed bytes at a multiple of `align` (a power of two).
    pub(crate) fn new(dma: &'d D, len: usize, align: usize) -> Option<Self> {
        // A buddy allocator hands out naturally aligned blocks, so try the
        // exact size first.
        let buf = OwnedDma::new(dma, len.max(align))?;
        if buf.device_addr().is_aligned(align as u64) {
            return Some(Self { buf, offset: 0, len });
        }
        drop(buf);
        let buf = OwnedDma::new(dma, len.checked_add(align)?)?;
        let start = buf.device_addr().as_u64();
        let offset = usize::try_from(start.next_multiple_of(align as u64).checked_sub(start)?).ok()?;
        Some(Self { buf, offset, len })
    }

    /// Device address of the aligned start.
    pub(crate) fn addr(&self) -> PhysAddr {
        PhysAddr::new(self.buf.device_addr().as_u64().wrapping_add(self.offset as u64))
    }

    /// Length in bytes, from the aligned start.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn load<T: osmium_hal::mmio::RegValue>(&self, off: usize) -> T {
        if off.checked_add(core::mem::size_of::<T>()).is_none_or(|e| e > self.len) {
            return T::default();
        }
        self.buf.load(self.offset.wrapping_add(off))
    }
}

/// The LPI property table, the per-CPU pending tables and an LPI ID
/// allocator, shared by every redistributor and ITS of one GIC.
pub struct LpiTables<'d, D: DmaAllocator + ?Sized> {
    dma: &'d D,
    id_bits: u32,
    /// One byte per LPI, LPI 8192 first.
    prop: OwnedDma<'d, D>,
    /// One bit per LPI: allocated.
    used: IrqSpinLock<OwnedDma<'d, D>>,
    /// Each CPU's pending table, once it has one.
    pending: IrqSpinLock<[Option<AlignedDma<'d, D>>; MAX_CPUS]>,
}

// SAFETY: the property table, the only field outside a lock, is only
// accessed with single volatile byte and word loads and stores, which race
// with the redistributors' reads of it in any case; the rest is behind
// locks. The allocator reference is shared, so it must be `Sync`.
unsafe impl<D: DmaAllocator + Sync + ?Sized> Sync for LpiTables<'_, D> {}
// SAFETY: the tables are owned memory; moving them to another CPU is fine
// when the allocator may be used from there.
unsafe impl<D: DmaAllocator + Sync + ?Sized> Send for LpiTables<'_, D> {}

/// The property-table byte for `priority` (higher is more urgent, as in
/// [`InterruptController::set_priority`](osmium_hal::irq::InterruptController::set_priority))
/// and `enabled`. The GIC keeps only the top six bits of the priority.
pub const fn property(priority: u8, enabled: bool) -> u8 {
    ((0xff - priority) & 0xfc) | PROP_RES1 | if enabled { PROP_ENABLE } else { 0 }
}

/// Bytes of a property table for `id_bits` interrupt-ID bits.
pub const fn property_table_len(id_bits: u32) -> usize {
    (1usize << id_bits) - FIRST_LPI as usize
}

/// Bytes of a pending table for `id_bits` interrupt-ID bits: a bit for
/// every ID, the 8192 non-LPI ones included.
pub const fn pending_table_len(id_bits: u32) -> usize {
    (1usize << id_bits) / 8
}

/// `GICR_PROPBASER`/`GITS_BASER` cacheability and shareability: inner
/// shareable, inner read-allocate write-allocate write-back, outer the same
/// as inner.
pub(crate) const CACHE_ATTRS: u64 = 7 << 7 | 1 << 10;
/// The shareability field (bits 11:10) of the base registers.
pub(crate) const SHAREABILITY: u64 = 3 << 10;

impl<'d, D: DmaAllocator + ?Sized> LpiTables<'d, D> {
    /// Allocates a property table for LPIs `8192..2^id_bits`, all disabled.
    /// Pending tables are allocated per CPU as they enable LPIs.
    pub fn new(dma: &'d D, id_bits: u32) -> Result<Self, LpiError> {
        if !(MIN_LPI_ID_BITS..=MAX_LPI_ID_BITS).contains(&id_bits) {
            return Err(LpiError::BadIdBits);
        }
        let len = property_table_len(id_bits);
        let prop = OwnedDma::new(dma, len).ok_or(LpiError::NoMemory)?;
        let used = OwnedDma::new(dma, len / 8).ok_or(LpiError::NoMemory)?;
        let fill = u64::from_ne_bytes([property(0, false); 8]);
        for off in (0..len).step_by(8) {
            prop.store(off, fill);
        }
        Ok(Self {
            dma,
            id_bits,
            prop,
            used: IrqSpinLock::new(used),
            pending: IrqSpinLock::new([const { None }; MAX_CPUS]),
        })
    }

    /// Interrupt-ID bits the tables cover.
    pub fn id_bits(&self) -> u32 {
        self.id_bits
    }

    /// How many LPIs the tables cover.
    pub fn count(&self) -> u32 {
        (1u32 << self.id_bits) - FIRST_LPI
    }

    /// Device address of the property table.
    pub fn property_table(&self) -> PhysAddr {
        self.prop.device_addr()
    }

    /// Whether `intid` is an LPI these tables cover.
    pub fn covers(&self, intid: u32) -> bool {
        intid >= FIRST_LPI && intid < 1 << self.id_bits
    }

    /// Allocates a free LPI ID. Its configuration is left disabled.
    pub fn alloc(&self) -> Option<u32> {
        let used = self.used.lock();
        for word in 0..self.count() as usize / 64 {
            let w: u64 = used.load(word * 8);
            if w != u64::MAX {
                let bit = w.trailing_ones() as usize;
                used.store(word * 8, w | 1 << bit);
                return u32::try_from(word * 64 + bit).ok().map(|i| i + FIRST_LPI);
            }
        }
        None
    }

    /// Returns `intid` to the allocator and disables it. The caller must
    /// already have unmapped it from every ITS.
    pub fn free(&self, intid: u32) {
        if !self.covers(intid) {
            return;
        }
        let i = (intid - FIRST_LPI) as usize;
        let _ = self.configure(intid, 0, false);
        let used = self.used.lock();
        let w: u64 = used.load(i / 64 * 8);
        used.store(i / 64 * 8, w & !(1 << (i % 64)));
    }

    /// Whether `intid` is allocated.
    pub fn is_allocated(&self, intid: u32) -> bool {
        if !self.covers(intid) {
            return false;
        }
        let i = (intid - FIRST_LPI) as usize;
        self.used.lock().load::<u64>(i / 64 * 8) & 1 << (i % 64) != 0
    }

    /// Writes `intid`'s configuration. Redistributors may hold a cached copy:
    /// it takes effect after an ITS `INV` for an event mapped to it (as
    /// [`Its::map_event`](super::its::Its::map_event) does) or an `INVALL`.
    pub fn configure(&self, intid: u32, priority: u8, enabled: bool) -> Result<(), LpiError> {
        if !self.covers(intid) {
            return Err(LpiError::BadLpi);
        }
        self.prop.store((intid - FIRST_LPI) as usize, property(priority, enabled));
        osmium_arch::barrier::dma_wmb();
        Ok(())
    }

    /// `intid`'s configuration byte, if the tables cover it.
    pub fn property(&self, intid: u32) -> Option<u8> {
        self.covers(intid).then(|| self.prop.load((intid - FIRST_LPI) as usize))
    }

    /// The `GICR_PROPBASER` value for these tables.
    pub(crate) fn propbaser(&self) -> u64 {
        (self.prop.device_addr().as_u64() & ADDR_MASK_4K) | CACHE_ATTRS | u64::from(self.id_bits - 1)
    }

    /// Allocates (or reuses) `cpu`'s pending table and returns its
    /// `GICR_PENDBASER` value.
    pub(crate) fn pendbaser(&self, cpu: usize) -> Result<u64, LpiError> {
        let mut pending = self.pending.lock();
        let slot = pending.get_mut(cpu).ok_or(LpiError::NoRedistributor)?;
        if slot.is_none() {
            *slot = Some(
                AlignedDma::new(self.dma, pending_table_len(self.id_bits), PENDING_ALIGN).ok_or(LpiError::NoMemory)?,
            );
        }
        let pa = slot.as_ref().map_or(0, |t| t.addr().as_u64());
        Ok((pa & ADDR_MASK_64K) | CACHE_ATTRS | PENDBASER_PTZ)
    }

    /// Whether `intid` is pending in `cpu`'s pending table. The
    /// redistributor may hold pending state it has not written back, so
    /// this is only exact while LPIs are off on that CPU; tests and
    /// diagnostics only.
    pub fn pending_in_table(&self, cpu: usize, intid: u32) -> bool {
        let pending = self.pending.lock();
        let Some(Some(t)) = pending.get(cpu) else { return false };
        let byte = (intid / 8) as usize;
        byte < t.len() && t.load::<u8>(byte) & 1 << (intid % 8) != 0
    }
}

/// Address bits 51:12 of a base register.
pub(crate) const ADDR_MASK_4K: u64 = 0x000f_ffff_ffff_f000;
/// Address bits 51:16 of a base register.
pub(crate) const ADDR_MASK_64K: u64 = 0x000f_ffff_ffff_0000;
/// `GICR_PENDBASER.PTZ`: the pending table is all zeros.
const PENDBASER_PTZ: u64 = 1 << 62;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iommu::testing::HostDma;

    #[test]
    fn property_bytes() {
        assert_eq!(property(0, false), 0xfe);
        assert_eq!(property(0xff, true), 0x03);
        assert_eq!(property(0x5f, true), 0xa3, "priority 0xa0 as the GIC encodes it");
        assert_eq!(property_table_len(14), 8192);
        assert_eq!(pending_table_len(16), 8192);
    }

    #[test]
    fn allocation_and_configuration() {
        let dma = HostDma::default();
        assert_eq!(LpiTables::new(&dma, 13).err(), Some(LpiError::BadIdBits));
        assert_eq!(LpiTables::new(&dma, 17).err(), Some(LpiError::BadIdBits));
        let t = LpiTables::new(&dma, 14).unwrap();
        assert_eq!(t.count(), 8192);
        assert_eq!(t.property(8192), Some(property(0, false)));
        assert_eq!(t.property(16383), Some(property(0, false)));
        assert_eq!(t.property(16384), None);
        let ids: std::vec::Vec<u32> = (0..70).map(|_| t.alloc().unwrap()).collect();
        assert_eq!(ids[0], 8192);
        assert_eq!(ids[69], 8192 + 69, "allocation crosses a bitmap word");
        t.configure(8200, 0x5f, true).unwrap();
        assert_eq!(t.property(8200), Some(0xa3));
        assert_eq!(t.configure(100, 0, true), Err(LpiError::BadLpi));
        t.free(8200);
        assert!(!t.is_allocated(8200));
        assert_eq!(t.property(8200), Some(property(0, false)), "freeing disables");
        assert_eq!(t.alloc(), Some(8200), "a freed ID is reused");
        for _ in 70..8192 {
            assert!(t.alloc().is_some());
        }
        assert_eq!(t.alloc(), None, "exhausted");
        let pb = t.propbaser();
        assert_eq!(pb & 0x1f, 13, "IDbits - 1");
        assert_eq!(pb & ADDR_MASK_4K, t.property_table().as_u64());
    }

    #[test]
    fn pending_tables_are_64k_aligned_and_reused() {
        let dma = HostDma::default();
        let t = LpiTables::new(&dma, 16).unwrap();
        let a = t.pendbaser(1).unwrap();
        assert_eq!(a & ADDR_MASK_64K & 0xffff, 0);
        assert_ne!(a & ADDR_MASK_64K, 0);
        assert_ne!(a & PENDBASER_PTZ, 0);
        assert_eq!(t.pendbaser(1).unwrap(), a, "one table per CPU");
        assert_ne!(t.pendbaser(2).unwrap(), a);
        assert_eq!(t.pendbaser(MAX_CPUS), Err(LpiError::NoRedistributor));
        assert!(!t.pending_in_table(1, 8192));
    }
}
