//! GICv4.0 virtual LPIs: direct injection of a device's MSIs into a guest.
//!
//! A hypervisor gives each virtual CPU a *vPE*: an ID the ITS knows it by
//! ([`Its::map_vpe`], `VMAPP`, naming the redistributor it runs on) and a
//! virtual pending table ([`Vpe`]). Each VM gets a virtual LPI property table
//! ([`VlpiTables`]), the same format as the physical one. An event mapped
//! with [`Its::map_virtual_event`] (`VMAPTI`) then sets its virtual LPI
//! pending in the vPE's table without the hypervisor running at all.
//!
//! While the vPE is *resident* on a redistributor
//! ([`GicV3::make_vpe_resident`], writing `GICR_VPROPBASER` and
//! `GICR_VPENDBASER.Valid` before entering the guest), the virtual LPI is
//! signalled straight to the virtual CPU interface: the guest acknowledges
//! it through `ICC_IAR1_EL1` (the `ICV_` view) with no list register and no
//! exit. While it is not, the ITS raises the event's *doorbell*, a physical
//! LPI the hypervisor chose, to tell it the vCPU has work.
//! [`GicV3::make_vpe_nonresident`] (`Valid` = 0) ends a residency when the
//! vCPU is descheduled; [`Its::move_vpe`] (`VMOVP`) follows a vCPU to
//! another physical CPU.
//!
//! GICv4.1 (vSGIs, `GICR_VPENDBASER` by vPE ID, `VMAPP` with a default
//! doorbell) is not implemented.

use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_mm::PhysAddr;

use super::its::{Its, ItsError, TableType, VIRTUAL_EVENT, cmd};
use super::lpi::{ADDR_MASK_4K, ADDR_MASK_64K, AlignedDma, CACHE_ATTRS, MAX_LPI_ID_BITS, MIN_LPI_ID_BITS};
use super::lpi::{pending_table_len, property, property_table_len};
use super::{CpuInterface, FIRST_LPI, GicV3, SPIN_LIMIT};

/// Offset of the virtual-LPI frame within a GICv4 redistributor.
const GICR_VLPI_FRAME: usize = 0x2_0000;
const GICR_VPROPBASER: usize = GICR_VLPI_FRAME + 0x70;
const GICR_VPENDBASER: usize = GICR_VLPI_FRAME + 0x78;
const VPENDBASER_VALID: u64 = 1 << 63;
const VPENDBASER_PENDING_LAST: u64 = 1 << 61;
const VPENDBASER_DIRTY: u64 = 1 << 60;
/// Virtual pending tables are 64 KiB aligned, like physical ones.
const VPT_ALIGN: usize = 0x1_0000;

/// Why a virtual-LPI operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VlpiError {
    /// The calling CPU's redistributor has no virtual LPI support
    /// (`GICR_TYPER.VLPIS`).
    Unsupported,
    /// The calling CPU has no redistributor.
    NoRedistributor,
    /// The ID bits are outside 14..=16.
    BadIdBits,
    /// Out of memory for a table.
    NoMemory,
    /// The virtual interrupt ID is not an LPI the tables cover.
    BadVintid,
    /// Another vPE is resident on this redistributor.
    Busy,
    /// The redistributor did not finish parsing the outgoing vPE's table
    /// (`GICR_VPENDBASER.Dirty` stayed set).
    Timeout,
}

/// A VM's virtual LPI property table: a priority and enable byte per
/// virtual LPI, shared by all its vPEs.
pub struct VlpiTables<'d, D: DmaAllocator + ?Sized> {
    prop: OwnedDma<'d, D>,
    id_bits: u32,
}

// SAFETY: the table is only accessed with single volatile byte and word
// stores and loads, which race with the GIC's reads of it in any case.
unsafe impl<D: DmaAllocator + Sync + ?Sized> Sync for VlpiTables<'_, D> {}
// SAFETY: owned memory; the allocator is `Sync`, so it may free it anywhere.
unsafe impl<D: DmaAllocator + Sync + ?Sized> Send for VlpiTables<'_, D> {}

impl<'d, D: DmaAllocator + ?Sized> VlpiTables<'d, D> {
    /// A property table for virtual LPIs `8192..2^id_bits`, all disabled.
    pub fn new(dma: &'d D, id_bits: u32) -> Result<Self, VlpiError> {
        if !(MIN_LPI_ID_BITS..=MAX_LPI_ID_BITS).contains(&id_bits) {
            return Err(VlpiError::BadIdBits);
        }
        let len = property_table_len(id_bits);
        let prop = OwnedDma::new(dma, len).ok_or(VlpiError::NoMemory)?;
        let fill = u64::from_ne_bytes([property(0, false); 8]);
        for off in (0..len).step_by(8) {
            prop.store(off, fill);
        }
        Ok(Self { prop, id_bits })
    }

    /// Interrupt-ID bits the table covers.
    pub fn id_bits(&self) -> u32 {
        self.id_bits
    }

    /// Writes virtual LPI `vintid`'s configuration (higher `priority` is
    /// more urgent). A resident vPE may cache it: follow with
    /// [`Its::invalidate_vpe`], or map the event afterwards.
    pub fn configure(&self, vintid: u32, priority: u8, enabled: bool) -> Result<(), VlpiError> {
        if vintid < FIRST_LPI || vintid >= 1 << self.id_bits {
            return Err(VlpiError::BadVintid);
        }
        self.prop.store((vintid - FIRST_LPI) as usize, property(priority, enabled));
        osmium_arch::barrier::dma_wmb();
        Ok(())
    }

    /// `vintid`'s configuration byte.
    pub fn property(&self, vintid: u32) -> Option<u8> {
        (vintid >= FIRST_LPI && vintid < 1 << self.id_bits).then(|| self.prop.load((vintid - FIRST_LPI) as usize))
    }

    fn vpropbaser(&self) -> u64 {
        (self.prop.device_addr().as_u64() & ADDR_MASK_4K) | CACHE_ATTRS | u64::from(self.id_bits - 1)
    }
}

/// A virtual PE: the ITS's name for a vCPU, and its virtual pending table.
pub struct Vpe<'d, D: DmaAllocator + ?Sized> {
    id: u16,
    id_bits: u32,
    vpt: AlignedDma<'d, D>,
}

// SAFETY: the pending table is only touched by the GIC, and by `pending`
// with single volatile byte loads.
unsafe impl<D: DmaAllocator + Sync + ?Sized> Sync for Vpe<'_, D> {}
// SAFETY: owned memory; the allocator is `Sync`.
unsafe impl<D: DmaAllocator + Sync + ?Sized> Send for Vpe<'_, D> {}

impl<'d, D: DmaAllocator + ?Sized> Vpe<'d, D> {
    /// vPE `id` with a zeroed pending table for `id_bits` interrupt-ID bits
    /// (those of its VM's [`VlpiTables`]).
    pub fn new(dma: &'d D, id: u16, id_bits: u32) -> Result<Self, VlpiError> {
        if !(MIN_LPI_ID_BITS..=MAX_LPI_ID_BITS).contains(&id_bits) {
            return Err(VlpiError::BadIdBits);
        }
        let vpt = AlignedDma::new(dma, pending_table_len(id_bits), VPT_ALIGN).ok_or(VlpiError::NoMemory)?;
        Ok(Self { id, id_bits, vpt })
    }

    /// The vPE ID.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Device address of the virtual pending table.
    pub fn pending_table(&self) -> PhysAddr {
        self.vpt.addr()
    }

    /// Whether `vintid` is pending in the table. Exact only while the vPE
    /// is not resident (a resident one's state may be held in the
    /// redistributor); diagnostics and tests.
    pub fn is_pending(&self, vintid: u32) -> bool {
        let byte = (vintid / 8) as usize;
        byte < self.vpt.len() && self.vpt.load::<u8>(byte) & 1 << (vintid % 8) != 0
    }

    fn vpendbaser(&self) -> u64 {
        VPENDBASER_VALID | (self.vpt.addr().as_u64() & ADDR_MASK_64K) | CACHE_ATTRS
    }
}

impl<C: CpuInterface> GicV3<C> {
    /// The calling CPU's redistributor offset, if it has virtual LPIs.
    fn vlpi_redist(&self) -> Result<usize, VlpiError> {
        let rd = self.redistributor(osmium_arch::cpu::current_id()).ok_or(VlpiError::NoRedistributor)?;
        if rd.vlpis { Ok(rd.offset) } else { Err(VlpiError::Unsupported) }
    }

    /// Makes `vpe`, of the VM whose property table is `vm`, resident on the
    /// calling CPU's redistributor: its pending virtual LPIs are signalled to
    /// this CPU's virtual CPU interface from now on. Call before entering
    /// the vCPU's guest, on the CPU [`Its::map_vpe`] or [`Its::move_vpe`]
    /// last named, with interrupts masked so the task stays on it.
    pub fn make_vpe_resident<D: DmaAllocator + ?Sized>(
        &self,
        vm: &VlpiTables<'_, D>,
        vpe: &Vpe<'_, D>,
    ) -> Result<(), VlpiError> {
        let rd = self.vlpi_redist()?;
        let current: u64 = self.gicr.read(rd + GICR_VPENDBASER).unwrap_or(0);
        if current & VPENDBASER_VALID != 0 {
            return Err(VlpiError::Busy);
        }
        let _ = self.gicr.write(rd + GICR_VPROPBASER, vm.vpropbaser());
        osmium_arch::barrier::mb();
        let _ = self.gicr.write(rd + GICR_VPENDBASER, vpe.vpendbaser());
        Ok(())
    }

    /// Ends the residency of whatever vPE is resident on the calling CPU's
    /// redistributor, after the vCPU has left its guest. Waits for the
    /// redistributor to write its state back (`Dirty`) and returns whether a
    /// virtual LPI was still pending (`PendingLast`): if so, the vCPU has
    /// work even though no doorbell may come.
    pub fn make_vpe_nonresident(&self) -> Result<bool, VlpiError> {
        let rd = self.vlpi_redist()?;
        let current: u64 = self.gicr.read(rd + GICR_VPENDBASER).unwrap_or(0);
        let _ = self.gicr.write(rd + GICR_VPENDBASER, current & !VPENDBASER_VALID);
        for _ in 0..SPIN_LIMIT {
            let v: u64 = self.gicr.read(rd + GICR_VPENDBASER).unwrap_or(0);
            if v & VPENDBASER_DIRTY == 0 {
                return Ok(v & VPENDBASER_PENDING_LAST != 0);
            }
            core::hint::spin_loop();
        }
        Err(VlpiError::Timeout)
    }

    /// The virtual pending table of the vPE resident on the calling CPU, if
    /// one is.
    pub fn resident_vpe(&self) -> Option<PhysAddr> {
        let rd = self.vlpi_redist().ok()?;
        let v: u64 = self.gicr.read(rd + GICR_VPENDBASER).ok()?;
        (v & VPENDBASER_VALID != 0).then(|| PhysAddr::new(v & ADDR_MASK_64K))
    }
}

impl<D: DmaAllocator + ?Sized> Its<'_, D> {
    fn check_vpe(&self, id: u16) -> Result<(), ItsError> {
        if !self.has_virtual_lpis() {
            return Err(ItsError::Unsupported);
        }
        match self.table_entries(TableType::Vpes) {
            Some(n) if u64::from(id) < n => Ok(()),
            _ => Err(ItsError::BadVpe),
        }
    }

    /// Tells the ITS that `vpe` runs on the redistributor `target` (from
    /// [`Its::collection_target`]) and where its pending table is (`VMAPP`).
    pub fn map_vpe<A: DmaAllocator + ?Sized>(&self, vpe: &Vpe<'_, A>, target: u64) -> Result<(), ItsError> {
        self.check_vpe(vpe.id)?;
        let table = vpe.pending_table().as_u64();
        self.submit(&[cmd::vmapp(vpe.id, target, table, vpe.id_bits, true), cmd::vsync(vpe.id)])
    }

    /// Forgets `vpe` (`VMAPP` with V = 0). Unmap its events first.
    pub fn unmap_vpe<A: DmaAllocator + ?Sized>(&self, vpe: &Vpe<'_, A>) -> Result<(), ItsError> {
        self.check_vpe(vpe.id)?;
        self.submit(&[cmd::vmapp(vpe.id, 0, 0, vpe.id_bits, false)])
    }

    /// Moves `vpe` to the redistributor `target` (`VMOVP`), when its vCPU
    /// moves to another physical CPU. Make it non-resident on the old one
    /// first. A single ITS needs no `VMOVP` sequencing; several would.
    pub fn move_vpe<A: DmaAllocator + ?Sized>(&self, vpe: &Vpe<'_, A>, target: u64) -> Result<(), ItsError> {
        self.check_vpe(vpe.id)?;
        self.submit(&[cmd::vmovp(vpe.id, target, 0, 0), cmd::vsync(vpe.id)])
    }

    /// Maps `device`'s `event` to virtual LPI `vintid` of `vpe` (`VMAPTI`),
    /// with physical LPI `doorbell` raised when the vPE is not resident
    /// (`None` for no doorbell; the doorbell must be allocated and enabled in
    /// the physical [`LpiTables`](super::lpi::LpiTables), then made known
    /// with [`Its::invalidate_collection`]). Configure `vintid` in the VM's
    /// [`VlpiTables`] first; this reloads it (`INV`).
    pub fn map_virtual_event<A: DmaAllocator + ?Sized>(
        &self,
        device: u32,
        event: u32,
        vpe: &Vpe<'_, A>,
        vintid: u32,
        doorbell: Option<u32>,
    ) -> Result<(), ItsError> {
        self.check_vpe(vpe.id)?;
        if vintid < FIRST_LPI || vintid >= 1 << vpe.id_bits {
            return Err(ItsError::BadEvent);
        }
        let db = doorbell.unwrap_or(cmd::NO_DOORBELL);
        self.with_event(device, event, |events, slot| {
            if events.load::<u64>(slot) != 0 {
                return Err(ItsError::BadEvent);
            }
            self.submit(&[
                cmd::vmapti(device, event, vpe.id, vintid, db),
                cmd::inv(device, event),
                cmd::vsync(vpe.id),
            ])?;
            events.store(slot, VIRTUAL_EVENT | u64::from(vintid) | u64::from(vpe.id) << 32);
            Ok(())
        })
    }

    /// Moves `device`'s virtual `event` to `vpe` (`VMOVI`), with a new
    /// doorbell. The virtual interrupt ID stays the same.
    pub fn move_virtual_event<A: DmaAllocator + ?Sized>(
        &self,
        device: u32,
        event: u32,
        vpe: &Vpe<'_, A>,
        doorbell: Option<u32>,
    ) -> Result<(), ItsError> {
        self.check_vpe(vpe.id)?;
        self.with_event(device, event, |events, slot| {
            let e: u64 = events.load(slot);
            if e & VIRTUAL_EVENT == 0 {
                return Err(ItsError::BadEvent);
            }
            let old = (e >> 32 & 0xffff) as u16;
            self.submit(&[cmd::vmovi(device, event, vpe.id, doorbell), cmd::vsync(old), cmd::vsync(vpe.id)])?;
            events.store(slot, VIRTUAL_EVENT | (e & 0xffff_ffff) | u64::from(vpe.id) << 32);
            Ok(())
        })
    }

    /// The virtual LPI and vPE `device`'s `event` is mapped to, if virtual.
    pub fn virtual_event(&self, device: u32, event: u32) -> Option<(u32, u16)> {
        let e = self.with_event(device, event, |events, slot| Ok(events.load::<u64>(slot))).ok()?;
        (e & VIRTUAL_EVENT != 0).then_some((e as u32, (e >> 32 & 0xffff) as u16))
    }

    /// Reloads the configuration of every virtual LPI of `vpe` (`VINVALL`).
    pub fn invalidate_vpe<A: DmaAllocator + ?Sized>(&self, vpe: &Vpe<'_, A>) -> Result<(), ItsError> {
        self.check_vpe(vpe.id)?;
        self.submit(&[cmd::vinvall(vpe.id), cmd::vsync(vpe.id)])
    }

    /// Reloads the configuration of every physical LPI of collection `icid`
    /// (`INVALL`): after configuring a doorbell, which no event names.
    pub fn invalidate_collection(&self, icid: u16) -> Result<(), ItsError> {
        let target = self.collection(icid).ok_or(ItsError::BadCollection)?;
        self.submit(&[cmd::invall(icid), cmd::sync(target)])
    }
}

#[cfg(test)]
mod tests;
