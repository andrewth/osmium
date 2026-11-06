// SPDX-License-Identifier: GPL-2.0-only
//! The GICv3 interrupt translation service (ITS).
//!
//! An ITS turns a device's message-signalled interrupt into an LPI. The
//! device writes an *event ID* (its MSI data) to the ITS's `GITS_TRANSLATER`
//! register; the bus tags the write with a *device ID* (for PCI, normally
//! the requester ID, through the device tree's `msi-map`). The ITS looks the
//! device up in its device table, finds the device's interrupt translation
//! table (ITT), and the event's entry there names the LPI and the
//! *collection* it goes to; the collection table names the redistributor.
//!
//! Software fills those tables (in memory the ITS owns) only through
//! commands on a ring in memory: `GITS_CBASER` locates it, software appends
//! at `GITS_CWRITER` and the ITS consumes up to `GITS_CREADR`. [`Its`] sets
//! up the ring and the tables `GITS_BASER<n>` asks for, then offers:
//!
//! - [`Its::map_collection`]: a collection per CPU (`MAPC`), targeted by
//!   [`Its::collection_target`];
//! - [`Its::add_device`] / [`Its::remove_device`]: an ITT per device (`MAPD`);
//! - [`Its::map_event`]: allocate an LPI from the [`LpiTables`], enable it,
//!   map the event to it (`MAPTI`, `INV`, `SYNC`) and return the MSI
//!   message the device must be programmed with; [`Its::unmap_event`]
//!   (`DISCARD`) undoes it, [`Its::move_event`] (`MOVI`) retargets it;
//! - [`Its::trigger`] (`INT`) and [`Its::clear`] (`CLEAR`), which raise and
//!   withdraw an event as if the device had written it.
//!
//! Every command batch ends with a `SYNC` (or `VSYNC`) and is waited for,
//! so on return the ITS has acted on it. GICv4 virtual LPIs (`VMAPP`,
//! `VMAPTI`, `VMOVP`, ...) are in [`super::v4`].
//!
//! Not implemented: two-level (indirect) device tables, so the device table
//! is flat and its size bounds the device IDs; recovery from a stalled
//! command queue (`GITS_CREADR.Stalled`) beyond reporting it; and cache
//! maintenance, so an ITS whose tables read back as non-shareable is
//! refused.

use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::ioext::IoMemExt;
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::MsiMessage;
use osmium_hal::timer::Clock;
use osmium_mm::PhysAddr;
use osmium_sync::IrqSpinLock;

use super::lpi::{ADDR_MASK_4K, AlignedDma, LpiError, LpiTables};
use super::{CpuInterface, GicV3};

const GITS_CTLR: usize = 0x0000;
const GITS_IIDR: usize = 0x0004;
const GITS_TYPER: usize = 0x0008;
const GITS_CBASER: usize = 0x0080;
const GITS_CWRITER: usize = 0x0088;
const GITS_CREADR: usize = 0x0090;
const GITS_BASER: usize = 0x0100;
/// The doorbell devices write, in the second 64 KiB frame.
pub const GITS_TRANSLATER: u64 = 0x1_0040;
/// Bytes of register space an ITS has: the control and translation frames.
pub const ITS_REGS_LEN: usize = 0x2_0000;

const CTLR_ENABLED: u32 = 1 << 0;
const CTLR_QUIESCENT: u32 = 1 << 31;

const TYPER_PHYSICAL: u64 = 1 << 0;
const TYPER_VIRTUAL: u64 = 1 << 1;
const TYPER_PTA: u64 = 1 << 19;
const TYPER_CIL: u64 = 1 << 36;

const BASER_VALID: u64 = 1 << 63;
const BASER_INDIRECT: u64 = 1 << 62;
/// Inner write-back read/write-allocate (61:59), outer as inner (55:53 = 0),
/// inner shareable (11:10).
const BASER_ATTRS: u64 = 7 << 59 | 1 << 10;
const BASER_SHAREABILITY: u64 = 3 << 10;
/// The read-only `Type` and `Entry_Size` fields, written back unchanged.
const BASER_RO: u64 = 7 << 56 | 0x1f << 48;
/// Address bits 47:12 of a `GITS_BASER<n>`.
const BASER_ADDR: u64 = 0x0000_ffff_ffff_f000;
/// `CREADR.Stalled`: a command failed and the ITS stopped.
const CREADR_STALLED: u64 = 1 << 0;
/// Offset bits of `CWRITER`/`CREADR`.
const QUEUE_OFFSET: u64 = 0xf_ffe0;

/// Bytes per command.
const CMD_LEN: usize = 32;
/// The command ring: one 4 KiB page, 128 commands.
const QUEUE_LEN: usize = 4096;

/// How many devices one [`Its`] tracks.
pub const MAX_DEVICES: usize = 32;
/// How many collections one [`Its`] tracks (one per CPU is the usual use).
pub const MAX_COLLECTIONS: usize = osmium_arch::MAX_CPUS;
/// The most event-ID bits [`Its::add_device`] gives a device (2048 events,
/// the most MSI-X has).
pub const MAX_EVENT_BITS: u32 = 11;

/// Bound on waiting for the ITS, in nanoseconds.
const TIMEOUT_NS: u64 = 1_000_000_000;

/// `GITS_BASER<n>.Type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableType {
    /// The device table.
    Devices,
    /// The vPE table (GICv4).
    Vpes,
    /// The interrupt collection table.
    Collections,
}

impl TableType {
    const fn from_field(ty: u64) -> Option<Self> {
        match ty {
            1 => Some(Self::Devices),
            2 => Some(Self::Vpes),
            4 => Some(Self::Collections),
            _ => None,
        }
    }
}

/// Why an ITS operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItsError {
    /// The register window is too small, or the registers read as all ones.
    BadRegisters,
    /// The ITS lacks something needed: physical LPIs, a flat table big
    /// enough, or (for the GICv4 calls) virtual LPIs.
    Unsupported,
    /// Out of memory for a table.
    NoMemory,
    /// A table or the command queue reads back as non-shareable.
    NotCoherent,
    /// The ITS did not consume a command in time, or did not quiesce.
    Timeout,
    /// The ITS stopped at a command it rejected (`GITS_CREADR.Stalled`).
    CommandStalled,
    /// The device ID is beyond the device table, or not added, or already
    /// added.
    BadDevice,
    /// The event ID is beyond the device's ITT, or already (or not) mapped.
    BadEvent,
    /// The collection ID is out of range or not mapped.
    BadCollection,
    /// The vPE ID is beyond the vPE table.
    BadVpe,
    /// [`MAX_DEVICES`] devices are already added.
    TooManyDevices,
    /// An LPI table operation failed (none free, for one).
    Lpi(LpiError),
}

impl From<LpiError> for ItsError {
    fn from(e: LpiError) -> Self {
        Self::Lpi(e)
    }
}

/// A mapped event: the LPI it raises and the message the device sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiVector {
    /// The LPI's interrupt ID, as [`InterruptController::claim`](osmium_hal::irq::InterruptController::claim) reports it.
    pub intid: u32,
    /// Program this into the device's MSI or MSI-X entry.
    pub message: MsiMessage,
}

/// Command encodings, one `[u64; 4]` per command as the ITS reads it.
///
/// A *target* (`rdbase`) is what [`Its::collection_target`] returns: the
/// redistributor's physical address shifted right by 16 when
/// `GITS_TYPER.PTA` is set, else its processor number.
pub mod cmd {
    /// One ITS command.
    pub type Command = [u64; 4];

    const MOVI: u64 = 0x01;
    const INT: u64 = 0x03;
    const CLEAR: u64 = 0x04;
    const SYNC: u64 = 0x05;
    const MAPD: u64 = 0x08;
    const MAPC: u64 = 0x09;
    const MAPTI: u64 = 0x0a;
    const MAPI: u64 = 0x0b;
    const INV: u64 = 0x0c;
    const INVALL: u64 = 0x0d;
    const MOVALL: u64 = 0x0e;
    const DISCARD: u64 = 0x0f;
    const VMOVI: u64 = 0x21;
    const VMOVP: u64 = 0x22;
    const VSYNC: u64 = 0x25;
    const VMAPP: u64 = 0x29;
    const VMAPTI: u64 = 0x2a;
    const VINVALL: u64 = 0x2d;

    const VALID: u64 = 1 << 63;
    /// ITT address bits 51:8.
    const ITT_ADDR: u64 = 0x000f_ffff_ffff_ff00;
    /// Target and vPT address bits 51:16.
    const ADDR_51_16: u64 = 0x000f_ffff_ffff_0000;
    /// The doorbell value meaning "no doorbell".
    pub const NO_DOORBELL: u32 = 1023;

    const fn dev(code: u64, device: u32) -> u64 {
        code | (device as u64) << 32
    }

    const fn target(rdbase: u64) -> u64 {
        (rdbase << 16) & ADDR_51_16
    }

    const fn vpe(vpe: u16) -> u64 {
        (vpe as u64) << 32
    }

    /// `MAPD`: device `device` gets the ITT at `itt` (256-byte aligned) with
    /// `event_bits` bits of event ID; with `valid` false, unmaps it.
    pub const fn mapd(device: u32, itt: u64, event_bits: u32, valid: bool) -> Command {
        let size = event_bits.saturating_sub(1) as u64 & 0x1f;
        let dw2 = if valid { VALID | (itt & ITT_ADDR) } else { 0 };
        [dev(MAPD, device), size, dw2, 0]
    }

    /// `MAPC`: collection `icid` goes to redistributor `rdbase`.
    pub const fn mapc(icid: u16, rdbase: u64, valid: bool) -> Command {
        let v = if valid { VALID | target(rdbase) } else { 0 };
        [MAPC, 0, v | icid as u64, 0]
    }

    /// `MAPTI`: `device`'s `event` raises LPI `intid` in collection `icid`.
    pub const fn mapti(device: u32, event: u32, intid: u32, icid: u16) -> Command {
        [dev(MAPTI, device), event as u64 | (intid as u64) << 32, icid as u64, 0]
    }

    /// `MAPI`: `device`'s `event` raises the LPI whose ID is `event`.
    pub const fn mapi(device: u32, event: u32, icid: u16) -> Command {
        [dev(MAPI, device), event as u64, icid as u64, 0]
    }

    /// `MOVI`: `device`'s `event` moves to collection `icid`.
    pub const fn movi(device: u32, event: u32, icid: u16) -> Command {
        [dev(MOVI, device), event as u64, icid as u64, 0]
    }

    /// `DISCARD`: forget `device`'s `event` (and clear its pending LPI).
    pub const fn discard(device: u32, event: u32) -> Command {
        [dev(DISCARD, device), event as u64, 0, 0]
    }

    /// `INT`: raise `device`'s `event` as if the device had written it.
    pub const fn int(device: u32, event: u32) -> Command {
        [dev(INT, device), event as u64, 0, 0]
    }

    /// `CLEAR`: clear the pending state of `device`'s `event`'s LPI.
    pub const fn clear(device: u32, event: u32) -> Command {
        [dev(CLEAR, device), event as u64, 0, 0]
    }

    /// `INV`: reload the configuration of `device`'s `event`'s LPI.
    pub const fn inv(device: u32, event: u32) -> Command {
        [dev(INV, device), event as u64, 0, 0]
    }

    /// `INVALL`: reload the configuration of every LPI in collection `icid`.
    pub const fn invall(icid: u16) -> Command {
        [INVALL, 0, icid as u64, 0]
    }

    /// `MOVALL`: move every pending LPI from one redistributor to another.
    pub const fn movall(from: u64, to: u64) -> Command {
        [MOVALL, 0, target(from), target(to)]
    }

    /// `SYNC`: wait until every earlier command's effect on `rdbase` is
    /// visible.
    pub const fn sync(rdbase: u64) -> Command {
        [SYNC, 0, target(rdbase), 0]
    }

    /// `VMAPP` (GICv4.0): vPE `vpe` lives on redistributor `rdbase`, with its
    /// virtual pending table at `vpt` (64 KiB aligned) covering `id_bits`
    /// bits of virtual interrupt ID.
    pub const fn vmapp(vpe_id: u16, rdbase: u64, vpt: u64, id_bits: u32, valid: bool) -> Command {
        let dw2 = if valid { VALID | target(rdbase) } else { 0 };
        [VMAPP, vpe(vpe_id), dw2, (vpt & ADDR_51_16) | (id_bits.saturating_sub(1) as u64 & 0x1f)]
    }

    /// `VMAPTI`: `device`'s `event` raises virtual LPI `vintid` on vPE
    /// `vpe`; if the vPE is not resident, physical LPI `doorbell` instead
    /// ([`NO_DOORBELL`] for none).
    pub const fn vmapti(device: u32, event: u32, vpe_id: u16, vintid: u32, doorbell: u32) -> Command {
        [dev(VMAPTI, device), event as u64 | vpe(vpe_id), vintid as u64 | (doorbell as u64) << 32, 0]
    }

    /// `VMOVI`: `device`'s `event` moves to vPE `vpe`, with `doorbell` as for
    /// [`vmapti`] (`None` leaves no doorbell).
    pub const fn vmovi(device: u32, event: u32, vpe_id: u16, doorbell: Option<u32>) -> Command {
        let dw2 = match doorbell {
            Some(db) => 1 | (db as u64) << 32,
            None => 0,
        };
        [dev(VMOVI, device), event as u64 | vpe(vpe_id), dw2, 0]
    }

    /// `VMOVP`: vPE `vpe` moves to redistributor `rdbase`. `seq` and
    /// `its_list` coordinate several ITSes (`GITS_TYPER.VMOVP` clear); a
    /// single ITS passes 0 for both.
    pub const fn vmovp(vpe_id: u16, rdbase: u64, seq: u16, its_list: u16) -> Command {
        [VMOVP | (seq as u64) << 32, its_list as u64 | vpe(vpe_id), target(rdbase), 0]
    }

    /// `VSYNC`: wait until every earlier command's effect on vPE `vpe` is
    /// visible.
    pub const fn vsync(vpe_id: u16) -> Command {
        [VSYNC, vpe(vpe_id), 0, 0]
    }

    /// `VINVALL`: reload the configuration of every virtual LPI of vPE `vpe`.
    pub const fn vinvall(vpe_id: u16) -> Command {
        [VINVALL, vpe(vpe_id), 0, 0]
    }
}

/// The number of bytes and the `GITS_BASER<n>.Size` field for a flat table
/// of `entries` entries of `entry_size` bytes in pages of `page` bytes, or
/// `None` if it needs more than the 256 pages a flat table can have.
pub const fn flat_table_size(entries: u64, entry_size: u64, page: u64) -> Option<(usize, u64)> {
    let bytes = entries.saturating_mul(entry_size);
    let pages = bytes.div_ceil(page);
    let pages = if pages == 0 { 1 } else { pages };
    if pages > 256 {
        return None;
    }
    Some(((pages * page) as usize, pages - 1))
}

/// A device's interrupt translation table and which LPI each event has.
struct Device<'d, D: DmaAllocator + ?Sized> {
    id: u32,
    event_bits: u32,
    _itt: OwnedDma<'d, D>,
    /// Per event: the LPI it raises and its collection, as `intid | icid << 32`
    /// (zero for an unmapped event). For a virtual event (GICv4), the
    /// virtual interrupt ID with [`VIRTUAL_EVENT`] set and the vPE ID in
    /// place of the collection.
    events: OwnedDma<'d, D>,
}

/// Marks a [`Device::events`] slot as mapped to a virtual LPI.
pub(crate) const VIRTUAL_EVENT: u64 = 1 << 63;

/// The command ring.
struct Queue<'d, D: DmaAllocator + ?Sized> {
    ring: OwnedDma<'d, D>,
    /// Byte offset of the next free slot.
    write: usize,
}

/// One table set up from a `GITS_BASER<n>`.
struct Table<'d, D: DmaAllocator + ?Sized> {
    ty: TableType,
    entries: u64,
    _mem: AlignedDma<'d, D>,
}

/// An interrupt translation service, set up and enabled.
pub struct Its<'d, D: DmaAllocator + ?Sized> {
    io: IoMem,
    phys: PhysAddr,
    clock: &'d dyn Clock,
    dma: &'d D,
    typer: u64,
    device_bits: u32,
    queue: IrqSpinLock<Queue<'d, D>>,
    tables: [Option<Table<'d, D>>; 8],
    devices: IrqSpinLock<[Option<Device<'d, D>>; MAX_DEVICES]>,
    /// Each collection's target, or `u64::MAX`.
    collections: IrqSpinLock<[u64; MAX_COLLECTIONS]>,
}

// SAFETY: the tables in `tables` are never touched by the CPU after setup;
// the queue, devices and collections are behind locks; the registers are
// an `IoMem`. The allocator and clock references are shared, so the
// allocator must be `Sync` (the clock is by its trait).
unsafe impl<D: DmaAllocator + Sync + ?Sized> Sync for Its<'_, D> {}
// SAFETY: as above, for moving the owned memory to another CPU.
unsafe impl<D: DmaAllocator + Sync + ?Sized> Send for Its<'_, D> {}

/// What [`Its::new`] sizes its tables for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItsConfig {
    /// Device IDs `0..2^device_bits` get device-table entries (capped at
    /// what the ITS implements). 16 covers a whole PCI segment.
    pub device_bits: u32,
    /// vPE IDs `0..vpes` get vPE-table entries, if the ITS has virtual
    /// LPIs (GICv4).
    pub vpes: u32,
}

impl Default for ItsConfig {
    fn default() -> Self {
        Self { device_bits: 16, vpes: 64 }
    }
}

impl<'d, D: DmaAllocator + ?Sized> Its<'d, D> {
    /// Takes over the ITS whose registers (both 64 KiB frames) are `io`, at
    /// physical address `phys` (the MSI doorbell is there plus
    /// [`GITS_TRANSLATER`]). Disables it if firmware left it on, allocates
    /// the command queue and the tables its `GITS_BASER<n>` registers ask
    /// for, sized by `config`, and enables it. Collections and devices are
    /// then mapped with the methods below.
    pub fn new(
        io: IoMem,
        phys: PhysAddr,
        dma: &'d D,
        clock: &'d dyn Clock,
        config: ItsConfig,
    ) -> Result<Self, ItsError> {
        if io.len() < ITS_REGS_LEN {
            return Err(ItsError::BadRegisters);
        }
        let typer: u64 = io.rd(GITS_TYPER);
        let iidr: u32 = io.rd(GITS_IIDR);
        if typer == u64::MAX && iidr == u32::MAX {
            return Err(ItsError::BadRegisters);
        }
        if typer & TYPER_PHYSICAL == 0 {
            return Err(ItsError::Unsupported);
        }
        let hw_device_bits = (typer >> 13 & 0x1f) as u32 + 1;
        let device_bits = config.device_bits.clamp(1, hw_device_bits);

        // Quiesce before reprogramming.
        let ctlr: u32 = io.rd(GITS_CTLR);
        if ctlr & CTLR_ENABLED != 0 {
            io.wr(GITS_CTLR, ctlr & !CTLR_ENABLED);
        }
        wait(clock, || io.rd::<u32>(GITS_CTLR) & CTLR_QUIESCENT != 0)?;

        let ring = OwnedDma::new(dma, QUEUE_LEN).ok_or(ItsError::NoMemory)?;
        let cbaser =
            BASER_VALID | BASER_ATTRS | (ring.device_addr().as_u64() & ADDR_MASK_4K) | (QUEUE_LEN / 4096 - 1) as u64;
        io.wr(GITS_CBASER, cbaser);
        if io.rd::<u64>(GITS_CBASER) & BASER_SHAREABILITY == 0 {
            io.wr(GITS_CBASER, 0u64);
            return Err(ItsError::NotCoherent);
        }
        io.wr(GITS_CWRITER, 0u64);

        let virt = typer & TYPER_VIRTUAL != 0;
        let mut tables: [Option<Table<'d, D>>; 8] = [const { None }; 8];
        let mut failed = None;
        for (n, slot) in tables.iter_mut().enumerate() {
            let off = GITS_BASER + n * 8;
            let v: u64 = io.rd(off);
            let Some(ty) = TableType::from_field(v >> 56 & 7) else { continue };
            let entries = match ty {
                TableType::Devices => 1u64 << device_bits,
                TableType::Collections => MAX_COLLECTIONS as u64,
                TableType::Vpes if virt => u64::from(config.vpes.max(1)),
                TableType::Vpes => continue,
            };
            match Self::setup_table(&io, off, v, ty, entries, dma) {
                Ok(table) => *slot = Some(table),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        if failed.is_none() && tables.iter().flatten().all(|t| t.ty != TableType::Devices) {
            failed = Some(ItsError::Unsupported);
        }
        if let Some(e) = failed {
            // The queue and the tables already programmed are freed on
            // return: invalidate the registers that point at them first.
            for (n, _) in tables.iter().enumerate().filter(|(_, t)| t.is_some()) {
                io.wr(GITS_BASER + n * 8, 0u64);
            }
            io.wr(GITS_CBASER, 0u64);
            return Err(e);
        }

        osmium_arch::barrier::mb();
        io.wr(GITS_CTLR, io.rd::<u32>(GITS_CTLR) | CTLR_ENABLED);
        Ok(Self {
            io,
            phys,
            clock,
            dma,
            typer,
            device_bits,
            queue: IrqSpinLock::new(Queue { ring, write: 0 }),
            tables,
            devices: IrqSpinLock::new([const { None }; MAX_DEVICES]),
            collections: IrqSpinLock::new([u64::MAX; MAX_COLLECTIONS]),
        })
    }

    /// Allocates and programs the table of `GITS_BASER<n>` (at `off`, read
    /// as `v`). Tries 4 KiB pages first and follows whatever page size the
    /// ITS insists on.
    fn setup_table(
        io: &IoMem,
        off: usize,
        v: u64,
        ty: TableType,
        entries: u64,
        dma: &'d D,
    ) -> Result<Table<'d, D>, ItsError> {
        let entry_size = (v >> 48 & 0x1f) + 1;
        let mut page_code = 0u64;
        for _ in 0..3 {
            let page = 4096u64 << (2 * page_code);
            let (bytes, size) = flat_table_size(entries, entry_size, page).ok_or(ItsError::Unsupported)?;
            let mem = AlignedDma::new(dma, bytes, page as usize).ok_or(ItsError::NoMemory)?;
            let pa = mem.addr().as_u64();
            // With 64 KiB pages, address bits 51:48 go in 15:12.
            let addr = if page_code == 2 { (pa & 0xffff_ffff_0000) | (pa >> 48 & 0xf) << 12 } else { pa & BASER_ADDR };
            io.wr(off, BASER_VALID | BASER_ATTRS | (v & BASER_RO) | addr | page_code << 8 | size);
            let back: u64 = io.rd(off);
            let back_code = back >> 8 & 3;
            if back_code == page_code {
                if back & BASER_SHAREABILITY == 0 {
                    io.wr(off, 0u64);
                    return Err(ItsError::NotCoherent);
                }
                if back & BASER_INDIRECT != 0 {
                    io.wr(off, 0u64);
                    return Err(ItsError::Unsupported);
                }
                return Ok(Table { ty, entries: (bytes as u64) / entry_size, _mem: mem });
            }
            io.wr(off, 0u64);
            page_code = back_code.min(2);
        }
        Err(ItsError::Unsupported)
    }

    /// The physical address of the MSI doorbell, `GITS_TRANSLATER`.
    pub fn doorbell(&self) -> u64 {
        self.phys.as_u64().wrapping_add(GITS_TRANSLATER)
    }

    /// `GITS_TYPER`.
    pub fn typer(&self) -> u64 {
        self.typer
    }

    /// Whether the ITS can map events to virtual LPIs (GICv4).
    pub fn has_virtual_lpis(&self) -> bool {
        self.typer & TYPER_VIRTUAL != 0
    }

    /// Whether collections target redistributors by physical address
    /// (`GITS_TYPER.PTA`) rather than processor number.
    pub fn targets_by_address(&self) -> bool {
        self.typer & TYPER_PTA != 0
    }

    /// Device IDs the device table covers: `0..2^device_bits()`.
    pub fn device_bits(&self) -> u32 {
        self.device_bits
    }

    /// How many entries the table of type `ty` has room for, if there is one.
    pub fn table_entries(&self, ty: TableType) -> Option<u64> {
        self.tables.iter().flatten().find(|t| t.ty == ty).map(|t| t.entries)
    }

    /// The bits of collection ID the ITS implements.
    fn collection_bits(&self) -> u32 {
        if self.typer & TYPER_CIL != 0 { (self.typer >> 32 & 0xf) as u32 + 1 } else { 16 }
    }

    /// The target that names the redistributor of logical CPU `cpu`, for
    /// [`Its::map_collection`]. `gicr_phys` is the physical address of the
    /// redistributor region `gic` was created on.
    pub fn collection_target<C: CpuInterface>(&self, gic: &GicV3<C>, cpu: usize, gicr_phys: PhysAddr) -> Option<u64> {
        let rd = gic.redistributor(cpu)?;
        Some(if self.targets_by_address() {
            gicr_phys.as_u64().checked_add(rd.offset as u64)? >> 16
        } else {
            u64::from(rd.processor_number)
        })
    }

    /// Writes `cmds` to the queue and waits until the ITS has consumed them.
    pub fn submit(&self, cmds: &[cmd::Command]) -> Result<(), ItsError> {
        let mut q = self.queue.lock();
        for c in cmds {
            let next = (q.write + CMD_LEN) % QUEUE_LEN;
            // Full when the slot after this one is where the ITS reads.
            wait(self.clock, || self.read_offset() != next as u64)?;
            for (i, w) in c.iter().enumerate() {
                q.ring.store(q.write + i * 8, *w);
            }
            q.write = next;
        }
        osmium_arch::barrier::mb();
        self.io.wr(GITS_CWRITER, q.write as u64);
        let done = q.write as u64;
        let mut stalled = false;
        wait(self.clock, || {
            let r: u64 = self.io.rd(GITS_CREADR);
            stalled = r & CREADR_STALLED != 0;
            stalled || r & QUEUE_OFFSET == done
        })?;
        if stalled { Err(ItsError::CommandStalled) } else { Ok(()) }
    }

    fn read_offset(&self) -> u64 {
        self.io.rd::<u64>(GITS_CREADR) & QUEUE_OFFSET
    }

    /// Maps collection `icid` to the redistributor `target` (from
    /// [`Its::collection_target`]) and reloads the configuration of the
    /// LPIs already in it.
    pub fn map_collection(&self, icid: u16, target: u64) -> Result<(), ItsError> {
        if icid as usize >= MAX_COLLECTIONS
            || u32::from(icid) >= 1 << self.collection_bits()
            || self.table_entries(TableType::Collections).is_some_and(|n| u64::from(icid) >= n)
        {
            return Err(ItsError::BadCollection);
        }
        self.submit(&[cmd::mapc(icid, target, true), cmd::invall(icid), cmd::sync(target)])?;
        if let Some(slot) = self.collections.lock().get_mut(icid as usize) {
            *slot = target;
        }
        Ok(())
    }

    /// The target collection `icid` is mapped to.
    pub fn collection(&self, icid: u16) -> Option<u64> {
        self.collections.lock().get(icid as usize).copied().filter(|&t| t != u64::MAX)
    }

    /// Gives device `device` an ITT with room for `events` event IDs
    /// (rounded up to a power of two, at most 2^[`MAX_EVENT_BITS`]).
    pub fn add_device(&self, device: u32, events: u32) -> Result<(), ItsError> {
        let hw_event_bits = (self.typer >> 8 & 0x1f) as u32 + 1;
        let event_bits = events.max(2).next_power_of_two().trailing_zeros();
        if event_bits > MAX_EVENT_BITS || event_bits > hw_event_bits {
            return Err(ItsError::BadEvent);
        }
        if u64::from(device) >= 1u64 << self.device_bits {
            return Err(ItsError::BadDevice);
        }
        let mut devices = self.devices.lock();
        if devices.iter().flatten().any(|d| d.id == device) {
            return Err(ItsError::BadDevice);
        }
        let slot = devices.iter_mut().find(|d| d.is_none()).ok_or(ItsError::TooManyDevices)?;
        let itt_entry = (self.typer >> 4 & 0xf) as usize + 1;
        let itt = OwnedDma::new(self.dma, (itt_entry << event_bits).max(256)).ok_or(ItsError::NoMemory)?;
        let events = OwnedDma::new(self.dma, 8 << event_bits).ok_or(ItsError::NoMemory)?;
        self.submit(&[cmd::mapd(device, itt.device_addr().as_u64(), event_bits, true)])?;
        *slot = Some(Device { id: device, event_bits, _itt: itt, events });
        Ok(())
    }

    /// Discards every mapped event of `device` (freeing their LPIs to
    /// `lpis`; virtual ones go back to nobody) and unmaps its ITT.
    pub fn remove_device<A: DmaAllocator + ?Sized>(
        &self,
        device: u32,
        lpis: &LpiTables<'_, A>,
    ) -> Result<(), ItsError> {
        let mut devices = self.devices.lock();
        let slot =
            devices.iter_mut().find(|d| d.as_ref().is_some_and(|d| d.id == device)).ok_or(ItsError::BadDevice)?;
        if let Some(d) = slot.as_ref() {
            for event in 0..1u32 << d.event_bits {
                let e: u64 = d.events.load(event as usize * 8);
                if e != 0 {
                    self.submit(&[cmd::discard(device, event)])?;
                    if e & VIRTUAL_EVENT == 0 {
                        lpis.free(e as u32);
                    }
                    d.events.store(event as usize * 8, 0u64);
                }
            }
        }
        self.submit(&[cmd::mapd(device, 0, 0, false)])?;
        // The ITS no longer reads the ITT.
        *slot = None;
        Ok(())
    }

    /// Runs `f` on `device`'s event slot, under the device lock.
    pub(crate) fn with_event<R>(
        &self,
        device: u32,
        event: u32,
        f: impl FnOnce(&OwnedDma<'d, D>, usize) -> Result<R, ItsError>,
    ) -> Result<R, ItsError> {
        let devices = self.devices.lock();
        let d = devices.iter().flatten().find(|d| d.id == device).ok_or(ItsError::BadDevice)?;
        if event >= 1 << d.event_bits {
            return Err(ItsError::BadEvent);
        }
        f(&d.events, event as usize * 8)
    }

    /// Allocates an LPI from `lpis`, gives it `priority` (higher is more
    /// urgent) and enables it, and maps `device`'s `event` to it in
    /// collection `icid`. Returns the LPI and the MSI message: the doorbell
    /// address, with `event` as the data.
    pub fn map_event<A: DmaAllocator + ?Sized>(
        &self,
        device: u32,
        event: u32,
        icid: u16,
        lpis: &LpiTables<'_, A>,
        priority: u8,
    ) -> Result<MsiVector, ItsError> {
        let target = self.collection(icid).ok_or(ItsError::BadCollection)?;
        self.with_event(device, event, |events, slot| {
            if events.load::<u64>(slot) != 0 {
                return Err(ItsError::BadEvent);
            }
            let intid = lpis.alloc().ok_or(ItsError::Lpi(LpiError::BadLpi))?;
            let mapped = lpis.configure(intid, priority, true).map_err(ItsError::from).and_then(|()| {
                self.submit(&[cmd::mapti(device, event, intid, icid), cmd::inv(device, event), cmd::sync(target)])
            });
            if let Err(e) = mapped {
                lpis.free(intid);
                return Err(e);
            }
            events.store(slot, u64::from(intid) | u64::from(icid) << 32);
            Ok(MsiVector { intid, message: MsiMessage { address: self.doorbell(), data: event } })
        })
    }

    /// The LPI `device`'s `event` is mapped to, if it is mapped to one.
    pub fn event_lpi(&self, device: u32, event: u32) -> Option<u32> {
        self.with_event(device, event, |events, slot| Ok(events.load::<u64>(slot)))
            .ok()
            .filter(|&e| e != 0 && e & VIRTUAL_EVENT == 0)
            .map(|e| e as u32)
    }

    /// Unmaps `device`'s `event` (`DISCARD`) and frees its LPI to `lpis`.
    /// The device should no longer send it.
    pub fn unmap_event<A: DmaAllocator + ?Sized>(
        &self,
        device: u32,
        event: u32,
        lpis: &LpiTables<'_, A>,
    ) -> Result<(), ItsError> {
        self.with_event(device, event, |events, slot| {
            let e: u64 = events.load(slot);
            if e == 0 {
                return Err(ItsError::BadEvent);
            }
            let sync = if e & VIRTUAL_EVENT != 0 {
                cmd::vsync((e >> 32) as u16)
            } else {
                cmd::sync(self.collection((e >> 32) as u16).unwrap_or(0))
            };
            self.submit(&[cmd::discard(device, event), sync])?;
            if e & VIRTUAL_EVENT == 0 {
                lpis.free(e as u32);
            }
            events.store(slot, 0u64);
            Ok(())
        })
    }

    /// Moves `device`'s (physical) `event` to collection `icid` (`MOVI`).
    pub fn move_event(&self, device: u32, event: u32, icid: u16) -> Result<(), ItsError> {
        let target = self.collection(icid).ok_or(ItsError::BadCollection)?;
        self.with_event(device, event, |events, slot| {
            let e: u64 = events.load(slot);
            if e == 0 || e & VIRTUAL_EVENT != 0 {
                return Err(ItsError::BadEvent);
            }
            let old = self.collection((e >> 32) as u16).unwrap_or(target);
            self.submit(&[cmd::movi(device, event, icid), cmd::sync(old), cmd::sync(target)])?;
            events.store(slot, (e & 0xffff_ffff) | u64::from(icid) << 32);
            Ok(())
        })
    }

    /// Raises `device`'s `event` as if the device had sent it (`INT`).
    pub fn trigger(&self, device: u32, event: u32) -> Result<(), ItsError> {
        self.event_command(device, event, cmd::int(device, event))
    }

    /// Clears the pending state of `device`'s `event`'s interrupt (`CLEAR`).
    pub fn clear(&self, device: u32, event: u32) -> Result<(), ItsError> {
        self.event_command(device, event, cmd::clear(device, event))
    }

    /// Issues `c` about a mapped event, followed by the matching sync.
    fn event_command(&self, device: u32, event: u32, c: cmd::Command) -> Result<(), ItsError> {
        let e = self.with_event(device, event, |events, slot| Ok(events.load::<u64>(slot)))?;
        if e == 0 {
            return Err(ItsError::BadEvent);
        }
        let sync = if e & VIRTUAL_EVENT != 0 {
            cmd::vsync((e >> 32) as u16)
        } else {
            cmd::sync(self.collection((e >> 32) as u16).ok_or(ItsError::BadCollection)?)
        };
        self.submit(&[c, sync])
    }
}

impl<D: DmaAllocator + ?Sized> Drop for Its<'_, D> {
    /// Disables the ITS and invalidates its tables before their memory goes.
    fn drop(&mut self) {
        let ctlr: u32 = self.io.rd(GITS_CTLR);
        self.io.wr(GITS_CTLR, ctlr & !CTLR_ENABLED);
        let _ = wait(self.clock, || self.io.rd::<u32>(GITS_CTLR) & CTLR_QUIESCENT != 0);
        for n in 0..8 {
            if self.tables.get(n).is_some_and(Option::is_some) {
                self.io.wr(GITS_BASER + n * 8, 0u64);
            }
        }
        self.io.wr(GITS_CBASER, 0u64);
    }
}

/// Polls `done` for up to [`TIMEOUT_NS`].
fn wait(clock: &dyn Clock, mut done: impl FnMut() -> bool) -> Result<(), ItsError> {
    let deadline = clock.now_ns().saturating_add(TIMEOUT_NS);
    loop {
        if done() {
            return Ok(());
        }
        if clock.now_ns() > deadline {
            return Err(ItsError::Timeout);
        }
        osmium_arch::cpu::spin_hint();
    }
}

#[cfg(test)]
pub(crate) mod tests;
