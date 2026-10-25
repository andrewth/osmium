//! Arm SMMUv3.
//!
//! [`Smmuv3`] drives one System MMU. Its [`Iommu`] implementation is stage 2
//! only: each stream table entry points at a [`Aarch64Stage2`] page table
//! (4 KiB granule, 4 levels, starting at level 0). [`Smmuv3::stage1`] returns
//! a second [`Iommu`] view of the same unit that attaches devices through
//! stage 1 instead: the entry points at a context descriptor (one per stream,
//! no substreams) whose `TTB0` is an [`Aarch64Stage1Io`] table, and the domain
//! number is the ASID. [`Smmuv3::attach_nested`] configures both stages for
//! guest-style nesting. Which stages exist is read from `IDR0.S1P`/`S2P`.
//!
//! The stream table is linear (one 64-byte entry per stream ID) or, when
//! `IDR0.ST_LEVEL` allows and the stream ID space is large ([`StreamTableLayout`]),
//! two-level: a level-1 array of descriptors, each linking a 4 KiB level-2
//! table of 64 entries that is allocated when the first device in its range
//! attaches (and freed when the unit is dropped). The stream ID of a PCI function is its requester ID plus a fixed
//! offset ([`Smmuv3::set_stream_offset`], from the device tree's `iommu-map`
//! or the ACPI IORT; zero by default). Software talks to the unit through a
//! command queue (stream-table and TLB invalidations, followed by a
//! `CMD_SYNC` that it polls for) and reads faults from the event queue.
//!
//! The driver needs `IDR0.S2P` or `S1P`, `IDR0.COHACC`, AArch64 table format and 4 KiB
//! granules, and refuses units that preset their queues or tables. The
//! stream table must be aligned to its own size: allocators that hand out
//! power-of-two blocks (frame allocators) do. Contexts with substreams
//! (PASIDs), ATS, PRI, MSI-signalled completion and the interrupt lines are
//! not used; unattached stream IDs abort.

use core::mem::ManuallyDrop;

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::iommu::{DeviceId, DomainId, Fault, Iommu, IommuError};
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::Address;
use osmium_hal::timer::Clock;
use osmium_mm::PhysAddr;
use osmium_mm::paging::formats::{Aarch64, Aarch64Stage2};
use osmium_mm::paging::{MapFlags, PageTableFormat};
use osmium_sync::IrqSpinLock;

use super::{DEFAULT_TIMEOUT_NS, Pages, Regs, wait_until};

// Registers (page 0, then the event queue's pointers in page 1).
const IDR0: usize = 0x00;
const IDR1: usize = 0x04;
const IDR5: usize = 0x14;
const CR0: usize = 0x20;
const CR0ACK: usize = 0x24;
const CR1: usize = 0x28;
const CR2: usize = 0x2c;
const GBPA: usize = 0x44;
const GERROR: usize = 0x60;
const GERRORN: usize = 0x64;
const STRTAB_BASE: usize = 0x80;
const STRTAB_BASE_CFG: usize = 0x88;
const CMDQ_BASE: usize = 0x90;
const CMDQ_PROD: usize = 0x98;
const CMDQ_CONS: usize = 0x9c;
const EVENTQ_BASE: usize = 0xa0;
const EVENTQ_PROD: usize = 0x100a8;
const EVENTQ_CONS: usize = 0x100ac;
const REGS_LEN: usize = 0x100b0;

// IDR0.
const IDR0_S2P: u32 = 1 << 0;
const IDR0_S1P: u32 = 1 << 1;
const IDR0_TTF_AARCH64: u32 = 1 << 3;
const IDR0_COHACC: u32 = 1 << 4;
const IDR0_ASID16: u32 = 1 << 12;
const IDR0_ST_LEVEL_SHIFT: u32 = 27;
const IDR0_VMID16: u32 = 1 << 18;
// IDR1.
const IDR1_TABLES_PRESET: u32 = 1 << 30;
const IDR1_QUEUES_PRESET: u32 = 1 << 29;
// IDR5.
const IDR5_GRAN4K: u32 = 1 << 4;

// CR0 bits.
const CR0_SMMUEN: u32 = 1 << 0;
const CR0_EVENTQEN: u32 = 1 << 2;
const CR0_CMDQEN: u32 = 1 << 3;
/// Inner/outer write-back cacheable, inner shareable, for tables and queues.
const CR1_COHERENT: u32 = 3 << 10 | 1 << 8 | 1 << 6 | 3 << 4 | 1 << 2 | 1;
const CR2_RECINVSID: u32 = 1 << 1;
const BASE_RA: u64 = 1 << 62;
const GERROR_CMDQ_ERR: u32 = 1 << 0;
// GBPA: global bypass attributes, used while SMMUEN is clear.
const GBPA_ABORT: u32 = 1 << 20;
const GBPA_UPDATE: u32 = 1 << 31;

// Commands (opcode in bits 7:0).
const CMD_CFGI_STE: u64 = 0x03;
const CMD_CFGI_CD: u64 = 0x05;
const CMD_CFGI_ALL: u64 = 0x04;
const CMD_TLBI_NH_ASID: u64 = 0x11;
const CMD_TLBI_S12_VMALL: u64 = 0x28;
const CMD_TLBI_NSNH_ALL: u64 = 0x30;
const CMD_SYNC: u64 = 0x46;
/// CMD_SYNC completion signal: send event (no interrupt or MSI needed).
const SYNC_CS_SEV: u64 = 2 << 12;
const CMD_BYTES: usize = 16;
const EVENT_BYTES: usize = 32;

// Stream table entry.
const STE_BYTES: usize = 64;
const STE_V: u64 = 1 << 0;
const STE_CONFIG_S1: u64 = 5 << 1;
const STE_CONFIG_S2: u64 = 6 << 1;
const STE_CONFIG_NESTED: u64 = 7 << 1;
const STE_CONFIG_MASK: u64 = 7 << 1;
const S2AA64: u64 = 1 << 51;
const S2R: u64 = 1 << 58;
const ADDR_MASK_4: u64 = 0x000f_ffff_ffff_fff0;
/// Address mask for pointers aligned to 64 bytes (`S1ContextPtr`, `L2Ptr`).
const ADDR_MASK_6: u64 = 0x000f_ffff_ffff_ffc0;
/// STE word 1 for stage 1: `S1DSS` = use substream 0, inner and outer
/// write-back read/write-allocate, inner shareable table walks.
const STE1_S1: u64 = 2 | 1 << 2 | 1 << 4 | 3 << 6;

// Context descriptor (64 bytes; word 0 holds the TCR fields, `V` and the ASID).
const CD_BYTES: usize = 64;
const CD_V: u64 = 1 << 31;
const CD_EPD1: u64 = 1 << 30;
const CD_AA64: u64 = 1 << 41;
const CD_R: u64 = 1 << 45;
const CD_A: u64 = 1 << 46;
const CD_ASET: u64 = 1 << 47;
/// Stage 1 input size: 48 bits, 4 levels from level 0.
const S1_VA_BITS: u32 = 48;
/// `MAIR` attribute 0 is normal write-back, attribute 1 is Device-nGnRnE.
const CD_MAIR: u64 = 0xff;

// Two-level stream tables: each level-2 table is one 4 KiB page of
// `2^L2_SPLIT` entries, which a level-1 descriptor describes with `Span` =
// `L2_SPLIT + 1`.
const L2_SPLIT: u32 = 6;
const L1_FMT_TWO_LEVEL: u32 = 1 << 16;
const L1_DESC_BYTES: usize = 8;

/// Largest queue this driver sizes: one 4 KiB page.
const QUEUE_BYTES: usize = 4096;

/// How the stream table is laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamTableLayout {
    /// Two-level when the unit supports it (`IDR0.ST_LEVEL`) and there are
    /// more than 256 stream IDs; linear otherwise.
    Auto,
    /// One entry per stream ID, allocated up front.
    Linear,
    /// A level-1 array of descriptors, with 64-entry level-2 tables allocated
    /// on demand. Fails with [`IommuError::Unsupported`] on a unit without
    /// two-level tables.
    TwoLevel,
}

/// Which translation stages a stream entry enables.
#[derive(Clone, Copy)]
enum Mode {
    /// Stage 2 only (`root` is an [`Aarch64Stage2`] table).
    S2,
    /// Stage 1 only (`root` is an [`Aarch64Stage1Io`] table).
    S1,
    /// Both; `root` is the stage 1 table, `s2_root` the stage 2 one.
    Nested { s2_root: PhysAddr },
}

/// What to invalidate in the TLB after a stream entry changes.
#[derive(Clone, Copy)]
enum Tlb {
    /// Stage 1 and 2 entries of a VMID.
    Vmid(u16),
    /// Stage 1 entries of an ASID (VMID 0).
    Asid(u16),
}

/// An entry of the stream table, located by [`Smmuv3::ste_slot`].
enum Slot<'s> {
    /// In the linear table.
    Linear(&'s DmaBuffer, usize),
    /// In a level-2 page.
    Page(DmaBuffer, usize),
}

impl Slot<'_> {
    fn buf(&self) -> &DmaBuffer {
        match self {
            Slot::Linear(b, _) => b,
            Slot::Page(b, _) => b,
        }
    }

    fn off(&self) -> usize {
        match *self {
            Slot::Linear(_, o) | Slot::Page(_, o) => o,
        }
    }
}

struct Buffers<'d, D: DmaAllocator + ?Sized> {
    /// The linear stream table, or the level-1 array.
    strtab: OwnedDma<'d, D>,
    /// Level-2 tables, one per level-1 descriptor (two-level tables only).
    l2: Option<Pages<'d, D>>,
    /// Context descriptor pages (64 descriptors each), created by the first
    /// stage-1 attach.
    cds: Option<Pages<'d, D>>,
    commands: OwnedDma<'d, D>,
    events: OwnedDma<'d, D>,
}

struct State<'d, D: DmaAllocator + ?Sized> {
    /// Freed in `drop` only once the unit has stopped using them.
    buffers: ManuallyDrop<Buffers<'d, D>>,
    /// Command queue producer index with wrap bit.
    prod: u32,
    enabled: bool,
}

/// An Arm SMMUv3.
pub struct Smmuv3<'d, D: DmaAllocator + Sync + ?Sized> {
    regs: Regs,
    dma: &'d D,
    s1p: bool,
    s2p: bool,
    asids: u32,
    page_slots: usize,
    clock: &'d dyn Clock,
    segment: u16,
    stream_offset: u32,
    stream_count: u32,
    vmids: u32,
    ia_bits: u32,
    ps: u64,
    cmdq_log2: u32,
    evtq_log2: u32,
    timeout_ns: u64,
    state: IrqSpinLock<State<'d, D>>,
}

/// Index mask plus wrap bit for a queue of `2^log2` entries.
const fn wrap_mask(log2: u32) -> u32 {
    (2u32 << log2) - 1
}

impl<'d, D: DmaAllocator + Sync + ?Sized> Smmuv3<'d, D> {
    /// Takes over the SMMU whose registers (both 64 KiB pages) are `io`,
    /// serving PCI segment `segment` and stream IDs `0..=max_stream_id`.
    /// Translation stays off until the first device attaches. The stream
    /// table layout is [`StreamTableLayout::Auto`].
    pub fn new(
        io: IoMem,
        dma: &'d D,
        clock: &'d dyn Clock,
        segment: u16,
        max_stream_id: u32,
    ) -> Result<Self, IommuError> {
        Self::with_layout(io, dma, clock, segment, max_stream_id, StreamTableLayout::Auto)
    }

    /// As [`new`](Self::new), with an explicit stream table layout.
    pub fn with_layout(
        io: IoMem,
        dma: &'d D,
        clock: &'d dyn Clock,
        segment: u16,
        max_stream_id: u32,
        layout: StreamTableLayout,
    ) -> Result<Self, IommuError> {
        let regs = Regs::new(io, REGS_LEN)?;
        let (idr0, idr1, idr5) = (regs.r32(IDR0), regs.r32(IDR1), regs.r32(IDR5));
        if idr0 == !0 && idr1 == !0 {
            return Err(IommuError::BadRegisters);
        }
        if idr0 & (IDR0_S2P | IDR0_S1P) == 0
            || idr0 & IDR0_COHACC == 0
            || idr0 & IDR0_TTF_AARCH64 == 0
            || idr5 & IDR5_GRAN4K == 0
            || idr1 & (IDR1_TABLES_PRESET | IDR1_QUEUES_PRESET) != 0
        {
            return Err(IommuError::Unsupported);
        }
        let sid_bits = idr1 & 0x3f;
        let mut stream_log2 = (u32::BITS - max_stream_id.max(1).leading_zeros()).max(1);
        let two_level_ok = (idr0 >> IDR0_ST_LEVEL_SHIFT) & 3 != 0;
        let two_level = match layout {
            StreamTableLayout::Linear => false,
            StreamTableLayout::TwoLevel if !two_level_ok => return Err(IommuError::Unsupported),
            StreamTableLayout::TwoLevel => true,
            StreamTableLayout::Auto => two_level_ok && stream_log2 > 8,
        };
        if two_level {
            // The level-1 array needs at least one descriptor.
            stream_log2 = stream_log2.max(L2_SPLIT + 1);
        }
        if stream_log2 > sid_bits || stream_log2 > 24 {
            return Err(IommuError::Unsupported);
        }
        // Stage-2 input size follows the output size, up to 48 bits; the
        // level-0 start needs at least 40.
        let oas = idr5 & 7;
        let out_bits = [32, 36, 40, 42, 44, 48, 52].get(oas as usize).copied().unwrap_or(48);
        let ia_bits = out_bits.min(48);
        if ia_bits < 40 {
            return Err(IommuError::Unsupported);
        }
        let cmdq_log2 = ((idr1 >> 21) & 0x1f).min(8);
        let evtq_log2 = ((idr1 >> 16) & 0x1f).min(7);
        if cmdq_log2 < 2 || evtq_log2 < 2 {
            return Err(IommuError::Unsupported);
        }
        let strtab_bytes = if two_level {
            (1usize << (stream_log2 - L2_SPLIT)) * L1_DESC_BYTES
        } else {
            (1usize << stream_log2) * STE_BYTES
        };
        let strtab = OwnedDma::new(dma, strtab_bytes).ok_or(IommuError::OutOfMemory)?;
        if !strtab.device_addr().is_aligned(strtab_bytes.max(4096) as u64) {
            return Err(IommuError::Unsupported);
        }
        // One page per 64 stream IDs, for level-2 tables and context descriptors.
        let page_slots = 1usize << stream_log2.saturating_sub(L2_SPLIT);
        let buffers = Buffers {
            strtab,
            l2: if two_level { Some(Pages::new(dma, page_slots)?) } else { None },
            cds: None,
            commands: OwnedDma::new(dma, QUEUE_BYTES).ok_or(IommuError::OutOfMemory)?,
            events: OwnedDma::new(dma, QUEUE_BYTES).ok_or(IommuError::OutOfMemory)?,
        };
        let (strtab_addr, commands_addr, events_addr) = (
            buffers.strtab.device_addr().as_u64(),
            buffers.commands.device_addr().as_u64(),
            buffers.events.device_addr().as_u64(),
        );
        let unit = Self {
            regs,
            dma,
            s1p: idr0 & IDR0_S1P != 0,
            s2p: idr0 & IDR0_S2P != 0,
            page_slots,
            asids: if idr0 & IDR0_ASID16 != 0 { 1 << 16 } else { 1 << 8 },
            clock,
            segment,
            stream_offset: 0,
            stream_count: max_stream_id + 1,
            vmids: if idr0 & IDR0_VMID16 != 0 { 1 << 16 } else { 1 << 8 },
            ia_bits,
            ps: oas.min(5) as u64,
            cmdq_log2,
            evtq_log2,
            timeout_ns: DEFAULT_TIMEOUT_NS,
            state: IrqSpinLock::new(State { buffers: ManuallyDrop::new(buffers), prod: 0, enabled: false }),
        };
        // Reconfiguration needs the unit off.
        unit.set_cr0(0)?;
        // Until the first attach, let DMA bypass the unit rather than abort,
        // as with the other IOMMUs here; the reset value is implementation
        // defined. Changes to GBPA take effect through the UPDATE handshake.
        unit.wait(|| unit.regs.r32(GBPA) & GBPA_UPDATE == 0)?;
        unit.regs.w32(GBPA, unit.regs.r32(GBPA) & !GBPA_ABORT | GBPA_UPDATE);
        unit.wait(|| unit.regs.r32(GBPA) & GBPA_UPDATE == 0)?;
        unit.regs.w32(CR1, CR1_COHERENT);
        unit.regs.w32(CR2, CR2_RECINVSID);
        unit.regs.w64(STRTAB_BASE, strtab_addr & ADDR_MASK_4 & !0x3f | BASE_RA);
        let fmt = if two_level { L1_FMT_TWO_LEVEL | L2_SPLIT << 6 } else { 0 };
        unit.regs.w32(STRTAB_BASE_CFG, stream_log2 | fmt);
        unit.regs.w64(CMDQ_BASE, commands_addr & ADDR_MASK_4 & !0x1f | BASE_RA | cmdq_log2 as u64);
        unit.regs.w32(CMDQ_PROD, 0);
        unit.regs.w32(CMDQ_CONS, 0);
        unit.regs.w64(EVENTQ_BASE, events_addr & ADDR_MASK_4 & !0x1f | BASE_RA | evtq_log2 as u64);
        unit.regs.w32(EVENTQ_PROD, 0);
        unit.regs.w32(EVENTQ_CONS, 0);
        unit.set_cr0(CR0_CMDQEN)?;
        {
            let mut st = unit.state.lock();
            unit.post(&mut st, CMD_CFGI_ALL, 31)?;
            unit.post(&mut st, CMD_TLBI_NSNH_ALL, 0)?;
            unit.sync(&mut st)?;
        }
        unit.set_cr0(CR0_CMDQEN | CR0_EVENTQEN)?;
        Ok(unit)
    }

    /// Sets the value added to a PCI requester ID to form its stream ID.
    pub fn set_stream_offset(&mut self, offset: u32) {
        self.stream_offset = offset;
    }

    /// Sets how long to wait for the hardware, in nanoseconds.
    pub fn set_timeout_ns(&mut self, timeout_ns: u64) {
        self.timeout_ns = timeout_ns;
    }

    /// Whether translation is switched on (after the first attach).
    pub fn translating(&self) -> bool {
        self.regs.r32(CR0ACK) & CR0_SMMUEN != 0
    }

    fn wait(&self, done: impl FnMut() -> bool) -> Result<(), IommuError> {
        wait_until(self.clock, self.timeout_ns, done)
    }

    fn set_cr0(&self, value: u32) -> Result<(), IommuError> {
        self.regs.w32(CR0, value);
        self.wait(|| self.regs.r32(CR0ACK) == value)
    }

    fn buffers<'st>(st: &'st State<'d, D>) -> &'st Buffers<'d, D> {
        &st.buffers
    }

    fn stream_id(&self, device: DeviceId) -> Result<u32, IommuError> {
        let sid = (device.bdf() as u32).checked_add(self.stream_offset).ok_or(IommuError::InvalidDevice)?;
        if device.segment() != self.segment || sid >= self.stream_count {
            return Err(IommuError::InvalidDevice);
        }
        Ok(sid)
    }

    fn post(&self, st: &mut State<'d, D>, q0: u64, q1: u64) -> Result<(), IommuError> {
        let mask = wrap_mask(self.cmdq_log2);
        let cons = self.regs.r32(CMDQ_CONS) & mask;
        let (prod, index_mask) = (st.prod, (1u32 << self.cmdq_log2) - 1);
        // Full: same index, different wrap.
        if prod & index_mask == cons & index_mask && prod != cons {
            return Err(IommuError::Busy);
        }
        let at = (prod & index_mask) as usize * CMD_BYTES;
        let cmds = &Self::buffers(st).commands;
        cmds.store::<u64>(at, q0);
        cmds.store::<u64>(at + 8, q1);
        // The producer write is MMIO: only a full barrier orders the command before it.
        barrier::mb();
        st.prod = (prod + 1) & mask;
        self.regs.w32(CMDQ_PROD, st.prod);
        Ok(())
    }

    /// Posts `CMD_SYNC` and waits until the unit has consumed every command.
    fn sync(&self, st: &mut State<'d, D>) -> Result<(), IommuError> {
        self.post(st, CMD_SYNC | SYNC_CS_SEV, 0)?;
        let (mask, want) = (wrap_mask(self.cmdq_log2), st.prod);
        let done = self.wait(|| {
            (self.regs.r32(GERROR) ^ self.regs.r32(GERRORN)) & GERROR_CMDQ_ERR != 0
                || self.regs.r32(CMDQ_CONS) & mask == want
        });
        let active = self.regs.r32(GERROR) ^ self.regs.r32(GERRORN);
        if active & GERROR_CMDQ_ERR != 0 {
            // The unit stopped at the faulting command (CONS). Replace it with
            // a CMD_SYNC, which cannot fault, and empty the queue, both
            // before acknowledging: the unit resumes at CONS on the
            // acknowledgement and must find nothing to run.
            let cons = self.regs.r32(CMDQ_CONS) & mask;
            let at = (cons & ((1u32 << self.cmdq_log2) - 1)) as usize * CMD_BYTES;
            let cmds = &Self::buffers(st).commands;
            cmds.store::<u64>(at, CMD_SYNC);
            cmds.store::<u64>(at + 8, 0);
            st.prod = cons;
            barrier::mb();
            self.regs.w32(CMDQ_PROD, st.prod);
            barrier::mb();
            self.regs.w32(GERRORN, self.regs.r32(GERROR));
            return Err(IommuError::Hardware);
        }
        done
    }

    /// Locates the stream table entry for `sid`; `None` if its level-2 table
    /// does not exist yet.
    fn ste_slot<'s>(b: &'s Buffers<'d, D>, sid: u32) -> Option<Slot<'s>> {
        let off = (sid & ((1 << L2_SPLIT) - 1)) as usize * STE_BYTES;
        match &b.l2 {
            None => Some(Slot::Linear(&b.strtab, sid as usize * STE_BYTES)),
            Some(pages) => pages.get((sid >> L2_SPLIT) as usize).map(|page| Slot::Page(page, off)),
        }
    }

    /// As [`ste_slot`](Self::ste_slot), allocating and linking the level-2
    /// table if needed. The flag says whether it is new.
    fn ste_slot_create<'s>(b: &'s Buffers<'d, D>, sid: u32) -> Result<(Slot<'s>, bool), IommuError> {
        let Some(pages) = &b.l2 else {
            return Ok((Slot::Linear(&b.strtab, sid as usize * STE_BYTES), false));
        };
        let index = (sid >> L2_SPLIT) as usize;
        let (page, created) = pages.get_or_alloc(index)?;
        if created {
            // The zeroed page must be visible before the descriptor makes it reachable.
            barrier::dma_wmb();
            let desc = (L2_SPLIT + 1) as u64 | page.device_addr().as_u64() & ADDR_MASK_6;
            b.strtab.store::<u64>(index * L1_DESC_BYTES, desc);
            barrier::dma_wmb();
        }
        Ok((Slot::Page(page, (sid & ((1 << L2_SPLIT) - 1)) as usize * STE_BYTES), created))
    }

    /// Makes sure the context descriptor pages exist.
    fn ensure_cds(&self, st: &mut State<'d, D>) -> Result<(), IommuError> {
        if st.buffers.cds.is_none() {
            st.buffers.cds = Some(Pages::new(self.dma, self.page_slots)?);
        }
        Ok(())
    }

    /// The page of context descriptors for `sid` and the descriptor's offset in it.
    fn cd_slot(b: &Buffers<'d, D>, sid: u32) -> Option<(DmaBuffer, usize)> {
        let page = b.cds.as_ref()?.get((sid >> L2_SPLIT) as usize)?;
        Some((page, (sid & ((1 << L2_SPLIT) - 1)) as usize * CD_BYTES))
    }

    /// Invalidates what the unit caches for `sid` (its entry, optionally its
    /// context descriptor) and the translations named by `tlb`, then waits.
    fn flush_stream(
        &self,
        st: &mut State<'d, D>,
        sid: u32,
        tlb: Tlb,
        with_cd: bool,
        leaf: bool,
    ) -> Result<(), IommuError> {
        self.post(st, CMD_CFGI_STE | (sid as u64) << 32, leaf as u64)?;
        if with_cd {
            // SSID 0, leaf only.
            self.post(st, CMD_CFGI_CD | (sid as u64) << 32, 1)?;
        }
        match tlb {
            Tlb::Vmid(vmid) => self.post(st, CMD_TLBI_S12_VMALL | (vmid as u64) << 32, 0)?,
            Tlb::Asid(asid) => self.post(st, CMD_TLBI_NH_ASID | (asid as u64) << 48, 0)?,
        }
        self.sync(st)
    }

    /// Whether the unit has a stage 1 (`IDR0.S1P`).
    pub fn has_stage1(&self) -> bool {
        self.s1p
    }

    /// Whether the unit has a stage 2 (`IDR0.S2P`).
    pub fn has_stage2(&self) -> bool {
        self.s2p
    }

    /// Whether the stream table is two-level.
    pub fn two_level(&self) -> bool {
        self.regs.r32(STRTAB_BASE_CFG) & L1_FMT_TWO_LEVEL != 0
    }

    /// A stage-1 [`Iommu`] view of this unit: devices attached through it
    /// translate through an [`Aarch64Stage1Io`] table, with the domain number
    /// as the ASID. Fails with [`IommuError::Unsupported`] on a unit without
    /// stage 1.
    pub fn stage1(&self) -> Result<Stage1<'_, 'd, D>, IommuError> {
        if self.s1p { Ok(Stage1 { unit: self }) } else { Err(IommuError::Unsupported) }
    }

    /// Allocates (if needed) the context descriptor page that `device`'s
    /// stage-1 or nested entry uses and returns its physical address. A
    /// nested attach reads that page and the stage-1 tables through stage 2,
    /// so the caller maps it there (IPA = PA) before
    /// [`attach_nested`](Self::attach_nested).
    pub fn context_descriptor_page(&self, device: DeviceId) -> Result<PhysAddr, IommuError> {
        let sid = self.stream_id(device)?;
        let mut st = self.state.lock();
        self.ensure_cds(&mut st)?;
        let cds = st.buffers.cds.as_ref().ok_or(IommuError::OutOfMemory)?;
        Ok(cds.get_or_alloc((sid >> L2_SPLIT) as usize)?.0.device_addr())
    }

    /// Routes `device`'s DMA through both stages: `s1_root` (an
    /// [`Aarch64Stage1Io`] table, in IPA space) translates IOVAs to IPAs and
    /// `s2_root` (an [`Aarch64Stage2`] table) translates those to physical
    /// addresses. `domain` is both the ASID and the VMID. Stage 2 must map the
    /// stage-1 tables and the descriptor page from
    /// [`context_descriptor_page`](Self::context_descriptor_page) at their own
    /// physical addresses, because the unit reads them through it. Undo with
    /// [`Iommu::detach`].
    ///
    /// # Safety
    /// As for [`Iommu::attach`], for both tables.
    pub unsafe fn attach_nested(
        &self,
        device: DeviceId,
        domain: DomainId,
        s1_root: PhysAddr,
        s2_root: PhysAddr,
    ) -> Result<(), IommuError> {
        self.attach_with(device, domain, s1_root, Mode::Nested { s2_root })
    }

    fn attach_with(&self, device: DeviceId, domain: DomainId, root: PhysAddr, mode: Mode) -> Result<(), IommuError> {
        let sid = self.stream_id(device)?;
        let (stage1, stage2) = (!matches!(mode, Mode::S2), !matches!(mode, Mode::S1));
        if stage1 && (!self.s1p || domain.0 as u32 >= self.asids)
            || stage2 && (!self.s2p || domain.0 as u32 >= self.vmids)
        {
            return Err(IommuError::Unsupported);
        }
        let bad = |pa: PhysAddr| !pa.is_aligned(4096) || pa.as_u64() & !ADDR_MASK_4 != 0;
        if bad(root) || matches!(mode, Mode::Nested { s2_root } if bad(s2_root)) {
            return Err(IommuError::OutOfRange);
        }
        let mut st = self.state.lock();
        if stage1 {
            self.ensure_cds(&mut st)?;
        }
        let (slot, created) = Self::ste_slot_create(&st.buffers, sid)?;
        let (ste, at) = (slot.buf(), slot.off());
        if ste.load::<u64>(at) & STE_V != 0 {
            return Err(IommuError::Busy);
        }
        let mut cd_ptr = 0;
        if stage1 {
            let cds = st.buffers.cds.as_ref().ok_or(IommuError::OutOfMemory)?;
            let cd = cds.get_or_alloc((sid >> L2_SPLIT) as usize)?.0;
            let cd_at = (sid & ((1 << L2_SPLIT) - 1)) as usize * CD_BYTES;
            cd_ptr = cd.device_addr().as_u64().wrapping_add(cd_at as u64) & ADDR_MASK_6;
            // T0SZ, 4 KiB granule, write-back walks, inner shareable, no TTB1.
            let tcr = (64 - S1_VA_BITS) as u64 | 1 << 8 | 1 << 10 | 3 << 12 | CD_EPD1 | self.ps << 32;
            for q in 0..CD_BYTES / 8 {
                cd.store::<u64>(cd_at + q * 8, 0);
            }
            cd.store::<u64>(cd_at + 8, root.as_u64() & ADDR_MASK_4);
            cd.store::<u64>(cd_at + 24, CD_MAIR);
            barrier::dma_wmb();
            cd.store::<u64>(cd_at, tcr | CD_R | CD_A | CD_ASET | CD_AA64 | CD_V | (domain.0 as u64) << 48);
        }
        // VTCR: T0SZ, SL0 = 2 (start at level 0), IR0/OR0 write-back,
        // SH0 inner shareable, 4 KiB granule, output size.
        let vtcr = (64 - self.ia_bits) as u64 | 2 << 6 | 1 << 8 | 1 << 10 | 3 << 12 | self.ps << 16;
        let s2_word2 = domain.0 as u64 | vtcr << 32 | S2AA64 | S2R;
        let (w0, w1, w2, w3, tlb) = match mode {
            Mode::S2 => (STE_CONFIG_S2, 0, s2_word2, root.as_u64() & ADDR_MASK_4, Tlb::Vmid(domain.0)),
            Mode::S1 => (STE_CONFIG_S1 | cd_ptr, STE1_S1, 0, 0, Tlb::Asid(domain.0)),
            Mode::Nested { s2_root } => {
                (STE_CONFIG_NESTED | cd_ptr, STE1_S1, s2_word2, s2_root.as_u64() & ADDR_MASK_4, Tlb::Vmid(domain.0))
            }
        };
        for q in 1..8 {
            ste.store::<u64>(at + q * 8, 0);
        }
        ste.store::<u64>(at + 8, w1);
        ste.store::<u64>(at + 16, w2);
        ste.store::<u64>(at + 24, w3);
        barrier::dma_wmb();
        ste.store::<u64>(at, STE_V | w0);
        barrier::dma_wmb();
        // A new level-2 table also invalidates the cached level-1 descriptor.
        let result = self.flush_stream(&mut st, sid, tlb, stage1, !created).and_then(|()| {
            if !st.enabled {
                self.set_cr0(CR0_CMDQEN | CR0_EVENTQEN | CR0_SMMUEN)?;
                st.enabled = true;
            }
            Ok(())
        });
        if result.is_err() {
            let _ = self.teardown(&mut st, sid);
        }
        result
    }

    /// Invalidates the entry (and context descriptor) of `sid` and flushes.
    fn teardown(&self, st: &mut State<'d, D>, sid: u32) -> Result<(), IommuError> {
        let slot = Self::ste_slot(&st.buffers, sid).ok_or(IommuError::NotAttached)?;
        let (ste, at) = (slot.buf(), slot.off());
        let word0 = ste.load::<u64>(at);
        if word0 & STE_V == 0 {
            return Err(IommuError::NotAttached);
        }
        let with_cd = word0 & STE_CONFIG_MASK != STE_CONFIG_S2;
        let cd = if with_cd { Self::cd_slot(&st.buffers, sid) } else { None };
        let tlb = if word0 & STE_CONFIG_MASK == STE_CONFIG_S1 {
            Tlb::Asid(cd.as_ref().map_or(0, |(page, off)| (page.load::<u64>(*off) >> 48) as u16))
        } else {
            Tlb::Vmid(ste.load::<u64>(at + 16) as u16)
        };
        ste.store::<u64>(at, 0);
        barrier::dma_wmb();
        for q in 1..8 {
            ste.store::<u64>(at + q * 8, 0);
        }
        if let Some((page, off)) = &cd {
            page.store::<u64>(*off, 0);
            barrier::dma_wmb();
            for q in 1..CD_BYTES / 8 {
                page.store::<u64>(*off + q * 8, 0);
            }
        }
        barrier::dma_wmb();
        self.flush_stream(st, sid, tlb, with_cd, true)
    }

    /// Removes and returns the oldest event-queue record, if any.
    fn pop_fault(&self) -> Option<Fault> {
        let st = self.state.lock();
        let (cons, prod) = (self.regs.r32(EVENTQ_CONS), self.regs.r32(EVENTQ_PROD));
        let mask = wrap_mask(self.evtq_log2);
        if cons & mask == prod & mask {
            return None;
        }
        barrier::dma_rmb();
        let at = (cons & ((1 << self.evtq_log2) - 1)) as usize * EVENT_BYTES;
        let events = &Self::buffers(&st).events;
        let (q0, q1, q2) = (events.load::<u64>(at), events.load::<u64>(at + 8), events.load::<u64>(at + 16));
        // Advance, and acknowledge an overflow the unit flagged (bit 31).
        // The slot is the unit's again once CONS moves: finish reading first.
        barrier::mb();
        self.regs.w32(EVENTQ_CONS, (prod & 1 << 31) | cons.wrapping_add(1) & mask);
        let sid = ((q0 >> 32) as u32).wrapping_sub(self.stream_offset);
        Some(Fault {
            device: DeviceId::new(self.segment, Address::new((sid >> 8) as u8, (sid >> 3) as u8 & 31, sid as u8 & 7)),
            iova: q2,
            // RnW (bit 35 of the second word) is 1 for a read.
            write: q1 & 1 << 35 == 0,
            reason: (q0 & 0xff) as u32,
        })
    }
}

/// The stage-1 view of an [`Smmuv3`], from [`Smmuv3::stage1`]. Devices
/// attached through it share the unit's stream table with the stage-2 view,
/// and either view's `detach` removes any device.
pub struct Stage1<'unit, 'd, D: DmaAllocator + Sync + ?Sized> {
    unit: &'unit Smmuv3<'d, D>,
}

impl<D: DmaAllocator + Sync + ?Sized> Iommu for Stage1<'_, '_, D> {
    type Format = Aarch64Stage1Io;

    fn iova_limit(&self) -> u64 {
        1 << S1_VA_BITS
    }

    unsafe fn attach(&self, device: DeviceId, domain: DomainId, root: PhysAddr) -> Result<(), IommuError> {
        self.unit.attach_with(device, domain, root, Mode::S1)
    }

    fn detach(&self, device: DeviceId) -> Result<(), IommuError> {
        self.unit.detach(device)
    }

    fn invalidate(&self, domain: DomainId) -> Result<(), IommuError> {
        let mut st = self.unit.state.lock();
        self.unit.post(&mut st, CMD_TLBI_NH_ASID | (domain.0 as u64) << 48, 0)?;
        self.unit.sync(&mut st)
    }

    fn take_fault(&self) -> Option<Fault> {
        self.unit.take_fault()
    }
}

/// AArch64 stage 1 as the SMMU walks it for DMA: 4 KiB granule, 48-bit input
/// addresses from level 0 (`TTB0` only), entries readable by "unprivileged"
/// transactions (`AP[1]`), normal write-back memory through `MAIR` attribute
/// 0 and Device-nGnRnE through attribute 1. Stage 1 cannot deny reads, so
/// every mapping is readable; `USER` and `GLOBAL` are dropped.
pub struct Aarch64Stage1Io;

mod s1 {
    pub const AP_UNPRIV: u64 = 1 << 6;
    pub const AP_RO: u64 = 1 << 7;
    pub const ATTR_DEVICE: u64 = 1 << 2;
    pub const ATTR_MASK: u64 = 0b111 << 2;
    pub const SH_INNER: u64 = 0b11 << 8;
    pub const SH_OUTER: u64 = 0b10 << 8;
    pub const AF: u64 = 1 << 10;
    pub const NG: u64 = 1 << 11;
    pub const PXN: u64 = 1 << 53;
    pub const UXN: u64 = 1 << 54;
}

impl PageTableFormat for Aarch64Stage1Io {
    const LEVELS: usize = 4;
    const VA_BITS: u32 = 48;
    const SIGN_EXTEND: bool = false;
    const MAX_LEAF_LEVEL: usize = 2;
    const BREAK_BEFORE_MAKE: bool = true;

    fn table(pa: PhysAddr) -> u64 {
        Aarch64::table(pa)
    }

    fn leaf(pa: PhysAddr, f: MapFlags, level: usize) -> u64 {
        let mut e = pa.as_u64() | 1 | s1::AF | s1::AP_UNPRIV | s1::NG;
        if level == 0 {
            e |= 1 << 1;
        }
        e |= if f.contains(MapFlags::DEVICE) { s1::ATTR_DEVICE | s1::SH_OUTER } else { s1::SH_INNER };
        if !f.contains(MapFlags::WRITE) {
            e |= s1::AP_RO;
        }
        if !f.contains(MapFlags::EXEC) || f.contains(MapFlags::DEVICE) {
            e |= s1::PXN | s1::UXN;
        }
        e
    }

    fn is_valid(pte: u64) -> bool {
        Aarch64::is_valid(pte)
    }

    fn is_leaf(pte: u64, level: usize) -> bool {
        Aarch64::is_leaf(pte, level)
    }

    fn addr(pte: u64, level: usize) -> PhysAddr {
        Aarch64::addr(pte, level)
    }

    fn flags(pte: u64, _level: usize) -> MapFlags {
        let mut f = MapFlags::READ;
        if pte & s1::AP_RO == 0 {
            f = f | MapFlags::WRITE;
        }
        if pte & s1::UXN == 0 {
            f = f | MapFlags::EXEC;
        }
        if pte & s1::ATTR_MASK == s1::ATTR_DEVICE {
            f = f | MapFlags::DEVICE;
        }
        f
    }
}

impl<D: DmaAllocator + Sync + ?Sized> Iommu for Smmuv3<'_, D> {
    type Format = Aarch64Stage2;

    fn iova_limit(&self) -> u64 {
        1 << self.ia_bits
    }

    unsafe fn attach(&self, device: DeviceId, domain: DomainId, root: PhysAddr) -> Result<(), IommuError> {
        self.attach_with(device, domain, root, Mode::S2)
    }

    fn detach(&self, device: DeviceId) -> Result<(), IommuError> {
        let sid = self.stream_id(device)?;
        let mut st = self.state.lock();
        self.teardown(&mut st, sid)
    }

    fn invalidate(&self, domain: DomainId) -> Result<(), IommuError> {
        let mut st = self.state.lock();
        self.post(&mut st, CMD_TLBI_S12_VMALL | (domain.0 as u64) << 32, 0)?;
        self.sync(&mut st)
    }

    fn take_fault(&self) -> Option<Fault> {
        self.pop_fault()
    }
}

impl<D: DmaAllocator + Sync + ?Sized> Drop for Smmuv3<'_, D> {
    fn drop(&mut self) {
        let mut st = self.state.lock();
        let stopped = self.set_cr0(0).is_ok();
        // A unit that will not stop may still read its tables: leak them.
        if stopped {
            // SAFETY: dropped once, here; the unit no longer uses them.
            unsafe { ManuallyDrop::drop(&mut st.buffers) };
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::vec::Vec;

    use osmium_hal::iommu::{IoDomain, IommuDma};
    use osmium_mm::VirtAddr;
    use osmium_mm::paging::{MapFlags, PageSize, PageTable};

    use super::super::testing::*;
    use super::*;

    const NIC: Address = Address::new(0, 3, 1);
    const FAR: Address = Address::new(0, 5, 0);

    fn dev(a: Address) -> DeviceId {
        DeviceId::new(0, a)
    }

    #[derive(Default)]
    struct Hw {
        log: Vec<std::string::String>,
        stall: bool,
        /// Reject the next command with CMDQ_ERR.
        error_next: bool,
    }

    struct Fake {
        regs: HostRegs,
        hw: Arc<Mutex<Hw>>,
        _pump: Pump,
    }

    fn fake(idr0_extra: u32, idr0_clear: u32) -> Fake {
        let regs = HostRegs::new(0x20000);
        // S1P, S2P, AArch64 tables, coherent walks, 16-bit VMIDs and ASIDs,
        // two-level stream tables.
        let idr0 = IDR0_S1P | IDR0_S2P | IDR0_TTF_AARCH64 | IDR0_COHACC | IDR0_VMID16 | IDR0_ASID16 | 1 << 27;
        regs.w32(IDR0, (idr0 | idr0_extra) & !idr0_clear);
        // SIDSIZE 16, EVENTQS 7, CMDQS 8.
        regs.w32(IDR1, 16 | 7 << 16 | 8 << 21);
        // OAS 44 bits, 4 KiB granule.
        regs.w32(IDR5, 4 | IDR5_GRAN4K);
        let hw = Arc::new(Mutex::new(Hw::default()));
        let (r, h) = (regs.clone(), hw.clone());
        let pump = Pump::start(move || {
            let mut hw = h.lock().unwrap();
            let cr0 = r.r32(CR0);
            r.w32(CR0ACK, cr0);
            // Writes to GBPA complete at once.
            r.w32(GBPA, r.r32(GBPA) & !GBPA_UPDATE);
            // A command error stops the queue until it is acknowledged.
            let errored = (r.r32(GERROR) ^ r.r32(GERRORN)) & GERROR_CMDQ_ERR != 0;
            if cr0 & CR0_CMDQEN == 0 || hw.stall || errored {
                return;
            }
            let base = r.r64(CMDQ_BASE);
            let log2 = (base & 0x1f) as u32;
            let base = base & ADDR_MASK_4 & !0x1f;
            let mask = wrap_mask(log2);
            let prod = r.r32(CMDQ_PROD) & mask;
            let mut cons = r.r32(CMDQ_CONS) & mask;
            while cons != prod {
                let at = base + (cons & ((1 << log2) - 1)) as u64 * 16;
                let (q0, q1) = (mem64(at), mem64(at + 8));
                if hw.error_next {
                    hw.error_next = false;
                    r.w32(GERROR, r.r32(GERROR) ^ GERROR_CMDQ_ERR);
                    return;
                }
                match q0 & 0xff {
                    CMD_CFGI_STE => hw.log.push(std::format!("cfgi_ste {} leaf {}", q0 >> 32, q1 & 1)),
                    CMD_CFGI_ALL => {
                        assert_eq!(q1 & 0x1f, 31);
                        hw.log.push("cfgi_all".into());
                    }
                    CMD_CFGI_CD => hw.log.push(std::format!("cfgi_cd {} leaf {}", q0 >> 32, q1 & 1)),
                    CMD_TLBI_NH_ASID => {
                        hw.log.push(std::format!("tlbi_nh_asid {} vmid {}", q0 >> 48, (q0 >> 32) & 0xffff))
                    }
                    CMD_TLBI_S12_VMALL => hw.log.push(std::format!("tlbi_s12 {}", (q0 >> 32) & 0xffff)),
                    CMD_TLBI_NSNH_ALL => hw.log.push("tlbi_nsnh".into()),
                    CMD_SYNC => {
                        assert_eq!((q0 >> 12) & 3, 2, "CS = SEV");
                        hw.log.push("sync".into());
                    }
                    op => panic!("unexpected command {op:#x}"),
                }
                cons = (cons + 1) & mask;
                r.w32(CMDQ_CONS, cons);
            }
        });
        Fake { regs, hw, _pump: pump }
    }

    impl Fake {
        fn log(&self) -> Vec<std::string::String> {
            self.hw.lock().unwrap().log.clone()
        }

        fn translating(&self) -> bool {
            self.regs.r32(CR0) & CR0_SMMUEN != 0
        }

        /// Address of the stream table entry for `sid`, walking the level-1
        /// array of a two-level table.
        fn ste_addr(&self, sid: u32) -> Result<u64, &'static str> {
            let cfg = self.regs.r32(STRTAB_BASE_CFG);
            let base = self.regs.r64(STRTAB_BASE) & ADDR_MASK_4 & !0x3f;
            if cfg & L1_FMT_TWO_LEVEL == 0 {
                return Ok(base + sid as u64 * 64);
            }
            assert_eq!((cfg >> 6) & 0x1f, L2_SPLIT);
            let l1 = mem64(base + (sid >> L2_SPLIT) as u64 * 8);
            let span = l1 & 0x1f;
            if span == 0 {
                return Err("l1 descriptor invalid");
            }
            assert_eq!(span, L2_SPLIT as u64 + 1);
            Ok((l1 & ADDR_MASK_6) + (sid & 63) as u64 * 64)
        }

        /// Walks a stage-2 table (4 KiB granule, from level 0).
        fn walk_s2(&self, steaddr: u64, ipa: u64, write: bool) -> Result<u64, &'static str> {
            let q2 = mem64(steaddr + 16);
            assert_ne!(q2 & S2AA64, 0);
            let vtcr = q2 >> 32;
            let (t0sz, sl0, tg0) = (vtcr & 0x3f, (vtcr >> 6) & 3, (vtcr >> 14) & 3);
            assert_eq!((sl0, tg0), (2, 0), "start at level 0, 4 KiB granule");
            if ipa >> (64 - t0sz) != 0 {
                return Err("address size");
            }
            let mut table = mem64(steaddr + 24) & ADDR_MASK_4;
            for level in 0..4 {
                let shift = 39 - 9 * level;
                let e = mem64(table + ((ipa >> shift) & 0x1ff) * 8);
                if e & 1 == 0 {
                    return Err("translation");
                }
                if level == 3 || e & 2 == 0 {
                    assert!(level == 3 && e & 2 != 0, "no block descriptors in this test");
                    if e & 1 << 10 == 0 {
                        return Err("access flag");
                    }
                    let ap = (e >> 6) & 3;
                    if write && ap & 2 == 0 || !write && ap & 1 == 0 {
                        return Err("permission");
                    }
                    return Ok((e & 0x0000_ffff_ffff_f000) | (ipa & 0xfff));
                }
                table = e & 0x0000_ffff_ffff_f000;
            }
            panic!("walk did not terminate")
        }

        /// Walks the stage-1 table of the context descriptor the entry points at.
        fn walk_s1(&self, steaddr: u64, iova: u64, write: bool) -> Result<u64, &'static str> {
            let q0 = mem64(steaddr);
            assert_eq!(q0 >> 59, 0, "one context descriptor, linear");
            assert_eq!((q0 >> 4) & 3, 0);
            let cd = q0 & ADDR_MASK_6;
            let cd0 = mem64(cd);
            if cd0 & CD_V == 0 {
                return Err("cd invalid");
            }
            assert_ne!(cd0 & CD_AA64, 0);
            assert_ne!(cd0 & CD_EPD1, 0, "no TTB1 walks");
            let (t0sz, tg0) = (cd0 & 0x3f, (cd0 >> 6) & 3);
            assert_eq!(tg0, 0, "4 KiB granule");
            if iova >> (64 - t0sz) != 0 {
                return Err("address size");
            }
            assert_eq!(mem64(cd + 24) & 0xff, CD_MAIR, "attribute 0 is normal write-back");
            let mut table = mem64(cd + 8) & ADDR_MASK_4;
            for level in 0..4 {
                let shift = 39 - 9 * level;
                let e = mem64(table + ((iova >> shift) & 0x1ff) * 8);
                if e & 1 == 0 {
                    return Err("translation");
                }
                if level == 3 || e & 2 == 0 {
                    assert!(level == 3 && e & 2 != 0, "no block descriptors in this test");
                    if e & 1 << 10 == 0 {
                        return Err("access flag");
                    }
                    // AP[1] lets unprivileged transactions through; AP[2] is read-only.
                    if e & 1 << 6 == 0 || write && e & 1 << 7 != 0 {
                        return Err("permission");
                    }
                    return Ok((e & 0x0000_ffff_ffff_f000) | (iova & 0xfff));
                }
                table = e & 0x0000_ffff_ffff_f000;
            }
            panic!("walk did not terminate")
        }

        /// Looks `iova` up for stream `sid` as the unit would.
        fn translate(&self, sid: u32, iova: u64, write: bool) -> Result<u64, &'static str> {
            if !self.translating() {
                return Ok(iova);
            }
            let steaddr = self.ste_addr(sid)?;
            let q0 = mem64(steaddr);
            if q0 & STE_V == 0 {
                return Err("abort");
            }
            match q0 & STE_CONFIG_MASK {
                STE_CONFIG_S2 => self.walk_s2(steaddr, iova, write),
                STE_CONFIG_S1 => self.walk_s1(steaddr, iova, write),
                // The stage-1 table walks themselves would go through stage 2
                // too; the tests map them at their own addresses, so only the
                // output is walked here.
                STE_CONFIG_NESTED => {
                    self.walk_s1(steaddr, iova, write).and_then(|ipa| self.walk_s2(steaddr, ipa, write))
                }
                c => panic!("unexpected config {c:#x}"),
            }
        }

        fn vmid_of(&self, sid: u32) -> u64 {
            mem64(self.ste_addr(sid).unwrap() + 16) & 0xffff
        }

        fn asid_of(&self, sid: u32) -> u64 {
            let cd = mem64(self.ste_addr(sid).unwrap()) & ADDR_MASK_6;
            mem64(cd) >> 48
        }

        fn push_event(&self, id: u64, sid: u32, read: bool, addr: u64) {
            let base = self.regs.r64(EVENTQ_BASE) & ADDR_MASK_4 & !0x1f;
            let log2 = (self.regs.r64(EVENTQ_BASE) & 0x1f) as u32;
            let prod = self.regs.r32(EVENTQ_PROD);
            let at = base + (prod & ((1 << log2) - 1)) as u64 * 32;
            set_mem64(at, id | (sid as u64) << 32);
            set_mem64(at + 8, (read as u64) << 35);
            set_mem64(at + 16, addr);
            self.regs.w32(EVENTQ_PROD, (prod + 1) & wrap_mask(log2));
        }
    }

    fn setup<'dev>(dma: &'dev HostDma, clock: &'dev StdClock, f: &Fake) -> Smmuv3<'dev, HostDma> {
        // 64 stream IDs keeps the stream table to one page, which HostDma aligns.
        Smmuv3::new(f.regs.io(), dma, clock, 0, 63).expect("unit comes up")
    }

    fn sid(a: Address) -> u32 {
        dev(a).bdf() as u32
    }

    #[test]
    fn programs_tables_and_stays_off() {
        let (f, dma, clock) = (fake(0, 0), HostDma::default(), StdClock::default());
        let unit = setup(&dma, &clock, &f);
        assert!(!f.translating() && !unit.translating());
        assert_eq!(f.regs.r32(STRTAB_BASE_CFG), 6, "64 streams, linear");
        assert_eq!(f.regs.r32(CR1), CR1_COHERENT);
        assert_eq!(f.regs.r32(CR0) & (CR0_CMDQEN | CR0_EVENTQEN), CR0_CMDQEN | CR0_EVENTQEN);
        assert_eq!(f.log(), ["cfgi_all", "tlbi_nsnh", "sync"]);
        assert_eq!(unit.iova_limit(), 1 << 44);
        assert_eq!(dma.live(), 3);
        drop(unit);
        assert_eq!(dma.live(), 0);
        assert_eq!(f.regs.r32(CR0), 0);
    }

    #[test]
    fn refuses_unsuitable_hardware() {
        let (dma, clock) = (HostDma::default(), StdClock::default());
        let small = HostRegs::new(0x1000);
        assert_eq!(Smmuv3::new(small.io(), &dma, &clock, 0, 63).err(), Some(IommuError::BadRegisters));
        for clear in [IDR0_S2P | IDR0_S1P, IDR0_COHACC, IDR0_TTF_AARCH64] {
            let f = fake(0, clear);
            assert_eq!(Smmuv3::new(f.regs.io(), &dma, &clock, 0, 63).err(), Some(IommuError::Unsupported));
        }
        let f = fake(0, 0);
        f.regs.w32(IDR5, 4); // no 4 KiB granule
        assert_eq!(Smmuv3::new(f.regs.io(), &dma, &clock, 0, 63).err(), Some(IommuError::Unsupported));
        let f = fake(0, 0);
        f.regs.w32(IDR1, f.regs.r32(IDR1) & !0x3f | 8); // 8-bit stream IDs
        assert_eq!(Smmuv3::new(f.regs.io(), &dma, &clock, 0, 0xffff).err(), Some(IommuError::Unsupported));
        assert_eq!(dma.live(), 0, "nothing leaked on failure");
    }

    #[test]
    fn attach_translates_and_detach_blocks() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let unit = setup(&dma, &clock, &f);
        let backing = HostDma::default();
        let buf = backing.alloc_coherent(8192).unwrap();
        let base = buf.device_addr().as_u64();
        let mut d = IoDomain::new(&unit, DomainId(0x1234), &tables).unwrap();
        d.map(0x20_0000, buf.device_addr(), 0x2000, MapFlags::RW).unwrap();
        d.map(0x40_0000, buf.device_addr(), 0x1000, MapFlags::READ).unwrap();
        d.attach(dev(NIC)).unwrap();
        assert!(f.translating(), "first attach turns the unit on");
        let s = sid(NIC);
        assert_eq!(f.vmid_of(s), 0x1234);
        assert_eq!(f.translate(s, 0x20_0123, true), Ok(base + 0x123));
        assert_eq!(f.translate(s, 0x20_1fff, false), Ok(base + 0x1fff));
        assert_eq!(f.translate(s, 0x40_0000, true), Err("permission"));
        assert_eq!(f.translate(s, 0x30_0000, false), Err("translation"));
        assert_eq!(f.translate(sid(FAR), 0x20_0000, false), Err("abort"));
        assert_eq!(f.translate(s, 1 << 44, false), Err("address size"));

        d.map(0x50_0000, buf.device_addr() + 0x1000, 0x1000, MapFlags::RW).unwrap();
        assert_eq!(f.translate(s, 0x50_0008, true), Ok(base + 0x1008));
        d.unmap(0x50_0000, 0x1000).unwrap();
        assert_eq!(f.translate(s, 0x50_0008, true), Err("translation"));
        let log = f.log();
        assert!(log.contains(&std::format!("cfgi_ste {s} leaf 1")), "{log:?}");
        assert!(log.contains(&"tlbi_s12 4660".into()));
        assert_eq!(log.last().unwrap(), "sync");

        assert_eq!(d.attach(dev(NIC)), Err(IommuError::Busy));
        d.detach(dev(NIC)).unwrap();
        assert_eq!(f.translate(s, 0x20_0000, false), Err("abort"));
        assert_eq!(d.detach(dev(NIC)), Err(IommuError::NotAttached));
        drop(d);
        // SAFETY: nothing maps it any more.
        unsafe { backing.free_coherent(buf) };
    }

    #[test]
    fn stream_offset_and_limits() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let mut unit = setup(&dma, &clock, &f);
        unit.set_stream_offset(0x10);
        let mut d = IoDomain::new(&unit, DomainId(1), &tables).unwrap();
        d.map(0x1000, PhysAddr::new(0xaaa000), 0x1000, MapFlags::RW).unwrap();
        // requester 0x19 + 0x10 = stream 0x29, inside the 64 entries.
        d.attach(dev(NIC)).unwrap();
        assert_eq!(f.translate(0x29, 0x1000, false), Ok(0xaaa000));
        assert_eq!(f.translate(0x19, 0x1000, false), Err("abort"));
        // Bus 1 is beyond stream 63.
        assert_eq!(d.attach(dev(Address::new(1, 0, 0))), Err(IommuError::InvalidDevice));
        assert_eq!(d.attach(DeviceId::new(1, NIC)), Err(IommuError::InvalidDevice));
    }

    #[test]
    fn eight_bit_vmids() {
        let (f, dma, clock, tables) =
            (fake(0, IDR0_VMID16), HostDma::default(), StdClock::default(), HostTables::default());
        let unit = setup(&dma, &clock, &f);
        let mut d = IoDomain::new(&unit, DomainId(256), &tables).unwrap();
        assert_eq!(d.attach(dev(NIC)), Err(IommuError::Unsupported));
        let mut d = IoDomain::new(&unit, DomainId(255), &tables).unwrap();
        d.attach(dev(NIC)).unwrap();
    }

    #[test]
    fn command_timeout_and_error() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let mut unit = setup(&dma, &clock, &f);
        unit.set_timeout_ns(50_000_000);
        {
            let mut d = IoDomain::new(&unit, DomainId(1), &tables).unwrap();
            f.hw.lock().unwrap().stall = true;
            assert_eq!(d.attach(dev(NIC)), Err(IommuError::Timeout));
            assert!(!f.translating());
            f.hw.lock().unwrap().stall = false;
            // The stuck commands run once the unit recovers; give it time.
            std::thread::sleep(core::time::Duration::from_millis(10));
            let before = f.log().len();
            f.hw.lock().unwrap().error_next = true;
            assert_eq!(d.attach(dev(NIC)), Err(IommuError::Hardware));
            std::thread::sleep(core::time::Duration::from_millis(10));
            // Only the rollback's own cfgi, tlbi and sync ran; the rejected
            // attach's commands were dropped, not re-executed.
            assert_eq!(f.log().len(), before + 3, "{:?}", f.log());
            // The error was acknowledged and the queue still works.
            d.attach(dev(NIC)).unwrap();
        }
        assert_eq!(f.regs.r32(GERROR), f.regs.r32(GERRORN));
    }

    #[test]
    fn unit_resets_to_bypass() {
        let (f, dma, clock) = (fake(0, 0), HostDma::default(), StdClock::default());
        f.regs.w32(GBPA, GBPA_ABORT);
        let _unit = setup(&dma, &clock, &f);
        assert_eq!(f.regs.r32(GBPA) & GBPA_ABORT, 0, "DMA passes until the first attach");
    }

    #[test]
    fn command_queue_wraps() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let unit = setup(&dma, &clock, &f);
        let mut d = IoDomain::new(&unit, DomainId(1), &tables).unwrap();
        // 256 entries; each attach+detach posts 6 commands.
        for _ in 0..120 {
            d.attach(dev(NIC)).unwrap();
            d.detach(dev(NIC)).unwrap();
        }
    }

    #[test]
    fn events_become_faults() {
        let (f, dma, clock) = (fake(0, 0), HostDma::default(), StdClock::default());
        let unit = setup(&dma, &clock, &f);
        assert_eq!(unit.take_fault(), None);
        f.push_event(0x10, sid(NIC), false, 0x1234_5678);
        f.push_event(0x13, sid(FAR), true, 0x9000);
        let a = unit.take_fault().unwrap();
        assert_eq!((a.device, a.iova, a.write, a.reason), (dev(NIC), 0x1234_5678, true, 0x10));
        let b = unit.take_fault().unwrap();
        assert_eq!((b.device, b.iova, b.write, b.reason), (dev(FAR), 0x9000, false, 0x13));
        assert_eq!(unit.take_fault(), None);
        for i in 0..300u64 {
            f.push_event(0x10, sid(NIC), true, i << 12);
            assert_eq!(unit.take_fault().unwrap().iova, i << 12);
        }
    }

    #[test]
    fn iommu_dma_end_to_end() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let backing = HostDma::default();
        let unit = setup(&dma, &clock, &f);
        let alloc = {
            let domain = IoDomain::new(&unit, DomainId(3), &tables).unwrap();
            IommuDma::new(domain, &backing, 0x10_0000..0x1000_0000).unwrap()
        };
        alloc.with_domain(|d| d.attach(dev(NIC))).unwrap();
        let ring = alloc.alloc_coherent(4096).unwrap();
        ring.store::<u32>(8, 0xc0ffee);
        let iova = ring.device_addr().as_u64();
        let pa = f.translate(sid(NIC), iova + 8, true).unwrap();
        assert_eq!(mem32(pa), 0xc0ffee);
        // SAFETY: the "device" is the fake and is idle.
        unsafe { alloc.free_coherent(ring) };
        assert_eq!(f.translate(sid(NIC), iova, false), Err("translation"));
        assert_eq!(backing.live(), 0);
        alloc.with_domain(|d| d.detach(dev(NIC))).unwrap();
    }

    #[test]
    fn two_level_stream_table() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        // 512 stream IDs: more than 256, so Auto picks two levels (8 descriptors).
        let unit = Smmuv3::new(f.regs.io(), &dma, &clock, 0, 511).unwrap();
        assert!(unit.two_level());
        assert_eq!(f.regs.r32(STRTAB_BASE_CFG), 9 | L2_SPLIT << 6 | L1_FMT_TWO_LEVEL);
        assert_eq!(dma.live(), 4, "level-1 array, level-2 page index, two queues; no level-2 page yet");
        let mut d = IoDomain::new(&unit, DomainId(7), &tables).unwrap();
        d.map(0x1000, PhysAddr::new(0xaaa000), 0x1000, MapFlags::RW).unwrap();
        d.attach(dev(NIC)).unwrap();
        assert_eq!(dma.live(), 5, "one level-2 page");
        let s = sid(NIC);
        assert_eq!(f.translate(s, 0x1000, false), Ok(0xaaa000));
        // The same 64 stream IDs share the page; bus 1 is another range.
        let near = Address::new(0, 3, 2);
        d.attach(dev(near)).unwrap();
        assert_eq!(dma.live(), 5);
        let far = Address::new(1, 0, 0);
        d.attach(dev(far)).unwrap();
        assert_eq!(dma.live(), 6);
        assert_eq!(f.translate(sid(far), 0x1000, false), Ok(0xaaa000));
        // Streams whose level-2 table does not exist abort.
        assert_eq!(f.translate(sid(Address::new(1, 8, 0)), 0x1000, false), Err("l1 descriptor invalid"));
        // A new table is announced with a non-leaf CFGI_STE.
        let log = f.log();
        let first = std::format!("cfgi_ste {s} leaf 0");
        assert!(log.contains(&first), "{log:?}");
        assert!(log.contains(&std::format!("cfgi_ste {} leaf 1", sid(near))), "{log:?}");
        // Out of range for the 9-bit table.
        assert_eq!(d.attach(dev(Address::new(2, 0, 0))), Err(IommuError::InvalidDevice));
        d.detach(dev(far)).unwrap();
        assert_eq!(f.translate(sid(far), 0x1000, false), Err("abort"));
        assert_eq!(d.detach(dev(far)), Err(IommuError::NotAttached));
        assert_eq!(d.detach(dev(Address::new(1, 8, 0))), Err(IommuError::NotAttached));
        drop(d);
        drop(unit);
        assert_eq!(dma.live(), 0, "level-2 pages freed");
    }

    #[test]
    fn layout_selection() {
        let (dma, clock) = (HostDma::default(), StdClock::default());
        let f = fake(0, 0);
        let u = Smmuv3::new(f.regs.io(), &dma, &clock, 0, 63).unwrap();
        assert!(!u.two_level(), "small tables stay linear");
        drop(u);
        let u = Smmuv3::with_layout(f.regs.io(), &dma, &clock, 0, 63, StreamTableLayout::Linear).unwrap();
        assert!(!u.two_level());
        drop(u);
        // Explicit two-level with few streams rounds up to one descriptor.
        let u = Smmuv3::with_layout(f.regs.io(), &dma, &clock, 0, 3, StreamTableLayout::TwoLevel).unwrap();
        assert_eq!(f.regs.r32(STRTAB_BASE_CFG), 7 | L2_SPLIT << 6 | L1_FMT_TWO_LEVEL);
        drop(u);
        let f = fake(0, 1 << 27);
        let r = Smmuv3::with_layout(f.regs.io(), &dma, &clock, 0, 511, StreamTableLayout::TwoLevel);
        assert_eq!(r.err(), Some(IommuError::Unsupported));
        assert_eq!(dma.live(), 0);
    }

    #[test]
    fn stage1_translates_by_asid() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let unit = setup(&dma, &clock, &f);
        let s1 = unit.stage1().unwrap();
        assert_eq!(s1.iova_limit(), 1 << 48);
        let mut d = IoDomain::new(&s1, DomainId(0x42), &tables).unwrap();
        d.map(0x20_0000, PhysAddr::new(0xbbb000), 0x2000, MapFlags::RW).unwrap();
        d.map(0x40_0000, PhysAddr::new(0xccc000), 0x1000, MapFlags::READ).unwrap();
        d.map(0x1000_0000_0000, PhysAddr::new(0xddd000), 0x1000, MapFlags::RW).unwrap();
        d.attach(dev(NIC)).unwrap();
        assert_eq!(dma.live(), 5, "stream table, two queues, descriptor page index and one descriptor page");
        assert!(f.translating());
        let s = sid(NIC);
        assert_eq!(f.asid_of(s), 0x42);
        assert_eq!(f.translate(s, 0x20_0123, true), Ok(0xbbb123));
        assert_eq!(f.translate(s, 0x20_1000, false), Ok(0xbbc000));
        assert_eq!(f.translate(s, 0x40_0000, false), Ok(0xccc000));
        assert_eq!(f.translate(s, 0x40_0000, true), Err("permission"));
        assert_eq!(f.translate(s, 0x30_0000, false), Err("translation"));
        assert_eq!(f.translate(s, 0x1000_0000_0000, true), Ok(0xddd000));
        assert_eq!(f.translate(s, 1 << 48, false), Err("address size"));
        // The stage-2 view of the same unit still serves other devices.
        let mut d2 = IoDomain::new(&unit, DomainId(9), &tables).unwrap();
        d2.map(0x1000, PhysAddr::new(0xeee000), 0x1000, MapFlags::RW).unwrap();
        d2.attach(dev(FAR)).unwrap();
        assert_eq!(f.translate(sid(FAR), 0x1000, true), Ok(0xeee000));
        assert_eq!(f.vmid_of(sid(FAR)), 9);
        // One stream, one configuration.
        assert_eq!(d2.attach(dev(NIC)), Err(IommuError::Busy));
        d.unmap(0x40_0000, 0x1000).unwrap();
        assert_eq!(f.translate(s, 0x40_0000, false), Err("translation"));
        let log = f.log();
        assert!(log.contains(&std::format!("cfgi_ste {s} leaf 1")), "{log:?}");
        assert!(log.contains(&std::format!("cfgi_cd {s} leaf 1")), "{log:?}");
        assert!(log.contains(&"tlbi_nh_asid 66 vmid 0".into()), "{log:?}");
        assert_eq!(log.last().unwrap(), "sync");
        // Detach removes the descriptor and flushes by ASID.
        let before = f.log().len();
        d.detach(dev(NIC)).unwrap();
        assert_eq!(f.translate(s, 0x20_0000, false), Err("abort"));
        assert_eq!(
            f.log()[before..],
            [
                std::format!("cfgi_ste {s} leaf 1"),
                std::format!("cfgi_cd {s} leaf 1"),
                "tlbi_nh_asid 66 vmid 0".into(),
                "sync".into()
            ]
        );
        assert_eq!(d.detach(dev(NIC)), Err(IommuError::NotAttached));
        // The domain can be attached again (descriptor was cleared).
        d.attach(dev(NIC)).unwrap();
        assert_eq!(f.translate(s, 0x20_0123, true), Ok(0xbbb123));
        // An explicit invalidate is by ASID.
        let before = f.log().len();
        s1.invalidate(DomainId(0x42)).unwrap();
        assert_eq!(f.log()[before..], ["tlbi_nh_asid 66 vmid 0", "sync"]);
        d.detach(dev(NIC)).unwrap();
        d2.detach(dev(FAR)).unwrap();
        // Either view detaches any device.
        d.attach(dev(NIC)).unwrap();
        unit.detach(dev(NIC)).unwrap();
        assert_eq!(f.translate(s, 0x20_0000, false), Err("abort"));
    }

    #[test]
    fn stage1_flags_and_limits() {
        // Format round trip.
        let rw = Aarch64Stage1Io::leaf(PhysAddr::new(0x1000), MapFlags::RW, 0);
        assert_eq!(Aarch64Stage1Io::flags(rw, 0), MapFlags::RW);
        assert_ne!(rw & s1::AP_UNPRIV, 0);
        let ro = Aarch64Stage1Io::leaf(PhysAddr::new(0x1000), MapFlags::READ, 0);
        assert_eq!(Aarch64Stage1Io::flags(ro, 0), MapFlags::READ);
        let dev_page = Aarch64Stage1Io::leaf(PhysAddr::new(0x1000), MapFlags::RW | MapFlags::DEVICE, 0);
        assert!(Aarch64Stage1Io::flags(dev_page, 0).contains(MapFlags::DEVICE));
        let x = Aarch64Stage1Io::leaf(PhysAddr::new(0x1000), MapFlags::READ | MapFlags::EXEC, 0);
        assert!(Aarch64Stage1Io::flags(x, 0).contains(MapFlags::EXEC));
        assert_eq!(Aarch64Stage1Io::addr(rw, 0), PhysAddr::new(0x1000));

        let (dma, clock, tables) = (HostDma::default(), StdClock::default(), HostTables::default());
        // No stage 1 on the unit.
        let f = fake(0, IDR0_S1P);
        let unit = setup(&dma, &clock, &f);
        assert_eq!(unit.stage1().err(), Some(IommuError::Unsupported));
        assert!(!unit.has_stage1() && unit.has_stage2());
        // No stage 2: stage-2 attach is refused, stage 1 works, 8-bit ASIDs.
        let f = fake(0, IDR0_S2P | IDR0_ASID16);
        let unit = setup(&dma, &clock, &f);
        assert!(unit.has_stage1() && !unit.has_stage2());
        let mut d = IoDomain::new(&unit, DomainId(1), &tables).unwrap();
        assert_eq!(d.attach(dev(NIC)), Err(IommuError::Unsupported));
        let s1 = unit.stage1().unwrap();
        let mut d = IoDomain::new(&s1, DomainId(256), &tables).unwrap();
        assert_eq!(d.attach(dev(NIC)), Err(IommuError::Unsupported));
        let mut d = IoDomain::new(&s1, DomainId(255), &tables).unwrap();
        d.attach(dev(NIC)).unwrap();
    }

    #[test]
    fn nested_translation() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let unit = setup(&dma, &clock, &f);
        // Stage 1 maps IOVA -> IPA; stage 2 maps IPA -> PA.
        let mut s1 = PageTable::<Aarch64Stage1Io, _>::new(&tables).unwrap();
        s1.map(VirtAddr::new(0x10_0000), PhysAddr::new(0x7000), PageSize::Size4K, MapFlags::RW).unwrap().ignore();
        let mut s2 = PageTable::<Aarch64Stage2, _>::new(&tables).unwrap();
        s2.map(VirtAddr::new(0x7000), PhysAddr::new(0x99_9000), PageSize::Size4K, MapFlags::READ).unwrap().ignore();
        let cd_page = unit.context_descriptor_page(dev(NIC)).unwrap();
        assert!(cd_page.is_aligned(4096));
        // SAFETY: both tables outlive the attachment, which is undone below.
        unsafe { unit.attach_nested(dev(NIC), DomainId(5), s1.root(), s2.root()) }.unwrap();
        let s = sid(NIC);
        assert_eq!(mem64(f.ste_addr(s).unwrap()) & STE_CONFIG_MASK, STE_CONFIG_NESTED);
        assert_eq!(f.vmid_of(s), 5);
        assert_eq!(f.asid_of(s), 5);
        assert_eq!(f.translate(s, 0x10_0040, false), Ok(0x99_9040));
        // Stage 2 forbids the write that stage 1 allows.
        assert_eq!(f.translate(s, 0x10_0040, true), Err("permission"));
        assert_eq!(f.translate(s, 0x20_0000, false), Err("translation"));
        let log = f.log();
        assert!(log.contains(&"tlbi_s12 5".into()) && log.contains(&std::format!("cfgi_cd {s} leaf 1")), "{log:?}");
        unit.detach(dev(NIC)).unwrap();
        assert_eq!(f.translate(s, 0x10_0040, false), Err("abort"));
        assert_eq!(f.log().last().unwrap(), "sync");
        // Needs both stages.
        let f = fake(0, IDR0_S1P);
        let unit = setup(&dma, &clock, &f);
        // SAFETY: the call fails before the tables are used.
        let r = unsafe { unit.attach_nested(dev(NIC), DomainId(5), PhysAddr::new(0x1000), PhysAddr::new(0x2000)) };
        assert_eq!(r, Err(IommuError::Unsupported));
    }
}
