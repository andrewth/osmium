//! Intel VT-d DMA and interrupt remapping.
//!
//! [`Vtd`] drives one remapping unit (a DRHD in the ACPI DMAR table) in one
//! of two translation modes.
//!
//! **Legacy mode** ([`Vtd::new`]): a root table of 256 bus entries, each
//! pointing at a context table of 256 device/function entries, each pointing
//! at a second-level page table in [`VtdSecondLevel`] format with a 48-bit,
//! four-level walk. Invalidation uses the register interface (context-command
//! and IOTLB registers).
//!
//! **Scalable mode** ([`Vtd::new_scalable`]): the root entry of a bus points
//! at two context tables (functions 0 to 127 and 128 to 255) of 256-bit
//! entries; each entry points at a PASID directory, whose first PASID table
//! has an entry for PASID 0 (the `RID_PASID` that requests without a PASID
//! use) of type second-level-only, pointing at the same
//! [`VtdSecondLevel`] table. The directory and table are allocated on a
//! device's first attach and reused until the driver is dropped. The unit
//! must report `ECAP.SMTS` and `ECAP.SLTS`. Scalable mode invalidates through
//! the queue only (context-cache, PASID-cache and IOTLB descriptors); first-level
//! and nested translation and PASIDs other than 0 are not used yet.
//!
//! **Queued invalidation** is on in scalable mode and when interrupt
//! remapping is enabled (see [`remap`]): a one-page ring of descriptors, each
//! submission followed by an invalidation-wait descriptor that writes a status
//! word. A queue the firmware left enabled is switched off at start-up.
//!
//! **Interrupt remapping** (`ECAP.IR`) is in [`remap`]: the interrupt remapping
//! table, [`remap::Irte`] programming with entry-cache invalidation,
//! extended interrupt mode for x2APIC, and the remappable-format MSI message and
//! I/O APIC entry.
//!
//! It needs `CAP.SAGAW` bit 2 (4-level tables) and, from [`Vtd::new`],
//! `ECAP.C` (the unit's table walks snoop the CPU caches). A unit without it
//! needs cache lines written back after every table change, including the
//! caller's second-level tables, which this tree has no way to do, so
//! [`Vtd::new`] refuses it; QEMU's model reports the bit clear although its
//! memory is always coherent, and [`Vtd::new_assuming_coherent`] is for that.
//! With caching mode (`CAP.CM`, as in virtual machines) domain 0 is
//! reserved and the driver invalidates after every change, as it does anyway.
//! Device IOTLBs and nested translation are not used. Pass-through is not
//! offered: unattached devices are blocked once translation is on.
//!
//! Faults are read back from the fault-recording registers by
//! [`Iommu::take_fault`]; the fault interrupt stays masked.

use core::mem::ManuallyDrop;
use core::ptr::NonNull;
use core::sync::atomic::AtomicBool;

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::iommu::{DeviceId, DomainId, Fault, Iommu, IommuError};
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;
use osmium_mm::PhysAddr;
use osmium_mm::paging::formats::VtdSecondLevel;
use osmium_sync::IrqSpinLock;

use super::{DEFAULT_TIMEOUT_NS, Pages, Regs, wait_until};

mod qi;
pub mod remap;

// Registers.
const VER: usize = 0x00;
const CAP: usize = 0x08;
const ECAP: usize = 0x10;
const GCMD: usize = 0x18;
const GSTS: usize = 0x1c;
const RTADDR: usize = 0x20;
const CCMD: usize = 0x28;
const FSTS: usize = 0x34;
const IQH: usize = 0x80;
const IQT: usize = 0x88;
const IQA: usize = 0x90;
const IRTA: usize = 0xb8;

// GCMD/GSTS bits (the command and its status share a position).
const TE: u32 = 1 << 31;
const SRTP: u32 = 1 << 30;
const WBF: u32 = 1 << 27;
const QIE: u32 = 1 << 26;
const IRE: u32 = 1 << 25;
const SIRTP: u32 = 1 << 24;
const CFI: u32 = 1 << 23;
/// Bits of GSTS that persist and must be written back with every command.
const PERSISTENT: u32 = TE | QIE | IRE | CFI;

// CAP fields.
const CAP_RWBF: u64 = 1 << 4;
const CAP_CM: u64 = 1 << 7;
const CAP_DWD: u64 = 1 << 54;
const CAP_DRD: u64 = 1 << 55;
// ECAP fields.
const ECAP_C: u64 = 1 << 0;
const ECAP_QI: u64 = 1 << 1;
const ECAP_IR: u64 = 1 << 3;
const ECAP_EIM: u64 = 1 << 4;
const ECAP_SMTS: u64 = 1 << 43;
const ECAP_SLTS: u64 = 1 << 46;

/// `RTADDR.TTM` bit: the root table is in scalable mode.
const RTADDR_SCALABLE: u64 = 1 << 10;

// Command and IOTLB registers.
const ICC: u64 = 1 << 63;
const CIRG_GLOBAL: u64 = 1 << 61;
const CIRG_DEVICE: u64 = 3 << 61;
const IVT: u64 = 1 << 63;
const IIRG_GLOBAL: u64 = 1 << 60;
const IIRG_DOMAIN: u64 = 2 << 60;

// FSTS bits.
const FSTS_PFO: u32 = 1 << 0;
/// Primary pending fault: a record waits, and FRI says which.
const FSTS_PPF: u32 = 1 << 1;
/// Invalidation queue error: the unit stopped at a bad descriptor.
const FSTS_IQE: u32 = 1 << 4;
/// Invalidation queue, completion and time-out errors.
const FSTS_QI_ERRORS: u32 = FSTS_IQE | 1 << 5 | 1 << 6;

/// Fault recording register: F (bit 127), read/write type and reason.
const FRCD_F: u64 = 1 << 63;

/// Present bit of root, context, PASID directory and PASID table entries.
const PRESENT: u64 = 1;
/// Legacy context entry AW, and PASID table entry AW (bits 4:2): 48-bit address width, 4-level table.
const AW_48: u64 = 2;
/// PASID table entry translation type (bits 8:6): second level only.
const PGTT_SECOND_LEVEL: u64 = 2;

/// Bytes of one device's PASID structures: the directory page, then the first PASID table's page.
const PASID_BUF_LEN: usize = 8192;
/// Offset of the PASID table in that buffer.
const PASID_TABLE: usize = 4096;

struct Tables<'d, D: DmaAllocator + ?Sized> {
    dma: &'d D,
    root: OwnedDma<'d, D>,
    context: Pages<'d, D>,
    /// Scalable mode: per bus, a page of records (CPU pointer, device address) of
    /// the devices' [`PASID_BUF_LEN`] buffers.
    pasid: Option<Pages<'d, D>>,
}

/// The record in `aux` (a page of 256 records) for function `devfn`, as a buffer.
fn pasid_record(aux: &DmaBuffer, devfn: usize) -> Option<DmaBuffer> {
    let cpu = NonNull::new(aux.load::<u64>(devfn * 16) as *mut u8)?;
    let device = PhysAddr::new(aux.load::<u64>(devfn * 16 + 8));
    // SAFETY: recorded by `pasid_buf` from a buffer of this length that the
    // owning `Tables` has not freed.
    Some(unsafe { DmaBuffer::new(cpu, device, PASID_BUF_LEN) })
}

/// The PASID directory and table of `device`, allocating them if `create`.
fn pasid_buf<D: DmaAllocator + ?Sized>(
    tables: &Tables<'_, D>,
    device: DeviceId,
    create: bool,
) -> Result<Option<DmaBuffer>, IommuError> {
    let pasid = tables.pasid.as_ref().ok_or(IommuError::Unsupported)?;
    let bus = device.bus() as usize;
    let devfn = (device.bdf() & 0xff) as usize;
    let aux = if create { pasid.get_or_alloc(bus)?.0 } else { pasid.get(bus).ok_or(IommuError::NotAttached)? };
    if let Some(buf) = pasid_record(&aux, devfn) {
        return Ok(Some(buf));
    }
    if !create {
        return Ok(None);
    }
    let buf = tables.dma.alloc_coherent(PASID_BUF_LEN).ok_or(IommuError::OutOfMemory)?;
    aux.store::<u64>(devfn * 16, buf.cpu_ptr().as_ptr() as u64);
    aux.store::<u64>(devfn * 16 + 8, buf.device_addr().as_u64());
    Ok(Some(buf))
}

impl<D: DmaAllocator + ?Sized> Drop for Tables<'_, D> {
    fn drop(&mut self) {
        let Some(pasid) = &self.pasid else { return };
        for bus in 0..256 {
            let Some(aux) = pasid.get(bus) else { continue };
            for devfn in 0..256 {
                if let Some(buf) = pasid_record(&aux, devfn) {
                    // SAFETY: allocated from `dma` in `pasid_buf`, and the
                    // owner stopped the hardware before dropping the tables.
                    unsafe { self.dma.free_coherent(buf) };
                }
            }
        }
    }
}

struct State<'d, D: DmaAllocator + ?Sized> {
    tables: Option<Tables<'d, D>>,
    /// Persistent GCMD bits as last written.
    gcmd: u32,
    /// Next fault-recording register to read.
    next_fault: usize,
    /// The interrupt remapping table, once enabled.
    ir: Option<remap::Remap<'d, D>>,
}

/// An Intel VT-d remapping unit.
pub struct Vtd<'d, D: DmaAllocator + Sync + ?Sized> {
    regs: Regs,
    dma: &'d D,
    clock: &'d dyn Clock,
    segment: u16,
    cap: u64,
    ecap: u64,
    /// Scalable-mode tables rather than legacy.
    scalable: bool,
    /// Offset of the IOTLB invalidate register.
    iotlb: usize,
    /// Offset of the first fault recording register.
    frcd: usize,
    nfr: usize,
    domains: u32,
    iova_limit: u64,
    timeout_ns: u64,
    /// Lock order: `state`, then `qi`.
    state: IrqSpinLock<State<'d, D>>,
    qi: IrqSpinLock<Option<qi::Queue<'d, D>>>,
    /// Whether invalidations go through `qi`.
    qi_on: AtomicBool,
}

impl<'d, D: DmaAllocator + Sync + ?Sized> Vtd<'d, D> {
    /// Takes over the unit whose registers are `io`, serving PCI segment
    /// `segment`, in legacy mode. Translation stays off until the first
    /// device attaches. Fails with [`IommuError::Unsupported`] if the unit
    /// does not snoop the CPU caches when it walks tables (`ECAP.C`).
    pub fn new(io: IoMem, dma: &'d D, clock: &'d dyn Clock, segment: u16) -> Result<Self, IommuError> {
        Self::build(io, dma, clock, segment, false, false)
    }

    /// Like [`new`](Self::new), but accepts a unit that reports `ECAP.C`
    /// clear.
    ///
    /// # Safety
    /// The caller guarantees the unit sees the CPU's table writes without
    /// any cache maintenance: it is emulated, or the memory the tables
    /// live in is uncached or write-through. Otherwise it walks stale tables.
    pub unsafe fn new_assuming_coherent(
        io: IoMem,
        dma: &'d D,
        clock: &'d dyn Clock,
        segment: u16,
    ) -> Result<Self, IommuError> {
        Self::build(io, dma, clock, segment, true, false)
    }

    /// Like [`new`](Self::new), but in scalable mode. Fails with
    /// [`IommuError::Unsupported`] unless the unit has scalable mode, second-level
    /// translation in it and queued invalidation.
    pub fn new_scalable(io: IoMem, dma: &'d D, clock: &'d dyn Clock, segment: u16) -> Result<Self, IommuError> {
        Self::build(io, dma, clock, segment, false, true)
    }

    /// Like [`new_scalable`](Self::new_scalable), but accepts a unit that
    /// reports `ECAP.C` clear.
    ///
    /// # Safety
    /// As for [`new_assuming_coherent`](Self::new_assuming_coherent).
    pub unsafe fn new_scalable_assuming_coherent(
        io: IoMem,
        dma: &'d D,
        clock: &'d dyn Clock,
        segment: u16,
    ) -> Result<Self, IommuError> {
        Self::build(io, dma, clock, segment, true, true)
    }

    fn build(
        io: IoMem,
        dma: &'d D,
        clock: &'d dyn Clock,
        segment: u16,
        assume_coherent: bool,
        scalable: bool,
    ) -> Result<Self, IommuError> {
        let regs = Regs::new(io, 0x100)?;
        let ver = regs.r32(VER);
        if ver == 0 || ver == !0 {
            return Err(IommuError::BadRegisters);
        }
        let (cap, ecap) = (regs.r64(CAP), regs.r64(ECAP));
        if (ecap & ECAP_C == 0 && !assume_coherent) || (cap >> 8) & 0x4 == 0 {
            return Err(IommuError::Unsupported);
        }
        if scalable && ecap & (ECAP_SMTS | ECAP_SLTS | ECAP_QI) != ECAP_SMTS | ECAP_SLTS | ECAP_QI {
            return Err(IommuError::Unsupported);
        }
        let nd = (cap & 7) as u32;
        if nd > 6 {
            return Err(IommuError::Unsupported);
        }
        let iotlb = ((ecap >> 8) & 0x3ff) as usize * 16 + 8;
        let frcd = ((cap >> 24) & 0x3ff) as usize * 16;
        let nfr = ((cap >> 40) & 0xff) as usize + 1;
        if iotlb + 8 > regs.len() || frcd + nfr * 16 > regs.len() {
            return Err(IommuError::BadRegisters);
        }
        let mgaw = ((cap >> 16) & 0x3f) as u32 + 1;
        let root = OwnedDma::new(dma, 4096).ok_or(IommuError::OutOfMemory)?;
        // Scalable mode splits a bus's context table in two pages.
        let context = Pages::new(dma, if scalable { 512 } else { 256 })?;
        let pasid = if scalable { Some(Pages::new(dma, 256)?) } else { None };
        let tables = Tables { dma, root, context, pasid };
        let gcmd = regs.r32(GSTS) & PERSISTENT;
        let vtd = Self {
            regs,
            dma,
            clock,
            segment,
            cap,
            ecap,
            scalable,
            iotlb,
            frcd,
            nfr,
            domains: 1 << (4 + 2 * nd),
            iova_limit: 1 << mgaw.min(48),
            timeout_ns: DEFAULT_TIMEOUT_NS,
            state: IrqSpinLock::new(State { tables: Some(tables), gcmd, next_fault: 0, ir: None }),
            qi: IrqSpinLock::new(None),
            qi_on: AtomicBool::new(false),
        };
        {
            let mut st = vtd.state.lock();
            // Firmware may have left translation, interrupt remapping or queued invalidation on.
            vtd.set_enabled(&mut st, TE, false)?;
            vtd.set_enabled(&mut st, IRE, false)?;
            vtd.set_enabled(&mut st, QIE, false)?;
            if scalable {
                vtd.enable_qi(&mut st)?;
            }
            let root = st.tables.as_ref().ok_or(IommuError::Unsupported)?.root.device_addr();
            vtd.regs.w64(RTADDR, root.as_u64() | if scalable { RTADDR_SCALABLE } else { 0 });
            vtd.regs.w32(GCMD, st.gcmd | SRTP);
            vtd.wait(|| vtd.regs.r32(GSTS) & SRTP != 0)?;
            vtd.flush_write_buffer(&st)?;
            vtd.invalidate_all()?;
        }
        Ok(vtd)
    }

    /// Sets how long to wait for the hardware, in nanoseconds.
    pub fn set_timeout_ns(&mut self, timeout_ns: u64) {
        self.timeout_ns = timeout_ns;
    }

    /// Whether translation is switched on (after the first attach).
    pub fn translating(&self) -> bool {
        self.regs.r32(GSTS) & TE != 0
    }

    /// Whether the unit uses scalable-mode tables.
    pub fn scalable(&self) -> bool {
        self.scalable
    }

    fn wait(&self, done: impl FnMut() -> bool) -> Result<(), IommuError> {
        wait_until(self.clock, self.timeout_ns, done)
    }

    fn set_enabled(&self, st: &mut State<'d, D>, bit: u32, on: bool) -> Result<(), IommuError> {
        if (self.regs.r32(GSTS) & bit != 0) == on {
            return Ok(());
        }
        if on {
            st.gcmd |= bit;
        } else {
            st.gcmd &= !bit;
        }
        self.regs.w32(GCMD, st.gcmd);
        self.wait(|| (self.regs.r32(GSTS) & bit != 0) == on)
    }

    fn flush_write_buffer(&self, st: &State<'d, D>) -> Result<(), IommuError> {
        if self.cap & CAP_RWBF == 0 {
            return Ok(());
        }
        self.regs.w32(GCMD, st.gcmd | WBF);
        self.wait(|| self.regs.r32(GSTS) & WBF == 0)
    }

    /// Drain-reads and drain-writes bits for the register IOTLB command.
    fn drain_bits(&self) -> u64 {
        let mut bits = 0;
        if self.cap & CAP_DWD != 0 {
            bits |= 1 << 48;
        }
        if self.cap & CAP_DRD != 0 {
            bits |= 1 << 49;
        }
        bits
    }

    fn invalidate_context(&self, granularity: u64) -> Result<(), IommuError> {
        self.regs.w64(CCMD, ICC | granularity);
        self.wait(|| self.regs.r64(CCMD) & ICC == 0)
    }

    /// Flushes every cached context, PASID and IOTLB entry.
    fn invalidate_all(&self) -> Result<(), IommuError> {
        if self.qi_active() {
            self.qi_context(qi::GRAN_GLOBAL, 0, 0)?;
            if self.scalable {
                self.qi_pasid_cache(0, None)?;
            }
            return self.qi_iotlb(qi::GRAN_GLOBAL, 0);
        }
        self.invalidate_context(CIRG_GLOBAL)?;
        self.regs.w64(self.iotlb, IVT | IIRG_GLOBAL | self.drain_bits());
        self.wait(|| self.regs.r64(self.iotlb) & IVT == 0)
    }

    /// Flushes cached entries for `device` (context cache, and in scalable
    /// mode its PASID 0) and the IOTLB entries of `domain`.
    fn invalidate_device(&self, device: DeviceId, domain: u16) -> Result<(), IommuError> {
        if self.qi_active() {
            self.qi_context(qi::GRAN_DEVICE, domain, device.bdf())?;
            if self.scalable {
                self.qi_pasid_cache(domain, Some(0))?;
            }
            return self.qi_iotlb(qi::GRAN_DOMAIN, domain);
        }
        let cmd = CIRG_DEVICE | (device.bdf() as u64) << 16 | domain as u64;
        self.invalidate_context(cmd)?;
        self.invalidate_domain(domain)
    }

    fn invalidate_domain(&self, domain: u16) -> Result<(), IommuError> {
        if self.qi_active() {
            return self.qi_iotlb(qi::GRAN_DOMAIN, domain);
        }
        self.regs.w64(self.iotlb, IVT | IIRG_DOMAIN | self.drain_bits() | (domain as u64) << 32);
        self.wait(|| self.regs.r64(self.iotlb) & IVT == 0)
    }

    /// Where `device`'s context entry lives: the offset of the root-table
    /// word that points at the context table, that table's slot in the
    /// tables' index, and the entry's offset in it.
    fn context_location(&self, device: DeviceId) -> (usize, usize, usize) {
        let bus = device.bus() as usize;
        let devfn = (device.bdf() & 0xff) as usize;
        if self.scalable {
            // Functions 0 to 127 use the low pointer, 128 to 255 the high one.
            let half = devfn >> 7;
            (bus * 16 + half * 8, bus * 2 + half, (devfn & 0x7f) * 32)
        } else {
            (bus * 16, bus, devfn * 16)
        }
    }

    /// Takes `device`'s context entry (at `off` in `ctx`) and, in scalable
    /// mode, its PASID 0 entry out of service. Caller invalidates.
    fn unlink(&self, tables: &Tables<'d, D>, ctx: &DmaBuffer, off: usize, device: DeviceId) {
        ctx.store::<u64>(off, 0);
        barrier::dma_wmb();
        if self.scalable {
            if let Ok(Some(buf)) = pasid_buf(tables, device, false) {
                buf.store::<u64>(PASID_TABLE, 0);
            }
            barrier::dma_wmb();
        }
        ctx.store::<u64>(off + 8, 0);
        barrier::mb();
    }
}

impl<D: DmaAllocator + Sync + ?Sized> Iommu for Vtd<'_, D> {
    type Format = VtdSecondLevel;

    fn iova_limit(&self) -> u64 {
        self.iova_limit
    }

    fn max_leaf_size(&self) -> osmium_mm::paging::PageSize {
        // CAP.SLLPS: bit 34 for 2 MiB second-level pages, bit 35 for 1 GiB. A
        // 1 GiB-only unit (2) is treated as pages only: the generic code uses
        // 2 MiB wherever it does not use 1 GiB, so it needs both.
        match (self.cap >> 34) & 3 {
            3 => osmium_mm::paging::PageSize::Size1G,
            1 => osmium_mm::paging::PageSize::Size2M,
            _ => osmium_mm::paging::PageSize::Size4K,
        }
    }

    unsafe fn attach(&self, device: DeviceId, domain: DomainId, root: PhysAddr) -> Result<(), IommuError> {
        if device.segment() != self.segment {
            return Err(IommuError::InvalidDevice);
        }
        if domain.0 as u32 >= self.domains || (self.cap & CAP_CM != 0 && domain.0 == 0) {
            return Err(IommuError::Unsupported);
        }
        if !root.is_aligned(4096) {
            return Err(IommuError::OutOfRange);
        }
        let mut st = self.state.lock();
        let tables = st.tables.as_mut().ok_or(IommuError::Unsupported)?;
        let (root_off, slot, off) = self.context_location(device);
        let (ctx, created) = tables.context.get_or_alloc(slot)?;
        if created {
            // Zeroed, so every entry is not-present until linked.
            barrier::dma_wmb();
            tables.root.store::<u64>(root_off, ctx.device_addr().as_u64() | PRESENT);
        }
        if ctx.load::<u64>(off) & PRESENT != 0 {
            return Err(IommuError::Busy);
        }
        if self.scalable {
            let pasid = pasid_buf(tables, device, true)?.ok_or(IommuError::OutOfMemory)?;
            let table = pasid.device_addr().as_u64() + PASID_TABLE as u64;
            // Directory entry 0 -> the table; its entry 0 (the RID_PASID) -> the domain's table.
            pasid.store::<u64>(0, table | PRESENT);
            for q in 1..8 {
                pasid.store::<u64>(PASID_TABLE + q * 8, 0);
            }
            pasid.store::<u64>(PASID_TABLE + 8, domain.0 as u64);
            barrier::dma_wmb();
            pasid.store::<u64>(PASID_TABLE, root.as_u64() | PGTT_SECOND_LEVEL << 6 | AW_48 << 2 | PRESENT);
            // Context entry: RID_PASID 0, no PASID-tagged requests, no device TLB, directory
            // size field 0 (128 directory entries).
            for q in 1..4 {
                ctx.store::<u64>(off + q * 8, 0);
            }
            barrier::dma_wmb();
            ctx.store::<u64>(off, pasid.device_addr().as_u64() | PRESENT);
        } else {
            ctx.store::<u64>(off + 8, AW_48 | (domain.0 as u64) << 8);
            barrier::dma_wmb();
            ctx.store::<u64>(off, root.as_u64() | PRESENT);
        }
        // The next steps write registers: only a full barrier orders the entry before them.
        barrier::mb();
        let result = self
            .flush_write_buffer(&st)
            .and_then(|()| self.invalidate_device(device, domain.0))
            .and_then(|()| self.set_enabled(&mut st, TE, true));
        if result.is_err() {
            // Do not leave a half-attached device pointing at the caller's table.
            if let Some(tables) = st.tables.as_ref()
                && let Some(ctx) = tables.context.get(slot)
            {
                self.unlink(tables, &ctx, off, device);
            }
            let _ = self.invalidate_device(device, domain.0);
        }
        result
    }

    fn detach(&self, device: DeviceId) -> Result<(), IommuError> {
        if device.segment() != self.segment {
            return Err(IommuError::InvalidDevice);
        }
        let st = self.state.lock();
        let tables = st.tables.as_ref().ok_or(IommuError::NotAttached)?;
        let (_, slot, off) = self.context_location(device);
        let ctx =
            tables.context.get(slot).filter(|c| c.load::<u64>(off) & PRESENT != 0).ok_or(IommuError::NotAttached)?;
        let domain = if self.scalable {
            let pasid = pasid_buf(tables, device, false)?.ok_or(IommuError::NotAttached)?;
            (pasid.load::<u64>(PASID_TABLE + 8) & 0xffff) as u16
        } else {
            (ctx.load::<u64>(off + 8) >> 8) as u16
        };
        self.unlink(tables, &ctx, off, device);
        self.flush_write_buffer(&st)?;
        self.invalidate_device(device, domain)
    }

    fn invalidate(&self, domain: DomainId) -> Result<(), IommuError> {
        let st = self.state.lock();
        self.flush_write_buffer(&st)?;
        self.invalidate_domain(domain.0)
    }

    fn take_fault(&self) -> Option<Fault> {
        let mut st = self.state.lock();
        // With a record pending, FRI names the oldest one: take it as the
        // cursor, so records left by firmware or an earlier owner are found.
        let fsts = self.regs.r32(FSTS);
        if fsts & FSTS_PPF != 0 {
            let fri = (fsts >> 8 & 0xff) as usize;
            if fri < self.nfr {
                st.next_fault = fri;
            }
        }
        let at = self.frcd + st.next_fault * 16;
        let hi = self.regs.r64(at + 8);
        if hi & FRCD_F == 0 {
            // Records lost to overflow are gone; acknowledge so logging resumes.
            if self.regs.r32(FSTS) & FSTS_PFO != 0 {
                self.regs.w32(FSTS, FSTS_PFO);
            }
            return None;
        }
        let lo = self.regs.r64(at);
        // Clear F (write one) to hand the record back to the hardware.
        self.regs.w64(at + 8, FRCD_F);
        st.next_fault = (st.next_fault + 1) % self.nfr;
        let sid = hi as u16;
        Some(Fault {
            device: DeviceId::new(
                self.segment,
                osmium_hal::pci::Address::new((sid >> 8) as u8, (sid >> 3) as u8 & 31, sid as u8 & 7),
            ),
            iova: lo & !0xfff,
            // Bit 126 is the request type: 1 for a read.
            write: hi & (1 << 62) == 0,
            reason: ((hi >> 32) & 0xff) as u32,
        })
    }
}

impl<D: DmaAllocator + Sync + ?Sized> Drop for Vtd<'_, D> {
    fn drop(&mut self) {
        let mut st = self.state.lock();
        let tables = ManuallyDrop::new(st.tables.take());
        let ir = ManuallyDrop::new(st.ir.take());
        // If remapping or translation would not stop the unit may still read the tables.
        let ir_off = self.set_enabled(&mut st, IRE, false).is_ok();
        let te_off = self.set_enabled(&mut st, TE, false).is_ok();
        // Frees the queue unless the unit does not stop.
        let _ = self.disable_qi(&mut st);
        if te_off {
            drop(ManuallyDrop::into_inner(tables));
        }
        if ir_off {
            drop(ManuallyDrop::into_inner(ir));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::vec::Vec;

    use osmium_hal::iommu::{IoDomain, IommuDma};
    use osmium_hal::pci::Address;
    use osmium_mm::paging::MapFlags;

    use super::super::testing::*;
    use super::remap::{Irte, Source};
    use super::*;

    const REGS: usize = 0x1000;
    /// IOTLB registers at ECAP.IRO * 16 (the invalidate register is 8 on), fault records at CAP.FRO * 16.
    const IOTLB_BASE: usize = 0x100;
    const FRO: usize = 0x40;
    const NIC: Address = Address::new(0, 3, 1);
    const FAR: Address = Address::new(5, 0x1f, 7);

    fn dev(a: Address) -> DeviceId {
        DeviceId::new(0, a)
    }

    const SCALABLE: u64 = ECAP_SMTS | ECAP_SLTS | ECAP_QI;
    const REMAP: u64 = ECAP_IR | ECAP_QI | ECAP_EIM;

    #[derive(Default)]
    struct Hw {
        root: u64,
        /// The root table is in scalable mode.
        smt: bool,
        /// Interrupt remapping table base, size and mode as latched by SIRTP.
        irta: u64,
        /// GSTS bits the unit keeps set whatever the driver asks.
        pin_status: Option<u32>,
        log: Vec<std::string::String>,
        /// Never completes invalidations.
        stall: bool,
    }

    /// Plays the remapping unit: latches the root pointer, acknowledges
    /// commands, and (through `translate`) walks the tables it was given.
    struct Fake {
        regs: HostRegs,
        hw: Arc<Mutex<Hw>>,
        _pump: Pump,
    }

    /// Executes the descriptors between the queue's head and tail.
    fn process_queue(r: &HostRegs, hw: &mut Hw) {
        let (iqa, tail) = (r.r64(IQA), r.r64(IQT));
        let (base, len) = (iqa & !0xfff, if iqa & 1 << 11 != 0 { 32 } else { 16 });
        let mut head = r.r64(IQH);
        // After a queue error the unit waits for software to acknowledge it.
        while head != tail && r.r32(FSTS) & FSTS_IQE == 0 {
            let (lo, hi) = (mem64(base + head), mem64(base + head + 8));
            let (g, did) = (lo >> 4 & 3, lo >> 16 & 0xffff);
            match lo & 0xf {
                1 => hw.log.push(std::format!("qi ctx g{g} did {did} sid {:#x}", lo >> 32 & 0xffff)),
                2 => hw.log.push(std::format!("qi iotlb g{g} did {did}")),
                4 => hw.log.push(std::format!("qi iec g{g} idx {}", lo >> 32 & 0xffff)),
                7 => hw.log.push(std::format!("qi pasid g{g} did {did} pasid {}", lo >> 32 & 0xfffff)),
                5 => {
                    if lo & 1 << 5 != 0 {
                        // SAFETY: the driver's status word, in a live DMA allocation.
                        unsafe { (hi as *mut u32).write_volatile((lo >> 32) as u32) };
                    }
                }
                t => {
                    hw.log.push(std::format!("qi bad type {t}"));
                    r.w32(FSTS, r.r32(FSTS) | 1 << 4);
                    return;
                }
            }
            head = (head + len) % 4096;
            r.w64(IQH, head);
        }
    }

    fn fake(cap_extra: u64, ecap_extra: u64) -> Fake {
        let regs = HostRegs::new(REGS);
        regs.w32(VER, 0x10);
        // ND=2, SAGAW = 3- and 4-level, MGAW=47, FRO=4 (x16), NFR=2.
        regs.w64(CAP, 2 | 0x6 << 8 | 47 << 16 | (FRO as u64 / 16) << 24 | 1 << 40 | cap_extra);
        regs.w64(ECAP, ECAP_C | (IOTLB_BASE as u64 / 16) << 8 | ecap_extra);
        let hw = Arc::new(Mutex::new(Hw::default()));
        let (r, h) = (regs.clone(), hw.clone());
        let pump = Pump::start(move || {
            let mut hw = h.lock().unwrap();
            let g = r.r32(GCMD);
            let mut s = r.r32(GSTS);
            if g & SRTP != 0 {
                let rt = r.r64(RTADDR);
                hw.root = rt & !0xfff;
                hw.smt = rt & RTADDR_SCALABLE != 0;
                hw.log.push("srtp".into());
                s |= SRTP;
                r.w32(GCMD, g & !SRTP);
            }
            if g & SIRTP != 0 {
                hw.irta = r.r64(IRTA);
                hw.log.push("sirtp".into());
                s |= SIRTP;
                r.w32(GCMD, r.r32(GCMD) & !SIRTP);
            }
            if g & WBF != 0 {
                r.w32(GCMD, r.r32(GCMD) & !WBF);
                hw.log.push("wbf".into());
            }
            // Persistent bits follow their commands.
            for bit in [TE, QIE, IRE, CFI] {
                s = if g & bit != 0 { s | bit } else { s & !bit };
            }
            if let Some(pinned) = hw.pin_status {
                s |= pinned;
            }
            r.w32(GSTS, s);
            // F is write-one-to-clear: the driver writes just F to hand a record back.
            for i in 0..2 {
                if r.r64(FRO + i * 16 + 8) == FRCD_F {
                    r.w64(FRO + i * 16 + 8, 0);
                }
            }
            // Like the other write-one-to-clear bits: the driver writes all the error bits at once.
            if r.r32(FSTS) & FSTS_QI_ERRORS == FSTS_QI_ERRORS {
                r.w32(FSTS, r.r32(FSTS) & !FSTS_QI_ERRORS);
            }
            if hw.stall {
                return;
            }
            if s & QIE != 0 {
                process_queue(&r, &mut hw);
            }
            let c = r.r64(CCMD);
            if c & ICC != 0 {
                hw.log.push(std::format!("ctx {:#x} did {}", (c >> 61) & 3, c & 0xffff));
                r.w64(CCMD, c & !ICC);
            }
            let t = r.r64(IOTLB_BASE + 8);
            if t & IVT != 0 {
                hw.log.push(std::format!("iotlb {} did {}", (t >> 60) & 3, (t >> 32) & 0xffff));
                r.w64(IOTLB_BASE + 8, t & !IVT);
            }
        });
        Fake { regs, hw, _pump: pump }
    }

    impl Fake {
        fn log(&self) -> Vec<std::string::String> {
            self.hw.lock().unwrap().log.clone()
        }

        fn translating(&self) -> bool {
            self.regs.r32(GSTS) & TE != 0
        }

        /// Walks the legacy-mode tables for `sid` and `iova`, as the unit would.
        fn translate(&self, sid: u16, iova: u64, write: bool) -> Result<u64, &'static str> {
            if !self.translating() {
                return Ok(iova); // untranslated
            }
            let (root, smt) = {
                let hw = self.hw.lock().unwrap();
                (hw.root, hw.smt)
            };
            let rootent = mem64(root + (sid >> 8) as u64 * 16 + if smt { (sid >> 7 & 1) as u64 * 8 } else { 0 });
            if rootent & 1 == 0 {
                return Err("root entry not present");
            }
            let (mut table, levels);
            if smt {
                let ctx = (rootent & !0xfff) + (sid & 0x7f) as u64 * 32;
                let lo = mem64(ctx);
                if lo & 1 == 0 {
                    return Err("context entry not present");
                }
                assert_eq!(lo & 0xffe, 0, "PASIDE, DTE and PDTS are unused");
                let rid_pasid = mem64(ctx + 8) & 0xf_ffff;
                let dirent = mem64((lo & !0xfff) + (rid_pasid >> 6) * 8);
                if dirent & 1 == 0 {
                    return Err("PASID directory entry not present");
                }
                let pe = (dirent & !0xfff) + (rid_pasid & 63) * 64;
                let q0 = mem64(pe);
                if q0 & 1 == 0 {
                    return Err("PASID entry not present");
                }
                assert_eq!(q0 >> 6 & 7, 2, "second-level translation only");
                levels = match q0 >> 2 & 7 {
                    2 => 4,
                    1 => 3,
                    _ => return Err("bad address width"),
                };
                table = q0 & !0xfff & 0x000f_ffff_ffff_ffff;
            } else {
                let ctx = (rootent & !0xfff) + (sid & 0xff) as u64 * 16;
                let (lo, hi) = (mem64(ctx), mem64(ctx + 8));
                if lo & 1 == 0 {
                    return Err("context entry not present");
                }
                assert_eq!(lo >> 2 & 3, 0, "translation type: untranslated requests via second level");
                levels = match hi & 7 {
                    2 => 4,
                    1 => 3,
                    _ => return Err("bad address width"),
                };
                table = lo & !0xfff & 0x000f_ffff_ffff_ffff;
            }
            for level in (0..levels).rev() {
                let e = mem64(table + ((iova >> (12 + 9 * level)) & 0x1ff) * 8);
                if e & 3 == 0 {
                    return Err("not present");
                }
                if write && e & 2 == 0 || !write && e & 1 == 0 {
                    return Err("permission");
                }
                if level == 0 || e & 0x80 != 0 {
                    let size = 1u64 << (12 + 9 * level);
                    return Ok((e & 0x000f_ffff_ffff_f000 & !(size - 1)) | (iova & (size - 1)));
                }
                table = e & 0x000f_ffff_ffff_f000;
            }
            panic!("walk did not terminate")
        }

        /// Looks `handle` up in the interrupt remapping table as the unit would, and
        /// returns the delivered (vector, destination) if `sid` may use it.
        fn remap(&self, sid: u16, handle: u16) -> Result<(u8, u32), &'static str> {
            if self.regs.r32(GSTS) & IRE == 0 {
                return Err("remapping off");
            }
            let irta = self.hw.lock().unwrap().irta;
            if handle as u64 >= 1 << ((irta & 0xf) + 1) {
                return Err("index out of range");
            }
            let at = (irta & !0xfff) + handle as u64 * 16;
            let (lo, hi) = (mem64(at), mem64(at + 8));
            if lo & 1 == 0 {
                return Err("entry not present");
            }
            match hi >> 18 & 3 {
                0 => {}
                1 if hi as u16 == sid => {}
                2 if (hi >> 8) as u8 <= (sid >> 8) as u8 && (sid >> 8) as u8 <= hi as u8 => {}
                _ => return Err("source mismatch"),
            }
            let dest = if irta & 1 << 11 != 0 { (lo >> 32) as u32 } else { (lo >> 40) as u8 as u32 };
            Ok((((lo >> 16) & 0xff) as u8, dest))
        }

        fn domain_of(&self, sid: u16) -> u64 {
            let (root, smt) = {
                let hw = self.hw.lock().unwrap();
                (hw.root, hw.smt)
            };
            if smt {
                let ent = mem64(root + (sid >> 8) as u64 * 16 + (sid >> 7 & 1) as u64 * 8);
                let ctx = (ent & !0xfff) + (sid & 0x7f) as u64 * 32;
                let dir = mem64(ctx) & !0xfff;
                let table = mem64(dir) & !0xfff;
                return mem64(table + 8) & 0xffff;
            }
            let ctx = (mem64(root + (sid >> 8) as u64 * 16) & !0xfff) + (sid & 0xff) as u64 * 16;
            mem64(ctx + 8) >> 8 & 0xffff
        }

        fn record_fault(&self, index: usize, sid: u16, iova: u64, reason: u8, read: bool) {
            let at = FRO + index * 16;
            self.regs.w64(at, iova & !0xfff);
            self.regs.w64(at + 8, FRCD_F | (read as u64) << 62 | (reason as u64) << 32 | sid as u64);
        }
    }

    fn setup<'dev>(f: &Fake, dma: &'dev HostDma, clock: &'dev StdClock) -> Vtd<'dev, HostDma> {
        Vtd::new(f.regs.io(), dma, clock, 0).expect("unit comes up")
    }

    #[test]
    fn programs_root_table_and_stays_off() {
        let (f, dma, clock) = (fake(0, 0), HostDma::default(), StdClock::default());
        let vtd = setup(&f, &dma, &clock);
        let log = f.log();
        assert_eq!(&log[..2], ["srtp", "ctx 0x1 did 0"], "root pointer, then a global context flush: {log:?}");
        assert!(log[2].starts_with("iotlb 1"), "global IOTLB flush");
        assert!(!f.translating() && !vtd.translating());
        assert_eq!(dma.live(), 2, "the root table and the context-table index");
        assert_eq!(vtd.iova_limit(), 1 << 48);
        drop(vtd);
        assert_eq!(dma.live(), 0);
    }

    #[test]
    fn large_page_support_follows_sllps() {
        use osmium_mm::paging::PageSize;
        let (clock, dma) = (StdClock::default(), HostDma::default());
        let cases = [(0, PageSize::Size4K), (1, PageSize::Size2M), (2, PageSize::Size4K), (3, PageSize::Size1G)];
        for (sllps, want) in cases {
            let f = fake(sllps << 34, 0);
            let vtd = Vtd::new(f.regs.io(), &dma, &clock, 0).unwrap();
            assert_eq!(vtd.max_leaf_size(), want, "SLLPS {sllps}");
        }
    }

    #[test]
    fn refuses_unsuitable_hardware() {
        let clock = StdClock::default();
        let dma = HostDma::default();
        let blank = HostRegs::new(REGS);
        assert_eq!(Vtd::new(blank.io(), &dma, &clock, 0).err(), Some(IommuError::BadRegisters));
        let small = HostRegs::new(0x80);
        assert_eq!(Vtd::new(small.io(), &dma, &clock, 0).err(), Some(IommuError::BadRegisters));

        // No coherent walks.
        let f = fake(0, 0);
        f.regs.w64(ECAP, f.regs.r64(ECAP) & !ECAP_C);
        assert_eq!(Vtd::new(f.regs.io(), &dma, &clock, 0).err(), Some(IommuError::Unsupported));
        // Without ECAP.C only the explicit constructor takes it.
        let f = fake(0, 0);
        f.regs.w64(ECAP, f.regs.r64(ECAP) & !ECAP_C);
        assert_eq!(Vtd::new(f.regs.io(), &dma, &clock, 0).err(), Some(IommuError::Unsupported));
        // SAFETY: the fake is plain memory.
        assert!(unsafe { Vtd::new_assuming_coherent(f.regs.io(), &dma, &clock, 0) }.is_ok());
        // 3-level tables only.
        let f = fake(0, 0);
        f.regs.w64(CAP, f.regs.r64(CAP) & !(0x4 << 8));
        assert_eq!(Vtd::new(f.regs.io(), &dma, &clock, 0).err(), Some(IommuError::Unsupported));
        assert_eq!(dma.live(), 0, "nothing leaked on failure");
    }

    #[test]
    fn attach_translates_and_detach_blocks() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let vtd = setup(&f, &dma, &clock);
        let mut d = IoDomain::new(&vtd, DomainId(7), &tables).unwrap();
        let backing = HostDma::default();
        let buf = backing.alloc_coherent(8192).unwrap();
        d.map(0x20_0000, buf.device_addr(), 0x2000, MapFlags::RW).unwrap();
        d.map(0x40_0000, buf.device_addr(), 0x1000, MapFlags::READ).unwrap();

        // Before attach, translation is off and nothing is mapped for the NIC.
        assert!(!f.translating());
        d.attach(dev(NIC)).unwrap();
        assert!(f.translating(), "first attach turns the unit on");
        let sid = dev(NIC).bdf();
        assert_eq!(f.domain_of(sid), 7);
        let base = buf.device_addr().as_u64();
        assert_eq!(f.translate(sid, 0x20_0123, true), Ok(base + 0x123));
        assert_eq!(f.translate(sid, 0x20_1fff, false), Ok(base + 0x1fff));
        assert_eq!(f.translate(sid, 0x40_0000, false), Ok(base));
        assert_eq!(f.translate(sid, 0x40_0000, true), Err("permission"));
        assert_eq!(f.translate(sid, 0x30_0000, false), Err("not present"));
        // A device that is not attached is blocked, even on an attached bus.
        assert_eq!(f.translate(dev(Address::new(0, 3, 2)).bdf(), 0x20_0000, false), Err("context entry not present"));
        assert_eq!(f.translate(dev(FAR).bdf(), 0x20_0000, false), Err("root entry not present"));

        // Mapping after attach shows up, and unmapping removes it.
        d.map(0x50_0000, buf.device_addr() + 0x1000, 0x1000, MapFlags::RW).unwrap();
        assert_eq!(f.translate(sid, 0x50_0008, true), Ok(base + 0x1008));
        d.unmap(0x50_0000, 0x1000).unwrap();
        assert_eq!(f.translate(sid, 0x50_0008, true), Err("not present"));
        let log = f.log();
        assert!(log.iter().any(|l| l == "iotlb 2 did 7"), "domain-selective flush: {log:?}");
        assert!(log.iter().any(|l| l.starts_with("ctx 0x3 did 7")), "device-selective context flush");

        assert_eq!(d.attach(dev(NIC)), Err(IommuError::Busy));
        d.detach(dev(NIC)).unwrap();
        assert_eq!(f.translate(sid, 0x20_0000, false), Err("context entry not present"));
        assert_eq!(d.detach(dev(NIC)), Err(IommuError::NotAttached));
        drop(d);
        // SAFETY: nothing maps it any more.
        unsafe { backing.free_coherent(buf) };
        assert_eq!(tables.live.load(core::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn two_buses_two_domains() {
        let (f, dma, clock) = (fake(0, 0), HostDma::default(), StdClock::default());
        let (t1, t2) = (HostTables::default(), HostTables::default());
        let vtd = setup(&f, &dma, &clock);
        let mut a = IoDomain::new(&vtd, DomainId(1), &t1).unwrap();
        let mut b = IoDomain::new(&vtd, DomainId(2), &t2).unwrap();
        a.map(0x1000, PhysAddr::new(0xaaa000), 0x1000, MapFlags::RW).unwrap();
        b.map(0x1000, PhysAddr::new(0xbbb000), 0x1000, MapFlags::RW).unwrap();
        a.attach(dev(NIC)).unwrap();
        b.attach(dev(FAR)).unwrap();
        assert_eq!(f.translate(dev(NIC).bdf(), 0x1000, false), Ok(0xaaa000));
        assert_eq!(f.translate(dev(FAR).bdf(), 0x1000, false), Ok(0xbbb000));
        assert_eq!(dma.live(), 2 + 2, "root, index, and a context table per bus");
        drop(a);
        drop(b);
        assert_eq!(f.translate(dev(NIC).bdf(), 0x1000, false), Err("context entry not present"));
    }

    #[test]
    fn rejects_bad_requests() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let vtd = setup(&f, &dma, &clock);
        let mut other_segment = IoDomain::new(&vtd, DomainId(1), &tables).unwrap();
        assert_eq!(other_segment.attach(DeviceId::new(1, NIC)), Err(IommuError::InvalidDevice));
        // ND = 2: 1 << (4 + 4) = 256 domains.
        let mut big = IoDomain::new(&vtd, DomainId(256), &tables).unwrap();
        assert_eq!(big.attach(dev(NIC)), Err(IommuError::Unsupported));
        // The failed attach left no trace.
        assert!(!f.translating());
        assert_eq!(big.detach(dev(NIC)), Err(IommuError::NotAttached));
    }

    #[test]
    fn caching_mode_reserves_domain_zero() {
        let (f, dma, clock, tables) = (fake(CAP_CM, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let vtd = setup(&f, &dma, &clock);
        let mut d = IoDomain::new(&vtd, DomainId(0), &tables).unwrap();
        assert_eq!(d.attach(dev(NIC)), Err(IommuError::Unsupported));
    }

    #[test]
    fn write_buffer_flush_when_required() {
        let (f, dma, clock, tables) =
            (fake(CAP_RWBF, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let vtd = setup(&f, &dma, &clock);
        let mut d = IoDomain::new(&vtd, DomainId(1), &tables).unwrap();
        d.attach(dev(NIC)).unwrap();
        assert!(f.log().iter().filter(|l| *l == "wbf").count() >= 2);
    }

    #[test]
    fn invalidation_timeout_rolls_back_attach() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let mut vtd = setup(&f, &dma, &clock);
        vtd.set_timeout_ns(50_000_000);
        f.hw.lock().unwrap().stall = true;
        {
            let mut d = IoDomain::new(&vtd, DomainId(1), &tables).unwrap();
            assert_eq!(d.attach(dev(NIC)), Err(IommuError::Timeout));
            assert!(!f.translating(), "never switched on");
            // The context entry is not left pointing at the table.
            let root = f.hw.lock().unwrap().root;
            let ctx = mem64(root) & !0xfff;
            assert_eq!(mem64(ctx + dev(NIC).bdf() as u64 * 16), 0);
        }
        f.hw.lock().unwrap().stall = false;
        let mut d = IoDomain::new(&vtd, DomainId(1), &tables).unwrap();
        d.attach(dev(NIC)).unwrap();
    }

    #[test]
    fn fault_cursor_follows_fri() {
        let (f, dma, clock) = (fake(0, 0), HostDma::default(), StdClock::default());
        let vtd = setup(&f, &dma, &clock);
        // A record left at index 1 (as after firmware ran), with FRI pointing at it.
        f.record_fault(1, dev(FAR).bdf(), 0x9000, 5, true);
        f.regs.w32(FSTS, FSTS_PPF | 1 << 8);
        assert_eq!(vtd.take_fault().unwrap().iova, 0x9000);
        std::thread::sleep(core::time::Duration::from_millis(5));
        f.regs.w32(FSTS, 0);
        assert_eq!(vtd.take_fault(), None);
    }

    #[test]
    fn faults_are_read_and_acknowledged() {
        let (f, dma, clock) = (fake(0, 0), HostDma::default(), StdClock::default());
        let vtd = setup(&f, &dma, &clock);
        assert_eq!(vtd.take_fault(), None);
        f.record_fault(0, dev(NIC).bdf(), 0x1234_5678, 6, false);
        f.record_fault(1, dev(FAR).bdf(), 0x9000, 5, true);
        // The fake clears F on its own thread; give it a moment after each take.
        let settle = || std::thread::sleep(core::time::Duration::from_millis(5));
        let a = vtd.take_fault().unwrap();
        settle();
        assert_eq!((a.device, a.iova, a.write, a.reason), (dev(NIC), 0x1234_5000, true, 6));
        let b = vtd.take_fault().unwrap();
        settle();
        assert_eq!((b.device, b.iova, b.write, b.reason), (dev(FAR), 0x9000, false, 5));
        assert_eq!(vtd.take_fault(), None);
        assert_eq!(f.regs.r64(FRO + 8) & FRCD_F, 0, "F bit cleared for reuse");
        // Wraps back to the first record.
        f.record_fault(0, dev(NIC).bdf(), 0x2000, 6, true);
        assert_eq!(vtd.take_fault().unwrap().iova, 0x2000);
        settle();
    }

    #[test]
    fn takes_over_firmware_state() {
        let (f, dma, clock) = (fake(0, 0), HostDma::default(), StdClock::default());
        // Firmware left translation and queued invalidation on.
        f.regs.w32(GSTS, TE | QIE);
        f.regs.w32(GCMD, TE | QIE);
        let vtd = setup(&f, &dma, &clock);
        assert!(!f.translating());
        assert_eq!(f.regs.r32(GSTS) & QIE, 0);
        drop(vtd);
    }

    #[test]
    fn iommu_dma_end_to_end() {
        let (f, dma, clock, tables) = (fake(0, 0), HostDma::default(), StdClock::default(), HostTables::default());
        let backing = HostDma::default();
        let vtd = setup(&f, &dma, &clock);
        let alloc = {
            let domain = IoDomain::new(&vtd, DomainId(3), &tables).unwrap();
            IommuDma::new(domain, &backing, 0x10_0000..0xfee0_0000).unwrap()
        };
        alloc.with_domain(|d| d.attach(dev(NIC))).unwrap();
        let ring = alloc.alloc_coherent(4096).unwrap();
        ring.store::<u32>(8, 0xc0ffee);
        let iova = ring.device_addr().as_u64();
        assert_eq!(iova, 0x10_0000);
        let pa = f.translate(dev(NIC).bdf(), iova + 8, true).unwrap();
        assert_eq!(mem32(pa), 0xc0ffee, "device reads what the CPU wrote, via the IOVA");
        // Outside the buffer the device gets nothing.
        assert_eq!(f.translate(dev(NIC).bdf(), iova + 4096, false), Err("not present"));
        // SAFETY: the "device" is the fake and is idle.
        unsafe { alloc.free_coherent(ring) };
        assert_eq!(f.translate(dev(NIC).bdf(), iova, false), Err("not present"));
        assert_eq!(backing.live(), 0);
        alloc.with_domain(|d| d.detach(dev(NIC))).unwrap();
    }

    fn scalable<'dev>(f: &Fake, dma: &'dev HostDma, clock: &'dev StdClock) -> Vtd<'dev, HostDma> {
        Vtd::new_scalable(f.regs.io(), dma, clock, 0).expect("scalable unit comes up")
    }

    #[test]
    fn scalable_mode_needs_scalable_hardware() {
        let (dma, clock) = (HostDma::default(), StdClock::default());
        for ecap in [0, ECAP_SMTS | ECAP_QI, ECAP_SMTS | ECAP_SLTS, ECAP_SLTS | ECAP_QI] {
            let f = fake(0, ecap);
            assert_eq!(Vtd::new_scalable(f.regs.io(), &dma, &clock, 0).err(), Some(IommuError::Unsupported));
        }
        assert_eq!(dma.live(), 0);
        // Legacy mode still works on such a unit.
        let f = fake(0, SCALABLE);
        let vtd = setup(&f, &dma, &clock);
        assert!(!vtd.scalable());
        assert_eq!(f.regs.r32(GSTS) & QIE, 0, "legacy mode keeps register invalidation");
    }

    #[test]
    fn scalable_mode_comes_up_through_the_queue() {
        let (dma, clock) = (HostDma::default(), StdClock::default());
        let f = fake(0, SCALABLE);
        let vtd = scalable(&f, &dma, &clock);
        assert!(vtd.scalable() && !vtd.translating());
        assert_ne!(f.regs.r32(GSTS) & QIE, 0);
        assert_ne!(f.regs.r64(IQA) & 1 << 11, 0, "256-bit descriptors");
        assert!(f.hw.lock().unwrap().smt, "root table type");
        let log = f.log();
        assert_eq!(log, ["srtp", "qi ctx g1 did 0 sid 0x0", "qi pasid g3 did 0 pasid 0", "qi iotlb g1 did 0"]);
        // root, two-page context index, PASID index, queue and status.
        assert_eq!(dma.live(), 4);
        drop(vtd);
        assert_eq!(dma.live(), 0);
        assert_eq!(f.regs.r32(GSTS) & QIE, 0);
    }

    #[test]
    fn scalable_attach_translates_and_detach_blocks() {
        let (dma, clock, tables) = (HostDma::default(), StdClock::default(), HostTables::default());
        let f = fake(0, SCALABLE);
        let vtd = scalable(&f, &dma, &clock);
        let backing = HostDma::default();
        let buf = backing.alloc_coherent(8192).unwrap();
        let base = buf.device_addr().as_u64();
        let mut d = IoDomain::new(&vtd, DomainId(7), &tables).unwrap();
        d.map(0x20_0000, buf.device_addr(), 0x2000, MapFlags::RW).unwrap();
        d.map(0x40_0000, buf.device_addr(), 0x1000, MapFlags::READ).unwrap();
        // Functions below and above 128 of one bus use the two halves of the root entry.
        let (low, high) = (dev(NIC), dev(Address::new(0, 0x1f, 7)));
        d.attach(low).unwrap();
        d.attach(high).unwrap();
        assert!(f.translating());
        for sid in [low.bdf(), high.bdf()] {
            assert_eq!(f.domain_of(sid), 7);
            assert_eq!(f.translate(sid, 0x20_0123, true), Ok(base + 0x123));
            assert_eq!(f.translate(sid, 0x40_0000, false), Ok(base));
            assert_eq!(f.translate(sid, 0x40_0000, true), Err("permission"));
            assert_eq!(f.translate(sid, 0x30_0000, false), Err("not present"));
        }
        assert_eq!(f.translate(dev(Address::new(0, 3, 2)).bdf(), 0x20_0000, false), Err("context entry not present"));
        assert_eq!(f.translate(dev(FAR).bdf(), 0x20_0000, false), Err("root entry not present"));
        // The mapping change reaches the unit through a domain-selective IOTLB descriptor.
        d.map(0x50_0000, buf.device_addr() + 0x1000, 0x1000, MapFlags::RW).unwrap();
        assert_eq!(f.translate(low.bdf(), 0x50_0008, true), Ok(base + 0x1008));
        let log = f.log();
        assert!(log.iter().any(|l| l == "qi ctx g3 did 7 sid 0x19"), "device-selective context flush: {log:?}");
        assert!(log.iter().any(|l| l == "qi pasid g1 did 7 pasid 0"), "PASID-selective flush: {log:?}");
        assert!(log.iter().any(|l| l == "qi iotlb g2 did 7"), "domain-selective IOTLB flush: {log:?}");
        assert!(!log.iter().any(|l| l.starts_with("ctx ") || l.starts_with("iotlb ")), "no register invalidation");

        assert_eq!(d.attach(low), Err(IommuError::Busy));
        let live = dma.live();
        d.detach(low).unwrap();
        assert_eq!(f.translate(low.bdf(), 0x20_0000, false), Err("context entry not present"));
        assert_eq!(f.translate(high.bdf(), 0x20_0000, true), Ok(base), "the other half is untouched");
        assert_eq!(d.detach(low), Err(IommuError::NotAttached));
        // Attaching again reuses the PASID structures.
        d.attach(low).unwrap();
        assert_eq!(dma.live(), live);
        assert_eq!(f.translate(low.bdf(), 0x20_0000, true), Ok(base));
        drop(d);
        assert_eq!(f.translate(low.bdf(), 0x20_0000, false), Err("context entry not present"));
        drop(vtd);
        // SAFETY: nothing maps it any more.
        unsafe { backing.free_coherent(buf) };
        assert_eq!(dma.live(), 0, "PASID buffers freed too");
        assert_eq!(tables.live.load(core::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn scalable_attach_rolls_back_when_the_queue_stalls() {
        let (dma, clock, tables) = (HostDma::default(), StdClock::default(), HostTables::default());
        let f = fake(0, SCALABLE);
        let mut vtd = scalable(&f, &dma, &clock);
        vtd.set_timeout_ns(50_000_000);
        f.hw.lock().unwrap().stall = true;
        {
            let mut d = IoDomain::new(&vtd, DomainId(1), &tables).unwrap();
            assert_eq!(d.attach(dev(NIC)), Err(IommuError::Timeout));
            assert!(!f.translating());
        }
        f.hw.lock().unwrap().stall = false;
        // The stalled descriptors drain, and the queue is usable again.
        std::thread::sleep(core::time::Duration::from_millis(20));
        let mut d = IoDomain::new(&vtd, DomainId(1), &tables).unwrap();
        d.attach(dev(NIC)).unwrap();
        assert!(f.translating());
    }

    #[test]
    fn queue_errors_are_reported_and_recovered() {
        let (dma, clock) = (HostDma::default(), StdClock::default());
        let f = fake(0, SCALABLE);
        let vtd = scalable(&f, &dma, &clock);
        assert_eq!(vtd.qi_submit([0xf, 0]), Err(IommuError::Hardware));
        std::thread::sleep(core::time::Duration::from_millis(5));
        assert_eq!(f.regs.r32(FSTS) & FSTS_QI_ERRORS, 0, "error acknowledged");
        // Skip the bad descriptor as the unit would, and carry on.
        vtd.qi_iec(None).unwrap();
    }

    #[test]
    fn takes_over_firmware_interrupt_remapping() {
        let (f, dma, clock) = (fake(0, REMAP), HostDma::default(), StdClock::default());
        f.regs.w32(GSTS, TE | QIE | IRE);
        f.regs.w32(GCMD, TE | QIE | IRE);
        let vtd = setup(&f, &dma, &clock);
        assert_eq!(f.regs.r32(GSTS) & (TE | QIE | IRE), 0);
        assert_eq!(vtd.interrupt_entries(), 0);
        assert!(!vtd.interrupt_remapping_enabled());
    }

    #[test]
    fn interrupt_remapping_lifecycle() {
        let (f, dma, clock) = (fake(0, REMAP), HostDma::default(), StdClock::default());
        let vtd = setup(&f, &dma, &clock);
        assert!(vtd.supports_interrupt_remapping() && vtd.supports_extended_interrupt_mode());
        let sid = dev(NIC).bdf();
        assert_eq!(vtd.set_irte(0, &Irte::fixed(0x40, 1, Source::Any)), Err(IommuError::NotAttached));
        assert_eq!(f.remap(sid, 0), Err("remapping off"));

        // Bad sizes.
        for n in [0, 1, 3, 255, 1 << 17] {
            assert_eq!(vtd.enable_interrupt_remapping(n, false, false), Err(IommuError::OutOfRange), "{n}");
        }
        assert_eq!(dma.live(), 2, "nothing allocated yet");
        vtd.enable_interrupt_remapping(256, false, false).unwrap();
        assert_eq!(vtd.enable_interrupt_remapping(256, false, false), Err(IommuError::Busy));
        assert!(vtd.interrupt_remapping_enabled());
        assert_eq!(vtd.interrupt_entries(), 256);
        assert_eq!(f.regs.r32(GSTS) & CFI, 0, "compatibility-format interrupts blocked");
        let irta = f.regs.r64(IRTA);
        assert_eq!(irta & 0xf, 7, "2^(7+1) entries");
        assert_eq!(irta & 1 << 11, 0, "xAPIC mode");
        let log = f.log();
        assert!(log.ends_with(&["sirtp".into(), "qi iec g0 idx 0".into()]), "{log:?}");
        assert_ne!(f.regs.r32(GSTS) & QIE, 0, "remapping brings the queue up");

        // Entries start out blocked.
        assert_eq!(f.remap(sid, 5), Err("entry not present"));
        let irte = Irte { vector: 0x61, destination: 3, level: true, ..Irte::fixed(0, 0, Source::Device(NIC)) };
        vtd.set_irte(5, &irte).unwrap();
        assert_eq!(f.remap(sid, 5), Ok((0x61, 3)));
        assert_eq!(f.remap(dev(FAR).bdf(), 5), Err("source mismatch"));
        assert_eq!(vtd.irte(5), Some(irte));
        assert!(f.log().iter().any(|l| l == "qi iec g1 idx 5"), "entry-selective invalidation");
        // Retarget; a bus range admits the NIC but not the far bus.
        let wide = Irte::fixed(0x62, 0xff, Source::Buses { first: 0, last: 3 });
        vtd.set_irte(5, &wide).unwrap();
        assert_eq!(f.remap(sid, 5), Ok((0x62, 0xff)));
        assert_eq!(f.remap(dev(FAR).bdf(), 5), Err("source mismatch"));
        // xAPIC IDs are 8 bits.
        assert_eq!(vtd.set_irte(6, &Irte::fixed(0x62, 0x100, Source::Any)), Err(IommuError::OutOfRange));
        assert_eq!(vtd.set_irte(256, &irte), Err(IommuError::OutOfRange));
        assert_eq!(f.remap(sid, 6), Err("entry not present"));

        vtd.clear_irte(5).unwrap();
        assert_eq!(f.remap(sid, 5), Err("entry not present"));
        assert_eq!(vtd.irte(5), None);
        assert_eq!(vtd.clear_irte(256), Err(IommuError::OutOfRange));

        // A message built for the handle selects the same entry in the address.
        let m = remap::msi_message(5);
        assert_eq!(m.address >> 5 & 0x7fff, 5);
        vtd.disable_interrupt_remapping().unwrap();
        assert!(!vtd.interrupt_remapping_enabled());
        assert_eq!(vtd.disable_interrupt_remapping(), Err(IommuError::NotAttached));
        // Can be enabled again, in extended mode, with compatibility format on.
        vtd.enable_interrupt_remapping(2, true, true).unwrap();
        assert_ne!(f.regs.r32(GSTS) & CFI, 0);
        assert_ne!(f.regs.r64(IRTA) & 1 << 11, 0);
        vtd.set_irte(1, &Irte::fixed(0x70, 0x1234, Source::Any)).unwrap();
        assert_eq!(f.remap(sid, 1), Ok((0x70, 0x1234)));
        assert_eq!(f.remap(sid, 2), Err("index out of range"));
        drop(vtd);
        assert_eq!(f.regs.r32(GSTS) & (IRE | QIE), 0);
        assert_eq!(dma.live(), 0, "table and queue freed");
    }

    #[test]
    fn interrupt_remapping_needs_hardware_support() {
        let (dma, clock) = (HostDma::default(), StdClock::default());
        // No IR, IR without the queue, and no extended mode.
        for ecap in [0, ECAP_IR, ECAP_QI] {
            let f = fake(0, ecap);
            let vtd = setup(&f, &dma, &clock);
            assert!(!vtd.supports_interrupt_remapping());
            assert_eq!(vtd.enable_interrupt_remapping(256, false, false), Err(IommuError::Unsupported));
        }
        let f = fake(0, ECAP_IR | ECAP_QI);
        let vtd = setup(&f, &dma, &clock);
        assert_eq!(vtd.enable_interrupt_remapping(256, true, false), Err(IommuError::Unsupported));
        vtd.enable_interrupt_remapping(256, false, false).unwrap();
    }

    #[test]
    fn legacy_translation_uses_the_queue_once_remapping_starts_it() {
        let (f, dma, clock, tables) = (fake(0, REMAP), HostDma::default(), StdClock::default(), HostTables::default());
        let vtd = setup(&f, &dma, &clock);
        vtd.enable_interrupt_remapping(8, false, false).unwrap();
        let mut d = IoDomain::new(&vtd, DomainId(4), &tables).unwrap();
        d.map(0x1000, PhysAddr::new(0xaaa000), 0x1000, MapFlags::RW).unwrap();
        d.attach(dev(NIC)).unwrap();
        assert_eq!(f.translate(dev(NIC).bdf(), 0x1000, false), Ok(0xaaa000));
        let log = f.log();
        assert!(log.iter().any(|l| l == "qi ctx g3 did 4 sid 0x19"), "{log:?}");
        assert!(log.iter().any(|l| l == "qi iotlb g2 did 4"));
        let queued = log.iter().position(|l| l == "sirtp").unwrap();
        assert!(
            !log[queued..].iter().any(|l| l.starts_with("ctx ") || l.starts_with("iotlb ")),
            "no register invalidation after the queue starts: {log:?}"
        );
        drop(d);
    }

    #[test]
    fn remapping_that_will_not_stop_leaks_its_table() {
        let (f, dma, clock) = (fake(0, REMAP), HostDma::default(), StdClock::default());
        let mut vtd = setup(&f, &dma, &clock);
        vtd.set_timeout_ns(20_000_000);
        vtd.enable_interrupt_remapping(4, false, false).unwrap();
        // The unit stops acknowledging.
        f.hw.lock().unwrap().pin_status = Some(IRE | QIE | TE);
        let before = dma.live();
        drop(vtd);
        assert_eq!(dma.live(), before, "the tables, remapping table and queue stay allocated");
    }
}
