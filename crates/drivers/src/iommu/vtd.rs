//! Intel VT-d DMA remapping.
//!
//! [`Vtd`] drives one remapping unit (a DRHD in the ACPI DMAR table) in
//! legacy mode: a root table of 256 bus entries, each pointing at a context
//! table of 256 device/function entries, each pointing at a second-level
//! page table in [`VtdSecondLevel`] format with a 48-bit, four-level walk.
//! Invalidation uses the register interface (context-command and IOTLB
//! registers), so no invalidation queue is needed; a queue the firmware left
//! enabled is switched off.
//!
//! It needs `CAP.SAGAW` bit 2 (4-level tables) and, from [`Vtd::new`],
//! `ECAP.C` (the unit's table walks snoop the CPU caches). A unit without it
//! needs cache lines written back after every table change, which this tree
//! has no way to do, so [`Vtd::new`] refuses it; QEMU's model reports the
//! bit clear although its memory is always coherent, and
//! [`Vtd::new_assuming_coherent`] is for that. With caching mode (`CAP.CM`, as in virtual machines) domain 0 is
//! reserved and the driver invalidates after every change, as it does anyway.
//! Scalable mode, interrupt remapping, device IOTLBs and nested translation
//! are not used. Pass-through is not offered: unattached devices are blocked
//! once translation is on.
//!
//! Faults are read back from the fault-recording registers by
//! [`Iommu::take_fault`]; the fault interrupt stays masked.

use core::mem::ManuallyDrop;

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::iommu::{DeviceId, DomainId, Fault, Iommu, IommuError};
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;
use osmium_mm::PhysAddr;
use osmium_mm::paging::formats::VtdSecondLevel;
use osmium_sync::IrqSpinLock;

use super::{DEFAULT_TIMEOUT_NS, Pages, Regs, wait_until};

// Registers.
const VER: usize = 0x00;
const CAP: usize = 0x08;
const ECAP: usize = 0x10;
const GCMD: usize = 0x18;
const GSTS: usize = 0x1c;
const RTADDR: usize = 0x20;
const CCMD: usize = 0x28;
const FSTS: usize = 0x34;

// GCMD/GSTS bits (the command and its status share a position).
const TE: u32 = 1 << 31;
const SRTP: u32 = 1 << 30;
const WBF: u32 = 1 << 27;
const QIE: u32 = 1 << 26;
const IRE: u32 = 1 << 25;
const CFI: u32 = 1 << 23;
/// Bits of GSTS that persist and must be written back with every command.
const PERSISTENT: u32 = TE | QIE | IRE | CFI;

// CAP fields.
const CAP_RWBF: u64 = 1 << 4;
const CAP_CM: u64 = 1 << 7;
const CAP_DWD: u64 = 1 << 54;
const CAP_DRD: u64 = 1 << 55;
const ECAP_C: u64 = 1 << 0;

// Command and IOTLB registers.
const ICC: u64 = 1 << 63;
const CIRG_GLOBAL: u64 = 1 << 61;
const CIRG_DEVICE: u64 = 3 << 61;
const IVT: u64 = 1 << 63;
const IIRG_GLOBAL: u64 = 1 << 60;
const IIRG_DOMAIN: u64 = 2 << 60;
const IOTLB_DW: u64 = 1 << 48;
const IOTLB_DR: u64 = 1 << 49;

// FSTS bits.
const FSTS_PFO: u32 = 1 << 0;

/// Fault recording register: F (bit 127), read/write type and reason.
const FRCD_F: u64 = 1 << 63;

/// Legacy-mode entries.
const PRESENT: u64 = 1;
/// Context entry AW: 48-bit address width, 4-level table.
const AW_48: u64 = 2;

struct Tables<'d, D: DmaAllocator + ?Sized> {
    root: OwnedDma<'d, D>,
    context: Pages<'d, D>,
}

struct State<'d, D: DmaAllocator + ?Sized> {
    tables: Option<Tables<'d, D>>,
    /// Persistent GCMD bits as last written.
    gcmd: u32,
    /// Next fault-recording register to read.
    next_fault: usize,
}

/// An Intel VT-d remapping unit.
pub struct Vtd<'d, D: DmaAllocator + Sync + ?Sized> {
    regs: Regs,
    clock: &'d dyn Clock,
    segment: u16,
    cap: u64,
    /// Offset of the IOTLB invalidate register.
    iotlb: usize,
    /// Offset of the first fault recording register.
    frcd: usize,
    nfr: usize,
    domains: u32,
    iova_limit: u64,
    timeout_ns: u64,
    state: IrqSpinLock<State<'d, D>>,
}

impl<'d, D: DmaAllocator + Sync + ?Sized> Vtd<'d, D> {
    /// Takes over the unit whose registers are `io`, serving PCI segment
    /// `segment`. Translation stays off until the first device attaches.
    /// Fails with [`IommuError::Unsupported`] if the unit does not snoop
    /// the CPU caches when it walks tables (`ECAP.C`).
    pub fn new(io: IoMem, dma: &'d D, clock: &'d dyn Clock, segment: u16) -> Result<Self, IommuError> {
        Self::build(io, dma, clock, segment, false)
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
        Self::build(io, dma, clock, segment, true)
    }

    fn build(
        io: IoMem,
        dma: &'d D,
        clock: &'d dyn Clock,
        segment: u16,
        assume_coherent: bool,
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
        let tables = Tables { root, context: Pages::new(dma, 256)? };
        let gcmd = regs.r32(GSTS) & PERSISTENT;
        let vtd = Self {
            regs,
            clock,
            segment,
            cap,
            iotlb,
            frcd,
            nfr,
            domains: 1 << (4 + 2 * nd),
            iova_limit: 1 << mgaw.min(48),
            timeout_ns: DEFAULT_TIMEOUT_NS,
            state: IrqSpinLock::new(State { tables: Some(tables), gcmd, next_fault: 0 }),
        };
        {
            let mut st = vtd.state.lock();
            // Firmware may have left translation or queued invalidation on.
            vtd.set_enabled(&mut st, TE, false)?;
            vtd.set_enabled(&mut st, QIE, false)?;
            let root = st.tables.as_ref().expect("just made").root.device_addr();
            vtd.regs.w64(RTADDR, root.as_u64());
            vtd.regs.w32(GCMD, st.gcmd | SRTP);
            vtd.wait(|| vtd.regs.r32(GSTS) & SRTP != 0)?;
            vtd.flush_write_buffer(&st)?;
            vtd.invalidate_context(CIRG_GLOBAL)?;
            vtd.regs.w64(vtd.iotlb, IVT | IIRG_GLOBAL | vtd.drain_bits());
            vtd.wait(|| vtd.regs.r64(vtd.iotlb) & IVT == 0)?;
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

    fn drain_bits(&self) -> u64 {
        let mut bits = 0;
        if self.cap & CAP_DWD != 0 {
            bits |= IOTLB_DW;
        }
        if self.cap & CAP_DRD != 0 {
            bits |= IOTLB_DR;
        }
        bits
    }

    fn invalidate_context(&self, granularity: u64) -> Result<(), IommuError> {
        self.regs.w64(CCMD, ICC | granularity);
        self.wait(|| self.regs.r64(CCMD) & ICC == 0)
    }

    /// Flushes cached entries for `device` (context cache) and the IOTLB
    /// entries of `domain`.
    fn invalidate_device(&self, device: DeviceId, domain: u16) -> Result<(), IommuError> {
        let cmd = CIRG_DEVICE | (device.bdf() as u64) << 16 | domain as u64;
        self.invalidate_context(cmd)?;
        self.invalidate_domain(domain)
    }

    fn invalidate_domain(&self, domain: u16) -> Result<(), IommuError> {
        self.regs.w64(self.iotlb, IVT | IIRG_DOMAIN | self.drain_bits() | (domain as u64) << 32);
        self.wait(|| self.regs.r64(self.iotlb) & IVT == 0)
    }
}

impl<D: DmaAllocator + Sync + ?Sized> Iommu for Vtd<'_, D> {
    type Format = VtdSecondLevel;

    fn iova_limit(&self) -> u64 {
        self.iova_limit
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
        let bus = device.bus() as usize;
        let (ctx, created) = tables.context.get_or_alloc(bus)?;
        if created {
            // Zeroed, so every entry is not-present until linked.
            barrier::dma_wmb();
            tables.root.store::<u64>(bus * 16, ctx.device_addr().as_u64() | PRESENT);
        }
        let off = (device.bdf() & 0xff) as usize * 16;
        if ctx.load::<u64>(off) & PRESENT != 0 {
            return Err(IommuError::Busy);
        }
        ctx.store::<u64>(off + 8, AW_48 | (domain.0 as u64) << 8);
        barrier::dma_wmb();
        ctx.store::<u64>(off, root.as_u64() | PRESENT);
        barrier::dma_wmb();
        let result = self
            .flush_write_buffer(&st)
            .and_then(|()| self.invalidate_device(device, domain.0))
            .and_then(|()| self.set_enabled(&mut st, TE, true));
        if result.is_err() {
            // Do not leave a half-attached device pointing at the caller's table.
            let tables = st.tables.as_mut().expect("checked above");
            let ctx = tables.context.get(bus).expect("made above");
            ctx.store::<u64>(off, 0);
            barrier::dma_wmb();
            ctx.store::<u64>(off + 8, 0);
            let _ = self.invalidate_device(device, domain.0);
        }
        result
    }

    fn detach(&self, device: DeviceId) -> Result<(), IommuError> {
        if device.segment() != self.segment {
            return Err(IommuError::InvalidDevice);
        }
        let mut st = self.state.lock();
        let tables = st.tables.as_mut().ok_or(IommuError::NotAttached)?;
        let off = (device.bdf() & 0xff) as usize * 16;
        let ctx = tables
            .context
            .get(device.bus() as usize)
            .filter(|c| c.load::<u64>(off) & PRESENT != 0)
            .ok_or(IommuError::NotAttached)?;
        let domain = (ctx.load::<u64>(off + 8) >> 8) as u16;
        ctx.store::<u64>(off, 0);
        barrier::dma_wmb();
        ctx.store::<u64>(off + 8, 0);
        barrier::dma_wmb();
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
        let off = self.set_enabled(&mut st, TE, false).is_ok();
        // If translation would not stop the unit may still read the tables.
        if off {
            drop(ManuallyDrop::into_inner(tables));
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

    #[derive(Default)]
    struct Hw {
        root: u64,
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
                hw.root = r.r64(RTADDR);
                hw.log.push("srtp".into());
                s |= SRTP;
                r.w32(GCMD, g & !SRTP);
            }
            if g & WBF != 0 {
                r.w32(GCMD, r.r32(GCMD) & !WBF);
                hw.log.push("wbf".into());
            }
            // Persistent bits follow their commands.
            for bit in [TE, QIE] {
                s = if g & bit != 0 { s | bit } else { s & !bit };
            }
            r.w32(GSTS, s);
            // F is write-one-to-clear: the driver writes just F to hand a record back.
            for i in 0..2 {
                if r.r64(FRO + i * 16 + 8) == FRCD_F {
                    r.w64(FRO + i * 16 + 8, 0);
                }
            }
            if hw.stall {
                return;
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
            let root = self.hw.lock().unwrap().root;
            let rootent = mem64(root + (sid >> 8) as u64 * 16);
            if rootent & 1 == 0 {
                return Err("root entry not present");
            }
            let ctx = (rootent & !0xfff) + (sid & 0xff) as u64 * 16;
            let (lo, hi) = (mem64(ctx), mem64(ctx + 8));
            if lo & 1 == 0 {
                return Err("context entry not present");
            }
            assert_eq!(lo >> 2 & 3, 0, "translation type: untranslated requests via second level");
            let levels = match hi & 7 {
                2 => 4,
                1 => 3,
                _ => return Err("bad address width"),
            };
            let mut table = lo & !0xfff & 0x000f_ffff_ffff_ffff;
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
            unreachable!()
        }

        fn domain_of(&self, sid: u16) -> u64 {
            let root = self.hw.lock().unwrap().root;
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
}
