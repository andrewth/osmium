//! AMD-Vi (the AMD IOMMU).
//!
//! [`AmdVi`] drives one unit (an IVHD block in the ACPI IVRS table). A device
//! table with a 32-byte entry per requester ID (bus/device/function) points
//! each device at a four-level I/O page table
//! ([`osmium_mm::paging::formats::AmdVi`]). Software talks to the unit
//! through a command buffer in memory (device-table and page invalidations,
//! completion waits) and reads faults from an event log; both are 256
//! entries of 16 bytes.
//!
//! The unit is switched on when the driver starts, because command
//! processing needs it, with an all-zero device table. An invalid entry lets
//! a device's DMA through untranslated (Linux marks idle devices blocked for
//! that reason), so the first attach writes a blocked entry (valid, no page
//! table, no permissions) for every other requester ID the table covers, and
//! detaching a device blocks it again.
//!
//! Interrupts from attached devices are forwarded unchanged (`IntCtl` = 1 in
//! the device table entry; blocked devices have theirs aborted); interrupt
//! remapping is not used. Only 4 KiB pages are used, the guest-translation,
//! PPR and GA logs are left off, and the unit's own coherency control is not
//! touched.

use core::mem::ManuallyDrop;

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::iommu::{DeviceId, DomainId, Fault, Iommu, IommuError};
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::Address;
use osmium_hal::timer::Clock;
use osmium_mm::PhysAddr;
use osmium_mm::paging::formats::AmdVi as PageFormat;
use osmium_sync::IrqSpinLock;

use super::{DEFAULT_TIMEOUT_NS, Regs, wait_until};

// Registers.
const DEV_TAB_BAR: usize = 0x0000;
const CMD_BUF_BAR: usize = 0x0008;
const EVT_LOG_BAR: usize = 0x0010;
const CONTROL: usize = 0x0018;
const CMD_HEAD: usize = 0x2000;
const CMD_TAIL: usize = 0x2008;
const EVT_HEAD: usize = 0x2010;
const EVT_TAIL: usize = 0x2018;
const STATUS: usize = 0x2020;
const REGS_LEN: usize = 0x2028;

// CONTROL bits.
const IOMMU_EN: u64 = 1 << 0;
const EVENT_LOG_EN: u64 = 1 << 2;
const CMD_BUF_EN: u64 = 1 << 12;

// STATUS bits.
const EVENT_OVERFLOW: u64 = 1 << 0;
const EVENT_LOG_RUN: u64 = 1 << 3;
const CMD_BUF_RUN: u64 = 1 << 4;

/// Command buffer and event log: 2^8 entries of 16 bytes = one page.
const QUEUE_BYTES: usize = 4096;
const QUEUE_LEN_CODE: u64 = 8 << 56;
const ENTRY: usize = 16;

// Commands (opcode in bits 63:60 of the first quadword).
const OP_COMPLETION_WAIT: u64 = 0x1;
const OP_INVALIDATE_DEVTAB_ENTRY: u64 = 0x2;
const OP_INVALIDATE_PAGES: u64 = 0x3;

// Device table entry.
const DTE_BYTES: usize = 32;
const DTE_V: u64 = 1 << 0;
const DTE_TV: u64 = 1 << 1;
const DTE_MODE_4: u64 = 4 << 9;
const DTE_MODE_MASK: u64 = 7 << 9;
/// Valid with translation but no page table or permissions: blocks the device.
const DTE_BLOCKED: u64 = DTE_V | DTE_TV;
const DTE_IR: u64 = 1 << 61;
const DTE_IW: u64 = 1 << 62;
/// IntCtl (bits 61:60 of the third quadword): forward interrupts as they are.
const DTE_INTCTL_FORWARD: u64 = 1 << 60;
const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

/// Invalidate-pages address operand meaning "everything" (S set, all ones).
const ALL_PAGES: u64 = 0x7fff_ffff_ffff_f000 | 0b11;

struct Buffers<'d, D: DmaAllocator + ?Sized> {
    devtab: OwnedDma<'d, D>,
    commands: OwnedDma<'d, D>,
    events: OwnedDma<'d, D>,
    /// Target of completion-wait stores.
    scratch: OwnedDma<'d, D>,
}

struct State<'d, D: DmaAllocator + ?Sized> {
    buffers: Option<Buffers<'d, D>>,
    /// Byte offset the next command goes to.
    tail: usize,
    /// Value the next completion-wait stores.
    wait_seq: u64,
    /// Whether every requester ID without a domain has been blocked.
    blocked: bool,
}

/// An AMD-Vi IOMMU.
pub struct AmdVi<'d, D: DmaAllocator + Sync + ?Sized> {
    regs: Regs,
    clock: &'d dyn Clock,
    /// Highest bus number the device table covers.
    max_bus: u8,
    segment: u16,
    timeout_ns: u64,
    state: IrqSpinLock<State<'d, D>>,
}

impl<'d, D: DmaAllocator + Sync + ?Sized> AmdVi<'d, D> {
    /// Takes over the unit whose registers are `io`, serving PCI segment
    /// `segment` and requesters on buses `0..=max_bus` (the device table costs
    /// 8 KiB per bus). Devices keep untranslated DMA until the first attach.
    pub fn new(io: IoMem, dma: &'d D, clock: &'d dyn Clock, segment: u16, max_bus: u8) -> Result<Self, IommuError> {
        let regs = Regs::new(io, REGS_LEN)?;
        if regs.r64(CONTROL) == !0 {
            return Err(IommuError::BadRegisters);
        }
        let devtab_bytes = (max_bus as usize + 1) * 256 * DTE_BYTES;
        let buffers = Buffers {
            devtab: OwnedDma::new(dma, devtab_bytes).ok_or(IommuError::OutOfMemory)?,
            commands: OwnedDma::new(dma, QUEUE_BYTES).ok_or(IommuError::OutOfMemory)?,
            events: OwnedDma::new(dma, QUEUE_BYTES).ok_or(IommuError::OutOfMemory)?,
            scratch: OwnedDma::new(dma, 4096).ok_or(IommuError::OutOfMemory)?,
        };
        let unit = Self {
            regs,
            clock,
            max_bus,
            segment,
            timeout_ns: DEFAULT_TIMEOUT_NS,
            state: IrqSpinLock::new(State { buffers: None, tail: 0, wait_seq: 0, blocked: false }),
        };
        // Stop whatever firmware left running before pointing it at new tables.
        unit.regs.w64(CONTROL, 0);
        unit.wait(|| unit.regs.r64(STATUS) & (CMD_BUF_RUN | EVENT_LOG_RUN) == 0)?;
        unit.regs.w64(DEV_TAB_BAR, buffers.devtab.device_addr().as_u64() | (devtab_bytes / 4096 - 1) as u64);
        unit.regs.w64(CMD_BUF_BAR, buffers.commands.device_addr().as_u64() | QUEUE_LEN_CODE);
        unit.regs.w64(EVT_LOG_BAR, buffers.events.device_addr().as_u64() | QUEUE_LEN_CODE);
        for reg in [CMD_HEAD, CMD_TAIL, EVT_HEAD, EVT_TAIL] {
            unit.regs.w64(reg, 0);
        }
        unit.state.lock().buffers = Some(buffers);
        // The device table is all invalid, which passes DMA through.
        unit.regs.w64(CONTROL, CMD_BUF_EN | EVENT_LOG_EN | IOMMU_EN);
        unit.wait(|| unit.regs.r64(STATUS) & (CMD_BUF_RUN | EVENT_LOG_RUN) == CMD_BUF_RUN | EVENT_LOG_RUN)?;
        Ok(unit)
    }

    /// Sets how long to wait for the hardware, in nanoseconds.
    pub fn set_timeout_ns(&mut self, timeout_ns: u64) {
        self.timeout_ns = timeout_ns;
    }

    /// Whether devices without a domain are blocked (after the first attach).
    pub fn translating(&self) -> bool {
        self.state.lock().blocked
    }

    fn wait(&self, done: impl FnMut() -> bool) -> Result<(), IommuError> {
        wait_until(self.clock, self.timeout_ns, done)
    }

    fn buffers<'st>(st: &'st State<'d, D>) -> &'st Buffers<'d, D> {
        st.buffers.as_ref().expect("buffers exist after new")
    }

    fn post(&self, st: &mut State<'d, D>, q0: u64, q1: u64) -> Result<(), IommuError> {
        let next = (st.tail + ENTRY) % QUEUE_BYTES;
        if next as u64 == self.regs.r64(CMD_HEAD) {
            return Err(IommuError::Busy);
        }
        let cmds = &Self::buffers(st).commands;
        cmds.store::<u64>(st.tail, q0);
        cmds.store::<u64>(st.tail + 8, q1);
        barrier::dma_wmb();
        st.tail = next;
        self.regs.w64(CMD_TAIL, next as u64);
        Ok(())
    }

    /// Posts a completion wait and blocks until the unit has run every
    /// command before it.
    fn sync(&self, st: &mut State<'d, D>) -> Result<(), IommuError> {
        st.wait_seq += 1;
        let seq = st.wait_seq;
        let store = Self::buffers(st).scratch.device_addr().as_u64();
        self.post(st, (store & 0x000f_ffff_ffff_fff8) | 1 | OP_COMPLETION_WAIT << 60, seq)?;
        let scratch = &Self::buffers(st).scratch;
        self.wait(|| scratch.load::<u64>(0) == seq)?;
        barrier::dma_rmb();
        Ok(())
    }

    fn invalidate_pages(&self, st: &mut State<'d, D>, domain: u16) -> Result<(), IommuError> {
        self.post(st, (domain as u64) << 32 | OP_INVALIDATE_PAGES << 60, ALL_PAGES)
    }

    fn invalidate_device(&self, st: &mut State<'d, D>, requester: u16) -> Result<(), IommuError> {
        self.post(st, requester as u64 | OP_INVALIDATE_DEVTAB_ENTRY << 60, 0)
    }

    /// Writes a blocked entry for every requester ID without a valid one and
    /// makes the unit reread the device table.
    fn block_all(&self, st: &mut State<'d, D>) -> Result<(), IommuError> {
        let count = (self.max_bus as usize + 1) * 256;
        let devtab = &Self::buffers(st).devtab;
        for id in 0..count {
            let off = id * DTE_BYTES;
            if devtab.load::<u64>(off) & DTE_V == 0 {
                for q in 1..4 {
                    devtab.store::<u64>(off + q * 8, 0);
                }
                devtab.store::<u64>(off, DTE_BLOCKED);
            }
        }
        barrier::dma_wmb();
        for id in 0..count {
            self.invalidate_device(st, id as u16)?;
            // The command buffer holds 255 commands.
            if id % 64 == 63 {
                self.sync(st)?;
            }
        }
        self.sync(st)
    }

    /// Replaces `device`'s entry with a blocked one.
    fn block(&self, st: &State<'d, D>, off: usize) {
        let devtab = &Self::buffers(st).devtab;
        devtab.store::<u64>(off, DTE_BLOCKED);
        barrier::dma_wmb();
        for q in 1..4 {
            devtab.store::<u64>(off + q * 8, 0);
        }
        barrier::dma_wmb();
    }

    fn check(&self, device: DeviceId) -> Result<usize, IommuError> {
        if device.segment() != self.segment || device.bus() > self.max_bus {
            return Err(IommuError::InvalidDevice);
        }
        Ok(device.bdf() as usize * DTE_BYTES)
    }
}

impl<D: DmaAllocator + Sync + ?Sized> Iommu for AmdVi<'_, D> {
    type Format = PageFormat;

    fn iova_limit(&self) -> u64 {
        1 << 48
    }

    unsafe fn attach(&self, device: DeviceId, domain: DomainId, root: PhysAddr) -> Result<(), IommuError> {
        let off = self.check(device)?;
        if !root.is_aligned(4096) || root.as_u64() & !ADDR_MASK != 0 {
            return Err(IommuError::OutOfRange);
        }
        let mut st = self.state.lock();
        if Self::buffers(&st).devtab.load::<u64>(off) & DTE_MODE_MASK != 0 {
            return Err(IommuError::Busy);
        }
        if !st.blocked {
            self.block_all(&mut st)?;
            st.blocked = true;
        }
        let devtab = &Self::buffers(&st).devtab;
        devtab.store::<u64>(off + 8, domain.0 as u64);
        devtab.store::<u64>(off + 16, DTE_INTCTL_FORWARD);
        devtab.store::<u64>(off + 24, 0);
        barrier::dma_wmb();
        devtab.store::<u64>(off, root.as_u64() | DTE_V | DTE_TV | DTE_MODE_4 | DTE_IR | DTE_IW);
        barrier::dma_wmb();
        let result = self
            .invalidate_device(&mut st, device.bdf())
            .and_then(|()| self.invalidate_pages(&mut st, domain.0))
            .and_then(|()| self.sync(&mut st));
        if result.is_err() {
            self.block(&st, off);
            let _ = self.invalidate_device(&mut st, device.bdf()).and_then(|()| self.sync(&mut st));
        }
        result
    }

    fn detach(&self, device: DeviceId) -> Result<(), IommuError> {
        let off = self.check(device)?;
        let mut st = self.state.lock();
        let devtab = &Self::buffers(&st).devtab;
        if devtab.load::<u64>(off) & DTE_MODE_MASK == 0 {
            return Err(IommuError::NotAttached);
        }
        let domain = devtab.load::<u64>(off + 8) as u16;
        self.block(&st, off);
        self.invalidate_device(&mut st, device.bdf())?;
        self.invalidate_pages(&mut st, domain)?;
        self.sync(&mut st)
    }

    fn invalidate(&self, domain: DomainId) -> Result<(), IommuError> {
        let mut st = self.state.lock();
        self.invalidate_pages(&mut st, domain.0)?;
        self.sync(&mut st)
    }

    fn take_fault(&self) -> Option<Fault> {
        let st = self.state.lock();
        let head = self.regs.r64(EVT_HEAD) as usize;
        let tail = self.regs.r64(EVT_TAIL) as usize;
        if head == tail {
            // Logging stopped on overflow; the log is empty now, so resume it.
            if self.regs.r64(STATUS) & EVENT_OVERFLOW != 0 {
                self.regs.w64(STATUS, EVENT_OVERFLOW);
            }
            return None;
        }
        barrier::dma_rmb();
        let events = &Self::buffers(&st).events;
        let (q0, q1) = (events.load::<u64>(head), events.load::<u64>(head + 8));
        self.regs.w64(EVT_HEAD, ((head + ENTRY) % QUEUE_BYTES) as u64);
        let requester = q0 as u16;
        Some(Fault {
            device: DeviceId::new(
                self.segment,
                Address::new((requester >> 8) as u8, (requester >> 3) as u8 & 31, requester as u8 & 7),
            ),
            iova: q1,
            // Flags are bits 59:48; RW (bit 5 of them) means write.
            write: (q0 >> 48) & 0x20 != 0,
            reason: (q0 >> 60) as u32,
        })
    }
}

impl<D: DmaAllocator + Sync + ?Sized> Drop for AmdVi<'_, D> {
    fn drop(&mut self) {
        let mut st = self.state.lock();
        let buffers = ManuallyDrop::new(st.buffers.take());
        self.regs.w64(CONTROL, 0);
        let stopped = self.wait(|| self.regs.r64(STATUS) & (CMD_BUF_RUN | EVENT_LOG_RUN) == 0).is_ok();
        // A unit that will not stop may still read its tables: leak them.
        if stopped {
            drop(ManuallyDrop::into_inner(buffers));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::vec::Vec;

    use osmium_hal::iommu::{IoDomain, IommuDma};
    use osmium_mm::paging::MapFlags;

    use super::super::testing::*;
    use super::*;

    const NIC: Address = Address::new(0, 3, 1);
    const FAR: Address = Address::new(4, 0x1f, 7);

    fn dev(a: Address) -> DeviceId {
        DeviceId::new(0, a)
    }

    #[derive(Default)]
    struct Hw {
        log: Vec<std::string::String>,
        /// Ignores the command buffer.
        stall: bool,
    }

    struct Fake {
        regs: HostRegs,
        hw: Arc<Mutex<Hw>>,
        _pump: Pump,
    }

    fn fake() -> Fake {
        let regs = HostRegs::new(0x4000);
        let hw = Arc::new(Mutex::new(Hw::default()));
        let (r, h) = (regs.clone(), hw.clone());
        let pump = Pump::start(move || {
            let mut hw = h.lock().unwrap();
            let c = r.r64(CONTROL);
            let mut status = r.r64(STATUS) & !(CMD_BUF_RUN | EVENT_LOG_RUN);
            // Like QEMU's model, the queues run only while the unit is on.
            if c & IOMMU_EN != 0 && c & CMD_BUF_EN != 0 {
                status |= CMD_BUF_RUN;
            }
            if c & IOMMU_EN != 0 && c & EVENT_LOG_EN != 0 {
                status |= EVENT_LOG_RUN;
            }
            // Overflow is write-one-to-clear: the driver writes just that bit.
            if r.r64(STATUS) == EVENT_OVERFLOW && status & EVENT_OVERFLOW != 0 && c & IOMMU_EN != 0 {
                status = 0;
            }
            r.w64(STATUS, status);
            if status & CMD_BUF_RUN == 0 || hw.stall {
                return;
            }
            let base = r.r64(CMD_BUF_BAR);
            assert_eq!(base >> 56, 8, "256-entry command buffer");
            let base = base & ADDR_MASK;
            let (mut head, tail) = (r.r64(CMD_HEAD), r.r64(CMD_TAIL));
            while head != tail {
                let (q0, q1) = (mem64(base + head), mem64(base + head + 8));
                match q0 >> 60 {
                    OP_COMPLETION_WAIT => {
                        assert_eq!(q0 & 1, 1, "store requested");
                        set_mem64(q0 & 0x000f_ffff_ffff_fff8, q1);
                        hw.log.push("wait".into());
                    }
                    OP_INVALIDATE_DEVTAB_ENTRY => hw.log.push(std::format!("devtab {:#x}", q0 & 0xffff)),
                    OP_INVALIDATE_PAGES => {
                        assert_eq!(q1 & !0xfff, 0x7fff_ffff_ffff_f000, "flush-all address");
                        hw.log.push(std::format!("pages {}", (q0 >> 32) & 0xffff));
                    }
                    op => panic!("unexpected command {op:#x}"),
                }
                head = (head + 16) % 4096;
                r.w64(CMD_HEAD, head);
            }
        });
        Fake { regs, hw, _pump: pump }
    }

    impl Fake {
        fn log(&self) -> Vec<std::string::String> {
            self.hw.lock().unwrap().log.clone()
        }

        fn translating(&self) -> bool {
            self.regs.r64(CONTROL) & IOMMU_EN != 0
        }

        /// Looks `iova` up for `sid` as the unit would.
        fn translate(&self, sid: u16, iova: u64, write: bool) -> Result<u64, &'static str> {
            if !self.translating() {
                return Ok(iova);
            }
            let tab = self.regs.r64(DEV_TAB_BAR) & ADDR_MASK;
            let dte = tab + sid as u64 * 32;
            let q0 = mem64(dte);
            if q0 & DTE_V == 0 {
                // An invalid entry passes DMA through untranslated.
                return Ok(iova);
            }
            assert_ne!(q0 & DTE_TV, 0);
            let mode = (q0 >> 9) & 7;
            if mode == 0 {
                assert_eq!(q0 & (DTE_IR | DTE_IW), 0, "a blocked entry grants nothing");
                return Err("device blocked");
            }
            assert_eq!(mode, 4);
            assert_eq!(mem64(dte + 16) >> 60 & 3, 1, "interrupts forwarded");
            let (ir, iw) = (q0 & DTE_IR != 0, q0 & DTE_IW != 0);
            let mut table = q0 & ADDR_MASK;
            let mut level = mode;
            loop {
                let e = mem64(table + ((iova >> (12 + 9 * (level - 1))) & 0x1ff) * 8);
                if e & 1 == 0 {
                    return Err("not present");
                }
                let (ok_r, ok_w) = (ir && e & 1 << 61 != 0, iw && e & 1 << 62 != 0);
                if write && !ok_w || !write && !ok_r {
                    return Err("permission");
                }
                let next = (e >> 9) & 7;
                if level == 1 {
                    assert_eq!(next, 0, "last-level entry ends the walk");
                    return Ok((e & ADDR_MASK) | (iova & 0xfff));
                }
                assert_eq!(next, level - 1, "NextLevel names the table below");
                table = e & ADDR_MASK;
                level -= 1;
            }
        }

        fn domain_of(&self, sid: u16) -> u64 {
            mem64((self.regs.r64(DEV_TAB_BAR) & ADDR_MASK) + sid as u64 * 32 + 8) & 0xffff
        }

        fn push_event(&self, sid: u16, kind: u64, flags: u64, addr: u64) {
            let base = self.regs.r64(EVT_LOG_BAR) & ADDR_MASK;
            let tail = self.regs.r64(EVT_TAIL);
            set_mem64(base + tail, sid as u64 | flags << 48 | kind << 60);
            set_mem64(base + tail + 8, addr);
            self.regs.w64(EVT_TAIL, (tail + 16) % 4096);
        }
    }

    fn setup<'dev>(dma: &'dev HostDma, clock: &'dev StdClock, f: &Fake) -> AmdVi<'dev, HostDma> {
        AmdVi::new(f.regs.io(), dma, clock, 0, 7).expect("unit comes up")
    }

    #[test]
    fn programs_tables_and_stays_off() {
        let (f, dma, clock) = (fake(), HostDma::default(), StdClock::default());
        let unit = setup(&dma, &clock, &f);
        assert!(!unit.translating());
        let c = f.regs.r64(CONTROL);
        assert_eq!(c & (CMD_BUF_EN | EVENT_LOG_EN | IOMMU_EN), CMD_BUF_EN | EVENT_LOG_EN | IOMMU_EN);
        assert_eq!(f.translate(dev(NIC).bdf(), 0x1234, false), Ok(0x1234), "DMA passes until the first attach");
        // 8 buses x 256 functions x 32 bytes = 64 KiB = 16 pages.
        assert_eq!(f.regs.r64(DEV_TAB_BAR) & 0xfff, 15);
        assert_eq!(f.regs.r64(EVT_LOG_BAR) >> 56, 8);
        assert_eq!(dma.live(), 4);
        drop(unit);
        assert_eq!(dma.live(), 0);
        assert_eq!(f.regs.r64(CONTROL), 0);
    }

    #[test]
    fn refuses_bad_registers() {
        let (dma, clock) = (HostDma::default(), StdClock::default());
        let small = HostRegs::new(0x1000);
        assert_eq!(AmdVi::new(small.io(), &dma, &clock, 0, 0).err(), Some(IommuError::BadRegisters));
        assert_eq!(dma.live(), 0);
    }

    #[test]
    fn attach_translates_and_detach_blocks() {
        let (f, dma, clock, tables) = (fake(), HostDma::default(), StdClock::default(), HostTables::default());
        let unit = setup(&dma, &clock, &f);
        let backing = HostDma::default();
        let buf = backing.alloc_coherent(8192).unwrap();
        let base = buf.device_addr().as_u64();
        let mut d = IoDomain::new(&unit, DomainId(9), &tables).unwrap();
        d.map(0x20_0000, buf.device_addr(), 0x2000, MapFlags::RW).unwrap();
        d.map(0x40_0000, buf.device_addr(), 0x1000, MapFlags::READ).unwrap();
        d.attach(dev(NIC)).unwrap();
        assert!(unit.translating(), "first attach blocks everything else");
        let sid = dev(NIC).bdf();
        assert_eq!(f.domain_of(sid), 9);
        assert_eq!(f.translate(sid, 0x20_0123, true), Ok(base + 0x123));
        assert_eq!(f.translate(sid, 0x20_1fff, false), Ok(base + 0x1fff));
        assert_eq!(f.translate(sid, 0x40_0000, true), Err("permission"));
        assert_eq!(f.translate(sid, 0x30_0000, false), Err("not present"));
        assert_eq!(f.translate(dev(Address::new(0, 3, 2)).bdf(), 0x20_0000, false), Err("device blocked"));
        assert_eq!(f.translate(dev(FAR).bdf(), 0x20_0000, false), Err("device blocked"), "other buses too");
        assert_eq!(f.translate(0x0800, 0x20_0000, false), Ok(0x20_0000), "beyond max_bus the table does not reach");

        d.map(0x50_0000, buf.device_addr() + 0x1000, 0x1000, MapFlags::RW).unwrap();
        assert_eq!(f.translate(sid, 0x50_0008, true), Ok(base + 0x1008));
        d.unmap(0x50_0000, 0x1000).unwrap();
        assert_eq!(f.translate(sid, 0x50_0008, true), Err("not present"));
        let log = f.log();
        assert!(log.contains(&"devtab 0x19".into()) && log.contains(&"pages 9".into()), "{log:?}");
        assert_eq!(log.last().unwrap(), "wait", "every operation ends with a completion wait");

        assert_eq!(d.attach(dev(NIC)), Err(IommuError::Busy));
        d.detach(dev(NIC)).unwrap();
        assert_eq!(f.translate(sid, 0x20_0000, false), Err("device blocked"));
        assert_eq!(d.detach(dev(NIC)), Err(IommuError::NotAttached));
        drop(d);
        // SAFETY: nothing maps it any more.
        unsafe { backing.free_coherent(buf) };
    }

    #[test]
    fn domains_are_separate() {
        let (f, dma, clock) = (fake(), HostDma::default(), StdClock::default());
        let (t1, t2) = (HostTables::default(), HostTables::default());
        let unit = setup(&dma, &clock, &f);
        let mut a = IoDomain::new(&unit, DomainId(1), &t1).unwrap();
        let mut b = IoDomain::new(&unit, DomainId(0), &t2).unwrap();
        a.map(0x1000, PhysAddr::new(0xaaa000), 0x1000, MapFlags::RW).unwrap();
        b.map(0x1000, PhysAddr::new(0xbbb000), 0x1000, MapFlags::RW).unwrap();
        a.attach(dev(NIC)).unwrap();
        b.attach(dev(FAR)).unwrap();
        assert_eq!(f.translate(dev(NIC).bdf(), 0x1000, false), Ok(0xaaa000));
        assert_eq!(f.translate(dev(FAR).bdf(), 0x1000, false), Ok(0xbbb000));
        // Deep mappings exercise every level's NextLevel.
        a.map(0x7f_8000_0000_0000 >> 8, PhysAddr::new(0xccc000), 0x1000, MapFlags::RW).unwrap();
        assert_eq!(f.translate(dev(NIC).bdf(), 0x7f_8000_0000_0000 >> 8, true), Ok(0xccc000));
    }

    #[test]
    fn rejects_bad_requests() {
        let (f, dma, clock, tables) = (fake(), HostDma::default(), StdClock::default(), HostTables::default());
        let unit = setup(&dma, &clock, &f);
        let mut d = IoDomain::new(&unit, DomainId(1), &tables).unwrap();
        assert_eq!(d.attach(DeviceId::new(1, NIC)), Err(IommuError::InvalidDevice));
        assert_eq!(d.attach(dev(Address::new(8, 0, 0))), Err(IommuError::InvalidDevice), "beyond max_bus");
        assert!(!unit.translating());
    }

    #[test]
    fn timeout_rolls_back_attach() {
        let (f, dma, clock, tables) = (fake(), HostDma::default(), StdClock::default(), HostTables::default());
        let mut unit = setup(&dma, &clock, &f);
        unit.set_timeout_ns(5_000_000);
        f.hw.lock().unwrap().stall = true;
        {
            let mut d = IoDomain::new(&unit, DomainId(1), &tables).unwrap();
            assert_eq!(d.attach(dev(NIC)), Err(IommuError::Timeout));
        }
        assert!(!unit.translating(), "the first attach never finished");
        let tab = f.regs.r64(DEV_TAB_BAR) & ADDR_MASK;
        assert_eq!(mem64(tab + dev(NIC).bdf() as u64 * 32) & DTE_MODE_MASK, 0, "no page table left in the entry");
    }

    #[test]
    fn events_become_faults() {
        let (f, dma, clock) = (fake(), HostDma::default(), StdClock::default());
        let unit = setup(&dma, &clock, &f);
        assert_eq!(unit.take_fault(), None);
        f.push_event(dev(NIC).bdf(), 2, 0x20, 0x1234_5678);
        f.push_event(dev(FAR).bdf(), 2, 0, 0x9000);
        let a = unit.take_fault().unwrap();
        assert_eq!((a.device, a.iova, a.write, a.reason), (dev(NIC), 0x1234_5678, true, 2));
        let b = unit.take_fault().unwrap();
        assert_eq!((b.device, b.iova, b.write), (dev(FAR), 0x9000, false));
        assert_eq!(unit.take_fault(), None);
        // The ring wraps.
        for i in 0..300u64 {
            f.push_event(dev(NIC).bdf(), 2, 0, i << 12);
            assert_eq!(unit.take_fault().unwrap().iova, i << 12);
        }
        assert_eq!(f.regs.r64(EVT_HEAD), f.regs.r64(EVT_TAIL));
    }

    #[test]
    fn overflow_is_acknowledged_once_drained() {
        let (f, dma, clock) = (fake(), HostDma::default(), StdClock::default());
        let unit = setup(&dma, &clock, &f);
        f.regs.w64(STATUS, f.regs.r64(STATUS) | EVENT_OVERFLOW);
        assert_eq!(unit.take_fault(), None);
        std::thread::sleep(core::time::Duration::from_millis(5));
        assert_eq!(f.regs.r64(STATUS) & EVENT_OVERFLOW, 0);
    }

    #[test]
    fn iommu_dma_end_to_end() {
        let (f, dma, clock, tables) = (fake(), HostDma::default(), StdClock::default(), HostTables::default());
        let backing = HostDma::default();
        let unit = setup(&dma, &clock, &f);
        let alloc = {
            let domain = IoDomain::new(&unit, DomainId(3), &tables).unwrap();
            IommuDma::new(domain, &backing, 0x10_0000..0xfee0_0000).unwrap()
        };
        alloc.with_domain(|d| d.attach(dev(NIC))).unwrap();
        let ring = alloc.alloc_coherent(4096).unwrap();
        ring.store::<u32>(8, 0xc0ffee);
        let iova = ring.device_addr().as_u64();
        let pa = f.translate(dev(NIC).bdf(), iova + 8, true).unwrap();
        assert_eq!(mem32(pa), 0xc0ffee);
        // SAFETY: the "device" is the fake and is idle.
        unsafe { alloc.free_coherent(ring) };
        assert_eq!(f.translate(dev(NIC).bdf(), iova, false), Err("not present"));
        assert_eq!(backing.live(), 0);
        alloc.with_domain(|d| d.detach(dev(NIC))).unwrap();
    }
}
