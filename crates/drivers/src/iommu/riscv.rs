//! The RISC-V IOMMU.
//!
//! [`RiscvIommu`] drives one unit (the `riscv-iommu` PCI function QEMU
//! provides, or a platform device) with first-stage translation only: the
//! device directory table (two levels, indexed by the PCI requester ID) holds
//! one device context per function, whose `fsc` points at a table in
//! [`Sv39Io`] format. IOVAs are 39 bits sign-extended, so a domain uses the
//! lower 256 GiB. The domain number is the context's `PSCID`. Both the base
//! (32-byte) and the extended (64-byte, `capabilities.MSI_FLAT`) context
//! formats are handled; the MSI page table fields stay zero, so a device's MSI
//! writes are translated like any other DMA and need their target page mapped
//! in its domain. Software talks to the unit through a command queue (device
//! directory and address-translation invalidations, then an `IOFENCE.C` that
//! stores a sequence number) and reads faults from the fault queue.
//!
//! Until the first device attaches the unit is in `Bare` mode (pass-through);
//! after that, unattached devices fault. Dropping the driver returns the unit
//! to `Bare`. Second-stage translation, process contexts, the page-request
//! queue, ATS, hardware performance monitors and the interrupt lines are not
//! used.

use core::mem::ManuallyDrop;

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::iommu::{DeviceId, DomainId, Fault, Iommu, IommuError};
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::Address;
use osmium_hal::timer::Clock;
use osmium_mm::PhysAddr;
use osmium_mm::paging::formats::Sv39Io;
use osmium_sync::IrqSpinLock;

use super::{DEFAULT_TIMEOUT_NS, Pages, Regs, wait_until};

// Registers.
const CAPS: usize = 0x00;
const FCTL: usize = 0x08;
const DDTP: usize = 0x10;
const CQB: usize = 0x18;
const CQH: usize = 0x20;
const CQT: usize = 0x24;
const FQB: usize = 0x28;
const FQH: usize = 0x30;
const FQT: usize = 0x34;
const CQCSR: usize = 0x48;
const FQCSR: usize = 0x4c;
const REGS_LEN: usize = 0x58;

// capabilities.
const CAPS_VERSION_MASK: u64 = 0xff;
const CAPS_VERSION_1_0: u64 = 0x10;
const CAPS_SV39: u64 = 1 << 9;
const CAPS_MSI_FLAT: u64 = 1 << 22;

const FCTL_BE: u32 = 1 << 0;

// ddtp.
const DDTP_MODE_MASK: u64 = 0xf;
const DDTP_BARE: u64 = 1;
const DDTP_2LVL: u64 = 3;
const DDTP_BUSY: u64 = 1 << 4;
const PPN_SHIFT: u32 = 10;

// Queue control and status registers (cqcsr, fqcsr).
const QCSR_EN: u32 = 1 << 0;
const QCSR_MF: u32 = 1 << 8;
const CQCSR_TO: u32 = 1 << 9;
const CQCSR_ILL: u32 = 1 << 10;
const FQCSR_OF: u32 = 1 << 9;
const QCSR_ON: u32 = 1 << 16;
const QCSR_BUSY: u32 = 1 << 17;
const CQ_ERRORS: u32 = QCSR_MF | CQCSR_TO | CQCSR_ILL;
const FQ_ERRORS: u32 = QCSR_MF | FQCSR_OF;

/// Command queue: 256 entries of 16 bytes. Fault queue: 128 of 32.
const CQ_LOG2: u32 = 8;
const FQ_LOG2: u32 = 7;
const CMD_BYTES: usize = 16;
const FAULT_BYTES: usize = 32;

// Commands.
const OP_IOTINVAL: u64 = 1;
const OP_IOFENCE: u64 = 2;
const OP_IODIR: u64 = 3;
/// `IOTINVAL.VMA` (function 0) for one `PSCID`.
const IOTINVAL_PSCV: u64 = 1 << 32;
const IOFENCE_PR: u64 = 1 << 10;
const IOFENCE_PW: u64 = 1 << 11;
const IOFENCE_AV: u64 = 1 << 12;
const IODIR_DV: u64 = 1 << 33;

// Device context: translation control and first-stage pointer.
const TC_V: u64 = 1;
const FSC_SV39: u64 = 8 << 60;

/// Leaf-table indices below the root: 128 base contexts or 64 extended.
const ROOT_ENTRIES: usize = 512;
const DDT_V: u64 = 1;

struct Tables<'d, D: DmaAllocator + ?Sized> {
    root: OwnedDma<'d, D>,
    leaves: Pages<'d, D>,
    commands: OwnedDma<'d, D>,
    faults: OwnedDma<'d, D>,
    /// Target of `IOFENCE.C` stores.
    fence: OwnedDma<'d, D>,
}

struct State<'d, D: DmaAllocator + ?Sized> {
    tables: Option<Tables<'d, D>>,
    cq_tail: u32,
    fence_seq: u32,
    enabled: bool,
}

/// A RISC-V IOMMU.
pub struct RiscvIommu<'d, D: DmaAllocator + Sync + ?Sized> {
    regs: Regs,
    clock: &'d dyn Clock,
    segment: u16,
    /// Bytes per device context: 32 (base) or 64 (extended).
    dc_bytes: usize,
    timeout_ns: u64,
    state: IrqSpinLock<State<'d, D>>,
}

fn ppn(pa: PhysAddr) -> u64 {
    pa.as_u64() >> 12
}

impl<'d, D: DmaAllocator + Sync + ?Sized> RiscvIommu<'d, D> {
    /// Takes over the unit whose registers are `io`, serving PCI segment
    /// `segment`. The unit goes to pass-through (`Bare`) until the first
    /// attach.
    pub fn new(io: IoMem, dma: &'d D, clock: &'d dyn Clock, segment: u16) -> Result<Self, IommuError> {
        let regs = Regs::new(io, REGS_LEN)?;
        let caps = regs.r64(CAPS);
        if caps == !0 || caps & CAPS_VERSION_MASK < CAPS_VERSION_1_0 {
            return Err(IommuError::BadRegisters);
        }
        if caps & CAPS_SV39 == 0 {
            return Err(IommuError::Unsupported);
        }
        let tables = Tables {
            root: OwnedDma::new(dma, 4096).ok_or(IommuError::OutOfMemory)?,
            leaves: Pages::new(dma, ROOT_ENTRIES)?,
            commands: OwnedDma::new(dma, CMD_BYTES << CQ_LOG2).ok_or(IommuError::OutOfMemory)?,
            faults: OwnedDma::new(dma, FAULT_BYTES << FQ_LOG2).ok_or(IommuError::OutOfMemory)?,
            fence: OwnedDma::new(dma, 4096).ok_or(IommuError::OutOfMemory)?,
        };
        let unit = Self {
            regs,
            clock,
            segment,
            dc_bytes: if caps & CAPS_MSI_FLAT != 0 { 64 } else { 32 },
            timeout_ns: DEFAULT_TIMEOUT_NS,
            state: IrqSpinLock::new(State { tables: None, cq_tail: 0, fence_seq: 0, enabled: false }),
        };
        // Quiesce, then configure: queues and the directory only change while off.
        unit.set_ddtp(0)?;
        unit.set_queue(CQCSR, 0)?;
        unit.set_queue(FQCSR, 0)?;
        if unit.regs.r32(FCTL) & FCTL_BE != 0 {
            unit.regs.w32(FCTL, unit.regs.r32(FCTL) & !FCTL_BE);
            if unit.regs.r32(FCTL) & FCTL_BE != 0 {
                return Err(IommuError::Unsupported);
            }
        }
        unit.regs.w64(CQB, ppn(tables.commands.device_addr()) << PPN_SHIFT | (CQ_LOG2 - 1) as u64);
        unit.regs.w64(FQB, ppn(tables.faults.device_addr()) << PPN_SHIFT | (FQ_LOG2 - 1) as u64);
        unit.state.lock().tables = Some(tables);
        unit.set_queue(CQCSR, QCSR_EN)?;
        unit.set_queue(FQCSR, QCSR_EN)?;
        {
            let mut st = unit.state.lock();
            st.cq_tail = unit.regs.r32(CQT);
        }
        unit.set_ddtp(DDTP_BARE)?;
        Ok(unit)
    }

    /// Sets how long to wait for the hardware, in nanoseconds.
    pub fn set_timeout_ns(&mut self, timeout_ns: u64) {
        self.timeout_ns = timeout_ns;
    }

    /// Whether translation is switched on (after the first attach).
    pub fn translating(&self) -> bool {
        self.regs.r64(DDTP) & DDTP_MODE_MASK == DDTP_2LVL
    }

    fn wait(&self, done: impl FnMut() -> bool) -> Result<(), IommuError> {
        wait_until(self.clock, self.timeout_ns, done)
    }

    /// Writes `ddtp` (mode, plus the root's PPN for table modes) and checks
    /// that the unit took the mode.
    fn set_ddtp_with_root(&self, mode: u64, root: PhysAddr) -> Result<(), IommuError> {
        self.wait(|| self.regs.r64(DDTP) & DDTP_BUSY == 0)?;
        self.regs.w64(DDTP, ppn(root) << PPN_SHIFT | mode);
        self.wait(|| self.regs.r64(DDTP) & DDTP_BUSY == 0)?;
        if self.regs.r64(DDTP) & DDTP_MODE_MASK != mode {
            return Err(IommuError::Unsupported);
        }
        Ok(())
    }

    fn set_ddtp(&self, mode: u64) -> Result<(), IommuError> {
        self.set_ddtp_with_root(mode, PhysAddr::ZERO)
    }

    /// Enables (`QCSR_EN`) or disables (0) a queue and waits for the unit.
    /// Disabling also clears stale error bits.
    fn set_queue(&self, csr: usize, value: u32) -> Result<(), IommuError> {
        let errors = if csr == CQCSR { CQ_ERRORS } else { FQ_ERRORS };
        self.regs.w32(csr, value | if value == 0 { errors } else { 0 });
        let on = value & QCSR_EN != 0;
        self.wait(|| {
            let v = self.regs.r32(csr);
            v & QCSR_BUSY == 0 && (v & QCSR_ON != 0) == on
        })
    }

    fn tables<'st>(st: &'st State<'d, D>) -> &'st Tables<'d, D> {
        st.tables.as_ref().expect("tables exist after new")
    }

    fn post(&self, st: &mut State<'d, D>, q0: u64, q1: u64) -> Result<(), IommuError> {
        let mask = (1u32 << CQ_LOG2) - 1;
        let next = (st.cq_tail + 1) & mask;
        if next == self.regs.r32(CQH) & mask {
            return Err(IommuError::Busy);
        }
        let at = st.cq_tail as usize * CMD_BYTES;
        let cmds = &Self::tables(st).commands;
        cmds.store::<u64>(at, q0);
        cmds.store::<u64>(at + 8, q1);
        barrier::dma_wmb();
        st.cq_tail = next;
        self.regs.w32(CQT, next);
        Ok(())
    }

    /// Posts an `IOFENCE.C` and waits until the unit stores its sequence
    /// number, which it does once every earlier command has finished.
    fn fence(&self, st: &mut State<'d, D>) -> Result<(), IommuError> {
        st.fence_seq = st.fence_seq.wrapping_add(1);
        let seq = st.fence_seq;
        let at = Self::tables(st).fence.device_addr().as_u64();
        self.post(st, OP_IOFENCE | IOFENCE_PR | IOFENCE_PW | IOFENCE_AV | (seq as u64) << 32, at >> 2)?;
        let word = &Self::tables(st).fence;
        let waited = self.wait(|| word.load::<u32>(0) == seq || self.regs.r32(CQCSR) & CQ_ERRORS != 0);
        if self.regs.r32(CQCSR) & CQ_ERRORS != 0 {
            // The queue stopped on a bad or slow command. Restart it empty.
            self.set_queue(CQCSR, 0)?;
            self.set_queue(CQCSR, QCSR_EN)?;
            st.cq_tail = self.regs.r32(CQT);
            return Err(IommuError::Hardware);
        }
        waited?;
        barrier::dma_rmb();
        Ok(())
    }

    fn flush_device(&self, st: &mut State<'d, D>, requester: u16, domain: u16) -> Result<(), IommuError> {
        self.post(st, OP_IODIR | IODIR_DV | (requester as u64) << 40, 0)?;
        self.post(st, OP_IOTINVAL | IOTINVAL_PSCV | (domain as u64) << 12, 0)?;
        self.fence(st)
    }

    /// Byte offset of `requester`'s context within its leaf table, and the
    /// root index of that table.
    fn locate(&self, device: DeviceId) -> Result<(usize, usize), IommuError> {
        if device.segment() != self.segment {
            return Err(IommuError::InvalidDevice);
        }
        let per_leaf = 4096 / self.dc_bytes;
        let id = device.bdf() as usize;
        let (index, slot) = (id / per_leaf, id % per_leaf);
        if index >= ROOT_ENTRIES {
            return Err(IommuError::InvalidDevice);
        }
        Ok((index, slot * self.dc_bytes))
    }
}

impl<D: DmaAllocator + Sync + ?Sized> Iommu for RiscvIommu<'_, D> {
    type Format = Sv39Io;

    fn iova_limit(&self) -> u64 {
        // Sv39 sign-extends bit 38; stay in the lower half.
        1 << 38
    }

    unsafe fn attach(&self, device: DeviceId, domain: DomainId, root: PhysAddr) -> Result<(), IommuError> {
        let (index, off) = self.locate(device)?;
        if !root.is_aligned(4096) || ppn(root) >> 44 != 0 {
            return Err(IommuError::OutOfRange);
        }
        let mut st = self.state.lock();
        let tables = st.tables.as_mut().ok_or(IommuError::Unsupported)?;
        let (leaf, created) = tables.leaves.get_or_alloc(index)?;
        if created {
            barrier::dma_wmb();
            tables.root.store::<u64>(index * 8, ppn(leaf.device_addr()) << PPN_SHIFT | DDT_V);
        }
        if leaf.load::<u64>(off) & TC_V != 0 {
            return Err(IommuError::Busy);
        }
        // First stage only: no second stage (iohgatp Bare), no process table,
        // no MSI table (msiptp Off). The domain is the PSCID.
        for q in 1..self.dc_bytes / 8 {
            leaf.store::<u64>(off + q * 8, 0);
        }
        leaf.store::<u64>(off + 16, (domain.0 as u64) << 12);
        leaf.store::<u64>(off + 24, FSC_SV39 | ppn(root));
        barrier::dma_wmb();
        leaf.store::<u64>(off, TC_V);
        barrier::dma_wmb();
        let result = self.flush_device(&mut st, device.bdf(), domain.0).and_then(|()| {
            if st.enabled {
                return Ok(());
            }
            let root_ddt = Self::tables(&st).root.device_addr();
            self.set_ddtp_with_root(DDTP_2LVL, root_ddt)?;
            st.enabled = true;
            Ok(())
        });
        if result.is_err() {
            let leaf = Self::tables(&st).leaves.get(index).expect("made above");
            leaf.store::<u64>(off, 0);
            barrier::dma_wmb();
            leaf.store::<u64>(off + 24, 0);
            let _ = self.flush_device(&mut st, device.bdf(), domain.0);
        }
        result
    }

    fn detach(&self, device: DeviceId) -> Result<(), IommuError> {
        let (index, off) = self.locate(device)?;
        let mut st = self.state.lock();
        let leaf = Self::tables(&st)
            .leaves
            .get(index)
            .filter(|l| l.load::<u64>(off) & TC_V != 0)
            .ok_or(IommuError::NotAttached)?;
        let domain = (leaf.load::<u64>(off + 16) >> 12) as u16;
        leaf.store::<u64>(off, 0);
        barrier::dma_wmb();
        for q in 1..self.dc_bytes / 8 {
            leaf.store::<u64>(off + q * 8, 0);
        }
        barrier::dma_wmb();
        self.flush_device(&mut st, device.bdf(), domain)
    }

    fn invalidate(&self, domain: DomainId) -> Result<(), IommuError> {
        let mut st = self.state.lock();
        self.post(&mut st, OP_IOTINVAL | IOTINVAL_PSCV | (domain.0 as u64) << 12, 0)?;
        self.fence(&mut st)
    }

    fn take_fault(&self) -> Option<Fault> {
        let st = self.state.lock();
        let mask = (1u32 << FQ_LOG2) - 1;
        let (head, tail) = (self.regs.r32(FQH) & mask, self.regs.r32(FQT) & mask);
        if head == tail {
            // Records were lost; the queue is drained, so acknowledge.
            if self.regs.r32(FQCSR) & FQ_ERRORS != 0 {
                self.regs.w32(FQCSR, QCSR_EN | FQ_ERRORS);
            }
            return None;
        }
        barrier::dma_rmb();
        let faults = &Self::tables(&st).faults;
        let at = head as usize * FAULT_BYTES;
        let (q0, iotval) = (faults.load::<u64>(at), faults.load::<u64>(at + 16));
        self.regs.w32(FQH, (head + 1) & mask);
        let requester = (q0 >> 40) as u16;
        // Transaction types 3 and 6 are untranslated and translated writes.
        let ttyp = (q0 >> 34) & 0x3f;
        Some(Fault {
            device: DeviceId::new(
                self.segment,
                Address::new((requester >> 8) as u8, (requester >> 3) as u8 & 31, requester as u8 & 7),
            ),
            iova: iotval,
            write: matches!(ttyp, 3 | 6),
            reason: (q0 & 0xfff) as u32,
        })
    }
}

impl<D: DmaAllocator + Sync + ?Sized> Drop for RiscvIommu<'_, D> {
    fn drop(&mut self) {
        let mut st = self.state.lock();
        let tables = ManuallyDrop::new(st.tables.take());
        // Back to pass-through, then stop the queues; if the unit will not
        // stop it may still read the tables, so leak them.
        let stopped =
            self.set_ddtp(DDTP_BARE).is_ok() && self.set_queue(CQCSR, 0).is_ok() && self.set_queue(FQCSR, 0).is_ok();
        if stopped {
            drop(ManuallyDrop::into_inner(tables));
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
    const FAR: Address = Address::new(0, 9, 0);

    fn dev(a: Address) -> DeviceId {
        DeviceId::new(0, a)
    }

    #[derive(Default)]
    struct Hw {
        log: Vec<std::string::String>,
        stall: bool,
        /// Fail the next command as illegal.
        ill_next: bool,
    }

    struct Fake {
        regs: HostRegs,
        hw: Arc<Mutex<Hw>>,
        ext: bool,
        _pump: Pump,
    }

    fn fake(ext: bool) -> Fake {
        let regs = HostRegs::new(0x1000);
        regs.w64(CAPS, 0x10 | CAPS_SV39 | if ext { CAPS_MSI_FLAT } else { 0 });
        let hw = Arc::new(Mutex::new(Hw::default()));
        let (r, h) = (regs.clone(), hw.clone());
        let pump = Pump::start(move || {
            let mut hw = h.lock().unwrap();
            // Queue enables follow their requests; disabling clears errors.
            let fq = r.r32(FQCSR);
            r.w32(FQCSR, if fq & QCSR_EN != 0 { fq | QCSR_ON } else { 0 });
            let cq = r.r32(CQCSR);
            if cq & QCSR_EN == 0 {
                r.w32(CQCSR, 0);
                return;
            }
            r.w32(CQCSR, cq | QCSR_ON);
            if cq & CQ_ERRORS != 0 || hw.stall {
                return;
            }
            let base = (r.r64(CQB) >> PPN_SHIFT) << 12;
            assert_eq!(r.r64(CQB) & 0x1f, 7, "256 entries");
            let mut head = r.r32(CQH);
            let tail = r.r32(CQT);
            while head != tail {
                let at = base + head as u64 * 16;
                let (q0, q1) = (mem64(at), mem64(at + 8));
                if hw.ill_next {
                    hw.ill_next = false;
                    r.w32(CQCSR, cq | CQCSR_ILL);
                    return;
                }
                match q0 & 0x7f {
                    OP_IODIR => {
                        assert_eq!(q0 >> 7 & 7, 0, "INVAL_DDT");
                        assert_ne!(q0 & IODIR_DV, 0);
                        hw.log.push(std::format!("inval_ddt {:#x}", q0 >> 40));
                    }
                    OP_IOTINVAL => {
                        assert_eq!(q0 >> 7 & 7, 0, "VMA");
                        assert_ne!(q0 & IOTINVAL_PSCV, 0);
                        assert_eq!(q0 & (1 << 33), 0, "no GSCID");
                        hw.log.push(std::format!("vma {}", (q0 >> 12) & 0xfffff));
                    }
                    OP_IOFENCE => {
                        assert_eq!(q0 & (IOFENCE_PR | IOFENCE_PW | IOFENCE_AV), IOFENCE_PR | IOFENCE_PW | IOFENCE_AV);
                        // SAFETY: the driver's fence word, in a live allocation.
                        unsafe { ((q1 << 2) as *mut u32).write_volatile((q0 >> 32) as u32) };
                        hw.log.push("fence".into());
                    }
                    op => panic!("unexpected command {op:#x}"),
                }
                head = (head + 1) & 0xff;
                r.w32(CQH, head);
            }
        });
        Fake { regs, hw, ext, _pump: pump }
    }

    impl Fake {
        fn log(&self) -> Vec<std::string::String> {
            self.hw.lock().unwrap().log.clone()
        }

        fn mode(&self) -> u64 {
            self.regs.r64(DDTP) & 0xf
        }

        fn dc(&self, id: u16) -> u64 {
            let (per_leaf, size) = if self.ext { (64, 64) } else { (128, 32) };
            let root = (self.regs.r64(DDTP) >> PPN_SHIFT) << 12;
            let nl = mem64(root + (id as u64 / per_leaf) * 8);
            assert_ne!(nl & 1, 0, "leaf table linked");
            ((nl >> PPN_SHIFT) << 12) + (id as u64 % per_leaf) * size
        }

        /// Translates as the unit would: first-stage Sv39 from the device context.
        fn translate(&self, id: u16, iova: u64, write: bool) -> Result<u64, &'static str> {
            match self.mode() {
                1 => return Ok(iova),
                3 => {}
                m => panic!("ddtp mode {m}"),
            }
            let root = (self.regs.r64(DDTP) >> PPN_SHIFT) << 12;
            let nl = mem64(root + (id as u64 / if self.ext { 64 } else { 128 }) * 8);
            if nl & 1 == 0 {
                return Err("ddt entry not valid");
            }
            let dc = self.dc(id);
            if mem64(dc) & TC_V == 0 {
                return Err("context not valid");
            }
            if self.ext {
                assert_eq!(mem64(dc + 32), 0, "no MSI page table");
            }
            assert_eq!(mem64(dc + 8), 0, "no second stage");
            let fsc = mem64(dc + 24);
            assert_eq!(fsc >> 60, 8, "Sv39");
            // Sign extension: bits 63:39 must repeat bit 38.
            if (iova as i64) << 25 >> 25 != iova as i64 {
                return Err("page fault");
            }
            let mut table = (fsc & 0xfff_ffff_ffff) << 12;
            for level in (0..3).rev() {
                let e = mem64(table + ((iova >> (12 + 9 * level)) & 0x1ff) * 8);
                if e & 1 == 0 {
                    return Err("page fault");
                }
                if e & 0xe == 0 {
                    // QEMU's model walks only through entries with U set.
                    assert_ne!(e & 0x10, 0, "table entries carry U");
                    table = ((e >> 10) & 0xfff_ffff_ffff) << 12;
                    continue;
                }
                assert_ne!(e & 0x10, 0, "DMA is a user access: leaves need U");
                assert_ne!(e & 0x40, 0, "A set");
                if write && (e & 4 == 0 || e & 0x80 == 0) || !write && e & 2 == 0 {
                    return Err("permission");
                }
                let size = 1u64 << (12 + 9 * level);
                return Ok((((e >> 10) & 0xfff_ffff_ffff) << 12 & !(size - 1)) | (iova & (size - 1)));
            }
            Err("page fault")
        }

        fn pscid_of(&self, id: u16) -> u64 {
            (mem64(self.dc(id) + 16) >> 12) & 0xfffff
        }

        fn push_fault(&self, id: u16, cause: u64, ttyp: u64, addr: u64) {
            let base = (self.regs.r64(FQB) >> PPN_SHIFT) << 12;
            let tail = self.regs.r32(FQT);
            let at = base + tail as u64 * 32;
            set_mem64(at, cause | ttyp << 34 | (id as u64) << 40);
            set_mem64(at + 16, addr);
            self.regs.w32(FQT, (tail + 1) & 0x7f);
        }
    }

    fn setup<'dev>(dma: &'dev HostDma, clock: &'dev StdClock, f: &Fake) -> RiscvIommu<'dev, HostDma> {
        RiscvIommu::new(f.regs.io(), dma, clock, 0).expect("unit comes up")
    }

    fn both(test: impl Fn(bool)) {
        test(false);
        test(true);
    }

    #[test]
    fn programs_queues_and_goes_bare() {
        both(|ext| {
            let (f, dma, clock) = (fake(ext), HostDma::default(), StdClock::default());
            let unit = setup(&dma, &clock, &f);
            assert_eq!(f.mode(), 1);
            assert!(!unit.translating());
            assert_eq!(f.regs.r32(CQCSR) & (QCSR_EN | QCSR_ON), QCSR_EN | QCSR_ON);
            assert_eq!(f.regs.r32(FQCSR) & (QCSR_EN | QCSR_ON), QCSR_EN | QCSR_ON);
            assert_eq!(f.regs.r64(FQB) & 0x1f, 6, "128 entries");
            assert_eq!(f.translate(0x19, 0x1234, false), Ok(0x1234));
            assert_eq!(dma.live(), 5, "directory root and leaf index, two queues, fence word");
            drop(unit);
            assert_eq!(dma.live(), 0);
            assert_eq!(f.regs.r32(CQCSR) & QCSR_ON, 0);
            assert_eq!(f.mode(), 1);
        });
    }

    #[test]
    fn refuses_unsuitable_hardware() {
        let (dma, clock) = (HostDma::default(), StdClock::default());
        let small = HostRegs::new(0x20);
        assert_eq!(RiscvIommu::new(small.io(), &dma, &clock, 0).err(), Some(IommuError::BadRegisters));
        let f = fake(false);
        f.regs.w64(CAPS, 0x0f | CAPS_SV39);
        assert_eq!(RiscvIommu::new(f.regs.io(), &dma, &clock, 0).err(), Some(IommuError::BadRegisters));
        f.regs.w64(CAPS, 0x10);
        assert_eq!(RiscvIommu::new(f.regs.io(), &dma, &clock, 0).err(), Some(IommuError::Unsupported));
        assert_eq!(dma.live(), 0);
    }

    #[test]
    fn attach_translates_and_detach_blocks() {
        both(|ext| {
            let (f, dma, clock, tables) = (fake(ext), HostDma::default(), StdClock::default(), HostTables::default());
            let unit = setup(&dma, &clock, &f);
            let backing = HostDma::default();
            let buf = backing.alloc_coherent(8192).unwrap();
            let base = buf.device_addr().as_u64();
            let mut d = IoDomain::new(&unit, DomainId(0x77), &tables).unwrap();
            d.map(0x20_0000, buf.device_addr(), 0x2000, MapFlags::RW).unwrap();
            d.map(0x40_0000, buf.device_addr(), 0x1000, MapFlags::READ).unwrap();
            d.map(0x1_8000_0000, buf.device_addr() + 0x1000, 0x1000, MapFlags::RW).unwrap();
            d.attach(dev(NIC)).unwrap();
            assert!(unit.translating() && f.mode() == 3, "first attach turns translation on");
            let id = dev(NIC).bdf();
            assert_eq!(f.pscid_of(id), 0x77);
            assert_eq!(f.translate(id, 0x20_0123, true), Ok(base + 0x123));
            assert_eq!(f.translate(id, 0x20_1fff, false), Ok(base + 0x1fff));
            assert_eq!(f.translate(id, 0x40_0000, true), Err("permission"));
            assert_eq!(f.translate(id, 0x1_8000_0008, true), Ok(base + 0x1008), "another root slot");
            assert_eq!(f.translate(id, 0x30_0000, false), Err("page fault"));
            assert_eq!(f.translate(id, 1 << 39, false), Err("page fault"), "not canonical");
            assert_eq!(f.translate(dev(Address::new(5, 0, 0)).bdf(), 0x20_0000, false), Err("ddt entry not valid"));
            assert_eq!(f.translate(dev(Address::new(0, 3, 2)).bdf(), 0x20_0000, false), Err("context not valid"));

            d.map(0x50_0000, buf.device_addr() + 0x1000, 0x1000, MapFlags::RW).unwrap();
            assert_eq!(f.translate(id, 0x50_0008, true), Ok(base + 0x1008));
            d.unmap(0x50_0000, 0x1000).unwrap();
            assert_eq!(f.translate(id, 0x50_0008, true), Err("page fault"));
            let log = f.log();
            assert!(log.contains(&std::format!("inval_ddt {id:#x}")) && log.contains(&"vma 119".into()), "{log:?}");
            assert_eq!(log.last().unwrap(), "fence");

            assert_eq!(d.attach(dev(NIC)), Err(IommuError::Busy));
            d.detach(dev(NIC)).unwrap();
            assert_eq!(f.translate(id, 0x20_0000, false), Err("context not valid"));
            assert_eq!(d.detach(dev(NIC)), Err(IommuError::NotAttached));
            drop(d);
            // SAFETY: nothing maps it any more.
            unsafe { backing.free_coherent(buf) };
        });
    }

    #[test]
    fn domains_are_separate() {
        both(|ext| {
            let (f, dma, clock) = (fake(ext), HostDma::default(), StdClock::default());
            let (t1, t2) = (HostTables::default(), HostTables::default());
            let unit = setup(&dma, &clock, &f);
            let mut a = IoDomain::new(&unit, DomainId(1), &t1).unwrap();
            let mut b = IoDomain::new(&unit, DomainId(2), &t2).unwrap();
            a.map(0x1000, PhysAddr::new(0xaaa000), 0x1000, MapFlags::RW).unwrap();
            b.map(0x1000, PhysAddr::new(0xbbb000), 0x1000, MapFlags::RW).unwrap();
            a.attach(dev(NIC)).unwrap();
            b.attach(dev(Address::new(5, 0, 0))).unwrap();
            assert_eq!(f.translate(dev(NIC).bdf(), 0x1000, false), Ok(0xaaa000));
            assert_eq!(f.translate(0x500, 0x1000, false), Ok(0xbbb000));
        });
    }

    #[test]
    fn rejects_bad_requests() {
        let (f, dma, clock, tables) = (fake(true), HostDma::default(), StdClock::default(), HostTables::default());
        let unit = setup(&dma, &clock, &f);
        let mut d = IoDomain::new(&unit, DomainId(1), &tables).unwrap();
        assert_eq!(d.attach(DeviceId::new(1, NIC)), Err(IommuError::InvalidDevice));
        // Extended contexts index 15 bits: bus 128 and up do not fit.
        assert_eq!(d.attach(dev(Address::new(128, 0, 0))), Err(IommuError::InvalidDevice));
        assert_eq!(f.mode(), 1);
    }

    #[test]
    fn command_timeout_and_illegal_command() {
        let (f, dma, clock, tables) = (fake(false), HostDma::default(), StdClock::default(), HostTables::default());
        let mut unit = setup(&dma, &clock, &f);
        unit.set_timeout_ns(5_000_000);
        {
            let mut d = IoDomain::new(&unit, DomainId(1), &tables).unwrap();
            f.hw.lock().unwrap().stall = true;
            assert_eq!(d.attach(dev(NIC)), Err(IommuError::Timeout));
            assert_eq!(f.mode(), 1);
            f.hw.lock().unwrap().stall = false;
            std::thread::sleep(core::time::Duration::from_millis(10));
            f.hw.lock().unwrap().ill_next = true;
            assert_eq!(d.attach(dev(NIC)), Err(IommuError::Hardware));
            // The queue was restarted and works again.
            d.attach(dev(NIC)).unwrap();
            assert_eq!(f.mode(), 3);
        }
    }

    #[test]
    fn command_queue_wraps() {
        let (f, dma, clock, tables) = (fake(false), HostDma::default(), StdClock::default(), HostTables::default());
        let unit = setup(&dma, &clock, &f);
        let mut d = IoDomain::new(&unit, DomainId(1), &tables).unwrap();
        for _ in 0..200 {
            d.attach(dev(NIC)).unwrap();
            d.detach(dev(NIC)).unwrap();
        }
    }

    #[test]
    fn fault_records_become_faults() {
        let (f, dma, clock) = (fake(false), HostDma::default(), StdClock::default());
        let unit = setup(&dma, &clock, &f);
        assert_eq!(unit.take_fault(), None);
        f.push_fault(dev(NIC).bdf(), 7, 3, 0x1234_5678);
        f.push_fault(dev(FAR).bdf(), 5, 2, 0x9000);
        let a = unit.take_fault().unwrap();
        assert_eq!((a.device, a.iova, a.write, a.reason), (dev(NIC), 0x1234_5678, true, 7));
        let b = unit.take_fault().unwrap();
        assert_eq!((b.device, b.iova, b.write, b.reason), (dev(FAR), 0x9000, false, 5));
        assert_eq!(unit.take_fault(), None);
        for i in 0..300u64 {
            f.push_fault(dev(NIC).bdf(), 5, 2, i << 12);
            assert_eq!(unit.take_fault().unwrap().iova, i << 12);
        }
    }

    #[test]
    fn iommu_dma_end_to_end() {
        let (f, dma, clock, tables) = (fake(true), HostDma::default(), StdClock::default(), HostTables::default());
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
        let pa = f.translate(dev(NIC).bdf(), iova + 8, true).unwrap();
        assert_eq!(mem32(pa), 0xc0ffee);
        // SAFETY: the "device" is the fake and is idle.
        unsafe { alloc.free_coherent(ring) };
        assert_eq!(f.translate(dev(NIC).bdf(), iova, false), Err("page fault"));
        assert_eq!(backing.live(), 0);
        alloc.with_domain(|d| d.detach(dev(NIC))).unwrap();
    }
}
