//! Arm SMMUv3.
//!
//! [`Smmuv3`] drives one System MMU in stage-2-only mode: a linear stream
//! table holds one 64-byte entry per stream ID, each pointing at a
//! [`Aarch64Stage2`] page table (4 KiB granule, 4 levels, starting at level
//! 0). The stream ID of a PCI function is its requester ID plus a fixed
//! offset ([`Smmuv3::set_stream_offset`], from the device tree's `iommu-map`
//! or the ACPI IORT; zero by default). Software talks to the unit through a
//! command queue (stream-table and TLB invalidations, followed by a
//! `CMD_SYNC` that it polls for) and reads faults from the event queue.
//!
//! The driver needs `IDR0.S2P`, `IDR0.COHACC`, AArch64 table format and 4 KiB
//! granules, and refuses units that preset their queues or tables. The
//! stream table must be aligned to its own size: allocators that hand out
//! power-of-two blocks (frame allocators) do. Stage 1, contexts with
//! substreams (PASIDs), ATS, PRI, MSI-signalled completion and the interrupt
//! lines are not used; unattached stream IDs abort.

use core::mem::ManuallyDrop;

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::iommu::{DeviceId, DomainId, Fault, Iommu, IommuError};
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::Address;
use osmium_hal::timer::Clock;
use osmium_mm::PhysAddr;
use osmium_mm::paging::formats::Aarch64Stage2;
use osmium_sync::IrqSpinLock;

use super::{DEFAULT_TIMEOUT_NS, Regs, wait_until};

// Registers (page 0, then the event queue's pointers in page 1).
const IDR0: usize = 0x00;
const IDR1: usize = 0x04;
const IDR5: usize = 0x14;
const CR0: usize = 0x20;
const CR0ACK: usize = 0x24;
const CR1: usize = 0x28;
const CR2: usize = 0x2c;
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
const IDR0_TTF_AARCH64: u32 = 1 << 3;
const IDR0_COHACC: u32 = 1 << 4;
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

// Commands (opcode in bits 7:0).
const CMD_CFGI_STE: u64 = 0x03;
const CMD_CFGI_ALL: u64 = 0x04;
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
const STE_CONFIG_S2: u64 = 6 << 1;
const S2AA64: u64 = 1 << 51;
const S2R: u64 = 1 << 58;
const ADDR_MASK_4: u64 = 0x000f_ffff_ffff_fff0;

/// Largest queue this driver sizes: one 4 KiB page.
const QUEUE_BYTES: usize = 4096;

struct Buffers<'d, D: DmaAllocator + ?Sized> {
    strtab: OwnedDma<'d, D>,
    commands: OwnedDma<'d, D>,
    events: OwnedDma<'d, D>,
}

struct State<'d, D: DmaAllocator + ?Sized> {
    buffers: Option<Buffers<'d, D>>,
    /// Command queue producer index with wrap bit.
    prod: u32,
    enabled: bool,
}

/// An Arm SMMUv3.
pub struct Smmuv3<'d, D: DmaAllocator + Sync + ?Sized> {
    regs: Regs,
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
    /// Translation stays off until the first device attaches.
    pub fn new(
        io: IoMem,
        dma: &'d D,
        clock: &'d dyn Clock,
        segment: u16,
        max_stream_id: u32,
    ) -> Result<Self, IommuError> {
        let regs = Regs::new(io, REGS_LEN)?;
        let (idr0, idr1, idr5) = (regs.r32(IDR0), regs.r32(IDR1), regs.r32(IDR5));
        if idr0 == !0 && idr1 == !0 {
            return Err(IommuError::BadRegisters);
        }
        if idr0 & IDR0_S2P == 0
            || idr0 & IDR0_COHACC == 0
            || idr0 & IDR0_TTF_AARCH64 == 0
            || idr5 & IDR5_GRAN4K == 0
            || idr1 & (IDR1_TABLES_PRESET | IDR1_QUEUES_PRESET) != 0
        {
            return Err(IommuError::Unsupported);
        }
        let sid_bits = idr1 & 0x3f;
        let stream_log2 = (u32::BITS - max_stream_id.max(1).leading_zeros()).max(1);
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
        let strtab_bytes = (1usize << stream_log2) * STE_BYTES;
        let strtab = OwnedDma::new(dma, strtab_bytes).ok_or(IommuError::OutOfMemory)?;
        if !strtab.device_addr().is_aligned(strtab_bytes.max(4096) as u64) {
            return Err(IommuError::Unsupported);
        }
        let buffers = Buffers {
            strtab,
            commands: OwnedDma::new(dma, QUEUE_BYTES).ok_or(IommuError::OutOfMemory)?,
            events: OwnedDma::new(dma, QUEUE_BYTES).ok_or(IommuError::OutOfMemory)?,
        };
        let unit = Self {
            regs,
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
            state: IrqSpinLock::new(State { buffers: None, prod: 0, enabled: false }),
        };
        // Reconfiguration needs the unit off.
        unit.set_cr0(0)?;
        unit.regs.w32(CR1, CR1_COHERENT);
        unit.regs.w32(CR2, CR2_RECINVSID);
        unit.regs.w64(STRTAB_BASE, buffers.strtab.device_addr().as_u64() & ADDR_MASK_4 & !0x3f | BASE_RA);
        unit.regs.w32(STRTAB_BASE_CFG, stream_log2);
        unit.regs
            .w64(CMDQ_BASE, buffers.commands.device_addr().as_u64() & ADDR_MASK_4 & !0x1f | BASE_RA | cmdq_log2 as u64);
        unit.regs.w32(CMDQ_PROD, 0);
        unit.regs.w32(CMDQ_CONS, 0);
        unit.regs
            .w64(EVENTQ_BASE, buffers.events.device_addr().as_u64() & ADDR_MASK_4 & !0x1f | BASE_RA | evtq_log2 as u64);
        unit.regs.w32(EVENTQ_PROD, 0);
        unit.regs.w32(EVENTQ_CONS, 0);
        unit.state.lock().buffers = Some(buffers);
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
        st.buffers.as_ref().expect("buffers exist after new")
    }

    fn stream_id(&self, device: DeviceId) -> Result<u32, IommuError> {
        let sid = device.bdf() as u32 + self.stream_offset;
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
        barrier::dma_wmb();
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
            // Acknowledge, and resynchronize our producer with the unit.
            self.regs.w32(GERRORN, self.regs.r32(GERROR));
            st.prod = self.regs.r32(CMDQ_CONS) & mask;
            self.regs.w32(CMDQ_PROD, st.prod);
            return Err(IommuError::Hardware);
        }
        done
    }

    fn flush_stream(&self, st: &mut State<'d, D>, sid: u32, vmid: u16) -> Result<(), IommuError> {
        self.post(st, CMD_CFGI_STE | (sid as u64) << 32, 1)?;
        self.post(st, CMD_TLBI_S12_VMALL | (vmid as u64) << 32, 0)?;
        self.sync(st)
    }
}

impl<D: DmaAllocator + Sync + ?Sized> Iommu for Smmuv3<'_, D> {
    type Format = Aarch64Stage2;

    fn iova_limit(&self) -> u64 {
        1 << self.ia_bits
    }

    unsafe fn attach(&self, device: DeviceId, domain: DomainId, root: PhysAddr) -> Result<(), IommuError> {
        let sid = self.stream_id(device)?;
        if domain.0 as u32 >= self.vmids {
            return Err(IommuError::Unsupported);
        }
        if !root.is_aligned(4096) || root.as_u64() & !ADDR_MASK_4 != 0 {
            return Err(IommuError::OutOfRange);
        }
        let mut st = self.state.lock();
        let at = sid as usize * STE_BYTES;
        let strtab = &Self::buffers(&st).strtab;
        if strtab.load::<u64>(at) & STE_V != 0 {
            return Err(IommuError::Busy);
        }
        // VTCR: T0SZ, SL0 = 2 (start at level 0), IR0/OR0 write-back,
        // SH0 inner shareable, 4 KiB granule, output size.
        let vtcr = (64 - self.ia_bits) as u64 | 2 << 6 | 1 << 8 | 1 << 10 | 3 << 12 | self.ps << 16;
        for q in 1..8 {
            strtab.store::<u64>(at + q * 8, 0);
        }
        strtab.store::<u64>(at + 16, domain.0 as u64 | vtcr << 32 | S2AA64 | S2R);
        strtab.store::<u64>(at + 24, root.as_u64() & ADDR_MASK_4);
        barrier::dma_wmb();
        strtab.store::<u64>(at, STE_V | STE_CONFIG_S2);
        barrier::dma_wmb();
        let result = self.flush_stream(&mut st, sid, domain.0).and_then(|()| {
            if !st.enabled {
                self.set_cr0(CR0_CMDQEN | CR0_EVENTQEN | CR0_SMMUEN)?;
                st.enabled = true;
            }
            Ok(())
        });
        if result.is_err() {
            let strtab = &Self::buffers(&st).strtab;
            strtab.store::<u64>(at, 0);
            barrier::dma_wmb();
            for q in 1..8 {
                strtab.store::<u64>(at + q * 8, 0);
            }
            let _ = self.flush_stream(&mut st, sid, domain.0);
        }
        result
    }

    fn detach(&self, device: DeviceId) -> Result<(), IommuError> {
        let sid = self.stream_id(device)?;
        let mut st = self.state.lock();
        let at = sid as usize * STE_BYTES;
        let strtab = &Self::buffers(&st).strtab;
        if strtab.load::<u64>(at) & STE_V == 0 {
            return Err(IommuError::NotAttached);
        }
        let vmid = strtab.load::<u64>(at + 16) as u16;
        strtab.store::<u64>(at, 0);
        barrier::dma_wmb();
        for q in 1..8 {
            strtab.store::<u64>(at + q * 8, 0);
        }
        barrier::dma_wmb();
        self.flush_stream(&mut st, sid, vmid)
    }

    fn invalidate(&self, domain: DomainId) -> Result<(), IommuError> {
        let mut st = self.state.lock();
        self.post(&mut st, CMD_TLBI_S12_VMALL | (domain.0 as u64) << 32, 0)?;
        self.sync(&mut st)
    }

    fn take_fault(&self) -> Option<Fault> {
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
        self.regs.w32(EVENTQ_CONS, (prod & 1 << 31) | (cons + 1) & mask);
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

impl<D: DmaAllocator + Sync + ?Sized> Drop for Smmuv3<'_, D> {
    fn drop(&mut self) {
        let mut st = self.state.lock();
        let buffers = ManuallyDrop::new(st.buffers.take());
        let stopped = self.set_cr0(0).is_ok();
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
    const FAR: Address = Address::new(0, 9, 0);

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
        // S2P, AArch64 tables, coherent walks, 16-bit VMIDs.
        regs.w32(IDR0, (IDR0_S2P | IDR0_TTF_AARCH64 | IDR0_COHACC | IDR0_VMID16 | idr0_extra) & !idr0_clear);
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
            if cr0 & CR0_CMDQEN == 0 || hw.stall {
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

        /// Looks `iova` up for stream `sid` as the unit would, walking a
        /// 4 KiB-granule stage-2 table from level 0.
        fn translate(&self, sid: u32, iova: u64, write: bool) -> Result<u64, &'static str> {
            if !self.translating() {
                return Ok(iova);
            }
            let steaddr = (self.regs.r64(STRTAB_BASE) & ADDR_MASK_4 & !0x3f) + sid as u64 * 64;
            let q0 = mem64(steaddr);
            if q0 & STE_V == 0 {
                return Err("abort");
            }
            assert_eq!((q0 >> 1) & 7, 6, "stage-2 translate, stage 1 bypass");
            let q2 = mem64(steaddr + 16);
            assert_ne!(q2 & S2AA64, 0);
            let vtcr = q2 >> 32;
            let (t0sz, sl0, tg0) = (vtcr & 0x3f, (vtcr >> 6) & 3, (vtcr >> 14) & 3);
            assert_eq!((sl0, tg0), (2, 0), "start at level 0, 4 KiB granule");
            if iova >> (64 - t0sz) != 0 {
                return Err("address size");
            }
            let mut table = mem64(steaddr + 24) & ADDR_MASK_4;
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
                    let ap = (e >> 6) & 3;
                    if write && ap & 2 == 0 || !write && ap & 1 == 0 {
                        return Err("permission");
                    }
                    return Ok((e & 0x0000_ffff_ffff_f000) | (iova & 0xfff));
                }
                table = e & 0x0000_ffff_ffff_f000;
            }
            unreachable!()
        }

        fn vmid_of(&self, sid: u32) -> u64 {
            mem64((self.regs.r64(STRTAB_BASE) & ADDR_MASK_4 & !0x3f) + sid as u64 * 64 + 16) & 0xffff
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
        for clear in [IDR0_S2P, IDR0_COHACC, IDR0_TTF_AARCH64] {
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
            f.hw.lock().unwrap().error_next = true;
            assert_eq!(d.attach(dev(NIC)), Err(IommuError::Hardware));
            std::thread::sleep(core::time::Duration::from_millis(10));
            // The error was acknowledged and the queue still works.
            d.attach(dev(NIC)).unwrap();
        }
        assert_eq!(f.regs.r32(GERROR), f.regs.r32(GERRORN));
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
}
