use super::*;
use crate::gicv3::tests::{Fake, FakeCpu};
use crate::iommu::testing::{HostDma, HostRegs, Pump, StdClock, mem64};
use std::sync::{Arc, Mutex};
use std::vec::Vec;

pub(crate) const ITS_PHYS: u64 = 0x808_0000;

/// `GITS_TYPER` of the fake: physical LPIs, 8-byte ITT entries, 16 event
/// and 16 device ID bits.
pub(crate) const TYPER: u64 = TYPER_PHYSICAL | 7 << 4 | 15 << 8 | 15 << 13;

/// A fake ITS: a thread consumes the command queue and records commands.
pub(crate) struct FakeIts {
    pub(crate) regs: HostRegs,
    cmds: Arc<Mutex<Vec<cmd::Command>>>,
    _pump: Pump,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Quirks {
    /// Stall at a command with this code.
    pub(crate) stall_on: Option<u64>,
}

impl FakeIts {
    pub(crate) fn new(typer: u64, quirks: Quirks) -> Self {
        let regs = HostRegs::new(ITS_REGS_LEN);
        regs.w64(GITS_TYPER, typer);
        regs.w32(GITS_CTLR, CTLR_QUIESCENT);
        regs.w64(GITS_BASER, 1 << 56 | 7 << 48);
        regs.w64(GITS_BASER + 8, 4 << 56 | 7 << 48);
        regs.w64(GITS_BASER + 16, 2 << 56 | 31 << 48);
        let cmds = Arc::new(Mutex::new(Vec::new()));
        let (r, log) = (regs.clone(), cmds.clone());
        let pump = Pump::start(move || {
            let ctlr = r.r32(GITS_CTLR);
            if ctlr & CTLR_ENABLED == 0 {
                r.w32(GITS_CTLR, ctlr | CTLR_QUIESCENT);
                return;
            }
            r.w32(GITS_CTLR, ctlr & !CTLR_QUIESCENT);
            let base = r.r64(GITS_CBASER) & ADDR_MASK_4K;
            let mut rd = r.r64(GITS_CREADR);
            if rd & CREADR_STALLED != 0 {
                return;
            }
            while rd != r.r64(GITS_CWRITER) & QUEUE_OFFSET {
                let c: cmd::Command = core::array::from_fn(|i| mem64(base + rd + i as u64 * 8));
                if quirks.stall_on == Some(c[0] & 0xff) {
                    r.w64(GITS_CREADR, rd | CREADR_STALLED);
                    return;
                }
                log.lock().unwrap().push(c);
                rd = (rd + CMD_LEN as u64) % QUEUE_LEN as u64;
                r.w64(GITS_CREADR, rd);
            }
        });
        Self { regs, cmds, _pump: pump }
    }

    pub(crate) fn its<'d>(
        &self,
        dma: &'d HostDma,
        clock: &'d StdClock,
        config: ItsConfig,
    ) -> Result<Its<'d, HostDma>, ItsError> {
        Its::new(self.regs.io(), PhysAddr::new(ITS_PHYS), dma, clock, config)
    }

    pub(crate) fn take(&self) -> Vec<cmd::Command> {
        core::mem::take(&mut *self.cmds.lock().unwrap())
    }
}

#[test]
fn command_encodings() {
    // Field positions as the GICv3 architecture specification lays them out.
    assert_eq!(cmd::mapd(0x18, 0x4321_0000, 5, true), [0x18_0000_0008, 4, 1 << 63 | 0x4321_0000, 0]);
    assert_eq!(cmd::mapd(7, 0x4321_0000, 5, false), [0x7_0000_0008, 4, 0, 0]);
    assert_eq!(cmd::mapc(3, 2, true), [0x09, 0, 1 << 63 | 2 << 16 | 3, 0]);
    assert_eq!(cmd::mapc(3, 0x80a, true)[2], 1 << 63 | 0x80a_0000 | 3, "a PTA target is the address >> 16");
    assert_eq!(cmd::mapti(0x10, 4, 8195, 1), [0x10_0000_000a, 8195 << 32 | 4, 1, 0]);
    assert_eq!(cmd::mapi(0x10, 4, 1), [0x10_0000_000b, 4, 1, 0]);
    assert_eq!(cmd::movi(0x10, 4, 2), [0x10_0000_0001, 4, 2, 0]);
    assert_eq!(cmd::discard(0x10, 4), [0x10_0000_000f, 4, 0, 0]);
    assert_eq!(cmd::int(0x10, 4), [0x10_0000_0003, 4, 0, 0]);
    assert_eq!(cmd::clear(0x10, 4), [0x10_0000_0004, 4, 0, 0]);
    assert_eq!(cmd::inv(0x10, 4), [0x10_0000_000c, 4, 0, 0]);
    assert_eq!(cmd::invall(5), [0x0d, 0, 5, 0]);
    assert_eq!(cmd::sync(1), [0x05, 0, 1 << 16, 0]);
    assert_eq!(cmd::movall(0, 1), [0x0e, 0, 0, 1 << 16]);
    assert_eq!(cmd::vmapp(9, 1, 0x4567_0000, 16, true), [0x29, 9 << 32, 1 << 63 | 1 << 16, 0x4567_0000 | 15]);
    assert_eq!(cmd::vmapti(0x10, 4, 9, 8192, cmd::NO_DOORBELL), [0x10_0000_002a, 9 << 32 | 4, 1023 << 32 | 8192, 0]);
    assert_eq!(cmd::vmovi(0x10, 4, 9, Some(8200)), [0x10_0000_0021, 9 << 32 | 4, 8200 << 32 | 1, 0]);
    assert_eq!(cmd::vmovi(0x10, 4, 9, None)[2], 0);
    assert_eq!(cmd::vmovp(9, 1, 2, 3), [2 << 32 | 0x22, 9 << 32 | 3, 1 << 16, 0]);
    assert_eq!(cmd::vsync(9), [0x25, 9 << 32, 0, 0]);
    assert_eq!(cmd::vinvall(9), [0x2d, 9 << 32, 0, 0]);
}

#[test]
fn flat_table_sizing() {
    assert_eq!(flat_table_size(1 << 16, 8, 4096), Some((512 * 1024, 127)));
    assert_eq!(flat_table_size(64, 8, 4096), Some((4096, 0)));
    assert_eq!(flat_table_size(64, 8, 65536), Some((65536, 0)));
    assert_eq!(flat_table_size(0, 8, 4096), Some((4096, 0)), "never an empty table");
    assert_eq!(flat_table_size(1 << 20, 8, 4096), None, "needs an indirect table");
    assert_eq!(flat_table_size(1 << 20, 8, 65536), Some((8 << 20, 127)));
}

#[test]
fn setup_programs_queue_and_tables() {
    let (dma, clock) = (HostDma::default(), StdClock::default());
    let fake = FakeIts::new(TYPER, Quirks::default());
    let its = fake.its(&dma, &clock, ItsConfig { device_bits: 8, vpes: 64 }).unwrap();
    assert_eq!(its.doorbell(), ITS_PHYS + 0x1_0040);
    assert_eq!(its.device_bits(), 8);
    assert!(!its.has_virtual_lpis());
    assert_eq!(its.table_entries(TableType::Devices), Some(512), "one 4 KiB page of 8-byte entries");
    assert_eq!(its.table_entries(TableType::Collections), Some(512));
    assert_eq!(its.table_entries(TableType::Vpes), None, "no virtual LPIs, no vPE table");
    let dev = fake.regs.r64(GITS_BASER);
    assert_eq!(dev & (BASER_VALID | BASER_RO | 3 << 8 | 0xff), BASER_VALID | 1 << 56 | 7 << 48);
    assert_eq!(dev & BASER_SHAREABILITY, 1 << 10);
    assert_eq!(fake.regs.r64(GITS_BASER + 16) & BASER_VALID, 0);
    let cb = fake.regs.r64(GITS_CBASER);
    assert_eq!(cb & (BASER_VALID | 0xff), BASER_VALID);
    assert_ne!(fake.regs.r32(GITS_CTLR) & CTLR_ENABLED, 0);
    drop(its);
    assert_eq!(fake.regs.r32(GITS_CTLR) & CTLR_ENABLED, 0, "disabled on drop");
    assert_eq!(fake.regs.r64(GITS_BASER) & BASER_VALID, 0);
    assert_eq!(dma.live(), 0, "everything freed");
}

#[test]
fn device_table_covers_the_hardware_bits_at_most() {
    let (dma, clock) = (HostDma::default(), StdClock::default());
    let fake = FakeIts::new(TYPER & !(0x1f << 13) | 9 << 13, Quirks::default());
    let its = fake.its(&dma, &clock, ItsConfig::default()).unwrap();
    assert_eq!(its.device_bits(), 10);
    assert_eq!(its.add_device(1 << 10, 4), Err(ItsError::BadDevice));
}

#[test]
fn virtual_its_gets_a_vpe_table() {
    let (dma, clock) = (HostDma::default(), StdClock::default());
    let fake = FakeIts::new(TYPER | TYPER_VIRTUAL, Quirks::default());
    let its = fake.its(&dma, &clock, ItsConfig { device_bits: 8, vpes: 200 }).unwrap();
    assert!(its.has_virtual_lpis());
    assert_eq!(its.table_entries(TableType::Vpes), Some(256), "two pages of 32-byte entries");
    assert_eq!(fake.regs.r64(GITS_BASER + 16) & 0xff, 1);
}

#[test]
fn refuses_bad_windows_and_non_physical_its() {
    let (dma, clock) = (HostDma::default(), StdClock::default());
    let small = HostRegs::new(0x1000);
    let r = Its::new(small.io(), PhysAddr::new(0), &dma, &clock, ItsConfig::default());
    assert_eq!(r.err(), Some(ItsError::BadRegisters));
    let none = FakeIts::new(TYPER & !TYPER_PHYSICAL, Quirks::default());
    assert_eq!(none.its(&dma, &clock, ItsConfig::default()).err(), Some(ItsError::Unsupported));
}

/// A `HostDma` that refuses allocations after the first `left`.
struct Limited {
    inner: HostDma,
    left: core::cell::Cell<usize>,
}

impl DmaAllocator for Limited {
    fn alloc_coherent(&self, len: usize) -> Option<osmium_hal::dma::DmaBuffer> {
        let left = self.left.get().checked_sub(1)?;
        self.left.set(left);
        self.inner.alloc_coherent(len)
    }

    unsafe fn free_coherent(&self, buf: osmium_hal::dma::DmaBuffer) {
        // SAFETY: forwarded contract.
        unsafe { self.inner.free_coherent(buf) }
    }
}

#[test]
fn failed_setup_invalidates_what_it_programmed() {
    let clock = StdClock::default();
    let fake = FakeIts::new(TYPER, Quirks::default());
    // The queue and the device table, then nothing for the collection table.
    let dma = Limited { inner: HostDma::default(), left: core::cell::Cell::new(2) };
    let r = Its::new(fake.regs.io(), PhysAddr::new(ITS_PHYS), &dma, &clock, ItsConfig { device_bits: 8, vpes: 1 });
    assert_eq!(r.err(), Some(ItsError::NoMemory));
    assert_eq!(dma.inner.live(), 0, "everything freed");
    assert_eq!(fake.regs.r64(GITS_BASER) & BASER_VALID, 0, "the device table's register no longer points at it");
    assert_eq!(fake.regs.r64(GITS_CBASER) & BASER_VALID, 0, "nor the queue's");
    assert_eq!(fake.regs.r32(GITS_CTLR) & CTLR_ENABLED, 0);
}

#[test]
fn the_command_queue_wraps() {
    let (dma, clock) = (HostDma::default(), StdClock::default());
    let lpis = LpiTables::new(&dma, 14).unwrap();
    let fake = FakeIts::new(TYPER, Quirks::default());
    let its = fake.its(&dma, &clock, ItsConfig { device_bits: 8, vpes: 1 }).unwrap();
    its.map_collection(0, 0).unwrap();
    its.add_device(1, 1).unwrap();
    its.map_event(1, 0, 0, &lpis, 0x5f).unwrap();
    fake.take();
    // Two commands (INT, SYNC) per trigger: several trips round the
    // 128-slot ring, each command seen once and in order.
    let rounds = 3 * QUEUE_LEN / CMD_LEN / 2 + 1;
    for _ in 0..rounds {
        its.trigger(1, 0).unwrap();
    }
    let cmds = fake.take();
    assert_eq!(cmds.len(), 2 * rounds);
    assert!(cmds.chunks(2).all(|c| c == [cmd::int(1, 0), cmd::sync(0)]));
    assert_eq!(fake.regs.r64(GITS_CWRITER), fake.regs.r64(GITS_CREADR));
    assert!(fake.regs.r64(GITS_CWRITER) < QUEUE_LEN as u64);
}

#[test]
fn map_and_unmap_events() {
    let (dma, clock) = (HostDma::default(), StdClock::default());
    let lpis = LpiTables::new(&dma, 14).unwrap();
    let fake = FakeIts::new(TYPER, Quirks::default());
    let its = fake.its(&dma, &clock, ItsConfig { device_bits: 16, vpes: 1 }).unwrap();
    assert_eq!(its.map_collection(64, 0), Err(ItsError::BadCollection));
    its.map_collection(0, 2).unwrap();
    assert_eq!(fake.take(), [cmd::mapc(0, 2, true), cmd::invall(0), cmd::sync(2)]);
    assert_eq!(its.collection(0), Some(2));
    assert_eq!(its.collection(1), None);

    let dev = 0x0018; // 00:03.0
    assert_eq!(its.map_event(dev, 0, 0, &lpis, 0x5f), Err(ItsError::BadDevice));
    its.add_device(dev, 3).unwrap();
    assert_eq!(its.add_device(dev, 3), Err(ItsError::BadDevice), "added twice");
    assert_eq!(its.add_device(1, 4096), Err(ItsError::BadEvent), "more events than MSI-X has");
    let c = fake.take();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0][..2], [0x18_0000_0008, 1], "2 event bits for 3 events");
    assert_ne!(c[0][2] & 1 << 63, 0);

    let v = its.map_event(dev, 1, 0, &lpis, 0x5f).unwrap();
    assert_eq!(v.intid, 8192);
    assert_eq!(v.message, MsiMessage { address: ITS_PHYS + 0x1_0040, data: 1 });
    assert_eq!(fake.take(), [cmd::mapti(dev, 1, 8192, 0), cmd::inv(dev, 1), cmd::sync(2)]);
    assert_eq!(lpis.property(8192), Some(0xa3), "enabled at priority 0xa0");
    assert_eq!(its.event_lpi(dev, 1), Some(8192));
    assert_eq!(its.event_lpi(dev, 0), None);
    assert_eq!(its.map_event(dev, 1, 0, &lpis, 0x5f), Err(ItsError::BadEvent), "mapped twice");
    assert_eq!(its.map_event(dev, 4, 0, &lpis, 0x5f), Err(ItsError::BadEvent), "beyond the ITT");
    assert_eq!(its.map_event(dev, 0, 1, &lpis, 0x5f), Err(ItsError::BadCollection));

    its.trigger(dev, 1).unwrap();
    its.clear(dev, 1).unwrap();
    assert_eq!(fake.take(), [cmd::int(dev, 1), cmd::sync(2), cmd::clear(dev, 1), cmd::sync(2)]);
    assert_eq!(its.trigger(dev, 2), Err(ItsError::BadEvent));

    its.map_collection(1, 3).unwrap();
    fake.take();
    its.move_event(dev, 1, 1).unwrap();
    assert_eq!(fake.take(), [cmd::movi(dev, 1, 1), cmd::sync(2), cmd::sync(3)]);
    its.trigger(dev, 1).unwrap();
    assert_eq!(fake.take()[1], cmd::sync(3), "the event now syncs on its new collection");

    its.unmap_event(dev, 1, &lpis).unwrap();
    assert_eq!(fake.take(), [cmd::discard(dev, 1), cmd::sync(3)]);
    assert!(!lpis.is_allocated(8192));
    assert_eq!(lpis.property(8192), Some(crate::gicv3::lpi::property(0, false)));
    assert_eq!(its.unmap_event(dev, 1, &lpis), Err(ItsError::BadEvent));

    let v = its.map_event(dev, 2, 0, &lpis, 0x5f).unwrap();
    fake.take();
    its.remove_device(dev, &lpis).unwrap();
    assert_eq!(fake.take(), [cmd::discard(dev, 2), cmd::mapd(dev, 0, 0, false)]);
    assert!(!lpis.is_allocated(v.intid));
    assert_eq!(its.remove_device(dev, &lpis), Err(ItsError::BadDevice));
    drop(its);
    drop(lpis);
    assert_eq!(dma.live(), 0);
}

#[test]
fn too_many_devices() {
    let (dma, clock) = (HostDma::default(), StdClock::default());
    let fake = FakeIts::new(TYPER, Quirks::default());
    let its = fake.its(&dma, &clock, ItsConfig { device_bits: 8, vpes: 1 }).unwrap();
    for d in 0..MAX_DEVICES as u32 {
        its.add_device(d, 1).unwrap();
    }
    assert_eq!(its.add_device(200, 1), Err(ItsError::TooManyDevices));
}

#[test]
fn a_stalled_queue_is_reported() {
    let (dma, clock) = (HostDma::default(), StdClock::default());
    let lpis = LpiTables::new(&dma, 14).unwrap();
    let fake = FakeIts::new(TYPER, Quirks { stall_on: Some(0x0a) });
    let its = fake.its(&dma, &clock, ItsConfig { device_bits: 8, vpes: 1 }).unwrap();
    its.map_collection(0, 0).unwrap();
    its.add_device(1, 1).unwrap();
    assert_eq!(its.map_event(1, 0, 0, &lpis, 1), Err(ItsError::CommandStalled));
    assert_eq!(lpis.alloc(), Some(8192), "the LPI went back");
}

#[test]
fn collection_targets_follow_pta() {
    let (dma, clock) = (HostDma::default(), StdClock::default());
    let (mut f, cpu) = (Fake::new(), FakeCpu::new(1));
    f.r[(crate::gicv3::GICR_STRIDE + crate::gicv3::GICR_TYPER) / 4] |= 1 << 8;
    let gic = f.gic(&cpu);
    assert!(gic.init_cpu());
    let gicr = PhysAddr::new(0x80a_0000);
    let fake = FakeIts::new(TYPER, Quirks::default());
    let its = fake.its(&dma, &clock, ItsConfig { device_bits: 8, vpes: 1 }).unwrap();
    assert_eq!(its.collection_target(&gic, 0, gicr), Some(1), "processor number");
    assert_eq!(its.collection_target(&gic, 1, gicr), None, "no redistributor");
    drop(its);
    let fake = FakeIts::new(TYPER | TYPER_PTA, Quirks::default());
    let its = fake.its(&dma, &clock, ItsConfig { device_bits: 8, vpes: 1 }).unwrap();
    assert_eq!(its.collection_target(&gic, 0, gicr), Some((0x80a_0000 + 0x2_0000) >> 16), "address");
}
