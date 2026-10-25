//! Tests of interrupt-driven completion, native command queuing and ATAPI
//! drives, against the fake HBA.

use std::vec;
use std::vec::Vec;

use osmium_hal::block::{BlockDevice, BlockError};

use super::atapi::{READ_10, READ_CAPACITY_10, REQUEST_SENSE, TEST_UNIT_READY};
use super::disk::{FLUSH_CACHE_EXT, READ_DMA_EXT, READ_FPDMA_QUEUED, READ_LOG_EXT, WRITE_DMA_EXT, WRITE_FPDMA_QUEUED};
use super::fake::{self, Cmd, FakeDev, FakeHba};
use super::port::{IE, IS, MAX_SLOTS, SERR};
use super::{Ahci, AhciDisk, AhciError, AhciIrq, GHC_IE, cap};
use osmium_drivers::virtio::testing::HostDma;

const SECTORS: u64 = 1000;

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed)).collect()
}

/// Runs `body` against the disk on port 0 of a fake HBA set up by `setup`;
/// returns the commands the disk saw (IDENTIFY first) and its contents.
fn with_disk(
    dev: FakeDev,
    setup: impl FnOnce(&mut FakeHba),
    body: impl FnOnce(&mut AhciDisk<'_, HostDma>),
) -> (Vec<Cmd>, Vec<u8>) {
    let dma = HostDma::default();
    let mut hba = FakeHba::new(1);
    hba.attach(0, dev);
    setup(&mut hba);
    let mut ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
    let mut disk = ahci.take_disk(0).unwrap();
    body(&mut disk);
    drop((disk, ahci));
    assert_eq!(dma.live.get(), 0);
    let hba = fake::uninstall();
    let FakeDev::Disk { data, .. } = &hba.ports[0].dev.as_ref().unwrap() else { panic!("wrong fake device kind") };
    (hba.log, data.clone())
}

#[test]
fn ncq_keeps_several_commands_in_flight() {
    let original = pattern(SECTORS as usize * 512, 7);
    let new = pattern(300 * 512, 99);
    let (log, disk) = with_disk(
        FakeDev::disk(SECTORS, 512).with_ncq(32).with_data(original.clone()),
        |_| {},
        |d| {
            assert_eq!(d.queue_depth(), MAX_SLOTS);
            // 100 sectors = 50 KiB: three full 16 KiB chunks and a short
            // one, all queued together.
            let mut buf = vec![0u8; 100 * 512];
            d.read_blocks(5, &mut buf).unwrap();
            assert!(buf == original[5 * 512..105 * 512]);
            fake::with(|f| {
                assert_eq!(f.ports[0].max_inflight, 4);
                // The device finishes the highest tag first.
                assert_eq!(f.ports[0].slots_run[1..], [3, 2, 1, 0]);
            });

            // A write bigger than one round (8 x 16 KiB) takes several.
            d.write_blocks(20, &new).unwrap();
            let mut back = vec![0u8; new.len()];
            d.read_blocks(20, &mut back).unwrap();
            assert!(back == new);
            fake::with(|f| assert_eq!(f.ports[0].max_inflight, 8));
            // A single sector is queued too; a flush is not.
            d.read_blocks(0, &mut [0u8; 512]).unwrap();
            d.flush().unwrap();
        },
    );
    // Executed highest tag first: the short chunk at the end goes first.
    let first: Vec<_> = log[1..5].iter().map(|c| (c.command, c.lba, c.count, c.bytes)).collect();
    let q = READ_FPDMA_QUEUED;
    assert_eq!(first, [(q, 5 + 96, 4, 2048), (q, 5 + 64, 32, 16384), (q, 5 + 32, 32, 16384), (q, 5, 32, 16384)]);
    assert!(log.iter().all(|c| c.command != READ_DMA_EXT && c.command != WRITE_DMA_EXT));
    assert!(log.iter().any(|c| c.command == WRITE_FPDMA_QUEUED));
    assert_eq!(log.last().unwrap().command, FLUSH_CACHE_EXT);
    assert!(disk[20 * 512..320 * 512] == new[..]);
    assert!(disk[..20 * 512] == original[..20 * 512], "nothing else touched");
}

#[test]
fn ncq_needs_both_ends_and_a_queue() {
    let depth = |dev: FakeDev, setup: fn(&mut FakeHba)| {
        let mut depth = 0;
        with_disk(dev, setup, |disk| depth = disk.queue_depth());
        depth
    };
    assert_eq!(depth(FakeDev::disk(SECTORS, 512), |_| {}), 1, "a disk without NCQ");
    assert_eq!(depth(FakeDev::disk(SECTORS, 512).with_ncq(1), |_| {}), 1, "a queue of one");
    assert_eq!(depth(FakeDev::disk(SECTORS, 512).with_ncq(32), |h| h.cap &= !cap::SNCQ), 1, "an HBA without");
    assert_eq!(depth(FakeDev::disk(SECTORS, 512).with_ncq(3), |_| {}), 3, "the disk's queue limits");
    assert_eq!(depth(FakeDev::disk(SECTORS, 512).with_ncq(32), |h| h.cap = h.cap & !(31 << 8) | 1 << 8), 2, "NCS");

    // Without it, nothing is queued.
    let (log, _) = with_disk(
        FakeDev::disk(SECTORS, 512).with_ncq(32),
        |h| h.cap &= !cap::SNCQ,
        |d| d.read_blocks(0, &mut [0u8; 1024]).unwrap(),
    );
    assert_eq!(log[1].command, READ_DMA_EXT);

    // Sectors bigger than a chunk make the chunk a sector.
    let data = pattern(3 * 32768, 1);
    let (log, disk) = with_disk(
        FakeDev::disk(64, 32768).with_ncq(4),
        |_| {},
        |d| {
            assert_eq!(d.queue_depth(), 4);
            d.write_blocks(0, &data).unwrap();
        },
    );
    assert_eq!(log[1..].iter().map(|c| (c.count, c.bytes)).collect::<Vec<_>>(), [(1, 32768); 3]);
    assert!(disk[..3 * 32768] == data[..]);
}

#[test]
fn ncq_errors_fail_the_round_and_clear_the_device() {
    let (log, _) = with_disk(
        FakeDev::disk(SECTORS, 512).with_ncq(32),
        |f| f.ports[0].fail_from = 64,
        |d| {
            let mut buf = vec![0u8; 100 * 512];
            // The chunk past sector 64 fails; the rest are abandoned.
            assert_eq!(d.read_blocks(0, &mut buf), Err(BlockError::Io));
            fake::with(|f| {
                assert_eq!(f.ports[0].starts, 2, "restarted");
                assert!(!f.ports[0].ncq_error_pending(), "the error log was read");
            });
            // The device accepts commands again, queued or not.
            assert_eq!(d.read_blocks(0, &mut buf[..64 * 512]), Ok(()));
            assert_eq!(d.write_blocks(10, &buf[..512]), Ok(()));
            assert_eq!(d.flush(), Ok(()));
            fake::with(|f| assert_eq!(f.port_reg(0, SERR), 0));
        },
    );
    assert_eq!(log.iter().filter(|c| c.command == READ_LOG_EXT).count(), 1);
}

#[test]
fn a_hung_queue_times_out_and_is_not_read_for_a_log() {
    let (log, _) = with_disk(
        FakeDev::disk(SECTORS, 512).with_ncq(32),
        |_| {},
        |d| {
            let mut buf = vec![0u8; 100 * 512];
            fake::with(|f| f.ports[0].hang = true);
            assert_eq!(d.read_blocks(0, &mut buf), Err(BlockError::Io));
            fake::with(|f| f.ports[0].hang = false);
            assert_eq!(d.read_blocks(0, &mut buf), Ok(()));
        },
    );
    assert!(log.iter().all(|c| c.command != READ_LOG_EXT));
}

std::thread_local! {
    static IRQ: core::cell::RefCell<Option<AhciIrq>> = const { core::cell::RefCell::new(None) };
    /// (idle calls, interrupts handled)
    static IDLES: core::cell::Cell<(u32, u32)> = const { core::cell::Cell::new((0, 0)) };
}

/// A wait hook that, like a `wfi` between interrupts, takes the HBA's
/// interrupt if its line is up and runs the handler.
fn idle() {
    IDLES.with(|c| c.set((c.get().0 + 1, c.get().1)));
    fake::with(|f| f.sleep());
    if fake::with(|f| f.irq_asserted()) {
        let handled = IRQ.with(|i| i.borrow().as_ref().unwrap().handle());
        assert!(handled);
        assert!(!fake::with(|f| f.irq_asserted()), "the handler quiets the line");
        IDLES.with(|c| c.set((c.get().0, c.get().1 + 1)));
    }
}

#[test]
fn interrupts_wake_the_waiter() {
    for ncq in [0, 32] {
        IDLES.with(|c| c.set((0, 0)));
        let dma = HostDma::default();
        let mut hba = FakeHba::new(1);
        hba.attach(0, FakeDev::disk(SECTORS, 512).with_ncq(ncq).with_data(pattern(SECTORS as usize * 512, 3)));
        hba.ports[0].fail_from = 500;
        let mut ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
        IRQ.with(|i| *i.borrow_mut() = Some(ahci.irq()));
        let mut disk = ahci.take_disk(0).unwrap();

        // Polled until asked: the hook never runs.
        let mut buf = vec![0u8; 40 * 512];
        disk.read_blocks(0, &mut buf).unwrap();
        assert_eq!(IDLES.with(|c| c.get()), (0, 0));
        fake::with(|f| assert_eq!((f.ghc() & GHC_IE, f.port_reg(0, IE)), (0, 0)));

        ahci.enable_interrupts();
        disk.enable_interrupts(idle);
        disk.read_blocks(0, &mut buf).unwrap();
        assert!(buf == pattern(SECTORS as usize * 512, 3)[..40 * 512]);
        disk.write_blocks(60, &buf).unwrap();
        disk.flush().unwrap();
        let (idles, handled) = IDLES.with(|c| c.get());
        assert!(idles > 0 && handled > 0, "slept {idles}, interrupted {handled}");
        // One command: the interrupt that woke the waiter is the only one.
        let raised = fake::with(|f| f.irq_raises);
        disk.read_blocks(0, &mut buf[..512]).unwrap();
        assert_eq!(fake::with(|f| f.irq_raises), raised + 1, "no interrupt after the command finished");
        fake::with(|f| {
            assert!(!f.irq_asserted(), "nothing left asserted");
            assert_eq!(f.port_reg(0, IE), 0, "disarmed between commands");
            assert_eq!(f.port_reg(0, IS), 0);
        });

        // An error interrupts too, and recovery leaves the line quiet.
        assert_eq!(disk.read_blocks(480, &mut buf), Err(BlockError::Io));
        assert_eq!(disk.read_blocks(0, &mut buf), Ok(()));
        fake::with(|f| assert!(!f.irq_asserted()));

        // Back to polling.
        disk.disable_interrupts();
        let before = IDLES.with(|c| c.get());
        disk.read_blocks(0, &mut buf).unwrap();
        assert_eq!(IDLES.with(|c| c.get()), before);
        ahci.disable_interrupts();
        fake::with(|f| assert_eq!(f.ghc() & GHC_IE, 0));
        drop((disk, ahci));
        assert_eq!(dma.live.get(), 0);
        fake::uninstall();
    }
}

#[test]
fn the_handler_ignores_an_interrupt_that_is_not_the_hbas() {
    let dma = HostDma::default();
    let mut hba = FakeHba::new(2);
    hba.attach(0, FakeDev::disk(8, 512));
    let mut ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
    ahci.enable_interrupts();
    assert!(!ahci.irq().handle(), "nothing pending");
    drop(ahci);
    fake::uninstall();
}

/// A disc of `blocks` 2048-byte blocks.
fn disc(blocks: usize) -> Vec<u8> {
    pattern(blocks * 2048, 11)
}

/// Runs `body` against the optical drive on port 0.
fn with_cd(dev: FakeDev, body: impl FnOnce(&mut super::AhciAtapi<'_, HostDma>)) -> (Vec<Cmd>, Vec<u8>) {
    let dma = HostDma::default();
    let mut hba = FakeHba::new(1);
    hba.attach(0, dev);
    let mut ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
    assert!(ahci.atapi_drives().eq([0]));
    assert_eq!(ahci.disks().count(), 0);
    let mut cd = ahci.take_atapi(0).unwrap();
    body(&mut cd);
    drop((cd, ahci));
    assert_eq!(dma.live.get(), 0);
    let hba = fake::uninstall();
    let FakeDev::Atapi(cd) = hba.ports[0].dev.as_ref().unwrap() else { panic!("wrong fake device kind") };
    (hba.log, cd.scsi.clone())
}

#[test]
fn atapi_reads_a_disc() {
    let image = disc(100);
    let (log, scsi) = with_cd(FakeDev::atapi(Some(image.clone())), |cd| {
        assert_eq!((cd.block_size(), cd.num_blocks()), (2048, 100));
        assert_eq!((cd.model(), cd.serial(), cd.port()), ("Fake DVD-ROM", "CD0001", 0));

        let mut buf = vec![0u8; 3 * 2048];
        cd.read_blocks(7, &mut buf).unwrap();
        assert!(buf == image[7 * 2048..10 * 2048]);
        // 64 KiB per command: 32 blocks.
        let mut all = vec![0u8; 100 * 2048];
        cd.read_blocks(0, &mut all).unwrap();
        assert!(all == image);
        cd.read_blocks(0, &mut []).unwrap();
        fake::with(|f| {
            let reads: Vec<_> = f.ports[0].packets.iter().filter(|p| p[0] == READ_10).collect();
            assert_eq!(reads.len(), 5);
            // READ(10): big-endian LBA in bytes 2-5, count in 7-8.
            assert_eq!(reads[0][..10], [READ_10, 0, 0, 0, 0, 7, 0, 0, 3, 0]);
            assert_eq!(reads[4][..10], [READ_10, 0, 0, 0, 0, 96, 0, 0, 4, 0]);
        });

        assert_eq!(cd.write_blocks(0, &buf), Err(BlockError::ReadOnly));
        assert_eq!(cd.read_blocks(98, &mut buf), Err(BlockError::OutOfRange));
        assert_eq!(cd.read_blocks(0, &mut [0; 100]), Err(BlockError::BadBuffer));
        assert_eq!(cd.flush(), Ok(()));
    });
    assert_eq!(scsi[..2], [TEST_UNIT_READY, READ_CAPACITY_10]);
    assert!(log[0].command == 0xa1, "IDENTIFY PACKET DEVICE first");
    assert!(log.iter().all(|c| c.command != READ_DMA_EXT));
}

#[test]
fn atapi_without_dma_uses_pio_and_a_drive_can_be_empty_or_change() {
    // A PIO-only drive with no disc: 0 blocks, until one is put in.
    let mut pio = FakeDev::atapi(None);
    if let FakeDev::Atapi(c) = &mut pio {
        c.dma = false;
    }
    let (_, scsi) = with_cd(pio, |cd| {
        assert_eq!(cd.num_blocks(), 0);
        assert_eq!(cd.read_blocks(0, &mut [0; 2048]), Err(BlockError::OutOfRange));
        // The new disc answers its first command with a unit attention.
        fake::with(|f| {
            let FakeDev::Atapi(c) = f.ports[0].dev.as_mut().unwrap() else { panic!("wrong fake device kind") };
            c.disc = Some(disc(10));
            c.attention = true;
        });
        cd.reload().unwrap();
        assert_eq!(cd.num_blocks(), 10);
        // Reads that need DMA features fail on this fake if asked wrongly;
        // here the driver must have asked for PIO.
        let mut buf = [0u8; 2048];
        cd.read_blocks(9, &mut buf).unwrap();
        assert!(buf[..] == disc(10)[9 * 2048..]);

        // Disc removed again.
        fake::with(|f| {
            let FakeDev::Atapi(c) = f.ports[0].dev.as_mut().unwrap() else { panic!("wrong fake device kind") };
            c.disc = None;
        });
        cd.reload().unwrap();
        assert_eq!(cd.num_blocks(), 0);
    });
    // Empty: TUR fails, SENSE says no medium. Changed: TUR (attention),
    // SENSE, TUR, CAPACITY, then a READ(10). Gone: TUR, SENSE.
    let (t, s, c) = (TEST_UNIT_READY, REQUEST_SENSE, READ_CAPACITY_10);
    assert_eq!(scsi, [t, s, t, s, t, c, READ_10, t, s]);
}

#[test]
fn atapi_errors_recover_the_port() {
    let (log, _) = with_cd(FakeDev::atapi(Some(disc(100))), |cd| {
        fake::with(|f| {
            let FakeDev::Atapi(c) = f.ports[0].dev.as_mut().unwrap() else { panic!("wrong fake device kind") };
            c.fail_from = 50;
        });
        let mut buf = vec![0u8; 4 * 2048];
        assert_eq!(cd.read_blocks(48, &mut buf), Err(BlockError::Io));
        assert_eq!(cd.read_blocks(10, &mut buf), Ok(()));
        fake::with(|f| assert_eq!(f.port_reg(0, SERR), 0));
        // Not ready for a while: loading retries.
        fake::with(|f| {
            let FakeDev::Atapi(c) = f.ports[0].dev.as_mut().unwrap() else { panic!("wrong fake device kind") };
            c.not_ready = 2;
        });
        cd.reload().unwrap();
        assert_eq!(cd.num_blocks(), 100);
    });
    assert!(log.len() > 4);
}

#[test]
fn disks_and_drives_are_taken_by_the_right_call() {
    let dma = HostDma::default();
    let mut hba = FakeHba::new(2);
    hba.attach(0, FakeDev::disk(8, 512));
    hba.attach(1, FakeDev::atapi(None));
    let mut ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
    assert_eq!(ahci.take_atapi(0).err(), Some(AhciError::Unsupported));
    assert_eq!(ahci.take_disk(1).err(), Some(AhciError::Unsupported));
    assert_eq!(ahci.take_atapi(2).err(), Some(AhciError::NoDevice));
    assert!(ahci.disks().eq([0]) && ahci.atapi_drives().eq([1]));
    let cd = ahci.take_atapi(1).unwrap();
    assert_eq!(ahci.take_atapi(1).err(), Some(AhciError::NoDevice), "taken");
    drop((cd, ahci));
    assert_eq!(dma.live.get(), 0);
    fake::uninstall();
}
