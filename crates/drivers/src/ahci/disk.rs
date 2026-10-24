//! A SATA disk on one AHCI port.

use osmium_hal::block::{BlockDevice, BlockError};
use osmium_hal::dma::{DmaAllocator, OwnedDma};

use super::AhciError;
use super::port::{Command, MAX_SLOTS, Port};

/// Bytes of DMA bounce buffer per disk, and so the most one command
/// transfers.
pub const DATA_LEN: usize = 64 * 1024;

// ATA commands.
pub(super) const IDENTIFY_DEVICE: u8 = 0xec;
pub(super) const READ_DMA_EXT: u8 = 0x25;
pub(super) const WRITE_DMA_EXT: u8 = 0x35;
pub(super) const FLUSH_CACHE_EXT: u8 = 0xea;
pub(super) const READ_FPDMA_QUEUED: u8 = 0x60;
pub(super) const WRITE_FPDMA_QUEUED: u8 = 0x61;
pub(super) const READ_LOG_EXT: u8 = 0x2f;
/// The log page (in the LBA) holding the details of an NCQ error.
pub(super) const NCQ_ERROR_LOG: u64 = 0x10;
pub(super) const IDENTIFY_PACKET_DEVICE: u8 = 0xa1;

/// The device register for commands that take an LBA.
pub(super) const DEVICE_LBA: u8 = 0x40;

const IDENTIFY_LEN: usize = 512;
const SECTOR_SIZE: usize = 512;
/// Bytes one queued command moves, at least (a sector may be larger).
const NCQ_CHUNK: usize = 16 * 1024;

// IDENTIFY DEVICE words.
const ID_SERIAL: usize = 10;
const ID_MODEL: usize = 27;
/// Word 75 bits 4:0 are the queue depth less one; word 76 bit 8 says the
/// device does native command queuing.
const ID_QUEUE_DEPTH: usize = 75;
const ID_SATA_CAPS: usize = 76;
const ID_NCQ: u16 = 1 << 8;
const ID_COMMAND_SETS: usize = 83;
const ID_LBA48: u16 = 1 << 10;
/// Words 83 and 106 are valid when their bits 15:14 are 01.
const ID_VALID_MASK: u16 = 0xc000;
const ID_VALID: u16 = 0x4000;
const ID_MAX_LBA48: usize = 100;
/// Sectors a 48-bit LBA reaches.
const MAX_SECTORS: u64 = 1 << 48;
const ID_SECTOR_SIZES: usize = 106;
const ID_LOGICAL_SECTOR: usize = 117;

/// A SATA disk, addressed in logical sectors with 48-bit LBAs. It owns its
/// port; dropping it stops the port and frees its memory.
///
/// If the HBA and the disk both do native command queuing, a read or write
/// of more than one chunk (16 KiB, or a sector if that is larger) keeps up
/// to eight chunks in flight at once, each in its own command slot with its
/// own part of the bounce buffer ([`AhciDisk::queue_depth`]).
pub struct AhciDisk<'d, D: DmaAllocator + ?Sized> {
    port: Port<'d, D>,
    sectors: u64,
    sector_size: usize,
    /// Commands in flight at once: 1 unless the disk does NCQ.
    slots: usize,
    /// Bytes of bounce buffer per slot.
    chunk: usize,
    model: [u8; 40],
    serial: [u8; 20],
}

impl<'d, D: DmaAllocator + ?Sized> AhciDisk<'d, D> {
    /// Gives `port` a bounce buffer from `dma` and identifies its disk.
    pub(super) fn new(mut port: Port<'d, D>, dma: &'d D) -> Result<Self, AhciError> {
        port.set_data(OwnedDma::new(dma, DATA_LEN).ok_or(AhciError::NoMemory)?)?;
        let cmd = Command { command: IDENTIFY_DEVICE, len: IDENTIFY_LEN, ..Command::default() };
        port.exec(cmd)?;
        let mut id = [0u8; IDENTIFY_LEN];
        port.data()?.read(0, &mut id);
        let word = |i: usize| id.get(2 * i..).and_then(|b| b.first_chunk::<2>()).map_or(0, |&b| u16::from_le_bytes(b));

        let sets = word(ID_COMMAND_SETS);
        if sets & ID_VALID_MASK != ID_VALID || sets & ID_LBA48 == 0 {
            return Err(AhciError::Unsupported);
        }
        // Words 100–103 count sectors in 64 bits, beyond what the commands
        // can address.
        let sectors = (0..4).fold(0u64, |n, i| n | (word(ID_MAX_LBA48 + i) as u64) << (16 * i)).min(MAX_SECTORS);
        // Bit 12 of word 106 says words 117–118 hold the logical sector
        // size, in words.
        let sizes = word(ID_SECTOR_SIZES);
        let sector_size = if sizes & ID_VALID_MASK == ID_VALID && sizes & 1 << 12 != 0 {
            2 * (word(ID_LOGICAL_SECTOR) as usize | (word(ID_LOGICAL_SECTOR + 1) as usize) << 16)
        } else {
            SECTOR_SIZE
        };
        if !sector_size.is_power_of_two() || !(SECTOR_SIZE..=DATA_LEN).contains(&sector_size) {
            return Err(AhciError::Unsupported);
        }
        // ATA strings hold two characters per word, high byte first.
        let string = |first: usize, out: &mut [u8]| {
            for (i, pair) in out.as_chunks_mut::<2>().0.iter_mut().enumerate() {
                pair.copy_from_slice(&word(first + i).to_be_bytes());
            }
        };
        let mut model = [0u8; 40];
        let mut serial = [0u8; 20];
        string(ID_MODEL, &mut model);
        string(ID_SERIAL, &mut serial);

        // Native command queuing needs both ends, and a queue worth having.
        let depth = (word(ID_QUEUE_DEPTH) & 0x1f) as usize + 1;
        let slots = if port.hba_ncq() && word(ID_SATA_CAPS) & ID_NCQ != 0 { depth.min(port.max_slots()) } else { 1 };
        let chunk = if slots > 1 { NCQ_CHUNK.max(sector_size) } else { DATA_LEN };
        if slots > 1 {
            port.set_data(OwnedDma::new(dma, slots * chunk).ok_or(AhciError::NoMemory)?)?;
            port.set_slots(slots);
        }
        Ok(Self { port, sectors, sector_size, slots, chunk, model, serial })
    }

    /// Commands the disk keeps in flight at once: more than 1 means native
    /// command queuing is in use.
    pub fn queue_depth(&self) -> usize {
        self.slots
    }

    /// Waits for completions by calling `idle` between looks at the port
    /// (typically a function that sleeps until the next interrupt), with
    /// the port's interrupts armed, instead of spinning. The HBA's interrupts must be on
    /// ([`Ahci::enable_interrupts`](super::Ahci::enable_interrupts)), and
    /// the kernel's handler must call [`AhciIrq::handle`](super::AhciIrq::handle).
    ///
    /// `idle` must return when a timer interrupt arrives even if the disk
    /// stays silent, or a dead disk would hang the caller: waits are only
    /// bounded by a count of `idle` calls. A spurious return is harmless.
    pub fn enable_interrupts(&mut self, idle: fn()) {
        self.port.set_idle(Some(idle));
    }

    /// Goes back to polling.
    pub fn disable_interrupts(&mut self) {
        self.port.set_idle(None);
    }

    /// The port the disk is on.
    pub fn port(&self) -> u8 {
        self.port.index()
    }

    /// The model, from IDENTIFY DEVICE, without its padding.
    pub fn model(&self) -> &str {
        trim(&self.model)
    }

    /// The serial number, from IDENTIFY DEVICE, without its padding.
    pub fn serial(&self) -> &str {
        trim(&self.serial)
    }

    /// Moves `len` bytes of the bounce buffer to or from the disk at `lba`.
    fn transfer(&mut self, command: u8, lba: u64, len: usize, write: bool) -> Result<(), BlockError> {
        let count = (len / self.sector_size) as u16;
        let cmd = Command { command, lba, count, device: DEVICE_LBA, len, write, ..Command::default() };
        self.port.exec(cmd).map_err(|_| BlockError::Io)
    }

    /// One round of queued commands over `len` bytes of the bounce buffer
    /// (at most `slots * chunk`), starting at `lba`.
    fn transfer_queued(&mut self, command: u8, lba: u64, len: usize, write: bool) -> Result<(), BlockError> {
        let mut cmds = [Command::default(); MAX_SLOTS];
        let n = len.div_ceil(self.chunk);
        for (i, cmd) in cmds.iter_mut().take(n).enumerate() {
            let off = i * self.chunk;
            let bytes = self.chunk.min(len.saturating_sub(off));
            let sectors = (bytes / self.sector_size) as u16;
            *cmd = Command {
                command,
                features: sectors,
                lba: lba + (off / self.sector_size) as u64,
                // The tag is the slot, in bits 7:3.
                count: (i as u16) << 3,
                device: DEVICE_LBA,
                len: bytes,
                write,
                data_off: off,
                packet: None,
            };
        }
        self.port.exec_queued(cmds.get(..n).unwrap_or(&[])).map_err(|_| BlockError::Io)
    }
}

/// `s` without leading and trailing spaces and NULs, or `""` if it is
/// not text.
pub(super) fn trim(s: &[u8]) -> &str {
    core::str::from_utf8(s).unwrap_or("").trim_matches([' ', '\0'])
}

impl<D: DmaAllocator + ?Sized> BlockDevice for AhciDisk<'_, D> {
    fn block_size(&self) -> usize {
        self.sector_size
    }

    fn num_blocks(&self) -> u64 {
        self.sectors
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let round = self.slots * self.chunk;
        for (i, part) in buf.chunks_mut(round).enumerate() {
            let sector = lba + (i * round / self.sector_size) as u64;
            if self.slots > 1 {
                self.transfer_queued(READ_FPDMA_QUEUED, sector, part.len(), false)?;
            } else {
                self.transfer(READ_DMA_EXT, sector, part.len(), false)?;
            }
            self.port.data().map_err(|_| BlockError::Io)?.read(0, part);
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let round = self.slots * self.chunk;
        for (i, part) in buf.chunks(round).enumerate() {
            let sector = lba + (i * round / self.sector_size) as u64;
            self.port.data().map_err(|_| BlockError::Io)?.write(0, part);
            if self.slots > 1 {
                self.transfer_queued(WRITE_FPDMA_QUEUED, sector, part.len(), true)?;
            } else {
                self.transfer(WRITE_DMA_EXT, sector, part.len(), true)?;
            }
        }
        Ok(())
    }

    /// Flushes the disk's write cache.
    fn flush(&mut self) -> Result<(), BlockError> {
        self.transfer(FLUSH_CACHE_EXT, 0, 0, false)
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake::{self, Cmd, FakeClock, FakeDev, FakeHba};
    use super::super::port::{CMD, CMD_FRE, CMD_ST, SERR};
    use super::super::{Ahci, cap};
    use super::*;
    use crate::virtio::testing::HostDma;
    use std::vec;
    use std::vec::Vec;

    const SECTORS: u64 = 1000;

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed)).collect()
    }

    /// Runs `body` against the disk on port 0 of a fake HBA set up by
    /// `setup`; returns the commands the disk saw (IDENTIFY first) and its
    /// final contents.
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
    fn identify() {
        let mut dev = FakeDev::disk(SECTORS, 512);
        dev.set_model("QEMU HARDDISK", "QM00001");
        with_disk(
            dev,
            |_| {},
            |d| {
                assert_eq!((d.block_size(), d.num_blocks()), (512, SECTORS));
                assert_eq!((d.model(), d.serial(), d.port()), ("QEMU HARDDISK", "QM00001", 0));
            },
        );

        let (log, _) = with_disk(
            FakeDev::disk(1 << 40, 4096),
            |_| {},
            |d| {
                assert_eq!((d.block_size(), d.num_blocks()), (4096, 1 << 40));
            },
        );
        assert_eq!(log, [Cmd { command: IDENTIFY_DEVICE, lba: 0, count: 0, bytes: 512 }]);
    }

    #[test]
    fn rejects_disks_it_cannot_drive() {
        let mut no_lba48 = FakeDev::disk(SECTORS, 512);
        no_lba48.set_lba48(false);
        for dev in [no_lba48, FakeDev::disk(SECTORS, 256), FakeDev::disk(SECTORS, 2 * DATA_LEN)] {
            let dma = HostDma::default();
            let mut hba = FakeHba::new(1);
            hba.attach(0, dev);
            let mut ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
            assert_eq!(ahci.take_disk(0).err(), Some(AhciError::Unsupported));
            assert_eq!(ahci.device(0), None, "the port is gone");
            assert_eq!(dma.live.get(), 0, "and its memory freed");
            fake::with(|f| assert_eq!(f.port_reg(0, CMD) & (CMD_ST | CMD_FRE), 0));
            drop(ahci);
            fake::uninstall();
        }
    }

    #[test]
    fn read_write_and_flush() {
        let original = pattern(SECTORS as usize * 512, 1);
        let new = pattern(1024, 99);
        let (log, disk) = with_disk(
            FakeDev::disk(SECTORS, 512).with_data(original.clone()),
            |_| {},
            |d| {
                let mut buf = [0u8; 1024];
                d.read_blocks(10, &mut buf).unwrap();
                assert_eq!(buf[..], original[10 * 512..12 * 512]);
                d.write_blocks(20, &new).unwrap();
                d.read_blocks(20, &mut buf).unwrap();
                assert_eq!(buf[..], new[..]);
                d.flush().unwrap();
                d.read_blocks(0, &mut []).unwrap();
            },
        );
        let cmd = |command, lba, count, bytes| Cmd { command, lba, count, bytes };
        assert_eq!(
            log[1..],
            [
                cmd(READ_DMA_EXT, 10, 2, 1024),
                cmd(WRITE_DMA_EXT, 20, 2, 1024),
                cmd(READ_DMA_EXT, 20, 2, 1024),
                cmd(FLUSH_CACHE_EXT, 0, 0, 0)
            ]
        );
        assert_eq!(disk[20 * 512..22 * 512], new[..]);
        assert_eq!(disk[..20 * 512], original[..20 * 512], "nothing else touched");
    }

    #[test]
    fn large_transfers_are_split() {
        for sector_size in [512, 4096] {
            let sectors = (400 * 512 / sector_size) as u64; // 200 KiB
            let data = pattern(400 * 512, 5);
            let (log, disk) = with_disk(
                FakeDev::disk(sectors, sector_size),
                |_| {},
                |d| {
                    d.write_blocks(0, &data).unwrap();
                    let mut back = vec![0u8; data.len()];
                    d.read_blocks(0, &mut back).unwrap();
                    assert!(back == data);
                },
            );
            assert!(disk == data);
            let chunk = DATA_LEN / sector_size;
            let of = |c| {
                log.iter().filter(|r| r.command == c).map(|r| (r.lba as usize, r.count as usize)).collect::<Vec<_>>()
            };
            let last = sectors as usize - 3 * chunk;
            let expected = [(0, chunk), (chunk, chunk), (2 * chunk, chunk), (3 * chunk, last)];
            assert_eq!(of(WRITE_DMA_EXT), expected);
            assert_eq!(of(READ_DMA_EXT), expected);
            assert_eq!(log.last().unwrap().bytes as usize, 400 * 512 - 3 * DATA_LEN, "short last chunk");
        }
    }

    #[test]
    fn device_errors_recover_the_port() {
        // The device frees the task file itself; holds it (BSY) for CLO to
        // override; or holds it on an HBA without CLO, needing a COMRESET.
        for (holds_bsy, clo) in [(false, false), (true, true), (true, false)] {
            let setup = |f: &mut FakeHba| {
                f.ports[0].fail_from = 6;
                f.ports[0].fail_flush = true;
                f.ports[0].busy_after_error = holds_bsy;
                if !clo {
                    f.cap &= !cap::SCLO;
                }
            };
            let (log, _) = with_disk(FakeDev::disk(8, 512), setup, |d| {
                let mut buf = [0u8; 512];
                assert_eq!(d.read_blocks(6, &mut buf), Err(BlockError::Io));
                assert_eq!(d.write_blocks(7, &buf), Err(BlockError::Io));
                assert_eq!(d.flush(), Err(BlockError::Io));
                // The port recovers: later commands still work.
                assert_eq!(d.read_blocks(5, &mut buf), Ok(()));
                fake::with(|f| {
                    let p = &f.ports[0];
                    assert_eq!(p.starts, 4, "restarted after each error");
                    assert_eq!(
                        (p.clos, p.comresets),
                        if !holds_bsy {
                            (0, 0)
                        } else if clo {
                            (3, 0)
                        } else {
                            (0, 3)
                        }
                    );
                    assert_eq!(f.port_reg(0, SERR), 0);
                });

                assert_eq!(d.read_blocks(8, &mut buf), Err(BlockError::OutOfRange));
                assert_eq!(d.write_blocks(7, &[0; 1024]), Err(BlockError::OutOfRange));
                assert_eq!(d.read_blocks(u64::MAX, &mut buf), Err(BlockError::OutOfRange));
                assert_eq!(d.read_blocks(0, &mut [0; 100]), Err(BlockError::BadBuffer));
            });
            assert_eq!(log.len(), 5, "IDENTIFY and four commands; rejected ones never reach the disk");
        }
    }

    #[test]
    fn a_command_that_never_finishes_times_out() {
        with_disk(
            FakeDev::disk(8, 512),
            |_| {},
            |d| {
                let mut buf = [0u8; 512];
                fake::with(|f| f.ports[0].hang = true);
                assert_eq!(d.read_blocks(0, &mut buf), Err(BlockError::Io));
                fake::with(|f| f.ports[0].hang = false);
                assert_eq!(d.read_blocks(0, &mut buf), Ok(()));
            },
        );
    }

    #[test]
    fn identify_needs_valid_word_83_and_48_bit_lbas() {
        // LBA48 set, but bits 15:14 do not say the word is valid.
        for w83 in [ID_LBA48, 0xc000 | ID_LBA48] {
            let dma = HostDma::default();
            let mut hba = FakeHba::new(1);
            hba.attach(0, FakeDev::disk(SECTORS, 512));
            hba.ports[0].identify_words = vec![(ID_COMMAND_SETS, w83)];
            let mut ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
            assert_eq!(ahci.take_disk(0).err(), Some(AhciError::Unsupported), "word 83 {w83:#x}");
            drop(ahci);
            fake::uninstall();
        }

        // Words 100–103 count past what a 48-bit LBA reaches.
        for sectors in [(1 << 48) + 1, u64::MAX] {
            let (log, _) = with_disk(
                FakeDev::disk(sectors, 512),
                |_| {},
                |d| {
                    assert_eq!(d.num_blocks(), 1 << 48);
                    let mut buf = [0u8; 512];
                    assert_eq!(d.read_blocks(1 << 48, &mut buf), Err(BlockError::OutOfRange));
                },
            );
            assert_eq!(log.len(), 1, "nothing past IDENTIFY reaches the disk");
        }
    }

    /// QEMU never fills in the byte count of a queued command; that is not
    /// a short transfer, while a different non-zero count still is.
    #[test]
    fn queued_reads_without_a_byte_count_succeed() {
        let data = pattern(8 * 512, 9);
        with_disk(
            FakeDev::disk(8, 512).with_data(data.clone()).with_ncq(4),
            |hba| hba.ports[0].ncq_no_prdbc = true,
            |d| {
                let mut buf = [0u8; 1024];
                d.read_blocks(2, &mut buf).unwrap();
                assert_eq!(buf[..], data[2 * 512..4 * 512]);
                fake::with(|f| f.ports[0].ncq_no_prdbc = false);
                fake::with(|f| f.ports[0].short_by = 512);
                assert_eq!(d.read_blocks(2, &mut buf), Err(BlockError::Io), "a short count is still caught");
            },
        );
    }

    #[test]
    fn short_reads_fail() {
        let data = pattern(8 * 512, 3);
        let (log, _) = with_disk(
            FakeDev::disk(8, 512).with_data(data.clone()),
            |_| {},
            |d| {
                let mut buf = [0u8; 1024];
                d.read_blocks(0, &mut buf).unwrap();
                fake::with(|f| f.ports[0].short_by = 512);
                // The bounce buffer still holds sectors 0–1 past the first
                // 512 bytes; none of that may come back as sector 3.
                assert_eq!(d.read_blocks(2, &mut buf), Err(BlockError::Io));
                fake::with(|f| assert_eq!(f.ports[0].starts, 2, "recovered"));
                // Writes are not checked.
                assert_eq!(d.write_blocks(4, &data[..512]), Ok(()));
                fake::with(|f| f.ports[0].short_by = 0);
                d.read_blocks(2, &mut buf).unwrap();
                assert_eq!(buf[..], data[2 * 512..4 * 512]);
            },
        );
        assert_eq!(log.len(), 5);

        let dma = HostDma::default();
        let mut hba = FakeHba::new(1);
        hba.attach(0, FakeDev::disk(8, 512));
        hba.ports[0].short_by = 2;
        let mut ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
        assert_eq!(ahci.take_disk(0).err(), Some(AhciError::ShortTransfer), "short IDENTIFY");
        drop(ahci);
        fake::uninstall();
    }

    #[test]
    fn a_port_that_cannot_recover_is_broken() {
        let dma = HostDma::default();
        let mut hba = FakeHba::new(1);
        hba.attach(0, FakeDev::disk(8, 512));
        let mut ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
        let mut d = ahci.take_disk(0).unwrap();
        let mut buf = [0u8; 512];
        // The command never finishes and the engine will not stop, so the
        // HBA may still be running it.
        fake::with(|f| (f.ports[0].hang, f.ports[0].wont_stop) = (true, true));
        assert_eq!(d.read_blocks(0, &mut buf), Err(BlockError::Io));
        let (slot0, commands) = fake::with(|f| (f.slot0(0), f.log.len()));
        assert_eq!(d.write_blocks(1, &[0x55; 512]), Err(BlockError::Io));
        assert_eq!(d.read_blocks(2, &mut buf), Err(BlockError::Io));
        assert_eq!(d.flush(), Err(BlockError::Io));
        // Even once the HBA settles down, the port stays broken.
        fake::with(|f| f.ports[0].hang = false);
        assert_eq!(d.read_blocks(2, &mut buf), Err(BlockError::Io));
        fake::with(|f| {
            assert_eq!(f.slot0(0), slot0, "command table and bounce buffer untouched");
            assert_eq!(f.log.len(), commands, "nothing more issued");
        });
        drop((d, ahci));
        assert_eq!(dma.live.get(), 2, "port memory and bounce buffer leaked, not freed under the HBA");
        fake::uninstall();
    }

    #[test]
    fn comreset_is_held_for_a_millisecond() {
        let dma = HostDma::default();
        let mut hba = FakeHba::new(1);
        hba.cap &= !cap::SCLO;
        hba.attach(0, FakeDev::disk(8, 512));
        hba.ports[0].fail_from = 0;
        hba.ports[0].busy_after_error = true;
        let mut ahci = Ahci::new(fake::install(hba), &dma, Some(&FakeClock)).unwrap();
        let mut d = ahci.take_disk(0).unwrap();
        assert_eq!(d.read_blocks(0, &mut [0; 512]), Err(BlockError::Io));
        fake::with(|f| {
            assert_eq!(f.ports[0].comresets, 1);
            assert!(f.ports[0].comreset_held_ns.unwrap() >= 1_000_000);
        });
        drop((d, ahci));
        fake::uninstall();
    }

    #[test]
    fn disks_outlive_the_hba() {
        let dma = HostDma::default();
        let mut hba = FakeHba::new(2);
        hba.attach(0, FakeDev::disk(8, 512));
        hba.attach(1, FakeDev::disk(16, 512));
        let mut ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
        let mut a = ahci.take_disk(0).unwrap();
        assert_eq!(ahci.take_disk(0).err(), Some(AhciError::NoDevice), "taken");
        let mut b = ahci.take_disk(1).unwrap();
        assert_eq!(dma.live.get(), 4, "each disk: port memory and bounce buffer");
        drop(ahci);
        assert_eq!(dma.live.get(), 4);
        a.write_blocks(1, &[1; 512]).unwrap();
        b.write_blocks(15, &[2; 512]).unwrap();
        drop(a);
        assert_eq!(dma.live.get(), 2);
        fake::with(|f| assert_eq!(f.port_reg(0, CMD) & (CMD_ST | CMD_FRE), 0, "port 0 stopped"));
        let mut buf = [0u8; 512];
        b.read_blocks(15, &mut buf).unwrap();
        assert_eq!(buf, [2; 512]);
        drop(b);
        assert_eq!(dma.live.get(), 0);
        fake::uninstall();
    }
}
