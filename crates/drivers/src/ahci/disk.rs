//! A SATA disk on one AHCI port.

use osmium_hal::block::{BlockDevice, BlockError};
use osmium_hal::dma::{DmaAllocator, OwnedDma};

use super::AhciError;
use super::port::{Command, Port};

/// Bytes of DMA bounce buffer per disk, and so the most one command
/// transfers.
pub const DATA_LEN: usize = 64 * 1024;

// ATA commands.
pub(super) const IDENTIFY_DEVICE: u8 = 0xec;
pub(super) const READ_DMA_EXT: u8 = 0x25;
pub(super) const WRITE_DMA_EXT: u8 = 0x35;
pub(super) const FLUSH_CACHE_EXT: u8 = 0xea;

/// The device register for commands that take an LBA.
pub(super) const DEVICE_LBA: u8 = 0x40;

const IDENTIFY_LEN: usize = 512;
const SECTOR_SIZE: usize = 512;

// IDENTIFY DEVICE words.
const ID_SERIAL: usize = 10;
const ID_MODEL: usize = 27;
const ID_COMMAND_SETS: usize = 83;
const ID_LBA48: u16 = 1 << 10;
const ID_MAX_LBA48: usize = 100;
const ID_SECTOR_SIZES: usize = 106;
const ID_LOGICAL_SECTOR: usize = 117;

/// A SATA disk, addressed in logical sectors with 48-bit LBAs. It owns its
/// port; dropping it stops the port and frees its memory.
pub struct AhciDisk<'d, D: DmaAllocator + ?Sized> {
    port: Port<'d, D>,
    sectors: u64,
    sector_size: usize,
    model: [u8; 40],
    serial: [u8; 20],
}

impl<'d, D: DmaAllocator + ?Sized> AhciDisk<'d, D> {
    /// Gives `port` a bounce buffer from `dma` and identifies its disk.
    pub(super) fn new(mut port: Port<'d, D>, dma: &'d D) -> Result<Self, AhciError> {
        port.set_data(OwnedDma::new(dma, DATA_LEN).ok_or(AhciError::NoMemory)?)?;
        let cmd = Command { command: IDENTIFY_DEVICE, lba: 0, count: 0, device: 0, len: IDENTIFY_LEN, write: false };
        port.exec(cmd)?;
        let mut id = [0u8; IDENTIFY_LEN];
        port.data().read(0, &mut id);
        let word = |i: usize| u16::from_le_bytes([id[2 * i], id[2 * i + 1]]);

        if word(ID_COMMAND_SETS) & ID_LBA48 == 0 {
            return Err(AhciError::Unsupported);
        }
        let sectors = (0..4).fold(0u64, |n, i| n | (word(ID_MAX_LBA48 + i) as u64) << (16 * i));
        // Word 106 is valid when bits 15:14 are 01; bit 12 says words
        // 117–118 hold the logical sector size, in words.
        let sizes = word(ID_SECTOR_SIZES);
        let sector_size = if sizes & 0xc000 == 0x4000 && sizes & 1 << 12 != 0 {
            2 * (word(ID_LOGICAL_SECTOR) as usize | (word(ID_LOGICAL_SECTOR + 1) as usize) << 16)
        } else {
            SECTOR_SIZE
        };
        if !sector_size.is_power_of_two() || !(SECTOR_SIZE..=DATA_LEN).contains(&sector_size) {
            return Err(AhciError::Unsupported);
        }
        // ATA strings hold two characters per word, high byte first.
        let string = |first: usize, out: &mut [u8]| {
            for (i, pair) in out.chunks_mut(2).enumerate() {
                pair.copy_from_slice(&word(first + i).to_be_bytes());
            }
        };
        let mut model = [0u8; 40];
        let mut serial = [0u8; 20];
        string(ID_MODEL, &mut model);
        string(ID_SERIAL, &mut serial);
        Ok(Self { port, sectors, sector_size, model, serial })
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
        let cmd = Command { command, lba, count, device: DEVICE_LBA, len, write };
        self.port.exec(cmd).map_err(|_| BlockError::Io)
    }
}

/// `s` without leading and trailing spaces and NULs, or `""` if it is
/// not text.
fn trim(s: &[u8]) -> &str {
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
        for (i, chunk) in buf.chunks_mut(DATA_LEN).enumerate() {
            let sector = lba + (i * DATA_LEN / self.sector_size) as u64;
            self.transfer(READ_DMA_EXT, sector, chunk.len(), false)?;
            self.port.data().read(0, chunk);
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        for (i, chunk) in buf.chunks(DATA_LEN).enumerate() {
            let sector = lba + (i * DATA_LEN / self.sector_size) as u64;
            self.port.data().write(0, chunk);
            self.transfer(WRITE_DMA_EXT, sector, chunk.len(), true)?;
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
    use super::super::fake::{self, Cmd, FakeDev, FakeHba};
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
        let mut ahci = Ahci::new(fake::install(hba), &dma).unwrap();
        let mut disk = ahci.take_disk(0).unwrap();
        body(&mut disk);
        drop((disk, ahci));
        assert_eq!(dma.live.get(), 0);
        let hba = fake::uninstall();
        let FakeDev::Disk { data, .. } = &hba.ports[0].dev.as_ref().unwrap() else { unreachable!() };
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
            let mut ahci = Ahci::new(fake::install(hba), &dma).unwrap();
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
    fn disks_outlive_the_hba() {
        let dma = HostDma::default();
        let mut hba = FakeHba::new(2);
        hba.attach(0, FakeDev::disk(8, 512));
        hba.attach(1, FakeDev::disk(16, 512));
        let mut ahci = Ahci::new(fake::install(hba), &dma).unwrap();
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
