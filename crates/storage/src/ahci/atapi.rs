//! An ATAPI packet device (an optical drive) on one AHCI port, as a
//! read-only block device.

use osmium_hal::block::{BlockDevice, BlockError};
use osmium_hal::dma::{DmaAllocator, OwnedDma};

use super::AhciError;
use super::disk::{DATA_LEN, IDENTIFY_PACKET_DEVICE};
use super::port::{Command, Port};

/// The ATA PACKET command.
pub(super) const PACKET: u8 = 0xa0;

// SCSI commands, as ATAPI carries them.
pub(super) const TEST_UNIT_READY: u8 = 0x00;
pub(super) const REQUEST_SENSE: u8 = 0x03;
pub(super) const READ_CAPACITY_10: u8 = 0x25;
pub(super) const READ_10: u8 = 0x28;

const IDENTIFY_LEN: usize = 512;
const SENSE_LEN: usize = 18;
const CAPACITY_LEN: usize = 8;
/// The additional sense code, in the sense data: medium not present.
const SENSE_ASC: usize = 12;
const ASC_NO_MEDIUM: u8 = 0x3a;

// IDENTIFY PACKET DEVICE words.
const ID_GENERAL: usize = 0;
const ID_SERIAL: usize = 10;
const ID_MODEL: usize = 27;
const ID_CAPABILITIES: usize = 49;
const ID_DMA: u16 = 1 << 8;
/// Word 0 bits 15:14: 10 is an ATAPI device.
const GENERAL_PROTOCOL_MASK: u16 = 0xc000;
const GENERAL_ATAPI: u16 = 0x8000;
/// Word 0 bits 12:8: the SCSI peripheral device type; 5 is CD/DVD.
const GENERAL_TYPE_MASK: u16 = 0x1f00;
const TYPE_OPTICAL: u16 = 5 << 8;

/// An optical drive on an AHCI port, addressed in the logical blocks of its
/// medium (2048 bytes for a CD-ROM or DVD) and read-only: writes fail with
/// [`BlockError::ReadOnly`]. It owns its port; dropping it stops the port
/// and frees its memory.
///
/// Reads use the SCSI READ(10) command, in PACKET commands with DMA if the
/// drive has it. A drive with no disc in it reports 0 blocks; call
/// [`reload`](Self::reload) after the medium changes, which is also how a
/// disc inserted later gets noticed. Hand it to `osmium_fs_iso9660` like
/// any other block device.
pub struct AhciAtapi<'d, D: DmaAllocator + ?Sized> {
    port: Port<'d, D>,
    blocks: u64,
    block_size: usize,
    dma: bool,
    model: [u8; 40],
    serial: [u8; 20],
}

impl<'d, D: DmaAllocator + ?Sized> AhciAtapi<'d, D> {
    /// Gives `port` a bounce buffer from `dma`, identifies the drive and
    /// reads the medium's size.
    pub(super) fn new(mut port: Port<'d, D>, dma: &'d D) -> Result<Self, AhciError> {
        port.set_data(OwnedDma::new(dma, DATA_LEN).ok_or(AhciError::NoMemory)?)?;
        port.exec(Command { command: IDENTIFY_PACKET_DEVICE, len: IDENTIFY_LEN, ..Command::default() })?;
        let mut id = [0u8; IDENTIFY_LEN];
        port.data()?.read(0, &mut id);
        let word = |i: usize| id.get(2 * i..).and_then(|b| b.first_chunk::<2>()).map_or(0, |&b| u16::from_le_bytes(b));

        let general = word(ID_GENERAL);
        // Only optical drives are handled. Packets are built 16 bytes long,
        // zero padded, which serves devices that take 12 or 16.
        if general & GENERAL_PROTOCOL_MASK != GENERAL_ATAPI || general & GENERAL_TYPE_MASK != TYPE_OPTICAL {
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
        let dma_ok = word(ID_CAPABILITIES) & ID_DMA != 0;
        let mut drive = Self { port, blocks: 0, block_size: 2048, dma: dma_ok, model, serial };
        drive.reload()?;
        Ok(drive)
    }

    /// The port the drive is on.
    pub fn port(&self) -> u8 {
        self.port.index()
    }

    /// The model, from IDENTIFY PACKET DEVICE, without its padding.
    pub fn model(&self) -> &str {
        super::disk::trim(&self.model)
    }

    /// The serial number, from IDENTIFY PACKET DEVICE, without its padding.
    pub fn serial(&self) -> &str {
        super::disk::trim(&self.serial)
    }

    /// Runs one SCSI command from the drive: `len` bytes of its data into
    /// the bounce buffer at 0 (for `len` 0, none).
    fn packet(&mut self, cdb: &[u8], len: usize) -> Result<(), AhciError> {
        let mut packet = [0u8; 16];
        for (dst, src) in packet.iter_mut().zip(cdb) {
            *dst = *src;
        }
        let cmd = Command {
            command: PACKET,
            // Features bit 0: the data moves by DMA. The byte count limit
            // (LBA bits 23:8) is what a PIO drive moves per DRQ block; the
            // HBA reassembles them.
            features: self.dma as u16,
            lba: (len.min(0xfffe) as u64) << 8,
            len,
            packet: Some(packet),
            ..Command::default()
        };
        self.port.exec(cmd)
    }

    /// Reads the medium's size again, after a disc change. With no disc (or
    /// one that is not ready), the drive has 0 blocks.
    pub fn reload(&mut self) -> Result<(), AhciError> {
        self.blocks = 0;
        // A disc that was just inserted or swapped answers its first
        // commands with a "unit attention" check condition, cleared by
        // REQUEST SENSE; a spinning-up one with "not ready". An empty tray
        // is "medium not present", which retrying will not change.
        for _ in 0..4 {
            match self.packet(&[TEST_UNIT_READY, 0, 0, 0, 0, 0], 0) {
                Ok(()) => break,
                Err(AhciError::Device { .. }) => {
                    match self.packet(&[REQUEST_SENSE, 0, 0, 0, SENSE_LEN as u8, 0], SENSE_LEN) {
                        Ok(()) => {
                            let mut sense = [0u8; SENSE_LEN];
                            self.port.data()?.read(0, &mut sense);
                            if sense[SENSE_ASC] == ASC_NO_MEDIUM {
                                return Ok(());
                            }
                        }
                        Err(AhciError::Device { .. }) => {}
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => return Err(e),
            }
        }
        match self.packet(&[READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], CAPACITY_LEN) {
            Ok(()) => {}
            // No medium: nothing to read.
            Err(AhciError::Device { .. }) => return Ok(()),
            Err(e) => return Err(e),
        }
        let mut cap = [0u8; CAPACITY_LEN];
        self.port.data()?.read(0, &mut cap);
        let last = u32::from_be_bytes([cap[0], cap[1], cap[2], cap[3]]);
        let size = u32::from_be_bytes([cap[4], cap[5], cap[6], cap[7]]) as usize;
        if !size.is_power_of_two() || !(512..=DATA_LEN).contains(&size) {
            return Err(AhciError::Unsupported);
        }
        // The last LBA plus one, which can reach 2^32.
        self.blocks = last as u64 + 1;
        self.block_size = size;
        Ok(())
    }
}

impl<D: DmaAllocator + ?Sized> BlockDevice for AhciAtapi<'_, D> {
    fn block_size(&self) -> usize {
        self.block_size
    }

    fn num_blocks(&self) -> u64 {
        self.blocks
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let per_command = DATA_LEN / self.block_size;
        for (i, chunk) in buf.chunks_mut(per_command * self.block_size).enumerate() {
            // READ(10) has 32-bit LBAs, and check_range kept it inside the
            // medium whose last LBA is 32 bits.
            let first = u32::try_from(lba + (i * per_command) as u64).map_err(|_| BlockError::OutOfRange)?;
            let count = (chunk.len() / self.block_size) as u16;
            let mut cdb = [0u8; 10];
            cdb[0] = READ_10;
            cdb[2..6].copy_from_slice(&first.to_be_bytes());
            cdb[7..9].copy_from_slice(&count.to_be_bytes());
            self.packet(&cdb, chunk.len()).map_err(|_| BlockError::Io)?;
            self.port.data().map_err(|_| BlockError::Io)?.read(0, chunk);
        }
        Ok(())
    }

    fn write_blocks(&mut self, _lba: u64, _buf: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
}
