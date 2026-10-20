//! USB mass storage: SCSI over Bulk-Only Transport (class 08/06/50), as
//! used by USB sticks, card readers and external drives.
//!
//! Each command is a Command Block Wrapper on the bulk OUT endpoint, an
//! optional data stage, and a Command Status Wrapper on the bulk IN
//! endpoint (BOT 1.0 §5). Stalls are cleared and the status still read;
//! a malformed status triggers Reset Recovery (§5.3.4).

use osmium_hal::block::{BlockDevice, BlockError};
use osmium_hal::usb::{
    DeviceId, Direction, Recipient, RequestKind, SetupPacket, TransferType, UsbError, UsbHost, find_interface,
};

const CBW_SIGNATURE: &[u8; 4] = b"USBC";
const CSW_SIGNATURE: &[u8; 4] = b"USBS";
const GET_MAX_LUN: u8 = 0xfe;
const BULK_ONLY_RESET: u8 = 0xff;

const TEST_UNIT_READY: u8 = 0x00;
const REQUEST_SENSE: u8 = 0x03;
const INQUIRY: u8 = 0x12;
const READ_CAPACITY_10: u8 = 0x25;
const READ_10: u8 = 0x28;
const WRITE_10: u8 = 0x2a;
const SYNCHRONIZE_CACHE_10: u8 = 0x35;

/// Bytes moved by one READ(10)/WRITE(10) at most.
const MAX_COMMAND_BYTES: usize = 64 * 1024;

/// Why a mass-storage command failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// The transport failed.
    Usb(UsbError),
    /// The device reported the command failed, with this SCSI sense key
    /// (2 = not ready, 3 = medium error, 5 = illegal request, 6 = unit
    /// attention, 7 = write protected).
    Failed {
        /// Sense key from REQUEST SENSE (0 if that failed too).
        sense_key: u8,
    },
    /// The device's status made no sense; it was reset.
    Phase,
    /// The device has no mass-storage (Bulk-Only, SCSI) interface.
    NotMassStorage,
}

impl From<UsbError> for StorageError {
    fn from(e: UsbError) -> Self {
        StorageError::Usb(e)
    }
}

/// Identification from SCSI INQUIRY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inquiry {
    /// Peripheral device type (0 = direct access block device).
    pub device_type: u8,
    /// Removable medium.
    pub removable: bool,
    /// Vendor, space padded.
    pub vendor: [u8; 8],
    /// Product, space padded.
    pub product: [u8; 16],
}

impl Inquiry {
    /// The vendor without padding (or "?" if not ASCII).
    pub fn vendor(&self) -> &str {
        trimmed(&self.vendor)
    }

    /// The product without padding (or "?" if not ASCII).
    pub fn product(&self) -> &str {
        trimmed(&self.product)
    }
}

fn trimmed(b: &[u8]) -> &str {
    core::str::from_utf8(b).map(str::trim_end).unwrap_or("?")
}

enum Data<'a> {
    None,
    In(&'a mut [u8]),
    Out(&'a [u8]),
}

/// A USB mass-storage device, as a [`BlockDevice`].
pub struct UsbStorage<H: UsbHost> {
    host: H,
    dev: DeviceId,
    interface: u8,
    bulk_in: u8,
    bulk_out: u8,
    lun: u8,
    tag: u32,
    block_size: usize,
    blocks: u64,
}

impl<H: UsbHost> UsbStorage<H> {
    /// Drives LUN 0 of the enumerated device `dev`, whose configuration
    /// descriptor set is `config`. Waits for the medium to become ready and
    /// reads its capacity.
    pub fn new(host: H, dev: DeviceId, config: &[u8]) -> Result<Self, StorageError> {
        let iface = find_interface(config, |i| i.class == 8 && i.subclass == 6 && i.protocol == 0x50)
            .ok_or(StorageError::NotMassStorage)?;
        let bulk_in = iface.endpoint(TransferType::Bulk, Direction::In).ok_or(StorageError::NotMassStorage)?;
        let bulk_out = iface.endpoint(TransferType::Bulk, Direction::Out).ok_or(StorageError::NotMassStorage)?;
        let mut s = Self {
            host,
            dev,
            interface: iface.descriptor.number,
            bulk_in: bulk_in.address,
            bulk_out: bulk_out.address,
            lun: 0,
            tag: 0,
            block_size: 0,
            blocks: 0,
        };

        // Devices with one LUN may stall GET MAX LUN; either way we use LUN 0.
        let mut max_lun = [0u8];
        let req = SetupPacket::new(
            Direction::In,
            RequestKind::Class,
            Recipient::Interface,
            GET_MAX_LUN,
            0,
            s.interface as u16,
            1,
        );
        let _ = s.host.control_in(dev, req, &mut max_lun);

        // The first commands after power-on report UNIT ATTENTION.
        let mut ready = Err(StorageError::Phase);
        for _ in 0..5 {
            ready = s.command(&[TEST_UNIT_READY, 0, 0, 0, 0, 0], Data::None);
            if ready.is_ok() {
                break;
            }
        }
        ready?;

        let mut cap = [0u8; 8];
        s.command(&[READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::In(&mut cap))?;
        let last = u32::from_be_bytes(cap[0..4].try_into().unwrap());
        s.block_size = u32::from_be_bytes(cap[4..8].try_into().unwrap()) as usize;
        s.blocks = last as u64 + 1;
        if s.block_size == 0 || s.block_size > MAX_COMMAND_BYTES {
            return Err(StorageError::Phase);
        }
        Ok(s)
    }

    /// The device handle.
    pub fn device(&self) -> DeviceId {
        self.dev
    }

    /// Identifies the device.
    pub fn inquiry(&mut self) -> Result<Inquiry, StorageError> {
        let mut d = [0u8; 36];
        self.command(&[INQUIRY, 0, 0, 0, 36, 0], Data::In(&mut d))?;
        Ok(Inquiry {
            device_type: d[0] & 0x1f,
            removable: d[1] & 0x80 != 0,
            vendor: d[8..16].try_into().unwrap(),
            product: d[16..32].try_into().unwrap(),
        })
    }

    fn clear_halt(&mut self, endpoint: u8) {
        let _ = self.host.control_out(self.dev, SetupPacket::clear_halt(endpoint), &[]);
    }

    /// BOT Reset Recovery: a Bulk-Only Mass Storage Reset, then clear both
    /// endpoints.
    fn reset_recovery(&mut self) {
        let req = SetupPacket::new(
            Direction::Out,
            RequestKind::Class,
            Recipient::Interface,
            BULK_ONLY_RESET,
            0,
            self.interface as u16,
            0,
        );
        let _ = self.host.control_out(self.dev, req, &[]);
        self.clear_halt(self.bulk_in);
        self.clear_halt(self.bulk_out);
    }

    fn sense_key(&mut self) -> u8 {
        let mut sense = [0u8; 18];
        match self.transport(&[REQUEST_SENSE, 0, 0, 0, 18, 0], Data::In(&mut sense)) {
            Ok(0) => sense[2] & 0xf,
            _ => 0,
        }
    }

    /// Runs a SCSI command; on a failed status, fetches the sense key.
    fn command(&mut self, cb: &[u8], data: Data<'_>) -> Result<(), StorageError> {
        match self.transport(cb, data)? {
            0 => Ok(()),
            _ => Err(StorageError::Failed { sense_key: self.sense_key() }),
        }
    }

    /// One CBW, data stage, CSW exchange; returns the CSW status (0 passed,
    /// 1 failed).
    fn transport(&mut self, cb: &[u8], data: Data<'_>) -> Result<u8, StorageError> {
        self.tag = self.tag.wrapping_add(1);
        let (len, flags) = match &data {
            Data::None => (0, 0),
            Data::In(b) => (b.len(), 0x80),
            Data::Out(b) => (b.len(), 0),
        };
        let mut cbw = [0u8; 31];
        cbw[0..4].copy_from_slice(CBW_SIGNATURE);
        cbw[4..8].copy_from_slice(&self.tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(len as u32).to_le_bytes());
        cbw[12] = flags;
        cbw[13] = self.lun;
        cbw[14] = cb.len() as u8;
        cbw[15..15 + cb.len()].copy_from_slice(cb);
        if let Err(e) = self.host.transfer_out(self.dev, self.bulk_out, &cbw) {
            self.reset_recovery();
            return Err(e.into());
        }

        // A stalled data stage still ends with a status (§6.7.2, §6.7.3).
        let stage = match data {
            Data::None => Ok(()),
            Data::In(b) => self.host.transfer_in(self.dev, self.bulk_in, b).map(drop),
            Data::Out(b) => self.host.transfer_out(self.dev, self.bulk_out, b),
        };
        match stage {
            Ok(()) => {}
            Err(UsbError::Stall) => {
                let ep = if flags != 0 { self.bulk_in } else { self.bulk_out };
                self.clear_halt(ep);
            }
            Err(e) => {
                self.reset_recovery();
                return Err(e.into());
            }
        }

        let mut csw = [0u8; 13];
        let mut got = self.host.transfer_in(self.dev, self.bulk_in, &mut csw);
        if got == Err(UsbError::Stall) {
            self.clear_halt(self.bulk_in);
            got = self.host.transfer_in(self.dev, self.bulk_in, &mut csw);
        }
        let valid = got == Ok(13) && &csw[0..4] == CSW_SIGNATURE && csw[4..8] == cbw[4..8] && csw[12] <= 1;
        if !valid {
            self.reset_recovery();
            return Err(StorageError::Phase);
        }
        Ok(csw[12])
    }

    fn rw_command(op: u8, lba: u64, blocks: usize) -> [u8; 10] {
        let lba = (lba as u32).to_be_bytes();
        let n = (blocks as u16).to_be_bytes();
        [op, 0, lba[0], lba[1], lba[2], lba[3], 0, n[0], n[1], 0]
    }

    fn chunk_blocks(&self) -> usize {
        (MAX_COMMAND_BYTES / self.block_size).max(1)
    }
}

fn block_error(e: StorageError) -> BlockError {
    match e {
        StorageError::Failed { sense_key: 7 } => BlockError::ReadOnly,
        _ => BlockError::Io,
    }
}

impl<H: UsbHost> BlockDevice for UsbStorage<H> {
    fn block_size(&self) -> usize {
        self.block_size
    }

    fn num_blocks(&self) -> u64 {
        self.blocks
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        if lba + (buf.len() / self.block_size) as u64 > u32::MAX as u64 {
            return Err(BlockError::OutOfRange); // READ(10) addresses 32 bits
        }
        let step = self.chunk_blocks();
        for (i, chunk) in buf.chunks_mut(step * self.block_size).enumerate() {
            let at = lba + (i * step) as u64;
            let cb = Self::rw_command(READ_10, at, chunk.len() / self.block_size);
            self.command(&cb, Data::In(chunk)).map_err(block_error)?;
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        if lba + (buf.len() / self.block_size) as u64 > u32::MAX as u64 {
            return Err(BlockError::OutOfRange);
        }
        let step = self.chunk_blocks();
        for (i, chunk) in buf.chunks(step * self.block_size).enumerate() {
            let at = lba + (i * step) as u64;
            let cb = Self::rw_command(WRITE_10, at, chunk.len() / self.block_size);
            self.command(&cb, Data::Out(chunk)).map_err(block_error)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), BlockError> {
        match self.command(&[SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], Data::None) {
            // Many sticks have no cache and reject the command.
            Ok(()) | Err(StorageError::Failed { sense_key: 5 }) => Ok(()),
            Err(e) => Err(block_error(e)),
        }
    }
}

#[cfg(test)]
// Tests drop drivers explicitly to end their borrow of the fake device.
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use osmium_hal::usb::{EndpointDescriptor, PortStatus};
    use std::vec::Vec;

    const CONFIG: [u8; 32] = [
        9, 2, 32, 0, 1, 1, 0, 0x80, 50, //
        9, 4, 0, 0, 2, 8, 6, 0x50, 0, //
        7, 5, 0x81, 2, 0x00, 0x02, 0, //
        7, 5, 0x02, 2, 0x00, 0x02, 0,
    ];

    /// Where the fake is in the CBW, data, CSW sequence.
    enum Phase {
        Idle,
        DataIn(Vec<u8>),
        DataOut([u8; 31]),
        Status(u8),
    }

    /// A Bulk-Only stick backed by memory, speaking just enough SCSI.
    struct FakeStick {
        disk: Vec<u8>,
        phase: Phase,
        tag: [u8; 4],
        /// The next command with this opcode fails with this sense key.
        fail_next: Option<(u8, u8)>,
        sense: u8,
        /// Stall the next data stage.
        stall_data: bool,
        halted: bool,
        commands: Vec<u8>,
        resets: usize,
    }

    impl FakeStick {
        fn new(blocks: usize) -> Self {
            Self {
                disk: (0..blocks * 512).map(|i| (i / 512) as u8).collect(),
                phase: Phase::Idle,
                tag: [0; 4],
                fail_next: Some((TEST_UNIT_READY, 6)), // unit attention
                sense: 0,
                stall_data: false,
                halted: false,
                commands: Vec::new(),
                resets: 0,
            }
        }

        fn range(cb: &[u8]) -> (usize, usize) {
            let lba = u32::from_be_bytes(cb[2..6].try_into().unwrap()) as usize;
            let n = u16::from_be_bytes(cb[7..9].try_into().unwrap()) as usize;
            (lba * 512, n * 512)
        }

        /// Starts a command from its CBW and returns the next phase.
        fn start(&mut self, cbw: [u8; 31]) -> Phase {
            self.tag = cbw[4..8].try_into().unwrap();
            let cb = &cbw[15..15 + cbw[14] as usize];
            self.commands.push(cb[0]);
            if let Some((op, key)) = self.fail_next
                && op == cb[0]
            {
                self.fail_next = None;
                self.sense = key;
                return Phase::Status(1);
            }
            let reply = match cb[0] {
                INQUIRY => {
                    let mut d = std::vec![0u8; 36];
                    d[1] = 0x80;
                    d[8..16].copy_from_slice(b"OSMIUM  ");
                    d[16..32].copy_from_slice(b"FAKE STICK      ");
                    d
                }
                READ_CAPACITY_10 => {
                    let last = (self.disk.len() / 512 - 1) as u32;
                    [last.to_be_bytes(), 512u32.to_be_bytes()].concat()
                }
                REQUEST_SENSE => {
                    let mut d = std::vec![0u8; 18];
                    d[0] = 0x70;
                    d[2] = self.sense;
                    d
                }
                READ_10 => {
                    let (off, len) = Self::range(cb);
                    self.disk[off..off + len].to_vec()
                }
                WRITE_10 => return Phase::DataOut(cbw),
                _ => return Phase::Status(0),
            };
            Phase::DataIn(reply)
        }

        /// Fails the data stage with a stall if one was requested.
        fn stalls(&mut self) -> bool {
            if !self.stall_data {
                return false;
            }
            self.stall_data = false;
            self.halted = true;
            self.sense = 3; // medium error
            true
        }
    }

    impl UsbHost for FakeStick {
        fn num_ports(&self) -> u8 {
            1
        }
        fn port_status(&self, _: u8) -> PortStatus {
            unimplemented!()
        }
        fn attach(&mut self, _: u8) -> Result<DeviceId, UsbError> {
            unimplemented!()
        }
        fn detach(&mut self, _: DeviceId) {}
        fn configure_endpoints(&mut self, _: DeviceId, _: &[EndpointDescriptor]) -> Result<(), UsbError> {
            Ok(())
        }
        fn control_in(&mut self, _: DeviceId, s: SetupPacket, _: &mut [u8]) -> Result<usize, UsbError> {
            assert_eq!(s.request, GET_MAX_LUN);
            Err(UsbError::Stall)
        }
        fn control_out(&mut self, _: DeviceId, s: SetupPacket, _: &[u8]) -> Result<(), UsbError> {
            match s.request {
                BULK_ONLY_RESET => self.resets += 1,
                _ => self.halted = false, // CLEAR_FEATURE(ENDPOINT_HALT)
            }
            Ok(())
        }
        fn transfer_in(&mut self, _: DeviceId, ep: u8, buf: &mut [u8]) -> Result<usize, UsbError> {
            assert_eq!(ep, 0x81);
            if self.halted {
                return Err(UsbError::Stall);
            }
            match core::mem::replace(&mut self.phase, Phase::Idle) {
                Phase::DataIn(_) if self.stalls() => {
                    self.phase = Phase::Status(1);
                    Err(UsbError::Stall)
                }
                Phase::DataIn(reply) => {
                    let n = reply.len().min(buf.len());
                    buf[..n].copy_from_slice(&reply[..n]);
                    self.phase = Phase::Status(0);
                    Ok(n)
                }
                Phase::Status(status) => {
                    buf[0..4].copy_from_slice(CSW_SIGNATURE);
                    buf[4..8].copy_from_slice(&self.tag);
                    buf[8..12].fill(0);
                    buf[12] = status;
                    Ok(13)
                }
                _ => panic!("IN transfer with no data or status pending"),
            }
        }
        fn transfer_out(&mut self, _: DeviceId, ep: u8, data: &[u8]) -> Result<(), UsbError> {
            assert_eq!(ep, 0x02);
            match core::mem::replace(&mut self.phase, Phase::Idle) {
                Phase::Idle => {
                    assert_eq!(&data[0..4], CBW_SIGNATURE);
                    self.phase = self.start(data.try_into().unwrap());
                    Ok(())
                }
                Phase::DataOut(_) if self.stalls() => {
                    self.phase = Phase::Status(1);
                    Err(UsbError::Stall)
                }
                Phase::DataOut(cbw) => {
                    let (off, len) = Self::range(&cbw[15..25]);
                    self.disk[off..off + len].copy_from_slice(&data[..len]);
                    self.phase = Phase::Status(0);
                    Ok(())
                }
                _ => panic!("OUT transfer during a data-in or status phase"),
            }
        }
        fn submit_in(&mut self, _: DeviceId, _: u8, _: usize) -> Result<(), UsbError> {
            unimplemented!()
        }
        fn poll_in(&mut self, _: DeviceId, _: u8, _: &mut [u8]) -> Option<Result<usize, UsbError>> {
            unimplemented!()
        }
    }

    #[test]
    fn probe_read_write() {
        let mut stick = FakeStick::new(300);
        let mut s = UsbStorage::new(&mut stick, DeviceId(1), &CONFIG).unwrap();
        assert_eq!((s.block_size(), s.num_blocks()), (512, 300));
        let inq = s.inquiry().unwrap();
        assert_eq!((inq.vendor(), inq.product(), inq.removable), ("OSMIUM", "FAKE STICK", true));

        // 200 blocks: two READ(10)s of 128 and 72 blocks.
        let mut buf = std::vec![0u8; 200 * 512];
        s.read_blocks(50, &mut buf).unwrap();
        assert!(buf.chunks(512).enumerate().all(|(i, b)| b.iter().all(|&x| x == (50 + i) as u8)));
        s.write_blocks(3, &[0xaa; 1024]).unwrap();
        let mut one = [0u8; 512];
        s.read_blocks(4, &mut one).unwrap();
        assert_eq!(one, [0xaa; 512]);
        assert_eq!(s.read_blocks(299, &mut [0; 1024]), Err(BlockError::OutOfRange));
        s.flush().unwrap();
        drop(s);
        // Unit attention on the first TEST UNIT READY was retried after sense.
        assert_eq!(&stick.commands[..4], &[TEST_UNIT_READY, REQUEST_SENSE, TEST_UNIT_READY, READ_CAPACITY_10]);
        assert_eq!(stick.commands.iter().filter(|&&c| c == READ_10).count(), 3);
    }

    #[test]
    fn stalled_data_stage_reports_sense() {
        let mut stick = FakeStick::new(8);
        let mut s = UsbStorage::new(&mut stick, DeviceId(1), &CONFIG).unwrap();
        s.host.stall_data = true;
        assert_eq!(s.read_blocks(0, &mut [0; 512]), Err(BlockError::Io));
        assert!(!s.host.halted, "the halt was cleared");
        s.host.stall_data = true;
        assert_eq!(s.write_blocks(0, &[0; 512]), Err(BlockError::Io));
        let mut b = [0u8; 512];
        s.read_blocks(1, &mut b).unwrap();
        assert_eq!(b, [1; 512], "the device works afterwards");
        assert_eq!(s.host.resets, 0, "a stall is not a phase error");
        assert_eq!(s.host.sense, 3);
    }

    #[test]
    fn not_mass_storage() {
        let mut hid = CONFIG;
        hid[14] = 3;
        let mut stick = FakeStick::new(1);
        assert_eq!(UsbStorage::new(&mut stick, DeviceId(1), &hid).err(), Some(StorageError::NotMassStorage));
    }
}
