//! The SCSI commands a block initiator needs (SPC-4, SBC-3), and parsing of
//! what they return.
//!
//! CDBs are built as the 16-byte field of the iSCSI SCSI Command PDU; a
//! shorter CDB is zero padded, and the target knows its length from the
//! opcode.

/// A command descriptor block, zero padded to 16 bytes.
pub type Cdb = [u8; 16];

/// Operation codes.
pub mod op {
    #![allow(missing_docs)]
    pub const TEST_UNIT_READY: u8 = 0x00;
    pub const REQUEST_SENSE: u8 = 0x03;
    pub const INQUIRY: u8 = 0x12;
    pub const READ_CAPACITY_10: u8 = 0x25;
    pub const READ_10: u8 = 0x28;
    pub const WRITE_10: u8 = 0x2a;
    pub const SYNCHRONIZE_CACHE_10: u8 = 0x35;
    pub const READ_16: u8 = 0x88;
    pub const WRITE_16: u8 = 0x8a;
    pub const SYNCHRONIZE_CACHE_16: u8 = 0x91;
    /// SERVICE ACTION IN(16); READ CAPACITY(16) is service action 0x10.
    pub const SERVICE_ACTION_IN_16: u8 = 0x9e;
    pub const REPORT_LUNS: u8 = 0xa0;
}

/// The READ CAPACITY(16) service action.
pub const SA_READ_CAPACITY_16: u8 = 0x10;

/// SCSI status codes (SAM-5 §5.3).
pub mod status {
    #![allow(missing_docs)]
    pub const GOOD: u8 = 0x00;
    pub const CHECK_CONDITION: u8 = 0x02;
    pub const CONDITION_MET: u8 = 0x04;
    pub const BUSY: u8 = 0x08;
    pub const RESERVATION_CONFLICT: u8 = 0x18;
    pub const TASK_SET_FULL: u8 = 0x28;
    pub const ACA_ACTIVE: u8 = 0x30;
    pub const TASK_ABORTED: u8 = 0x40;
}

/// Sense keys (SPC-4 §4.5.6).
pub mod sense_key {
    #![allow(missing_docs)]
    pub const NO_SENSE: u8 = 0x0;
    pub const RECOVERED_ERROR: u8 = 0x1;
    pub const NOT_READY: u8 = 0x2;
    pub const MEDIUM_ERROR: u8 = 0x3;
    pub const HARDWARE_ERROR: u8 = 0x4;
    pub const ILLEGAL_REQUEST: u8 = 0x5;
    pub const UNIT_ATTENTION: u8 = 0x6;
    pub const DATA_PROTECT: u8 = 0x7;
    pub const ABORTED_COMMAND: u8 = 0xb;
}

/// Additional sense code for LOGICAL BLOCK ADDRESS OUT OF RANGE.
pub const ASC_LBA_OUT_OF_RANGE: u8 = 0x21;

/// The largest block count one READ(10)/WRITE(10) can carry.
pub const MAX_BLOCKS_10: u32 = 0xffff;

/// The `N` bytes at `at` of `d`, if `d` is long enough.
fn chunk<const N: usize>(d: &[u8], at: usize) -> Option<[u8; N]> {
    d.get(at..)?.first_chunk::<N>().copied()
}

/// Copies `src` into `dst` at `at`, if it fits.
fn put(dst: &mut [u8], at: usize, src: &[u8]) {
    if let Some(d) = at.checked_add(src.len()).and_then(|end| dst.get_mut(at..end)) {
        d.copy_from_slice(src);
    }
}

fn cdb(bytes: &[u8]) -> Cdb {
    let mut c = [0; 16];
    put(&mut c, 0, bytes);
    c
}

/// TEST UNIT READY.
pub fn test_unit_ready() -> Cdb {
    cdb(&[op::TEST_UNIT_READY, 0, 0, 0, 0, 0])
}

/// Standard INQUIRY data, up to `len` bytes.
pub fn inquiry(len: u16) -> Cdb {
    let [n0, n1] = len.to_be_bytes();
    cdb(&[op::INQUIRY, 0, 0, n0, n1, 0])
}

/// READ CAPACITY(10), which returns 8 bytes.
pub fn read_capacity_10() -> Cdb {
    cdb(&[op::READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0])
}

/// READ CAPACITY(16), returning up to 32 bytes.
pub fn read_capacity_16() -> Cdb {
    let mut c = cdb(&[op::SERVICE_ACTION_IN_16, SA_READ_CAPACITY_16]);
    put(&mut c, 13, &[32]);
    c
}

/// REPORT LUNS, returning up to `len` bytes.
pub fn report_luns(len: u32) -> Cdb {
    let mut c = cdb(&[op::REPORT_LUNS]);
    put(&mut c, 6, &len.to_be_bytes());
    c
}

/// SYNCHRONIZE CACHE(10) of the whole medium.
pub fn synchronize_cache_10() -> Cdb {
    cdb(&[op::SYNCHRONIZE_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0])
}

/// READ(10) or WRITE(10) when the range fits in 32 bits of LBA and 16 of
/// count, else READ(16) or WRITE(16).
fn rw(op10: u8, op16: u8, lba: u64, blocks: u32) -> Cdb {
    if lba.saturating_add(blocks.max(1) as u64) <= u32::MAX as u64 + 1 && blocks <= MAX_BLOCKS_10 {
        let [l0, l1, l2, l3] = (lba as u32).to_be_bytes();
        let [n0, n1] = (blocks as u16).to_be_bytes();
        cdb(&[op10, 0, l0, l1, l2, l3, 0, n0, n1, 0])
    } else {
        let mut c = cdb(&[op16]);
        put(&mut c, 2, &lba.to_be_bytes());
        put(&mut c, 10, &blocks.to_be_bytes());
        c
    }
}

/// Reads `blocks` blocks at `lba`.
pub fn read(lba: u64, blocks: u32) -> Cdb {
    rw(op::READ_10, op::READ_16, lba, blocks)
}

/// Writes `blocks` blocks at `lba`.
pub fn write(lba: u64, blocks: u32) -> Cdb {
    rw(op::WRITE_10, op::WRITE_16, lba, blocks)
}

/// The LBA and block count of a READ or WRITE in either size, as a target
/// decodes it.
pub fn rw_range(cdb: &[u8]) -> Option<(u64, u32)> {
    match cdb.first()? {
        0x28 | 0x2a => {
            let lba = u32::from_be_bytes(chunk(cdb, 2)?) as u64;
            Some((lba, u16::from_be_bytes(chunk(cdb, 7)?) as u32))
        }
        0x88 | 0x8a => Some((u64::from_be_bytes(chunk(cdb, 2)?), u32::from_be_bytes(chunk(cdb, 10)?))),
        _ => None,
    }
}

/// Decoded sense data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sense {
    /// The sense key, one of [`sense_key`].
    pub key: u8,
    /// Additional sense code.
    pub asc: u8,
    /// Additional sense code qualifier.
    pub ascq: u8,
}

impl Sense {
    /// Parses fixed (0x70, 0x71) or descriptor (0x72, 0x73) format sense
    /// data.
    pub fn parse(d: &[u8]) -> Option<Self> {
        match d.first()? & 0x7f {
            0x70 | 0x71 => {
                let key = d.get(2)? & 0xf;
                match d.get(12..14) {
                    Some(&[asc, ascq]) => Some(Self { key, asc, ascq }),
                    _ => Some(Self { key, asc: 0, ascq: 0 }),
                }
            }
            0x72 | 0x73 => match d.get(1..4) {
                Some(&[key, asc, ascq]) => Some(Self { key: key & 0xf, asc, ascq }),
                _ => None,
            },
            _ => None,
        }
    }

    /// Parses the data segment of an iSCSI SCSI Response: a two-byte
    /// SenseLength, then the sense data (RFC 7143 §11.4.7.2).
    pub fn from_response(data: &[u8]) -> Option<Self> {
        let len = u16::from_be_bytes([*data.first()?, *data.get(1)?]) as usize;
        Self::parse(data.get(2..)?.get(..len)?)
    }

    /// Fixed format sense data with `key`, `asc` and `ascq`, as a target
    /// returns it.
    pub fn to_fixed(self) -> [u8; 18] {
        let mut d = [0; 18];
        put(&mut d, 0, &[0x70, 0, self.key, 0, 0, 0, 0, 10, 0, 0, 0, 0, self.asc, self.ascq]);
        d
    }
}

/// Identification from standard INQUIRY data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inquiry {
    /// Peripheral qualifier (top three bits) and device type: 0 is a
    /// direct-access block device, 5 an optical drive.
    pub peripheral: u8,
    /// Removable medium.
    pub removable: bool,
    /// Vendor, space padded.
    pub vendor: [u8; 8],
    /// Product, space padded.
    pub product: [u8; 16],
    /// Product revision, space padded.
    pub revision: [u8; 4],
}

impl Inquiry {
    /// Parses at least 36 bytes of standard INQUIRY data.
    pub fn parse(d: &[u8]) -> Option<Self> {
        let [peripheral, flags] = chunk(d, 0)?;
        Some(Self {
            peripheral,
            removable: flags & 0x80 != 0,
            vendor: chunk(d, 8)?,
            product: chunk(d, 16)?,
            revision: chunk(d, 32)?,
        })
    }

    /// The device type (low five bits of the peripheral byte).
    pub fn device_type(&self) -> u8 {
        self.peripheral & 0x1f
    }

    /// The vendor without padding (or "?" if not ASCII).
    pub fn vendor(&self) -> &str {
        trimmed(&self.vendor)
    }

    /// The product without padding (or "?" if not ASCII).
    pub fn product(&self) -> &str {
        trimmed(&self.product)
    }

    /// The revision without padding (or "?" if not ASCII).
    pub fn revision(&self) -> &str {
        trimmed(&self.revision)
    }
}

fn trimmed(b: &[u8]) -> &str {
    core::str::from_utf8(b).map(str::trim_end).unwrap_or("?")
}

/// The medium's size from READ CAPACITY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    /// The address of the last block.
    pub last_lba: u64,
    /// Bytes per block.
    pub block_size: u32,
}

impl Capacity {
    /// Parses READ CAPACITY(10) data. A last LBA of 0xffffffff means the
    /// medium is too large and READ CAPACITY(16) is needed.
    pub fn parse_10(d: &[u8]) -> Option<Self> {
        Some(Self { last_lba: u32::from_be_bytes(chunk(d, 0)?) as u64, block_size: u32::from_be_bytes(chunk(d, 4)?) })
    }

    /// Parses READ CAPACITY(16) data.
    pub fn parse_16(d: &[u8]) -> Option<Self> {
        Some(Self { last_lba: u64::from_be_bytes(chunk(d, 0)?), block_size: u32::from_be_bytes(chunk(d, 8)?) })
    }

    /// The number of blocks (saturating, for a target that claims the last LBA is `u64::MAX`).
    pub fn blocks(&self) -> u64 {
        self.last_lba.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_pick_the_cdb_size() {
        let c = read(0x0102_0304, 8);
        assert_eq!(&c[..10], &[0x28, 0, 1, 2, 3, 4, 0, 0, 8, 0]);
        assert_eq!(rw_range(&c), Some((0x0102_0304, 8)));
        // The last block addressable by READ(10) still fits.
        assert_eq!(write(u32::MAX as u64, 1)[0], op::WRITE_10);
        let c = write(1 << 32, 2);
        assert_eq!(&c[..14], &[0x8a, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert_eq!(rw_range(&c), Some((1 << 32, 2)));
        assert_eq!(read(0, 0x10000)[0], op::READ_16, "too many blocks for READ(10)");
        assert_eq!(rw_range(&test_unit_ready()), None);
    }

    #[test]
    fn sense_formats() {
        let fixed = Sense { key: sense_key::ILLEGAL_REQUEST, asc: 0x21, ascq: 0 }.to_fixed();
        assert_eq!(Sense::parse(&fixed), Some(Sense { key: 5, asc: 0x21, ascq: 0 }));
        assert_eq!(Sense::parse(&[0x72, 0x06, 0x29, 0x00, 0, 0, 0, 0]), Some(Sense { key: 6, asc: 0x29, ascq: 0 }));
        assert_eq!(Sense::parse(&[0x00, 0, 0]), None);
        let mut resp = std::vec![0, 18];
        resp.extend_from_slice(&fixed);
        assert_eq!(Sense::from_response(&resp).map(|s| s.key), Some(5));
        assert_eq!(Sense::from_response(&[0, 30, 0x70]), None, "truncated");
    }

    #[test]
    fn inquiry_and_capacity() {
        let mut d = [b' '; 36];
        d[0] = 0;
        d[1] = 0x80;
        d[8..14].copy_from_slice(b"OSMIUM");
        d[16..20].copy_from_slice(b"DISK");
        d[32..36].copy_from_slice(b"0001");
        let i = Inquiry::parse(&d).unwrap();
        assert_eq!(
            (i.device_type(), i.removable, i.vendor(), i.product(), i.revision()),
            (0, true, "OSMIUM", "DISK", "0001")
        );
        assert_eq!(Inquiry::parse(&d[..35]), None);

        let c = Capacity::parse_10(&[0, 0, 0x0f, 0xff, 0, 0, 2, 0]).unwrap();
        assert_eq!((c.blocks(), c.block_size), (4096, 512));
        let c = Capacity::parse_16(&[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!((c.last_lba, c.block_size), (1 << 32, 4096));
        assert_eq!(read_capacity_16()[..2], [0x9e, 0x10]);
        assert_eq!(read_capacity_16()[13], 32);
    }
}
