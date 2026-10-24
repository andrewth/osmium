//! Directory records (ECMA-119 section 9.1).

use osmium_fs::Errno;

/// File flags.
pub mod flag {
    /// The existence bit: hidden from the user (shown anyway, like Linux).
    #[allow(dead_code)]
    pub const HIDDEN: u8 = 0x01;
    /// A directory.
    pub const DIRECTORY: u8 = 0x02;
    /// An associated file (resource fork); not shown.
    pub const ASSOCIATED: u8 = 0x04;
    /// Not the file's last extent: the next record continues it.
    pub const MULTI_EXTENT: u8 = 0x80;
}

/// Smallest valid record: 33 fixed bytes and a one-byte identifier.
const MIN_LEN: usize = 34;

/// One directory record.
pub struct Record<'src> {
    /// First logical block of the data, after any extended attribute record.
    pub extent: u32,
    /// Bytes in this extent.
    pub size: u32,
    /// [`flag`] bits.
    pub flags: u8,
    /// File unit size and interleave gap size, in logical blocks (both
    /// non-zero for an interleaved file).
    pub interleave: (u8, u8),
    /// The raw file identifier.
    pub name: &'src [u8],
    /// The system use area (SUSP and Rock Ridge entries).
    pub system_use: &'src [u8],
}

impl<'src> Record<'src> {
    /// Parses a record of exactly `r.len()` bytes.
    pub fn parse(r: &'src [u8]) -> Result<Self, Errno> {
        let [len, xattr, ..] = *r else { return Err(Errno::EIO) };
        if r.len() < MIN_LEN || len as usize != r.len() {
            return Err(Errno::EIO);
        }
        let byte = |at: usize| r.get(at).copied().ok_or(Errno::EIO);
        let name_len = byte(32)? as usize;
        let name_end = 33 + name_len;
        if name_len == 0 || name_end > r.len() {
            return Err(Errno::EIO);
        }
        // A padding byte keeps the system use area at an even offset.
        let su = (name_end + (name_len + 1) % 2).min(r.len());
        let le32 = |at: usize| {
            r.get(at..).and_then(|t| t.first_chunk::<4>()).map(|c| u32::from_le_bytes(*c)).ok_or(Errno::EIO)
        };
        Ok(Record {
            extent: le32(2)?.wrapping_add(xattr as u32),
            size: le32(10)?,
            flags: byte(25)?,
            interleave: (byte(26)?, byte(27)?),
            name: r.get(33..name_end).ok_or(Errno::EIO)?,
            system_use: r.get(su..).ok_or(Errno::EIO)?,
        })
    }

    /// The `.` (first) record of a directory.
    pub fn is_dot(&self) -> bool {
        self.name == [0]
    }

    /// The `..` (second) record of a directory.
    pub fn is_dotdot(&self) -> bool {
        self.name == [1]
    }
}

/// The records of a directory read into memory, with their byte offsets.
///
/// Records never cross a logical block; a zero length byte means the rest
/// of the block is padding.
pub struct Records<'src> {
    data: &'src [u8],
    block: usize,
    pos: usize,
}

impl<'src> Records<'src> {
    /// Walks `data`, a directory extent of `block`-byte logical blocks.
    pub fn new(data: &'src [u8], block: usize) -> Self {
        Records { data, block, pos: 0 }
    }
}

impl<'src> Iterator for Records<'src> {
    type Item = Result<(usize, Record<'src>), Errno>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let at = self.pos;
            let len = *self.data.get(at)? as usize;
            if len == 0 {
                self.pos = (at / self.block.max(1) + 1) * self.block.max(1);
                continue;
            }
            let Some(r) = self.data.get(at..at.saturating_add(len)) else {
                self.pos = self.data.len();
                return Some(Err(Errno::EIO));
            };
            self.pos = at + len;
            return Some(Record::parse(r).map(|rec| (at, rec)));
        }
    }
}
