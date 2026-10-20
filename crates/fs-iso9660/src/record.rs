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
        if r.len() < MIN_LEN || r[0] as usize != r.len() {
            return Err(Errno::EIO);
        }
        let name_len = r[32] as usize;
        let name_end = 33 + name_len;
        if name_len == 0 || name_end > r.len() {
            return Err(Errno::EIO);
        }
        // A padding byte keeps the system use area at an even offset.
        let su = (name_end + (name_len + 1) % 2).min(r.len());
        let le32 = |at: usize| u32::from_le_bytes(r[at..at + 4].try_into().expect("fixed-width slice"));
        Ok(Record {
            extent: le32(2).wrapping_add(r[1] as u32),
            size: le32(10),
            flags: r[25],
            interleave: (r[26], r[27]),
            name: &r[33..name_end],
            system_use: &r[su..],
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
                self.pos = (at / self.block + 1) * self.block;
                continue;
            }
            let Some(r) = self.data.get(at..at + len) else {
                self.pos = self.data.len();
                return Some(Err(Errno::EIO));
            };
            self.pos = at + len;
            return Some(Record::parse(r).map(|rec| (at, rec)));
        }
    }
}
