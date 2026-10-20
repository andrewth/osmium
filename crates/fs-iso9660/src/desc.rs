//! Volume descriptors (ECMA-119 section 8).

use alloc::string::String;

use osmium_fs::Errno;

use crate::name;

/// Volume descriptors are 2048 bytes, whatever the logical block size.
pub const SIZE: usize = 2048;

/// Byte offset of the first descriptor (system area: 16 sectors).
pub const FIRST: u64 = 16 * SIZE as u64;

/// What one volume descriptor is.
pub enum Descriptor {
    /// The primary volume descriptor.
    Primary(Volume),
    /// A supplementary volume descriptor with a Joliet escape sequence.
    Joliet(Volume),
    /// The set terminator.
    Terminator,
    /// Anything else: boot records, partitions, other supplementary sets.
    Other,
}

/// The fields of a primary or Joliet descriptor that the driver uses.
pub struct Volume {
    /// Logical block size: extents are counted in these.
    pub block_size: u32,
    /// The volume identifier, trailing spaces removed.
    pub volume_id: String,
    /// The root directory's 34-byte directory record.
    pub root: [u8; 34],
}

impl Descriptor {
    /// Parses one descriptor; `EINVAL` if it has no `CD001` signature.
    pub fn parse(d: &[u8]) -> Result<Self, Errno> {
        if d.len() < SIZE || &d[1..6] != b"CD001" || d[6] != 1 {
            return Err(Errno::EINVAL);
        }
        Ok(match d[0] {
            255 => Descriptor::Terminator,
            1 => Descriptor::Primary(Volume::parse(d, false)?),
            2 if is_joliet(&d[88..91]) => Descriptor::Joliet(Volume::parse(d, true)?),
            _ => Descriptor::Other,
        })
    }
}

/// Whether `esc` is one of the UCS-2 level 1-3 escape sequences.
fn is_joliet(esc: &[u8]) -> bool {
    esc[0] == 0x25 && esc[1] == 0x2f && matches!(esc[2], 0x40 | 0x43 | 0x45)
}

impl Volume {
    fn parse(d: &[u8], joliet: bool) -> Result<Self, Errno> {
        let block_size = u16::from_le_bytes([d[128], d[129]]) as u32;
        if !block_size.is_power_of_two() || !(512..=2048).contains(&block_size) {
            return Err(Errno::EINVAL);
        }
        let id = &d[40..72];
        let mut volume_id = if joliet { name::ucs2(id) } else { String::from_utf8_lossy(id).into_owned() };
        volume_id.truncate(volume_id.trim_end_matches([' ', '\0']).len());
        Ok(Volume { block_size, volume_id, root: d[156..190].try_into().expect("fixed-width slice") })
    }
}
