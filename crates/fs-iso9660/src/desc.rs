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
    /// Parses one descriptor; `EINVAL` if it has no `CD001` signature. A
    /// primary or Joliet descriptor whose fields make no sense (a bad block
    /// size, say) is [`Descriptor::Other`]: the set may hold a good one too,
    /// and Linux skips what it cannot use.
    pub fn parse(d: &[u8]) -> Result<Self, Errno> {
        if d.len() < SIZE {
            return Err(Errno::EINVAL);
        }
        let (Some(&kind), Some(sig), Some(&version)) = (d.first(), field::<5>(d, 1), d.get(6)) else {
            return Err(Errno::EINVAL);
        };
        if &sig != b"CD001" || version != 1 {
            return Err(Errno::EINVAL);
        }
        Ok(match kind {
            255 => Descriptor::Terminator,
            1 => usable(Volume::parse(d, false))?.map_or(Descriptor::Other, Descriptor::Primary),
            2 if field::<3>(d, 88).is_some_and(|esc| is_joliet(&esc)) => {
                usable(Volume::parse(d, true))?.map_or(Descriptor::Other, Descriptor::Joliet)
            }
            _ => Descriptor::Other,
        })
    }
}

/// A parsed volume, `None` for one that makes no sense; running out of
/// memory is still an error.
fn usable(v: Result<Volume, Errno>) -> Result<Option<Volume>, Errno> {
    match v {
        Ok(v) => Ok(Some(v)),
        Err(Errno::ENOMEM) => Err(Errno::ENOMEM),
        Err(_) => Ok(None),
    }
}

/// Whether `esc` is one of the UCS-2 level 1-3 escape sequences.
fn is_joliet(esc: &[u8; 3]) -> bool {
    matches!(esc, [0x25, 0x2f, 0x40 | 0x43 | 0x45])
}

/// The `N` bytes of `d` at `at`, if `d` is long enough.
fn field<const N: usize>(d: &[u8], at: usize) -> Option<[u8; N]> {
    d.get(at..)?.first_chunk::<N>().copied()
}

impl Volume {
    fn parse(d: &[u8], joliet: bool) -> Result<Self, Errno> {
        let block_size = u16::from_le_bytes(field::<2>(d, 128).ok_or(Errno::EINVAL)?) as u32;
        if !block_size.is_power_of_two() || !(512..=2048).contains(&block_size) {
            return Err(Errno::EINVAL);
        }
        let id = d.get(40..72).ok_or(Errno::EINVAL)?;
        let mut volume_id = if joliet { name::ucs2(id)? } else { name::lossy(id)? };
        volume_id.truncate(volume_id.trim_end_matches([' ', '\0']).len());
        Ok(Volume { block_size, volume_id, root: field::<34>(d, 156).ok_or(Errno::EINVAL)? })
    }
}
