//! Checksums: CRC32C (the default) and xxHash64. SHA-256 and BLAKE2b file
//! systems are refused at mount.

use crate::xxhash::xxh64;

/// `BTRFS_CSUM_TYPE_CRC32`.
pub const CRC32C: u16 = 0;
/// `BTRFS_CSUM_TYPE_XXHASH`.
pub const XXHASH: u16 = 1;

// invariant: `i` is bounded by the 256-entry table in a const evaluation, which
// fails the build rather than panicking at run time.
#[allow(clippy::indexing_slicing)]
const fn table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 { crc >> 1 ^ 0x82f6_3b78 } else { crc >> 1 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static TABLE: [u32; 256] = table();

/// Raw CRC32C (no inversion in or out), as Linux's `crc32c()`.
pub fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = TABLE.get(((crc ^ b as u32) & 0xff) as usize).copied().unwrap_or(0) ^ crc >> 8;
    }
    crc
}

/// The hash of a directory entry's or extended attribute's name.
pub fn name_hash(name: &[u8]) -> u64 {
    crc32c(!1, name) as u64
}

/// Bytes of a checksum of type `ty`, or `None` for a type not supported.
pub fn size(ty: u16) -> Option<usize> {
    match ty {
        CRC32C => Some(4),
        XXHASH => Some(8),
        _ => None,
    }
}

/// The type-`ty` checksum of `data`, zero-padded to the 32 bytes of space
/// it is stored in.
pub fn compute(ty: u16, data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    match ty {
        CRC32C => out.get_mut(..4).into_iter().for_each(|o| o.copy_from_slice(&(!crc32c(!0, data)).to_le_bytes())),
        XXHASH => out.get_mut(..8).into_iter().for_each(|o| o.copy_from_slice(&xxh64(data, 0).to_le_bytes())),
        _ => {}
    }
    out
}

/// Whether `stored` begins with the type-`ty` checksum of `data`.
pub fn matches(ty: u16, data: &[u8], stored: &[u8]) -> bool {
    let Some(n) = size(ty) else { return false };
    stored.get(..n).is_some_and(|s| compute(ty, data).get(..n) == Some(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_values() {
        assert_eq!(!crc32c(!0, b"123456789"), 0xe306_9283);
        // `btrfs_name_hash("default")`, as `btrfs inspect-internal` prints it.
        assert_eq!(name_hash(b"default"), 0x8dbf_c2d2);
    }
}
