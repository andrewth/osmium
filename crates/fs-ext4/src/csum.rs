//! The checksums ext4 uses: CRC32C (Castagnoli) for `metadata_csum` and
//! CRC16 (ANSI) for group descriptors under `uninit_bg`. Both are Linux's
//! raw forms, with no inversion on the way in or out; callers pass the seed.

// invariant: `i` is bounded by the 256-entry table in a const evaluation, which
// fails the build rather than panicking at run time.
#[allow(clippy::indexing_slicing)]
const fn table(poly: u32) -> [u32; 256] {
    let mut table = [0; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 { crc >> 1 ^ poly } else { crc >> 1 };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

static CRC32C: [u32; 256] = table(0x82f6_3b78);
static CRC16: [u32; 256] = table(0xa001);

pub fn crc32c(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = CRC32C.get(((crc ^ b as u32) & 0xff) as usize).copied().unwrap_or(0) ^ crc >> 8;
    }
    crc
}

pub fn crc16(crc: u16, data: &[u8]) -> u16 {
    let mut crc = crc as u32;
    for &b in data {
        crc = CRC16.get(((crc ^ b as u32) & 0xff) as usize).copied().unwrap_or(0) ^ crc >> 8;
    }
    crc as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_values() {
        // The catalogued check values, which invert in and out.
        assert_eq!(!crc32c(!0, b"123456789"), 0xe306_9283);
        // CRC-16/ARC starts from zero.
        assert_eq!(crc16(0, b"123456789"), 0xbb3d);
    }
}
