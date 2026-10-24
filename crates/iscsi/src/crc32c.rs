//! CRC32C (Castagnoli), the iSCSI header and data digest (RFC 7143 §12.1).

const fn table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut rest: &mut [u32] = &mut t;
    let mut i = 0u32;
    while let [slot, tail @ ..] = rest {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0x82f6_3b78 } else { c >> 1 };
            k += 1;
        }
        *slot = c;
        rest = tail;
        i += 1;
    }
    t
}

static TABLE: [u32; 256] = table();

/// A CRC32C computation in progress.
#[derive(Clone, Copy, Debug)]
pub struct Crc32c(u32);

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    /// A CRC of no bytes.
    pub const fn new() -> Self {
        Self(!0)
    }

    /// Appends `data`.
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.0 = TABLE.get(((self.0 ^ b as u32) & 0xff) as usize).copied().unwrap_or(0) ^ (self.0 >> 8);
        }
    }

    /// The CRC of everything appended.
    pub const fn finish(self) -> u32 {
        !self.0
    }
}

/// The CRC32C of `data`. On the wire the digest is these four bytes in
/// little-endian order.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut c = Crc32c::new();
    c.update(data);
    c.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn known_vectors() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        // RFC 3720 appendix B.4.
        assert_eq!(crc32c(&[0u8; 32]), 0x8a91_36aa);
        assert_eq!(crc32c(&[0xffu8; 32]), 0x62a8_ab43);
        let up: Vec<u8> = (0..32).collect();
        assert_eq!(crc32c(&up), 0x46dd_794e);
        let down: Vec<u8> = (0..32).rev().collect();
        assert_eq!(crc32c(&down), 0x113f_db5c);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut c = Crc32c::new();
        c.update(b"1234");
        c.update(b"56789");
        assert_eq!(c.finish(), 0xe306_9283);
    }
}
