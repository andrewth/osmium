//! Checksums: CRC32C (the default), xxHash64, SHA-256 and BLAKE2b-256.

// `as_chunks` would need the nightly-only const generics at each call site for
// no gain over the checked iterators here.
#![allow(clippy::chunks_exact_to_as_chunks)]

use crate::xxhash::xxh64;

/// `BTRFS_CSUM_TYPE_CRC32`.
pub const CRC32C: u16 = 0;
/// `BTRFS_CSUM_TYPE_XXHASH`.
pub const XXHASH: u16 = 1;
/// `BTRFS_CSUM_TYPE_SHA256`.
pub const SHA256: u16 = 2;
/// `BTRFS_CSUM_TYPE_BLAKE2` (BLAKE2b with a 256-bit digest).
pub const BLAKE2: u16 = 3;

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
        SHA256 | BLAKE2 => Some(32),
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
        SHA256 => out = sha256(data),
        BLAKE2 => out = blake2b256(data),
        _ => {}
    }
    out
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

fn sha256_block(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (i, c) in block.chunks_exact(4).take(16).enumerate() {
        if let (Some(slot), Ok(a)) = (w.get_mut(i), <[u8; 4]>::try_from(c)) {
            *slot = u32::from_be_bytes(a);
        }
    }
    for i in 16..64 {
        let at = |j: usize| w.get(i - j).copied().unwrap_or(0);
        let s0 = at(15).rotate_right(7) ^ at(15).rotate_right(18) ^ at(15) >> 3;
        let s1 = at(2).rotate_right(17) ^ at(2).rotate_right(19) ^ at(2) >> 10;
        let v = at(16).wrapping_add(s0).wrapping_add(at(7)).wrapping_add(s1);
        if let Some(slot) = w.get_mut(i) {
            *slot = v;
        }
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for (k, wi) in K256.iter().zip(w.iter()) {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(*k).wrapping_add(*wi);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(y);
    }
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] =
        [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    let mut blocks = data.chunks_exact(64);
    for b in &mut blocks {
        sha256_block(&mut h, b);
    }
    let rest = blocks.remainder();
    let mut tail = [0u8; 128];
    if let Some(t) = tail.get_mut(..rest.len()) {
        t.copy_from_slice(rest);
    }
    if let Some(t) = tail.get_mut(rest.len()) {
        *t = 0x80;
    }
    let total = if rest.len() < 56 { 64 } else { 128 };
    let bits = (data.len() as u64).wrapping_mul(8).to_be_bytes();
    if let Some(t) = tail.get_mut(total - 8..total) {
        t.copy_from_slice(&bits);
    }
    for b in tail.chunks_exact(64).take(total / 64) {
        sha256_block(&mut h, b);
    }
    let mut out = [0u8; 32];
    for (o, v) in out.chunks_exact_mut(4).zip(h) {
        o.copy_from_slice(&v.to_be_bytes());
    }
    out
}

const B2_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const B2_SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

// invariant: `v`, `h` and `m` are fixed arrays of 16, 8 and 16 words, and every
// index is a constant below that, a loop bound within it, or a `B2_SIGMA`
// entry, which is below 16.
#[allow(clippy::indexing_slicing)]
fn b2_compress(h: &mut [u64; 8], block: &[u8], count: u128, last: bool) {
    let mut m = [0u64; 16];
    for (slot, c) in m.iter_mut().zip(block.chunks_exact(8)) {
        if let Ok(a) = <[u8; 8]>::try_from(c) {
            *slot = u64::from_le_bytes(a);
        }
    }
    let mut v = [0u64; 16];
    for i in 0..8 {
        if let (Some(a), Some(b), Some(c)) = (v.get_mut(i), h.get(i), B2_IV.get(i)) {
            *a = *b;
            if let Some(d) = v.get_mut(i + 8) {
                *d = *c;
            }
        }
    }
    v[12] ^= count as u64;
    v[13] ^= (count >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    // Twelve rounds; the last two reuse the first two permutations.
    for s in B2_SIGMA.iter().chain(B2_SIGMA.iter().take(2)) {
        let mx = |r: usize| m.get(s.get(r).copied().unwrap_or(0) as usize).copied().unwrap_or(0);
        let mut g = |a: usize, b: usize, c: usize, d: usize, x: u64, y: u64| {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(63);
        };
        g(0, 4, 8, 12, mx(0), mx(1));
        g(1, 5, 9, 13, mx(2), mx(3));
        g(2, 6, 10, 14, mx(4), mx(5));
        g(3, 7, 11, 15, mx(6), mx(7));
        g(0, 5, 10, 15, mx(8), mx(9));
        g(1, 6, 11, 12, mx(10), mx(11));
        g(2, 7, 8, 13, mx(12), mx(13));
        g(3, 4, 9, 14, mx(14), mx(15));
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b with a 32-byte digest and no key, of `data`.
pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = B2_IV;
    h[0] ^= 0x0101_0020;
    // The last block is the final one even when full, except for no data at all.
    let full = if data.is_empty() { 0 } else { (data.len() - 1) / 128 };
    let mut count = 0u128;
    for b in data.chunks(128).take(full) {
        count += 128;
        b2_compress(&mut h, b, count, false);
    }
    let rest = data.get(full * 128..).unwrap_or(&[]);
    let mut last = [0u8; 128];
    if let Some(t) = last.get_mut(..rest.len()) {
        t.copy_from_slice(rest);
    }
    count += rest.len() as u128;
    b2_compress(&mut h, &last, count, true);
    let mut out = [0u8; 32];
    for (o, v) in out.chunks_exact_mut(8).zip(h) {
        o.copy_from_slice(&v.to_le_bytes());
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
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn check_values() {
        assert_eq!(!crc32c(!0, b"123456789"), 0xe306_9283);
        // `btrfs_name_hash("default")`, as `btrfs inspect-internal` prints it.
        assert_eq!(name_hash(b"default"), 0x8dbf_c2d2);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        let million = vec![b'a'; 1_000_000];
        assert_eq!(hex(&sha256(&million)), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
        // Padding boundaries: 55, 56 and 64 bytes.
        assert_eq!(hex(&sha256(&[b'a'; 55])), "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
        assert_eq!(hex(&sha256(&[b'a'; 56])), "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
        assert_eq!(hex(&sha256(&[b'a'; 64])), "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    }

    #[test]
    fn blake2b_vectors() {
        assert_eq!(hex(&blake2b256(b"")), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
        assert_eq!(hex(&blake2b256(b"abc")), "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
        // One full block, one over, two full blocks, and several.
        assert_eq!(hex(&blake2b256(&[0u8; 128])), "378d0caaaa3855f1b38693c1d6ef004fd118691c95c959d4efa950d6d6fcf7c1");
        assert_eq!(hex(&blake2b256(&[0u8; 129])), "baadfb64c3bd2cd187b54accc5e61a0720ed86bf48c28017873536cf9015d1b8");
        assert_eq!(hex(&blake2b256(&[0u8; 256])), "2b69702a889248a4d6620475a105dccd5e0d4230aca8a492aaf6510e55d55b02");
        let mixed: Vec<u8> = (0..768).map(|i| i as u8).collect();
        assert_eq!(hex(&blake2b256(&mixed)), "b8007121274217790e2923e0ad7027986e5a99d5531ef6ae7d294140fc81615d");
    }
}
