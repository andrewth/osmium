// SPDX-License-Identifier: GPL-2.0-only
//! The ChaCha20 block function (RFC 8439).

/// The ChaCha20 block for `key`, block `counter` and `nonce`, as 64 bytes.
pub fn block(key: &[u32; 8], counter: u32, nonce: &[u32; 3], out: &mut [u8; 64]) {
    let mut init = [0u32; 16];
    init[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    init[4..12].copy_from_slice(key);
    init[12] = counter;
    init[13..].copy_from_slice(nonce);
    let mut x = init;
    for _ in 0..10 {
        x = double_round(x);
    }
    for ((o, xi), ii) in out.as_chunks_mut::<4>().0.iter_mut().zip(x).zip(init) {
        *o = xi.wrapping_add(ii).to_le_bytes();
    }
    crate::wipe_words(&mut x);
    crate::wipe_words(&mut init);
}

/// A column round followed by a diagonal round.
#[inline(always)]
fn double_round(x: [u32; 16]) -> [u32; 16] {
    let [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15] = x;
    let (x0, x4, x8, x12) = quarter(x0, x4, x8, x12);
    let (x1, x5, x9, x13) = quarter(x1, x5, x9, x13);
    let (x2, x6, x10, x14) = quarter(x2, x6, x10, x14);
    let (x3, x7, x11, x15) = quarter(x3, x7, x11, x15);
    let (x0, x5, x10, x15) = quarter(x0, x5, x10, x15);
    let (x1, x6, x11, x12) = quarter(x1, x6, x11, x12);
    let (x2, x7, x8, x13) = quarter(x2, x7, x8, x13);
    let (x3, x4, x9, x14) = quarter(x3, x4, x9, x14);
    [x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15]
}

#[inline(always)]
fn quarter(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(16);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(12);
    a = a.wrapping_add(b);
    d = (d ^ a).rotate_left(8);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_left(7);
    (a, b, c, d)
}

/// Reads 32 little-endian bytes as eight key words.
pub fn key_words(bytes: &[u8; 32]) -> [u32; 8] {
    let mut k = [0u32; 8];
    for (w, b) in k.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *w = u32::from_le_bytes(*b);
    }
    k
}

#[cfg(test)]
mod tests {
    use super::{block, key_words};

    #[test]
    fn rfc_8439_section_2_3_2() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [0x0900_0000, 0x4a00_0000, 0];
        let mut out = [0u8; 64];
        block(&key_words(&key), 1, &nonce, &mut out);
        let expect = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4, 0xc7, 0xd1,
            0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46,
            0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16,
            0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(out, expect);
    }
}
