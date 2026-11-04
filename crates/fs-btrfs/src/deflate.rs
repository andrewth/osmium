//! zlib compression (RFC 1950 around RFC 1951): greedy LZ77 matching coded
//! with the fixed Huffman code in a single block. It does not reach what
//! zlib's dynamic codes do, but every stream it writes is valid and any zlib
//! reads it.

use alloc::vec::Vec;

use osmium_fs::Errno;

use crate::lz::{Finder, MIN_MATCH};
use crate::zlib::{DIST_BASE, DIST_EXTRA, LEN_BASE, LEN_EXTRA, adler32};

/// Longest match deflate can code.
const MAX_MATCH: usize = 258;
/// Farthest back a match can reach.
const WINDOW: usize = 32768;

/// Bits written LSB-first, with a bound on the bytes.
struct Bits {
    out: Vec<u8>,
    acc: u64,
    count: u32,
    limit: usize,
}

impl Bits {
    /// `n` (at most 32) low bits of `v`, `EFBIG` once the output passes the
    /// limit.
    fn put(&mut self, v: u32, n: u32) -> Result<(), Errno> {
        self.acc |= u64::from(v) << self.count;
        self.count += n;
        while self.count >= 8 {
            self.byte(self.acc as u8)?;
            self.acc >>= 8;
            self.count -= 8;
        }
        Ok(())
    }

    fn byte(&mut self, b: u8) -> Result<(), Errno> {
        if self.out.len() >= self.limit {
            return Err(Errno::EFBIG);
        }
        self.out.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        self.out.push(b);
        Ok(())
    }

    /// A Huffman code of `n` bits, which goes out from its top bit.
    fn code(&mut self, code: u32, n: u32) -> Result<(), Errno> {
        self.put(code.reverse_bits() >> (32 - n), n)
    }

    /// A literal/length symbol in the fixed code.
    fn symbol(&mut self, sym: u32) -> Result<(), Errno> {
        match sym {
            0..=143 => self.code(0x30 + sym, 8),
            144..=255 => self.code(0x190 + sym - 144, 9),
            256..=279 => self.code(sym - 256, 7),
            _ => self.code(0xC0 + sym - 280, 8),
        }
    }

    fn flush(&mut self) -> Result<(), Errno> {
        if self.count > 0 {
            self.byte(self.acc as u8)?;
            self.acc = 0;
            self.count = 0;
        }
        Ok(())
    }
}

/// The index of the last entry of `base` that is at most `v`.
fn slot(base: &[u16], v: usize) -> usize {
    base.iter().rposition(|&b| usize::from(b) <= v).unwrap_or(0)
}

/// Compresses `src` into a zlib stream of fewer than `limit` bytes; `None`
/// if it would take more.
pub(crate) fn compress(src: &[u8], limit: usize) -> Result<Option<Vec<u8>>, Errno> {
    let mut finder = Finder::new(src.len())?;
    let mut w = Bits { out: Vec::new(), acc: 0, count: 0, limit };
    match encode(src, &mut finder, &mut w) {
        Ok(()) => Ok(Some(w.out)),
        Err(Errno::EFBIG) => Ok(None),
        Err(e) => Err(e),
    }
}

fn encode(src: &[u8], finder: &mut Finder, w: &mut Bits) -> Result<(), Errno> {
    w.out.try_reserve(limit_hint(w.limit)).map_err(|_| Errno::ENOMEM)?;
    // CMF/FLG: deflate with a 32 KiB window, fastest level, check bits valid.
    w.byte(0x78)?;
    w.byte(0x01)?;
    // One final block with the fixed codes.
    w.put(1, 1)?;
    w.put(1, 2)?;
    let mut pos = 0;
    while pos < src.len() {
        let found = finder.find(src, pos, WINDOW, MAX_MATCH).filter(|&(len, _)| len >= MIN_MATCH);
        let Some((len, dist)) = found else {
            w.symbol(u32::from(src.get(pos).copied().unwrap_or(0)))?;
            finder.insert(src, pos);
            pos += 1;
            continue;
        };
        let l = slot(&LEN_BASE, len);
        w.symbol(257 + l as u32)?;
        let extra = u32::from(LEN_EXTRA.get(l).copied().unwrap_or(0));
        w.put((len - usize::from(LEN_BASE.get(l).copied().unwrap_or(0))) as u32, extra)?;
        let d = slot(&DIST_BASE, dist);
        w.code(d as u32, 5)?;
        let extra = u32::from(DIST_EXTRA.get(d).copied().unwrap_or(0));
        w.put((dist - usize::from(DIST_BASE.get(d).copied().unwrap_or(0))) as u32, extra)?;
        for p in pos..pos + len {
            finder.insert(src, p);
        }
        pos += len;
    }
    w.symbol(256)?;
    w.flush()?;
    for b in adler32(src).to_be_bytes() {
        w.byte(b)?;
    }
    Ok(())
}

/// How much output to reserve up front.
fn limit_hint(limit: usize) -> usize {
    limit.min(1 << 17)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn text(n: usize) -> Vec<u8> {
        let words: [&[u8]; 6] = [b"btrfs ", b"extent ", b"osmium ", b"compressed ", b"the ", b"zlib\n"];
        let (mut v, mut x) = (Vec::new(), 12345u32);
        while v.len() < n {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            v.extend_from_slice(words[(x >> 16) as usize % words.len()]);
        }
        v.truncate(n);
        v
    }

    fn round(data: &[u8]) -> Option<usize> {
        let c = compress(data, data.len() * 2 + 64).unwrap()?;
        let mut out = std::vec![0u8; data.len()];
        assert_eq!(crate::zlib::decompress(&c, &mut out).unwrap(), data.len());
        assert_eq!(out, data);
        Some(c.len())
    }

    #[test]
    fn text_round_trips_and_shrinks() {
        let t = text(128 * 1024);
        assert!(round(&t).unwrap() < t.len() / 2);
    }

    #[test]
    fn zeroes_and_short_inputs() {
        assert!(round(&[0; 131072]).unwrap() < 1000);
        for n in [0, 1, 3, 4, 5, 100] {
            round(&text(n)).unwrap();
        }
    }

    #[test]
    fn noise_does_not_fit() {
        let mut x = 1u32;
        let n: Vec<u8> = (0..4096)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        assert!(compress(&n, n.len() - 4096 / 8).unwrap().is_none());
    }
}
