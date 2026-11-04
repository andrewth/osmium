//! A Zstandard compressor (RFC 8878): greedy LZ77 matching, literals stored
//! raw, sequences coded with the predefined FSE tables, all in one
//! single-segment frame with one block. The output is an ordinary frame that
//! any decoder reads; it gives up the Huffman-coded literals and tuned tables
//! of the reference compressor.

use alloc::vec::Vec;

use osmium_fs::Errno;

use super::{
    BLOCK_SIZE_MAX, Cell, FRAME_MAGIC, LL_BASE, LL_BITS, LL_FIELD, ML_BASE, ML_BITS, ML_FIELD, OF_FIELD, build_fse,
};
use crate::lz::Finder;

/// Longest match coded (the largest match length code reaches further).
const MAX_MATCH: usize = 1 << 16;

/// Bits written LSB-first, closed by the marker bit the decoder looks for.
struct Bits {
    out: Vec<u8>,
    acc: u64,
    count: u32,
}

impl Bits {
    /// `n` (at most 32) low bits of `v`.
    fn put(&mut self, v: u64, n: u32) -> Result<(), Errno> {
        self.acc |= (v & ((1u64 << n) - 1)) << self.count;
        self.count += n;
        while self.count >= 8 {
            self.out.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.count -= 8;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>, Errno> {
        self.put(1, 1)?;
        if self.count > 0 {
            self.put(0, 8 - self.count)?;
        }
        Ok(self.out)
    }
}

/// An FSE table seen from the encoder: running the decoder's table
/// backwards. Each symbol's cells cover every state, so the cell whose range
/// holds the state to come says which state to be in and what bits to send.
struct Coder {
    cells: [Cell; 64],
    log: u32,
    state: usize,
}

impl Coder {
    fn new(norm: &[i16], log: u32) -> Result<Self, Errno> {
        let mut cells = [Cell::default(); 64];
        build_fse(norm, log, &mut cells).map_err(|_| Errno::EIO)?;
        Ok(Coder { cells, log, state: 0 })
    }

    fn live(&self) -> &[Cell] {
        self.cells.get(..1 << self.log).unwrap_or(&[])
    }

    /// Starts in a state that decodes `sym`.
    fn init(&mut self, sym: usize) -> Result<(), Errno> {
        self.state = self.live().iter().position(|c| usize::from(c.sym) == sym).ok_or(Errno::EIO)?;
        Ok(())
    }

    /// Steps back to a state that decodes `sym` and then moves to the current one.
    fn encode(&mut self, sym: usize, w: &mut Bits) -> Result<(), Errno> {
        let now = self.state;
        let (at, c) = self
            .live()
            .iter()
            .enumerate()
            .find(|(_, c)| {
                usize::from(c.sym) == sym && usize::from(c.base) <= now && now < usize::from(c.base) + (1 << c.bits)
            })
            .ok_or(Errno::EIO)?;
        w.put((now - usize::from(c.base)) as u64, u32::from(c.bits))?;
        self.state = at;
        Ok(())
    }

    fn flush(&self, w: &mut Bits) -> Result<(), Errno> {
        w.put(self.state as u64, self.log)
    }
}

/// A sequence: literals, then a match.
struct Seq {
    lits: u32,
    len: u32,
    offset: u32,
}

/// The code for `v` in a table of baselines, and the value of its extra bits.
fn code(base: &[u32], bits: &[u8], v: u32) -> Result<(usize, u32, u32), Errno> {
    let c = base.iter().rposition(|&b| b <= v).ok_or(Errno::EIO)?;
    Ok((c, v - base.get(c).copied().ok_or(Errno::EIO)?, u32::from(bits.get(c).copied().ok_or(Errno::EIO)?)))
}

fn extend(v: &mut Vec<u8>, s: &[u8]) -> Result<(), Errno> {
    v.try_reserve(s.len()).map_err(|_| Errno::ENOMEM)?;
    v.extend_from_slice(s);
    Ok(())
}

/// Compresses `src` into a zstd frame of fewer than `limit` bytes; `None` if
/// it would take more, or is more than a block.
pub(crate) fn compress(src: &[u8], limit: usize) -> Result<Option<Vec<u8>>, Errno> {
    if src.len() > BLOCK_SIZE_MAX as usize {
        return Ok(None);
    }
    // Matches and the literals between them.
    let mut finder = Finder::new(src.len())?;
    let (mut seqs, mut lits) = (Vec::new(), Vec::new());
    let (mut pos, mut lit_start) = (0, 0);
    while pos < src.len() {
        let Some((len, dist)) = finder.find(src, pos, src.len(), MAX_MATCH) else {
            finder.insert(src, pos);
            pos += 1;
            continue;
        };
        let run = src.get(lit_start..pos).ok_or(Errno::EIO)?;
        seqs.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        seqs.push(Seq { lits: run.len() as u32, len: len as u32, offset: dist as u32 });
        extend(&mut lits, run)?;
        for p in pos..pos + len {
            finder.insert(src, p);
        }
        pos += len;
        lit_start = pos;
    }
    extend(&mut lits, src.get(lit_start..).ok_or(Errno::EIO)?)?;
    if seqs.is_empty() {
        return Ok(None);
    }

    // The block: raw literals, then the sequences.
    let mut block = Vec::new();
    block.try_reserve(lits.len() + 64).map_err(|_| Errno::ENOMEM)?;
    let n = lits.len();
    if n < 4096 {
        block.extend_from_slice(&[((n & 15) << 4 | 1 << 2) as u8, (n >> 4) as u8]);
    } else {
        block.extend_from_slice(&[((n & 15) << 4 | 3 << 2) as u8, (n >> 4) as u8, (n >> 12) as u8]);
    }
    block.extend_from_slice(&lits);
    let count = seqs.len();
    if count < 128 {
        block.push(count as u8);
    } else if count < 0x7F00 {
        block.extend_from_slice(&[(count >> 8) as u8 + 128, count as u8]);
    } else {
        let c = count - 0x7F00;
        block.extend_from_slice(&[255, c as u8, (c >> 8) as u8]);
    }
    // All three tables predefined.
    block.push(0);
    let mut ll = Coder::new(LL_FIELD.default, LL_FIELD.default_log)?;
    let mut of = Coder::new(OF_FIELD.default, OF_FIELD.default_log)?;
    let mut ml = Coder::new(ML_FIELD.default, ML_FIELD.default_log)?;
    let mut w = Bits { out: Vec::new(), acc: 0, count: 0 };
    w.out.try_reserve(src.len() / 2).map_err(|_| Errno::ENOMEM)?;
    // Written last to first, so that the decoder reads first to last.
    for (i, s) in seqs.iter().enumerate().rev() {
        let (llc, lle, llb) = code(&LL_BASE, &LL_BITS, s.lits)?;
        let (mlc, mle, mlb) = code(&ML_BASE, &ML_BITS, s.len)?;
        // Offsets are always sent as new ones: the value is the offset plus 3.
        let ofv = s.offset + 3;
        let ofc = ofv.ilog2();
        if i + 1 == count {
            ml.init(mlc)?;
            of.init(ofc as usize)?;
            ll.init(llc)?;
        } else {
            of.encode(ofc as usize, &mut w)?;
            ml.encode(mlc, &mut w)?;
            ll.encode(llc, &mut w)?;
        }
        w.put(u64::from(lle), llb)?;
        w.put(u64::from(mle), mlb)?;
        w.put(u64::from(ofv - (1 << ofc)), ofc)?;
        if w.out.len() >= limit {
            return Ok(None);
        }
    }
    ml.flush(&mut w)?;
    of.flush(&mut w)?;
    ll.flush(&mut w)?;
    extend(&mut block, &w.finish()?)?;

    // Frame header: single segment, 4-byte content size, no checksum.
    let total = 4 + 1 + 4 + 3 + block.len();
    if total >= limit {
        return Ok(None);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(total).map_err(|_| Errno::ENOMEM)?;
    out.extend_from_slice(&FRAME_MAGIC.to_le_bytes());
    out.push(0x20 | 2 << 6);
    out.extend_from_slice(&(src.len() as u32).to_le_bytes());
    let header = (block.len() as u32) << 3 | 2 << 1 | 1;
    out.extend_from_slice(&header.to_le_bytes()[..3]);
    out.extend_from_slice(&block);
    Ok(Some(out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn text(n: usize) -> Vec<u8> {
        let words: [&[u8]; 6] = [b"btrfs ", b"extent ", b"osmium ", b"compressed ", b"the ", b"zstd\n"];
        let (mut v, mut x) = (Vec::new(), 4242u32);
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
        assert_eq!(super::super::decompress(&c, &mut out), Ok(data.len()));
        assert_eq!(out, data);
        Some(c.len())
    }

    #[test]
    fn text_round_trips_and_shrinks() {
        let t = text(128 * 1024);
        assert!(round(&t).unwrap() < t.len() / 2);
        round(&text(4096)).unwrap();
        round(&text(8192 + 5)).unwrap();
    }

    #[test]
    fn runs_and_odd_sizes() {
        assert!(round(&[0; 131072]).unwrap() < 1000);
        let mut mixed = text(5000);
        mixed.extend_from_slice(&[9; 3000]);
        mixed.extend_from_slice(&text(70000));
        round(&mixed).unwrap();
        for n in [8, 100, 4095, 4096, 12288] {
            round(&text(n));
        }
    }

    #[test]
    fn noise_is_refused() {
        let mut x = 1u32;
        let n: Vec<u8> = (0..8192)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        assert!(compress(&n, n.len() - 4096).unwrap().is_none());
    }
}
