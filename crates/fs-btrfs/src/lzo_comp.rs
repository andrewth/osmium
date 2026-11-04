//! LZO compression in btrfs's framing (see [`crate::lzo`] for the layout):
//! each sector becomes one LZO1X segment, written with greedy matching and the
//! M2 and M3 match forms (so no match reaches back more than 16 KiB). The
//! output is plain LZO1X, version 0, which Linux and liblzo2 both read.

use alloc::vec::Vec;

use osmium_fs::Errno;

use crate::lz::Finder;

/// Bytes in a length field.
const LEN: usize = 4;
/// Farthest back an M3 match reaches.
const MAX_DIST: usize = 1 << 14;

fn push(v: &mut Vec<u8>, b: u8) -> Result<(), Errno> {
    v.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
    v.push(b);
    Ok(())
}

fn extend(v: &mut Vec<u8>, s: &[u8]) -> Result<(), Errno> {
    v.try_reserve(s.len()).map_err(|_| Errno::ENOMEM)?;
    v.extend_from_slice(s);
    Ok(())
}

/// An extended length of `v` (at least 1): zero bytes worth 255 each, then
/// the rest.
fn count(seg: &mut Vec<u8>, v: usize) -> Result<(), Errno> {
    let zeros = v.saturating_sub(1) / 255;
    for _ in 0..zeros {
        push(seg, 0)?;
    }
    push(seg, (v - zeros * 255) as u8)
}

/// A literal run of `lits` (4 bytes or more) where an instruction is expected.
fn run(seg: &mut Vec<u8>, lits: &[u8]) -> Result<(), Errno> {
    let n = lits.len();
    if n <= 18 {
        push(seg, (n - 3) as u8)?;
    } else {
        push(seg, 0)?;
        count(seg, n - 18)?;
    }
    extend(seg, lits)
}

/// Compresses one sector into raw LZO1X.
fn segment(src: &[u8], finder: &mut Finder, seg: &mut Vec<u8>) -> Result<(), Errno> {
    seg.clear();
    finder.reset();
    // The byte holding the "literals that follow" bits of the last match.
    let mut patch: Option<usize> = None;
    let (mut pos, mut lit_start) = (0, 0);
    // Emits `src[lit_start..end]` as the literals before the next instruction.
    let flush = |seg: &mut Vec<u8>, patch: Option<usize>, lit_start: usize, end: usize| -> Result<(), Errno> {
        let lits = src.get(lit_start..end).ok_or(Errno::EIO)?;
        let n = lits.len();
        if n == 0 {
            return Ok(());
        }
        match patch {
            None if n <= 238 => push(seg, 17 + n as u8)?,
            Some(at) if n <= 3 => *seg.get_mut(at).ok_or(Errno::EIO)? |= n as u8,
            _ => return run(seg, lits),
        }
        extend(seg, lits)
    };
    while pos < src.len() {
        let Some((len, dist)) = finder.find(src, pos, MAX_DIST, src.len()) else {
            finder.insert(src, pos);
            pos += 1;
            continue;
        };
        flush(seg, patch, lit_start, pos)?;
        if dist <= 2048 && len <= 8 {
            patch = Some(seg.len());
            push(seg, ((len - 1) << 5 | ((dist - 1) & 7) << 2) as u8)?;
            push(seg, ((dist - 1) >> 3) as u8)?;
        } else {
            if len <= 33 {
                push(seg, 32 | (len - 2) as u8)?;
            } else {
                push(seg, 32)?;
                count(seg, len - 33)?;
            }
            patch = Some(seg.len());
            let d = (dist - 1) << 2;
            push(seg, d as u8)?;
            push(seg, (d >> 8) as u8)?;
        }
        for p in pos..pos + len {
            finder.insert(src, p);
        }
        pos += len;
        lit_start = pos;
    }
    flush(seg, patch, lit_start, src.len())?;
    extend(seg, &[17, 0, 0])
}

/// Compresses `src` into btrfs LZO data of fewer than `limit` bytes; `None`
/// if it would take more.
pub(crate) fn compress(src: &[u8], sectorsize: usize, limit: usize) -> Result<Option<Vec<u8>>, Errno> {
    if sectorsize < LEN {
        return Err(Errno::EINVAL);
    }
    let mut out = Vec::new();
    out.try_reserve_exact(limit.min(1 << 17).saturating_add(sectorsize)).map_err(|_| Errno::ENOMEM)?;
    out.extend_from_slice(&[0; LEN]);
    let mut finder = Finder::new(sectorsize)?;
    let mut seg = Vec::new();
    for sector in src.chunks(sectorsize) {
        segment(sector, &mut finder, &mut seg)?;
        // A header does not straddle sectors.
        let left = sectorsize - out.len() % sectorsize;
        if left < LEN {
            out.resize(out.len() + left, 0);
        }
        extend(&mut out, &(seg.len() as u32).to_le_bytes())?;
        extend(&mut out, &seg)?;
        if out.len() >= limit {
            return Ok(None);
        }
    }
    let total = (out.len() as u32).to_le_bytes();
    out.get_mut(..LEN).ok_or(Errno::EIO)?.copy_from_slice(&total);
    Ok(Some(out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn text(n: usize) -> Vec<u8> {
        let words: [&[u8]; 6] = [b"btrfs ", b"extent ", b"osmium ", b"compressed ", b"the ", b"lzo\n"];
        let (mut v, mut x) = (Vec::new(), 777u32);
        while v.len() < n {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            v.extend_from_slice(words[(x >> 16) as usize % words.len()]);
        }
        v.truncate(n);
        v
    }

    fn round(data: &[u8], ss: usize) -> Option<usize> {
        let c = compress(data, ss, data.len() * 2 + 64).unwrap()?;
        let mut out = std::vec![0u8; data.len()];
        assert_eq!(crate::lzo::decompress(&c, &mut out, ss).unwrap(), data.len());
        assert_eq!(out, data);
        Some(c.len())
    }

    #[test]
    fn text_round_trips_and_shrinks() {
        let t = text(128 * 1024);
        assert!(round(&t, 4096).unwrap() < t.len() / 2);
        round(&t, 8192).unwrap();
    }

    #[test]
    fn runs_and_short_inputs() {
        assert!(round(&[0; 131072], 4096).unwrap() < 4000);
        let mut mixed = text(4096);
        mixed.extend_from_slice(&[7; 4096]);
        round(&mixed, 4096).unwrap();
        for n in [1, 2, 3, 4, 5, 17, 18, 19, 100, 4096] {
            round(&text(n), 4096).unwrap();
        }
    }

    #[test]
    fn noise_round_trips_or_is_refused() {
        let mut x = 1u32;
        let n: Vec<u8> = (0..16384)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        round(&n, 4096).unwrap();
        assert!(compress(&n, 4096, n.len() - 4096).unwrap().is_none());
    }
}
