//! Striped and mirrored chunks: mapping a logical range onto the stripes of
//! its chunk, and rebuilding a RAID5 or RAID6 strip from the others.

use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::try_zeroed;

use crate::Shared;
use crate::disk::{Chunk, profile};

/// Where a piece of a chunk's logical range lives.
pub(crate) enum Place {
    /// Whole copies on `count` stripes from `first`, each at its `offset +
    /// off`.
    Copies { first: usize, count: usize, off: u64 },
    /// Data strip `data` of full stripe `row` of a parity profile, from byte
    /// `soff` of the strip.
    Parity { row: u64, data: usize, soff: u64 },
}

/// A run of a logical range that lies within one stripe element.
pub(crate) struct Piece {
    /// Bytes in it.
    pub len: u64,
    pub place: Place,
}

impl Chunk {
    /// Parity strips per full stripe: 1 for RAID5, 2 for RAID6, else 0.
    pub fn parity(&self) -> usize {
        if self.ty & profile::RAID6 != 0 {
            2
        } else if self.ty & profile::RAID5 != 0 {
            1
        } else {
            0
        }
    }

    /// The piece at `within` bytes into the chunk, at most `max` bytes long.
    pub(crate) fn piece(&self, within: u64, max: u64) -> Result<Piece, Errno> {
        let n = self.stripes.len();
        let (nu, sl) = (n as u64, self.stripe_len);
        if self.ty & profile::STRIPED == 0 {
            return Ok(Piece { len: max, place: Place::Copies { first: 0, count: n, off: within } });
        }
        if sl == 0 || nu == 0 {
            return Err(Errno::EIO);
        }
        let (nr, soff) = (within / sl, within % sl);
        let len = max.min(sl - soff);
        let rowoff = |row: u64| row.checked_mul(sl).and_then(|r| r.checked_add(soff)).ok_or(Errno::EIO);
        let place = if self.ty & profile::RAID0 != 0 {
            Place::Copies { first: (nr % nu) as usize, count: 1, off: rowoff(nr / nu)? }
        } else if self.ty & profile::RAID10 != 0 {
            let sub = self.sub_stripes as u64;
            let groups = nu.checked_div(sub).filter(|&g| g > 0).ok_or(Errno::EIO)?;
            Place::Copies { first: ((nr % groups) * sub) as usize, count: sub as usize, off: rowoff(nr / groups)? }
        } else {
            let data = nu.checked_sub(self.parity() as u64).filter(|&d| d > 0).ok_or(Errno::EIO)?;
            Place::Parity { row: nr / data, data: (nr % data) as usize, soff }
        };
        Ok(Piece { len, place })
    }

    /// The logical address of byte `r` of stripe `i`'s device extent, and
    /// how many bytes from it are contiguous logically. `None` for the
    /// parity profiles, and beyond the chunk.
    pub(crate) fn rmap(&self, i: usize, r: u64) -> Option<(u64, u64)> {
        let (n, sl) = (self.stripes.len() as u64, self.stripe_len);
        let (at, room) = if self.ty & profile::STRIPED == 0 {
            (r, self.length.checked_sub(r)?)
        } else if self.ty & (profile::RAID5 | profile::RAID6) != 0 || sl == 0 {
            return None;
        } else {
            let (groups, col) = if self.ty & profile::RAID10 != 0 {
                let sub = self.sub_stripes as u64;
                (n.checked_div(sub)?, i as u64 / sub)
            } else {
                (n, i as u64)
            };
            let nr = (r / sl).checked_mul(groups)?.checked_add(col)?;
            let soff = r % sl;
            (nr.checked_mul(sl)?.checked_add(soff)?, sl - soff)
        };
        let room = room.min(self.length.checked_sub(at)?);
        (room > 0).then_some((self.logical.checked_add(at)?, room))
    }
}

/// GF(2^8) with the polynomial 0x11d and generator 2, as RAID6 uses: the
/// powers of 2 twice over, and the logarithms.
const fn gf_tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    // invariant: `i` < 255 and `x` < 256 index arrays of 512 and 256, in a
    // const evaluation that fails the build rather than panicking.
    #[allow(clippy::indexing_slicing)]
    while i < 255 {
        exp[i] = x as u8;
        exp[i + 255] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    (exp, log)
}

static GF: ([u8; 512], [u8; 256]) = gf_tables();

/// `g^i`.
fn gpow(i: usize) -> u8 {
    GF.0.get(i % 255).copied().unwrap_or(0)
}

/// `a * b`.
fn gmul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let (la, lb) = (GF.1.get(a as usize).copied().unwrap_or(0), GF.1.get(b as usize).copied().unwrap_or(0));
    GF.0.get(la as usize + lb as usize).copied().unwrap_or(0)
}

/// `1 / a`, for a nonzero `a`.
fn ginv(a: u8) -> u8 {
    let la = GF.1.get(a as usize).copied().unwrap_or(0) as usize;
    GF.0.get((255 - la) % 255).copied().unwrap_or(0)
}

/// `dst ^= c * src`.
fn mul_xor(dst: &mut [u8], src: &[u8], c: u8) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= gmul(*s, c);
    }
}

/// `dst ^= src`.
fn xor(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

/// Rebuilds the strips of one row of a parity profile that are `None` in
/// `strips` (by role: the data strips, then P, then Q), as far as the parity
/// allows, so that data strip `want` is `Some`. `parity` is 1 or 2.
pub(crate) fn rebuild(strips: &mut [Option<Vec<u8>>], parity: usize, len: usize, want: usize) -> Result<(), Errno> {
    let nd = strips.len().checked_sub(parity).ok_or(Errno::EIO)?;
    // The missing strips: at most `parity` of them, or there is nothing to do.
    let gone = strips.iter().filter(|s| s.is_none()).count();
    if gone > parity || want >= nd || strips.get(want).is_none_or(|s| s.is_some()) {
        return Err(Errno::EIO);
    }
    let (p_at, q_at) = (nd, nd + 1);
    let mut lost = [0usize; 2];
    let mut nlost = 0;
    for (i, _) in strips.iter().enumerate().take(nd).filter(|(_, s)| s.is_none()) {
        *lost.get_mut(nlost).ok_or(Errno::EIO)? = i;
        nlost += 1;
    }
    let p_ok = strips.get(p_at).is_some_and(|s| s.is_some());
    let q_ok = parity == 2 && strips.get(q_at).is_some_and(|s| s.is_some());
    // What the data strips present add up to, plainly (for P) and weighted
    // (for Q).
    let mut psum: Vec<u8> = try_zeroed(len)?;
    let mut qsum: Vec<u8> = try_zeroed(len)?;
    for (i, s) in strips.iter().enumerate().take(nd) {
        if let Some(s) = s {
            xor(&mut psum, s);
            mul_xor(&mut qsum, s, gpow(i));
        }
    }
    let stored = |at: usize| -> Result<&[u8], Errno> { strips.get(at).and_then(|s| s.as_deref()).ok_or(Errno::EIO) };
    match (lost.get(..nlost).unwrap_or(&[]), p_ok, q_ok) {
        // One data strip: what P adds to the others, or what Q does.
        (&[x], true, _) => {
            xor(&mut psum, stored(p_at)?);
            *strips.get_mut(x).ok_or(Errno::EIO)? = Some(psum);
        }
        (&[x], false, true) => {
            xor(&mut qsum, stored(q_at)?);
            let mut d: Vec<u8> = try_zeroed(len)?;
            mul_xor(&mut d, &qsum, ginv(gpow(x)));
            *strips.get_mut(x).ok_or(Errno::EIO)? = Some(d);
        }
        // Two data strips, with both parities: a = Dx ^ Dy and
        // b = gx Dx ^ gy Dy give Dx = (b ^ gy a) / (gx ^ gy).
        (&[x, y], true, true) => {
            xor(&mut psum, stored(p_at)?);
            xor(&mut qsum, stored(q_at)?);
            let (gy, inv) = (gpow(y), ginv(gpow(x) ^ gpow(y)));
            let mut dx: Vec<u8> = try_zeroed(len)?;
            let mut dy: Vec<u8> = try_zeroed(len)?;
            for (((a, b), px), py) in psum.iter().zip(&qsum).zip(dx.iter_mut()).zip(dy.iter_mut()) {
                let vx = gmul(b ^ gmul(gy, *a), inv);
                *px = vx;
                *py = a ^ vx;
            }
            *strips.get_mut(x).ok_or(Errno::EIO)? = Some(dx);
            *strips.get_mut(y).ok_or(Errno::EIO)? = Some(dy);
        }
        _ => return Err(Errno::EIO),
    }
    Ok(())
}

impl<D: BlockDevice + Send + 'static> Shared<D> {
    /// Reads one piece into `buf` from the first copy that reads and that
    /// `good` accepts, or, for a parity profile, from the strip itself or
    /// else rebuilt from the rest of its row.
    pub(crate) fn read_piece(
        &self,
        chunk: &Chunk,
        place: &Place,
        buf: &mut [u8],
        good: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), Errno> {
        match *place {
            Place::Copies { first, count, off } => {
                for s in chunk.stripes.iter().skip(first).take(count) {
                    let Some(at) = s.offset.checked_add(off) else { continue };
                    if self.read_phys(s.devid, at, buf).is_ok() && good(buf) {
                        return Ok(());
                    }
                }
                Err(Errno::EIO)
            }
            Place::Parity { row, data, soff } => {
                let n = chunk.stripes.len();
                let rel = row.checked_mul(chunk.stripe_len).and_then(|r| r.checked_add(soff)).ok_or(Errno::EIO)?;
                // Role `k` (data, then P, then Q) of this row lives on stripe
                // `(k + row) % n`.
                let read_role = |k: usize, out: &mut [u8]| -> bool {
                    let at = ((k as u64).wrapping_add(row) % n as u64) as usize;
                    chunk
                        .stripes
                        .get(at)
                        .and_then(|s| Some((s.devid, s.offset.checked_add(rel)?)))
                        .is_some_and(|(devid, at)| self.read_phys(devid, at, out).is_ok())
                };
                if read_role(data, buf) && good(buf) {
                    return Ok(());
                }
                let mut strips: Vec<Option<Vec<u8>>> = Vec::new();
                strips.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
                for k in 0..n {
                    let mut v = try_zeroed(buf.len())?;
                    strips.push((k != data && read_role(k, &mut v)).then_some(v));
                }
                rebuild(&mut strips, chunk.parity(), buf.len(), data)?;
                let got = strips.get(data).and_then(|s| s.as_ref()).ok_or(Errno::EIO)?;
                buf.copy_from_slice(got);
                if good(buf) { Ok(()) } else { Err(Errno::EIO) }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn field() {
        assert_eq!(gmul(2, 0x80), 0x1d);
        for a in 1..=255u8 {
            assert_eq!(gmul(a, ginv(a)), 1);
        }
    }

    fn row(nd: usize, parity: usize) -> Vec<Option<Vec<u8>>> {
        let mut s: Vec<Option<Vec<u8>>> =
            (0..nd).map(|i| Some((0..16).map(|b| (b * 7 + i * 31 + 3) as u8).collect())).collect();
        let (mut p, mut q) = (vec![0u8; 16], vec![0u8; 16]);
        for (i, d) in s.iter().enumerate() {
            xor(&mut p, d.as_ref().unwrap());
            mul_xor(&mut q, d.as_ref().unwrap(), gpow(i));
        }
        s.push(Some(p));
        if parity == 2 {
            s.push(Some(q));
        }
        s
    }

    #[test]
    fn rebuilds() {
        for (nd, parity) in [(2, 1), (3, 1), (4, 2), (5, 2)] {
            let full = row(nd, parity);
            for x in 0..nd {
                let mut s = full.clone();
                s[x] = None;
                rebuild(&mut s, parity, 16, x).unwrap();
                assert_eq!(s, full);
                if parity == 2 {
                    // Data and P gone: from Q. Data and Q gone: from P.
                    for gone in [nd, nd + 1] {
                        let mut s = full.clone();
                        (s[x], s[gone]) = (None, None);
                        rebuild(&mut s, parity, 16, x).unwrap();
                        assert_eq!(s[x], full[x]);
                    }
                    for y in x + 1..nd {
                        let mut s = full.clone();
                        (s[x], s[y]) = (None, None);
                        rebuild(&mut s, parity, 16, x).unwrap();
                        assert_eq!(s, full);
                    }
                }
            }
            let mut s = full.clone();
            for slot in s.iter_mut().take(parity + 1) {
                *slot = None;
            }
            assert!(rebuild(&mut s, parity, 16, 0).is_err());
        }
    }
}
