//! Match finding shared by the compressors: a hash of four bytes with chains
//! through earlier positions, searched a few steps deep.

use alloc::vec::Vec;

use osmium_fs::Errno;

/// Shortest match found.
pub(crate) const MIN_MATCH: usize = 4;
/// Bits of the hash.
const HASH_BITS: u32 = 14;
/// Chain links followed per search.
const DEPTH: usize = 24;

/// Where earlier four-byte sequences of a buffer start.
pub(crate) struct Finder {
    /// Position plus one of the latest sequence with each hash; 0 for none.
    head: Vec<u32>,
    /// For each position, `head`'s previous value when it was inserted.
    prev: Vec<u32>,
}

impl Finder {
    /// A finder for buffers of up to `n` bytes.
    pub(crate) fn new(n: usize) -> Result<Self, Errno> {
        let mut head = Vec::new();
        head.try_reserve_exact(1 << HASH_BITS).map_err(|_| Errno::ENOMEM)?;
        head.resize(1 << HASH_BITS, 0);
        let mut prev = Vec::new();
        prev.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
        prev.resize(n, 0);
        Ok(Finder { head, prev })
    }

    /// Forgets every position, for a new buffer.
    pub(crate) fn reset(&mut self) {
        self.head.fill(0);
    }

    fn hash(data: &[u8], pos: usize) -> Option<usize> {
        let w = u32::from_le_bytes(*data.get(pos..)?.first_chunk::<4>()?);
        Some((w.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize)
    }

    /// Records that a sequence starts at `pos`.
    pub(crate) fn insert(&mut self, data: &[u8], pos: usize) {
        if let Some(h) = Self::hash(data, pos)
            && let Some(slot) = self.head.get_mut(h)
            && let Some(p) = self.prev.get_mut(pos)
        {
            *p = *slot;
            *slot = pos as u32 + 1;
        }
    }

    /// The longest earlier match for `data[pos..]`, as `(length, distance)`,
    /// of at most `max_len` bytes and `max_dist` back.
    pub(crate) fn find(&self, data: &[u8], pos: usize, max_dist: usize, max_len: usize) -> Option<(usize, usize)> {
        let tail = data.get(pos..)?;
        let max_len = max_len.min(tail.len());
        let mut cand = *self.head.get(Self::hash(data, pos)?)?;
        let mut best: Option<(usize, usize)> = None;
        for _ in 0..DEPTH {
            let Some(c) = (cand as usize).checked_sub(1) else { break };
            let Some(dist) = pos.checked_sub(c).filter(|&d| d > 0 && d <= max_dist) else { break };
            let len = data.get(c..).unwrap_or(&[]).iter().zip(tail).take(max_len).take_while(|(a, b)| a == b).count();
            if len >= MIN_MATCH && best.is_none_or(|(l, _)| len > l) {
                best = Some((len, dist));
                if len == max_len {
                    break;
                }
            }
            let Some(&next) = self.prev.get(c) else { break };
            cand = next;
        }
        best
    }
}
