//! IPv6 fragmentation and reassembly (RFC 8200 section 4.5).
//!
//! [`fragment`] cuts a payload into the pieces that carry it over a link of
//! a given MTU. A [`Reassembler`] collects the pieces that arrive and hands
//! back the datagram when the last one is in. It is built for hostile
//! networks:
//!
//! - every limit is bounded ([`Limits`]): datagrams in flight, pieces and
//!   bytes per datagram, bytes in total, and how long a datagram may take;
//! - a datagram whose pieces overlap or contradict each other is discarded
//!   whole (RFC 5722), and so is one with an empty piece or a middle piece
//!   that is not a multiple of 8 bytes;
//! - when the bytes held would exceed the budget the oldest datagram goes
//!   first, so a flood costs a bounded amount of memory.
//!
//! The interface does this on its own; the types are public for code that
//! builds packets itself.

use alloc::vec::Vec;
use core::net::Ipv6Addr;
use core::time::Duration;

use crate::Instant;
use crate::ipv6::{IPV6_HEADER_LEN, IPV6_MIN_MTU, Ipv6Fragment};
use crate::wire::put;

/// Length of a fragment header.
pub const FRAGMENT_HEADER_LEN: usize = 8;
/// The most bytes a reassembled datagram can have: what the 16-bit payload
/// length holds.
pub const MAX_DATAGRAM: usize = 65535;

/// Cuts `payload`, an upper-layer message of protocol `next_header`, into
/// pieces for a link of `mtu` bytes, each as the bytes that follow the IPv6
/// header: a fragment header with `ident`, then the piece. The IPv6 header
/// of each carries next header 44 ([`PROTO_FRAGMENT`](crate::ipv6::PROTO_FRAGMENT))
/// and a payload length of the piece's length.
///
/// Returns `None` if the payload would not fit a datagram or `mtu` is under
/// the IPv6 minimum of 1280.
pub fn fragment(payload: &[u8], next_header: u8, mtu: usize, ident: u32) -> Option<Vec<Vec<u8>>> {
    if mtu < IPV6_MIN_MTU || payload.len() > MAX_DATAGRAM {
        return None;
    }
    // Every piece but the last is a multiple of 8 bytes.
    let step = (mtu - IPV6_HEADER_LEN - FRAGMENT_HEADER_LEN) / 8 * 8;
    let mut pieces = Vec::with_capacity(payload.len().div_ceil(step).max(1));
    let mut offset = 0;
    loop {
        let piece = payload.get(offset..)?.get(..step.min(payload.len() - offset))?;
        let more = offset + piece.len() < payload.len();
        let mut b = alloc::vec![0; FRAGMENT_HEADER_LEN + piece.len()];
        // The offset is a multiple of 8, so its low 3 bits are free for the
        // flags; it fits 13 bits of 8-byte units because the payload is
        // under 64 KiB.
        let field = u16::try_from(offset).ok()? | u16::from(more);
        put(&mut b, 0, &[next_header, 0]);
        put(&mut b, 2, &field.to_be_bytes());
        put(&mut b, 4, &ident.to_be_bytes());
        put(&mut b, FRAGMENT_HEADER_LEN, piece);
        pieces.push(b);
        offset += piece.len();
        if !more {
            return Some(pieces);
        }
    }
}

/// The limits a [`Reassembler`] keeps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Datagrams being put together at once. A new one past this evicts the
    /// oldest.
    pub datagrams: usize,
    /// Pieces one datagram may arrive in; more condemn it, so that a stream
    /// of tiny pieces cannot make the bookkeeping outgrow the datagram.
    pub pieces: usize,
    /// The most bytes one datagram can have, up to [`MAX_DATAGRAM`].
    pub datagram_bytes: usize,
    /// The most bytes held for all datagrams together. The oldest datagrams
    /// are evicted to make room.
    pub total_bytes: usize,
    /// How long a datagram may take from its first piece to its last
    /// (RFC 8200 specifies 60 seconds).
    pub timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            datagrams: 8,
            pieces: 128,
            datagram_bytes: MAX_DATAGRAM,
            total_bytes: 192 * 1024,
            timeout: Duration::from_secs(60),
        }
    }
}

/// Why a piece was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// The piece is empty, a middle piece is not a multiple of 8 bytes, or
    /// it reaches past the largest datagram.
    Malformed,
    /// It overlaps or contradicts what was already held; the datagram is
    /// discarded with it (RFC 5722).
    Overlap,
    /// The datagram has more pieces or bytes than the limits allow, and is
    /// discarded.
    TooBig,
}

/// A datagram put back together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    /// Source address.
    pub src: Ipv6Addr,
    /// Destination address.
    pub dst: Ipv6Addr,
    /// The protocol the data starts with, as the first piece's fragment
    /// header named it.
    pub next_header: u8,
    /// The datagram's bytes after the fragment header's position: any
    /// extension headers that came after it and the upper-layer message.
    pub data: Vec<u8>,
}

struct Entry {
    src: Ipv6Addr,
    dst: Ipv6Addr,
    ident: u32,
    first: Instant,
    /// The datagram's length, known once its last piece arrives.
    total: Option<usize>,
    /// The next header of the piece at offset 0, once it has arrived.
    next_header: Option<u8>,
    /// `(offset, bytes)`, sorted and disjoint.
    pieces: Vec<(usize, Vec<u8>)>,
    /// Bytes held in `pieces`.
    held: usize,
}

impl Entry {
    fn complete(&self) -> bool {
        let Some(total) = self.total else { return false };
        // Sorted and disjoint, so the pieces are the whole when they are
        // contiguous and their sizes add up.
        self.next_header.is_some() && self.held == total
    }

    fn assemble(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.held);
        for (_, piece) in &self.pieces {
            data.extend_from_slice(piece);
        }
        data
    }
}

/// Puts fragmented IPv6 datagrams back together, within [`Limits`].
pub struct Reassembler {
    limits: Limits,
    entries: Vec<Entry>,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// A reassembler with the default limits.
    pub fn new() -> Self {
        Self::with_limits(Limits::default())
    }

    /// A reassembler with `limits`.
    pub fn with_limits(limits: Limits) -> Self {
        Self { limits, entries: Vec::new() }
    }

    /// The limits in force.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Replaces the limits; what is held beyond them is evicted.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
        while self.entries.len() > self.limits.datagrams.max(1) || self.held() > self.limits.total_bytes {
            if self.entries.is_empty() {
                break;
            }
            self.entries.remove(0);
        }
    }

    /// Datagrams being put together.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no datagram is being put together.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Bytes held for datagrams in progress.
    pub fn held(&self) -> usize {
        self.entries.iter().map(|e| e.held).sum()
    }

    /// Takes a piece of a datagram from `src` to `dst`. `fragment` is its
    /// fragment header, `next_header` the one that header names, and `data`
    /// the bytes after it. Returns the datagram when this was its last
    /// missing piece.
    pub fn add(
        &mut self,
        now: Instant,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        fragment: Ipv6Fragment,
        next_header: u8,
        data: &[u8],
    ) -> Result<Option<Datagram>, Reject> {
        let max = self.limits.datagram_bytes.min(MAX_DATAGRAM);
        let end = fragment.offset.checked_add(data.len()).ok_or(Reject::Malformed)?;
        if data.is_empty() || (fragment.more && data.len() % 8 != 0) || end > MAX_DATAGRAM {
            return Err(Reject::Malformed);
        }
        if end > max || data.len() > self.limits.total_bytes {
            return Err(Reject::TooBig);
        }
        let i = match self.entries.iter().position(|e| (e.src, e.dst, e.ident) == (src, dst, fragment.ident)) {
            Some(i) => i,
            None => {
                self.make_room(data.len());
                self.entries.push(Entry {
                    src,
                    dst,
                    ident: fragment.ident,
                    first: now,
                    total: None,
                    next_header: None,
                    pieces: Vec::new(),
                    held: 0,
                });
                self.entries.len() - 1
            }
        };
        let outcome = self.insert(i, fragment, next_header, data);
        match outcome {
            Err(e) => {
                self.entries.remove(i);
                Err(e)
            }
            Ok(()) => {
                let Some(entry) = self.entries.get(i) else { return Ok(None) };
                if !entry.complete() {
                    return Ok(None);
                }
                let data = entry.assemble();
                let next_header = entry.next_header.ok_or(Reject::Malformed)?;
                self.entries.remove(i);
                Ok(Some(Datagram { src, dst, next_header, data }))
            }
        }
    }

    /// Evicts the oldest datagrams until a new one with `incoming` bytes
    /// fits the limits.
    fn make_room(&mut self, incoming: usize) {
        let datagrams = self.limits.datagrams.max(1);
        while !self.entries.is_empty()
            && (self.entries.len() >= datagrams || self.held().saturating_add(incoming) > self.limits.total_bytes)
        {
            self.entries.remove(0);
        }
    }

    fn insert(&mut self, i: usize, fragment: Ipv6Fragment, next_header: u8, data: &[u8]) -> Result<(), Reject> {
        let others: usize = self.entries.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, e)| e.held).sum();
        let limits = self.limits;
        let entry = self.entries.get_mut(i).ok_or(Reject::Malformed)?;
        let end = fragment.offset + data.len();
        if !fragment.more {
            // The last piece fixes the length; a second, different one or a
            // piece beyond the end contradicts it.
            if entry.total.is_some_and(|t| t != end) {
                return Err(Reject::Overlap);
            }
            entry.total = Some(end);
        }
        if entry.total.is_some_and(|t| end > t) {
            return Err(Reject::Overlap);
        }
        let at = entry.pieces.partition_point(|(o, _)| *o < fragment.offset);
        if let Some((o, d)) = at.checked_sub(1).and_then(|k| entry.pieces.get(k))
            && o + d.len() > fragment.offset
        {
            return Err(Reject::Overlap);
        }
        if let Some((o, d)) = entry.pieces.get(at) {
            if *o == fragment.offset && *d == data {
                return Ok(()); // an exact duplicate carries nothing new
            }
            if *o < end {
                return Err(Reject::Overlap);
            }
        }
        if entry.pieces.len() >= limits.pieces
            || entry.held + data.len() > limits.datagram_bytes
            || others.saturating_add(entry.held).saturating_add(data.len()) > limits.total_bytes
        {
            return Err(Reject::TooBig);
        }
        if fragment.offset == 0 {
            entry.next_header = Some(next_header);
        }
        entry.pieces.insert(at, (fragment.offset, data.to_vec()));
        entry.held += data.len();
        Ok(())
    }

    /// Discards datagrams that have been in progress longer than the
    /// timeout. Returns how many.
    pub fn expire(&mut self, now: Instant) -> usize {
        let timeout = self.limits.timeout;
        let before = self.entries.len();
        self.entries.retain(|e| now - e.first < timeout);
        before - self.entries.len()
    }

    /// When the next datagram times out.
    pub fn poll_at(&self) -> Option<Instant> {
        self.entries.iter().map(|e| e.first + self.limits.timeout).min()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    const A: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const B: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    fn frag(offset: usize, more: bool, ident: u32) -> Ipv6Fragment {
        Ipv6Fragment { offset, more, ident }
    }

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + i / 256) as u8).collect()
    }

    /// The (fragment, data) pairs `fragment` produced, parsed back.
    fn pieces(data: &[u8], mtu: usize, ident: u32) -> Vec<(Ipv6Fragment, Vec<u8>)> {
        fragment(data, 17, mtu, ident)
            .unwrap()
            .into_iter()
            .map(|b| {
                let field = u16::from_be_bytes([b[2], b[3]]);
                assert_eq!(b[0], 17);
                let f =
                    frag(usize::from(field & 0xfff8), field & 1 != 0, u32::from_be_bytes(b[4..8].try_into().unwrap()));
                (f, b[8..].to_vec())
            })
            .collect()
    }

    #[test]
    fn fragments_fit_the_mtu_and_cover_the_payload() {
        let data = payload(5000);
        let all = pieces(&data, 1280, 9);
        assert_eq!(all.len(), 5);
        for (n, (f, d)) in all.iter().enumerate() {
            assert!(IPV6_HEADER_LEN + FRAGMENT_HEADER_LEN + d.len() <= 1280);
            assert_eq!(f.more, n + 1 < all.len());
            assert_eq!(f.offset, n * 1232);
            assert_eq!(f.ident, 9);
        }
        assert_eq!(all.iter().flat_map(|(_, d)| d.iter().copied()).collect::<Vec<_>>(), data);
        // An odd MTU rounds the pieces down to a multiple of 8.
        let odd = pieces(&data, 1501, 1);
        assert!(odd.iter().all(|(_, d)| d.len() % 8 == 0 || d.len() == odd.last().unwrap().1.len()));
        // An empty payload is one empty piece; too big or too small an MTU fail.
        assert_eq!(fragment(&[], 17, 1280, 1).unwrap().len(), 1);
        assert!(fragment(&data, 17, 1279, 1).is_none());
        assert!(fragment(&vec![0; 65535], 17, 1280, 1).is_some());
        assert!(fragment(&vec![0; 65536], 17, 1280, 1).is_none());
    }

    #[test]
    fn reassembles_out_of_order_and_duplicated_pieces() {
        let data = payload(4000);
        let mut all = pieces(&data, 1280, 5);
        all.reverse();
        let dup = all[1].clone();
        all.insert(2, dup);
        let mut r = Reassembler::new();
        let mut done = None;
        for (f, d) in &all {
            if let Some(x) = r.add(Instant::ZERO, A, B, *f, 17, d).unwrap() {
                assert!(done.replace(x).is_none());
            }
        }
        let got = done.unwrap();
        assert_eq!((got.src, got.dst, got.next_header), (A, B, 17));
        assert_eq!(got.data, data);
        assert!(r.is_empty());
        assert_eq!(r.held(), 0);
    }

    #[test]
    fn datagrams_are_told_apart_by_source_destination_and_ident() {
        let (d1, d2) = (payload(3000), payload(2999));
        let mut r = Reassembler::new();
        let mut out = Vec::new();
        let (p1, p2) = (pieces(&d1, 1280, 1), pieces(&d2, 1280, 2));
        for ((f1, x1), (f2, x2)) in p1.iter().zip(&p2) {
            out.extend(r.add(Instant::ZERO, A, B, *f1, 17, x1).unwrap());
            out.extend(r.add(Instant::ZERO, B, A, *f2, 17, x2).unwrap());
        }
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].data, d1);
        assert_eq!(out[1].data, d2);
    }

    #[test]
    fn overlap_discards_the_datagram() {
        let mut r = Reassembler::new();
        assert_eq!(r.add(Instant::ZERO, A, B, frag(0, true, 1), 17, &[1; 24]), Ok(None));
        assert_eq!(r.add(Instant::ZERO, A, B, frag(16, false, 1), 17, &[2; 24]), Err(Reject::Overlap));
        assert!(r.is_empty());
        // Overlap from the other side, and with different bytes at the same spot.
        assert_eq!(r.add(Instant::ZERO, A, B, frag(16, true, 2), 17, &[1; 16]), Ok(None));
        assert_eq!(r.add(Instant::ZERO, A, B, frag(0, true, 2), 17, &[1; 24]), Err(Reject::Overlap));
        assert_eq!(r.add(Instant::ZERO, A, B, frag(0, true, 3), 17, &[1; 16]), Ok(None));
        assert_eq!(r.add(Instant::ZERO, A, B, frag(0, true, 3), 17, &[9; 16]), Err(Reject::Overlap));
        assert!(r.is_empty());
    }

    #[test]
    fn contradictory_lengths_are_refused() {
        let mut r = Reassembler::new();
        assert_eq!(r.add(Instant::ZERO, A, B, frag(8, false, 1), 17, &[1; 8]), Ok(None));
        // Another end, and a piece past the end.
        assert_eq!(r.add(Instant::ZERO, A, B, frag(8, false, 1), 17, &[1; 16]), Err(Reject::Overlap));
        assert_eq!(r.add(Instant::ZERO, A, B, frag(8, false, 2), 17, &[1; 8]), Ok(None));
        assert_eq!(r.add(Instant::ZERO, A, B, frag(16, true, 2), 17, &[1; 8]), Err(Reject::Overlap));
        assert!(r.is_empty());
    }

    #[test]
    fn malformed_pieces_are_refused_without_a_trace() {
        let mut r = Reassembler::new();
        let t = Instant::ZERO;
        assert_eq!(r.add(t, A, B, frag(0, true, 1), 17, &[]), Err(Reject::Malformed));
        assert_eq!(r.add(t, A, B, frag(0, false, 1), 17, &[]), Err(Reject::Malformed));
        assert_eq!(r.add(t, A, B, frag(0, true, 1), 17, &[0; 13]), Err(Reject::Malformed));
        assert_eq!(r.add(t, A, B, frag(65528, false, 1), 17, &[0; 16]), Err(Reject::Malformed));
        assert_eq!(r.add(t, A, B, frag(usize::MAX - 7, false, 1), 17, &[0; 16]), Err(Reject::Malformed));
        assert!(r.is_empty());
    }

    #[test]
    fn a_datagram_without_its_first_piece_never_completes() {
        let mut r = Reassembler::new();
        assert_eq!(r.add(Instant::ZERO, A, B, frag(8, false, 1), 17, &[1; 8]), Ok(None));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn piece_and_size_limits_condemn_the_datagram() {
        let limits = Limits { pieces: 4, datagram_bytes: 64, ..Limits::default() };
        let mut r = Reassembler::with_limits(limits);
        let t = Instant::ZERO;
        for n in 0..4 {
            assert_eq!(r.add(t, A, B, frag(n * 8, true, 1), 17, &[0; 8]), Ok(None));
        }
        assert_eq!(r.add(t, A, B, frag(32, true, 1), 17, &[0; 8]), Err(Reject::TooBig));
        assert!(r.is_empty());
        assert_eq!(r.add(t, A, B, frag(64, false, 2), 17, &[0; 8]), Err(Reject::TooBig));
        assert!(r.is_empty());
    }

    #[test]
    fn memory_stays_within_the_budget_under_a_flood() {
        let limits = Limits { datagrams: 4, total_bytes: 1000, ..Limits::default() };
        let mut r = Reassembler::with_limits(limits);
        for ident in 0..1000u32 {
            // A million tries would be no different: the oldest go first.
            let _ = r.add(Instant::ZERO, A, B, frag(0, true, ident), 17, &[0; 400]);
            assert!(r.len() <= 4);
            assert!(r.held() <= 1000);
        }
        assert_eq!(r.len(), 2);
        // A piece too big for the whole budget is refused outright.
        let mut r = Reassembler::with_limits(limits);
        assert_eq!(r.add(Instant::ZERO, A, B, frag(0, true, 1), 17, &[0; 1008]), Err(Reject::TooBig));
        assert!(r.is_empty());
    }

    #[test]
    fn old_datagrams_time_out() {
        let mut r = Reassembler::new();
        r.add(Instant::ZERO, A, B, frag(0, true, 1), 17, &[0; 8]).unwrap();
        r.add(Instant::from_millis(30_000), A, B, frag(0, true, 2), 17, &[0; 8]).unwrap();
        assert_eq!(r.poll_at(), Some(Instant::from_millis(60_000)));
        assert_eq!(r.expire(Instant::from_millis(59_999)), 0);
        assert_eq!(r.expire(Instant::from_millis(60_000)), 1);
        assert_eq!(r.len(), 1);
        assert_eq!(r.expire(Instant::from_millis(90_000)), 1);
        assert_eq!(r.poll_at(), None);
    }

    #[test]
    fn shrinking_the_limits_evicts() {
        let mut r = Reassembler::new();
        for ident in 0..5 {
            r.add(Instant::ZERO, A, B, frag(0, true, ident), 17, &[0; 8]).unwrap();
        }
        r.set_limits(Limits { datagrams: 2, ..Limits::default() });
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn random_pieces_never_panic() {
        let mut r =
            Reassembler::with_limits(Limits { datagrams: 3, pieces: 16, total_bytes: 4096, ..Limits::default() });
        let mut x = 0x1234_5678_9abc_def0u64;
        for n in 0..20_000u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let len = (x >> 8) as usize % 40;
            let f = frag(((x >> 16) as usize % 64) * 8, x & 1 != 0, (x >> 4) as u32 % 6);
            let _ = r.add(Instant::from_millis(n), A, B, f, 17, &vec![x as u8; len]);
            r.expire(Instant::from_millis(n));
            assert!(r.held() <= 4096 && r.len() <= 3);
        }
    }
}
