// SPDX-License-Identifier: GPL-2.0-only
//! A Zstandard decoder (RFC 8878), for compressed extents.
//!
//! The whole output lives in the caller's buffer, which doubles as the match window, so the decoder needs no
//! window memory: only its entropy tables (about 9 KiB) and a literals buffer (up to 128 KiB), all on the heap.
//! Every input is treated as hostile: lengths are checked before use, bitstreams may not be read past their
//! start, table parameters are bounded, and work is linear in the input and output sizes.

use alloc::vec::Vec;

use crate::DecodeError;
use crate::xxhash::xxh64;

mod comp;
pub(crate) use comp::compress;

type Result<T> = core::result::Result<T, DecodeError>;

const CORRUPT: DecodeError = DecodeError::Corrupt;

/// Magic number of a Zstandard frame (section 3.1.1).
const FRAME_MAGIC: u32 = 0xFD2F_B528;
/// Magic number of a skippable frame, with the low four bits masked off (section 3.1.2).
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
/// The largest block, before or after decompression, unless the window is smaller (section 3.1.1.2).
const BLOCK_SIZE_MAX: u64 = 128 * 1024;

/// Decodes the zstd frames in `src` into `dst`; returns the bytes written.
///
/// Frames (and skippable frames) are decoded back to back. Decoding stops cleanly when the rest of the input
/// is all zeros (sector padding) or shorter than a frame magic; anything else that is not a frame is corrupt,
/// as is output that would not fit in `dst`.
pub(crate) fn decompress(src: &[u8], dst: &mut [u8]) -> Result<usize> {
    let mut dec = Decoder::new()?;
    let mut lits = Vec::new();
    let mut out = Out { dst, pos: 0, frame_start: 0, limit: 0 };
    let mut src = src;
    loop {
        // `all` stops at the first non-zero byte, which for a real frame is the first byte of its magic.
        if src.iter().all(|&b| b == 0) {
            return Ok(out.pos);
        }
        let Some((magic, rest)) = src.split_first_chunk::<4>() else { return Ok(out.pos) };
        let magic = u32::from_le_bytes(*magic);
        let used = if magic == FRAME_MAGIC {
            dec.frame(rest, &mut lits, &mut out)?
        } else if magic & !0xF == SKIPPABLE_MAGIC {
            let size = usize::try_from(le(rest, 0, 4)?).map_err(|_| CORRUPT)?;
            let used = size.checked_add(4).ok_or(CORRUPT)?;
            if used > rest.len() {
                return Err(CORRUPT);
            }
            used
        } else {
            return Err(CORRUPT);
        };
        src = rest.get(used..).ok_or(CORRUPT)?;
    }
}

/// The byte at `at`.
fn byte(src: &[u8], at: usize) -> Result<u8> {
    src.get(at).copied().ok_or(CORRUPT)
}

/// The `n`-byte (at most 8) little-endian integer at `at`.
fn le(src: &[u8], at: usize, n: usize) -> Result<u64> {
    let bytes = src.get(at..at.checked_add(n).ok_or(CORRUPT)?).ok_or(CORRUPT)?;
    if n > 8 {
        return Err(CORRUPT);
    }
    Ok(bytes.iter().rev().fold(0, |v, &b| v << 8 | u64::from(b)))
}

/// The `n` (at most 56) bits of `data` starting at bit `start`, counting from the least significant bit of the
/// first byte; bits past the end read as zero.
fn bits(data: &[u8], start: usize, n: u32) -> u64 {
    let (at, shift) = (start / 8, start % 8);
    let word = match data.get(at..).and_then(|t| t.first_chunk::<8>()) {
        Some(w) => u64::from_le_bytes(*w),
        None => {
            let mut w = [0u8; 8];
            for (d, s) in w.iter_mut().zip(data.get(at..).unwrap_or(&[])) {
                *d = *s;
            }
            u64::from_le_bytes(w)
        }
    };
    // shift <= 7 and n <= 56, so the field lies within `word`.
    (word >> shift) & ((1u64 << n.min(56)) - 1)
}

/// A bitstream read forwards from its first byte (FSE table descriptions, section 4.1.1). Reads past the end
/// return zeros; the caller checks how far it got.
struct Forward<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Forward<'_> {
    fn peek(&self, n: u32) -> u64 {
        bits(self.data, self.pos, n)
    }

    fn skip(&mut self, n: u32) {
        self.pos = self.pos.saturating_add(n as usize);
    }

    fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.skip(n);
        v
    }
}

/// A bitstream read backwards from its end (sections 4.1 and 4.2.2): the last byte's highest set bit marks
/// where the data stops, and fields are read from there towards bit 0 of the first byte.
struct Reverse<'a> {
    data: &'a [u8],
    /// Bits left to read.
    pos: usize,
}

impl<'a> Reverse<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        let last = *data.last().ok_or(CORRUPT)?;
        if last == 0 {
            return Err(CORRUPT);
        }
        let full = (data.len() - 1).checked_mul(8).ok_or(CORRUPT)?;
        Ok(Reverse { data, pos: full + 7 - last.leading_zeros() as usize })
    }

    /// The next `n` bits (at most 56) without consuming them; missing bits past the start read as zero.
    fn peek(&self, n: u32) -> u64 {
        let n = n.min(56);
        match self.pos.checked_sub(n as usize) {
            Some(start) => bits(self.data, start, n),
            // pos < n <= 56 here.
            None => bits(self.data, 0, self.pos as u32) << (n as usize - self.pos),
        }
    }

    fn consume(&mut self, n: u32) -> Result<()> {
        self.pos = self.pos.checked_sub(n as usize).ok_or(CORRUPT)?;
        Ok(())
    }

    /// Reads `n` bits; running past the start of the stream is corrupt.
    fn read(&mut self, n: u32) -> Result<u64> {
        let v = self.peek(n);
        self.consume(n)?;
        Ok(v)
    }

    /// Reads `n` bits, zero-filling past the start; also returns whether the stream overflowed.
    fn read_overflowing(&mut self, n: u32) -> (u64, bool) {
        let v = self.peek(n);
        match self.pos.checked_sub(n as usize) {
            Some(pos) => {
                self.pos = pos;
                (v, false)
            }
            None => {
                self.pos = 0;
                (v, true)
            }
        }
    }
}

/// One state of an FSE decoding table (section 4.1).
#[derive(Clone, Copy, Default)]
struct Cell {
    sym: u8,
    bits: u8,
    base: u16,
}

/// Most symbols in an FSE alphabet (match length codes, 0..=52).
const FSE_SYMBOLS: usize = 64;

/// Parses an FSE table description (section 4.1.1) into `norm`; returns the accuracy log, the number of
/// symbols described and the bytes used.
fn read_counts(src: &[u8], max_log: u32, max_sym: usize, norm: &mut [i16; FSE_SYMBOLS]) -> Result<(u32, usize, usize)> {
    let mut br = Forward { data: src, pos: 0 };
    let log = br.read(4) as u32 + 5;
    if log > max_log {
        return Err(CORRUPT);
    }
    *norm = [0; FSE_SYMBOLS];
    // Probabilities still to hand out (plus one), and the variable field width that encodes the next one.
    let mut remaining: i32 = (1 << log) + 1;
    let mut threshold: i32 = 1 << log;
    let mut nbits = log + 1;
    let mut sym = 0;
    while remaining > 1 {
        if sym > max_sym {
            return Err(CORRUPT);
        }
        // Values below `max` fit in nbits - 1 bits; the rest take nbits (section 4.1.1).
        let max = 2 * threshold - 1 - remaining;
        let low = br.peek(nbits - 1) as i32;
        let count = if low < max {
            br.skip(nbits - 1);
            low
        } else {
            let v = br.read(nbits) as i32;
            if v >= threshold { v - max } else { v }
        } - 1;
        // A probability of -1 ("less than 1") takes one slot.
        remaining -= count.abs();
        *norm.get_mut(sym).ok_or(CORRUPT)? = count as i16;
        sym += 1;
        if count == 0 {
            // A zero probability is followed by 2-bit repeat flags: that many more zeros, continuing while 3.
            loop {
                let run = br.read(2) as usize;
                sym += run;
                if sym > max_sym {
                    return Err(CORRUPT);
                }
                if run != 3 {
                    break;
                }
            }
        }
        while remaining < threshold && threshold > 1 {
            nbits -= 1;
            threshold >>= 1;
        }
    }
    let used = br.pos.div_ceil(8);
    if remaining != 1 || used > src.len() {
        return Err(CORRUPT);
    }
    Ok((log, sym, used))
}

/// Builds the decoding table for normalized counts `norm` (summing to `1 << log`) in `cells` (section 4.1.1).
fn build_fse(norm: &[i16], log: u32, cells: &mut [Cell]) -> Result<()> {
    let size = 1usize << log;
    let cells = cells.get_mut(..size).ok_or(CORRUPT)?;
    if norm.len() > FSE_SYMBOLS {
        return Err(CORRUPT);
    }
    // Symbols of probability -1 take one cell each at the top of the table.
    let mut next = [0u16; FSE_SYMBOLS];
    let mut high = size;
    for (sym, (&count, next)) in norm.iter().zip(next.iter_mut()).enumerate() {
        if count == -1 {
            high = high.checked_sub(1).ok_or(CORRUPT)?;
            *cells.get_mut(high).ok_or(CORRUPT)? = Cell { sym: sym as u8, bits: 0, base: 0 };
            *next = 1;
        } else {
            *next = u16::try_from(count).map_err(|_| CORRUPT)?;
        }
    }
    // The others are spread with a fixed step that visits every cell, skipping the top ones.
    let (step, mask) = ((size >> 1) + (size >> 3) + 3, size - 1);
    let mut p = 0;
    for (sym, &count) in norm.iter().enumerate() {
        for _ in 0..count.max(0) {
            cells.get_mut(p).ok_or(CORRUPT)?.sym = sym as u8;
            p = (1..=size).map(|i| (p + i * step) & mask).find(|&q| q < high).ok_or(CORRUPT)?;
        }
    }
    if p != 0 {
        return Err(CORRUPT);
    }
    // Each symbol's states, in table order, number count..2*count; state x reads enough bits to land back
    // in the table: bits = log - floor(log2 x), base = (x << bits) - size.
    for cell in cells.iter_mut() {
        let next = next.get_mut(cell.sym as usize).ok_or(CORRUPT)?;
        let x = u32::from(*next);
        *next = next.checked_add(1).ok_or(CORRUPT)?;
        let bits = log.checked_sub(x.checked_ilog2().ok_or(CORRUPT)?).ok_or(CORRUPT)?;
        let base = (x << bits).checked_sub(size as u32).ok_or(CORRUPT)?;
        *cell = Cell { sym: cell.sym, bits: bits as u8, base: u16::try_from(base).map_err(|_| CORRUPT)? };
    }
    Ok(())
}

/// An FSE table for one of the sequence fields, kept across blocks for the repeat mode.
struct Fse {
    cells: Vec<Cell>,
    log: u32,
    valid: bool,
}

/// A predefined distribution and the limits of one sequence field (sections 3.1.1.3.2.2 and 4.1.1).
struct Field {
    default: &'static [i16],
    default_log: u32,
    max_log: u32,
    max_sym: usize,
}

const LL_FIELD: Field = Field {
    default: &[
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1,
    ],
    default_log: 6,
    max_log: 9,
    max_sym: 35,
};
const ML_FIELD: Field = Field {
    default: &[
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
    ],
    default_log: 6,
    max_log: 9,
    max_sym: 52,
};
const OF_FIELD: Field = Field {
    default: &[1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1],
    default_log: 5,
    max_log: 8,
    max_sym: 31,
};

impl Fse {
    fn new(max_log: u32) -> Result<Self> {
        Ok(Fse { cells: table(1 << max_log)?, log: 0, valid: false })
    }

    /// Sets up the table for compression mode `mode` from the description at the start of `src`; returns the
    /// bytes used (section 3.1.1.3.2.1).
    fn load(&mut self, mode: u8, src: &[u8], field: &Field) -> Result<usize> {
        let repeat = self.valid;
        self.valid = false;
        let used = match mode {
            // Predefined.
            0 => {
                build_fse(field.default, field.default_log, &mut self.cells)?;
                self.log = field.default_log;
                0
            }
            // RLE: a single symbol, read with no bits.
            1 => {
                let sym = byte(src, 0)?;
                if sym as usize > field.max_sym {
                    return Err(CORRUPT);
                }
                *self.cells.first_mut().ok_or(CORRUPT)? = Cell { sym, bits: 0, base: 0 };
                self.log = 0;
                1
            }
            // FSE compressed.
            2 => {
                let mut norm = [0; FSE_SYMBOLS];
                let (log, n, used) = read_counts(src, field.max_log, field.max_sym, &mut norm)?;
                build_fse(norm.get(..n).ok_or(CORRUPT)?, log, &mut self.cells)?;
                self.log = log;
                used
            }
            // Repeat the previous block's table; there must be one in this frame.
            _ if repeat => 0,
            _ => return Err(CORRUPT),
        };
        self.valid = true;
        Ok(used)
    }

    fn cell(&self, state: u64) -> Result<Cell> {
        self.cells.get(usize::try_from(state).map_err(|_| CORRUPT)?).copied().ok_or(CORRUPT)
    }
}

/// A zeroed heap table of `len` entries.
fn table<T: Copy + Default>(len: usize) -> Result<Vec<T>> {
    let mut v = Vec::new();
    v.try_reserve_exact(len).map_err(|_| DecodeError::OutOfMemory)?;
    v.resize(len, T::default());
    Ok(v)
}

/// One entry of a Huffman decoding table, indexed by the next `max_bits` bits.
#[derive(Clone, Copy, Default)]
struct HufCell {
    sym: u8,
    bits: u8,
}

/// Longest Huffman code (section 4.2.1).
const HUF_MAX_BITS: u32 = 11;

/// The literals Huffman table, kept across blocks for treeless literals.
struct Huffman {
    cells: Vec<HufCell>,
    max_bits: u32,
    valid: bool,
}

impl Huffman {
    /// Reads a Huffman tree description (section 4.2.1) from the start of `src`; returns the bytes used.
    fn read_tree(&mut self, src: &[u8]) -> Result<usize> {
        self.valid = false;
        let mut weights = [0u8; 256];
        let header = byte(src, 0)? as usize;
        let (n, used) = if header < 128 {
            // FSE-compressed weights, `header` bytes (section 4.2.1.2).
            let body = src.get(1..1 + header).ok_or(CORRUPT)?;
            (fse_weights(body, &mut weights)?, 1 + header)
        } else {
            // header - 127 weights, 4 bits each, high nibble first.
            let n = header - 127;
            let body = src.get(1..1 + n.div_ceil(2)).ok_or(CORRUPT)?;
            for (i, w) in weights.iter_mut().take(n).enumerate() {
                let b = byte(body, i / 2)?;
                *w = if i % 2 == 0 { b >> 4 } else { b & 0xF };
            }
            (n, 1 + n.div_ceil(2))
        };
        self.build(&mut weights, n)?;
        Ok(used)
    }

    /// Builds the decoding table from the first `n` weights, deriving the last symbol's (section 4.2.1.3).
    fn build(&mut self, weights: &mut [u8; 256], n: usize) -> Result<()> {
        let mut total = 0u32;
        for &w in weights.get(..n).ok_or(CORRUPT)? {
            if w as u32 > HUF_MAX_BITS {
                return Err(CORRUPT);
            }
            if w > 0 {
                total += 1 << (w - 1);
            }
        }
        // The implied last weight brings the total to the next power of two, which must be a power of two away.
        let max_bits = total.checked_ilog2().ok_or(CORRUPT)? + 1;
        let rest = (1u32 << max_bits) - total;
        if max_bits > HUF_MAX_BITS || !rest.is_power_of_two() {
            return Err(CORRUPT);
        }
        let syms = n + 1;
        *weights.get_mut(n).ok_or(CORRUPT)? = rest.ilog2() as u8 + 1;
        let weights = weights.get(..syms).ok_or(CORRUPT)?;
        // A complete prefix code has an even number (at least two) of the longest codes.
        let ones = weights.iter().filter(|&&w| w == 1).count();
        if ones < 2 || ones % 2 != 0 {
            return Err(CORRUPT);
        }
        // Codes go to symbols in order of increasing weight, then of symbol value; a symbol of weight w covers
        // 2^(w-1) consecutive table entries.
        let mut at = 0;
        for w in 1..=max_bits {
            let (len, bits) = (1usize << (w - 1), (max_bits + 1 - w) as u8);
            for (sym, _) in weights.iter().enumerate().filter(|&(_, &x)| u32::from(x) == w) {
                let end = at + len;
                self.cells.get_mut(at..end).ok_or(CORRUPT)?.fill(HufCell { sym: sym as u8, bits });
                at = end;
            }
        }
        if at != 1 << max_bits {
            return Err(CORRUPT);
        }
        self.max_bits = max_bits;
        self.valid = true;
        Ok(())
    }

    /// Decodes one Huffman-coded stream (section 4.2.2), which must hold exactly `out.len()` symbols.
    fn decode(&self, data: &[u8], out: &mut [u8]) -> Result<()> {
        let mut br = Reverse::new(data)?;
        for o in out {
            let cell = self.cells.get(br.peek(self.max_bits) as usize).copied().ok_or(CORRUPT)?;
            *o = cell.sym;
            br.consume(cell.bits.into())?;
        }
        if br.pos != 0 {
            return Err(CORRUPT);
        }
        Ok(())
    }
}

/// Decodes FSE-compressed Huffman weights (section 4.2.1.2) into `out`; returns how many.
fn fse_weights(src: &[u8], out: &mut [u8; 256]) -> Result<usize> {
    // Weights are at most 11, so a description naming more symbols is not one an encoder makes.
    let mut norm = [0; FSE_SYMBOLS];
    let (log, n, used) = read_counts(src, 6, 12, &mut norm)?;
    let mut cells = [Cell::default(); 64];
    build_fse(norm.get(..n).ok_or(CORRUPT)?, log, &mut cells)?;
    let cell = |state: u64| cells.get(state as usize).copied().ok_or(CORRUPT);

    // Two interleaved states share the stream. When an update runs past the start of the stream, the other
    // state's current symbol is the last weight.
    let mut br = Reverse::new(src.get(used..).ok_or(CORRUPT)?)?;
    let (mut this, mut other) = (br.read(log)?, br.read(log)?);
    let mut n = 0;
    loop {
        let c = cell(this)?;
        *out.get_mut(n).filter(|_| n < 255).ok_or(CORRUPT)? = c.sym;
        n += 1;
        let (v, overflow) = br.read_overflowing(c.bits.into());
        if overflow {
            *out.get_mut(n).filter(|_| n < 255).ok_or(CORRUPT)? = cell(other)?.sym;
            n += 1;
            break;
        }
        // Alternate between the two states. At most 255 weights bound the loop.
        (this, other) = (other, u64::from(c.base) + v);
    }
    Ok(n)
}

/// Literal length codes 0..=35: baselines and extra bits (section 3.1.1.3.2.1.1).
const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024,
    2048, 4096, 8192, 16384, 32768, 65536,
];
const LL_BITS: [u8; 36] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

/// Match length codes 0..=52: baselines and extra bits (section 3.1.1.3.2.1.1).
const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539,
];
const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
    3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// A length field: its code's baseline plus the extra bits.
fn length(base: &[u32], bits: &[u8], code: u8, br: &mut Reverse) -> Result<usize> {
    let (base, bits) = (*base.get(code as usize).ok_or(CORRUPT)?, *bits.get(code as usize).ok_or(CORRUPT)?);
    Ok(base as usize + br.read(bits.into())? as usize)
}

/// The output buffer and how much of it is filled.
struct Out<'d> {
    dst: &'d mut [u8],
    pos: usize,
    /// Where the current frame's output starts: matches may not reach before it.
    frame_start: usize,
    /// Where the current block's output must end.
    limit: usize,
}

impl Out<'_> {
    /// Reserves `n` bytes at the end of the output.
    fn grow(&mut self, n: usize) -> Result<&mut [u8]> {
        let end = self.pos.checked_add(n).filter(|&end| end <= self.limit).ok_or(CORRUPT)?;
        let out = self.dst.get_mut(self.pos..end).ok_or(CORRUPT)?;
        self.pos = end;
        Ok(out)
    }

    fn put(&mut self, data: &[u8]) -> Result<()> {
        self.grow(data.len())?.copy_from_slice(data);
        Ok(())
    }

    /// Copies `len` bytes from `offset` back (section 3.1.1.4); the copy may overlap its own output.
    fn copy_match(&mut self, offset: usize, len: usize) -> Result<()> {
        if offset == 0 || offset > self.pos - self.frame_start {
            return Err(CORRUPT);
        }
        let (src, start) = (self.pos - offset, self.pos);
        self.grow(len)?;
        // The bytes from src to `at` repeat with period `offset`, so copying them forward doubles the run.
        let mut at = start;
        while at < self.pos {
            let n = (at - src).min(self.pos - at);
            let (head, tail) = self.dst.split_at_mut_checked(at).ok_or(CORRUPT)?;
            tail.get_mut(..n).ok_or(CORRUPT)?.copy_from_slice(head.get(src..src + n).ok_or(CORRUPT)?);
            at += n;
        }
        Ok(())
    }
}

/// Decoder state carried from block to block within a frame.
struct Decoder {
    ll: Fse,
    of: Fse,
    ml: Fse,
    huf: Huffman,
    /// Repeat offsets (section 3.1.1.5).
    reps: [usize; 3],
}

impl Decoder {
    fn new() -> Result<Self> {
        Ok(Decoder {
            ll: Fse::new(LL_FIELD.max_log)?,
            of: Fse::new(OF_FIELD.max_log)?,
            ml: Fse::new(ML_FIELD.max_log)?,
            huf: Huffman { cells: table(1 << HUF_MAX_BITS)?, max_bits: 0, valid: false },
            reps: [1, 4, 8],
        })
    }

    /// Decodes one frame from `src` (just past the magic); returns the bytes used.
    fn frame(&mut self, src: &[u8], lits: &mut Vec<u8>, out: &mut Out) -> Result<usize> {
        // Frame header (section 3.1.1.1).
        let fhd = byte(src, 0)?;
        let single_segment = fhd & 0x20 != 0;
        let checksum = fhd & 0x04 != 0;
        if fhd & 0x08 != 0 {
            return Err(CORRUPT);
        }
        let mut at = 1;
        let mut window = 0;
        if !single_segment {
            // Window descriptor: 2^(10 + exponent) plus mantissa eighths of that.
            let wd = byte(src, 1)?;
            let base = 1u64 << (10 + (wd >> 3));
            window = base + (base >> 3) * u64::from(wd & 7);
            at = 2;
        }
        let id_size = match fhd & 3 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        if le(src, at, id_size)? != 0 {
            return Err(CORRUPT); // No dictionaries.
        }
        at += id_size;
        let fcs_size = match fhd >> 6 {
            0 if single_segment => 1,
            0 => 0,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let content_size = match fcs_size {
            0 => None,
            2 => Some(le(src, at, 2)? + 256),
            n => Some(le(src, at, n)?),
        };
        at += fcs_size;
        if let Some(size) = content_size {
            if single_segment {
                window = size;
            }
            if size > (out.dst.len() - out.pos) as u64 {
                return Err(CORRUPT);
            }
        }
        let block_max = window.min(BLOCK_SIZE_MAX) as usize;

        self.reps = [1, 4, 8];
        self.ll.valid = false;
        self.of.valid = false;
        self.ml.valid = false;
        self.huf.valid = false;
        out.frame_start = out.pos;

        // Blocks (section 3.1.1.2), each with a 3-byte header.
        loop {
            let header = le(src, at, 3)?;
            at += 3;
            let size = (header >> 3) as usize;
            if size > block_max {
                return Err(CORRUPT);
            }
            out.limit = out.dst.len().min(out.pos.saturating_add(block_max));
            match (header >> 1) & 3 {
                0 => {
                    out.put(src.get(at..at + size).ok_or(CORRUPT)?)?;
                    at += size;
                }
                1 => {
                    let b = byte(src, at)?;
                    out.grow(size)?.fill(b);
                    at += 1;
                }
                // An empty compressed block has no literals section, but the reference streaming decoder (and so
                // Linux) accepts it as an empty block; so do we.
                2 if size == 0 => {}
                2 => {
                    self.block(src.get(at..at + size).ok_or(CORRUPT)?, block_max, lits, out)?;
                    at += size;
                }
                _ => return Err(CORRUPT),
            }
            if header & 1 != 0 {
                break;
            }
        }

        let produced = out.dst.get(out.frame_start..out.pos).ok_or(CORRUPT)?;
        if content_size.is_some_and(|size| size != produced.len() as u64) {
            return Err(CORRUPT);
        }
        if checksum {
            // The low 32 bits of the XXH64 of the frame's content (section 3.1.1).
            if le(src, at, 4)? != xxh64(produced, 0) & 0xFFFF_FFFF {
                return Err(CORRUPT);
            }
            at += 4;
        }
        Ok(at)
    }

    /// Decodes a compressed block (section 3.1.1.3).
    fn block(&mut self, block: &[u8], block_max: usize, buf: &mut Vec<u8>, out: &mut Out) -> Result<()> {
        let (lits, used) = literals(&mut self.huf, block, block_max, buf)?;
        let src = block.get(used..).ok_or(CORRUPT)?;

        // Sequences section header (section 3.1.1.3.2.1).
        let b0 = byte(src, 0)?;
        let (count, mut at) = match b0 {
            0..128 => (usize::from(b0), 1),
            128..255 => ((usize::from(b0 - 128) << 8) + usize::from(byte(src, 1)?), 2),
            255 => (usize::from(byte(src, 1)?) + (usize::from(byte(src, 2)?) << 8) + 0x7F00, 3),
        };
        if count == 0 {
            if at != src.len() {
                return Err(CORRUPT);
            }
            return out.put(lits);
        }
        let modes = byte(src, at)?;
        if modes & 3 != 0 {
            return Err(CORRUPT);
        }
        at += 1;
        // The tables come in the order literal lengths, offsets, match lengths.
        at += self.ll.load(modes >> 6, src.get(at..).ok_or(CORRUPT)?, &LL_FIELD)?;
        at += self.of.load((modes >> 4) & 3, src.get(at..).ok_or(CORRUPT)?, &OF_FIELD)?;
        at += self.ml.load((modes >> 2) & 3, src.get(at..).ok_or(CORRUPT)?, &ML_FIELD)?;

        // The sequences bitstream (section 3.1.1.3.2): initial states, then per sequence the offset, match
        // length and literal length extra bits, then (except after the last) the LL, ML and OF state updates.
        let mut br = Reverse::new(src.get(at..).ok_or(CORRUPT)?)?;
        let mut ll_state = br.read(self.ll.log)?;
        let mut of_state = br.read(self.of.log)?;
        let mut ml_state = br.read(self.ml.log)?;
        let mut lits = lits;
        for i in 0..count {
            let (ll_cell, of_cell, ml_cell) =
                (self.ll.cell(ll_state)?, self.of.cell(of_state)?, self.ml.cell(ml_state)?);
            // Offset codes are at most 31 (the table builders check), so this fits.
            let of_value = 1u64.checked_shl(of_cell.sym.into()).ok_or(CORRUPT)? + br.read(of_cell.sym.into())?;
            let ml = length(&ML_BASE, &ML_BITS, ml_cell.sym, &mut br)?;
            let ll = length(&LL_BASE, &LL_BITS, ll_cell.sym, &mut br)?;
            if i + 1 < count {
                ll_state = u64::from(ll_cell.base) + br.read(ll_cell.bits.into())?;
                ml_state = u64::from(ml_cell.base) + br.read(ml_cell.bits.into())?;
                of_state = u64::from(of_cell.base) + br.read(of_cell.bits.into())?;
            }

            // Repeat offsets (section 3.1.1.5): values 1-3 pick a recent offset, shifted by one when the literal
            // length is zero, the shifted 3 meaning the most recent offset minus one.
            let [r0, r1, r2] = self.reps;
            let offset = if of_value > 3 {
                let offset = usize::try_from(of_value - 3).map_err(|_| CORRUPT)?;
                self.reps = [offset, r0, r1];
                offset
            } else {
                match of_value as usize - usize::from(ll != 0) {
                    0 => r0,
                    1 => {
                        self.reps = [r1, r0, r2];
                        r1
                    }
                    2 => {
                        self.reps = [r2, r0, r1];
                        r2
                    }
                    _ => {
                        let offset = r0.checked_sub(1).filter(|&o| o != 0).ok_or(CORRUPT)?;
                        self.reps = [offset, r0, r1];
                        offset
                    }
                }
            };

            // Execute (section 3.1.1.4).
            let (now, rest) = lits.split_at_checked(ll).ok_or(CORRUPT)?;
            lits = rest;
            out.put(now)?;
            out.copy_match(offset, ml)?;
        }
        if br.pos != 0 {
            return Err(CORRUPT);
        }
        out.put(lits)
    }
}

/// Decodes the literals section (section 3.1.1.3.1) at the start of `block`; returns the literals (from the
/// block itself or decoded into `buf`) and the bytes used.
fn literals<'a>(huf: &mut Huffman, block: &'a [u8], max: usize, buf: &'a mut Vec<u8>) -> Result<(&'a [u8], usize)> {
    let b0 = byte(block, 0)?;
    let (kind, format) = (b0 & 3, (b0 >> 2) & 3);
    if kind < 2 {
        // Raw or RLE: a 5-, 12- or 20-bit size.
        let (header, size) = match format {
            0 | 2 => (1, usize::from(b0 >> 3)),
            1 => (2, usize::from(b0 >> 4) + (usize::from(byte(block, 1)?) << 4)),
            _ => (3, usize::from(b0 >> 4) + (usize::from(byte(block, 1)?) << 4) + (usize::from(byte(block, 2)?) << 12)),
        };
        if size > max {
            return Err(CORRUPT);
        }
        if kind == 0 {
            return Ok((block.get(header..header + size).ok_or(CORRUPT)?, header + size));
        }
        let b = byte(block, header)?;
        resize(buf, size)?;
        buf.fill(b);
        return Ok((buf, header + 1));
    }

    // Huffman-coded, with a new tree (2) or the previous one (3): regenerated and compressed sizes of 10, 10,
    // 14 or 18 bits; format 0 has one stream, the others four.
    let (header, width, four) = match format {
        0 => (3, 10, false),
        1 => (3, 10, true),
        2 => (4, 14, true),
        _ => (5, 18, true),
    };
    let h = le(block, 0, header)?;
    let mask = (1 << width) - 1;
    let (size, comp) = (((h >> 4) & mask) as usize, ((h >> (4 + width)) & mask) as usize);
    if size > max {
        return Err(CORRUPT);
    }
    let mut data = block.get(header..header + comp).ok_or(CORRUPT)?;
    if kind == 2 {
        data = data.get(huf.read_tree(data)?..).ok_or(CORRUPT)?;
    } else if !huf.valid {
        return Err(CORRUPT);
    }
    resize(buf, size)?;
    if !four {
        huf.decode(data, buf)?;
    } else {
        // A jump table of three 2-byte stream sizes (the fourth takes the rest); each of the first three
        // streams decodes ceil(size / 4) symbols (section 3.1.1.3.1.6).
        let ([a0, a1, b0, b1, c0, c1], streams) = data.split_first_chunk::<6>().ok_or(CORRUPT)?;
        let sizes = [u16::from_le_bytes([*a0, *a1]), u16::from_le_bytes([*b0, *b1]), u16::from_le_bytes([*c0, *c1])];
        let seg = size.div_ceil(4);
        let (mut streams, mut out) = (streams, buf.as_mut_slice());
        for len in sizes {
            let (s, rest) = streams.split_at_checked(len.into()).ok_or(CORRUPT)?;
            let (o, rest_out) = out.split_at_mut_checked(seg).ok_or(CORRUPT)?;
            huf.decode(s, o)?;
            (streams, out) = (rest, rest_out);
        }
        huf.decode(streams, out)?;
    }
    Ok((buf, header + comp))
}

/// Sets `buf` to `len` bytes, failing rather than aborting if memory runs out.
fn resize(buf: &mut Vec<u8>, len: usize) -> Result<()> {
    buf.clear();
    buf.try_reserve_exact(len).map_err(|_| DecodeError::OutOfMemory)?;
    buf.resize(len, 0);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use alloc::vec;

    // Vectors made with python-zstandard 0.25 (zstd 1.5.7) from the generators below, which match the Python
    // ones that made them byte for byte.

    /// `noise(1, 100)` at level 3: incompressible, so one raw block.
    const RAW: &str = "\
        28b52ffd2064210300414129256501710dff2ee489e6a3e47b2531af5cf0b9a2d97a9c69b76a0c1404381cf6fd52b80b2b3b59ab82c50252\
        86fbdab3ca0dc1d4035d15eb5a6832487ed0217bb3f2ed1020967f83da45cdea7fbd00a67d5f971a9649035bf55c1856021c869fc8";
    /// 3000 `z`s at level 3, flushed every 1000 bytes, with a checksum: a compressed block then RLE blocks.
    const RLE: &str = "\
        28b52ffd04584c0000107a7a0100e32b8005421f007a421f007a010000a8c9e479";
    /// `letters(2, 200)` at level 3, with a checksum: single-stream Huffman literals, predefined tables.
    const HUF1: &str = "\
        28b52ffd24c8bd030042471213a02739402c01cf342f6ce8343baaaaaa9efb0a94c9ee4376f8b71677240dcf47d7a71015b6b195c6699762\
        3858e0b69399de3528bb912692534798f3767c23274042041171311e08110044c500265cd6c0812573d116c48626162942480977675a8969\
        e84c6bacf6126190ce605286f6b23906da56d844";
    /// 300 bytes `noise(6, 300) % 7` at level 3: directly encoded Huffman weights, four streams, RLE ML table.
    const DIRECT: &str = "\
        28b52ffd602c002d040006d019852111111800170017009d2e223c60d94cfab829009162cd63f832b52b94a03c1c0137c0d07580c8bb98e1\
        eda344f94c2b6a89ab55934b3a31d48c8a5feac029e1a81a71456bb391b9a77c07d06a8a255cbbbedb31ec88d47262a0c57121d8776b5408\
        5b8b7a350b04015d53760cf19760cf24d6cce60169e1c289e20a03f0a28a02";
    /// `letters(3, 700)` at level 1: four-stream Huffman literals, FSE-compressed weights and tables.
    const L1: &str = "\
        28b52ffd60bc01d50a0016183315a025c901c17d029ed2d7c45d2d594b555555cfe6082f002e002c004361c54caf1aa90a0a8860be8f3231\
        0e20fab689c8de0ed9c6df8ed9dbc6a52134c2b90f4cfc06e5d001021648b7f1dd2f17190a2b6692d008c3d2dc54d66f5eaf0f8515545589\
        3628c9d9bc00010b2eb3eb8bfda1b06264b6718d45068446d8656299bc49228b502db7f1f2bb35a63d1456b8f745de8eca2f9200010b3424\
        d50dcad932ff3e1b9473956d7c955ce8ea9acf29ffa8aa6f4223d0abdc5be5f4fff427e7d14cd3d6a6445e79d4d190d72c3a20101c23593e\
        85020fe520d20c95f7fe51f49c2beebc2b2ef36f1aa0a83f9b8109f3d360362e611cdc951b0ddb9617c75186bfd9bd80a21c509b66c0c1e6\
        387719f47dab5536c3d90fdb415b46d10d7b8f48b928d818f6dc4077ae1957f3f80a8ee1bb00a6f9f4ae8c357c8d66dbcc23703868f02ab3\
        f72ab5b55d79e50d542791d3416d8d107e2ee004";
    /// `letters(3, 700)` at level 3, with a checksum.
    const L3: &str = "\
        28b52ffd64bc01ed090096132812b0a772802d87252dc1722835894992a4a220280022001f00b1c6c08211e2bac5b87078c07249daa6bd3d\
        c8967478128568e0d40d145e0265d0040526acd2e101df37992c4403c1d2a6a253dfe74cd32c6448d627bbfeecc722e190000732c8b4d404\
        217d9a638aa5648b37a66579dd61c2b4dddbdfba7f5982642a7bf1eb21570fdd3eba79e271ee8f34f54dab71ef2cfa93722494686b33db1b\
        47de48904f4ea8e12ce71873a92869372042a39c3c0f1070cc073c2a7df2a14231f0e49386aae7d77362a7f02d489a1b4203c81f1accf7c3\
        008fc72c177fdc19eb1d748ef3aa9bb942e5c820d9b2773ffaa62c964b2ce260e4547989ad00f00ff673aab9f3e0916904fcd78946f1d429\
        a0fb2b62c0e8890ec9ef52d27fb7b576a4355b665747e226b26626f0b482d24f5505e5897480813e48d040fc336e15021f556c";
    /// `letters(3, 700)` at level 15, without the content size.
    const L15: &str = "\
        28b52ffd0000dd090056d42911b019c6e08e0909b598b1d0a0244992821229002400210005262618d7c598807860b9242dd35bc424c4df22\
        644b423c1984c870ea0a85d7a01cf42161c12a211e1c2c4d8d4ebd64f539879b66d1a02487647db2ebcffed89010cf7048c04205995633d6\
        049e62298bb7f16929215e5e778669bbf7b7ee5f9641328dec8d5f1f72f54fdf6406ddced17c7c70ff4853dfb41af7fe3f9a9f94478632da\
        daddde78a46390cf903e2d48a8111d539049a6280569391010814290a9071038b6073c0aeae250b73cc2cbf5a5f4d0ea5e58971db25f7eb4\
        16be0ca8e92f864d81f9eea2a865eab6cc9ebbbc3f402b12548ee044c3fd2508d665321fb207f394300024cfb9ffd244d70c2db60b64ae8a\
        9b0cdf56d8f72a7f6006b380fe1dc62fcb56d076be35631cfa363c93bc99d975abe6a53f5a70ff83d0c36e15";
    /// `letters(3, 700)` at level 19, with a checksum.
    const L19: &str = "\
        28b52ffd64bc01c5090036932711b019c6e08e0909b598b1d0a02449928212260021001f006b0a4c4c30ae8b3101f1c072495aa6bd45c896\
        8478320891e1d4150aaf4139e843c28255423cfb269383a5a9d1a997acfe1c6e9a851c92f5c9ae3ffb6323c321010b15645acd08d33cc552\
        166fe3d35242bcbcee0cd376ef6fddbf2c83641ad91bbf3ee4ea0fddced17c7c70ff4853dfb41af7fe3f9a9f94478632dadaddde78a46390\
        cf901e4ca80121738e51b528853603101881428ea9071040b6073c0aeafa50373cc6cbfdd27a48753bd8ceceb70bdf42ab5f3674cc17c3e6\
        c27c7711aca5725066cf1d5e1a6015e9548ae644d2fdb91eb764b03f7a93795cd801664fb09f69ce0bc687110247d7f72688b7ad40775bbe\
        604064371d1fcdaee21781d6f218d3fc6c74904b6da65683a7ffbd6ed45f94a6db07388362c6faa7bb2a021f556c";
    /// `letters(4, 2000)` at level 19, flushed every 400 bytes, with a checksum: treeless literals and repeated
    /// LL, OF and ML tables in later blocks, and an empty last raw block.
    const BLOCKS: &str = "\
        28b52ffd04680c0600328c1a11c01b0e582db9882c59e11b6eaeaaca9c1b448cc6d03ae57fa63c174be2feafde389778b6fcec439ad72191\
        df6fb99fbaac1aaa69ad367e95475242d7f645200f6a56c3ed27793ad36cb7c0c282646f2f2a1a1ade46cabe7e9288d1e060da5c9d13aff0\
        2dcd149454082828204400d5ed0110708c35064e48439b32880387730a2f3b68405ed7b6f39666800aae1846abb21f70781c597b164b8d7a\
        0d7e546bd038b18a515ce02b5bd3188ceea5383a7504b05724937b76310cd258f62704050023890f342b9aead89c615df2d0dcf669ef7a59\
        dc5cde14998ae4b3a8a57764d38b1ffacc642a7d76fda1d5d8dea8abb75eeffca159a73853449bbfffdbcd2b490c32aca0c6c8c603200282\
        1c4a3eac6c033c434d7f424aa0a47f2f09df6348071d08a6891fd94e6eb5fcfa24f205ffda4148bba661fc6275c9b5f226a059dfaa9247fc\
        6ed41d9c13fafbc99c44d1b42802ce493d474dd2e4c2b45ddd52e61e161c0500d3c910498593c7edb0dc3a49a5f564929bab741b29915967\
        e7533df489e49e3c646eee95a66d0d6d7ef3a5a9875aae9188f47b68db3b3a67f3eb2d4f558df87a3392a7d8552b2dac500a61551d308618\
        546637cba834a9ea0494402cfb3b1e20f8776f151ef6e5eb2c6cc248ba9fd1a8fd8e9387ebad795583ba8c2bb7aa9cc2f0fdf3bd6a8136aa\
        62fd00dfbce74649249ee4df140546552edb3bc4ebd869d4cc2127d4040023080e355bf7b5feaccaba67b45bf3991a793ab4d3987f67a81f\
        b986b33f93b32a7a57ee87543369bf49444e975a53db2a2253e9c4de67a9e6050532f810404eeb67d3dfcf0d28f0c997bf019c629af14d40\
        59fd57f0c6052490237134e08ecadbbb4246c86e152a1828100d1c5e53f3cc19dc2ed340540e5edb14f46943a7ce32068b9cccc299b04edc\
        366287cb3d0182ac0239debd076373049c040073870ce7ba926d1aff54178ba58da556d598abaac9f5d2df7a6758ebe8e33aa6b724cd3e33\
        fdd4cd71d1b4e8d6756fdb508b38abd934fc50023f05d017b300fba1dd408e9c5760e5fff57958414ae22ce008c4f9637131105689391dd3\
        7c0f7169941f90af9a546150e68ef522e9cd2b5318beed31f4e2f817b971a1b905bc074f8a17621a60597646158f0ebd2e723981c2010100\
        00586039c4";
    /// `large()` (300 KiB) at level 19, with a checksum: three blocks, two of them full size.
    const LARGE: &str = "\
        28b52ffda400b00400dc0700f2c20a11b0eb60141624733030513e0c13dd6e8e01f8b588b21904efc8abbacccadae1cdafbb8b783ad13c56\
        8d8571a8c12b1436f60e2044801833e3cc011240400b60020668c48188b9ffff1f6bfdbf03406a01fc7b0011faaeb71a78c91b5ec472c27f\
        e67a4e061af5780840cf9101591c0b08bcc9da85372655b10bd9a6b2013f34c653822c7010f7b4c4a132ffc078a0ab02ec9f769662fa2174\
        2f7768c01837533d760582a0c884f97e1113376f767dd7328f84ac47a9690b83627337bb001167f69f19dd19da76bd9c7006a3de06e045fe\
        96513e6c396839c5c7e5f0bdf0dba3e0120431183c02da04c4cdaaa432c1b2259ee011174d5103540000000100fdff0300f2080445000000\
        0100fd2f1d000181de1683";
    /// `deletions()` at level 19: repeat offsets, including "most recent minus one".
    const REPM1: &str = "\
        28b52ffd60a1033d060012c30a10b0eb600cc392391818560dc354be3c06cf5ce7e83b176133a3253895957551d5d8a8bd5e93c453f08c02\
        54a8b12b29d6d80e204c60caca36122816a00420011642e11bd19860269ce0262cec2ba6d0adee0dc9f1f0fbb04c8637f67a5a5e67dc9236\
        524abab6de245bd93fb1968f66941c678263b385da22f5a317e1426efe0e23def7ba24cfb04ee62fb8385cef102be1e6126ab2e76f56f329\
        52ab668055f05943cb570b2e05aa0dbc3e51515c1f1cc048b400a5678ba749f532dc1875f1c78da802";

    /// xorshift64.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    const WORDS: [&[u8]; 10] =
        [b"extent", b"inode", b"btrfs", b"tree", b"chunk", b"csum", b"root", b"node", b"leaf", b"key\n"];

    /// Space-separated words.
    fn text(seed: u64, n: usize) -> Vec<u8> {
        let mut r = Rng(seed);
        let mut out = Vec::new();
        while out.len() < n {
            out.extend_from_slice(WORDS[(r.next() % 10) as usize]);
            out.push(b' ');
        }
        out.truncate(n);
        out
    }

    /// Words separated by runs of random letters, so most bytes end up as Huffman-coded literals.
    fn letters(seed: u64, n: usize) -> Vec<u8> {
        let mut r = Rng(seed);
        let mut out = Vec::new();
        while out.len() < n {
            out.extend_from_slice(WORDS[(r.next() % 10) as usize]);
            for _ in 0..r.next() % 8 {
                out.push(b"etaoinsh"[(r.next() % 8) as usize]);
            }
        }
        out.truncate(n);
        out
    }

    fn noise(seed: u64, n: usize) -> Vec<u8> {
        let mut r = Rng(seed);
        (0..n).map(|_| r.next() as u8).collect()
    }

    /// A 1 KiB chunk of text repeated to 300 KiB, with a marker every 16 KiB.
    fn large() -> Vec<u8> {
        let mut out = text(5, 1024).repeat(300);
        for i in (0..out.len()).step_by(16384) {
            out[i] = b'#';
        }
        out
    }

    /// Text followed by a copy with a byte deleted every 40 or so.
    fn deletions() -> Vec<u8> {
        let base = text(9, 600);
        let mut copy = base.clone();
        let mut r = Rng(11);
        for i in (1..copy.len()).rev().step_by(40) {
            copy.remove(i - (r.next() % 20) as usize);
        }
        [base, copy].concat()
    }

    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes().chunks(2).map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
    }

    /// Decodes `src` into exactly-sized, larger and too small buffers.
    fn check(src: &[u8], want: &[u8]) {
        let mut dst = vec![0; want.len() + 100];
        assert_eq!(decompress(src, &mut dst[..want.len()]), Ok(want.len()));
        assert!(dst[..want.len()] == *want);
        assert_eq!(decompress(src, &mut dst), Ok(want.len()));
        if !want.is_empty() {
            assert_eq!(decompress(src, &mut dst[..want.len() - 1]), Err(CORRUPT));
        }
    }

    fn all() -> [(&'static str, Vec<u8>); 11] {
        let small = noise(6, 300).iter().map(|b| b % 7).collect();
        [
            (RAW, noise(1, 100)),
            (RLE, vec![b'z'; 3000]),
            (HUF1, letters(2, 200)),
            (DIRECT, small),
            (L1, letters(3, 700)),
            (L3, letters(3, 700)),
            (L15, letters(3, 700)),
            (L19, letters(3, 700)),
            (BLOCKS, letters(4, 2000)),
            (LARGE, large()),
            (REPM1, deletions()),
        ]
    }

    #[test]
    fn vectors() {
        for (src, want) in all() {
            check(&unhex(src), &want);
        }
    }

    #[test]
    fn checksum_mismatch() {
        let mut src = unhex(L3);
        *src.last_mut().unwrap() ^= 1;
        assert_eq!(decompress(&src, &mut [0; 700]), Err(CORRUPT));
    }

    #[test]
    fn concatenated_and_padded() {
        // A frame, a skippable frame, another frame and sector padding.
        let mut src = unhex(RAW);
        src.extend_from_slice(&[0x5A, 0x2A, 0x4D, 0x18, 3, 0, 0, 0, 1, 2, 3]);
        src.extend_from_slice(&unhex(HUF1));
        src.resize(src.len() + 300, 0);
        check(&src, &[noise(1, 100), letters(2, 200)].concat());

        // Too short to hold a magic: ignored.
        let mut short = unhex(HUF1);
        short.extend_from_slice(&[1, 2, 3]);
        assert_eq!(decompress(&short, &mut [0; 200]), Ok(200));

        // Anything else is not.
        let mut junk = unhex(HUF1);
        junk.extend_from_slice(&[0, 0, 0, 0, 1]);
        assert_eq!(decompress(&junk, &mut [0; 200]), Err(CORRUPT));
        let mut truncated_skip = unhex(HUF1);
        truncated_skip.extend_from_slice(&[0x50, 0x2A, 0x4D, 0x18, 9, 0, 0, 0, 1]);
        assert_eq!(decompress(&truncated_skip, &mut [0; 200]), Err(CORRUPT));
        assert_eq!(decompress(&[], &mut [0; 1]), Ok(0));
    }

    /// A frame with a 1 KiB window, an optional 4-byte content size and a dictionary ID field of `did.len()`
    /// bytes.
    fn frame(size: Option<u32>, did: &[u8], blocks: &[&[u8]]) -> Vec<u8> {
        let fcs = size.map(u32::to_le_bytes);
        let fhd = if fcs.is_some() { 0x80 } else { 0 } | if did.is_empty() { 0 } else { 1 };
        [&[0x28, 0xB5, 0x2F, 0xFD, fhd, 0][..], did, fcs.as_ref().map_or(&[], |f| &f[..]), &blocks.concat()].concat()
    }

    /// "abc" as a raw block that is not the last.
    const ABC: &[u8] = &[3 << 3, 0, 0, b'a', b'b', b'c'];
    /// The last block: compressed, no literals and one sequence (RLE tables: LL 0, offset code 2, ML 3) whose
    /// two offset bits make offset 3.
    const MATCH3: &[u8] = &[7 << 3 | 2 << 1 | 1, 0, 0, 0x00, 0x01, 0x54, 0x00, 0x02, 0x00, 0b110];
    /// The same with offset 1.
    const MATCH1: &[u8] = &[7 << 3 | 2 << 1 | 1, 0, 0, 0x00, 0x01, 0x54, 0x00, 0x02, 0x00, 0b100];

    #[test]
    fn handmade() {
        check(&frame(Some(6), &[], &[ABC, MATCH3]), b"abcabc");
        check(&frame(Some(6), &[0], &[ABC, MATCH1]), b"abcccc");
        // Dictionaries are not supported.
        assert_eq!(decompress(&frame(Some(6), &[7], &[ABC, MATCH3]), &mut [0; 6]), Err(CORRUPT));
        // The content size must match.
        assert_eq!(decompress(&frame(Some(5), &[], &[ABC, MATCH3]), &mut [0; 6]), Err(CORRUPT));
        // A match may not reach into an earlier frame.
        let two = [frame(Some(6), &[], &[ABC, MATCH3]), frame(None, &[], &[MATCH3])].concat();
        assert_eq!(decompress(&two, &mut [0; 9]), Err(CORRUPT));
        // The reserved header bit and block type.
        let mut reserved = frame(Some(6), &[], &[ABC, MATCH3]);
        reserved[4] |= 0x08;
        assert_eq!(decompress(&reserved, &mut [0; 6]), Err(CORRUPT));
        assert_eq!(decompress(&frame(None, &[], &[&[3 << 1 | 1, 0, 0]]), &mut [0; 6]), Err(CORRUPT));
        // An empty frame.
        check(&frame(Some(0), &[], &[&[1, 0, 0]]), b"");
        // Blocks may not be larger than the window.
        let big = [&[0x28, 0xB5, 0x2F, 0xFD, 0x20, 6][..], ABC, MATCH3].concat();
        assert_eq!(decompress(&big, &mut [0; 6]), Err(CORRUPT));
    }

    /// Mutated and truncated vectors must fail cleanly or decode within bounds.
    #[test]
    fn hostile() {
        let mut r = Rng(0x2545_F491_4F6C_DD1D);
        let vectors: Vec<_> =
            all().into_iter().filter(|(v, _)| *v != LARGE).map(|(v, w)| (unhex(v), w.len())).collect();
        let mut buf = vec![0u8; 4096];
        for _ in 0..30_000 {
            let (src, len) = &vectors[(r.next() % vectors.len() as u64) as usize];
            let mut src = src.clone();
            for _ in 0..1 + r.next() % 4 {
                let at = (r.next() % src.len() as u64) as usize;
                match r.next() % 4 {
                    0 => src[at] ^= 1 << (r.next() % 8),
                    1 => src[at] = r.next() as u8,
                    2 => src.truncate(at),
                    _ => src.insert(at, r.next() as u8),
                }
                if src.is_empty() {
                    break;
                }
            }
            let dst_len = match r.next() % 3 {
                0 => *len,
                1 => (r.next() % 4096) as usize,
                _ => 4000,
            };
            buf.fill(0xA5);
            if let Ok(n) = decompress(&src, &mut buf[..dst_len]) {
                assert!(n <= dst_len);
            }
            assert!(buf[dst_len..].iter().all(|&b| b == 0xA5));
        }
    }
}
