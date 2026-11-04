//! zlib decompression (RFC 1950 framing around RFC 1951 deflate), as btrfs
//! stores it: one zlib stream per extent.
//!
//! The decoder is canonical-Huffman and bit-at-a-time, in the style of zlib's
//! `contrib/puff`: small tables (well under 2 KiB of stack), no allocation, and
//! the output buffer doubles as the history window.

use crate::DecodeError::{self, Corrupt};

/// Longest Huffman code deflate allows.
const MAX_BITS: usize = 15;
/// Literal/length symbols (286 and 287 appear only in the fixed code).
const MAX_LCODES: usize = 288;
/// Distance symbols (30 and 31 appear only in the fixed code).
const MAX_DCODES: usize = 32;

/// Base lengths and extra bits for length symbols 257..=285.
pub(crate) const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
pub(crate) const LEN_EXTRA: [u8; 29] =
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
/// Base distances and extra bits for distance symbols 0..=29.
pub(crate) const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
pub(crate) const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
/// Order in which the code length code lengths are sent.
const CL_ORDER: [u8; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Decompresses the zlib stream in `src` into `dst`, returning the bytes
/// written. Output that would not fit in `dst` is corruption; bytes after the
/// Adler-32 trailer are ignored.
pub(crate) fn decompress(src: &[u8], dst: &mut [u8]) -> Result<usize, DecodeError> {
    let [cmf, flg, ..] = *src else { return Err(Corrupt) };
    // CM 8 (deflate), a window of at most 32 KiB, a valid check, no preset dictionary.
    if cmf & 0x0f != 8 || cmf >> 4 > 7 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 || flg & 0x20 != 0 {
        return Err(Corrupt);
    }
    let mut s = Inflate { src, pos: 2, bits: 0, nbits: 0, dst, out: 0 };
    loop {
        let last = s.bits(1)?;
        match s.bits(2)? {
            0 => s.stored()?,
            1 => s.fixed()?,
            2 => s.dynamic()?,
            _ => return Err(Corrupt),
        }
        if last == 1 {
            break;
        }
    }
    // The trailer is byte aligned; fewer than 8 bits are ever buffered, so
    // dropping them is the alignment.
    let trailer = src.get(s.pos..).and_then(|t| t.first_chunk::<4>()).ok_or(Corrupt)?;
    let written = s.dst.get(..s.out).ok_or(Corrupt)?;
    if u32::from_be_bytes(*trailer) != adler32(written) {
        return Err(Corrupt);
    }
    Ok(s.out)
}

/// The Adler-32 checksum of `data`.
pub(crate) fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    // 5552 bytes is the most that cannot overflow `b` before the reduction.
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += u32::from(x);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    b << 16 | a
}

/// A canonical Huffman code: the number of codes of each length, and the
/// symbols ordered by code (length first, then symbol value).
struct Huffman<const N: usize> {
    count: [u16; MAX_BITS + 1],
    symbol: [u16; N],
}

impl<const N: usize> Huffman<N> {
    /// Builds the code for the symbol code lengths `lengths` (at most `N`;
    /// 0 means unused). Returns the code and how many codes of the longest
    /// length are left unassigned: 0 for a complete code, more for an
    /// incomplete one. An oversubscribed code is corruption.
    fn new(lengths: &[u8]) -> Result<(Self, u32), DecodeError> {
        let mut h = Huffman { count: [0; MAX_BITS + 1], symbol: [0; N] };
        for &len in lengths {
            *h.count.get_mut(usize::from(len)).ok_or(Corrupt)? += 1;
        }
        // Check the counts against the code space, one length at a time.
        let mut left: u32 = 1;
        for &count in h.count.iter().skip(1) {
            left = (left << 1).checked_sub(u32::from(count)).ok_or(Corrupt)?;
        }
        // Offsets of the first symbol of each length in `symbol`.
        let (mut offs, mut sum) = ([0u16; MAX_BITS + 1], 0);
        for (off, &count) in offs.iter_mut().zip(&h.count).skip(1) {
            *off = sum;
            sum += count;
        }
        for (sym, &len) in lengths.iter().enumerate() {
            if len != 0 {
                let off = offs.get_mut(usize::from(len)).ok_or(Corrupt)?;
                *h.symbol.get_mut(usize::from(*off)).ok_or(Corrupt)? = sym as u16;
                *off += 1;
            }
        }
        Ok((h, left))
    }

    /// True if no symbol has a code longer than one bit (so the code holds at
    /// most two symbols). zlib accepts such a code even when incomplete.
    fn at_most_one_bit(&self) -> bool {
        self.count.iter().skip(2).all(|&c| c == 0)
    }
}

/// The decoder state.
struct Inflate<'src, 'dst> {
    src: &'src [u8],
    /// Next unread byte of `src`.
    pos: usize,
    /// Buffered bits, least significant first; never more than 7 between calls.
    bits: u32,
    nbits: u32,
    dst: &'dst mut [u8],
    /// Bytes written to `dst`.
    out: usize,
}

impl Inflate<'_, '_> {
    /// Takes the next `n` (at most 16) bits, least significant first.
    fn bits(&mut self, n: u32) -> Result<u32, DecodeError> {
        while self.nbits < n {
            let byte = *self.src.get(self.pos).ok_or(Corrupt)?;
            self.pos += 1;
            self.bits |= u32::from(byte) << self.nbits;
            self.nbits += 8;
        }
        let v = self.bits & ((1 << n) - 1);
        self.bits >>= n;
        self.nbits -= n;
        Ok(v)
    }

    /// Decodes one symbol. Huffman codes are packed most significant bit
    /// first, so they are read a bit at a time.
    fn decode<const N: usize>(&mut self, h: &Huffman<N>) -> Result<usize, DecodeError> {
        // `code` is the bits read so far; `first` the first code of length
        // `len`; `index` the position of that code's symbol in `h.symbol`.
        let (mut code, mut first, mut index) = (0usize, 0usize, 0usize);
        for &count in h.count.iter().skip(1) {
            code |= self.bits(1)? as usize;
            let count = usize::from(count);
            if code < first + count {
                return h.symbol.get(index + (code - first)).map(|&s| usize::from(s)).ok_or(Corrupt);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        // Ran past the longest length: a code that an incomplete set left unused.
        Err(Corrupt)
    }

    /// A stored (uncompressed) block.
    fn stored(&mut self) -> Result<(), DecodeError> {
        self.bits = 0;
        self.nbits = 0;
        let header = self.src.get(self.pos..).and_then(|t| t.first_chunk::<4>()).ok_or(Corrupt)?;
        let [l0, l1, n0, n1] = *header;
        let len = u16::from_le_bytes([l0, l1]);
        if len != !u16::from_le_bytes([n0, n1]) {
            return Err(Corrupt);
        }
        let (start, len) = (self.pos + 4, usize::from(len));
        let data = self.src.get(start..start + len).ok_or(Corrupt)?;
        self.dst.get_mut(self.out..).and_then(|d| d.get_mut(..len)).ok_or(Corrupt)?.copy_from_slice(data);
        self.pos = start + len;
        self.out += len;
        Ok(())
    }

    /// A block with the fixed codes of RFC 1951 section 3.2.6.
    fn fixed(&mut self) -> Result<(), DecodeError> {
        let mut lengths = [0u8; MAX_LCODES];
        for (sym, len) in lengths.iter_mut().enumerate() {
            *len = match sym {
                0..144 => 8,
                144..256 => 9,
                256..280 => 7,
                _ => 8,
            };
        }
        let (lit, _) = Huffman::<MAX_LCODES>::new(&lengths)?;
        let (dist, _) = Huffman::<MAX_DCODES>::new(&[5; MAX_DCODES])?;
        self.codes(&lit, &dist)
    }

    /// A block with dynamic codes, described at its start.
    fn dynamic(&mut self) -> Result<(), DecodeError> {
        let nlen = self.bits(5)? as usize + 257;
        let ndist = self.bits(5)? as usize + 1;
        let ncode = self.bits(4)? as usize + 4;
        if nlen > 286 || ndist > 30 {
            return Err(Corrupt);
        }
        // The code length code, which must be complete.
        let mut lengths = [0u8; MAX_LCODES + MAX_DCODES];
        for &sym in CL_ORDER.iter().take(ncode) {
            *lengths.get_mut(usize::from(sym)).ok_or(Corrupt)? = self.bits(3)? as u8;
        }
        let (cl, left) = Huffman::<19>::new(lengths.get(..19).ok_or(Corrupt)?)?;
        if left != 0 {
            return Err(Corrupt);
        }
        // The literal/length and distance code lengths, as one sequence:
        // repeats may run from one into the other.
        let total = nlen + ndist;
        let mut i = 0;
        while i < total {
            let sym = self.decode(&cl)?;
            let (len, repeat) = match sym {
                0..16 => (sym as u8, 1),
                16 => (*lengths.get(i.wrapping_sub(1)).ok_or(Corrupt)?, 3 + self.bits(2)? as usize),
                17 => (0, 3 + self.bits(3)? as usize),
                _ => (0, 11 + self.bits(7)? as usize),
            };
            if repeat > total - i {
                return Err(Corrupt);
            }
            lengths.get_mut(i..i + repeat).ok_or(Corrupt)?.fill(len);
            i += repeat;
        }
        let (lit_lengths, dist_lengths) = lengths.split_at_checked(nlen).ok_or(Corrupt)?;
        let dist_lengths = dist_lengths.get(..ndist).ok_or(Corrupt)?;
        // A block must be able to end.
        if lit_lengths.get(256).is_none_or(|&l| l == 0) {
            return Err(Corrupt);
        }
        // Like zlib, an incomplete code is only accepted when it has a single
        // one-bit code (or, for distances, none at all); decoding one of the
        // missing codes is then corruption.
        let (lit, left) = Huffman::<MAX_LCODES>::new(lit_lengths)?;
        if left != 0 && !lit.at_most_one_bit() {
            return Err(Corrupt);
        }
        let (dist, left) = Huffman::<MAX_DCODES>::new(dist_lengths)?;
        if left != 0 && !dist.at_most_one_bit() {
            return Err(Corrupt);
        }
        self.codes(&lit, &dist)
    }

    /// The compressed data of a block, up to and including end-of-block.
    fn codes(&mut self, lit: &Huffman<MAX_LCODES>, dist: &Huffman<MAX_DCODES>) -> Result<(), DecodeError> {
        loop {
            let sym = self.decode(lit)?;
            if sym < 256 {
                *self.dst.get_mut(self.out).ok_or(Corrupt)? = sym as u8;
                self.out += 1;
                continue;
            }
            if sym == 256 {
                return Ok(());
            }
            let i = sym - 257;
            let base = *LEN_BASE.get(i).ok_or(Corrupt)?;
            let len = usize::from(base) + self.bits(u32::from(*LEN_EXTRA.get(i).ok_or(Corrupt)?))? as usize;
            let d = self.decode(dist)?;
            let base = *DIST_BASE.get(d).ok_or(Corrupt)?;
            let distance = usize::from(base) + self.bits(u32::from(*DIST_EXTRA.get(d).ok_or(Corrupt)?))? as usize;
            self.out = copy_match(self.dst, self.out, distance, len)?;
        }
    }
}

/// Appends `len` bytes copied from `distance` bytes back in `out`, at `pos`;
/// the copy may overlap itself (a run). Returns the new position.
fn copy_match(out: &mut [u8], pos: usize, distance: usize, len: usize) -> Result<usize, DecodeError> {
    let from = pos.checked_sub(distance).ok_or(Corrupt)?;
    let end = pos.checked_add(len).filter(|&e| e <= out.len()).ok_or(Corrupt)?;
    if distance >= len {
        out.copy_within(from..from + len, pos);
    } else {
        for i in pos..end {
            let b = *out.get(i - distance).ok_or(Corrupt)?;
            *out.get_mut(i).ok_or(Corrupt)? = b;
        }
    }
    Ok(end)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::string_slice, clippy::panic)]
mod tests {
    use super::*;
    use std::vec::Vec;

    // Generated with python3's zlib from the `text` and `noise` inputs below.
    /// 111 bytes.
    const STORED: &str = "78010164009bff627472667320627472667320636f6d70726573736564207a6c69620a2062747266732074686520657874656e7420657874\
    656e7420636f6d70726573736564206f66206f736d69756d207a6c69620a20657874656e74206120636f6d7072657373656420684a2532";
    /// 904 bytes.
    const LEVEL1: &str = "7801ed56b16a1541142db4d1c2cac66eab808560632158da09e20f586c928d06f37c21ef2941042dec2cc44eb4d50f102cc4c2c646c12a08\
    696c0d04d2d8a7f0de3d6766ceddd9fd017949deeccc9d73cf3df7ceec7de9f697ddc365d385479bd6f3c56cfbd1ac595fee6d2d9aa1953e\
    1bf3d9ee5eb758749bc4cdb70cda364f76b6d7cf73140c2997f7bbc63f244104b898bffd898be300a03370c124f0980bb0b22dd318463686\
    a942928f280843b830337245f54014cd90895142e45ce9dd6a395ae65be3c16e415bad1065099cac08db8aca98817870830f384224a4618e\
    51f2e754883c7559aa5fadd332d150420cbfaa6ea3ece51080c748b23a68a5ae86645da022009ac4ddd54c86e1061f200283bf1ffe1bb69c\
    cb3f165a68938359c3918b084a9c06381d787c962e172ccc2c6bc9eb7021638ea605ce9a532f30bdf6cc0328912aecf08d35e2b67bfb2746\
    151a99228417d30480532a8b24129f8a36b49b8529fb03462d66154cd8d26473fd88a8d94b5f103e53cd371a0f2480d1e50dd7e9ec7c2f79\
    e6ae4483a79f3296506e82b844229ba9d299ab0f908eb9ec8200e3509bd059d128264574be5c237806044de6975d7b09a56ac189be123205\
    0aac29d3fe723873ca2887ab18b08391796381a24ebd8329bcf08d4f6be5204690099f700781d43310af8a26e4c0e07c006b35295723988a\
    19c148355582727204a69ae4aaab66622ae9a8c688394babe2b801ff73d88330dc1b690ac2c8f43d3da0834f318732f554654f1d314fdd80\
    8939b4ced10486e2a0224880e1724b10c5e91e3ba998b59e7d0532858042165cc407f48b0b78299458ae2aacb8b9ba88e62abff8021e9fd2\
    c1998288ea5678c9b465da5a18f3fb0e48403ab79e9eb865b96273b824263b31a40bf24b28198492f59be9a6140dc8d2d77a9898934a42c2\
    df79dbd5cfaa02ab0afcf715b87ceee4dadddf47dde1eb079f6f9f5ebd707ae5cdc1fb2f8f777eddb8f563ede5d3bf970e5fbcfafeeeeb9f\
    6f27379fadedb66f3f9dfd79e7f9fe99e30f1bcdbdeb9b1f2fb207c547eec7a1310eadf4a9da4fdfc9d2b71d3a9560a4ff795723091a17db\
    5adf29c5a574433a6b2bac9b60cca51220c4a65456321da66a40fee10b83215c98d9b9a27a208ae689ef929c2bbdf10d9617f0124981dd82\
    86ffb2268b009afeeb8ed484722501b8c1871e08a44100467acb010a915b65a97eb54ecb44430931fcaa3a8cb29743001e63cc5824c91451\
    a675fd038e150af8";
    /// 633 bytes.
    const LEVEL6: &str = "789ced573d4b0341102db4d1c2cac62e956021d85808967682f8072c26c99d0613134c1411410b3b0bb1136df5070816626163a36025421a\
    5b05218dbd8577eeeded9bd9d924b5dc798997ddd9f97c6f762fdaeb445b9d52c4fe917d68b61bb59d46a9dcd98edbde68f6abd26cb4b6a3\
    763baa6672cd3811a5d27ebd561ecfbe41265bdcd988fe3e9912b3d20827eb931b96a472996ab3d8c8b12110e7b1780ea02f716042866a5c\
    4a6f167aea5832c82c417cc641fc061379ac79ce211d1494cffd2125a97e126ce59c9d60f1ac6a2cb9316a5cc37a42fcbea274d4739cb9cf\
    4b80a6403116799076171e669b47ac577aa05f0af0843741331c883ca3e68f4d594a24a641ad5d204baed34e1770e94c9f88b3cdb82d114f\
    1c901e1db03a790d1cedb33842eca7dc0955bf680e4314904c862cdc89b3ca7e58df88259404145dac21b8104b2aef02be76171a6b341aed\
    1c1ee46f8267e84d4c0741d42a0894ee62331da39f7901dd2c9259fac653c918433c47e1661e4b176437e5a12a381076a1019a5b98f33428\
    0dc4ea3031f487a13edbb755138437cc3e8520f556852aab658f1141e146a0eb8782f4b647685d3e6e42a7079258b2c30a4200b5316f0139\
    15f2119d8a4a8ff7b00610d277752b30c4de284f0b78e2713e2b105169266a464e851fad060036e5e9550f0cfd600a84959b899f89beec70\
    c8637d5c059b4665e2296592b286daee248282c082acb420840838f562e846ce07b783283baa67d251878aabb88aebdf5f3363bdf9b5f7cf\
    a87bb679b7f23337f1337bfe7a75bf5b7f5b5c7e9e3e39f89eea1e9f3e5d3e7c3cf6960ea75b74713bfab27ab437f2755d29ad2f546f26f9\
    f9ba78bf2fdeef8bf77bf4eb178e150af8";
    /// 633 bytes.
    const LEVEL9: &str = "78daed57b14a0341102db4d1c2cac62e956021d85808967682f8031693e44e838909268a88a0859d85d889b6fa01828558d8d828588990c6\
    564148636fe19d7b7bfb667636492d775ee2656f76f6cdcc7bb377d15e27daea9422f68fec45b3dda8ed344ae5ce76dcf646b35f9566a3b5\
    1db5db5135b36bc6892995f6ebb5f278f60d36d9e4ce46f4f7c99c9899c638999f9c3025b5cb5c9bc9c68e0d81398fc5038058e2c00d19aa\
    81949e2cf4145832c85682f80c40fc8625f258f39c433a28689fe32125a97e126ce5dc3ac1e259d75872b3a88186f584f87d47e9a8079cc1\
    e725c0a5c03116799077171e669b47ac577a202e8578024d70194e449e51f3c76e5949244b835b3b41965c979d6ee0d2995e11579b812d19\
    4f9c909e1cb03a790d9cecb33842eaa71c84ea5f3487210a48264396eec455653fac6fc4924a828a2ed6105d8825957701dfbb0b8d351a4d\
    768e0ff237c135f426e683206a95044a77b1998e11675e407717c52cb1f15432c510cf51b899c71282eca63c548507625d6880e614cb791e\
    9406627d9818fad350bfdbb755138437cc3e8524f566852aab658f0941d146a0eb531825df5ca075f9bc093d3d90e4921d561802ac8d790b\
    c8a5908fe852547abcc735a090beab5b8321f646f9b4804f3c0eb342115566a266e45cf8d16a0460b73cbfea03433f9a8260e566e267a2af\
    3a1cf3581f57c9a64999784a99a5aca1b63b89a020b0a02a2d0921022ebd18ba91c3e076106547f59674d2a1e2288ee2f8f7c7cc586f7eed\
    fd33ea9e6ddeadfccc4dfccc9ebf5eddefd6df16979fa74f0ebea7bac7a74f970f1f8fbda5c3e9165ddc8ebeac1eed8d7c5d574aeb0bd59b\
    c9a878bf2fdeef8bf7fb20ae5f8e150af8";
    /// 154 bytes.
    const FIXED: &str = "7801cb2fcecd2ccd55c88750553999495c0a49254569c53021342a0daa0659656a45496a5e094c092a0f593584041a81aa046208844c5448\
    cecf2d284a2d2e4e4d416622ab413119681a945f92910a6322694c048b2309a0ba124902625e22d4122409a8528838c8349853519c039280\
    3a09cd7d9846010511e6a0aa80b83711ecaf34146f23f426c25d8062552292042ee783550200b4b5b646";
    /// 286 bytes.
    const HUFFMAN: &str = "780105c1510ac4300805c0ff9ce25d2db6ca0ab1169f8192d3ef4c327c0792e13b7096cb807419910cdf8164f80e24c377200d67b90c9ce5\
    32205d46e8d7fa3492e13ba05febd34886efc0592e0367b90c9ce5329006fd5a9f46327c07a4cb08e93262e2ca784b49bd7165bca5a4de90\
    2e23a4cb8864f80e9ce532908664f80ef44f910cdf812be32d25f5c644ff1457c65b4aea8d64f80ee8d7fa34ae8cb794d41b67b90c4c4897\
    1157c65b4aea0dfd5a9f867419d13f85741931215d4624c377a07f8ab35c0692e13b7096cb401aae8cb794d41bfab53e8d34f44f215d46a4\
    e1ca784b49bd31d13fc5441ad2205d46489711fab53e8d344c48971113c9f01d38cb65606242ba8c98b832de52526fe8d7fa34a4cb88b35c\
    c61fb4b5b646";
    /// 420 bytes.
    const MULTI: &str = "18956c4f5b0ec3200cfbdf29b81add40ab34c6549854f5f40392ac4ea84a9597e3d839ba0cef78adcbcd2d758bc5e592d66f72f519dc3da7\
    cf164a098f0ef2321a79d86b78570980ec8b8a890a067a2e0dbdb425b613fa0087935c2da3503a0a9d592277c8f585b0fe9f0a7a65a0463d\
    f7f9b4ae0617a51c7cfb2ea1de982541b21c914a3918844a2e6f4606088c9741b9550223e3d19442099a20a5fb0017a371e690d1df262066\
    c10dfd030000ffff003c00c3ffa505c143e5b7e3e1853137d9a1da7bcb522509b0b898d9417b219062da78f6e07b0ae23ceb4f405a326f59\
    3add8e6fe2cc55e32f86c523aec2146ea7000000ffff6d4f5b0ec3200cfbdf29b81add40ab34c6549854f5f40392ac4ea84a9597e3d839ba\
    0cef78adcbcd2d758bc5e592d66f72f519dc3da7cf164a098f0ef2321a79d86b78570980ec8b8a890a067a2e0dbdb425b613fa0087935c2d\
    a3503a0a9d592277c8f585b0fe9f0a7a65a0463df7f9b4ae0617a51c7cfb2ea1de982541b21c914a3918844a2e6f4606088c9741b9550223\
    e3d19442099a20a5fb0017a371e690d1df262066c10dfd033c5b24cf";
    /// 8 bytes.
    const EMPTY: &str = "789c030000000001";

    const WORDS: [&[u8]; 8] = [b"the", b"btrfs", b"extent", b"osmium", b"of", b"compressed", b"a", b"zlib\n"];

    fn xorshift(x: &mut u32) -> u32 {
        *x ^= *x << 13;
        *x ^= *x >> 17;
        *x ^= *x << 5;
        *x
    }

    /// `n` bytes of space-separated words (compressible).
    fn text(n: usize, seed: u32) -> Vec<u8> {
        let (mut x, mut v) = (seed, Vec::new());
        while v.len() < n {
            v.extend_from_slice(WORDS[xorshift(&mut x) as usize % 8]);
            v.push(b' ');
        }
        v.truncate(n);
        v
    }

    /// `n` pseudo-random bytes (incompressible).
    fn noise(n: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..n).map(|_| xorshift(&mut x) as u8).collect()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn level_input() -> Vec<u8> {
        [text(3000, 2), [b'a'; 1000].to_vec(), noise(64, 9), text(800, 2)].concat()
    }

    fn vectors() -> Vec<(Vec<u8>, Vec<u8>)> {
        let small = text(500, 3);
        let multi = [text(700, 4), noise(60, 5), text(700, 4)].concat();
        std::vec![
            (hex(STORED), text(100, 1)),
            (hex(LEVEL1), level_input()),
            (hex(LEVEL6), level_input()),
            (hex(LEVEL9), level_input()),
            (hex(FIXED), small.clone()),
            (hex(HUFFMAN), small),
            (hex(MULTI), multi),
            (hex(EMPTY), Vec::new()),
        ]
    }

    fn inflate(src: &[u8], len: usize) -> Result<Vec<u8>, DecodeError> {
        let mut dst = std::vec![0xa5; len];
        let n = decompress(src, &mut dst)?;
        assert!(n <= len);
        dst.truncate(n);
        Ok(dst)
    }

    #[test]
    fn python_vectors() {
        for (z, plain) in vectors() {
            assert_eq!(inflate(&z, plain.len()).unwrap(), plain);
            // A larger buffer is fine, and so is btrfs's zero padding after the trailer.
            assert_eq!(inflate(&[&z[..], &[0; 9]].concat(), plain.len() + 100).unwrap(), plain);
            if !plain.is_empty() {
                assert_eq!(inflate(&z, plain.len() - 1), Err(Corrupt));
            }
            for cut in 0..z.len() {
                assert_eq!(inflate(&z[..cut], plain.len()), Err(Corrupt), "cut at {cut}");
            }
            let mut bad = z.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert_eq!(inflate(&bad, plain.len()), Err(Corrupt));
        }
    }

    #[test]
    fn header() {
        let z = hex(FIXED);
        let len = 500;
        let with = |cmf: u8, flg: u8| [&[cmf, flg][..], &z[2..]].concat();
        // Sets FCHECK so that only the field under test is wrong.
        let check = |cmf: u8, flg: u8| {
            let f = flg & 0xe0;
            let rem = (u16::from(cmf) << 8 | u16::from(f)) % 31;
            with(cmf, f | if rem == 0 { 0 } else { 31 - rem as u8 })
        };
        assert!(inflate(&check(0x78, 0x80), len).is_ok());
        assert!(inflate(&check(0x08, 0x00), len).is_ok()); // a 256-byte window still decodes
        assert_eq!(inflate(&check(0x78, 0x20), len), Err(Corrupt)); // FDICT
        assert_eq!(inflate(&check(0x77, 0x00), len), Err(Corrupt)); // CM 7
        assert_eq!(inflate(&check(0x88, 0x00), len), Err(Corrupt)); // CINFO 8
        assert_eq!(inflate(&with(0x78, 0x02), len), Err(Corrupt)); // FCHECK
        assert_eq!(inflate(&[0x78], len), Err(Corrupt));
    }

    /// Writes deflate bit streams by hand.
    #[derive(Default)]
    struct Bits {
        v: Vec<u8>,
        n: u32,
    }

    impl Bits {
        fn put(&mut self, value: u32, n: u32) {
            for i in 0..n {
                if self.n % 8 == 0 {
                    self.v.push(0);
                }
                *self.v.last_mut().unwrap() |= ((value >> i & 1) as u8) << (self.n % 8);
                self.n += 1;
            }
        }

        /// A Huffman code, most significant bit first.
        fn code(&mut self, (code, len): (u32, u32)) {
            for i in (0..len).rev() {
                self.put(code >> i & 1, 1);
            }
        }

        /// The finished zlib stream for output `plain`.
        fn zlib(self, plain: &[u8]) -> Vec<u8> {
            [&[0x78, 0x01][..], &self.v, &adler32(plain).to_be_bytes()].concat()
        }
    }

    /// Canonical codes for `lengths` (RFC 1951 section 3.2.2).
    fn canonical(lengths: &[u8]) -> Vec<(u32, u32)> {
        let mut count = [0u32; 16];
        lengths.iter().for_each(|&l| count[l as usize] += 1);
        count[0] = 0;
        let mut next = [0u32; 16];
        for b in 1..16 {
            next[b] = (next[b - 1] + count[b - 1]) << 1;
        }
        lengths
            .iter()
            .map(|&l| {
                let c = next[l as usize];
                next[l as usize] += 1;
                (c, u32::from(l))
            })
            .collect()
    }

    fn fixed_lit(sym: usize) -> (u32, u32) {
        let lens: Vec<u8> =
            (0..288).map(|s| [8, 9, 7, 8][(s >= 144) as usize + (s >= 256) as usize + (s >= 280) as usize]).collect();
        canonical(&lens)[sym]
    }

    /// A one-block stream with fixed codes; `syms` are literal/length symbols
    /// with their extra bits, or (for `Dist`) distance symbols.
    fn fixed(syms: &[Sym]) -> Bits {
        let mut b = Bits::default();
        b.put(1, 1);
        b.put(1, 2);
        for s in syms {
            match *s {
                Sym::Lit(sym, extra, n) => {
                    b.code(fixed_lit(sym));
                    b.put(extra, n);
                }
                Sym::Dist(sym, extra, n) => {
                    b.code((sym as u32, 5));
                    b.put(extra, n);
                }
            }
        }
        b
    }

    #[derive(Clone, Copy)]
    enum Sym {
        Lit(usize, u32, u32),
        Dist(usize, u32, u32),
    }
    use Sym::{Dist, Lit};

    /// A one-block stream with a dynamic code. `cl` is the code length
    /// sequence as (symbol, extra, extra bits); `body` is coded with the
    /// resulting codes.
    fn dynamic(nlen: usize, ndist: usize, cl: &[(usize, u32, u32)], body: &[Sym]) -> Bits {
        // A complete code length code: 13 four-bit codes and 6 five-bit ones.
        let cl_lens: Vec<u8> = (0..19).map(|s| if s < 13 { 4 } else { 5 }).collect();
        let cl_codes = canonical(&cl_lens);
        let mut b = Bits::default();
        b.put(1, 1);
        b.put(2, 2);
        b.put((nlen - 257) as u32, 5);
        b.put((ndist - 1) as u32, 5);
        b.put(15, 4);
        for &s in &CL_ORDER {
            b.put(u32::from(cl_lens[usize::from(s)]), 3);
        }
        let mut lengths = Vec::new();
        for &(sym, extra, n) in cl {
            b.code(cl_codes[sym]);
            b.put(extra, n);
            match sym {
                0..16 => lengths.push(sym as u8),
                16 => lengths.extend(std::vec![lengths.last().copied().unwrap_or(0); 3 + extra as usize]),
                17 => lengths.extend(std::vec![0; 3 + extra as usize]),
                _ => lengths.extend(std::vec![0; 11 + extra as usize]),
            }
        }
        lengths.resize(nlen + ndist, 0);
        let lit = canonical(&lengths[..nlen]);
        let dist = canonical(&lengths[nlen..]);
        for s in body {
            match *s {
                Lit(sym, extra, n) => {
                    b.code(lit[sym]);
                    b.put(extra, n);
                }
                Dist(sym, extra, n) => {
                    b.code(dist[sym]);
                    b.put(extra, n);
                }
            }
        }
        b
    }

    /// Code lengths giving literals `a` and `b`, end-of-block and length
    /// symbol 257 two bits each, then `dist` for the distance code.
    fn lens(dist: &[usize]) -> Vec<(usize, u32, u32)> {
        let mut v = std::vec![(18, 97 - 11, 7), (2, 0, 0), (2, 0, 0)]; // zeros, then 'a' (97) and 'b'
        v.extend([(18, 138 - 11, 7), (18, 19 - 11, 7)]); // 157 zeros up to 256
        v.extend([(2, 0, 0), (2, 0, 0)]); // 256, 257
        v.extend(dist.iter().map(|&l| (l, 0, 0)));
        v
    }

    #[test]
    fn dynamic_codes() {
        // One distance code of one bit: incomplete, but zlib accepts it.
        let body = [Lit(97, 0, 0), Lit(257, 0, 0), Dist(0, 0, 0), Lit(98, 0, 0), Lit(256, 0, 0)];
        let z = dynamic(258, 1, &lens(&[1]), &body).zlib(b"aaaab");
        assert_eq!(inflate(&z, 5).unwrap(), b"aaaab");
        // Two one-bit distance codes are complete.
        let z = dynamic(258, 2, &lens(&[1, 1]), &body).zlib(b"aaaab");
        assert_eq!(inflate(&z, 5).unwrap(), b"aaaab");
        // No distance codes at all is fine until one is used.
        let z = dynamic(258, 1, &lens(&[0]), &[Lit(97, 0, 0), Lit(256, 0, 0)]).zlib(b"a");
        assert_eq!(inflate(&z, 1).unwrap(), b"a");
        let z = dynamic(258, 1, &lens(&[0]), &body).zlib(b"aaaab");
        assert_eq!(inflate(&z, 5), Err(Corrupt));
        // Incomplete beyond one bit, and oversubscribed.
        let z = dynamic(258, 2, &lens(&[2, 2]), &body).zlib(b"aaaab");
        assert_eq!(inflate(&z, 5), Err(Corrupt));
        let z = dynamic(258, 3, &lens(&[1, 1, 1]), &body).zlib(b"aaaab");
        assert_eq!(inflate(&z, 5), Err(Corrupt));
        // An incomplete literal/length code (three two-bit codes).
        let mut cl = lens(&[1]);
        cl[2] = (0, 0, 0);
        let z = dynamic(258, 1, &cl, &[Lit(97, 0, 0), Lit(256, 0, 0)]).zlib(b"a");
        assert_eq!(inflate(&z, 1), Err(Corrupt));
        // No end-of-block code.
        let mut cl = lens(&[1]);
        (cl[5], cl[6]) = ((0, 0, 0), (1, 0, 0));
        assert_eq!(inflate(&dynamic(258, 1, &cl, &[]).zlib(b""), 1), Err(Corrupt));
        // A repeat with nothing to repeat, and repeats running past the end.
        let z = dynamic(258, 1, &[(16, 0, 2)], &[]).zlib(b"");
        assert_eq!(inflate(&z, 1), Err(Corrupt));
        let mut cl = lens(&[]);
        cl.push((16, 0, 2));
        assert_eq!(inflate(&dynamic(258, 1, &cl, &[]).zlib(b""), 1), Err(Corrupt));
        // A repeat may run from the literal/length lengths into the distance
        // ones: here zeros for 258 and distances 0 and 1, before a lone
        // distance 2 (base 3). A lone two-bit code is still rejected.
        let mut cl = lens(&[]);
        cl.extend([(17, 0, 3), (1, 0, 0)]);
        let body = [Lit(97, 0, 0), Lit(98, 0, 0), Lit(97, 0, 0), Lit(257, 0, 0), Dist(2, 0, 0), Lit(256, 0, 0)];
        assert_eq!(inflate(&dynamic(259, 3, &cl, &body).zlib(b"abaaba"), 6).unwrap(), b"abaaba");
        *cl.last_mut().unwrap() = (2, 0, 0);
        assert_eq!(inflate(&dynamic(259, 3, &cl, &body).zlib(b"abaaba"), 6), Err(Corrupt));
        // Too many length or distance codes.
        assert_eq!(inflate(&dynamic(287, 1, &[], &[]).zlib(b""), 1), Err(Corrupt));
        assert_eq!(inflate(&dynamic(258, 31, &[], &[]).zlib(b""), 1), Err(Corrupt));
    }

    #[test]
    fn fixed_codes() {
        // 'a' then a 258-byte run, written both as symbol 285 and as 284 with all extra bits set.
        let run: Vec<u8> = std::vec![b'a'; 259];
        for len in [Lit(285, 0, 0), Lit(284, 31, 5)] {
            let z = fixed(&[Lit(97, 0, 0), len, Dist(0, 0, 0), Lit(256, 0, 0)]).zlib(&run);
            assert_eq!(inflate(&z, 259).unwrap(), run);
            assert_eq!(inflate(&z, 258), Err(Corrupt));
        }
        // The longest distance, 32768, reaching exactly the first byte.
        let mut plain = noise(32768, 1);
        let mut syms: Vec<Sym> = plain.iter().map(|&b| Lit(usize::from(b), 0, 0)).collect();
        syms.extend([Lit(257, 0, 0), Dist(29, 8191, 13), Lit(256, 0, 0)]);
        plain.extend_from_within(..3);
        let z = fixed(&syms).zlib(&plain);
        assert_eq!(inflate(&z, plain.len()).unwrap(), plain);
        // Too far back.
        let z = fixed(&[Lit(97, 0, 0), Lit(257, 0, 0), Dist(1, 0, 0), Lit(256, 0, 0)]).zlib(b"aaaa");
        assert_eq!(inflate(&z, 4), Err(Corrupt));
        // Symbols that only exist to complete the fixed codes.
        for bad in [[Lit(97, 0, 0), Lit(286, 0, 0)], [Lit(97, 0, 0), Lit(287, 0, 0)]] {
            assert_eq!(inflate(&fixed(&bad).zlib(b"a"), 9), Err(Corrupt));
        }
        for d in [30, 31] {
            let z = fixed(&[Lit(97, 0, 0), Lit(257, 0, 0), Dist(d, 0, 0)]).zlib(b"a");
            assert_eq!(inflate(&z, 9), Err(Corrupt));
        }
        // Block type 3.
        let mut b = Bits::default();
        b.put(1, 1);
        b.put(3, 2);
        assert_eq!(inflate(&b.zlib(b""), 9), Err(Corrupt));
    }

    #[test]
    fn stored_blocks() {
        let mut b = Bits::default();
        b.put(0, 1);
        b.put(0, 2);
        b.put(0, 5); // pad to the byte boundary
        b.v.extend([3, 0, !3, 0xff, b'a', b'b', b'c']);
        b.n = b.v.len() as u32 * 8;
        b.put(1, 1); // final, empty stored block
        b.put(0, 2);
        b.put(0, 5);
        b.v.extend([0, 0, 0xff, 0xff]);
        let z = b.zlib(b"abc");
        assert_eq!(inflate(&z, 3).unwrap(), b"abc");
        let mut bad = z.clone();
        bad[5] ^= 1; // NLEN
        assert_eq!(inflate(&bad, 3), Err(Corrupt));
    }

    /// Mutated and truncated streams never panic or overrun `dst`.
    #[test]
    fn hostile_input() {
        let mut x = 0x2545_f491u32;
        for (z, plain) in vectors() {
            for _ in 0..3000 {
                let mut m = z.clone();
                for _ in 0..1 + xorshift(&mut x) % 4 {
                    let i = xorshift(&mut x) as usize % m.len();
                    match xorshift(&mut x) % 4 {
                        0 => m[i] = xorshift(&mut x) as u8,
                        1 => m[i] ^= 1 << (xorshift(&mut x) % 8),
                        2 => m.truncate(i.max(1)),
                        _ => m.insert(i, xorshift(&mut x) as u8),
                    }
                }
                let len = match xorshift(&mut x) % 3 {
                    0 => plain.len(),
                    1 => xorshift(&mut x) as usize % (plain.len() + 1),
                    _ => plain.len() + 64,
                };
                let mut dst = std::vec![0; len];
                if let Ok(n) = decompress(&m, &mut dst) {
                    assert!(n <= len);
                }
            }
        }
    }
}
