// SPDX-License-Identifier: GPL-2.0-only
//! LZO decompression as btrfs stores it (`fs/btrfs/lzo.c` in Linux): a
//! sequence of length-prefixed LZO1X segments, each the compression of at most
//! one sector.
//!
//! ```text
//! u32 le   total length of the compressed data, these 4 bytes included
//! repeat:  u32 le segment length, then that many bytes of raw LZO1X
//! ```
//!
//! A segment header never straddles a sector boundary: when fewer than 4 bytes
//! are left in the sector, the writer pads to the next one with zeros.
//! Payloads may straddle.
//!
//! The segment decoder follows Linux's `lzo1x_decompress_safe`, including the
//! run-length extension of bitstream version 1 (the "lzo-rle" format; btrfs
//! itself writes version 0, but the kernel decoder it uses accepts both).

use crate::DecodeError::{self, Corrupt};

/// Bytes in a length field.
const LEN: usize = 4;

/// Decompresses the btrfs LZO data in `src` into `dst`, returning the bytes
/// written. Each segment may produce at most `sectorsize` bytes; output that
/// would not fit in `dst` is corruption. Stops when the data is consumed or
/// `dst` is full.
pub(crate) fn decompress(src: &[u8], dst: &mut [u8], sectorsize: usize) -> Result<usize, DecodeError> {
    let le32 = |at: usize| {
        src.get(at..).and_then(|t| t.first_chunk::<LEN>()).map(|c| u32::from_le_bytes(*c) as usize).ok_or(Corrupt)
    };
    let total = le32(0)?;
    if total < LEN || total > src.len() || sectorsize < LEN {
        return Err(Corrupt);
    }
    let (mut pos, mut out) = (LEN, 0);
    while out < dst.len() {
        let left = sectorsize - pos % sectorsize;
        if left < LEN {
            pos = pos.saturating_add(left); // zero padding
        }
        if pos >= total {
            break;
        }
        if total - pos < LEN {
            return Err(Corrupt);
        }
        let seg_len = le32(pos)?;
        pos += LEN;
        if seg_len == 0 || seg_len > total - pos {
            return Err(Corrupt);
        }
        let seg = src.get(pos..pos + seg_len).ok_or(Corrupt)?;
        pos += seg_len;
        let window = dst.get_mut(out..).ok_or(Corrupt)?;
        let window_len = window.len().min(sectorsize);
        out += lzo1x(seg, window.get_mut(..window_len).ok_or(Corrupt)?)?;
    }
    Ok(out)
}

/// Bytes of input not yet read.
struct Input<'src> {
    src: &'src [u8],
    pos: usize,
}

impl Input<'_> {
    fn byte(&mut self) -> Result<usize, DecodeError> {
        let b = *self.src.get(self.pos).ok_or(Corrupt)?;
        self.pos += 1;
        Ok(usize::from(b))
    }

    /// The little-endian u16 at the cursor, not consumed.
    fn peek16(&self) -> Result<usize, DecodeError> {
        let c = self.src.get(self.pos..).and_then(|t| t.first_chunk::<2>()).ok_or(Corrupt)?;
        Ok(usize::from(u16::from_le_bytes(*c)))
    }

    fn has(&self, n: usize) -> bool {
        self.src.len().saturating_sub(self.pos) >= n
    }

    /// An extended length: a run of zero bytes, each worth 255, then a
    /// non-zero byte added to them.
    fn count(&mut self) -> Result<usize, DecodeError> {
        let mut n: usize = 0;
        loop {
            match self.byte()? {
                0 => n = n.checked_add(255).ok_or(Corrupt)?,
                b => return n.checked_add(b).ok_or(Corrupt),
            }
        }
    }

    /// Copies `n` literal bytes to `out` at `*op`. Like Linux, a literal run
    /// must leave room for at least the 3-byte end marker after it.
    fn literals(&mut self, out: &mut [u8], op: &mut usize, n: usize) -> Result<(), DecodeError> {
        if n.checked_add(3).is_none_or(|need| !self.has(need)) {
            return Err(Corrupt);
        }
        let from = self.src.get(self.pos..self.pos + n).ok_or(Corrupt)?;
        out.get_mut(*op..).and_then(|o| o.get_mut(..n)).ok_or(Corrupt)?.copy_from_slice(from);
        self.pos += n;
        *op += n;
        Ok(())
    }
}

/// Decompresses one raw LZO1X stream from `src` into `out` (whose start is the
/// limit of look-behind), returning the bytes written. Mirrors Linux's
/// `lzo1x_decompress_safe`; anything it rejects is corruption here, including
/// input left over after the end marker.
fn lzo1x(src: &[u8], out: &mut [u8]) -> Result<usize, DecodeError> {
    if src.len() < 3 {
        return Err(Corrupt);
    }
    let mut ip = Input { src, pos: 0 };
    // Version 1 streams open with 17 and the version byte. (A version 0 stream
    // can only start with 17 when it is the bare end marker, 3 bytes long.)
    let mut version = 0;
    if src.len() >= 5 && src.first() == Some(&17) {
        ip.pos = 1;
        version = ip.byte()?;
    }
    let mut op = 0;
    // `state` is the number of literals that followed the last instruction
    // (4 standing for "4 or more"): it decides what a code below 16 means.
    let mut state;
    // A first byte above 17 is a literal run with no preceding match.
    let first = *src.get(ip.pos).ok_or(Corrupt)?;
    if first > 17 {
        ip.pos += 1;
        let t = usize::from(first) - 17;
        ip.literals(out, &mut op, t)?;
        state = if t < 4 { t } else { 4 };
    } else {
        state = 0;
    }
    loop {
        let t = ip.byte()?;
        // Each match yields its look-behind distance, its length, and how many
        // literals (0..=3) follow it, taken from its low two bits.
        let (distance, len, next);
        if t < 16 {
            if state == 0 {
                // A literal run: 3 + t, or 18 + extended count when t is 0.
                let n = if t == 0 { 18 + ip.count()? } else { t + 3 };
                ip.literals(out, &mut op, n)?;
                state = 4;
                continue;
            }
            let h = ip.byte()?;
            next = t & 3;
            if state != 4 {
                // M1 right after a match's trailing literals: 2 bytes, at most 1 KiB back.
                (distance, len) = (1 + (t >> 2) + (h << 2), 2);
            } else {
                // After a long literal run: 3 bytes, 2 KiB + 1 to 3 KiB back.
                (distance, len) = (1 + 0x800 + (t >> 2) + (h << 2), 3);
            }
        } else if t >= 64 {
            // M2: 3 to 8 bytes, at most 2 KiB back.
            let h = ip.byte()?;
            (distance, len, next) = (1 + ((t >> 2) & 7) + (h << 3), (t >> 5) + 1, t & 3);
        } else if t >= 32 {
            // M3: at most 16 KiB back.
            let len3 = if t & 31 == 0 { 33 + ip.count()? } else { (t & 31) + 2 };
            let d = ip.peek16()?;
            ip.pos += 2;
            (distance, len, next) = (1 + (d >> 2), len3, d & 3);
        } else {
            let d = ip.peek16()?;
            if version != 0 && d & 0xfffc == 0xfffc && t & 0xf8 == 0x18 {
                // Version 1 zero run: 4 + an 11-bit length.
                let hi = usize::from(*src.get(ip.pos + 2).ok_or(Corrupt)?);
                let n = ((t & 7) | hi << 3) + 4;
                out.get_mut(op..).and_then(|o| o.get_mut(..n)).ok_or(Corrupt)?.fill(0);
                op += n;
                ip.pos += 3;
                state = d & 3;
                ip.literals(out, &mut op, state)?;
                continue;
            }
            // M4: 16 KiB to 48 KiB back, or the end marker (distance 0x4000).
            let (len4, d) = if t & 7 == 0 { (9 + ip.count()?, ip.peek16()?) } else { ((t & 7) + 2, d) };
            ip.pos += 2;
            let far = ((t & 8) << 11) + (d >> 2);
            if far == 0 {
                // The marker is 0x11 0x00 0x00 and must end the input.
                return if len4 == 3 && ip.pos == src.len() { Ok(op) } else { Err(Corrupt) };
            }
            (distance, len, next) = (far + 0x4000, len4, d & 3);
        }
        op = copy_match(out, op, distance, len)?;
        state = next;
        ip.literals(out, &mut op, next)?;
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

    // Raw LZO1X-1 streams from liblzo2's `lzo1x_1_compress`, of the inputs below.
    /// 1253 bytes.
    const SEG_TEXT: &str = "046f736d69756d20d800087a6c69620a206274726673e802c403fa006620ac04b400a40503657874656e74e0062c3400bc042a17006f6620\
    2c8800b008b400096120636f6d707265737365642a2800b403b400c811ae0a6f66ff0e746865e801290e0161207c02294000d407c8102960\
    00bd0961d41f296000c805b00f7409a401e405c00a6003a808c002d101662a1803ca096f669412bd086f2b8400be1561207d1a66cc11bc04\
    28ec00e50f61fc1daa0d612028600036f802a7056f662070052990007417c00c6801c81868016c00fc0a2dc000d404d80029710061278407\
    2aa003ac0fb019740a29c0008012293c00c811ac05307c0129a400b00ac804d806d401b4072c4d006fec2a842c291c01d804b809295c00b0\
    082940002f8400c407d80030600336c000f02abc03bc0cc5176ff46c29dc01a00427c8077c0c2ce408c010c808b40a29fc00dc02b8082a14\
    00a405b400940a02736d69756d805429f800d40b2944002a0c01ac0136f00e29d000292800ac06294000a810c00d27a006b8042b68012cdc\
    03c01b68172a0c00fc06d803d80a27fc047c5f944e6c062be401a0072a14002bf001a003d809b00138b806700bec0029a4032e4c02d409cc\
    12d4032abc007c759415a415c40427dc01dc01640dc104666088ac01291c01275c0ea4037c0da401c00829a8006c0929c401c414dc042714\
    052ec000a847b422279000d0062dac00c40abc0f750d61c4cb34f4002a9c002fe8008015fc69299c01b0062f4000c012d800ac0ff40fcc0b\
    840ab807b400f40b9c8628900078b42ad003f017700a6c0029ec01a8032f4000d410b4036806bc0dbc01d0032b000abc038014d803ac0529\
    6401fc13a4138805ac04f4182c3400d808f003d801293c017812d402279000e894e809276c09a0022df400c412d800cc09282420cc1abc15\
    29e800f4e1dc06a80bd00170122b3406b407c8092b501dbc066006a401f018b4017c022b84052900026c03a40a2b8400a007b40029380229\
    e000b0062940002928009416280c04a805b400d402b001bc0b6810e016275414f8558c3b27a40d6805d811a408d0012bec022df414a4f464\
    07cc0f2ba002293000b4112a1400d40ba802254c238009f0ec276400291801a013d80464906801a0052f940029d803d013299401d40f7807\
    fc04ac0b291801bc0ab4006005a401cc0960022b640429e0002c9004c80df02e60076c00dc08d800943aa00cb856d406b012d0047806ec04\
    28f80b2cb401a0069809d406a4066c077c8d90c1b05d2b88012b2c0327a40874066c00c8056801a00cb400a81527b400a40d2c2401a80da4\
    03b006b4002ab804ac04b0092c3406a4162af400d01a2f1001a002b400cc04985b6816bc07d402b80ca802b400b006b400c01dcc05bc0368\
    08c0022d9c12ac06292803342800b808b400c009d80029bc00740ca80427900180186820a024640430dc002cc402740598f78440cc032994\
    012a140ab40dc40ab001b400c8029c0d27bc357401292001cc04d800a021ec37d0027c73c8012b5c012cc00a294c0130b802bc06b4006010\
    680af40cac0e601eb823bc012cf4098821d80a2cd8017409bc0a270014320001a80b280401e80628f8006010906aaca12bfc01dc06278401\
    7817b40c7c07ec00ac0a291c04fc3ea805324401e403d82b29ec0027ac01c803680e6814a01929a000cc13271828321402cc08b40d000165\
    7874656e74206120657874656e742061207a110000";
    /// 403 bytes.
    const SEG_RUNS: &str = "08636f6d7072657373656420292800096274726673206f736d69756d2a5c00027a6c69620afc02b0042fd400ac04b003b40003657874656e\
    74f806d40ad0022ff8000174686520ec00b807b400d806b0016004c008d8006502618007c005dc02da006f66f80fb8137805c803d800bc02\
    b80bc802296e026120bc03c6036f662a5404c40ea50461316600612028dc00e60961202e4c02d808d8002ac4002b4c01b80cd803d8002ba4\
    02304e006f66e010cc03d80077206f6620891161e024d40127cc02bc0dd41266066120b42429d001ac04b802ac0127f8006406d007bc0360\
    0229e800c811286c00272002c4032cac05bc043368002896036f66d835299c01297400b85a801fb015d809d8002cc2016f66944acc03bc05\
    cc02e0212b7803c005741c2880072b840029520261206d567a200000000000000000000000a1000022f42e279c3323d83422d42f29782f25\
    2c307c04250430c4027c046c002ca831d003300001d00724ec337c06241832880eb0022b8400b403d409c403d8000e6274726673207a6c69\
    620a20657874656e110000";
    /// 364 bytes.
    const SEG_TAIL: &str = "037a6c69620a20b4000e6f736d69756d20636f6d70726573736564fc02056620657874656e74dc01b405c80229b400056f66207468652061\
    2a0401297800292800cf076f6620cc0e7c066c00293a006f662a1e016f66d00fc8070262747266732a80002b5002b403aa026120b401780b\
    290802f003dc096811e80c299400dd1161c01ba409a807c007b0012cb002c803291c01b50461f81dd80ab402299800292800c8047416d809\
    b405dc02cc02026f66206120dc2e29f000a805b4002958009405640ad008273c022fa400d80bbc1dd001e029294001292800c80acc05d401\
    bc07640e6c008415c403f0097c2eb84e64042cf400dc1ac4069017880864056c00b4166401bc0c293402a803d8092f7400c40a6407c801d8\
    00b8067c02ac06b400b402e416299401b803d40cac44c009cc022b8000691d66d05127380ba404640ec407297801d0082b6001bc05a41229\
    a80060082a80020e726573736564206f736d69756d2061206f110000";
    /// 534 bytes.
    const FAR: &str = "00be0808297a8c0cfcd7f2e5a08fc452c5bff42509cb97039d232615ee2dfdb52be518ff647b3279c0e232f60758919924ce1981f7e34cad\
    b73d7137f3ea5442b1d3b08f1e70d9951c73253d2595cd30c16956120017710da7235020eba7b39adcb0402a053a22b8db30379ef6381097\
    5f053254d6edc5da69ed9a84dd286bb9116f2f961a3738b0d7a61b0cb373978d5e419256136c5a39945cbac8a4ae57756ff6a1d871f8fab5\
    463b3bff2a09221d7cd24979b4530e69a6be932fa18133ca94c04f745f04e798f30f00000000000000002000000000000000000000000000\
    0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000811800\
    10bfc00c03627472667320b4000a6f6620636f6d707265737365642a2800016f6620612a3c00027a6c69620af0060b736d69756d20746865\
    2061206f66282000292801700303657874656e746404c40196056f6665026fac08b6106120da016f66c80cbc02b30e6f6620a0016c0ac005\
    2b6c02cc02a00ba905619012b408d00fb803d81568096c00c807a00529f802dd027410000000000000000000000000000000000000000000\
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000099501116800914040ab400\
    100004500e000220636f6d70726573736564206f736d69756d2074110000";

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

    /// The segments and what they decompress to.
    fn segments() -> [(Vec<u8>, Vec<u8>); 3] {
        [
            (hex(SEG_TEXT), text(4096, 3)),
            (hex(SEG_RUNS), [text(900, 5), [b'z'; 3000].to_vec(), text(196, 6)].concat()),
            (hex(SEG_TAIL), text(1000, 7)),
        ]
    }

    /// An LZO1X stream of `data` as one literal run.
    fn literal(data: &[u8]) -> Vec<u8> {
        let n = data.len();
        let mut v = if n <= 238 {
            std::vec![17 + n as u8]
        } else {
            let zeros = (n - 19) / 255;
            [std::vec![0; 1 + zeros], std::vec![(n - 18 - 255 * zeros) as u8]].concat()
        };
        v.extend_from_slice(data);
        v.extend([0x11, 0, 0]);
        v
    }

    /// Frames `segments` the way btrfs does, padding so that no segment
    /// header straddles a sector.
    fn frame(segments: &[&[u8]], sectorsize: usize) -> Vec<u8> {
        let mut v = std::vec![0; 4];
        for seg in segments {
            let left = sectorsize - v.len() % sectorsize;
            if left < 4 {
                v.resize(v.len() + left, 0);
            }
            v.extend((seg.len() as u32).to_le_bytes());
            v.extend_from_slice(seg);
        }
        let total = v.len() as u32;
        v[..4].copy_from_slice(&total.to_le_bytes());
        v
    }

    fn run(src: &[u8], len: usize, sectorsize: usize) -> Result<Vec<u8>, DecodeError> {
        let mut dst = std::vec![0xa5; len];
        let n = decompress(src, &mut dst, sectorsize)?;
        assert!(n <= len);
        dst.truncate(n);
        Ok(dst)
    }

    #[test]
    fn liblzo2_segments() {
        let segs = segments();
        for (z, plain) in &segs {
            assert_eq!(run(&frame(&[z], 4096), plain.len(), 4096).unwrap(), *plain);
            // Every truncation of a segment is caught.
            for cut in 1..z.len() {
                assert_eq!(run(&frame(&[&z[..cut]], 4096), plain.len(), 4096), Err(Corrupt), "cut at {cut}");
            }
            // More than a sector of output, more than dst, input after the end marker.
            assert_eq!(run(&frame(&[z], 4096), plain.len() - 1, 4096), Err(Corrupt));
            assert_eq!(run(&frame(&[z], plain.len() - 1), plain.len(), plain.len() - 1), Err(Corrupt));
            assert_eq!(run(&frame(&[&[&z[..], &[0]].concat()], 4096), plain.len(), 4096), Err(Corrupt));
        }
        let all: Vec<u8> = segs.iter().flat_map(|(_, p)| p.iter().copied()).collect();
        let framed = frame(&[&segs[0].0, &segs[1].0, &segs[2].0], 4096);
        assert_eq!(run(&framed, all.len(), 4096).unwrap(), all);
        // A larger dst is fine; one ending at a segment boundary stops there.
        assert_eq!(run(&framed, all.len() + 500, 4096).unwrap(), all);
        assert_eq!(run(&framed, 8192, 4096).unwrap(), all[..8192]);
        // btrfs's padding after the compressed data is ignored.
        assert_eq!(run(&[&framed[..], &[0; 300]].concat(), all.len(), 4096).unwrap(), all);
    }

    #[test]
    fn far_matches() {
        // Matches over 16 KiB back (M4), in one 35 KiB segment.
        let plain =
            [noise(200, 8), std::vec![0; 17000], noise(200, 8), text(300, 9), std::vec![0; 17000], text(300, 9)]
                .concat();
        let mut dst = std::vec![0; plain.len()];
        assert_eq!(lzo1x(&hex(FAR), &mut dst), Ok(plain.len()));
        assert_eq!(dst, plain);
    }

    #[test]
    fn sector_padding() {
        let segs = segments();
        // Size a literal segment so that the next header would start 2 bytes
        // before the end of the first sector, then one that straddles the second.
        let at = 4 + 4 + segs[0].0.len() + 4;
        let n = (1..4096).find(|&n| (at + literal(&noise(n, 1)).len()) % 4096 == 4094).unwrap();
        let (fill, big) = (noise(n, 1), noise(4096, 2));
        let (lit_fill, lit_big) = (literal(&fill), literal(&big));
        let framed = frame(&[&segs[0].0, &lit_fill, &segs[1].0, &lit_big, &segs[2].0], 4096);
        assert_eq!(&framed[4094..4100], &[0, 0, segs[1].0.len() as u8, (segs[1].0.len() >> 8) as u8, 0, 0]);
        let plain = [&segs[0].1[..], &fill, &segs[1].1, &big, &segs[2].1].concat();
        assert_eq!(run(&framed, plain.len(), 4096).unwrap(), plain);
        // Without the padding the header is misread.
        let mut unpadded = framed.clone();
        unpadded.drain(4094..4096);
        let total = unpadded.len() as u32;
        unpadded[..4].copy_from_slice(&total.to_le_bytes());
        assert_eq!(run(&unpadded, plain.len(), 4096), Err(Corrupt));

        // Small sectors and segments of every size up to one sector, so that
        // headers land at every offset.
        let mut x = 7;
        let chunks: Vec<Vec<u8>> = (0..400).map(|i| noise(1 + xorshift(&mut x) as usize % 64, i)).collect();
        let lits: Vec<Vec<u8>> = chunks.iter().map(|c| literal(c)).collect();
        let refs: Vec<&[u8]> = lits.iter().map(|l| &l[..]).collect();
        let plain = chunks.concat();
        assert_eq!(run(&frame(&refs, 64), plain.len(), 64).unwrap(), plain);
    }

    #[test]
    fn framing_errors() {
        let z = hex(SEG_TAIL);
        let good = frame(&[&z], 4096);
        let mut bad = good.clone();
        bad[..4].copy_from_slice(&(good.len() as u32 + 1).to_le_bytes()); // total past the input
        assert_eq!(run(&bad, 1000, 4096), Err(Corrupt));
        bad[..4].copy_from_slice(&3u32.to_le_bytes()); // total shorter than itself
        assert_eq!(run(&bad, 1000, 4096), Err(Corrupt));
        bad[..4].copy_from_slice(&6u32.to_le_bytes()); // a truncated segment header
        assert_eq!(run(&bad, 1000, 4096), Err(Corrupt));
        let mut bad = good.clone();
        bad[4..8].copy_from_slice(&0u32.to_le_bytes()); // empty segment
        assert_eq!(run(&bad, 1000, 4096), Err(Corrupt));
        bad[4..8].copy_from_slice(&(z.len() as u32 + 1).to_le_bytes()); // segment past the total
        assert_eq!(run(&bad, 1000, 4096), Err(Corrupt));
        assert_eq!(run(&good, 1000, 3), Err(Corrupt));
        assert_eq!(run(&good[..3], 1000, 4096), Err(Corrupt));
        // Nothing but the total length: no output.
        assert_eq!(run(&4u32.to_le_bytes(), 1000, 4096).unwrap(), b"");
        // A segment cannot look back into the one before.
        // "abc", then (in the second) an M3 match of 12 bytes from 3 back.
        let (first, reach) = ([17 + 3, b'a', b'b', b'c', 0x11, 0, 0], [0x2a, 0x08, 0x00, 0x11, 0, 0]);
        assert_eq!(run(&frame(&[&first, &reach], 64), 100, 64), Err(Corrupt));
        let joined = [17 + 3, b'a', b'b', b'c', 0x2a, 0x08, 0x00, 0x11, 0, 0];
        assert_eq!(run(&frame(&[&joined], 64), 100, 64).unwrap(), b"abcabcabcabcabc");
    }

    #[test]
    fn hand_assembled() {
        let mut out = [0; 64];
        // The bare end marker.
        assert_eq!(lzo1x(&[0x11, 0, 0], &mut out), Ok(0));
        assert_eq!(lzo1x(&[0x11, 0], &mut out), Err(Corrupt));
        // Literals "abc", then an M2 match of 3 bytes at distance 3 and one
        // trailing literal: 0x40 | (len - 1) << 5 | (dist - 1) & 7 << 2 | 1.
        let s = [17 + 3, b'a', b'b', b'c', 0x40 | 2 << 2 | 1, 0, b'!', 0x11, 0, 0];
        assert_eq!(lzo1x(&s, &mut out), Ok(7));
        assert_eq!(&out[..7], b"abcabc!");
        // Then an M1 match (2 bytes, distance 1 + 0 + (1 << 2) = 5) since one
        // literal followed the previous match.
        let s = [17 + 3, b'a', b'b', b'c', 0x40 | 2 << 2 | 1, 0, b'!', 0x00, 1, 0x11, 0, 0];
        assert_eq!(lzo1x(&s, &mut out), Ok(9));
        assert_eq!(&out[..9], b"abcabc!ca");
        // An M3 match with an extended length: 33 + 255 + 2 = 290 bytes at distance 1.
        let mut big = [0; 400];
        let s = [17 + 1, b'x', 0x20, 0, 2, 0, 0, 0x11, 0, 0];
        assert_eq!(lzo1x(&s, &mut big), Ok(291));
        assert!(big[..291].iter().all(|&b| b == b'x'));
        assert_eq!(lzo1x(&s, &mut big[..290]), Err(Corrupt));
        // A match before any output.
        assert_eq!(lzo1x(&[0x40, 0, 0x11, 0, 0], &mut out), Err(Corrupt));
        // An end marker with a length other than 3 (M4 with t & 7 == 2).
        assert_eq!(lzo1x(&[17 + 1, b'x', 0x12, 0, 0], &mut out), Err(Corrupt));
        // An extended length that is all zeros.
        assert_eq!(lzo1x(&[0, 0, 0, 0], &mut out), Err(Corrupt));
    }

    #[test]
    fn version_1_zero_runs() {
        let mut out = [0xff; 64];
        // Version 1: "abcd", a run of (0x18 & 7 | 1 << 3) + 4 = 12 zeros with one
        // trailing literal, then the end marker.
        let s = [17, 1, 17 + 4, b'a', b'b', b'c', b'd', 0x18, 0xfd, 0xff, 1, b'!', 0x11, 0, 0];
        assert_eq!(lzo1x(&s, &mut out), Ok(17));
        assert_eq!(&out[..17], b"abcd\0\0\0\0\0\0\0\0\0\0\0\0!");
        assert_eq!(lzo1x(&s, &mut out[..16]), Err(Corrupt));
        // In version 0 the same bytes are an M4 match far out of reach.
        let mut s0 = s;
        s0[1] = 0;
        assert_eq!(lzo1x(&s0, &mut out), Err(Corrupt));
    }

    /// Mutated and truncated input never panics or overruns `dst`.
    #[test]
    fn hostile_input() {
        let segs = segments();
        let small: Vec<Vec<u8>> = (0..20).map(|i| literal(&noise(1 + i * 3, i as u32))).collect();
        let small_refs: Vec<&[u8]> = small.iter().map(|l| &l[..]).collect();
        let inputs = [
            (frame(&[&segs[0].0, &segs[1].0, &segs[2].0], 4096), 4096, 9192),
            (frame(&small_refs, 64), 64, 700),
            (frame(&[&hex(FAR)], 1 << 16), 1 << 16, 35000),
        ];
        let mut x = 0x2545_f491u32;
        for (z, sectorsize, len) in inputs {
            for _ in 0..4000 {
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
                // Keep the total length right half of the time, to get past the framing.
                if xorshift(&mut x) % 2 == 0 && m.len() >= 4 {
                    let total = m.len() as u32;
                    m[..4].copy_from_slice(&total.to_le_bytes());
                }
                let len = if xorshift(&mut x) % 2 == 0 { len } else { xorshift(&mut x) as usize % (len + 1) };
                let mut dst = std::vec![0; len];
                if let Ok(n) = decompress(&m, &mut dst, sectorsize) {
                    assert!(n <= len);
                }
            }
        }
    }
}
