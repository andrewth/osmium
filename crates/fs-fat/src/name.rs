//! File names: validation, 8.3 short names and VFAT long names (Microsoft
//! FAT specification §6, §7).

use alloc::string::String;
use alloc::vec::Vec;

use osmium_fs::Errno;

/// Longest long name, in UTF-16 code units.
pub const MAX_NAME: usize = 255;

/// UTF-16 code units per long-name directory entry.
pub const LFN_CHARS: usize = 13;

/// NTRes bits: the base name or extension is stored upper case but shown
/// lower case (as Windows NT and Linux use them).
pub const LOWER_BASE: u8 = 0x08;
/// See [`LOWER_BASE`].
pub const LOWER_EXT: u8 = 0x10;

/// Checks that `name` can be a FAT long name.
pub fn validate(name: &str) -> Result<(), Errno> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(Errno::EINVAL);
    }
    if name.encode_utf16().count() > MAX_NAME {
        return Err(Errno::ENAMETOOLONG);
    }
    if name.chars().any(|c| (c as u32) < 0x20 || "\"*/:<>?\\|".contains(c)) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Characters allowed in a short name besides A–Z and 0–9.
fn short_char_ok(c: u8) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit() || b"$%'-_@~`!(){}^#&".contains(&c)
}

/// The checksum of a short name that ties long-name entries to it.
pub fn checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, &c| sum.rotate_right(1).wrapping_add(c))
}

/// How a short name is shown: `NAME.EXT`, with the NTRes case bits applied.
pub fn short_to_string(short: &[u8; 11], ntres: u8) -> String {
    let mut out = String::new();
    let part = |bytes: &[u8], lower: bool, out: &mut String| {
        for &b in bytes.iter().take_while(|&&b| b != b' ') {
            // 0x05 stands for a leading 0xE5 (which marks a free entry).
            let b = if b == 0x05 { 0xe5 } else { b };
            let c = if lower { b.to_ascii_lowercase() } else { b };
            // Bytes above 0x7f are in an OEM code page we do not know.
            out.push(if c.is_ascii() { c as char } else { '_' });
        }
    };
    part(&short[..8], ntres & LOWER_BASE != 0, &mut out);
    if short[8] != b' ' {
        out.push('.');
        part(&short[8..], ntres & LOWER_EXT != 0, &mut out);
    }
    out
}

/// If `name` can be stored as a short name alone (8.3, short-name
/// characters, and each part either all lower or all upper case), returns
/// the short name and its NTRes case bits.
pub fn exact_short(name: &str) -> Option<([u8; 11], u8)> {
    let (base, ext) = match name.rfind('.') {
        Some(i) => (&name[..i], &name[i + 1..]),
        None => (name, ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 || (name.contains('.') && ext.is_empty()) {
        return None;
    }
    let mut short = [b' '; 11];
    let mut ntres = 0;
    let (base_field, ext_field) = short.split_at_mut(8);
    for (part, field, flag) in [(base, base_field, LOWER_BASE), (ext, ext_field, LOWER_EXT)] {
        let lower = part.bytes().any(|b| b.is_ascii_lowercase());
        let upper = part.bytes().any(|b| b.is_ascii_uppercase());
        if lower && upper {
            return None;
        }
        if lower {
            ntres |= flag;
        }
        for (i, b) in part.bytes().enumerate() {
            let b = b.to_ascii_uppercase();
            if !short_char_ok(b) {
                return None;
            }
            field[i] = b;
        }
    }
    if short[0] == 0xe5 {
        short[0] = 0x05;
    }
    Some((short, ntres))
}

/// Generates the short name for a long name (§6.1's "numeric-tail"
/// algorithm), choosing the first `~N` not in `taken`.
pub fn generate_short(name: &str, taken: &[[u8; 11]]) -> Result<[u8; 11], Errno> {
    let clean = |s: &str| -> Vec<u8> {
        s.chars()
            .filter(|&c| c != ' ' && c != '.')
            .map(|c| {
                let u = c.to_ascii_uppercase();
                if u.is_ascii() && short_char_ok(u as u8) { u as u8 } else { b'_' }
            })
            .collect()
    };
    let trimmed = name.trim_start_matches('.');
    let (base, ext) = match trimmed.rfind('.') {
        Some(i) => (clean(&trimmed[..i]), clean(&trimmed[i + 1..])),
        None => (clean(trimmed), Vec::new()),
    };
    let base: &[u8] = if base.is_empty() { b"_" } else { &base };
    let mut short = [b' '; 11];
    for (i, &b) in ext.iter().take(3).enumerate() {
        short[8 + i] = b;
    }
    for n in 1..1_000_000u32 {
        let mut tail = [0u8; 8];
        let mut t = n;
        let mut len = 0;
        while t > 0 {
            tail[7 - len] = b'0' + (t % 10) as u8;
            t /= 10;
            len += 1;
        }
        let tail = &tail[8 - len..];
        let keep = base.len().min(8 - 1 - len);
        short[..8].fill(b' ');
        short[..keep].copy_from_slice(&base[..keep]);
        short[keep] = b'~';
        short[keep + 1..keep + 1 + len].copy_from_slice(tail);
        if !taken.contains(&short) {
            return Ok(short);
        }
    }
    Err(Errno::EEXIST)
}

/// The long-name entries for `name` with short-name checksum `sum`, in
/// on-disk order (last part first).
pub fn lfn_entries(name: &str, sum: u8) -> Vec<[u8; 32]> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let count = units.len().div_ceil(LFN_CHARS);
    let mut out = Vec::with_capacity(count);
    for seq in (1..=count).rev() {
        let mut e = [0u8; 32];
        e[0] = seq as u8 | if seq == count { 0x40 } else { 0 };
        e[11] = 0x0f;
        e[13] = sum;
        let chunk = &units[(seq - 1) * LFN_CHARS..];
        for i in 0..LFN_CHARS {
            // The name ends with a NUL, then 0xFFFF padding.
            let u = match i.cmp(&chunk.len()) {
                core::cmp::Ordering::Less => chunk[i],
                core::cmp::Ordering::Equal => 0,
                core::cmp::Ordering::Greater => 0xffff,
            };
            let at = LFN_OFFSETS[i];
            e[at..at + 2].copy_from_slice(&u.to_le_bytes());
        }
        out.push(e);
    }
    out
}

/// Byte offsets of the 13 UTF-16 units in a long-name entry.
pub const LFN_OFFSETS: [usize; LFN_CHARS] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];

/// The UTF-16 units of one long-name entry, up to the terminating NUL.
pub fn lfn_units(e: &[u8]) -> impl Iterator<Item = u16> + '_ {
    LFN_OFFSETS.iter().map(|&at| u16::from_le_bytes([e[at], e[at + 1]])).take_while(|&u| u != 0 && u != 0xffff)
}

/// Case-insensitive name comparison, as FAT requires (ASCII folding only).
pub fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(b: &[u8; 11]) -> &str {
        core::str::from_utf8(b).unwrap()
    }

    #[test]
    fn validation() {
        assert_eq!(validate("hello world.txt"), Ok(()));
        assert_eq!(validate("a:b"), Err(Errno::EINVAL));
        assert_eq!(validate(""), Err(Errno::EINVAL));
        assert_eq!(validate(&"x".repeat(256)), Err(Errno::ENAMETOOLONG));
        assert_eq!(validate(&"é".repeat(255)), Ok(()), "limit counts UTF-16 units, not bytes");
    }

    #[test]
    fn exact_short_names() {
        assert_eq!(exact_short("README.TXT"), Some((*b"README  TXT", 0)));
        assert_eq!(exact_short("readme.txt"), Some((*b"README  TXT", LOWER_BASE | LOWER_EXT)));
        assert_eq!(exact_short("Makefile"), None, "mixed case needs a long name");
        assert_eq!(exact_short("a.tar.gz"), None);
        assert_eq!(exact_short("toolongname"), None);
        assert_eq!(exact_short("with space"), None);
        let (n, f) = exact_short("boot").unwrap();
        assert_eq!(short_to_string(&n, f), "boot");
        assert_eq!(short_to_string(b"README  TXT", 0), "README.TXT");
    }

    #[test]
    fn generated_short_names() {
        let a = generate_short("Long File Name.html", &[]).unwrap();
        assert_eq!(s(&a), "LONGFI~1HTM");
        let b = generate_short("Long File Name.html", &[a]).unwrap();
        assert_eq!(s(&b), "LONGFI~2HTM");
        assert_eq!(s(&generate_short(".bashrc", &[]).unwrap()), "BASHRC~1   ");
        assert_eq!(s(&generate_short("naïve", &[]).unwrap()), "NA_VE~1    ");
        let many: Vec<[u8; 11]> = (1..=9)
            .map(|n| {
                generate_short("x", &[])
                    .map(|mut v| {
                        v[2] = b'0' + n;
                        v
                    })
                    .unwrap()
            })
            .collect();
        assert_eq!(s(&generate_short("x", &many).unwrap()), "X~10       ", "the tail grows past 9");
    }

    #[test]
    fn long_name_entries() {
        let short = *b"LONGFI~1HTM";
        let sum = checksum(&short);
        let es = lfn_entries("Long File Name.html", sum);
        assert_eq!(es.len(), 2);
        assert_eq!(es[0][0], 0x42, "last part first, with the 0x40 flag");
        assert_eq!(es[1][0], 0x01);
        let mut name: Vec<u16> = es.iter().rev().flat_map(|e| lfn_units(e)).collect();
        assert_eq!(String::from_utf16(&name).unwrap(), "Long File Name.html");
        name.clear();
        assert!(es.iter().all(|e| e[11] == 0x0f && e[13] == sum));
        // Exactly 13 units: no terminator, no padding.
        let one = lfn_entries("abcdefghijklm", 0);
        assert_eq!((one.len(), lfn_units(&one[0]).count()), (1, 13));
    }

    #[test]
    fn checksum_matches_spec_algorithm() {
        // Computed independently with the specification's ChkSum routine.
        assert_eq!(checksum(b"FOO     BAR"), 0x53);
    }
}
