//! File identifiers: plain ISO 9660 and Joliet (UCS-2) names.

use alloc::string::String;

/// A plain ISO 9660 identifier as Linux shows it by default (`map=normal`):
/// lower case, without the `;1` version or a trailing `.` left by an empty
/// extension.
pub fn iso(raw: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(raw).into_owned();
    s.make_ascii_lowercase();
    let keep = strip_version(&s).trim_end_matches('.').len();
    s.truncate(keep);
    s
}

/// A Joliet identifier: big-endian UCS-2 (UTF-16 here), without `;1`.
pub fn joliet(raw: &[u8]) -> String {
    let mut s = ucs2(raw);
    let keep = strip_version(&s).len();
    s.truncate(keep);
    s
}

/// Decodes big-endian UTF-16, replacing anything invalid.
pub fn ucs2(raw: &[u8]) -> String {
    let units = raw.as_chunks::<2>().0.iter().map(|&c| u16::from_be_bytes(c));
    char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
}

/// `s` without a `;<digits>` version suffix.
fn strip_version(s: &str) -> &str {
    match s.rfind(';') {
        Some(i) if s[i + 1..].bytes().all(|b| b.is_ascii_digit()) => &s[..i],
        _ => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_names() {
        assert_eq!(iso(b"README.TXT;1"), "readme.txt");
        assert_eq!(iso(b"MAKEFILE.;1"), "makefile");
        assert_eq!(iso(b"BOOT"), "boot");
        assert_eq!(iso(b"A;B"), "a;b");
    }

    #[test]
    fn joliet_names() {
        let raw: alloc::vec::Vec<u8> = "Mixed Case.txt;1".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(joliet(&raw), "Mixed Case.txt");
        // A surrogate pair, and a lone surrogate.
        assert_eq!(ucs2(&[0xd8, 0x3d, 0xde, 0x00]), "\u{1f600}");
        assert_eq!(ucs2(&[0xd8, 0x3d, 0x00, 0x41]), "\u{fffd}A");
    }
}
