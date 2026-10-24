//! File identifiers: plain ISO 9660 and Joliet (UCS-2) names.

use alloc::string::String;

use osmium_sync::fallible::OutOfMemory;

/// `raw` as text, with anything that is not UTF-8 replaced (like
/// `String::from_utf8_lossy`), failing instead of panicking if memory runs
/// out.
pub fn lossy(raw: &[u8]) -> Result<String, OutOfMemory> {
    let mut s = String::new();
    // An invalid byte becomes a three-byte replacement character.
    s.try_reserve_exact(raw.len().saturating_mul(3))?;
    for chunk in raw.utf8_chunks() {
        s.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            s.push(char::REPLACEMENT_CHARACTER);
        }
    }
    Ok(s)
}

/// A plain ISO 9660 identifier as Linux shows it by default (`map=normal`):
/// lower case, without the `;1` version or a trailing `.` left by an empty
/// extension.
pub fn iso(raw: &[u8]) -> Result<String, OutOfMemory> {
    let mut s = lossy(raw)?;
    s.make_ascii_lowercase();
    let keep = strip_version(&s).trim_end_matches('.').len();
    s.truncate(keep);
    Ok(s)
}

/// A Joliet identifier: big-endian UCS-2 (UTF-16 here), without `;1`.
pub fn joliet(raw: &[u8]) -> Result<String, OutOfMemory> {
    let mut s = ucs2(raw)?;
    let keep = strip_version(&s).len();
    s.truncate(keep);
    Ok(s)
}

/// Decodes big-endian UTF-16, replacing anything invalid.
pub fn ucs2(raw: &[u8]) -> Result<String, OutOfMemory> {
    let units = raw.as_chunks::<2>().0.iter().map(|&c| u16::from_be_bytes(c));
    let mut s = String::new();
    // Each unit is at most three bytes of UTF-8.
    s.try_reserve_exact(raw.len() / 2 * 3)?;
    s.extend(char::decode_utf16(units).map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER)));
    Ok(s)
}

/// `s` without a `;<digits>` version suffix.
fn strip_version(s: &str) -> &str {
    match s.rsplit_once(';') {
        Some((head, version)) if version.bytes().all(|b| b.is_ascii_digit()) => head,
        _ => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_names() {
        assert_eq!(iso(b"README.TXT;1").unwrap(), "readme.txt");
        assert_eq!(iso(b"MAKEFILE.;1").unwrap(), "makefile");
        assert_eq!(iso(b"BOOT").unwrap(), "boot");
        assert_eq!(iso(b"A;B").unwrap(), "a;b");
    }

    #[test]
    fn joliet_names() {
        let raw: alloc::vec::Vec<u8> = "Mixed Case.txt;1".encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(joliet(&raw).unwrap(), "Mixed Case.txt");
        // A surrogate pair, and a lone surrogate.
        assert_eq!(ucs2(&[0xd8, 0x3d, 0xde, 0x00]).unwrap(), "\u{1f600}");
        assert_eq!(ucs2(&[0xd8, 0x3d, 0x00, 0x41]).unwrap(), "\u{fffd}A");
    }
}
