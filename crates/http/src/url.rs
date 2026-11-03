//! Percent-decoding and query strings.

use alloc::string::String;
use alloc::vec::Vec;

/// Decodes `%XX` escapes. `None` if an escape is malformed or the result
/// isn't UTF-8.
pub fn percent_decode(s: &str) -> Option<String> {
    decode(s, false)
}

/// Splits an `application/x-www-form-urlencoded` string, such as a query,
/// into decoded `(name, value)` pairs. `+` means a space. Pairs that don't
/// decode are skipped.
pub fn query_pairs(query: &str) -> impl Iterator<Item = (String, String)> + '_ {
    query.split('&').filter(|p| !p.is_empty()).filter_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        Some((decode(k, true)?, decode(v, true)?))
    })
}

fn decode(s: &str, plus_is_space: bool) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let hi = hex(bytes.next()?)?;
                let lo = hex(bytes.next()?)?;
                out.push(hi << 4 | lo);
            }
            b'+' if plus_is_space => out.push(b' '),
            b => out.push(b),
        }
    }
    String::from_utf8(out).ok()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
