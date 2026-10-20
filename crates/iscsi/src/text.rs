//! Text keys (RFC 7143 §6): `key=value` pairs, each ended by a NUL, in the
//! data segment of Login and Text PDUs.

use alloc::vec::Vec;

/// Appends `key=value` and its NUL to `out`.
pub fn push(out: &mut Vec<u8>, key: &str, value: &str) {
    out.extend_from_slice(key.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value.as_bytes());
    out.push(0);
}

/// The pairs in `data`. Empty strings (padding NULs) are skipped; a pair
/// that is not UTF-8 or has no `=` makes the whole segment malformed
/// (`None`).
pub fn parse(data: &[u8]) -> Option<Vec<(&str, &str)>> {
    data.split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| core::str::from_utf8(s).ok().and_then(|s| s.split_once('=')))
        .collect()
}

/// A numeric value: decimal, or hexadecimal with a `0x` prefix.
pub fn number(value: &str) -> Option<u64> {
    match value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => value.parse().ok(),
    }
}

/// A boolean value: `Yes` or `No`.
pub fn boolean(value: &str) -> Option<bool> {
    match value {
        "Yes" => Some(true),
        "No" => Some(false),
        _ => None,
    }
}

/// `Yes` or `No`.
pub fn yes_no(b: bool) -> &'static str {
    if b { "Yes" } else { "No" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn pairs_round_trip() {
        let mut d = Vec::new();
        push(&mut d, "InitiatorName", "iqn.2026-10.org.osmium:init");
        push(&mut d, "TargetAddress", "10.0.2.100:3260,1");
        d.extend_from_slice(&[0, 0]); // padding
        assert_eq!(
            parse(&d).unwrap(),
            [("InitiatorName", "iqn.2026-10.org.osmium:init"), ("TargetAddress", "10.0.2.100:3260,1")]
        );
        assert_eq!(parse(b"novalue\0"), None);
        assert_eq!(parse(b""), Some(vec![]));
    }

    #[test]
    fn values() {
        assert_eq!((number("8192"), number("0x2000"), number("x")), (Some(8192), Some(8192), None));
        assert_eq!((boolean("Yes"), boolean("No"), boolean("yes")), (Some(true), Some(false), None));
    }
}
