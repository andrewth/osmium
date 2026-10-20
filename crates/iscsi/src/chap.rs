//! CHAP authentication (RFC 7143 §12.1, RFC 1994) with MD5.
//!
//! The initiator proves it knows a shared secret: the target sends an
//! identifier and a random challenge, and the answer is
//! `MD5(identifier || secret || challenge)`. With mutual CHAP the initiator
//! also challenges the target, so each side authenticates the other.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::IscsiError;
use crate::md5::Md5;
use crate::text;

/// The only CHAP algorithm: MD5.
const ALGORITHM_MD5: &str = "5";

/// The longest challenge accepted (RFC 7143 §12.1.3).
const MAX_CHALLENGE: usize = 1024;

/// Credentials for CHAP login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chap {
    /// The name we authenticate as (`CHAP_N`).
    pub name: String,
    /// The secret we share with the target; RFC 7143 asks for at least 96
    /// bits, and iSCSI targets commonly require 12 to 16 bytes.
    pub secret: Vec<u8>,
    /// Also authenticate the target.
    pub mutual: Option<Mutual>,
}

/// What mutual CHAP needs to check the target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mutual {
    /// The name the target must authenticate as.
    pub name: String,
    /// The secret we share with the target for its direction. RFC 7143
    /// requires it to differ from [`Chap::secret`].
    pub secret: Vec<u8>,
    /// Our challenge to the target; its first byte is the identifier. The
    /// caller must supply unpredictable bytes, new for every login.
    pub challenge: [u8; 16],
}

impl Chap {
    /// One-way CHAP as `name` with `secret`.
    pub fn new(name: &str, secret: &[u8]) -> Self {
        Self { name: name.into(), secret: secret.into(), mutual: None }
    }

    /// Also demands that the target prove it knows `secret` as `name`,
    /// challenging it with `challenge` (random bytes).
    pub fn mutual(mut self, name: &str, secret: &[u8], challenge: [u8; 16]) -> Self {
        self.mutual = Some(Mutual { name: name.into(), secret: secret.into(), challenge });
        self
    }
}

/// The CHAP response to `id` and `challenge` for `secret`.
pub fn response(id: u8, secret: &[u8], challenge: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(&[id]);
    h.update(secret);
    h.update(challenge);
    h.finish()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::from("0x");
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A binary key value: hexadecimal with a `0x` prefix or base64 with `0b`
/// (RFC 7143 §6.1).
pub fn decode_binary(value: &str) -> Option<Vec<u8>> {
    if let Some(h) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        if h.is_empty() || h.len() % 2 != 0 {
            return None;
        }
        return h
            .as_bytes()
            .chunks(2)
            .map(|p| Some((char::from(p[0]).to_digit(16)? << 4 | char::from(p[1]).to_digit(16)?) as u8))
            .collect();
    }
    let b = value.strip_prefix("0b").or_else(|| value.strip_prefix("0B"))?;
    let b = b.trim_end_matches('=').as_bytes();
    if b.is_empty() || b.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for &c in b {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = acc << 6 | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Compares in time independent of where the inputs differ.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y)) == 0
}

fn value<'a>(keys: &[(&'a str, &'a str)], key: &str) -> Option<&'a str> {
    keys.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
}

fn bad(m: &'static str) -> IscsiError {
    IscsiError::Negotiation(m)
}

/// The keys that start CHAP once the target has agreed to it.
pub(crate) fn start() -> Vec<u8> {
    let mut out = Vec::new();
    text::push(&mut out, "CHAP_A", ALGORITHM_MD5);
    out
}

/// The target's challenge in `keys` (its reply to [`start`]).
fn challenge(keys: &[(&str, &str)]) -> Result<(u8, Vec<u8>), IscsiError> {
    if value(keys, "CHAP_A").is_none_or(|a| a != ALGORITHM_MD5) {
        return Err(bad("target did not choose CHAP with MD5"));
    }
    let id = value(keys, "CHAP_I").and_then(text::number).and_then(|i| u8::try_from(i).ok());
    let id = id.ok_or(bad("bad CHAP_I"))?;
    let c = value(keys, "CHAP_C").and_then(decode_binary).ok_or(bad("bad CHAP_C"))?;
    if c.is_empty() || c.len() > MAX_CHALLENGE {
        return Err(bad("CHAP_C has a bad length"));
    }
    Ok((id, c))
}

/// Answers the target's challenge in `keys`: the text to send, and for
/// mutual CHAP the response the target must give to ours.
pub(crate) fn answer(chap: &Chap, keys: &[(&str, &str)]) -> Result<(Vec<u8>, Option<[u8; 16]>), IscsiError> {
    let (id, c) = challenge(keys)?;
    let mut out = Vec::new();
    text::push(&mut out, "CHAP_N", &chap.name);
    text::push(&mut out, "CHAP_R", &hex(&response(id, &chap.secret, &c)));
    let mut expected = None;
    if let Some(m) = &chap.mutual {
        // A target that reflects our own challenge back would be
        // authenticated by our own answer (RFC 7143 §12.1.3).
        if same(&c, &m.challenge) {
            return Err(bad("target reflected our CHAP challenge"));
        }
        let mid = m.challenge[0];
        text::push(&mut out, "CHAP_I", &mid.to_string());
        text::push(&mut out, "CHAP_C", &hex(&m.challenge));
        expected = Some(response(mid, &m.secret, &m.challenge));
    }
    Ok((out, expected))
}

/// Checks the target's final reply: with mutual CHAP, its name and response.
pub(crate) fn verify(chap: &Chap, expected: Option<[u8; 16]>, keys: &[(&str, &str)]) -> Result<(), IscsiError> {
    let (Some(m), Some(expected)) = (&chap.mutual, expected) else {
        return Ok(());
    };
    if value(keys, "CHAP_N") != Some(m.name.as_str()) {
        return Err(bad("target authenticated as the wrong name"));
    }
    let r = value(keys, "CHAP_R").and_then(decode_binary).ok_or(bad("bad CHAP_R"))?;
    if !same(&r, &expected) {
        return Err(bad("target failed CHAP authentication"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_is_md5_of_id_secret_challenge() {
        let r = response(7, b"secret", b"\x01\x02\x03");
        assert_ne!(r, response(8, b"secret", &[1, 2, 3]));
        assert_eq!(response(1, b"abc", b"def"), crate::md5::md5(b"\x01abcdef"));
    }

    #[test]
    fn binary_values() {
        assert_eq!(decode_binary("0x0aFf").unwrap(), [0x0a, 0xff]);
        assert_eq!(decode_binary("0b/+8=").unwrap(), [0xff, 0xef]);
        assert_eq!(decode_binary("0bTWFu").unwrap(), b"Man");
        assert_eq!(decode_binary("0bTWE=").unwrap(), b"Ma");
        for v in ["", "0x", "0xabc", "0xzz", "0b", "0b!!!!", "abcd", "0bA"] {
            assert_eq!(decode_binary(v), None, "{v:?}");
        }
        assert_eq!(hex(&[1, 0xab]), "0x01ab");
    }

    #[test]
    fn answers_and_verification() {
        let chap = Chap::new("user", b"0123456789abcdef").mutual("tgt", b"fedcba9876543210", [9; 16]);
        let mut keys = std::vec![("CHAP_A", "5"), ("CHAP_I", "3"), ("CHAP_C", "0x0102030405")];
        let (out, expected) = answer(&chap, &keys).unwrap();
        let sent = text::parse(&out).unwrap();
        assert_eq!(value(&sent, "CHAP_N"), Some("user"));
        assert_eq!(
            value(&sent, "CHAP_R").and_then(decode_binary).unwrap(),
            response(3, b"0123456789abcdef", &[1, 2, 3, 4, 5])
        );
        assert_eq!(value(&sent, "CHAP_I"), Some("9"));
        let theirs = hex(&expected.unwrap());
        let ok = [("CHAP_N", "tgt"), ("CHAP_R", theirs.as_str())];
        verify(&chap, expected, &ok).unwrap();
        assert!(verify(&chap, expected, &[("CHAP_N", "other"), ("CHAP_R", theirs.as_str())]).is_err());
        assert!(verify(&chap, expected, &[("CHAP_N", "tgt"), ("CHAP_R", "0x00")]).is_err());
        assert!(verify(&chap, expected, &[("CHAP_N", "tgt")]).is_err());

        let reflected = hex(&[9; 16]);
        keys[2].1 = &reflected;
        assert!(answer(&chap, &keys).is_err());
        assert!(answer(&chap, &[("CHAP_A", "7"), ("CHAP_I", "3"), ("CHAP_C", "0x01")]).is_err());
        assert!(answer(&chap, &[("CHAP_A", "5"), ("CHAP_I", "256"), ("CHAP_C", "0x01")]).is_err());
        assert!(answer(&chap, &[("CHAP_A", "5"), ("CHAP_I", "1")]).is_err());
    }
}
