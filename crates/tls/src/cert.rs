//! Self-signed ECDSA P-256 server certificates, and PEM encoding.
//!
//! A device that serves HTTPS needs a certificate before anyone has had a
//! chance to give it one. [`self_signed`] makes a fresh key and an X.509 v3
//! certificate for it, signed by itself, naming the host names and addresses
//! the server answers on. Clients have to be told to trust it explicitly
//! (for example by pinning it); it is a starting point until the operator
//! installs a certificate from a real CA.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

use osmium_rand::SharedRng;
use p256::ecdsa::signature::Signer as _;
use p256::pkcs8::EncodePrivateKey;

/// A name the certificate is valid for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectName<'a> {
    /// A DNS host name, such as `hyperon.local`.
    Dns(&'a str),
    /// An IP address.
    Ip(IpAddr),
}

/// The period a certificate is valid for, in seconds since the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    /// The first second the certificate is valid.
    pub not_before: u64,
    /// The last second the certificate is valid.
    pub not_after: u64,
}

/// A certificate and its private key, both DER-encoded.
pub struct SelfSigned {
    /// The X.509 certificate.
    pub cert_der: Vec<u8>,
    /// The private key, as PKCS#8. Wiped when dropped.
    pub key_pkcs8_der: Vec<u8>,
}

impl Drop for SelfSigned {
    fn drop(&mut self) {
        osmium_rand::wipe(&mut self.key_pkcs8_der);
    }
}

/// Why [`self_signed`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertError {
    /// No names were given.
    NoNames,
    /// A DNS name was empty or not ASCII.
    InvalidName,
    /// `not_after` is before `not_before`, or a date is past the year 9999.
    InvalidValidity,
    /// The random number generator isn't seeded.
    NoRandomness,
    /// The key couldn't be encoded.
    Encoding,
}

impl core::fmt::Display for CertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            CertError::NoNames => "no subject names",
            CertError::InvalidName => "invalid DNS name",
            CertError::InvalidValidity => "invalid validity period",
            CertError::NoRandomness => "random number generator not seeded",
            CertError::Encoding => "key encoding failed",
        })
    }
}

/// A new P-256 key and a self-signed certificate for `names`.
///
/// The subject's common name is the first DNS name, or `osmium` if there is
/// none. The certificate is an end-entity certificate (`CA:FALSE`) for TLS
/// server authentication only.
pub fn self_signed(rng: &SharedRng, names: &[SubjectName<'_>], validity: Validity) -> Result<SelfSigned, CertError> {
    if names.is_empty() {
        return Err(CertError::NoNames);
    }
    if names.iter().any(|n| matches!(n, SubjectName::Dns(d) if d.is_empty() || !d.is_ascii())) {
        return Err(CertError::InvalidName);
    }
    if validity.not_after < validity.not_before {
        return Err(CertError::InvalidValidity);
    }
    let key = generate_key(rng)?;
    let mut serial = [0u8; 16];
    rng.fill(&mut serial).map_err(|_| CertError::NoRandomness)?;
    // Positive, and with a non-zero first byte, so the INTEGER is minimal as it stands.
    serial[0] = (serial[0] & 0x7f) | 0x40;

    let cn = names
        .iter()
        .find_map(|n| match n {
            SubjectName::Dns(d) => Some(*d),
            SubjectName::Ip(_) => None,
        })
        .unwrap_or("osmium");
    let name = der::seq(&[&der::set(&[&der::seq(&[
        &der::oid(oid::COMMON_NAME),
        &der::tlv(der::UTF8_STRING, cn.as_bytes()),
    ])])]);
    let sig_alg = der::seq(&[&der::oid(oid::ECDSA_WITH_SHA256)]);
    let point = key.verifying_key().to_sec1_point(false);
    let spki = der::seq(&[
        &der::seq(&[&der::oid(oid::EC_PUBLIC_KEY), &der::oid(oid::PRIME256V1)]),
        &der::bit_string(point.as_bytes()),
    ]);
    let validity = der::seq(&[&der::time(validity.not_before)?, &der::time(validity.not_after)?]);

    let mut san = Vec::new();
    for n in names {
        match n {
            SubjectName::Dns(d) => san.extend(der::tlv(0x82, d.as_bytes())),
            SubjectName::Ip(IpAddr::V4(a)) => san.extend(der::tlv(0x87, &a.octets())),
            SubjectName::Ip(IpAddr::V6(a)) => san.extend(der::tlv(0x87, &a.octets())),
        }
    }
    let extensions = der::seq(&[
        &extension(oid::SUBJECT_ALT_NAME, false, &der::tlv(der::SEQUENCE, &san)),
        &extension(oid::BASIC_CONSTRAINTS, true, &der::seq(&[])),
        // digitalSignature only.
        &extension(oid::KEY_USAGE, true, &der::tlv(der::BIT_STRING, &[0x07, 0x80])),
        &extension(oid::EXT_KEY_USAGE, false, &der::seq(&[&der::oid(oid::SERVER_AUTH)])),
    ]);

    let tbs = der::seq(&[
        &der::tlv(0xa0, &der::tlv(der::INTEGER, &[2])), // version 3
        &der::tlv(der::INTEGER, &serial),
        &sig_alg,
        &name,
        &validity,
        &name,
        &spki,
        &der::tlv(0xa3, &extensions),
    ]);
    let sig: p256::ecdsa::Signature = key.sign(&tbs);
    let cert_der = der::seq(&[&tbs, &sig_alg, &der::bit_string(sig.to_der().as_bytes())]);
    let key_pkcs8_der = key.to_pkcs8_der().map_err(|_| CertError::Encoding)?.as_bytes().to_vec();
    Ok(SelfSigned { cert_der, key_pkcs8_der })
}

fn generate_key(rng: &SharedRng) -> Result<p256::ecdsa::SigningKey, CertError> {
    let mut bytes = [0u8; 32];
    // A random 32-byte string is a valid scalar unless it is zero or at least
    // the group order: a chance of about 2^-32 per try.
    for _ in 0..16 {
        rng.fill(&mut bytes).map_err(|_| CertError::NoRandomness)?;
        let key = p256::ecdsa::SigningKey::from_slice(&bytes);
        osmium_rand::wipe(&mut bytes);
        if let Ok(key) = key {
            return Ok(key);
        }
    }
    Err(CertError::NoRandomness)
}

fn extension(id: &[u64], critical: bool, value: &[u8]) -> Vec<u8> {
    let id = der::oid(id);
    let value = der::tlv(der::OCTET_STRING, value);
    if critical { der::seq(&[&id, &[der::BOOLEAN, 1, 0xff], &value]) } else { der::seq(&[&id, &value]) }
}

/// Object identifiers used in certificates.
mod oid {
    pub const COMMON_NAME: &[u64] = &[2, 5, 4, 3];
    pub const EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
    pub const PRIME256V1: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
    pub const ECDSA_WITH_SHA256: &[u64] = &[1, 2, 840, 10045, 4, 3, 2];
    pub const SUBJECT_ALT_NAME: &[u64] = &[2, 5, 29, 17];
    pub const BASIC_CONSTRAINTS: &[u64] = &[2, 5, 29, 19];
    pub const KEY_USAGE: &[u64] = &[2, 5, 29, 15];
    pub const EXT_KEY_USAGE: &[u64] = &[2, 5, 29, 37];
    pub const SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
}

/// Just enough DER to write a certificate.
mod der {
    use alloc::vec::Vec;

    use super::CertError;

    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0c;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;

    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let len = content.len();
        let mut out = Vec::with_capacity(content.len() + 6);
        out.push(tag);
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let bytes = len.to_be_bytes();
            let skip = bytes.iter().take_while(|&&b| b == 0).count();
            let significant = bytes.get(skip..).unwrap_or(&[]);
            out.push(0x80 | significant.len() as u8);
            out.extend_from_slice(significant);
        }
        out.extend_from_slice(content);
        out
    }

    pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
        tlv(SEQUENCE, &parts.concat())
    }

    pub fn set(parts: &[&[u8]]) -> Vec<u8> {
        tlv(SET, &parts.concat())
    }

    pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
        tlv(BIT_STRING, &[&[0u8][..], bytes].concat())
    }

    pub fn oid(arcs: &[u64]) -> Vec<u8> {
        let mut body = Vec::new();
        let (first, rest) = match arcs {
            [a, b, rest @ ..] => (a * 40 + b, rest),
            _ => (0, &[][..]),
        };
        for &arc in core::iter::once(&first).chain(rest) {
            let mut groups = [0u8; 10];
            let mut n = 0;
            let mut v = arc;
            loop {
                if let Some(g) = groups.get_mut(n) {
                    *g = (v & 0x7f) as u8;
                }
                n += 1;
                v >>= 7;
                if v == 0 {
                    break;
                }
            }
            for i in (0..n).rev() {
                let g = groups.get(i).copied().unwrap_or(0);
                body.push(if i == 0 { g } else { g | 0x80 });
            }
        }
        tlv(OID, &body)
    }

    /// UTCTime for 1950–2049, GeneralizedTime after (RFC 5280, section 4.1.2.5).
    pub fn time(unix: u64) -> Result<Vec<u8>, CertError> {
        let days = unix / 86_400;
        let secs = unix % 86_400;
        let (y, m, d) = civil_from_days(days);
        if y > 9999 {
            return Err(CertError::InvalidValidity);
        }
        let (hh, mm, ss) = (secs / 3600, secs / 60 % 60, secs % 60);
        let mut s = alloc::format!("{:02}{m:02}{d:02}{hh:02}{mm:02}{ss:02}Z", y % 100);
        if y < 2050 {
            Ok(tlv(UTC_TIME, s.as_bytes()))
        } else {
            s = alloc::format!("{y:04}{}", s.get(2..).unwrap_or(""));
            Ok(tlv(GENERALIZED_TIME, s.as_bytes()))
        }
    }

    /// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
    pub fn civil_from_days(days: u64) -> (u64, u64, u64) {
        let z = days + 719_468;
        let era = z / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + u64::from(m <= 2);
        (y, m, d)
    }
}

/// PEM-encodes `der` with the given label, such as `CERTIFICATE` or `PRIVATE KEY`.
pub fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = Vec::with_capacity(der.len().div_ceil(3) * 4);
    for chunk in der.chunks(3) {
        let [a, b, c] = [0, 1, 2].map(|i| chunk.get(i).copied().unwrap_or(0));
        let n = u32::from(a) << 16 | u32::from(b) << 8 | u32::from(c);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            b64.push(if i <= chunk.len() {
                ALPHABET.get((n >> shift & 63) as usize).copied().unwrap_or(b'=')
            } else {
                b'='
            });
        }
    }
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 2 * label.len() + 40);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for line in b64.chunks(64) {
        out.extend(line.iter().map(|&b| b as char));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}
