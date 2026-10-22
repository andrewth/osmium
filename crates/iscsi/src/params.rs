//! Login key negotiation (RFC 7143 §6, §13).
//!
//! The initiator offers values in its Login Requests and the target answers
//! with the results; the target may also offer keys of its own, which are
//! answered in the next request. Each key's result follows its function:
//! the minimum for lengths and counts, OR for `InitialR2T`, AND for
//! `ImmediateData`, and so on. Declarative keys such as
//! `MaxRecvDataSegmentLength` take effect as sent, one per direction.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::IscsiError;
use crate::text::{self, boolean, number, yes_no};

/// Whether to use a CRC32C digest (`HeaderDigest` or `DataDigest`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DigestPolicy {
    /// No digest; fail if the target insists on one.
    #[default]
    Off,
    /// Use one if the target supports it (`CRC32C,None`).
    Prefer,
    /// Use one or fail the login (`CRC32C`).
    Require,
}

impl DigestPolicy {
    fn offer(self) -> &'static str {
        match self {
            Self::Off => "None",
            Self::Prefer => "CRC32C,None",
            Self::Require => "CRC32C",
        }
    }

    /// Picks from a list of values the target allows.
    fn choose(self, value: &str) -> Result<bool, IscsiError> {
        let has = |v| value.split(',').any(|x| x == v);
        match self {
            Self::Off if has("None") => Ok(false),
            Self::Off => Err(IscsiError::Negotiation("target requires digests")),
            Self::Prefer if has("CRC32C") => Ok(true),
            Self::Prefer if has("None") => Ok(false),
            Self::Require if has("CRC32C") => Ok(true),
            _ => Err(IscsiError::Negotiation("target does not agree on a digest")),
        }
    }
}

/// What the initiator asks for in operational negotiation. The values in
/// effect are the [`Params`] the target agreed to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    /// The longest data segment the target may send us (declarative).
    pub max_recv_data_segment_length: u32,
    /// The longest solicited data sequence: one R2T's worth, or one burst
    /// of Data-In.
    pub max_burst_length: u32,
    /// The most unsolicited data (immediate plus Data-Out before any R2T)
    /// a write may send.
    pub first_burst_length: u32,
    /// Ask for an R2T before any Data-Out (`No` allows unsolicited
    /// Data-Out).
    pub initial_r2t: bool,
    /// Allow data in the SCSI Command PDU itself.
    pub immediate_data: bool,
    /// CRC32C over each PDU header.
    pub header_digest: DigestPolicy,
    /// CRC32C over each data segment.
    pub data_digest: DigestPolicy,
}

impl Default for Offer {
    fn default() -> Self {
        Self {
            max_recv_data_segment_length: 65536,
            max_burst_length: 262_144,
            first_burst_length: 65536,
            initial_r2t: false,
            immediate_data: true,
            header_digest: DigestPolicy::Off,
            data_digest: DigestPolicy::Off,
        }
    }
}

/// The operational parameters in effect for a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// The longest data segment the target sends us.
    pub max_recv_data_segment_length: u32,
    /// The longest data segment we may send: the target's declared
    /// `MaxRecvDataSegmentLength`.
    pub max_xmit_data_segment_length: u32,
    /// The longest solicited data sequence.
    pub max_burst_length: u32,
    /// The most unsolicited data per write.
    pub first_burst_length: u32,
    /// Data-Out waits for an R2T.
    pub initial_r2t: bool,
    /// The SCSI Command PDU may carry data.
    pub immediate_data: bool,
    /// PDU headers carry a CRC32C digest.
    pub header_digest: bool,
    /// Data segments carry a CRC32C digest.
    pub data_digest: bool,
    /// R2Ts outstanding per command; always 1 here.
    pub max_outstanding_r2t: u32,
    /// Always 0: a failure ends the session.
    pub error_recovery_level: u8,
    /// Seconds to wait before reconnecting after a logout or failure.
    pub default_time2wait: u16,
    /// Seconds the target keeps state for a reconnection.
    pub default_time2retain: u16,
    /// Data PDUs arrive in increasing offset order.
    pub data_pdu_in_order: bool,
    /// Data sequences arrive in increasing offset order.
    pub data_sequence_in_order: bool,
    /// Connections per session; always 1 here.
    pub max_connections: u16,
    /// The target's `TargetAlias`, if it sent one.
    pub target_alias: Option<String>,
    /// The target's `TargetPortalGroupTag`, if it sent one.
    pub target_portal_group_tag: Option<u16>,
}

impl Default for Params {
    /// The RFC 7143 defaults, in effect for whatever is not negotiated.
    fn default() -> Self {
        Self {
            max_recv_data_segment_length: 8192,
            max_xmit_data_segment_length: 8192,
            max_burst_length: 262_144,
            first_burst_length: 65536,
            initial_r2t: true,
            immediate_data: true,
            header_digest: false,
            data_digest: false,
            max_outstanding_r2t: 1,
            error_recovery_level: 0,
            default_time2wait: 2,
            default_time2retain: 20,
            data_pdu_in_order: true,
            data_sequence_in_order: true,
            max_connections: 1,
            target_alias: None,
            target_portal_group_tag: None,
        }
    }
}

/// Values the initiator sends for keys that are not in [`Offer`].
const TIME2WAIT: u16 = 2;
const TIME2RETAIN: u16 = 0;

/// The smallest and largest data segment lengths allowed (RFC 7143 §13.12).
const MIN_DSL: u64 = 512;
const MAX_DSL: u64 = (1 << 24) - 1;

/// Keys that are negotiated at most once per login (RFC 7143 section 6.2): a
/// second appearance, from either side, would renegotiate the result.
const ONCE: [&str; 15] = [
    "AuthMethod",
    "HeaderDigest",
    "DataDigest",
    "MaxRecvDataSegmentLength",
    "MaxBurstLength",
    "FirstBurstLength",
    "MaxOutstandingR2T",
    "MaxConnections",
    "ErrorRecoveryLevel",
    "DefaultTime2Wait",
    "DefaultTime2Retain",
    "InitialR2T",
    "ImmediateData",
    "DataPDUInOrder",
    "DataSequenceInOrder",
];

/// Tracks one login's negotiation.
pub(crate) struct Negotiator {
    offer: Offer,
    /// The results so far.
    pub(crate) params: Params,
    /// Keys we offered and the target has not answered yet.
    offered: Vec<&'static str>,
    /// CHAP is the only authentication we accept.
    chap: bool,
    /// The [`ONCE`] keys the target has answered or offered already.
    settled: Vec<&'static str>,
}

impl Negotiator {
    pub(crate) fn new(offer: Offer) -> Self {
        Self { offer, params: Params::default(), offered: Vec::new(), chap: false, settled: Vec::new() }
    }

    fn offer(&mut self, out: &mut Vec<u8>, key: &'static str, value: &str) {
        text::push(out, key, value);
        self.offered.push(key);
    }

    /// The SecurityNegotiation keys of the first Login Request. A discovery
    /// session names no target. With `chap`, authentication is required and
    /// CHAP is the method offered.
    pub(crate) fn security_keys(&mut self, initiator_name: &str, target_name: Option<&str>, chap: bool) -> Vec<u8> {
        self.chap = chap;
        let mut out = Vec::new();
        text::push(&mut out, "InitiatorName", initiator_name);
        match target_name {
            Some(name) => {
                text::push(&mut out, "SessionType", "Normal");
                text::push(&mut out, "TargetName", name);
            }
            None => text::push(&mut out, "SessionType", "Discovery"),
        }
        self.offer(&mut out, "AuthMethod", if chap { "CHAP" } else { "None" });
        out
    }

    /// The LoginOperationalNegotiation keys. A discovery session moves no
    /// SCSI data, so it negotiates only digests and segment length.
    pub(crate) fn operational_keys(&mut self, discovery: bool) -> Vec<u8> {
        let o = self.offer.clone();
        let mut out = Vec::new();
        self.offer(&mut out, "HeaderDigest", o.header_digest.offer());
        self.offer(&mut out, "DataDigest", o.data_digest.offer());
        let mrdsl = (o.max_recv_data_segment_length as u64).clamp(MIN_DSL, MAX_DSL) as u32;
        text::push(&mut out, "MaxRecvDataSegmentLength", &mrdsl.to_string());
        self.params.max_recv_data_segment_length = mrdsl;
        if discovery {
            return out;
        }
        self.offer(&mut out, "InitialR2T", yes_no(o.initial_r2t));
        self.offer(&mut out, "ImmediateData", yes_no(o.immediate_data));
        self.offer(&mut out, "MaxBurstLength", &o.max_burst_length.to_string());
        self.offer(&mut out, "FirstBurstLength", &o.first_burst_length.to_string());
        self.offer(&mut out, "MaxOutstandingR2T", "1");
        self.offer(&mut out, "MaxConnections", "1");
        self.offer(&mut out, "ErrorRecoveryLevel", "0");
        self.offer(&mut out, "DefaultTime2Wait", &TIME2WAIT.to_string());
        self.offer(&mut out, "DefaultTime2Retain", &TIME2RETAIN.to_string());
        self.offer(&mut out, "DataPDUInOrder", "Yes");
        self.offer(&mut out, "DataSequenceInOrder", "Yes");
        out
    }

    /// Settles the keys of a declined offer: the RFC 7143 default stays in
    /// effect, except that where it is more than we offered we keep to our
    /// offer (a smaller burst, or no immediate data, is always allowed).
    /// `InitialR2T` keeps its default of Yes, the safe side of its OR function.
    fn keep_default(&mut self, key: &str) {
        let (p, o) = (&mut self.params, &self.offer);
        match key {
            "MaxBurstLength" => p.max_burst_length = p.max_burst_length.min(o.max_burst_length),
            "FirstBurstLength" => p.first_burst_length = p.first_burst_length.min(o.first_burst_length),
            "ImmediateData" => p.immediate_data &= o.immediate_data,
            "InitialR2T" => p.initial_r2t = true,
            _ => {}
        }
    }

    /// Ends the operational negotiation. A key we offered that the target
    /// never answered is treated like a declined one ([`keep_default`]), and
    /// for the digests that means none: so a [`DigestPolicy::Require`]
    /// the target did not answer with `CRC32C` fails the login rather than
    /// running without the digest.
    pub(crate) fn finish(&mut self) -> Result<(), IscsiError> {
        for key in core::mem::take(&mut self.offered) {
            match key {
                "HeaderDigest" if self.offer.header_digest == DigestPolicy::Require => {
                    return Err(IscsiError::Negotiation("target did not answer our required HeaderDigest"));
                }
                "DataDigest" if self.offer.data_digest == DigestPolicy::Require => {
                    return Err(IscsiError::Negotiation("target did not answer our required DataDigest"));
                }
                _ => self.keep_default(key),
            }
        }
        let p = &mut self.params;
        p.first_burst_length = p.first_burst_length.min(p.max_burst_length);
        Ok(())
    }

    /// Applies the keys of a Login Response and returns the answers owed
    /// for keys the target offered itself.
    pub(crate) fn respond(&mut self, data: &[u8]) -> Result<Vec<u8>, IscsiError> {
        let bad = IscsiError::Negotiation;
        let pairs = text::parse(data).ok_or(IscsiError::Protocol("malformed login text"))?;
        let mut replies = Vec::new();
        for (key, value) in pairs {
            if let Some(&once) = ONCE.iter().find(|&&k| k == key) {
                if self.settled.contains(&once) {
                    return Err(bad("target renegotiated a key"));
                }
                self.settled.push(once);
            }
            let ours = match self.offered.iter().position(|k| *k == key) {
                Some(i) => {
                    self.offered.swap_remove(i);
                    true
                }
                None => false,
            };
            if matches!(value, "Reject" | "Irrelevant" | "NotUnderstood") {
                // The default stays in effect (RFC 7143 §6.2), which is
                // fine for anything but authentication and digests. Where
                // the default is more than we offered, we keep to our offer:
                // a smaller burst, or no immediate data, is always allowed.
                match key {
                    "AuthMethod" => return Err(bad("target rejected our AuthMethod")),
                    "HeaderDigest" | "DataDigest" => return Err(bad("target rejected our digest offer")),
                    _ => self.keep_default(key),
                }
                continue;
            }
            let p = &mut self.params;
            let o = &self.offer;
            let num =
                |min: u64, max: u64| number(value).filter(|v| (min..=max).contains(v)).ok_or(bad("bad numeric value"));
            // A key with the minimum function: the target's answer to our
            // offer may not exceed it, and its own offer is cut to ours.
            let least = |min: u64, max: u64, offered: u64| match num(min, max)? {
                v if ours && v > offered => Err(bad("target chose more than we offered")),
                v => Ok(v.min(offered)),
            };
            let flag = || boolean(value).ok_or(bad("bad boolean value"));
            // The result, to send back if the target offered the key.
            let result: Option<String> = match key {
                "AuthMethod" => {
                    let want = if self.chap { "CHAP" } else { "None" };
                    if !value.split(',').any(|v| v == want) {
                        return Err(bad(if self.chap {
                            "target does not offer CHAP"
                        } else {
                            "target requires authentication"
                        }));
                    }
                    Some(want.into())
                }
                "HeaderDigest" | "DataDigest" => {
                    let policy = if key == "HeaderDigest" { o.header_digest } else { o.data_digest };
                    // Our offer's answer is one value from it; a digest the
                    // target itself offers is chosen from its list.
                    let on = if ours {
                        match (value, policy) {
                            ("None", DigestPolicy::Off | DigestPolicy::Prefer) => false,
                            ("CRC32C", DigestPolicy::Prefer | DigestPolicy::Require) => true,
                            _ => return Err(bad("target chose a digest we did not offer")),
                        }
                    } else {
                        policy.choose(value)?
                    };
                    if key == "HeaderDigest" {
                        p.header_digest = on;
                    } else {
                        p.data_digest = on;
                    }
                    Some(if on { "CRC32C" } else { "None" }.into())
                }
                // CHAP is handled by the session, which sees the same text.
                k if k.starts_with("CHAP_") => None,
                "MaxRecvDataSegmentLength" => {
                    p.max_xmit_data_segment_length = num(MIN_DSL, MAX_DSL)? as u32;
                    None
                }
                "MaxBurstLength" => {
                    p.max_burst_length = least(MIN_DSL, MAX_DSL, o.max_burst_length.into())? as u32;
                    Some(p.max_burst_length.to_string())
                }
                "FirstBurstLength" => {
                    p.first_burst_length = least(MIN_DSL, MAX_DSL, o.first_burst_length.into())? as u32;
                    Some(p.first_burst_length.to_string())
                }
                "MaxOutstandingR2T" => {
                    p.max_outstanding_r2t = least(1, 65535, 1)? as u32;
                    Some("1".into())
                }
                "MaxConnections" => {
                    p.max_connections = least(1, 65535, 1)? as u16;
                    Some("1".into())
                }
                "ErrorRecoveryLevel" => {
                    p.error_recovery_level = least(0, 2, 0)? as u8;
                    Some("0".into())
                }
                "DefaultTime2Wait" => {
                    // The maximum function: the answer may not be below ours.
                    p.default_time2wait = match num(0, 3600)? as u16 {
                        v if ours && v < TIME2WAIT => return Err(bad("target chose less than we offered")),
                        v => v.max(TIME2WAIT),
                    };
                    Some(p.default_time2wait.to_string())
                }
                "DefaultTime2Retain" => {
                    p.default_time2retain = least(0, 3600, TIME2RETAIN.into())? as u16;
                    Some(p.default_time2retain.to_string())
                }
                "InitialR2T" => {
                    p.initial_r2t = flag()? || o.initial_r2t;
                    Some(yes_no(p.initial_r2t).into())
                }
                "ImmediateData" => {
                    p.immediate_data = flag()? && o.immediate_data;
                    Some(yes_no(p.immediate_data).into())
                }
                // We need in-order data, which the OR function guarantees.
                "DataPDUInOrder" => {
                    flag()?;
                    Some("Yes".into())
                }
                "DataSequenceInOrder" => {
                    flag()?;
                    Some("Yes".into())
                }
                "TargetAlias" => {
                    p.target_alias = Some(value.into());
                    None
                }
                "TargetPortalGroupTag" => {
                    p.target_portal_group_tag = Some(num(0, 65535)? as u16);
                    None
                }
                "TargetAddress" | "SessionType" | "TargetName" | "InitiatorName" | "InitiatorAlias" => None,
                // Markers (obsolete) and anything else are declined.
                "IFMarker" | "OFMarker" => Some("No".into()),
                _ => Some("NotUnderstood".into()),
            };
            if !ours && let Some(r) = result {
                text::push(&mut replies, key, &r);
            }
        }
        let p = &mut self.params;
        p.first_burst_length = p.first_burst_length.min(p.max_burst_length);
        Ok(replies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    fn keys(data: &[u8]) -> Vec<(&str, &str)> {
        text::parse(data).unwrap()
    }

    #[test]
    fn offers_and_results() {
        let mut n = Negotiator::new(Offer::default());
        let sec = n.security_keys("iqn.init", Some("iqn.target"), false);
        assert_eq!(
            keys(&sec),
            [
                ("InitiatorName", "iqn.init"),
                ("SessionType", "Normal"),
                ("TargetName", "iqn.target"),
                ("AuthMethod", "None")
            ]
        );
        assert_eq!(n.respond(b"AuthMethod=None\0TargetPortalGroupTag=1\0").unwrap(), vec![]);
        assert_eq!(n.params.target_portal_group_tag, Some(1));

        let op = n.operational_keys(false);
        assert!(keys(&op).contains(&("MaxRecvDataSegmentLength", "65536")));
        assert!(keys(&op).contains(&("InitialR2T", "No")));
        let mut resp = Vec::new();
        for (k, v) in [
            ("HeaderDigest", "None"),
            ("DataDigest", "None"),
            ("MaxRecvDataSegmentLength", "4096"),
            ("InitialR2T", "Yes"),
            ("ImmediateData", "No"),
            ("MaxBurstLength", "131072"),
            ("FirstBurstLength", "0x8000"),
            ("DefaultTime2Wait", "5"),
            ("DefaultTime2Retain", "0"),
            ("ErrorRecoveryLevel", "0"),
        ] {
            text::push(&mut resp, k, v);
        }
        assert_eq!(n.respond(&resp).unwrap(), vec![], "no answers owed for keys we offered");
        let p = &n.params;
        assert_eq!((p.max_recv_data_segment_length, p.max_xmit_data_segment_length), (65536, 4096));
        assert_eq!((p.initial_r2t, p.immediate_data), (true, false));
        assert_eq!((p.max_burst_length, p.first_burst_length), (131_072, 32768));
        assert_eq!(p.default_time2wait, 5);
    }

    #[test]
    fn target_offers_are_answered() {
        let mut n = Negotiator::new(Offer { max_burst_length: 65536, ..Offer::default() });
        n.security_keys("i", Some("t"), false);
        let replies = n
            .respond(
                b"AuthMethod=None\0MaxBurstLength=1048576\0X-com.example.Foo=1\0OFMarker=Yes\0DataDigest=CRC32C,None\0",
            )
            .unwrap();
        assert_eq!(
            keys(&replies),
            [
                ("MaxBurstLength", "65536"),
                ("X-com.example.Foo", "NotUnderstood"),
                ("OFMarker", "No"),
                ("DataDigest", "None")
            ]
        );
        assert_eq!(n.params.max_burst_length, 65536);
    }

    #[test]
    fn failures() {
        let mut n = Negotiator::new(Offer::default());
        n.security_keys("i", None, false);
        assert!(matches!(n.respond(b"AuthMethod=CHAP\0"), Err(IscsiError::Negotiation(_))));
        assert!(matches!(n.respond(b"AuthMethod=Reject\0"), Err(IscsiError::Negotiation(_))));
        let mut n = Negotiator::new(Offer::default());
        n.operational_keys(true);
        assert!(matches!(n.respond(b"HeaderDigest=CRC32C\0"), Err(IscsiError::Negotiation(_))));
        assert!(matches!(n.respond(b"MaxBurstLength=lots\0"), Err(IscsiError::Negotiation(_))));
        assert!(matches!(n.respond(b"garbage\0"), Err(IscsiError::Protocol(_))));
        // Rejecting an ordinary key leaves the default.
        let mut n = Negotiator::new(Offer::default());
        n.operational_keys(false);
        n.respond(b"ImmediateData=Reject\0InitialR2T=Irrelevant\0").unwrap();
        assert_eq!((n.params.immediate_data, n.params.initial_r2t), (true, true));
    }

    #[test]
    fn an_answered_key_cannot_be_renegotiated() {
        let mut n = Negotiator::new(Offer::default());
        n.operational_keys(false);
        n.respond(b"MaxBurstLength=65536\0").unwrap();
        let burst = n.params.max_burst_length;
        // A later response, offering the key afresh, does not change it.
        assert!(matches!(n.respond(b"MaxBurstLength=4096\0"), Err(IscsiError::Negotiation(_))));
        assert_eq!(n.params.max_burst_length, burst);
        // Nor does a repeat inside one response, or of a target's own offer.
        let mut n = Negotiator::new(Offer::default());
        n.security_keys("i", Some("t"), false);
        let twice = n.respond(b"ErrorRecoveryLevel=0\0ErrorRecoveryLevel=0\0");
        assert!(matches!(twice, Err(IscsiError::Negotiation(_))));
        let mut n = Negotiator::new(Offer::default());
        n.security_keys("i", Some("t"), false);
        n.respond(b"AuthMethod=None\0InitialR2T=Yes\0").unwrap();
        assert!(matches!(n.respond(b"InitialR2T=No\0"), Err(IscsiError::Negotiation(_))));
        // Declarative keys that may repeat are fine.
        n.respond(b"TargetAddress=a\0TargetAddress=b\0").unwrap();
    }

    #[test]
    fn rejected_keys_keep_to_our_offer() {
        let offer =
            Offer { max_burst_length: 16384, first_burst_length: 4096, immediate_data: false, ..Offer::default() };
        let mut n = Negotiator::new(offer);
        n.operational_keys(false);
        n.respond(b"MaxBurstLength=Reject\0FirstBurstLength=Irrelevant\0ImmediateData=Reject\0").unwrap();
        let p = &n.params;
        assert_eq!((p.max_burst_length, p.first_burst_length, p.immediate_data), (16384, 4096, false));
    }

    #[test]
    fn answers_beyond_our_offer_fail() {
        for reply in [
            &b"ErrorRecoveryLevel=2\0"[..],
            b"MaxBurstLength=262145\0",
            b"FirstBurstLength=65537\0",
            b"MaxOutstandingR2T=2\0",
            b"MaxConnections=4\0",
            b"DefaultTime2Retain=20\0",
            b"DefaultTime2Wait=1\0",
            b"MaxBurstLength=256\0",
            b"MaxRecvDataSegmentLength=100\0",
        ] {
            let mut n = Negotiator::new(Offer::default());
            n.operational_keys(false);
            assert!(matches!(n.respond(reply), Err(IscsiError::Negotiation(_))), "{reply:?}");
        }
        // The same values offered by the target are cut to ours.
        let mut n = Negotiator::new(Offer::default());
        n.security_keys("i", Some("t"), false);
        let replies = n.respond(b"ErrorRecoveryLevel=2\0DefaultTime2Retain=20\0MaxOutstandingR2T=2\0").unwrap();
        assert_eq!(
            keys(&replies),
            [("ErrorRecoveryLevel", "0"), ("DefaultTime2Retain", "0"), ("MaxOutstandingR2T", "1")]
        );
    }
}
