//! IPv4 header options (RFC 791).
//!
//! A receiver walks the options once, checking every length so that a
//! malformed list cannot send it past the header, and keeps what it
//! understands. Options it does not know are skipped by their length.
//! Packets with a source route (loose or strict) are refused: forwarding is
//! not supported, and a source-routed packet addressed to us is a classic
//! spoofing tool (RFC 7126 recommends dropping them).

use crate::wire::{IPV4_HEADER_LEN, Ipv4Header, checksum};

/// Option type: end of option list.
pub const OPT_END: u8 = 0;
/// Option type: no operation (padding).
pub const OPT_NOP: u8 = 1;
/// Option type: record route.
pub const OPT_RECORD_ROUTE: u8 = 7;
/// Option type: internet timestamp.
pub const OPT_TIMESTAMP: u8 = 68;
/// Option type: loose source route.
pub const OPT_LOOSE_SOURCE_ROUTE: u8 = 131;
/// Option type: strict source route.
pub const OPT_STRICT_SOURCE_ROUTE: u8 = 137;
/// Option type: router alert (RFC 2113).
pub const OPT_ROUTER_ALERT: u8 = 148;

/// Length of an IPv4 header carrying only the router alert option.
pub const HEADER_LEN_ROUTER_ALERT: usize = IPV4_HEADER_LEN + 4;

/// What a header's options said.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    /// A router alert option is present: the packet wants routers to look
    /// at it, as IGMP does.
    pub router_alert: bool,
    /// A record route option is present. It is not filled in.
    pub record_route: bool,
    /// A timestamp option is present. It is not filled in.
    pub timestamp: bool,
}

/// Walks the options area of a header (the bytes after the fixed 20).
/// Returns `None` if an option is truncated or has an impossible length, or
/// if the packet is source routed.
pub fn parse(mut opts: &[u8]) -> Option<Options> {
    let mut found = Options::default();
    while let [kind, rest @ ..] = opts {
        match *kind {
            OPT_END => break,
            OPT_NOP => opts = rest,
            kind => {
                let len = usize::from(*rest.first()?);
                if len < 2 || len > opts.len() {
                    return None;
                }
                match kind {
                    OPT_LOOSE_SOURCE_ROUTE | OPT_STRICT_SOURCE_ROUTE => return None,
                    OPT_ROUTER_ALERT if len != 4 => return None,
                    OPT_ROUTER_ALERT => found.router_alert = true,
                    // Type, length, pointer (which starts at 4) and data.
                    OPT_RECORD_ROUTE | OPT_TIMESTAMP if len < 3 || opts[2] < 4 => return None,
                    OPT_RECORD_ROUTE => found.record_route = true,
                    OPT_TIMESTAMP => found.timestamp = true,
                    _ => {}
                }
                opts = &opts[len..];
            }
        }
    }
    Some(found)
}

/// The options of the IPv4 packet `packet`, whose header length and
/// checksum have been checked (as [`Ipv4Header::parse`] does).
pub fn of_packet(packet: &[u8]) -> Option<Options> {
    let header_len = usize::from(*packet.first()? & 0xf) * 4;
    parse(packet.get(IPV4_HEADER_LEN..header_len)?)
}

/// Writes the header with a router alert option into the first
/// [`HEADER_LEN_ROUTER_ALERT`] bytes of `buf`, as IGMP requires (RFC 2236).
pub fn emit_with_router_alert(header: &Ipv4Header, buf: &mut [u8]) {
    header.emit(buf);
    let total = (HEADER_LEN_ROUTER_ALERT + header.payload_len) as u16;
    buf[0] = 0x46;
    buf[2..4].copy_from_slice(&total.to_be_bytes());
    buf[20..24].copy_from_slice(&[OPT_ROUTER_ALERT, 4, 0, 0]);
    buf[10..12].fill(0);
    let sum = checksum::of(&buf[..HEADER_LEN_ROUTER_ALERT]);
    buf[10..12].copy_from_slice(&sum.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_options() {
        assert_eq!(parse(&[]), Some(Options::default()));
        assert_eq!(parse(&[1, 1, 0, 0xff]), Some(Options::default()), "nothing after the end is read");
        let ra = parse(&[OPT_ROUTER_ALERT, 4, 0, 0]).unwrap();
        assert!(ra.router_alert);
        // Record route with its pointer, then padding.
        let rr = parse(&[OPT_RECORD_ROUTE, 7, 4, 0, 0, 0, 0, 1]).unwrap();
        assert!(rr.record_route && !rr.router_alert);
        assert!(parse(&[OPT_TIMESTAMP, 4, 5, 0]).unwrap().timestamp);
        // Unknown options are skipped by length.
        assert_eq!(parse(&[0x88, 3, 9, OPT_ROUTER_ALERT, 4, 0, 0]).map(|o| o.router_alert), Some(true));
    }

    #[test]
    fn malformed_options_are_rejected() {
        let bad: &[&[u8]] = &[
            &[0x88],                   // no length
            &[0x88, 0],                // length below 2
            &[0x88, 1],                // length below 2
            &[0x88, 5, 0, 0],          // length past the end
            &[OPT_ROUTER_ALERT, 3, 0], // wrong router alert length
            &[OPT_RECORD_ROUTE, 2],    // no pointer
            &[OPT_RECORD_ROUTE, 3, 3], // pointer inside the option header
            &[OPT_LOOSE_SOURCE_ROUTE, 7, 4, 1, 2, 3, 4],
            &[OPT_STRICT_SOURCE_ROUTE, 3, 4],
            &[1, 1, OPT_TIMESTAMP],
        ];
        for opts in bad {
            assert_eq!(parse(opts), None, "{opts:?}");
        }
        // No input panics.
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                let _ = parse(&[a, b, 4, 0]);
                let _ = parse(&[1, a, b]);
            }
        }
    }

    #[test]
    fn router_alert_header_round_trips() {
        use core::net::Ipv4Addr;
        let h = Ipv4Header {
            src: Ipv4Addr::new(10, 0, 0, 1),
            dst: Ipv4Addr::new(224, 0, 0, 2),
            protocol: 2,
            ttl: 1,
            ident: 3,
            payload_len: 8,
        };
        let mut b = [0u8; 32];
        emit_with_router_alert(&h, &mut b);
        b[24..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let (parsed, payload) = Ipv4Header::parse(&b).unwrap();
        assert_eq!((parsed, payload), (h, &[1, 2, 3, 4, 5, 6, 7, 8][..]));
        assert!(of_packet(&b).unwrap().router_alert);
    }
}
