//! IPv6 packet formats: the IPv6 header with its extension headers, ICMPv6
//! (echo and neighbor discovery, RFC 4443 and RFC 4861), and the address
//! arithmetic that stateless autoconfiguration needs.
//!
//! Like [`wire`](crate::wire), the parsers check lengths and checksums and
//! return `None` for anything malformed. UDP and TCP over IPv6 use the same
//! headers as over IPv4 ([`UdpHeader`](crate::wire::UdpHeader),
//! [`TcpHeader`](crate::wire::TcpHeader)), given IPv6 addresses for the
//! pseudo-header.

use alloc::vec::Vec;
use core::net::Ipv6Addr;

use osmium_hal::net::MacAddress;

use crate::wire::{checksum, put};

/// EtherType of IPv6.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Next-header value of ICMPv6.
pub const PROTO_ICMPV6: u8 = 58;
/// Next-header value of the hop-by-hop options header.
pub const PROTO_HOPOPTS: u8 = 0;
/// Next-header value of the routing header.
pub const PROTO_ROUTING: u8 = 43;
/// Next-header value of the fragment header.
pub const PROTO_FRAGMENT: u8 = 44;
/// Next-header value of the authentication header.
pub const PROTO_AH: u8 = 51;
/// Next-header value meaning there is nothing after this header.
pub const PROTO_NONE: u8 = 59;
/// Next-header value of the destination options header.
pub const PROTO_DSTOPTS: u8 = 60;

/// Length of an IPv6 header.
pub const IPV6_HEADER_LEN: usize = 40;
/// Length of an ICMPv6 header (type, code and checksum).
pub const ICMPV6_HEADER_LEN: usize = 4;
/// The smallest MTU an IPv6 link has (RFC 8200).
pub const IPV6_MIN_MTU: usize = 1280;
/// Extension headers followed in one packet; more is a malformed or hostile
/// packet.
const MAX_EXTENSION_HEADERS: usize = 8;

/// ICMPv6 type: destination unreachable.
pub const ICMPV6_DEST_UNREACHABLE: u8 = 1;
/// ICMPv6 destination-unreachable code: port unreachable.
pub const ICMPV6_PORT_UNREACHABLE: u8 = 4;
/// ICMPv6 type: packet too big.
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;
/// ICMPv6 type: echo request.
pub const ICMPV6_ECHO_REQUEST: u8 = 128;
/// ICMPv6 type: echo reply.
pub const ICMPV6_ECHO_REPLY: u8 = 129;
/// ICMPv6 type: router solicitation.
pub const ICMPV6_ROUTER_SOLICIT: u8 = 133;
/// ICMPv6 type: router advertisement.
pub const ICMPV6_ROUTER_ADVERT: u8 = 134;
/// ICMPv6 type: neighbor solicitation.
pub const ICMPV6_NEIGHBOR_SOLICIT: u8 = 135;
/// ICMPv6 type: neighbor advertisement.
pub const ICMPV6_NEIGHBOR_ADVERT: u8 = 136;

const OPT_SOURCE_LL: u8 = 1;
const OPT_TARGET_LL: u8 = 2;
const OPT_PREFIX_INFO: u8 = 3;
const OPT_MTU: u8 = 5;
const OPT_RDNSS: u8 = 25;

/// Hop-by-hop and destination option: padding of one byte.
const TLV_PAD1: u8 = 0;
/// Hop-by-hop and destination option: padding.
const TLV_PADN: u8 = 1;

/// All nodes on the link, `ff02::1`.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// All routers on the link, `ff02::2`.
pub const ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(*b.get(at..)?.first_chunk()?))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(*b.get(at..)?.first_chunk()?))
}

fn addr(b: &[u8], at: usize) -> Option<Ipv6Addr> {
    Some(Ipv6Addr::from(*b.get(at..)?.first_chunk::<16>()?))
}

fn mac(b: &[u8]) -> Option<MacAddress> {
    Some(MacAddress(*b.first_chunk()?))
}

/// Returns true for `fe80::/10`.
pub fn is_link_local(a: Ipv6Addr) -> bool {
    a.segments().first().is_some_and(|s| s & 0xffc0 == 0xfe80)
}

/// The multicast address a node joins for each of its unicast addresses,
/// `ff02::1:ffXX:XXXX` with the low 24 bits of `a`.
pub fn solicited_node(a: Ipv6Addr) -> Ipv6Addr {
    let [.., a, b, c] = a.octets();
    Ipv6Addr::from([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, a, b, c])
}

/// The Ethernet address IPv6 multicast address `a` maps to: `33:33` and its
/// low 32 bits (RFC 2464).
pub fn multicast_mac(a: Ipv6Addr) -> MacAddress {
    let [.., a, b, c, d] = a.octets();
    MacAddress([0x33, 0x33, a, b, c, d])
}

/// The modified EUI-64 interface identifier of `mac` (RFC 4291 appendix A).
pub fn eui64(mac: MacAddress) -> [u8; 8] {
    let [m0, m1, m2, m3, m4, m5] = mac.0;
    [m0 ^ 2, m1, m2, 0xff, 0xfe, m3, m4, m5]
}

/// The link-local address `mac` autoconfigures: `fe80::` and its EUI-64.
pub fn link_local_from_mac(mac: MacAddress) -> Ipv6Addr {
    with_prefix(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 64, eui64(mac))
}

/// `prefix`'s first `prefix_len` bits followed by `iid`'s low bits.
pub fn with_prefix(prefix: Ipv6Addr, prefix_len: u8, iid: [u8; 8]) -> Ipv6Addr {
    let mask = prefix_mask(prefix_len);
    Ipv6Addr::from((u128::from(prefix) & mask) | (u128::from(u64::from_be_bytes(iid)) & !mask))
}

fn prefix_mask(prefix_len: u8) -> u128 {
    u128::MAX.checked_shl(128 - u32::from(prefix_len.min(128))).unwrap_or(0)
}

/// Returns true if `a` and `b` share their first `prefix_len` bits.
pub fn same_prefix(a: Ipv6Addr, b: Ipv6Addr, prefix_len: u8) -> bool {
    let mask = prefix_mask(prefix_len);
    u128::from(a) & mask == u128::from(b) & mask
}

/// Returns true for an address a packet's source can be: not unspecified,
/// multicast or loopback.
pub fn is_valid_source(a: Ipv6Addr) -> bool {
    !(a.is_unspecified() || a.is_multicast() || a.is_loopback())
}

/// A fragment header: this packet carries one piece of a larger datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Fragment {
    /// Byte offset of the piece in the datagram (a multiple of 8).
    pub offset: usize,
    /// More pieces follow.
    pub more: bool,
    /// The datagram's identification.
    pub ident: u32,
}

impl Ipv6Fragment {
    /// Returns true if this is a whole datagram sent with a fragment header
    /// (an "atomic fragment", RFC 6946).
    pub const fn is_whole(&self) -> bool {
        self.offset == 0 && !self.more
    }
}

/// An IPv6 header, with the extension headers after it already walked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Header {
    /// Source address.
    pub src: Ipv6Addr,
    /// Destination address.
    pub dst: Ipv6Addr,
    /// The upper-layer protocol, after any extension headers.
    pub next_header: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// Length of the upper-layer payload that follows the headers (for a
    /// piece of a fragmented datagram, of the piece).
    pub payload_len: usize,
    /// The fragment header, if the packet had one.
    pub fragment: Option<Ipv6Fragment>,
}

/// Checks the options of a hop-by-hop or destination options header. Returns
/// false if one calls for the packet to be discarded: an unknown option whose
/// type says so (top bits other than `00`), a jumbo payload (not supported)
/// or a length that overruns the header.
fn options_ok(mut opts: &[u8]) -> bool {
    while let [ty, rest @ ..] = opts {
        match *ty {
            TLV_PAD1 => opts = rest,
            ty => {
                let Some((&len, rest)) = rest.split_first() else { return false };
                let Some(rest) = rest.get(usize::from(len)..) else { return false };
                // Unknown options are skipped only when their top bits are 00.
                if ty != TLV_PADN && ty >> 6 != 0 {
                    return false;
                }
                opts = rest;
            }
        }
    }
    true
}

impl Ipv6Header {
    /// Splits a packet into its header and upper-layer payload, walking the
    /// extension headers on the way. Returns `None` if it is malformed, has
    /// a routing header with hops left, a jumbo payload, or an option that
    /// calls for it to be discarded.
    pub fn parse(b: &[u8]) -> Option<(Self, &[u8])> {
        if b.len() < IPV6_HEADER_LEN || *b.first()? >> 4 != 6 {
            return None;
        }
        let total = usize::from(be16(b, 4)?);
        let body = b.get(IPV6_HEADER_LEN..IPV6_HEADER_LEN.checked_add(total)?)?;
        let mut header = Self {
            src: addr(b, 8)?,
            dst: addr(b, 24)?,
            next_header: *b.get(6)?,
            hop_limit: *b.get(7)?,
            payload_len: 0,
            fragment: None,
        };
        let mut rest = body;
        for n in 0..=MAX_EXTENSION_HEADERS {
            match header.next_header {
                // Hop-by-hop options belong first only.
                PROTO_HOPOPTS | PROTO_DSTOPTS | PROTO_ROUTING | PROTO_AH | PROTO_FRAGMENT => {
                    if n == MAX_EXTENSION_HEADERS || (header.next_header == PROTO_HOPOPTS && n != 0) {
                        return None;
                    }
                }
                _ => {
                    header.payload_len = rest.len();
                    return Some((header, rest));
                }
            }
            let (next, len) = match header.next_header {
                PROTO_FRAGMENT => {
                    let field = be16(rest, 2)?;
                    let fragment = Ipv6Fragment {
                        offset: usize::from(field & 0xfff8),
                        more: field & 1 != 0,
                        ident: be32(rest, 4)?,
                    };
                    // A second fragment header makes no sense.
                    if header.fragment.replace(fragment).is_some() {
                        return None;
                    }
                    let inner = *rest.first()?;
                    let after = rest.get(8..)?;
                    // The bytes of a piece are not headers, so the walk stops
                    // here: reassembly (see [`frag6`](crate::frag6)) puts the
                    // pieces together and walks what is left.
                    if !fragment.is_whole() {
                        header.next_header = inner;
                        header.payload_len = after.len();
                        return Some((header, after));
                    }
                    (inner, 8)
                }
                PROTO_AH => (*rest.first()?, (usize::from(*rest.get(1)?) + 2) * 4),
                PROTO_ROUTING => {
                    // A packet with routing headers left to visit is not for
                    // us to forward, and a host does not process them.
                    if *rest.get(3)? != 0 {
                        return None;
                    }
                    (*rest.first()?, (usize::from(*rest.get(1)?) + 1) * 8)
                }
                _ => {
                    let len = (usize::from(*rest.get(1)?) + 1) * 8;
                    if !options_ok(rest.get(2..len)?) {
                        return None;
                    }
                    (*rest.first()?, len)
                }
            };
            rest = rest.get(len..)?;
            header.next_header = next;
        }
        None
    }

    /// Writes the 40-byte header for `self.payload_len` bytes of
    /// `self.next_header` payload, with no extension headers.
    pub fn emit(&self, buf: &mut [u8]) {
        put(buf, 0, &[0x60, 0, 0, 0]);
        put(buf, 4, &(self.payload_len as u16).to_be_bytes());
        put(buf, 6, &[self.next_header, self.hop_limit]);
        put(buf, 8, &self.src.octets());
        put(buf, 24, &self.dst.octets());
    }
}

/// An ICMPv6 message's type and code; the body after the checksum is
/// handled separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Icmpv6Header {
    /// Message type.
    pub ty: u8,
    /// Message code.
    pub code: u8,
}

impl Icmpv6Header {
    /// Splits a message carried from `src` to `dst` into its header and
    /// body (the bytes after the checksum), verifying the checksum.
    pub fn parse(b: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> Option<(Self, &[u8])> {
        if b.len() < ICMPV6_HEADER_LEN {
            return None;
        }
        if checksum::finish(checksum::add(checksum::pseudo_header(src, dst, PROTO_ICMPV6, b.len()), b)) != 0 {
            return None;
        }
        Some((Self { ty: *b.first()?, code: *b.get(1)? }, b.get(ICMPV6_HEADER_LEN..)?))
    }

    /// Builds the message from `src` to `dst`: this header, `body`, and the
    /// checksum.
    pub fn emit(&self, src: Ipv6Addr, dst: Ipv6Addr, body: &[u8]) -> Vec<u8> {
        let len = ICMPV6_HEADER_LEN + body.len();
        let mut b = Vec::with_capacity(len);
        b.extend_from_slice(&[self.ty, self.code, 0, 0]);
        b.extend_from_slice(body);
        let sum = checksum::finish(checksum::add(checksum::pseudo_header(src, dst, PROTO_ICMPV6, len), &b));
        put(&mut b, 2, &sum.to_be_bytes());
        b
    }
}

/// The body of an echo request or reply: identifier, sequence number and
/// data.
pub fn echo_body(ident: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(4 + data.len());
    b.extend_from_slice(&ident.to_be_bytes());
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(data);
    b
}

/// Splits an echo body into identifier, sequence number and data.
pub fn parse_echo(body: &[u8]) -> Option<(u16, u16, &[u8])> {
    Some((be16(body, 0)?, be16(body, 2)?, body.get(4..)?))
}

/// What the options of a neighbor discovery message carry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NdOptions {
    source_ll: Option<MacAddress>,
    target_ll: Option<MacAddress>,
    mtu: Option<u32>,
    prefixes: Vec<PrefixInfo>,
    /// Servers of RDNSS options with a lifetime, and the longest of those.
    rdnss: Vec<Ipv6Addr>,
    rdnss_lifetime: u32,
    /// Servers of RDNSS options with lifetime 0: no longer to be used.
    rdnss_withdrawn: Vec<Ipv6Addr>,
}

/// Walks the options in `b`; `None` if one is malformed (a zero length
/// invalidates the message, RFC 4861 section 7.1).
fn parse_options(mut b: &[u8]) -> Option<NdOptions> {
    let mut o = NdOptions::default();
    while !b.is_empty() {
        let ty = *b.first()?;
        let len = usize::from(*b.get(1)?) * 8;
        if len == 0 {
            return None;
        }
        let opt = b.get(..len)?;
        b = b.get(len..)?;
        match ty {
            OPT_SOURCE_LL if len == 8 => o.source_ll = mac(opt.get(2..)?),
            OPT_TARGET_LL if len == 8 => o.target_ll = mac(opt.get(2..)?),
            OPT_MTU if len == 8 => o.mtu = be32(opt, 4),
            OPT_PREFIX_INFO if len == 32 => {
                if o.prefixes.len() < 8 {
                    o.prefixes.push(PrefixInfo {
                        prefix_len: *opt.get(2)?,
                        on_link: *opt.get(3)? & 0x80 != 0,
                        autonomous: *opt.get(3)? & 0x40 != 0,
                        valid_lifetime: be32(opt, 4)?,
                        preferred_lifetime: be32(opt, 8)?,
                        prefix: addr(opt, 16)?,
                    });
                }
            }
            OPT_RDNSS if len >= 24 && (len - 8) % 16 == 0 => {
                let lifetime = be32(opt, 4)?;
                for chunk in opt.get(8..)?.as_chunks::<16>().0.iter().take(4) {
                    if lifetime == 0 {
                        o.rdnss_withdrawn.push(Ipv6Addr::from(*chunk));
                    } else {
                        o.rdnss.push(Ipv6Addr::from(*chunk));
                        o.rdnss_lifetime = o.rdnss_lifetime.max(lifetime);
                    }
                }
            }
            _ => {}
        }
    }
    Some(o)
}

fn push_ll_option(out: &mut Vec<u8>, ty: u8, mac: MacAddress) {
    out.extend_from_slice(&[ty, 1]);
    out.extend_from_slice(&mac.0);
}

/// A neighbor solicitation: who has `target`?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborSolicit {
    /// The address being resolved or checked.
    pub target: Ipv6Addr,
    /// The sender's link-layer address; absent in duplicate address
    /// detection.
    pub source_ll: Option<MacAddress>,
}

impl NeighborSolicit {
    /// Parses the body of a type 135 message.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let target = addr(body, 4)?;
        let o = parse_options(body.get(20..)?)?;
        Some(Self { target, source_ll: o.source_ll })
    }

    /// The body of the message.
    pub fn emit(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(28);
        b.extend_from_slice(&[0; 4]);
        b.extend_from_slice(&self.target.octets());
        if let Some(m) = self.source_ll {
            push_ll_option(&mut b, OPT_SOURCE_LL, m);
        }
        b
    }
}

/// A neighbor advertisement: `target` is at the given link-layer address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeighborAdvert {
    /// The sender is a router.
    pub router: bool,
    /// Sent in answer to a solicitation.
    pub solicited: bool,
    /// The advertisement overrides a cached link-layer address.
    pub override_: bool,
    /// The address being advertised.
    pub target: Ipv6Addr,
    /// The target's link-layer address.
    pub target_ll: Option<MacAddress>,
}

impl NeighborAdvert {
    /// Parses the body of a type 136 message.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let flags = *body.first()?;
        let target = addr(body, 4)?;
        let o = parse_options(body.get(20..)?)?;
        Some(Self {
            router: flags & 0x80 != 0,
            solicited: flags & 0x40 != 0,
            override_: flags & 0x20 != 0,
            target,
            target_ll: o.target_ll,
        })
    }

    /// The body of the message.
    pub fn emit(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(28);
        let flags = u8::from(self.router) << 7 | u8::from(self.solicited) << 6 | u8::from(self.override_) << 5;
        b.extend_from_slice(&[flags, 0, 0, 0]);
        b.extend_from_slice(&self.target.octets());
        if let Some(m) = self.target_ll {
            push_ll_option(&mut b, OPT_TARGET_LL, m);
        }
        b
    }
}

/// A router solicitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouterSolicit {
    /// The sender's link-layer address.
    pub source_ll: Option<MacAddress>,
}

impl RouterSolicit {
    /// Parses the body of a type 133 message.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let o = parse_options(body.get(4..)?)?;
        Some(Self { source_ll: o.source_ll })
    }

    /// The body of the message.
    pub fn emit(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(12);
        b.extend_from_slice(&[0; 4]);
        if let Some(m) = self.source_ll {
            push_ll_option(&mut b, OPT_SOURCE_LL, m);
        }
        b
    }
}

/// A prefix information option of a router advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixInfo {
    /// Length of the prefix in bits.
    pub prefix_len: u8,
    /// Addresses with the prefix are on the link.
    pub on_link: bool,
    /// Hosts may autoconfigure addresses (SLAAC) from the prefix.
    pub autonomous: bool,
    /// Seconds the prefix is valid; `u32::MAX` is infinite.
    pub valid_lifetime: u32,
    /// Seconds addresses from the prefix are preferred.
    pub preferred_lifetime: u32,
    /// The prefix.
    pub prefix: Ipv6Addr,
}

/// A router advertisement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterAdvert {
    /// Suggested hop limit, 0 for none.
    pub hop_limit: u8,
    /// Addresses are available from DHCPv6.
    pub managed: bool,
    /// Other configuration is available from DHCPv6.
    pub other: bool,
    /// Seconds the sender is a default router; 0 means it is not one.
    pub router_lifetime: u16,
    /// The sender's link-layer address.
    pub source_ll: Option<MacAddress>,
    /// The link's MTU.
    pub mtu: Option<u32>,
    /// The advertised prefixes.
    pub prefixes: Vec<PrefixInfo>,
    /// Recursive DNS servers (RFC 8106).
    pub dns: Vec<Ipv6Addr>,
    /// Seconds the servers in `dns` are valid; `u32::MAX` is infinite.
    pub dns_lifetime: u32,
    /// Servers the router withdrew (lifetime 0).
    pub dns_withdrawn: Vec<Ipv6Addr>,
}

impl RouterAdvert {
    /// Parses the body of a type 134 message.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let flags = *body.get(1)?;
        let o = parse_options(body.get(12..)?)?;
        Some(Self {
            hop_limit: *body.first()?,
            managed: flags & 0x80 != 0,
            other: flags & 0x40 != 0,
            router_lifetime: be16(body, 2)?,
            source_ll: o.source_ll,
            mtu: o.mtu,
            prefixes: o.prefixes,
            dns: o.rdnss,
            dns_lifetime: o.rdnss_lifetime,
            dns_withdrawn: o.rdnss_withdrawn,
        })
    }

    /// The body of the message (the reachable and retransmit times are sent
    /// as unspecified).
    pub fn emit(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(16 + 32 * self.prefixes.len());
        b.push(self.hop_limit);
        b.push(u8::from(self.managed) << 7 | u8::from(self.other) << 6);
        b.extend_from_slice(&self.router_lifetime.to_be_bytes());
        b.extend_from_slice(&[0; 8]);
        if let Some(m) = self.source_ll {
            push_ll_option(&mut b, OPT_SOURCE_LL, m);
        }
        if let Some(mtu) = self.mtu {
            b.extend_from_slice(&[OPT_MTU, 1, 0, 0]);
            b.extend_from_slice(&mtu.to_be_bytes());
        }
        for p in &self.prefixes {
            b.extend_from_slice(&[
                OPT_PREFIX_INFO,
                4,
                p.prefix_len,
                u8::from(p.on_link) << 7 | u8::from(p.autonomous) << 6,
            ]);
            b.extend_from_slice(&p.valid_lifetime.to_be_bytes());
            b.extend_from_slice(&p.preferred_lifetime.to_be_bytes());
            b.extend_from_slice(&[0; 4]);
            b.extend_from_slice(&p.prefix.octets());
        }
        for (servers, lifetime) in [(&self.dns, self.dns_lifetime), (&self.dns_withdrawn, 0)] {
            if !servers.is_empty() {
                b.extend_from_slice(&[OPT_RDNSS, 1 + 2 * servers.len() as u8, 0, 0]);
                b.extend_from_slice(&lifetime.to_be_bytes());
                for d in servers {
                    b.extend_from_slice(&d.octets());
                }
            }
        }
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const DST: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);

    fn packet(next: u8, body: &[u8]) -> Vec<u8> {
        let mut p = alloc::vec![0; IPV6_HEADER_LEN + body.len()];
        Ipv6Header { src: SRC, dst: DST, next_header: next, hop_limit: 64, payload_len: body.len(), fragment: None }
            .emit(&mut p);
        p[IPV6_HEADER_LEN..].copy_from_slice(body);
        p
    }

    #[test]
    fn header_round_trip() {
        let p = packet(17, b"hello");
        let (h, payload) = Ipv6Header::parse(&p).unwrap();
        assert_eq!((h.src, h.dst, h.next_header, h.hop_limit, h.payload_len), (SRC, DST, 17, 64, 5));
        assert_eq!(payload, b"hello");
        assert_eq!(h.fragment, None);
        // Trailing link padding is cut off; a short packet is refused.
        let mut padded = p.clone();
        padded.extend_from_slice(&[0; 10]);
        assert_eq!(Ipv6Header::parse(&padded).unwrap().1, b"hello");
        assert!(Ipv6Header::parse(&p[..p.len() - 1]).is_none());
        assert!(Ipv6Header::parse(&p[..39]).is_none());
        let mut v4 = p;
        v4[0] = 0x40;
        assert!(Ipv6Header::parse(&v4).is_none());
    }

    #[test]
    fn extension_headers_are_skipped() {
        // Hop-by-hop (PadN), destination options (Pad1 + PadN), then UDP.
        let mut body = alloc::vec![PROTO_DSTOPTS, 0, TLV_PADN, 4, 0, 0, 0, 0];
        body.extend_from_slice(&[17, 0, TLV_PAD1, TLV_PADN, 3, 0, 0, 0]);
        body.extend_from_slice(b"data");
        let p = packet(PROTO_HOPOPTS, &body);
        let (h, payload) = Ipv6Header::parse(&p).unwrap();
        assert_eq!((h.next_header, payload), (17, &b"data"[..]));
        assert_eq!(h.payload_len, 4);
    }

    #[test]
    fn fragment_header_is_reported() {
        let mut body = alloc::vec![17, 0, 0, 8 | 1, 0, 0, 0, 7];
        body.extend_from_slice(b"piece");
        let p = packet(PROTO_FRAGMENT, &body);
        let (h, payload) = Ipv6Header::parse(&p).unwrap();
        assert_eq!(h.fragment, Some(Ipv6Fragment { offset: 8, more: true, ident: 7 }));
        assert_eq!((h.next_header, payload), (17, &b"piece"[..]));
        // Offset 0 and no more fragments: an atomic fragment, a whole datagram.
        body[3] = 0;
        let (h, _) = Ipv6Header::parse(&packet(PROTO_FRAGMENT, &body)).unwrap();
        assert!(h.fragment.unwrap().is_whole());
    }

    #[test]
    fn hostile_extension_headers_are_refused() {
        // Header length running past the packet.
        assert!(Ipv6Header::parse(&packet(PROTO_DSTOPTS, &[17, 5, 0, 0, 0, 0, 0, 0])).is_none());
        // An option whose length overruns its header.
        assert!(Ipv6Header::parse(&packet(PROTO_DSTOPTS, &[17, 0, TLV_PADN, 9, 0, 0, 0, 0])).is_none());
        // An unknown option that says to discard (top bits 01, 10 and 11).
        for ty in [0x41, 0x81, 0xc1] {
            assert!(Ipv6Header::parse(&packet(PROTO_DSTOPTS, &[17, 0, ty, 4, 0, 0, 0, 0])).is_none());
        }
        // An unknown option that says to skip (top bits 00).
        assert!(Ipv6Header::parse(&packet(PROTO_DSTOPTS, &[17, 0, 0x1e, 4, 0, 0, 0, 0])).is_some());
        // A routing header with segments left.
        assert!(Ipv6Header::parse(&packet(PROTO_ROUTING, &[17, 0, 2, 1, 0, 0, 0, 0])).is_none());
        assert!(Ipv6Header::parse(&packet(PROTO_ROUTING, &[17, 0, 2, 0, 0, 0, 0, 0])).is_some());
        // Hop-by-hop options anywhere but first.
        let nested = [PROTO_HOPOPTS, 0, TLV_PADN, 4, 0, 0, 0, 0];
        assert!(Ipv6Header::parse(&packet(PROTO_DSTOPTS, &nested)).is_none());
        // A chain of extension headers that never ends.
        let chain: Vec<u8> = (0..20).flat_map(|_| [PROTO_DSTOPTS, 0, TLV_PADN, 4, 0, 0, 0, 0]).collect();
        assert!(Ipv6Header::parse(&packet(PROTO_DSTOPTS, &chain)).is_none());
        // Two fragment headers.
        let twice = [PROTO_FRAGMENT, 0, 0, 0, 0, 0, 0, 1, 17, 0, 0, 0, 0, 0, 0, 1];
        assert!(Ipv6Header::parse(&packet(PROTO_FRAGMENT, &twice)).is_none());
        // Truncated headers.
        assert!(Ipv6Header::parse(&packet(PROTO_FRAGMENT, &[17, 0, 0])).is_none());
        assert!(Ipv6Header::parse(&packet(PROTO_AH, &[17])).is_none());
    }

    #[test]
    fn addresses() {
        let mac = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(link_local_from_mac(mac), "fe80::5054:ff:fe12:3456".parse::<Ipv6Addr>().unwrap());
        let a: Ipv6Addr = "2001:db8::5054:ff:fe12:3456".parse().unwrap();
        assert_eq!(solicited_node(a), "ff02::1:ff12:3456".parse::<Ipv6Addr>().unwrap());
        assert_eq!(multicast_mac(solicited_node(a)), MacAddress([0x33, 0x33, 0xff, 0x12, 0x34, 0x56]));
        let p: Ipv6Addr = "2001:db8:1:2::".parse().unwrap();
        assert_eq!(with_prefix(p, 64, eui64(mac)), "2001:db8:1:2:5054:ff:fe12:3456".parse::<Ipv6Addr>().unwrap());
        assert!(same_prefix(p, "2001:db8:1:2::99".parse().unwrap(), 64));
        assert!(!same_prefix(p, "2001:db8:1:3::".parse().unwrap(), 64));
        assert!(same_prefix(p, "2001:db8:1:3::".parse().unwrap(), 0));
        assert!(is_link_local(SRC) && !is_link_local(a));
    }

    #[test]
    fn icmpv6_checksum() {
        let body = echo_body(0x1234, 9, b"ping");
        let m = Icmpv6Header { ty: ICMPV6_ECHO_REQUEST, code: 0 }.emit(SRC, DST, &body);
        let (h, b) = Icmpv6Header::parse(&m, SRC, DST).unwrap();
        assert_eq!(h.ty, ICMPV6_ECHO_REQUEST);
        assert_eq!(parse_echo(b), Some((0x1234, 9, &b"ping"[..])));
        assert!(Icmpv6Header::parse(&m, DST, Ipv6Addr::LOCALHOST).is_none(), "pseudo-header covered");
        let mut bad = m;
        bad[5] ^= 1;
        assert!(Icmpv6Header::parse(&bad, SRC, DST).is_none());
    }

    #[test]
    fn neighbor_discovery_round_trip() {
        let mac = MacAddress([2, 0, 0, 0, 0, 7]);
        let ns = NeighborSolicit { target: DST, source_ll: Some(mac) };
        assert_eq!(NeighborSolicit::parse(&ns.emit()), Some(ns));
        let dad = NeighborSolicit { target: DST, source_ll: None };
        assert_eq!(NeighborSolicit::parse(&dad.emit()), Some(dad));
        let na = NeighborAdvert { router: false, solicited: true, override_: true, target: DST, target_ll: Some(mac) };
        assert_eq!(NeighborAdvert::parse(&na.emit()), Some(na));
        let rs = RouterSolicit { source_ll: Some(mac) };
        assert_eq!(RouterSolicit::parse(&rs.emit()), Some(rs));
        let ra = RouterAdvert {
            hop_limit: 64,
            managed: false,
            other: true,
            router_lifetime: 1800,
            source_ll: Some(mac),
            mtu: Some(1400),
            prefixes: alloc::vec![PrefixInfo {
                prefix_len: 64,
                on_link: true,
                autonomous: true,
                valid_lifetime: 86400,
                preferred_lifetime: 14400,
                prefix: "2001:db8:1:2::".parse().unwrap(),
            }],
            dns: alloc::vec![SRC],
            dns_lifetime: 600,
            dns_withdrawn: alloc::vec![DST],
        };
        assert_eq!(RouterAdvert::parse(&ra.emit()), Some(ra));
    }

    #[test]
    fn bad_options_are_refused() {
        let mut ns = NeighborSolicit { target: DST, source_ll: Some(MacAddress([2; 6])) }.emit();
        ns[21] = 0; // option length 0
        assert!(NeighborSolicit::parse(&ns).is_none());
        let mut ns = NeighborSolicit { target: DST, source_ll: Some(MacAddress([2; 6])) }.emit();
        ns[21] = 2; // longer than the message
        assert!(NeighborSolicit::parse(&ns).is_none());
        assert!(NeighborSolicit::parse(&[0; 10]).is_none());
        assert!(RouterAdvert::parse(&[0; 8]).is_none());
    }
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use crate::wire::fuzz_tests::rand;

    #[test]
    fn arbitrary_bytes_do_not_panic_the_ipv6_parsers() {
        let mut state = 0x1234_5678_9abc_def1;
        // Valid messages to mutate, so that the options are reached.
        let ra = RouterAdvert {
            hop_limit: 64,
            managed: false,
            other: false,
            router_lifetime: 100,
            source_ll: Some(MacAddress([2; 6])),
            mtu: Some(1500),
            prefixes: alloc::vec![PrefixInfo {
                prefix_len: 64,
                on_link: true,
                autonomous: true,
                valid_lifetime: 10,
                preferred_lifetime: 5,
                prefix: Ipv6Addr::LOCALHOST,
            }],
            dns: alloc::vec![Ipv6Addr::LOCALHOST],
            dns_lifetime: 5,
            dns_withdrawn: alloc::vec![Ipv6Addr::UNSPECIFIED],
        }
        .emit();
        let ns = NeighborSolicit { target: Ipv6Addr::LOCALHOST, source_ll: Some(MacAddress([2; 6])) }.emit();
        for round in 0..20_000 {
            let mut m = if round % 2 == 0 { ra.clone() } else { ns.clone() };
            for _ in 0..1 + rand(&mut state) % 4 {
                let at = (rand(&mut state) % m.len() as u64) as usize;
                m[at] = rand(&mut state) as u8;
            }
            m.truncate((rand(&mut state) % (m.len() as u64 + 1)) as usize);
            let _ = RouterAdvert::parse(&m);
            let _ = NeighborSolicit::parse(&m);
            let _ = NeighborAdvert::parse(&m);
            let _ = RouterSolicit::parse(&m);
            let _ = parse_echo(&m);
            let raw: Vec<u8> = (0..rand(&mut state) % 120).map(|_| rand(&mut state) as u8).collect();
            let _ = Ipv6Header::parse(&raw);
            let mut packet = alloc::vec![0x60, 0, 0, 0, 0, raw.len() as u8, (rand(&mut state) % 64) as u8, 64];
            packet.extend_from_slice(&[0; 32]);
            packet.extend_from_slice(&raw);
            let _ = Ipv6Header::parse(&packet);
            let _ = Icmpv6Header::parse(&raw, Ipv6Addr::LOCALHOST, Ipv6Addr::LOCALHOST);
        }
    }
}
