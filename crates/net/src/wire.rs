//! Packet formats: Ethernet II, ARP, IPv4, ICMP echo, UDP and TCP headers
//! (the last two over IPv4 or IPv6; see [`ipv6`](crate::ipv6) for the rest of IPv6),
//! parsed from and written into byte slices, and the Internet checksum.
//!
//! Parsers check lengths and checksums and return `None` for anything
//! malformed, so their callers can drop a packet with one `let ... else`.

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr};

use osmium_hal::net::MacAddress;

/// EtherType of IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType of ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// IP protocol number of ICMP.
pub const PROTO_ICMP: u8 = 1;
/// IP protocol number of TCP.
pub const PROTO_TCP: u8 = 6;
/// IP protocol number of UDP.
pub const PROTO_UDP: u8 = 17;

/// Length of an Ethernet II header.
pub const ETH_HEADER_LEN: usize = 14;
/// Length of an ARP packet for Ethernet and IPv4.
pub const ARP_LEN: usize = 28;
/// Length of an IPv4 header without options.
pub const IPV4_HEADER_LEN: usize = 20;
/// Length of a UDP header.
pub const UDP_HEADER_LEN: usize = 8;
/// Length of a TCP header without options.
pub const TCP_HEADER_LEN: usize = 20;
/// Length of an ICMP echo header.
pub const ICMP_HEADER_LEN: usize = 8;

/// The `N` bytes at `at`, or zeros if `b` is too short. Every caller checks
/// the length first, so the fallback is never used on a well-formed parse.
pub(crate) fn array<const N: usize>(b: &[u8], at: usize) -> [u8; N] {
    b.get(at..).and_then(|s| s.first_chunk::<N>()).copied().unwrap_or([0; N])
}

/// Copies `src` to `buf` at `at`; does nothing if `buf` is too short (the
/// emitters' callers size the buffer by the header's constant length).
pub(crate) fn put(buf: &mut [u8], at: usize, src: &[u8]) {
    if let Some(dst) = at.checked_add(src.len()).and_then(|end| buf.get_mut(at..end)) {
        dst.copy_from_slice(src);
    }
}

pub(crate) fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(array(b, at))
}

pub(crate) fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(array(b, at))
}

pub(crate) fn ip(b: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::from(array::<4>(b, at))
}

pub(crate) fn mac(b: &[u8], at: usize) -> MacAddress {
    MacAddress(array(b, at))
}

/// The byte at `at`, or 0 if `b` is too short.
pub(crate) fn byte(b: &[u8], at: usize) -> u8 {
    b.get(at).copied().unwrap_or(0)
}

/// The Internet checksum (RFC 1071).
pub mod checksum {
    use core::net::IpAddr;

    /// Adds `data` to a running one's-complement sum, as big-endian 16-bit
    /// words, padding an odd final byte with zero.
    pub fn add(sum: u32, data: &[u8]) -> u32 {
        // A 64-bit accumulator cannot overflow for any slice length.
        let mut sum = u64::from(sum);
        let (words, rest) = data.as_chunks::<2>();
        for w in words {
            sum += u64::from(u16::from_be_bytes(*w));
        }
        if let [last] = rest {
            sum += u64::from(*last) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u32
    }

    /// Folds a running sum and complements it: the value to store in a
    /// checksum field. Verifying a packet whose checksum field is included
    /// yields 0.
    pub fn finish(mut sum: u32) -> u16 {
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// The checksum of `data` alone.
    pub fn of(data: &[u8]) -> u16 {
        finish(add(0, data))
    }

    /// The running sum of the pseudo-header that UDP, TCP and ICMPv6
    /// checksums cover: RFC 791's for IPv4 addresses, RFC 8200's for IPv6.
    /// The two addresses are of one family; a mixed pair sums as IPv4.
    pub fn pseudo_header(src: impl Into<IpAddr>, dst: impl Into<IpAddr>, protocol: u8, len: usize) -> u32 {
        match (src.into(), dst.into()) {
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let sum = add(add(0, &src.octets()), &dst.octets());
                add(sum, &[(len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8, 0, 0, 0, protocol])
            }
            (src, dst) => {
                let octets = |a: IpAddr| match a {
                    IpAddr::V4(a) => a.octets(),
                    IpAddr::V6(_) => [0; 4],
                };
                let sum = add(add(0, &octets(src)), &octets(dst));
                add(sum, &[0, protocol, (len >> 8) as u8, len as u8])
            }
        }
    }
}

/// An Ethernet II header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthernetHeader {
    /// Destination MAC address.
    pub dst: MacAddress,
    /// Source MAC address.
    pub src: MacAddress,
    /// The payload's protocol, such as [`ETHERTYPE_IPV4`].
    pub ethertype: u16,
}

impl EthernetHeader {
    /// Splits `frame` into its header and payload.
    pub fn parse(frame: &[u8]) -> Option<(Self, &[u8])> {
        if frame.len() < ETH_HEADER_LEN {
            return None;
        }
        let header = Self { dst: mac(frame, 0), src: mac(frame, 6), ethertype: be16(frame, 12) };
        Some((header, frame.get(ETH_HEADER_LEN..)?))
    }

    /// Writes the header into the first [`ETH_HEADER_LEN`] bytes of `buf`.
    pub fn emit(&self, buf: &mut [u8]) {
        put(buf, 0, &self.dst.0);
        put(buf, 6, &self.src.0);
        put(buf, 12, &self.ethertype.to_be_bytes());
    }
}

/// ARP operation: request.
pub const ARP_REQUEST: u16 = 1;
/// ARP operation: reply.
pub const ARP_REPLY: u16 = 2;

/// An ARP packet for IPv4 over Ethernet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    /// [`ARP_REQUEST`] or [`ARP_REPLY`].
    pub op: u16,
    /// The sender's MAC address.
    pub sender_mac: MacAddress,
    /// The sender's IPv4 address.
    pub sender_ip: Ipv4Addr,
    /// The target's MAC address (zero in a request).
    pub target_mac: MacAddress,
    /// The target's IPv4 address.
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    /// Parses an ARP packet, rejecting other hardware and protocol types.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < ARP_LEN || b.get(0..6) != Some(&[0, 1, 0x08, 0x00, 6, 4]) {
            return None;
        }
        Some(Self {
            op: be16(b, 6),
            sender_mac: mac(b, 8),
            sender_ip: ip(b, 14),
            target_mac: mac(b, 18),
            target_ip: ip(b, 24),
        })
    }

    /// Writes the packet into the first [`ARP_LEN`] bytes of `buf`.
    pub fn emit(&self, buf: &mut [u8]) {
        put(buf, 0, &[0, 1, 0x08, 0x00, 6, 4]);
        put(buf, 6, &self.op.to_be_bytes());
        put(buf, 8, &self.sender_mac.0);
        put(buf, 14, &self.sender_ip.octets());
        put(buf, 18, &self.target_mac.0);
        put(buf, 24, &self.target_ip.octets());
    }
}

/// An IPv4 header, without options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Header {
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// The payload's protocol, such as [`PROTO_TCP`].
    pub protocol: u8,
    /// Time to live.
    pub ttl: u8,
    /// Identification field.
    pub ident: u16,
    /// Length of the payload in bytes.
    pub payload_len: usize,
}

/// Where a packet's payload sits in the datagram it was fragmented from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Fragment {
    /// More fragments follow this one.
    pub more: bool,
    /// Offset of the payload in the datagram, in bytes (a multiple of 8).
    pub offset: usize,
}

impl Fragment {
    /// Returns true if the packet is a whole datagram.
    pub const fn is_whole(&self) -> bool {
        !self.more && self.offset == 0
    }
}

impl Ipv4Header {
    /// Splits a packet into its header and payload, verifying the version,
    /// lengths, header checksum and options (see [`ipopt`](crate::ipopt)); a
    /// packet with malformed or source-route options is rejected. Fragments are
    /// rejected; [`parse_fragment`](Self::parse_fragment) accepts them.
    pub fn parse(b: &[u8]) -> Option<(Self, &[u8])> {
        let (header, fragment, payload) = Self::parse_fragment(b)?;
        fragment.is_whole().then_some((header, payload))
    }

    /// Like [`parse`](Self::parse), but also returns where the payload sits
    /// in its datagram, for packets that are fragments.
    pub fn parse_fragment(b: &[u8]) -> Option<(Self, Fragment, &[u8])> {
        let &first = b.first()?;
        if b.len() < IPV4_HEADER_LEN || first >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(first & 0xf) * 4;
        let total_len = usize::from(be16(b, 2));
        if header_len < IPV4_HEADER_LEN || total_len < header_len || total_len > b.len() {
            return None;
        }
        if checksum::of(b.get(..header_len)?) != 0 || crate::ipopt::parse(b.get(IPV4_HEADER_LEN..header_len)?).is_none()
        {
            return None;
        }
        let fragment = Fragment { more: byte(b, 6) & 0x20 != 0, offset: usize::from(be16(b, 6) & 0x1fff) * 8 };
        let header = Self {
            src: ip(b, 12),
            dst: ip(b, 16),
            protocol: byte(b, 9),
            ttl: byte(b, 8),
            ident: be16(b, 4),
            payload_len: total_len - header_len,
        };
        Some((header, fragment, b.get(header_len..total_len)?))
    }

    /// Writes the header, with DF set and its checksum, into the first
    /// [`IPV4_HEADER_LEN`] bytes of `buf`.
    pub fn emit(&self, buf: &mut [u8]) {
        self.emit_inner(buf, 0x4000);
    }

    /// Writes the header of a fragment: DF clear, and the fragment fields of
    /// `fragment` (whose offset must be a multiple of 8).
    pub fn emit_fragment(&self, buf: &mut [u8], fragment: Fragment) {
        let flags = u16::from(fragment.more) << 13 | (fragment.offset / 8) as u16 & 0x1fff;
        self.emit_inner(buf, flags);
    }

    fn emit_inner(&self, buf: &mut [u8], flags_offset: u16) {
        let total = (IPV4_HEADER_LEN + self.payload_len) as u16;
        put(buf, 0, &[0x45, 0]);
        put(buf, 2, &total.to_be_bytes());
        put(buf, 4, &self.ident.to_be_bytes());
        put(buf, 6, &flags_offset.to_be_bytes());
        put(buf, 8, &[self.ttl, self.protocol, 0, 0]);
        put(buf, 12, &self.src.octets());
        put(buf, 16, &self.dst.octets());
        let sum = checksum::of(buf.get(..IPV4_HEADER_LEN).unwrap_or(&[]));
        put(buf, 10, &sum.to_be_bytes());
    }
}

/// ICMP type: echo reply.
pub const ICMP_ECHO_REPLY: u8 = 0;
/// ICMP type: destination unreachable.
pub const ICMP_DEST_UNREACHABLE: u8 = 3;
/// ICMP type: echo request.
pub const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP destination-unreachable code: port unreachable.
pub const ICMP_PORT_UNREACHABLE: u8 = 3;

/// An ICMP message header: type, code and the four bytes after the
/// checksum (identifier and sequence number for echo messages).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IcmpHeader {
    /// Message type, such as [`ICMP_ECHO_REQUEST`].
    pub ty: u8,
    /// Message code.
    pub code: u8,
    /// Echo identifier.
    pub ident: u16,
    /// Echo sequence number.
    pub seq: u16,
}

impl IcmpHeader {
    /// Splits an ICMP message into its header and data, verifying the
    /// checksum.
    pub fn parse(b: &[u8]) -> Option<(Self, &[u8])> {
        if b.len() < ICMP_HEADER_LEN || checksum::of(b) != 0 {
            return None;
        }
        let header = Self { ty: byte(b, 0), code: byte(b, 1), ident: be16(b, 4), seq: be16(b, 6) };
        Some((header, b.get(ICMP_HEADER_LEN..)?))
    }

    /// Builds the message: this header, `data`, and the checksum.
    pub fn emit(&self, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(ICMP_HEADER_LEN + data.len());
        b.extend_from_slice(&[self.ty, self.code, 0, 0]);
        b.extend_from_slice(&self.ident.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(data);
        let sum = checksum::of(&b);
        put(&mut b, 2, &sum.to_be_bytes());
        b
    }
}

/// A UDP header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpHeader {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
}

impl UdpHeader {
    /// Splits a datagram carried from `src` to `dst` into its header and
    /// payload, verifying the length and, unless it is zero, the checksum.
    pub fn parse(b: &[u8], src: impl Into<IpAddr>, dst: impl Into<IpAddr>) -> Option<(Self, &[u8])> {
        let (src, dst) = (src.into(), dst.into());
        if b.len() < UDP_HEADER_LEN {
            return None;
        }
        let len = usize::from(be16(b, 4));
        if len < UDP_HEADER_LEN || len > b.len() {
            return None;
        }
        let b = b.get(..len)?;
        // Over IPv4 a zero checksum means none was computed; IPv6 has no such
        // escape (RFC 8200 section 8.1).
        let unchecked = be16(b, 6) == 0 && src.is_ipv4();
        if !unchecked && checksum::finish(checksum::add(checksum::pseudo_header(src, dst, PROTO_UDP, len), b)) != 0 {
            return None;
        }
        Some((Self { src_port: be16(b, 0), dst_port: be16(b, 2) }, b.get(UDP_HEADER_LEN..)?))
    }

    /// Builds the datagram from `src` to `dst`: this header, `payload`, and
    /// the checksum.
    pub fn emit(&self, src: impl Into<IpAddr>, dst: impl Into<IpAddr>, payload: &[u8]) -> Vec<u8> {
        let (src, dst) = (src.into(), dst.into());
        let len = UDP_HEADER_LEN + payload.len();
        let mut b = Vec::with_capacity(len);
        b.extend_from_slice(&self.src_port.to_be_bytes());
        b.extend_from_slice(&self.dst_port.to_be_bytes());
        b.extend_from_slice(&(len as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(payload);
        // A computed 0 is sent as all ones; 0 means "no checksum".
        let sum = match checksum::finish(checksum::add(checksum::pseudo_header(src, dst, PROTO_UDP, len), &b)) {
            0 => 0xffff,
            s => s,
        };
        put(&mut b, 6, &sum.to_be_bytes());
        b
    }
}

/// TCP flag: FIN.
pub const TCP_FIN: u8 = 0x01;
/// TCP flag: SYN.
pub const TCP_SYN: u8 = 0x02;
/// TCP flag: RST.
pub const TCP_RST: u8 = 0x04;
/// TCP flag: PSH.
pub const TCP_PSH: u8 = 0x08;
/// TCP flag: ACK.
pub const TCP_ACK: u8 = 0x10;

/// A TCP header. Of the options, the maximum segment size, window scale,
/// SACK and timestamps are kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TcpHeader {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgment number (meaningful with [`TCP_ACK`]).
    pub ack: u32,
    /// Flags: [`TCP_FIN`], [`TCP_SYN`], [`TCP_RST`], [`TCP_PSH`], [`TCP_ACK`].
    pub flags: u8,
    /// Receive window.
    pub window: u16,
    /// The maximum segment size option.
    pub mss: Option<u16>,
    /// The window scale option's shift count (RFC 7323), in SYN segments.
    pub wscale: Option<u8>,
    /// The SACK-permitted option (RFC 2018), in SYN segments.
    pub sack_permitted: bool,
    /// The SACK option's blocks, as `(left edge, right edge)`; only the first
    /// `sack_len` are meaningful.
    pub sack: [(u32, u32); MAX_SACK_BLOCKS],
    /// Number of blocks in `sack`.
    pub sack_len: u8,
    /// The timestamps option (RFC 7323) as `(TSval, TSecr)`.
    pub timestamps: Option<(u32, u32)>,
}

/// The most SACK blocks a segment carries: a TCP header has room for four.
pub const MAX_SACK_BLOCKS: usize = 4;

impl TcpHeader {
    /// Splits a segment carried from `src` to `dst` into its header and
    /// payload, verifying the data offset and checksum.
    pub fn parse(b: &[u8], src: impl Into<IpAddr>, dst: impl Into<IpAddr>) -> Option<(Self, &[u8])> {
        if b.len() < TCP_HEADER_LEN {
            return None;
        }
        let offset = usize::from(byte(b, 12) >> 4) * 4;
        if offset < TCP_HEADER_LEN || offset > b.len() {
            return None;
        }
        if checksum::finish(checksum::add(checksum::pseudo_header(src, dst, PROTO_TCP, b.len()), b)) != 0 {
            return None;
        }
        let mut header = Self {
            src_port: be16(b, 0),
            dst_port: be16(b, 2),
            seq: be32(b, 4),
            ack: be32(b, 8),
            flags: byte(b, 13) & 0x3f,
            window: be16(b, 14),
            ..Self::default()
        };
        let mut opts = b.get(TCP_HEADER_LEN..offset)?;
        while let [kind, rest @ ..] = opts {
            match kind {
                0 => break,
                1 => opts = rest,
                _ => {
                    let Some(&len) = rest.first() else { break };
                    let len = usize::from(len);
                    if len < 2 || len > opts.len() {
                        break;
                    }
                    match (*kind, len) {
                        (2, 4) => header.mss = Some(be16(opts, 2)),
                        (3, 3) => header.wscale = Some(byte(opts, 2)),
                        (4, 2) => header.sack_permitted = true,
                        (8, 10) => header.timestamps = Some((be32(opts, 2), be32(opts, 6))),
                        (5, _) if len >= 10 && (len - 2) % 8 == 0 => {
                            for block in opts.get(2..len).unwrap_or(&[]).as_chunks::<8>().0 {
                                let Some(slot) = header.sack.get_mut(usize::from(header.sack_len)) else { break };
                                *slot = (be32(block, 0), be32(block, 4));
                                header.sack_len += 1;
                            }
                        }
                        _ => {}
                    }
                    let Some(next) = opts.get(len..) else { break };
                    opts = next;
                }
            }
        }
        Some((header, b.get(offset..)?))
    }

    /// Builds the segment from `src` to `dst`: this header (with its
    /// options), `payload`, and the checksum.
    pub fn emit(&self, src: impl Into<IpAddr>, dst: impl Into<IpAddr>, payload: &[u8]) -> Vec<u8> {
        // A TCP header carries at most 40 bytes of options.
        let mut opts = Vec::with_capacity(40);
        if let Some(mss) = self.mss {
            opts.extend_from_slice(&[2, 4]);
            opts.extend_from_slice(&mss.to_be_bytes());
        }
        if let Some((val, echo)) = self.timestamps {
            opts.extend_from_slice(&[1, 1, 8, 10]);
            opts.extend_from_slice(&val.to_be_bytes());
            opts.extend_from_slice(&echo.to_be_bytes());
        }
        if self.sack_permitted {
            opts.extend_from_slice(&[4, 2]);
        }
        if let Some(shift) = self.wscale {
            opts.extend_from_slice(&[1, 3, 3, shift]);
        }
        // The 40 bytes of options hold four SACK blocks, or three beside
        // timestamps.
        let room = if self.timestamps.is_some() { MAX_SACK_BLOCKS - 1 } else { MAX_SACK_BLOCKS };
        let blocks = self.sack.get(..usize::from(self.sack_len).min(room)).unwrap_or(&[]);
        if !blocks.is_empty() {
            opts.extend_from_slice(&[1, 1, 5, 2 + 8 * blocks.len() as u8]);
            for (left, right) in blocks {
                opts.extend_from_slice(&left.to_be_bytes());
                opts.extend_from_slice(&right.to_be_bytes());
            }
        }
        while opts.len() % 4 != 0 {
            opts.push(1);
        }
        let header_len = TCP_HEADER_LEN + opts.len();
        let len = header_len + payload.len();
        let mut b = Vec::with_capacity(len);
        b.extend_from_slice(&self.src_port.to_be_bytes());
        b.extend_from_slice(&self.dst_port.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ack.to_be_bytes());
        b.extend_from_slice(&[(header_len as u8 / 4) << 4, self.flags]);
        b.extend_from_slice(&self.window.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend_from_slice(&opts);
        b.extend_from_slice(payload);
        let sum = checksum::finish(checksum::add(checksum::pseudo_header(src, dst, PROTO_TCP, len), &b));
        put(&mut b, 16, &sum.to_be_bytes());
        b
    }

    /// Returns true if every flag in `flags` is set.
    pub const fn has(&self, flags: u8) -> bool {
        self.flags & flags == flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum::finish(checksum::add(0, &data)), !0xddf2);
        assert_eq!(checksum::of(&[0xab]), !0xab00, "an odd byte is padded on the right");
    }

    #[test]
    fn ipv4_round_trip() {
        let h = Ipv4Header {
            src: Ipv4Addr::new(10, 0, 2, 15),
            dst: Ipv4Addr::new(10, 0, 2, 2),
            protocol: PROTO_UDP,
            ttl: 64,
            ident: 7,
            payload_len: 3,
        };
        let mut b = [0u8; 23];
        h.emit(&mut b);
        b[20..].copy_from_slice(b"abc");
        assert_eq!(Ipv4Header::parse(&b), Some((h, &b"abc"[..])));
        b[8] = 63;
        assert_eq!(Ipv4Header::parse(&b), None, "a bad checksum is rejected");
    }

    #[test]
    fn ipv4_rejects_fragments() {
        let h = Ipv4Header {
            src: Ipv4Addr::LOCALHOST,
            dst: Ipv4Addr::LOCALHOST,
            protocol: 0,
            ttl: 1,
            ident: 0,
            payload_len: 0,
        };
        let mut b = [0u8; 20];
        h.emit(&mut b);
        b[6] = 0x20; // MF
        b[10..12].fill(0);
        let sum = checksum::of(&b);
        b[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(Ipv4Header::parse(&b), None);
    }

    #[test]
    fn ipv4_fragment_fields() {
        let h = Ipv4Header {
            src: Ipv4Addr::LOCALHOST,
            dst: Ipv4Addr::LOCALHOST,
            protocol: 17,
            ttl: 1,
            ident: 9,
            payload_len: 8,
        };
        let mut b = [0u8; 28];
        let frag = Fragment { more: true, offset: 1480 };
        h.emit_fragment(&mut b, frag);
        assert_eq!(Ipv4Header::parse(&b), None);
        assert_eq!(Ipv4Header::parse_fragment(&b), Some((h, frag, &[0u8; 8][..])));
        h.emit(&mut b);
        assert_eq!(Ipv4Header::parse_fragment(&b).unwrap().1, Fragment::default());
    }

    #[test]
    fn tcp_options_round_trip() {
        let (src, dst) = (Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8));
        let syn = TcpHeader {
            flags: TCP_SYN,
            mss: Some(1460),
            wscale: Some(7),
            sack_permitted: true,
            timestamps: Some((0xdead_beef, 0)),
            ..Default::default()
        };
        let b = syn.emit(src, dst, &[]);
        assert_eq!(TcpHeader::parse(&b, src, dst), Some((syn, &[][..])));
        // Beside timestamps a segment carries three SACK blocks, not four.
        let mut ack = TcpHeader { flags: TCP_ACK, sack_len: 4, timestamps: Some((1, 2)), ..Default::default() };
        ack.sack = [(10, 20), (30, 40), (50, 60), (70, 80)];
        let b = ack.emit(src, dst, &[]);
        let (parsed, _) = TcpHeader::parse(&b, src, dst).unwrap();
        assert_eq!((parsed.sack_len, parsed.timestamps), (3, Some((1, 2))));
        assert_eq!(b.len(), 60, "12 timestamp bytes and 3 blocks fill the 40 option bytes");
        let mut ack = TcpHeader { flags: TCP_ACK, sack_len: 3, ..Default::default() };
        ack.sack[..3].copy_from_slice(&[(10, 20), (30, 40), (50, 60)]);
        let b = ack.emit(src, dst, b"x");
        assert_eq!(TcpHeader::parse(&b, src, dst), Some((ack, &b"x"[..])));
    }

    #[test]
    fn tcp_round_trip_with_mss() {
        let (src, dst) = (Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8));
        let h = TcpHeader {
            src_port: 1,
            dst_port: 2,
            seq: 3,
            ack: 4,
            flags: TCP_SYN | TCP_ACK,
            window: 5,
            mss: Some(1460),
            ..Default::default()
        };
        let b = h.emit(src, dst, b"hi");
        assert_eq!(TcpHeader::parse(&b, src, dst), Some((h, &b"hi"[..])));
        assert_eq!(
            TcpHeader::parse(&b, src, Ipv4Addr::new(5, 6, 7, 9)),
            None,
            "the pseudo-header covers the addresses"
        );
    }

    #[test]
    fn udp_round_trip() {
        let (src, dst) = (Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8));
        let h = UdpHeader { src_port: 68, dst_port: 67 };
        let mut b = h.emit(src, dst, b"payload");
        assert_eq!(UdpHeader::parse(&b, src, dst), Some((h, &b"payload"[..])));
        b[6..8].fill(0);
        b[8] ^= 1;
        assert!(UdpHeader::parse(&b, src, dst).is_some(), "a zero checksum is not checked");
    }

    #[test]
    fn every_truncation_of_a_packet_is_handled() {
        let (src, dst) = (Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8));
        let tcp = TcpHeader { flags: TCP_SYN, mss: Some(1460), sack_permitted: true, ..Default::default() }
            .emit(src, dst, b"x");
        let udp = UdpHeader { src_port: 1, dst_port: 2 }.emit(src, dst, b"payload");
        let icmp = IcmpHeader { ty: ICMP_ECHO_REQUEST, code: 0, ident: 1, seq: 2 }.emit(b"abc");
        let mut ip = [0u8; 28];
        Ipv4Header { src, dst, protocol: PROTO_UDP, ttl: 1, ident: 0, payload_len: 8 }.emit(&mut ip);
        for n in 0..tcp.len() {
            assert_eq!(TcpHeader::parse(&tcp[..n], src, dst), None);
        }
        for n in 0..udp.len() {
            assert_eq!(UdpHeader::parse(&udp[..n], src, dst), None);
        }
        for n in 0..icmp.len() {
            assert_eq!(IcmpHeader::parse(&icmp[..n]), None);
        }
        for n in 0..ip.len() {
            assert_eq!(Ipv4Header::parse_fragment(&ip[..n]), None);
        }
        for n in 0..ARP_LEN {
            assert_eq!(
                ArpPacket::parse(
                    &[0, 1, 8, 0, 6, 4, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][..n]
                ),
                None
            );
        }
        for n in 0..ETH_HEADER_LEN {
            assert_eq!(EthernetHeader::parse(&[0; ETH_HEADER_LEN][..n]), None);
        }
    }

    #[test]
    fn emitting_into_a_short_buffer_does_not_panic() {
        let h = Ipv4Header {
            src: Ipv4Addr::LOCALHOST,
            dst: Ipv4Addr::LOCALHOST,
            protocol: 0,
            ttl: 1,
            ident: 0,
            payload_len: 0,
        };
        for n in 0..IPV4_HEADER_LEN {
            h.emit(&mut alloc::vec![0; n]);
            EthernetHeader { dst: MacAddress::default(), src: MacAddress::default(), ethertype: 0 }
                .emit(&mut alloc::vec![0; n]);
        }
    }

    #[test]
    fn the_checksum_of_a_long_input_does_not_overflow() {
        let data = alloc::vec![0xffu8; 1 << 20];
        assert_eq!(checksum::of(&data), 0);
    }

    #[test]
    fn arp_round_trip() {
        let p = ArpPacket {
            op: ARP_REQUEST,
            sender_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            sender_ip: Ipv4Addr::new(10, 0, 0, 1),
            target_mac: MacAddress::default(),
            target_ip: Ipv4Addr::new(10, 0, 0, 2),
        };
        let mut b = [0u8; ARP_LEN];
        p.emit(&mut b);
        assert_eq!(ArpPacket::parse(&b), Some(p));
    }
}

#[cfg(test)]
pub(crate) mod fuzz_tests {
    use super::*;

    /// A xorshift generator, so that the inputs are the same on every run.
    pub(crate) fn rand(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn arbitrary_tcp_segments_do_not_panic() {
        let (src, dst) = (core::net::Ipv4Addr::new(10, 0, 0, 1), core::net::Ipv4Addr::new(10, 0, 0, 2));
        let mut state = 0x9e37_79b9_7f4a_7c15;
        let mut parsed = 0;
        for _ in 0..20_000 {
            let len = 20 + (rand(&mut state) % 64) as usize;
            let mut b: Vec<u8> = (0..len).map(|_| rand(&mut state) as u8).collect();
            // A plausible data offset, and a valid checksum, so that the
            // options are reached.
            b[12] = ((5 + rand(&mut state) % 11) as u8) << 4;
            b[16] = 0;
            b[17] = 0;
            let sum = checksum::finish(checksum::add(checksum::pseudo_header(src, dst, PROTO_TCP, b.len()), &b));
            b[16..18].copy_from_slice(&sum.to_be_bytes());
            if TcpHeader::parse(&b, src, dst).is_some() {
                parsed += 1;
            }
            // And with a checksum that does not fit.
            b[17] ^= 1;
            let _ = TcpHeader::parse(&b, src, dst);
        }
        assert!(parsed > 5_000, "the generator reaches the option parser ({parsed})");
    }
}
