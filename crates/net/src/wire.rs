//! Packet formats: Ethernet II, ARP, IPv4, ICMP echo, UDP and TCP headers,
//! parsed from and written into byte slices, and the Internet checksum.
//!
//! Parsers check lengths and checksums and return `None` for anything
//! malformed, so their callers can drop a packet with one `let ... else`.

use alloc::vec::Vec;
use core::net::Ipv4Addr;

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

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn ip(b: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3])
}

fn mac(b: &[u8], at: usize) -> MacAddress {
    MacAddress(b[at..at + 6].try_into().unwrap())
}

/// The Internet checksum (RFC 1071).
pub mod checksum {
    use core::net::Ipv4Addr;

    /// Adds `data` to a running one's-complement sum, as big-endian 16-bit
    /// words, padding an odd final byte with zero.
    pub fn add(mut sum: u32, data: &[u8]) -> u32 {
        let (words, rest) = data.as_chunks::<2>();
        for w in words {
            sum += u32::from(u16::from_be_bytes(*w));
        }
        if let [last] = rest {
            sum += u32::from(*last) << 8;
        }
        // Fold early so that long inputs cannot overflow.
        (sum & 0xffff) + (sum >> 16)
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

    /// The running sum of the IPv4 pseudo-header that UDP and TCP
    /// checksums cover.
    pub fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, len: usize) -> u32 {
        let sum = add(add(0, &src.octets()), &dst.octets());
        add(sum, &[0, protocol, (len >> 8) as u8, len as u8])
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
        Some((header, &frame[ETH_HEADER_LEN..]))
    }

    /// Writes the header into the first [`ETH_HEADER_LEN`] bytes of `buf`.
    pub fn emit(&self, buf: &mut [u8]) {
        buf[0..6].copy_from_slice(&self.dst.0);
        buf[6..12].copy_from_slice(&self.src.0);
        buf[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
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
        if b.len() < ARP_LEN || b[0..6] != [0, 1, 0x08, 0x00, 6, 4] {
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
        buf[0..6].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4]);
        buf[6..8].copy_from_slice(&self.op.to_be_bytes());
        buf[8..14].copy_from_slice(&self.sender_mac.0);
        buf[14..18].copy_from_slice(&self.sender_ip.octets());
        buf[18..24].copy_from_slice(&self.target_mac.0);
        buf[24..28].copy_from_slice(&self.target_ip.octets());
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

impl Ipv4Header {
    /// Splits a packet into its header and payload, verifying the version,
    /// lengths and header checksum. Options are skipped. Fragments are
    /// rejected, since the stack does not reassemble them.
    pub fn parse(b: &[u8]) -> Option<(Self, &[u8])> {
        if b.len() < IPV4_HEADER_LEN || b[0] >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(b[0] & 0xf) * 4;
        let total_len = usize::from(be16(b, 2));
        if header_len < IPV4_HEADER_LEN || total_len < header_len || total_len > b.len() {
            return None;
        }
        if checksum::of(&b[..header_len]) != 0 {
            return None;
        }
        let more_fragments = b[6] & 0x20 != 0;
        let offset = be16(b, 6) & 0x1fff;
        if more_fragments || offset != 0 {
            return None;
        }
        let header = Self {
            src: ip(b, 12),
            dst: ip(b, 16),
            protocol: b[9],
            ttl: b[8],
            ident: be16(b, 4),
            payload_len: total_len - header_len,
        };
        Some((header, &b[header_len..total_len]))
    }

    /// Writes the header, with DF set and its checksum, into the first
    /// [`IPV4_HEADER_LEN`] bytes of `buf`.
    pub fn emit(&self, buf: &mut [u8]) {
        let total = (IPV4_HEADER_LEN + self.payload_len) as u16;
        buf[0] = 0x45;
        buf[1] = 0;
        buf[2..4].copy_from_slice(&total.to_be_bytes());
        buf[4..6].copy_from_slice(&self.ident.to_be_bytes());
        buf[6..8].copy_from_slice(&[0x40, 0]);
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        buf[10..12].fill(0);
        buf[12..16].copy_from_slice(&self.src.octets());
        buf[16..20].copy_from_slice(&self.dst.octets());
        let sum = checksum::of(&buf[..IPV4_HEADER_LEN]);
        buf[10..12].copy_from_slice(&sum.to_be_bytes());
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
        let header = Self { ty: b[0], code: b[1], ident: be16(b, 4), seq: be16(b, 6) };
        Some((header, &b[ICMP_HEADER_LEN..]))
    }

    /// Builds the message: this header, `data`, and the checksum.
    pub fn emit(&self, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(ICMP_HEADER_LEN + data.len());
        b.extend_from_slice(&[self.ty, self.code, 0, 0]);
        b.extend_from_slice(&self.ident.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(data);
        let sum = checksum::of(&b);
        b[2..4].copy_from_slice(&sum.to_be_bytes());
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
    pub fn parse(b: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<(Self, &[u8])> {
        if b.len() < UDP_HEADER_LEN {
            return None;
        }
        let len = usize::from(be16(b, 4));
        if len < UDP_HEADER_LEN || len > b.len() {
            return None;
        }
        let b = &b[..len];
        if be16(b, 6) != 0 && checksum::finish(checksum::add(checksum::pseudo_header(src, dst, PROTO_UDP, len), b)) != 0
        {
            return None;
        }
        Some((Self { src_port: be16(b, 0), dst_port: be16(b, 2) }, &b[UDP_HEADER_LEN..]))
    }

    /// Builds the datagram from `src` to `dst`: this header, `payload`, and
    /// the checksum.
    pub fn emit(&self, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
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
        b[6..8].copy_from_slice(&sum.to_be_bytes());
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

/// A TCP header. Of the options, only the maximum segment size is kept.
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
}

impl TcpHeader {
    /// Splits a segment carried from `src` to `dst` into its header and
    /// payload, verifying the data offset and checksum.
    pub fn parse(b: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> Option<(Self, &[u8])> {
        if b.len() < TCP_HEADER_LEN {
            return None;
        }
        let offset = usize::from(b[12] >> 4) * 4;
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
            flags: b[13] & 0x3f,
            window: be16(b, 14),
            mss: None,
        };
        let mut opts = &b[TCP_HEADER_LEN..offset];
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
                    if *kind == 2 && len == 4 {
                        header.mss = Some(be16(opts, 2));
                    }
                    opts = &opts[len..];
                }
            }
        }
        Some((header, &b[offset..]))
    }

    /// Builds the segment from `src` to `dst`: this header (with the MSS
    /// option if set), `payload`, and the checksum.
    pub fn emit(&self, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let header_len = TCP_HEADER_LEN + if self.mss.is_some() { 4 } else { 0 };
        let len = header_len + payload.len();
        let mut b = Vec::with_capacity(len);
        b.extend_from_slice(&self.src_port.to_be_bytes());
        b.extend_from_slice(&self.dst_port.to_be_bytes());
        b.extend_from_slice(&self.seq.to_be_bytes());
        b.extend_from_slice(&self.ack.to_be_bytes());
        b.extend_from_slice(&[(header_len as u8 / 4) << 4, self.flags]);
        b.extend_from_slice(&self.window.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        if let Some(mss) = self.mss {
            b.extend_from_slice(&[2, 4]);
            b.extend_from_slice(&mss.to_be_bytes());
        }
        b.extend_from_slice(payload);
        let sum = checksum::finish(checksum::add(checksum::pseudo_header(src, dst, PROTO_TCP, len), &b));
        b[16..18].copy_from_slice(&sum.to_be_bytes());
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
