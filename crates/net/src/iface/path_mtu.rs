// SPDX-License-Identifier: GPL-2.0-only
//! Path MTU discovery: learning from ICMP "fragmentation needed" and ICMPv6
//! "packet too big", and telling the connections it affects.
//!
//! A report is believed only if the packet it quotes is one we could have
//! sent just now: a TCP segment whose sequence number is in flight, an echo
//! request with a socket's identifier, or a UDP datagram whose whole header
//! (ports, length and checksum, which depends on the payload) matches one of
//! the [`SENT_UDP`] most recently sent to that destination. Knowing a bound
//! UDP port is not enough to make the interface shrink its packets.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::Interface;
use crate::Instant;
use crate::ipv6::{IPV6_HEADER_LEN, PROTO_ICMPV6};
use crate::pmtu::plateau_below;
use crate::socket::{Packet, Socket, SocketSet};
use crate::wire::{PROTO_ICMP, PROTO_TCP, PROTO_UDP, be16, be32, ip};

/// The ICMP and ICMPv6 echo request types, whose quoted identifier names the
/// socket that sent them.
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;

/// UDP datagrams remembered for checking the ICMP errors that quote them.
pub(super) const SENT_UDP: usize = 32;

/// A UDP datagram sent recently: its destination and its 8-byte header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct SentUdp {
    dst: IpAddr,
    header: [u8; 8],
}

impl Interface {
    /// Remembers the header of `p` if it is a UDP datagram.
    pub(super) fn note_sent(&mut self, p: &Packet) {
        let Some(&[a, b, c, d, e, f, g, h]) = p.payload.get(..8) else { return };
        if p.protocol != PROTO_UDP {
            return;
        }
        let sent = SentUdp { dst: p.dst, header: [a, b, c, d, e, f, g, h] };
        self.sent_udp.retain(|s| *s != sent);
        if self.sent_udp.len() >= SENT_UDP {
            self.sent_udp.pop_front();
        }
        self.sent_udp.push_back(sent);
    }

    /// The largest IP packet sent to `dst` now: the link's MTU, or less if a
    /// router has reported a smaller path MTU (see [`pmtu`](crate::pmtu)).
    pub fn path_mtu(&self, dst: IpAddr, now: Instant) -> usize {
        self.pmtu.path_mtu(dst, self.link_mtu_for(dst), now)
    }

    /// Forgets the path MTU learned for `dst`, to try the full MTU again.
    pub fn forget_path_mtu(&mut self, dst: IpAddr) {
        self.pmtu.remove(dst);
    }

    fn link_mtu_for(&self, dst: IpAddr) -> usize {
        if dst.is_ipv6() { self.v6.mtu(self.mtu) } else { self.mtu }
    }

    /// An ICMP "fragmentation needed" message (RFC 1191) with next-hop MTU
    /// `next_hop_mtu` (0 from an old router) quoting `quote`, which starts
    /// with the offending packet's IP header.
    pub(super) fn process_frag_needed(
        &mut self,
        now: Instant,
        next_hop_mtu: usize,
        quote: &[u8],
        sockets: &mut SocketSet,
    ) {
        let Some(config) = self.config else { return };
        let Some(&first) = quote.first() else { return };
        let header_len = usize::from(first & 0xf) * 4;
        if first >> 4 != 4 || header_len < 20 || quote.len() < header_len + 8 {
            return;
        }
        let (src, dst): (Ipv4Addr, Ipv4Addr) = (ip(quote, 12), ip(quote, 16));
        // Only our own packets to a unicast destination can be the subject.
        if src != config.address
            || dst == src
            || dst.is_unspecified()
            || dst.is_multicast()
            || dst.is_broadcast()
            || dst.is_loopback()
            || dst == config.broadcast()
        {
            return;
        }
        let total = usize::from(be16(quote, 2));
        let reported = if next_hop_mtu == 0 { plateau_below(total) } else { next_hop_mtu };
        // The packet must have been bigger than the MTU it is said to exceed.
        if total <= reported {
            return;
        }
        let Some(transport) = quote.get(header_len..) else { return };
        if self.quoted_flow(sockets, quote.get(9).copied().unwrap_or(0), src.into(), dst.into(), transport) {
            self.apply_path_mtu(now, dst.into(), reported, sockets);
        }
    }

    /// An ICMPv6 "packet too big" message (RFC 8201) whose body is the MTU
    /// and then as much of the offending packet as fits.
    pub(super) fn process_packet_too_big(&mut self, now: Instant, body: &[u8], sockets: &mut SocketSet) {
        let (Some(&[a, b, c, d]), Some(quote)) = (body.get(..4), body.get(4..)) else { return };
        let reported = usize::try_from(u32::from_be_bytes([a, b, c, d])).unwrap_or(usize::MAX);
        if quote.len() < IPV6_HEADER_LEN + 8 || quote.first().is_none_or(|b| b >> 4 != 6) {
            return;
        }
        let addr = |at: usize| -> Ipv6Addr {
            let mut a = [0; 16];
            a.copy_from_slice(quote.get(at..at + 16).unwrap_or(&[0; 16]));
            Ipv6Addr::from(a)
        };
        let (src, dst) = (addr(8), addr(24));
        if !self.v6.is_ours(src)
            || self.v6.is_ours(dst)
            || dst.is_multicast()
            || dst.is_unspecified()
            || dst.is_loopback()
        {
            return;
        }
        let total = IPV6_HEADER_LEN + usize::from(be16(quote, 4));
        if total <= reported {
            return;
        }
        // Extension headers would hide the transport header; a packet with
        // them is not taken as proof.
        let proto = quote.get(6).copied().unwrap_or(0);
        let Some(transport) = quote.get(IPV6_HEADER_LEN..) else { return };
        if self.quoted_flow(sockets, proto, src.into(), dst.into(), transport) {
            self.apply_path_mtu(now, dst.into(), reported, sockets);
        }
    }

    /// Returns true if the packet an ICMP error quotes (`transport` is what
    /// follows its IP header, at least eight bytes) is one a socket of ours
    /// could have sent just now: for TCP its sequence number is in flight on
    /// that connection, for UDP its header is that of a datagram recently
    /// sent to `dst`, and for an echo request the identifier is a socket's.
    fn quoted_flow(&self, sockets: &SocketSet, proto: u8, src: IpAddr, dst: IpAddr, transport: &[u8]) -> bool {
        match proto {
            PROTO_TCP => {
                let local = SocketAddr::new(src, be16(transport, 0));
                let remote = SocketAddr::new(dst, be16(transport, 2));
                let seq = be32(transport, 4);
                sockets.iter().any(|(_, s)| matches!(s, Socket::Tcp(t) if t.has_in_flight(local, remote, seq)))
            }
            PROTO_UDP => {
                let local = SocketAddr::new(src, be16(transport, 0));
                let header = transport.get(..8);
                sockets.iter().any(|(_, s)| matches!(s, Socket::Udp(u) if u.accepts(local)))
                    && self.sent_udp.iter().any(|s| s.dst == dst && Some(&s.header[..]) == header)
            }
            PROTO_ICMP | PROTO_ICMPV6 => {
                let echo = if proto == PROTO_ICMP { ICMP_ECHO_REQUEST } else { ICMPV6_ECHO_REQUEST };
                let ident = be16(transport, 4);
                transport.first() == Some(&echo)
                    && sockets.iter().any(|(_, s)| matches!(s, Socket::Icmp(i) if i.ident() == ident))
            }
            _ => false,
        }
    }

    /// Records the validated report and makes TCP connections to `dst` fit
    /// and resend.
    fn apply_path_mtu(&mut self, now: Instant, dst: IpAddr, reported: usize, sockets: &mut SocketSet) {
        let link = self.link_mtu_for(dst);
        let Some(mtu) = self.pmtu.update(dst, reported, link, now) else { return };
        for (_, s) in sockets.iter_mut() {
            if let Socket::Tcp(t) = s {
                t.path_mtu_reduced(dst, mtu);
            }
        }
    }
}

#[cfg(test)]
mod tests;
