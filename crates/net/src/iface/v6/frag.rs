//! Fragmentation and reassembly for IPv6 on an [`Interface`]: datagrams
//! larger than the MTU are sent in pieces (except TCP, which sizes its
//! segments to fit), and pieces that arrive are put back together within
//! the limits of [`frag6`](crate::frag6).
//!
//! Extension headers that came before a fragment header (hop-by-hop,
//! routing, destination options) are checked on arrival and then left out
//! of the reassembled packet. No ICMPv6 time-exceeded message is sent when
//! a datagram times out.

use core::net::Ipv6Addr;

use osmium_hal::net::MacAddress;

use super::{Interface, Ipv6Header, PROTO_FRAGMENT, PROTO_TCP};
use crate::Instant;
use crate::frag6::{self, Limits, Reassembler};
use crate::ipv6::{IPV6_HEADER_LEN, Ipv6Fragment};
use crate::socket::SocketSet;
use crate::wire::put;

impl Interface {
    /// The limits on putting fragmented IPv6 datagrams back together.
    pub fn ipv6_reassembly_limits(&self) -> Limits {
        self.v6.reasm.limits()
    }

    /// Sets the limits on reassembling fragmented IPv6 datagrams (see
    /// [`Limits::default`] for the defaults); datagrams held beyond them are
    /// discarded.
    pub fn set_ipv6_reassembly_limits(&mut self, limits: Limits) {
        self.v6.reasm.set_limits(limits);
    }

    /// Bytes held for IPv6 datagrams that are not yet complete.
    pub fn ipv6_reassembly_bytes(&self) -> usize {
        self.v6.reasm.held()
    }

    /// Queues the frames that carry `payload` of protocol `next_header` to
    /// `dst_mac`: one, or fragments if it exceeds the MTU. TCP is not
    /// fragmented, and a datagram that does not fit the queue is dropped
    /// whole rather than sent in part.
    pub(super) fn queue_ip6(
        &mut self,
        dst_mac: MacAddress,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        hop_limit: u8,
        payload: &[u8],
    ) {
        let mtu = self.v6.mtu(self.mtu);
        if IPV6_HEADER_LEN + payload.len() <= mtu {
            let frame = self.ip6_frame(dst_mac, src, dst, next_header, hop_limit, payload);
            return self.queue_frame(frame);
        }
        if next_header == PROTO_TCP {
            return;
        }
        let ident = self.rng.next_u32();
        let Some(pieces) = frag6::fragment(payload, next_header, mtu, ident) else { return };
        if self.tx.len().saturating_add(pieces.len()) > super::super::TX_QUEUE {
            return;
        }
        for piece in pieces {
            let frame = self.ip6_frame(dst_mac, src, dst, PROTO_FRAGMENT, hop_limit, &piece);
            self.queue_frame(frame);
        }
    }

    /// Handles an IPv6 packet from a frame addressed to us or to a group.
    pub(in crate::iface) fn process_ipv6(&mut self, now: Instant, bytes: &[u8], sockets: &mut SocketSet) {
        self.process_ipv6_with(now, bytes, sockets, false);
    }

    /// Takes a piece of a fragmented datagram addressed to us. Once the
    /// datagram is whole it is processed as a packet of its own.
    pub(super) fn reassemble6(
        &mut self,
        now: Instant,
        ip: &Ipv6Header,
        fragment: Ipv6Fragment,
        data: &[u8],
        sockets: &mut SocketSet,
    ) {
        let Ok(Some(done)) = self.v6.reasm.add(now, ip.src, ip.dst, fragment, ip.next_header, data) else { return };
        let header = Ipv6Header {
            src: done.src,
            dst: done.dst,
            next_header: done.next_header,
            hop_limit: ip.hop_limit,
            payload_len: done.data.len(),
            fragment: None,
        };
        let mut packet = alloc::vec![0; IPV6_HEADER_LEN + done.data.len()];
        header.emit(&mut packet);
        put(&mut packet, IPV6_HEADER_LEN, &done.data);
        self.process_ipv6_with(now, &packet, sockets, true);
    }
}

impl super::State {
    /// Discards datagrams that took too long.
    pub(super) fn expire_fragments(&mut self, now: Instant) {
        self.reasm.expire(now);
    }
}

pub(super) fn new_reassembler() -> Reassembler {
    Reassembler::new()
}

#[cfg(test)]
mod tests;
