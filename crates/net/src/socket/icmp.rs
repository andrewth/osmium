//! ICMP echo (ping) sockets. The interface answers echo requests itself;
//! these sockets send requests and collect the replies.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::IpAddr;

use super::{Cx, Packet};
use crate::ipv6::{ICMPV6_ECHO_REQUEST, Icmpv6Header, PROTO_ICMPV6, echo_body};
use crate::wire::{ICMP_ECHO_REQUEST, IcmpHeader, PROTO_ICMP};
use crate::{Error, Instant};

/// Largest echo payload accepted, as for UDP.
const MAX_PAYLOAD: usize = 65535 - 20 - 8;

/// An echo reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EchoReply {
    /// Who answered.
    pub from: IpAddr,
    /// The sequence number of the request it answers.
    pub seq: u16,
    /// The echoed data.
    pub data: Vec<u8>,
    /// When the reply arrived.
    pub at: Instant,
}

/// Sends echo requests with one identifier and receives the replies that
/// carry it.
pub struct IcmpSocket {
    ident: u16,
    tx: VecDeque<(IpAddr, u16, Vec<u8>)>,
    rx: VecDeque<EchoReply>,
    limit: usize,
}

impl IcmpSocket {
    /// A socket for echo identifier `ident`, queueing up to `packets`
    /// requests and replies each.
    pub fn new(ident: u16, packets: usize) -> Self {
        Self { ident, tx: VecDeque::new(), rx: VecDeque::new(), limit: packets }
    }

    /// The echo identifier.
    pub fn ident(&self) -> u16 {
        self.ident
    }

    /// Queues an echo request to `dst`, an IPv4 or IPv6 address (ICMPv6
    /// for the latter).
    pub fn send_echo(&mut self, dst: impl Into<IpAddr>, seq: u16, data: &[u8]) -> Result<(), Error> {
        let dst = dst.into();
        if dst.is_unspecified() {
            return Err(Error::InvalidAddress);
        }
        if data.len() > MAX_PAYLOAD {
            return Err(Error::TooLarge);
        }
        if self.tx.len() >= self.limit {
            return Err(Error::WouldBlock);
        }
        self.tx.push_back((dst, seq, data.to_vec()));
        Ok(())
    }

    /// Takes the next reply.
    pub fn recv(&mut self) -> Option<EchoReply> {
        self.rx.pop_front()
    }

    pub(crate) fn process(&mut self, reply: EchoReply) {
        if self.rx.len() < self.limit {
            self.rx.push_back(reply);
        }
    }

    pub(crate) fn poll_at(&self) -> Option<Instant> {
        (!self.tx.is_empty()).then_some(Instant::ZERO)
    }

    pub(crate) fn dispatch(&mut self, cx: &mut Cx, out: &mut Vec<Packet>) {
        while let Some((dst, _, _)) = self.tx.front() {
            let Some(src) = cx.source_for(*dst) else { return };
            let Some((dst, seq, data)) = self.tx.pop_front() else { return };
            let (protocol, payload) = match (src, dst) {
                (IpAddr::V6(s), IpAddr::V6(d)) => (
                    PROTO_ICMPV6,
                    Icmpv6Header { ty: ICMPV6_ECHO_REQUEST, code: 0 }.emit(s, d, &echo_body(self.ident, seq, &data)),
                ),
                _ => (PROTO_ICMP, IcmpHeader { ty: ICMP_ECHO_REQUEST, code: 0, ident: self.ident, seq }.emit(&data)),
            };
            out.push(Packet { src, dst, protocol, payload });
        }
    }
}
