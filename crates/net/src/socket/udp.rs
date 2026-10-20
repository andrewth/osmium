//! UDP sockets.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddr};

use super::{Cx, Packet, binds};
use crate::wire::{PROTO_UDP, UdpHeader};
use crate::{Error, Instant};

/// Largest payload [`UdpSocket::send_to`] accepts to an IPv4 address: what a
/// datagram of 65535 bytes holds. The interface fragments what does not fit
/// its MTU.
pub const MAX_PAYLOAD: usize = 65535 - 20 - 8;

/// Largest payload accepted to an IPv6 address: what the 16-bit payload
/// length holds after the UDP header. IPv6 datagrams are not fragmented on
/// the way out, so one larger than the MTU allows is dropped.
pub const MAX_PAYLOAD_V6: usize = 65535 - 8;

/// A UDP socket with bounded queues of datagrams in each direction.
pub struct UdpSocket {
    local: Option<SocketAddr>,
    rx: VecDeque<(SocketAddr, Vec<u8>)>,
    tx: VecDeque<(SocketAddr, Vec<u8>)>,
    rx_limit: usize,
    tx_limit: usize,
}

impl UdpSocket {
    /// An unbound socket that queues up to `rx_packets` received and
    /// `tx_packets` outgoing datagrams. Datagrams that arrive when the
    /// receive queue is full are dropped.
    pub fn new(rx_packets: usize, tx_packets: usize) -> Self {
        Self { local: None, rx: VecDeque::new(), tx: VecDeque::new(), rx_limit: rx_packets, tx_limit: tx_packets }
    }

    /// Binds the socket to `port` on every IPv4 address of the interface.
    /// [`Interface::ephemeral_port`](crate::Interface::ephemeral_port)
    /// picks one for a client. Use [`bind_addr`](Self::bind_addr) with
    /// `[::]` for an IPv6 socket.
    pub fn bind(&mut self, port: u16) -> Result<(), Error> {
        self.bind_addr(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port))
    }

    /// Binds the socket to `local`; an unspecified address takes traffic
    /// to any address of the interface of its family (including IPv4
    /// broadcasts). A socket serves one family: it sends only to remotes of
    /// the family it is bound to.
    pub fn bind_addr(&mut self, local: impl Into<SocketAddr>) -> Result<(), Error> {
        let local = local.into();
        if local.port() == 0 {
            return Err(Error::InvalidAddress);
        }
        if self.local.is_some() {
            return Err(Error::InvalidState);
        }
        self.local = Some(local);
        Ok(())
    }

    /// The address the socket is bound to.
    pub fn local_endpoint(&self) -> Option<SocketAddr> {
        self.local
    }

    /// Unbinds the socket and discards both queues.
    pub fn close(&mut self) {
        self.local = None;
        self.rx.clear();
        self.tx.clear();
    }

    /// Queues `data` as one datagram to `remote`.
    pub fn send_to(&mut self, data: &[u8], remote: impl Into<SocketAddr>) -> Result<(), Error> {
        let remote = remote.into();
        let Some(local) = self.local else { return Err(Error::InvalidState) };
        if remote.port() == 0 || remote.ip().is_unspecified() || local.is_ipv4() != remote.is_ipv4() {
            return Err(Error::InvalidAddress);
        }
        if data.len() > if remote.is_ipv4() { MAX_PAYLOAD } else { MAX_PAYLOAD_V6 } {
            return Err(Error::TooLarge);
        }
        if self.tx.len() >= self.tx_limit {
            return Err(Error::WouldBlock);
        }
        self.tx.push_back((remote, data.to_vec()));
        Ok(())
    }

    /// Takes the next datagram, copying as much as fits into `buf` (the rest
    /// is discarded), and returns its full length and sender.
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        let (from, data) = self.rx.pop_front().ok_or(Error::WouldBlock)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((data.len(), from))
    }

    /// Like [`recv_from`](Self::recv_from), but leaves the datagram queued
    /// (`MSG_PEEK`).
    pub fn peek_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        let (from, data) = self.rx.front().ok_or(Error::WouldBlock)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((data.len(), *from))
    }

    /// Returns true if a datagram is waiting.
    pub fn can_recv(&self) -> bool {
        !self.rx.is_empty()
    }

    /// Returns true if [`send_to`](Self::send_to) has room for a datagram.
    pub fn can_send(&self) -> bool {
        self.tx.len() < self.tx_limit
    }

    pub(crate) fn accepts(&self, dst: SocketAddr) -> bool {
        self.local.is_some_and(|l| binds(l, dst))
    }

    pub(crate) fn process(&mut self, src: SocketAddr, data: &[u8]) {
        if self.rx.len() < self.rx_limit {
            self.rx.push_back((src, data.to_vec()));
        }
    }

    pub(crate) fn poll_at(&self) -> Option<Instant> {
        (!self.tx.is_empty()).then_some(Instant::ZERO)
    }

    pub(crate) fn dispatch(&mut self, cx: &mut Cx, out: &mut Vec<Packet>) {
        let Some(local) = self.local else { return };
        while let Some((remote, data)) = self.tx.front() {
            // Datagrams to this host itself come from the loopback address.
            let src = if !local.ip().is_unspecified() {
                local.ip()
            } else if remote.ip().is_loopback() {
                remote.ip()
            } else {
                // Without an address of the interface's, hold the datagram.
                match cx.source_for(remote.ip()) {
                    Some(a) => a,
                    None => return,
                }
            };
            let header = UdpHeader { src_port: local.port(), dst_port: remote.port() };
            let payload = header.emit(src, remote.ip(), data);
            out.push(Packet { src, dst: remote.ip(), protocol: PROTO_UDP, payload });
            self.tx.pop_front();
        }
    }
}
