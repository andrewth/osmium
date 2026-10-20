//! UDP sockets.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};

use super::{Cx, Packet, binds};
use crate::wire::{PROTO_UDP, UdpHeader};
use crate::{Error, Instant};

/// Largest payload [`UdpSocket::send_to`] accepts: what a datagram of 65535
/// bytes holds. The interface fragments what does not fit its MTU.
pub const MAX_PAYLOAD: usize = 65535 - 20 - 8;

/// A UDP socket with bounded queues of datagrams in each direction.
pub struct UdpSocket {
    local: Option<SocketAddrV4>,
    rx: VecDeque<(SocketAddrV4, Vec<u8>)>,
    tx: VecDeque<(SocketAddrV4, Vec<u8>)>,
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

    /// Binds the socket to `port` on every address of the interface.
    /// [`Interface::ephemeral_port`](crate::Interface::ephemeral_port)
    /// picks one for a client.
    pub fn bind(&mut self, port: u16) -> Result<(), Error> {
        self.bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
    }

    /// Binds the socket to `local`; an unspecified address takes traffic
    /// to any address of the interface (including broadcasts).
    pub fn bind_addr(&mut self, local: SocketAddrV4) -> Result<(), Error> {
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
    pub fn local_endpoint(&self) -> Option<SocketAddrV4> {
        self.local
    }

    /// Unbinds the socket and discards both queues.
    pub fn close(&mut self) {
        self.local = None;
        self.rx.clear();
        self.tx.clear();
    }

    /// Queues `data` as one datagram to `remote`.
    pub fn send_to(&mut self, data: &[u8], remote: SocketAddrV4) -> Result<(), Error> {
        if self.local.is_none() {
            return Err(Error::InvalidState);
        }
        if remote.port() == 0 || remote.ip().is_unspecified() {
            return Err(Error::InvalidAddress);
        }
        if data.len() > MAX_PAYLOAD {
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
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4), Error> {
        let (from, data) = self.rx.pop_front().ok_or(Error::WouldBlock)?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((data.len(), from))
    }

    /// Returns true if a datagram is waiting.
    pub fn can_recv(&self) -> bool {
        !self.rx.is_empty()
    }

    /// Returns true if [`send_to`](Self::send_to) has room for a datagram.
    pub fn can_send(&self) -> bool {
        self.tx.len() < self.tx_limit
    }

    pub(crate) fn accepts(&self, dst: SocketAddrV4) -> bool {
        self.local.is_some_and(|l| binds(l, dst))
    }

    pub(crate) fn process(&mut self, src: SocketAddrV4, data: &[u8]) {
        if self.rx.len() < self.rx_limit {
            self.rx.push_back((src, data.to_vec()));
        }
    }

    pub(crate) fn poll_at(&self) -> Option<Instant> {
        (!self.tx.is_empty()).then_some(Instant::ZERO)
    }

    pub(crate) fn dispatch(&mut self, cx: &mut Cx, out: &mut Vec<Packet>) {
        let Some(local) = self.local else { return };
        let src = if local.ip().is_unspecified() {
            match cx.addr {
                Some(a) => a,
                None => return,
            }
        } else {
            *local.ip()
        };
        while let Some((remote, data)) = self.tx.pop_front() {
            let header = UdpHeader { src_port: local.port(), dst_port: remote.port() };
            let payload = header.emit(src, *remote.ip(), &data);
            out.push(Packet { src, dst: *remote.ip(), protocol: PROTO_UDP, payload });
        }
    }
}
