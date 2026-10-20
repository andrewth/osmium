//! Sockets: `AF_INET` streams (TCP) and datagrams (UDP) over the
//! [`NetStack`], as files in the descriptor table.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use osmium_fs::{Errno, File, FileKind, Stat};
use osmium_net::{Error, Socket, SocketAddr, SocketHandle, SocketSet, TcpSocket, TcpState, UdpSocket};
use osmium_sync::IrqSpinLock;

use crate::fd::{Access, OpenFile};
use crate::net::{NetStack, stack};
use crate::process::Process;

type SysResult = Result<u64, Errno>;

/// The IPv4 address of `a`. The socket layer is `AF_INET` only, so an IPv6
/// address (which it never creates) reads as unspecified.
fn v4(a: SocketAddr) -> SocketAddrV4 {
    match a {
        SocketAddr::V4(a) => a,
        SocketAddr::V6(a) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, a.port()),
    }
}

const AF_INET: u64 = 2;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;
const SOCKADDR_LEN: usize = 16;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_NOSIGNAL: u64 = 0x4000;
const SOL_SOCKET: u64 = 1;
const IPPROTO_TCP: u64 = 6;
const IPPROTO_UDP: u64 = 17;
const SO_TYPE: u64 = 3;
const SO_ERROR: u64 = 4;
const SO_REUSEADDR: u64 = 2;
const SO_KEEPALIVE: u64 = 9;
const SO_SNDBUF: u64 = 7;
const SO_RCVBUF: u64 = 8;
const SO_REUSEPORT: u64 = 15;
const SO_RCVTIMEO: u64 = 20;
const SO_SNDTIMEO: u64 = 21;
const TCP_NODELAY: u64 = 1;
/// `O_NONBLOCK` in `fcntl` status flags.
pub(crate) const O_NONBLOCK: u64 = 0o4000;

/// Bytes a stream socket buffers in each direction.
const TCP_BUFFER: usize = 16 * 1024;
/// Datagrams a UDP socket queues in each direction.
const UDP_QUEUE: usize = 16;
/// Most connections that may wait to be accepted.
const MAX_BACKLOG: usize = 16;
/// Bytes moved per send or receive call at most.
const IO_MAX: usize = 64 * 1024;

enum Tcp {
    /// Not connected or listening, possibly bound to an address.
    Unconnected(Option<SocketAddrV4>),
    /// Waiting for connections on `port`: one listening socket per slot of
    /// backlog.
    Listening { port: u16, backlog: Vec<SocketHandle> },
    /// Connecting or connected.
    Connected(SocketHandle),
}

enum Kind {
    Tcp(Tcp),
    Udp { handle: SocketHandle, peer: Option<SocketAddrV4> },
}

/// One socket: a file in the descriptor table, so `dup`, `fork` and `close`
/// work on it as on any other.
pub struct SocketFile {
    net: Arc<NetStack>,
    kind: IrqSpinLock<Kind>,
    nonblock: AtomicBool,
    /// `SO_RCVTIMEO` and `SO_SNDTIMEO` in nanoseconds; 0 waits for ever.
    rcv_timeout: AtomicU64,
    snd_timeout: AtomicU64,
}

fn net_errno(e: Error) -> Errno {
    match e {
        Error::WouldBlock => Errno::EAGAIN,
        Error::TooLarge => Errno::EMSGSIZE,
        Error::InvalidState => Errno::EINVAL,
        Error::InvalidAddress => Errno::EINVAL,
        Error::ConnectionRefused => Errno::ECONNREFUSED,
        Error::ConnectionReset => Errno::ECONNRESET,
        Error::TimedOut => Errno::ETIMEDOUT,
    }
}

/// Whether a connection has something for `recv` to report: data, the peer's
/// end of stream, or an error.
fn readable(t: &TcpSocket) -> bool {
    t.can_recv()
        || t.error().is_some()
        || matches!(t.state(), TcpState::CloseWait | TcpState::Closing | TcpState::LastAck | TcpState::TimeWait)
        || t.state() == TcpState::Closed
}

fn in_use(sockets: &SocketSet, port: u16, udp: bool) -> bool {
    sockets.iter().any(|(_, s)| match s {
        Socket::Tcp(t) => {
            !udp && !matches!(t.state(), TcpState::Closed | TcpState::TimeWait) && t.local_endpoint().port() == port
        }
        Socket::Udp(u) => udp && u.local_endpoint().is_some_and(|a| a.port() == port),
        _ => false,
    })
}

impl SocketFile {
    fn new(net: Arc<NetStack>, kind: Kind, nonblock: bool) -> Self {
        Self {
            net,
            kind: IrqSpinLock::new(kind),
            nonblock: AtomicBool::new(nonblock),
            rcv_timeout: AtomicU64::new(0),
            snd_timeout: AtomicU64::new(0),
        }
    }

    /// A new, unconnected stream socket on `net`.
    pub fn stream(net: Arc<NetStack>) -> Self {
        Self::new(net, Kind::Tcp(Tcp::Unconnected(None)), false)
    }

    /// A new, unbound datagram socket on `net`.
    pub fn datagram(net: Arc<NetStack>) -> Self {
        let handle = net.op(|_, s| s.add(UdpSocket::new(UDP_QUEUE, UDP_QUEUE)));
        Self::new(net, Kind::Udp { handle, peer: None }, false)
    }

    /// Whether calls fail with `EAGAIN` instead of waiting.
    pub fn is_nonblocking(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    /// Sets `O_NONBLOCK`.
    pub fn set_nonblocking(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    fn wait_mode(&self, flags: u64) -> bool {
        !self.is_nonblocking() && flags & MSG_DONTWAIT == 0
    }

    /// The interface address, or what is bound.
    fn fill(&self, a: SocketAddrV4) -> SocketAddrV4 {
        if a.ip().is_unspecified()
            && let Some(c) = self.net.peek(|i, _| i.config())
        {
            return SocketAddrV4::new(c.address, a.port());
        }
        a
    }

    /// Checks that `a` can be bound here and picks a port if it has none.
    fn bind_addr(&self, a: SocketAddrV4, udp: bool) -> Result<SocketAddrV4, Errno> {
        self.net.op(|iface, s| {
            if !a.ip().is_unspecified() && iface.config().map(|c| c.address) != Some(*a.ip()) {
                return Err(Errno::EADDRNOTAVAIL);
            }
            let mut port = a.port();
            if port == 0 {
                port =
                    (0..64).map(|_| iface.ephemeral_port()).find(|&p| !in_use(s, p, udp)).ok_or(Errno::EADDRINUSE)?;
            } else if in_use(s, port, udp) {
                return Err(Errno::EADDRINUSE);
            }
            Ok(SocketAddrV4::new(*a.ip(), port))
        })
    }

    /// `bind`.
    pub fn bind(&self, a: SocketAddrV4) -> Result<(), Errno> {
        let mut kind = self.kind.lock();
        match &mut *kind {
            Kind::Tcp(Tcp::Unconnected(bound @ None)) => {
                *bound = Some(self.bind_addr(a, false)?);
                Ok(())
            }
            Kind::Udp { handle, .. } => {
                let h = *handle;
                if self.net.peek(|_, s| s.get::<UdpSocket>(h).local_endpoint().is_some()) {
                    return Err(Errno::EINVAL);
                }
                let a = self.bind_addr(a, true)?;
                self.net.op(|_, s| s.get_mut::<UdpSocket>(h).bind_addr(a)).map_err(net_errno)
            }
            _ => Err(Errno::EINVAL),
        }
    }

    /// `listen`.
    pub fn listen(&self, backlog: usize) -> Result<(), Errno> {
        let mut kind = self.kind.lock();
        let bound = match &*kind {
            Kind::Tcp(Tcp::Unconnected(b)) => *b,
            Kind::Tcp(Tcp::Listening { .. }) => return Ok(()),
            Kind::Tcp(Tcp::Connected(_)) => return Err(Errno::EINVAL),
            Kind::Udp { .. } => return Err(Errno::EOPNOTSUPP),
        };
        let a = match bound {
            Some(a) => a,
            None => self.bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0), false)?,
        };
        let port = a.port();
        let n = backlog.clamp(1, MAX_BACKLOG);
        let backlog = self.net.op(|_, s| {
            (0..n)
                .map(|_| {
                    let mut t = TcpSocket::new(TCP_BUFFER, TCP_BUFFER);
                    t.listen(port).expect("a fresh socket can listen");
                    s.add(t)
                })
                .collect()
        });
        *kind = Kind::Tcp(Tcp::Listening { port, backlog });
        Ok(())
    }

    /// `accept`: waits for a connection and returns it with the peer's
    /// address.
    pub fn accept(&self, nonblock: bool, wait: bool) -> Result<(SocketFile, SocketAddrV4), Errno> {
        let (port, backlog) = match &*self.kind.lock() {
            Kind::Tcp(Tcp::Listening { port, backlog }) => (*port, backlog.clone()),
            _ => return Err(Errno::EINVAL),
        };
        let ready = |s: &SocketSet| {
            backlog
                .iter()
                .position(|&h| !matches!(s.get::<TcpSocket>(h).state(), TcpState::Listen | TcpState::SynReceived))
        };
        let deadline = self.net.deadline(self.rcv_timeout.load(Ordering::Relaxed));
        loop {
            let taken = self.net.op(|_, s| {
                let i = ready(s)?;
                let h = backlog[i];
                let peer = v4(s.get::<TcpSocket>(h).remote_endpoint());
                let mut t = TcpSocket::new(TCP_BUFFER, TCP_BUFFER);
                t.listen(port).expect("a fresh socket can listen");
                Some((i, h, peer, s.add(t)))
            });
            if let Some((i, h, peer, fresh)) = taken {
                // The slot is the same listener, or a clone's, so look it up
                // again rather than assume.
                if let Kind::Tcp(Tcp::Listening { backlog, .. }) = &mut *self.kind.lock() {
                    backlog[i] = fresh;
                }
                return Ok((Self::new(self.net.clone(), Kind::Tcp(Tcp::Connected(h)), nonblock), peer));
            }
            if !wait {
                return Err(Errno::EAGAIN);
            }
            if !self.net.wait(deadline, |s| ready(s).is_some()) {
                return Err(Errno::EAGAIN);
            }
        }
    }

    /// `connect`.
    pub fn connect(&self, to: SocketAddrV4) -> Result<(), Errno> {
        let mut kind = self.kind.lock();
        match &mut *kind {
            Kind::Udp { handle, peer } => {
                let h = *handle;
                if self.net.peek(|_, s| s.get::<UdpSocket>(h).local_endpoint().is_none()) {
                    let a = self.bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0), true)?;
                    self.net.op(|_, s| s.get_mut::<UdpSocket>(h).bind_addr(a)).map_err(net_errno)?;
                }
                *peer = Some(to);
                Ok(())
            }
            Kind::Tcp(Tcp::Listening { .. }) => Err(Errno::EISCONN),
            Kind::Tcp(Tcp::Unconnected(bound)) => {
                if self.net.peek(|i, _| i.config()).is_none() {
                    return Err(Errno::ENETUNREACH);
                }
                let port = bound.map_or(0, |a| a.port());
                let h = self.net.op(|_, s| {
                    let mut t = TcpSocket::new(TCP_BUFFER, TCP_BUFFER);
                    t.connect(to, port).map(|()| s.add(t))
                });
                let h = h.map_err(net_errno)?;
                *kind = Kind::Tcp(Tcp::Connected(h));
                drop(kind);
                self.finish_connect(h)
            }
            Kind::Tcp(Tcp::Connected(h)) => {
                let h = *h;
                drop(kind);
                let (state, port) = self.net.peek(|_, s| {
                    let t = s.get::<TcpSocket>(h);
                    (t.state(), t.local_endpoint().port())
                });
                match state {
                    TcpState::SynSent => self.finish_connect(h),
                    TcpState::Closed => {
                        self.net.op(|_, s| s.get_mut::<TcpSocket>(h).connect(to, port)).map_err(net_errno)?;
                        self.finish_connect(h)
                    }
                    _ => Err(Errno::EISCONN),
                }
            }
        }
    }

    /// Waits for (or, if non-blocking, reports) the end of the handshake.
    fn finish_connect(&self, h: SocketHandle) -> Result<(), Errno> {
        let state = self.net.peek(|_, s| s.get::<TcpSocket>(h).state());
        if state == TcpState::SynSent {
            if self.is_nonblocking() {
                return Err(Errno::EINPROGRESS);
            }
            self.net.wait(None, |s| s.get::<TcpSocket>(h).state() != TcpState::SynSent);
        }
        self.net.peek(|_, s| {
            let t = s.get::<TcpSocket>(h);
            match (t.state(), t.error()) {
                (_, Some(e)) => Err(net_errno(e)),
                (TcpState::Closed, None) => Err(Errno::ECONNREFUSED),
                _ => Ok(()),
            }
        })
    }

    fn tcp_handle(&self) -> Result<SocketHandle, Errno> {
        match &*self.kind.lock() {
            Kind::Tcp(Tcp::Connected(h)) => Ok(*h),
            _ => Err(Errno::ENOTCONN),
        }
    }

    /// `send`/`sendto`: `to` overrides a datagram socket's peer.
    pub fn send(&self, data: &[u8], to: Option<SocketAddrV4>, flags: u64) -> Result<usize, Errno> {
        let wait = self.wait_mode(flags);
        let udp = match &*self.kind.lock() {
            Kind::Udp { handle, peer } => Some((*handle, *peer)),
            _ => None,
        };
        if let Some((h, peer)) = udp {
            return self.send_datagram(h, data, to.or(peer), wait);
        }
        let h = self.tcp_handle()?;
        let deadline = self.net.deadline(self.snd_timeout.load(Ordering::Relaxed));
        let mut done = 0;
        loop {
            let r = self.net.op(|_, s| s.get_mut::<TcpSocket>(h).send(&data[done..]));
            match r {
                Ok(n) => done += n,
                Err(Error::WouldBlock) if done > 0 => return Ok(done),
                Err(Error::WouldBlock) if !wait => return Err(Errno::EAGAIN),
                Err(Error::WouldBlock) => {
                    let ready = |s: &SocketSet| {
                        let t = s.get::<TcpSocket>(h);
                        t.can_send() || !t.may_send()
                    };
                    if !self.net.wait(deadline, ready) {
                        return Err(Errno::EAGAIN);
                    }
                    continue;
                }
                Err(_) if done > 0 => return Ok(done),
                Err(Error::InvalidState) => return Err(Errno::EPIPE),
                Err(e) => return Err(net_errno(e)),
            }
            if done == data.len() || !wait {
                return Ok(done);
            }
        }
    }

    fn send_datagram(
        &self,
        h: SocketHandle,
        data: &[u8],
        to: Option<SocketAddrV4>,
        wait: bool,
    ) -> Result<usize, Errno> {
        let to = to.ok_or(Errno::EDESTADDRREQ)?;
        if self.net.peek(|_, s| s.get::<UdpSocket>(h).local_endpoint().is_none()) {
            let a = self.bind_addr(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0), true)?;
            self.net.op(|_, s| s.get_mut::<UdpSocket>(h).bind_addr(a)).map_err(net_errno)?;
        }
        let deadline = self.net.deadline(self.snd_timeout.load(Ordering::Relaxed));
        loop {
            match self.net.op(|_, s| s.get_mut::<UdpSocket>(h).send_to(data, to)) {
                Ok(()) => return Ok(data.len()),
                Err(Error::WouldBlock) if wait && self.net.wait(deadline, |s| s.get::<UdpSocket>(h).can_send()) => {}
                Err(e) => return Err(net_errno(e)),
            }
        }
    }

    /// `recv`/`recvfrom`: returns the bytes copied and the sender (for
    /// datagrams).
    pub fn recv(&self, buf: &mut [u8], flags: u64) -> Result<(usize, Option<SocketAddrV4>), Errno> {
        let wait = self.wait_mode(flags);
        let udp = match &*self.kind.lock() {
            Kind::Udp { handle, peer } => Some((*handle, *peer)),
            _ => None,
        };
        let deadline = self.net.deadline(self.rcv_timeout.load(Ordering::Relaxed));
        if let Some((h, peer)) = udp {
            loop {
                match self.net.op(|_, s| s.get_mut::<UdpSocket>(h).recv_from(buf)) {
                    Ok((_, from)) if peer.is_some_and(|p| SocketAddr::V4(p) != from) => continue,
                    Ok((n, from)) => return Ok((n.min(buf.len()), Some(v4(from)))),
                    Err(Error::WouldBlock) if wait && self.net.wait(deadline, |s| s.get::<UdpSocket>(h).can_recv()) => {
                    }
                    Err(e) => return Err(net_errno(e)),
                }
            }
        }
        let h = self.tcp_handle()?;
        loop {
            match self.net.op(|_, s| s.get_mut::<TcpSocket>(h).recv(buf)) {
                Ok(n) => return Ok((n, None)),
                Err(Error::WouldBlock) if wait && self.net.wait(deadline, |s| readable(s.get::<TcpSocket>(h))) => {}
                Err(Error::InvalidState) => return Err(Errno::ENOTCONN),
                Err(e) => return Err(net_errno(e)),
            }
        }
    }

    /// `shutdown`: `how` is 0 (read), 1 (write) or 2 (both). Reads cannot be
    /// shut down separately; a stream's write side sends its FIN.
    pub fn shutdown(&self, how: u64) -> Result<(), Errno> {
        if how > 2 {
            return Err(Errno::EINVAL);
        }
        match &*self.kind.lock() {
            Kind::Tcp(Tcp::Connected(h)) => {
                if how != 0 {
                    self.net.op(|_, s| s.get_mut::<TcpSocket>(*h).close());
                }
                Ok(())
            }
            Kind::Udp { peer: Some(_), .. } => Ok(()),
            _ => Err(Errno::ENOTCONN),
        }
    }

    /// The local address, `getsockname`.
    pub fn local_addr(&self) -> SocketAddrV4 {
        let a = match &*self.kind.lock() {
            Kind::Tcp(Tcp::Unconnected(b)) => b.unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            Kind::Tcp(Tcp::Listening { port, .. }) => SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, *port),
            Kind::Tcp(Tcp::Connected(h)) => self.net.peek(|_, s| v4(s.get::<TcpSocket>(*h).local_endpoint())),
            Kind::Udp { handle, .. } => self
                .net
                .peek(|_, s| s.get::<UdpSocket>(*handle).local_endpoint())
                .map_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0), v4),
        };
        self.fill(a)
    }

    /// The peer's address, `getpeername`.
    pub fn peer_addr(&self) -> Result<SocketAddrV4, Errno> {
        match &*self.kind.lock() {
            Kind::Tcp(Tcp::Connected(h)) => {
                let (state, a) = self.net.peek(|_, s| {
                    let t = s.get::<TcpSocket>(*h);
                    (t.state(), v4(t.remote_endpoint()))
                });
                if matches!(state, TcpState::SynSent | TcpState::Closed) { Err(Errno::ENOTCONN) } else { Ok(a) }
            }
            Kind::Udp { peer: Some(a), .. } => Ok(*a),
            _ => Err(Errno::ENOTCONN),
        }
    }

    /// `SO_ERROR`: the pending error of a stream, as an errno (0 for none).
    fn pending_error(&self) -> i32 {
        match &*self.kind.lock() {
            Kind::Tcp(Tcp::Connected(h)) => {
                self.net.peek(|_, s| s.get::<TcpSocket>(*h).error()).map_or(0, |e| net_errno(e).0)
            }
            _ => 0,
        }
    }

    fn type_code(&self) -> u64 {
        if matches!(&*self.kind.lock(), Kind::Udp { .. }) { SOCK_DGRAM } else { SOCK_STREAM }
    }
}

impl Drop for SocketFile {
    fn drop(&mut self) {
        match core::mem::replace(self.kind.get_mut(), Kind::Tcp(Tcp::Unconnected(None))) {
            Kind::Udp { handle, .. } => {
                self.net.op(|_, s| drop(s.remove(handle)));
            }
            Kind::Tcp(Tcp::Connected(h)) => self.net.release_tcp(h, false),
            Kind::Tcp(Tcp::Listening { backlog, .. }) => {
                for h in backlog {
                    self.net.release_tcp(h, true);
                }
            }
            Kind::Tcp(Tcp::Unconnected(_)) => {}
        }
    }
}

impl File for SocketFile {
    fn read(&self, _off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.recv(buf, 0).map(|(n, _)| n)
    }

    fn write(&self, _off: u64, buf: &[u8]) -> Result<usize, Errno> {
        self.send(buf, None, 0)
    }

    fn stat(&self) -> Stat {
        Stat { kind: FileKind::Socket, mode: 0o777, nlink: 1, ..Stat::default() }
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// Whether `file` is a socket in non-blocking mode (for `F_GETFL`).
pub(crate) fn status_flags(file: &Arc<dyn File>) -> u64 {
    match file.as_any().and_then(|a| a.downcast_ref::<SocketFile>()) {
        Some(s) if s.is_nonblocking() => O_NONBLOCK,
        _ => 0,
    }
}

/// Applies `F_SETFL` to a socket; other files have no flags to change.
pub(crate) fn set_status_flags(file: &Arc<dyn File>, flags: u64) {
    if let Some(s) = file.as_any().and_then(|a| a.downcast_ref::<SocketFile>()) {
        s.set_nonblocking(flags & O_NONBLOCK != 0);
    }
}

fn sock(of: &Arc<OpenFile>) -> Result<&SocketFile, Errno> {
    of.file().as_any().and_then(|a| a.downcast_ref::<SocketFile>()).ok_or(Errno::ENOTSOCK)
}

fn open(p: &Process, fd: i32) -> Result<Arc<OpenFile>, Errno> {
    p.files().lock().get(fd)
}

/// Reads a `struct sockaddr_in` of `len` bytes at `va`.
fn get_addr(p: &Process, va: u64, len: u64) -> Result<SocketAddrV4, Errno> {
    if len < SOCKADDR_LEN as u64 {
        return Err(Errno::EINVAL);
    }
    let mut b = [0u8; SOCKADDR_LEN];
    p.memory().read(va, &mut b)?;
    if u16::from_ne_bytes([b[0], b[1]]) as u64 != AF_INET {
        return Err(Errno::EAFNOSUPPORT);
    }
    Ok(SocketAddrV4::new(Ipv4Addr::new(b[4], b[5], b[6], b[7]), u16::from_be_bytes([b[2], b[3]])))
}

/// Writes `a` as a `struct sockaddr_in` at `va`, truncated to the `u32`
/// length at `lenp`, which gets the full size. Does nothing if `va` is 0.
fn put_addr(p: &Process, va: u64, lenp: u64, a: SocketAddrV4) -> Result<(), Errno> {
    if va == 0 {
        return Ok(());
    }
    let mut cap = [0u8; 4];
    p.memory().read(lenp, &mut cap)?;
    let mut b = [0u8; SOCKADDR_LEN];
    b[..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
    b[2..4].copy_from_slice(&a.port().to_be_bytes());
    b[4..8].copy_from_slice(&a.ip().octets());
    let n = (u32::from_ne_bytes(cap) as usize).min(SOCKADDR_LEN);
    p.memory().write(va, &b[..n])?;
    p.memory().write(lenp, &(SOCKADDR_LEN as u32).to_ne_bytes())
}

pub(crate) fn socket(p: &Process, domain: u64, ty: u64, protocol: u64) -> SysResult {
    if domain != AF_INET {
        return Err(Errno::EAFNOSUPPORT);
    }
    let net = stack().ok_or(Errno::EAFNOSUPPORT)?.clone();
    let file = match (ty & 0xf, protocol) {
        (SOCK_STREAM, 0 | IPPROTO_TCP) => SocketFile::stream(net),
        (SOCK_DGRAM, 0 | IPPROTO_UDP) => SocketFile::datagram(net),
        (SOCK_STREAM | SOCK_DGRAM, _) => return Err(Errno::EPROTONOSUPPORT),
        _ => return Err(Errno::EPROTOTYPE),
    };
    file.set_nonblocking(ty & SOCK_NONBLOCK != 0);
    let open = OpenFile::new(Arc::new(file), Access::RW);
    p.files().lock().insert_from(0, open, ty & SOCK_CLOEXEC != 0).map(|fd| fd as u64)
}

pub(crate) fn bind(p: &Process, fd: i32, addr: u64, len: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = sock(&of)?;
    s.bind(get_addr(p, addr, len)?).map(|()| 0)
}

pub(crate) fn listen(p: &Process, fd: i32, backlog: u64) -> SysResult {
    let of = open(p, fd)?;
    sock(&of)?.listen((backlog as i32).max(1) as usize).map(|()| 0)
}

pub(crate) fn accept(p: &Process, fd: i32, addr: u64, lenp: u64, flags: u64) -> SysResult {
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    let of = open(p, fd)?;
    let s = sock(&of)?;
    let (conn, peer) = s.accept(flags & SOCK_NONBLOCK != 0, !s.is_nonblocking())?;
    put_addr(p, addr, lenp, peer)?;
    let open = OpenFile::new(Arc::new(conn), Access::RW);
    p.files().lock().insert_from(0, open, flags & SOCK_CLOEXEC != 0).map(|fd| fd as u64)
}

pub(crate) fn connect(p: &Process, fd: i32, addr: u64, len: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = sock(&of)?;
    s.connect(get_addr(p, addr, len)?).map(|()| 0)
}

pub(crate) fn sendto(p: &Process, fd: i32, buf: u64, len: u64, flags: u64, addr: u64, alen: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = sock(&of)?;
    let to = if addr != 0 { Some(get_addr(p, addr, alen)?) } else { None };
    let n = len as usize;
    if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if n > IO_MAX && s.type_code() == SOCK_DGRAM {
        return Err(Errno::EMSGSIZE);
    }
    let mut data = vec![0u8; n.min(IO_MAX)];
    p.memory().read(buf, &mut data)?;
    s.send(&data, to, flags).map(|n| n as u64)
}

pub(crate) fn recvfrom(p: &Process, fd: i32, buf: u64, len: u64, flags: u64, addr: u64, lenp: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = sock(&of)?;
    if flags & !MSG_DONTWAIT != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut data = vec![0u8; (len as usize).min(IO_MAX)];
    let (n, from) = s.recv(&mut data, flags)?;
    p.memory().write(buf, &data[..n])?;
    if let Some(from) = from {
        put_addr(p, addr, lenp, from)?;
    }
    Ok(n as u64)
}

pub(crate) fn shutdown(p: &Process, fd: i32, how: u64) -> SysResult {
    let of = open(p, fd)?;
    sock(&of)?.shutdown(how).map(|()| 0)
}

pub(crate) fn getsockname(p: &Process, fd: i32, addr: u64, lenp: u64) -> SysResult {
    let of = open(p, fd)?;
    put_addr(p, addr, lenp, sock(&of)?.local_addr()).map(|()| 0)
}

pub(crate) fn getpeername(p: &Process, fd: i32, addr: u64, lenp: u64) -> SysResult {
    let of = open(p, fd)?;
    put_addr(p, addr, lenp, sock(&of)?.peer_addr()?).map(|()| 0)
}

/// Whether option `name` at `level` is one this layer accepts and ignores.
fn known_option(level: u64, name: u64) -> bool {
    match level {
        SOL_SOCKET => matches!(name, SO_REUSEADDR | SO_REUSEPORT | SO_KEEPALIVE | SO_SNDBUF | SO_RCVBUF),
        IPPROTO_TCP => name == TCP_NODELAY,
        _ => false,
    }
}

pub(crate) fn setsockopt(p: &Process, fd: i32, level: u64, name: u64, val: u64, len: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = sock(&of)?;
    if level == SOL_SOCKET && matches!(name, SO_RCVTIMEO | SO_SNDTIMEO) {
        // struct timeval { time_t sec; suseconds_t usec; }
        if len < 16 {
            return Err(Errno::EINVAL);
        }
        let mut tv = [0u8; 16];
        p.memory().read(val, &mut tv)?;
        let sec = u64::from_ne_bytes(tv[..8].try_into().unwrap());
        let usec = u64::from_ne_bytes(tv[8..].try_into().unwrap());
        if usec >= 1_000_000 || sec > u64::MAX / 2_000_000_000 {
            return Err(Errno::EINVAL);
        }
        let ns = sec * 1_000_000_000 + usec * 1000;
        let timeout = if name == SO_RCVTIMEO { &s.rcv_timeout } else { &s.snd_timeout };
        timeout.store(ns, Ordering::Relaxed);
        return Ok(0);
    }
    if !known_option(level, name) {
        return Err(Errno::ENOPROTOOPT);
    }
    if len < 4 {
        return Err(Errno::EINVAL);
    }
    p.memory().read(val, &mut [0u8; 4])?;
    Ok(0)
}

pub(crate) fn getsockopt(p: &Process, fd: i32, level: u64, name: u64, val: u64, lenp: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = sock(&of)?;
    let v: i32 = match (level, name) {
        (SOL_SOCKET, SO_TYPE) => s.type_code() as i32,
        (SOL_SOCKET, SO_ERROR) => s.pending_error(),
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => TCP_BUFFER as i32,
        _ if known_option(level, name) => 0,
        _ => return Err(Errno::ENOPROTOOPT),
    };
    let mut cap = [0u8; 4];
    p.memory().read(lenp, &mut cap)?;
    let n = (u32::from_ne_bytes(cap) as usize).min(4);
    p.memory().write(val, &v.to_ne_bytes()[..n])?;
    p.memory().write(lenp, &4u32.to_ne_bytes())?;
    Ok(0)
}
