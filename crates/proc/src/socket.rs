//! Sockets: `AF_INET` streams (TCP) and datagrams (UDP) over the
//! [`NetStack`], as files in the descriptor table.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use osmium_fs::{Errno, File, FileKind, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, Stat};
use osmium_net::{
    BindProtocol, Error, ReuseOptions, Socket, SocketAddr, SocketHandle, SocketSet, TcpSocket, TcpState, UdpSocket,
};
use osmium_sync::IrqSpinLock;
use osmium_sync::fallible::{try_arc, try_zeroed};

use crate::bytes;
use crate::fd::{Access, OpenFile};
use crate::net::{NetStack, stack};
use crate::oom;
use crate::process::Process;
use crate::unix::{self, UnixSocket};

type SysResult = Result<u64, Errno>;

const AF_UNIX: u64 = 1;
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
const MSG_PEEK: u64 = 0x2;
const MSG_TRUNC: u64 = 0x20;
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

/// The next group number for the listeners of a socket (see
/// `TcpSocket::set_reuse_group`).
static NEXT_GROUP: AtomicU32 = AtomicU32::new(1);

/// Bytes a stream socket buffers in each direction.
const TCP_BUFFER: usize = 16 * 1024;
/// Datagrams a UDP socket queues in each direction.
const UDP_QUEUE: usize = 16;
/// Most connections that may wait to be accepted.
const MAX_BACKLOG: usize = 16;
/// Bytes moved per send or receive call at most.
const IO_MAX: usize = 64 * 1024;
/// `struct msghdr` on 64-bit Linux.
const MSGHDR_LEN: usize = 56;
/// Most `iovec`s of one `sendmsg` or `recvmsg` (`UIO_MAXIOV`).
const IOV_MAX: u64 = 1024;

/// The sockets that wait to be accepted: one per slot, up to [`MAX_BACKLOG`].
type Backlog = [Option<SocketHandle>; MAX_BACKLOG];

// The backlog is inline, not boxed: a listening socket made by `accept` or
// `listen` must not need memory it cannot report the lack of.
#[allow(clippy::large_enum_variant)]
enum Tcp {
    /// Not connected or listening, possibly bound to an address.
    Unconnected(Option<SocketAddrV4>),
    /// Waiting for connections to `addr`: one listening socket per slot of
    /// backlog.
    Listening { addr: SocketAddrV4, backlog: Backlog },
    /// Connecting or connected.
    Connected(SocketHandle),
}

#[allow(clippy::large_enum_variant)]
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
    /// `SO_REUSEADDR` and `SO_REUSEPORT`. Processes have no user ids yet, so
    /// every socket has the same owner for `SO_REUSEPORT`.
    reuse_addr: AtomicBool,
    reuse_port: AtomicBool,
}

/// What a receive took.
struct Received {
    copied: usize,
    truncated: bool,
    from: Option<SocketAddrV4>,
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
        Error::AddressInUse => Errno::EADDRINUSE,
        Error::OutOfMemory => Errno::ENOMEM,
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
            reuse_addr: AtomicBool::new(false),
            reuse_port: AtomicBool::new(false),
        }
    }

    /// A new, unconnected stream socket on `net`.
    pub fn stream(net: Arc<NetStack>) -> Self {
        Self::new(net, Kind::Tcp(Tcp::Unconnected(None)), false)
    }

    /// A new, unbound datagram socket on `net`.
    pub fn datagram(net: Arc<NetStack>) -> Result<Self, Errno> {
        let handle = net.op(|_, s| s.try_add(UdpSocket::new(UDP_QUEUE, UDP_QUEUE))).map_err(net_errno)?;
        Ok(Self::new(net, Kind::Udp { handle, peer: None }, false))
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

    /// The socket's `SO_REUSEADDR` and `SO_REUSEPORT`.
    fn reuse(&self) -> ReuseOptions {
        ReuseOptions {
            addr: self.reuse_addr.load(Ordering::Relaxed),
            port: self.reuse_port.load(Ordering::Relaxed),
            owner: 0,
        }
    }

    /// Checks that `a` can be bound here and picks a port if it has none.
    /// A port that is named is checked against the other sockets with the
    /// `SO_REUSEADDR` and `SO_REUSEPORT` rules; one that is chosen must be
    /// free of every socket.
    fn bind_addr(&self, a: SocketAddrV4, udp: bool) -> Result<SocketAddrV4, Errno> {
        self.net.op(|iface, s| {
            if !a.ip().is_unspecified() && !a.ip().is_loopback() && iface.config().map(|c| c.address) != Some(*a.ip()) {
                return Err(Errno::EADDRNOTAVAIL);
            }
            let mut port = a.port();
            if port == 0 {
                port =
                    (0..64).map(|_| iface.ephemeral_port()).find(|&p| !in_use(s, p, udp)).ok_or(Errno::EADDRINUSE)?;
            } else {
                let proto = if udp { BindProtocol::Udp } else { BindProtocol::Tcp };
                s.check_bind(proto, SocketAddr::V4(SocketAddrV4::new(*a.ip(), port)), self.reuse(), None)
                    .map_err(net_errno)?;
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
        let n = backlog.clamp(1, MAX_BACKLOG);
        let reuse = self.reuse();
        // The listeners of this socket share an accept group, so that
        // `SO_REUSEPORT` spreads connections over sockets, not listeners.
        let group = NEXT_GROUP.fetch_add(1, Ordering::Relaxed).max(1);
        let backlog = self.net.op(|_, s| {
            // Listening is a bind of its own: another socket may have come
            // since `bind`.
            s.check_bind(BindProtocol::Tcp, SocketAddr::V4(a), reuse, None).map_err(net_errno)?;
            let mut backlog: Backlog = [None; MAX_BACKLOG];
            for slot in backlog.iter_mut().take(n) {
                let mut t = TcpSocket::new(TCP_BUFFER, TCP_BUFFER);
                t.set_reuse(reuse);
                t.set_reuse_group(group);
                if let Err(e) = t.listen_on(a) {
                    for h in backlog.iter().flatten() {
                        drop(s.remove(*h));
                    }
                    return Err(net_errno(e));
                }
                match s.try_add(t) {
                    Ok(h) => *slot = Some(h),
                    Err(e) => {
                        // Give back the sockets made so far.
                        for h in backlog.iter().flatten() {
                            drop(s.remove(*h));
                        }
                        return Err(net_errno(e));
                    }
                }
            }
            Ok(backlog)
        })?;
        *kind = Kind::Tcp(Tcp::Listening { addr: a, backlog });
        Ok(())
    }

    /// `accept`: waits for a connection and returns it with the peer's
    /// address.
    pub fn accept(&self, nonblock: bool, wait: bool) -> Result<(SocketFile, SocketAddrV4), Errno> {
        let ready = |s: &SocketSet, h: SocketHandle| {
            !matches!(s.get::<TcpSocket>(h).state(), TcpState::Listen | TcpState::SynReceived)
        };
        let deadline = self.net.deadline(self.rcv_timeout.load(Ordering::Relaxed));
        loop {
            // Claim a connection under the socket's lock, against the live
            // backlog, so two concurrent accepts never take the same slot.
            // (The order is kind, then net, as in `connect`.)
            let (taken, snapshot) = {
                let mut kind = self.kind.lock();
                let Kind::Tcp(Tcp::Listening { addr, backlog }) = &mut *kind else { return Err(Errno::EINVAL) };
                let addr = *addr;
                let taken = self.net.op(|_, s| {
                    let i = backlog.iter().position(|h| h.is_some_and(|h| ready(s, h)))?;
                    let h = backlog.get(i).copied().flatten()?;
                    let mut t = TcpSocket::new(TCP_BUFFER, TCP_BUFFER);
                    // The replacement is one more listener of the same socket.
                    let (reuse, group) = {
                        let old = s.get::<TcpSocket>(h);
                        (old.reuse(), old.reuse_group())
                    };
                    t.set_reuse(reuse);
                    t.set_reuse_group(group);
                    if let Err(e) = t.listen_on(addr) {
                        return Some(Err(net_errno(e)));
                    }
                    // Without a socket to replace it, the connection stays
                    // in the backlog for a later accept.
                    let fresh = match s.try_add(t) {
                        Ok(fresh) => fresh,
                        Err(e) => return Some(Err(net_errno(e))),
                    };
                    let peer = v4(s.get::<TcpSocket>(h).remote_endpoint());
                    if let Some(slot) = backlog.get_mut(i) {
                        *slot = Some(fresh);
                    }
                    Some(Ok((h, peer)))
                });
                (taken, *backlog)
            };
            if let Some(taken) = taken {
                let (h, peer) = taken?;
                return Ok((Self::new(self.net.clone(), Kind::Tcp(Tcp::Connected(h)), nonblock), peer));
            }
            if !wait {
                return Err(Errno::EAGAIN);
            }
            // The snapshot only decides when to wake; the claim above rechecks.
            if !self.net.wait(deadline, |s| snapshot.iter().flatten().any(|&h| ready(s, h)))? {
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
                if !to.ip().is_loopback() && self.net.peek(|i, _| i.config()).is_none() {
                    return Err(Errno::ENETUNREACH);
                }
                let port = bound.map_or(0, |a| a.port());
                let h = self.net.op(|_, s| {
                    let mut t = TcpSocket::new(TCP_BUFFER, TCP_BUFFER);
                    // A connection keeps the options, which decide whether a
                    // bind may take its port while it lingers.
                    t.set_reuse(self.reuse());
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
            self.net.wait(None, |s| s.get::<TcpSocket>(h).state() != TcpState::SynSent)?;
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
            let r = self.net.op(|_, s| s.get_mut::<TcpSocket>(h).send(data.get(done..).unwrap_or_default()));
            match r {
                Ok(n) => done += n,
                Err(Error::WouldBlock) if done > 0 => return Ok(done),
                Err(Error::WouldBlock) if !wait => return Err(Errno::EAGAIN),
                Err(Error::WouldBlock) => {
                    let ready = |s: &SocketSet| {
                        let t = s.get::<TcpSocket>(h);
                        t.can_send() || !t.may_send()
                    };
                    if !self.net.wait(deadline, ready)? {
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
                Err(Error::WouldBlock) if wait && self.net.wait(deadline, |s| s.get::<UdpSocket>(h).can_send())? => {}
                Err(e) => return Err(net_errno(e)),
            }
        }
    }

    /// `recv`/`recvfrom`: returns the bytes copied and the sender (for
    /// datagrams).
    pub fn recv(&self, buf: &mut [u8], flags: u64) -> Result<(usize, Option<SocketAddrV4>), Errno> {
        self.recv_full(buf, flags).map(|r| (r.copied, r.from))
    }

    /// [`recv`](Self::recv) that also reports truncation. `MSG_PEEK` leaves
    /// the data queued.
    fn recv_full(&self, buf: &mut [u8], flags: u64) -> Result<Received, Errno> {
        let wait = self.wait_mode(flags);
        let peek = flags & MSG_PEEK != 0;
        let udp = match &*self.kind.lock() {
            Kind::Udp { handle, peer } => Some((*handle, *peer)),
            _ => None,
        };
        let deadline = self.net.deadline(self.rcv_timeout.load(Ordering::Relaxed));
        if let Some((h, peer)) = udp {
            loop {
                let got = if peek {
                    self.net.peek(|_, s| s.get::<UdpSocket>(h).peek_from(buf))
                } else {
                    self.net.op(|_, s| s.get_mut::<UdpSocket>(h).recv_from(buf))
                };
                match got {
                    Ok((_, from)) if peer.is_some_and(|p| SocketAddr::V4(p) != from) => {
                        // Not from our peer: dropped, even when only peeking.
                        if peek {
                            let _ = self.net.op(|_, s| s.get_mut::<UdpSocket>(h).recv_from(&mut []));
                        }
                    }
                    Ok((full, from)) => {
                        let copied = full.min(buf.len());
                        return Ok(Received { copied, truncated: full > copied, from: Some(v4(from)) });
                    }
                    Err(Error::WouldBlock)
                        if wait && self.net.wait(deadline, |s| s.get::<UdpSocket>(h).can_recv())? => {}
                    Err(e) => return Err(net_errno(e)),
                }
            }
        }
        let h = self.tcp_handle()?;
        loop {
            let got = if peek {
                self.net.peek(|_, s| s.get::<TcpSocket>(h).peek(buf))
            } else {
                self.net.op(|_, s| s.get_mut::<TcpSocket>(h).recv(buf))
            };
            match got {
                Ok(n) => return Ok(Received { copied: n, truncated: false, from: None }),
                Err(Error::WouldBlock) if wait && self.net.wait(deadline, |s| readable(s.get::<TcpSocket>(h)))? => {}
                Err(Error::InvalidState) => return Err(Errno::ENOTCONN),
                Err(e) => return Err(net_errno(e)),
            }
        }
    }

    /// Which `poll` conditions hold.
    fn readiness(&self) -> u32 {
        let kind = self.kind.lock();
        self.net.peek(|_, s| match &*kind {
            Kind::Tcp(Tcp::Unconnected(_)) => POLLOUT | POLLHUP,
            Kind::Tcp(Tcp::Listening { backlog, .. }) => {
                let up = backlog
                    .iter()
                    .flatten()
                    .any(|&h| !matches!(s.get::<TcpSocket>(h).state(), TcpState::Listen | TcpState::SynReceived));
                if up { POLLIN } else { 0 }
            }
            Kind::Tcp(Tcp::Connected(h)) => {
                let t = s.get::<TcpSocket>(*h);
                let state = t.state();
                let mut m = 0;
                if readable(t) {
                    m |= POLLIN;
                }
                if state != TcpState::SynSent && (t.can_send() || !t.may_send()) {
                    m |= POLLOUT;
                }
                if t.error().is_some() {
                    m |= POLLERR;
                }
                if matches!(state, TcpState::CloseWait | TcpState::Closing | TcpState::LastAck | TcpState::TimeWait) {
                    m |= POLLRDHUP;
                }
                if state == TcpState::Closed {
                    m |= POLLRDHUP | POLLHUP;
                }
                m
            }
            Kind::Udp { handle, .. } => {
                let u = s.get::<UdpSocket>(*handle);
                (if u.can_recv() { POLLIN } else { 0 }) | (if u.can_send() { POLLOUT } else { 0 })
            }
        })
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

    /// Sets `SO_REUSEPORT` (`port`) or `SO_REUSEADDR`. As on Linux they matter
    /// to the binds made afterwards; a datagram socket that is bound already
    /// takes the change at once, as its options live in the stack.
    fn set_reuse_option(&self, port: bool, on: bool) {
        if port { &self.reuse_port } else { &self.reuse_addr }.store(on, Ordering::Relaxed);
        let reuse = self.reuse();
        if let Kind::Udp { handle, .. } = &*self.kind.lock() {
            let h = *handle;
            self.net.op(|_, s| s.get_mut::<UdpSocket>(h).set_reuse(reuse));
        }
    }

    /// The value of `SO_REUSEPORT` (`port`) or `SO_REUSEADDR`.
    fn reuse_option(&self, port: bool) -> bool {
        if port { &self.reuse_port } else { &self.reuse_addr }.load(Ordering::Relaxed)
    }

    /// The local address, `getsockname`.
    pub fn local_addr(&self) -> SocketAddrV4 {
        let a = match &*self.kind.lock() {
            Kind::Tcp(Tcp::Unconnected(b)) => b.unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            Kind::Tcp(Tcp::Listening { addr, .. }) => *addr,
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
                self.net.op(|_, s| drop(s.try_remove(handle)));
            }
            Kind::Tcp(Tcp::Connected(h)) => self.net.release_tcp(h, false),
            Kind::Tcp(Tcp::Listening { backlog, .. }) => {
                for h in backlog.into_iter().flatten() {
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

    fn poll(&self) -> u32 {
        self.readiness()
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }
}

/// Whether `file` is a socket in non-blocking mode (for `F_GETFL`).
pub(crate) fn status_flags(file: &Arc<dyn File>) -> u64 {
    let any = file.as_any();
    let inet = any.and_then(|a| a.downcast_ref::<SocketFile>()).is_some_and(SocketFile::is_nonblocking);
    let unix = any.and_then(|a| a.downcast_ref::<UnixSocket>()).is_some_and(UnixSocket::is_nonblocking);
    if inet || unix { O_NONBLOCK } else { 0 }
}

/// Applies `F_SETFL` to a socket; other files have no flags to change.
pub(crate) fn set_status_flags(file: &Arc<dyn File>, flags: u64) {
    if let Some(s) = file.as_any().and_then(|a| a.downcast_ref::<SocketFile>()) {
        s.set_nonblocking(flags & O_NONBLOCK != 0);
    }
    if let Some(s) = file.as_any().and_then(|a| a.downcast_ref::<UnixSocket>()) {
        s.set_nonblocking(flags & O_NONBLOCK != 0);
    }
}

/// An `AF_INET` socket, for the calls only those have (`bind`, `connect`...).
fn sock(of: &Arc<OpenFile>) -> Result<&SocketFile, Errno> {
    let any = of.file().as_any();
    match any.and_then(|a| a.downcast_ref::<SocketFile>()) {
        Some(s) => Ok(s),
        None if any.is_some_and(|a| a.is::<UnixSocket>()) => Err(Errno::EOPNOTSUPP),
        None => Err(Errno::ENOTSOCK),
    }
}

/// Either kind of socket, for the calls both have.
enum Any<'sock> {
    Inet(&'sock SocketFile),
    Unix(&'sock UnixSocket),
}

fn any(of: &Arc<OpenFile>) -> Result<Any<'_>, Errno> {
    if let Some(u) = of.file().as_any().and_then(|a| a.downcast_ref::<UnixSocket>()) {
        return Ok(Any::Unix(u));
    }
    sock(of).map(Any::Inet)
}

impl Any<'_> {
    fn is_dgram(&self) -> bool {
        match self {
            Any::Inet(s) => s.type_code() == SOCK_DGRAM,
            Any::Unix(u) => u.is_dgram(),
        }
    }

    fn type_code(&self) -> u64 {
        if self.is_dgram() { SOCK_DGRAM } else { SOCK_STREAM }
    }

    fn send(&self, data: &[u8], to: Option<SocketAddrV4>, flags: u64) -> Result<usize, Errno> {
        match self {
            Any::Inet(s) => s.send(data, to, flags),
            Any::Unix(_) if to.is_some() => Err(Errno::EISCONN),
            Any::Unix(u) => u.send(data, !u.is_nonblocking() && flags & MSG_DONTWAIT == 0),
        }
    }

    fn recv(&self, buf: &mut [u8], flags: u64) -> Result<Received, Errno> {
        match self {
            Any::Inet(s) => s.recv_full(buf, flags),
            Any::Unix(u) => {
                let wait = !u.is_nonblocking() && flags & MSG_DONTWAIT == 0;
                let r = u.recv(buf, flags & MSG_PEEK != 0, wait)?;
                Ok(Received { copied: r.copied, truncated: r.truncated, from: None })
            }
        }
    }
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
    if u64::from(bytes::u16_at(&b, 0)?) != AF_INET {
        return Err(Errno::EAFNOSUPPORT);
    }
    let [_, _, p0, p1, a0, a1, a2, a3, ..] = b;
    Ok(SocketAddrV4::new(Ipv4Addr::new(a0, a1, a2, a3), u16::from_be_bytes([p0, p1])))
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
    bytes::put(&mut b, 0, &(AF_INET as u16).to_ne_bytes())?;
    bytes::put(&mut b, 2, &a.port().to_be_bytes())?;
    bytes::put(&mut b, 4, &a.ip().octets())?;
    let n = (u32::from_ne_bytes(cap) as usize).min(SOCKADDR_LEN);
    p.memory().write(va, bytes::slice(&b, 0, n)?)?;
    p.memory().write(lenp, &(SOCKADDR_LEN as u32).to_ne_bytes())
}

pub(crate) fn socket(p: &Process, domain: u64, ty: u64, protocol: u64) -> SysResult {
    if domain != AF_INET {
        return Err(Errno::EAFNOSUPPORT);
    }
    let net = stack().ok_or(Errno::EAFNOSUPPORT)?.clone();
    let file = match (ty & 0xf, protocol) {
        (SOCK_STREAM, 0 | IPPROTO_TCP) => SocketFile::stream(net),
        (SOCK_DGRAM, 0 | IPPROTO_UDP) => SocketFile::datagram(net)?,
        (SOCK_STREAM | SOCK_DGRAM, _) => return Err(Errno::EPROTONOSUPPORT),
        _ => return Err(Errno::EPROTOTYPE),
    };
    file.set_nonblocking(ty & SOCK_NONBLOCK != 0);
    let file = try_arc(file).map_err(oom)?;
    let open = OpenFile::try_new(file, Access::RW)?;
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
    let conn = try_arc(conn).map_err(oom)?;
    let open = OpenFile::try_new(conn, Access::RW)?;
    p.files().lock().insert_from(0, open, flags & SOCK_CLOEXEC != 0).map(|fd| fd as u64)
}

pub(crate) fn connect(p: &Process, fd: i32, addr: u64, len: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = sock(&of)?;
    s.connect(get_addr(p, addr, len)?).map(|()| 0)
}

pub(crate) fn sendto(p: &Process, fd: i32, buf: u64, len: u64, flags: u64, addr: u64, alen: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = any(&of)?;
    if addr != 0 && matches!(s, Any::Unix(_)) {
        return Err(Errno::EISCONN);
    }
    let to = if addr != 0 { Some(get_addr(p, addr, alen)?) } else { None };
    let n = len as usize;
    if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    if n > IO_MAX && s.is_dgram() {
        return Err(Errno::EMSGSIZE);
    }
    let mut data = try_zeroed(n.min(IO_MAX)).map_err(oom)?;
    p.memory().read(buf, &mut data)?;
    s.send(&data, to, flags).map(|n| n as u64)
}

/// Writes the address `recvfrom` and `recvmsg` report: the sender, or a zero
/// length for a socket with no addresses.
fn put_from(p: &Process, addr: u64, lenp: u64, from: Option<SocketAddrV4>) -> Result<(), Errno> {
    match from {
        Some(from) => put_addr(p, addr, lenp, from),
        None if addr != 0 && lenp != 0 => p.memory().write(lenp, &0u32.to_ne_bytes()),
        None => Ok(()),
    }
}

pub(crate) fn recvfrom(p: &Process, fd: i32, buf: u64, len: u64, flags: u64, addr: u64, lenp: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = any(&of)?;
    if flags & !(MSG_DONTWAIT | MSG_PEEK) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut data = try_zeroed((len as usize).min(IO_MAX)).map_err(oom)?;
    let r = s.recv(&mut data, flags)?;
    p.memory().write(buf, bytes::slice(&data, 0, r.copied)?)?;
    put_from(p, addr, lenp, r.from)?;
    Ok(r.copied as u64)
}

/// The `struct iovec` array of `count` entries at `iov`, and the sum of their
/// lengths.
fn read_iov(p: &Process, iov: u64, count: u64) -> Result<(Vec<(u64, usize)>, usize), Errno> {
    if count > IOV_MAX {
        return Err(Errno::EMSGSIZE);
    }
    let mut v = Vec::new();
    v.try_reserve_exact(count as usize).map_err(|_| Errno::ENOMEM)?;
    let mut total = 0usize;
    for i in 0..count {
        let at = i.checked_mul(16).and_then(|o| iov.checked_add(o)).ok_or(Errno::EFAULT)?;
        let mut b = [0u8; 16];
        p.memory().read(at, &mut b)?;
        let base = bytes::u64_at(&b, 0)?;
        let len = bytes::u64_at(&b, 8)?;
        let len = usize::try_from(len).map_err(|_| Errno::EINVAL)?;
        total = total.checked_add(len).filter(|&t| t <= isize::MAX as usize).ok_or(Errno::EINVAL)?;
        v.push((base, len));
    }
    Ok((v, total))
}

/// The fields of a `struct msghdr` that are used.
struct MsgHdr {
    name: u64,
    iov: u64,
    iovlen: u64,
    controllen: u64,
}

fn read_msghdr(p: &Process, msg: u64) -> Result<MsgHdr, Errno> {
    let mut b = [0u8; MSGHDR_LEN];
    p.memory().read(msg, &mut b)?;
    Ok(MsgHdr {
        name: bytes::u64_at(&b, 0)?,
        iov: bytes::u64_at(&b, 16)?,
        iovlen: bytes::u64_at(&b, 24)?,
        controllen: bytes::u64_at(&b, 40)?,
    })
}

pub(crate) fn sendmsg(p: &Process, fd: i32, msg: u64, flags: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = any(&of)?;
    let h = read_msghdr(p, msg)?;
    if flags & !(MSG_DONTWAIT | MSG_NOSIGNAL) != 0 || h.controllen != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut namelen = [0u8; 4];
    p.memory().read(msg.checked_add(8).ok_or(Errno::EFAULT)?, &mut namelen)?;
    let to = if h.name != 0 {
        if matches!(s, Any::Unix(_)) {
            return Err(Errno::EISCONN);
        }
        Some(get_addr(p, h.name, u64::from(u32::from_ne_bytes(namelen)))?)
    } else {
        None
    };
    let (iov, total) = read_iov(p, h.iov, h.iovlen)?;
    if total > IO_MAX && s.is_dgram() {
        return Err(Errno::EMSGSIZE);
    }
    // Gather the pieces into one buffer, so a datagram goes out whole.
    let mut data = try_zeroed(total.min(IO_MAX)).map_err(oom)?;
    let mut at = 0;
    for (base, len) in iov {
        let take = len.min(data.len().saturating_sub(at));
        if take > 0 {
            p.memory().read(base, bytes::slice_mut(&mut data, at, take)?)?;
            at += take;
        }
    }
    s.send(&data, to, flags).map(|n| n as u64)
}

pub(crate) fn recvmsg(p: &Process, fd: i32, msg: u64, flags: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = any(&of)?;
    let h = read_msghdr(p, msg)?;
    if flags & !(MSG_DONTWAIT | MSG_PEEK) != 0 {
        return Err(Errno::EOPNOTSUPP);
    }
    let (iov, total) = read_iov(p, h.iov, h.iovlen)?;
    let mut data = try_zeroed(total.min(IO_MAX)).map_err(oom)?;
    let r = s.recv(&mut data, flags)?;
    // Scatter what arrived over the buffers, in order.
    let mut at = 0;
    for (base, len) in iov {
        let take = len.min(r.copied.saturating_sub(at));
        if take > 0 {
            p.memory().write(base, bytes::slice(&data, at, take)?)?;
            at += take;
        }
    }
    let namelen_at = msg.checked_add(8).ok_or(Errno::EFAULT)?;
    put_from(p, h.name, namelen_at, r.from)?;
    // No ancillary data is ever returned.
    p.memory().write(msg.checked_add(40).ok_or(Errno::EFAULT)?, &0u64.to_ne_bytes())?;
    let flags_out = if r.truncated { MSG_TRUNC as u32 } else { 0 };
    p.memory().write(msg.checked_add(48).ok_or(Errno::EFAULT)?, &flags_out.to_ne_bytes())?;
    Ok(r.copied as u64)
}

pub(crate) fn socketpair(p: &Process, domain: u64, ty: u64, protocol: u64, sv: u64) -> SysResult {
    if domain != AF_UNIX {
        return Err(Errno::EAFNOSUPPORT);
    }
    if ty & !(0xf | SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        return Err(Errno::EINVAL);
    }
    let dgram = match ty & 0xf {
        SOCK_STREAM => false,
        SOCK_DGRAM => true,
        _ => return Err(Errno::EPROTOTYPE),
    };
    if protocol != 0 {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let (a, b) = unix::socketpair(dgram, ty & SOCK_NONBLOCK != 0)?;
    let (a, b) = (try_arc(a).map_err(oom)?, try_arc(b).map_err(oom)?);
    let (a, b) = (OpenFile::try_new(a, Access::RW)?, OpenFile::try_new(b, Access::RW)?);
    let cloexec = ty & SOCK_CLOEXEC != 0;
    let (fa, fb) = {
        let mut files = p.files().lock();
        let fa = files.insert_from(0, a, cloexec)?;
        match files.insert_from(0, b, cloexec) {
            Ok(fb) => (fa, fb),
            Err(e) => {
                let _ = files.close(fa);
                return Err(e);
            }
        }
    };
    let mut out = [0u8; 8];
    let filled = bytes::put(&mut out, 0, &fa.to_ne_bytes()).and_then(|()| bytes::put(&mut out, 4, &fb.to_ne_bytes()));
    if let Err(e) = filled.and_then(|()| p.memory().write(sv, &out)) {
        let mut files = p.files().lock();
        let _ = files.close(fa);
        let _ = files.close(fb);
        return Err(e);
    }
    Ok(0)
}

pub(crate) fn shutdown(p: &Process, fd: i32, how: u64) -> SysResult {
    let of = open(p, fd)?;
    match any(&of)? {
        Any::Inet(s) => s.shutdown(how),
        Any::Unix(u) => u.shutdown(how),
    }
    .map(|()| 0)
}

/// Writes an unnamed `AF_UNIX` address (just the family), as `socketpair`
/// ends have.
fn put_unix_addr(p: &Process, va: u64, lenp: u64) -> Result<(), Errno> {
    if va == 0 {
        return Ok(());
    }
    let mut cap = [0u8; 4];
    p.memory().read(lenp, &mut cap)?;
    let n = (u32::from_ne_bytes(cap) as usize).min(2);
    p.memory().write(va, bytes::slice(&(AF_UNIX as u16).to_ne_bytes(), 0, n)?)?;
    p.memory().write(lenp, &2u32.to_ne_bytes())
}

pub(crate) fn getsockname(p: &Process, fd: i32, addr: u64, lenp: u64) -> SysResult {
    let of = open(p, fd)?;
    match any(&of)? {
        Any::Inet(s) => put_addr(p, addr, lenp, s.local_addr()),
        Any::Unix(_) => put_unix_addr(p, addr, lenp),
    }
    .map(|()| 0)
}

pub(crate) fn getpeername(p: &Process, fd: i32, addr: u64, lenp: u64) -> SysResult {
    let of = open(p, fd)?;
    match any(&of)? {
        Any::Inet(s) => put_addr(p, addr, lenp, s.peer_addr()?),
        Any::Unix(_) => put_unix_addr(p, addr, lenp),
    }
    .map(|()| 0)
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
    let s = any(&of)?;
    if level == SOL_SOCKET && matches!(name, SO_RCVTIMEO | SO_SNDTIMEO) {
        // struct timeval { time_t sec; suseconds_t usec; }
        if len < 16 {
            return Err(Errno::EINVAL);
        }
        let mut tv = [0u8; 16];
        p.memory().read(val, &mut tv)?;
        let sec = bytes::u64_at(&tv, 0)?;
        let usec = bytes::u64_at(&tv, 8)?;
        if usec >= 1_000_000 || sec > u64::MAX / 2_000_000_000 {
            return Err(Errno::EINVAL);
        }
        let ns = sec * 1_000_000_000 + usec * 1000;
        // Socket pairs accept timeouts and ignore them.
        if let Any::Inet(s) = s {
            let timeout = if name == SO_RCVTIMEO { &s.rcv_timeout } else { &s.snd_timeout };
            timeout.store(ns, Ordering::Relaxed);
        }
        return Ok(0);
    }
    if !known_option(level, name) {
        return Err(Errno::ENOPROTOOPT);
    }
    if len < 4 {
        return Err(Errno::EINVAL);
    }
    let mut word = [0u8; 4];
    p.memory().read(val, &mut word)?;
    if level == SOL_SOCKET
        && matches!(name, SO_REUSEADDR | SO_REUSEPORT)
        && let Any::Inet(s) = s
    {
        s.set_reuse_option(name == SO_REUSEPORT, u32::from_ne_bytes(word) != 0);
    }
    Ok(0)
}

pub(crate) fn getsockopt(p: &Process, fd: i32, level: u64, name: u64, val: u64, lenp: u64) -> SysResult {
    let of = open(p, fd)?;
    let s = any(&of)?;
    let v: i32 = match (level, name) {
        (SOL_SOCKET, SO_TYPE) => s.type_code() as i32,
        (SOL_SOCKET, SO_ERROR) => match &s {
            Any::Inet(s) => s.pending_error(),
            Any::Unix(_) => 0,
        },
        (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF) => TCP_BUFFER as i32,
        (SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT) => match &s {
            Any::Inet(s) => i32::from(s.reuse_option(name == SO_REUSEPORT)),
            Any::Unix(_) => 0,
        },
        _ if known_option(level, name) => 0,
        _ => return Err(Errno::ENOPROTOOPT),
    };
    let mut cap = [0u8; 4];
    p.memory().read(lenp, &mut cap)?;
    let n = (u32::from_ne_bytes(cap) as usize).min(4);
    p.memory().write(val, bytes::slice(&v.to_ne_bytes(), 0, n)?)?;
    p.memory().write(lenp, &4u32.to_ne_bytes())?;
    Ok(0)
}
