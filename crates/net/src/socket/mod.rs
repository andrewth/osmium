//! Sockets and the set an interface serves.

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use osmium_hal::net::MacAddress;

use crate::rng::Rng;
use crate::{Error, Instant};

pub mod dhcp;
pub mod dns;
pub mod icmp;
pub mod tcp;
pub mod udp;

use dhcp::DhcpClient;
use icmp::IcmpSocket;
use tcp::TcpSocket;
use udp::UdpSocket;

/// What a socket sees of the interface while it is processed or asked for
/// packets.
pub(crate) struct Cx<'cx> {
    pub(crate) now: Instant,
    /// The interface's address, once configured.
    pub(crate) addr: Option<Ipv4Addr>,
    /// The interface's usable global IPv6 address, if it has one.
    pub(crate) addr6: Option<Ipv6Addr>,
    /// The interface's usable link-local IPv6 address.
    pub(crate) link_local6: Option<Ipv6Addr>,
    pub(crate) mac: MacAddress,
    /// The TCP maximum segment size the interface's MTU allows over IPv4.
    pub(crate) mss: u16,
    /// The same over IPv6.
    pub(crate) mss6: u16,
    /// What the path MTU cache has learned, if the caller keeps one.
    pub(crate) pmtu: Option<&'cx crate::pmtu::PathMtuCache>,
    pub(crate) rng: &'cx mut Rng,
}

impl Cx<'_> {
    /// The address of the interface a packet to `dst` leaves from. For IPv6
    /// a link-local destination (or multicast) is answered from the
    /// link-local address and anything else from the global one.
    pub(crate) fn source_for(&self, dst: IpAddr) -> Option<IpAddr> {
        match dst {
            IpAddr::V4(_) => self.addr.map(IpAddr::V4),
            IpAddr::V6(d) if crate::ipv6::is_link_local(d) || d.is_multicast() => self.link_local6.map(IpAddr::V6),
            IpAddr::V6(_) => self.addr6.or(self.link_local6).map(IpAddr::V6),
        }
    }

    /// The TCP maximum segment size for a connection to `remote`: the
    /// interface's, or less if a router has reported a smaller path MTU.
    pub(crate) fn mss_for(&self, remote: &SocketAddr) -> u16 {
        let link = if remote.is_ipv6() { self.mss6 } else { self.mss };
        let overhead = if remote.is_ipv6() { crate::ipv6::IPV6_HEADER_LEN } else { crate::wire::IPV4_HEADER_LEN }
            + crate::wire::TCP_HEADER_LEN;
        match self.pmtu.and_then(|c| c.lookup(remote.ip(), self.now)) {
            Some(mtu) => link.min(mtu.saturating_sub(overhead).clamp(1, usize::from(u16::MAX)) as u16),
            None => link,
        }
    }
}

/// An IP packet a socket wants sent; the interface adds the IP and
/// Ethernet headers. The two addresses are of one family.
pub(crate) struct Packet {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) protocol: u8,
    /// The transport header and payload, checksum included.
    pub(crate) payload: Vec<u8>,
}

/// Any socket.
#[allow(clippy::large_enum_variant)] // the variants are public and not boxed
pub enum Socket {
    /// A TCP connection or listener.
    Tcp(TcpSocket),
    /// A UDP socket.
    Udp(UdpSocket),
    /// An ICMP echo (ping) socket.
    Icmp(IcmpSocket),
    /// A DHCP client.
    Dhcp(DhcpClient),
}

impl Socket {
    fn poll_at(&self) -> Option<Instant> {
        match self {
            Socket::Tcp(s) => s.poll_at(),
            Socket::Udp(s) => s.poll_at(),
            Socket::Icmp(s) => s.poll_at(),
            Socket::Dhcp(s) => s.poll_at(),
        }
    }

    /// The port a TCP or UDP socket is bound to, if it is bound.
    fn local_port(&self) -> Option<u16> {
        match self {
            Socket::Tcp(s) => Some(s.local_endpoint().port()).filter(|&p| p != 0),
            Socket::Udp(s) => s.local_endpoint().map(|a| a.port()),
            Socket::Icmp(_) | Socket::Dhcp(_) => None,
        }
    }

    pub(crate) fn dispatch(&mut self, cx: &mut Cx, out: &mut Vec<Packet>) {
        match self {
            Socket::Tcp(s) => s.dispatch(cx, out),
            Socket::Udp(s) => s.dispatch(cx, out),
            Socket::Icmp(s) => s.dispatch(cx, out),
            Socket::Dhcp(s) => s.dispatch(cx, out),
        }
    }
}

/// A socket type that can be looked up in a [`SocketSet`] by handle.
pub trait AnySocket: Sized + sealed::Sealed {
    /// Wraps the socket.
    fn upcast(self) -> Socket;
    /// The socket, if `s` is one of this type.
    fn downcast(s: &Socket) -> Option<&Self>;
    /// The socket, if `s` is one of this type.
    fn downcast_mut(s: &mut Socket) -> Option<&mut Self>;
    /// The socket, if `s` is one of this type.
    fn downcast_owned(s: Socket) -> Option<Self>;
}

mod sealed {
    pub trait Sealed {}
}

macro_rules! any_socket {
    ($ty:ty, $variant:ident) => {
        impl sealed::Sealed for $ty {}

        impl AnySocket for $ty {
            fn upcast(self) -> Socket {
                Socket::$variant(self)
            }

            fn downcast(s: &Socket) -> Option<&Self> {
                if let Socket::$variant(s) = s { Some(s) } else { None }
            }

            fn downcast_mut(s: &mut Socket) -> Option<&mut Self> {
                if let Socket::$variant(s) = s { Some(s) } else { None }
            }

            fn downcast_owned(s: Socket) -> Option<Self> {
                if let Socket::$variant(s) = s { Some(s) } else { None }
            }
        }
    };
}

any_socket!(TcpSocket, Tcp);
any_socket!(UdpSocket, Udp);
any_socket!(IcmpSocket, Icmp);
any_socket!(DhcpClient, Dhcp);

/// `SO_REUSEADDR` and `SO_REUSEPORT` of a socket, with the Linux meaning.
///
/// Two sockets of one protocol conflict when they are bound to the same
/// port and their addresses overlap (the same address, or either one
/// unspecified, in one address family). Overlapping sockets may coexist
/// when
///
/// * both have `addr` set, unless the other one is a listening TCP socket.
///   For TCP this lets a server bind a port that still has connections in
///   TIME-WAIT or ESTABLISHED (those sockets must have had `addr` set too,
///   as accepted connections inherit it), and a listener on a specific
///   address share the port with one on the wildcard address only if the
///   other does not listen. For UDP any two sockets that both have `addr`
///   set may share an address; a unicast datagram then goes to the
///   socket with the most specific address (the lowest handle among
///   equals, where Linux takes the newest), and broadcasts and multicasts
///   to all of them; or
/// * both have `port` set and the same `owner` (Linux requires an equal
///   effective uid). The sockets form a group: a TCP connection request or
///   a unicast UDP datagram goes to one of them, chosen by a hash of the
///   flow, so the packets of a flow always reach the same one. The choice
///   is among the sockets of the most specific matching address, so a
///   specific address still wins over the wildcard.
///
/// Both sockets must have set the option before they bind; one that did
/// not cannot be shared with later. The check is made by
/// [`SocketSet::bind_udp`] and [`SocketSet::listen_tcp`]. The sockets' own
/// `bind_addr` and `listen_on` do not look at other sockets.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReuseOptions {
    /// `SO_REUSEADDR`.
    pub addr: bool,
    /// `SO_REUSEPORT`.
    pub port: bool,
    /// Who owns the socket, for `SO_REUSEPORT`.
    pub owner: u32,
}

impl ReuseOptions {
    /// Neither option set.
    pub const NONE: Self = Self { addr: false, port: false, owner: 0 };
}

/// Which protocol a bind is for: TCP and UDP ports are separate spaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// Returns true if two bound addresses (of one protocol) overlap.
fn overlaps(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port()
        && a.is_ipv4() == b.is_ipv4()
        && (a.ip().is_unspecified() || b.ip().is_unspecified() || a.ip() == b.ip())
}

/// Whether a socket that binds may share its address with one that has it.
fn may_share(proto: BindProtocol, new: ReuseOptions, other: ReuseOptions, other_listening: bool) -> bool {
    (new.addr && other.addr && !(proto == BindProtocol::Tcp && other_listening))
        || (new.port && other.port && new.owner == other.owner)
}

/// A hash of a flow, the same for all its packets, that picks among the
/// sockets of a `SO_REUSEPORT` group (FNV-1a over both endpoints).
fn flow_hash(src: SocketAddr, dst: SocketAddr) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    let mut mix = |b: u8| {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    };
    for a in [src, dst] {
        match a.ip() {
            IpAddr::V4(ip) => ip.octets().into_iter().for_each(&mut mix),
            IpAddr::V6(ip) => ip.octets().into_iter().for_each(&mut mix),
        }
        a.port().to_be_bytes().into_iter().for_each(&mut mix);
    }
    // A last mix, so that ports that differ in the low bits spread.
    h ^= h >> 15;
    h = h.wrapping_mul(0x2c1b_3c6d);
    h ^= h >> 12;
    h
}

/// Identifies a socket in a [`SocketSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SocketHandle(usize);

/// The sockets an [`Interface`](crate::Interface) serves.
#[derive(Default)]
pub struct SocketSet {
    slots: Vec<Option<Socket>>,
}

impl SocketSet {
    /// An empty set.
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Adds a socket and returns its handle. Handles of removed sockets are
    /// reused.
    pub fn add(&mut self, socket: impl AnySocket) -> SocketHandle {
        let socket = Some(socket.upcast());
        if let Some((i, slot)) = self.slots.iter_mut().enumerate().find(|(_, s)| s.is_none()) {
            *slot = socket;
            SocketHandle(i)
        } else {
            self.slots.push(socket);
            SocketHandle(self.slots.len() - 1)
        }
    }

    /// [`add`](Self::add), failing with [`Error::OutOfMemory`] instead of
    /// panicking. The set is unchanged on failure.
    pub fn try_add(&mut self, socket: impl AnySocket) -> Result<SocketHandle, Error> {
        let socket = Some(socket.upcast());
        if let Some((i, slot)) = self.slots.iter_mut().enumerate().find(|(_, s)| s.is_none()) {
            *slot = socket;
            return Ok(SocketHandle(i));
        }
        self.slots.try_reserve(1).map_err(|_| Error::OutOfMemory)?;
        self.slots.push(socket);
        Ok(SocketHandle(self.slots.len() - 1))
    }

    /// The socket `handle` names, or `None` if the handle was removed or
    /// names a socket of another type.
    pub fn try_get<T: AnySocket>(&self, handle: SocketHandle) -> Option<&T> {
        self.slots.get(handle.0).and_then(Option::as_ref).and_then(T::downcast)
    }

    /// The socket `handle` names, or `None` if the handle was removed or
    /// names a socket of another type.
    pub fn try_get_mut<T: AnySocket>(&mut self, handle: SocketHandle) -> Option<&mut T> {
        self.slots.get_mut(handle.0).and_then(Option::as_mut).and_then(T::downcast_mut)
    }

    /// Removes the socket `handle` names and returns it, or `None` if it was
    /// already removed.
    pub fn try_remove(&mut self, handle: SocketHandle) -> Option<Socket> {
        self.slots.get_mut(handle.0).and_then(Option::take)
    }

    /// The socket `handle` names.
    ///
    /// # Panics
    ///
    /// If the handle was removed or names a socket of another type; that is
    /// a bug in the caller, as handles are not derived from external input.
    /// [`try_get`](Self::try_get) does not panic.
    #[allow(clippy::expect_used)] // invariant: the caller's own live handle
    pub fn get<T: AnySocket>(&self, handle: SocketHandle) -> &T {
        self.try_get(handle).expect("no socket of that type")
    }

    /// The socket `handle` names.
    ///
    /// # Panics
    ///
    /// If the handle was removed or names a socket of another type; see
    /// [`get`](Self::get). [`try_get_mut`](Self::try_get_mut) does not panic.
    #[allow(clippy::expect_used)] // invariant: the caller's own live handle
    pub fn get_mut<T: AnySocket>(&mut self, handle: SocketHandle) -> &mut T {
        self.try_get_mut(handle).expect("no socket of that type")
    }

    /// Removes the socket `handle` names and returns it. A TCP connection
    /// that is removed while open simply goes silent; call
    /// [`TcpSocket::abort`] and poll first to reset it.
    ///
    /// # Panics
    ///
    /// If the handle was already removed (a caller bug);
    /// [`try_remove`](Self::try_remove) does not panic.
    #[allow(clippy::expect_used)] // invariant: the caller's own live handle
    pub fn remove(&mut self, handle: SocketHandle) -> Socket {
        self.try_remove(handle).expect("socket already removed")
    }

    /// Every socket, in handle order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket)> {
        self.slots.iter_mut().enumerate().filter_map(|(i, s)| Some((SocketHandle(i), s.as_mut()?)))
    }

    /// Every socket, in handle order.
    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &Socket)> {
        self.slots.iter().enumerate().filter_map(|(i, s)| Some((SocketHandle(i), s.as_ref()?)))
    }

    /// The earliest time any socket needs polling.
    pub(crate) fn poll_at(&self) -> Option<Instant> {
        self.iter().filter_map(|(_, s)| s.poll_at()).min()
    }

    /// Returns true if a TCP or UDP socket of the set is bound to `port`.
    pub(crate) fn port_in_use(&self, port: u16) -> bool {
        self.iter().any(|(_, s)| s.local_port() == Some(port))
    }

    /// Checks that a socket may bind `addr` with `reuse`, against every other socket of the set for `proto`
    /// except `except`; see [`ReuseOptions`] for the rules. TCP sockets in
    /// any state but closed, TIME-WAIT included, hold their address.
    pub fn check_bind(
        &self,
        proto: BindProtocol,
        addr: SocketAddr,
        reuse: ReuseOptions,
        except: Option<SocketHandle>,
    ) -> Result<(), Error> {
        if addr.port() == 0 {
            return Err(Error::InvalidAddress);
        }
        for (h, s) in self.iter() {
            if Some(h) == except {
                continue;
            }
            let (other, other_reuse, listening) = match (proto, s) {
                (BindProtocol::Tcp, Socket::Tcp(t)) => match t.bound() {
                    Some((a, l)) => (a, t.reuse(), l),
                    None => continue,
                },
                (BindProtocol::Udp, Socket::Udp(u)) => match u.local_endpoint() {
                    Some(a) => (a, u.reuse(), false),
                    None => continue,
                },
                _ => continue,
            };
            if overlaps(addr, other) && !may_share(proto, reuse, other_reuse, listening) {
                return Err(Error::AddressInUse);
            }
        }
        Ok(())
    }

    /// Binds the UDP socket `handle` to `addr` if no other socket holds it
    /// (see [`ReuseOptions`]), failing with [`Error::AddressInUse`] if one
    /// does. The socket's options are those of
    /// [`UdpSocket::set_reuse`].
    pub fn bind_udp(&mut self, handle: SocketHandle, addr: SocketAddr) -> Result<(), Error> {
        let reuse = self.try_get::<UdpSocket>(handle).ok_or(Error::InvalidState)?.reuse();
        self.check_bind(BindProtocol::Udp, addr, reuse, Some(handle))?;
        self.try_get_mut::<UdpSocket>(handle).ok_or(Error::InvalidState)?.bind_addr(addr)
    }

    /// Makes the TCP socket `handle` listen on `addr` if no other socket
    /// holds it (see [`ReuseOptions`]), failing with
    /// [`Error::AddressInUse`] if one does. The socket's options are those
    /// of [`TcpSocket::set_reuse`].
    pub fn listen_tcp(&mut self, handle: SocketHandle, addr: SocketAddr) -> Result<(), Error> {
        let reuse = self.try_get::<TcpSocket>(handle).ok_or(Error::InvalidState)?.reuse();
        self.check_bind(BindProtocol::Tcp, addr, reuse, Some(handle))?;
        self.try_get_mut::<TcpSocket>(handle).ok_or(Error::InvalidState)?.listen_on(addr)
    }

    /// The UDP sockets a datagram `src` -> `dst` goes to. A unicast one
    /// goes to a single socket: of those bound to `dst` exactly, if any,
    /// otherwise of those bound to the wildcard, and among several with
    /// `SO_REUSEPORT` the one the flow hashes to. Broadcasts and multicasts
    /// go to every socket that takes them.
    pub(crate) fn udp_targets(&self, src: SocketAddr, dst: SocketAddr) -> Vec<SocketHandle> {
        let mut all: Vec<(SocketHandle, bool, bool)> = Vec::new();
        for (h, s) in self.iter() {
            if let Socket::Udp(u) = s
                && u.accepts(dst)
            {
                let exact = u.local_endpoint().is_some_and(|l| l.ip() == dst.ip());
                all.push((h, exact, u.reuse().port));
            }
        }
        let many = match dst.ip() {
            IpAddr::V4(a) => a.is_broadcast() || a.is_multicast(),
            IpAddr::V6(a) => a.is_multicast(),
        };
        if many {
            return all.into_iter().map(|(h, ..)| h).collect();
        }
        let tier: Vec<_> = if all.iter().any(|c| c.1) { all.into_iter().filter(|c| c.1).collect() } else { all };
        let pick = match tier.as_slice() {
            [] => None,
            [only] => Some(only.0),
            many if many.iter().all(|c| c.2) => many.get(flow_hash(src, dst) as usize % many.len()).map(|c| c.0),
            [first, ..] => Some(first.0),
        };
        pick.into_iter().collect()
    }

    /// The listening TCP socket a SYN `src` -> `dst` goes to: of the
    /// listeners on `dst` exactly, if any, otherwise on the wildcard. When
    /// the candidates all have `SO_REUSEPORT`, the SYN is spread over their
    /// groups (see [`TcpSocket::set_reuse_group`]) by flow hash and goes to
    /// the first listener of the group it picks.
    pub(crate) fn tcp_listener(&self, src: SocketAddr, dst: SocketAddr) -> Option<SocketHandle> {
        let mut all: Vec<(SocketHandle, bool, &TcpSocket)> = Vec::new();
        for (h, s) in self.iter() {
            if let Socket::Tcp(t) = s
                && t.accepts_listen(dst)
            {
                all.push((h, t.local_endpoint().ip() == dst.ip(), t));
            }
        }
        let specific = all.iter().any(|c| c.1);
        all.retain(|c| c.1 == specific);
        let (first, rest) = all.split_first()?;
        if rest.is_empty() || !all.iter().all(|c| c.2.reuse().port) {
            return Some(first.0);
        }
        // A socket without a group is a group of one.
        let key = |c: &(SocketHandle, bool, &TcpSocket)| match c.2.reuse_group() {
            0 => (1u64 << 32) | c.0.0 as u64,
            g => u64::from(g),
        };
        let mut groups: Vec<(u64, SocketHandle)> = Vec::new();
        for c in &all {
            if !groups.iter().any(|g| g.0 == key(c)) {
                groups.push((key(c), c.0));
            }
        }
        groups.get(flow_hash(src, dst) as usize % groups.len()).map(|g| g.1)
    }

    /// A random ephemeral port that no socket of the set is bound to (or,
    /// should the range be crowded, the last one tried).
    pub(crate) fn free_ephemeral_port(&self, rng: &mut Rng) -> u16 {
        let mut port = rng.ephemeral_port();
        for _ in 0..64 {
            if !self.port_in_use(port) {
                break;
            }
            port = rng.ephemeral_port();
        }
        port
    }

    /// Gives each TCP connection that is waiting to send its SYN from an
    /// unchosen port a random one that is free.
    pub(crate) fn assign_ephemeral_ports(&mut self, rng: &mut Rng) {
        if !self.iter().any(|(_, s)| matches!(s, Socket::Tcp(t) if t.needs_port())) {
            return;
        }
        let mut used: Vec<u16> = self.iter().filter_map(|(_, s)| s.local_port()).collect();
        for (_, s) in self.iter_mut() {
            if let Socket::Tcp(t) = s
                && t.needs_port()
            {
                let mut port = rng.ephemeral_port();
                for _ in 0..64 {
                    if !used.contains(&port) {
                        break;
                    }
                    port = rng.ephemeral_port();
                }
                used.push(port);
                t.set_ephemeral_port(port);
            }
        }
    }
}

/// Returns true if a socket bound to `bound` takes traffic for `dst`: the
/// ports match, the address families match, and the address is either
/// unspecified or equal.
pub(crate) fn binds(bound: SocketAddr, dst: SocketAddr) -> bool {
    bound.port() == dst.port()
        && bound.is_ipv4() == dst.is_ipv4()
        && (bound.ip().is_unspecified() || bound.ip() == dst.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_ports_avoid_bound_ports() {
        let first = Rng::new(5).ephemeral_port();
        let mut set = SocketSet::new();
        let mut udp = UdpSocket::new(1, 1);
        udp.bind(first).unwrap();
        set.add(udp);
        assert!(set.port_in_use(first));
        let port = set.free_ephemeral_port(&mut Rng::new(5));
        assert_ne!(port, first);
        // A connection that waits for a port gets a free one, too.
        let mut tcp = TcpSocket::new(64, 64);
        tcp.connect(SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 80), 0).unwrap();
        let h = set.add(tcp);
        set.assign_ephemeral_ports(&mut Rng::new(5));
        let got = set.get::<TcpSocket>(h).local_endpoint().port();
        assert!(got >= 49152 && got != first);
    }
}
