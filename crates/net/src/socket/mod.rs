//! Sockets and the set an interface serves.

use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use osmium_hal::net::MacAddress;

use crate::Instant;
use crate::rng::Rng;

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

    /// The TCP maximum segment size for a connection to `remote`.
    pub(crate) fn mss_for(&self, remote: &SocketAddr) -> u16 {
        if remote.is_ipv6() { self.mss6 } else { self.mss }
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
        if let Some(i) = self.slots.iter().position(Option::is_none) {
            self.slots[i] = socket;
            SocketHandle(i)
        } else {
            self.slots.push(socket);
            SocketHandle(self.slots.len() - 1)
        }
    }

    /// The socket `handle` names.
    ///
    /// # Panics
    ///
    /// If the handle was removed or names a socket of another type.
    pub fn get<T: AnySocket>(&self, handle: SocketHandle) -> &T {
        self.slots.get(handle.0).and_then(Option::as_ref).and_then(T::downcast).expect("no socket of that type")
    }

    /// The socket `handle` names.
    ///
    /// # Panics
    ///
    /// If the handle was removed or names a socket of another type.
    pub fn get_mut<T: AnySocket>(&mut self, handle: SocketHandle) -> &mut T {
        self.slots.get_mut(handle.0).and_then(Option::as_mut).and_then(T::downcast_mut).expect("no socket of that type")
    }

    /// Removes the socket `handle` names and returns it. A TCP connection
    /// that is removed while open simply goes silent; call
    /// [`TcpSocket::abort`] and poll first to reset it.
    ///
    /// # Panics
    ///
    /// If the handle was already removed.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket {
        self.slots.get_mut(handle.0).and_then(Option::take).expect("socket already removed")
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
}

/// Returns true if a socket bound to `bound` takes traffic for `dst`: the
/// ports match, the address families match, and the address is either
/// unspecified or equal.
pub(crate) fn binds(bound: SocketAddr, dst: SocketAddr) -> bool {
    bound.port() == dst.port()
        && bound.is_ipv4() == dst.is_ipv4()
        && (bound.ip().is_unspecified() || bound.ip() == dst.ip())
}
