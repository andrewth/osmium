//! A polled IPv4 and IPv6 network stack over any [`NetDevice`].
//!
//! - [`Interface`]: one Ethernet interface with an IPv4 address and, once
//!   [`enable_ipv6`](Interface::enable_ipv6) is called, IPv6 addresses. It
//!   answers ARP, neighbor discovery and ICMP echo, resolves next hops, and
//!   moves packets between the device and the sockets each time it is polled.
//! - [`SocketSet`]: the sockets an interface serves, addressed by
//!   [`SocketHandle`]: [`TcpSocket`], [`UdpSocket`], [`IcmpSocket`] (ping)
//!   and [`DhcpClient`], which configures the interface from a DHCP lease.
//! - [`DnsClient`]: a resolver for IPv4 (`A`) and IPv6 (`AAAA`) addresses
//!   over a UDP socket, with retries and a cache.
//! - [`ipv6`]: the IPv6 and ICMPv6 packet formats, usable on their own.
//! - [`wire`]: the packet formats, usable on their own.
//!
//! The stack keeps no globals and never blocks or reads a clock: the caller
//! passes the time ([`Instant`]) to [`Interface::poll`] and decides when to
//! poll again, from a timer, a receive interrupt, or
//! [`Interface::poll_at`]. Locking is the caller's choice too; a kernel
//! typically wraps the interface, the device and the socket set in one lock.
//!
//! TCP reassembles out-of-order data, is congestion controlled (NewReno, or
//! RFC 6675 recovery with SACK), negotiates window scaling, and uses
//! timestamps (RFC 7323) for round-trip samples and protection against
//! wrapped sequence numbers. Fragmented IPv4 datagrams are reassembled, and
//! UDP and ICMP datagrams larger than the MTU are fragmented when sent. IP
//! options are checked and skipped ([`ipopt`]). An interface can join
//! multicast groups ([`Interface::join_multicast_group`]), reported with
//! IGMPv2 ([`igmp`]). The DNS client retries truncated answers over TCP.
//!
//! IPv6 runs beside IPv4 on one interface: a link-local address with
//! duplicate address detection, neighbor discovery instead of ARP, SLAAC from
//! router advertisements, and UDP, TCP and ICMPv6 echo. Sockets are v4 or v6
//! by the address they bind or connect to. IPv6 extension headers are walked
//! on receipt; IPv6 datagrams larger than the MTU are fragmented on send and
//! reassembled on receipt within bounded limits ([`frag6`]).
//!
//! Not supported: IP forwarding, IGMPv3 reports.
//!
//! [`NetDevice`]: osmium_hal::net::NetDevice
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod arp;
mod error;
pub mod frag6;
mod iface;
pub mod igmp;
pub mod ipopt;
pub mod ipv6;
mod rng;
mod socket;
mod time;
pub mod wire;

#[cfg(test)]
mod testing;
#[cfg(test)]
mod loopback_tests;

pub use error::Error;
pub use iface::{Config, Interface, Ipv6Address};
pub use socket::dhcp::{DhcpClient, DhcpEvent};
pub use socket::dns::{DnsClient, DnsError, DnsQuery};
pub use socket::icmp::{EchoReply, IcmpSocket};
pub use socket::tcp::{State as TcpState, TcpSocket};
pub use socket::udp::UdpSocket;
pub use socket::{AnySocket, Socket, SocketHandle, SocketSet};
pub use time::Instant;

pub use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
