//! A polled IPv4 network stack over any [`NetDevice`].
//!
//! - [`Interface`]: one Ethernet interface with an IPv4 address. It answers
//!   ARP and ICMP echo, resolves next hops, and moves packets between the
//!   device and the sockets each time it is polled.
//! - [`SocketSet`]: the sockets an interface serves, addressed by
//!   [`SocketHandle`]: [`TcpSocket`], [`UdpSocket`], [`IcmpSocket`] (ping)
//!   and [`DhcpClient`], which configures the interface from a DHCP lease.
//! - [`wire`]: the packet formats, usable on their own.
//!
//! The stack keeps no globals and never blocks or reads a clock: the caller
//! passes the time ([`Instant`]) to [`Interface::poll`] and decides when to
//! poll again, from a timer, a receive interrupt, or
//! [`Interface::poll_at`]. Locking is the caller's choice too; a kernel
//! typically wraps the interface, the device and the socket set in one lock.
//!
//! Not supported: IP fragmentation and reassembly (fragments are dropped and
//! packets are sent with DF set), IP options, TCP window scaling, SACK,
//! out-of-order reassembly (TCP drops out-of-order segments and lets the peer
//! retransmit), IPv6 and multicast.
//!
//! [`NetDevice`]: osmium_hal::net::NetDevice
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod arp;
mod error;
mod iface;
mod rng;
mod socket;
mod time;
pub mod wire;

#[cfg(test)]
mod testing;

pub use error::Error;
pub use iface::{Config, Interface};
pub use socket::dhcp::{DhcpClient, DhcpEvent};
pub use socket::icmp::{EchoReply, IcmpSocket};
pub use socket::tcp::{State as TcpState, TcpSocket};
pub use socket::udp::UdpSocket;
pub use socket::{AnySocket, Socket, SocketHandle, SocketSet};
pub use time::Instant;

pub use core::net::{Ipv4Addr, SocketAddrV4};
