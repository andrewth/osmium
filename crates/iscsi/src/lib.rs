//! An iSCSI initiator (RFC 7143) over [`osmium_net`] TCP.
//!
//! [`IscsiDisk`] logs in to a target and presents one of its logical units
//! as a [`BlockDevice`](osmium_hal::block::BlockDevice); [`discover`] asks a
//! portal which targets it has. Both reach the network through [`Net`],
//! which polls the caller's [`Interface`](osmium_net::Interface) and lends
//! out the [`SocketSet`](osmium_net::SocketSet) their socket lives in:
//! like the stack itself, the initiator is polled and single-threaded, and
//! an operation blocks by pumping the network until the target answers.
//!
//! ```no_run
//! # use osmium_hal::net::NetDevice;
//! use osmium_hal::block::BlockDevice;
//! use osmium_iscsi::{IscsiDisk, Options, Stack};
//! use osmium_net::{Interface, Ipv4Addr, SocketAddrV4, SocketSet};
//!
//! fn disk(iface: &mut Interface, dev: &mut impl NetDevice, sockets: &mut SocketSet, now_ns: fn() -> u64) {
//!     let net = Stack { iface, dev, sockets, now_ns };
//!     let portal = SocketAddrV4::new(Ipv4Addr::new(10, 0, 2, 100), 3260);
//!     let opts = Options::new("iqn.2026-10.org.osmium:host", "iqn.2026-10.org.osmium:disk0");
//!     let mut disk = IscsiDisk::connect(net, portal, &opts).unwrap();
//!     let mut block = [0u8; 512];
//!     disk.read_blocks(0, &mut block).unwrap();
//! } // dropping the disk logs out
//! ```
//!
//! By default the session negotiates no authentication (AuthMethod=None)
//! and no digests. [`Options::chap`] ([`Chap`]) logs in with CHAP-MD5,
//! one-way or mutual, and [`Offer::header_digest`] / [`Offer::data_digest`]
//! ([`DigestPolicy`]) ask for CRC32C digests. It uses
//! error recovery level 0, one connection and one outstanding R2T, and
//! runs one command at a time. Writes send immediate and unsolicited data
//! as `ImmediateData`, `InitialR2T` and `FirstBurstLength` allow, and the
//! rest in answer to R2Ts.
//!
//! The PDU codec ([`pdu`]), text keys ([`text`]) and SCSI command set
//! ([`scsi`]) are usable on their own, e.g. to write a target.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod chap;
mod disk;
mod error;
mod net;
pub mod crc32c;
pub mod md5;
pub mod params;
pub mod pdu;
pub mod scsi;
mod session;
pub mod text;

#[cfg(test)]
mod testing;
#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod tests;

pub use disk::IscsiDisk;
pub use error::IscsiError;
pub use net::{Net, Stack};
pub use chap::{Chap, Mutual};
pub use params::{DigestPolicy, Offer, Params};
pub use session::{Data, DiscoveredTarget, Options, discover};
