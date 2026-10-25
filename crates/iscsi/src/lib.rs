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
//! ([`DigestPolicy`]) ask for CRC32C digests. Writes send immediate and
//! unsolicited data as `ImmediateData`, `InitialR2T` and `FirstBurstLength`
//! allow, and the rest in answer to R2Ts (one outstanding at a time).
//!
//! A target that answers a login with Target Moved Temporarily or
//! Permanently is followed to the address it names, a few times over
//! ([`IscsiDisk::portal`] says where the session ended up, and
//! [`IscsiDisk::moved_permanently`] whether to use that address from now on).
//!
//! [`Offer::max_connections`] asks for several connections in the session
//! (MC/S). Reads and writes larger than `MaxBurstLength` then run as
//! commands in parallel over the free connections: CmdSN numbers them as
//! one sequence, each connection keeps its own StatSN and ExpStatSN, and a
//! command's PDUs stay on the connection it was sent on.
//!
//! [`Offer::error_recovery_level`] asks to recover from failures instead of
//! dropping the session. At level 1 a Data-In, R2T or status that is lost or
//! fails its data digest is requested again (SNACK, including DataACK and
//! R-Data), a quiet connection is nudged (and a command the target never
//! acknowledged is sent again), and a command the target rejects for a digest
//! error is retried. At level 2 a lost connection is replaced by a new login
//! with the same CID, and each task that was on it is reassigned (TASK
//! REASSIGN) or, if the target never got the command, sent again. Level 0,
//! the default, drops the session on any failure.
//!
//! [`IscsiSession`] shares one session between the block devices of all of
//! a target's logical units (REPORT LUNS lists them, [`IscsiSession::disk`]
//! opens one).
//!
//! The PDU codec ([`pdu`]), text keys ([`text`]) and SCSI command set
//! ([`scsi`]) are usable on their own, e.g. to write a target.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod chap;
pub mod crc32c;
mod disk;
mod error;
pub mod md5;
mod net;
pub mod params;
pub mod pdu;
pub mod scsi;
mod session;
pub mod text;

#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_recovery;
#[cfg(test)]
mod tests_session;

pub use chap::{Chap, Mutual};
pub use disk::{IscsiDisk, IscsiSession};
pub use error::IscsiError;
pub use net::{Net, Stack};
pub use params::{DigestPolicy, Offer, Params};
pub use session::{Data, DiscoveredTarget, Options, discover};
