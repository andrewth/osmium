//! TLS 1.3 servers for kernels and firmware, built on rustls.
//!
//! - [`provider`]: a rustls crypto provider with one cipher suite
//!   (ChaCha20-Poly1305 with SHA-256), one key exchange (X25519) and one
//!   signature scheme (ECDSA P-256), implemented in pure Rust by the
//!   RustCrypto crates and drawing its randomness from `osmium-rand`.
//! - [`server_config`]: a TLS 1.3-only rustls server configuration for one
//!   certificate chain and key.
//! - [`ServerSession`]: one connection, with no I/O of its own: bytes from the
//!   network go in, bytes for the network come out.
//! - [`cert`]: self-signed certificates for a server's first boot, and PEM.
//! - [`self_test`]: an in-memory handshake that checks the whole stack works
//!   on this machine, for running at boot.
//!
//! Needs `alloc`.
//!
//! # Example
//!
//! ```no_run
//! # use osmium_tls::*;
//! # use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
//! # #[derive(Debug)] struct Clock;
//! # impl rustls::time_provider::TimeProvider for Clock {
//! #     fn current_time(&self) -> Option<UnixTime> { Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_800_000_000))) }
//! # }
//! static RNG: osmium_rand::SharedRng = osmium_rand::SharedRng::new();
//! RNG.seed(&osmium_rand::CpuEntropy).expect("no entropy");
//!
//! let names = [cert::SubjectName::Dns("hyperon.local")];
//! let validity = cert::Validity { not_before: 1_800_000_000, not_after: 1_800_000_000 + 365 * 86_400 };
//! let id = cert::self_signed(&RNG, &names, validity).expect("certificate");
//! let config = server_config(
//!     shared_provider(&RNG),
//!     alloc::sync::Arc::new(Clock),
//!     vec![CertificateDer::from(id.cert_der.clone())],
//!     PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_pkcs8_der.clone())),
//! )
//! .expect("config");
//!
//! let mut tls = ServerSession::new(config).expect("session");
//! # let from_network: &[u8] = &[];
//! tls.receive(from_network).expect("TLS error");
//! // ...send tls.outgoing(), then call tls.sent(n); read() and write() application data.
//! # extern crate alloc;
//! ```
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod cert;
mod provider;
mod selftest;
mod session;
mod sign;

use alloc::sync::Arc;
use alloc::vec::Vec;

pub use provider::{SIGNATURE_ALGORITHMS, TLS13_CHACHA20_POLY1305_SHA256, provider, shared_provider};
pub use rustls;
pub use selftest::{FixedTime, self_test};
pub use session::{MAX_INCOMING, ServerSession};
pub use sign::{ECDSA_P256_SHA256, EcdsaSigningKey};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::time_provider::TimeProvider;
use rustls::{Error, ServerConfig};

/// A TLS 1.3-only server configuration presenting `cert_chain` (end-entity
/// certificate first) and signing with `key`, without client authentication.
///
/// `time` supplies the wall-clock time, which rustls needs for session
/// tickets. Set fields such as `alpn_protocols` on the result before sharing
/// it, through `Arc::get_mut`.
pub fn server_config(
    provider: Arc<rustls::crypto::CryptoProvider>,
    time: Arc<dyn TimeProvider>,
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, Error> {
    let config = ServerConfig::builder_with_details(provider, time)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests;
