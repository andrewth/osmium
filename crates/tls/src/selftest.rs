//! A power-on check of the whole TLS stack, with no network.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use osmium_rand::SharedRng;
use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::unbuffered::{AppDataRecord, ConnectionState, UnbufferedStatus};
use rustls::{ClientConfig, Error};

use crate::cert::{SubjectName, Validity, self_signed};
use crate::session::{Grow, ServerSession, append};

const NAME: &str = "self-test.invalid";
const MESSAGE: &[u8] = b"osmium-tls self-test";

/// A clock stuck at one time.
#[derive(Debug)]
pub struct FixedTime(pub u64);

impl TimeProvider for FixedTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(self.0)))
    }
}

/// Runs a TLS 1.3 handshake and an echo between a client and a
/// [`ServerSession`] in memory, using a fresh self-signed certificate.
///
/// This exercises every algorithm of the provider (key generation, ECDSA
/// signing and verification, X25519, HKDF, ChaCha20-Poly1305) and the
/// generator in `rng`, which must be seeded. Run it once at boot, before
/// serving anything, to catch a miscompiled or misconfigured crypto backend.
/// `now` is the time in seconds since the Unix epoch, roughly; an RTC that
/// hasn't been set is fine.
pub fn self_test(rng: &'static SharedRng, now: u64) -> Result<(), Error> {
    let validity = Validity { not_before: now.saturating_sub(86_400), not_after: now.saturating_add(86_400) };
    let id = self_signed(rng, &[SubjectName::Dns(NAME)], validity)
        .map_err(|e| Error::General(alloc::format!("certificate: {e}")))?;
    let provider = crate::shared_provider(rng);
    let time: Arc<dyn TimeProvider> = Arc::new(FixedTime(now));
    let cert = CertificateDer::from(id.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_pkcs8_der.clone()));
    let server_config = crate::server_config(provider.clone(), time.clone(), vec![cert.clone()], key)?;

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert)?;
    let client_config = ClientConfig::builder_with_details(provider, time)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(NAME).map_err(|_| Error::General("bad name".into()))?;
    let mut client = Client::new(Arc::new(client_config), name)?;
    let mut server = ServerSession::new(server_config)?;

    for _ in 0..64 {
        client.step()?;
        let out = core::mem::take(&mut client.outgoing);
        let mut rest = &out[..];
        while !rest.is_empty() {
            let n = server.receive(rest)?;
            rest = rest.get(n..).unwrap_or(&[]);
        }
        let mut echo = vec![0u8; server.readable()];
        let n = server.read(&mut echo);
        if n > 0 {
            server.write(echo.get(..n).unwrap_or(&[]))?;
        }
        client.incoming.extend_from_slice(server.outgoing());
        let sent = server.outgoing().len();
        server.sent(sent);
        if client.received.len() >= MESSAGE.len() {
            return if client.received == MESSAGE {
                Ok(())
            } else {
                Err(Error::General("echo came back different".into()))
            };
        }
    }
    Err(Error::General("handshake did not finish".into()))
}

/// The client half: an unbuffered rustls client that sends [`MESSAGE`] once
/// the handshake is done.
struct Client {
    conn: UnbufferedClientConnection,
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    received: Vec<u8>,
    sent: bool,
}

impl Client {
    fn new(config: Arc<ClientConfig>, name: ServerName<'static>) -> Result<Self, Error> {
        Ok(Self {
            conn: UnbufferedClientConnection::new(config, name)?,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            received: Vec::new(),
            sent: false,
        })
    }

    fn step(&mut self) -> Result<(), Error> {
        loop {
            let UnbufferedStatus { mut discard, state } = self.conn.process_tls_records(&mut self.incoming);
            let mut again = true;
            match state? {
                ConnectionState::ReadTraffic(mut r) => {
                    while let Some(record) = r.next_record() {
                        let AppDataRecord { discard: d, payload } = record?;
                        discard += d;
                        self.received.extend_from_slice(payload);
                    }
                }
                ConnectionState::EncodeTlsData(mut e) => {
                    append(&mut self.outgoing, |buf| e.encode(buf).map_err(Grow::from))?;
                }
                ConnectionState::TransmitTlsData(t) => t.done(),
                ConnectionState::WriteTraffic(mut w) => {
                    if !self.sent {
                        append(&mut self.outgoing, |buf| w.encrypt(MESSAGE, buf).map_err(Grow::from))?;
                        self.sent = true;
                    }
                    again = false;
                }
                _ => again = false,
            }
            self.incoming.drain(..discard.min(self.incoming.len()));
            if !again {
                return Ok(());
            }
        }
    }
}
