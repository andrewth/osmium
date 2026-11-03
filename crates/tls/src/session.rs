//! A TLS server connection that does no I/O of its own.
//!
//! [`ServerSession`] sits between a byte transport (a TCP socket from
//! `osmium-net`, a virtio-vsock stream, a test pipe) and the application:
//!
//! ```text
//! network ──receive()──▶ ┌───────────────┐ ──read()──▶  application
//! network ◀─outgoing()── │ ServerSession │ ◀─write()──  application
//!                        └───────────────┘
//! ```
//!
//! The caller moves bytes: whatever arrives from the peer goes to
//! [`receive`](ServerSession::receive), and whatever
//! [`outgoing`](ServerSession::outgoing) returns goes to the peer, after
//! which the caller reports how much was sent with
//! [`sent`](ServerSession::sent). The session never blocks, so it works the
//! same from a polling loop, an interrupt-driven driver or an async task.

use alloc::sync::Arc;
use alloc::vec::Vec;

use rustls::server::UnbufferedServerConnection;
use rustls::unbuffered::{
    AppDataRecord, ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedStatus,
};
use rustls::{Error, ServerConfig};

/// Bytes of received TLS records buffered before [`ServerSession::receive`]
/// refuses more: one maximum-size record and its header, with slack.
pub const MAX_INCOMING: usize = 16 * 1024 + 2048;

/// One TLS server connection.
pub struct ServerSession {
    conn: UnbufferedServerConnection,
    /// Received bytes not yet consumed by rustls.
    incoming: Vec<u8>,
    /// Encrypted bytes waiting to go to the network.
    outgoing: Vec<u8>,
    /// Decrypted application data waiting for [`read`](Self::read).
    plain_in: Vec<u8>,
    /// Application data waiting for the handshake to finish.
    plain_out: Vec<u8>,
    handshaking: bool,
    close_requested: bool,
    close_sent: bool,
    peer_closed: bool,
    closed: bool,
    error: Option<Error>,
}

impl ServerSession {
    /// A new connection waiting for a client hello.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        Ok(Self {
            conn: UnbufferedServerConnection::new(config)?,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            plain_in: Vec::new(),
            plain_out: Vec::new(),
            handshaking: true,
            close_requested: false,
            close_sent: false,
            peer_closed: false,
            closed: false,
            error: None,
        })
    }

    /// Takes bytes received from the peer and processes as much as it can.
    ///
    /// Returns how many bytes were taken: fewer than `data.len()` only when
    /// [`MAX_INCOMING`] bytes are already waiting, which means the caller
    /// should first [`read`](Self::read) what has been decrypted.
    pub fn receive(&mut self, data: &[u8]) -> Result<usize, Error> {
        let take = data.len().min(MAX_INCOMING.saturating_sub(self.incoming.len()));
        self.incoming.extend_from_slice(data.get(..take).unwrap_or(&[]));
        self.process()?;
        Ok(take)
    }

    /// Encrypted bytes to send to the peer.
    pub fn outgoing(&self) -> &[u8] {
        &self.outgoing
    }

    /// Records that the first `n` bytes of [`outgoing`](Self::outgoing) were sent.
    pub fn sent(&mut self, n: usize) {
        self.outgoing.drain(..n.min(self.outgoing.len()));
    }

    /// Copies decrypted application data into `buf`, returning how much.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.plain_in.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), self.plain_in.get(..n)) {
            dst.copy_from_slice(src);
        }
        self.plain_in.drain(..n);
        n
    }

    /// Bytes of decrypted application data waiting for [`read`](Self::read).
    pub fn readable(&self) -> usize {
        self.plain_in.len()
    }

    /// Queues `data` to be encrypted and sent. Data written during the
    /// handshake is held until it finishes.
    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.close_requested || self.closed {
            return Err(Error::General("write after close".into()));
        }
        self.plain_out.extend_from_slice(data);
        self.process()
    }

    /// Sends a `close_notify` alert once any queued data has been sent.
    pub fn close(&mut self) -> Result<(), Error> {
        self.close_requested = true;
        self.process()
    }

    /// Whether the handshake is still in progress.
    pub fn is_handshaking(&self) -> bool {
        self.handshaking
    }

    /// Whether the peer has sent `close_notify`. Data already decrypted can
    /// still be read.
    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// Whether the connection is finished in both directions, or failed. Any
    /// remaining [`outgoing`](Self::outgoing) bytes should still be sent: they
    /// may hold the alert that tells the peer why.
    pub fn is_closed(&self) -> bool {
        self.closed || self.error.is_some()
    }

    /// The ALPN protocol agreed in the handshake.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.conn.alpn_protocol()
    }

    fn process(&mut self) -> Result<(), Error> {
        if let Some(e) = &self.error {
            return Err(e.clone());
        }
        let result = self.step();
        if let Err(e) = &result {
            self.error = Some(e.clone());
        }
        result
    }

    /// Runs rustls until it needs more input or has nothing more to do.
    fn step(&mut self) -> Result<(), Error> {
        loop {
            let UnbufferedStatus { mut discard, state } = self.conn.process_tls_records(&mut self.incoming);
            let state = match state {
                Ok(state) => state,
                Err(e) => {
                    self.incoming.drain(..discard.min(self.incoming.len()));
                    self.flush_alert();
                    return Err(e);
                }
            };
            let mut again = true;
            match state {
                ConnectionState::ReadTraffic(mut r) => {
                    while let Some(record) = r.next_record() {
                        let AppDataRecord { discard: d, payload } = record?;
                        discard += d;
                        self.plain_in.extend_from_slice(payload);
                    }
                }
                ConnectionState::ReadEarlyData(mut r) => {
                    // Early data is off unless the config enables it; take it as ordinary data.
                    while let Some(record) = r.next_record() {
                        let AppDataRecord { discard: d, payload } = record?;
                        discard += d;
                        self.plain_in.extend_from_slice(payload);
                    }
                }
                ConnectionState::EncodeTlsData(mut e) => {
                    append(&mut self.outgoing, |buf| e.encode(buf).map_err(Grow::from))?;
                }
                ConnectionState::TransmitTlsData(t) => {
                    // Queued in `outgoing`, in order, for the caller to send.
                    t.done();
                }
                ConnectionState::BlockedHandshake => again = false,
                ConnectionState::WriteTraffic(mut w) => {
                    self.handshaking = false;
                    if !self.plain_out.is_empty() {
                        let plain = core::mem::take(&mut self.plain_out);
                        append(&mut self.outgoing, |buf| w.encrypt(&plain, buf).map_err(Grow::from))?;
                    }
                    if self.close_requested && !self.close_sent {
                        append(&mut self.outgoing, |buf| w.queue_close_notify(buf).map_err(Grow::from))?;
                        self.close_sent = true;
                    }
                    again = false;
                }
                ConnectionState::PeerClosed => {
                    self.peer_closed = true;
                    // Answer with our own close_notify, as RFC 8446 section 6.1 asks.
                    self.close_requested = true;
                }
                ConnectionState::Closed => {
                    self.closed = true;
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

impl ServerSession {
    /// After a failure rustls queues a fatal alert for the peer, and hands it
    /// out from the next `process_tls_records` call. Collect it into
    /// `outgoing`, so the peer learns why the connection ended.
    fn flush_alert(&mut self) {
        for _ in 0..4 {
            let UnbufferedStatus { state, .. } = self.conn.process_tls_records(&mut []);
            match state {
                Ok(ConnectionState::EncodeTlsData(mut e)) => {
                    if append(&mut self.outgoing, |buf| e.encode(buf).map_err(Grow::from)).is_err() {
                        return;
                    }
                }
                Ok(ConnectionState::TransmitTlsData(t)) => t.done(),
                _ => return,
            }
        }
    }
}

/// Why an encode into `outgoing` didn't fit, or failed for good.
pub(crate) enum Grow {
    To(usize),
    Fail(Error),
}

impl From<EncodeError> for Grow {
    fn from(e: EncodeError) -> Self {
        match e {
            EncodeError::InsufficientSize(InsufficientSizeError { required_size }) => Grow::To(required_size),
            other => Grow::Fail(Error::General(alloc::format!("{other}"))),
        }
    }
}

impl From<EncryptError> for Grow {
    fn from(e: EncryptError) -> Self {
        match e {
            EncryptError::InsufficientSize(InsufficientSizeError { required_size }) => Grow::To(required_size),
            other => Grow::Fail(Error::General(alloc::format!("{other}"))),
        }
    }
}

/// Lets `f` write at the end of `out`, growing the space until it fits.
pub(crate) fn append(out: &mut Vec<u8>, mut f: impl FnMut(&mut [u8]) -> Result<usize, Grow>) -> Result<(), Error> {
    let start = out.len();
    let mut room = 1024;
    loop {
        out.resize(start + room, 0);
        match f(out.get_mut(start..).unwrap_or(&mut [])) {
            Ok(n) => {
                out.truncate(start + n);
                return Ok(());
            }
            Err(Grow::To(required)) if required > room => room = required,
            Err(Grow::To(_)) => {
                out.truncate(start);
                return Err(Error::General("TLS encoder asked for less space than it had".into()));
            }
            Err(Grow::Fail(e)) => {
                out.truncate(start);
                return Err(e);
            }
        }
    }
}
