// SPDX-License-Identifier: GPL-2.0-only
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
//!
//! Receive-side memory is bounded: at most [`MAX_INCOMING`] bytes of
//! ciphertext are buffered, and once [`MAX_PLAINTEXT`] bytes of decrypted
//! data are waiting for [`read`](ServerSession::read) the session stops
//! decrypting, so [`receive`](ServerSession::receive) takes fewer bytes and
//! the transport's own flow control (a TCP receive window, say) pushes back
//! on the peer. Writing still works while reads are held back.
//!
//! TLS 1.3 early data (0-RTT) is refused: an attacker can replay it, and the
//! session has no way to tell the application which bytes were early.
//! [`ServerSession::new`] rejects a configuration that would accept it.

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

/// Bytes of decrypted application data waiting for [`ServerSession::read`]
/// at which the session stops decrypting more. The record that crosses the
/// limit is kept whole, so up to 16 KiB more than this can be waiting.
pub const MAX_PLAINTEXT: usize = 64 * 1024;

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
    ///
    /// Fails if `config` accepts early data (its `max_early_data_size` is not
    /// zero), since the session never delivers replayable 0-RTT bytes.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        if config.max_early_data_size != 0 {
            return Err(Error::General("TLS early data is not supported".into()));
        }
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
    /// [`MAX_INCOMING`] bytes are already waiting, which happens when
    /// [`MAX_PLAINTEXT`] decrypted bytes are waiting for [`read`](Self::read).
    /// The caller should keep the rest and offer it again after reading.
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
    ///
    /// Reading below [`MAX_PLAINTEXT`] resumes decrypting received records
    /// that were held back. An error found while doing so closes the session
    /// (see [`is_closed`](Self::is_closed)) and is returned by the next
    /// [`receive`](Self::receive) or [`write`](Self::write).
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.plain_in.len());
        if let (Some(dst), Some(src)) = (buf.get_mut(..n), self.plain_in.get(..n)) {
            dst.copy_from_slice(src);
        }
        self.plain_in.drain(..n);
        if n > 0 && !self.incoming.is_empty() && self.plain_in.len() < MAX_PLAINTEXT {
            // An error is kept in `self.error` for the next call that can return it.
            let _ = self.process();
        }
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
            // With MAX_PLAINTEXT bytes waiting, hold the received records back
            // and show rustls no input, so it still reaches WriteTraffic for
            // whatever the application writes. rustls's handshake deframer
            // keeps offsets into the input only while a handshake message is
            // incomplete, and application data never arrives in that state
            // (RFC 8446 section 5.1, which rustls enforces), so when the limit
            // is reached nothing in rustls refers into `incoming`.
            let hold = self.plain_in.len() >= MAX_PLAINTEXT;
            let input: &mut [u8] = if hold { &mut [] } else { &mut self.incoming };
            let UnbufferedStatus { mut discard, state } = self.conn.process_tls_records(input);
            if hold {
                discard = 0;
            }
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
                ConnectionState::ReadEarlyData(_) => {
                    // `new` refuses configs that accept early data, so this is
                    // not reached; never hand replayable bytes over as ordinary data.
                    return Err(Error::General("TLS early data is not supported".into()));
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
