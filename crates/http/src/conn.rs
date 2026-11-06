//! One HTTP/1.1 connection, with no I/O of its own.

use alloc::vec::Vec;

use crate::request::{self, HttpError, Limits, Method, Parsed, Request};
use crate::response::Response;

/// The server side of one connection.
///
/// ```text
/// transport ──receive()──▶ ┌────────────┐ ──next_request()──▶ application
/// transport ◀─outgoing()── │ Connection │ ◀────respond()───── application
///                          └────────────┘
/// ```
///
/// Requests come out one at a time: after [`next_request`](Self::next_request)
/// returns one, it returns `None` until [`respond`](Self::respond) has
/// answered it, so responses always go out in request order even when a
/// client pipelines. When [`should_close`](Self::should_close) is true and
/// [`outgoing`](Self::outgoing) is empty, close the transport.
pub struct Connection {
    limits: Limits,
    incoming: Vec<u8>,
    outgoing: Vec<u8>,
    /// The request being answered: whether it was `HEAD`, and whether to close after it.
    awaiting: Option<(bool, bool)>,
    continue_sent: bool,
    closing: bool,
}

impl Connection {
    /// A new connection with `limits`.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            awaiting: None,
            continue_sent: false,
            closing: false,
        }
    }

    /// Takes bytes received from the client, returning how many it took.
    ///
    /// It buffers at most one request's worth (the head and body limits
    /// together, with room for chunk framing and trailers), so a request
    /// within the [`Limits`] always fits. Fewer than `data.len()` means
    /// the buffer is full: answer the pending request, then offer the rest
    /// again. Until then, stop reading from the transport. After the
    /// connection has started closing, input is discarded and counted as taken.
    pub fn receive(&mut self, data: &[u8]) -> usize {
        if self.closing {
            return data.len();
        }
        let take = data.len().min(self.limits.max_request().saturating_sub(self.incoming.len()));
        self.incoming.extend_from_slice(data.get(..take).unwrap_or(&[]));
        take
    }

    /// The next complete request, if one has arrived and the previous one has
    /// been answered.
    ///
    /// A malformed request gives `Some(Err(_))`: the error response has
    /// already been queued, and the connection will close after it.
    pub fn next_request(&mut self) -> Option<Result<Request, HttpError>> {
        if self.awaiting.is_some() || self.closing {
            return None;
        }
        let parsed = match request::parse(&self.incoming, &self.limits) {
            // A full buffer that still holds no whole request can never
            // complete, since `receive` takes no more: refuse it rather than
            // stalling. The parser's own limits should catch this first.
            Ok(Parsed::Incomplete { .. }) if self.incoming.len() >= self.limits.max_request() => {
                Err(HttpError::BodyTooLarge)
            }
            other => other,
        };
        match parsed {
            Ok(Parsed::Complete(req, used)) => {
                self.incoming.drain(..used.min(self.incoming.len()));
                self.continue_sent = false;
                self.awaiting = Some((req.method == Method::Head, !req.keep_alive()));
                Some(Ok(req))
            }
            Ok(Parsed::Incomplete { expects_continue }) => {
                if expects_continue && !self.continue_sent {
                    self.outgoing.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
                    self.continue_sent = true;
                }
                None
            }
            Err(e) => {
                Response::error(e.status()).write_to(&mut self.outgoing, false, true);
                self.closing = true;
                self.incoming.clear();
                Some(Err(e))
            }
        }
    }

    /// Answers the request [`next_request`](Self::next_request) last
    /// returned. Does nothing if there is none.
    pub fn respond(&mut self, response: Response) {
        let Some((head, close)) = self.awaiting.take() else { return };
        response.write_to(&mut self.outgoing, head, close);
        if close {
            self.closing = true;
            self.incoming.clear();
        }
    }

    /// Bytes to send to the client.
    pub fn outgoing(&self) -> &[u8] {
        &self.outgoing
    }

    /// Records that the first `n` bytes of [`outgoing`](Self::outgoing) were sent.
    pub fn sent(&mut self, n: usize) {
        self.outgoing.drain(..n.min(self.outgoing.len()));
    }

    /// Whether the connection should be closed once [`outgoing`](Self::outgoing)
    /// has been sent.
    pub fn should_close(&self) -> bool {
        self.closing
    }

    /// Whether a request has been returned and not yet answered.
    pub fn is_awaiting_response(&self) -> bool {
        self.awaiting.is_some()
    }
}
