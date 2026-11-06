// SPDX-License-Identifier: GPL-2.0-only
//! An HTTP/1.1 server with no I/O of its own.
//!
//! [`Connection`] turns bytes from a client into [`Request`]s and
//! [`Response`]s into bytes for the client. What carries the bytes is up to
//! the caller: a TCP socket from `osmium-net`, an `osmium-tls`
//! `ServerSession` over one, or a test buffer. Nothing here blocks, so it
//! runs the same from a polling loop or an async task.
//!
//! Parsing follows RFC 9112 strictly where leniency has been exploited:
//! a request with both `Content-Length` and `Transfer-Encoding`, conflicting
//! lengths, obsolete line folding, whitespace before a header colon, control
//! characters in values, transfer codings other than `chunked` and requests
//! larger than the [`Limits`] are all refused with the matching status and
//! the connection closed.
//!
//! Needs `alloc`. There are no dependencies.
//!
//! ```
//! use osmium_http::{Connection, Limits, Method, Response};
//!
//! let mut conn = Connection::new(Limits::default());
//! conn.receive(b"GET /hello HTTP/1.1\r\nHost: hyperon\r\n\r\n");
//! while let Some(req) = conn.next_request() {
//!     let Ok(req) = req else { break }; // the error response is already queued
//!     let resp = match (&req.method, req.path()) {
//!         (Method::Get, "/hello") => Response::text(200, "hello\n"),
//!         _ => Response::error(404),
//!     };
//!     conn.respond(resp);
//! }
//! assert!(conn.outgoing().starts_with(b"HTTP/1.1 200 OK\r\n"));
//! ```
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod conn;
mod request;
mod response;
pub mod url;

pub use conn::Connection;
pub use request::{HttpError, Limits, Method, Request, Version};
pub use response::{Response, content_type, reason};

#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod tests;
