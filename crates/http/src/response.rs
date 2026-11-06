// SPDX-License-Identifier: GPL-2.0-only
//! Responses.

use alloc::string::String;
use alloc::vec::Vec;

/// A response to send. [`crate::Connection::respond`] adds `Content-Length`
/// and `Connection`, so set neither.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The status code.
    pub status: u16,
    /// Header fields, in order.
    pub headers: Vec<(String, String)>,
    /// The body. Not sent in answer to `HEAD`, though its length still is.
    pub body: Vec<u8>,
}

impl Response {
    /// An empty response with `status`.
    pub fn new(status: u16) -> Self {
        Self { status, headers: Vec::new(), body: Vec::new() }
    }

    /// Adds a header field.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sets the body and its `Content-Type`.
    pub fn body(self, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        let mut r = self.header("Content-Type", content_type);
        r.body = body.into();
        r
    }

    /// A `text/plain` response.
    pub fn text(status: u16, text: &str) -> Self {
        Self::new(status).body("text/plain; charset=utf-8", text.as_bytes())
    }

    /// An `application/json` response. `json` must already be JSON.
    pub fn json(status: u16, json: &str) -> Self {
        Self::new(status).body("application/json", json.as_bytes())
    }

    /// A redirect to `location` (use 301 or 308 for permanent, 302, 303 or 307 for temporary).
    pub fn redirect(status: u16, location: &str) -> Self {
        Self::new(status).header("Location", location)
    }

    /// A plain response for an error status: the code and its reason phrase.
    pub fn error(status: u16) -> Self {
        let reason = reason(status);
        let mut body = String::with_capacity(reason.len() + 5);
        body.push_str(itoa(status).as_str());
        body.push(' ');
        body.push_str(reason);
        body.push('\n');
        Self::text(status, &body)
    }

    /// Writes the status line, headers and (unless `omit_body`) the body to
    /// `out`, adding `Content-Length` and, if `close`, `Connection: close`.
    /// Header fields that could break the framing (bad names, CR or LF in a
    /// value) and any `Content-Length`, `Transfer-Encoding` or `Connection`
    /// set by the caller are dropped.
    pub(crate) fn write_to(&self, out: &mut Vec<u8>, omit_body: bool, close: bool) {
        out.extend_from_slice(b"HTTP/1.1 ");
        out.extend_from_slice(itoa(self.status).as_bytes());
        out.push(b' ');
        out.extend_from_slice(reason(self.status).as_bytes());
        out.extend_from_slice(b"\r\n");
        for (name, value) in &self.headers {
            let reserved =
                ["content-length", "transfer-encoding", "connection"].iter().any(|r| name.eq_ignore_ascii_case(r));
            let safe_name = !name.is_empty() && name.bytes().all(|b| b.is_ascii_graphic() && b != b':');
            let safe_value = value.bytes().all(|b| b >= 0x20 && b != 0x7f || b == b'\t');
            if reserved || !safe_name || !safe_value {
                continue;
            }
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        // 1xx and 204 responses never carry a body or its length (RFC 9110, section 8.6).
        let bodyless = self.status < 200 || self.status == 204;
        if !bodyless {
            out.extend_from_slice(b"Content-Length: ");
            out.extend_from_slice(itoa(self.body.len() as u64).as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if close {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        out.extend_from_slice(b"\r\n");
        if !omit_body && !bodyless && self.status != 304 {
            out.extend_from_slice(&self.body);
        }
    }
}

/// The reason phrase for a status code.
pub fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

/// A content type for a file name, from its extension.
pub fn content_type(path: &str) -> &'static str {
    let ext = path.rsplit_once('.').map_or("", |(_, e)| e);
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "wasm" => "application/wasm",
        "pem" | "crt" => "application/x-pem-file",
        _ => "application/octet-stream",
    }
}

fn itoa(n: impl Into<u64>) -> String {
    use core::fmt::Write;
    let mut s = String::new();
    let _ = write!(s, "{}", n.into());
    s
}
