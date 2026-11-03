//! Requests, and the parser that reads them from a byte buffer.

use alloc::string::String;
use alloc::vec::Vec;

use crate::url;

/// Size limits for one request. Anything larger is refused with the matching
/// status code, and the connection is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Request line and headers together, in bytes (431 when exceeded).
    pub max_head: usize,
    /// Number of header fields (431 when exceeded).
    pub max_headers: usize,
    /// Body, after any chunked decoding, in bytes (413 when exceeded).
    pub max_body: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_head: 16 * 1024, max_headers: 64, max_body: 1024 * 1024 }
    }
}

/// The HTTP version of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    /// HTTP/1.0: connections close after each response unless asked otherwise.
    Http10,
    /// HTTP/1.1: connections stay open unless asked otherwise.
    Http11,
}

/// A request method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`: answered like `GET`, without the body.
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `DELETE`
    Delete,
    /// `PATCH`
    Patch,
    /// `OPTIONS`
    Options,
    /// Any other token.
    Other(String),
}

impl Method {
    fn parse(token: &str) -> Self {
        match token {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "PATCH" => Method::Patch,
            "OPTIONS" => Method::Options,
            other => Method::Other(other.into()),
        }
    }

    /// The method as it appears on the wire.
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Patch => "PATCH",
            Method::Options => "OPTIONS",
            Method::Other(s) => s,
        }
    }
}

/// A complete request, with its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The method.
    pub method: Method,
    /// The request target as sent: usually a path and query, such as `/vms?state=running`.
    pub target: String,
    /// The HTTP version.
    pub version: Version,
    /// Header fields in the order received, names as sent.
    pub headers: Vec<(String, String)>,
    /// The body, with any chunked transfer coding removed.
    pub body: Vec<u8>,
}

impl Request {
    /// The value of the first header named `name`, compared case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Every value of the headers named `name`, in order.
    pub fn headers_named<'r>(&'r self, name: &'r str) -> impl Iterator<Item = &'r str> + 'r {
        self.headers.iter().filter(move |(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// The path part of the target, still percent-encoded.
    pub fn path(&self) -> &str {
        self.target.split_once('?').map_or(self.target.as_str(), |(p, _)| p)
    }

    /// The query part of the target, without the `?`.
    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, q)| q)
    }

    /// The decoded value of the first query parameter named `name`.
    pub fn query_param(&self, name: &str) -> Option<String> {
        url::query_pairs(self.query()?).find(|(k, _)| k == name).map(|(_, v)| v)
    }

    /// The path split into decoded segments: `/vms/web%201/start` gives
    /// `["vms", "web 1", "start"]`. `None` if a segment's percent-encoding is
    /// invalid or decodes to `/`, `.` or `..`, which would make the path mean
    /// something other than it appears to.
    pub fn segments(&self) -> Option<Vec<String>> {
        let mut out = Vec::new();
        for raw in self.path().split('/').filter(|s| !s.is_empty()) {
            let s = url::percent_decode(raw)?;
            if s.contains('/') || s == "." || s == ".." {
                return None;
            }
            out.push(s);
        }
        Some(out)
    }

    /// Whether the client wants the connection kept open after this request.
    pub fn keep_alive(&self) -> bool {
        let has = |token: &str| {
            self.headers_named("connection").flat_map(|v| v.split(',')).any(|t| t.trim().eq_ignore_ascii_case(token))
        };
        match self.version {
            Version::Http11 => !has("close"),
            Version::Http10 => has("keep-alive"),
        }
    }
}

/// Why a request was refused. Each maps to a status code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpError {
    /// Malformed or ambiguous (400).
    BadRequest(&'static str),
    /// The body is larger than [`Limits::max_body`] (413).
    BodyTooLarge,
    /// The request line and headers are larger than [`Limits::max_head`], or
    /// there are more than [`Limits::max_headers`] (431).
    HeadersTooLarge,
    /// A transfer coding other than `chunked` (501).
    NotImplemented(&'static str),
    /// An HTTP version other than 1.0 or 1.1 (505).
    VersionNotSupported,
}

impl HttpError {
    /// The status code to answer with.
    pub fn status(&self) -> u16 {
        match self {
            HttpError::BadRequest(_) => 400,
            HttpError::BodyTooLarge => 413,
            HttpError::HeadersTooLarge => 431,
            HttpError::NotImplemented(_) => 501,
            HttpError::VersionNotSupported => 505,
        }
    }
}

impl core::fmt::Display for HttpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HttpError::BadRequest(why) => write!(f, "bad request: {why}"),
            HttpError::BodyTooLarge => f.write_str("body too large"),
            HttpError::HeadersTooLarge => f.write_str("headers too large"),
            HttpError::NotImplemented(why) => write!(f, "not implemented: {why}"),
            HttpError::VersionNotSupported => f.write_str("HTTP version not supported"),
        }
    }
}

/// What [`parse`] found at the front of the buffer.
#[derive(Debug)]
pub(crate) enum Parsed {
    /// More bytes are needed. `expects_continue` is true once the head is
    /// complete and the client sent `Expect: 100-continue`.
    Incomplete { expects_continue: bool },
    /// A whole request, and how many buffer bytes it used.
    Complete(Request, usize),
}

/// How the body is delimited.
enum Framing {
    Length(usize),
    Chunked,
}

/// Parses one request from the front of `buf`.
pub(crate) fn parse(buf: &[u8], limits: &Limits) -> Result<Parsed, HttpError> {
    // Empty lines before a request line are ignored (RFC 9112, section 2.2).
    let skip = buf.iter().take_while(|&&b| b == b'\r' || b == b'\n').count();
    let buf = buf.get(skip..).unwrap_or(&[]);
    let Some(head_len) = find(buf, b"\r\n\r\n").map(|i| i + 4) else {
        if buf.len() > limits.max_head {
            return Err(HttpError::HeadersTooLarge);
        }
        return Ok(Parsed::Incomplete { expects_continue: false });
    };
    if head_len > limits.max_head {
        return Err(HttpError::HeadersTooLarge);
    }
    let head = buf.get(..head_len - 4).unwrap_or(&[]);
    // Bare CR and LF need no check of their own: after splitting on CRLF they
    // can only sit inside a line, where tokens, targets and values reject them.
    let head = core::str::from_utf8(head).map_err(|_| HttpError::BadRequest("head is not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let (method, target, version) = request_line(lines.next().unwrap_or(""))?;

    let mut headers = Vec::new();
    for line in lines {
        if headers.len() == limits.max_headers {
            return Err(HttpError::HeadersTooLarge);
        }
        headers.push(header_line(line)?);
    }
    let mut request = Request { method, target: target.into(), version, headers, body: Vec::new() };
    if version == Version::Http11 && request.header("host").is_none() {
        return Err(HttpError::BadRequest("HTTP/1.1 request without Host"));
    }

    let framing = framing(&request, limits)?;
    let body_start = skip + head_len;
    let rest = buf.get(head_len..).unwrap_or(&[]);
    let expects_continue = version == Version::Http11
        && request.header("expect").is_some_and(|v| v.trim().eq_ignore_ascii_case("100-continue"));
    match framing {
        Framing::Length(n) => match rest.get(..n) {
            Some(body) => {
                request.body = body.to_vec();
                Ok(Parsed::Complete(request, body_start + n))
            }
            None => Ok(Parsed::Incomplete { expects_continue }),
        },
        Framing::Chunked => match dechunk(rest, limits)? {
            Some((body, used)) => {
                request.body = body;
                Ok(Parsed::Complete(request, body_start + used))
            }
            None => Ok(Parsed::Incomplete { expects_continue }),
        },
    }
}

fn request_line(line: &str) -> Result<(Method, &str, Version), HttpError> {
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HttpError::BadRequest("malformed request line"));
    };
    if method.is_empty() || !method.bytes().all(is_tchar) {
        return Err(HttpError::BadRequest("invalid method"));
    }
    if target.is_empty() || !target.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(HttpError::BadRequest("invalid request target"));
    }
    if !(target.starts_with('/') || target == "*" || target.starts_with("http://") || target.starts_with("https://")) {
        return Err(HttpError::BadRequest("invalid request target"));
    }
    let version = match version {
        "HTTP/1.1" => Version::Http11,
        "HTTP/1.0" => Version::Http10,
        v if v.starts_with("HTTP/") => return Err(HttpError::VersionNotSupported),
        _ => return Err(HttpError::BadRequest("invalid HTTP version")),
    };
    Ok((Method::parse(method), target, version))
}

fn header_line(line: &str) -> Result<(String, String), HttpError> {
    if line.starts_with([' ', '\t']) {
        return Err(HttpError::BadRequest("obsolete line folding"));
    }
    let (name, value) = line.split_once(':').ok_or(HttpError::BadRequest("header without a colon"))?;
    if name.is_empty() || !name.bytes().all(is_tchar) {
        // Includes whitespace before the colon, which RFC 9112 section 5.1 says to reject.
        return Err(HttpError::BadRequest("invalid header name"));
    }
    let value = value.trim_matches([' ', '\t']);
    if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(HttpError::BadRequest("control character in header value"));
    }
    Ok((name.into(), value.into()))
}

fn framing(request: &Request, limits: &Limits) -> Result<Framing, HttpError> {
    let te: Vec<&str> = request.headers_named("transfer-encoding").flat_map(|v| v.split(',')).map(str::trim).collect();
    let mut lengths = request.headers_named("content-length").flat_map(|v| v.split(',')).map(str::trim);
    if !te.is_empty() {
        // Both framings at once is the classic request-smuggling setup (RFC 9112, section 6.1).
        if lengths.next().is_some() {
            return Err(HttpError::BadRequest("both Content-Length and Transfer-Encoding"));
        }
        if request.version == Version::Http10 {
            return Err(HttpError::BadRequest("Transfer-Encoding in HTTP/1.0"));
        }
        return match te.as_slice() {
            [only] if only.eq_ignore_ascii_case("chunked") => Ok(Framing::Chunked),
            _ => Err(HttpError::NotImplemented("transfer coding other than chunked")),
        };
    }
    let mut length = None;
    for l in lengths {
        if l.is_empty() || !l.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HttpError::BadRequest("invalid Content-Length"));
        }
        let n: usize = l.parse().map_err(|_| HttpError::BodyTooLarge)?;
        if length.is_some_and(|m| m != n) {
            return Err(HttpError::BadRequest("conflicting Content-Length values"));
        }
        length = Some(n);
    }
    let n = length.unwrap_or(0);
    if n > limits.max_body {
        return Err(HttpError::BodyTooLarge);
    }
    Ok(Framing::Length(n))
}

/// Decodes a chunked body from the front of `buf`: the body and the bytes
/// used, or `None` if it isn't all there yet.
///
/// The chunks are located first and copied only once all have arrived, so a
/// body that trickles in costs a walk over the chunk headers per call, not a
/// copy of everything received so far.
fn dechunk(buf: &[u8], limits: &Limits) -> Result<Option<(Vec<u8>, usize)>, HttpError> {
    let mut chunks: Vec<(usize, usize)> = Vec::new();
    let mut total = 0usize;
    let mut pos = 0;
    loop {
        let rest = buf.get(pos..).unwrap_or(&[]);
        // A size line longer than this is refused, so never scan further for its end.
        let Some(eol) = find(rest.get(..1026).unwrap_or(rest), b"\r\n") else {
            return if rest.len() > 1024 { Err(HttpError::BadRequest("chunk size line too long")) } else { Ok(None) };
        };
        let line = core::str::from_utf8(rest.get(..eol).unwrap_or(&[]))
            .map_err(|_| HttpError::BadRequest("invalid chunk size"))?;
        // Chunk extensions (";name=value") carry nothing we use.
        let size = line.split(';').next().unwrap_or("").trim_end_matches([' ', '\t']);
        if size.is_empty() || size.len() > 16 || !size.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(HttpError::BadRequest("invalid chunk size"));
        }
        let size = usize::from_str_radix(size, 16).map_err(|_| HttpError::BodyTooLarge)?;
        pos += eol + 2;
        if size == 0 {
            break;
        }
        total = total.saturating_add(size);
        if total > limits.max_body {
            return Err(HttpError::BodyTooLarge);
        }
        let Some(crlf) = buf.get(pos.saturating_add(size)..).and_then(|r| r.get(..2)) else { return Ok(None) };
        if crlf != b"\r\n" {
            return Err(HttpError::BadRequest("chunk not followed by CRLF"));
        }
        chunks.push((pos, size));
        pos += size + 2;
    }
    // Trailer fields, ignored, up to the empty line.
    let mut trailer_bytes = 0usize;
    loop {
        let rest = buf.get(pos..).unwrap_or(&[]);
        let Some(eol) = find(rest, b"\r\n") else {
            return if rest.len() > limits.max_head { Err(HttpError::HeadersTooLarge) } else { Ok(None) };
        };
        pos += eol + 2;
        if eol == 0 {
            let mut body = Vec::with_capacity(total);
            for (start, len) in chunks {
                body.extend_from_slice(buf.get(start..start + len).unwrap_or(&[]));
            }
            return Ok(Some((body, pos)));
        }
        trailer_bytes += eol + 2;
        if trailer_bytes > limits.max_head {
            return Err(HttpError::HeadersTooLarge);
        }
    }
}

/// RFC 9110 `tchar`: the characters allowed in tokens such as methods and header names.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
