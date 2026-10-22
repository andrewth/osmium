//! A DNS stub resolver (RFC 1035) for IPv4 and IPv6 addresses.
//!
//! [`DnsClient`] puts a [`UdpSocket`] in the [`SocketSet`] for each query it
//! sends, on a fresh random port, and is polled like the other clients: [`resolve`](DnsClient::resolve) starts a lookup,
//! [`poll`](DnsClient::poll) sends queries, retries them with backoff and
//! reads the answers, and [`result`](DnsClient::result) takes the outcome.
//! It asks the servers it was given, or else the one DHCP reported. Answers
//! are cached for their TTL, failures for a short while.
//!
//! [`resolve`](DnsClient::resolve) asks for `A` records and
//! [`resolve6`](DnsClient::resolve6) for `AAAA` records (collect those with
//! [`result_ip`](DnsClient::result_ip)); a caller that wants both starts both
//! and prefers the family it can reach. Servers may be IPv4 or IPv6: the
//! ones the interface learned from DHCP and from router advertisements are
//! used unless some are set. A response is believed only if it arrives on
//! the port that query was sent from, from the address and port of the
//! server it was sent to, echoes the query's random id and question, and
//! its records belong to the name asked for (directly or through the
//! `CNAME`s that lead from it).
//!
//! A response that does not fit a datagram (TC set) is asked for again over
//! TCP (RFC 7766): the client opens a connection to the server that sent it,
//! sends the query with its two-byte length prefix, and reads the
//! length-prefixed answer, which may be larger than 512 bytes. The
//! connection lives in the same [`SocketSet`] and is closed afterwards. If it
//! cannot be had in time, the addresses the truncated response did carry are
//! used, or else the lookup fails with [`DnsError::Truncated`].

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use super::SocketHandle;
use crate::rng::Rng;
use crate::{Error, Instant, Interface, SocketSet, TcpSocket, TcpState, UdpSocket};

const SERVER_PORT: u16 = 53;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_CNAME: u16 = 5;
const CLASS_IN: u16 = 1;
const HEADER_LEN: usize = 12;
/// Lookups in progress at once.
const MAX_QUERIES: usize = 8;
const CACHE_ENTRIES: usize = 16;
/// Addresses kept per name.
const MAX_ADDRESSES: usize = 8;
/// CNAMEs followed in one answer.
const MAX_CHAIN: usize = 8;
/// Queries sent for one lookup, to rotating servers.
const ATTEMPTS: u8 = 4;
/// Wait before the first retry; it doubles each time.
const FIRST_TIMEOUT: Duration = Duration::from_secs(1);
/// How long a lookup waits for a server address before giving up.
const NO_SERVER_WAIT: Duration = Duration::from_secs(10);
const MAX_TTL: u32 = 24 * 3600;
const NEGATIVE_TTL: Duration = Duration::from_secs(30);
/// How long a result nobody collects is kept.
const RESULT_KEEP: Duration = Duration::from_secs(60);
/// The largest response read (EDNS is not used, so servers send at most
/// 512 bytes; a little more is tolerated).
const MAX_RESPONSE: usize = 1232;

/// How long a TCP lookup may take, handshake included.
const TCP_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest TCP response accepted; a longer one fails the lookup.
const MAX_TCP_RESPONSE: usize = 16 * 1024;
/// Buffers of the TCP socket: the response, and the one query.
const TCP_RX: usize = MAX_TCP_RESPONSE + 2;
const TCP_TX: usize = 512;
/// How long a finished TCP socket is given to close before it is removed.
const TCP_CLOSE_GRACE: Duration = Duration::from_secs(5);

/// Why a lookup failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    /// The name is empty, has an empty or over-long label, or has bytes a
    /// host name cannot.
    InvalidName,
    /// No server was configured or reported in time.
    NoServer,
    /// Too many lookups are in progress.
    TooManyQueries,
    /// The name does not exist.
    NameNotFound,
    /// The name exists but has no address of the kind asked for.
    NoAddress,
    /// The server failed or refused.
    ServerFailure,
    /// The response did not fit a datagram, and the TCP retry failed.
    Truncated,
    /// No server answered.
    Timeout,
    /// The lookup was cancelled, or its result already taken.
    Cancelled,
}

impl core::fmt::Display for DnsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            DnsError::InvalidName => "invalid name",
            DnsError::NoServer => "no DNS server",
            DnsError::TooManyQueries => "too many lookups",
            DnsError::NameNotFound => "name not found",
            DnsError::NoAddress => "no address",
            DnsError::ServerFailure => "DNS server failure",
            DnsError::Truncated => "DNS response truncated",
            DnsError::Timeout => "DNS lookup timed out",
            DnsError::Cancelled => "lookup cancelled",
        })
    }
}

impl core::error::Error for DnsError {}

/// A lookup started by [`DnsClient::resolve`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DnsQuery(u32);

type Outcome = Result<Vec<IpAddr>, DnsError>;

/// Where a lookup stands on the TCP retry.
enum Tcp {
    /// Not needed (yet).
    No,
    /// A server sent a truncated response: connect to it and ask again. The
    /// addresses it did give, and their TTL, are the fallback.
    Wanted { server: IpAddr, partial: Vec<IpAddr>, ttl: u32 },
    /// A [`TcpJob`] is working on it; UDP retries are off.
    Active,
}

/// A query in flight over TCP.
struct TcpJob {
    query: DnsQuery,
    socket: SocketHandle,
    started: Instant,
    /// Bytes received: a two-byte length and the message.
    buf: Vec<u8>,
    partial: Vec<IpAddr>,
    ttl: u32,
}

struct Query {
    handle: DnsQuery,
    tcp: Tcp,
    /// Lower case, without a trailing dot.
    name: String,
    /// The record type asked for, `TYPE_A` or `TYPE_AAAA`.
    qtype: u16,
    id: u16,
    /// The socket each attempt was sent from (a random port of its own), and
    /// the server it went to; only that server's answer to that socket counts.
    socks: Vec<(SocketHandle, SocketAddr)>,
    started: Instant,
    attempts: u8,
    next_try: Instant,
    result: Option<(Outcome, Instant)>,
}

struct CacheEntry {
    name: String,
    qtype: u16,
    outcome: Outcome,
    expires: Instant,
}

/// A DNS resolver; see the module documentation.
pub struct DnsClient {
    servers: Vec<IpAddr>,
    queries: Vec<Query>,
    cache: Vec<CacheEntry>,
    jobs: Vec<TcpJob>,
    /// TCP sockets that are done, closing, and when to give up on that.
    closing: Vec<(SocketHandle, Instant)>,
    /// Query sockets of lookups that are over, to remove at the next poll.
    dead: Vec<SocketHandle>,
    rng: Rng,
    next_handle: u32,
}

/// Lower-cases `name`, drops one trailing dot and checks it is a plausible
/// host name.
fn normalize(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > 253 {
        return None;
    }
    for label in name.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return None;
        }
    }
    Some(name.to_ascii_lowercase())
}

/// A query for the `qtype` record of `name`, which [`normalize`] accepted.
fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut m = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, one question
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&CLASS_IN.to_be_bytes());
    m
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// Reads the (possibly compressed) name at `pos` into `out`, lower-cased and
/// dot-separated. Returns the offset after the name where it started.
/// Compression pointers must point backwards, which rules out loops.
fn read_name(msg: &[u8], mut pos: usize, out: &mut String) -> Option<usize> {
    let mut end = None;
    loop {
        let len = *msg.get(pos)?;
        match len {
            0 => return Some(end.unwrap_or(pos + 1)),
            1..=63 => {
                let label = msg.get(pos + 1..pos + 1 + usize::from(len))?;
                if !out.is_empty() {
                    out.push('.');
                }
                out.extend(label.iter().map(|b| char::from(b.to_ascii_lowercase())));
                if out.len() > 253 {
                    return None;
                }
                pos += 1 + usize::from(len);
            }
            0xc0..=0xff => {
                let target = usize::from(be16(msg, pos)? & 0x3fff);
                if target >= pos {
                    return None;
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return None,
        }
    }
}

/// What a response said.
#[derive(Debug, PartialEq, Eq)]
struct Response {
    id: u16,
    rcode: u8,
    truncated: bool,
    /// The question's name.
    name: String,
    /// The question's type.
    qtype: u16,
    addresses: Vec<IpAddr>,
    /// The smallest TTL among the records used, in seconds.
    ttl: u32,
}

/// Parses a response to a query for the `A` or `AAAA` record of one name.
fn parse_response(msg: &[u8]) -> Option<Response> {
    let flags = be16(msg, 2)?;
    // A response (QR), to a standard query (opcode 0).
    if flags & 0xf800 != 0x8000 || be16(msg, 4)? != 1 {
        return None;
    }
    let mut name = String::new();
    let mut pos = read_name(msg, HEADER_LEN, &mut name)?;
    let qtype = be16(msg, pos)?;
    if !matches!(qtype, TYPE_A | TYPE_AAAA) || be16(msg, pos + 2)? != CLASS_IN {
        return None;
    }
    pos += 4;
    let mut r = Response {
        id: be16(msg, 0)?,
        rcode: (flags & 0xf) as u8,
        truncated: flags & 0x0200 != 0,
        name: name.clone(),
        qtype,
        addresses: Vec::new(),
        ttl: u32::MAX,
    };
    let mut chain = alloc::vec![name];
    for _ in 0..be16(msg, 6)? {
        let mut owner = String::new();
        pos = read_name(msg, pos, &mut owner)?;
        let (ty, class) = (be16(msg, pos)?, be16(msg, pos + 2)?);
        let ttl = u32::from_be_bytes(msg.get(pos + 4..pos + 8)?.try_into().ok()?);
        let len = usize::from(be16(msg, pos + 8)?);
        let data = pos + 10;
        msg.get(data..data + len)?;
        pos = data + len;
        if class != CLASS_IN || !chain.contains(&owner) {
            continue;
        }
        match ty {
            TYPE_CNAME if chain.len() < MAX_CHAIN => {
                let mut target = String::new();
                read_name(msg, data, &mut target)?;
                chain.push(target);
                r.ttl = r.ttl.min(ttl);
            }
            TYPE_A if qtype == TYPE_A && len == 4 && r.addresses.len() < MAX_ADDRESSES => {
                let ip = Ipv4Addr::new(msg[data], msg[data + 1], msg[data + 2], msg[data + 3]);
                // An answer is never a non-address.
                if !(ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()) {
                    r.addresses.push(ip.into());
                    r.ttl = r.ttl.min(ttl);
                }
            }
            TYPE_AAAA if qtype == TYPE_AAAA && len == 16 && r.addresses.len() < MAX_ADDRESSES => {
                let octets: [u8; 16] = msg[data..data + 16].try_into().ok()?;
                let ip = Ipv6Addr::from(octets);
                if !(ip.is_unspecified() || ip.is_multicast()) {
                    r.addresses.push(ip.into());
                    r.ttl = r.ttl.min(ttl);
                }
            }
            _ => {}
        }
    }
    Some(r)
}

impl DnsClient {
    /// A resolver whose ids and ports are drawn from `iface`'s random number
    /// generator.
    /// Servers come from the interface's configuration (DHCP) unless
    /// [`set_servers`](Self::set_servers) names some.
    pub fn new(iface: &mut Interface, _sockets: &mut SocketSet) -> Self {
        Self {
            servers: Vec::new(),
            queries: Vec::new(),
            cache: Vec::new(),
            jobs: Vec::new(),
            closing: Vec::new(),
            dead: Vec::new(),
            rng: Rng::new(iface.random_u64()),
            next_handle: 0,
        }
    }

    /// The servers to ask, in order of preference, instead of the one DHCP
    /// reported. An empty list goes back to that one.
    pub fn set_servers(&mut self, servers: &[Ipv4Addr]) {
        self.servers = servers.iter().copied().map(IpAddr::V4).collect();
    }

    /// Like [`set_servers`](Self::set_servers), with IPv4 and IPv6 servers.
    pub fn set_servers_ip(&mut self, servers: &[IpAddr]) {
        self.servers = servers.to_vec();
    }

    /// Starts looking up the IPv4 addresses of `name`. A dotted-quad is
    /// answered as itself, and a cached name at once; collect the result with
    /// [`result`](Self::result) after polling.
    pub fn resolve(&mut self, name: &str, now: Instant) -> Result<DnsQuery, DnsError> {
        self.start(name, TYPE_A, now)
    }

    /// Starts looking up the IPv6 addresses of `name` (`AAAA` records). An
    /// IPv6 literal is answered as itself. Collect the result with
    /// [`result_ip`](Self::result_ip).
    pub fn resolve6(&mut self, name: &str, now: Instant) -> Result<DnsQuery, DnsError> {
        self.start(name, TYPE_AAAA, now)
    }

    fn start(&mut self, name: &str, qtype: u16, now: Instant) -> Result<DnsQuery, DnsError> {
        let literal = match qtype {
            TYPE_A => name.parse::<Ipv4Addr>().ok().map(IpAddr::V4),
            _ => name.parse::<Ipv6Addr>().ok().map(IpAddr::V6),
        };
        let name = if literal.is_some() { String::new() } else { normalize(name).ok_or(DnsError::InvalidName)? };
        let handle = DnsQuery(self.next_handle);
        let mut query = Query {
            handle,
            tcp: Tcp::No,
            id: 0,
            socks: Vec::new(),
            started: now,
            attempts: 0,
            next_try: now,
            result: None,
            name: name.clone(),
            qtype,
        };
        if let Some(ip) = literal {
            query.result = Some((Ok(alloc::vec![ip]), now));
        } else if let Some(c) = self.cache.iter().find(|c| c.name == name && c.qtype == qtype && c.expires > now) {
            query.result = Some((c.outcome.clone(), now));
        } else {
            if self.queries.iter().filter(|q| q.result.is_none()).count() >= MAX_QUERIES {
                return Err(DnsError::TooManyQueries);
            }
            loop {
                query.id = self.rng.next_u32() as u16;
                if !self.queries.iter().any(|q| q.result.is_none() && q.id == query.id) {
                    break;
                }
            }
        }
        self.next_handle = self.next_handle.wrapping_add(1);
        self.queries.push(query);
        Ok(handle)
    }

    /// Takes the outcome of `query`: `None` while it is in progress, then
    /// the addresses (at least one) or the error. A query's outcome can be
    /// taken once.
    pub fn result(&mut self, query: DnsQuery) -> Option<Result<Vec<Ipv4Addr>, DnsError>> {
        Some(self.result_ip(query)?.map(|v| {
            v.into_iter()
                .filter_map(|a| match a {
                    IpAddr::V4(a) => Some(a),
                    IpAddr::V6(_) => None,
                })
                .collect()
        }))
    }

    /// Like [`result`](Self::result), with addresses of either family: the
    /// outcome of a [`resolve6`](Self::resolve6) lookup is collected here.
    pub fn result_ip(&mut self, query: DnsQuery) -> Option<Result<Vec<IpAddr>, DnsError>> {
        let i = self.queries.iter().position(|q| q.handle == query);
        let Some(i) = i else { return Some(Err(DnsError::Cancelled)) };
        self.queries[i].result.as_ref()?;
        let q = self.queries.remove(i);
        self.dead.extend(q.socks.iter().map(|&(h, _)| h));
        q.result.map(|(r, _)| r)
    }

    /// Abandons `query`.
    pub fn cancel(&mut self, query: DnsQuery) {
        for q in self.queries.iter().filter(|q| q.handle == query) {
            self.dead.extend(q.socks.iter().map(|&(h, _)| h));
        }
        self.queries.retain(|q| q.handle != query);
    }

    /// Returns true while any lookup is in progress.
    pub fn is_busy(&self) -> bool {
        self.queries.iter().any(|q| q.result.is_none())
    }

    /// When the client next needs polling if nothing arrives; the
    /// interface's own `poll_at` does not know about it, so a caller takes
    /// the earlier of the two.
    pub fn poll_at(&self) -> Option<Instant> {
        self.queries.iter().filter(|q| q.result.is_none()).map(|q| q.next_try).min()
    }

    fn servers(&self, iface: &Interface) -> Vec<IpAddr> {
        if self.servers.is_empty() {
            let v4 = iface.config().and_then(|c| c.dns).into_iter().map(IpAddr::V4);
            v4.chain(iface.ipv6_dns().iter().copied().map(IpAddr::V6)).collect()
        } else {
            self.servers.clone()
        }
    }

    fn finish(&mut self, i: usize, outcome: Outcome, ttl: Option<Duration>, now: Instant) {
        let q = &mut self.queries[i];
        q.result = Some((outcome.clone(), now));
        let Some(ttl) = ttl else { return };
        let entry = CacheEntry { name: q.name.clone(), qtype: q.qtype, outcome, expires: now + ttl };
        self.cache.retain(|c| !(c.name == entry.name && c.qtype == entry.qtype) && c.expires > now);
        if self.cache.len() >= CACHE_ENTRIES {
            self.cache.remove(0);
        }
        self.cache.push(entry);
    }

    /// Takes a response that reached one of query `i`'s sockets from the
    /// server that socket asked.
    fn handle_response(&mut self, i: usize, msg: &[u8], from: IpAddr, now: Instant) {
        let Some(r) = parse_response(msg) else { return };
        let q = &self.queries[i];
        if q.result.is_some() || q.id != r.id || q.name != r.name || q.qtype != r.qtype {
            return;
        }
        if r.truncated && r.rcode == 0 {
            // The answer is partial: get all of it over TCP. One attempt
            // only; a second truncated datagram changes nothing.
            if matches!(self.queries[i].tcp, Tcp::No) {
                self.queries[i].tcp = Tcp::Wanted { server: from, partial: r.addresses, ttl: r.ttl };
            }
            return;
        }
        self.apply(i, r, now);
    }

    /// Acts on a response that answers query `i`.
    fn apply(&mut self, i: usize, r: Response, now: Instant) {
        match r.rcode {
            0 if !r.addresses.is_empty() => {
                let ttl = (r.ttl > 0).then(|| Duration::from_secs(u64::from(r.ttl.min(MAX_TTL))));
                self.finish(i, Ok(r.addresses), ttl, now);
            }
            0 => self.finish(i, Err(DnsError::NoAddress), Some(NEGATIVE_TTL), now),
            3 => self.finish(i, Err(DnsError::NameNotFound), Some(NEGATIVE_TTL), now),
            // Another server may do better.
            _ if self.queries[i].attempts < ATTEMPTS => self.queries[i].next_try = now,
            _ => self.finish(i, Err(DnsError::ServerFailure), None, now),
        }
    }

    /// Starts the TCP retries that are wanted, moves their data, and tidies
    /// the sockets of those that are done.
    fn poll_tcp(&mut self, now: Instant, sockets: &mut SocketSet) {
        // Close the sockets of the jobs whose lookup ended, and reap.
        let mut j = 0;
        while j < self.jobs.len() {
            let ended = self.queries.iter().find(|q| q.handle == self.jobs[j].query).is_none_or(|q| q.result.is_some());
            if ended {
                let job = self.jobs.swap_remove(j);
                self.retire(job.socket, now, sockets);
            } else {
                j += 1;
            }
        }
        let mut c = 0;
        while c < self.closing.len() {
            let (handle, deadline) = self.closing[c];
            let done = matches!(sockets.get::<TcpSocket>(handle).state(), TcpState::Closed | TcpState::TimeWait);
            if done || now >= deadline {
                sockets.remove(handle);
                self.closing.swap_remove(c);
            } else {
                c += 1;
            }
        }

        // Start the wanted connections.
        for i in 0..self.queries.len() {
            if self.queries[i].result.is_some() || !matches!(self.queries[i].tcp, Tcp::Wanted { .. }) {
                continue;
            }
            let Tcp::Wanted { server, partial, ttl } = core::mem::replace(&mut self.queries[i].tcp, Tcp::Active) else {
                continue;
            };
            let q = &self.queries[i];
            let mut message = encode_query(q.id, &q.name, q.qtype);
            message.splice(0..0, (message.len() as u16).to_be_bytes());
            let mut socket = TcpSocket::new(TCP_RX, TCP_TX);
            // The query waits in the send buffer until the handshake is done.
            let started = socket.connect(SocketAddr::new(server, SERVER_PORT), 0).is_ok()
                && socket.send(&message) == Ok(message.len());
            if !started {
                self.tcp_failed(i, partial, ttl, now);
                continue;
            }
            self.jobs.push(TcpJob {
                query: q.handle,
                socket: sockets.add(socket),
                started: now,
                buf: Vec::new(),
                partial,
                ttl,
            });
            self.queries[i].next_try = now + TCP_TIMEOUT;
        }

        // Move data.
        let mut j = 0;
        while j < self.jobs.len() {
            let Some(i) = self.queries.iter().position(|q| q.handle == self.jobs[j].query) else {
                j += 1;
                continue;
            };
            let job = &mut self.jobs[j];
            let socket = sockets.get_mut::<TcpSocket>(job.socket);
            let mut chunk = [0u8; 512];
            let mut failed = socket.error().is_some() || now - job.started >= TCP_TIMEOUT;
            while !failed {
                match socket.recv(&mut chunk) {
                    Ok(0) => {
                        // The server closed before it finished answering.
                        failed = true;
                    }
                    Ok(n) if job.buf.len() + n <= TCP_RX => job.buf.extend_from_slice(&chunk[..n]),
                    Ok(_) => failed = true,
                    Err(_) => break,
                }
            }
            if !failed && socket.state() == TcpState::Closed {
                failed = true;
            }
            let reply = match job.buf.as_slice() {
                [hi, lo, rest @ ..] if rest.len() >= usize::from(u16::from_be_bytes([*hi, *lo])) => {
                    Some(&rest[..usize::from(u16::from_be_bytes([*hi, *lo]))])
                }
                _ => None,
            };
            if let Some(msg) = reply {
                // The connection is the server's: its answer need not be
                // checked against a source address, only against the query.
                let response = parse_response(msg).filter(|r| {
                    r.id == self.queries[i].id && r.name == self.queries[i].name && r.qtype == self.queries[i].qtype
                });
                let (partial, ttl) = (core::mem::take(&mut job.partial), job.ttl);
                match response {
                    // Truncation over TCP is no matter: take what there is.
                    Some(r) => self.apply(i, r, now),
                    None => self.tcp_failed(i, partial, ttl, now),
                }
            } else if failed {
                let (partial, ttl) = (core::mem::take(&mut job.partial), job.ttl);
                self.tcp_failed(i, partial, ttl, now);
            }
            // A finished query makes the next call retire the job.
            j += 1;
        }
    }

    /// Closes a job's socket and leaves it to be removed.
    fn retire(&mut self, socket: SocketHandle, now: Instant, sockets: &mut SocketSet) {
        sockets.get_mut::<TcpSocket>(socket).close();
        self.closing.push((socket, now + TCP_CLOSE_GRACE));
    }

    /// The TCP retry of query `i` did not work out: the addresses the
    /// truncated response carried will do, if it carried any.
    fn tcp_failed(&mut self, i: usize, partial: Vec<IpAddr>, ttl: u32, now: Instant) {
        if partial.is_empty() {
            self.finish(i, Err(DnsError::Truncated), None, now);
        } else {
            let ttl = (ttl > 0).then(|| Duration::from_secs(u64::from(ttl.min(MAX_TTL))));
            self.finish(i, Ok(partial), ttl, now);
        }
    }

    /// Reads responses, sends and retries queries, and expires old results.
    /// Call it whenever the interface is polled.
    pub fn poll(&mut self, now: Instant, iface: &Interface, sockets: &mut SocketSet) {
        let servers = self.servers(iface);
        self.remove_dead(sockets);
        let mut buf = [0u8; MAX_RESPONSE];
        for i in 0..self.queries.len() {
            for k in 0..self.queries[i].socks.len() {
                let (socket, server) = self.queries[i].socks[k];
                while let Ok((n, from)) = sockets.get_mut::<UdpSocket>(socket).recv_from(&mut buf) {
                    if n <= buf.len() && from == server && servers.contains(&server.ip()) {
                        self.handle_response(i, &buf[..n], from.ip(), now);
                    }
                }
            }
        }
        self.poll_tcp(now, sockets);

        for i in 0..self.queries.len() {
            let q = &self.queries[i];
            if q.result.is_none() && q.next_try <= now && matches!(q.tcp, Tcp::No) {
                if servers.is_empty() {
                    if now - q.started >= NO_SERVER_WAIT {
                        self.finish(i, Err(DnsError::NoServer), None, now);
                    } else {
                        self.queries[i].next_try = now + Duration::from_millis(250);
                    }
                    continue;
                }
                if q.attempts >= ATTEMPTS {
                    self.finish(i, Err(DnsError::Timeout), None, now);
                    continue;
                }
                let server = SocketAddr::new(servers[usize::from(q.attempts) % servers.len()], SERVER_PORT);
                let message = encode_query(q.id, &q.name, q.qtype);
                // A port of its own for each query, so that an off-path forger
                // must guess it as well as the id (RFC 5452).
                let any = if server.is_ipv6() { Ipv6Addr::UNSPECIFIED.into() } else { Ipv4Addr::UNSPECIFIED.into() };
                let mut socket = UdpSocket::new(4, 4);
                socket
                    .bind_addr(SocketAddr::new(any, sockets.free_ephemeral_port(&mut self.rng)))
                    .expect("a fresh socket binds");
                match socket.send_to(&message, server) {
                    Ok(()) => {
                        let q = &mut self.queries[i];
                        q.socks.push((sockets.add(socket), server));
                        q.next_try = now + FIRST_TIMEOUT * (1 << q.attempts);
                        q.attempts += 1;
                    }
                    // Try again at the next poll.
                    Err(Error::WouldBlock) => {}
                    Err(_) => self.finish(i, Err(DnsError::ServerFailure), None, now),
                }
            }
        }
        for q in &mut self.queries {
            if q.result.is_some() {
                self.dead.extend(q.socks.drain(..).map(|(h, _)| h));
            }
        }
        self.remove_dead(sockets);
        self.queries.retain(|q| q.result.as_ref().is_none_or(|(_, at)| now - *at < RESULT_KEEP));
    }

    /// Removes the sockets of queries that are over.
    fn remove_dead(&mut self, sockets: &mut SocketSet) {
        for h in self.dead.drain(..) {
            sockets.remove(h);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socket::Socket;
    use crate::testing::sa;
    use crate::testing::{A_IP, B_IP, Fate, Host, config, pair, run};

    /// A response to `query` with the given answer records appended, each
    /// `(owner name, type, ttl, data)`.
    fn response(query: &[u8], rcode: u8, answers: &[(&[u8], u16, u32, &[u8])]) -> Vec<u8> {
        let mut m = query.to_vec();
        m[2] = 0x81; // QR, RD
        m[3] = 0x80 | rcode; // RA
        m[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (owner, ty, ttl, data) in answers {
            m.extend_from_slice(owner);
            m.extend_from_slice(&ty.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&(data.len() as u16).to_be_bytes());
            m.extend_from_slice(data);
        }
        m
    }

    const Q: &[u8] = &[0xc0, 0x0c];
    const IP1: [u8; 4] = [93, 184, 216, 34];

    #[test]
    fn names() {
        assert_eq!(normalize("Example.COM.").as_deref(), Some("example.com"));
        for bad in ["", ".", "a..b", "a b.com", "-.\u{e9}.com", &"a".repeat(64), &["abc."; 70].concat()] {
            assert_eq!(normalize(bad), None, "{bad:?}");
        }
        assert_eq!(
            encode_query(0x1234, "a.bc", TYPE_A),
            [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]
        );
    }

    #[test]
    fn parses_cname_chains_and_ignores_unrelated_records() {
        let q = encode_query(7, "www.example.com", TYPE_A);
        // www.example.com -> cdn.example.com, the target compressed against the question.
        let cname_data = [3, b'c', b'd', b'n', 0xc0, 16]; // "cdn" + pointer to "example.com" at offset 16
        let m = response(
            &q,
            0,
            &[
                (Q, TYPE_CNAME, 300, &cname_data),
                (&[0xc0, 12 + 4], TYPE_A, 10, &[6, 6, 6, 6]), // owner "example.com": not in the chain
                (&[3, b'c', b'd', b'n', 0xc0, 16], TYPE_A, 60, &IP1),
                (Q, TYPE_A, 100, &[1, 2, 3, 4]),
            ],
        );
        let r = parse_response(&m).unwrap();
        assert_eq!((r.id, r.rcode, r.name.as_str()), (7, 0, "www.example.com"));
        assert_eq!(r.addresses, [IpAddr::from(IP1), IpAddr::from([1, 2, 3, 4])]);
        assert_eq!(r.ttl, 60);
    }

    #[test]
    fn rejects_malformed_responses() {
        let q = encode_query(7, "a.com", TYPE_A);
        let good = response(&q, 0, &[(Q, TYPE_A, 60, &IP1)]);
        assert!(parse_response(&good).is_some());
        for len in 0..good.len() {
            let _ = parse_response(&good[..len]); // never panics
        }
        assert_eq!(parse_response(&good[..good.len() - 1]), None, "short rdata");
        let mut not_response = good.clone();
        not_response[2] &= 0x7f;
        assert_eq!(parse_response(&not_response), None);
        let mut wrong_type = good.clone();
        wrong_type[12 + 7] = 28; // AAAA question
        assert_eq!(parse_response(&wrong_type), None);
        // A pointer to itself, and one forward.
        for ptr in [[0xc0, 12 + 7 + 4], [0xc0, 0xff]] {
            let m = response(&q, 0, &[(&ptr, TYPE_A, 60, &IP1)]);
            assert_eq!(parse_response(&m), None);
        }
        // An unspecified address is not an answer.
        let m = response(&q, 0, &[(Q, TYPE_A, 60, &[0, 0, 0, 0])]);
        assert!(parse_response(&m).unwrap().addresses.is_empty());
    }

    /// A DNS server on B that answers every name with `IP1`, counting the
    /// queries it sees and ignoring the first `ignore` of them.
    struct Server {
        socket: crate::SocketHandle,
        queries: usize,
        ignore: usize,
        ttl: u32,
        rcode: u8,
        /// Answer over UDP with TC set (and one address).
        truncate: bool,
        /// The TCP listener, if the server has one.
        tcp: Option<crate::SocketHandle>,
        tcp_queries: usize,
        tcp_rx: Vec<u8>,
        tcp_tx: Vec<u8>,
    }

    /// The addresses the TCP server gives.
    fn big_answer() -> Vec<IpAddr> {
        (1..=8).map(|n| IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))).collect()
    }

    impl Server {
        fn new(b: &mut Host) -> Self {
            let socket = b.sockets.add(UdpSocket::new(16, 16));
            b.sockets.get_mut::<UdpSocket>(socket).bind(53).unwrap();
            Self {
                socket,
                queries: 0,
                ignore: 0,
                ttl: 60,
                rcode: 0,
                truncate: false,
                tcp: None,
                tcp_queries: 0,
                tcp_rx: Vec::new(),
                tcp_tx: Vec::new(),
            }
        }

        fn listen(&mut self, b: &mut Host) {
            let mut socket = TcpSocket::new(4096, 4096);
            socket.listen(53).unwrap();
            self.tcp = Some(b.sockets.add(socket));
        }

        /// Serves one TCP connection, answering with more than 512 bytes and
        /// dribbling the reply out in pieces.
        fn serve_tcp(&mut self, b: &mut Host) {
            let Some(handle) = self.tcp else { return };
            let socket = b.sockets.get_mut::<TcpSocket>(handle);
            if !self.tcp_tx.is_empty() {
                let n = socket.send(&self.tcp_tx[..self.tcp_tx.len().min(100)]).unwrap_or(0);
                self.tcp_tx.drain(..n);
                if self.tcp_tx.is_empty() {
                    socket.close();
                }
                return;
            }
            let mut buf = [0u8; 600];
            if let Ok(n @ 1..) = socket.recv(&mut buf) {
                self.tcp_rx.extend_from_slice(&buf[..n]);
            }
            let [hi, lo, query @ ..] = self.tcp_rx.as_slice() else { return };
            if query.len() < usize::from(u16::from_be_bytes([*hi, *lo])) {
                return;
            }
            self.tcp_queries += 1;
            let query = query.to_vec();
            self.tcp_rx.clear();
            let noise = [7u8; 30];
            let addrs: Vec<[u8; 4]> = big_answer()
                .iter()
                .map(|a| match a {
                    IpAddr::V4(a) => a.octets(),
                    IpAddr::V6(_) => unreachable!("big_answer is IPv4"),
                })
                .collect();
            let mut answers: Vec<(&[u8], u16, u32, &[u8])> = (0..30).map(|_| (Q, 16, 60, &noise[..])).collect();
            answers.extend(addrs.iter().map(|a| (Q, TYPE_A, 60, &a[..])));
            let r = response(&query, 0, &answers);
            assert!(r.len() > 512, "the point is a response too big for UDP");
            self.tcp_tx = (r.len() as u16).to_be_bytes().to_vec();
            self.tcp_tx.extend_from_slice(&r);
            // The first byte alone, then the rest.
            let first: Vec<u8> = self.tcp_tx.drain(..1).collect();
            socket.send(&first).unwrap();
        }

        fn serve(&mut self, b: &mut Host) {
            let mut buf = [0u8; 600];
            while let Ok((n, from)) = b.sockets.get_mut::<UdpSocket>(self.socket).recv_from(&mut buf) {
                self.queries += 1;
                if self.ignore > 0 {
                    self.ignore -= 1;
                    continue;
                }
                let answers: &[(&[u8], u16, u32, &[u8])] = &[(Q, TYPE_A, self.ttl, &IP1)];
                let none: &[(&[u8], u16, u32, &[u8])] = &[];
                let mut r = response(&buf[..n], self.rcode, if self.rcode == 0 { answers } else { none });
                if self.truncate {
                    r[2] |= 0x02;
                }
                b.sockets.get_mut::<UdpSocket>(self.socket).send_to(&r, from).unwrap();
            }
            self.serve_tcp(b);
        }
    }

    struct Setup {
        a: Host,
        b: Host,
        dns: DnsClient,
        server: Server,
        now: Instant,
    }

    impl Setup {
        fn new() -> Self {
            let (mut a, mut b) = pair();
            a.iface.set_config(Some(crate::Config { dns: Some(B_IP), ..config(A_IP) }));
            let dns = DnsClient::new(&mut a.iface, &mut a.sockets);
            let server = Server::new(&mut b);
            Self { a, b, dns, server, now: Instant::ZERO }
        }

        /// Runs until `q` has an outcome or `limit` ms pass.
        fn wait(&mut self, q: DnsQuery, limit: u64) -> Option<Outcome> {
            let end = self.now.as_millis() + limit;
            while self.now.as_millis() < end {
                self.a.poll(self.now);
                self.b.poll(self.now);
                self.server.serve(&mut self.b);
                self.b.poll(self.now);
                self.dns.poll(self.now, &self.a.iface, &mut self.a.sockets);
                if let Some(r) = self.dns.result_ip(q) {
                    return Some(r);
                }
                self.now = Instant::from_millis(self.now.as_millis() + 1);
            }
            None
        }
    }

    #[test]
    fn resolves_and_caches() {
        let mut t = Setup::new();
        let q = t.dns.resolve("Example.Com", t.now).unwrap();
        assert_eq!(t.wait(q, 1000), Some(Ok(alloc::vec![IpAddr::from(IP1)])));
        assert_eq!(t.server.queries, 1);
        // Cached: answered by resolve itself, without a packet.
        let q = t.dns.resolve("example.com", t.now).unwrap();
        assert_eq!(t.dns.result_ip(q), Some(Ok(alloc::vec![IpAddr::from(IP1)])));
        assert_eq!(t.server.queries, 1);
        // After the TTL it asks again.
        t.now = t.now + Duration::from_secs(61);
        let q = t.dns.resolve("example.com", t.now).unwrap();
        assert_eq!(t.dns.result_ip(q), None);
        assert!(t.wait(q, 1000).unwrap().is_ok());
        assert_eq!(t.server.queries, 2);
        assert_eq!(t.dns.result_ip(q), Some(Err(DnsError::Cancelled)), "taken once");
    }

    #[test]
    fn truncated_responses_are_retried_over_tcp() {
        let mut t = Setup::new();
        t.server.truncate = true;
        t.server.listen(&mut t.b);
        let q = t.dns.resolve("big.example", t.now).unwrap();
        assert_eq!(t.wait(q, 5000), Some(Ok(big_answer())));
        assert_eq!((t.server.queries, t.server.tcp_queries), (1, 1));
        // The answer is cached, and the connection's socket is gone.
        let q = t.dns.resolve("big.example", t.now).unwrap();
        assert_eq!(t.dns.result_ip(q), Some(Ok(big_answer())));
        for _ in 0..200 {
            t.a.poll(t.now);
            t.b.poll(t.now);
            t.dns.poll(t.now, &t.a.iface, &mut t.a.sockets);
            t.now = Instant::from_millis(t.now.as_millis() + 1);
        }
        assert_eq!(t.a.sockets.iter().count(), 0, "the query and TCP sockets are gone");
        assert!(t.dns.jobs.is_empty() && t.dns.closing.is_empty());
    }

    #[test]
    fn a_failed_tcp_retry_falls_back_to_the_partial_answer() {
        // Nobody listens on TCP port 53: the connection is refused, and the
        // address the truncated response carried is used.
        let mut t = Setup::new();
        t.server.truncate = true;
        let q = t.dns.resolve("part.example", t.now).unwrap();
        assert_eq!(t.wait(q, 5000), Some(Ok(alloc::vec![IpAddr::V4(Ipv4Addr::from(IP1))])));
        assert_eq!(t.server.queries, 1, "no UDP retry while TCP was tried");

        // A truncated response with no address at all.
        let mut t = Setup::new();
        t.server.truncate = true;
        t.server.rcode = 0;
        let q = t.dns.resolve("none.example", t.now).unwrap();
        // Make the UDP answer carry none by dropping its records: rcode 0
        // with TC and no answers.
        let mut query = encode_query(t.dns.queries[0].id, "none.example", TYPE_A);
        query[2] = 0x83;
        query[3] = 0x80;
        t.dns.handle_response(0, &query, IpAddr::V4(B_IP), t.now);
        assert_eq!(t.wait(q, 5000), Some(Err(DnsError::Truncated)));
    }

    #[test]
    fn a_silent_tcp_server_times_out() {
        let mut t = Setup::new();
        t.server.truncate = true;
        t.server.listen(&mut t.b);
        // The server accepts but never answers: B's TCP replies are dropped
        // after the handshake.
        t.b.set_shaper(|n, _| if n > 4 { Fate::Drop } else { Fate::Deliver });
        let q = t.dns.resolve("slow.example", t.now).unwrap();
        let start = t.now;
        assert_eq!(t.wait(q, 20_000), Some(Ok(alloc::vec![IpAddr::V4(Ipv4Addr::from(IP1))])));
        assert!((TCP_TIMEOUT..TCP_TIMEOUT + Duration::from_secs(1)).contains(&(t.now - start)));
    }

    #[test]
    fn literals_and_bad_names() {
        let mut t = Setup::new();
        let q = t.dns.resolve("10.1.2.3", t.now).unwrap();
        assert_eq!(t.dns.result_ip(q), Some(Ok(alloc::vec![IpAddr::from([10, 1, 2, 3])])));
        assert_eq!(t.dns.resolve("not a name", t.now), Err(DnsError::InvalidName));
        for _ in 0..MAX_QUERIES {
            t.dns.resolve("busy.example", t.now).unwrap();
        }
        assert_eq!(t.dns.resolve("one.more", t.now), Err(DnsError::TooManyQueries));
    }

    #[test]
    fn retries_lost_queries_and_responses() {
        let mut t = Setup::new();
        t.server.ignore = 2; // the first two queries get no answer
        let q = t.dns.resolve("slow.example", t.now).unwrap();
        let start = t.now;
        assert!(t.wait(q, 10_000).unwrap().is_ok());
        assert_eq!(t.server.queries, 3);
        let waited = (t.now - start).as_millis();
        assert!((3000..3100).contains(&waited), "1 s then 2 s backoff: {waited} ms");

        // Everything lost: gives up after four tries (1 + 2 + 4 + 8 s).
        let mut t = Setup::new();
        t.b.set_shaper(|n, _| if n > 1 { Fate::Drop } else { Fate::Deliver });
        let q = t.dns.resolve("gone.example", t.now).unwrap();
        assert_eq!(t.wait(q, 30_000), Some(Err(DnsError::Timeout)));
        assert_eq!(t.server.queries, 4);
        assert!(!t.dns.is_busy());
    }

    #[test]
    fn duplicated_and_reordered_responses() {
        let mut t = Setup::new();
        t.b.set_shaper(|n, _| match n % 3 {
            1 => Fate::Delay(1),
            2 => Fate::Duplicate,
            _ => Fate::Deliver,
        });
        let first = t.dns.resolve("one.example", t.now).unwrap();
        let second = t.dns.resolve("two.example", t.now).unwrap();
        let (mut r1, mut r2) = (None, None);
        for _ in 0..3000 {
            t.a.poll(t.now);
            t.b.poll(t.now);
            t.server.serve(&mut t.b);
            t.b.poll(t.now);
            t.dns.poll(t.now, &t.a.iface, &mut t.a.sockets);
            r1 = r1.or(t.dns.result_ip(first));
            r2 = r2.or(t.dns.result_ip(second));
            t.now = Instant::from_millis(t.now.as_millis() + 1);
            if r1.is_some() && r2.is_some() {
                break;
            }
        }
        assert_eq!(r1, Some(Ok(alloc::vec![IpAddr::from(IP1)])));
        assert_eq!(r2, Some(Ok(alloc::vec![IpAddr::from(IP1)])));
    }

    #[test]
    fn nxdomain_is_cached_briefly_and_servfail_is_retried() {
        let mut t = Setup::new();
        t.server.rcode = 3;
        let q = t.dns.resolve("nope.example", t.now).unwrap();
        assert_eq!(t.wait(q, 1000), Some(Err(DnsError::NameNotFound)));
        let q = t.dns.resolve("nope.example", t.now).unwrap();
        assert_eq!(t.dns.result_ip(q), Some(Err(DnsError::NameNotFound)));
        assert_eq!(t.server.queries, 1);
        t.now = t.now + Duration::from_secs(31);
        t.server.rcode = 0;
        let q = t.dns.resolve("nope.example", t.now).unwrap();
        assert!(t.wait(q, 1000).unwrap().is_ok(), "the negative entry expired");

        let mut t = Setup::new();
        t.server.rcode = 2;
        let q = t.dns.resolve("broken.example", t.now).unwrap();
        assert_eq!(t.wait(q, 1000), Some(Err(DnsError::ServerFailure)));
        assert_eq!(t.server.queries, usize::from(ATTEMPTS));
    }

    #[test]
    fn forged_responses_are_ignored() {
        let mut t = Setup::new();
        let q = t.dns.resolve("victim.example", t.now).unwrap();
        t.a.poll(t.now);
        t.dns.poll(t.now, &t.a.iface, &mut t.a.sockets);
        let (sock, server) = t.dns.queries[0].socks[0];
        assert_eq!(server, sa(B_IP, 53));
        let port = t.a.sockets.get::<UdpSocket>(sock).local_endpoint().unwrap().port();
        assert!(port >= 49152, "a random port");
        let query_id = t.dns.queries[0].id;
        let evil = [6, 6, 6, 6];
        let spoof = |id: u16, name: &str, from_port: u16| {
            let mut m = response(&encode_query(id, name, TYPE_A), 0, &[(Q, TYPE_A, 600, &evil)]);
            m[..2].copy_from_slice(&id.to_be_bytes());
            (m, from_port)
        };
        // Wrong id, wrong question, wrong source port: all dropped.
        let attempts = [
            spoof(query_id ^ 1, "victim.example", 53),
            spoof(query_id, "other.example", 53),
            spoof(query_id, "victim.example", 5353),
        ];
        let mut now = t.now;
        for (m, from_port) in attempts {
            t.b.sockets.get_mut::<UdpSocket>(t.server.socket).close();
            let s = t.b.sockets.get_mut::<UdpSocket>(t.server.socket);
            s.bind(from_port).unwrap();
            s.send_to(&m, sa(A_IP, port)).unwrap();
            run(&mut t.a, &mut t.b, &mut now, 5, |_, _| false);
            t.dns.poll(now, &t.a.iface, &mut t.a.sockets);
            assert_eq!(t.dns.result_ip(q), None);
        }
        // The real server's answer still gets through.
        t.b.sockets.get_mut::<UdpSocket>(t.server.socket).close();
        t.b.sockets.get_mut::<UdpSocket>(t.server.socket).bind(53).unwrap();
        t.now = now;
        assert_eq!(t.wait(q, 3000), Some(Ok(alloc::vec![IpAddr::from(IP1)])));
    }

    #[test]
    fn each_query_has_its_own_port_and_answers_only_reach_their_own() {
        let mut t = Setup::new();
        let q1 = t.dns.resolve("one.example", t.now).unwrap();
        let q2 = t.dns.resolve("two.example", t.now).unwrap();
        t.a.poll(t.now);
        t.dns.poll(t.now, &t.a.iface, &mut t.a.sockets);
        let port_of = |t: &Setup, i: usize| {
            let (sock, _) = t.dns.queries[i].socks[0];
            t.a.sockets.get::<UdpSocket>(sock).local_endpoint().unwrap().port()
        };
        let (p1, p2) = (port_of(&t, 0), port_of(&t, 1));
        assert_ne!(p1, p2);
        // A well-formed answer to the first query (right id, question and
        // server address and port) arriving on the second query's port.
        let evil = [6, 6, 6, 6];
        let id1 = t.dns.queries[0].id;
        let forged = response(&encode_query(id1, "one.example", TYPE_A), 0, &[(Q, TYPE_A, 600, &evil)]);
        t.b.sockets.get_mut::<UdpSocket>(t.server.socket).close();
        let s = t.b.sockets.get_mut::<UdpSocket>(t.server.socket);
        s.bind(53).unwrap();
        s.send_to(&forged, sa(A_IP, p2)).unwrap();
        let mut now = t.now;
        run(&mut t.a, &mut t.b, &mut now, 5, |_, _| false);
        t.dns.poll(now, &t.a.iface, &mut t.a.sockets);
        assert_eq!(t.dns.result_ip(q1), None, "an answer on another query's port is not believed");
        // On its own port the same datagram is accepted.
        t.b.sockets.get_mut::<UdpSocket>(t.server.socket).send_to(&forged, sa(A_IP, p1)).unwrap();
        run(&mut t.a, &mut t.b, &mut now, 5, |_, _| false);
        t.dns.poll(now, &t.a.iface, &mut t.a.sockets);
        assert_eq!(t.dns.result_ip(q1), Some(Ok(alloc::vec![IpAddr::from(Ipv4Addr::from(evil))])));
        t.dns.cancel(q2);
        t.dns.poll(now, &t.a.iface, &mut t.a.sockets);
        assert!(t.a.sockets.iter().all(|(_, s)| !matches!(s, Socket::Udp(_))), "query sockets are removed");
    }

    #[test]
    fn waits_for_a_server_to_be_configured() {
        let mut t = Setup::new();
        let old = t.a.iface.config();
        t.a.iface.set_config(Some(crate::Config { dns: None, ..old.unwrap() }));
        let q = t.dns.resolve("later.example", t.now).unwrap();
        assert_eq!(t.wait(q, 2000), None, "still waiting");
        t.a.iface.set_config(old);
        assert!(t.wait(q, 2000).unwrap().is_ok());

        let mut t = Setup::new();
        t.a.iface.set_config(Some(crate::Config { dns: None, ..t.a.iface.config().unwrap() }));
        let q = t.dns.resolve("never.example", t.now).unwrap();
        assert_eq!(t.wait(q, 12_000), Some(Err(DnsError::NoServer)));
        // Explicit servers need no DHCP.
        t.dns.set_servers(&[B_IP]);
        let q = t.dns.resolve("now.example", t.now).unwrap();
        assert!(t.wait(q, 2000).unwrap().is_ok());
    }

    #[test]
    fn parses_aaaa_answers_and_keeps_the_families_apart() {
        let aaaa = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let q = encode_query(9, "v6.example", TYPE_AAAA);
        let m = response(
            &q,
            0,
            &[
                (Q, TYPE_A, 60, &IP1), // an A record does not answer an AAAA question
                (Q, TYPE_AAAA, 120, &aaaa.octets()),
                (Q, TYPE_AAAA, 90, &Ipv6Addr::UNSPECIFIED.octets()),
                (Q, TYPE_AAAA, 90, &[1, 2, 3]), // wrong length
            ],
        );
        let r = parse_response(&m).unwrap();
        assert_eq!((r.qtype, r.addresses, r.ttl), (TYPE_AAAA, alloc::vec![IpAddr::V6(aaaa)], 120));
        let q = encode_query(9, "v4.example", TYPE_A);
        let m = response(&q, 0, &[(Q, TYPE_AAAA, 120, &aaaa.octets())]);
        assert!(parse_response(&m).unwrap().addresses.is_empty());
    }

    #[test]
    fn resolves_aaaa_through_an_ipv6_server() {
        let aaaa = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);
        let (mut a, mut b, mut now) = crate::testing::pair6();
        let server_addr = b.iface.ipv6_link_local().unwrap();
        let mut dns = DnsClient::new(&mut a.iface, &mut a.sockets);
        dns.set_servers_ip(&[IpAddr::V6(server_addr)]);
        let server = b.sockets.add(UdpSocket::new(8, 8));
        b.sockets.get_mut::<UdpSocket>(server).bind_addr(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 53)).unwrap();

        let q6 = dns.resolve6("Host.Example", now).unwrap();
        let q4 = dns.resolve("Host.Example", now).unwrap();
        assert_eq!(
            dns.resolve6("::1", now).map(|q| dns.result_ip(q)),
            Ok(Some(Ok(alloc::vec![Ipv6Addr::LOCALHOST.into()])))
        );
        let (mut r6, mut r4) = (None, None);
        for _ in 0..2000 {
            a.poll(now);
            b.poll(now);
            let mut buf = [0u8; 600];
            while let Ok((n, from)) = b.sockets.get_mut::<UdpSocket>(server).recv_from(&mut buf) {
                // AAAA gets an address; A gets an empty answer.
                let is_aaaa = buf[n - 3] == TYPE_AAAA as u8;
                let answers: &[(&[u8], u16, u32, &[u8])] =
                    if is_aaaa { &[(Q, TYPE_AAAA, 60, &aaaa.octets())] } else { &[] };
                let r = response(&buf[..n], 0, answers);
                b.sockets.get_mut::<UdpSocket>(server).send_to(&r, from).unwrap();
            }
            b.poll(now);
            dns.poll(now, &a.iface, &mut a.sockets);
            r6 = r6.or(dns.result_ip(q6));
            r4 = r4.or(dns.result(q4));
            now = Instant::from_millis(now.as_millis() + 1);
            if r6.is_some() && r4.is_some() {
                break;
            }
        }
        assert_eq!(r6, Some(Ok(alloc::vec![IpAddr::V6(aaaa)])));
        assert_eq!(r4, Some(Err(DnsError::NoAddress)));
        assert!(a.sockets.iter().all(|(_, s)| !matches!(s, Socket::Udp(_))), "query sockets are removed");
        // The AAAA answer is cached apart from the A lookup.
        let again = dns.resolve6("host.example", now).unwrap();
        assert_eq!(dns.result_ip(again), Some(Ok(alloc::vec![IpAddr::V6(aaaa)])));
    }
}

#[cfg(test)]
mod fuzz_tests {
    use super::*;
    use crate::wire::fuzz_tests::rand;

    #[test]
    fn arbitrary_responses_do_not_panic() {
        let mut state = 0x0bad_cafe_f00d_5eed;
        let mut query = encode_query(7, "www.example.com", TYPE_A);
        // A response with a compressed answer name, to mutate.
        query[2] = 0x81;
        query[3] = 0x80;
        query[7] = 1;
        let question_end = query.len();
        query.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0, 0, 4, 1, 2, 3, 4]);
        assert!(parse_response(&query).is_some());
        for _ in 0..30_000 {
            let mut m = query.clone();
            for _ in 0..1 + rand(&mut state) % 4 {
                let at = (rand(&mut state) % m.len() as u64) as usize;
                m[at] = rand(&mut state) as u8;
            }
            if rand(&mut state) % 4 == 0 {
                m.truncate(question_end + (rand(&mut state) % 17) as usize);
            }
            let _ = parse_response(&m);
        }
        for _ in 0..10_000 {
            let raw: Vec<u8> = (0..rand(&mut state) % 80).map(|_| rand(&mut state) as u8).collect();
            let _ = parse_response(&raw);
        }
    }
}
