//! A DNS stub resolver (RFC 1035) for IPv4 addresses.
//!
//! [`DnsClient`] owns a [`UdpSocket`] in the [`SocketSet`] and is polled
//! like the other clients: [`resolve`](DnsClient::resolve) starts a lookup,
//! [`poll`](DnsClient::poll) sends queries, retries them with backoff and
//! reads the answers, and [`result`](DnsClient::result) takes the outcome.
//! It asks the servers it was given, or else the one DHCP reported. Answers
//! are cached for their TTL, failures for a short while.
//!
//! Only `A` records are asked for. A response is believed only if it comes
//! from a configured server, echoes the query's random id and question, and
//! its records belong to the name asked for (directly or through the
//! `CNAME`s that lead from it). A truncated response (TC) is an error: there
//! is no TCP fallback.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::time::Duration;

use super::SocketHandle;
use crate::rng::Rng;
use crate::{Error, Instant, Interface, SocketSet, UdpSocket};

const SERVER_PORT: u16 = 53;
const TYPE_A: u16 = 1;
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
    /// The name exists but has no IPv4 address.
    NoAddress,
    /// The server failed or refused.
    ServerFailure,
    /// The response did not fit a datagram (and TCP is not used).
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
            DnsError::NoAddress => "no IPv4 address",
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

type Outcome = Result<Vec<Ipv4Addr>, DnsError>;

struct Query {
    handle: DnsQuery,
    /// Lower case, without a trailing dot.
    name: String,
    id: u16,
    started: Instant,
    attempts: u8,
    next_try: Instant,
    result: Option<(Outcome, Instant)>,
}

struct CacheEntry {
    name: String,
    outcome: Outcome,
    expires: Instant,
}

/// A DNS resolver; see the module documentation.
pub struct DnsClient {
    socket: SocketHandle,
    servers: Vec<Ipv4Addr>,
    queries: Vec<Query>,
    cache: Vec<CacheEntry>,
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

/// A query for the `A` record of `name`, which [`normalize`] accepted.
fn encode_query(id: u16, name: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(HEADER_LEN + name.len() + 6);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD, one question
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&TYPE_A.to_be_bytes());
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
    addresses: Vec<Ipv4Addr>,
    /// The smallest TTL among the records used, in seconds.
    ttl: u32,
}

/// Parses a response to a query for the `A` record of one name.
fn parse_response(msg: &[u8]) -> Option<Response> {
    let flags = be16(msg, 2)?;
    // A response (QR), to a standard query (opcode 0).
    if flags & 0xf800 != 0x8000 || be16(msg, 4)? != 1 {
        return None;
    }
    let mut name = String::new();
    let mut pos = read_name(msg, HEADER_LEN, &mut name)?;
    if (be16(msg, pos)?, be16(msg, pos + 2)?) != (TYPE_A, CLASS_IN) {
        return None;
    }
    pos += 4;
    let mut r = Response {
        id: be16(msg, 0)?,
        rcode: (flags & 0xf) as u8,
        truncated: flags & 0x0200 != 0,
        name: name.clone(),
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
            TYPE_A if len == 4 && r.addresses.len() < MAX_ADDRESSES => {
                let ip = Ipv4Addr::new(msg[data], msg[data + 1], msg[data + 2], msg[data + 3]);
                // An answer is never a non-address.
                if !(ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast()) {
                    r.addresses.push(ip);
                    r.ttl = r.ttl.min(ttl);
                }
            }
            _ => {}
        }
    }
    Some(r)
}

impl DnsClient {
    /// A resolver with its socket added to `sockets`, bound to a random
    /// port, and its ids drawn from `iface`'s random number generator.
    /// Servers come from the interface's configuration (DHCP) unless
    /// [`set_servers`](Self::set_servers) names some.
    pub fn new(iface: &mut Interface, sockets: &mut SocketSet) -> Self {
        let mut socket = UdpSocket::new(8, 8);
        socket.bind(iface.ephemeral_port()).expect("a fresh socket binds");
        Self {
            socket: sockets.add(socket),
            servers: Vec::new(),
            queries: Vec::new(),
            cache: Vec::new(),
            rng: Rng::new(iface.random_u64()),
            next_handle: 0,
        }
    }

    /// The servers to ask, in order of preference, instead of the one DHCP
    /// reported. An empty list goes back to that one.
    pub fn set_servers(&mut self, servers: &[Ipv4Addr]) {
        self.servers = servers.to_vec();
    }

    /// The socket handle, so that a caller can remove the socket.
    pub fn socket(&self) -> SocketHandle {
        self.socket
    }

    /// Starts looking up the IPv4 addresses of `name`. A dotted-quad is
    /// answered as itself, and a cached name at once; collect the result with
    /// [`result`](Self::result) after polling.
    pub fn resolve(&mut self, name: &str, now: Instant) -> Result<DnsQuery, DnsError> {
        let literal = name.parse::<Ipv4Addr>().ok();
        let name = normalize(name).ok_or(DnsError::InvalidName)?;
        let handle = DnsQuery(self.next_handle);
        let mut query =
            Query { handle, id: 0, started: now, attempts: 0, next_try: now, result: None, name: name.clone() };
        if let Some(ip) = literal {
            query.result = Some((Ok(alloc::vec![ip]), now));
        } else if let Some(c) = self.cache.iter().find(|c| c.name == name && c.expires > now) {
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
        let i = self.queries.iter().position(|q| q.handle == query);
        let Some(i) = i else { return Some(Err(DnsError::Cancelled)) };
        self.queries[i].result.as_ref()?;
        self.queries.remove(i).result.map(|(r, _)| r)
    }

    /// Abandons `query`.
    pub fn cancel(&mut self, query: DnsQuery) {
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

    fn servers(&self, iface: &Interface) -> Vec<Ipv4Addr> {
        if self.servers.is_empty() {
            iface.config().and_then(|c| c.dns).into_iter().collect()
        } else {
            self.servers.clone()
        }
    }

    fn finish(&mut self, i: usize, outcome: Outcome, ttl: Option<Duration>, now: Instant) {
        let q = &mut self.queries[i];
        q.result = Some((outcome.clone(), now));
        let Some(ttl) = ttl else { return };
        let entry = CacheEntry { name: q.name.clone(), outcome, expires: now + ttl };
        self.cache.retain(|c| c.name != entry.name && c.expires > now);
        if self.cache.len() >= CACHE_ENTRIES {
            self.cache.remove(0);
        }
        self.cache.push(entry);
    }

    fn handle_response(&mut self, msg: &[u8], now: Instant) {
        let Some(r) = parse_response(msg) else { return };
        let Some(i) = self.queries.iter().position(|q| q.result.is_none() && q.id == r.id && q.name == r.name) else {
            return;
        };
        match r.rcode {
            0 if !r.addresses.is_empty() => {
                let ttl = (r.ttl > 0).then(|| Duration::from_secs(u64::from(r.ttl.min(MAX_TTL))));
                self.finish(i, Ok(r.addresses), ttl, now);
            }
            0 if r.truncated => self.finish(i, Err(DnsError::Truncated), None, now),
            0 => self.finish(i, Err(DnsError::NoAddress), Some(NEGATIVE_TTL), now),
            3 => self.finish(i, Err(DnsError::NameNotFound), Some(NEGATIVE_TTL), now),
            // Another server may do better.
            _ if self.queries[i].attempts < ATTEMPTS => self.queries[i].next_try = now,
            _ => self.finish(i, Err(DnsError::ServerFailure), None, now),
        }
    }

    /// Reads responses, sends and retries queries, and expires old results.
    /// Call it whenever the interface is polled.
    pub fn poll(&mut self, now: Instant, iface: &Interface, sockets: &mut SocketSet) {
        let servers = self.servers(iface);
        let mut buf = [0u8; MAX_RESPONSE];
        while let Ok((n, from)) = sockets.get_mut::<UdpSocket>(self.socket).recv_from(&mut buf) {
            if n <= buf.len() && from.port() == SERVER_PORT && servers.contains(from.ip()) {
                self.handle_response(&buf[..n], now);
            }
        }

        for i in 0..self.queries.len() {
            let q = &self.queries[i];
            if q.result.is_none() && q.next_try <= now {
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
                let server = SocketAddrV4::new(servers[usize::from(q.attempts) % servers.len()], SERVER_PORT);
                let message = encode_query(q.id, &q.name);
                match sockets.get_mut::<UdpSocket>(self.socket).send_to(&message, server) {
                    Ok(()) => {
                        let q = &mut self.queries[i];
                        q.next_try = now + FIRST_TIMEOUT * (1 << q.attempts);
                        q.attempts += 1;
                    }
                    // Try again at the next poll.
                    Err(Error::WouldBlock) => {}
                    Err(_) => self.finish(i, Err(DnsError::ServerFailure), None, now),
                }
            }
        }
        self.queries.retain(|q| q.result.as_ref().is_none_or(|(_, at)| now - *at < RESULT_KEEP));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            encode_query(0x1234, "a.bc"),
            [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 2, b'b', b'c', 0, 0, 1, 0, 1]
        );
    }

    #[test]
    fn parses_cname_chains_and_ignores_unrelated_records() {
        let q = encode_query(7, "www.example.com");
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
        assert_eq!(r.addresses, [Ipv4Addr::from(IP1), Ipv4Addr::new(1, 2, 3, 4)]);
        assert_eq!(r.ttl, 60);
    }

    #[test]
    fn rejects_malformed_responses() {
        let q = encode_query(7, "a.com");
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
    }

    impl Server {
        fn new(b: &mut Host) -> Self {
            let socket = b.sockets.add(UdpSocket::new(16, 16));
            b.sockets.get_mut::<UdpSocket>(socket).bind(53).unwrap();
            Self { socket, queries: 0, ignore: 0, ttl: 60, rcode: 0 }
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
                let r = response(&buf[..n], self.rcode, if self.rcode == 0 { answers } else { none });
                b.sockets.get_mut::<UdpSocket>(self.socket).send_to(&r, from).unwrap();
            }
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
                if let Some(r) = self.dns.result(q) {
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
        assert_eq!(t.wait(q, 1000), Some(Ok(alloc::vec![Ipv4Addr::from(IP1)])));
        assert_eq!(t.server.queries, 1);
        // Cached: answered by resolve itself, without a packet.
        let q = t.dns.resolve("example.com", t.now).unwrap();
        assert_eq!(t.dns.result(q), Some(Ok(alloc::vec![Ipv4Addr::from(IP1)])));
        assert_eq!(t.server.queries, 1);
        // After the TTL it asks again.
        t.now = t.now + Duration::from_secs(61);
        let q = t.dns.resolve("example.com", t.now).unwrap();
        assert_eq!(t.dns.result(q), None);
        assert!(t.wait(q, 1000).unwrap().is_ok());
        assert_eq!(t.server.queries, 2);
        assert_eq!(t.dns.result(q), Some(Err(DnsError::Cancelled)), "taken once");
    }

    #[test]
    fn literals_and_bad_names() {
        let mut t = Setup::new();
        let q = t.dns.resolve("10.1.2.3", t.now).unwrap();
        assert_eq!(t.dns.result(q), Some(Ok(alloc::vec![Ipv4Addr::new(10, 1, 2, 3)])));
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
            r1 = r1.or(t.dns.result(first));
            r2 = r2.or(t.dns.result(second));
            t.now = Instant::from_millis(t.now.as_millis() + 1);
            if r1.is_some() && r2.is_some() {
                break;
            }
        }
        assert_eq!(r1, Some(Ok(alloc::vec![Ipv4Addr::from(IP1)])));
        assert_eq!(r2, Some(Ok(alloc::vec![Ipv4Addr::from(IP1)])));
    }

    #[test]
    fn nxdomain_is_cached_briefly_and_servfail_is_retried() {
        let mut t = Setup::new();
        t.server.rcode = 3;
        let q = t.dns.resolve("nope.example", t.now).unwrap();
        assert_eq!(t.wait(q, 1000), Some(Err(DnsError::NameNotFound)));
        let q = t.dns.resolve("nope.example", t.now).unwrap();
        assert_eq!(t.dns.result(q), Some(Err(DnsError::NameNotFound)));
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
        let port = t.a.sockets.get::<UdpSocket>(t.dns.socket()).local_endpoint().unwrap().port();
        let query_id = t.dns.queries[0].id;
        let evil = [6, 6, 6, 6];
        let spoof = |id: u16, name: &str, from_port: u16| {
            let mut m = response(&encode_query(id, name), 0, &[(Q, TYPE_A, 600, &evil)]);
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
            s.send_to(&m, SocketAddrV4::new(A_IP, port)).unwrap();
            run(&mut t.a, &mut t.b, &mut now, 5, |_, _| false);
            t.dns.poll(now, &t.a.iface, &mut t.a.sockets);
            assert_eq!(t.dns.result(q), None);
        }
        // The real server's answer still gets through.
        t.b.sockets.get_mut::<UdpSocket>(t.server.socket).close();
        t.b.sockets.get_mut::<UdpSocket>(t.server.socket).bind(53).unwrap();
        t.now = now;
        assert_eq!(t.wait(q, 3000), Some(Ok(alloc::vec![Ipv4Addr::from(IP1)])));
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
}
