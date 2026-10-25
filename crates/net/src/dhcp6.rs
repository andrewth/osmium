//! A DHCPv6 client (RFC 8415): stateful, leasing addresses (an IA_NA) and
//! DNS servers, or stateless, asking only for configuration such as DNS
//! servers with an Information-request (RFC 8415 section 18.2.6).
//!
//! [`Message`] is the wire format, with a parser that treats every length as
//! hostile. [`Dhcp6Client`] runs the exchanges over a UDP socket of the
//! [`SocketSet`] and applies what it learns to the
//! [`Interface`]: addresses with their lifetimes, and DNS servers.
//!
//! Which mode to run is up to the caller; the router advertisement's
//! managed and other-configuration flags
//! ([`Interface::ipv6_ra_flags`]) say what the network offers.
//!
//! The client:
//!
//! - solicits, collects advertisements for the first retransmission time and
//!   takes the one with the highest preference (255 at once), requests the
//!   addresses, renews at T1, rebinds at T2, and starts over when the lease
//!   runs out or the server no longer knows it;
//! - retransmits with the randomized exponential backoff of RFC 8415
//!   section 15, keeping one transaction id for an exchange;
//! - checks the transaction id, its own DUID, and (after the advertisement)
//!   the server's, and ignores addresses that are unusable or whose
//!   preferred lifetime exceeds the valid one;
//! - never renews more often than every 30 seconds, whatever a server says.
//!
//! Prefix delegation, reconfigure, rapid commit and unicast to the server are
//! not supported.

use alloc::vec::Vec;
use core::net::{Ipv6Addr, SocketAddr};
use core::time::Duration;

use osmium_hal::net::MacAddress;

use crate::rng::Rng;
use crate::socket::SocketSet;
use crate::socket::udp::UdpSocket;
use crate::{Error, Instant, Interface, SocketHandle};

/// UDP port clients listen on.
pub const CLIENT_PORT: u16 = 546;
/// UDP port servers and relay agents listen on.
pub const SERVER_PORT: u16 = 547;
/// `All_DHCP_Relay_Agents_and_Servers`, `ff02::1:2`.
pub const ALL_SERVERS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// Message type: Solicit.
pub const SOLICIT: u8 = 1;
/// Message type: Advertise.
pub const ADVERTISE: u8 = 2;
/// Message type: Request.
pub const REQUEST: u8 = 3;
/// Message type: Renew.
pub const RENEW: u8 = 5;
/// Message type: Rebind.
pub const REBIND: u8 = 6;
/// Message type: Reply.
pub const REPLY: u8 = 7;
/// Message type: Release.
pub const RELEASE: u8 = 8;
/// Message type: Information-request.
pub const INFORMATION_REQUEST: u8 = 11;

const OPT_CLIENTID: u16 = 1;
const OPT_SERVERID: u16 = 2;
const OPT_IA_NA: u16 = 3;
const OPT_IAADDR: u16 = 5;
const OPT_ORO: u16 = 6;
const OPT_PREFERENCE: u16 = 7;
const OPT_ELAPSED_TIME: u16 = 8;
const OPT_STATUS_CODE: u16 = 13;
const OPT_RAPID_COMMIT: u16 = 14;
const OPT_DNS_SERVERS: u16 = 23;
const OPT_INFO_REFRESH_TIME: u16 = 32;

/// Status code: success.
pub const STATUS_SUCCESS: u16 = 0;
/// Status code: no addresses are available.
pub const STATUS_NO_ADDRS_AVAIL: u16 = 2;
/// Status code: the server has no binding for the client.
pub const STATUS_NO_BINDING: u16 = 3;

/// The longest DUID (RFC 8415 section 11.1) plus its two-byte type.
const MAX_DUID: usize = 130;
/// IA_NA options kept from a message.
const MAX_IA: usize = 4;
/// Addresses kept from an IA_NA.
const MAX_IA_ADDRS: usize = 8;
/// DNS servers kept from a message.
const MAX_DNS_SERVERS: usize = 4;
/// Messages longer than this are not looked at.
const MAX_MESSAGE: usize = 2048;

/// A lifetime of "forever".
const INFINITY: u32 = u32::MAX;
/// The shortest time between renewals, whatever T1 says.
const MIN_T1: u32 = 30;
/// The shortest information refresh time (`IRT_MINIMUM`, RFC 8415 section
/// 7.6).
const MIN_REFRESH: u32 = 600;
/// The information refresh time when the server names none
/// (`IRT_DEFAULT`).
const DEFAULT_REFRESH: u32 = 86_400;
/// Longest wait before the first message (`SOL_MAX_DELAY`).
const MAX_DELAY: Duration = Duration::from_secs(1);

/// An address with its lifetimes in an IA_NA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IaAddr {
    /// The address.
    pub addr: Ipv6Addr,
    /// Seconds it is preferred.
    pub preferred: u32,
    /// Seconds it is valid.
    pub valid: u32,
    /// A status code the address came with.
    pub status: Option<u16>,
}

/// An identity association for non-temporary addresses (IA_NA).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct IaNa {
    /// The association's identifier.
    pub iaid: u32,
    /// Seconds until the client should renew, 0 for the client to choose.
    pub t1: u32,
    /// Seconds until the client should rebind, 0 for the client to choose.
    pub t2: u32,
    /// The addresses.
    pub addrs: Vec<IaAddr>,
    /// A status code for the whole association.
    pub status: Option<u16>,
}

/// A DHCPv6 client/server message.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Message {
    /// Message type.
    pub ty: u8,
    /// Transaction id (24 bits).
    pub xid: u32,
    /// The client's DUID.
    pub client_id: Option<Vec<u8>>,
    /// The server's DUID.
    pub server_id: Option<Vec<u8>>,
    /// Non-temporary address associations.
    pub ia_na: Vec<IaNa>,
    /// A status code for the whole message.
    pub status: Option<u16>,
    /// The server's preference, 0 if absent.
    pub preference: u8,
    /// Centiseconds since the client began the exchange.
    pub elapsed: Option<u16>,
    /// Option codes the client asks for.
    pub oro: Vec<u16>,
    /// DNS servers.
    pub dns: Vec<Ipv6Addr>,
    /// Seconds until the client should ask for configuration again.
    pub info_refresh: Option<u32>,
    /// The rapid commit option is present.
    pub rapid_commit: bool,
}

fn be16(b: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(*b.first_chunk()?))
}

fn be32(b: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(*b.first_chunk()?))
}

/// The options of `b` as `(code, value)`, or `None` if one overruns.
fn options(mut b: &[u8]) -> Option<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let code = be16(b)?;
        let len = usize::from(be16(b.get(2..)?)?);
        let value = b.get(4..)?.get(..len)?;
        b = b.get(4 + len..)?;
        out.push((code, value));
        // An option list this long is an attack, not a message.
        if out.len() > 256 {
            return None;
        }
    }
    Some(out)
}

fn status(value: &[u8]) -> Option<u16> {
    be16(value)
}

fn duid(value: &[u8]) -> Option<Vec<u8>> {
    (value.len() >= 2 && value.len() <= MAX_DUID).then(|| value.to_vec())
}

impl IaNa {
    fn parse(value: &[u8]) -> Option<Self> {
        let mut ia =
            Self { iaid: be32(value)?, t1: be32(value.get(4..)?)?, t2: be32(value.get(8..)?)?, ..Self::default() };
        for (code, v) in options(value.get(12..)?)? {
            match code {
                OPT_IAADDR => {
                    let addr = Ipv6Addr::from(*v.first_chunk::<16>()?);
                    let (preferred, valid) = (be32(v.get(16..)?)?, be32(v.get(20..)?)?);
                    let mut a = IaAddr { addr, preferred, valid, status: None };
                    for (code, v) in options(v.get(24..)?)? {
                        if code == OPT_STATUS_CODE && a.status.is_none() {
                            a.status = Some(status(v)?);
                        }
                    }
                    if ia.addrs.len() < MAX_IA_ADDRS {
                        ia.addrs.push(a);
                    }
                }
                OPT_STATUS_CODE if ia.status.is_none() => ia.status = Some(status(v)?),
                _ => {}
            }
        }
        Some(ia)
    }
}

fn put_option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(value.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
    out.extend_from_slice(value);
}

impl Message {
    /// Parses a message. Returns `None` if it is truncated or any option's
    /// length overruns its container. Unknown options are skipped, repeated
    /// ones count once, and lists are cut to a sensible length.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() > MAX_MESSAGE {
            return None;
        }
        let mut m = Self { ty: *b.first()?, xid: be32(b)? & 0xff_ffff, ..Self::default() };
        for (code, v) in options(b.get(4..)?)? {
            match code {
                OPT_CLIENTID if m.client_id.is_none() => m.client_id = Some(duid(v)?),
                OPT_SERVERID if m.server_id.is_none() => m.server_id = Some(duid(v)?),
                OPT_IA_NA => {
                    let ia = IaNa::parse(v)?;
                    if m.ia_na.len() < MAX_IA {
                        m.ia_na.push(ia);
                    }
                }
                OPT_STATUS_CODE if m.status.is_none() => m.status = Some(status(v)?),
                OPT_PREFERENCE => m.preference = *v.first()?,
                OPT_ELAPSED_TIME => m.elapsed = Some(be16(v)?),
                OPT_ORO => {
                    if v.len() % 2 != 0 {
                        return None;
                    }
                    m.oro = v.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).take(32).collect();
                }
                OPT_DNS_SERVERS => {
                    if v.len() % 16 != 0 {
                        return None;
                    }
                    let servers = v.as_chunks::<16>().0.iter().map(|c| Ipv6Addr::from(*c));
                    m.dns = servers.take(MAX_DNS_SERVERS).collect();
                }
                OPT_INFO_REFRESH_TIME => m.info_refresh = Some(be32(v)?),
                OPT_RAPID_COMMIT => m.rapid_commit = true,
                _ => {}
            }
        }
        Some(m)
    }

    /// The message's bytes.
    pub fn emit(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.push(self.ty);
        out.extend_from_slice(&[(self.xid >> 16) as u8, (self.xid >> 8) as u8, self.xid as u8]);
        if let Some(id) = &self.client_id {
            put_option(&mut out, OPT_CLIENTID, id);
        }
        if let Some(id) = &self.server_id {
            put_option(&mut out, OPT_SERVERID, id);
        }
        if let Some(e) = self.elapsed {
            put_option(&mut out, OPT_ELAPSED_TIME, &e.to_be_bytes());
        }
        if self.ty == ADVERTISE || self.preference != 0 {
            put_option(&mut out, OPT_PREFERENCE, &[self.preference]);
        }
        if let Some(s) = self.status {
            put_option(&mut out, OPT_STATUS_CODE, &s.to_be_bytes());
        }
        for ia in &self.ia_na {
            let mut v = Vec::with_capacity(12 + 28 * ia.addrs.len());
            for n in [ia.iaid, ia.t1, ia.t2] {
                v.extend_from_slice(&n.to_be_bytes());
            }
            for a in &ia.addrs {
                let mut x = Vec::with_capacity(24);
                x.extend_from_slice(&a.addr.octets());
                x.extend_from_slice(&a.preferred.to_be_bytes());
                x.extend_from_slice(&a.valid.to_be_bytes());
                if let Some(s) = a.status {
                    put_option(&mut x, OPT_STATUS_CODE, &s.to_be_bytes());
                }
                put_option(&mut v, OPT_IAADDR, &x);
            }
            if let Some(s) = ia.status {
                put_option(&mut v, OPT_STATUS_CODE, &s.to_be_bytes());
            }
            put_option(&mut out, OPT_IA_NA, &v);
        }
        if !self.oro.is_empty() {
            let v: Vec<u8> = self.oro.iter().flat_map(|c| c.to_be_bytes()).collect();
            put_option(&mut out, OPT_ORO, &v);
        }
        if !self.dns.is_empty() {
            let v: Vec<u8> = self.dns.iter().flat_map(|a| a.octets()).collect();
            put_option(&mut out, OPT_DNS_SERVERS, &v);
        }
        if let Some(t) = self.info_refresh {
            put_option(&mut out, OPT_INFO_REFRESH_TIME, &t.to_be_bytes());
        }
        if self.rapid_commit {
            put_option(&mut out, OPT_RAPID_COMMIT, &[]);
        }
        out
    }
}

/// The DUID-LL (RFC 8415 section 11.4) of an Ethernet interface.
pub fn duid_ll(mac: MacAddress) -> Vec<u8> {
    let mut d = alloc::vec![0, 3, 0, 1];
    d.extend_from_slice(&mac.0);
    d
}

/// What the client is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dhcp6State {
    /// Not started: waiting for a link-local address.
    Idle,
    /// Looking for servers.
    Soliciting,
    /// Asking the chosen server for its addresses.
    Requesting,
    /// Holding a lease.
    Bound,
    /// Asking the lease's server to extend it (T1 has passed).
    Renewing,
    /// Asking any server to extend it (T2 has passed).
    Rebinding,
    /// Asking for configuration only.
    Informing,
    /// Has configuration; will ask again after the refresh time.
    Informed,
    /// Giving the lease back.
    Releasing,
    /// Stopped by [`Dhcp6Client::release`].
    Released,
}

/// What happened, as [`Dhcp6Client::poll`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dhcp6Event {
    /// Addresses (or, for a stateless client, configuration) were obtained.
    Configured,
    /// A lease was extended or configuration refreshed.
    Renewed,
    /// The lease ran out or was withdrawn, and its addresses were removed.
    Lost,
    /// The lease was given back.
    Released,
}

/// What a DHCPv6 mode asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Leases an address (IA_NA) and DNS servers.
    Stateful,
    /// Asks for DNS servers and other configuration only, for a network
    /// whose addresses come from router advertisements.
    Stateless,
}

/// An address the client holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeasedAddress {
    /// The address.
    pub addr: Ipv6Addr,
    /// Seconds it was preferred for, from when it was granted.
    pub preferred: u32,
    /// Seconds it was valid for, from when it was granted.
    pub valid: u32,
}

/// A lease.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    /// The addresses.
    pub addresses: Vec<LeasedAddress>,
    /// DNS servers.
    pub dns: Vec<Ipv6Addr>,
    /// The leasing server's DUID.
    pub server_id: Vec<u8>,
    /// When it was granted or last extended.
    pub granted: Instant,
}

/// A message in flight and when to send it again (RFC 8415 section 15).
struct Exchange {
    ty: u8,
    xid: u32,
    /// When the exchange began, for the elapsed-time option.
    started: Instant,
    /// When to send next.
    next: Instant,
    /// The current retransmission time.
    rt: Duration,
    /// Messages sent.
    count: u8,
    irt: Duration,
    mrt: Duration,
    /// Messages to send before giving up, 0 for no limit.
    mrc: u8,
    /// When to give up.
    deadline: Option<Instant>,
}

/// A DHCPv6 client. See the [module](self) documentation.
pub struct Dhcp6Client {
    mode: Mode,
    socket: SocketHandle,
    rng: Rng,
    duid: Vec<u8>,
    iaid: u32,
    state: Dhcp6State,
    ex: Option<Exchange>,
    /// The best advertisement so far, and when to stop waiting for better.
    advert: Option<Message>,
    select_at: Option<Instant>,
    /// The server a lease is with.
    server: Option<Vec<u8>>,
    lease: Option<Lease>,
    t1_at: Option<Instant>,
    t2_at: Option<Instant>,
    expires_at: Option<Instant>,
    refresh_at: Option<Instant>,
    informed: bool,
    dns: Vec<Ipv6Addr>,
}

/// The `(retransmission time, first)` rule: `prev` is the last time, `None`
/// for the first.
fn next_rt(rng: &mut Rng, prev: Option<Duration>, irt: Duration, mrt: Duration, solicit: bool) -> Duration {
    // A random factor in [-0.1, 0.1] (for the first Solicit, [0, 0.1]) of
    // `base`, in thousandths.
    let mut jitter = |base: Duration| -> Duration {
        let ms = i64::try_from(base.as_millis()).unwrap_or(i64::MAX / 1000);
        let permille = i64::from(rng.next_u32() % 201) - 100;
        let permille = if prev.is_none() && solicit { permille.abs() } else { permille };
        let delta = ms.saturating_mul(permille) / 1000;
        Duration::from_millis(ms.saturating_add(delta).max(1) as u64)
    };
    match prev {
        None => jitter(irt),
        Some(p) => {
            let doubled = jitter(p.saturating_mul(2));
            if doubled > mrt { jitter(mrt) } else { doubled }
        }
    }
}

impl Dhcp6Client {
    /// A client of `mode` using a new UDP socket in `sockets`, bound to port
    /// 546. Fails if the port is taken. IPv6 must be enabled on `iface`;
    /// the client waits for a link-local address.
    pub fn new(iface: &mut Interface, sockets: &mut SocketSet, mode: Mode) -> Result<Self, Error> {
        let mut socket = UdpSocket::new(8, 8);
        let any = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), CLIENT_PORT);
        if sockets.iter().any(|(_, s)| matches!(s, crate::Socket::Udp(u) if u.local_endpoint() == Some(any))) {
            return Err(Error::InvalidAddress);
        }
        socket.bind_addr(any)?;
        let mac = iface.mac_address();
        let [.., a, b, c, d] = mac.0;
        Ok(Self {
            mode,
            socket: sockets.add(socket),
            rng: Rng::new(iface.random_u64()),
            duid: duid_ll(mac),
            iaid: u32::from_be_bytes([a, b, c, d]),
            state: Dhcp6State::Idle,
            ex: None,
            advert: None,
            select_at: None,
            server: None,
            lease: None,
            t1_at: None,
            t2_at: None,
            expires_at: None,
            refresh_at: None,
            informed: false,
            dns: Vec::new(),
        })
    }

    /// The client's DUID.
    pub fn duid(&self) -> &[u8] {
        &self.duid
    }

    /// What the client is doing.
    pub fn state(&self) -> Dhcp6State {
        self.state
    }

    /// The lease, while one is held.
    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    /// The DNS servers learned.
    pub fn dns(&self) -> &[Ipv6Addr] {
        &self.dns
    }

    /// When [`poll`](Self::poll) next has something to do.
    pub fn poll_at(&self) -> Option<Instant> {
        if matches!(self.state, Dhcp6State::Idle) {
            return Some(Instant::ZERO);
        }
        let timers = [
            self.ex.as_ref().map(|e| e.next),
            self.select_at.filter(|_| self.advert.is_some()),
            self.t1_at.filter(|_| matches!(self.state, Dhcp6State::Bound)),
            self.refresh_at.filter(|_| matches!(self.state, Dhcp6State::Informed)),
            self.expires_at,
        ];
        timers.into_iter().flatten().min()
    }

    /// Gives the lease back and stops: the addresses are removed from
    /// `iface` and a Release is sent (and retransmitted up to four times
    /// until a Reply). Does nothing without a lease.
    pub fn release(&mut self, now: Instant, iface: &mut Interface) {
        if self.server.is_none()
            || self.lease.is_none()
            || !matches!(self.state, Dhcp6State::Bound | Dhcp6State::Renewing | Dhcp6State::Rebinding)
        {
            return;
        }
        self.state = Dhcp6State::Releasing;
        self.begin(RELEASE, now, now, Duration::from_secs(1), Duration::from_secs(1), 4, None);
        for a in self.lease.iter().flat_map(|l| l.addresses.iter()) {
            iface.remove_ipv6_address(a.addr);
        }
        self.clear_timers();
    }

    /// Starts again from the beginning, after [`release`](Self::release) or
    /// to force a fresh lease. Addresses held stay until they expire.
    pub fn restart(&mut self) {
        self.state = Dhcp6State::Idle;
        self.ex = None;
        self.lease = None;
        self.server = None;
        self.advert = None;
        self.select_at = None;
        self.clear_timers();
    }

    fn clear_timers(&mut self) {
        self.t1_at = None;
        self.t2_at = None;
        self.expires_at = None;
        self.refresh_at = None;
    }

    /// Reads replies, sends and retransmits messages, and applies leases to
    /// `iface`. Call it whenever the interface is polled. Returns the first
    /// event that happened, if any.
    pub fn poll(&mut self, now: Instant, iface: &mut Interface, sockets: &mut SocketSet) -> Option<Dhcp6Event> {
        if !iface.ipv6_enabled() || iface.ipv6_link_local().is_none() {
            return None;
        }
        let mut event = None;
        let mut buf = [0u8; MAX_MESSAGE];
        while let Some(Ok((n, from))) = sockets.try_get_mut::<UdpSocket>(self.socket).map(|s| s.recv_from(&mut buf)) {
            if from.port() == SERVER_PORT
                && let Some(msg) = buf.get(..n).and_then(Message::parse)
            {
                let e = self.handle(now, iface, msg);
                event = event.or(e);
            }
        }
        if matches!(self.state, Dhcp6State::Idle) {
            let delay = self.start_delay();
            self.start(now, now + delay);
        }
        let e = self.timers(now, iface);
        event = event.or(e);
        let e = self.send_due(now, sockets, iface);
        event.or(e)
    }

    /// A random wait before the first message, so that hosts that start
    /// together do not all call at once.
    fn start_delay(&mut self) -> Duration {
        Duration::from_millis(u64::from(self.rng.next_u32()) % (MAX_DELAY.as_millis() as u64 + 1))
    }

    fn start(&mut self, now: Instant, first: Instant) {
        self.advert = None;
        self.select_at = None;
        self.server = None;
        match self.mode {
            Mode::Stateful => {
                self.state = Dhcp6State::Soliciting;
                self.begin(SOLICIT, now, first, Duration::from_secs(1), Duration::from_secs(3600), 0, None);
            }
            Mode::Stateless => self.start_info(now, first),
        }
    }

    fn start_info(&mut self, now: Instant, first: Instant) {
        self.state = Dhcp6State::Informing;
        let (irt, mrt) = (Duration::from_secs(1), Duration::from_secs(3600));
        self.begin(INFORMATION_REQUEST, now, first, irt, mrt, 0, None);
    }

    #[allow(clippy::too_many_arguments)] // the parameters of RFC 8415 section 15
    fn begin(
        &mut self,
        ty: u8,
        now: Instant,
        first: Instant,
        irt: Duration,
        mrt: Duration,
        mrc: u8,
        deadline: Option<Instant>,
    ) {
        self.ex = Some(Exchange {
            ty,
            xid: self.rng.next_u32() & 0xff_ffff,
            started: first.max(now),
            next: first,
            rt: Duration::ZERO,
            count: 0,
            irt,
            mrt,
            mrc,
            deadline,
        });
    }

    /// Transitions that depend on time rather than on messages.
    fn timers(&mut self, now: Instant, iface: &mut Interface) -> Option<Dhcp6Event> {
        use Dhcp6State::*;
        if matches!(self.state, Bound | Renewing | Rebinding) && self.expires_at.is_some_and(|t| now >= t) {
            return Some(self.lose(now, iface));
        }
        match self.state {
            Soliciting if self.select_at.is_some_and(|t| now >= t) && self.advert.is_some() => self.request(now),
            Bound if self.t1_at.is_some_and(|t| now >= t) => {
                self.state = Renewing;
                let (irt, mrt) = (Duration::from_secs(10), Duration::from_secs(600));
                self.begin(RENEW, now, now, irt, mrt, 0, self.t2_at);
            }
            Informed if self.refresh_at.is_some_and(|t| now >= t) => self.start_info(now, now),
            _ => {}
        }
        None
    }

    /// The lease is gone: remove its addresses and begin again.
    fn lose(&mut self, now: Instant, iface: &mut Interface) -> Dhcp6Event {
        for a in self.lease.iter().flat_map(|l| l.addresses.iter()) {
            iface.remove_ipv6_address(a.addr);
        }
        self.lease = None;
        self.clear_timers();
        let delay = self.start_delay();
        self.start(now, now + delay);
        Dhcp6Event::Lost
    }

    /// Moves from Soliciting to Requesting with the advertisement held.
    fn request(&mut self, now: Instant) {
        let Some(server) = self.advert.as_ref().and_then(|a| a.server_id.clone()) else { return };
        self.server = Some(server);
        self.state = Dhcp6State::Requesting;
        self.select_at = None;
        self.begin(REQUEST, now, now, Duration::from_secs(1), Duration::from_secs(30), 10, None);
    }

    /// Sends the message of the exchange if it is due, or gives up on it.
    fn send_due(&mut self, now: Instant, sockets: &mut SocketSet, iface: &mut Interface) -> Option<Dhcp6Event> {
        let ex = self.ex.as_ref()?;
        if ex.next > now {
            return None;
        }
        if ex.deadline.is_some_and(|d| now >= d) || (ex.mrc > 0 && ex.count >= ex.mrc) {
            return self.exhausted(now, iface);
        }
        let message = self.message(now)?;
        let bytes = message.emit();
        if let Some(s) = sockets.try_get_mut::<UdpSocket>(self.socket) {
            let _ = s.send_to(&bytes, SocketAddr::new(ALL_SERVERS.into(), SERVER_PORT));
        }
        let ex = self.ex.as_mut()?;
        let prev = (ex.count > 0).then_some(ex.rt);
        ex.rt = next_rt(&mut self.rng, prev, ex.irt, ex.mrt, ex.ty == SOLICIT);
        ex.count = ex.count.saturating_add(1);
        // Wake up in time to give up when the exchange runs out of time.
        ex.next = ex.deadline.map_or(now + ex.rt, |d| (now + ex.rt).min(d));
        None
    }

    /// The message the current exchange sends.
    fn message(&self, now: Instant) -> Option<Message> {
        let ex = self.ex.as_ref()?;
        let elapsed = (now - ex.started).as_millis() / 10;
        let mut m = Message {
            ty: ex.ty,
            xid: ex.xid,
            client_id: Some(self.duid.clone()),
            elapsed: Some(u16::try_from(elapsed).unwrap_or(u16::MAX)),
            oro: alloc::vec![OPT_DNS_SERVERS],
            ..Message::default()
        };
        let ia = |addrs: Vec<IaAddr>| IaNa { iaid: self.iaid, addrs, ..IaNa::default() };
        let leased = || {
            let leased = self.lease.iter().flat_map(|l| l.addresses.iter());
            leased.map(|a| IaAddr { addr: a.addr, preferred: 0, valid: 0, status: None }).collect::<Vec<_>>()
        };
        match ex.ty {
            SOLICIT => m.ia_na.push(ia(Vec::new())),
            REQUEST => {
                m.server_id = self.server.clone();
                let offered = self.advert.iter().flat_map(|a| a.ia_na.iter()).find(|i| i.iaid == self.iaid);
                let addrs = offered.map(|i| i.addrs.iter().map(|a| IaAddr { status: None, ..*a }).collect());
                m.ia_na.push(ia(addrs.unwrap_or_default()));
            }
            RENEW | RELEASE => {
                m.server_id = self.server.clone();
                m.ia_na.push(ia(leased()));
            }
            REBIND => m.ia_na.push(ia(leased())),
            INFORMATION_REQUEST => m.oro.push(OPT_INFO_REFRESH_TIME),
            _ => return None,
        }
        Some(m)
    }

    /// An exchange ran out of time or attempts.
    fn exhausted(&mut self, now: Instant, iface: &mut Interface) -> Option<Dhcp6Event> {
        use Dhcp6State::*;
        match self.state {
            Requesting => {
                let delay = self.start_delay();
                self.start(now, now + delay);
            }
            Renewing => {
                self.state = Rebinding;
                let (irt, mrt) = (Duration::from_secs(10), Duration::from_secs(600));
                self.begin(REBIND, now, now, irt, mrt, 0, self.expires_at);
            }
            Rebinding => return Some(self.lose(now, iface)),
            Releasing => return Some(self.released()),
            _ => self.ex = None,
        }
        None
    }

    fn released(&mut self) -> Dhcp6Event {
        self.state = Dhcp6State::Released;
        self.ex = None;
        self.lease = None;
        self.server = None;
        Dhcp6Event::Released
    }

    /// What the client makes of a message from a server.
    fn handle(&mut self, now: Instant, iface: &mut Interface, msg: Message) -> Option<Dhcp6Event> {
        use Dhcp6State::*;
        if msg.client_id.as_deref() != Some(self.duid.as_slice()) {
            return None;
        }
        if self.ex.as_ref()?.xid != msg.xid {
            return None;
        }
        match (self.state, msg.ty) {
            (Soliciting, ADVERTISE) => {
                self.on_advertise(now, msg);
                None
            }
            (Requesting | Renewing | Rebinding, REPLY) => self.on_lease_reply(now, iface, msg),
            (Informing, REPLY) => self.on_info_reply(now, iface, msg),
            (Releasing, REPLY) if msg.server_id.is_some() && msg.server_id == self.server => Some(self.released()),
            _ => None,
        }
    }

    /// The addresses of `msg`'s association that can be used, with its
    /// timers; `None` if the association is missing, failed or malformed.
    /// The addresses whose lifetime is 0 (withdrawn) come second.
    fn usable(&self, msg: &Message) -> Option<(u32, u32, Vec<IaAddr>, Vec<Ipv6Addr>)> {
        let ia = msg.ia_na.iter().find(|i| i.iaid == self.iaid)?;
        if ia.status.is_some_and(|s| s != STATUS_SUCCESS) || (ia.t1 != 0 && ia.t2 != 0 && ia.t1 > ia.t2) {
            return None;
        }
        let mut good = Vec::new();
        let mut withdrawn = Vec::new();
        for a in &ia.addrs {
            let unusable = a.addr.is_unspecified()
                || a.addr.is_multicast()
                || a.addr.is_loopback()
                || crate::ipv6::is_link_local(a.addr);
            if unusable || a.status.is_some_and(|s| s != STATUS_SUCCESS) || a.preferred > a.valid {
                continue;
            }
            if a.valid == 0 {
                withdrawn.push(a.addr);
            } else {
                good.push(*a);
            }
        }
        Some((ia.t1, ia.t2, good, withdrawn))
    }

    fn on_advertise(&mut self, now: Instant, msg: Message) {
        let server = msg.server_id.is_some();
        let ok = msg.status.is_none_or(|s| s == STATUS_SUCCESS);
        if !server || !ok || self.usable(&msg).is_none_or(|(_, _, good, _)| good.is_empty()) {
            return;
        }
        let Some(ex) = self.ex.as_ref() else { return };
        // Wait out the first retransmission time for a better one, unless
        // the server is the most preferred there can be.
        let select_at = if msg.preference == 255 || ex.count > 1 { now } else { ex.next };
        if msg.preference == 255 {
            self.advert = Some(msg);
            self.select_at = Some(now);
        } else if self.advert.as_ref().is_none_or(|best| msg.preference > best.preference) {
            self.advert = Some(msg);
            self.select_at.get_or_insert(select_at);
        }
    }

    fn on_lease_reply(&mut self, now: Instant, iface: &mut Interface, msg: Message) -> Option<Dhcp6Event> {
        let was_requesting = matches!(self.state, Dhcp6State::Requesting);
        let server = msg.server_id.clone()?;
        if !matches!(self.state, Dhcp6State::Rebinding) && Some(&server) != self.server.as_ref() {
            return None;
        }
        match msg.status {
            Some(STATUS_NO_ADDRS_AVAIL) => return self.start_over(now),
            Some(s) if s != STATUS_SUCCESS => return None,
            _ => {}
        }
        let ia = msg.ia_na.iter().find(|i| i.iaid == self.iaid)?;
        match ia.status {
            Some(STATUS_NO_BINDING) if !was_requesting => {
                // The server forgot the lease: ask for the same addresses again.
                let held = self.lease.as_ref()?;
                let addrs = held.addresses.iter().map(|a| IaAddr {
                    addr: a.addr,
                    preferred: a.preferred,
                    valid: a.valid,
                    status: None,
                });
                let again = Message {
                    server_id: Some(server),
                    ia_na: alloc::vec![IaNa { iaid: self.iaid, addrs: addrs.collect(), ..IaNa::default() }],
                    ..Message::default()
                };
                self.advert = Some(again);
                self.request(now);
                return None;
            }
            Some(STATUS_NO_ADDRS_AVAIL) => return self.start_over(now),
            _ => {}
        }
        let (ia_t1, ia_t2, good, withdrawn) = self.usable(&msg)?;
        if good.is_empty() && withdrawn.is_empty() {
            return None;
        }
        // Addresses the server took back.
        for w in &withdrawn {
            iface.remove_ipv6_address(*w);
        }
        let mut addresses: Vec<LeasedAddress> = self
            .lease
            .iter()
            .flat_map(|l| l.addresses.iter().copied())
            .filter(|a| !withdrawn.contains(&a.addr) && !good.iter().any(|g| g.addr == a.addr))
            .collect();
        for g in &good {
            if iface.add_dhcpv6_address(now, g.addr, g.valid).is_ok() {
                addresses.push(LeasedAddress { addr: g.addr, preferred: g.preferred, valid: g.valid });
            }
        }
        if addresses.is_empty() {
            return self.start_over(now);
        }
        let dns =
            if msg.dns.is_empty() { self.lease.as_ref().map(|l| l.dns.clone()).unwrap_or_default() } else { msg.dns };
        let longest = addresses.iter().map(|a| a.valid).max().unwrap_or(0);
        iface.set_dhcpv6_dns(now, &dns, longest);
        self.dns = dns.clone();
        // T1 and T2 default to half and four fifths of the shortest preferred
        // lifetime (RFC 8415 section 14.2).
        let shortest = addresses.iter().map(|a| a.preferred).min().unwrap_or(0);
        let fraction = |n: u32, d: u32| {
            if shortest == INFINITY { INFINITY } else { (u64::from(shortest) * u64::from(n) / u64::from(d)) as u32 }
        };
        let t1 = if ia_t1 != 0 { ia_t1 } else { fraction(1, 2) };
        let t2 = if ia_t2 != 0 { ia_t2 } else { fraction(4, 5) };
        let secs = |s: u32| now + Duration::from_secs(u64::from(s));
        self.t1_at = (t1 != INFINITY).then(|| secs(t1.max(MIN_T1)));
        self.t2_at = (t2 != INFINITY).then(|| secs(t2.max(t1.max(MIN_T1))));
        self.expires_at = (longest != INFINITY).then(|| secs(longest));
        self.lease = Some(Lease { addresses, dns, server_id: server.clone(), granted: now });
        self.server = Some(server);
        self.state = Dhcp6State::Bound;
        self.advert = None;
        self.ex = None;
        Some(if was_requesting { Dhcp6Event::Configured } else { Dhcp6Event::Renewed })
    }

    /// The server cannot serve us: look for another.
    fn start_over(&mut self, now: Instant) -> Option<Dhcp6Event> {
        let delay = self.start_delay();
        self.start(now, now + delay);
        None
    }

    fn on_info_reply(&mut self, now: Instant, iface: &mut Interface, msg: Message) -> Option<Dhcp6Event> {
        if msg.server_id.is_none() || msg.status.is_some_and(|s| s != STATUS_SUCCESS) {
            return None;
        }
        let refresh = msg.info_refresh.map_or(DEFAULT_REFRESH, |t| t.max(MIN_REFRESH));
        // The servers are good until the next refresh has had time to fail.
        iface.set_dhcpv6_dns(now, &msg.dns, refresh.saturating_mul(2));
        self.dns = msg.dns;
        self.refresh_at = (refresh != INFINITY).then(|| now + Duration::from_secs(u64::from(refresh)));
        self.state = Dhcp6State::Informed;
        self.ex = None;
        let first = !self.informed;
        self.informed = true;
        Some(if first { Dhcp6Event::Configured } else { Dhcp6Event::Renewed })
    }
}

#[cfg(test)]
mod tests;
