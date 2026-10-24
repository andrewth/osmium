//! A DHCPv4 client (RFC 2131) that configures its interface.

use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::time::Duration;

use osmium_hal::net::MacAddress;

use super::{Cx, Packet};
use crate::wire::{PROTO_UDP, UdpHeader, put};
use crate::{Config, Instant};

pub(crate) const CLIENT_PORT: u16 = 68;
pub(crate) const SERVER_PORT: u16 = 67;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// The fixed BOOTP fields before the options, magic cookie included.
const FIXED_LEN: usize = 240;

pub(crate) const DISCOVER: u8 = 1;
pub(crate) const OFFER: u8 = 2;
pub(crate) const REQUEST: u8 = 3;
pub(crate) const ACK: u8 = 5;
pub(crate) const NAK: u8 = 6;

pub(crate) const OPT_SUBNET_MASK: u8 = 1;
pub(crate) const OPT_ROUTER: u8 = 3;
pub(crate) const OPT_DNS: u8 = 6;
pub(crate) const OPT_REQUESTED_IP: u8 = 50;
pub(crate) const OPT_LEASE_TIME: u8 = 51;
pub(crate) const OPT_MESSAGE_TYPE: u8 = 53;
pub(crate) const OPT_SERVER_ID: u8 = 54;
pub(crate) const OPT_PARAMETERS: u8 = 55;
pub(crate) const OPT_RENEWAL_TIME: u8 = 58;
const OPT_END: u8 = 255;
const OPT_PAD: u8 = 0;

/// Lease assumed when the server names none.
const DEFAULT_LEASE: u32 = 24 * 3600;
/// The shortest lease and renewal time taken, in seconds, so that a server
/// cannot make the client renew in a tight loop.
const MIN_LEASE: u32 = 60;
const MIN_RENEWAL: u32 = 30;

/// Returns true if `ip` can be one host's address.
fn unicast(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() || ip.is_loopback())
}

/// The fields of a DHCP message the client uses.
#[derive(Debug)]
pub(crate) struct Message {
    pub(crate) op: u8,
    pub(crate) xid: u32,
    pub(crate) ciaddr: Ipv4Addr,
    pub(crate) yiaddr: Ipv4Addr,
    pub(crate) chaddr: MacAddress,
    pub(crate) ty: u8,
    pub(crate) server: Option<Ipv4Addr>,
    pub(crate) requested: Option<Ipv4Addr>,
    pub(crate) mask: Option<Ipv4Addr>,
    pub(crate) router: Option<Ipv4Addr>,
    pub(crate) dns: Option<Ipv4Addr>,
    pub(crate) lease: Option<u32>,
    pub(crate) renewal: Option<u32>,
}

impl Default for Message {
    fn default() -> Self {
        let none = Ipv4Addr::UNSPECIFIED;
        Self {
            op: 0,
            xid: 0,
            ciaddr: none,
            yiaddr: none,
            chaddr: MacAddress::default(),
            ty: 0,
            server: None,
            requested: None,
            mask: None,
            router: None,
            dns: None,
            lease: None,
            renewal: None,
        }
    }
}

fn addr(b: &[u8]) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::from(*b.first_chunk::<4>()?))
}

impl Message {
    pub(crate) fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < FIXED_LEN || b.get(1..3) != Some(&[1, 6]) || b.get(236..240) != Some(&MAGIC) {
            return None;
        }
        let mut m = Message {
            op: *b.first()?,
            xid: u32::from_be_bytes(*b.get(4..)?.first_chunk()?),
            ciaddr: addr(b.get(12..)?)?,
            yiaddr: addr(b.get(16..)?)?,
            chaddr: MacAddress(*b.get(28..)?.first_chunk()?),
            ..Message::default()
        };
        let mut opts = b.get(FIXED_LEN..)?;
        while let [code, rest @ ..] = opts {
            match *code {
                OPT_END => break,
                OPT_PAD => opts = rest,
                code => {
                    let (&len, rest) = rest.split_first()?;
                    let value = rest.get(..usize::from(len))?;
                    let be32 = || Some(u32::from_be_bytes(*value.first_chunk()?));
                    match code {
                        OPT_MESSAGE_TYPE => m.ty = *value.first()?,
                        OPT_SERVER_ID => m.server = addr(value),
                        OPT_REQUESTED_IP => m.requested = addr(value),
                        OPT_SUBNET_MASK => m.mask = addr(value),
                        OPT_ROUTER => m.router = addr(value),
                        OPT_DNS => m.dns = addr(value),
                        OPT_LEASE_TIME => m.lease = be32(),
                        OPT_RENEWAL_TIME => m.renewal = be32(),
                        _ => {}
                    }
                    opts = rest.get(usize::from(len)..)?;
                }
            }
        }
        Some(m)
    }

    pub(crate) fn emit(&self) -> Vec<u8> {
        let mut b = alloc::vec![0u8; FIXED_LEN];
        let broadcast = self.op == BOOTREQUEST && self.ciaddr.is_unspecified();
        // Ask for broadcast replies: we cannot take unicast before we have an
        // address on stacks that filter by address.
        let flags: u8 = if broadcast { 0x80 } else { 0 };
        put(&mut b, 0, &[self.op, 1 /* Ethernet */, 6]);
        put(&mut b, 4, &self.xid.to_be_bytes());
        put(&mut b, 10, &[flags]);
        put(&mut b, 12, &self.ciaddr.octets());
        put(&mut b, 16, &self.yiaddr.octets());
        put(&mut b, 28, &self.chaddr.0);
        put(&mut b, 236, &MAGIC);
        let mut opt = |code: u8, value: &[u8]| {
            b.push(code);
            b.push(value.len() as u8);
            b.extend_from_slice(value);
        };
        opt(OPT_MESSAGE_TYPE, &[self.ty]);
        let addrs = [
            (OPT_REQUESTED_IP, self.requested),
            (OPT_SERVER_ID, self.server),
            (OPT_SUBNET_MASK, self.mask),
            (OPT_ROUTER, self.router),
            (OPT_DNS, self.dns),
        ];
        for (code, a) in addrs {
            if let Some(a) = a {
                opt(code, &a.octets());
            }
        }
        if let Some(t) = self.lease {
            opt(OPT_LEASE_TIME, &t.to_be_bytes());
        }
        if let Some(t) = self.renewal {
            opt(OPT_RENEWAL_TIME, &t.to_be_bytes());
        }
        if self.op == BOOTREQUEST {
            opt(OPT_PARAMETERS, &[OPT_SUBNET_MASK, OPT_ROUTER, OPT_DNS, OPT_LEASE_TIME, OPT_RENEWAL_TIME]);
        }
        b.push(OPT_END);
        b
    }
}

/// What a [`DhcpClient`] did to its interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpEvent {
    /// A lease was obtained or changed, and the interface now uses it.
    Configured(Config),
    /// The lease was lost; the interface has no address.
    Deconfigured,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Discovering,
    Requesting { server: Ipv4Addr, addr: Ipv4Addr },
    Bound,
    Renewing,
}

#[derive(Clone, Copy)]
struct Lease {
    config: Config,
    server: Ipv4Addr,
    renew_at: Instant,
    expires_at: Instant,
}

/// Obtains and renews a lease, and applies it to the interface that polls
/// it. One client per interface.
pub struct DhcpClient {
    phase: Phase,
    xid: u32,
    next_send: Instant,
    attempts: u32,
    lease: Option<Lease>,
    event: Option<DhcpEvent>,
    /// A change the interface has not applied yet.
    iface_update: Option<Option<Config>>,
}

impl Default for DhcpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpClient {
    /// A client that starts discovering on the first poll.
    pub const fn new() -> Self {
        Self {
            phase: Phase::Discovering,
            xid: 0,
            next_send: Instant::ZERO,
            attempts: 0,
            lease: None,
            event: None,
            iface_update: None,
        }
    }

    /// The configuration from the current lease.
    pub fn config(&self) -> Option<Config> {
        self.lease.map(|l| l.config)
    }

    /// Takes the latest change to the interface's configuration.
    pub fn take_event(&mut self) -> Option<DhcpEvent> {
        self.event.take()
    }

    /// Drops any lease and starts over, for example after the link comes
    /// back up on another network.
    pub fn restart(&mut self) {
        if self.lease.take().is_some() {
            self.deconfigured();
        }
        self.phase = Phase::Discovering;
        self.attempts = 0;
        self.next_send = Instant::ZERO;
    }

    fn deconfigured(&mut self) {
        self.event = Some(DhcpEvent::Deconfigured);
        self.iface_update = Some(None);
    }

    pub(crate) fn take_iface_update(&mut self) -> Option<Option<Config>> {
        self.iface_update.take()
    }

    pub(crate) fn poll_at(&self) -> Option<Instant> {
        match (self.phase, self.lease) {
            (Phase::Bound, Some(l)) => Some(l.renew_at),
            _ => Some(self.next_send),
        }
    }

    fn backoff(&self, cap: Duration) -> Duration {
        (Duration::from_secs(1) * (1 << self.attempts.min(6))).min(cap)
    }

    pub(crate) fn dispatch(&mut self, cx: &mut Cx, out: &mut Vec<Packet>) {
        let now = cx.now;
        if let (Phase::Bound, Some(l)) = (self.phase, self.lease)
            && now >= l.renew_at
        {
            self.phase = Phase::Renewing;
            self.attempts = 0;
            self.next_send = now;
        }
        if let (Phase::Renewing, Some(l)) = (self.phase, self.lease)
            && now >= l.expires_at
        {
            self.restart();
        }
        if self.phase == Phase::Bound || now < self.next_send {
            return;
        }
        if self.attempts == 0 && !matches!(self.phase, Phase::Requesting { .. }) {
            self.xid = cx.rng.next_u32();
        }
        let mut m = Message { op: BOOTREQUEST, xid: self.xid, chaddr: cx.mac, ..Message::default() };
        let (src, dst) = match self.phase {
            Phase::Discovering => {
                m.ty = DISCOVER;
                self.next_send = now + self.backoff(Duration::from_secs(16));
                (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST)
            }
            Phase::Requesting { server, addr } => {
                if self.attempts >= 4 {
                    self.phase = Phase::Discovering;
                    self.attempts = 0;
                    self.next_send = now;
                    return;
                }
                m.ty = REQUEST;
                m.server = Some(server);
                m.requested = Some(addr);
                self.next_send = now + self.backoff(Duration::from_secs(16));
                (Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST)
            }
            Phase::Renewing => {
                let Some(l) = self.lease else { return };
                m.ty = REQUEST;
                m.ciaddr = l.config.address;
                self.next_send = now + self.backoff(Duration::from_secs(60));
                (l.config.address, l.server)
            }
            Phase::Bound => return,
        };
        self.attempts += 1;
        let payload = UdpHeader { src_port: CLIENT_PORT, dst_port: SERVER_PORT }.emit(src, dst, &m.emit());
        out.push(Packet { src: src.into(), dst: dst.into(), protocol: PROTO_UDP, payload });
    }

    pub(crate) fn process(&mut self, cx: &mut Cx, data: &[u8]) {
        let Some(m) = Message::parse(data) else { return };
        if m.op != BOOTREPLY || m.xid != self.xid || m.chaddr != cx.mac {
            return;
        }
        let now = cx.now;
        match (self.phase, m.ty) {
            (Phase::Discovering, OFFER) => {
                let Some(server) = m.server else { return };
                if !unicast(m.yiaddr) {
                    return;
                }
                // The REQUEST keeps the DISCOVER's transaction id.
                self.phase = Phase::Requesting { server, addr: m.yiaddr };
                self.attempts = 0;
                self.next_send = now;
            }
            (Phase::Requesting { .. } | Phase::Renewing, ACK | NAK) => self.answered(now, &m),
            _ => {}
        }
    }

    /// Takes an ACK or NAK to a REQUEST.
    fn answered(&mut self, now: Instant, m: &Message) {
        // Only the server we chose may answer.
        let server = match (self.phase, self.lease) {
            (Phase::Requesting { server, .. }, _) | (Phase::Renewing, Some(Lease { server, .. })) => server,
            _ => return,
        };
        if m.server != Some(server) {
            return;
        }
        match m.ty {
            ACK => {
                if !unicast(m.yiaddr) || matches!(self.phase, Phase::Requesting { addr, .. } if addr != m.yiaddr) {
                    return;
                }
                let prefix_len = m.mask.map_or(24, |mask| u32::from(mask).leading_ones() as u8);
                if !(1..=30).contains(&prefix_len) {
                    return;
                }
                let mut config = Config { address: m.yiaddr, prefix_len, gateway: m.router, dns: m.dns };
                if m.yiaddr == config.broadcast() {
                    return;
                }
                // A router off the subnet could never be reached.
                config.gateway = m.router.filter(|&r| config.contains(r) && r != m.yiaddr && r != config.broadcast());
                let lease = m.lease.unwrap_or(DEFAULT_LEASE).max(MIN_LEASE);
                let renewal = m.renewal.unwrap_or(lease / 2).clamp(MIN_RENEWAL, lease);
                let changed = self.lease.map(|l| l.config) != Some(config);
                self.lease = Some(Lease {
                    config,
                    server,
                    renew_at: now + Duration::from_secs(renewal.into()),
                    expires_at: now + Duration::from_secs(lease.into()),
                });
                self.phase = Phase::Bound;
                self.attempts = 0;
                if changed {
                    self.event = Some(DhcpEvent::Configured(config));
                    self.iface_update = Some(Some(config));
                }
            }
            _ => self.restart(), // NAK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SocketHandle;
    use crate::testing::{Host, link, run};
    use crate::wire::{EthernetHeader, Ipv4Header};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::vec;

    const SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
    const OFFERED: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

    /// Messages the client sent, in order.
    type Log = Rc<RefCell<Vec<Message>>>;

    /// Makes `server` a DHCP server on its link: it answers each DISCOVER
    /// and REQUEST that `client` sends (taken from the wire by a filter on
    /// the client) with `reply(request) -> (type, lease)`, or not at all.
    fn serve(client: &mut Host, server: &Host, mut reply: impl FnMut(&Message) -> Option<(u8, u32)> + 'static) -> Log {
        let log = Log::default();
        let seen = log.clone();
        let server_mac = server.dev.mac;
        let to_client = server.dev.tx.clone();
        client.set_filter(move |_, frame| {
            let Some(m) = (|| {
                let (_, ip) = EthernetHeader::parse(frame)?;
                let (iph, udp) = Ipv4Header::parse(ip)?;
                let (_, data) = UdpHeader::parse(udp, iph.src, iph.dst)?;
                Message::parse(data)
            })() else {
                return true;
            };
            if let Some((ty, lease)) = reply(&m) {
                let r = Message {
                    op: BOOTREPLY,
                    xid: m.xid,
                    yiaddr: OFFERED,
                    chaddr: m.chaddr,
                    ty,
                    server: Some(SERVER),
                    mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
                    router: Some(SERVER),
                    dns: Some(Ipv4Addr::new(10, 0, 2, 3)),
                    lease: Some(lease),
                    ..Message::default()
                };
                let udp = UdpHeader { src_port: SERVER_PORT, dst_port: CLIENT_PORT }.emit(SERVER, OFFERED, &r.emit());
                let mut f = vec![0; 34 + udp.len()];
                EthernetHeader { dst: m.chaddr, src: server_mac, ethertype: crate::wire::ETHERTYPE_IPV4 }.emit(&mut f);
                let ip = Ipv4Header {
                    src: SERVER,
                    dst: OFFERED,
                    protocol: PROTO_UDP,
                    ttl: 64,
                    ident: 0,
                    payload_len: udp.len(),
                };
                ip.emit(&mut f[14..]);
                f[34..].copy_from_slice(&udp);
                to_client.borrow_mut().push_back(f);
            }
            seen.borrow_mut().push(m);
            false // the server host's own stack never sees it
        });
        log
    }

    fn client() -> (Host, Host, SocketHandle) {
        let (mut a, b) = link();
        let h = a.sockets.add(DhcpClient::new());
        (a, b, h)
    }

    fn ack_everything(m: &Message) -> Option<(u8, u32)> {
        Some((if m.ty == DISCOVER { OFFER } else { ACK }, 3600))
    }

    #[test]
    fn obtains_and_renews_a_lease() {
        let (mut a, mut b, h) = client();
        let log = serve(&mut a, &b, ack_everything);
        let mut now = Instant::ZERO;
        assert!(run(&mut a, &mut b, &mut now, 100, |a, _| a.iface.config().is_some()));
        let config =
            Config { address: OFFERED, prefix_len: 24, gateway: Some(SERVER), dns: Some(Ipv4Addr::new(10, 0, 2, 3)) };
        assert_eq!(a.iface.config(), Some(config));
        assert_eq!(a.sockets.get_mut::<DhcpClient>(h).take_event(), Some(DhcpEvent::Configured(config)));
        {
            let log = log.borrow();
            assert_eq!(log.iter().map(|m| m.ty).collect::<Vec<_>>(), [DISCOVER, REQUEST]);
            assert_eq!(log[0].xid, log[1].xid, "one transaction");
            assert_eq!((log[1].requested, log[1].server), (Some(OFFERED), Some(SERVER)));
        }
        assert_eq!(a.iface.poll_at(&a.sockets), Some(now + Duration::from_secs(1800)), "sleeps until T1");

        // At T1 the client renews by unicast from its address, after
        // resolving the server.
        b.iface.set_config(Some(crate::testing::config(SERVER)));
        now = now + Duration::from_secs(1800);
        run(&mut a, &mut b, &mut now, 20, |_, _| false);
        let log = log.borrow();
        let renew = log.last().unwrap();
        assert_eq!((renew.ty, renew.ciaddr, renew.server), (REQUEST, OFFERED, None));
        assert_eq!(a.sockets.get_mut::<DhcpClient>(h).take_event(), None, "the same lease: no event");
    }

    #[test]
    fn nak_restarts_and_expiry_deconfigures() {
        let (mut a, mut b, h) = client();
        let naks = Rc::new(RefCell::new(true));
        let nak = naks.clone();
        serve(&mut a, &b, move |m| match m.ty {
            DISCOVER => Some((OFFER, 10)),
            _ if *nak.borrow() => Some((NAK, 0)),
            _ if m.ciaddr.is_unspecified() => Some((ACK, 10)),
            _ => None, // renewals go unanswered
        });
        let mut now = Instant::ZERO;
        run(&mut a, &mut b, &mut now, 50, |_, _| false);
        assert_eq!(a.iface.config(), None, "NAKed");
        *naks.borrow_mut() = false;
        assert!(run(&mut a, &mut b, &mut now, 5000, |a, _| a.iface.config().is_some()), "rediscovered");
        a.sockets.get_mut::<DhcpClient>(h).take_event();
        // The 10 s lease is taken as the 60 s minimum.
        assert!(run(&mut a, &mut b, &mut now, 60_100, |a, _| a.iface.config().is_none()), "lease expired");
        assert_eq!(a.sockets.get_mut::<DhcpClient>(h).take_event(), Some(DhcpEvent::Deconfigured));
    }

    #[test]
    fn retries_with_backoff() {
        let (mut a, mut b, _) = client();
        let log = serve(&mut a, &b, |_| None);
        let mut now = Instant::ZERO;
        run(&mut a, &mut b, &mut now, 16_000, |_, _| false);
        // Sent at 0, 1, 3, 7 and 15 seconds.
        assert_eq!(log.borrow().len(), 5);
    }

    /// Feeds `reply` to a client that has taken the OFFER of [`OFFERED`]
    /// from [`SERVER`], and returns the client.
    fn requesting(reply: impl FnOnce(&mut Message)) -> DhcpClient {
        let mut rng = crate::rng::Rng::new(1);
        let mac = MacAddress([2, 0, 0, 0, 0, 1]);
        let mut cx = Cx {
            now: Instant::ZERO,
            addr: None,
            mac,
            mss: 1460,
            mss6: 1440,
            addr6: None,
            link_local6: None,
            rng: &mut rng,
        };
        let mut c = DhcpClient::new();
        c.dispatch(&mut cx, &mut Vec::new());
        let mut m = Message {
            op: BOOTREPLY,
            xid: c.xid,
            yiaddr: OFFERED,
            chaddr: mac,
            ty: OFFER,
            server: Some(SERVER),
            mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            router: Some(SERVER),
            ..Message::default()
        };
        c.process(&mut cx, &m.emit());
        assert_eq!(c.phase, Phase::Requesting { server: SERVER, addr: OFFERED });
        m.ty = ACK;
        reply(&mut m);
        c.process(&mut cx, &m.emit());
        c
    }

    #[test]
    fn rejects_bad_acks() {
        let other = Ipv4Addr::new(10, 0, 2, 9);
        assert!(requesting(|_| {}).config().is_some());
        assert!(requesting(|m| m.server = Some(other)).config().is_none(), "another server");
        assert!(requesting(|m| m.server = None).config().is_none(), "no server id");
        assert!(requesting(|m| m.yiaddr = other).config().is_none(), "not the offered address");
        let mut c = requesting(|m| (m.ty, m.server) = (NAK, Some(other)));
        assert!(matches!(c.phase, Phase::Requesting { .. }), "another server's NAK");
        assert!(c.take_event().is_none());
        for mask in [[255, 255, 255, 255], [255, 255, 255, 254], [0, 0, 0, 0]] {
            assert!(requesting(|m| m.mask = Some(mask.into())).config().is_none(), "mask {mask:?}");
        }
        for router in [[10, 0, 3, 1], [10, 0, 2, 255], [10, 0, 2, 15]] {
            let c = requesting(|m| m.router = Some(router.into()));
            assert_eq!(c.config().unwrap().gateway, None, "router {router:?}");
        }
    }

    #[test]
    fn truncated_and_garbage_messages_are_rejected() {
        let wire =
            Message { op: BOOTREPLY, ty: OFFER, server: Some(Ipv4Addr::new(10, 0, 0, 1)), ..Message::default() }.emit();
        assert!(Message::parse(&wire).is_some());
        for n in 0..FIXED_LEN {
            assert!(Message::parse(&wire[..n]).is_none());
        }
        // An option whose length runs past the end.
        let mut bad = wire[..FIXED_LEN].to_vec();
        bad.extend_from_slice(&[OPT_DNS, 200, 1, 2]);
        assert!(Message::parse(&bad).is_none());
        // A length byte missing.
        let mut bad = wire[..FIXED_LEN].to_vec();
        bad.push(OPT_DNS);
        assert!(Message::parse(&bad).is_none());
    }

    #[test]
    fn short_leases_are_lengthened() {
        let c = requesting(|m| (m.lease, m.renewal) = (Some(1), Some(0)));
        let l = c.lease.unwrap();
        assert_eq!((l.renew_at, l.expires_at), (Instant::from_millis(30_000), Instant::from_millis(60_000)));
    }
}
