//! IPv6 on an [`Interface`]: link-local and autoconfigured addresses,
//! duplicate address detection, neighbor discovery in place of ARP, router
//! discovery for SLAAC, ICMPv6 echo, and UDP and TCP delivery.
//!
//! IPv6 is off until [`Interface::enable_ipv6`] is called, and then runs
//! beside IPv4 on the same interface. Fragmented packets are put back
//! together and large datagrams are fragmented on send (see [`frag`]); TCP
//! avoids fragmentation by its segment size.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use osmium_hal::net::MacAddress;

use super::{Interface, PENDING};
use crate::ipv6::*;
use crate::socket::icmp::EchoReply;
use crate::socket::tcp::reset_for;
use crate::socket::{Cx, Packet, Socket, SocketSet};
use crate::wire::*;
use crate::{Error, Instant};

mod addrgen;
mod frag;
pub use addrgen::TemporaryAddress;

/// Hop limit of the packets we originate.
const HOP_LIMIT: u8 = 64;
/// Neighbor discovery messages are sent and accepted with this hop limit
/// only, which proves they did not cross a router.
const ND_HOP_LIMIT: u8 = 255;
/// How long duplicate address detection listens (RFC 4862 RetransTimer).
const DAD_WAIT: Duration = Duration::from_secs(1);
/// Time between router solicitations (RFC 4861 RTR_SOLICITATION_INTERVAL).
const RS_INTERVAL: Duration = Duration::from_secs(4);
/// Router solicitations sent before giving up.
const RS_MAX: u8 = 3;
/// Time between neighbor solicitations for one address.
const NS_RETRY: Duration = Duration::from_secs(1);
/// How long packets wait for a neighbor before they are dropped.
const NS_GIVE_UP: Duration = Duration::from_secs(3);
/// How long a learned link-layer address stays valid.
const NEIGHBOR_LIFETIME: Duration = Duration::from_secs(60);
/// Neighbors kept; the oldest is replaced when the cache is full.
const NEIGHBORS: usize = 32;
const MAX_ADDRESSES: usize = 8;
const MAX_PREFIXES: usize = 8;
const MAX_ROUTERS: usize = 4;
const MAX_DNS: usize = 4;
/// A lifetime of "forever" in a router advertisement.
const INFINITE: u32 = u32::MAX;
/// RFC 4862 section 5.5.3 e): a valid lifetime shorter than this does not
/// shorten an address's remaining lifetime.
const TWO_HOURS: u32 = 7200;
/// The most of an offending packet an ICMPv6 error quotes, so that the error
/// fits the minimum MTU.
const MAX_QUOTE: usize = IPV6_MIN_MTU - IPV6_HEADER_LEN - ICMPV6_HEADER_LEN - 4;

/// An IPv6 address of an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Address {
    /// The address.
    pub addr: Ipv6Addr,
    /// Length of the prefix of the link the address is on.
    pub prefix_len: u8,
    /// Duplicate address detection has finished: the address is in use.
    /// Until then it is tentative and answers nothing but detection.
    pub usable: bool,
}

#[derive(Clone, Copy)]
enum Dad {
    /// The first probe has not been sent.
    Idle,
    /// Probed; the address is ours if nobody objects before this time.
    Probing(Instant),
    /// Another host has the address.
    Duplicate,
    Done,
}

struct Address {
    addr: Ipv6Addr,
    prefix_len: u8,
    dad: Dad,
    /// When an autoconfigured address stops being valid.
    expires: Option<Instant>,
}

struct Prefix {
    prefix: Ipv6Addr,
    len: u8,
    expires: Option<Instant>,
}

struct Router {
    addr: Ipv6Addr,
    expires: Instant,
}

struct Neighbor {
    ip: Ipv6Addr,
    mac: MacAddress,
    expires: Instant,
}

struct Request {
    ip: Ipv6Addr,
    first: Instant,
    last: Instant,
}

/// The interface's IPv6 state.
pub(super) struct State {
    enabled: bool,
    slaac: bool,
    link_local: Address,
    addrs: Vec<Address>,
    prefixes: Vec<Prefix>,
    routers: Vec<Router>,
    gateway: Option<Ipv6Addr>,
    dns: Vec<Ipv6Addr>,
    /// When the servers in `dns` stop being valid.
    dns_expires: Option<Instant>,
    /// The MTU a router advertised.
    mtu: Option<usize>,
    neighbors: Vec<Neighbor>,
    requests: Vec<Request>,
    pending: VecDeque<(Ipv6Addr, Packet)>,
    /// Router solicitations sent, and when the next is due; `None` once an
    /// advertisement arrived or the attempts ran out.
    rs_sent: u8,
    rs_next: Option<Instant>,
    /// Fragmented datagrams being put back together.
    reasm: crate::frag6::Reassembler,
    /// How SLAAC addresses are formed, and the temporary ones.
    privacy: addrgen::Privacy,
}

fn lifetime(now: Instant, secs: u32) -> Option<Instant> {
    (secs != INFINITE).then(|| now + Duration::from_secs(u64::from(secs)))
}

impl State {
    pub(super) fn new(mac: MacAddress) -> Self {
        Self {
            enabled: false,
            slaac: true,
            link_local: Address { addr: link_local_from_mac(mac), prefix_len: 64, dad: Dad::Idle, expires: None },
            addrs: Vec::new(),
            prefixes: Vec::new(),
            routers: Vec::new(),
            gateway: None,
            dns: Vec::new(),
            dns_expires: None,
            mtu: None,
            neighbors: Vec::new(),
            requests: Vec::new(),
            pending: VecDeque::new(),
            rs_sent: 0,
            rs_next: None,
            reasm: frag::new_reassembler(),
            privacy: addrgen::Privacy::default(),
        }
    }

    fn all(&self) -> impl Iterator<Item = &Address> {
        core::iter::once(&self.link_local).chain(self.addrs.iter())
    }

    fn usable_addrs(&self) -> impl Iterator<Item = &Address> {
        self.all().filter(|a| matches!(a.dad, Dad::Done))
    }

    /// The link-local address, once it is usable.
    pub(super) fn link_local(&self) -> Option<Ipv6Addr> {
        (self.enabled && matches!(self.link_local.dad, Dad::Done)).then_some(self.link_local.addr)
    }

    /// The preferred global address.
    pub(super) fn global(&self) -> Option<Ipv6Addr> {
        if !self.enabled {
            return None;
        }
        self.preferred_temp().or_else(|| self.addrs.iter().find(|a| matches!(a.dad, Dad::Done)).map(|a| a.addr))
    }

    /// The MTU in use, given the link's.
    pub(super) fn mtu(&self, link: usize) -> usize {
        self.mtu.map_or(link, |m| m.min(link))
    }

    /// True for an address of ours that has passed duplicate detection.
    fn is_ours(&self, a: Ipv6Addr) -> bool {
        self.usable_addrs().any(|x| x.addr == a)
    }

    /// True for an address of ours, whether or not it has passed detection.
    fn is_tentative_or_ours(&self, a: Ipv6Addr) -> bool {
        self.all().any(|x| x.addr == a)
    }

    pub(super) fn poll_at(&self) -> Option<Instant> {
        if !self.enabled {
            return None;
        }
        let dad = self.all().filter_map(|a| match a.dad {
            Dad::Idle => Some(Instant::ZERO),
            Dad::Probing(t) => Some(t),
            Dad::Duplicate | Dad::Done => None,
        });
        let expiry = self
            .addrs
            .iter()
            .filter_map(|a| a.expires)
            .chain(self.prefixes.iter().filter_map(|p| p.expires))
            .chain(self.routers.iter().map(|r| r.expires))
            .chain(self.dns_expires);
        let nd = self.requests.iter().map(|r| r.last + NS_RETRY);
        dad.chain(self.rs_next).chain(expiry).chain(nd).chain(self.reasm.poll_at()).chain(self.privacy_poll_at()).min()
    }

    fn on_link(&self, dst: Ipv6Addr) -> bool {
        is_link_local(dst)
            || self.prefixes.iter().any(|p| same_prefix(p.prefix, dst, p.len))
            || self.addrs.iter().any(|a| same_prefix(a.addr, dst, a.prefix_len))
    }

    fn next_hop(&self, dst: Ipv6Addr) -> Option<Ipv6Addr> {
        if self.on_link(dst) {
            return Some(dst);
        }
        self.routers.first().map(|r| r.addr).or(self.gateway)
    }

    fn lookup(&self, ip: Ipv6Addr, now: Instant) -> Option<MacAddress> {
        self.neighbors.iter().find(|n| n.ip == ip && n.expires > now).map(|n| n.mac)
    }

    fn insert(&mut self, ip: Ipv6Addr, mac: MacAddress, now: Instant) {
        let expires = now + NEIGHBOR_LIFETIME;
        if let Some(n) = self.neighbors.iter_mut().find(|n| n.ip == ip) {
            n.mac = mac;
            n.expires = expires;
        } else if self.neighbors.len() < NEIGHBORS {
            self.neighbors.push(Neighbor { ip, mac, expires });
        } else if let Some(n) = self.neighbors.iter_mut().min_by_key(|n| n.expires) {
            *n = Neighbor { ip, mac, expires };
        }
    }
}

impl Interface {
    /// Turns IPv6 on: the interface derives its link-local address from its
    /// MAC address, checks it for duplicates, and (unless
    /// [`set_slaac`](Self::set_slaac) turned it off) solicits a router
    /// advertisement to autoconfigure global addresses and a default router.
    /// This happens over the following polls. Fails if the link's MTU is
    /// under the 1280 bytes IPv6 requires.
    pub fn enable_ipv6(&mut self) -> Result<(), Error> {
        if self.mtu < IPV6_MIN_MTU {
            return Err(Error::InvalidState);
        }
        if !self.v6.enabled {
            self.v6.enabled = true;
        }
        Ok(())
    }

    /// Turns IPv6 off and forgets its addresses, routers and neighbors.
    pub fn disable_ipv6(&mut self) {
        let slaac = self.v6.slaac;
        let privacy = core::mem::take(&mut self.v6.privacy).reset();
        self.v6 = State::new(self.mac);
        self.v6.slaac = slaac;
        self.v6.privacy = privacy;
    }

    /// Returns true if IPv6 is on.
    pub fn ipv6_enabled(&self) -> bool {
        self.v6.enabled
    }

    /// Chooses whether router advertisements autoconfigure addresses and
    /// routers (the default). With it off only the link-local address and
    /// those from [`add_ipv6_address`](Self::add_ipv6_address) are used.
    pub fn set_slaac(&mut self, slaac: bool) {
        self.v6.slaac = slaac;
    }

    /// Adds a static address with its prefix, which it also makes on-link.
    /// It is used once duplicate address detection passes.
    pub fn add_ipv6_address(&mut self, addr: Ipv6Addr, prefix_len: u8) -> Result<(), Error> {
        let unusable = addr.is_unspecified() || addr.is_multicast() || addr.is_loopback() || is_link_local(addr);
        if prefix_len > 128 || unusable {
            return Err(Error::InvalidAddress);
        }
        if self.v6.is_tentative_or_ours(addr) {
            return Ok(());
        }
        if self.v6.addrs.len() >= MAX_ADDRESSES {
            return Err(Error::WouldBlock);
        }
        self.v6.addrs.push(Address { addr, prefix_len, dad: Dad::Idle, expires: None });
        Ok(())
    }

    /// Sets a default router used when no router advertisement named one.
    pub fn set_ipv6_gateway(&mut self, gateway: Option<Ipv6Addr>) {
        self.v6.gateway = gateway;
    }

    /// The interface's IPv6 addresses, the link-local one first.
    pub fn ipv6_addresses(&self) -> Vec<Ipv6Address> {
        self.v6
            .all()
            .map(|a| Ipv6Address { addr: a.addr, prefix_len: a.prefix_len, usable: matches!(a.dad, Dad::Done) })
            .collect()
    }

    /// The link-local address, once duplicate address detection has passed.
    pub fn ipv6_link_local(&self) -> Option<Ipv6Addr> {
        self.v6.link_local()
    }

    /// The default router: one a router advertisement named, else the one
    /// [`set_ipv6_gateway`](Self::set_ipv6_gateway) set.
    pub fn ipv6_gateway(&self) -> Option<Ipv6Addr> {
        self.v6.routers.first().map(|r| r.addr).or(self.v6.gateway)
    }

    /// DNS servers that router advertisements reported (RFC 8106).
    pub fn ipv6_dns(&self) -> &[Ipv6Addr] {
        &self.v6.dns
    }

    /// The MTU IPv6 uses: the link's, or a smaller one a router advertised.
    pub fn ipv6_mtu(&self) -> usize {
        self.v6.mtu(self.mtu)
    }

    /// Timers: duplicate address detection, router solicitation, lifetimes
    /// and neighbor solicitation retries.
    pub(super) fn poll_v6(&mut self, now: Instant) {
        if !self.v6.enabled {
            return;
        }
        // Duplicate address detection.
        let mut probes = Vec::new();
        let slaac = self.v6.slaac;
        let mut link_local_done = false;
        for (i, a) in core::iter::once(&mut self.v6.link_local).chain(self.v6.addrs.iter_mut()).enumerate() {
            match a.dad {
                Dad::Idle => {
                    a.dad = Dad::Probing(now + DAD_WAIT);
                    probes.push(a.addr);
                }
                Dad::Probing(t) if now >= t => {
                    a.dad = Dad::Done;
                    link_local_done |= i == 0;
                }
                _ => {}
            }
        }
        if link_local_done && slaac {
            self.v6.rs_sent = 0;
            self.v6.rs_next = Some(now);
        }
        for target in probes {
            let dst = solicited_node(target);
            let body = NeighborSolicit { target, source_ll: None }.emit();
            self.send_icmp6(multicast_mac(dst), Ipv6Addr::UNSPECIFIED, dst, ICMPV6_NEIGHBOR_SOLICIT, &body);
        }

        // Router solicitation.
        if self.v6.rs_next.is_some_and(|t| now >= t)
            && let Some(src) = self.v6.link_local()
        {
            let body = RouterSolicit { source_ll: Some(self.mac) }.emit();
            self.send_icmp6(multicast_mac(ALL_ROUTERS), src, ALL_ROUTERS, ICMPV6_ROUTER_SOLICIT, &body);
            self.v6.rs_sent += 1;
            self.v6.rs_next = (self.v6.rs_sent < RS_MAX).then(|| now + RS_INTERVAL);
        }

        self.v6.expire_fragments(now);

        // Lifetimes.
        let v6 = &mut self.v6;
        v6.addrs.retain(|a| a.expires.is_none_or(|t| t > now));
        v6.prefixes.retain(|p| p.expires.is_none_or(|t| t > now));
        v6.routers.retain(|r| r.expires > now);
        if v6.dns_expires.is_some_and(|t| t <= now) {
            v6.dns.clear();
            v6.dns_expires = None;
        }
        self.privacy_poll(now);

        // Neighbor solicitation retries.
        let mut i = 0;
        while i < self.v6.requests.len() {
            let Some(r) = self.v6.requests.get_mut(i) else { break };
            if now - r.first >= NS_GIVE_UP {
                let ip = r.ip;
                self.v6.requests.swap_remove(i);
                self.v6.pending.retain(|(hop, _)| *hop != ip);
                continue;
            }
            if now - r.last >= NS_RETRY {
                r.last = now;
                let ip = r.ip;
                let src = self.v6.pending.iter().find(|(hop, _)| *hop == ip).map(|(_, p)| p.src);
                self.send_ns(ip, src);
            }
            i += 1;
        }
    }

    /// Sends an ICMPv6 message from `src` to `dst` in a frame to `dst_mac`.
    fn send_icmp6(&mut self, dst_mac: MacAddress, src: Ipv6Addr, dst: Ipv6Addr, ty: u8, body: &[u8]) {
        let msg = Icmpv6Header { ty, code: 0 }.emit(src, dst, body);
        let frame = self.ip6_frame(dst_mac, src, dst, PROTO_ICMPV6, ND_HOP_LIMIT, &msg);
        self.queue_frame(frame);
    }

    fn ip6_frame(
        &self,
        dst_mac: MacAddress,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
        hop_limit: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = self.ethernet_frame(dst_mac, ETHERTYPE_IPV6, IPV6_HEADER_LEN + payload.len());
        let header = Ipv6Header { src, dst, next_header, hop_limit, payload_len: payload.len(), fragment: None };
        header.emit(frame.get_mut(ETH_HEADER_LEN..).unwrap_or(&mut []));
        crate::wire::put(&mut frame, ETH_HEADER_LEN + IPV6_HEADER_LEN, payload);
        frame
    }

    /// Asks for the link-layer address of `target`, from the source address
    /// of the packet that wants it if it is ours, else the link-local one.
    fn send_ns(&mut self, target: Ipv6Addr, preferred_src: Option<IpAddr>) {
        let src = match preferred_src {
            Some(IpAddr::V6(s)) if self.v6.is_ours(s) => s,
            _ => match self.v6.link_local() {
                Some(ll) => ll,
                None => return,
            },
        };
        let dst = solicited_node(target);
        let body = NeighborSolicit { target, source_ll: Some(self.mac) }.emit();
        self.send_icmp6(multicast_mac(dst), src, dst, ICMPV6_NEIGHBOR_SOLICIT, &body);
    }

    /// Routes an IPv6 packet to its next hop, resolving the hop's link-layer
    /// address first if it is not cached.
    pub(super) fn send_ip6(&mut self, now: Instant, p: Packet) {
        let (IpAddr::V6(src), IpAddr::V6(dst)) = (p.src, p.dst) else { return };
        // TCP sizes its segments to the MTU; everything else is fragmented.
        let too_big = IPV6_HEADER_LEN + p.payload.len() > self.v6.mtu(self.mtu);
        if !self.v6.enabled || p.payload.len() > crate::frag6::MAX_DATAGRAM || (too_big && p.protocol == PROTO_TCP) {
            return;
        }
        // ::1 never goes on the link, as a destination or a source.
        if dst.is_loopback() {
            if src.is_loopback() {
                self.queue_loopback6(src, dst, p.protocol, &p.payload);
            }
            return;
        }
        if src.is_loopback() {
            return;
        }
        if dst.is_multicast() {
            return self.queue_ip6(multicast_mac(dst), src, dst, p.protocol, HOP_LIMIT, &p.payload);
        }
        let Some(hop) = self.v6.next_hop(dst) else { return };
        if let Some(mac) = self.v6.lookup(hop, now) {
            return self.queue_ip6(mac, src, dst, p.protocol, HOP_LIMIT, &p.payload);
        }
        if self.v6.pending.len() >= PENDING {
            return;
        }
        self.v6.pending.push_back((hop, p));
        if !self.v6.requests.iter().any(|r| r.ip == hop) {
            self.v6.requests.push(Request { ip: hop, first: now, last: now });
            self.send_ns(hop, Some(IpAddr::V6(src)));
        }
    }

    fn learned6(&mut self, now: Instant, ip: Ipv6Addr, mac: MacAddress) {
        self.v6.insert(ip, mac, now);
        self.v6.requests.retain(|r| r.ip != ip);
        let mut i = 0;
        while i < self.v6.pending.len() {
            if self.v6.pending.get(i).is_some_and(|(hop, _)| *hop == ip) {
                let Some((_, p)) = self.v6.pending.remove(i) else { break };
                if let (IpAddr::V6(src), IpAddr::V6(dst)) = (p.src, p.dst) {
                    self.queue_ip6(mac, src, dst, p.protocol, HOP_LIMIT, &p.payload);
                }
            } else {
                i += 1;
            }
        }
    }

    /// Handles an IPv6 packet; `reassembled` if it was put together from
    /// fragments, in which case it may not be fragmented again.
    fn process_ipv6_with(&mut self, now: Instant, bytes: &[u8], sockets: &mut SocketSet, reassembled: bool) {
        if !self.v6.enabled {
            return;
        }
        let Some((ip, payload)) = Ipv6Header::parse(bytes) else { return };
        // A source that is ours is forged, except that an advertisement
        // answering our duplicate address probe comes from the address.
        let own_source =
            self.v6.is_ours(ip.src) || (ip.next_header != PROTO_ICMPV6 && self.v6.is_tentative_or_ours(ip.src));
        if ip.src.is_multicast() || (ip.src.is_loopback() && !self.looping) || own_source {
            return;
        }
        let to_us = self.v6.is_ours(ip.dst) || (self.looping && ip.dst.is_loopback());
        let group = ip.dst == ALL_NODES || self.v6.all().any(|a| solicited_node(a.addr) == ip.dst);
        if !(to_us || group) {
            return;
        }
        // Only a duplicate address probe comes from the unspecified address.
        if ip.src.is_unspecified() && ip.next_header != PROTO_ICMPV6 {
            return;
        }
        if let Some(fragment) = ip.fragment.filter(|f| !f.is_whole()) {
            // Only unicast to us is worth holding pieces for, and a datagram
            // that contains a fragment header of its own is nonsense.
            if to_us && !reassembled {
                self.reassemble6(now, &ip, fragment, payload, sockets);
            }
            return;
        }
        match ip.next_header {
            PROTO_ICMPV6 => self.process_icmpv6(now, &ip, payload, to_us, sockets),
            PROTO_UDP => self.process_udp6(now, &ip, bytes, payload, to_us, sockets),
            PROTO_TCP if to_us => self.process_tcp6(now, &ip, payload, sockets),
            _ => {}
        }
    }

    fn cx6(&mut self, now: Instant) -> Cx<'_> {
        Cx {
            now,
            addr: self.config.map(|c| c.address),
            addr6: self.v6.global(),
            link_local6: self.v6.link_local(),
            mac: self.mac,
            mss: self.mss(),
            mss6: self.mss6(),
            rng: &mut self.rng,
        }
    }

    fn process_udp6(
        &mut self,
        now: Instant,
        ip: &Ipv6Header,
        bytes: &[u8],
        payload: &[u8],
        to_us: bool,
        sockets: &mut SocketSet,
    ) {
        let Some((udp, data)) = UdpHeader::parse(payload, ip.src, ip.dst) else { return };
        let dst = SocketAddr::new(ip.dst.into(), udp.dst_port);
        let src = SocketAddr::new(ip.src.into(), udp.src_port);
        for (_, s) in sockets.iter_mut() {
            if let Socket::Udp(s) = s
                && s.accepts(dst)
            {
                s.process(src, data);
                return;
            }
        }
        // Port unreachable, quoting as much of the packet as fits the
        // minimum MTU. Nothing is said about packets sent to a group.
        if to_us && !ip.src.is_unspecified() {
            let mut body = alloc::vec![0; 4];
            body.extend_from_slice(bytes.get(..MAX_QUOTE).unwrap_or(bytes));
            let header = Icmpv6Header { ty: ICMPV6_DEST_UNREACHABLE, code: ICMPV6_PORT_UNREACHABLE };
            let payload = header.emit(ip.dst, ip.src, &body);
            self.send_ip6(now, Packet { src: ip.dst.into(), dst: ip.src.into(), protocol: PROTO_ICMPV6, payload });
        }
    }

    fn process_tcp6(&mut self, now: Instant, ip: &Ipv6Header, payload: &[u8], sockets: &mut SocketSet) {
        let Some((tcp, data)) = TcpHeader::parse(payload, ip.src, ip.dst) else { return };
        let dst = SocketAddr::new(ip.dst.into(), tcp.dst_port);
        let src = SocketAddr::new(ip.src.into(), tcp.src_port);
        let socket = {
            let mut exact = None;
            let mut listen = None;
            let mut queued = None;
            for (h, s) in sockets.iter() {
                if let Socket::Tcp(s) = s {
                    if s.accepts_exact(dst, src) {
                        exact = Some(h);
                        break;
                    }
                    if listen.is_none() && s.accepts_listen(dst) {
                        listen = Some(h);
                    }
                    if queued.is_none() && s.accepts_queued(dst) {
                        queued = Some(h);
                    }
                }
            }
            exact.or(listen).or(queued)
        };
        let rst = match socket {
            Some(h) => {
                let mut cx = self.cx6(now);
                sockets.get_mut::<crate::TcpSocket>(h).process(&mut cx, dst, src, &tcp, data)
            }
            None => reset_for(&tcp, data.len()),
        };
        if let Some(rst) = rst {
            let payload = rst.emit(ip.dst, ip.src, &[]);
            self.send_ip6(now, Packet { src: ip.dst.into(), dst: ip.src.into(), protocol: PROTO_TCP, payload });
        }
    }

    fn process_icmpv6(&mut self, now: Instant, ip: &Ipv6Header, payload: &[u8], to_us: bool, sockets: &mut SocketSet) {
        let Some((icmp, body)) = Icmpv6Header::parse(payload, ip.src, ip.dst) else { return };
        // Neighbor discovery proves its locality by its hop limit.
        let nd = ip.hop_limit == ND_HOP_LIMIT && icmp.code == 0;
        match icmp.ty {
            ICMPV6_ECHO_REQUEST if to_us && icmp.code == 0 && !ip.src.is_unspecified() => {
                let Some((ident, seq, data)) = parse_echo(body) else { return };
                let header = Icmpv6Header { ty: ICMPV6_ECHO_REPLY, code: 0 };
                let payload = header.emit(ip.dst, ip.src, &echo_body(ident, seq, data));
                self.send_ip6(now, Packet { src: ip.dst.into(), dst: ip.src.into(), protocol: PROTO_ICMPV6, payload });
            }
            ICMPV6_ECHO_REPLY if to_us => {
                let Some((ident, seq, data)) = parse_echo(body) else { return };
                for (_, s) in sockets.iter_mut() {
                    if let Socket::Icmp(s) = s
                        && s.ident() == ident
                    {
                        s.process(EchoReply { from: ip.src.into(), seq, data: data.to_vec(), at: now });
                        break;
                    }
                }
            }
            ICMPV6_NEIGHBOR_SOLICIT if nd => self.process_ns(now, ip, body),
            ICMPV6_NEIGHBOR_ADVERT if nd => self.process_na(now, ip, body),
            ICMPV6_ROUTER_ADVERT if nd && is_link_local(ip.src) => self.process_ra(now, ip, body),
            _ => {}
        }
    }

    fn process_ns(&mut self, now: Instant, ip: &Ipv6Header, body: &[u8]) {
        let Some(ns) = NeighborSolicit::parse(body) else { return };
        if ns.target.is_multicast() {
            return;
        }
        let Some(own) = self.v6.all().find(|a| a.addr == ns.target) else { return };
        let tentative = !matches!(own.dad, Dad::Done);
        if ip.src.is_unspecified() {
            // Someone is probing an address (RFC 4862 section 5.4.3). If we
            // are probing it too, neither of us may have it; if it is ours,
            // tell the prober.
            if ip.dst != solicited_node(ns.target) || ns.source_ll.is_some() {
                return;
            }
            if tentative {
                self.duplicate(ns.target);
            } else {
                let advert = NeighborAdvert {
                    router: false,
                    solicited: false,
                    override_: true,
                    target: ns.target,
                    target_ll: Some(self.mac),
                };
                let body = advert.emit();
                self.send_icmp6(multicast_mac(ALL_NODES), ns.target, ALL_NODES, ICMPV6_NEIGHBOR_ADVERT, &body);
            }
            return;
        }
        if tentative {
            return;
        }
        if ip.src.is_multicast() {
            return;
        }
        let Some(ll) = ns.source_ll.filter(|m| !m.is_multicast()) else {
            // A unicast solicitation needs no source link-layer option
            // (RFC 4861 7.2.3, 7.2.4): answer from the neighbor cache, or
            // look the sender up so that its next probe finds an entry.
            if ip.dst == ns.target
                && ns.source_ll.is_none()
                && let Some(ll) = self.v6.lookup(ip.src, now)
            {
                let advert = NeighborAdvert {
                    router: false,
                    solicited: true,
                    override_: true,
                    target: ns.target,
                    target_ll: Some(self.mac),
                };
                self.send_icmp6(ll, ns.target, ip.src, ICMPV6_NEIGHBOR_ADVERT, &advert.emit());
            } else if ip.dst == ns.target && ns.source_ll.is_none() && !self.v6.requests.iter().any(|r| r.ip == ip.src)
            {
                self.v6.requests.push(Request { ip: ip.src, first: now, last: now });
                self.send_ns(ip.src, Some(IpAddr::V6(ns.target)));
            }
            return;
        };
        self.learned6(now, ip.src, ll);
        let advert = NeighborAdvert {
            router: false,
            solicited: true,
            override_: true,
            target: ns.target,
            target_ll: Some(self.mac),
        };
        self.send_icmp6(ll, ns.target, ip.src, ICMPV6_NEIGHBOR_ADVERT, &advert.emit());
    }

    fn process_na(&mut self, now: Instant, ip: &Ipv6Header, body: &[u8]) {
        let Some(na) = NeighborAdvert::parse(body) else { return };
        if na.target.is_multicast() || (ip.dst.is_multicast() && na.solicited) {
            return;
        }
        // Someone else answers for an address we are probing.
        if self.v6.all().any(|a| a.addr == na.target && !matches!(a.dad, Dad::Done)) {
            self.duplicate(na.target);
            return;
        }
        let Some(ll) = na.target_ll.filter(|m| !m.is_multicast()) else { return };
        // Only what we asked for, or a change to what we know.
        let wanted = self.v6.requests.iter().any(|r| r.ip == na.target);
        if wanted || (na.override_ && self.v6.neighbors.iter().any(|n| n.ip == na.target)) {
            self.learned6(now, na.target, ll);
        }
    }

    /// `a` is in use by another host, so it is dropped. A link-local one
    /// leaves IPv6 on the interface unusable (RFC 4862 section 5.4.5).
    fn duplicate(&mut self, a: Ipv6Addr) {
        if self.v6.link_local.addr == a {
            self.v6.link_local.dad = Dad::Duplicate;
            self.v6.rs_next = None;
        } else {
            let expires = self.v6.addrs.iter().find(|x| x.addr == a).and_then(|x| x.expires);
            self.v6.addrs.retain(|x| x.addr != a);
            self.address_collided(a, expires);
        }
    }

    fn process_ra(&mut self, now: Instant, ip: &Ipv6Header, body: &[u8]) {
        if !self.v6.slaac {
            return;
        }
        let Some(ra) = RouterAdvert::parse(body) else { return };
        self.v6.rs_next = None;
        if let Some(ll) = ra.source_ll.filter(|m| !m.is_multicast()) {
            self.learned6(now, ip.src, ll);
        }
        // The router: listed while its lifetime lasts, gone at 0.
        if ra.router_lifetime == 0 {
            self.v6.routers.retain(|r| r.addr != ip.src);
        } else {
            // Updated in place, so that the default router (the first) does
            // not change with every advertisement.
            let expires = now + Duration::from_secs(u64::from(ra.router_lifetime));
            if let Some(r) = self.v6.routers.iter_mut().find(|r| r.addr == ip.src) {
                r.expires = expires;
            } else if self.v6.routers.len() < MAX_ROUTERS {
                self.v6.routers.push(Router { addr: ip.src, expires });
            }
        }
        // Only a router we accepted (lifetime above 0) may lower the MTU.
        let accepted = self.v6.routers.iter().any(|r| r.addr == ip.src);
        if let Some(mtu) = ra.mtu.and_then(|m| usize::try_from(m).ok()).filter(|&m| accepted && m >= IPV6_MIN_MTU) {
            self.v6.mtu = Some(mtu.min(self.mtu));
        }
        // RDNSS (RFC 8106): lifetime 0 withdraws a server; others replace the
        // list and last for their lifetime.
        self.v6.dns.retain(|d| !ra.dns_withdrawn.contains(d));
        if !ra.dns.is_empty() {
            let usable = |d: &&Ipv6Addr| !d.is_multicast() && !d.is_unspecified();
            self.v6.dns = ra.dns.iter().filter(usable).copied().take(MAX_DNS).collect();
            self.v6.dns_expires = lifetime(now, ra.dns_lifetime);
        }
        if self.v6.dns.is_empty() {
            self.v6.dns_expires = None;
        }
        for p in &ra.prefixes {
            // Link-local prefixes and nonsense are ignored.
            let sane = p.prefix_len <= 128
                && !is_link_local(p.prefix)
                && !p.prefix.is_multicast()
                && p.preferred_lifetime <= p.valid_lifetime;
            if !sane {
                continue;
            }
            let expires = lifetime(now, p.valid_lifetime);
            if p.on_link {
                if let Some(x) = self.v6.prefixes.iter_mut().find(|x| x.prefix == p.prefix && x.len == p.prefix_len) {
                    x.expires = expires;
                } else if self.v6.prefixes.len() < MAX_PREFIXES && p.valid_lifetime > 0 {
                    self.v6.prefixes.push(Prefix { prefix: p.prefix, len: p.prefix_len, expires });
                }
            }
            // SLAAC needs a 64-bit prefix to put the 64-bit identifier after.
            if !p.autonomous || p.prefix_len != 64 {
                continue;
            }
            self.temp_for_prefix(now, p.prefix, p.valid_lifetime, p.preferred_lifetime);
            let addr = self.slaac_address(p.prefix);
            if let Some(a) = self.v6.addrs.iter_mut().find(|a| a.addr == addr) {
                // RFC 4862 section 5.5.3 e).
                let Some(current) = a.expires else { continue };
                let remaining = (current - now).as_secs();
                if p.valid_lifetime > TWO_HOURS || u64::from(p.valid_lifetime) > remaining {
                    a.expires = expires;
                } else if remaining > u64::from(TWO_HOURS) {
                    a.expires = lifetime(now, TWO_HOURS);
                }
            } else if p.valid_lifetime > 0 && self.v6.addrs.len() < MAX_ADDRESSES {
                self.v6.addrs.push(Address { addr, prefix_len: 64, dad: Dad::Idle, expires });
            }
        }
    }
}

#[cfg(test)]
mod tests;
