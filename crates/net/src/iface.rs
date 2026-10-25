//! An Ethernet interface: ARP, IPv4 routing to the next hop, ICMP echo, and
//! the glue between a device and the sockets.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use core::time::Duration;

use osmium_hal::net::{MacAddress, NetDevice, NetError};

use crate::Instant;
use crate::arp::ArpCache;
use crate::igmp::{
    ALL_HOSTS, IGMP_QUERY, IGMP_REPORT_V1, IGMP_REPORT_V2, Igmp, IgmpPacket, Outgoing, PROTO_IGMP, multicast_mac,
};
use crate::ipopt;
use crate::ipv6::{ETHERTYPE_IPV6, IPV6_HEADER_LEN, Ipv6Header};
use crate::rng::Rng;
use crate::socket::icmp::EchoReply;
use crate::socket::tcp::reset_for;
use crate::socket::{Cx, Packet, Socket, SocketSet, dhcp};
use crate::wire::*;

mod v6;
pub use v6::Ipv6Address;

/// Frames waiting for the device; more are dropped.
const TX_QUEUE: usize = 128;
/// Packets waiting for ARP resolution; more are dropped.
const PENDING: usize = 32;
const ARP_RETRY: Duration = Duration::from_secs(1);
/// How long packets wait for an ARP reply before they are dropped.
const ARP_GIVE_UP: Duration = Duration::from_secs(3);
/// Frames read from the device per poll, so that a flood cannot starve
/// transmission.
const RX_BURST: usize = 64;
const TTL: u8 = 64;
/// Pieces one datagram may arrive in; more condemn it, so that a stream of
/// tiny fragments cannot make the bookkeeping outgrow the datagram.
const MAX_PIECES: usize = 512;
/// How long the pieces of a fragmented datagram are kept (RFC 791 suggests
/// 15 s).
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(15);
/// Datagrams being reassembled at once; the oldest is dropped for a new one.
const REASSEMBLIES: usize = 8;
/// The most payload a datagram can have (the 16-bit total length less a
/// header).
const MAX_DATAGRAM: usize = 65535 - IPV4_HEADER_LEN;
/// The largest receive buffer allocated, whatever the device claims: room
/// for an IP packet of 65535 bytes and its Ethernet header.
const MAX_FRAME: usize = 65550;

/// An interface's IPv4 configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// The interface's address.
    pub address: Ipv4Addr,
    /// Length of the subnet prefix, 0 to 32.
    pub prefix_len: u8,
    /// The router for destinations outside the subnet.
    pub gateway: Option<Ipv4Addr>,
    /// A DNS server, as DHCP reports it. The stack itself does not use it.
    pub dns: Option<Ipv4Addr>,
}

impl Config {
    /// The subnet mask.
    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::MAX.checked_shl(32 - u32::from(self.prefix_len.min(32))).unwrap_or(0))
    }

    /// The subnet's broadcast address.
    pub fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.address) | !u32::from(self.netmask()))
    }

    /// Returns true if `ip` is on the subnet.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let mask = u32::from(self.netmask());
        u32::from(ip) & mask == u32::from(self.address) & mask
    }
}

struct Pending {
    next_hop: Ipv4Addr,
    packet: Packet,
}

/// A fragmented datagram being put back together.
struct Reassembly {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    ident: u16,
    first: Instant,
    /// The datagram's payload length, known once its last fragment arrives.
    total: Option<usize>,
    header: Ipv4Header,
    /// `(offset, bytes)`, sorted, disjoint.
    pieces: Vec<(usize, Vec<u8>)>,
}

impl Reassembly {
    /// Adds a fragment. Returns false if it overlaps what is held, which
    /// condemns the whole datagram.
    fn add(&mut self, offset: usize, more: bool, data: &[u8]) -> bool {
        let end = offset + data.len();
        if !more {
            if self.total.is_some_and(|t| t != end) {
                return false;
            }
            self.total = Some(end);
        }
        if self.total.is_some_and(|t| end > t) {
            return false;
        }
        if self.pieces.len() >= MAX_PIECES {
            return false;
        }
        let at = self.pieces.partition_point(|(o, _)| *o < offset);
        if let Some((o, d)) = at.checked_sub(1).and_then(|i| self.pieces.get(i))
            && o + d.len() > offset
        {
            return false;
        }
        if let Some((o, d)) = self.pieces.get(at) {
            if *o == offset && d.len() == data.len() {
                return true; // a duplicate
            }
            if *o < end {
                return false;
            }
        }
        self.pieces.insert(at, (offset, data.to_vec()));
        true
    }

    /// The whole payload, if every piece is here.
    fn complete(&self) -> Option<Vec<u8>> {
        let total = self.total?;
        let mut next = 0;
        for (o, d) in &self.pieces {
            if *o != next {
                return None;
            }
            next += d.len();
        }
        (next == total).then(|| self.pieces.iter().flat_map(|(_, d)| d.iter().copied()).collect())
    }
}

struct ArpRequest {
    ip: Ipv4Addr,
    first: Instant,
    last: Instant,
}

/// One Ethernet interface and its IPv4 state.
pub struct Interface {
    mac: MacAddress,
    mtu: usize,
    config: Option<Config>,
    arp: ArpCache,
    requests: Vec<ArpRequest>,
    pending: VecDeque<Pending>,
    tx: VecDeque<Vec<u8>>,
    ident: u16,
    rng: Rng,
    rx_buf: Vec<u8>,
    reassembling: Vec<Reassembly>,
    igmp: Igmp,
    multicast_ttl: u8,
    v6: v6::State,
    /// IPv4 packets addressed to 127.0.0.0/8, delivered by the next poll.
    loopback: VecDeque<Vec<u8>>,
    /// Set while a looped-back packet is being processed.
    looping: bool,
    /// A packet was looped back since [`loopback_pending`](Self::loopback_pending) last said so.
    looped: bool,
}

/// The part of an Ethernet frame after its header.
fn ip_area(frame: &mut [u8]) -> &mut [u8] {
    frame.get_mut(ETH_HEADER_LEN..).unwrap_or(&mut [])
}

impl Interface {
    /// An unconfigured interface for `dev`, which it takes the MAC address
    /// and MTU from. `seed` keys the generator of TCP initial sequence
    /// numbers, DHCP and DNS transaction ids and ephemeral ports; use a
    /// hardware random number, or [`new_with_entropy`](Self::new_with_entropy)
    /// for more than 64 bits.
    pub fn new<D: NetDevice + ?Sized>(dev: &D, seed: u64) -> Self {
        let frame = dev.max_frame_len().min(MAX_FRAME);
        Self {
            mac: dev.mac_address(),
            mtu: frame.saturating_sub(ETH_HEADER_LEN).min(1500),
            config: None,
            arp: ArpCache::new(),
            requests: Vec::new(),
            pending: VecDeque::new(),
            tx: VecDeque::new(),
            ident: 0,
            rng: Rng::new(seed),
            rx_buf: vec![0; frame],
            reassembling: Vec::new(),
            igmp: Igmp::new(),
            multicast_ttl: 1,
            v6: v6::State::new(dev.mac_address()),
            loopback: VecDeque::new(),
            looping: false,
            looped: false,
        }
    }

    /// Like [`new`](Self::new), with the random number generator keyed from
    /// `entropy`, bytes from a hardware source (such as a TRNG or the
    /// firmware's random seed). TCP initial sequence numbers, DHCP and DNS
    /// transaction ids and ephemeral ports are unpredictable to a peer only
    /// as far as this is.
    pub fn new_with_entropy<D: NetDevice + ?Sized>(dev: &D, seed: u64, entropy: &[u8]) -> Self {
        let mut iface = Self::new(dev, seed);
        iface.add_entropy(entropy);
        iface
    }

    /// Mixes `entropy` into the generator that picks TCP initial sequence
    /// numbers, transaction ids and ephemeral ports. Call it whenever fresh
    /// randomness is at hand, such as at each timer interrupt.
    pub fn add_entropy(&mut self, entropy: &[u8]) {
        self.rng.mix(entropy);
    }

    /// The interface's MAC address.
    pub fn mac_address(&self) -> MacAddress {
        self.mac
    }

    /// The largest IP packet the interface sends.
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// The IPv4 configuration, if any.
    pub fn config(&self) -> Option<Config> {
        self.config
    }

    /// Sets or clears the IPv4 configuration. A [`DhcpClient`] in the
    /// socket set does this itself.
    ///
    /// [`DhcpClient`]: crate::DhcpClient
    pub fn set_config(&mut self, config: Option<Config>) {
        if config.map(|c| c.address) != self.config.map(|c| c.address) {
            self.arp.clear();
            self.pending.clear();
            self.requests.clear();
        }
        self.config = config;
    }

    /// Joins the multicast `group` (such as 239.1.2.3): the interface then
    /// accepts packets for it, which [`UdpSocket`](crate::UdpSocket)s bound
    /// to its port receive, and reports the membership with IGMP so that
    /// routers and snooping switches forward it. A group joined twice must
    /// be left twice. The 224.0.0.1 all-hosts group is always joined.
    ///
    /// Fails with [`Error::InvalidAddress`](crate::Error::InvalidAddress) if
    /// `group` is not a multicast address and
    /// [`Error::WouldBlock`](crate::Error::WouldBlock) if the interface is in
    /// [`MAX_GROUPS`](crate::igmp::MAX_GROUPS) groups already.
    pub fn join_multicast_group(&mut self, now: Instant, group: Ipv4Addr) -> Result<(), crate::Error> {
        self.igmp.join(group, now)
    }

    /// Leaves a group joined with
    /// [`join_multicast_group`](Self::join_multicast_group), telling the
    /// routers if this host was the last to report it. Fails with
    /// [`Error::InvalidState`](crate::Error::InvalidState) if the group was
    /// not joined.
    pub fn leave_multicast_group(&mut self, now: Instant, group: Ipv4Addr) -> Result<(), crate::Error> {
        if let Some(Outgoing { dst, message }) = self.igmp.leave(group, now)?
            && let Some(c) = self.config
        {
            self.send_igmp(now, c.address, dst, message);
        }
        Ok(())
    }

    /// Returns true if the interface accepts packets for `group`.
    pub fn is_multicast_member(&self, group: Ipv4Addr) -> bool {
        self.igmp.is_member(group)
    }

    /// The groups joined, in the order they were.
    pub fn multicast_groups(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.igmp.groups()
    }

    /// Sets the time to live of multicast datagrams sent; the default 1 keeps
    /// them on the link. (IGMP messages always use 1.)
    pub fn set_multicast_ttl(&mut self, ttl: u8) {
        self.multicast_ttl = ttl;
    }

    fn send_igmp(&mut self, now: Instant, src: Ipv4Addr, dst: Ipv4Addr, message: IgmpPacket) {
        self.send_ip(now, Packet { src: src.into(), dst: dst.into(), protocol: PROTO_IGMP, payload: message.emit() });
    }

    pub(crate) fn random_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    /// A random port in the dynamic range, for binding a client socket.
    pub fn ephemeral_port(&mut self) -> u16 {
        self.rng.ephemeral_port()
    }

    /// Like [`ephemeral_port`](Self::ephemeral_port), but a port no TCP or
    /// UDP socket of `sockets` is bound to.
    pub fn ephemeral_port_in(&mut self, sockets: &SocketSet) -> u16 {
        sockets.free_ephemeral_port(&mut self.rng)
    }

    fn mss(&self) -> u16 {
        self.mtu.saturating_sub(IPV4_HEADER_LEN + TCP_HEADER_LEN).max(1) as u16
    }

    /// The TCP maximum segment size over IPv6.
    fn mss6(&self) -> u16 {
        self.v6.mtu(self.mtu).saturating_sub(IPV6_HEADER_LEN + TCP_HEADER_LEN).max(1) as u16
    }

    /// Receives what `dev` has, lets the sockets process it, sends what the
    /// sockets have queued, and retries ARP. Returns true if any frame was
    /// received or sent.
    pub fn poll<D: NetDevice + ?Sized>(&mut self, now: Instant, dev: &mut D, sockets: &mut SocketSet) -> bool {
        let mut active = false;
        let mut buf = core::mem::take(&mut self.rx_buf);
        for _ in 0..RX_BURST {
            match dev.receive(&mut buf) {
                Ok(n) => {
                    active = true;
                    // A device that reports more than it could have copied
                    // is not believed.
                    if let Some(frame) = buf.get(..n) {
                        self.process_frame(now, frame, sockets);
                    }
                }
                Err(NetError::WouldBlock) => break,
                Err(_) => continue,
            }
        }
        self.rx_buf = buf;

        for (_, s) in sockets.iter_mut() {
            if let Socket::Dhcp(d) = s
                && let Some(config) = d.take_iface_update()
            {
                self.set_config(config);
            }
        }

        self.poll_v6(now);

        sockets.assign_ephemeral_ports(&mut self.rng);
        let mut out = Vec::new();
        for (_, s) in sockets.iter_mut() {
            if self.tx.len() >= TX_QUEUE / 2 {
                break;
            }
            let mut cx = Cx {
                now,
                addr: self.config.map(|c| c.address),
                addr6: self.v6.global(),
                link_local6: self.v6.link_local(),
                mac: self.mac,
                mss: self.mss(),
                mss6: self.mss6(),
                rng: &mut self.rng,
            };
            s.dispatch(&mut cx, &mut out);
            for p in out.drain(..) {
                self.send_ip(now, p);
            }
        }

        let looped = self.loopback.len();
        for _ in 0..looped {
            let Some(bytes) = self.loopback.pop_front() else { break };
            self.looping = true;
            self.looped = true;
            if bytes.first().is_some_and(|b| b >> 4 == 6) {
                self.process_ipv6(now, &bytes, sockets);
            } else {
                self.process_ipv4(now, &bytes, false, sockets);
            }
            self.looping = false;
        }

        if let Some(c) = self.config {
            for Outgoing { dst, message } in self.igmp.poll(now) {
                self.send_igmp(now, c.address, dst, message);
            }
        }
        self.retry_arp(now);
        self.reassembling.retain(|r| now - r.first < REASSEMBLY_TIMEOUT);
        active | self.flush(dev)
    }

    /// Whether packets to 127.0.0.0/8 were sent or delivered since this was
    /// last asked. If so, poll again: the sockets that received them have
    /// replies to send, and those arrive in the same way, without a device.
    pub fn loopback_pending(&mut self) -> bool {
        core::mem::take(&mut self.looped)
    }

    /// When the interface next needs polling if nothing arrives: a time at
    /// or before now means at once. `None` means only when a frame arrives.
    pub fn poll_at(&self, sockets: &SocketSet) -> Option<Instant> {
        if !self.tx.is_empty() {
            return Some(Instant::ZERO);
        }
        let arp = self.requests.iter().map(|r| r.last + ARP_RETRY).min();
        let arp = match (arp, self.config.and(self.igmp.poll_at())) {
            (Some(a), Some(g)) => Some(a.min(g)),
            (a, g) => a.or(g),
        };
        let arp = match (arp, self.v6.poll_at()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        match (arp, sockets.poll_at()) {
            (Some(a), Some(s)) => Some(a.min(s)),
            (a, s) => a.or(s),
        }
    }

    /// How long until the interface next needs polling, measured from
    /// `now`; `None` means only when a frame arrives.
    pub fn poll_delay(&self, now: Instant, sockets: &SocketSet) -> Option<Duration> {
        self.poll_at(sockets).map(|t| t - now)
    }

    fn flush<D: NetDevice + ?Sized>(&mut self, dev: &mut D) -> bool {
        let mut sent = false;
        while let Some(frame) = self.tx.front() {
            match dev.transmit(frame) {
                Ok(()) => sent = true,
                Err(NetError::WouldBlock) => break,
                // Too large or a dead link: nothing to gain by keeping it.
                Err(_) => {}
            }
            self.tx.pop_front();
        }
        sent
    }

    /// Queues `p` for delivery to this host's own sockets, no device involved.
    fn queue_loopback(&mut self, p: &Packet) {
        if self.loopback.len() >= TX_QUEUE {
            return;
        }
        let (IpAddr::V4(src), IpAddr::V4(dst)) = (p.src, p.dst) else { return };
        let header = Ipv4Header { src, dst, protocol: p.protocol, ttl: TTL, ident: 0, payload_len: p.payload.len() };
        let mut bytes = vec![0; IPV4_HEADER_LEN + p.payload.len()];
        header.emit(&mut bytes);
        crate::wire::put(&mut bytes, IPV4_HEADER_LEN, &p.payload);
        self.loopback.push_back(bytes);
        self.looped = true;
    }

    /// Queues an IPv6 packet to this host itself (`::1`), no device involved.
    fn queue_loopback6(&mut self, src: Ipv6Addr, dst: Ipv6Addr, protocol: u8, payload: &[u8]) {
        if self.loopback.len() >= TX_QUEUE {
            return;
        }
        let header =
            Ipv6Header { src, dst, next_header: protocol, hop_limit: 64, payload_len: payload.len(), fragment: None };
        let mut bytes = vec![0; IPV6_HEADER_LEN + payload.len()];
        header.emit(&mut bytes);
        crate::wire::put(&mut bytes, IPV6_HEADER_LEN, payload);
        self.loopback.push_back(bytes);
        self.looped = true;
    }

    fn queue_frame(&mut self, frame: Vec<u8>) {
        if self.tx.len() < TX_QUEUE {
            self.tx.push_back(frame);
        }
    }

    fn ethernet_frame(&self, dst: MacAddress, ethertype: u16, len: usize) -> Vec<u8> {
        let mut frame = vec![0; ETH_HEADER_LEN + len];
        EthernetHeader { dst, src: self.mac, ethertype }.emit(&mut frame);
        frame
    }

    /// The frames that carry `p` to `dst_mac`: one, or fragments if it
    /// exceeds the MTU.
    fn ip_frames(&mut self, dst_mac: MacAddress, p: &Packet) -> Vec<Vec<u8>> {
        let (IpAddr::V4(p_src), IpAddr::V4(p_dst)) = (p.src, p.dst) else { return Vec::new() };
        self.ident = self.ident.wrapping_add(1);
        let step = self.mtu.saturating_sub(IPV4_HEADER_LEN) / 8 * 8;
        let whole = IPV4_HEADER_LEN + p.payload.len() <= self.mtu;
        // IGMP carries the router alert option (RFC 2236); it is never
        // fragmented.
        let alert = p.protocol == PROTO_IGMP && whole;
        let hlen = if alert { ipopt::HEADER_LEN_ROUTER_ALERT } else { IPV4_HEADER_LEN };
        let ttl = if p.protocol == PROTO_IGMP {
            1
        } else if p.dst.is_multicast() {
            self.multicast_ttl
        } else {
            TTL
        };
        if step == 0 && !whole {
            return Vec::new();
        }
        let mut frames = Vec::with_capacity(if whole { 1 } else { p.payload.len().div_ceil(step) });
        let mut offset = 0;
        while offset < p.payload.len() || (whole && frames.is_empty()) {
            let len = if whole { p.payload.len() } else { step.min(p.payload.len().saturating_sub(offset)) };
            let mut frame = self.ethernet_frame(dst_mac, ETHERTYPE_IPV4, hlen + len);
            let header =
                Ipv4Header { src: p_src, dst: p_dst, protocol: p.protocol, ttl, ident: self.ident, payload_len: len };
            if alert {
                ipopt::emit_with_router_alert(&header, ip_area(&mut frame));
            } else if whole {
                header.emit(ip_area(&mut frame));
            } else {
                let fragment = Fragment { more: offset + len < p.payload.len(), offset };
                header.emit_fragment(ip_area(&mut frame), fragment);
            }
            crate::wire::put(&mut frame, ETH_HEADER_LEN + hlen, p.payload.get(offset..offset + len).unwrap_or(&[]));
            frames.push(frame);
            offset += len;
        }
        frames
    }

    fn queue_ip(&mut self, dst_mac: MacAddress, p: &Packet) {
        for frame in self.ip_frames(dst_mac, p) {
            self.queue_frame(frame);
        }
    }

    /// Routes `p` to its next hop, resolving the hop's MAC address first if
    /// it is not cached.
    fn send_ip(&mut self, now: Instant, p: Packet) {
        let (IpAddr::V4(_), IpAddr::V4(p_dst)) = (p.src, p.dst) else { return self.send_ip6(now, p) };
        // TCP sizes its segments to the MTU and relies on DF; everything else
        // is fragmented.
        let too_big = IPV4_HEADER_LEN + p.payload.len() > self.mtu;
        if (too_big && p.protocol == PROTO_TCP) || p.payload.len() > MAX_DATAGRAM || self.mtu < IPV4_HEADER_LEN + 8 {
            return;
        }
        if p.dst.is_loopback() {
            return self.queue_loopback(&p);
        }
        if p.dst.is_multicast() {
            // Multicast has no next hop to resolve: the group names the MAC.
            if self.config.is_some() {
                self.queue_ip(multicast_mac(p_dst), &p);
            }
            return;
        }
        let next_hop = match self.config {
            _ if p_dst.is_broadcast() => None,
            Some(c) if p_dst == c.broadcast() => None,
            Some(c) if c.contains(p_dst) => Some(p_dst),
            Some(Config { gateway: Some(gw), .. }) => Some(gw),
            _ => return,
        };
        let Some(hop) = next_hop else {
            return self.queue_ip(MacAddress::BROADCAST, &p);
        };
        if let Some(mac) = self.arp.lookup(hop, now) {
            return self.queue_ip(mac, &p);
        }
        if self.pending.len() >= PENDING {
            return;
        }
        self.pending.push_back(Pending { next_hop: hop, packet: p });
        if !self.requests.iter().any(|r| r.ip == hop) {
            self.requests.push(ArpRequest { ip: hop, first: now, last: now });
            self.send_arp_request(hop);
        }
    }

    fn send_arp_request(&mut self, target_ip: Ipv4Addr) {
        let Some(c) = self.config else { return };
        let request = ArpPacket {
            op: ARP_REQUEST,
            sender_mac: self.mac,
            sender_ip: c.address,
            target_mac: MacAddress::default(),
            target_ip,
        };
        let mut frame = self.ethernet_frame(MacAddress::BROADCAST, ETHERTYPE_ARP, ARP_LEN);
        request.emit(ip_area(&mut frame));
        self.queue_frame(frame);
    }

    fn retry_arp(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.requests.len() {
            let Some(r) = self.requests.get_mut(i) else { break };
            if now - r.first >= ARP_GIVE_UP {
                let ip = r.ip;
                self.requests.swap_remove(i);
                self.pending.retain(|p| p.next_hop != ip);
                continue;
            }
            if now - r.last >= ARP_RETRY {
                r.last = now;
                let ip = r.ip;
                self.send_arp_request(ip);
            }
            i += 1;
        }
    }

    fn learned(&mut self, now: Instant, ip: Ipv4Addr, mac: MacAddress) {
        self.arp.insert(ip, mac, now);
        self.requests.retain(|r| r.ip != ip);
        let mut i = 0;
        while i < self.pending.len() {
            match self.pending.get(i) {
                Some(p) if p.next_hop == ip => {
                    if let Some(p) = self.pending.remove(i) {
                        self.queue_ip(mac, &p.packet);
                    }
                }
                _ => i += 1,
            }
        }
    }

    fn process_frame(&mut self, now: Instant, frame: &[u8], sockets: &mut SocketSet) {
        let Some((eth, payload)) = EthernetHeader::parse(frame) else { return };
        if eth.dst != self.mac && !eth.dst.is_multicast() {
            return;
        }
        match eth.ethertype {
            ETHERTYPE_ARP => self.process_arp(now, payload),
            ETHERTYPE_IPV4 => self.process_ipv4(now, payload, eth.dst.is_multicast(), sockets),
            ETHERTYPE_IPV6 => self.process_ipv6(now, payload, sockets),
            _ => {}
        }
    }

    fn process_arp(&mut self, now: Instant, payload: &[u8]) {
        let Some(arp) = ArpPacket::parse(payload) else { return };
        let Some(c) = self.config else { return };
        if arp.sender_ip.is_unspecified() || arp.sender_mac.is_multicast() {
            return;
        }
        // Nobody else may claim our address or the subnet's broadcast, and
        // hosts off the subnet are reached through the gateway.
        let ip = arp.sender_ip;
        if ip == c.address || ip == c.broadcast() || !(c.contains(ip) || c.gateway == Some(ip)) {
            return;
        }
        // RFC 826: update an existing entry from any packet, add one only
        // when we are the target.
        let for_us = arp.target_ip == c.address;
        if for_us || self.arp.contains(arp.sender_ip) {
            self.learned(now, arp.sender_ip, arp.sender_mac);
        }
        if for_us && arp.op == ARP_REQUEST {
            let reply = ArpPacket {
                op: ARP_REPLY,
                sender_mac: self.mac,
                sender_ip: c.address,
                target_mac: arp.sender_mac,
                target_ip: arp.sender_ip,
            };
            let mut frame = self.ethernet_frame(arp.sender_mac, ETHERTYPE_ARP, ARP_LEN);
            reply.emit(ip_area(&mut frame));
            self.queue_frame(frame);
        }
    }

    /// Takes a fragment of a datagram; returns the datagram, as a whole
    /// packet, once its last piece arrives.
    fn reassemble(&mut self, now: Instant, ip: &Ipv4Header, fragment: Fragment, payload: &[u8]) -> Option<Vec<u8>> {
        // Every piece but the last is a whole number of 8-byte units, and
        // none is empty.
        if payload.is_empty()
            || (fragment.more && payload.len() % 8 != 0)
            || fragment.offset + payload.len() > MAX_DATAGRAM
        {
            return None;
        }
        let key = |r: &Reassembly| (r.src, r.dst, r.protocol, r.ident) == (ip.src, ip.dst, ip.protocol, ip.ident);
        let i = match self.reassembling.iter().position(key) {
            Some(i) => i,
            None => {
                if self.reassembling.len() >= REASSEMBLIES {
                    self.reassembling.remove(0);
                }
                self.reassembling.push(Reassembly {
                    src: ip.src,
                    dst: ip.dst,
                    protocol: ip.protocol,
                    ident: ip.ident,
                    first: now,
                    total: None,
                    header: *ip,
                    pieces: Vec::new(),
                });
                self.reassembling.len() - 1
            }
        };
        let r = self.reassembling.get_mut(i)?;
        if !r.add(fragment.offset, fragment.more, payload) {
            self.reassembling.remove(i);
            return None;
        }
        let data = r.complete()?;
        let header = Ipv4Header { payload_len: data.len(), ..r.header };
        self.reassembling.remove(i);
        let mut packet = vec![0; IPV4_HEADER_LEN + data.len()];
        header.emit(&mut packet);
        crate::wire::put(&mut packet, IPV4_HEADER_LEN, &data);
        Some(packet)
    }

    /// Handles an IPv4 packet that arrived in a link-layer broadcast or
    /// multicast frame if `link_multicast`.
    fn process_ipv4(&mut self, now: Instant, bytes: &[u8], link_multicast: bool, sockets: &mut SocketSet) {
        let Some((ip, fragment, payload)) = Ipv4Header::parse_fragment(bytes) else { return };
        // A source that is no one host's, or is ours, is forged.
        let src = ip.src;
        if src.is_unspecified() || src.is_broadcast() || src.is_multicast() || (src.is_loopback() && !self.looping) {
            return;
        }
        if self.config.is_some_and(|c| src == c.address || src == c.broadcast()) {
            return;
        }
        let ours = self.config.map(|c| c.address);
        let to_us = Some(ip.dst) == ours || (self.looping && ip.dst.is_loopback());
        // Multicast is taken for the groups joined, and only once configured.
        let to_group = ours.is_some() && ip.dst.is_multicast() && self.igmp.is_member(ip.dst);
        let broadcast = ip.dst.is_broadcast() || self.config.is_some_and(|c| ip.dst == c.broadcast());
        // Before it has an address the interface takes UDP to anyone, which
        // is how a DHCP server's unicast OFFER arrives; it goes to the DHCP
        // client alone.
        let unconfigured_udp = ours.is_none() && ip.protocol == PROTO_UDP;
        if !(to_us || broadcast || unconfigured_udp || to_group) {
            return;
        }
        if !fragment.is_whole() {
            if let Some(whole) = self.reassemble(now, &ip, fragment, payload) {
                self.process_ipv4(now, &whole, link_multicast, sockets);
            }
            return;
        }
        let mut cx = Cx {
            now,
            addr: ours,
            addr6: self.v6.global(),
            link_local6: self.v6.link_local(),
            mac: self.mac,
            mss: self.mss(),
            mss6: self.mss6(),
            rng: &mut self.rng,
        };
        let mut reply = None;
        match ip.protocol {
            PROTO_ICMP => {
                let Some((icmp, data)) = IcmpHeader::parse(payload) else { return };
                match icmp.ty {
                    ICMP_ECHO_REQUEST if to_us => {
                        let echo =
                            IcmpHeader { ty: ICMP_ECHO_REPLY, code: 0, ident: icmp.ident, seq: icmp.seq }.emit(data);
                        reply = Some(Packet {
                            src: ip.dst.into(),
                            dst: ip.src.into(),
                            protocol: PROTO_ICMP,
                            payload: echo,
                        });
                    }
                    ICMP_ECHO_REPLY if to_us => {
                        for (_, s) in sockets.iter_mut() {
                            if let Socket::Icmp(s) = s
                                && s.ident() == icmp.ident
                            {
                                s.process(EchoReply {
                                    from: ip.src.into(),
                                    seq: icmp.seq,
                                    data: data.to_vec(),
                                    at: now,
                                });
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
            PROTO_UDP => {
                let Some((udp, data)) = UdpHeader::parse(payload, ip.src, ip.dst) else { return };
                if ours.is_none() && !self.looping && udp.dst_port != dhcp::CLIENT_PORT {
                    return;
                }
                let dst = SocketAddr::new(ip.dst.into(), udp.dst_port);
                let src = SocketAddr::new(ip.src.into(), udp.src_port);
                let mut delivered = false;
                let targets = sockets.udp_targets(src, dst);
                // The DHCP client takes its replies when its handle comes before the UDP sockets'.
                let dhcp = if udp.dst_port == dhcp::CLIENT_PORT && udp.src_port == dhcp::SERVER_PORT {
                    sockets.iter().find(|(h, s)| matches!(s, Socket::Dhcp(_)) && targets.first().is_none_or(|t| h < t))
                } else {
                    None
                };
                if let Some((h, _)) = dhcp {
                    if let Some(s) = sockets.try_get_mut::<crate::DhcpClient>(h) {
                        s.process(&mut cx, data);
                    }
                    delivered = true;
                } else {
                    for h in targets {
                        if let Some(s) = sockets.try_get_mut::<crate::UdpSocket>(h) {
                            s.process(src, data);
                            delivered = true;
                        }
                    }
                }
                // No errors about frames that went to the whole link.
                if !delivered && to_us && !link_multicast {
                    // Port unreachable, quoting the IP header and the first
                    // eight bytes of the datagram (RFC 792).
                    // Not the frame's padding, which `bytes` may carry past
                    // the packet.
                    let header_len = usize::from(bytes.first().copied().unwrap_or(0) & 0xf) * 4;
                    let quoted = bytes.get(..header_len + payload.len().min(UDP_HEADER_LEN)).unwrap_or(&[]);
                    // The ident and seq fields are the message's four unused bytes.
                    let header =
                        IcmpHeader { ty: ICMP_DEST_UNREACHABLE, code: ICMP_PORT_UNREACHABLE, ident: 0, seq: 0 };
                    let icmp = header.emit(quoted);
                    reply =
                        Some(Packet { src: ip.dst.into(), dst: ip.src.into(), protocol: PROTO_ICMP, payload: icmp });
                }
            }
            PROTO_IGMP if to_group => {
                let Some(msg) = IgmpPacket::parse(payload) else { return };
                // Queries and reports are link-local (TTL 1, RFC 2236 / 3376).
                if ip.ttl != 1 {
                    return;
                }
                match msg.ty {
                    IGMP_QUERY if ip.dst == ALL_HOSTS && msg.group.is_unspecified() || ip.dst == msg.group => {
                        self.igmp.on_query(msg, now, cx.rng);
                    }
                    IGMP_REPORT_V1 | IGMP_REPORT_V2 if ip.dst == msg.group => self.igmp.on_report(msg.group),
                    _ => {}
                }
            }
            PROTO_TCP if to_us => {
                let Some((tcp, data)) = TcpHeader::parse(payload, ip.src, ip.dst) else { return };
                let dst = SocketAddr::new(ip.dst.into(), tcp.dst_port);
                let src = SocketAddr::new(ip.src.into(), tcp.src_port);
                let socket = {
                    let mut exact = None;
                    let mut queued = None;
                    for (h, s) in sockets.iter() {
                        if let Socket::Tcp(s) = s {
                            if s.accepts_exact(dst, src) {
                                exact = Some(h);
                                break;
                            }
                            if queued.is_none() && s.accepts_queued(dst) {
                                queued = Some(h);
                            }
                        }
                    }
                    exact.or_else(|| sockets.tcp_listener(src, dst)).or(queued)
                };
                let rst = match socket {
                    Some(h) => sockets.get_mut::<crate::TcpSocket>(h).process(&mut cx, dst, src, &tcp, data),
                    None => reset_for(&tcp, data.len()),
                };
                if let Some(rst) = rst {
                    reply = Some(Packet {
                        src: ip.dst.into(),
                        dst: ip.src.into(),
                        protocol: PROTO_TCP,
                        payload: rst.emit(ip.dst, ip.src, &[]),
                    });
                }
            }
            _ => {}
        }
        if let Some(p) = reply {
            self.send_ip(now, p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::igmp::{ALL_ROUTERS, IGMP_LEAVE};
    use crate::testing::sa;
    use crate::testing::{A_IP, B_IP, pair, run};
    use crate::{IcmpSocket, UdpSocket};

    #[test]
    fn config_math() {
        let c = Config { address: Ipv4Addr::new(10, 0, 2, 15), prefix_len: 24, gateway: None, dns: None };
        assert_eq!(c.netmask(), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(c.broadcast(), Ipv4Addr::new(10, 0, 2, 255));
        assert!(c.contains(Ipv4Addr::new(10, 0, 2, 2)) && !c.contains(Ipv4Addr::new(10, 0, 3, 2)));
        assert_eq!(Config { prefix_len: 0, ..c }.netmask(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(Config { prefix_len: 32, ..c }.netmask(), Ipv4Addr::BROADCAST);
    }

    #[test]
    fn ping_resolves_with_arp() {
        let (mut a, mut b) = pair();
        let h = a.sockets.add(IcmpSocket::new(0x1234, 4));
        a.sockets.get_mut::<IcmpSocket>(h).send_echo(B_IP, 7, b"hello").unwrap();
        let mut now = Instant::ZERO;
        let mut reply = None;
        assert!(run(&mut a, &mut b, &mut now, 100, |a, _| {
            reply = a.sockets.get_mut::<IcmpSocket>(h).recv();
            reply.is_some()
        }));
        let reply = reply.unwrap();
        assert_eq!((reply.from, reply.seq, &reply.data[..]), (IpAddr::from(B_IP), 7, &b"hello"[..]));
        assert_eq!(b.iface.arp.lookup(A_IP, now), Some(a.iface.mac_address()), "B learned A from its request");
    }

    #[test]
    fn udp_exchange_and_port_unreachable() {
        let (mut a, mut b) = pair();
        let ha = a.sockets.add(UdpSocket::new(4, 4));
        let hb = b.sockets.add(UdpSocket::new(4, 4));
        a.sockets.get_mut::<UdpSocket>(ha).bind(1000).unwrap();
        b.sockets.get_mut::<UdpSocket>(hb).bind(2000).unwrap();
        a.sockets.get_mut::<UdpSocket>(ha).send_to(b"ping", sa(B_IP, 2000)).unwrap();
        let mut now = Instant::ZERO;
        let mut buf = [0u8; 16];
        assert!(run(&mut a, &mut b, &mut now, 100, |_, b| b.sockets.get::<UdpSocket>(hb).can_recv()));
        let (n, from) = b.sockets.get_mut::<UdpSocket>(hb).recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from), (&b"ping"[..], sa(A_IP, 1000)));

        // Nothing on port 3000: B answers with an ICMP error, which A drops.
        a.sockets.get_mut::<UdpSocket>(ha).send_to(b"x", sa(B_IP, 3000)).unwrap();
        let mut errors = 0;
        b.set_filter(move |_, f| {
            if f.len() > 34 && f[23] == PROTO_ICMP && f[34] == ICMP_DEST_UNREACHABLE {
                errors += 1;
                assert_eq!(errors, 1);
            }
            true
        });
        run(&mut a, &mut b, &mut now, 20, |_, _| false);
        assert!(!a.sockets.get::<UdpSocket>(ha).can_recv());
    }

    /// Records every frame `host` sends.
    fn record(host: &mut crate::testing::Host) -> std::rc::Rc<std::cell::RefCell<Vec<Vec<u8>>>> {
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let log = seen.clone();
        host.set_filter(move |_, f| {
            log.borrow_mut().push(f.to_vec());
            true
        });
        seen
    }

    #[test]
    fn unresolved_packets_are_dropped() {
        let (mut a, mut b) = pair();
        b.set_filter(|_, _| false); // B never answers
        let sent = record(&mut a);
        let h = a.sockets.add(IcmpSocket::new(1, 4));
        a.sockets.get_mut::<IcmpSocket>(h).send_echo(B_IP, 0, b"").unwrap();
        let mut now = Instant::ZERO;
        run(&mut a, &mut b, &mut now, 5000, |_, _| false);
        let sent = sent.borrow();
        assert_eq!(sent.len(), 3, "one ARP request a second until it gives up");
        assert!(sent.iter().all(|f| f.len() == ETH_HEADER_LEN + ARP_LEN));
        assert!(a.iface.pending.is_empty() && a.iface.requests.is_empty());
        assert_eq!(a.iface.poll_at(&a.sockets), None, "nothing left to do");
    }

    #[test]
    fn off_link_goes_to_the_gateway() {
        let (mut a, mut b) = pair();
        a.iface.set_config(Some(Config { gateway: Some(B_IP), ..a.iface.config().unwrap() }));
        let sent = record(&mut a);
        let far = Ipv4Addr::new(8, 8, 8, 8);
        let h = a.sockets.add(IcmpSocket::new(1, 4));
        a.sockets.get_mut::<IcmpSocket>(h).send_echo(far, 0, b"").unwrap();
        let mut now = Instant::ZERO;
        run(&mut a, &mut b, &mut now, 50, |_, _| false);
        let sent = sent.borrow();
        let (eth, arp) = EthernetHeader::parse(&sent[0]).unwrap();
        assert_eq!(eth.ethertype, ETHERTYPE_ARP);
        assert_eq!(ArpPacket::parse(arp).unwrap().target_ip, B_IP, "ARP for the gateway, not the destination");
        let (eth, ip) = EthernetHeader::parse(&sent[1]).unwrap();
        assert_eq!((eth.dst, Ipv4Header::parse(ip).unwrap().0.dst), (b.iface.mac_address(), far));
    }

    /// A UDP datagram from `src` to `dst`:`port`, in a frame to `mac`.
    fn udp_frame(mac: MacAddress, src: Ipv4Addr, dst: Ipv4Addr, port: u16) -> Vec<u8> {
        let udp = UdpHeader { src_port: 9, dst_port: port }.emit(src, dst, b"x");
        let mut f = vec![0; ETH_HEADER_LEN + IPV4_HEADER_LEN + udp.len()];
        EthernetHeader { dst: mac, src: MacAddress([2, 0, 0, 0, 0, 9]), ethertype: ETHERTYPE_IPV4 }.emit(&mut f);
        Ipv4Header { src, dst, protocol: PROTO_UDP, ttl: 64, ident: 0, payload_len: udp.len() }
            .emit(&mut f[ETH_HEADER_LEN..]);
        f[ETH_HEADER_LEN + IPV4_HEADER_LEN..].copy_from_slice(&udp);
        f
    }

    #[test]
    fn forged_sources_are_dropped() {
        let (a, mut b) = pair();
        let sent = record(&mut b);
        let hb = b.sockets.add(UdpSocket::new(8, 8));
        b.sockets.get_mut::<UdpSocket>(hb).bind(2000).unwrap();
        let mac = b.iface.mac_address();
        let forged = [B_IP, Ipv4Addr::new(192, 168, 1, 255), Ipv4Addr::BROADCAST, Ipv4Addr::UNSPECIFIED];
        for src in forged.into_iter().chain([Ipv4Addr::new(224, 0, 0, 1), Ipv4Addr::LOCALHOST]) {
            a.dev.tx.borrow_mut().push_back(udp_frame(mac, src, B_IP, 2000));
        }
        // Nothing listens on 3000, but the frame went to the whole link.
        a.dev.tx.borrow_mut().push_back(udp_frame(MacAddress::BROADCAST, A_IP, B_IP, 3000));
        b.poll(Instant::ZERO);
        assert!(!b.sockets.get::<UdpSocket>(hb).can_recv());
        assert!(sent.borrow().is_empty(), "no ICMP errors");
        a.dev.tx.borrow_mut().push_back(udp_frame(mac, A_IP, B_IP, 2000));
        b.poll(Instant::ZERO);
        assert!(b.sockets.get::<UdpSocket>(hb).can_recv());
    }

    #[test]
    fn icmp_unreachable_quotes_the_header_and_eight_bytes_only() {
        let (mut a, mut b) = pair();
        let sent = record(&mut b);
        let mut frame = udp_frame(b.iface.mac_address(), A_IP, B_IP, 3000);
        frame.extend_from_slice(&[0xee; 20]); // link-layer padding
        a.dev.tx.borrow_mut().push_back(frame);
        let mut now = Instant::ZERO;
        run(&mut a, &mut b, &mut now, 50, |_, _| false);
        let sent = sent.borrow();
        let errors: Vec<_> =
            sent.iter().filter(|f| f.len() > 34 && f[12..14] == [8, 0] && f[34] == ICMP_DEST_UNREACHABLE).collect();
        assert_eq!(errors.len(), 1);
        let ip = &errors[0][ETH_HEADER_LEN..];
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]]));
        assert_eq!(total, IPV4_HEADER_LEN + 8 + IPV4_HEADER_LEN + UDP_HEADER_LEN, "no padding in the quote");
    }

    #[test]
    fn unconfigured_takes_only_dhcp() {
        let (a, mut b) = crate::testing::link();
        let hb = b.sockets.add(UdpSocket::new(8, 8));
        b.sockets.get_mut::<UdpSocket>(hb).bind(2000).unwrap();
        a.dev.tx.borrow_mut().push_back(udp_frame(b.iface.mac_address(), A_IP, B_IP, 2000));
        b.poll(Instant::ZERO);
        assert!(!b.sockets.get::<UdpSocket>(hb).can_recv());
    }

    #[test]
    fn arp_cannot_claim_our_own_or_far_addresses() {
        let (a, mut b) = pair();
        let sent = record(&mut b);
        for ip in [B_IP, Ipv4Addr::new(192, 168, 1, 255), Ipv4Addr::new(10, 0, 0, 1)] {
            let arp = ArpPacket {
                op: ARP_REQUEST,
                sender_mac: MacAddress([2, 0, 0, 0, 0, 9]),
                sender_ip: ip,
                target_mac: MacAddress::default(),
                target_ip: B_IP,
            };
            let mut f = vec![0; ETH_HEADER_LEN + ARP_LEN];
            EthernetHeader { dst: MacAddress::BROADCAST, src: arp.sender_mac, ethertype: ETHERTYPE_ARP }.emit(&mut f);
            arp.emit(&mut f[ETH_HEADER_LEN..]);
            a.dev.tx.borrow_mut().push_back(f);
            b.poll(Instant::ZERO);
            assert!(!b.iface.arp.contains(ip), "{ip}");
        }
        assert!(sent.borrow().is_empty(), "no replies");
    }

    fn udp_pair(
        a: &mut crate::testing::Host,
        b: &mut crate::testing::Host,
    ) -> (crate::SocketHandle, crate::SocketHandle) {
        let ha = a.sockets.add(UdpSocket::new(4, 4));
        let hb = b.sockets.add(UdpSocket::new(4, 4));
        a.sockets.get_mut::<UdpSocket>(ha).bind(1000).unwrap();
        b.sockets.get_mut::<UdpSocket>(hb).bind(2000).unwrap();
        (ha, hb)
    }

    fn big(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 13 + i / 7) as u8).collect()
    }

    #[test]
    fn fragments_are_sent_and_reassembled_despite_reordering_and_duplication() {
        use crate::testing::Fate;
        let (mut a, mut b) = pair();
        let (ha, hb) = udp_pair(&mut a, &mut b);
        // Some fragments arrive late and some twice.
        a.set_shaper(|n, f| match (f.len() > 100, n % 3) {
            (false, _) => Fate::Deliver,
            (true, 0) => Fate::Duplicate,
            (true, 1) if n < 6 => Fate::Delay(2),
            _ => Fate::Deliver,
        });
        let data = big(8000);
        a.sockets.get_mut::<UdpSocket>(ha).send_to(&data, sa(B_IP, 2000)).unwrap();
        let mut now = Instant::ZERO;
        assert!(run(&mut a, &mut b, &mut now, 200, |_, b| b.sockets.get::<UdpSocket>(hb).can_recv()));
        let mut buf = vec![0u8; 9000];
        let (n, from) = b.sockets.get_mut::<UdpSocket>(hb).recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from), (&data[..], sa(A_IP, 1000)));
        run(&mut a, &mut b, &mut now, 100, |_, _| false);
        assert!(!b.sockets.get::<UdpSocket>(hb).can_recv(), "delivered once");
        assert!(b.iface.reassembling.is_empty());
    }

    #[test]
    fn fragments_are_sent_to_the_mtu() {
        let (mut a, mut b) = pair();
        let (ha, _) = udp_pair(&mut a, &mut b);
        let sent = record(&mut a);
        a.sockets.get_mut::<UdpSocket>(ha).send_to(&big(4000), sa(B_IP, 2000)).unwrap();
        let mut now = Instant::ZERO;
        run(&mut a, &mut b, &mut now, 50, |_, _| false);
        let sent = sent.borrow();
        let frags: Vec<_> = sent
            .iter()
            .filter_map(|f| Ipv4Header::parse_fragment(EthernetHeader::parse(f)?.1))
            .filter(|(h, _, _)| h.protocol == PROTO_UDP)
            .collect();
        assert_eq!(frags.len(), 3);
        assert!(frags.iter().all(|(h, ..)| h.ident == frags[0].0.ident));
        let offsets: Vec<_> = frags.iter().map(|(_, f, p)| (f.offset, f.more, p.len())).collect();
        assert_eq!(offsets, [(0, true, 1480), (1480, true, 1480), (2960, false, 1048)]);
    }

    #[test]
    fn a_lost_fragment_loses_the_datagram_and_its_buffers_expire() {
        let (mut a, mut b) = pair();
        let (ha, hb) = udp_pair(&mut a, &mut b);
        let mut count = 0;
        a.set_filter(move |_, f| {
            if f.len() > 100 {
                count += 1;
                return count != 2;
            }
            true
        });
        a.sockets.get_mut::<UdpSocket>(ha).send_to(&big(4000), sa(B_IP, 2000)).unwrap();
        let mut now = Instant::ZERO;
        run(&mut a, &mut b, &mut now, 1000, |_, _| false);
        assert!(!b.sockets.get::<UdpSocket>(hb).can_recv());
        assert_eq!(b.iface.reassembling.len(), 1);
        run(&mut a, &mut b, &mut now, 15_000, |_, _| false);
        assert!(b.iface.reassembling.is_empty(), "gave up after the timeout");
    }

    /// A fragment of datagram `ident` from A to B.
    fn fragment(ident: u16, offset: usize, more: bool, data: &[u8]) -> Vec<u8> {
        let mut f = vec![0; ETH_HEADER_LEN + IPV4_HEADER_LEN + data.len()];
        EthernetHeader {
            dst: MacAddress([2, 0, 0, 0, 0, 2]),
            src: MacAddress([2, 0, 0, 0, 0, 9]),
            ethertype: ETHERTYPE_IPV4,
        }
        .emit(&mut f);
        let h = Ipv4Header { src: A_IP, dst: B_IP, protocol: PROTO_UDP, ttl: 64, ident, payload_len: data.len() };
        h.emit_fragment(&mut f[ETH_HEADER_LEN..], Fragment { more, offset });
        f[ETH_HEADER_LEN + IPV4_HEADER_LEN..].copy_from_slice(data);
        f
    }

    #[test]
    fn overlapping_and_malformed_fragments_are_dropped() {
        let (a, mut b) = pair();
        let hb = b.sockets.add(UdpSocket::new(4, 4));
        b.sockets.get_mut::<UdpSocket>(hb).bind(2000).unwrap();
        let udp = UdpHeader { src_port: 9, dst_port: 2000 }.emit(A_IP, B_IP, &big(40));
        let push = |f: Vec<u8>| a.dev.tx.borrow_mut().push_back(f);
        // The first 24 bytes, then a fragment that overlaps them.
        push(fragment(1, 0, true, &udp[..24]));
        push(fragment(1, 16, false, &udp[16..]));
        b.poll(Instant::ZERO);
        assert!(!b.sockets.get::<UdpSocket>(hb).can_recv() && b.iface.reassembling.is_empty(), "overlap condemns it");
        // A middle fragment that is not a multiple of 8 bytes.
        push(fragment(2, 0, true, &udp[..13]));
        // A fragment past the end of a datagram's last.
        push(fragment(3, 24, false, &udp[24..]));
        push(fragment(3, 48, true, &udp[..8]));
        // Tiling exactly works.
        push(fragment(4, 0, true, &udp[..24]));
        push(fragment(4, 24, false, &udp[24..]));
        b.poll(Instant::ZERO);
        assert!(b.sockets.get::<UdpSocket>(hb).can_recv());
        assert!(b.iface.reassembling.len() <= 1);
    }

    #[test]
    fn partial_datagrams_are_bounded() {
        let (a, mut b) = pair();
        for ident in 0..100 {
            a.dev.tx.borrow_mut().push_back(fragment(ident, 0, true, &[0; 64]));
        }
        b.poll(Instant::ZERO);
        assert_eq!(b.iface.reassembling.len(), REASSEMBLIES);
    }

    #[test]
    fn large_ping_is_fragmented_both_ways() {
        let (mut a, mut b) = pair();
        let h = a.sockets.add(IcmpSocket::new(0x77, 4));
        a.sockets.get_mut::<IcmpSocket>(h).send_echo(B_IP, 1, &big(5000)).unwrap();
        let mut now = Instant::ZERO;
        let mut reply = None;
        assert!(run(&mut a, &mut b, &mut now, 100, |a, _| {
            reply = a.sockets.get_mut::<IcmpSocket>(h).recv();
            reply.is_some()
        }));
        assert_eq!(reply.unwrap().data, big(5000));
    }

    /// Claims more than it could have copied, and a huge frame size.
    struct Liar;

    impl NetDevice for Liar {
        fn mac_address(&self) -> MacAddress {
            MacAddress([2, 0, 0, 0, 0, 7])
        }

        fn max_frame_len(&self) -> usize {
            usize::MAX
        }

        fn transmit(&mut self, _: &[u8]) -> Result<(), NetError> {
            Ok(())
        }

        fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
            Ok(buf.len() + 1)
        }

        fn can_receive(&self) -> bool {
            true
        }

        fn can_transmit(&self) -> bool {
            true
        }
    }

    #[test]
    fn device_lengths_are_not_trusted() {
        let mut iface = Interface::new(&Liar, 1);
        assert_eq!(iface.rx_buf.len(), MAX_FRAME);
        iface.poll(Instant::ZERO, &mut Liar, &mut SocketSet::new());
        assert_eq!(iface.mss(), 1460);
    }

    const GROUP: Ipv4Addr = Ipv4Addr::new(239, 1, 2, 3);

    /// An IGMP message from A to `dst`, in a frame to `dst`'s multicast MAC.
    fn igmp_frame(dst: Ipv4Addr, ttl: u8, msg: IgmpPacket) -> Vec<u8> {
        let payload = msg.emit();
        let mut f = vec![0; ETH_HEADER_LEN + ipopt::HEADER_LEN_ROUTER_ALERT + payload.len()];
        EthernetHeader { dst: multicast_mac(dst), src: MacAddress([2, 0, 0, 0, 0, 1]), ethertype: ETHERTYPE_IPV4 }
            .emit(&mut f);
        let h = Ipv4Header { src: A_IP, dst, protocol: PROTO_IGMP, ttl, ident: 0, payload_len: payload.len() };
        ipopt::emit_with_router_alert(&h, &mut f[ETH_HEADER_LEN..]);
        f[ETH_HEADER_LEN + ipopt::HEADER_LEN_ROUTER_ALERT..].copy_from_slice(&payload);
        f
    }

    /// The IGMP messages in the frames `sent`, with their IP headers and
    /// destination MACs.
    fn igmp_sent(sent: &[Vec<u8>]) -> Vec<(MacAddress, Ipv4Header, IgmpPacket)> {
        sent.iter()
            .filter_map(|f| {
                let (eth, ip) = EthernetHeader::parse(f)?;
                let (h, payload) = Ipv4Header::parse(ip)?;
                if h.protocol != PROTO_IGMP {
                    return None;
                }
                assert!(ipopt::of_packet(ip)?.router_alert, "IGMP carries router alert");
                Some((eth.dst, h, IgmpPacket::parse(payload).unwrap()))
            })
            .collect()
    }

    #[test]
    fn multicast_udp_reaches_members_only() {
        let (mut a, mut b) = pair();
        let sent = record(&mut a);
        let hb = b.sockets.add(UdpSocket::new(8, 8));
        b.sockets.get_mut::<UdpSocket>(hb).bind(5000).unwrap();
        let ha = a.sockets.add(UdpSocket::new(8, 8));
        a.sockets.get_mut::<UdpSocket>(ha).bind(6000).unwrap();
        let mut now = Instant::ZERO;
        let dst = sa(GROUP, 5000);

        a.sockets.get_mut::<UdpSocket>(ha).send_to(b"before", dst).unwrap();
        run(&mut a, &mut b, &mut now, 20, |_, _| false);
        assert!(!b.sockets.get::<UdpSocket>(hb).can_recv(), "B has not joined");

        assert!(!b.iface.is_multicast_member(GROUP));
        b.iface.join_multicast_group(now, GROUP).unwrap();
        assert!(b.iface.is_multicast_member(GROUP) && b.iface.multicast_groups().eq([GROUP]));
        a.sockets.get_mut::<UdpSocket>(ha).send_to(b"after", dst).unwrap();
        run(&mut a, &mut b, &mut now, 20, |_, _| false);
        let mut buf = [0u8; 16];
        let (n, from) = b.sockets.get_mut::<UdpSocket>(hb).recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from), (&b"after"[..], sa(A_IP, 6000)));
        assert!(!b.sockets.get::<UdpSocket>(hb).can_recv());

        // It went to the group's MAC with TTL 1, and needed no ARP.
        {
            let sent = sent.borrow();
            assert!(sent.iter().all(|f| EthernetHeader::parse(f).unwrap().0.ethertype == ETHERTYPE_IPV4));
            let (eth, ip) = EthernetHeader::parse(&sent[0]).unwrap();
            assert_eq!((eth.dst, Ipv4Header::parse(ip).unwrap().0.ttl), (multicast_mac(GROUP), 1));
        }

        b.iface.leave_multicast_group(now, GROUP).unwrap();
        a.sockets.get_mut::<UdpSocket>(ha).send_to(b"gone", dst).unwrap();
        run(&mut a, &mut b, &mut now, 20, |_, _| false);
        assert!(!b.sockets.get::<UdpSocket>(hb).can_recv());
    }

    #[test]
    fn joins_report_queries_are_answered_and_leaves_announced() {
        let (mut a, mut b) = pair();
        let sent = record(&mut b);
        let mut now = Instant::ZERO;
        assert_eq!(b.iface.join_multicast_group(now, A_IP), Err(crate::Error::InvalidAddress));
        assert_eq!(b.iface.leave_multicast_group(now, GROUP), Err(crate::Error::InvalidState));
        b.iface.join_multicast_group(now, GROUP).unwrap();
        assert_eq!(b.iface.poll_at(&b.sockets), Some(now));
        run(&mut a, &mut b, &mut now, 1, |_, _| false);
        {
            let msgs = igmp_sent(&sent.borrow());
            let (mac, ip, msg) = &msgs[0];
            assert_eq!((*mac, ip.dst, ip.ttl, ip.src), (multicast_mac(GROUP), GROUP, 1, B_IP));
            assert_eq!((msg.ty, msg.group), (IGMP_REPORT_V2, GROUP));
        }
        // The second unsolicited report.
        run(&mut a, &mut b, &mut now, 10_000, |_, _| false);
        assert_eq!(igmp_sent(&sent.borrow()).len(), 2);

        // A general query with a one second response time.
        let query = IgmpPacket { ty: IGMP_QUERY, max_response: 10, group: Ipv4Addr::UNSPECIFIED };
        sent.borrow_mut().clear();
        a.dev.tx.borrow_mut().push_back(igmp_frame(ALL_HOSTS, 64, query));
        run(&mut a, &mut b, &mut now, 1100, |_, _| false);
        assert!(igmp_sent(&sent.borrow()).is_empty(), "a query with a bad TTL is ignored");
        a.dev.tx.borrow_mut().push_back(igmp_frame(ALL_HOSTS, 1, query));
        assert!(run(&mut a, &mut b, &mut now, 1100, |_, _| !igmp_sent(&sent.borrow()).is_empty()));
        assert_eq!(igmp_sent(&sent.borrow())[0].2.group, GROUP);

        // Another member's report cancels ours.
        sent.borrow_mut().clear();
        a.dev.tx.borrow_mut().push_back(igmp_frame(ALL_HOSTS, 1, query));
        run(&mut a, &mut b, &mut now, 1, |_, _| false);
        let report = IgmpPacket { ty: IGMP_REPORT_V2, max_response: 0, group: GROUP };
        a.dev.tx.borrow_mut().push_back(igmp_frame(GROUP, 1, report));
        run(&mut a, &mut b, &mut now, 1500, |_, _| false);
        assert!(igmp_sent(&sent.borrow()).is_empty(), "suppressed by another member's report");

        // We were not the last to report, so leaving is silent; join again
        // and leave: now it is announced.
        b.iface.leave_multicast_group(now, GROUP).unwrap();
        b.iface.join_multicast_group(now, GROUP).unwrap();
        run(&mut a, &mut b, &mut now, 1, |_, _| false);
        sent.borrow_mut().clear();
        b.iface.leave_multicast_group(now, GROUP).unwrap();
        run(&mut a, &mut b, &mut now, 1, |_, _| false);
        let msgs = igmp_sent(&sent.borrow());
        assert_eq!(msgs.len(), 1);
        let (mac, ip, msg) = &msgs[0];
        assert_eq!((*mac, ip.dst, msg.ty, msg.group), (multicast_mac(ALL_ROUTERS), ALL_ROUTERS, IGMP_LEAVE, GROUP));
    }

    /// A UDP datagram from A to B carrying the IP `options` (a multiple of
    /// four bytes).
    fn udp_with_options(options: &[u8]) -> Vec<u8> {
        let udp = UdpHeader { src_port: 9, dst_port: 2000 }.emit(A_IP, B_IP, b"x");
        let hlen = IPV4_HEADER_LEN + options.len();
        let mut f = vec![0; ETH_HEADER_LEN + hlen + udp.len()];
        let src = MacAddress([2, 0, 0, 0, 0, 1]);
        EthernetHeader { dst: MacAddress([2, 0, 0, 0, 0, 2]), src, ethertype: ETHERTYPE_IPV4 }.emit(&mut f);
        let ip = &mut f[ETH_HEADER_LEN..];
        Ipv4Header { src: A_IP, dst: B_IP, protocol: PROTO_UDP, ttl: 64, ident: 0, payload_len: udp.len() }.emit(ip);
        ip[0] = 0x40 | (hlen / 4) as u8;
        ip[2..4].copy_from_slice(&((hlen + udp.len()) as u16).to_be_bytes());
        ip[20..hlen].copy_from_slice(options);
        ip[hlen..].copy_from_slice(&udp);
        ip[10..12].fill(0);
        let sum = checksum::of(&ip[..hlen]);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        f
    }

    #[test]
    fn ip_options_are_skipped_or_rejected() {
        let (a, mut b) = pair();
        let hb = b.sockets.add(UdpSocket::new(8, 8));
        b.sockets.get_mut::<UdpSocket>(hb).bind(2000).unwrap();
        let sent = record(&mut b);
        let good: [&[u8]; 3] = [&[1, 1, 1, 0], &[148, 4, 0, 0], &[0x88, 4, 1, 2]];
        let bad: [&[u8]; 5] = [
            &[0x88, 9, 0, 0],            // runs past the header
            &[0x88, 1, 0, 0],            // length below 2
            &[131, 7, 4, 1, 2, 3, 4, 0], // loose source route
            &[137, 7, 4, 1, 2, 3, 4, 0], // strict source route
            &[148, 3, 0, 1],             // bad router alert
        ];
        for opts in bad {
            a.dev.tx.borrow_mut().push_back(udp_with_options(opts));
            b.poll(Instant::ZERO);
            assert!(!b.sockets.get::<UdpSocket>(hb).can_recv(), "{opts:?}");
        }
        for opts in good {
            a.dev.tx.borrow_mut().push_back(udp_with_options(opts));
            b.poll(Instant::ZERO);
            assert!(b.sockets.get_mut::<UdpSocket>(hb).recv_from(&mut [0; 4]).is_ok(), "{opts:?}");
        }
        assert!(sent.borrow().is_empty(), "no ICMP for dropped packets");
    }

    #[test]
    fn a_stream_of_tiny_fragments_is_condemned() {
        let (a, mut b) = pair();
        for n in 0..MAX_PIECES + 1 {
            a.dev.tx.borrow_mut().push_back(fragment(1, n * 8, true, &[0; 8]));
        }
        for _ in 0..(MAX_PIECES + 1).div_ceil(RX_BURST) {
            b.poll(Instant::ZERO);
        }
        assert!(b.iface.reassembling.is_empty());
    }
}
