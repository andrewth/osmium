//! An Ethernet interface: ARP, IPv4 routing to the next hop, ICMP echo, and
//! the glue between a device and the sockets.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{Ipv4Addr, SocketAddrV4};
use core::time::Duration;

use osmium_hal::net::{MacAddress, NetDevice, NetError};

use crate::Instant;
use crate::arp::ArpCache;
use crate::rng::Rng;
use crate::socket::icmp::EchoReply;
use crate::socket::tcp::reset_for;
use crate::socket::{Cx, Packet, Socket, SocketSet, dhcp};
use crate::wire::*;

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
}

impl Interface {
    /// An unconfigured interface for `dev`, which it takes the MAC address
    /// and MTU from. `seed` seeds TCP initial sequence numbers, DHCP
    /// transaction ids and ephemeral ports; use a hardware random number or
    /// at least a clock reading.
    pub fn new<D: NetDevice + ?Sized>(dev: &D, seed: u64) -> Self {
        let frame = dev.max_frame_len();
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
        }
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

    /// A random port in the dynamic range, for binding a client socket.
    pub fn ephemeral_port(&mut self) -> u16 {
        self.rng.ephemeral_port()
    }

    fn mss(&self) -> u16 {
        (self.mtu - IPV4_HEADER_LEN - TCP_HEADER_LEN) as u16
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
                    self.process_frame(now, &buf[..n], sockets);
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

        let mut out = Vec::new();
        for (_, s) in sockets.iter_mut() {
            if self.tx.len() >= TX_QUEUE / 2 {
                break;
            }
            let mut cx =
                Cx { now, addr: self.config.map(|c| c.address), mac: self.mac, mss: self.mss(), rng: &mut self.rng };
            s.dispatch(&mut cx, &mut out);
            for p in out.drain(..) {
                self.send_ip(now, p);
            }
        }

        self.retry_arp(now);
        active | self.flush(dev)
    }

    /// When the interface next needs polling if nothing arrives: a time at
    /// or before now means at once. `None` means only when a frame arrives.
    pub fn poll_at(&self, sockets: &SocketSet) -> Option<Instant> {
        if !self.tx.is_empty() {
            return Some(Instant::ZERO);
        }
        let arp = self.requests.iter().map(|r| r.last + ARP_RETRY).min();
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

    fn ip_frame(&mut self, dst_mac: MacAddress, p: &Packet) -> Vec<u8> {
        let mut frame = self.ethernet_frame(dst_mac, ETHERTYPE_IPV4, IPV4_HEADER_LEN + p.payload.len());
        self.ident = self.ident.wrapping_add(1);
        let header = Ipv4Header {
            src: p.src,
            dst: p.dst,
            protocol: p.protocol,
            ttl: TTL,
            ident: self.ident,
            payload_len: p.payload.len(),
        };
        header.emit(&mut frame[ETH_HEADER_LEN..]);
        frame[ETH_HEADER_LEN + IPV4_HEADER_LEN..].copy_from_slice(&p.payload);
        frame
    }

    /// Routes `p` to its next hop, resolving the hop's MAC address first if
    /// it is not cached.
    fn send_ip(&mut self, now: Instant, p: Packet) {
        if IPV4_HEADER_LEN + p.payload.len() > self.mtu {
            return;
        }
        let next_hop = match self.config {
            _ if p.dst.is_broadcast() => None,
            Some(c) if p.dst == c.broadcast() => None,
            Some(c) if c.contains(p.dst) => Some(p.dst),
            Some(Config { gateway: Some(gw), .. }) => Some(gw),
            _ => return,
        };
        let Some(hop) = next_hop else {
            let frame = self.ip_frame(MacAddress::BROADCAST, &p);
            return self.queue_frame(frame);
        };
        if let Some(mac) = self.arp.lookup(hop, now) {
            let frame = self.ip_frame(mac, &p);
            return self.queue_frame(frame);
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
        request.emit(&mut frame[ETH_HEADER_LEN..]);
        self.queue_frame(frame);
    }

    fn retry_arp(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.requests.len() {
            let r = &mut self.requests[i];
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
            if self.pending[i].next_hop == ip {
                let p = self.pending.remove(i).unwrap();
                let frame = self.ip_frame(mac, &p.packet);
                self.queue_frame(frame);
            } else {
                i += 1;
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
            ETHERTYPE_IPV4 => self.process_ipv4(now, payload, sockets),
            _ => {}
        }
    }

    fn process_arp(&mut self, now: Instant, payload: &[u8]) {
        let Some(arp) = ArpPacket::parse(payload) else { return };
        let Some(c) = self.config else { return };
        if arp.sender_ip.is_unspecified() || arp.sender_mac.is_multicast() {
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
            reply.emit(&mut frame[ETH_HEADER_LEN..]);
            self.queue_frame(frame);
        }
    }

    fn process_ipv4(&mut self, now: Instant, bytes: &[u8], sockets: &mut SocketSet) {
        let Some((ip, payload)) = Ipv4Header::parse(bytes) else { return };
        let ours = self.config.map(|c| c.address);
        let to_us = Some(ip.dst) == ours;
        let broadcast = ip.dst.is_broadcast() || self.config.is_some_and(|c| ip.dst == c.broadcast());
        // Before it has an address the interface takes UDP to anyone, which
        // is how a DHCP server's unicast OFFER arrives.
        let unconfigured_udp = ours.is_none() && ip.protocol == PROTO_UDP;
        if !(to_us || broadcast || unconfigured_udp) {
            return;
        }
        let mut cx = Cx { now, addr: ours, mac: self.mac, mss: self.mss(), rng: &mut self.rng };
        let mut reply = None;
        match ip.protocol {
            PROTO_ICMP => {
                let Some((icmp, data)) = IcmpHeader::parse(payload) else { return };
                match icmp.ty {
                    ICMP_ECHO_REQUEST if to_us => {
                        let echo =
                            IcmpHeader { ty: ICMP_ECHO_REPLY, code: 0, ident: icmp.ident, seq: icmp.seq }.emit(data);
                        reply = Some(Packet { src: ip.dst, dst: ip.src, protocol: PROTO_ICMP, payload: echo });
                    }
                    ICMP_ECHO_REPLY if to_us => {
                        for (_, s) in sockets.iter_mut() {
                            if let Socket::Icmp(s) = s
                                && s.ident() == icmp.ident
                            {
                                s.process(EchoReply { from: ip.src, seq: icmp.seq, data: data.to_vec(), at: now });
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
            PROTO_UDP => {
                let Some((udp, data)) = UdpHeader::parse(payload, ip.src, ip.dst) else { return };
                let dst = SocketAddrV4::new(ip.dst, udp.dst_port);
                let src = SocketAddrV4::new(ip.src, udp.src_port);
                let mut delivered = false;
                for (_, s) in sockets.iter_mut() {
                    match s {
                        Socket::Udp(s) if s.accepts(dst) => {
                            s.process(src, data);
                            delivered = true;
                            break;
                        }
                        Socket::Dhcp(s) if udp.dst_port == dhcp::CLIENT_PORT && udp.src_port == dhcp::SERVER_PORT => {
                            s.process(&mut cx, data);
                            delivered = true;
                            break;
                        }
                        _ => {}
                    }
                }
                if !delivered && to_us {
                    // Port unreachable, quoting the IP header and the first
                    // eight bytes of the datagram (RFC 792).
                    let quoted = &bytes[..(bytes.len() - payload.len() + UDP_HEADER_LEN).min(bytes.len())];
                    // The ident and seq fields are the message's four unused bytes.
                    let header =
                        IcmpHeader { ty: ICMP_DEST_UNREACHABLE, code: ICMP_PORT_UNREACHABLE, ident: 0, seq: 0 };
                    let icmp = header.emit(quoted);
                    reply = Some(Packet { src: ip.dst, dst: ip.src, protocol: PROTO_ICMP, payload: icmp });
                }
            }
            PROTO_TCP if to_us => {
                let Some((tcp, data)) = TcpHeader::parse(payload, ip.src, ip.dst) else { return };
                let dst = SocketAddrV4::new(ip.dst, tcp.dst_port);
                let src = SocketAddrV4::new(ip.src, tcp.src_port);
                let socket = {
                    let mut exact = None;
                    let mut listen = None;
                    for (h, s) in sockets.iter() {
                        if let Socket::Tcp(s) = s {
                            if s.accepts_exact(dst, src) {
                                exact = Some(h);
                                break;
                            }
                            if listen.is_none() && s.accepts_listen(dst) {
                                listen = Some(h);
                            }
                        }
                    }
                    exact.or(listen)
                };
                let rst = match socket {
                    Some(h) => sockets.get_mut::<crate::TcpSocket>(h).process(&mut cx, dst, src, &tcp, data),
                    None => reset_for(&tcp, data.len()),
                };
                if let Some(rst) = rst {
                    reply = Some(Packet {
                        src: ip.dst,
                        dst: ip.src,
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
        assert_eq!((reply.from, reply.seq, &reply.data[..]), (B_IP, 7, &b"hello"[..]));
        assert_eq!(b.iface.arp.lookup(A_IP, now), Some(a.iface.mac_address()), "B learned A from its request");
    }

    #[test]
    fn udp_exchange_and_port_unreachable() {
        let (mut a, mut b) = pair();
        let ha = a.sockets.add(UdpSocket::new(4, 4));
        let hb = b.sockets.add(UdpSocket::new(4, 4));
        a.sockets.get_mut::<UdpSocket>(ha).bind(1000).unwrap();
        b.sockets.get_mut::<UdpSocket>(hb).bind(2000).unwrap();
        a.sockets.get_mut::<UdpSocket>(ha).send_to(b"ping", SocketAddrV4::new(B_IP, 2000)).unwrap();
        let mut now = Instant::ZERO;
        let mut buf = [0u8; 16];
        assert!(run(&mut a, &mut b, &mut now, 100, |_, b| b.sockets.get::<UdpSocket>(hb).can_recv()));
        let (n, from) = b.sockets.get_mut::<UdpSocket>(hb).recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from), (&b"ping"[..], SocketAddrV4::new(A_IP, 1000)));

        // Nothing on port 3000: B answers with an ICMP error, which A drops.
        a.sockets.get_mut::<UdpSocket>(ha).send_to(b"x", SocketAddrV4::new(B_IP, 3000)).unwrap();
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
}
