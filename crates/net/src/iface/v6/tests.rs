use std::cell::RefCell;
use std::rc::Rc;
use std::vec;

use super::*;
use crate::testing::{A_IP, B_IP, Host, config, link, pair6, run};
use crate::{IcmpSocket, TcpSocket, TcpState, UdpSocket};

const ROUTER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x99]);
const ROUTER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);
const PREFIX: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 0);

fn ll(h: &Host) -> Ipv6Addr {
    h.iface.ipv6_link_local().unwrap()
}

fn any6(port: u16) -> SocketAddr {
    SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)
}

/// An Ethernet frame carrying an IPv6 packet.
fn frame(dst_mac: MacAddress, src: Ipv6Addr, dst: Ipv6Addr, next: u8, hop_limit: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0; ETH_HEADER_LEN + IPV6_HEADER_LEN + payload.len()];
    EthernetHeader { dst: dst_mac, src: ROUTER_MAC, ethertype: ETHERTYPE_IPV6 }.emit(&mut f);
    let h = Ipv6Header { src, dst, next_header: next, hop_limit, payload_len: payload.len(), fragment: None };
    h.emit(&mut f[ETH_HEADER_LEN..]);
    f[ETH_HEADER_LEN + IPV6_HEADER_LEN..].copy_from_slice(payload);
    f
}

fn icmp_frame(dst_mac: MacAddress, src: Ipv6Addr, dst: Ipv6Addr, hop: u8, ty: u8, body: &[u8]) -> Vec<u8> {
    frame(dst_mac, src, dst, PROTO_ICMPV6, hop, &Icmpv6Header { ty, code: 0 }.emit(src, dst, body))
}

fn advert(prefix_len: u8, autonomous: bool, valid: u32) -> RouterAdvert {
    RouterAdvert {
        hop_limit: 64,
        managed: false,
        other: false,
        router_lifetime: 1800,
        source_ll: Some(ROUTER_MAC),
        mtu: Some(1400),
        prefixes: vec![PrefixInfo {
            prefix_len,
            on_link: true,
            autonomous,
            valid_lifetime: valid,
            preferred_lifetime: valid.min(3600),
            prefix: PREFIX,
        }],
        dns: vec!["2001:db8::53".parse().unwrap()],
    }
}

type Log = Rc<RefCell<Vec<Vec<u8>>>>;

/// Records every frame the host sends.
fn record(h: &mut Host) -> Log {
    let log: Log = Rc::default();
    let l = log.clone();
    h.set_filter(move |_, f| {
        l.borrow_mut().push(f.to_vec());
        true
    });
    log
}

/// The ICMPv6 messages in `log` as `(type, code, destination)`.
fn icmp_sent(log: &Log) -> Vec<(u8, u8, Ipv6Addr)> {
    log.borrow()
        .iter()
        .filter_map(|f| {
            let (_, p) = EthernetHeader::parse(f)?;
            let (ip, p) = Ipv6Header::parse(p)?;
            let (icmp, _) = Icmpv6Header::parse(p, ip.src, ip.dst)?;
            Some((icmp.ty, icmp.code, ip.dst))
        })
        .collect()
}

#[test]
fn link_local_addresses_follow_duplicate_detection() {
    let (mut a, mut b) = link();
    a.iface.enable_ipv6().unwrap();
    let mut now = Instant::ZERO;
    a.poll(now);
    let addrs = a.iface.ipv6_addresses();
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0].addr, link_local_from_mac(a.iface.mac_address()));
    assert!(!addrs[0].usable, "tentative while it is probed");
    assert_eq!(a.iface.ipv6_link_local(), None);
    assert!(run(&mut a, &mut b, &mut now, 2000, |a, _| a.iface.ipv6_link_local().is_some()));
    assert!(now.as_millis() >= 1000, "after the one second detection wait");
    assert!(a.iface.ipv6_addresses()[0].usable);
    assert!(!b.iface.ipv6_enabled() && b.iface.ipv6_link_local().is_none());
    a.iface.disable_ipv6();
    assert_eq!(a.iface.ipv6_link_local(), None);
}

#[test]
fn ping_resolves_with_neighbor_discovery() {
    let (mut a, mut b, mut now) = pair6();
    let (a_ll, b_ll) = (ll(&a), ll(&b));
    let h = a.sockets.add(IcmpSocket::new(0x4242, 4));
    a.sockets.get_mut::<IcmpSocket>(h).send_echo(b_ll, 3, b"hello6").unwrap();
    let mut reply = None;
    assert!(run(&mut a, &mut b, &mut now, 200, |a, _| {
        reply = a.sockets.get_mut::<IcmpSocket>(h).recv();
        reply.is_some()
    }));
    let reply = reply.unwrap();
    assert_eq!((reply.from, reply.seq, &reply.data[..]), (IpAddr::V6(b_ll), 3, &b"hello6"[..]));
    // B learned A from the solicitation.
    assert_eq!(b.iface.v6.lookup(a_ll, now), Some(a.iface.mac_address()));
    assert_eq!(a.iface.v6.lookup(b_ll, now), Some(b.iface.mac_address()));
}

#[test]
fn udp_both_families_on_one_interface() {
    let (mut a, mut b, mut now) = pair6();
    a.iface.set_config(Some(config(A_IP)));
    b.iface.set_config(Some(config(B_IP)));
    let (b_ll, a_ll) = (ll(&b), ll(&a));
    let sa6 = a.sockets.add(UdpSocket::new(4, 4));
    let sb6 = b.sockets.add(UdpSocket::new(4, 4));
    let sb4 = b.sockets.add(UdpSocket::new(4, 4));
    a.sockets.get_mut::<UdpSocket>(sa6).bind_addr(any6(1000)).unwrap();
    b.sockets.get_mut::<UdpSocket>(sb6).bind_addr(any6(2000)).unwrap();
    b.sockets.get_mut::<UdpSocket>(sb4).bind(2000).unwrap();
    a.sockets.get_mut::<UdpSocket>(sa6).send_to(b"v6 datagram", SocketAddr::new(b_ll.into(), 2000)).unwrap();
    // A v6 socket cannot send to a v4 address.
    assert_eq!(
        a.sockets.get_mut::<UdpSocket>(sa6).send_to(b"x", SocketAddr::new(B_IP.into(), 2000)),
        Err(Error::InvalidAddress)
    );
    assert!(run(&mut a, &mut b, &mut now, 200, |_, b| b.sockets.get::<UdpSocket>(sb6).can_recv()));
    let mut buf = [0; 64];
    let (n, from) = b.sockets.get_mut::<UdpSocket>(sb6).recv_from(&mut buf).unwrap();
    assert_eq!((&buf[..n], from), (&b"v6 datagram"[..], SocketAddr::new(a_ll.into(), 1000)));
    assert!(!b.sockets.get::<UdpSocket>(sb4).can_recv(), "the IPv4 socket on that port did not see it");
    // The reply comes back to a v6 address.
    b.sockets.get_mut::<UdpSocket>(sb6).send_to(b"pong", from).unwrap();
    assert!(run(&mut a, &mut b, &mut now, 200, |a, _| a.sockets.get::<UdpSocket>(sa6).can_recv()));
    let (n, from) = a.sockets.get_mut::<UdpSocket>(sa6).recv_from(&mut buf).unwrap();
    assert_eq!((&buf[..n], from), (&b"pong"[..], SocketAddr::new(b_ll.into(), 2000)));
    // IPv4 keeps working beside it.
    let ca = a.sockets.add(UdpSocket::new(4, 4));
    a.sockets.get_mut::<UdpSocket>(ca).bind(1001).unwrap();
    a.sockets.get_mut::<UdpSocket>(ca).send_to(b"v4", SocketAddr::new(B_IP.into(), 2000)).unwrap();
    assert!(run(&mut a, &mut b, &mut now, 200, |_, b| b.sockets.get::<UdpSocket>(sb4).can_recv()));
}

#[test]
fn udp_to_a_closed_port_gets_icmpv6_port_unreachable() {
    let (mut a, mut b, mut now) = pair6();
    let b_ll = ll(&b);
    let log = record(&mut b);
    let h = a.sockets.add(UdpSocket::new(4, 4));
    a.sockets.get_mut::<UdpSocket>(h).bind_addr(any6(1000)).unwrap();
    a.sockets.get_mut::<UdpSocket>(h).send_to(b"knock", SocketAddr::new(b_ll.into(), 9)).unwrap();
    run(&mut a, &mut b, &mut now, 200, |_, _| false);
    let found = log.borrow().iter().any(|f| {
        let Some((_, p)) = EthernetHeader::parse(f) else { return false };
        let Some((ip, p)) = Ipv6Header::parse(p) else { return false };
        let Some((icmp, body)) = Icmpv6Header::parse(p, ip.src, ip.dst) else { return false };
        (icmp.ty, icmp.code) == (ICMPV6_DEST_UNREACHABLE, ICMPV6_PORT_UNREACHABLE) && body.ends_with(b"knock")
    });
    assert!(found, "B sent port unreachable quoting the datagram");
}

#[test]
fn tcp_over_ipv6() {
    let (mut a, mut b, mut now) = pair6();
    let b_ll = ll(&b);
    let ca = a.sockets.add(TcpSocket::new(4096, 4096));
    let cb = b.sockets.add(TcpSocket::new(4096, 4096));
    b.sockets.get_mut::<TcpSocket>(cb).listen_on(any6(80)).unwrap();
    a.sockets.get_mut::<TcpSocket>(ca).connect(SocketAddr::new(b_ll.into(), 80), 0).unwrap();
    assert!(run(&mut a, &mut b, &mut now, 1000, |a, b| {
        a.sockets.get::<TcpSocket>(ca).state() == TcpState::Established
            && b.sockets.get::<TcpSocket>(cb).state() == TcpState::Established
    }));
    let local = a.sockets.get::<TcpSocket>(ca).local_endpoint();
    assert_eq!(local.ip(), IpAddr::V6(ll(&a)));
    assert_eq!(b.sockets.get::<TcpSocket>(cb).remote_endpoint(), local);

    // Enough data to need many segments in each direction.
    let data: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    let (mut sent, mut got_b, mut echoed, mut got_a) = (0, Vec::new(), 0, Vec::new());
    let mut buf = [0; 2048];
    assert!(run(&mut a, &mut b, &mut now, 20_000, |a, b| {
        sent += a.sockets.get_mut::<TcpSocket>(ca).send(&data[sent..]).unwrap_or(0);
        while let Ok(n @ 1..) = b.sockets.get_mut::<TcpSocket>(cb).recv(&mut buf) {
            got_b.extend_from_slice(&buf[..n]);
        }
        echoed += b.sockets.get_mut::<TcpSocket>(cb).send(&got_b[echoed..]).unwrap_or(0);
        while let Ok(n @ 1..) = a.sockets.get_mut::<TcpSocket>(ca).recv(&mut buf) {
            got_a.extend_from_slice(&buf[..n]);
        }
        got_a.len() == data.len()
    }));
    assert_eq!(got_b, data);
    assert_eq!(got_a, data);
    assert_eq!(usize::from(a.iface.mss6()), 1500 - 40 - 20);

    a.sockets.get_mut::<TcpSocket>(ca).close();
    assert!(run(&mut a, &mut b, &mut now, 200, |_, b| b.sockets.get::<TcpSocket>(cb).state() == TcpState::CloseWait));
}

#[test]
fn tcp_to_a_closed_port_is_reset() {
    let (mut a, mut b, mut now) = pair6();
    let ca = a.sockets.add(TcpSocket::new(1024, 1024));
    a.sockets.get_mut::<TcpSocket>(ca).connect(SocketAddr::new(ll(&b).into(), 81), 0).unwrap();
    assert!(run(&mut a, &mut b, &mut now, 1000, |a, _| a.sockets.get::<TcpSocket>(ca).state() == TcpState::Closed));
    assert_eq!(a.sockets.get::<TcpSocket>(ca).error(), Some(Error::ConnectionRefused));
}

#[test]
fn extension_headers_are_skipped_on_delivery() {
    let (mut a, _b, _) = pair6();
    let (a_ll, a_mac) = (ll(&a), a.iface.mac_address());
    let h = a.sockets.add(UdpSocket::new(4, 4));
    a.sockets.get_mut::<UdpSocket>(h).bind_addr(any6(7000)).unwrap();
    let udp = UdpHeader { src_port: 5, dst_port: 7000 }.emit(ROUTER, a_ll, b"through headers");
    // Hop-by-hop with PadN, then destination options, then UDP.
    let mut p = vec![PROTO_DSTOPTS, 0, 1, 4, 0, 0, 0, 0, PROTO_UDP, 0, 1, 4, 0, 0, 0, 0];
    p.extend_from_slice(&udp);
    a.inject(frame(a_mac, ROUTER, a_ll, PROTO_HOPOPTS, 64, &p));
    a.poll(Instant::from_millis(5000));
    let mut buf = [0; 64];
    let (n, from) = a.sockets.get_mut::<UdpSocket>(h).recv_from(&mut buf).unwrap();
    assert_eq!((&buf[..n], from), (&b"through headers"[..], SocketAddr::new(ROUTER.into(), 5)));

    // A fragment that is not the whole datagram is dropped; the same
    // datagram under an atomic fragment header is delivered.
    let mut frag = vec![PROTO_UDP, 0, 0, 1, 0, 0, 0, 9];
    frag.extend_from_slice(&udp);
    a.inject(frame(a_mac, ROUTER, a_ll, PROTO_FRAGMENT, 64, &frag));
    a.poll(Instant::from_millis(5001));
    assert!(!a.sockets.get::<UdpSocket>(h).can_recv());
    frag[3] = 0;
    a.inject(frame(a_mac, ROUTER, a_ll, PROTO_FRAGMENT, 64, &frag));
    a.poll(Instant::from_millis(5002));
    assert!(a.sockets.get::<UdpSocket>(h).can_recv());
    a.sockets.get_mut::<UdpSocket>(h).recv_from(&mut buf).unwrap();

    // A corrupt UDP checksum, and none at all (illegal over IPv6), are dropped.
    let mut bad = udp.clone();
    bad[8] ^= 1;
    a.inject(frame(a_mac, ROUTER, a_ll, PROTO_UDP, 64, &bad));
    let mut none = udp;
    none[6..8].fill(0);
    a.inject(frame(a_mac, ROUTER, a_ll, PROTO_UDP, 64, &none));
    a.poll(Instant::from_millis(5003));
    assert!(!a.sockets.get::<UdpSocket>(h).can_recv());
}

#[test]
fn neighbor_discovery_rejects_forgeries() {
    let (mut a, _b, now) = pair6();
    let (a_ll, a_mac) = (ll(&a), a.iface.mac_address());
    let forged_mac = MacAddress([2, 0, 0, 0, 0, 0x66]);
    let solicit = |hop: u8, target: Ipv6Addr| {
        let body = NeighborSolicit { target, source_ll: Some(forged_mac) }.emit();
        icmp_frame(a_mac, ROUTER, a_ll, hop, ICMPV6_NEIGHBOR_SOLICIT, &body)
    };
    let log = record(&mut a);
    // Hop limit 64: crossed a router, so not neighbor discovery.
    a.inject(solicit(64, a_ll));
    // A target that is not ours.
    a.inject(solicit(255, ROUTER));
    a.poll(now);
    assert!(a.iface.v6.lookup(ROUTER, now).is_none() && log.borrow().is_empty());
    // A proper one is answered and learned.
    a.inject(solicit(255, a_ll));
    a.poll(now);
    assert_eq!(a.iface.v6.lookup(ROUTER, now), Some(forged_mac));
    assert_eq!(icmp_sent(&log), [(ICMPV6_NEIGHBOR_ADVERT, 0, ROUTER)]);
    // An unsolicited advertisement does not add an entry...
    let other: Ipv6Addr = "fe80::77".parse().unwrap();
    let na =
        NeighborAdvert { router: false, solicited: false, override_: true, target: other, target_ll: Some(forged_mac) };
    a.inject(icmp_frame(a_mac, other, a_ll, 255, ICMPV6_NEIGHBOR_ADVERT, &na.emit()));
    a.poll(now);
    assert!(a.iface.v6.lookup(other, now).is_none());
    // ...a bad checksum is dropped...
    let mut f = solicit(255, a_ll);
    let last = f.len() - 1;
    f[last] ^= 0xff;
    a.inject(f);
    a.poll(now);
    assert_eq!(log.borrow().len(), 1);
    // ...and a router advertisement needs a link-local source and hop limit 255.
    let global_src: Ipv6Addr = "2001:db8::99".parse().unwrap();
    a.inject(icmp_frame(a_mac, global_src, a_ll, 255, ICMPV6_ROUTER_ADVERT, &advert(64, true, 1000).emit()));
    a.inject(icmp_frame(a_mac, ROUTER, a_ll, 64, ICMPV6_ROUTER_ADVERT, &advert(64, true, 1000).emit()));
    a.poll(now);
    assert_eq!(a.iface.ipv6_addresses().len(), 1);
    assert_eq!(a.iface.ipv6_gateway(), None);
}

#[test]
fn router_advertisement_configures_slaac() {
    let (mut a, mut b) = link();
    let log = record(&mut a);
    a.iface.enable_ipv6().unwrap();
    let mut now = Instant::ZERO;
    assert!(run(&mut a, &mut b, &mut now, 2000, |a, _| a.iface.ipv6_link_local().is_some()));
    let a_mac = a.iface.mac_address();
    // Router solicitations go out once the link-local address is usable.
    run(&mut a, &mut b, &mut now, 10, |_, _| false);
    let sent = icmp_sent(&log);
    assert!(sent.contains(&(ICMPV6_NEIGHBOR_SOLICIT, 0, solicited_node(ll(&a)))), "duplicate address probe");
    assert!(sent.contains(&(ICMPV6_ROUTER_SOLICIT, 0, ALL_ROUTERS)));

    let ra = advert(64, true, 7000).emit();
    a.inject(icmp_frame(multicast_mac(ALL_NODES), ROUTER, ALL_NODES, 255, ICMPV6_ROUTER_ADVERT, &ra));
    a.poll(now);
    let global = with_prefix(PREFIX, 64, eui64(a_mac));
    assert!(!a.iface.ipv6_addresses().iter().any(|x| x.addr == global && x.usable), "tentative first");
    assert!(run(&mut a, &mut b, &mut now, 2000, |a, _| a.iface.v6.global() == Some(global)));
    assert_eq!(a.iface.ipv6_gateway(), Some(ROUTER));
    assert_eq!(a.iface.ipv6_dns(), ["2001:db8::53".parse::<Ipv6Addr>().unwrap()]);
    assert_eq!(a.iface.ipv6_mtu(), 1400);
    assert_eq!(a.iface.v6.lookup(ROUTER, now), Some(ROUTER_MAC), "from the source link-layer option");

    // Off-link traffic goes to the router's MAC, from the global address.
    let h = a.sockets.add(UdpSocket::new(4, 4));
    a.sockets.get_mut::<UdpSocket>(h).bind_addr(any6(1000)).unwrap();
    let far: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
    log.borrow_mut().clear();
    a.sockets.get_mut::<UdpSocket>(h).send_to(b"far", SocketAddr::new(far.into(), 53)).unwrap();
    a.poll(now);
    let sent = log.borrow().clone();
    let (eth, p) = EthernetHeader::parse(&sent[0]).unwrap();
    let (ip, _) = Ipv6Header::parse(p).unwrap();
    assert_eq!((eth.dst, ip.src, ip.dst), (ROUTER_MAC, global, far));

    // The address lives as long as the router said.
    a.poll(Instant::from_millis(8_000_000));
    assert!(!a.iface.ipv6_addresses().iter().any(|x| x.addr == global));
    assert_eq!(a.iface.ipv6_gateway(), None, "router lifetime ended");
}

#[test]
fn slaac_ignores_what_it_should() {
    let (mut a, _b, now) = pair6();
    let ra = |a: &mut Host, ra: RouterAdvert| {
        a.inject(icmp_frame(multicast_mac(ALL_NODES), ROUTER, ALL_NODES, 255, ICMPV6_ROUTER_ADVERT, &ra.emit()));
        a.poll(now);
    };
    // Not a /64, or not autonomous: no address.
    ra(&mut a, advert(48, true, 1000));
    ra(&mut a, advert(64, false, 1000));
    assert_eq!(a.iface.ipv6_addresses().len(), 1);
    // A preferred lifetime above the valid one is nonsense.
    let mut bad = advert(64, true, 1000);
    bad.prefixes[0].preferred_lifetime = 2000;
    ra(&mut a, bad);
    assert_eq!(a.iface.ipv6_addresses().len(), 1);
    // A router lifetime of 0 withdraws the router.
    ra(&mut a, advert(64, true, 1000));
    assert_eq!(a.iface.ipv6_gateway(), Some(ROUTER));
    ra(&mut a, RouterAdvert { router_lifetime: 0, prefixes: vec![], ..advert(64, true, 1000) });
    assert_eq!(a.iface.ipv6_gateway(), None);
    // With SLAAC off, advertisements are ignored.
    a.iface.set_slaac(false);
    let before = a.iface.ipv6_addresses().len();
    ra(&mut a, advert(64, true, 2000));
    assert_eq!(a.iface.ipv6_addresses().len(), before);
}

#[test]
fn static_addresses_and_gateway() {
    let (mut a, mut b, mut now) = pair6();
    let (x, y): (Ipv6Addr, Ipv6Addr) = ("2001:db8:5::1".parse().unwrap(), "2001:db8:5::2".parse().unwrap());
    assert_eq!(a.iface.add_ipv6_address(ll(&a), 64), Err(Error::InvalidAddress));
    assert_eq!(a.iface.add_ipv6_address(Ipv6Addr::UNSPECIFIED, 64), Err(Error::InvalidAddress));
    assert_eq!(a.iface.add_ipv6_address(x, 129), Err(Error::InvalidAddress));
    a.iface.add_ipv6_address(x, 64).unwrap();
    b.iface.add_ipv6_address(y, 64).unwrap();
    assert!(run(&mut a, &mut b, &mut now, 2000, |a, b| a.iface.v6.global().is_some() && b.iface.v6.global().is_some()));
    // Addresses on one prefix talk without a router.
    let h = a.sockets.add(IcmpSocket::new(1, 4));
    a.sockets.get_mut::<IcmpSocket>(h).send_echo(y, 1, b"static").unwrap();
    let mut reply = None;
    assert!(run(&mut a, &mut b, &mut now, 200, |a, _| {
        reply = a.sockets.get_mut::<IcmpSocket>(h).recv();
        reply.is_some()
    }));
    assert_eq!(reply.unwrap().from, IpAddr::V6(y));
    // An absent neighbor drops the packet after the retries.
    let z: Ipv6Addr = "2001:db8:5::99".parse().unwrap();
    a.sockets.get_mut::<IcmpSocket>(h).send_echo(z, 2, b"nobody").unwrap();
    run(&mut a, &mut b, &mut now, 4000, |_, _| false);
    assert!(a.iface.v6.pending.is_empty() && a.iface.v6.requests.is_empty());
    assert!(a.sockets.get_mut::<IcmpSocket>(h).recv().is_none());
    // Off-link destinations need a gateway.
    let far: Ipv6Addr = "2001:db8:9::1".parse().unwrap();
    a.sockets.get_mut::<IcmpSocket>(h).send_echo(far, 3, b"far").unwrap();
    a.poll(now);
    assert!(a.iface.v6.requests.is_empty(), "no route, nothing asked");
    a.iface.set_ipv6_gateway(Some(ll(&b)));
    assert_eq!(a.iface.ipv6_gateway(), Some(ll(&b)));
}

#[test]
fn duplicate_address_detection_catches_a_clash() {
    // B already uses the address when A wants it.
    let x: Ipv6Addr = "2001:db8:5::1".parse().unwrap();
    let (mut a, mut b, mut now) = pair6();
    b.iface.add_ipv6_address(x, 64).unwrap();
    assert!(run(&mut a, &mut b, &mut now, 2000, |_, b| b.iface.v6.global() == Some(x)));
    a.iface.add_ipv6_address(x, 64).unwrap();
    run(&mut a, &mut b, &mut now, 2000, |_, _| false);
    assert!(!a.iface.ipv6_addresses().iter().any(|s| s.addr == x), "A gave the address up");
    assert_eq!(b.iface.v6.global(), Some(x), "B kept it");

    // Both probing at once: at most one gets it (here B, which had not yet
    // probed, sees A's probe first and withdraws).
    let (mut a, mut b, mut now) = pair6();
    a.iface.add_ipv6_address(x, 64).unwrap();
    b.iface.add_ipv6_address(x, 64).unwrap();
    run(&mut a, &mut b, &mut now, 3000, |_, _| false);
    assert_eq!((a.iface.v6.global(), b.iface.v6.global()), (Some(x), None));
}
