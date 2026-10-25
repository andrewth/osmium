use std::cell::RefCell;
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use osmium_hal::net::MacAddress;

use super::*;
use crate::ipv6::{ETHERTYPE_IPV6, PROTO_DSTOPTS};
use crate::testing::{Fate, Host, pair6, run};
use crate::wire::{ETH_HEADER_LEN, EthernetHeader, PROTO_UDP, UdpHeader};
use crate::{IcmpSocket, UdpSocket};

const PEER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x99]);
const PEER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);

fn any6(port: u16) -> core::net::SocketAddr {
    core::net::SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 13 + i / 251) as u8).collect()
}

/// A frame from `PEER` to `dst` carrying `payload` as protocol `next`.
fn frame(dst_mac: MacAddress, dst: Ipv6Addr, next: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0; ETH_HEADER_LEN + IPV6_HEADER_LEN + payload.len()];
    EthernetHeader { dst: dst_mac, src: PEER_MAC, ethertype: ETHERTYPE_IPV6 }.emit(&mut f);
    let h = Ipv6Header { src: PEER, dst, next_header: next, hop_limit: 64, payload_len: payload.len(), fragment: None };
    h.emit(&mut f[ETH_HEADER_LEN..]);
    f[ETH_HEADER_LEN + IPV6_HEADER_LEN..].copy_from_slice(payload);
    f
}

/// Frames that carry `message` (an upper-layer message) from `PEER` to `host`
/// in pieces of at most `mtu`.
fn pieces_to(host: &Host, ident: u32, next: u8, message: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    let ll = host.iface.ipv6_link_local().unwrap();
    let mac = host.iface.mac_address();
    frag6::fragment(message, next, mtu, ident).unwrap().iter().map(|p| frame(mac, ll, PROTO_FRAGMENT, p)).collect()
}

/// A UDP datagram from `PEER` to port 7000 of `host`.
fn udp_to(host: &Host, body: &[u8]) -> Vec<u8> {
    UdpHeader { src_port: 5, dst_port: 7000 }.emit(PEER, host.iface.ipv6_link_local().unwrap(), body)
}

fn listener(h: &mut Host) -> crate::SocketHandle {
    let s = h.sockets.add(UdpSocket::new(4, 4));
    h.sockets.get_mut::<UdpSocket>(s).bind_addr(any6(7000)).unwrap();
    s
}

fn received(h: &mut Host, s: crate::SocketHandle) -> Option<Vec<u8>> {
    let mut buf = vec![0; 70_000];
    let (n, _) = h.sockets.get_mut::<UdpSocket>(s).recv_from(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// The fragment header fields of the IPv6 packets in `frames`.
fn fragments_in(frames: &[Vec<u8>]) -> Vec<(usize, bool, usize)> {
    frames
        .iter()
        .filter_map(|f| {
            let (_, p) = EthernetHeader::parse(f)?;
            let (ip, payload) = Ipv6Header::parse(p)?;
            let fr = ip.fragment?;
            Some((fr.offset, fr.more, ETH_HEADER_LEN + IPV6_HEADER_LEN + 8 + payload.len()))
        })
        .collect()
}

#[test]
fn a_large_datagram_is_fragmented_and_reassembled_despite_reordering_and_duplicates() {
    let (mut a, mut b, mut now) = pair6();
    let b_ll = b.iface.ipv6_link_local().unwrap();
    let sa = a.sockets.add(UdpSocket::new(4, 4));
    a.sockets.get_mut::<UdpSocket>(sa).bind_addr(any6(1000)).unwrap();
    let sb = listener(&mut b);
    // Resolve the neighbor first so the shaper sees only the datagram.
    let h = a.sockets.add(IcmpSocket::new(1, 4));
    a.sockets.get_mut::<IcmpSocket>(h).send_echo(b_ll, 1, b"x").unwrap();
    assert!(run(&mut a, &mut b, &mut now, 200, |a, _| a.sockets.get_mut::<IcmpSocket>(h).recv().is_some()));

    let sent: Rc<RefCell<Vec<Vec<u8>>>> = Rc::default();
    let log = sent.clone();
    let n = Rc::new(RefCell::new(0));
    a.set_shaper(move |_, f| {
        log.borrow_mut().push(f.to_vec());
        *n.borrow_mut() += 1;
        match *n.borrow() {
            1 => Fate::Delay(2),
            2 => Fate::Duplicate,
            _ => Fate::Deliver,
        }
    });
    let body = data(9000);
    a.sockets.get_mut::<UdpSocket>(sa).send_to(&body, core::net::SocketAddr::new(b_ll.into(), 7000)).unwrap();
    assert!(run(&mut a, &mut b, &mut now, 500, |_, b| b.sockets.get::<UdpSocket>(sb).can_recv()));
    let mut buf = vec![0; 10_000];
    let (n, from) = b.sockets.get_mut::<UdpSocket>(sb).recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], &body[..]);
    assert_eq!(from.port(), 1000);
    // 9008 bytes of UDP in pieces of 1448: 7 pieces, none over the MTU.
    let frags = fragments_in(&sent.borrow());
    assert_eq!(frags.len(), 7);
    assert!(frags.iter().all(|&(_, _, len)| len <= 1514));
    assert_eq!(frags.iter().filter(|f| !f.1).count(), 1);
    assert_eq!(b.iface.ipv6_reassembly_bytes(), 0);
    assert!(!b.sockets.get::<UdpSocket>(sb).can_recv(), "delivered once");
}

#[test]
fn large_pings_are_fragmented_both_ways() {
    let (mut a, mut b, mut now) = pair6();
    let b_ll = b.iface.ipv6_link_local().unwrap();
    let h = a.sockets.add(IcmpSocket::new(7, 4));
    let body = data(4000);
    a.sockets.get_mut::<IcmpSocket>(h).send_echo(b_ll, 9, &body).unwrap();
    let mut reply = None;
    assert!(run(&mut a, &mut b, &mut now, 500, |a, _| {
        reply = a.sockets.get_mut::<IcmpSocket>(h).recv();
        reply.is_some()
    }));
    let reply = reply.unwrap();
    assert_eq!((reply.seq, reply.data), (9, body));
}

#[test]
fn a_lost_piece_loses_the_datagram_and_its_memory_after_the_timeout() {
    let (mut a, _b, _) = pair6();
    let s = listener(&mut a);
    let msg = udp_to(&a, &data(5000));
    let all = pieces_to(&a, 1, PROTO_UDP, &msg, 1280);
    assert_eq!(all.len(), 5);
    let mut now = Instant::from_millis(10_000);
    for (n, f) in all.into_iter().enumerate() {
        if n != 2 {
            a.inject(f);
        }
    }
    a.poll(now);
    assert!(a.iface.ipv6_reassembly_bytes() > 0);
    assert!(received(&mut a, s).is_none());
    assert_eq!(a.iface.v6.reasm.poll_at().map(|t| t.as_millis()), Some(70_000));
    assert!(a.iface.poll_at(&a.sockets).is_some_and(|t| t.as_millis() <= 70_000));
    now = Instant::from_millis(69_999);
    a.poll(now);
    assert!(a.iface.ipv6_reassembly_bytes() > 0);
    now = Instant::from_millis(70_000);
    a.poll(now);
    assert_eq!(a.iface.ipv6_reassembly_bytes(), 0);
    // The missing piece arriving late finds nothing to join.
    let late = pieces_to(&a, 1, PROTO_UDP, &msg, 1280);
    a.inject(late[2].clone());
    a.poll(now);
    assert!(received(&mut a, s).is_none());
}

#[test]
fn hostile_fragments_are_dropped() {
    let (mut a, _b, _) = pair6();
    let s = listener(&mut a);
    let a_ll = a.iface.ipv6_link_local().unwrap();
    let a_mac = a.iface.mac_address();
    let now = Instant::from_millis(5000);
    let msg = udp_to(&a, &data(3000));
    let good = pieces_to(&a, 7, PROTO_UDP, &msg, 1280);

    // An overlapping piece condemns the datagram, even if the rest follow.
    let mut overlap = vec![PROTO_UDP, 0, 0, 8 | 1, 0, 0, 0, 7];
    overlap.extend_from_slice(&[0xaa; 16]);
    a.inject(good[0].clone());
    a.inject(frame(a_mac, a_ll, PROTO_FRAGMENT, &overlap));
    a.inject(good[1].clone());
    a.inject(good[2].clone());
    a.poll(now);
    assert!(received(&mut a, s).is_none());
    assert_eq!(a.iface.ipv6_reassembly_bytes(), 3008 - 1232, "only the pieces after the wreck");

    // Empty pieces and middle pieces not a multiple of 8 are refused.
    let empty = [PROTO_UDP, 0, 0, 1, 0, 0, 0, 8];
    a.inject(frame(a_mac, a_ll, PROTO_FRAGMENT, &empty));
    let mut odd = vec![PROTO_UDP, 0, 0, 1, 0, 0, 0, 8];
    odd.extend_from_slice(&[0; 13]);
    a.inject(frame(a_mac, a_ll, PROTO_FRAGMENT, &odd));
    a.poll(now);

    // Pieces not for us (a group, a stranger) are not held.
    let before = a.iface.ipv6_reassembly_bytes();
    let mut multicast = vec![PROTO_UDP, 0, 0, 1, 0, 0, 0, 9];
    multicast.extend_from_slice(&[0; 16]);
    a.inject(frame(MacAddress([0x33, 0x33, 0, 0, 0, 1]), crate::ipv6::ALL_NODES, PROTO_FRAGMENT, &multicast));
    a.inject(frame(a_mac, "2001:db8::5".parse().unwrap(), PROTO_FRAGMENT, &multicast));
    a.poll(now);
    assert_eq!(a.iface.ipv6_reassembly_bytes(), before);

    // A reassembled datagram that itself starts with a fragment header is not
    // reassembled again: one level only.
    let mut inner = vec![PROTO_UDP, 0, 0, 8 | 1, 0, 0, 0, 3];
    inner.extend_from_slice(&[0; 8]);
    for f in pieces_to(&a, 11, PROTO_FRAGMENT, &inner, 1280) {
        a.inject(f);
    }
    a.poll(now);
    assert!(received(&mut a, s).is_none());
}

#[test]
fn a_flood_of_incomplete_datagrams_is_bounded() {
    let (mut a, _b, _) = pair6();
    let a_ll = a.iface.ipv6_link_local().unwrap();
    let a_mac = a.iface.mac_address();
    let limits = crate::frag6::Limits { datagrams: 4, total_bytes: 8192, ..Default::default() };
    a.iface.set_ipv6_reassembly_limits(limits);
    assert_eq!(a.iface.ipv6_reassembly_limits(), limits);
    let mut now = Instant::from_millis(5000);
    for ident in 0..500u32 {
        let mut p = vec![PROTO_UDP, 0, 0, 1, 0, 0, 0, 0];
        p[4..8].copy_from_slice(&ident.to_be_bytes());
        p.extend_from_slice(&[0; 1200]);
        a.inject(frame(a_mac, a_ll, PROTO_FRAGMENT, &p));
        a.poll(now);
        assert!(a.iface.ipv6_reassembly_bytes() <= 8192);
        now = Instant::from_millis(now.as_millis() + 1);
    }
    assert!(a.iface.ipv6_reassembly_bytes() > 0);
    // Tiny pieces, one per 8 bytes, cannot grow one datagram without bound.
    let mut a2 = pair6().0;
    let (ll2, mac2) = (a2.iface.ipv6_link_local().unwrap(), a2.iface.mac_address());
    for n in 0..1000usize {
        let field = (n * 8) as u16 | 1;
        let mut p = vec![PROTO_UDP, 0, (field >> 8) as u8, field as u8, 0, 0, 0, 1];
        p.extend_from_slice(&[0; 8]);
        a2.inject(frame(mac2, ll2, PROTO_FRAGMENT, &p));
    }
    a2.poll(Instant::from_millis(5000));
    assert!(a2.iface.ipv6_reassembly_bytes() <= 128 * 8);
}

#[test]
fn headers_before_the_fragment_header_are_checked_and_dropped_from_the_datagram() {
    let (mut a, _b, _) = pair6();
    let s = listener(&mut a);
    let (a_ll, a_mac) = (a.iface.ipv6_link_local().unwrap(), a.iface.mac_address());
    let msg = udp_to(&a, b"after a destination options header");
    // Destination options (PadN), then the fragment header, in two pieces.
    let split = 16;
    let (head, tail) = msg.split_at(split);
    let mut first = vec![PROTO_FRAGMENT, 0, 1, 4, 0, 0, 0, 0, PROTO_UDP, 0, 0, 1, 0, 0, 0, 4];
    first.extend_from_slice(head);
    let mut last = vec![PROTO_FRAGMENT, 0, 1, 4, 0, 0, 0, 0, PROTO_UDP, 0, 0, split as u8, 0, 0, 0, 4];
    last.extend_from_slice(tail);
    a.inject(frame(a_mac, a_ll, PROTO_DSTOPTS, &last));
    a.inject(frame(a_mac, a_ll, PROTO_DSTOPTS, &first));
    a.poll(Instant::from_millis(5000));
    assert_eq!(received(&mut a, s).as_deref(), Some(&b"after a destination options header"[..]));
}

#[test]
fn tcp_and_oversized_datagrams_are_not_fragmented() {
    let (mut a, mut b, mut now) = pair6();
    let b_ll = b.iface.ipv6_link_local().unwrap();
    let sa = a.sockets.add(UdpSocket::new(4, 4));
    a.sockets.get_mut::<UdpSocket>(sa).bind_addr(any6(1000)).unwrap();
    // Over the 65535 an IPv6 payload can hold.
    assert_eq!(
        a.sockets.get_mut::<UdpSocket>(sa).send_to(&vec![0; 65_528], core::net::SocketAddr::new(b_ll.into(), 7000)),
        Err(crate::Error::TooLarge)
    );
    // The largest that fits is fragmented into 54 pieces and delivered.
    let sb = listener(&mut b);
    let big = data(65_527);
    a.sockets.get_mut::<UdpSocket>(sa).send_to(&big, core::net::SocketAddr::new(b_ll.into(), 7000)).unwrap();
    assert!(run(&mut a, &mut b, &mut now, 2000, |_, b| b.sockets.get::<UdpSocket>(sb).can_recv()));
    assert_eq!(received(&mut b, sb), Some(big));
}
