use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use osmium_hal::net::MacAddress;

use super::*;
use crate::ipv6::{ETHERTYPE_IPV6, ICMPV6_PACKET_TOO_BIG, Icmpv6Header, Ipv6Header};
use crate::pmtu::{ICMP_FRAGMENTATION_NEEDED, MIN_MTU_V4, MIN_MTU_V6, PMTU_TIMEOUT};
use crate::testing::{A_IP, B_IP, Host, pair, pair6, run, sa};
use crate::wire::*;
use crate::{SocketHandle, TcpSocket, TcpState, UdpSocket};

const ROUTER4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 254);
const ROUTER6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);
const ROUTER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x99]);

type Conn = (SocketHandle, SocketHandle);

/// An ICMP "fragmentation needed" from the router to `dst`, quoting `quote`.
fn frag_needed(dst_mac: MacAddress, dst: Ipv4Addr, quote: &[u8], mtu: u16) -> Vec<u8> {
    let header = IcmpHeader { ty: ICMP_DEST_UNREACHABLE, code: ICMP_FRAGMENTATION_NEEDED, ident: 0, seq: mtu };
    let icmp = header.emit(quote);
    let mut f = vec![0; ETH_HEADER_LEN + IPV4_HEADER_LEN + icmp.len()];
    EthernetHeader { dst: dst_mac, src: ROUTER_MAC, ethertype: ETHERTYPE_IPV4 }.emit(&mut f);
    Ipv4Header { src: ROUTER4, dst, protocol: PROTO_ICMP, ttl: 64, ident: 0, payload_len: icmp.len() }
        .emit(&mut f[ETH_HEADER_LEN..]);
    f[ETH_HEADER_LEN + IPV4_HEADER_LEN..].copy_from_slice(&icmp);
    f
}

/// An ICMPv6 "packet too big" from the router to `dst`.
fn too_big(dst_mac: MacAddress, dst: Ipv6Addr, quote: &[u8], mtu: u32) -> Vec<u8> {
    let mut body = mtu.to_be_bytes().to_vec();
    body.extend_from_slice(quote);
    let icmp = Icmpv6Header { ty: ICMPV6_PACKET_TOO_BIG, code: 0 }.emit(ROUTER6, dst, &body);
    let mut f = vec![0; ETH_HEADER_LEN + IPV6_HEADER_LEN + icmp.len()];
    EthernetHeader { dst: dst_mac, src: ROUTER_MAC, ethertype: ETHERTYPE_IPV6 }.emit(&mut f);
    Ipv6Header { src: ROUTER6, dst, next_header: PROTO_ICMPV6, hop_limit: 64, payload_len: icmp.len(), fragment: None }
        .emit(&mut f[ETH_HEADER_LEN..]);
    f[ETH_HEADER_LEN + IPV6_HEADER_LEN..].copy_from_slice(&icmp);
    f
}

/// A narrow hop beyond the host: packets longer than `limit` (IPv4 ones if
/// DF is set) are dropped and answered with the ICMP error a router would
/// send, which waits in `errors`.
struct Bottleneck {
    errors: Rc<RefCell<Vec<Vec<u8>>>>,
    /// Errors sent so far.
    sent: Rc<Cell<usize>>,
    /// The longest IP packet let through.
    longest: Rc<Cell<usize>>,
}

impl Bottleneck {
    fn new(h: &mut Host, limit: usize) -> Self {
        let b = Self { errors: Rc::default(), sent: Rc::default(), longest: Rc::default() };
        let (errors, sent, longest) = (b.errors.clone(), b.sent.clone(), b.longest.clone());
        let mac = h.dev.mac;
        h.set_filter(move |_, f| {
            let Some((eth, p)) = EthernetHeader::parse(f) else { return true };
            let error = match eth.ethertype {
                ETHERTYPE_IPV4 if p.len() >= 28 => {
                    let total = usize::from(be16(p, 2));
                    if total <= limit || p[6] & 0x40 == 0 {
                        longest.set(longest.get().max(total));
                        return true;
                    }
                    frag_needed(mac, ip(p, 12), &p[..28], limit as u16)
                }
                ETHERTYPE_IPV6 if p.len() >= 48 => {
                    let total = IPV6_HEADER_LEN + usize::from(be16(p, 4));
                    if total <= limit {
                        longest.set(longest.get().max(total));
                        return true;
                    }
                    let mut src = [0; 16];
                    src.copy_from_slice(&p[8..24]);
                    too_big(mac, Ipv6Addr::from(src), &p[..48], limit as u32)
                }
                _ => return true,
            };
            sent.set(sent.get() + 1);
            errors.borrow_mut().push(error);
            false
        });
        b
    }

    fn deliver(&self, h: &mut Host) {
        for f in self.errors.borrow_mut().drain(..) {
            h.inject(f);
        }
    }
}

/// A on an ephemeral port connected to B listening on `port` at `b_addr`.
fn connect(a: &mut Host, b: &mut Host, now: &mut Instant, b_addr: IpAddr, port: u16) -> Conn {
    let ca = a.sockets.add(TcpSocket::new(65535, 65535));
    let cb = b.sockets.add(TcpSocket::new(65535, 65535));
    let any = if b_addr.is_ipv4() { Ipv4Addr::UNSPECIFIED.into() } else { Ipv6Addr::UNSPECIFIED.into() };
    b.sockets.get_mut::<TcpSocket>(cb).listen_on(SocketAddr::new(any, port)).unwrap();
    a.sockets.get_mut::<TcpSocket>(ca).connect(SocketAddr::new(b_addr, port), 0).unwrap();
    assert!(run(a, b, now, 1000, |a, b| {
        a.sockets.get::<TcpSocket>(ca).state() == TcpState::Established
            && b.sockets.get::<TcpSocket>(cb).state() == TcpState::Established
    }));
    (ca, cb)
}

/// Sends `len` bytes from A to B, delivering the bottleneck's errors to A;
/// returns the time it took.
fn transfer(
    a: &mut Host,
    b: &mut Host,
    now: &mut Instant,
    bottleneck: &Bottleneck,
    (ca, cb): Conn,
    len: usize,
) -> core::time::Duration {
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let (mut sent, mut got) = (0, Vec::new());
    let mut buf = [0; 2048];
    let start = *now;
    assert!(
        run(a, b, now, 20_000, |a, b| {
            bottleneck.deliver(a);
            sent += a.sockets.get_mut::<TcpSocket>(ca).send(&data[sent..]).unwrap_or(0);
            while let Ok(n @ 1..) = b.sockets.get_mut::<TcpSocket>(cb).recv(&mut buf) {
                got.extend_from_slice(&buf[..n]);
            }
            got.len() == data.len()
        }),
        "transfer stalled"
    );
    assert!(got == data, "data intact");
    *now - start
}

#[test]
fn tcp_shrinks_its_segments_and_resends_without_waiting() {
    let (mut a, mut b) = pair();
    let mut now = Instant::ZERO;
    let conn = connect(&mut a, &mut b, &mut now, B_IP.into(), 80);
    let narrow = Bottleneck::new(&mut a, 1000);
    assert_eq!(a.iface.path_mtu(B_IP.into(), now), 1500);
    let took = transfer(&mut a, &mut b, &mut now, &narrow, conn, 30_000);
    assert_eq!(a.iface.path_mtu(B_IP.into(), now), 1000);
    assert!(narrow.longest.get() <= 1000 && narrow.longest.get() > 900, "{}", narrow.longest.get());
    assert!(narrow.sent.get() >= 1);
    // The minimum retransmission timeout is 200 ms: waiting for it would
    // take longer than this.
    assert!(took < core::time::Duration::from_millis(190), "{took:?}");

    // A new connection to the same host starts with small segments, so the
    // router has nothing to complain about.
    let errors = narrow.sent.get();
    let conn2 = connect(&mut a, &mut b, &mut now, B_IP.into(), 81);
    transfer(&mut a, &mut b, &mut now, &narrow, conn2, 10_000);
    assert_eq!(narrow.sent.get(), errors);
}

#[test]
fn the_cache_entry_expires() {
    let (mut a, mut b) = pair();
    let mut now = Instant::ZERO;
    let conn = connect(&mut a, &mut b, &mut now, B_IP.into(), 80);
    let narrow = Bottleneck::new(&mut a, 1200);
    transfer(&mut a, &mut b, &mut now, &narrow, conn, 10_000);
    assert_eq!(a.iface.path_mtu(B_IP.into(), now), 1200);
    assert_eq!(a.iface.path_mtu(B_IP.into(), now + (PMTU_TIMEOUT - core::time::Duration::from_secs(1))), 1200);
    assert_eq!(a.iface.path_mtu(B_IP.into(), now + PMTU_TIMEOUT), 1500);
    a.iface.forget_path_mtu(B_IP.into());
    assert_eq!(a.iface.path_mtu(B_IP.into(), now), 1500);
}

/// Makes A send data that nobody acknowledges; returns the first frame
/// longer than 1000 bytes, without its Ethernet header.
fn unacknowledged_segment(a: &mut Host, ca: SocketHandle, now: Instant) -> Vec<u8> {
    let seen: Rc<RefCell<Option<Vec<u8>>>> = Rc::default();
    let s = seen.clone();
    a.set_filter(move |_, f| {
        if f.len() > 1000 {
            s.borrow_mut().get_or_insert_with(|| f[ETH_HEADER_LEN..].to_vec());
        }
        false
    });
    a.sockets.get_mut::<TcpSocket>(ca).send(&[7; 4000]).unwrap();
    a.poll(now);
    seen.borrow().clone().expect("a data segment was sent")
}

fn v4_in_flight() -> (Host, Instant, Vec<u8>) {
    let (mut a, mut b) = pair();
    let mut now = Instant::ZERO;
    let (ca, _) = connect(&mut a, &mut b, &mut now, B_IP.into(), 80);
    let seg = unacknowledged_segment(&mut a, ca, now);
    (a, now, seg)
}

#[test]
fn forged_or_stale_reports_are_ignored() {
    let (mut a, now, seg) = v4_in_flight();
    let a_mac = a.iface.mac_address();
    let total = usize::from(be16(&seg, 2));
    assert!(total > 1400);
    let send = |a: &mut Host, quote: &[u8], mtu: u16| {
        a.inject(frag_needed(a_mac, A_IP, quote, mtu));
        a.poll(now);
        a.iface.path_mtu(B_IP.into(), now)
    };

    assert_eq!(send(&mut a, &seg[..24], 1000), 1500, "too short to hold the sequence number");
    let mut bad = seg[..28].to_vec();
    bad[12] ^= 1;
    assert_eq!(send(&mut a, &bad, 1000), 1500, "source is not ours");
    let mut bad = seg[..28].to_vec();
    bad[19] ^= 1;
    assert_eq!(send(&mut a, &bad, 1000), 1500, "no connection to that destination");
    let mut bad = seg[..28].to_vec();
    bad[20] ^= 1;
    assert_eq!(send(&mut a, &bad, 1000), 1500, "no connection from that port");
    let mut bad = seg[..28].to_vec();
    bad[24] ^= 0x80;
    assert_eq!(send(&mut a, &bad, 1000), 1500, "sequence number out of the window");
    let mut bad = seg[..28].to_vec();
    bad[9] = PROTO_UDP;
    assert_eq!(send(&mut a, &bad, 1000), 1500, "no UDP socket on that port");
    // The packet must have been bigger than the MTU it exceeded, and the
    // MTU cannot raise the path's.
    assert_eq!(send(&mut a, &seg[..28], total as u16), 1500);
    assert_eq!(send(&mut a, &seg[..28], 1600), 1500);
    let mut bad = seg[..28].to_vec();
    bad[16..20].copy_from_slice(&[255; 4]);
    assert_eq!(send(&mut a, &bad, 1000), 1500, "not a host");
    // Addressed to someone else.
    a.inject(frag_needed(a_mac, Ipv4Addr::new(192, 168, 1, 77), &seg[..28], 1000));
    a.poll(now);
    assert_eq!(a.iface.path_mtu(B_IP.into(), now), 1500);

    // The real thing is believed.
    assert_eq!(send(&mut a, &seg[..28], 1000), 1000);
}

#[test]
fn a_tiny_mtu_is_raised_to_the_floor() {
    let (mut a, now, seg) = v4_in_flight();
    let a_mac = a.iface.mac_address();
    a.inject(frag_needed(a_mac, A_IP, &seg[..28], 68));
    a.poll(now);
    assert_eq!(a.iface.path_mtu(B_IP.into(), now), MIN_MTU_V4);
}

#[test]
fn a_router_that_reports_no_mtu_is_guessed_with_the_plateau_table() {
    let (mut a, now, seg) = v4_in_flight();
    let a_mac = a.iface.mac_address();
    let total = usize::from(be16(&seg, 2));
    a.inject(frag_needed(a_mac, A_IP, &seg[..28], 0));
    a.poll(now);
    assert_eq!(a.iface.path_mtu(B_IP.into(), now), plateau_below(total));
    assert!(a.iface.path_mtu(B_IP.into(), now) < total);
}

#[test]
fn udp_is_fragmented_to_the_path_mtu() {
    let (mut a, mut b) = pair();
    let mut now = Instant::ZERO;
    let narrow = Bottleneck::new(&mut a, 1000);
    let tx = a.sockets.add(UdpSocket::new(4, 4));
    let rx = b.sockets.add(UdpSocket::new(4, 4));
    a.sockets.get_mut::<UdpSocket>(tx).bind(5000).unwrap();
    b.sockets.get_mut::<UdpSocket>(rx).bind(6000).unwrap();
    let data: Vec<u8> = (0..1400u32).map(|i| i as u8).collect();
    // The first datagram goes out whole with DF and is lost.
    a.sockets.get_mut::<UdpSocket>(tx).send_to(&data, sa(B_IP, 6000)).unwrap();
    assert!(!run(&mut a, &mut b, &mut now, 50, |a, _| {
        narrow.deliver(a);
        false
    }));
    assert_eq!(narrow.sent.get(), 1);
    assert_eq!(a.iface.path_mtu(B_IP.into(), now), 1000);
    // The next is cut to fit and arrives.
    a.sockets.get_mut::<UdpSocket>(tx).send_to(&data, sa(B_IP, 6000)).unwrap();
    assert!(run(&mut a, &mut b, &mut now, 100, |_, b| b.sockets.get::<UdpSocket>(rx).can_recv()));
    let mut buf = [0; 2000];
    let (n, _) = b.sockets.get_mut::<UdpSocket>(rx).recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], &data[..]);
    assert_eq!(narrow.sent.get(), 1);
    assert!(narrow.longest.get() <= 1000);
}

#[test]
fn ipv6_packet_too_big_shrinks_tcp() {
    let (mut a, mut b, mut now) = pair6();
    let b_ll: IpAddr = b.iface.ipv6_link_local().unwrap().into();
    let conn = connect(&mut a, &mut b, &mut now, b_ll, 80);
    let narrow = Bottleneck::new(&mut a, 1300);
    assert_eq!(a.iface.path_mtu(b_ll, now), 1500);
    let took = transfer(&mut a, &mut b, &mut now, &narrow, conn, 30_000);
    assert_eq!(a.iface.path_mtu(b_ll, now), 1300);
    assert!(narrow.longest.get() <= 1300 && narrow.longest.get() > 1200, "{}", narrow.longest.get());
    assert!(took < core::time::Duration::from_millis(190), "{took:?}");
    assert_eq!(a.iface.path_mtu(B_IP.into(), now), 1500, "IPv4 is unaffected");
    assert_eq!(a.iface.path_mtu(b_ll, now + PMTU_TIMEOUT), 1500);
}

#[test]
fn ipv6_reports_are_validated_and_floored() {
    let (mut a, mut b, mut now) = pair6();
    let b_ll = b.iface.ipv6_link_local().unwrap();
    let a_ll = a.iface.ipv6_link_local().unwrap();
    let (ca, _) = connect(&mut a, &mut b, &mut now, b_ll.into(), 80);
    let seg = unacknowledged_segment(&mut a, ca, now);
    let a_mac = a.iface.mac_address();
    let send = |a: &mut Host, quote: &[u8], mtu: u32| {
        a.inject(too_big(a_mac, a_ll, quote, mtu));
        a.poll(now);
        a.iface.path_mtu(b_ll.into(), now)
    };
    assert_eq!(send(&mut a, &seg[..44], 1300), 1500, "too short to hold the sequence number");
    let mut bad = seg[..48].to_vec();
    bad[8] ^= 1;
    assert_eq!(send(&mut a, &bad, 1300), 1500, "source is not ours");
    let mut bad = seg[..48].to_vec();
    bad[24] ^= 1;
    assert_eq!(send(&mut a, &bad, 1300), 1500, "no such connection");
    let mut bad = seg[..48].to_vec();
    bad[44] ^= 0x80;
    assert_eq!(send(&mut a, &bad, 1300), 1500, "sequence number out of the window");
    let mut bad = seg[..48].to_vec();
    bad[6] = 0; // a hop-by-hop header would hide the transport header
    assert_eq!(send(&mut a, &bad, 1300), 1500);
    assert_eq!(send(&mut a, &seg[..48], 2000), 1500, "cannot raise");
    assert_eq!(send(&mut a, &seg[..48], 1600), 1500);
    // Below the IPv6 minimum is taken as the minimum.
    assert_eq!(send(&mut a, &seg[..48], 600), MIN_MTU_V6);
    assert_eq!(send(&mut a, &seg[..48], 1280), MIN_MTU_V6);
}
