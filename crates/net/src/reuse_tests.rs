//! `SO_REUSEADDR` and `SO_REUSEPORT`: bind conflicts and delivery.

use alloc::vec::Vec;

use crate::testing::{A_IP, B_IP, Host, pair, run, sa};
use crate::{BindProtocol, Error, Instant, ReuseOptions, SocketHandle, TcpSocket, TcpState, UdpSocket};

const ADDR: ReuseOptions = ReuseOptions { addr: true, port: false, owner: 0 };
const PORT: ReuseOptions = ReuseOptions { addr: false, port: true, owner: 0 };

fn udp(h: &mut Host, reuse: ReuseOptions) -> SocketHandle {
    let mut s = UdpSocket::new(64, 4);
    s.set_reuse(reuse);
    h.sockets.add(s)
}

fn tcp(h: &mut Host, reuse: ReuseOptions) -> SocketHandle {
    let mut s = TcpSocket::new(4096, 4096);
    s.set_reuse(reuse);
    h.sockets.add(s)
}

fn any(port: u16) -> core::net::SocketAddr {
    sa(core::net::Ipv4Addr::UNSPECIFIED, port)
}

#[test]
fn udp_conflicts_without_options() {
    let (mut a, _) = pair();
    let h1 = udp(&mut a, ReuseOptions::NONE);
    let h2 = udp(&mut a, ReuseOptions::NONE);
    a.sockets.bind_udp(h1, any(5000)).unwrap();
    assert_eq!(a.sockets.bind_udp(h2, any(5000)), Err(Error::AddressInUse));
    // The wildcard overlaps every specific address, and the reverse.
    assert_eq!(a.sockets.bind_udp(h2, sa(A_IP, 5000)), Err(Error::AddressInUse));
    a.sockets.bind_udp(h2, sa(A_IP, 5001)).unwrap();
    let h3 = udp(&mut a, ReuseOptions::NONE);
    assert_eq!(a.sockets.bind_udp(h3, any(5001)), Err(Error::AddressInUse));
    // Another port is free, and port 0 is not a port.
    a.sockets.bind_udp(h3, any(5002)).unwrap();
    assert_eq!(a.sockets.check_bind(BindProtocol::Udp, any(0), ReuseOptions::NONE, None), Err(Error::InvalidAddress));
}

#[test]
fn udp_reuseaddr_needs_both_and_prefers_the_specific_address() {
    let (mut a, mut b) = pair();
    let wild = udp(&mut b, ADDR);
    let plain = udp(&mut b, ReuseOptions::NONE);
    let spec = udp(&mut b, ADDR);
    b.sockets.bind_udp(wild, any(5000)).unwrap();
    // One side without the option is not enough.
    assert_eq!(b.sockets.bind_udp(plain, sa(B_IP, 5000)), Err(Error::AddressInUse));
    b.sockets.bind_udp(spec, sa(B_IP, 5000)).unwrap();
    // Both socket pairs may even share one address.
    let twin = udp(&mut b, ADDR);
    b.sockets.bind_udp(twin, sa(B_IP, 5000)).unwrap();

    let tx = udp(&mut a, ReuseOptions::NONE);
    a.sockets.bind_udp(tx, any(6000)).unwrap();
    a.sockets.get_mut::<UdpSocket>(tx).send_to(b"x", sa(B_IP, 5000)).unwrap();
    let mut now = Instant::ZERO;
    assert!(run(&mut a, &mut b, &mut now, 100, |_, b| b.sockets.get::<UdpSocket>(spec).can_recv()));
    // Unicast went to one socket: the specific one, not the wildcard.
    assert!(!b.sockets.get::<UdpSocket>(wild).can_recv());
    assert!(!b.sockets.get::<UdpSocket>(twin).can_recv());
}

#[test]
fn udp_reuseport_needs_the_same_owner_and_both_sides() {
    let (mut a, _) = pair();
    let h1 = udp(&mut a, ReuseOptions { owner: 7, ..PORT });
    let same = udp(&mut a, ReuseOptions { owner: 7, ..PORT });
    let other = udp(&mut a, ReuseOptions { owner: 8, ..PORT });
    let plain = udp(&mut a, ReuseOptions::NONE);
    let only_addr = udp(&mut a, ADDR);
    a.sockets.bind_udp(h1, any(5000)).unwrap();
    a.sockets.bind_udp(same, any(5000)).unwrap();
    assert_eq!(a.sockets.bind_udp(other, any(5000)), Err(Error::AddressInUse));
    assert_eq!(a.sockets.bind_udp(plain, any(5000)), Err(Error::AddressInUse));
    assert_eq!(a.sockets.bind_udp(only_addr, any(5000)), Err(Error::AddressInUse));
    // Closing one frees nothing while the other holds the port.
    a.sockets.get_mut::<UdpSocket>(h1).close();
    assert_eq!(a.sockets.bind_udp(plain, any(5000)), Err(Error::AddressInUse));
    a.sockets.get_mut::<UdpSocket>(same).close();
    a.sockets.bind_udp(plain, any(5000)).unwrap();
}

#[test]
fn udp_reuseport_spreads_flows_and_keeps_each_on_one_socket() {
    let (mut a, mut b) = pair();
    let rx: Vec<_> = (0..3).map(|_| udp(&mut b, PORT)).collect();
    for &h in &rx {
        b.sockets.bind_udp(h, any(5000)).unwrap();
    }
    let senders: Vec<_> = (0..24)
        .map(|i| {
            let h = udp(&mut a, ReuseOptions::NONE);
            a.sockets.bind_udp(h, sa(A_IP, 6000 + i)).unwrap();
            h
        })
        .collect();
    let mut now = Instant::ZERO;
    let mut owner = [None; 24];
    for round in 0..2 {
        for &h in &senders {
            a.sockets.get_mut::<UdpSocket>(h).send_to(&[round], sa(B_IP, 5000)).unwrap();
        }
        run(&mut a, &mut b, &mut now, 100, |_, _| false);
        for (i, &h) in rx.iter().enumerate() {
            let mut buf = [0; 4];
            while let Ok((_, from)) = b.sockets.get_mut::<UdpSocket>(h).recv_from(&mut buf) {
                let slot = &mut owner[usize::from(from.port() - 6000)];
                // Both datagrams of a flow reach one socket.
                assert!(slot.is_none_or(|o| o == i), "flow moved");
                *slot = Some(i);
            }
        }
    }
    assert!(owner.iter().all(Option::is_some), "every datagram delivered");
    for i in 0..3 {
        assert!(owner.contains(&Some(i)), "socket {i} got nothing");
    }
}

#[test]
fn udp_broadcast_reaches_every_sharing_socket() {
    let (mut a, mut b) = pair();
    let rx: Vec<_> = (0..2).map(|_| udp(&mut b, ADDR)).collect();
    for &h in &rx {
        b.sockets.bind_udp(h, any(5000)).unwrap();
    }
    let tx = udp(&mut a, ReuseOptions::NONE);
    a.sockets.bind_udp(tx, any(6000)).unwrap();
    a.sockets.get_mut::<UdpSocket>(tx).send_to(b"x", sa(core::net::Ipv4Addr::BROADCAST, 5000)).unwrap();
    let mut now = Instant::ZERO;
    assert!(run(&mut a, &mut b, &mut now, 100, |_, b| rx.iter().all(|&h| b.sockets.get::<UdpSocket>(h).can_recv())));
}

#[test]
fn tcp_listeners_conflict_unless_reuseport() {
    let (mut a, _) = pair();
    let l1 = tcp(&mut a, ADDR);
    let l2 = tcp(&mut a, ADDR);
    a.sockets.listen_tcp(l1, any(8000)).unwrap();
    // SO_REUSEADDR does not let two sockets listen on one address, nor a
    // specific address under a wildcard listener.
    assert_eq!(a.sockets.listen_tcp(l2, any(8000)), Err(Error::AddressInUse));
    assert_eq!(a.sockets.listen_tcp(l2, sa(A_IP, 8000)), Err(Error::AddressInUse));
    // UDP and TCP ports are separate.
    let u = udp(&mut a, ReuseOptions::NONE);
    a.sockets.bind_udp(u, any(8000)).unwrap();

    let p1 = tcp(&mut a, ReuseOptions { owner: 1, ..PORT });
    let p2 = tcp(&mut a, ReuseOptions { owner: 1, ..PORT });
    let p3 = tcp(&mut a, ReuseOptions { owner: 2, ..PORT });
    a.sockets.listen_tcp(p1, any(9000)).unwrap();
    a.sockets.listen_tcp(p2, any(9000)).unwrap();
    assert_eq!(a.sockets.listen_tcp(p3, any(9000)), Err(Error::AddressInUse));
}

/// Connects `client` (on `a`, from `port`) to port 8000 of `b` and closes
/// it first so that it ends up in TIME-WAIT.
fn leave_time_wait(a: &mut Host, b: &mut Host, client: SocketHandle, server: SocketHandle, port: u16) {
    a.sockets.get_mut::<TcpSocket>(client).connect(sa(B_IP, 8000), port).unwrap();
    let mut now = Instant::ZERO;
    assert!(run(a, b, &mut now, 500, |a, b| {
        a.sockets.get::<TcpSocket>(client).state() == TcpState::Established
            && b.sockets.get::<TcpSocket>(server).state() == TcpState::Established
    }));
    a.sockets.get_mut::<TcpSocket>(client).close();
    assert!(run(a, b, &mut now, 500, |_, b| b.sockets.get::<TcpSocket>(server).state() == TcpState::CloseWait));
    b.sockets.get_mut::<TcpSocket>(server).close();
    assert!(run(a, b, &mut now, 500, |a, _| a.sockets.get::<TcpSocket>(client).state() == TcpState::TimeWait));
}

#[test]
fn bind_over_time_wait_needs_reuseaddr_on_both() {
    for (old, new, ok) in [(ADDR, ADDR, true), (ReuseOptions::NONE, ADDR, false), (ADDR, ReuseOptions::NONE, false)] {
        let (mut a, mut b) = pair();
        let server = tcp(&mut b, ReuseOptions::NONE);
        b.sockets.get_mut::<TcpSocket>(server).listen(8000).unwrap();
        let client = tcp(&mut a, old);
        leave_time_wait(&mut a, &mut b, client, server, 9000);
        let fresh = tcp(&mut a, new);
        let got = a.sockets.listen_tcp(fresh, sa(A_IP, 9000));
        assert_eq!(got.is_ok(), ok, "old {old:?}, new {new:?}");
        if !ok {
            assert_eq!(got, Err(Error::AddressInUse));
        }
    }
}

#[test]
fn a_restarted_server_binds_over_its_old_connections() {
    let (mut a, mut b) = pair();
    // The first server accepts a client and is still connected.
    let old = tcp(&mut b, ADDR);
    b.sockets.listen_tcp(old, any(8000)).unwrap();
    let client = tcp(&mut a, ReuseOptions::NONE);
    a.sockets.get_mut::<TcpSocket>(client).connect(sa(B_IP, 8000), 0).unwrap();
    let mut now = Instant::ZERO;
    assert!(run(&mut a, &mut b, &mut now, 500, |_, b| b.sockets.get::<TcpSocket>(old).state() == TcpState::Established));
    // The connection holds the port, but a new listener with SO_REUSEADDR
    // may take it (and one without may not).
    let fresh = tcp(&mut b, ADDR);
    b.sockets.listen_tcp(fresh, any(8000)).unwrap();
    let plain = tcp(&mut b, ReuseOptions::NONE);
    assert_eq!(b.sockets.listen_tcp(plain, any(8000)), Err(Error::AddressInUse));
}

#[test]
fn tcp_reuseport_spreads_connections_over_groups() {
    let (mut a, mut b) = pair();
    let opts = ReuseOptions { owner: 3, ..PORT };
    // Two server sockets, each with a backlog of 4 listeners.
    let groups: Vec<Vec<SocketHandle>> = (1..=2)
        .map(|g| {
            (0..4)
                .map(|_| {
                    let mut s = TcpSocket::new(4096, 4096);
                    s.set_reuse(opts);
                    s.set_reuse_group(g);
                    let h = b.sockets.add(s);
                    b.sockets.listen_tcp(h, any(8000)).unwrap();
                    h
                })
                .collect()
        })
        .collect();
    let clients: Vec<_> = (0..6)
        .map(|i| {
            let c = tcp(&mut a, ReuseOptions::NONE);
            a.sockets.get_mut::<TcpSocket>(c).connect(sa(B_IP, 8000), 7000 + i * 13).unwrap();
            c
        })
        .collect();
    let mut now = Instant::ZERO;
    let done = |a: &mut Host| clients.iter().all(|&c| a.sockets.get::<TcpSocket>(c).state() == TcpState::Established);
    assert!(run(&mut a, &mut b, &mut now, 1000, |a, _| done(a)));
    let per: Vec<usize> = groups
        .iter()
        .map(|g| g.iter().filter(|&&h| b.sockets.get::<TcpSocket>(h).state() == TcpState::Established).count())
        .collect();
    assert_eq!(per.iter().sum::<usize>(), 6);
    assert!(per.iter().all(|&n| n > 0), "both groups got connections: {per:?}");
}
