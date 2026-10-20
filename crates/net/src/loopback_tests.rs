//! Delivery to 127.0.0.0/8 inside the interface, with no device.

use alloc::vec;

use crate::testing::{Host, link, pair};
use crate::{Instant, Ipv4Addr, SocketAddrV4, TcpSocket, TcpState, UdpSocket};

const LO: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

fn spin(h: &mut Host, now: &mut Instant, mut done: impl FnMut(&mut Host) -> bool) {
    for _ in 0..200 {
        h.poll(*now);
        if done(h) {
            return;
        }
        *now = Instant::from_millis(now.as_millis() + 1);
    }
    panic!("timed out");
}

#[test]
fn udp_loops_back_even_unconfigured() {
    let (mut a, _b) = link();
    assert!(a.iface.config().is_none());
    let rx = a.sockets.add(UdpSocket::new(4, 4));
    let tx = a.sockets.add(UdpSocket::new(4, 4));
    a.sockets.get_mut::<UdpSocket>(rx).bind(7000).unwrap();
    a.sockets.get_mut::<UdpSocket>(tx).bind(7001).unwrap();
    a.sockets.get_mut::<UdpSocket>(tx).send_to(b"hi", SocketAddrV4::new(Ipv4Addr::new(127, 1, 2, 3), 7000)).unwrap();
    let mut now = Instant::ZERO;
    spin(&mut a, &mut now, |h| h.sockets.get::<UdpSocket>(rx).can_recv());
    let mut buf = [0; 8];
    let (n, from) = a.sockets.get::<UdpSocket>(rx).peek_from(&mut buf).unwrap();
    assert_eq!((&buf[..n], from.port()), (&b"hi"[..], 7001));
    assert!(from.ip().is_loopback());
    // A peek leaves it queued.
    assert!(a.sockets.get_mut::<UdpSocket>(rx).recv_from(&mut buf).is_ok());
    assert!(!a.sockets.get::<UdpSocket>(rx).can_recv());
}

#[test]
fn tcp_loops_back_and_peeks() {
    let (mut a, _b) = pair();
    let l = a.sockets.add(TcpSocket::new(4096, 4096));
    a.sockets.get_mut::<TcpSocket>(l).listen(8000).unwrap();
    let c = a.sockets.add(TcpSocket::new(4096, 4096));
    a.sockets.get_mut::<TcpSocket>(c).connect(SocketAddrV4::new(LO, 8000), 0).unwrap();
    let mut now = Instant::ZERO;
    spin(&mut a, &mut now, |h| {
        h.sockets.get::<TcpSocket>(c).state() == TcpState::Established
            && h.sockets.get::<TcpSocket>(l).state() == TcpState::Established
    });
    a.sockets.get_mut::<TcpSocket>(c).send(b"hello").unwrap();
    spin(&mut a, &mut now, |h| h.sockets.get::<TcpSocket>(l).can_recv());
    let mut buf = vec![0; 16];
    assert_eq!(a.sockets.get::<TcpSocket>(l).peek(&mut buf), Ok(5));
    assert_eq!(a.sockets.get_mut::<TcpSocket>(l).recv(&mut buf), Ok(5));
    assert_eq!(&buf[..5], b"hello");
}
