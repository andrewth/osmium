//! Socket system calls against a simulated peer on a simulated link.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use osmium_boot::elf::Elf;
use osmium_fs::Errno;
use osmium_hal::net::{MacAddress, NetDevice, NetError};
use osmium_mm::addr::PhysAddr;
use osmium_mm::paging::MapFlags;
use osmium_net::{Config, Instant, Interface, SocketAddr, SocketAddrV4, SocketSet, TcpSocket, UdpSocket};

use crate::net::{NetStack, set_stack, stack};
use crate::{Outcome, Process, Sys, UserMemory, dispatch};

type Queue = Arc<Mutex<VecDeque<Vec<u8>>>>;

struct Port {
    mac: MacAddress,
    rx: Queue,
    tx: Queue,
}

impl NetDevice for Port {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        self.tx.lock().unwrap().push_back(frame.to_vec());
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        let f = self.rx.lock().unwrap().pop_front().ok_or(NetError::WouldBlock)?;
        buf[..f.len()].copy_from_slice(&f);
        Ok(f.len())
    }

    fn can_receive(&self) -> bool {
        !self.rx.lock().unwrap().is_empty()
    }

    fn can_transmit(&self) -> bool {
        true
    }
}

/// Plain bytes at `BASE`.
struct Flat(Mutex<Vec<u8>>);

const BASE: u64 = 0x1000;

impl UserMemory for Flat {
    fn root(&self) -> PhysAddr {
        PhysAddr(0)
    }

    fn read(&self, va: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let m = self.0.lock().unwrap();
        let off = va.checked_sub(BASE).ok_or(Errno::EFAULT)? as usize;
        buf.copy_from_slice(m.get(off..off + buf.len()).ok_or(Errno::EFAULT)?);
        Ok(())
    }

    fn write(&self, va: u64, data: &[u8]) -> Result<(), Errno> {
        let mut m = self.0.lock().unwrap();
        let off = va.checked_sub(BASE).ok_or(Errno::EFAULT)? as usize;
        m.get_mut(off..off + data.len()).ok_or(Errno::EFAULT)?.copy_from_slice(data);
        Ok(())
    }

    fn map_anon(&self, _: u64, _: u64, _: MapFlags) -> Result<(), Errno> {
        Err(Errno::ENOMEM)
    }

    fn unmap(&self, _: u64, _: u64) {}

    fn load_elf(&self, _: &Elf<'_>) -> Result<u64, Errno> {
        Err(Errno::ENOEXEC)
    }

    fn fork(&self) -> Result<Box<dyn UserMemory>, Errno> {
        Err(Errno::ENOMEM)
    }

    fn cow_fault(&self, _: u64) -> bool {
        false
    }
}

static NOW: AtomicU64 = AtomicU64::new(1_000_000);

fn now_ns() -> u64 {
    NOW.load(Ordering::Relaxed)
}

struct Peer {
    iface: Interface,
    dev: Port,
    sockets: SocketSet,
}

const US: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const THEM: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

fn config(address: Ipv4Addr) -> Option<Config> {
    Some(Config { address, prefix_len: 24, gateway: None, dns: None })
}

fn setup() -> (Arc<NetStack>, Peer) {
    let (ab, ba): (Queue, Queue) = Default::default();
    let ours = Port { mac: MacAddress([2, 0, 0, 0, 0, 1]), rx: ba.clone(), tx: ab.clone() };
    let theirs = Port { mac: MacAddress([2, 0, 0, 0, 0, 2]), rx: ab, tx: ba };
    let mut iface = Interface::new(&ours, 1);
    iface.set_config(config(US));
    let net = Arc::new(NetStack::new(iface, Box::new(ours), SocketSet::new(), now_ns));
    let mut piface = Interface::new(&theirs, 2);
    piface.set_config(config(THEM));
    set_stack(net.clone());
    (net, Peer { iface: piface, dev: theirs, sockets: SocketSet::new() })
}

/// Runs both ends for a few milliseconds of simulated time.
fn pump(net: &NetStack, peer: &mut Peer) {
    for _ in 0..20 {
        NOW.fetch_add(1_000_000, Ordering::Relaxed);
        net.poll();
        peer.iface.poll(Instant::from_nanos(now_ns()), &mut peer.dev, &mut peer.sockets);
    }
}

fn call(p: &Process, sys: Sys, args: &[u64]) -> i64 {
    let mut a = [0; 6];
    a[..args.len()].copy_from_slice(args);
    match dispatch(p, sys.number(), a) {
        Outcome::Return(v) => v,
        o => panic!("unexpected {o:?}"),
    }
}

fn err(e: Errno) -> i64 {
    -(e.0 as i64)
}

fn sockaddr(ip: Ipv4Addr, port: u16) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..2].copy_from_slice(&2u16.to_ne_bytes());
    b[2..4].copy_from_slice(&port.to_be_bytes());
    b[4..8].copy_from_slice(&ip.octets());
    b
}

fn parse(b: &[u8]) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::new(b[4], b[5], b[6], b[7]), u16::from_be_bytes([b[2], b[3]]))
}

const ADDR: u64 = BASE;
const LEN: u64 = BASE + 0x20;
const BUF: u64 = BASE + 0x100;
const STREAM_NB: u64 = 1 | 0o4000;
const DGRAM: u64 = 2;

fn put(p: &Process, va: u64, b: &[u8]) {
    p.memory().write(va, b).unwrap();
}

fn get(p: &Process, va: u64, n: usize) -> Vec<u8> {
    let mut v = alloc::vec![0; n];
    p.memory().read(va, &mut v).unwrap();
    v
}

fn connect_to(p: &Process, fd: u64, ip: Ipv4Addr, port: u16) -> i64 {
    put(p, ADDR, &sockaddr(ip, port));
    call(p, Sys::Connect, &[fd, ADDR, 16])
}

#[test]
fn sockets_over_a_simulated_link() {
    assert!(stack().is_none());
    let p = Process::new("sock", Flat(Mutex::new(alloc::vec![0; 0x4000])), 0);
    assert_eq!(call(&p, Sys::Socket, &[2, 1, 0]), err(Errno::EAFNOSUPPORT), "no stack yet");
    let (net, mut peer) = setup();

    assert_eq!(call(&p, Sys::Socket, &[1, 1, 0]), err(Errno::EAFNOSUPPORT));
    assert_eq!(call(&p, Sys::Socket, &[2, 3, 0]), err(Errno::EPROTOTYPE));
    assert_eq!(call(&p, Sys::Socket, &[2, 2, 6]), err(Errno::EPROTONOSUPPORT));
    assert_eq!(call(&p, Sys::Bind, &[9, ADDR, 16]), err(Errno::EBADF));

    // An echo server on the peer; a client with a non-blocking connect.
    let mut echo = TcpSocket::new(1024, 1024);
    echo.listen(7).unwrap();
    let echo = peer.sockets.add(echo);
    let fd = call(&p, Sys::Socket, &[2, STREAM_NB, 0]) as u64;
    assert_eq!(connect_to(&p, fd, THEM, 7), err(Errno::EINPROGRESS));
    assert_eq!(call(&p, Sys::Read, &[fd, BUF, 16]), err(Errno::EAGAIN));
    pump(&net, &mut peer);
    assert_eq!(connect_to(&p, fd, THEM, 7), err(Errno::EISCONN));
    assert_eq!(call(&p, Sys::Getsockopt, &[fd, 1, 4, BUF, LEN]), 0);
    assert_eq!(get(&p, BUF, 4), [0; 4], "SO_ERROR");
    put(&p, BUF, b"hello over TCP");
    assert_eq!(call(&p, Sys::Write, &[fd, BUF, 14]), 14);
    assert_eq!(call(&p, Sys::Read, &[fd, BUF, 64]), err(Errno::EAGAIN));
    pump(&net, &mut peer);
    let mut b = [0u8; 64];
    let n = peer.sockets.get_mut::<TcpSocket>(echo).recv(&mut b).unwrap();
    assert_eq!(&b[..n], b"hello over TCP");
    peer.sockets.get_mut::<TcpSocket>(echo).send(&b[..n]).unwrap();
    pump(&net, &mut peer);
    put(&p, LEN, &16u32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Recvfrom, &[fd, BUF, 64, 0, 0, 0]), 14);
    assert_eq!(get(&p, BUF, 14), b"hello over TCP");
    assert_eq!(call(&p, Sys::Getpeername, &[fd, ADDR, LEN]), 0);
    assert_eq!(parse(&get(&p, ADDR, 16)), SocketAddrV4::new(THEM, 7));
    assert_eq!(call(&p, Sys::Getsockname, &[fd, ADDR, LEN]), 0);
    assert_eq!(*parse(&get(&p, ADDR, 16)).ip(), US);
    assert_eq!(call(&p, Sys::Lseek, &[fd, 0, 0]), err(Errno::ESPIPE));

    // dup shares the socket, F_GETFL shows O_NONBLOCK, F_SETFL clears it.
    let dup = call(&p, Sys::Dup, &[fd]) as u64;
    assert_eq!(call(&p, Sys::Fcntl, &[dup, 3, 0]) & 0o4000, 0o4000);
    assert_eq!(call(&p, Sys::Fcntl, &[dup, 4, 0]), 0);
    assert_eq!(call(&p, Sys::Fcntl, &[fd, 3, 0]) & 0o4000, 0);
    assert_eq!(call(&p, Sys::Fcntl, &[fd, 4, 0o4000]), 0);

    // shutdown(SHUT_WR) sends a FIN; the peer closing ends our reads.
    assert_eq!(call(&p, Sys::Shutdown, &[fd, 1]), 0);
    pump(&net, &mut peer);
    assert_eq!(peer.sockets.get_mut::<TcpSocket>(echo).recv(&mut b), Ok(0));
    peer.sockets.get_mut::<TcpSocket>(echo).close();
    pump(&net, &mut peer);
    assert_eq!(call(&p, Sys::Read, &[fd, BUF, 64]), 0);
    assert_eq!(call(&p, Sys::Close, &[fd]), 0);
    assert_eq!(call(&p, Sys::Close, &[dup]), 0);
    pump(&net, &mut peer);

    // Refused: the peer has no listener on 9.
    let fd = call(&p, Sys::Socket, &[2, STREAM_NB, 0]) as u64;
    assert_eq!(connect_to(&p, fd, THEM, 9), err(Errno::EINPROGRESS));
    pump(&net, &mut peer);
    assert_eq!(call(&p, Sys::Read, &[fd, BUF, 4]), err(Errno::ECONNREFUSED));
    assert_eq!(call(&p, Sys::Close, &[fd]), 0);

    // A server: bind, listen, accept.
    let srv = call(&p, Sys::Socket, &[2, STREAM_NB, 0]) as u64;
    put(&p, ADDR, &sockaddr(Ipv4Addr::UNSPECIFIED, 8080));
    assert_eq!(call(&p, Sys::Bind, &[srv, ADDR, 16]), 0);
    assert_eq!(call(&p, Sys::Bind, &[srv, ADDR, 16]), err(Errno::EINVAL), "already bound");
    let other = call(&p, Sys::Socket, &[2, 2, 0]) as u64;
    assert_eq!(call(&p, Sys::Listen, &[other, 1]), err(Errno::EOPNOTSUPP));
    assert_eq!(call(&p, Sys::Listen, &[srv, 4]), 0);
    assert_eq!(call(&p, Sys::Accept, &[srv, 0, 0]), err(Errno::EAGAIN));
    let mut c = TcpSocket::new(1024, 1024);
    c.connect(SocketAddrV4::new(US, 8080), 0).unwrap();
    c.send(b"to the server").unwrap();
    let c = peer.sockets.add(c);
    pump(&net, &mut peer);
    put(&p, LEN, &16u32.to_ne_bytes());
    let conn = call(&p, Sys::Accept4, &[srv, ADDR, LEN, 0o4000]);
    assert!(conn >= 0, "accept: {conn}");
    let conn = conn as u64;
    assert_eq!(SocketAddr::V4(parse(&get(&p, ADDR, 16))), peer.sockets.get::<TcpSocket>(c).local_endpoint());
    assert_eq!(call(&p, Sys::Read, &[conn, BUF, 64]), 13);
    assert_eq!(get(&p, BUF, 13), b"to the server");
    put(&p, BUF, b"reply");
    assert_eq!(call(&p, Sys::Sendto, &[conn, BUF, 5, 0, 0, 0]), 5);
    pump(&net, &mut peer);
    let n = peer.sockets.get_mut::<TcpSocket>(c).recv(&mut b).unwrap();
    assert_eq!(&b[..n], b"reply");
    assert_eq!(call(&p, Sys::Accept, &[srv, 0, 0]), err(Errno::EAGAIN), "the next one waits");
    // Closing with the connection open sends a FIN; the listener goes away.
    assert_eq!(call(&p, Sys::Close, &[conn]), 0);
    assert_eq!(call(&p, Sys::Close, &[srv]), 0);
    pump(&net, &mut peer);
    assert_eq!(peer.sockets.get_mut::<TcpSocket>(c).recv(&mut b), Ok(0));

    // UDP: bind, receive with the sender's address, reply, auto-bind.
    let u = call(&p, Sys::Socket, &[2, DGRAM | 0o4000, 0]) as u64;
    put(&p, ADDR, &sockaddr(Ipv4Addr::UNSPECIFIED, 5000));
    assert_eq!(call(&p, Sys::Bind, &[u, ADDR, 16]), 0);
    let dup = call(&p, Sys::Socket, &[2, DGRAM, 0]) as u64;
    assert_eq!(call(&p, Sys::Bind, &[dup, ADDR, 16]), err(Errno::EADDRINUSE));
    assert_eq!(call(&p, Sys::Recvfrom, &[u, BUF, 64, 0, 0, 0]), err(Errno::EAGAIN));
    let mut s = UdpSocket::new(4, 4);
    s.bind(4000).unwrap();
    s.send_to(b"datagram", SocketAddrV4::new(US, 5000)).unwrap();
    let s = peer.sockets.add(s);
    pump(&net, &mut peer);
    put(&p, LEN, &16u32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Recvfrom, &[u, BUF, 64, 0, ADDR, LEN]), 8);
    assert_eq!(get(&p, BUF, 8), b"datagram");
    assert_eq!(parse(&get(&p, ADDR, 16)), SocketAddrV4::new(THEM, 4000));
    put(&p, BUF, b"pong");
    put(&p, ADDR, &sockaddr(THEM, 4000));
    assert_eq!(call(&p, Sys::Sendto, &[u, BUF, 4, 0, ADDR, 16]), 4);
    assert_eq!(call(&p, Sys::Sendto, &[dup, BUF, 4, 0, 0, 0]), err(Errno::EDESTADDRREQ));
    assert_eq!(call(&p, Sys::Sendto, &[dup, BUF, 4, 0, ADDR, 16]), 4, "auto-binds an ephemeral port");
    pump(&net, &mut peer);
    let (n, from) = peer.sockets.get_mut::<UdpSocket>(s).recv_from(&mut b).unwrap();
    assert_eq!((&b[..n], from), (&b"pong"[..], SocketAddr::V4(SocketAddrV4::new(US, 5000))));
    let (_, from) = peer.sockets.get_mut::<UdpSocket>(s).recv_from(&mut b).unwrap();
    assert_ne!(from.port(), 0);
    // A connected datagram socket reads and writes plainly.
    assert_eq!(connect_to(&p, dup, THEM, 4000), 0);
    assert_eq!(call(&p, Sys::Write, &[dup, BUF, 4]), 4);
    assert_eq!(call(&p, Sys::Getpeername, &[dup, ADDR, LEN]), 0);
    assert_eq!(call(&p, Sys::Setsockopt, &[dup, 1, 2, BUF, 4]), 0);
    assert_eq!(call(&p, Sys::Setsockopt, &[dup, 1, 999, BUF, 4]), err(Errno::ENOPROTOOPT));
    assert_eq!(call(&p, Sys::Getsockopt, &[dup, 1, 3, BUF, LEN]), 0);
    assert_eq!(get(&p, BUF, 4), 2i32.to_ne_bytes());
    let tv: Vec<u8> = [1u64, 500_000].iter().flat_map(|v| v.to_ne_bytes()).collect();
    put(&p, BUF, &tv);
    assert_eq!(call(&p, Sys::Setsockopt, &[dup, 1, 20, BUF, 16]), 0, "SO_RCVTIMEO");
    assert_eq!(call(&p, Sys::Setsockopt, &[dup, 1, 20, BUF, 8]), err(Errno::EINVAL));
    assert_eq!(call(&p, Sys::Close, &[u]), 0);
    assert_eq!(call(&p, Sys::Close, &[dup]), 0);
    pump(&net, &mut peer);
    assert_eq!(call(&p, Sys::Bind, &[u, ADDR, 16]), err(Errno::EBADF));
}
