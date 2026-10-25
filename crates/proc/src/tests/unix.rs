#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! `AF_UNIX` sockets: names in the file system and abstract names, streams
//! and datagrams, and file descriptors and credentials in ancillary data.

use std::sync::Mutex as StdMutex;
use std::vec;

use super::*;
use crate::{MAX_IN_FLIGHT, in_flight};

const STREAM: u64 = 1;
const DGRAM: u64 = 2;
const NONBLOCK: u64 = 0o4000;
const SOL_SOCKET: u64 = 1;
const SO_PASSCRED: u64 = 16;
const SO_PEERCRED: u64 = 17;
const MSG_PEEK: u64 = 2;
const MSG_CTRUNC: u32 = 8;

const ADDR: u64 = DATA + 0x100;
const LEN: u64 = DATA + 0x180;
const SV: u64 = DATA + 0x1c0;
const MSG: u64 = DATA + 0x200;
const IOV: u64 = DATA + 0x300;
const CTL: u64 = DATA + 0x400;
const BUF: u64 = DATA + 0x800;

/// Tests that count files in flight share a global counter.
static SERIAL: StdMutex<()> = StdMutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn err(e: Errno) -> i64 {
    -i64::from(e.0)
}

fn sockaddr(name: &[u8], abstract_name: bool) -> Vec<u8> {
    let mut v = 1u16.to_ne_bytes().to_vec();
    if abstract_name {
        v.push(0);
        v.extend_from_slice(name);
    } else {
        v.extend_from_slice(name);
        v.push(0);
    }
    v
}

fn socket(p: &Process, ty: u64) -> u64 {
    let r = call(p, Sys::Socket, &[1, ty, 0]);
    assert!(r >= 0, "socket: {r}");
    r as u64
}

fn bind(p: &Process, fd: u64, addr: &[u8]) -> i64 {
    put(p, ADDR, addr);
    call(p, Sys::Bind, &[fd, ADDR, addr.len() as u64])
}

fn connect(p: &Process, fd: u64, addr: &[u8]) -> i64 {
    put(p, ADDR, addr);
    call(p, Sys::Connect, &[fd, ADDR, addr.len() as u64])
}

/// `getsockname` or `getpeername`: the address bytes and the length reported.
fn name_of(p: &Process, sys: Sys, fd: u64) -> (i64, Vec<u8>, u32) {
    put(p, LEN, &64u32.to_ne_bytes());
    let r = call(p, sys, &[fd, ADDR, LEN]);
    let len = u32::from_ne_bytes(get(p, LEN, 4).try_into().unwrap());
    (r, get(p, ADDR, (len as usize).min(64)), len)
}

fn write(p: &Process, fd: u64, data: &[u8]) -> i64 {
    put(p, BUF, data);
    call(p, Sys::Write, &[fd, BUF, data.len() as u64])
}

fn read(p: &Process, fd: u64, max: u64) -> Result<Vec<u8>, i64> {
    let r = call(p, Sys::Read, &[fd, BUF, max]);
    if r < 0 { Err(r) } else { Ok(get(p, BUF, r as usize)) }
}

/// A `msghdr` over one buffer, with `name` as its address and `control` bytes
/// of ancillary data at `CTL`.
fn msghdr(p: &Process, name: u64, namelen: u32, len: u64, controllen: u64) {
    let mut v = vec![0u8; 56];
    v[..8].copy_from_slice(&name.to_ne_bytes());
    v[8..12].copy_from_slice(&namelen.to_ne_bytes());
    v[16..24].copy_from_slice(&IOV.to_ne_bytes());
    v[24..32].copy_from_slice(&1u64.to_ne_bytes());
    v[32..40].copy_from_slice(&CTL.to_ne_bytes());
    v[40..48].copy_from_slice(&controllen.to_ne_bytes());
    put(p, MSG, &v);
    let mut io = BUF.to_ne_bytes().to_vec();
    io.extend(len.to_ne_bytes());
    put(p, IOV, &io);
}

fn cmsg(level: i32, kind: i32, payload: &[u8]) -> Vec<u8> {
    let mut v = ((16 + payload.len()) as u64).to_ne_bytes().to_vec();
    v.extend(level.to_ne_bytes());
    v.extend(kind.to_ne_bytes());
    v.extend_from_slice(payload);
    while v.len() % 8 != 0 {
        v.push(0);
    }
    v
}

fn rights(fds: &[i32]) -> Vec<u8> {
    cmsg(1, 1, &fds.iter().flat_map(|f| f.to_ne_bytes()).collect::<Vec<_>>())
}

/// `sendmsg` of `data` with `control` as ancillary data.
fn sendmsg(p: &Process, fd: u64, data: &[u8], control: &[u8]) -> i64 {
    put(p, BUF, data);
    put(p, CTL, control);
    msghdr(p, 0, 0, data.len() as u64, control.len() as u64);
    call(p, Sys::Sendmsg, &[fd, MSG, 0])
}

struct Got {
    data: Vec<u8>,
    /// Received `(level, type, payload)`.
    cmsgs: Vec<(i32, i32, Vec<u8>)>,
    flags: u32,
}

impl Got {
    fn fds(&self) -> Vec<i32> {
        self.cmsgs
            .iter()
            .filter(|c| (c.0, c.1) == (1, 1))
            .flat_map(|c| c.2.chunks(4).map(|b| i32::from_ne_bytes(b.try_into().unwrap())))
            .collect()
    }
}

fn recvmsg(p: &Process, fd: u64, max: u64, controllen: u64, flags: u64) -> Result<Got, i64> {
    put(p, CTL, &[0; 256]);
    msghdr(p, 0, 0, max, controllen);
    let r = call(p, Sys::Recvmsg, &[fd, MSG, flags]);
    if r < 0 {
        return Err(r);
    }
    let data = get(p, BUF, r as usize);
    let used = u64::from_ne_bytes(get(p, MSG + 40, 8).try_into().unwrap()) as usize;
    let flags = u32::from_ne_bytes(get(p, MSG + 48, 4).try_into().unwrap());
    let raw = get(p, CTL, used);
    let mut cmsgs = Vec::new();
    let mut off = 0;
    while off + 16 <= raw.len() {
        let len = u64::from_ne_bytes(raw[off..off + 8].try_into().unwrap()) as usize;
        let level = i32::from_ne_bytes(raw[off + 8..off + 12].try_into().unwrap());
        let kind = i32::from_ne_bytes(raw[off + 12..off + 16].try_into().unwrap());
        cmsgs.push((level, kind, raw[off + 16..off + len].to_vec()));
        off += (len + 7) & !7;
    }
    Ok(Got { data, cmsgs, flags })
}

fn pair(p: &Process, ty: u64) -> (u64, u64) {
    assert_eq!(call(p, Sys::Socketpair, &[1, ty, 0, SV]), 0);
    let b = get(p, SV, 8);
    (u32::from_ne_bytes(b[..4].try_into().unwrap()) as u64, u32::from_ne_bytes(b[4..].try_into().unwrap()) as u64)
}

fn pipe(p: &Process) -> (i32, i32) {
    assert_eq!(call(p, Sys::Pipe2, &[SV, 0]), 0);
    let b = get(p, SV, 8);
    (i32::from_ne_bytes(b[..4].try_into().unwrap()), i32::from_ne_bytes(b[4..].try_into().unwrap()))
}

fn close(p: &Process, fd: u64) {
    assert_eq!(call(p, Sys::Close, &[fd]), 0);
}

#[test]
fn a_stream_connects_to_a_path_and_is_accepted() {
    let (p, _) = process("unix-path");
    let path = sockaddr(b"/tmp/stream.sock", false);
    let server = socket(&p, STREAM);
    assert_eq!(call(&p, Sys::Listen, &[server, 4]), err(Errno::EINVAL), "not bound yet");
    assert_eq!(bind(&p, server, &path), 0);
    assert_eq!(bind(&p, server, &sockaddr(b"/tmp/other.sock", false)), err(Errno::EINVAL), "bound twice");
    let st = crate::vfs().unwrap().stat("/tmp/stream.sock", true).unwrap();
    assert_eq!(st.kind, osmium_fs::FileKind::Socket, "bind makes a socket node");
    let other = socket(&p, STREAM);
    assert_eq!(bind(&p, other, &path), err(Errno::EADDRINUSE));
    close(&p, other);

    assert_eq!(call(&p, Sys::Listen, &[server, 4]), 0);
    let client = socket(&p, STREAM);
    assert_eq!(connect(&p, client, &path), 0, "connect does not wait for accept");
    let conn = call(&p, Sys::Accept, &[server, 0, 0]);
    assert!(conn >= 0, "{conn}");
}

#[test]
fn data_flows_both_ways_between_a_client_and_the_accepted_socket() {
    let (p, _) = process("unix-flow");
    let path = sockaddr(b"/tmp/flow.sock", false);
    let server = socket(&p, STREAM | NONBLOCK);
    assert_eq!(bind(&p, server, &path), 0);
    assert_eq!(call(&p, Sys::Accept, &[server, 0, 0]), err(Errno::EINVAL), "not listening");
    assert_eq!(call(&p, Sys::Listen, &[server, 4]), 0);
    assert_eq!(call(&p, Sys::Accept, &[server, 0, 0]), err(Errno::EAGAIN), "nothing waiting");
    let client = socket(&p, STREAM);
    assert_eq!(connect(&p, client, &path), 0);
    put(&p, LEN, &64u32.to_ne_bytes());
    let conn = call(&p, Sys::Accept, &[server, ADDR, LEN]);
    assert!(conn >= 0, "{conn}");
    assert_eq!(u32::from_ne_bytes(get(&p, LEN, 4).try_into().unwrap()), 2, "the client never bound");
    let conn = conn as u64;
    assert_eq!(write(&p, client, b"request"), 7);
    assert_eq!(read(&p, conn, 64).unwrap(), b"request");
    assert_eq!(write(&p, conn, b"reply"), 5);
    assert_eq!(read(&p, client, 64).unwrap(), b"reply");

    // The accepted socket is named like the listener; the client is unnamed.
    let (r, name, len) = name_of(&p, Sys::Getsockname, conn);
    assert_eq!((r, len), (0, 2 + 14 + 1));
    assert_eq!(&name[2..16], b"/tmp/flow.sock");
    let (r, name, _) = name_of(&p, Sys::Getpeername, client);
    assert_eq!(r, 0);
    assert_eq!(&name[2..16], b"/tmp/flow.sock");
    let (r, _, len) = name_of(&p, Sys::Getpeername, conn);
    assert_eq!((r, len), (0, 2), "the client never bound");

    // Closing the client ends the stream.
    close(&p, client);
    assert_eq!(read(&p, conn, 64).unwrap(), b"");
    assert_eq!(write(&p, conn, b"x"), err(Errno::EPIPE));
}

#[test]
fn connect_failures() {
    let (p, _) = process("unix-refused");
    let c = socket(&p, STREAM);
    assert_eq!(connect(&p, c, &sockaddr(b"/tmp/missing.sock", false)), err(Errno::ENOENT));
    assert_eq!(connect(&p, c, &sockaddr(b"/hello.txt", false)), err(Errno::ECONNREFUSED), "not a socket");
    assert_eq!(connect(&p, c, &sockaddr(b"nobody", true)), err(Errno::ECONNREFUSED));
    // A bound socket that does not listen refuses; one that is gone does too.
    let s = socket(&p, STREAM);
    assert_eq!(bind(&p, s, &sockaddr(b"/tmp/idle.sock", false)), 0);
    assert_eq!(connect(&p, c, &sockaddr(b"/tmp/idle.sock", false)), err(Errno::ECONNREFUSED));
    close(&p, s);
    assert_eq!(connect(&p, c, &sockaddr(b"/tmp/idle.sock", false)), err(Errno::ECONNREFUSED));
    // The name is still taken by the file, as on Linux.
    let s = socket(&p, STREAM);
    assert_eq!(bind(&p, s, &sockaddr(b"/tmp/idle.sock", false)), err(Errno::EADDRINUSE));
    crate::vfs().unwrap().unlink("/tmp/idle.sock").unwrap();
    assert_eq!(bind(&p, s, &sockaddr(b"/tmp/idle.sock", false)), 0, "free once unlinked");
    // Types must match, and sizes are checked.
    let d = socket(&p, DGRAM);
    assert_eq!(call(&p, Sys::Listen, &[s, 1]), 0);
    assert_eq!(connect(&p, d, &sockaddr(b"/tmp/idle.sock", false)), err(Errno::EPROTOTYPE));
    assert_eq!(connect(&p, c, &[1, 0]), err(Errno::EINVAL), "no name");
    assert_eq!(connect(&p, c, &[2, 0, 0, 0]), err(Errno::EAFNOSUPPORT));
    assert_eq!(bind(&p, d, &[1; 200]), err(Errno::EINVAL), "too long");
    // Listening twice and connecting a listener.
    assert_eq!(connect(&p, s, &sockaddr(b"/tmp/idle.sock", false)), err(Errno::EINVAL));
    assert_eq!(call(&p, Sys::Socket, &[1, 5, 0]), err(Errno::EPROTOTYPE));
}

#[test]
fn a_full_backlog_blocks_or_fails_without_waiting() {
    let (p, _) = process("unix-backlog");
    let name = sockaddr(b"backlog", true);
    let s = socket(&p, STREAM);
    assert_eq!(bind(&p, s, &name), 0);
    assert_eq!(call(&p, Sys::Listen, &[s, 1]), 0);
    let first = socket(&p, STREAM | NONBLOCK);
    assert_eq!(connect(&p, first, &name), 0);
    let second = socket(&p, STREAM | NONBLOCK);
    assert_eq!(connect(&p, second, &name), err(Errno::EAGAIN));
    assert!(call(&p, Sys::Accept, &[s, 0, 0]) >= 0);
    assert_eq!(connect(&p, second, &name), 0, "room again");
}

#[test]
fn abstract_names_and_autobind() {
    let (p, _) = process("unix-abstract");
    let s = socket(&p, STREAM);
    let name = sockaddr(b"osmium-test", true);
    assert_eq!(bind(&p, s, &name), 0);
    let (r, got, len) = name_of(&p, Sys::Getsockname, s);
    assert_eq!((r, len as usize), (0, name.len()));
    assert_eq!(got, name);
    let t = socket(&p, STREAM);
    assert_eq!(bind(&p, t, &name), err(Errno::EADDRINUSE));
    // A name of different length is a different name.
    assert_eq!(bind(&p, t, &sockaddr(b"osmium-tes", true)), 0);
    assert_eq!(call(&p, Sys::Listen, &[s, 1]), 0);
    let c = socket(&p, STREAM);
    assert_eq!(connect(&p, c, &name), 0);
    // Closing frees the name.
    close(&p, s);
    assert_eq!(connect(&p, socket(&p, STREAM), &name), err(Errno::ECONNREFUSED));
    let u = socket(&p, STREAM);
    assert_eq!(bind(&p, u, &name), 0);

    // An empty address binds an automatic abstract name.
    let a = socket(&p, DGRAM);
    assert_eq!(bind(&p, a, &1u16.to_ne_bytes()), 0);
    let (r, got, len) = name_of(&p, Sys::Getsockname, a);
    assert_eq!((r, len), (0, 2 + 1 + 5));
    assert_eq!(got[2], 0);
    assert!(got[3..].iter().all(u8::is_ascii_hexdigit));
    let b = socket(&p, DGRAM);
    assert_eq!(bind(&p, b, &1u16.to_ne_bytes()), 0);
    assert_ne!(name_of(&p, Sys::Getsockname, b).1, got);
}

#[test]
fn datagrams_find_the_receiver_by_name_and_report_the_sender() {
    let (p, _) = process("unix-dgram");
    let rx = socket(&p, DGRAM | NONBLOCK);
    let tx = socket(&p, DGRAM | NONBLOCK);
    let rx_name = sockaddr(b"/tmp/dgram-rx", false);
    let tx_name = sockaddr(b"dgram-tx", true);
    assert_eq!(bind(&p, rx, &rx_name), 0);
    assert_eq!(bind(&p, tx, &tx_name), 0);

    let sendto = |fd: u64, data: &[u8], to: &[u8]| {
        put(&p, BUF, data);
        put(&p, ADDR, to);
        call(&p, Sys::Sendto, &[fd, BUF, data.len() as u64, 0, ADDR, to.len() as u64])
    };
    assert_eq!(sendto(tx, b"one", &rx_name), 3);
    assert_eq!(sendto(tx, b"two", &rx_name), 3);
    put(&p, LEN, &64u32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Recvfrom, &[rx, BUF + 0x100, 64, 0, ADDR + 0x40, LEN]), 3);
    assert_eq!(get(&p, BUF + 0x100, 3), b"one");
    assert_eq!(u32::from_ne_bytes(get(&p, LEN, 4).try_into().unwrap()) as usize, tx_name.len());
    assert_eq!(get(&p, ADDR + 0x40, tx_name.len()), tx_name);

    // The receiver answers to the name it was just given.
    assert_eq!(sendto(rx, b"back", &tx_name), 4);
    assert_eq!(read(&p, tx, 64).unwrap(), b"back");
    assert_eq!(read(&p, rx, 64).unwrap(), b"two");
    assert_eq!(read(&p, rx, 64).unwrap_err(), err(Errno::EAGAIN));

    // A name that nobody holds, a stream's name, and connect fixing the peer.
    assert_eq!(sendto(tx, b"x", &sockaddr(b"nobody", true)), err(Errno::ECONNREFUSED));
    assert_eq!(sendto(tx, b"x", &sockaddr(b"/tmp/missing", false)), err(Errno::ENOENT));
    assert_eq!(write(&p, tx, b"x"), err(Errno::EDESTADDRREQ));
    assert_eq!(connect(&p, tx, &rx_name), 0);
    assert_eq!(write(&p, tx, b"direct"), 6);
    assert_eq!(read(&p, rx, 64).unwrap(), b"direct");
    let (r, _, _) = name_of(&p, Sys::Getpeername, tx);
    assert_eq!(r, 0);
    // The receiver goes away: a connected sender is refused.
    close(&p, rx);
    assert_eq!(write(&p, tx, b"gone"), err(Errno::ECONNREFUSED));
}

#[test]
fn a_descriptor_travels_in_a_message() {
    let _g = serial();
    let (p, _) = process("unix-rights");
    let (a, b) = pair(&p, STREAM);
    let (rd, wr) = pipe(&p);
    let base = in_flight();
    assert_eq!(sendmsg(&p, a, b"x", &rights(&[wr])), 1);
    assert_eq!(in_flight(), base + 1);
    // The sender's own copy can go; the file lives on in the message.
    close(&p, wr as u64);
    let got = recvmsg(&p, b, 16, 64, 0).unwrap();
    assert_eq!(got.data, b"x");
    assert_eq!(got.flags, 0);
    assert_eq!(in_flight(), base);
    let [received] = got.fds()[..] else { panic!("one descriptor: {:?}", got.cmsgs) };
    assert_eq!(write(&p, received as u64, b"through the pipe"), 16);
    assert_eq!(read(&p, rd as u64, 64).unwrap(), b"through the pipe");

    // The receiver may ask for close-on-exec.
    let (rd2, wr2) = pipe(&p);
    assert_eq!(sendmsg(&p, a, b"y", &rights(&[wr2])), 1);
    let got = recvmsg(&p, b, 16, 64, 0x4000_0000).unwrap();
    assert_eq!(call(&p, Sys::Fcntl, &[got.fds()[0] as u64, 1, 0]), 1);
    let _ = rd2;
}

#[test]
fn ancillary_data_stays_with_its_bytes_in_a_stream() {
    let _g = serial();
    let (p, _) = process("unix-boundary");
    let (a, b) = pair(&p, STREAM);
    let (_rd, wr) = pipe(&p);
    assert_eq!(write(&p, a, b"plain"), 5);
    assert_eq!(sendmsg(&p, a, b"carry", &rights(&[wr])), 5);
    assert_eq!(write(&p, a, b"tail"), 4);
    // A read does not run across the byte that has descriptors with it.
    let got = recvmsg(&p, b, 64, 64, 0).unwrap();
    assert_eq!((&got.data[..], got.fds().len()), (&b"plain"[..], 0));
    let got = recvmsg(&p, b, 64, 64, 0).unwrap();
    assert_eq!(got.fds().len(), 1);
    assert_eq!(got.data, b"carrytail");
    close(&p, got.fds()[0] as u64);
}

#[test]
fn what_does_not_fit_is_truncated_and_closed() {
    let _g = serial();
    let (p, _) = process("unix-ctrunc");
    let (a, b) = pair(&p, DGRAM);
    let (_rd, wr) = pipe(&p);
    let (_rd2, wr2) = pipe(&p);
    let open = |p: &Process| call(p, Sys::Dup, &[0]) as u64;
    let probe = open(&p);
    close(&p, probe);
    let base = in_flight();
    // No room for any control message.
    assert_eq!(sendmsg(&p, a, b"m", &rights(&[wr])), 1);
    let got = recvmsg(&p, b, 16, 0, 0).unwrap();
    assert_eq!((got.data, got.flags & MSG_CTRUNC), (b"m".to_vec(), MSG_CTRUNC));
    assert_eq!(in_flight(), base, "dropped with the message");
    assert_eq!(open(&p), probe, "no descriptor was installed");
    close(&p, probe);
    // Room for one of two.
    assert_eq!(sendmsg(&p, a, b"m", &rights(&[wr, wr2])), 1);
    let got = recvmsg(&p, b, 16, 20, 0).unwrap();
    assert_eq!((got.fds().len(), got.flags & MSG_CTRUNC), (1, MSG_CTRUNC));
    assert_eq!(in_flight(), base);
    // A plain read throws the descriptors away.
    assert_eq!(sendmsg(&p, a, b"m", &rights(&[wr])), 1);
    assert_eq!(in_flight(), base + 1);
    assert_eq!(read(&p, b, 8).unwrap(), b"m");
    assert_eq!(in_flight(), base);
}

#[test]
fn peeking_copies_the_descriptors_and_leaves_the_message() {
    let _g = serial();
    let (p, _) = process("unix-peek");
    for ty in [STREAM, DGRAM] {
        let (a, b) = pair(&p, ty);
        let (rd, wr) = pipe(&p);
        let base = in_flight();
        assert_eq!(sendmsg(&p, a, b"p", &rights(&[wr])), 1);
        let peeked = recvmsg(&p, b, 8, 64, MSG_PEEK).unwrap();
        assert_eq!(peeked.fds().len(), 1);
        assert_eq!(in_flight(), base + 1, "the message still holds its copy");
        let taken = recvmsg(&p, b, 8, 64, 0).unwrap();
        assert_eq!((&taken.data[..], taken.fds().len()), (&b"p"[..], 1));
        assert_eq!(in_flight(), base);
        assert_eq!(write(&p, taken.fds()[0] as u64, b"z"), 1);
        assert_eq!(read(&p, rd as u64, 8).unwrap(), b"z");
    }
}

#[test]
fn files_in_flight_are_limited() {
    let _g = serial();
    let (p, _) = process("unix-limit");
    let (a, b) = pair(&p, STREAM);
    let (_rd, wr) = pipe(&p);
    let base = in_flight();
    assert_eq!(sendmsg(&p, a, b"x", &rights(&vec![wr; 254])), err(Errno::EINVAL), "more than one message may carry");
    assert_eq!(sendmsg(&p, a, b"x", &rights(&[99])), err(Errno::EBADF));
    assert_eq!(sendmsg(&p, a, b"x", &rights(&[wr, wr])[..20]), err(Errno::EINVAL), "a short message");
    assert_eq!(in_flight(), base, "failed sends claim nothing");

    let full = rights(&vec![wr; 253]);
    let mut sent = 0;
    let r = loop {
        let r = sendmsg(&p, a, b"x", &full);
        if r < 0 {
            break r;
        }
        sent += 1;
        assert!(sent <= MAX_IN_FLIGHT / 253, "the limit never came");
    };
    assert_eq!(r, err(Errno::ETOOMANYREFS));
    assert!(in_flight() > base + MAX_IN_FLIGHT - 253);
    assert!(in_flight() <= MAX_IN_FLIGHT);
    // Receiving frees places; closing the receiver frees the rest.
    let got = recvmsg(&p, b, 8, 4096, 0).unwrap();
    assert_eq!(got.fds().len(), 253);
    assert_eq!(sendmsg(&p, a, b"x", &rights(&[wr])), 1);
    close(&p, b);
    assert_eq!(in_flight(), base, "everything queued was dropped with the socket");
    let _ = a;
}

#[test]
fn credentials_are_passed_when_asked_for() {
    let (p, _) = process("unix-cred");
    let (a, b) = pair(&p, DGRAM);
    let pid = p.pid().0;
    let ucred = |pid: u32, uid: u32| -> Vec<u8> {
        cmsg(1, 2, &[pid.to_ne_bytes(), uid.to_ne_bytes(), 0u32.to_ne_bytes()].concat())
    };
    // Nothing comes unless the receiver asks.
    assert_eq!(sendmsg(&p, a, b"q", &[]), 1);
    assert!(recvmsg(&p, b, 8, 64, 0).unwrap().cmsgs.is_empty());
    put(&p, BUF, &1i32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Setsockopt, &[b, SOL_SOCKET, SO_PASSCRED, BUF, 4]), 0);
    put(&p, LEN, &4u32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Getsockopt, &[b, SOL_SOCKET, SO_PASSCRED, BUF + 0x40, LEN]), 0);
    assert_eq!(get(&p, BUF + 0x40, 4), 1i32.to_ne_bytes());
    assert_eq!(sendmsg(&p, a, b"q", &[]), 1);
    let got = recvmsg(&p, b, 8, 64, 0).unwrap();
    let [(1, 2, c)] = &got.cmsgs[..] else { panic!("{:?}", got.cmsgs) };
    assert_eq!(u32::from_ne_bytes(c[..4].try_into().unwrap()), pid);
    // Sending one's own identity explicitly is fine; claiming another is not.
    assert_eq!(sendmsg(&p, a, b"q", &ucred(pid, 0)), 1);
    assert_eq!(recvmsg(&p, b, 8, 64, 0).unwrap().cmsgs.len(), 1);
    assert_eq!(sendmsg(&p, a, b"q", &ucred(pid + 1, 0)), err(Errno::EPERM));
    assert_eq!(sendmsg(&p, a, b"q", &ucred(pid, 7)), err(Errno::EPERM));
    // Too little room: truncated.
    assert_eq!(sendmsg(&p, a, b"q", &[]), 1);
    assert_eq!(recvmsg(&p, b, 8, 16, 0).unwrap().flags & MSG_CTRUNC, MSG_CTRUNC);

    // SO_PEERCRED.
    put(&p, LEN, &12u32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Getsockopt, &[a, SOL_SOCKET, SO_PEERCRED, BUF, LEN]), 0);
    assert_eq!(u32::from_ne_bytes(get(&p, BUF, 4).try_into().unwrap()), pid);
    // Other control messages are refused.
    assert_eq!(sendmsg(&p, a, b"q", &cmsg(1, 9, &[0; 4])), err(Errno::EINVAL));
    assert_eq!(sendmsg(&p, a, b"q", &cmsg(6, 1, &[0; 4])), err(Errno::EINVAL));
}

#[test]
fn a_stream_passes_credentials_and_descriptors_to_an_accepted_socket() {
    let _g = serial();
    let (p, _) = process("unix-accepted");
    let name = sockaddr(b"/tmp/passing.sock", false);
    let s = socket(&p, STREAM);
    assert_eq!(bind(&p, s, &name), 0);
    assert_eq!(call(&p, Sys::Listen, &[s, 2]), 0);
    let c = socket(&p, STREAM);
    assert_eq!(connect(&p, c, &name), 0);
    let conn = call(&p, Sys::Accept, &[s, 0, 0]) as u64;
    put(&p, BUF, &1i32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Setsockopt, &[conn, SOL_SOCKET, SO_PASSCRED, BUF, 4]), 0);
    let (rd, wr) = pipe(&p);
    let creds = sendmsg(&p, c, b"hello", &rights(&[wr]));
    assert_eq!(creds, 5);
    let got = recvmsg(&p, conn, 64, 128, 0).unwrap();
    assert_eq!(got.data, b"hello");
    let kinds: Vec<_> = got.cmsgs.iter().map(|c| (c.0, c.1)).collect();
    assert_eq!(kinds, [(1, 1), (1, 2)], "rights then credentials");
    assert_eq!(write(&p, got.fds()[0] as u64, b"ok"), 2);
    assert_eq!(read(&p, rd as u64, 8).unwrap(), b"ok");
    // Descriptors go the other way too, and a socket can be one of them.
    let (x, y) = pair(&p, STREAM);
    assert_eq!(sendmsg(&p, conn, b"s", &rights(&[x as i32])), 1);
    let got = recvmsg(&p, c, 8, 64, 0).unwrap();
    let passed = got.fds()[0] as u64;
    assert_eq!(write(&p, y, b"via"), 3);
    assert_eq!(read(&p, passed, 8).unwrap(), b"via");
}

#[test]
fn closing_a_listener_drops_what_waits_on_it() {
    let _g = serial();
    let (p, _) = process("unix-drop");
    let name = sockaddr(b"drop-me", true);
    let s = socket(&p, STREAM);
    assert_eq!(bind(&p, s, &name), 0);
    assert_eq!(call(&p, Sys::Listen, &[s, 4]), 0);
    let c = socket(&p, STREAM | NONBLOCK);
    assert_eq!(connect(&p, c, &name), 0);
    close(&p, s);
    assert_eq!(read(&p, c, 8).unwrap(), b"", "the connection never completed: end of file");
    assert_eq!(write(&p, c, b"x"), err(Errno::EPIPE));
}

#[test]
fn polling_a_listener_and_a_connected_socket() {
    let (p, _) = process("unix-poll");
    let name = sockaddr(b"poll-me", true);
    let s = socket(&p, STREAM);
    assert_eq!(bind(&p, s, &name), 0);
    assert_eq!(call(&p, Sys::Listen, &[s, 4]), 0);
    let revents = |fd: u64| {
        let mut e = [0u8; 8];
        e[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
        e[4..6].copy_from_slice(&0x5u16.to_ne_bytes());
        put(&p, BUF, &e);
        put(&p, BUF + 0x20, &[0; 16]);
        call(&p, Sys::Ppoll, &[BUF, 1, BUF + 0x20, 0, 0]);
        u16::from_ne_bytes(get(&p, BUF + 6, 2).try_into().unwrap())
    };
    assert_eq!(revents(s), 0);
    let c = socket(&p, STREAM);
    assert_eq!(connect(&p, c, &name), 0);
    assert_eq!(revents(s), 1, "a connection waits");
    let conn = call(&p, Sys::Accept, &[s, 0, 0]) as u64;
    assert_eq!(revents(s), 0);
    assert_eq!(revents(conn), 4, "writable only");
    assert_eq!(write(&p, c, b"x"), 1);
    assert_eq!(revents(conn), 5);
}
