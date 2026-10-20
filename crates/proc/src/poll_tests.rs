//! `poll`, `select`, `epoll`, `sendmsg`/`recvmsg`, `socketpair` and
//! `MSG_PEEK`, on in-memory socket pairs (so no network stack is needed).

use alloc::vec::Vec;
use std::sync::Mutex;

use osmium_fs::Errno;

use crate::net_tests::{BASE, Flat, call, err, get, put};
use crate::{Process, Sys};

pub(crate) const SV: u64 = BASE + 0x300;
pub(crate) const TS: u64 = BASE + 0x320;
pub(crate) const PF: u64 = BASE + 0x400;
pub(crate) const MSG: u64 = BASE + 0x500;
pub(crate) const IOV: u64 = BASE + 0x600;
pub(crate) const B1: u64 = BASE + 0x800;
pub(crate) const B2: u64 = BASE + 0x900;
pub(crate) const EV: u64 = BASE + 0xa00;
pub(crate) const SETS: u64 = BASE + 0xb00;
pub(crate) const NAMELEN: u64 = MSG + 8;

const STREAM: u64 = 1;
const DGRAM: u64 = 2;
const NONBLOCK: u64 = 0o4000;
pub(crate) const MSG_PEEK: u64 = 2;
pub(crate) const IN: u32 = 1;
pub(crate) const OUT: u32 = 4;
pub(crate) const HUP: u32 = 0x10;
const ET: u32 = 1 << 31;
const ONESHOT: u32 = 1 << 30;

#[cfg(target_arch = "x86_64")]
const EVENT_LEN: usize = 12;
#[cfg(not(target_arch = "x86_64"))]
const EVENT_LEN: usize = 16;
#[cfg(target_arch = "x86_64")]
const DATA_OFF: usize = 4;
#[cfg(not(target_arch = "x86_64"))]
const DATA_OFF: usize = 8;

fn process() -> alloc::sync::Arc<Process> {
    let p = Process::new("poll", Flat(Mutex::new(alloc::vec![0; 0x4000])), 0);
    put(&p, TS, &[0; 16]);
    p
}

fn pair(p: &Process, ty: u64) -> (u64, u64) {
    assert_eq!(call(p, Sys::Socketpair, &[1, ty | NONBLOCK, 0, SV]), 0);
    let b = get(p, SV, 8);
    (u32::from_ne_bytes(b[..4].try_into().unwrap()) as u64, u32::from_ne_bytes(b[4..].try_into().unwrap()) as u64)
}

/// `ppoll` with a zero timeout on one descriptor; returns its `revents`.
pub(crate) fn revents(p: &Process, fd: u64, events: u32) -> u32 {
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&(fd as i32).to_ne_bytes());
    e[4..6].copy_from_slice(&(events as u16).to_ne_bytes());
    put(p, PF, &e);
    let n = call(p, Sys::Ppoll, &[PF, 1, TS, 0, 0]);
    let r = u16::from_ne_bytes(get(p, PF + 6, 2).try_into().unwrap()) as u32;
    assert_eq!(n, i64::from(r != 0));
    r
}

/// A `msghdr` with `iovs` as its buffers.
pub(crate) fn msghdr(p: &Process, name: u64, namelen: u32, iovs: &[(u64, u64)], controllen: u64) {
    let mut v = alloc::vec![0u8; 56];
    v[..8].copy_from_slice(&name.to_ne_bytes());
    v[8..12].copy_from_slice(&namelen.to_ne_bytes());
    v[16..24].copy_from_slice(&IOV.to_ne_bytes());
    v[24..32].copy_from_slice(&(iovs.len() as u64).to_ne_bytes());
    v[40..48].copy_from_slice(&controllen.to_ne_bytes());
    put(p, MSG, &v);
    let mut io = Vec::new();
    for (base, len) in iovs {
        io.extend(base.to_ne_bytes());
        io.extend(len.to_ne_bytes());
    }
    put(p, IOV, &io);
}

pub(crate) fn event(p: &Process, events: u32, data: u64) {
    let mut b = alloc::vec![0u8; EVENT_LEN];
    b[..4].copy_from_slice(&events.to_ne_bytes());
    b[DATA_OFF..DATA_OFF + 8].copy_from_slice(&data.to_ne_bytes());
    put(p, EV, &b);
}

pub(crate) fn ctl(p: &Process, ep: u64, op: u64, fd: u64, events: u32, data: u64) -> i64 {
    event(p, events, data);
    call(p, Sys::EpollCtl, &[ep, op, fd, EV])
}

/// `epoll_pwait` with no wait; returns the `(events, data)` pairs.
pub(crate) fn drain(p: &Process, ep: u64) -> Vec<(u32, u64)> {
    let n = call(p, Sys::EpollPwait, &[ep, EV, 8, 0, 0, 0]);
    assert!(n >= 0, "epoll_pwait: {n}");
    let raw = get(p, EV, n as usize * EVENT_LEN);
    raw.chunks(EVENT_LEN)
        .map(|c| {
            (
                u32::from_ne_bytes(c[..4].try_into().unwrap()),
                u64::from_ne_bytes(c[DATA_OFF..DATA_OFF + 8].try_into().unwrap()),
            )
        })
        .collect()
}

#[test]
fn stream_pair_with_peek_and_vectors() {
    let p = process();
    let (a, b) = pair(&p, STREAM);
    assert_eq!(call(&p, Sys::Read, &[a, B1, 8]), err(Errno::EAGAIN));
    assert_eq!(revents(&p, a, IN | OUT), OUT);

    put(&p, B1, b"hello");
    assert_eq!(call(&p, Sys::Write, &[a, B1, 5]), 5);
    assert_eq!(revents(&p, b, IN | OUT), IN | OUT);
    assert_eq!(call(&p, Sys::Recvfrom, &[b, B2, 3, MSG_PEEK, 0, 0]), 3);
    assert_eq!(get(&p, B2, 3), b"hel");
    assert_eq!(call(&p, Sys::Recvfrom, &[b, B2, 16, 0, 0, 0]), 5, "the peek left it queued");
    assert_eq!(get(&p, B2, 5), b"hello");
    assert_eq!(call(&p, Sys::Recvfrom, &[b, B2, 16, 0, 0, 0]), err(Errno::EAGAIN));

    // Gather two buffers out, scatter over three on the way in.
    put(&p, B1, b"ab");
    put(&p, B1 + 0x10, b"cde");
    msghdr(&p, 0, 0, &[(B1, 2), (B1 + 0x10, 3)], 0);
    assert_eq!(call(&p, Sys::Sendmsg, &[a, MSG, 0]), 5);
    msghdr(&p, 0, 0, &[(B2, 2), (B2 + 0x10, 1), (B2 + 0x20, 10)], 0);
    assert_eq!(call(&p, Sys::Recvmsg, &[b, MSG, 0]), 5);
    assert_eq!(get(&p, B2, 2), b"ab");
    assert_eq!(get(&p, B2 + 0x10, 1), b"c");
    assert_eq!(get(&p, B2 + 0x20, 2), b"de");
    assert_eq!(get(&p, MSG + 48, 4), [0; 4], "msg_flags");
    assert_eq!(get(&p, NAMELEN, 4), [0; 4], "no name");

    // Names mean nothing to a connected pair; control data is not supported.
    assert_eq!(call(&p, Sys::Sendto, &[a, B1, 2, 0, B2, 16]), err(Errno::EISCONN));
    msghdr(&p, 0, 0, &[(B1, 2)], 8);
    assert_eq!(call(&p, Sys::Sendmsg, &[a, MSG, 0]), err(Errno::EOPNOTSUPP));
    assert_eq!(call(&p, Sys::Recvmsg, &[b, MSG, 0x10000]), err(Errno::EOPNOTSUPP), "unknown flag");

    // Getsockname gives an unnamed AF_UNIX address; SO_TYPE is a stream.
    put(&p, B2, &16u32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Getsockname, &[a, B1, B2]), 0);
    assert_eq!(get(&p, B1, 2), 1u16.to_ne_bytes());
    assert_eq!(get(&p, B2, 4), 2u32.to_ne_bytes());
    put(&p, B2, &4u32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Getsockopt, &[a, 1, 3, B1, B2]), 0);
    assert_eq!(get(&p, B1, 4), 1i32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Bind, &[a, B1, 16]), err(Errno::EOPNOTSUPP));

    // shutdown(SHUT_WR) is end of file for the peer; close is a hang-up.
    assert_eq!(call(&p, Sys::Shutdown, &[a, 1]), 0);
    assert_eq!(call(&p, Sys::Read, &[b, B2, 4]), 0);
    assert_eq!(revents(&p, b, IN), IN);
    assert_eq!(call(&p, Sys::Write, &[a, B1, 1]), err(Errno::EPIPE));
    assert_eq!(call(&p, Sys::Close, &[a]), 0);
    assert_ne!(revents(&p, b, 0) & HUP, 0);
    assert_eq!(call(&p, Sys::Write, &[b, B1, 1]), err(Errno::EPIPE));
}

#[test]
fn datagram_pair_keeps_boundaries_and_reports_truncation() {
    let p = process();
    let (a, b) = pair(&p, DGRAM);
    put(&p, B1, b"first");
    put(&p, B1 + 0x10, b"second!");
    assert_eq!(call(&p, Sys::Sendto, &[a, B1, 5, 0, 0, 0]), 5);
    assert_eq!(call(&p, Sys::Sendto, &[a, B1 + 0x10, 7, 0, 0, 0]), 7);
    // A small buffer takes the front of the first datagram and says so.
    msghdr(&p, 0, 0, &[(B2, 3)], 0);
    assert_eq!(call(&p, Sys::Recvmsg, &[b, MSG, MSG_PEEK]), 3);
    assert_eq!(u32::from_ne_bytes(get(&p, MSG + 48, 4).try_into().unwrap()), 0x20);
    assert_eq!(call(&p, Sys::Recvmsg, &[b, MSG, 0]), 3);
    assert_eq!(get(&p, B2, 3), b"fir");
    assert_eq!(call(&p, Sys::Recvfrom, &[b, B2, 64, 0, 0, 0]), 7, "the rest of the first is gone");
    assert_eq!(get(&p, B2, 7), b"second!");
    assert_eq!(call(&p, Sys::Recvfrom, &[b, B2, 64, 0, 0, 0]), err(Errno::EAGAIN));
    // Fill the queue: the sender sees it full, and recovers once it drains.
    let mut sent = 0;
    while call(&p, Sys::Sendto, &[a, B1, 1, 0, 0, 0]) == 1 {
        sent += 1;
    }
    assert!(sent > 0);
    assert_eq!(revents(&p, a, OUT), 0);
    assert_eq!(call(&p, Sys::Recvfrom, &[b, B2, 1, 0, 0, 0]), 1);
    assert_eq!(revents(&p, a, OUT), OUT);
    // Oversized datagrams are refused whole.
    assert_eq!(call(&p, Sys::Sendto, &[a, B1, 1 << 20, 0, 0, 0]), err(Errno::EMSGSIZE));
}

#[test]
fn bad_arguments_are_rejected() {
    let p = process();
    let (a, _b) = pair(&p, STREAM);
    assert_eq!(call(&p, Sys::Socketpair, &[2, 1, 0, SV]), err(Errno::EAFNOSUPPORT));
    assert_eq!(call(&p, Sys::Socketpair, &[1, 3, 0, SV]), err(Errno::EPROTOTYPE));
    assert_eq!(call(&p, Sys::Socketpair, &[1, 1, 6, SV]), err(Errno::EPROTONOSUPPORT));
    let before = call(&p, Sys::Dup, &[a]);
    assert_eq!(call(&p, Sys::Socketpair, &[1, 1, 0, 0x100000]), err(Errno::EFAULT));
    assert_eq!(call(&p, Sys::Dup, &[a]), before + 1, "a failed socketpair leaves no descriptors behind");

    // iovec problems: too many, a wild pointer, a length that wraps.
    msghdr(&p, 0, 0, &[(B1, 1)], 0);
    put(&p, MSG + 24, &2000u64.to_ne_bytes());
    assert_eq!(call(&p, Sys::Sendmsg, &[a, MSG, 0]), err(Errno::EMSGSIZE));
    put(&p, MSG + 24, &1u64.to_ne_bytes());
    put(&p, MSG + 16, &0xffff_ffff_ffff_fff8u64.to_ne_bytes());
    assert_eq!(call(&p, Sys::Sendmsg, &[a, MSG, 0]), err(Errno::EFAULT));
    msghdr(&p, 0, 0, &[(B1, u64::MAX)], 0);
    assert_eq!(call(&p, Sys::Sendmsg, &[a, MSG, 0]), err(Errno::EINVAL));
    msghdr(&p, 0, 0, &[(B1, 1 << 62), (B1, 1 << 62)], 0);
    assert_eq!(call(&p, Sys::Recvmsg, &[a, MSG, 0]), err(Errno::EINVAL), "the total wraps");
    msghdr(&p, 0, 0, &[(0xdead_0000, 4)], 0);
    assert_eq!(call(&p, Sys::Sendmsg, &[a, MSG, 0]), err(Errno::EFAULT));
    assert_eq!(call(&p, Sys::Sendmsg, &[a, 0xffff_ffff_ffff_fff0, 0]), err(Errno::EFAULT));
    assert_eq!(call(&p, Sys::Sendmsg, &[99, MSG, 0]), err(Errno::EBADF));

    // poll and select limits.
    assert_eq!(call(&p, Sys::Ppoll, &[PF, 5000, TS, 0, 0]), err(Errno::EINVAL));
    assert_eq!(call(&p, Sys::Ppoll, &[0x100000, 1, TS, 0, 0]), err(Errno::EFAULT));
    assert_eq!(call(&p, Sys::Ppoll, &[PF, 1, TS, SETS, 4]), err(Errno::EINVAL), "sigsetsize");
    assert_eq!(call(&p, Sys::Pselect6, &[2000, 0, 0, 0, TS, 0]), err(Errno::EINVAL));
    put(&p, TS, &(-1i64).to_ne_bytes());
    assert_eq!(call(&p, Sys::Ppoll, &[PF, 1, TS, 0, 0]), err(Errno::EINVAL), "negative timeout");
    put(&p, TS, &[0; 16]);
    // A closed or never-open descriptor is POLLNVAL, a negative one is skipped.
    assert_eq!(revents(&p, 77, IN), 0x20);
    assert_eq!(revents(&p, u64::MAX, IN), 0);
    // select on a descriptor that is not open.
    put(&p, SETS, &[0; 16]);
    put(&p, SETS + 5, &[1]);
    assert_eq!(call(&p, Sys::Pselect6, &[41, SETS, 0, 0, TS, 0]), err(Errno::EBADF));

    // epoll misuse.
    assert_eq!(call(&p, Sys::EpollCreate1, &[1]), err(Errno::EINVAL));
    let ep = call(&p, Sys::EpollCreate1, &[0o2000000]) as u64;
    assert_eq!(call(&p, Sys::Fcntl, &[ep, 1, 0]), 1, "close-on-exec");
    assert_eq!(call(&p, Sys::EpollPwait, &[ep, EV, 0, 0, 0, 0]), err(Errno::EINVAL));
    assert_eq!(call(&p, Sys::EpollPwait, &[ep, 0x100000, 4, 0, 0, 0]), err(Errno::EFAULT));
    assert_eq!(call(&p, Sys::EpollPwait, &[a, EV, 4, 0, 0, 0]), err(Errno::EINVAL), "not an epoll");
    assert_eq!(ctl(&p, ep, 1, ep, IN, 0), err(Errno::EINVAL), "itself");
    assert_eq!(ctl(&p, ep, 1, 88, IN, 0), err(Errno::EBADF));
    assert_eq!(ctl(&p, ep, 9, a, IN, 0), err(Errno::EINVAL));
    assert_eq!(ctl(&p, ep, 3, a, IN, 0), err(Errno::ENOENT));
    assert_eq!(ctl(&p, ep, 2, a, IN, 0), err(Errno::ENOENT));
    assert_eq!(call(&p, Sys::EpollCtl, &[ep, 1, a, 0x100000]), err(Errno::EFAULT));
    assert_eq!(ctl(&p, ep, 1, a, IN, 0), 0);
    assert_eq!(ctl(&p, ep, 1, a, IN, 0), err(Errno::EEXIST));
}

#[test]
fn select_reports_ready_sets() {
    let p = process();
    let (a, b) = pair(&p, STREAM);
    let n = b.max(a) + 1;
    let set = |bits: &[u64]| {
        let mut w = [0u8; 8];
        for &b in bits {
            w[b as usize / 8] |= 1 << (b % 8);
        }
        w
    };
    // Nothing to read yet, but both ends can write.
    put(&p, SETS, &set(&[a, b]));
    put(&p, SETS + 0x10, &set(&[a, b]));
    assert_eq!(call(&p, Sys::Pselect6, &[n, SETS, SETS + 0x10, 0, TS, 0]), 2);
    assert_eq!(get(&p, SETS, 8), [0; 8]);
    assert_eq!(get(&p, SETS + 0x10, 8), set(&[a, b]));
    // Data arrives for b.
    put(&p, B1, b"x");
    assert_eq!(call(&p, Sys::Write, &[a, B1, 1]), 1);
    put(&p, SETS, &set(&[a, b]));
    put(&p, SETS + 0x10, &[0; 8]);
    assert_eq!(call(&p, Sys::Pselect6, &[n, SETS, 0, 0, TS, 0]), 1);
    assert_eq!(get(&p, SETS, 8), set(&[b]));
    // The classic select takes a timeval.
    #[cfg(target_arch = "x86_64")]
    {
        put(&p, SETS, &set(&[a]));
        assert_eq!(call(&p, Sys::Select, &[n, SETS, 0, 0, TS]), 0);
        put(&p, SETS, &set(&[b]));
        assert_eq!(call(&p, Sys::Select, &[n, SETS, 0, 0, TS]), 1);
        put(&p, PF, &[0; 8]);
        assert_eq!(call(&p, Sys::Poll, &[PF, 0, 0]), 0, "no descriptors, no wait");
    }
}

#[test]
fn epoll_levels_edges_and_one_shots() {
    let p = process();
    let (a, b) = pair(&p, STREAM);
    let ep = call(&p, Sys::EpollCreate1, &[0]) as u64;
    assert_eq!(ctl(&p, ep, 1, b, IN, 0xb0b), 0);
    assert!(drain(&p, ep).is_empty());
    put(&p, B1, b"xy");
    assert_eq!(call(&p, Sys::Write, &[a, B1, 2]), 2);
    assert_eq!(drain(&p, ep), [(IN, 0xb0b)]);
    assert_eq!(drain(&p, ep), [(IN, 0xb0b)], "level-triggered: still readable");
    assert_eq!(revents(&p, ep, IN), IN, "an epoll descriptor is itself pollable");

    // Edge-triggered: reported once, then again only after it clears and returns.
    assert_eq!(ctl(&p, ep, 3, b, IN | ET, 7), 0);
    assert_eq!(drain(&p, ep), [(IN, 7)]);
    assert!(drain(&p, ep).is_empty());
    assert_eq!(call(&p, Sys::Read, &[b, B2, 8]), 2);
    assert!(drain(&p, ep).is_empty());
    assert_eq!(call(&p, Sys::Write, &[a, B1, 1]), 1);
    assert_eq!(drain(&p, ep), [(IN, 7)]);

    // One-shot: disarmed after it reports, until modified.
    assert_eq!(ctl(&p, ep, 3, b, IN | ONESHOT, 9), 0);
    assert_eq!(drain(&p, ep), [(IN, 9)]);
    assert!(drain(&p, ep).is_empty());
    assert_eq!(ctl(&p, ep, 3, b, IN | ONESHOT, 9), 0);
    assert_eq!(drain(&p, ep), [(IN, 9)]);

    // A peer hanging up is reported whether asked for or not.
    assert_eq!(ctl(&p, ep, 3, b, 0, 5), 0);
    assert!(drain(&p, ep).is_empty() || drain(&p, ep)[0].0 & IN == 0);
    assert_eq!(call(&p, Sys::Close, &[a]), 0);
    let ev = drain(&p, ep);
    assert_eq!(ev.len(), 1);
    assert_ne!(ev[0].0 & HUP, 0);

    // Deleting stops reports; closing the last descriptor drops the entry.
    assert_eq!(ctl(&p, ep, 2, b, 0, 0), 0);
    assert!(drain(&p, ep).is_empty());
    assert_eq!(ctl(&p, ep, 1, b, IN, 1), 0);
    assert!(!drain(&p, ep).is_empty());
    assert_eq!(call(&p, Sys::Close, &[b]), 0);
    assert!(drain(&p, ep).is_empty());

    // Nesting: an epoll descriptor can be watched by another.
    let (c, d) = pair(&p, DGRAM);
    let inner = call(&p, Sys::EpollCreate1, &[0]) as u64;
    let outer = call(&p, Sys::EpollCreate1, &[0]) as u64;
    assert_eq!(ctl(&p, inner, 1, d, IN, 1), 0);
    assert_eq!(ctl(&p, outer, 1, inner, IN, 2), 0);
    assert!(drain(&p, outer).is_empty());
    put(&p, B1, b"z");
    assert_eq!(call(&p, Sys::Sendto, &[c, B1, 1, 0, 0, 0]), 1);
    assert_eq!(drain(&p, outer), [(IN, 2)]);
}
