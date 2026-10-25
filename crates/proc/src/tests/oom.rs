#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Running out of memory in the middle of a system call is an error, and
//! leaves nothing behind. Each test fails every allocation of an operation in
//! turn (see [`crate::failing`]).

use super::*;
use crate::failing::every_failure;

fn enomem<T: core::fmt::Debug>(r: Result<T, Errno>) {
    assert_eq!(r.unwrap_err(), Errno::ENOMEM);
}

#[test]
fn map_anon_fails_cleanly_and_can_be_retried() {
    let frames = leaked_frames();
    let s = space(frames);
    // Tables stay once made, so make them first: the tables are not what
    // this test measures. (Failing to make one is covered by `fork`.)
    s.map_anon(DATA, 0x3000, MapFlags::RW).unwrap();
    s.unmap(DATA, 0x3000);
    let base = frames.live();
    let failures = every_failure(
        || s.map_anon(DATA, 0x3000, MapFlags::RW),
        |r, injected| {
            if injected {
                // What was mapped before it ran out is the caller's to give
                // back, as `Process::mmap_anon` does.
                enomem(r);
                s.unmap(DATA, 0x3000);
                assert_eq!(frames.live(), base, "nothing left allocated");
            } else {
                r.unwrap();
            }
        },
    );
    assert!(failures > 3, "every page and table was a point of failure: {failures}");
    s.unmap(DATA, 0x3000);
    assert_eq!(frames.live(), base);
}

#[test]
fn fork_fails_cleanly_and_leaves_the_parent_whole() {
    platform();
    let (p, frames) = process("oom-fork");
    put(&p, DATA, b"parent");
    let live = frames.live();
    let failures = every_failure(
        || p.fork(),
        |r, injected| {
            if injected {
                assert_eq!(r.unwrap_err(), Errno::ENOMEM);
                assert!(p.children().is_empty(), "no child is left registered");
            } else {
                let child = r.unwrap();
                assert_eq!(p.children(), [child.pid()]);
                p.forget_child(child.pid());
            }
            // The child is gone (or never was), and the parent can still write
            // and read its pages, copying them if they were left shared.
            put(&p, DATA, b"parent");
            assert_eq!(get(&p, DATA, 6), b"parent");
        },
    );
    assert!(failures > 5, "{failures}");
    assert_eq!(frames.live(), live, "no frame leaked, shared or copied");
}

#[test]
fn mmap_and_munmap_fail_cleanly() {
    let (p, frames) = process("oom-mmap");
    // Tables stay once made: make the mmap area's first.
    let warm = p.mmap_anon(0x8000, MapFlags::RW).unwrap();
    call(&p, Sys::Munmap, &[warm, 0x8000]);
    let live = frames.live();
    let first = p.mmap_anon(0x1000, MapFlags::RW).unwrap();
    let same_place = |p: &Process| {
        let va = p.mmap_anon(0x1000, MapFlags::RW).unwrap();
        p.memory().unmap(va, 0x1000);
        assert_eq!(call(p, Sys::Munmap, &[va, 0x1000]), 0);
        va
    };
    let next = same_place(&p);
    assert_eq!(next, first + 0x1000);
    let failures = every_failure(
        || p.mmap_anon(0x3000, MapFlags::RW),
        |r, injected| {
            if injected {
                enomem(r);
                assert_eq!(same_place(&p), next, "the failed mapping gave its range back");
            } else {
                let va = r.unwrap();
                assert_eq!(call(&p, Sys::Munmap, &[va, 0x3000]), 0);
            }
        },
    );
    assert!(failures > 3, "{failures}");
    // munmap itself: out of memory before anything is unmapped.
    let va = p.mmap_anon(0x2000, MapFlags::RW).unwrap();
    let failures = every_failure(
        || call(&p, Sys::Munmap, &[va, 0x2000]),
        |r, injected| {
            if injected {
                assert_eq!(r, -(Errno::ENOMEM.0 as i64));
                put(&p, va, b"still mapped");
            } else {
                assert_eq!(r, 0);
            }
        },
    );
    assert!(failures > 0);
    assert_eq!(call(&p, Sys::Munmap, &[first, 0x1000]), 0);
    assert_eq!(frames.live(), live);
}

#[test]
fn clone_fails_cleanly_and_leaves_no_thread_behind() {
    platform();
    let (p, _) = process("oom-clone");
    let main = p.leader();
    let flags = 0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x4_0000;
    let args = [flags, DATA + 0x3000, 0, 0, 0, 0];
    for n in 0.. {
        let (outcome, injected) = crate::failing::failing_at(n, || dispatch_as(&p, &main, Sys::Clone.number(), args));
        if !injected {
            assert!(matches!(outcome, Outcome::Thread { .. }), "{outcome:?}");
            assert_eq!(n, 1, "creating a thread allocates its record, and nothing else");
            return;
        }
        let Outcome::Return(r) = outcome else { panic!("failure {n}: {outcome:?}") };
        assert_eq!(r, -(Errno::ENOMEM.0 as i64), "failure {n}");
        assert_eq!(p.threads(), [p.pid().0], "failure {n}: no thread was left registered");
    }
}

const NOMEM: i64 = -(Errno::ENOMEM.0 as i64);

/// Runs the system call `op` with each of its allocations failing in turn. A
/// run that hits the failure returns `ENOMEM`, or succeeds where it could do
/// without (a short write). `after` sees every result and cleans up.
fn sweep(mut op: impl FnMut() -> i64, mut after: impl FnMut(i64, bool)) -> usize {
    every_failure(&mut op, |r, injected| {
        assert!(r >= 0 || (injected && r == NOMEM), "result {r}, injected: {injected}");
        after(r, injected);
    })
}

fn fds_open(p: &Process) -> usize {
    p.files().lock().len()
}

fn word32(p: &Process, va: u64) -> i32 {
    i32::from_ne_bytes(get(p, va, 4).try_into().unwrap())
}

#[test]
fn descriptor_creating_calls_fail_cleanly_and_leak_no_descriptor() {
    let (p, _) = process("oom-fds");
    let base = fds_open(&p);
    let closing = |r: i64, injected: bool, fds: &[u64]| {
        for fd in fds.iter().filter(|_| r >= 0) {
            assert_eq!(call(&p, Sys::Close, &[*fd]), 0);
        }
        if injected {
            assert_eq!(fds_open(&p), base, "a failed call leaves no descriptor behind");
        }
    };

    // pipe2
    let n = sweep(
        || call(&p, Sys::Pipe2, &[DATA, 0]),
        |r, injected| closing(r, injected, &[word32(&p, DATA) as u64, word32(&p, DATA + 4) as u64]),
    );
    assert!(n >= 3, "{n}");
    // socketpair, stream and datagram
    for ty in [1, 2] {
        let n = sweep(
            || call(&p, Sys::Socketpair, &[1, ty, 0, DATA]),
            |r, injected| closing(r, injected, &[word32(&p, DATA) as u64, word32(&p, DATA + 4) as u64]),
        );
        assert!(n >= 3, "{n}");
    }
    // socket(AF_UNIX), stream and datagram
    for ty in [1, 2] {
        let n = sweep(|| call(&p, Sys::Socket, &[1, ty, 0]), |r, injected| closing(r, injected, &[r as u64]));
        assert!(n >= 2, "{n}");
    }
    // epoll_create1
    let epfd = std::cell::Cell::new(0);
    let n = sweep(
        || {
            let r = call(&p, Sys::EpollCreate1, &[0]);
            epfd.set(r as u64);
            r
        },
        |r, injected| closing(r, injected, &[epfd.get()]),
    );
    assert!(n >= 2, "{n}");
    // dup, and fcntl's F_DUPFD, which may have to grow the table
    for (sys, args) in [(Sys::Dup, [1u64, 0, 0]), (Sys::Fcntl, [1, 0, 20])] {
        let dup = std::cell::Cell::new(0);
        let n = sweep(
            || {
                let r = call(&p, sys, &args);
                dup.set(r as u64);
                r
            },
            |r, injected| closing(r, injected, &[dup.get()]),
        );
        assert!(n >= usize::from(sys == Sys::Fcntl), "{sys:?}: {n}");
    }
    assert_eq!(fds_open(&p), base);
}

#[test]
fn pipe_and_socket_io_fail_cleanly_and_keep_the_stream_intact() {
    let (p, _) = process("oom-io");
    put(&p, DATA + 0x100, b"0123456789abcdef");
    // A pipe, and a stream and a datagram socket pair, in descriptors we know.
    assert_eq!(call(&p, Sys::Pipe2, &[DATA, 0]), 0);
    let (pr, pw) = (word32(&p, DATA) as u64, word32(&p, DATA + 4) as u64);
    assert_eq!(call(&p, Sys::Socketpair, &[1, 1, 0, DATA + 8]), 0);
    let (sa, sb) = (word32(&p, DATA + 8) as u64, word32(&p, DATA + 12) as u64);
    assert_eq!(call(&p, Sys::Socketpair, &[1, 2, 0, DATA + 16]), 0);
    let (da, db) = (word32(&p, DATA + 16) as u64, word32(&p, DATA + 20) as u64);
    // iovec of two pieces at DATA + 0x200
    let iov: Vec<u8> = [DATA + 0x100, 6, DATA + 0x106, 10].iter().flat_map(|v| v.to_ne_bytes()).collect();
    put(&p, DATA + 0x200, &iov);

    // Each write that succeeds is read back whole, so a failed one queued
    // nothing; the read itself has to cope too.
    let cases: [(&str, Sys, [u64; 6], u64, u64); 5] = [
        ("write", Sys::Write, [pw, DATA + 0x100, 16, 0, 0, 0], pr, 16),
        ("writev", Sys::Writev, [pw, DATA + 0x200, 2, 0, 0, 0], pr, 16),
        ("send stream", Sys::Sendto, [sa, DATA + 0x100, 16, 0, 0, 0], sb, 16),
        ("send datagram", Sys::Sendto, [da, DATA + 0x100, 16, 0, 0, 0], db, 16),
        ("sendmsg", Sys::Sendmsg, [da, DATA + 0x300, 0, 0, 0, 0], db, 16),
    ];
    // msghdr for sendmsg at DATA + 0x300: name, namelen, iov, iovlen, ..
    let mut msg = [0u8; 56];
    msg[16..24].copy_from_slice(&(DATA + 0x200).to_ne_bytes());
    msg[24..32].copy_from_slice(&2u64.to_ne_bytes());
    put(&p, DATA + 0x300, &msg);
    for (name, sys, args, reader, len) in cases {
        let n = sweep(
            || call(&p, sys, &args),
            |r, injected| {
                // Drain whatever was queued, without blocking forever.
                let flags = if sys == Sys::Sendto && reader == db { 0x40 } else { 0 };
                let got = if reader == sb || reader == db {
                    call(&p, Sys::Recvfrom, &[reader, DATA + 0x400, 64, flags | 0x40, 0, 0])
                } else {
                    call(&p, Sys::Fcntl, &[reader, 4, 0o4000]);
                    call(&p, Sys::Read, &[reader, DATA + 0x400, 64])
                };
                if r >= 0 && r as u64 == len {
                    assert_eq!(got, len as i64, "{name}: a successful send is all there");
                    assert_eq!(get(&p, DATA + 0x400, 16), b"0123456789abcdef", "{name}");
                } else if injected {
                    assert!(got <= 0 || got as u64 <= len, "{name}: {got}");
                }
            },
        );
        assert!(n >= 1, "{name}: {n}");
    }
}

#[test]
fn waiting_calls_fail_cleanly_before_they_consume_anything() {
    let (p, _) = process("oom-wait");
    assert_eq!(call(&p, Sys::Pipe2, &[DATA, 0]), 0);
    let (pr, pw) = (word32(&p, DATA) as u64, word32(&p, DATA + 4) as u64);
    put(&p, DATA + 0x100, b"x");
    assert_eq!(call(&p, Sys::Write, &[pw, DATA + 0x100, 1]), 1);

    // ppoll on the readable pipe end: pollfd { fd, events: POLLIN }
    let mut pollfd = [0u8; 8];
    pollfd[..4].copy_from_slice(&(pr as i32).to_ne_bytes());
    pollfd[4..6].copy_from_slice(&1u16.to_ne_bytes());
    put(&p, DATA + 0x200, &pollfd);
    let n = sweep(|| call(&p, Sys::Ppoll, &[DATA + 0x200, 1, 0, 0, 0]), |r, _| assert!(r <= 1));
    assert!(n >= 2, "ppoll: {n}");

    // pselect6 with a read set holding the pipe end
    put(&p, DATA + 0x300, &(1u64 << pr).to_ne_bytes());
    let n = sweep(
        || {
            put(&p, DATA + 0x300, &(1u64 << pr).to_ne_bytes());
            call(&p, Sys::Pselect6, &[pr + 1, DATA + 0x300, 0, 0, 0, 0])
        },
        |r, _| assert!(r <= 1),
    );
    assert!(n >= 3, "pselect6: {n}");

    // epoll: add (a node is made first), wait (buffers are made first), del
    let epfd = call(&p, Sys::EpollCreate1, &[0]) as u64;
    let mut ev = [0u8; 16];
    ev[..4].copy_from_slice(&1u32.to_ne_bytes());
    put(&p, DATA + 0x400, &ev);
    let n = sweep(
        || call(&p, Sys::EpollCtl, &[epfd, 1, pr, DATA + 0x400]),
        |r, injected| {
            // Added, or not: either way the next attempt starts from nothing.
            if r >= 0 {
                assert_eq!(call(&p, Sys::EpollCtl, &[epfd, 2, pr, DATA + 0x400]), 0);
            } else {
                assert!(injected);
                assert_eq!(call(&p, Sys::EpollCtl, &[epfd, 2, pr, DATA + 0x400]), -(Errno::ENOENT.0 as i64));
            }
        },
    );
    assert!(n >= 1, "epoll_ctl: {n}");
    assert_eq!(call(&p, Sys::EpollCtl, &[epfd, 1, pr, DATA + 0x400]), 0);
    let n = sweep(
        || call(&p, Sys::EpollPwait, &[epfd, DATA + 0x500, 4, 0, 0, 0]),
        |r, injected| {
            // The pipe is level-triggered and unread: it is still reported.
            assert!(r == 1 || injected, "{r}");
        },
    );
    assert!(n >= 2, "epoll_pwait: {n}");
}

#[test]
fn getcwd_and_big_reads_fail_cleanly() {
    let (p, _) = process("oom-misc");
    let n = sweep(|| call(&p, Sys::Getcwd, &[DATA, 64]), |_, _| ());
    assert!(n >= 1, "getcwd: {n}");
    // The console's `read` hands out a line however big the buffer is.
    let n = sweep(|| call(&p, Sys::Read, &[0, DATA + 0x400, 4096]), |_, _| ());
    assert!(n >= 1, "read: {n}");
}
