//! `pipe` and `pipe2`: ends, readiness, capacity, hang-up and `SIGPIPE`.

use std::sync::Mutex;

use osmium_fs::Errno;

use crate::net_tests::{BASE, Flat, call, err, get, put};
use crate::poll_tests::{B1, B2, IN, OUT, SV, revents};
use crate::{Process, Sys};

const NONBLOCK: u64 = 0o4000;
const CLOEXEC: u64 = 0o2000000;
const ERR: u32 = 8;
const HUP: u32 = 0x10;
const SET: u64 = BASE + 0x3c0;

fn process() -> alloc::sync::Arc<Process> {
    Process::new("pipe", Flat(Mutex::new(alloc::vec![0; 0x4000])), 0)
}

fn make(p: &Process, flags: u64) -> (u64, u64) {
    assert_eq!(call(p, Sys::Pipe2, &[SV, flags]), 0);
    let b = get(p, SV, 8);
    (u32::from_ne_bytes(b[..4].try_into().unwrap()) as u64, u32::from_ne_bytes(b[4..].try_into().unwrap()) as u64)
}

#[test]
fn bytes_flow_from_the_write_end_to_the_read_end() {
    let p = process();
    let (r, w) = make(&p, NONBLOCK);
    assert_eq!(call(&p, Sys::Read, &[r, B1, 8]), err(Errno::EAGAIN));
    assert_eq!(revents(&p, r, IN), 0);
    assert_eq!(revents(&p, w, OUT), OUT);

    put(&p, B1, b"hello");
    assert_eq!(call(&p, Sys::Write, &[w, B1, 5]), 5);
    assert_eq!(revents(&p, r, IN), IN);
    assert_eq!(call(&p, Sys::Read, &[r, B2, 3]), 3);
    assert_eq!(get(&p, B2, 3), b"hel");
    assert_eq!(call(&p, Sys::Read, &[r, B2, 8]), 2);
    assert_eq!(get(&p, B2, 2), b"lo");
    assert_eq!(revents(&p, r, IN), 0);

    // Each end only does its own direction.
    assert_eq!(call(&p, Sys::Write, &[r, B1, 1]), err(Errno::EBADF));
    assert_eq!(call(&p, Sys::Read, &[w, B2, 1]), err(Errno::EBADF));
}

#[test]
fn flags_set_blocking_and_close_on_exec() {
    let p = process();
    let (r, w) = make(&p, NONBLOCK | CLOEXEC);
    assert_eq!(call(&p, Sys::Fcntl, &[r, 1, 0]), 1, "close-on-exec");
    assert_eq!(call(&p, Sys::Fcntl, &[r, 3, 0]) & NONBLOCK as i64, NONBLOCK as i64);
    assert_eq!(call(&p, Sys::Fcntl, &[w, 3, 0]) & 3, 1, "write only");
    assert_eq!(call(&p, Sys::Fcntl, &[r, 4, 0]), 0, "F_SETFL clears O_NONBLOCK");
    assert_eq!(call(&p, Sys::Fcntl, &[r, 3, 0]) & NONBLOCK as i64, 0);
    assert_eq!(call(&p, Sys::Fcntl, &[w, 3, 0]) & NONBLOCK as i64, NONBLOCK as i64, "the ends are separate");
    assert_eq!(call(&p, Sys::Pipe2, &[SV, 0o40000]), err(Errno::EINVAL));
}

#[test]
fn closing_the_writer_ends_the_stream_after_the_data() {
    let p = process();
    let (r, w) = make(&p, NONBLOCK);
    put(&p, B1, b"ab");
    assert_eq!(call(&p, Sys::Write, &[w, B1, 2]), 2);
    assert_eq!(call(&p, Sys::Close, &[w]), 0);
    assert_eq!(revents(&p, r, IN), IN | HUP);
    assert_eq!(call(&p, Sys::Read, &[r, B2, 8]), 2);
    assert_eq!(call(&p, Sys::Read, &[r, B2, 8]), 0, "end of file");
    assert_eq!(revents(&p, r, IN), HUP);
}

#[test]
fn a_dup_keeps_the_pipe_open() {
    let p = process();
    let (r, w) = make(&p, NONBLOCK);
    let w2 = call(&p, Sys::Dup, &[w]) as u64;
    assert_eq!(call(&p, Sys::Close, &[w]), 0);
    assert_eq!(call(&p, Sys::Read, &[r, B2, 8]), err(Errno::EAGAIN), "a writer remains");
    assert_eq!(call(&p, Sys::Close, &[w2]), 0);
    assert_eq!(call(&p, Sys::Read, &[r, B2, 8]), 0);
}

#[test]
fn writing_with_no_reader_is_epipe_and_raises_sigpipe() {
    let p = process();
    // Block SIGPIPE so that it stays visible in the pending set.
    put(&p, SET, &(1u64 << 12).to_ne_bytes());
    assert_eq!(call(&p, Sys::RtSigprocmask, &[0, SET, 0, 8]), 0);
    let (r, w) = make(&p, NONBLOCK);
    assert_eq!(call(&p, Sys::Close, &[r]), 0);
    assert_eq!(revents(&p, w, OUT), ERR);
    put(&p, B1, b"x");
    assert_eq!(call(&p, Sys::Write, &[w, B1, 1]), err(Errno::EPIPE));
    assert_eq!(call(&p, Sys::RtSigpending, &[SET, 8]), 0);
    let pending = u64::from_ne_bytes(get(&p, SET, 8).try_into().unwrap());
    assert_eq!(pending, 1 << 12, "SIGPIPE");
}

#[test]
fn a_full_pipe_refuses_writes_and_small_ones_are_whole() {
    let p = process();
    let (r, w) = make(&p, NONBLOCK);
    put(&p, B1, &[7; 0x800]);
    let mut total = 0;
    // 32 writes of 2 KiB fill 64 KiB exactly.
    for _ in 0..32 {
        assert_eq!(call(&p, Sys::Write, &[w, B1, 0x800]), 0x800);
        total += 0x800;
    }
    assert_eq!(total, 64 * 1024);
    assert_eq!(call(&p, Sys::Write, &[w, B1, 1]), err(Errno::EAGAIN));
    assert_eq!(revents(&p, w, OUT), 0);

    // 1 KiB of room is not enough for a 4 KiB write, so none of it goes in.
    assert_eq!(call(&p, Sys::Read, &[r, B2, 0x400]), 0x400);
    assert_eq!(revents(&p, w, OUT), 0);
    assert_eq!(call(&p, Sys::Write, &[w, B1, 0x800]), err(Errno::EAGAIN));
    // A write that does not fit when the pipe is that full is taken in part
    // only if it is longer than PIPE_BUF; this one is not.
    assert_eq!(call(&p, Sys::Read, &[r, B2, 0x400 + 0x800]), 0x400 + 0x800);
    assert_eq!(revents(&p, w, OUT), OUT);
    assert_eq!(call(&p, Sys::Write, &[w, B1, 0x800]), 0x800);
}
