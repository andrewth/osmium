#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Regressions from a code review: partial vectored I/O, descriptors closed
//! at exit, auto-reaped children, `getppid` after the parent ends, path
//! length limits and `mprotect` across holes.

use core::sync::atomic::{AtomicUsize, Ordering};

use super::sigthread::{STACK, clone_flags, clone_thread, sigaction};
use super::*;
use crate::fd::Access;
use crate::signal::{SIG_IGN, SigAction, sa, sig::*};
use crate::thread;

fn err(e: Errno) -> i64 {
    -(e.0 as i64)
}

/// A regular file whose first read yields four bytes and whose later reads
/// would block; writes succeed once and then fail.
struct Scripted {
    reads: AtomicUsize,
    writes: AtomicUsize,
}

impl Scripted {
    fn install(p: &Process) -> (u64, Arc<Self>) {
        let f = Arc::new(Self { reads: AtomicUsize::new(0), writes: AtomicUsize::new(0) });
        let fd = p.files().lock().insert(OpenFile::new(f.clone(), Access::RW)).unwrap() as u64;
        (fd, f)
    }
}

impl File for Scripted {
    fn read(&self, _off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
            buf[..4].copy_from_slice(b"abcd");
            Ok(4)
        } else {
            Err(Errno::EAGAIN)
        }
    }
    fn write(&self, _off: u64, buf: &[u8]) -> Result<usize, Errno> {
        if self.writes.fetch_add(1, Ordering::SeqCst) == 0 { Ok(buf.len()) } else { Err(Errno::EIO) }
    }
    fn poll(&self) -> u32 {
        0
    }
    fn stat(&self) -> Stat {
        Stat { kind: FileKind::Regular, mode: 0o644, ..Stat::default() }
    }
}

fn iov(p: &Process, at: u64, pieces: &[(u64, u64)]) {
    let bytes: Vec<u8> = pieces.iter().flat_map(|&(b, l)| [b, l]).flat_map(|v| v.to_ne_bytes()).collect();
    put(p, at, &bytes);
}

#[test]
fn readv_returns_what_was_read_when_a_later_piece_would_block() {
    let (p, _) = process("readv-partial");
    let (fd, f) = Scripted::install(&p);
    iov(&p, DATA + 0x300, &[(DATA + 0x100, 4), (DATA + 0x200, 4)]);
    assert_eq!(call(&p, Sys::Readv, &[fd, DATA + 0x300, 2]), 4, "not EAGAIN: four bytes were consumed");
    assert_eq!(get(&p, DATA + 0x100, 4), b"abcd");
    assert_eq!(f.reads.load(Ordering::SeqCst), 1, "the second piece did not even try to read");
}

#[test]
fn writev_keeps_the_count_when_a_later_flush_fails() {
    let (p, _) = process("writev-partial");
    let (fd, f) = Scripted::install(&p);
    // 64 KiB are gathered and written (one flush); the 8 bytes after them fail.
    const BASE: u64 = 0x200_0000;
    p.memory().map_anon(BASE, 0x8000, MapFlags::RW).unwrap();
    iov(&p, DATA + 0x300, &[(BASE, 0x8000), (BASE, 0x8000), (BASE, 8)]);
    assert_eq!(call(&p, Sys::Writev, &[fd, DATA + 0x300, 3]), 0x10000, "the first flush is not forgotten");
    assert_eq!(f.writes.load(Ordering::SeqCst), 2);
    // With nothing written yet, the error still shows.
    iov(&p, DATA + 0x300, &[(BASE, 8)]);
    assert_eq!(call(&p, Sys::Writev, &[fd, DATA + 0x300, 1]), err(Errno::EIO));
}

#[test]
fn a_pipe_reaches_eof_when_its_writer_process_exits() {
    let (p, _) = process("exit-closes-fds");
    assert_eq!(call(&p, Sys::Pipe2, &[DATA, 0]), 0);
    assert_eq!(p.files().lock().len(), 5);
    let leader = p.leader();
    thread::exit_thread(&p, &leader, ExitStatus::Code(0));
    assert_eq!(p.exit_status(), Some(ExitStatus::Code(0)));
    assert!(p.files().lock().is_empty(), "the zombie holds no descriptors");
}

#[test]
fn getppid_follows_the_parent_to_init_when_it_ends() {
    let (p, _) = process("ppid-parent");
    let child = p.fork().unwrap();
    assert_eq!(call(&child, Sys::Getppid, &[]), p.pid().0 as i64);
    p.set_exited(ExitStatus::Code(0));
    assert_eq!(call(&child, Sys::Getppid, &[]), 1);
}

fn ign_chld(p: &Process, flags: u64, handler: u64) {
    let act = SigAction { handler, flags, restorer: 0, mask: 0 };
    assert_eq!(sigaction(p, SIGCHLD, act), 0);
}

#[test]
fn children_are_reaped_at_once_under_sig_ign_or_nocldwait() {
    for (flags, handler) in [(0, SIG_IGN), (sa::NOCLDWAIT, 0)] {
        let (p, _) = process("autoreap");
        let kept = p.fork().unwrap();
        ign_chld(&p, flags, handler);
        let gone = p.fork().unwrap();
        assert_eq!(p.children().len(), 2);
        gone.set_exited(ExitStatus::Code(1));
        assert_eq!(p.children(), alloc::vec![kept.pid()], "the exited child needs no wait4");
        kept.set_exited(ExitStatus::Code(2));
        assert!(p.children().is_empty());
        assert_eq!(call(&p, Sys::Wait4, &[u64::MAX, 0, 1, 0]), err(Errno::ECHILD));
    }
    // Without either, the zombie stays for wait4.
    let (p, _) = process("no-autoreap");
    let c = p.fork().unwrap();
    c.set_exited(ExitStatus::Code(1));
    assert_eq!(p.children(), alloc::vec![c.pid()]);
}

#[test]
fn a_path_of_exactly_path_max_is_too_long() {
    let (p, _) = process("pathmax");
    let at_cwd = (-100i64) as u64;
    let mut path: Vec<u8> = b"/a".iter().copied().cycle().take(osmium_fs::PATH_MAX).collect();
    path.push(0);
    // Starts 16 bytes before a page boundary, so the NUL lies in the second chunk.
    put(&p, DATA + 0xff0, &path);
    assert_eq!(call(&p, Sys::Openat, &[at_cwd, DATA + 0xff0, 0, 0]), err(Errno::ENAMETOOLONG));
    put(&p, DATA + 0xff0 + osmium_fs::PATH_MAX as u64 - 1, &[0]);
    assert_eq!(call(&p, Sys::Openat, &[at_cwd, DATA + 0xff0, 0, 0]), err(Errno::ENOENT), "one shorter is a lookup");
}

#[test]
fn mprotect_across_a_hole_is_enomem() {
    let (p, _) = process("mprotect-hole");
    const P: u64 = 0x1000;
    let a = call(&p, Sys::Mmap, &[0, 3 * P, 3, 0x22, u64::MAX, 0]) as u64;
    assert_eq!(call(&p, Sys::Munmap, &[a + P, P]), 0);
    assert_eq!(call(&p, Sys::Mprotect, &[a, 3 * P, 1]), err(Errno::ENOMEM), "the hole is in the middle");
    assert_eq!(call(&p, Sys::Mprotect, &[a, P, 1]), 0);
    assert_eq!(call(&p, Sys::Mprotect, &[a + 2 * P, P, 1]), 0);
}

#[test]
fn execve_from_the_last_thread_after_the_leader_exited_promotes_it() {
    platform();
    let (p, _) = process("exec-nonleader");
    let main = p.leader();
    let Outcome::Thread { tid, .. } = clone_thread(&p, &main, clone_flags(), STACK, DATA + 0x10, DATA + 0x20, 0) else {
        panic!("no thread")
    };
    let th = p.group.find(tid).unwrap();
    thread::exit_thread(&p, &main, ExitStatus::Code(0));
    assert_eq!(p.group.live(), 1);
    put(&p, DATA + 0x100, b"/bin/prog\0");
    let out = dispatch_as(&p, &th, Sys::Execve.number(), [DATA + 0x100, 0, 0, 0, 0, 0]);
    assert!(matches!(out, Outcome::Exec { .. }), "{out:?}");
    assert_eq!(th.tid(), p.pid().0, "the caller took the process id");
    assert_eq!(p.threads(), alloc::vec![p.pid().0]);
}

#[test]
fn a_failed_thread_setup_write_leaves_no_thread() {
    platform();
    let (p, _) = process("clone-ctid");
    let main = p.leader();
    // CHILD_SETTID to an unmapped address, after PARENT_SETTID succeeded.
    let flags = clone_flags() | 0x100_0000;
    let out = clone_thread(&p, &main, flags, STACK, DATA + 0x10, 0xdead_0000, 0);
    assert!(matches!(out, Outcome::Return(v) if v == err(Errno::EFAULT)), "{out:?}");
    assert_eq!(p.threads(), alloc::vec![p.pid().0]);
    assert_eq!(p.group.live(), 1);
}
