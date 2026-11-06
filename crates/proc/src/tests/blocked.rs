// SPDX-License-Identifier: GPL-2.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Blocking calls give up when the thread is interrupted or the process is
//! killed. These run on the real scheduler: each test thread is one CPU, and
//! the process's task blocks in a system call until the test interrupts it.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, Ordering};

use osmium_sched::{FifoScheduler, TaskBuilder};

use super::*;
use crate::signal::{self, sig::*};

static SCHED: FifoScheduler = FifoScheduler::new(2);

const PENDING: i64 = i64::MIN;
const EINTR: i64 = -(Errno::EINTR.0 as i64);

/// Makes the calling test thread a fresh CPU with a unique id.
pub(super) fn become_cpu() {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| osmium_sched::inject_scheduler(&SCHED));
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: each test thread gets a distinct id below MAX_CPUS.
    unsafe { osmium_arch::cpu::set_current_id(id) };
    osmium_sched::init_cpu();
}

/// Runs `body` as the process's task, then lets it run until it blocks (the
/// test's own task yields to it on this CPU). Returns the task and the cell
/// that `body`'s result lands in; it holds `PENDING` while the task is
/// blocked.
pub(super) fn block_in(
    p: &Arc<Process>,
    body: impl FnOnce(&Process) -> i64 + Send + 'static,
) -> (Arc<osmium_sched::Task>, Arc<AtomicI64>) {
    let result = Arc::new(AtomicI64::new(PENDING));
    let (q, r) = (p.clone(), result.clone());
    let builder = TaskBuilder::new("blocked").stack_size(256 * 1024).cpu(osmium_arch::cpu::current_id());
    let task = p.spawn(builder, move || r.store(body(&q), Ordering::SeqCst));
    osmium_sched::yield_now();
    assert_eq!(result.load(Ordering::SeqCst), PENDING, "the call blocks");
    (task, result)
}

fn pipe_fds(p: &Process) -> (u64, u64) {
    assert_eq!(call(p, Sys::Pipe2, &[DATA, 0]), 0);
    let b = get(p, DATA, 8);
    (u32::from_ne_bytes(b[..4].try_into().unwrap()) as u64, u32::from_ne_bytes(b[4..].try_into().unwrap()) as u64)
}

#[test]
fn kill_ends_a_blocked_pipe_read() {
    become_cpu();
    let (p, _) = process("kill-pipe");
    let (r, _w) = pipe_fds(&p);
    let (task, result) = block_in(&p, move |p| call(p, Sys::Read, &[r, DATA + 0x100, 8]));
    signal::send(&p, SIGKILL, p.pid()).unwrap();
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), EINTR);
    assert_eq!(p.group.exiting.get().copied(), Some(ExitStatus::Signal(SIGKILL)));
}

#[test]
fn exit_group_from_another_thread_ends_a_blocked_socket_read() {
    become_cpu();
    let (p, _) = process("exit-group-unix");
    assert_eq!(call(&p, Sys::Socketpair, &[1, 1, 0, DATA]), 0);
    let fd = u32::from_ne_bytes(get(&p, DATA, 4).try_into().unwrap()) as u64;
    let (task, result) = block_in(&p, move |p| call(p, Sys::Read, &[fd, DATA + 0x100, 8]));
    crate::thread::exit_group(&p, ExitStatus::Code(7));
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), EINTR);
}

#[test]
fn kill_ends_a_blocked_poll() {
    become_cpu();
    let (p, _) = process("kill-poll");
    let (r, _w) = pipe_fds(&p);
    let mut e = [0u8; 8];
    e[..4].copy_from_slice(&(r as i32).to_ne_bytes());
    e[4..6].copy_from_slice(&1u16.to_ne_bytes());
    put(&p, DATA + 0x200, &e);
    // ppoll with no timeout at all.
    let (task, result) = block_in(&p, |p| call(p, Sys::Ppoll, &[DATA + 0x200, 1, 0, 0, 0]));
    signal::send(&p, SIGKILL, p.pid()).unwrap();
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), EINTR);
}

#[test]
fn kill_ends_a_blocked_wait4() {
    become_cpu();
    let (p, _) = process("kill-wait4");
    let child = p.fork().unwrap();
    let (task, result) = block_in(&p, |p| call(p, Sys::Wait4, &[u64::MAX, 0, 0, 0]));
    signal::send(&p, SIGKILL, p.pid()).unwrap();
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), EINTR);
    assert_eq!(child.exit_status(), None, "the child was not reaped");
}

#[test]
fn a_signal_interrupts_a_blocked_read_but_data_wins() {
    become_cpu();
    let (p, _) = process("eintr");
    let (r, w) = pipe_fds(&p);
    let (task, result) = block_in(&p, move |p| call(p, Sys::Read, &[r, DATA + 0x100, 8]));
    signal::send(&p, SIGUSR1, p.pid()).unwrap();
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), EINTR);
    assert_eq!(p.exit_status(), None, "only the call was interrupted");

    // With data in the pipe and the signal still pending, the read succeeds.
    put(&p, DATA + 0x300, b"abc");
    assert_eq!(call(&p, Sys::Write, &[w, DATA + 0x300, 3]), 3);
    assert_eq!(call(&p, Sys::Read, &[r, DATA + 0x100, 8]), 3);
}

/// The sequence `examples/user/init.rs`'s restart check once raced on: a
/// signal for a reader asleep in `read`, then data, both before the reader
/// runs again. It wakes to find data and returns it, as Linux does
/// (`wait_event_interruptible` checks the condition before signals), and the
/// signal stays pending for the way out. So a writer that wants the read
/// interrupted must wait until it has been, as the demo now does.
#[test]
fn data_that_lands_before_an_interrupted_reader_runs_wins_over_the_signal() {
    become_cpu();
    let (p, _) = process("eintr-race");
    let (r, w) = pipe_fds(&p);
    let (task, result) = block_in(&p, move |p| call(p, Sys::Read, &[r, DATA + 0x100, 8]));
    // Both on this CPU, so the reader cannot run in between.
    signal::send(&p, SIGUSR1, p.pid()).unwrap();
    put(&p, DATA + 0x300, b"x");
    assert_eq!(call(&p, Sys::Write, &[w, DATA + 0x300, 1]), 1);
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), 1, "the data, not EINTR");
    assert_eq!(get(&p, DATA + 0x100, 1), b"x");
    assert_ne!(p.signals.pending_for_test() & signal::bit(SIGUSR1), 0, "still pending");
}

#[test]
fn ppoll_installs_its_mask_for_the_wait_only() {
    become_cpu();
    let (p, _) = process("ppoll-mask");
    let (r, _w) = pipe_fds(&p);
    let usr1 = 1u64 << (SIGUSR1 - 1);
    let usr2 = 1u64 << (SIGUSR2 - 1);
    // The caller blocks SIGUSR1; ppoll's mask blocks SIGUSR2 instead.
    p.leader().mask.store(usr1, Ordering::SeqCst);
    let pollfd: Vec<u8> = (r as i32).to_ne_bytes().into_iter().chain(1u16.to_ne_bytes()).chain([0; 2]).collect();
    put(&p, DATA + 0x100, &pollfd);
    put(&p, DATA + 0x200, &usr2.to_ne_bytes());
    // A zero timeout: nothing is ready, and the caller's mask is back at once.
    put(&p, DATA + 0x300, &[0; 16]);
    assert_eq!(call(&p, Sys::Ppoll, &[DATA + 0x100, 1, DATA + 0x300, DATA + 0x200, 8]), 0);
    assert_eq!(p.leader().signal_mask(), usr1);

    // SIGUSR1 is pending: the caller's mask blocks it, ppoll's lets it in, so
    // a wait with no timeout ends with EINTR at once, and the mask stays
    // ppoll's (for the handler) until the signal is delivered.
    signal::send(&p, SIGUSR1, p.pid()).unwrap();
    let (task, result) = block_or_finish(&p, move |p| call(p, Sys::Ppoll, &[DATA + 0x100, 1, 0, DATA + 0x200, 8]));
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), EINTR);
    assert_eq!(p.leader().signal_mask(), usr2, "the handler would run with ppoll's mask");
    assert_eq!(p.leader().sig.take_saved_mask(), Some(usr1), "and the caller's comes back after it");
}

/// [`block_in`] for a call that may not block at all.
fn block_or_finish(
    p: &Arc<Process>,
    body: impl FnOnce(&Process) -> i64 + Send + 'static,
) -> (Arc<osmium_sched::Task>, Arc<AtomicI64>) {
    let result = Arc::new(AtomicI64::new(PENDING));
    let (q, r) = (p.clone(), result.clone());
    let builder = TaskBuilder::new("maybe-blocked").stack_size(256 * 1024).cpu(osmium_arch::cpu::current_id());
    let task = p.spawn(builder, move || r.store(body(&q), Ordering::SeqCst));
    (task, result)
}

#[test]
fn a_signal_wakes_only_the_threads_it_concerns() {
    become_cpu();
    let (a, _) = process("wake-a");
    let (b, _) = process("wake-b");
    let (ra, _wa) = pipe_fds(&a);
    // `b` waits in `sigsuspend`, which only a signal for it can end.
    put(&b, DATA + 0x200, &0u64.to_ne_bytes());
    let (ta, result_a) = block_in(&a, move |p| call(p, Sys::Read, &[ra, DATA + 0x100, 8]));
    let (tb, result_b) = block_in(&b, move |p| call(p, Sys::RtSigsuspend, &[DATA + 0x200, 8]));
    // A signal for `a` wakes `a`'s reader at once (it is made ready by the
    // sender), and leaves `b`'s asleep.
    signal::send(&a, SIGTERM, a.pid()).unwrap();
    assert_eq!(tb.state(), osmium_sched::TaskState::Blocked, "another process's sleeper is not woken");
    assert_ne!(ta.state(), osmium_sched::TaskState::Blocked);
    ta.join();
    assert_eq!(result_a.load(Ordering::SeqCst), EINTR);
    assert_eq!(result_b.load(Ordering::SeqCst), PENDING);
    signal::send(&b, SIGKILL, b.pid()).unwrap();
    tb.join();
    assert_eq!(result_b.load(Ordering::SeqCst), EINTR);
}

/// Two descriptors from a call that fills an `int[2]` at `DATA`.
fn fd_pair(p: &Process) -> (u64, u64) {
    let b = get(p, DATA, 8);
    (u32::from_ne_bytes(b[..4].try_into().unwrap()) as u64, u32::from_ne_bytes(b[4..].try_into().unwrap()) as u64)
}

#[test]
fn a_change_to_one_file_wakes_only_the_calls_watching_it() {
    use osmium_sched::TaskState::Blocked;
    become_cpu();
    let poll_on = |p: &Process, fd: u64| {
        let pollfd: Vec<u8> = (fd as i32).to_ne_bytes().into_iter().chain(1u16.to_ne_bytes()).chain([0; 2]).collect();
        put(p, DATA + 0x100, &pollfd);
    };
    // `a` polls its pipe; `b` polls another pipe, `c` waits in epoll on
    // that pipe and `d` reads a socket pair.
    let (a, _) = process("ready-a");
    let (ra, wa) = pipe_fds(&a);
    poll_on(&a, ra);
    let (ta, result_a) = block_in(&a, |p| call(p, Sys::Ppoll, &[DATA + 0x100, 1, 0, 0, 0]));
    let (b, _) = process("ready-b");
    let (rb, wb) = pipe_fds(&b);
    poll_on(&b, rb);
    let (tb, result_b) = block_in(&b, |p| call(p, Sys::Ppoll, &[DATA + 0x100, 1, 0, 0, 0]));
    let ep = call(&b, Sys::EpollCreate1, &[0]) as u64;
    #[cfg(target_arch = "x86_64")]
    let event = [1u32.to_ne_bytes().as_slice(), &7u64.to_ne_bytes()].concat();
    #[cfg(not(target_arch = "x86_64"))]
    let event = [1u32.to_ne_bytes().as_slice(), &[0; 4], &7u64.to_ne_bytes()].concat();
    put(&b, DATA + 0x400, &event);
    assert_eq!(call(&b, Sys::EpollCtl, &[ep, 1, rb, DATA + 0x400]), 0);
    let (tc, result_c) = block_in(&b, move |p| call(p, Sys::EpollPwait, &[ep, DATA + 0x500, 4, u64::MAX, 0, 8]));
    let (d, _) = process("ready-d");
    assert_eq!(call(&d, Sys::Socketpair, &[1, 1, 0, DATA]), 0);
    let (s0, s1) = fd_pair(&d);
    let (td, result_d) = block_in(&d, move |p| call(p, Sys::Read, &[s0, DATA + 0x200, 8]));

    // Data in `a`'s pipe wakes `a`'s poll alone.
    put(&a, DATA + 0x300, b"x");
    assert_eq!(call(&a, Sys::Write, &[wa, DATA + 0x300, 1]), 1);
    assert_ne!(ta.state(), Blocked, "the poller of the pipe written to wakes");
    for (t, what) in [(&tb, "a poll of another pipe"), (&tc, "an epoll of another pipe"), (&td, "a socket read")] {
        assert_eq!(t.state(), Blocked, "{what} sleeps on");
    }
    ta.join();
    assert_eq!(result_a.load(Ordering::SeqCst), 1);

    // `b`'s pipe wakes both its waiters, and the socket pair its reader.
    put(&b, DATA + 0x300, b"y");
    assert_eq!(call(&b, Sys::Write, &[wb, DATA + 0x300, 1]), 1);
    assert_eq!(td.state(), Blocked);
    put(&d, DATA + 0x300, b"z");
    assert_eq!(call(&d, Sys::Write, &[s1, DATA + 0x300, 1]), 1);
    for t in [&tb, &tc, &td] {
        t.join();
    }
    assert_eq!(result_b.load(Ordering::SeqCst), 1);
    assert_eq!(result_c.load(Ordering::SeqCst), 1);
    assert_eq!(result_d.load(Ordering::SeqCst), 1);
}

#[test]
fn a_file_without_a_queue_is_polled_again_on_a_tick() {
    become_cpu();
    let (p, _) = process("ready-tick");
    // A file with no queue of its own: `poll` reports whatever the test says.
    struct Flag(core::sync::atomic::AtomicU32);
    impl osmium_fs::File for Flag {
        fn stat(&self) -> osmium_fs::Stat {
            osmium_fs::Stat::default()
        }
        fn poll(&self) -> u32 {
            self.0.load(Ordering::SeqCst)
        }
    }
    let flag = Arc::new(Flag(core::sync::atomic::AtomicU32::new(0)));
    let f = p.files().lock().insert(crate::fd::OpenFile::new(flag.clone(), crate::fd::Access::RW)).unwrap();
    let pollfd: Vec<u8> = f.to_ne_bytes().into_iter().chain(1u16.to_ne_bytes()).chain([0; 2]).collect();
    put(&p, DATA + 0x100, &pollfd);
    let (task, result) = block_in(&p, |p| call(p, Sys::Ppoll, &[DATA + 0x100, 1, 0, 0, 0]));
    // Its readiness changes without a word; a tick (which other tests may
    // also give at any time) makes the poll look again.
    flag.0.store(1, Ordering::SeqCst);
    crate::poll::tick();
    task.join();
    assert_eq!(result.load(Ordering::SeqCst), 1);
}
