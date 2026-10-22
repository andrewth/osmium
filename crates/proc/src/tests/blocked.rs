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
fn become_cpu() {
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
fn block_in(
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
