// SPDX-License-Identifier: GPL-2.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Futexes against the memory system: operations racing `fork` and
//! `munmap` on other CPUs never fault, do file I/O or shoot down other CPUs
//! under a spin lock; process-shared futexes meet across forked shared
//! memory; and priority-inheritance locks work on copy-on-write pages.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::blocked::become_cpu;
use super::restart::{lock_in, op, thread_at, word};
use super::smp::{install, masked_flush_of};
use super::*;
use crate::futex::{self, Ctx, Waiter};

const P: u64 = 0x1000;
const WAKE: u64 = 1;
const REQUEUE: u64 = 3;
const WAKE_OP: u64 = 5;
const UNLOCK_PI: u64 = 7;
const PRIVATE: u64 = 128;
/// `FUTEX_OP_ADD` with argument 1, comparison `EQ 0` (never true here).
const ADD_ONE: u64 = (1 << 28) | (1 << 12);

/// A file in memory that notes any I/O it gets with interrupts masked (that
/// is, under a spin lock, where blocking I/O would be fatal).
#[derive(Default)]
struct Backing {
    data: StdMutex<Vec<u8>>,
    masked: AtomicBool,
    reads: AtomicUsize,
}

impl Backing {
    fn note(&self) {
        if !osmium_arch::irq::are_enabled() {
            self.masked.store(true, Ordering::SeqCst);
        }
    }
}

impl File for Backing {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.note();
        self.reads.fetch_add(1, Ordering::SeqCst);
        let d = self.data.lock().unwrap();
        let rest = d.get(off as usize..).unwrap_or(&[]);
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(n)
    }
    fn write(&self, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        self.note();
        let mut d = self.data.lock().unwrap();
        let end = off as usize + buf.len();
        if d.len() < end {
            d.resize(end, 0);
        }
        d[off as usize..end].copy_from_slice(buf);
        Ok(buf.len())
    }
    fn stat(&self) -> Stat {
        Stat { ino: 91, size: self.data.lock().unwrap().len() as u64, mode: 0o644, nlink: 1, ..Stat::default() }
    }
}

fn backing(pages: u64) -> Arc<Backing> {
    Arc::new(Backing { data: StdMutex::new(alloc::vec![0; (pages * P) as usize]), ..Backing::default() })
}

fn map_shared(p: &Process, f: &Arc<Backing>, va: u64, len: u64) {
    let file: Arc<dyn File> = f.clone();
    let map = crate::FileMapping { file, offset: 0, shared: true, prot: MapFlags::RW, writable: true };
    p.memory().map_file(va, len, map).unwrap();
}

fn futex_call(p: &Process, a: [u64; 6]) -> i64 {
    super::sigthread::callt(p, &p.leader(), Sys::Futex, &a)
}

fn u32_at(p: &Process, va: u64) -> u32 {
    u32::from_ne_bytes(get(p, va, 4).try_into().unwrap())
}

#[test]
fn the_futex_word_is_never_copied_or_loaded_under_the_lock() {
    let (p, frames) = process("futex-word");
    let mem = p.memory();
    let va = DATA + 0x2000;
    put(&p, va, &7u32.to_ne_bytes());
    let child = mem.fork().unwrap();
    let live = frames.live();
    let mut seen = None;
    // A load from a shared copy-on-write page is fine as it is...
    assert_eq!(mem.with_word(va, false, &mut |w, _| seen = Some(w.load(Ordering::SeqCst))), Ok(true));
    assert_eq!(seen, Some(7));
    // ...a store is refused, rather than copying the page under the caller's lock.
    let mut ran = false;
    assert_eq!(mem.with_word(va, true, &mut |_, _| ran = true), Ok(false));
    assert!(!ran);
    assert_eq!(frames.live(), live, "nothing was copied");
    mem.prefault(va, 4, true).unwrap();
    assert_eq!(
        mem.with_word(va, true, &mut |w, _| {
            w.fetch_add(1, Ordering::SeqCst);
        }),
        Ok(true)
    );
    assert_eq!(u32_at(&p, va), 8);
    let mut b = [0; 4];
    child.read(va, &mut b).unwrap();
    assert_eq!(u32::from_ne_bytes(b), 7, "the child keeps its copy");

    // A file page that is not loaded yet is not read under the lock either.
    let f = backing(1);
    let fva = 0x50_0000;
    map_shared(&p, &f, fva, P);
    assert_eq!(mem.with_word(fva, false, &mut |_, _| ran = true), Ok(false));
    assert_eq!(f.reads.load(Ordering::SeqCst), 0);
    // And addresses that can never work fail outright.
    assert_eq!(mem.with_word(0x7777_0000, false, &mut |_, _| ()), Err(Errno::EFAULT));
    mem.map_anon(0x51_0000, P, MapFlags::READ).unwrap();
    assert_eq!(mem.with_word(0x51_0000, true, &mut |_, _| ()), Err(Errno::EFAULT), "read-only");
    assert_eq!(mem.with_word(va + 2, false, &mut |_, _| ()), Err(Errno::EINVAL), "unaligned");
}

#[test]
fn futex_ops_racing_fork_never_shoot_down_under_a_lock() {
    install();
    let (p, _) = process("futex-fork-race");
    let va = 0x7100_0000;
    p.memory().map_anon(va, P, MapFlags::RW).unwrap();
    const ROUNDS: u64 = 3000;
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        // Forks over and over, keeping a few children alive so the page's
        // frame stays shared and every store must copy it.
        s.spawn(|| {
            let mut kids = std::collections::VecDeque::new();
            while !done.load(Ordering::SeqCst) {
                kids.push_back(p.memory().fork().unwrap());
                if kids.len() > 3 {
                    kids.pop_front();
                }
            }
        });
        for _ in 0..ROUNDS {
            // *va += 1, and wake whoever waits on it.
            assert_eq!(futex_call(&p, [va + 4, WAKE_OP, 1, 0, va, ADD_ONE]), 0);
        }
        done.store(true, Ordering::SeqCst);
    });
    assert_eq!(u32_at(&p, va) as u64, ROUNDS, "each WAKE_OP added exactly once");
    assert!(!masked_flush_of(va), "a shootdown was sent with interrupts masked");
}

#[test]
fn futex_ops_racing_munmap_never_read_the_file_under_a_lock() {
    install();
    let (p, _) = process("futex-munmap-race");
    let f = backing(1);
    let va = 0x52_0000;
    map_shared(&p, &f, va, P);
    let done = AtomicBool::new(false);
    std::thread::scope(|s| {
        // Drops the page (writing it back) and maps the file again, so the
        // next touch reads it in.
        s.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                p.memory().munmap(va, P).unwrap();
                map_shared(&p, &f, va, P);
            }
        });
        for _ in 0..2000 {
            // EFAULT when it lands in the gap between munmap and mmap.
            let r = futex_call(&p, [va + 4, WAKE_OP, 1, 0, va, ADD_ONE]);
            assert!(r == 0 || r == -(Errno::EFAULT.0 as i64), "{r}");
            let r = futex_call(&p, [va, WAKE, 1, 0, 0, 0]);
            assert!(r == 0 || r == -(Errno::EFAULT.0 as i64), "{r}");
        }
        done.store(true, Ordering::SeqCst);
    });
    assert!(f.reads.load(Ordering::SeqCst) > 0, "the page was read in again");
    assert!(!f.masked.load(Ordering::SeqCst), "file I/O ran with interrupts masked");
    assert!(!masked_flush_of(va), "a shootdown was sent with interrupts masked");
}

/// A waiter at `addr` in `p`, queued if the word holds `val`.
fn waiter(p: &Process, addr: u64, val: u32, private: bool) -> core::pin::Pin<Box<Waiter>> {
    let w = Box::pin(Waiter::new(u32::MAX));
    w.as_ref().enqueue(&Ctx::new(p, private), addr, val).unwrap();
    w
}

fn woken(w: &core::pin::Pin<Box<Waiter>>) -> bool {
    w.woken.load(Ordering::SeqCst)
}

#[test]
fn process_shared_futexes_meet_in_memory_a_fork_shares() {
    platform();
    let (p, _) = process("futex-pshared");
    let f = backing(1);
    let (a1, a2) = (0x53_0000, 0x53_0004);
    map_shared(&p, &f, a1, P);
    put(&p, a1, &1u32.to_ne_bytes());
    let c = fork_child(&p);
    assert_eq!(futex::key_for_test(&p, a1, false), futex::key_for_test(&c, a1, false), "keyed by the frame");
    assert_ne!(futex::key_for_test(&p, a1, true), futex::key_for_test(&c, a1, true), "private: by the space");
    assert_ne!(futex::key_for_test(&p, DATA, false), futex::key_for_test(&c, DATA, false), "copy-on-write");

    // The child waits, the parent wakes.
    let w = waiter(&c, a1, 1, false);
    assert_eq!(futex_call(&p, [a1, WAKE | PRIVATE, 1, 0, 0, 0]), 0, "a private wake stays in its space");
    assert_eq!(futex_call(&p, [a1, WAKE, 1, 0, 0, 0]), 1);
    assert!(woken(&w));
    // A private wait is only for the child's own threads.
    let w = waiter(&c, a1, 1, true);
    assert_eq!(futex_call(&p, [a1, WAKE | PRIVATE, 1, 0, 0, 0]), 0);
    assert_eq!(futex_call(&p, [a1, WAKE, 1, 0, 0, 0]), 0);
    assert_eq!(futex_call(&c, [a1, WAKE | PRIVATE, 1, 0, 0, 0]), 1);
    assert!(woken(&w));

    // The parent moves the child's waiter to a2, then WAKE_OP there wakes it
    // and changes the shared word, which the child sees.
    let w = waiter(&c, a1, 1, false);
    assert_eq!(futex_call(&p, [a1, REQUEUE, 0, 1, a2, 0]), 1);
    assert!(!woken(&w));
    assert_eq!(futex_call(&p, [a1, WAKE, 1, 0, 0, 0]), 0, "it is not at a1 any more");
    assert_eq!(futex_call(&p, [DATA, WAKE_OP, 0, 1, a2, ADD_ONE | 5]), 0, "the old value is not 5");
    assert_eq!(futex_call(&p, [a2, WAKE_OP, 1, 0, a2, ADD_ONE]), 1);
    assert!(woken(&w));
    assert_eq!(u32_at(&c, a2), 2);

    // Private memory is not shared: a parent's wake does not reach the child.
    let w = waiter(&c, DATA, u32_at(&c, DATA), false);
    assert_eq!(futex_call(&p, [DATA, WAKE, 1, 0, 0, 0]), 0);
    assert_eq!(futex_call(&c, [DATA, WAKE, 1, 0, 0, 0]), 1);
    assert!(woken(&w));
}

#[test]
fn priority_inheritance_works_on_copy_on_write_pages() {
    install();
    become_cpu();
    platform();
    let (p, _) = process("futex-pi-cow");
    let addr = 0x7200_0000;
    p.memory().map_anon(addr, P, MapFlags::RW).unwrap();
    let (a, _) = thread_at(&p, &p.leader(), 1, 1);
    let (b, b_task) = thread_at(&p, &p.leader(), 2, 9);
    let (c, _) = thread_at(&p, &p.leader(), 3, 5);
    const TRYLOCK_PI: u64 = 8;
    let waiters = 0x8000_0000;
    let forks = || (0..2).map(|_| p.memory().fork().unwrap()).collect::<Vec<_>>();

    let kids = forks();
    assert_eq!(op(&p, &a, addr, TRYLOCK_PI), 0, "on a copy-on-write page");
    assert_eq!(word(&p, addr), a.tid());
    let mut b4 = [0; 4];
    kids[0].read(addr, &mut b4).unwrap();
    assert_eq!(u32::from_ne_bytes(b4), 0, "the copies keep the old word");

    // b blocks: setting FUTEX_WAITERS copies the page first.
    let kids = forks();
    let (tb, rb) = lock_in(&p, &b, addr);
    assert_eq!(word(&p, addr), a.tid() | waiters);
    let (tc, rc) = lock_in(&p, &c, addr);

    // Unlocking hands over through a freshly shared page too.
    let more = forks();
    assert_eq!(op(&p, &a, addr, UNLOCK_PI), 0);
    tb.join();
    assert_eq!(rb.load(Ordering::SeqCst), 0);
    assert_eq!(word(&p, addr), b.tid() | waiters, "c still waits");
    assert_eq!(b_task.priority(), 9);

    // b dies owning it: the robust-list path hands it to c, on a shared page again.
    let last = forks();
    assert!(crate::futex_pi::owner_died(&p, b.tid(), addr));
    tc.join();
    assert_eq!(rc.load(Ordering::SeqCst), 0);
    assert_eq!(word(&p, addr), c.tid() | 0x4000_0000);
    drop((kids, more, last));
    assert!(!masked_flush_of(addr), "a shootdown was sent with interrupts masked");
}

#[test]
fn timers_wake_only_the_buckets_of_expired_sleepers() {
    // Tiny deadlines that no other test's clock is near.
    let t1 = futex::timer_for_test(2, 5);
    let t2 = futex::timer_for_test(4, 9);
    assert_eq!(futex::expire_for_test(1) & (1 << 5 | 1 << 9), 0, "nothing is due yet");
    assert!(!t1.has_fired() && !t2.has_fired());
    let due = futex::expire_for_test(2);
    assert!(due & (1 << 5) != 0 && due & (1 << 9) == 0, "{due:#x}");
    assert!(t1.has_fired() && !t2.has_fired());
    assert_eq!(futex::expire_for_test(3) & (1 << 5 | 1 << 9), 0, "a fired timer is gone");
    drop(t2);
    assert_eq!(futex::expire_for_test(4) & (1 << 9), 0, "a dropped timer is gone");
}

/// A futex sleep in bucket `b` that counts each look at its condition, and
/// returns 0 once `go` is set, or the negated errno.
fn counted_sleep(
    p: &Arc<Process>,
    b: usize,
    looks: &Arc<AtomicUsize>,
    go: &Arc<AtomicBool>,
) -> (Arc<osmium_sched::Task>, Arc<core::sync::atomic::AtomicI64>) {
    let (looks, go) = (looks.clone(), go.clone());
    super::blocked::block_in(p, move |p| {
        let th = crate::thread::current_thread(p);
        let ready = || {
            looks.fetch_add(1, Ordering::SeqCst);
            go.load(Ordering::SeqCst)
        };
        match futex::sleep_on(p, &th, None, &|| b, &ready) {
            Ok(()) => 0,
            Err(e) => -(e.0 as i64),
        }
    })
}

#[test]
fn a_signal_wakes_only_the_futex_sleeper_it_is_for() {
    use crate::signal::sig::{SIGKILL, SIGUSR1};
    become_cpu();
    let b = 17;
    let (quiet, _) = process("futex-quiet");
    let (target, _) = process("futex-target");
    let (looks, go) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicBool::new(false)));
    let (quiet_task, quiet_result) = counted_sleep(&quiet, b, &looks, &go);
    let (target_task, target_result) =
        counted_sleep(&target, b, &Arc::new(AtomicUsize::new(0)), &Arc::new(AtomicBool::new(false)));
    let before = looks.load(Ordering::SeqCst);
    // Both sleep in bucket `b`. A signal for one, and its process ending, leave the other asleep.
    crate::signal::send(&target, SIGUSR1, target.pid()).unwrap();
    target_task.join();
    assert_eq!(target_result.load(Ordering::SeqCst), -(Errno::EINTR.0 as i64));
    crate::signal::kill_group(&target, ExitStatus::Signal(SIGKILL));
    osmium_sched::yield_now();
    assert_eq!(looks.load(Ordering::SeqCst), before, "the other sleeper was not woken");
    assert_eq!(quiet_result.load(Ordering::SeqCst), i64::MIN, "and still sleeps");
    // A wake of its bucket still reaches it.
    go.store(true, Ordering::SeqCst);
    futex::wake_bucket(b);
    quiet_task.join();
    assert_eq!(quiet_result.load(Ordering::SeqCst), 0);
}
