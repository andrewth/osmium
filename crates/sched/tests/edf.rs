#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Earliest-deadline-first scheduling with real context switches on the
//! host: each test thread acts as one CPU. A test binary of its own, since a
//! process has one scheduler.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use osmium_sched::{EdfScheduler, TaskBuilder, TaskState};

static SCHED: EdfScheduler = EdfScheduler::new(2);

/// Makes the calling test thread a fresh CPU with a unique id.
fn become_cpu() {
    static NEXT: AtomicUsize = AtomicUsize::new(1);
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| osmium_sched::inject_scheduler(&SCHED));
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: each test thread gets a distinct id below MAX_CPUS.
    unsafe { osmium_arch::cpu::set_current_id(id) };
    osmium_sched::init_cpu();
}

fn builder(name: &'static str, deadline: u64) -> TaskBuilder {
    TaskBuilder::new(name).stack_size(256 * 1024).cpu(osmium_arch::cpu::current_id()).deadline(deadline)
}

type Log = Arc<StdMutex<Vec<&'static str>>>;

fn logger(log: &Log, name: &'static str) -> impl FnOnce() + Send + 'static {
    let log = log.clone();
    move || log.lock().unwrap().push(name)
}

#[test]
fn tasks_run_in_deadline_order() {
    become_cpu();
    let log = Log::default();
    let tasks = [("late", 50), ("none", 0), ("soon", 5), ("mid", 20)]
        .map(|(name, deadline)| builder(name, deadline).spawn(logger(&log, name)));
    // The three with a deadline run earliest first, then the boot task
    // (which has none) and the other one without, in arrival order: the
    // other one arrived before the boot task yielded.
    osmium_sched::yield_now();
    assert_eq!(*log.lock().unwrap(), ["soon", "mid", "late", "none"]);
    for t in &tasks {
        t.join();
        assert_eq!(t.state(), TaskState::Exited);
    }
    assert_eq!(*log.lock().unwrap(), ["soon", "mid", "late", "none"]);
}

#[test]
fn an_earlier_deadline_preempts_at_the_next_tick() {
    become_cpu();
    let log = Log::default();
    let l = log.clone();
    let late = builder("late", 100).spawn(move || {
        l.lock().unwrap().push("late starts");
        // Released while `late` runs: it is queued, not run...
        let urgent = builder("urgent", 3).spawn(logger(&l, "urgent"));
        l.lock().unwrap().push("late still runs");
        // ...until a tick finds a queued task with an earlier deadline.
        osmium_sched::tick();
        osmium_sched::preempt_if_needed();
        l.lock().unwrap().push("late resumes");
        urgent.join();
    });
    late.join();
    assert_eq!(*log.lock().unwrap(), ["late starts", "late still runs", "urgent", "late resumes"]);
}
