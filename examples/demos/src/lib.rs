//! Scheduler demos shared by the example kernels. Each prints one line that
//! `scripts/check.sh` looks for.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use osmium::hal::println;
use osmium::sched::timer::TimerQueue;
use osmium::sched::{Mutex, TaskBuilder};

/// What the demos need from the kernel.
pub struct Env {
    /// Timer callbacks, processed from the timer interrupt.
    pub timers: &'static TimerQueue,
    /// Timer interrupts so far.
    pub ticks: &'static AtomicU64,
    /// Monotonic time in nanoseconds.
    pub now_ns: fn() -> u64,
}

/// Runs every demo in turn.
pub fn run_all(env: &Env) {
    cooperative();
    mutex();
    preemption(env);
    sleep(env);
}

/// Tasks that yield to each other interleave in FIFO order.
pub fn cooperative() {
    let tasks: Vec<_> = ["A", "B", "C"]
        .into_iter()
        .map(|name| {
            TaskBuilder::new(name).spawn(move || {
                for i in 0..2 {
                    println!("[task]  {name}{i}");
                    osmium::sched::yield_now();
                }
            })
        })
        .collect();
    for t in tasks {
        t.join();
    }
}

/// A sleeping mutex keeps its data consistent across yields.
pub fn mutex() {
    static COUNTER: Mutex<u64> = Mutex::new(0);
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            TaskBuilder::new("adder").spawn(|| {
                for _ in 0..1000 {
                    let mut g = COUNTER.lock();
                    let v = *g;
                    osmium::sched::yield_now();
                    *g = v + 1;
                }
            })
        })
        .collect();
    for t in tasks {
        t.join();
    }
    println!("[mutex] 4 tasks x 1000 increments across yields = {}", *COUNTER.lock());
}

/// A task that never yields is preempted by the timer interrupt; otherwise
/// the task it waits for could never run on this CPU.
pub fn preemption(env: &Env) {
    static FLAG: AtomicBool = AtomicBool::new(false);
    let start = env.ticks.load(Ordering::Relaxed);
    let cpu = osmium::arch::cpu::current_id();
    let spinner = TaskBuilder::new("spinner").cpu(cpu).spawn(|| {
        while !FLAG.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    });
    let setter = TaskBuilder::new("setter").cpu(cpu).spawn(|| FLAG.store(true, Ordering::Release));
    spinner.join();
    setter.join();
    println!("[preempt] busy-looping task was preempted after {} ticks", env.ticks.load(Ordering::Relaxed) - start);
}

/// A task sleeps on the timer queue.
pub fn sleep(env: &Env) {
    let (timers, now_ns) = (env.timers, env.now_ns);
    let t = TaskBuilder::new("sleeper").spawn(move || {
        let t0 = now_ns();
        timers.sleep_until(t0 + 50_000_000);
        println!("[timer] slept {} ms (asked for 50)", (now_ns() - t0) / 1_000_000);
    });
    t.join();
}
