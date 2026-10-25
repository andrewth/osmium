#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Real context switches on the host: each test thread acts as one CPU.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use osmium_sched::{FifoScheduler, Mutex, Semaphore, TaskBuilder, TaskState, WaitQueue};

static SCHED: FifoScheduler = FifoScheduler::new(2).with_stealing();

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

fn builder(name: &'static str) -> TaskBuilder {
    // Debug builds of std formatting need more than the 64 KiB default.
    // Pinned, so other tests' CPUs (threads) never steal these tasks.
    TaskBuilder::new(name).stack_size(256 * 1024).cpu(osmium_arch::cpu::current_id())
}

#[test]
fn yield_interleaves_tasks() {
    become_cpu();
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let tasks: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|name| {
            let log = log.clone();
            builder(name).spawn(move || {
                for i in 0..3 {
                    log.lock().unwrap().push(format!("{name}{i}"));
                    osmium_sched::yield_now();
                }
            })
        })
        .collect();
    for t in &tasks {
        t.join();
        assert_eq!(t.state(), TaskState::Exited);
    }
    assert_eq!(*log.lock().unwrap(), ["a0", "b0", "a1", "b1", "a2", "b2"]);
}

#[test]
fn fp_state_follows_its_task() {
    use osmium_arch::fp::{FpState, host};
    become_cpu();
    // SAFETY: hosted, so the FP registers are a per-thread variable.
    assert!(unsafe { osmium_arch::fp::enable() });
    let ok = Arc::new(AtomicUsize::new(0));
    let tasks: Vec<_> = [1u64, 2]
        .into_iter()
        .map(|v| {
            let ok = ok.clone();
            builder("fp").fp_state(FpState::new()).spawn(move || {
                host::use_fp();
                assert_eq!(host::live(), 0, "a new task starts from FpState::new");
                host::use_fp();
                host::set_live(v);
                for _ in 0..3 {
                    osmium_sched::yield_now();
                    host::use_fp();
                    assert_eq!(host::live(), v);
                    // A task without FP state runs between the two.
                    builder("no-fp").spawn(|| {}).join();
                }
                ok.fetch_add(1, Ordering::Relaxed);
            })
        })
        .collect();
    for t in &tasks {
        t.join();
    }
    assert_eq!(ok.load(Ordering::Relaxed), 2);
}

#[test]
fn sve_state_task_runs_and_hosted_enable_reports_none() {
    become_cpu();
    // SAFETY: hosted, so there are no SVE registers to disturb.
    assert_eq!(unsafe { osmium_arch::fp::sve::enable() }, None);
    assert!(!osmium_arch::fp::avx_enabled());
    let n = Arc::new(AtomicUsize::new(0));
    let tasks: Vec<_> = (0..2)
        .map(|_| {
            let n = n.clone();
            // The hosted SveState save/restore are no-ops, so this checks the
            // builder and the switch path only.
            builder("sve").sve_state().spawn(move || {
                for _ in 0..3 {
                    osmium_sched::yield_now();
                }
                n.fetch_add(1, Ordering::Relaxed);
            })
        })
        .collect();
    for t in &tasks {
        t.join();
    }
    assert_eq!(n.load(Ordering::Relaxed), 2);
}

#[test]
fn exited_task_is_freed() {
    become_cpu();
    let payload = Arc::new(());
    let p = payload.clone();
    let t = builder("short").spawn(move || drop(p));
    t.join();
    let weak = Arc::downgrade(&t);
    drop(t);
    // The CPU state may hold the last reference until the next switch.
    osmium_sched::yield_now();
    assert!(weak.upgrade().is_none(), "task (and its stack) freed");
    assert_eq!(Arc::strong_count(&payload), 1, "closure dropped");
}

#[test]
fn wait_queue_and_mutex() {
    become_cpu();
    let mutex = Arc::new(Mutex::new(0u32));
    let ready = Arc::new((AtomicUsize::new(0), WaitQueue::new()));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let (mutex, ready) = (mutex.clone(), ready.clone());
            builder("worker").spawn(move || {
                // Wait for the go signal.
                ready.1.wait_until(|| (ready.0.load(Ordering::Acquire) == 1).then_some(()));
                for _ in 0..100 {
                    let mut g = mutex.lock();
                    let v = *g;
                    osmium_sched::yield_now(); // hold the lock across a switch
                    *g = v + 1;
                }
            })
        })
        .collect();
    // Let the workers block.
    osmium_sched::yield_now();
    assert_eq!(ready.1.len(), 4);
    ready.0.store(1, Ordering::Release);
    assert_eq!(ready.1.wake_all(), 4);
    for w in &workers {
        w.join();
    }
    assert_eq!(*mutex.lock(), 400);
}

#[test]
fn semaphore_producer_consumer() {
    become_cpu();
    let items = Arc::new((Semaphore::new(0), std::sync::Mutex::new(Vec::new())));
    let consumer = {
        let items = items.clone();
        builder("consumer").spawn(move || {
            for _ in 0..10 {
                items.0.acquire();
                let v = items.1.lock().unwrap().remove(0);
                assert!(v < 10);
            }
        })
    };
    for i in 0..10 {
        items.1.lock().unwrap().push(i);
        items.0.release();
        if i % 3 == 0 {
            osmium_sched::yield_now();
        }
    }
    consumer.join();
    assert_eq!(items.0.available(), 0);
}

#[test]
fn tick_preemption() {
    become_cpu();
    let spins = Arc::new(AtomicUsize::new(0));
    let s = spins.clone();
    let spinner = builder("spinner").spawn(move || {
        // Never yields voluntarily; only preemption lets the boot task run.
        while s.load(Ordering::Relaxed) < usize::MAX {
            s.fetch_add(1, Ordering::Relaxed);
            // Stand-in for a timer interrupt arriving.
            osmium_sched::tick();
            osmium_sched::preempt_if_needed();
            if s.load(Ordering::Relaxed) >= 50 {
                break;
            }
        }
    });
    // Run the spinner; it gets preempted after its 2-tick slice and we resume.
    osmium_sched::yield_now();
    let seen = spins.load(Ordering::Relaxed);
    assert!((1..50).contains(&seen), "preempted mid-loop after {seen} iterations");
    spinner.join();
    assert_eq!(spins.load(Ordering::Relaxed), 50);
}

#[test]
fn timer_sleep() {
    become_cpu();
    let timers = Arc::new(osmium_sched::timer::TimerQueue::new());
    let woke = Arc::new(AtomicUsize::new(0));
    let sleeper = {
        let (timers, woke) = (timers.clone(), woke.clone());
        builder("sleeper").spawn(move || {
            timers.sleep_until(100);
            woke.store(1, Ordering::Release);
        })
    };
    osmium_sched::yield_now();
    assert_eq!(woke.load(Ordering::Acquire), 0);
    assert_eq!(timers.process(50), 0);
    assert_eq!(timers.process(100), 1);
    sleeper.join();
    assert_eq!(woke.load(Ordering::Acquire), 1);
}

#[test]
fn migration_between_cpus() {
    static HOOK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    fn hook(_cpu: usize) {
        HOOK_CALLS.fetch_add(1, Ordering::Relaxed);
    }
    become_cpu();
    osmium_sched::set_remote_wake_hook(hook);
    let home = osmium_arch::cpu::current_id();

    // A second host thread acts as another CPU that just keeps scheduling.
    let (tx, rx) = std::sync::mpsc::channel();
    let other = std::thread::spawn(move || {
        become_cpu();
        tx.send(osmium_arch::cpu::current_id()).unwrap();
        while !DONE.load(Ordering::Acquire) {
            osmium_sched::yield_now();
            std::thread::yield_now();
        }
    });
    let away = rx.recv().unwrap();

    let visited = Arc::new(std::sync::Mutex::new(Vec::new()));
    let v = visited.clone();
    let hopper = builder("hopper").spawn(move || {
        for _ in 0..50 {
            let here = osmium_arch::cpu::current_id();
            v.lock().unwrap().push(here);
            // Requeue on the other CPU; it may pick us up while this CPU is
            // still saving our registers, which `on_cpu` must handle.
            osmium_sched::current().set_cpu(if here == home { away } else { home });
            osmium_sched::yield_now();
        }
    });
    hopper.join();
    DONE.store(true, Ordering::Release);
    other.join().unwrap();

    let visited = visited.lock().unwrap();
    let expected: Vec<usize> = (0..50).map(|i| if i % 2 == 0 { home } else { away }).collect();
    assert_eq!(*visited, expected, "alternated between the two CPUs");
    assert!(HOOK_CALLS.load(Ordering::Relaxed) >= 50, "every hop notified the target CPU");
}

#[test]
fn task_data() {
    become_cpu();
    #[derive(Debug, PartialEq)]
    struct AddressSpace(u64);
    let t = builder("with-data").data(AddressSpace(0x1234)).build(|| {});
    assert_eq!(t.data::<AddressSpace>(), Some(&AddressSpace(0x1234)));
    assert_eq!(t.data::<u32>(), None, "wrong type");
    assert_eq!(t.set_data(7u32), Err(7), "already set");
    let u = builder("later").build(|| {});
    assert!(u.data::<u32>().is_none());
    u.set_data(9u32).unwrap();
    assert_eq!(u.data::<u32>(), Some(&9));
}

#[test]
fn idle_cpu_steals_unpinned_work() {
    static DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static MOVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    become_cpu();
    let home = osmium_arch::cpu::current_id();

    static GATE: WaitQueue = WaitQueue::new();
    // Another "CPU" with nothing of its own to run: its boot task blocks, so
    // its idle task runs, and an idle CPU steals.
    let thief = std::thread::spawn(move || {
        become_cpu();
        GATE.wait_until(|| DONE.load(Ordering::Acquire).then_some(()));
    });

    // Wait until the thief CPU is idle (its boot task blocked on the gate).
    while GATE.is_empty() {
        std::thread::yield_now();
    }

    let ran_on = Arc::new(std::sync::Mutex::new(Vec::new()));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let ran_on = ran_on.clone();
            // Unpinned (no .cpu()): starts here, but any CPU may run it.
            TaskBuilder::new("work").stack_size(256 * 1024).spawn(move || {
                // Keep going until some task has run elsewhere (the host
                // decides when the thief thread runs), then a little longer.
                // Bounded either way.
                for i in 0..1_000_000 {
                    let here = osmium_arch::cpu::current_id();
                    ran_on.lock().unwrap().push(here);
                    if here != home {
                        MOVED.store(true, Ordering::Release);
                    }
                    if i >= 20 && MOVED.load(Ordering::Acquire) {
                        break;
                    }
                    osmium_sched::yield_now();
                }
            })
        })
        .collect();
    for t in &tasks {
        t.join();
    }
    DONE.store(true, Ordering::Release);
    GATE.wake_all();
    thief.join().unwrap();

    let ran_on = ran_on.lock().unwrap();
    assert!(ran_on.iter().any(|&c| c != home), "some work ran on another CPU");
}

#[test]
fn mutex_with_stealing_across_cpus() {
    static GATE: WaitQueue = WaitQueue::new();
    static DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    become_cpu();
    let thieves: Vec<_> = (0..3)
        .map(|_| {
            std::thread::spawn(|| {
                become_cpu();
                GATE.wait_until(|| DONE.load(Ordering::Acquire).then_some(()));
            })
        })
        .collect();
    while GATE.len() < 3 {
        std::thread::yield_now();
    }
    let mutex = Arc::new(Mutex::new(0u32));
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let mutex = mutex.clone();
            // Unpinned: idle CPUs steal them while they contend.
            TaskBuilder::new("adder").stack_size(256 * 1024).spawn(move || {
                for _ in 0..500 {
                    let mut g = mutex.lock();
                    let v = *g;
                    osmium_sched::yield_now();
                    *g = v + 1;
                }
            })
        })
        .collect();
    for w in &workers {
        w.join();
    }
    DONE.store(true, Ordering::Release);
    GATE.wake_all();
    for t in thieves {
        t.join().unwrap();
    }
    assert_eq!(*mutex.lock(), 2000);
}

#[test]
fn woken_task_is_placed_on_an_idle_cpu() {
    static GATE: WaitQueue = WaitQueue::new();
    static DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    become_cpu();
    let home = osmium_arch::cpu::current_id();
    let thief = std::thread::spawn(|| {
        become_cpu();
        GATE.wait_until(|| DONE.load(Ordering::Acquire).then_some(()));
    });
    while GATE.is_empty() {
        std::thread::yield_now();
    }
    // This CPU stays busy (it spins instead of blocking), so the only way the
    // unpinned task can run is on the idle CPU, where spawn placed it.
    let ran_on = Arc::new(AtomicUsize::new(usize::MAX));
    let r = ran_on.clone();
    let t = TaskBuilder::new("placed").stack_size(256 * 1024).spawn(move || {
        r.store(osmium_arch::cpu::current_id(), Ordering::Release);
    });
    while ran_on.load(Ordering::Acquire) == usize::MAX {
        std::thread::yield_now();
    }
    assert_ne!(ran_on.load(Ordering::Acquire), home);
    t.join();
    DONE.store(true, Ordering::Release);
    GATE.wake_all();
    thief.join().unwrap();
}

#[test]
fn pin_while_queued_survives_scheduling() {
    static DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    become_cpu();
    let (tx, rx) = std::sync::mpsc::channel();
    let other = std::thread::spawn(move || {
        become_cpu();
        tx.send(osmium_arch::cpu::current_id()).unwrap();
        while !DONE.load(Ordering::Acquire) {
            osmium_sched::yield_now();
            std::thread::yield_now();
        }
    });
    let away = rx.recv().unwrap();

    let ran_on = Arc::new(AtomicUsize::new(usize::MAX));
    let r = ran_on.clone();
    // Queued on this CPU, then re-pinned to the other one while still Ready.
    let t = builder("repinned").spawn(move || r.store(osmium_arch::cpu::current_id(), Ordering::Relaxed));
    t.pin(away);
    // Our own pick finds the task in our queue; it must be sent on, not run here.
    osmium_sched::yield_now();
    t.join();
    DONE.store(true, Ordering::Release);
    other.join().unwrap();
    assert_eq!(ran_on.load(Ordering::Relaxed), away);
    assert_eq!(t.affinity(), 1 << away, "scheduling does not rewrite the affinity");
}
