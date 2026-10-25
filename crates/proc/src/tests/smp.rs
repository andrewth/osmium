#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! The threads of one process on several CPUs: page-table changes shoot down
//! the other CPUs, after the address space's lock and before frames are
//! freed, and write faults that lose a race with another CPU are retried.

use std::sync::Mutex as StdMutex;
use std::sync::Once as StdOnce;

use super::*;

/// A page no other test maps.
const MARK: u64 = 0x6000_0000;

/// What the remote-flush hook saw covering the marked page: how many pages
/// it was asked to flush, and the frames live at that moment.
static SEEN: StdMutex<Vec<(usize, usize)>> = StdMutex::new(Vec::new());
static WATCHED: StdMutex<Option<&'static HeapFrames>> = StdMutex::new(None);
/// One test at a time owns the marked page and the log.
static SERIAL: StdMutex<()> = StdMutex::new(());

fn install() {
    static ONCE: StdOnce = StdOnce::new();
    ONCE.call_once(|| {
        osmium_arch::mmu::set_remote_flush(|start, pages| {
            let mark = MARK as usize;
            if (start..start + pages * 0x1000).contains(&mark) {
                let live = WATCHED.lock().unwrap().map_or(0, |f| f.live());
                SEEN.lock().unwrap().push((pages, live));
            }
        });
    });
}

fn seen_since(n: usize) -> Vec<(usize, usize)> {
    SEEN.lock().unwrap().split_off(n)
}

#[test]
fn unmapping_shoots_down_other_cpus_before_freeing() {
    install();
    assert!(osmium_arch::mmu::remote_flush_supported());
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (p, frames) = process("smp-unmap");
    *WATCHED.lock().unwrap() = Some(frames);
    p.memory().map_anon(MARK, 0x2000, MapFlags::RW).unwrap();
    let before = frames.live();
    let n = SEEN.lock().unwrap().len();
    p.memory().unmap(MARK, 0x2000);
    let seen = seen_since(n);
    *WATCHED.lock().unwrap() = None;
    assert_eq!(seen.len(), 1, "one shootdown for the range");
    assert_eq!(seen[0].0, 2, "both pages");
    assert!(seen[0].1 >= before, "the frames were still allocated when the other CPUs were flushed");
    assert!(frames.live() < before, "and are freed afterwards");
}

#[test]
fn fork_and_copy_on_write_shoot_down_other_cpus() {
    install();
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (p, frames) = process("smp-fork");
    *WATCHED.lock().unwrap() = Some(frames);
    p.memory().map_anon(MARK, 0x1000, MapFlags::RW).unwrap();
    let n = SEEN.lock().unwrap().len();
    let c = fork_child(&p);
    // The parent's writable page became read-only: stale writable entries
    // on other CPUs must go before the fork returns.
    let forked = seen_since(n);
    let shared = frames.live();
    let n = SEEN.lock().unwrap().len();
    assert!(p.handle_page_fault(MARK, true));
    let copied = seen_since(n);
    let after = frames.live();
    *WATCHED.lock().unwrap() = None;
    assert!(!forked.is_empty(), "fork shot down the parent's other CPUs");
    assert_eq!(after, shared + 1);
    assert_eq!(copied.len(), 1, "the copy replaced the mapping on every CPU");
    assert_eq!(copied[0].1, shared + 1, "the old frame was kept until then");
    drop(c);
}

#[test]
fn a_write_fault_that_lost_the_race_is_retried() {
    let (p, _) = process("smp-spurious");
    // Several CPUs fault on the same shared page at once. Exactly one copies
    // it; the rest find it writable already and retry, none is killed.
    for round in 0..50u64 {
        let page = DATA + (round % 4) * 0x1000;
        let q = fork_child(&p);
        let results: Vec<bool> = std::thread::scope(|s| {
            let hs: Vec<_> =
                (0..4).map(|_| s.spawn(|| q.handle_page_fault(page, true) || q.memory().stale_fault(page))).collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(results.iter().all(|&ok| ok), "round {round}: {results:?}");
        put(&q, page, b"w");
    }
}

#[test]
fn threads_on_many_cpus_map_unmap_and_fault_together() {
    install();
    let (p, frames) = process("smp-stress");
    let c = fork_child(&p);
    std::thread::scope(|s| {
        for t in 0..4u64 {
            let (p, c) = (&p, &c);
            s.spawn(move || {
                for i in 0..200u64 {
                    let va = 0x8000_0000 + (t * 0x100 + i % 8) * 0x1000;
                    p.memory().map_anon(va, 0x1000, MapFlags::RW).unwrap();
                    put(p, va, b"x");
                    p.memory().unmap(va, 0x1000);
                    // Everyone also writes the pages the child shares.
                    let page = DATA + (i % 4) * 0x1000;
                    let _ = p.handle_page_fault(page, true) || p.memory().stale_fault(page);
                    let _ = c.handle_page_fault(page, true) || c.memory().stale_fault(page);
                }
            });
        }
    });
    let shared = frames.live();
    drop(c);
    assert!(frames.live() <= shared);
    for i in 0..4 {
        assert!(!p.handle_page_fault(DATA + i * 0x1000, true), "writable and unshared");
    }
    drop(p);
    assert_eq!(frames.live(), 1, "only the kernel table is left: no frame was leaked or freed twice");
}
