//! Read-copy-update.
//!
//! [`Rcu`] is a *domain*: readers enter it with [`Rcu::read_lock`] and may
//! dereference `RcuCell` pointers (or any pointer the updater publishes) until
//! the guard drops; an updater publishes a replacement and calls
//! [`Rcu::synchronize`], which returns once every reader that could still see the
//! old value has left, so the old value can be freed.
//!
//! The design is sleepable RCU in the style of Linux's SRCU, chosen because it
//! needs nothing from the scheduler and works unchanged on host threads:
//!
//! - Readers bump a per-CPU "locked" counter in one of two slots; leaving bumps the
//!   matching "unlocked" counter, possibly on another CPU if the reader migrated.
//!   There is no shared cache line on the read side.
//! - `synchronize` flips the active slot and waits for each slot to drain, in turn.
//! - A reader section may be preempted or block (but it must not call `synchronize`
//!   on the same domain, which would wait for itself).
//! - Cost trade-off: unlike classic RCU, entering a read section costs a
//!   sequentially consistent fence, and a grace period is latency-bound by the
//!   longest reader. There is no call-back list; use [`Rcu::synchronize`] or
//!   `RcuCell::update` (blocking).

use core::sync::atomic::{AtomicUsize, Ordering, fence};

use osmium_arch::MAX_CPUS;
use osmium_arch::cpu::spin_hint;

use crate::percpu::PerCpu;
use crate::spin::RawSpinLock;

/// Per-CPU reader counters, one pair per slot.
#[repr(align(64))]
struct CpuCounts {
    lock: [AtomicUsize; 2],
    unlock: [AtomicUsize; 2],
}

impl CpuCounts {
    const fn new() -> Self {
        Self { lock: [AtomicUsize::new(0), AtomicUsize::new(0)], unlock: [AtomicUsize::new(0), AtomicUsize::new(0)] }
    }
}

/// An RCU domain. Readers and updaters of one data structure must share a domain.
///
/// Usually a `static`. Independent subsystems should use separate domains so one's
/// slow readers do not delay the other's grace periods.
///
/// # Lock ordering
/// `synchronize` takes an internal spin lock that serializes grace periods, then waits
/// for readers. Do not call it while holding any lock a reader may need, and never
/// from inside a read section of the same domain.
pub struct Rcu {
    /// The slot new readers enter (0 or 1).
    active: AtomicUsize,
    counts: PerCpu<CpuCounts>,
    /// Serializes grace periods; the two-slot protocol is only correct with one updater at a time.
    gp: RawSpinLock<()>,
}

impl Rcu {
    /// Creates a domain with no readers.
    pub const fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            counts: PerCpu::new([const { CpuCounts::new() }; MAX_CPUS]),
            gp: RawSpinLock::new(()),
        }
    }

    /// Enters a read-side critical section.
    ///
    /// Pointers loaded with `RcuCell::read` stay valid until the guard drops.
    /// Sections may nest and may be held across a task switch.
    pub fn read_lock(&self) -> RcuReadGuard<'_> {
        // The slot may be flipped between this load and the increment; `synchronize` drains both slots in
        // sequence so that a reader landing in a stale slot late is still safe: it entered after the updater's
        // scan of that slot, hence (by the fences) after the updater's publish, and sees the new pointer.
        let idx = self.active.load(Ordering::Relaxed) & 1;
        if let Some(slot) = self.counts.get().lock.get(idx) {
            slot.fetch_add(1, Ordering::Relaxed);
        }
        // Full barrier: the increment must be visible before any load of the protected pointer. It pairs with
        // the fences in `synchronize`/`wait_slot` (store-buffering: reader {inc; fence; load ptr} against
        // updater {store ptr; fence; load counters}; at least one side sees the other's store).
        fence(Ordering::SeqCst);
        RcuReadGuard { rcu: self, idx }
    }

    /// Waits until every read-side critical section that began before the call has ended.
    ///
    /// Spins with a CPU relax hint; use [`synchronize_with`](Self::synchronize_with) to
    /// yield to a scheduler instead.
    pub fn synchronize(&self) {
        self.synchronize_with(spin_hint);
    }

    /// Like [`synchronize`](Self::synchronize), calling `wait` between polls (for example a task yield).
    pub fn synchronize_with(&self, mut wait: impl FnMut()) {
        // Serialize grace periods. Polling `try_lock` lets `wait` run (a yield, say) instead of burning the CPU,
        // and keeps this usable before a scheduler exists.
        let _gp = loop {
            if let Some(g) = self.gp.try_lock() {
                break g;
            }
            wait();
        };
        // Order the caller's earlier update (e.g. the pointer swap) before the counter scans below.
        fence(Ordering::SeqCst);
        let old = self.active.load(Ordering::Relaxed) & 1;
        // Phase 1: new readers go to the other slot; drain the slot that held readers up to now.
        self.active.store(old ^ 1, Ordering::Relaxed);
        self.wait_slot(old, &mut wait);
        // Phase 2: flip back and drain the other slot, which catches a reader that read the stale index
        // just before the previous grace period's flip.
        self.active.store(old, Ordering::Relaxed);
        self.wait_slot(old ^ 1, &mut wait);
        fence(Ordering::SeqCst);
    }

    /// Waits until no reader is inside `slot`.
    fn wait_slot(&self, slot: usize, wait: &mut impl FnMut()) {
        loop {
            // Read every unlock count *before* every lock count: a reader that leaves between the scans makes
            // lock > unlock (we poll again) rather than a false match. Both only grow (wrapping) and
            // unlock <= lock always, so equality means the slot was empty in between.
            // Acquire on the unlock loads pairs with the Release in `RcuReadGuard::drop`, ordering the
            // reader's accesses before whatever the updater does next (freeing the old value).
            fence(Ordering::SeqCst);
            let mut unlocked = 0usize;
            for c in self.counts.iter() {
                unlocked = unlocked.wrapping_add(c.unlock.get(slot).map_or(0, |a| a.load(Ordering::Acquire)));
            }
            fence(Ordering::SeqCst);
            let mut locked = 0usize;
            for c in self.counts.iter() {
                locked = locked.wrapping_add(c.lock.get(slot).map_or(0, |a| a.load(Ordering::Relaxed)));
            }
            if locked == unlocked {
                return;
            }
            wait();
        }
    }
}

impl Default for Rcu {
    fn default() -> Self {
        Self::new()
    }
}

/// A read-side critical section; ends on drop.
#[must_use = "the read-side critical section ends immediately if the guard is dropped"]
pub struct RcuReadGuard<'rcu> {
    rcu: &'rcu Rcu,
    idx: usize,
}

impl Drop for RcuReadGuard<'_> {
    fn drop(&mut self) {
        // Release: all reads of protected data happen before the updater observes this unlock. The counter
        // may belong to another CPU than the one the reader started on; only the sums matter.
        if let Some(slot) = self.rcu.counts.get().unlock.get(self.idx) {
            slot.fetch_add(1, Ordering::Release);
        }
    }
}

#[cfg(feature = "alloc")]
pub use cell::RcuCell;

#[cfg(feature = "alloc")]
mod cell {
    use alloc::boxed::Box;
    use core::marker::PhantomData;
    use core::sync::atomic::{AtomicPtr, Ordering};

    use super::{Rcu, RcuReadGuard};

    /// An RCU-protected, heap-allocated value.
    ///
    /// Readers get `&T` tied to an [`RcuReadGuard`] without taking a lock; an updater
    /// swaps in a new `Box<T>` and frees the old one after a grace period.
    ///
    /// ```
    /// use osmium_sync::{Rcu, RcuCell};
    ///
    /// let rcu = Rcu::new();
    /// let cell = RcuCell::new(Box::new(1u32));
    /// {
    ///     let g = rcu.read_lock();
    ///     assert_eq!(*cell.read(&g), 1);
    /// }
    /// cell.update(&rcu, Box::new(2));
    /// assert_eq!(*cell.read(&rcu.read_lock()), 2);
    /// ```
    ///
    /// Updates take `&self` so the cell can be shared with readers; the swap itself is atomic, so
    /// concurrent updaters are memory-safe (each frees exactly the value it unlinked), though which
    /// value wins is up to the caller to arrange.
    pub struct RcuCell<T> {
        ptr: AtomicPtr<T>,
        _owns: PhantomData<Box<T>>,
    }

    // SAFETY: readers hand out `&T` across threads (`T: Sync`) and the updater drops a `T` on its own
    // thread (`T: Send`).
    unsafe impl<T: Send + Sync> Sync for RcuCell<T> {}
    // SAFETY: owning the cell owns the `Box<T>`.
    unsafe impl<T: Send> Send for RcuCell<T> {}

    impl<T> RcuCell<T> {
        /// Creates a cell holding `value`.
        pub fn new(value: Box<T>) -> Self {
            Self { ptr: AtomicPtr::new(Box::into_raw(value)), _owns: PhantomData }
        }

        /// Reads the current value; it stays valid for as long as the guard.
        ///
        /// The guard must belong to the domain updaters synchronize on.
        pub fn read<'g>(&self, _guard: &'g RcuReadGuard<'_>) -> &'g T {
            // Acquire pairs with the Release half of the swap in `replace`, so the new value's initialization
            // is visible (Rust has no consume ordering).
            let p = self.ptr.load(Ordering::Acquire);
            // SAFETY: `ptr` always holds a live `Box` allocation; `replace` frees the old one only after
            // `synchronize`, which waits for this guard's section to end.
            unsafe { &*p }
        }

        /// Replaces the value, waits for a grace period on `rcu` and returns the old value.
        ///
        /// Must not be called inside a read section of `rcu`.
        pub fn replace(&self, rcu: &Rcu, value: Box<T>) -> Box<T> {
            // AcqRel: Release publishes the initialization of `value`; the fence in `synchronize` orders the
            // swap before the reader scans.
            let old = self.ptr.swap(Box::into_raw(value), Ordering::AcqRel);
            rcu.synchronize();
            // SAFETY: `old` came from `Box::into_raw`, was unlinked by the swap above (so we are its only
            // owner), and no reader that could have loaded it remains.
            unsafe { Box::from_raw(old) }
        }

        /// Replaces the value and drops the old one after a grace period.
        pub fn update(&self, rcu: &Rcu, value: Box<T>) {
            drop(self.replace(rcu, value));
        }
    }

    impl<T> Drop for RcuCell<T> {
        fn drop(&mut self) {
            // SAFETY: `&mut self` means no readers can exist (they borrow the cell); the pointer is a live Box.
            drop(unsafe { Box::from_raw(*self.ptr.get_mut()) });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::vec::Vec;

    #[test]
    fn synchronize_without_readers_returns() {
        let rcu = Rcu::new();
        rcu.synchronize();
        rcu.synchronize();
    }

    #[test]
    fn nested_readers_and_finished_readers() {
        let rcu = Rcu::new();
        let a = rcu.read_lock();
        let b = rcu.read_lock();
        drop(a);
        drop(b);
        rcu.synchronize();
    }

    #[test]
    fn synchronize_waits_for_reader() {
        let rcu = Arc::new(Rcu::new());
        let done = Arc::new(AtomicBool::new(false));
        let g = rcu.read_lock();
        let (r2, d2) = (rcu.clone(), done.clone());
        let t = std::thread::spawn(move || {
            r2.synchronize();
            d2.store(true, Ordering::SeqCst);
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!done.load(Ordering::SeqCst));
        drop(g);
        t.join().unwrap();
        assert!(done.load(Ordering::SeqCst));
    }

    #[test]
    fn reader_migrating_between_cpus_is_counted() {
        // Lock on one CPU id, unlock on another: sums, not slots, decide.
        let rcu = Arc::new(Rcu::new());
        // SAFETY: host simulation; this thread's id is its own.
        unsafe { osmium_arch::cpu::set_current_id(1) };
        let g = rcu.read_lock();
        let done = Arc::new(AtomicBool::new(false));
        let (r2, d2) = (rcu.clone(), done.clone());
        let t = std::thread::spawn(move || {
            r2.synchronize();
            d2.store(true, Ordering::SeqCst);
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!done.load(Ordering::SeqCst));
        // SAFETY: as above.
        unsafe { osmium_arch::cpu::set_current_id(2) };
        drop(g);
        t.join().unwrap();
    }

    #[cfg(feature = "alloc")]
    mod cell {
        use super::*;
        use std::boxed::Box;
        use std::sync::atomic::AtomicUsize;

        /// Marked dead on drop; readers check it was never freed under them.
        struct Node {
            value: usize,
            alive: AtomicBool,
            drops: Arc<AtomicUsize>,
        }
        impl Drop for Node {
            fn drop(&mut self) {
                self.alive.store(false, Ordering::SeqCst);
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[test]
        fn readers_never_see_freed_value() {
            let rcu = Arc::new(Rcu::new());
            let drops = Arc::new(AtomicUsize::new(0));
            let mk = |v| Box::new(Node { value: v, alive: AtomicBool::new(true), drops: drops.clone() });
            let cell = Arc::new(RcuCell::new(mk(0)));
            let stop = Arc::new(AtomicBool::new(false));
            let started = Arc::new(AtomicUsize::new(0));
            let readers: Vec<_> = (0..4)
                .map(|i| {
                    let (rcu, cell, stop, started) = (rcu.clone(), cell.clone(), stop.clone(), started.clone());
                    std::thread::spawn(move || {
                        // SAFETY: host simulation; distinct CPU ids exercise the per-CPU counters.
                        unsafe { osmium_arch::cpu::set_current_id(10 + i) };
                        let mut last = 0;
                        let mut n = 0u64;
                        while !stop.load(Ordering::Relaxed) {
                            let g = rcu.read_lock();
                            let node = cell.read(&g);
                            assert!(node.alive.load(Ordering::SeqCst), "read a freed node");
                            assert!(node.value >= last, "values went backwards");
                            last = node.value;
                            std::thread::yield_now();
                            assert!(node.alive.load(Ordering::SeqCst), "node freed during read section");
                            n += 1;
                            if n == 1 {
                                started.fetch_add(1, Ordering::SeqCst);
                            }
                        }
                        n
                    })
                })
                .collect();
            while started.load(Ordering::SeqCst) < 4 {
                std::thread::yield_now();
            }
            for v in 1..=300 {
                cell.update(&rcu, mk(v));
            }
            stop.store(true, Ordering::Relaxed);
            for r in readers {
                assert!(r.join().unwrap() > 0);
            }
            assert_eq!(drops.load(Ordering::SeqCst), 300);
            drop(cell);
            assert_eq!(drops.load(Ordering::SeqCst), 301);
        }

        #[test]
        fn concurrent_updaters_are_serialized() {
            let rcu = Arc::new(Rcu::new());
            let cell = Arc::new(RcuCell::new(Box::new(0usize)));
            let ts: Vec<_> = (0..4)
                .map(|_| {
                    let (rcu, cell) = (rcu.clone(), cell.clone());
                    std::thread::spawn(move || {
                        for i in 0..200 {
                            let _seen: usize = *cell.read(&rcu.read_lock());
                            cell.update(&rcu, Box::new(i));
                        }
                    })
                })
                .collect();
            for t in ts {
                t.join().unwrap();
            }
        }
    }
}
