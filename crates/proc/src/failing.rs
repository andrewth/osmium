//! A host-test allocator that can fail one allocation of the calling thread,
//! for tests that walk an operation through every point where memory could
//! run out. An allocation that goes through an infallible constructor
//! (`Box::new`, `vec!`, `Vec::push`) when this one fails aborts the test
//! binary, which is how the tests find them.

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

std::thread_local! {
    /// Allocations to let through before failing one; `None` when disarmed.
    static COUNTDOWN: Cell<Option<usize>> = const { Cell::new(None) };
    static REACHED: Cell<bool> = const { Cell::new(false) };
}

/// Whether this allocation is the one to fail.
fn fail_now() -> bool {
    COUNTDOWN.with(|c| match c.get() {
        Some(0) => {
            c.set(None);
            REACHED.with(|r| r.set(true));
            true
        }
        Some(n) => {
            c.set(Some(n - 1));
            false
        }
        None => false,
    })
}

pub(crate) struct Failing;

// SAFETY: forwards to `System`, except for the allocations it fails.
unsafe impl GlobalAlloc for Failing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded contract.
        if fail_now() { core::ptr::null_mut() } else { unsafe { System.alloc(layout) } }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded contract.
        if fail_now() { core::ptr::null_mut() } else { unsafe { System.alloc_zeroed(layout) } }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded contract.
        if fail_now() { core::ptr::null_mut() } else { unsafe { System.realloc(ptr, layout, new_size) } }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded contract.
        unsafe { System.dealloc(ptr, layout) }
    }
}

/// Runs `f` with its `n`th allocation (counting from 0) failing. Returns
/// what `f` returned, and whether `f` made that many allocations, so the
/// failure was injected.
pub(crate) fn failing_at<R>(n: usize, f: impl FnOnce() -> R) -> (R, bool) {
    REACHED.with(|r| r.set(false));
    COUNTDOWN.with(|c| c.set(Some(n)));
    let r = f();
    COUNTDOWN.with(|c| c.set(None));
    (r, REACHED.with(Cell::get))
}

/// Runs `op` with the 0th, 1st, 2nd... allocation failing in turn, until a
/// run makes fewer allocations than that. `check` sees each run's result and
/// whether it had a failure injected, once the failure is disarmed (so it
/// may allocate); it is called with `false` last, for the run that finished.
/// Returns how many failures were injected.
#[allow(clippy::unreachable)] // test-only helper: the loop ends when a run has no failure left to inject.
pub(crate) fn every_failure<R>(mut op: impl FnMut() -> R, mut check: impl FnMut(R, bool)) -> usize {
    for n in 0.. {
        let (r, hit) = failing_at(n, &mut op);
        check(r, hit);
        if !hit {
            return n;
        }
    }
    unreachable!()
}
