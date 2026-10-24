#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Creating a task reports running out of memory as an error.

use core::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};

use osmium_sched::{OutOfMemory, StackAllocator, TaskBuilder};

/// Hands out stacks until told to stop.
struct Stacks {
    exhausted: AtomicBool,
}

// SAFETY: stacks are leaked heap blocks, exclusively owned, 16-byte aligned.
unsafe impl StackAllocator for Stacks {
    fn alloc(&self, size: usize) -> Option<(NonNull<u8>, usize)> {
        if self.exhausted.load(Ordering::SeqCst) {
            return None;
        }
        let block = Box::leak(vec![0u128; size.div_ceil(16)].into_boxed_slice());
        Some((NonNull::new(block.as_mut_ptr().cast())?, block.len() * 16))
    }

    unsafe fn free(&self, _base: NonNull<u8>, _len: usize) {}
}

static STACKS: Stacks = Stacks { exhausted: AtomicBool::new(false) };

#[test]
fn no_stack_is_an_error_not_a_panic() {
    osmium_sched::set_stack_allocator(&STACKS);
    assert!(TaskBuilder::new("fits").try_build(|| {}).is_ok());
    STACKS.exhausted.store(true, Ordering::SeqCst);
    assert_eq!(TaskBuilder::new("starved").try_build(|| {}).unwrap_err(), OutOfMemory);
    // `try_spawn` fails before the task is queued.
    assert_eq!(TaskBuilder::new("starved").try_spawn(|| {}).unwrap_err(), OutOfMemory);
    STACKS.exhausted.store(false, Ordering::SeqCst);
    assert!(TaskBuilder::new("fits again").try_build(|| {}).is_ok());
}
