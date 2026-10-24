//! Allocation that reports failure instead of panicking.
//!
//! The kernel heap returns null when it runs out of memory, and the
//! infallible constructors (`Box::new`, `vec!`, `Vec::push`) turn that into a
//! panic. Code that serves a request from user space uses these instead, so
//! running out of memory is an error the caller can return (`ENOMEM`).

use alloc::boxed::Box;
use alloc::collections::TryReserveError;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::mem::MaybeUninit;

/// The allocator had no memory to give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfMemory;

impl From<TryReserveError> for OutOfMemory {
    fn from(_: TryReserveError) -> Self {
        OutOfMemory
    }
}

/// `Box::new`, failing with [`OutOfMemory`].
#[inline]
pub fn try_box<T>(value: T) -> Result<Box<T>, OutOfMemory> {
    Box::try_new(value).map_err(|_| OutOfMemory)
}

/// `Arc::new`, failing with [`OutOfMemory`].
#[inline]
pub fn try_arc<T>(value: T) -> Result<Arc<T>, OutOfMemory> {
    Arc::try_new(value).map_err(|_| OutOfMemory)
}

/// The memory for an `Arc<T>`, to be filled in later with [`init_arc`]: for
/// code that must reserve the memory before it knows the value.
pub fn try_arc_uninit<T>() -> Result<Arc<MaybeUninit<T>>, OutOfMemory> {
    Arc::try_new_uninit().map_err(|_| OutOfMemory)
}

/// Fills in the memory [`try_arc_uninit`] reserved. Cannot fail.
#[allow(clippy::expect_used)] // invariant: `try_arc_uninit` hands out a unique Arc and callers fill it before sharing.
pub fn init_arc<T>(mut slot: Arc<MaybeUninit<T>>, value: T) -> Arc<T> {
    Arc::get_mut(&mut slot).expect("the memory is not shared yet").write(value);
    // SAFETY: just initialized.
    unsafe { slot.assume_init() }
}

/// A boxed slice of `len` uninitialized `T`s.
#[inline]
pub fn try_uninit_slice<T>(len: usize) -> Result<Box<[MaybeUninit<T>]>, OutOfMemory> {
    Box::try_new_uninit_slice(len).map_err(|_| OutOfMemory)
}

/// `vec![0; len]`, failing with [`OutOfMemory`].
#[inline]
pub fn try_zeroed(len: usize) -> Result<Vec<u8>, OutOfMemory> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let layout = Layout::array::<u8>(len).map_err(|_| OutOfMemory)?;
    // SAFETY: the size is not zero. Asking for zeroed memory (rather than
    // writing zeroes to fresh memory) lets the allocator skip the work for
    // pages it knows are clear.
    let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return Err(OutOfMemory);
    }
    // SAFETY: `ptr` came from the global allocator with the layout of `len`
    // bytes, all of them initialized (to zero).
    Ok(unsafe { Vec::from_raw_parts(ptr, len, len) })
}

/// `Vec::push`, failing with [`OutOfMemory`] and dropping `value`.
#[inline]
pub fn try_push<T>(v: &mut Vec<T>, value: T) -> Result<(), OutOfMemory> {
    v.try_reserve(1)?;
    v.push(value);
    Ok(())
}

/// `Vec::extend_from_slice`, failing with [`OutOfMemory`].
#[inline]
pub fn try_extend_from_slice<T: Clone>(v: &mut Vec<T>, items: &[T]) -> Result<(), OutOfMemory> {
    v.try_reserve(items.len())?;
    v.extend_from_slice(items);
    Ok(())
}

/// `slice.to_vec()`, failing with [`OutOfMemory`].
#[inline]
pub fn try_to_vec<T: Clone>(items: &[T]) -> Result<Vec<T>, OutOfMemory> {
    let mut v = Vec::new();
    try_extend_from_slice(&mut v, items)?;
    Ok(v)
}

/// `String::from(s)`, failing with [`OutOfMemory`].
#[inline]
pub fn try_string(s: &str) -> Result<alloc::string::String, OutOfMemory> {
    let mut out = alloc::string::String::new();
    out.try_reserve_exact(s.len())?;
    out.push_str(s);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers_succeed_when_memory_is_available() {
        assert_eq!(*try_box(7).unwrap(), 7);
        assert_eq!(*try_arc(8).unwrap(), 8);
        assert_eq!(try_uninit_slice::<u128>(4).unwrap().len(), 4);
        assert_eq!(try_zeroed(5).unwrap(), [0; 5]);
        let mut v = Vec::new();
        try_push(&mut v, 1).unwrap();
        try_extend_from_slice(&mut v, &[2, 3]).unwrap();
        assert_eq!(v, [1, 2, 3]);
        assert_eq!(try_to_vec(&[4, 5]).unwrap(), [4, 5]);
        assert_eq!(try_string("hi").unwrap(), "hi");
        let slot = try_arc_uninit::<u64>().unwrap();
        assert_eq!(*init_arc(slot, 9), 9);
    }

    #[test]
    fn an_impossible_size_is_an_error_not_a_panic() {
        assert_eq!(try_zeroed(usize::MAX).unwrap_err(), OutOfMemory);
        assert!(try_uninit_slice::<u128>(usize::MAX / 2).is_err());
        let mut v: Vec<u64> = Vec::new();
        assert!(v.try_reserve(usize::MAX / 8).is_err());
    }
}
