//! Bounds-checked access to the fixed-layout byte buffers that system calls
//! copy in from and out to user memory. A buffer that is too short is an
//! `EINVAL` error, never an out-of-range index.

use osmium_fs::Errno;

/// The `len` bytes at `off`.
pub(crate) fn slice(b: &[u8], off: usize, len: usize) -> Result<&[u8], Errno> {
    b.get(off..off.checked_add(len).ok_or(Errno::EINVAL)?).ok_or(Errno::EINVAL)
}

/// The `len` bytes at `off`, writable.
pub(crate) fn slice_mut(b: &mut [u8], off: usize, len: usize) -> Result<&mut [u8], Errno> {
    b.get_mut(off..off.checked_add(len).ok_or(Errno::EINVAL)?).ok_or(Errno::EINVAL)
}

/// Copies `src` to `off`.
pub(crate) fn put(b: &mut [u8], off: usize, src: &[u8]) -> Result<(), Errno> {
    slice_mut(b, off, src.len())?.copy_from_slice(src);
    Ok(())
}

/// The first `N` bytes at `off`, as an array.
pub(crate) fn array<const N: usize>(b: &[u8], off: usize) -> Result<[u8; N], Errno> {
    slice(b, off, N)?.first_chunk::<N>().copied().ok_or(Errno::EINVAL)
}

macro_rules! readers {
    ($($name:ident: $t:ty),*) => {$(
        /// The native-endian value at `off`.
        pub(crate) fn $name(b: &[u8], off: usize) -> Result<$t, Errno> {
            Ok(<$t>::from_ne_bytes(array(b, off)?))
        }
    )*};
}

readers!(u16_at: u16, u32_at: u32, u64_at: u64, i32_at: i32, i64_at: i64);
