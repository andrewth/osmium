//! Memory-mapped I/O.
//!
//! Describe a device's register block as a `#[repr(C)]` struct of
//! [`ReadOnly`], [`WriteOnly`] and [`ReadWrite`] cells, then turn its base
//! address into a reference once, unsafely:
//!
//! ```
//! use osmium_hal::mmio::{ReadOnly, ReadWrite};
//!
//! #[repr(C)]
//! struct Regs {
//!     data: ReadWrite<u32>,
//!     status: ReadOnly<u32>,
//! }
//!
//! fn poll(regs: &Regs) -> u32 {
//!     while regs.status.read() & 1 == 0 {}
//!     regs.data.read()
//! }
//! # let fake = Regs { data: ReadWrite::new(7), status: ReadOnly::new(1) };
//! # assert_eq!(poll(&fake), 7);
//! ```

use core::cell::UnsafeCell;
use core::fmt;

/// Integer types that registers can hold.
pub trait RegValue: Copy + sealed::Sealed {}
impl RegValue for u8 {}
impl RegValue for u16 {}
impl RegValue for u32 {}
impl RegValue for u64 {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for u8 {}
    impl Sealed for u16 {}
    impl Sealed for u32 {}
    impl Sealed for u64 {}
}

macro_rules! cell {
    ($(#[$m:meta])* $name:ident, read: $r:tt, write: $w:tt) => {
        $(#[$m])*
        #[repr(transparent)]
        pub struct $name<T: RegValue>(UnsafeCell<T>);

        // SAFETY: every access is a single volatile load or store of an
        // integer, which hardware registers are designed to accept from any CPU.
        unsafe impl<T: RegValue> Sync for $name<T> {}

        impl<T: RegValue> $name<T> {
            /// Creates a cell holding `value`, for register blocks kept in
            /// ordinary memory (tests, emulated devices, shared-memory rings).
            pub const fn new(value: T) -> Self {
                Self(UnsafeCell::new(value))
            }
        }

        cell!(@read $r $name);
        cell!(@write $w $name);
    };
    (@read true $name:ident) => {
        impl<T: RegValue> $name<T> {
            /// Performs a volatile read.
            #[inline]
            pub fn read(&self) -> T {
                // SAFETY: the cell is a valid, aligned `T` by construction.
                unsafe { self.0.get().read_volatile() }
            }
        }
    };
    (@write true $name:ident) => {
        impl<T: RegValue> $name<T> {
            /// Performs a volatile write.
            #[inline]
            pub fn write(&self, value: T) {
                // SAFETY: the cell is a valid, aligned `T` by construction.
                unsafe { self.0.get().write_volatile(value) }
            }
        }
    };
    (@read false $name:ident) => {};
    (@write false $name:ident) => {};
}

cell!(
    /// A read-only register.
    ReadOnly, read: true, write: false
);
cell!(
    /// A write-only register.
    WriteOnly, read: false, write: true
);
cell!(
    /// A read/write register.
    ReadWrite, read: true, write: true
);

macro_rules! modify {
    ($($t:ty),*) => {$(
        impl ReadWrite<$t> {
            /// Read-modify-write. Not atomic with respect to other writers.
            #[inline]
            pub fn modify(&self, f: impl FnOnce($t) -> $t) {
                self.write(f(self.read()));
            }

            /// Sets the bits in `mask`.
            #[inline]
            pub fn set_bits(&self, mask: $t) {
                self.modify(|v| v | mask);
            }

            /// Clears the bits in `mask`.
            #[inline]
            pub fn clear_bits(&self, mask: $t) {
                self.modify(|v| v & !mask);
            }
        }
    )*};
}
modify!(u8, u16, u32, u64);

/// An access fell outside an [`IoMem`] window or was misaligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoMemError;

/// A window of device memory with bounds-checked, volatile accessors.
///
/// Use it where registers are addressed by offset (as device trees and PCI
/// BARs describe them) rather than through a typed register block.
#[derive(Clone)]
pub struct IoMem {
    base: *mut u8,
    len: usize,
}

// SAFETY: accesses are single volatile loads/stores, valid from any CPU.
unsafe impl Send for IoMem {}
// SAFETY: as above.
unsafe impl Sync for IoMem {}

impl IoMem {
    /// Wraps `len` bytes of device memory at `base`.
    ///
    /// # Safety
    /// `[base, base + len)` must be mapped (normally as device memory), and
    /// accesses through this window must not violate memory safety: it must
    /// not alias Rust-managed memory.
    pub const unsafe fn new(base: *mut u8, len: usize) -> Self {
        Self { base, len }
    }

    /// Length of the window in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the window is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Base address of the window.
    pub fn base(&self) -> *mut u8 {
        self.base
    }

    /// Returns the sub-window `[offset, offset + len)`.
    pub fn slice(&self, offset: usize, len: usize) -> Result<IoMem, IoMemError> {
        let end = offset.checked_add(len).ok_or(IoMemError)?;
        if end > self.len {
            return Err(IoMemError);
        }
        // SAFETY: a sub-range of a valid window.
        Ok(unsafe { IoMem::new(self.base.add(offset), len) })
    }

    fn ptr<T>(&self, offset: usize) -> Result<*mut T, IoMemError> {
        let size = core::mem::size_of::<T>();
        if offset.checked_add(size).is_none_or(|end| end > self.len) || !offset.is_multiple_of(size) {
            return Err(IoMemError);
        }
        // SAFETY: bounds checked above.
        Ok(unsafe { self.base.add(offset) }.cast())
    }

    /// Reads the register at `offset`.
    #[inline]
    pub fn read<T: RegValue>(&self, offset: usize) -> Result<T, IoMemError> {
        // SAFETY: in bounds and aligned (checked); valid per `new`.
        Ok(unsafe { self.ptr::<T>(offset)?.read_volatile() })
    }

    /// Writes the register at `offset`.
    #[inline]
    pub fn write<T: RegValue>(&self, offset: usize, value: T) -> Result<(), IoMemError> {
        // SAFETY: in bounds and aligned (checked); valid per `new`.
        unsafe { self.ptr::<T>(offset)?.write_volatile(value) };
        Ok(())
    }

    /// Reinterprets the start of the window as a register block.
    pub fn as_regs<R: RegisterBlock>(&self) -> Result<&R, IoMemError> {
        if core::mem::size_of::<R>() > self.len || !(self.base as usize).is_multiple_of(core::mem::align_of::<R>()) {
            return Err(IoMemError);
        }
        // SAFETY: size and alignment checked; `R` consists only of register
        // cells, which are valid for any bit pattern.
        Ok(unsafe { &*self.base.cast::<R>() })
    }
}

impl fmt::Debug for IoMem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IoMem({:p}, {:#x})", self.base, self.len)
    }
}

/// A `#[repr(C)]` struct made only of register cells (and padding arrays of
/// them), so any bit pattern is valid.
///
/// # Safety
/// Implementors must be `#[repr(C)]` and contain only [`ReadOnly`],
/// [`WriteOnly`], [`ReadWrite`] fields or arrays of them.
pub unsafe trait RegisterBlock: Sync {}

#[cfg(test)]
// Tests drop drivers explicitly to end their use of the fake register memory
// before inspecting it.
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;

    #[test]
    fn iomem_bounds_and_alignment() {
        let mut backing = [0u32; 4];
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(backing.as_mut_ptr().cast(), 16) };
        io.write::<u32>(4, 0xdead_beef).unwrap();
        assert_eq!(io.read::<u32>(4), Ok(0xdead_beef));
        assert_eq!(io.read::<u8>(4), Ok(0xef));
        assert_eq!(io.read::<u32>(2), Err(IoMemError), "misaligned");
        assert_eq!(io.read::<u32>(16), Err(IoMemError), "out of bounds");
        assert_eq!(io.slice(8, 8).unwrap().read::<u64>(0), Ok(0));
        assert!(io.slice(12, 8).is_err());
        drop(io);
        assert_eq!(backing[1], 0xdead_beef);
    }

    #[test]
    fn register_block() {
        #[repr(C)]
        struct Regs {
            a: ReadWrite<u32>,
            b: ReadOnly<u32>,
        }
        // SAFETY: only register cells.
        unsafe impl RegisterBlock for Regs {}
        let mut backing = [5u32, 9];
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(backing.as_mut_ptr().cast(), 8) };
        let regs: &Regs = io.as_regs().unwrap();
        regs.a.set_bits(0b10);
        assert_eq!(regs.a.read(), 7);
        assert_eq!(regs.b.read(), 9);
    }
}
