//! Panic-free register access for drivers: an access outside the window
//! reads as all ones and a write is dropped, as on a bus with no device.

use crate::mmio::{IoMem, RegValue};

/// A register value with an all-ones pattern.
pub trait Ones {
    /// All bits set.
    const ONES: Self;
}
impl Ones for u8 {
    const ONES: Self = u8::MAX;
}
impl Ones for u16 {
    const ONES: Self = u16::MAX;
}
impl Ones for u32 {
    const ONES: Self = u32::MAX;
}
impl Ones for u64 {
    const ONES: Self = u64::MAX;
}

/// Infallible register access.
pub trait IoMemExt {
    /// Reads a register, or all ones if it lies outside the window.
    fn rd<T: RegValue + Ones>(&self, offset: usize) -> T;
    /// Writes a register; a write outside the window is ignored.
    fn wr<T: RegValue>(&self, offset: usize, value: T);
}

impl IoMemExt for IoMem {
    fn rd<T: RegValue + Ones>(&self, offset: usize) -> T {
        // The barrier keeps the load a plain `mov`: left alone, the compiler folds a volatile
        // read into the next operation (`or reg, [mem]`), which a hypervisor that emulates
        // MMIO by decoding the faulting instruction may not support.
        core::hint::black_box(self.read(offset).unwrap_or(T::ONES))
    }
    fn wr<T: RegValue>(&self, offset: usize, value: T) {
        let _ = self.write(offset, value);
    }
}
