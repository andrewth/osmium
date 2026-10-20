//! Typed x86 I/O ports.

use core::marker::PhantomData;

use osmium_arch::x86_64 as cpu;

/// Integer widths that I/O ports transfer.
pub trait PortValue: Copy {
    /// Reads from `port`.
    ///
    /// # Safety
    /// See [`Port::new`].
    unsafe fn read(port: u16) -> Self;
    /// Writes to `port`.
    ///
    /// # Safety
    /// See [`Port::new`].
    unsafe fn write(port: u16, value: Self);
}

macro_rules! port_value {
    ($t:ty, $in:ident, $out:ident) => {
        impl PortValue for $t {
            unsafe fn read(port: u16) -> Self {
                // SAFETY: forwarded contract.
                unsafe { cpu::$in(port) }
            }
            unsafe fn write(port: u16, value: Self) {
                // SAFETY: forwarded contract.
                unsafe { cpu::$out(port, value) }
            }
        }
    };
}
port_value!(u8, inb, outb);
port_value!(u16, inw, outw);
port_value!(u32, inl, outl);

/// An I/O port carrying values of type `T`.
#[derive(Debug)]
pub struct Port<T: PortValue> {
    port: u16,
    _t: PhantomData<T>,
}

impl<T: PortValue> Port<T> {
    /// Creates a handle to `port`.
    ///
    /// # Safety
    /// The caller must own the device behind the port, and accesses through
    /// it must not compromise memory safety (for example by programming a
    /// DMA engine).
    pub const unsafe fn new(port: u16) -> Self {
        Self { port, _t: PhantomData }
    }

    /// The port number.
    pub fn number(&self) -> u16 {
        self.port
    }

    /// Reads the port.
    #[inline]
    pub fn read(&self) -> T {
        // SAFETY: guaranteed by `new`.
        unsafe { T::read(self.port) }
    }

    /// Writes the port.
    #[inline]
    pub fn write(&self, value: T) {
        // SAFETY: guaranteed by `new`.
        unsafe { T::write(self.port, value) }
    }
}
