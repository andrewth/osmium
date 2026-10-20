//! The global console behind [`print!`](crate::print) and
//! [`println!`](crate::println).
//!
//! The console can be replaced at runtime, so a kernel can start with an
//! early console (say, SBI or a polled UART) and switch to a better one
//! later. Output before any console is installed is discarded.

use core::fmt::{self, Write};

use osmium_sync::{IrqDisabled, IrqSpinLock, RwSpinLock};

use crate::serial::{SerialPort, SerialWriter};

/// A sink for console text.
pub trait Console: Sync {
    /// Writes `s`. Implementations serialize concurrent writers.
    fn write_str(&self, s: &str);

    /// Writes a formatted message. The default calls `write_str` once per
    /// fragment; implementations with a lock should override it to hold the
    /// lock for the whole message, so lines from different CPUs do not
    /// interleave.
    fn write_fmt(&self, args: fmt::Arguments<'_>) {
        struct Adapter<'a, C: Console + ?Sized>(&'a C);
        impl<C: Console + ?Sized> Write for Adapter<'_, C> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.0.write_str(s);
                Ok(())
            }
        }
        let _ = Adapter(self).write_fmt(args);
    }
}

static CONSOLE: RwSpinLock<Option<&'static dyn Console>, IrqDisabled> = RwSpinLock::new(None);

/// Installs `console`, returning the previous one.
pub fn set_console(console: &'static dyn Console) -> Option<&'static dyn Console> {
    CONSOLE.write().replace(console)
}

/// Writes formatted text to the console.
#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    let console = *CONSOLE.read();
    if let Some(c) = console {
        c.write_fmt(args);
    }
}

/// Prints to the global console.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => { $crate::console::_print(format_args!($($arg)*)) };
}

/// Prints to the global console, with a newline.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::console::_print(format_args!("{}\n", format_args!($($arg)*))) };
}

/// A console on a serial port, with `\n` translated to `\r\n`.
pub struct SerialConsole<S> {
    port: IrqSpinLock<S>,
}

impl<S: SerialPort + Send> SerialConsole<S> {
    /// Wraps `port`.
    pub const fn new(port: S) -> Self {
        Self { port: IrqSpinLock::new(port) }
    }

    /// Locks the port for direct use, for example to read input.
    pub fn port(&self) -> osmium_sync::SpinLockGuard<'_, S, IrqDisabled> {
        self.port.lock()
    }
}

impl<S: SerialPort + Send> Console for SerialConsole<S> {
    fn write_str(&self, s: &str) {
        let mut port = self.port.lock();
        let _ = SerialWriter(&mut *port).write_str(s);
    }

    fn write_fmt(&self, args: fmt::Arguments<'_>) {
        let mut port = self.port.lock();
        let _ = SerialWriter(&mut *port).write_fmt(args);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    struct Capture(Vec<u8>);
    impl SerialPort for Capture {
        fn write_byte(&mut self, b: u8) {
            self.0.push(b);
        }
        fn read_byte(&mut self) -> Option<u8> {
            None
        }
    }

    #[test]
    fn println_goes_to_installed_console() {
        static CON: SerialConsole<Capture> = SerialConsole::new(Capture(Vec::new()));
        crate::println!("dropped");
        // A previous test binary run can't have installed one; this is the first.
        set_console(&CON);
        crate::println!("hello {}", 42);
        assert_eq!(CON.port().0, b"hello 42\r\n");
    }
}
