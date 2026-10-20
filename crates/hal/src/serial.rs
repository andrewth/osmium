//! Byte-oriented serial ports.

use core::fmt;

/// A UART or similar byte stream.
pub trait SerialPort {
    /// Writes one byte, waiting for room in the transmitter.
    fn write_byte(&mut self, byte: u8);

    /// Reads one byte if one is available.
    fn read_byte(&mut self) -> Option<u8>;

    /// Writes all of `bytes`.
    fn write_bytes(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b);
        }
    }
}

/// Adapts a [`SerialPort`] to [`fmt::Write`], translating `\n` to `\r\n`.
pub struct SerialWriter<'a, S: SerialPort + ?Sized>(pub &'a mut S);

impl<S: SerialPort + ?Sized> fmt::Write for SerialWriter<'_, S> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.0.write_byte(b'\r');
            }
            self.0.write_byte(b);
        }
        Ok(())
    }
}
