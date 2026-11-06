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
///
/// Text goes to [`SerialPort::write_bytes`] a line at a time, so a port
/// with a per-request cost (a virtio console's queue round trip) pays it per
/// line rather than per byte.
pub struct SerialWriter<'port, S: SerialPort + ?Sized>(pub &'port mut S);

impl<S: SerialPort + ?Sized> fmt::Write for SerialWriter<'_, S> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut lines = s.as_bytes().split(|&b| b == b'\n');
        if let Some(first) = lines.next()
            && !first.is_empty()
        {
            self.0.write_bytes(first);
        }
        for line in lines {
            self.0.write_bytes(b"\r\n");
            if !line.is_empty() {
                self.0.write_bytes(line);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;
    use std::vec::Vec;

    /// Records each `write_bytes` call.
    #[derive(Default)]
    struct Calls(Vec<Vec<u8>>);

    impl SerialPort for Calls {
        fn write_byte(&mut self, b: u8) {
            self.0.push(std::vec![b]);
        }
        fn read_byte(&mut self) -> Option<u8> {
            None
        }
        fn write_bytes(&mut self, bytes: &[u8]) {
            self.0.push(bytes.to_vec());
        }
    }

    #[test]
    fn writes_whole_lines() {
        let mut port = Calls::default();
        write!(SerialWriter(&mut port), "ab\ncd\n\n{}", 42).unwrap();
        let calls: Vec<&[u8]> = port.0.iter().map(Vec::as_slice).collect();
        assert_eq!(calls, [&b"ab"[..], b"\r\n", b"cd", b"\r\n", b"\r\n", b"42"]);
    }
}
