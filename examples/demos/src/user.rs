//! Pieces the example kernels share for running user programs.

use osmium::fs::{Errno, File, FileKind, Stat};
use osmium::hal::println;

/// Descriptors 0, 1 and 2 of every process: each write becomes one line of
/// the kernel log, tagged with the process's name. Reads see end of file.
pub struct LogConsole;

impl File for LogConsole {
    fn write(&self, _off: u64, buf: &[u8]) -> Result<usize, Errno> {
        let name = osmium::proc::current().map_or("?", |p| p.name());
        println!("[user]  {name}: {}", core::str::from_utf8(buf).unwrap_or("<not utf-8>"));
        Ok(buf.len())
    }

    fn read(&self, _off: u64, _buf: &mut [u8]) -> Result<usize, Errno> {
        Ok(0)
    }

    fn stat(&self) -> Stat {
        Stat { kind: FileKind::CharDevice, mode: 0o620, ..Stat::default() }
    }
}
