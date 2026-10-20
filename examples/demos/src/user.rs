//! Pieces the example kernels share for running user programs.

use alloc::sync::Weak;

use osmium::fs::{Errno, File, FileKind, Stat};
use osmium::hal::println;
use osmium::proc::Process;

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

/// Waits, briefly, until `processes` have been freed, and returns how many
/// were. A joined task has exited, but the CPU that ran it drops it (and its
/// process) only once it has finished switching away, which may lag behind.
pub fn freed(processes: &[Weak<Process>]) -> usize {
    let count = || processes.iter().filter(|p| p.strong_count() == 0).count();
    for _ in 0..1_000_000 {
        if count() == processes.len() {
            break;
        }
        osmium::arch::cpu::spin_hint();
    }
    count()
}
