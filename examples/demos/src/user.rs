//! Pieces the example kernels share for running user programs.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};

use osmium::fs::dev::{DevDir, Null, Zero};
use osmium::fs::{Errno, File, FileKind, OpenFlags, RamFs, Stat, Vfs};
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

/// Builds the namespace user programs see, and gives it and the console to
/// osmium-proc: a RAM file system with `/etc/motd` and a world-writable
/// `/tmp`, and `/dev` holding `console`, `null` and `zero`.
pub fn boot_vfs() {
    let vfs: &'static Vfs = Box::leak(Box::new(Vfs::new(RamFs::new(1).root())));
    vfs.mkdir("/etc", 0o755).unwrap();
    let motd = vfs.open("/etc/motd", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
    motd.write(0, b"welcome to osmium\n").unwrap();
    vfs.mkdir("/tmp", 0o1777).unwrap();
    vfs.mkdir("/dev", 0o755).unwrap();
    let console: Arc<dyn File> = Arc::new(LogConsole);
    let dev = DevDir::new(2);
    dev.insert("console", console.clone());
    dev.insert("null", Arc::new(Null::new()));
    dev.insert("zero", Arc::new(Zero::new()));
    vfs.mount("/dev", Arc::new(dev)).unwrap();
    osmium::proc::set_vfs(vfs);
    osmium::proc::set_console(console);
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
