//! A user program: an ordinary `no_std` Rust binary, compiled to an ELF by
//! each example kernel's build script and loaded with `osmium_boot::elf`.
//! System calls follow Linux numbering and conventions for each
//! architecture (`syscall`, `ecall`, `svc #0`).
#![no_std]
#![no_main]

use core::fmt::Write;

#[cfg(target_arch = "x86_64")]
mod sys {
    pub const WRITE: u64 = 1;
    pub const WRITEV: u64 = 20;
    pub const MMAP: u64 = 9;
    pub const BRK: u64 = 12;
    pub const GETPID: u64 = 39;
    pub const UNAME: u64 = 63;
    pub const READ: u64 = 0;
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const GETDENTS64: u64 = 217;
    pub const EXIT: u64 = 60;

    pub fn call3(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
        let ret;
        // SAFETY: rax = number, rdi/rsi/rdx = arguments; the CPU clobbers
        // rcx and r11.
        unsafe {
            core::arch::asm!("syscall", inlateout("rax") nr => ret, in("rdi") a0, in("rsi") a1, in("rdx") a2,
                 out("rcx") _, out("r11") _, options(nostack))
        };
        ret
    }

    pub fn call6(nr: u64, a: [u64; 6]) -> u64 {
        let ret;
        // SAFETY: as for `call3`, with r10, r8 and r9 for arguments 4-6.
        unsafe {
            core::arch::asm!("syscall", inlateout("rax") nr => ret, in("rdi") a[0], in("rsi") a[1], in("rdx") a[2],
                 in("r10") a[3], in("r8") a[4], in("r9") a[5], out("rcx") _, out("r11") _, options(nostack))
        };
        ret
    }
}

#[cfg(target_arch = "riscv64")]
mod sys {
    pub const WRITE: u64 = 64;
    pub const WRITEV: u64 = 66;
    pub const MMAP: u64 = 222;
    pub const BRK: u64 = 214;
    pub const GETPID: u64 = 172;
    pub const UNAME: u64 = 160;
    pub const READ: u64 = 63;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const GETDENTS64: u64 = 61;
    pub const EXIT: u64 = 93;

    pub fn call3(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
        let ret;
        // SAFETY: a7 = number, a0-a2 = arguments, a0 = result.
        unsafe { core::arch::asm!("ecall", in("a7") nr, inlateout("a0") a0 => ret, in("a1") a1, in("a2") a2, options(nostack)) };
        ret
    }

    pub fn call6(nr: u64, a: [u64; 6]) -> u64 {
        let ret;
        // SAFETY: a7 = number, a0-a5 = arguments, a0 = result.
        unsafe {
            core::arch::asm!("ecall", in("a7") nr, inlateout("a0") a[0] => ret, in("a1") a[1], in("a2") a[2],
                in("a3") a[3], in("a4") a[4], in("a5") a[5], options(nostack))
        };
        ret
    }
}

#[cfg(target_arch = "aarch64")]
mod sys {
    pub const WRITE: u64 = 64;
    pub const WRITEV: u64 = 66;
    pub const MMAP: u64 = 222;
    pub const BRK: u64 = 214;
    pub const GETPID: u64 = 172;
    pub const UNAME: u64 = 160;
    pub const READ: u64 = 63;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const GETDENTS64: u64 = 61;
    pub const EXIT: u64 = 93;

    pub fn call3(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
        let ret;
        // SAFETY: x8 = number, x0-x2 = arguments, x0 = result.
        unsafe { core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a0 => ret, in("x1") a1, in("x2") a2, options(nostack)) };
        ret
    }

    pub fn call6(nr: u64, a: [u64; 6]) -> u64 {
        let ret;
        // SAFETY: x8 = number, x0-x5 = arguments, x0 = result.
        unsafe {
            core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a[0] => ret, in("x1") a[1], in("x2") a[2],
                in("x3") a[3], in("x4") a[4], in("x5") a[5], options(nostack))
        };
        ret
    }
}

fn write(bytes: &[u8]) {
    sys::call3(sys::WRITE, 1, bytes.as_ptr() as u64, bytes.len() as u64);
}

fn exit(code: u64) -> ! {
    sys::call3(sys::EXIT, code, 0, 0);
    loop {}
}

/// Formats into a fixed buffer (there is no heap here).
struct Buf {
    bytes: [u8; 96],
    len: usize,
}

impl Write for Buf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len + s.len();
        self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Lives in the writable data segment.
static mut CALLS: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let primes = (2u64..200).filter(|n| (2..*n).take_while(|d| d * d <= *n).all(|d| n % d != 0)).count();
    // SAFETY: single-threaded program.
    unsafe { CALLS += 1 };
    let mut buf = Buf { bytes: [0; 96], len: 0 };
    let _ = write!(buf, "hello from a Rust ELF: {primes} primes below 200, data segment says {}", unsafe { CALLS });
    write(&buf.bytes[..buf.len]);
    process_api();
    files();
    exit(0)
}

/// Exercises the kernel's process API and reports what it saw in one line.
fn process_api() {
    let pid = sys::call3(sys::GETPID, 0, 0, 0);

    // struct utsname: six 65-byte fields; sysname is first, machine fifth.
    let mut uts = [0u8; 65 * 6];
    sys::call3(sys::UNAME, uts.as_mut_ptr() as u64, 0, 0);
    let field = |i: usize| {
        let f = &uts[i * 65..(i + 1) * 65];
        core::str::from_utf8(&f[..f.iter().position(|&b| b == 0).unwrap_or(65)]).unwrap_or("?")
    };

    // Grow the heap by two pages and use them.
    let base = sys::call3(sys::BRK, 0, 0, 0);
    let top = sys::call3(sys::BRK, base + 8192, 0, 0);
    let heap = (top == base + 8192).then(|| {
        let p = base as *mut u64;
        // SAFETY: the kernel just mapped base..top read/write.
        unsafe {
            p.write_volatile(0x5eed);
            p.add(1023).write_volatile(7);
            p.read_volatile() == 0x5eed && p.add(1023).read_volatile() == 7
        }
    });

    // One anonymous page: PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS.
    let page = sys::call6(sys::MMAP, [0, 4096, 3, 0x22, u64::MAX, 0]);
    let mapped = (page as i64) > 0 && {
        let p = page as *mut u32;
        // SAFETY: the kernel just mapped this page read/write.
        unsafe {
            p.write_volatile(42);
            p.read_volatile() == 42
        }
    };

    let mut buf = Buf { bytes: [0; 96], len: 0 };
    let ok = |b: bool| if b { "ok" } else { "FAILED" };
    let _ = write!(buf, "pid {pid} on {}/{}: brk {}, mmap {}, writev ", field(0), field(4), ok(heap == Some(true)),
        ok(mapped));
    // Two pieces, one line: the second iovec finishes the message.
    let iov = [buf.bytes.as_ptr() as u64, buf.len as u64, b"ok".as_ptr() as u64, 2];
    let n = sys::call3(sys::WRITEV, 1, iov.as_ptr() as u64, 2);
    if n != buf.len as u64 + 2 {
        write(b"writev FAILED");
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(101)
}

const AT_FDCWD: u64 = -100i64 as u64;

/// Opens a NUL-terminated `path` with Linux `flags` (`O_CREAT` and friends
/// have the same values on every architecture used here).
fn open(path: &[u8], flags: u64) -> i64 {
    sys::call6(sys::OPENAT, [AT_FDCWD, path.as_ptr() as u64, flags, 0o644, 0, 0]) as i64
}

/// Reads files from the kernel's namespace, writes one, and lists `/`.
fn files() {
    let mut motd = [0u8; 64];
    let fd = open(b"/etc/motd\0", 0);
    let n = if fd >= 0 { sys::call3(sys::READ, fd as u64, motd.as_mut_ptr() as u64, 64) as usize } else { 0 };
    sys::call3(sys::CLOSE, fd as u64, 0, 0);
    let motd = core::str::from_utf8(&motd[..n.min(64)]).unwrap_or("?").trim_end();

    // O_WRONLY | O_CREAT | O_TRUNC, then read it back.
    let fd = open(b"/tmp/note\0", 0o1101);
    let wrote = fd >= 0 && sys::call3(sys::WRITE, fd as u64, b"kept".as_ptr() as u64, 4) == 4;
    sys::call3(sys::CLOSE, fd as u64, 0, 0);
    let mut back = [0u8; 8];
    let fd = open(b"/tmp/note\0", 0);
    let round_trip = wrote && fd >= 0 && sys::call3(sys::READ, fd as u64, back.as_mut_ptr() as u64, 8) == 4
        && &back[..4] == b"kept";
    sys::call3(sys::CLOSE, fd as u64, 0, 0);

    // Count the entries of "/", "." and ".." included.
    let mut dents = [0u8; 512];
    let fd = open(b"/\0", 0);
    let mut entries = 0;
    loop {
        let n = sys::call3(sys::GETDENTS64, fd as u64, dents.as_mut_ptr() as u64, dents.len() as u64) as i64;
        if n <= 0 {
            break;
        }
        let mut off = 0;
        while off < n as usize {
            entries += 1;
            off += u16::from_ne_bytes([dents[off + 16], dents[off + 17]]) as usize;
        }
    }
    sys::call3(sys::CLOSE, fd as u64, 0, 0);

    let mut buf = Buf { bytes: [0; 96], len: 0 };
    let ok = if round_trip { "ok" } else { "FAILED" };
    let _ = write!(buf, "/etc/motd: \"{motd}\"; /tmp/note {ok}; / has {entries} entries");
    write(&buf.bytes[..buf.len]);
}
