//! A user program that exercises `fork`, `execve` and `wait4`: it forks a
//! child that changes memory and exits, then forks one that execs this same
//! program again with arguments and an environment, and reaps both.
//! Started as `init`, run again as `init child`.
#![no_std]
#![no_main]

use core::fmt::Write;

#[cfg(target_arch = "riscv64")]
mod sys {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const GETPID: u64 = 172;
    pub const GETPPID: u64 = 173;
    pub const EXECVE: u64 = 221;
    pub const WAIT4: u64 = 260;

    pub fn call(nr: u64, a: [u64; 5]) -> i64 {
        let ret: u64;
        // SAFETY: a7 = number, a0-a4 = arguments, a0 = result.
        unsafe {
            core::arch::asm!("ecall", in("a7") nr, inlateout("a0") a[0] => ret, in("a1") a[1], in("a2") a[2],
                in("a3") a[3], in("a4") a[4], options(nostack))
        };
        ret as i64
    }

    /// `clone(SIGCHLD, 0, ...)`: the asm-generic `fork`.
    pub fn fork() -> i64 {
        call(220, [17, 0, 0, 0, 0])
    }

    /// Entry: pass the initial stack pointer (at `argc`) to `main`.
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub extern "C" fn _start() -> ! {
        core::arch::naked_asm!("mv a0, sp", "j {}", sym super::main)
    }
}

#[cfg(target_arch = "aarch64")]
mod sys {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const GETPID: u64 = 172;
    pub const GETPPID: u64 = 173;
    pub const EXECVE: u64 = 221;
    pub const WAIT4: u64 = 260;

    pub fn call(nr: u64, a: [u64; 5]) -> i64 {
        let ret: u64;
        // SAFETY: x8 = number, x0-x4 = arguments, x0 = result.
        unsafe {
            core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a[0] => ret, in("x1") a[1], in("x2") a[2],
                in("x3") a[3], in("x4") a[4], options(nostack))
        };
        ret as i64
    }

    /// `clone(SIGCHLD, 0, ...)`: the asm-generic `fork`.
    pub fn fork() -> i64 {
        call(220, [17, 0, 0, 0, 0])
    }

    /// Entry: pass the initial stack pointer (at `argc`) to `main`.
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub extern "C" fn _start() -> ! {
        core::arch::naked_asm!("mov x0, sp", "b {}", sym super::main)
    }
}

#[cfg(target_arch = "x86_64")]
mod sys {
    pub const WRITE: u64 = 1;
    pub const EXIT: u64 = 60;
    pub const GETPID: u64 = 39;
    pub const GETPPID: u64 = 110;
    pub const EXECVE: u64 = 59;
    pub const WAIT4: u64 = 61;

    pub fn call(nr: u64, a: [u64; 5]) -> i64 {
        let ret: u64;
        // SAFETY: rax = number, rdi/rsi/rdx/r10/r8 = arguments; the CPU
        // clobbers rcx and r11.
        unsafe {
            core::arch::asm!("syscall", inlateout("rax") nr => ret, in("rdi") a[0], in("rsi") a[1], in("rdx") a[2],
                in("r10") a[3], in("r8") a[4], out("rcx") _, out("r11") _, options(nostack))
        };
        ret as i64
    }

    pub fn fork() -> i64 {
        call(57, [0; 5])
    }

    /// Entry: pass the initial stack pointer (at `argc`) to `main`.
    #[unsafe(naked)]
    #[unsafe(no_mangle)]
    pub extern "C" fn _start() -> ! {
        core::arch::naked_asm!("mov rdi, rsp", "call {}", sym super::main)
    }
}

/// Formats into a fixed buffer (there is no heap here).
struct Buf {
    bytes: [u8; 128],
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

/// Writes one formatted line to standard output.
macro_rules! say {
    ($($arg:tt)*) => {{
        let mut buf = Buf { bytes: [0; 128], len: 0 };
        let _ = write!(buf, $($arg)*);
        sys::call(sys::WRITE, [1, buf.bytes.as_ptr() as u64, buf.len as u64, 0, 0]);
    }};
}

fn exit(code: u64) -> ! {
    sys::call(sys::EXIT, [code, 0, 0, 0, 0]);
    loop {}
}

/// `wait4(pid, &status, 0, NULL)`: the child reaped (or `-errno`) and the
/// code it exited with.
fn wait(pid: i64) -> (i64, i32) {
    let mut status = 0i32;
    let r = sys::call(sys::WAIT4, [pid as u64, &mut status as *mut i32 as u64, 0, 0, 0]);
    (r, (status >> 8) & 0xff)
}

/// The NUL-terminated string at `p`.
///
/// # Safety
/// `p` must point at a NUL-terminated string that lives forever.
unsafe fn cstr(p: *const u8) -> &'static str {
    let mut n = 0;
    // SAFETY: the caller promises a terminator.
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    // SAFETY: as above; the kernel copied these bytes from our own strings.
    core::str::from_utf8(unsafe { core::slice::from_raw_parts(p, n) }).unwrap_or("?")
}

/// Lives in the writable data segment: the fork child changes its copy.
static mut MARK: u64 = 1;

/// # Safety
/// `sp` must be the initial stack pointer the kernel set up.
unsafe extern "C" fn main(sp: *const u64) -> ! {
    // SAFETY: the kernel laid out argc, argv, NULL, envp, NULL at `sp`.
    let (argc, argv) = unsafe { (*sp as usize, sp.add(1) as *const *const u8) };
    // SAFETY: as above.
    let arg = |i: usize| unsafe { cstr(*argv.add(i)) };
    let pid = sys::call(sys::GETPID, [0; 5]);
    let ppid = sys::call(sys::GETPPID, [0; 5]);
    if argc >= 2 && arg(1) == "child" {
        // SAFETY: envp starts after argv's NULL; this program is given one
        // variable.
        let env = unsafe { cstr(*argv.add(argc + 1)) };
        say!("pid {pid} (parent {ppid}) exec'd as \"{} {}\" with {env}", arg(0), arg(1));
        exit(5);
    }

    let child = sys::fork();
    if child == 0 {
        // SAFETY: single-threaded program.
        unsafe { MARK = 2 };
        say!("fork child: pid {pid_now}, parent {parent}", pid_now = sys::call(sys::GETPID, [0; 5]),
            parent = sys::call(sys::GETPPID, [0; 5]));
        exit(7);
    }
    let (reaped, code) = wait(child);
    // SAFETY: single-threaded program.
    let mark = unsafe { MARK };
    say!("fork: pid {pid} reaped child {reaped} (status {code}); parent's memory unchanged: {}",
        if reaped == child && mark == 1 { "ok" } else { "FAILED" });

    if sys::fork() == 0 {
        let path = b"/bin/init\0";
        let args = [b"init\0".as_ptr(), b"child\0".as_ptr(), core::ptr::null()];
        let env = [b"HOME=/\0".as_ptr(), core::ptr::null()];
        let r = sys::call(sys::EXECVE, [path.as_ptr() as u64, args.as_ptr() as u64, env.as_ptr() as u64, 0, 0]);
        say!("execve failed: {r}");
        exit(127);
    }
    let (reaped, code) = wait(-1);
    let (none, _) = wait(-1);
    say!("execve: child {reaped} exited with status {code}; then wait4 says {none} (-ECHILD)");
    exit(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(101)
}
