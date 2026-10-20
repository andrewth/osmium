//! A user program that exercises `fork`, `execve` and `wait4`: it forks a
//! child that changes memory and exits, then forks one that execs this same
//! program again with arguments and an environment, and reaps both. Where
//! the kernel offers FP (`AT_HWCAP`), it also checks that FP registers are
//! inherited by `fork`, cleared by `execve` and kept across switches.
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
    pub const SCHED_YIELD: u64 = 124;

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

    /// `AT_HWCAP` bit for the D extension.
    pub const HWCAP_FP: u64 = 1 << (b'd' - b'a');

    /// Puts `v` in `f8` and selects round-towards-zero if `rtz`.
    pub fn fp_set(v: u64, rtz: bool) {
        // SAFETY: this program is soft-float: nothing else uses FP registers.
        unsafe {
            core::arch::asm!(".option push", ".option arch, +d", "fmv.d.x f8, {v}", "fsrm {m}", ".option pop",
                v = in(reg) v, m = in(reg) rtz as u64, options(nomem, nostack))
        }
    }

    /// `f8`, and whether round-towards-zero is selected.
    pub fn fp_get() -> (u64, bool) {
        let (v, m): (u64, u64);
        // SAFETY: as above.
        unsafe {
            core::arch::asm!(".option push", ".option arch, +d", "fmv.x.d {v}, f8", "frrm {m}", ".option pop",
                v = out(reg) v, m = out(reg) m, options(nomem, nostack))
        }
        (v, m == 1)
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
    pub const SCHED_YIELD: u64 = 124;

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

    /// `AT_HWCAP` bit `HWCAP_FP`.
    pub const HWCAP_FP: u64 = 1;

    /// Puts `v` in `d8` and selects round-towards-zero if `rtz`.
    pub fn fp_set(v: u64, rtz: bool) {
        // SAFETY: this program is soft-float: nothing else uses FP registers.
        unsafe {
            core::arch::asm!(".arch_extension fp", "fmov d8, {v}", "msr fpcr, {m}",
                v = in(reg) v, m = in(reg) if rtz { 3u64 << 22 } else { 0 }, options(nomem, nostack))
        }
    }

    /// `d8`, and whether round-towards-zero is selected.
    pub fn fp_get() -> (u64, bool) {
        let (v, m): (u64, u64);
        // SAFETY: as above.
        unsafe {
            core::arch::asm!(".arch_extension fp", "fmov {v}, d8", "mrs {m}, fpcr",
                v = out(reg) v, m = out(reg) m, options(nomem, nostack))
        }
        (v, m >> 22 & 3 == 3)
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
    pub const SCHED_YIELD: u64 = 24;

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

    /// `AT_HWCAP` (CPUID.1:EDX) bit for SSE2.
    pub const HWCAP_FP: u64 = 1 << 26;

    /// Puts `v` in `xmm8` and selects round-towards-zero if `rtz`.
    pub fn fp_set(v: u64, rtz: bool) {
        let mxcsr: u32 = if rtz { 0x7f80 } else { 0x1f80 };
        // SAFETY: this program is soft-float: nothing else uses SSE registers.
        unsafe {
            core::arch::asm!("movq xmm8, {v}", "ldmxcsr [{m}]", v = in(reg) v, m = in(reg) &mxcsr,
                options(readonly, nostack))
        }
    }

    /// `xmm8`'s low half, and whether round-towards-zero is selected.
    pub fn fp_get() -> (u64, bool) {
        let v: u64;
        let mut mxcsr = 0u32;
        // SAFETY: as above.
        unsafe {
            core::arch::asm!("movq {v}, xmm8", "stmxcsr [{m}]", v = out(reg) v, m = in(reg) &mut mxcsr,
                options(nostack))
        }
        (v, mxcsr >> 13 & 3 == 3)
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

/// The `AT_HWCAP` entry of the auxiliary vector at `auxv`, or 0.
///
/// # Safety
/// `auxv` must point at the kernel's (key, value) pairs, ended by key 0.
unsafe fn hwcap(mut auxv: *const u64) -> u64 {
    // SAFETY: the caller promises the terminator.
    while unsafe { *auxv } != 0 {
        // SAFETY: as above.
        if unsafe { *auxv } == 16 {
            // SAFETY: each key has a value.
            return unsafe { *auxv.add(1) };
        }
        // SAFETY: as above.
        auxv = unsafe { auxv.add(2) };
    }
    0
}

/// Calls `sched_yield` `n` times, checking after each that the FP state is
/// still `(v, rtz)`.
fn fp_kept(v: u64, rtz: bool, n: usize) -> bool {
    (0..n).all(|_| {
        sys::call(sys::SCHED_YIELD, [0; 5]);
        sys::fp_get() == (v, rtz)
    })
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
    // SAFETY: envp starts after argv's NULL; this program is given at most
    // one variable, so auxv follows the envp NULL at argc + 2 or argc + 3.
    let auxv = unsafe {
        let envp = argv.add(argc + 1);
        let envc = if (*envp).is_null() { 0 } else { 1 };
        envp.add(envc + 1) as *const u64
    };
    // SAFETY: the kernel ended auxv with AT_NULL.
    let fp = unsafe { hwcap(auxv) } & sys::HWCAP_FP != 0;
    if argc >= 2 && arg(1) == "child" {
        // SAFETY: as above.
        let env = unsafe { cstr(*argv.add(argc + 1)) };
        say!("pid {pid} (parent {ppid}) exec'd as \"{} {}\" with {env}", arg(0), arg(1));
        if fp {
            // The parent set FP registers before forking this process.
            let ok = sys::fp_get() == (0, false);
            say!("fp: exec'd program starts with cleared FP registers: {}", if ok { "ok" } else { "FAILED" });
        }
        exit(5);
    }
    if fp {
        sys::fp_set(0x0123_4567_89ab_cdef, true);
    }

    let child = sys::fork();
    if child == 0 {
        // SAFETY: single-threaded program.
        unsafe { MARK = 2 };
        say!(
            "fork child: pid {pid_now}, parent {parent}",
            pid_now = sys::call(sys::GETPID, [0; 5]),
            parent = sys::call(sys::GETPPID, [0; 5])
        );
        exit(7);
    }
    let (reaped, code) = wait(child);
    // SAFETY: single-threaded program.
    let mark = unsafe { MARK };
    say!(
        "fork: pid {pid} reaped child {reaped} (status {code}); parent's memory unchanged: {}",
        if reaped == child && mark == 1 { "ok" } else { "FAILED" }
    );

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

    if fp {
        // Each process's FP registers are its own: the child inherits ours,
        // then changes them while we yield and wait.
        let ours = (0x0123_4567_89ab_cdef, true);
        if sys::fork() == 0 {
            let inherited = sys::fp_get() == ours;
            sys::fp_set(0xfedc_ba98_7654_3210, false);
            exit(if inherited && fp_kept(0xfedc_ba98_7654_3210, false, 50) { 0 } else { 1 });
        }
        let kept = fp_kept(ours.0, ours.1, 50);
        let (_, code) = wait(-1);
        let ok = kept && code == 0 && sys::fp_get() == ours;
        say!("fp: FP registers inherited by fork and kept across switches: {}", if ok { "ok" } else { "FAILED" });
    } else {
        say!("fp: the kernel does not offer FP (AT_HWCAP)");
    }
    exit(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(101)
}
