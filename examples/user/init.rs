//! A user program that exercises `fork`, `execve` and `wait4`: it forks a
//! child that changes memory and exits, then forks one that execs this same
//! program again with arguments and an environment, and reaps both. Where
//! the kernel offers FP (`AT_HWCAP`), it also checks that FP registers are
//! inherited by `fork`, cleared by `execve` and kept across switches.
//! Started as `init`, run again as `init child`.
#![no_std]
#![no_main]

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

#[cfg(target_arch = "riscv64")]
mod sys {
    pub const WRITE: u64 = 64;
    pub const EXIT: u64 = 93;
    pub const GETPID: u64 = 172;
    pub const GETPPID: u64 = 173;
    pub const EXECVE: u64 = 221;
    pub const WAIT4: u64 = 260;
    pub const SCHED_YIELD: u64 = 124;
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const LSEEK: u64 = 62;
    pub const MMAP: u64 = 222;
    pub const MUNMAP: u64 = 215;
    pub const MPROTECT: u64 = 226;
    pub const MSYNC: u64 = 227;
    pub const GETCPU: u64 = 168;

    pub fn call(nr: u64, a: [u64; 5]) -> i64 {
        call6(nr, [a[0], a[1], a[2], a[3], a[4], 0])
    }

    pub fn call6(nr: u64, a: [u64; 6]) -> i64 {
        let ret: u64;
        // SAFETY: a7 = number, a0-a5 = arguments, a0 = result.
        unsafe {
            core::arch::asm!("ecall", in("a7") nr, inlateout("a0") a[0] => ret, in("a1") a[1], in("a2") a[2],
                in("a3") a[3], in("a4") a[4], in("a5") a[5], options(nostack))
        };
        ret as i64
    }

    /// `clone(SIGCHLD, 0, ...)`: the asm-generic `fork`.
    pub fn fork() -> i64 {
        call(220, [17, 0, 0, 0, 0])
    }

    pub const RT_SIGACTION: u64 = 134;
    pub const KILL: u64 = 129;
    pub const GETTID: u64 = 178;
    pub const FUTEX: u64 = 98;
    pub const EXIT_GROUP: u64 = 94;
    pub const READ: u64 = 63;
    pub const PIPE2: u64 = 59;
    pub const TKILL: u64 = 130;
    pub const RT_SIGPROCMASK: u64 = 135;
    pub const RT_SIGSUSPEND: u64 = 133;
    pub const SIGALTSTACK: u64 = 132;
    pub const RT_SIGQUEUEINFO: u64 = 138;

    /// `sigaction` as the kernel reads it: no restorer, the kernel supplies one.
    #[repr(C)]
    pub struct SigAction {
        pub handler: u64,
        pub flags: u64,
        pub mask: u64,
    }

    pub fn sigaction(handler: u64) -> SigAction {
        SigAction { handler, flags: 4, mask: 0 }
    }

    /// `clone` that runs `f(arg)` on the new thread's stack (ending at
    /// `stack_top`, 16-byte aligned) and never returns there; returns the
    /// thread id (or `-errno`) to the caller.
    ///
    /// # Safety
    /// The stack must be writable memory that nothing else uses.
    pub unsafe fn clone_thread(
        flags: u64,
        stack_top: u64,
        ptid: u64,
        ctid: u64,
        tls: u64,
        f: extern "C" fn(u64) -> !,
        arg: u64,
    ) -> i64 {
        // The child takes its arguments off its new stack.
        let sp = stack_top - 16;
        // SAFETY: the caller owns the stack.
        unsafe { (sp as *mut [u64; 2]).write([arg, f as usize as u64]) };
        let ret: i64;
        // SAFETY: `clone`; the child path never returns here.
        unsafe {
            core::arch::asm!("ecall", "bnez a0, 2f", "ld a0, 0(sp)", "ld a1, 8(sp)", "addi sp, sp, 16", "jalr a1", "unimp", "2:", in("a7") 220u64, inlateout("a0") flags => ret, inout("a1") sp => _, inout("a2") ptid => _,
                inout("a3") tls => _, inout("a4") ctid => _, clobber_abi("C"))
        };
        ret
    }

    /// The thread pointer register.
    pub fn thread_pointer() -> u64 {
        let tp: u64;
        // SAFETY: reads a register.
        unsafe { core::arch::asm!("mv {}, tp", out(reg) tp, options(nomem, nostack)) };
        tp
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
    pub const OPENAT: u64 = 56;
    pub const CLOSE: u64 = 57;
    pub const LSEEK: u64 = 62;
    pub const MMAP: u64 = 222;
    pub const MUNMAP: u64 = 215;
    pub const MPROTECT: u64 = 226;
    pub const MSYNC: u64 = 227;
    pub const GETCPU: u64 = 168;

    pub fn call(nr: u64, a: [u64; 5]) -> i64 {
        call6(nr, [a[0], a[1], a[2], a[3], a[4], 0])
    }

    pub fn call6(nr: u64, a: [u64; 6]) -> i64 {
        let ret: u64;
        // SAFETY: x8 = number, x0-x5 = arguments, x0 = result.
        unsafe {
            core::arch::asm!("svc #0", in("x8") nr, inlateout("x0") a[0] => ret, in("x1") a[1], in("x2") a[2],
                in("x3") a[3], in("x4") a[4], in("x5") a[5], options(nostack))
        };
        ret as i64
    }

    /// `clone(SIGCHLD, 0, ...)`: the asm-generic `fork`.
    pub fn fork() -> i64 {
        call(220, [17, 0, 0, 0, 0])
    }

    pub const RT_SIGACTION: u64 = 134;
    pub const KILL: u64 = 129;
    pub const GETTID: u64 = 178;
    pub const FUTEX: u64 = 98;
    pub const EXIT_GROUP: u64 = 94;
    pub const READ: u64 = 63;
    pub const PIPE2: u64 = 59;
    pub const TKILL: u64 = 130;
    pub const RT_SIGPROCMASK: u64 = 135;
    pub const RT_SIGSUSPEND: u64 = 133;
    pub const SIGALTSTACK: u64 = 132;
    pub const RT_SIGQUEUEINFO: u64 = 138;

    /// `sigaction` as the kernel reads it: no restorer, the kernel supplies one.
    #[repr(C)]
    pub struct SigAction {
        pub handler: u64,
        pub flags: u64,
        pub mask: u64,
    }

    pub fn sigaction(handler: u64) -> SigAction {
        SigAction { handler, flags: 4, mask: 0 }
    }

    /// `clone` that runs `f(arg)` on the new thread's stack (ending at
    /// `stack_top`, 16-byte aligned) and never returns there; returns the
    /// thread id (or `-errno`) to the caller.
    ///
    /// # Safety
    /// The stack must be writable memory that nothing else uses.
    pub unsafe fn clone_thread(
        flags: u64,
        stack_top: u64,
        ptid: u64,
        ctid: u64,
        tls: u64,
        f: extern "C" fn(u64) -> !,
        arg: u64,
    ) -> i64 {
        // The child takes its arguments off its new stack.
        let sp = stack_top - 16;
        // SAFETY: the caller owns the stack.
        unsafe { (sp as *mut [u64; 2]).write([arg, f as usize as u64]) };
        let ret: i64;
        // SAFETY: `clone`; the child path never returns here.
        unsafe {
            core::arch::asm!("svc #0", "cbnz x0, 2f", "ldp x0, x1, [sp], #16", "blr x1", "brk #0", "2:", in("x8") 220u64, inlateout("x0") flags => ret, inout("x1") sp => _, inout("x2") ptid => _,
                inout("x3") tls => _, inout("x4") ctid => _, clobber_abi("C"))
        };
        ret
    }

    /// The thread pointer register.
    pub fn thread_pointer() -> u64 {
        let tp: u64;
        // SAFETY: reads a register.
        unsafe { core::arch::asm!("mrs {}, tpidrro_el0", out(reg) tp, options(nomem, nostack)) };
        tp
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
    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const LSEEK: u64 = 8;
    pub const MMAP: u64 = 9;
    pub const MUNMAP: u64 = 11;
    pub const MPROTECT: u64 = 10;
    pub const MSYNC: u64 = 26;
    pub const GETCPU: u64 = 309;

    pub fn call(nr: u64, a: [u64; 5]) -> i64 {
        call6(nr, [a[0], a[1], a[2], a[3], a[4], 0])
    }

    pub fn call6(nr: u64, a: [u64; 6]) -> i64 {
        let ret: u64;
        // SAFETY: rax = number, rdi/rsi/rdx/r10/r8/r9 = arguments; the CPU
        // clobbers rcx and r11.
        unsafe {
            core::arch::asm!("syscall", inlateout("rax") nr => ret, in("rdi") a[0], in("rsi") a[1], in("rdx") a[2],
                in("r10") a[3], in("r8") a[4], in("r9") a[5], out("rcx") _, out("r11") _, options(nostack))
        };
        ret as i64
    }

    pub fn fork() -> i64 {
        call(57, [0; 5])
    }

    pub const RT_SIGACTION: u64 = 13;
    pub const KILL: u64 = 62;
    pub const GETTID: u64 = 186;
    pub const FUTEX: u64 = 202;
    pub const EXIT_GROUP: u64 = 231;
    pub const READ: u64 = 0;
    pub const PIPE2: u64 = 293;
    pub const TKILL: u64 = 200;
    pub const RT_SIGPROCMASK: u64 = 14;
    pub const RT_SIGSUSPEND: u64 = 130;
    pub const SIGALTSTACK: u64 = 131;
    pub const RT_SIGQUEUEINFO: u64 = 129;

    /// `sigaction` as the kernel reads it; without `SA_RESTORER` the kernel
    /// supplies the return trampoline.
    #[repr(C)]
    pub struct SigAction {
        pub handler: u64,
        pub flags: u64,
        pub restorer: u64,
        pub mask: u64,
    }

    pub fn sigaction(handler: u64) -> SigAction {
        SigAction { handler, flags: 4, restorer: 0, mask: 0 }
    }

    /// `clone` that runs `f(arg)` on the new thread's stack (ending at
    /// `stack_top`, 16-byte aligned) and never returns there; returns the
    /// thread id (or `-errno`) to the caller.
    ///
    /// # Safety
    /// The stack must be writable memory that nothing else uses.
    pub unsafe fn clone_thread(
        flags: u64,
        stack_top: u64,
        ptid: u64,
        ctid: u64,
        tls: u64,
        f: extern "C" fn(u64) -> !,
        arg: u64,
    ) -> i64 {
        // The child takes its arguments off its new stack.
        let sp = stack_top - 16;
        // SAFETY: the caller owns the stack.
        unsafe { (sp as *mut [u64; 2]).write([arg, f as usize as u64]) };
        let ret: i64;
        // SAFETY: `clone`; the child path never returns here.
        unsafe {
            core::arch::asm!("syscall", "test rax, rax", "jnz 2f", "pop rdi", "pop rax", "call rax", "ud2", "2:",
                inlateout("rax") 56u64 => ret, inout("rdi") flags => _, inout("rsi") sp => _, inout("rdx") ptid => _,
                inout("r10") ctid => _, inout("r8") tls => _, out("rcx") _, out("r11") _)
        };
        ret
    }

    /// The thread pointer: the word at `FS:0`, which the program makes point at itself.
    pub fn thread_pointer() -> u64 {
        let tp: u64;
        // SAFETY: reads the word at FS:0.
        unsafe { core::arch::asm!("mov {}, fs:[0]", out(reg) tp, options(nostack, readonly)) };
        tp
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

static GOT_SIGNAL: AtomicU32 = AtomicU32::new(0);
static GOT_CHLD: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_signal(sig: i32, _info: *const u8, _ctx: *const u8) {
    GOT_SIGNAL.store(sig as u32, Ordering::SeqCst);
}

extern "C" fn on_chld(_sig: i32, _info: *const u8, _ctx: *const u8) {
    GOT_CHLD.fetch_add(1, Ordering::SeqCst);
}

/// Reports the fault address from `siginfo` and ends the process with 42.
extern "C" fn on_segv(sig: i32, info: *const u8, _ctx: *const u8) {
    // SAFETY: the kernel put a `siginfo` there; `si_addr` is at offset 16.
    let addr = unsafe { (info.add(16) as *const u64).read() };
    say!("signals: handler for signal {sig} ran: fault at address {addr:#x}");
    exit(42)
}

fn catch(sig: u64, handler: extern "C" fn(i32, *const u8, *const u8)) {
    let act = sys::sigaction(handler as usize as u64);
    let r = sys::call(sys::RT_SIGACTION, [sig, &act as *const sys::SigAction as u64, 0, 8, 0]);
    assert!(r == 0);
}

/// A thread's stack, 16-byte aligned, and the thread pointer block its
/// creator gives it (the first word points at the block, as on x86_64).
#[repr(align(16))]
struct Stack([u8; 16384]);
static mut WORKER_STACK: Stack = Stack([0; 16384]);
static mut SPINNER_STACK: Stack = Stack([0; 16384]);
static mut WAITER_STACKS: [Stack; 3] = [const { Stack([0; 16384]) }; 3];
#[repr(C)]
struct Tls {
    me: u64,
    tag: u64,
}
static mut WORKER_TLS: Tls = Tls { me: 0, tag: 0xfeed };
static COUNTER: AtomicU32 = AtomicU32::new(0);
static WORKER_TID: AtomicU32 = AtomicU32::new(0);
static WORKER_TLS_OK: AtomicU32 = AtomicU32::new(0);
/// `CLONE_PARENT_SETTID` and `CLONE_CHILD_SETTID`/`CLONE_CHILD_CLEARTID` words.
static mut PTID: u32 = 0;
static mut CTID: u32 = 0;

extern "C" fn worker(arg: u64) -> ! {
    COUNTER.fetch_add(arg as u32, Ordering::SeqCst);
    WORKER_TID.store(sys::call(sys::GETTID, [0; 5]) as u32, Ordering::SeqCst);
    // SAFETY: only this thread reads its block, set up before it started.
    let tls = sys::thread_pointer() as *const Tls;
    let ok = tls as usize == (&raw const WORKER_TLS) as usize && unsafe { (*tls).tag } == 0xfeed;
    WORKER_TLS_OK.store(ok as u32, Ordering::SeqCst);
    // The kernel clears CTID and wakes the joiner.
    exit(0)
}

/// The futex word the waiters sleep on (0 until released), the one they are
/// requeued to, and how many have started and finished.
static GATE: AtomicU32 = AtomicU32::new(0);
static GATE2: AtomicU32 = AtomicU32::new(0);
static STARTED: AtomicU32 = AtomicU32::new(0);
static FINISHED: AtomicU32 = AtomicU32::new(0);
static mut WAITER_CTIDS: [u32; 3] = [0; 3];

extern "C" fn waiter(_: u64) -> ! {
    STARTED.fetch_add(1, Ordering::SeqCst);
    // FUTEX_WAIT | FUTEX_PRIVATE_FLAG while the gate is still 0; a gate that
    // has opened already is `EAGAIN`.
    sys::call(sys::FUTEX, [GATE.as_ptr() as u64, 128, 0, 0, 0]);
    FINISHED.fetch_add(1, Ordering::SeqCst);
    exit(0)
}

/// A page of its own, for the threads on other CPUs to read until one
/// thread unmaps it.
#[repr(align(4096))]
struct OwnPage([u8; 4096]);
static mut SMP_PAGE: OwnPage = OwnPage([1; 4096]);
static SMP_READY: AtomicU32 = AtomicU32::new(0);
static SMP_FAULTED: AtomicU32 = AtomicU32::new(0);
/// Bit `n` is set once a thread was seen running on CPU `n`.
static SMP_CPUS: AtomicU32 = AtomicU32::new(0);

fn note_cpu() {
    let mut cpu = 0u32;
    sys::call(sys::GETCPU, [&mut cpu as *mut u32 as u64, 0, 0, 0, 0]);
    SMP_CPUS.fetch_or(1 << (cpu & 31), Ordering::SeqCst);
}

/// Reads the shared page until it is unmapped under it.
extern "C" fn page_reader(_: u64) -> ! {
    note_cpu();
    SMP_READY.fetch_add(1, Ordering::SeqCst);
    loop {
        // SAFETY: a mapped byte until the leader unmaps it; then the fault
        // reaches `on_smp_segv`.
        unsafe { core::ptr::read_volatile((&raw const SMP_PAGE) as *const u8) };
    }
}

/// Counts the fault and ends this thread only.
extern "C" fn on_smp_segv(_sig: i32, _info: *const u8, _ctx: *const u8) {
    SMP_FAULTED.fetch_add(1, Ordering::SeqCst);
    exit(0)
}

extern "C" fn spinner(_: u64) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// `CLONE_VM | FS | FILES | SIGHAND | THREAD | SYSVSEM`.
const THREAD: u64 = 0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x4_0000;
const SETTLS: u64 = 0x8_0000;
const PARENT_SETTID: u64 = 0x10_0000;
const CHILD_CLEARTID: u64 = 0x20_0000;
const CHILD_SETTID: u64 = 0x100_0000;

/// Signal handlers, and threads joined with `futex`, as C libraries use them.
/// File-backed `mmap`: a private mapping is a copy, a shared one reaches the
/// file through `msync` and `munmap`, and survives `fork` as one page.
fn file_maps() {
    const AT_FDCWD: u64 = -100i64 as u64;
    // O_RDWR | O_CREAT | O_TRUNC
    const FLAGS: u64 = 2 | 0o100 | 0o1000;
    const PROT_RW: u64 = 3;
    const MAP_SHARED: u64 = 1;
    const MAP_PRIVATE: u64 = 2;
    const MS_SYNC: u64 = 4;
    let path = b"/tmp/mmap.dat\0";
    let fd = sys::call(sys::OPENAT, [AT_FDCWD, path.as_ptr() as u64, FLAGS, 0o644, 0]) as u64;
    let mut data = [0u8; 5000];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let wrote = sys::call(sys::WRITE, [fd, data.as_ptr() as u64, 5000, 0, 0]);
    let file_byte = |at: u64| {
        let mut b = [0u8; 1];
        sys::call(sys::LSEEK, [fd, at, 0, 0, 0]);
        sys::call(sys::READ, [fd, b.as_mut_ptr() as u64, 1, 0, 0]);
        b[0]
    };

    let private = sys::call6(sys::MMAP, [0, 8192, PROT_RW, MAP_PRIVATE, fd, 0]);
    let shared = sys::call6(sys::MMAP, [0, 8192, PROT_RW, MAP_SHARED, fd, 0]);
    let mut ok = wrote == 5000 && private > 0 && shared > 0;
    if ok {
        let (private, shared) = (private as *mut u8, shared as *mut u8);
        // SAFETY: both mappings are 8192 bytes, readable and writable. The
        // file has 5000 bytes, so the rest of the second page reads as zero.
        unsafe {
            ok &= private.add(4999).read_volatile() == (4999 % 251) as u8 && private.add(5000).read_volatile() == 0;
            private.write_volatile(0xee);
            ok &= file_byte(0) == 0 && private.read_volatile() == 0xee;
            shared.add(1).write_volatile(0xdd);
            ok &= sys::call(sys::MSYNC, [shared as u64, 8192, MS_SYNC, 0, 0]) == 0 && file_byte(1) == 0xdd;
            ok &= shared.read_volatile() == 0 && shared.add(4999).read_volatile() == (4999 % 251) as u8;
            // The private copy was loaded before the shared store.
            ok &= private.add(1).read_volatile() == 1;
        }
        // A forked child's store to a shared page is the parent's too.
        if sys::fork() == 0 {
            // SAFETY: as above.
            unsafe { shared.add(3).write_volatile(0x77) };
            exit(0);
        }
        wait(-1);
        // SAFETY: as above.
        unsafe {
            ok &= shared.add(3).read_volatile() == 0x77;
            shared.add(2).write_volatile(0xcc);
        }
        // Unmapping saves what the child and we stored.
        ok &= sys::call(sys::MUNMAP, [shared as u64, 8192, 0, 0, 0]) == 0;
        ok &= file_byte(2) == 0xcc && file_byte(3) == 0x77;
        // Read-only and back, with the data kept.
        ok &= sys::call(sys::MPROTECT, [private as u64, 4096, 1, 0, 0]) == 0;
        // SAFETY: as above; the page is readable.
        ok &= unsafe { private.read_volatile() } == 0xee;
        ok &= sys::call(sys::MPROTECT, [private as u64, 4096, PROT_RW, 0, 0]) == 0;
        // SAFETY: as above; the page is writable again.
        unsafe { private.write_volatile(0xef) };
        ok &= sys::call(sys::MUNMAP, [private as u64, 8192, 0, 0, 0]) == 0 && file_byte(0) == 0;
    }
    sys::call(sys::CLOSE, [fd, 0, 0, 0, 0]);
    say!("mmap: private copy, shared write-back (msync, munmap, fork), mprotect: {}", if ok { "ok" } else { "FAILED" });
}

fn signals_and_threads() {
    let pid = sys::call(sys::GETPID, [0; 5]) as u64;

    // A handler runs on a signal frame and returns through `rt_sigreturn`.
    catch(10, on_signal);
    let r = sys::call(sys::KILL, [pid, 10, 0, 0, 0]);
    let ok = r == 0 && GOT_SIGNAL.load(Ordering::SeqCst) == 10;
    say!("signals: SIGUSR1 sent to myself ran its handler and returned: {}", if ok { "ok" } else { "FAILED" });

    // A fault becomes SIGSEGV for the program's handler.
    catch(11, on_segv);
    if sys::fork() == 0 {
        // SAFETY: deliberately faults, to reach the handler.
        unsafe { core::ptr::read_volatile(8 as *const u8) };
        exit(1);
    }
    let (reaped, code) = wait(-1);
    say!(
        "signals: SIGSEGV handled in child {reaped}, exit status {code}: {}",
        if code == 42 { "ok" } else { "FAILED" }
    );

    // SIGCHLD reaches the parent when a child exits.
    catch(17, on_chld);
    if sys::fork() == 0 {
        exit(3);
    }
    let (reaped, code) = wait(-1);
    let ok = reaped > 0 && code == 3 && GOT_CHLD.load(Ordering::SeqCst) == 1;
    say!("signals: SIGCHLD handler ran when child {reaped} exited: {}", if ok { "ok" } else { "FAILED" });

    // A thread shares memory, has its own id and thread pointer, and a
    // CLONE_CHILD_CLEARTID word that `futex` waits on.
    COUNTER.store(1, Ordering::SeqCst);
    // SAFETY: statics only this program uses; the stack is the thread's own.
    let (tid, ctid) = unsafe {
        WORKER_TLS.me = (&raw const WORKER_TLS) as u64;
        let top = (&raw mut WORKER_STACK) as u64 + 16384;
        let tid = sys::clone_thread(
            THREAD | SETTLS | PARENT_SETTID | CHILD_SETTID | CHILD_CLEARTID,
            top,
            (&raw mut PTID) as u64,
            (&raw mut CTID) as u64,
            (&raw const WORKER_TLS) as u64,
            worker,
            1,
        );
        (tid, &raw mut CTID)
    };
    // pthread_join: wait while the word still holds the tid.
    // SAFETY: as above.
    while unsafe { core::ptr::read_volatile(ctid) } != 0 {
        sys::call(sys::FUTEX, [ctid as u64, 128, tid as u64, 0, 0]);
    }
    // SAFETY: the thread has ended.
    let ptid = unsafe { core::ptr::read_volatile(&raw const PTID) };
    let ok = tid > 0
        && ptid as i64 == tid
        && WORKER_TID.load(Ordering::SeqCst) as i64 == tid
        && tid as u64 != pid
        && COUNTER.load(Ordering::SeqCst) == 2
        && WORKER_TLS_OK.load(Ordering::SeqCst) == 1;
    say!(
        "threads: thread {tid} of process {pid} joined with futex; shared counter, thread id, TLS: {}",
        if ok { "ok" } else { "FAILED" }
    );

    // Several threads sleep on one futex; FUTEX_REQUEUE wakes one and moves
    // the rest to another word, and the joins use CLONE_CHILD_CLEARTID.
    let mut tids = [0i64; 3];
    for (i, t) in tids.iter_mut().enumerate() {
        // SAFETY: statics only this program uses; each thread has its own stack.
        *t = unsafe {
            let top = (&raw mut WAITER_STACKS) as u64 + (i as u64 + 1) * 16384;
            let ctid = (&raw mut WAITER_CTIDS) as u64 + i as u64 * 4;
            sys::clone_thread(THREAD | CHILD_SETTID | CHILD_CLEARTID, top, 0, ctid, 0, waiter, 0)
        };
    }
    while STARTED.load(Ordering::SeqCst) < 3 {
        sys::call(sys::SCHED_YIELD, [0; 5]);
    }
    GATE.store(1, Ordering::SeqCst);
    // REQUEUE: wake 1, move up to 2 more to GATE2.
    let moved = sys::call(sys::FUTEX, [GATE.as_ptr() as u64, 128 | 3, 1, 2, GATE2.as_ptr() as u64]);
    sys::call(sys::FUTEX, [GATE2.as_ptr() as u64, 128 | 1, 10, 0, 0]);
    for (i, &tid) in tids.iter().enumerate() {
        // SAFETY: as above; the kernel clears the word when the thread ends.
        let ctid = unsafe { (&raw mut WAITER_CTIDS) as *mut u32 }.wrapping_add(i);
        while unsafe { core::ptr::read_volatile(ctid) } != 0 {
            sys::call(sys::FUTEX, [ctid as u64, 128, tid as u64, 0, 0]);
        }
    }
    let ok = tids.iter().all(|&t| t > 0) && (0..=3).contains(&moved) && FINISHED.load(Ordering::SeqCst) == 3;
    say!(
        "threads: 3 threads slept on a futex, were requeued and woken, and joined: {}",
        if ok { "ok" } else { "FAILED" }
    );

    // exit_group ends a thread that never stops.
    if sys::fork() == 0 {
        // SAFETY: the spinner's own stack.
        let top = unsafe { (&raw mut SPINNER_STACK) as u64 + 16384 };
        // SAFETY: as above.
        unsafe { sys::clone_thread(THREAD, top, 0, 0, 0, spinner, 0) };
        for _ in 0..20 {
            sys::call(sys::SCHED_YIELD, [0; 5]);
        }
        sys::call(sys::EXIT_GROUP, [9, 0, 0, 0, 0]);
        exit(1);
    }
    let (reaped, code) = wait(-1);
    say!(
        "threads: exit_group ended a spinning thread, process {reaped} status {code}: {}",
        if code == 9 { "ok" } else { "FAILED" }
    );

    // The threads of one process run on several CPUs at once, and unmapping
    // a page in one of them reaches the TLBs of the others: the readers fault.
    if sys::fork() == 0 {
        catch(11, on_smp_segv);
        for i in 0..3u64 {
            // SAFETY: statics only this program uses; each thread has its own stack.
            unsafe {
                let top = (&raw mut WAITER_STACKS) as u64 + (i + 1) * 16384;
                sys::clone_thread(THREAD, top, 0, 0, 0, page_reader, 0);
            }
        }
        let mut spins = 0u64;
        while SMP_READY.load(Ordering::SeqCst) < 3 && spins < 20_000_000 {
            sys::call(sys::SCHED_YIELD, [0; 5]);
            spins += 1;
        }
        note_cpu();
        let cpus = SMP_CPUS.load(Ordering::SeqCst).count_ones();
        sys::call(sys::MUNMAP, [(&raw const SMP_PAGE) as u64, 4096, 0, 0, 0]);
        spins = 0;
        while SMP_FAULTED.load(Ordering::SeqCst) < 3 && spins < 20_000_000 {
            sys::call(sys::SCHED_YIELD, [0; 5]);
            spins += 1;
        }
        let ok = SMP_READY.load(Ordering::SeqCst) == 3 && cpus >= 2 && SMP_FAULTED.load(Ordering::SeqCst) == 3;
        say!(
            "smp: 3 threads of process {pid} read a page on several CPUs; munmap faulted them all: {}",
            if ok { "ok" } else { "FAILED" }
        );
        exit(if ok { 0 } else { 1 });
    }
    wait(-1);
}

/// Written by the signal handler of the restart demonstration.
static RESTART_HANDLED: AtomicU32 = AtomicU32::new(0);
static PIPE_FDS: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
static MAIN_TID: AtomicU32 = AtomicU32::new(0);
static mut RESTART_STACK: Stack = Stack([0; 16384]);
static mut RESTART_CTID: u32 = 0;
static mut PI_STACK: Stack = Stack([0; 16384]);
static mut PI_CTID: u32 = 0;
/// The priority-inheritance futex word: 0, or the owner's thread id.
static PI_WORD: AtomicU32 = AtomicU32::new(0);
static PI_GOT: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_restart_signal(_sig: i32, _info: *const u8, _ctx: *const u8) {
    RESTART_HANDLED.fetch_add(1, Ordering::SeqCst);
}

/// Sends the main thread a signal while it is blocked in `read`, then the
/// byte it waits for.
extern "C" fn interrupter(_: u64) -> ! {
    for _ in 0..20 {
        sys::call(sys::SCHED_YIELD, [0; 5]);
    }
    sys::call(sys::TKILL, [MAIN_TID.load(Ordering::SeqCst) as u64, 12, 0, 0, 0]);
    for _ in 0..20 {
        sys::call(sys::SCHED_YIELD, [0; 5]);
    }
    let b = b"x";
    sys::call(sys::WRITE, [PIPE_FDS[1].load(Ordering::SeqCst) as u64, b.as_ptr() as u64, 1, 0, 0]);
    exit(0)
}

/// Locks the priority-inheritance futex the main thread holds, with
/// `FUTEX_LOCK_PI`, then unlocks it.
extern "C" fn pi_locker(_: u64) -> ! {
    let me = sys::call(sys::GETTID, [0; 5]) as u32;
    if PI_WORD.compare_exchange(0, me, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        // FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG: the kernel queues us and hands the lock over.
        let r = sys::call(sys::FUTEX, [PI_WORD.as_ptr() as u64, 128 | 6, 0, 0, 0]);
        PI_GOT.store((r == 0 && PI_WORD.load(Ordering::SeqCst) & 0x3fff_ffff == me) as u32, Ordering::SeqCst);
    }
    // Userspace unlock fails if the waiters bit is set; then UNLOCK_PI.
    if PI_WORD.compare_exchange(me, 0, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        sys::call(sys::FUTEX, [PI_WORD.as_ptr() as u64, 128 | 7, 0, 0, 0]);
    }
    exit(0)
}

/// Reads one byte from the pipe while a signal arrives; returns the result
/// of `read`.
fn read_through_signal(flags: u64) -> i64 {
    let mut act = sys::sigaction(on_restart_signal as usize as u64);
    act.flags |= flags;
    sys::call(sys::RT_SIGACTION, [12, &act as *const sys::SigAction as u64, 0, 8, 0]);
    RESTART_HANDLED.store(0, Ordering::SeqCst);
    // SAFETY: statics only this program uses; the stack is the thread's own.
    unsafe {
        let top = (&raw mut RESTART_STACK) as u64 + 16384;
        sys::clone_thread(
            THREAD | CHILD_SETTID | CHILD_CLEARTID,
            top,
            0,
            (&raw mut RESTART_CTID) as u64,
            0,
            interrupter,
            0,
        )
    };
    let mut byte = [0u8; 1];
    let r = sys::call(sys::READ, [PIPE_FDS[0].load(Ordering::SeqCst) as u64, byte.as_mut_ptr() as u64, 1, 0, 0]);
    // SAFETY: the kernel clears the word when the thread ends.
    while unsafe { core::ptr::read_volatile(&raw const RESTART_CTID) } != 0 {
        sys::call(sys::SCHED_YIELD, [0; 5]);
    }
    if r == -4 {
        // The interrupted read left the byte in the pipe.
        sys::call(sys::READ, [PIPE_FDS[0].load(Ordering::SeqCst) as u64, byte.as_mut_ptr() as u64, 1, 0, 0]);
    }
    r
}

/// `SA_RESTART` and priority-inheritance futexes.
fn restarts_and_pi() {
    let mut fds = [0u32; 2];
    let r = sys::call(sys::PIPE2, [fds.as_mut_ptr() as u64, 0, 0, 0, 0]);
    PIPE_FDS[0].store(fds[0], Ordering::SeqCst);
    PIPE_FDS[1].store(fds[1], Ordering::SeqCst);
    MAIN_TID.store(sys::call(sys::GETTID, [0; 5]) as u32, Ordering::SeqCst);
    // A handler without SA_RESTART interrupts the blocked read (EINTR).
    let plain = read_through_signal(0);
    let ran_plain = RESTART_HANDLED.load(Ordering::SeqCst);
    // With SA_RESTART the read continues after the handler and gets the byte.
    let restarted = read_through_signal(0x1000_0000);
    let ran_restart = RESTART_HANDLED.load(Ordering::SeqCst);
    let ok = r == 0 && plain == -4 && ran_plain == 1 && restarted == 1 && ran_restart == 1;
    say!(
        "restart: read gave EINTR without SA_RESTART and was restarted transparently with it ({restarted} byte): {}",
        if ok { "ok" } else { "FAILED" }
    );

    // The main thread owns the lock; a second thread waits for it in the
    // kernel with FUTEX_LOCK_PI, and is handed it by FUTEX_UNLOCK_PI.
    let me = MAIN_TID.load(Ordering::SeqCst);
    PI_WORD.store(me, Ordering::SeqCst);
    // SAFETY: statics only this program uses; the stack is the thread's own.
    let tid = unsafe {
        let top = (&raw mut PI_STACK) as u64 + 16384;
        sys::clone_thread(THREAD | CHILD_SETTID | CHILD_CLEARTID, top, 0, (&raw mut PI_CTID) as u64, 0, pi_locker, 0)
    };
    // FUTEX_WAITERS (bit 31) says the thread is queued in the kernel.
    let mut spins = 0;
    while PI_WORD.load(Ordering::SeqCst) != 0x8000_0000 | me && spins < 10_000 {
        sys::call(sys::SCHED_YIELD, [0; 5]);
        spins += 1;
    }
    let queued = PI_WORD.load(Ordering::SeqCst) == 0x8000_0000 | me;
    // The owner trying to lock again is a deadlock (EDEADLK).
    let trylock = sys::call(sys::FUTEX, [PI_WORD.as_ptr() as u64, 128 | 8, 0, 0, 0]);
    let unlock = sys::call(sys::FUTEX, [PI_WORD.as_ptr() as u64, 128 | 7, 0, 0, 0]);
    // SAFETY: the kernel clears the word when the thread ends.
    while unsafe { core::ptr::read_volatile(&raw const PI_CTID) } != 0 {
        sys::call(sys::SCHED_YIELD, [0; 5]);
    }
    let ok = tid > 0
        && queued
        && trylock == -35
        && unlock == 0
        && PI_GOT.load(Ordering::SeqCst) == 1
        && PI_WORD.load(Ordering::SeqCst) == 0;
    say!(
        "futex: FUTEX_LOCK_PI waited, was handed the lock by FUTEX_UNLOCK_PI, and released it: {}",
        if ok { "ok" } else { "FAILED" }
    );
}

const SIGUSR2: u64 = 12;
const SIGRT1: u64 = 33;
const SIGRT2: u64 = 34;
const SA_SIGINFO: u64 = 4;
const SA_ONSTACK: u64 = 0x0800_0000;
const WUNTRACED: u64 = 2;
const WCONTINUED: u64 = 8;
const EINTR: i64 = -4;

/// How many queued signals the handler has seen, and each as `signo << 8 | si_value`.
static NQUEUED: AtomicU32 = AtomicU32::new(0);
static QUEUED: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
/// Set if a queued signal did not say `SI_QUEUE` (-1).
static BAD_CODE: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_queued(sig: i32, info: *const u8, _ctx: *const u8) {
    // SAFETY: the kernel put a `siginfo` there; `si_code` is at offset 8 and `si_value` at 24.
    let (code, value) = unsafe { ((info.add(8) as *const i32).read(), (info.add(24) as *const u64).read()) };
    if code != -1 {
        BAD_CODE.store(1, Ordering::SeqCst);
    }
    let n = NQUEUED.fetch_add(1, Ordering::SeqCst) as usize;
    if let Some(slot) = QUEUED.get(n) {
        slot.store((sig as u32) << 8 | value as u32, Ordering::SeqCst);
    }
}

/// An address inside the handler's stack frame.
static HANDLER_SP: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_altstack(_sig: i32, _info: *const u8, _ctx: *const u8) {
    let marker = 0u8;
    HANDLER_SP.store(core::hint::black_box(&marker) as *const u8 as usize, Ordering::SeqCst);
}

static GOT_USR2: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_usr2(_sig: i32, _info: *const u8, _ctx: *const u8) {
    GOT_USR2.fetch_add(1, Ordering::SeqCst);
}

#[repr(align(16))]
struct AltStack([u8; 16384]);
static mut ALT_STACK: AltStack = AltStack([0; 16384]);

/// `struct stack_t`.
#[repr(C)]
struct StackT {
    sp: u64,
    flags: i32,
    size: u64,
}

/// `struct siginfo` as `rt_sigqueueinfo` takes it: 128 bytes.
#[repr(C)]
struct SigInfo {
    signo: i32,
    errno: i32,
    code: i32,
    _pad: i32,
    pid: i32,
    uid: i32,
    value: u64,
    _rest: [u64; 12],
}

fn catch_with(sig: u64, handler: extern "C" fn(i32, *const u8, *const u8), flags: u64) {
    let mut act = sys::sigaction(handler as usize as u64);
    act.flags = flags;
    let r = sys::call(sys::RT_SIGACTION, [sig, &act as *const sys::SigAction as u64, 0, 8, 0]);
    assert!(r == 0);
}

/// `rt_sigprocmask(how, &set, &old)`: the old mask. `how` 0 blocks, 1 unblocks, 2 sets.
fn sigprocmask(how: u64, set: u64) -> u64 {
    let mut old = 0u64;
    sys::call(sys::RT_SIGPROCMASK, [how, &set as *const u64 as u64, &mut old as *mut u64 as u64, 8, 0]);
    // SAFETY: the kernel wrote through the pointer.
    unsafe { core::ptr::read_volatile(&old) }
}

/// `wait4(pid, &status, options, NULL)` that retries when a signal interrupts it: the child
/// reaped (or `-errno`) and the whole status word.
fn wait_opts(pid: i64, options: u64) -> (i64, i32) {
    loop {
        let mut status = 0i32;
        let r = sys::call(sys::WAIT4, [pid as u64, &mut status as *mut i32 as u64, options, 0, 0]);
        if r != EINTR {
            // SAFETY: the kernel wrote through the pointer.
            return (r, unsafe { core::ptr::read_volatile(&status) });
        }
    }
}

/// Queued signals, the alternate signal stack, `sigsuspend`, and stopping and continuing.
fn queued_signals_and_job_control() {
    let pid = sys::call(sys::GETPID, [0; 5]);

    // Real-time signals queue, with the value `rt_sigqueueinfo` passed, lowest number first.
    catch_with(SIGRT1, on_queued, SA_SIGINFO);
    catch_with(SIGRT2, on_queued, SA_SIGINFO);
    sigprocmask(2, 1 << (SIGRT1 - 1) | 1 << (SIGRT2 - 1));
    for (sig, value) in [(SIGRT2, 1u64), (SIGRT1, 2), (SIGRT2, 3)] {
        let info =
            SigInfo { signo: sig as i32, errno: 0, code: -1, _pad: 0, pid: pid as i32, uid: 0, value, _rest: [0; 12] };
        let r = sys::call(sys::RT_SIGQUEUEINFO, [pid as u64, sig, &info as *const SigInfo as u64, 0, 0]);
        assert!(r == 0);
    }
    let held = NQUEUED.load(Ordering::SeqCst) == 0;
    // Unblocking delivers all three before the call returns.
    sigprocmask(2, 0);
    let order = [(SIGRT1 as u32) << 8 | 2, (SIGRT2 as u32) << 8 | 1, (SIGRT2 as u32) << 8 | 3];
    let got = [0, 1, 2].map(|i| QUEUED[i].load(Ordering::SeqCst));
    let ok = held && NQUEUED.load(Ordering::SeqCst) == 3 && got == order && BAD_CODE.load(Ordering::SeqCst) == 0;
    say!(
        "signals: 3 queued real-time signals arrived in order with si_value and SI_QUEUE: {}",
        if ok { "ok" } else { "FAILED" }
    );

    // A handler with SA_ONSTACK runs on the stack `sigaltstack` named.
    // SAFETY: a static only this program uses.
    let base = unsafe { (&raw mut ALT_STACK) as u64 };
    let ss = StackT { sp: base, flags: 0, size: 16384 };
    let r = sys::call(sys::SIGALTSTACK, [&ss as *const StackT as u64, 0, 0, 0, 0]);
    catch_with(10, on_altstack, SA_SIGINFO | SA_ONSTACK);
    sys::call(sys::KILL, [pid as u64, 10, 0, 0, 0]);
    let sp = HANDLER_SP.load(Ordering::SeqCst) as u64;
    let ok = r == 0 && sp > base && sp < base + 16384;
    say!("signals: SA_ONSTACK handler ran on the sigaltstack: {}", if ok { "ok" } else { "FAILED" });

    // sigsuspend waits for a signal the caller had blocked, and gives the mask back.
    catch_with(SIGUSR2, on_usr2, SA_SIGINFO);
    sigprocmask(0, 1 << (SIGUSR2 - 1));
    if sys::fork() == 0 {
        for _ in 0..5 {
            sys::call(sys::SCHED_YIELD, [0; 5]);
        }
        sys::call(sys::KILL, [pid as u64, SIGUSR2, 0, 0, 0]);
        exit(0);
    }
    let nothing = 0u64;
    let r = sys::call(sys::RT_SIGSUSPEND, [&nothing as *const u64 as u64, 8, 0, 0, 0]);
    let mask = sigprocmask(0, 0);
    wait(-1);
    let ok = r == EINTR && GOT_USR2.load(Ordering::SeqCst) == 1 && mask & (1 << (SIGUSR2 - 1)) != 0;
    say!(
        "signals: sigsuspend returned EINTR after SIGUSR2 from the child and kept the mask: {}",
        if ok { "ok" } else { "FAILED" }
    );

    // SIGSTOP stops a child, which wait4 reports with WUNTRACED; SIGCONT resumes it, reported with WCONTINUED.
    let child = sys::fork();
    if child == 0 {
        loop {
            sys::call(sys::SCHED_YIELD, [0; 5]);
        }
    }
    sys::call(sys::KILL, [child as u64, 19, 0, 0, 0]);
    let (r1, stopped) = wait_opts(child, WUNTRACED);
    sys::call(sys::KILL, [child as u64, 18, 0, 0, 0]);
    let (r2, continued) = wait_opts(child, WCONTINUED);
    sys::call(sys::KILL, [child as u64, 9, 0, 0, 0]);
    let (r3, killed) = wait_opts(child, 0);
    let ok =
        r1 == child && stopped == 19 << 8 | 0x7f && r2 == child && continued == 0xffff && r3 == child && killed == 9;
    say!(
        "signals: SIGSTOP stopped child {child} (WUNTRACED), SIGCONT continued it (WCONTINUED), SIGKILL ended it: {}",
        if ok { "ok" } else { "FAILED" }
    );
}

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
    file_maps();
    signals_and_threads();
    restarts_and_pi();
    queued_signals_and_job_control();
    exit(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(101)
}
