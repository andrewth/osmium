//! A user program that exercises `fork`, `execve` and `wait4`: it forks a
//! child that changes memory and exits, then forks one that execs this same
//! program again with arguments and an environment, and reaps both. Where
//! the kernel offers FP (`AT_HWCAP`), it also checks that FP registers are
//! inherited by `fork`, cleared by `execve` and kept across switches.
//! Started as `init`, run again as `init child`.
#![no_std]
#![no_main]

use core::fmt::Write;
use core::sync::atomic::{AtomicU32, Ordering};

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

    pub const RT_SIGACTION: u64 = 134;
    pub const KILL: u64 = 129;
    pub const GETTID: u64 = 178;
    pub const FUTEX: u64 = 98;
    pub const EXIT_GROUP: u64 = 94;
    pub const READ: u64 = 63;
    pub const PIPE2: u64 = 59;
    pub const TKILL: u64 = 130;

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

    pub const RT_SIGACTION: u64 = 134;
    pub const KILL: u64 = 129;
    pub const GETTID: u64 = 178;
    pub const FUTEX: u64 = 98;
    pub const EXIT_GROUP: u64 = 94;
    pub const READ: u64 = 63;
    pub const PIPE2: u64 = 59;
    pub const TKILL: u64 = 130;

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

    pub const RT_SIGACTION: u64 = 13;
    pub const KILL: u64 = 62;
    pub const GETTID: u64 = 186;
    pub const FUTEX: u64 = 202;
    pub const EXIT_GROUP: u64 = 231;
    pub const READ: u64 = 0;
    pub const PIPE2: u64 = 293;
    pub const TKILL: u64 = 200;

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
    signals_and_threads();
    restarts_and_pi();
    exit(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(101)
}
