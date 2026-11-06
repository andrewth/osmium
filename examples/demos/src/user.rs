//! Pieces the example kernels share for running user programs: the boot
//! file system, the user address-space layout, spawning flat and ELF
//! programs, the demos that run them, and the user-mode half of a trap
//! handler.
//!
//! A kernel supplies what is genuinely its own: an [`Enter`] function that
//! drops to user mode, the [`Platform`](osmium::proc::Platform) hooks that
//! activate a table and resume a forked child, and its trap entry.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::ops::Range;

use osmium::arch::cpu;
use osmium::arch::trap::{Access, Trap, TrapFrame};
use osmium::fs::dev::{DevDir, Null, Zero};
use osmium::fs::{Errno, File, FileKind, OpenFlags, RamFs, Stat, Vfs};
use osmium::hal::println;
use osmium::mm::paging::PageTableFormat;
use osmium::mm::{MapFlags, PAGE_SIZE};
use osmium::proc::{AddressSpace, ExitStatus, Platform, Process, UserMemory};
use osmium::sched::{Task, TaskBuilder};

use crate::kernel::{FRAMES, Frames, KernelTable};

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
    if VFS.set(vfs).is_err() {
        println!("[user]  boot_vfs called twice; keeping the first file system");
        return;
    }
    let made = (|| {
        vfs.mkdir("/etc", 0o755)?;
        vfs.open("/etc/motd", OpenFlags::WRITE | OpenFlags::CREATE, 0o644)?.write(0, b"welcome to osmium\n")?;
        vfs.mkdir("/tmp", 0o1777)?;
        vfs.mkdir("/dev", 0o755)
    })();
    if let Err(e) = made {
        println!("[user]  building the boot file system failed: {e:?}");
    }
    let console: Arc<dyn File> = Arc::new(LogConsole);
    let dev = DevDir::new(2);
    dev.insert("console", console.clone());
    dev.insert("null", Arc::new(Null::new()));
    dev.insert("zero", Arc::new(Zero::new()));
    if let Err(e) = vfs.mount("/dev", Arc::new(dev)) {
        println!("[user]  mounting /dev failed: {e:?}");
    }
    osmium::proc::set_vfs(vfs);
    osmium::proc::set_console(console);
}

static VFS: osmium::sync::Once<&'static Vfs> = osmium::sync::Once::new();

/// Writes `image` to `/bin/<name>` with mode 0755 (making `/bin` if
/// needed), for `execve`. Call after [`boot_vfs`].
pub fn install(name: &str, image: &[u8]) -> Result<(), Errno> {
    let vfs = VFS.get().ok_or(Errno::ENOENT)?;
    if vfs.stat("/bin", true).is_err() {
        vfs.mkdir("/bin", 0o755)?;
    }
    let path = alloc::format!("/bin/{name}");
    let file = vfs.open(&path, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNC, 0o755)?;
    if file.write(0, image)? == image.len() { Ok(()) } else { Err(Errno::EIO) }
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

// --- The user address-space layout ------------------------------------------
//
// Every process has its own table. The kernel's root entries
// `KERNEL_ROOT_ENTRIES` are shared into it; user programs live above them.
// `build.rs` links the static user programs at `USER_BASE`.

/// Where flat programs (and the static ELF programs, by their link address)
/// are mapped: 64 GiB, root entry 64 of Sv39, clear of RAM and the PCIe
/// windows below.
#[cfg(target_arch = "riscv64")]
pub const USER_BASE: u64 = 0x10_0000_0000;
/// The top of a new program's stack.
#[cfg(target_arch = "riscv64")]
pub const STACK_TOP: u64 = 0x11_0000_0000;
/// Where `mmap` places anonymous memory.
#[cfg(target_arch = "riscv64")]
pub const MMAP_AREA: Range<u64> = 0x12_0000_0000..0x13_0000_0000;
/// Where position-independent programs are loaded.
#[cfg(target_arch = "riscv64")]
pub const LOAD_BASE: u64 = 0x14_0000_0000;
/// The kernel's root entries, shared into every user table: the first
/// 64 GiB.
#[cfg(target_arch = "riscv64")]
pub const KERNEL_ROOT_ENTRIES: Range<usize> = 0..64;

/// Where flat programs (and the static ELF programs, by their link address)
/// are mapped: 512 GiB, root entry 1.
#[cfg(not(target_arch = "riscv64"))]
pub const USER_BASE: u64 = 0x80_0000_0000;
/// The top of a new program's stack, just below 1 TiB.
#[cfg(not(target_arch = "riscv64"))]
pub const STACK_TOP: u64 = 0xff_0000_0000;
/// Where `mmap` places anonymous memory.
#[cfg(not(target_arch = "riscv64"))]
pub const MMAP_AREA: Range<u64> = 0xa0_0000_0000..0xa1_0000_0000;
/// Where position-independent programs are loaded.
#[cfg(not(target_arch = "riscv64"))]
pub const LOAD_BASE: u64 = 0xb0_0000_0000;
/// The kernel's root entries, shared into every user table: the first
/// 512 GiB, where it lives.
#[cfg(not(target_arch = "riscv64"))]
pub const KERNEL_ROOT_ENTRIES: Range<usize> = 0..1;

/// The Rust user program, built by `build.rs` from `examples/user/hello.rs`.
pub static HELLO_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hello.elf"));
/// The Rust program that forks and execs, from `examples/user/init.rs`.
pub static INIT_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/init.elf"));
/// The Rust program that uses sockets, from `examples/user/net.rs`.
#[cfg(target_arch = "riscv64")]
pub static NET_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/net.elf"));
/// Position-independent programs, from `examples/user/pie.rs` (as a static
/// PIE and linked against the interpreter) and `ld.rs` (the interpreter).
#[cfg(target_arch = "riscv64")]
pub static PIE_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pie.elf"));
#[cfg(target_arch = "riscv64")]
#[allow(missing_docs)]
pub static DYN_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/dyn.elf"));
#[cfg(target_arch = "riscv64")]
#[allow(missing_docs)]
pub static LD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ld.elf"));

/// Drops to user mode at `pc` with stack pointer `sp`, on the current task,
/// whose process's table the switch hook has made active.
///
/// # Safety
/// `pc` and `sp` must be mapped user-accessible in the current process,
/// and traps from user mode must land on this task's kernel stack.
pub type Enter = unsafe fn(pc: u64, sp: u64) -> !;

/// A new, empty user address space sharing `KERNEL_ROOT_ENTRIES` of the
/// kernel's `table`, with table and user pages from [`FRAMES`]: what
/// [`Platform::new_memory`] returns.
pub fn new_space<F: PageTableFormat + Send + Sync + 'static>(
    table: &KernelTable<F>,
) -> Result<Box<dyn UserMemory>, Errno> {
    let pt = table.lock();
    let pt = pt.as_ref().ok_or(Errno::ENOMEM)?;
    // SAFETY: the kernel table lives for the whole run.
    let space = unsafe { AddressSpace::<F, &'static Frames>::new(&FRAMES, pt, KERNEL_ROOT_ENTRIES) };
    osmium::sync::fallible::try_box(space.map_err(|_| Errno::ENOMEM)?)
        .map(|space| space as Box<dyn UserMemory>)
        .map_err(|_| Errno::ENOMEM)
}

/// The [`Platform`] `fork` and `execve` need, with this module's layout and
/// a 64 KiB stack.
pub fn platform(
    new_memory: fn() -> Result<Box<dyn UserMemory>, Errno>,
    activate: fn(osmium::mm::PhysAddr),
    resume: fn(TrapFrame) -> !,
) -> Platform {
    Platform {
        new_memory,
        activate,
        resume,
        stack_top: STACK_TOP,
        stack_size: 64 * 1024,
        mmap_area: MMAP_AREA,
        load_base: LOAD_BASE,
    }
}

/// Copies the flat program `code` into fresh pages at [`USER_BASE`] (code
/// read/execute, a stack page read/write), and spawns a task on `cpu` that
/// drops to user mode there. Every `?` in the code becomes the digit `n`,
/// so the copy can tell which process it is.
pub fn spawn_flat(
    platform: &Platform,
    name: &'static str,
    n: u8,
    code: &[u8],
    cpu: usize,
    enter: Enter,
) -> Result<(Arc<Task>, Weak<Process>), Errno> {
    let mut code = code.to_vec();
    if let Some(q) = code.iter_mut().find(|b| **b == b'?') {
        *q = b'0' + n % 10;
    }
    let (code_va, stack_va) = (USER_BASE, USER_BASE + 0x8000);
    let memory = (platform.new_memory)()?;
    memory.map_code(code_va, &code)?;
    memory.map_anon(stack_va, PAGE_SIZE as u64, MapFlags::RW)?;
    let process = Process::new_boxed(name, memory, USER_BASE + 0x10000);
    let task = process.spawn(TaskBuilder::new(name).cpu(cpu), move || {
        // SAFETY: both pages are mapped user-accessible in this process, and
        // the kernel's switch hook routes its traps to this task's stack.
        unsafe { enter(code_va, stack_va + PAGE_SIZE as u64) }
    });
    Ok((task, Arc::downgrade(&process)))
}

/// Loads the ELF executable `image` into a new address space, with a stack
/// page below [`STACK_TOP`], and spawns a task on `cpu` that runs it in user
/// mode.
pub fn spawn_elf(
    platform: &Platform,
    name: &'static str,
    image: &[u8],
    cpu: usize,
    enter: Enter,
) -> Result<(Arc<Task>, Weak<Process>), Errno> {
    let elf = osmium::boot::elf::Elf::new(image).map_err(|_| Errno::ENOEXEC)?;
    let memory = (platform.new_memory)()?;
    let brk = memory.load_elf(&elf)?;
    memory.map_anon(STACK_TOP - PAGE_SIZE as u64, PAGE_SIZE as u64, MapFlags::RW)?;
    let entry = elf.entry();
    let process = Process::new_boxed(name, memory, brk);
    process.set_mmap_area(MMAP_AREA);
    let task = process.spawn(TaskBuilder::new(name).cpu(cpu), move || {
        // SAFETY: the image and the stack page are mapped user-accessible in
        // this process, and the switch hook routes its traps here.
        unsafe { enter(entry, STACK_TOP) }
    });
    Ok((task, Arc::downgrade(&process)))
}

/// Starts a process that `exec`s `/bin/<name>` (installed from `image`)
/// on `cpu`, or wherever the scheduler puts it, and waits for its task.
/// Returns the process, to check that it was torn down.
pub fn run(
    platform: &Platform,
    name: &'static str,
    image: &[u8],
    cpu: Option<usize>,
    enter: Enter,
) -> Result<Weak<Process>, Errno> {
    install(name, image)?;
    let process = Process::new_boxed(name, (platform.new_memory)()?, 0);
    let weak = Arc::downgrade(&process);
    let builder = TaskBuilder::new(name);
    let builder = match cpu {
        Some(cpu) => builder.cpu(cpu),
        None => builder,
    };
    let task = process.spawn(builder, move || {
        let path = alloc::format!("/bin/{name}");
        let entry = osmium::proc::current().ok_or(Errno::ENOENT).and_then(|p| p.exec(&path, &[name.as_bytes()], &[]));
        match entry {
            // SAFETY: exec activated the new table and mapped the program and
            // its stack; the switch hook routes this task's traps here.
            Ok(entry) => unsafe { enter(entry.pc, entry.sp) },
            Err(e) => {
                println!("[user]  exec {path}: {e:?}");
                osmium::proc::exit(ExitStatus::Code(127))
            }
        }
    });
    drop(process);
    task.join();
    Ok(weak)
}

/// The user demos: two copies of the flat program `hello` and one of `bad`
/// (which reads kernel memory and is killed), then [`HELLO_ELF`], all on
/// CPU 1 when there is one, each in its own address space; then `/bin/init`,
/// which forks, execs and waits. `mode` names the CPU's user mode.
pub fn demo(platform: &Platform, hello: &[u8], bad: &[u8], mode: &str, enter: Enter) {
    // On another CPU when there is one: user code may own the register the
    // kernel keeps its CPU id in, and trap entry must restore it, which CPU 0
    // alone would not test.
    let cpu = 1 % crate::kernel::online();
    println!("[user]  running 3 {mode} programs on CPU {cpu}");
    println!("[user]  each program has its own page table; all run at {USER_BASE:#x}");
    let spawned = [
        spawn_flat(platform, "user-1", 1, hello, cpu, enter),
        spawn_flat(platform, "user-2", 2, hello, cpu, enter),
        spawn_flat(platform, "user-bad", 3, bad, cpu, enter),
        spawn_elf(platform, "user-elf", HELLO_ELF, cpu, enter),
    ];
    let mut processes = Vec::new();
    for spawned in spawned {
        match spawned {
            Ok((task, process)) => {
                task.join();
                processes.push(process);
            }
            Err(e) => println!("[user]  spawning a program failed: {e:?}"),
        }
    }
    // Exited tasks (and their address spaces) are freed once their CPU has
    // switched away from them.
    let torn_down = freed(&processes);
    println!("[user]  {torn_down} of 4 address spaces torn down with their tasks");
    match run(platform, "init", INIT_ELF, Some(cpu), enter) {
        Ok(init) => {
            let freed = freed(&[init]);
            println!("[user]  init and its children reaped; {freed} of 1 init address space torn down");
        }
        Err(e) => println!("[user]  init: {e:?}"),
    }
}

/// Runs `/bin/pie`, a static PIE that the kernel relocates, and `/bin/dyn`,
/// the same program linked against the interpreter `/bin/ld`, which
/// relocates it.
#[cfg(target_arch = "riscv64")]
pub fn pie_demo(platform: &Platform, enter: Enter) {
    if let Err(e) = install("ld", LD_ELF) {
        println!("[user]  installing /bin/ld: {e:?}");
    }
    for (name, image) in [("pie", PIE_ELF), ("dyn", DYN_ELF)] {
        if let Err(e) = run(platform, name, image, None, enter) {
            println!("[user]  {name}: {e:?}");
        }
    }
    println!("[user]  position-independent programs exited");
}

/// Gives `dev` to osmium-proc's socket calls (after a DHCP lease), polls it
/// from a task, and runs `/bin/net`, which does a TCP echo round trip and
/// reads a file by TFTP over UDP.
#[cfg(target_arch = "riscv64")]
pub fn socket_demo(
    platform: &Platform,
    mut dev: Box<dyn osmium::hal::net::NetDevice + Send>,
    timers: &'static osmium::sched::timer::TimerQueue,
    enter: Enter,
) {
    use crate::kernel::now_ns;
    use core::sync::atomic::{AtomicBool, Ordering};
    use osmium::net::{DhcpClient, Instant, Interface, SocketSet};
    use osmium::proc::net::{NetStack, set_stack};

    let mut iface = Interface::new(&*dev, now_ns());
    let mut sockets = SocketSet::new();
    sockets.add(DhcpClient::new());
    let start = now_ns();
    while iface.config().is_none() && now_ns() - start < 5_000_000_000 {
        iface.poll(Instant::from_nanos(now_ns()), &mut *dev, &mut sockets);
    }
    let Some(config) = iface.config() else {
        println!("[sock]  no DHCP lease");
        return;
    };
    println!("[sock]  {} on the socket stack", config.address);
    let stack = Arc::new(NetStack::new(iface, dev, sockets, now_ns));
    set_stack(stack.clone());
    static STOP: AtomicBool = AtomicBool::new(false);
    let poller = TaskBuilder::new("net-poll").spawn(move || {
        while !STOP.load(Ordering::Acquire) {
            stack.poll();
            timers.sleep_until(now_ns() + 1_000_000);
        }
    });
    if let Err(e) = run(platform, "net", NET_ELF, None, enter) {
        println!("[sock]  net: {e:?}");
    }
    STOP.store(true, Ordering::Release);
    poller.join();
    println!("[sock]  net exited; its sockets are closed");
}

/// Handles a system call from user mode.
pub fn syscall(frame: &mut TrapFrame) {
    if let Some(status) = osmium::proc::syscall::handle(frame) {
        let task = osmium::sched::current();
        if let ExitStatus::Code(code) = status {
            println!("[user]  {} exited with status {code} (kernel sees CPU {})", task.name(), cpu::current_id());
        }
        drop(task);
        osmium::proc::exit(status);
    }
}

/// A fault in user mode raises a signal: the program's handler runs, or the
/// default action ends it (and only it, not the kernel).
pub fn user_fault(frame: &mut TrapFrame, cause: Trap) {
    let (sig, addr) = match cause {
        Trap::PageFault { addr, .. } => (11, addr),
        Trap::Misaligned { addr } => (7, addr),
        Trap::IllegalInstruction => (4, frame.pc()),
        Trap::Breakpoint => (5, frame.pc()),
        _ => (11, frame.pc()),
    };
    if let Some(status) = osmium::proc::signal::user_fault(frame, sig, addr) {
        let task = osmium::sched::current();
        println!("[user]  {} killed: {cause:?} at pc {:#x}", task.name(), frame.pc());
        drop(task);
        osmium::proc::exit(status);
    }
}

/// A user page fault that the process's memory resolves: a write to a page
/// `fork` shares gets its own copy, and the first touch of a demand-paged
/// `mmap` page its frame. The faulting instruction is then retried.
pub fn resolves(cause: Trap) -> bool {
    matches!(cause, Trap::PageFault { addr, access } if osmium::proc::handle_page_fault(addr as u64, access == Access::Write))
}

/// The user-mode half of a trap handler, for a trap taken from user mode
/// that is not an interrupt: a system call, a fault the process's memory
/// resolves, or a fault that raises a signal. Returns false for an
/// interrupt, which the kernel handles as it would from kernel mode.
pub fn handle(frame: &mut TrapFrame) -> bool {
    match frame.cause() {
        Trap::Syscall => syscall(frame),
        Trap::Interrupt(_) => return false,
        cause if resolves(cause) => {}
        cause => user_fault(frame, cause),
    }
    true
}

/// Run after the trap handler, before returning to user mode from an
/// interrupt: delivers pending signals (and stops threads of a process
/// that is ending).
pub fn before_return(frame: &mut TrapFrame) {
    if frame.from_user()
        && matches!(frame.cause(), Trap::Interrupt(_))
        && let Some(status) = osmium::proc::signal::deliver(frame)
    {
        osmium::proc::exit(status);
    }
}
