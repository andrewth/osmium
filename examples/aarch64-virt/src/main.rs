//! A small kernel for QEMU's AArch64 `virt` machine (GICv2), built entirely
//! from Osmium components. QEMU starts ELF kernels at EL1 with the MMU off
//! and the device tree at the base of RAM.
//!
//! The same steps as the RISC-V example, on different hardware: PL011 UART,
//! GICv2 interrupt controller, generic timer, AArch64 stage-1 paging and
//! PSCI for power-off.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use core::ptr::NonNull;
use osmium::arch::aarch64::{self, psci};
use osmium::arch::trap::{self, Access, Interrupt, Trap, TrapFrame};
use osmium::arch::{MAX_CPUS, cpu, irq, mmu};
use osmium::boot::fdt::Fdt;
use osmium::drivers::gicv2::GicV2;
use osmium::drivers::pl011::Pl011;
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::irq::{InterruptController, IrqTable};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::timer::TickRate;
use osmium::mm::frame::order_for;
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::PageSize;
use osmium::mm::paging::formats::Aarch64;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};

use osmium::arch::trap::TrapCpu;
use osmium::proc::{AddressSpace, ExitStatus, Process, UserMemory};
use osmium::sched::timer::TimerQueue;
use osmium::sched::{FifoScheduler, StackAllocator, Task, TaskBuilder};
use osmium::sync::{IrqSpinLock, Once};

core::arch::global_asm!(
    r#"
    .section .text.entry, "ax"
    .globl _start
_start:
    mov x19, x0
    adrp x1, boot_stack_top
    add x1, x1, :lo12:boot_stack_top
    mov sp, x1
    adrp x2, _bss_start
    add x2, x2, :lo12:_bss_start
    adrp x3, _bss_end
    add x3, x3, :lo12:_bss_end
1:  cmp x2, x3
    b.hs 2f
    str xzr, [x2], #8
    b 1b
2:  mov x0, x19
    bl kmain
3:  wfe
    b 3b

    // Secondary CPUs start here (via PSCI CPU_ON) at EL1 with the MMU off
    // and x0 = &SecondaryBoot.
    .globl secondary_start
secondary_start:
    ldr x1, [x0]
    mov sp, x1
    bl secondary_main
    b 3b

    .section .bss.stack, "aw", @nobits
    .balign 4096
    .space 65536
boot_stack_top:
"#
);

// User programs: position-independent EL0 code, copied into user pages.
// System calls use `svc #0` with Linux numbering: x8 = number, x0-x2 = args.
core::arch::global_asm!(
    r#"
    .section .rodata.user, "a"
    .balign 4
    .globl user_hello, user_hello_end, user_bad, user_bad_end
user_hello:
    mov x19, #3
1:  mov x8, #64                 // write(1, msg, 20)
    mov x0, #1
    adr x1, 3f
    mov x2, #20
    svc #0
    movz x9, #0x2d00            // busy-wait 20M iterations: only the timer
    movk x9, #0x131, lsl #16    // can switch us out
2:  subs x9, x9, #1
    b.ne 2b
    subs x19, x19, #1
    b.ne 1b
    mov x8, #93                 // exit(0)
    mov x0, #0
    svc #0
    udf #0
3:  .ascii "hello from process ?"
user_hello_end:

    .balign 4
user_bad:
    mov x8, #64
    mov x0, #1
    adr x1, 1f
    mov x2, #27
    svc #0
    movz x9, #0x4020, lsl #16   // kernel text: not EL0-accessible
    ldr x10, [x9]
    udf #0
1:  .ascii "about to read kernel memory"
user_bad_end:
"#
);

unsafe extern "C" {
    static user_hello: u8;
    static user_hello_end: u8;
    static user_bad: u8;
    static user_bad_end: u8;
    fn secondary_start();
    static _kernel_start: u8;
    static _etext: u8;
    static _erodata: u8;
    static _kernel_end: u8;
}

fn sym(s: &u8) -> u64 {
    s as *const u8 as u64
}

/// Where QEMU puts the device tree for ELF kernels.
const RAM_BASE_DTB: usize = 0x4000_0000;
/// QEMU virt's PL011, used for the console before the device tree is read.
const EARLY_UART: usize = 0x0900_0000;
/// Timer interrupt period.
const TICK_NS: u64 = 10_000_000;

type Frames = LockedFrames<BuddyAllocator<OffsetMapper>, OffsetMapper>;

// SAFETY: the kernel runs identity-mapped, before and after enabling the MMU.
static FRAMES: Frames = unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

/// The kernel page table, shared by all CPUs.
static PT: IrqSpinLock<Option<PageTable<Aarch64, &'static Frames>>> = IrqSpinLock::new(None);

/// Task stacks with an unmapped guard page below them.
struct GuardedStacks;

// SAFETY: blocks come from the frame allocator (exclusive, page aligned) and
// the usable part stays mapped read/write.
unsafe impl StackAllocator for GuardedStacks {
    fn alloc(&self, size: usize) -> Option<(NonNull<u8>, usize)> {
        let order = order_for(size + PAGE_SIZE);
        let guard = FRAMES.lock().alloc(order)?;
        let (_, flush) = PT.lock().as_mut()?.unmap_4k(VirtAddr::new(guard.0)).ok()?;
        flush.flush();
        Some((NonNull::new((guard.0 + PAGE_SIZE as u64) as *mut u8)?, (PAGE_SIZE << order) - PAGE_SIZE))
    }

    unsafe fn free(&self, base: NonNull<u8>, len: usize) {
        let guard = base.as_ptr() as u64 - PAGE_SIZE as u64;
        {
            let mut pt = PT.lock();
            let flags = MapFlags::RW | MapFlags::GLOBAL;
            let pt = pt.as_mut().expect("as_mut returned None");
            pt.map(VirtAddr::new(guard), PhysAddr::new(guard), PageSize::Size4K, flags).expect("map failed").flush();
        }
        // SAFETY: the block came from `alloc` with the same order.
        unsafe { FRAMES.lock().dealloc(PhysAddr::new(guard), order_for(len + PAGE_SIZE)) };
    }
}

/// Tells the exception vectors where the incoming task's stack ends.
fn on_switch(next: &osmium::sched::Task) {
    // Each process runs on its own TTBR0 table; kernel tasks on the kernel's.
    let root = osmium::proc::root_for(next).map_or(TTBR0.load(Ordering::Relaxed), |r| r.0);
    if aarch64::read_ttbr0_el1() & 0x0000_ffff_ffff_f000 != root {
        // SAFETY: both kinds of table map the kernel (shared root entry 0).
        unsafe { aarch64::write_ttbr0_el1(root) };
        osmium::arch::mmu::flush_all();
    }
    TrapCpu::current().set_stack_limit(next.kernel_stack_range().map_or(0, |r| r.start));
}

/// Gives this CPU an emergency stack for exceptions from an overflowed stack.
fn set_exception_stack() {
    let stack = alloc::vec![0u8; 16 * 1024].leak();
    let lo = stack.as_ptr() as usize;
    TrapCpu::current().set_exception_stack(lo..lo + stack.len());
}

static UART: Once<SerialConsole<Pl011>> = Once::new();
static GIC: Once<GicV2> = Once::new();
static IRQS: IrqTable<256> = IrqTable::new();
static SCHED: FifoScheduler = FifoScheduler::new(2).with_stealing();
static TIMERS: TimerQueue = TimerQueue::new();
static RATE: Once<TickRate> = Once::new();
static TICKS: AtomicU64 = AtomicU64::new(0);
static PSCI: Once<psci::Conduit> = Once::new();
static TTBR0: AtomicU64 = AtomicU64::new(0);
static VTIMER_IRQ: AtomicU32 = AtomicU32::new(0);
static ONLINE: AtomicUsize = AtomicUsize::new(1);
static IPIS: AtomicU64 = AtomicU64::new(0);
/// SGI used to wake other CPUs.
const IPI_SGI: u32 = 1;

/// Handed to a secondary CPU through `x0`.
#[repr(C)]
struct SecondaryBoot {
    stack_top: u64,
    cpu: usize,
}

/// Waits up to a second for `n` CPUs to be online.
fn wait_online(n: usize) -> bool {
    let deadline = now_ns() + 1_000_000_000;
    while ONLINE.load(Ordering::Acquire) < n {
        if now_ns() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

fn now_ns() -> u64 {
    RATE.get().expect("RATE initialised").ticks_to_ns(cpu::ticks())
}

fn shutdown() -> ! {
    psci::system_off(*PSCI.get().unwrap_or(&psci::Conduit::Hvc))
}

#[unsafe(no_mangle)]
extern "C" fn kmain(x0: usize) -> ! {
    // SAFETY: a single CPU runs this kernel; id 0 is unique.
    unsafe { cpu::set_current_id(0) };
    trap::set_handler(on_trap);
    // SAFETY: we run on a valid kernel stack from here on.
    unsafe { trap::install() };
    // SAFETY: the kernel is soft-float. Processes may use FP: each one's
    // registers are switched with its task.
    unsafe { osmium::arch::fp::enable() };

    // SAFETY: QEMU virt's PL011 lives here and nothing else drives it.
    let mut uart = Pl011::new(unsafe { IoMem::new(EARLY_UART as *mut u8, 0x1000) }).expect("new failed");
    uart.init(None);
    set_console(UART.call_once(|| SerialConsole::new(uart)));
    println!("\nosmium aarch64-virt example (EL{})", aarch64::current_el());

    // --- Device tree -------------------------------------------------------
    // QEMU passes the device tree in x0 only for Linux images.
    let dtb = if x0 != 0 { x0 } else { RAM_BASE_DTB };
    // SAFETY: QEMU places a valid device tree there; we reserve it below.
    let fdt = unsafe { Fdt::from_ptr(dtb as *const u8) }.expect("no device tree");
    let model = fdt.root().property("model").and_then(|p| p.as_str()).unwrap_or("?");
    println!("[fdt]   {model}, {} bytes at {dtb:#x}", fdt.total_size());
    let uart_node = fdt.find_compatible(&["arm,pl011"]).expect("no PL011");
    println!(
        "[uart]  pl011 at {:#x} (confirmed by the device tree)",
        uart_node.reg().next().expect("next returned None").0
    );
    let conduit = fdt
        .find_node("/psci")
        .and_then(|n| n.property("method"))
        .and_then(|p| p.as_str())
        .and_then(psci::Conduit::from_method)
        .unwrap_or(psci::Conduit::Hvc);
    PSCI.call_once(|| conduit);
    RATE.call_once(|| TickRate::new(aarch64::counter_frequency()));

    // --- Interrupt controller and timer line ------------------------------
    let gic_node = fdt.find_compatible(&["arm,cortex-a15-gic", "arm,gic-400"]).expect("no GICv2");
    let mut regs = gic_node.reg();
    let (gicd, gicd_len) =
        regs.next().map(|(a, s)| (a, s.expect("GIC register has a size"))).expect("GIC register present");
    let (gicc, gicc_len) =
        regs.next().map(|(a, s)| (a, s.expect("GIC register has a size"))).expect("GIC register present");
    // The virtual timer is the third `interrupts` triple: (PPI, number, flags).
    // (No heap yet, so no collecting into a Vec.)
    let timer = fdt.find_compatible(&["arm,armv8-timer"]).expect("no timer");
    let vtimer_irq = 16 + timer.interrupts().nth(2 * 3 + 1).expect("timer has no virtual timer interrupt");
    println!(
        "[gic]   distributor {gicd:#x}, cpu interface {gicc:#x}; virtual timer is INTID {vtimer_irq}; PSCI via {conduit:?}"
    );

    // --- Physical memory ---------------------------------------------------
    let mut map = MemoryMap::<32>::new();
    fdt.fill_memory_map(&mut map, Some(PhysAddr::new(dtb as u64))).expect("fill_memory_map failed");
    // SAFETY: linker-provided symbols.
    let (kstart, etext, erodata, kend) =
        unsafe { (sym(&_kernel_start), sym(&_etext), sym(&_erodata), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).expect("reserve failed");
    map.page_align_usable();
    for r in map.regions() {
        println!("[mem]   {:#011x}..{:#011x} {:?}", r.start.0, r.end.0, r.kind);
    }
    {
        let mut buddy = FRAMES.lock();
        for r in map.usable() {
            // SAFETY: the memory map says the range is free RAM, identity-mapped.
            unsafe { buddy.add_region(r.start, r.end) };
        }
        println!(
            "[frame] buddy allocator: {} free frames ({} MiB)",
            buddy.free_frames(),
            (buddy.free_frames() * PAGE_SIZE) >> 20
        );
    }

    // --- Heap ------------------------------------------------------------
    HEAP.init(&FRAMES);
    let squares: Vec<u64> = (0..1000).map(|i| i * i).collect();
    let s: String = ["heap", "works"].join(" ");
    println!("[heap]  {s} (sum of squares {})", squares.iter().sum::<u64>());

    // --- Paging (stage 1, 4 KiB granule, W^X) ------------------------------
    // The kernel's own memory node is mapped piecewise below (W^X); any
    // other node, all of which the frame allocator was given, as RW.
    let ram = fdt
        .memory()
        .find(|&(base, len)| (base..base + len).contains(&kstart))
        .expect("no memory node holds the kernel");
    let ram_end = ram.0 + ram.1;
    let mut pt: PageTable<Aarch64, &'static Frames> = PageTable::new(&FRAMES).expect("new failed");
    let k = |f| f | MapFlags::GLOBAL;
    let va = |a: u64| VirtAddr::new(a);
    let pa = |a: u64| PhysAddr::new(a);
    // Read/write RAM uses 4 KiB pages from the start: unmapping a task
    // stack's guard page must not split a live block, which on AArch64
    // needs break-before-make and would briefly unmap 2 MiB under other
    // CPUs.
    let map_4k = |pt: &mut PageTable<Aarch64, &'static Frames>, start: u64, len: u64| {
        for p in (start..start + len).step_by(PAGE_SIZE) {
            pt.map(va(p), pa(p), PageSize::Size4K, k(MapFlags::RW)).expect("map failed").ignore();
        }
    };
    map_4k(&mut pt, ram.0, kstart - ram.0);
    pt.map_range(va(kstart), pa(kstart), etext - kstart, k(MapFlags::RX)).expect("map_range failed");
    pt.map_range(va(etext), pa(etext), erodata - etext, k(MapFlags::READ)).expect("map_range failed");
    map_4k(&mut pt, erodata, ram_end - erodata);
    for (base, len) in fdt.memory().filter(|&m| m != ram) {
        let (start, end) = (base.next_multiple_of(PAGE_SIZE as u64), (base + len) & !(PAGE_SIZE as u64 - 1));
        if start < end {
            map_4k(&mut pt, start, end - start);
        }
    }
    for (base, len) in [(EARLY_UART as u64, PAGE_SIZE as u64), (gicd, gicd_len), (gicc, gicc_len)] {
        pt.map_range(va(base), pa(base), len.next_multiple_of(PAGE_SIZE as u64), k(MapFlags::RW | MapFlags::DEVICE))
            .expect("map_range failed");
    }
    enable_mmu(pt.root());
    TTBR0.store(pt.root().0, Ordering::Release);
    let t = pt.translate(va(kmain as *const () as u64)).expect("translate failed");
    println!("[mmu]   MMU on, TTBR0 {:#x}; kmain mapped {:?} via {:?} page", pt.root().0, t.flags, t.size);
    *PT.lock() = Some(pt);
    set_exception_stack();
    osmium::sched::set_stack_allocator(&GuardedStacks);
    osmium::sched::set_switch_hook(on_switch);
    println!("[guard] task stacks get unmapped guard pages; overflowing exceptions move to a per-CPU exception stack");

    // --- Interrupts, scheduler ---------------------------------------------
    // SAFETY: the device tree says the GIC lives here, mapped as device memory above.
    let gic = GIC.call_once(|| unsafe {
        GicV2::new(IoMem::new(gicd as *mut u8, gicd_len as usize), IoMem::new(gicc as *mut u8, gicc_len as usize))
    });
    gic.init_distributor();
    VTIMER_IRQ.store(vtimer_irq, Ordering::Relaxed);
    IRQS.register(vtimer_irq, &on_timer).expect("register failed");
    IRQS.register(IPI_SGI, &|_| {
        IPIS.fetch_add(1, Ordering::Relaxed);
    })
    .expect("register failed");

    osmium::sched::inject_scheduler(&SCHED);
    osmium::sched::init_cpu();
    start_local_interrupts();
    println!("[sched] FIFO scheduler, {} ms tick, {} lines on the GIC", TICK_NS / 1_000_000, gic.num_irqs());

    // --- Secondary CPUs -----------------------------------------------------
    osmium::sched::set_remote_wake_hook(|cpu| GIC.get().expect("GIC initialised").send_sgi(1 << cpu, IPI_SGI));
    let boot_mpidr = aarch64::read_mpidr_el1() & 0xff_00ff_ffff;
    let cpus = fdt.find_node("/cpus").expect("no /cpus");
    let mpidrs = cpus
        .children()
        .filter(|c| c.property("device_type").and_then(|p| p.as_str()) == Some("cpu"))
        .filter_map(|c| c.reg().next().map(|(m, _)| m));
    let mut ncpus = 1;
    for mpidr in mpidrs.filter(|&m| m != boot_mpidr).take(MAX_CPUS - 1) {
        let stack = alloc::vec![0u8; 64 * 1024].leak();
        let boot = alloc::boxed::Box::leak(alloc::boxed::Box::new(SecondaryBoot {
            stack_top: (stack.as_ptr() as u64 + stack.len() as u64) & !15,
            cpu: ncpus,
        }));
        // SAFETY: `secondary_start` sets up its stack from `boot`.
        let rc = unsafe { psci::cpu_on(conduit, mpidr, secondary_start as *const () as u64, boot as *const _ as u64) };
        // One CPU at a time: one that fails to start or never checks in
        // ends the bring-up, so CPU indices stay dense.
        if rc != 0 {
            println!("[smp]   PSCI CPU_ON {mpidr:#x} failed ({rc}); continuing with {ncpus} CPUs");
            break;
        }
        if !wait_online(ncpus + 1) {
            println!("[smp]   CPU {mpidr:#x} did not check in within 1 s; continuing with {ncpus} CPUs");
            break;
        }
        ncpus += 1;
    }
    println!("[smp]   {ncpus} CPUs online");

    demos::run_all(&demos::Env { timers: &TIMERS, ticks: &TICKS, now_ns });
    if ncpus > 1 {
        demos::smp(ncpus);
        demos::balance(ncpus, &|| SCHED.steals());
    }
    fault_demo();
    overflow_demo();
    demos::user::boot_vfs();
    user_demo(ncpus);

    println!(
        "[done]  {} timer ticks, {} IPIs, {} free frames; shutting down",
        TICKS.load(Ordering::Relaxed),
        IPIS.load(Ordering::Relaxed),
        FRAMES.lock().free_frames()
    );
    shutdown()
}

/// Per-CPU interrupt setup: GIC CPU interface, banked timer and IPI lines,
/// the generic timer, and the CPU's interrupt mask.
fn start_local_interrupts() {
    let gic = GIC.get().expect("GIC initialised");
    let vtimer = VTIMER_IRQ.load(Ordering::Relaxed);
    gic.init_cpu();
    gic.set_priority(vtimer, 0x80);
    gic.enable(vtimer);
    gic.enable(IPI_SGI);
    arm_timer();
    // SAFETY: enables the virtual timer; the GIC routes it to this CPU.
    unsafe { aarch64::write_cntv_ctl_el0(1) };
    irq::enable();
}

/// Entry point of secondary CPUs, on their own stack with the MMU off.
#[unsafe(no_mangle)]
extern "C" fn secondary_main(boot: &SecondaryBoot) -> ! {
    // SAFETY: each secondary gets a distinct logical id from the boot CPU.
    unsafe { cpu::set_current_id(boot.cpu) };
    // SAFETY: we are on the stack the boot CPU allocated for us.
    unsafe { trap::install() };
    // SAFETY: as on the boot CPU.
    unsafe { osmium::arch::fp::enable() };
    enable_mmu(PhysAddr::new(TTBR0.load(Ordering::Acquire)));
    set_exception_stack();
    osmium::sched::init_cpu();
    start_local_interrupts();
    println!("[smp]   MPIDR {:#x} online as CPU {}", aarch64::read_mpidr_el1() & 0xff_ffff, boot.cpu);
    ONLINE.fetch_add(1, Ordering::Release);
    // Hand the CPU to the scheduler for good.
    osmium::sched::exit()
}

/// Programs MAIR, TCR and TTBR0 and turns on the MMU and caches.
fn enable_mmu(root: PhysAddr) {
    let parange = aarch64::read_id_aa64mmfr0_el1() & 0xf;
    let tcr = 16                 // T0SZ: 48-bit addresses
        | 1 << 8                 // IRGN0: write-back, write-allocate
        | 1 << 10                // ORGN0: write-back, write-allocate
        | 3 << 12                // SH0: inner shareable
        | 1 << 23                // EPD1: no TTBR1 walks
        | parange.min(5) << 32; // IPS: what the CPU supports
    // SAFETY: the table identity-maps the running code, its stack, the heap
    // and every device we touch; the barriers order the table writes.
    unsafe {
        aarch64::write_mair_el1(aarch64::MAIR_VALUE);
        aarch64::write_tcr_el1(tcr);
        aarch64::write_ttbr0_el1(root.0);
        core::arch::asm!("dsb ish", "isb");
        mmu::flush_all();
        let sctlr = aarch64::read_sctlr_el1() | 1 << 0 | 1 << 2 | 1 << 12; // M, C, I
        aarch64::write_sctlr_el1(sctlr);
    }
}

fn arm_timer() {
    let ticks = RATE.get().expect("RATE initialised").ns_to_ticks(TICK_NS);
    // SAFETY: reprograms only the virtual timer's countdown.
    unsafe { aarch64::write_cntv_tval_el0(ticks) };
}

fn on_timer(_irq: u32) {
    if cpu::current_id() == 0 {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }
    arm_timer();
    TIMERS.process(now_ns());
    osmium::sched::tick();
}

/// The last synchronous exception that `on_trap` recovered from.
static RECOVERED: IrqSpinLock<Option<Trap>> = IrqSpinLock::new(None);
static RECOVER: AtomicBool = AtomicBool::new(false);

fn fault_demo() {
    RECOVER.store(true, Ordering::SeqCst);
    // SAFETY: the handler steps over the breakpoint.
    unsafe { core::arch::asm!("brk #0") };
    println!("[trap]  recovered from {:?}", RECOVERED.lock().take().expect("recovery recorded by the trap handler"));
    // Nothing is mapped at 0x1000: a data abort.
    // SAFETY: the read faults and the handler skips it; the value is never used.
    let _ = unsafe { core::ptr::read_volatile(0x1000 as *const u64) };
    println!("[trap]  recovered from {:?}", RECOVERED.lock().take().expect("recovery recorded by the trap handler"));
    RECOVER.store(false, Ordering::SeqCst);
}

/// A task that recurses until it runs off the bottom of its stack.
fn overflow_demo() {
    #[inline(never)]
    fn recurse(depth: u64) -> u64 {
        let frame = core::hint::black_box([depth; 32]);
        if core::hint::black_box(true) { recurse(depth + 1) + frame[7] } else { 0 }
    }
    let t = TaskBuilder::new("deep").stack_size(16 * 1024).spawn(|| {
        recurse(0);
    });
    t.join();
    println!("[guard] the other tasks keep running: {} free frames", FRAMES.lock().free_frames());
}

/// Where every user program is mapped, each in its own address space:
/// 512 GiB (root entry 1); the kernel lives under root entry 0, shared.
const USER_BASE: u64 = 0x80_0000_0000;

/// A process's memory: a table sharing the kernel's root entry 0, with
/// table and user pages from `FRAMES`.
type Space = AddressSpace<Aarch64, &'static Frames>;

fn new_space() -> Space {
    // SAFETY: the kernel table lives for the whole run.
    unsafe { Space::new(&FRAMES, PT.lock().as_ref().expect("as_ref returned None"), 0..1) }
        .expect("out of memory for a page table")
}

/// Makes code just written to `range` of the running process visible to
/// instruction fetch on every CPU. The code was written through the kernel's
/// identity map; cleaning by the user address reaches the same lines.
fn sync_icache(range: core::ops::Range<u64>) {
    for line in (range.start & !63..range.end).step_by(64) {
        // SAFETY: cache maintenance on a mapped EL0 page (PAN is off).
        unsafe { core::arch::asm!("dc cvau, {}", in(reg) line) };
    }
    // SAFETY: barriers and instruction-cache invalidation only.
    unsafe { core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb") };
}

/// Copies a user program into fresh pages, maps it EL0-accessible (code
/// read/execute, stack read/write) at slot `n`, and spawns a task on `cpu`
/// that drops to EL0 there.
fn spawn_user(name: &'static str, n: u64, code: (&u8, &u8), cpu: usize) -> (Arc<Task>, Weak<Process>) {
    let (start, end) = (code.0 as *const u8, code.1 as *const u8);
    // SAFETY: the linker symbols delimit the program's bytes.
    let mut code = unsafe { core::slice::from_raw_parts(start, end as usize - start as usize) }.to_vec();
    assert!(code.len() <= PAGE_SIZE);
    // Tell this copy which process it is (the '?' in its message).
    if let Some(q) = code.iter().position(|&b| b == b'?') {
        code[q] = b'0' + n as u8;
    }
    let (code_va, stack_va, len) = (USER_BASE, USER_BASE + 0x8000, code.len() as u64);
    let space = new_space();
    space.load_flat(code_va, &code, MapFlags::RX).expect("load_flat failed");
    space.map_anon(stack_va, PAGE_SIZE as u64, MapFlags::RW).expect("map_anon failed");
    let process = Process::new(name, space, USER_BASE + 0x10000);
    let task = process.spawn(TaskBuilder::new(name).cpu(cpu), move || {
        // The switch hook has installed this process's table.
        sync_icache(code_va..code_va + len);
        let kernel_top =
            osmium::sched::current().kernel_stack_range().expect("kernel_stack_range returned None").end as u64;
        // SAFETY: vectors are installed, `kernel_top` is this task's own
        // kernel stack, and both pages are mapped EL0-accessible.
        unsafe { aarch64::enter_user(code_va, stack_va + PAGE_SIZE as u64, kernel_top) }
    });
    (task, Arc::downgrade(&process))
}

/// The Rust user program, built by `build.rs` from `examples/user/hello.rs`.
static HELLO_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hello.elf"));

/// Loads an ELF executable into a new address space and spawns a task on
/// `cpu` that runs it in user mode.
fn spawn_elf(name: &'static str, image: &[u8], cpu: usize) -> (Arc<Task>, Weak<Process>) {
    let elf = osmium::boot::elf::Elf::new(image).expect("bad user ELF");
    let space = new_space();
    let brk = space.load_elf(&elf).expect("loading the user ELF failed");
    let code: Vec<_> = elf.segments().filter(|s| s.flags.execute).map(|s| s.vaddr..s.vaddr + s.mem_size).collect();
    let stack_top: u64 = 0xff_0000_0000;
    space.map_anon(stack_top - PAGE_SIZE as u64, PAGE_SIZE as u64, MapFlags::RW).expect("map_anon failed");
    let entry = elf.entry();
    let process = Process::new(name, space, brk);
    process.set_mmap_area(0xa0_0000_0000..0xa1_0000_0000);
    let task = process.spawn(TaskBuilder::new(name).cpu(cpu), move || {
        // The switch hook has installed this process's table.
        code.into_iter().for_each(sync_icache);
        let kernel_top =
            osmium::sched::current().kernel_stack_range().expect("kernel_stack_range returned None").end as u64;
        // SAFETY: vectors are installed, the switch hook installs this
        // process's table, and its pages are mapped EL0-accessible.
        unsafe { aarch64::enter_user(entry, stack_top, kernel_top) }
    });
    (task, Arc::downgrade(&process))
}

/// The Rust program that forks and execs, from `examples/user/init.rs`.
static INIT_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/init.elf"));

/// What `fork` and `execve` need: spaces like `new_space`'s, a stack below
/// 0xff_0000_0000 and an `mmap` area above it, as for `spawn_elf`.
/// osmium-proc makes loaded and copied code visible to instruction fetch.
fn platform() -> osmium::proc::Platform {
    osmium::proc::Platform {
        new_memory: || {
            // SAFETY: the kernel table lives for the whole run.
            let space = unsafe { Space::new(&FRAMES, PT.lock().as_ref().expect("as_ref returned None"), 0..1) };
            Ok(alloc::boxed::Box::new(space.map_err(|_| osmium::fs::Errno::ENOMEM)?))
        },
        activate: |root| {
            // SAFETY: the table shares the kernel's root entry 0.
            unsafe { aarch64::write_ttbr0_el1(root.0) };
            osmium::arch::mmu::flush_all();
        },
        resume: |frame| {
            let kernel_top =
                osmium::sched::current().kernel_stack_range().expect("kernel_stack_range returned None").end as u64;
            // SAFETY: the child's task is running with its table active (the
            // switch hook); the frame, its parent's from an svc, is on this
            // task's stack.
            unsafe { aarch64::resume_user(&frame, kernel_top) }
        },
        stack_top: 0xff_0000_0000,
        stack_size: 64 * 1024,
        mmap_area: 0xa0_0000_0000..0xa1_0000_0000,
    }
}

/// Runs `/bin/init`, which forks, execs and waits, on `cpu`; its children
/// go wherever the scheduler puts them.
fn fork_exec_demo(cpu: usize) {
    demos::user::install("init", INIT_ELF);
    let process =
        Process::new_boxed("init", (platform().new_memory)().expect("out of memory for the init address space"), 0);
    let init = Arc::downgrade(&process);
    let task = process.spawn(TaskBuilder::new("init").cpu(cpu), || {
        let entry = osmium::proc::current()
            .expect("current returned None")
            .exec("/bin/init", &[b"init"], &[])
            .expect("exec /bin/init");
        let kernel_top =
            osmium::sched::current().kernel_stack_range().expect("kernel_stack_range returned None").end as u64;
        // SAFETY: exec activated the new table; vectors are installed and
        // `kernel_top` is this task's own kernel stack.
        unsafe { aarch64::enter_user(entry.pc, entry.sp, kernel_top) }
    });
    drop(process);
    task.join();
    // The task holds the process: let it go too.
    drop(task);
    let freed = demos::user::freed(&[init]);
    println!("[user]  init and its children reaped; {freed} of 1 init address space torn down");
}

fn user_demo(ncpus: usize) {
    osmium::proc::set_platform(platform());
    // SAFETY: linker symbols delimiting the user programs.
    let (hello, bad) = unsafe { ((&user_hello, &user_hello_end), (&user_bad, &user_bad_end)) };
    let cpu = 1 % ncpus;
    let spawned = [
        spawn_user("user-1", 1, hello, cpu),
        spawn_user("user-2", 2, hello, cpu),
        spawn_user("user-bad", 3, bad, cpu),
        spawn_elf("user-elf", HELLO_ELF, cpu),
    ];
    println!("[user]  running 3 EL0 programs on CPU {cpu}");
    println!("[user]  each program has its own page table; all run at {USER_BASE:#x}");
    let mut processes = Vec::new();
    for (task, process) in spawned {
        task.join();
        processes.push(process);
    }
    // Exited tasks (and their address spaces) are freed once their CPU has
    // switched away from them.
    let freed = demos::user::freed(&processes);
    println!("[user]  {freed} of 4 address spaces torn down with their tasks");
    fork_exec_demo(cpu);
}

/// Handles `svc #0` from EL0. ELR already points past the `svc`.
fn syscall(frame: &mut TrapFrame) {
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
fn user_fault(frame: &mut TrapFrame, cause: Trap) {
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

/// Runs the trap handler, then, before returning to user mode from an
/// interrupt, delivers pending signals (and stops threads of a process that
/// is ending).
fn on_trap(frame: &mut TrapFrame) {
    handle_trap(frame);
    if frame.from_user() && matches!(frame.cause(), Trap::Interrupt(_)) {
        if let Some(status) = osmium::proc::signal::deliver(frame) {
            osmium::proc::exit(status);
        }
    }
}

fn handle_trap(frame: &mut TrapFrame) {
    if frame.from_user() {
        match frame.cause() {
            Trap::Syscall => return syscall(frame),
            Trap::Interrupt(_) => {}
            // A write to a page `fork` shares gets its own copy; retry.
            Trap::PageFault { addr, access: Access::Write } if osmium::proc::handle_page_fault(addr as u64, true) => return,
            cause => return user_fault(frame, cause),
        }
    }
    if TrapCpu::current().overflowed(frame) {
        // This frame lives on the exception stack; the task's own stack is
        // exhausted, so it cannot continue. End only that task.
        let task = osmium::sched::current();
        println!(
            "[guard] task {:?} overflowed its stack ({:?} at sp {:#x}); killed",
            task.name(),
            frame.cause(),
            frame.sp()
        );
        // A nested exception must stay on the exception stack.
        RECOVER.store(true, Ordering::SeqCst);
        // SAFETY: the breakpoint arm below steps over it.
        unsafe { core::arch::asm!("brk #0") };
        RECOVER.store(false, Ordering::SeqCst);
        println!(
            "[guard] nested {:?} on the exception stack handled",
            RECOVERED.lock().take().expect("recovery recorded by the trap handler")
        );
        drop(task);
        osmium::sched::exit();
    }
    match frame.cause() {
        Trap::Interrupt(Interrupt::External) => {
            IRQS.handle_pending(GIC.get().expect("GIC initialised"));
            // Leaving an interrupt is a preemption point.
            osmium::sched::preempt_if_needed();
        }
        cause @ (Trap::Breakpoint | Trap::PageFault { .. }) if RECOVER.load(Ordering::SeqCst) => {
            *RECOVERED.lock() = Some(cause);
            // A64 instructions are always 4 bytes.
            frame.set_pc(frame.pc() + 4);
        }
        cause => panic!("unhandled trap {cause:?} at pc {:#x}, ESR {:#x}", frame.pc(), frame.esr),
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;
    irq::disable();
    // Straight to the PL011, not through the console: the panic may have
    // come from inside println, with the console's locks held.
    // SAFETY: the UART is already set up and mapped at this address.
    if let Ok(mut uart) = Pl011::new(unsafe { IoMem::new(EARLY_UART as *mut u8, 0x1000) }) {
        let _ = writeln!(osmium::hal::serial::SerialWriter(&mut uart), "\n[panic] {info}");
    }
    shutdown()
}
