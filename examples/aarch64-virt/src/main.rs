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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use osmium::arch::aarch64::{self, psci};
use osmium::arch::trap::{self, Interrupt, Trap, TrapFrame};
use osmium::arch::{cpu, irq, mmu};
use osmium::boot::fdt::Fdt;
use osmium::drivers::gicv2::GicV2;
use osmium::drivers::pl011::Pl011;
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::irq::{InterruptController, IrqTable};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::timer::TickRate;
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::Aarch64;
use osmium::mm::frame::order_for;
use osmium::mm::paging::PageSize;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use core::ptr::NonNull;

use osmium::arch::trap::TrapCpu;
use osmium::sched::{FifoScheduler, StackAllocator, TaskBuilder};
use osmium::sched::timer::TimerQueue;
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
1:  mov x8, #64                 // write(1, msg, 14)
    mov x0, #1
    adr x1, 3f
    mov x2, #14
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
3:  .ascii "hello from EL0"
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
            let pt = pt.as_mut().unwrap();
            pt.map(VirtAddr::new(guard), PhysAddr::new(guard), PageSize::Size4K, flags).unwrap().flush();
        }
        // SAFETY: the block came from `alloc` with the same order.
        unsafe { FRAMES.lock().dealloc(PhysAddr::new(guard), order_for(len + PAGE_SIZE)) };
    }
}

/// Tells the exception vectors where the incoming task's stack ends.
fn on_switch(next: &osmium::sched::Task) {
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
static SCHED: FifoScheduler = FifoScheduler::new(2);
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

fn now_ns() -> u64 {
    RATE.get().unwrap().ticks_to_ns(cpu::ticks())
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

    // SAFETY: QEMU virt's PL011 lives here and nothing else drives it.
    let mut uart = Pl011::new(unsafe { IoMem::new(EARLY_UART as *mut u8, 0x1000) }).unwrap();
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
    println!("[uart]  pl011 at {:#x} (confirmed by the device tree)", uart_node.reg().next().unwrap().0);
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
    let (gicd, gicd_len) = regs.next().map(|(a, s)| (a, s.unwrap())).unwrap();
    let (gicc, gicc_len) = regs.next().map(|(a, s)| (a, s.unwrap())).unwrap();
    // The virtual timer is the third `interrupts` triple: (PPI, number, flags).
    // (No heap yet, so no collecting into a Vec.)
    let timer = fdt.find_compatible(&["arm,armv8-timer"]).expect("no timer");
    let vtimer_irq = 16 + timer.interrupts().nth(2 * 3 + 1).expect("timer has no virtual timer interrupt");
    println!(
        "[gic]   distributor {gicd:#x}, cpu interface {gicc:#x}; virtual timer is INTID {vtimer_irq}; PSCI via {conduit:?}"
    );

    // --- Physical memory ---------------------------------------------------
    let mut map = MemoryMap::<32>::new();
    fdt.fill_memory_map(&mut map, Some(PhysAddr::new(dtb as u64))).unwrap();
    // SAFETY: linker-provided symbols.
    let (kstart, etext, erodata, kend) =
        unsafe { (sym(&_kernel_start), sym(&_etext), sym(&_erodata), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).unwrap();
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
        println!("[frame] buddy allocator: {} free frames ({} MiB)", buddy.free_frames(), (buddy.free_frames() * PAGE_SIZE) >> 20);
    }

    // --- Heap ------------------------------------------------------------
    HEAP.init(&FRAMES);
    let squares: Vec<u64> = (0..1000).map(|i| i * i).collect();
    let s: String = ["heap", "works"].join(" ");
    println!("[heap]  {s} (sum of squares {})", squares.iter().sum::<u64>());

    // --- Paging (stage 1, 4 KiB granule, W^X) ------------------------------
    let ram = fdt.memory().next().expect("no memory node");
    let ram_end = ram.0 + ram.1;
    let mut pt: PageTable<Aarch64, &'static Frames> = PageTable::new(&FRAMES).unwrap();
    let k = |f| f | MapFlags::GLOBAL;
    let va = |a: u64| VirtAddr::new(a);
    let pa = |a: u64| PhysAddr::new(a);
    pt.map_range(va(ram.0), pa(ram.0), kstart - ram.0, k(MapFlags::RW)).unwrap();
    pt.map_range(va(kstart), pa(kstart), etext - kstart, k(MapFlags::RX)).unwrap();
    pt.map_range(va(etext), pa(etext), erodata - etext, k(MapFlags::READ)).unwrap();
    pt.map_range(va(erodata), pa(erodata), ram_end - erodata, k(MapFlags::RW)).unwrap();
    for (base, len) in [(EARLY_UART as u64, PAGE_SIZE as u64), (gicd, gicd_len), (gicc, gicc_len)] {
        pt.map_range(va(base), pa(base), len.next_multiple_of(PAGE_SIZE as u64), k(MapFlags::RW | MapFlags::DEVICE)).unwrap();
    }
    enable_mmu(pt.root());
    TTBR0.store(pt.root().0, Ordering::Release);
    let t = pt.translate(va(kmain as *const () as u64)).unwrap();
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
    IRQS.register(vtimer_irq, &on_timer).unwrap();
    IRQS.register(IPI_SGI, &|_| {
        IPIS.fetch_add(1, Ordering::Relaxed);
    })
    .unwrap();

    osmium::sched::inject_scheduler(&SCHED);
    osmium::sched::init_cpu();
    start_local_interrupts();
    println!("[sched] FIFO scheduler, {} ms tick, {} lines on the GIC", TICK_NS / 1_000_000, gic.num_irqs());

    // --- Secondary CPUs -----------------------------------------------------
    osmium::sched::set_remote_wake_hook(|cpu| GIC.get().unwrap().send_sgi(1 << cpu, IPI_SGI));
    let boot_mpidr = aarch64::read_mpidr_el1() & 0xff_00ff_ffff;
    let cpus = fdt.find_node("/cpus").expect("no /cpus");
    let mpidrs = cpus
        .children()
        .filter(|c| c.property("device_type").and_then(|p| p.as_str()) == Some("cpu"))
        .filter_map(|c| c.reg().next().map(|(m, _)| m));
    let mut ncpus = 1;
    for mpidr in mpidrs.filter(|&m| m != boot_mpidr) {
        let stack = alloc::vec![0u8; 64 * 1024].leak();
        let boot = alloc::boxed::Box::leak(alloc::boxed::Box::new(SecondaryBoot {
            stack_top: (stack.as_ptr() as u64 + stack.len() as u64) & !15,
            cpu: ncpus,
        }));
        // SAFETY: `secondary_start` sets up its stack from `boot`.
        let rc = unsafe { psci::cpu_on(conduit, mpidr, secondary_start as *const () as u64, boot as *const _ as u64) };
        assert_eq!(rc, 0, "PSCI CPU_ON {mpidr:#x} failed");
        ncpus += 1;
    }
    while ONLINE.load(Ordering::Acquire) < ncpus {
        core::hint::spin_loop();
    }
    println!("[smp]   {ncpus} CPUs online");

    demos::run_all(&demos::Env { timers: &TIMERS, ticks: &TICKS, now_ns });
    if ncpus > 1 {
        demos::smp(ncpus);
    }
    fault_demo();
    overflow_demo();
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
    let gic = GIC.get().unwrap();
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
        | parange.min(5) << 32;  // IPS: what the CPU supports
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
    let ticks = RATE.get().unwrap().ns_to_ticks(TICK_NS);
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
    println!("[trap]  recovered from {:?}", RECOVERED.lock().take().unwrap());
    // Nothing is mapped at 0x1000: a data abort.
    // SAFETY: the read faults and the handler skips it; the value is never used.
    let _ = unsafe { core::ptr::read_volatile(0x1000 as *const u64) };
    println!("[trap]  recovered from {:?}", RECOVERED.lock().take().unwrap());
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

/// Where user programs are mapped: 64 GiB, clear of RAM and devices.
const USER_BASE: u64 = 0x10_0000_0000;

/// Copies a user program into fresh pages, maps it EL0-accessible (code
/// read/execute, stack read/write) at slot `n`, and spawns a task on `cpu`
/// that drops to EL0 there.
fn spawn_user(name: &'static str, n: u64, code: (&u8, &u8), cpu: usize) -> alloc::sync::Arc<osmium::sched::Task> {
    let (start, end) = (code.0 as *const u8, code.1 as *const u8);
    let len = end as usize - start as usize;
    assert!(len <= PAGE_SIZE);
    let mut frames = FRAMES.lock();
    let (code_pa, stack_pa) = (frames.alloc_frame().unwrap(), frames.alloc_frame().unwrap());
    drop(frames);
    // SAFETY: fresh frames, identity-mapped; the program fits in one page.
    unsafe {
        core::ptr::write_bytes(code_pa.0 as *mut u8, 0, PAGE_SIZE);
        core::ptr::copy_nonoverlapping(start, code_pa.0 as *mut u8, len);
        // Make the new code visible to instruction fetch on every CPU.
        for line in (code_pa.0..code_pa.0 + len as u64).step_by(64) {
            core::arch::asm!("dc cvau, {}", in(reg) line);
        }
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb");
    }
    let (code_va, stack_va) = (USER_BASE + n * 0x10000, USER_BASE + n * 0x10000 + 0x8000);
    {
        let mut pt = PT.lock();
        let pt = pt.as_mut().unwrap();
        pt.map(VirtAddr::new(code_va), code_pa, PageSize::Size4K, MapFlags::RX | MapFlags::USER).unwrap().flush();
        pt.map(VirtAddr::new(stack_va), stack_pa, PageSize::Size4K, MapFlags::RW | MapFlags::USER).unwrap().flush();
    }
    TaskBuilder::new(name).cpu(cpu).spawn(move || {
        let kernel_top = osmium::sched::current().kernel_stack_range().unwrap().end as u64;
        // SAFETY: vectors are installed, `kernel_top` is this task's own
        // kernel stack, and both pages are mapped EL0-accessible.
        unsafe { aarch64::enter_user(code_va, stack_va + PAGE_SIZE as u64, kernel_top) }
    })
}

fn user_demo(ncpus: usize) {
    // SAFETY: linker symbols delimiting the user programs.
    let (hello, bad) = unsafe { ((&user_hello, &user_hello_end), (&user_bad, &user_bad_end)) };
    let cpu = 1 % ncpus;
    let tasks = [
        spawn_user("user-1", 0, hello, cpu),
        spawn_user("user-2", 1, hello, cpu),
        spawn_user("user-bad", 2, bad, cpu),
    ];
    println!("[user]  running 3 EL0 programs on CPU {cpu}");
    for t in tasks {
        t.join();
    }
}

/// Handles `svc #0` from EL0. ELR already points past the `svc`.
fn syscall(frame: &mut TrapFrame) {
    let (nr, a0, a1, a2) = (frame.x[8], frame.x[0], frame.x[1], frame.x[2]);
    let task = osmium::sched::current();
    match nr {
        64 if a0 == 1 && a2 <= 256 && user_readable(a1, a2) => {
            // SAFETY: every page of the buffer is mapped EL0-readable, and
            // PAN is off, so EL1 can read it.
            let bytes = unsafe { core::slice::from_raw_parts(a1 as *const u8, a2 as usize) };
            println!("[user]  {}: {}", task.name(), core::str::from_utf8(bytes).unwrap_or("<not utf-8>"));
            frame.set_return(a2);
        }
        93 => {
            println!("[user]  {} exited with status {a0} (kernel sees CPU {})", task.name(), cpu::current_id());
            drop(task);
            osmium::sched::exit();
        }
        _ => frame.set_return(-38i64 as u64), // ENOSYS
    }
}

fn user_readable(addr: u64, len: u64) -> bool {
    let Some(end) = addr.checked_add(len) else { return false };
    let pt = PT.lock();
    let pt = pt.as_ref().unwrap();
    (addr & !(PAGE_SIZE as u64 - 1)..end)
        .step_by(PAGE_SIZE)
        .all(|p| pt.translate(VirtAddr::new(p)).is_some_and(|t| t.flags.contains(MapFlags::USER)))
}

fn on_trap(frame: &mut TrapFrame) {
    if frame.from_user() {
        match frame.cause() {
            Trap::Syscall => return syscall(frame),
            Trap::Interrupt(_) => {}
            cause => {
                // A fault in user mode ends that task, not the kernel.
                let task = osmium::sched::current();
                println!("[user]  {} killed: {cause:?} at pc {:#x}", task.name(), frame.pc());
                drop(task);
                osmium::sched::exit();
            }
        }
    }
    if TrapCpu::current().overflowed(frame) {
        // This frame lives on the exception stack; the task's own stack is
        // exhausted, so it cannot continue. End only that task.
        let task = osmium::sched::current();
        println!("[guard] task {:?} overflowed its stack ({:?} at sp {:#x}); killed", task.name(), frame.cause(), frame.sp());
        // A nested exception must stay on the exception stack.
        RECOVER.store(true, Ordering::SeqCst);
        // SAFETY: the breakpoint arm below steps over it.
        unsafe { core::arch::asm!("brk #0") };
        RECOVER.store(false, Ordering::SeqCst);
        println!("[guard] nested {:?} on the exception stack handled", RECOVERED.lock().take().unwrap());
        drop(task);
        osmium::sched::exit();
    }
    match frame.cause() {
        Trap::Interrupt(Interrupt::External) => {
            IRQS.handle_pending(GIC.get().unwrap());
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
    irq::disable();
    println!("\n[panic] {info}");
    shutdown()
}
