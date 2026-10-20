//! A small kernel for QEMU's RISC-V `virt` machine, built entirely from
//! Osmium components. OpenSBI (QEMU's `-bios default`) starts it in S-mode
//! with the hart id in `a0` and the device tree in `a1`.
//!
//! It walks through the toolkit in boot order: device tree, memory map,
//! frame allocator, heap, Sv39 paging, UART console, scheduler, timer
//! interrupts with preemption, and sleeping on a timer queue.
#![no_std]
#![no_main]

extern crate alloc;

mod trap;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use osmium::arch::riscv64::{self, SatpMode, sbi};
use osmium::arch::{cpu, irq};
use osmium::boot::fdt::Fdt;
use osmium::drivers::uart16550::{Mmio, Uart16550};
use osmium::hal::console::{Console, SerialConsole, set_console};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::timer::TickRate;
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::Sv39;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sched::timer::TimerQueue;
use osmium::sched::{FifoScheduler, Mutex, TaskBuilder};
use osmium::sync::Once;

core::arch::global_asm!(
    r#"
    .section .text.entry
    .globl _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, boot_stack_top
    la t0, _bss_start
    la t1, _bss_end
1:  bgeu t0, t1, 2f
    sd zero, 0(t0)
    addi t0, t0, 8
    j 1b
2:  call kmain

    .section .bss.stack
    .align 12
    .space 65536
boot_stack_top:
"#
);

unsafe extern "C" {
    static _kernel_start: u8;
    static _etext: u8;
    static _erodata: u8;
    static _kernel_end: u8;
}

fn sym(s: &u8) -> u64 {
    s as *const u8 as u64
}

/// The firmware console, used until the UART driver takes over.
struct SbiConsole;

impl Console for SbiConsole {
    fn write_str(&self, s: &str) {
        for b in s.bytes() {
            if b == b'\n' {
                sbi::console_putchar(b'\r');
            }
            sbi::console_putchar(b);
        }
    }
}

type Frames = LockedFrames<BuddyAllocator<OffsetMapper>, OffsetMapper>;

// SAFETY: the kernel runs identity-mapped (before and after enabling
// paging), so physical address = virtual address for all RAM.
static FRAMES: Frames = unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

static UART: Once<SerialConsole<Uart16550<Mmio>>> = Once::new();
static SCHED: FifoScheduler = FifoScheduler::new(2);
static TIMERS: TimerQueue = TimerQueue::new();
static RATE: Once<TickRate> = Once::new();
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Timer interrupt period.
const TICK_NS: u64 = 10_000_000;

fn now_ns() -> u64 {
    RATE.get().unwrap().ticks_to_ns(cpu::ticks())
}

#[unsafe(no_mangle)]
extern "C" fn kmain(hartid: usize, dtb: usize) -> ! {
    // SAFETY: a single hart runs this kernel; id 0 is unique.
    unsafe { cpu::set_current_id(0) };
    // Before anything can fault: OpenSBI leaves stvec pointing at `_start`.
    trap::init();
    set_console(&SbiConsole);
    println!("\nosmium riscv-virt example (hart {hartid})");

    // --- Device tree -------------------------------------------------------
    // SAFETY: OpenSBI passes a valid DTB that nothing overwrites (we reserve it below).
    let fdt = unsafe { Fdt::from_ptr(dtb as *const u8) }.expect("bad device tree");
    let model = fdt.root().property("model").and_then(|p| p.as_str()).unwrap_or("?");
    println!("[fdt]   {model}, {} bytes, bootargs {:?}", fdt.total_size(), fdt.bootargs().unwrap_or(""));
    let timebase = fdt.find_node("/cpus").and_then(|c| c.property("timebase-frequency")).and_then(|p| p.as_u32());
    RATE.call_once(|| TickRate::new(timebase.unwrap_or(10_000_000) as u64));

    // --- Console on the real UART -----------------------------------------
    let uart_node = fdt.find_compatible(&["ns16550a"]).expect("no UART");
    let (uart_base, uart_len) = uart_node.reg().next().map(|(a, s)| (a, s.unwrap_or(0x100))).unwrap();
    let shift = uart_node.property("reg-shift").and_then(|p| p.as_u32()).unwrap_or(0) as u8;
    // SAFETY: the device tree says the UART's registers live here; nothing else uses them.
    let io = unsafe { IoMem::new(uart_base as *mut u8, uart_len as usize) };
    let mut uart = Uart16550::new(Mmio::new(io, shift));
    uart.init(None);
    set_console(UART.call_once(|| SerialConsole::new(uart)));
    println!("[uart]  ns16550a at {uart_base:#x}, console switched from SBI");

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
    let mut s = String::new();
    for w in ["heap", "works"] {
        s.push_str(w);
        s.push(' ');
    }
    println!("[heap]  {}(sum of squares {}), {:?}", s, squares.iter().sum::<u64>(), HEAP.stats());

    // --- Paging (Sv39, W^X) ------------------------------------------------
    let ram = fdt.memory().next().expect("no memory node");
    let ram_end = ram.0 + ram.1;
    let mut pt: PageTable<Sv39, &'static Frames> = PageTable::new(&FRAMES).unwrap();
    let k = |f| f | MapFlags::GLOBAL;
    let va = |a: u64| VirtAddr::new(a);
    let pa = |a: u64| PhysAddr::new(a);
    // RAM below the kernel holds firmware (PMP-protected, never touched) and
    // free frames the allocator hands out.
    pt.map_range(va(ram.0), pa(ram.0), kstart - ram.0, k(MapFlags::RW)).unwrap();
    pt.map_range(va(kstart), pa(kstart), etext - kstart, k(MapFlags::RX)).unwrap();
    pt.map_range(va(etext), pa(etext), erodata - etext, k(MapFlags::READ)).unwrap();
    pt.map_range(va(erodata), pa(erodata), ram_end - erodata, k(MapFlags::RW)).unwrap();
    let uart_page = uart_base & !(PAGE_SIZE as u64 - 1);
    pt.map_range(va(uart_page), pa(uart_page), PAGE_SIZE as u64, k(MapFlags::RW | MapFlags::DEVICE)).unwrap();
    // SAFETY: the table identity-maps the running code, its stack, the heap and the UART.
    unsafe { riscv64::write_satp(SatpMode::Sv39, 0, pt.root().0) };
    let t = pt.translate(va(kmain as *const () as u64)).unwrap();
    println!("[mmu]   Sv39 on, root {:#x}; kmain mapped {:?} via {:?} page", pt.root().0, t.flags, t.size);
    let t = pt.translate(va(ram_end - 1)).unwrap();
    println!("[mmu]   top of RAM mapped {:?} via {:?} page", t.flags, t.size);
    // The table must outlive the kernel.
    alloc::boxed::Box::leak(alloc::boxed::Box::new(pt));

    // --- Scheduler and timer interrupts -----------------------------------
    osmium::sched::inject_scheduler(&SCHED);
    osmium::sched::init_cpu();
    sbi::set_timer(cpu::ticks() + RATE.get().unwrap().ns_to_ticks(TICK_NS));
    // SAFETY: enabling the supervisor timer interrupt; the trap vector is installed.
    unsafe { riscv64::write_sie(riscv64::SIE_STIE) };
    irq::enable();
    println!("[sched] FIFO scheduler, {} ms tick", TICK_NS / 1_000_000);

    cooperative_demo();
    mutex_demo();
    preemption_demo();
    sleep_demo();

    println!("[done]  {} timer ticks, {} free frames; shutting down", TICKS.load(Ordering::Relaxed), FRAMES.lock().free_frames());
    sbi::shutdown()
}

fn cooperative_demo() {
    let tasks: Vec<_> = ["A", "B", "C"]
        .into_iter()
        .map(|name| {
            TaskBuilder::new(name).spawn(move || {
                for i in 0..2 {
                    println!("[task]  {name}{i}");
                    osmium::sched::yield_now();
                }
            })
        })
        .collect();
    for t in tasks {
        t.join();
    }
}

fn mutex_demo() {
    static COUNTER: Mutex<u64> = Mutex::new(0);
    let tasks: Vec<_> = (0..4)
        .map(|_| {
            TaskBuilder::new("adder").spawn(|| {
                for _ in 0..1000 {
                    let mut g = COUNTER.lock();
                    let v = *g;
                    osmium::sched::yield_now();
                    *g = v + 1;
                }
            })
        })
        .collect();
    for t in tasks {
        t.join();
    }
    println!("[mutex] 4 tasks x 1000 increments across yields = {}", *COUNTER.lock());
}

fn preemption_demo() {
    static FLAG: AtomicBool = AtomicBool::new(false);
    let start = TICKS.load(Ordering::Relaxed);
    // `spinner` never yields. On one CPU, `setter` can only run if the timer
    // interrupt preempts it.
    let spinner = TaskBuilder::new("spinner").spawn(|| {
        while !FLAG.load(Ordering::Acquire) {
            core::hint::spin_loop();
        }
    });
    let setter = TaskBuilder::new("setter").spawn(|| FLAG.store(true, Ordering::Release));
    spinner.join();
    setter.join();
    println!("[preempt] busy-looping task was preempted after {} ticks", TICKS.load(Ordering::Relaxed) - start);
}

fn sleep_demo() {
    let t = TaskBuilder::new("sleeper").spawn(|| {
        let t0 = now_ns();
        TIMERS.sleep_until(t0 + 50_000_000);
        println!("[timer] slept {} ms (asked for 50)", (now_ns() - t0) / 1_000_000);
    });
    t.join();
}

/// Called from the trap handler on every supervisor timer interrupt.
fn on_timer() {
    TICKS.fetch_add(1, Ordering::Relaxed);
    let rate = RATE.get().unwrap();
    sbi::set_timer(cpu::ticks() + rate.ns_to_ticks(TICK_NS));
    TIMERS.process(now_ns());
    osmium::sched::tick();
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    irq::disable();
    // Fall back to the firmware console in case the UART lock is held.
    set_console(&SbiConsole);
    println!("\n[panic] {info}");
    sbi::shutdown()
}
