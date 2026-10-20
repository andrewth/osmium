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
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sched::FifoScheduler;
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

    .section .bss.stack, "aw", @nobits
    .balign 4096
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

static UART: Once<SerialConsole<Pl011>> = Once::new();
static GIC: Once<GicV2> = Once::new();
static IRQS: IrqTable<256> = IrqTable::new();
static SCHED: FifoScheduler = FifoScheduler::new(2);
static TIMERS: TimerQueue = TimerQueue::new();
static RATE: Once<TickRate> = Once::new();
static TICKS: AtomicU64 = AtomicU64::new(0);
static PSCI: Once<psci::Conduit> = Once::new();

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
    let t = pt.translate(va(kmain as *const () as u64)).unwrap();
    println!("[mmu]   MMU on, TTBR0 {:#x}; kmain mapped {:?} via {:?} page", pt.root().0, t.flags, t.size);
    // The table must outlive the kernel.
    alloc::boxed::Box::leak(alloc::boxed::Box::new(pt));

    // --- Interrupts, scheduler ---------------------------------------------
    // SAFETY: the device tree says the GIC lives here, mapped as device memory above.
    let gic = GIC.call_once(|| unsafe {
        GicV2::new(IoMem::new(gicd as *mut u8, gicd_len as usize), IoMem::new(gicc as *mut u8, gicc_len as usize))
    });
    gic.init_distributor();
    gic.init_cpu();
    IRQS.register(vtimer_irq, &on_timer).unwrap();
    gic.set_priority(vtimer_irq, 0x80);
    gic.enable(vtimer_irq);

    osmium::sched::inject_scheduler(&SCHED);
    osmium::sched::init_cpu();
    arm_timer();
    // SAFETY: enables the virtual timer; the GIC routes it to us.
    unsafe { aarch64::write_cntv_ctl_el0(1) };
    irq::enable();
    println!("[sched] FIFO scheduler, {} ms tick, {} lines on the GIC", TICK_NS / 1_000_000, gic.num_irqs());

    demos::run_all(&demos::Env { timers: &TIMERS, ticks: &TICKS, now_ns });
    fault_demo();

    println!("[done]  {} timer ticks, {} free frames; shutting down", TICKS.load(Ordering::Relaxed), FRAMES.lock().free_frames());
    shutdown()
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
    TICKS.fetch_add(1, Ordering::Relaxed);
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

fn on_trap(frame: &mut TrapFrame) {
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
