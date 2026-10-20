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

mod hyp;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use osmium::arch::riscv64::{self, SatpMode, sbi};
use osmium::arch::trap::{self, Interrupt, Trap, TrapFrame};
use osmium::arch::{MAX_CPUS, cpu, irq};
use osmium::boot::fdt::Fdt;
use osmium::drivers::uart16550::{Mmio, Uart16550};
use osmium::drivers::virtio::mmio::MmioTransport;
use osmium::drivers::virtio::net::VirtioNet;
use osmium::drivers::virtio::{DeviceType, Transport};
use osmium::drivers::xhci::Xhci;
use osmium::hal::pci;
use osmium::hal::usb::UsbHost;
use osmium::hal::console::{Console, SerialConsole, set_console};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::timer::TickRate;
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::Sv39;
use osmium::mm::frame::order_for;
use osmium::mm::paging::PageSize;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sched::timer::TimerQueue;
use core::ptr::NonNull;

use osmium::arch::trap::TrapCpu;
use osmium::proc::{AddressSpace, ExitStatus, Process, UserMemory};
use osmium::sched::{FifoScheduler, StackAllocator, Task, TaskBuilder};
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

    # Secondary harts start here (via SBI HSM) with a0 = hart id and
    # a1 = &SecondaryBoot, MMU off.
    .globl secondary_start
secondary_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    ld sp, 0(a1)
    call secondary_main

    .section .bss.stack
    .align 12
    .space 65536
boot_stack_top:
"#
);

// User programs: position-independent U-mode code, copied into user pages.
// System calls use `ecall` with Linux numbering: a7 = number, a0-a2 = args.
core::arch::global_asm!(
    r#"
    .section .rodata.user, "a"
    .globl user_hello, user_hello_end, user_bad, user_bad_end
user_hello:
    li s0, 3
1:  li a7, 64               // write(1, msg, 20)
    li a0, 1
    lla a1, 3f
    li a2, 20
    ecall
    li t0, 20000000         // busy-wait: only the timer can switch us out
2:  addi t0, t0, -1
    bnez t0, 2b
    addi s0, s0, -1
    bnez s0, 1b
    li a7, 93               // exit(0)
    li a0, 0
    ecall
    unimp
3:  .ascii "hello from process ?"
user_hello_end:

user_bad:
    li a7, 64
    li a0, 1
    lla a1, 1f
    li a2, 27
    ecall
    li t0, 0x80200000       // kernel text: not user-accessible
    ld t1, 0(t0)
    unimp
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
pub(crate) static FRAMES: Frames = unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

/// The kernel page table, shared by all harts.
static PT: osmium::sync::IrqSpinLock<Option<PageTable<Sv39, &'static Frames>>> = osmium::sync::IrqSpinLock::new(None);

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
            let pt = pt.as_mut().unwrap();
            let flags = MapFlags::RW | MapFlags::GLOBAL;
            pt.map(VirtAddr::new(guard), PhysAddr::new(guard), PageSize::Size4K, flags).unwrap().flush();
        }
        // SAFETY: the block came from `alloc` with the same order.
        unsafe { FRAMES.lock().dealloc(PhysAddr::new(guard), order_for(len + PAGE_SIZE)) };
    }
}

/// Tells the trap entry where the incoming task's stack ends, so a trap
/// taken below it moves to the exception stack.
fn on_switch(next: &osmium::sched::Task) {
    // Each process runs on its own page table; kernel tasks on the kernel's.
    let root = osmium::proc::root_for(next).map_or(SATP_ROOT.load(Ordering::Relaxed), |r| r.0);
    if riscv64::read_satp() & ((1 << 44) - 1) != (root >> 12) as usize {
        // SAFETY: both kinds of table map the kernel (shared root entries).
        unsafe { riscv64::write_satp(SatpMode::Sv39, 0, root) };
    }
    let cpu = TrapCpu::current();
    cpu.set_stack_limit(next.kernel_stack_range().map_or(0, |r| r.start));
    // Where traps from U-mode land while `next` runs user code.
    cpu.set_kernel_stack(next.kernel_stack_range().map_or(0, |r| r.end));
}

/// Gives this hart an emergency stack for traps from an overflowed stack.
fn set_exception_stack() {
    let stack = alloc::vec![0u8; 16 * 1024].leak();
    let lo = stack.as_ptr() as usize;
    TrapCpu::current().set_exception_stack(lo..lo + stack.len());
}

static UART: Once<SerialConsole<Uart16550<Mmio>>> = Once::new();
static SCHED: FifoScheduler = FifoScheduler::new(2);
static TIMERS: TimerQueue = TimerQueue::new();
static RATE: Once<TickRate> = Once::new();
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Hart id of each logical CPU.
static HARTS: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];
static ONLINE: AtomicUsize = AtomicUsize::new(1);
static SATP_ROOT: AtomicU64 = AtomicU64::new(0);

/// Handed to a secondary hart through `a1`.
#[repr(C)]
struct SecondaryBoot {
    stack_top: u64,
    cpu: usize,
}

/// Timer interrupt period.
const TICK_NS: u64 = 10_000_000;

/// A PCIe host bridge from the device tree: the ECAM window and the 32-bit
/// memory window BARs are assigned from (both as base and length).
struct PcieHost {
    ecam: (u64, u64),
    mem: (u64, u64),
}

fn pcie_host(fdt: &Fdt<'_>) -> Option<PcieHost> {
    let node = fdt.find_compatible(&["pci-host-ecam-generic"])?;
    let (base, len) = node.reg().next()?;
    // Each `ranges` entry: PCI address (3 cells), CPU address (2), size (2).
    let cells: Vec<u32> = node.property("ranges")?.as_u32_cells().collect();
    let mem = cells.as_chunks::<7>().0.iter().find(|r| r[0] >> 24 & 3 == 2).map(|r| {
        let cpu = (r[3] as u64) << 32 | r[4] as u64;
        let size = (r[5] as u64) << 32 | r[6] as u64;
        (cpu, size)
    })?;
    Some(PcieHost { ecam: (base, len?), mem })
}

/// Finds the first xHCI controller, assigns its BARs and enables it; returns
/// its address and BAR 0.
fn find_xhci(host: &PcieHost) -> Option<(pci::Address, u64, u64)> {
    // SAFETY: the device tree puts the ECAM window here, mapped as device
    // memory; only this function uses it.
    let ecam = pci::Ecam::new(unsafe { IoMem::new(host.ecam.0 as *mut u8, host.ecam.1 as usize) }, 0);
    let mut found = None;
    pci::for_each_function(&ecam, 0, |f| {
        if found.is_none() && f.class() == pci::Class::XHCI {
            found = Some(f.address());
        }
    });
    let f = pci::Function::new(&ecam, found?)?;
    // Firmware (OpenSBI) leaves BARs unassigned on this machine.
    pci::BarAllocator::new(host.mem.0, host.mem.1).assign(&f).ok()?;
    let bar = f.bar(0)?;
    f.enable_memory_and_dma();
    Some((f.address(), bar.address, bar.size))
}

/// Base and size of every virtio-mmio slot in the device tree.
fn virtio_slots<'a>(fdt: &Fdt<'a>) -> impl Iterator<Item = (u64, u64)> + 'a {
    fdt.all_nodes()
        .filter(|n| n.compatible().any(|c| c == "virtio,mmio"))
        .filter_map(|n| n.reg().next().map(|(a, s)| (a, s.unwrap_or(0x200))))
}

fn now_ns() -> u64 {
    RATE.get().unwrap().ticks_to_ns(cpu::ticks())
}

#[unsafe(no_mangle)]
extern "C" fn kmain(hartid: usize, dtb: usize) -> ! {
    // SAFETY: the boot hart is logical CPU 0; secondaries get 1, 2, ...
    unsafe { cpu::set_current_id(0) };
    HARTS[0].store(hartid, Ordering::Relaxed);
    // Before anything can fault: OpenSBI leaves stvec pointing at `_start`.
    trap::set_handler(on_trap);
    // SAFETY: we run on a valid kernel stack from here on.
    unsafe { trap::install() };
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
    for (base, _) in virtio_slots(&fdt) {
        let page = base & !(PAGE_SIZE as u64 - 1);
        pt.map_range(va(page), pa(page), PAGE_SIZE as u64, k(MapFlags::RW | MapFlags::DEVICE)).unwrap();
    }
    let pcie = pcie_host(&fdt);
    if let Some(h) = &pcie {
        for (base, len) in [h.ecam, h.mem] {
            pt.map_range(va(base), pa(base), len, k(MapFlags::RW | MapFlags::DEVICE)).unwrap();
        }
    }
    // SAFETY: the table identity-maps the running code, its stack, the heap and the UART.
    unsafe { riscv64::write_satp(SatpMode::Sv39, 0, pt.root().0) };
    SATP_ROOT.store(pt.root().0, Ordering::Release);
    let t = pt.translate(va(kmain as *const () as u64)).unwrap();
    println!("[mmu]   Sv39 on, root {:#x}; kmain mapped {:?} via {:?} page", pt.root().0, t.flags, t.size);
    let t = pt.translate(va(ram_end - 1)).unwrap();
    println!("[mmu]   top of RAM mapped {:?} via {:?} page", t.flags, t.size);
    *PT.lock() = Some(pt);
    set_exception_stack();
    osmium::sched::set_stack_allocator(&GuardedStacks);
    osmium::sched::set_switch_hook(on_switch);
    println!("[guard] task stacks get unmapped guard pages; overflowing traps move to a per-hart exception stack");

    // --- Scheduler and timer interrupts -----------------------------------
    osmium::sched::inject_scheduler(&SCHED);
    osmium::sched::init_cpu();
    sbi::set_timer(cpu::ticks() + RATE.get().unwrap().ns_to_ticks(TICK_NS));
    // SAFETY: enabling timer and software interrupts; the trap vector is installed.
    unsafe { riscv64::write_sie(riscv64::SIE_STIE | riscv64::SIE_SSIE) };
    irq::enable();
    println!("[sched] FIFO scheduler, {} ms tick", TICK_NS / 1_000_000);

    // --- Secondary harts ----------------------------------------------------
    osmium::sched::set_remote_wake_hook(|cpu| {
        let _ = sbi::send_ipi(1, HARTS[cpu].load(Ordering::Relaxed));
    });
    let cpus = fdt.find_node("/cpus").expect("no /cpus");
    let harts = cpus
        .children()
        .filter(|c| c.property("device_type").and_then(|p| p.as_str()) == Some("cpu"))
        .filter(|c| c.property("status").and_then(|p| p.as_str()).is_none_or(|s| s == "okay"))
        .filter_map(|c| c.reg().next().map(|(h, _)| h as usize));
    let mut ncpus = 1;
    for h in harts.filter(|&h| h != hartid) {
        let stack = alloc::vec![0u8; 64 * 1024].leak();
        let boot = alloc::boxed::Box::leak(alloc::boxed::Box::new(SecondaryBoot {
            stack_top: (stack.as_ptr() as u64 + stack.len() as u64) & !15,
            cpu: ncpus,
        }));
        HARTS[ncpus].store(h, Ordering::Relaxed);
        // SAFETY: `secondary_start` sets up gp and the stack from `boot`.
        unsafe { sbi::hart_start(h, secondary_start as *const () as usize, boot as *const _ as usize) }
            .expect("hart_start failed");
        ncpus += 1;
    }
    while ONLINE.load(Ordering::Acquire) < ncpus {
        core::hint::spin_loop();
    }
    println!("[smp]   {ncpus} CPUs online");

    // --- virtio-net ----------------------------------------------------------
    let net = virtio_slots(&fdt).find_map(|(base, len)| {
        // SAFETY: the device tree puts a virtio-mmio slot here, mapped above;
        // nothing else uses it.
        let t = MmioTransport::new(unsafe { IoMem::new(base as *mut u8, len as usize) }).ok()?;
        (t.device_type() == DeviceType::Net).then_some((base, t))
    });
    match net {
        Some((base, t)) => {
            let legacy = if t.is_legacy() { "legacy" } else { "1.x" };
            let mut net = VirtioNet::new(t, &FRAMES).expect("virtio-net init failed");
            println!("[net]   virtio-net ({legacy}) at {base:#x}");
            demos::arp(&mut net, now_ns);
        }
        None => println!("[net]   no virtio-net device"),
    }

    // --- xHCI behind PCIe ------------------------------------------------------
    match pcie.as_ref().and_then(find_xhci) {
        Some((addr, base, len)) => {
            // SAFETY: BAR 0 was just assigned this range inside the mapped
            // window; nothing else uses it.
            let io = unsafe { IoMem::new(base as *mut u8, len as usize) };
            let mut hc = Xhci::new(io, &FRAMES).expect("xHCI init failed");
            hc.no_op().expect("xHCI command ring");
            println!("[usb]   xHCI at {:02x}:{:02x}.{} BAR0 {base:#x}, {} ports", addr.bus, addr.device, addr.function, hc.num_ports());
            demos::usb(&mut hc);
        }
        None => println!("[usb]   no xHCI controller"),
    }

    demos::run_all(&demos::Env { timers: &TIMERS, ticks: &TICKS, now_ns });
    if ncpus > 1 {
        demos::smp(ncpus);
    }
    fault_demo();
    overflow_demo();
    osmium::proc::set_console(Arc::new(demos::user::LogConsole));
    user_demo();
    hyp::demo();
    hyp::demo_irq();

    println!("[done]  {} timer ticks, {} free frames; shutting down", TICKS.load(Ordering::Relaxed), FRAMES.lock().free_frames());
    sbi::shutdown()
}

/// The last synchronous trap that `on_trap` recovered from.
static RECOVERED: osmium::sync::IrqSpinLock<Option<Trap>> = osmium::sync::IrqSpinLock::new(None);
static RECOVER: AtomicBool = AtomicBool::new(false);

fn fault_demo() {
    RECOVER.store(true, Ordering::SeqCst);
    // SAFETY: the handler steps over the breakpoint.
    unsafe { core::arch::asm!("ebreak") };
    println!("[trap]  recovered from {:?}", RECOVERED.lock().take().unwrap());
    // Nothing is mapped at 0x1000: a load page fault.
    // SAFETY: the read faults and the handler skips it; the value is never used.
    let _ = unsafe { core::ptr::read_volatile(0x1000 as *const u64) };
    println!("[trap]  recovered from {:?}", RECOVERED.lock().take().unwrap());
    RECOVER.store(false, Ordering::SeqCst);
}

/// Entry point of secondary harts, on their own stack with the MMU off.
#[unsafe(no_mangle)]
extern "C" fn secondary_main(hartid: usize, boot: &SecondaryBoot) -> ! {
    // SAFETY: each secondary gets a distinct logical id from the boot hart.
    unsafe { cpu::set_current_id(boot.cpu) };
    // SAFETY: we are on the stack the boot hart allocated for us.
    unsafe { trap::install() };
    // SAFETY: the boot hart's table identity-maps everything we touch.
    unsafe { riscv64::write_satp(SatpMode::Sv39, 0, SATP_ROOT.load(Ordering::Acquire)) };
    set_exception_stack();
    osmium::sched::init_cpu();
    sbi::set_timer(cpu::ticks() + RATE.get().unwrap().ns_to_ticks(TICK_NS));
    // SAFETY: as on the boot hart.
    unsafe { riscv64::write_sie(riscv64::SIE_STIE | riscv64::SIE_SSIE) };
    irq::enable();
    println!("[smp]   hart {hartid} online as CPU {}", boot.cpu);
    ONLINE.fetch_add(1, Ordering::Release);
    // This flow of execution has nothing more to do: hand the CPU to the
    // scheduler for good.
    osmium::sched::exit()
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

/// Where every user program is mapped, each in its own address space: 64 GiB
/// (root entry 64), clear of RAM and the PCIe windows, which the kernel
/// shares from root entries 0..64.
const USER_BASE: u64 = 0x10_0000_0000;

/// A process's memory: an Sv39 table sharing the kernel's root entries
/// 0..64, with table and user pages from `FRAMES`.
type Space = AddressSpace<Sv39, &'static Frames>;

fn new_space() -> Space {
    // SAFETY: the kernel table lives for the whole run.
    unsafe { Space::new(&FRAMES, PT.lock().as_ref().unwrap(), 0..64) }.expect("out of memory for a page table")
}

/// Copies a user program into fresh pages, maps it user-accessible (code
/// read/execute, stack read/write) at slot `n`, and spawns a task that drops
/// to U-mode there.
fn spawn_user(name: &'static str, n: u64, code: (&u8, &u8), cpu: usize) -> (Arc<Task>, Weak<Process>) {
    let (start, end) = (code.0 as *const u8, code.1 as *const u8);
    // SAFETY: the linker symbols delimit the program's bytes.
    let mut code = unsafe { core::slice::from_raw_parts(start, end as usize - start as usize) }.to_vec();
    assert!(code.len() <= PAGE_SIZE);
    // Tell this copy which process it is (the '?' in its message).
    if let Some(q) = code.iter().position(|&b| b == b'?') {
        code[q] = b'0' + n as u8;
    }
    let (code_va, stack_va) = (USER_BASE, USER_BASE + 0x8000);
    let space = new_space();
    space.load_flat(code_va, &code, MapFlags::RX).unwrap();
    space.map_anon(stack_va, PAGE_SIZE as u64, MapFlags::RW).unwrap();
    let process = Process::new(name, space, USER_BASE + 0x10000);
    let task = process.spawn(TaskBuilder::new(name).cpu(cpu), move || {
        // The code was written through the identity map, possibly by another
        // hart: make it visible to this hart's instruction fetch.
        // SAFETY: fence.i only synchronizes this hart's instruction stream.
        unsafe { core::arch::asm!("fence.i") };
        // SAFETY: traps are installed, the switch hook keeps TrapCpu's kernel
        // stack on this task, and both pages are mapped user-accessible.
        unsafe { riscv64::enter_user(code_va as usize, (stack_va as usize) + PAGE_SIZE) }
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
    let stack_top: u64 = 0x11_0000_0000;
    space.map_anon(stack_top - PAGE_SIZE as u64, PAGE_SIZE as u64, MapFlags::RW).unwrap();
    let entry = elf.entry();
    let process = Process::new(name, space, brk);
    process.set_mmap_area(0x12_0000_0000..0x13_0000_0000);
    let task = process.spawn(TaskBuilder::new(name).cpu(cpu), move || {
        // SAFETY: the code was written through the identity map; make it
        // visible to this hart's instruction fetch.
        unsafe { core::arch::asm!("fence.i") };
        // SAFETY: traps are installed, the switch hook installs this
        // process's table and kernel stack, and its pages are mapped.
        unsafe { riscv64::enter_user(entry as usize, stack_top as usize) }
    });
    (task, Arc::downgrade(&process))
}

fn user_demo() {
    // SAFETY: linker symbols delimiting the user programs.
    let (hello, bad) = unsafe { ((&user_hello, &user_hello_end), (&user_bad, &user_bad_end)) };
    // Run them on another hart (when there is one): user code owns `tp`, so
    // traps from U-mode must restore the kernel's CPU id, and a wrong id
    // would only go unnoticed on CPU 0.
    let cpu = 1 % ONLINE.load(Ordering::Acquire);
    let spawned = [
        spawn_user("user-1", 1, hello, cpu),
        spawn_user("user-2", 2, hello, cpu),
        spawn_user("user-bad", 3, bad, cpu),
        spawn_elf("user-elf", HELLO_ELF, cpu),
    ];
    println!("[user]  running 3 U-mode programs on CPU {cpu}");
    println!("[user]  each program has its own page table; all run at {USER_BASE:#x}");
    let mut processes = Vec::new();
    for (task, process) in spawned {
        task.join();
        processes.push(process);
    }
    // Exited tasks (and their address spaces) are freed after the next switch.
    osmium::sched::yield_now();
    let freed = processes.iter().filter(|p| p.strong_count() == 0).count();
    println!("[user]  {freed} of 4 address spaces torn down with their tasks");
}

/// Handles `ecall` from U-mode.
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
                osmium::proc::exit(ExitStatus::Signal(11));
            }
        }
    }
    if TrapCpu::current().overflowed(frame) {
        // This frame lives on the exception stack; the task's own stack is
        // exhausted, so it cannot continue. End only that task.
        let task = osmium::sched::current();
        println!("[guard] task {:?} overflowed its stack ({:?} at sp {:#x}); killed", task.name(), frame.cause(), frame.sp());
        // A trap taken while on the exception stack must nest there, not be
        // mistaken for another overflow.
        RECOVER.store(true, Ordering::SeqCst);
        // SAFETY: the breakpoint arm below steps over it.
        unsafe { core::arch::asm!("ebreak") };
        RECOVER.store(false, Ordering::SeqCst);
        println!("[guard] nested {:?} on the exception stack handled", RECOVERED.lock().take().unwrap());
        drop(task);
        osmium::sched::exit();
    }
    match frame.cause() {
        Trap::Interrupt(Interrupt::Software) => {
            // An IPI: new work was queued here. Clear it; the idle loop or
            // the next preemption point picks the work up.
            // SAFETY: clears only SSIP.
            unsafe { riscv64::write_sip(riscv64::read_sip() & !riscv64::SIE_SSIE) };
            osmium::sched::preempt_if_needed();
        }
        cause @ (Trap::Breakpoint | Trap::PageFault { .. }) if RECOVER.load(Ordering::SeqCst) => {
            *RECOVERED.lock() = Some(cause);
            // Step over the instruction: 2 bytes if compressed, else 4.
            // SAFETY: the faulting instruction is mapped executable code.
            let insn = unsafe { (frame.pc() as *const u16).read() };
            frame.set_pc(frame.pc() + if insn & 3 == 3 { 4 } else { 2 });
        }
        Trap::Interrupt(Interrupt::Timer) => {
            on_timer();
            // Leaving an interrupt is a preemption point.
            osmium::sched::preempt_if_needed();
        }
        cause => panic!("unhandled trap {cause:?} at pc {:#x}", frame.pc()),
    }
}

/// Called on every supervisor timer interrupt.
fn on_timer() {
    if cpu::current_id() == 0 {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }
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
