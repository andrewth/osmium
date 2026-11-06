// SPDX-License-Identifier: GPL-2.0-only
//! A small kernel for QEMU's AArch64 `virt` machine (GICv2 or GICv3), built entirely
//! from Osmium components. QEMU starts ELF kernels at EL1 with the MMU off
//! and the device tree at the base of RAM.
//!
//! The same steps as the RISC-V example, on different hardware: PL011 UART,
//! GICv2 or GICv3 interrupt controller (probed from the device tree), generic timer, AArch64 stage-1 paging and
//! PSCI for power-off. What every example kernel does the same way lives in
//! the `demos` crate.
#![no_std]
#![no_main]

extern crate alloc;

mod iommu;
mod its;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use demos::guest::image;
use demos::kernel::{FRAMES, Frames, GuardedStacks, KernelTable, now_ns};
use osmium::arch::aarch64::{self, psci};
use osmium::arch::trap::{self, Interrupt, Trap, TrapFrame};
use osmium::arch::{cpu, irq, mmu};
use osmium::boot::fdt::Fdt;
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::irq::{InterruptController, IrqTable, MAX_CLAIMS_PER_CALL};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::timer::TickRate;
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::PageSize;
use osmium::mm::paging::formats::Aarch64;
use osmium::mm::{MapFlags, MemoryMap, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::proc::ExitStatus;
use osmium::sysdrv::gicv2::GicV2;
use osmium::sysdrv::gicv3::{FIRST_LPI, GicV3, SysRegs};
use osmium::sysdrv::pl011::Pl011;

use osmium::arch::trap::TrapCpu;
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

    // Secondary CPUs start here (via PSCI CPU_ON) at EL1 with the MMU off
    // and x0 = &SecondaryBoot.
    .globl secondary_start
secondary_start:
    ldr x1, [x0]
    mov sp, x1
    bl secondary_main
    b 3b

    // The boot stack, above a guard page that kmain unmaps once the MMU is
    // on, so an overflow faults instead of overwriting .data below.
    .section .bss.stack, "aw", @nobits
    .balign 4096
    .globl boot_stack_guard
boot_stack_guard:
    .space 4096
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
    static boot_stack_guard: u8;
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
/// Bytes of a secondary CPU's boot stack.
const SECONDARY_STACK: usize = 64 * 1024;

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

/// The kernel page table, shared by all CPUs.
static PT: KernelTable<Aarch64> = IrqSpinLock::new(None);

/// Task stacks and secondary CPUs' stacks, each above an unmapped guard
/// page. TLB maintenance on this table is broadcast to the inner shareable
/// domain, so no other CPU needs telling.
static STACKS: GuardedStacks<Aarch64> = GuardedStacks::new(&PT, |_| {});

/// Tells the exception vectors where the incoming task's stack ends.
fn on_switch(next: &osmium::sched::Task) {
    // Each process runs on its own TTBR0 table; kernel tasks on the kernel's.
    let kernel = osmium::mm::PhysAddr::new(TTBR0.load(Ordering::Relaxed));
    let root = osmium::proc::switch_root(next, kernel).0;
    if aarch64::read_ttbr0_el1() & 0x0000_ffff_ffff_f000 != root {
        // SAFETY: both kinds of table map the kernel (shared root entry 0).
        unsafe { aarch64::write_ttbr0_el1(root) };
        osmium::arch::mmu::flush_all();
    }
    TrapCpu::current().set_stack_limit(demos::kernel::stack_limit(next));
}

static UART: Once<SerialConsole<Pl011>> = Once::new();
static GIC: Once<Gic> = Once::new();

/// The interrupt controller the device tree describes.
#[allow(clippy::large_enum_variant, reason = "one static value: boxing buys nothing")]
enum Gic {
    V2(GicV2),
    V3(GicV3<SysRegs>),
}

impl Gic {
    fn init_cpu(&self) {
        match self {
            Gic::V2(g) => g.init_cpu(),
            Gic::V3(g) => {
                if !g.init_cpu() {
                    println!("[gic]   GICv3 CPU interface {} failed to come up", cpu::current_id());
                }
            }
        }
    }

    fn num_irqs(&self) -> u32 {
        match self {
            Gic::V2(g) => g.num_irqs(),
            Gic::V3(g) => g.num_irqs(),
        }
    }

    fn send_sgi(&self, cpu: usize, sgi: u32) {
        match self {
            Gic::V2(g) => g.send_sgi(1 << cpu, sgi),
            Gic::V3(g) => {
                g.send_sgi(1 << cpu, sgi);
            }
        }
    }
}

impl InterruptController for Gic {
    fn enable(&self, irq: u32) {
        match self {
            Gic::V2(g) => g.enable(irq),
            Gic::V3(g) => g.enable(irq),
        }
    }
    fn set_target(&self, irq: u32, cpu: usize) -> bool {
        match self {
            Gic::V2(g) => g.set_target(irq, cpu),
            Gic::V3(g) => g.set_target(irq, cpu),
        }
    }
    fn disable(&self, irq: u32) {
        match self {
            Gic::V2(g) => g.disable(irq),
            Gic::V3(g) => g.disable(irq),
        }
    }
    fn claim(&self) -> Option<u32> {
        match self {
            Gic::V2(g) => g.claim(),
            Gic::V3(g) => g.claim(),
        }
    }
    fn complete(&self, irq: u32) {
        match self {
            Gic::V2(g) => g.complete(irq),
            Gic::V3(g) => g.complete(irq),
        }
    }
    fn set_priority(&self, irq: u32, priority: u8) {
        match self {
            Gic::V2(g) => g.set_priority(irq, priority),
            Gic::V3(g) => g.set_priority(irq, priority),
        }
    }
}
static IRQS: IrqTable<256> = IrqTable::new();
/// LPI handlers, indexed by interrupt ID minus [`FIRST_LPI`].
static LPIS: IrqTable<64> = IrqTable::new();

/// Claims and dispatches pending interrupts: lines through [`IRQS`], LPIs
/// through [`LPIS`].
fn handle_irqs(gic: &Gic) {
    for _ in 0..MAX_CLAIMS_PER_CALL {
        let Some(irq) = gic.claim() else { break };
        match irq.checked_sub(FIRST_LPI) {
            Some(lpi) => LPIS.dispatch(lpi),
            None => IRQS.dispatch(irq),
        };
        gic.complete(irq);
    }
}
static SCHED: FifoScheduler = FifoScheduler::new(2).with_stealing();
static TIMERS: TimerQueue = TimerQueue::new();
static TICKS: AtomicU64 = AtomicU64::new(0);
static PSCI: Once<psci::Conduit> = Once::new();
static TTBR0: AtomicU64 = AtomicU64::new(0);
static VTIMER_IRQ: AtomicU32 = AtomicU32::new(0);
static IPIS: AtomicU64 = AtomicU64::new(0);
/// SGI used to wake other CPUs.
const IPI_SGI: u32 = 1;

/// Handed to a secondary CPU through `x0`.
#[repr(C)]
struct SecondaryBoot {
    /// Read first, by `secondary_start`.
    stack_top: u64,
    cpu: usize,
    /// The lowest address of the stack, above its guard page.
    stack_limit: u64,
}

fn shutdown() -> ! {
    psci::system_off(*PSCI.get().unwrap_or(&psci::Conduit::Hvc))
}

/// Says why the kernel cannot boot, and powers off.
fn fatal(why: &str) -> ! {
    println!("[boot]  {why}; shutting down");
    shutdown()
}

/// When the CPU has SVE (QEMU `-cpu max`, not the default Cortex-A72), checks
/// that `SveState` keeps all of `z0`: two patterns are captured and restored
/// in turn. Leaves SVE enabled; the kernel never uses it.
fn sve_selftest(model: &str) {
    use osmium::arch::fp::{SveState, sve};
    // `aarch64-hyp` traps SVE (CPTR_EL2.TZ) and does not switch it between
    // vCPUs, so its guests must leave it alone.
    if model.starts_with("osmium") {
        println!("[fp]    no SVE: tasks keep q0-q31 only");
        return;
    }
    // SAFETY: the kernel is soft-float and never touches SVE registers.
    let Some(vl) = (unsafe { sve::enable() }) else {
        println!("[fp]    no SVE: tasks keep q0-q31 only");
        return;
    };
    let mut buf = alloc::vec![0u8; 3 * vl];
    let (a, rest) = buf.split_at_mut(vl);
    let (b, out) = rest.split_at_mut(vl);
    for (i, (x, y)) in a.iter_mut().zip(b.iter_mut()).enumerate() {
        *x = i as u8 + 1;
        *y = 0xf0 - i as u8;
    }
    let mut sa = alloc::boxed::Box::new(SveState::new());
    let mut sb = alloc::boxed::Box::new(SveState::new());
    let mut ok = true;
    irq::without(|| {
        // SAFETY: SVE is on (above); `a` and `b` hold `vl` bytes, which is
        // what `ldr z0` / `str z0` move, and z0 is declared clobbered.
        unsafe {
            core::arch::asm!(".arch_extension sve", "ldr z0, [{}]", in(reg) a.as_ptr(), out("v0") _);
            sa.save();
            core::arch::asm!(".arch_extension sve", "ldr z0, [{}]", in(reg) b.as_ptr(), out("v0") _);
            sb.save();
            sa.restore();
            core::arch::asm!(".arch_extension sve", "str z0, [{}]", in(reg) out.as_mut_ptr(), out("v0") _);
        }
        ok &= out == a;
        // SAFETY: as above.
        unsafe {
            sb.restore();
            core::arch::asm!(".arch_extension sve", "str z0, [{}]", in(reg) out.as_mut_ptr(), out("v0") _);
        }
        ok &= out == b;
    });
    println!(
        "[fp]    SVE {} bit vectors: z0 kept across SveState save/restore: {}",
        vl * 8,
        if ok { "ok" } else { "FAILED" }
    );
}

/// A register window: base and length.
type Window = (u64, u64);

/// The interrupt controller's two register windows from the device tree:
/// the distributor, then the CPU interface (GICv2) or the redistributors
/// (GICv3); and whether it is a GICv3.
fn gic_windows(fdt: &Fdt<'_>) -> Option<(Window, Window, bool)> {
    let v3_node = fdt.find_compatible(&["arm,gic-v3"]);
    let node = v3_node.or_else(|| fdt.find_compatible(&["arm,cortex-a15-gic", "arm,gic-400"]))?;
    let mut regs = node.reg();
    let (d, d_len) = regs.next()?;
    let (c, c_len) = regs.next()?;
    Some(((d, d_len?), (c, c_len?), v3_node.is_some()))
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
    let Ok(mut uart) = Pl011::new(unsafe { IoMem::new(EARLY_UART as *mut u8, 0x1000) }) else { shutdown() };
    uart.init(None);
    set_console(UART.call_once(|| SerialConsole::new(uart)));
    println!("\nosmium aarch64-virt example (EL{})", aarch64::current_el());

    // --- Device tree -------------------------------------------------------
    // QEMU passes the device tree in x0 only for Linux images.
    let dtb = if x0 != 0 { x0 } else { RAM_BASE_DTB };
    // SAFETY: QEMU places a valid device tree there; we reserve it below.
    let Ok(fdt) = (unsafe { Fdt::from_ptr(dtb as *const u8) }) else { fatal("no device tree") };
    let model = fdt.root().property("model").and_then(|p| p.as_str()).unwrap_or("?");
    println!("[fdt]   {model}, {} bytes at {dtb:#x}", fdt.total_size());
    let Some((uart_base, _)) = fdt.find_compatible(&["arm,pl011"]).and_then(|n| n.reg().next()) else {
        fatal("no PL011 in the device tree")
    };
    println!("[uart]  pl011 at {uart_base:#x} (confirmed by the device tree)");
    let conduit = fdt
        .find_node("/psci")
        .and_then(|n| n.property("method"))
        .and_then(|p| p.as_str())
        .and_then(psci::Conduit::from_method)
        .unwrap_or(psci::Conduit::Hvc);
    PSCI.call_once(|| conduit);
    demos::kernel::set_rate(TickRate::new(aarch64::counter_frequency()));

    // --- Interrupt controller and timer line ------------------------------
    let Some(((gicd, gicd_len), (gicc, gicc_len), is_v3)) = gic_windows(&fdt) else {
        fatal("no GIC (with sized register windows) in the device tree")
    };
    // The virtual timer is the third `interrupts` triple: (PPI, number, flags).
    // (No heap yet, so no collecting into a Vec.)
    let Some(vtimer) = fdt.find_compatible(&["arm,armv8-timer"]).and_then(|t| t.interrupts().nth(2 * 3 + 1)) else {
        fatal("no virtual timer interrupt in the device tree")
    };
    let vtimer_irq = 16 + vtimer;
    println!(
        "[gic]   GICv{} distributor {gicd:#x}, {} {gicc:#x}; virtual timer is INTID {vtimer_irq}; PSCI via {conduit:?}",
        if is_v3 { 3 } else { 2 },
        if is_v3 { "redistributors" } else { "cpu interface" }
    );

    // --- Physical memory ---------------------------------------------------
    let mut map = MemoryMap::<32>::new();
    if fdt.fill_memory_map(&mut map, Some(PhysAddr::new(dtb as u64))).is_err() {
        fatal("the device tree's memory map does not fit");
    }
    // SAFETY: linker-provided symbols.
    let (kstart, etext, erodata, kend) =
        unsafe { (sym(&_kernel_start), sym(&_etext), sym(&_erodata), sym(&_kernel_end)) };
    if map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).is_err() {
        fatal("cannot reserve the kernel image");
    }
    map.page_align_usable();
    for r in map.regions() {
        println!("[mem]   {:#011x}..{:#011x} {:?}", r.start.0, r.end.0, r.kind);
    }
    // SAFETY: the memory map says these ranges are free RAM, identity-mapped.
    unsafe { demos::kernel::add_ram(map.usable().map(|r| r.start..r.end)) };
    demos::kernel::report_frames();

    // --- Heap ------------------------------------------------------------
    HEAP.init(&FRAMES);
    let squares: Vec<u64> = (0..1000).map(|i| i * i).collect();
    let s: String = ["heap", "works"].join(" ");
    println!("[heap]  {s} (sum of squares {})", squares.iter().sum::<u64>());
    sve_selftest(model);

    // --- Paging (stage 1, 4 KiB granule, W^X) ------------------------------
    // The kernel's own memory node is mapped piecewise below (W^X); any
    // other node, all of which the frame allocator was given, as RW.
    let Some(ram) = fdt.memory().find(|&(base, len)| (base..base + len).contains(&kstart)) else {
        fatal("no memory node holds the kernel")
    };
    let ram_end = ram.0 + ram.1;
    let Ok(mut pt) = PageTable::<Aarch64, &'static Frames>::new(&FRAMES) else { fatal("no memory for a page table") };
    let k = |f| f | MapFlags::GLOBAL;
    let va = |a: u64| VirtAddr::new(a);
    let pa = |a: u64| PhysAddr::new(a);
    // Read/write RAM uses 4 KiB pages from the start: unmapping a task
    // stack's guard page must not split a live block, which on AArch64
    // needs break-before-make and would briefly unmap 2 MiB under other
    // CPUs.
    let map_4k = |pt: &mut PageTable<Aarch64, &'static Frames>, start: u64, len: u64| {
        (start..start + len).step_by(PAGE_SIZE).all(|p| pt.map(va(p), pa(p), PageSize::Size4K, k(MapFlags::RW)).is_ok())
    };
    let mapped = map_4k(&mut pt, ram.0, kstart - ram.0)
        && pt.map_range(va(kstart), pa(kstart), etext - kstart, k(MapFlags::RX)).is_ok()
        && pt.map_range(va(etext), pa(etext), erodata - etext, k(MapFlags::READ)).is_ok()
        && map_4k(&mut pt, erodata, ram_end - erodata)
        && fdt.memory().filter(|&m| m != ram).all(|(base, len)| {
            let (start, end) = (base.next_multiple_of(PAGE_SIZE as u64), (base + len) & !(PAGE_SIZE as u64 - 1));
            start >= end || map_4k(&mut pt, start, end - start)
        });
    if !mapped {
        fatal("cannot map the kernel and RAM");
    }
    for (base, len) in [(EARLY_UART as u64, PAGE_SIZE as u64), (gicd, gicd_len), (gicc, gicc_len)] {
        demos::kernel::map_device(&mut pt, base, len);
    }
    enable_mmu(pt.root());
    TTBR0.store(pt.root().0, Ordering::Release);
    // The page below the boot stack becomes its guard (see `_start`).
    // SAFETY: a linker symbol.
    let guard = unsafe { sym(&boot_stack_guard) };
    if demos::kernel::unmap_guard(&mut pt, guard) {
        let bottom = guard as usize + PAGE_SIZE;
        demos::kernel::set_boot_stack_limit(bottom);
        TrapCpu::current().set_stack_limit(bottom);
    }
    if let Some(t) = pt.translate(va(kmain as *const () as u64)) {
        println!("[mmu]   MMU on, TTBR0 {:#x}; kmain mapped {:?} via {:?} page", pt.root().0, t.flags, t.size);
    }
    *PT.lock() = Some(pt);
    demos::fault::set_exception_stack();
    osmium::sched::set_stack_allocator(&STACKS);
    osmium::sched::set_switch_hook(on_switch);
    println!(
        "[guard] boot, CPU and task stacks get unmapped guard pages; overflowing exceptions move to a per-CPU \
         exception stack"
    );

    // --- Interrupts, scheduler ---------------------------------------------
    // SAFETY: the device tree says the GIC lives here, mapped as device memory above.
    let gic = GIC.call_once(|| unsafe {
        let (d, c) = (IoMem::new(gicd as *mut u8, gicd_len as usize), IoMem::new(gicc as *mut u8, gicc_len as usize));
        if is_v3 { Gic::V3(GicV3::new(d, c, SysRegs::new())) } else { Gic::V2(GicV2::new(d, c)) }
    });
    match gic {
        Gic::V2(g) => g.init_distributor(),
        Gic::V3(g) => g.init_distributor(),
    }
    VTIMER_IRQ.store(vtimer_irq, Ordering::Relaxed);
    let counted_ipi = &|_| {
        IPIS.fetch_add(1, Ordering::Relaxed);
    };
    if IRQS.register(vtimer_irq, &on_timer).is_err() || IRQS.register(IPI_SGI, counted_ipi).is_err() {
        fatal("cannot register the timer and IPI handlers");
    }

    osmium::sched::inject_scheduler(&SCHED);
    osmium::sched::init_cpu();
    start_local_interrupts();
    println!("[sched] FIFO scheduler, {} ms tick, {} lines on the GIC", TICK_NS / 1_000_000, gic.num_irqs());

    // --- Secondary CPUs -----------------------------------------------------
    osmium::sched::set_remote_wake_hook(|cpu| {
        if let Some(gic) = GIC.get() {
            gic.send_sgi(cpu, IPI_SGI);
        }
    });
    let boot_mpidr = aarch64::read_mpidr_el1() & 0xff_00ff_ffff;
    let mpidrs = fdt
        .find_node("/cpus")
        .into_iter()
        .flat_map(|cpus| cpus.children())
        .filter(|c| c.property("device_type").and_then(|p| p.as_str()) == Some("cpu"))
        .filter_map(|c| c.reg().next().map(|(m, _)| m));
    let mut ncpus = 1;
    for (cpu, mpidr) in demos::kernel::secondaries(mpidrs, boot_mpidr) {
        // Above a guard page, which takes effect once the CPU turns its MMU on.
        let Some(stack) = STACKS.leak(SECONDARY_STACK) else {
            println!("[smp]   no memory for CPU {mpidr:#x}'s stack; continuing with {ncpus} CPUs");
            break;
        };
        let boot = alloc::boxed::Box::leak(alloc::boxed::Box::new(SecondaryBoot {
            stack_top: stack.end,
            cpu,
            stack_limit: stack.start,
        }));
        if let Gic::V3(g) = gic {
            // SGIs are addressed by affinity, so the boot CPU maps the new CPU first.
            g.register_cpu(cpu, mpidr);
        }
        // SAFETY: `secondary_start` sets up its stack from `boot`.
        let rc = unsafe { psci::cpu_on(conduit, mpidr, secondary_start as *const () as u64, boot as *const _ as u64) };
        // One CPU at a time: one that fails to start or never checks in
        // ends the bring-up, so CPU indices stay dense.
        if rc != 0 {
            println!("[smp]   PSCI CPU_ON {mpidr:#x} failed ({rc}); continuing with {ncpus} CPUs");
            break;
        }
        if !demos::kernel::wait_online(cpu + 1) {
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
    demos::fault::fault_demo();
    demos::fault::overflow_demo();
    demos::user::boot_vfs();
    user_demo();
    iommu::demo(&fdt);
    its::demo(&fdt);

    println!(
        "[done]  {} timer ticks, {} IPIs, {} free frames; shutting down",
        TICKS.load(Ordering::Relaxed),
        IPIS.load(Ordering::Relaxed),
        demos::kernel::free_frames()
    );
    shutdown()
}

/// Per-CPU interrupt setup: GIC CPU interface, banked timer and IPI lines,
/// the generic timer, and the CPU's interrupt mask.
fn start_local_interrupts() {
    let Some(gic) = GIC.get() else { return };
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
    // The MMU is on, so the guard page below this stack is in force.
    demos::kernel::set_boot_stack_limit(boot.stack_limit as usize);
    TrapCpu::current().set_stack_limit(boot.stack_limit as usize);
    demos::fault::set_exception_stack();
    osmium::sched::init_cpu();
    start_local_interrupts();
    println!("[smp]   MPIDR {:#x} online as CPU {}", aarch64::read_mpidr_el1() & 0xff_ffff, boot.cpu);
    demos::kernel::check_in();
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
    let Some(rate) = demos::kernel::rate() else { return };
    // SAFETY: reprograms only the virtual timer's countdown.
    unsafe { aarch64::write_cntv_tval_el0(rate.ns_to_ticks(TICK_NS)) };
}

fn on_timer(_irq: u32) {
    if cpu::current_id() == 0 {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }
    arm_timer();
    TIMERS.process(now_ns());
    osmium::sched::tick();
}

/// Drops to EL0 at `pc` with stack pointer `sp`, taking exceptions from EL0
/// on this task's kernel stack.
///
/// # Safety
/// See [`demos::user::Enter`].
unsafe fn enter_user(pc: u64, sp: u64) -> ! {
    let Some(stack) = osmium::sched::current().kernel_stack_range() else {
        println!("[user]  {} has no kernel stack of its own", osmium::sched::current().name());
        osmium::proc::exit(ExitStatus::Code(127))
    };
    // SAFETY: the caller's contract; vectors are installed and `stack` is
    // this task's own kernel stack.
    unsafe { aarch64::enter_user(pc, sp, stack.end as u64) }
}

/// What `fork` and `execve` need: spaces sharing the kernel's root entry 0,
/// laid out as `demos::user` says. osmium-proc makes loaded and copied code
/// visible to instruction fetch.
fn platform() -> osmium::proc::Platform {
    demos::user::platform(
        || demos::user::new_space(&PT),
        |root| {
            // SAFETY: the table shares the kernel's root entry 0.
            unsafe { aarch64::write_ttbr0_el1(root.0) };
            osmium::arch::mmu::flush_all();
        },
        |frame| {
            let Some(stack) = osmium::sched::current().kernel_stack_range() else {
                osmium::proc::exit(ExitStatus::Code(127))
            };
            // SAFETY: the child's task is running with its table active (the
            // switch hook); the frame, its parent's from an svc, is on this
            // task's stack.
            unsafe { aarch64::resume_user(&frame, stack.end as u64) }
        },
    )
}

/// The user demos: the hand-written EL0 programs, then the Rust ones.
fn user_demo() {
    osmium::proc::set_platform(platform());
    // SAFETY: linker symbols delimiting the user programs in .rodata.
    let (hello, bad) = unsafe { (image(&user_hello, &user_hello_end), image(&user_bad, &user_bad_end)) };
    demos::user::demo(&platform(), hello, bad, "EL0", enter_user);
}

/// Runs the trap handler, then, before returning to user mode from an
/// interrupt, delivers pending signals (and stops threads of a process that
/// is ending).
fn on_trap(frame: &mut TrapFrame) {
    handle_trap(frame);
    demos::user::before_return(frame);
}

fn handle_trap(frame: &mut TrapFrame) {
    if frame.from_user() && demos::user::handle(frame) {
        return;
    }
    demos::fault::on_overflow(frame);
    match frame.cause() {
        Trap::Interrupt(Interrupt::External) => {
            if let Some(gic) = GIC.get() {
                handle_irqs(gic);
            }
            // Leaving an interrupt is a preemption point.
            osmium::sched::preempt_if_needed();
        }
        Trap::Breakpoint | Trap::PageFault { .. } if demos::fault::recovered(frame) => {}
        cause => unhandled(frame, cause),
    }
}

/// A kernel exception with no handler: a bug in this kernel, so stop it.
#[allow(clippy::panic)] // a kernel exception nothing handles leaves no safe way on
fn unhandled(frame: &TrapFrame, cause: Trap) -> ! {
    panic!("unhandled trap {cause:?} at pc {:#x}, ESR {:#x}", frame.pc(), frame.esr)
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
