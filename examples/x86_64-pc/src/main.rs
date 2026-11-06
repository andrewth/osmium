// SPDX-License-Identifier: GPL-2.0-only
//! A small kernel for QEMU's x86_64 PC (q35), built entirely from Osmium
//! components. QEMU loads the ELF directly through the PVH boot protocol and
//! enters `pvh_start` in 32-bit protected mode with `ebx` pointing at the
//! start-info structure.
//!
//! The same steps as the RISC-V and AArch64 examples, on PC hardware: COM1
//! 16550 UART, local APIC timer calibrated against the PIT, x86_64 4-level
//! paging, and the IDT from `osmium_arch::trap`.
#![no_std]
#![no_main]

extern crate alloc;

mod aml;
mod iommu;
mod msi;
mod usb;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use demos::guest::image;
pub(crate) use demos::kernel::{FRAMES, Frames, now_ns};
use demos::kernel::{GuardedStacks, KernelTable};
use osmium::arch::trap::{self, Trap, TrapFrame};
use osmium::arch::x86_64 as x86;
use osmium::arch::{MAX_CPUS, cpu, irq};
use osmium::boot::acpi::{Acpi, Dmar, EcamWindow, HpetTable, Ivrs, Madt, Mcfg};
use osmium::boot::pvh::StartInfo;
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::display::{Display, FramebufferInfo};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::timer::{Clock, TickRate};
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::X86_64;
use osmium::mm::{MapFlags, MemoryMap, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sysdrv::hpet::{self, Hpet};
use osmium::sysdrv::lapic::{self, LocalApic};
use osmium::sysdrv::pit::{self, Pit};
use osmium::sysdrv::uart16550::{Pio, Uart16550};

use osmium::sched::FifoScheduler;
use osmium::sched::timer::TimerQueue;
use osmium::sync::{IrqSpinLock, Once};

osmium::boot::pvh_start!(kmain, ap: ap_main);

// User programs: position-independent ring-3 code, copied into user pages.
// System calls: rax = number, rdi/rsi/rdx = arguments. `user_hello` enters
// with `syscall`, `user_bad` with `int 0x80`; the kernel sees the same frame.
core::arch::global_asm!(
    r#"
    .section .rodata.user, "a"
    .globl user_hello, user_hello_end, user_bad, user_bad_end
user_hello:
    mov $3, %ebx
1:  lea 3f(%rip), %rsi
    mov $(4f - 3f), %edx
    mov $1, %edi
    mov $1, %eax              // write(1, msg, len), via the syscall instruction
    syscall
    mov $20000000, %ecx       // busy-wait without yielding: only the timer
2:  dec %ecx                  // can switch us out
    jnz 2b
    dec %ebx
    jnz 1b
    mov $60, %eax             // exit(0)
    xor %edi, %edi
    syscall
    ud2
3:  .ascii "hello from process ?"
4:
user_hello_end:

user_bad:
    mov $1, %eax
    lea 1f(%rip), %rsi
    mov $(2f - 1f), %edx
    mov $1, %edi
    int $0x80
    mov 0x200000, %rax        // read kernel text: not user-accessible
    ud2
1:  .ascii "about to read kernel memory"
2:
user_bad_end:
"#,
    options(att_syntax)
);

unsafe extern "C" {
    static user_hello: u8;
    static user_hello_end: u8;
    static user_bad: u8;
    static user_bad_end: u8;
    static boot_pml4: u8;
    fn ap_start64();
    static _kernel_start: u8;
    static _etext: u8;
    static _erodata: u8;
    static _kernel_end: u8;
}

fn sym(s: &u8) -> u64 {
    s as *const u8 as u64
}

/// The guard page below the boot stack: `osmium_boot::pvh_start!` puts the
/// boot tables first in `.bss.boot` (`boot_pml4`, the PDPT and four PDs,
/// one page each) and the 64 KiB boot stack right after them, so the page
/// below the stack is the last page directory's. Only the CPU's page walker
/// reads that page once the kernel's own table is active (physically, for
/// application processors still on the boot tables), so its virtual mapping
/// can go.
const BOOT_STACK_GUARD_OFFSET: u64 = 5 * PAGE_SIZE as u64;

const COM1: u16 = 0x3f8;
/// RAM the PVH boot tables identity-map (`pvh_start!`): the first 4 GiB.
const BOOT_MAPPED: u64 = 1 << 32;
/// Physical address the AP trampoline is copied to (STARTUP vector 0x08).
const TRAMPOLINE: u64 = x86::smp::TRAMPOLINE;
const IPI_VECTOR: u8 = 33;
/// Vector of the TLB shootdown IPI.
const SHOOTDOWN_VECTOR: u8 = 34;
/// Vector for COM1's receive interrupt, routed through the I/O APIC.
const COM1_VECTOR: u8 = 40;
/// COM1's ISA IRQ.
const COM1_IRQ: u8 = 4;
/// Vector for the HPET comparator demo, routed through the I/O APIC.
const HPET_VECTOR: u8 = 41;
const DOUBLE_FAULT: u8 = 8;
/// IST slot for the double-fault handler's stack.
const DOUBLE_FAULT_IST: u8 = 1;
/// Vectors that can arrive while rsp is not a kernel stack, such as in the
/// syscall entry before it switches stacks (rsp is still the user's): debug,
/// NMI and machine check, each with an IST stack of its own (slots 2-4).
const ANY_STACK_VECTORS: [u8; 3] = [1, 2, 18];
const TIMER_VECTOR: u8 = 32;
const SPURIOUS_VECTOR: u8 = 0xff;
/// Where the (masked) legacy PICs deliver, so a spurious IRQ is harmless.
const PIC_VECTORS: core::ops::Range<u8> = 0xe0..0xf0;
/// Timer interrupt period.
const TICK_NS: u64 = 10_000_000;
/// Bytes of an [`ApStack`], its guard page included.
const AP_STACK: u64 = size_of::<ApStack>() as u64;

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

/// The kernel page table, shared by all CPUs.
static PT: KernelTable<X86_64> = IrqSpinLock::new(None);

/// Task stacks with an unmapped guard page below them, so an overflow
/// faults instead of silently overwriting whatever lies beneath. The old
/// mapping was global and may be cached on any CPU.
static STACKS: GuardedStacks<X86_64> = GuardedStacks::new(&PT, |va| shootdown_others(va, 1));

/// Gives this CPU its own GDT and TSS, with fresh stacks for double faults
/// and for `ANY_STACK_VECTORS`.
fn load_cpu_tables() {
    let tables = alloc::boxed::Box::leak(alloc::boxed::Box::new(x86::CpuTables::new()));
    // A copy: the TSS is packed, so its fields cannot be borrowed.
    let mut ist = tables.tss.ist;
    for top in ist.iter_mut().take(ANY_STACK_VECTORS.len() + 1) {
        let stack = alloc::vec![0u8; 16 * 1024].leak();
        *top = (stack.as_ptr() as u64 + stack.len() as u64) & !15;
    }
    tables.tss.ist = ist;
    let ptr = &raw mut *tables;
    if let Some(slot) = CPU_TABLES.get(cpu::current_id()) {
        slot.store(ptr, Ordering::Relaxed);
    }
    // SAFETY: the kernel is soft-float. Processes may use x87 and SSE: each
    // one's registers are switched with its task.
    unsafe { osmium::arch::fp::enable() };
    // SAFETY: called once per CPU, with interrupts disabled.
    irq::without(|| unsafe { tables.load() });
    // SAFETY: the tables are loaded on this CPU and live forever; traps are
    // installed; the kernel does not use the GS base.
    unsafe { (&*ptr).enable_syscall() };
}

/// Checks that `FpState` keeps all 256 bits of `ymm0` when AVX is on: two
/// patterns are captured and restored in turn.
fn avx_selftest() {
    use osmium::arch::fp::{self, FpState};
    if !fp::avx_enabled() {
        println!("[fp]    no AVX (or no XSAVE): FXSAVE switches x87 and SSE state");
        return;
    }
    let a: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
    let b: [u8; 32] = core::array::from_fn(|i| 0xf0 - i as u8);
    let mut out = [[0u8; 32]; 2];
    irq::without(|| {
        // SAFETY: fp::enable ran on this CPU (load_cpu_tables) and returned
        // true with AVX on, so the VEX loads and stores are legal; the
        // kernel does not use ymm0 itself, and the pointers cover 32 bytes.
        unsafe {
            core::arch::asm!("vmovdqu ymm0, [{}]", in(reg) a.as_ptr(), out("xmm0") _);
            let sa = FpState::capture();
            core::arch::asm!("vmovdqu ymm0, [{}]", in(reg) b.as_ptr(), out("xmm0") _);
            let sb = FpState::capture();
            sa.restore();
            core::arch::asm!("vmovdqu [{}], ymm0", in(reg) out[0].as_mut_ptr(), out("xmm0") _);
            sb.restore();
            core::arch::asm!("vmovdqu [{}], ymm0", in(reg) out[1].as_mut_ptr(), out("xmm0") _);
            FpState::new().restore();
        }
    });
    let ok = out[0] == a && out[1] == b;
    println!("[fp]    ymm0 kept across XSAVE/XRSTOR: {}", if ok { "ok" } else { "FAILED" });
}

/// Application processors' first stacks (`AP_STACKS[cpu - 1]`; the boot CPU
/// has its own), where each stays as its CPU's bootstrap task. In the
/// kernel image, not the heap: an AP first runs on the boot tables, which
/// map only the first 4 GiB. Each sits above a guard page that is unmapped
/// in the kernel's table, which the AP switches to first thing.
#[repr(C, align(4096))]
#[allow(dead_code)] // only its address is used
struct ApStack {
    guard: [u8; PAGE_SIZE],
    stack: [u8; 64 * 1024],
}
static mut AP_STACKS: [ApStack; MAX_CPUS - 1] =
    [const { ApStack { guard: [0; PAGE_SIZE], stack: [0; 64 * 1024] } }; MAX_CPUS - 1];

/// Each CPU's GDT and TSS, so the switch hook can update `rsp[0]`.
static CPU_TABLES: [core::sync::atomic::AtomicPtr<x86::CpuTables>; MAX_CPUS] =
    [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];

/// Points this CPU's TSS at the incoming task's kernel stack, where the CPU
/// will put the trap frame when that task traps out of ring 3.
fn on_switch(next: &osmium::sched::Task) {
    // Each process runs on its own page table; kernel tasks on the kernel's.
    let kernel = osmium::mm::PhysAddr::new(CR3.load(Ordering::Relaxed));
    let root = osmium::proc::switch_root(next, kernel).0;
    if x86::read_cr3() & !0xfff != root {
        // SAFETY: both kinds of table map the kernel (shared root entry 0).
        unsafe { x86::write_cr3(root) };
    }
    // FS.base is the thread pointer of the incoming thread (0 for kernel tasks).
    // SAFETY: a user-supplied base is checked to be canonical by `arch_prctl`.
    unsafe { x86::wrmsr(x86::msr::IA32_FS_BASE, osmium::proc::thread::tls_for(next).unwrap_or(0)) };
    let tables = CPU_TABLES.get(cpu::current_id()).map_or(core::ptr::null_mut(), |t| t.load(Ordering::Relaxed));
    if let (Some(top), false) = (next.kernel_stack_top(), tables.is_null()) {
        // SAFETY: this CPU's own tables; interrupts are off during a switch.
        unsafe { (*tables).tss.rsp[0] = top as u64 };
    }
}

/// CPUs that still owe an acknowledgement of the current shootdown.
static SHOOT_PENDING: AtomicUsize = AtomicUsize::new(0);
/// First page the current shootdown invalidates, and how many pages.
static SHOOT_ADDR: AtomicUsize = AtomicUsize::new(0);
static SHOOT_PAGES: AtomicUsize = AtomicUsize::new(0);
/// Held by the CPU running a shootdown.
static SHOOT_BUSY: AtomicBool = AtomicBool::new(false);

/// Invalidates this CPU's entries for the pending shootdown pages, if it owes them.
fn shootdown_service() {
    let me = 1usize << cpu::current_id();
    if SHOOT_PENDING.load(Ordering::Acquire) & me != 0 {
        let (va, pages) = (SHOOT_ADDR.load(Ordering::Acquire), SHOOT_PAGES.load(Ordering::Acquire));
        if pages > 32 {
            osmium::arch::mmu::flush_all();
        } else {
            for i in 0..pages {
                osmium::arch::mmu::flush_page(va + i * PAGE_SIZE);
            }
        }
        SHOOT_PENDING.fetch_and(!me, Ordering::AcqRel);
    }
}

/// Invalidates `pages` pages from `va` on every online CPU but this one, and
/// returns once they have all done so (the hook behind
/// `osmium::arch::mmu::flush_remote`, for user threads on several CPUs).
/// Waiting CPUs keep servicing requests, so two initiators cannot deadlock
/// even when interrupts are off.
#[allow(
    clippy::expect_used,
    reason = "a lost shootdown IPI would leave a stale TLB entry or hang the wait; neither can be recovered from"
)]
fn shootdown_others(va: usize, pages: usize) {
    let me = cpu::current_id();
    let others = ((1usize << demos::kernel::online()) - 1) & !(1 << me);
    if others == 0 {
        return;
    }
    while SHOOT_BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        shootdown_service();
        core::hint::spin_loop();
    }
    SHOOT_ADDR.store(va, Ordering::Release);
    SHOOT_PAGES.store(pages, Ordering::Release);
    SHOOT_PENDING.store(others, Ordering::Release);
    if let Some(apic) = LAPIC.get() {
        for (_, id) in APIC_IDS.iter().enumerate().filter(|&(c, _)| others & (1 << c) != 0) {
            // The wait below would never end without the IPI.
            apic.send_ipi(id.load(Ordering::Relaxed) as u8, SHOOTDOWN_VECTOR)
                .expect("shootdown IPI accepted by the local APIC");
        }
    }
    while SHOOT_PENDING.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
    SHOOT_BUSY.store(false, Ordering::Release);
}

/// Received bytes, from the COM1 interrupt handler to the reader task.
static RX: osmium::sync::SpscRing<u8, 256> = osmium::sync::SpscRing::new();
static RX_PRODUCER: IrqSpinLock<Option<osmium::sync::Producer<'static, u8, 256>>> = IrqSpinLock::new(None);
static RX_READY: osmium::sched::WaitQueue = osmium::sched::WaitQueue::new();
/// First I/O APIC (address, first GSI) and COM1's line, from the MADT.
static IOAPIC_INFO: Once<(u64, u32, u32, osmium::sysdrv::ioapic::LineMode)> = Once::new();

/// The HPET's registers (from the ACPI `HPET` table), once found.
static HPET_BASE: Once<u64> = Once::new();
static HPET: Once<Hpet> = Once::new();
/// Comparator interrupts taken by the HPET demo.
static HPET_FIRED: AtomicU32 = AtomicU32::new(0);

static UART: Once<SerialConsole<Uart16550<Pio>>> = Once::new();
static LAPIC: Once<LocalApic> = Once::new();
static SCHED: FifoScheduler = FifoScheduler::new(2).with_stealing();
static TIMERS: TimerQueue = TimerQueue::new();
static TICKS: AtomicU64 = AtomicU64::new(0);
/// APIC id of each logical CPU.
static APIC_IDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static CR3: AtomicU64 = AtomicU64::new(0);
/// APIC timer initial count for one tick.
static APIC_TICK_COUNT: AtomicU32 = AtomicU32::new(0);

/// Powers QEMU off: ACPI PM1a control (q35/i440fx), then isa-debug-exit.
fn shutdown() -> ! {
    // The firmware's own way first: \_S5_ from the DSDT, written to the register the FADT names.
    aml::power_off();
    // With no ACPI tables to say how (a guest of the x86_64-hyp example), QEMU's fixed PM1a control register.
    // SAFETY: QEMU's ACPI PM1a control register; SLP_TYP=0, SLP_EN.
    unsafe {
        x86::outw(0x604, 0x2000);
        x86::outb(0xf4, 0);
    }
    cpu::halt_forever()
}

#[unsafe(no_mangle)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "boot: what QEMU's machine provides is set up once here, so a failure means a broken machine or a bug in this example; the panic handler reports which"
)]
extern "C" fn kmain(start_info: usize) -> ! {
    trap::set_handler(on_trap);
    // SAFETY: we run on the boot stack from here on.
    unsafe { trap::install() };

    // SAFETY: COM1 belongs to this kernel.
    let mut uart = Uart16550::new(unsafe { Pio::new(COM1) });
    uart.init(Some(1));
    set_console(UART.call_once(|| SerialConsole::new(uart)));
    let mut brand = [0u8; 48];
    println!("\nosmium x86_64-pc example on {}", cpu_brand(&mut brand));
    // SAFETY: the only CPU; requires RDTSCP, which `-cpu max` provides.
    unsafe { cpu::set_current_id(0) };

    // --- PVH start info -----------------------------------------------------
    // SAFETY: QEMU passes a valid start-info structure, identity-mapped by
    // the boot page tables. Everything needed from it is copied out before
    // those tables are replaced.
    let info = unsafe { StartInfo::from_ptr(start_info as *const u8) }.expect("bad PVH start info");
    let mut map = MemoryMap::<32>::new();
    info.fill_memory_map(&mut map).expect("fill_memory_map failed");
    println!(
        "[pvh]   start info v{} at {start_info:#x}, {} memory-map entries, RSDP {:?}",
        info.version(),
        info.memory_map().count(),
        info.rsdp()
    );

    // --- VESA, through the video BIOS --------------------------------------
    // First: the BIOS needs the boot tables' identity map of low memory and
    // the machine as SeaBIOS left it (IVT, PIC), before IRQs are ours.
    let vesa = vesa(800, 600);

    // --- CPUs from the ACPI MADT (read while the boot tables map it) ---------
    // Every enabled CPU's APIC id; the boot CPU's own id comes later from
    // its local APIC's ID register (not CPUID, which a hypervisor may not
    // virtualize).
    let mut madt_ids = [None; MAX_CPUS];
    let mut ecam = None;
    let mut iommus = iommu::Units::default();
    if let Some(rsdp) = info.rsdp() {
        // SAFETY: the boot tables identity-map the first 4 GiB, where QEMU's
        // ACPI tables live; they are only read here.
        let read = |pa: u64, len: usize| Some(unsafe { core::slice::from_raw_parts(pa as *const u8, len) });
        let acpi = Acpi::new(rsdp.0, read).ok();
        ecam = acpi
            .as_ref()
            .and_then(|a| a.find(b"MCFG"))
            .and_then(Mcfg::parse)
            .and_then(|m| m.entries().find(|e| e.segment == 0));
        iommus.vtd = acpi
            .as_ref()
            .and_then(|a| a.find(b"DMAR"))
            .and_then(Dmar::parse)
            .and_then(|d| d.units().find(|u| u.segment == 0));
        iommus.amd = acpi
            .as_ref()
            .and_then(|a| a.find(b"IVRS"))
            .and_then(Ivrs::parse)
            .and_then(|i| i.units().find(|u| u.segment == 0));
        if let Some(h) = acpi.as_ref().and_then(|a| a.find(b"HPET")).and_then(HpetTable::parse) {
            HPET_BASE.call_once(|| h.base);
        }
        let madt = acpi.and_then(|a| a.find(b"APIC")).and_then(Madt::parse);
        if let Some(m) = &madt
            && let Some(io) = m.io_apics().next()
        {
            let (gsi, active_low, level) = m.isa_irq(COM1_IRQ);
            IOAPIC_INFO
                .call_once(|| (io.addr, io.gsi_base, gsi, osmium::sysdrv::ioapic::LineMode { active_low, level }));
        }
        let enabled = madt.iter().flat_map(|m| m.local_apics()).filter(|c| c.enabled);
        for (slot, c) in madt_ids.iter_mut().zip(enabled) {
            *slot = Some(c.apic_id);
        }
    }
    println!("[acpi]  MADT lists {} enabled CPUs", madt_ids.iter().flatten().count());

    // --- Physical memory ---------------------------------------------------
    // SAFETY: linker-provided symbols.
    let (kstart, etext, erodata, kend) =
        unsafe { (sym(&_kernel_start), sym(&_etext), sym(&_erodata), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).expect("reserve failed");
    map.page_align_usable();
    for r in map.regions() {
        println!("[mem]   {:#011x}..{:#011x} {:?}", r.start.0, r.end.0, r.kind);
    }
    // Only RAM below 4 GiB for now: the allocator writes into free frames,
    // and the boot tables map just the first 4 GiB. The rest is added once
    // the kernel's own table maps it.
    let below = PhysAddr::new(BOOT_MAPPED);
    // SAFETY: the memory map says the ranges are free RAM, identity-mapped.
    unsafe { demos::kernel::add_ram(map.usable().filter(|r| r.start < below).map(|r| r.start..r.end.min(below))) };
    demos::kernel::report_frames();

    // --- Heap ------------------------------------------------------------
    HEAP.init(&FRAMES);
    let squares: Vec<u64> = (0..1000).map(|i| i * i).collect();
    let s: String = ["heap", "works"].join(" ");
    println!("[heap]  {s} (sum of squares {})", squares.iter().sum::<u64>());

    // --- AML: the DSDT's devices, and the way to power off -------------------------
    // Needs the heap, and the boot tables' identity map of the ACPI tables and of what AML touches.
    if let Some(rsdp) = info.rsdp() {
        aml::init(rsdp.0);
    }

    // --- Paging (4-level, W^X, NX) -----------------------------------------
    let mut pt: PageTable<X86_64, &'static Frames> = PageTable::new(&FRAMES).expect("new failed");
    let k = |f| f | MapFlags::GLOBAL;
    let va = |a: u64| VirtAddr::new(a);
    let pa = |a: u64| PhysAddr::new(a);
    // The first 1 MiB stays unmapped, so null-ish pointers fault.
    pt.map_range(va(0x10_0000), pa(0x10_0000), kstart - 0x10_0000, k(MapFlags::RW)).expect("map_range failed");
    pt.map_range(va(kstart), pa(kstart), etext - kstart, k(MapFlags::RX)).expect("map_range failed");
    pt.map_range(va(etext), pa(etext), erodata - etext, k(MapFlags::READ)).expect("map_range failed");
    pt.map_range(va(erodata), pa(erodata), kend.next_multiple_of(PAGE_SIZE as u64) - erodata, k(MapFlags::RW))
        .expect("map_range failed");
    // RAM above the kernel, one region at a time: a single span to the end
    // of RAM would cover the PCI hole below 4 GiB (and the local APIC) as
    // cacheable memory once there is RAM above it.
    for r in map.usable().filter(|r| r.end.0 > kend) {
        let start = r.start.0.max(kend.next_multiple_of(PAGE_SIZE as u64));
        pt.map_range(va(start), pa(start), r.end.0 - start, k(MapFlags::RW)).expect("map_range failed");
    }
    pt.map_range(
        va(lapic::DEFAULT_BASE),
        pa(lapic::DEFAULT_BASE),
        PAGE_SIZE as u64,
        k(MapFlags::RW | MapFlags::DEVICE),
    )
    .expect("map_range failed");
    if let Some(&(io, ..)) = IOAPIC_INFO.get() {
        pt.map_range(va(io), pa(io), PAGE_SIZE as u64, k(MapFlags::RW | MapFlags::DEVICE)).expect("map_range failed");
    }
    if let Some(&base) = HPET_BASE.get() {
        pt.map_range(va(base), pa(base), PAGE_SIZE as u64, k(MapFlags::RW | MapFlags::DEVICE))
            .expect("map_range failed");
    }
    // Writable so the boot CPU can install the AP trampoline there.
    pt.map_range(va(TRAMPOLINE), pa(TRAMPOLINE), PAGE_SIZE as u64, k(MapFlags::RW)).expect("map_range failed");
    // SAFETY: the new table maps the running code, its stack, the heap and the APIC.
    unsafe { x86::write_cr3(pt.root().0) };
    CR3.store(pt.root().0, Ordering::Release);
    // SAFETY: free RAM, identity-mapped by the table just loaded.
    unsafe { demos::kernel::add_ram(map.usable().filter(|r| r.end > below).map(|r| r.start.max(below)..r.end)) };
    // Guard pages below the boot stack and the APs' stacks (see
    // `BOOT_STACK_GUARD_OFFSET` and `ApStack`).
    // SAFETY: a linker symbol; only the address is taken.
    let boot_guard = unsafe { sym(&boot_pml4) } + BOOT_STACK_GUARD_OFFSET;
    let ap_stacks = (&raw const AP_STACKS) as u64;
    let guards = core::iter::once(boot_guard).chain((0..MAX_CPUS as u64 - 1).map(|i| ap_stacks + i * AP_STACK));
    let guarded =
        guards.filter(|&g| g.is_multiple_of(PAGE_SIZE as u64) && demos::kernel::unmap_guard(&mut pt, g)).count();
    demos::kernel::set_boot_stack_limit(boot_guard as usize + PAGE_SIZE);
    if let Some(t) = pt.translate(va(kmain as *const () as u64)) {
        println!("[mmu]   CR3 {:#x}; kmain mapped {:?} via {:?} page", pt.root().0, t.flags, t.size);
    }
    demos::kernel::rand_demo();
    *PT.lock() = Some(pt);
    load_cpu_tables();
    // SAFETY: this CPU's TSS now has a double-fault stack; APs load theirs
    // before enabling interrupts.
    unsafe { trap::set_ist(DOUBLE_FAULT, DOUBLE_FAULT_IST) };
    for (i, &vector) in ANY_STACK_VECTORS.iter().enumerate() {
        // SAFETY: as above; load_cpu_tables fills these IST slots too.
        unsafe { trap::set_ist(vector, DOUBLE_FAULT_IST + 1 + i as u8) };
    }
    osmium::sched::set_stack_allocator(&STACKS);
    osmium::sched::set_switch_hook(on_switch);
    // SAFETY: the syscall handler treats every argument as untrusted.
    unsafe { trap::allow_from_user(trap::SYSCALL_VECTOR) };
    println!(
        "[guard] task stacks and {guarded} boot stacks get unmapped guard pages; double faults run on \
         IST{DOUBLE_FAULT_IST}"
    );
    avx_selftest();

    // --- Displays: the VESA framebuffer, then PCI adapters (virtio-vga) -----
    display_demo(vesa, ecam);

    // --- Timers: calibrate TSC and APIC timer against the PIT ---------------
    // SAFETY: the PIT and port 0x61 belong to this kernel.
    let pit = Pit::new(unsafe { pit::Pio::new() });
    let tsc_hz = pit.calibrate(10_000_000, cpu::ticks);
    demos::kernel::set_rate(TickRate::new(tsc_hz));
    // Move the legacy 8259 PICs off the exception vectors (their power-on
    // bases alias IRQ 0-7 onto vectors 8-15, IRQ 0 onto #DF), then mask
    // them; the local APIC delivers everything. Only spurious IRQ 7 or 15
    // can still arrive, as PIC_VECTORS.start + 7 or + 15.
    // SAFETY: the PIC command and data ports.
    unsafe {
        x86::outb(0x20, 0x11); // ICW1: edge, cascade, ICW4 follows
        x86::outb(0xa0, 0x11);
        x86::outb(0x21, PIC_VECTORS.start); // ICW2: vector base
        x86::outb(0xa1, PIC_VECTORS.start + 8);
        x86::outb(0x21, 0x04); // ICW3: slave on IRQ 2
        x86::outb(0xa1, 0x02);
        x86::outb(0x21, 0x01); // ICW4: 8086 mode
        x86::outb(0xa1, 0x01);
        x86::outb(0x21, 0xff);
        x86::outb(0xa1, 0xff);
    }
    // SAFETY: the local APIC's default address, mapped uncached above.
    let apic = LAPIC.call_once(|| LocalApic::new(unsafe { IoMem::new(lapic::DEFAULT_BASE as *mut u8, PAGE_SIZE) }));
    apic.enable(SPURIOUS_VECTOR);
    // CPU 0 is this one; the others are started below in MADT order.
    let my_apic = apic.id();
    APIC_IDS[0].store(my_apic, Ordering::Relaxed);
    let mut ncpus = 1;
    for id in madt_ids.into_iter().flatten().filter(|&id| id != my_apic) {
        APIC_IDS[ncpus].store(id, Ordering::Relaxed);
        ncpus += 1;
    }
    apic.start_timer(TIMER_VECTOR, u32::MAX, false);
    let apic_hz = pit.calibrate(10_000_000, || u32::MAX as u64 - apic.timer_remaining() as u64);
    apic.stop_timer();
    hpet_init(&pit);
    println!(
        "[timer] TSC {} MHz, APIC timer {} MHz (divided by 16), measured with the PIT",
        tsc_hz / 1_000_000,
        apic_hz / 1_000_000
    );

    // --- Scheduler ---------------------------------------------------------
    osmium::sched::inject_scheduler(&SCHED);
    osmium::sched::init_cpu();
    APIC_TICK_COUNT.store((apic_hz * TICK_NS / 1_000_000_000) as u32, Ordering::Relaxed);
    apic.start_timer(TIMER_VECTOR, APIC_TICK_COUNT.load(Ordering::Relaxed), true);
    irq::enable();
    println!("[sched] FIFO scheduler, {} ms tick, APIC id {}", TICK_NS / 1_000_000, apic.id());

    // --- Application processors (INIT, STARTUP, STARTUP) ---------------------
    osmium::sched::set_remote_wake_hook(|cpu| {
        // A lost wake-up is picked up at that CPU's next tick.
        if let (Some(apic), Some(id)) = (LAPIC.get(), APIC_IDS.get(cpu)) {
            let _ = apic.send_ipi(id.load(Ordering::Relaxed) as u8, IPI_VECTOR);
        }
    });
    osmium::arch::mmu::set_remote_flush(shootdown_others);
    // SAFETY: the trampoline page is free low memory (reserved from the
    // allocator), mapped writable above; no AP is starting yet.
    unsafe { x86::smp::install() };
    for (cpu, apic_id) in APIC_IDS.iter().enumerate().take(ncpus).skip(1) {
        // SAFETY: only the address is taken; this AP is its sole user.
        let stack = unsafe { &raw mut AP_STACKS[cpu - 1] };
        let boot = x86::smp::ApBoot {
            cr3: &raw const boot_pml4 as u64,
            stack_top: (stack as u64 + AP_STACK) & !15,
            entry: ap_start64 as *const () as u64,
            cpu,
        };
        // SAFETY: the trampoline is installed and the previous AP has
        // checked in (below); the boot tables identity-map it and the kernel.
        let started = unsafe { apic.start_ap(apic_id.load(Ordering::Relaxed) as u8, &boot, |ns| pit.wait_ns(ns)) };
        if started.is_err() {
            println!(
                "[smp]   APIC id {} did not accept the startup IPIs; continuing with {cpu} CPUs",
                apic_id.load(Ordering::Relaxed)
            );
            ncpus = cpu;
            break;
        }
        // One AP at a time: they share the trampoline's slots. One that
        // never checks in ends the bring-up (it may still be in the
        // trampoline), so CPU indices stay dense.
        if !demos::kernel::wait_online(cpu + 1) {
            println!(
                "[smp]   APIC id {} did not check in within 1 s; continuing with {cpu} CPUs",
                apic_id.load(Ordering::Relaxed)
            );
            ncpus = cpu;
            break;
        }
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
    serial_demo();
    hpet_demo();
    usb::demo(ecam);
    msi::demo(ecam);
    iommu::demo(ecam, iommus);

    println!(
        "[done]  {} timer ticks, {} free frames; shutting down",
        TICKS.load(Ordering::Relaxed),
        demos::kernel::free_frames()
    );
    shutdown()
}

/// Sets a `width` by `height` 32-bit VESA mode through the video BIOS, and
/// returns its framebuffer and the video memory size.
fn vesa(width: u16, height: u16) -> Option<(PhysAddr, FramebufferInfo, usize)> {
    use osmium::display::vbe::{RealModeBios, Vbe};
    // SAFETY: 0x5000..0x8000 is free low memory, kept from the frame
    // allocator and identity-mapped (and executable) in the boot tables,
    // whose root is below 4 GiB. Only this CPU runs, and nothing has
    // touched the IVT, the PIC or the BIOS data area yet. Without a video
    // BIOS (as a hypervisor's PVH guest) nothing is called.
    let Some(bios) = (unsafe { RealModeBios::probe() }) else {
        println!("[vesa]  no video BIOS");
        return None;
    };
    // SAFETY: as above.
    unsafe { x86::bios::install() };
    let mut vbe = Vbe::new(bios).inspect_err(|e| println!("[vesa]  no VBE: {e:?}")).ok()?;
    let (major, minor) = (vbe.version() >> 8, vbe.version() & 0xff);
    let Some(mode) = vbe.find_mode(width, height, 32) else {
        println!("[vesa]  VBE {major}.{minor}: no {width}x{height} mode among {}", vbe.modes().len());
        return None;
    };
    let (addr, fb) = vbe.set_mode(&mode).inspect_err(|e| println!("[vesa]  set mode {:#x}: {e:?}", mode.mode)).ok()?;
    println!(
        "[vesa]  VBE {major}.{minor}, {} KiB, {} modes; set mode {:#x}: {}x{} {}bpp at {:#x}",
        vbe.memory() / 1024,
        vbe.modes().len(),
        mode.mode,
        fb.width,
        fb.height,
        fb.format.bpp,
        addr.0
    );
    Some((addr, fb, vbe.memory()))
}

/// Draws on the VESA framebuffer, reading the mode back from the Bochs
/// DISPI registers the BIOS programmed, then on every PCI display adapter.
fn display_demo(vesa: Option<(PhysAddr, FramebufferInfo, usize)>, ecam: Option<EcamWindow>) {
    use osmium::display::bochs::BochsVbe;
    // Identity-maps device memory and returns a window onto it.
    // SAFETY: the windows are video memory and BARs of the display devices
    // this demo owns.
    let mut map = |addr: u64, size: u64| unsafe { demos::kernel::map_io(&PT, addr, size) };
    if let Some((addr, fb, vram)) = vesa {
        let vram = map(addr.0, vram.max(fb.size()) as u64);
        // SAFETY: the VGA device's DISPI and VGA ports; this kernel owns them.
        match unsafe { BochsVbe::new_ports(vram) } {
            Ok(mut dispi) if dispi.info() == fb => {
                println!("[vesa]  DISPI {:#x} reads back the BIOS's mode", dispi.version());
                demos::display::show("vesa", &mut dispi);
            }
            Ok(dispi) => println!("[vesa]  DISPI holds {:?}, not the BIOS's {fb:?}", dispi.info()),
            Err(e) => println!("[vesa]  no DISPI behind the BIOS: {e:?}"),
        }
    }
    let Some(ecam) = ecam else { return };
    // Bus 0 is enough for QEMU's q35; SeaBIOS assigned the BARs.
    let cfg = osmium::hal::pci::Ecam::new(map(ecam.base, 1 << 20), 0);
    demos::display::pci(&cfg, 0, 800, 600, None, &mut map, &FRAMES);
}

/// The CPUID brand string (no heap needed: called before the heap exists).
fn cpu_brand(buf: &mut [u8; 48]) -> &str {
    let words = (0x8000_0002..=0x8000_0004).map(|leaf| x86::cpuid(leaf, 0)).flat_map(|r| [r.eax, r.ebx, r.ecx, r.edx]);
    for (chunk, w) in buf.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        *chunk = w.to_le_bytes();
    }
    let brand = buf.split(|&b| b == 0).next().unwrap_or(&[]);
    core::str::from_utf8(brand).unwrap_or("?").trim()
}

/// This CPU's local APIC id (0 before the local APIC is set up).
pub(crate) fn apic_id() -> u8 {
    LAPIC.get().map_or(0, |apic| apic.id() as u8)
}

/// Rust entry of application processors, on their own stack.
#[unsafe(no_mangle)]
extern "C" fn ap_main(cpu: usize) -> ! {
    // SAFETY: the boot CPU's table maps everything this CPU touches.
    unsafe { x86::write_cr3(CR3.load(Ordering::Acquire)) };
    // SAFETY: the boot CPU hands out distinct indices.
    unsafe { cpu::set_current_id(cpu) };
    // SAFETY: we are on the stack the boot CPU allocated for us. Traps go in
    // first, as on the boot CPU, so an exception while the tables load is
    // handled rather than a triple fault.
    unsafe { trap::install() };
    load_cpu_tables();
    // The boot CPU set the local APIC up before starting this one.
    let Some(apic) = LAPIC.get() else { cpu::halt_forever() };
    apic.enable(SPURIOUS_VECTOR);
    osmium::sched::init_cpu();
    apic.start_timer(TIMER_VECTOR, APIC_TICK_COUNT.load(Ordering::Relaxed), true);
    irq::enable();
    println!("[smp]   APIC id {} online as CPU {cpu}", apic.id());
    demos::kernel::check_in();
    // Hand the CPU to the scheduler for good.
    osmium::sched::exit()
}

fn on_timer() {
    if cpu::current_id() == 0 {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }
    TIMERS.process(now_ns());
    osmium::sched::tick();
}

/// Starts the HPET found in the ACPI tables and checks its counter against the PIT.
fn hpet_init(pit: &Pit<pit::Pio>) {
    let Some(&base) = HPET_BASE.get() else {
        println!("[hpet]  no HPET table; skipping");
        return;
    };
    // SAFETY: the ACPI table says the register block lives here; mapped uncached above.
    let io = unsafe { IoMem::new(base as *mut u8, hpet::REGISTER_BYTES) };
    let Ok(h) = Hpet::new(io) else {
        println!("[hpet]  the register block at {base:#x} is not an HPET");
        return;
    };
    h.enable();
    let h = HPET.call_once(|| h);
    let t0 = h.now_ns();
    pit.wait_ns(10_000_000);
    let dt = h.now_ns().saturating_sub(t0);
    println!(
        "[hpet]  {} comparators, {} bit counter at {} MHz; legacy replacement {}",
        h.timer_count(),
        if h.counter_is_64bit() { 64 } else { 32 },
        h.frequency() / 1_000_000,
        if h.has_legacy_replacement() { "available" } else { "absent" }
    );
    // The PIT waited 10 ms of its own: the HPET should have seen about the same.
    if (8_000_000..=50_000_000).contains(&dt) {
        println!("[hpet]  main counter agrees with a 10 ms PIT wait");
    } else {
        println!("[hpet]  main counter disagrees with the PIT: {dt} ns for 10 ms");
    }
}

/// Wires an HPET comparator through the I/O APIC to this CPU and takes a one-shot and a periodic
/// interrupt from it.
fn hpet_demo() {
    let (Some(h), Some(&(io_addr, gsi_base, ..))) = (HPET.get(), IOAPIC_INFO.get()) else {
        return;
    };
    // SAFETY: the MADT says the I/O APIC lives here; mapped uncached above.
    let ioapic = osmium::sysdrv::ioapic::IoApic::new(unsafe { IoMem::new(io_addr as *mut u8, PAGE_SIZE) }, gsi_base);
    // The highest I/O APIC input some comparator can drive, avoiding the ISA lines.
    let pick = (0..h.timer_count())
        .filter_map(|i| Some((i, h.caps(i).ok().filter(|c| c.periodic)?.routes)))
        .flat_map(|(i, routes)| (16..32u8).rev().map(move |gsi| (i, gsi, routes)))
        .find(|&(_, gsi, routes)| routes & (1 << gsi) != 0 && ioapic.handles(gsi as u32));
    let Some((index, gsi, _)) = pick else {
        println!("[hpet]  no comparator can drive an I/O APIC input; skipping");
        return;
    };
    if let Err(e) = h.route(index, gsi, false) {
        return println!("[hpet]  routing comparator {index} to input {gsi}: {e:?}");
    }
    let mode = osmium::sysdrv::ioapic::LineMode { active_low: false, level: false };
    ioapic.route(gsi as u32, HPET_VECTOR, apic_id(), mode);
    println!("[hpet]  comparator {index} -> I/O APIC input {gsi} -> vector {HPET_VECTOR}");

    let wait = |what: &str, want: u32| {
        let limit = h.now_ns() + 200_000_000;
        while HPET_FIRED.load(Ordering::SeqCst) < want && h.now_ns() < limit {
            core::hint::spin_loop();
        }
        HPET_FIRED.load(Ordering::SeqCst) >= want || {
            println!("[hpet]  {what}: no interrupt within 200 ms");
            false
        }
    };
    let Some(timer) = h.timer(index) else { return println!("[hpet]  no comparator {index}") };
    osmium::hal::timer::OneShotTimer::set_deadline(&timer, h.now_ns() + 2_000_000);
    if wait("one-shot", 1) {
        println!("[hpet]  one-shot comparator interrupt taken");
    }
    osmium::hal::timer::OneShotTimer::cancel(&timer);
    let base = HPET_FIRED.load(Ordering::SeqCst);
    if h.start_periodic(index, 1_000_000).is_ok() && wait("periodic", base + 3) {
        println!("[hpet]  periodic comparator interrupts taken");
    }
    let _ = h.stop(index);
    ioapic.mask(gsi as u32);
}

/// Routes COM1's receive interrupt through the I/O APIC to this CPU and
/// waits up to 300 ms for a line of input. To feed it under QEMU:
/// `-chardev file,id=s0,path=out.log,input-path=in.txt -serial chardev:s0`.
/// Bytes that arrive before the UART is initialized are dropped when its
/// receive FIFO is reset, so start the input with a newline.
fn serial_demo() {
    let Some(&(io_addr, gsi_base, gsi, mode)) = IOAPIC_INFO.get() else {
        println!("[uart]  no I/O APIC in the MADT; skipping");
        return;
    };
    // SAFETY: the MADT says the I/O APIC lives here; mapped uncached above.
    let ioapic = osmium::sysdrv::ioapic::IoApic::new(unsafe { IoMem::new(io_addr as *mut u8, PAGE_SIZE) }, gsi_base);
    let (Some((producer, mut rx)), Some(uart)) = (RX.split(), UART.get()) else {
        return println!("[uart]  the receive ring or the console is not set up; skipping");
    };
    *RX_PRODUCER.lock() = Some(producer);
    ioapic.route(gsi, COM1_VECTOR, apic_id(), mode);
    uart.port().enable_rx_interrupt();
    println!("[uart]  COM1 IRQ {COM1_IRQ} -> GSI {gsi} -> vector {COM1_VECTOR} on {} I/O APIC lines", ioapic.lines());

    let deadline = now_ns() + 300_000_000;
    let timed_out = alloc::sync::Arc::new(AtomicBool::new(false));
    let t = timed_out.clone();
    TIMERS.add(deadline, move || {
        t.store(true, Ordering::Release);
        RX_READY.wake_all();
    });
    let mut line = String::new();
    loop {
        let got =
            RX_READY.wait_until(|| rx.pop().map(Some).or_else(|| timed_out.load(Ordering::Acquire).then_some(None)));
        match got {
            Some(b'\n' | b'\r') if !line.is_empty() => break,
            Some(b) if b.is_ascii_graphic() || b == b' ' => line.push(b as char),
            Some(_) => {}
            None => break,
        }
    }
    ioapic.mask(gsi);
    if line.is_empty() {
        println!("[uart]  no input within 300 ms (feed COM1 to see interrupt-driven input)");
    } else {
        println!("[uart]  interrupt-driven input: {line:?}");
    }
}

/// What `fork` and `execve` need: spaces sharing the kernel's root entry 0,
/// laid out as `demos::user` says.
fn platform() -> osmium::proc::Platform {
    demos::user::platform(
        || demos::user::new_space(&PT),
        // SAFETY: the table shares the kernel's root entry 0. Instruction
        // fetch is coherent with stores on x86, so nothing else is needed.
        |root| unsafe { x86::write_cr3(root.0) },
        |frame| {
            // A new thread can start on another CPU before its creator has
            // recorded its task id, so the switch hook that loaded FS.base
            // did not know the thread pointer yet. Load it now.
            let tls = osmium::proc::thread::tls_for(&osmium::sched::current()).unwrap_or(0);
            // SAFETY: a base the thread itself set, checked canonical by `arch_prctl`.
            unsafe { x86::wrmsr(x86::msr::IA32_FS_BASE, tls) };
            // SAFETY: the child's task is running with its table active (the
            // switch hook), and the frame is its parent's from a system call.
            unsafe { x86::resume_user(&frame) }
        },
    )
}

/// The user demos: the hand-written ring-3 programs (`user_hello` enters
/// the kernel with `syscall`, `user_bad` with `int 0x80`), then the Rust
/// ones. On CPU 1: the syscall stub finds its kernel stack through that
/// CPU's GS base, which CPU 0 alone would not test.
fn user_demo() {
    osmium::proc::set_platform(platform());
    // SAFETY: linker symbols delimiting the user programs in .rodata.
    let (hello, bad) = unsafe { (image(&user_hello, &user_hello_end), image(&user_bad, &user_bad_end)) };
    // `CpuTables` are loaded and the switch hook keeps `rsp[0]` on the
    // running task's kernel stack, as `x86::enter_user` requires.
    demos::user::demo(&platform(), hello, bad, "ring-3", x86::enter_user);
}
/// Runs the trap handler, then, before returning to user mode from an
/// interrupt, delivers pending signals (and stops threads of a process that
/// is ending).
fn on_trap(frame: &mut TrapFrame) {
    handle_trap(frame);
    demos::user::before_return(frame);
}

/// Acknowledges the interrupt being handled at this CPU's local APIC.
pub(crate) fn eoi() {
    if let Some(apic) = LAPIC.get() {
        apic.eoi();
    }
}

fn handle_trap(frame: &mut TrapFrame) {
    // System calls, and exceptions (vectors below 32) from ring 3.
    if frame.from_user() && demos::user::handle(frame) {
        return;
    }
    match (frame.vector(), frame.cause()) {
        (DOUBLE_FAULT, _) => {
            // Reached through IST1: the task's own stack is unusable. A
            // double fault cannot be resumed, so end only the faulting task.
            let task = osmium::sched::current();
            println!(
                "[guard] task {:?} overflowed its stack (rsp {:#x} hit the guard page); killed",
                task.name(),
                frame.sp()
            );
            drop(task);
            osmium::sched::exit();
        }
        (TIMER_VECTOR, _) => {
            // Acknowledge before a possible task switch, or no further
            // timer interrupts would be delivered.
            eoi();
            on_timer();
            osmium::sched::preempt_if_needed();
        }
        (IPI_VECTOR, _) => {
            eoi();
            osmium::sched::preempt_if_needed();
        }
        (SHOOTDOWN_VECTOR, _) => {
            shootdown_service();
            eoi();
        }
        (HPET_VECTOR, _) => {
            HPET_FIRED.fetch_add(1, Ordering::SeqCst);
            eoi();
        }
        (COM1_VECTOR, _) => {
            // Drain the UART's FIFO into the ring, then wake the reader.
            if let (Some(p), Some(uart)) = (RX_PRODUCER.lock().as_mut(), UART.get()) {
                let mut port = uart.port();
                while let Some(b) = osmium::hal::serial::SerialPort::read_byte(&mut *port) {
                    let _ = p.push(b);
                }
            }
            eoi();
            RX_READY.wake_all();
            osmium::sched::preempt_if_needed();
        }
        (msi::VECTOR, _) => msi::on_interrupt(),
        (usb::VECTOR, _) => usb::on_interrupt(),
        (SPURIOUS_VECTOR, _) => {}
        // A spurious IRQ from a masked PIC: no EOI (none was latched).
        (v, _) if PIC_VECTORS.contains(&v) => {}
        (_, Trap::Breakpoint | Trap::PageFault { .. }) if demos::fault::recovered(frame) => {}
        (v, cause) => unhandled(frame, v, cause),
    }
}

/// A kernel trap with no handler: a bug in this kernel, so stop it.
#[allow(clippy::panic)] // a kernel trap nothing handles leaves no safe way on
fn unhandled(frame: &TrapFrame, vector: u8, cause: Trap) -> ! {
    panic!("unhandled trap {cause:?} (vector {vector}) at rip {:#x}, error {:#x}", frame.pc(), frame.error_code)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;
    irq::disable();
    // Straight to COM1, not through the console: the panic may have come
    // from inside println, with the console's locks held.
    // SAFETY: the port is already set up; writes may interleave with
    // another CPU's output, which is fine for a dying kernel.
    let mut com1 = Uart16550::new(unsafe { Pio::new(COM1) });
    let _ = writeln!(osmium::hal::serial::SerialWriter(&mut com1), "\n[panic] {info}");
    shutdown()
}
