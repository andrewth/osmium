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
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use core::ptr::NonNull;
use osmium::arch::trap::{self, Access, Trap, TrapFrame};
use osmium::arch::x86_64 as x86;
use osmium::arch::{MAX_CPUS, cpu, irq};
use osmium::boot::acpi::{Acpi, Dmar, EcamWindow, HpetTable, Ivrs, Madt, Mcfg};
use osmium::boot::pvh::StartInfo;
use osmium::sysdrv::hpet::{self, Hpet};
use osmium::sysdrv::lapic::{self, LocalApic};
use osmium::sysdrv::pit::{self, Pit};
use osmium::sysdrv::uart16550::{Pio, Uart16550};
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::display::{Display, FramebufferInfo};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::timer::{Clock, TickRate};
use osmium::mm::frame::order_for;
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::PageSize;
use osmium::mm::paging::formats::X86_64;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};

use osmium::proc::{AddressSpace, ExitStatus, Process, UserMemory};
use osmium::sched::timer::TimerQueue;
use osmium::sched::{FifoScheduler, StackAllocator, Task, TaskBuilder};
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

type Frames = LockedFrames<BuddyAllocator<OffsetMapper>, OffsetMapper>;

// SAFETY: the kernel runs identity-mapped, before and after switching tables.
static FRAMES: Frames = unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

/// The kernel page table, shared by all CPUs.
static PT: IrqSpinLock<Option<PageTable<X86_64, &'static Frames>>> = IrqSpinLock::new(None);

/// Gives this CPU its own GDT and TSS, with fresh stacks for double faults
/// and for `ANY_STACK_VECTORS`.
fn load_cpu_tables() {
    let tables = alloc::boxed::Box::leak(alloc::boxed::Box::new(x86::CpuTables::new()));
    for slot in 0..=ANY_STACK_VECTORS.len() {
        let stack = alloc::vec![0u8; 16 * 1024].leak();
        tables.tss.ist[slot] = (stack.as_ptr() as u64 + stack.len() as u64) & !15;
    }
    let ptr = &raw mut *tables;
    CPU_TABLES[cpu::current_id()].store(ptr, Ordering::Relaxed);
    // SAFETY: the kernel is soft-float. Processes may use x87 and SSE: each
    // one's registers are switched with its task.
    unsafe { osmium::arch::fp::enable() };
    // SAFETY: called once per CPU, with interrupts disabled.
    irq::without(|| unsafe { tables.load() });
    // SAFETY: the tables are loaded on this CPU and live forever; traps are
    // installed; the kernel does not use the GS base.
    unsafe { (&*ptr).enable_syscall() };
}

/// Application processors' first stacks (`AP_STACKS[cpu - 1]`; the boot CPU
/// has its own), where each stays as its CPU's bootstrap task.
#[repr(align(16))]
#[allow(dead_code)] // only its address is used
struct ApStack([u8; 64 * 1024]);
static mut AP_STACKS: [ApStack; MAX_CPUS - 1] = [const { ApStack([0; 64 * 1024]) }; MAX_CPUS - 1];

/// Each CPU's GDT and TSS, so the switch hook can update `rsp[0]`.
static CPU_TABLES: [core::sync::atomic::AtomicPtr<x86::CpuTables>; MAX_CPUS] =
    [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];

/// Points this CPU's TSS at the incoming task's kernel stack, where the CPU
/// will put the trap frame when that task traps out of ring 3.
fn on_switch(next: &osmium::sched::Task) {
    // Each process runs on its own page table; kernel tasks on the kernel's.
    let root = osmium::proc::root_for(next).map_or(CR3.load(Ordering::Relaxed), |r| r.0);
    if x86::read_cr3() & !0xfff != root {
        // SAFETY: both kinds of table map the kernel (shared root entry 0).
        unsafe { x86::write_cr3(root) };
    }
    // FS.base is the thread pointer of the incoming thread (0 for kernel tasks).
    // SAFETY: a user-supplied base is checked to be canonical by `arch_prctl`.
    unsafe { x86::wrmsr(x86::msr::IA32_FS_BASE, osmium::proc::thread::tls_for(next).unwrap_or(0)) };
    let tables = CPU_TABLES[cpu::current_id()].load(Ordering::Relaxed);
    if let (Some(top), false) = (next.kernel_stack_top(), tables.is_null()) {
        // SAFETY: this CPU's own tables; interrupts are off during a switch.
        unsafe { (*tables).tss.rsp[0] = top as u64 };
    }
}

/// CPUs that still owe an acknowledgement of the current shootdown.
static SHOOT_PENDING: AtomicUsize = AtomicUsize::new(0);
/// Page the current shootdown invalidates.
static SHOOT_ADDR: AtomicUsize = AtomicUsize::new(0);
/// Held by the CPU running a shootdown.
static SHOOT_BUSY: AtomicBool = AtomicBool::new(false);

/// Invalidates this CPU's entry for the pending shootdown page, if it owes one.
fn shootdown_service() {
    let me = 1usize << cpu::current_id();
    if SHOOT_PENDING.load(Ordering::Acquire) & me != 0 {
        osmium::arch::mmu::flush_page(SHOOT_ADDR.load(Ordering::Acquire));
        SHOOT_PENDING.fetch_and(!me, Ordering::AcqRel);
    }
}

/// Invalidates `va` on every online CPU and returns once all have done so.
/// Waiting CPUs keep servicing requests, so two initiators cannot deadlock
/// even when interrupts are off.
fn shootdown(va: usize) {
    osmium::arch::mmu::flush_page(va);
    let me = cpu::current_id();
    let others = ((1usize << ONLINE.load(Ordering::Acquire)) - 1) & !(1 << me);
    if others == 0 {
        return;
    }
    while SHOOT_BUSY.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        shootdown_service();
        core::hint::spin_loop();
    }
    SHOOT_ADDR.store(va, Ordering::Release);
    SHOOT_PENDING.store(others, Ordering::Release);
    let apic = LAPIC.get().expect("LAPIC initialised");
    for cpu in (0..MAX_CPUS).filter(|c| others & (1 << c) != 0) {
        apic.send_ipi(APIC_IDS[cpu].load(Ordering::Relaxed) as u8, SHOOTDOWN_VECTOR);
    }
    while SHOOT_PENDING.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
    SHOOT_BUSY.store(false, Ordering::Release);
}

/// Task stacks with an unmapped guard page below them, so an overflow
/// faults instead of silently overwriting whatever lies beneath.
struct GuardedStacks;

// SAFETY: blocks come from the frame allocator (exclusive, page aligned) and
// the usable part stays mapped read/write.
unsafe impl StackAllocator for GuardedStacks {
    fn alloc(&self, size: usize) -> Option<(NonNull<u8>, usize)> {
        let order = order_for(size + PAGE_SIZE);
        let guard = FRAMES.lock().alloc(order)?;
        {
            let mut pt = PT.lock();
            let (_, flush) = pt.as_mut()?.unmap_4k(VirtAddr::new(guard.0)).ok()?;
            flush.flush();
        }
        // The old mapping was global and may be cached on any CPU.
        shootdown(guard.0 as usize);
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
static TSC_RATE: Once<TickRate> = Once::new();
static TICKS: AtomicU64 = AtomicU64::new(0);
/// APIC id of each logical CPU.
static APIC_IDS: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
static ONLINE: AtomicUsize = AtomicUsize::new(1);
static CR3: AtomicU64 = AtomicU64::new(0);
/// APIC timer initial count for one tick.
static APIC_TICK_COUNT: AtomicU32 = AtomicU32::new(0);

fn now_ns() -> u64 {
    TSC_RATE.get().expect("TSC_RATE initialised").ticks_to_ns(cpu::ticks())
}

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
    {
        let mut buddy = FRAMES.lock();
        // Only RAM below 4 GiB for now: the allocator writes into free
        // frames, and the boot tables map just the first 4 GiB. The rest is
        // added once the kernel's own table maps it.
        for r in map.usable().filter(|r| r.start.0 < BOOT_MAPPED) {
            // SAFETY: the memory map says the range is free RAM, identity-mapped.
            unsafe { buddy.add_region(r.start, r.end.min(PhysAddr::new(BOOT_MAPPED))) };
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
    {
        let mut buddy = FRAMES.lock();
        for r in map.usable().filter(|r| r.end.0 > BOOT_MAPPED) {
            // SAFETY: free RAM, identity-mapped by the table just loaded.
            unsafe { buddy.add_region(r.start.max(PhysAddr::new(BOOT_MAPPED)), r.end) };
        }
    }
    let t = pt.translate(va(kmain as *const () as u64)).expect("translate failed");
    println!("[mmu]   CR3 {:#x}; kmain mapped {:?} via {:?} page", pt.root().0, t.flags, t.size);
    *PT.lock() = Some(pt);
    load_cpu_tables();
    // SAFETY: this CPU's TSS now has a double-fault stack; APs load theirs
    // before enabling interrupts.
    unsafe { trap::set_ist(DOUBLE_FAULT, DOUBLE_FAULT_IST) };
    for (i, &vector) in ANY_STACK_VECTORS.iter().enumerate() {
        // SAFETY: as above; load_cpu_tables fills these IST slots too.
        unsafe { trap::set_ist(vector, DOUBLE_FAULT_IST + 1 + i as u8) };
    }
    osmium::sched::set_stack_allocator(&GuardedStacks);
    osmium::sched::set_switch_hook(on_switch);
    // SAFETY: the syscall handler treats every argument as untrusted.
    unsafe { trap::allow_from_user(trap::SYSCALL_VECTOR) };
    println!("[guard] task stacks get unmapped guard pages; double faults run on IST{DOUBLE_FAULT_IST}");

    // --- Displays: the VESA framebuffer, then PCI adapters (virtio-vga) -----
    display_demo(vesa, ecam);

    // --- Timers: calibrate TSC and APIC timer against the PIT ---------------
    // SAFETY: the PIT and port 0x61 belong to this kernel.
    let pit = Pit::new(unsafe { pit::Pio::new() });
    let tsc_hz = pit.calibrate(10_000_000, cpu::ticks);
    TSC_RATE.call_once(|| TickRate::new(tsc_hz));
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
        LAPIC.get().expect("LAPIC initialised").send_ipi(APIC_IDS[cpu].load(Ordering::Relaxed) as u8, IPI_VECTOR)
    });
    // SAFETY: the trampoline page is free low memory (reserved from the
    // allocator), mapped writable above; no AP is starting yet.
    unsafe { x86::smp::install() };
    for (cpu, apic_id) in APIC_IDS.iter().enumerate().take(ncpus).skip(1) {
        // In the kernel image, not the heap: the AP first runs on the boot
        // tables, which map only the first 4 GiB.
        // SAFETY: only the address is taken; this AP is its sole user.
        let stack = unsafe { &raw mut AP_STACKS[cpu - 1] };
        let boot = x86::smp::ApBoot {
            cr3: &raw const boot_pml4 as u64,
            stack_top: (stack as u64 + size_of::<ApStack>() as u64) & !15,
            entry: ap_start64 as *const () as u64,
            cpu,
        };
        // SAFETY: the trampoline is installed and the previous AP has
        // checked in (below); the boot tables identity-map it and the kernel.
        unsafe { apic.start_ap(apic_id.load(Ordering::Relaxed) as u8, &boot, |ns| pit.wait_ns(ns)) };
        // One AP at a time: they share the trampoline's slots. One that
        // never checks in ends the bring-up (it may still be in the
        // trampoline), so CPU indices stay dense.
        let deadline = now_ns() + 1_000_000_000;
        while ONLINE.load(Ordering::Acquire) <= cpu && now_ns() < deadline {
            core::hint::spin_loop();
        }
        if ONLINE.load(Ordering::Acquire) <= cpu {
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
    fault_demo();
    overflow_demo();
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
        FRAMES.lock().free_frames()
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
    let mut guard = PT.lock();
    let pt = guard.as_mut().expect("as_mut returned None");
    // Identity-maps device memory (the pages not mapped yet); returns a
    // window onto it.
    let mut map = |addr: u64, size: u64| {
        let end = (addr + size).next_multiple_of(PAGE_SIZE as u64);
        for page in (addr & !(PAGE_SIZE as u64 - 1)..end).step_by(PAGE_SIZE) {
            if pt.translate(VirtAddr::new(page)).is_none() {
                let flags = MapFlags::RW | MapFlags::DEVICE | MapFlags::GLOBAL;
                pt.map_range(VirtAddr::new(page), PhysAddr::new(page), PAGE_SIZE as u64, flags)
                    .expect("map_range failed");
            }
        }
        // SAFETY: just mapped as device memory; the demo owns the device.
        unsafe { IoMem::new(addr as *mut u8, size as usize) }
    };
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
    for (i, leaf) in (0x8000_0002..=0x8000_0004).enumerate() {
        let r = x86::cpuid(leaf, 0);
        for (j, w) in [r.eax, r.ebx, r.ecx, r.edx].into_iter().enumerate() {
            buf[i * 16 + j * 4..][..4].copy_from_slice(&w.to_le_bytes());
        }
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(48);
    core::str::from_utf8(&buf[..end]).unwrap_or("?").trim()
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
    let apic = LAPIC.get().expect("LAPIC initialised");
    apic.enable(SPURIOUS_VECTOR);
    osmium::sched::init_cpu();
    apic.start_timer(TIMER_VECTOR, APIC_TICK_COUNT.load(Ordering::Relaxed), true);
    irq::enable();
    println!("[smp]   APIC id {} online as CPU {cpu}", apic.id());
    ONLINE.fetch_add(1, Ordering::Release);
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

/// The last exception that `on_trap` recovered from.
static RECOVERED: [IrqSpinLock<Option<Trap>>; MAX_CPUS] = [const { IrqSpinLock::new(None) }; MAX_CPUS];
/// Whether this CPU expects a trap and may recover from it. Per CPU, so a real
/// fault on another CPU is never taken for the demo's.
static RECOVER: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// Runs `f`, which must take one breakpoint or page fault, with recovery armed
/// on this CPU only (interrupts off, so the task cannot migrate meanwhile).
/// Returns the trap that was recovered from.
fn recover_trap(f: impl FnOnce()) -> Trap {
    irq::without(|| {
        let cpu = cpu::current_id();
        RECOVER[cpu].store(true, Ordering::SeqCst);
        f();
        RECOVER[cpu].store(false, Ordering::SeqCst);
        RECOVERED[cpu].lock().take().expect("recovery recorded by the trap handler")
    })
}

fn fault_demo() {
    // SAFETY: the handler steps over the breakpoint.
    let t = recover_trap(|| unsafe { core::arch::asm!("int3") });
    println!("[trap]  recovered from {:?}", t);
    // The first 1 MiB is unmapped: a page fault.
    let t = recover_trap(|| {
        let v: u64;
        // SAFETY: the read faults and the handler skips it; the value is never used.
        unsafe { core::arch::asm!("mov {}, qword ptr [0x1000]", out(reg) v) };
        let _ = v;
    });
    println!("[trap]  recovered from {:?}", t);
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
    println!("[guard] the other tasks keep running: {}", alloc::format!("{} free frames", FRAMES.lock().free_frames()));
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
    h.route(index, gsi, false).expect("route was in the capability mask");
    let mode = osmium::sysdrv::ioapic::LineMode { active_low: false, level: false };
    ioapic.route(gsi as u32, HPET_VECTOR, LAPIC.get().expect("LAPIC initialised").id() as u8, mode);
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
    let timer = h.timer(index).expect("index was valid");
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
    let (producer, mut rx) = RX.split().expect("split returned None");
    *RX_PRODUCER.lock() = Some(producer);
    ioapic.route(gsi, COM1_VECTOR, LAPIC.get().expect("LAPIC initialised").id() as u8, mode);
    UART.get().expect("UART initialised").port().enable_rx_interrupt();
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

/// Where every user program is mapped, each in its own address space:
/// root entry 1 (512 GiB), outside the kernel's root entry 0.
const USER_BASE: u64 = 0x80_0000_0000;

/// A process's memory: a table sharing the kernel's root entry 0, with
/// table and user pages from `FRAMES`.
type Space = AddressSpace<X86_64, &'static Frames>;

fn new_space() -> Space {
    // SAFETY: the kernel table lives for the whole run.
    unsafe { Space::new(&FRAMES, PT.lock().as_ref().expect("as_ref returned None"), 0..1) }
        .expect("out of memory for a page table")
}

/// Copies a user program into fresh pages, maps it user-accessible (code
/// read/execute, stack read/write) at slot `n`, and spawns a task that drops
/// to ring 3 there.
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
    space.load_flat(code_va, &code, MapFlags::RX).expect("load_flat failed");
    space.map_anon(stack_va, PAGE_SIZE as u64, MapFlags::RW).expect("map_anon failed");
    let process = Process::new(name, space, USER_BASE + 0x10000);
    let task = process.spawn(TaskBuilder::new(name).cpu(cpu), move || {
        // SAFETY: CpuTables are loaded, the switch hook keeps rsp[0] on this
        // task's kernel stack, and both pages are mapped user-accessible.
        unsafe { x86::enter_user(code_va, stack_va + PAGE_SIZE as u64) }
    });
    (task, Arc::downgrade(&process))
}

/// The Rust user program, built by `build.rs`.
static HELLO_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/hello.elf"));

/// Loads an ELF executable into a new address space and spawns a task on
/// `cpu` that runs it in ring 3.
fn spawn_elf(name: &'static str, image: &[u8], cpu: usize) -> (Arc<Task>, Weak<Process>) {
    use osmium::boot::elf::{Elf, Machine};
    let elf = Elf::new(image).expect("bad user ELF");
    assert_eq!(elf.machine(), Machine::X86_64);
    let space = new_space();
    let brk = space.load_elf(&elf).expect("loading the user ELF failed");
    // A one-page stack just below 1 TiB, clear of the image.
    let stack_top = 0xff_0000_0000u64;
    space.map_anon(stack_top - PAGE_SIZE as u64, PAGE_SIZE as u64, MapFlags::RW).expect("map_anon failed");
    let entry = elf.entry();
    let process = Process::new(name, space, brk);
    process.set_mmap_area(0xa0_0000_0000..0xa1_0000_0000);
    let task = process.spawn(TaskBuilder::new(name).cpu(cpu), move || {
        // SAFETY: as for the hand-written programs: CpuTables are loaded, the
        // switch hook installs this process's table, and its pages are mapped.
        unsafe { x86::enter_user(entry, stack_top) }
    });
    (task, Arc::downgrade(&process))
}

/// The Rust program that forks and execs, from `examples/user/init.rs`.
static INIT_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/init.elf"));

/// What `fork` and `execve` need: spaces like `new_space`'s, and a stack
/// and `mmap` area where `spawn_elf` puts them.
fn platform() -> osmium::proc::Platform {
    osmium::proc::Platform {
        new_memory: || {
            // SAFETY: the kernel table lives for the whole run.
            let space = unsafe { Space::new(&FRAMES, PT.lock().as_ref().expect("as_ref returned None"), 0..1) };
            osmium::sync::fallible::try_box(space.map_err(|_| osmium::fs::Errno::ENOMEM)?)
                .map(|space| space as alloc::boxed::Box<dyn osmium::proc::UserMemory>)
                .map_err(|_| osmium::fs::Errno::ENOMEM)
        },
        // SAFETY: the table shares the kernel's root entry 0. Instruction
        // fetch is coherent with stores on x86, so nothing else is needed.
        activate: |root| unsafe { x86::write_cr3(root.0) },
        // SAFETY: the child's task is running with its table active (the
        // switch hook), and the frame is its parent's from a system call.
        resume: |frame| unsafe { x86::resume_user(&frame) },
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
        // SAFETY: exec activated the new table; CpuTables are loaded and the
        // switch hook keeps rsp[0] on this task's kernel stack.
        unsafe { x86::enter_user(entry.pc, entry.sp) }
    });
    drop(process);
    task.join();
    // The task holds the process: let it go too.
    drop(task);
    let freed = demos::user::freed(&[init]);
    println!("[user]  init and its children reaped; {freed} of 1 init address space torn down");
}

fn user_demo() {
    osmium::proc::set_platform(platform());
    // SAFETY: linker symbols delimiting the user programs.
    let (hello, bad) = unsafe { ((&user_hello, &user_hello_end), (&user_bad, &user_bad_end)) };
    // On another CPU: the syscall stub finds its kernel stack through that
    // CPU's GS base, which CPU 0 alone would not test.
    let cpu = 1 % ONLINE.load(Ordering::Acquire);
    println!("[user]  running 3 ring-3 programs on CPU {cpu}");
    let spawned = [
        spawn_user("user-1", 1, hello, cpu),
        spawn_user("user-2", 2, hello, cpu),
        spawn_user("user-bad", 3, bad, cpu),
        spawn_elf("user-elf", HELLO_ELF, cpu),
    ];
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

/// Handles `syscall` and `int 0x80` from ring 3.
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
        println!("[user]  {} killed: {cause:?} at rip {:#x}", task.name(), frame.pc());
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
    // A write to a page `fork` shares gets its own copy; retry.
    if let Trap::PageFault { addr, access: Access::Write } = frame.cause()
        && frame.from_user()
        && osmium::proc::handle_page_fault(addr as u64, true)
    {
        return;
    }
    if frame.from_user() && frame.vector() < 32 && frame.cause() != Trap::Syscall {
        let cause = frame.cause();
        return user_fault(frame, cause);
    }
    match (frame.vector(), frame.cause()) {
        (_, Trap::Syscall) if frame.from_user() => syscall(frame),
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
            LAPIC.get().expect("LAPIC initialised").eoi();
            on_timer();
            osmium::sched::preempt_if_needed();
        }
        (IPI_VECTOR, _) => {
            LAPIC.get().expect("LAPIC initialised").eoi();
            osmium::sched::preempt_if_needed();
        }
        (SHOOTDOWN_VECTOR, _) => {
            shootdown_service();
            LAPIC.get().expect("LAPIC initialised").eoi();
        }
        (HPET_VECTOR, _) => {
            HPET_FIRED.fetch_add(1, Ordering::SeqCst);
            LAPIC.get().expect("LAPIC initialised").eoi();
        }
        (COM1_VECTOR, _) => {
            // Drain the UART's FIFO into the ring, then wake the reader.
            if let Some(p) = RX_PRODUCER.lock().as_mut() {
                let mut port = UART.get().expect("UART initialised").port();
                while let Some(b) = osmium::hal::serial::SerialPort::read_byte(&mut *port) {
                    let _ = p.push(b);
                }
            }
            LAPIC.get().expect("LAPIC initialised").eoi();
            RX_READY.wake_all();
            osmium::sched::preempt_if_needed();
        }
        (msi::VECTOR, _) => msi::on_interrupt(),
        (usb::VECTOR, _) => usb::on_interrupt(),
        (SPURIOUS_VECTOR, _) => {}
        // A spurious IRQ from a masked PIC: no EOI (none was latched).
        (v, _) if PIC_VECTORS.contains(&v) => {}
        (_, cause @ (Trap::Breakpoint | Trap::PageFault { .. }))
            if RECOVER[cpu::current_id()].load(Ordering::SeqCst) =>
        {
            *RECOVERED[cpu::current_id()].lock() = Some(cause);
            // `int3` is 1 byte; the faulting `mov rax, [0x1000]` is 8.
            let len = if cause == Trap::Breakpoint { 1 } else { 8 };
            frame.set_pc(frame.pc() + len);
        }
        (v, cause) => {
            panic!("unhandled trap {cause:?} (vector {v}) at rip {:#x}, error {:#x}", frame.pc(), frame.error_code)
        }
    }
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
