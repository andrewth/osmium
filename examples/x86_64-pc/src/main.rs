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

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use osmium::arch::trap::{self, Trap, TrapFrame};
use osmium::arch::x86_64 as x86;
use osmium::arch::{MAX_CPUS, cpu, irq};
use osmium::boot::acpi::{Acpi, Madt};
use osmium::boot::pvh::StartInfo;
use osmium::drivers::lapic::{self, LocalApic};
use osmium::drivers::pit::{self, Pit};
use osmium::drivers::uart16550::{Pio, Uart16550};
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::timer::TickRate;
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::X86_64;
use osmium::mm::frame::order_for;
use osmium::mm::paging::PageSize;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use core::ptr::NonNull;

use osmium::sched::{FifoScheduler, StackAllocator, TaskBuilder};
use osmium::sched::timer::TimerQueue;
use osmium::sync::{IrqSpinLock, Once};

osmium::boot::pvh_entry_note!("pvh_start");

// 32-bit PVH entry: zero .bss, identity-map the first 4 GiB with 2 MiB
// pages, enter long mode with NX enabled, and call `kmain(start_info)`.
core::arch::global_asm!(
    r#"
    .section .text.entry, "ax"
    .code32
    .globl pvh_start
pvh_start:
    cli
    cld
    mov %ebx, %esi

    mov $_bss_start, %edi
    mov $_bss_end, %ecx
    sub %edi, %ecx
    shr $2, %ecx
    xor %eax, %eax
    rep stosl

    // PML4[0] -> PDPT; PDPT[0..4] -> PD[0..4]; PD entries map 2 MiB each.
    mov $boot_pdpt, %eax
    or $0x3, %eax
    mov %eax, boot_pml4
    mov $boot_pd, %eax
    or $0x3, %eax
    mov $boot_pdpt, %edi
    mov $4, %ecx
1:  mov %eax, (%edi)
    add $0x1000, %eax
    add $8, %edi
    loop 1b
    mov $boot_pd, %edi
    mov $0x83, %eax
    mov $2048, %ecx
2:  mov %eax, (%edi)
    add $0x200000, %eax
    add $8, %edi
    loop 2b

    mov $boot_pml4, %eax
    mov %eax, %cr3
    mov %cr4, %eax
    or $(1 << 5), %eax
    mov %eax, %cr4
    mov $0xc0000080, %ecx
    rdmsr
    or $((1 << 8) | (1 << 11)), %eax
    wrmsr
    mov %cr0, %eax
    or $((1 << 31) | (1 << 16) | 1), %eax
    mov %eax, %cr0

    lgdt boot_gdtr
    ljmp $0x08, $long_entry

    .code64
long_entry:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    xor %ax, %ax
    mov %ax, %fs
    mov %ax, %gs
    mov $boot_stack_top, %rsp
    mov %esi, %edi
    call kmain
3:  hlt
    jmp 3b

    // Application processors arrive here from the trampoline, still on the
    // boot page tables, with rdi = CPU index and rsp = their stack.
    .globl ap_start64
ap_start64:
    lgdt boot_gdtr
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    xor %ax, %ax
    mov %ax, %fs
    mov %ax, %gs
    pushq $0x08
    lea 4f(%rip), %rax
    push %rax
    lretq
4:  call ap_main
    jmp 3b

    .section .rodata
    .balign 8
boot_gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
boot_gdtr:
    .word boot_gdtr - boot_gdt - 1
    .quad boot_gdt

    .section .bss.boot, "aw", @nobits
    .balign 4096
boot_pml4: .space 4096
boot_pdpt: .space 4096
boot_pd:   .space 4096 * 4
    .space 65536
boot_stack_top:
"#,
    options(att_syntax)
);

// Real-mode AP trampoline. It is assembled here but runs as a copy at
// `TRAMPOLINE` (0x8000), so every absolute address is computed relative to
// that copy. Real mode -> protected mode -> long mode on the boot page tables,
// then a jump to `tramp_entry`.
core::arch::global_asm!(
    r#"
    .section .rodata.trampoline, "a"
    .code16
    .globl tramp_start
tramp_start:
    cli
    cld
    mov %cs, %ax
    mov %ax, %ds
    lgdtl tramp_gdtr - tramp_start
    mov %cr0, %eax
    or $1, %eax
    mov %eax, %cr0
    ljmpl $0x18, $(0x8000 + tramp_pm32 - tramp_start)

    .code32
tramp_pm32:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov 0x8000 + (tramp_cr3 - tramp_start), %eax
    mov %eax, %cr3
    mov %cr4, %eax
    or $(1 << 5), %eax
    mov %eax, %cr4
    mov $0xc0000080, %ecx
    rdmsr
    or $((1 << 8) | (1 << 11)), %eax
    wrmsr
    mov %cr0, %eax
    or $((1 << 31) | (1 << 16)), %eax
    mov %eax, %cr0
    ljmp $0x08, $(0x8000 + tramp_lm64 - tramp_start)

    .code64
tramp_lm64:
    mov 0x8000 + (tramp_stack - tramp_start), %rsp
    mov 0x8000 + (tramp_cpu - tramp_start), %rdi
    mov 0x8000 + (tramp_entry - tramp_start), %rax
    jmp *%rax

    .balign 8
tramp_gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00cf9a000000ffff
tramp_gdtr:
    .word 31
    .long 0x8000 + (tramp_gdt - tramp_start)
    .balign 8
    .globl tramp_cr3, tramp_stack, tramp_entry, tramp_cpu, tramp_end
tramp_cr3:   .quad 0
tramp_stack: .quad 0
tramp_entry: .quad 0
tramp_cpu:   .quad 0
tramp_end:
"#,
    options(att_syntax)
);

// User programs: position-independent ring-3 code, copied into user pages.
// System calls go through `int 0x80`: rax = number, rdi/rsi/rdx = arguments.
core::arch::global_asm!(
    r#"
    .section .rodata.user, "a"
    .globl user_hello, user_hello_end, user_bad, user_bad_end
user_hello:
    mov $3, %ebx
1:  lea 3f(%rip), %rsi
    mov $(4f - 3f), %edx
    mov $1, %edi
    mov $1, %eax              // write(1, msg, len)
    int $0x80
    mov $20000000, %ecx       // busy-wait without yielding: only the timer
2:  dec %ecx                  // can switch us out
    jnz 2b
    dec %ebx
    jnz 1b
    mov $60, %eax             // exit(0)
    xor %edi, %edi
    int $0x80
    ud2
3:  .ascii "hello from ring 3"
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
    static tramp_start: u8;
    static tramp_cr3: u8;
    static tramp_stack: u8;
    static tramp_entry: u8;
    static tramp_cpu: u8;
    static tramp_end: u8;
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
/// Physical address the AP trampoline is copied to (STARTUP vector 0x08).
const TRAMPOLINE: u64 = 0x8000;
const IPI_VECTOR: u8 = 33;
/// Vector for COM1's receive interrupt, routed through the I/O APIC.
const COM1_VECTOR: u8 = 40;
/// COM1's ISA IRQ.
const COM1_IRQ: u8 = 4;
const DOUBLE_FAULT: u8 = 8;
/// IST slot for the double-fault handler's stack.
const DOUBLE_FAULT_IST: u8 = 1;
const TIMER_VECTOR: u8 = 32;
const SPURIOUS_VECTOR: u8 = 0xff;
/// Timer interrupt period.
const TICK_NS: u64 = 10_000_000;

type Frames = LockedFrames<BuddyAllocator<OffsetMapper>, OffsetMapper>;

// SAFETY: the kernel runs identity-mapped, before and after switching tables.
static FRAMES: Frames = unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

/// The kernel page table, shared by all CPUs.
static PT: IrqSpinLock<Option<PageTable<X86_64, &'static Frames>>> = IrqSpinLock::new(None);

/// Gives this CPU its own GDT and TSS, with a fresh stack for double faults.
fn load_cpu_tables() {
    let tables = alloc::boxed::Box::leak(alloc::boxed::Box::new(x86::CpuTables::new()));
    let stack = alloc::vec![0u8; 16 * 1024].leak();
    tables.tss.ist[DOUBLE_FAULT_IST as usize - 1] = (stack.as_ptr() as u64 + stack.len() as u64) & !15;
    CPU_TABLES[cpu::current_id()].store(&raw mut *tables, Ordering::Relaxed);
    // SAFETY: called once per CPU, with interrupts disabled.
    irq::without(|| unsafe { tables.load() });
}

/// Each CPU's GDT and TSS, so the switch hook can update `rsp[0]`.
static CPU_TABLES: [core::sync::atomic::AtomicPtr<x86::CpuTables>; MAX_CPUS] =
    [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];

/// Points this CPU's TSS at the incoming task's kernel stack, where the CPU
/// will put the trap frame when that task traps out of ring 3.
fn on_switch(next: &osmium::sched::Task) {
    let tables = CPU_TABLES[cpu::current_id()].load(Ordering::Relaxed);
    if let (Some(top), false) = (next.kernel_stack_top(), tables.is_null()) {
        // SAFETY: this CPU's own tables; interrupts are off during a switch.
        unsafe { (*tables).tss.rsp[0] = top as u64 };
    }
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
        let mut pt = PT.lock();
        let (_, flush) = pt.as_mut()?.unmap_4k(VirtAddr::new(guard.0)).ok()?;
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

/// Received bytes, from the COM1 interrupt handler to the reader task.
static RX: osmium::sync::SpscRing<u8, 256> = osmium::sync::SpscRing::new();
static RX_PRODUCER: IrqSpinLock<Option<osmium::sync::Producer<'static, u8, 256>>> = IrqSpinLock::new(None);
static RX_READY: osmium::sched::WaitQueue = osmium::sched::WaitQueue::new();
/// First I/O APIC (address, first GSI) and COM1's line, from the MADT.
static IOAPIC_INFO: Once<(u64, u32, u32, osmium::drivers::ioapic::LineMode)> = Once::new();

static UART: Once<SerialConsole<Uart16550<Pio>>> = Once::new();
static LAPIC: Once<LocalApic> = Once::new();
static SCHED: FifoScheduler = FifoScheduler::new(2);
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
    TSC_RATE.get().unwrap().ticks_to_ns(cpu::ticks())
}

/// Powers QEMU off: ACPI PM1a control (q35/i440fx), then isa-debug-exit.
fn shutdown() -> ! {
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
    info.fill_memory_map(&mut map).unwrap();
    println!(
        "[pvh]   start info v{} at {start_info:#x}, {} memory-map entries, RSDP {:?}",
        info.version(),
        info.memory_map().count(),
        info.rsdp()
    );

    // --- CPUs from the ACPI MADT (read while the boot tables map it) ---------
    let my_apic = x86::cpuid(1, 0).ebx >> 24;
    APIC_IDS[0].store(my_apic, Ordering::Relaxed);
    let mut ncpus = 1;
    if let Some(rsdp) = info.rsdp() {
        // SAFETY: the boot tables identity-map the first 4 GiB, where QEMU's
        // ACPI tables live; they are only read here.
        let read = |pa: u64, len: usize| Some(unsafe { core::slice::from_raw_parts(pa as *const u8, len) });
        let madt = Acpi::new(rsdp.0, read).ok().and_then(|a| a.find(b"APIC")).and_then(Madt::parse);
        if let Some(m) = &madt
            && let Some(io) = m.io_apics().next()
        {
            let (gsi, active_low, level) = m.isa_irq(COM1_IRQ);
            IOAPIC_INFO.call_once(|| (io.addr, io.gsi_base, gsi, osmium::drivers::ioapic::LineMode { active_low, level }));
        }
        for c in madt.iter().flat_map(|m| m.local_apics()).filter(|c| c.enabled && c.apic_id != my_apic) {
            APIC_IDS[ncpus].store(c.apic_id, Ordering::Relaxed);
            ncpus += 1;
        }
    }
    println!("[acpi]  MADT lists {ncpus} enabled CPUs; this one is APIC id {my_apic}");

    // --- Physical memory ---------------------------------------------------
    // SAFETY: linker-provided symbols.
    let (kstart, etext, erodata, kend) =
        unsafe { (sym(&_kernel_start), sym(&_etext), sym(&_erodata), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).unwrap();
    map.page_align_usable();
    for r in map.regions() {
        println!("[mem]   {:#011x}..{:#011x} {:?}", r.start.0, r.end.0, r.kind);
    }
    let ram_end = map.usable().map(|r| r.end.0).max().unwrap();
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

    // --- Paging (4-level, W^X, NX) -----------------------------------------
    let mut pt: PageTable<X86_64, &'static Frames> = PageTable::new(&FRAMES).unwrap();
    let k = |f| f | MapFlags::GLOBAL;
    let va = |a: u64| VirtAddr::new(a);
    let pa = |a: u64| PhysAddr::new(a);
    // The first 1 MiB stays unmapped, so null-ish pointers fault.
    pt.map_range(va(0x10_0000), pa(0x10_0000), kstart - 0x10_0000, k(MapFlags::RW)).unwrap();
    pt.map_range(va(kstart), pa(kstart), etext - kstart, k(MapFlags::RX)).unwrap();
    pt.map_range(va(etext), pa(etext), erodata - etext, k(MapFlags::READ)).unwrap();
    pt.map_range(va(erodata), pa(erodata), ram_end - erodata, k(MapFlags::RW)).unwrap();
    pt.map_range(va(lapic::DEFAULT_BASE), pa(lapic::DEFAULT_BASE), PAGE_SIZE as u64, k(MapFlags::RW | MapFlags::DEVICE))
        .unwrap();
    if let Some(&(io, ..)) = IOAPIC_INFO.get() {
        pt.map_range(va(io), pa(io), PAGE_SIZE as u64, k(MapFlags::RW | MapFlags::DEVICE)).unwrap();
    }
    // Writable so the boot CPU can install the AP trampoline there.
    pt.map_range(va(TRAMPOLINE), pa(TRAMPOLINE), PAGE_SIZE as u64, k(MapFlags::RW)).unwrap();
    // SAFETY: the new table maps the running code, its stack, the heap and the APIC.
    unsafe { x86::write_cr3(pt.root().0) };
    CR3.store(pt.root().0, Ordering::Release);
    let t = pt.translate(va(kmain as *const () as u64)).unwrap();
    println!("[mmu]   CR3 {:#x}; kmain mapped {:?} via {:?} page", pt.root().0, t.flags, t.size);
    *PT.lock() = Some(pt);
    load_cpu_tables();
    // SAFETY: this CPU's TSS now has a double-fault stack; APs load theirs
    // before enabling interrupts.
    unsafe { trap::set_ist(DOUBLE_FAULT, DOUBLE_FAULT_IST) };
    osmium::sched::set_stack_allocator(&GuardedStacks);
    osmium::sched::set_switch_hook(on_switch);
    // SAFETY: the syscall handler treats every argument as untrusted.
    unsafe { trap::allow_from_user(trap::SYSCALL_VECTOR) };
    println!("[guard] task stacks get unmapped guard pages; double faults run on IST{DOUBLE_FAULT_IST}");

    // --- Timers: calibrate TSC and APIC timer against the PIT ---------------
    // SAFETY: the PIT and port 0x61 belong to this kernel.
    let pit = Pit::new(unsafe { pit::Pio::new() });
    let tsc_hz = pit.calibrate(10_000_000, cpu::ticks);
    TSC_RATE.call_once(|| TickRate::new(tsc_hz));
    // Mask the legacy 8259 PICs; the local APIC delivers everything.
    // SAFETY: the PIC data ports.
    unsafe {
        x86::outb(0x21, 0xff);
        x86::outb(0xa1, 0xff);
    }
    // SAFETY: the local APIC's default address, mapped uncached above.
    let apic = LAPIC.call_once(|| LocalApic::new(unsafe { IoMem::new(lapic::DEFAULT_BASE as *mut u8, PAGE_SIZE) }));
    apic.enable(SPURIOUS_VECTOR);
    apic.start_timer(TIMER_VECTOR, u32::MAX, false);
    let apic_hz = pit.calibrate(10_000_000, || u32::MAX as u64 - apic.timer_remaining() as u64);
    apic.stop_timer();
    println!("[timer] TSC {} MHz, APIC timer {} MHz (divided by 16), measured with the PIT", tsc_hz / 1_000_000, apic_hz / 1_000_000);

    // --- Scheduler ---------------------------------------------------------
    osmium::sched::inject_scheduler(&SCHED);
    osmium::sched::init_cpu();
    APIC_TICK_COUNT.store((apic_hz * TICK_NS / 1_000_000_000) as u32, Ordering::Relaxed);
    apic.start_timer(TIMER_VECTOR, APIC_TICK_COUNT.load(Ordering::Relaxed), true);
    irq::enable();
    println!("[sched] FIFO scheduler, {} ms tick, APIC id {}", TICK_NS / 1_000_000, apic.id());

    // --- Application processors (INIT, STARTUP, STARTUP) ---------------------
    osmium::sched::set_remote_wake_hook(|cpu| {
        LAPIC.get().unwrap().send_ipi(APIC_IDS[cpu].load(Ordering::Relaxed) as u8, IPI_VECTOR)
    });
    // Linker symbols delimiting the trampoline image and its slots.
    let (start, end) = (&raw const tramp_start as u64, &raw const tramp_end as u64);
    let slot = |s: *const u8| (TRAMPOLINE + (s as u64 - start)) as *mut u64;
    // SAFETY: the trampoline page is free low memory (reserved from the
    // allocator) mapped writable above; the image fits in one page.
    unsafe { core::ptr::copy_nonoverlapping(start as *const u8, TRAMPOLINE as *mut u8, (end - start) as usize) };
    for (cpu, apic_id) in APIC_IDS.iter().enumerate().take(ncpus).skip(1) {
        let stack = alloc::vec![0u8; 64 * 1024].leak();
        // SAFETY: slots inside the copied trampoline; the AP reads them
        // after STARTUP, which happens after these writes.
        unsafe {
            slot(&raw const tramp_cr3).write_volatile(&raw const boot_pml4 as u64);
            slot(&raw const tramp_stack).write_volatile((stack.as_ptr() as u64 + stack.len() as u64) & !15);
            slot(&raw const tramp_entry).write_volatile(ap_start64 as *const () as u64);
            slot(&raw const tramp_cpu).write_volatile(cpu as u64);
        }
        let id = apic_id.load(Ordering::Relaxed) as u8;
        apic.send_init(id);
        pit.wait_ns(10_000_000);
        for _ in 0..2 {
            apic.send_startup(id, (TRAMPOLINE >> 12) as u8);
            pit.wait_ns(200_000);
        }
        // One AP at a time: they share the trampoline's slots.
        while ONLINE.load(Ordering::Acquire) <= cpu {
            core::hint::spin_loop();
        }
    }
    println!("[smp]   {ncpus} CPUs online");

    demos::run_all(&demos::Env { timers: &TIMERS, ticks: &TICKS, now_ns });
    if ncpus > 1 {
        demos::smp(ncpus);
    }
    fault_demo();
    overflow_demo();
    user_demo();
    serial_demo();

    println!("[done]  {} timer ticks, {} free frames; shutting down", TICKS.load(Ordering::Relaxed), FRAMES.lock().free_frames());
    shutdown()
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
    load_cpu_tables();
    // SAFETY: we are on the stack the boot CPU allocated for us.
    unsafe { trap::install() };
    let apic = LAPIC.get().unwrap();
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
static RECOVERED: IrqSpinLock<Option<Trap>> = IrqSpinLock::new(None);
static RECOVER: AtomicBool = AtomicBool::new(false);

fn fault_demo() {
    RECOVER.store(true, Ordering::SeqCst);
    // SAFETY: the handler steps over the breakpoint.
    unsafe { core::arch::asm!("int3") };
    println!("[trap]  recovered from {:?}", RECOVERED.lock().take().unwrap());
    // The first 1 MiB is unmapped: a page fault.
    // SAFETY: the read faults and the handler skips it; the value is never used.
    let v: u64;
    unsafe { core::arch::asm!("mov {}, qword ptr [0x1000]", out(reg) v) };
    let _ = v;
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
    println!("[guard] the other tasks keep running: {}", alloc::format!("{} free frames", FRAMES.lock().free_frames()));
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
    let ioapic = osmium::drivers::ioapic::IoApic::new(unsafe { IoMem::new(io_addr as *mut u8, PAGE_SIZE) }, gsi_base);
    let (producer, mut rx) = RX.split().unwrap();
    *RX_PRODUCER.lock() = Some(producer);
    ioapic.route(gsi, COM1_VECTOR, LAPIC.get().unwrap().id() as u8, mode);
    UART.get().unwrap().port().enable_rx_interrupt();
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
        let got = RX_READY.wait_until(|| rx.pop().map(Some).or_else(|| timed_out.load(Ordering::Acquire).then_some(None)));
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

/// Where user programs are mapped; well above the identity-mapped RAM.
const USER_BASE: u64 = 0x4000_0000;

/// Copies a user program into fresh pages, maps it user-accessible (code
/// read/execute, stack read/write) at slot `n`, and spawns a task that drops
/// to ring 3 there.
fn spawn_user(name: &'static str, n: u64, code: (&u8, &u8)) -> alloc::sync::Arc<osmium::sched::Task> {
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
    }
    let (code_va, stack_va) = (USER_BASE + n * 0x10000, USER_BASE + n * 0x10000 + 0x8000);
    {
        let mut pt = PT.lock();
        let pt = pt.as_mut().unwrap();
        pt.map(VirtAddr::new(code_va), code_pa, PageSize::Size4K, MapFlags::RX | MapFlags::USER).unwrap().flush();
        pt.map(VirtAddr::new(stack_va), stack_pa, PageSize::Size4K, MapFlags::RW | MapFlags::USER).unwrap().flush();
    }
    TaskBuilder::new(name).spawn(move || {
        // SAFETY: CpuTables are loaded, the switch hook keeps rsp[0] on this
        // task's kernel stack, and both pages are mapped user-accessible.
        unsafe { x86::enter_user(code_va, stack_va + PAGE_SIZE as u64) }
    })
}

fn user_demo() {
    // SAFETY: linker symbols delimiting the user programs.
    let (hello, bad) = unsafe { ((&user_hello, &user_hello_end), (&user_bad, &user_bad_end)) };
    let tasks = [spawn_user("user-1", 0, hello), spawn_user("user-2", 1, hello), spawn_user("user-bad", 2, bad)];
    for t in tasks {
        t.join();
    }
}

/// Handles `int 0x80` from ring 3.
fn syscall(frame: &mut TrapFrame) {
    let [nr, a0, a1, a2, ..] = frame.syscall_args();
    let task = osmium::sched::current();
    match nr {
        // write(fd, buf, len): only stdout, only from user-accessible memory.
        1 if a0 == 1 && a2 <= 256 && user_readable(a1, a2) => {
            // SAFETY: every page of the buffer is mapped user-readable.
            let bytes = unsafe { core::slice::from_raw_parts(a1 as *const u8, a2 as usize) };
            println!("[user]  {}: {}", task.name(), core::str::from_utf8(bytes).unwrap_or("<not utf-8>"));
            frame.set_return(a2);
        }
        60 => {
            println!("[user]  {} exited with status {a0}", task.name());
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
    if frame.from_user() && frame.vector() < 32 && frame.cause() != Trap::Syscall {
        // A fault in user mode ends that task, not the kernel.
        let task = osmium::sched::current();
        println!("[user]  {} killed: {:?} at rip {:#x}", task.name(), frame.cause(), frame.pc());
        drop(task);
        osmium::sched::exit();
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
            LAPIC.get().unwrap().eoi();
            on_timer();
            osmium::sched::preempt_if_needed();
        }
        (IPI_VECTOR, _) => {
            LAPIC.get().unwrap().eoi();
            osmium::sched::preempt_if_needed();
        }
        (COM1_VECTOR, _) => {
            // Drain the UART's FIFO into the ring, then wake the reader.
            if let Some(p) = RX_PRODUCER.lock().as_mut() {
                let mut port = UART.get().unwrap().port();
                while let Some(b) = osmium::hal::serial::SerialPort::read_byte(&mut *port) {
                    let _ = p.push(b);
                }
            }
            LAPIC.get().unwrap().eoi();
            RX_READY.wake_all();
            osmium::sched::preempt_if_needed();
        }
        (SPURIOUS_VECTOR, _) => {}
        (_, cause @ (Trap::Breakpoint | Trap::PageFault { .. })) if RECOVER.load(Ordering::SeqCst) => {
            *RECOVERED.lock() = Some(cause);
            // `int3` is 1 byte; the faulting `mov rax, [0x1000]` is 8.
            let len = if cause == Trap::Breakpoint { 1 } else { 8 };
            frame.set_pc(frame.pc() + len);
        }
        (v, cause) => panic!("unhandled trap {cause:?} (vector {v}) at rip {:#x}, error {:#x}", frame.pc(), frame.error_code),
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    irq::disable();
    println!("\n[panic] {info}");
    shutdown()
}
