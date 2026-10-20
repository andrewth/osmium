//! A small hypervisor for QEMU's x86_64 PC (q35) on AMD SVM, built from
//! Osmium components. QEMU loads the ELF through PVH; the kernel enables
//! SVM and runs a 32-bit protected-mode guest under nested paging.
//!
//! The guest prints through an emulated 16550 on port 0x3f8 (every port is
//! intercepted, so this is not the host's COM1), reads the UART's status
//! register, does the same with a second 16550 at a guest-physical address
//! the nested page table leaves unmapped (each access a nested page fault,
//! decoded and emulated), then programs an emulated 8259 PIC pair and an
//! IDT and takes COM1's receive interrupt (injected through `EVENTINJ`),
//! then counts ticks of an emulated 8254 PIT on IRQ 0, and asks to be
//! shut down with `vmmcall`.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use osmium::arch::trap::{self, TrapFrame};
use osmium::arch::x86_64 as x86;
use osmium::arch::{cpu, irq};
use osmium::boot::pvh::StartInfo;
use osmium::drivers::pit::{Pio as PitPio, Pit};
use osmium::drivers::uart16550::{Pio, Uart16550};
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::{print, println};
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::X86_64;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sync::{IrqSpinLock, Once};
use osmium::virt::devices::{
    IpiKind, IpiTarget, LAPIC_WINDOW, Uart16550 as Uart16550Model, VirtualLapic, VirtualPic, VirtualPit, decode_icr,
};
use osmium::virt::smp::GuestCpus;
use osmium::virt::x86::{self as svm, SvmPages, SvmVcpu};
use osmium::virt::{Bus, GuestMemory, GuestPhysAddr, VmExit, run_vcpu};

osmium::boot::pvh_start!(kmain);

// The guest: position-independent 32-bit code copied into guest RAM. It
// runs in protected mode with paging off, flat segments.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .globl x86_guest, x86_guest_end
    .code32
    .set GBASE, 0x100000            // where the host copies this code
x86_guest:
    call 1f
1:  pop %esi
    add $(4f - 1b), %esi
    mov $0x3f8, %dx
2:  lodsb
    test %al, %al
    jz 3f
    out %al, %dx                    // I/O exit
    jmp 2b
3:  mov $0x3fd, %dx
    in %dx, %al                     // I/O exit: LSR
    movzbl %al, %edi
    mov $0xfed00000, %ebx           // a second 16550, memory-mapped:
6:  lodsb                           // the next string follows the first
    test %al, %al
    jz 7f
    mov %al, (%ebx)                 // nested page fault -> MMIO write
    jmp 6b
7:  movzbl 5(%ebx), %ecx            // nested page fault -> MMIO read: LSR
    // 8259 PICs: master at vector 0x20, slave at 0x28; only IRQ 4 (COM1).
    mov $0x11, %al
    out %al, $0x20
    out %al, $0xa0
    mov $0x20, %al
    out %al, $0x21
    mov $0x28, %al
    out %al, $0xa1
    mov $4, %al
    out %al, $0x21
    mov $2, %al
    out %al, $0xa1
    mov $1, %al
    out %al, $0x21
    out %al, $0xa1
    mov $0xef, %al
    out %al, $0x21
    mov $0xff, %al
    out %al, $0xa1
    lgdt GBASE + gdtr - x86_guest   // interrupt delivery reloads CS from it
    lidt GBASE + idtr - x86_guest
    mov $0x3f9, %dx                 // 16550 IER: receive interrupt
    mov $1, %al
    out %al, %dx
8:  sti
    hlt                             // halt exit; the interrupt arrives here
    cli
    cmpb $0, GBASE + received - x86_guest
    je 8b
    mov $0x3f8, %dx                 // report it over port I/O
    mov $GBASE + 9f - x86_guest, %esi
10: lodsb
    test %al, %al
    jz 11f
    out %al, %dx
    jmp 10b
11: movb GBASE + received - x86_guest, %al
    out %al, %dx
    mov $0x0a, %al
    out %al, %dx
    // 8254 PIT channel 0: rate generator, 1193 ticks (1 ms); IRQ 0 on.
    mov $0x34, %al
    out %al, $0x43
    mov $(1193 & 0xff), %al
    out %al, $0x40
    mov $(1193 >> 8), %al
    out %al, $0x40
    mov $0xee, %al
    out %al, $0x21
12: sti
    hlt
    cli
    cmpb $5, GBASE + ticks - x86_guest
    jb 12b
    mov $0xff, %al                  // mask the PIC again
    out %al, $0x21
    mov $0x3f8, %dx
    mov $GBASE + 13f - x86_guest, %esi
14: lodsb
    test %al, %al
    jz 15f
    out %al, %dx
    jmp 14b
15: mov $1, %eax                    // hypercall 1: power off
    vmmcall
5:  jmp 5b

irq0:                               // PIT: count, EOI, return
    push %eax
    incb GBASE + ticks - x86_guest
    mov $0x20, %al
    out %al, $0x20
    pop %eax
    iret

irq4:                               // COM1: read the byte, EOI, return
    push %eax
    push %edx
    mov $0x3f8, %dx
    in %dx, %al
    movb %al, GBASE + received - x86_guest
    mov $0x20, %al
    out %al, $0x20
    pop %edx
    pop %eax
    iret

4:  .asciz "[guest] hello from SVM over port I/O\n"
    .asciz "[guest] and over MMIO (nested page faults)\n"
9:  .asciz "[guest] IRQ 4 through the 8259 PIC, received: "
13: .asciz "[guest] 5 ticks from the 8254 PIT on IRQ 0\n"
received:
    .byte 0
ticks:
    .byte 0
    .balign 8
idt:
    .space 0x20 * 8
    .word (GBASE + irq0 - x86_guest) & 0xffff
    .word 0x08
    .word 0x8e00
    .word (GBASE + irq0 - x86_guest) >> 16
    .space 3 * 8
    .word (GBASE + irq4 - x86_guest) & 0xffff
    .word 0x08                      // the guest's flat code segment
    .word 0x8e00                    // present, 32-bit interrupt gate
    .word (GBASE + irq4 - x86_guest) >> 16
idt_end:
idtr:
    .word idt_end - idt - 1
    .long GBASE + idt - x86_guest
    .balign 8
gdt:
    .quad 0
    .quad 0x00cf9a000000ffff         // 0x08: flat 32-bit code
    .quad 0x00cf92000000ffff         // 0x10: flat data
gdtr:
    .word gdtr - gdt - 1
    .long GBASE + gdt - x86_guest
x86_guest_end:
    .code64
"#,
    options(att_syntax)
);

// A 64-bit guest, entered directly in long mode on page tables the host
// built in its RAM. It prints through the MMIO 16550 (mapped in its own
// tables, unmapped in the nested ones), so every access is a nested page
// fault whose instruction is fetched through the guest's tables. Then it
// programs its emulated local APIC's timer (periodic, vector 0x40) and
// takes three interrupts through a 64-bit IDT.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .globl lm_guest, lm_guest_end
    .code64
    .set GBASE, 0x100000
lm_guest:
    lea 3f(%rip), %rsi
    mov $0xfed00000, %rbx
1:  lodsb
    test %al, %al
    jz 2f
    mov %al, (%rbx)                 // nested page fault -> MMIO write
    jmp 1b
2:  movzbq 5(%rbx), %r12            // MMIO read into a REX register
    lgdt lm_gdtr(%rip)
    mov $0x10, %ax
    mov %ax, %ss                    // iretq reloads SS from the GDT
    lidt lm_idtr(%rip)
    mov $0xfee00000, %rdi           // local APIC
    movl $0x1ff, 0xf0(%rdi)         // SVR: enabled, spurious vector 0xff
    movl $0xb, 0x3e0(%rdi)          // timer divide by 1
    movl $0x20040, 0x320(%rdi)      // LVT timer: periodic, vector 0x40
    movl $100000, 0x380(%rdi)       // initial count: 1 ms at 100 MHz
5:  sti
    hlt
    cli
    cmpl $3, lm_ticks(%rip)
    jb 5b
    movl $0, 0x380(%rdi)            // stop the timer
    lea 6f(%rip), %rsi
7:  lodsb
    test %al, %al
    jz 8f
    mov %al, (%rbx)
    jmp 7b
8:  mov $1, %eax
    vmmcall
4:  jmp 4b

lm_timer:                           // APIC timer: count, EOI, return
    incl lm_ticks(%rip)
    movl $0, 0xb0(%rdi)             // EOI
    iretq

3:  .asciz "[guest] 64-bit, paging on, MMIO through the guest's page tables\n"
6:  .asciz "[guest] 3 local APIC timer interrupts through a 64-bit IDT\n"
    .balign 4
lm_ticks:
    .long 0
    .balign 8
lm_gdt:
    .quad 0
    .quad 0x00af9a000000ffff         // 0x08: 64-bit code
    .quad 0x00cf92000000ffff         // 0x10: data
lm_gdtr:
    .word lm_gdtr - lm_gdt - 1
    .quad GBASE + lm_gdt - lm_guest
    .balign 16
lm_idt:
    .space 0x40 * 16
    .word (GBASE + lm_timer - lm_guest) & 0xffff
    .word 0x08
    .word 0x8e00                    // present, 64-bit interrupt gate
    .word (GBASE + lm_timer - lm_guest) >> 16
    .long 0
    .long 0
lm_idt_end:
lm_idtr:
    .word lm_idt_end - lm_idt - 1
    .quad GBASE + lm_idt - lm_guest
lm_guest_end:
"#,
    options(att_syntax)
);

// A two-vCPU guest started the PC way. The BSP (32-bit, at GBASE) enables
// its local APIC and sends the AP INIT and STARTUP with vector 8; the AP
// starts in real mode at 0x8000 (the host copies `smp_ap` there), prints,
// switches to protected mode, sends the BSP a fixed IPI (vector 0x41)
// through its own APIC's ICR, and asks to be stopped (hypercall 2). The BSP
// takes the IPI in its IDT, prints, and powers off.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .globl smp_bsp, smp_bsp_end, smp_ap, smp_ap_end
    .code32
    .set SBASE, 0x100000
smp_bsp:
    lgdt SBASE + smp_gdtr - smp_bsp
    lidt SBASE + smp_idtr - smp_bsp
    mov $0xfee00000, %edi           // local APIC
    movl $0x1ff, 0xf0(%edi)         // SVR: enabled
    movl $0x01000000, 0x310(%edi)   // ICR destination: APIC 1
    movl $0x00004500, 0x300(%edi)   // INIT
    movl $0x00004608, 0x300(%edi)   // STARTUP, vector 8: real mode at 0x8000
1:  sti
    hlt                             // wait for the AP's IPI
    cli
    cmpb $0, SBASE + smp_flag - smp_bsp
    je 1b
    mov $0x3f8, %dx
    mov $SBASE + 3f - smp_bsp, %esi
2:  lodsb
    test %al, %al
    jz 4f
    out %al, %dx
    jmp 2b
4:  mov $1, %eax                    // hypercall 1: power off
    vmmcall
5:  jmp 5b
smp_ipi:
    movb $1, SBASE + smp_flag - smp_bsp
    movl $0, 0xb0(%edi)             // EOI
    iret
3:  .asciz "[smp-guest] cpu 0: IPI 0x41 from cpu 1 through the local APICs\n"
smp_flag:
    .byte 0
    .balign 8
smp_gdt:
    .quad 0
    .quad 0x00cf9a000000ffff        // 0x08: flat 32-bit code
    .quad 0x00cf92000000ffff        // 0x10: flat data
smp_gdtr:
    .word smp_gdtr - smp_gdt - 1
    .long SBASE + smp_gdt - smp_bsp
    .balign 8
smp_idt:
    .space 0x41 * 8
    .word (SBASE + smp_ipi - smp_bsp) & 0xffff
    .word 0x08
    .word 0x8e00
    .word (SBASE + smp_ipi - smp_bsp) >> 16
smp_idt_end:
smp_idtr:
    .word smp_idt_end - smp_idt - 1
    .long SBASE + smp_idt - smp_bsp
smp_bsp_end:

    .code16
    .set ABASE, 0x8000
smp_ap:
    cli
    mov %cs, %ax
    mov %ax, %ds                    // DS = CS: offsets from smp_ap
    mov $0x3f8, %dx
    mov $(6f - smp_ap), %si
7:  lodsb
    test %al, %al
    jz 8f
    out %al, %dx
    jmp 7b
8:  lgdtl (smp_ap_gdtr - smp_ap)
    mov %cr0, %eax
    or $1, %eax
    mov %eax, %cr0                  // protected mode
    ljmpl $0x08, $(ABASE + 9f - smp_ap)
    .code32
9:  mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %ss
    movl $0, 0xfee00310             // ICR destination: APIC 0
    movl $0x41, 0xfee00300          // fixed IPI, vector 0x41
    mov $2, %eax                    // hypercall 2: stop this vCPU
    vmmcall
10: jmp 10b
6:  .asciz "[smp-guest] cpu 1: up in real mode at 0x8000 after INIT/STARTUP\n"
    .balign 8
smp_ap_gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
smp_ap_gdtr:
    .word smp_ap_gdtr - smp_ap_gdt - 1
    .long ABASE + smp_ap_gdt - smp_ap
smp_ap_end:
    .code64
"#,
    options(att_syntax)
);

unsafe extern "C" {
    static _kernel_start: u8;
    static _kernel_end: u8;
    static x86_guest: u8;
    static x86_guest_end: u8;
    static lm_guest: u8;
    static lm_guest_end: u8;
    static smp_bsp: u8;
    static smp_bsp_end: u8;
    static smp_ap: u8;
    static smp_ap_end: u8;
}

fn sym(s: &u8) -> u64 {
    s as *const u8 as u64
}

const COM1: u16 = 0x3f8;

type Frames = LockedFrames<BuddyAllocator<OffsetMapper>, OffsetMapper>;

// SAFETY: the kernel runs identity-mapped by the boot page tables.
static FRAMES: Frames = unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

static UART: Once<SerialConsole<Uart16550<Pio>>> = Once::new();

/// Powers QEMU off: ACPI PM1a control (q35), then isa-debug-exit.
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
    println!("\nosmium x86_64-hyp example");

    // SAFETY: QEMU passes a valid start-info structure, identity-mapped.
    let info = unsafe { StartInfo::from_ptr(start_info as *const u8) }.expect("bad PVH start info");
    let mut map = MemoryMap::<32>::new();
    info.fill_memory_map(&mut map).unwrap();
    // SAFETY: linker-provided symbols.
    let (kstart, kend) = unsafe { (sym(&_kernel_start), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).unwrap();
    map.page_align_usable();
    {
        let mut buddy = FRAMES.lock();
        for r in map.usable() {
            // SAFETY: the memory map says the range is free RAM, identity-mapped.
            unsafe { buddy.add_region(r.start, r.end) };
        }
        println!("[frame] {} free frames ({} MiB)", buddy.free_frames(), (buddy.free_frames() * PAGE_SIZE) >> 20);
    }
    HEAP.init(&FRAMES);

    let hsave = FRAMES.lock().alloc(0).expect("host save area");
    match svm::enable(hsave.0) {
        Ok(()) => println!("[svm]   SVM on, nested paging available, host save area {:#x}", hsave.0),
        Err(e) => {
            println!("[svm]   cannot enable SVM: {e:?} (run QEMU with -cpu max)");
            shutdown()
        }
    }
    guest_demo();
    long_mode_demo();
    smp_demo();

    println!("[done]  {} free frames; shutting down", FRAMES.lock().free_frames());
    shutdown()
}

const GUEST_ENTRY: u64 = 0x10_0000;
const GUEST_MMIO_UART: u64 = 0xfed0_0000;
const GUEST_LAPIC: u64 = 0xfee0_0000;
/// The emulated local APIC timer's input clock.
const LAPIC_TIMER_HZ: u64 = 100_000_000;

static TSC_HZ: AtomicU64 = AtomicU64::new(0);

/// Host time in nanoseconds for the emulated timers: the TSC, calibrated
/// once against the real PIT.
fn clock() -> impl Fn() -> u64 + Copy + Send + Sync + 'static {
    if TSC_HZ.load(Ordering::Relaxed) == 0 {
        // SAFETY: nothing else uses the host's PIT.
        TSC_HZ.store(unsafe { Pit::new(PitPio::new()) }.calibrate(10_000_000, cpu::ticks), Ordering::Relaxed);
    }
    let hz = TSC_HZ.load(Ordering::Relaxed) as u128;
    move || (cpu::ticks() as u128 * 1_000_000_000 / hz) as u64
}
const GUEST_RAM_ORDER: u32 = 9; // 2 MiB at guest-physical 0

/// One block of `order` frames as (host pointer, physical address).
fn block(order: u32) -> (NonNull<u8>, u64) {
    let pa = FRAMES.lock().alloc(order).expect("out of frames");
    (NonNull::new(pa.0 as *mut u8).unwrap(), pa.0)
}

fn guest_demo() {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GuestPhysAddr(0), ram.0 as *mut u8, len) };
    let mem = Arc::new(mem);
    // SAFETY: linker symbols bounding the guest image in .rodata.
    let image = unsafe {
        let start = &raw const x86_guest;
        core::slice::from_raw_parts(start, (&raw const x86_guest_end).offset_from(start) as usize)
    };
    mem.write(GuestPhysAddr(GUEST_ENTRY), image).unwrap();

    // Nested page table: guest-physical 0..2 MiB onto the block. NPT walks
    // are user accesses, so the leaves need USER.
    let mut npt: PageTable<X86_64, &'static Frames> = PageTable::new(&FRAMES).expect("NPT root");
    let flags = MapFlags::RW | MapFlags::EXEC | MapFlags::USER;
    npt.map_range(VirtAddr::new(0), PhysAddr::new(ram.0), len, flags).unwrap();

    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    let out = line.clone();
    let pio = Bus::new();
    let console = move |b| {
        let mut l = out.lock();
        l.push(b);
        if b == b'\n' {
            print!("{}", core::str::from_utf8(&l).unwrap_or("?\n"));
            l.clear();
        }
    };
    let intr = Arc::new(AtomicBool::new(false));
    let i = intr.clone();
    let pic = Arc::new(VirtualPic::new(move |level| i.store(level, Ordering::Release)));
    let p = pic.clone();
    let com1 = Arc::new(Uart16550Model::new(console.clone()).with_irq(move |level| p.set_level(4, level)));
    pio.insert(0x3f8, 8, com1.clone()).unwrap();
    pio.insert(0x20, 2, pic.master()).unwrap();
    pio.insert(0xa0, 2, pic.slave()).unwrap();
    let clock = clock();
    let p = pic.clone();
    let pit = Arc::new(VirtualPit::new(clock, move |level| p.set_level(0, level)));
    pio.insert(0x40, 4, pit.clone()).unwrap();
    let mmio = Bus::new();
    mmio.insert(GUEST_MMIO_UART, 8, Arc::new(Uart16550Model::new(console))).unwrap();

    let (vmcb, iopm, msrpm, host) = (block(0), block(2), block(1), block(0));
    // SAFETY: fresh blocks of at least the required sizes, owned by the vCPU.
    let mut vcpu =
        unsafe { SvmVcpu::new(SvmPages { vmcb, iopm, msrpm, host }, npt.root().0, GUEST_ENTRY as u32, len as u32) }
            .with_memory(mem.clone())
            .with_irq_line(intr);
    // The PIC's output is the vCPU's INTR line; delivery acknowledges it.
    let p = pic.clone();
    vcpu.connect_intr(move || p.acknowledge());
    let (mut hypercalls, mut halts, mut typed) = (0, 0, false);
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { nr: 1, .. } => {
            hypercalls += 1;
            ControlFlow::Break(VmExit::Shutdown)
        }
        VmExit::Halt => {
            halts += 1;
            // The guest waits with interrupts on. The first time, "type" a
            // key, which raises COM1's IRQ 4 at the PIC.
            if !typed {
                com1.push_input(b'k');
                typed = true;
            }
            // Then sleep until the PIT's next expiry: a host with other work
            // would arm a timer for the deadline and run something else.
            loop {
                pit.poll();
                if v.interrupt_pending() {
                    break ControlFlow::Continue(());
                }
                let Some(deadline) = pit.next_deadline() else { break ControlFlow::Break(VmExit::Halt) };
                while clock() < deadline {
                    core::hint::spin_loop();
                }
            }
        }
        VmExit::ExternalInterrupt => ControlFlow::Continue(()),
        other => ControlFlow::Break(other),
    });
    println!(
        "[hyp]   guest exit {exit:?}: {hypercalls} hypercall, LSR {:#x} (port) {:#x} (MMIO); {halts} halts, TSC {} MHz",
        vcpu.regs.rdi,
        vcpu.regs.rcx,
        TSC_HZ.load(Ordering::Relaxed) / 1_000_000
    );

    drop(vcpu);
    drop(npt);
    drop(mem);
    // SAFETY: the guest has stopped; nothing references these blocks.
    unsafe {
        let mut f = FRAMES.lock();
        f.dealloc(PhysAddr::new(vmcb.1), 0);
        f.dealloc(PhysAddr::new(iopm.1), 2);
        f.dealloc(PhysAddr::new(msrpm.1), 1);
        f.dealloc(PhysAddr::new(host.1), 0);
        f.dealloc(ram, GUEST_RAM_ORDER);
    }
}

/// Runs a 64-bit guest with paging on: long mode set up in the VMCB, page
/// tables built by the host in guest RAM.
fn long_mode_demo() {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GuestPhysAddr(0), ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the guest image in .rodata.
    let image = unsafe {
        let start = &raw const lm_guest;
        core::slice::from_raw_parts(start, (&raw const lm_guest_end).offset_from(start) as usize)
    };
    mem.write(GuestPhysAddr(GUEST_ENTRY), image).unwrap();
    // Guest page tables: PML4 0x1000 -> PDPT 0x2000. PDPT[0] -> PD 0x3000
    // mapping 0..2 MiB (RAM); PDPT[3] -> PD 0x4000 mapping the 2 MiB page
    // holding the MMIO UART, uncached.
    let pte = |gpa: u64, v: u64| mem.write_obj(GuestPhysAddr(gpa), v).unwrap();
    pte(0x1000, 0x2003);
    pte(0x2000, 0x3003);
    pte(0x2000 + 3 * 8, 0x4003);
    pte(0x3000, 0x83);
    let uart_page = GUEST_MMIO_UART & !0x1f_ffff;
    pte(0x4000 + ((GUEST_MMIO_UART >> 21) & 0x1ff) * 8, uart_page | 0x9b); // P, RW, PWT, PCD, PS
    pte(0x4000 + ((GUEST_LAPIC >> 21) & 0x1ff) * 8, (GUEST_LAPIC & !0x1f_ffff) | 0x9b);
    let mem = Arc::new(mem);

    let mut npt: PageTable<X86_64, &'static Frames> = PageTable::new(&FRAMES).expect("NPT root");
    npt.map_range(VirtAddr::new(0), PhysAddr::new(ram.0), len, MapFlags::RW | MapFlags::EXEC | MapFlags::USER).unwrap();

    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    let out = line.clone();
    let mmio = Bus::new();
    let uart = Uart16550Model::new(move |b| {
        let mut l = out.lock();
        l.push(b);
        if b == b'\n' {
            print!("{}", core::str::from_utf8(&l).unwrap_or("?\n"));
            l.clear();
        }
    });
    mmio.insert(GUEST_MMIO_UART, 8, Arc::new(uart)).unwrap();
    let intr = Arc::new(AtomicBool::new(false));
    let i = intr.clone();
    let apic = Arc::new(VirtualLapic::new(0, LAPIC_TIMER_HZ, clock(), move |level| i.store(level, Ordering::Release)));
    mmio.insert(GUEST_LAPIC, LAPIC_WINDOW, apic.clone()).unwrap();
    let pio = Bus::new();

    let (vmcb, iopm, msrpm, host) = (block(0), block(2), block(1), block(0));
    // SAFETY: fresh blocks of at least the required sizes, owned by the vCPU.
    let mut vcpu =
        unsafe { SvmVcpu::new(SvmPages { vmcb, iopm, msrpm, host }, npt.root().0, GUEST_ENTRY as u32, len as u32) }
            .with_memory(mem.clone())
            .with_irq_line(intr);
    vcpu.set_long_mode(0x1000);
    let a = apic.clone();
    vcpu.connect_intr(move || a.acknowledge());
    let now = clock();
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { nr: 1, .. } => ControlFlow::Break(VmExit::Shutdown),
        VmExit::Halt => loop {
            apic.poll();
            if v.interrupt_pending() {
                break ControlFlow::Continue(());
            }
            let Some(deadline) = apic.next_deadline() else { break ControlFlow::Break(VmExit::Halt) };
            while now() < deadline {
                core::hint::spin_loop();
            }
        },
        VmExit::ExternalInterrupt => ControlFlow::Continue(()),
        other => ControlFlow::Break(other),
    });
    println!("[hyp]   64-bit guest exit {exit:?}, LSR {:#x} in r12", vcpu.regs.r12);

    drop(vcpu);
    drop(npt);
    drop(mem);
    // SAFETY: the guest has stopped; nothing references these blocks.
    unsafe {
        let mut f = FRAMES.lock();
        f.dealloc(PhysAddr::new(vmcb.1), 0);
        f.dealloc(PhysAddr::new(iopm.1), 2);
        f.dealloc(PhysAddr::new(msrpm.1), 1);
        f.dealloc(PhysAddr::new(host.1), 0);
        f.dealloc(ram, GUEST_RAM_ORDER);
    }
}

/// The bytes between two linker symbols.
fn image(start: &u8, end: &u8) -> &'static [u8] {
    // SAFETY: symbol pairs bounding images in .rodata.
    unsafe { core::slice::from_raw_parts(start, (end as *const u8).offset_from(start) as usize) }
}

/// Runs a two-vCPU guest whose BSP starts its AP with INIT and STARTUP
/// through emulated local APICs. Both vCPUs share this host CPU: each runs
/// until it halts with nothing to do, then the other gets a turn.
fn smp_demo() {
    const N: usize = 2;
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GuestPhysAddr(0), ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the two images.
    let (bsp, ap) = unsafe { (image(&smp_bsp, &smp_bsp_end), image(&smp_ap, &smp_ap_end)) };
    mem.write(GuestPhysAddr(GUEST_ENTRY), bsp).unwrap();
    mem.write(GuestPhysAddr(0x8000), ap).unwrap();
    let mem = Arc::new(mem);
    let mut npt: PageTable<X86_64, &'static Frames> = PageTable::new(&FRAMES).expect("NPT root");
    npt.map_range(VirtAddr::new(0), PhysAddr::new(ram.0), len, MapFlags::RW | MapFlags::EXEC | MapFlags::USER).unwrap();

    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    let com1 = Arc::new(Uart16550Model::new(move |b| {
        let mut l = line.lock();
        l.push(b);
        if b == b'\n' {
            print!("{}", core::str::from_utf8(&l).unwrap_or("?\n"));
            l.clear();
        }
    }));
    let pio = Bus::new();
    pio.insert(0x3f8, 8, com1).unwrap();

    // One local APIC per vCPU. An ICR write the sender cannot deliver
    // itself lands in the hook: STARTUP becomes a start request, a fixed
    // IPI is delivered to the target's APIC.
    let cpus = GuestCpus::new(N);
    let apics: Arc<[Once<Arc<VirtualLapic>>; N]> = Arc::new([const { Once::new() }; N]);
    let lines: Vec<Arc<AtomicBool>> = (0..N).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let mut buses = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        // Weak: the APICs hold these hooks, so a strong reference would be a cycle.
        let (l, c, a) = (l.clone(), cpus.clone(), Arc::downgrade(&apics));
        let apic = VirtualLapic::new(i as u8, LAPIC_TIMER_HZ, clock(), move |level| l.store(level, Ordering::Release))
            .with_ipi(move |high, low| match decode_icr(high, low) {
                (IpiTarget::Apic(n), IpiKind::Startup(page)) => {
                    let _ = c.request_start(n as usize, (page as u64) << 12, 0);
                }
                (IpiTarget::Apic(n), IpiKind::Fixed(v)) => {
                    if let Some(apic) = a.upgrade().and_then(|a| a.get(n as usize).and_then(|o| o.get()).cloned()) {
                        apic.deliver(v);
                        c.kick(n as usize);
                    }
                }
                _ => {} // INIT: the target is already waiting for STARTUP
            });
        let apic = apics[i].call_once(|| Arc::new(apic)).clone();
        let mmio = Bus::new();
        mmio.insert(GUEST_LAPIC, LAPIC_WINDOW, apic).unwrap();
        buses.push(mmio);
    }

    let mut pages = Vec::new();
    let mut make = |i: usize, entry: u32| {
        let p = (block(0), block(2), block(1), block(0));
        pages.push(p);
        let (vmcb, iopm, msrpm, host) = p;
        // SAFETY: fresh blocks of at least the required sizes, owned by the vCPU.
        let mut v = unsafe { SvmVcpu::new(SvmPages { vmcb, iopm, msrpm, host }, npt.root().0, entry, len as u32) }
            .with_memory(mem.clone())
            .with_irq_line(lines[i].clone());
        let a = apics[i].get().unwrap().clone();
        v.connect_intr(move || a.acknowledge());
        cpus.attach_svm(i, &mut v);
        v
    };
    cpus.request_start(0, GUEST_ENTRY, 0).unwrap();
    let mut vcpus: [Option<SvmVcpu>; N] = [const { None }; N];
    let mut switches = 0;
    let result = 'outer: loop {
        for i in 0..N {
            if vcpus[i].is_none() {
                let Some((entry, _)) = cpus.take_start(i) else { continue };
                let mut v = make(i, entry as u32);
                if i > 0 {
                    v.set_real_mode((entry >> 12) as u8);
                }
                vcpus[i] = Some(v);
            }
            let v = vcpus[i].as_mut().unwrap();
            switches += 1;
            let exit = run_vcpu(v, &buses[i], &pio, |v, exit| match exit {
                VmExit::Hypercall { nr: 1 | 2, .. } => ControlFlow::Break(exit),
                VmExit::Halt if v.interrupt_pending() => ControlFlow::Continue(()),
                VmExit::ExternalInterrupt => ControlFlow::Continue(()),
                other => ControlFlow::Break(other),
            });
            match exit {
                VmExit::Hypercall { nr: 1, .. } => break 'outer VmExit::Shutdown,
                VmExit::Hypercall { nr: 2, .. } => {
                    vcpus[i] = None;
                    cpus.stopped(i);
                }
                VmExit::Halt => {} // the other vCPU's turn
                other => break 'outer other,
            }
        }
    };
    println!(
        "[hyp]   SMP guest exit {result:?}: {N} vCPUs on one host CPU, {switches} turns; cpu 1 status {:?}",
        cpus.status(1)
    );

    drop(vcpus);
    drop(buses);
    drop(apics);
    drop(npt);
    drop(mem);
    // SAFETY: the guest has stopped; nothing references these blocks.
    unsafe {
        let mut f = FRAMES.lock();
        for (vmcb, iopm, msrpm, host) in pages {
            f.dealloc(PhysAddr::new(vmcb.1), 0);
            f.dealloc(PhysAddr::new(iopm.1), 2);
            f.dealloc(PhysAddr::new(msrpm.1), 1);
            f.dealloc(PhysAddr::new(host.1), 0);
        }
        f.dealloc(ram, GUEST_RAM_ORDER);
    }
}

fn on_trap(frame: &mut TrapFrame) {
    panic!("unexpected trap {:?} at rip {:#x}, error {:#x}", frame.cause(), frame.pc(), frame.error_code)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    irq::disable();
    println!("\n[panic] {info}");
    shutdown()
}
