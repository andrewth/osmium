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

mod kernel;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU64, AtomicUsize, Ordering};

use osmium::arch::trap::{self, TrapFrame};
use osmium::arch::x86_64 as x86;
use osmium::arch::{cpu, irq};
use osmium::boot::acpi::{Acpi, Madt};
use osmium::boot::pvh::StartInfo;
use osmium::drivers::lapic::{self, LocalApic};
use osmium::drivers::pit::{Pio as PitPio, Pit};
use osmium::drivers::uart16550::{Pio, Uart16550};
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::mmio::IoMem;
use osmium::hal::{print, println};
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::X86_64;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sync::{IrqSpinLock, Once};
use osmium::virt::devices::{
    IOAPIC_WINDOW, IpiKind, IpiTarget, LAPIC_WINDOW, Uart16550 as Uart16550Model, VirtualIoApic, VirtualLapic,
    VirtualPic, VirtualPit, decode_icr,
};
use osmium::virt::smp::GuestCpus;
use osmium::virt::x86::{self as svm, SvmPages, SvmVcpu};
use osmium::virt::{Bus, GuestMemory, GuestPhysAddr, VmExit, run_vcpu};

osmium::boot::pvh_start!(kmain, ap: ap_main);

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
// takes three interrupts through a 64-bit IDT, then routes COM1's IRQ 4
// through the emulated I/O APIC and takes a received byte.
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
    // I/O APIC: COM1 (GSI 4) to vector 0x44 on APIC 0, edge, unmasked.
8:  mov $0xfec00000, %r8
    movl $0x18, (%r8)               // IOREGSEL: redirection entry 4, low
    movl $0x44, 0x10(%r8)           // IOWIN
    movl $0x19, (%r8)               // high: destination APIC 0
    movl $0, 0x10(%r8)
    mov $0x3f9, %dx                 // 16550 IER: receive interrupt
    mov $1, %al
    out %al, %dx
9:  sti
    hlt
    cli
    cmpb $0, lm_rx(%rip)
    je 9b
    lea 10f(%rip), %rsi
11: lodsb
    test %al, %al
    jz 12f
    mov %al, (%rbx)
    jmp 11b
12: movb lm_rx(%rip), %al
    mov %al, (%rbx)
    movb $0x0a, (%rbx)
    mov $1, %eax
    vmmcall
4:  jmp 4b

lm_com1:                            // COM1 via the I/O APIC: read, EOI
    push %rax
    push %rdx
    mov $0x3f8, %dx
    in %dx, %al
    movb %al, lm_rx(%rip)
    movl $0, 0xb0(%rdi)             // local APIC EOI
    pop %rdx
    pop %rax
    iretq

lm_timer:                           // APIC timer: count, EOI, return
    incl lm_ticks(%rip)
    movl $0, 0xb0(%rdi)             // EOI
    iretq

3:  .asciz "[guest] 64-bit, paging on, MMIO through the guest's page tables\n"
6:  .asciz "[guest] 3 local APIC timer interrupts through a 64-bit IDT\n"
10: .asciz "[guest] COM1 IRQ 4 through the I/O APIC, received: "
lm_rx:
    .byte 0
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
    .space 3 * 16
    .word (GBASE + lm_com1 - lm_guest) & 0xffff
    .word 0x08
    .word 0x8e00
    .word (GBASE + lm_com1 - lm_guest) >> 16
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
// spins with interrupts on, takes the IPI in its IDT, prints, and powers
// off. Each vCPU runs on its own host CPU.
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
    sti                             // wait for the AP's IPI in guest code
1:  cmpb $0, SBASE + smp_flag - smp_bsp // with no exits: only a kick of
    je 1b                           // this host CPU gets it in
    cli
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
    static boot_pml4: u8;
    fn ap_start64();
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
    // The AP trampoline's page (and the rest of low memory) stays out of the allocator.
    map.reserve(PhysAddr::new(0), PhysAddr::new(0x10_0000), RegionKind::Reserved).unwrap();
    // With enough RAM, so does the window for a guest kernel image (QEMU's
    // loader may have put one there).
    let top = map.regions().iter().map(|r| r.end.0).max().unwrap_or(0);
    let image_window = top >= kernel::IMAGE_BASE + kernel::IMAGE_WINDOW;
    if image_window {
        let (base, end) = (kernel::IMAGE_BASE, kernel::IMAGE_BASE + kernel::IMAGE_WINDOW);
        map.reserve(PhysAddr::new(base), PhysAddr::new(end), RegionKind::Reserved).unwrap();
    }
    let my_apic = x86::cpuid(1, 0).ebx >> 24;
    HOST_APIC_IDS[0].store(my_apic as u8, Ordering::Relaxed);
    let mut ncpus = 1;
    if let Some(rsdp) = info.rsdp() {
        // SAFETY: the boot tables identity-map the first 4 GiB, where QEMU's
        // ACPI tables live; they are only read here.
        let read = |pa: u64, len: usize| Some(unsafe { core::slice::from_raw_parts(pa as *const u8, len) });
        let madt = Acpi::new(rsdp.0, read).ok().and_then(|a| a.find(b"APIC")).and_then(Madt::parse);
        for c in madt.iter().flat_map(|m| m.local_apics()).filter(|c| c.enabled && c.apic_id != my_apic) {
            if ncpus < HOST_APIC_IDS.len() {
                HOST_APIC_IDS[ncpus].store(c.apic_id as u8, Ordering::Relaxed);
                ncpus += 1;
            }
        }
    }
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
    // Host interrupts: the 8259s masked, the local APIC on for kicks. The
    // host runs with interrupts enabled so a kick exits the guest.
    // SAFETY: the PIC data ports.
    unsafe {
        x86::outb(0x21, 0xff);
        x86::outb(0xa1, 0xff);
    }
    // SAFETY: the local APIC's default address, identity-mapped by the boot tables.
    let apic = LAPIC.call_once(|| LocalApic::new(unsafe { IoMem::new(lapic::DEFAULT_BASE as *mut u8, PAGE_SIZE) }));
    apic.enable(SPURIOUS_VECTOR);
    irq::enable();

    // A whole guest kernel if QEMU's loader provided one, else the demos.
    if let Some((elf, entry)) = image_window.then(kernel::image).flatten() {
        if ncpus > 1 {
            start_host_cpu(1);
        }
        kernel::boot(&elf, entry, ncpus);
    } else {
        guest_demo();
        long_mode_demo();
        if ncpus > 1 {
            start_host_cpu(1);
            smp_demo();
        } else {
            println!("[smp]   one host CPU: skipping the SMP guest (run QEMU with -smp 2)");
        }
    }

    println!("[done]  {} free frames; shutting down", FRAMES.lock().free_frames());
    shutdown()
}

const GUEST_ENTRY: u64 = 0x10_0000;
const GUEST_MMIO_UART: u64 = 0xfed0_0000;
const GUEST_LAPIC: u64 = 0xfee0_0000;
const GUEST_IOAPIC: u64 = 0xfec0_0000;
/// The emulated local APIC timer's input clock.
const LAPIC_TIMER_HZ: u64 = 100_000_000;

static TSC_HZ: AtomicU64 = AtomicU64::new(0);

static LAPIC: Once<LocalApic> = Once::new();
/// Host CPU index to local APIC ID.
static HOST_APIC_IDS: [AtomicU8; 2] = [const { AtomicU8::new(0) }; 2];
static ONLINE: AtomicUsize = AtomicUsize::new(1);
/// The vector one host CPU sends another to kick its vCPU out of guest code.
const KICK_VECTOR: u8 = 0xf0;
const SPURIOUS_VECTOR: u8 = 0xff;

/// Starts host CPU `cpu` through the shared trampoline and waits for it.
fn start_host_cpu(cpu: usize) {
    // SAFETY: low memory is reserved and identity-mapped writable; this is
    // the only AP start in flight.
    unsafe { x86::smp::install() };
    let stack = alloc::vec![0u8; 64 * 1024].leak();
    let boot = x86::smp::ApBoot {
        cr3: &raw const boot_pml4 as u64,
        stack_top: (stack.as_ptr() as u64 + stack.len() as u64) & !15,
        entry: ap_start64 as *const () as u64,
        cpu,
    };
    // SAFETY: nothing else uses the host's PIT.
    let pit = Pit::new(unsafe { PitPio::new() });
    let id = HOST_APIC_IDS[cpu].load(Ordering::Relaxed);
    // SAFETY: the trampoline is installed and no other AP is in it.
    unsafe { LAPIC.get().unwrap().start_ap(id, &boot, |ns| pit.wait_ns(ns)) };
    while ONLINE.load(Ordering::Acquire) <= cpu {
        core::hint::spin_loop();
    }
    println!("[smp]   host CPU {cpu} (APIC id {id}) online with SVM on");
}

/// Rust entry of the second host CPU: SVM on, then run vCPUs it is given.
#[unsafe(no_mangle)]
extern "C" fn ap_main(cpu: usize) -> ! {
    // SAFETY: the boot CPU hands out distinct indices.
    unsafe { cpu::set_current_id(cpu) };
    // SAFETY: we are on the stack the boot CPU allocated for us.
    unsafe { trap::install() };
    LAPIC.get().unwrap().enable(SPURIOUS_VECTOR);
    let hsave = FRAMES.lock().alloc(0).expect("host save area");
    svm::enable(hsave.0).expect("SVM on the second CPU");
    irq::enable();
    ONLINE.fetch_add(1, Ordering::Release);
    loop {
        // SAFETY: smp_demo publishes the VM only while it lives, and waits
        // for this CPU to let go before freeing it.
        if let Some(vm) = unsafe { SMP_VM.load(Ordering::Acquire).as_ref() } {
            vcpu_loop(vm, cpu);
            vm.released.store(true, Ordering::Release);
            while !SMP_VM.load(Ordering::Acquire).is_null() {
                core::hint::spin_loop();
            }
        }
        // SAFETY: kernel::boot publishes its VM only while it lives, and
        // waits for every vCPU loop to finish before dropping it.
        if let Some(vm) = unsafe { kernel::KERNEL_VM.load(Ordering::Acquire).as_ref() } {
            kernel::vcpu_loop(vm, cpu);
            while !kernel::KERNEL_VM.load(Ordering::Acquire).is_null() {
                core::hint::spin_loop();
            }
        }
        core::hint::spin_loop();
    }
}

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
    // COM1 -> I/O APIC input 4 -> local APIC. The I/O APIC holds the APIC
    // weakly: the APIC's EOI hook holds the I/O APIC.
    let ioapic: Arc<Once<Arc<VirtualIoApic>>> = Arc::new(Once::new());
    let io = ioapic.clone();
    let apic = Arc::new(
        VirtualLapic::new(0, LAPIC_TIMER_HZ, clock(), move |level| i.store(level, Ordering::Release))
            .with_eoi(move |v| io.get().unwrap().eoi(v)),
    );
    let a = Arc::downgrade(&apic);
    let ioapic = ioapic
        .call_once(|| {
            Arc::new(VirtualIoApic::new(0, move |m| {
                if let Some(a) = a.upgrade() {
                    a.deliver(m.vector)
                }
            }))
        })
        .clone();
    mmio.insert(GUEST_LAPIC, LAPIC_WINDOW, apic.clone()).unwrap();
    mmio.insert(GUEST_IOAPIC, IOAPIC_WINDOW, ioapic.clone()).unwrap();
    let io = ioapic.clone();
    let com1 = Arc::new(Uart16550Model::new(|_| {}).with_irq(move |level| io.set_level(4, level)));
    let pio = Bus::new();
    pio.insert(0x3f8, 8, com1.clone()).unwrap();

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
    let mut typed = false;
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { nr: 1, .. } => ControlFlow::Break(VmExit::Shutdown),
        VmExit::Halt => loop {
            // Once the timer is stopped the guest waits for COM1: type a key.
            if apic.next_deadline().is_none() && !typed {
                typed = true;
                com1.push_input(b'z');
            }
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

/// A two-vCPU guest shared by both host CPUs.
struct SmpVm {
    cpus: Arc<GuestCpus>,
    mem: Arc<GuestMemory>,
    ncr3: u64,
    ram_len: u64,
    pio: Bus,
    /// Per vCPU: its MMIO bus (its own local APIC), its INTR line, its APIC.
    buses: Vec<Bus>,
    lines: Vec<Arc<AtomicBool>>,
    apics: Arc<[Once<Arc<VirtualLapic>>; 2]>,
    done: AtomicBool,
    /// Set by the second host CPU once it has stopped touching the VM.
    released: AtomicBool,
}

static SMP_VM: AtomicPtr<SmpVm> = AtomicPtr::new(core::ptr::null_mut());

/// Runs vCPU `me` of `vm` on this host CPU whenever it is started, until
/// the guest is done.
fn vcpu_loop(vm: &SmpVm, me: usize) {
    while !vm.done.load(Ordering::Acquire) {
        let Some((entry, _)) = vm.cpus.take_start(me) else {
            core::hint::spin_loop();
            continue;
        };
        let (vmcb, iopm, msrpm, host) = (block(0), block(2), block(1), block(0));
        // SAFETY: fresh blocks of at least the required sizes, owned by the vCPU.
        let mut v =
            unsafe { SvmVcpu::new(SvmPages { vmcb, iopm, msrpm, host }, vm.ncr3, entry as u32, vm.ram_len as u32) }
                .with_memory(vm.mem.clone())
                .with_irq_line(vm.lines[me].clone());
        if me > 0 {
            v.set_real_mode((entry >> 12) as u8); // started by STARTUP
        }
        let a = vm.apics[me].get().unwrap().clone();
        v.connect_intr(move || a.acknowledge());
        vm.cpus.attach_svm(me, &mut v);
        let exit = run_vcpu(&mut v, &vm.buses[me], &vm.pio, |v, exit| match exit {
            VmExit::Hypercall { nr: 1 | 2, .. } => ControlFlow::Break(exit),
            VmExit::Halt => loop {
                if v.interrupt_pending() {
                    break ControlFlow::Continue(());
                }
                if vm.done.load(Ordering::Acquire) {
                    break ControlFlow::Break(VmExit::Halt);
                }
                core::hint::spin_loop();
            },
            // A kick: the next entry delivers what the APIC now has.
            VmExit::ExternalInterrupt => ControlFlow::Continue(()),
            other => ControlFlow::Break(other),
        });
        drop(v);
        // SAFETY: the vCPU that owned these blocks is gone.
        unsafe {
            let mut f = FRAMES.lock();
            f.dealloc(PhysAddr::new(vmcb.1), 0);
            f.dealloc(PhysAddr::new(iopm.1), 2);
            f.dealloc(PhysAddr::new(msrpm.1), 1);
            f.dealloc(PhysAddr::new(host.1), 0);
        }
        match exit {
            VmExit::Hypercall { nr: 2, .. } => vm.cpus.stopped(me),
            VmExit::Hypercall { nr: 1, .. } => vm.done.store(true, Ordering::Release),
            other => {
                println!("[hyp]   SMP vCPU {me} stopped unexpectedly: {other:?}");
                vm.done.store(true, Ordering::Release);
            }
        }
    }
}

/// Runs a two-vCPU guest whose BSP starts its AP with INIT and STARTUP
/// through emulated local APICs: vCPU 0 on this host CPU, vCPU 1 on host
/// CPU 1. The fixed IPI from vCPU 1 reaches vCPU 0 while it runs guest code
/// because the host kicks host CPU 0 with a physical IPI.
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

    // A vCPU's interrupt arriving while it runs guest code on another host
    // CPU kicks that CPU with a physical IPI, so the guest exits and the
    // next entry delivers it.
    let kicks = Arc::new(AtomicU64::new(0));
    let k = kicks.clone();
    let cpus = GuestCpus::with_kick(N, move |host| {
        k.fetch_add(1, Ordering::Relaxed);
        LAPIC.get().unwrap().send_ipi(HOST_APIC_IDS[host].load(Ordering::Relaxed), KICK_VECTOR);
    });
    // One local APIC per vCPU. An ICR write the sender cannot deliver
    // itself lands in the hook: STARTUP becomes a start request, a fixed
    // IPI is delivered to the target's APIC (kicking its vCPU).
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

    cpus.request_start(0, GUEST_ENTRY, 0).unwrap();
    let vm = SmpVm {
        cpus,
        mem: Arc::new(mem),
        ncr3: npt.root().0,
        ram_len: len,
        pio,
        buses,
        lines,
        apics,
        done: AtomicBool::new(false),
        released: AtomicBool::new(false),
    };
    SMP_VM.store(&raw const vm as *mut SmpVm, Ordering::Release);
    vcpu_loop(&vm, 0);
    while !vm.released.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    SMP_VM.store(core::ptr::null_mut(), Ordering::Release);
    println!(
        "[hyp]   SMP guest done: 2 vCPUs on host CPUs 0 and 1, {} kick(s); cpu 1 status {:?}",
        kicks.load(Ordering::Relaxed),
        vm.cpus.status(1)
    );

    drop(vm);
    drop(npt);
    // SAFETY: the guest has stopped; nothing references its RAM.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
}

fn on_trap(frame: &mut TrapFrame) {
    match frame.vector() {
        // A kick: taking it is all it is for (the guest has already exited).
        // A kick, or the host tick that makes a busy guest exit.
        KICK_VECTOR | kernel::HOST_TICK_VECTOR => return LAPIC.get().unwrap().eoi(),
        SPURIOUS_VECTOR => return,
        _ => {}
    }
    panic!("unexpected trap {:?} at rip {:#x}, error {:#x}", frame.cause(), frame.pc(), frame.error_code)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    irq::disable();
    println!("\n[panic] {info}");
    shutdown()
}
