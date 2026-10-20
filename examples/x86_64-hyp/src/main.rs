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
//! and asks to be shut down with `vmmcall`.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicBool, Ordering};
use core::ptr::NonNull;

use osmium::arch::trap::{self, TrapFrame};
use osmium::arch::x86_64 as x86;
use osmium::arch::{cpu, irq};
use osmium::boot::pvh::StartInfo;
use osmium::drivers::uart16550::{Pio, Uart16550};
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::{print, println};
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::X86_64;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sync::{IrqSpinLock, Once};
use osmium::virt::devices::{Uart16550 as Uart16550Model, VirtualPic};
use osmium::virt::x86::{self as svm, SvmPages, SvmVcpu};
use osmium::virt::{Bus, GuestMemory, GuestPhysAddr, VmExit, run_vcpu};

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
    mov $1, %eax                    // hypercall 1: power off
    vmmcall
5:  jmp 5b

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
received:
    .byte 0
    .balign 8
idt:
    .space 0x24 * 8
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

unsafe extern "C" {
    static _kernel_start: u8;
    static _kernel_end: u8;
    static x86_guest: u8;
    static x86_guest_end: u8;
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

    println!("[done]  {} free frames; shutting down", FRAMES.lock().free_frames());
    shutdown()
}

const GUEST_ENTRY: u64 = 0x10_0000;
const GUEST_MMIO_UART: u64 = 0xfed0_0000;
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
    let mmio = Bus::new();
    mmio.insert(GUEST_MMIO_UART, 8, Arc::new(Uart16550Model::new(console))).unwrap();

    let (vmcb, iopm, msrpm) = (block(0), block(2), block(1));
    // SAFETY: fresh blocks of at least the required sizes, owned by the vCPU.
    let mut vcpu = unsafe { SvmVcpu::new(SvmPages { vmcb, iopm, msrpm }, npt.root().0, GUEST_ENTRY as u32, len as u32) }
        .with_memory(mem.clone())
        .with_irq_line(intr);
    // The PIC's output is the vCPU's INTR line; delivery acknowledges it.
    let p = pic.clone();
    vcpu.connect_intr(move || p.acknowledge());
    let (mut hypercalls, mut halts) = (0, 0);
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { nr: 1, .. } => {
            hypercalls += 1;
            ControlFlow::Break(VmExit::Shutdown)
        }
        VmExit::Halt => {
            halts += 1;
            // The guest waits with interrupts on: "type" a key, which raises
            // COM1's IRQ 4 at the PIC.
            com1.push_input(b'k');
            if v.interrupt_pending() { ControlFlow::Continue(()) } else { ControlFlow::Break(VmExit::Halt) }
        }
        VmExit::ExternalInterrupt => ControlFlow::Continue(()),
        other => ControlFlow::Break(other),
    });
    println!(
        "[hyp]   guest exit {exit:?}: {hypercalls} hypercall, {halts} halt, LSR {:#x} (port) {:#x} (MMIO)",
        vcpu.regs.rdi, vcpu.regs.rcx
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
