//! A small hypervisor for an x86_64 PC (q35) on Intel VMX, built from
//! Osmium components. QEMU loads the ELF through PVH; the kernel enables VMX
//! and runs a 32-bit protected-mode guest under EPT.
//!
//! The guest prints through an emulated 16550 on port 0x3f8 (every port is
//! intercepted), does the same through a second 16550 at a guest-physical
//! address the EPT leaves unmapped (each access an EPT violation, decoded and
//! emulated), reads CPUID, round-trips an MSR, turns on paging and long
//! mode itself, and asks to be shut down with `vmcall`.
//!
//! VMX needs real hardware or nested virtualization: QEMU's TCG does not
//! emulate it. Run with `-accel kvm -cpu host` on an Intel host.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;
use core::ptr::NonNull;

use osmium::arch::trap::{self, TrapFrame};
use osmium::arch::x86_64 as x86;
use osmium::arch::{cpu, irq};
use osmium::boot::pvh::StartInfo;
use osmium::drivers::uart16550::{Pio, Uart16550};
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::{print, println};
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::Ept;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sync::{IrqSpinLock, Once};
use osmium::virt::devices::Uart16550 as Uart16550Model;
use osmium::virt::stage2::eptp;
use osmium::virt::x86::vmx::{self, VmxPages, VmxVcpu};
use osmium::virt::{Bus, GuestMemory, GuestPhysAddr, VmExit, run_vcpu};

osmium::boot::pvh_start!(kmain);

// The guest: position-independent 32-bit code copied into guest RAM at
// GUEST_ENTRY. Protected mode, paging off, flat segments.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .globl vmx_guest, vmx_guest_end
    .code32
vmx_guest:
    call 1f
1:  pop %esi
    add $(9f - 1b), %esi
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
4:  lodsb                           // the next string follows the first
    test %al, %al
    jz 5f
    mov %al, (%ebx)                 // EPT violation -> MMIO write
    jmp 4b
5:  movzbl 5(%ebx), %ebx            // EPT violation -> MMIO read: LSR
    push %ebx                       // cpuid clobbers ebx
    xor %eax, %eax
    cpuid                           // CPUID exit; VMX must be hidden
    mov $1, %eax
    cpuid
    mov %ecx, %ebp
    pop %ebx
    mov $0xc0000102, %ecx           // IA32_KERNEL_GS_BASE round trip
    mov $0x12345678, %eax
    xor %edx, %edx
    wrmsr
    xor %eax, %eax
    rdmsr
    mov %eax, %esi
    mov $1, %eax                    // vmcall 1: done (edi, ebx, ebp, esi report)
    vmcall
6:  hlt
    jmp 6b
9:  .asciz "[guest] hello from VMX over port I/O\n"
    .asciz "[guest] and over MMIO (EPT violations)\n"
vmx_guest_end:
    .code64
"#,
    options(att_syntax)
);

unsafe extern "C" {
    static vmx_guest: u8;
    static vmx_guest_end: u8;
    static _kernel_start: u8;
    static _kernel_end: u8;
}

fn sym(s: &u8) -> u64 {
    s as *const u8 as u64
}

const COM1: u16 = 0x3f8;
const GUEST_ENTRY: u64 = 0x1000;
const GUEST_MMIO_UART: u64 = 0xfed0_0000;
const GUEST_RAM_ORDER: u32 = 9; // 2 MiB

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

/// One block of `order` frames as (host pointer, physical address).
fn block(order: u32) -> (NonNull<u8>, u64) {
    let pa = FRAMES.lock().alloc(order).expect("out of frames");
    (NonNull::new(pa.0 as *mut u8).unwrap(), pa.0)
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
    println!("\nosmium x86_64-vmx example");

    // SAFETY: QEMU passes a valid start-info structure, identity-mapped.
    let info = unsafe { StartInfo::from_ptr(start_info as *const u8) }.expect("bad PVH start info");
    let mut map = MemoryMap::<32>::new();
    info.fill_memory_map(&mut map).unwrap();
    // SAFETY: linker-provided symbols.
    let (kstart, kend) = unsafe { (sym(&_kernel_start), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).unwrap();
    map.reserve(PhysAddr::new(0), PhysAddr::new(0x10_0000), RegionKind::Reserved).unwrap();
    map.page_align_usable();
    {
        let mut buddy = FRAMES.lock();
        // Only what PVH's boot tables identity-map (the first 4 GiB).
        const BOOT_MAPPED: u64 = 1 << 32;
        for r in map.usable().filter(|r| r.start.0 < BOOT_MAPPED) {
            // SAFETY: the memory map says the range is free RAM, identity-mapped.
            unsafe { buddy.add_region(r.start, PhysAddr::new(r.end.0.min(BOOT_MAPPED))) };
        }
        println!("[frame] {} free frames ({} MiB)", buddy.free_frames(), (buddy.free_frames() * PAGE_SIZE) >> 20);
    }
    HEAP.init(&FRAMES);

    // VM exit restores the host's task register, so the host needs a TSS.
    let tables = alloc::boxed::Box::leak(alloc::boxed::Box::new(x86::CpuTables::new()));
    // SAFETY: this CPU's own tables, loaded once with interrupts off.
    unsafe { tables.load() };
    match vmx::enable(block(0)) {
        Ok(()) => println!("[vmx]   VMX on: EPT, VPID and unrestricted guest available"),
        Err(e) => {
            println!("[vmx]   cannot enable VMX: {e:?} (run QEMU with -accel kvm -cpu host on an Intel host)");
            shutdown()
        }
    }
    // Host interrupts: the 8259s masked. The host runs with interrupts
    // enabled, as a real one would, so a host interrupt exits the guest.
    // SAFETY: the PIC data ports.
    unsafe {
        x86::outb(0x21, 0xff);
        x86::outb(0xa1, 0xff);
    }
    irq::enable();

    guest_demo();
    println!("[done]");
    shutdown()
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
        let start = &raw const vmx_guest;
        core::slice::from_raw_parts(start, (&raw const vmx_guest_end).offset_from(start) as usize)
    };
    mem.write(GuestPhysAddr(GUEST_ENTRY), image).unwrap();

    let mut ept: PageTable<Ept, &'static Frames> = PageTable::new(&FRAMES).expect("EPT root");
    ept.map_range(VirtAddr::new(0), PhysAddr::new(ram.0), len, MapFlags::RW | MapFlags::EXEC).unwrap();

    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    let out = line.clone();
    let console = move |b| {
        let mut l = out.lock();
        l.push(b);
        if b == b'\n' {
            print!("{}", core::str::from_utf8(&l).unwrap_or("?\n"));
            l.clear();
        }
    };
    let pio = Bus::new();
    pio.insert(0x3f8, 8, Arc::new(Uart16550Model::new(console.clone()))).unwrap();
    let mmio = Bus::new();
    mmio.insert(GUEST_MMIO_UART, 8, Arc::new(Uart16550Model::new(console))).unwrap();

    let (vmcs, msr_bitmap, msr_area) = (block(0), block(0), block(0));
    // SAFETY: fresh blocks of the required size, owned by the vCPU.
    let mut vcpu = unsafe {
        VmxVcpu::new(VmxPages { vmcs, msr_bitmap, msr_area }, eptp(ept.root()), GUEST_ENTRY as u32, len as u32)
    }
    .with_memory(mem.clone());
    let mut hypercalls = 0;
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |_, exit| match exit {
        VmExit::Hypercall { nr: 1, .. } => {
            hypercalls += 1;
            ControlFlow::Break(VmExit::Shutdown)
        }
        VmExit::ExternalInterrupt => ControlFlow::Continue(()),
        other => ControlFlow::Break(other),
    });
    let r = &vcpu.regs;
    println!(
        "[hyp]   guest exit {exit:?}: {hypercalls} hypercall, LSR {:#x} (port) {:#x} (MMIO); KERNEL_GS_BASE {:#x}",
        r.rdi, r.rbx, r.rsi
    );
    // CPUID.1:ECX as the guest saw it: hypervisor bit set, VMX (bit 5) clear.
    println!(
        "[hyp]   guest CPUID.1:ECX {:#x}: VMX {}",
        r.rbp,
        if r.rbp & (1 << 5) == 0 { "hidden" } else { "VISIBLE" }
    );
    if exit != VmExit::Shutdown {
        println!("[hyp]   entry error {:#x}", vcpu.instruction_error());
    }
    drop(vcpu);
    drop(ept);
    drop(mem);
}

fn on_trap(frame: &mut TrapFrame) {
    panic!("unexpected trap {:?} at rip {:#x}, error {:#x}", frame.cause(), frame.pc(), frame.error_code)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("panic: {info}");
    shutdown()
}
