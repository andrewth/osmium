//! A small hypervisor for QEMU's AArch64 `virt` machine, built from Osmium
//! components. With `-machine virt,virtualization=on` QEMU starts ELF
//! kernels at EL2; this one stays there (non-VHE), turns on the EL2 MMU and
//! runs a guest at EL1 under stage-2 translation.
//!
//! The guest prints through an emulated 16550 (data-abort MMIO exits),
//! reads the UART's status register, executes `wfi` (a trapped halt) and
//! powers off through PSCI over `hvc`.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;

use osmium::arch::aarch64::{self, psci};
use osmium::arch::trap::{self, TrapFrame};
use osmium::arch::{cpu, irq, mmu};
use osmium::boot::fdt::Fdt;
use osmium::drivers::pl011::Pl011;
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::mmio::IoMem;
use osmium::hal::{print, println};
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::Aarch64El2;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sync::{IrqSpinLock, Once};
use osmium::virt::aarch64::{self as vm, Aarch64Vcpu};
use osmium::virt::devices::Uart16550;
use osmium::virt::stage2::{Stage2Table, map_guest_memory, vttbr};
use osmium::virt::{Bus, GuestMemory, GuestPhysAddr, VmExit, run_vcpu};

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

// The guest: position-independent EL1 code copied to the start of its RAM.
// It runs with its MMU off, so every access is a stage-2 (IPA) access.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .globl guest_image, guest_image_end
guest_image:
    movz x0, #0x1000, lsl #16       // the emulated 16550
    adr x1, 4f
1:  ldrb w2, [x1], #1
    cbz w2, 2f
    strb w2, [x0]                   // MMIO write exit
    b 1b
2:  ldrb w20, [x0, #5]              // MMIO read exit: LSR
    wfi                             // halt exit
    movz x0, #0x0008
    movk x0, #0x8400, lsl #16       // PSCI SYSTEM_OFF
    hvc #0
3:  b 3b
4:  .asciz "[guest] hello from EL1 over MMIO\n"
    .balign 4
guest_image_end:
"#
);

unsafe extern "C" {
    static _kernel_start: u8;
    static _etext: u8;
    static _erodata: u8;
    static _kernel_end: u8;
    static guest_image: u8;
    static guest_image_end: u8;
}

fn sym(s: &u8) -> u64 {
    s as *const u8 as u64
}

/// QEMU virt's PL011, and where it puts the device tree for ELF kernels.
const EARLY_UART: usize = 0x0900_0000;
const RAM_BASE_DTB: usize = 0x4000_0000;

type Frames = LockedFrames<BuddyAllocator<OffsetMapper>, OffsetMapper>;

// SAFETY: the kernel runs identity-mapped (before and after enabling the
// MMU), so physical address = virtual address for all RAM.
static FRAMES: Frames = unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

static UART: Once<SerialConsole<Pl011>> = Once::new();
static PSCI: Once<psci::Conduit> = Once::new();

fn shutdown() -> ! {
    psci::system_off(*PSCI.get().unwrap_or(&psci::Conduit::Smc))
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
    println!("\nosmium aarch64-hyp example (EL{})", aarch64::current_el());
    assert_eq!(aarch64::current_el(), 2, "run QEMU with -machine virt,virtualization=on");

    let dtb = if x0 != 0 { x0 } else { RAM_BASE_DTB };
    // SAFETY: QEMU places a valid device tree there; we reserve it below.
    let fdt = unsafe { Fdt::from_ptr(dtb as *const u8) }.expect("no device tree");
    let conduit = fdt
        .find_node("/psci")
        .and_then(|n| n.property("method"))
        .and_then(|p| p.as_str())
        .and_then(psci::Conduit::from_method)
        .unwrap_or(psci::Conduit::Smc);
    PSCI.call_once(|| conduit);
    println!("[fdt]   {} bytes at {dtb:#x}; PSCI via {conduit:?}", fdt.total_size());

    // --- Physical memory ---------------------------------------------------
    let mut map = MemoryMap::<32>::new();
    fdt.fill_memory_map(&mut map, Some(PhysAddr::new(dtb as u64))).unwrap();
    // SAFETY: linker-provided symbols.
    let (kstart, etext, erodata, kend) =
        unsafe { (sym(&_kernel_start), sym(&_etext), sym(&_erodata), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).unwrap();
    map.page_align_usable();
    let (ram_start, ram_end) = map.regions().iter().fold((u64::MAX, 0), |(s, e), r| (s.min(r.start.0), e.max(r.end.0)));
    {
        let mut buddy = FRAMES.lock();
        for r in map.usable() {
            // SAFETY: the memory map says the range is free RAM, identity-mapped.
            unsafe { buddy.add_region(r.start, r.end) };
        }
        println!("[frame] {} free frames ({} MiB)", buddy.free_frames(), (buddy.free_frames() * PAGE_SIZE) >> 20);
    }
    HEAP.init(&FRAMES);

    // --- EL2 stage-1 MMU -----------------------------------------------------
    let mut pt: PageTable<Aarch64El2, &'static Frames> = PageTable::new(&FRAMES).unwrap();
    let rw = MapFlags::RW | MapFlags::GLOBAL;
    let id = |pt: &mut PageTable<Aarch64El2, _>, a: u64, b: u64, f| pt.map_range(VirtAddr::new(a), PhysAddr::new(a), b - a, f).unwrap();
    id(&mut pt, ram_start, kstart, rw);
    id(&mut pt, kstart, etext, MapFlags::RX | MapFlags::GLOBAL);
    id(&mut pt, etext, erodata, MapFlags::READ | MapFlags::GLOBAL);
    id(&mut pt, erodata, ram_end, rw);
    id(&mut pt, EARLY_UART as u64, EARLY_UART as u64 + 0x1000, rw | MapFlags::DEVICE);
    enable_mmu(pt.root());
    println!("[mmu]   EL2 MMU on, TTBR0_EL2 {:#x}; RAM {ram_start:#x}..{ram_end:#x}", pt.root().0);
    core::mem::forget(pt);

    vm::init_cpu();
    guest_demo();

    println!("[done]  {} free frames; shutting down", FRAMES.lock().free_frames());
    shutdown()
}

/// Programs MAIR_EL2, TCR_EL2 and TTBR0_EL2 and turns on the EL2 MMU and caches.
fn enable_mmu(root: PhysAddr) {
    let parange = aarch64::read_id_aa64mmfr0_el1() & 0xf;
    let tcr = 16                 // T0SZ: 48-bit addresses
        | 1 << 8                 // IRGN0: write-back, write-allocate
        | 1 << 10                // ORGN0: write-back, write-allocate
        | 3 << 12                // SH0: inner shareable
        | parange.min(5) << 16   // PS: what the CPU supports
        | 1 << 23 | 1 << 31;     // RES1
    // SAFETY: the table identity-maps the running code, its stack, the heap
    // and the UART; the barriers order the table writes.
    unsafe {
        aarch64::write_mair_el2(aarch64::MAIR_VALUE);
        aarch64::write_tcr_el2(tcr);
        aarch64::write_ttbr0_el2(root.0);
        core::arch::asm!("dsb ish", "isb");
        mmu::flush_all();
        // M, C, I, plus the RES1 bits of SCTLR_EL2 (E2H = 0).
        aarch64::write_sctlr_el2(0x30c5_0830 | 1 << 0 | 1 << 2 | 1 << 12);
        core::arch::asm!("isb");
    }
}

const GUEST_RAM: GuestPhysAddr = GuestPhysAddr(0x4000_0000);
const GUEST_RAM_ORDER: u32 = 9; // 2 MiB
const GUEST_UART: u64 = 0x1000_0000;

fn guest_demo() {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GUEST_RAM, ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the guest image in .rodata.
    let image = unsafe {
        let start = &raw const guest_image;
        core::slice::from_raw_parts(start, (&raw const guest_image_end).offset_from(start) as usize)
    };
    mem.write(GUEST_RAM, image).unwrap();

    let mut s2: Stage2Table<_> = PageTable::new(&FRAMES).expect("stage-2 root");
    map_guest_memory(&mut s2, &mem, |p| PhysAddr::new(p as u64)).unwrap();

    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    let out = line.clone();
    let mmio = Bus::new();
    let uart = Uart16550::new(move |b| {
        let mut l = out.lock();
        l.push(b);
        if b == b'\n' {
            print!("{}", core::str::from_utf8(&l).unwrap_or("?\n"));
            l.clear();
        }
    });
    mmio.insert(GUEST_UART, 8, Arc::new(uart)).unwrap();
    let pio = Bus::new();

    let mut vcpu = Aarch64Vcpu::new(GUEST_RAM, 0, vttbr(s2.root(), 1));
    let (mut hypercalls, mut halts, mut interrupts) = (0, 0, 0);
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { .. } => {
            hypercalls += 1;
            match vm::psci::handle(v, exit) {
                Some(vm::psci::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
                _ => ControlFlow::Continue(()),
            }
        }
        VmExit::Halt => {
            halts += 1;
            ControlFlow::Continue(())
        }
        VmExit::ExternalInterrupt => {
            interrupts += 1;
            ControlFlow::Continue(())
        }
        other => ControlFlow::Break(other),
    });
    println!(
        "[hyp]   guest exit {exit:?}: {hypercalls} hypercall, {halts} halt, {interrupts} host interrupts, LSR {:#x}",
        vcpu.state.x[20]
    );

    drop(mmio);
    drop(s2);
    drop(mem);
    // SAFETY: the guest has stopped and nothing references its RAM.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
}

fn on_trap(frame: &mut TrapFrame) {
    panic!("unexpected trap {:?} at pc {:#x}, ESR {:#x}", frame.cause(), frame.pc(), frame.esr)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    irq::disable();
    println!("\n[panic] {info}");
    shutdown()
}
