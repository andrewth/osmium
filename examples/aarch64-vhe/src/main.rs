//! A VHE hypervisor for QEMU's AArch64 `virt` machine, built from Osmium
//! components. QEMU starts ELF kernels at EL2 with `-machine
//! virt,virtualization=on`; this one sets `HCR_EL2.E2H` and `TGE` before
//! anything else and from then on runs as an EL1 kernel would, through
//! `osmium-arch`'s EL1 build: its `_EL1` register names reach the EL2
//! registers, the stage-1 MMU uses the EL2&0 regime with the EL1 `TCR`
//! layout, and user-mode (EL0) traps arrive at EL2.
//!
//! A guest then runs at EL1 under stage 2 (`osmium-virt` with `aarch64-vhe`):
//! it points its own `VBAR_EL1` at a handler and takes an `svc` there (which
//! needs `TGE` clear), writes `TPIDR_EL1`, prints through an emulated 16550
//! (data-abort MMIO exits), reads the UART's status register, executes `wfi`
//! (a trapped halt) and powers off through PSCI over `hvc`. Last, the host
//! drops to a user program at EL0 whose `svc` must reach the host's own trap
//! handler again, through the vectors the guest's exits came through.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::ops::ControlFlow;

use demos::guest::image;
use demos::kernel::{FRAMES, Frames};
use osmium::arch::aarch64::{self, psci};
use osmium::arch::trap::{self, Trap, TrapFrame};
use osmium::arch::{cpu, irq, mmu};
use osmium::boot::fdt::Fdt;
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::Aarch64;
use osmium::mm::{FrameAllocator, MapFlags, MemoryMap, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sync::Once;
use osmium::sysdrv::pl011::Pl011;
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

    // The boot stack, above a guard page that kmain unmaps before turning
    // the MMU on, so an overflow faults instead of overwriting .data below.
    .section .bss.stack, "aw", @nobits
    .balign 4096
    .globl boot_stack_guard
boot_stack_guard:
    .space 4096
    .space 65536
boot_stack_top:
"#
);

// The guest: position-independent EL1 code copied to the start of its RAM,
// running with its MMU off. Its exception vectors are 0x800 into the image.
// It also turns on FP and overwrites d0, which the host is using.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .arch_extension fp
    .balign 0x800
    .globl guest_image, guest_image_end
guest_image:
    movz x0, #0x1000, lsl #16       // the emulated 16550
    adr x1, 9f
    msr vbar_el1, x1                // VBAR_EL12 to the host
    isb
    movz x2, #0xdead
    msr tpidr_el1, x2               // not redirected by VHE: the guest's own
    mov x1, #0x300000
    msr cpacr_el1, x1               // CPACR_EL12 to the host: FP on
    isb
    fmov d0, x2                     // the host's d0 must survive this
    svc #0                          // to the guest's EL1 vector (TGE = 0)
    adr x1, 8f
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
8:  .asciz "[guest] hello from EL1 under a VHE host\n"
    .balign 0x800
9:  .space 0x200                    // VBAR_EL1: synchronous, EL1h, at 0x200
    mrs x21, esr_el1
    eret
    .balign 4
guest_image_end:

    // The host's user program: one system call, then a loop it never reaches.
    .balign 4
    .globl user_image, user_image_end
user_image:
    mov x8, #172                    // getpid, as a Linux program would ask
    svc #0
1:  b 1b
user_image_end:
"#
);

unsafe extern "C" {
    static boot_stack_guard: u8;
    static _kernel_start: u8;
    static _etext: u8;
    static _erodata: u8;
    static _kernel_end: u8;
    static guest_image: u8;
    static guest_image_end: u8;
    static user_image: u8;
    static user_image_end: u8;
}

fn sym(s: &u8) -> u64 {
    s as *const u8 as u64
}

/// QEMU virt's PL011, and where it puts the device tree for ELF kernels.
const EARLY_UART: usize = 0x0900_0000;
const RAM_BASE_DTB: usize = 0x4000_0000;

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

static UART: Once<SerialConsole<Pl011>> = Once::new();
static PSCI: Once<psci::Conduit> = Once::new();

/// `HCR_EL2` for the host: VHE (E2H), its EL0 trapping to EL2 (TGE), and an
/// AArch64 EL1 for guests (RW).
const HCR_HOST: u64 = vm::HCR_E2H | vm::HCR_TGE | 1 << 31;

fn read_hcr() -> u64 {
    aarch64::read_hcr_el2()
}

/// Where the user program is mapped: away from the identity-mapped RAM.
const USER_VA: u64 = 0x10_0000_0000;

fn shutdown() -> ! {
    psci::system_off(*PSCI.get().unwrap_or(&psci::Conduit::Smc))
}

#[unsafe(no_mangle)]
#[allow(
    clippy::expect_used,
    reason = "boot: what QEMU's machine provides is set up once here, so a failure means a broken machine or a bug in this example; the panic handler reports which"
)]
extern "C" fn kmain(x0: usize) -> ! {
    // VHE first: from here on the EL1 register names reach EL2, which is what
    // osmium-arch's EL1 build (with `aarch64-vhe`) expects.
    let mmfr1: u64;
    // SAFETY: reading an ID register has no side effects.
    unsafe { core::arch::asm!("mrs {}, id_aa64mmfr1_el1", out(reg) mmfr1, options(nomem, nostack)) };
    let vh = (mmfr1 >> 8) & 0xf;
    if aarch64::current_el() == 2 && vh != 0 {
        // SAFETY: nothing runs below EL2 yet, and the MMU is off.
        unsafe {
            aarch64::write_hcr_el2(HCR_HOST);
            core::arch::asm!("isb");
        }
    }
    // SAFETY: a single CPU runs this kernel; id 0 is unique.
    unsafe { cpu::set_current_id(0) };
    trap::set_handler(on_trap);
    // SAFETY: we run on a valid kernel stack from here on.
    unsafe { trap::install() };

    // SAFETY: QEMU virt's PL011 lives here and nothing else drives it.
    let mut uart = Pl011::new(unsafe { IoMem::new(EARLY_UART as *mut u8, 0x1000) }).expect("new failed");
    uart.init(None);
    set_console(UART.call_once(|| SerialConsole::new(uart)));
    println!("\nosmium aarch64-vhe example (EL{})", aarch64::current_el());
    assert_eq!(aarch64::current_el(), 2, "run QEMU with -machine virt,virtualization=on");
    assert!(vh != 0, "this CPU has no VHE (ID_AA64MMFR1_EL1.VH = 0): use -cpu max or neoverse-n1");
    println!("[vhe]   HCR_EL2 {:#x}: E2H and TGE set", read_hcr());

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

    // --- Physical memory ---------------------------------------------------
    let mut map = MemoryMap::<32>::new();
    fdt.fill_memory_map(&mut map, Some(PhysAddr::new(dtb as u64))).expect("fill_memory_map failed");
    // SAFETY: linker-provided symbols.
    let (kstart, etext, erodata, kend) =
        unsafe { (sym(&_kernel_start), sym(&_etext), sym(&_erodata), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).expect("reserve failed");
    map.page_align_usable();
    let (ram_start, ram_end) = map.regions().iter().fold((u64::MAX, 0), |(s, e), r| (s.min(r.start.0), e.max(r.end.0)));
    // SAFETY: the memory map says these ranges are free RAM, identity-mapped.
    unsafe { demos::kernel::add_ram(map.usable().map(|r| r.start..r.end)) };
    HEAP.init(&FRAMES);

    // --- EL2&0 stage-1 MMU ---------------------------------------------------
    // The EL1 table format: with E2H the EL2&0 regime has EL0 permissions
    // (AP[1], UXN) like EL1&0, which the user program below relies on.
    let mut pt: PageTable<Aarch64, &'static Frames> = PageTable::new(&FRAMES).expect("new failed");
    let rw = MapFlags::RW | MapFlags::GLOBAL;
    let id = |pt: &mut PageTable<Aarch64, _>, a: u64, b: u64, f| {
        pt.map_range(VirtAddr::new(a), PhysAddr::new(a), b - a, f).expect("map_range failed")
    };
    id(&mut pt, ram_start, kstart, rw);
    id(&mut pt, kstart, etext, MapFlags::RX | MapFlags::GLOBAL);
    id(&mut pt, etext, erodata, MapFlags::READ | MapFlags::GLOBAL);
    id(&mut pt, erodata, ram_end, rw);
    id(&mut pt, EARLY_UART as u64, EARLY_UART as u64 + 0x1000, rw | MapFlags::DEVICE);
    // The user program's page, executable at EL0 only.
    let user = FRAMES.lock().alloc(0).expect("no memory for the user program");
    // SAFETY: linker symbols bounding the user program in .rodata.
    let code = unsafe { image(&user_image, &user_image_end) };
    // SAFETY: a fresh, identity-mapped frame that only the user mapping will share.
    unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), user.0 as *mut u8, code.len()) };
    pt.map_range(VirtAddr::new(USER_VA), user, PAGE_SIZE as u64, MapFlags::RX | MapFlags::USER)
        .expect("map_range failed");
    // The page below the boot stack becomes its guard (see `_start`). Before
    // the MMU is on: splitting the block it sits in while the table is live
    // would need break-before-make under the running stack.
    // SAFETY: a linker symbol.
    let guard = unsafe { sym(&boot_stack_guard) };
    let guarded = demos::kernel::unmap_guard(&mut pt, guard);
    enable_mmu(pt.root());
    if guarded {
        let bottom = guard as usize + PAGE_SIZE;
        demos::kernel::set_boot_stack_limit(bottom);
        osmium::arch::trap::TrapCpu::current().set_stack_limit(bottom);
    }
    println!(
        "[mmu]   EL2&0 MMU on (TCR in the EL1 layout), TTBR0 {:#x}; RAM {ram_start:#x}..{ram_end:#x}",
        pt.root().0
    );
    core::mem::forget(pt);

    vm::init_cpu();
    guest_demo();
    user_demo()
}

/// Programs MAIR, TCR and TTBR0 through their EL1 names, which VHE
/// redirects to the EL2 registers, and turns on the MMU and caches.
fn enable_mmu(root: PhysAddr) {
    let parange = aarch64::read_id_aa64mmfr0_el1() & 0xf;
    let tcr = 16                 // T0SZ: 48-bit addresses
        | 1 << 8                 // IRGN0: write-back, write-allocate
        | 1 << 10                // ORGN0: write-back, write-allocate
        | 3 << 12                // SH0: inner shareable
        | 1 << 23                // EPD1: no TTBR1 walks
        | 2 << 30                // TG1: 4 KiB
        | parange.min(5) << 32; // IPS: what the CPU supports
    // SAFETY: the table identity-maps the running code, its stack, the heap
    // and the UART; the barriers order the table writes.
    unsafe {
        aarch64::write_mair_el1(aarch64::MAIR_VALUE);
        aarch64::write_tcr_el1(tcr);
        aarch64::write_ttbr0_el1(root.0);
        core::arch::asm!("dsb ish", "isb");
        mmu::flush_all();
        let sctlr = aarch64::read_sctlr_el1() | 1 << 0 | 1 << 2 | 1 << 12; // M, C, I
        aarch64::write_sctlr_el1(sctlr);
        core::arch::asm!("isb");
    }
}

const GUEST_RAM: GuestPhysAddr = GuestPhysAddr(0x4000_0000);
const GUEST_RAM_ORDER: u32 = 9; // 2 MiB
const GUEST_UART: u64 = 0x1000_0000;

#[allow(
    clippy::expect_used,
    reason = "demo setup on fresh memory and fixed guest addresses: a failure is a bug in this example, reported by the panic handler"
)]
fn guest_demo() {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GUEST_RAM, ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the guest image in .rodata.
    mem.write(GUEST_RAM, unsafe { image(&guest_image, &guest_image_end) }).expect("write failed");
    let mut s2: Stage2Table<_> = PageTable::new(&FRAMES).expect("stage-2 root");
    map_guest_memory(&mut s2, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");
    let mmio = Bus::new();
    let uart = Uart16550::new(demos::guest::console(""));
    mmio.insert(GUEST_UART, 8, Arc::new(uart)).expect("insert failed");
    let pio = Bus::new();

    // The host's own FP/SIMD registers are live (CPTR_EL2.FPEN, through
    // CPACR_EL1): the vCPU must put them back after the guest.
    const HOST_D0: u64 = 0x0123_4567_89ab_cdef;
    // SAFETY: the kernel itself is soft-float and keeps nothing in FP/SIMD.
    let fp = unsafe { osmium::arch::fp::enable() };
    if fp {
        // SAFETY: FP/SIMD is on; d0 holds nothing of the kernel's.
        unsafe { core::arch::asm!(".arch_extension fp", "fmov d0, {}", in(reg) HOST_D0, options(nomem, nostack)) };
    }

    let mut vcpu = Aarch64Vcpu::new(GUEST_RAM, 0, vttbr(s2.root(), 1));
    let (mut hypercalls, mut halts) = (0, 0);
    let mut tge_on_exits = true;
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| {
        // Every exit comes back to a host with its own HCR_EL2.
        tge_on_exits &= read_hcr() == HCR_HOST;
        match exit {
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
            other => ControlFlow::Break(other),
        }
    });
    println!(
        "[vhe]   guest exit {exit:?}: {hypercalls} hypercall, {halts} halt, LSR {:#x}; HCR_EL2 back to the host's on every exit: {tge_on_exits}",
        vcpu.state.x[20]
    );
    let d0: u64;
    // SAFETY: FP/SIMD is still on for the host; reads d0 only.
    unsafe { core::arch::asm!(".arch_extension fp", "fmov {}, d0", out(reg) d0, options(nomem, nostack)) };
    println!("[vhe]   host d0 kept across the guest: {}; guest d0 {:#x}", fp && d0 == HOST_D0, vcpu.fp.q[0] as u64);
    let svc = vcpu.state.x[21] >> 26 == 0x15 && vcpu.el1.vbar == GUEST_RAM.0 + 0x800;
    println!(
        "[vhe]   guest svc taken at its own VBAR_EL1: {svc}; guest TPIDR_EL1 {:#x}, host CPU id still {}",
        vcpu.el1.tpidr_el1,
        cpu::current_id()
    );

    drop(mmio);
    drop(s2);
    drop(mem);
    // SAFETY: the guest has stopped and nothing references its RAM.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
}

/// Runs the user program at EL0; its `svc` ends in [`on_trap`].
fn user_demo() -> ! {
    let stack = alloc::vec![0u8; 16 * 1024].leak();
    let top = (stack.as_ptr() as u64 + stack.len() as u64) & !15;
    // SAFETY: the vectors are installed, `top` is the top of a fresh kernel
    // stack, and the program is mapped EL0-executable at USER_VA. It needs no
    // stack of its own.
    unsafe { aarch64::enter_user(USER_VA, USER_VA + PAGE_SIZE as u64, top) }
}

#[allow(
    clippy::panic,
    reason = "a trap this example never enables is a bug in it; stopping with a report is all there is to do"
)]
fn on_trap(frame: &mut TrapFrame) {
    if frame.from_user() && frame.cause() == Trap::Syscall {
        println!(
            "[user]  svc from EL0 (x8 = {}) reached the host's trap handler at EL{}, HCR_EL2 {:#x}",
            frame.x[8],
            aarch64::current_el(),
            read_hcr()
        );
        println!("[done]  {} free frames; shutting down", FRAMES.lock().free_frames());
        shutdown()
    }
    panic!("unexpected trap {:?} at pc {:#x}, ESR {:#x}", frame.cause(), frame.pc(), frame.esr)
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;
    irq::disable();
    // Straight to the PL011, not through the console: the panic may have
    // come from inside println, with the console's lock held.
    // SAFETY: the UART is already set up and mapped at this address.
    if let Ok(mut uart) = Pl011::new(unsafe { IoMem::new(EARLY_UART as *mut u8, 0x1000) }) {
        let _ = writeln!(osmium::hal::serial::SerialWriter(&mut uart), "\n[panic] {info}");
    }
    shutdown()
}
