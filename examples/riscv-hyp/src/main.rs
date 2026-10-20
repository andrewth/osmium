//! A hypervisor for QEMU's RISC-V virt machine (H extension), built from
//! Osmium components, that boots a whole guest kernel: an ELF image QEMU
//! places in host RAM with
//!
//! ```text
//! -device loader,file=<kernel ELF>,addr=0x98000000,force-raw=on
//! ```
//!
//! The guest gets 64 MiB of RAM at 0x8000_0000, a 16550 at 0x1000_0000 and
//! a PLIC at 0x0c00_0000, described by a generated device tree, and SBI
//! from the hypervisor (timer, console, HSM, IPI, RFENCE, reset). Its
//! console output is printed with a `| ` prefix. The guest used by
//! `scripts/check.sh` is Osmium's own `riscv-virt` kernel.
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;
use core::sync::atomic::Ordering;

use osmium::arch::cpu;
use osmium::arch::riscv64::sbi as host_sbi;
use osmium::arch::trap::{self, TrapFrame};
use osmium::boot::elf::Elf;
use osmium::boot::fdt::Fdt;
use osmium::drivers::uart16550::{Mmio, Uart16550};
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::mm::heap::LockedHeap;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind};
use osmium::sync::{IrqSpinLock, Once};
use osmium::virt::devices::{Uart16550 as Uart16550Model, VirtualPlic};
use osmium::virt::riscv::fdt::GuestMachine;
use osmium::virt::riscv::{self, RiscvVcpu, sbi};
use osmium::virt::smp::GuestCpus;
use osmium::virt::stage2::{GStageTable, hgatp_sv39x4, map_guest_memory};
use osmium::virt::{Bus, GuestMemory, GuestPhysAddr, VmExit, run_vcpu};

core::arch::global_asm!(
    r#"
    .section .text.entry
    .globl _start
_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    la sp, boot_stack_top
    la t0, _bss_start
    la t1, _bss_end
1:  bgeu t0, t1, 2f
    sd zero, 0(t0)
    addi t0, t0, 8
    j 1b
2:  call kmain

    .section .bss.stack
    .align 12
    .space 65536
boot_stack_top:
"#
);

unsafe extern "C" {
    static _kernel_start: u8;
    static _kernel_end: u8;
}

/// Where QEMU's loader puts the guest kernel, and the window kept free for it.
const IMAGE_BASE: u64 = 0x9800_0000;
const IMAGE_WINDOW: u64 = 0x0800_0000;

const GUEST_RAM: u64 = 0x8000_0000;
const GUEST_RAM_ORDER: u32 = 14; // 64 MiB
const GUEST_UART: u64 = 0x1000_0000;
const UART_IRQ: u32 = 10;
const PLIC_BASE: u64 = 0x0c00_0000;
/// The guest's device tree, at the top of its RAM.
const GUEST_DTB_SIZE: u64 = 0x1_0000;

type Frames = LockedFrames<BuddyAllocator<OffsetMapper>, OffsetMapper>;

// SAFETY: the kernel runs with the MMU off, so physical = virtual.
static FRAMES: Frames = unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

static UART: Once<SerialConsole<Uart16550<Mmio>>> = Once::new();

fn sym(s: &u8) -> u64 {
    s as *const u8 as u64
}

#[unsafe(no_mangle)]
extern "C" fn kmain(hartid: usize, dtb: usize) -> ! {
    // SAFETY: this kernel runs on one hart, logical CPU 0.
    unsafe { cpu::set_current_id(0) };
    trap::set_handler(on_trap);
    // SAFETY: we run on the boot stack from here on.
    unsafe { trap::install() };

    // SAFETY: OpenSBI passes a valid DTB, reserved below.
    let fdt = unsafe { Fdt::from_ptr(dtb as *const u8) }.expect("bad device tree");
    let uart_node = fdt.find_compatible(&["ns16550a"]).expect("no UART");
    let (uart_base, uart_len) = uart_node.reg().next().map(|(a, s)| (a, s.unwrap_or(0x100))).unwrap();
    // SAFETY: the device tree says the UART's registers live here; nothing else uses them.
    let io = unsafe { IoMem::new(uart_base as *mut u8, uart_len as usize) };
    let mut uart = Uart16550::new(Mmio::new(io, 0));
    uart.init(None);
    set_console(UART.call_once(|| SerialConsole::new(uart)));
    println!("\nosmium riscv-hyp example (hart {hartid})");

    let mut map = MemoryMap::<32>::new();
    fdt.fill_memory_map(&mut map, Some(PhysAddr::new(dtb as u64))).unwrap();
    // SAFETY: linker-provided symbols.
    let (kstart, kend) = unsafe { (sym(&_kernel_start), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).unwrap();
    map.reserve(PhysAddr::new(IMAGE_BASE), PhysAddr::new(IMAGE_BASE + IMAGE_WINDOW), RegionKind::Reserved).unwrap();
    map.page_align_usable();
    {
        let mut buddy = FRAMES.lock();
        for r in map.usable() {
            // SAFETY: the memory map says the range is free RAM.
            unsafe { buddy.add_region(r.start, r.end) };
        }
        println!("[frame] {} free frames ({} MiB)", buddy.free_frames(), (buddy.free_frames() * PAGE_SIZE) >> 20);
    }
    HEAP.init(&FRAMES);
    riscv::init_cpu();

    // SAFETY: the window is reserved RAM that QEMU's loader filled (or left zero).
    let window = unsafe { core::slice::from_raw_parts(IMAGE_BASE as *const u8, IMAGE_WINDOW as usize) };
    match Elf::new(window) {
        Ok(elf) => boot_guest(&elf),
        Err(e) => println!(
            "[hyp]   no guest kernel at {IMAGE_BASE:#x} ({e:?}): pass one with -device loader,file=...,addr={IMAGE_BASE:#x},force-raw=on"
        ),
    }
    host_sbi::shutdown()
}

/// The guest's console: whole lines, prefixed so they stand apart from the host's.
fn guest_console() -> impl Fn(u8) + Send + Sync + Clone + 'static {
    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    move |b| {
        let mut l = line.lock();
        match b {
            b'\n' => {
                println!("| {}", core::str::from_utf8(&l).unwrap_or("?"));
                l.clear();
            }
            b'\r' => {}
            _ => l.push(b),
        }
    }
}

/// Loads `elf` into fresh guest RAM and runs it on one vCPU until it shuts
/// down.
fn boot_guest(elf: &Elf<'_>) {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by the guest for the rest of the run.
    unsafe { mem.add_region(GuestPhysAddr(GUEST_RAM), ram.0 as *mut u8, len) };
    // The image is linked where it runs: physical = virtual.
    let mut loaded = 0;
    for s in elf.segments() {
        mem.write(GuestPhysAddr(s.vaddr), s.data).expect("guest segment outside its RAM");
        let zeros = alloc::vec![0u8; (s.mem_size - s.data.len() as u64) as usize];
        mem.write(GuestPhysAddr(s.vaddr + s.data.len() as u64), &zeros).expect("guest segment outside its RAM");
        loaded += s.mem_size;
    }
    println!("[hyp]   guest kernel: {} KiB loaded, entry {:#x}", loaded >> 10, elf.entry());

    let dtb_at = GUEST_RAM + len - GUEST_DTB_SIZE;
    let dtb = GuestMachine {
        harts: 1,
        isa: "rv64imac",
        timebase: 10_000_000,
        memory: &[(GUEST_RAM, len)],
        plic: Some((PLIC_BASE, 32)),
        uarts: &[(GUEST_UART, UART_IRQ)],
        virtio: &[],
        bootargs: "",
    }
    .to_dtb();
    assert!(dtb.len() as u64 <= GUEST_DTB_SIZE);
    mem.write(GuestPhysAddr(dtb_at), &dtb).unwrap();
    let mem = Arc::new(mem);

    let mut gstage: GStageTable<_> = PageTable::new(&FRAMES).expect("G-stage root");
    map_guest_memory(&mut gstage, &mem, |p| PhysAddr::new(p as u64)).unwrap();
    let hgatp = hgatp_sv39x4(gstage.root(), 1);

    let mut vcpu = RiscvVcpu::new(GuestPhysAddr(elf.entry()), 0, dtb_at, hgatp);
    let eip = vcpu.external_irq();
    // Context 1 is hart 0's S-mode context (0 is its unconnected M context).
    let plic = Arc::new(VirtualPlic::new(32, 2, move |ctx, level| {
        if ctx == 1 {
            eip.store(level, Ordering::Release)
        }
    }));
    let p = plic.clone();
    let uart = Arc::new(Uart16550Model::new(guest_console()).with_irq(move |level| p.set_level(UART_IRQ, level)));
    let mmio = Bus::new();
    mmio.insert(PLIC_BASE, VirtualPlic::mmio_size(2), plic).unwrap();
    mmio.insert(GUEST_UART, 8, uart).unwrap();
    let pio = Bus::new();
    let cpus = GuestCpus::new(1);
    cpus.request_start(0, elf.entry(), dtb_at).unwrap();
    let _ = cpus.take_start(0);
    cpus.attach(0, &mut vcpu);

    let sbi_out = guest_console();
    let (mut exits, mut halts) = (0u64, 0u64);
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| {
        exits += 1;
        match exit {
            VmExit::Hypercall { .. } => {
                match sbi::handle_smp(v, &mem, exit, &mut |b| b.iter().for_each(|&c| sbi_out(c)), Some((&cpus, 0))) {
                    Some(sbi::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
                    Some(sbi::Outcome::Stop) => ControlFlow::Break(VmExit::Halt),
                    _ => ControlFlow::Continue(()),
                }
            }
            VmExit::Halt => {
                // The guest idles in wfi: run it again once it has an
                // interrupt (its timer, or a device).
                halts += 1;
                let deadline = riscv::time() + 50_000_000; // 5 s
                while !v.interrupt_pending(riscv::time()) {
                    if riscv::time() > deadline {
                        return ControlFlow::Break(VmExit::Halt);
                    }
                    core::hint::spin_loop();
                }
                ControlFlow::Continue(())
            }
            VmExit::ExternalInterrupt => ControlFlow::Continue(()),
            other => ControlFlow::Break(other),
        }
    });
    println!("[hyp]   guest exit {exit:?} after {exits} exits ({halts} in wfi), pc {:#x}", vcpu.state.pc);
}

fn on_trap(frame: &mut TrapFrame) {
    panic!("unexpected trap {:?} at pc {:#x}", frame.cause(), frame.pc())
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    println!("\n[panic] {info}");
    host_sbi::shutdown()
}
