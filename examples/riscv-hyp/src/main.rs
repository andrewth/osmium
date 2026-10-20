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
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use osmium::arch::cpu;
use osmium::arch::riscv64::{self as rv, sbi as host_sbi};
use osmium::arch::trap::{self, TrapFrame};
use osmium::boot::elf::Elf;
use osmium::boot::fdt::Fdt;
use osmium::drivers::ramdisk::RamDisk;
use osmium::drivers::uart16550::{Mmio, Uart16550};
use osmium::drivers::virtio::mmio::MmioTransport;
use osmium::drivers::virtio::net::VirtioNet;
use osmium::drivers::virtio::{DeviceType, Transport as _};
use osmium::hal::block::BlockDevice as _;
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::mmio::IoMem;
use osmium::hal::net::NetDevice as _;
use osmium::hal::println;
use osmium::mm::heap::LockedHeap;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind};
use osmium::sync::{IrqSpinLock, Once};
use osmium::virt::devices::{Uart16550 as Uart16550Model, VirtualPlic};
use osmium::virt::riscv::fdt::GuestMachine;
use osmium::virt::riscv::{self, HartId, RiscvVcpu, sbi};
use osmium::virt::smp::GuestCpus;
use osmium::virt::stage2::{GStageTable, Hgatp, hgatp_sv39x4, map_guest_memory};
use osmium::virt::virtio::{MMIO_SIZE, VirtioBlock, VirtioMmio, VirtioNetDevice};
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

    # Secondary harts start here (SBI HSM) with a0 = hart id and
    # a1 = &SecondaryBoot.
    .globl secondary_start
secondary_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    ld sp, 0(a1)
    call secondary_main

    .section .bss.stack
    .align 12
    .space 65536
boot_stack_top:
"#
);

unsafe extern "C" {
    static _kernel_start: u8;
    static _kernel_end: u8;
    fn secondary_start();
}

/// Handed to a secondary hart through `a1`.
#[repr(C)]
struct SecondaryBoot {
    stack_top: u64,
    cpu: usize,
}

/// Most harts the guest gets: one vCPU per host hart.
const MAX_HARTS: usize = 4;
/// Host hart ID of each logical CPU.
static HARTS: [AtomicUsize; MAX_HARTS] = [const { AtomicUsize::new(0) }; MAX_HARTS];
static ONLINE: AtomicUsize = AtomicUsize::new(1);

/// Where QEMU's loader puts the guest kernel, and the window kept free for it.
const IMAGE_BASE: u64 = 0x9800_0000;
const IMAGE_WINDOW: u64 = 0x0800_0000;

const GUEST_RAM: u64 = 0x8000_0000;
const GUEST_RAM_ORDER: u32 = 14; // 64 MiB
const GUEST_UART: u64 = 0x1000_0000;
const UART_IRQ: u32 = 10;
const PLIC_BASE: u64 = 0x0c00_0000;
/// virtio-blk over a host RAM disk, in QEMU virt's first virtio-mmio slot.
const BLK_BASE: u64 = 0x1000_1000;
const BLK_IRQ: u32 = 1;
const DISK_ORDER: u32 = 10; // 4 MiB
/// virtio-net bridged to the host's own virtio-net, in the second slot.
const NET_BASE: u64 = 0x1000_2000;
const NET_IRQ: u32 = 2;
/// How often (in timer ticks) hart 0 moves frames from the host NIC to
/// the guest while the guest runs: 1 ms.
const NET_POLL_TICKS: u64 = 10_000;

type HostNic = VirtioNet<'static, MmioTransport, Frames>;
/// The host's virtio-net, which the guest's network card is bridged to.
static HOST_NIC: Once<IrqSpinLock<HostNic>> = Once::new();
/// The guest's device tree, at the top of its RAM.
const GUEST_DTB_SIZE: u64 = 0x1_0000;

type Frames = LockedFrames<BuddyAllocator<OffsetMapper>, OffsetMapper>;

// SAFETY: the kernel runs with the MMU off, so physical = virtual.
static FRAMES: Frames = unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

static UART: Once<SerialConsole<Uart16550<Mmio>>> = Once::new();
/// Base and length of the console UART's registers, for the panic handler.
static UART_REGS: (AtomicUsize, AtomicUsize) = (AtomicUsize::new(0), AtomicUsize::new(0));

fn sym(s: &u8) -> u64 {
    s as *const u8 as u64
}

#[unsafe(no_mangle)]
extern "C" fn kmain(hartid: usize, dtb: usize) -> ! {
    // SAFETY: the boot hart is logical CPU 0; secondaries get 1, 2, ...
    unsafe { cpu::set_current_id(0) };
    HARTS[0].store(hartid, Ordering::Relaxed);
    trap::set_handler(on_trap);
    // SAFETY: we run on the boot stack from here on.
    unsafe { trap::install() };

    // SAFETY: OpenSBI passes a valid DTB, reserved below.
    let fdt = unsafe { Fdt::from_ptr(dtb as *const u8) }.expect("bad device tree");
    let uart_node = fdt.find_compatible(&["ns16550a"]).expect("no UART");
    let (uart_base, uart_len) =
        uart_node.reg().next().map(|(a, s)| (a, s.unwrap_or(0x100))).expect("UART has a reg property");
    // SAFETY: the device tree says the UART's registers live here; nothing else uses them.
    let io = unsafe { IoMem::new(uart_base as *mut u8, uart_len as usize) };
    UART_REGS.0.store(uart_base as usize, Ordering::Relaxed);
    UART_REGS.1.store(uart_len as usize, Ordering::Relaxed);
    let mut uart = Uart16550::new(Mmio::new(io, 0));
    uart.init(None);
    set_console(UART.call_once(|| SerialConsole::new(uart)));
    println!("\nosmium riscv-hyp example (hart {hartid})");

    let mut map = MemoryMap::<32>::new();
    fdt.fill_memory_map(&mut map, Some(PhysAddr::new(dtb as u64))).expect("fill_memory_map failed");
    // SAFETY: linker-provided symbols.
    let (kstart, kend) = unsafe { (sym(&_kernel_start), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).expect("reserve failed");
    // With enough RAM, keep the window for the guest kernel image (where
    // QEMU's loader puts it) out of the allocator.
    let top = map.regions().iter().map(|r| r.end.0).max().unwrap_or(0);
    let image_window = top >= IMAGE_BASE + IMAGE_WINDOW;
    if image_window {
        map.reserve(PhysAddr::new(IMAGE_BASE), PhysAddr::new(IMAGE_BASE + IMAGE_WINDOW), RegionKind::Reserved)
            .expect("reserve failed");
    }
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
    // Kicks arrive as supervisor software interrupts. With SSIE on they
    // exit a running guest; the host itself keeps sstatus.SIE off.
    // SAFETY: only enables a source the host never takes in HS-mode.
    unsafe { rv::write_sie(rv::read_sie() | 1 << 1) };

    // The host's virtio-net, if QEMU has one: the guest's card is bridged to it.
    let nic = fdt
        .all_nodes()
        .filter(|n| n.compatible().any(|c| c == "virtio,mmio"))
        .filter_map(|n| n.reg().next().map(|(a, s)| (a, s.unwrap_or(0x200))))
        .find_map(|(base, len)| {
            // SAFETY: the device tree puts a virtio-mmio slot here; nothing else uses it.
            let t = MmioTransport::new(unsafe { IoMem::new(base as *mut u8, len as usize) }).ok()?;
            (t.device_type() == DeviceType::Net).then_some(t)
        });
    if let Some(t) = nic {
        let nic = VirtioNet::new(t, &FRAMES).expect("virtio-net init failed");
        println!("[net]   host virtio-net {}: bridged to the guest", nic.mac_address());
        HOST_NIC.call_once(|| IrqSpinLock::new(nic));
    }

    // One vCPU per host hart: start the others.
    let cpus = fdt.find_node("/cpus").expect("no /cpus");
    let mut ncpus = 1;
    for c in cpus.children().filter(|c| c.name().starts_with("cpu@")) {
        let Some(h) = c.reg().next().map(|(a, _)| a as usize) else { continue };
        if h == hartid || ncpus == MAX_HARTS {
            continue;
        }
        let stack = alloc::vec![0u8; 64 * 1024].leak();
        let boot = alloc::boxed::Box::leak(alloc::boxed::Box::new(SecondaryBoot {
            stack_top: (stack.as_ptr() as u64 + stack.len() as u64) & !15,
            cpu: ncpus,
        }));
        HARTS[ncpus].store(h, Ordering::Relaxed);
        // SAFETY: secondary_start sets up gp and the stack from `boot`.
        unsafe { host_sbi::hart_start(h, secondary_start as *const () as usize, boot as *const _ as usize) }
            .expect("hart_start failed");
        ncpus += 1;
        while ONLINE.load(Ordering::Acquire) < ncpus {
            core::hint::spin_loop();
        }
    }
    println!("[smp]   {ncpus} host harts online, one per guest vCPU");

    if !image_window {
        println!("[hyp]   RAM ends below {:#x}: run QEMU with -m 512M and a guest kernel", IMAGE_BASE + IMAGE_WINDOW);
        host_sbi::shutdown()
    }
    // SAFETY: the window is reserved RAM that QEMU's loader filled (or left zero).
    let window = unsafe { core::slice::from_raw_parts(IMAGE_BASE as *const u8, IMAGE_WINDOW as usize) };
    match Elf::new(window) {
        Ok(elf) => boot_guest(&elf, ncpus),
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

/// A guest shared by every host hart, each running one of its vCPUs.
struct Vm {
    cpus: Arc<GuestCpus>,
    mem: Arc<GuestMemory>,
    hgatp: Hgatp,
    mmio: Bus,
    /// The guest's network card, bridged to [`HOST_NIC`].
    net: Option<Arc<VirtioMmio<VirtioNetDevice>>>,
    /// Per vCPU: its external-interrupt line (PLIC context 2n + 1).
    lines: Vec<Arc<AtomicBool>>,
    done: AtomicBool,
    /// vCPUs not yet back in their host loop for good.
    running: AtomicUsize,
}

static VM: AtomicPtr<Vm> = AtomicPtr::new(core::ptr::null_mut());

/// Rust entry of a secondary host hart: ready it for guests, then run the
/// vCPU with its index whenever the guest starts it.
#[unsafe(no_mangle)]
extern "C" fn secondary_main(_hartid: usize, boot: &SecondaryBoot) -> ! {
    // SAFETY: the boot hart hands out distinct logical ids.
    unsafe { cpu::set_current_id(boot.cpu) };
    // SAFETY: we are on the stack the boot hart allocated for us.
    unsafe { trap::install() };
    riscv::init_cpu();
    // SAFETY: as on the boot hart: kicks exit the guest; the host never takes them.
    unsafe { rv::write_sie(rv::read_sie() | 1 << 1) };
    ONLINE.fetch_add(1, Ordering::Release);
    loop {
        // SAFETY: boot_guest publishes the VM only while it lives, and waits
        // for every vCPU loop to finish before freeing it.
        if let Some(vm) = unsafe { VM.load(Ordering::Acquire).as_ref() } {
            vcpu_loop(vm, boot.cpu);
            while !VM.load(Ordering::Acquire).is_null() {
                core::hint::spin_loop();
            }
        }
        core::hint::spin_loop();
    }
}

/// Moves frames the host NIC has received into the guest's card.
fn poll_net(vm: &Vm) {
    let (Some(nic), Some(net)) = (HOST_NIC.get(), &vm.net) else { return };
    let mut frames = Vec::new();
    {
        let mut nic = nic.lock();
        let mut buf = [0u8; 1514];
        while let Ok(n) = nic.receive(&mut buf) {
            frames.push(buf[..n].to_vec());
        }
    }
    // Outside the NIC's lock: the card's transmit path takes it.
    for f in frames {
        net.with_device(|d, ctx| d.receive(&f, ctx));
    }
}

/// Runs vCPU `me` on this host hart each time the guest starts it, until
/// the guest is done. Returns the exit that ended the guest, if it was this
/// vCPU's.
fn vcpu_loop(vm: &Vm, me: usize) -> Option<VmExit> {
    let sbi_out = guest_console();
    let mut last = None;
    while !vm.done.load(Ordering::Acquire) {
        let Some((entry, opaque)) = vm.cpus.take_start(me) else {
            core::hint::spin_loop();
            continue;
        };
        let mut vcpu = RiscvVcpu::new(GuestPhysAddr(entry), HartId(me as u64), opaque, vm.hgatp)
            .with_external_irq(vm.lines[me].clone())
            .with_memory(vm.mem.clone());
        vm.cpus.attach(me, &mut vcpu);
        let mut stopped = false;
        // Hart 0 polls the host NIC on a host timer, so frames reach a
        // guest that busy-waits for them without exiting.
        let mut next_poll = riscv::time() + NET_POLL_TICKS;
        if me == 0 && vm.net.is_some() {
            host_sbi::set_timer(next_poll);
            // SAFETY: as with SSIE: the timer exits the guest; the host never takes it.
            unsafe { rv::write_sie(rv::read_sie() | 1 << 5) };
        }
        let exit = run_vcpu(&mut vcpu, &vm.mmio, &Bus::new(), |v, exit| match exit {
            VmExit::Hypercall { .. } => {
                match sbi::handle_smp(
                    v,
                    &vm.mem,
                    exit,
                    &mut |b| b.iter().for_each(|&c| sbi_out(c)),
                    Some((&vm.cpus, me)),
                ) {
                    Some(sbi::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
                    Some(sbi::Outcome::Stop) => {
                        stopped = true;
                        ControlFlow::Break(VmExit::Halt)
                    }
                    _ => ControlFlow::Continue(()),
                }
            }
            VmExit::Halt => {
                // The guest idles in wfi: run it again once it has an
                // interrupt (its timer, an IPI or a device), or stop when
                // another vCPU has shut the guest down.
                while !v.interrupt_pending(riscv::time()) {
                    if vm.done.load(Ordering::Acquire) {
                        return ControlFlow::Break(VmExit::Halt);
                    }
                    if me == 0 {
                        poll_net(vm);
                    }
                    core::hint::spin_loop();
                }
                ControlFlow::Continue(())
            }
            VmExit::ExternalInterrupt => {
                // A kick from another hart: clear it; the next entry delivers
                // whatever the guest now has pending.
                // SAFETY: clears only this hart's software-interrupt bit.
                unsafe { rv::write_sip(rv::read_sip() & !(1 << 1)) };
                if me == 0 && riscv::time() >= next_poll {
                    // The host timer: bring in received frames, re-arm.
                    poll_net(vm);
                    next_poll = riscv::time() + NET_POLL_TICKS;
                    host_sbi::set_timer(next_poll);
                }
                if vm.done.load(Ordering::Acquire) {
                    return ControlFlow::Break(VmExit::Halt);
                }
                ControlFlow::Continue(())
            }
            other => ControlFlow::Break(other),
        });
        if stopped {
            continue; // hart_stop: wait for the guest to start it again
        }
        if !vm.done.swap(true, Ordering::AcqRel) {
            // This vCPU ended the guest: get the others out of guest code.
            for i in 0..vm.lines.len() {
                vm.cpus.kick(i);
            }
            last = Some(exit);
            if exit != VmExit::Shutdown {
                println!("[hyp]   vCPU {me} stopped the guest: {exit:?} at pc {:#x}", vcpu.state.pc);
            }
        }
    }
    vm.running.fetch_sub(1, Ordering::AcqRel);
    last
}

/// Loads `elf` into fresh guest RAM and runs it with one vCPU per host
/// hart until it shuts down.
fn boot_guest(elf: &Elf<'_>, harts: usize) {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by the guest for the rest of the run.
    unsafe { mem.add_region(GuestPhysAddr(GUEST_RAM), ram.0 as *mut u8, len) };
    // The image is linked where it runs: physical = virtual.
    let image = match mem.load_elf(elf) {
        Ok(r) => r,
        Err(e) => {
            println!("[hyp]   the guest kernel does not fit its RAM ({e:?})");
            return;
        }
    };
    let dtb_at = GUEST_RAM + len - GUEST_DTB_SIZE;
    if image.end > dtb_at {
        println!("[hyp]   the guest kernel overlaps its device tree at {dtb_at:#x}");
        return;
    }
    let kib = (image.end - image.start) >> 10;
    println!("[hyp]   guest kernel: {kib} KiB loaded, entry {:#x}, {harts} vCPUs", elf.entry());
    let dtb = GuestMachine {
        harts: harts as u32,
        isa: "rv64imac",
        timebase: 10_000_000,
        memory: &[(GUEST_RAM, len)],
        plic: Some((PLIC_BASE, 32)),
        uarts: &[(GUEST_UART, UART_IRQ)],
        virtio: if HOST_NIC.get().is_some() {
            &[(BLK_BASE, BLK_IRQ), (NET_BASE, NET_IRQ)]
        } else {
            &[(BLK_BASE, BLK_IRQ)]
        },
        bootargs: "",
    }
    .to_dtb();
    assert!(dtb.len() as u64 <= GUEST_DTB_SIZE);
    mem.write(GuestPhysAddr(dtb_at), &dtb).expect("write failed");
    let mem = Arc::new(mem);

    let mut gstage: GStageTable<_> = PageTable::new(&FRAMES).expect("G-stage root");
    map_guest_memory(&mut gstage, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");

    // Hart n's S-mode context is 2n + 1 (2n is its unconnected M context).
    let lines: Vec<Arc<AtomicBool>> = (0..harts).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let l = lines.clone();
    let plic = Arc::new(VirtualPlic::new(32, 2 * harts, move |ctx, level| {
        if ctx % 2 == 1 {
            l[ctx / 2].store(level, Ordering::Release)
        }
    }));
    let plic_for_blk = plic.clone();
    let p = plic.clone();
    let uart = Arc::new(Uart16550Model::new(guest_console()).with_irq(move |level| p.set_level(UART_IRQ, level)));
    let mmio = Bus::new();
    mmio.insert(PLIC_BASE, VirtualPlic::mmio_size(2 * harts), plic).expect("insert failed");
    mmio.insert(GUEST_UART, 8, uart).expect("insert failed");
    // The disk: a host RAM disk the guest reaches through virtio-blk.
    let disk_pa = FRAMES.lock().alloc(DISK_ORDER).expect("no memory for the disk");
    let disk_len = PAGE_SIZE << DISK_ORDER;
    // SAFETY: a fresh block, zeroed and owned by the disk for the rest of the run.
    let disk_buf = unsafe {
        let p = disk_pa.0 as *mut u8;
        p.write_bytes(0, disk_len);
        core::slice::from_raw_parts_mut(p, disk_len)
    };
    let p = plic_for_blk.clone();
    let blk = Arc::new(VirtioMmio::new(VirtioBlock::new(RamDisk::new(disk_buf, 512)), mem.clone(), move |level| {
        p.set_level(BLK_IRQ, level)
    }));
    mmio.insert(BLK_BASE, MMIO_SIZE, blk.clone()).expect("insert failed");
    // The network card: frames the guest sends go out on the host NIC;
    // hart 0 brings received ones in (`poll_net`). Same MAC as the host
    // NIC, which the host itself does not use.
    let net = HOST_NIC.get().map(|nic| {
        let mac = nic.lock().mac_address().0;
        let backend = |frame: &[u8], _: &mut dyn FnMut(&[u8])| {
            let _ = HOST_NIC.get().expect("HOST_NIC initialised").lock().transmit(frame);
        };
        let p = plic_for_blk.clone();
        let dev = Arc::new(VirtioMmio::new(VirtioNetDevice::new(mac, backend), mem.clone(), move |level| {
            p.set_level(NET_IRQ, level)
        }));
        mmio.insert(NET_BASE, MMIO_SIZE, dev.clone()).expect("insert failed");
        dev
    });
    // An IPI or fence for a vCPU running guest code on another hart kicks
    // that hart with a host IPI.
    let cpus = GuestCpus::with_kick(harts, |cpu| {
        let _ = host_sbi::send_ipi(1, HARTS[cpu].load(Ordering::Relaxed));
    });
    cpus.request_start(0, elf.entry(), dtb_at).expect("request_start failed");

    let vm = Vm {
        cpus,
        mem,
        hgatp: hgatp_sv39x4(gstage.root(), 1),
        mmio,
        net,
        lines,
        done: AtomicBool::new(false),
        running: AtomicUsize::new(harts),
    };
    VM.store(&raw const vm as *mut Vm, Ordering::Release);
    let exit = vcpu_loop(&vm, 0);
    while vm.running.load(Ordering::Acquire) > 0 {
        core::hint::spin_loop();
    }
    VM.store(core::ptr::null_mut(), Ordering::Release);
    match exit {
        Some(e) => println!("[hyp]   guest exit {e:?} from vCPU 0"),
        None => println!("[hyp]   guest ended by another vCPU"),
    }
    // riscv-virt's block demo writes (i * 13 + 5) to the middle sector.
    let mut sector = [0u8; 512];
    let lba = (disk_len / 512 / 2) as u64;
    blk.with_device(|b, _| b.disk().read_blocks(lba, &mut sector)).expect("with_device failed");
    if sector.iter().enumerate().all(|(i, &b)| b == (i * 13 + 5) as u8) {
        println!("[hyp]   the host RAM disk holds the guest's write to sector {lba}");
    } else {
        println!("[hyp]   sector {lba} of the host RAM disk was not written by the guest");
    }
}

fn on_trap(frame: &mut TrapFrame) {
    panic!("unexpected trap {:?} at pc {:#x}", frame.cause(), frame.pc())
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;
    // Straight to the UART, not through the console: the panic may have come
    // from inside println, with the console's lock held.
    let (base, len) = (UART_REGS.0.load(Ordering::Relaxed), UART_REGS.1.load(Ordering::Relaxed));
    if base != 0 {
        // SAFETY: the registers are the ones the console already drives; writes
        // may interleave with its output, which is fine for a dying kernel.
        let mut uart = Uart16550::new(Mmio::new(unsafe { IoMem::new(base as *mut u8, len) }, 0));
        let _ = writeln!(osmium::hal::serial::SerialWriter(&mut uart), "\n[panic] {info}");
    }
    host_sbi::shutdown()
}
