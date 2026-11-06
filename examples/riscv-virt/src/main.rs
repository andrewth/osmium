//! A small kernel for QEMU's RISC-V `virt` machine, built entirely from
//! Osmium components. OpenSBI (QEMU's `-bios default`) starts it in S-mode
//! with the hart id in `a0` and the device tree in `a1`.
//!
//! It walks through the toolkit in boot order: device tree, memory map,
//! frame allocator, heap, Sv39 paging, UART console, scheduler, timer
//! interrupts with preemption, and sleeping on a timer queue.
#![no_std]
#![no_main]

extern crate alloc;

mod hyp;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use demos::guest::image;
pub(crate) use demos::kernel::{FRAMES, Frames};
use demos::kernel::{GuardedStacks, KernelTable, Uptime, now_ns};
use osmium::arch::riscv64::{self, SatpMode, sbi};
use osmium::arch::trap::{self, Interrupt, Trap, TrapFrame};
use osmium::arch::{MAX_CPUS, cpu, irq};
use osmium::boot::fdt::{Fdt, Node};
use osmium::drivers::virtio::console::VirtioConsole;
use osmium::drivers::virtio::mmio::MmioTransport;
use osmium::drivers::virtio::{DeviceType, Transport};
use osmium::hal::block::BlockDevice;
use osmium::hal::console::{Console, SerialConsole, set_console};
use osmium::hal::dma::DmaAllocator;
use osmium::hal::iommu::{DeviceId, DomainId, IoDomain, Iommu, IommuDma};
use osmium::hal::irq::{InterruptController, IrqTable, RegisterError};
use osmium::hal::mmio::IoMem;
use osmium::hal::pci;
use osmium::hal::println;
use osmium::hal::timer::TickRate;
use osmium::hal::usb::UsbHost;
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::Sv39;
use osmium::mm::{MapFlags, MemoryMap, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::netdev::virtio_net::VirtioNet;
use osmium::sched::timer::TimerQueue;
use osmium::storage::ahci::{self, Ahci};
use osmium::storage::nvme::{self, Nvme};
use osmium::storage::virtio_blk::VirtioBlk;
use osmium::sysdrv::iommu::riscv::RiscvIommu;
use osmium::sysdrv::plic::Plic;
use osmium::sysdrv::uart16550::{Mmio, Uart16550};
use osmium::usb::ehci::Ehci;
use osmium::usb::ohci::Ohci;
use osmium::usb::xhci::Xhci;

use osmium::arch::trap::TrapCpu;
use osmium::sched::FifoScheduler;
use osmium::sync::Once;

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

    # Secondary harts start here (via SBI HSM) with a0 = hart id and
    # a1 = &SecondaryBoot, MMU off.
    .globl secondary_start
secondary_start:
    .option push
    .option norelax
    la gp, __global_pointer$
    .option pop
    ld sp, 0(a1)
    call secondary_main

    # The boot hart runs all of kmain on this stack (device probing and driver
    # setup inline into big frames). 64 KiB was outgrown; keep generous
    # headroom. It sits first in .bss, above .data: the page below it is a
    # guard page that kmain unmaps once paging is on, so an overflow faults
    # instead of overwriting the statics there.
    .section .bss.stack
    .align 12
    .globl boot_stack_guard
boot_stack_guard:
    .space 4096
boot_stack_bottom:
    .space 262144
boot_stack_top:
"#
);

// User programs: position-independent U-mode code, copied into user pages.
// System calls use `ecall` with Linux numbering: a7 = number, a0-a2 = args.
core::arch::global_asm!(
    r#"
    .section .rodata.user, "a"
    .globl user_hello, user_hello_end, user_bad, user_bad_end
user_hello:
    li s0, 3
1:  li a7, 64               // write(1, msg, 20)
    li a0, 1
    lla a1, 3f
    li a2, 20
    ecall
    li t0, 20000000         // busy-wait: only the timer can switch us out
2:  addi t0, t0, -1
    bnez t0, 2b
    addi s0, s0, -1
    bnez s0, 1b
    li a7, 93               // exit(0)
    li a0, 0
    ecall
    unimp
3:  .ascii "hello from process ?"
user_hello_end:

user_bad:
    li a7, 64
    li a0, 1
    lla a1, 1f
    li a2, 27
    ecall
    li t0, 0x80200000       // kernel text: not user-accessible
    ld t1, 0(t0)
    unimp
1:  .ascii "about to read kernel memory"
user_bad_end:
"#
);

unsafe extern "C" {
    static user_hello: u8;
    static user_hello_end: u8;
    static user_bad: u8;
    static user_bad_end: u8;
    fn secondary_start();
    static boot_stack_guard: u8;
    static _kernel_start: u8;
    static _etext: u8;
    static _erodata: u8;
    static _kernel_end: u8;
}

fn sym(s: &u8) -> u64 {
    s as *const u8 as u64
}

/// The firmware console, used until the UART driver takes over.
struct SbiConsole;

impl Console for SbiConsole {
    fn write_str(&self, s: &str) {
        for b in s.bytes() {
            if b == b'\n' {
                sbi::console_putchar(b'\r');
            }
            sbi::console_putchar(b);
        }
    }
}

/// The xHCI controller. Its lock masks interrupts on the locking CPU: the
/// controller's interrupt handler takes the same lock, so on one CPU the
/// handler must never run while the lock is held (it would spin forever on
/// a lock its own CPU owns). Masking costs timer-tick latency only for the
/// length of one polled operation, and unlike `try_lock`-and-defer it needs
/// no way to quiet a level-triggered line the handler could not service.
/// Another CPU holding the lock only delays the handler until it releases.
static XHCI: Once<osmium::sync::IrqSpinLock<Xhci<'static, Frames>>> = Once::new();

/// The EHCI and OHCI controllers, under the same kind of lock as [`XHCI`].
static EHCI: Once<osmium::sync::IrqSpinLock<Ehci<'static, Frames>>> = Once::new();
static OHCI: Once<osmium::sync::IrqSpinLock<Ohci<'static, Frames>>> = Once::new();

/// The platform interrupt controller, once the device tree has been read.
static PLIC: Once<Plic> = Once::new();
/// External interrupt handlers by PLIC source number.
static IRQS: IrqTable<64> = IrqTable::new();

/// PLIC handler for the USB controllers' INTx lines. QEMU virt swizzles four
/// sources over every function, so two controllers can share one: each
/// handler checks its own controller's status and ignores a line that is not
/// its own.
fn usb_irq(_irq: u32) {
    if let Some(xhci) = XHCI.get() {
        xhci.lock().handle_interrupt();
    }
    if let Some(ehci) = EHCI.get() {
        ehci.lock().handle_interrupt();
    }
    if let Some(ohci) = OHCI.get() {
        ohci.lock().handle_interrupt();
    }
}

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

/// The kernel page table, shared by all harts.
static PT: KernelTable<Sv39> = osmium::sync::IrqSpinLock::new(None);

/// Task stacks and secondary harts' stacks, each above an unmapped guard page.
static STACKS: GuardedStacks<Sv39> = GuardedStacks::new(&PT, |va| remote_sfence_vma(va, PAGE_SIZE));

/// Invalidates `[start, start + size)` on every other online hart (SBI RFENCE
/// `remote_sfence_vma`, which returns once the harts have done it).
fn remote_sfence_vma(start: usize, size: usize) {
    const EID_RFENCE: usize = 0x5246_4e43;
    let me = cpu::current_id();
    for hart in HARTS.iter().take(demos::kernel::online()).enumerate().filter(|&(c, _)| c != me) {
        let hart = hart.1.load(Ordering::Relaxed);
        // SAFETY: an SBI remote fence only flushes TLB entries on the named hart.
        unsafe {
            core::arch::asm!("ecall", inlateout("a0") 1usize => _, inlateout("a1") hart => _,
                in("a2") start, in("a3") size, in("a6") 1usize, in("a7") EID_RFENCE, options(nostack))
        }
    }
}

/// Tells the trap entry where the incoming task's stack ends, so a trap
/// taken below it moves to the exception stack.
fn on_switch(next: &osmium::sched::Task) {
    // Each process runs on its own page table; kernel tasks on the kernel's.
    let kernel = SATP_ROOT.load(Ordering::Relaxed);
    let root = osmium::proc::switch_root(next, osmium::mm::PhysAddr::new(kernel)).0;
    if riscv64::read_satp() & ((1 << 44) - 1) != (root >> 12) as usize {
        // SAFETY: both kinds of table map the kernel (shared root entries).
        unsafe { riscv64::write_satp(SatpMode::Sv39, 0, root) };
    }
    if root != kernel {
        // User code may have been written on another hart (by fork, exec or
        // a loader) since this hart last fetched from those frames.
        // SAFETY: fence.i only synchronizes this hart's instruction stream.
        unsafe { core::arch::asm!("fence.i") };
    }
    let cpu = TrapCpu::current();
    cpu.set_stack_limit(demos::kernel::stack_limit(next));
    // Where traps from U-mode land while `next` runs user code.
    cpu.set_kernel_stack(next.kernel_stack_range().map_or(0, |r| r.end));
}

/// Returns true if the first hart's `riscv,isa` names single-letter
/// extension `letter`.
fn isa_has(fdt: &osmium::boot::fdt::Fdt<'_>, letter: char) -> bool {
    let isa = fdt
        .find_node("/cpus")
        .and_then(|cpus| cpus.children().find(|c| c.property("riscv,isa").is_some()))
        .and_then(|c| c.property("riscv,isa"))
        .and_then(|p| p.as_str())
        .unwrap_or("");
    isa.strip_prefix("rv64").unwrap_or("").split('_').next().unwrap_or("").contains(letter)
}

/// Returns true if the first hart's `riscv,isa` names multi-letter
/// extension `ext` (such as `zkr`).
fn isa_has_ext(fdt: &osmium::boot::fdt::Fdt<'_>, ext: &str) -> bool {
    fdt.find_node("/cpus")
        .and_then(|cpus| cpus.children().find(|c| c.property("riscv,isa").is_some()))
        .and_then(|c| c.property("riscv,isa"))
        .and_then(|p| p.as_str())
        .is_some_and(|isa| isa.split('_').skip(1).any(|e| e == ext))
}

static UART: Once<SerialConsole<Uart16550<Mmio>>> = Once::new();
static SCHED: FifoScheduler = FifoScheduler::new(2).with_stealing();
static TIMERS: TimerQueue = TimerQueue::new();
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Hart id of each logical CPU.
static HARTS: [AtomicUsize; MAX_CPUS] = [const { AtomicUsize::new(0) }; MAX_CPUS];
static SATP_ROOT: AtomicU64 = AtomicU64::new(0);

/// Handed to a secondary hart through `a1`.
#[repr(C)]
struct SecondaryBoot {
    /// Read first, by `secondary_start`.
    stack_top: u64,
    cpu: usize,
    /// The lowest address of the stack, above its guard page.
    stack_limit: u64,
}

/// Bytes of a secondary hart's boot stack.
const SECONDARY_STACK: usize = 64 * 1024;

/// Timer interrupt period.
const TICK_NS: u64 = 10_000_000;

/// Asks the SBI for this hart's next timer interrupt, a tick from now.
fn arm_timer() {
    if let Some(rate) = demos::kernel::rate() {
        sbi::set_timer(cpu::ticks() + rate.ns_to_ticks(TICK_NS));
    }
}

/// A PCIe host bridge from the device tree: the ECAM window and the 32-bit
/// memory window BARs are assigned from (both as base and length).
struct PcieHost {
    ecam: (u64, u64),
    mem: (u64, u64),
}

fn pcie_host(fdt: &Fdt<'_>) -> Option<PcieHost> {
    let node = fdt.find_compatible(&["pci-host-ecam-generic"])?;
    let (base, len) = node.reg().next()?;
    // Each `ranges` entry: PCI address (3 cells), CPU address (2), size (2).
    let cells: Vec<u32> = node.property("ranges")?.as_u32_cells().collect();
    let mem = cells.as_chunks::<7>().0.iter().find(|r| r[0] >> 24 & 3 == 2).map(|r| {
        let cpu = (r[3] as u64) << 32 | r[4] as u64;
        let size = (r[5] as u64) << 32 | r[6] as u64;
        (cpu, size)
    })?;
    Some(PcieHost { ecam: (base, len?), mem })
}

/// Finds the first function of class `class`, assigns its BARs from `bars`
/// and enables it; returns its address, BAR `bar` and interrupt pin.
fn find_pci(
    host: &PcieHost,
    bars: &mut pci::BarAllocator,
    class: pci::Class,
    bar: u8,
) -> Option<(pci::Address, u64, u64, u8)> {
    // SAFETY: the device tree puts the ECAM window here, mapped as device
    // memory; only this function uses it.
    let ecam = pci::Ecam::new(unsafe { IoMem::new(host.ecam.0 as *mut u8, host.ecam.1 as usize) }, 0);
    let mut found = None;
    pci::for_each_function(&ecam, 0, |f| {
        if found.is_none() && f.class() == class {
            found = Some(f.address());
        }
    });
    let f = pci::Function::new(&ecam, found?)?;
    // Firmware (OpenSBI) leaves BARs unassigned on this machine. One
    // allocator serves every device, so their BARs don't overlap.
    bars.assign(&f).ok()?;
    // Bus addresses double as CPU addresses because QEMU's `ranges` maps the
    // 32-bit window 1:1; another board would translate here.
    let bar = f.bar(bar)?;
    // Memory space and bus master only: unassigned I/O BARs (ich9-ahci has
    // legacy ones) stay at 0 and must not decode.
    f.enable_memory_and_dma();
    Some((f.address(), bar.address, bar.size, f.interrupt_pin()))
}

/// The PLIC source a PCI function's INTx `pin` (1 = INTA) is wired to, read
/// from the host bridge's `interrupt-map`: entries of child unit address
/// (3 cells), pin (1), interrupt parent phandle, parent unit address (the
/// parent's `#address-cells`) and parent specifier (`#interrupt-cells`).
fn pci_intx_irq(fdt: &Fdt<'_>, addr: pci::Address, pin: u8) -> Option<u32> {
    let node = fdt.find_compatible(&["pci-host-ecam-generic"])?;
    let map: Vec<u32> = node.property("interrupt-map")?.as_u32_cells().collect();
    let mask: Vec<u32> = node.property("interrupt-map-mask")?.as_u32_cells().collect();
    let unit = [(addr.bus as u32) << 16 | (addr.device as u32) << 11 | (addr.function as u32) << 8, 0, 0, pin as u32];
    let cell = |n: &Node<'_>, name, default| n.property(name).and_then(|p| p.as_u32()).unwrap_or(default) as usize;
    let mut rest = map.as_slice();
    while let Some((&[a0, a1, a2, a_pin, phandle], after)) = rest.split_first_chunk::<5>() {
        let parent = fdt.all_nodes().find(|n| n.property("phandle").and_then(|p| p.as_u32()) == Some(phandle))?;
        let (acells, icells) = (cell(&parent, "#address-cells", 0), cell(&parent, "#interrupt-cells", 1));
        let parent_unit = after.get(..acells + icells)?;
        let masked = |k: usize, v: u32| v & mask.get(k).copied().unwrap_or(!0);
        if [a0, a1, a2, a_pin].iter().zip(unit).enumerate().all(|(k, (&m, u))| masked(k, m) == masked(k, u)) {
            return parent_unit.get(acells).copied();
        }
        rest = after.get(acells + icells..)?;
    }
    None
}

/// Routes a USB function's INTx line to a PLIC source on this hart and
/// registers [`usb_irq`] for it (once, if functions share the source). The
/// caller then turns the controller's interrupts on. Returns the PLIC source
/// number.
fn usb_interrupts(fdt: &Fdt<'_>, addr: pci::Address, pin: u8, plic_base: u64, plic_len: u64) -> Option<u32> {
    if pin == 0 {
        return None;
    }
    // QEMU virt swizzles INTx over four PLIC sources starting at 32.
    let swizzle = 32 + (addr.device as u32 + pin as u32 - 1) % 4;
    let irq = match pci_intx_irq(fdt, addr, pin) {
        Some(irq) if irq == swizzle => irq,
        Some(irq) => {
            println!("[usb]   interrupt-map says source {irq}, the virt swizzle {swizzle}; using the map");
            irq
        }
        None => swizzle,
    };
    // SAFETY: the device tree puts the PLIC here; it was mapped as device memory.
    let io = unsafe { IoMem::new(plic_base as *mut u8, plic_len as usize) };
    let plic = PLIC.call_once(|| {
        Plic::new(io, |cpu| Plic::supervisor_context(HARTS.get(cpu).map_or(0, |h| h.load(Ordering::Relaxed))))
    });
    match IRQS.register(irq, &usb_irq) {
        Ok(()) | Err(RegisterError::Busy) => {}
        Err(RegisterError::OutOfRange) => return None,
    }
    plic.set_threshold(0);
    plic.enable(irq);
    // SAFETY: only adds supervisor external interrupts; the handler is registered.
    unsafe { riscv64::write_sie(riscv64::read_sie() | riscv64::SIE_SEIE) };
    Some(irq)
}

/// Base and size of every virtio-mmio slot in the device tree.
fn virtio_slots<'src>(fdt: &Fdt<'src>) -> impl Iterator<Item = (u64, u64)> + 'src {
    fdt.all_nodes()
        .filter(|n| n.compatible().any(|c| c == "virtio,mmio"))
        .filter_map(|n| n.reg().next().map(|(a, s)| (a, s.unwrap_or(0x200))))
}

/// Runs `before` ahead of every transfer on the disk it wraps.
struct Before<'hook, B> {
    disk: B,
    before: &'hook dyn Fn(),
}

impl<B: BlockDevice> BlockDevice for Before<'_, B> {
    fn block_size(&self) -> usize {
        self.disk.block_size()
    }

    fn num_blocks(&self) -> u64 {
        self.disk.num_blocks()
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), osmium::hal::block::BlockError> {
        (self.before)();
        self.disk.read_blocks(lba, buf)
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), osmium::hal::block::BlockError> {
        (self.before)();
        self.disk.write_blocks(lba, buf)
    }

    fn flush(&mut self) -> Result<(), osmium::hal::block::BlockError> {
        self.disk.flush()
    }
}

/// Brings up an NVMe controller whose DMA memory comes from `dma`, and runs
/// a block round trip on it, calling `before` ahead of each transfer.
fn nvme_demo<D: DmaAllocator>(addr: pci::Address, io: IoMem, dma: &D, before: &dyn Fn()) {
    let (b, d, f) = (addr.bus, addr.device, addr.function);
    let more = io.clone();
    match Nvme::new(io, dma, &Uptime) {
        Ok(disk) => {
            let (model, nsid) = (alloc::string::String::from(disk.model()), disk.namespace());
            let mut disk = Before { disk, before };
            let (n, bs) = (disk.num_blocks(), disk.block_size());
            let r = demos::block_roundtrip(&mut disk);
            println!("[nvme]  {b:02x}:{d:02x}.{f} \"{model}\" namespace {nsid}: {n} blocks of {bs}; round trip {r:?}");
        }
        Err(e) => println!("[nvme]  {b:02x}:{d:02x}.{f}: init failed: {e:?}"),
    }
    // Again with several I/O queue pairs, each given a round trip of its own.
    match Nvme::with_queues(more, dma, &Uptime, None, 4) {
        Ok(disk) => {
            let n = disk.io_queues();
            let mut ok = 0;
            for mut handle in (0..n).filter_map(|q| disk.queue(q)) {
                before();
                ok += demos::block_roundtrip(&mut handle).is_ok() as usize;
            }
            println!("[nvme]  {b:02x}:{d:02x}.{f} {n} I/O queues; round trip on each: {ok} ok");
        }
        Err(e) => println!("[nvme]  {b:02x}:{d:02x}.{f}: multi-queue init failed: {e:?}"),
    }
}

#[unsafe(no_mangle)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "boot: what QEMU's machine provides is set up once here, so a failure means a broken machine or a bug in this example; the panic handler reports which"
)]
extern "C" fn kmain(hartid: usize, dtb: usize) -> ! {
    // SAFETY: the boot hart is logical CPU 0; secondaries get 1, 2, ...
    unsafe { cpu::set_current_id(0) };
    HARTS[0].store(hartid, Ordering::Relaxed);
    // Before anything can fault: OpenSBI leaves stvec pointing at `_start`.
    trap::set_handler(on_trap);
    // SAFETY: we run on a valid kernel stack from here on.
    unsafe { trap::install() };
    set_console(&SbiConsole);
    println!("\nosmium riscv-virt example (hart {hartid})");

    // --- Device tree -------------------------------------------------------
    // SAFETY: OpenSBI passes a valid DTB that nothing overwrites (we reserve it below).
    let fdt = unsafe { Fdt::from_ptr(dtb as *const u8) }.expect("bad device tree");
    let model = fdt.root().property("model").and_then(|p| p.as_str()).unwrap_or("?");
    println!("[fdt]   {model}, {} bytes, bootargs {:?}", fdt.total_size(), fdt.bootargs().unwrap_or(""));
    let timebase = fdt.find_node("/cpus").and_then(|c| c.property("timebase-frequency")).and_then(|p| p.as_u32());
    demos::kernel::set_rate(TickRate::new(timebase.unwrap_or(10_000_000) as u64));

    // --- Console on the real UART -----------------------------------------
    let uart_node = fdt.find_compatible(&["ns16550a"]).expect("no UART");
    let (uart_base, uart_len) =
        uart_node.reg().next().map(|(a, s)| (a, s.unwrap_or(0x100))).expect("UART has a reg property");
    let shift = uart_node.property("reg-shift").and_then(|p| p.as_u32()).unwrap_or(0) as u8;
    // SAFETY: the device tree says the UART's registers live here; nothing else uses them.
    let io = unsafe { IoMem::new(uart_base as *mut u8, uart_len as usize) };
    let mut uart = Uart16550::new(Mmio::new(io, shift));
    uart.init(None);
    set_console(UART.call_once(|| SerialConsole::new(uart)));
    println!("[uart]  ns16550a at {uart_base:#x}, console switched from SBI");

    // --- Physical memory ---------------------------------------------------
    let mut map = MemoryMap::<32>::new();
    fdt.fill_memory_map(&mut map, Some(PhysAddr::new(dtb as u64))).expect("fill_memory_map failed");
    // SAFETY: linker-provided symbols.
    let (kstart, etext, erodata, kend) =
        unsafe { (sym(&_kernel_start), sym(&_etext), sym(&_erodata), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).expect("reserve failed");
    map.page_align_usable();
    for r in map.regions() {
        println!("[mem]   {:#011x}..{:#011x} {:?}", r.start.0, r.end.0, r.kind);
    }
    // SAFETY: the memory map says these ranges are free RAM, identity-mapped.
    unsafe { demos::kernel::add_ram(map.usable().map(|r| r.start..r.end)) };
    demos::kernel::report_frames();

    // --- Heap ------------------------------------------------------------
    HEAP.init(&FRAMES);
    let squares: Vec<u64> = (0..1000).map(|i| i * i).collect();
    let mut s = String::new();
    for w in ["heap", "works"] {
        s.push_str(w);
        s.push(' ');
    }
    println!("[heap]  {}(sum of squares {}), {:?}", s, squares.iter().sum::<u64>(), HEAP.stats());

    // --- Paging (Sv39, W^X) ------------------------------------------------
    // The kernel's own memory node is mapped piecewise below (W^X); any
    // other node, all of which the frame allocator was given, as RW.
    let ram = fdt
        .memory()
        .find(|&(base, len)| (base..base + len).contains(&kstart))
        .expect("no memory node holds the kernel");
    let ram_end = ram.0 + ram.1;
    let mut pt: PageTable<Sv39, &'static Frames> = PageTable::new(&FRAMES).expect("new failed");
    let k = |f| f | MapFlags::GLOBAL;
    let va = |a: u64| VirtAddr::new(a);
    let pa = |a: u64| PhysAddr::new(a);
    // RAM below the kernel holds firmware (PMP-protected, never touched) and
    // free frames the allocator hands out.
    pt.map_range(va(ram.0), pa(ram.0), kstart - ram.0, k(MapFlags::RW)).expect("map_range failed");
    pt.map_range(va(kstart), pa(kstart), etext - kstart, k(MapFlags::RX)).expect("map_range failed");
    pt.map_range(va(etext), pa(etext), erodata - etext, k(MapFlags::READ)).expect("map_range failed");
    pt.map_range(va(erodata), pa(erodata), ram_end - erodata, k(MapFlags::RW)).expect("map_range failed");
    for (base, len) in fdt.memory().filter(|&m| m != ram) {
        let (start, end) = (base.next_multiple_of(PAGE_SIZE as u64), (base + len) & !(PAGE_SIZE as u64 - 1));
        if start < end {
            pt.map_range(va(start), pa(start), end - start, k(MapFlags::RW)).expect("map_range failed");
        }
    }
    // Device windows from the device tree.
    let mut map_device = |base, len| demos::kernel::map_device(&mut pt, base, len);
    map_device(uart_base, PAGE_SIZE as u64);
    for (base, len) in virtio_slots(&fdt) {
        map_device(base, len);
    }
    let plic_reg = fdt.find_compatible(&["riscv,plic0", "sifive,plic-1.0.0"]).and_then(|n| n.reg().next());
    if let Some((base, Some(len))) = plic_reg {
        map_device(base, len);
    }
    let pcie = pcie_host(&fdt);
    let mut bars = pcie.as_ref().map(|h| pci::BarAllocator::new(h.mem.0, h.mem.1));
    if let Some(h) = &pcie {
        for (base, len) in [h.ecam, h.mem] {
            map_device(base, len);
        }
    }
    // SAFETY: the table identity-maps the running code, its stack, the heap and the UART.
    unsafe { riscv64::write_satp(SatpMode::Sv39, 0, pt.root().0) };
    SATP_ROOT.store(pt.root().0, Ordering::Release);
    // The page below the boot stack becomes its guard (see `_start`).
    // SAFETY: a linker symbol.
    let guard = unsafe { sym(&boot_stack_guard) };
    if demos::kernel::unmap_guard(&mut pt, guard) {
        let bottom = guard as usize + PAGE_SIZE;
        demos::kernel::set_boot_stack_limit(bottom);
        TrapCpu::current().set_stack_limit(bottom);
    }
    let t = pt.translate(va(kmain as *const () as u64)).expect("translate failed");
    println!("[mmu]   Sv39 on, root {:#x}; kmain mapped {:?} via {:?} page", pt.root().0, t.flags, t.size);
    let t = pt.translate(va(ram_end - 1)).expect("translate failed");
    println!("[mmu]   top of RAM mapped {:?} via {:?} page", t.flags, t.size);
    if isa_has_ext(&fdt, "zkr") {
        // SAFETY: the devicetree lists Zkr, and OpenSBI sets `mseccfg.SSEED` for
        // harts that have it, so S-mode may read `seed`.
        unsafe { osmium::arch::rng::assume_seed_csr() };
    }
    demos::kernel::rand_demo();
    *PT.lock() = Some(pt);
    demos::fault::set_exception_stack();
    osmium::sched::set_stack_allocator(&STACKS);
    osmium::sched::set_switch_hook(on_switch);
    println!(
        "[guard] boot, hart and task stacks get unmapped guard pages; overflowing traps move to a per-hart exception stack"
    );
    // Processes may use FP: each one's registers are switched with its task.
    if isa_has(&fdt, 'd') {
        // SAFETY: the kernel is soft-float, and the harts have D.
        let on = unsafe { osmium::arch::fp::enable() };
        println!("[fp]    user FP/SIMD state switched per task: {on}");
    }

    // --- Scheduler and timer interrupts -----------------------------------
    osmium::sched::inject_scheduler(&SCHED);
    osmium::sched::init_cpu();
    arm_timer();
    // SAFETY: enabling timer and software interrupts; the trap vector is installed.
    unsafe { riscv64::write_sie(riscv64::SIE_STIE | riscv64::SIE_SSIE) };
    irq::enable();
    println!("[sched] FIFO scheduler, {} ms tick", TICK_NS / 1_000_000);

    // --- Secondary harts ----------------------------------------------------
    osmium::sched::set_remote_wake_hook(|cpu| {
        if let Some(h) = HARTS.get(cpu) {
            let _ = sbi::send_ipi(1, h.load(Ordering::Relaxed));
        }
    });
    // User threads run on any hart: address-space changes shoot the others down.
    osmium::arch::mmu::set_remote_flush(|start, pages| remote_sfence_vma(start, pages * PAGE_SIZE));
    let cpus = fdt.find_node("/cpus").expect("no /cpus");
    let harts = cpus
        .children()
        .filter(|c| c.property("device_type").and_then(|p| p.as_str()) == Some("cpu"))
        .filter(|c| c.property("status").and_then(|p| p.as_str()).is_none_or(|s| s == "okay"))
        .filter_map(|c| c.reg().next().map(|(h, _)| h as usize));
    let mut ncpus = 1;
    for (cpu, h) in demos::kernel::secondaries(harts, hartid) {
        // Above a guard page, which takes effect once the hart turns paging on.
        let Some(stack) = STACKS.leak(SECONDARY_STACK) else {
            println!("[smp]   no memory for hart {h}'s stack; continuing with {ncpus} CPUs");
            break;
        };
        let boot = alloc::boxed::Box::leak(alloc::boxed::Box::new(SecondaryBoot {
            stack_top: stack.end,
            cpu,
            stack_limit: stack.start,
        }));
        if let Some(slot) = HARTS.get(cpu) {
            slot.store(h, Ordering::Relaxed);
        }
        // SAFETY: `secondary_start` sets up gp and the stack from `boot`.
        let started = unsafe { sbi::hart_start(h, secondary_start as *const () as usize, boot as *const _ as usize) };
        // One hart at a time: a hart that fails to start or never checks in
        // ends the bring-up, so CPU indices stay dense.
        if let Err(e) = started {
            println!("[smp]   hart {h} did not start ({e:?}); continuing with {ncpus} CPUs");
            break;
        }
        if !demos::kernel::wait_online(cpu + 1) {
            println!("[smp]   hart {h} did not check in within 1 s; continuing with {ncpus} CPUs");
            break;
        }
        ncpus += 1;
    }
    println!("[smp]   {ncpus} CPUs online");

    // --- virtio-net ----------------------------------------------------------
    let net = virtio_slots(&fdt).find_map(|(base, len)| {
        // SAFETY: the device tree puts a virtio-mmio slot here, mapped above;
        // nothing else uses it.
        let t = MmioTransport::new(unsafe { IoMem::new(base as *mut u8, len as usize) }).ok()?;
        (t.device_type() == DeviceType::Net).then_some((base, t))
    });
    match net {
        Some((base, t)) => {
            let legacy = if t.is_legacy() { "legacy" } else { "1.x" };
            let mut net = VirtioNet::new(t, &FRAMES).expect("virtio-net init failed");
            println!("[net]   virtio-net ({legacy}) at {base:#x}");
            demos::arp(&mut net, now_ns);
            demos::net(&mut net, now_ns);
            demos::net6();
            demos::iscsi(&mut net, now_ns);
            *NETDEV.lock() = Some(alloc::boxed::Box::new(net));
        }
        None => println!("[net]   no virtio-net device"),
    }

    // --- virtio-blk ----------------------------------------------------------
    let blk = virtio_slots(&fdt).find_map(|(base, len)| {
        // SAFETY: the device tree puts a virtio-mmio slot here, mapped above;
        // nothing else uses it (the net probe's transport was dropped).
        let t = MmioTransport::new(unsafe { IoMem::new(base as *mut u8, len as usize) }).ok()?;
        (t.device_type() == DeviceType::Block).then_some((base, t))
    });
    match blk {
        Some((base, t)) => {
            let legacy = if t.is_legacy() { "legacy" } else { "1.x" };
            let mut disk = VirtioBlk::new(t, &FRAMES).expect("virtio-blk init failed");
            let n = disk.num_blocks();
            match demos::block_roundtrip(&mut disk) {
                Ok(lba) => println!(
                    "[blk]   virtio-blk ({legacy}) at {base:#x}: {n} sectors; wrote and read back sector {lba}"
                ),
                Err(e) => println!("[blk]   virtio-blk ({legacy}) at {base:#x}: {n} sectors; round trip failed: {e:?}"),
            }
        }
        None => println!("[blk]   no virtio-blk device"),
    }

    // --- virtio-console ------------------------------------------------------
    let vcon = virtio_slots(&fdt).find_map(|(base, len)| {
        // SAFETY: the device tree puts a virtio-mmio slot here, mapped above;
        // nothing else uses it (earlier probes' transports were dropped).
        let t = MmioTransport::new(unsafe { IoMem::new(base as *mut u8, len as usize) }).ok()?;
        (t.device_type() == DeviceType::Console).then_some((base, t))
    });
    match vcon {
        Some((base, t)) => {
            let legacy = if t.is_legacy() { "legacy" } else { "1.x" };
            let mut con = VirtioConsole::new(t, &FRAMES).expect("virtio-console init failed");
            // With multiport the device announces its ports through the control queue.
            for _ in 0..50_000_000u32 {
                con.poll();
                if con.port_present(0) {
                    break;
                }
                core::hint::spin_loop();
            }
            let msg = b"hello from osmium over virtio-console\n";
            match con.write(0, msg) {
                Ok(()) => {
                    println!("[vcon]  virtio-console ({legacy}) at {base:#x}: wrote {} bytes to port 0", msg.len())
                }
                Err(e) => println!("[vcon]  virtio-console ({legacy}) at {base:#x}: write failed: {e:?}"),
            }
        }
        None => println!("[vcon]  no virtio-console device"),
    }

    // --- IOMMU behind PCIe ------------------------------------------------------
    // Before any other PCI DMA: QEMU's riscv-iommu starts out blocking it all
    // and the driver puts it in pass-through until a device attaches.
    let iommu = pcie.as_ref().zip(bars.as_mut()).and_then(|(h, b)| find_pci(h, b, pci::Class::IOMMU, 0)).and_then(
        |(addr, base, len, _)| {
            // SAFETY: BAR 0 was just assigned this range inside the mapped
            // window; nothing else uses it.
            let io = unsafe { IoMem::new(base as *mut u8, len as usize) };
            match RiscvIommu::new(io, &FRAMES, &Uptime, 0) {
                Ok(unit) => {
                    println!(
                        "[iommu] {:02x}:{:02x}.{} RISC-V IOMMU: Sv39 domains, {} bit I/O addresses",
                        addr.bus,
                        addr.device,
                        addr.function,
                        unit.iova_limit().trailing_zeros()
                    );
                    Some(unit)
                }
                Err(e) => {
                    println!("[iommu] {:02x}:{:02x}.{}: init failed: {e:?}", addr.bus, addr.device, addr.function);
                    None
                }
            }
        },
    );

    if let Some(unit) = &iommu {
        match pcie.as_ref().zip(bars.as_mut()).and_then(|(h, b)| find_pci(h, b, demos::iommu::TESTDEV_CLASS, 0)) {
            Some((addr, base, len, _)) => {
                // SAFETY: BAR 0 was just assigned this range inside the mapped
                // window; nothing else uses it.
                let io = unsafe { IoMem::new(base as *mut u8, len as usize) };
                demos::iommu::testdev(unit, DeviceId::new(0, addr), io, &FRAMES, "riscv-iommu");
            }
            None => println!("[iommu] no iommu-testdev"),
        }
    }

    // --- AHCI behind PCIe -------------------------------------------------------
    match pcie.as_ref().zip(bars.as_mut()).and_then(|(h, b)| find_pci(h, b, ahci::CLASS, ahci::ABAR)) {
        Some((addr, base, len, _)) => {
            // SAFETY: BAR 5 was just assigned this range inside the mapped
            // window; nothing else uses it.
            let io = unsafe { IoMem::new(base as *mut u8, len as usize) };
            let (b, d, f) = (addr.bus, addr.device, addr.function);
            match Ahci::new(io, &FRAMES, Some(&Uptime)) {
                Ok(mut hba) => {
                    let ports: Vec<u8> = hba.disks().collect();
                    println!("[ahci]  {b:02x}:{d:02x}.{f} AHCI {:#x}, SATA disks on ports {ports:?}", hba.version());
                    for port in ports {
                        match hba.take_disk(port) {
                            Ok(mut disk) => {
                                let (n, bs) = (disk.num_blocks(), disk.block_size());
                                let r = demos::block_roundtrip(&mut disk);
                                println!(
                                    "[ahci]  port {port} \"{}\": {n} sectors of {bs}; round trip {r:?}",
                                    disk.model()
                                );
                            }
                            Err(e) => println!("[ahci]  port {port}: {e:?}"),
                        }
                    }
                }
                Err(e) => println!("[ahci]  {b:02x}:{d:02x}.{f}: init failed: {e:?}"),
            }
        }
        None => println!("[ahci]  no AHCI controller"),
    }

    // --- NVMe behind PCIe -------------------------------------------------------
    match pcie.as_ref().zip(bars.as_mut()).and_then(|(h, b)| find_pci(h, b, pci::Class::NVME, nvme::BAR)) {
        Some((addr, base, len, _)) => {
            // SAFETY: BAR 0 was just assigned this range inside the mapped
            // window; nothing else uses it.
            let io = unsafe { IoMem::new(base as *mut u8, len as usize) };
            match &iommu {
                // Behind an IOMMU the controller sees only the buffers its
                // driver allocates from the domain, at I/O virtual addresses.
                Some(unit) => {
                    let id = DeviceId::new(0, addr);
                    let domain = IoDomain::new(unit, DomainId(1), &FRAMES).expect("IOMMU domain");
                    let dma = IommuDma::new(domain, &FRAMES, 0x10_0000..0x4000_0000).expect("IOVA window");
                    match dma.with_domain(|d| d.attach(id)) {
                        Ok(()) => {
                            println!("[iommu] NVMe {id:?} attached to domain 1; its DMA now goes through the IOMMU")
                        }
                        Err(e) => println!("[iommu] attaching the NVMe controller failed: {e:?}"),
                    }
                    // QEMU 11.0 caches only the permission of the first access to
                    // a page in its IOTLB (the NVMe driver's buffers are written
                    // by the device first, then read), so flush it ahead of each
                    // transfer. Newer QEMU caches the page's full permission.
                    nvme_demo(addr, io, &dma, &|| {
                        let _ = unit.invalidate(DomainId(1));
                    });
                    let mut faults = 0;
                    while let Some(f) = unit.take_fault() {
                        println!("[iommu] fault: {f:?}");
                        faults += 1;
                    }
                    let detached = dma.with_domain(|d| d.detach(id));
                    println!("[iommu] NVMe detached: {detached:?}, {faults} faults logged");
                }
                None => nvme_demo(addr, io, &FRAMES, &|| {}),
            }
        }
        None => println!("[nvme]  no NVMe controller"),
    }

    // --- Displays behind PCIe (virtio-gpu-pci, bochs-display) -------------------
    if let (Some(h), Some(b)) = (pcie.as_ref(), bars.as_mut()) {
        // SAFETY: the device tree puts the ECAM window here, mapped as device
        // memory; the display probe is its only user meanwhile.
        let ecam = pci::Ecam::new(unsafe { IoMem::new(h.ecam.0 as *mut u8, h.ecam.1 as usize) }, 0);
        // SAFETY: BARs are assigned inside the memory window, mapped above.
        let mut map = |addr: u64, size: u64| unsafe { IoMem::new(addr as *mut u8, size as usize) };
        demos::display::pci(&ecam, 0, 640, 480, Some(b), &mut map, &FRAMES);
    }
    let gpu = virtio_slots(&fdt).find_map(|(base, len)| {
        // SAFETY: a virtio-mmio slot from the device tree, mapped above;
        // nothing else uses it.
        let t = MmioTransport::new(unsafe { IoMem::new(base as *mut u8, len as usize) }).ok()?;
        (t.device_type() == DeviceType::Gpu).then_some(t)
    });
    if let Some(t) = gpu {
        demos::display::virtio_gpu("virtio-gpu-mmio", t, &FRAMES);
    }

    // --- xHCI behind PCIe ------------------------------------------------------
    match pcie.as_ref().zip(bars.as_mut()).and_then(|(h, b)| find_pci(h, b, pci::Class::XHCI, 0)) {
        Some((addr, base, len, pin)) => {
            // SAFETY: BAR 0 was just assigned this range inside the mapped
            // window; nothing else uses it.
            let io = unsafe { IoMem::new(base as *mut u8, len as usize) };
            let mut hc = Xhci::with_clock(io, &FRAMES, &Uptime).expect("xHCI init failed");
            hc.no_op().expect("xHCI command ring");
            println!(
                "[usb]   xHCI at {:02x}:{:02x}.{} BAR0 {base:#x}, {} ports",
                addr.bus,
                addr.device,
                addr.function,
                hc.num_ports()
            );
            // In a static, so drivers built on it (and a file system on the
            // USB stick) and the interrupt handler can live as long as the kernel.
            let xhci = XHCI.call_once(|| osmium::sync::IrqSpinLock::new(hc));
            match plic_reg.and_then(|(base, len)| usb_interrupts(&fdt, addr, pin, base, len?)) {
                Some(irq) => {
                    xhci.lock().enable_interrupts();
                    println!("[usb]   xHCI interrupts on PLIC source {irq}");
                }
                None => println!("[usb]   xHCI interrupts unavailable; polling"),
            }
            let found = demos::usb(xhci, now_ns);
            demos::usb_uas(xhci, &found, now_ns);
            println!("[usb]   xHCI interrupts: {}", xhci.lock().interrupts_handled());
        }
        None => println!("[usb]   no xHCI controller"),
    }

    // --- EHCI and OHCI behind PCIe ---------------------------------------------
    match pcie.as_ref().zip(bars.as_mut()).and_then(|(h, b)| find_pci(h, b, pci::Class::EHCI, 0)) {
        Some((addr, base, len, pin)) => {
            // SAFETY: BAR 0 was just assigned this range inside the mapped
            // window; nothing else uses it.
            let io = unsafe { IoMem::new(base as *mut u8, len as usize) };
            match Ehci::new(io, &FRAMES, &Uptime) {
                Ok(hc) => {
                    println!(
                        "[usb]   EHCI at {:02x}:{:02x}.{} BAR0 {base:#x}, {} ports",
                        addr.bus,
                        addr.device,
                        addr.function,
                        hc.ports()
                    );
                    let ehci = EHCI.call_once(|| osmium::sync::IrqSpinLock::new(hc));
                    match plic_reg.and_then(|(base, len)| usb_interrupts(&fdt, addr, pin, base, len?)) {
                        Some(irq) => {
                            ehci.lock().enable_interrupts();
                            println!("[usb]   EHCI interrupts on PLIC source {irq}");
                        }
                        None => println!("[usb]   EHCI interrupts unavailable; polling"),
                    }
                    demos::usb(ehci, now_ns);
                    println!("[usb]   EHCI interrupts: {}", ehci.lock().interrupts_handled());
                }
                Err(e) => println!("[usb]   EHCI init failed: {e:?}"),
            }
        }
        None => println!("[usb]   no EHCI controller"),
    }
    match pcie.as_ref().zip(bars.as_mut()).and_then(|(h, b)| find_pci(h, b, osmium::usb::ohci::CLASS, 0)) {
        Some((addr, base, len, pin)) => {
            // SAFETY: BAR 0 was just assigned this range inside the mapped
            // window; nothing else uses it.
            let io = unsafe { IoMem::new(base as *mut u8, len as usize) };
            match Ohci::new(io, &FRAMES, &Uptime) {
                Ok(hc) => {
                    println!(
                        "[usb]   OHCI at {:02x}:{:02x}.{} BAR0 {base:#x}, {} ports",
                        addr.bus,
                        addr.device,
                        addr.function,
                        hc.ports()
                    );
                    let ohci = OHCI.call_once(|| osmium::sync::IrqSpinLock::new(hc));
                    match plic_reg.and_then(|(base, len)| usb_interrupts(&fdt, addr, pin, base, len?)) {
                        Some(irq) => {
                            ohci.lock().enable_interrupts();
                            println!("[usb]   OHCI interrupts on PLIC source {irq}");
                        }
                        None => println!("[usb]   OHCI interrupts unavailable; polling"),
                    }
                    demos::usb(ohci, now_ns);
                    println!("[usb]   OHCI interrupts: {}", ohci.lock().interrupts_handled());
                }
                Err(e) => println!("[usb]   OHCI init failed: {e:?}"),
            }
        }
        None => println!("[usb]   no OHCI controller"),
    }

    demos::run_all(&demos::Env { timers: &TIMERS, ticks: &TICKS, now_ns });
    if ncpus > 1 {
        demos::smp(ncpus);
        demos::balance(ncpus, &|| SCHED.steals());
    }
    demos::fault::fault_demo();
    demos::fault::overflow_demo();
    demos::user::boot_vfs();
    user_demo();
    if hyp::available(&fdt) {
        hyp::demo();
        hyp::demo_irq();
        hyp::demo_smp(ncpus);
        hyp::demo_fp();
    } else {
        println!("[hyp]   no H extension in riscv,isa: skipping the guests (running as one?)");
    }

    println!(
        "[done]  {} timer ticks, {} free frames; shutting down",
        TICKS.load(Ordering::Relaxed),
        demos::kernel::free_frames()
    );
    sbi::shutdown()
}

/// Entry point of secondary harts, on their own stack with the MMU off.
#[unsafe(no_mangle)]
extern "C" fn secondary_main(hartid: usize, boot: &SecondaryBoot) -> ! {
    // SAFETY: each secondary gets a distinct logical id from the boot hart.
    unsafe { cpu::set_current_id(boot.cpu) };
    // SAFETY: we are on the stack the boot hart allocated for us.
    unsafe { trap::install() };
    // SAFETY: the boot hart's table identity-maps everything we touch.
    unsafe { riscv64::write_satp(SatpMode::Sv39, 0, SATP_ROOT.load(Ordering::Acquire)) };
    // Paging is on, so the guard page below this stack is in force.
    demos::kernel::set_boot_stack_limit(boot.stack_limit as usize);
    TrapCpu::current().set_stack_limit(boot.stack_limit as usize);
    demos::fault::set_exception_stack();
    if osmium::arch::fp::enabled() {
        // SAFETY: as on the boot hart.
        unsafe { osmium::arch::fp::enable() };
    }
    osmium::sched::init_cpu();
    arm_timer();
    // SAFETY: as on the boot hart.
    unsafe { riscv64::write_sie(riscv64::SIE_STIE | riscv64::SIE_SSIE) };
    irq::enable();
    println!("[smp]   hart {hartid} online as CPU {}", boot.cpu);
    demos::kernel::check_in();
    // This flow of execution has nothing more to do: hand the CPU to the
    // scheduler for good.
    osmium::sched::exit()
}

/// Drops to U-mode at `pc` with stack pointer `sp`.
///
/// # Safety
/// See [`demos::user::Enter`].
unsafe fn enter_user(pc: u64, sp: u64) -> ! {
    // The code may have been written through the identity map, possibly by
    // another hart: make it visible to this hart's instruction fetch.
    // SAFETY: fence.i only synchronizes this hart's instruction stream.
    unsafe { core::arch::asm!("fence.i") };
    // SAFETY: the caller's contract; traps are installed, and the switch
    // hook keeps TrapCpu's kernel stack on this task.
    unsafe { riscv64::enter_user(pc as usize, sp as usize) }
}

/// What `fork` and `execve` need: Sv39 spaces sharing the kernel's root
/// entries, laid out as `demos::user` says.
fn platform() -> osmium::proc::Platform {
    demos::user::platform(
        || demos::user::new_space(&PT),
        |root| {
            // SAFETY: the table shares the kernel's root entries; fence.i
            // only synchronizes this hart's instruction stream.
            unsafe {
                riscv64::write_satp(SatpMode::Sv39, 0, root.0);
                core::arch::asm!("fence.i");
            }
        },
        // SAFETY: the child's task is running with its table active (the
        // switch hook), and the frame is its parent's from an ecall.
        |frame| unsafe { riscv64::resume_user(&frame) },
    )
}

/// The user demos: the hand-written U-mode programs, the Rust ones, the
/// position-independent ones, and the socket calls over virtio-net.
fn user_demo() {
    osmium::proc::set_platform(platform());
    let platform = platform();
    // SAFETY: linker symbols delimiting the user programs in .rodata.
    let (hello, bad) = unsafe { (image(&user_hello, &user_hello_end), image(&user_bad, &user_bad_end)) };
    demos::user::demo(&platform, hello, bad, "U-mode", enter_user);
    demos::user::pie_demo(&platform, enter_user);
    // Taken out first: the lock must not be held while the demo runs.
    let dev = NETDEV.lock().take();
    match dev {
        Some(dev) => demos::user::socket_demo(&platform, dev, &TIMERS, enter_user),
        None => println!("[sock]  no network device"),
    }
}

/// The virtio-net device, kept for the socket demo once the others are done
/// with it.
static NETDEV: osmium::sync::IrqSpinLock<Option<alloc::boxed::Box<dyn osmium::hal::net::NetDevice + Send>>> =
    osmium::sync::IrqSpinLock::new(None);

/// Runs the trap handler, then, before returning to user mode from an
/// interrupt, delivers pending signals (and stops threads of a process that
/// is ending).
fn on_trap(frame: &mut TrapFrame) {
    handle_trap(frame);
    demos::user::before_return(frame);
}

fn handle_trap(frame: &mut TrapFrame) {
    if frame.from_user() && demos::user::handle(frame) {
        return;
    }
    demos::fault::on_overflow(frame);
    match frame.cause() {
        Trap::Interrupt(Interrupt::Software) => {
            // An IPI: new work was queued here. Clear it; the idle loop or
            // the next preemption point picks the work up.
            // SAFETY: clears only SSIP.
            unsafe { riscv64::write_sip(riscv64::read_sip() & !riscv64::SIE_SSIE) };
            osmium::sched::preempt_if_needed();
        }
        Trap::Breakpoint | Trap::PageFault { .. } if demos::fault::recovered(frame) => {}
        Trap::Interrupt(Interrupt::External) => {
            if let Some(plic) = PLIC.get() {
                IRQS.handle_pending(plic);
            }
        }
        Trap::Interrupt(Interrupt::Timer) => {
            on_timer();
            // Leaving an interrupt is a preemption point.
            osmium::sched::preempt_if_needed();
        }
        cause => unhandled(frame, cause),
    }
}

/// A kernel trap with no handler: a bug in this kernel, so stop it.
#[allow(clippy::panic)] // a kernel trap nothing handles leaves no safe way on
fn unhandled(frame: &TrapFrame, cause: Trap) -> ! {
    panic!("unhandled trap {cause:?} at pc {:#x}", frame.pc())
}

/// Called on every supervisor timer interrupt.
fn on_timer() {
    if cpu::current_id() == 0 {
        TICKS.fetch_add(1, Ordering::Relaxed);
    }
    arm_timer();
    TIMERS.process(now_ns());
    osmium::sched::tick();
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;
    irq::disable();
    // Through the firmware console, bypassing the console registry and the
    // UART's lock: the panic may have come from inside println.
    struct Sbi;
    impl core::fmt::Write for Sbi {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            SbiConsole.write_str(s);
            Ok(())
        }
    }
    let _ = writeln!(Sbi, "\n[panic] {info}");
    sbi::shutdown()
}
