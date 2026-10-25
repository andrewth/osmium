//! Runs a tiny guest in VS-mode with the H extension: it prints through an
//! emulated 16550 (MMIO exits), reads the UART's status register, prints
//! through the SBI debug console (hypercalls), spins long enough for host
//! timer interrupts to arrive, executes `wfi` (a halt exit) and shuts down
//! through SBI.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::Cell;
use core::ops::ControlFlow;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use osmium::drivers::ramdisk::RamDisk;
use osmium::hal::block::BlockDevice as _;
use osmium::hal::dma::{DmaAllocator, DmaBuffer};
use osmium::hal::{print, println};
use osmium::mm::{FrameAllocator, MapFlags, PageTable, PhysAddr, VirtAddr};
use osmium::sched::TaskBuilder;
use osmium::sync::IrqSpinLock;
use osmium::virt::devices::{Uart16550, VirtualPlic};
use osmium::virt::riscv::fdt::GuestMachine;
use osmium::virt::riscv::harts::GuestHarts;
use osmium::virt::riscv::{self, HartId, RiscvVcpu, sbi};
use osmium::virt::stage2::{GStageTable, hgatp_sv39x4, map_guest_memory};
use osmium::virt::virtio::{MMIO_SIZE, VirtioBlock, VirtioMmio, VirtioNetDevice};
use osmium::virt::{Bus, GuestMemory, GuestPhysAddr, Vcpu, VmExit, run_vcpu};

use crate::FRAMES;

const GUEST_RAM: GuestPhysAddr = GuestPhysAddr(0x8000_0000);
const GUEST_RAM_ORDER: u32 = 9; // 2 MiB
const GUEST_UART: u64 = 0x1000_0000;

// The guest: position-independent code copied to the start of guest RAM.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .globl guest_image
guest_image:
    .option push
    .option norelax
    li a0, {uart}
    la a1, 3f
1:  lbu a2, 0(a1)
    beqz a2, 2f
    sb a2, 0(a0)            # MMIO write exit
    addi a1, a1, 1
    j 1b
2:  lbu s0, 5(a0)           # MMIO read exit: LSR
    li a7, 0x4442434E       # SBI DBCN write(len, lo, hi)
    li a6, 0
    li a0, 5f - 4f
    la a1, 4f
    li a2, 0
    ecall
    mv s1, a0               # SBI error code
    rdtime t0               # spin 100 ms (10 MHz timebase) so host
    li t1, 1000000          # timer interrupts (10 ms) arrive mid-guest
    add t1, t1, t0
7:  rdtime t0
    bltu t0, t1, 7b
    wfi                     # halt exit
    li a7, 0x53525354       # SBI SRST: shutdown
    li a6, 0
    li a0, 0
    li a1, 0
    ecall
6:  j 6b
3:  .asciz "[guest] hello over MMIO\n"
4:  .ascii "[guest] hello over SBI\n"
5:
    .option pop
    .globl guest_image_end
guest_image_end:
"#,
    uart = const GUEST_UART,
);

unsafe extern "C" {
    static guest_image: u8;
    static guest_image_end: u8;
}

/// Whether the boot hart has the H extension, from its `riscv,isa` string
/// (the single-letter extensions before the first `_`). Under a hypervisor
/// that does not offer nested virtualization it is absent.
pub fn available(fdt: &osmium::boot::fdt::Fdt<'_>) -> bool {
    let isa = fdt
        .find_node("/cpus")
        .and_then(|cpus| cpus.children().find(|c| c.property("riscv,isa").is_some()))
        .and_then(|c| c.property("riscv,isa"))
        .and_then(|p| p.as_str())
        .unwrap_or("");
    let letters = isa.strip_prefix("rv64").unwrap_or("").split('_').next().unwrap_or("");
    letters.contains('h')
}

pub fn demo() {
    riscv::init_cpu();

    // Guest RAM: one 2 MiB block, identity mapped in the host.
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = 4096u64 << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GUEST_RAM, ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the guest image in .rodata.
    let image = unsafe {
        let start = &raw const guest_image;
        core::slice::from_raw_parts(start, (&raw const guest_image_end).offset_from(start) as usize)
    };
    mem.write(GUEST_RAM, image).expect("write failed");

    let mut gstage: GStageTable<_> = PageTable::new(&FRAMES).expect("G-stage root");
    map_guest_memory(&mut gstage, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");
    let hgatp = hgatp_sv39x4(gstage.root(), 1);

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
    mmio.insert(GUEST_UART, 8, Arc::new(uart)).expect("insert failed");
    let pio = Bus::new();

    let mut vcpu = RiscvVcpu::new(GUEST_RAM, HartId(0), 0, hgatp);
    let (mut hypercalls, mut halts, mut interrupts) = (0, 0, 0);
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { .. } => {
            hypercalls += 1;
            let mut console = |b: &[u8]| print!("{}", core::str::from_utf8(b).unwrap_or("?"));
            match sbi::handle(v, &mem, exit, &mut console) {
                Some(sbi::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
                _ => ControlFlow::Continue(()),
            }
        }
        VmExit::Halt => {
            halts += 1;
            ControlFlow::Continue(())
        }
        // The host already took the interrupt when the exit path restored
        // its interrupt-enable bit.
        VmExit::ExternalInterrupt => {
            interrupts += 1;
            ControlFlow::Continue(())
        }
        other => ControlFlow::Break(other),
    });
    let (lsr, dbcn_err) = (vcpu.state.x[8], vcpu.state.x[9]);
    println!(
        "[hyp]   guest exit {exit:?}: {hypercalls} hypercalls, {halts} halt, {interrupts} host interrupts, LSR {lsr:#x}, DBCN error {dbcn_err}"
    );

    drop(gstage);
    drop(mem);
    // SAFETY: the guest has stopped and nothing references its RAM.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
}

const PLIC_BASE: u64 = 0x0c00_0000;
const UART_IRQ: u32 = 10;
const NET_BASE: u64 = 0x1000_1000;
const NET_IRQ: u32 = 1;
const BLK_BASE: u64 = 0x1000_2000;
const BLK_IRQ: u32 = 2;
/// The sector the driver guest writes and the host checks.
const BLK_SECTOR: u64 = 3;
const BLK_TEXT: &[u8] = b"written by osmium's virtio-blk driver in a guest";
const GATEWAY_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
const GATEWAY_IP: [u8; 4] = [10, 0, 2, 2];
/// Guest RAM for the driver demo, clear of the host image the guest also sees.
const GUEST2_RAM: GuestPhysAddr = GuestPhysAddr(0x1_0000_0000);

/// Runs osmium's own UART and PLIC drivers as a guest. The guest's code is
/// the host's: the kernel's text and read-only data are mapped into the
/// guest at their own addresses (read-only), so `guest_main` runs in
/// VS-mode exactly where it was linked, against an emulated PLIC and 16550.
/// It takes a timer interrupt (Sstc), then a UART receive interrupt
/// injected through the PLIC as `hvip.VSEIP`, then brings up a virtio-net
/// card with osmium's driver and resolves the gateway over ARP, answered by
/// a responder in the hypervisor.
pub fn demo_irq() {
    let free_before = FRAMES.lock().free_frames();
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = 4096u64 << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GUEST2_RAM, ram.0 as *mut u8, len) };
    let mem = Arc::new(mem);

    let dtb = GuestMachine {
        harts: 1,
        isa: "rv64imac",
        timebase: 10_000_000,
        memory: &[(GUEST2_RAM.0, len)],
        plic: Some((PLIC_BASE, 32)),
        uarts: &[(GUEST_UART, UART_IRQ)],
        virtio: &[(NET_BASE, NET_IRQ), (BLK_BASE, BLK_IRQ)],
        bootargs: "",
    }
    .to_dtb();
    mem.write(GUEST2_RAM, &dtb).expect("write failed");

    let mut gstage: GStageTable<_> = PageTable::new(&FRAMES).expect("G-stage root");
    map_guest_memory(&mut gstage, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");
    // SAFETY: linker symbols.
    let (start, etext, erodata) =
        unsafe { (crate::sym(&crate::_kernel_start), crate::sym(&crate::_etext), crate::sym(&crate::_erodata)) };
    let rx = MapFlags::READ | MapFlags::EXEC;
    gstage.map_range(VirtAddr::new(start), PhysAddr::new(start), etext - start, rx).expect("map_range failed");
    gstage
        .map_range(VirtAddr::new(etext), PhysAddr::new(etext), erodata - etext, MapFlags::READ)
        .expect("map_range failed");
    let hgatp = hgatp_sv39x4(gstage.root(), 2);

    let mut vcpu = RiscvVcpu::new(GuestPhysAddr(guest_main as *const () as u64), HartId(0), GUEST2_RAM.0, hgatp)
        .with_memory(mem.clone());
    vcpu.state.x[2] = GUEST2_RAM.0 + len; // sp
    let gp: u64;
    // SAFETY: reads gp.
    unsafe { core::arch::asm!("mv {}, gp", out(reg) gp) };
    vcpu.state.x[3] = gp;
    vcpu.state.x[4] = 0; // tp: CPU id 0 for osmium_arch::cpu::current_id

    let eip = vcpu.external_irq();
    let plic = Arc::new(VirtualPlic::new(32, 2, move |ctx, level| {
        if ctx == 1 {
            eip.store(level, Ordering::Release);
        }
    }));
    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    let out = line.clone();
    let p = plic.clone();
    let uart = Arc::new(
        Uart16550::new(move |b| {
            let mut l = out.lock();
            if b != b'\r' {
                l.push(b);
            }
            if b == b'\n' {
                print!("{}", core::str::from_utf8(&l).unwrap_or("?\n"));
                l.clear();
            }
        })
        .with_irq(move |level| p.set_level(UART_IRQ, level)),
    );
    let mmio = Bus::new();
    mmio.insert(PLIC_BASE, VirtualPlic::mmio_size(2), plic.clone()).expect("insert failed");
    mmio.insert(GUEST_UART, 8, uart.clone()).expect("insert failed");
    let p = plic.clone();
    let net = VirtioMmio::new(
        VirtioNetDevice::new([0x52, 0x54, 0, 0x12, 0x34, 0x56], arp_responder),
        mem.clone(),
        move |level| p.set_level(NET_IRQ, level),
    );
    mmio.insert(NET_BASE, MMIO_SIZE, Arc::new(net)).expect("insert failed");
    // A 32 KiB RAM disk behind virtio-blk. The device needs 'static data;
    // the buffer is reclaimed once the device is gone.
    let disk_buf: &'static mut [u8] = alloc::vec![0u8; 64 * 512].leak();
    let disk_raw = disk_buf as *mut [u8];
    let disk = RamDisk::new(disk_buf, 512);
    let p = plic.clone();
    let blk = Arc::new(VirtioMmio::new(VirtioBlock::new(disk), mem.clone(), move |level| p.set_level(BLK_IRQ, level)));
    mmio.insert(BLK_BASE, MMIO_SIZE, blk.clone()).expect("insert failed");
    let pio = Bus::new();

    let mut halts = 0;
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { .. } => {
            match sbi::handle(v, &mem, exit, &mut |b| print!("{}", core::str::from_utf8(b).unwrap_or("?"))) {
                Some(sbi::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
                _ => ControlFlow::Continue(()),
            }
        }
        VmExit::Halt => {
            // The guest waits in wfi: run it again once it has an interrupt.
            halts += 1;
            if halts == 1 {
                // "Typed" once the guest's driver has reset the UART: it is
                // delivered when the guest enables the receive interrupt.
                for &b in b"ping\n" {
                    uart.push_input(b);
                }
            }
            let deadline = riscv::time() + 10_000_000; // 1 s
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
    });
    // The guest's block write must be on the host's RAM disk.
    let mut sector = [0u8; 512];
    blk.with_device(|b, _| b.disk().read_blocks(BLK_SECTOR, &mut sector)).expect("with_device failed");
    if sector.starts_with(BLK_TEXT) {
        println!("[hyp]   the host RAM disk holds the sector the guest wrote ({BLK_SECTOR})");
    } else {
        println!("[hyp]   sector {BLK_SECTOR} on the host's RAM disk is not what the guest wrote");
    }

    drop(blk);
    drop(mmio);
    // SAFETY: the device that borrowed the buffer has just been dropped.
    drop(unsafe { alloc::boxed::Box::from_raw(disk_raw) });
    drop(gstage);
    drop(mem);
    // SAFETY: the guest has stopped, and the devices that could reach its
    // RAM are gone.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
    let used = free_before - FRAMES.lock().free_frames();
    println!("[hyp]   driver guest exit {exit:?} after {halts} halts; {used} frames still in use");
}

/// The driver guest. Runs in VS-mode from the shared host image, so it uses
/// no statics: only its stack, the device tree and MMIO.
extern "C" fn guest_main(_hartid: usize, dtb: usize) -> ! {
    use core::fmt::Write;
    use osmium::boot::fdt::Fdt;
    use osmium::drivers::plic::Plic;
    use osmium::drivers::uart16550::{Mmio, Uart16550 as UartDriver};
    use osmium::drivers::virtio::DeviceType;
    use osmium::drivers::virtio::Transport;
    use osmium::drivers::virtio::blk::VirtioBlk;
    use osmium::drivers::virtio::mmio::MmioTransport;
    use osmium::netdev::virtio_net::VirtioNet;
    use osmium::hal::block::BlockDevice;
    use osmium::hal::irq::InterruptController;
    use osmium::hal::mmio::IoMem;
    use osmium::hal::net::{MacAddress, NetDevice};
    use osmium::hal::serial::{SerialPort, SerialWriter};

    // SAFETY: the hypervisor put a device tree at `dtb`.
    let Ok(fdt) = (unsafe { Fdt::from_ptr(dtb as *const u8) }) else { sbi_shutdown() };
    let node = fdt.find_compatible(&["ns16550a"]).expect("find_compatible returned None");
    let (base, size) = node.reg().next().expect("next returned None");
    let irq = node.interrupts().next().expect("next returned None");
    // SAFETY: the UART's register window from the device tree.
    let mut uart = UartDriver::new(Mmio::new(unsafe { IoMem::new(base as *mut u8, size.unwrap_or(8) as usize) }, 0));
    uart.init(None);
    let pnode = fdt.find_compatible(&["riscv,plic0"]).expect("find_compatible returned None");
    let (pbase, psize) = pnode.reg().next().expect("next returned None");
    // SAFETY: the PLIC's register window from the device tree.
    let plic = Plic::new(
        unsafe { IoMem::new(pbase as *mut u8, psize.expect("PLIC reg has a size") as usize) },
        Plic::supervisor_context,
    );
    let _ = writeln!(SerialWriter(&mut uart), "[vguest] osmium UART and PLIC drivers in VS-mode; UART irq {irq}");

    // Interrupts stay globally off (sstatus.SIE = 0): wfi still wakes for
    // the sources enabled in sie, and the guest polls sip.
    let (seie, stie) = (1usize << 9, 1usize << 5);
    // SAFETY: the guest owns its (virtual) S-mode CSRs.
    unsafe { core::arch::asm!("csrs sie, {}", in(reg) seie | stie) };

    let t0 = rdtime();
    // SAFETY: stimecmp (Sstc) is the guest's own timer.
    unsafe { core::arch::asm!("csrw 0x14d, {}", in(reg) t0 + 50_000) };
    while sip() & stie == 0 {
        // SAFETY: waits for an interrupt.
        unsafe { core::arch::asm!("wfi") };
    }
    // SAFETY: as above.
    unsafe { core::arch::asm!("csrw 0x14d, {}", in(reg) u64::MAX) };
    let _ = writeln!(SerialWriter(&mut uart), "[vguest] timer interrupt after {} us", (rdtime() - t0) / 10);

    plic.set_threshold(0);
    plic.enable(irq);
    uart.enable_rx_interrupt();
    let mut got = [0u8; 16];
    let mut n = 0;
    while n == 0 || got[n - 1] != b'\n' {
        while sip() & seie == 0 {
            // SAFETY: waits for an interrupt.
            unsafe { core::arch::asm!("wfi") };
        }
        let Some(claimed) = plic.claim() else { continue };
        while let Some(b) = uart.read_byte() {
            if n < got.len() {
                got[n] = b;
                n += 1;
            }
        }
        plic.complete(claimed);
        let line = core::str::from_utf8(&got[..n]).unwrap_or("?").trim_end();
        let _ = writeln!(SerialWriter(&mut uart), "[vguest] PLIC claim {claimed}: received {line:?}");
    }

    // virtio-net with osmium's driver; DMA memory from the top half of RAM.
    let vnode = fdt.all_nodes().find(|n| n.is_compatible("virtio,mmio")).expect("find failed");
    let (vbase, vsize) = vnode.reg().next().expect("next returned None");
    let virq = vnode.interrupts().next().expect("next returned None");
    let (ram_base, ram_size) = fdt.memory().next().expect("next returned None");
    let dma = BumpDma { next: Cell::new(ram_base + ram_size / 2), end: ram_base + ram_size - 0x10000 };
    // SAFETY: the virtio-mmio window from the device tree.
    let Ok(t) = MmioTransport::new(unsafe {
        IoMem::new(vbase as *mut u8, vsize.expect("virtio-mmio reg has a size") as usize)
    }) else {
        sbi_shutdown()
    };
    let Ok(mut net) = VirtioNet::new(t, &dma) else { sbi_shutdown() };
    plic.enable(virq);
    let mac = net.mac_address();
    let _ = writeln!(
        SerialWriter(&mut uart),
        "[vguest] virtio-net {mac}, irq {virq}, link {}",
        if net.link_up() { "up" } else { "down" }
    );
    let me = [10, 0, 2, 15];
    let mut req = [0u8; 42];
    req[0..6].copy_from_slice(&[0xff; 6]);
    req[6..12].copy_from_slice(&mac.0);
    req[12..14].copy_from_slice(&[0x08, 0x06]);
    req[14..22].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
    req[22..28].copy_from_slice(&mac.0);
    req[28..32].copy_from_slice(&me);
    req[38..42].copy_from_slice(&GATEWAY_IP);
    let _ = net.transmit(&req);
    let mut frame = [0u8; 1514];
    loop {
        while sip() & seie == 0 {
            // SAFETY: waits for an interrupt.
            unsafe { core::arch::asm!("wfi") };
        }
        let Some(claimed) = plic.claim() else { continue };
        net.transport().ack_interrupt();
        let reply = net.receive(&mut frame);
        plic.complete(claimed);
        if let Ok(n) = reply
            && n >= 42
            && frame[12..14] == [0x08, 0x06]
            && frame[20..22] == [0, 2]
        {
            let gw = MacAddress(frame[22..28].try_into().expect("fixed-width slice"));
            let _ = writeln!(SerialWriter(&mut uart), "[vguest] PLIC claim {claimed}: ARP reply, 10.0.2.2 is at {gw}");
            break;
        }
    }

    // virtio-blk with osmium's driver (polled): write a sector, read it back.
    let blk = fdt.all_nodes().filter(|n| n.is_compatible("virtio,mmio")).find_map(|n| {
        let (b, s) = n.reg().next()?;
        // SAFETY: a virtio-mmio window from the device tree.
        let t = MmioTransport::new(unsafe { IoMem::new(b as *mut u8, s? as usize) }).ok()?;
        (t.device_type() == DeviceType::Block).then_some(t)
    });
    let Some(Ok(mut disk)) = blk.map(|t| VirtioBlk::new(t, &dma)) else { sbi_shutdown() };
    let mut sector = [0u8; 512];
    sector[..BLK_TEXT.len()].copy_from_slice(BLK_TEXT);
    let mut back = [0u8; 512];
    let ok = disk.write_blocks(BLK_SECTOR, &sector).is_ok()
        && disk.read_blocks(BLK_SECTOR, &mut back).is_ok()
        && back == sector;
    let _ = writeln!(
        SerialWriter(&mut uart),
        "[vguest] virtio-blk: {} sectors; sector {BLK_SECTOR} {}",
        disk.num_blocks(),
        if ok { "written and read back" } else { "FAILED" }
    );
    drop(disk);
    sbi_shutdown()
}

/// Hands out guest RAM for the guest's DMA (guest physical = guest virtual,
/// paging off) and never frees it.
struct BumpDma {
    next: Cell<u64>,
    end: u64,
}

impl DmaAllocator for BumpDma {
    fn alloc_coherent(&self, len: usize) -> Option<DmaBuffer> {
        let at = self.next.get().next_multiple_of(4096);
        let end = at.checked_add(len as u64).filter(|&e| e <= self.end)?;
        self.next.set(end);
        // SAFETY: unused guest RAM, handed out once.
        unsafe {
            (at as *mut u8).write_bytes(0, len);
            Some(DmaBuffer::new(NonNull::new(at as *mut u8)?, PhysAddr::new(at), len))
        }
    }

    unsafe fn free_coherent(&self, _buf: DmaBuffer) {}
}

/// The hypervisor's side of the guest's link: answers ARP requests for the
/// gateway address.
fn arp_responder(f: &[u8], reply: &mut dyn FnMut(&[u8])) {
    if f.len() < 42 || f[12..14] != [0x08, 0x06] || f[20..22] != [0, 1] || f[38..42] != GATEWAY_IP {
        return;
    }
    let mut r = [0u8; 42];
    r[0..6].copy_from_slice(&f[6..12]);
    r[6..12].copy_from_slice(&GATEWAY_MAC);
    r[12..22].copy_from_slice(&[0x08, 0x06, 0, 1, 0x08, 0x00, 6, 4, 0, 2]);
    r[22..28].copy_from_slice(&GATEWAY_MAC);
    r[28..32].copy_from_slice(&GATEWAY_IP);
    r[32..42].copy_from_slice(&f[22..32]);
    reply(&r);
}

fn sip() -> usize {
    let v: usize;
    // SAFETY: reads the guest's sip.
    unsafe { core::arch::asm!("csrr {}, sip", out(reg) v) };
    v
}

fn rdtime() -> u64 {
    let v: u64;
    // SAFETY: reads the time counter.
    unsafe { core::arch::asm!("rdtime {}", out(reg) v) };
    v
}

fn sbi_shutdown() -> ! {
    osmium::arch::riscv64::sbi::shutdown()
}

// A two-hart guest: hart 0 starts hart 1 through SBI HSM, hart 1 asks for a
// remote sfence.vma on hart 0, sends it an IPI and stops itself, hart 0 spins on sip.SSIP until the IPI arrives
// (the hypervisor kicks its host CPU to make it exit) and waits for hart 1
// to report STOPPED, then powers off. Position independent.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .globl smp_guest, smp_guest_end
smp_guest:
    .option push
    .option norelax
    bnez a0, 5f
    li a0, 11f - 10f                // hart 0
    la a1, 10f
    jal ra, 20f
    li a7, 0x48534D                 // HSM hart_start(1, smp_guest, 0x1234)
    li a6, 0
    li a0, 1
    la a1, smp_guest
    li a2, 0x1234
    ecall
    mv s2, a0
    li t0, 2
    csrs sie, t0                    // SSIE
1:  csrr t1, sip                    // busy-wait in the guest: the IPI can
                                    // only arrive through an exit
    andi t1, t1, 2
    beqz t1, 1b
    csrc sip, t0
2:  li a7, 0x48534D                 // HSM hart_get_status(1) until STOPPED
    li a6, 2
    li a0, 1
    ecall
    li t2, 1
    bne a1, t2, 2b
    li a0, 13f - 12f
    la a1, 12f
    jal ra, 20f
    li a7, 0x53525354               // SRST: shutdown
    li a6, 0
    li a0, 0
    li a1, 0
    ecall
3:  j 3b
5:  mv s3, a1                       // hart 1: a1 = opaque
    li a0, 12f - 11f
    la a1, 11f
    jal ra, 20f
    li a7, 0x52464E43               // RFENCE remote_sfence_vma(hart 0, all)
    li a6, 1
    li a0, 1
    li a1, 0
    li a2, 0
    li a3, -1
    ecall
    li a7, 0x735049                 // IPI send_ipi(mask 1, base 0)
    li a6, 0
    li a0, 1
    li a1, 0
    ecall
    li a7, 0x48534D                 // HSM hart_stop
    li a6, 1
    ecall
6:  j 6b
20: li a7, 0x4442434E               // DBCN write(a0 bytes at a1)
    li a6, 0
    li a2, 0
    ecall
    ret
10: .ascii "[smp-guest] hart 0: starting hart 1\n"
11: .ascii "[smp-guest] hart 1: running, sending hart 0 an IPI, stopping\n"
12: .ascii "[smp-guest] hart 0: got the IPI; hart 1 is stopped\n"
13:
    .option pop
    .balign 4
smp_guest_end:
"#
);

unsafe extern "C" {
    static smp_guest: u8;
    static smp_guest_end: u8;
}

/// Runs the two-hart guest, each vCPU in a host task pinned to its own
/// host CPU (1 and 2 when there are enough).
pub fn demo_smp(ncpus: usize) {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = 4096u64 << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GUEST_RAM, ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the guest image in .rodata.
    let image = unsafe {
        let start = &raw const smp_guest;
        core::slice::from_raw_parts(start, (&raw const smp_guest_end).offset_from(start) as usize)
    };
    mem.write(GUEST_RAM, image).expect("write failed");
    let mem = Arc::new(mem);
    let mut gstage: GStageTable<_> = PageTable::new(&FRAMES).expect("G-stage root");
    map_guest_memory(&mut gstage, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");
    let hgatp = hgatp_sv39x4(gstage.root(), 3);

    // Kick a host CPU out of its guest with a host IPI; its handler only
    // clears the interrupt, and the exit makes the vCPU look at its lines.
    let kicks = Arc::new(AtomicU64::new(0));
    let k = kicks.clone();
    let harts = GuestHarts::with_kick(2, move |cpu| {
        k.fetch_add(1, Ordering::Relaxed);
        let _ = osmium::arch::riscv64::sbi::send_ipi(1, crate::HARTS[cpu].load(Ordering::Relaxed));
    });
    harts.request_start(0, GUEST_RAM.0, 0).expect("request_start failed");
    let buses = Arc::new((Bus::new(), Bus::new()));
    let done = Arc::new(AtomicBool::new(false));
    let results = Arc::new([AtomicU64::new(u64::MAX), AtomicU64::new(u64::MAX)]);

    let tasks: Vec<_> = (0..2usize)
        .map(|h| {
            let (mem, harts, buses, done, results) =
                (mem.clone(), harts.clone(), buses.clone(), done.clone(), results.clone());
            let cpu = if ncpus > 2 { h + 1 } else { 0 };
            TaskBuilder::new("vcpu").cpu(cpu).spawn(move || {
                riscv::init_cpu();
                while !done.load(Ordering::Acquire) {
                    let Some((entry, opaque)) = harts.take_start(h) else {
                        osmium::sched::yield_now();
                        continue;
                    };
                    let mut vcpu =
                        RiscvVcpu::new(GuestPhysAddr(entry), HartId(h as u64), opaque, hgatp).with_memory(mem.clone());
                    harts.attach(h, &mut vcpu);
                    let mut stopped = false;
                    let exit = run_vcpu(&mut vcpu, &buses.0, &buses.1, |v, exit| match exit {
                        VmExit::Hypercall { .. } => {
                            let mut console = |b: &[u8]| print!("{}", core::str::from_utf8(b).unwrap_or("?"));
                            match sbi::handle_smp(v, &mem, exit, &mut console, Some((&harts, h))) {
                                Some(sbi::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
                                Some(sbi::Outcome::Stop) => {
                                    stopped = true;
                                    ControlFlow::Break(VmExit::Halt)
                                }
                                _ => ControlFlow::Continue(()),
                            }
                        }
                        VmExit::Halt => {
                            let deadline = riscv::time() + 10_000_000; // 1 s
                            while !v.interrupt_pending(riscv::time()) {
                                if riscv::time() > deadline {
                                    return ControlFlow::Break(VmExit::Halt);
                                }
                                core::hint::spin_loop();
                            }
                            ControlFlow::Continue(())
                        }
                        VmExit::ExternalInterrupt if done.load(Ordering::Acquire) => ControlFlow::Break(VmExit::Halt),
                        VmExit::ExternalInterrupt => ControlFlow::Continue(()),
                        other => ControlFlow::Break(other),
                    });
                    // hart 0 records its HSM result (s2), hart 1 its opaque (s3).
                    results[h].store(if h == 0 { vcpu.state.x[18] } else { vcpu.state.x[19] }, Ordering::Release);
                    if !stopped {
                        if exit != VmExit::Shutdown {
                            println!("[hyp]   SMP guest hart {h} stopped unexpectedly: {exit:?}");
                        }
                        done.store(true, Ordering::Release);
                        // Get the other vCPUs out of guest code so they see it.
                        (0..2).for_each(|i| harts.kick(i));
                    }
                }
            })
        })
        .collect();
    for t in &tasks {
        t.join();
    }
    let cpus = if ncpus > 2 { "host CPUs 1 and 2" } else { "host CPU 0" };
    println!(
        "[hyp]   SMP guest: 2 vCPUs on {cpus}; hart_start returned {}, hart 1 got opaque {:#x}; {} kick(s)",
        results[0].load(Ordering::Acquire) as i64,
        results[1].load(Ordering::Acquire),
        kicks.load(Ordering::Relaxed)
    );

    drop(gstage);
    drop(mem);
    // SAFETY: both vCPUs have stopped and nothing references the guest's RAM.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
}

// Two copies of this run interleaved on one host hart, each with its own
// a0: compute a0 + 10 in f3, yield (hypercall 0x0A000000) so the other
// copy runs, then add a0 again and report f3 as an integer (hypercall
// 0x0A000001). If FP registers were not switched, the second half would
// see the other copy's values.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .globl fp_guest, fp_guest_end
fp_guest:
    .option push
    .option arch, +d
    li t0, 0x6000                   // sstatus.FS = Dirty: FP on
    csrs sstatus, t0
    mv s0, a0
    fcvt.d.l f1, s0
    li t1, 10
    fcvt.d.l f2, t1
    fadd.d f3, f1, f2
    li a7, 0x0A000000               // yield to the other vCPU
    ecall
    fadd.d f3, f3, f1
    fcvt.l.d a0, f3
    li a7, 0x0A000001               // report a0
    ecall
1:  j 1b
    .option pop
fp_guest_end:
"#
);

unsafe extern "C" {
    static fp_guest: u8;
    static fp_guest_end: u8;
}

const YIELD: u64 = 0x0a00_0000;
const REPORT: u64 = 0x0a00_0001;

/// Interleaves two vCPUs on this hart and checks each computed with its own
/// floating-point registers.
pub fn demo_fp() {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = 4096u64 << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guests until it is freed below.
    unsafe { mem.add_region(GUEST_RAM, ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the guest image in .rodata.
    let image = unsafe {
        let start = &raw const fp_guest;
        core::slice::from_raw_parts(start, (&raw const fp_guest_end).offset_from(start) as usize)
    };
    mem.write(GUEST_RAM, image).expect("write failed");
    let mut gstage: GStageTable<_> = PageTable::new(&FRAMES).expect("G-stage root");
    map_guest_memory(&mut gstage, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");
    let hgatp = hgatp_sv39x4(gstage.root(), 4);
    let (mmio, pio) = (Bus::new(), Bus::new());

    // Runs `v` to its next yield or report; returns which, and a0.
    let step = |v: &mut RiscvVcpu| {
        let exit = run_vcpu(v, &mmio, &pio, |_, exit| match exit {
            VmExit::Hypercall { nr: YIELD | REPORT, .. } | VmExit::Halt => ControlFlow::Break(exit),
            VmExit::ExternalInterrupt => ControlFlow::Continue(()),
            other => ControlFlow::Break(other),
        });
        let a0 = v.state.x[10];
        v.complete_hypercall(0);
        (exit, a0)
    };
    let mut vcpus = [RiscvVcpu::new(GUEST_RAM, HartId(1), 0, hgatp), RiscvVcpu::new(GUEST_RAM, HartId(2), 0, hgatp)];
    let steps: Vec<_> = [0, 1, 0, 1].into_iter().map(|i| step(&mut vcpus[i])).collect();
    let ok = |(e, _): &(VmExit, u64), nr| matches!(e, VmExit::Hypercall { nr: n, .. } if *n == nr);
    let (ra, rb) = (steps[2].1, steps[3].1);
    let fine = ok(&steps[0], YIELD) && ok(&steps[1], YIELD) && ok(&steps[2], REPORT) && ok(&steps[3], REPORT);
    println!(
        "[hyp]   FP guests interleaved on one hart: vCPU a0=1 got {ra}, a0=2 got {rb} (expected 12 and 14){}",
        if fine && ra == 12 && rb == 14 { "" } else { "; MISMATCH" }
    );

    drop(gstage);
    drop(mem);
    // SAFETY: both vCPUs are done and nothing references the guests' RAM.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
}
