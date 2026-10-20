//! Runs a tiny guest in VS-mode with the H extension: it prints through an
//! emulated 16550 (MMIO exits), reads the UART's status register, prints
//! through the SBI debug console (hypercalls), spins long enough for host
//! timer interrupts to arrive, executes `wfi` (a halt exit) and shuts down
//! through SBI.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;
use core::sync::atomic::Ordering;

use osmium::hal::{print, println};
use osmium::mm::{FrameAllocator, MapFlags, PageTable, PhysAddr, VirtAddr};
use osmium::sync::IrqSpinLock;
use osmium::virt::devices::{Uart16550, VirtualPlic};
use osmium::virt::riscv::fdt::GuestMachine;
use osmium::virt::riscv::{self, RiscvVcpu, sbi};
use osmium::virt::stage2::{GStageTable, hgatp_sv39x4, map_guest_memory};
use osmium::virt::{Bus, GuestMemory, GuestPhysAddr, VmExit, run_vcpu};

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
    rdtime t0               # spin 30 ms (10 MHz timebase) so host
    li t1, 300000           # timer interrupts arrive mid-guest
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
    mem.write(GUEST_RAM, image).unwrap();

    let mut gstage: GStageTable<_> = PageTable::new(&FRAMES).expect("G-stage root");
    map_guest_memory(&mut gstage, &mem, |p| PhysAddr::new(p as u64)).unwrap();
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
    mmio.insert(GUEST_UART, 8, Arc::new(uart)).unwrap();
    let pio = Bus::new();

    let mut vcpu = RiscvVcpu::new(GUEST_RAM, 0, 0, hgatp);
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
/// Guest RAM for the driver demo, clear of the host image the guest also sees.
const GUEST2_RAM: GuestPhysAddr = GuestPhysAddr(0x1_0000_0000);

/// Runs osmium's own UART and PLIC drivers as a guest. The guest's code is
/// the host's: the kernel's text and read-only data are mapped into the
/// guest at their own addresses (read-only), so `guest_main` runs in
/// VS-mode exactly where it was linked, against an emulated PLIC and 16550.
/// It takes a timer interrupt (Sstc), then a UART receive interrupt
/// injected through the PLIC as `hvip.VSEIP`.
pub fn demo_irq() {
    let free_before = FRAMES.lock().free_frames();
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = 4096u64 << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GUEST2_RAM, ram.0 as *mut u8, len) };

    let dtb = GuestMachine {
        harts: 1,
        isa: "rv64imac",
        timebase: 10_000_000,
        memory: &[(GUEST2_RAM.0, len)],
        plic: Some((PLIC_BASE, 32)),
        uarts: &[(GUEST_UART, UART_IRQ)],
        virtio: &[],
        bootargs: "",
    }
    .to_dtb();
    mem.write(GUEST2_RAM, &dtb).unwrap();

    let mut gstage: GStageTable<_> = PageTable::new(&FRAMES).expect("G-stage root");
    map_guest_memory(&mut gstage, &mem, |p| PhysAddr::new(p as u64)).unwrap();
    // SAFETY: linker symbols.
    let (start, etext, erodata) = unsafe { (crate::sym(&crate::_kernel_start), crate::sym(&crate::_etext), crate::sym(&crate::_erodata)) };
    let rx = MapFlags::READ | MapFlags::EXEC;
    gstage.map_range(VirtAddr::new(start), PhysAddr::new(start), etext - start, rx).unwrap();
    gstage.map_range(VirtAddr::new(etext), PhysAddr::new(etext), erodata - etext, MapFlags::READ).unwrap();
    let hgatp = hgatp_sv39x4(gstage.root(), 2);

    let mut vcpu = RiscvVcpu::new(GuestPhysAddr(guest_main as *const () as u64), 0, GUEST2_RAM.0, hgatp);
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
    mmio.insert(PLIC_BASE, VirtualPlic::mmio_size(2), plic.clone()).unwrap();
    mmio.insert(GUEST_UART, 8, uart.clone()).unwrap();
    let pio = Bus::new();

    let mut halts = 0;
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { .. } => match sbi::handle(v, &mem, exit, &mut |b| print!("{}", core::str::from_utf8(b).unwrap_or("?"))) {
            Some(sbi::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
            _ => ControlFlow::Continue(()),
        },
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
    drop(gstage);
    drop(mem);
    // SAFETY: the guest has stopped and nothing references its RAM.
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
    use osmium::hal::irq::InterruptController;
    use osmium::hal::mmio::IoMem;
    use osmium::hal::serial::{SerialPort, SerialWriter};

    // SAFETY: the hypervisor put a device tree at `dtb`.
    let Ok(fdt) = (unsafe { Fdt::from_ptr(dtb as *const u8) }) else { sbi_shutdown() };
    let node = fdt.find_compatible(&["ns16550a"]).unwrap();
    let (base, size) = node.reg().next().unwrap();
    let irq = node.interrupts().next().unwrap();
    // SAFETY: the UART's register window from the device tree.
    let mut uart = UartDriver::new(Mmio::new(unsafe { IoMem::new(base as *mut u8, size.unwrap_or(8) as usize) }, 0));
    uart.init(None);
    let pnode = fdt.find_compatible(&["riscv,plic0"]).unwrap();
    let (pbase, psize) = pnode.reg().next().unwrap();
    // SAFETY: the PLIC's register window from the device tree.
    let plic = Plic::new(unsafe { IoMem::new(pbase as *mut u8, psize.unwrap() as usize) }, Plic::supervisor_context);
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
    sbi_shutdown()
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
