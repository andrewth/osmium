//! Runs a tiny guest in VS-mode with the H extension: it prints through an
//! emulated 16550 (MMIO exits), reads the UART's status register, prints
//! through the SBI debug console (hypercalls), spins long enough for host
//! timer interrupts to arrive, executes `wfi` (a halt exit) and shuts down
//! through SBI.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;

use osmium::hal::{print, println};
use osmium::mm::{FrameAllocator, PageTable, PhysAddr};
use osmium::sync::IrqSpinLock;
use osmium::virt::devices::Uart16550;
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
