//! A small hypervisor for QEMU's AArch64 `virt` machine, built from Osmium
//! components. With `-machine virt,virtualization=on` QEMU starts ELF
//! kernels at EL2; this one stays there (non-VHE), turns on the EL2 MMU and
//! runs a guest at EL1 under stage-2 translation.
//!
//! The first guest prints through an emulated 16550 (data-abort MMIO
//! exits), reads the UART's status register, executes `wfi` (a trapped
//! halt) and powers off through PSCI over `hvc`. The second programs an
//! emulated GICv2 like a kernel would and takes its virtual timer interrupt
//! and then a UART receive interrupt, acknowledging each through the
//! virtual CPU interface.
//!
//! On a GICv3 host (`-machine virt,virtualization=on,gic-version=3`) the
//! hypervisor drives the physical GICv3 and also runs GICv3 guests: a
//! distributor and redistributors emulated by `VirtualGicV3`, with the
//! guest using the system-register CPU interface through the host's list
//! registers. One guest takes an SGI it sends itself (`ICC_SGI1R_EL1` traps),
//! its virtual timer and a UART interrupt; another has two vCPUs on two host
//! CPUs and sends an SGI from one to the other.
#![no_std]
#![no_main]

extern crate alloc;

mod kernel;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, AtomicUsize, Ordering};

use osmium::arch::aarch64::{self, psci};
use osmium::arch::trap::{self, TrapFrame};
use osmium::arch::{cpu, irq, mmu};
use osmium::boot::fdt::Fdt;
use osmium::drivers::gicv2::GicV2;
use osmium::drivers::gicv3::GicV3;
use osmium::drivers::pl011::Pl011;
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::irq::InterruptController;
use osmium::hal::mmio::IoMem;
use osmium::hal::{print, println};
use osmium::mm::heap::LockedHeap;
use osmium::mm::paging::formats::Aarch64El2;
use osmium::mm::{BuddyAllocator, FrameAllocator, LockedFrames, MapFlags, MemoryMap, OffsetMapper, PageTable};
use osmium::mm::{PAGE_SIZE, PhysAddr, RegionKind, VirtAddr};
use osmium::sync::{IrqSpinLock, Once};
use osmium::virt::aarch64::{self as vm, Aarch64Vcpu};
use osmium::virt::devices::{GIC_WINDOW, GICD_V3_WINDOW, Uart16550, VirtualGicV2, VirtualGicV3};
use osmium::virt::smp::GuestCpus;
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

    // Secondary CPUs start here (PSCI CPU_ON) at EL2, MMU off, x0 = &SecondaryBoot.
    .globl secondary_start
secondary_start:
    ldr x1, [x0]
    mov sp, x1
    bl secondary_main
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

    .balign 4
    .globl gic_guest, gic_guest_end
gic_guest:
    movz x9, #0x0800, lsl #16       // GICD
    movz x10, #0x0801, lsl #16      // GICC
    movz x0, #0x1000, lsl #16       // 16550
    mov w1, #1
    str w1, [x9]                    // GICD_CTLR
    str w1, [x10]                   // GICC_CTLR
    mov w1, #0xff
    str w1, [x10, #4]               // GICC_PMR
    movz w1, #0x0800, lsl #16       // INTID 27: the virtual timer
    str w1, [x9, #0x100]            // GICD_ISENABLER0
    mov w1, #2                      // INTID 33: the UART
    str w1, [x9, #0x104]            // GICD_ISENABLER1
    mrs x1, cntvct_el0              // timer: about 1 ms from now
    mrs x2, cntfrq_el0
    add x1, x1, x2, lsr #10
    msr cntv_cval_el0, x1
    add x5, x1, x2, lsr #10         // spin (no exits) until 1 ms past the
    mov x1, #1                      // deadline, so the expiry usually exits
    msr cntv_ctl_el0, x1            // through the physical GIC (under TCG it
                                    // can land after the wfi below instead)
8:  mrs x6, cntvct_el0
    cmp x6, x5
    b.lo 8b
1:  wfi                             // IRQs stay masked: wfi still wakes
    ldr w3, [x10, #0xc]             // GICC_IAR
    cmp w3, #1023
    b.eq 1b
    mov x1, #2
    msr cntv_ctl_el0, x1            // mask the timer, then complete
    str w3, [x10, #0x10]            // GICC_EOIR
    mov w21, w3
    mov w1, #1
    strb w1, [x0, #1]               // 16550 IER: receive interrupt
2:  wfi
    ldr w3, [x10, #0xc]
    cmp w3, #1023
    b.eq 2b
    mov w22, w3
    adr x1, 6f
3:  ldrb w2, [x1], #1               // prefix
    cbz w2, 4f
    strb w2, [x0]
    b 3b
4:  ldrb w4, [x0, #5]               // LSR: echo while data is ready
    tbz w4, #0, 5f
    ldrb w4, [x0]
    strb w4, [x0]
    b 4b
5:  str w3, [x10, #0x10]            // GICC_EOIR
    movz x0, #0x0008
    movk x0, #0x8400, lsl #16       // PSCI SYSTEM_OFF
    hvc #0
7:  b 7b
6:  .asciz "[guest] UART interrupt, received: "
    .balign 4
gic_guest_end:
"#
);

// A two-vCPU guest. CPU 0 enables SGI 1 on its (banked) vGIC interface and
// starts CPU 1 with PSCI CPU_ON; CPU 1 prints, sends CPU 0 SGI 1 through
// GICD_SGIR and turns itself off. CPU 0 meanwhile spins in guest code with
// IRQs unmasked, never exiting: the SGI reaches it only because the host
// kicks its host CPU. Its IRQ vector takes the SGI (IAR reports the
// sender); then it waits for AFFINITY_INFO to say CPU 1 is off. Both enter
// here; x0 (the CPU_ON context, 0 for the boot CPU) tells them apart.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 0x800
    .globl smp_guest, smp_guest_end
smp_guest:
    movz x9, #0x0800, lsl #16       // GICD
    movz x10, #0x0801, lsl #16      // GICC (this CPU's)
    movz x11, #0x1000, lsl #16      // 16550
    cbnz x0, 5f
    adr x1, 10f
    bl 20f
    mov w1, #1
    str w1, [x9]                    // GICD_CTLR
    str w1, [x10]                   // GICC_CTLR
    mov w1, #0xff
    str w1, [x10, #4]               // GICC_PMR
    mov w1, #2
    str w1, [x9, #0x100]            // GICD_ISENABLER0: SGI 1
    movz x0, #0x0003
    movk x0, #0xc400, lsl #16       // PSCI CPU_ON(1, smp_guest, 0x1234)
    mov x1, #1
    adr x2, smp_guest
    movz x3, #0x1234
    hvc #0
    mov x20, x0
    adr x1, 30f
    msr vbar_el1, x1
    isb
    mov x23, #0
    msr daifclr, #2                 // IRQs on
1:  cbz x23, 1b                     // no exits: only a kick gets the SGI in
    msr daifset, #2
2:  movz x0, #0x0004
    movk x0, #0xc400, lsl #16       // PSCI AFFINITY_INFO(1) until OFF
    mov x1, #1
    mov x2, #0
    hvc #0
    cmp x0, #1
    b.ne 2b
    adr x1, 12f
    bl 20f
    movz x0, #0x0008
    movk x0, #0x8400, lsl #16       // PSCI SYSTEM_OFF
    hvc #0
3:  b 3b
5:  mov x22, x0                     // CPU 1: x0 = the CPU_ON context
    adr x1, 11f
    bl 20f
    movz w1, #1, lsl #16
    add w1, w1, #1                  // GICD_SGIR: SGI 1 to CPU 0 only
    str w1, [x9, #0xf00]
    movz x0, #0x0002
    movk x0, #0x8400, lsl #16       // PSCI CPU_OFF
    hvc #0
6:  b 6b
20: ldrb w2, [x1], #1               // print the string at x1
    cbz w2, 21f
    strb w2, [x11]
    b 20b
21: ret
10: .asciz "[smp-guest] cpu 0: starting cpu 1 with PSCI CPU_ON\n"
11: .asciz "[smp-guest] cpu 1: up, sending cpu 0 SGI 1, turning off\n"
12: .asciz "[smp-guest] cpu 0: got the SGI in guest code; cpu 1 is off\n"
    .balign 0x800
30: .space 0x280                    // VBAR_EL1: IRQ from EL1h at 0x280
    ldr w3, [x10, #0xc]             // GICC_IAR
    str w3, [x10, #0x10]            // GICC_EOIR
    mov w21, w3
    mov x23, #1
    eret
    .balign 4
smp_guest_end:
"#
);

// The GICv3 counterparts of the two guests above. Nothing here is visible to
// a GICv2 guest: the CPU interface is the system registers (ICC_*), spelled
// by encoding, and each CPU has its own redistributor (128 KiB apart, found
// by Aff0 from MPIDR_EL1). ICC_SRE_EL1 S3_0_C12_C12_5, ICC_PMR_EL1
// S3_0_C4_C6_0, ICC_BPR1_EL1 S3_0_C12_C12_3, ICC_IGRPEN1_EL1 S3_0_C12_C12_7,
// ICC_IAR1_EL1 S3_0_C12_C12_0, ICC_EOIR1_EL1 S3_0_C12_C12_1, ICC_SGI1R_EL1
// S3_0_C12_C11_5.
//
// One vCPU: bring the GIC up, send itself SGI 3 (the write traps to the
// hypervisor), take the virtual timer, then a UART receive interrupt, each
// by reading ICC_IAR1_EL1 and completing with ICC_EOIR1_EL1.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .globl gicv3_guest, gicv3_guest_end
gicv3_guest:
    movz x9, #0x0800, lsl #16       // GICD
    movz x10, #0x080a, lsl #16      // GICR region
    movz x0, #0x1000, lsl #16       // 16550
    mrs x24, mpidr_el1
    and x1, x24, #0xff
    lsl x1, x1, #17
    add x10, x10, x1                // this CPU's redistributor
    mov w1, #0x13
    str w1, [x9]                    // GICD_CTLR: ARE, Group 0 and 1
    str wzr, [x10, #0x14]           // GICR_WAKER: ProcessorSleep = 0
1:  ldr w1, [x10, #0x14]
    tbnz w1, #2, 1b                 // until ChildrenAsleep clears
    add x12, x10, #0x10000          // the SGI frame
    mov w1, #-1
    str w1, [x12, #0x80]            // GICR_IGROUPR0: Group 1
    movz w1, #0x0800, lsl #16
    orr w1, w1, #8                  // SGI 3 and PPI 27 (the virtual timer)
    str w1, [x12, #0x100]           // GICR_ISENABLER0
    mov w1, #2                      // INTID 33: the UART
    str w1, [x9, #0x104]            // GICD_ISENABLER1
    mrs x1, S3_0_C12_C12_5
    orr x1, x1, #1
    msr S3_0_C12_C12_5, x1          // ICC_SRE_EL1.SRE
    isb
    mov x1, #0xff
    msr S3_0_C4_C6_0, x1            // ICC_PMR_EL1
    msr S3_0_C12_C12_3, xzr         // ICC_BPR1_EL1
    mov x1, #1
    msr S3_0_C12_C12_7, x1          // ICC_IGRPEN1_EL1
    isb
    mov x1, #3
    lsl x1, x1, #24
    orr x1, x1, #1                  // SGI 3, TargetList = Aff0 0
    msr S3_0_C12_C11_5, x1          // ICC_SGI1R_EL1: traps to EL2
    mrs x20, S3_0_C12_C12_0         // ICC_IAR1_EL1: the SGI
    msr S3_0_C12_C12_1, x20         // ICC_EOIR1_EL1
    mrs x1, cntvct_el0              // timer: about 1 ms from now
    mrs x2, cntfrq_el0
    add x1, x1, x2, lsr #10
    msr cntv_cval_el0, x1
    add x5, x1, x2, lsr #10         // spin until 1 ms past the deadline
    mov x1, #1
    msr cntv_ctl_el0, x1
8:  mrs x6, cntvct_el0
    cmp x6, x5
    b.lo 8b
2:  wfi
    mrs x3, S3_0_C12_C12_0
    cmp w3, #1023
    b.eq 2b
    mov x1, #2
    msr cntv_ctl_el0, x1            // mask the timer, then complete
    msr S3_0_C12_C12_1, x3
    mov w21, w3
    mov w1, #1
    strb w1, [x0, #1]               // 16550 IER: receive interrupt
3:  wfi
    mrs x3, S3_0_C12_C12_0
    cmp w3, #1023
    b.eq 3b
    mov w22, w3
    adr x1, 6f
4:  ldrb w2, [x1], #1               // prefix
    cbz w2, 5f
    strb w2, [x0]
    b 4b
5:  ldrb w4, [x0, #5]               // LSR: echo while data is ready
    tbz w4, #0, 7f
    ldrb w4, [x0]
    strb w4, [x0]
    b 5b
7:  msr S3_0_C12_C12_1, x3
    movz x0, #0x0008
    movk x0, #0x8400, lsl #16       // PSCI SYSTEM_OFF
    hvc #0
9:  b 9b
6:  .asciz "[guest] GICv3 UART interrupt, received: "
    .balign 4
gicv3_guest_end:
"#
);

// A two-vCPU GICv3 guest, the counterpart of smp_guest: CPU 0 brings the
// distributor and its redistributor up and starts CPU 1; CPU 1 wakes its
// own redistributor, sends CPU 0 SGI 1 with ICC_SGI1R_EL1 and turns itself
// off. CPU 0 spins in guest code with IRQs unmasked until its handler has
// acknowledged the SGI.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 0x800
    .globl smp_guest_v3, smp_guest_v3_end
smp_guest_v3:
    movz x9, #0x0800, lsl #16       // GICD
    movz x10, #0x080a, lsl #16      // GICR region
    movz x11, #0x1000, lsl #16      // 16550
    mrs x24, mpidr_el1
    and x1, x24, #0xff
    lsl x1, x1, #17
    add x10, x10, x1                // this CPU's redistributor
    str wzr, [x10, #0x14]           // GICR_WAKER: wake it
1:  ldr w1, [x10, #0x14]
    tbnz w1, #2, 1b
    mrs x1, S3_0_C12_C12_5
    orr x1, x1, #1
    msr S3_0_C12_C12_5, x1          // ICC_SRE_EL1.SRE
    isb
    mov x1, #0xff
    msr S3_0_C4_C6_0, x1            // ICC_PMR_EL1
    msr S3_0_C12_C12_3, xzr         // ICC_BPR1_EL1
    mov x1, #1
    msr S3_0_C12_C12_7, x1          // ICC_IGRPEN1_EL1
    isb
    cbnz x0, 5f
    adr x1, 10f
    bl 20f
    mov w1, #0x13
    str w1, [x9]                    // GICD_CTLR: ARE, Group 0 and 1
    add x12, x10, #0x10000
    mov w1, #-1
    str w1, [x12, #0x80]            // GICR_IGROUPR0
    mov w1, #2
    str w1, [x12, #0x100]           // GICR_ISENABLER0: SGI 1
    movz x0, #0x0003
    movk x0, #0xc400, lsl #16       // PSCI CPU_ON(1, smp_guest_v3, 0x1234)
    mov x1, #1
    adr x2, smp_guest_v3
    movz x3, #0x1234
    hvc #0
    mov x20, x0
    adr x1, 30f
    msr vbar_el1, x1
    isb
    mov x23, #0
    msr daifclr, #2                 // IRQs on
2:  cbz x23, 2b                     // no exits: only a kick gets the SGI in
    msr daifset, #2
3:  movz x0, #0x0004
    movk x0, #0xc400, lsl #16       // PSCI AFFINITY_INFO(1) until OFF
    mov x1, #1
    mov x2, #0
    hvc #0
    cmp x0, #1
    b.ne 3b
    adr x1, 12f
    bl 20f
    movz x0, #0x0008
    movk x0, #0x8400, lsl #16       // PSCI SYSTEM_OFF
    hvc #0
4:  b 4b
5:  mov x22, x0                     // CPU 1: x0 = the CPU_ON context
    adr x1, 11f
    bl 20f
    mov x1, #1
    lsl x1, x1, #24
    orr x1, x1, #1                  // SGI 1, TargetList = Aff0 0
    msr S3_0_C12_C11_5, x1          // ICC_SGI1R_EL1: traps to EL2
    movz x0, #0x0002
    movk x0, #0x8400, lsl #16       // PSCI CPU_OFF
    hvc #0
6:  b 6b
20: ldrb w2, [x1], #1               // print the string at x1
    cbz w2, 21f
    strb w2, [x11]
    b 20b
21: ret
10: .asciz "[smp-guest] cpu 0: GICv3 up, starting cpu 1 with PSCI CPU_ON\n"
11: .asciz "[smp-guest] cpu 1: up, sending cpu 0 SGI 1 with ICC_SGI1R_EL1, turning off\n"
12: .asciz "[smp-guest] cpu 0: got the SGI in guest code; cpu 1 is off\n"
    .balign 0x800
30: .space 0x280                    // VBAR_EL1: IRQ from EL1h at 0x280
    mrs x3, S3_0_C12_C12_0          // ICC_IAR1_EL1
    msr S3_0_C12_C12_1, x3          // ICC_EOIR1_EL1
    mov w21, w3
    mov x23, #1
    eret
    .balign 4
smp_guest_v3_end:
"#
);

// Two copies run interleaved on one host CPU, each with its own x0: turn
// FP on, compute x0 + 10 in d3, yield (hvc with x0 = 0xc6000000), add x0
// again and report the result (hvc with x0 = 0xc6000001, result in x1).
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .globl fp_guest, fp_guest_end
fp_guest:
    .arch_extension fp
    .arch_extension simd
    mov x19, x0
    movz x1, #0x30, lsl #16         // CPACR_EL1.FPEN = 3: FP/SIMD on
    msr cpacr_el1, x1
    isb
    scvtf d1, x19
    fmov d2, #10.0
    fadd d3, d1, d2
    movz x0, #0xc600, lsl #16       // yield to the other vCPU
    hvc #0
    fadd d3, d3, d1
    fcvtzs x1, d3
    movz x0, #0xc600, lsl #16       // report x1
    add x0, x0, #1
    hvc #0
1:  b 1b
fp_guest_end:
"#
);

unsafe extern "C" {
    fn secondary_start();
    static _kernel_start: u8;
    static _etext: u8;
    static _erodata: u8;
    static _kernel_end: u8;
    static guest_image: u8;
    static guest_image_end: u8;
    static gic_guest: u8;
    static gic_guest_end: u8;
    static smp_guest: u8;
    static smp_guest_end: u8;
    static gicv3_guest: u8;
    static gicv3_guest_end: u8;
    static smp_guest_v3: u8;
    static smp_guest_v3_end: u8;
    static fp_guest: u8;
    static fp_guest_end: u8;
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
static TTBR0: AtomicU64 = AtomicU64::new(0);
static ONLINE: AtomicUsize = AtomicUsize::new(1);
/// The multi-vCPU demo guest being run; leaked, so never freed.
static SMP_VM: AtomicPtr<SmpVm> = AtomicPtr::new(core::ptr::null_mut());

/// Handed to a secondary CPU through `x0`.
#[repr(C)]
struct SecondaryBoot {
    stack_top: u64,
    cpu: usize,
}

#[unsafe(no_mangle)]
extern "C" fn secondary_main(boot: &SecondaryBoot) -> ! {
    // SAFETY: each secondary gets a distinct logical id from the boot CPU.
    unsafe { cpu::set_current_id(boot.cpu) };
    // SAFETY: we are on the stack the boot CPU allocated for us.
    unsafe { trap::install() };
    enable_mmu(PhysAddr::new(TTBR0.load(Ordering::Acquire)));
    // This CPU's GIC interface, for kicks from the other CPU.
    let gic = PHYS_GIC.get().expect("PHYS_GIC initialised");
    gic.init_cpu();
    gic.enable(KICK_SGI);
    // A guest's timer expiring while it runs here exits it, as on CPU 0.
    gic.enable(VTIMER_INTID);
    ONLINE.fetch_add(1, Ordering::Release);
    // Wait for a guest, then run its vCPU with our index while it lives.
    loop {
        // SAFETY: smp_guest_demo publishes leaked guests, which are never freed.
        if let Some(vm) = unsafe { SMP_VM.load(Ordering::Acquire).as_ref() } {
            vcpu_loop(vm, boot.cpu);
        }
        // SAFETY: kernel::boot publishes the VM only while it lives, and
        // waits for every vCPU loop to finish before dropping it.
        if let Some(vm) = unsafe { kernel::KERNEL_VM.load(Ordering::Acquire).as_ref() } {
            kernel::vcpu_loop(vm, boot.cpu);
            while !kernel::KERNEL_VM.load(Ordering::Acquire).is_null() {
                core::hint::spin_loop();
            }
        }
        core::hint::spin_loop();
    }
}

/// The host's interrupt controller, whichever version QEMU provides.
#[allow(clippy::large_enum_variant)] // one static value: boxing buys nothing
enum PhysGic {
    V2(GicV2),
    V3(GicV3),
}

impl PhysGic {
    /// Readies the calling CPU's interface (at EL2 for a GICv3).
    fn init_cpu(&self) {
        match self {
            PhysGic::V2(g) => g.init_cpu(),
            PhysGic::V3(g) => assert!(g.init_cpu(true), "no GICv3 redistributor for this CPU"),
        }
    }

    /// Sends SGI `sgi` to the host CPUs in the `cpus` mask.
    fn send_sgi(&self, cpus: u64, sgi: u32) {
        match self {
            PhysGic::V2(g) => g.send_sgi(cpus as u8, sgi),
            PhysGic::V3(g) => g.send_sgi(cpus, sgi),
        }
    }
}

impl InterruptController for PhysGic {
    fn enable(&self, irq: u32) {
        match self {
            PhysGic::V2(g) => g.enable(irq),
            PhysGic::V3(g) => g.enable(irq),
        }
    }

    fn disable(&self, irq: u32) {
        match self {
            PhysGic::V2(g) => g.disable(irq),
            PhysGic::V3(g) => g.disable(irq),
        }
    }

    fn claim(&self) -> Option<u32> {
        match self {
            PhysGic::V2(g) => g.claim(),
            PhysGic::V3(g) => g.claim(),
        }
    }

    fn complete(&self, irq: u32) {
        match self {
            PhysGic::V2(g) => g.complete(irq),
            PhysGic::V3(g) => g.complete(irq),
        }
    }
}

static PHYS_GIC: Once<PhysGic> = Once::new();
/// The physical SGI one host CPU sends another to kick its vCPU out of
/// guest code.
const KICK_SGI: u32 = 0;

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
    let mut uart = Pl011::new(unsafe { IoMem::new(EARLY_UART as *mut u8, 0x1000) }).expect("new failed");
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
    fdt.fill_memory_map(&mut map, Some(PhysAddr::new(dtb as u64))).expect("fill_memory_map failed");
    // SAFETY: linker-provided symbols.
    let (kstart, etext, erodata, kend) =
        unsafe { (sym(&_kernel_start), sym(&_etext), sym(&_erodata), sym(&_kernel_end)) };
    map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).expect("reserve failed");
    // With enough RAM, keep the window for a guest kernel image out of the
    // allocator (QEMU's loader may have put one there).
    let top = map.regions().iter().map(|r| r.end.0).max().unwrap_or(0);
    let image_window = top >= kernel::IMAGE_BASE + kernel::IMAGE_WINDOW;
    if image_window {
        let (base, end) = (kernel::IMAGE_BASE, kernel::IMAGE_BASE + kernel::IMAGE_WINDOW);
        map.reserve(PhysAddr::new(base), PhysAddr::new(end), RegionKind::Reserved).expect("reserve failed");
    }
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
    let mut pt: PageTable<Aarch64El2, &'static Frames> = PageTable::new(&FRAMES).expect("new failed");
    let rw = MapFlags::RW | MapFlags::GLOBAL;
    let id = |pt: &mut PageTable<Aarch64El2, _>, a: u64, b: u64, f| {
        pt.map_range(VirtAddr::new(a), PhysAddr::new(a), b - a, f).expect("map_range failed")
    };
    id(&mut pt, ram_start, kstart, rw);
    id(&mut pt, kstart, etext, MapFlags::RX | MapFlags::GLOBAL);
    id(&mut pt, etext, erodata, MapFlags::READ | MapFlags::GLOBAL);
    id(&mut pt, erodata, ram_end, rw);
    id(&mut pt, EARLY_UART as u64, EARLY_UART as u64 + 0x1000, rw | MapFlags::DEVICE);
    let gic_node = fdt.find_compatible(&["arm,gic-v3", "arm,cortex-a15-gic", "arm,gic-400"]).expect("no GIC");
    let gic_v3 = gic_node.compatible().any(|c| c == "arm,gic-v3");
    let mut regs = gic_node.reg();
    let (gicd, gicd_len) =
        regs.next().map(|(a, s)| (a, s.expect("GIC register has a size"))).expect("GIC register present");
    // The CPU interface (GICv2) or the redistributor region (GICv3).
    let (gicc, gicc_len) =
        regs.next().map(|(a, s)| (a, s.expect("GIC register has a size"))).expect("GIC register present");
    id(&mut pt, gicd, gicd + gicd_len, rw | MapFlags::DEVICE);
    id(&mut pt, gicc, gicc + gicc_len, rw | MapFlags::DEVICE);
    enable_mmu(pt.root());
    TTBR0.store(pt.root().0, Ordering::Release);
    println!("[mmu]   EL2 MMU on, TTBR0_EL2 {:#x}; RAM {ram_start:#x}..{ram_end:#x}", pt.root().0);
    core::mem::forget(pt);

    // The physical GIC only needs the virtual timer's PPI enabled: its
    // expiry while a guest runs then forces an exit (HCR_EL2.IMO). The host
    // keeps IRQs masked and never takes it.
    // SAFETY: the GIC's windows from the device tree, mapped above.
    let gic = PHYS_GIC.call_once(|| unsafe {
        let (d, c) = (IoMem::new(gicd as *mut u8, gicd_len as usize), IoMem::new(gicc as *mut u8, gicc_len as usize));
        if gic_v3 { PhysGic::V3(GicV3::new(d, c)) } else { PhysGic::V2(GicV2::new(d, c)) }
    });
    match gic {
        PhysGic::V2(g) => g.init_distributor(),
        PhysGic::V3(g) => g.init_distributor(),
    }
    gic.init_cpu();
    gic.enable(VTIMER_INTID);
    gic.enable(KICK_SGI);
    let version = if gic_v3 { "GICv3 (distributor/redistributors)" } else { "GICv2" };
    println!("[gic]   physical {version} at {gicd:#x}/{gicc:#x}; INTID {VTIMER_INTID} forces exits");

    vm::init_cpu();

    // --- Secondary CPUs -------------------------------------------------------
    let boot_mpidr = aarch64::read_mpidr_el1() & 0xff_00ff_ffff;
    let mpidrs = fdt
        .find_node("/cpus")
        .expect("no /cpus")
        .children()
        .filter(|c| c.property("device_type").and_then(|p| p.as_str()) == Some("cpu"))
        .filter_map(|c| c.reg().next().map(|(m, _)| m));
    let mut ncpus = 1;
    for mpidr in mpidrs.filter(|&m| m != boot_mpidr) {
        let stack = alloc::vec![0u8; 64 * 1024].leak();
        let boot = alloc::boxed::Box::leak(alloc::boxed::Box::new(SecondaryBoot {
            stack_top: (stack.as_ptr() as u64 + stack.len() as u64) & !15,
            cpu: ncpus,
        }));
        // SAFETY: `secondary_start` sets up its stack from `boot`.
        let rc = unsafe { psci::cpu_on(conduit, mpidr, secondary_start as *const () as u64, boot as *const _ as u64) };
        assert_eq!(rc, 0, "PSCI CPU_ON {mpidr:#x} failed");
        ncpus += 1;
    }
    while ONLINE.load(Ordering::Acquire) < ncpus {
        core::hint::spin_loop();
    }
    println!("[smp]   {ncpus} CPUs online at EL2");

    // A whole guest kernel if QEMU's loader provided one, else the demos.
    match image_window.then(kernel::image).flatten() {
        Some(elf) => kernel::boot(&elf, ncpus),
        None => {
            guest_demo();
            gic_guest_demo();
            if matches!(gic, PhysGic::V3(_)) {
                gicv3_guest_demo();
            }
            fp_demo();
            if ncpus >= 2 {
                smp_guest_demo(false);
                if matches!(gic, PhysGic::V3(_)) {
                    smp_guest_demo(true);
                }
            }
        }
    }

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
        | 1 << 23 | 1 << 31; // RES1
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
const VTIMER_INTID: u32 = 27;
const GUEST_GICD: u64 = 0x0800_0000;
const GUEST_GICC: u64 = 0x0801_0000;
/// Where GICv3 guests find their redistributors (QEMU virt's address).
const GUEST_GICR: u64 = 0x080a_0000;
const GUEST_UART_INTID: u32 = 33;
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
    mem.write(GUEST_RAM, image).expect("write failed");

    let mut s2: Stage2Table<_> = PageTable::new(&FRAMES).expect("stage-2 root");
    map_guest_memory(&mut s2, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");

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

/// Runs a guest that programs an emulated GICv2: its virtual timer and a
/// 16550 receive interrupt arrive as virtual IRQs (`HCR_EL2.VI`).
fn gic_guest_demo() {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GUEST_RAM, ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the guest image in .rodata.
    let image = unsafe {
        let start = &raw const gic_guest;
        core::slice::from_raw_parts(start, (&raw const gic_guest_end).offset_from(start) as usize)
    };
    mem.write(GUEST_RAM, image).expect("write failed");
    let mut s2: Stage2Table<_> = PageTable::new(&FRAMES).expect("stage-2 root");
    map_guest_memory(&mut s2, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");

    let mut vcpu = Aarch64Vcpu::new(GUEST_RAM, 0, vttbr(s2.root(), 2));
    let irq = vcpu.irq_line();
    let vgic = Arc::new(VirtualGicV2::new(64, move |level| irq.store(level, Ordering::Release)));
    let g = vgic.clone();
    let masked = AtomicBool::new(false);
    vcpu.connect_timer(move |level| {
        g.set_level(VTIMER_INTID, level);
        // While the virtual interrupt is up, keep the physical one from
        // exiting the guest again; restore it once the guest has dealt
        // with the timer.
        if masked.swap(level, Ordering::Relaxed) != level {
            let gic = PHYS_GIC.get().expect("PHYS_GIC initialised");
            if level { gic.disable(VTIMER_INTID) } else { gic.enable(VTIMER_INTID) }
        }
    });

    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    let out = line.clone();
    let g = vgic.clone();
    let uart = Arc::new(
        Uart16550::new(move |b| {
            let mut l = out.lock();
            l.push(b);
            if b == b'\n' {
                print!("{}", core::str::from_utf8(&l).unwrap_or("?\n"));
                l.clear();
            }
        })
        .with_irq(move |level| g.set_level(GUEST_UART_INTID, level)),
    );
    let mmio = Bus::new();
    mmio.insert(GUEST_GICD, GIC_WINDOW, vgic.distributor()).expect("insert failed");
    mmio.insert(GUEST_GICC, GIC_WINDOW, vgic.cpu_interface()).expect("insert failed");
    mmio.insert(GUEST_UART, 8, uart.clone()).expect("insert failed");
    let pio = Bus::new();

    let (mut halts, mut interrupts, mut typed) = (0, 0, false);
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { .. } => match vm::psci::handle(v, exit) {
            Some(vm::psci::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
            _ => ControlFlow::Continue(()),
        },
        VmExit::Halt => {
            halts += 1;
            if v.state.x[21] != 0 && !typed {
                // The timer is handled and the guest waits for the UART:
                // "type" a line.
                typed = true;
                for &b in b"ping\n" {
                    uart.push_input(b);
                }
            }
            let deadline = vm::counter() + aarch64::counter_frequency();
            while !v.interrupt_pending(vm::counter()) {
                if vm::counter() > deadline {
                    return ControlFlow::Break(VmExit::Halt);
                }
                core::hint::spin_loop();
            }
            ControlFlow::Continue(())
        }
        VmExit::ExternalInterrupt => {
            interrupts += 1;
            ControlFlow::Continue(())
        }
        other => ControlFlow::Break(other),
    });
    println!(
        "[hyp]   vGIC guest exit {exit:?}: INTID {} (timer) then INTID {} (UART), {halts} halts, {interrupts} timer exits",
        vcpu.state.x[21], vcpu.state.x[22]
    );

    drop(mmio);
    drop(s2);
    drop(mem);
    // SAFETY: the guest has stopped and nothing references its RAM.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
}

/// Runs a guest that programs an emulated GICv3 through its system
/// registers and redistributor: an SGI it sends itself, its virtual timer
/// and a 16550 receive interrupt, arriving through the list registers.
fn gicv3_guest_demo() {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GUEST_RAM, ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the guest image in .rodata.
    let image = unsafe {
        let start = &raw const gicv3_guest;
        core::slice::from_raw_parts(start, (&raw const gicv3_guest_end).offset_from(start) as usize)
    };
    mem.write(GUEST_RAM, image).expect("write failed");
    let mut s2: Stage2Table<_> = PageTable::new(&FRAMES).expect("stage-2 root");
    map_guest_memory(&mut s2, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");

    let vcpu = Aarch64Vcpu::new(GUEST_RAM, 0, vttbr(s2.root(), 6));
    let irq = vcpu.irq_line();
    let vgic = Arc::new(VirtualGicV3::new(1, 64, move |_, level| irq.store(level, Ordering::Release)));
    let mut vcpu = vcpu.with_vgic_v3(vgic.clone(), 0);
    let g = vgic.clone();
    let masked = AtomicBool::new(false);
    vcpu.connect_timer(move |level| {
        g.set_private_level(0, VTIMER_INTID, level);
        // As with the GICv2 guest: keep the physical timer interrupt from
        // exiting the guest again while the virtual one is up.
        if masked.swap(level, Ordering::Relaxed) != level {
            let gic = PHYS_GIC.get().expect("PHYS_GIC initialised");
            if level { gic.disable(VTIMER_INTID) } else { gic.enable(VTIMER_INTID) }
        }
    });

    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    let out = line.clone();
    let g = vgic.clone();
    let uart = Arc::new(
        Uart16550::new(move |b| {
            let mut l = out.lock();
            l.push(b);
            if b == b'\n' {
                print!("{}", core::str::from_utf8(&l).unwrap_or("?\n"));
                l.clear();
            }
        })
        .with_irq(move |level| g.set_level(GUEST_UART_INTID, level)),
    );
    let mmio = Bus::new();
    mmio.insert(GUEST_GICD, GICD_V3_WINDOW, vgic.distributor()).expect("insert failed");
    mmio.insert(GUEST_GICR, VirtualGicV3::redistributor_window(1), vgic.redistributors()).expect("insert failed");
    mmio.insert(GUEST_UART, 8, uart.clone()).expect("insert failed");
    let pio = Bus::new();

    let (mut halts, mut interrupts, mut typed) = (0, 0, false);
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| match exit {
        VmExit::Hypercall { .. } => match vm::psci::handle(v, exit) {
            Some(vm::psci::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
            _ => ControlFlow::Continue(()),
        },
        VmExit::Halt => {
            halts += 1;
            if v.state.x[21] != 0 && !typed {
                // The timer is handled and the guest waits for the UART:
                // "type" a line.
                typed = true;
                for &b in b"ping\n" {
                    uart.push_input(b);
                }
            }
            let deadline = vm::counter() + aarch64::counter_frequency();
            while !v.interrupt_pending(vm::counter()) {
                if vm::counter() > deadline {
                    return ControlFlow::Break(VmExit::Halt);
                }
                core::hint::spin_loop();
            }
            ControlFlow::Continue(())
        }
        VmExit::ExternalInterrupt => {
            interrupts += 1;
            // The physical timer PPI (or a maintenance interrupt): acknowledge it.
            let gic = PHYS_GIC.get().expect("PHYS_GIC initialised");
            if let Some(irq) = gic.claim() {
                gic.complete(irq);
            }
            ControlFlow::Continue(())
        }
        other => ControlFlow::Break(other),
    });
    println!(
        "[hyp]   vGICv3 guest exit {exit:?}: MPIDR {:#x}, INTID {} (SGI via ICC_SGI1R), INTID {} (timer) then INTID {} (UART), {halts} halts, {interrupts} host interrupts",
        vcpu.state.x[24], vcpu.state.x[20], vcpu.state.x[21], vcpu.state.x[22]
    );
    // Leave the physical timer PPI as the next guest expects it.
    PHYS_GIC.get().expect("PHYS_GIC initialised").enable(VTIMER_INTID);

    drop(mmio);
    drop(s2);
    drop(mem);
    // SAFETY: the guest has stopped and nothing references its RAM.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
}

const YIELD: u64 = 0xc600_0000;
const REPORT: u64 = 0xc600_0001;

/// Interleaves two vCPUs on this CPU and checks each computed with its own
/// FP/SIMD registers.
fn fp_demo() {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
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
    let mut s2: Stage2Table<_> = PageTable::new(&FRAMES).expect("stage-2 root");
    map_guest_memory(&mut s2, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");
    let (mmio, pio) = (Bus::new(), Bus::new());
    let vttbr = vttbr(s2.root(), 4);
    let step = |v: &mut Aarch64Vcpu| {
        let exit = run_vcpu(v, &mmio, &pio, |_, exit| match exit {
            VmExit::Hypercall { nr: YIELD | REPORT, .. } => ControlFlow::Break(exit),
            VmExit::ExternalInterrupt => ControlFlow::Continue(()),
            other => ControlFlow::Break(other),
        });
        let x1 = v.state.x[1];
        (exit, x1)
    };
    let mut vcpus = [Aarch64Vcpu::new(GUEST_RAM, 1, vttbr), Aarch64Vcpu::new(GUEST_RAM, 2, vttbr)];
    let steps: Vec<_> = [0, 1, 0, 1].into_iter().map(|i| step(&mut vcpus[i])).collect();
    let is = |s: &(VmExit, u64), n| matches!(s.0, VmExit::Hypercall { nr, .. } if nr == n);
    let fine = is(&steps[0], YIELD) && is(&steps[1], YIELD) && is(&steps[2], REPORT) && is(&steps[3], REPORT);
    let (a, b) = (steps[2].1, steps[3].1);
    println!(
        "[hyp]   FP guests interleaved on one CPU: vCPU x0=1 got {a}, x0=2 got {b} (expected 12 and 14){}",
        if fine && a == 12 && b == 14 { "" } else { "; MISMATCH" }
    );

    drop(s2);
    drop(mem);
    // SAFETY: both vCPUs are done and nothing references the guests' RAM.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
}

/// A guest shared by the host CPUs that run its vCPUs.
struct SmpVm {
    cpus: Arc<GuestCpus>,
    /// Keeps the guest's RAM alive.
    #[allow(dead_code)]
    mem: GuestMemory,
    vttbr: u64,
    /// Per vCPU: its MMIO bus (its own vGIC views plus the shared UART)
    /// and its IRQ line.
    buses: Vec<Bus>,
    lines: Vec<Arc<AtomicBool>>,
    /// The guest's virtual GICv3, if it has one instead of a GICv2.
    gic3: Option<Arc<VirtualGicV3>>,
    done: AtomicBool,
    /// CPU_ON's result and the IAR value (vCPU 0), the context (vCPU 1).
    results: [AtomicU64; 3],
    /// Physical kick SGIs taken on exits from vCPU 0.
    kicks: AtomicU64,
}

/// Runs vCPU `me` of `vm` whenever it is started, until the guest is done.
fn vcpu_loop(vm: &SmpVm, me: usize) {
    let pio = Bus::new();
    while !vm.done.load(Ordering::Acquire) {
        let Some((entry, context)) = vm.cpus.take_start(me) else {
            core::hint::spin_loop();
            continue;
        };
        let vcpu = Aarch64Vcpu::new(GuestPhysAddr(entry), context, vm.vttbr).with_irq_line(vm.lines[me].clone());
        let mut vcpu = match &vm.gic3 {
            Some(g) => vcpu.with_vgic_v3(g.clone(), me),
            None => vcpu,
        };
        vm.cpus.attach_arm(me, &mut vcpu);
        let mut stopped = false;
        let exit = run_vcpu(&mut vcpu, &vm.buses[me], &pio, |v, exit| match exit {
            VmExit::Hypercall { .. } => match vm::psci::handle_smp(v, exit, Some((&vm.cpus, me))) {
                Some(vm::psci::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
                Some(vm::psci::Outcome::Stop) => {
                    stopped = true;
                    ControlFlow::Break(VmExit::Halt)
                }
                _ => ControlFlow::Continue(()),
            },
            VmExit::Halt => {
                let deadline = vm::counter() + aarch64::counter_frequency();
                while !v.interrupt_pending(vm::counter()) {
                    if vm::counter() > deadline {
                        return ControlFlow::Break(VmExit::Halt);
                    }
                    core::hint::spin_loop();
                }
                ControlFlow::Continue(())
            }
            VmExit::ExternalInterrupt => {
                // A kick (or another physical interrupt): acknowledge it; the
                // next entry delivers whatever the vGIC now has pending.
                let gic = PHYS_GIC.get().expect("PHYS_GIC initialised");
                if let Some(irq) = gic.claim() {
                    if irq == KICK_SGI && me == 0 {
                        vm.kicks.fetch_add(1, Ordering::Relaxed);
                    }
                    gic.complete(irq);
                }
                if vm.done.load(Ordering::Acquire) {
                    return ControlFlow::Break(VmExit::Halt);
                }
                ControlFlow::Continue(())
            }
            other => ControlFlow::Break(other),
        });
        if me == 0 {
            vm.results[0].store(vcpu.state.x[20], Ordering::Release);
            vm.results[1].store(vcpu.state.x[21], Ordering::Release);
        } else {
            vm.results[2].store(vcpu.state.x[22], Ordering::Release);
        }
        if !stopped {
            if exit != VmExit::Shutdown {
                println!("[hyp]   SMP vCPU {me} stopped unexpectedly: {exit:?}");
            }
            vm.done.store(true, Ordering::Release);
            // Get the other vCPUs out of guest code so they see it.
            (0..vm.lines.len()).for_each(|i| vm.cpus.kick(i));
        }
    }
}

/// Runs a two-vCPU guest: vCPU 0 on this CPU, vCPU 1 on host CPU 1, under
/// an emulated GICv2, or GICv3 if `v3`.
fn smp_guest_demo(v3: bool) {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).expect("no memory for the guest");
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this guest for the rest of the run.
    unsafe { mem.add_region(GUEST_RAM, ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the guest image in .rodata.
    let image = unsafe {
        let (start, end) = if v3 {
            (&raw const smp_guest_v3, &raw const smp_guest_v3_end)
        } else {
            (&raw const smp_guest, &raw const smp_guest_end)
        };
        core::slice::from_raw_parts(start, end.offset_from(start) as usize)
    };
    mem.write(GUEST_RAM, image).expect("write failed");
    let mut s2: Stage2Table<_> = PageTable::new(&FRAMES).expect("stage-2 root");
    map_guest_memory(&mut s2, &mem, |p| PhysAddr::new(p as u64)).expect("map_guest_memory failed");
    let vttbr = vttbr(s2.root(), if v3 { 5 } else { 3 });
    core::mem::forget(s2); // in use by both CPUs until power-off

    // A vCPU's interrupt arriving while it runs guest code on another host
    // CPU kicks that CPU with a physical SGI, so the guest exits and the
    // next entry delivers it.
    let cpus =
        GuestCpus::with_kick(2, |host| PHYS_GIC.get().expect("PHYS_GIC initialised").send_sgi(1 << host, KICK_SGI));
    let lines: Vec<Arc<AtomicBool>> = (0..2).map(|_| Arc::new(AtomicBool::new(false))).collect();
    let (l, c) = (lines.clone(), cpus.clone());
    let output = move |cpu: usize, level: bool| {
        l[cpu].store(level, Ordering::Release);
        if level {
            c.kick(cpu);
        }
    };
    let (gic2, gic3) = if v3 {
        (None, Some(Arc::new(VirtualGicV3::new(2, 64, output))))
    } else {
        (Some(Arc::new(VirtualGicV2::with_cpus(2, 64, output))), None)
    };
    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    let uart: Arc<Uart16550> = Arc::new(Uart16550::new(move |b| {
        let mut l = line.lock();
        l.push(b);
        if b == b'\n' {
            print!("{}", core::str::from_utf8(&l).unwrap_or("?\n"));
            l.clear();
        }
    }));
    let buses = (0..2)
        .map(|cpu| {
            let bus = Bus::new();
            if let Some(g) = &gic3 {
                bus.insert(GUEST_GICD, GICD_V3_WINDOW, g.distributor()).expect("insert failed");
                bus.insert(GUEST_GICR, VirtualGicV3::redistributor_window(2), g.redistributors())
                    .expect("insert failed");
            } else if let Some(g) = &gic2 {
                bus.insert(GUEST_GICD, GIC_WINDOW, g.distributor_for(cpu)).expect("insert failed");
                bus.insert(GUEST_GICC, GIC_WINDOW, g.cpu_interface_for(cpu)).expect("insert failed");
            }
            bus.insert(GUEST_UART, 8, uart.clone()).expect("insert failed");
            bus
        })
        .collect();
    cpus.request_start(0, GUEST_RAM.0, 0).expect("request_start failed");
    let vm: &'static SmpVm = alloc::boxed::Box::leak(alloc::boxed::Box::new(SmpVm {
        cpus,
        mem,
        vttbr,
        buses,
        lines,
        gic3,
        done: AtomicBool::new(false),
        results: [AtomicU64::new(u64::MAX), AtomicU64::new(0), AtomicU64::new(0)],
        kicks: AtomicU64::new(0),
    }));
    SMP_VM.store(vm as *const SmpVm as *mut SmpVm, Ordering::Release);
    vcpu_loop(vm, 0);
    let r = |i: usize| vm.results[i].load(Ordering::Acquire);
    let gic = if v3 { "GICv3 " } else { "" };
    println!(
        "[hyp]   SMP {gic}guest: 2 vCPUs on host CPUs 0 and 1; CPU_ON returned {}, cpu 1 got context {:#x}, IAR {:#x}",
        r(0) as i64,
        r(2),
        r(1)
    );
    println!("[hyp]   vCPU 0 kicked out of guest code by a host SGI {} time(s)", vm.kicks.load(Ordering::Relaxed));
}

fn on_trap(frame: &mut TrapFrame) {
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
