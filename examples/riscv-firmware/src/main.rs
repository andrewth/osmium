//! Machine-mode RISC-V firmware for QEMU `virt`, built from Osmium parts,
//! with no heap, no scheduler and no OpenSBI (`-bios none`).
//!
//! Two async tasks run on the heap-free executor: one awaits machine timer
//! interrupts from the CLINT, the other reads UART input delivered by the
//! PLIC. When both finish, the firmware powers the machine off; a real
//! bootloader would hand off to an OS instead.
#![no_std]
#![no_main]

use core::future::poll_fn;
use core::pin::pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::Poll;

use osmium::arch::trap::{self, Interrupt, Trap, TrapFrame};
use osmium::arch::{cpu, irq};
use osmium::drivers::clint::Clint;
use osmium::drivers::plic::Plic;
use osmium::drivers::uart16550::{Mmio, Uart16550};
use osmium::exec::{AtomicWaker, Executor, Signal};
use osmium::hal::console::{SerialConsole, set_console};
use osmium::hal::irq::InterruptController;
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::serial::SerialPort;
use osmium::sync::{IrqSpinLock, Once, Producer, SpscRing};

core::arch::global_asm!(
    r#"
    .section .text.entry
    .globl _start
_start:
    // Only hart 0 runs the firmware; the others park.
    csrr t0, mhartid
    bnez t0, 3f
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
2:  call fw_main
3:  wfi
    j 3b

    .section .bss.stack
    .align 12
    .space 16384
boot_stack_top:
"#
);

// QEMU `virt` addresses (a real board would read them from its device tree).
const UART_BASE: usize = 0x1000_0000;
const UART_IRQ: u32 = 10;
const CLINT_BASE: usize = 0x0200_0000;
const PLIC_BASE: usize = 0x0c00_0000;
const TEST_DEVICE: usize = 0x10_0000;
/// 10 ms at QEMU's 10 MHz `mtime`.
const TICK: u64 = 100_000;
const MIE_MTIE: usize = 1 << 7;
const MIE_MEIE: usize = 1 << 11;

static UART: Once<SerialConsole<Uart16550<Mmio>>> = Once::new();
static CLINT: Once<Clint> = Once::new();
static PLIC: Once<Plic> = Once::new();

static EXEC: Executor<4> = Executor::new();
static TICKS: Signal<u64> = Signal::new();
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static RX: SpscRing<u8, 64> = SpscRing::new();
static RX_PRODUCER: IrqSpinLock<Option<Producer<'static, u8, 64>>> = IrqSpinLock::new(None);
static RX_WAKER: AtomicWaker = AtomicWaker::new();
static TICKER_DONE: AtomicBool = AtomicBool::new(false);

#[unsafe(no_mangle)]
extern "C" fn fw_main(hart: usize) -> ! {
    // SAFETY: only hart 0 gets here.
    unsafe { cpu::set_current_id(0) };
    trap::set_handler(on_trap);
    // SAFETY: we run on the boot stack; installs mtvec and mscratch.
    unsafe { trap::install() };

    // SAFETY: QEMU virt's 16550 lives here; nothing else drives it.
    let mut uart = Uart16550::new(Mmio::new(unsafe { IoMem::new(UART_BASE as *mut u8, 0x100) }, 0));
    uart.init(None);
    uart.enable_rx_interrupt();
    set_console(UART.call_once(|| SerialConsole::new(uart)));
    println!("\nosmium riscv-firmware: M-mode, no heap, no OpenSBI (hart {hart})");

    // SAFETY: QEMU virt's CLINT and PLIC; this firmware owns them.
    let clint = CLINT.call_once(|| Clint::new(unsafe { IoMem::new(CLINT_BASE as *mut u8, 0x1_0000) }));
    let plic = PLIC.call_once(|| Plic::new(unsafe { IoMem::new(PLIC_BASE as *mut u8, 0x40_0000) }, Plic::machine_context));
    plic.set_priority(UART_IRQ, 1);
    plic.enable(UART_IRQ);
    plic.set_threshold(0);
    let (producer, consumer) = RX.split().unwrap();
    *RX_PRODUCER.lock() = Some(producer);

    clint.set_deadline(0, clint.mtime() + TICK);
    // SAFETY: enables the machine timer and external interrupts; the trap
    // vector is installed.
    unsafe { core::arch::asm!("csrs mie, {}", in(reg) MIE_MTIE | MIE_MEIE) };
    irq::enable();
    println!("[fw]    CLINT timer every 10 ms, UART IRQ {UART_IRQ} through the PLIC; async tasks on a heap-free executor");

    EXEC.run_to_completion(&mut [pin!(ticker()), pin!(console(consumer))]);

    println!("[fw]    all tasks finished after {} timer interrupts; powering off", TICK_COUNT.load(Ordering::Relaxed));
    // SAFETY: QEMU's SiFive test device: 0x5555 means "pass, power off".
    unsafe { (TEST_DEVICE as *mut u32).write_volatile(0x5555) };
    cpu::halt_forever()
}

/// Awaits five timer interrupts.
async fn ticker() {
    let mut last = 0;
    for _ in 0..5 {
        last = TICKS.wait().await;
    }
    println!("[fw]    ticker task awaited 5 timer interrupts (last was #{last})");
    TICKER_DONE.store(true, Ordering::Release);
    // Let the console task notice the deadline.
    RX_WAKER.wake();
}

/// Collects one line of UART input, or gives up when the ticker finishes.
async fn console(mut rx: osmium::sync::Consumer<'static, u8, 64>) {
    let mut line = [0u8; 64];
    let mut len = 0;
    loop {
        let next = poll_fn(|cx| {
            RX_WAKER.register(cx.waker());
            match rx.pop() {
                Some(b) => Poll::Ready(Some(b)),
                None if TICKER_DONE.load(Ordering::Acquire) => Poll::Ready(None),
                None => Poll::Pending,
            }
        })
        .await;
        match next {
            Some(b'\n' | b'\r') if len > 0 => break,
            Some(b) if (b.is_ascii_graphic() || b == b' ') && len < line.len() => {
                line[len] = b;
                len += 1;
            }
            Some(_) => {}
            None => break,
        }
    }
    match core::str::from_utf8(&line[..len]) {
        Ok("") => println!("[fw]    console task: no input before the ticker finished"),
        Ok(s) => println!("[fw]    console task: interrupt-driven input {s:?}"),
        Err(_) => println!("[fw]    console task: input was not UTF-8"),
    }
}

fn on_trap(frame: &mut TrapFrame) {
    match frame.cause() {
        Trap::Interrupt(Interrupt::Timer) => {
            let clint = CLINT.get().unwrap();
            clint.set_deadline(0, clint.mtime() + TICK);
            TICKS.signal(TICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1);
        }
        Trap::Interrupt(Interrupt::External) => {
            let plic = PLIC.get().unwrap();
            while let Some(irq) = plic.claim() {
                if irq == UART_IRQ {
                    let mut port = UART.get().unwrap().port();
                    let mut producer = RX_PRODUCER.lock();
                    while let Some(b) = port.read_byte() {
                        if let Some(p) = producer.as_mut() {
                            let _ = p.push(b);
                        }
                    }
                    RX_WAKER.wake();
                }
                plic.complete(irq);
            }
        }
        cause => panic!("unhandled trap {cause:?} at pc {:#x}", frame.pc()),
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    irq::disable();
    println!("\n[panic] {info}");
    // SAFETY: SiFive test device: 0x3333 with a code means "fail".
    unsafe { (TEST_DEVICE as *mut u32).write_volatile(0x0001_3333) };
    cpu::halt_forever()
}
