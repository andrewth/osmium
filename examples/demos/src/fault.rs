//! Fault demos shared by the example kernels: recovering from a breakpoint
//! and a page fault, and a task that overflows its guarded stack.
//!
//! A kernel's trap handler calls [`recovered`] for breakpoints and page
//! faults (and, on RISC-V and AArch64, [`on_overflow`] first).

use core::sync::atomic::{AtomicBool, Ordering};

use osmium::arch::trap::{Trap, TrapFrame};
use osmium::arch::{MAX_CPUS, cpu, irq};
use osmium::hal::println;
use osmium::sched::TaskBuilder;
use osmium::sync::IrqSpinLock;

/// The last synchronous trap that [`recovered`] recovered from, per CPU.
static RECOVERED: [IrqSpinLock<Option<Trap>>; MAX_CPUS] = [const { IrqSpinLock::new(None) }; MAX_CPUS];
/// Whether this CPU expects a trap and may recover from it. Per CPU, so a real
/// fault on another CPU is never taken for the demo's.
static RECOVER: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// Runs `f`, which must take one breakpoint or page fault, with recovery armed
/// on this CPU only (interrupts off, so the task cannot migrate meanwhile).
/// Returns the trap that was recovered from, or `None` if `f` took none.
pub fn recover_trap(f: impl FnOnce()) -> Option<Trap> {
    irq::without(|| {
        let cpu = cpu::current_id();
        let (armed, last) = (RECOVER.get(cpu)?, RECOVERED.get(cpu)?);
        armed.store(true, Ordering::SeqCst);
        f();
        armed.store(false, Ordering::SeqCst);
        last.lock().take()
    })
}

/// Called by the trap handler for a breakpoint or page fault taken in the
/// kernel: if this CPU armed [`recover_trap`], records the trap, steps over
/// the instruction and returns true. Returns false for any other trap.
pub fn recovered(frame: &mut TrapFrame) -> bool {
    let cause = frame.cause();
    let cpu = cpu::current_id();
    let (Some(armed), Some(last)) = (RECOVER.get(cpu), RECOVERED.get(cpu)) else { return false };
    if !matches!(cause, Trap::Breakpoint | Trap::PageFault { .. }) || !armed.load(Ordering::SeqCst) {
        return false;
    }
    *last.lock() = Some(cause);
    frame.set_pc(frame.pc() + insn_len(frame, cause));
    true
}

/// The length of the instruction that trapped: what [`fault_demo`] runs.
#[cfg(target_arch = "riscv64")]
fn insn_len(frame: &TrapFrame, _cause: Trap) -> usize {
    // SAFETY: the faulting instruction is mapped executable kernel code.
    let insn = unsafe { (frame.pc() as *const u16).read() };
    // 2 bytes if compressed, else 4.
    if insn & 3 == 3 { 4 } else { 2 }
}

/// The length of the instruction that trapped: A64 instructions are 4 bytes.
#[cfg(target_arch = "aarch64")]
fn insn_len(_frame: &TrapFrame, _cause: Trap) -> usize {
    4
}

/// The length of the instruction that trapped: `int3` is 1 byte; the
/// faulting `mov rax, [0x1000]` of [`fault_demo`] is 8.
#[cfg(target_arch = "x86_64")]
fn insn_len(_frame: &TrapFrame, cause: Trap) -> usize {
    if cause == Trap::Breakpoint { 1 } else { 8 }
}

/// Takes a breakpoint.
fn breakpoint() {
    // SAFETY: the trap handler steps over the breakpoint (`recover_trap`).
    unsafe {
        #[cfg(target_arch = "riscv64")]
        core::arch::asm!("ebreak");
        #[cfg(target_arch = "aarch64")]
        core::arch::asm!("brk #0");
        #[cfg(target_arch = "x86_64")]
        core::arch::asm!("int3");
    }
}

/// Reads unmapped address 0x1000, a page fault in every example kernel.
fn read_unmapped() {
    #[cfg(target_arch = "x86_64")]
    {
        let v: u64;
        // SAFETY: the read faults and the handler skips the 8-byte
        // instruction; the value is never used.
        unsafe { core::arch::asm!("mov {}, qword ptr [0x1000]", out(reg) v) };
        let _ = v;
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // SAFETY: the read faults and the handler skips it; the value is never used.
        let _ = unsafe { core::ptr::read_volatile(0x1000 as *const u64) };
    }
}

/// Recovers from a breakpoint and a page fault in kernel code.
pub fn fault_demo() {
    for (what, f) in [("a breakpoint", breakpoint as fn()), ("a read of unmapped memory", read_unmapped)] {
        match recover_trap(f) {
            Some(t) => println!("[trap]  recovered from {t:?}"),
            None => println!("[trap]  {what} did not trap"),
        }
    }
}

/// A task that recurses until it runs off the bottom of its stack, into the
/// guard page below it; the trap handler ends only that task.
pub fn overflow_demo() {
    #[inline(never)]
    fn recurse(depth: u64) -> u64 {
        let frame = core::hint::black_box([depth; 32]);
        if core::hint::black_box(true) { recurse(depth + 1) + frame[7] } else { 0 }
    }
    let t = TaskBuilder::new("deep").stack_size(16 * 1024).spawn(|| {
        recurse(0);
    });
    t.join();
    println!("[guard] the other tasks keep running: {} free frames", crate::kernel::free_frames());
}

/// Gives this CPU an emergency stack for traps from an overflowed stack.
#[cfg(not(target_arch = "x86_64"))]
pub fn set_exception_stack() {
    use osmium::arch::trap::TrapCpu;
    let stack = alloc::vec![0u8; 16 * 1024].leak();
    let lo = stack.as_ptr() as usize;
    TrapCpu::current().set_exception_stack(lo..lo + stack.len());
}

/// Called first by the trap handler: if `frame` was saved on the exception
/// stack because the interrupted task overflowed its own, ends that task
/// (after checking that a nested trap stays on the exception stack).
/// Returns only for a frame that did not overflow.
#[cfg(not(target_arch = "x86_64"))]
pub fn on_overflow(frame: &TrapFrame) {
    use osmium::arch::trap::TrapCpu;
    if !TrapCpu::current().overflowed(frame) {
        return;
    }
    // The task's own stack is exhausted, so it cannot continue.
    let task = osmium::sched::current();
    println!(
        "[guard] task {:?} overflowed its stack ({:?} at sp {:#x}); killed",
        task.name(),
        frame.cause(),
        frame.sp()
    );
    // A trap taken while on the exception stack must nest there, not be
    // mistaken for another overflow.
    match recover_trap(breakpoint) {
        Some(t) => println!("[guard] nested {t:?} on the exception stack handled"),
        None => println!("[guard] a breakpoint on the exception stack did not trap"),
    }
    drop(task);
    osmium::sched::exit();
}
