//! Supervisor trap entry.
//!
//! The kernel never runs user code, so traps always arrive on a kernel stack
//! and the frame is pushed there. Only caller-saved registers are saved: the
//! Rust handler preserves the rest. If the handler switches tasks
//! (preemption), the frame simply stays on the preempted task's stack until
//! that task is resumed and returns from the handler.

use osmium::arch::riscv64;

core::arch::global_asm!(
    r#"
    .section .text
    .align 4
    .globl trap_entry
trap_entry:
    addi sp, sp, -18*8
    sd ra, 0*8(sp)
    sd t0, 1*8(sp)
    sd t1, 2*8(sp)
    sd t2, 3*8(sp)
    sd t3, 4*8(sp)
    sd t4, 5*8(sp)
    sd t5, 6*8(sp)
    sd t6, 7*8(sp)
    sd a0, 8*8(sp)
    sd a1, 9*8(sp)
    sd a2, 10*8(sp)
    sd a3, 11*8(sp)
    sd a4, 12*8(sp)
    sd a5, 13*8(sp)
    sd a6, 14*8(sp)
    sd a7, 15*8(sp)
    csrr t0, sepc
    sd t0, 16*8(sp)
    csrr t0, sstatus
    sd t0, 17*8(sp)
    mv a0, sp
    call trap_handler
    ld t0, 16*8(sp)
    csrw sepc, t0
    ld t0, 17*8(sp)
    csrw sstatus, t0
    ld ra, 0*8(sp)
    ld t0, 1*8(sp)
    ld t1, 2*8(sp)
    ld t2, 3*8(sp)
    ld t3, 4*8(sp)
    ld t4, 5*8(sp)
    ld t5, 6*8(sp)
    ld t6, 7*8(sp)
    ld a0, 8*8(sp)
    ld a1, 9*8(sp)
    ld a2, 10*8(sp)
    ld a3, 11*8(sp)
    ld a4, 12*8(sp)
    ld a5, 13*8(sp)
    ld a6, 14*8(sp)
    ld a7, 15*8(sp)
    addi sp, sp, 18*8
    sret
"#
);

unsafe extern "C" {
    fn trap_entry();
}

/// Registers saved by `trap_entry`.
#[repr(C)]
pub struct TrapFrame {
    regs: [u64; 16],
    sepc: u64,
    sstatus: u64,
}

const INTERRUPT: usize = 1 << 63;
const SUPERVISOR_TIMER: usize = INTERRUPT | 5;

/// Installs the trap vector (direct mode).
pub fn init() {
    // SAFETY: `trap_entry` is 4-byte aligned and handles every S-mode trap.
    unsafe { riscv64::write_stvec(trap_entry as *const () as usize) };
}

#[unsafe(no_mangle)]
extern "C" fn trap_handler(frame: &mut TrapFrame) {
    match riscv64::read_scause() {
        SUPERVISOR_TIMER => {
            crate::on_timer();
            // Leaving an interrupt is a preemption point.
            osmium::sched::preempt_if_needed();
        }
        cause => panic!(
            "unhandled trap: scause {cause:#x}, sepc {:#x}, stval {:#x}, sstatus {:#x}",
            frame.sepc,
            riscv64::read_stval(),
            frame.sstatus
        ),
    }
}
