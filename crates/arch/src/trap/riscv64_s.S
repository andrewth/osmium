.section .text.osmium_trap, "ax", @progbits
.balign 4
.globl osmium_trap_entry
osmium_trap_entry:
    // sp <-> sscratch: sp = this CPU's TrapCpu, sscratch = interrupted sp.
    csrrw sp, sscratch, sp
    sd t0, 0x00(sp)
    sd t1, 0x30(sp)
    // HOOK: guest exits (riscv64-hs) branch away here, before the
    // stack decision; t0/t1 are saved in TrapCpu.
    // Pick the stack for the frame; t0 = frame base.
    csrr t1, sstatus
    andi t1, t1, 0x100   // SPP: 0 = from U-mode
    beqz t1, 2f
    csrr t0, sscratch
    // Already on the exception stack (a trap inside the overflow handler)?
    // Then nest there, below the live frame.
    ld t1, 0x38(sp)
    bltu t0, t1, 4f
    ld t1, 0x10(sp)
    bgtu t0, t1, 4f
    addi t0, t0, -288
    j 3f
4:  addi t0, t0, -288
    ld t1, 0x18(sp)
    bgeu t0, t1, 3f
    // Interrupted sp is below the current stack's limit: overflow.
    ld t0, 0x10(sp)
    addi t0, t0, -288
    j 3f
2:  // From user mode: the kernel stack for this CPU's running task.
    ld t0, 0x08(sp)
    addi t0, t0, -288
3:
    sd x1, 8(t0)
    sd x3, 24(t0)
    sd x4, 32(t0)
    sd x7, 56(t0)
    sd x8, 64(t0)
    sd x9, 72(t0)
    sd x10, 80(t0)
    sd x11, 88(t0)
    sd x12, 96(t0)
    sd x13, 104(t0)
    sd x14, 112(t0)
    sd x15, 120(t0)
    sd x16, 128(t0)
    sd x17, 136(t0)
    sd x18, 144(t0)
    sd x19, 152(t0)
    sd x20, 160(t0)
    sd x21, 168(t0)
    sd x22, 176(t0)
    sd x23, 184(t0)
    sd x24, 192(t0)
    sd x25, 200(t0)
    sd x26, 208(t0)
    sd x27, 216(t0)
    sd x28, 224(t0)
    sd x29, 232(t0)
    sd x30, 240(t0)
    sd x31, 248(t0)
    ld t1, 0x00(sp)
    sd t1, 40(t0)
    ld t1, 0x30(sp)
    sd t1, 48(t0)
    csrr t1, sscratch
    sd t1, 16(t0)
    csrw sscratch, sp
    mv sp, t0
    csrr t0, sepc
    sd t0, 256(sp)
    csrr t0, sstatus
    sd t0, 264(sp)
    csrr t0, scause
    sd t0, 272(sp)
    csrr t0, stval
    sd t0, 280(sp)
    mv a0, sp
    call osmium_trap_dispatch
    ld t0, 256(sp)
    csrw sepc, t0
    ld t0, 264(sp)
    csrw sstatus, t0
    ld x1, 8(sp)
    ld x3, 24(sp)
    ld x4, 32(sp)
    ld x5, 40(sp)
    ld x6, 48(sp)
    ld x7, 56(sp)
    ld x8, 64(sp)
    ld x9, 72(sp)
    ld x10, 80(sp)
    ld x11, 88(sp)
    ld x12, 96(sp)
    ld x13, 104(sp)
    ld x14, 112(sp)
    ld x15, 120(sp)
    ld x16, 128(sp)
    ld x17, 136(sp)
    ld x18, 144(sp)
    ld x19, 152(sp)
    ld x20, 160(sp)
    ld x21, 168(sp)
    ld x22, 176(sp)
    ld x23, 184(sp)
    ld x24, 192(sp)
    ld x25, 200(sp)
    ld x26, 208(sp)
    ld x27, 216(sp)
    ld x28, 224(sp)
    ld x29, 232(sp)
    ld x30, 240(sp)
    ld x31, 248(sp)
    ld sp, 16(sp)
    sret
