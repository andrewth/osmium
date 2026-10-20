.section .text.osmium_trap, "ax", @progbits
// Lower-EL vectors 8-11 are guest exits while a vCPU runs on this CPU
// (TrapCpu.guest != 0): they branch to osmium_el2_guest_exit (osmium-virt)
// with x0 = TrapCpu.guest, x1 = the vector number and the guest's x0/x1
// pushed on the stack. Otherwise they fall through to the normal stub.
// The symbol is weak so builds without osmium-virt still link; the branch
// is only taken once a vCPU has set TrapCpu.guest.
.weak osmium_el2_guest_exit
.macro osmium_guest_vector kind
    stp x0, x1, [sp, #-16]!
    mrs x0, tpidr_el2
    adrp x1, OSMIUM_TRAP_CPUS
    add x1, x1, :lo12:OSMIUM_TRAP_CPUS
    add x0, x1, x0, lsl #6
    ldr x0, [x0, #0x20]             // TrapCpu.guest
    cbz x0, 1f
    mov x1, #\kind
    b osmium_el2_guest_exit
1:  ldp x0, x1, [sp], #16
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #\kind
    b osmium_trap_common
.endm

.macro osmium_kernel_vector kind
    // Current EL with SP_ELx: check sp before the first store, in case the
    // kernel stack has overflowed. Exactly 32 instructions (the slot size).
    //
    // TPIDRRO_EL0 and SP_EL0 are used as scratch and do NOT survive any
    // current-EL exception. The kernel must not keep values in them; an
    // EL0 user-mode return path must restore them (user TLS and stack)
    // from the task, and the lower-EL vectors must save them before
    // anything can take a current-EL exception.
    msr tpidrro_el0, x0
    msr sp_el0, x1
    mrs x0, tpidr_el2
    adrp x1, OSMIUM_TRAP_CPUS
    add x1, x1, :lo12:OSMIUM_TRAP_CPUS
    add x0, x1, x0, lsl #6          // x0 = &TrapCpu
    ldr x1, [x0, #0x38]             // already on the exception stack?
    cmp sp, x1
    b.lo 1f
    ldr x1, [x0, #0x10]
    cmp sp, x1
    b.ls 2f
1:  ldr x1, [x0, #0x18]             // stack_lo (0 = no check)
    add x1, x1, #304
    cmp sp, x1
    b.hs 2f
    mov x1, sp                      // overflow: move to the exception stack
    ldr x0, [x0, #0x10]
    sub x0, x0, #304
    mov sp, x0
    str x1, [sp, #248]              // frame.sp = interrupted sp
    mrs x0, tpidrro_el0
    mrs x1, sp_el0
    stp x0, x1, [sp, #0]
    mov x0, #\kind
    b osmium_trap_common_sp_saved
2:  mrs x0, tpidrro_el0
    mrs x1, sp_el0
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #\kind
    b osmium_trap_common
.endm

.balign 2048
.globl osmium_trap_vectors
osmium_trap_vectors:
// Each vector starts exactly 0x80 bytes after the previous one; if a
// vector grows too large, `.org` fails (it cannot move backwards).
.org osmium_trap_vectors + 0x0
osmium_vec_0:
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #0
    b osmium_trap_common
.org osmium_trap_vectors + 0x80
osmium_vec_1:
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #1
    b osmium_trap_common
.org osmium_trap_vectors + 0x100
osmium_vec_2:
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #2
    b osmium_trap_common
.org osmium_trap_vectors + 0x180
osmium_vec_3:
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #3
    b osmium_trap_common
.org osmium_trap_vectors + 0x200
osmium_vec_4:
    osmium_kernel_vector 4
.org osmium_trap_vectors + 0x280
osmium_vec_5:
    osmium_kernel_vector 5
.org osmium_trap_vectors + 0x300
osmium_vec_6:
    osmium_kernel_vector 6
.org osmium_trap_vectors + 0x380
osmium_vec_7:
    osmium_kernel_vector 7
.org osmium_trap_vectors + 0x400
osmium_vec_8:
    osmium_guest_vector 8
.org osmium_trap_vectors + 0x480
osmium_vec_9:
    osmium_guest_vector 9
.org osmium_trap_vectors + 0x500
osmium_vec_10:
    osmium_guest_vector 10
.org osmium_trap_vectors + 0x580
osmium_vec_11:
    osmium_guest_vector 11
.org osmium_trap_vectors + 0x600
osmium_vec_12:
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #12
    b osmium_trap_common
.org osmium_trap_vectors + 0x680
osmium_vec_13:
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #13
    b osmium_trap_common
.org osmium_trap_vectors + 0x700
osmium_vec_14:
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #14
    b osmium_trap_common
.org osmium_trap_vectors + 0x780
osmium_vec_15:
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #15
    b osmium_trap_common
osmium_trap_common:
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
    add x1, sp, #304
    str x1, [sp, #248]
    b 3f
osmium_trap_common_sp_saved:
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]
3:
    mrs x1, elr_el2
    str x1, [sp, #256]
    mrs x1, spsr_el2
    str x1, [sp, #264]
    mrs x1, esr_el2
    str x1, [sp, #272]
    mrs x1, far_el2
    str x1, [sp, #280]
    str x0, [sp, #288]
    mov x0, sp
    bl osmium_trap_dispatch
    ldr x1, [sp, #256]
    msr elr_el2, x1
    ldr x1, [sp, #264]
    msr spsr_el2, x1
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]
    ldp x0, x1, [sp, #0]
    add sp, sp, #304
    eret
