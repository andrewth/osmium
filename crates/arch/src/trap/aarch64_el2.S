.section .text.osmium_trap, "ax", @progbits
.balign 2048
.globl osmium_trap_vectors
osmium_trap_vectors:
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #0
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #1
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #2
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #3
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #4
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #5
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #6
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #7
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #8
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #9
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #10
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #11
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #12
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #13
    b osmium_trap_common
.balign 0x80
    sub sp, sp, #304
    stp x0, x1, [sp, #0]
    mov x0, #14
    b osmium_trap_common
.balign 0x80
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
