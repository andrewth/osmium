//! Calling the PC BIOS from long mode.
//!
//! A thunk copied to [`THUNK`] drops the boot CPU from long mode to real
//! mode, runs one software interrupt through the BIOS's interrupt vector
//! table, and comes back: 64-bit code → 32-bit compatibility mode → paging
//! and long mode off → 16-bit protected mode → real mode, then the same
//! steps in reverse. It saves and restores the GDT, IDT, CR0, CR3, EFER's
//! LME bit, the data segment selectors and the FS and GS bases (which real
//! mode segment loads overwrite).
//!
//! This is for early boot on BIOS machines (or QEMU booting a PVH kernel,
//! where SeaBIOS has run): VESA mode setting through `int 10h` is the usual
//! use. The BIOS assumes the machine is as it left it, so call it before the
//! kernel takes over interrupt controllers or the low megabyte; see
//! [`int`].
//!
//! Low memory used: [`BUFFER`]`..+BUFFER_LEN` for data the call exchanges
//! with the BIOS (`es:di` points there with [`int_with_buffer`]), up to
//! [`THUNK`] for the real-mode stack, and the [`THUNK`] page for the code.

/// Physical address the thunk runs at: below the AP trampoline (0x8000),
/// above the BIOS data area.
pub const THUNK: u64 = 0x7000;

/// Physical address of the buffer [`int_with_buffer`] passes in `es:di`.
pub const BUFFER: u64 = 0x5000;

/// Bytes of [`BUFFER`]. The real-mode stack runs from [`THUNK`] down to the
/// end of the buffer.
pub const BUFFER_LEN: usize = 0x400;

/// Registers for a BIOS call: inputs before, outputs after.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Regs {
    /// EAX.
    pub eax: u32,
    /// EBX.
    pub ebx: u32,
    /// ECX.
    pub ecx: u32,
    /// EDX.
    pub edx: u32,
    /// ESI.
    pub esi: u32,
    /// EDI.
    pub edi: u32,
    /// EBP.
    pub ebp: u32,
    /// DS.
    pub ds: u16,
    /// ES.
    pub es: u16,
    /// FLAGS after the call (carry is bit 0); ignored on input.
    pub flags: u16,
}

// Assembled here, but it runs as a copy at THUNK, so every absolute address
// is computed relative to that copy. Selectors of the thunk's own GDT: 0x08
// 64-bit code, 0x10 32-bit code, 0x18 32-bit data, 0x20 16-bit code, 0x28
// 16-bit data.
core::arch::global_asm!(
    r#"
    .section .rodata.osmium_bios, "a"
    .code64
    .globl osmium_bios_start
osmium_bios_start:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    pushfq
    cli
    mov %rsp, {base} + (51f - osmium_bios_start)
    sgdt {base} + (52f - osmium_bios_start)
    sidt {base} + (53f - osmium_bios_start)
    mov %cr0, %rax
    mov %rax, {base} + (54f - osmium_bios_start)
    mov %cr3, %rax
    mov %rax, {base} + (55f - osmium_bios_start)
    mov %cs, {base} + (56f - osmium_bios_start)
    mov %ds, {base} + (56f + 2 - osmium_bios_start)
    mov %es, {base} + (56f + 4 - osmium_bios_start)
    mov %ss, {base} + (56f + 6 - osmium_bios_start)
    mov $0xc0000100, %ecx
    rdmsr
    mov %eax, {base} + (57f - osmium_bios_start)
    mov %edx, {base} + (57f + 4 - osmium_bios_start)
    mov $0xc0000101, %ecx
    rdmsr
    mov %eax, {base} + (57f + 8 - osmium_bios_start)
    mov %edx, {base} + (57f + 12 - osmium_bios_start)

    lgdt {base} + (41f - osmium_bios_start)
    pushq $0x10
    pushq ${base} + (1f - osmium_bios_start)
    lretq

    .code32
1:  mov $0x18, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    // Paging off leaves long mode (LMA clears), then LME off.
    mov %cr0, %eax
    and $0x7fffffff, %eax
    mov %eax, %cr0
    mov $0xc0000080, %ecx
    rdmsr
    and $~(1 << 8), %eax
    wrmsr
    ljmp $0x20, ${base} + (2f - osmium_bios_start)

    .code16
2:  mov $0x28, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    mov %cr0, %eax
    and $~1, %eax
    mov %eax, %cr0
    ljmp $0, ${base} + (3f - osmium_bios_start)

3:  xor %ax, %ax
    mov %ax, %ds
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    mov ${base}, %sp
    lidt {base} + (42f - osmium_bios_start)
    mov {base} + (60f + 0 - osmium_bios_start), %eax
    mov {base} + (60f + 4 - osmium_bios_start), %ebx
    mov {base} + (60f + 8 - osmium_bios_start), %ecx
    mov {base} + (60f + 12 - osmium_bios_start), %edx
    mov {base} + (60f + 16 - osmium_bios_start), %esi
    mov {base} + (60f + 20 - osmium_bios_start), %edi
    mov {base} + (60f + 24 - osmium_bios_start), %ebp
    mov {base} + (60f + 30 - osmium_bios_start), %es
    mov {base} + (60f + 28 - osmium_bios_start), %ds
    sti
    .byte 0xcd                      // int imm8, patched by `int`
    .globl osmium_bios_vector
osmium_bios_vector:
    .byte 0
    cli
    mov %eax, %cs:{base} + (60f + 0 - osmium_bios_start)
    mov %ebx, %cs:{base} + (60f + 4 - osmium_bios_start)
    mov %ecx, %cs:{base} + (60f + 8 - osmium_bios_start)
    mov %edx, %cs:{base} + (60f + 12 - osmium_bios_start)
    mov %esi, %cs:{base} + (60f + 16 - osmium_bios_start)
    mov %edi, %cs:{base} + (60f + 20 - osmium_bios_start)
    mov %ebp, %cs:{base} + (60f + 24 - osmium_bios_start)
    mov %ds, %cs:{base} + (60f + 28 - osmium_bios_start)
    mov %es, %cs:{base} + (60f + 30 - osmium_bios_start)
    pushf
    pop %ax
    mov %ax, %cs:{base} + (60f + 32 - osmium_bios_start)
    cld

    xor %ax, %ax
    mov %ax, %ds
    lgdtl {base} + (41f - osmium_bios_start)
    mov %cr0, %eax
    or $1, %eax
    mov %eax, %cr0
    ljmpl $0x10, ${base} + (4f - osmium_bios_start)

    .code32
4:  mov $0x18, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov {base} + (55f - osmium_bios_start), %eax
    mov %eax, %cr3
    mov %cr4, %eax
    or $(1 << 5), %eax
    mov %eax, %cr4
    mov $0xc0000080, %ecx
    rdmsr
    or $(1 << 8), %eax
    wrmsr
    mov {base} + (54f - osmium_bios_start), %eax
    mov %eax, %cr0
    ljmp $0x08, ${base} + (5f - osmium_bios_start)

    .code64
5:  lgdt {base} + (52f - osmium_bios_start)
    lidt {base} + (53f - osmium_bios_start)
    mov {base} + (51f - osmium_bios_start), %rsp
    mov {base} + (56f + 2 - osmium_bios_start), %ds
    mov {base} + (56f + 4 - osmium_bios_start), %es
    mov {base} + (56f + 6 - osmium_bios_start), %ss
    xor %eax, %eax
    mov %ax, %fs
    mov %ax, %gs
    mov $0xc0000100, %ecx
    mov {base} + (57f - osmium_bios_start), %eax
    mov {base} + (57f + 4 - osmium_bios_start), %edx
    wrmsr
    mov $0xc0000101, %ecx
    mov {base} + (57f + 8 - osmium_bios_start), %eax
    mov {base} + (57f + 12 - osmium_bios_start), %edx
    wrmsr
    movzwq {base} + (56f - osmium_bios_start), %rax
    push %rax
    lea 6f(%rip), %rax
    push %rax
    lretq
6:  popfq
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret

    .balign 16
40: .quad 0
    .quad 0x00af9a000000ffff        // 0x08: 64-bit code
    .quad 0x00cf9a000000ffff        // 0x10: 32-bit code
    .quad 0x00cf92000000ffff        // 0x18: 32-bit data
    .quad 0x00009a000000ffff        // 0x20: 16-bit code, 64 KiB
    .quad 0x000092000000ffff        // 0x28: 16-bit data, 64 KiB
41: .word 47                        // thunk GDTR
    .quad {base} + (40b - osmium_bios_start)
42: .word 0x3ff                     // real-mode IVT
    .quad 0
    .balign 8
51: .quad 0                         // saved RSP
52: .word 0                         // saved GDTR
    .quad 0
53: .word 0                         // saved IDTR
    .quad 0
    .balign 8
54: .quad 0                         // saved CR0
55: .quad 0                         // saved CR3
56: .word 0, 0, 0, 0                // saved CS, DS, ES, SS
57: .quad 0, 0                      // saved FS and GS bases
    .balign 8
    .globl osmium_bios_regs
osmium_bios_regs:
60: .fill 36, 1, 0                  // `Regs`
    .globl osmium_bios_end
osmium_bios_end:
    .text
"#,
    base = const THUNK,
    options(att_syntax)
);

unsafe extern "C" {
    static osmium_bios_start: u8;
    static osmium_bios_vector: u8;
    static osmium_bios_regs: u8;
    static osmium_bios_end: u8;
}

fn in_thunk(sym: *const u8) -> *mut u8 {
    (THUNK + (sym as u64 - &raw const osmium_bios_start as u64)) as *mut u8
}

/// Copies the thunk to [`THUNK`].
///
/// # Safety
/// The page at [`THUNK`] and the memory from [`BUFFER`] up to it must be
/// free, identity-mapped and writable.
pub unsafe fn install() {
    let (start, end) = (&raw const osmium_bios_start, &raw const osmium_bios_end);
    debug_assert!((end as usize - start as usize) < 4096);
    // SAFETY: the caller owns the page; the image is smaller than one.
    unsafe { core::ptr::copy_nonoverlapping(start, THUNK as *mut u8, end as usize - start as usize) };
}

/// Runs software interrupt `vector` in real mode with `regs`, and returns
/// the registers it left.
///
/// # Safety
/// - [`install`] has run, on this CPU's current page tables the low
///   megabyte is identity-mapped and executable, and CR3 is below 4 GiB.
/// - CR4.PCIDE is clear (paging cannot be switched off with it set) and no
///   CET shadow stack is active.
/// - Nothing may raise an NMI meanwhile: the 64-bit IDT stays loaded through
///   the 32- and 16-bit stages, so one there is unrecoverable. That is
///   acceptable in early boot.
/// - Only the boot CPU runs, and nothing has changed what the BIOS relies
///   on: the interrupt vector table and BIOS data areas, the legacy PIC
///   (masked or as the BIOS programmed it), and no local APIC timer or I/O
///   APIC routes that would fire while the BIOS enables interrupts.
/// - The call itself is memory safe: it writes only memory the caller owns
///   (such as [`BUFFER`]).
pub unsafe fn int(vector: u8, regs: &mut Regs) {
    let slot = in_thunk(&raw const osmium_bios_regs).cast::<Regs>();
    let entry = in_thunk(&raw const osmium_bios_start);
    // SAFETY: inside the installed copy (caller's contract); the thunk
    // saves and restores every register and CPU table it changes, and its
    // callee-saved registers per the C ABI.
    unsafe {
        in_thunk(&raw const osmium_bios_vector).write_volatile(vector);
        slot.write_volatile(*regs);
        let f: extern "C" fn() = core::mem::transmute(entry);
        f();
        *regs = slot.read_volatile();
    }
}

/// [`int`] with `es:di` pointing at [`BUFFER`], which holds a copy of `buf`
/// before the call and is copied back to it after.
///
/// # Safety
/// As [`int`]; the call may write only the buffer.
pub unsafe fn int_with_buffer(vector: u8, regs: &mut Regs, buf: &mut [u8]) {
    assert!(buf.len() <= BUFFER_LEN);
    regs.es = (BUFFER >> 4) as u16;
    regs.edi = (BUFFER & 0xf) as u32;
    // SAFETY: the buffer is low memory reserved for this (`install`).
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), BUFFER as *mut u8, buf.len());
        int(vector, regs);
        core::ptr::copy_nonoverlapping(BUFFER as *const u8, buf.as_mut_ptr(), buf.len());
    }
}
