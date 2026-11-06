/* SPDX-License-Identifier: GPL-2.0-only */
/* Shared by the RISC-V S-mode examples (riscv-virt, riscv-hyp): loaded by
   OpenSBI at the start of S-mode payload space on QEMU virt. */
OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
    . = 0x80200000;
    _kernel_start = .;

    .text : {
        *(.text.entry)
        *(.text .text.*)
    }

    . = ALIGN(4K);
    _etext = .;
    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
    }

    . = ALIGN(4K);
    _erodata = .;
    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }
    PROVIDE(__global_pointer$ = ADDR(.data) + 0x800);

    . = ALIGN(4K);
    .bss (NOLOAD) : {
        _bss_start = .;
        *(.bss.stack)
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        . = ALIGN(8);
        _bss_end = .;
    }

    . = ALIGN(4K);
    _kernel_end = .;

    /DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) }
}
