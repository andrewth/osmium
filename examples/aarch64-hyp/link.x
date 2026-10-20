/* QEMU virt: RAM starts at 0x40000000 and, for ELF kernels, the device tree
   is placed at its base, so the kernel is linked above it. */
ENTRY(_start)

SECTIONS
{
    . = 0x40200000;
    _kernel_start = .;

    .text : {
        *(.text.entry)
        *(.text .text.*)
    }

    . = ALIGN(4K);
    _etext = .;
    .rodata : { *(.rodata .rodata.*) }

    . = ALIGN(4K);
    _erodata = .;
    .data : { *(.data .data.*) }

    . = ALIGN(4K);
    .bss (NOLOAD) : {
        _bss_start = .;
        *(.bss.stack)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(8);
        _bss_end = .;
    }

    . = ALIGN(4K);
    _kernel_end = .;

    /DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) }
}
