/* Loaded by QEMU's PVH loader at its physical link address. */
ENTRY(pvh_start)

SECTIONS
{
    . = 0x200000;
    _kernel_start = .;

    .note : { KEEP(*(.note.Xen)) }

    .text : {
        *(.text.entry)
        *(.text .text.*)
    }

    . = ALIGN(4K);
    _etext = .;
    .rodata : { *(.rodata .rodata.*) }

    . = ALIGN(4K);
    _erodata = .;
    .data : { *(.data .data.*) *(.got .got.*) }

    . = ALIGN(4K);
    .bss (NOLOAD) : {
        _bss_start = .;
        *(.bss.boot)
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(8);
        _bss_end = .;
    }

    . = ALIGN(4K);
    _kernel_end = .;

    /DISCARD/ : { *(.eh_frame) *(.eh_frame_hdr) }
}
