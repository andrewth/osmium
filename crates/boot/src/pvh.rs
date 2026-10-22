//! The PVH boot protocol (Xen `hvm_start_info`), used by QEMU, Firecracker
//! and Cloud Hypervisor to start x86 kernels directly in 32-bit protected
//! mode.
//!
//! A kernel advertises its 32-bit entry point with [`pvh_entry_note!`](crate::pvh_entry_note),
//! or uses the ready-made x86-64 entry from [`pvh_start!`](crate::pvh_start).
//! The loader enters it with paging off and `ebx` holding the physical
//! address of the start-info structure.

use osmium_mm::{MemoryMap, PhysAddr, RegionKind};

use crate::{cstr, le32, le64};

/// `hvm_start_info.magic`.
pub const MAGIC: u32 = 0x336e_c578;

/// Emits the ELF note (`XEN_ELFNOTE_PHYS32_ENTRY`) that tells a PVH loader
/// where the 32-bit entry point is. Pass the entry symbol's name.
///
/// ```ignore
/// osmium_boot::pvh_entry_note!("pvh_start");
/// ```
#[macro_export]
macro_rules! pvh_entry_note {
    ($entry:literal) => {
        core::arch::global_asm!(concat!(
            ".pushsection .note.Xen, \"a\", @note\n",
            ".balign 4\n",
            ".long 4\n",  // name size ("Xen\0")
            ".long 4\n",  // descriptor size
            ".long 18\n", // XEN_ELFNOTE_PHYS32_ENTRY
            ".asciz \"Xen\"\n",
            ".balign 4\n",
            ".long ",
            $entry,
            "\n",
            ".balign 4\n",
            ".popsection\n",
        ));
    };
}

/// Emits a complete x86-64 PVH entry point, `pvh_start`, plus its ELF note.
///
/// The 32-bit entry zeroes `_bss_start.._bss_end` (from the linker script),
/// identity-maps the first 4 GiB with 2 MiB pages, enables long mode with NX
/// and write protection, loads a flat GDT (code `0x08`, data `0x10`), and
/// calls `main(start_info_phys)` on a 64 KiB boot stack. If `main` returns, the
/// CPU halts. The boot page-table root is exported as `boot_pml4`.
///
/// With `ap: ap_main`, it also emits `ap_start64`: 64-bit code for
/// application processors that reach long mode on the boot page tables (with
/// `rdi` = CPU index and `rsp` = their stack). It reloads the GDT and segments
/// and calls `ap_main`.
///
/// The linker script must place `.text.entry` and `.bss.boot` and keep
/// `.note.Xen`, all below 4 GiB. `osmium_boot_stack_top` must be below 2 GiB:
/// the 64-bit entry loads it with a sign-extended 32-bit immediate.
///
/// ```ignore
/// osmium_boot::pvh_start!(kmain);
/// osmium_boot::pvh_start!(kmain, ap: ap_main);
/// ```
#[macro_export]
macro_rules! pvh_start {
    ($main:path) => {
        $crate::pvh_entry_note!("pvh_start");
        core::arch::global_asm!($crate::__pvh_start_asm!(), main = sym $main, options(att_syntax));
    };
    ($main:path, ap: $ap_main:path) => {
        $crate::pvh_start!($main);
        core::arch::global_asm!(
            r#"
    .section .text.entry, "ax"
    .code64
    .globl ap_start64
ap_start64:
    lgdt osmium_boot_gdtr
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    xor %ax, %ax
    mov %ax, %fs
    mov %ax, %gs
    pushq $0x08
    lea 1f(%rip), %rax
    push %rax
    lretq
1:  call {ap_main}
2:  hlt
    jmp 2b
"#,
            ap_main = sym $ap_main,
            options(att_syntax)
        );
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __pvh_start_asm {
    () => {
        r#"
    .section .text.entry, "ax"
    .code32
    .globl pvh_start
pvh_start:
    cli
    cld
    mov %ebx, %esi

    mov $_bss_start, %edi
    mov $_bss_end, %ecx
    sub %edi, %ecx
    shr $2, %ecx
    xor %eax, %eax
    rep stosl

    // PML4[0] -> PDPT; PDPT[0..4] -> PD[0..4]; PD entries map 2 MiB each.
    mov $osmium_boot_pdpt, %eax
    or $0x3, %eax
    mov %eax, boot_pml4
    mov $osmium_boot_pd, %eax
    or $0x3, %eax
    mov $osmium_boot_pdpt, %edi
    mov $4, %ecx
1:  mov %eax, (%edi)
    add $0x1000, %eax
    add $8, %edi
    loop 1b
    mov $osmium_boot_pd, %edi
    mov $0x83, %eax
    mov $2048, %ecx
2:  mov %eax, (%edi)
    add $0x200000, %eax
    add $8, %edi
    loop 2b

    mov $boot_pml4, %eax
    mov %eax, %cr3
    mov %cr4, %eax
    or $(1 << 5), %eax
    mov %eax, %cr4
    mov $0xc0000080, %ecx
    rdmsr
    or $((1 << 8) | (1 << 11)), %eax
    wrmsr
    mov %cr0, %eax
    or $((1 << 31) | (1 << 16) | 1), %eax
    mov %eax, %cr0

    lgdt osmium_boot_gdtr
    ljmp $0x08, $3f

    .code64
3:  mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    xor %ax, %ax
    mov %ax, %fs
    mov %ax, %gs
    mov $osmium_boot_stack_top, %rsp
    mov %esi, %edi
    call {main}
4:  hlt
    jmp 4b

    .section .rodata
    .balign 8
osmium_boot_gdt:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
    .globl osmium_boot_gdtr
osmium_boot_gdtr:
    .word osmium_boot_gdtr - osmium_boot_gdt - 1
    .quad osmium_boot_gdt

    .section .bss.boot, "aw", @nobits
    .balign 4096
    .globl boot_pml4
boot_pml4:        .space 4096
osmium_boot_pdpt: .space 4096
osmium_boot_pd:   .space 4096 * 4
    .space 65536
osmium_boot_stack_top:
"#
    };
}

/// The start-info structure was malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidStartInfo;

/// One E820-style memory-map entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemmapEntry {
    /// First byte.
    pub addr: u64,
    /// Length in bytes.
    pub size: u64,
    /// E820 type: 1 RAM, 2 reserved, 3 ACPI reclaimable, 4 ACPI NVS, 5 bad.
    pub typ: u32,
}

/// A boot module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module {
    /// Physical address.
    pub addr: PhysAddr,
    /// Size in bytes.
    pub size: u64,
}

/// A parsed `hvm_start_info`.
#[derive(Clone, Copy, Debug)]
pub struct StartInfo<'src> {
    header: &'src [u8],
    memmap: &'src [u8],
    modules: &'src [u8],
    cmdline: Option<&'src str>,
    /// Bytes of the command line, NUL included.
    cmdline_len: usize,
    /// Physical address of the header, if known.
    at: Option<PhysAddr>,
}

const HEADER_V0: usize = 40;
const HEADER_V1: usize = 56;
const MODULE_SIZE: u64 = 32;
const MEMMAP_ENTRY_SIZE: u64 = 24;

impl<'src> StartInfo<'src> {
    /// Parses a start-info header plus the memory map, module list and
    /// command line it points to, given as byte slices.
    pub fn parse(
        header: &'src [u8],
        memmap: &'src [u8],
        modules: &'src [u8],
        cmdline: Option<&'src [u8]>,
    ) -> Result<Self, InvalidStartInfo> {
        if le32(header, 0) != Some(MAGIC) || header.len() < HEADER_V0 {
            return Err(InvalidStartInfo);
        }
        let cmdline_len = cmdline.map_or(0, |c| c.iter().position(|&b| b == 0).map_or(c.len(), |n| n + 1));
        Ok(Self { header, memmap, modules, cmdline: cmdline.and_then(cstr), cmdline_len, at: None })
    }

    /// Parses the structure at `ptr`, following its physical pointers as
    /// identity-mapped addresses (as they are at PVH entry).
    ///
    /// # Safety
    /// `ptr` must point at a valid `hvm_start_info` whose memory map, module
    /// list and command line are readable at their physical addresses and
    /// unmodified for `'src`.
    pub unsafe fn from_ptr(ptr: *const u8) -> Result<Self, InvalidStartInfo> {
        // SAFETY: the caller guarantees the v0 header is readable.
        let v0 = unsafe { core::slice::from_raw_parts(ptr, HEADER_V0) };
        if le32(v0, 0) != Some(MAGIC) {
            return Err(InvalidStartInfo);
        }
        let version = le32(v0, 4).ok_or(InvalidStartInfo)?;
        let len = if version >= 1 { HEADER_V1 } else { HEADER_V0 };
        // SAFETY: the version says this much is present.
        let header = unsafe { core::slice::from_raw_parts(ptr, len) };
        let slice = |pa: u64, n: usize| -> &'src [u8] {
            if pa == 0 || n == 0 {
                &[]
            } else {
                // SAFETY: the caller guarantees the pointed-to data is readable.
                unsafe { core::slice::from_raw_parts(pa as usize as *const u8, n) }
            }
        };
        // Lengths and ends that overflow are malformed.
        let checked = |(pa, len): (u64, u64)| -> Result<(u64, usize), InvalidStartInfo> {
            pa.checked_add(len).ok_or(InvalidStartInfo)?;
            Ok((pa, usize::try_from(len).map_err(|_| InvalidStartInfo)?))
        };
        let (modules_pa, modules_len) = checked(Self::modules_range(header))?;
        let modules = slice(modules_pa, modules_len);
        let (memmap_pa, memmap_len) = checked(Self::memmap_range(header))?;
        let memmap = slice(memmap_pa, memmap_len);
        let cmdline_pa = le64(header, 24).unwrap_or(0);
        let cmdline = (cmdline_pa != 0).then(|| {
            // SAFETY: a NUL-terminated string at a caller-guaranteed readable address.
            unsafe { core::ffi::CStr::from_ptr(cmdline_pa as usize as *const core::ffi::c_char) }.to_bytes_with_nul()
        });
        let mut info = Self::parse(header, memmap, modules, cmdline)?;
        info.at = Some(PhysAddr::new(ptr as usize as u64));
        Ok(info)
    }

    /// Physical address and length in bytes of the module list. A `u32`
    /// count times the entry size cannot overflow a `u64`; the end can.
    fn modules_range(header: &[u8]) -> (u64, u64) {
        let count = le32(header, 12).unwrap_or(0) as u64;
        (le64(header, 16).unwrap_or(0), count * MODULE_SIZE)
    }

    /// Physical address and length in bytes of the memory map (version 1
    /// and later; empty before).
    fn memmap_range(header: &[u8]) -> (u64, u64) {
        if le32(header, 4).unwrap_or(0) < 1 {
            return (0, 0);
        }
        let count = le32(header, 48).unwrap_or(0) as u64;
        (le64(header, 40).unwrap_or(0), count * MEMMAP_ENTRY_SIZE)
    }

    /// Structure version (0 has no memory map; the loader then provides
    /// one through E820 or the firmware).
    pub fn version(&self) -> u32 {
        le32(self.header, 4).unwrap_or(0)
    }

    /// The kernel command line.
    pub fn cmdline(&self) -> Option<&'src str> {
        self.cmdline
    }

    /// Physical address of the ACPI RSDP, if the loader provided it.
    pub fn rsdp(&self) -> Option<PhysAddr> {
        le64(self.header, 32).filter(|&a| a != 0).map(PhysAddr::new)
    }

    /// The memory map.
    pub fn memory_map(&self) -> impl Iterator<Item = MemmapEntry> + 'src + use<'src> {
        self.memmap
            .as_chunks::<24>()
            .0
            .iter()
            .filter_map(|e| Some(MemmapEntry { addr: le64(e, 0)?, size: le64(e, 8)?, typ: le32(e, 16)? }))
    }

    /// Boot modules.
    pub fn modules(&self) -> impl Iterator<Item = Module> + 'src + use<'src> {
        self.modules
            .as_chunks::<32>()
            .0
            .iter()
            .filter_map(|m| Some(Module { addr: PhysAddr::new(le64(m, 0)?), size: le64(m, 8)? }))
    }

    /// Adds the memory map to `map` and reserves, as
    /// [`RegionKind::Bootloader`], the modules and the loader's own
    /// structures: the start-info header (when parsed with
    /// [`StartInfo::from_ptr`], which knows its address), the module list,
    /// the memory map and the command line. Also reserves the first 1 MiB
    /// (real-mode IVT, BIOS data, option ROMs), which E820 maps often report
    /// as partly usable. Module command lines are not reserved: their
    /// lengths are only known by reading them.
    ///
    /// RAM entries whose end overflows are malformed and skipped; reserved
    /// ranges that overflow are clamped to the top of the address space. If
    /// the map runs out of room, it gives up detail or RAM as
    /// [`MemoryMap::add_lossy`] describes; the result is the number of usable
    /// bytes dropped, worth logging if not zero.
    pub fn fill_memory_map<const N: usize>(&self, map: &mut MemoryMap<N>) -> Result<u64, osmium_mm::map::MapFull> {
        let mut lost = 0;
        let mut add = |map: &mut MemoryMap<N>, a: u64, s: u64, kind| -> Result<(), osmium_mm::map::MapFull> {
            lost += map.add_lossy(PhysAddr::new(a), PhysAddr::new(a.saturating_add(s)), kind)?;
            Ok(())
        };
        for e in self.memory_map() {
            let kind = match e.typ {
                1 => RegionKind::Usable,
                3 => RegionKind::AcpiReclaimable,
                4 => RegionKind::AcpiNvs,
                5 => RegionKind::BadMemory,
                _ => RegionKind::Reserved,
            };
            if kind != RegionKind::Usable || e.addr.checked_add(e.size).is_some() {
                add(map, e.addr, e.size, kind)?;
            }
        }
        for m in self.modules() {
            add(map, m.addr.0, m.size, RegionKind::Bootloader)?;
        }
        if let Some(at) = self.at {
            add(map, at.0, self.header.len() as u64, RegionKind::Bootloader)?;
        }
        let header = self.header;
        for (pa, len) in [Self::modules_range(header), Self::memmap_range(header)] {
            if pa != 0 {
                add(map, pa, len, RegionKind::Bootloader)?;
            }
        }
        if let Some(pa) = le64(header, 24).filter(|&pa| pa != 0) {
            add(map, pa, self.cmdline_len.max(1) as u64, RegionKind::Bootloader)?;
        }
        add(map, 0, 0x10_0000, RegionKind::Reserved)?;
        Ok(lost)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn parse_v1() {
        let mut h = Vec::new();
        for v in [MAGIC, 1, 0, 1] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        for v in [0x1000u64, 0x2000, 0xf_5000, 0x3000] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        h.extend_from_slice(&3u32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        let mut mm = Vec::new();
        for (a, s, t) in [(0u64, 0x9_fc00u64, 1u32), (0x10_0000, 0x7ee_0000, 1), (0xfeff_c000, 0x4000, 2)] {
            mm.extend_from_slice(&a.to_le_bytes());
            mm.extend_from_slice(&s.to_le_bytes());
            mm.extend_from_slice(&t.to_le_bytes());
            mm.extend_from_slice(&0u32.to_le_bytes());
        }
        let mut modl = Vec::new();
        for v in [0x400_0000u64, 0x1234, 0, 0] {
            modl.extend_from_slice(&v.to_le_bytes());
        }
        let info = StartInfo::parse(&h, &mm, &modl, Some(b"console=ttyS0\0")).unwrap();
        assert_eq!(info.version(), 1);
        assert_eq!(info.cmdline(), Some("console=ttyS0"));
        assert_eq!(info.rsdp(), Some(PhysAddr::new(0xf_5000)));
        assert_eq!(info.memory_map().count(), 3);
        assert_eq!(info.modules().next(), Some(Module { addr: PhysAddr::new(0x400_0000), size: 0x1234 }));
        let mut map = MemoryMap::<16>::new();
        info.fill_memory_map(&mut map).unwrap();
        assert_eq!(map.total(RegionKind::Usable), 0x7ee_0000 - 0x1234);
        assert!(map.usable().all(|r| r.start.0 >= 0x10_0000), "low 1 MiB reserved");
        assert!(StartInfo::parse(&h[..8], &[], &[], None).is_err());
    }

    #[test]
    fn loader_structures_are_reserved() {
        // Module list, command line and memory map above 1 MiB, in RAM.
        let mut h = Vec::new();
        for v in [MAGIC, 1, 0, 1] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        for v in [0x20_0000u64, 0x20_1000, 0, 0x20_2000] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        h.extend_from_slice(&2u32.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        let mut mm = Vec::new();
        // RAM, and a malformed entry whose end overflows.
        for (a, s) in [(0x10_0000u64, 0x7f0_0000u64), (0x1_0000_0000, u64::MAX)] {
            mm.extend_from_slice(&a.to_le_bytes());
            mm.extend_from_slice(&s.to_le_bytes());
            mm.extend_from_slice(&1u32.to_le_bytes());
            mm.extend_from_slice(&0u32.to_le_bytes());
        }
        let mut modl = Vec::new();
        for v in [0x400_0000u64, 0x1000, 0, 0] {
            modl.extend_from_slice(&v.to_le_bytes());
        }
        let mut info = StartInfo::parse(&h, &mm, &modl, Some(b"quiet\0")).unwrap();
        info.at = Some(PhysAddr::new(0x20_3000));
        let mut map = MemoryMap::<16>::new();
        assert_eq!(info.fill_memory_map(&mut map), Ok(0));
        // Module, module list, command line, memory map and header.
        assert_eq!(map.total(RegionKind::Bootloader), 0x1000 + 32 + 6 + 2 * 24 + HEADER_V1 as u64);
        assert_eq!(map.total(RegionKind::Usable), 0x7f0_0000 - (0x1000 + 32 + 6 + 2 * 24 + HEADER_V1 as u64));
        assert!(map.usable().all(|r| r.end.0 <= 0x800_0000), "overflowing entry skipped");
    }
}
