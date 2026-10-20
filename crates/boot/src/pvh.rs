//! The PVH boot protocol (Xen `hvm_start_info`), used by QEMU, Firecracker
//! and Cloud Hypervisor to start x86 kernels directly in 32-bit protected
//! mode.
//!
//! A kernel advertises its 32-bit entry point with [`pvh_entry_note!`](crate::pvh_entry_note).
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
            ".long ", $entry, "\n",
            ".balign 4\n",
            ".popsection\n",
        ));
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
pub struct StartInfo<'a> {
    header: &'a [u8],
    memmap: &'a [u8],
    modules: &'a [u8],
    cmdline: Option<&'a str>,
}

const HEADER_V0: usize = 40;
const HEADER_V1: usize = 56;

impl<'a> StartInfo<'a> {
    /// Parses a start-info header plus the memory map, module list and
    /// command line it points to, given as byte slices.
    pub fn parse(header: &'a [u8], memmap: &'a [u8], modules: &'a [u8], cmdline: Option<&'a [u8]>) -> Result<Self, InvalidStartInfo> {
        if le32(header, 0) != Some(MAGIC) || header.len() < HEADER_V0 {
            return Err(InvalidStartInfo);
        }
        Ok(Self { header, memmap, modules, cmdline: cmdline.and_then(cstr) })
    }

    /// Parses the structure at `ptr`, following its physical pointers as
    /// identity-mapped addresses (as they are at PVH entry).
    ///
    /// # Safety
    /// `ptr` must point at a valid `hvm_start_info` whose memory map, module
    /// list and command line are readable at their physical addresses and
    /// unmodified for `'a`.
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
        let slice = |pa: u64, n: usize| -> &'a [u8] {
            if pa == 0 || n == 0 {
                &[]
            } else {
                // SAFETY: the caller guarantees the pointed-to data is readable.
                unsafe { core::slice::from_raw_parts(pa as usize as *const u8, n) }
            }
        };
        let nr_modules = le32(header, 12).unwrap_or(0) as usize;
        let modules = slice(le64(header, 16).unwrap_or(0), nr_modules * 32);
        let (memmap_pa, entries) =
            if version >= 1 { (le64(header, 40).unwrap_or(0), le32(header, 48).unwrap_or(0) as usize) } else { (0, 0) };
        let memmap = slice(memmap_pa, entries * 24);
        let cmdline_pa = le64(header, 24).unwrap_or(0);
        let cmdline = (cmdline_pa != 0).then(|| {
            // SAFETY: a NUL-terminated string at a caller-guaranteed readable address.
            unsafe { core::ffi::CStr::from_ptr(cmdline_pa as usize as *const core::ffi::c_char) }.to_bytes_with_nul()
        });
        Self::parse(header, memmap, modules, cmdline)
    }

    /// Structure version (0 has no memory map; the loader then provides
    /// one through E820 or the firmware).
    pub fn version(&self) -> u32 {
        le32(self.header, 4).unwrap_or(0)
    }

    /// The kernel command line.
    pub fn cmdline(&self) -> Option<&'a str> {
        self.cmdline
    }

    /// Physical address of the ACPI RSDP, if the loader provided it.
    pub fn rsdp(&self) -> Option<PhysAddr> {
        le64(self.header, 32).filter(|&a| a != 0).map(PhysAddr::new)
    }

    /// The memory map.
    pub fn memory_map(&self) -> impl Iterator<Item = MemmapEntry> + 'a + use<'a> {
        self.memmap
            .as_chunks::<24>()
            .0
            .iter()
            .filter_map(|e| Some(MemmapEntry { addr: le64(e, 0)?, size: le64(e, 8)?, typ: le32(e, 16)? }))
    }

    /// Boot modules.
    pub fn modules(&self) -> impl Iterator<Item = Module> + 'a + use<'a> {
        self.modules
            .as_chunks::<32>()
            .0
            .iter()
            .filter_map(|m| Some(Module { addr: PhysAddr::new(le64(m, 0)?), size: le64(m, 8)? }))
    }

    /// Adds the memory map and modules to `map`, and reserves the first
    /// 1 MiB (real-mode IVT, BIOS data, option ROMs), which E820 maps often
    /// report as partly usable.
    pub fn fill_memory_map<const N: usize>(&self, map: &mut MemoryMap<N>) -> Result<(), osmium_mm::map::MapFull> {
        for e in self.memory_map() {
            let kind = match e.typ {
                1 => RegionKind::Usable,
                3 => RegionKind::AcpiReclaimable,
                4 => RegionKind::AcpiNvs,
                5 => RegionKind::BadMemory,
                _ => RegionKind::Reserved,
            };
            map.add(PhysAddr::new(e.addr), PhysAddr::new(e.addr.saturating_add(e.size)), kind)?;
        }
        for m in self.modules() {
            map.reserve(m.addr, m.addr + m.size, RegionKind::Bootloader)?;
        }
        map.reserve(PhysAddr::new(0), PhysAddr::new(0x10_0000), RegionKind::Reserved)
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
}
