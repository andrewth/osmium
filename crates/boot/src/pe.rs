//! PE32+ (COFF) image parsing, mapping and base relocation: what a UEFI
//! firmware or a boot loader needs to load an `.efi` application or a Windows
//! style kernel.
//!
//! Every offset read from the file is bounds checked: images are untrusted.
//!
//! ```ignore
//! let info = pe::parse(file, pe::MACHINE_X86_64)?;
//! let mut mem = std::vec![0u8; info.size_of_image as usize];
//! pe::load(file, &info, &mut mem, load_addr)?;
//! let entry = load_addr + info.entry_rva as u64;
//! ```

/// `Machine` value of x86_64 images.
pub const MACHINE_X86_64: u16 = 0x8664;
/// `Machine` value of AArch64 images.
pub const MACHINE_AARCH64: u16 = 0xAA64;
/// `Machine` value of RISC-V 64 images.
pub const MACHINE_RISCV64: u16 = 0x5064;

/// Why an image was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    /// Not a PE32+ image for this machine, or uses a feature that is not handled.
    Unsupported,
    /// Headers, sections or relocations are inconsistent or outside the file.
    Malformed,
    /// The destination or output buffer is too small.
    BufferTooSmall,
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

const DOS_MAGIC: u16 = 0x5A4D;
const PE_MAGIC: u32 = 0x0000_4550;
const OPT_MAGIC_PE32_PLUS: u16 = 0x20B;
const DIR_BASERELOC: usize = 5;
const REL_ABSOLUTE: u16 = 0;
const REL_DIR64: u16 = 10;

/// Subsystem of UEFI applications.
pub const SUBSYSTEM_EFI_APPLICATION: u16 = 10;
/// Subsystem of UEFI boot-service drivers.
pub const SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: u16 = 11;
/// Subsystem of UEFI runtime drivers.
pub const SUBSYSTEM_EFI_RUNTIME_DRIVER: u16 = 12;

/// Largest SectionAlignment accepted (arm64 Linux uses 64 KiB).
pub const MAX_SECTION_ALIGNMENT: u32 = 2 * 1024 * 1024;

/// The header fields a loader needs.
#[derive(Debug, Clone, Copy)]
pub struct PeInfo {
    /// The preferred load address.
    pub image_base: u64,
    /// Bytes of memory the mapped image occupies.
    pub size_of_image: u32,
    /// Bytes of headers copied to the start of the image.
    pub size_of_headers: u32,
    /// Entry point, relative to the image base.
    pub entry_rva: u32,
    /// The `Subsystem` field.
    pub subsystem: u16,
    /// Required load-address alignment (at least 1; may exceed the page size,
    /// e.g. arm64 Linux images use 64 KiB).
    pub section_alignment: u32,
    reloc_rva: u32,
    reloc_size: u32,
    relocs_stripped: bool,
    section_table: usize,
    num_sections: usize,
}

fn u16_at(d: &[u8], o: usize) -> Result<u16, PeError> {
    d.get(o..o.checked_add(2).ok_or(PeError::Malformed)?).map(|b| le16(b, 0)).ok_or(PeError::Malformed)
}

fn u32_at(d: &[u8], o: usize) -> Result<u32, PeError> {
    d.get(o..o.checked_add(4).ok_or(PeError::Malformed)?).map(|b| le32(b, 0)).ok_or(PeError::Malformed)
}

fn u64_at(d: &[u8], o: usize) -> Result<u64, PeError> {
    d.get(o..o.checked_add(8).ok_or(PeError::Malformed)?).map(|b| le64(b, 0)).ok_or(PeError::Malformed)
}

/// Validates the headers of `file` for `machine` (a `MACHINE_*` value).
pub fn parse(file: &[u8], machine: u16) -> Result<PeInfo, PeError> {
    if u16_at(file, 0)? != DOS_MAGIC {
        return Err(PeError::Unsupported);
    }
    let pe = u32_at(file, 0x3C)? as usize;
    if u32_at(file, pe)? != PE_MAGIC {
        return Err(PeError::Unsupported);
    }
    let coff = pe + 4;
    if u16_at(file, coff)? != machine {
        return Err(PeError::Unsupported);
    }
    let num_sections = u16_at(file, coff + 2)? as usize;
    let opt_size = u16_at(file, coff + 16)? as usize;
    let opt = coff + 20;
    if u16_at(file, opt)? != OPT_MAGIC_PE32_PLUS || opt_size < 112 {
        return Err(PeError::Unsupported);
    }
    let section_alignment = u32_at(file, opt + 32)?;
    let num_dirs = u32_at(file, opt + 108)? as usize;
    let (reloc_rva, reloc_size) = if num_dirs > DIR_BASERELOC && opt_size >= 112 + (DIR_BASERELOC + 1) * 8 {
        (u32_at(file, opt + 112 + DIR_BASERELOC * 8)?, u32_at(file, opt + 116 + DIR_BASERELOC * 8)?)
    } else {
        (0, 0)
    };
    let info = PeInfo {
        image_base: u64_at(file, opt + 24)?,
        size_of_image: u32_at(file, opt + 56)?,
        size_of_headers: u32_at(file, opt + 60)?,
        entry_rva: u32_at(file, opt + 16)?,
        subsystem: u16_at(file, opt + 68)?,
        section_alignment: section_alignment.max(1),
        reloc_rva,
        reloc_size,
        relocs_stripped: u16_at(file, coff + 18)? & 0x0001 != 0, // IMAGE_FILE_RELOCS_STRIPPED
        section_table: opt + opt_size,
        num_sections,
    };
    // The caller aligns the load address; bound what it has to over-allocate.
    if !info.section_alignment.is_power_of_two() || info.section_alignment > MAX_SECTION_ALIGNMENT {
        return Err(PeError::Unsupported);
    }
    if info.size_of_image == 0
        || info.size_of_headers > info.size_of_image
        || info.size_of_headers as usize > file.len()
        || info.entry_rva >= info.size_of_image
    {
        return Err(PeError::Malformed);
    }
    // The section table must lie within the file.
    let table_end = info.section_table.checked_add(num_sections * 40).ok_or(PeError::Malformed)?;
    if table_end > file.len() {
        return Err(PeError::Malformed);
    }
    Ok(info)
}

/// Map `file` into `dest` (zeroed, `size_of_image` bytes or more) as if it
/// were loaded at `load_addr`, applying base relocations.
pub fn load(file: &[u8], info: &PeInfo, dest: &mut [u8], load_addr: u64) -> Result<(), PeError> {
    let size = info.size_of_image as usize;
    if dest.len() < size {
        return Err(PeError::BufferTooSmall);
    }
    dest[..size].fill(0);
    dest[..info.size_of_headers as usize].copy_from_slice(&file[..info.size_of_headers as usize]);

    for i in 0..info.num_sections {
        let s = info.section_table + i * 40;
        let virtual_size = u32_at(file, s + 8)? as usize;
        let va = u32_at(file, s + 12)? as usize;
        let raw_size = u32_at(file, s + 16)? as usize;
        let raw_ptr = u32_at(file, s + 20)? as usize;
        let n = if virtual_size == 0 { raw_size } else { raw_size.min(virtual_size) };
        if n == 0 {
            continue;
        }
        let src = file.get(raw_ptr..raw_ptr.checked_add(n).ok_or(PeError::Malformed)?).ok_or(PeError::Malformed)?;
        let dst = dest
            .get_mut(va..va.checked_add(n).ok_or(PeError::Malformed)?)
            .filter(|_| va + n <= size)
            .ok_or(PeError::Malformed)?;
        dst.copy_from_slice(src);
    }

    let delta = load_addr.wrapping_sub(info.image_base);
    if delta == 0 {
        return Ok(());
    }
    if info.reloc_size == 0 {
        // Position-independent code with nothing to fix up is fine; only
        // images explicitly built for a fixed address can't move.
        return if info.relocs_stripped { Err(PeError::Malformed) } else { Ok(()) };
    }
    let (start, len) = (info.reloc_rva as usize, info.reloc_size as usize);
    let end = start.checked_add(len).filter(|&e| e <= size).ok_or(PeError::Malformed)?;
    let mut off = start;
    while off + 8 <= end {
        let page = u32_at(dest, off)? as usize;
        let block = u32_at(dest, off + 4)? as usize;
        if block < 8 || off + block > end {
            return Err(PeError::Malformed);
        }
        for e in (off + 8..off + block).step_by(2) {
            let entry = u16_at(dest, e)?;
            let at = page + (entry & 0x0FFF) as usize;
            match entry >> 12 {
                REL_ABSOLUTE => {}
                REL_DIR64 => {
                    if at.checked_add(8).is_none_or(|e| e > size) {
                        return Err(PeError::Malformed);
                    }
                    let v = u64_at(dest, at)?.wrapping_add(delta);
                    dest[at..at + 8].copy_from_slice(&v.to_le_bytes());
                }
                _ => return Err(PeError::Unsupported),
            }
        }
        off += block;
    }
    Ok(())
}

/// A DIR64 fixup site of a loaded image and the value it held right after
/// loading. Runtime drivers keep these so `SetVirtualAddressMap` can move them.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixup {
    /// Image-relative address of the 8-byte site.
    pub rva: u32,
    /// Padding; zero.
    pub reserved: u32,
    /// The site's value right after loading.
    pub value: u64,
}

/// Call `f(rva)` for every DIR64 fixup site of the loaded `image`.
fn for_each_fixup(image: &[u8], info: &PeInfo, mut f: impl FnMut(usize)) -> Result<(), PeError> {
    if info.reloc_size == 0 {
        return Ok(());
    }
    let size = info.size_of_image as usize;
    // Every site is bounds-checked against `size_of_image`, so `image` must cover all of it.
    if image.len() < size {
        return Err(PeError::Malformed);
    }
    let (start, len) = (info.reloc_rva as usize, info.reloc_size as usize);
    let end = start.checked_add(len).filter(|&e| e <= size).ok_or(PeError::Malformed)?;
    let mut off = start;
    while off + 8 <= end {
        let page = u32_at(image, off)? as usize;
        let block = u32_at(image, off + 4)? as usize;
        if block < 8 || off + block > end {
            return Err(PeError::Malformed);
        }
        for e in (off + 8..off + block).step_by(2) {
            let entry = u16_at(image, e)?;
            let at = page + (entry & 0x0FFF) as usize;
            match entry >> 12 {
                REL_ABSOLUTE => {}
                REL_DIR64 => {
                    if at.checked_add(8).is_none_or(|e| e > size) {
                        return Err(PeError::Malformed);
                    }
                    f(at)
                }
                _ => return Err(PeError::Unsupported),
            }
        }
        off += block;
    }
    Ok(())
}

/// How many [`Fixup`]s `collect_fixups` will produce for this loaded image.
pub fn count_fixups(image: &[u8], info: &PeInfo) -> Result<usize, PeError> {
    let mut n = 0;
    for_each_fixup(image, info, |_| n += 1)?;
    Ok(n)
}

/// Record every DIR64 site of the (already relocated) `image` with its current
/// value. `out` must have room for `count_fixups` entries.
pub fn collect_fixups(image: &[u8], info: &PeInfo, out: &mut [Fixup]) -> Result<usize, PeError> {
    let mut n = 0;
    let mut full = false;
    for_each_fixup(image, info, |at| {
        let Some(slot) = out.get_mut(n) else {
            full = true;
            return;
        };
        let value = le64(image, at);
        *slot = Fixup { rva: at as u32, reserved: 0, value };
        n += 1;
    })?;
    if full { Err(PeError::BufferTooSmall) } else { Ok(n) }
}

/// Move a runtime image by `delta` (new base - old base, wrapping): each
/// recorded site that still holds its recorded value gets `delta` added. A site
/// the driver changed since (e.g. converted itself with `ConvertPointer` in its
/// address-change notification) is left alone, as edk2 does.
pub fn rebase(image: &mut [u8], fixups: &[Fixup], delta: u64) {
    for f in fixups {
        let at = f.rva as usize;
        let Some(site) = at.checked_add(8).and_then(|e| image.get_mut(at..e)) else { continue };
        if le64(site, 0) == f.value {
            site.copy_from_slice(&f.value.wrapping_add(delta).to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE32+: headers in the first 0x200 bytes, one .text section at
    /// RVA 0x1000 holding an absolute pointer, one reloc block at RVA 0x2000.
    fn sample(image_base: u64) -> std::vec::Vec<u8> {
        let mut f = std::vec![0u8; 0x400];
        f[0..2].copy_from_slice(b"MZ");
        f[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        f[0x40..0x44].copy_from_slice(b"PE\0\0");
        f[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        f[0x46..0x48].copy_from_slice(&2u16.to_le_bytes()); // sections
        f[0x54..0x56].copy_from_slice(&240u16.to_le_bytes()); // opt size
        let o = 0x58;
        f[o..o + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        f[o + 16..o + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry
        f[o + 24..o + 32].copy_from_slice(&image_base.to_le_bytes());
        f[o + 32..o + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // section align
        f[o + 56..o + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // size of image
        f[o + 60..o + 64].copy_from_slice(&0x200u32.to_le_bytes()); // headers
        f[o + 68..o + 70].copy_from_slice(&10u16.to_le_bytes()); // subsystem
        f[o + 108..o + 112].copy_from_slice(&16u32.to_le_bytes());
        f[o + 152..o + 156].copy_from_slice(&0x2000u32.to_le_bytes()); // reloc rva
        f[o + 156..o + 160].copy_from_slice(&12u32.to_le_bytes()); // reloc size
        let s = o + 240; // 0x148
        for (i, (va, raw)) in [(0x1000u32, 0x200u32), (0x2000, 0x300)].iter().enumerate() {
            let h = s + i * 40;
            f[h + 8..h + 12].copy_from_slice(&0x100u32.to_le_bytes());
            f[h + 12..h + 16].copy_from_slice(&va.to_le_bytes());
            f[h + 16..h + 20].copy_from_slice(&0x100u32.to_le_bytes());
            f[h + 20..h + 24].copy_from_slice(&raw.to_le_bytes());
        }
        // .text: pointer to image_base+0x1234 at offset 8.
        f[0x208..0x210].copy_from_slice(&(image_base + 0x1234).to_le_bytes());
        // .reloc: page 0x1000, block 12 bytes: DIR64 at 8, padding.
        f[0x300..0x304].copy_from_slice(&0x1000u32.to_le_bytes());
        f[0x304..0x308].copy_from_slice(&12u32.to_le_bytes());
        f[0x308..0x30A].copy_from_slice(&((10u16 << 12) | 8).to_le_bytes());
        f
    }

    #[test]
    fn parses_and_relocates() {
        let f = sample(0x1_4000_0000);
        let info = parse(&f, 0x8664).unwrap();
        assert_eq!(info.entry_rva, 0x1000);
        let mut mem = std::vec![0xAAu8; 0x3000];
        load(&f, &info, &mut mem, 0x20_0000).unwrap();
        assert_eq!(&mem[..2], b"MZ");
        let v = u64::from_le_bytes(mem[0x1008..0x1010].try_into().unwrap());
        assert_eq!(v, 0x20_0000 + 0x1234);
    }

    #[test]
    fn large_section_alignment() {
        let mut f = sample(0x1_4000_0000);
        f[0x58 + 32..0x58 + 36].copy_from_slice(&0x10000u32.to_le_bytes());
        let info = parse(&f, 0x8664).unwrap();
        assert_eq!(info.section_alignment, 0x10000);
        f[0x58 + 32..0x58 + 36].copy_from_slice(&0x3000u32.to_le_bytes()); // not a power of two
        assert_eq!(parse(&f, 0x8664).unwrap_err(), PeError::Unsupported);
        f[0x58 + 32..0x58 + 36].copy_from_slice(&(MAX_SECTION_ALIGNMENT * 2).to_le_bytes());
        assert_eq!(parse(&f, 0x8664).unwrap_err(), PeError::Unsupported);
    }

    #[test]
    fn no_relocation_at_preferred_base() {
        let f = sample(0x20_0000);
        let info = parse(&f, 0x8664).unwrap();
        let mut mem = std::vec![0u8; 0x3000];
        load(&f, &info, &mut mem, 0x20_0000).unwrap();
        let v = u64::from_le_bytes(mem[0x1008..0x1010].try_into().unwrap());
        assert_eq!(v, 0x20_0000 + 0x1234);
    }

    #[test]
    fn missing_relocs_only_fatal_when_stripped() {
        let mut f = sample(0x1_4000_0000);
        // Drop the reloc directory.
        f[0x58 + 156..0x58 + 160].copy_from_slice(&0u32.to_le_bytes());
        let info = parse(&f, 0x8664).unwrap();
        let mut mem = std::vec![0u8; 0x3000];
        assert_eq!(load(&f, &info, &mut mem, 0x20_0000), Ok(()));
        let mut g = sample(0x1_4000_0000);
        g[0x58 + 156..0x58 + 160].copy_from_slice(&0u32.to_le_bytes());
        g[0x44 + 18..0x44 + 20].copy_from_slice(&1u16.to_le_bytes()); // RELOCS_STRIPPED
        let info = parse(&g, 0x8664).unwrap();
        assert_eq!(load(&g, &info, &mut mem, 0x20_0000), Err(PeError::Malformed));
        // Still fine at the preferred base.
        assert_eq!(load(&g, &info, &mut mem, 0x1_4000_0000), Ok(()));
    }

    #[test]
    fn runtime_fixups_move_unmodified_sites() {
        let f = sample(0x1_4000_0000);
        let info = parse(&f, 0x8664).unwrap();
        let mut mem = std::vec![0u8; 0x3000];
        load(&f, &info, &mut mem, 0x20_0000).unwrap();
        assert_eq!(count_fixups(&mem, &info), Ok(1));
        let mut fx = [Fixup { rva: 0, reserved: 0, value: 0 }; 1];
        assert_eq!(collect_fixups(&mem, &info, &mut fx), Ok(1));
        assert_eq!(fx[0], Fixup { rva: 0x1008, reserved: 0, value: 0x20_0000 + 0x1234 });
        assert_eq!(collect_fixups(&mem, &info, &mut []), Err(PeError::BufferTooSmall));
        // An image shorter than size_of_image is an error, not a panic.
        assert_eq!(count_fixups(&mem[..0x1004], &info), Err(PeError::Malformed));
        assert_eq!(collect_fixups(&mem[..0x1004], &info, &mut fx), Err(PeError::Malformed));
        // Moved to virtual base 0xffff_8000_0000_0000 (delta wraps).
        let delta = 0xffff_8000_0000_0000u64.wrapping_sub(0x20_0000);
        let mut moved = mem.clone();
        rebase(&mut moved, &fx, delta);
        let v = u64::from_le_bytes(moved[0x1008..0x1010].try_into().unwrap());
        assert_eq!(v, 0xffff_8000_0000_0000 + 0x1234);
        // A site the driver converted itself is left as it is.
        let mut own = mem.clone();
        own[0x1008..0x1010].copy_from_slice(&0x1111u64.to_le_bytes());
        rebase(&mut own, &fx, delta);
        assert_eq!(u64::from_le_bytes(own[0x1008..0x1010].try_into().unwrap()), 0x1111);
        // A site beyond the image is ignored, not a panic.
        rebase(&mut moved, &[Fixup { rva: 0x2ffc, reserved: 0, value: 0 }], delta);
    }

    #[test]
    fn rejects_malformed() {
        let f = sample(0x1_4000_0000);
        assert_eq!(parse(&f, 0xAA64).unwrap_err(), PeError::Unsupported);
        assert!(parse(&f[..0x100], 0x8664).is_err()); // truncated
        let mut bad = f.clone();
        bad[0x58 + 56..0x58 + 60].copy_from_slice(&0u32.to_le_bytes()); // size_of_image 0
        assert_eq!(parse(&bad, 0x8664).unwrap_err(), PeError::Malformed);
        // Section pointing outside the file.
        let mut bad = f.clone();
        bad[0x148 + 20..0x148 + 24].copy_from_slice(&0xFFFF_FF00u32.to_le_bytes());
        let info = parse(&bad, 0x8664).unwrap();
        let mut mem = std::vec![0u8; 0x3000];
        assert_eq!(load(&bad, &info, &mut mem, 0x20_0000), Err(PeError::Malformed));
        // Reloc block overrunning the directory.
        let mut bad = f;
        bad[0x304..0x308].copy_from_slice(&0x1000u32.to_le_bytes());
        let info = parse(&bad, 0x8664).unwrap();
        assert_eq!(load(&bad, &info, &mut mem, 0x20_0000), Err(PeError::Malformed));
    }
}
