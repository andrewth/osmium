//! ELF64 executables: enough to load a kernel, a guest or a user program.
//!
//! [`Elf::new`] validates the header; [`Elf::segments`] yields the
//! loadable segments with their file bytes, memory size and permissions.
//! The caller maps memory and copies [`Segment::data`], zero-filling up to
//! [`Segment::mem_size`].
//!
//! Position-independent images (`ET_DYN`) are loaded at a bias the caller
//! chooses ([`Elf::load_into_at`], [`Elf::segments_at`]); [`Elf::interp`]
//! names the program interpreter of a dynamically linked one, and
//! [`Elf::dynamic`] reads the relocation tables a loader has to apply. Every
//! field is untrusted: offsets, sizes and addresses are checked arithmetic.

use osmium_mm::frame::OwnedFrame;
use osmium_mm::paging::{MapError, MapFlags, PageTable, PageTableFormat, TableAlloc};
use osmium_mm::{PAGE_SIZE, VirtAddr};

use crate::{le32, le64};

/// Why a file is not a loadable ELF64 image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// Not ELF, or not 64-bit little-endian.
    NotElf64,
    /// Not an executable (`ET_EXEC`) or position-independent executable (`ET_DYN`).
    NotExecutable,
    /// A header or segment lies outside the file, or is inconsistent.
    Truncated,
}

/// A machine type (`e_machine`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Machine(pub u16);

impl Machine {
    /// x86_64.
    pub const X86_64: Self = Self(62);
    /// AArch64.
    pub const AARCH64: Self = Self(183);
    /// RISC-V.
    pub const RISCV: Self = Self(243);
}

/// A parsed ELF64 file.
#[derive(Clone, Copy, Debug)]
pub struct Elf<'src> {
    data: &'src [u8],
}

/// Segment permission flags (`p_flags`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentFlags {
    /// Readable.
    pub read: bool,
    /// Writable.
    pub write: bool,
    /// Executable.
    pub execute: bool,
}

/// A loadable (`PT_LOAD`) segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment<'src> {
    /// Virtual address of the segment's first byte.
    pub vaddr: u64,
    /// Bytes to copy from the file.
    pub data: &'src [u8],
    /// Size in memory; bytes past `data.len()` are zero (`.bss`).
    pub mem_size: u64,
    /// Permissions.
    pub flags: SegmentFlags,
    /// Required alignment.
    pub align: u64,
}

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;

/// Longest interpreter path accepted (Linux's `PATH_MAX`).
const INTERP_MAX: usize = 4096;
/// Most `PT_DYNAMIC` entries read.
const DYNAMIC_MAX: usize = 4096;

/// What the `PT_DYNAMIC` segment says about relocation, as virtual
/// addresses and sizes in the image (before any load bias).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dynamic {
    /// `DT_RELA`: address of the relocation table with addends.
    pub rela: u64,
    /// `DT_RELASZ`: its size in bytes.
    pub rela_size: u64,
    /// `DT_RELAENT`: the size of an entry (24 when absent).
    pub rela_ent: u64,
    /// `DT_JMPREL`: address of the PLT relocations, which are `Rela` when
    /// `DT_PLTREL` says so.
    pub jmprel: u64,
    /// `DT_PLTRELSZ`: their size in bytes.
    pub jmprel_size: u64,
    /// `DT_SYMTAB`: address of the symbol table.
    pub symtab: u64,
    /// `DT_SYMENT`: the size of a symbol (24 when absent).
    pub sym_ent: u64,
    /// Whether the image needs shared libraries (`DT_NEEDED`).
    pub needed: bool,
    /// Whether it has relocations without addends (`DT_REL`, or `DT_PLTREL`
    /// naming them), which this crate's users do not apply.
    pub rel: bool,
    /// Whether it uses packed relative relocations (`DT_RELR`), likewise.
    pub relr: bool,
}

impl<'src> Elf<'src> {
    /// Validates `data` as a little-endian ELF64 executable.
    pub fn new(data: &'src [u8]) -> Result<Self, ElfError> {
        if data.get(..4) != Some(b"\x7fELF") || data.get(4) != Some(&2) || data.get(5) != Some(&1) {
            return Err(ElfError::NotElf64);
        }
        let typ =
            u16::from_le_bytes([*data.get(16).ok_or(ElfError::Truncated)?, *data.get(17).ok_or(ElfError::Truncated)?]);
        if typ != 2 && typ != 3 {
            return Err(ElfError::NotExecutable);
        }
        let elf = Self { data };
        // Validate the program header table up front.
        let (off, size, n) = elf.ph_table()?;
        if size < 56 || size.checked_mul(n).and_then(|len| off.checked_add(len)).is_none_or(|end| end > data.len()) {
            return Err(ElfError::Truncated);
        }
        for s in elf.raw_segments() {
            s?;
        }
        Ok(elf)
    }

    fn u16_at(&self, off: usize) -> Option<u16> {
        Some(u16::from_le_bytes(*self.data.get(off..)?.first_chunk::<2>()?))
    }

    fn ph_table(&self) -> Result<(usize, usize, usize), ElfError> {
        let off = le64(self.data, 32).ok_or(ElfError::Truncated)? as usize;
        let size = self.u16_at(54).ok_or(ElfError::Truncated)? as usize;
        let n = self.u16_at(56).ok_or(ElfError::Truncated)? as usize;
        Ok((off, size, n))
    }

    /// The target machine.
    pub fn machine(&self) -> Machine {
        Machine(self.u16_at(18).unwrap_or(0))
    }

    /// The entry point.
    pub fn entry(&self) -> u64 {
        le64(self.data, 24).unwrap_or(0)
    }

    /// Returns true for a position-independent executable (`ET_DYN`), whose
    /// addresses are relative to a load base the loader chooses.
    pub fn is_pie(&self) -> bool {
        self.u16_at(16) == Some(3)
    }

    fn raw_segments(&self) -> impl Iterator<Item = Result<Segment<'src>, ElfError>> + use<'src> {
        let data = self.data;
        let (off, size, n) = self.ph_table().unwrap_or((0, 0, 0));
        (0..n).filter_map(move |i| {
            let ph = off.checked_add(i.checked_mul(size)?)?;
            if le32(data, ph)? != PT_LOAD {
                return None;
            }
            let seg = (|| {
                let flags = le32(data, ph + 4)?;
                let (offset, vaddr) = (le64(data, ph + 8)? as usize, le64(data, ph + 16)?);
                let (filesz, memsz, align) =
                    (le64(data, ph + 32)? as usize, le64(data, ph + 40)?, le64(data, ph + 48)?);
                if (filesz as u64) > memsz {
                    return None;
                }
                Some(Segment {
                    vaddr,
                    data: data.get(offset..offset.checked_add(filesz)?)?,
                    mem_size: memsz,
                    flags: SegmentFlags { read: flags & 4 != 0, write: flags & 2 != 0, execute: flags & 1 != 0 },
                    align,
                })
            })();
            Some(seg.ok_or(ElfError::Truncated))
        })
    }

    /// Maps and fills every loadable segment into `pt`, with each page's
    /// permissions taken from its segments (plus `extra`, e.g.
    /// `MapFlags::USER`). Pages come from `alloc_frame`, which hands over a
    /// reference to each frame; `pt` must own its leaves (see
    /// [`PageTable::new_owned`]). Frames are reached through `pt`'s allocator
    /// mapping, and are zeroed before the file data is
    /// copied in, so `.bss` reads as zero. Pages shared by two segments get
    /// both segments' permissions.
    ///
    /// Relocations are not applied. On error, pages mapped so far stay mapped; drop the table.
    ///
    /// Every page the image touches is mapped by this call: a page that is
    /// already mapped (other than by an earlier segment of this image) is
    /// [`MapError::AlreadyMapped`], and [`PageTable::map`] refuses the root
    /// entries a table shares with the kernel, so an image never writes
    /// memory it does not own.
    pub fn load_into<F: PageTableFormat, A: TableAlloc>(
        &self,
        pt: &mut PageTable<F, A>,
        extra: MapFlags,
        alloc_frame: impl FnMut() -> Option<OwnedFrame<A>>,
    ) -> Result<(), MapError> {
        self.load_into_at(pt, extra, 0, alloc_frame)
    }

    /// Like [`load_into`](Self::load_into), with `bias` added to every
    /// segment's address (for a position-independent image). The addresses
    /// must not overflow ([`MapError::InvalidAddress`]). Relocations are not
    /// applied: that is the caller's job, after the pages exist.
    pub fn load_into_at<F: PageTableFormat, A: TableAlloc>(
        &self,
        pt: &mut PageTable<F, A>,
        extra: MapFlags,
        bias: u64,
        mut alloc_frame: impl FnMut() -> Option<OwnedFrame<A>>,
    ) -> Result<(), MapError> {
        self.span_at(bias).ok_or(MapError::InvalidAddress)?;
        let page = PAGE_SIZE as u64;
        // The pages a segment covers; None if its end overflows.
        let pages = |s: &Segment<'_>| {
            let end = s.vaddr.checked_add(s.mem_size)?.checked_next_multiple_of(page)?;
            Some(s.vaddr & !(page - 1)..end)
        };
        for (i, seg) in self.segments_at(bias).enumerate() {
            let mut flags = extra | MapFlags::READ;
            if seg.flags.write {
                flags = flags | MapFlags::WRITE;
            }
            if seg.flags.execute {
                flags = flags | MapFlags::EXEC;
            }
            let span = pages(&seg).ok_or(MapError::InvalidAddress)?;
            // `new` checked filesz <= memsz, and `span` fits in a u64.
            let file_end = seg.vaddr.checked_add(seg.data.len() as u64).ok_or(MapError::InvalidAddress)?;
            for va in span.step_by(PAGE_SIZE) {
                let pa = match pt.translate(VirtAddr::new(va)) {
                    // A page this segment shares with an earlier one of this
                    // image, which this call mapped: add our permissions.
                    Some(t) if self.segments_at(bias).take(i).any(|s| pages(&s).is_some_and(|r| r.contains(&va))) => {
                        pt.protect(VirtAddr::new(va), t.flags | flags).map_err(|_| MapError::InvalidAddress)?.ignore();
                        t.pa
                    }
                    Some(_) => return Err(MapError::AlreadyMapped),
                    None => {
                        let frame = alloc_frame().ok_or(MapError::OutOfMemory)?;
                        let pa = frame.pa();
                        // SAFETY: a fresh frame from the caller, reachable
                        // through the table allocator's mapping.
                        unsafe { pt.allocator().phys_to_virt(pa).write_bytes(0, PAGE_SIZE) };
                        pt.map_owned(VirtAddr::new(va), frame, flags).map_err(|(e, _)| e)?.ignore();
                        pa
                    }
                };
                // `va` is below the page-aligned end of `span`, so this
                // cannot overflow.
                let (lo, hi) = (va.max(seg.vaddr), va.saturating_add(page).min(file_end));
                if lo < hi {
                    let src = seg
                        .data
                        .get((lo - seg.vaddr) as usize..(hi - seg.vaddr) as usize)
                        .ok_or(MapError::InvalidAddress)?;
                    // SAFETY: the destination lies within the page's frame,
                    // which this call mapped.
                    unsafe {
                        let dst = pt.allocator().phys_to_virt(pa + (lo - va));
                        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
                    }
                }
            }
        }
        Ok(())
    }

    /// The loadable segments as they appear when the image is loaded with
    /// `bias` added to every address. A segment whose address would overflow
    /// is left out; [`Elf::span_at`] reports that.
    pub fn segments_at(&self, bias: u64) -> impl Iterator<Item = Segment<'src>> + use<'src> {
        self.segments().filter_map(move |s| Some(Segment { vaddr: s.vaddr.checked_add(bias)?, ..s }))
    }

    /// The page-aligned addresses the non-empty segments cover when loaded
    /// at `bias`: from the first page of the lowest to the end of the
    /// highest, rounded up. `None` if any address overflows. An image with
    /// no memory yields `0..0`.
    pub fn span_at(&self, bias: u64) -> Option<core::ops::Range<u64>> {
        let page = PAGE_SIZE as u64;
        let (mut lo, mut hi) = (u64::MAX, 0u64);
        for s in self.segments().filter(|s| s.mem_size != 0) {
            let start = s.vaddr.checked_add(bias)?;
            lo = lo.min(start & !(page - 1));
            hi = hi.max(start.checked_add(s.mem_size)?.checked_next_multiple_of(page)?);
        }
        Some(if lo > hi { 0..0 } else { lo..hi })
    }

    /// The lowest page-aligned virtual address any non-empty segment starts
    /// at, before any bias (0 for a typical `ET_DYN`).
    pub fn lowest_address(&self) -> u64 {
        let lo = self.segments().filter(|s| s.mem_size != 0).map(|s| s.vaddr).min();
        lo.unwrap_or(0) & !(PAGE_SIZE as u64 - 1)
    }

    fn program_header(&self, kind: u32) -> Option<(usize, usize)> {
        let (off, size, n) = self.ph_table().ok()?;
        (0..n).find_map(|i| {
            let ph = off.checked_add(i.checked_mul(size)?)?;
            if le32(self.data, ph)? != kind {
                return None;
            }
            let offset = usize::try_from(le64(self.data, ph.checked_add(8)?)?).ok()?;
            let filesz = usize::try_from(le64(self.data, ph.checked_add(32)?)?).ok()?;
            Some((offset, filesz))
        })
    }

    /// The program interpreter's path (`PT_INTERP`) without its NUL, if the
    /// image names one. It must be non-empty, NUL-terminated, free of other
    /// NULs, at most 4096 bytes and inside the file.
    pub fn interp(&self) -> Result<Option<&'src [u8]>, ElfError> {
        let Some((offset, filesz)) = self.program_header(PT_INTERP) else { return Ok(None) };
        if !(2..=INTERP_MAX).contains(&filesz) {
            return Err(ElfError::Truncated);
        }
        let end = offset.checked_add(filesz).ok_or(ElfError::Truncated)?;
        let bytes = self.data.get(offset..end).ok_or(ElfError::Truncated)?;
        match bytes.split_last() {
            Some((0, path)) if !path.contains(&0) => Ok(Some(path)),
            _ => Err(ElfError::Truncated),
        }
    }

    /// The file bytes the loadable segments put at `vaddr..vaddr + len`
    /// (before any bias), if one segment's file data covers all of them.
    pub fn bytes_at(&self, vaddr: u64, len: u64) -> Option<&'src [u8]> {
        let end = vaddr.checked_add(len)?;
        self.segments().find_map(|s| {
            let seg_end = s.vaddr.checked_add(s.data.len() as u64)?;
            if vaddr < s.vaddr || end > seg_end {
                return None;
            }
            let from = usize::try_from(vaddr - s.vaddr).ok()?;
            s.data.get(from..from.checked_add(usize::try_from(len).ok()?)?)
        })
    }

    /// Reads the `PT_DYNAMIC` segment: where the relocation and symbol
    /// tables are. An image without one yields the empty [`Dynamic`].
    pub fn dynamic(&self) -> Result<Dynamic, ElfError> {
        let mut d = Dynamic { rela_ent: 24, sym_ent: 24, ..Dynamic::default() };
        let Some((offset, filesz)) = self.program_header(PT_DYNAMIC) else { return Ok(d) };
        let end = offset.checked_add(filesz).ok_or(ElfError::Truncated)?;
        let bytes = self.data.get(offset..end).ok_or(ElfError::Truncated)?;
        let mut pltrel = 0;
        for entry in bytes.as_chunks::<16>().0.iter().take(DYNAMIC_MAX) {
            let tag = le64(entry, 0).ok_or(ElfError::Truncated)?;
            let val = le64(entry, 8).ok_or(ElfError::Truncated)?;
            match tag {
                0 => break,
                1 => d.needed = true,
                2 => d.jmprel_size = val,
                5 => {}
                6 => d.symtab = val,
                7 => d.rela = val,
                8 => d.rela_size = val,
                9 => d.rela_ent = val,
                11 => d.sym_ent = val,
                17 | 18 => d.rel |= val != 0,
                20 => pltrel = val,
                23 => d.jmprel = val,
                35 | 36 => d.relr |= val != 0,
                _ => {}
            }
        }
        // DT_PLTREL: 17 is DT_REL, 7 is DT_RELA.
        if d.jmprel_size != 0 && pltrel == 17 {
            d.rel = true;
            d.jmprel_size = 0;
        }
        Ok(d)
    }

    /// The loadable segments, in file order.
    pub fn segments(&self) -> impl Iterator<Item = Segment<'src>> + use<'src> {
        // `new` validated every segment.
        self.raw_segments().filter_map(Result::ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osmium_mm::PhysAddr;
    use std::vec::Vec;

    /// A minimal ELF64 executable: one RX segment with 4 bytes of code and
    /// one RW segment with 2 bytes of data and 0x100 bytes of .bss.
    fn sample() -> Vec<u8> {
        let mut f = std::vec![0u8; 0x200];
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = 2; // 64-bit
        f[5] = 1; // little-endian
        f[6] = 1;
        f[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        f[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
        f[24..32].copy_from_slice(&0x40_1000u64.to_le_bytes()); // entry
        f[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
        f[52..54].copy_from_slice(&64u16.to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&2u16.to_le_bytes());
        let ph = |f: &mut Vec<u8>, at: usize, flags: u32, off: u64, va: u64, filesz: u64, memsz: u64| {
            f[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
            f[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
            f[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
            f[at + 16..at + 24].copy_from_slice(&va.to_le_bytes());
            f[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
            f[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
            f[at + 48..at + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        };
        ph(&mut f, 64, 5, 0x180, 0x40_1000, 4, 4);
        ph(&mut f, 120, 6, 0x184, 0x40_2000, 2, 0x102);
        f[0x180..0x184].copy_from_slice(&[0x90, 0x90, 0x0f, 0x05]);
        f[0x184..0x186].copy_from_slice(&[0xaa, 0xbb]);
        f
    }

    #[test]
    fn parses_segments() {
        let f = sample();
        let elf = Elf::new(&f).unwrap();
        assert_eq!((elf.machine(), elf.entry(), elf.is_pie()), (Machine::X86_64, 0x40_1000, false));
        let segs: Vec<_> = elf.segments().collect();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].data, [0x90, 0x90, 0x0f, 0x05]);
        assert_eq!(segs[0].flags, SegmentFlags { read: true, write: false, execute: true });
        assert_eq!((segs[1].vaddr, segs[1].data.len(), segs[1].mem_size), (0x40_2000, 2, 0x102));
        assert!(segs[1].flags.write && !segs[1].flags.execute);
    }

    #[test]
    fn loads_into_a_page_table() {
        use osmium_mm::paging::formats::X86_64;
        use osmium_mm::{PhysMapper, paging::TableAlloc};
        use std::alloc::{Layout, alloc_zeroed};
        use std::cell::RefCell;

        /// Host memory as "physical" memory: physical address = host address.
        struct Host(RefCell<Vec<u64>>);
        // SAFETY: host addresses are directly dereferenceable.
        unsafe impl PhysMapper for Host {
            fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
                pa.0 as *mut u8
            }
        }
        fn page() -> PhysAddr {
            // SAFETY: non-zero size; leaked for the test's duration.
            PhysAddr::new(unsafe { alloc_zeroed(Layout::from_size_align(4096, 4096).unwrap()) } as u64)
        }
        // SAFETY: fresh, exclusive, page-aligned host pages.
        unsafe impl TableAlloc for Host {
            fn alloc_table(&self) -> Option<PhysAddr> {
                Some(page())
            }
            unsafe fn free_table(&self, _: PhysAddr) {}
            fn claim_frame(&self, _: PhysAddr) -> bool {
                true
            }
        }
        let host = Host(RefCell::new(Vec::new()));
        let f = sample();
        let elf = Elf::new(&f).unwrap();
        let mut pt: PageTable<X86_64, &Host> = PageTable::new_owned(&host).unwrap();
        elf.load_into(&mut pt, MapFlags::USER, || {
            let p = page();
            host.0.borrow_mut().push(p.0);
            OwnedFrame::claim(&host, p)
        })
        .unwrap();
        assert_eq!(host.0.borrow().len(), 2, "one page per segment");
        let code = pt.translate(VirtAddr::new(0x40_1000)).unwrap();
        assert!(code.flags.contains(MapFlags::USER | MapFlags::EXEC) && !code.flags.contains(MapFlags::WRITE));
        // SAFETY: the translated host page.
        assert_eq!(unsafe { *(code.pa.0 as *const [u8; 4]) }, [0x90, 0x90, 0x0f, 0x05]);
        let data = pt.translate(VirtAddr::new(0x40_2000)).unwrap();
        assert!(data.flags.contains(MapFlags::WRITE) && !data.flags.contains(MapFlags::EXEC));
        // SAFETY: as above; bytes past the file data are zero (.bss).
        assert_eq!(unsafe { *(data.pa.0 as *const [u8; 4]) }, [0xaa, 0xbb, 0, 0]);

        // A page that is already mapped (here standing in for kernel memory
        // in a shared root entry) is refused, not written through.
        let victim = page();
        let mut pt: PageTable<X86_64, &Host> = PageTable::new_owned(&host).unwrap();
        let victim_frame = OwnedFrame::claim(&host, victim).unwrap();
        pt.map_owned(VirtAddr::new(0x40_2000), victim_frame, MapFlags::READ | MapFlags::WRITE).unwrap().ignore();
        assert_eq!(
            elf.load_into(&mut pt, MapFlags::USER, || OwnedFrame::claim(&host, page())),
            Err(MapError::AlreadyMapped)
        );
        // SAFETY: the host page mapped above.
        assert_eq!(unsafe { *(victim.0 as *const [u8; 2]) }, [0, 0], "nothing copied into it");

        // Two segments sharing a page: both permissions, both contents.
        let mut g = sample();
        g[120 + 16..120 + 24].copy_from_slice(&0x40_1800u64.to_le_bytes());
        let elf = Elf::new(&g).unwrap();
        let mut pt: PageTable<X86_64, &Host> = PageTable::new_owned(&host).unwrap();
        elf.load_into(&mut pt, MapFlags::USER, || OwnedFrame::claim(&host, page())).unwrap();
        let t = pt.translate(VirtAddr::new(0x40_1000)).unwrap();
        assert!(t.flags.contains(MapFlags::WRITE | MapFlags::EXEC));
        // SAFETY: the translated host page.
        let bytes = unsafe { &*(t.pa.0 as *const [u8; 0x802]) };
        assert_eq!((&bytes[..4], &bytes[0x800..]), (&[0x90, 0x90, 0x0f, 0x05][..], &[0xaa, 0xbb][..]));

        // A segment whose end overflows the address space.
        let mut g = sample();
        g[120 + 16..120 + 24].copy_from_slice(&0xffff_ffff_ffff_f000u64.to_le_bytes());
        let elf = Elf::new(&g).unwrap();
        let mut pt: PageTable<X86_64, &Host> = PageTable::new_owned(&host).unwrap();
        assert_eq!(
            elf.load_into(&mut pt, MapFlags::USER, || OwnedFrame::claim(&host, page())),
            Err(MapError::InvalidAddress)
        );
    }

    /// A PIE with `PT_INTERP` and `PT_DYNAMIC` for the bias and dynamic tests.
    fn pie() -> Vec<u8> {
        let mut f = sample();
        f[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        f[56..58].copy_from_slice(&4u16.to_le_bytes());
        // Segments at 0 and 0x2000.
        f[64 + 16..64 + 24].copy_from_slice(&0u64.to_le_bytes());
        f[120 + 16..120 + 24].copy_from_slice(&0x2000u64.to_le_bytes());
        // PT_INTERP: "/ld\0" at 0x190.
        f[0x190..0x194].copy_from_slice(b"/ld\0");
        let at = 176;
        f[at..at + 4].copy_from_slice(&3u32.to_le_bytes());
        f[at + 8..at + 16].copy_from_slice(&0x190u64.to_le_bytes());
        f[at + 32..at + 40].copy_from_slice(&4u64.to_le_bytes());
        // Dynamic entries at 0x1a0: RELA 0x180, RELASZ 24, NULL.
        for (i, (tag, val)) in [(7u64, 0x180u64), (8, 24), (0, 0)].into_iter().enumerate() {
            f[0x1a0 + i * 16..0x1a8 + i * 16].copy_from_slice(&tag.to_le_bytes());
            f[0x1a8 + i * 16..0x1b0 + i * 16].copy_from_slice(&val.to_le_bytes());
        }
        let at = 232;
        f[at..at + 4].copy_from_slice(&2u32.to_le_bytes());
        f[at + 8..at + 16].copy_from_slice(&0x1a0u64.to_le_bytes());
        f[at + 32..at + 40].copy_from_slice(&48u64.to_le_bytes());
        f
    }

    #[test]
    fn bias_interpreter_and_dynamic_section() {
        let f = pie();
        let elf = Elf::new(&f).unwrap();
        assert!(elf.is_pie());
        assert_eq!(elf.interp(), Ok(Some(&b"/ld"[..])));
        let d = elf.dynamic().unwrap();
        assert_eq!((d.rela, d.rela_size, d.rela_ent, d.needed), (0x180, 24, 24, false));
        assert_eq!(elf.bytes_at(0, 4), Some(&[0x90, 0x90, 0x0f, 0x05][..]));
        assert_eq!(elf.bytes_at(2, 4), None, "past the segment's file data");
        assert_eq!(elf.bytes_at(u64::MAX, 2), None);
        assert_eq!(elf.span_at(0x10_0000), Some(0x10_0000..0x10_3000));
        assert_eq!(elf.span_at(u64::MAX - 0xfff), None, "overflow");
        assert_eq!(elf.segments_at(0x10_0000).map(|s| s.vaddr).collect::<Vec<_>>(), [0x10_0000, 0x10_2000]);
        assert_eq!(elf.segments_at(u64::MAX - 0x1000).count(), 1, "the one that overflows is left out");
        assert_eq!(elf.lowest_address(), 0);
        // No interpreter or dynamic section in a plain executable.
        let g = sample();
        let plain = Elf::new(&g).unwrap();
        assert_eq!(
            (plain.interp(), plain.dynamic()),
            (Ok(None), Ok(Dynamic { rela_ent: 24, sym_ent: 24, ..Dynamic::default() }))
        );
        // Hostile interpreter paths.
        let mut h = pie();
        h[176 + 32..176 + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(Elf::new(&h).unwrap().interp(), Err(ElfError::Truncated));
        let mut h = pie();
        h[0x193] = b'x';
        assert_eq!(Elf::new(&h).unwrap().interp(), Err(ElfError::Truncated), "not terminated");
        let mut h = pie();
        h[176 + 8..176 + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(Elf::new(&h).unwrap().interp(), Err(ElfError::Truncated), "offset overflow");
        let mut h = pie();
        h[232 + 32..232 + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(Elf::new(&h).unwrap().dynamic(), Err(ElfError::Truncated));
    }

    #[test]
    fn loads_at_a_bias() {
        use osmium_mm::paging::formats::X86_64;
        use osmium_mm::{PhysMapper, paging::TableAlloc};
        use std::alloc::{Layout, alloc_zeroed};

        struct Host;
        // SAFETY: host addresses are directly dereferenceable.
        unsafe impl PhysMapper for Host {
            fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
                pa.0 as *mut u8
            }
        }
        fn page() -> PhysAddr {
            // SAFETY: non-zero size; leaked for the test's duration.
            PhysAddr::new(unsafe { alloc_zeroed(Layout::from_size_align(4096, 4096).unwrap()) } as u64)
        }
        // SAFETY: fresh, exclusive, page-aligned host pages.
        unsafe impl TableAlloc for Host {
            fn alloc_table(&self) -> Option<PhysAddr> {
                Some(page())
            }
            unsafe fn free_table(&self, _: PhysAddr) {}
            fn claim_frame(&self, _: PhysAddr) -> bool {
                true
            }
        }
        let f = pie();
        let elf = Elf::new(&f).unwrap();
        let mut pt: PageTable<X86_64, &Host> = PageTable::new_owned(&Host).unwrap();
        elf.load_into_at(&mut pt, MapFlags::USER, 0x10_0000, || OwnedFrame::claim(&Host, page())).unwrap();
        assert!(pt.translate(VirtAddr::new(0x10_0000)).is_some() && pt.translate(VirtAddr::new(0x10_2000)).is_some());
        assert!(pt.translate(VirtAddr::new(0x0)).is_none() && pt.translate(VirtAddr::new(0x2000)).is_none());
        let mut pt: PageTable<X86_64, &Host> = PageTable::new_owned(&Host).unwrap();
        assert_eq!(
            elf.load_into_at(&mut pt, MapFlags::USER, u64::MAX - 0xfff, || OwnedFrame::claim(&Host, page())),
            Err(MapError::InvalidAddress)
        );
    }

    #[test]
    fn rejects_bad_files() {
        let mut f = sample();
        assert_eq!(Elf::new(&f[..40]).err(), Some(ElfError::Truncated));
        f[0x40 + 32..0x40 + 40].copy_from_slice(&0x1000u64.to_le_bytes()); // filesz past EOF
        assert_eq!(Elf::new(&f).err(), Some(ElfError::Truncated));
        assert_eq!(Elf::new(b"\x7fELF\x01\x01").err(), Some(ElfError::NotElf64));
        let mut g = sample();
        g[16] = 1; // ET_REL
        assert_eq!(Elf::new(&g).err(), Some(ElfError::NotExecutable));
    }
}
