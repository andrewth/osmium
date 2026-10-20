//! ELF64 executables: enough to load a kernel, a guest or a user program.
//!
//! [`Elf::new`] validates the header; [`Elf::segments`] yields the
//! loadable segments with their file bytes, memory size and permissions.
//! The caller maps memory and copies [`Segment::data`], zero-filling up to
//! [`Segment::mem_size`].

use osmium_mm::paging::{MapError, MapFlags, PageSize, PageTable, PageTableFormat, TableAlloc};
use osmium_mm::{PAGE_SIZE, PhysAddr, VirtAddr};

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
pub struct Elf<'a> {
    data: &'a [u8],
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
pub struct Segment<'a> {
    /// Virtual address of the segment's first byte.
    pub vaddr: u64,
    /// Bytes to copy from the file.
    pub data: &'a [u8],
    /// Size in memory; bytes past `data.len()` are zero (`.bss`).
    pub mem_size: u64,
    /// Permissions.
    pub flags: SegmentFlags,
    /// Required alignment.
    pub align: u64,
}

const PT_LOAD: u32 = 1;

impl<'a> Elf<'a> {
    /// Validates `data` as a little-endian ELF64 executable.
    pub fn new(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.get(..4) != Some(b"\x7fELF") || data.get(4) != Some(&2) || data.get(5) != Some(&1) {
            return Err(ElfError::NotElf64);
        }
        let typ = u16::from_le_bytes([*data.get(16).ok_or(ElfError::Truncated)?, *data.get(17).ok_or(ElfError::Truncated)?]);
        if typ != 2 && typ != 3 {
            return Err(ElfError::NotExecutable);
        }
        let elf = Self { data };
        // Validate the program header table up front.
        let (off, size, n) = elf.ph_table()?;
        if size < 56 || off.checked_add(size * n).is_none_or(|end| end > data.len()) {
            return Err(ElfError::Truncated);
        }
        for s in elf.raw_segments() {
            s?;
        }
        Ok(elf)
    }

    fn u16_at(&self, off: usize) -> Option<u16> {
        Some(u16::from_le_bytes([*self.data.get(off)?, *self.data.get(off + 1)?]))
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

    fn raw_segments(&self) -> impl Iterator<Item = Result<Segment<'a>, ElfError>> + use<'a> {
        let data = self.data;
        let (off, size, n) = self.ph_table().unwrap_or((0, 0, 0));
        (0..n).filter_map(move |i| {
            let ph = off + i * size;
            if le32(data, ph)? != PT_LOAD {
                return None;
            }
            let seg = (|| {
                let flags = le32(data, ph + 4)?;
                let (offset, vaddr) = (le64(data, ph + 8)? as usize, le64(data, ph + 16)?);
                let (filesz, memsz, align) = (le64(data, ph + 32)? as usize, le64(data, ph + 40)?, le64(data, ph + 48)?);
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
    /// `MapFlags::USER`). Pages come from `alloc_frame`, are reached through
    /// `pt`'s allocator mapping, and are zeroed before the file data is
    /// copied in, so `.bss` reads as zero. Pages shared by two segments get
    /// both segments' permissions.
    ///
    /// Only absolute (non-PIE) images are supported; relocations are not
    /// applied. On error, pages mapped so far stay mapped; drop the table.
    pub fn load_into<F: PageTableFormat, A: TableAlloc>(
        &self,
        pt: &mut PageTable<F, A>,
        extra: MapFlags,
        mut alloc_frame: impl FnMut() -> Option<PhysAddr>,
    ) -> Result<(), MapError> {
        let page = PAGE_SIZE as u64;
        for seg in self.segments() {
            let mut flags = extra | MapFlags::READ;
            if seg.flags.write {
                flags = flags | MapFlags::WRITE;
            }
            if seg.flags.execute {
                flags = flags | MapFlags::EXEC;
            }
            let end = seg.vaddr.checked_add(seg.mem_size).ok_or(MapError::InvalidAddress)?;
            let mut va = seg.vaddr & !(page - 1);
            while va < end {
                let pa = match pt.translate(VirtAddr::new(va)) {
                    Some(t) => {
                        let _ = pt.protect(VirtAddr::new(va), t.flags | flags);
                        t.pa
                    }
                    None => {
                        let pa = alloc_frame().ok_or(MapError::OutOfMemory)?;
                        // SAFETY: a fresh frame from the caller, reachable
                        // through the table allocator's mapping.
                        unsafe { pt.allocator().phys_to_virt(pa).write_bytes(0, PAGE_SIZE) };
                        pt.map(VirtAddr::new(va), pa, PageSize::Size4K, flags)?.ignore();
                        pa
                    }
                };
                let (lo, hi) = (va.max(seg.vaddr), (va + page).min(seg.vaddr + seg.data.len() as u64));
                if lo < hi {
                    let src = &seg.data[(lo - seg.vaddr) as usize..(hi - seg.vaddr) as usize];
                    // SAFETY: the destination lies within the page's frame.
                    unsafe {
                        let dst = pt.allocator().phys_to_virt(pa + (lo - va));
                        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
                    }
                }
                va += page;
            }
        }
        Ok(())
    }

    /// The loadable segments, in file order.
    pub fn segments(&self) -> impl Iterator<Item = Segment<'a>> + use<'a> {
        // `new` validated every segment.
        self.raw_segments().filter_map(Result::ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        }
        let host = Host(RefCell::new(Vec::new()));
        let f = sample();
        let elf = Elf::new(&f).unwrap();
        let mut pt: PageTable<X86_64, &Host> = PageTable::new(&host).unwrap();
        elf.load_into(&mut pt, MapFlags::USER, || {
            let p = page();
            host.0.borrow_mut().push(p.0);
            Some(p)
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
