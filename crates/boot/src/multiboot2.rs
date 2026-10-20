//! Multiboot2 boot information.

use osmium_hal::display::{FramebufferInfo, PixelFormat};
use osmium_mm::{MemoryMap, PhysAddr, RegionKind};

use crate::{cstr, le32, le64};

/// Magic value a Multiboot2 loader leaves in EAX.
pub const BOOTLOADER_MAGIC: u32 = 0x36d7_6289;

const TAG_END: u32 = 0;
const TAG_CMDLINE: u32 = 1;
const TAG_LOADER_NAME: u32 = 2;
const TAG_MODULE: u32 = 3;
const TAG_MMAP: u32 = 6;
const TAG_FRAMEBUFFER: u32 = 8;
const TAG_RSDP_V1: u32 = 14;
const TAG_RSDP_V2: u32 = 15;

/// The information structure was malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidInfo;

/// A parsed Multiboot2 information structure.
#[derive(Clone, Copy, Debug)]
pub struct BootInfo<'a> {
    data: &'a [u8],
}

/// A raw tag.
#[derive(Clone, Copy, Debug)]
pub struct Tag<'a> {
    /// Tag type.
    pub typ: u32,
    /// Payload after the 8-byte tag header.
    pub payload: &'a [u8],
}

/// A boot module (initrd, configuration, ...).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module<'a> {
    /// First byte.
    pub start: PhysAddr,
    /// One past the last byte.
    pub end: PhysAddr,
    /// The module's command line.
    pub cmdline: &'a str,
}

/// Linear framebuffer description.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Framebuffer {
    /// Physical address.
    pub addr: PhysAddr,
    /// Bytes per row.
    pub pitch: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bits per pixel.
    pub bpp: u8,
    /// Framebuffer type: 0 indexed colour, 1 direct RGB, 2 EGA text.
    pub kind: u8,
    /// For direct RGB, the channel layout from the colour info.
    pub format: Option<PixelFormat>,
}

impl Framebuffer {
    /// Its geometry, for a direct RGB framebuffer.
    pub fn info(&self) -> Option<FramebufferInfo> {
        Some(FramebufferInfo { width: self.width, height: self.height, stride: self.pitch, format: self.format? })
    }
}

impl<'a> BootInfo<'a> {
    /// Parses the structure in `data`.
    pub fn new(data: &'a [u8]) -> Result<Self, InvalidInfo> {
        let total = le32(data, 0).ok_or(InvalidInfo)? as usize;
        if total < 16 || total > data.len() {
            return Err(InvalidInfo);
        }
        Ok(Self { data: &data[..total] })
    }

    /// Parses the structure at physical address `addr`, as passed in EBX.
    ///
    /// # Safety
    /// `ptr` must point at a valid structure that stays unmodified for `'a`.
    pub unsafe fn from_ptr(ptr: *const u8) -> Result<Self, InvalidInfo> {
        // SAFETY: the caller guarantees the header is readable.
        let total = unsafe { (ptr as *const u32).read_unaligned() } as usize;
        // SAFETY: the caller guarantees the whole structure is readable.
        Self::new(unsafe { core::slice::from_raw_parts(ptr, total) })
    }

    /// Size of the structure in bytes.
    pub fn total_size(&self) -> usize {
        self.data.len()
    }

    /// All tags, up to the end tag.
    pub fn tags(&self) -> impl Iterator<Item = Tag<'a>> + 'a + use<'a> {
        let data = self.data;
        let mut off = 8;
        core::iter::from_fn(move || {
            let typ = le32(data, off)?;
            let size = le32(data, off + 4)? as usize;
            if typ == TAG_END || size < 8 {
                return None;
            }
            let payload = data.get(off + 8..off + size)?;
            off = (off + size + 7) & !7;
            Some(Tag { typ, payload })
        })
    }

    fn tag(&self, typ: u32) -> Option<&'a [u8]> {
        self.tags().find(|t| t.typ == typ).map(|t| t.payload)
    }

    /// The kernel command line.
    pub fn cmdline(&self) -> Option<&'a str> {
        cstr(self.tag(TAG_CMDLINE)?)
    }

    /// The boot loader's name.
    pub fn loader_name(&self) -> Option<&'a str> {
        cstr(self.tag(TAG_LOADER_NAME)?)
    }

    /// Loaded modules.
    pub fn modules(&self) -> impl Iterator<Item = Module<'a>> + 'a + use<'a> {
        self.tags().filter(|t| t.typ == TAG_MODULE).filter_map(|t| {
            Some(Module {
                start: PhysAddr::new(le32(t.payload, 0)? as u64),
                end: PhysAddr::new(le32(t.payload, 4)? as u64),
                cmdline: cstr(t.payload.get(8..)?)?,
            })
        })
    }

    /// `(base, length, type)` of each memory-map entry. Type 1 is usable RAM.
    pub fn memory_map(&self) -> impl Iterator<Item = (u64, u64, u32)> + 'a + use<'a> {
        let payload = self.tag(TAG_MMAP).unwrap_or(&[]);
        let entry_size = le32(payload, 0).unwrap_or(24).max(1) as usize;
        payload.get(8..).unwrap_or(&[]).chunks_exact(entry_size).filter_map(|e| Some((le64(e, 0)?, le64(e, 8)?, le32(e, 16)?)))
    }

    /// Adds the memory map, the info structure itself (if `info_at` is given)
    /// and the modules to `map`.
    pub fn fill_memory_map<const N: usize>(
        &self,
        map: &mut MemoryMap<N>,
        info_at: Option<PhysAddr>,
    ) -> Result<(), osmium_mm::map::MapFull> {
        for (base, len, typ) in self.memory_map() {
            let kind = match typ {
                1 => RegionKind::Usable,
                3 => RegionKind::AcpiReclaimable,
                4 => RegionKind::AcpiNvs,
                5 => RegionKind::BadMemory,
                _ => RegionKind::Reserved,
            };
            map.add(PhysAddr::new(base), PhysAddr::new(base.saturating_add(len)), kind)?;
        }
        for m in self.modules() {
            map.reserve(m.start, m.end, RegionKind::Bootloader)?;
        }
        if let Some(at) = info_at {
            map.reserve(at, at + self.total_size() as u64, RegionKind::Bootloader)?;
        }
        Ok(())
    }

    /// The ACPI RSDP copied by the loader (v2 preferred).
    pub fn rsdp(&self) -> Option<&'a [u8]> {
        self.tag(TAG_RSDP_V2).or_else(|| self.tag(TAG_RSDP_V1))
    }

    /// The linear framebuffer, if the loader set one up.
    pub fn framebuffer(&self) -> Option<Framebuffer> {
        let p = self.tag(TAG_FRAMEBUFFER)?;
        Some(Framebuffer {
            addr: PhysAddr::new(le64(p, 0)?),
            pitch: le32(p, 8)?,
            width: le32(p, 12)?,
            height: le32(p, 16)?,
            bpp: *p.get(20)?,
            kind: *p.get(21)?,
            // Direct RGB colour info: position and size of red, green and
            // blue, a byte each.
            format: p.get(24..30).filter(|_| p[21] == 1).and_then(|c| {
                let mask = |pos: u8, size: u8| if size == 0 || size > 8 { 0 } else { ((1u32 << size) - 1) << pos };
                PixelFormat::from_masks(p[20], mask(c[0], c[1]), mask(c[2], c[3]), mask(c[4], c[5]))
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn tag(out: &mut Vec<u8>, typ: u32, payload: &[u8]) {
        out.extend_from_slice(&typ.to_le_bytes());
        out.extend_from_slice(&(8 + payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        while out.len() % 8 != 0 {
            out.push(0);
        }
    }

    #[test]
    fn parse_tags() {
        let mut b = std::vec![0u8; 8];
        tag(&mut b, TAG_CMDLINE, b"root=/dev/vda\0");
        let mut m = Vec::new();
        m.extend_from_slice(&0x20_0000u32.to_le_bytes());
        m.extend_from_slice(&0x30_0000u32.to_le_bytes());
        m.extend_from_slice(b"initrd\0");
        tag(&mut b, TAG_MODULE, &m);
        let mut mm = Vec::new();
        mm.extend_from_slice(&24u32.to_le_bytes());
        mm.extend_from_slice(&0u32.to_le_bytes());
        for (base, len, typ) in [(0u64, 0x9_fc00u64, 1u32), (0x10_0000, 0x7ef_0000, 1), (0xf_0000, 0x1_0000, 2)] {
            mm.extend_from_slice(&base.to_le_bytes());
            mm.extend_from_slice(&len.to_le_bytes());
            mm.extend_from_slice(&typ.to_le_bytes());
            mm.extend_from_slice(&0u32.to_le_bytes());
        }
        tag(&mut b, TAG_MMAP, &mm);
        tag(&mut b, TAG_END, &[]);
        let total = b.len() as u32;
        b[..4].copy_from_slice(&total.to_le_bytes());

        let info = BootInfo::new(&b).unwrap();
        assert_eq!(info.cmdline(), Some("root=/dev/vda"));
        assert_eq!(
            info.modules().collect::<Vec<_>>(),
            [Module { start: PhysAddr::new(0x20_0000), end: PhysAddr::new(0x30_0000), cmdline: "initrd" }]
        );
        assert_eq!(info.memory_map().count(), 3);
        let mut map = MemoryMap::<16>::new();
        info.fill_memory_map(&mut map, None).unwrap();
        assert_eq!(map.total(RegionKind::Usable), 0x9_fc00 + 0x7ef_0000 - 0x10_0000);
        assert_eq!(map.total(RegionKind::Bootloader), 0x10_0000);
        assert!(info.rsdp().is_none());
        assert!(info.framebuffer().is_none());

        // An 800x600 XRGB8888 framebuffer: address, pitch, width, height,
        // bpp, type 1 (RGB), reserved, then red 16/8, green 8/8, blue 0/8.
        let mut fb = Vec::new();
        fb.extend_from_slice(&0xfd00_0000u64.to_le_bytes());
        for v in [3200u32, 800, 600] {
            fb.extend_from_slice(&v.to_le_bytes());
        }
        fb.extend_from_slice(&[32, 1, 0, 0, 16, 8, 8, 8, 0, 8]);
        let mut b = std::vec![0u8; 8];
        tag(&mut b, TAG_FRAMEBUFFER, &fb);
        tag(&mut b, TAG_END, &[]);
        let total = b.len() as u32;
        b[..4].copy_from_slice(&total.to_le_bytes());
        let f = BootInfo::new(&b).unwrap().framebuffer().unwrap();
        assert_eq!((f.addr, f.kind, f.format), (PhysAddr::new(0xfd00_0000), 1, Some(PixelFormat::XRGB8888)));
        assert_eq!(f.info().map(|i| (i.width, i.height, i.stride)), Some((800, 600, 3200)));
        assert!(BootInfo::new(&b[..10]).is_err());
    }
}
