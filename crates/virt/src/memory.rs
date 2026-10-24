//! Guest physical memory.

use alloc::vec::Vec;
use core::fmt;

/// A guest-physical address.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct GuestPhysAddr(pub u64);

impl fmt::Debug for GuestPhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GPA({:#x})", self.0)
    }
}

/// Plain data: every bit pattern is valid and the type has no padding, so
/// it can be copied to and from guest memory as bytes.
///
/// # Safety
/// Implementors must have no padding, no invalid bit patterns and no
/// pointers or references.
pub unsafe trait Pod: Copy + 'static {}

macro_rules! pod {
    ($($t:ty),*) => { $(
        // SAFETY: primitive integers are plain data.
        unsafe impl Pod for $t {}
    )* };
}
pod!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, usize, isize);
// SAFETY: arrays of plain data are plain data.
unsafe impl<T: Pod, const N: usize> Pod for [T; N] {}

/// A guest access fell outside guest memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutOfBounds(pub GuestPhysAddr);

/// One contiguous range of guest memory backed by host memory.
#[derive(Clone, Copy, Debug)]
pub struct GuestRegion {
    /// First guest-physical address.
    pub gpa: GuestPhysAddr,
    /// Length in bytes.
    pub len: u64,
    /// Host address of the first byte.
    pub host: *mut u8,
}

/// The guest's RAM layout.
#[derive(Default)]
pub struct GuestMemory {
    regions: Vec<GuestRegion>,
}

// SAFETY: the regions are plain memory owned by the VM; all access copies
// bytes with volatile operations, since the guest may change them at any time.
unsafe impl Send for GuestMemory {}
// SAFETY: as above.
unsafe impl Sync for GuestMemory {}

impl GuestMemory {
    /// Creates an empty layout.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `len` bytes of host memory at `host` as guest RAM at `gpa`.
    /// Returns false if it overlaps an existing region or wraps the
    /// address space.
    ///
    /// # Safety
    /// The host memory must stay valid for the life of this object and must
    /// not be accessed as Rust references while the guest can reach it.
    pub unsafe fn add_region(&mut self, gpa: GuestPhysAddr, host: *mut u8, len: u64) -> bool {
        let Some(end) = gpa.0.checked_add(len) else { return false };
        // Existing regions never wrap (checked here), so their ends cannot overflow.
        if self.regions.iter().any(|r| gpa.0 < r.gpa.0.saturating_add(r.len) && r.gpa.0 < end) {
            return false;
        }
        let at = self.regions.partition_point(|r| r.gpa < gpa);
        self.regions.insert(at, GuestRegion { gpa, len, host });
        true
    }

    /// The regions, in address order.
    pub fn regions(&self) -> &[GuestRegion] {
        &self.regions
    }

    /// Host pointer for `[gpa, gpa + len)` if the range lies in one region.
    pub fn host_ptr(&self, gpa: GuestPhysAddr, len: u64) -> Option<*mut u8> {
        let r = self.region_of(gpa)?;
        let off = gpa.0 - r.gpa.0;
        // SAFETY: `off` is inside the region (checked by `region_of`).
        (off.checked_add(len)? <= r.len).then(|| unsafe { r.host.add(off as usize) })
    }

    fn region_of(&self, gpa: GuestPhysAddr) -> Option<&GuestRegion> {
        let i = self.regions.partition_point(|r| r.gpa.0.saturating_add(r.len) <= gpa.0);
        self.regions.get(i).filter(|r| r.gpa <= gpa)
    }

    /// Copies guest memory at `gpa` into `buf`; the range may span regions.
    pub fn read(&self, gpa: GuestPhysAddr, buf: &mut [u8]) -> Result<(), OutOfBounds> {
        self.for_each_chunk(gpa, buf.len(), |host, done, n| {
            let end = done.saturating_add(n);
            for (i, d) in buf.get_mut(done..end).unwrap_or_default().iter_mut().enumerate() {
                // SAFETY: `host..host+n` lies inside a region.
                *d = unsafe { host.add(i).read_volatile() };
            }
        })
    }

    /// Copies `buf` into guest memory at `gpa`; the range may span regions.
    pub fn write(&self, gpa: GuestPhysAddr, buf: &[u8]) -> Result<(), OutOfBounds> {
        self.for_each_chunk(gpa, buf.len(), |host, done, n| {
            let end = done.saturating_add(n);
            for (i, &b) in buf.get(done..end).unwrap_or_default().iter().enumerate() {
                // SAFETY: `host..host+n` lies inside a region.
                unsafe { host.add(i).write_volatile(b) };
            }
        })
    }

    /// Copies the loadable segments of `elf`, a kernel linked where it runs
    /// (guest-physical = virtual addresses), into guest memory and zeroes
    /// the rest of each segment's memory size. Returns the guest-physical
    /// range the image now occupies. A segment that is not wholly inside
    /// guest memory (or wraps the address space) fails before it is
    /// written; segments before it stay loaded.
    pub fn load_elf(&self, elf: &osmium_boot::elf::Elf<'_>) -> Result<core::ops::Range<u64>, OutOfBounds> {
        let (mut low, mut high) = (u64::MAX, 0);
        for s in elf.segments() {
            let start = GuestPhysAddr(s.vaddr);
            let end = s.vaddr.checked_add(s.mem_size).ok_or(OutOfBounds(start))?;
            let filled = s.vaddr.checked_add(s.data.len() as u64).filter(|&f| f <= end).ok_or(OutOfBounds(start))?;
            // Check the whole segment before writing any of it.
            self.for_each_chunk(start, s.mem_size as usize, |_, _, _| {})?;
            self.write(start, s.data)?;
            // The rest is zeroes, a page at a time (the size is the image's
            // to choose, so it must not size a host allocation).
            let zeros = [0u8; 4096];
            let mut at = filled;
            while at < end {
                let n = (end - at).min(zeros.len() as u64) as usize;
                self.write(GuestPhysAddr(at), zeros.get(..n).unwrap_or_default())?;
                at += n as u64;
            }
            (low, high) = (low.min(s.vaddr), high.max(end));
        }
        Ok(if low > high { 0..0 } else { low..high })
    }

    /// Reads a `T` at `gpa`.
    pub fn read_obj<T: Pod>(&self, gpa: GuestPhysAddr) -> Result<T, OutOfBounds> {
        let mut v = core::mem::MaybeUninit::<T>::zeroed();
        // SAFETY: `T: Pod`, so its bytes may be written freely and any bytes are a valid `T`.
        let bytes = unsafe { core::slice::from_raw_parts_mut(v.as_mut_ptr().cast::<u8>(), size_of::<T>()) };
        self.read(gpa, bytes)?;
        // SAFETY: fully initialized above; every bit pattern is valid for `T`.
        Ok(unsafe { v.assume_init() })
    }

    /// Writes a `T` at `gpa`.
    pub fn write_obj<T: Pod>(&self, gpa: GuestPhysAddr, value: T) -> Result<(), OutOfBounds> {
        // SAFETY: `T: Pod` has no padding, so all its bytes are initialized.
        let bytes = unsafe { core::slice::from_raw_parts((&raw const value).cast::<u8>(), size_of::<T>()) };
        self.write(gpa, bytes)
    }

    fn for_each_chunk(
        &self,
        gpa: GuestPhysAddr,
        len: usize,
        mut f: impl FnMut(*mut u8, usize, usize),
    ) -> Result<(), OutOfBounds> {
        // Validate the whole range first, so a failed access has no effect.
        let mut done = 0usize;
        while done < len {
            let at = GuestPhysAddr(gpa.0.checked_add(done as u64).ok_or(OutOfBounds(gpa))?);
            let r = self.region_of(at).ok_or(OutOfBounds(at))?;
            let avail = usize::try_from(r.gpa.0.saturating_add(r.len).saturating_sub(at.0)).unwrap_or(usize::MAX);
            done += avail.min(len - done);
        }
        done = 0;
        while done < len {
            let at = GuestPhysAddr(gpa.0.wrapping_add(done as u64));
            let r = self.region_of(at).ok_or(OutOfBounds(at))?;
            let off = at.0.saturating_sub(r.gpa.0) as usize;
            let n = (r.len as usize).saturating_sub(off).min(len - done);
            // SAFETY: `off` is inside the region.
            f(unsafe { r.host.add(off) }, done, n);
            done += n;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_an_elf() {
        // A minimal ELF64 with one PT_LOAD: 4 bytes of data, 0x2000 in memory.
        let mut image = alloc::vec![0u8; 0x100];
        image[0..4].copy_from_slice(b"\x7fELF");
        image[4] = 2; // 64-bit
        image[5] = 1; // little-endian
        image[6] = 1;
        image[16] = 2; // ET_EXEC
        image[18..20].copy_from_slice(&0xf3u16.to_le_bytes()); // RISC-V
        image[20] = 1;
        image[24..32].copy_from_slice(&0x1000u64.to_le_bytes()); // entry
        image[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
        image[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
        image[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        image[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum
        let ph = 64;
        image[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        image[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // R X
        image[ph + 8..ph + 16].copy_from_slice(&0xf0u64.to_le_bytes()); // offset
        image[ph + 16..ph + 24].copy_from_slice(&0x1000u64.to_le_bytes()); // vaddr
        image[ph + 24..ph + 32].copy_from_slice(&0x1000u64.to_le_bytes()); // paddr
        image[ph + 32..ph + 40].copy_from_slice(&4u64.to_le_bytes()); // filesz
        image[ph + 40..ph + 48].copy_from_slice(&0x2000u64.to_le_bytes()); // memsz
        image[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // align
        image[0xf0..0xf4].copy_from_slice(b"code");
        let elf = osmium_boot::elf::Elf::new(&image).unwrap();

        let mut ram = alloc::vec![0xffu8; 0x4000];
        let mut mem = GuestMemory::new();
        // SAFETY: `ram` outlives `mem`.
        unsafe { mem.add_region(GuestPhysAddr(0), ram.as_mut_ptr(), 0x4000) };
        assert_eq!(mem.load_elf(&elf), Ok(0x1000..0x3000));
        let mut b = [0u8; 8];
        mem.read(GuestPhysAddr(0x1000), &mut b).unwrap();
        assert_eq!(&b, b"code\0\0\0\0", "data, then zeroes");
        assert_eq!(mem.read_obj::<u8>(GuestPhysAddr(0x2fff)), Ok(0));
        assert_eq!(mem.read_obj::<u8>(GuestPhysAddr(0x3000)), Ok(0xff), "nothing past the segment");

        // The same image in too little memory fails before writing it.
        let mut small = alloc::vec![0xffu8; 0x2000];
        let mut mem = GuestMemory::new();
        // SAFETY: `small` outlives `mem`.
        unsafe { mem.add_region(GuestPhysAddr(0), small.as_mut_ptr(), 0x2000) };
        assert!(mem.load_elf(&elf).is_err());
        assert_eq!(mem.read_obj::<u8>(GuestPhysAddr(0x1000)), Ok(0xff));
    }

    #[test]
    fn spanning_and_bounds() {
        let mut low = [0u8; 0x1000];
        let mut high = [0u8; 0x1000];
        let mut mem = GuestMemory::new();
        // SAFETY: the arrays outlive `mem` and are only accessed through it until the end.
        unsafe {
            assert!(mem.add_region(GuestPhysAddr(0x1000), high.as_mut_ptr(), 0x1000));
            assert!(mem.add_region(GuestPhysAddr(0), low.as_mut_ptr(), 0x1000));
            assert!(!mem.add_region(GuestPhysAddr(0x800), low.as_mut_ptr(), 0x1000), "overlap");
        }
        mem.write_obj(GuestPhysAddr(0xffc), 0x1122_3344_5566_7788u64).unwrap();
        assert_eq!(mem.read_obj::<u64>(GuestPhysAddr(0xffc)), Ok(0x1122_3344_5566_7788));
        assert_eq!(mem.read_obj::<u32>(GuestPhysAddr(0x1000)), Ok(0x1122_3344));
        assert_eq!(mem.write_obj(GuestPhysAddr(0x1ffe), 0u32), Err(OutOfBounds(GuestPhysAddr(0x2000))));
        assert_eq!(mem.read_obj::<u16>(GuestPhysAddr(0x1ffe)), Ok(0), "failed write had no effect");
        assert!(mem.host_ptr(GuestPhysAddr(0xff0), 0x20).is_none(), "spans regions");
        assert!(mem.host_ptr(GuestPhysAddr(0x1ff0), 0x10).is_some());
        drop(mem);
        assert_eq!(low[0xffc..], [0x88, 0x77, 0x66, 0x55]);
        assert_eq!(high[..4], [0x44, 0x33, 0x22, 0x11]);
    }
}
