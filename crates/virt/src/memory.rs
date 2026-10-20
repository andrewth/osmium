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
    /// Returns false if it overlaps an existing region.
    ///
    /// # Safety
    /// The host memory must stay valid for the life of this object and must
    /// not be accessed as Rust references while the guest can reach it.
    pub unsafe fn add_region(&mut self, gpa: GuestPhysAddr, host: *mut u8, len: u64) -> bool {
        let end = gpa.0.saturating_add(len);
        if self.regions.iter().any(|r| gpa.0 < r.gpa.0 + r.len && r.gpa.0 < end) {
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
        let i = self.regions.partition_point(|r| r.gpa.0 + r.len <= gpa.0);
        self.regions.get(i).filter(|r| r.gpa <= gpa)
    }

    /// Copies guest memory at `gpa` into `buf`; the range may span regions.
    pub fn read(&self, gpa: GuestPhysAddr, buf: &mut [u8]) -> Result<(), OutOfBounds> {
        self.for_each_chunk(gpa, buf.len(), |host, done, n| {
            for i in 0..n {
                // SAFETY: `host..host+n` lies inside a region.
                buf[done + i] = unsafe { host.add(i).read_volatile() };
            }
        })
    }

    /// Copies `buf` into guest memory at `gpa`; the range may span regions.
    pub fn write(&self, gpa: GuestPhysAddr, buf: &[u8]) -> Result<(), OutOfBounds> {
        self.for_each_chunk(gpa, buf.len(), |host, done, n| {
            for i in 0..n {
                // SAFETY: `host..host+n` lies inside a region.
                unsafe { host.add(i).write_volatile(buf[done + i]) };
            }
        })
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
            let at = GuestPhysAddr(gpa.0 + done as u64);
            let r = self.region_of(at).ok_or(OutOfBounds(at))?;
            done += ((r.gpa.0 + r.len - at.0) as usize).min(len - done);
        }
        done = 0;
        while done < len {
            let at = GuestPhysAddr(gpa.0 + done as u64);
            let r = self.region_of(at).expect("validated above");
            let off = (at.0 - r.gpa.0) as usize;
            let n = (r.len as usize - off).min(len - done);
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
