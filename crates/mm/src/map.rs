//! Boot-time physical memory accounting.

use crate::addr::{PAGE_SIZE, PhysAddr};

/// What a physical range is used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegionKind {
    /// Free RAM.
    Usable,
    /// Firmware-reserved or otherwise unusable.
    Reserved,
    /// ACPI tables; usable once parsed.
    AcpiReclaimable,
    /// ACPI non-volatile storage.
    AcpiNvs,
    /// Defective RAM.
    BadMemory,
    /// Device registers.
    Mmio,
    /// The loaded kernel or firmware image.
    Kernel,
    /// Boot loader data, modules, initrd or the device tree.
    Bootloader,
    /// Owned by an allocator or another subsystem.
    Allocated,
}

/// A half-open physical range `[start, end)` and its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    /// First byte.
    pub start: PhysAddr,
    /// One past the last byte.
    pub end: PhysAddr,
    /// What the range holds.
    pub kind: RegionKind,
}

impl Region {
    /// Creates a region.
    pub const fn new(start: PhysAddr, end: PhysAddr, kind: RegionKind) -> Self {
        Self { start, end, kind }
    }

    /// Size in bytes.
    pub const fn len(&self) -> u64 {
        self.end.0 - self.start.0
    }

    /// Returns true if the region is empty.
    pub const fn is_empty(&self) -> bool {
        self.end.0 <= self.start.0
    }
}

/// The map has no room for another region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapFull;

/// A sorted list of non-overlapping regions with a fixed capacity `N`.
///
/// Used before any allocator exists, which is why it needs no heap. Adding
/// usable RAM never overrides an existing region, while [`MemoryMap::reserve`]
/// always does, so the order in which firmware entries and reservations are
/// added does not matter.
#[derive(Clone)]
pub struct MemoryMap<const N: usize> {
    regions: [Region; N],
    len: usize,
}

impl<const N: usize> MemoryMap<N> {
    /// Creates an empty map.
    pub const fn new() -> Self {
        Self { regions: [Region::new(PhysAddr::ZERO, PhysAddr::ZERO, RegionKind::Reserved); N], len: 0 }
    }

    /// Returns the regions in address order.
    pub fn regions(&self) -> &[Region] {
        &self.regions[..self.len]
    }

    /// Iterates over usable regions.
    pub fn usable(&self) -> impl Iterator<Item = &Region> {
        self.regions().iter().filter(|r| r.kind == RegionKind::Usable)
    }

    /// Total bytes of the given kind.
    pub fn total(&self, kind: RegionKind) -> u64 {
        self.regions().iter().filter(|r| r.kind == kind).map(Region::len).sum()
    }

    /// Adds a firmware-reported range. Usable RAM only fills gaps; any other
    /// kind overrides what is there.
    pub fn add(&mut self, start: PhysAddr, end: PhysAddr, kind: RegionKind) -> Result<(), MapFull> {
        if kind != RegionKind::Usable {
            return self.reserve(start, end, kind);
        }
        let mut cursor = start;
        while cursor < end {
            // The first region that ends after the cursor.
            let next = self.regions().iter().find(|r| r.end > cursor).copied();
            match next {
                Some(r) if r.start <= cursor => cursor = r.end,
                Some(r) => {
                    let gap_end = if r.start < end { r.start } else { end };
                    self.set(cursor, gap_end, kind)?;
                    cursor = gap_end;
                }
                None => {
                    self.set(cursor, end, kind)?;
                    cursor = end;
                }
            }
        }
        Ok(())
    }

    /// Marks `[start, end)` as `kind`, overriding anything there.
    pub fn reserve(&mut self, start: PhysAddr, end: PhysAddr, kind: RegionKind) -> Result<(), MapFull> {
        self.set(start, end, kind)
    }

    /// Shrinks each usable region inward to page boundaries and drops those
    /// that become empty.
    pub fn page_align_usable(&mut self) {
        let mut i = 0;
        while i < self.len {
            let r = &mut self.regions[i];
            if r.kind == RegionKind::Usable {
                r.start = r.start.align_up(PAGE_SIZE as u64);
                r.end = r.end.align_down(PAGE_SIZE as u64);
                if r.is_empty() {
                    self.remove(i);
                    continue;
                }
            }
            i += 1;
        }
    }

    /// Finds the lowest usable, `align`-aligned range of `size` bytes, marks
    /// it [`RegionKind::Allocated`] and returns its start. For allocating
    /// early boot structures before a real allocator exists.
    pub fn allocate(&mut self, size: u64, align: u64) -> Option<PhysAddr> {
        let start = self.usable().find_map(|r| {
            let s = r.start.align_up(align);
            (s.0.checked_add(size)? <= r.end.0).then_some(s)
        })?;
        self.reserve(start, start + size, RegionKind::Allocated).ok()?;
        Some(start)
    }

    fn set(&mut self, start: PhysAddr, end: PhysAddr, kind: RegionKind) -> Result<(), MapFull> {
        if start >= end {
            return Ok(());
        }
        // Build into a scratch array so that running out of room leaves the
        // map unchanged.
        let mut out = [Region::new(PhysAddr::ZERO, PhysAddr::ZERO, kind); N];
        let mut n = 0;
        let mut push = |r: Region, out: &mut [Region; N]| -> Result<(), MapFull> {
            if r.is_empty() {
                return Ok(());
            }
            if n > 0 && out[n - 1].kind == r.kind && out[n - 1].end == r.start {
                out[n - 1].end = r.end;
                return Ok(());
            }
            if n == N {
                return Err(MapFull);
            }
            out[n] = r;
            n += 1;
            Ok(())
        };
        let mut inserted = false;
        for r in self.regions() {
            if r.end <= start || (inserted && r.start >= end) {
                push(*r, &mut out)?;
                continue;
            }
            // `r` overlaps [start, end): keep the parts outside it.
            push(Region::new(r.start, start.min(r.end), r.kind), &mut out)?;
            if !inserted {
                push(Region::new(start, end, kind), &mut out)?;
                inserted = true;
            }
            push(Region::new(end.max(r.start), r.end, r.kind), &mut out)?;
        }
        if !inserted {
            push(Region::new(start, end, kind), &mut out)?;
        }
        self.regions = out;
        self.len = n;
        Ok(())
    }

    fn remove(&mut self, i: usize) {
        self.regions.copy_within(i + 1..self.len, i);
        self.len -= 1;
    }
}

impl<const N: usize> Default for MemoryMap<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> core::fmt::Debug for MemoryMap<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.regions()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use RegionKind::*;

    fn pa(x: u64) -> PhysAddr {
        PhysAddr::new(x)
    }

    #[test]
    fn reserve_splits_and_merges() {
        let mut m = MemoryMap::<8>::new();
        m.add(pa(0x1000), pa(0x10000), Usable).unwrap();
        m.reserve(pa(0x4000), pa(0x6000), Kernel).unwrap();
        assert_eq!(
            m.regions(),
            [
                Region::new(pa(0x1000), pa(0x4000), Usable),
                Region::new(pa(0x4000), pa(0x6000), Kernel),
                Region::new(pa(0x6000), pa(0x10000), Usable),
            ]
        );
        m.reserve(pa(0x4000), pa(0x6000), Usable).unwrap();
        assert_eq!(m.regions(), [Region::new(pa(0x1000), pa(0x10000), Usable)]);
    }

    #[test]
    fn usable_does_not_override() {
        let mut m = MemoryMap::<8>::new();
        m.add(pa(0x3000), pa(0x4000), Reserved).unwrap();
        m.add(pa(0x0), pa(0x8000), Usable).unwrap();
        assert_eq!(m.total(Usable), 0x7000);
        assert_eq!(m.total(Reserved), 0x1000);
        assert_eq!(m.regions().len(), 3);
    }

    #[test]
    fn page_align_and_allocate() {
        let mut m = MemoryMap::<8>::new();
        m.add(pa(0x0800), pa(0x1800), Usable).unwrap();
        m.add(pa(0x10_0123), pa(0x20_0000), Usable).unwrap();
        m.page_align_usable();
        assert_eq!(m.regions(), [Region::new(pa(0x10_1000), pa(0x20_0000), Usable)]);
        let a = m.allocate(0x2000, 0x1_0000).unwrap();
        assert_eq!(a, pa(0x11_0000));
        assert_eq!(m.total(Allocated), 0x2000);
    }

    #[test]
    fn full_map_reports_error() {
        let mut m = MemoryMap::<2>::new();
        m.add(pa(0), pa(0x1000), Usable).unwrap();
        m.add(pa(0x2000), pa(0x3000), Reserved).unwrap();
        assert_eq!(m.add(pa(0x5000), pa(0x6000), Kernel), Err(MapFull));
        assert_eq!(m.regions().len(), 2);
    }
}
