//! Second-stage (guest-physical to host-physical) translation.

use osmium_mm::paging::formats::{Aarch64Stage2, Ept, Sv39x4, Sv48x4};
use osmium_mm::paging::{MapError, MapFlags, PageTable, TableAlloc};
use osmium_mm::{PAGE_SIZE, PhysAddr, VirtAddr};

use crate::memory::GuestMemory;

/// Intel EPT tables.
pub type EptTable<A> = PageTable<Ept, A>;

/// Arm stage-2 tables (48-bit IPA, starting at level 0).
pub type Stage2Table<A> = PageTable<Aarch64Stage2, A>;

/// RISC-V G-stage tables, Sv39x4 (41-bit guest-physical addresses).
pub type GStageTable<A> = PageTable<Sv39x4, A>;

/// RISC-V G-stage tables, Sv48x4 (50-bit guest-physical addresses).
pub type GStage48Table<A> = PageTable<Sv48x4, A>;

/// An encoded `hgatp` register: translation mode, VMID and G-stage root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hgatp(pub u64);

/// Encodes `hgatp` for an Sv39x4 G-stage table rooted at `root` (16 KiB
/// aligned) with `vmid` (up to 14 bits).
pub const fn hgatp_sv39x4(root: PhysAddr, vmid: u16) -> Hgatp {
    Hgatp(8 << 60 | ((vmid as u64) & 0x3fff) << 44 | root.0 >> 12)
}

/// Encodes `hgatp` for an Sv48x4 G-stage table.
pub const fn hgatp_sv48x4(root: PhysAddr, vmid: u16) -> Hgatp {
    Hgatp(9 << 60 | ((vmid as u64) & 0x3fff) << 44 | root.0 >> 12)
}

/// Encodes the VMCS EPT pointer for a 4-level, write-back EPT rooted at `root`.
pub const fn eptp(root: PhysAddr) -> u64 {
    root.0 | (3 << 3) | 6
}

/// Encodes `VTTBR_EL2` for a stage-2 table rooted at `root` with `vmid`.
pub const fn vttbr(root: PhysAddr, vmid: u16) -> u64 {
    root.0 | (vmid as u64) << 48
}

/// Maps every region of `mem` into a stage-2 table as read/write/execute
/// RAM. `host_to_phys` converts a region's host pointer to its host-physical
/// address; regions must be physically contiguous and page aligned.
pub fn map_guest_memory<F, A>(
    table: &mut PageTable<F, A>,
    mem: &GuestMemory,
    host_to_phys: impl Fn(*mut u8) -> PhysAddr,
) -> Result<(), MapError>
where
    F: osmium_mm::paging::PageTableFormat,
    A: TableAlloc,
{
    // Whole pages only: rounding a region up would hand the guest the host
    // memory that follows it.
    let page = PAGE_SIZE as u64;
    for r in mem.regions() {
        let pa = host_to_phys(r.host);
        if !r.gpa.0.is_multiple_of(page) || !pa.0.is_multiple_of(page) || !r.len.is_multiple_of(page) {
            return Err(MapError::Misaligned);
        }
        table.map_range(VirtAddr::new(r.gpa.0), pa, r.len, MapFlags::RW | MapFlags::EXEC)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::GuestPhysAddr;
    use osmium_mm::PhysMapper;
    use std::alloc::{Layout, alloc, dealloc};

    /// Table frames from the host heap; "physical" = host address.
    struct HostFrames;

    // SAFETY: host addresses are directly dereferenceable.
    unsafe impl PhysMapper for HostFrames {
        fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
            pa.as_usize() as *mut u8
        }
    }

    // SAFETY: frames are fresh, exclusive, page-aligned host allocations.
    unsafe impl TableAlloc for HostFrames {
        fn alloc_table(&self) -> Option<PhysAddr> {
            // SAFETY: non-zero size.
            let p = unsafe { alloc(Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap()) };
            (!p.is_null()).then(|| PhysAddr::new(p as u64))
        }
        unsafe fn free_table(&self, pa: PhysAddr) {
            // SAFETY: allocated in `alloc_table` with this layout.
            unsafe { dealloc(pa.as_usize() as *mut u8, Layout::from_size_align(PAGE_SIZE, PAGE_SIZE).unwrap()) }
        }
    }

    #[test]
    fn guest_memory_into_ept_and_stage2() {
        let mut mem = GuestMemory::new();
        // Pretend host-physical addresses; nothing is dereferenced.
        // SAFETY: the guest memory is never accessed in this test.
        unsafe {
            mem.add_region(GuestPhysAddr(0), 0x1_0000_0000 as *mut u8, 0x20_0000);
            mem.add_region(GuestPhysAddr(0x4000_0000), 0x2_0000_0000 as *mut u8, 0x3000);
        }
        let mut ept: EptTable<_> = PageTable::new(HostFrames).unwrap();
        map_guest_memory(&mut ept, &mem, |p| PhysAddr::new(p as u64)).unwrap();
        let t = ept.translate(VirtAddr::new(0x1234)).unwrap();
        assert_eq!(t.pa, PhysAddr::new(0x1_0000_1234));
        assert_eq!(t.size, osmium_mm::PageSize::Size2M);
        assert_eq!(ept.translate(VirtAddr::new(0x4000_2010)).unwrap().pa, PhysAddr::new(0x2_0000_2010));
        assert!(ept.translate(VirtAddr::new(0x4000_3000)).is_none());
        assert_eq!(eptp(ept.root()) & 0xfff, 0x1e);

        let mut s2: Stage2Table<_> = PageTable::new(HostFrames).unwrap();
        map_guest_memory(&mut s2, &mem, |p| PhysAddr::new(p as u64)).unwrap();
        assert!(s2.translate(VirtAddr::new(0x4000_0000)).unwrap().flags.contains(MapFlags::RW | MapFlags::EXEC));
        assert_eq!(vttbr(PhysAddr::new(0x8000_0000), 5), 0x0005_0000_8000_0000);
        assert_eq!(hgatp_sv39x4(PhysAddr::new(0x8020_4000), 3), Hgatp(0x8000_3000_0008_0204));
    }

    #[test]
    fn guest_memory_into_gstage() {
        let mut mem = GuestMemory::new();
        // SAFETY: the guest memory is never accessed in this test.
        unsafe { mem.add_region(GuestPhysAddr(0x8000_0000), 0x1_0000_0000 as *mut u8, 0x40_0000) };
        let mut g: GStageTable<_> = PageTable::new(RootFrames).unwrap();
        assert_eq!(g.root().0 % 0x4000, 0, "16 KiB-aligned root");
        map_guest_memory(&mut g, &mem, |p| PhysAddr::new(p as u64)).unwrap();
        assert_eq!(g.translate(VirtAddr::new(0x8012_3456)).unwrap().pa, PhysAddr::new(0x1_0012_3456));
        // Above the 39-bit range a plain Sv39 table would cover.
        g.map(VirtAddr::new(0x180_0000_0000), PhysAddr::new(0x5000), osmium_mm::PageSize::Size4K, MapFlags::READ)
            .unwrap()
            .ignore();
        assert_eq!(g.translate(VirtAddr::new(0x180_0000_0010)).unwrap().pa, PhysAddr::new(0x5010));
    }

    /// Like `HostFrames`, but also hands out 16 KiB-aligned roots.
    struct RootFrames;

    // SAFETY: as for `HostFrames`.
    unsafe impl PhysMapper for RootFrames {
        fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
            pa.as_usize() as *mut u8
        }
    }

    // SAFETY: fresh, exclusive host allocations of the requested size and alignment.
    unsafe impl TableAlloc for RootFrames {
        fn alloc_table(&self) -> Option<PhysAddr> {
            self.alloc_root(1)
        }
        unsafe fn free_table(&self, pa: PhysAddr) {
            // SAFETY: forwarded.
            unsafe { self.free_root(pa, 1) }
        }
        fn alloc_root(&self, pages: usize) -> Option<PhysAddr> {
            let l = Layout::from_size_align(PAGE_SIZE * pages, PAGE_SIZE * pages).unwrap();
            // SAFETY: non-zero size.
            let p = unsafe { alloc(l) };
            (!p.is_null()).then(|| PhysAddr::new(p as u64))
        }
        unsafe fn free_root(&self, pa: PhysAddr, pages: usize) {
            let l = Layout::from_size_align(PAGE_SIZE * pages, PAGE_SIZE * pages).unwrap();
            // SAFETY: allocated in `alloc_root` with this layout.
            unsafe { dealloc(pa.as_usize() as *mut u8, l) }
        }
    }
}
