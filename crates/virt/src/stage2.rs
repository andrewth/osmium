//! Second-stage (guest-physical to host-physical) translation.

use osmium_mm::paging::formats::{Aarch64Stage2, Ept};
use osmium_mm::paging::{MapError, MapFlags, PageTable, TableAlloc};
use osmium_mm::{PAGE_SIZE, PhysAddr, VirtAddr};

use crate::memory::GuestMemory;

/// Intel EPT tables.
pub type EptTable<A> = PageTable<Ept, A>;

/// Arm stage-2 tables (48-bit IPA, starting at level 0).
pub type Stage2Table<A> = PageTable<Aarch64Stage2, A>;

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
    for r in mem.regions() {
        let len = r.len.next_multiple_of(PAGE_SIZE as u64);
        table.map_range(VirtAddr::new(r.gpa.0), host_to_phys(r.host), len, MapFlags::RW | MapFlags::EXEC)?;
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
    }
}
