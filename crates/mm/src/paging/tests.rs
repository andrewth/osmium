use super::formats::*;
use super::*;
use crate::frame::testmem::SimRam;
use crate::frame::{BuddyAllocator, FrameAllocator, LockedFrames};

type Frames<'a> = LockedFrames<BuddyAllocator<&'a SimRam>, &'a SimRam>;

fn frames(ram: &SimRam) -> Frames<'_> {
    let mut b = BuddyAllocator::new(ram);
    // SAFETY: simulated RAM owned by the test.
    unsafe {
        b.add_region(ram.base, ram.end());
        LockedFrames::new(b, ram)
    }
}

fn va(x: u64) -> VirtAddr {
    VirtAddr::new(x)
}
fn pa(x: u64) -> PhysAddr {
    PhysAddr::new(x)
}

fn exercise<F: PageTableFormat>(high_va: u64) {
    let ram = SimRam::new(0x8000_0000, 2 << 20);
    let frames = frames(&ram);
    let before = frames.lock().free_frames();
    {
        let mut pt: PageTable<F, _> = PageTable::new(&frames).unwrap();

        // 4 KiB mapping, translate with offset, protect, unmap.
        pt.map(va(0x40_0000), pa(0x1234_5000), PageSize::Size4K, MapFlags::RW).unwrap().ignore();
        let t = pt.translate(va(0x40_0abc)).unwrap();
        assert_eq!(t.pa, pa(0x1234_5abc));
        assert_eq!(t.size, PageSize::Size4K);
        assert!(t.flags.contains(MapFlags::RW));
        assert!(!t.flags.contains(MapFlags::EXEC));
        // A leaf must grant some access: RISC-V would read V-only as a
        // table pointer. protect() can't drop to no access either.
        for size in [PageSize::Size4K, PageSize::Size2M] {
            let f = MapFlags::USER | MapFlags::GLOBAL;
            assert_eq!(pt.map(va(0x60_0000), pa(0x20_0000), size, f).err(), Some(MapError::NoAccess));
        }
        assert!(pt.translate(va(0x60_0000)).is_none());
        assert_eq!(pt.protect(va(0x40_0000), MapFlags::USER).err(), Some(UnmapError::NoAccess));
        assert_eq!(pt.unmap(va(0x60_0000)).err(), Some(UnmapError::NotMapped));
        assert_eq!(
            pt.map(va(0x40_0000), pa(0x1000), PageSize::Size4K, MapFlags::READ).err(),
            Some(MapError::AlreadyMapped)
        );
        pt.protect(va(0x40_0000), MapFlags::RX).unwrap().ignore();
        let t = pt.translate(va(0x40_0000)).unwrap();
        assert!(t.flags.contains(MapFlags::RX) && !t.flags.contains(MapFlags::WRITE));
        let (t, _flush) = pt.unmap(va(0x40_0000)).map(|(t, f)| (t, f.ignore())).unwrap();
        assert_eq!(t.pa, pa(0x1234_5000));
        assert!(pt.translate(va(0x40_0000)).is_none());
        assert_eq!(pt.unmap(va(0x40_0000)).err(), Some(UnmapError::NotMapped));

        // 2 MiB mapping blocks 4 KiB mappings underneath it.
        pt.map(va(0x20_0000), pa(0x4000_0000), PageSize::Size2M, MapFlags::RW).unwrap().ignore();
        assert_eq!(pt.translate(va(0x21_2345)).unwrap().pa, pa(0x4001_2345));
        assert_eq!(
            pt.map(va(0x20_1000), pa(0x1000), PageSize::Size4K, MapFlags::RW).err(),
            Some(MapError::HugePageConflict)
        );
        assert_eq!(
            pt.map(va(0x30_1000), pa(0x1000), PageSize::Size2M, MapFlags::RW).err(),
            Some(MapError::Misaligned)
        );

        // Upper-half (or highest) addresses, and out-of-range ones.
        pt.map(va(high_va), pa(0x9000), PageSize::Size4K, MapFlags::READ | MapFlags::GLOBAL).unwrap().ignore();
        assert_eq!(pt.translate(va(high_va + 8)).unwrap().pa, pa(0x9008));
        assert_eq!(
            pt.map(va(1 << (F::VA_BITS + 1)), pa(0), PageSize::Size4K, MapFlags::READ).err(),
            Some(MapError::InvalidAddress)
        );

        // map_range uses huge pages where it can.
        pt.map_range(va(0x4000_0000), pa(0x8000_0000), (1 << 30) + (2 << 20) + 0x3000, MapFlags::RW).unwrap();
        assert_eq!(pt.translate(va(0x4000_0000)).unwrap().size, PageSize::Size1G);
        assert_eq!(pt.translate(va(0x8000_0000)).unwrap().size, PageSize::Size2M);
        assert_eq!(pt.translate(va(0x8020_2000)).unwrap().size, PageSize::Size4K);
        assert_eq!(pt.translate(va(0x8020_2000)).unwrap().pa, pa(0xc020_2000));

        // Punch a 4 KiB hole into the 1 GiB page: two splits.
        let (t, f) = pt.unmap_4k(va(0x4123_4567)).unwrap();
        f.ignore();
        assert_eq!((t.pa, t.size), (pa(0x8123_4000), PageSize::Size4K));
        assert!(pt.translate(va(0x4123_4000)).is_none());
        let around = pt.translate(va(0x4123_5008)).unwrap();
        assert_eq!((around.pa, around.size, around.flags), (pa(0x8123_5008), PageSize::Size4K, MapFlags::RW | MapFlags::READ));
        assert_eq!(pt.translate(va(0x4000_0000)).unwrap().size, PageSize::Size2M, "the rest stays 2 MiB");
        assert_eq!(pt.translate(va(0x7fff_ffff)).unwrap().pa, pa(0xbfff_ffff));
        assert_eq!(pt.split(va(0x4123_5000)), Ok(PageSize::Size4K));
    }
    assert_eq!(frames.lock().free_frames(), before, "drop frees every table");
}

#[test]
fn x86_64() {
    exercise::<X86_64>(0xffff_ffff_ffff_f000);
}

#[test]
fn aarch64() {
    exercise::<Aarch64>(0xffff_ffff_ffff_f000);
}

#[test]
fn aarch64_el2() {
    exercise::<Aarch64El2>(0x0000_ffff_ffff_f000);
}

#[test]
fn sv39() {
    exercise::<Sv39>(0xffff_ffff_ffff_f000);
}

#[test]
fn sv48() {
    exercise::<Sv48>(0xffff_ffff_ffff_f000);
}

#[test]
fn sv39x4() {
    // The top of the 41-bit space lands in the fourth root page.
    exercise::<Sv39x4>(0x0000_01ff_ffff_f000);
}

#[test]
fn sv48x4() {
    exercise::<Sv48x4>(0x0003_ffff_ffff_f000);
}

#[test]
fn ept() {
    exercise::<Ept>(0x0000_ffff_ffff_f000);
}

#[test]
fn aarch64_stage2() {
    exercise::<Aarch64Stage2>(0x0000_ffff_ffff_f000);
}

#[test]
fn encodings() {
    // Values checked against the architecture manuals.
    // EL2 kernel text: AF, AP[1] (RES1), RO, inner shareable, executable, nG = 0.
    assert_eq!(Aarch64El2::leaf(pa(0x4008_0000), MapFlags::RX | MapFlags::GLOBAL, 0), 0x4008_07c3);
    assert_eq!(Aarch64El2::leaf(pa(0x900_0000), MapFlags::RW | MapFlags::DEVICE, 0), 0x0040_0000_0900_0447);
    assert_eq!(Aarch64El2::flags(0x4008_07c3, 0), MapFlags::RX | MapFlags::READ);
    assert_eq!(Sv39x4::leaf(pa(0x5000), MapFlags::RW | MapFlags::GLOBAL, 0), 0x14d7, "V|R|W|U|A|D, no G");
    assert_eq!(Sv39x4::flags(0x14d7, 0), MapFlags::RW | MapFlags::READ);
    assert_eq!(X86_64::leaf(pa(0x5000), MapFlags::RW, 0), 0x8000_0000_0000_5063);
    assert_eq!(X86_64::leaf(pa(0x20_0000), MapFlags::RX | MapFlags::GLOBAL, 1), 0x20_01a1);
    assert_eq!(Sv39::leaf(pa(0x8020_0000), MapFlags::RW, 0), 0x2008_00c7);
    assert_eq!(Sv39::table(pa(0x8020_1000)), 0x2008_0401);
    // AArch64 kernel RX page: AF | SH inner | AP RO | nG clear | UXN | page | valid.
    assert_eq!(Aarch64::leaf(pa(0x4000_0000), MapFlags::RX | MapFlags::GLOBAL, 0), 0x0040_0000_4000_0783);
    assert_eq!(Ept::leaf(pa(0x1000), MapFlags::RW | MapFlags::EXEC, 0), 0x1077);
    assert!(Ept::flags(Ept::leaf(pa(0), MapFlags::READ | MapFlags::DEVICE, 0), 0).contains(MapFlags::DEVICE));
    assert!(Aarch64::flags(Aarch64::leaf(pa(0), MapFlags::RW | MapFlags::DEVICE, 0), 0).contains(MapFlags::DEVICE));
}

#[test]
fn shared_kernel_entries() {
    let ram = SimRam::new(0x8000_0000, 2 << 20);
    let frames = frames(&ram);
    let before = frames.lock().free_frames();
    let mut kernel: PageTable<X86_64, _> = PageTable::new(&frames).unwrap();
    // Kernel lives under root entry 0 (the first 512 GiB).
    kernel.map(va(0x20_0000), pa(0x20_0000), PageSize::Size4K, MapFlags::RW).unwrap().ignore();
    let kernel_tables = before - frames.lock().free_frames();
    {
        let mut proc_a: PageTable<X86_64, _> = PageTable::new(&frames).unwrap();
        let mut proc_b: PageTable<X86_64, _> = PageTable::new(&frames).unwrap();
        // SAFETY: `kernel` outlives both process tables.
        unsafe {
            proc_a.share_root_entries(&kernel, 0..1);
            proc_b.share_root_entries(&kernel, 0..1);
        }
        // The same user address maps to different frames per process.
        let user = va(0x80_0000_0000);
        proc_a.map(user, pa(0x1000), PageSize::Size4K, MapFlags::RW | MapFlags::USER).unwrap().ignore();
        proc_b.map(user, pa(0x2000), PageSize::Size4K, MapFlags::RW | MapFlags::USER).unwrap().ignore();
        assert_eq!(proc_a.translate(user).unwrap().pa, pa(0x1000));
        assert_eq!(proc_b.translate(user).unwrap().pa, pa(0x2000));
        assert!(kernel.translate(user).is_none());
        // Both see the kernel, including later changes made through it.
        assert_eq!(proc_a.translate(va(0x20_0000)).unwrap().pa, pa(0x20_0000));
        kernel.map(va(0x30_0000), pa(0x30_0000), PageSize::Size4K, MapFlags::RW).unwrap().ignore();
        assert_eq!(proc_b.translate(va(0x30_0000)).unwrap().pa, pa(0x30_0000));
        // Kernel mappings cannot be changed through a process table.
        assert_eq!(proc_a.map(va(0x40_0000), pa(0), PageSize::Size4K, MapFlags::RW).err(), Some(MapError::InvalidAddress));
        assert_eq!(proc_a.unmap(va(0x20_0000)).err(), Some(UnmapError::InvalidAddress));
    }
    // Dropping the processes freed only their own tables.
    assert!(kernel.translate(va(0x30_0000)).is_some());
    drop(kernel);
    assert_eq!(frames.lock().free_frames(), before, "everything freed exactly once");
    assert!(kernel_tables > 0);
}
