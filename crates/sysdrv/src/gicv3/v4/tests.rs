// Tests drop drivers explicitly to end their use of the fake register memory
// before inspecting it.
#![allow(clippy::drop_non_drop)]

use super::*;
use crate::gicv3::its::ItsConfig;
use crate::gicv3::its::tests::{FakeIts, Quirks, TYPER};
use crate::gicv3::lpi::LpiTables;
use crate::gicv3::tests::{Fake, FakeCpu};
use crate::gicv3::{GICD_TYPER, GICR_STRIDE_V4, GICR_TYPER, GICR_TYPER_LAST, GICR_TYPER_PLPIS, GICR_TYPER_VLPIS};
use crate::iommu::testing::{HostDma, StdClock};

const TYPER_VIRTUAL: u64 = 1 << 1;

#[test]
fn tables_and_vpes() {
    let dma = HostDma::default();
    assert_eq!(VlpiTables::new(&dma, 12).err(), Some(VlpiError::BadIdBits));
    assert_eq!(Vpe::new(&dma, 0, 17).err(), Some(VlpiError::BadIdBits));
    let vm = VlpiTables::new(&dma, 14).unwrap();
    vm.configure(8192, 0x5f, true).unwrap();
    assert_eq!(vm.property(8192), Some(0xa3));
    assert_eq!(vm.property(8193), Some(property(0, false)));
    assert_eq!(vm.configure(16384, 0, true), Err(VlpiError::BadVintid));
    assert_eq!(vm.configure(8191, 0, true), Err(VlpiError::BadVintid));
    assert_eq!(vm.vpropbaser() & 0x1f, 13);
    let vpe = Vpe::new(&dma, 3, 14).unwrap();
    assert_eq!(vpe.id(), 3);
    assert_eq!(vpe.pending_table().as_u64() % 0x1_0000, 0);
    assert!(!vpe.is_pending(8192));
    let vpend = vpe.vpendbaser();
    assert_ne!(vpend & VPENDBASER_VALID, 0);
    assert_eq!(vpend & ADDR_MASK_64K, vpe.pending_table().as_u64());
}

/// One GICv4 redistributor (with the VLPI frames), affinity 0.
fn v4_gic() -> Fake {
    let mut f = Fake::new();
    f.d[GICD_TYPER / 4] |= 1 << 17 | 15 << 19;
    f.r = std::vec![0u32; GICR_STRIDE_V4 / 4];
    f.r[GICR_TYPER / 4] = (GICR_TYPER_LAST | GICR_TYPER_VLPIS | GICR_TYPER_PLPIS) as u32;
    f
}

#[test]
fn residency() {
    let dma = HostDma::default();
    let vm = VlpiTables::new(&dma, 14).unwrap();
    let (a, b) = (Vpe::new(&dma, 0, 14).unwrap(), Vpe::new(&dma, 1, 14).unwrap());
    let cpu = FakeCpu::new(0);
    let mut f = v4_gic();
    let gic = f.gic(&cpu);
    assert!(gic.init_cpu());
    assert_eq!(gic.resident_vpe(), None);
    gic.make_vpe_resident(&vm, &a).unwrap();
    assert_eq!(gic.resident_vpe(), Some(a.pending_table()));
    assert_eq!(gic.make_vpe_resident(&vm, &b), Err(VlpiError::Busy));
    assert_eq!(gic.make_vpe_nonresident(), Ok(false));
    assert_eq!(gic.resident_vpe(), None);
    gic.make_vpe_resident(&vm, &b).unwrap();
    drop(gic);
    let r64 = |off: usize| u64::from(f.r[off / 4]) | u64::from(f.r[off / 4 + 1]) << 32;
    assert_eq!(r64(GICR_VPROPBASER) & ADDR_MASK_4K, vm.prop.device_addr().as_u64());
    assert_eq!(r64(GICR_VPENDBASER), b.vpendbaser());
}

#[test]
fn residency_needs_vlpis() {
    let dma = HostDma::default();
    let vm = VlpiTables::new(&dma, 14).unwrap();
    let vpe = Vpe::new(&dma, 0, 14).unwrap();
    let cpu = FakeCpu::new(0);
    let mut f = Fake::new();
    let gic = f.gic(&cpu);
    assert_eq!(gic.make_vpe_resident(&vm, &vpe), Err(VlpiError::NoRedistributor));
    assert!(gic.init_cpu());
    assert_eq!(gic.make_vpe_resident(&vm, &vpe), Err(VlpiError::Unsupported));
}

#[test]
fn virtual_events() {
    let (dma, clock) = (HostDma::default(), StdClock::default());
    let lpis = LpiTables::new(&dma, 14).unwrap();
    let vpe = Vpe::new(&dma, 2, 14).unwrap();
    let far = Vpe::new(&dma, 200, 14).unwrap();

    let physical = FakeIts::new(TYPER, Quirks::default());
    let its = physical.its(&dma, &clock, ItsConfig { device_bits: 8, vpes: 64 }).unwrap();
    assert_eq!(its.map_vpe(&vpe, 0), Err(ItsError::Unsupported), "a GICv3 ITS");
    drop(its);

    let fake = FakeIts::new(TYPER | TYPER_VIRTUAL, Quirks::default());
    let its = fake.its(&dma, &clock, ItsConfig { device_bits: 8, vpes: 64 }).unwrap();
    assert_eq!(its.map_vpe(&far, 0), Err(ItsError::BadVpe), "beyond the vPE table (one page, 128 entries)");
    its.map_vpe(&vpe, 1).unwrap();
    let vpt = vpe.pending_table().as_u64();
    assert_eq!(fake.take(), [cmd::vmapp(2, 1, vpt, 14, true), cmd::vsync(2)]);
    its.map_collection(0, 1).unwrap();
    its.add_device(7, 2).unwrap();
    fake.take();

    assert_eq!(its.map_virtual_event(7, 0, &vpe, 100, None), Err(ItsError::BadEvent), "not an LPI");
    its.map_virtual_event(7, 0, &vpe, 8192, Some(8200)).unwrap();
    assert_eq!(fake.take(), [cmd::vmapti(7, 0, 2, 8192, 8200), cmd::inv(7, 0), cmd::vsync(2)]);
    assert_eq!(its.virtual_event(7, 0), Some((8192, 2)));
    assert_eq!(its.event_lpi(7, 0), None, "not a physical LPI");
    assert_eq!(its.map_virtual_event(7, 0, &vpe, 8193, None), Err(ItsError::BadEvent), "mapped twice");
    its.map_virtual_event(7, 1, &vpe, 8193, None).unwrap();
    fake.take();

    its.trigger(7, 0).unwrap();
    assert_eq!(fake.take(), [cmd::int(7, 0), cmd::vsync(2)]);
    its.move_vpe(&vpe, 0).unwrap();
    assert_eq!(fake.take(), [cmd::vmovp(2, 0, 0, 0), cmd::vsync(2)]);
    let other = Vpe::new(&dma, 5, 14).unwrap();
    its.move_virtual_event(7, 0, &other, None).unwrap();
    assert_eq!(fake.take(), [cmd::vmovi(7, 0, 5, None), cmd::vsync(2), cmd::vsync(5)]);
    assert_eq!(its.virtual_event(7, 0), Some((8192, 5)));
    its.invalidate_vpe(&vpe).unwrap();
    its.invalidate_collection(0).unwrap();
    assert_eq!(fake.take(), [cmd::vinvall(2), cmd::vsync(2), cmd::invall(0), cmd::sync(1)]);

    its.unmap_event(7, 0, &lpis).unwrap();
    assert_eq!(fake.take(), [cmd::discard(7, 0), cmd::vsync(5)]);
    assert_eq!(lpis.alloc(), Some(8192), "a virtual event frees no physical LPI");
    its.remove_device(7, &lpis).unwrap();
    assert_eq!(fake.take(), [cmd::discard(7, 1), cmd::mapd(7, 0, 0, false)]);
    its.unmap_vpe(&vpe).unwrap();
    assert_eq!(fake.take(), [cmd::vmapp(2, 0, 0, 14, false)]);
}
