//! IOMMU demo: Intel VT-d or AMD-Vi, whichever the firmware describes in its
//! DMAR or IVRS table, put in front of QEMU's `iommu-testdev`.
//!
//! This runs last among the PCI demos because an enabled unit blocks every
//! device that is not attached to a domain; dropping the driver switches
//! translation off again.

use osmium::boot::acpi::{AmdIommuUnit, DmaRemapUnit, EcamWindow};
use osmium::sysdrv::iommu::amdvi::AmdVi;
use osmium::sysdrv::iommu::vtd::Vtd;
use osmium::hal::iommu::{DeviceId, Iommu};
use osmium::hal::pci;
use osmium::hal::println;

/// The IOMMUs the ACPI tables describe on PCI segment 0.
#[derive(Clone, Copy, Default)]
pub struct Units {
    /// The first VT-d remapping unit, from the DMAR.
    pub vtd: Option<DmaRemapUnit>,
    /// The first AMD IOMMU, from the IVRS.
    pub amd: Option<AmdIommuUnit>,
}

/// Runs the demo on every IOMMU found.
pub fn demo(ecam: Option<EcamWindow>, units: Units) {
    if units.vtd.is_none() && units.amd.is_none() {
        println!("[iommu] no DMAR or IVRS table; skipping");
        return;
    }
    let Some(ecam) = ecam else {
        println!("[iommu] no ECAM window; skipping");
        return;
    };
    let cfg = pci::Ecam::new(crate::msi::map(ecam.base, 1 << 20), 0);
    let mut found = None;
    pci::for_each_function(&cfg, 0, |f| {
        if found.is_none() && f.class() == demos::iommu::TESTDEV_CLASS {
            found = Some(f.address());
        }
    });
    let Some(func) = found.and_then(|a| pci::Function::new(&cfg, a)) else {
        println!("[iommu] no iommu-testdev; skipping");
        return;
    };
    let Some(bar) = func.bar(0).filter(|b| b.address != 0) else {
        println!("[iommu] iommu-testdev has no BAR 0 address; skipping");
        return;
    };
    func.enable_memory_and_dma();
    let regs = || crate::msi::map(bar.address, bar.size);
    let id = DeviceId::new(0, func.address());

    if let Some(unit) = units.vtd {
        // Scalable mode if the unit has it (`x-scalable-mode=on`), else legacy.
        let map = || crate::msi::map(unit.base, 0x1000);
        // SAFETY: QEMU's VT-d reports ECAP.C clear, but its memory is always coherent.
        let scalable =
            unsafe { Vtd::new_scalable_assuming_coherent(map(), &crate::FRAMES, &crate::msi::Uptime, unit.segment) };
        let vtd = scalable.or_else(|_| {
            // SAFETY: as above.
            unsafe { Vtd::new_assuming_coherent(map(), &crate::FRAMES, &crate::msi::Uptime, unit.segment) }
        });
        match vtd {
            Ok(vtd) => {
                println!(
                    "[iommu] VT-d unit at {:#x}: {} bit I/O addresses",
                    unit.base,
                    vtd.iova_limit().trailing_zeros()
                );
                if vtd.scalable() {
                    println!("[iommu] VT-d scalable mode: PASID directory and table per device, queued invalidation");
                }
                interrupt_remapping(&vtd);
                demos::iommu::testdev(
                    &vtd,
                    id,
                    regs(),
                    &crate::FRAMES,
                    if vtd.scalable() { "vt-d-scalable" } else { "vt-d" },
                );
            }
            Err(e) => println!("[iommu] VT-d unit at {:#x}: init failed: {e:?}", unit.base),
        }
    }
    if let Some(unit) = units.amd {
        // The device table covers bus 0 only: the test device sits there.
        match AmdVi::new(crate::msi::map(unit.base, 0x4000), &crate::FRAMES, &crate::msi::Uptime, unit.segment, 0) {
            Ok(amd) => {
                println!(
                    "[iommu] AMD-Vi unit at {:#x}: {} bit I/O addresses",
                    unit.base,
                    amd.iova_limit().trailing_zeros()
                );
                demos::iommu::testdev(&amd, id, regs(), &crate::FRAMES, "amd-vi");
            }
            Err(e) => println!("[iommu] AMD-Vi unit at {:#x}: init failed: {e:?}", unit.base),
        }
    }
}

/// Turns VT-d interrupt remapping on and off again, programming one table
/// entry in between. Nothing here raises a remapped interrupt, so this
/// checks that the unit accepts the table, the queued invalidation of its
/// entry cache and the entry. Compatibility-format interrupts stay allowed
/// so the kernel's own interrupts keep arriving.
fn interrupt_remapping(vtd: &Vtd<'_, impl osmium::hal::dma::DmaAllocator + Sync>) {
    use osmium::drivers::iommu::vtd::remap::{Irte, Source};
    if !vtd.supports_interrupt_remapping() {
        println!("[iommu] VT-d interrupt remapping not supported; skipping");
        return;
    }
    if let Err(e) = vtd.enable_interrupt_remapping(256, false, true) {
        println!("[iommu] VT-d interrupt remapping: enabling failed: {e:?}");
        return;
    }
    let entry = Irte::fixed(0x55, 0, Source::Any);
    let programmed = vtd.set_irte(7, &entry).is_ok() && vtd.irte(7) == Some(entry);
    let cleared = vtd.clear_irte(7).is_ok() && vtd.irte(7).is_none();
    println!(
        "[iommu] VT-d interrupt remapping on with {} entries; entry programmed {}, invalidated and cleared {}",
        vtd.interrupt_entries(),
        programmed,
        cleared
    );
    if let Err(e) = vtd.disable_interrupt_remapping() {
        println!("[iommu] VT-d interrupt remapping: disabling failed: {e:?}");
    }
}
