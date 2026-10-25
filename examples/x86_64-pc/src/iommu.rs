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
        // SAFETY: QEMU's VT-d reports ECAP.C clear, but its memory is always coherent.
        let vtd = unsafe {
            Vtd::new_assuming_coherent(
                crate::msi::map(unit.base, 0x1000),
                &crate::FRAMES,
                &crate::msi::Uptime,
                unit.segment,
            )
        };
        match vtd {
            Ok(vtd) => {
                println!(
                    "[iommu] VT-d unit at {:#x}: {} bit I/O addresses",
                    unit.base,
                    vtd.iova_limit().trailing_zeros()
                );
                demos::iommu::testdev(&vtd, id, regs(), &crate::FRAMES, "vt-d");
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
