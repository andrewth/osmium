//! IOMMU demo: the Arm SMMUv3 that QEMU's `virt,iommu=smmuv3` puts in front
//! of its PCI bus, with QEMU's `iommu-testdev` behind it.
//!
//! The device tree names the SMMU (`arm,smmu-v3`) and the PCIe host bridge
//! (`pci-host-ecam-generic`: ECAM window and the 32-bit window BARs come
//! from). Nothing else on this machine does PCI DMA, so the SMMU taking over
//! the bus blocks nobody; dropping the driver switches it off again.

use alloc::vec::Vec;

use osmium::boot::fdt::Fdt;
use osmium::sysdrv::iommu::smmuv3::{Smmuv3, StreamTableLayout};
use osmium::hal::iommu::{DeviceId, Iommu};
use osmium::hal::mmio::IoMem;
use osmium::hal::pci;
use osmium::hal::println;
use osmium::hal::timer::Clock;
use osmium::mm::{MapFlags, PAGE_SIZE, PhysAddr, VirtAddr};

struct Uptime;

impl Clock for Uptime {
    fn now_ns(&self) -> u64 {
        crate::now_ns()
    }
}

/// Identity-maps `[addr, addr + size)` as device memory (the pages not
/// mapped yet) and returns a window onto it.
fn map(addr: u64, size: u64) -> IoMem {
    let mut guard = crate::PT.lock();
    let pt = guard.as_mut().expect("kernel page table installed");
    let end = (addr + size).next_multiple_of(PAGE_SIZE as u64);
    for page in (addr & !(PAGE_SIZE as u64 - 1)..end).step_by(PAGE_SIZE) {
        if pt.translate(VirtAddr::new(page)).is_none() {
            let flags = MapFlags::RW | MapFlags::DEVICE | MapFlags::GLOBAL;
            pt.map_range(VirtAddr::new(page), PhysAddr::new(page), PAGE_SIZE as u64, flags).expect("map_range failed");
        }
    }
    // SAFETY: just mapped as device memory; the demo owns the device.
    unsafe { IoMem::new(addr as *mut u8, size as usize) }
}

/// Runs the demo if the device tree has an SMMU and the bus a test device.
pub fn demo(fdt: &Fdt<'_>) {
    let Some(smmu) = fdt.find_compatible(&["arm,smmu-v3"]).and_then(|n| n.reg().next()) else {
        println!("[iommu] no SMMUv3 in the device tree; skipping");
        return;
    };
    let Some(host) = fdt.find_compatible(&["pci-host-ecam-generic"]) else {
        println!("[iommu] no PCIe host bridge; skipping");
        return;
    };
    let Some((ecam, Some(ecam_len))) = host.reg().next() else { return };
    // Each `ranges` entry: PCI address (3 cells), CPU address (2), size (2).
    let ranges: Vec<u32> = host.property("ranges").map(|p| p.as_u32_cells().collect()).unwrap_or_default();
    let Some((win, win_len)) = ranges.as_chunks::<7>().0.iter().find(|r| r[0] >> 24 & 3 == 2).map(|r| {
        // The 32-bit memory window: bus addresses double as CPU addresses.
        (u64::from(r[3]) << 32 | u64::from(r[4]), u64::from(r[5]) << 32 | u64::from(r[6]))
    }) else {
        println!("[iommu] the host bridge has no 32-bit memory window; skipping");
        return;
    };

    let cfg = pci::Ecam::new(map(ecam, ecam_len.min(1 << 20)), 0);
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
    // Firmware did not assign BARs on this machine.
    if pci::BarAllocator::new(win, win_len).assign(&func).is_err() {
        println!("[iommu] cannot assign the test device's BAR; skipping");
        return;
    }
    let Some(bar) = func.bar(0).filter(|b| b.address != 0) else {
        println!("[iommu] iommu-testdev has no BAR 0 address; skipping");
        return;
    };
    func.enable_memory_and_dma();
    let id = DeviceId::new(0, func.address());

    // Both register pages of the SMMU, and every stream ID of bus 0.
    match Smmuv3::new(map(smmu.0, 0x20000), &crate::FRAMES, &Uptime, 0, 0xff) {
        Ok(unit) => {
            println!("[iommu] SMMUv3 at {:#x}: {} bit I/O addresses", smmu.0, unit.iova_limit().trailing_zeros());
            demos::iommu::testdev(&unit, id, map(bar.address, bar.size), &crate::FRAMES, "smmuv3");
        }
        Err(e) => println!("[iommu] SMMUv3 at {:#x}: init failed: {e:?}", smmu.0),
    }

    // The same device again through stage 1 (context descriptor, ASID 2) and a
    // two-level stream table, which allocates the level-2 table the test
    // device's stream ID falls in when it attaches.
    let layout = StreamTableLayout::TwoLevel;
    match Smmuv3::with_layout(map(smmu.0, 0x20000), &crate::FRAMES, &Uptime, 0, 0x1ff, layout) {
        Ok(unit) => match unit.stage1() {
            Ok(stage1) => {
                println!("[iommu] SMMUv3 stage 1, two-level stream table: {}", unit.two_level());
                demos::iommu::testdev(&stage1, id, map(bar.address, bar.size), &crate::FRAMES, "smmuv3 stage 1");
            }
            Err(e) => println!("[iommu] SMMUv3 has no stage 1: {e:?}"),
        },
        Err(e) => println!("[iommu] SMMUv3 two-level init failed: {e:?}"),
    }
}
