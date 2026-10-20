//! IOMMU demo shared by the example kernels, driven by QEMU's
//! `iommu-testdev` (`-device iommu-testdev`): a PCI function that, when its
//! trigger register is read, writes a known pattern to an I/O virtual address
//! (through the IOMMU) and reads it back from a physical address (around it).

use osmium::hal::dma::DmaAllocator;
use osmium::hal::iommu::{DeviceId, DomainId, IoDomain, Iommu};
use osmium::hal::mmio::IoMem;
use osmium::hal::pci;
use osmium::hal::println;
use osmium::mm::MapFlags;
use osmium::mm::paging::TableAlloc;

/// The test device's PCI class (Other, 0x00/0xff/0x00); QEMU gives it Red Hat's vendor ID.
pub const TESTDEV_CLASS: pci::Class = pci::Class { class: 0x00, subclass: 0xff, prog_if: 0x00 };

const REG_TRIGGER: usize = 0x00;
const REG_IOVA_LO: usize = 0x04;
const REG_IOVA_HI: usize = 0x08;
const REG_LEN: usize = 0x0c;
const REG_RESULT: usize = 0x10;
const REG_DOORBELL: usize = 0x14;
const REG_PA_LO: usize = 0x1c;
const REG_PA_HI: usize = 0x20;
const PATTERN: u32 = 0x1234_5678;

/// Has the device write its pattern to `iova` and read `pa` back; returns the
/// device's result code (0 on success, an `0xdead....` error otherwise).
fn dma(regs: &IoMem, iova: u64, pa: u64, len: u32) -> u32 {
    let w = |off, v: u32| regs.write(off, v).expect("testdev register");
    w(REG_IOVA_LO, iova as u32);
    w(REG_IOVA_HI, (iova >> 32) as u32);
    w(REG_PA_LO, pa as u32);
    w(REG_PA_HI, (pa >> 32) as u32);
    w(REG_LEN, len);
    w(REG_DOORBELL, 1);
    // The DMA runs inside this read.
    let _: u32 = regs.read(REG_TRIGGER).expect("testdev register");
    regs.read(REG_RESULT).expect("testdev register")
}

/// Takes every logged fault off `iommu` (a blocked DMA the device retries in
/// 4-byte pieces logs many) and returns how many were for `id`.
fn drain<I: Iommu>(iommu: &I, id: DeviceId) -> usize {
    let mut n = 0;
    while let Some(f) = iommu.take_fault() {
        n += usize::from(f.device == id);
    }
    n
}

/// Puts the test device in its own domain behind `iommu`, maps one page at an
/// I/O virtual address and has the device DMA through it; then checks that an
/// unmapped address and a detached device are both blocked.
pub fn testdev<I: Iommu, A: DmaAllocator + TableAlloc>(iommu: &I, id: DeviceId, regs: IoMem, frames: &A, tag: &str) {
    const IOVA: u64 = 0x2000_0000;
    let mut domain = IoDomain::new(iommu, DomainId(2), frames).expect("IOMMU domain");
    let page = frames.alloc_coherent(4096).expect("a DMA page");
    let pa = page.device_addr();
    if let Err(e) = domain.map(IOVA, pa, 4096, MapFlags::RW).and_then(|()| domain.attach(id)) {
        println!("[iommu] {tag}: mapping and attaching the test device failed: {e:?}");
        return;
    }

    let result = dma(&regs, IOVA, pa.as_u64(), 64);
    let seen = page.load::<u32>(0);
    if result == 0 && seen == PATTERN {
        let words = (0..16).filter(|i| page.load::<u32>(i * 4) == PATTERN).count();
        println!(
            "[iommu] {tag}: device wrote {seen:#x} through IOVA {IOVA:#x} into physical page {pa:?} ({words}/16 words)"
        );
    } else {
        println!("[iommu] {tag}: DMA through IOVA {IOVA:#x} failed: result {result:#x}, memory holds {seen:#x}");
    }
    drain(iommu, id);

    // A page nobody mapped. How much a fault says (address, direction)
    // differs between IOMMUs, and QEMU's models leave some out, so only the
    // count of faults for this device is checked.
    let result = dma(&regs, IOVA + 0x10_0000, pa.as_u64(), 64);
    match drain(iommu, id) {
        n if result != 0 && n > 0 => println!("[iommu] {tag}: DMA to an unmapped IOVA blocked; {n} faults logged"),
        n => println!("[iommu] {tag}: unmapped IOVA not blocked or not reported: result {result:#x}, {n} faults"),
    }

    // Detached: nothing gets through, not even the mapped page. (QEMU's
    // AMD-Vi blocks such a device without logging an event.)
    page.store::<u32>(0, 0);
    domain.detach(id).expect("detach");
    let result = dma(&regs, IOVA, pa.as_u64(), 64);
    let seen = page.load::<u32>(0);
    match drain(iommu, id) {
        n if result != 0 && seen == 0 => println!("[iommu] {tag}: detached device blocked ({n} faults logged)"),
        n => println!("[iommu] {tag}: detached device not blocked: result {result:#x}, memory {seen:#x}, {n} faults"),
    }
    drop(domain);
    // SAFETY: allocated above; the device is detached and nothing maps it.
    unsafe { frames.free_coherent(page) };
}
