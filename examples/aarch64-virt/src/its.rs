//! MSI-X through the GICv3 ITS: an NVMe controller's interrupts arrive as
//! LPIs.
//!
//! QEMU's `virt,gic-version=3` puts an ITS (`arm,gic-v3-its`) under the GIC
//! node, and the PCIe host bridge's `msi-map` sends every requester ID to it
//! as the device ID. The demo hands the redistributor of this CPU the LPI
//! tables, maps a collection to it, gives the NVMe controller an ITT and
//! maps MSI-X table entries 0 and 1 to two LPIs; the messages the ITS hands
//! back (its `GITS_TRANSLATER` doorbell, the event ID as data) go into the
//! table. The admin completions of bringing the controller up then raise
//! entry 0's LPI; an `INT` command raises it from software; a second driver
//! instance completes its I/O through entry 1's LPI.

use core::sync::atomic::{AtomicU32, Ordering};

use alloc::vec::Vec;
use osmium::boot::fdt::Fdt;
use osmium::hal::block::BlockDevice;
use osmium::hal::irq::IrqHandler;
use osmium::hal::mmio::IoMem;
use osmium::hal::pci::{self, Function, MsiError};
use osmium::hal::println;
use osmium::hal::timer::Clock;
use osmium::mm::{MapFlags, PAGE_SIZE, PhysAddr, VirtAddr};
use osmium::storage::nvme::{self, Interrupts, IrqSignal, Nvme, NvmeError};
use osmium::sync::Once;
use osmium::sysdrv::gicv3::its::{Its, ItsConfig, ItsError};
use osmium::sysdrv::gicv3::lpi::{LpiError, LpiTables};
use osmium::sysdrv::gicv3::{FIRST_LPI, GicV3, SysRegs};

use crate::{FRAMES, Frames, Gic};

/// The LPI tables every redistributor reads; they must outlive the GIC.
static LPI_TABLES: Once<LpiTables<'static, Frames>> = Once::new();

/// Interrupts on entry 0's LPI.
static ADMIN: AtomicU32 = AtomicU32::new(0);
/// Raised by entry 1's LPI, for the NVMe driver to wait on.
static IO: IrqSignal = IrqSignal::new();

struct Uptime;

impl Clock for Uptime {
    fn now_ns(&self) -> u64 {
        crate::now_ns()
    }
}

#[derive(Debug)]
#[allow(dead_code)] // fields are only printed
enum Error {
    Its(ItsError),
    Lpi(LpiError),
    Msi(MsiError),
    Nvme(NvmeError),
    NoBar,
}

impl From<ItsError> for Error {
    fn from(e: ItsError) -> Self {
        Self::Its(e)
    }
}

impl From<LpiError> for Error {
    fn from(e: LpiError) -> Self {
        Self::Lpi(e)
    }
}

impl From<MsiError> for Error {
    fn from(e: MsiError) -> Self {
        Self::Msi(e)
    }
}

impl From<NvmeError> for Error {
    fn from(e: NvmeError) -> Self {
        Self::Nvme(e)
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

/// Spins for up to 100 ms until `done` holds.
fn wait(done: impl Fn() -> bool) -> bool {
    let deadline = crate::now_ns() + 100_000_000;
    while !done() {
        if crate::now_ns() > deadline {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// The PCIe host bridge: its ECAM window and its 32-bit memory window.
pub struct HostBridge {
    pub ecam: (u64, u64),
    pub mem32: (u64, u64),
}

/// Finds the `pci-host-ecam-generic` bridge and its 32-bit memory window,
/// where bus addresses double as CPU addresses.
pub fn host_bridge(fdt: &Fdt<'_>) -> Option<HostBridge> {
    let host = fdt.find_compatible(&["pci-host-ecam-generic"])?;
    let (ecam, Some(ecam_len)) = host.reg().next()? else { return None };
    // Each `ranges` entry: PCI address (3 cells), CPU address (2), size (2).
    let ranges: Vec<u32> = host.property("ranges").map(|p| p.as_u32_cells().collect()).unwrap_or_default();
    let mem32 = ranges
        .as_chunks::<7>()
        .0
        .iter()
        .find(|r| r[0] >> 24 & 3 == 2)
        .map(|r| (u64::from(r[3]) << 32 | u64::from(r[4]), u64::from(r[5]) << 32 | u64::from(r[6])))?;
    Some(HostBridge { ecam: (ecam, ecam_len), mem32 })
}

/// The ITS device ID of requester `rid`, from the bridge's `msi-map`
/// (`rid-base`, `msi-controller`, `msi-base`, `length`), which must point at
/// `its_phandle`. Without an `msi-map`, the requester ID itself.
fn device_id(fdt: &Fdt<'_>, rid: u32, its_phandle: Option<u32>) -> Option<u32> {
    let host = fdt.find_compatible(&["pci-host-ecam-generic"])?;
    let Some(map) = host.property("msi-map") else { return Some(rid) };
    let cells: Vec<u32> = map.as_u32_cells().collect();
    cells.as_chunks::<4>().0.iter().find_map(|&[base, phandle, msi_base, len]| {
        (rid.checked_sub(base).is_some_and(|off| off < len) && its_phandle.is_none_or(|p| p == phandle))
            .then(|| msi_base + (rid - base))
    })
}

/// Runs the demo if the GIC is a GICv3 with an ITS and the bus has an NVMe
/// controller.
pub fn demo(fdt: &Fdt<'_>) {
    let Some(Gic::V3(gic)) = crate::GIC.get() else { return };
    let Some(its_node) = fdt.find_compatible(&["arm,gic-v3-its"]) else {
        println!("[its]   no ITS in the device tree; skipping");
        return;
    };
    let Some((its_phys, Some(its_len))) = its_node.reg().next() else { return };
    let its_phandle = its_node.property("phandle").and_then(|p| p.as_u32_cells().next());
    let gicr_phys = fdt.find_compatible(&["arm,gic-v3"]).and_then(|n| n.reg().nth(1)).map_or(0, |r| r.0);
    let Some(bridge) = host_bridge(fdt) else {
        println!("[its]   no PCIe host bridge; skipping");
        return;
    };
    let cfg = pci::Ecam::new(map(bridge.ecam.0, bridge.ecam.1.min(1 << 20)), 0);
    let mut found = None;
    pci::for_each_function(&cfg, 0, |f| {
        if found.is_none() && f.class() == pci::Class::NVME {
            found = Some(f.address());
        }
    });
    let Some(func) = found.and_then(|a| Function::new(&cfg, a)) else {
        println!("[its]   no NVMe controller; skipping");
        return;
    };
    let a = func.address();
    let rid = u32::from(a.bus) << 8 | u32::from(a.device) << 3 | u32::from(a.function);
    let Some(dev) = device_id(fdt, rid, its_phandle) else {
        println!("[its]   requester {rid:#x} is not in the msi-map; skipping");
        return;
    };
    println!("[its]   ITS at {its_phys:#x}; nvme {:02x}:{:02x}.{} is device {dev:#x}", a.bus, a.device, a.function);
    let its = map(its_phys, its_len);
    if let Err(e) = run(gic, its, PhysAddr::new(its_phys), PhysAddr::new(gicr_phys), &func, dev, &bridge) {
        println!("[its]   {e:?}");
    }
}

fn run(
    gic: &GicV3<SysRegs>,
    its_regs: IoMem,
    its_phys: PhysAddr,
    gicr_phys: PhysAddr,
    func: &Function<'_, pci::Ecam>,
    dev: u32,
    bridge: &HostBridge,
) -> Result<(), Error> {
    // LPIs on this CPU, and a collection (numbered after the CPU) aimed at it.
    // Interrupts stay off so the task cannot move between the two.
    let id_bits = gic.lpi_id_bits().ok_or(LpiError::Unsupported)?.min(14);
    let tables = match LPI_TABLES.get() {
        Some(t) => t,
        None => LPI_TABLES.call_once(|| LpiTables::new(&FRAMES, id_bits).expect("LPI tables")),
    };
    let its = Its::new(its_regs, its_phys, &FRAMES, &Uptime, ItsConfig { device_bits: 16, vpes: 0 })?;
    let (cpu, icid) = osmium::arch::irq::without(|| -> Result<_, Error> {
        let cpu = osmium::arch::cpu::current_id();
        gic.enable_lpis(tables)?;
        let target = its.collection_target(gic, cpu, gicr_phys).ok_or(ItsError::BadCollection)?;
        its.map_collection(cpu as u16, target)?;
        Ok((cpu, cpu as u16))
    })?;
    println!(
        "[its]   {} LPIs; ITS targets redistributors by {}; collection {icid} on CPU {cpu}",
        tables.count(),
        if its.targets_by_address() { "address" } else { "processor number" }
    );

    if pci::BarAllocator::new(bridge.mem32.0, bridge.mem32.1).assign(func).is_err() {
        return Err(Error::NoBar);
    }
    let msix = func.msix()?;
    let bar = |i| func.bar(i).filter(|b| b.address != 0).ok_or(Error::NoBar);
    let (regs, table_bar) = (bar(nvme::BAR)?, bar(msix.table_bir())?);
    func.enable_memory_and_dma();
    let table = msix.table(&map(table_bar.address, table_bar.size))?;
    for i in 0..table.len() {
        table.set_masked(i, true)?;
    }
    its.add_device(dev, u32::from(table.len()))?;

    // Entry 0: admin completions.
    let admin = its.map_event(dev, 0, icid, tables, 0x5f)?;
    static COUNT_ADMIN: fn(u32) = |_| {
        ADMIN.fetch_add(1, Ordering::Relaxed);
    };
    register(admin.intid, &COUNT_ADMIN);
    table.set_message(0, admin.message)?;
    table.set_masked(0, false)?;
    msix.enable(func);

    let disk = Nvme::new(map(regs.address, regs.size), &FRAMES, &Uptime)?;
    let ok = wait(|| ADMIN.load(Ordering::Relaxed) > 0);
    let n = ADMIN.load(Ordering::Relaxed);
    if ok {
        println!(
            "[its]   nvme MSI-X entry 0 -> device {dev:#x} event 0 -> LPI {} on CPU {cpu}: {n} interrupts from admin \
             completions (doorbell {:#x})",
            admin.intid, admin.message.address
        );
    } else {
        println!("[its]   nvme MSI-X entry 0 (LPI {}): no interrupt within 100 ms of {:?}", admin.intid, disk.model());
    }
    drop(disk);

    // The same LPI from software: an INT command for the event.
    let before = ADMIN.load(Ordering::Relaxed);
    its.trigger(dev, 0)?;
    if wait(|| ADMIN.load(Ordering::Relaxed) > before) {
        println!("[its]   INT command for device {dev:#x} event 0 raised LPI {}", admin.intid);
    } else {
        println!("[its]   INT command for device {dev:#x} event 0: no LPI");
    }

    // Entry 1: I/O completions, waited for by the driver.
    let io = its.map_event(dev, 1, icid, tables, 0x5f)?;
    static SIGNAL_IO: fn(u32) = |_| IO.notify();
    register(io.intid, &SIGNAL_IO);
    table.set_message(1, io.message)?;
    table.set_masked(1, false)?;
    let idle = || core::hint::spin_loop();
    let irq = Interrupts { vector: 1, signal: &IO, idle: &idle };
    let mut disk = Nvme::with_interrupts(map(regs.address, regs.size), &FRAMES, &Uptime, irq)?;
    let before = IO.count();
    let mut buf = alloc::vec![0xa5u8; 4 * nvme::DATA_LEN];
    let read = disk.read_blocks(0, &mut buf).is_ok() && buf.iter().all(|&b| b == 0);
    let n = IO.count().wrapping_sub(before);
    if read && n > 0 {
        println!(
            "[its]   nvme completions by LPI {}: {} KiB read, {n} interrupts on MSI-X entry 1",
            io.intid,
            buf.len() / 1024
        );
    } else {
        println!("[its]   nvme completions by LPI {}: read ok {read}, interrupts {n}", io.intid);
    }
    drop(disk);

    table.set_masked(1, true)?;
    table.set_masked(0, true)?;
    msix.disable(func);
    its.remove_device(dev, tables)?;
    unregister(admin.intid);
    unregister(io.intid);
    println!("[its]   device {dev:#x} unmapped; LPIs {} and {} free again", admin.intid, io.intid);
    Ok(())
}

fn register(intid: u32, handler: &'static dyn IrqHandler) {
    let _ = crate::LPIS.register(intid - FIRST_LPI, handler);
}

fn unregister(intid: u32) {
    crate::LPIS.unregister(intid - FIRST_LPI);
}
