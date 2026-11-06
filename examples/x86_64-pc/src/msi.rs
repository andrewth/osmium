//! MSI-X under QEMU: an NVMe controller's admin completions arrive as
//! message-signalled interrupts at [`VECTOR`] on this CPU's local APIC.
//!
//! The first driver instance polls; it does not know about the interrupts.
//! Every admin queue completion raises MSI-X table entry 0 (the admin
//! completion queue always uses interrupt vector 0), so bringing the
//! controller up is enough to see interrupts arrive. A further admin command
//! with the entry masked must leave its interrupt pending in the PBA, to be
//! sent when the entry is unmasked.
//!
//! A second instance is then created with [`Nvme::with_interrupts`] on table
//! entry 1 (same vector): its I/O completion queue raises MSI-X, the handler
//! calls [`IrqSignal::notify`], and a transfer split into several commands
//! is kept in flight and reaped by interrupt.

use core::sync::atomic::{AtomicU32, Ordering};

pub use demos::kernel::Uptime;
use osmium::boot::acpi::EcamWindow;
use osmium::hal::block::BlockDevice;
use osmium::hal::mmio::IoMem;
use osmium::hal::pci::{self, Function, MsiError};
use osmium::hal::println;
use osmium::storage::nvme::{self, Interrupts, IrqSignal, Nvme, NvmeError};
use osmium::sysdrv::lapic;

/// The IDT vector entry 0 is programmed to raise.
pub const VECTOR: u8 = 0x50;

/// Interrupts received at [`VECTOR`].
static DELIVERED: AtomicU32 = AtomicU32::new(0);

/// Raised on every interrupt at [`VECTOR`], for the NVMe driver to wait on.
static SIGNAL: IrqSignal = IrqSignal::new();

/// Handles [`VECTOR`].
pub fn on_interrupt() {
    DELIVERED.fetch_add(1, Ordering::Relaxed);
    SIGNAL.notify();
    crate::eoi();
}

#[derive(Debug)]
#[allow(dead_code)] // fields are only printed
enum Error {
    Msi(MsiError),
    Nvme(NvmeError),
    NoBar(u8),
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

/// Identity-maps `[addr, addr + size)` in the kernel's table as device
/// memory and returns a window onto it.
///
/// # Safety
/// The window must be a device's registers that the calling demo owns.
pub unsafe fn map(addr: u64, size: u64) -> IoMem {
    // SAFETY: the caller's contract.
    unsafe { demos::kernel::map_io(&crate::PT, addr, size) }
}

/// Spins for up to 100 ms until `done` holds.
fn wait(done: impl Fn() -> bool) -> bool {
    demos::kernel::wait_for(100_000_000, done)
}
/// Finds the first NVMe controller on bus 0 and runs the demo on it.
pub fn demo(ecam: Option<EcamWindow>) {
    let Some(ecam) = ecam else {
        println!("[msi]   no ECAM window; skipping");
        return;
    };
    // SAFETY: the ECAM window from the MCFG; only this demo uses it meanwhile.
    let cfg = pci::Ecam::new(unsafe { map(ecam.base, 1 << 20) }, 0);
    let mut found = None;
    pci::for_each_function(&cfg, 0, |f| {
        if found.is_none() && f.class() == pci::Class::NVME {
            found = Some(f.address());
        }
    });
    let Some(func) = found.and_then(|a| Function::new(&cfg, a)) else {
        println!("[msi]   no NVMe controller; skipping");
        return;
    };
    let a = func.address();
    if let Err(e) = run(&func) {
        println!("[msi]   nvme {:02x}:{:02x}.{}: {e:?}", a.bus, a.device, a.function);
    }
}

fn run(func: &Function<'_, pci::Ecam>) -> Result<(), Error> {
    let msix = func.msix()?;
    // Probe every BAR before memory decoding goes on (probing turns it off).
    let bar = |i| func.bar(i).filter(|b| b.address != 0).ok_or(Error::NoBar(i));
    let (regs, table_bar, pba_bar) = (bar(nvme::BAR)?, bar(msix.table_bir())?, bar(msix.pba_bir())?);
    func.enable_memory_and_dma();
    // SAFETY: the BARs holding the MSI-X table and PBA; only this demo uses them.
    let (table_io, pba_io) = unsafe { (map(table_bar.address, table_bar.size), map(pba_bar.address, pba_bar.size)) };
    let table = msix.table(&table_io)?;
    let pba = msix.pba(&pba_io)?;

    // Everything masked but entry 0, which goes to this CPU.
    let apic = crate::apic_id();
    for i in 0..table.len() {
        table.set_masked(i, true)?;
    }
    table.set_message(0, lapic::msi_message(apic, VECTOR))?;
    table.set_masked(0, false)?;
    msix.enable(func);

    // SAFETY: the controller's register BAR; this driver owns it.
    let mut disk = Nvme::new(unsafe { map(regs.address, regs.size) }, &crate::FRAMES, &Uptime)?;
    let delivered = wait(|| DELIVERED.load(Ordering::Relaxed) > 0);
    let n = DELIVERED.load(Ordering::Relaxed);
    if delivered {
        println!(
            "[msi]   nvme MSI-X vector {VECTOR:#x} delivered to APIC {apic}: {n} interrupts from admin completions \
             (entry 0 of {}, table at BAR{} + {:#x})",
            table.len(),
            msix.table_bir(),
            msix.table_offset()
        );
    } else {
        println!("[msi]   nvme MSI-X vector {VECTOR:#x}: no interrupt within 100 ms of {:?}", disk.model());
    }

    // With entry 0 masked, an admin command's interrupt waits in the PBA.
    table.set_masked(0, true)?;
    let before = DELIVERED.load(Ordering::Relaxed);
    disk.active_namespaces(&mut [0; 4])?;
    let pending = wait(|| pba.is_pending(0) == Ok(true));
    let held = DELIVERED.load(Ordering::Relaxed) == before;
    table.set_masked(0, false)?;
    let sent = wait(|| DELIVERED.load(Ordering::Relaxed) > before);
    if pending && held && sent {
        println!("[msi]   masked entry 0 held an IDENTIFY completion pending in the PBA; unmasking delivered it");
    } else {
        println!("[msi]   masking entry 0: pending {pending}, held {held}, delivered on unmask {sent}");
    }

    drop(disk);

    // Interrupt-driven completions: table entry 1, to the same vector.
    table.set_message(1, lapic::msi_message(apic, VECTOR))?;
    table.set_masked(1, false)?;
    let idle = || core::hint::spin_loop();
    let irq = Interrupts { vector: 1, signal: &SIGNAL, idle: &idle };
    // SAFETY: as above; the first driver instance has been dropped.
    let mut disk = Nvme::with_interrupts(unsafe { map(regs.address, regs.size) }, &crate::FRAMES, &Uptime, irq)?;
    let before = SIGNAL.count();
    // Eight commands' worth, kept in flight several at a time.
    let mut buf = alloc::vec![0xa5u8; 8 * nvme::DATA_LEN];
    let ok = disk.read_blocks(0, &mut buf).is_ok() && buf.iter().all(|&b| b == 0);
    let n = SIGNAL.count().wrapping_sub(before);
    if ok && n > 0 {
        println!(
            "[msi]   nvme completions by interrupt: {} KiB read in commands of up to {} KiB, up to {} in flight, {n} \
             interrupts on MSI-X entry 1",
            buf.len() / 1024,
            disk.max_transfer() / 1024,
            disk.queue_depth()
        );
    } else {
        println!("[msi]   nvme completions by interrupt: read ok {ok}, interrupts {n}");
    }
    drop(disk);
    table.set_masked(1, true)?;
    table.set_masked(0, true)?;
    msix.disable(func);
    Ok(())
}
