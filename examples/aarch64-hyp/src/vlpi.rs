//! GICv4 direct injection: a virtual LPI reaches a guest through the ITS
//! with no list register and no exit.
//!
//! On a GICv4 host (`-machine virt,virtualization=on,gic-version=4`) the
//! hypervisor enables physical LPIs on this CPU, sets up the ITS, gives a
//! one-vCPU guest a vPE (`VMAPP`, aimed at this CPU's redistributor) and a
//! virtual LPI property table, and maps two events of a device ID no real
//! device uses to virtual LPIs 8192 and 8193 of that vPE (`VMAPTI`), event 0
//! with a doorbell. Events are raised with the ITS's `INT` command, exactly
//! as a device's MSI write would raise them.
//!
//! Event 0 is raised before the guest runs, while the vPE is not resident:
//! the virtual LPI waits in the vPE's pending table and the ITS rings the
//! doorbell, a physical LPI the hypervisor takes. Then the vPE is made
//! resident and the guest started; it finds virtual LPI 8192 waiting in its
//! CPU interface (`ICC_IAR1_EL1`, the `ICV_` view), completes it, and asks
//! by hypercall for event 1, which the ITS delivers straight to it while it
//! runs.

use alloc::sync::Arc;
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicBool, Ordering};

use demos::guest::image;
use osmium::arch::aarch64;
use osmium::boot::fdt::Fdt;
use osmium::hal::irq::InterruptController;
use osmium::hal::mmio::IoMem;
use osmium::hal::println;
use osmium::hal::timer::{Clock, TickRate};
use osmium::mm::paging::PageTable;
use osmium::mm::{FrameAllocator, PAGE_SIZE, PhysAddr};
use osmium::sync::Once;
use osmium::sysdrv::gicv3::its::{Its, ItsConfig, ItsError};
use osmium::sysdrv::gicv3::lpi::{LpiError, LpiTables};
use osmium::sysdrv::gicv3::v4::{VlpiError, VlpiTables, Vpe};
use osmium::virt::aarch64::{self as vm, Aarch64Vcpu};
use osmium::virt::devices::VirtualGicV3;
use osmium::virt::stage2::{Stage2Table, map_guest_memory, vttbr};
use osmium::virt::{Bus, GuestMemory, VmExit, run_vcpu};

use crate::{FRAMES, Frames, GUEST_RAM, GUEST_RAM_ORDER, PHYS_GIC, PhysGic};

// The guest: turn on the CPU interface, wait for a virtual interrupt,
// complete it, ask for another with HVC 0xc6000002, wait for that one, and
// power off. x20 and x21 keep the two interrupt IDs.
core::arch::global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .globl vlpi_guest, vlpi_guest_end
vlpi_guest:
    mrs x1, S3_0_C12_C12_5
    orr x1, x1, #1
    msr S3_0_C12_C12_5, x1          // ICC_SRE_EL1.SRE
    isb
    mov x1, #0xff
    msr S3_0_C4_C6_0, x1            // ICC_PMR_EL1
    msr S3_0_C12_C12_3, xzr         // ICC_BPR1_EL1
    mov x1, #1
    msr S3_0_C12_C12_7, x1          // ICC_IGRPEN1_EL1
    isb
1:  mrs x20, S3_0_C12_C12_0         // ICC_IAR1_EL1
    cmp w20, #1023
    b.ne 2f
    wfi
    b 1b
2:  msr S3_0_C12_C12_1, x20         // ICC_EOIR1_EL1
    movz x0, #0x0002
    movk x0, #0xc600, lsl #16       // "raise event 1"
    hvc #0
3:  mrs x21, S3_0_C12_C12_0
    cmp w21, #1023
    b.ne 4f
    wfi
    b 3b
4:  msr S3_0_C12_C12_1, x21
    movz x0, #0x0008
    movk x0, #0x8400, lsl #16       // PSCI SYSTEM_OFF
    hvc #0
5:  b 5b
    .balign 4
vlpi_guest_end:
"#
);

unsafe extern "C" {
    static vlpi_guest: u8;
    static vlpi_guest_end: u8;
}

/// The guest's request for event 1.
const RAISE: u64 = 0xc600_0002;
/// A device ID no PCI function has (QEMU's `msi-map` covers 0..0x10000).
const DEVICE: u32 = 0xff00;
/// The virtual LPIs events 0 and 1 raise.
const VLPI: [u32; 2] = [8192, 8193];
/// LPI ID bits, physical and virtual.
const ID_BITS: u32 = 14;

/// The physical LPI tables; they must outlive the GIC.
static LPI_TABLES: Once<LpiTables<'static, Frames>> = Once::new();

struct Uptime;

impl Clock for Uptime {
    fn now_ns(&self) -> u64 {
        TickRate::new(aarch64::counter_frequency()).ticks_to_ns(vm::counter())
    }
}

#[derive(Debug)]
#[allow(dead_code)] // fields are only printed
enum Error {
    Its(ItsError),
    Lpi(LpiError),
    Vlpi(VlpiError),
    Other(&'static str),
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

impl From<VlpiError> for Error {
    fn from(e: VlpiError) -> Self {
        Self::Vlpi(e)
    }
}

/// The ITS's registers, if the device tree has one: physical address and
/// length.
pub fn its_window(fdt: &Fdt<'_>) -> Option<(u64, u64)> {
    let (base, len) = fdt.find_compatible(&["arm,gic-v3-its"])?.reg().next()?;
    Some((base, len?))
}

/// Runs the demo if the host GIC is a GICv3 with an ITS that has virtual
/// LPIs. `its` is the ITS window, mapped by the caller; `gicr` the
/// redistributor region's physical address.
pub fn demo(its: Option<(u64, u64)>, gicr: u64) {
    let Some(PhysGic::V3(_)) = PHYS_GIC.get() else { return };
    let Some((base, len)) = its else {
        println!("[vlpi]  no ITS; skipping");
        return;
    };
    if let Err(e) = run(base, len, gicr) {
        println!("[vlpi]  {e:?}");
    }
}

/// Polls this CPU's interface for up to a second for `intid`, completing
/// whatever else turns up.
fn take(intid: u32) -> bool {
    let Some(gic) = PHYS_GIC.get() else { return false };
    let deadline = Uptime.now_ns() + 1_000_000_000;
    while Uptime.now_ns() < deadline {
        if let Some(irq) = gic.claim() {
            gic.complete(irq);
            if irq == intid {
                return true;
            }
        }
        core::hint::spin_loop();
    }
    false
}

fn run(base: u64, len: u64, gicr: u64) -> Result<(), Error> {
    let Some(PhysGic::V3(gic)) = PHYS_GIC.get() else { return Ok(()) };
    // SAFETY: the ITS window from the device tree, mapped by kmain as device
    // memory; only this demo drives it.
    let regs = unsafe { IoMem::new(base as *mut u8, len as usize) };
    let its = Its::new(regs, PhysAddr::new(base), &FRAMES, &Uptime, ItsConfig { device_bits: 16, vpes: 8 })?;
    if !its.has_virtual_lpis() {
        println!("[vlpi]  the ITS has no virtual LPIs (a GICv3); skipping");
        return Ok(());
    }
    let tables = match LPI_TABLES.get() {
        Some(t) => t,
        None => {
            let tables = LpiTables::new(&FRAMES, ID_BITS)?;
            LPI_TABLES.call_once(|| tables)
        }
    };
    // The host runs with interrupts masked, so this stays on CPU 0.
    let cpu = osmium::arch::cpu::current_id();
    gic.enable_lpis(tables)?;
    let target = its.collection_target(gic, cpu, PhysAddr::new(gicr)).ok_or(Error::Other("no redistributor"))?;
    its.map_collection(0, target)?;

    // The doorbell: a physical LPI in collection 0's redistributor.
    let doorbell = tables.alloc().ok_or(Error::Other("no free LPI"))?;
    tables.configure(doorbell, 0x5f, true)?;
    its.invalidate_collection(0)?;

    let vm = VlpiTables::new(&FRAMES, ID_BITS)?;
    for v in VLPI {
        vm.configure(v, 0x5f, true)?;
    }
    let vpe = Vpe::new(&FRAMES, 0, ID_BITS)?;
    its.map_vpe(&vpe, target)?;
    its.add_device(DEVICE, 2)?;
    its.map_virtual_event(DEVICE, 0, &vpe, VLPI[0], Some(doorbell))?;
    its.map_virtual_event(DEVICE, 1, &vpe, VLPI[1], None)?;
    println!(
        "[vlpi]  GICv4 ITS: vPE {} on CPU {cpu}'s redistributor; device {DEVICE:#x} events 0 and 1 -> vLPIs {} and {}, \
         doorbell LPI {doorbell}",
        vpe.id(),
        VLPI[0],
        VLPI[1]
    );

    // Not resident: the vLPI waits in the vPE's table and the doorbell rings.
    its.trigger(DEVICE, 0)?;
    let rang = take(doorbell);
    let waiting = vpe.is_pending(VLPI[0]);
    println!(
        "[vlpi]  vPE {} not resident: INT for event 0 {} vLPI {} in its pending table and {} the doorbell, physical LPI {doorbell}",
        vpe.id(),
        if waiting { "left" } else { "did NOT leave" },
        VLPI[0],
        if rang { "rang" } else { "did NOT ring" }
    );

    let outcome = run_guest(gic, &its, &vm, &vpe);

    its.remove_device(DEVICE, tables)?;
    its.unmap_vpe(&vpe)?;
    tables.free(doorbell);
    let (exit, first, second, exits) = outcome?;
    println!(
        "[vlpi]  guest exit {exit:?}: took vLPI {first} (pending while away) then vLPI {second} (INT while resident) \
         through ICC_IAR1_EL1, {exits} exits"
    );
    Ok(())
}

/// Runs the guest with the vPE resident on this CPU; returns its exit, the
/// two interrupt IDs it acknowledged and how many exits it took.
fn run_guest(
    gic: &osmium::sysdrv::gicv3::GicV3<crate::El2Regs>,
    its: &Its<'_, Frames>,
    vm: &VlpiTables<'_, Frames>,
    vpe: &Vpe<'_, Frames>,
) -> Result<(VmExit, u64, u64, u32), Error> {
    let ram = FRAMES.lock().alloc(GUEST_RAM_ORDER).ok_or(Error::Other("no memory for the guest"))?;
    let len = (PAGE_SIZE as u64) << GUEST_RAM_ORDER;
    let mut mem = GuestMemory::new();
    // SAFETY: a fresh block owned by this demo, reached only through `mem`
    // and the guest until it is freed below.
    unsafe { mem.add_region(GUEST_RAM, ram.0 as *mut u8, len) };
    // SAFETY: linker symbols bounding the guest image in .rodata.
    let image = unsafe { image(&vlpi_guest, &vlpi_guest_end) };
    mem.write(GUEST_RAM, image).map_err(|_| Error::Other("guest image"))?;
    let mut s2: Stage2Table<_> = PageTable::new(&FRAMES).map_err(|_| Error::Other("stage-2 root"))?;
    map_guest_memory(&mut s2, &mem, |p| PhysAddr::new(p as u64)).map_err(|_| Error::Other("stage 2"))?;

    // The guest uses the virtual CPU interface (ICH_HCR_EL2.En), so it gets a
    // virtual GICv3, though nothing is ever injected through the model.
    let mem = Arc::new(mem);
    let vcpu = Aarch64Vcpu::new(GUEST_RAM, 0, vttbr(s2.root(), 9)).with_memory(mem.clone());
    let irq = vcpu.irq_line();
    let vgic = Arc::new(VirtualGicV3::new(1, 64, move |_, level: bool| irq.store(level, Ordering::Release)));
    let mut vcpu = vcpu.with_vgic_v3(vgic, 0);
    let (mmio, pio) = (Bus::new(), Bus::new());

    gic.make_vpe_resident(vm, vpe)?;
    let raised = AtomicBool::new(false);
    let mut exits = 0u32;
    let deadline = Uptime.now_ns() + 2_000_000_000;
    let exit = run_vcpu(&mut vcpu, &mmio, &pio, |v, exit| {
        exits += 1;
        if Uptime.now_ns() > deadline {
            return ControlFlow::Break(exit);
        }
        match exit {
            VmExit::Hypercall { nr: RAISE, .. } => {
                raised.store(its.trigger(DEVICE, 1).is_ok(), Ordering::Relaxed);
                ControlFlow::Continue(())
            }
            VmExit::Hypercall { .. } => match vm::psci::handle(v, exit) {
                Some(vm::psci::Outcome::Shutdown) => ControlFlow::Break(VmExit::Shutdown),
                _ => ControlFlow::Continue(()),
            },
            // The guest's `wfi`s: just let it look again.
            VmExit::Halt => ControlFlow::Continue(()),
            VmExit::ExternalInterrupt => {
                let _ = crate::ack_irq();
                ControlFlow::Continue(())
            }
            other => ControlFlow::Break(other),
        }
    });
    let left_pending = gic.make_vpe_nonresident();

    let (first, second) = (vcpu.state.x[20] & 0xff_ffff, vcpu.state.x[21] & 0xff_ffff);
    drop(vcpu);
    drop(s2);
    drop(mem);
    // SAFETY: the guest has stopped and nothing references its RAM.
    unsafe { FRAMES.lock().dealloc(ram, GUEST_RAM_ORDER) };
    if left_pending? {
        println!("[vlpi]  a vLPI was still pending when the vPE left");
    }
    if !raised.load(Ordering::Relaxed) {
        return Err(Error::Other("INT for event 1 failed"));
    }
    Ok((exit, first, second, exits))
}
