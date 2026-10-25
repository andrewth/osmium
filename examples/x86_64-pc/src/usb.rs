//! USB 1.1 and 2.0 host controllers under QEMU: the EHCI controller
//! first, so that it hands the low- and full-speed devices on its ports to
//! its companion UHCI controllers, then every UHCI controller on bus 0
//! (reached through its I/O ports, BAR 4). Each runs the shared USB demo on
//! whatever is plugged into its root ports.
//!
//! The controllers complete by interrupt as well as by polling. They have no
//! MSI, only a PCI INTx line, and finding which I/O APIC input a function's
//! line reaches takes the AML `_PRT`. This example has no AML interpreter, so
//! it routes all of the q35 chipset's PCI inputs ([`PCI_GSIS`]) to [`VECTOR`],
//! where [`on_interrupt`] asks every controller whether the line is its own.
//! Nothing else on this machine raises INTx.

use alloc::vec::Vec;

use osmium::boot::acpi::EcamWindow;
use osmium::usb::ehci::{self, Ehci};
use osmium::drivers::ioapic::{IoApic, LineMode};
use osmium::usb::uhci::{self, Uhci, UhciRegs};
use osmium::hal::mmio::IoMem;
use osmium::hal::pci::{self, BarKind, Function, command};
use osmium::hal::println;
use osmium::mm::PAGE_SIZE;
use osmium::sync::{IrqSpinLock, Once};

use crate::Frames;
use crate::msi::{Uptime, map};

/// The IDT vector the controllers' INTx lines are routed to.
pub const VECTOR: u8 = 0x51;

/// The I/O APIC inputs of the ICH9's PIRQ A to H lines.
const PCI_GSIS: core::ops::Range<u32> = 16..24;

/// UHCI controllers driven at most: one on its own and an ICH9's three
/// EHCI companions.
const MAX_UHCI: usize = 4;

/// The controllers, in statics so the drivers built on them (and a file
/// system on a USB stick) can live as long as the kernel. EHCI must stay
/// up, too: dropping it would route its ports back to the companions.
static EHCI: Once<IrqSpinLock<Ehci<'static, Frames>>> = Once::new();
static UHCI: [Once<IrqSpinLock<Uhci<'static, Frames>>>; MAX_UHCI] = [const { Once::new() }; MAX_UHCI];

/// Handles [`VECTOR`]: every controller acknowledges its own interrupt, and
/// ignores the line if it was not asserting it.
pub fn on_interrupt() {
    if let Some(ehci) = EHCI.get() {
        ehci.lock().handle_interrupt();
    }
    for uhci in &UHCI {
        if let Some(uhci) = uhci.get() {
            uhci.lock().handle_interrupt();
        }
    }
    crate::LAPIC.get().expect("LAPIC initialised").eoi();
}

/// Routes the PCI interrupt inputs to [`VECTOR`] on this CPU. False if the
/// MADT listed no I/O APIC.
fn route_pci_lines() -> bool {
    let Some(&(io_addr, gsi_base, ..)) = crate::IOAPIC_INFO.get() else { return false };
    // SAFETY: the MADT says the I/O APIC lives here; mapped uncached at boot.
    let ioapic = IoApic::new(unsafe { IoMem::new(io_addr as *mut u8, PAGE_SIZE) }, gsi_base);
    let dest = crate::LAPIC.get().expect("LAPIC initialised").id() as u8;
    // PCI lines are active low and level triggered.
    let mode = LineMode { active_low: true, level: true };
    for gsi in PCI_GSIS {
        ioapic.route(gsi, VECTOR, dest, mode);
    }
    true
}

/// Runs the USB demo on the first EHCI controller and every UHCI
/// controller on bus 0.
pub fn demo(ecam: Option<EcamWindow>) {
    let Some(ecam) = ecam else {
        println!("[usb]   no ECAM window; skipping EHCI and UHCI");
        return;
    };
    let cfg = pci::Ecam::new(map(ecam.base, 1 << 20), 0);
    let irq = route_pci_lines();
    if !irq {
        println!("[usb]   no I/O APIC in the MADT; polling");
    }
    let (mut ehcis, mut uhcis) = (Vec::new(), Vec::new());
    pci::for_each_function(&cfg, 0, |f| match f.class() {
        pci::Class::EHCI => ehcis.push(f.address()),
        uhci::CLASS => uhcis.push(f.address()),
        _ => {}
    });
    match ehcis.first().and_then(|&a| Function::new(&cfg, a)) {
        Some(func) => run_ehci(&func, irq),
        None => println!("[usb]   no EHCI controller"),
    }
    if uhcis.is_empty() {
        println!("[usb]   no UHCI controller");
    }
    for (slot, &a) in UHCI.iter().zip(&uhcis) {
        if let Some(func) = Function::new(&cfg, a) {
            run_uhci(&func, slot, irq);
        }
    }
}

fn run_ehci(func: &Function<'_, pci::Ecam>, irq: bool) {
    let a = func.address();
    let Some(bar) = func.bar(0).filter(|b| b.kind != BarKind::Io && b.address != 0) else {
        println!("[usb]   EHCI {:02x}:{:02x}.{}: no registers in BAR 0", a.bus, a.device, a.function);
        return;
    };
    func.enable_memory_and_dma();
    let io = map(bar.address, bar.size);
    ehci::release_from_firmware(func, &io, &Uptime);
    match Ehci::new(io, &crate::FRAMES, &Uptime) {
        Ok(hc) => {
            println!(
                "[usb]   EHCI at {:02x}:{:02x}.{} BAR0 {:#x}, {} ports",
                a.bus,
                a.device,
                a.function,
                bar.address,
                hc.ports()
            );
            let ehci = EHCI.call_once(|| IrqSpinLock::new(hc));
            if irq {
                ehci.lock().enable_interrupts();
            }
            demos::usb(ehci, crate::now_ns);
            println!("[usb]   EHCI interrupts: {}", ehci.lock().interrupts_handled());
        }
        Err(e) => println!("[usb]   EHCI init failed: {e:?}"),
    }
}

fn run_uhci(func: &Function<'_, pci::Ecam>, slot: &'static Once<IrqSpinLock<Uhci<'static, Frames>>>, irq: bool) {
    let a = func.address();
    // SeaBIOS assigned the I/O window; probing it turns decoding off, so
    // the command register is set afterwards.
    let Some(bar) = func.bar(4).filter(|b| b.kind == BarKind::Io && b.address != 0) else {
        println!("[usb]   UHCI {:02x}:{:02x}.{}: no I/O window in BAR 4", a.bus, a.device, a.function);
        return;
    };
    func.set_command(func.command() | command::IO_SPACE | command::BUS_MASTER);
    uhci::release_from_firmware(func);
    // SAFETY: BAR 4 is this controller's I/O window, and nothing else
    // drives the controller.
    let regs = unsafe { UhciRegs::ports(bar.address as u16) };
    match Uhci::new(regs, &crate::FRAMES, &Uptime) {
        Ok(hc) => {
            println!(
                "[usb]   UHCI at {:02x}:{:02x}.{} ports {:#x}, {} ports",
                a.bus,
                a.device,
                a.function,
                bar.address,
                hc.ports()
            );
            let uhci = slot.call_once(|| IrqSpinLock::new(hc));
            if irq {
                uhci.lock().enable_interrupts();
            }
            demos::usb(uhci, crate::now_ns);
            println!("[usb]   UHCI interrupts: {}", uhci.lock().interrupts_handled());
        }
        Err(e) => println!("[usb]   UHCI init failed: {e:?}"),
    }
}
