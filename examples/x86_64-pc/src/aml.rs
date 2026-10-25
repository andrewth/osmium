//! The firmware's AML: the DSDT's devices, resources and interrupt routing, and power off through `_S5_`.

use osmium::acpi::aml::{Config, Host, HostError, Interpreter, PciAddress, ROOT};
use osmium::acpi::fadt::Fadt;
use osmium::acpi::pm::Pm;
use osmium::acpi::resource::{AddressKind, Resource};
use osmium::arch::x86_64 as x86;
use osmium::boot::acpi::Acpi;
use osmium::hal::println;
use osmium::sync::{IrqSpinLock, Once};

/// Memory below this is identity-mapped by the boot page tables, which is all AML may touch.
const MAPPED: u64 = 1 << 32;

/// The PC as AML sees it: memory (the boot tables' identity map), port I/O, and PCI configuration space
/// through the legacy 0xCF8/0xCFC mechanism, which reaches the first 256 bytes of segment 0.
struct PcHost;

impl PcHost {
    fn pci_address(addr: PciAddress, offset: u16) -> Result<u32, HostError> {
        if addr.segment != 0 || offset >= 256 || addr.device >= 32 || addr.function >= 8 {
            return Err(HostError::Unsupported);
        }
        Ok(0x8000_0000
            | u32::from(addr.bus) << 16
            | u32::from(addr.device) << 11
            | u32::from(addr.function) << 8
            | u32::from(offset & 0xfc))
    }
}

impl Host for PcHost {
    fn read_memory(&mut self, addr: u64, bits: u8) -> Result<u64, HostError> {
        let len = u64::from(bits / 8);
        if addr.checked_add(len).is_none_or(|end| end > MAPPED) {
            return Err(HostError::Fault);
        }
        let mut v = 0u64;
        for i in 0..len {
            // SAFETY: inside the first 4 GiB, which the boot page tables identity-map (RAM and the
            // devices' MMIO windows); firmware describes what lives there.
            let b = unsafe { core::ptr::read_volatile((addr + i) as *const u8) };
            v |= u64::from(b) << (8 * i);
        }
        Ok(v)
    }

    fn write_memory(&mut self, addr: u64, bits: u8, value: u64) -> Result<(), HostError> {
        let len = u64::from(bits / 8);
        if addr.checked_add(len).is_none_or(|end| end > MAPPED) {
            return Err(HostError::Fault);
        }
        for i in 0..len {
            // SAFETY: as in `read_memory`.
            unsafe { core::ptr::write_volatile((addr + i) as *mut u8, (value >> (8 * i)) as u8) };
        }
        Ok(())
    }

    fn read_io(&mut self, port: u16, bits: u8) -> Result<u64, HostError> {
        // SAFETY: port I/O on the PC platform; firmware knows which ports are its own.
        Ok(unsafe {
            match bits {
                8 => u64::from(x86::inb(port)),
                16 => u64::from(x86::inw(port)),
                _ => u64::from(x86::inl(port)),
            }
        })
    }

    fn write_io(&mut self, port: u16, bits: u8, value: u64) -> Result<(), HostError> {
        // SAFETY: as in `read_io`.
        unsafe {
            match bits {
                8 => x86::outb(port, value as u8),
                16 => x86::outw(port, value as u16),
                _ => x86::outl(port, value as u32),
            }
        }
        Ok(())
    }

    fn read_pci(&mut self, addr: PciAddress, offset: u16, bits: u8) -> Result<u64, HostError> {
        let cfg = Self::pci_address(addr, offset)?;
        let data = 0xcfc + (offset & 3);
        // SAFETY: the configuration mechanism's address and data ports.
        Ok(unsafe {
            x86::outl(0xcf8, cfg);
            match bits {
                8 => u64::from(x86::inb(data)),
                16 => u64::from(x86::inw(data)),
                _ => u64::from(x86::inl(data)),
            }
        })
    }

    fn write_pci(&mut self, addr: PciAddress, offset: u16, bits: u8, value: u64) -> Result<(), HostError> {
        let cfg = Self::pci_address(addr, offset)?;
        let data = 0xcfc + (offset & 3);
        // SAFETY: as in `read_pci`.
        unsafe {
            x86::outl(0xcf8, cfg);
            match bits {
                8 => x86::outb(data, value as u8),
                16 => x86::outw(data, value as u16),
                _ => x86::outl(data, value as u32),
            }
        }
        Ok(())
    }

    fn stall(&mut self, micros: u32) {
        // A read of the POST diagnostic port takes about a microsecond on a PC.
        for _ in 0..micros {
            // SAFETY: port 0x80 is the conventional delay port.
            unsafe { x86::inb(0x80) };
        }
    }

    fn notify(&mut self, path: &str, value: u8) {
        println!("[aml]   Notify({path}, {value:#x})");
    }
}

struct Machine {
    aml: Interpreter<PcHost>,
    pm: Pm,
}

static MACHINE: Once<IrqSpinLock<Machine>> = Once::new();

/// Loads the DSDT and SSDTs from the tables at `rsdp`, runs `_REG` and `_INI`, reports what the firmware
/// describes, and keeps the interpreter for [`power_off`].
pub fn init(rsdp: u64) {
    // SAFETY: the boot tables identity-map the first 4 GiB, where QEMU's ACPI tables live; they are only read.
    let read = |pa: u64, len: usize| Some(unsafe { core::slice::from_raw_parts(pa as *const u8, len) });
    let Ok(acpi) = Acpi::new(rsdp, read) else {
        println!("[aml]   no usable RSDT");
        return;
    };
    let Some(fadt) = acpi.find(b"FACP").and_then(Fadt::parse) else {
        println!("[aml]   no FADT");
        return;
    };
    let mut aml = Interpreter::new(PcHost, Config::default());
    let report = match aml.load_tables(&acpi) {
        Ok(r) => r,
        Err(e) => {
            println!("[aml]   no DSDT: {e}");
            return;
        }
    };
    let objects = aml.namespace().descendants(ROOT).len();
    let devices = aml.devices().len();
    println!(
        "[aml]   {} tables loaded ({} failed): {objects} objects, {devices} devices",
        report.loaded.len(),
        report.failed.len()
    );
    let init = aml.initialize();
    println!(
        "[aml]   _REG run {} times, _INI {} times, {} methods failed",
        init.reg_run,
        init.ini_run,
        init.errors.len()
    );
    for (path, e) in &init.errors {
        println!("[aml]     {path}: {e}");
    }

    // The host bridge: its resources and where PCI interrupts go.
    if let Some(&bridge) = aml.find_devices("PNP0A08").first() {
        let path = aml.namespace().path(bridge);
        let resources = aml.current_resources(bridge).unwrap_or_default();
        let bus = resources.iter().find_map(|r| match r {
            Resource::Address(a) if a.kind == AddressKind::BusNumber => Some((a.min, a.max)),
            _ => None,
        });
        println!("[aml]   host bridge {path} (PNP0A08): {} resources, buses {:?}", resources.len(), bus);
        match aml.pci_routing_table(bridge) {
            Ok(prt) => {
                let mut routed = None;
                for e in &prt {
                    if let Ok(Some(r)) = aml.route_pci_irq(bridge, e.device, e.function.unwrap_or(0), e.pin) {
                        routed = Some((e.device, e.pin, r));
                        break;
                    }
                }
                if let Some((dev, pin, r)) = routed {
                    println!(
                        "[aml]   PCI routing: {} rows; device {dev} INT{} -> GSI {} ({}, active {})",
                        prt.len(),
                        char::from(b'A' + pin),
                        r.gsi,
                        if r.level_triggered { "level" } else { "edge" },
                        if r.active_low { "low" } else { "high" }
                    );
                } else {
                    println!("[aml]   PCI routing: {} rows, none resolved", prt.len());
                }
            }
            Err(e) => println!("[aml]   no _PRT: {e}"),
        }
    }

    let pm = Pm::new(fadt);
    match pm.sleep_types(&mut aml, 5) {
        Ok((a, b)) => println!("[aml]   \\_S5_ sleep type {a}/{b}"),
        Err(e) => println!("[aml]   no \\_S5_: {e:?}"),
    }
    match pm.enable(aml.host_mut()) {
        Ok(()) => println!("[acpi]  ACPI mode on, SCI on IRQ {}", pm.fadt().sci_int),
        Err(e) => println!("[acpi]  could not enter ACPI mode: {e:?}"),
    }
    println!("[aml]   deepest nesting {} of {}", aml.peak_depth(), Config::default().max_depth);
    MACHINE.call_once(|| IrqSpinLock::new(Machine { aml, pm }));
}

/// Powers off through the firmware's `\_S5_`. Returns if there is no ACPI to do it with, or it failed.
pub fn power_off() {
    let Some(m) = MACHINE.get() else { return };
    let mut m = m.lock();
    let Machine { aml, pm } = &mut *m;
    println!("[acpi]  powering off through \\_S5_");
    if let Err(e) = pm.power_off(aml) {
        println!("[acpi]  power off failed: {e:?}");
    }
}
