//! What the interpreter needs from the machine it runs on.

use alloc::string::String;

/// Why a [`Host`] access failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    /// The host does not implement this kind of access.
    Unsupported,
    /// The access was attempted and failed (bad address, no such device, timeout).
    Fault,
}

/// The location of a PCI function.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PciAddress {
    /// The PCI segment group (`_SEG`).
    pub segment: u16,
    /// The bus number.
    pub bus: u8,
    /// The device number, 0 to 31.
    pub device: u8,
    /// The function number, 0 to 7.
    pub function: u8,
}

/// Address-space ids of operation regions (ACPI 6.5 table 19.x, `OperationRegion`).
pub mod space {
    /// Physical memory.
    pub const SYSTEM_MEMORY: u8 = 0;
    /// Port I/O.
    pub const SYSTEM_IO: u8 = 1;
    /// PCI configuration space.
    pub const PCI_CONFIG: u8 = 2;
    /// Embedded controller.
    pub const EMBEDDED_CONTROL: u8 = 3;
    /// SMBus.
    pub const SMBUS: u8 = 4;
    /// CMOS.
    pub const SYSTEM_CMOS: u8 = 5;
    /// A PCI BAR.
    pub const PCI_BAR_TARGET: u8 = 6;
    /// IPMI.
    pub const IPMI: u8 = 7;
    /// General-purpose I/O.
    pub const GPIO: u8 = 8;
    /// A serial bus behind a general-purpose bus.
    pub const GENERIC_SERIAL_BUS: u8 = 9;
    /// A platform communications channel.
    pub const PCC: u8 = 10;
}

/// The machine under the interpreter: memory, ports, PCI configuration space, time and the OS's answers
/// to the firmware.
///
/// Every access method has a default that refuses with [`HostError::Unsupported`], so a host implements
/// what its machine has. `bits` is always 8, 16, 32 or 64 and the access is aligned to it relative to the start of its operation
/// region (I/O port and PCI configuration accesses are never wider than 32 bits).
/// The interpreter never calls the host re-entrantly, so a host may be a plain struct holding the mappings
/// it needs.
pub trait Host {
    /// Reads `bits` bits of physical memory at `addr`.
    fn read_memory(&mut self, addr: u64, bits: u8) -> Result<u64, HostError> {
        let _ = (addr, bits);
        Err(HostError::Unsupported)
    }

    /// Writes `bits` bits of physical memory at `addr`.
    fn write_memory(&mut self, addr: u64, bits: u8, value: u64) -> Result<(), HostError> {
        let _ = (addr, bits, value);
        Err(HostError::Unsupported)
    }

    /// Reads `bits` bits from I/O port `port`.
    fn read_io(&mut self, port: u16, bits: u8) -> Result<u64, HostError> {
        let _ = (port, bits);
        Err(HostError::Unsupported)
    }

    /// Writes `bits` bits to I/O port `port`.
    fn write_io(&mut self, port: u16, bits: u8, value: u64) -> Result<(), HostError> {
        let _ = (port, bits, value);
        Err(HostError::Unsupported)
    }

    /// Reads `bits` bits of PCI configuration space at byte `offset`.
    fn read_pci(&mut self, addr: PciAddress, offset: u16, bits: u8) -> Result<u64, HostError> {
        let _ = (addr, offset, bits);
        Err(HostError::Unsupported)
    }

    /// Writes `bits` bits of PCI configuration space at byte `offset`.
    fn write_pci(&mut self, addr: PciAddress, offset: u16, bits: u8, value: u64) -> Result<(), HostError> {
        let _ = (addr, offset, bits, value);
        Err(HostError::Unsupported)
    }

    /// Reads from an operation region in any other address space (see [`space`]), such as the embedded
    /// controller. `offset` is the region's offset plus the field's byte offset.
    fn read_region(&mut self, space: u8, offset: u64, bits: u8) -> Result<u64, HostError> {
        let _ = (space, offset, bits);
        Err(HostError::Unsupported)
    }

    /// Writes to an operation region in any other address space.
    fn write_region(&mut self, space: u8, offset: u64, bits: u8, value: u64) -> Result<(), HostError> {
        let _ = (space, offset, bits, value);
        Err(HostError::Unsupported)
    }

    /// Whether the host serves operation regions in `space`. The interpreter calls `_REG(space, 1)` for
    /// each served space that a device's regions use. The default serves memory, I/O and PCI
    /// configuration space.
    fn serves_region(&mut self, space: u8) -> bool {
        matches!(space, space::SYSTEM_MEMORY | space::SYSTEM_IO | space::PCI_CONFIG)
    }

    /// Busy-waits `micros` microseconds (`Stall`). The default returns at once.
    fn stall(&mut self, micros: u32) {
        let _ = micros;
    }

    /// Sleeps `millis` milliseconds (`Sleep`). The default returns at once.
    fn sleep(&mut self, millis: u32) {
        let _ = millis;
    }

    /// A monotonic count of 100 ns ticks (`Timer`).
    fn timer(&mut self) -> u64 {
        0
    }

    /// The `Notify` operator: `value` was sent to the object at `path` (for example `\_SB_.PWRB`).
    fn notify(&mut self, path: &str, value: u8) {
        let _ = (path, value);
    }

    /// A value stored to the `Debug` object, formatted.
    fn debug(&mut self, message: &str) {
        let _ = message;
    }

    /// The `Fatal` operator ran. The interpreter then fails the running method with
    /// [`AmlError::Fatal`](super::AmlError::Fatal).
    fn fatal(&mut self, kind: u8, code: u32, arg: u64) {
        let _ = (kind, code, arg);
    }

    /// Whether the OS claims the interface or feature named `name` in `_OSI`. The default accepts the
    /// OS-neutral feature strings and no OS vendor's.
    fn supports_interface(&mut self, name: &str) -> bool {
        matches!(
            name,
            "Module Device"
                | "Processor Device"
                | "3.0 _SCP Extensions"
                | "Processor Aggregator Device"
                | "Extended Address Space Descriptor"
        )
    }

    /// The table `LoadTable` asks for, if the host has one. Unused by default.
    fn find_table(&mut self, signature: [u8; 4], oem_id: &[u8], oem_table_id: &[u8]) -> Option<String> {
        let _ = (signature, oem_id, oem_table_id);
        None
    }
}
