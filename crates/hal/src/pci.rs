//! PCI and PCI Express configuration space.
//!
//! [`ConfigAccess`] reads and writes configuration dwords; [`Ecam`]
//! implements it over a memory-mapped ECAM window (the device tree's
//! `pci-host-ecam-generic`, ACPI's MCFG), and on x86 `PortIo` implements it
//! with ports `0xcf8`/`0xcfc`. [`Function`] interprets a
//! function's type 0 header on top of any access method: identification,
//! command bits, BAR probing and assignment, and the capability list.
//!
//! On machines whose firmware leaves BARs unassigned (QEMU `virt` booted
//! with OpenSBI, for one), [`BarAllocator`] hands out addresses from the host
//! bridge's memory window.
//!
//! [`Function::msi`] and [`Function::msix`] program message-signalled
//! interrupts ([`MsiMessage`]).
//!
//! [`Function::extended_capabilities`] walks PCIe extended configuration
//! space, and [`Function::sriov`] turns a function's virtual functions on and
//! off.

use crate::mmio::IoMem;

mod msi;
pub use msi::{Msi, MsiError, MsiMessage, Msix, MsixPba, MsixTable};

mod sriov;
pub use sriov::{ExtCapabilities, SrIov, SrIovError, ext_cap};

/// Bus, device and function numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    /// Bus, 0–255.
    pub bus: u8,
    /// Device, 0–31.
    pub device: u8,
    /// Function, 0–7.
    pub function: u8,
}

impl Address {
    /// Bus `bus`, device `device`, function `function`.
    ///
    /// # Panics
    ///
    /// If `device` is 32 or more, or `function` is 8 or more.
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        assert!(device < 32 && function < 8);
        Self { bus, device, function }
    }
}

/// Reads and writes configuration space.
pub trait ConfigAccess {
    /// Reads the dword at `offset` (a multiple of 4) of `addr`'s space.
    /// Returns `0xffff_ffff` where no function responds.
    fn read32(&self, addr: Address, offset: u16) -> u32;

    /// Writes the dword at `offset` (a multiple of 4) of `addr`'s space.
    fn write32(&self, addr: Address, offset: u16, value: u32);

    /// Highest bus number reachable through this access method.
    fn max_bus(&self) -> u8 {
        255
    }
}

/// Enhanced Configuration Access Mechanism: 4 KiB of configuration space per
/// function, memory-mapped at `bus << 20 | device << 15 | function << 12`.
pub struct Ecam {
    io: IoMem,
    first_bus: u8,
}

impl Ecam {
    /// Uses the ECAM window `io`, whose first megabyte is bus `first_bus`
    /// (the device tree's `bus-range` start). The window's length decides
    /// how many buses are reachable.
    pub fn new(io: IoMem, first_bus: u8) -> Self {
        Self { io, first_bus }
    }

    fn offset(&self, addr: Address, offset: u16) -> Option<usize> {
        let bus = addr.bus.checked_sub(self.first_bus)? as usize;
        // Offsets past the 4 KiB function space are not accessible (reads give all ones).
        if offset >= 0x1000 {
            return None;
        }
        Some(bus << 20 | (addr.device as usize) << 15 | (addr.function as usize) << 12 | (offset as usize & 0xffc))
    }
}

impl ConfigAccess for Ecam {
    fn read32(&self, addr: Address, offset: u16) -> u32 {
        self.offset(addr, offset).and_then(|o| self.io.read(o).ok()).unwrap_or(!0)
    }

    fn write32(&self, addr: Address, offset: u16, value: u32) {
        if let Some(o) = self.offset(addr, offset) {
            let _ = self.io.write(o, value);
        }
    }

    fn max_bus(&self) -> u8 {
        let buses = (self.io.len() >> 20).max(1);
        (self.first_bus as usize + buses - 1).min(255) as u8
    }
}

/// x86 configuration mechanism #1: an address written to port `0xcf8`
/// selects the dword that port `0xcfc` reads or writes. It reaches only the
/// first 256 bytes of each function; use [`Ecam`] (from ACPI's MCFG) for
/// PCIe extended configuration space.
#[cfg(target_arch = "x86_64")]
pub struct PortIo {
    // The address/data pair must not interleave with another CPU's, or with
    // an interrupt handler's on this CPU.
    lock: osmium_sync::SpinLock<(), osmium_sync::IrqDisabled>,
}

#[cfg(target_arch = "x86_64")]
impl PortIo {
    const ADDRESS: u16 = 0xcf8;
    const DATA: u16 = 0xcfc;

    /// Uses ports `0xcf8` and `0xcfc`.
    ///
    /// # Safety
    /// Nothing else may use those ports while this exists (create one per
    /// system and share it).
    pub const unsafe fn new() -> Self {
        Self { lock: osmium_sync::SpinLock::new(()) }
    }

    fn select(addr: Address, offset: u16) {
        let v = 1 << 31
            | (addr.bus as u32) << 16
            | (addr.device as u32) << 11
            | (addr.function as u32) << 8
            | (offset as u32 & 0xfc);
        // SAFETY: the ports are ours per `new`.
        unsafe { osmium_arch::x86_64::outl(Self::ADDRESS, v) }
    }
}

#[cfg(target_arch = "x86_64")]
impl ConfigAccess for PortIo {
    fn read32(&self, addr: Address, offset: u16) -> u32 {
        if offset >= 256 {
            return !0;
        }
        let _guard = self.lock.lock();
        Self::select(addr, offset);
        // SAFETY: the ports are ours per `new`.
        unsafe { osmium_arch::x86_64::inl(Self::DATA) }
    }

    fn write32(&self, addr: Address, offset: u16, value: u32) {
        if offset >= 256 {
            return;
        }
        let _guard = self.lock.lock();
        Self::select(addr, offset);
        // SAFETY: the ports are ours per `new`.
        unsafe { osmium_arch::x86_64::outl(Self::DATA, value) }
    }
}

/// Configuration header offsets.
pub mod reg {
    #![allow(missing_docs)]
    pub const VENDOR_DEVICE: u16 = 0x00;
    pub const COMMAND_STATUS: u16 = 0x04;
    pub const CLASS_REVISION: u16 = 0x08;
    pub const HEADER_TYPE: u16 = 0x0c;
    pub const BAR0: u16 = 0x10;
    pub const SUBSYSTEM: u16 = 0x2c;
    pub const CAPABILITIES: u16 = 0x34;
    pub const INTERRUPT: u16 = 0x3c;
}

/// Command register bits.
pub mod command {
    #![allow(missing_docs)]
    pub const IO_SPACE: u16 = 1 << 0;
    pub const MEMORY_SPACE: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const INTX_DISABLE: u16 = 1 << 10;
}

/// Capability IDs.
pub mod cap {
    #![allow(missing_docs)]
    pub const POWER_MANAGEMENT: u8 = 0x01;
    pub const MSI: u8 = 0x05;
    pub const VENDOR: u8 = 0x09;
    pub const PCI_EXPRESS: u8 = 0x10;
    pub const MSIX: u8 = 0x11;
}

/// Class, subclass and programming interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Class {
    /// Base class.
    pub class: u8,
    /// Subclass.
    pub subclass: u8,
    /// Programming interface.
    pub prog_if: u8,
}

impl Class {
    /// USB xHCI controller (0c/03/30).
    pub const XHCI: Self = Self { class: 0x0c, subclass: 0x03, prog_if: 0x30 };
    /// USB EHCI controller (0c/03/20).
    pub const EHCI: Self = Self { class: 0x0c, subclass: 0x03, prog_if: 0x20 };
    /// NVMe controller (01/08/02).
    pub const NVME: Self = Self { class: 0x01, subclass: 0x08, prog_if: 0x02 };
    /// System IOMMU (08/06/00), such as the RISC-V IOMMU PCI function.
    pub const IOMMU: Self = Self { class: 0x08, subclass: 0x06, prog_if: 0x00 };
    /// Ethernet controller (02/00/00).
    pub const ETHERNET: Self = Self { class: 0x02, subclass: 0x00, prog_if: 0x00 };
}

/// What a BAR decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarKind {
    /// I/O ports.
    Io,
    /// Memory below 4 GiB.
    Memory32 {
        /// Reads have no side effects.
        prefetchable: bool,
    },
    /// Memory anywhere; occupies this BAR and the next.
    Memory64 {
        /// Reads have no side effects.
        prefetchable: bool,
    },
}

/// A probed base address register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bar {
    /// BAR index, 0–5.
    pub index: u8,
    /// What it decodes.
    pub kind: BarKind,
    /// Current bus address (0 if unassigned).
    pub address: u64,
    /// Size in bytes (a power of two).
    pub size: u64,
}

/// One PCI function, reached through `C`.
pub struct Function<'cfg, C: ConfigAccess + ?Sized> {
    cfg: &'cfg C,
    addr: Address,
}

impl<'cfg, C: ConfigAccess + ?Sized> Function<'cfg, C> {
    /// The function at `addr`, or `None` if nothing responds there.
    pub fn new(cfg: &'cfg C, addr: Address) -> Option<Self> {
        let f = Self { cfg, addr };
        (f.vendor_id() != 0xffff).then_some(f)
    }

    /// Its address.
    pub fn address(&self) -> Address {
        self.addr
    }

    /// Reads a configuration dword.
    pub fn read32(&self, offset: u16) -> u32 {
        self.cfg.read32(self.addr, offset)
    }

    /// Writes a configuration dword.
    pub fn write32(&self, offset: u16, value: u32) {
        self.cfg.write32(self.addr, offset, value)
    }

    /// Reads a configuration word (`offset` a multiple of 2).
    pub fn read16(&self, offset: u16) -> u16 {
        (self.read32(offset & !3) >> ((offset & 2) * 8)) as u16
    }

    /// Reads a configuration byte.
    pub fn read8(&self, offset: u16) -> u8 {
        (self.read32(offset & !3) >> ((offset & 3) * 8)) as u8
    }

    /// Vendor ID.
    pub fn vendor_id(&self) -> u16 {
        self.read16(reg::VENDOR_DEVICE)
    }

    /// Device ID.
    pub fn device_id(&self) -> u16 {
        self.read16(reg::VENDOR_DEVICE + 2)
    }

    /// Class code.
    pub fn class(&self) -> Class {
        let v = self.read32(reg::CLASS_REVISION);
        Class { class: (v >> 24) as u8, subclass: (v >> 16) as u8, prog_if: (v >> 8) as u8 }
    }

    /// Header type, without the multi-function bit (0 for an endpoint, 1
    /// for a PCI-to-PCI bridge).
    pub fn header_type(&self) -> u8 {
        self.read8(reg::HEADER_TYPE + 2) & 0x7f
    }

    /// True if function 0 of this device reports more functions.
    pub fn is_multi_function(&self) -> bool {
        self.read8(reg::HEADER_TYPE + 2) & 0x80 != 0
    }

    /// The command register.
    pub fn command(&self) -> u16 {
        self.read16(reg::COMMAND_STATUS)
    }

    /// Writes the command register. The status half of the dword is written
    /// as zero, which leaves its write-1-to-clear bits alone.
    pub fn set_command(&self, value: u16) {
        self.write32(reg::COMMAND_STATUS, value as u32);
    }

    /// Enables memory decoding and bus mastering (DMA), as a driver does
    /// before touching a device's MMIO BARs.
    pub fn enable_memory_and_dma(&self) {
        self.set_command(self.command() | command::MEMORY_SPACE | command::BUS_MASTER);
    }

    /// Legacy interrupt pin (1 = INTA# .. 4 = INTD#; 0 = none).
    pub fn interrupt_pin(&self) -> u8 {
        self.read8(reg::INTERRUPT + 1)
    }

    /// Probes BAR `index` by writing all ones and reading back the size
    /// mask, then restores it. Returns `None` for an unimplemented BAR or
    /// the upper half of a 64-bit BAR. Memory and I/O decoding are switched
    /// off during the probe; call it before the driver uses the device.
    pub fn bar(&self, index: u8) -> Option<Bar> {
        if index >= 6 || self.header_type() != 0 {
            return None;
        }
        let off = reg::BAR0 + index as u16 * 4;
        let lo = self.read32(off);
        let kind = if lo & 1 != 0 {
            BarKind::Io
        } else {
            let prefetchable = lo & 8 != 0;
            match lo >> 1 & 3 {
                0 => BarKind::Memory32 { prefetchable },
                2 if index < 5 => BarKind::Memory64 { prefetchable },
                _ => return None,
            }
        };

        let cmd = self.command();
        self.set_command(cmd & !(command::MEMORY_SPACE | command::IO_SPACE));
        self.write32(off, !0);
        let mask_lo = self.read32(off);
        self.write32(off, lo);
        let (address, mask) = if let BarKind::Memory64 { .. } = kind {
            let hi = self.read32(off + 4);
            self.write32(off + 4, !0);
            let mask_hi = self.read32(off + 4);
            self.write32(off + 4, hi);
            ((hi as u64) << 32 | (lo & !0xf) as u64, (mask_hi as u64) << 32 | (mask_lo & !0xf) as u64)
        } else {
            let flags = if kind == BarKind::Io { 3 } else { 0xf };
            ((lo & !flags) as u64, (mask_lo & !flags) as u64)
        };
        self.set_command(cmd);

        // The size is the lowest writable address bit. The bits above it
        // need not all read back as ones: an I/O BAR may decode only 16
        // bits, and a 64-bit BAR below 4 GiB may hardwire its upper half to
        // zero. An unimplemented BAR reads back zero.
        (mask != 0).then(|| Bar { index, kind, address, size: 1 << mask.trailing_zeros() })
    }

    /// Programs `bar` to decode at `address`, which must be aligned to its
    /// size.
    ///
    /// # Panics
    ///
    /// If `address` is not aligned to the BAR's size.
    pub fn set_bar(&self, bar: &Bar, address: u64) {
        assert!(address.is_multiple_of(bar.size), "BAR address not aligned to its size");
        let off = reg::BAR0 + bar.index as u16 * 4;
        let flags = self.read32(off) & if bar.kind == BarKind::Io { 3 } else { 0xf };
        self.write32(off, address as u32 | flags);
        if let BarKind::Memory64 { .. } = bar.kind {
            self.write32(off + 4, (address >> 32) as u32);
        } else {
            assert!(address >> 32 == 0, "32-bit BAR above 4 GiB");
        }
    }

    /// Iterates over the capability list as `(id, offset)` pairs.
    pub fn capabilities(&self) -> Capabilities<'_, 'cfg, C> {
        let has_list = self.read16(reg::COMMAND_STATUS + 2) & (1 << 4) != 0;
        let next = if has_list { self.read8(reg::CAPABILITIES) & !3 } else { 0 };
        Capabilities { func: self, next, budget: 48 }
    }

    /// Offset of the first capability with ID `id`.
    pub fn find_capability(&self, id: u8) -> Option<u16> {
        self.capabilities().find(|&(cid, _)| cid == id).map(|(_, off)| off)
    }
}

/// Iterator returned by [`Function::capabilities`].
pub struct Capabilities<'f, 'cfg, C: ConfigAccess + ?Sized> {
    func: &'f Function<'cfg, C>,
    next: u8,
    // Bounds the walk on a malformed (cyclic) list.
    budget: u8,
}

impl<C: ConfigAccess + ?Sized> Iterator for Capabilities<'_, '_, C> {
    type Item = (u8, u16);

    fn next(&mut self) -> Option<(u8, u16)> {
        if self.next < 0x40 || self.budget == 0 {
            return None;
        }
        self.budget -= 1;
        let off = self.next as u16;
        let header = self.func.read16(off);
        self.next = (header >> 8) as u8 & !3;
        Some((header as u8, off))
    }
}

/// Visits every function on buses `first..=cfg.max_bus()` by brute force
/// (no bridge walking), calling `f` for each.
pub fn for_each_function<C: ConfigAccess + ?Sized>(cfg: &C, first: u8, mut f: impl FnMut(Function<'_, C>)) {
    for bus in first..=cfg.max_bus() {
        for device in 0..32 {
            let Some(f0) = Function::new(cfg, Address::new(bus, device, 0)) else {
                continue;
            };
            let functions = if f0.is_multi_function() { 8 } else { 1 };
            f(f0);
            for function in 1..functions {
                if let Some(func) = Function::new(cfg, Address::new(bus, device, function)) {
                    f(func);
                }
            }
        }
    }
}

/// Hands out naturally aligned addresses from a window (a host bridge's
/// non-prefetchable memory range, from the device tree's `ranges`).
#[derive(Debug)]
pub struct BarAllocator {
    next: u64,
    end: u64,
}

impl BarAllocator {
    /// Allocates from `[base, base + size)` (bus addresses). A window running past `u64::MAX` is clamped to it.
    pub const fn new(base: u64, size: u64) -> Self {
        Self { next: base, end: base.saturating_add(size) }
    }

    /// Returns an address for a region of `size` bytes, aligned to `size`.
    pub fn alloc(&mut self, size: u64) -> Option<u64> {
        let addr = self.next.checked_next_multiple_of(size)?;
        let end = addr.checked_add(size)?;
        (end <= self.end).then(|| {
            self.next = end;
            addr
        })
    }

    /// Assigns every unassigned memory BAR of `func` from this window.
    /// 64-bit BARs are kept below 4 GiB when the window is.
    pub fn assign<C: ConfigAccess + ?Sized>(&mut self, func: &Function<'_, C>) -> Result<(), BarError> {
        let mut index = 0;
        while index < 6 {
            let bar = func.bar(index);
            index += match bar {
                Some(Bar { kind: BarKind::Memory64 { .. }, .. }) => 2,
                _ => 1,
            };
            let Some(bar) = bar else { continue };
            if bar.kind == BarKind::Io || bar.address != 0 {
                continue;
            }
            let addr = self.alloc(bar.size).ok_or(BarError::OutOfSpace)?;
            if addr >> 32 != 0 && matches!(bar.kind, BarKind::Memory32 { .. }) {
                return Err(BarError::OutOfSpace);
            }
            func.set_bar(&bar, addr);
        }
        Ok(())
    }
}

/// Why BAR assignment failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarError {
    /// The window is exhausted, or a 32-bit BAR cannot reach it.
    OutOfSpace,
}

#[cfg(test)]
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use std::collections::BTreeMap;
    use std::vec::Vec;

    #[test]
    fn bar_window_past_the_top_is_clamped() {
        let mut a = BarAllocator::new(u64::MAX - 0xfff, u64::MAX);
        assert_eq!(a.alloc(0x1000), None);
        let mut a = BarAllocator::new(0x1000, u64::MAX);
        assert_eq!(a.alloc(0x1000), Some(0x1000));
    }

    /// Configuration space with BARs that decode like hardware: writes keep
    /// only the address bits above the BAR's size, and bits in `hardwired`
    /// read back as zero.
    #[derive(Default)]
    pub(super) struct FakeConfig {
        space: RefCell<BTreeMap<(Address, u16), u32>>,
        bar_sizes: BTreeMap<(Address, u16), u64>,
        hardwired: BTreeMap<(Address, u16), u32>,
    }

    impl FakeConfig {
        pub(super) fn set(&self, a: Address, off: u16, v: u32) {
            self.space.borrow_mut().insert((a, off), v);
        }
    }

    impl ConfigAccess for FakeConfig {
        fn read32(&self, a: Address, off: u16) -> u32 {
            *self.space.borrow().get(&(a, off)).unwrap_or(&!0)
        }
        fn write32(&self, a: Address, off: u16, v: u32) {
            let is_bar = (reg::BAR0..reg::BAR0 + 24).contains(&off);
            let upper_half = off >= reg::BAR0 + 4 && self.bar_sizes.contains_key(&(a, off - 4));
            let v = match self.bar_sizes.get(&(a, off)) {
                Some(&size) => (v & !(size - 1) as u32) | (self.read32(a, off) & 0xf),
                // Unimplemented BARs are hardwired to zero.
                None if is_bar && !upper_half => 0,
                None => v,
            };
            let v = v & !self.hardwired.get(&(a, off)).copied().unwrap_or(0);
            self.set(a, off, v);
        }
        fn max_bus(&self) -> u8 {
            0
        }
    }

    fn xhci(cfg: &mut FakeConfig, a: Address) {
        cfg.set(a, reg::VENDOR_DEVICE, 0x000d_1b36); // QEMU xHCI
        cfg.set(a, reg::COMMAND_STATUS, 1 << 20); // capability list present
        cfg.set(a, reg::CLASS_REVISION, 0x0c03_3001);
        cfg.set(a, reg::HEADER_TYPE, 0);
        cfg.set(a, reg::BAR0, 0b0100); // 64-bit memory
        cfg.set(a, reg::BAR0 + 4, 0);
        cfg.bar_sizes.insert((a, reg::BAR0), 0x4000);
        cfg.set(a, reg::BAR0 + 8, 0); // BAR2 unimplemented
        cfg.set(a, reg::BAR0 + 12, 0);
        cfg.set(a, reg::BAR0 + 16, 0);
        cfg.set(a, reg::BAR0 + 20, 0);
        cfg.set(a, reg::CAPABILITIES, 0x40);
        cfg.set(a, 0x40, 0x0000_5011); // MSI-X, next 0x50
        cfg.set(a, 0x50, 0x0000_4005); // MSI, next 0x40: a loop
    }

    #[test]
    fn enumerate_identify_and_assign() {
        let mut cfg = FakeConfig::default();
        let a = Address::new(0, 2, 0);
        xhci(&mut cfg, a);
        cfg.set(Address::new(0, 0, 0), reg::VENDOR_DEVICE, 0x0008_1b36); // host bridge
        cfg.set(Address::new(0, 0, 0), reg::HEADER_TYPE, 0);

        let mut found = Vec::new();
        for_each_function(&cfg, 0, |f| found.push((f.address(), f.class())));
        assert_eq!(found.len(), 2);
        assert_eq!(found[1], (a, Class::XHCI));

        let f = Function::new(&cfg, a).unwrap();
        assert_eq!((f.vendor_id(), f.device_id()), (0x1b36, 0x000d));
        let bar = f.bar(0).unwrap();
        assert_eq!((bar.kind, bar.address, bar.size), (BarKind::Memory64 { prefetchable: false }, 0, 0x4000));
        assert_eq!(f.bar(2), None);

        let mut alloc = BarAllocator::new(0x4000_1000, 0x10_0000);
        alloc.assign(&f).unwrap();
        assert_eq!(f.bar(0).unwrap().address, 0x4000_4000, "aligned to its size");
        assert_eq!(alloc.alloc(0x1000), Some(0x4000_8000));

        f.enable_memory_and_dma();
        assert_eq!(f.command() & 6, 6);
    }

    #[test]
    fn bar_sizes_with_zero_upper_bits() {
        let mut cfg = FakeConfig::default();
        let a = Address::new(0, 3, 0);
        cfg.set(a, reg::VENDOR_DEVICE, 0x1000_1af4);
        cfg.set(a, reg::HEADER_TYPE, 0);
        // BAR0: 32-byte I/O BAR at 0xc040 decoding only 16 address bits.
        cfg.set(a, reg::BAR0, 0xc041);
        cfg.bar_sizes.insert((a, reg::BAR0), 0x20);
        cfg.hardwired.insert((a, reg::BAR0), 0xffff_0000);
        // BAR1: 1 MiB 64-bit prefetchable BAR whose upper half is hardwired
        // to zero (it can only decode below 4 GiB).
        cfg.set(a, reg::BAR0 + 4, 0b1100);
        cfg.set(a, reg::BAR0 + 8, 0);
        cfg.bar_sizes.insert((a, reg::BAR0 + 4), 0x10_0000);
        cfg.hardwired.insert((a, reg::BAR0 + 8), !0);
        // BAR3: 8 GiB 64-bit BAR: the low dword has no writable address bits.
        cfg.set(a, reg::BAR0 + 12, 0b0100);
        cfg.set(a, reg::BAR0 + 16, 0);
        cfg.bar_sizes.insert((a, reg::BAR0 + 12), 1 << 33);
        cfg.hardwired.insert((a, reg::BAR0 + 16), 1);

        let f = Function::new(&cfg, a).unwrap();
        let io = f.bar(0).unwrap();
        assert_eq!((io.kind, io.address, io.size), (BarKind::Io, 0xc040, 0x20));
        let mem = f.bar(1).unwrap();
        assert_eq!((mem.kind, mem.size), (BarKind::Memory64 { prefetchable: true }, 0x10_0000));
        let big = f.bar(3).unwrap();
        assert_eq!((big.kind, big.size), (BarKind::Memory64 { prefetchable: false }, 1 << 33));
        assert_eq!(cfg.read32(a, reg::BAR0), 0xc041, "restored after probing");
    }

    #[test]
    fn capability_walk_is_bounded() {
        let mut cfg = FakeConfig::default();
        let a = Address::new(0, 1, 0);
        xhci(&mut cfg, a);
        let f = Function::new(&cfg, a).unwrap();
        assert_eq!(f.find_capability(cap::MSI), Some(0x50));
        assert_eq!(f.find_capability(cap::PCI_EXPRESS), None);
        assert_eq!(f.capabilities().count(), 48);
    }

    /// Offsets of 4 KiB and up must not alias register 0.
    fn backing_probe(ecam: &Ecam) {
        ecam.write32(Address::new(0, 0, 0), 0, 0x1234);
        assert_eq!(ecam.read32(Address::new(0, 0, 0), 0x1000), !0);
        ecam.write32(Address::new(0, 0, 0), 0x1000, 0x5678);
        assert_eq!(ecam.read32(Address::new(0, 0, 0), 0), 0x1234);
    }

    #[test]
    fn ecam_offsets() {
        let mut backing = std::vec![0u32; (2 << 20) / 4];
        // SAFETY: the window covers a local buffer.
        let io = unsafe { IoMem::new(backing.as_mut_ptr().cast(), 2 << 20) };
        let ecam = Ecam::new(io, 0);
        assert_eq!(ecam.max_bus(), 1);
        ecam.write32(Address::new(1, 3, 2), 0x10, 0xabcd);
        assert_eq!(ecam.read32(Address::new(5, 0, 0), 0), !0, "outside the window");
        backing_probe(&ecam);
        drop(ecam);
        assert_eq!(backing[(1 << 20 | 3 << 15 | 2 << 12 | 0x10) / 4], 0xabcd);
    }
}
