//! x86 I/O APIC: routes external interrupt lines (global system interrupts)
//! to local-APIC vectors.

use crate::ioext::IoMemExt;
use osmium_hal::mmio::IoMem;
use osmium_sync::{IrqDisabled, IrqSpinLock, SpinLockGuard};

// A held `IoApic::lock`, which owns the select/window pair.
type Selected<'lock> = SpinLockGuard<'lock, (), IrqDisabled>;

const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;
const REG_VERSION: u32 = 0x01;
const REG_REDIRECTION: u32 = 0x10;
/// IOREGSEL is 8 bits wide and the redirection table starts at 0x10 with
/// two registers per entry, so at most 120 entries are addressable.
const MAX_LINES: u32 = 120;

const MASKED: u32 = 1 << 16;
const LEVEL: u32 = 1 << 15;
const ACTIVE_LOW: u32 = 1 << 13;

/// Default physical base of the first I/O APIC.
pub const DEFAULT_BASE: u64 = 0xfec0_0000;

/// Electrical behaviour of an interrupt line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LineMode {
    /// The line signals by being low (PCI) rather than high (ISA).
    pub active_low: bool,
    /// Level-triggered (PCI) rather than edge-triggered (ISA).
    pub level: bool,
}

/// An I/O APIC handling GSIs `gsi_base ..= gsi_base + max_entry`.
pub struct IoApic {
    io: IoMem,
    gsi_base: u32,
    /// Serializes the select/window register pair.
    lock: IrqSpinLock<()>,
}

impl IoApic {
    /// Wraps the register window (mapped uncached) of the I/O APIC whose
    /// first line is `gsi_base` (from the ACPI MADT).
    pub fn new(io: IoMem, gsi_base: u32) -> Self {
        Self { io, gsi_base, lock: IrqSpinLock::new(()) }
    }

    // The `_locked` accessors require `self.lock` to be held; taking its
    // guard as an argument makes that hard to forget.
    fn read_locked(&self, _: &Selected<'_>, reg: u32) -> u32 {
        let _ = self.io.write(IOREGSEL, reg);
        self.io.rd(IOWIN)
    }

    fn write_locked(&self, _: &Selected<'_>, reg: u32, v: u32) {
        let _ = self.io.write(IOREGSEL, reg);
        let _ = self.io.write(IOWIN, v);
    }

    fn read(&self, reg: u32) -> u32 {
        self.read_locked(&self.lock.lock(), reg)
    }

    /// Number of redirection entries (lines), at most 120 however many the
    /// version register claims.
    pub fn lines(&self) -> u32 {
        ((self.read(REG_VERSION) >> 16 & 0xff) + 1).min(MAX_LINES)
    }

    /// Returns true if this I/O APIC handles `gsi`.
    pub fn handles(&self, gsi: u32) -> bool {
        gsi >= self.gsi_base && gsi - self.gsi_base < self.lines()
    }

    /// The register of `gsi`'s redirection entry, if this unit handles it.
    fn entry(&self, gsi: u32) -> Option<u32> {
        self.handles(gsi).then(|| REG_REDIRECTION + 2 * (gsi - self.gsi_base))
    }

    /// Delivers `gsi` as `vector` to the CPU with local APIC id `dest`
    /// (fixed delivery, physical destination) and unmasks it.
    pub fn route(&self, gsi: u32, vector: u8, dest: u8, mode: LineMode) {
        let Some(reg) = self.entry(gsi) else { return };
        let mut low = vector as u32;
        if mode.active_low {
            low |= ACTIVE_LOW;
        }
        if mode.level {
            low |= LEVEL;
        }
        // Mask while changing, then write the destination, then unmask, all
        // under one lock hold.
        let g = self.lock.lock();
        self.write_locked(&g, reg, MASKED);
        self.write_locked(&g, reg + 1, (dest as u32) << 24);
        self.write_locked(&g, reg, low);
    }

    /// Updates the low half of `gsi`'s entry with one lock hold, so a
    /// concurrent update is not lost.
    fn modify(&self, gsi: u32, f: impl FnOnce(u32) -> u32) {
        // `entry` reads the version register, so call it before locking.
        let Some(reg) = self.entry(gsi) else { return };
        let g = self.lock.lock();
        let v = self.read_locked(&g, reg);
        self.write_locked(&g, reg, f(v));
    }

    /// Masks `gsi`.
    pub fn mask(&self, gsi: u32) {
        self.modify(gsi, |v| v | MASKED);
    }

    /// Unmasks `gsi`.
    pub fn unmask(&self, gsi: u32) {
        self.modify(gsi, |v| v & !MASKED);
    }
}

#[cfg(test)]
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;

    #[test]
    fn route_programs_redirection_entry() {
        // A real I/O APIC multiplexes registers through IOREGSEL/IOWIN; with
        // plain memory we can only observe the last select and window write.
        let mut regs = [0u32; 8];
        regs[IOWIN / 4] = 23 << 16; // version register reads: 24 lines
        // SAFETY: the window covers a local array.
        let apic = IoApic::new(unsafe { IoMem::new(regs.as_mut_ptr().cast(), 32) }, 0);
        assert_eq!(apic.lines(), 24);
        assert!(apic.handles(23) && !apic.handles(24));
        apic.route(4, 40, 0, LineMode::default());
        drop(apic);
        assert_eq!(regs[IOREGSEL / 4], REG_REDIRECTION + 8, "entry 4, low half written last");
        assert_eq!(regs[IOWIN / 4], 40, "vector 40, edge, active high, unmasked");
    }

    #[test]
    fn lines_capped_by_register_select_width() {
        let mut regs = [0u32; 8];
        regs[IOWIN / 4] = 0xff << 16; // claims 256 lines
        // SAFETY: the window covers a local array.
        let apic = IoApic::new(unsafe { IoMem::new(regs.as_mut_ptr().cast(), 32) }, 0);
        assert_eq!(apic.lines(), 120);
        assert!(apic.handles(119) && !apic.handles(120));
    }

    #[test]
    fn unhandled_gsi_is_ignored() {
        let mut regs = [0u32; 8];
        regs[IOWIN / 4] = 23 << 16;
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), 32) };
        let apic = IoApic::new(io, 0);
        apic.route(1000, 0x30, 0, LineMode { level: false, active_low: false });
        assert!(!apic.handles(1000));
    }
}
