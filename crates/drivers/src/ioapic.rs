//! x86 I/O APIC: routes external interrupt lines (global system interrupts)
//! to local-APIC vectors.

use osmium_hal::mmio::IoMem;
use osmium_sync::IrqSpinLock;

const IOREGSEL: usize = 0x00;
const IOWIN: usize = 0x10;
const REG_VERSION: u32 = 0x01;
const REG_REDIRECTION: u32 = 0x10;

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

    fn read(&self, reg: u32) -> u32 {
        let _g = self.lock.lock();
        let _ = self.io.write(IOREGSEL, reg);
        self.io.read(IOWIN).expect("I/O APIC window too small")
    }

    fn write(&self, reg: u32, v: u32) {
        let _g = self.lock.lock();
        let _ = self.io.write(IOREGSEL, reg);
        let _ = self.io.write(IOWIN, v);
    }

    /// Number of redirection entries (lines).
    pub fn lines(&self) -> u32 {
        (self.read(REG_VERSION) >> 16 & 0xff) + 1
    }

    /// Returns true if this I/O APIC handles `gsi`.
    pub fn handles(&self, gsi: u32) -> bool {
        gsi >= self.gsi_base && gsi - self.gsi_base < self.lines()
    }

    fn entry(&self, gsi: u32) -> u32 {
        assert!(self.handles(gsi), "GSI {gsi} not handled by this I/O APIC");
        REG_REDIRECTION + 2 * (gsi - self.gsi_base)
    }

    /// Delivers `gsi` as `vector` to the CPU with local APIC id `dest`
    /// (fixed delivery, physical destination) and unmasks it.
    pub fn route(&self, gsi: u32, vector: u8, dest: u8, mode: LineMode) {
        let reg = self.entry(gsi);
        let mut low = vector as u32;
        if mode.active_low {
            low |= ACTIVE_LOW;
        }
        if mode.level {
            low |= LEVEL;
        }
        // Mask while changing, then write the destination, then unmask.
        self.write(reg, MASKED);
        self.write(reg + 1, (dest as u32) << 24);
        self.write(reg, low);
    }

    /// Masks `gsi`.
    pub fn mask(&self, gsi: u32) {
        let reg = self.entry(gsi);
        self.write(reg, self.read(reg) | MASKED);
    }

    /// Unmasks `gsi`.
    pub fn unmask(&self, gsi: u32) {
        let reg = self.entry(gsi);
        self.write(reg, self.read(reg) & !MASKED);
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
}
