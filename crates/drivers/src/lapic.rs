//! x86 local APIC in xAPIC (MMIO) mode.

use crate::ioext::IoMemExt;
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::MsiMessage;

const ID: usize = 0x020;
const EOI: usize = 0x0b0;
const SVR: usize = 0x0f0;
const ICR_LOW: usize = 0x300;
const ICR_HIGH: usize = 0x310;
const LVT_TIMER: usize = 0x320;
const TIMER_INITIAL: usize = 0x380;
const TIMER_CURRENT: usize = 0x390;
const TIMER_DIVIDE: usize = 0x3e0;

const ICR_PENDING: u32 = 1 << 12;
const ICR_INIT: u32 = 0b101 << 8;
const ICR_STARTUP: u32 = 0b110 << 8;
const ICR_LEVEL_ASSERT: u32 = 1 << 14;
const LVT_MASKED: u32 = 1 << 16;
const LVT_PERIODIC: u32 = 1 << 17;

/// Default physical base of the local APIC.
pub const DEFAULT_BASE: u64 = 0xfee0_0000;

/// The current CPU's local APIC.
///
/// Every CPU sees its own APIC at the same address, so one instance serves
/// all CPUs.
pub struct LocalApic {
    io: IoMem,
}

impl LocalApic {
    /// Wraps the 4 KiB register window (mapped uncached).
    pub fn new(io: IoMem) -> Self {
        Self { io }
    }

    fn read(&self, reg: usize) -> u32 {
        self.io.rd(reg)
    }

    fn write(&self, reg: usize, v: u32) {
        self.io.wr(reg, v)
    }

    /// Software-enables the APIC with the given spurious-interrupt vector.
    pub fn enable(&self, spurious_vector: u8) {
        self.write(SVR, 0x100 | spurious_vector as u32);
    }

    /// This CPU's APIC id.
    pub fn id(&self) -> u32 {
        self.read(ID) >> 24
    }

    /// Signals end of interrupt.
    pub fn eoi(&self) {
        self.write(EOI, 0);
    }

    /// Sends fixed-delivery interrupt `vector` to the CPU with APIC id `dest`.
    pub fn send_ipi(&self, dest: u8, vector: u8) {
        self.send_icr(dest, vector as u32);
    }

    /// Sends an INIT IPI to the CPU with APIC id `dest`: the first step of
    /// starting an application processor.
    pub fn send_init(&self, dest: u8) {
        self.send_icr(dest, ICR_INIT | ICR_LEVEL_ASSERT);
    }

    /// Sends a STARTUP IPI: CPU `dest` starts in real mode at physical
    /// address `page << 12` (so the entry must be page aligned and below 1 MiB).
    pub fn send_startup(&self, dest: u8, page: u8) {
        self.send_icr(dest, ICR_STARTUP | page as u32);
    }

    /// Starts the application processor with APIC id `dest` through the
    /// trampoline in `osmium_arch::x86_64::smp`: fills its slots from `boot`,
    /// then INIT, 10 ms, and STARTUP twice, 200 µs apart. `delay_ns` busy-waits
    /// (a calibrated PIT or TSC). Returns once the IPIs are sent; the caller
    /// waits for the AP to check in before starting the next one.
    ///
    /// # Safety
    /// As for `smp::prepare`: the trampoline is installed and no other AP is
    /// still in it. `boot` must describe a valid stack and entry.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    pub unsafe fn start_ap(&self, dest: u8, boot: &osmium_arch::x86_64::smp::ApBoot, delay_ns: impl Fn(u64)) {
        use osmium_arch::x86_64::smp;
        // SAFETY: the caller upholds `prepare`'s contract.
        unsafe { smp::prepare(boot) };
        self.send_init(dest);
        delay_ns(10_000_000);
        for _ in 0..2 {
            self.send_startup(dest, (smp::TRAMPOLINE >> 12) as u8);
            delay_ns(200_000);
        }
    }

    fn send_icr(&self, dest: u8, low: u32) {
        self.write(ICR_HIGH, (dest as u32) << 24);
        self.write(ICR_LOW, low);
        while self.read(ICR_LOW) & ICR_PENDING != 0 {
            core::hint::spin_loop();
        }
    }

    /// Starts the timer: `count` ticks of the bus clock divided by 16, then
    /// interrupt `vector`, once or periodically.
    pub fn start_timer(&self, vector: u8, count: u32, periodic: bool) {
        self.write(TIMER_DIVIDE, 0b0011);
        self.write(LVT_TIMER, vector as u32 | if periodic { LVT_PERIODIC } else { 0 });
        self.write(TIMER_INITIAL, count);
    }

    /// Stops the timer.
    pub fn stop_timer(&self) {
        self.write(LVT_TIMER, LVT_MASKED);
        self.write(TIMER_INITIAL, 0);
    }

    /// Remaining ticks of the current timer period.
    pub fn timer_remaining(&self) -> u32 {
        self.read(TIMER_CURRENT)
    }
}

/// The MSI or MSI-X message that raises fixed, edge-triggered interrupt
/// `vector` on the CPU with xAPIC id `apic_id` (physical destination mode).
pub const fn msi_message(apic_id: u8, vector: u8) -> MsiMessage {
    MsiMessage { address: DEFAULT_BASE | (apic_id as u64) << 12, data: vector as u32 }
}

#[cfg(test)]
// Tests drop drivers explicitly to end their use of the fake register memory
// before inspecting it.
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;

    #[test]
    fn registers() {
        let mut regs = [0u32; 0x1000 / 4];
        regs[ID / 4] = 3 << 24;
        // SAFETY: the window covers a local array.
        let apic = LocalApic::new(unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x1000) });
        apic.enable(0xff);
        assert_eq!(apic.id(), 3);
        apic.send_ipi(2, 0x40);
        apic.start_timer(0x20, 1000, true);
        apic.eoi();
        drop(apic);
        assert_eq!(regs[SVR / 4], 0x1ff);
        assert_eq!(regs[ICR_HIGH / 4], 2 << 24);
        assert_eq!(regs[ICR_LOW / 4], 0x40);
        assert_eq!(regs[LVT_TIMER / 4], 0x20 | LVT_PERIODIC);
        assert_eq!(regs[TIMER_INITIAL / 4], 1000);
    }

    #[test]
    fn init_and_startup() {
        let mut regs = [0u32; 0x1000 / 4];
        // SAFETY: the window covers a local array.
        let apic = LocalApic::new(unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x1000) });
        apic.send_init(3);
        assert_eq!(read_icr(&apic), (3 << 24, 0x4500));
        apic.send_startup(3, 0x08);
        drop(apic);
        assert_eq!((regs[ICR_HIGH / 4], regs[ICR_LOW / 4]), (3 << 24, 0x0608));
    }

    #[test]
    fn msi() {
        assert_eq!(msi_message(3, 0x50), MsiMessage { address: 0xfee0_3000, data: 0x50 });
    }

    fn read_icr(apic: &LocalApic) -> (u32, u32) {
        (apic.read(ICR_HIGH), apic.read(ICR_LOW))
    }
}
