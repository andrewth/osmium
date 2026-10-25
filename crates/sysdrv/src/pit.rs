//! Intel 8254 programmable interval timer (PC PIT).
//!
//! Used here as a fixed-frequency reference: channel 2 (the speaker channel,
//! which has a readable output bit and no interrupt) times a short interval
//! against which the local APIC timer and the TSC are calibrated.

/// The PIT input clock in Hz.
pub const FREQUENCY: u64 = 1_193_182;

const CHANNEL2: u16 = 0x42;
const COMMAND: u16 = 0x43;
const PORT_B: u16 = 0x61;
const GATE2: u8 = 1 << 0;
const SPEAKER: u8 = 1 << 1;
const OUT2: u8 = 1 << 5;

/// How the PIT's I/O ports are reached.
pub trait PitPorts {
    /// Reads a byte from `port`.
    fn inb(&self, port: u16) -> u8;
    /// Writes a byte to `port`.
    fn outb(&self, port: u16, value: u8);
}

/// The real x86 I/O ports.
#[cfg(target_arch = "x86_64")]
pub struct Pio(());

#[cfg(target_arch = "x86_64")]
impl Pio {
    /// Uses ports 0x40–0x43 and 0x61.
    ///
    /// # Safety
    /// The caller must own the PIT and port 0x61.
    pub const unsafe fn new() -> Self {
        Self(())
    }
}

#[cfg(target_arch = "x86_64")]
impl PitPorts for Pio {
    fn inb(&self, port: u16) -> u8 {
        // SAFETY: ownership asserted in `new`.
        unsafe { osmium_arch::x86_64::inb(port) }
    }
    fn outb(&self, port: u16, value: u8) {
        // SAFETY: ownership asserted in `new`.
        unsafe { osmium_arch::x86_64::outb(port, value) }
    }
}

/// The PIT.
pub struct Pit<P: PitPorts> {
    ports: P,
}

impl<P: PitPorts> Pit<P> {
    /// Wraps the ports.
    pub const fn new(ports: P) -> Self {
        Self { ports }
    }

    /// Busy-waits for `ticks` PIT ticks (at most 65535, about 55 ms) using
    /// channel 2 in one-shot mode. Returns at once for 0 (which the
    /// hardware would count as 65536).
    pub fn wait_ticks(&self, ticks: u16) {
        if ticks == 0 {
            return;
        }
        let b = self.ports.inb(PORT_B) & !(GATE2 | SPEAKER);
        self.ports.outb(PORT_B, b);
        // Channel 2 (bits 7:6 = 10), low then high byte (5:4 = 11),
        // mode 0, interrupt on terminal count (3:1 = 000), binary (0 = 0).
        self.ports.outb(COMMAND, 0xb0);
        self.ports.outb(CHANNEL2, ticks as u8);
        self.ports.outb(CHANNEL2, (ticks >> 8) as u8);
        // Raising the gate starts the count; OUT2 goes high at zero.
        self.ports.outb(PORT_B, b | GATE2);
        while self.ports.inb(PORT_B) & OUT2 == 0 {
            core::hint::spin_loop();
        }
        self.ports.outb(PORT_B, b);
    }

    /// Whole PIT ticks in `ns` nanoseconds, saturated to what one count can
    /// time.
    fn ticks_in(ns: u64) -> u16 {
        (ns as u128 * FREQUENCY as u128 / 1_000_000_000).min(u16::MAX as u128) as u16
    }

    /// Busy-waits for about `ns` nanoseconds: rounded down to whole ticks
    /// (about 838 ns each, so shorter waits return at once) and capped at
    /// 65535 ticks (about 55 ms).
    pub fn wait_ns(&self, ns: u64) {
        self.wait_ticks(Self::ticks_in(ns));
    }

    /// Measures how far a counter advances in about `ns` nanoseconds and
    /// returns its frequency in Hz. `read` samples the counter; for a
    /// down-counter such as the APIC timer, return its negation (or
    /// `u64::MAX - value`).
    ///
    /// The PIT can time only 1 to 65535 ticks (about 838 ns to 55 ms) in one
    /// count, so `ns` is clamped to that range, and the frequency is worked
    /// out from the ticks actually waited. Longer intervals within the range
    /// give more precise results; 10 ms is typical.
    pub fn calibrate(&self, ns: u64, mut read: impl FnMut() -> u64) -> u64 {
        let ticks = Self::ticks_in(ns).max(1);
        let start = read();
        self.wait_ticks(ticks);
        let delta = read().wrapping_sub(start);
        (delta as u128 * FREQUENCY as u128 / ticks as u128).min(u64::MAX as u128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::vec::Vec;

    struct Fake {
        log: RefCell<Vec<(u16, u8)>>,
        reads: Cell<u32>,
    }

    impl PitPorts for Fake {
        fn inb(&self, port: u16) -> u8 {
            assert_eq!(port, PORT_B);
            self.reads.set(self.reads.get() + 1);
            // Speaker on and OUT2 high after a few polls.
            SPEAKER | if self.reads.get() > 3 { OUT2 } else { 0 }
        }
        fn outb(&self, port: u16, value: u8) {
            self.log.borrow_mut().push((port, value));
        }
    }

    #[test]
    fn one_shot_sequence() {
        let pit = Pit::new(Fake { log: RefCell::new(Vec::new()), reads: Cell::new(0) });
        let mut counter = 0u64;
        let hz = pit.calibrate(10_000_000, || {
            counter += 1_000_000;
            counter
        });
        // 10 ms is 11931.82 ticks; the 11931 actually waited are 9.9993 ms.
        assert_eq!(hz, 100_006_872, "1e6 counts in 11931 ticks");
        // 10 ms = 11931 ticks = 0x2e9b; the speaker bit is cleared.
        assert_eq!(
            *pit.ports.log.borrow(),
            [(PORT_B, 0), (COMMAND, 0xb0), (CHANNEL2, 0x9b), (CHANNEL2, 0x2e), (PORT_B, 1), (PORT_B, 0)]
        );
    }

    #[test]
    fn calibrate_clamps_the_interval() {
        let fake = || Fake { log: RefCell::new(Vec::new()), reads: Cell::new(0) };
        let counts = |step: u64| {
            let mut c = u64::MAX - step / 2; // wraps during the measurement
            move || {
                c = c.wrapping_add(step);
                c
            }
        };
        // Zero and sub-tick intervals time one tick rather than dividing by
        // zero or counting 65536.
        let pit = Pit::new(fake());
        assert_eq!(pit.calibrate(0, counts(1000)), 1000 * FREQUENCY);
        assert_eq!(pit.ports.log.borrow()[2..4], [(CHANNEL2, 1), (CHANNEL2, 0)]);
        // Overlong intervals time 65535 ticks, and a huge count saturates.
        let pit = Pit::new(fake());
        assert_eq!(pit.calibrate(u64::MAX, counts(65535)), FREQUENCY);
        assert_eq!(pit.ports.log.borrow()[2..4], [(CHANNEL2, 0xff), (CHANNEL2, 0xff)]);
        assert_eq!(Pit::new(fake()).calibrate(1_000_000, counts(u64::MAX / 2)), u64::MAX);
        // A zero-tick wait touches no ports.
        let pit = Pit::new(fake());
        pit.wait_ns(500);
        assert!(pit.ports.log.borrow().is_empty());
    }
}
