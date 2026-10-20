use alloc::boxed::Box;

use osmium_sync::IrqSpinLock;

use crate::bus::BusDevice;

/// The 8254's input clock in Hz.
pub const PIT_HZ: u64 = 1_193_182;

/// Nanoseconds to whole PIT ticks.
fn ticks(ns: u64) -> u64 {
    (ns as u128 * PIT_HZ as u128 / 1_000_000_000) as u64
}

/// PIT ticks to nanoseconds, rounded up so a deadline is never early.
fn ns(ticks: u64) -> u64 {
    (ticks as u128 * 1_000_000_000).div_ceil(PIT_HZ as u128) as u64
}

/// One counter.
#[derive(Default)]
struct Channel {
    /// Operating mode (0-5; 6 and 7 are read as 2 and 3).
    mode: u8,
    /// Read/write access: 1 = low byte, 2 = high byte, 3 = low then high.
    access: u8,
    /// The count written by the guest (0 means 65536).
    reload: u16,
    /// The low byte of a two-byte write in progress.
    low: Option<u8>,
    /// Whether the next two-byte read returns the high byte.
    read_high: bool,
    /// A count latched by a latch or read-back command.
    latched: Option<u16>,
    /// Whether the latched value is the status byte (read before the count).
    status: Option<u8>,
    /// When counting started (ns), or `None` until a count is written.
    start: Option<u64>,
    /// Periods (or, for one-shot modes, terminal counts) already signalled.
    fired: u64,
}

impl Channel {
    fn period(&self) -> u64 {
        if self.reload == 0 { 0x1_0000 } else { self.reload as u64 }
    }

    fn periodic(&self) -> bool {
        matches!(self.mode, 2 | 3)
    }

    /// Modes 1 and 5 start on a gate edge; the gate is never raised here.
    fn gated(&self) -> bool {
        matches!(self.mode, 1 | 5)
    }

    /// Terminal counts reached by `now`.
    fn expiries(&self, now: u64) -> u64 {
        let Some(start) = self.start else { return 0 };
        if self.gated() {
            return 0;
        }
        let t = ticks(now.saturating_sub(start));
        if self.periodic() { t / self.period() } else { (t >= self.period()) as u64 }
    }

    /// The counting element at `now`.
    fn count(&self, now: u64) -> u16 {
        let Some(start) = self.start else { return self.reload };
        if self.gated() {
            return self.reload;
        }
        let t = ticks(now.saturating_sub(start));
        let p = self.period();
        if self.periodic() {
            (p - t % p) as u16
        } else {
            // After the terminal count the counter wraps and keeps going.
            (p.wrapping_sub(t)) as u16
        }
    }

    /// The OUT pin at `now` as the status byte reports it.
    fn out(&self, now: u64) -> bool {
        match self.mode {
            0 => self.expiries(now) > 0,
            3 => {
                // High for the first half of each period.
                let p = self.period();
                self.count(now) as u64 > p / 2 || self.start.is_none()
            }
            _ => true,
        }
    }

    /// When the next unsignalled expiry falls, if one will.
    fn deadline(&self) -> Option<u64> {
        let start = self.start?;
        if self.gated() || (!self.periodic() && self.fired > 0) {
            return None;
        }
        Some(start + ns((self.fired + 1) * self.period()))
    }

    fn control(&mut self, v: u8, now: u64) {
        let access = (v >> 4) & 3;
        if access == 0 {
            // Counter latch: holds the count until it has been read.
            if self.latched.is_none() {
                self.latched = Some(self.count(now));
            }
            return;
        }
        let mode = (v >> 1) & 7;
        *self = Channel { mode: if mode >= 6 { mode - 4 } else { mode }, access, ..Channel::default() };
    }

    fn write(&mut self, v: u8, now: u64) {
        let count = match (self.access, self.low.take()) {
            (1, _) => v as u16,
            (2, _) => (v as u16) << 8,
            (_, None) => {
                self.low = Some(v);
                if self.mode == 0 {
                    // Writing the first byte stops a mode 0 count.
                    self.start = None;
                }
                return;
            }
            (_, Some(lo)) => (v as u16) << 8 | lo as u16,
        };
        // A new count takes effect now: OUT drops in mode 0, and the
        // periodic modes restart with it.
        self.reload = count;
        self.start = Some(now);
        self.fired = 0;
    }

    fn read(&mut self, now: u64) -> u8 {
        if let Some(s) = self.status.take() {
            return s;
        }
        let v = self.latched.unwrap_or_else(|| self.count(now));
        let (byte, done) = match self.access {
            1 => (v as u8, true),
            2 => ((v >> 8) as u8, true),
            _ if self.read_high => ((v >> 8) as u8, true),
            _ => (v as u8, false),
        };
        self.read_high = !done;
        if done {
            self.latched = None;
        }
        byte
    }
}

/// An emulated Intel 8254 PIT at ports 0x40-0x43, for guests that use the
/// PC's legacy timer. Channel 0's output drives the callback (wire it to
/// IRQ 0 of a [`VirtualPic`](super::VirtualPic)); channels 1 and 2 count
/// but have no output.
///
/// The counters run from a host clock in nanoseconds and are computed when
/// read, so the model costs nothing between accesses. Channel 0's
/// interrupts are delivered by [`poll`](Self::poll): call it whenever the
/// host has the chance (every port access does) and arm a host timer for
/// [`next_deadline`](Self::next_deadline) so a guest that is halted or
/// spinning still gets its ticks on time. Expiries that pile up between
/// polls are coalesced into one edge, as a guest that does not acknowledge
/// IRQ 0 in time would see on hardware.
///
/// Modes 0, 2, 3 and 4 work as on hardware; channel 0's gate is tied high,
/// so modes 1 and 5 never start. BCD counting is not supported.
pub struct VirtualPit {
    channels: IrqSpinLock<[Channel; 3]>,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    output: Box<dyn Fn(bool) + Send + Sync>,
}

impl VirtualPit {
    /// A PIT whose time comes from `clock` (monotonic nanoseconds) and whose
    /// channel 0 output drives `output`.
    pub fn new(clock: impl Fn() -> u64 + Send + Sync + 'static, output: impl Fn(bool) + Send + Sync + 'static) -> Self {
        Self { channels: IrqSpinLock::new(Default::default()), clock: Box::new(clock), output: Box::new(output) }
    }

    /// Raises IRQ 0 for any channel 0 expiry since the last poll. Returns
    /// whether it did.
    pub fn poll(&self) -> bool {
        let now = (self.clock)();
        let mut c = self.channels.lock();
        let ch = &mut c[0];
        let n = ch.expiries(now);
        if n <= ch.fired {
            return false;
        }
        ch.fired = n;
        let periodic = ch.periodic();
        drop(c);
        // A fresh edge each time: the PIC latches rising edges.
        if periodic {
            (self.output)(false);
        }
        (self.output)(true);
        true
    }

    /// When channel 0 next expires (in the clock's nanoseconds), if it is
    /// counting toward an expiry not yet signalled.
    pub fn next_deadline(&self) -> Option<u64> {
        self.channels.lock()[0].deadline()
    }
}

impl BusDevice for VirtualPit {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let now = (self.clock)();
        data.fill(0);
        if offset < 3 {
            data[0] = self.channels.lock()[offset as usize].read(now);
        }
        self.poll();
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let now = (self.clock)();
        let v = data.first().copied().unwrap_or(0);
        let mut c = self.channels.lock();
        let mut lower = false;
        match offset {
            0..=2 => {
                c[offset as usize].write(v, now);
                lower = offset == 0 && c[0].mode == 0;
            }
            3 if v >> 6 == 3 => {
                // Read-back: bit 5 clear latches counts, bit 4 clear latches
                // status, bits 3:1 select channels.
                for (i, ch) in c.iter_mut().enumerate() {
                    if v & (2 << i) == 0 {
                        continue;
                    }
                    if v & 0x10 == 0 && ch.status.is_none() {
                        let null = ch.start.is_none();
                        ch.status = Some((ch.out(now) as u8) << 7 | (null as u8) << 6 | ch.access << 4 | ch.mode << 1);
                    }
                    if v & 0x20 == 0 && ch.latched.is_none() {
                        ch.latched = Some(ch.count(now));
                    }
                }
            }
            3 => {
                let i = (v >> 6) as usize;
                c[i].control(v, now);
                // A control word sets OUT low in mode 0, high otherwise.
                lower = i == 0 && c[0].mode == 0 && v & 0x30 != 0;
            }
            _ => {}
        }
        drop(c);
        if lower {
            (self.output)(false);
        }
        self.poll();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU64, Ordering};

    struct Rig {
        pit: VirtualPit,
        now: Arc<AtomicU64>,
        edges: Arc<IrqSpinLock<Vec<bool>>>,
    }

    impl Rig {
        fn new() -> Self {
            let now = Arc::new(AtomicU64::new(1_000));
            let edges = Arc::new(IrqSpinLock::new(Vec::new()));
            let (n, e) = (now.clone(), edges.clone());
            let pit = VirtualPit::new(move || n.load(Ordering::SeqCst), move |l| e.lock().push(l));
            Rig { pit, now, edges }
        }
        fn out(&self, port: u64, v: u8) {
            self.pit.write(port, &[v]);
        }
        fn inb(&self, port: u64) -> u8 {
            let mut b = [0];
            self.pit.read(port, &mut b);
            b[0]
        }
        fn advance(&self, ns: u64) {
            self.now.fetch_add(ns, Ordering::SeqCst);
        }
        fn rising(&self) -> usize {
            self.edges.lock().iter().filter(|&&l| l).count()
        }
    }

    #[test]
    fn rate_generator_ticks_and_deadlines() {
        let r = Rig::new();
        r.out(3, 0x34); // channel 0, low/high, mode 2
        r.out(0, (1193 & 0xff) as u8);
        assert_eq!(r.pit.next_deadline(), None, "no count until both bytes");
        r.out(0, (1193 >> 8) as u8);
        let d = r.pit.next_deadline().unwrap();
        assert_eq!(d, 1_000 + ns(1193)); // about 1 ms after the write
        assert!(!r.pit.poll());
        r.advance(d - 1_000);
        assert!(r.pit.poll());
        assert_eq!(r.rising(), 1);
        assert_eq!(r.pit.next_deadline().unwrap(), 1_000 + ns(2 * 1193));
        // Three periods missed: one edge, and the deadline moves past them.
        r.advance(3 * ns(1193));
        assert!(r.pit.poll());
        assert_eq!(r.rising(), 2);
        assert!(!r.pit.poll());
        assert!(r.pit.next_deadline().unwrap() > r.now.load(Ordering::SeqCst));
    }

    #[test]
    fn one_shot_and_latch() {
        let r = Rig::new();
        r.out(3, 0x30); // channel 0, low/high, mode 0
        assert_eq!(*r.edges.lock(), [false], "OUT drops on the control word");
        r.out(0, 100);
        r.out(0, 0);
        r.advance(ns(40));
        r.out(3, 0x00); // latch channel 0
        r.advance(ns(10));
        assert_eq!((r.inb(0), r.inb(0)), (60, 0), "the latched count, not the live one");
        assert_eq!(r.inb(0), 50, "live again after the latch is read");
        r.advance(ns(60));
        assert!(r.pit.poll());
        assert_eq!(r.pit.next_deadline(), None, "one shot only");
        r.advance(ns(1000));
        assert!(!r.pit.poll());
        assert_eq!(r.rising(), 1);
    }

    #[test]
    fn read_back_status() {
        let r = Rig::new();
        r.out(3, 0xb6); // channel 2, low/high, mode 3
        r.out(3, 0xe8); // read-back: status only, channel 2
        assert_eq!(r.inb(2), 0x80 | 0x40 | 0x30 | 3 << 1, "OUT high, null count, mode 3");
        r.out(2, 0x00);
        r.out(2, 0x10); // 0x1000
        r.advance(ns(0x100));
        r.out(3, 0xd8); // read-back: count only
        r.advance(ns(0x100));
        assert_eq!((r.inb(2), r.inb(2)), (0x00, 0x0f));
        assert_eq!(r.rising(), 0, "channel 2 has no interrupt");
    }
}
