use alloc::boxed::Box;

use osmium_sync::IrqSpinLock;

use crate::bus::BusDevice;

/// The xAPIC's register window, at guest-physical `0xfee0_0000` by default.
pub const LAPIC_WINDOW: u64 = 0x1000;

const ID: u64 = 0x20;
const VERSION: u64 = 0x30;
const TPR: u64 = 0x80;
const PPR: u64 = 0xa0;
const EOI: u64 = 0xb0;
const LDR: u64 = 0xd0;
const DFR: u64 = 0xe0;
const SVR: u64 = 0xf0;
const ISR: u64 = 0x100;
const TMR: u64 = 0x180;
const IRR: u64 = 0x200;
const ESR: u64 = 0x280;
const ICR_LOW: u64 = 0x300;
const ICR_HIGH: u64 = 0x310;
const LVT_TIMER: u64 = 0x320;
const LVT_LINT0: u64 = 0x350;
const LVT_LINT1: u64 = 0x360;
const LVT_ERROR: u64 = 0x370;
const TIMER_INITIAL: u64 = 0x380;
const TIMER_CURRENT: u64 = 0x390;
const TIMER_DIVIDE: u64 = 0x3e0;

const MASKED: u32 = 1 << 16;
const PERIODIC: u32 = 1 << 17;
const SVR_ENABLE: u32 = 1 << 8;
/// Version 0x14 (an integrated APIC) with six LVT entries.
const VERSION_VALUE: u32 = 0x0005_0014;

/// A 256-bit vector set (IRR, ISR).
#[derive(Default, Clone, Copy)]
struct Bits([u32; 8]);

impl Bits {
    fn set(&mut self, v: u8) {
        self.0[v as usize / 32] |= 1 << (v % 32);
    }
    fn clear(&mut self, v: u8) {
        self.0[v as usize / 32] &= !(1 << (v % 32));
    }
    fn highest(&self) -> Option<u8> {
        (0..8).rev().find(|&i| self.0[i] != 0).map(|i| (i * 32 + 31 - self.0[i].leading_zeros() as usize) as u8)
    }
}

struct State {
    id: u8,
    tpr: u8,
    ldr: u32,
    dfr: u32,
    svr: u32,
    irr: Bits,
    isr: Bits,
    esr: u32,
    icr_high: u32,
    icr_low: u32,
    lvt: [u32; 4], // timer, LINT0, LINT1, error
    initial: u32,
    divide: u32,
    /// When the timer was loaded (ns), while it counts.
    start: Option<u64>,
    /// Timer expiries already turned into interrupts.
    fired: u64,
}

impl State {
    fn divisor(&self) -> u64 {
        let d = (self.divide & 3) | (self.divide & 8) >> 1;
        if d == 7 { 1 } else { 2 << d }
    }

    fn periodic(&self) -> bool {
        self.lvt[0] & PERIODIC != 0
    }

    /// Timer ticks since the load at `now`.
    fn elapsed(&self, now: u64, hz: u64) -> Option<u64> {
        let start = self.start?;
        Some((now.saturating_sub(start) as u128 * hz as u128 / 1_000_000_000 / self.divisor() as u128) as u64)
    }

    fn expiries(&self, now: u64, hz: u64) -> u64 {
        let Some(t) = self.elapsed(now, hz) else { return 0 };
        let n = self.initial as u64;
        if self.periodic() { t / n } else { (t >= n) as u64 }
    }

    fn current(&self, now: u64, hz: u64) -> u32 {
        let Some(t) = self.elapsed(now, hz) else { return 0 };
        let n = self.initial as u64;
        if self.periodic() { (n - t % n) as u32 } else { n.saturating_sub(t) as u32 }
    }

    fn deadline(&self, hz: u64) -> Option<u64> {
        let start = self.start?;
        if !self.periodic() && self.fired > 0 {
            return None;
        }
        let ticks = (self.fired + 1) * self.initial as u64 * self.divisor();
        Some(start + (ticks as u128 * 1_000_000_000).div_ceil(hz as u128) as u64)
    }

    /// The processor priority: the higher of the task priority and the
    /// class of the highest interrupt in service.
    fn ppr(&self) -> u8 {
        let isr = self.isr.highest().unwrap_or(0) & 0xf0;
        if self.tpr & 0xf0 >= isr { self.tpr } else { isr }
    }

    /// The vector the APIC would deliver now.
    fn deliverable(&self) -> Option<u8> {
        if self.svr & SVR_ENABLE == 0 {
            return None;
        }
        let v = self.irr.highest()?;
        (v & 0xf0 > self.ppr() & 0xf0).then_some(v)
    }

    fn accept(&mut self, vector: u8) {
        if vector < 16 {
            self.esr |= 1 << 6; // received illegal vector
        } else {
            self.irr.set(vector);
        }
    }
}

type Ipi = Box<dyn Fn(u32, u32) + Send + Sync>;

/// An emulated local APIC in xAPIC (MMIO) mode, for one vCPU: task and
/// processor priority, IRR/ISR, EOI, the spurious-vector enable, and the
/// timer in one-shot and periodic modes. Put it on the vCPU's MMIO bus at
/// `0xfee0_0000` ([`LAPIC_WINDOW`] bytes) and hand an SVM vCPU
/// [`acknowledge`](Self::acknowledge) with `connect_intr`.
///
/// The timer counts at `timer_hz` (before the divide configuration) in host
/// time from a nanosecond clock, computed when read; deliver its
/// interrupts with [`poll`](Self::poll), at
/// [`next_deadline`](Self::next_deadline), as for
/// [`VirtualPit`](super::VirtualPit).
///
/// Self IPIs (shorthand, or this APIC's own ID) are delivered locally;
/// every other ICR write goes to the [`with_ipi`](Self::with_ipi) hook, to
/// be routed to other vCPUs' APICs with [`deliver`](Self::deliver). LINT0,
/// LINT1 and the error LVT can be programmed but raise nothing; TSC-deadline
/// mode is not offered.
pub struct VirtualLapic {
    state: IrqSpinLock<State>,
    timer_hz: u64,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    output: Box<dyn Fn(bool) + Send + Sync>,
    ipi: Option<Ipi>,
    asserted: core::sync::atomic::AtomicBool,
}

impl VirtualLapic {
    /// The APIC with ID `id` in its reset state (software-disabled, all
    /// LVT entries masked). Its timer runs at `timer_hz` on `clock`
    /// (monotonic nanoseconds); `output` follows whether it has an
    /// interrupt for the CPU.
    pub fn new(
        id: u8,
        timer_hz: u64,
        clock: impl Fn() -> u64 + Send + Sync + 'static,
        output: impl Fn(bool) + Send + Sync + 'static,
    ) -> Self {
        let state = State {
            id,
            tpr: 0,
            ldr: 0,
            dfr: u32::MAX,
            svr: 0xff,
            irr: Bits::default(),
            isr: Bits::default(),
            esr: 0,
            icr_high: 0,
            icr_low: 0,
            lvt: [MASKED; 4],
            initial: 0,
            divide: 0,
            start: None,
            fired: 0,
        };
        Self {
            state: IrqSpinLock::new(state),
            timer_hz,
            clock: Box::new(clock),
            output: Box::new(output),
            ipi: None,
            asserted: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Sends IPIs this APIC cannot deliver itself to `ipi(icr_high,
    /// icr_low)`: the destination is in `icr_high` bits 31:24, the vector,
    /// delivery mode and shorthand in `icr_low`.
    pub fn with_ipi(mut self, ipi: impl Fn(u32, u32) + Send + Sync + 'static) -> Self {
        self.ipi = Some(Box::new(ipi));
        self
    }

    /// Accepts a fixed interrupt with `vector` from outside (an IPI from
    /// another vCPU, or an I/O APIC).
    pub fn deliver(&self, vector: u8) {
        let mut s = self.state.lock();
        s.accept(vector);
        self.update(&s);
    }

    /// Moves the highest deliverable interrupt from IRR to ISR and returns
    /// its vector (the INTA cycle), or `None` if there is none.
    pub fn acknowledge(&self) -> Option<u8> {
        let mut s = self.state.lock();
        let v = s.deliverable()?;
        s.irr.clear(v);
        s.isr.set(v);
        self.update(&s);
        Some(v)
    }

    /// Whether this APIC has an interrupt for the CPU.
    pub fn asserted(&self) -> bool {
        self.asserted.load(core::sync::atomic::Ordering::Acquire)
    }

    /// Turns any timer expiry since the last poll into an interrupt.
    /// Returns whether there was one.
    pub fn poll(&self) -> bool {
        let now = (self.clock)();
        let mut s = self.state.lock();
        let n = s.expiries(now, self.timer_hz);
        if n <= s.fired {
            return false;
        }
        s.fired = n;
        if s.lvt[0] & MASKED == 0 {
            let v = s.lvt[0] as u8;
            s.accept(v);
        }
        self.update(&s);
        true
    }

    /// When the timer next expires (in the clock's nanoseconds), if it is
    /// counting toward an expiry not yet signalled.
    pub fn next_deadline(&self) -> Option<u64> {
        self.state.lock().deadline(self.timer_hz)
    }

    fn update(&self, s: &State) {
        let now = s.deliverable().is_some();
        if self.asserted.swap(now, core::sync::atomic::Ordering::AcqRel) != now {
            (self.output)(now);
        }
    }

    fn read_reg(&self, s: &State, reg: u64, now: u64) -> u32 {
        match reg {
            ID => (s.id as u32) << 24,
            VERSION => VERSION_VALUE,
            TPR => s.tpr as u32,
            PPR => s.ppr() as u32,
            LDR => s.ldr,
            DFR => s.dfr,
            SVR => s.svr,
            ISR..0x180 => s.isr.0[((reg - ISR) / 0x10) as usize],
            TMR..0x200 => 0,
            IRR..0x280 => s.irr.0[((reg - IRR) / 0x10) as usize],
            ESR => s.esr,
            ICR_LOW => s.icr_low,
            ICR_HIGH => s.icr_high,
            LVT_TIMER => s.lvt[0],
            LVT_LINT0 => s.lvt[1],
            LVT_LINT1 => s.lvt[2],
            LVT_ERROR => s.lvt[3],
            TIMER_INITIAL => s.initial,
            TIMER_CURRENT => s.current(now, self.timer_hz),
            TIMER_DIVIDE => s.divide,
            _ => 0,
        }
    }
}

impl BusDevice for VirtualLapic {
    fn read(&self, offset: u64, data: &mut [u8]) {
        self.poll();
        let now = (self.clock)();
        let v = self.read_reg(&self.state.lock(), offset & !0xf, now);
        // Registers are 32 bits wide at 16-byte strides.
        let bytes = (v >> (8 * (offset & 3))).to_le_bytes();
        let n = data.len().min(4);
        data[..n].copy_from_slice(&bytes[..n]);
        data[n..].fill(0);
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let mut b = [0u8; 4];
        let n = data.len().min(4);
        b[..n].copy_from_slice(&data[..n]);
        let v = u32::from_le_bytes(b);
        let now = (self.clock)();
        let mut s = self.state.lock();
        let mut ipi = None;
        match offset {
            TPR => s.tpr = v as u8,
            EOI => {
                if let Some(i) = s.isr.highest() {
                    s.isr.clear(i);
                }
            }
            LDR => s.ldr = v & 0xff00_0000,
            DFR => s.dfr = v | 0x0fff_ffff,
            SVR => {
                s.svr = v & 0x3ff;
                if v & SVR_ENABLE == 0 {
                    // Software disable masks every LVT entry.
                    for l in &mut s.lvt {
                        *l |= MASKED;
                    }
                }
            }
            ESR => s.esr = 0,
            ICR_HIGH => s.icr_high = v & 0xff00_0000,
            ICR_LOW => {
                s.icr_low = v & !(1 << 12); // delivery status: always idle
                let (vector, mode, shorthand) = (v as u8, (v >> 8) & 7, (v >> 18) & 3);
                let to_self = shorthand == 1 || (shorthand == 0 && s.icr_high >> 24 == s.id as u32);
                if mode == 0 && to_self {
                    s.accept(vector);
                }
                if shorthand >= 2 || !to_self {
                    // Others (all-including-self also lands here).
                    if shorthand == 2 && mode == 0 {
                        s.accept(vector);
                    }
                    ipi = Some((s.icr_high, s.icr_low));
                }
            }
            LVT_TIMER | LVT_LINT0 | LVT_LINT1 | LVT_ERROR => {
                let i = ((offset - LVT_TIMER) / 0x10) as usize;
                let i = if i == 0 { 0 } else { i - 2 };
                s.lvt[i] = if s.svr & SVR_ENABLE == 0 { v | MASKED } else { v };
            }
            TIMER_INITIAL => {
                s.initial = v;
                s.start = (v != 0).then_some(now);
                s.fired = 0;
            }
            TIMER_DIVIDE => s.divide = v & 0xb,
            _ => {}
        }
        self.update(&s);
        drop(s);
        if let (Some((high, low)), Some(f)) = (ipi, &self.ipi) {
            f(high, low);
        }
        self.poll();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    struct Rig {
        apic: VirtualLapic,
        now: Arc<AtomicU64>,
        line: Arc<AtomicBool>,
    }

    /// A 100 MHz timer: 10 ns per tick.
    fn rig() -> Rig {
        let now = Arc::new(AtomicU64::new(500));
        let line = Arc::new(AtomicBool::new(false));
        let (n, l) = (now.clone(), line.clone());
        let apic =
            VirtualLapic::new(0, 100_000_000, move || n.load(Ordering::SeqCst), move |v| l.store(v, Ordering::SeqCst));
        Rig { apic, now, line }
    }

    impl Rig {
        fn w(&self, reg: u64, v: u32) {
            self.apic.write(reg, &v.to_le_bytes());
        }
        fn r(&self, reg: u64) -> u32 {
            let mut b = [0; 4];
            self.apic.read(reg, &mut b);
            u32::from_le_bytes(b)
        }
        fn line(&self) -> bool {
            self.line.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn priorities_and_eoi() {
        let r = rig();
        r.apic.deliver(0x41);
        assert!(!r.line(), "software-disabled after reset");
        r.w(SVR, 0x1ff);
        assert!(r.line());
        r.apic.deliver(0x62);
        assert_eq!(r.apic.acknowledge(), Some(0x62), "highest vector first");
        assert_eq!(r.r(PPR), 0x60);
        assert!(!r.line(), "0x41 waits behind 0x62 in service");
        r.w(EOI, 0);
        assert!(r.line());
        r.w(TPR, 0x40);
        assert!(!r.line(), "TPR class 4 holds back 0x41");
        r.w(TPR, 0x30);
        assert_eq!(r.apic.acknowledge(), Some(0x41));
        assert_eq!(r.r(ISR + 0x20), 1 << 1, "ISR word 2 bit 1 = vector 0x41");
        r.w(EOI, 0);
        assert_eq!(r.apic.acknowledge(), None);
    }

    #[test]
    fn periodic_timer() {
        let r = rig();
        r.w(SVR, 0x1ff);
        r.w(TIMER_DIVIDE, 0x3); // divide by 16
        r.w(LVT_TIMER, PERIODIC | 0x40);
        r.w(TIMER_INITIAL, 1000); // 1000 * 16 ticks of 10 ns = 160 us
        assert_eq!(r.apic.next_deadline(), Some(500 + 160_000));
        r.now.fetch_add(40_000, Ordering::SeqCst);
        assert_eq!(r.r(TIMER_CURRENT), 750);
        assert!(!r.line());
        r.now.fetch_add(120_000, Ordering::SeqCst);
        assert!(r.apic.poll());
        assert_eq!(r.apic.acknowledge(), Some(0x40));
        r.w(EOI, 0);
        assert_eq!(r.apic.next_deadline(), Some(500 + 320_000));
        // Masked: the timer counts on, raising nothing.
        r.w(LVT_TIMER, PERIODIC | MASKED | 0x40);
        r.now.fetch_add(200_000, Ordering::SeqCst);
        assert!(r.apic.poll());
        assert!(!r.line());
        // Initial count 0 stops it.
        r.w(TIMER_INITIAL, 0);
        assert_eq!(r.apic.next_deadline(), None);
    }

    #[test]
    fn one_shot_timer_and_self_ipi() {
        let r = rig();
        r.w(SVR, 0x1ff);
        r.w(TIMER_DIVIDE, 0xb); // divide by 1
        r.w(LVT_TIMER, 0x50);
        r.w(TIMER_INITIAL, 100);
        r.now.fetch_add(1000, Ordering::SeqCst);
        assert_eq!(r.r(TIMER_CURRENT), 0, "the read polls the expiry");
        assert_eq!(r.apic.next_deadline(), None);
        assert_eq!(r.apic.acknowledge(), Some(0x50));
        r.w(EOI, 0);
        // A self IPI by shorthand, and one to another APIC through the hook.
        let sent = Arc::new(IrqSpinLock::new(Vec::new()));
        let s = sent.clone();
        let r = Rig { apic: r.apic.with_ipi(move |h, l| s.lock().push((h >> 24, l as u8))), ..r };
        r.w(ICR_LOW, 1 << 18 | 0x60);
        assert_eq!(r.apic.acknowledge(), Some(0x60));
        r.w(EOI, 0);
        r.w(ICR_HIGH, 1 << 24);
        r.w(ICR_LOW, 0x61);
        assert_eq!(*sent.lock(), [(1, 0x61)]);
        assert_eq!(r.apic.acknowledge(), None);
        // Vectors 0-15 are illegal: refused, and the error recorded.
        r.apic.deliver(0x05);
        assert_eq!(r.apic.acknowledge(), None);
        assert_eq!(r.r(ESR), 1 << 6);
    }
}
