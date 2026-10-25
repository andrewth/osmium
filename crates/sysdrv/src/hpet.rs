//! x86 High Precision Event Timer (HPET).
//!
//! One free-running main counter (at least 10 MHz, 32 or 64 bits wide) and a
//! few comparators. [`Hpet`] implements [`Clock`] on the main counter; each
//! comparator is a one-shot or periodic timer, reached through [`Hpet`]'s
//! per-index methods or through [`HpetTimer`], which implements
//! [`OneShotTimer`].
//!
//! A comparator's interrupt reaches the CPU in one of two ways:
//!
//! * **Legacy replacement** ([`Hpet::set_legacy_replacement`]): comparator 0
//!   drives ISA IRQ 0 (the PIT's line) and comparator 1 drives IRQ 8 (the RTC's). Route them
//!   as the ACPI MADT says (IRQ 0 usually lands on GSI 2).
//! * **I/O APIC routing** ([`Hpet::route`]): the comparator drives one of the I/O APIC inputs its
//!   capability mask allows. Program that input in the [`IoApic`](crate::ioapic::IoApic) with
//!   [`LineMode`](crate::ioapic::LineMode) matching the `level` argument.
//!
//! Message (FSB) delivery is not supported.
//!
//! Where the HPET lives comes from the ACPI `HPET` table
//! (`HpetTable` in the `boot` crate's `acpi` module) or from the platform.
//!
//! # Time
//!
//! The counter period is a count of femtoseconds, read from the capabilities register and
//! checked against the specification's 100 ns limit. With a 32-bit counter [`Clock::now_ns`] extends it to
//! 64 bits by noticing wraps, so it must be called at least once per wrap (about 5 minutes at
//! 14.3 MHz); a comparator that is armed does so itself.

use core::sync::atomic::{AtomicU64, Ordering};
use osmium_hal::ioext::IoMemExt;
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::{Clock, OneShotTimer};

const GCAP_ID: usize = 0x00;
const GEN_CONFIG: usize = 0x10;
const GINTR_STA: usize = 0x20;
const MAIN_COUNTER: usize = 0xf0;
const TIMER_BASE: usize = 0x100;
const TIMER_STRIDE: usize = 0x20;
const TIMER_COMPARATOR: usize = 0x08;

/// Size of the register block in bytes.
pub const REGISTER_BYTES: usize = 0x400;

const ENABLE_CNF: u64 = 1 << 0;
const LEG_RT_CNF: u64 = 1 << 1;

const GCAP_LEG_RT_CAP: u64 = 1 << 15;
const GCAP_COUNT_SIZE_CAP: u64 = 1 << 13;

const TN_INT_TYPE_LEVEL: u64 = 1 << 1;
const TN_INT_ENB: u64 = 1 << 2;
const TN_TYPE_PERIODIC: u64 = 1 << 3;
const TN_PER_INT_CAP: u64 = 1 << 4;
const TN_SIZE_CAP: u64 = 1 << 5;
const TN_VAL_SET: u64 = 1 << 6;
const TN_32MODE: u64 = 1 << 8;
const TN_ROUTE_SHIFT: u32 = 9;
const TN_ROUTE_MASK: u64 = 0x1f << TN_ROUTE_SHIFT;
const TN_FSB_EN: u64 = 1 << 14;

/// The specification's longest counter period: 100 ns, in femtoseconds.
const MAX_PERIOD_FS: u32 = 100_000_000;
const FS_PER_NS: u128 = 1_000_000;
/// A comparator is never armed closer than this many ticks to the counter, so the match cannot
/// be missed while the write is in flight.
const MIN_TICKS: u64 = 8;

/// Why an HPET could not be used or a request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HpetError {
    /// The register block reads as absent (all ones) or reports a counter period of zero or over 100 ns.
    BadDevice,
    /// The comparator index is beyond the ones the hardware has.
    NoSuchTimer,
    /// The comparator cannot run in periodic mode.
    NotPeriodic,
    /// The period is zero or does not fit the comparator.
    BadPeriod,
    /// The comparator cannot be wired to that interrupt line.
    BadRoute,
    /// The HPET lacks the legacy replacement option.
    NoLegacyReplacement,
}

/// What one comparator can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerCaps {
    /// Supports periodic mode.
    pub periodic: bool,
    /// Has a 64-bit comparator (it is compared in 32 bits when the main counter is 32 bits wide).
    pub wide: bool,
    /// Bit `n` set: the comparator can drive I/O APIC input `n`.
    pub routes: u32,
}

/// An HPET.
///
/// Configuration methods read, modify and write registers without a lock: one owner should set
/// the device up. The counter and [`OneShotTimer`] methods may be used from any CPU.
pub struct Hpet {
    io: IoMem,
    period_fs: u32,
    timers: u8,
    counter64: bool,
    legacy_cap: bool,
    /// The last 64-bit time handed out for a 32-bit counter.
    extended: AtomicU64,
}

impl Hpet {
    /// Wraps the register block (mapped uncached; [`REGISTER_BYTES`] long) and checks that it
    /// looks like an HPET. The counter is left as it is: call [`Hpet::enable`] to run it.
    pub fn new(io: IoMem) -> Result<Self, HpetError> {
        let cap: u64 = io.rd(GCAP_ID);
        let period_fs = (cap >> 32) as u32;
        if cap == u64::MAX || period_fs == 0 || period_fs > MAX_PERIOD_FS {
            return Err(HpetError::BadDevice);
        }
        let hpet = Self {
            io,
            period_fs,
            timers: (((cap >> 8) & 0x1f) + 1) as u8,
            counter64: cap & GCAP_COUNT_SIZE_CAP != 0,
            legacy_cap: cap & GCAP_LEG_RT_CAP != 0,
            extended: AtomicU64::new(0),
        };
        // Start the 32-bit extension from the counter as it is now.
        let _ = hpet.ticks();
        Ok(hpet)
    }

    /// The counter period in femtoseconds.
    pub fn period_fs(&self) -> u32 {
        self.period_fs
    }

    /// The counter frequency in Hz, rounded down.
    pub fn frequency(&self) -> u64 {
        // 10^15 fs per second; the period is nonzero (checked in `new`).
        1_000_000_000_000_000 / self.period_fs as u64
    }

    /// The number of comparators.
    pub fn timer_count(&self) -> usize {
        self.timers as usize
    }

    /// True if the main counter is 64 bits wide.
    pub fn counter_is_64bit(&self) -> bool {
        self.counter64
    }

    /// True if legacy replacement routing is available.
    pub fn has_legacy_replacement(&self) -> bool {
        self.legacy_cap
    }

    /// Starts the main counter and lets comparators interrupt.
    pub fn enable(&self) {
        let v: u64 = self.io.rd(GEN_CONFIG);
        self.io.wr(GEN_CONFIG, v | ENABLE_CNF);
    }

    /// Halts the main counter (comparators stop matching).
    pub fn disable(&self) {
        let v: u64 = self.io.rd(GEN_CONFIG);
        self.io.wr(GEN_CONFIG, v & !ENABLE_CNF);
    }

    /// Turns legacy replacement routing on or off.
    pub fn set_legacy_replacement(&self, on: bool) -> Result<(), HpetError> {
        if !self.legacy_cap {
            return Err(HpetError::NoLegacyReplacement);
        }
        let v: u64 = self.io.rd(GEN_CONFIG);
        self.io.wr(GEN_CONFIG, if on { v | LEG_RT_CNF } else { v & !LEG_RT_CNF });
        Ok(())
    }

    /// Ticks to nanoseconds, saturating.
    pub fn ticks_to_ns(&self, ticks: u64) -> u64 {
        saturate(ticks as u128 * self.period_fs as u128 / FS_PER_NS)
    }

    /// Nanoseconds to ticks, saturating.
    pub fn ns_to_ticks(&self, ns: u64) -> u64 {
        saturate(ns as u128 * FS_PER_NS / self.period_fs as u128)
    }

    /// The raw main counter (32 bits wide unless [`Hpet::counter_is_64bit`]).
    pub fn raw_counter(&self) -> u64 {
        if self.counter64 { self.io.rd(MAIN_COUNTER) } else { self.io.rd::<u32>(MAIN_COUNTER) as u64 }
    }

    /// The main counter as a 64-bit tick count, extending a 32-bit counter across wraps.
    pub fn ticks(&self) -> u64 {
        let raw = self.raw_counter();
        if self.counter64 {
            return raw;
        }
        let mut prev = self.extended.load(Ordering::Relaxed);
        loop {
            let mut next = (prev & !0xffff_ffff) | raw;
            if next < prev {
                // The low half went backwards: the counter wrapped since the last call.
                next = next.saturating_add(1 << 32);
            }
            match self.extended.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return next,
                Err(p) => prev = p,
            }
        }
    }

    /// A handle to comparator `index`, or `None` if there is no such comparator.
    pub fn timer(&self, index: usize) -> Option<HpetTimer<'_>> {
        (index < self.timer_count()).then_some(HpetTimer { hpet: self, index: index as u8 })
    }

    fn cfg_reg(index: u8) -> usize {
        TIMER_BASE + TIMER_STRIDE * index as usize
    }

    fn check(&self, index: usize) -> Result<u8, HpetError> {
        if index < self.timer_count() { Ok(index as u8) } else { Err(HpetError::NoSuchTimer) }
    }

    /// What comparator `index` can do.
    pub fn caps(&self, index: usize) -> Result<TimerCaps, HpetError> {
        let cfg: u64 = self.io.rd(Self::cfg_reg(self.check(index)?));
        Ok(TimerCaps { periodic: cfg & TN_PER_INT_CAP != 0, wide: cfg & TN_SIZE_CAP != 0, routes: (cfg >> 32) as u32 })
    }

    /// The comparator's width in bits as it will be compared against the main counter.
    fn width_mask(&self, cfg: u64) -> u64 {
        if self.counter64 && cfg & TN_SIZE_CAP != 0 { u64::MAX } else { 0xffff_ffff }
    }

    fn write_comparator(&self, index: u8, mask: u64, value: u64) {
        let reg = Self::cfg_reg(index) + TIMER_COMPARATOR;
        if mask == u64::MAX { self.io.wr(reg, value) } else { self.io.wr(reg, value as u32) }
    }

    /// Wires comparator `index` to I/O APIC input `gsi_input` (the line number on the I/O APIC the
    /// HPET is connected to; usually the same as the GSI), edge- or level-triggered. Ignored while
    /// legacy replacement is on for comparators 0 and 1. Does not enable interrupts: arming does.
    pub fn route(&self, index: usize, gsi_input: u8, level: bool) -> Result<(), HpetError> {
        let index = self.check(index)?;
        let reg = Self::cfg_reg(index);
        let cfg: u64 = self.io.rd(reg);
        if gsi_input >= 32 || (cfg >> 32) & (1 << gsi_input) == 0 {
            return Err(HpetError::BadRoute);
        }
        let mut cfg = (cfg & !(TN_ROUTE_MASK | TN_INT_TYPE_LEVEL | TN_FSB_EN)) | ((gsi_input as u64) << TN_ROUTE_SHIFT);
        if level {
            cfg |= TN_INT_TYPE_LEVEL;
        }
        self.io.wr(reg, cfg);
        Ok(())
    }

    /// Arms comparator `index` as a one-shot timer that fires when the main counter reaches
    /// absolute time `deadline_ns` (on the scale of [`Clock::now_ns`]). A deadline in the past
    /// fires after a few ticks. A comparator that is 32 bits wide cannot wait longer than half
    /// its range (about 150 s at 14.3 MHz), so a farther deadline fires early and must be re-armed.
    pub fn arm_oneshot(&self, index: usize, deadline_ns: u64) -> Result<(), HpetError> {
        let index = self.check(index)?;
        let reg = Self::cfg_reg(index);
        let cfg: u64 = self.io.rd(reg);
        let mask = self.width_mask(cfg);
        let target = self.ns_to_ticks(deadline_ns);
        let now = self.ticks();
        let mut delta = target.saturating_sub(now).max(MIN_TICKS);
        if mask != u64::MAX {
            delta = delta.min(mask >> 1);
        }
        let cfg = (cfg & !(TN_TYPE_PERIODIC | TN_VAL_SET | TN_FSB_EN | TN_32MODE)) | TN_INT_ENB;
        self.io.wr(reg, cfg);
        let mut cmp = now.wrapping_add(delta) & mask;
        self.write_comparator(index, mask, cmp);
        // Writing took time: if the counter has already passed the match value the interrupt
        // would only come after a full wrap, so move it a little ahead of the counter instead.
        for _ in 0..4 {
            let raw = self.raw_counter() & mask;
            if cmp.wrapping_sub(raw) & mask <= mask >> 1 && cmp.wrapping_sub(raw) & mask >= MIN_TICKS / 2 {
                break;
            }
            cmp = raw.wrapping_add(MIN_TICKS * 2) & mask;
            self.write_comparator(index, mask, cmp);
        }
        Ok(())
    }

    /// Starts comparator `index` interrupting every `period_ns` nanoseconds (rounded down to
    /// whole counter ticks), the first time one period from now.
    pub fn start_periodic(&self, index: usize, period_ns: u64) -> Result<(), HpetError> {
        let index = self.check(index)?;
        let reg = Self::cfg_reg(index);
        let cfg: u64 = self.io.rd(reg);
        if cfg & TN_PER_INT_CAP == 0 {
            return Err(HpetError::NotPeriodic);
        }
        let mask = self.width_mask(cfg);
        let period = self.ns_to_ticks(period_ns);
        if period == 0 || period > mask >> 1 {
            return Err(HpetError::BadPeriod);
        }
        let cfg = (cfg & !(TN_FSB_EN | TN_32MODE)) | TN_TYPE_PERIODIC | TN_INT_ENB;
        // With VAL_SET the first comparator write sets the accumulator (the next match), the
        // second the period that is added after each match.
        self.io.wr(reg, cfg | TN_VAL_SET);
        self.write_comparator(index, mask, self.ticks().wrapping_add(period.max(MIN_TICKS)) & mask);
        self.write_comparator(index, mask, period);
        Ok(())
    }

    /// Stops comparator `index` from interrupting.
    pub fn stop(&self, index: usize) -> Result<(), HpetError> {
        let index = self.check(index)?;
        let reg = Self::cfg_reg(index);
        let cfg: u64 = self.io.rd(reg);
        self.io.wr(reg, cfg & !(TN_INT_ENB | TN_TYPE_PERIODIC | TN_VAL_SET));
        Ok(())
    }

    /// Acknowledges a level-triggered comparator interrupt. Edge-triggered ones need nothing.
    pub fn ack(&self, index: usize) -> Result<(), HpetError> {
        let index = self.check(index)?;
        self.io.wr(GINTR_STA, 1u64 << index);
        Ok(())
    }

    /// Bit `n` set: comparator `n` has a level-triggered interrupt pending.
    pub fn pending(&self) -> u32 {
        self.io.rd::<u64>(GINTR_STA) as u32
    }
}

fn saturate(v: u128) -> u64 {
    v.min(u64::MAX as u128) as u64
}

impl Clock for Hpet {
    fn now_ns(&self) -> u64 {
        self.ticks_to_ns(self.ticks())
    }
}

/// One comparator of an [`Hpet`] as a [`OneShotTimer`]. The interrupt routing must already be
/// set up, through legacy replacement or [`Hpet::route`].
#[derive(Clone, Copy)]
pub struct HpetTimer<'hpet> {
    hpet: &'hpet Hpet,
    index: u8,
}

impl HpetTimer<'_> {
    /// The comparator's index.
    pub fn index(&self) -> usize {
        self.index as usize
    }
}

impl OneShotTimer for HpetTimer<'_> {
    fn set_deadline(&self, deadline_ns: u64) {
        // The index was checked when this handle was made.
        let _ = self.hpet.arm_oneshot(self.index(), deadline_ns);
    }

    fn cancel(&self) {
        let _ = self.hpet.stop(self.index());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// QEMU's HPET: 62.5 MHz would be 16 ns; the common 10 MHz (100 ns) one is used here.
    const PERIOD: u64 = 100_000_000;

    struct Fake {
        regs: Vec<AtomicU64>,
    }

    impl Fake {
        /// `timers` comparators, all 64-bit and periodic-capable and routable to inputs 20-23
        /// except comparator 0 (inputs 0 and 2 as well), with a 64-bit counter if `wide`.
        fn new(period: u64, timers: u64, wide: bool) -> Self {
            let regs: Vec<_> = (0..REGISTER_BYTES / 8).map(|_| AtomicU64::new(0)).collect();
            let cap =
                (period << 32) | GCAP_LEG_RT_CAP | (timers - 1) << 8 | if wide { GCAP_COUNT_SIZE_CAP } else { 0 } | 1;
            regs[GCAP_ID / 8].store(cap, Ordering::Relaxed);
            for t in 0..timers {
                let routes = if t == 0 { 0x00f0_0005u64 } else { 0x00f0_0000 };
                regs[(TIMER_BASE + TIMER_STRIDE * t as usize) / 8]
                    .store(routes << 32 | TN_PER_INT_CAP | TN_SIZE_CAP, Ordering::Relaxed);
            }
            Self { regs }
        }
        fn hpet(&self) -> Hpet {
            // SAFETY: the window covers the buffer, which outlives the driver in every test.
            let io = unsafe { IoMem::new(self.regs.as_ptr() as *mut u8, REGISTER_BYTES) };
            Hpet::new(io).expect("valid device")
        }
        fn get(&self, off: usize) -> u64 {
            self.regs[off / 8].load(Ordering::Relaxed)
        }
        fn set(&self, off: usize, v: u64) {
            self.regs[off / 8].store(v, Ordering::Relaxed);
        }
        fn cfg(&self, t: usize) -> u64 {
            self.get(TIMER_BASE + TIMER_STRIDE * t)
        }
        fn cmp(&self, t: usize) -> u64 {
            self.get(TIMER_BASE + TIMER_STRIDE * t + TIMER_COMPARATOR)
        }
    }

    #[test]
    fn rejects_bad_devices() {
        let f = Fake::new(PERIOD, 3, true);
        f.set(GCAP_ID, f.get(GCAP_ID) & 0xffff_ffff); // period 0
        assert_eq!(f.hpet_err(), HpetError::BadDevice);
        f.set(GCAP_ID, u64::MAX);
        assert_eq!(f.hpet_err(), HpetError::BadDevice);
        f.set(GCAP_ID, (u64::from(MAX_PERIOD_FS) + 1) << 32);
        assert_eq!(f.hpet_err(), HpetError::BadDevice);
        f.set(GCAP_ID, u64::from(MAX_PERIOD_FS) << 32);
        assert!(Hpet::new(unsafe_io(&f)).is_ok());
    }

    fn unsafe_io(f: &Fake) -> IoMem {
        // SAFETY: the window covers the buffer, which outlives the use in each test.
        unsafe { IoMem::new(f.regs.as_ptr() as *mut u8, REGISTER_BYTES) }
    }

    impl Fake {
        fn hpet_err(&self) -> HpetError {
            Hpet::new(unsafe_io(self)).err().expect("rejected")
        }
    }

    #[test]
    fn identity_and_clock() {
        let f = Fake::new(PERIOD, 3, true);
        let h = f.hpet();
        assert_eq!((h.timer_count(), h.frequency(), h.counter_is_64bit()), (3, 10_000_000, true));
        assert!(h.has_legacy_replacement());
        h.enable();
        assert_eq!(f.get(GEN_CONFIG), ENABLE_CNF);
        f.set(MAIN_COUNTER, 10_000_000);
        assert_eq!(h.now_ns(), 1_000_000_000);
        // A huge counter does not overflow the conversion; it saturates.
        f.set(MAIN_COUNTER, u64::MAX);
        assert_eq!(h.now_ns(), u64::MAX);
        h.disable();
        assert_eq!(f.get(GEN_CONFIG), 0);
        // A 10 ns tick.
        let g = Fake::new(10_000_000, 2, true);
        g.set(MAIN_COUNTER, 123);
        assert_eq!(g.hpet().now_ns(), 1230);
        assert_eq!(g.hpet().ns_to_ticks(1230), 123);
    }

    #[test]
    fn counter32_wraps_are_extended() {
        let f = Fake::new(PERIOD, 3, false);
        f.set(MAIN_COUNTER, 0xffff_fff0);
        let h = f.hpet();
        assert_eq!(h.ticks(), 0xffff_fff0);
        f.set(MAIN_COUNTER, 0xffff_ffff);
        assert_eq!(h.ticks(), 0xffff_ffff);
        f.set(MAIN_COUNTER, 5);
        assert_eq!(h.ticks(), (1 << 32) + 5);
        f.set(MAIN_COUNTER, 0x8000_0000);
        assert_eq!(h.ticks(), (1 << 32) + 0x8000_0000);
        f.set(MAIN_COUNTER, 1);
        assert_eq!(h.ticks(), (2 << 32) + 1);
        // Only the low half of the register is the counter.
        f.set(MAIN_COUNTER, 0xdead_beef_0000_0002);
        assert_eq!(h.ticks(), (2 << 32) + 2);
    }

    #[test]
    fn one_shot_arms_ahead_of_the_counter() {
        let f = Fake::new(PERIOD, 3, true);
        let h = f.hpet();
        f.set(MAIN_COUNTER, 1000);
        h.timer(1).expect("timer 1").set_deadline(h.ticks_to_ns(5000));
        assert_eq!(f.cmp(1), 5000);
        assert_eq!(f.cfg(1) & (TN_INT_ENB | TN_TYPE_PERIODIC), TN_INT_ENB);
        // Nothing else changes.
        assert_eq!(f.cmp(0), 0);
        assert_eq!(f.cfg(0) & TN_INT_ENB, 0);
        // A deadline in the past fires a few ticks from now.
        h.arm_oneshot(1, 0).unwrap();
        assert_eq!(f.cmp(1), 1000 + MIN_TICKS);
        h.timer(1).unwrap().cancel();
        assert_eq!(f.cfg(1) & TN_INT_ENB, 0);
        assert!(h.timer(3).is_none());
        assert_eq!(h.arm_oneshot(3, 5), Err(HpetError::NoSuchTimer));
    }

    #[test]
    fn narrow_comparators_wrap_and_clamp() {
        let f = Fake::new(PERIOD, 2, false);
        let h = f.hpet();
        f.set(MAIN_COUNTER, 0xffff_ff00);
        let _ = h.ticks();
        // 0x200 ticks ahead crosses the 32-bit wrap: compared on the low 32 bits.
        h.arm_oneshot(0, h.ticks_to_ns(0xffff_ff00 + 0x200)).unwrap();
        assert_eq!(f.cmp(0), 0x100);
        // Far in the future: clamped to half the range from now.
        h.arm_oneshot(0, u64::MAX).unwrap();
        assert_eq!(f.cmp(0), (0xffff_ff00 + 0x7fff_ffff) & 0xffff_ffff);
    }

    #[test]
    fn periodic_mode() {
        let f = Fake::new(PERIOD, 3, true);
        let h = f.hpet();
        f.set(MAIN_COUNTER, 100);
        h.start_periodic(2, 1_000_000).unwrap(); // 1 ms = 10_000 ticks
        assert_eq!(f.cmp(2), 10_000, "period is the last comparator write");
        assert_eq!(f.cfg(2) & (TN_TYPE_PERIODIC | TN_INT_ENB | TN_VAL_SET), TN_TYPE_PERIODIC | TN_INT_ENB | TN_VAL_SET);
        assert_eq!(h.start_periodic(2, 0), Err(HpetError::BadPeriod));
        assert_eq!(h.start_periodic(2, 50), Err(HpetError::BadPeriod), "under one tick");
        assert_eq!(h.start_periodic(7, 1_000_000), Err(HpetError::NoSuchTimer));
        h.stop(2).unwrap();
        assert_eq!(f.cfg(2) & (TN_TYPE_PERIODIC | TN_INT_ENB), 0);
        // One-shot afterwards clears the periodic bit again.
        h.arm_oneshot(2, 1_000_000).unwrap();
        assert_eq!(f.cfg(2) & (TN_TYPE_PERIODIC | TN_INT_ENB), TN_INT_ENB);
        // Without the capability, and with a period too long for 32 bits.
        f.set(TIMER_BASE + TIMER_STRIDE, f.cfg(1) & !TN_PER_INT_CAP);
        assert_eq!(h.start_periodic(1, 1_000_000), Err(HpetError::NotPeriodic));
        let n = Fake::new(PERIOD, 2, false);
        assert_eq!(n.hpet().start_periodic(0, 400_000_000_000), Err(HpetError::BadPeriod));
        assert!(n.hpet().start_periodic(0, 100_000_000_000).is_ok());
    }

    #[test]
    fn routing() {
        let f = Fake::new(PERIOD, 3, true);
        let h = f.hpet();
        h.route(0, 2, true).unwrap();
        assert_eq!((f.cfg(0) & TN_ROUTE_MASK) >> TN_ROUTE_SHIFT, 2);
        assert_ne!(f.cfg(0) & TN_INT_TYPE_LEVEL, 0);
        assert_eq!(f.cfg(0) & TN_INT_ENB, 0, "routing does not enable");
        h.route(0, 20, false).unwrap();
        assert_eq!((f.cfg(0) & TN_ROUTE_MASK) >> TN_ROUTE_SHIFT, 20);
        assert_eq!(f.cfg(0) & TN_INT_TYPE_LEVEL, 0);
        assert_eq!(h.route(1, 2, false), Err(HpetError::BadRoute), "not in the capability mask");
        assert_eq!(h.route(1, 32, false), Err(HpetError::BadRoute));
        assert_eq!(h.route(1, 255, false), Err(HpetError::BadRoute));
        assert_eq!(h.route(5, 20, false), Err(HpetError::NoSuchTimer));
        let caps = h.caps(0).unwrap();
        assert!(caps.periodic && caps.wide);
        assert_eq!(caps.routes, 0x00f0_0005);
        // Level interrupts are acknowledged by writing their status bit.
        h.ack(2).unwrap();
        assert_eq!(f.get(GINTR_STA), 4);
    }

    #[test]
    fn legacy_replacement() {
        let f = Fake::new(PERIOD, 3, true);
        let h = f.hpet();
        h.enable();
        h.set_legacy_replacement(true).unwrap();
        assert_eq!(f.get(GEN_CONFIG), ENABLE_CNF | LEG_RT_CNF);
        h.set_legacy_replacement(false).unwrap();
        assert_eq!(f.get(GEN_CONFIG), ENABLE_CNF);
        f.set(GCAP_ID, f.get(GCAP_ID) & !GCAP_LEG_RT_CAP);
        let h = f.hpet();
        assert_eq!(h.set_legacy_replacement(true), Err(HpetError::NoLegacyReplacement));
    }
}
