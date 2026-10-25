//! Where file systems get the time from.
//!
//! No file system reads hardware itself. Time comes from a [`Clock`], which
//! the platform implements over its RTC or timer. A file system can be given
//! its own clock (see [`ClockSlot`]); otherwise it uses the global one set by
//! [`set_clock`], and with neither, every time is the epoch (1970-01-01).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, AtomicU32, Ordering};

use osmium_sync::RwSpinLock;

/// A point in time: seconds and nanoseconds since 1970-01-01 00:00:00 UTC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp {
    /// Whole seconds since the epoch (negative before it).
    pub sec: i64,
    /// Nanoseconds past `sec`, below 1_000_000_000.
    pub nsec: u32,
}

impl Timestamp {
    /// The epoch.
    pub const ZERO: Timestamp = Timestamp { sec: 0, nsec: 0 };

    /// A whole-second time.
    pub const fn from_secs(sec: i64) -> Self {
        Timestamp { sec, nsec: 0 }
    }
}

/// A source of wall-clock time.
pub trait Clock: Send + Sync {
    /// The current time.
    fn now(&self) -> Timestamp;
}

/// A clock that reads whatever it was last set to, for tests and for
/// platforms without a time source that still want stable stamps.
#[derive(Debug, Default)]
pub struct ManualClock {
    sec: AtomicI64,
    nsec: AtomicU32,
}

impl ManualClock {
    /// A clock showing `t`.
    pub const fn new(t: Timestamp) -> Self {
        ManualClock { sec: AtomicI64::new(t.sec), nsec: AtomicU32::new(t.nsec) }
    }

    /// Sets the time shown.
    pub fn set(&self, t: Timestamp) {
        self.sec.store(t.sec, Ordering::Relaxed);
        self.nsec.store(t.nsec, Ordering::Relaxed);
    }

    /// Moves the time forward by `secs` seconds.
    pub fn advance(&self, secs: i64) {
        self.sec.fetch_add(secs, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        Timestamp { sec: self.sec.load(Ordering::Relaxed), nsec: self.nsec.load(Ordering::Relaxed) }
    }
}

/// A clock that may be set later: a file system's own, falling back to the
/// global clock while unset.
pub struct ClockSlot(RwSpinLock<Option<Arc<dyn Clock>>>);

impl Default for ClockSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockSlot {
    /// An empty slot, which reads the global clock.
    pub const fn new() -> Self {
        ClockSlot(RwSpinLock::new(None))
    }

    /// Uses `clock` from now on.
    pub fn set(&self, clock: Arc<dyn Clock>) {
        *self.0.write() = Some(clock);
    }

    fn own(&self) -> Option<Arc<dyn Clock>> {
        self.0.read().clone()
    }

    /// The time: from the slot's clock if it has one, else the global one.
    pub fn now(&self) -> Timestamp {
        match self.own() {
            Some(c) => c.now(),
            None => now(),
        }
    }
}

static GLOBAL: ClockSlot = ClockSlot::new();

/// Sets the clock that file systems without their own use. Call it once
/// the platform has a time source.
pub fn set_clock(clock: Arc<dyn Clock>) {
    GLOBAL.set(clock);
}

/// The time from the global clock, or the epoch if none is set.
pub fn now() -> Timestamp {
    GLOBAL.own().map_or(Timestamp::ZERO, |c| c.now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_prefers_its_own_clock() {
        let slot = ClockSlot::new();
        assert_eq!(slot.now().nsec, 0);
        let c = Arc::new(ManualClock::new(Timestamp { sec: 100, nsec: 5 }));
        slot.set(c.clone());
        assert_eq!(slot.now(), Timestamp { sec: 100, nsec: 5 });
        c.advance(10);
        assert_eq!(slot.now().sec, 110);
    }
}
