//! Time as the caller reports it.

use core::ops::{Add, Sub};
use core::time::Duration;

/// A point in time with millisecond resolution, on whatever monotonic clock
/// the caller uses. Only differences matter, so the epoch can be boot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    /// The clock's epoch. [`Interface::poll_at`](crate::Interface::poll_at)
    /// returns it when the interface has work to do immediately.
    pub const ZERO: Self = Self(0);

    /// `ms` milliseconds after the epoch.
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// `us` microseconds after the epoch, truncated to milliseconds.
    pub const fn from_micros(us: u64) -> Self {
        Self(us / 1000)
    }

    /// `ns` nanoseconds after the epoch, truncated to milliseconds.
    pub const fn from_nanos(ns: u64) -> Self {
        Self(ns / 1_000_000)
    }

    /// Milliseconds since the epoch.
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

impl Add<Duration> for Instant {
    type Output = Self;

    fn add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.as_millis() as u64))
    }
}

impl Sub for Instant {
    type Output = Duration;

    /// The time from `rhs` to `self`, or zero if `rhs` is later.
    fn sub(self, rhs: Self) -> Duration {
        Duration::from_millis(self.0.saturating_sub(rhs.0))
    }
}
