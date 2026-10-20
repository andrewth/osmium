//! Clocks and timers.

/// A monotonic clock.
pub trait Clock: Sync {
    /// Nanoseconds since an arbitrary, fixed origin.
    fn now_ns(&self) -> u64;
}

/// A per-CPU one-shot timer that raises an interrupt at a deadline.
pub trait OneShotTimer: Sync {
    /// Arms the timer for absolute time `deadline_ns` on the [`Clock`]'s scale.
    fn set_deadline(&self, deadline_ns: u64);
    /// Disarms the timer.
    fn cancel(&self);
}

/// Converts between a counter running at `hz` and nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickRate {
    hz: u64,
}

impl TickRate {
    /// A counter running at `hz` ticks per second.
    pub const fn new(hz: u64) -> Self {
        assert!(hz > 0);
        Self { hz }
    }

    /// Ticks to nanoseconds, without intermediate overflow; saturates.
    pub const fn ticks_to_ns(self, ticks: u64) -> u64 {
        saturate((ticks as u128 * 1_000_000_000) / self.hz as u128)
    }

    /// Nanoseconds to ticks, without intermediate overflow; saturates.
    pub const fn ns_to_ticks(self, ns: u64) -> u64 {
        saturate((ns as u128 * self.hz as u128) / 1_000_000_000)
    }
}

const fn saturate(v: u128) -> u64 {
    if v > u64::MAX as u128 { u64::MAX } else { v as u64 }
}

#[cfg(test)]
mod tests {
    use super::TickRate;

    #[test]
    fn conversions() {
        let r = TickRate::new(10_000_000); // QEMU virt `time` CSR
        assert_eq!(r.ticks_to_ns(10_000_000), 1_000_000_000);
        assert_eq!(r.ns_to_ticks(1_000), 10);
        assert_eq!(r.ticks_to_ns(u64::MAX), u64::MAX);
        assert_eq!(TickRate::new(1 << 40).ticks_to_ns(1 << 40), 1_000_000_000);
    }
}
