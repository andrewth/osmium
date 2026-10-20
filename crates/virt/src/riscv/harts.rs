//! The harts of a multi-vCPU RISC-V guest: SBI HSM state and IPIs.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use osmium_sync::IrqSpinLock;

/// SBI HSM hart states.
pub mod status {
    /// Running.
    pub const STARTED: u64 = 0;
    /// Not running; can be started.
    pub const STOPPED: u64 = 1;
    /// A start was requested and the hart has not run yet.
    pub const START_PENDING: u64 = 2;
}

struct Slot {
    state: AtomicU64,
    start: IrqSpinLock<Option<(u64, u64)>>,
    ipi: Arc<AtomicBool>,
}

/// Shared state for a guest's harts. Each vCPU's host task takes start
/// requests with [`take_start`](Self::take_start), connects its IPI line
/// with [`RiscvVcpu::connect_ipi`](super::RiscvVcpu::connect_ipi), and passes
/// this to [`sbi::handle_smp`](super::sbi::handle_smp), which implements
/// HSM and IPI on top of it.
pub struct GuestHarts {
    slots: Vec<Slot>,
}

impl GuestHarts {
    /// `n` harts, all stopped.
    pub fn new(n: usize) -> Arc<Self> {
        let slots = (0..n)
            .map(|_| Slot {
                state: AtomicU64::new(status::STOPPED),
                start: IrqSpinLock::new(None),
                ipi: Arc::new(AtomicBool::new(false)),
            })
            .collect();
        Arc::new(Self { slots })
    }

    /// Number of harts.
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether there are no harts.
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Asks a stopped hart to start at `entry` with `a1` = `opaque` (SBI
    /// `hart_start`). Returns the SBI error: `INVALID_PARAM` for a bad hart,
    /// `ALREADY_AVAILABLE` if it is not stopped.
    pub fn request_start(&self, hart: usize, entry: u64, opaque: u64) -> Result<(), i64> {
        let slot = self.slots.get(hart).ok_or(super::sbi::ERR_INVALID_PARAM)?;
        slot.state
            .compare_exchange(status::STOPPED, status::START_PENDING, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| super::sbi::ERR_ALREADY_AVAILABLE)?;
        *slot.start.lock() = Some((entry, opaque));
        Ok(())
    }

    /// Takes hart `hart`'s pending start request (entry, opaque), marking it
    /// started; `None` if there is none.
    pub fn take_start(&self, hart: usize) -> Option<(u64, u64)> {
        let slot = self.slots.get(hart)?;
        let req = slot.start.lock().take()?;
        slot.state.store(status::STARTED, Ordering::Release);
        Some(req)
    }

    /// Marks `hart` stopped (after SBI `hart_stop`).
    pub fn stopped(&self, hart: usize) {
        if let Some(s) = self.slots.get(hart) {
            s.state.store(status::STOPPED, Ordering::Release);
        }
    }

    /// The HSM status of `hart`.
    pub fn status(&self, hart: usize) -> Option<u64> {
        self.slots.get(hart).map(|s| s.state.load(Ordering::Acquire))
    }

    /// `hart`'s software-interrupt line, for its vCPU.
    pub fn ipi_line(&self, hart: usize) -> Arc<AtomicBool> {
        self.slots[hart].ipi.clone()
    }

    /// Raises the software interrupt of every hart in `mask` (bit `i` =
    /// hart `base + i`; `base` = `u64::MAX` means all harts).
    pub fn send_ipi(&self, mask: u64, base: u64) -> Result<(), i64> {
        for (i, s) in self.slots.iter().enumerate() {
            let hit = if base == u64::MAX {
                true
            } else {
                (i as u64).checked_sub(base).is_some_and(|b| b < 64 && mask & (1 << b) != 0)
            };
            if hit {
                s.ipi.store(true, Ordering::Release);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_stop_ipi() {
        let h = GuestHarts::new(3);
        assert_eq!(h.status(1), Some(status::STOPPED));
        assert_eq!(h.take_start(1), None);
        h.request_start(1, 0x8000_0000, 7).unwrap();
        assert_eq!(h.status(1), Some(status::START_PENDING));
        assert_eq!(h.request_start(1, 0, 0), Err(super::super::sbi::ERR_ALREADY_AVAILABLE));
        assert_eq!(h.take_start(1), Some((0x8000_0000, 7)));
        assert_eq!(h.status(1), Some(status::STARTED));
        h.stopped(1);
        assert_eq!(h.status(1), Some(status::STOPPED));
        assert_eq!(h.request_start(5, 0, 0), Err(super::super::sbi::ERR_INVALID_PARAM));

        h.send_ipi(0b10, 1).unwrap();
        assert!(!h.ipi_line(0).load(Ordering::SeqCst));
        assert!(!h.ipi_line(1).load(Ordering::SeqCst));
        assert!(h.ipi_line(2).load(Ordering::SeqCst));
        h.send_ipi(0, u64::MAX).unwrap();
        assert!(h.ipi_line(0).load(Ordering::SeqCst));
    }
}
