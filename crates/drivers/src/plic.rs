//! RISC-V Platform-Level Interrupt Controller.

use osmium_hal::irq::InterruptController;
use osmium_hal::mmio::IoMem;

const PRIORITY: usize = 0x0;
const ENABLE: usize = 0x2000;
const ENABLE_STRIDE: usize = 0x80;
const CONTEXT: usize = 0x20_0000;
const CONTEXT_STRIDE: usize = 0x1000;
const THRESHOLD: usize = 0x0;
const CLAIM: usize = 0x4;
/// Source ids are 1–1023; 0 means "no interrupt".
const MAX_SOURCES: u32 = 1023;

/// A PLIC.
///
/// Each hart has one or more *contexts* (privilege modes). `context_of`
/// maps the current CPU id (from `osmium_arch::cpu::current_id`) to the
/// context this driver programs. [`Plic::supervisor_context`] gives the
/// layout used by QEMU `virt` and most SiFive parts.
///
/// Per-source operations ignore source 0 and sources above the count (by
/// default the architectural maximum, 1023; narrow it with
/// [`Plic::with_num_sources`]). Larger numbers would otherwise land in the
/// pending bits or in another context's enables.
pub struct Plic {
    io: IoMem,
    context_of: fn(usize) -> usize,
    num_sources: u32,
}

impl Plic {
    /// Context of hart `hart`'s S-mode when every hart has an M and an S context.
    pub fn supervisor_context(hart: usize) -> usize {
        2 * hart + 1
    }

    /// Context of hart `hart`'s M-mode in the same layout.
    pub fn machine_context(hart: usize) -> usize {
        2 * hart
    }

    /// Wraps the PLIC register window.
    pub fn new(io: IoMem, context_of: fn(usize) -> usize) -> Self {
        Self { io, context_of, num_sources: MAX_SOURCES }
    }

    /// Limits the driver to sources `1..=n` (the device tree's
    /// `riscv,ndev`). `n` is capped at 1023.
    pub fn with_num_sources(mut self, n: u32) -> Self {
        self.num_sources = n.min(MAX_SOURCES);
        self
    }

    fn valid(&self, irq: u32) -> bool {
        (1..=self.num_sources).contains(&irq)
    }

    fn context(&self) -> usize {
        CONTEXT + (self.context_of)(osmium_arch::cpu::current_id()) * CONTEXT_STRIDE
    }

    fn enable_word(&self, irq: u32) -> usize {
        ENABLE + (self.context_of)(osmium_arch::cpu::current_id()) * ENABLE_STRIDE + (irq as usize / 32) * 4
    }

    /// Accepts all priorities above `threshold` on the current CPU's context.
    pub fn set_threshold(&self, threshold: u32) {
        self.io.write(self.context() + THRESHOLD, threshold).expect("PLIC window too small");
    }
}

impl InterruptController for Plic {
    /// Enables `irq` for the current CPU's context. A source with priority 0
    /// never fires, so this also raises its priority to 1 if it is 0. Does
    /// nothing for a source the PLIC lacks, or if the window is too small.
    fn enable(&self, irq: u32) {
        if !self.valid(irq) {
            return;
        }
        let prio = PRIORITY + irq as usize * 4;
        if self.io.read::<u32>(prio) == Ok(0) {
            let _ = self.io.write(prio, 1u32);
        }
        let w = self.enable_word(irq);
        if let Ok(v) = self.io.read::<u32>(w) {
            let _ = self.io.write(w, v | 1 << (irq % 32));
        }
    }

    /// Does nothing for a source the PLIC lacks, or if the window is too
    /// small.
    fn disable(&self, irq: u32) {
        if !self.valid(irq) {
            return;
        }
        let w = self.enable_word(irq);
        if let Ok(v) = self.io.read::<u32>(w) {
            let _ = self.io.write(w, v & !(1 << (irq % 32)));
        }
    }

    fn claim(&self) -> Option<u32> {
        let irq: u32 = self.io.read(self.context() + CLAIM).ok()?;
        (irq != 0).then_some(irq)
    }

    /// Ignores ids [`InterruptController::claim`] never returns.
    fn complete(&self, irq: u32) {
        if self.valid(irq) {
            let _ = self.io.write(self.context() + CLAIM, irq);
        }
    }

    /// Does nothing for a source the PLIC lacks.
    fn set_priority(&self, irq: u32, priority: u8) {
        if !self.valid(irq) {
            return;
        }
        let _ = self.io.write(PRIORITY + irq as usize * 4, priority as u32);
    }
}

#[cfg(test)]
// Tests drop drivers explicitly to end their use of the fake register memory
// before inspecting it.
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn register_offsets() {
        let mut mem = vec![0u32; 0x40_0000 / 4];
        // SAFETY: the window covers a local buffer.
        let io = unsafe { IoMem::new(mem.as_mut_ptr().cast(), 0x40_0000) };
        let plic = Plic::new(io, Plic::supervisor_context);
        plic.enable(10);
        plic.enable(33);
        plic.set_threshold(0);
        plic.disable(33);
        plic.set_priority(7, 3);
        drop(plic);
        // Hart 0 S-mode is context 1.
        assert_eq!(mem[(0x2080) / 4], 1 << 10);
        assert_eq!(mem[(0x2084) / 4], 0);
        assert_eq!(mem[10], 1, "priority raised from 0");
        assert_eq!(mem[7], 3);

        mem[(0x20_1004) / 4] = 10; // pending claim on context 1
        // SAFETY: as above.
        let plic = Plic::new(unsafe { IoMem::new(mem.as_mut_ptr().cast(), 0x40_0000) }, Plic::supervisor_context);
        assert_eq!(plic.claim(), Some(10));
        plic.complete(10);
    }

    #[test]
    fn out_of_range_sources_are_ignored() {
        let mut mem = vec![0u32; 0x40_0000 / 4];
        // SAFETY: the window covers a local buffer.
        let io = unsafe { IoMem::new(mem.as_mut_ptr().cast(), 0x40_0000) };
        let plic = Plic::new(io, Plic::supervisor_context).with_num_sources(53);
        // 1024 + 10 would set a bit in context 2's enables and a pending bit.
        plic.enable(1024 + 10);
        plic.enable(54);
        plic.enable(0);
        plic.disable(u32::MAX);
        plic.set_priority(2000, 7);
        plic.complete(0);
        plic.enable(53);
        drop(plic);
        assert_eq!(mem.iter().filter(|&&v| v != 0).count(), 2, "only source 53's priority and enable bit");
        assert_eq!(mem[53], 1);
        assert_eq!(mem[0x2080 / 4 + 1], 1 << 21);

        // A window too small for the enables is not a panic.
        // SAFETY: as above.
        let small = Plic::new(unsafe { IoMem::new(mem.as_mut_ptr().cast(), 0x1000) }, Plic::supervisor_context);
        small.enable(5);
        small.disable(5);
    }
}
