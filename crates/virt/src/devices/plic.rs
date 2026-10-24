use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use osmium_sync::IrqSpinLock;

use crate::bus::BusDevice;

const PRIORITY: u64 = 0x0;
const PENDING: u64 = 0x1000;
const ENABLE: u64 = 0x2000;
const ENABLE_STRIDE: u64 = 0x80;
const CONTEXT: u64 = 0x20_0000;
const CONTEXT_STRIDE: u64 = 0x1000;

type Output = Box<dyn Fn(usize, bool) + Send + Sync>;

/// An emulated RISC-V PLIC with the register layout of QEMU `virt` and
/// SiFive parts, so guest drivers (Linux `sifive,plic-1.0.0`, `osmium-drivers`)
/// work unchanged.
///
/// Sources are level-triggered: devices drive them with
/// [`set_level`](Self::set_level). Each context's interrupt output is
/// reported through a callback whenever it changes; wire the S-mode
/// contexts to the vCPUs' external-interrupt lines.
pub struct VirtualPlic {
    state: IrqSpinLock<State>,
    output: Output,
}

struct State {
    priority: Vec<u32>,
    level: Vec<bool>,
    pending: Vec<bool>,
    in_service: Vec<bool>,
    enable: Vec<Vec<u32>>,
    threshold: Vec<u32>,
    asserted: Vec<bool>,
}

impl VirtualPlic {
    /// A PLIC with sources 1..`sources` (source 0 does not exist) and
    /// `contexts` contexts. `output(context, level)` reports changes of each
    /// context's interrupt line.
    pub fn new(sources: usize, contexts: usize, output: impl Fn(usize, bool) + Send + Sync + 'static) -> Self {
        let words = sources.div_ceil(32);
        let state = State {
            priority: vec![0; sources],
            level: vec![false; sources],
            pending: vec![false; sources],
            in_service: vec![false; sources],
            enable: vec![vec![0; words]; contexts],
            threshold: vec![0; contexts],
            asserted: vec![false; contexts],
        };
        Self { state: IrqSpinLock::new(state), output: Box::new(output) }
    }

    /// Size of the register window for `contexts` contexts.
    pub const fn mmio_size(contexts: usize) -> u64 {
        CONTEXT.saturating_add(CONTEXT_STRIDE.saturating_mul(contexts as u64))
    }

    /// Drives source `irq`'s input line.
    pub fn set_level(&self, irq: u32, level: bool) {
        let mut s = self.state.lock();
        let i = irq as usize;
        if i == 0 || i >= s.level.len() {
            return;
        }
        let Some(l) = s.level.get_mut(i) else { return };
        *l = level;
        if level
            && !s.in_service.get(i).copied().unwrap_or(true)
            && let Some(p) = s.pending.get_mut(i)
        {
            *p = true;
        }
        self.update(&mut s);
    }

    /// Whether context `ctx`'s interrupt line is asserted.
    pub fn asserted(&self, ctx: usize) -> bool {
        self.state.lock().asserted.get(ctx).copied().unwrap_or(false)
    }

    /// Re-evaluates every context's output and reports changes.
    fn update(&self, s: &mut State) {
        for ctx in 0..s.asserted.len() {
            let now = s.best(ctx).is_some();
            if let Some(a) = s.asserted.get_mut(ctx)
                && now != *a
            {
                *a = now;
                (self.output)(ctx, now);
            }
        }
    }
}

impl State {
    /// Highest-priority pending, enabled source above `ctx`'s threshold;
    /// ties go to the lowest source number.
    fn best(&self, ctx: usize) -> Option<usize> {
        let mut best: Option<(u32, usize)> = None;
        let enable = self.enable.get(ctx)?;
        let threshold = self.threshold.get(ctx).copied()?;
        for (i, &pending) in self.pending.iter().enumerate().skip(1) {
            let enabled = enable.get(i / 32).is_some_and(|w| w & (1 << (i % 32)) != 0);
            let p = self.priority.get(i).copied().unwrap_or(0);
            if pending && enabled && p > threshold && best.is_none_or(|(bp, _)| p > bp) {
                best = Some((p, i));
            }
        }
        best.map(|(_, i)| i)
    }

    fn read(&mut self, off: u64) -> u32 {
        let contexts = self.threshold.len() as u64;
        match off {
            o if o < PENDING => self.priority.get(((o - PRIORITY) / 4) as usize).copied().unwrap_or(0),
            o if o < ENABLE => {
                let base = ((o - PENDING) / 4 * 32) as usize;
                (0..32).filter(|b| self.pending.get(base + b).copied().unwrap_or(false)).fold(0, |w, b| w | 1 << b)
            }
            o if o < CONTEXT => {
                let (ctx, word) =
                    (((o - ENABLE) / ENABLE_STRIDE) as usize, ((o - ENABLE) % ENABLE_STRIDE / 4) as usize);
                self.enable.get(ctx).and_then(|e| e.get(word)).copied().unwrap_or(0)
            }
            o if (o - CONTEXT) / CONTEXT_STRIDE < contexts => {
                let ctx = ((o - CONTEXT) / CONTEXT_STRIDE) as usize;
                match (o - CONTEXT) % CONTEXT_STRIDE {
                    0 => self.threshold.get(ctx).copied().unwrap_or(0),
                    4 => {
                        // Claim: the source stops being pending until completed.
                        let Some(i) = self.best(ctx) else { return 0 };
                        if let Some(p) = self.pending.get_mut(i) {
                            *p = false;
                        }
                        if let Some(s) = self.in_service.get_mut(i) {
                            *s = true;
                        }
                        i as u32
                    }
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    fn write(&mut self, off: u64, v: u32) {
        let contexts = self.threshold.len() as u64;
        match off {
            o if o < PENDING => {
                if let Some(p) = self.priority.get_mut(((o - PRIORITY) / 4) as usize).filter(|_| o >= 4) {
                    *p = v & 7;
                }
            }
            o if o < ENABLE => {}
            o if o < CONTEXT => {
                let (ctx, word) =
                    (((o - ENABLE) / ENABLE_STRIDE) as usize, ((o - ENABLE) % ENABLE_STRIDE / 4) as usize);
                if let Some(w) = self.enable.get_mut(ctx).and_then(|e| e.get_mut(word)) {
                    // Source 0 does not exist.
                    *w = if word == 0 { v & !1 } else { v };
                }
            }
            o if (o - CONTEXT) / CONTEXT_STRIDE < contexts => {
                let ctx = ((o - CONTEXT) / CONTEXT_STRIDE) as usize;
                match (o - CONTEXT) % CONTEXT_STRIDE {
                    0 => {
                        if let Some(t) = self.threshold.get_mut(ctx) {
                            *t = v & 7;
                        }
                    }
                    4 => {
                        // Complete: a level still high pends the source again.
                        let i = v as usize;
                        if i > 0
                            && let Some(s) = self.in_service.get_mut(i)
                            && *s
                        {
                            *s = false;
                            if self.level.get(i).copied().unwrap_or(false)
                                && let Some(p) = self.pending.get_mut(i)
                            {
                                *p = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

impl BusDevice for VirtualPlic {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let mut s = self.state.lock();
        let v = s.read(offset & !3);
        // A claim changes what is pending.
        self.update(&mut s);
        let b = v.to_le_bytes();
        let at = (offset & 3) as usize;
        for (i, d) in data.iter_mut().enumerate() {
            *d = b.get(at + i).copied().unwrap_or(0);
        }
    }

    fn write(&self, offset: u64, data: &[u8]) {
        if offset & 3 != 0 || data.len() != 4 {
            return;
        }
        let mut s = self.state.lock();
        let &[a, b, c, d] = data else { return };
        s.write(offset, u32::from_le_bytes([a, b, c, d]));
        self.update(&mut s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    fn rd(p: &VirtualPlic, off: u64) -> u32 {
        let mut b = [0u8; 4];
        p.read(off, &mut b);
        u32::from_le_bytes(b)
    }

    fn wr(p: &VirtualPlic, off: u64, v: u32) {
        p.write(off, &v.to_le_bytes());
    }

    #[test]
    fn claim_complete_priority_threshold() {
        let line = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);
        let l = line.clone();
        let plic = VirtualPlic::new(64, 2, move |ctx, level| l[ctx].store(level, Ordering::SeqCst));
        let s_ctx = 1;
        let claim = CONTEXT + CONTEXT_STRIDE * s_ctx + 4;

        // Pending but neither enabled nor prioritized: no output.
        plic.set_level(10, true);
        assert_eq!(rd(&plic, PENDING), 1 << 10);
        assert!(!line[1].load(Ordering::SeqCst));
        wr(&plic, PRIORITY + 4 * 10, 1);
        wr(&plic, ENABLE + ENABLE_STRIDE * s_ctx, 1 << 10 | 1 << 3);
        assert!(line[1].load(Ordering::SeqCst));
        assert!(!line[0].load(Ordering::SeqCst), "M context not enabled");

        // A higher-priority source wins the claim.
        wr(&plic, PRIORITY + 4 * 3, 5);
        plic.set_level(3, true);
        plic.set_level(3, false);
        assert_eq!(rd(&plic, claim), 3);
        assert_eq!(rd(&plic, claim), 10);
        assert_eq!(rd(&plic, claim), 0);
        assert!(!line[1].load(Ordering::SeqCst), "everything claimed");

        // Completing a level-high source pends it again; low does not.
        wr(&plic, claim, 3);
        assert!(!line[1].load(Ordering::SeqCst));
        wr(&plic, claim, 10);
        assert!(line[1].load(Ordering::SeqCst));
        plic.set_level(10, false);

        // Threshold masks priorities at or below it.
        wr(&plic, CONTEXT + CONTEXT_STRIDE * s_ctx, 1);
        assert!(!line[1].load(Ordering::SeqCst));
        wr(&plic, CONTEXT + CONTEXT_STRIDE * s_ctx, 0);
        assert_eq!(rd(&plic, claim), 10);
        wr(&plic, claim, 10);
        assert!(!line[1].load(Ordering::SeqCst));
    }
}
