use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use osmium_sync::IrqSpinLock;

use crate::bus::BusDevice;

// Distributor registers.
const GICD_CTLR: u64 = 0x000;
const GICD_TYPER: u64 = 0x004;
const GICD_IIDR: u64 = 0x008;
const GICD_ISENABLER: u64 = 0x100;
const GICD_ICENABLER: u64 = 0x180;
const GICD_ISPENDR: u64 = 0x200;
const GICD_ICPENDR: u64 = 0x280;
const GICD_ISACTIVER: u64 = 0x300;
const GICD_ICACTIVER: u64 = 0x380;
const GICD_IPRIORITYR: u64 = 0x400;
const GICD_ITARGETSR: u64 = 0x800;
const GICD_ICFGR: u64 = 0xc00;

// CPU interface registers.
const GICC_CTLR: u64 = 0x00;
const GICC_PMR: u64 = 0x04;
const GICC_BPR: u64 = 0x08;
const GICC_IAR: u64 = 0x0c;
const GICC_EOIR: u64 = 0x10;
const GICC_RPR: u64 = 0x14;
const GICC_HPPIR: u64 = 0x18;
const GICC_IIDR: u64 = 0xfc;

/// No interrupt pending (`GICC_IAR`).
pub const SPURIOUS: u32 = 1023;

/// Size of each of the two register windows.
pub const GIC_WINDOW: u64 = 0x1000;

type Output = Box<dyn Fn(bool) + Send + Sync>;

/// An emulated GICv2 for one vCPU: a distributor and a CPU interface,
/// each a [`BusDevice`] (see [`distributor`](Self::distributor) and
/// [`cpu_interface`](Self::cpu_interface)), so guest drivers (Linux
/// `arm,cortex-a15-gic`, `osmium-drivers`' `GicV2`) work unchanged.
///
/// Devices drive interrupt lines with [`set_level`](Self::set_level).
/// Lines are level-sensitive; `GICD_ISPENDR` writes latch a pending state
/// until acknowledged. The CPU's IRQ output, reported through the callback,
/// is meant for [`Aarch64Vcpu::irq_line`](crate::aarch64::Aarch64Vcpu::irq_line).
pub struct VirtualGicV2 {
    state: IrqSpinLock<State>,
    output: Output,
}

struct State {
    dist_enable: bool,
    cpu_enable: bool,
    pmr: u8,
    bpr: u8,
    enabled: Vec<bool>,
    level: Vec<bool>,
    latched: Vec<bool>,
    active: Vec<bool>,
    priority: Vec<u8>,
    config: Vec<u8>,
    /// Priorities of acknowledged, not yet completed interrupts, innermost last.
    running: Vec<(u32, u8)>,
    asserted: bool,
}

impl State {
    fn pending(&self, i: usize) -> bool {
        (self.level[i] || self.latched[i]) && !self.active[i]
    }

    fn running_priority(&self) -> u8 {
        self.running.last().map_or(0xff, |&(_, p)| p)
    }

    /// Highest-priority (lowest value) pending, enabled interrupt that may
    /// preempt what is running; ties go to the lowest INTID.
    fn best(&self) -> Option<usize> {
        if !self.dist_enable || !self.cpu_enable {
            return None;
        }
        let mut best: Option<(u8, usize)> = None;
        for i in 0..self.enabled.len() {
            let p = self.priority[i];
            if self.enabled[i]
                && self.pending(i)
                && p < self.pmr
                && p < self.running_priority()
                && best.is_none_or(|(bp, _)| p < bp)
            {
                best = Some((p, i));
            }
        }
        best.map(|(_, i)| i)
    }

    /// Reads 32 one-bit flags starting at INTID `base`.
    fn bits(v: &[bool], base: usize) -> u32 {
        (0..32).filter(|b| v.get(base + b).copied().unwrap_or(false)).fold(0, |w, b| w | 1 << b)
    }

    fn set_bits(v: &mut [bool], base: usize, mask: u32, to: bool) {
        for b in 0..32 {
            if mask & (1 << b) != 0
                && let Some(x) = v.get_mut(base + b)
            {
                *x = to;
            }
        }
    }

    fn dist_read(&self, off: u64) -> u32 {
        let n = self.enabled.len();
        let word = |base: u64| ((off - base) / 4 * 32) as usize;
        let bytes = |base: u64, v: &[u8]| {
            let i = (off - base) as usize;
            (0..4).fold(0u32, |w, k| w | (v.get(i + k).copied().unwrap_or(0) as u32) << (8 * k))
        };
        match off {
            GICD_CTLR => self.dist_enable as u32,
            GICD_TYPER => (n / 32 - 1) as u32, // one CPU, no security extensions
            GICD_IIDR => 0x0200_043b,          // ARM, GICv2
            o if (GICD_ISENABLER..GICD_ICENABLER).contains(&o) => Self::bits(&self.enabled, word(GICD_ISENABLER)),
            o if (GICD_ICENABLER..GICD_ISPENDR).contains(&o) => Self::bits(&self.enabled, word(GICD_ICENABLER)),
            o if (GICD_ISPENDR..GICD_ISACTIVER).contains(&o) => {
                let base = word(if o < GICD_ICPENDR { GICD_ISPENDR } else { GICD_ICPENDR });
                (0..32).filter(|b| base + b < n && self.pending(base + b)).fold(0, |w, b| w | 1 << b)
            }
            o if (GICD_ISACTIVER..GICD_IPRIORITYR).contains(&o) => {
                Self::bits(&self.active, word(if o < GICD_ICACTIVER { GICD_ISACTIVER } else { GICD_ICACTIVER }))
            }
            o if (GICD_IPRIORITYR..GICD_ITARGETSR).contains(&o) => bytes(GICD_IPRIORITYR, &self.priority),
            // Every interrupt targets CPU 0.
            o if (GICD_ITARGETSR..GICD_ICFGR).contains(&o) => {
                let i = (o - GICD_ITARGETSR) as usize;
                (0..4).filter(|k| i + k < n).fold(0, |w, k| w | 1 << (8 * k))
            }
            o if (GICD_ICFGR..GICD_ICFGR + 0x100).contains(&o) => {
                let i = ((o - GICD_ICFGR) * 4) as usize;
                (0..16).fold(0, |w, k| w | (self.config.get(i + k).copied().unwrap_or(0) as u32 & 3) << (2 * k))
            }
            _ => 0,
        }
    }

    fn dist_write(&mut self, off: u64, v: u32) {
        let word = |base: u64| ((off - base) / 4 * 32) as usize;
        match off {
            GICD_CTLR => self.dist_enable = v & 1 != 0,
            o if (GICD_ISENABLER..GICD_ICENABLER).contains(&o) => {
                Self::set_bits(&mut self.enabled, word(GICD_ISENABLER), v, true)
            }
            o if (GICD_ICENABLER..GICD_ISPENDR).contains(&o) => {
                Self::set_bits(&mut self.enabled, word(GICD_ICENABLER), v, false)
            }
            o if (GICD_ISPENDR..GICD_ICPENDR).contains(&o) => Self::set_bits(&mut self.latched, word(GICD_ISPENDR), v, true),
            o if (GICD_ICPENDR..GICD_ISACTIVER).contains(&o) => {
                Self::set_bits(&mut self.latched, word(GICD_ICPENDR), v, false)
            }
            o if (GICD_ISACTIVER..GICD_ICACTIVER).contains(&o) => {
                Self::set_bits(&mut self.active, word(GICD_ISACTIVER), v, true)
            }
            o if (GICD_ICACTIVER..GICD_IPRIORITYR).contains(&o) => {
                Self::set_bits(&mut self.active, word(GICD_ICACTIVER), v, false)
            }
            o if (GICD_IPRIORITYR..GICD_ITARGETSR).contains(&o) => {
                let i = (o - GICD_IPRIORITYR) as usize;
                for k in 0..4 {
                    if let Some(p) = self.priority.get_mut(i + k) {
                        *p = (v >> (8 * k)) as u8;
                    }
                }
            }
            o if (GICD_ICFGR..GICD_ICFGR + 0x100).contains(&o) => {
                let i = ((o - GICD_ICFGR) * 4) as usize;
                // SGIs are always edge; PPIs here are fixed level.
                for k in 0..16 {
                    if i + k >= 32
                        && let Some(c) = self.config.get_mut(i + k)
                    {
                        *c = (v >> (2 * k)) as u8 & 3;
                    }
                }
            }
            _ => {}
        }
    }

    fn cpu_read(&mut self, off: u64) -> u32 {
        match off {
            GICC_CTLR => self.cpu_enable as u32,
            GICC_PMR => self.pmr as u32,
            GICC_BPR => self.bpr as u32,
            GICC_IAR => {
                let Some(i) = self.best() else { return SPURIOUS };
                self.active[i] = true;
                self.latched[i] = false;
                self.running.push((i as u32, self.priority[i]));
                i as u32
            }
            GICC_RPR => self.running_priority() as u32,
            GICC_HPPIR => self.best().map_or(SPURIOUS, |i| i as u32),
            GICC_IIDR => 0x0002_043b,
            _ => 0,
        }
    }

    fn cpu_write(&mut self, off: u64, v: u32) {
        match off {
            GICC_CTLR => self.cpu_enable = v & 1 != 0,
            GICC_PMR => self.pmr = v as u8,
            GICC_BPR => self.bpr = v as u8 & 7,
            GICC_EOIR => {
                let id = v & 0x3ff;
                if let Some(a) = self.active.get_mut(id as usize) {
                    *a = false;
                }
                if let Some(pos) = self.running.iter().rposition(|&(r, _)| r == id) {
                    self.running.remove(pos);
                }
            }
            _ => {}
        }
    }
}

impl VirtualGicV2 {
    /// A GIC with `lines` interrupt IDs (a multiple of 32, at least 64:
    /// SGIs 0-15, PPIs 16-31, SPIs from 32). `output` reports changes of
    /// the CPU's IRQ line.
    pub fn new(lines: usize, output: impl Fn(bool) + Send + Sync + 'static) -> Self {
        let lines = lines.max(64).next_multiple_of(32);
        let mut config = vec![0; lines];
        config[..16].fill(2); // SGIs: edge
        let state = State {
            dist_enable: false,
            cpu_enable: false,
            pmr: 0,
            bpr: 0,
            enabled: vec![false; lines],
            level: vec![false; lines],
            latched: vec![false; lines],
            active: vec![false; lines],
            priority: vec![0; lines],
            config,
            running: Vec::new(),
            asserted: false,
        };
        Self { state: IrqSpinLock::new(state), output: Box::new(output) }
    }

    /// Drives interrupt `intid`'s input line.
    pub fn set_level(&self, intid: u32, level: bool) {
        let mut s = self.state.lock();
        if let Some(l) = s.level.get_mut(intid as usize) {
            *l = level;
        }
        self.update(&mut s);
    }

    /// Whether the CPU's IRQ line is asserted.
    pub fn asserted(&self) -> bool {
        self.state.lock().asserted
    }

    fn update(&self, s: &mut State) {
        let now = s.best().is_some();
        if now != s.asserted {
            s.asserted = now;
            (self.output)(now);
        }
    }

    /// The distributor's register window, for the MMIO bus.
    pub fn distributor(self: &alloc::sync::Arc<Self>) -> alloc::sync::Arc<dyn BusDevice> {
        alloc::sync::Arc::new(Window { gic: self.clone(), cpu: false })
    }

    /// The CPU interface's register window, for the MMIO bus.
    pub fn cpu_interface(self: &alloc::sync::Arc<Self>) -> alloc::sync::Arc<dyn BusDevice> {
        alloc::sync::Arc::new(Window { gic: self.clone(), cpu: true })
    }
}

struct Window {
    gic: alloc::sync::Arc<VirtualGicV2>,
    cpu: bool,
}

impl BusDevice for Window {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let mut s = self.gic.state.lock();
        let v = if self.cpu { s.cpu_read(offset & !3) } else { s.dist_read(offset & !3) };
        self.gic.update(&mut s);
        let b = v.to_le_bytes();
        let at = (offset & 3) as usize;
        for (i, d) in data.iter_mut().enumerate() {
            *d = b.get(at + i).copied().unwrap_or(0);
        }
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let mut s = self.gic.state.lock();
        // Byte writes reach the byte-wide priority and target registers.
        if !self.cpu && data.len() == 1 && (GICD_IPRIORITYR..GICD_ICFGR).contains(&offset) {
            if let Some(p) = s.priority.get_mut((offset - GICD_IPRIORITYR) as usize).filter(|_| offset < GICD_ITARGETSR) {
                *p = data[0];
            }
        } else if data.len() == 4 && offset & 3 == 0 {
            let v = u32::from_le_bytes(data.try_into().unwrap());
            if self.cpu { s.cpu_write(offset, v) } else { s.dist_write(offset, v) }
        }
        self.gic.update(&mut s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    fn rd(w: &Arc<dyn BusDevice>, off: u64) -> u32 {
        let mut b = [0u8; 4];
        w.read(off, &mut b);
        u32::from_le_bytes(b)
    }

    fn wr(w: &Arc<dyn BusDevice>, off: u64, v: u32) {
        w.write(off, &v.to_le_bytes());
    }

    #[test]
    fn ack_eoi_priority_and_masking() {
        let line = Arc::new(AtomicBool::new(false));
        let l = line.clone();
        let gic = Arc::new(VirtualGicV2::new(64, move |v| l.store(v, Ordering::SeqCst)));
        let (d, c) = (gic.distributor(), gic.cpu_interface());
        assert_eq!(rd(&d, GICD_TYPER) & 0x1f, 1, "64 lines");

        // The timer PPI fires before anything is enabled: no output.
        gic.set_level(27, true);
        assert!(!line.load(Ordering::SeqCst));
        wr(&d, GICD_CTLR, 1);
        wr(&c, GICC_CTLR, 1);
        wr(&c, GICC_PMR, 0xf0);
        wr(&d, GICD_ISENABLER, 1 << 27);
        assert!(line.load(Ordering::SeqCst));
        assert_eq!(rd(&d, GICD_ISPENDR) & (1 << 27), 1 << 27);

        // A higher-priority SPI preempts; byte writes set priorities.
        d.write(GICD_IPRIORITYR + 27, &[0xa0]);
        d.write(GICD_IPRIORITYR + 33, &[0x40]);
        wr(&d, GICD_ISENABLER + 4, 1 << 1);
        gic.set_level(33, true);
        assert_eq!(rd(&c, GICC_HPPIR), 33);
        assert_eq!(rd(&c, GICC_IAR), 33);
        assert_eq!(rd(&c, GICC_RPR), 0x40);
        assert_eq!(rd(&c, GICC_IAR), SPURIOUS, "27 cannot preempt a 0x40 handler");
        assert!(!line.load(Ordering::SeqCst));
        gic.set_level(33, false);
        wr(&c, GICC_EOIR, 33);
        assert!(line.load(Ordering::SeqCst), "27 is still pending");
        assert_eq!(rd(&c, GICC_IAR), 27);
        assert!(!line.load(Ordering::SeqCst), "active, not re-signaled");
        gic.set_level(27, false);
        wr(&c, GICC_EOIR, 27);
        assert!(!line.load(Ordering::SeqCst));

        // A software-pended SGI, masked by PMR until it is lowered.
        d.write(GICD_IPRIORITYR + 3, &[0xf8]);
        wr(&d, GICD_ISENABLER, 1 << 3);
        wr(&d, GICD_ISPENDR, 1 << 3);
        assert!(!line.load(Ordering::SeqCst));
        wr(&c, GICC_PMR, 0xff);
        assert_eq!(rd(&c, GICC_IAR), 3);
        wr(&c, GICC_EOIR, 3);
        assert_eq!(rd(&c, GICC_IAR), SPURIOUS, "an acknowledged SGI stays cleared");
    }
}
