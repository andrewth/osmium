use alloc::boxed::Box;
use alloc::sync::Arc;
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
const GICD_SGIR: u64 = 0xf00;

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

/// Interrupts banked per CPU: SGIs 0-15 and PPIs 16-31.
const PRIVATE: usize = 32;

type Output = Box<dyn Fn(usize, bool) + Send + Sync>;

/// One interrupt's state.
#[derive(Clone, Copy, Default)]
struct Irq {
    enabled: bool,
    level: bool,
    latched: bool,
    active: bool,
    priority: u8,
    /// For SGIs: the CPU that sent the pending one.
    source: u8,
}

impl Irq {
    fn pending(&self) -> bool {
        (self.level || self.latched) && !self.active
    }
}

/// A CPU's banked interrupts and its CPU interface.
struct Cpu {
    private: [Irq; PRIVATE],
    enable: bool,
    pmr: u8,
    bpr: u8,
    /// Acknowledged, not yet completed interrupts (id, priority), innermost last.
    running: Vec<(u32, u8)>,
    asserted: bool,
}

struct State {
    dist_enable: bool,
    cpus: Vec<Cpu>,
    /// SPIs (32 and up).
    spis: Vec<Irq>,
    targets: Vec<u8>,
    config: Vec<u8>,
}

impl State {
    fn irq(&self, cpu: usize, i: usize) -> Option<&Irq> {
        if i < PRIVATE { self.cpus[cpu].private.get(i) } else { self.spis.get(i - PRIVATE) }
    }

    fn irq_mut(&mut self, cpu: usize, i: usize) -> Option<&mut Irq> {
        if i < PRIVATE { self.cpus[cpu].private.get_mut(i) } else { self.spis.get_mut(i - PRIVATE) }
    }

    fn lines(&self) -> usize {
        PRIVATE + self.spis.len()
    }

    fn running_priority(&self, cpu: usize) -> u8 {
        self.cpus[cpu].running.last().map_or(0xff, |&(_, p)| p)
    }

    /// The highest-priority (lowest value) interrupt `cpu` may take now;
    /// ties go to the lowest INTID.
    fn best(&self, cpu: usize) -> Option<usize> {
        let c = &self.cpus[cpu];
        if !self.dist_enable || !c.enable {
            return None;
        }
        let rp = self.running_priority(cpu);
        let mut best: Option<(u8, usize)> = None;
        for i in 0..self.lines() {
            let irq = self.irq(cpu, i).unwrap();
            // A uniprocessor GIC routes every SPI to its one CPU.
            let targeted = i < PRIVATE || self.cpus.len() == 1 || self.targets[i - PRIVATE] & (1 << cpu) != 0;
            let p = irq.priority;
            if targeted && irq.enabled && irq.pending() && p < c.pmr && p < rp && best.is_none_or(|(bp, _)| p < bp) {
                best = Some((p, i));
            }
        }
        best.map(|(_, i)| i)
    }

    /// 32 one-bit flags of `f` starting at INTID `base`, as `cpu` sees them.
    fn bits(&self, cpu: usize, base: usize, f: impl Fn(&Irq) -> bool) -> u32 {
        (0..32).filter(|b| self.irq(cpu, base + b).is_some_and(&f)).fold(0, |w, b| w | 1 << b)
    }

    fn set_bits(&mut self, cpu: usize, base: usize, mask: u32, f: impl Fn(&mut Irq)) {
        for b in 0..32 {
            if mask & (1 << b) != 0
                && let Some(irq) = self.irq_mut(cpu, base + b)
            {
                f(irq);
            }
        }
    }

    fn dist_read(&self, cpu: usize, off: u64) -> u32 {
        let word = |base: u64| ((off - base) / 4 * 32) as usize;
        let byte_at = |base: u64| (off - base) as usize;
        match off {
            GICD_CTLR => self.dist_enable as u32,
            // ITLinesNumber, CPUNumber - 1; no security extensions.
            GICD_TYPER => (self.lines() / 32 - 1) as u32 | ((self.cpus.len() as u32 - 1) & 7) << 5,
            GICD_IIDR => 0x0200_043b,
            o if (GICD_ISENABLER..GICD_ISPENDR).contains(&o) => {
                let base = if o < GICD_ICENABLER { GICD_ISENABLER } else { GICD_ICENABLER };
                self.bits(cpu, word(base), |i| i.enabled)
            }
            o if (GICD_ISPENDR..GICD_ISACTIVER).contains(&o) => {
                let base = if o < GICD_ICPENDR { GICD_ISPENDR } else { GICD_ICPENDR };
                self.bits(cpu, word(base), Irq::pending)
            }
            o if (GICD_ISACTIVER..GICD_IPRIORITYR).contains(&o) => {
                let base = if o < GICD_ICACTIVER { GICD_ISACTIVER } else { GICD_ICACTIVER };
                self.bits(cpu, word(base), |i| i.active)
            }
            o if (GICD_IPRIORITYR..GICD_ITARGETSR).contains(&o) => {
                let i = byte_at(GICD_IPRIORITYR);
                (0..4).fold(0, |w, k| w | (self.irq(cpu, i + k).map_or(0, |q| q.priority) as u32) << (8 * k))
            }
            o if (GICD_ITARGETSR..GICD_ICFGR).contains(&o) => {
                let i = byte_at(GICD_ITARGETSR);
                (0..4).fold(0, |w, k| {
                    let t = match i + k {
                        n if n < PRIVATE => 1 << cpu, // reads as the reading CPU
                        _ if self.cpus.len() == 1 => 0, // RAZ/WI on a uniprocessor
                        n => self.targets.get(n - PRIVATE).copied().unwrap_or(0),
                    };
                    w | (t as u32) << (8 * k)
                })
            }
            o if (GICD_ICFGR..GICD_ICFGR + 0x100).contains(&o) => {
                let i = ((o - GICD_ICFGR) * 4) as usize;
                (0..16).fold(0, |w, k| w | (self.config.get(i + k).copied().unwrap_or(0) as u32 & 3) << (2 * k))
            }
            _ => 0,
        }
    }

    fn dist_write(&mut self, cpu: usize, off: u64, v: u32) {
        let word = |base: u64| ((off - base) / 4 * 32) as usize;
        match off {
            GICD_CTLR => self.dist_enable = v & 1 != 0,
            o if (GICD_ISENABLER..GICD_ICENABLER).contains(&o) => {
                self.set_bits(cpu, word(GICD_ISENABLER), v, |i| i.enabled = true)
            }
            o if (GICD_ICENABLER..GICD_ISPENDR).contains(&o) => {
                self.set_bits(cpu, word(GICD_ICENABLER), v, |i| i.enabled = false)
            }
            o if (GICD_ISPENDR..GICD_ICPENDR).contains(&o) => {
                self.set_bits(cpu, word(GICD_ISPENDR), v, |i| i.latched = true)
            }
            o if (GICD_ICPENDR..GICD_ISACTIVER).contains(&o) => {
                self.set_bits(cpu, word(GICD_ICPENDR), v, |i| i.latched = false)
            }
            o if (GICD_ISACTIVER..GICD_ICACTIVER).contains(&o) => {
                self.set_bits(cpu, word(GICD_ISACTIVER), v, |i| i.active = true)
            }
            o if (GICD_ICACTIVER..GICD_IPRIORITYR).contains(&o) => {
                self.set_bits(cpu, word(GICD_ICACTIVER), v, |i| i.active = false)
            }
            o if (GICD_IPRIORITYR..GICD_ICFGR).contains(&o) => {
                for k in 0..4 {
                    self.write_byte(cpu, o + k, (v >> (8 * k)) as u8);
                }
            }
            o if (GICD_ICFGR..GICD_ICFGR + 0x100).contains(&o) => {
                let i = ((o - GICD_ICFGR) * 4) as usize;
                // SGIs are always edge; PPIs here are fixed level.
                for k in 0..16 {
                    if i + k >= PRIVATE
                        && let Some(c) = self.config.get_mut(i + k)
                    {
                        *c = (v >> (2 * k)) as u8 & 3;
                    }
                }
            }
            GICD_SGIR => {
                let sgi = (v & 0xf) as usize;
                let targets: u32 = match (v >> 24) & 3 {
                    0 => (v >> 16) & 0xff,
                    1 => !(1 << cpu),
                    2 => 1 << cpu,
                    _ => 0,
                };
                for (t, c) in self.cpus.iter_mut().enumerate() {
                    if targets & (1 << t) != 0 {
                        c.private[sgi].latched = true;
                        c.private[sgi].source = cpu as u8;
                    }
                }
            }
            _ => {}
        }
    }

    /// A byte write to the priority or target registers.
    fn write_byte(&mut self, cpu: usize, off: u64, b: u8) {
        if (GICD_IPRIORITYR..GICD_ITARGETSR).contains(&off) {
            if let Some(i) = self.irq_mut(cpu, (off - GICD_IPRIORITYR) as usize) {
                i.priority = b;
            }
        } else if (GICD_ITARGETSR..GICD_ICFGR).contains(&off) {
            let n = (off - GICD_ITARGETSR) as usize;
            if n >= PRIVATE
                && let Some(t) = self.targets.get_mut(n - PRIVATE)
            {
                *t = b;
            }
        }
    }

    fn cpu_read(&mut self, cpu: usize, off: u64) -> u32 {
        match off {
            GICC_CTLR => self.cpus[cpu].enable as u32,
            GICC_PMR => self.cpus[cpu].pmr as u32,
            GICC_BPR => self.cpus[cpu].bpr as u32,
            GICC_IAR => {
                let Some(i) = self.best(cpu) else { return SPURIOUS };
                let irq = self.irq_mut(cpu, i).unwrap();
                irq.active = true;
                irq.latched = false;
                let (prio, source) = (irq.priority, irq.source);
                self.cpus[cpu].running.push((i as u32, prio));
                // SGIs report the sending CPU in bits 12:10.
                if i < 16 { i as u32 | (source as u32) << 10 } else { i as u32 }
            }
            GICC_RPR => self.running_priority(cpu) as u32,
            GICC_HPPIR => self.best(cpu).map_or(SPURIOUS, |i| i as u32),
            GICC_IIDR => 0x0002_043b,
            _ => 0,
        }
    }

    fn cpu_write(&mut self, cpu: usize, off: u64, v: u32) {
        match off {
            GICC_CTLR => self.cpus[cpu].enable = v & 1 != 0,
            GICC_PMR => self.cpus[cpu].pmr = v as u8,
            GICC_BPR => self.cpus[cpu].bpr = v as u8 & 7,
            GICC_EOIR => {
                let id = v & 0x3ff;
                if let Some(irq) = self.irq_mut(cpu, id as usize) {
                    irq.active = false;
                }
                let running = &mut self.cpus[cpu].running;
                if let Some(pos) = running.iter().rposition(|&(r, _)| r == id) {
                    running.remove(pos);
                }
            }
            _ => {}
        }
    }
}

/// An emulated GICv2: a distributor shared by every vCPU and one CPU
/// interface per vCPU, each a [`BusDevice`]. SGIs and PPIs are banked per
/// CPU, SPIs have per-CPU targets (`GICD_ITARGETSR`), and `GICD_SGIR`
/// sends SGIs between CPUs. Guest drivers (Linux `arm,cortex-a15-gic`,
/// `osmium-drivers`' `GicV2`) work unchanged.
///
/// Because banked registers depend on who asks, each vCPU's MMIO bus gets
/// its own views: [`distributor_for`](Self::distributor_for) and
/// [`cpu_interface_for`](Self::cpu_interface_for). Devices drive SPIs with
/// [`set_level`](Self::set_level) and per-CPU PPIs (a vCPU's timer) with
/// [`set_private_level`](Self::set_private_level). Lines are
/// level-sensitive; `GICD_ISPENDR` and SGIs latch until acknowledged. Each
/// CPU's IRQ output is reported through the callback, meant for that vCPU's
/// [`Aarch64Vcpu::irq_line`](crate::aarch64::Aarch64Vcpu::irq_line).
pub struct VirtualGicV2 {
    state: IrqSpinLock<State>,
    output: Output,
}

impl VirtualGicV2 {
    /// A single-CPU GIC with `lines` interrupt IDs (a multiple of 32, at
    /// least 64). `output` reports changes of the CPU's IRQ line.
    pub fn new(lines: usize, output: impl Fn(bool) + Send + Sync + 'static) -> Self {
        Self::with_cpus(1, lines, move |_, level| output(level))
    }

    /// A GIC for `cpus` vCPUs (at most 8). `output(cpu, level)` reports
    /// changes of each CPU's IRQ line.
    pub fn with_cpus(cpus: usize, lines: usize, output: impl Fn(usize, bool) + Send + Sync + 'static) -> Self {
        assert!((1..=8).contains(&cpus), "GICv2 supports 1-8 CPUs");
        let lines = lines.max(64).next_multiple_of(32);
        let mut config = vec![0; lines];
        config[..16].fill(2); // SGIs: edge
        let cpu = || Cpu { private: [Irq::default(); PRIVATE], enable: false, pmr: 0, bpr: 0, running: Vec::new(), asserted: false };
        let state = State {
            dist_enable: false,
            cpus: (0..cpus).map(|_| cpu()).collect(),
            spis: vec![Irq::default(); lines - PRIVATE],
            targets: vec![0; lines - PRIVATE],
            config,
        };
        Self { state: IrqSpinLock::new(state), output: Box::new(output) }
    }

    /// Drives shared interrupt `intid` (an SPI, 32 and up; PPIs go to CPU 0).
    pub fn set_level(&self, intid: u32, level: bool) {
        self.set_private_level(0, intid, level);
    }

    /// Drives interrupt `intid` as seen by `cpu`: its own PPI for IDs below
    /// 32 (e.g. its virtual timer), the shared SPI otherwise.
    pub fn set_private_level(&self, cpu: usize, intid: u32, level: bool) {
        let mut s = self.state.lock();
        if cpu < s.cpus.len()
            && let Some(irq) = s.irq_mut(cpu, intid as usize)
        {
            irq.level = level;
        }
        self.update(&mut s);
    }

    /// Whether CPU 0's IRQ line is asserted.
    pub fn asserted(&self) -> bool {
        self.state.lock().cpus[0].asserted
    }

    fn update(&self, s: &mut State) {
        for cpu in 0..s.cpus.len() {
            let now = s.best(cpu).is_some();
            if now != s.cpus[cpu].asserted {
                s.cpus[cpu].asserted = now;
                (self.output)(cpu, now);
            }
        }
    }

    /// CPU 0's view of the distributor.
    pub fn distributor(self: &Arc<Self>) -> Arc<dyn BusDevice> {
        self.distributor_for(0)
    }

    /// CPU 0's CPU interface.
    pub fn cpu_interface(self: &Arc<Self>) -> Arc<dyn BusDevice> {
        self.cpu_interface_for(0)
    }

    /// The distributor as `cpu` sees it (banked SGI/PPI registers).
    pub fn distributor_for(self: &Arc<Self>, cpu: usize) -> Arc<dyn BusDevice> {
        Arc::new(Window { gic: self.clone(), cpu, interface: false })
    }

    /// `cpu`'s CPU interface.
    pub fn cpu_interface_for(self: &Arc<Self>, cpu: usize) -> Arc<dyn BusDevice> {
        Arc::new(Window { gic: self.clone(), cpu, interface: true })
    }
}

struct Window {
    gic: Arc<VirtualGicV2>,
    cpu: usize,
    interface: bool,
}

impl BusDevice for Window {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let mut s = self.gic.state.lock();
        let v = if self.interface { s.cpu_read(self.cpu, offset & !3) } else { s.dist_read(self.cpu, offset & !3) };
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
        if !self.interface && data.len() == 1 && (GICD_IPRIORITYR..GICD_ICFGR).contains(&offset) {
            s.write_byte(self.cpu, offset, data[0]);
        } else if data.len() == 4 && offset & 3 == 0 {
            let v = u32::from_le_bytes(data.try_into().unwrap());
            if self.interface { s.cpu_write(self.cpu, offset, v) } else { s.dist_write(self.cpu, offset, v) }
        }
        self.gic.update(&mut s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

        // A higher-priority SPI preempts; byte writes set priority and target.
        d.write(GICD_IPRIORITYR + 27, &[0xa0]);
        d.write(GICD_IPRIORITYR + 33, &[0x40]);
        // (No ITARGETSR write: a uniprocessor GIC routes SPIs to its CPU.)
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

    #[test]
    fn two_cpus_sgis_ppis_and_targets() {
        let lines = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);
        let l = lines.clone();
        let gic = Arc::new(VirtualGicV2::with_cpus(2, 64, move |cpu, v| l[cpu].store(v, Ordering::SeqCst)));
        let (d0, c0, d1, c1) = (gic.distributor_for(0), gic.cpu_interface_for(0), gic.distributor_for(1), gic.cpu_interface_for(1));
        assert_eq!(rd(&d0, GICD_TYPER) >> 5 & 7, 1, "two CPUs");
        wr(&d0, GICD_CTLR, 1);
        for (d, c) in [(&d0, &c0), (&d1, &c1)] {
            wr(c, GICC_CTLR, 1);
            wr(c, GICC_PMR, 0xff);
            wr(d, GICD_ISENABLER, 1 << 1 | 1 << 27); // banked: each CPU's own
        }
        assert_eq!(rd(&d1, GICD_ITARGETSR) & 0xff, 2, "private targets read as self");

        // CPU 0 sends SGI 1 to CPU 1.
        wr(&d0, GICD_SGIR, 0b10 << 16 | 1);
        assert!(!lines[0].load(Ordering::SeqCst));
        assert!(lines[1].load(Ordering::SeqCst));
        assert_eq!(rd(&c1, GICC_IAR), 1, "SGI 1 from CPU 0");
        wr(&c1, GICC_EOIR, 1);
        // CPU 1 sends one to all but itself: source 1 in IAR bits 12:10.
        wr(&d1, GICD_SGIR, 1 << 24 | 1);
        assert_eq!(rd(&c0, GICC_IAR), 1 | 1 << 10);

        // CPU 1's timer PPI does not reach CPU 0.
        gic.set_private_level(1, 27, true);
        assert_eq!(rd(&c1, GICC_HPPIR), 27);
        assert_eq!(rd(&c0, GICC_HPPIR), SPURIOUS);

        // An SPI goes where its target says.
        wr(&d0, GICD_ISENABLER + 4, 1);
        d0.write(GICD_ITARGETSR + 32, &[2]);
        gic.set_level(32, true);
        assert_eq!(rd(&c0, GICC_HPPIR), SPURIOUS);
        assert_eq!(rd(&c1, GICC_HPPIR), 27, "27 (prio 0, lower id) first");
    }
}
