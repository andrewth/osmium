use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use osmium_sync::IrqSpinLock;

use crate::bus::{BusDevice, get_le, put_le};

// Distributor registers.
const GICD_CTLR: u64 = 0x000;
const GICD_TYPER: u64 = 0x004;
const GICD_IIDR: u64 = 0x008;
const GICD_IGROUPR: u64 = 0x080;
const GICD_ISENABLER: u64 = 0x100;
const GICD_ICENABLER: u64 = 0x180;
const GICD_ISPENDR: u64 = 0x200;
const GICD_ICPENDR: u64 = 0x280;
const GICD_ISACTIVER: u64 = 0x300;
const GICD_ICACTIVER: u64 = 0x380;
const GICD_IPRIORITYR: u64 = 0x400;
const GICD_ICFGR: u64 = 0xc00;
const GICD_IROUTER: u64 = 0x6000;
const PIDR2: u64 = 0xffe8;

// Redistributor registers: the RD frame, then the SGI frame 64 KiB above.
const GICR_CTLR: u64 = 0x000;
const GICR_IIDR: u64 = 0x004;
const GICR_TYPER: u64 = 0x008;
const GICR_WAKER: u64 = 0x014;
const SGI_FRAME: u64 = 0x1_0000;
const GICR_IGROUPR0: u64 = 0x080;
const GICR_ISENABLER0: u64 = 0x100;
const GICR_ICENABLER0: u64 = 0x180;
const GICR_ISPENDR0: u64 = 0x200;
const GICR_ICPENDR0: u64 = 0x280;
const GICR_ISACTIVER0: u64 = 0x300;
const GICR_ICACTIVER0: u64 = 0x380;
const GICR_IPRIORITYR0: u64 = 0x400;
const GICR_ICFGR0: u64 = 0xc00;

/// `GICD_CTLR`: enable Group 0, enable Group 1, affinity routing (always
/// on), disable security (always on: one security state).
const CTLR_ENABLE_G0: u32 = 1;
const CTLR_ENABLE_G1: u32 = 2;
const CTLR_ARE: u32 = 1 << 4;
const CTLR_DS: u32 = 1 << 6;
/// `GICR_WAKER.ProcessorSleep` and `ChildrenAsleep`.
const WAKER_SLEEP: u32 = 1 << 1;
const WAKER_ASLEEP: u32 = 1 << 2;

/// Size of the distributor's register window.
pub const GICD_V3_WINDOW: u64 = 0x1_0000;
/// Size of one redistributor: the RD and SGI frames, 64 KiB each.
pub const GICR_STRIDE: u64 = 0x2_0000;

/// Interrupts banked per CPU: SGIs 0-15 and PPIs 16-31.
const PRIVATE: usize = 32;
/// The most vCPUs one GIC serves.
const MAX_CPUS: usize = 64;
/// `ICH_LR<n>_EL2` fields.
const LR_STATE_PENDING: u64 = 1;
const LR_STATE_ACTIVE: u64 = 2;
const LR_GROUP1: u64 = 1 << 60;

type Output = Box<dyn Fn(usize, bool) + Send + Sync>;

/// The affinity (`MPIDR_EL1` Aff3..Aff0, without the RES1 and MT bits) of
/// vCPU `cpu`: Aff0 counts within a cluster of 16, Aff1 the clusters, as on
/// QEMU's `virt` machine.
pub const fn vcpu_affinity(cpu: usize) -> u64 {
    ((cpu / 16) as u64) << 8 | (cpu % 16) as u64
}

/// The `MPIDR_EL1` value a guest sees on vCPU `cpu` (program it into
/// `VMPIDR_EL2`), so the guest finds its redistributor by affinity.
pub const fn vcpu_mpidr(cpu: usize) -> u64 {
    1 << 31 | vcpu_affinity(cpu)
}

/// One interrupt's state.
#[derive(Clone, Copy)]
struct Irq {
    enabled: bool,
    level: bool,
    latched: bool,
    active: bool,
    edge: bool,
    group1: bool,
    priority: u8,
}

impl Default for Irq {
    fn default() -> Self {
        // Reset to Group 1, the group non-secure software uses.
        Self { enabled: false, level: false, latched: false, active: false, edge: false, group1: true, priority: 0 }
    }
}

impl Irq {
    fn pending(&self) -> bool {
        (self.latched || (self.level && !self.edge)) && !self.active
    }
}

/// A vCPU's redistributor and the state of its CPU interface the model
/// keeps.
struct Cpu {
    private: [Irq; PRIVATE],
    asleep: bool,
    /// From the last `ICH_VMCR_EL2` the guest ran with.
    pmr: u8,
    enable_g0: bool,
    enable_g1: bool,
    /// The interrupts currently loaded in each list register.
    loaded: Vec<u32>,
    asserted: bool,
}

struct State {
    ctlr: u32,
    cpus: Vec<Cpu>,
    /// SPIs (32 and up).
    spis: Vec<Irq>,
    /// `GICD_IROUTER` per SPI.
    route: Vec<u64>,
}

impl State {
    fn irq(&self, cpu: usize, i: usize) -> Option<&Irq> {
        if i < PRIVATE { self.cpus.get(cpu)?.private.get(i) } else { self.spis.get(i - PRIVATE) }
    }

    fn irq_mut(&mut self, cpu: usize, i: usize) -> Option<&mut Irq> {
        if i < PRIVATE { self.cpus.get_mut(cpu)?.private.get_mut(i) } else { self.spis.get_mut(i - PRIVATE) }
    }

    fn lines(&self) -> usize {
        PRIVATE + self.spis.len()
    }

    /// The vCPU an SPI is routed to: the one `GICD_IROUTER` names, or for
    /// 1-of-N routing the lowest awake one.
    fn target(&self, spi: usize) -> Option<usize> {
        let r = self.route.get(spi - PRIVATE).copied()?;
        if r & (1 << 31) != 0 {
            return (0..self.cpus.len()).find(|&c| self.cpus.get(c).is_some_and(|c| !c.asleep)).or(Some(0));
        }
        let aff = (r & 0xff) | (r >> 8 & 0xff) << 8;
        (0..self.cpus.len()).find(|&c| vcpu_affinity(c) == aff)
    }

    /// Whether interrupt `i` can be delivered to `cpu` as far as the
    /// distributor and redistributor are concerned (priority masking is the
    /// CPU interface's).
    fn deliverable(&self, cpu: usize, i: usize) -> bool {
        let (Some(c), Some(irq)) = (self.cpus.get(cpu), self.irq(cpu, i)) else { return false };
        if c.asleep || self.ctlr & (CTLR_ENABLE_G0 | CTLR_ENABLE_G1) == 0 || !irq.enabled || !irq.pending() {
            return false;
        }
        i < PRIVATE || self.target(i) == Some(cpu)
    }

    fn group_enabled(&self, cpu: usize, group1: bool) -> bool {
        self.cpus.get(cpu).is_some_and(|c| if group1 { c.enable_g1 } else { c.enable_g0 })
    }

    /// The running priority: that of the highest-priority active interrupt.
    fn running_priority(&self, cpu: usize) -> u8 {
        (0..self.lines())
            .filter_map(|i| self.irq(cpu, i).filter(|q| q.active && (i < PRIVATE || self.target(i) == Some(cpu))))
            .map(|q| q.priority)
            .min()
            .unwrap_or(0xff)
    }

    /// Whether the CPU interface would signal an interrupt to `cpu`: the
    /// output line to the vCPU (wakes a halted guest).
    fn signals(&self, cpu: usize) -> bool {
        let rp = self.running_priority(cpu);
        let Some(c) = self.cpus.get(cpu) else { return false };
        (0..self.lines()).any(|i| {
            self.deliverable(cpu, i)
                && self.group_enabled(cpu, self.irq(cpu, i).is_some_and(|q| q.group1))
                && self.irq(cpu, i).is_some_and(|q| q.priority < c.pmr && q.priority < rp)
        })
    }

    /// 32 one-bit flags of `f` starting at INTID `base`, as `cpu` sees them.
    fn bits(&self, cpu: usize, base: usize, f: impl Fn(&Irq) -> bool) -> u32 {
        (0..32).filter(|b| self.irq(cpu, base + b).is_some_and(&f)).fold(0, |w, b| w | 1 << b)
    }

    fn set_bits(&mut self, cpu: usize, base: usize, mask: u32, f: impl Fn(&mut Irq)) {
        for b in 0..32 {
            // INTIDs 0-15 are SGIs, which have no level input; the rest are as written.
            if mask & (1 << b) != 0
                && let Some(irq) = self.irq_mut(cpu, base + b)
            {
                f(irq);
            }
        }
    }

    /// One banked or shared register of the per-interrupt arrays, selected by
    /// `off` relative to the array's base for the distributor (`cpu` is the
    /// redistributor for the SGI frame's copy of INTIDs 0-31).
    fn intr_read(&self, cpu: usize, bank: u64, rel: u64) -> u32 {
        let word = (rel / 4 * 32) as usize;
        match bank {
            GICD_IGROUPR => self.bits(cpu, word, |i| i.group1),
            GICD_ISENABLER | GICD_ICENABLER => self.bits(cpu, word, |i| i.enabled),
            GICD_ISPENDR | GICD_ICPENDR => self.bits(cpu, word, Irq::pending),
            GICD_ISACTIVER | GICD_ICACTIVER => self.bits(cpu, word, |i| i.active),
            GICD_IPRIORITYR => {
                let i = rel as usize;
                (0..4).fold(0, |w, k| w | (self.irq(cpu, i + k).map_or(0, |q| q.priority) as u32) << (8 * k))
            }
            GICD_ICFGR => {
                let i = (rel * 4) as usize;
                (0..16).fold(0, |w, k| w | (self.irq(cpu, i + k).is_some_and(|q| q.edge) as u32 * 2) << (2 * k))
            }
            _ => 0,
        }
    }

    fn intr_write(&mut self, cpu: usize, bank: u64, rel: u64, v: u32) {
        let word = (rel / 4 * 32) as usize;
        match bank {
            GICD_IGROUPR => {
                for b in 0..32 {
                    if let Some(i) = self.irq_mut(cpu, word + b) {
                        i.group1 = v & (1 << b) != 0;
                    }
                }
            }
            GICD_ISENABLER => self.set_bits(cpu, word, v, |i| i.enabled = true),
            GICD_ICENABLER => self.set_bits(cpu, word, v, |i| i.enabled = false),
            GICD_ISPENDR => self.set_bits(cpu, word, v, |i| i.latched = true),
            GICD_ICPENDR => self.set_bits(cpu, word, v, |i| i.latched = false),
            GICD_ISACTIVER => self.set_bits(cpu, word, v, |i| i.active = true),
            GICD_ICACTIVER => self.set_bits(cpu, word, v, |i| i.active = false),
            GICD_IPRIORITYR => {
                for k in 0..4 {
                    self.write_priority(cpu, rel as usize + k, (v >> (8 * k)) as u8);
                }
            }
            GICD_ICFGR => {
                let i = (rel * 4) as usize;
                for k in 0..16 {
                    // SGIs are always edge; PPIs here are fixed level.
                    if i + k >= 16
                        && let Some(irq) = self.irq_mut(cpu, i + k)
                    {
                        irq.edge = (v >> (2 * k)) & 2 != 0;
                    }
                }
            }
            _ => {}
        }
    }

    fn write_priority(&mut self, cpu: usize, intid: usize, b: u8) {
        if let Some(i) = self.irq_mut(cpu, intid) {
            i.priority = b;
        }
    }

    /// Which per-interrupt register array `off` falls in, and the offset in
    /// it. INTIDs 0-31 live in the redistributors, so the distributor's
    /// first words of each array are reserved.
    fn dist_bank(off: u64) -> Option<(u64, u64)> {
        let (bank, min) = match off {
            0x080..0x100 => (GICD_IGROUPR, 4),
            0x100..0x180 => (GICD_ISENABLER, 4),
            0x180..0x200 => (GICD_ICENABLER, 4),
            0x200..0x280 => (GICD_ISPENDR, 4),
            0x280..0x300 => (GICD_ICPENDR, 4),
            0x300..0x380 => (GICD_ISACTIVER, 4),
            0x380..0x400 => (GICD_ICACTIVER, 4),
            0x400..0x800 => (GICD_IPRIORITYR, PRIVATE as u64),
            0xc00..0xd00 => (GICD_ICFGR, 8),
            _ => return None,
        };
        let rel = off - bank;
        (rel >= min).then_some((bank, rel))
    }

    /// The SPI whose `GICD_IROUTER` register covers `off`.
    fn router(off: u64) -> Option<usize> {
        let spi = (off.checked_sub(GICD_IROUTER)? / 8) as usize;
        (PRIVATE..1020).contains(&spi).then_some(spi)
    }

    fn dist_read(&self, off: u64) -> u32 {
        match off {
            GICD_CTLR => self.ctlr | CTLR_ARE | CTLR_DS,
            // ITLinesNumber, CPUNumber = 0, IDbits = 15, no LPIs, one security state (DS).
            GICD_TYPER => (self.lines() / 32 - 1) as u32 | 15 << 19,
            GICD_IIDR => 0x0300_043b,
            PIDR2 => 0x30,
            o => {
                if let Some((bank, rel)) = Self::dist_bank(o) {
                    self.intr_read(0, bank, rel)
                } else if let Some(spi) = Self::router(o) {
                    let r = self.route.get(spi - PRIVATE).copied().unwrap_or(0);
                    if o & 4 == 0 { r as u32 } else { (r >> 32) as u32 }
                } else {
                    0
                }
            }
        }
    }

    fn dist_write(&mut self, off: u64, v: u32) {
        if off == GICD_CTLR {
            self.ctlr = v & (CTLR_ENABLE_G0 | CTLR_ENABLE_G1);
        } else if let Some((bank, rel)) = Self::dist_bank(off) {
            self.intr_write(0, bank, rel, v);
        } else if let Some(spi) = Self::router(off)
            && let Some(r) = self.route.get_mut(spi - PRIVATE)
        {
            // Only Aff0, Aff1 and IRM are meaningful with this many CPUs.
            let (lo, hi) = if off & 4 == 0 { (u64::from(v), *r >> 32) } else { (*r & 0xffff_ffff, u64::from(v)) };
            *r = (hi << 32 | lo) & 0xff_0000_ffff | (lo & (1 << 31));
        }
    }

    /// `redist` is the byte offset within redistributor `cpu`'s 128 KiB.
    fn redist_read(&self, cpu: usize, redist: u64) -> u32 {
        let Some(c) = self.cpus.get(cpu) else { return 0 };
        if redist < SGI_FRAME {
            return match redist {
                GICR_CTLR => 0,
                GICR_IIDR => 0x0300_043b,
                // Aff in bits 63:32, Last in bit 4, ProcessorNumber in 23:8.
                GICR_TYPER => (cpu as u32) << 8 | u32::from(cpu + 1 == self.cpus.len()) << 4,
                o if o == GICR_TYPER + 4 => vcpu_affinity(cpu) as u32,
                GICR_WAKER => {
                    if c.asleep {
                        WAKER_SLEEP | WAKER_ASLEEP
                    } else {
                        0
                    }
                }
                PIDR2 => 0x30,
                _ => 0,
            };
        }
        let o = redist - SGI_FRAME;
        match o {
            o if (GICR_IGROUPR0..GICR_IGROUPR0 + 4).contains(&o) => self.intr_read(cpu, GICD_IGROUPR, 0),
            o if (GICR_ISENABLER0..GICR_ISENABLER0 + 4).contains(&o)
                || (GICR_ICENABLER0..GICR_ICENABLER0 + 4).contains(&o) =>
            {
                self.intr_read(cpu, GICD_ISENABLER, 0)
            }
            o if (GICR_ISPENDR0..GICR_ISPENDR0 + 4).contains(&o) || (GICR_ICPENDR0..GICR_ICPENDR0 + 4).contains(&o) => {
                self.intr_read(cpu, GICD_ISPENDR, 0)
            }
            o if (GICR_ISACTIVER0..GICR_ISACTIVER0 + 4).contains(&o)
                || (GICR_ICACTIVER0..GICR_ICACTIVER0 + 4).contains(&o) =>
            {
                self.intr_read(cpu, GICD_ISACTIVER, 0)
            }
            o if (GICR_IPRIORITYR0..GICR_IPRIORITYR0 + PRIVATE as u64).contains(&o) => {
                self.intr_read(cpu, GICD_IPRIORITYR, o - GICR_IPRIORITYR0)
            }
            o if (GICR_ICFGR0..GICR_ICFGR0 + 8).contains(&o) => self.intr_read(cpu, GICD_ICFGR, o - GICR_ICFGR0),
            _ => 0,
        }
    }

    fn redist_write(&mut self, cpu: usize, redist: u64, v: u32) {
        if redist < SGI_FRAME {
            if redist == GICR_WAKER
                && let Some(c) = self.cpus.get_mut(cpu)
            {
                c.asleep = v & WAKER_SLEEP != 0;
            }
            return;
        }
        let o = redist - SGI_FRAME;
        match o {
            o if (GICR_IGROUPR0..GICR_IGROUPR0 + 4).contains(&o) => self.intr_write(cpu, GICD_IGROUPR, 0, v),
            o if (GICR_ISENABLER0..GICR_ISENABLER0 + 4).contains(&o) => self.intr_write(cpu, GICD_ISENABLER, 0, v),
            o if (GICR_ICENABLER0..GICR_ICENABLER0 + 4).contains(&o) => self.intr_write(cpu, GICD_ICENABLER, 0, v),
            o if (GICR_ISPENDR0..GICR_ISPENDR0 + 4).contains(&o) => self.intr_write(cpu, GICD_ISPENDR, 0, v),
            o if (GICR_ICPENDR0..GICR_ICPENDR0 + 4).contains(&o) => self.intr_write(cpu, GICD_ICPENDR, 0, v),
            o if (GICR_ISACTIVER0..GICR_ISACTIVER0 + 4).contains(&o) => self.intr_write(cpu, GICD_ISACTIVER, 0, v),
            o if (GICR_ICACTIVER0..GICR_ICACTIVER0 + 4).contains(&o) => self.intr_write(cpu, GICD_ICACTIVER, 0, v),
            o if (GICR_IPRIORITYR0..GICR_IPRIORITYR0 + PRIVATE as u64).contains(&o) => {
                self.intr_write(cpu, GICD_IPRIORITYR, o - GICR_IPRIORITYR0, v)
            }
            o if (GICR_ICFGR0..GICR_ICFGR0 + 8).contains(&o) => self.intr_write(cpu, GICD_ICFGR, o - GICR_ICFGR0, v),
            _ => {}
        }
    }
}

/// An emulated GICv3 without an ITS: a distributor and one redistributor
/// per vCPU as MMIO devices, plus the software side of the CPU interface.
///
/// # Scope
///
/// - One security state (`GICD_CTLR.DS` = 1) and affinity routing always on
///   (no legacy GICv2 mode). SGIs, PPIs and SPIs, Group 0 and 1, 8-bit
///   priorities, edge and level SPIs, `GICD_IROUTER` routing (Aff0, Aff1 and
///   1-of-N) and `GICR_WAKER` are modeled.
/// - No LPIs, no ITS, no GICv4, no message-based SPIs, no `GICD_STATUSR`,
///   no 16-bit `INTID` extended ranges.
/// - The CPU interface is not emulated register by register. A guest uses
///   the host's virtual CPU interface (`ICV_*` registers, which `HCR_EL2.IMO`
///   redirects), fed through list registers: before each guest entry call
///   [`fill_list_registers`](Self::fill_list_registers) and after each exit
///   [`sync_list_registers`](Self::sync_list_registers), which carry
///   pending and active state between this model and the hardware.
///   `ICC_SGI1R_EL1` writes trap to EL2; pass them to
///   [`send_sgi`](Self::send_sgi).
///
/// Devices drive SPIs with [`set_level`](Self::set_level) and per-vCPU PPIs
/// (a vCPU's timer) with [`set_private_level`](Self::set_private_level).
/// Each vCPU's "interrupt deliverable" output is reported through the
/// callback (meant for [`Aarch64Vcpu::irq_line`](crate::aarch64::Aarch64Vcpu::irq_line),
/// which wakes a guest halted in `wfi`).
pub struct VirtualGicV3 {
    state: IrqSpinLock<State>,
    output: Output,
}

impl VirtualGicV3 {
    /// A GIC for `cpus` vCPUs (`1..=64`, clamped) with `lines` interrupt IDs
    /// (rounded up to a multiple of 32, at least 64, at most 1024).
    /// `output(cpu, level)` reports changes of each vCPU's interrupt signal.
    pub fn new(cpus: usize, lines: usize, output: impl Fn(usize, bool) + Send + Sync + 'static) -> Self {
        let cpus = cpus.clamp(1, MAX_CPUS);
        let lines = lines.clamp(64, 1024).next_multiple_of(32);
        let cpu = || {
            let mut private = [Irq::default(); PRIVATE];
            // SGIs are edge-triggered.
            private.iter_mut().take(16).for_each(|i| i.edge = true);
            Cpu {
                private,
                asleep: true,
                pmr: 0,
                enable_g0: false,
                enable_g1: false,
                loaded: Vec::new(),
                asserted: false,
            }
        };
        let state = State {
            ctlr: 0,
            cpus: (0..cpus).map(|_| cpu()).collect(),
            spis: vec![Irq::default(); lines - PRIVATE],
            route: vec![0; lines - PRIVATE],
        };
        Self { state: IrqSpinLock::new(state), output: Box::new(output) }
    }

    /// Size of the redistributor region for `cpus` vCPUs.
    pub const fn redistributor_window(cpus: usize) -> u64 {
        GICR_STRIDE * cpus as u64
    }

    /// Drives shared interrupt `intid` (an SPI, 32 and up).
    pub fn set_level(&self, intid: u32, level: bool) {
        self.set_private_level(0, intid, level);
    }

    /// Drives interrupt `intid` as seen by `cpu`: its own PPI for IDs below
    /// 32 (e.g. its virtual timer), the shared SPI otherwise. A rising edge
    /// on an edge-triggered line latches it.
    pub fn set_private_level(&self, cpu: usize, intid: u32, level: bool) {
        let mut s = self.state.lock();
        if intid >= 16
            && let Some(irq) = s.irq_mut(cpu, intid as usize)
        {
            if level && !irq.level {
                irq.latched |= irq.edge;
            }
            irq.level = level;
        }
        self.update(&mut s);
    }

    /// Whether `cpu`'s interrupt signal is asserted.
    pub fn asserted(&self, cpu: usize) -> bool {
        self.state.lock().cpus.get(cpu).is_some_and(|c| c.asserted)
    }

    /// Handles a guest write of `value` to `ICC_SGI1R_EL1` (or
    /// `ICC_ASGI1R_EL1`, which this single-security-state model treats alike)
    /// by vCPU `from`: pends the SGI on each target.
    pub fn send_sgi(&self, from: usize, value: u64) {
        let mut s = self.state.lock();
        let sgi = ((value >> 24) & 0xf) as usize;
        let (aff1, aff2, aff3) = ((value >> 16) & 0xff, (value >> 32) & 0xff, (value >> 48) & 0xff);
        let range = ((value >> 44) & 0xf) * 16;
        let all_but_self = value & (1 << 40) != 0;
        for t in 0..s.cpus.len() {
            let aff = vcpu_affinity(t);
            let hit = if all_but_self {
                t != from
            } else {
                // vCPU affinities have Aff2 = Aff3 = 0.
                aff2 == 0 && aff3 == 0 && aff >> 8 == aff1 && {
                    let a0 = aff & 0xff;
                    a0 >= range && a0 - range < 16 && (value >> (a0 - range)) & 1 != 0
                }
            };
            if hit && let Some(irq) = s.cpus.get_mut(t).and_then(|c| c.private.get_mut(sgi)) {
                irq.latched = true;
            }
        }
        self.update(&mut s);
    }

    /// Fills `out` (one `ICH_LR<n>_EL2` image per hardware list register)
    /// with what `cpu`'s guest should see: the interrupts it is handling
    /// (active) first, then the pending ones that are deliverable, highest
    /// priority first. Unused registers are zero (invalid). Returns whether
    /// more interrupts were pending than registers (set `ICH_HCR_EL2.UIE` to
    /// get an exit when the guest has consumed them).
    pub fn fill_list_registers(&self, cpu: usize, out: &mut [u64]) -> bool {
        let mut s = self.state.lock();
        out.iter_mut().for_each(|l| *l = 0);
        let mut active = Vec::new();
        let mut pending = Vec::new();
        for i in 0..s.lines() {
            let Some(irq) = s.irq(cpu, i) else { continue };
            if i >= PRIVATE && s.target(i) != Some(cpu) {
                continue;
            }
            if irq.active {
                active.push((irq.priority, i));
            } else if s.deliverable(cpu, i) {
                pending.push((irq.priority, i));
            }
        }
        // The sort is stable: ties go to the lowest INTID.
        active.sort_by_key(|&(p, _)| p);
        pending.sort_by_key(|&(p, _)| p);
        let mut slots = out.iter_mut();
        let mut loaded = Vec::new();
        let mut overflow = false;
        for (state, list) in [(LR_STATE_ACTIVE, active), (LR_STATE_PENDING, pending)] {
            for (prio, i) in list {
                let Some(slot) = slots.next() else {
                    overflow = true;
                    break;
                };
                let group = if s.irq(cpu, i).is_some_and(|q| q.group1) { LR_GROUP1 } else { 0 };
                *slot = state << 62 | group | (prio as u64) << 48 | i as u64;
                loaded.push(i as u32);
            }
        }
        if let Some(c) = s.cpus.get_mut(cpu) {
            c.loaded = loaded;
        }
        overflow
    }

    /// Reads back after a guest exit: `lrs` are the `ICH_LR<n>_EL2` values
    /// and `vmcr` is `ICH_VMCR_EL2`. Interrupts the guest acknowledged become
    /// active here, completed ones inactive, and the priority mask and group
    /// enables the guest set are noted for the interrupt signal.
    pub fn sync_list_registers(&self, cpu: usize, lrs: &[u64], vmcr: u64) {
        let mut s = self.state.lock();
        let loaded = s.cpus.get_mut(cpu).map(|c| core::mem::take(&mut c.loaded)).unwrap_or_default();
        for (&id, &lr) in loaded.iter().zip(lrs) {
            let st = lr >> 62;
            if let Some(irq) = s.irq_mut(cpu, id as usize) {
                if st == 0 {
                    // Acknowledged and completed.
                    irq.active = false;
                    irq.latched = false;
                } else if st & LR_STATE_ACTIVE != 0 {
                    irq.active = true;
                    // An edge latched again while the guest handled it (state 3) stays pending
                    // for after its completion; otherwise the acknowledge consumed it.
                    irq.latched = st & LR_STATE_PENDING != 0;
                }
                // Still only pending: the guest has not taken it; it is offered again.
            }
        }
        if let Some(c) = s.cpus.get_mut(cpu) {
            c.pmr = (vmcr >> 24) as u8;
            c.enable_g0 = vmcr & 1 != 0;
            c.enable_g1 = vmcr & 2 != 0;
        }
        self.update(&mut s);
    }

    fn update(&self, s: &mut State) {
        for cpu in 0..s.cpus.len() {
            let now = s.signals(cpu);
            if let Some(c) = s.cpus.get_mut(cpu)
                && now != c.asserted
            {
                c.asserted = now;
                (self.output)(cpu, now);
            }
        }
    }

    /// The distributor, for every vCPU's bus ([`GICD_V3_WINDOW`] bytes).
    pub fn distributor(self: &Arc<Self>) -> Arc<dyn BusDevice> {
        Arc::new(Window { gic: self.clone(), redistributors: false })
    }

    /// The redistributors, back to back ([`redistributor_window`](Self::redistributor_window)
    /// bytes), for every vCPU's bus.
    pub fn redistributors(self: &Arc<Self>) -> Arc<dyn BusDevice> {
        Arc::new(Window { gic: self.clone(), redistributors: true })
    }
}

struct Window {
    gic: Arc<VirtualGicV3>,
    redistributors: bool,
}

impl Window {
    fn word_read(&self, s: &State, at: u64) -> u32 {
        if self.redistributors { s.redist_read((at / GICR_STRIDE) as usize, at % GICR_STRIDE) } else { s.dist_read(at) }
    }

    fn word_write(&self, s: &mut State, at: u64, v: u32) {
        if self.redistributors {
            s.redist_write((at / GICR_STRIDE) as usize, at % GICR_STRIDE, v)
        } else {
            s.dist_write(at, v)
        }
    }
}

impl BusDevice for Window {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let s = self.gic.state.lock();
        // Assemble the access from aligned words, so 64-bit registers read
        // as two halves and sub-word accesses pick their bytes.
        let mut bytes = [0u8; 8];
        let len = data.len().min(8) as u64;
        let first = offset & !3;
        let mut word = first;
        while word < offset.saturating_add(len) {
            let w = self.word_read(&s, word).to_le_bytes();
            for (k, b) in w.iter().enumerate() {
                let pos = word.wrapping_add(k as u64);
                if pos >= offset
                    && let Some(d) = bytes.get_mut(pos.wrapping_sub(offset) as usize)
                {
                    *d = *b;
                }
            }
            word = match word.checked_add(4) {
                Some(w) => w,
                None => break,
            };
        }
        put_le(data, u64::from_le_bytes(bytes));
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let mut s = self.gic.state.lock();
        match data.len() {
            // Byte writes reach the byte-wide priority registers.
            1 => {
                let byte = data.first().copied().unwrap_or(0);
                if self.redistributors {
                    let (cpu, o) = ((offset / GICR_STRIDE) as usize, offset % GICR_STRIDE);
                    let base = SGI_FRAME + GICR_IPRIORITYR0;
                    if (base..base + PRIVATE as u64).contains(&o) {
                        s.write_priority(cpu, (o - base) as usize, byte);
                    }
                } else if let Some((GICD_IPRIORITYR, rel)) = State::dist_bank(offset) {
                    s.write_priority(0, rel as usize, byte);
                }
            }
            4 if offset & 3 == 0 => self.word_write(&mut s, offset, get_le(data) as u32),
            8 if offset & 7 == 0 => {
                let v = get_le(data);
                self.word_write(&mut s, offset, v as u32);
                self.word_write(&mut s, offset | 4, (v >> 32) as u32);
            }
            _ => {}
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

    fn rd64(w: &Arc<dyn BusDevice>, off: u64) -> u64 {
        let mut b = [0u8; 8];
        w.read(off, &mut b);
        u64::from_le_bytes(b)
    }

    fn wr(w: &Arc<dyn BusDevice>, off: u64, v: u32) {
        w.write(off, &v.to_le_bytes());
    }

    const NLR: usize = 4;
    const VMCR_ALL: u64 = 0xf8 << 24 | 2; // PMR 0xf8, Group 1 enabled

    /// What the hardware's virtual CPU interface does with the list
    /// registers: acknowledge the highest-priority pending one, complete one.
    fn ack(lrs: &mut [u64]) -> Option<u32> {
        let best = lrs.iter_mut().filter(|l| **l >> 62 == LR_STATE_PENDING).min_by_key(|l| (**l >> 48) & 0xff)?;
        *best = (*best & !(3 << 62)) | LR_STATE_ACTIVE << 62;
        Some(*best as u32)
    }

    fn eoi(lrs: &mut [u64], id: u32) {
        for l in lrs.iter_mut().filter(|l| **l as u32 == id && **l >> 62 == LR_STATE_ACTIVE) {
            *l &= !(3 << 62);
        }
    }

    fn gic(cpus: usize) -> (Arc<VirtualGicV3>, Arc<[AtomicBool; 2]>) {
        let lines = Arc::new([AtomicBool::new(false), AtomicBool::new(false)]);
        let l = lines.clone();
        let g = Arc::new(VirtualGicV3::new(cpus, 64, move |cpu, v| {
            if let Some(x) = l.get(cpu) {
                x.store(v, Ordering::SeqCst)
            }
        }));
        (g, lines)
    }

    /// Wakes redistributor `cpu` and enables the distributor, as Linux does.
    fn bring_up(g: &Arc<VirtualGicV3>, cpu: usize) {
        let r = g.redistributors();
        wr(&r, cpu as u64 * GICR_STRIDE + GICR_WAKER, 0);
        assert_eq!(rd(&r, cpu as u64 * GICR_STRIDE + GICR_WAKER) & WAKER_ASLEEP, 0);
        wr(&g.distributor(), GICD_CTLR, 0x13);
    }

    #[test]
    fn identification_and_discovery() {
        let (g, _) = gic(2);
        let (d, r) = (g.distributor(), g.redistributors());
        assert_eq!(rd(&d, GICD_TYPER) & 0x1f, 1, "64 lines");
        assert_eq!(rd(&d, GICD_TYPER) >> 19 & 0x1f, 15, "16-bit INTIDs");
        assert_eq!(rd(&d, PIDR2) >> 4 & 0xf, 3, "architecture revision: GICv3");
        assert_eq!(rd(&d, GICD_CTLR) & (CTLR_ARE | CTLR_DS), CTLR_ARE | CTLR_DS);
        // Redistributors: affinity in TYPER[63:32], Last only on the final one.
        let t0 = rd64(&r, GICR_TYPER);
        let t1 = rd64(&r, GICR_STRIDE + GICR_TYPER);
        assert_eq!((t0 >> 32, t0 >> 4 & 1, t0 >> 8 & 0xffff), (0, 0, 0));
        assert_eq!((t1 >> 32, t1 >> 4 & 1, t1 >> 8 & 0xffff), (1, 1, 1));
        assert_eq!(rd(&r, GICR_STRIDE + PIDR2) >> 4 & 0xf, 3);
        // They start asleep until the guest clears ProcessorSleep.
        assert_eq!(rd(&r, GICR_WAKER) & WAKER_ASLEEP, WAKER_ASLEEP);
        wr(&r, GICR_WAKER, 0);
        assert_eq!(rd(&r, GICR_WAKER), 0);
        assert_eq!(rd(&r, GICR_STRIDE + GICR_WAKER) & WAKER_ASLEEP, WAKER_ASLEEP, "vCPU 1 still asleep");
        assert_eq!(vcpu_mpidr(17), 1 << 31 | 1 << 8 | 1);
    }

    #[test]
    fn ppi_through_list_registers() {
        let (g, lines) = gic(1);
        let (d, r) = (g.distributor(), g.redistributors());
        let sgi = SGI_FRAME;
        bring_up(&g, 0);
        // Everything starts in Group 1; the timer PPI fires before it is enabled.
        assert_eq!(rd(&r, sgi + GICR_IGROUPR0), !0);
        g.set_private_level(0, 27, true);
        let mut lr = [0u64; NLR];
        assert!(!g.fill_list_registers(0, &mut lr));
        assert_eq!(lr, [0; NLR], "not enabled: nothing to inject");
        wr(&r, sgi + GICR_ISENABLER0, 1 << 27);
        r.write(sgi + GICR_IPRIORITYR0 + 27, &[0xa0]);
        g.sync_list_registers(0, &lr, VMCR_ALL);
        assert!(lines[0].load(Ordering::SeqCst));
        assert_eq!(rd(&r, sgi + GICR_ISPENDR0), 1 << 27);

        // Pending in LR 0 with its priority and Group 1.
        assert!(!g.fill_list_registers(0, &mut lr));
        assert_eq!(lr[0], LR_STATE_PENDING << 62 | LR_GROUP1 | 0xa0 << 48 | 27);
        // The guest acknowledges it (the hardware turns the LR active); the
        // level still holds, but it is active so not signaled again.
        assert_eq!(ack(&mut lr), Some(27));
        g.sync_list_registers(0, &lr, VMCR_ALL);
        assert!(!lines[0].load(Ordering::SeqCst));
        assert_eq!(rd(&r, sgi + GICR_ISACTIVER0), 1 << 27);
        // Across an exit, the active interrupt stays loaded for the guest's EOI.
        g.fill_list_registers(0, &mut lr);
        assert_eq!(lr[0] >> 62, LR_STATE_ACTIVE);
        eoi(&mut lr, 27);
        g.sync_list_registers(0, &lr, VMCR_ALL);
        assert_eq!(rd(&r, sgi + GICR_ISACTIVER0), 0);
        assert!(lines[0].load(Ordering::SeqCst), "the timer level is still up: pending again");
        g.set_private_level(0, 27, false);
        assert!(!lines[0].load(Ordering::SeqCst));
        let _ = d;
    }

    #[test]
    fn spi_routing_priority_and_masking() {
        let (g, lines) = gic(2);
        let (d, r) = (g.distributor(), g.redistributors());
        bring_up(&g, 0);
        bring_up(&g, 1);
        // Two level SPIs at different priorities; SPI 33 routed to vCPU 1.
        wr(&d, GICD_ISENABLER + 4, 0b110);
        wr(&d, GICD_IPRIORITYR + 32, 0x80 << 8 | 0x40 << 16); // SPIs 33 and 34
        d.write(GICD_IPRIORITYR + 34, &[0x20]);
        d.write(GICD_IROUTER + 8 * 33, &1u64.to_le_bytes());
        assert_eq!(rd64(&d, GICD_IROUTER + 8 * 33), 1);
        assert_eq!(rd64(&d, GICD_IROUTER + 8 * 34), 0, "default: vCPU 0");
        g.set_level(33, true);
        g.set_level(34, true);
        let (mut lr0, mut lr1) = ([0u64; NLR], [0u64; NLR]);
        g.fill_list_registers(0, &mut lr0);
        g.fill_list_registers(1, &mut lr1);
        assert_eq!(lr0[0] as u32, 34);
        assert_eq!(lr0[1], 0);
        assert_eq!(lr1[0] as u32, 33);
        g.sync_list_registers(0, &lr0, VMCR_ALL);
        g.sync_list_registers(1, &lr1, VMCR_ALL);
        assert!(lines[0].load(Ordering::SeqCst) && lines[1].load(Ordering::SeqCst));

        // A priority mask at or below the interrupt's priority silences the signal.
        g.sync_list_registers(0, &lr0, 0x20 << 24 | 2);
        assert!(!lines[0].load(Ordering::SeqCst));
        // So does disabling Group 1 in the CPU interface.
        g.sync_list_registers(1, &lr1, 0xff << 24);
        assert!(!lines[1].load(Ordering::SeqCst));
        g.sync_list_registers(1, &lr1, VMCR_ALL);
        assert!(lines[1].load(Ordering::SeqCst));

        // The distributor's enable gates everything.
        wr(&d, GICD_CTLR, 0);
        assert!(!lines[1].load(Ordering::SeqCst));
        wr(&d, GICD_CTLR, 0x13);
        // 1-of-N routing goes to the lowest awake vCPU.
        d.write(GICD_IROUTER + 8 * 33, &(1u64 << 31).to_le_bytes());
        g.fill_list_registers(0, &mut lr0);
        assert!(lr0.iter().any(|l| *l as u32 == 33));
        let _ = r;
    }

    #[test]
    fn sgi_between_vcpus_and_edge_spi() {
        let (g, lines) = gic(2);
        let r = g.redistributors();
        bring_up(&g, 0);
        bring_up(&g, 1);
        for cpu in 0..2u64 {
            wr(&r, cpu * GICR_STRIDE + SGI_FRAME + GICR_ISENABLER0, 1 << 3);
        }
        for cpu in 0..2 {
            g.sync_list_registers(cpu, &[], VMCR_ALL);
        }
        // vCPU 0 sends SGI 3 to vCPU 1 only (TargetList bit 1).
        g.send_sgi(0, 3 << 24 | 0b10);
        assert!(!lines[0].load(Ordering::SeqCst));
        assert!(lines[1].load(Ordering::SeqCst));
        let mut lr = [0u64; NLR];
        g.fill_list_registers(1, &mut lr);
        assert_eq!(lr[0] as u32, 3);
        assert_eq!(ack(&mut lr), Some(3));
        g.sync_list_registers(1, &lr, VMCR_ALL);
        g.fill_list_registers(1, &mut lr);
        eoi(&mut lr, 3);
        g.sync_list_registers(1, &lr, VMCR_ALL);
        assert!(!lines[1].load(Ordering::SeqCst), "an acknowledged SGI is consumed");
        // vCPU 1 sends to everyone else; a wrong cluster number hits nobody.
        g.send_sgi(1, 1 << 40 | 3 << 24);
        assert!(lines[0].load(Ordering::SeqCst));
        assert!(!lines[1].load(Ordering::SeqCst));
        g.sync_list_registers(0, &[], VMCR_ALL);
        let mut none = [0u64; NLR];
        g.send_sgi(0, 3 << 24 | 5 << 16 | 0b11);
        g.fill_list_registers(1, &mut none);
        assert_eq!(none[0], 0);

        // An edge SPI latches on a rising edge and is consumed by the acknowledge.
        let d = g.distributor();
        wr(&d, GICD_ISENABLER + 4, 1 << 2);
        wr(&d, GICD_ICFGR + 8, 0b10 << 4); // INTID 34 edge
        g.set_level(34, true);
        g.set_level(34, false);
        assert!(lines[0].load(Ordering::SeqCst), "the pulse is remembered");
        let mut lr = [0u64; NLR];
        g.fill_list_registers(0, &mut lr);
        assert!(lr.iter().any(|l| *l as u32 == 34));
        ack(&mut lr);
        g.sync_list_registers(0, &lr, VMCR_ALL);
        g.fill_list_registers(0, &mut lr);
        eoi(&mut lr, 34);
        g.sync_list_registers(0, &lr, VMCR_ALL);
        assert!(!lines[0].load(Ordering::SeqCst));
    }

    #[test]
    fn list_register_overflow_and_nested_priority() {
        let (g, lines) = gic(1);
        let (d, _) = (g.distributor(), g.redistributors());
        bring_up(&g, 0);
        wr(&d, GICD_ISENABLER + 4, !0);
        for i in 0..6u32 {
            g.set_level(32 + i, true);
        }
        // Priorities 0x10 * (index + 1): lower INTID, higher priority.
        for i in 0..6u64 {
            d.write(GICD_IPRIORITYR + 32 + i, &[0x10 * (i as u8 + 1)]);
        }
        let mut lr = [0u64; 3];
        assert!(g.fill_list_registers(0, &mut lr), "6 pending, 3 registers");
        assert_eq!(lr.map(|l| l as u32), [32, 33, 34]);
        // Handle the first; a higher-priority interrupt preempts it, a
        // lower one cannot (the hardware enforces that; the model signals
        // only what could preempt).
        assert_eq!(ack(&mut lr), Some(32));
        g.sync_list_registers(0, &lr, VMCR_ALL);
        assert!(!lines[0].load(Ordering::SeqCst), "nothing outranks the running 0x10");
        g.fill_list_registers(0, &mut lr);
        eoi(&mut lr, 32);
        g.sync_list_registers(0, &lr, VMCR_ALL);
        g.set_level(32, false);
        assert!(g.fill_list_registers(0, &mut lr));
        assert_eq!(lr.map(|l| l as u32), [33, 34, 35]);
        // Deactivation by the distributor (a guest-written ICACTIVER) drops it.
        wr(&d, GICD_ISACTIVER + 4, 1 << 3);
        assert_eq!(rd(&d, GICD_ISACTIVER + 4), 1 << 3);
        wr(&d, GICD_ICACTIVER + 4, 1 << 3);
        assert_eq!(rd(&d, GICD_ISACTIVER + 4), 0);
    }

    #[test]
    fn byte_and_wide_register_access() {
        let (g, _) = gic(1);
        let d = g.distributor();
        // 64-bit writes split into two words; reads can be any width.
        d.write(GICD_IROUTER + 8 * 40, &0x0000_0000_0000_0000u64.to_le_bytes());
        let mut b = [0u8; 2];
        d.read(GICD_TYPER, &mut b);
        assert_eq!(u16::from_le_bytes(b) & 0x1f, 1);
        // Priorities: word write then byte read-modify.
        wr(&d, GICD_IPRIORITYR + 36, 0x44332211);
        d.write(GICD_IPRIORITYR + 37, &[0x99]);
        assert_eq!(rd(&d, GICD_IPRIORITYR + 36), 0x4433_9911);
        // Out-of-range and unaligned accesses are ignored.
        wr(&d, 0x7f00, 1);
        d.write(GICD_CTLR + 1, &[0xff, 0xff]);
        assert_eq!(rd(&d, GICD_CTLR) & 3, 0);
        assert_eq!(rd(&d, 0x7f00), 0);
    }
}
