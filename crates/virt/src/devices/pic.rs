use alloc::boxed::Box;

use osmium_sync::IrqSpinLock;

use crate::bus::BusDevice;

type Output = Box<dyn Fn(bool) + Send + Sync>;

/// One 8259A.
#[derive(Default)]
struct Chip {
    irr: u8,
    isr: u8,
    imr: u8,
    level: u8,
    base: u8,
    /// Next ICW expected (0 = initialized; 2..4 = in the init sequence).
    icw: u8,
    icw4: bool,
    auto_eoi: bool,
    read_isr: bool,
}

impl Chip {
    /// Highest-priority (lowest-numbered) request that is unmasked and not
    /// blocked by an interrupt in service at equal or higher priority.
    fn pending(&self) -> Option<u8> {
        let req = self.irr & !self.imr;
        let irq = (0..8).find(|i| req & (1 << i) != 0)?;
        let blocked = (0..=irq).any(|i| self.isr & (1 << i) != 0);
        (!blocked).then_some(irq)
    }

    fn set_level(&mut self, irq: u8, high: bool) {
        let bit = 1 << irq;
        // Edge-triggered: a rising edge requests.
        if high && self.level & bit == 0 {
            self.irr |= bit;
        }
        if high {
            self.level |= bit;
        } else {
            self.level &= !bit;
            self.irr &= !bit;
        }
    }

    fn ack(&mut self, irq: u8) {
        self.irr &= !(1 << irq);
        if !self.auto_eoi {
            self.isr |= 1 << irq;
        }
    }

    fn write(&mut self, port: u64, v: u8) {
        match (port, self.icw) {
            (0, _) if v & 0x10 != 0 => {
                // ICW1: restart initialization.
                *self = Chip { icw: 2, icw4: v & 1 != 0, level: self.level, ..Chip::default() };
            }
            (0, _) if v & 0x18 == 0 => {
                // OCW2: end of interrupt (non-specific 0x20, specific 0x60 | irq).
                match v & 0xe0 {
                    0x20 => {
                        if let Some(i) = (0..8).find(|i| self.isr & (1 << i) != 0) {
                            self.isr &= !(1 << i);
                        }
                    }
                    0x60 => self.isr &= !(1 << (v & 7)),
                    _ => {}
                }
            }
            (0, _) if v & 0x18 == 0x08 => {
                // OCW3: choose IRR or ISR for reads of the command port.
                if v & 2 != 0 {
                    self.read_isr = v & 1 != 0;
                }
            }
            (1, 2) => {
                self.base = v & 0xf8;
                self.icw = 3;
            }
            (1, 3) => self.icw = if self.icw4 { 4 } else { 0 },
            (1, 4) => {
                self.auto_eoi = v & 2 != 0;
                self.icw = 0;
            }
            (1, _) => self.imr = v, // OCW1
            _ => {}
        }
    }

    fn read(&self, port: u64) -> u8 {
        match port {
            0 if self.read_isr => self.isr,
            0 => self.irr,
            _ => self.imr,
        }
    }
}

/// An emulated pair of 8259A PICs (the PC's master at 0x20 and slave at
/// 0xa0, cascaded on IRQ 2), for guests that program the legacy interrupt
/// controller. Put [`master`](Self::master) and [`slave`](Self::slave) on
/// the port bus. Inputs are edge-triggered.
///
/// The CPU side is the output line (reported through the callback) and
/// [`acknowledge`](Self::acknowledge), which a vCPU calls when it delivers
/// the interrupt, returning the vector.
pub struct VirtualPic {
    state: IrqSpinLock<[Chip; 2]>,
    output: Output,
    asserted: core::sync::atomic::AtomicBool,
}

impl VirtualPic {
    /// A PIC pair, uninitialized and fully unmasked as after reset.
    pub fn new(output: impl Fn(bool) + Send + Sync + 'static) -> Self {
        Self {
            state: IrqSpinLock::new([Chip::default(), Chip::default()]),
            output: Box::new(output),
            asserted: core::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Drives ISA IRQ `irq` (0-15).
    pub fn set_level(&self, irq: u8, high: bool) {
        let mut s = self.state.lock();
        if irq < 8 {
            s[0].set_level(irq, high);
        } else if irq < 16 {
            s[1].set_level(irq - 8, high);
        }
        self.update(&mut s);
    }

    /// The pending vector, if any, without acknowledging it.
    fn pending(s: &[Chip; 2]) -> Option<(u8, Option<u8>)> {
        let mut m = s[0].irr;
        if s[1].pending().is_some() {
            m |= 1 << 2; // the slave raises the master's IRQ 2
        }
        let master = Chip { irr: m, ..Chip { imr: s[0].imr, isr: s[0].isr, ..Chip::default() } };
        let irq = master.pending()?;
        if irq == 2 { s[1].pending().map(|j| (irq, Some(j))) } else { Some((irq, None)) }
    }

    /// Acknowledges the highest-priority pending interrupt (the INTA
    /// cycle) and returns its vector, or `None` if nothing is pending.
    pub fn acknowledge(&self) -> Option<u8> {
        let mut s = self.state.lock();
        let (irq, slave) = Self::pending(&s)?;
        s[0].ack(irq);
        let vector = match slave {
            Some(j) => {
                s[1].ack(j);
                s[1].base | j
            }
            None => s[0].base | irq,
        };
        self.update(&mut s);
        Some(vector)
    }

    /// Whether the INTR line to the CPU is up.
    pub fn asserted(&self) -> bool {
        self.asserted.load(core::sync::atomic::Ordering::Acquire)
    }

    fn update(&self, s: &mut [Chip; 2]) {
        let now = Self::pending(s).is_some();
        if self.asserted.swap(now, core::sync::atomic::Ordering::AcqRel) != now {
            (self.output)(now);
        }
    }

    /// The master's ports (0x20-0x21), for the port bus.
    pub fn master(self: &alloc::sync::Arc<Self>) -> alloc::sync::Arc<dyn BusDevice> {
        alloc::sync::Arc::new(Ports { pic: self.clone(), chip: 0 })
    }

    /// The slave's ports (0xa0-0xa1), for the port bus.
    pub fn slave(self: &alloc::sync::Arc<Self>) -> alloc::sync::Arc<dyn BusDevice> {
        alloc::sync::Arc::new(Ports { pic: self.clone(), chip: 1 })
    }
}

struct Ports {
    pic: alloc::sync::Arc<VirtualPic>,
    chip: usize,
}

impl BusDevice for Ports {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let s = self.pic.state.lock();
        data.fill(0);
        data[0] = s[self.chip].read(offset);
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let mut s = self.pic.state.lock();
        s[self.chip].write(offset, data.first().copied().unwrap_or(0));
        self.pic.update(&mut s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, Ordering};

    fn out(p: &Arc<dyn BusDevice>, port: u64, v: u8) {
        p.write(port, &[v]);
    }

    /// The usual PC setup: master at 0x20, slave at 0x28, cascade on 2.
    fn init(pic: &Arc<VirtualPic>) -> (Arc<dyn BusDevice>, Arc<dyn BusDevice>) {
        let (m, s) = (pic.master(), pic.slave());
        for (p, base, cascade) in [(&m, 0x20, 4), (&s, 0x28, 2)] {
            out(p, 0, 0x11);
            out(p, 1, base);
            out(p, 1, cascade);
            out(p, 1, 0x01);
        }
        (m, s)
    }

    #[test]
    fn vectors_masks_eoi_and_cascade() {
        let line = Arc::new(AtomicBool::new(false));
        let l = line.clone();
        let pic = Arc::new(VirtualPic::new(move |v| l.store(v, Ordering::SeqCst)));
        let (m, s) = init(&pic);
        out(&m, 1, !(1 << 4 | 1 << 2)); // only COM1 and the cascade
        out(&s, 1, 0xff);

        pic.set_level(3, true);
        assert!(!line.load(Ordering::SeqCst), "IRQ 3 is masked");
        pic.set_level(4, true);
        assert!(line.load(Ordering::SeqCst));
        assert_eq!(pic.acknowledge(), Some(0x24));
        assert!(!line.load(Ordering::SeqCst), "in service");
        let mut b = [0u8];
        out(&m, 0, 0x0b); // OCW3: read ISR
        m.read(0, &mut b);
        assert_eq!(b[0], 1 << 4);
        out(&m, 0, 0x20); // EOI
        assert_eq!(pic.acknowledge(), None, "edge already consumed");

        // A new edge after EOI fires again.
        pic.set_level(4, false);
        pic.set_level(4, true);
        assert_eq!(pic.acknowledge(), Some(0x24));
        out(&m, 0, 0x20);

        // Slave IRQ 12 through the cascade.
        out(&s, 1, !(1 << 4));
        pic.set_level(12, true);
        assert!(line.load(Ordering::SeqCst));
        assert_eq!(pic.acknowledge(), Some(0x2c));
        out(&s, 0, 0x20);
        out(&m, 0, 0x20);
        assert!(!line.load(Ordering::SeqCst));
    }
}
