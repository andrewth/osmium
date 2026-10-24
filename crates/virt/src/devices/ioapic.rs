use alloc::boxed::Box;

use osmium_sync::IrqSpinLock;

use crate::bus::BusDevice;

/// The I/O APIC's register window (IOREGSEL at 0, IOWIN at 0x10), at
/// guest-physical `0xfec0_0000` on a PC.
pub const IOAPIC_WINDOW: u64 = 0x20;

const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;

const MASKED: u64 = 1 << 16;
const LEVEL: u64 = 1 << 15;
const REMOTE_IRR: u64 = 1 << 14;
const DELIVERY_STATUS: u64 = 1 << 12;

/// An interrupt the I/O APIC sends: the destination field (bits 63:56 of
/// the redirection entry), whether it is logical, the delivery mode and
/// the vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApicMessage {
    /// APIC ID (physical mode) or logical destination.
    pub dest: u8,
    /// Logical destination mode.
    pub logical: bool,
    /// Delivery mode (0 fixed, 1 lowest priority, 2 SMI, 4 NMI, 5 INIT, 7 ExtINT).
    pub mode: u8,
    /// Vector.
    pub vector: u8,
}

struct State {
    select: u8,
    id: u8,
    redir: [u64; 24],
    level: u32,
}

/// An emulated 82093AA-style I/O APIC with 24 inputs, for guests that
/// route device interrupts through it to their local APICs. Put it on the
/// MMIO bus at `0xfec0_0000` ([`IOAPIC_WINDOW`] bytes); drive inputs with
/// [`set_level`](Self::set_level); messages go to the callback, which
/// hands them to the target [`VirtualLapic`](super::VirtualLapic) (e.g.
/// with `deliver`).
///
/// Edge-triggered inputs send a message on each rising edge. Level-triggered
/// inputs send one while high and set the entry's remote IRR until the
/// local APIC's EOI for that vector reaches [`eoi`](Self::eoi); an input
/// still high then sends again. Masked inputs send nothing and are
/// re-evaluated when unmasked.
pub struct VirtualIoApic {
    state: IrqSpinLock<State>,
    send: Box<dyn Fn(IoApicMessage) + Send + Sync>,
}

impl VirtualIoApic {
    /// An I/O APIC with ID `id`, every entry masked, sending through `send`.
    pub fn new(id: u8, send: impl Fn(IoApicMessage) + Send + Sync + 'static) -> Self {
        Self { state: IrqSpinLock::new(State { select: 0, id, redir: [MASKED; 24], level: 0 }), send: Box::new(send) }
    }

    /// Drives input `gsi` (0-23).
    pub fn set_level(&self, gsi: u32, high: bool) {
        if gsi >= 24 {
            return;
        }
        let mut s = self.state.lock();
        let bit = 1 << gsi;
        let rising = high && s.level & bit == 0;
        if high {
            s.level |= bit;
        } else {
            s.level &= !bit;
        }
        let e = s.redir.get(gsi as usize).copied().unwrap_or(MASKED);
        let msg = if e & LEVEL != 0 { high } else { rising };
        let msg = msg.then(|| Self::fire(&mut s, gsi as usize)).flatten();
        drop(s);
        if let Some(m) = msg {
            (self.send)(m);
        }
    }

    /// The local APIC's EOI for `vector`: clears remote IRR on the
    /// level-triggered entries using it, and resends for inputs still high.
    pub fn eoi(&self, vector: u8) {
        let mut s = self.state.lock();
        let mut out = alloc::vec::Vec::new();
        for i in 0..24 {
            let Some(slot) = s.redir.get_mut(i) else { continue };
            let e = *slot;
            if e & LEVEL != 0 && e & REMOTE_IRR != 0 && e as u8 == vector {
                *slot &= !REMOTE_IRR;
                if s.level & (1 << i) != 0
                    && let Some(m) = Self::fire(&mut s, i)
                {
                    out.push(m);
                }
            }
        }
        drop(s);
        for m in out {
            (self.send)(m);
        }
    }

    /// The message for entry `i`, if it may send now; marks remote IRR for
    /// level-triggered entries.
    fn fire(s: &mut State, i: usize) -> Option<IoApicMessage> {
        let slot = s.redir.get_mut(i)?;
        let e = *slot;
        if e & MASKED != 0 || (e & LEVEL != 0 && e & REMOTE_IRR != 0) {
            return None;
        }
        if e & LEVEL != 0 {
            *slot |= REMOTE_IRR;
        }
        Some(IoApicMessage {
            dest: (e >> 56) as u8,
            logical: e & (1 << 11) != 0,
            mode: ((e >> 8) & 7) as u8,
            vector: e as u8,
        })
    }

    fn read_reg(s: &State) -> u32 {
        match s.select {
            0x00 => (s.id as u32 & 0xf) << 24,
            0x01 => 23 << 16 | 0x11, // 24 entries, version 0x11
            0x02 => (s.id as u32 & 0xf) << 24,
            r @ 0x10..=0x3f => {
                let e = s.redir.get(((r - 0x10) / 2) as usize).copied().unwrap_or(0);
                if r & 1 == 0 { e as u32 } else { (e >> 32) as u32 }
            }
            _ => 0,
        }
    }
}

impl BusDevice for VirtualIoApic {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let s = self.state.lock();
        let v = match offset & !3 {
            IOREGSEL => s.select as u32,
            IOWIN => Self::read_reg(&s),
            _ => 0,
        };
        let bytes = v.to_le_bytes();
        crate::bus::put_le(data, u32::from_le_bytes(bytes) as u64);
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let v = crate::bus::get_le(data) as u32;
        let mut s = self.state.lock();
        let mut msg = None;
        match offset & !3 {
            IOREGSEL => s.select = v as u8,
            IOWIN => match s.select {
                0x00 => s.id = (v >> 24) as u8 & 0xf,
                r @ 0x10..=0x3f => {
                    let i = ((r - 0x10) / 2) as usize;
                    let Some(&old) = s.redir.get(i) else { return };
                    // Remote IRR and delivery status are read-only.
                    let ro = REMOTE_IRR | DELIVERY_STATUS;
                    let new = if r & 1 == 0 {
                        (old & !0xffff_ffff) | (v as u64 & !ro) | (old & ro)
                    } else {
                        (old & 0xffff_ffff) | (v as u64) << 32
                    };
                    if let Some(slot) = s.redir.get_mut(i) {
                        *slot = new;
                    }
                    // Unmasking a level-triggered input that is high sends.
                    if old & MASKED != 0 && new & MASKED == 0 && new & LEVEL != 0 && s.level & (1 << i) != 0 {
                        msg = Self::fire(&mut s, i);
                    }
                }
                _ => {}
            },
            _ => {}
        }
        drop(s);
        if let Some(m) = msg {
            (self.send)(m);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    fn rig() -> (VirtualIoApic, Arc<IrqSpinLock<Vec<IoApicMessage>>>) {
        let sent = Arc::new(IrqSpinLock::new(Vec::new()));
        let s = sent.clone();
        (VirtualIoApic::new(0, move |m| s.lock().push(m)), sent)
    }

    fn reg(io: &VirtualIoApic, r: u8, v: u32) {
        io.write(IOREGSEL, &[r]);
        io.write(IOWIN, &v.to_le_bytes());
    }

    fn get(io: &VirtualIoApic, r: u8) -> u32 {
        io.write(IOREGSEL, &[r]);
        let mut b = [0; 4];
        io.read(IOWIN, &mut b);
        u32::from_le_bytes(b)
    }

    #[test]
    fn version_and_edge() {
        let (io, sent) = rig();
        assert_eq!(get(&io, 1), 0x0017_0011);
        io.set_level(4, true);
        assert!(sent.lock().is_empty(), "masked after reset");
        io.set_level(4, false);
        reg(&io, 0x10 + 2 * 4 + 1, 1 << 24); // destination APIC 1
        reg(&io, 0x10 + 2 * 4, 0x24); // edge, fixed, vector 0x24, unmasked
        io.set_level(4, true);
        io.set_level(4, true); // no new edge
        assert_eq!(*sent.lock(), [IoApicMessage { dest: 1, logical: false, mode: 0, vector: 0x24 }]);
    }

    #[test]
    fn level_remote_irr_and_eoi() {
        let (io, sent) = rig();
        reg(&io, 0x10 + 2 * 10, (LEVEL | MASKED) as u32 | 0x3a);
        io.set_level(10, true);
        assert!(sent.lock().is_empty());
        reg(&io, 0x10 + 2 * 10, LEVEL as u32 | 0x3a); // unmask while high: sends
        assert_eq!(sent.lock().len(), 1);
        assert_ne!(get(&io, 0x10 + 2 * 10) & REMOTE_IRR as u32, 0);
        io.set_level(10, true);
        assert_eq!(sent.lock().len(), 1, "remote IRR holds it");
        io.eoi(0x3a);
        assert_eq!(sent.lock().len(), 2, "still high after EOI: again");
        io.set_level(10, false);
        io.eoi(0x3a);
        assert_eq!(sent.lock().len(), 2);
        assert_eq!(get(&io, 0x10 + 2 * 10) & REMOTE_IRR as u32, 0);
    }
}
