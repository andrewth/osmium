use alloc::boxed::Box;
use alloc::collections::VecDeque;

use osmium_sync::IrqSpinLock;

use crate::bus::BusDevice;

/// The PL011's register window.
pub const PL011_WINDOW: u64 = 0x1000;

const DR: u64 = 0x00;
const RSR: u64 = 0x04;
const FR: u64 = 0x18;
const IBRD: u64 = 0x24;
const FBRD: u64 = 0x28;
const LCR_H: u64 = 0x2c;
const CR: u64 = 0x30;
const IFLS: u64 = 0x34;
const IMSC: u64 = 0x38;
const RIS: u64 = 0x3c;
const MIS: u64 = 0x40;
const ICR: u64 = 0x44;

const FR_RXFE: u32 = 1 << 4;
const FR_TXFE: u32 = 1 << 7;
/// Receive and receive-timeout interrupts: both follow "data waiting".
const INT_RX: u32 = 1 << 4 | 1 << 6;
/// Transmit interrupt: the (instant) transmitter is always ready.
const INT_TX: u32 = 1 << 5;

/// Peripheral and PrimeCell IDs at 0xfe0..0x1000 (a PL011 r1p5).
const ID: [u32; 8] = [0x11, 0x10, 0x34, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

#[derive(Default)]
struct State {
    ibrd: u32,
    fbrd: u32,
    lcr_h: u32,
    cr: u32,
    ifls: u32,
    imsc: u32,
    /// Transmit interrupt latched until cleared through ICR or a write to DR.
    tx_pending: bool,
    input: VecDeque<u8>,
    irq_level: bool,
}

impl State {
    fn ris(&self) -> u32 {
        (if self.input.is_empty() { 0 } else { INT_RX }) | if self.tx_pending { INT_TX } else { 0 }
    }
}

/// An emulated Arm PL011 UART, enough for guest consoles (Linux
/// `amba-pl011`, `osmium-drivers`' own driver). Transmitted bytes go to a
/// callback; received bytes are queued with [`push_input`](Self::push_input).
/// With [`with_irq`](Self::with_irq) the combined interrupt (receive,
/// receive timeout and transmit, as masked by `UARTIMSC`) drives a line, such
/// as a [`VirtualGicV2`](super::VirtualGicV2) SPI.
pub struct Pl011 {
    state: IrqSpinLock<State>,
    output: Box<dyn Fn(u8) + Send + Sync>,
    irq: Option<Box<dyn Fn(bool) + Send + Sync>>,
}

impl Pl011 {
    /// Creates the device; `output` receives every byte the guest sends.
    pub fn new(output: impl Fn(u8) + Send + Sync + 'static) -> Self {
        let state = State { cr: 0x300, ifls: 0x12, tx_pending: true, ..State::default() };
        Self { state: IrqSpinLock::new(state), output: Box::new(output), irq: None }
    }

    /// Reports the interrupt's level to `irq` whenever it changes.
    pub fn with_irq(mut self, irq: impl Fn(bool) + Send + Sync + 'static) -> Self {
        self.irq = Some(Box::new(irq));
        self
    }

    /// Queues a byte for the guest to read.
    pub fn push_input(&self, byte: u8) {
        let mut s = self.state.lock();
        s.input.push_back(byte);
        self.update_irq(&mut s);
    }

    fn update_irq(&self, s: &mut State) {
        let level = s.ris() & s.imsc != 0;
        if level != s.irq_level {
            s.irq_level = level;
            if let Some(irq) = &self.irq {
                irq(level);
            }
        }
    }
}

impl BusDevice for Pl011 {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let mut s = self.state.lock();
        let v = match offset & !3 {
            DR => s.input.pop_front().map_or(0, u32::from),
            RSR => 0,
            FR => FR_TXFE | if s.input.is_empty() { FR_RXFE } else { 0 },
            IBRD => s.ibrd,
            FBRD => s.fbrd,
            LCR_H => s.lcr_h,
            CR => s.cr,
            IFLS => s.ifls,
            IMSC => s.imsc,
            RIS => s.ris(),
            MIS => s.ris() & s.imsc,
            o @ 0xfe0..0x1000 => ID.get(((o - 0xfe0) / 4) as usize).copied().unwrap_or(0),
            _ => 0,
        };
        self.update_irq(&mut s);
        crate::bus::put_le(data, (v >> (8 * (offset & 3))) as u64);
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let v = crate::bus::get_le(data) as u32;
        let mut s = self.state.lock();
        match offset & !3 {
            DR => {
                // The byte leaves at once; the transmitter is ready again.
                (self.output)(v as u8);
                s.tx_pending = true;
            }
            IBRD => s.ibrd = v & 0xffff,
            FBRD => s.fbrd = v & 0x3f,
            LCR_H => s.lcr_h = v & 0xff,
            CR => s.cr = v & 0xffff,
            IFLS => s.ifls = v & 0x3f,
            IMSC => s.imsc = v & 0x7ff,
            ICR if v & INT_TX != 0 => s.tx_pending = false,
            _ => {}
        }
        self.update_irq(&mut s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicBool, Ordering};

    fn w(u: &Pl011, off: u64, v: u32) {
        u.write(off, &v.to_le_bytes());
    }
    fn r(u: &Pl011, off: u64) -> u32 {
        let mut b = [0; 4];
        u.read(off, &mut b);
        u32::from_le_bytes(b)
    }

    #[test]
    fn console_and_receive_interrupt() {
        let out = Arc::new(IrqSpinLock::new(Vec::new()));
        let line = Arc::new(AtomicBool::new(false));
        let (o, l) = (out.clone(), line.clone());
        let u = Pl011::new(move |b| o.lock().push(b)).with_irq(move |v| l.store(v, Ordering::SeqCst));
        assert_eq!((r(&u, 0xfe0), r(&u, 0xff0)), (0x11, 0x0d), "PL011 IDs");
        for &c in b"hi" {
            assert_eq!(r(&u, FR) & (1 << 5), 0, "never full");
            w(&u, DR, c as u32);
        }
        assert_eq!(&out.lock()[..], b"hi");
        assert_ne!(r(&u, FR) & FR_RXFE, 0);

        u.push_input(b'k');
        assert!(!line.load(Ordering::SeqCst), "masked");
        w(&u, IMSC, 1 << 4);
        assert!(line.load(Ordering::SeqCst));
        assert_eq!(r(&u, MIS), 1 << 4);
        assert_eq!(r(&u, DR), b'k' as u32);
        assert!(!line.load(Ordering::SeqCst), "drained");

        // The transmit interrupt latches until cleared.
        w(&u, IMSC, INT_TX);
        assert!(line.load(Ordering::SeqCst));
        w(&u, ICR, INT_TX);
        assert!(!line.load(Ordering::SeqCst));
        w(&u, DR, b'x' as u32);
        assert!(line.load(Ordering::SeqCst));
    }
}
