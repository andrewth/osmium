use alloc::boxed::Box;
use alloc::collections::VecDeque;

use osmium_sync::IrqSpinLock;

use crate::bus::BusDevice;

const LSR_DR: u8 = 0x01;
const LSR_THRE: u8 = 0x20;
const LSR_TEMT: u8 = 0x40;
const LCR_DLAB: u8 = 0x80;

/// An emulated NS16550A UART: enough for guest consoles (Linux `8250`,
/// firmware, `osmium-drivers`' own driver). Transmitted bytes go to a
/// callback; received bytes are queued with [`Uart16550::push_input`]. With
/// [`with_irq`](Uart16550::with_irq) the receive interrupt drives a line,
/// such as a [`VirtualPlic`](super::VirtualPlic) source.
/// Register spacing is one byte.
pub struct Uart16550 {
    state: IrqSpinLock<State>,
    output: Box<dyn Fn(u8) + Send + Sync>,
    irq: Option<Box<dyn Fn(bool) + Send + Sync>>,
}

#[derive(Default)]
struct State {
    ier: u8,
    lcr: u8,
    mcr: u8,
    scr: u8,
    dll: u8,
    dlm: u8,
    input: VecDeque<u8>,
    irq_level: bool,
}

impl Uart16550 {
    /// Creates the device; `output` receives every byte the guest sends.
    pub fn new(output: impl Fn(u8) + Send + Sync + 'static) -> Self {
        Self { state: IrqSpinLock::new(State::default()), output: Box::new(output), irq: None }
    }

    /// Reports the receive interrupt's level to `irq` whenever it changes.
    pub fn with_irq(mut self, irq: impl Fn(bool) + Send + Sync + 'static) -> Self {
        self.irq = Some(Box::new(irq));
        self
    }

    fn update_irq(&self, s: &mut State) {
        let level = s.ier & 1 != 0 && !s.input.is_empty();
        if level != s.irq_level {
            s.irq_level = level;
            if let Some(irq) = &self.irq {
                irq(level);
            }
        }
    }

    /// Queues a byte for the guest to read.
    pub fn push_input(&self, byte: u8) {
        let mut s = self.state.lock();
        s.input.push_back(byte);
        self.update_irq(&mut s);
    }

    /// Returns true if the guest enabled the receive interrupt and data is
    /// waiting, i.e. the interrupt line should be asserted.
    pub fn irq_pending(&self) -> bool {
        let s = self.state.lock();
        s.ier & 1 != 0 && !s.input.is_empty()
    }
}

impl BusDevice for Uart16550 {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let mut s = self.state.lock();
        let dlab = s.lcr & LCR_DLAB != 0;
        let v = match offset {
            0 if dlab => s.dll,
            0 => s.input.pop_front().unwrap_or(0),
            1 if dlab => s.dlm,
            1 => s.ier,
            // IIR: FIFOs enabled; RX data available or no interrupt pending.
            2 => 0xc0 | if s.ier & 1 != 0 && !s.input.is_empty() { 0x04 } else { 0x01 },
            3 => s.lcr,
            4 => s.mcr,
            5 => LSR_THRE | LSR_TEMT | if s.input.is_empty() { 0 } else { LSR_DR },
            6 => 0xb0, // MSR: DCD, DSR, CTS
            7 => s.scr,
            _ => 0xff,
        };
        data.fill(0);
        data[0] = v;
        self.update_irq(&mut s);
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let v = data.first().copied().unwrap_or(0);
        let mut s = self.state.lock();
        let dlab = s.lcr & LCR_DLAB != 0;
        match offset {
            0 if dlab => s.dll = v,
            0 => {
                drop(s);
                (self.output)(v);
            }
            1 if dlab => s.dlm = v,
            1 => {
                s.ier = v & 0x0f;
                self.update_irq(&mut s);
            }
            2 => {
                if v & 0x02 != 0 {
                    s.input.clear();
                    self.update_irq(&mut s);
                }
            }
            3 => s.lcr = v,
            4 => s.mcr = v,
            7 => s.scr = v,
            _ => {}
        }
    }
}
