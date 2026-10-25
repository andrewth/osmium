//! NS16550A-compatible UART.

use osmium_hal::ioext::IoMemExt;
use osmium_hal::mmio::{IoMem, IoMemError};
use osmium_hal::serial::SerialPort;

const RBR_THR: u8 = 0;
const IER: u8 = 1;
const FCR: u8 = 2;
const LCR: u8 = 3;
const MCR: u8 = 4;
const LSR: u8 = 5;

const LCR_DLAB: u8 = 0x80;
const LCR_8N1: u8 = 0x03;
const LSR_DATA_READY: u8 = 0x01;
const LSR_THR_EMPTY: u8 = 0x20;

/// How the UART's registers are reached.
pub trait UartIo {
    /// Reads register `reg` (0–7).
    fn read(&self, reg: u8) -> u8;
    /// Writes register `reg` (0–7).
    fn write(&self, reg: u8, value: u8);
}

/// Highest register number.
const LAST_REG: u8 = 7;

/// Registers in memory, `1 << shift` bytes apart (the device tree's
/// `reg-shift`), accessed as bytes.
///
/// Only the low three bits of a register number are used.
pub struct Mmio {
    io: IoMem,
    shift: u8,
}

impl Mmio {
    /// Uses the registers in `io` with the given register spacing.
    ///
    /// If `io` does not hold all eight registers at that spacing, reads of
    /// the missing ones return all ones and writes are dropped; see
    /// [`Mmio::try_new`] to reject such a window.
    pub fn new(io: IoMem, shift: u8) -> Self {
        Self { io, shift }
    }

    /// Uses the registers in `io` with the given register spacing, or fails
    /// if `io` does not hold all eight registers at that spacing.
    pub fn try_new(io: IoMem, shift: u8) -> Result<Self, IoMemError> {
        let last = (LAST_REG as usize).checked_shl(shift as u32).filter(|&o| o >> shift == LAST_REG as usize);
        match last {
            Some(o) if o < io.len() => Ok(Self { io, shift }),
            _ => Err(IoMemError),
        }
    }

    fn offset(&self, reg: u8) -> usize {
        // A shift that overflows gives an offset outside the window.
        ((reg & LAST_REG) as usize).checked_shl(self.shift as u32).unwrap_or(usize::MAX)
    }
}

impl UartIo for Mmio {
    fn read(&self, reg: u8) -> u8 {
        self.io.rd(self.offset(reg))
    }
    fn write(&self, reg: u8, value: u8) {
        self.io.wr(self.offset(reg), value);
    }
}

/// Registers in x86 I/O space starting at a base port (0x3f8 for COM1).
#[cfg(target_arch = "x86_64")]
pub struct Pio {
    base: u16,
}

#[cfg(target_arch = "x86_64")]
impl Pio {
    /// Uses ports `base..base + 8`. Only the low three bits of a register
    /// number are used.
    ///
    /// # Safety
    /// The caller must own those ports.
    ///
    /// Registers past port 0xffff stay at port 0xffff.
    pub const unsafe fn new(base: u16) -> Self {
        Self { base }
    }

    fn port(&self, reg: u8) -> u16 {
        self.base.saturating_add((reg & LAST_REG) as u16)
    }
}

#[cfg(target_arch = "x86_64")]
impl UartIo for Pio {
    fn read(&self, reg: u8) -> u8 {
        // SAFETY: ownership of the ports was asserted in `new`.
        unsafe { osmium_arch::x86_64::inb(self.port(reg)) }
    }
    fn write(&self, reg: u8, value: u8) {
        // SAFETY: ownership of the ports was asserted in `new`.
        unsafe { osmium_arch::x86_64::outb(self.port(reg), value) }
    }
}

/// An NS16550A UART.
pub struct Uart16550<I: UartIo> {
    io: I,
}

impl<I: UartIo> Uart16550<I> {
    /// Wraps the registers without touching the device.
    pub const fn new(io: I) -> Self {
        Self { io }
    }

    /// Programs 8N1 framing, enables and clears the FIFOs, and sets the baud
    /// divisor (`clock / (16 * baud)`). Pass `None` to keep the firmware's
    /// baud rate. Interrupts stay disabled; see
    /// [`Uart16550::enable_rx_interrupt`].
    pub fn init(&mut self, divisor: Option<u16>) {
        self.io.write(IER, 0);
        if let Some(d) = divisor {
            self.io.write(LCR, LCR_DLAB);
            self.io.write(RBR_THR, d as u8);
            self.io.write(IER, (d >> 8) as u8);
        }
        self.io.write(LCR, LCR_8N1);
        self.io.write(FCR, 0xc7);
        // DTR, RTS and OUT2 (which gates the IRQ line on PCs).
        self.io.write(MCR, 0x0b);
    }

    /// Raises an interrupt when received data is available.
    pub fn enable_rx_interrupt(&mut self) {
        self.io.write(IER, 0x01);
    }

    /// Returns the register backend.
    pub fn io(&self) -> &I {
        &self.io
    }
}

impl<I: UartIo> SerialPort for Uart16550<I> {
    fn write_byte(&mut self, byte: u8) {
        while self.io.read(LSR) & LSR_THR_EMPTY == 0 {
            core::hint::spin_loop();
        }
        self.io.write(RBR_THR, byte);
    }

    fn read_byte(&mut self) -> Option<u8> {
        (self.io.read(LSR) & LSR_DATA_READY != 0).then(|| self.io.read(RBR_THR))
    }
}

#[cfg(test)]
// Tests drop drivers explicitly to end their use of the fake register memory
// before inspecting it.
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::vec::Vec;

    /// A fake UART that records writes and serves LSR/RBR.
    struct Fake {
        regs: RefCell<[u8; 8]>,
        log: RefCell<Vec<(u8, u8)>>,
    }

    impl UartIo for Fake {
        fn read(&self, reg: u8) -> u8 {
            self.regs.borrow()[reg as usize]
        }
        fn write(&self, reg: u8, v: u8) {
            self.log.borrow_mut().push((reg, v));
        }
    }

    #[test]
    fn init_sequence_and_io() {
        let fake = Fake { regs: RefCell::new([0; 8]), log: RefCell::new(Vec::new()) };
        fake.regs.borrow_mut()[LSR as usize] = LSR_THR_EMPTY | LSR_DATA_READY;
        fake.regs.borrow_mut()[0] = b'k';
        let mut uart = Uart16550::new(fake);
        uart.init(Some(1));
        uart.write_byte(b'x');
        assert_eq!(uart.read_byte(), Some(b'k'));
        assert_eq!(
            *uart.io().log.borrow(),
            [(IER, 0), (LCR, 0x80), (0, 1), (IER, 0), (LCR, 3), (FCR, 0xc7), (MCR, 0x0b), (0, b'x')]
        );
    }

    #[test]
    fn mmio_backend_honours_reg_shift() {
        let mut regs = [0u8; 32];
        regs[LSR as usize * 4] = LSR_THR_EMPTY;
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(regs.as_mut_ptr(), regs.len()) };
        let mut uart = Uart16550::new(Mmio::new(io, 2));
        uart.write_byte(b'A');
        assert_eq!(uart.read_byte(), None);
        drop(uart);
        assert_eq!(regs[0], b'A');
    }

    #[test]
    fn mmio_rejects_unreachable_registers() {
        let mut regs = [0u8; 32];
        let base = regs.as_mut_ptr();
        let io = |len| {
            // SAFETY: the window lies within a local array.
            unsafe { IoMem::new(base, len) }
        };
        assert!(Mmio::try_new(io(29), 2).is_ok(), "register 7 at offset 28");
        assert!(Mmio::try_new(io(28), 2).is_err());
        assert!(Mmio::try_new(io(32), 3).is_err());
        assert!(Mmio::try_new(io(32), 62).is_err(), "7 << 62 overflows");
        assert!(Mmio::try_new(io(32), 64).is_err());
        assert!(Mmio::try_new(io(32), 255).is_err());
    }
}
