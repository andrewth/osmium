//! Arm PrimeCell PL011 UART.

use osmium_hal::mmio::{IoMem, IoMemError, ReadOnly, ReadWrite, RegisterBlock, WriteOnly};
use osmium_hal::serial::SerialPort;

#[repr(C)]
struct Regs {
    dr: ReadWrite<u32>,
    _rsr: ReadWrite<u32>,
    _reserved0: [ReadOnly<u32>; 4],
    fr: ReadOnly<u32>,
    _reserved1: ReadOnly<u32>,
    _ilpr: ReadWrite<u32>,
    ibrd: ReadWrite<u32>,
    fbrd: ReadWrite<u32>,
    lcr_h: ReadWrite<u32>,
    cr: ReadWrite<u32>,
    _ifls: ReadWrite<u32>,
    imsc: ReadWrite<u32>,
    _ris: ReadOnly<u32>,
    _mis: ReadOnly<u32>,
    icr: WriteOnly<u32>,
}

// SAFETY: repr(C), register cells only.
unsafe impl RegisterBlock for Regs {}

const FR_RXFE: u32 = 1 << 4;
const FR_TXFF: u32 = 1 << 5;
const FR_BUSY: u32 = 1 << 3;
const LCR_H_FEN: u32 = 1 << 4;
const LCR_H_WLEN8: u32 = 0b11 << 5;
const CR_UARTEN: u32 = 1 << 0;
const CR_TXE: u32 = 1 << 8;
const CR_RXE: u32 = 1 << 9;
const IMSC_RXIM: u32 = 1 << 4;

/// A PL011 UART.
pub struct Pl011 {
    io: IoMem,
}

impl Pl011 {
    /// Wraps the 4 KiB register window. Fails if it is too small.
    pub fn new(io: IoMem) -> Result<Self, IoMemError> {
        io.as_regs::<Regs>()?;
        Ok(Self { io })
    }

    fn regs(&self) -> &Regs {
        self.io.as_regs().expect("checked in new")
    }

    /// Programs 8N1 with FIFOs. With `Some((clock_hz, baud))` it also sets
    /// the divisor; with `None` the firmware's baud rate is kept. It is also
    /// kept if `clock / (16 * baud)` does not fit the divisor registers: a
    /// `baud` of 0, or one too high or too low for the clock.
    pub fn init(&mut self, clock_and_baud: Option<(u32, u32)>) {
        let r = self.regs();
        r.cr.write(0);
        while r.fr.read() & FR_BUSY != 0 {
            core::hint::spin_loop();
        }
        if let Some(div64) = clock_and_baud.and_then(|(clock, baud)| divisor64(clock, baud)) {
            r.ibrd.write((div64 >> 6) as u32);
            r.fbrd.write((div64 & 0x3f) as u32);
        }
        r.lcr_h.write(LCR_H_WLEN8 | LCR_H_FEN);
        r.icr.write(0x7ff);
        r.cr.write(CR_UARTEN | CR_TXE | CR_RXE);
    }

    /// Raises an interrupt when data is received.
    pub fn enable_rx_interrupt(&mut self) {
        self.regs().imsc.set_bits(IMSC_RXIM);
    }
}

/// The baud divisor in 1/64ths, `clock / (16 * baud) * 64` rounded, or
/// `None` if `baud` is 0 or the divisor is outside the hardware's range
/// (integer part 1 to 65535, with no fraction at 65535).
fn divisor64(clock: u32, baud: u32) -> Option<u64> {
    let baud = baud as u64;
    let div64 = (clock as u64 * 4 + baud / 2).checked_div(baud)?;
    (64..=0xffff << 6).contains(&div64).then_some(div64)
}

impl SerialPort for Pl011 {
    fn write_byte(&mut self, byte: u8) {
        let r = self.regs();
        while r.fr.read() & FR_TXFF != 0 {
            core::hint::spin_loop();
        }
        r.dr.write(byte as u32);
    }

    fn read_byte(&mut self) -> Option<u8> {
        let r = self.regs();
        (r.fr.read() & FR_RXFE == 0).then(|| r.dr.read() as u8)
    }
}

#[cfg(test)]
// Tests drop drivers explicitly to end their use of the fake register memory
// before inspecting it.
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;

    #[test]
    fn layout_and_io() {
        assert_eq!(core::mem::offset_of!(Regs, fr), 0x18);
        assert_eq!(core::mem::offset_of!(Regs, ibrd), 0x24);
        assert_eq!(core::mem::offset_of!(Regs, cr), 0x30);
        assert_eq!(core::mem::offset_of!(Regs, icr), 0x44);

        let mut regs = [0u32; 0x1000 / 4];
        regs[0x18 / 4] = FR_RXFE;
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x1000) };
        let mut uart = Pl011::new(io).unwrap();
        uart.init(Some((24_000_000, 115_200)));
        uart.write_byte(b'z');
        assert_eq!(uart.read_byte(), None);
        drop(uart);
        assert_eq!(regs[0], b'z' as u32);
        // 24 MHz / (16 * 115200) = 13.02 -> IBRD 13, FBRD 1.
        assert_eq!((regs[0x24 / 4], regs[0x28 / 4]), (13, 1));
        assert_eq!(regs[0x30 / 4], CR_UARTEN | CR_TXE | CR_RXE);
    }

    #[test]
    fn unrepresentable_baud_keeps_the_divisor() {
        assert_eq!(divisor64(24_000_000, 0), None);
        assert_eq!(divisor64(24_000_000, 3_000_000), None, "divisor 0.5");
        assert_eq!(divisor64(24_000_000, 1_500_000), Some(64), "divisor 1");
        assert_eq!(divisor64(u32::MAX, 1), None, "divisor above 65535");

        let mut regs = [0u32; 0x1000 / 4];
        regs[0x24 / 4] = 26;
        // SAFETY: the window covers a local array.
        let mut uart = Pl011::new(unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x1000) }).unwrap();
        uart.init(Some((24_000_000, 0)));
        drop(uart);
        assert_eq!(regs[0x24 / 4], 26, "firmware divisor kept");
        assert_eq!(regs[0x30 / 4], CR_UARTEN | CR_TXE | CR_RXE);
    }
}
