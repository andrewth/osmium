//! The HCA command register (HCR) and the big-endian contexts commands carry.
//!
//! Every structure the device reads or writes is a sequence of big-endian
//! dwords; the PRM names fields by dword index, bit offset and width, so
//! [`Ctx`] stores host-order dwords addressed the same way and converts at
//! the mailbox boundary.

use core::cell::Cell;
use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;

use super::Mlx4Error;

/// Command opcodes.
#[allow(missing_docs)]
pub mod op {
    pub const QUERY_DEV_CAP: u16 = 0x003;
    pub const QUERY_FW: u16 = 0x004;
    pub const INIT_HCA: u16 = 0x007;
    pub const CLOSE_HCA: u16 = 0x008;
    pub const INIT_PORT: u16 = 0x009;
    pub const CLOSE_PORT: u16 = 0x00a;
    pub const SET_PORT: u16 = 0x00c;
    pub const SW2HW_MPT: u16 = 0x00d;
    pub const HW2SW_MPT: u16 = 0x00f;
    pub const WRITE_MTT: u16 = 0x011;
    pub const MAP_EQ: u16 = 0x012;
    pub const SW2HW_EQ: u16 = 0x013;
    pub const HW2SW_EQ: u16 = 0x014;
    pub const SW2HW_CQ: u16 = 0x016;
    pub const HW2SW_CQ: u16 = 0x017;
    pub const RST2INIT_QP: u16 = 0x019;
    pub const INIT2RTR_QP: u16 = 0x01a;
    pub const RTR2RTS_QP: u16 = 0x01b;
    pub const RTS2RTS_QP: u16 = 0x01c;
    pub const TO_RST_QP: u16 = 0x021;
    pub const CONF_SPECIAL_QP: u16 = 0x023;
    pub const MAD_IFC: u16 = 0x024;
    pub const READ_MCG: u16 = 0x025;
    pub const WRITE_MCG: u16 = 0x026;
    pub const MGID_HASH: u16 = 0x027;
    pub const QUERY_PORT: u16 = 0x043;
    pub const SENSE_PORT: u16 = 0x04d;
    pub const RUN_FW: u16 = 0xff6;
    pub const UNMAP_ICM: u16 = 0xff9;
    pub const MAP_ICM: u16 = 0xffa;
    pub const UNMAP_ICM_AUX: u16 = 0xffb;
    pub const MAP_ICM_AUX: u16 = 0xffc;
    pub const SET_ICM_SIZE: u16 = 0xffd;
    pub const UNMAP_FA: u16 = 0xffe;
    pub const MAP_FA: u16 = 0xfff;
}

/// Offset of the HCR in BAR 0.
pub const HCR: usize = 0x80680;
const HCR_GO: u32 = 1 << 23;
const HCR_TOGGLE: u32 = 1 << 21;

/// Bytes per mailbox. Large enough for the biggest context (512 bytes) and
/// for a WRITE_MTT of [`MTTS_PER_WRITE`] entries.
pub const MAILBOX_LEN: usize = 4096;

/// How long a command may take. Linux allows its slowest class 60 s;
/// MAP_FA and INIT_HCA on a large firmware area are the slow ones.
const COMMAND_TIMEOUT_NS: u64 = 60_000_000_000;

/// A context or command parameter block: up to 512 bytes of dwords in host
/// order, addressed like the PRM (dword index, bit shift, width).
#[derive(Clone)]
pub struct Ctx {
    dw: [u32; 128],
}

impl Ctx {
    /// An all-zero context.
    pub const fn new() -> Self {
        Self { dw: [0; 128] }
    }

    /// Sets the `width`-bit field at bit `shift` of dword `dw`. A dword outside the
    /// context is ignored.
    pub fn set(&mut self, dw: usize, shift: u32, width: u32, value: u32) -> &mut Self {
        let mask = field_mask(shift, width);
        if let Some(d) = self.dw.get_mut(dw) {
            *d = (*d & !mask) | (value.checked_shl(shift).unwrap_or(0) & mask);
        }
        self
    }

    /// Reads the `width`-bit field at bit `shift` of dword `dw`; zero outside the context.
    pub fn get(&self, dw: usize, shift: u32, width: u32) -> u32 {
        let v = self.dword(dw).checked_shr(shift).unwrap_or(0);
        if width >= 32 { v } else { v & ((1 << width) - 1) }
    }

    /// Stores a 64-bit address as dword `dw` (high half) and `dw + 1` (low
    /// half), ORing the low half into whatever fields share its low bits.
    pub fn set_addr(&mut self, dw: usize, addr: u64) -> &mut Self {
        if let Some(d) = self.dw.get_mut(dw) {
            *d = (addr >> 32) as u32;
        }
        if let Some(d) = dw.checked_add(1).and_then(|i| self.dw.get_mut(i)) {
            *d |= addr as u32;
        }
        self
    }

    /// The whole dword `dw`; zero outside the context.
    pub fn dword(&self, dw: usize) -> u32 {
        self.dw.get(dw).copied().unwrap_or(0)
    }

    fn store(&self, buf: &DmaBuffer, len: usize) {
        for (i, &v) in self.dw.iter().take(len / 4).enumerate() {
            buf.store(i * 4, v.to_be());
        }
    }

    fn load(&mut self, buf: &DmaBuffer, len: usize) {
        for (i, v) in self.dw.iter_mut().take(len / 4).enumerate() {
            *v = u32::from_be(buf.load(i * 4));
        }
    }
}

/// The mask of the `width`-bit field at bit `shift`, clipped to the dword.
fn field_mask(shift: u32, width: u32) -> u32 {
    let ones = if width >= 32 { !0 } else { (1u32 << width) - 1 };
    ones.checked_shl(shift).unwrap_or(0)
}

/// What a command takes as input.
pub enum Input<'ctx> {
    /// Nothing (the input parameter is zero).
    None,
    /// A 64-bit immediate parameter.
    Imm(u64),
    /// The first `len` bytes of a context, through the input mailbox.
    Mailbox(&'ctx Ctx, usize),
    /// Mailbox contents written by a closure (for inputs larger than a
    /// [`Ctx`], such as WRITE_MTT).
    Raw(&'ctx dyn Fn(&DmaBuffer)),
}

/// The command interface: the HCR in BAR 0 and two mailboxes.
///
/// Commands run one at a time and are polled; the HCR's toggle bit tells a
/// finished command from the previous one.
pub struct Hcr<'d, D: DmaAllocator + ?Sized> {
    config: IoMem,
    clock: &'d dyn Clock,
    toggle: Cell<bool>,
    /// Set when the device may still be using driver memory (a command
    /// timed out, or teardown failed); owners then leak rather than free.
    wedged: Cell<bool>,
    // [input, output]; freed on drop unless wedged.
    mailboxes: ManuallyDrop<[OwnedDma<'d, D>; 2]>,
}

impl<'d, D: DmaAllocator + ?Sized> Hcr<'d, D> {
    /// Uses the HCR in `config` (BAR 0), with mailboxes from `dma`.
    pub fn new(config: IoMem, dma: &'d D, clock: &'d dyn Clock) -> Result<Self, Mlx4Error> {
        let mailbox = || OwnedDma::new(dma, MAILBOX_LEN).ok_or(Mlx4Error::NoMemory);
        let mailboxes = ManuallyDrop::new([mailbox()?, mailbox()?]);
        Ok(Self { config, clock, toggle: Cell::new(false), wedged: Cell::new(false), mailboxes })
    }

    /// Returns true if driver memory must be leaked rather than freed.
    pub fn is_wedged(&self) -> bool {
        self.wedged.get()
    }

    /// Records that the device may still access driver memory.
    pub fn wedge(&self) {
        self.wedged.set(true);
    }

    fn reg(&self, i: usize) -> u32 {
        u32::from_be(self.config.read(HCR + 4 * i).unwrap_or(!0))
    }

    fn set_reg(&self, i: usize, value: u32) {
        let _ = self.config.write(HCR + 4 * i, value.to_be());
    }

    /// Waits until the HCR is idle with the toggle bit we expect.
    fn wait(&self) -> Result<u32, Mlx4Error> {
        let deadline = self.clock.now_ns().saturating_add(COMMAND_TIMEOUT_NS);
        loop {
            let status = self.reg(6);
            if status & HCR_GO == 0 && (status & HCR_TOGGLE != 0) == self.toggle.get() {
                return Ok(status);
            }
            if self.clock.now_ns() > deadline {
                return Err(Mlx4Error::Timeout);
            }
            core::hint::spin_loop();
        }
    }

    /// Runs a command and returns its 64-bit immediate output parameter.
    pub fn exec(&self, opcode: u16, op_mod: u8, in_mod: u32, input: Input<'_>) -> Result<u64, Mlx4Error> {
        self.run(opcode, op_mod, in_mod, input, None)
    }

    /// Runs a command whose output is `len` bytes of mailbox, read into `out`.
    pub fn exec_out(
        &self,
        opcode: u16,
        op_mod: u8,
        in_mod: u32,
        input: Input<'_>,
        out: &mut Ctx,
        len: usize,
    ) -> Result<(), Mlx4Error> {
        self.run(opcode, op_mod, in_mod, input, Some((out, len))).map(drop)
    }

    fn run(
        &self,
        opcode: u16,
        op_mod: u8,
        in_mod: u32,
        input: Input<'_>,
        out: Option<(&mut Ctx, usize)>,
    ) -> Result<u64, Mlx4Error> {
        if self.wedged.get() {
            return Err(Mlx4Error::Timeout);
        }
        let [input_box, output_box] = &*self.mailboxes;
        self.wait().inspect_err(|_| self.wedge())?;
        let in_param = match input {
            Input::None => 0,
            Input::Imm(v) => v,
            Input::Mailbox(ctx, len) => {
                if len > 512 || !len.is_multiple_of(4) {
                    return Err(Mlx4Error::BadParameter);
                }
                ctx.store(input_box, len);
                input_box.device_addr().as_u64()
            }
            Input::Raw(fill) => {
                fill(input_box);
                input_box.device_addr().as_u64()
            }
        };
        let out_param = if out.is_some() { output_box.device_addr().as_u64() } else { 0 };
        let toggle = !self.toggle.get();
        self.toggle.set(toggle);

        self.set_reg(0, (in_param >> 32) as u32);
        self.set_reg(1, in_param as u32);
        self.set_reg(2, in_mod);
        self.set_reg(3, (out_param >> 32) as u32);
        self.set_reg(4, out_param as u32);
        self.set_reg(5, 0);
        // The mailbox and parameters must be visible before `go`.
        osmium_arch::barrier::mb();
        self.set_reg(6, HCR_GO | (toggle as u32) << 21 | (op_mod as u32 & 0xf) << 12 | opcode as u32 & 0xfff);

        let status = self.wait().inspect_err(|_| self.wedge())?;
        match status >> 24 {
            0 => {}
            status => return Err(Mlx4Error::Command { opcode, status: status as u8 }),
        }
        if let Some((ctx, len)) = out {
            osmium_arch::barrier::dma_rmb();
            ctx.load(output_box, len.min(512));
            return Ok(0);
        }
        Ok((self.reg(3) as u64) << 32 | self.reg(4) as u64)
    }
}

impl<D: DmaAllocator + ?Sized> Drop for Hcr<'_, D> {
    fn drop(&mut self) {
        // A wedged device may still write the output mailbox: leak them.
        if !self.wedged.get() {
            // SAFETY: dropped once, here, and never used again.
            unsafe { ManuallyDrop::drop(&mut self.mailboxes) }
        }
    }
}

/// MTT entries one WRITE_MTT can carry after its 16-byte header.
pub const MTTS_PER_WRITE: usize = (MAILBOX_LEN - 16) / 8;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_fields_outside_the_context_are_ignored() {
        let mut c = Ctx::new();
        c.set(128, 0, 32, 1).set(usize::MAX, 0, 32, 1).set_addr(127, !0).set_addr(usize::MAX, 1);
        c.set(0, 40, 40, 1).set(0, 0, 64, 1);
        assert_eq!((c.get(128, 0, 32), c.get(0, 33, 40), c.dword(usize::MAX)), (0, 0, 0));
        assert_eq!(c.dword(127), u32::MAX);
    }
}
