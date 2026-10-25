//! Message-signalled interrupts: MSI and MSI-X.
//!
//! A function raises a message-signalled interrupt by writing
//! [`MsiMessage::data`] to [`MsiMessage::address`]. The interrupt controller
//! decides both (on x86, `osmium_sysdrv::lapic::msi_message`); this module
//! only programs them into the function.
//!
//! [`Msi`] is the MSI capability: up to 32 vectors sharing one address,
//! entirely in configuration space. [`Msix`] is the MSI-X capability, whose
//! table of per-vector entries ([`MsixTable`]) and pending-bit array
//! ([`MsixPba`]) live in the function's memory BARs; the caller maps the BAR
//! that [`Msix::table_bir`] names and passes its window.
//!
//! Everything read from the device is checked before it is used: a
//! malformed capability, or a table that does not fit its BAR, is an
//! [`MsiError`], never a panic or an access outside the window.

use super::{ConfigAccess, Function, cap, command};
use crate::mmio::IoMem;

/// What a function writes, and where, to raise one interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MsiMessage {
    /// Bus address of the write.
    pub address: u64,
    /// The value written (MSI uses only the low 16 bits).
    pub data: u32,
}

/// Why an MSI or MSI-X operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsiError {
    /// The function has no such capability.
    NotPresent,
    /// The capability is malformed: a BAR indicator above 5, a reserved
    /// vector count, or registers past the end of configuration space.
    BadCapability,
    /// The MSI-X table or pending-bit array does not fit the BAR window.
    OutOfBar,
    /// The entry or vector index is beyond the table or capability.
    BadIndex,
    /// The message does not fit the capability: a 64-bit address on a
    /// 32-bit MSI capability, MSI data above 16 bits, or base data whose
    /// low bits clash with the vector count.
    BadMessage,
    /// The capability lacks the feature: per-vector masking, or that many
    /// vectors.
    Unsupported,
}

/// MSI message control bits.
const MSI_ENABLE: u16 = 1 << 0;
const MSI_64BIT: u16 = 1 << 7;
const MSI_PER_VECTOR_MASK: u16 = 1 << 8;
/// MSI-X message control bits.
const MSIX_FUNCTION_MASK: u16 = 1 << 14;
const MSIX_ENABLE: u16 = 1 << 15;
/// Bytes per MSI-X table entry, and the entry's vector-control mask bit.
const MSIX_ENTRY: usize = 16;
const MSIX_MASKED: u32 = 1 << 0;
/// Size of the configuration space capabilities live in.
const CONFIG_HEADER: u16 = 0x100;

/// Reads the message control word of the capability at `off`.
fn control<C: ConfigAccess + ?Sized>(func: &Function<'_, C>, off: u16) -> u16 {
    func.read16(off + 2)
}

/// Writes the message control word of the capability at `off`. It shares a
/// dword with the (read-only) ID and next pointer, which are written back
/// unchanged.
fn set_control<C: ConfigAccess + ?Sized>(func: &Function<'_, C>, off: u16, value: u16) {
    func.write32(off, (value as u32) << 16 | func.read16(off) as u32);
}

/// Sets the command register's INTx Disable bit.
fn disable_intx<C: ConfigAccess + ?Sized>(func: &Function<'_, C>) {
    func.set_command(func.command() | command::INTX_DISABLE);
}

impl<C: ConfigAccess + ?Sized> Function<'_, C> {
    /// The MSI capability.
    pub fn msi(&self) -> Result<Msi, MsiError> {
        let offset = self.find_capability(cap::MSI).ok_or(MsiError::NotPresent)?;
        let msi = Msi { offset, control: control(self, offset) };
        // Multiple Message Capable: 0..=5 (1 to 32 vectors); 6 and 7 are reserved.
        if msi.control >> 1 & 7 > 5 || offset + msi.len() > CONFIG_HEADER {
            return Err(MsiError::BadCapability);
        }
        Ok(msi)
    }

    /// The MSI-X capability, with its table and pending-bit array locations.
    pub fn msix(&self) -> Result<Msix, MsiError> {
        let offset = self.find_capability(cap::MSIX).ok_or(MsiError::NotPresent)?;
        if offset + 12 > CONFIG_HEADER {
            return Err(MsiError::BadCapability);
        }
        let table = self.read32(offset + 4);
        let pba = self.read32(offset + 8);
        let (table_bir, pba_bir) = ((table & 7) as u8, (pba & 7) as u8);
        if table_bir > 5 || pba_bir > 5 {
            return Err(MsiError::BadCapability);
        }
        Ok(Msix {
            offset,
            table_size: (control(self, offset) & 0x7ff) + 1,
            table_bir,
            table_offset: table & !7,
            pba_bir,
            pba_offset: pba & !7,
        })
    }

    /// Clears the enable bit of the capability `id` (MSI or MSI-X) if the
    /// function has it: the two must not be enabled together.
    fn disable_other(&self, id: u8, enable: u16) {
        if let Some(off) = self.find_capability(id)
            && off + 4 <= CONFIG_HEADER
        {
            let c = control(self, off);
            if c & enable != 0 {
                set_control(self, off, c & !enable);
            }
        }
    }
}

/// A function's MSI capability, from [`Function::msi`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msi {
    offset: u16,
    control: u16,
}

impl Msi {
    /// Configuration-space offset of the capability.
    pub fn offset(&self) -> u16 {
        self.offset
    }

    /// True if the address may be 64 bits wide.
    pub fn is_64bit(&self) -> bool {
        self.control & MSI_64BIT != 0
    }

    /// True if each vector can be masked on its own ([`Msi::set_masked`]).
    pub fn per_vector_masking(&self) -> bool {
        self.control & MSI_PER_VECTOR_MASK != 0
    }

    /// How many vectors the function can use (1, 2, 4, ..., 32).
    pub fn max_vectors(&self) -> u8 {
        1 << (self.control >> 1 & 7)
    }

    fn data_offset(&self) -> u16 {
        self.offset + if self.is_64bit() { 0xc } else { 8 }
    }

    /// Bytes of configuration space the capability occupies.
    fn len(&self) -> u16 {
        let base = if self.is_64bit() { 0xe } else { 0xa };
        // Mask and pending dwords follow the (dword-padded) data register.
        if self.per_vector_masking() { base + 10 } else { base }
    }

    /// Programs the message the function sends. With several vectors
    /// enabled, vector `n` sends `msg.data | n`.
    pub fn program<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, msg: MsiMessage) -> Result<(), MsiError> {
        if msg.data > 0xffff || (!self.is_64bit() && msg.address >> 32 != 0) || msg.address & 3 != 0 {
            return Err(MsiError::BadMessage);
        }
        func.write32(self.offset + 4, msg.address as u32);
        if self.is_64bit() {
            func.write32(self.offset + 8, (msg.address >> 32) as u32);
        }
        func.write32(self.data_offset(), msg.data);
        Ok(())
    }

    /// Enables MSI with `vectors` vectors (a power of two up to
    /// [`Msi::max_vectors`]), turning off MSI-X and INTx. The programmed
    /// data's low bits must be clear for the vector number to go there.
    pub fn enable<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, vectors: u8) -> Result<(), MsiError> {
        if !vectors.is_power_of_two() || vectors > self.max_vectors() {
            return Err(MsiError::Unsupported);
        }
        if func.read32(self.data_offset()) & (vectors as u32 - 1) != 0 {
            return Err(MsiError::BadMessage);
        }
        func.disable_other(cap::MSIX, MSIX_ENABLE);
        // Multiple Message Enable is log2 of the count, in bits 6:4.
        let mme = (vectors.trailing_zeros() as u16) << 4;
        let c = control(func, self.offset) & !(7 << 4);
        set_control(func, self.offset, c | mme | MSI_ENABLE);
        disable_intx(func);
        Ok(())
    }

    /// Disables MSI. INTx stays disabled.
    pub fn disable<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>) {
        set_control(func, self.offset, control(func, self.offset) & !MSI_ENABLE);
    }

    fn vector_bit(&self, vector: u8) -> Result<u32, MsiError> {
        if !self.per_vector_masking() {
            return Err(MsiError::Unsupported);
        }
        if vector >= self.max_vectors() {
            return Err(MsiError::BadIndex);
        }
        Ok(1 << vector)
    }

    /// Masks or unmasks `vector`. Needs [`Msi::per_vector_masking`].
    pub fn set_masked<C: ConfigAccess + ?Sized>(
        &self,
        func: &Function<'_, C>,
        vector: u8,
        masked: bool,
    ) -> Result<(), MsiError> {
        let bit = self.vector_bit(vector)?;
        let off = self.data_offset() + 4;
        let mask = func.read32(off);
        func.write32(off, if masked { mask | bit } else { mask & !bit });
        Ok(())
    }

    /// True if masked `vector` has an interrupt waiting. Needs
    /// [`Msi::per_vector_masking`].
    pub fn is_pending<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, vector: u8) -> Result<bool, MsiError> {
        let bit = self.vector_bit(vector)?;
        Ok(func.read32(self.data_offset() + 8) & bit != 0)
    }
}

/// A function's MSI-X capability, from [`Function::msix`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msix {
    offset: u16,
    table_size: u16,
    table_bir: u8,
    table_offset: u32,
    pba_bir: u8,
    pba_offset: u32,
}

impl Msix {
    /// Configuration-space offset of the capability.
    pub fn offset(&self) -> u16 {
        self.offset
    }

    /// Number of table entries (1–2048).
    pub fn table_size(&self) -> u16 {
        self.table_size
    }

    /// Index (0–5) of the BAR holding the table.
    pub fn table_bir(&self) -> u8 {
        self.table_bir
    }

    /// Offset of the table in its BAR.
    pub fn table_offset(&self) -> u32 {
        self.table_offset
    }

    /// Index (0–5) of the BAR holding the pending-bit array.
    pub fn pba_bir(&self) -> u8 {
        self.pba_bir
    }

    /// Offset of the pending-bit array in its BAR.
    pub fn pba_offset(&self) -> u32 {
        self.pba_offset
    }

    /// The table, inside `bar`: the window of the whole BAR that
    /// [`Msix::table_bir`] names, mapped as device memory.
    pub fn table(&self, bar: &IoMem) -> Result<MsixTable, MsiError> {
        let len = self.table_size as usize * MSIX_ENTRY;
        let io = bar.slice(self.table_offset as usize, len).map_err(|_| MsiError::OutOfBar)?;
        Ok(MsixTable { io, len: self.table_size })
    }

    /// The pending-bit array, inside `bar`: the window of the whole BAR that
    /// [`Msix::pba_bir`] names.
    pub fn pba(&self, bar: &IoMem) -> Result<MsixPba, MsiError> {
        // One bit per entry, in whole qwords.
        let len = (self.table_size as usize).div_ceil(64) * 8;
        let io = bar.slice(self.pba_offset as usize, len).map_err(|_| MsiError::OutOfBar)?;
        Ok(MsixPba { io, len: self.table_size })
    }

    /// Enables MSI-X, turning off MSI and INTx. Entries still masked (in
    /// the table, or all of them by [`Msix::set_function_mask`]) do not
    /// fire; their interrupts wait in the pending-bit array.
    pub fn enable<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>) {
        func.disable_other(cap::MSI, MSI_ENABLE);
        set_control(func, self.offset, control(func, self.offset) | MSIX_ENABLE);
        disable_intx(func);
    }

    /// Disables MSI-X. INTx stays disabled.
    pub fn disable<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>) {
        set_control(func, self.offset, control(func, self.offset) & !MSIX_ENABLE);
    }

    /// Masks or unmasks every entry at once, whatever its own mask bit.
    pub fn set_function_mask<C: ConfigAccess + ?Sized>(&self, func: &Function<'_, C>, masked: bool) {
        let c = control(func, self.offset);
        set_control(func, self.offset, if masked { c | MSIX_FUNCTION_MASK } else { c & !MSIX_FUNCTION_MASK });
    }
}

/// An MSI-X table, from [`Msix::table`].
#[derive(Clone, Debug)]
pub struct MsixTable {
    io: IoMem,
    len: u16,
}

impl MsixTable {
    /// Number of entries.
    pub fn len(&self) -> u16 {
        self.len
    }

    /// Always false: a table has at least one entry.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Byte offset of `index`'s entry.
    fn entry(&self, index: u16) -> Result<usize, MsiError> {
        if index >= self.len {
            return Err(MsiError::BadIndex);
        }
        Ok(index as usize * MSIX_ENTRY)
    }

    fn read(&self, off: usize) -> Result<u32, MsiError> {
        self.io.read(off).map_err(|_| MsiError::OutOfBar)
    }

    fn write(&self, off: usize, value: u32) -> Result<(), MsiError> {
        self.io.write(off, value).map_err(|_| MsiError::OutOfBar)
    }

    /// Programs entry `index`'s message. The entry is masked while its
    /// address and data change, so the function never sends half of each;
    /// its mask bit is then restored.
    pub fn set_message(&self, index: u16, msg: MsiMessage) -> Result<(), MsiError> {
        let e = self.entry(index)?;
        if msg.address & 3 != 0 {
            return Err(MsiError::BadMessage);
        }
        let ctrl = self.read(e + 12)?;
        self.write(e + 12, ctrl | MSIX_MASKED)?;
        self.write(e, msg.address as u32)?;
        self.write(e + 4, (msg.address >> 32) as u32)?;
        self.write(e + 8, msg.data)?;
        self.write(e + 12, ctrl)
    }

    /// Entry `index`'s message.
    pub fn message(&self, index: u16) -> Result<MsiMessage, MsiError> {
        let e = self.entry(index)?;
        let address = self.read(e)? as u64 | (self.read(e + 4)? as u64) << 32;
        Ok(MsiMessage { address, data: self.read(e + 8)? })
    }

    /// Masks or unmasks entry `index`. Unmasking an entry whose interrupt
    /// is pending sends it.
    pub fn set_masked(&self, index: u16, masked: bool) -> Result<(), MsiError> {
        let e = self.entry(index)?;
        let ctrl = self.read(e + 12)?;
        self.write(e + 12, if masked { ctrl | MSIX_MASKED } else { ctrl & !MSIX_MASKED })
    }

    /// True if entry `index` is masked.
    pub fn is_masked(&self, index: u16) -> Result<bool, MsiError> {
        let e = self.entry(index)?;
        Ok(self.read(e + 12)? & MSIX_MASKED != 0)
    }
}

/// An MSI-X pending-bit array, from [`Msix::pba`].
#[derive(Clone, Debug)]
pub struct MsixPba {
    io: IoMem,
    len: u16,
}

impl MsixPba {
    /// True if masked entry `index` has an interrupt waiting.
    pub fn is_pending(&self, index: u16) -> Result<bool, MsiError> {
        if index >= self.len {
            return Err(MsiError::BadIndex);
        }
        let word: u32 = self.io.read(index as usize / 32 * 4).map_err(|_| MsiError::OutOfBar)?;
        Ok(word >> (index % 32) & 1 != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::FakeConfig;
    use super::super::{Address, reg};
    use super::*;
    use std::vec::Vec;

    const A: Address = Address::new(0, 4, 0);

    /// A function with a capability list holding MSI at 0x50 (control
    /// `msi`) and MSI-X at 0x60 (control `msix`, table and PBA dwords).
    fn function(msi: u16, msix: Option<(u16, u32, u32)>) -> FakeConfig {
        let cfg = FakeConfig::default();
        cfg.set(A, reg::VENDOR_DEVICE, 0x0010_1b36);
        cfg.set(A, reg::COMMAND_STATUS, 1 << 20 | command::MEMORY_SPACE as u32);
        cfg.set(A, reg::HEADER_TYPE, 0);
        cfg.set(A, reg::CAPABILITIES, 0x50);
        let next = if msix.is_some() { 0x60 } else { 0 };
        cfg.set(A, 0x50, (msi as u32) << 16 | next << 8 | cap::MSI as u32);
        for off in (0x54..0x68).step_by(4) {
            cfg.set(A, off, 0);
        }
        if let Some((control, table, pba)) = msix {
            cfg.set(A, 0x60, (control as u32) << 16 | cap::MSIX as u32);
            cfg.set(A, 0x64, table);
            cfg.set(A, 0x68, pba);
        }
        cfg
    }

    /// A zeroed fake BAR of `len` bytes, and its window.
    fn bar(len: usize) -> (Vec<u32>, IoMem) {
        let mut mem = std::vec![0u32; len / 4];
        // SAFETY: the window covers a local buffer that outlives its use.
        let io = unsafe { IoMem::new(mem.as_mut_ptr().cast(), len) };
        (mem, io)
    }

    #[test]
    fn msi_64bit_with_masking() {
        // 64-bit, per-vector masking, 4 vectors (MMC = 2).
        let cfg = function(MSI_64BIT | MSI_PER_VECTOR_MASK | 2 << 1, None);
        let f = Function::new(&cfg, A).unwrap();
        let msi = f.msi().unwrap();
        assert_eq!(f.msix(), Err(MsiError::NotPresent));
        assert!(msi.is_64bit() && msi.per_vector_masking());
        assert_eq!((msi.offset(), msi.max_vectors()), (0x50, 4));

        let msg = MsiMessage { address: 0x1_fee0_1000, data: 0x40 };
        msi.program(&f, msg).unwrap();
        assert_eq!((cfg.read32(A, 0x54), cfg.read32(A, 0x58), cfg.read32(A, 0x5c)), (0xfee0_1000, 1, 0x40));
        assert_eq!(msi.program(&f, MsiMessage { data: 0x1_0000, ..msg }), Err(MsiError::BadMessage));

        assert_eq!(msi.enable(&f, 3), Err(MsiError::Unsupported));
        assert_eq!(msi.enable(&f, 8), Err(MsiError::Unsupported));
        msi.enable(&f, 4).unwrap();
        let control = cfg.read32(A, 0x50) >> 16;
        assert_eq!(control & 0x71, 2 << 4 | 1, "four vectors, enabled");
        assert_eq!(cfg.read32(A, 0x50) & 0xffff, cap::MSI as u32, "ID and next pointer kept");
        assert_ne!(f.command() & command::INTX_DISABLE, 0);
        assert_ne!(f.command() & command::MEMORY_SPACE, 0);

        msi.set_masked(&f, 3, true).unwrap();
        msi.set_masked(&f, 1, true).unwrap();
        msi.set_masked(&f, 3, false).unwrap();
        assert_eq!(cfg.read32(A, 0x60), 0b10, "mask register");
        assert_eq!(msi.set_masked(&f, 4, true), Err(MsiError::BadIndex));
        cfg.set(A, 0x64, 0b10);
        assert_eq!(msi.is_pending(&f, 1), Ok(true));

        msi.disable(&f);
        assert_eq!(cfg.read32(A, 0x50) >> 16 & 1, 0);
    }

    #[test]
    fn msi_32bit() {
        let cfg = function(0, None);
        let f = Function::new(&cfg, A).unwrap();
        let msi = f.msi().unwrap();
        assert_eq!(msi.max_vectors(), 1);
        let msg = MsiMessage { address: 0x1_fee0_0000, data: 0x41 };
        assert_eq!(msi.program(&f, msg), Err(MsiError::BadMessage), "address too wide");
        msi.program(&f, MsiMessage { address: 0xfee0_0000, ..msg }).unwrap();
        assert_eq!((cfg.read32(A, 0x54), cfg.read32(A, 0x58)), (0xfee0_0000, 0x41), "data at +8");
        assert_eq!(msi.set_masked(&f, 0, true), Err(MsiError::Unsupported));
        msi.enable(&f, 1).unwrap();
        assert_eq!(cfg.read32(A, 0x50) >> 16, MSI_ENABLE as u32);

        // Reserved vector counts are rejected.
        let cfg = function(7 << 1, None);
        assert_eq!(Function::new(&cfg, A).unwrap().msi(), Err(MsiError::BadCapability));
    }

    #[test]
    fn msix_table_and_enable() {
        // Four entries: table in BAR 2 at 0x2000, PBA in BAR 2 at 0x3000.
        let cfg = function(MSI_ENABLE, Some((3, 0x2000 | 2, 0x3000 | 2)));
        let f = Function::new(&cfg, A).unwrap();
        let msix = f.msix().unwrap();
        assert_eq!((msix.table_size(), msix.table_bir(), msix.table_offset()), (4, 2, 0x2000));
        assert_eq!((msix.pba_bir(), msix.pba_offset()), (2, 0x3000));

        let (_mem, io) = bar(0x4000);
        // Entries come out of reset masked.
        for i in 0..4 {
            io.write(0x2000 + i * 16 + 12, 1u32).unwrap();
        }
        let table = msix.table(&io).unwrap();
        assert_eq!(table.len(), 4);
        let msg = MsiMessage { address: 0x1_fee0_3000, data: 0x51 };
        table.set_message(2, msg).unwrap();
        assert_eq!(table.message(2), Ok(msg));
        assert_eq!(table.is_masked(2), Ok(true), "mask bit restored");
        table.set_masked(2, false).unwrap();
        assert_eq!(table.is_masked(2), Ok(false));
        assert_eq!(table.set_message(4, msg), Err(MsiError::BadIndex));
        assert_eq!(table.set_masked(4, false), Err(MsiError::BadIndex));

        msix.set_function_mask(&f, true);
        msix.enable(&f);
        assert_eq!(cfg.read32(A, 0x60) >> 16, (MSIX_ENABLE | MSIX_FUNCTION_MASK | 3) as u32);
        assert_eq!(cfg.read32(A, 0x50) >> 16 & 1, 0, "MSI turned off");
        assert_ne!(f.command() & command::INTX_DISABLE, 0);
        msix.set_function_mask(&f, false);
        assert_eq!(cfg.read32(A, 0x60) >> 16, (MSIX_ENABLE | 3) as u32);

        let pba = msix.pba(&io).unwrap();
        assert_eq!(pba.is_pending(2), Ok(false));
        io.write(0x3000, 1u32 << 2).unwrap();
        assert_eq!(pba.is_pending(2), Ok(true));
        assert_eq!(pba.is_pending(4), Err(MsiError::BadIndex));

        msix.disable(&f);
        assert_eq!(cfg.read32(A, 0x60) >> 16 & MSIX_ENABLE as u32, 0);
    }

    #[test]
    fn msix_untrusted_layout() {
        // BAR indicators 6 and 7 are reserved.
        let cfg = function(0, Some((0, 6, 0)));
        assert_eq!(Function::new(&cfg, A).unwrap().msix(), Err(MsiError::BadCapability));
        let cfg = function(0, Some((0, 0, 7)));
        assert_eq!(Function::new(&cfg, A).unwrap().msix(), Err(MsiError::BadCapability));

        let (_mem, io) = bar(0x1000);
        // 2048 entries (32 KiB) cannot fit a 4 KiB BAR.
        let cfg = function(0, Some((0x7ff, 0, 0x800)));
        let msix = Function::new(&cfg, A).unwrap().msix().unwrap();
        assert_eq!(msix.table_size(), 2048);
        assert_eq!(msix.table(&io).unwrap_err(), MsiError::OutOfBar);
        // A table that starts inside the BAR but runs past its end.
        let cfg = function(0, Some((1, 0xff8, 0x1000)));
        let msix = Function::new(&cfg, A).unwrap().msix().unwrap();
        assert_eq!(msix.table(&io).unwrap_err(), MsiError::OutOfBar);
        assert_eq!(msix.pba(&io).unwrap_err(), MsiError::OutOfBar);
        // An offset near the top of the address space does not wrap.
        let cfg = function(0, Some((0x7ff, 0xffff_fff8, 0xffff_fff8)));
        let msix = Function::new(&cfg, A).unwrap().msix().unwrap();
        assert_eq!(msix.table(&io).unwrap_err(), MsiError::OutOfBar);
        assert_eq!(msix.pba(&io).unwrap_err(), MsiError::OutOfBar);
    }
}
