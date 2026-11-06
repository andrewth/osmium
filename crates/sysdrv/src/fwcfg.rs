// SPDX-License-Identifier: GPL-2.0-only
//! QEMU `fw_cfg`: named blobs the hypervisor hands to the guest firmware
//! (ACPI tables, `-kernel`/`-initrd`/`-append`, the `ramfb` configuration,
//! SMBIOS, boot order, ...).
//!
//! The device is reached through a selector register and a data register
//! (I/O ports 0x510/0x511 on x86, an MMIO window on Arm and RISC-V), plus an
//! optional DMA doorbell. A platform supplies those through [`FwCfgIo`];
//! [`FwCfg`] does the rest.
//!
//! [`FwCfg::new`] uses the data register only: reads work, writes do not.
//! [`FwCfg::with_dma`] also takes a [`DmaAllocator`], from which it allocates
//! one buffer holding the DMA control block and a bounce area. Every DMA
//! transfer goes through that buffer, so caller memory is never handed to the
//! device and device addresses come from the allocator. A transfer the device
//! does not finish within [`SPIN_LIMIT`] polls fails with
//! [`FwCfgError::Timeout`]; the device may still write the buffer later, so
//! it is leaked rather than freed and DMA is switched off (reads fall back to
//! the data register).
//!
//! ```ignore
//! let mut cfg = FwCfg::with_dma(MyIo, &dma)?;
//! assert!(cfg.detect());
//! let kernel = cfg.find("opt/kernel").unwrap();
//! cfg.read(kernel.select, 0, &mut buf)?;
//! ```

use core::mem::ManuallyDrop;

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};

/// Most directory entries walked, whatever count the device reports.
const MAX_FILES: u32 = 4096;
const SEL_SIGNATURE: u16 = 0x0000;
const SEL_ID: u16 = 0x0001;
const SEL_FILE_DIR: u16 = 0x0019;

const ID_DMA: u32 = 2;

const DMA_ERROR: u32 = 1;
const DMA_READ: u32 = 2;
const DMA_SKIP: u32 = 4;
const DMA_SELECT: u32 = 8;
const DMA_WRITE: u32 = 16;

/// Polls of the DMA control word before a transfer is given up. QEMU
/// finishes a transfer before the doorbell write returns.
pub const SPIN_LIMIT: u32 = 10_000_000;

/// Size of the DMA buffer: the control block, then the bounce area.
const DMA_BUF_BYTES: usize = 16384;
/// Offset of the bounce area (the control block needs 16 bytes, 16-aligned).
const BOUNCE: usize = 64;
/// Largest transfer through the bounce area.
const CHUNK: usize = DMA_BUF_BYTES - BOUNCE;

/// Size of a file directory entry: size, selector, reserved, 56-byte name.
const DIR_ENTRY: usize = 64;
const NAME_LEN: usize = 56;

/// How the platform reaches the `fw_cfg` registers.
pub trait FwCfgIo {
    /// Writes the selector register (host byte order).
    fn select(&mut self, selector: u16);
    /// Reads the next byte of the selected item.
    fn read8(&mut self) -> u8;
    /// Whether the platform can ring the DMA doorbell ([`FwCfgIo::start_dma`]).
    fn has_dma_doorbell(&self) -> bool {
        false
    }
    /// Starts a DMA transfer described by the control block at device address
    /// `addr`, or returns `false` if the platform has no DMA doorbell.
    fn start_dma(&mut self, addr: u64) -> bool;
}

/// Why a `fw_cfg` transfer failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FwCfgError {
    /// The operation needs DMA (writes do), and it is not in use.
    NoDma,
    /// The DMA buffer could not be allocated.
    NoMemory,
    /// The device set the error bit in the control block.
    Device,
    /// The device did not finish a DMA transfer within [`SPIN_LIMIT`] polls.
    /// DMA is off from then on.
    Timeout,
    /// The offset or length does not fit the device's 32-bit fields.
    TooLarge,
}

/// A [`DmaAllocator`] with no memory: the allocator type of a [`FwCfg`]
/// made by [`FwCfg::new`].
#[derive(Debug)]
pub enum NoDma {}

impl DmaAllocator for NoDma {
    fn alloc_coherent(&self, _: usize) -> Option<DmaBuffer> {
        match *self {}
    }

    unsafe fn free_coherent(&self, _: DmaBuffer) {
        match *self {}
    }
}

/// A file in the `fw_cfg` directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct File {
    /// The selector to read or write it with.
    pub select: u16,
    /// Its size in bytes.
    pub size: u32,
}

/// A `fw_cfg` device.
pub struct FwCfg<'d, I: FwCfgIo, D: DmaAllocator + ?Sized = NoDma> {
    io: I,
    /// Control block and bounce area, if DMA is possible. `ManuallyDrop` so
    /// that a buffer the device may still write can be leaked.
    dma: Option<ManuallyDrop<OwnedDma<'d, D>>>,
    have_dma: bool,
}

impl<I: FwCfgIo> FwCfg<'static, I, NoDma> {
    /// Wraps the registers without touching the device and without DMA;
    /// call [`FwCfg::detect`] to check that it is there.
    pub const fn new(io: I) -> Self {
        Self { io, dma: None, have_dma: false }
    }
}

impl<'d, I: FwCfgIo, D: DmaAllocator + ?Sized> FwCfg<'d, I, D> {
    /// Wraps the registers and allocates the DMA buffer from `dma`, without
    /// touching the device. DMA is used once [`FwCfg::detect`] finds that
    /// the device and the platform's doorbell support it.
    pub fn with_dma(io: I, dma: &'d D) -> Result<Self, FwCfgError> {
        let buf = OwnedDma::new(dma, DMA_BUF_BYTES).ok_or(FwCfgError::NoMemory)?;
        if buf.len() < DMA_BUF_BYTES || !buf.device_addr().is_aligned(16) {
            return Err(FwCfgError::NoMemory);
        }
        Ok(Self { io, dma: Some(ManuallyDrop::new(buf)), have_dma: false })
    }

    /// Returns the register backend.
    pub fn io(&mut self) -> &mut I {
        &mut self.io
    }

    /// Whether the device answers with the "QEMU" signature. Also learns
    /// whether it supports DMA.
    pub fn detect(&mut self) -> bool {
        self.io.select(SEL_SIGNATURE);
        let sig = [self.io.read8(), self.io.read8(), self.io.read8(), self.io.read8()];
        if &sig != b"QEMU" {
            return false;
        }
        self.io.select(SEL_ID);
        let mut id = 0u32;
        for i in 0..4 {
            id |= (self.io.read8() as u32) << (8 * i);
        }
        self.have_dma = id & ID_DMA != 0 && self.io.has_dma_doorbell() && self.dma.is_some();
        true
    }

    /// Whether DMA transfers are in use (reads are faster; writes need it).
    pub fn has_dma(&self) -> bool {
        self.have_dma
    }

    /// The DMA buffer, while DMA is in use.
    fn buffer(&self) -> Result<&DmaBuffer, FwCfgError> {
        match &self.dma {
            Some(buf) if self.have_dma => Ok(buf),
            _ => Err(FwCfgError::NoDma),
        }
    }

    /// Runs one DMA transfer of `len` bytes between the device and the
    /// bounce area (or a select/skip, which moves no data).
    fn dma(&mut self, control: u32, len: u32) -> Result<(), FwCfgError> {
        let buf = self.buffer()?;
        let moves_data = control & (DMA_READ | DMA_WRITE) != 0;
        let data = if moves_data { buf.device_addr().as_u64() + BOUNCE as u64 } else { 0 };
        let block = buf.device_addr().as_u64();
        // The device reads and writes the block in big-endian.
        buf.store::<u32>(4, len.to_be());
        buf.store::<u64>(8, data.to_be());
        buf.store::<u32>(0, control.to_be());
        // The block (and any bounce data) must be visible to the device
        // before the doorbell write.
        barrier::mb();
        if !self.io.start_dma(block) {
            self.have_dma = false;
            return Err(FwCfgError::NoDma);
        }
        let buf = self.buffer()?;
        for _ in 0..SPIN_LIMIT {
            let c = u32::from_be(buf.load::<u32>(0));
            if c & DMA_ERROR != 0 {
                return Err(FwCfgError::Device);
            }
            if c == 0 {
                // Order the device's writes to the buffer after the control read.
                barrier::dma_rmb();
                return Ok(());
            }
            core::hint::spin_loop();
        }
        // The device may still write the control block or the bounce area:
        // never free them (dropping the `ManuallyDrop` leaks the buffer), and
        // stop using DMA.
        self.dma = None;
        self.have_dma = false;
        Err(FwCfgError::Timeout)
    }

    /// Reads `buf.len()` bytes of item `selector` starting at `offset`.
    ///
    /// With DMA the bytes are moved through the driver's own DMA buffer, a
    /// bounce area's worth at a time; without it, through the data register.
    pub fn read(&mut self, selector: u16, offset: u32, buf: &mut [u8]) -> Result<(), FwCfgError> {
        if buf.is_empty() {
            return Ok(());
        }
        u32::try_from(buf.len()).ok().and_then(|n| n.checked_add(offset)).ok_or(FwCfgError::TooLarge)?;
        if self.have_dma {
            let mut ctl = DMA_SELECT | (selector as u32) << 16;
            if offset != 0 {
                self.dma(ctl | DMA_SKIP, offset)?;
                ctl = 0;
            }
            for chunk in buf.chunks_mut(CHUNK) {
                // At most CHUNK bytes, which fits a u32.
                self.dma(ctl | DMA_READ, chunk.len() as u32)?;
                ctl = 0;
                self.buffer()?.read(BOUNCE, chunk);
            }
            return Ok(());
        }
        self.io.select(selector);
        for _ in 0..offset {
            self.io.read8();
        }
        for b in buf.iter_mut() {
            *b = self.io.read8();
        }
        Ok(())
    }

    /// Writes `buf` to item `selector`, from its start. Needs DMA; fails
    /// with [`FwCfgError::NoDma`] without it.
    pub fn write(&mut self, selector: u16, buf: &[u8]) -> Result<(), FwCfgError> {
        u32::try_from(buf.len()).map_err(|_| FwCfgError::TooLarge)?;
        let mut ctl = DMA_SELECT | (selector as u32) << 16;
        if buf.is_empty() {
            return self.dma(ctl, 0);
        }
        for chunk in buf.chunks(CHUNK) {
            self.buffer()?.write(BOUNCE, chunk);
            // At most CHUNK bytes, which fits a u32.
            self.dma(ctl | DMA_WRITE, chunk.len() as u32)?;
            ctl = 0;
        }
        Ok(())
    }

    /// Calls `f(name, file)` for each directory entry until it returns
    /// `false`. Entries whose names are not UTF-8 are skipped.
    pub fn for_each_file(&mut self, mut f: impl FnMut(&str, File) -> bool) {
        self.io.select(SEL_FILE_DIR);
        let mut n = [0u8; 4];
        for b in &mut n {
            *b = self.io.read8();
        }
        // A dead device reads as all ones; do not walk four billion entries.
        for _ in 0..u32::from_be_bytes(n).min(MAX_FILES) {
            let mut e = [0u8; DIR_ENTRY];
            for b in &mut e {
                *b = self.io.read8();
            }
            let name = &e[DIR_ENTRY - NAME_LEN..];
            let len = name.iter().position(|&c| c == 0).unwrap_or(NAME_LEN);
            let Ok(name) = core::str::from_utf8(name.get(..len).unwrap_or(&[])) else { continue };
            let size = u32::from_be_bytes([e[0], e[1], e[2], e[3]]);
            let select = u16::from_be_bytes([e[4], e[5]]);
            if !f(name, File { select, size }) {
                return;
            }
        }
    }

    /// Looks up a file by name in the directory.
    pub fn find(&mut self, name: &str) -> Option<File> {
        let mut found = None;
        self.for_each_file(|n, file| {
            if n == name {
                found = Some(file);
            }
            found.is_none()
        });
        found
    }
}

impl<I: FwCfgIo, D: DmaAllocator + ?Sized> Drop for FwCfg<'_, I, D> {
    fn drop(&mut self) {
        // Every transfer that returned has finished; one that timed out
        // already took the buffer out, leaking it.
        if let Some(buf) = self.dma.as_mut() {
            // SAFETY: not used again, and no transfer is in flight.
            unsafe { ManuallyDrop::drop(buf) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iommu::testing::HostDma;
    use std::vec::Vec;

    /// A fake device: the selected item's bytes are served one at a time
    /// through the data register, or moved by DMA when `dma` is set.
    struct Fake {
        items: Vec<(u16, Vec<u8>)>,
        cur: u16,
        pos: usize,
        dma: bool,
        /// Never complete a DMA transfer.
        stall: bool,
        /// Data addresses the DMA transfers used, with the block address.
        transfers: Vec<(u64, u64)>,
    }

    impl Fake {
        fn new() -> Self {
            let mut dir = 2u32.to_be_bytes().to_vec();
            for (size, sel, name) in [(5u32, 0x20u16, "opt/a"), (3, 0x21, "etc/b")] {
                dir.extend(size.to_be_bytes());
                dir.extend(sel.to_be_bytes());
                dir.extend([0, 0]);
                let mut n = [0u8; NAME_LEN];
                n[..name.len()].copy_from_slice(name.as_bytes());
                dir.extend(n);
            }
            let big: Vec<u8> = (0..40_000u32).map(|i| (i * 7 % 251) as u8).collect();
            Self {
                items: std::vec![
                    (SEL_SIGNATURE, b"QEMU".to_vec()),
                    (SEL_ID, 1u32.to_le_bytes().to_vec()),
                    (SEL_FILE_DIR, dir),
                    (0x20, b"hello".to_vec()),
                    (0x21, b"xyz".to_vec()),
                    (0x22, big),
                ],
                cur: 0,
                pos: 0,
                dma: false,
                stall: false,
                transfers: Vec::new(),
            }
        }

        fn with_dma() -> Self {
            let mut f = Self::new();
            f.dma = true;
            f.items[1].1 = 3u32.to_le_bytes().to_vec();
            f
        }

        fn item(&mut self, sel: u16) -> &mut Vec<u8> {
            if !self.items.iter().any(|(s, _)| *s == sel) {
                self.items.push((sel, Vec::new()));
            }
            &mut self.items.iter_mut().find(|(s, _)| *s == sel).unwrap().1
        }
    }

    impl FwCfgIo for Fake {
        fn select(&mut self, selector: u16) {
            self.cur = selector;
            self.pos = 0;
        }
        fn read8(&mut self) -> u8 {
            let (sel, pos) = (self.cur, self.pos);
            self.pos += 1;
            self.item(sel).get(pos).copied().unwrap_or(0)
        }
        fn has_dma_doorbell(&self) -> bool {
            self.dma
        }
        fn start_dma(&mut self, addr: u64) -> bool {
            if !self.dma {
                return false;
            }
            assert!(addr.is_multiple_of(16), "the control block is 16-byte aligned");
            let block = addr as *mut u8;
            // SAFETY: HostDma device addresses are host addresses, and the
            // driver handed over a live control block.
            let (control, len, data) = unsafe {
                (
                    u32::from_be(block.cast::<u32>().read_volatile()),
                    u32::from_be(block.add(4).cast::<u32>().read_volatile()) as usize,
                    u64::from_be(block.add(8).cast::<u64>().read_volatile()),
                )
            };
            self.transfers.push((addr, data));
            if self.stall {
                return true;
            }
            if control & DMA_SELECT != 0 {
                self.select((control >> 16) as u16);
            }
            if control & DMA_SKIP != 0 {
                self.pos += len;
            }
            let (sel, pos) = (self.cur, self.pos);
            if control & DMA_READ != 0 {
                let item = self.item(sel);
                for i in 0..len {
                    let b = item.get(pos + i).copied().unwrap_or(0);
                    // SAFETY: as above; `len` bytes at `data` are the bounce area.
                    unsafe { (data as *mut u8).add(i).write_volatile(b) };
                }
                self.pos += len;
            }
            if control & DMA_WRITE != 0 {
                let item = self.item(sel);
                for i in 0..len {
                    // SAFETY: as above.
                    let b = unsafe { (data as *const u8).add(i).read_volatile() };
                    if item.len() <= pos + i {
                        item.resize(pos + i + 1, 0);
                    }
                    item[pos + i] = b;
                }
                self.pos += len;
            }
            // SAFETY: as above.
            unsafe { block.cast::<u32>().write_volatile(0) };
            true
        }
    }

    #[test]
    fn detect_find_and_read() {
        let mut cfg = FwCfg::new(Fake::new());
        assert!(cfg.detect());
        assert!(!cfg.has_dma());
        assert_eq!(cfg.find("etc/b"), Some(File { select: 0x21, size: 3 }));
        assert_eq!(cfg.find("missing"), None);
        let f = cfg.find("opt/a").unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(cfg.read(f.select, 1, &mut buf), Ok(()));
        assert_eq!(&buf, b"ell");
        assert_eq!(cfg.write(f.select, b"x"), Err(FwCfgError::NoDma));
        let mut names = Vec::new();
        cfg.for_each_file(|n, _| {
            names.push(n.len());
            true
        });
        assert_eq!(names, [5, 5]);
    }

    #[test]
    fn dma_reads_and_writes_through_the_bounce_buffer() {
        let dma = HostDma::default();
        let mut cfg = FwCfg::with_dma(Fake::with_dma(), &dma).unwrap();
        assert_eq!(dma.live(), 1);
        assert!(cfg.detect());
        assert!(cfg.has_dma());

        let mut buf = [0u8; 3];
        assert_eq!(cfg.read(0x20, 1, &mut buf), Ok(()));
        assert_eq!(&buf, b"ell");
        // Larger than the bounce area: several chunks, continuing the item.
        let mut big = std::vec![0u8; 39_000];
        assert_eq!(cfg.read(0x22, 1000, &mut big), Ok(()));
        let want: Vec<u8> = (1000..40_000u32).map(|i| (i * 7 % 251) as u8).collect();
        assert_eq!(big, want);

        let payload: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        assert_eq!(cfg.write(0x30, &payload), Ok(()));
        assert_eq!(cfg.io().item(0x30), &payload);

        // Every transfer used the driver's own buffer.
        let transfers = cfg.io().transfers.clone();
        let block = transfers[0].0;
        assert!(transfers.len() > 6, "{transfers:?}");
        for (b, data) in transfers {
            assert_eq!(b, block);
            assert!(data == 0 || data == block + BOUNCE as u64, "{data:#x}");
        }
        drop(cfg);
        assert_eq!(dma.live(), 0);
    }

    #[test]
    fn dma_device_error_is_reported() {
        struct Err0(Fake);
        impl FwCfgIo for Err0 {
            fn select(&mut self, s: u16) {
                self.0.select(s)
            }
            fn read8(&mut self) -> u8 {
                self.0.read8()
            }
            fn has_dma_doorbell(&self) -> bool {
                true
            }
            fn start_dma(&mut self, addr: u64) -> bool {
                // SAFETY: as in `Fake::start_dma`.
                unsafe { (addr as *mut u32).write_volatile(DMA_ERROR.to_be()) };
                true
            }
        }
        let dma = HostDma::default();
        let mut cfg = FwCfg::with_dma(Err0(Fake::with_dma()), &dma).unwrap();
        assert!(cfg.detect() && cfg.has_dma());
        assert_eq!(cfg.read(0x20, 0, &mut [0; 2]), Err(FwCfgError::Device));
        assert!(cfg.has_dma(), "an error the device reported leaves DMA usable");
        drop(cfg);
        assert_eq!(dma.live(), 0);
    }

    #[test]
    fn dma_timeout_leaks_the_buffer_and_falls_back() {
        let dma = HostDma::default();
        let mut fake = Fake::with_dma();
        fake.stall = true;
        let mut cfg = FwCfg::with_dma(fake, &dma).unwrap();
        assert!(cfg.detect() && cfg.has_dma());
        let mut buf = [0u8; 5];
        assert_eq!(cfg.read(0x20, 0, &mut buf), Err(FwCfgError::Timeout));
        assert!(!cfg.has_dma());
        assert_eq!(cfg.write(0x30, b"x"), Err(FwCfgError::NoDma));
        assert_eq!(cfg.read(0x20, 0, &mut buf), Ok(()), "the data register still works");
        assert_eq!(&buf, b"hello");
        drop(cfg);
        assert_eq!(dma.live(), 1, "the device may still write it: leaked, not freed");
    }

    #[test]
    fn dma_needs_the_device_feature_and_a_doorbell() {
        let dma = HostDma::default();
        let mut cfg = FwCfg::with_dma(Fake::new(), &dma).unwrap();
        assert!(cfg.detect());
        assert!(!cfg.has_dma(), "the ID register does not offer DMA");
        let mut no_bell = Fake::with_dma();
        no_bell.dma = false;
        let mut cfg = FwCfg::with_dma(no_bell, &dma).unwrap();
        assert!(cfg.detect());
        assert!(!cfg.has_dma(), "no doorbell");
    }

    #[test]
    fn oversized_requests_are_refused() {
        let mut cfg = FwCfg::new(Fake::new());
        assert!(cfg.detect());
        assert_eq!(cfg.read(0x20, u32::MAX, &mut [0; 2]), Err(FwCfgError::TooLarge));
    }

    #[test]
    fn missing_device_is_not_detected() {
        struct Dead;
        impl FwCfgIo for Dead {
            fn select(&mut self, _: u16) {}
            fn read8(&mut self) -> u8 {
                0xFF
            }
            fn start_dma(&mut self, _: u64) -> bool {
                false
            }
        }
        assert!(!FwCfg::new(Dead).detect());
    }

    #[test]
    fn directory_walk_is_capped() {
        struct Ones(usize);
        impl FwCfgIo for Ones {
            fn select(&mut self, _: u16) {}
            fn read8(&mut self) -> u8 {
                self.0 += 1;
                0xFF
            }
            fn start_dma(&mut self, _: u64) -> bool {
                false
            }
        }
        let mut cfg = FwCfg::new(Ones(0));
        cfg.for_each_file(|_, _| true);
        assert!(cfg.io.0 <= 4 + MAX_FILES as usize * DIR_ENTRY);
    }
}
