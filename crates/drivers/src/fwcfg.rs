//! QEMU `fw_cfg`: named blobs the hypervisor hands to the guest firmware
//! (ACPI tables, `-kernel`/`-initrd`/`-append`, the `ramfb` configuration,
//! SMBIOS, boot order, ...).
//!
//! The device is reached through a selector register and a data register
//! (I/O ports 0x510/0x511 on x86, an MMIO window on Arm and RISC-V), plus an
//! optional DMA doorbell. A platform supplies those through [`FwCfgIo`];
//! [`FwCfg`] does the rest.
//!
//! ```ignore
//! let mut cfg = FwCfg::new(MyIo);
//! assert!(cfg.detect());
//! let kernel = cfg.find("opt/kernel").unwrap();
//! cfg.read(kernel.select, 0, &mut buf);
//! ```

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

const SEL_SIGNATURE: u16 = 0x0000;
const SEL_ID: u16 = 0x0001;
const SEL_FILE_DIR: u16 = 0x0019;

const ID_DMA: u32 = 2;

const DMA_ERROR: u32 = 1;
const DMA_READ: u32 = 2;
const DMA_SKIP: u32 = 4;
const DMA_SELECT: u32 = 8;
const DMA_WRITE: u32 = 16;

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
    /// The device address of `ptr`, which a DMA transfer reads or writes.
    /// The default is the identity, right when memory is identity mapped.
    fn dma_address(&self, ptr: *const u8) -> u64 {
        ptr as u64
    }
}

#[repr(C, align(16))]
struct DmaAccess {
    control: u32,
    length: u32,
    address: u64,
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
pub struct FwCfg<I: FwCfgIo> {
    io: I,
    dma: DmaAccess,
    have_dma: bool,
}

impl<I: FwCfgIo> FwCfg<I> {
    /// Wraps the registers without touching the device; call
    /// [`FwCfg::detect`] to check that it is there and to enable DMA.
    pub const fn new(io: I) -> Self {
        Self { io, dma: DmaAccess { control: 0, length: 0, address: 0 }, have_dma: false }
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
        self.have_dma = id & ID_DMA != 0 && self.io.has_dma_doorbell();
        true
    }

    /// Whether DMA transfers are in use (reads are faster; writes need it).
    pub fn has_dma(&self) -> bool {
        self.have_dma
    }

    fn dma(&mut self, control: u32, buf: *mut u8, len: u32) -> bool {
        let addr = self.io.dma_address(buf);
        let d = &raw mut self.dma;
        // SAFETY: `d` points into `self`; the device reads and writes this
        // block in big-endian, so accesses are volatile.
        unsafe {
            write_volatile(&raw mut (*d).length, len.to_be());
            write_volatile(&raw mut (*d).address, addr.to_be());
            write_volatile(&raw mut (*d).control, control.to_be());
        }
        fence(Ordering::SeqCst);
        let block = self.io.dma_address(d.cast());
        if !self.io.start_dma(block) {
            return false;
        }
        loop {
            // SAFETY: as above.
            let c = u32::from_be(unsafe { read_volatile(&raw const (*d).control) });
            if c & DMA_ERROR != 0 {
                return false;
            }
            if c == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
    }

    /// Reads `buf.len()` bytes of item `selector` starting at `offset`.
    ///
    /// With DMA the buffer must be reachable by the device at
    /// [`FwCfgIo::dma_address`].
    pub fn read(&mut self, selector: u16, offset: u32, buf: &mut [u8]) -> bool {
        if buf.is_empty() {
            return true;
        }
        if self.have_dma {
            let mut ctl = DMA_SELECT | DMA_READ | (selector as u32) << 16;
            if offset != 0 {
                if !self.dma(DMA_SELECT | DMA_SKIP | (selector as u32) << 16, core::ptr::null_mut(), offset) {
                    return false;
                }
                ctl = DMA_READ;
            }
            let Ok(len) = u32::try_from(buf.len()) else { return false };
            return self.dma(ctl, buf.as_mut_ptr(), len);
        }
        self.io.select(selector);
        for _ in 0..offset {
            self.io.read8();
        }
        for b in buf.iter_mut() {
            *b = self.io.read8();
        }
        true
    }

    /// Writes `buf` to item `selector`. Needs DMA; returns `false` without it.
    pub fn write(&mut self, selector: u16, buf: &[u8]) -> bool {
        let Ok(len) = u32::try_from(buf.len()) else { return false };
        self.have_dma && self.dma(DMA_SELECT | DMA_WRITE | (selector as u32) << 16, buf.as_ptr() as *mut u8, len)
    }

    /// Calls `f(name, file)` for each directory entry until it returns
    /// `false`. Entries whose names are not UTF-8 are skipped.
    pub fn for_each_file(&mut self, mut f: impl FnMut(&str, File) -> bool) {
        self.io.select(SEL_FILE_DIR);
        let mut n = [0u8; 4];
        for b in &mut n {
            *b = self.io.read8();
        }
        for _ in 0..u32::from_be_bytes(n) {
            let mut e = [0u8; DIR_ENTRY];
            for b in &mut e {
                *b = self.io.read8();
            }
            let name = &e[DIR_ENTRY - NAME_LEN..];
            let len = name.iter().position(|&c| c == 0).unwrap_or(NAME_LEN);
            let Ok(name) = core::str::from_utf8(&name[..len]) else { continue };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// A fake device: the selected item's bytes are served one at a time.
    struct Fake {
        items: Vec<(u16, Vec<u8>)>,
        cur: Vec<u8>,
        pos: usize,
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
            Self {
                items: std::vec![
                    (SEL_SIGNATURE, b"QEMU".to_vec()),
                    (SEL_ID, 1u32.to_le_bytes().to_vec()),
                    (SEL_FILE_DIR, dir),
                    (0x20, b"hello".to_vec()),
                    (0x21, b"xyz".to_vec()),
                ],
                cur: Vec::new(),
                pos: 0,
            }
        }
    }

    impl FwCfgIo for Fake {
        fn select(&mut self, selector: u16) {
            self.cur = self.items.iter().find(|(s, _)| *s == selector).map(|(_, d)| d.clone()).unwrap_or_default();
            self.pos = 0;
        }
        fn read8(&mut self) -> u8 {
            let b = self.cur.get(self.pos).copied().unwrap_or(0);
            self.pos += 1;
            b
        }
        fn start_dma(&mut self, _: u64) -> bool {
            false
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
        assert!(cfg.read(f.select, 1, &mut buf));
        assert_eq!(&buf, b"ell");
        assert!(!cfg.write(f.select, b"x"));
        let mut names = Vec::new();
        cfg.for_each_file(|n, _| {
            names.push(n.len());
            true
        });
        assert_eq!(names, [5, 5]);
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
}
