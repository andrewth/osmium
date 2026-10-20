//! A software AHCI HBA for host tests, with RAM disks on its ports.
//!
//! The register file is ordinary memory that the driver reaches through an
//! [`IoMem`] as usual. The driver's register helpers also call
//! [`before_read`] and [`after_write`] (in test builds only), which hand
//! each access to the fake installed on the current thread, so it can play
//! the hardware's side synchronously and deterministically: write-1-to-clear
//! bits, PxCMD.CR and FR clearing a few reads after ST and FRE do, the
//! signature arriving when FIS receive starts, and commands parsed from the
//! command list, command table, FIS and PRDT in DMA memory and run against
//! the disk a few PxCI reads after they are issued. Protocol mistakes the
//! driver could make (moving the command list under a running port, setting
//! ST while the device is busy, issuing a command on a stopped port)
//! panic the test.

use core::cell::{Cell, RefCell};
use std::boxed::Box;
use std::string::String;
use std::vec;
use std::vec::Vec;

use osmium_hal::mmio::IoMem;

use super::disk::{DEVICE_LBA, FLUSH_CACHE_EXT, IDENTIFY_DEVICE, READ_DMA_EXT, WRITE_DMA_EXT};
use super::port::*;
use super::{BOHC, BOHC_BOS, BOHC_OOS, CAP, CAP2, CAP2_BOH, GHC, HBA_IS, MAX_PORTS, PI, VS, cap};

/// Register reads it takes CR/FR, BSY and command completion to catch up.
const LAG: u32 = 2;

const REGS_LEN: usize = PORT_BASE + PORT_STRIDE * MAX_PORTS;
const MAX_DATA: usize = 4 << 20;

// ATA error register bits.
const ABRT: u8 = 1 << 2;
const IDNF: u8 = 1 << 4;
const UNC: u8 = 1 << 6;
const STS_READY: u32 = 0x50;
/// Command header DW0: the FIS length in dwords.
const HDR_CFL_MASK: u32 = 0x1f;

/// A command the disk ran (or failed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cmd {
    pub command: u8,
    pub lba: u64,
    pub count: u16,
    /// Bytes the PRDT described.
    pub bytes: u32,
}

pub enum FakeDev {
    Disk { data: Vec<u8>, sectors: u64, sector_size: usize, model: String, serial: String, lba48: bool },
    Atapi,
}

impl FakeDev {
    /// A zeroed disk (only its first [`MAX_DATA`] bytes are backed).
    pub fn disk(sectors: u64, sector_size: usize) -> Self {
        let len = (sectors as usize).saturating_mul(sector_size).min(MAX_DATA);
        FakeDev::Disk {
            data: vec![0; len],
            sectors,
            sector_size,
            model: "Fake Disk".into(),
            serial: "0001".into(),
            lba48: true,
        }
    }

    pub fn with_data(mut self, contents: Vec<u8>) -> Self {
        if let FakeDev::Disk { data, .. } = &mut self {
            *data = contents;
        }
        self
    }

    pub fn set_model(&mut self, m: &str, s: &str) {
        if let FakeDev::Disk { model, serial, .. } = self {
            *model = m.into();
            *serial = s.into();
        }
    }

    pub fn set_lba48(&mut self, on: bool) {
        if let FakeDev::Disk { lba48, .. } = self {
            *lba48 = on;
        }
    }

    fn signature(&self) -> u32 {
        match self {
            FakeDev::Disk { .. } => 0x0000_0101,
            FakeDev::Atapi => 0xeb14_0101,
        }
    }
}

#[derive(Default)]
pub struct FakePort {
    pub dev: Option<FakeDev>,
    /// Reads and writes reaching this LBA fail (uncorrectable).
    pub fail_from: u64,
    pub fail_flush: bool,
    /// A failed command leaves BSY set, so restarting needs CLO or COMRESET.
    pub busy_after_error: bool,
    /// Commands never complete.
    pub hang: bool,
    /// The device never clears BSY.
    pub busy_forever: bool,
    /// The command engine never stops (CR stays set).
    pub wont_stop: bool,

    pub starts: u32,
    pub clos: u32,
    pub comresets: u32,

    cmd: u32,
    is: u32,
    serr: u32,
    ci: u32,
    /// CMD reads left before CR and FR follow ST and FRE.
    settle: u32,
    /// TFD reads left before BSY clears.
    busy_reads: Option<u32>,
    /// CI reads left before the issued command runs.
    pending: Option<u32>,
    /// A command failed; nothing runs until ST is cleared.
    latched: bool,
    in_comreset: bool,
}

/// The register file.
struct Regs(Box<[Cell<u32>]>);

impl Regs {
    fn get(&self, off: usize) -> u32 {
        self.0[off / 4].get()
    }

    fn set(&self, off: usize, v: u32) {
        self.0[off / 4].set(v)
    }

    fn port_reg(&self, port: usize, reg: usize) -> u32 {
        self.get(PORT_BASE + PORT_STRIDE * port + reg)
    }

    fn pset(&self, port: usize, reg: usize, v: u32) {
        self.set(PORT_BASE + PORT_STRIDE * port + reg, v)
    }
}

pub struct FakeHba {
    regs: Regs,
    pub cap: u32,
    pub pi: u32,
    pub bios_owned: bool,
    pub handed_off: bool,
    pub ports: Vec<FakePort>,
    pub log: Vec<Cmd>,
}

std::thread_local! {
    static FAKE: RefCell<Option<FakeHba>> = const { RefCell::new(None) };
}

/// Makes `hba` this thread's HBA; returns its registers.
pub fn install(mut hba: FakeHba) -> IoMem {
    hba.reset();
    // SAFETY: the register file lives (boxed, so it does not move) until
    // `uninstall`, and is only touched through cells.
    let io = unsafe { IoMem::new(hba.regs.0.as_ptr() as *mut u8, REGS_LEN) };
    FAKE.with(|f| *f.borrow_mut() = Some(hba));
    io
}

/// Removes this thread's HBA. Its registers must no longer be used.
pub fn uninstall() -> FakeHba {
    FAKE.with(|f| f.borrow_mut().take()).expect("no fake HBA")
}

/// Runs `f` on this thread's HBA.
pub fn with<R>(f: impl FnOnce(&mut FakeHba) -> R) -> R {
    FAKE.with(|h| f(h.borrow_mut().as_mut().expect("no fake HBA")))
}

/// The driver is about to read the register at `off`.
pub fn before_read(off: usize) {
    FAKE.with(|h| {
        if let Some(h) = h.borrow_mut().as_mut() {
            h.read(off)
        }
    })
}

/// The driver wrote `v` to the register at `off`.
pub fn after_write(off: usize, v: u32) {
    FAKE.with(|h| {
        if let Some(h) = h.borrow_mut().as_mut() {
            h.write(off, v)
        }
    })
}

fn mem(addr: u64, len: usize) -> &'static mut [u8] {
    // SAFETY: test DMA memory is identity-mapped and outlives the command.
    unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) }
}

fn dword(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

impl FakeHba {
    /// An HBA with `ports` ports, all implemented and empty.
    pub fn new(ports: usize) -> Self {
        Self {
            regs: Regs((0..REGS_LEN / 4).map(|_| Cell::new(0)).collect()),
            cap: cap::S64A | cap::SCLO | 31 << 8 | (ports as u32 - 1),
            pi: ((1u64 << ports) - 1) as u32,
            bios_owned: false,
            handed_off: false,
            ports: (0..ports).map(|_| FakePort { fail_from: u64::MAX, ..FakePort::default() }).collect(),
            log: Vec::new(),
        }
    }

    pub fn attach(&mut self, port: usize, dev: FakeDev) {
        self.ports[port].dev = Some(dev);
    }

    /// Leaves `port` as firmware might: command engine and FIS receive on.
    pub fn running(&mut self, port: usize) {
        self.ports[port].cmd = CMD_ST | CMD_FRE | CMD_CR | CMD_FR;
    }

    pub fn ghc(&self) -> u32 {
        self.regs.get(GHC)
    }

    pub fn port_reg(&self, port: usize, reg: usize) -> u32 {
        self.regs.port_reg(port, reg)
    }

    /// Power-on register values.
    fn reset(&mut self) {
        let regs = &self.regs;
        regs.set(CAP, self.cap);
        regs.set(PI, self.pi);
        regs.set(VS, 0x0001_0300);
        regs.set(CAP2, if self.bios_owned { CAP2_BOH } else { 0 });
        regs.set(BOHC, if self.bios_owned { BOHC_BOS } else { 0 });
        for (p, port) in self.ports.iter().enumerate() {
            let present = port.dev.is_some();
            regs.pset(p, CMD, port.cmd);
            regs.pset(p, SSTS, if present { 0x113 } else { 0 });
            regs.pset(p, TFD, if present { STS_BSY } else { 0x7f });
            regs.pset(p, SIG, !0);
        }
    }

    fn read(&mut self, off: usize) {
        let regs = &self.regs;
        let Some((p, reg)) = self.port_of(off) else { return };
        let port = &mut self.ports[p];
        match reg {
            CMD if port.settle > 0 => port.settle -= 1,
            CMD => {
                let mut v = port.cmd & !(CMD_CR | CMD_FR);
                if port.cmd & CMD_ST != 0 || (port.wont_stop && port.cmd & CMD_CR != 0) {
                    v |= CMD_CR;
                }
                if port.cmd & CMD_FRE != 0 {
                    v |= CMD_FR;
                }
                port.cmd = v;
                regs.pset(p, CMD, v);
            }
            TFD => match port.busy_reads {
                Some(0) => {
                    port.busy_reads = None;
                    regs.pset(p, TFD, regs.port_reg(p, TFD) & !STS_BSY);
                }
                Some(n) => port.busy_reads = Some(n - 1),
                None => {}
            },
            CI => match port.pending {
                Some(0) => {
                    port.pending = None;
                    self.execute(p);
                }
                Some(n) => port.pending = Some(n - 1),
                None => {}
            },
            _ => {}
        }
    }

    fn port_of(&self, off: usize) -> Option<(usize, usize)> {
        let p = off.checked_sub(PORT_BASE)? / PORT_STRIDE;
        (p < self.ports.len()).then_some((p, (off - PORT_BASE) % PORT_STRIDE))
    }

    fn write(&mut self, off: usize, v: u32) {
        let regs = &self.regs;
        let Some((p, reg)) = self.port_of(off) else {
            match off {
                GHC => assert_eq!(v & 1, 0, "the driver does not reset the HBA"),
                BOHC if v & BOHC_OOS != 0 => {
                    self.handed_off = true;
                    regs.set(BOHC, BOHC_OOS);
                }
                HBA_IS => regs.set(HBA_IS, 0),
                CAP | PI | VS | CAP2 => panic!("write to read-only register {off:#x}"),
                _ => {}
            }
            return;
        };
        let port = &mut self.ports[p];
        match reg {
            CLB | CLBU => assert_eq!(port.cmd & (CMD_ST | CMD_CR), 0, "command list moved under a running port"),
            FB | FBU => assert_eq!(port.cmd & (CMD_FRE | CMD_FR), 0, "FIS area moved while receiving"),
            IS => {
                port.is &= !v;
                regs.pset(p, IS, port.is);
            }
            SERR => {
                port.serr &= !v;
                regs.pset(p, SERR, port.serr);
            }
            CMD => self.write_cmd(p, v),
            SCTL => self.write_sctl(p, v),
            CI => {
                assert_ne!(port.cmd & CMD_ST, 0, "command issued on a stopped port");
                assert!(!port.latched, "command issued before error recovery");
                port.ci |= v;
                regs.pset(p, CI, port.ci);
                regs.pset(p, TFD, regs.port_reg(p, TFD) | STS_BSY);
                port.pending = if port.hang { None } else { Some(LAG) };
            }
            TFD | SIG | SSTS => panic!("write to read-only port register {reg:#x}"),
            _ => {}
        }
    }

    fn write_cmd(&mut self, p: usize, v: u32) {
        let regs = &self.regs;
        let port = &mut self.ports[p];
        let prev = port.cmd;
        let mut new = v & !(CMD_CR | CMD_FR) | prev & (CMD_CR | CMD_FR);
        let mut tfd = regs.port_reg(p, TFD);
        if new & CMD_CLO != 0 {
            assert_eq!(new & CMD_ST, 0, "CLO while running");
            tfd &= !(STS_BSY | STS_DRQ);
            port.busy_reads = None;
            port.clos += 1;
            new &= !CMD_CLO;
        }
        if new & CMD_ST != 0 && prev & CMD_ST == 0 {
            assert_ne!(new & CMD_FRE, 0, "ST before FRE");
            assert_eq!(tfd & (STS_BSY | STS_DRQ), 0, "ST while the device is busy");
            port.starts += 1;
            port.latched = false;
        }
        if new & CMD_ST == 0 && prev & CMD_ST != 0 {
            port.ci = 0;
            port.pending = None;
            regs.pset(p, CI, 0);
        }
        if new & CMD_FRE != 0
            && prev & CMD_FRE == 0
            && let Some(dev) = &port.dev
        {
            regs.pset(p, SIG, dev.signature());
            if !port.busy_forever {
                port.busy_reads = Some(LAG);
            }
        }
        // CR and FR rise at once, and fall a little later.
        if new & CMD_ST != 0 {
            new |= CMD_CR;
        }
        if new & CMD_FRE != 0 {
            new |= CMD_FR;
        }
        port.cmd = new;
        port.settle = LAG;
        regs.pset(p, CMD, new);
        regs.pset(p, TFD, tfd);
    }

    fn write_sctl(&mut self, p: usize, v: u32) {
        let regs = &self.regs;
        let port = &mut self.ports[p];
        match v & DET_MASK {
            1 => {
                port.in_comreset = true;
                regs.pset(p, SSTS, 0);
                regs.pset(p, TFD, STS_BSY);
            }
            0 if port.in_comreset => {
                port.in_comreset = false;
                port.comresets += 1;
                port.serr |= 1 << 26; // X: device exchanged
                port.busy_reads = Some(LAG);
                regs.pset(p, SERR, port.serr);
                regs.pset(p, SSTS, 0x113);
            }
            _ => {}
        }
    }

    /// Runs the command in slot 0.
    fn execute(&mut self, p: usize) {
        let regs = &self.regs;
        let base = PORT_BASE + PORT_STRIDE * p;
        let clb = regs.get(base + CLB) as u64 | (regs.get(base + CLBU) as u64) << 32;
        let hdr = mem(clb, 32);
        let dw0 = dword(hdr, 0);
        assert_eq!(dw0 & HDR_CFL_MASK, 5, "a register FIS is five dwords");
        let write = dw0 & HDR_WRITE != 0;
        let prdtl = (dw0 >> 16) as usize;
        let ctba = dword(hdr, 8) as u64 | (dword(hdr, 12) as u64) << 32;
        assert_eq!(ctba % 128, 0, "command table alignment");
        let fis = mem(ctba, 20);
        assert_eq!((fis[0], fis[1] & FIS_COMMAND), (FIS_REG_H2D, FIS_COMMAND));
        let command = fis[2];
        let lba = u64::from_le_bytes([fis[4], fis[5], fis[6], fis[8], fis[9], fis[10], 0, 0]);
        let count = u16::from_le_bytes([fis[12], fis[13]]);
        let prds: Vec<(u64, usize)> = (0..prdtl)
            .map(|i| {
                let e = mem(ctba + 0x80 + 16 * i as u64, 16);
                let dba = dword(e, 0) as u64 | (dword(e, 4) as u64) << 32;
                assert_eq!(dba % 2, 0, "PRD data must be word aligned");
                (dba, (dword(e, 12) & 0x3f_ffff) as usize + 1)
            })
            .collect();
        let total: usize = prds.iter().map(|d| d.1).sum();
        self.log.push(Cmd { command, lba, count, bytes: total as u32 });

        let port = &mut self.ports[p];
        let result = match (port.dev.as_mut(), command) {
            (Some(FakeDev::Disk { .. }), IDENTIFY_DEVICE) => {
                assert!(!write);
                let id = identify(port.dev.as_ref().unwrap());
                scatter(&prds, &id);
                Ok(id.len())
            }
            (Some(FakeDev::Disk { data, sectors, sector_size, .. }), READ_DMA_EXT | WRITE_DMA_EXT) => {
                assert_ne!(fis[7] & DEVICE_LBA, 0, "LBA mode");
                assert_eq!(write, command == WRITE_DMA_EXT, "header W bit");
                let n = if count == 0 { 65536 } else { count as u64 };
                let bytes = n as usize * *sector_size;
                assert_eq!(total, bytes, "PRDT covers the transfer");
                let start = lba as usize * *sector_size;
                if lba + n > port.fail_from {
                    Err(UNC)
                } else if lba + n > *sectors || start + bytes > data.len() {
                    Err(IDNF)
                } else if write {
                    gather(&prds, &mut data[start..start + bytes]);
                    Ok(bytes)
                } else {
                    scatter(&prds, &data[start..start + bytes]);
                    Ok(bytes)
                }
            }
            (Some(FakeDev::Disk { .. }), FLUSH_CACHE_EXT) => {
                assert_eq!(prdtl, 0);
                if port.fail_flush { Err(ABRT) } else { Ok(0) }
            }
            _ => Err(ABRT),
        };
        match result {
            Ok(bytes) => {
                hdr[4..8].copy_from_slice(&(bytes as u32).to_le_bytes());
                port.ci &= !1;
                port.is |= 1; // D2H register FIS received
                regs.pset(p, TFD, STS_READY);
                let fb = regs.get(base + FB) as u64 | (regs.get(base + FBU) as u64) << 32;
                mem(fb + 0x40, 4).copy_from_slice(&[0x34, 0x40, STS_READY as u8, 0]);
            }
            Err(error) => {
                port.is |= IS_TFES;
                port.latched = true;
                let busy = if port.busy_after_error { STS_BSY } else { 0 };
                regs.pset(p, TFD, (error as u32) << 8 | busy | STS_READY | STS_ERR);
            }
        }
        regs.pset(p, CI, port.ci);
        regs.pset(p, IS, port.is);
    }
}

/// Copies `src` into the PRD buffers.
fn scatter(prds: &[(u64, usize)], mut src: &[u8]) {
    for &(addr, len) in prds {
        let n = len.min(src.len());
        mem(addr, n).copy_from_slice(&src[..n]);
        src = &src[n..];
    }
}

/// Fills `dst` from the PRD buffers.
fn gather(prds: &[(u64, usize)], mut dst: &mut [u8]) {
    for &(addr, len) in prds {
        let n = len.min(dst.len());
        let (head, rest) = dst.split_at_mut(n);
        head.copy_from_slice(mem(addr, n));
        dst = rest;
    }
}

/// IDENTIFY DEVICE data for a disk.
fn identify(dev: &FakeDev) -> [u8; 512] {
    let FakeDev::Disk { sectors, sector_size, model, serial, lba48, .. } = dev else { unreachable!() };
    let mut w = [0u16; 256];
    let string = |w: &mut [u16], s: &str| {
        let mut bytes = s.bytes().chain(core::iter::repeat(b' '));
        for word in w {
            *word = u16::from_be_bytes([bytes.next().unwrap(), bytes.next().unwrap()]);
        }
    };
    w[0] = 0x0040;
    string(&mut w[10..20], serial);
    string(&mut w[27..47], model);
    w[49] = 1 << 9 | 1 << 8; // LBA, DMA
    let lba28 = (*sectors).min(0x0fff_ffff);
    w[60] = lba28 as u16;
    w[61] = (lba28 >> 16) as u16;
    let lba48_bit = if *lba48 { 1 << 10 } else { 0 };
    w[83] = 0x4000 | lba48_bit;
    w[86] = lba48_bit;
    if *lba48 {
        for i in 0..4 {
            w[100 + i] = (sectors >> (16 * i)) as u16;
        }
    }
    w[106] = 0x4000 | if *sector_size != 512 { 1 << 12 } else { 0 };
    let words = (*sector_size / 2) as u32;
    w[117] = words as u16;
    w[118] = (words >> 16) as u16;
    let mut out = [0u8; 512];
    for (i, word) in w.iter().enumerate() {
        out[2 * i..2 * i + 2].copy_from_slice(&word.to_le_bytes());
    }
    out
}
