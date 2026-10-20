//! One HBA port: its registers, its DMA memory (command list, received-FIS
//! area, one command table), and running one command through slot 0.

use core::mem::ManuallyDrop;

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;

use super::{AhciError, POLL_LIMIT, cap, r32, w32};

// Port registers, relative to the port's base.
pub(super) const CLB: usize = 0x00;
pub(super) const CLBU: usize = 0x04;
pub(super) const FB: usize = 0x08;
pub(super) const FBU: usize = 0x0c;
pub(super) const IS: usize = 0x10;
pub(super) const IE: usize = 0x14;
pub(super) const CMD: usize = 0x18;
pub(super) const TFD: usize = 0x20;
pub(super) const SIG: usize = 0x24;
pub(super) const SSTS: usize = 0x28;
pub(super) const SCTL: usize = 0x2c;
pub(super) const SERR: usize = 0x30;
pub(super) const CI: usize = 0x38;

/// Port registers start here in ABAR, one block per port.
pub(super) const PORT_BASE: usize = 0x100;
pub(super) const PORT_STRIDE: usize = 0x80;

// PxCMD.
pub(super) const CMD_ST: u32 = 1 << 0;
pub(super) const CMD_SUD: u32 = 1 << 1;
pub(super) const CMD_CLO: u32 = 1 << 3;
pub(super) const CMD_FRE: u32 = 1 << 4;
pub(super) const CMD_FR: u32 = 1 << 14;
pub(super) const CMD_CR: u32 = 1 << 15;

// PxIS: the task file error and the fatal (host bus, interface) errors.
pub(super) const IS_TFES: u32 = 1 << 30;
const IS_ERRORS: u32 = IS_TFES | 1 << 29 | 1 << 28 | 1 << 27 | 1 << 26 | 1 << 24;

// PxTFD: the ATA status register, with the error register in bits 15:8.
pub(super) const STS_ERR: u32 = 1 << 0;
pub(super) const STS_DRQ: u32 = 1 << 3;
pub(super) const STS_BSY: u32 = 1 << 7;

/// PxSSTS.DET and PxSCTL.DET.
pub(super) const DET_MASK: u32 = 0xf;
/// PxSSTS.DET: a device is present but the link is not up yet.
pub(super) const DET_PRESENT: u32 = 1;
/// PxSSTS.DET: a device is present and the link is up.
pub(super) const DET_ESTABLISHED: u32 = 3;
/// PxSSTS.DET: the PHY is offline (disabled, or in a loopback mode).
pub(super) const DET_OFFLINE: u32 = 4;
/// PxSCTL.DET: hold COMRESET on the link.
const DET_COMRESET: u32 = 1;

/// How long COMRESET is held: at least 1 ms (AHCI 1.3.1 §10.4.2).
const COMRESET_NS: u64 = 1_000_000;
/// How long the PHY gets to bring the link up after spin-up or COMRESET.
const PHY_NS: u64 = 10_000_000;
/// Without a clock, those waits are counted in register reads instead,
/// assuming no uncached MMIO read takes less than 10 ns.
const COMRESET_POLLS: u32 = if cfg!(test) { 100 } else { 100_000 };
const PHY_POLLS: u32 = if cfg!(test) { 1000 } else { 1_000_000 };

// Port memory: the command list (32 headers of 32 bytes, 1 KiB aligned),
// the received-FIS area (256 bytes, 256 aligned) and the command table
// (128 aligned) with its single PRD entry.
pub(super) const CL_OFFSET: usize = 0;
pub(super) const FIS_OFFSET: usize = 0x400;
pub(super) const CT_OFFSET: usize = 0x500;
pub(super) const PRDT_OFFSET: usize = CT_OFFSET + 0x80;
pub(super) const PORT_MEM_LEN: usize = PRDT_OFFSET + 16;
/// Alignment the port memory needs (the command list's).
pub(super) const PORT_MEM_ALIGN: u64 = 1024;

// Command header DW0 (the FIS length in dwords is bits 4:0).
pub(super) const HDR_WRITE: u32 = 1 << 6;

/// Register host-to-device FIS: type and length in dwords.
pub(super) const FIS_REG_H2D: u8 = 0x27;
const FIS_H2D_DWORDS: u32 = 5;
/// The H2D FIS's "this is a command" bit (byte 1).
pub(super) const FIS_COMMAND: u8 = 0x80;

/// Largest byte count of one PRD entry.
pub(super) const PRD_MAX: usize = 4 << 20;

/// One ATA command to run in slot 0.
#[derive(Clone, Copy, Debug)]
pub(super) struct Command {
    pub command: u8,
    pub lba: u64,
    pub count: u16,
    /// The device register (0x40 selects LBA addressing).
    pub device: u8,
    /// Bytes of the data buffer to transfer (0 for none).
    pub len: usize,
    /// True if the data goes to the device.
    pub write: bool,
}

/// What a port has attached, from its signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    /// A SATA disk (signature 0000_0101).
    Ata,
    /// A packet device, such as an optical drive (EB14_0101). Not supported.
    Atapi,
    /// Something else: a port multiplier (9669_0101), an enclosure
    /// management bridge (C33C_0101), or an unknown signature.
    Other(u32),
}

impl From<u32> for DeviceKind {
    fn from(sig: u32) -> Self {
        match sig {
            0x0000_0101 => DeviceKind::Ata,
            0xeb14_0101 => DeviceKind::Atapi,
            other => DeviceKind::Other(other),
        }
    }
}

/// A port with a device on it, its memory programmed and its command
/// engine running. Dropping it stops the port, then frees the memory; if
/// the port will not stop, the memory is leaked rather than freed under
/// the HBA.
pub(super) struct Port<'d, D: DmaAllocator + ?Sized> {
    io: IoMem,
    base: usize,
    index: u8,
    /// The HBA's CAP register.
    cap: u32,
    clock: Option<&'d dyn Clock>,
    pub kind: DeviceKind,
    /// Error recovery failed. If the command engine would not stop, the
    /// HBA may still be running the abandoned command, so the command
    /// table and data buffer are left alone for good: every later command
    /// fails without touching them.
    broken: bool,
    mem: ManuallyDrop<OwnedDma<'d, D>>,
    /// The data buffer, once a disk driver has given it one.
    data: ManuallyDrop<Option<OwnedDma<'d, D>>>,
}

impl<'d, D: DmaAllocator + ?Sized> Port<'d, D> {
    /// Brings up port `index` (AHCI 1.3.1 §10.1.2): stops it, gives it a
    /// command list and received-FIS area, and starts it once the device is
    /// ready. Returns `Ok(None)` if no device is on the link.
    pub fn probe(
        io: &IoMem,
        index: u8,
        cap: u32,
        dma: &'d D,
        clock: Option<&'d dyn Clock>,
    ) -> Result<Option<Self>, AhciError> {
        let base = PORT_BASE + PORT_STRIDE * index as usize;
        let r = |reg| r32(io, base + reg);
        stop(io, base)?;
        let spin_up = cap & cap::SSS != 0;
        if spin_up {
            w32(io, base + CMD, r(CMD) | CMD_SUD);
        }
        // The PHY gets a while to bring the link up. Without staggered
        // spin-up an empty port is skipped at once; with it, the device
        // was only just told to spin up, so DET 0 does not mean empty yet.
        let link = || {
            let mut det = 0;
            wait(clock, PHY_NS, PHY_POLLS, || {
                det = r(SSTS) & DET_MASK;
                det == DET_ESTABLISHED || (det == 0 && !spin_up)
            });
            det
        };
        let mut det = link();
        // A device that never finishes negotiating, or a PHY left offline,
        // gets one COMRESET.
        if det == DET_PRESENT || det == DET_OFFLINE {
            comreset(io, base, clock);
            det = link();
        }
        if det != DET_ESTABLISHED {
            return Ok(None);
        }

        let mem = OwnedDma::new(dma, PORT_MEM_LEN).ok_or(AhciError::NoMemory)?;
        check_dma(&mem, PORT_MEM_ALIGN, cap)?;
        let cl = mem.device_addr().as_u64() + CL_OFFSET as u64;
        let fis = mem.device_addr().as_u64() + FIS_OFFSET as u64;
        w32(io, base + CLB, cl as u32);
        w32(io, base + CLBU, (cl >> 32) as u32);
        w32(io, base + FB, fis as u32);
        w32(io, base + FBU, (fis >> 32) as u32);
        // Slot 0's header points at the one command table, for good.
        let ct = mem.device_addr().as_u64() + CT_OFFSET as u64;
        mem.store::<u32>(CL_OFFSET + 8, ct as u32);
        mem.store::<u32>(CL_OFFSET + 12, (ct >> 32) as u32);

        let mut port = Self {
            io: io.clone(),
            base,
            index,
            cap,
            clock,
            kind: DeviceKind::Other(0),
            broken: false,
            mem: ManuallyDrop::new(mem),
            data: ManuallyDrop::new(None),
        };
        // Completions are polled.
        port.w(IE, 0);
        port.clear_errors();
        port.w(CMD, port.r(CMD) | CMD_FRE);
        // The signature arrives with the device's first D2H FIS, which
        // also clears BSY.
        if port.start().is_err() {
            return Ok(None);
        }
        port.kind = DeviceKind::from(port.r(SIG));
        Ok(Some(port))
    }

    pub fn index(&self) -> u8 {
        self.index
    }

    /// Gives the port its data buffer.
    pub fn set_data(&mut self, data: OwnedDma<'d, D>) -> Result<(), AhciError> {
        // PRDs address whole words.
        check_dma(&data, 2, self.cap)?;
        *self.data = Some(data);
        Ok(())
    }

    /// The data buffer, unless the port is broken (and the HBA may still
    /// be using it). Panics if there is none.
    pub fn data(&self) -> Result<&DmaBuffer, AhciError> {
        if self.broken {
            return Err(AhciError::Broken);
        }
        Ok(self.data.as_ref().expect("port has no data buffer"))
    }

    fn r(&self, reg: usize) -> u32 {
        r32(&self.io, self.base + reg)
    }

    fn w(&self, reg: usize, v: u32) {
        w32(&self.io, self.base + reg, v)
    }

    fn poll(&self, mut done: impl FnMut(&Self) -> bool) -> Result<(), AhciError> {
        for _ in 0..POLL_LIMIT {
            if done(self) {
                return Ok(());
            }
            osmium_arch::cpu::spin_hint();
        }
        Err(AhciError::Timeout)
    }

    /// Clears PxSERR and PxIS (both write-1-to-clear).
    fn clear_errors(&self) {
        self.w(SERR, self.r(SERR));
        self.w(IS, self.r(IS));
    }

    /// Sets PxCMD.ST once the device is idle. FRE must be set already.
    fn start(&self) -> Result<(), AhciError> {
        self.poll(|p| p.r(TFD) & (STS_BSY | STS_DRQ) == 0)?;
        self.w(CMD, self.r(CMD) | CMD_ST);
        Ok(())
    }

    /// Runs `cmd` in slot 0 and waits for it, over the first `cmd.len`
    /// bytes of the data buffer. A failed command leaves the port
    /// recovered and ready for the next one or, if recovery fails, broken.
    pub fn exec(&mut self, cmd: Command) -> Result<(), AhciError> {
        if self.broken {
            return Err(AhciError::Broken);
        }
        let data = if cmd.len == 0 { None } else { Some(self.data()?.device_addr().as_u64()) };
        let mem = &self.mem;
        let mut fis = [0u8; 20];
        fis[0] = FIS_REG_H2D;
        fis[1] = FIS_COMMAND;
        fis[2] = cmd.command;
        let lba = cmd.lba.to_le_bytes();
        fis[4..7].copy_from_slice(&lba[..3]);
        fis[7] = cmd.device;
        fis[8..11].copy_from_slice(&lba[3..6]);
        fis[12..14].copy_from_slice(&cmd.count.to_le_bytes());
        mem.write(CT_OFFSET, &fis);

        let prds = if data.is_some() { 1 } else { 0 };
        if let Some(data) = data {
            debug_assert!(cmd.len <= PRD_MAX && cmd.len % 2 == 0);
            mem.store::<u32>(PRDT_OFFSET, data as u32);
            mem.store::<u32>(PRDT_OFFSET + 4, (data >> 32) as u32);
            mem.store::<u32>(PRDT_OFFSET + 8, 0);
            mem.store::<u32>(PRDT_OFFSET + 12, cmd.len as u32 - 1);
        }
        let write = if cmd.write { HDR_WRITE } else { 0 };
        mem.store::<u32>(CL_OFFSET, prds << 16 | write | FIS_H2D_DWORDS);
        // PRD byte count, which the HBA updates.
        mem.store::<u32>(CL_OFFSET + 4, 0);

        self.w(IS, self.r(IS));
        barrier::mb();
        self.w(CI, 1);
        let mut failed = false;
        let done = self.poll(|p| {
            failed = p.r(IS) & IS_ERRORS != 0;
            failed || p.r(CI) & 1 == 0
        });
        barrier::dma_rmb();
        let tfd = self.r(TFD);
        let result = match done {
            Err(e) => Err(e),
            Ok(()) if failed || tfd & STS_ERR != 0 => {
                Err(AhciError::Device { status: tfd as u8, error: (tfd >> 8) as u8 })
            }
            // Data in must all have arrived, or the buffer is partly stale.
            Ok(()) if !cmd.write && mem.load::<u32>(CL_OFFSET + 4) != cmd.len as u32 => Err(AhciError::ShortTransfer),
            Ok(()) => Ok(()),
        };
        if result.is_err() && self.recover().is_err() {
            // The error to report is still the command's.
            self.broken = true;
        }
        result
    }

    /// Non-queued error recovery (AHCI 1.3.1 §6.2.2.2): stop the command
    /// engine, which also abandons the failed command, clear the errors,
    /// free the task file if the device still holds it, and start again.
    fn recover(&self) -> Result<(), AhciError> {
        self.w(CMD, self.r(CMD) & !CMD_ST);
        self.poll(|p| p.r(CMD) & CMD_CR == 0)?;
        self.clear_errors();
        if self.r(TFD) & (STS_BSY | STS_DRQ) != 0 {
            if self.cap & cap::SCLO != 0 {
                self.w(CMD, self.r(CMD) | CMD_CLO);
                self.poll(|p| p.r(CMD) & CMD_CLO == 0)?;
            } else {
                comreset(&self.io, self.base, self.clock);
                self.poll(|p| p.r(SSTS) & DET_MASK == DET_ESTABLISHED)?;
                self.clear_errors();
            }
        }
        self.start()
    }
}

impl<D: DmaAllocator + ?Sized> Drop for Port<'_, D> {
    fn drop(&mut self) {
        if stop(&self.io, self.base).is_ok() {
            // SAFETY: dropped once, here; the port no longer uses them.
            unsafe {
                ManuallyDrop::drop(&mut self.data);
                ManuallyDrop::drop(&mut self.mem);
            }
        }
    }
}

/// Stops the port at `base`: the command engine (ST, then wait for CR) and
/// then FIS receive (FRE, then wait for FR).
fn stop(io: &IoMem, base: usize) -> Result<(), AhciError> {
    let r = |reg| r32(io, base + reg);
    let wait = |bit| {
        for _ in 0..POLL_LIMIT {
            if r(CMD) & bit == 0 {
                return Ok(());
            }
            osmium_arch::cpu::spin_hint();
        }
        Err(AhciError::Timeout)
    };
    w32(io, base + CMD, r(CMD) & !CMD_ST);
    wait(CMD_CR)?;
    w32(io, base + CMD, r(CMD) & !CMD_FRE);
    wait(CMD_FR)
}

/// Resets the link at `base`, and the device on it, by holding COMRESET
/// for long enough. The port must be stopped; the link comes back up
/// later.
fn comreset(io: &IoMem, base: usize, clock: Option<&dyn Clock>) {
    let sctl = r32(io, base + SCTL) & !DET_MASK;
    w32(io, base + SCTL, sctl | DET_COMRESET);
    wait(clock, COMRESET_NS, COMRESET_POLLS, || {
        let _ = r32(io, base + SSTS);
        false
    });
    w32(io, base + SCTL, sctl);
}

/// Polls `done` until it holds, for at most `ns` by `clock` or, without
/// one, `polls` times. True if it held.
fn wait(clock: Option<&dyn Clock>, ns: u64, polls: u32, mut done: impl FnMut() -> bool) -> bool {
    let deadline = clock.map(|c| c.now_ns().saturating_add(ns));
    let mut n = 0;
    loop {
        if done() {
            return true;
        }
        n += 1;
        match (clock, deadline) {
            (Some(c), Some(end)) if c.now_ns() > end => return false,
            (None, _) if n >= polls => return false,
            _ => osmium_arch::cpu::spin_hint(),
        }
    }
}

/// Checks that the HBA can reach `buf`: aligned to `align`, and below
/// 4 GiB unless it does 64-bit addressing.
fn check_dma(buf: &DmaBuffer, align: u64, cap: u32) -> Result<(), AhciError> {
    let start = buf.device_addr().as_u64();
    let end = start + buf.len() as u64;
    if !start.is_multiple_of(align) || (cap & cap::S64A == 0 && end > 1 << 32) {
        return Err(AhciError::BadDmaAddress);
    }
    Ok(())
}
