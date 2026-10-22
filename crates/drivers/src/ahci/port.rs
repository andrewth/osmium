//! One HBA port: its registers, its DMA memory (command list, received-FIS
//! area, a command table per slot), and running commands through its slots:
//! one at a time through slot 0, or several queued (NCQ) at once.

use core::mem::ManuallyDrop;

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;

use super::disk::{NCQ_ERROR_LOG, READ_LOG_EXT};
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
pub(super) const SACT: usize = 0x34;
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
/// PxIS: a D2H register FIS arrived (a command finished).
pub(super) const IS_DHRS: u32 = 1 << 0;
/// PxIS: a set-device-bits FIS arrived (queued commands finished).
pub(super) const IS_SDBS: u32 = 1 << 3;
/// The PxIE bits armed while a command is waited for: its completions and
/// the errors.
const IE_WAIT: u32 = IS_DHRS | IS_SDBS | IS_ERRORS;

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

/// Command slots the driver uses, at most (the HBA may have up to 32).
pub(super) const MAX_SLOTS: usize = 8;

// Port memory: the command list (32 headers of 32 bytes, 1 KiB aligned),
// the received-FIS area (256 bytes, 256 aligned) and a command table
// (128 aligned) per slot, each with its single PRD entry and room for an
// ATAPI packet.
pub(super) const CL_OFFSET: usize = 0;
pub(super) const FIS_OFFSET: usize = 0x400;
pub(super) const CT_OFFSET: usize = 0x500;
const CT_STRIDE: usize = 0x100;
/// The ATAPI command, in the command table.
const ACMD_OFFSET: usize = 0x40;
/// The PRD table, in the command table.
const PRDT_IN_CT: usize = 0x80;
pub(super) const PORT_MEM_LEN: usize = CT_OFFSET + MAX_SLOTS * CT_STRIDE;

const fn header(slot: usize) -> usize {
    CL_OFFSET + 32 * slot
}

const fn table(slot: usize) -> usize {
    CT_OFFSET + CT_STRIDE * slot
}
/// Alignment the port memory needs (the command list's).
pub(super) const PORT_MEM_ALIGN: u64 = 1024;

// Command header DW0 (the FIS length in dwords is bits 4:0).
pub(super) const HDR_ATAPI: u32 = 1 << 5;
pub(super) const HDR_WRITE: u32 = 1 << 6;

/// Register host-to-device FIS: type and length in dwords.
pub(super) const FIS_REG_H2D: u8 = 0x27;
const FIS_H2D_DWORDS: u32 = 5;
/// The H2D FIS's "this is a command" bit (byte 1).
pub(super) const FIS_COMMAND: u8 = 0x80;

/// Largest byte count of one PRD entry.
pub(super) const PRD_MAX: usize = 4 << 20;

/// One ATA command to run in a slot.
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Command {
    pub command: u8,
    /// The features register (the sector count of a queued command).
    pub features: u16,
    pub lba: u64,
    pub count: u16,
    /// The device register (0x40 selects LBA addressing).
    pub device: u8,
    /// Bytes of the data buffer to transfer (0 for none).
    pub len: usize,
    /// True if the data goes to the device.
    pub write: bool,
    /// Where in the data buffer the transfer starts.
    pub data_off: usize,
    /// The ATAPI command packet, for a PACKET command.
    pub packet: Option<[u8; 16]>,
}

/// What a port has attached, from its signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceKind {
    /// A SATA disk (signature 0000_0101).
    Ata,
    /// A packet device, such as an optical drive (EB14_0101).
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
    /// Command slots in use (1 unless the disk does NCQ).
    slots: usize,
    /// What a waiter does between polls, with the port's interrupts armed;
    /// `None` polls.
    idle: Option<fn()>,
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
        // Each slot's header points at its command table, for good.
        for slot in 0..MAX_SLOTS {
            let ct = mem.device_addr().as_u64() + table(slot) as u64;
            mem.store::<u32>(header(slot) + 8, ct as u32);
            mem.store::<u32>(header(slot) + 12, (ct >> 32) as u32);
        }

        let mut port = Self {
            io: io.clone(),
            base,
            index,
            cap,
            clock,
            kind: DeviceKind::Other(0),
            broken: false,
            slots: 1,
            idle: None,
            mem: ManuallyDrop::new(mem),
            data: ManuallyDrop::new(None),
        };
        // Completions are polled until `set_idle`.
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

    /// Command slots the HBA offers and the driver would use.
    pub fn max_slots(&self) -> usize {
        ((self.cap >> 8 & 0x1f) as usize + 1).min(MAX_SLOTS)
    }

    /// True if the HBA supports native command queuing (CAP.SNCQ).
    pub fn hba_ncq(&self) -> bool {
        self.cap & cap::SNCQ != 0
    }

    /// Uses `slots` command slots, at most [`Port::max_slots`].
    pub fn set_slots(&mut self, slots: usize) {
        assert!((1..=self.max_slots()).contains(&slots));
        self.slots = slots;
    }

    /// Waits for completions by calling `idle` with the port's interrupts
    /// armed, rather than spinning; `None` goes back to polling.
    pub fn set_idle(&mut self, idle: Option<fn()>) {
        self.idle = idle;
        if idle.is_none() {
            self.w(IE, 0);
            self.w(IS, self.r(IS));
            w32(&self.io, super::HBA_IS, 1 << self.index);
        }
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

    /// Writes `cmd` into `slot`'s command table and header.
    fn build(&self, slot: usize, cmd: &Command) -> Result<(), AhciError> {
        let data = match cmd.len {
            0 => None,
            len => {
                let buf = self.data()?;
                match cmd.data_off.checked_add(len) {
                    Some(end) if end <= buf.len() => Some(buf.device_addr().as_u64() + cmd.data_off as u64),
                    _ => return Err(AhciError::Unsupported),
                }
            }
        };
        let mem = &self.mem;
        let ct = table(slot);
        let mut fis = [0u8; 20];
        fis[0] = FIS_REG_H2D;
        fis[1] = FIS_COMMAND;
        fis[2] = cmd.command;
        fis[3] = cmd.features as u8;
        let lba = cmd.lba.to_le_bytes();
        fis[4..7].copy_from_slice(&lba[..3]);
        fis[7] = cmd.device;
        fis[8..11].copy_from_slice(&lba[3..6]);
        fis[11] = (cmd.features >> 8) as u8;
        fis[12..14].copy_from_slice(&cmd.count.to_le_bytes());
        mem.write(ct, &fis);
        if let Some(packet) = &cmd.packet {
            mem.write(ct + ACMD_OFFSET, packet);
        }

        let prds = if data.is_some() { 1 } else { 0 };
        if let Some(data) = data {
            debug_assert!(cmd.len <= PRD_MAX && cmd.len % 2 == 0);
            let prd = ct + PRDT_IN_CT;
            mem.store::<u32>(prd, data as u32);
            mem.store::<u32>(prd + 4, (data >> 32) as u32);
            mem.store::<u32>(prd + 8, 0);
            mem.store::<u32>(prd + 12, cmd.len as u32 - 1);
        }
        let write = if cmd.write { HDR_WRITE } else { 0 };
        let atapi = if cmd.packet.is_some() { HDR_ATAPI } else { 0 };
        mem.store::<u32>(header(slot), prds << 16 | atapi | write | FIS_H2D_DWORDS);
        // PRD byte count, which the HBA updates.
        mem.store::<u32>(header(slot) + 4, 0);
        Ok(())
    }

    /// Clears the port's stale status before commands are issued.
    fn begin(&self) {
        self.w(IS, self.r(IS));
        if self.idle.is_some() {
            w32(&self.io, super::HBA_IS, 1 << self.index);
        }
    }

    /// Waits until none of the `mask` slots is outstanding (in PxSACT if
    /// `queued`, else PxCI) or the port reports an error. Returns whether
    /// it did, and whether the error bits were set.
    ///
    /// With an idle hook, a wait that is not yet over arms the port's
    /// interrupts and looks again before the hook runs, so a completion that
    /// lands in between wakes the hook instead of being slept through. The
    /// interrupt handler masks the port again ([`super::AhciIrq`]), which
    /// is why the arming repeats. A finished command is seen before the
    /// arming, so its status bits never raise an interrupt nobody waits for.
    fn wait_slots(&self, mask: u32, queued: bool) -> (Result<(), AhciError>, bool) {
        let reg = if queued { SACT } else { CI };
        let look = || {
            let failed = self.r(IS) & IS_ERRORS != 0;
            (failed || self.r(reg) & mask == 0).then_some(failed)
        };
        for _ in 0..POLL_LIMIT {
            if let Some(failed) = look() {
                return (Ok(()), failed);
            }
            match self.idle {
                Some(idle) => {
                    self.w(IE, IE_WAIT);
                    if let Some(failed) = look() {
                        return (Ok(()), failed);
                    }
                    idle();
                }
                None => osmium_arch::cpu::spin_hint(),
            }
        }
        (Err(AhciError::Timeout), false)
    }

    /// Disarms the port's interrupts once a wait is over. A failure's
    /// status is left for recovery to clear.
    fn finish(&self, failed: bool) {
        if self.idle.is_some() {
            self.w(IE, 0);
            if !failed {
                self.w(IS, self.r(IS));
                w32(&self.io, super::HBA_IS, 1 << self.index);
            }
        }
    }

    /// The error a finished wait amounts to, if any.
    fn outcome(&self, done: Result<(), AhciError>, failed: bool) -> Result<(), AhciError> {
        let tfd = self.r(TFD);
        match done {
            Err(e) => Err(e),
            Ok(()) if failed || tfd & STS_ERR != 0 => {
                Err(AhciError::Device { status: tfd as u8, error: (tfd >> 8) as u8 })
            }
            Ok(()) => Ok(()),
        }
    }

    /// Whether data in to `slot` all arrived, or the buffer is partly stale.
    ///
    /// The byte count the device leaves in the command header is cleared
    /// when the command is built. A queued command's count is optional
    /// (AHCI 1.3.1 §5.3.2 only requires it for the others, and QEMU leaves
    /// it at zero), so for those a zero means "not reported" and only a
    /// different, non-zero count is a short transfer.
    fn check_transferred(&self, slot: usize, cmd: &Command, queued: bool) -> Result<(), AhciError> {
        if cmd.write {
            return Ok(());
        }
        let done = self.mem.load::<u32>(header(slot) + 4);
        if done == cmd.len as u32 || (queued && done == 0) { Ok(()) } else { Err(AhciError::ShortTransfer) }
    }

    /// Runs `cmd` in slot 0 and waits for it, with no recovery.
    fn run(&self, cmd: &Command) -> Result<(), AhciError> {
        self.build(0, cmd)?;
        self.begin();
        barrier::mb();
        self.w(CI, 1);
        let (done, failed) = self.wait_slots(1, false);
        self.finish(failed);
        barrier::dma_rmb();
        self.outcome(done, failed)?;
        self.check_transferred(0, cmd, false)
    }

    /// Runs `cmd` in slot 0 and waits for it, over `cmd.len` bytes of the
    /// data buffer. A failed command leaves the port recovered and ready
    /// for the next one or, if recovery fails, broken.
    pub fn exec(&mut self, cmd: Command) -> Result<(), AhciError> {
        if self.broken {
            return Err(AhciError::Broken);
        }
        let result = self.run(&cmd);
        // A command that never reached the HBA needs no recovery.
        if result.is_err() && !matches!(result, Err(AhciError::Unsupported)) && self.recover(false).is_err() {
            // The error to report is still the command's.
            self.broken = true;
        }
        result
    }

    /// Issues `cmds` as native queued commands, command `i` in slot (and
    /// tag) `i`, and waits for all of them. The HBA and device then have
    /// them all in flight at once. Any failure fails the lot: the port is
    /// recovered, and the device's NCQ error state cleared, before this
    /// returns.
    pub fn exec_queued(&mut self, cmds: &[Command]) -> Result<(), AhciError> {
        if self.broken {
            return Err(AhciError::Broken);
        }
        assert!(!cmds.is_empty() && cmds.len() <= self.slots);
        for (slot, cmd) in cmds.iter().enumerate() {
            self.build(slot, cmd)?;
        }
        let mask = ((1u64 << cmds.len()) - 1) as u32;
        self.begin();
        barrier::mb();
        // PxSACT first: the device must know the tags when the commands go.
        self.w(SACT, mask);
        self.w(CI, mask);
        let (done, failed) = self.wait_slots(mask, true);
        self.finish(failed);
        barrier::dma_rmb();
        let result = self
            .outcome(done, failed)
            .and_then(|()| cmds.iter().enumerate().try_for_each(|(slot, cmd)| self.check_transferred(slot, cmd, true)));
        if let Err(e) = result
            && self.recover(matches!(e, AhciError::Device { .. })).is_err()
        {
            self.broken = true;
        }
        result
    }

    /// Error recovery (AHCI 1.3.1 §6.2.2): stop the command engine, which
    /// also abandons the failed commands, clear the errors, free the task
    /// file if the device still holds it, and start again. After a queued
    /// command failed, the device also refuses everything but READ LOG EXT
    /// until its NCQ error log (page 10h) has been read.
    fn recover(&self, read_ncq_log: bool) -> Result<(), AhciError> {
        self.w(CMD, self.r(CMD) & !CMD_ST);
        self.poll(|p| p.r(CMD) & CMD_CR == 0)?;
        self.clear_errors();
        w32(&self.io, super::HBA_IS, 1 << self.index);
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
        self.start()?;
        if read_ncq_log {
            let log = Command { command: READ_LOG_EXT, lba: NCQ_ERROR_LOG, count: 1, len: 512, ..Command::default() };
            if let Err(e) = self.run(&log) {
                // The device is in an unknown state; the next recovery
                // (or the caller's) finds the engine stopped.
                self.w(CMD, self.r(CMD) & !CMD_ST);
                return Err(e);
            }
        }
        Ok(())
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
