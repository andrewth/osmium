//! AHCI: SATA disks behind an Advanced Host Controller Interface HBA (PCI
//! class 01/06/01), such as Intel's ICH and QEMU's `ahci` device.
//!
//! [`Ahci::new`] takes the HBA's registers (ABAR, PCI BAR 5), switches the
//! HBA to AHCI mode, claims it from firmware and probes every implemented
//! port: a port with a device on its link gets a command list, a
//! received-FIS area and one command table, and its command engine is
//! started. [`Ahci::take_disk`] then turns a port with a SATA disk into an
//! [`AhciDisk`], a [`BlockDevice`](osmium_hal::block::BlockDevice) that owns
//! its port outright, so each disk can live on its own (in a static, say)
//! after the [`Ahci`] is gone.
//!
//! As with virtio-blk, everything is polled and synchronous: each port runs
//! one command at a time, in command slot 0, with data bounced through a
//! DMA buffer of [`DATA_LEN`] bytes (larger transfers are split). Reads and
//! writes use the 48-bit DMA commands. A command that fails, or does not
//! finish, is reported as an I/O error after the port is recovered, so
//! later commands still work.
//!
//! The caller enables memory decoding and bus mastering on the PCI
//! function. The [`DmaAllocator`] must hand out 1 KiB-aligned memory (any
//! page allocator does), below 4 GiB if the HBA lacks 64-bit addressing.
//! Waits on the hardware are bounded by a poll count, not a clock.
//!
//! Not yet supported: interrupts, native command queuing, port
//! multipliers, ATAPI devices, hot plug, and disks without 48-bit LBA.

mod disk;
mod port;

#[cfg(test)]
mod fake;

use osmium_hal::dma::DmaAllocator;
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::Class;

pub use disk::{AhciDisk, DATA_LEN};
pub use port::DeviceKind;
use port::{PORT_BASE, PORT_STRIDE, Port};

/// The PCI class of an AHCI HBA (01/06/01).
pub const CLASS: Class = Class { class: 0x01, subclass: 0x06, prog_if: 0x01 };

/// The BAR holding the HBA's registers (ABAR).
pub const ABAR: u8 = 5;

/// Ports per HBA, at most.
pub const MAX_PORTS: usize = 32;

// Generic host control registers.
const CAP: usize = 0x00;
const GHC: usize = 0x04;
const HBA_IS: usize = 0x08;
const PI: usize = 0x0c;
const VS: usize = 0x10;
const CAP2: usize = 0x24;
const BOHC: usize = 0x28;

/// CAP bits.
mod cap {
    /// 64-bit addressing.
    pub const S64A: u32 = 1 << 31;
    /// Staggered spin-up: ports start with their devices spun down.
    pub const SSS: u32 = 1 << 27;
    /// Command list override, to free a stuck task file.
    pub const SCLO: u32 = 1 << 24;
}

const GHC_IE: u32 = 1 << 1;
const GHC_AE: u32 = 1 << 31;
const CAP2_BOH: u32 = 1 << 0;
const BOHC_BOS: u32 = 1 << 0;
const BOHC_OOS: u32 = 1 << 1;
const BOHC_BB: u32 = 1 << 4;

/// Polls of a register before a wait on the HBA gives up.
const POLL_LIMIT: u32 = if cfg!(test) { 10_000 } else { 20_000_000 };

/// Why bringing up the HBA or a disk failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AhciError {
    /// The register window is too small for the ports the HBA implements.
    BadRegisters,
    /// DMA memory could not be allocated.
    NoMemory,
    /// DMA memory is misaligned, or above 4 GiB on an HBA without 64-bit
    /// addressing.
    BadDmaAddress,
    /// The HBA or the device did not finish in time.
    Timeout,
    /// No device on that port, no such port, or its disk is already taken.
    NoDevice,
    /// The device is not a disk this driver handles: not ATA (an ATAPI
    /// drive, say), no 48-bit LBA, or an odd sector size.
    Unsupported,
    /// The device failed a command, with these ATA status and error
    /// register values.
    Device {
        /// ATA status.
        status: u8,
        /// ATA error (bit 2 aborted, bit 4 ID not found, bit 6 uncorrectable).
        error: u8,
    },
}

/// Reads the 32-bit register at `off`; all ones if outside the window.
fn r32(io: &IoMem, off: usize) -> u32 {
    #[cfg(test)]
    if off + 4 <= io.len() {
        fake::before_read(off);
    }
    io.read::<u32>(off).unwrap_or(!0)
}

fn w32(io: &IoMem, off: usize, v: u32) {
    let _written = io.write(off, v);
    #[cfg(test)]
    if _written.is_ok() {
        fake::after_write(off, v);
    }
}

/// An AHCI HBA and the ports it has not handed out as disks. Dropping it
/// stops those ports and frees their memory; disks already taken keep
/// working.
pub struct Ahci<'d, D: DmaAllocator + ?Sized> {
    io: IoMem,
    dma: &'d D,
    cap: u32,
    pi: u32,
    version: u32,
    ports: [Option<Port<'d, D>>; MAX_PORTS],
}

impl<'d, D: DmaAllocator + ?Sized> Ahci<'d, D> {
    /// Initializes the HBA whose registers `io` maps (ABAR) and probes its
    /// ports, allocating their memory from `dma`. A port whose device never
    /// becomes ready is left stopped and reports no device.
    pub fn new(io: IoMem, dma: &'d D) -> Result<Self, AhciError> {
        if io.len() < PORT_BASE {
            return Err(AhciError::BadRegisters);
        }
        // AHCI mode first: until then the other registers may not respond.
        w32(&io, GHC, r32(&io, GHC) | GHC_AE);
        if r32(&io, CAP2) & CAP2_BOH != 0 {
            take_from_firmware(&io);
        }
        w32(&io, GHC, (r32(&io, GHC) | GHC_AE) & !GHC_IE);
        let cap = r32(&io, CAP);
        let pi = r32(&io, PI);
        let ports_len = PORT_BASE + PORT_STRIDE * (MAX_PORTS - pi.leading_zeros() as usize);
        if io.len() < ports_len {
            return Err(AhciError::BadRegisters);
        }

        let mut hba = Self { version: r32(&io, VS), io, dma, cap, pi, ports: core::array::from_fn(|_| None) };
        for i in 0..MAX_PORTS {
            if pi & 1 << i != 0 {
                hba.ports[i] = match Port::probe(&hba.io, i as u8, cap, dma) {
                    Err(AhciError::Timeout) => None,
                    other => other?,
                };
            }
        }
        w32(&hba.io, HBA_IS, r32(&hba.io, HBA_IS));
        Ok(hba)
    }

    /// The AHCI version (VS): major in bits 31:16, minor in 15:0, e.g.
    /// `0x0001_0300` for 1.3.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The HBA's capabilities (CAP).
    pub fn capabilities(&self) -> u32 {
        self.cap
    }

    /// Bit `n` set if port `n` exists (PI).
    pub fn ports_implemented(&self) -> u32 {
        self.pi
    }

    /// True if the HBA can reach memory above 4 GiB.
    pub fn supports_64bit(&self) -> bool {
        self.cap & cap::S64A != 0
    }

    /// What is attached to `port`; `None` if nothing is, or its disk has
    /// been taken.
    pub fn device(&self, port: u8) -> Option<DeviceKind> {
        self.ports.get(port as usize)?.as_ref().map(|p| p.kind)
    }

    /// Ports with a SATA disk not yet taken, lowest first.
    pub fn disks(&self) -> impl Iterator<Item = u8> + '_ {
        (0..MAX_PORTS as u8).filter(|&p| self.device(p) == Some(DeviceKind::Ata))
    }

    /// Takes the disk on `port`: identifies it and returns a block device
    /// that owns the port from now on. If identification fails, the port
    /// is stopped and stays unavailable.
    pub fn take_disk(&mut self, port: u8) -> Result<AhciDisk<'d, D>, AhciError> {
        let slot = self.ports.get_mut(port as usize).ok_or(AhciError::NoDevice)?;
        match slot.as_ref().map(|p| p.kind) {
            None => return Err(AhciError::NoDevice),
            Some(DeviceKind::Ata) => {}
            Some(_) => return Err(AhciError::Unsupported),
        }
        AhciDisk::new(slot.take().expect("checked above"), self.dma)
    }
}

/// Asks firmware to give up the HBA (AHCI 1.3.1 §10.6.3), waiting a while
/// for it to finish whatever it was doing. Firmware that never lets go
/// keeps it; the driver carries on anyway.
fn take_from_firmware(io: &IoMem) {
    w32(io, BOHC, r32(io, BOHC) | BOHC_OOS);
    let poll = |done: &dyn Fn(u32) -> bool| (0..POLL_LIMIT).any(|_| done(r32(io, BOHC)));
    if poll(&|b| b & BOHC_BOS == 0) {
        return;
    }
    // Firmware that is mid-command sets BB and gets longer to finish.
    if r32(io, BOHC) & BOHC_BB != 0 {
        poll(&|b| b & BOHC_BOS == 0);
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{self, FakeDev, FakeHba};
    use super::port::{CLB, CMD, CMD_FR, CMD_FRE, CMD_ST, PORT_MEM_LEN};
    use super::*;
    use crate::virtio::testing::HostDma;

    #[test]
    fn init_probes_ports() {
        let mut hba = FakeHba::new(4);
        hba.pi = 0b0111; // port 3 is not implemented
        hba.bios_owned = true;
        hba.attach(0, FakeDev::disk(100, 512));
        hba.attach(2, FakeDev::Atapi);
        hba.attach(3, FakeDev::disk(100, 512));
        // Firmware left port 0 running.
        hba.running(0);
        let io = fake::install(hba);
        let dma = HostDma::default();
        let mut ahci = Ahci::new(io, &dma).unwrap();
        fake::with(|f| {
            assert!(f.handed_off, "firmware was asked to let go");
            assert_eq!(f.ghc() & (GHC_AE | GHC_IE), GHC_AE);
            assert_eq!(f.port_reg(0, CMD) & (CMD_ST | CMD_FRE), CMD_ST | CMD_FRE);
            assert_ne!(f.port_reg(0, CLB), 0);
            assert_eq!(f.port_reg(1, CMD) & (CMD_ST | CMD_FRE), 0, "nothing on port 1");
            assert_eq!(f.port_reg(3, CLB), 0, "port 3 untouched");
        });
        assert_eq!(ahci.version(), 0x0001_0300);
        assert!(ahci.supports_64bit());
        assert_eq!(ahci.ports_implemented(), 0b0111);
        assert_eq!(
            (0..5).map(|p| ahci.device(p)).collect::<std::vec::Vec<_>>(),
            [Some(DeviceKind::Ata), None, Some(DeviceKind::Atapi), None, None]
        );
        assert!(ahci.disks().eq([0]));
        assert_eq!(dma.live.get(), 2, "memory for ports 0 and 2");

        assert_eq!(ahci.take_disk(1).err(), Some(AhciError::NoDevice));
        assert_eq!(ahci.take_disk(2).err(), Some(AhciError::Unsupported));
        assert_eq!(ahci.take_disk(3).err(), Some(AhciError::NoDevice));
        assert_eq!(ahci.take_disk(99).err(), Some(AhciError::NoDevice));
        drop(ahci);
        assert_eq!(dma.live.get(), 0);
        fake::with(|f| {
            for p in 0..4 {
                assert_eq!(f.port_reg(p, CMD) & (CMD_ST | CMD_FRE | CMD_FR), 0, "port {p} stopped");
            }
        });
        fake::uninstall();
    }

    #[test]
    fn needs_64bit_addressing_for_high_memory() {
        let dma = HostDma::default();
        let probe = std::boxed::Box::new([0u8; PORT_MEM_LEN]);
        if (probe.as_ptr() as u64) < 1 << 32 {
            return; // the host heap is low; nothing to test
        }
        let mut hba = FakeHba::new(2);
        hba.cap &= !cap::S64A;
        hba.attach(0, FakeDev::disk(8, 512));
        hba.attach(1, FakeDev::disk(8, 512));
        let io = fake::install(hba);
        assert_eq!(Ahci::new(io, &dma).err(), Some(AhciError::BadDmaAddress));
        assert_eq!(dma.live.get(), 0);
        fake::with(|f| assert_eq!(f.port_reg(0, CMD) & (CMD_ST | CMD_FRE), 0));
        fake::uninstall();
    }

    #[test]
    fn bad_register_window() {
        let dma = HostDma::default();
        let mut hba = FakeHba::new(4);
        hba.attach(3, FakeDev::disk(8, 512));
        let io = fake::install(hba);
        let short = io.slice(0, PORT_BASE + 3 * PORT_STRIDE).unwrap();
        assert_eq!(Ahci::new(short, &dma).err(), Some(AhciError::BadRegisters));
        assert_eq!(Ahci::new(io.slice(0, 0x80).unwrap(), &dma).err(), Some(AhciError::BadRegisters));
        assert!(Ahci::new(io, &dma).is_ok());
        assert_eq!(dma.live.get(), 0);
        fake::uninstall();
    }

    #[test]
    fn unresponsive_device_is_skipped() {
        let dma = HostDma::default();
        let mut hba = FakeHba::new(2);
        hba.attach(0, FakeDev::disk(8, 512));
        hba.attach(1, FakeDev::disk(8, 512));
        hba.ports[0].busy_forever = true;
        let io = fake::install(hba);
        let ahci = Ahci::new(io, &dma).unwrap();
        assert!(ahci.disks().eq([1]));
        assert_eq!(dma.live.get(), 1, "the skipped port's memory is freed");
        drop(ahci);
        fake::uninstall();
    }

    #[test]
    fn a_port_that_will_not_stop_leaks_its_memory() {
        let dma = HostDma::default();
        let mut hba = FakeHba::new(1);
        hba.attach(0, FakeDev::disk(8, 512));
        let io = fake::install(hba);
        let ahci = Ahci::new(io, &dma).unwrap();
        fake::with(|f| f.ports[0].wont_stop = true);
        drop(ahci);
        assert_eq!(dma.live.get(), 1, "not freed under a running HBA");
        fake::uninstall();
    }
}
