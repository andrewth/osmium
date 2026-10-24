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
//! As with virtio-blk, calls are synchronous: they return when the
//! command has finished. By default each port runs one command at a time,
//! in command slot 0, with data bounced through a DMA buffer of
//! [`DATA_LEN`] bytes (larger transfers are split), and completions are
//! polled. Reads and writes use the 48-bit DMA commands. A command that
//! fails, or does not finish, is reported as an I/O error after the port is
//! recovered, so later commands still work.
//!
//! **Interrupts.** [`Ahci::enable_interrupts`] turns on the HBA's interrupt
//! line, [`AhciDisk::enable_interrupts`] makes one disk wait for a command
//! by sleeping (in a function the caller supplies, typically a `wfi`/`hlt`)
//! with that port's interrupts armed rather than spinning, and the kernel's
//! interrupt handler calls [`AhciIrq::handle`]. The handler only masks the
//! interrupting ports; the waiter reads the completion from the port's
//! registers, so no state is shared and no completion is lost. It works the
//! same from INTx or a message-signalled interrupt: for MSI, enable it on
//! the PCI function with [`osmium_hal::pci::Function::msi`] (one vector is
//! enough: the HBA then sends it for every port) and route that vector to
//! the handler. Without `enable_interrupts` nothing changes: completions
//! are polled.
//!
//! **NCQ.** When both the HBA (CAP.SNCQ) and the disk support it, a disk
//! uses the FPDMA QUEUED commands, and a transfer of more than one chunk
//! keeps up to [`MAX_QUEUE`] chunks in flight, each in its own slot with its
//! own part of the bounce buffer ([`AhciDisk::queue_depth`]). A failure
//! anywhere in a queued round fails the whole call, after the port is
//! recovered and the device's NCQ error log read.
//!
//! **ATAPI.** [`Ahci::take_atapi`] turns a packet device (an optical drive)
//! into an [`AhciAtapi`], a read-only [`BlockDevice`](osmium_hal::block::BlockDevice) over the disc's
//! 2048-byte blocks, using IDENTIFY PACKET DEVICE and the PACKET command
//! with READ(10) and READ CAPACITY(10), so `osmium_fs_iso9660` can mount it.
//!
//! The caller enables memory decoding and bus mastering on the PCI
//! function. The [`DmaAllocator`] must hand out 1 KiB-aligned memory (any
//! page allocator does), below 4 GiB if the HBA lacks 64-bit addressing.
//! Waits on the hardware are bounded by a poll count, except the ones the
//! link protocol times (holding COMRESET, waiting for the PHY), which use
//! the [`Clock`] given to [`Ahci::new`] or, without one, a generous poll
//! count.
//!
//! Not yet supported: port multipliers, hot plug, disks without 48-bit LBA,
//! writing or ejecting optical media, and queued or interrupt-driven ATAPI
//! commands (an [`AhciAtapi`] polls, one command at a time). Queued
//! commands are in flight within one call only: a call does not return
//! before they have all finished.

mod atapi;
mod disk;
mod port;

#[cfg(test)]
mod fake;
#[cfg(test)]
mod feature_tests;

use osmium_hal::dma::DmaAllocator;
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::Class;
use osmium_hal::timer::Clock;

pub use atapi::AhciAtapi;
pub use disk::{AhciDisk, DATA_LEN};
pub use port::DeviceKind;
use port::{IE, PORT_BASE, PORT_STRIDE, Port};

/// Most commands a disk keeps in flight with NCQ.
pub const MAX_QUEUE: usize = port::MAX_SLOTS;

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
    /// Native command queuing.
    pub const SNCQ: u32 = 1 << 30;
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
    /// The device is not one this driver handles: not ATA (for
    /// [`Ahci::take_disk`]) or not an optical ATAPI drive (for
    /// [`Ahci::take_atapi`]), no 48-bit LBA, or an odd sector size.
    Unsupported,
    /// The device moved fewer bytes than the command asked for.
    ShortTransfer,
    /// An earlier command could not be recovered from, so the port no
    /// longer runs commands.
    Broken,
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
    /// becomes ready is left stopped and reports no device. `clock`, if
    /// there is one, times the link resets.
    pub fn new(io: IoMem, dma: &'d D, clock: Option<&'d dyn Clock>) -> Result<Self, AhciError> {
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
                let probed = match Port::probe(&hba.io, i as u8, cap, dma, clock) {
                    Err(AhciError::Timeout) => None,
                    other => other?,
                };
                if let Some(slot) = hba.ports.get_mut(i) {
                    *slot = probed;
                }
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

    /// Lets the HBA raise its interrupt line (INTx or MSI, whichever the
    /// bus function routes). Only ports whose disk called
    /// [`AhciDisk::enable_interrupts`] and are waiting on a command
    /// interrupt. Stays on after this [`Ahci`] is dropped.
    pub fn enable_interrupts(&mut self) {
        w32(&self.io, HBA_IS, r32(&self.io, HBA_IS));
        w32(&self.io, GHC, r32(&self.io, GHC) | GHC_IE);
    }

    /// Stops the HBA from raising its interrupt line.
    pub fn disable_interrupts(&mut self) {
        w32(&self.io, GHC, r32(&self.io, GHC) & !GHC_IE);
    }

    /// The handle for the kernel's interrupt handler.
    pub fn irq(&self) -> AhciIrq {
        AhciIrq { io: self.io.clone(), pi: self.pi }
    }

    /// Ports with a SATA disk not yet taken, lowest first.
    pub fn disks(&self) -> impl Iterator<Item = u8> + '_ {
        (0..MAX_PORTS as u8).filter(|&p| self.device(p) == Some(DeviceKind::Ata))
    }

    /// Ports with an ATAPI drive not yet taken, lowest first.
    pub fn atapi_drives(&self) -> impl Iterator<Item = u8> + '_ {
        (0..MAX_PORTS as u8).filter(|&p| self.device(p) == Some(DeviceKind::Atapi))
    }

    /// Takes the optical drive on `port`: identifies it, reads the size of
    /// the disc in it (none is fine: 0 blocks) and returns a read-only block
    /// device that owns the port from now on. If identification fails, the
    /// port is stopped and stays unavailable.
    pub fn take_atapi(&mut self, port: u8) -> Result<AhciAtapi<'d, D>, AhciError> {
        let slot = self.ports.get_mut(port as usize).ok_or(AhciError::NoDevice)?;
        match slot.as_ref().map(|p| p.kind) {
            None => return Err(AhciError::NoDevice),
            Some(DeviceKind::Atapi) => {}
            Some(_) => return Err(AhciError::Unsupported),
        }
        let port = slot.take().ok_or(AhciError::NoDevice)?;
        AhciAtapi::new(port, self.dma)
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
        let port = slot.take().ok_or(AhciError::NoDevice)?;
        AhciDisk::new(port, self.dma)
    }
}

/// The interrupt handler's view of an HBA: [`Ahci::irq`] hands it out, and
/// it keeps working (and can be copied to the kernel's handler) while the
/// [`Ahci`] and its disks come and go. It holds no state besides the
/// registers.
#[derive(Clone)]
pub struct AhciIrq {
    io: IoMem,
    pi: u32,
}

impl AhciIrq {
    /// Services the HBA's interrupt: for every port that raised one, masks
    /// the port's interrupts (PxIE) and acknowledges the HBA's status
    /// (IS). The port's own status (PxIS) is left alone, for whoever is
    /// waiting on the port to find; the waiter re-arms the port. Returns
    /// false, touching nothing, if no port had an interrupt pending (a
    /// shared line).
    pub fn handle(&self) -> bool {
        let pending = r32(&self.io, HBA_IS) & self.pi;
        if pending == 0 {
            return false;
        }
        for port in (0..MAX_PORTS).filter(|p| pending & 1 << p != 0) {
            w32(&self.io, PORT_BASE + PORT_STRIDE * port + IE, 0);
        }
        w32(&self.io, HBA_IS, pending);
        true
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
    use super::fake::{self, FakeClock, FakeDev, FakeHba};
    use super::port::{CLB, CMD, CMD_FR, CMD_FRE, CMD_ST, CMD_SUD, PORT_MEM_LEN};
    use super::*;
    use crate::virtio::testing::HostDma;

    #[test]
    fn init_probes_ports() {
        let mut hba = FakeHba::new(4);
        hba.pi = 0b0111; // port 3 is not implemented
        hba.bios_owned = true;
        hba.attach(0, FakeDev::disk(100, 512));
        hba.attach(2, FakeDev::atapi(None));
        hba.attach(3, FakeDev::disk(100, 512));
        // Firmware left port 0 running.
        hba.running(0);
        let io = fake::install(hba);
        let dma = HostDma::default();
        let mut ahci = Ahci::new(io, &dma, None).unwrap();
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
    fn staggered_spin_up_waits_for_the_phy() {
        for clock in [None, Some(&FakeClock as &dyn Clock)] {
            let dma = HostDma::default();
            let mut hba = FakeHba::new(5);
            hba.cap |= cap::SSS;
            // A slow PHY; one stuck negotiating; one left offline; an
            // empty port; and a link in a state COMRESET is not tried on.
            for p in 0..3 {
                hba.attach(p, FakeDev::disk(8, 512));
            }
            hba.ports[0].link_reads = 50;
            hba.ports[1].stuck_det = Some(port::DET_PRESENT);
            hba.ports[2].stuck_det = Some(port::DET_OFFLINE);
            hba.attach(4, FakeDev::atapi(None));
            hba.ports[4].stuck_det = Some(7); // not a state a COMRESET fixes
            let ahci = Ahci::new(fake::install(hba), &dma, clock).unwrap();
            assert!(ahci.disks().eq([0, 1, 2]));
            assert_eq!(ahci.device(4), None);
            fake::with(|f| {
                assert_eq!(f.ports.iter().map(|p| p.comresets).collect::<std::vec::Vec<_>>(), [0, 1, 1, 0, 0]);
                for p in 0..5 {
                    assert_ne!(f.port_reg(p, CMD) & CMD_SUD, 0, "port {p} spun up");
                }
                if clock.is_some() {
                    assert!(f.ports[1].comreset_held_ns.unwrap() >= 1_000_000);
                }
            });
            drop(ahci);
            fake::uninstall();
        }

        // Without SSS a port that reads empty is empty: no waiting for it.
        let dma = HostDma::default();
        let mut hba = FakeHba::new(1);
        hba.attach(0, FakeDev::disk(8, 512));
        hba.ports[0].link_reads = 50;
        let ahci = Ahci::new(fake::install(hba), &dma, None).unwrap();
        assert_eq!(ahci.device(0), None);
        drop(ahci);
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
        assert_eq!(Ahci::new(io, &dma, None).err(), Some(AhciError::BadDmaAddress));
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
        assert_eq!(Ahci::new(short, &dma, None).err(), Some(AhciError::BadRegisters));
        assert_eq!(Ahci::new(io.slice(0, 0x80).unwrap(), &dma, None).err(), Some(AhciError::BadRegisters));
        assert!(Ahci::new(io, &dma, None).is_ok());
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
        let ahci = Ahci::new(io, &dma, None).unwrap();
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
        let ahci = Ahci::new(io, &dma, None).unwrap();
        fake::with(|f| f.ports[0].wont_stop = true);
        drop(ahci);
        assert_eq!(dma.live.get(), 1, "not freed under a running HBA");
        fake::uninstall();
    }
}
