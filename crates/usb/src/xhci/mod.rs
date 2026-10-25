//! xHCI USB host controller (eXtensible Host Controller Interface 1.2).
//!
//! [`Xhci`] brings the controller up from its MMIO registers (normally PCI
//! BAR 0, class 0c/03/30) and implements [`UsbHost`]: root-port reset, slot
//! and device-context management, and control, bulk and interrupt
//! transfers. Everything is polled: requests are submitted and the event
//! ring is read until their completion arrives, so the driver needs no
//! interrupt line. Transfers go through one bounce buffer of
//! [`BOUNCE_LEN`] bytes; longer bulk and interrupt transfers are split.
//!
//! Interrupts are optional. [`Xhci::enable_interrupts`] turns on interrupter
//! 0 for whatever the bus function routes (INTx), and
//! [`Xhci::enable_message_interrupts`] first programs MSI-X or MSI on the
//! PCI function (falling back to INTx), so the event ring wakes the kernel
//! with no one polling.
//!
//! Devices behind hubs are addressed with [`UsbHost::attach_hub_port`]: the
//! slot context gets the route string (a nibble per hub tier), the root
//! port and, for a low- or full-speed device below a high-speed hub, the
//! transaction translator's slot and port. [`UsbHost::configure_hub`] marks a
//! slot as a hub (port count, think time, multi-TT). The hub class driver is
//! in [`crate::class::hub`].
//!
//! Isochronous endpoints ([`IsochHost`]) get a transfer ring like any other
//! endpoint plus up to [`ISOCH_DEPTH`] queued one-TRB transfers of at most
//! [`ISOCH_SLOT_LEN`] bytes each, started ASAP, in a given frame or one
//! interval after the previous one.
//!
//! Not yet supported: streams, SuperSpeed burst sizes from companion
//! descriptors (so SuperSpeed isochronous runs with a burst of one),
//! isochronous transfers spanning several TRBs, warm reset of SuperSpeed hub
//! ports, and more than one interrupter.

pub mod ring;
pub mod trb;

use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::{ConfigAccess, Function, MsiError, MsiMessage};
use osmium_hal::timer::Clock;
use osmium_hal::usb::{
    DeviceId, Direction, EndpointDescriptor, IsochHost, IsochStart, PortStatus, SetupPacket, Speed, TransferType,
    UsbError, UsbHost,
};
use osmium_mm::PhysAddr;

use ring::{EventRing, ProducerRing};
use trb::{Trb, completion, kind};

use crate::usbhc::{BULK_TIMEOUT_NS, CONTROL_TIMEOUT_NS};

// Capability registers.
const CAPLENGTH_HCIVERSION: usize = 0x00;
const HCSPARAMS1: usize = 0x04;
const HCSPARAMS2: usize = 0x08;
const HCCPARAMS1: usize = 0x10;
const DBOFF: usize = 0x14;
const RTSOFF: usize = 0x18;

// Operational registers, from CAPLENGTH.
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
const PAGESIZE: usize = 0x08;
const CRCR: usize = 0x18;
const DCBAAP: usize = 0x30;
const CONFIG: usize = 0x38;
const PORTSC: usize = 0x400;
const PORT_STRIDE: usize = 0x10;

/// Command Abort: stop the command ring after aborting the running command.
const CRCR_CA: u32 = 1 << 2;
/// Command Ring Running.
const CRCR_CRR: u32 = 1 << 3;
/// HCCPARAMS1: the controller can address 64 bits of memory.
const HCC_AC64: u32 = 1 << 0;

const CMD_RUN: u32 = 1 << 0;
const CMD_RESET: u32 = 1 << 1;
const CMD_INTE: u32 = 1 << 2;
const STS_HALTED: u32 = 1 << 0;
const STS_EINT: u32 = 1 << 3;
const STS_NOT_READY: u32 = 1 << 11;

const PORT_CONNECTED: u32 = 1 << 0;
const PORT_ENABLED: u32 = 1 << 1;
const PORT_RESET: u32 = 1 << 4;
const PORT_POWER: u32 = 1 << 9;
const PORT_RESET_CHANGE: u32 = 1 << 21;
/// Bits that keep their value when written back (Linux's
/// `xhci_port_state_to_neutral`); everything else is RO or RW1C.
const PORT_PRESERVE: u32 = 0x0e00_c3e0;
const PORT_CHANGES: u32 = 0x00fe_0000;

// Runtime registers. MFINDEX counts 125 us microframes (14 bits).
const MFINDEX: usize = 0x00;
// Interrupter 0.
const IMAN: usize = 0x20;
const IMAN_IP: u32 = 1 << 0;
const IMAN_IE: u32 = 1 << 1;
const IMOD: usize = 0x24;
/// Interrupt moderation: 400 x 250 ns = 100 us between interrupts.
const IMOD_INTERVAL: u32 = 400;
const ERSTSZ: usize = 0x28;
const ERSTBA: usize = 0x30;
const ERDP: usize = 0x38;
const ERDP_BUSY: u32 = 1 << 3;

const EXT_CAP_LEGACY: u32 = 1;
const LEGACY_BIOS_OWNED: u32 = 1 << 16;
const LEGACY_OS_OWNED: u32 = 1 << 24;
/// The bits of USBLEGCTLSTS (the dword after the capability header) that are
/// not SMI enables and so are written back as read.
const LEGACY_KEEP_BITS: u32 = 3 << 1 | 0xff << 5 | 7 << 17;
/// The write-1-to-clear SMI status bits of USBLEGCTLSTS.
const LEGACY_SMI_STATUS: u32 = 7 << 29;

/// Devices this driver handles at once (slot IDs 1..=MAX_SLOTS).
pub const MAX_SLOTS: u8 = 8;

/// Size of the transfer bounce buffer. Being 16 KiB and 16 KiB-aligned, it
/// never crosses the 64 KiB boundary a TRB buffer must not span.
pub const BOUNCE_LEN: usize = 16 * 1024;

/// How many times a register or the event ring is polled before giving up
/// when the controller was built without a clock (fewer in tests, whose fake
/// controller never answers).
const POLL_LIMIT: u32 = if cfg!(test) { 20_000 } else { 20_000_000 };

/// How long a register bit may take to change (reset, run/halt, firmware handoff).
const REGISTER_TIMEOUT_NS: u64 = if cfg!(test) { 50_000_000 } else { 1_000_000_000 };

/// Time a device gets to recover after the reset of a hub port.
const RESET_RECOVERY_NS: u64 = 10_000_000;

/// How long a port reset may take to report completion.
const PORT_RESET_TIMEOUT_NS: u64 = if cfg!(test) { 50_000_000 } else { 500_000_000 };

/// Time limit of a polling loop: by the clock if the controller has one,
/// else by counting polls.
struct Deadline<'d> {
    clock: Option<&'d dyn Clock>,
    end: u64,
    polls: u32,
}

impl<'d> Deadline<'d> {
    fn new(clock: Option<&'d dyn Clock>, ns: u64) -> Self {
        Self { clock, end: clock.map_or(0, |c| c.now_ns().saturating_add(ns)), polls: 0 }
    }

    /// Whether the time is up; call after each unsuccessful poll.
    fn expired(&mut self) -> bool {
        match self.clock {
            Some(c) => c.now_ns() > self.end,
            None => {
                self.polls += 1;
                self.polls >= POLL_LIMIT
            }
        }
    }
}

/// Bytes of one ring segment.
const RING_BYTES: usize = ring::RING_TRBS * 16;

/// Endpoint context types.
const EP_TYPE_ISOCH_OUT: u32 = 1;
const EP_TYPE_CONTROL: u32 = 4;
const EP_TYPE_ISOCH_IN: u32 = 5;

/// Isochronous endpoints this driver services at once, over all devices.
pub const MAX_ISOCH_ENDPOINTS: usize = 4;
/// Transfers queued per isochronous endpoint.
pub const ISOCH_DEPTH: usize = 4;
/// Bytes of one isochronous transfer (one service interval): enough for a
/// full-speed 1023-byte packet or three 1024-byte high-speed ones.
pub const ISOCH_SLOT_LEN: usize = 4096;
/// Frames ahead of now that the first `IsochStart::Next` transfer starts.
const ISOCH_LEAD_FRAMES: u16 = 3;

/// Why the controller could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XhciError {
    /// The register window is too small or does not look like xHCI.
    BadRegisters,
    /// The controller did not finish resetting or start.
    Timeout,
    /// The controller needs scratchpad pages larger than 4 KiB.
    Unsupported,
    /// DMA memory could not be allocated.
    NoMemory,
    /// The controller addresses only 32 bits and DMA memory lies above 4 GiB.
    HighMemory,
}

/// One addressed device.
struct Slot<'d, D: DmaAllocator + ?Sized> {
    output: OwnedDma<'d, D>,
    input: OwnedDma<'d, D>,
    /// Configured endpoints, endpoint 0 first. A short table rather than
    /// one entry per possible DCI keeps the controller struct small enough
    /// to build on a boot stack.
    endpoints: [Option<Endpoint<'d, D>>; MAX_ENDPOINTS],
    speed: Speed,
    /// Where the device sits in the topology.
    topo: Topology,
    /// Downstream ports, if the device was configured as a hub.
    hub_ports: u8,
    /// A transfer could not be cancelled, so a TRB pointing at the shared
    /// bounce buffer may still run: no more transfers on this slot.
    dead: bool,
}

/// How a device is reached, for its slot context.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Topology {
    /// Route string: a 4-bit port number per hub tier, the hub nearest the
    /// root port in the lowest nibble. Zero for a device on a root port.
    route: u32,
    /// The root hub port the device hangs off.
    root_port: u8,
    /// Slot of the hub it is plugged into, or 0 on a root port.
    parent: u8,
    /// Slot and port of the transaction translator serving a low- or
    /// full-speed device, or (0, 0).
    tt: (u8, u8),
}

/// One queued isochronous transfer.
#[derive(Clone, Copy)]
struct IsochTd {
    trb: u64,
    len: u32,
    done: Option<Trb>,
}

/// An isochronous endpoint's queue. Its transfer ring is the endpoint's
/// ring in the slot; transfer `k` (from `head`) uses buffer `k` of `buf`.
struct IsochEp<'d, D: DmaAllocator + ?Sized> {
    dev: u8,
    dci: usize,
    buf: OwnedDma<'d, D>,
    tds: [IsochTd; ISOCH_DEPTH],
    head: usize,
    count: usize,
    dir_in: bool,
    /// Largest transfer: all the transactions of one service interval.
    max_len: usize,
    mps: u32,
    burst: u32,
    ss: bool,
    /// Service interval in whole frames, or 0 if more than once a frame.
    period_frames: u16,
    /// The frame the previous transfer was scheduled in.
    last_frame: Option<u16>,
}

impl<'d, D: DmaAllocator + ?Sized> Slot<'d, D> {
    fn endpoint(&mut self, dci: usize) -> Option<&mut Endpoint<'d, D>> {
        self.endpoints.iter_mut().flatten().find(|e| e.dci == dci)
    }
}

/// A configured endpoint: its transfer ring and any `submit_in` transfer.
struct Endpoint<'d, D: DmaAllocator + ?Sized> {
    dci: usize,
    ring: ProducerRing<'d, D>,
    pending: Option<Pending<'d, D>>,
}

/// Endpoints per device, including endpoint 0.
pub const MAX_ENDPOINTS: usize = 8;

/// A transfer started by `submit_in`, with its own buffer so it can stay
/// outstanding while other transfers use the bounce buffer.
struct Pending<'d, D: DmaAllocator + ?Sized> {
    buf: OwnedDma<'d, D>,
    trb: u64,
    len: usize,
    /// Its Transfer Event, once the event ring has delivered it.
    done: Option<Trb>,
}

/// Largest transfer [`UsbHost::submit_in`] accepts (one page).
pub const MAX_SUBMIT_LEN: usize = 4096;

/// An xHCI controller.
///
/// The DMA memory is freed on drop only once the controller has halted;
/// one that will not halt might still write to it, so it is leaked.
pub struct Xhci<'d, D: DmaAllocator + ?Sized> {
    io: IoMem,
    op: usize,
    rt: usize,
    db: usize,
    ctx_size: usize,
    max_ports: u8,
    /// The controller takes 64-bit addresses; if not, all DMA memory must
    /// lie below 4 GiB.
    ac64: bool,
    /// A command could not be aborted and may still run: no more commands.
    commands_stuck: bool,
    dma: &'d D,
    dcbaa: ManuallyDrop<OwnedDma<'d, D>>,
    _scratchpad: ManuallyDrop<Option<(OwnedDma<'d, D>, OwnedDma<'d, D>)>>,
    commands: ManuallyDrop<ProducerRing<'d, D>>,
    events: ManuallyDrop<EventRing<'d, D>>,
    bounce: ManuallyDrop<OwnedDma<'d, D>>,
    slots: ManuallyDrop<[Option<Slot<'d, D>>; MAX_SLOTS as usize]>,
    isoch: ManuallyDrop<[Option<IsochEp<'d, D>>; MAX_ISOCH_ENDPOINTS]>,
    interrupts: u64,
    /// With message interrupts (never shared) every one is serviced,
    /// whatever `USBSTS` and `IMAN` say.
    mode: InterruptMode,
    /// Times the waits; without it they count polls instead.
    clock: Option<&'d dyn Clock>,
}

/// How the controller's interrupt reaches the CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptMode {
    /// MSI-X table entry 0.
    Msix,
    /// A single MSI vector.
    Msi,
    /// The legacy interrupt line (or none, if interrupts are not enabled).
    Intx,
}

fn speed_from_id(id: u32) -> Option<Speed> {
    match id {
        1 => Some(Speed::Full),
        2 => Some(Speed::Low),
        3 => Some(Speed::High),
        4 => Some(Speed::Super),
        5 => Some(Speed::SuperPlus),
        _ => None,
    }
}

fn speed_id(speed: Speed) -> u32 {
    match speed {
        Speed::Full => 1,
        Speed::Low => 2,
        Speed::High => 3,
        Speed::Super => 4,
        Speed::SuperPlus => 5,
    }
}

fn error_from(code: u8) -> UsbError {
    match code {
        completion::STALL => UsbError::Stall,
        completion::USB_TRANSACTION | completion::BABBLE | completion::DATA_BUFFER => UsbError::Transaction,
        completion::BANDWIDTH_OVERRUN
        | completion::RING_UNDERRUN
        | completion::RING_OVERRUN
        | completion::MISSED_SERVICE
        | completion::ISOCH_BUFFER_OVERRUN => UsbError::Transaction,
        completion::NO_SLOTS | completion::RESOURCE => UsbError::NoResources,
        completion::SLOT_NOT_ENABLED => UsbError::NoDevice,
        completion::ENDPOINT_NOT_ENABLED => UsbError::BadEndpoint,
        _ => UsbError::Controller,
    }
}

/// Device Context Index of endpoint address `ep` (endpoint 0 is 1).
fn dci(ep: u8) -> usize {
    let n = (ep & 0xf) as usize;
    if n == 0 { 1 } else { n * 2 + (ep >> 7) as usize }
}

/// The xHCI interval exponent (period = 2^n × 125 µs) for an endpoint.
fn interval(ep: &EndpointDescriptor, speed: Speed) -> u32 {
    let b = ep.interval as u32;
    match (ep.transfer_type(), speed) {
        (TransferType::Bulk | TransferType::Control, _) => 0,
        // Full-speed isochronous: 2^(bInterval-1) frames = 8 x that microframes.
        (TransferType::Isochronous, Speed::Full | Speed::Low) => (b.clamp(1, 16) - 1 + 3).min(15),
        // bInterval in frames (ms) at full and low speed.
        (TransferType::Interrupt, Speed::Full | Speed::Low) => {
            let micro = (b.max(1) * 8).min(1 << 15);
            (31 - micro.leading_zeros()).clamp(3, 10)
        }
        // Otherwise 2^(bInterval - 1) microframes.
        _ => b.clamp(1, 16) - 1,
    }
}

/// Writes dword `n` of the context at `ctx`.
fn ctx_set(buf: &DmaBuffer, ctx: usize, n: usize, value: u32) {
    buf.store(ctx + 4 * n, value.to_le());
}

fn ctx_get(buf: &DmaBuffer, ctx: usize, n: usize) -> u32 {
    u32::from_le(buf.load(ctx + 4 * n))
}

/// Whether a controller that takes 64-bit addresses if `ac64` can reach
/// `len` bytes of DMA memory at `addr`.
fn reachable(ac64: bool, addr: u64, len: usize) -> bool {
    ac64 || addr.checked_add(len as u64).is_some_and(|end| end <= 1 << 32)
}

/// `len` bytes of DMA memory the controller can reach.
fn new_dma<'d, D: DmaAllocator + ?Sized>(dma: &'d D, ac64: bool, len: usize) -> Option<OwnedDma<'d, D>> {
    OwnedDma::new(dma, len).filter(|b| reachable(ac64, b.device_addr().as_u64(), len))
}

/// A transfer ring the controller can reach.
fn new_ring<'d, D: DmaAllocator + ?Sized>(dma: &'d D, ac64: bool) -> Option<ProducerRing<'d, D>> {
    ProducerRing::new(dma).filter(|r| reachable(ac64, r.base().as_u64(), RING_BYTES))
}

impl<'d, D: DmaAllocator + ?Sized> Xhci<'d, D> {
    /// Takes the controller whose registers are `io` away from firmware,
    /// resets it, and starts it with DMA memory from `dma`. Ports are left
    /// as the reset found them; [`UsbHost::attach`] resets each one.
    ///
    /// Waits are counted in polls, which is a shorter or longer time depending
    /// on the CPU; prefer [`with_clock`](Self::with_clock).
    pub fn new(io: IoMem, dma: &'d D) -> Result<Self, XhciError> {
        Self::build(io, dma, None)
    }

    /// Like [`new`](Self::new), but every wait is limited by `clock`: a second
    /// for register changes, five for commands and transfers.
    pub fn with_clock(io: IoMem, dma: &'d D, clock: &'d dyn Clock) -> Result<Self, XhciError> {
        Self::build(io, dma, Some(clock))
    }

    fn build(io: IoMem, dma: &'d D, clock: Option<&'d dyn Clock>) -> Result<Self, XhciError> {
        let r = |off: usize| io.read::<u32>(off).map_err(|_| XhciError::BadRegisters);
        let cap = r(CAPLENGTH_HCIVERSION)?;
        let op = (cap & 0xff) as usize;
        let params1 = r(HCSPARAMS1)?;
        let params2 = r(HCSPARAMS2)?;
        let hccparams1 = r(HCCPARAMS1)?;
        let db = (r(DBOFF)? & !3) as usize;
        let rt = (r(RTSOFF)? & !0x1f) as usize;
        let max_ports = (params1 >> 24) as u8;
        // Every port's PORTSC, interrupter 0 and every doorbell must be in the window.
        let ports_end = op + PORTSC + max_ports as usize * PORT_STRIDE;
        let doorbells_end = db.saturating_add(4 * (MAX_SLOTS as usize + 1));
        if op < 0x20
            || cap >> 16 < 0x0090
            || max_ports == 0
            || io.len() < ports_end.max(rt.saturating_add(0x40)).max(doorbells_end)
        {
            return Err(XhciError::BadRegisters);
        }
        let max_slots = (params1 as u8).min(MAX_SLOTS);
        let ctx_size = if hccparams1 & (1 << 2) != 0 { 64 } else { 32 };
        let scratchpads = ((params2 >> 21 & 0x1f) << 5 | params2 >> 27) as usize;

        let no_mem = XhciError::NoMemory;
        let dcbaa = OwnedDma::new(dma, 2048).ok_or(no_mem)?;
        let scratchpad = if scratchpads > 0 {
            let pages = OwnedDma::new(dma, scratchpads * 4096).ok_or(no_mem)?;
            let array = OwnedDma::new(dma, scratchpads * 8).ok_or(no_mem)?;
            for i in 0..scratchpads {
                array.store(i * 8, (pages.device_addr().as_u64() + i as u64 * 4096).to_le());
            }
            dcbaa.store(0, array.device_addr().as_u64().to_le());
            Some((array, pages))
        } else {
            None
        };

        let hc = Self {
            op,
            rt,
            db,
            ctx_size,
            max_ports,
            ac64: hccparams1 & HCC_AC64 != 0,
            commands_stuck: false,
            dma,
            dcbaa: ManuallyDrop::new(dcbaa),
            _scratchpad: ManuallyDrop::new(scratchpad),
            commands: ManuallyDrop::new(ProducerRing::new(dma).ok_or(no_mem)?),
            events: ManuallyDrop::new(EventRing::new(dma).ok_or(no_mem)?),
            bounce: ManuallyDrop::new(OwnedDma::new(dma, BOUNCE_LEN).ok_or(no_mem)?),
            slots: ManuallyDrop::new([const { None }; MAX_SLOTS as usize]),
            isoch: ManuallyDrop::new([const { None }; MAX_ISOCH_ENDPOINTS]),
            interrupts: 0,
            mode: InterruptMode::Intx,
            clock,
            io,
        };
        if scratchpads > 0 && hc.op_read(PAGESIZE) & 1 == 0 {
            return Err(XhciError::Unsupported);
        }
        // Without AC64 the controller drops the high half of every address.
        let scratch = hc._scratchpad.iter().flat_map(|(a, p)| [&**a, &**p]);
        let buffers_ok = [&**hc.dcbaa, &**hc.bounce]
            .into_iter()
            .chain(scratch)
            .all(|b| reachable(hc.ac64, b.device_addr().as_u64(), b.len()));
        // The event ring's dequeue pointer is still its segment's start.
        let rings = [hc.commands.base(), hc.events.dequeue_addr()];
        if !buffers_ok
            || !rings.iter().all(|r| reachable(hc.ac64, r.as_u64(), RING_BYTES))
            || !reachable(hc.ac64, hc.events.table().as_u64(), 64)
        {
            return Err(XhciError::HighMemory);
        }
        hc.take_from_firmware((hccparams1 >> 16) as usize * 4);
        hc.reset()?;

        hc.op_write(CONFIG, max_slots as u32);
        hc.op_write64(DCBAAP, hc.dcbaa.device_addr().as_u64());
        hc.op_write64(CRCR, hc.commands.base().as_u64() | hc.commands.cycle() as u64);
        hc.rt_write(ERSTSZ, 1);
        hc.write_erdp();
        hc.rt_write64(ERSTBA, hc.events.table().as_u64());
        hc.rt_write(IMAN, 0);

        hc.op_write(USBCMD, CMD_RUN);
        hc.poll(REGISTER_TIMEOUT_NS, |hc| hc.op_read(USBSTS) & STS_HALTED == 0).map_err(|_| XhciError::Timeout)?;
        for port in 1..=hc.max_ports {
            let sc = hc.portsc(port);
            if sc & PORT_POWER == 0 {
                hc.set_portsc(port, (sc & PORT_PRESERVE) | PORT_POWER);
            }
        }
        Ok(hc)
    }

    /// Lets interrupter 0 raise the controller's interrupt line (INTx or
    /// MSI, whichever the bus function routes). From now on the kernel's
    /// handler must call [`handle_interrupt`](Self::handle_interrupt).
    ///
    /// Polled operations keep working: they pop events themselves, so the
    /// interrupt that follows an event they consumed finds an empty ring.
    /// The caller serializes both with one lock (the driver is `&mut self`
    /// throughout), so exactly one context drains the ring at a time, and
    /// an interrupt can only be handled between operations, never inside
    /// one: no waiter's completion is ever stolen by the handler. The
    /// handler must therefore not run on a CPU that holds that lock.
    pub fn enable_interrupts(&mut self) {
        self.rt_write(IMOD, IMOD_INTERVAL);
        self.rt_write(IMAN, IMAN_IP | IMAN_IE);
        self.op_write(USBSTS, STS_EINT);
        self.op_write(USBCMD, self.op_read(USBCMD) | CMD_INTE);
    }

    /// Routes the controller's interrupt through MSI-X (entry 0 of the
    /// table, in the BAR that `bar` returns for the table's BAR index) or,
    /// failing that, MSI with one vector, then calls
    /// [`enable_interrupts`](Self::enable_interrupts). `msg` is what the
    /// interrupt controller wants written (on x86,
    /// `osmium_drivers::lapic::msi_message`). With neither capability, or a
    /// message the capability cannot hold, the legacy line is used and
    /// [`InterruptMode::Intx`] returned. The kernel's handler must call
    /// [`handle_interrupt`](Self::handle_interrupt) as for INTx.
    ///
    /// Message interrupts are unshared, so `handle_interrupt` services every
    /// one and always returns true.
    pub fn enable_message_interrupts<C: ConfigAccess + ?Sized>(
        &mut self,
        func: &Function<'_, C>,
        msg: MsiMessage,
        bar: impl FnOnce(u8) -> Option<IoMem>,
    ) -> InterruptMode {
        self.mode = self.program_message(func, msg, bar).unwrap_or(InterruptMode::Intx);
        self.enable_interrupts();
        self.mode
    }

    fn program_message<C: ConfigAccess + ?Sized>(
        &self,
        func: &Function<'_, C>,
        msg: MsiMessage,
        bar: impl FnOnce(u8) -> Option<IoMem>,
    ) -> Result<InterruptMode, MsiError> {
        match func.msix() {
            Ok(msix) => {
                let window = bar(msix.table_bir()).ok_or(MsiError::OutOfBar)?;
                let table = msix.table(&window)?;
                table.set_message(0, msg)?;
                table.set_masked(0, false)?;
                msix.set_function_mask(func, false);
                msix.enable(func);
                return Ok(InterruptMode::Msix);
            }
            Err(MsiError::NotPresent) => {}
            Err(e) => return Err(e),
        }
        let msi = func.msi()?;
        msi.program(func, msg)?;
        msi.enable(func, 1)?;
        Ok(InterruptMode::Msi)
    }

    /// How interrupts are delivered: `Intx` until
    /// [`enable_message_interrupts`](Self::enable_message_interrupts)
    /// switches to messages.
    pub fn interrupt_mode(&self) -> InterruptMode {
        self.mode
    }

    /// Stops the controller from raising interrupts (polling still works).
    pub fn disable_interrupts(&mut self) {
        self.op_write(USBCMD, self.op_read(USBCMD) & !CMD_INTE);
        self.rt_write(IMAN, IMAN_IP);
    }

    /// Services the controller's interrupt: acknowledges it, then files
    /// every event on the ring (so `submit_in` completions are ready for
    /// `poll_in`) and advances `ERDP`. Returns false, doing nothing, if the
    /// controller was not asserting an interrupt (a shared line).
    ///
    /// The acknowledgement comes before draining: an event written after
    /// the drain raises a new interrupt instead of being missed.
    pub fn handle_interrupt(&mut self) -> bool {
        let asserted = self.op_read(USBSTS) & STS_EINT != 0 || self.rt_read(IMAN) & IMAN_IP != 0;
        if !asserted && self.mode == InterruptMode::Intx {
            return false;
        }
        // Both are write-1-to-clear; the other USBSTS bits are left alone
        // (writing 0) and IE stays set.
        self.op_write(USBSTS, STS_EINT);
        self.rt_write(IMAN, IMAN_IP | IMAN_IE);
        self.interrupts += 1;
        self.drain_events();
        true
    }

    /// How many interrupts [`handle_interrupt`](Self::handle_interrupt)
    /// has serviced.
    pub fn interrupts_handled(&self) -> u64 {
        self.interrupts
    }

    // `new` checked the window covers every register used, so these only
    // guard against a bug: reads outside it give 0, writes are dropped.
    fn r32(&self, off: usize) -> u32 {
        self.io.read(off).unwrap_or(0)
    }

    fn w32(&self, off: usize, v: u32) {
        let _ = self.io.write(off, v);
    }

    fn op_read(&self, reg: usize) -> u32 {
        self.r32(self.op + reg)
    }

    fn op_write(&self, reg: usize, v: u32) {
        self.w32(self.op + reg, v)
    }

    // 64-bit registers are written as two dwords, low first, which every
    // controller accepts (not all accept 64-bit accesses).
    fn op_write64(&self, reg: usize, v: u64) {
        self.op_write(reg, v as u32);
        self.op_write(reg + 4, (v >> 32) as u32);
    }

    fn rt_read(&self, reg: usize) -> u32 {
        self.r32(self.rt + reg)
    }

    fn rt_write(&self, reg: usize, v: u32) {
        self.w32(self.rt + reg, v)
    }

    fn rt_write64(&self, reg: usize, v: u64) {
        self.rt_write(reg, v as u32);
        self.rt_write(reg + 4, (v >> 32) as u32);
    }

    fn write_erdp(&self) {
        self.rt_write64(ERDP, self.events.dequeue_addr().as_u64() | ERDP_BUSY as u64);
    }

    fn ring_doorbell(&self, slot: u8, target: u32) {
        osmium_arch::barrier::mb();
        self.w32(self.db + 4 * slot as usize, target);
    }

    fn portsc(&self, port: u8) -> u32 {
        self.op_read(PORTSC + (port as usize).saturating_sub(1) * PORT_STRIDE)
    }

    fn set_portsc(&self, port: u8, v: u32) {
        self.op_write(PORTSC + (port as usize).saturating_sub(1) * PORT_STRIDE, v)
    }

    fn poll(&self, ns: u64, mut done: impl FnMut(&Self) -> bool) -> Result<(), UsbError> {
        let mut deadline = Deadline::new(self.clock, ns);
        loop {
            if done(self) {
                return Ok(());
            }
            if deadline.expired() {
                return Err(UsbError::Timeout);
            }
            osmium_arch::cpu::spin_hint();
        }
    }

    /// Claims the controller from BIOS/SMM if the USB Legacy Support
    /// capability says firmware owns it.
    fn take_from_firmware(&self, mut off: usize) {
        while off != 0 && off + 4 <= self.io.len() {
            let cap = self.r32(off);
            if cap & 0xff == EXT_CAP_LEGACY {
                if cap & LEGACY_BIOS_OWNED != 0 {
                    self.w32(off, cap | LEGACY_OS_OWNED);
                    // Firmware that never lets go keeps it; carry on anyway.
                    let _ = self.poll(REGISTER_TIMEOUT_NS, |hc| hc.r32(off) & LEGACY_BIOS_OWNED == 0);
                }
                // No more SMIs for USB events, and the pending ones are acknowledged.
                if off + 8 <= self.io.len() {
                    let ctl = self.r32(off + 4);
                    self.w32(off + 4, ctl & LEGACY_KEEP_BITS | LEGACY_SMI_STATUS);
                }
                return;
            }
            match (cap >> 8 & 0xff) as usize {
                0 => return,
                next => off += next * 4,
            }
        }
    }

    fn reset(&self) -> Result<(), XhciError> {
        let timeout = |_| XhciError::Timeout;
        self.poll(REGISTER_TIMEOUT_NS, |hc| hc.op_read(USBSTS) & STS_NOT_READY == 0).map_err(timeout)?;
        self.op_write(USBCMD, self.op_read(USBCMD) & !CMD_RUN);
        self.poll(REGISTER_TIMEOUT_NS, |hc| hc.op_read(USBSTS) & STS_HALTED != 0).map_err(timeout)?;
        self.op_write(USBCMD, CMD_RESET);
        self.poll(REGISTER_TIMEOUT_NS, |hc| {
            hc.op_read(USBCMD) & CMD_RESET == 0 && hc.op_read(USBSTS) & STS_NOT_READY == 0
        })
        .map_err(timeout)
    }

    /// Waits for the event that `matches`, discarding others (port status
    /// changes are read from `PORTSC` instead).
    fn wait_event(&mut self, ns: u64, matches: impl Fn(&Trb) -> bool) -> Result<Trb, UsbError> {
        let mut deadline = Deadline::new(self.clock, ns);
        loop {
            if let Some(ev) = self.events.pop() {
                self.write_erdp();
                if matches(&ev) {
                    return Ok(ev);
                }
                self.route(ev);
            } else if deadline.expired() {
                return Err(UsbError::Timeout);
            } else {
                osmium_arch::cpu::spin_hint();
            }
        }
    }

    /// Files an event nobody is waiting for: the completion of a
    /// `submit_in` transfer is kept for `poll_in`; anything else is dropped.
    fn route(&mut self, ev: Trb) {
        if ev.kind() != kind::TRANSFER_EVENT {
            return;
        }
        let i = ev.endpoint_id() as usize;
        if let Some(e) = self.isoch.iter_mut().flatten().find(|e| e.dev == ev.slot_id() && e.dci == i) {
            let (head, count) = (e.head, e.count);
            let hit =
                (0..count).map(|k| (head + k) % ISOCH_DEPTH).find(|&k| e.tds.get(k).is_some_and(|t| t.trb == ev.param));
            if let Some(td) = hit.and_then(|k| e.tds.get_mut(k)) {
                td.done = Some(ev);
            }
            return;
        }
        let pending = self.slot(DeviceId(ev.slot_id())).ok().and_then(|s| s.endpoint(i)?.pending.as_mut());
        if let Some(p) = pending
            && p.trb == ev.param
        {
            p.done = Some(ev);
        }
    }

    /// Routes every event already on the ring, without waiting.
    fn drain_events(&mut self) {
        let mut any = false;
        while let Some(ev) = self.events.pop() {
            any = true;
            self.route(ev);
        }
        if any {
            self.write_erdp();
        }
    }

    /// The ring for endpoint `endpoint`, if configured and not busy with a
    /// `submit_in` transfer.
    fn idle_ring(&mut self, dev: DeviceId, endpoint: u8) -> Result<&mut ProducerRing<'d, D>, UsbError> {
        if endpoint & 0xf == 0 {
            return Err(UsbError::BadEndpoint); // endpoint 0 carries control transfers only
        }
        let ep = self.live_slot(dev)?.endpoint(dci(endpoint)).ok_or(UsbError::BadEndpoint)?;
        if ep.pending.is_some() {
            return Err(UsbError::Busy);
        }
        Ok(&mut ep.ring)
    }

    /// Runs a command and returns its completion event. One that does not
    /// complete is aborted, so it cannot run later on memory since freed.
    fn command(&mut self, cmd: Trb) -> Result<Trb, UsbError> {
        if self.commands_stuck {
            return Err(UsbError::Controller);
        }
        let addr = self.commands.push(cmd);
        self.ring_doorbell(0, 0);
        let param = addr.as_u64();
        let ev = match self.wait_event(CONTROL_TIMEOUT_NS, |e| e.kind() == kind::COMMAND_COMPLETION && e.param == param)
        {
            Ok(ev) => ev,
            Err(e) => {
                self.abort_command(addr);
                return Err(e);
            }
        };
        match ev.completion_code() {
            completion::SUCCESS => Ok(ev),
            code => Err(error_from(code)),
        }
    }

    /// Takes the timed-out command at `addr` off the ring (xHCI 1.2
    /// §4.6.1.2): Command Abort, wait for the ring to stop, and drain the
    /// Command Ring Stopped event. A ring that stopped on the command, or
    /// never fetched it, would run it at the next doorbell, so it becomes a
    /// No Op. If the ring will not stop, no further commands are issued.
    fn abort_command(&mut self, addr: PhysAddr) {
        if self.op_read(CRCR) & CRCR_CRR != 0 {
            // The pointer bits are ignored while the ring runs.
            self.op_write(CRCR, CRCR_CA);
            if self.poll(REGISTER_TIMEOUT_NS, |hc| hc.op_read(CRCR) & CRCR_CRR == 0).is_err() {
                self.commands_stuck = true;
                return;
            }
            let stopped = |e: &Trb| {
                e.kind() == kind::COMMAND_COMPLETION && e.completion_code() == completion::COMMAND_RING_STOPPED
            };
            let _ = self.wait_event(REGISTER_TIMEOUT_NS, stopped);
        }
        self.commands.cancel(addr);
    }

    /// Checks the controller answers commands.
    pub fn no_op(&mut self) -> Result<(), UsbError> {
        self.command(Trb::no_op_command()).map(drop)
    }

    fn slot(&mut self, dev: DeviceId) -> Result<&mut Slot<'d, D>, UsbError> {
        let i = (dev.0 as usize).wrapping_sub(1);
        self.slots.get_mut(i).and_then(Option::as_mut).ok_or(UsbError::NoDevice)
    }

    /// The slot for `dev`, if transfers on it are still safe.
    fn live_slot(&mut self, dev: DeviceId) -> Result<&mut Slot<'d, D>, UsbError> {
        let slot = self.slot(dev)?;
        if slot.dead {
            return Err(UsbError::NoDevice);
        }
        Ok(slot)
    }

    /// Resets `port` if it is not already enabled (USB 3 ports enable
    /// themselves on connect; USB 2 ports need a reset).
    fn reset_port(&self, port: u8) -> Result<Speed, UsbError> {
        let sc = self.portsc(port);
        if sc & PORT_CONNECTED == 0 {
            return Err(UsbError::NoDevice);
        }
        if sc & PORT_ENABLED == 0 {
            self.set_portsc(port, (sc & PORT_PRESERVE) | PORT_RESET);
            self.poll(PORT_RESET_TIMEOUT_NS, |hc| hc.portsc(port) & PORT_RESET_CHANGE != 0)?;
        }
        let sc = self.portsc(port);
        // Acknowledge every change so the next connect is seen afresh.
        self.set_portsc(port, (sc & PORT_PRESERVE) | (sc & PORT_CHANGES));
        if sc & PORT_ENABLED == 0 {
            return Err(UsbError::Transaction);
        }
        speed_from_id(sc >> 10 & 0xf).ok_or(UsbError::Transaction)
    }

    /// Fills the input context's control, slot and endpoint 0 contexts for
    /// Address Device.
    fn init_input(&self, input: &DmaBuffer, topo: &Topology, speed: Speed, ep0: &ProducerRing<'d, D>) {
        let c = self.ctx_size;
        ctx_set(input, 0, 1, 0b11); // add slot and endpoint 0
        ctx_set(input, c, 0, (topo.route & 0xf_ffff) | speed_id(speed) << 20 | 1 << 27); // one context entry
        ctx_set(input, c, 1, (topo.root_port as u32) << 16);
        ctx_set(input, c, 2, topo.tt.0 as u32 | (topo.tt.1 as u32) << 8);
        let ep0_ctx = 2 * c;
        let mps = speed.default_max_packet0() as u32;
        ctx_set(input, ep0_ctx, 1, 3 << 1 | EP_TYPE_CONTROL << 3 | mps << 16);
        let deq = ep0.base().as_u64() | ep0.cycle() as u64;
        ctx_set(input, ep0_ctx, 2, deq as u32);
        ctx_set(input, ep0_ctx, 3, (deq >> 32) as u32);
        ctx_set(input, ep0_ctx, 4, 8); // average TRB length
    }

    /// Moves an endpoint's dequeue pointer past every queued TRB, after
    /// resetting it if it `halted` on an error, or stopping it (after a
    /// timeout, or if it was not halted after all). If the pointer cannot be
    /// moved, a TRB pointing at the shared bounce buffer may still run, so
    /// the slot is marked dead.
    fn recover(&mut self, dev: DeviceId, dci: usize, halted: bool) {
        let (addr, cycle) = match self.slot(dev).ok().and_then(|s| s.endpoint(dci)) {
            Some(e) => (e.ring.enqueue_addr().as_u64(), e.ring.cycle()),
            None => return,
        };
        if !halted || self.command(Trb::reset_endpoint(dev.0, dci as u8)).is_err() {
            let _ = self.command(Trb::stop_endpoint(dev.0, dci as u8));
        }
        if self.command(Trb::set_tr_dequeue(dev.0, dci as u8, addr, cycle)).is_err()
            && let Ok(slot) = self.slot(dev)
        {
            slot.dead = true;
        }
    }

    /// Enables a slot for a device at `topo` running at `speed` and
    /// addresses it.
    fn address_device(&mut self, topo: Topology, speed: Speed) -> Result<DeviceId, UsbError> {
        let slot_id = self.command(Trb::enable_slot())?.slot_id();
        let dev = DeviceId(slot_id);
        if slot_id == 0 || slot_id > MAX_SLOTS {
            let _ = self.command(Trb::disable_slot(slot_id));
            return Err(UsbError::NoResources);
        }
        if let Ok(held) = self.slot(dev) {
            // The controller handed out a slot it already gave us: it is
            // confused, and the device holding the slot is lost either way.
            held.dead = true;
            let _ = self.command(Trb::disable_slot(slot_id));
            return Err(UsbError::Controller);
        }

        let (dma, ac64, c) = (self.dma, self.ac64, self.ctx_size);
        let (Some(output), Some(input), Some(ep0)) =
            (new_dma(dma, ac64, 32 * c), new_dma(dma, ac64, 33 * c), new_ring(dma, ac64))
        else {
            let _ = self.command(Trb::disable_slot(slot_id));
            return Err(UsbError::NoResources);
        };
        self.init_input(&input, &topo, speed, &ep0);
        self.dcbaa.store(slot_id as usize * 8, output.device_addr().as_u64().to_le());
        let input_addr = input.device_addr().as_u64();
        let mut endpoints = [const { None }; MAX_ENDPOINTS];
        endpoints[0] = Some(Endpoint { dci: 1, ring: ep0, pending: None });
        let entry = self.slots.get_mut(slot_id as usize - 1).ok_or(UsbError::NoResources)?;
        *entry = Some(Slot { output, input, endpoints, speed, topo, hub_ports: 0, dead: false });

        let result = self.command(Trb::address_device(slot_id, input_addr)).and_then(|_| {
            // Learn endpoint 0's real packet size from the first 8 bytes of
            // the device descriptor, and tell the controller if it differs.
            let n = self.control(dev, SetupPacket::get_descriptor(1, 0, 8))?;
            if n < 8 {
                return Err(UsbError::BadDescriptor);
            }
            let raw = self.bounce.load::<u8>(7) as u16;
            let usb3 = self.bounce.load::<u8>(3) >= 3;
            let mps = if usb3 { 1 << raw.min(15) } else { raw };
            if mps != speed.default_max_packet0() && mps != 0 {
                let c = self.ctx_size;
                let slot = self.slot(dev)?;
                ctx_set(&slot.input, 0, 0, 0);
                ctx_set(&slot.input, 0, 1, 0b10); // endpoint 0 only
                let dw1 = ctx_get(&slot.input, 2 * c, 1);
                ctx_set(&slot.input, 2 * c, 1, (dw1 & 0xffff) | (mps as u32) << 16);
                self.command(Trb::evaluate_context(slot_id, input_addr))?;
            }
            Ok(dev)
        });
        if result.is_err() {
            self.detach(dev);
        }
        result
    }

    /// Runs a control transfer whose data stage (if any) uses the first
    /// `setup.length` bytes of the bounce buffer; returns the bytes moved.
    fn control(&mut self, dev: DeviceId, setup: SetupPacket) -> Result<usize, UsbError> {
        let len = setup.length as usize;
        if len > BOUNCE_LEN {
            return Err(UsbError::NoResources);
        }
        let dir_in = setup.direction() == Direction::In;
        let bounce = self.bounce.device_addr().as_u64();
        let ring = &mut self.live_slot(dev)?.endpoint(1).ok_or(UsbError::BadEndpoint)?.ring;
        let first = ring.push(Trb::setup_stage(&setup)).as_u64();
        let data = (len > 0).then(|| ring.push(Trb::data_stage(bounce, len as u32, dir_in)).as_u64());
        let status = ring.push(Trb::status_stage(!(len > 0 && dir_in))).as_u64();
        self.ring_doorbell(dev.0, 1);

        // Only events for this transfer's TRBs: a late one for an earlier
        // transfer must not complete this one.
        let slot = dev.0;
        let ours = move |e: &Trb| {
            e.kind() == kind::TRANSFER_EVENT
                && e.slot_id() == slot
                && e.endpoint_id() == 1
                && (e.param == first || Some(e.param) == data || e.param == status)
        };
        let mut moved = len;
        loop {
            let ev = match self.wait_event(CONTROL_TIMEOUT_NS, ours) {
                Ok(ev) => ev,
                Err(e) => {
                    self.recover(dev, 1, false);
                    return Err(e);
                }
            };
            match ev.completion_code() {
                completion::SUCCESS | completion::SHORT_PACKET => {
                    if Some(ev.param) == data {
                        moved = len - (ev.residual() as usize).min(len);
                    }
                    if ev.param == status {
                        return Ok(moved);
                    }
                }
                code => {
                    self.recover(dev, 1, true);
                    return Err(error_from(code));
                }
            }
        }
    }

    /// One bulk or interrupt transfer of at most [`BOUNCE_LEN`] bytes through
    /// the bounce buffer.
    fn transfer_chunk(&mut self, dev: DeviceId, endpoint: u8, len: usize) -> Result<usize, UsbError> {
        let i = dci(endpoint);
        let bounce = self.bounce.device_addr().as_u64();
        let trb = self.idle_ring(dev, endpoint)?.push(Trb::normal(bounce, len as u32)).as_u64();
        self.ring_doorbell(dev.0, i as u32);
        let ev = match self.wait_event(BULK_TIMEOUT_NS, |e| e.kind() == kind::TRANSFER_EVENT && e.param == trb) {
            Ok(ev) => ev,
            Err(e) => {
                // Left queued, the TRB could still move data through the
                // bounce buffer during another device's transfer.
                self.recover(dev, i, false);
                return Err(e);
            }
        };
        match ev.completion_code() {
            completion::SUCCESS | completion::SHORT_PACKET => Ok(len - (ev.residual() as usize).min(len)),
            code => {
                self.recover(dev, i, true);
                Err(error_from(code))
            }
        }
    }
}

impl<D: DmaAllocator + ?Sized> UsbHost for Xhci<'_, D> {
    fn num_ports(&self) -> u8 {
        self.max_ports
    }

    fn port_status(&self, port: u8) -> PortStatus {
        if port == 0 || port > self.max_ports {
            return PortStatus { connected: false, enabled: false, speed: None };
        }
        let sc = self.portsc(port);
        PortStatus {
            connected: sc & PORT_CONNECTED != 0,
            enabled: sc & PORT_ENABLED != 0,
            speed: if sc & PORT_CONNECTED != 0 { speed_from_id(sc >> 10 & 0xf) } else { None },
        }
    }

    fn attach(&mut self, port: u8) -> Result<DeviceId, UsbError> {
        if port == 0 || port > self.max_ports {
            return Err(UsbError::NoDevice);
        }
        let speed = self.reset_port(port)?;
        self.address_device(Topology { route: 0, root_port: port, parent: 0, tt: (0, 0) }, speed)
    }

    fn attach_hub_port(&mut self, hub: DeviceId, port: u8, speed: Speed) -> Result<DeviceId, UsbError> {
        let parent = self.live_slot(hub)?;
        if parent.hub_ports == 0 {
            return Err(UsbError::Unsupported); // not configured as a hub
        }
        if port == 0 || port > parent.hub_ports {
            return Err(UsbError::NoDevice);
        }
        // The route string has five nibbles; the hub's own route fills the
        // low ones. Port numbers above 14 are all encoded as 15.
        let depth = (0..5).take_while(|t| parent.topo.route >> (4 * t) & 0xf != 0).count();
        if depth >= 5 {
            return Err(UsbError::Unsupported);
        }
        let route = parent.topo.route | (port.min(15) as u32) << (4 * depth);
        // A low- or full-speed device is served by the nearest high-speed
        // hub's transaction translator: this hub's, if it is high speed,
        // else the one its own slot context names.
        let tt = match speed {
            Speed::Low | Speed::Full if parent.speed == Speed::High => (hub.0, port),
            Speed::Low | Speed::Full => parent.topo.tt,
            _ => (0, 0),
        };
        let topo = Topology { route, root_port: parent.topo.root_port, parent: hub.0, tt };
        // The device gets 10 ms to recover from the hub's port reset before
        // its first request (USB 2.0 §9.2.6.2); only a controller with a clock can wait.
        if self.clock.is_some() {
            let _ = self.poll(RESET_RECOVERY_NS, |_| false);
        }
        self.address_device(topo, speed)
    }

    fn configure_hub(&mut self, hub: DeviceId, ports: u8, think_time: u8, multi_tt: bool) -> Result<(), UsbError> {
        if ports == 0 {
            return Err(UsbError::Unsupported);
        }
        let c = self.ctx_size;
        let slot = self.live_slot(hub)?;
        // Slot context only (A0): the device's own copy, with the hub fields.
        ctx_set(&slot.input, 0, 0, 0);
        ctx_set(&slot.input, 0, 1, 1);
        for n in 0..4 {
            ctx_set(&slot.input, c, n, ctx_get(&slot.output, 0, n));
        }
        let hub_bits = 1 << 26 | (multi_tt as u32) << 25;
        let dw0 = ctx_get(&slot.input, c, 0) & !(1 << 26 | 1 << 25);
        ctx_set(&slot.input, c, 0, dw0 | hub_bits);
        let dw1 = ctx_get(&slot.input, c, 1) & 0x00ff_ffff;
        ctx_set(&slot.input, c, 1, dw1 | (ports as u32) << 24);
        let dw2 = ctx_get(&slot.input, c, 2) & !(3 << 16);
        ctx_set(&slot.input, c, 2, dw2 | (think_time as u32 & 3) << 16);
        let input = slot.input.device_addr().as_u64();
        self.command(Trb::configure_endpoint(hub.0, input))?;
        self.slot(hub)?.hub_ports = ports;
        Ok(())
    }

    fn detach(&mut self, dev: DeviceId) {
        if self.slot(dev).is_err() {
            return;
        }
        // Everything below a hub goes with it.
        for id in 1..=MAX_SLOTS {
            if self.slots.get(id as usize - 1).and_then(Option::as_ref).is_some_and(|s| s.topo.parent == dev.0) {
                self.detach(DeviceId(id));
            }
        }
        match self.command(Trb::disable_slot(dev.0)) {
            // Disabled, or never enabled: the controller is done with the slot's memory.
            Ok(_) | Err(UsbError::NoDevice) => {
                self.dcbaa.store(dev.0 as usize * 8, 0u64);
                if let Some(entry) = self.slots.get_mut((dev.0 as usize).wrapping_sub(1)) {
                    *entry = None;
                }
                for e in self.isoch.iter_mut().filter(|e| e.as_ref().is_some_and(|e| e.dev == dev.0)) {
                    *e = None;
                }
                // A child that could not be disabled is orphaned: its parent
                // id may be handed out again.
                for s in self.slots.iter_mut().flatten().filter(|s| s.topo.parent == dev.0) {
                    s.topo.parent = 0;
                }
            }
            // It may still use the contexts and rings: keep them, dead, for a later detach to retry.
            Err(_) => {
                if let Ok(slot) = self.slot(dev) {
                    slot.dead = true;
                }
            }
        }
    }

    fn configure_endpoints(&mut self, dev: DeviceId, endpoints: &[EndpointDescriptor]) -> Result<(), UsbError> {
        let (c, dma, ac64) = (self.ctx_size, self.dma, self.ac64);
        // Isochronous queue entries free once the ones being replaced go.
        let replaced = |e: &IsochEp<'_, D>| e.dev == dev.0 && endpoints.iter().any(|n| dci(n.address) == e.dci);
        let isoch_free = self.isoch.iter().filter(|e| e.as_ref().is_none_or(replaced)).count();
        let isoch_new = endpoints.iter().filter(|e| e.transfer_type() == TransferType::Isochronous).count();
        if isoch_new > isoch_free {
            return Err(UsbError::NoResources);
        }
        let slot = self.live_slot(dev)?;
        let speed = slot.speed;
        let mut new_rings: [Option<(usize, ProducerRing<'_, D>)>; MAX_ENDPOINTS] = [const { None }; MAX_ENDPOINTS];
        let mut new_isoch: [Option<IsochEp<'_, D>>; MAX_ENDPOINTS] = [const { None }; MAX_ENDPOINTS];
        // Endpoints the device keeps plus the new ones must fit the table.
        let kept =
            slot.endpoints.iter().flatten().filter(|e| endpoints.iter().all(|n| dci(n.address) != e.dci)).count();
        if kept + endpoints.len() > MAX_ENDPOINTS {
            return Err(UsbError::NoResources);
        }
        let mut add = 1u32; // the slot context
        // Endpoints being replaced are dropped and re-added (xHCI 1.2 section 4.6.6).
        let mut drop = 0u32;
        let mut last = 1;
        for (k, ep) in endpoints.iter().enumerate() {
            let i = dci(ep.address);
            if i < 2 {
                return Err(UsbError::BadEndpoint);
            }
            let ty = match (ep.transfer_type(), ep.direction()) {
                (TransferType::Control, _) => EP_TYPE_CONTROL,
                (TransferType::Bulk, Direction::Out) => 2,
                (TransferType::Interrupt, Direction::Out) => 3,
                (TransferType::Bulk, Direction::In) => 6,
                (TransferType::Interrupt, Direction::In) => 7,
                (TransferType::Isochronous, Direction::Out) => EP_TYPE_ISOCH_OUT,
                (TransferType::Isochronous, Direction::In) => EP_TYPE_ISOCH_IN,
            };
            let mps = ep.max_packet_size() as u32;
            // A high-speed periodic endpoint moving 2 or 3 packets a
            // microframe has the extra ones in Max Burst Size (Mult is for
            // SuperSpeed isochronous only). Elsewhere those bits are reserved.
            let isoch = ep.transfer_type() == TransferType::Isochronous;
            let periodic = isoch || ep.transfer_type() == TransferType::Interrupt;
            let burst = if periodic && speed == Speed::High { ep.extra_transactions() as u32 } else { 0 };
            if burst > 2 || (isoch && speed == Speed::Low) {
                return Err(UsbError::BadEndpoint);
            }
            let esit = if periodic { mps * (burst + 1) } else { 0 };
            if isoch {
                if esit as usize > ISOCH_SLOT_LEN || mps == 0 {
                    return Err(UsbError::BadEndpoint);
                }
                let buf = new_dma(dma, ac64, ISOCH_DEPTH * ISOCH_SLOT_LEN).ok_or(UsbError::NoResources)?;
                let microframes = 1u32 << interval(ep, speed);
                *new_isoch.get_mut(k).ok_or(UsbError::NoResources)? = Some(IsochEp {
                    dev: dev.0,
                    dci: i,
                    buf,
                    tds: [IsochTd { trb: 0, len: 0, done: None }; ISOCH_DEPTH],
                    head: 0,
                    count: 0,
                    dir_in: ep.direction() == Direction::In,
                    max_len: esit as usize,
                    mps,
                    burst,
                    ss: matches!(speed, Speed::Super | Speed::SuperPlus),
                    period_frames: (microframes / 8) as u16,
                    last_frame: None,
                });
            }
            let ring = new_ring(dma, ac64).ok_or(UsbError::NoResources)?;
            let ctx = (i + 1) * c;
            for n in 0..8 {
                ctx_set(&slot.input, ctx, n, 0);
            }
            ctx_set(&slot.input, ctx, 0, interval(ep, speed) << 16);
            // Isochronous endpoints do not retry (CErr 0).
            let cerr = if isoch { 0 } else { 3 };
            ctx_set(&slot.input, ctx, 1, cerr << 1 | ty << 3 | burst << 8 | mps << 16);
            let deq = ring.base().as_u64() | ring.cycle() as u64;
            ctx_set(&slot.input, ctx, 2, deq as u32);
            ctx_set(&slot.input, ctx, 3, (deq >> 32) as u32);
            let avg = if periodic { esit } else { 3072 };
            ctx_set(&slot.input, ctx, 4, (esit & 0xffff) << 16 | avg);
            *new_rings.get_mut(k).ok_or(UsbError::NoResources)? = Some((i, ring));
            if slot.endpoints.iter().flatten().any(|e| e.dci == i) {
                drop |= 1 << i;
            }
            add |= 1 << i;
            last = last.max(i);
        }
        // The slot context is copied from the output context with the
        // context-entry count raised to cover the new endpoints.
        ctx_set(&slot.input, 0, 0, drop);
        ctx_set(&slot.input, 0, 1, add);
        for n in 0..4 {
            ctx_set(&slot.input, c, n, ctx_get(&slot.output, 0, n));
        }
        let entries = (ctx_get(&slot.output, 0, 0) >> 27).max(last as u32);
        let dw0 = ctx_get(&slot.input, c, 0);
        ctx_set(&slot.input, c, 0, (dw0 & !(0x1f << 27)) | entries << 27);
        let input = slot.input.device_addr().as_u64();

        self.command(Trb::configure_endpoint(dev.0, input))?;
        // Rebuilt endpoints lose their queued isochronous transfers.
        for e in self.isoch.iter_mut() {
            if e.as_ref().is_some_and(replaced) {
                *e = None;
            }
        }
        for new in new_isoch.into_iter().flatten() {
            // Room was checked above.
            if let Some(free) = self.isoch.iter_mut().find(|e| e.is_none()) {
                *free = Some(new);
            }
        }
        let slot = self.slot(dev)?;
        for (i, ring) in new_rings.into_iter().flatten() {
            let ep = Endpoint { dci: i, ring, pending: None };
            match slot.endpoint(i) {
                Some(old) => *old = ep,
                // Room was checked above.
                None => {
                    if let Some(free) = slot.endpoints.iter_mut().find(|e| e.is_none()) {
                        *free = Some(ep);
                    }
                }
            }
        }
        Ok(())
    }

    fn control_in(&mut self, dev: DeviceId, setup: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError> {
        let len = (setup.length as usize).min(buf.len());
        let n = self.control(dev, SetupPacket { length: len as u16, ..setup })?;
        if let Some(dst) = buf.get_mut(..n) {
            self.bounce.read(0, dst);
        }
        Ok(n)
    }

    fn control_out(&mut self, dev: DeviceId, setup: SetupPacket, data: &[u8]) -> Result<(), UsbError> {
        let len = (setup.length as usize).min(data.len());
        if len > BOUNCE_LEN {
            return Err(UsbError::NoResources);
        }
        self.bounce.write(0, data.get(..len).ok_or(UsbError::NoResources)?);
        self.control(dev, SetupPacket { length: len as u16, ..setup }).map(drop)
    }

    fn transfer_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Result<usize, UsbError> {
        let mut done = 0;
        while done < buf.len() {
            let want = (buf.len() - done).min(BOUNCE_LEN);
            let n = self.transfer_chunk(dev, endpoint | 0x80, want)?;
            self.bounce.read(0, buf.get_mut(done..done + n).ok_or(UsbError::Controller)?);
            done += n;
            if n < want {
                break; // a short packet ends the transfer
            }
        }
        Ok(done)
    }

    fn submit_in(&mut self, dev: DeviceId, endpoint: u8, len: usize) -> Result<(), UsbError> {
        if len == 0 || len > MAX_SUBMIT_LEN {
            return Err(UsbError::NoResources);
        }
        let endpoint = endpoint | 0x80;
        let i = dci(endpoint);
        self.idle_ring(dev, endpoint)?;
        let buf = new_dma(self.dma, self.ac64, MAX_SUBMIT_LEN).ok_or(UsbError::NoResources)?;
        let addr = buf.device_addr().as_u64();
        let ep = self.slot(dev)?.endpoint(i).ok_or(UsbError::BadEndpoint)?;
        let trb = ep.ring.push(Trb::normal(addr, len as u32)).as_u64();
        ep.pending = Some(Pending { buf, trb, len, done: None });
        self.ring_doorbell(dev.0, i as u32);
        Ok(())
    }

    fn poll_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
        let i = dci(endpoint | 0x80);
        match self.slot(dev) {
            _ if endpoint & 0xf == 0 => return Some(Err(UsbError::BadEndpoint)),
            Ok(slot) if slot.endpoints.iter().flatten().any(|e| e.dci == i && e.pending.is_some()) => {}
            Ok(_) => return Some(Err(UsbError::BadEndpoint)),
            Err(e) => return Some(Err(e)),
        }
        self.drain_events();
        let ep = self.slot(dev).ok()?.endpoint(i)?;
        let ev = ep.pending.as_ref()?.done?;
        let p = ep.pending.take()?;
        Some(match ev.completion_code() {
            completion::SUCCESS | completion::SHORT_PACKET => {
                let n = (p.len - (ev.residual() as usize).min(p.len)).min(buf.len());
                if let Some(dst) = buf.get_mut(..n) {
                    p.buf.read(0, dst);
                }
                Ok(n)
            }
            code => {
                self.recover(dev, i, true);
                Err(error_from(code))
            }
        })
    }

    fn transfer_out(&mut self, dev: DeviceId, endpoint: u8, data: &[u8]) -> Result<(), UsbError> {
        if data.is_empty() {
            // A zero-length packet, which ends a transfer that filled its last packet.
            return self.transfer_chunk(dev, endpoint & 0x7f, 0).map(drop);
        }
        for chunk in data.chunks(BOUNCE_LEN) {
            self.bounce.write(0, chunk);
            self.transfer_chunk(dev, endpoint & 0x7f, chunk.len())?;
        }
        Ok(())
    }
}

impl<'d, D: DmaAllocator + ?Sized> Xhci<'d, D> {
    /// The queue of the isochronous endpoint with DCI `i` on `dev`.
    fn isoch_ep(&mut self, dev: DeviceId, i: usize) -> Result<&mut IsochEp<'d, D>, UsbError> {
        self.live_slot(dev)?;
        self.isoch.iter_mut().flatten().find(|e| e.dev == dev.0 && e.dci == i).ok_or(UsbError::BadEndpoint)
    }

    fn isoch_submit(
        &mut self,
        dev: DeviceId,
        endpoint: u8,
        data: Option<&[u8]>,
        len: usize,
        start: IsochStart,
    ) -> Result<(), UsbError> {
        let i = dci(endpoint);
        let mfindex = self.rt_read(MFINDEX);
        let e = self.isoch_ep(dev, i)?;
        if (data.is_some() && e.dir_in) || (data.is_none() && !e.dir_in) {
            return Err(UsbError::BadEndpoint);
        }
        if e.count == ISOCH_DEPTH {
            return Err(UsbError::Busy);
        }
        if len == 0 || len > e.max_len {
            return Err(UsbError::NoResources);
        }
        let k = (e.head + e.count) % ISOCH_DEPTH;
        if let Some(data) = data {
            e.buf.write(k * ISOCH_SLOT_LEN, data);
        }
        let frame = match start {
            IsochStart::Asap => None,
            IsochStart::Frame(f) => Some(f & 0x7ff),
            IsochStart::Next => match (e.last_frame, e.period_frames) {
                (_, 0) => None,
                (Some(last), p) => Some(last.wrapping_add(p) & 0x7ff),
                (None, _) => Some(((mfindex >> 3) as u16).wrapping_add(ISOCH_LEAD_FRAMES) & 0x7ff),
            },
        };
        let packets = len.div_ceil(e.mps as usize) as u32;
        let addr = e.buf.device_addr().as_u64() + (k * ISOCH_SLOT_LEN) as u64;
        let trb = Trb::isoch(addr, len as u32, packets, e.burst, e.ss, frame, e.dir_in);
        let ring = &mut self.slot(dev)?.endpoint(i).ok_or(UsbError::BadEndpoint)?.ring;
        let trb_addr = ring.push(trb).as_u64();
        let e = self.isoch_ep(dev, i)?;
        *e.tds.get_mut(k).ok_or(UsbError::BadEndpoint)? = IsochTd { trb: trb_addr, len: len as u32, done: None };
        e.count += 1;
        e.last_frame = frame;
        self.ring_doorbell(dev.0, i as u32);
        Ok(())
    }
}

impl<D: DmaAllocator + ?Sized> IsochHost for Xhci<'_, D> {
    fn isoch_frame(&self) -> u16 {
        (self.rt_read(MFINDEX) >> 3 & 0x7ff) as u16
    }

    fn isoch_submit_in(&mut self, dev: DeviceId, endpoint: u8, len: usize, start: IsochStart) -> Result<(), UsbError> {
        self.isoch_submit(dev, endpoint | 0x80, None, len, start)
    }

    fn isoch_submit_out(
        &mut self,
        dev: DeviceId,
        endpoint: u8,
        data: &[u8],
        start: IsochStart,
    ) -> Result<(), UsbError> {
        self.isoch_submit(dev, endpoint & 0x7f, Some(data), data.len(), start)
    }

    fn isoch_poll(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
        let i = dci(endpoint);
        if endpoint & 0xf == 0 {
            return Some(Err(UsbError::BadEndpoint));
        }
        self.drain_events();
        let e = match self.isoch_ep(dev, i) {
            Ok(e) if e.count > 0 => e,
            Ok(_) => return Some(Err(UsbError::BadEndpoint)),
            Err(err) => return Some(Err(err)),
        };
        let k = e.head;
        let td = *e.tds.get(k)?;
        let ev = td.done?;
        e.head = (k + 1) % ISOCH_DEPTH;
        e.count -= 1;
        Some(match ev.completion_code() {
            completion::SUCCESS | completion::SHORT_PACKET => {
                let n = td.len as usize - (ev.residual() as usize).min(td.len as usize);
                if e.dir_in {
                    let m = n.min(buf.len());
                    if let Some(dst) = buf.get_mut(..m) {
                        e.buf.read(k * ISOCH_SLOT_LEN, dst);
                    }
                    Ok(m)
                } else {
                    Ok(n)
                }
            }
            code => Err(error_from(code)),
        })
    }
}

impl<D: DmaAllocator + ?Sized> Drop for Xhci<'_, D> {
    fn drop(&mut self) {
        // Stop the controller before the rings and contexts are freed. One
        // that does not halt may still write to them: they are leaked.
        self.op_write(USBCMD, self.op_read(USBCMD) & !CMD_RUN);
        if self.poll(REGISTER_TIMEOUT_NS, |hc| hc.op_read(USBSTS) & STS_HALTED != 0).is_err() {
            return;
        }
        // SAFETY: each field is dropped once, here, and not used again.
        unsafe {
            ManuallyDrop::drop(&mut self.isoch);
            ManuallyDrop::drop(&mut self.slots);
            ManuallyDrop::drop(&mut self.bounce);
            ManuallyDrop::drop(&mut self.events);
            ManuallyDrop::drop(&mut self.commands);
            ManuallyDrop::drop(&mut self._scratchpad);
            ManuallyDrop::drop(&mut self.dcbaa);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn device_context_indices() {
        assert_eq!(dci(0), 1);
        assert_eq!(dci(0x01), 2);
        assert_eq!(dci(0x81), 3);
        assert_eq!(dci(0x8f), 31);
    }

    #[test]
    fn interval_exponents() {
        let ep =
            |attributes, interval| EndpointDescriptor { address: 0x81, attributes, max_packet_size_raw: 8, interval };
        // A full-speed keyboard polled every 10 ms: 2^6 x 125 us = 8 ms.
        assert_eq!(interval(&ep(3, 10), Speed::Full), 6);
        assert_eq!(interval(&ep(3, 1), Speed::Low), 3);
        assert_eq!(interval(&ep(3, 255), Speed::Full), 10);
        // Full-speed isochronous: bInterval 1 is every frame (2^3 microframes).
        assert_eq!(interval(&ep(1, 1), Speed::Full), 3);
        assert_eq!(interval(&ep(1, 4), Speed::Full), 6);
        assert_eq!(interval(&ep(1, 1), Speed::High), 0);
        // High speed: 2^(bInterval-1) microframes.
        assert_eq!(interval(&ep(3, 4), Speed::High), 3);
        assert_eq!(interval(&ep(2, 0), Speed::High), 0);
    }

    #[test]
    fn small_enough_for_a_boot_stack() {
        // A 31-entry table of rings and pending transfers per slot made the
        // controller ~30 KiB, which overflowed the 64 KiB boot stack of the
        // riscv-virt example when built and returned by value.
        let size = size_of::<Xhci<'_, crate::testing::HostDma>>();
        assert!(size < 16 * 1024, "Xhci is {size} bytes");
    }

    /// A controller over fake registers (op at 0x20, runtime at 0x200, no
    /// reset sequence) with one slot whose endpoint 3 has a `submit_in`
    /// transfer outstanding at TRB address 0x1000. Nothing answers commands
    /// or transfers.
    fn fake<'dma>(
        dma: &'dma crate::testing::HostDma,
        regs: &mut [u32],
    ) -> Xhci<'dma, crate::testing::HostDma> {
        // SAFETY: the window covers the caller's array, which outlives the controller.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), regs.len() * 4) };
        let mut endpoints = [const { None }; MAX_ENDPOINTS];
        endpoints[0] = Some(Endpoint { dci: 1, ring: ProducerRing::new(dma).unwrap(), pending: None });
        let pending = Pending { buf: OwnedDma::new(dma, 8).unwrap(), trb: 0x1000, len: 8, done: None };
        endpoints[1] = Some(Endpoint { dci: 3, ring: ProducerRing::new(dma).unwrap(), pending: Some(pending) });
        let slot = Slot {
            output: OwnedDma::new(dma, 1024).unwrap(),
            input: OwnedDma::new(dma, 1056).unwrap(),
            endpoints,
            speed: Speed::Full,
            topo: Topology { route: 0, root_port: 1, parent: 0, tt: (0, 0) },
            hub_ports: 0,
            dead: false,
        };
        let mut slots = [const { None }; MAX_SLOTS as usize];
        slots[0] = Some(slot);
        Xhci {
            io,
            op: 0x20,
            rt: 0x200,
            db: 0x100,
            ctx_size: 32,
            max_ports: 1,
            ac64: true,
            commands_stuck: false,
            dma,
            dcbaa: ManuallyDrop::new(OwnedDma::new(dma, 2048).unwrap()),
            _scratchpad: ManuallyDrop::new(None),
            commands: ManuallyDrop::new(ProducerRing::new(dma).unwrap()),
            events: ManuallyDrop::new(EventRing::new(dma).unwrap()),
            bounce: ManuallyDrop::new(OwnedDma::new(dma, BOUNCE_LEN).unwrap()),
            slots: ManuallyDrop::new(slots),
            isoch: ManuallyDrop::new([const { None }; MAX_ISOCH_ENDPOINTS]),
            interrupts: 0,
            mode: InterruptMode::Intx,
            clock: None,
        }
    }

    fn transfer_event(slot: u8, dci: u8, trb: u64) -> Trb {
        Trb {
            param: trb,
            status: (completion::SUCCESS as u32) << 24,
            control: kind::TRANSFER_EVENT << 10 | (dci as u32) << 16 | (slot as u32) << 24,
        }
    }

    #[test]
    fn interrupt_enable_sets_ie_and_inte() {
        let dma = crate::testing::HostDma::default();
        let mut regs = vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        hc.enable_interrupts();
        drop(hc);
        assert_eq!(regs[(0x200 + IMAN) / 4], IMAN_IP | IMAN_IE);
        assert_eq!(regs[(0x200 + IMOD) / 4], IMOD_INTERVAL);
        assert_eq!(regs[(0x20 + USBCMD) / 4] & CMD_INTE, CMD_INTE);
    }

    #[test]
    fn interrupt_not_ours_is_ignored() {
        let dma = crate::testing::HostDma::default();
        let mut regs = vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        hc.events.controller_write(0, transfer_event(1, 3, 0x1000));
        assert!(!hc.handle_interrupt());
        assert_eq!(hc.interrupts_handled(), 0);
        assert!(hc.slot(DeviceId(1)).unwrap().endpoint(3).unwrap().pending.as_ref().unwrap().done.is_none());
    }

    #[test]
    fn interrupt_files_events_and_acks() {
        let dma = crate::testing::HostDma::default();
        let mut regs = vec![0u32; 0x400];
        regs[(0x20 + USBSTS) / 4] = STS_EINT;
        let mut hc = fake(&dma, &mut regs);
        // A stray event for another transfer, then the keyboard's.
        hc.events.controller_write(0, transfer_event(1, 3, 0x2000));
        hc.events.controller_write(1, transfer_event(1, 3, 0x1000));
        hc.events.controller_write(2, Trb { param: 0, status: 0, control: kind::PORT_STATUS_CHANGE << 10 });
        assert!(hc.handle_interrupt());
        assert_eq!(hc.interrupts_handled(), 1);
        let done = hc.slot(DeviceId(1)).unwrap().endpoint(3).unwrap().pending.as_ref().unwrap().done;
        assert_eq!(done.map(|e| e.param), Some(0x1000));
        let erdp = hc.events.dequeue_addr().as_u64() | ERDP_BUSY as u64;
        drop(hc);
        // EINT and IP were written back (write-1-to-clear); ERDP moved past 3 events with EHB.
        assert_eq!(regs[(0x20 + USBSTS) / 4], STS_EINT);
        assert_eq!(regs[(0x200 + IMAN) / 4], IMAN_IP | IMAN_IE);
        let lo = regs[(0x200 + ERDP) / 4] as u64 | (regs[(0x200 + ERDP) / 4 + 1] as u64) << 32;
        assert_eq!(lo, erdp);
    }

    #[test]
    fn rejects_non_xhci_registers() {
        let mut regs = [0u32; 64];
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), 256) };
        let dma = crate::testing::HostDma::default();
        assert_eq!(Xhci::new(io, &dma).err(), Some(XhciError::BadRegisters));
        assert_eq!(dma.live.get(), 0);
    }

    /// Capability registers of a halted controller with `ports` ports, op at
    /// 0x20, doorbells at `db` and runtime registers at 0x200.
    fn caps(regs: &mut [u32], ports: u32, db: u32, ac64: bool) {
        regs[0] = 0x0100_0020;
        regs[HCSPARAMS1 / 4] = ports << 24 | MAX_SLOTS as u32;
        regs[HCCPARAMS1 / 4] = ac64 as u32;
        regs[DBOFF / 4] = db;
        regs[RTSOFF / 4] = 0x200;
        regs[(0x20 + USBSTS) / 4] = STS_HALTED;
    }

    #[test]
    fn rejects_windows_missing_ports_or_doorbells() {
        let dma = crate::testing::HostDma::default();
        let mut regs = [0u32; 0x110];
        // Four ports end at 0x460, past the 0x440-byte window.
        caps(&mut regs, 4, 0x100, true);
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x440) };
        assert_eq!(Xhci::new(io, &dma).err(), Some(XhciError::BadRegisters));
        // One port fits, but the doorbells of slots 1..=8 run past the end.
        caps(&mut regs, 1, 0x430, true);
        // SAFETY: as above.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x440) };
        assert_eq!(Xhci::new(io, &dma).err(), Some(XhciError::BadRegisters));
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn registers_outside_the_window_do_not_panic() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        let hc = fake(&dma, &mut regs);
        assert_eq!(hc.r32(0x10_0000), 0);
        hc.w32(0x10_0000, 1);
        hc.ring_doorbell(255, 1);
    }

    /// Hands out memory the device sees above 4 GiB.
    #[derive(Default)]
    struct HighDma(crate::testing::HostDma);

    impl DmaAllocator for HighDma {
        fn alloc_coherent(&self, len: usize) -> Option<DmaBuffer> {
            let b = self.0.alloc_coherent(len)?;
            let high = PhysAddr::new(b.device_addr().as_u64() | 1 << 40);
            // SAFETY: the same memory, at an address only the (fake) device uses.
            Some(unsafe { DmaBuffer::new(b.cpu_ptr(), high, len) })
        }

        unsafe fn free_coherent(&self, buf: DmaBuffer) {
            // SAFETY: forwarded contract; the buffer came from `self.0`.
            unsafe { self.0.free_coherent(buf) }
        }
    }

    #[test]
    fn needs_ac64_for_memory_above_4g() {
        assert!(reachable(false, 0xffff_f000, 0x1000));
        assert!(!reachable(false, 0xffff_f000, 0x1001));
        assert!(reachable(true, 1 << 40, 0x1000));

        let dma = HighDma::default();
        let mut regs = std::vec![0u32; 0x400];
        caps(&mut regs, 1, 0x100, false);
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x1000) };
        assert_eq!(Xhci::new(io, &dma).err(), Some(XhciError::HighMemory));
        // The controller was halted, so the memory was freed.
        assert_eq!(dma.0.live.get(), 0);
        // With AC64 it gets as far as the reset, which nothing completes here.
        caps(&mut regs, 1, 0x100, true);
        // SAFETY: as above.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x1000) };
        assert_eq!(Xhci::new(io, &dma).err(), Some(XhciError::Timeout));
    }

    #[test]
    fn waits_use_the_clock_and_the_smi_enables_are_cleared() {
        use crate::usbhc::fakedev::TickClock;
        let dma = HighDma::default();
        let mut regs = std::vec![0u32; 0x400];
        caps(&mut regs, 1, 0x100, true);
        // A legacy support capability at 0x300 with every SMI enable and status bit set.
        regs[HCCPARAMS1 / 4] |= 0xc0 << 16;
        regs[0xc0] = EXT_CAP_LEGACY;
        regs[0xc1] = u32::MAX;
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x1000) };
        let clock = TickClock::default();
        // The reset never completes: the time limit, not a count of polls, ends the wait.
        assert_eq!(Xhci::with_clock(io, &dma, &clock).err(), Some(XhciError::Timeout));
        assert!(clock.now_ns() >= REGISTER_TIMEOUT_NS, "waited the whole time");
        assert_eq!(regs[0xc1], LEGACY_KEEP_BITS | LEGACY_SMI_STATUS);
    }

    fn command_completion(trb: PhysAddr, code: u8, slot: u8) -> Trb {
        Trb {
            param: trb.as_u64(),
            status: (code as u32) << 24,
            control: kind::COMMAND_COMPLETION << 10 | (slot as u32) << 24,
        }
    }

    #[test]
    fn timed_out_command_is_aborted() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        regs[(0x20 + CRCR) / 4] = CRCR_CRR;
        let mut hc = fake(&dma, &mut regs);
        assert_eq!(hc.command(Trb::disable_slot(1)).err(), Some(UsbError::Timeout));
        // Aborted, and the TRB turned into a No Op in case the ring stopped on it.
        assert_eq!(hc.r32(0x20 + CRCR), CRCR_CA);
        let t = hc.commands.get(0);
        assert_eq!((t.kind(), t.cycle()), (kind::NO_OP_COMMAND, true));
        // A ring that is not running has not fetched its command: it is cancelled too.
        assert_eq!(hc.command(Trb::disable_slot(1)).err(), Some(UsbError::Timeout));
        assert_eq!(hc.commands.get(1).kind(), kind::NO_OP_COMMAND);
        assert!(!hc.commands_stuck);
    }

    #[test]
    fn stale_event_does_not_complete_a_control_transfer() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        // A late completion for an earlier transfer on endpoint 0.
        hc.events.controller_write(0, transfer_event(1, 1, 0xdead_0000));
        let mut buf = [0u8; 8];
        let dev = DeviceId(1);
        assert_eq!(hc.control_in(dev, SetupPacket::get_descriptor(1, 0, 8), &mut buf), Err(UsbError::Timeout));
        // Nothing answered Stop Endpoint or Set TR Dequeue Pointer, so the
        // queued TRBs may still use the bounce buffer: the slot is dead.
        assert!(hc.slot(dev).unwrap().dead);
        assert_eq!(hc.control_in(dev, SetupPacket::get_descriptor(1, 0, 8), &mut buf), Err(UsbError::NoDevice));
        assert_eq!(hc.transfer_in(dev, 0x83, &mut buf), Err(UsbError::NoDevice));
        assert_eq!(hc.transfer_out(dev, 0x02, &buf), Err(UsbError::NoDevice));
    }

    #[test]
    fn failed_detach_keeps_the_slot() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        hc.detach(DeviceId(1));
        assert!(hc.slot(DeviceId(1)).is_ok_and(|s| s.dead), "Disable Slot never completed");
        // Disable Slot completing, even with Slot Not Enabled, frees it.
        let next = hc.commands.enqueue_addr();
        hc.events.controller_write(0, command_completion(next, completion::SLOT_NOT_ENABLED, 1));
        hc.detach(DeviceId(1));
        assert!(hc.slot(DeviceId(1)).is_err());
    }

    #[test]
    fn drop_leaks_memory_of_a_controller_that_will_not_halt() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        drop(fake(&dma, &mut regs));
        assert!(dma.live.get() > 0);
        let dma = crate::testing::HostDma::default();
        regs[(0x20 + USBSTS) / 4] = STS_HALTED;
        drop(fake(&dma, &mut regs));
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn enable_slot_returning_a_slot_in_use() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        // Port 1: connected, enabled, full speed.
        regs[(0x20 + PORTSC) / 4] = PORT_CONNECTED | PORT_ENABLED | 1 << 10;
        let mut hc = fake(&dma, &mut regs);
        let output = hc.slot(DeviceId(1)).unwrap().output.device_addr();
        let enable = hc.commands.enqueue_addr();
        hc.events.controller_write(0, command_completion(enable, completion::SUCCESS, 1));
        assert_eq!(hc.attach(1), Err(UsbError::Controller));
        let slot = hc.slot(DeviceId(1)).unwrap();
        assert_eq!(slot.output.device_addr(), output, "not overwritten");
        assert!(slot.dead);
        // Enable Slot, then Disable Slot (cancelled here, as nothing answered it).
        assert_eq!(hc.commands.enqueue_addr().as_u64(), enable.as_u64() + 32);
    }

    #[test]
    fn endpoint_context_types_and_bursts() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        hc.slot(DeviceId(1)).unwrap().speed = Speed::High;
        let ep = |address, attributes, max_packet_size_raw| EndpointDescriptor {
            address,
            attributes,
            max_packet_size_raw,
            interval: 1,
        };
        let configure = hc.commands.enqueue_addr();
        hc.events.controller_write(0, command_completion(configure, completion::SUCCESS, 1));
        // A high-bandwidth interrupt IN endpoint (3 x 64 bytes), and a control endpoint.
        let eps = [ep(0x81, 3, 2 << 11 | 64), ep(0x02, 0, 64)];
        hc.configure_endpoints(DeviceId(1), &eps).unwrap();
        let input = &hc.slot(DeviceId(1)).unwrap().input;
        assert_eq!(ctx_get(input, 4 * 32, 1), 3 << 1 | 7 << 3 | 2 << 8 | 64 << 16);
        assert_eq!(ctx_get(input, 4 * 32, 4) >> 16, 3 * 64, "max ESIT payload");
        assert_eq!(ctx_get(input, 5 * 32, 1), 3 << 1 | EP_TYPE_CONTROL << 3 | 64 << 16);
        // The reserved fourth transaction is refused, and the bits mean nothing on bulk.
        assert_eq!(hc.configure_endpoints(DeviceId(1), &[ep(0x81, 3, 3 << 11 | 64)]), Err(UsbError::BadEndpoint));
        let configure = hc.commands.enqueue_addr();
        hc.events.controller_write(1, command_completion(configure, completion::SUCCESS, 1));
        hc.configure_endpoints(DeviceId(1), &[ep(0x83, 2, 3 << 11 | 512)]).unwrap();
        let input = &hc.slot(DeviceId(1)).unwrap().input;
        assert_eq!(ctx_get(input, 8 * 32, 1), 3 << 1 | 6 << 3 | 512 << 16);
    }

    // ---- message interrupts ----

    use core::cell::RefCell;
    use osmium_hal::pci::{Address, cap, reg};
    use std::collections::BTreeMap;

    /// Configuration space as a map of dwords; unset ones read as zero.
    #[derive(Default)]
    struct FakeConfig(RefCell<BTreeMap<u16, u32>>);

    impl FakeConfig {
        fn set(&self, off: u16, v: u32) {
            self.0.borrow_mut().insert(off, v);
        }
        fn get(&self, off: u16) -> u32 {
            self.0.borrow().get(&off).copied().unwrap_or(0)
        }
        /// A function with a capability list starting at 0x40: MSI-X (one
        /// entry, table at BAR 0 + 0x100) and/or a 64-bit MSI capability.
        fn with(msix: bool, msi: bool) -> Self {
            let cfg = Self::default();
            cfg.set(reg::VENDOR_DEVICE, 0x000d_1b36);
            cfg.set(reg::COMMAND_STATUS, 1 << 20);
            cfg.set(reg::CAPABILITIES, 0x40);
            let msi_at = if msix { 0x50 } else { 0x40 };
            if msix {
                cfg.set(0x40, (msi as u32 * 0x50) << 8 | cap::MSIX as u32);
                cfg.set(0x44, 0x100); // table: BAR 0, offset 0x100
                cfg.set(0x48, 0x180);
            }
            if msi {
                cfg.set(msi_at, (1 << 7) << 16 | cap::MSI as u32); // 64-bit, one vector
            }
            cfg
        }
    }

    impl ConfigAccess for FakeConfig {
        fn read32(&self, _: Address, off: u16) -> u32 {
            self.get(off)
        }
        fn write32(&self, _: Address, off: u16, v: u32) {
            self.set(off, v);
        }
    }

    const A: Address = Address::new(0, 3, 0);
    const MSG: MsiMessage = MsiMessage { address: 0xfee0_1000, data: 0x41 };

    #[test]
    fn msix_interrupts_service_every_message() {
        let cfg = FakeConfig::with(true, true);
        let f = Function::new(&cfg, A).unwrap();
        let dma = crate::testing::HostDma::default();
        let mut regs = vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        let mut table = [0u32; 0x80]; // the BAR: table at 0x100 is word 0x40
        table[0x40 + 3] = 1; // entry 0 starts masked
        // SAFETY: the window covers a local array that outlives the controller.
        let window = unsafe { IoMem::new(table.as_mut_ptr().cast(), 0x200) };
        let mut asked = None;
        let mode = hc.enable_message_interrupts(&f, MSG, |bir| {
            asked = Some(bir);
            Some(window)
        });
        assert_eq!((mode, asked, hc.interrupt_mode()), (InterruptMode::Msix, Some(0), InterruptMode::Msix));
        // Enabled in the capability, INTx off, entry 0 programmed and unmasked.
        assert_ne!(cfg.get(0x40) >> 16 & 0x8000, 0);
        assert_ne!(cfg.get(reg::COMMAND_STATUS) & 1 << 10, 0);
        assert_eq!(&table[0x40..0x44], [0xfee0_1000, 0, 0x41, 0]);
        // A message with neither USBSTS.EINT nor IMAN.IP set is still serviced.
        hc.events.inject(transfer_event(1, 3, 0x1000));
        assert!(hc.handle_interrupt());
        assert_eq!(hc.interrupts_handled(), 1);
        assert!(hc.slot(DeviceId(1)).unwrap().endpoint(3).unwrap().pending.as_ref().unwrap().done.is_some());
        drop(hc);
        assert_eq!(regs[(0x200 + IMAN) / 4], IMAN_IP | IMAN_IE);
    }

    #[test]
    fn msi_is_the_fallback_without_msix() {
        let cfg = FakeConfig::with(false, true);
        let f = Function::new(&cfg, A).unwrap();
        let dma = crate::testing::HostDma::default();
        let mut regs = vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        assert_eq!(hc.enable_message_interrupts(&f, MSG, |_| None), InterruptMode::Msi);
        // Address low/high, data (64-bit capability), enable bit.
        assert_eq!((cfg.get(0x44), cfg.get(0x48), cfg.get(0x4c)), (0xfee0_1000, 0, 0x41));
        assert_eq!(cfg.get(0x40) >> 16 & 1, 1);
        assert!(hc.handle_interrupt());
    }

    #[test]
    fn no_message_capability_leaves_intx() {
        let cfg = FakeConfig::with(false, false);
        let f = Function::new(&cfg, A).unwrap();
        let dma = crate::testing::HostDma::default();
        let mut regs = vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        assert_eq!(hc.enable_message_interrupts(&f, MSG, |_| None), InterruptMode::Intx);
        // The fake registers do not clear the bits enable_interrupts set.
        hc.rt_write(IMAN, 0);
        hc.op_write(USBSTS, 0);
        assert!(!hc.handle_interrupt(), "a shared line: nothing asserted, nothing done");
        // An MSI-X table the BAR cannot supply also falls back.
        let cfg = FakeConfig::with(true, false);
        let f = Function::new(&cfg, A).unwrap();
        assert_eq!(hc.enable_message_interrupts(&f, MSG, |_| None), InterruptMode::Intx);
        assert_eq!(cfg.get(0x40) >> 16 & 0x8000, 0, "MSI-X left disabled");
        drop(hc);
        assert_eq!(regs[(0x200 + IMAN) / 4], IMAN_IP | IMAN_IE, "interrupter still enabled");
    }

    // ---- hubs ----

    /// Makes slot 1 a hub with `ports` ports of speed `speed` at `topo`.
    fn make_hub(hc: &mut Xhci<'_, crate::testing::HostDma>, speed: Speed, topo: Topology, ports: u8) {
        let slot = hc.slot(DeviceId(1)).unwrap();
        slot.speed = speed;
        slot.topo = topo;
        slot.hub_ports = ports;
    }

    /// Runs `attach_hub_port` against a controller that enables slot `new`
    /// and then rejects Address Device, which leaves the new slot's input
    /// context behind (dead) to inspect.
    fn attach_and_inspect(
        hc: &mut Xhci<'_, crate::testing::HostDma>,
        port: u8,
        speed: Speed,
        new: u8,
    ) -> Topology {
        let enable = hc.commands.enqueue_addr();
        hc.events.inject(command_completion(enable, completion::SUCCESS, new));
        let address = PhysAddr::new(enable.as_u64() + 16);
        hc.events.inject(command_completion(address, completion::PARAMETER, new));
        assert_eq!(hc.attach_hub_port(DeviceId(1), port, speed), Err(UsbError::Controller));
        let c = hc.ctx_size;
        let slot = hc.slot(DeviceId(new)).unwrap();
        let (dw0, dw1, dw2) = (ctx_get(&slot.input, c, 0), ctx_get(&slot.input, c, 1), ctx_get(&slot.input, c, 2));
        assert_eq!(dw0 >> 20 & 0xf, speed_id(speed), "slot speed");
        assert_eq!(dw0 >> 27, 1);
        Topology {
            route: dw0 & 0xf_ffff,
            root_port: (dw1 >> 16) as u8,
            parent: slot.topo.parent,
            tt: (dw2 as u8, (dw2 >> 8) as u8),
        }
    }

    #[test]
    fn hub_slot_context_fields() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        // Not a hub yet.
        assert_eq!(hc.attach_hub_port(DeviceId(1), 1, Speed::Full), Err(UsbError::Unsupported));
        assert_eq!(hc.attach_hub_port(DeviceId(5), 1, Speed::Full), Err(UsbError::NoDevice));
        assert_eq!(hc.configure_hub(DeviceId(1), 0, 0, false), Err(UsbError::Unsupported));
        // The output context has the hub's address state; Configure Endpoint copies it.
        ctx_set(&hc.slot(DeviceId(1)).unwrap().output, 0, 3, 0x0200_0001);
        let configure = hc.commands.enqueue_addr();
        hc.events.inject(command_completion(configure, completion::SUCCESS, 1));
        hc.configure_hub(DeviceId(1), 4, 2, true).unwrap();
        let slot = hc.slot(DeviceId(1)).unwrap();
        assert_eq!(slot.hub_ports, 4);
        assert_eq!(ctx_get(&slot.input, 0, 1), 1, "only the slot context is added");
        let dw0 = ctx_get(&slot.input, 32, 0);
        assert_eq!((dw0 >> 26 & 1, dw0 >> 25 & 1), (1, 1), "hub and multi-TT bits");
        assert_eq!(ctx_get(&slot.input, 32, 1) >> 24, 4, "number of ports");
        assert_eq!(ctx_get(&slot.input, 32, 2) >> 16 & 3, 2, "TT think time");
        assert_eq!(ctx_get(&slot.input, 32, 3), 0x0200_0001, "state copied from the output context");
        assert_eq!(hc.commands.get(0).kind(), kind::CONFIGURE_ENDPOINT);
        // Ports beyond the hub's are refused.
        assert_eq!(hc.attach_hub_port(DeviceId(1), 5, Speed::Full), Err(UsbError::NoDevice));
        assert_eq!(hc.attach_hub_port(DeviceId(1), 0, Speed::Full), Err(UsbError::NoDevice));
    }

    #[test]
    fn device_behind_a_high_speed_hub_uses_its_translator() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        make_hub(&mut hc, Speed::High, Topology { route: 0, root_port: 3, parent: 0, tt: (0, 0) }, 4);
        let t = attach_and_inspect(&mut hc, 4, Speed::Full, 2);
        assert_eq!((t.route, t.root_port, t.parent, t.tt), (0x4, 3, 1, (1, 4)));
        // A high-speed device needs no translator.
        let t = attach_and_inspect(&mut hc, 2, Speed::High, 3);
        assert_eq!((t.route, t.tt), (0x2, (0, 0)));
    }

    #[test]
    fn nested_hubs_extend_the_route_string() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        // A full-speed hub on port 1 of a hub on port 2: its translator is the grandparent's.
        make_hub(&mut hc, Speed::Full, Topology { route: 0x12, root_port: 1, parent: 5, tt: (5, 2) }, 3);
        let t = attach_and_inspect(&mut hc, 3, Speed::Low, 2);
        assert_eq!((t.route, t.root_port, t.tt), (0x312, 1, (5, 2)));
        // Ports above 14 are encoded as 15; five tiers is the limit.
        make_hub(&mut hc, Speed::Super, Topology { route: 0x4321, root_port: 1, parent: 0, tt: (0, 0) }, 20);
        let t = attach_and_inspect(&mut hc, 17, Speed::Super, 3);
        assert_eq!(t.route, 0xf4321);
        make_hub(&mut hc, Speed::Super, Topology { route: 0x54321, root_port: 1, parent: 0, tt: (0, 0) }, 20);
        assert_eq!(hc.attach_hub_port(DeviceId(1), 1, Speed::Super), Err(UsbError::Unsupported));
    }

    #[test]
    fn detaching_a_hub_detaches_what_hangs_off_it() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        make_hub(&mut hc, Speed::High, Topology::default(), 4);
        let child = {
            let slot = hc.slot(DeviceId(1)).unwrap();
            Slot {
                output: OwnedDma::new(&dma, 1024).unwrap(),
                input: OwnedDma::new(&dma, 1056).unwrap(),
                endpoints: [const { None }; MAX_ENDPOINTS],
                speed: Speed::Full,
                topo: Topology { route: 2, root_port: 1, parent: 1, tt: (1, 2) },
                hub_ports: 0,
                dead: slot.dead,
            }
        };
        hc.slots[1] = Some(child);
        // Disable Slot for the child, then for the hub.
        let first = hc.commands.enqueue_addr();
        hc.events.inject(command_completion(first, completion::SUCCESS, 2));
        hc.events.inject(command_completion(PhysAddr::new(first.as_u64() + 16), completion::SUCCESS, 1));
        hc.detach(DeviceId(1));
        assert!(hc.slot(DeviceId(2)).is_err() && hc.slot(DeviceId(1)).is_err());
        assert_eq!(hc.commands.get(0).slot_id(), 2, "the child goes first");
    }

    // ---- isochronous endpoints ----

    fn iso_ep(address: u8, max_packet_size_raw: u16, interval: u8) -> EndpointDescriptor {
        EndpointDescriptor { address, attributes: 1, max_packet_size_raw, interval }
    }

    /// Configures `eps` on the high-speed slot 1, completing the command.
    fn configure_iso(hc: &mut Xhci<'_, crate::testing::HostDma>, eps: &[EndpointDescriptor]) {
        hc.slot(DeviceId(1)).unwrap().speed = Speed::High;
        let configure = hc.commands.enqueue_addr();
        hc.events.inject(command_completion(configure, completion::SUCCESS, 1));
        hc.configure_endpoints(DeviceId(1), eps).unwrap();
    }

    fn ring_trb(hc: &mut Xhci<'_, crate::testing::HostDma>, dci: usize, i: usize) -> (Trb, u64) {
        let ring = &hc.slot(DeviceId(1)).unwrap().endpoint(dci).unwrap().ring;
        (ring.get(i), ring.base().as_u64() + 16 * i as u64)
    }

    #[test]
    fn isochronous_endpoint_context() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        // High-bandwidth isochronous IN (3 x 512 per microframe, every 4th) and a full-speed-style OUT.
        configure_iso(&mut hc, &[iso_ep(0x82, 2 << 11 | 512, 4), iso_ep(0x03, 200, 1)]);
        let input = &hc.slot(DeviceId(1)).unwrap().input;
        // DCI 5 is context 6, DCI 6 context 7.
        assert_eq!(ctx_get(input, 6 * 32, 1), EP_TYPE_ISOCH_IN << 3 | 2 << 8 | 512 << 16, "CErr 0, burst 2");
        assert_eq!(ctx_get(input, 6 * 32, 0) >> 16 & 0xff, 3, "2^3 microframes");
        assert_eq!(ctx_get(input, 6 * 32, 4) >> 16, 1536);
        assert_eq!(ctx_get(input, 7 * 32, 1) >> 3 & 7, EP_TYPE_ISOCH_OUT);
        assert_eq!(hc.isoch.iter().flatten().count(), 2);
        // Too much for one TD buffer, and a low-speed device cannot do isochronous at all.
        let mut hc2 = hc;
        let big = [iso_ep(0x84, 2 << 11 | 2047, 1)];
        assert_eq!(hc2.configure_endpoints(DeviceId(1), &big), Err(UsbError::BadEndpoint));
        hc2.slot(DeviceId(1)).unwrap().speed = Speed::Low;
        assert_eq!(hc2.configure_endpoints(DeviceId(1), &[iso_ep(0x84, 8, 1)]), Err(UsbError::BadEndpoint));
        // Only MAX_ISOCH_ENDPOINTS fit.
        hc2.slot(DeviceId(1)).unwrap().speed = Speed::High;
        let five: [_; 5] = core::array::from_fn(|i| iso_ep(0x01 + i as u8, 64, 1));
        assert_eq!(hc2.configure_endpoints(DeviceId(1), &five), Err(UsbError::NoResources));
    }

    #[test]
    fn isochronous_in_schedules_and_completes() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        regs[0x200 / 4 + MFINDEX / 4] = 80 << 3 | 5; // frame 80
        let mut hc = fake(&dma, &mut regs);
        configure_iso(&mut hc, &[iso_ep(0x82, 2 << 11 | 512, 4)]);
        let dev = DeviceId(1);
        assert_eq!(hc.isoch_frame(), 80);
        // Explicit frame: three packets, TLBPC 2.
        hc.isoch_submit_in(dev, 2, 1500, IsochStart::Frame(0x803)).unwrap();
        let (trb, addr0) = ring_trb(&mut hc, 5, 0);
        assert_eq!((trb.kind(), trb.status & 0x1_ffff), (kind::ISOCH, 1500));
        assert_eq!((trb.control >> 20 & 0x7ff, trb.control >> 16 & 0xf), (3, 2), "frame 3 (11 bits)");
        assert_eq!(trb.control & trb::flag::SIA, 0);
        // Next follows the previous frame by one interval (8 microframes = 1 frame).
        hc.isoch_submit_in(dev, 2, 512, IsochStart::Next).unwrap();
        assert_eq!(ring_trb(&mut hc, 5, 1).0.control >> 20 & 0x7ff, 4);
        // Asap sets SIA; Next after it starts a few frames from now.
        hc.isoch_submit_in(dev, 2, 512, IsochStart::Asap).unwrap();
        assert_eq!(ring_trb(&mut hc, 5, 2).0.control & trb::flag::SIA, trb::flag::SIA);
        hc.isoch_submit_in(dev, 2, 512, IsochStart::Next).unwrap();
        assert_eq!(ring_trb(&mut hc, 5, 3).0.control >> 20 & 0x7ff, 83);
        assert_eq!(hc.isoch_submit_in(dev, 2, 512, IsochStart::Asap), Err(UsbError::Busy), "queue is full");
        // Doorbell for DCI 5 on slot 1.
        assert_eq!(hc.r32(0x100 + 4), 5);

        let mut buf = [0u8; 2048];
        assert!(hc.isoch_poll(dev, 0x82, &mut buf).is_none(), "nothing completed yet");
        // The first transfer ends short (36 bytes missing); the second is a missed service interval.
        hc.isoch.iter_mut().flatten().next().unwrap().buf.write(0, &[7u8; 1464]);
        let mut done = transfer_event(1, 5, addr0);
        done.status |= 36;
        hc.events.inject(done);
        let mut missed = transfer_event(1, 5, addr0 + 16);
        missed.status = (completion::MISSED_SERVICE as u32) << 24;
        hc.events.inject(missed);
        assert_eq!(hc.isoch_poll(dev, 0x82, &mut buf), Some(Ok(1464)));
        assert_eq!(buf[1463], 7);
        assert_eq!(hc.isoch_poll(dev, 0x82, &mut buf), Some(Err(UsbError::Transaction)));
        // The endpoint keeps running: two transfers left, and room for two more.
        assert!(hc.isoch_poll(dev, 0x82, &mut buf).is_none());
        hc.isoch_submit_in(dev, 2, 512, IsochStart::Next).unwrap();
        // Events for transfers nobody queued are ignored.
        hc.events.inject(transfer_event(1, 5, 0xdead));
        assert!(hc.isoch_poll(dev, 0x82, &mut buf).is_none());
        // Wrong direction and unconfigured endpoints.
        assert_eq!(hc.isoch_submit_out(dev, 2, &[0; 4], IsochStart::Asap), Err(UsbError::BadEndpoint));
        assert_eq!(hc.isoch_submit_in(dev, 4, 8, IsochStart::Asap), Err(UsbError::BadEndpoint));
        assert_eq!(hc.isoch_poll(dev, 6, &mut buf), Some(Err(UsbError::BadEndpoint)));
    }

    #[test]
    fn isochronous_out_copies_data_and_frames_sub_millisecond_intervals_asap() {
        let dma = crate::testing::HostDma::default();
        let mut regs = std::vec![0u32; 0x400];
        let mut hc = fake(&dma, &mut regs);
        // bInterval 1 at high speed: every microframe, which a frame number cannot express.
        configure_iso(&mut hc, &[iso_ep(0x03, 192, 1)]);
        let dev = DeviceId(1);
        let data = [0x5au8; 192];
        hc.isoch_submit_out(dev, 3, &data, IsochStart::Next).unwrap();
        let (trb, addr) = ring_trb(&mut hc, 6, 0);
        assert_eq!((trb.kind(), trb.status & 0x1_ffff), (kind::ISOCH, 192));
        assert_eq!(trb.control & trb::flag::SIA, trb::flag::SIA);
        assert_eq!(trb.control & trb::flag::ISP, 0);
        let mut check = [0u8; 192];
        hc.isoch.iter().flatten().next().unwrap().buf.read(0, &mut check);
        assert_eq!(check, data);
        assert_eq!(hc.isoch_submit_out(dev, 3, &[0; 193], IsochStart::Asap), Err(UsbError::NoResources));
        hc.events.inject(transfer_event(1, 6, addr));
        assert_eq!(hc.isoch_poll(dev, 3, &mut []), Some(Ok(192)));
        assert_eq!(hc.isoch_poll(dev, 3, &mut []), Some(Err(UsbError::BadEndpoint)), "nothing queued");
        // Detaching drops the endpoint's queue (and its buffer).
        let live = dma.live.get();
        let disable = hc.commands.enqueue_addr();
        hc.events.inject(command_completion(disable, completion::SUCCESS, 1));
        hc.detach(dev);
        assert_eq!(hc.isoch.iter().flatten().count(), 0);
        assert!(dma.live.get() < live);
    }
}
