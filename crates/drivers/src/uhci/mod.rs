//! UHCI USB 1.1 host controller (Intel Universal Host Controller Interface
//! 1.1, PCI class 0c/03/00).
//!
//! [`Uhci`] resets the controller, builds a fixed schedule and implements
//! [`UsbHost`] for low- and full-speed devices on its two (or more) root
//! ports and on full-speed hubs. High-speed devices are the business of the
//! EHCI controller beside it; this one never sees them.
//!
//! The registers are I/O ports on a PC (BAR 4) and sit in memory on a few
//! other platforms, so [`UhciRegs`] takes either.
//!
//! # Schedule
//!
//! Every entry of the 1024-entry frame list points at the same chain of
//! queue heads, so each runs once per frame:
//!
//! ```text
//! frame list -> periodic 0..3 -> synchronous -> asynchronous 0..3 -> end
//! ```
//!
//! The queue heads are never relinked. Starting a transfer points a queue
//! head's element at a chain of transfer descriptors (one per packet) and
//! ending it points the element back at nothing. The synchronous queue head
//! carries the transfers of [`UsbHost`]'s blocking calls. A transfer started
//! by `submit_in` takes the periodic queue head (interrupt endpoints) or the
//! asynchronous one (bulk) of its slot. Interrupt endpoints are therefore
//! polled every frame rather than every `bInterval` frames, which devices
//! tolerate: they NAK when they have nothing to say.
//!
//! Interrupts are optional. [`Uhci::enable_interrupts`] unmasks the
//! completion and error interrupts, and the kernel's handler for the
//! controller's line (a PCI INTx, shared with other functions) must then
//! call [`Uhci::handle_interrupt`]. The last descriptor of every transfer
//! asks for an interrupt on completion. Polled operations keep working: they
//! read the descriptors, never USBSTS, so the handler cannot steal a
//! completion from them. Until interrupts are enabled USBINTR stays zero and
//! the driver needs no interrupt line.
//!
//! Not supported: isochronous endpoints and suspend.

use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::{ConfigAccess, Function};
use osmium_hal::timer::Clock;
use osmium_hal::usb::{DeviceId, EndpointDescriptor, PortStatus, SetupPacket, Speed, TransferType, UsbError, UsbHost};

use crate::usbhc::{
    self, BOUNCE_LEN, BULK_TIMEOUT_NS, CONTROL_TIMEOUT_NS, Data, DevTable, Hc, MAX_PENDING, MAX_SUBMIT_LEN, Pipe,
};

// Registers.
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x02;
const USBINTR: usize = 0x04;
const FRNUM: usize = 0x06;
const FRBASEADD: usize = 0x08;
const SOFMOD: usize = 0x0c;
const PORTSC: usize = 0x10;

const CMD_RUN: u16 = 1 << 0;
const CMD_HCRESET: u16 = 1 << 1;
const CMD_CONFIGURE: u16 = 1 << 6;
const CMD_MAXP: u16 = 1 << 7;
/// A transfer descriptor with the interrupt-on-completion bit finished, or
/// a short packet detected.
const STS_INT: u16 = 1 << 0;
/// A transfer descriptor ended in an error.
const STS_ERROR: u16 = 1 << 1;
const STS_HALTED: u16 = 1 << 5;
/// The USBSTS bits [`Uhci::handle_interrupt`] services.
const STS_EVENTS: u16 = STS_INT | STS_ERROR;
/// USBINTR: interrupt on a timeout or CRC error, and on completion.
const INTR_TIMEOUT_CRC: u16 = 1 << 0;
const INTR_IOC: u16 = 1 << 2;
/// Every USBSTS bit that is write-one-to-clear.
const STS_ALL: u16 = 0x3f;

const PORT_CONNECTED: u16 = 1 << 0;
const PORT_CONNECT_CHANGE: u16 = 1 << 1;
const PORT_ENABLED: u16 = 1 << 2;
const PORT_ENABLE_CHANGE: u16 = 1 << 3;
const PORT_LOW_SPEED: u16 = 1 << 8;
const PORT_RESET: u16 = 1 << 9;
const PORT_OVERCURRENT_CHANGE: u16 = 1 << 11;
/// Always reads 1; its absence marks a port that is not there.
const PORT_RESERVED_ONE: u16 = 1 << 7;
/// The write-one-to-clear bits, which writes back must not set by accident.
const PORT_CHANGES: u16 = PORT_CONNECT_CHANGE | PORT_ENABLE_CHANGE | PORT_OVERCURRENT_CHANGE;
const MAX_PORTS: u8 = 8;

/// PCI configuration offset of the legacy support register.
const LEGACY_SUPPORT: u16 = 0xc0;
/// Its write-one-to-clear SMI status bits.
const LEGACY_STATUS: u16 = 0x8f00;
/// The value that leaves BIOS emulation off and routes PIRQ.
const LEGACY_PIRQ: u16 = 0x2000;

// Link pointers.
const LINK_TERMINATE: u32 = 1 << 0;
const LINK_QH: u32 = 1 << 1;
const LINK_DEPTH: u32 = 1 << 2;

// TD control and status.
const TD_ACTIVE: u32 = 1 << 23;
const TD_STALLED: u32 = 1 << 22;
const TD_DATA_BUFFER: u32 = 1 << 21;
const TD_BABBLE: u32 = 1 << 20;
const TD_CRC_TIMEOUT: u32 = 1 << 18;
const TD_BITSTUFF: u32 = 1 << 17;
const TD_ERRORS: u32 = TD_STALLED | TD_DATA_BUFFER | TD_BABBLE | TD_CRC_TIMEOUT | TD_BITSTUFF;
const TD_IOC: u32 = 1 << 24;
const TD_LOW_SPEED: u32 = 1 << 26;
const TD_THREE_ERRORS: u32 = 3 << 27;
const TD_SHORT_PACKET_DETECT: u32 = 1 << 29;

const PID_SETUP: u32 = 0x2d;
const PID_IN: u32 = 0x69;
const PID_OUT: u32 = 0xe1;

const FRAMES: usize = 1024;
const QH_SIZE: usize = 16;
const TD_SIZE: usize = 32;
/// Offset of the first TD in a transfer's memory; the setup packet is
/// before it.
const TD_BASE: usize = 16;
/// Descriptors in the synchronous transfer, which bounds the bytes a single
/// run moves to this many packets.
const SYNC_TDS: usize = 128;
/// Descriptors in a transfer started by `submit_in`.
const PENDING_TDS: usize = 32;

// Queue head positions in the queue head block, in chain order.
const QH_PERIODIC: usize = 0;
const QH_SYNC: usize = QH_PERIODIC + MAX_PENDING;
const QH_ASYNC: usize = QH_SYNC + 1;
const QH_COUNT: usize = QH_ASYNC + MAX_PENDING;

/// Why the controller could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UhciError {
    /// The registers do not look like a UHCI controller's.
    BadRegisters,
    /// The controller did not reset or start.
    Timeout,
    /// DMA memory could not be allocated.
    NoMemory,
    /// The controller addresses 32 bits and DMA memory lies above 4 GiB.
    HighMemory,
}

/// How the controller's registers are reached.
pub enum UhciRegs {
    /// Memory-mapped, 0x14 bytes plus two per port.
    Mmio(IoMem),
    /// I/O ports from this base (PCI BAR 4).
    #[cfg(target_arch = "x86_64")]
    Ports(u16),
}

impl UhciRegs {
    /// Registers at I/O port `base`.
    ///
    /// # Safety
    /// `base` must be the I/O window of a UHCI controller the caller owns.
    #[cfg(target_arch = "x86_64")]
    pub const unsafe fn ports(base: u16) -> Self {
        Self::Ports(base)
    }

    fn r16(&self, off: usize) -> u16 {
        match self {
            // The window was checked against the registers used, so a miss
            // only follows a bug: it reads as a missing port.
            Self::Mmio(io) => io.read::<u16>(off).unwrap_or(0xffff),
            #[cfg(target_arch = "x86_64")]
            Self::Ports(base) => {
                // SAFETY: `ports` vouched for the window.
                unsafe { osmium_hal::port::Port::<u16>::new(base.wrapping_add(off as u16)) }.read()
            }
        }
    }

    fn w16(&self, off: usize, v: u16) {
        match self {
            Self::Mmio(io) => {
                let _ = io.write::<u16>(off, v);
            }
            #[cfg(target_arch = "x86_64")]
            Self::Ports(base) => {
                // SAFETY: `ports` vouched for the window.
                unsafe { osmium_hal::port::Port::<u16>::new(base.wrapping_add(off as u16)) }.write(v)
            }
        }
    }

    fn w32(&self, off: usize, v: u32) {
        match self {
            Self::Mmio(io) => {
                let _ = io.write::<u32>(off, v);
            }
            #[cfg(target_arch = "x86_64")]
            Self::Ports(base) => {
                // SAFETY: `ports` vouched for the window.
                unsafe { osmium_hal::port::Port::<u32>::new(base.wrapping_add(off as u16)) }.write(v)
            }
        }
    }

    fn w8(&self, off: usize, v: u8) {
        match self {
            Self::Mmio(io) => {
                let _ = io.write::<u8>(off, v);
            }
            #[cfg(target_arch = "x86_64")]
            Self::Ports(base) => {
                // SAFETY: `ports` vouched for the window.
                unsafe { osmium_hal::port::Port::<u8>::new(base.wrapping_add(off as u16)) }.write(v)
            }
        }
    }

    fn fits(&self) -> bool {
        match self {
            Self::Mmio(io) => io.len() >= PORTSC + 2 * 2,
            #[cfg(target_arch = "x86_64")]
            Self::Ports(_) => true,
        }
    }
}

/// Memory for one transfer: its setup packet and descriptors, and the data.
struct Xfer<'d, D: DmaAllocator + ?Sized> {
    mem: OwnedDma<'d, D>,
    buf: OwnedDma<'d, D>,
}

impl<'d, D: DmaAllocator + ?Sized> Xfer<'d, D> {
    fn new(dma: &'d D, tds: usize, buf_len: usize) -> Result<Self, UsbError> {
        let mem = OwnedDma::new(dma, TD_BASE + tds * TD_SIZE).ok_or(UsbError::NoResources)?;
        let buf = OwnedDma::new(dma, buf_len).ok_or(UsbError::NoResources)?;
        if !usbhc::below_4g(&mem) || !usbhc::below_4g(&buf) {
            return Err(UsbError::NoResources);
        }
        Ok(Self { mem, buf })
    }

    fn td_addr(&self, i: usize) -> u32 {
        (self.mem.device_addr().as_u64() + (TD_BASE + i * TD_SIZE) as u64) as u32
    }

    fn status(&self, i: usize) -> u32 {
        u32::from_le(self.mem.load(TD_BASE + i * TD_SIZE + 4))
    }

    fn token(&self, i: usize) -> u32 {
        u32::from_le(self.mem.load(TD_BASE + i * TD_SIZE + 8))
    }
}

/// The descriptors of a transfer built into an [`Xfer`].
#[derive(Clone, Copy)]
struct Plan {
    /// Descriptors used.
    count: usize,
    /// The data-stage descriptors `first..last`, and their direction.
    first: usize,
    last: usize,
    dir_in: bool,
    /// A control transfer: its last descriptor is the status stage, which a
    /// short data packet skips to.
    control: bool,
    /// The queue head's element has been moved on to the status stage.
    skipped: bool,
}

enum Progress {
    Running,
    /// Finished having moved this many bytes; `clean` if no descriptor was
    /// left unrun.
    Done {
        bytes: usize,
        clean: bool,
    },
    Failed(UsbError),
}

/// A transfer started by `submit_in`.
struct Pending<'d, D: DmaAllocator + ?Sized> {
    xfer: Xfer<'d, D>,
    plan: Plan,
    /// Position of the queue head it runs in.
    qh: usize,
    len: usize,
}

struct Mem<'d, D: DmaAllocator + ?Sized> {
    frames: OwnedDma<'d, D>,
    qhs: OwnedDma<'d, D>,
    sync: Xfer<'d, D>,
    pending: [Option<Pending<'d, D>>; MAX_PENDING],
}

/// A UHCI controller.
///
/// The DMA memory is freed on drop only once the controller has halted;
/// one that will not halt might still read it, so it is leaked.
pub struct Uhci<'d, D: DmaAllocator + ?Sized> {
    regs: UhciRegs,
    clock: &'d dyn Clock,
    dma: &'d D,
    ports: u8,
    devs: DevTable,
    /// The synchronous transfer's memory may still be in use by the controller.
    wedged: bool,
    /// USBINTR has been unmasked by [`Uhci::enable_interrupts`].
    interrupts_enabled: bool,
    /// Interrupts [`Uhci::handle_interrupt`] has serviced.
    interrupts: u64,
    mem: ManuallyDrop<Mem<'d, D>>,
}

/// Takes the controller of PCI function `func` away from BIOS: no SMI
/// emulation of a legacy keyboard or mouse, interrupts routed to the PIRQ.
/// Call before [`Uhci::new`].
pub fn release_from_firmware<C: ConfigAccess + ?Sized>(func: &Function<'_, C>) {
    let dword = func.read32(LEGACY_SUPPORT);
    func.write32(LEGACY_SUPPORT, dword & 0xffff_0000 | (LEGACY_STATUS | LEGACY_PIRQ) as u32);
}

/// The PCI class of a UHCI controller.
pub const CLASS: osmium_hal::pci::Class = osmium_hal::pci::Class { class: 0x0c, subclass: 0x03, prog_if: 0x00 };

impl<'d, D: DmaAllocator + ?Sized> Uhci<'d, D> {
    /// Resets the controller and starts it with DMA memory from `dma`.
    /// `clock` times resets and the waits for transfers.
    pub fn new(regs: UhciRegs, dma: &'d D, clock: &'d dyn Clock) -> Result<Self, UhciError> {
        if !regs.fits() {
            return Err(UhciError::BadRegisters);
        }
        let ports = (0..MAX_PORTS)
            .take_while(|&i| {
                let sc = regs.r16(PORTSC + 2 * i as usize);
                sc != 0xffff && sc & PORT_RESERVED_ONE != 0
            })
            .count() as u8;
        if ports < 2 {
            return Err(UhciError::BadRegisters);
        }

        let no_mem = UhciError::NoMemory;
        let frames = OwnedDma::new(dma, FRAMES * 4).ok_or(no_mem)?;
        let qhs = OwnedDma::new(dma, QH_COUNT * QH_SIZE).ok_or(no_mem)?;
        if !usbhc::below_4g(&frames) || !usbhc::below_4g(&qhs) {
            return Err(UhciError::HighMemory);
        }
        let sync = Xfer::new(dma, SYNC_TDS, BOUNCE_LEN).map_err(|_| no_mem)?;

        let hc = Self {
            regs,
            clock,
            dma,
            ports,
            devs: DevTable::new(),
            wedged: false,
            interrupts_enabled: false,
            interrupts: 0,
            mem: ManuallyDrop::new(Mem { frames, qhs, sync, pending: [const { None }; MAX_PENDING] }),
        };
        hc.build_schedule();
        hc.reset()?;
        hc.regs.w16(USBINTR, 0);
        hc.regs.w16(FRNUM, 0);
        hc.regs.w32(FRBASEADD, hc.mem.frames.device_addr().as_u64() as u32);
        hc.regs.w8(SOFMOD, 64);
        hc.regs.w16(USBSTS, STS_ALL);
        hc.regs.w16(USBCMD, CMD_RUN | CMD_CONFIGURE | CMD_MAXP);
        if !usbhc::wait(clock, 10_000_000, || hc.regs.r16(USBSTS) & STS_HALTED == 0) {
            return Err(UhciError::Timeout);
        }
        Ok(hc)
    }

    /// Lets the controller raise its interrupt line when a transfer
    /// completes or fails. From now on the kernel's handler must call
    /// [`handle_interrupt`](Self::handle_interrupt).
    ///
    /// Polled operations keep working; see the module documentation. The
    /// caller serializes both with one lock (the driver is `&mut self`
    /// throughout), so the handler must not run on a CPU that holds it.
    pub fn enable_interrupts(&mut self) {
        self.regs.w16(USBSTS, STS_EVENTS);
        self.regs.w16(USBINTR, INTR_TIMEOUT_CRC | INTR_IOC);
        self.interrupts_enabled = true;
    }

    /// Stops the controller from raising interrupts (polling still works).
    pub fn disable_interrupts(&mut self) {
        self.regs.w16(USBINTR, 0);
        self.interrupts_enabled = false;
    }

    /// Services the controller's interrupt by acknowledging it. Returns
    /// false, doing nothing, if interrupts are not enabled or the controller
    /// was not asserting one (a shared line).
    pub fn handle_interrupt(&mut self) -> bool {
        if !self.interrupts_enabled {
            return false;
        }
        let events = self.regs.r16(USBSTS) & STS_EVENTS;
        if events == 0 {
            return false;
        }
        // Write-one-to-clear. A transfer that completes after this raises
        // the interrupt again.
        self.regs.w16(USBSTS, events);
        self.interrupts += 1;
        true
    }

    /// How many interrupts [`handle_interrupt`](Self::handle_interrupt) has
    /// serviced.
    pub fn interrupts_handled(&self) -> u64 {
        self.interrupts
    }

    /// Number of root ports found.
    pub fn ports(&self) -> u8 {
        self.ports
    }

    fn qh_addr(&self, i: usize) -> u32 {
        (self.mem.qhs.device_addr().as_u64() + (i * QH_SIZE) as u64) as u32
    }

    fn set_element(&self, qh: usize, element: u32) {
        osmium_arch::barrier::dma_wmb();
        self.mem.qhs.store(qh * QH_SIZE + 4, element.to_le());
    }

    #[cfg(test)]
    fn element(&self, qh: usize) -> u32 {
        u32::from_le(self.mem.qhs.load(qh * QH_SIZE + 4))
    }

    /// Links the queue heads in chain order, empty, and points every frame
    /// at the first.
    fn build_schedule(&self) {
        for i in 0..QH_COUNT {
            let link = if i + 1 < QH_COUNT { self.qh_addr(i + 1) | LINK_QH } else { LINK_TERMINATE };
            self.mem.qhs.store(i * QH_SIZE, link.to_le());
            self.mem.qhs.store(i * QH_SIZE + 4, LINK_TERMINATE.to_le());
        }
        let first = (self.qh_addr(QH_PERIODIC) | LINK_QH).to_le();
        for i in 0..FRAMES {
            self.mem.frames.store(i * 4, first);
        }
    }

    fn reset(&self) -> Result<(), UhciError> {
        let timeout = UhciError::Timeout;
        self.regs.w16(USBINTR, 0);
        self.regs.w16(USBCMD, 0);
        if !usbhc::wait(self.clock, 20_000_000, || self.regs.r16(USBSTS) & STS_HALTED != 0) {
            return Err(timeout);
        }
        self.regs.w16(USBCMD, CMD_HCRESET);
        if !usbhc::wait(self.clock, 100_000_000, || self.regs.r16(USBCMD) & CMD_HCRESET == 0) {
            return Err(timeout);
        }
        Ok(())
    }

    fn port_reg(port: u8) -> usize {
        PORTSC + 2 * (port as usize).saturating_sub(1)
    }

    /// Waits for the controller to finish the frame it is in, so that it no
    /// longer reads a queue head's old element.
    fn next_frame(&self) -> bool {
        let start = self.regs.r16(FRNUM);
        usbhc::wait(self.clock, 3_000_000, || self.regs.r16(FRNUM) != start)
    }

    fn td_ctrl(pipe: &Pipe, extra: u32) -> u32 {
        let low = if usbhc::is_low(pipe.speed) { TD_LOW_SPEED } else { 0 };
        TD_ACTIVE | TD_THREE_ERRORS | low | extra
    }

    /// Writes descriptor `i` of `x`, linked to `i + 1` (or ending the chain
    /// if `last`).
    fn put_td(x: &Xfer<'d, D>, i: usize, last: bool, ctrl: u32, token: u32, buffer: u32) {
        let link = if last { LINK_TERMINATE } else { x.td_addr(i + 1) | LINK_DEPTH };
        let off = TD_BASE + i * TD_SIZE;
        // One interrupt per transfer, when its last descriptor retires.
        let ctrl = if last { ctrl | TD_IOC } else { ctrl };
        x.mem.store(off, link.to_le());
        x.mem.store(off + 4, ctrl.to_le());
        x.mem.store(off + 8, token.to_le());
        x.mem.store(off + 12, buffer.to_le());
    }

    fn token(pipe: &Pipe, pid: u32, toggle: bool, len: usize) -> u32 {
        let max_len = (len as u32).wrapping_sub(1) & 0x7ff;
        max_len << 21 | (toggle as u32) << 19 | (pipe.endpoint as u32 & 0xf) << 15 | (pipe.address as u32) << 8 | pid
    }

    fn buf_addr(x: &Xfer<'d, D>, off: usize) -> u32 {
        (x.buf.device_addr().as_u64() + off as u64) as u32
    }

    /// Builds the packets of a data stage of `len` bytes from offset 0 of
    /// `x.buf`, one descriptor each, from descriptor `first`. Returns the
    /// index after the last. `in` transfers stop the queue at a short packet.
    #[allow(clippy::too_many_arguments)]
    fn put_data(
        x: &Xfer<'d, D>,
        pipe: &Pipe,
        first: usize,
        len: usize,
        toggle: bool,
        dir_in: bool,
        tail: bool,
    ) -> usize {
        let mps = pipe.mps as usize;
        let (pid, extra) = if dir_in { (PID_IN, TD_SHORT_PACKET_DETECT) } else { (PID_OUT, 0) };
        let count = usbhc::packets(len, pipe.mps);
        for k in 0..count {
            let off = k * mps;
            let n = len.saturating_sub(off).min(mps);
            let last = tail && k + 1 == count;
            let t = toggle ^ (k % 2 == 1);
            Self::put_td(
                x,
                first + k,
                last,
                Self::td_ctrl(pipe, extra),
                Self::token(pipe, pid, t, n),
                Self::buf_addr(x, off),
            );
        }
        first + count
    }

    /// Descriptors for a control transfer: setup, data, status.
    fn build_control(x: &Xfer<'d, D>, pipe: &Pipe, setup: SetupPacket, len: usize, dir_in: bool) -> Plan {
        x.mem.write(0, &setup.to_bytes());
        let setup_addr = x.mem.device_addr().as_u64() as u32;
        Self::put_td(x, 0, false, Self::td_ctrl(pipe, 0), Self::token(pipe, PID_SETUP, false, 8), setup_addr);
        let mut next = 1;
        if len > 0 {
            next = Self::put_data(x, pipe, 1, len, true, dir_in, false);
        }
        let status_pid = if len > 0 && dir_in { PID_OUT } else { PID_IN };
        let ctrl = Self::td_ctrl(pipe, 0);
        Self::put_td(x, next, true, ctrl, Self::token(pipe, status_pid, true, 0), 0);
        Plan { count: next + 1, first: 1, last: next, dir_in, control: true, skipped: false }
    }

    /// Descriptors for a bulk or interrupt transfer of `len` bytes.
    fn build_bulk(x: &Xfer<'d, D>, pipe: &Pipe, toggle: bool, len: usize, dir_in: bool) -> Plan {
        let end = Self::put_data(x, pipe, 0, len, toggle, dir_in, true);
        Plan { count: end, first: 0, last: end, dir_in, control: false, skipped: false }
    }

    /// Where a transfer built into `x` stands.
    fn progress(&self, x: &Xfer<'d, D>, qh: usize, plan: &mut Plan) -> Progress {
        let mut bytes = 0;
        let mut i = 0;
        while i < plan.count {
            let st = x.status(i);
            if st & TD_ACTIVE != 0 {
                return Progress::Running;
            }
            if st & TD_ERRORS != 0 {
                return Progress::Failed(error_from(st));
            }
            if (plan.first..plan.last).contains(&i) {
                let expected = (x.token(i) >> 21).wrapping_add(1) & 0x7ff;
                let actual = if plan.dir_in { st.wrapping_add(1) & 0x7ff } else { expected };
                bytes += actual as usize;
                if actual < expected {
                    // A short packet: the controller leaves the queue at
                    // this descriptor, so the rest is skipped.
                    if !plan.control {
                        return Progress::Done { bytes, clean: i + 1 == plan.count };
                    }
                    let status = plan.count - 1;
                    if !plan.skipped {
                        plan.skipped = true;
                        self.set_element(qh, x.td_addr(status));
                    }
                    i = status;
                    continue;
                }
            }
            i += 1;
        }
        Progress::Done { bytes, clean: true }
    }

    /// Stops the queue head's transfer and waits until the controller is
    /// done with its descriptors. False if the controller did not go on to
    /// another frame: it may still be using them, so the caller must not free
    /// or reuse their memory.
    fn abort(&self, x: &Xfer<'d, D>, qh: usize, plan: &Plan) -> bool {
        self.set_element(qh, LINK_TERMINATE);
        for i in 0..plan.count {
            let off = TD_BASE + i * TD_SIZE + 4;
            x.mem.store(off, (u32::from_le(x.mem.load(off)) & !TD_ACTIVE).to_le());
        }
        let quiet = self.next_frame();
        self.set_element(qh, LINK_TERMINATE);
        quiet
    }

    /// Ends a transfer that has stopped: the queue head empties, after a
    /// frame's wait if descriptors were left unrun.
    /// False as for [`abort`](Self::abort).
    fn finish(&self, x: &Xfer<'d, D>, qh: usize, plan: &Plan, clean: bool) -> bool {
        if clean {
            self.set_element(qh, LINK_TERMINATE);
            true
        } else {
            self.abort(x, qh, plan)
        }
    }

    /// Runs the transfer built into the synchronous `Xfer` to its end.
    fn run_sync(&mut self, mut plan: Plan, timeout_ns: u64) -> Result<usize, UsbError> {
        if self.wedged {
            return Err(UsbError::Timeout);
        }
        let qh = QH_SYNC;
        let first = self.mem.sync.td_addr(0);
        self.set_element(qh, first);
        let mut outcome = Progress::Running;
        let done = usbhc::wait(self.clock, timeout_ns, || {
            outcome = self.progress(&self.mem.sync, qh, &mut plan);
            !matches!(outcome, Progress::Running)
        });
        let x = &self.mem.sync;
        let (result, quiet) = match outcome {
            Progress::Done { bytes, clean } if done => (Ok(bytes), self.finish(x, qh, &plan, clean)),
            Progress::Failed(e) if done => (Err(e), self.abort(x, qh, &plan)),
            _ => (Err(UsbError::Timeout), self.abort(x, qh, &plan)),
        };
        // The synchronous memory is not reused if the controller may still use it.
        self.wedged |= !quiet;
        result
    }
}

fn error_from(status: u32) -> UsbError {
    if status & TD_STALLED != 0 && status & (TD_DATA_BUFFER | TD_BABBLE | TD_CRC_TIMEOUT | TD_BITSTUFF) == 0 {
        UsbError::Stall
    } else {
        UsbError::Transaction
    }
}

impl<D: DmaAllocator + ?Sized> Hc for Uhci<'_, D> {
    fn devices(&mut self) -> &mut DevTable {
        &mut self.devs
    }

    fn clock(&self) -> &dyn Clock {
        self.clock
    }

    fn root_ports(&self) -> u8 {
        self.ports
    }

    fn root_port_status(&self, port: u8) -> PortStatus {
        if port == 0 || port > self.ports {
            return PortStatus { connected: false, enabled: false, speed: None };
        }
        let sc = self.regs.r16(Self::port_reg(port));
        let connected = sc & PORT_CONNECTED != 0;
        let speed = if sc & PORT_LOW_SPEED != 0 { Speed::Low } else { Speed::Full };
        PortStatus { connected, enabled: sc & PORT_ENABLED != 0, speed: connected.then_some(speed) }
    }

    fn reset_port(&mut self, port: u8) -> Result<Speed, UsbError> {
        let reg = Self::port_reg(port);
        let keep = |sc: u16| sc & !PORT_CHANGES;
        if self.regs.r16(reg) & PORT_CONNECTED == 0 {
            return Err(UsbError::NoDevice);
        }
        // 50 ms of reset (USB 2.0 §7.1.7.5), then 10 ms for the device to
        // recover before the first request.
        self.regs.w16(reg, keep(self.regs.r16(reg)) | PORT_RESET);
        usbhc::delay(self.clock, 50_000_000);
        self.regs.w16(reg, keep(self.regs.r16(reg)) & !PORT_RESET);
        usbhc::delay(self.clock, 10_000_000);
        // The port enables itself on request once the reset is over.
        let enabled = usbhc::wait(self.clock, 20_000_000, || {
            let sc = self.regs.r16(reg);
            if sc & PORT_ENABLED == 0 {
                self.regs.w16(reg, keep(sc) | PORT_ENABLED);
            }
            self.regs.r16(reg) & PORT_ENABLED != 0
        });
        let sc = self.regs.r16(reg);
        self.regs.w16(reg, keep(sc) | PORT_CONNECT_CHANGE | PORT_ENABLE_CHANGE);
        if sc & PORT_CONNECTED == 0 {
            return Err(UsbError::NoDevice);
        }
        if !enabled {
            return Err(UsbError::Transaction);
        }
        Ok(if sc & PORT_LOW_SPEED != 0 { Speed::Low } else { Speed::Full })
    }

    fn control(&mut self, pipe: &Pipe, setup: SetupPacket, data: Data<'_>) -> Result<usize, UsbError> {
        let len = data.len();
        let mps = pipe.mps as usize;
        if len > BOUNCE_LEN || usbhc::packets(len, pipe.mps) + 2 > SYNC_TDS || mps == 0 {
            return Err(UsbError::NoResources);
        }
        let dir_in = matches!(data, Data::In(_));
        if let Data::Out(out) = &data {
            self.mem.sync.buf.write(0, out);
        }
        let plan = Self::build_control(&self.mem.sync, pipe, setup, len, dir_in);
        let moved = self.run_sync(plan, CONTROL_TIMEOUT_NS)?;
        if let Data::In(buf) = data
            && let Some(dst) = buf.get_mut(..moved.min(len))
        {
            self.mem.sync.buf.read(0, dst);
        }
        Ok(moved)
    }

    fn chunk_max(&self, pipe: &Pipe) -> usize {
        let mps = (pipe.mps as usize).max(1);
        BOUNCE_LEN.min(SYNC_TDS * mps) / mps * mps
    }

    fn bulk_chunk(&mut self, pipe: &Pipe, toggle: bool, data: Data<'_>) -> Result<usize, UsbError> {
        let n = data.len();
        let dir_in = matches!(data, Data::In(_));
        if let Data::Out(out) = &data {
            self.mem.sync.buf.write(0, out);
        }
        let plan = Self::build_bulk(&self.mem.sync, pipe, toggle, n, dir_in);
        let moved = self.run_sync(plan, BULK_TIMEOUT_NS)?;
        if let Data::In(buf) = data
            && let Some(dst) = buf.get_mut(..moved.min(n))
        {
            self.mem.sync.buf.read(0, dst);
        }
        Ok(moved)
    }

    fn submit(&mut self, pipe: &Pipe, toggle: bool, len: usize) -> Result<usize, UsbError> {
        if len == 0 || len > MAX_SUBMIT_LEN || pipe.mps == 0 || usbhc::packets(len, pipe.mps) > PENDING_TDS {
            return Err(UsbError::NoResources);
        }
        let slot = self.mem.pending.iter().position(Option::is_none).ok_or(UsbError::NoResources)?;
        let xfer = Xfer::new(self.dma, PENDING_TDS, MAX_SUBMIT_LEN)?;
        let plan = Self::build_bulk(&xfer, pipe, toggle, len, true);
        let qh = if pipe.ttype == TransferType::Interrupt { QH_PERIODIC + slot } else { QH_ASYNC + slot };
        let first = xfer.td_addr(0);
        *self.mem.pending.get_mut(slot).ok_or(UsbError::NoResources)? = Some(Pending { xfer, plan, qh, len });
        self.set_element(qh, first);
        Ok(slot)
    }

    fn poll(&mut self, slot: usize, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
        let mut p = self.mem.pending.get_mut(slot)?.take()?;
        let progress = self.progress(&p.xfer, p.qh, &mut p.plan);
        let quiet;
        let result = match progress {
            Progress::Running => {
                if let Some(entry) = self.mem.pending.get_mut(slot) {
                    *entry = Some(p);
                }
                return None;
            }
            Progress::Done { bytes, clean } => {
                quiet = self.finish(&p.xfer, p.qh, &p.plan, clean);
                let n = bytes.min(p.len).min(buf.len());
                if let Some(dst) = buf.get_mut(..n) {
                    p.xfer.buf.read(0, dst);
                }
                Ok(n)
            }
            Progress::Failed(e) => {
                quiet = self.abort(&p.xfer, p.qh, &p.plan);
                Err(e)
            }
        };
        if !quiet {
            // The controller may still be using the memory: leak it.
            core::mem::forget(p);
        }
        Some(result)
    }

    fn cancel(&mut self, slot: usize) {
        // If the controller may still be using the memory, leak it.
        if let Some(p) = self.mem.pending.get_mut(slot).and_then(Option::take)
            && !self.abort(&p.xfer, p.qh, &p.plan)
        {
            core::mem::forget(p);
        }
    }
}

impl<D: DmaAllocator + ?Sized> UsbHost for Uhci<'_, D> {
    fn num_ports(&self) -> u8 {
        self.ports
    }

    fn port_status(&self, port: u8) -> PortStatus {
        self.root_port_status(port)
    }

    fn attach(&mut self, port: u8) -> Result<DeviceId, UsbError> {
        usbhc::attach(self, port)
    }

    fn detach(&mut self, dev: DeviceId) {
        usbhc::detach(self, dev)
    }

    fn configure_endpoints(&mut self, dev: DeviceId, endpoints: &[EndpointDescriptor]) -> Result<(), UsbError> {
        usbhc::configure_endpoints(self, dev, endpoints)
    }

    fn control_in(&mut self, dev: DeviceId, setup: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError> {
        usbhc::control_in(self, dev, setup, buf)
    }

    fn control_out(&mut self, dev: DeviceId, setup: SetupPacket, data: &[u8]) -> Result<(), UsbError> {
        usbhc::control_out(self, dev, setup, data)
    }

    fn transfer_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Result<usize, UsbError> {
        usbhc::transfer_in(self, dev, endpoint, buf)
    }

    fn transfer_out(&mut self, dev: DeviceId, endpoint: u8, data: &[u8]) -> Result<(), UsbError> {
        usbhc::transfer_out(self, dev, endpoint, data)
    }

    fn submit_in(&mut self, dev: DeviceId, endpoint: u8, len: usize) -> Result<(), UsbError> {
        usbhc::submit_in(self, dev, endpoint, len)
    }

    fn poll_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
        usbhc::poll_in(self, dev, endpoint, buf)
    }

    fn attach_hub_port(&mut self, hub: DeviceId, _port: u8, speed: Speed) -> Result<DeviceId, UsbError> {
        usbhc::attach_hub_port(self, hub, speed)
    }

    fn configure_hub(&mut self, hub: DeviceId, _ports: u8, _think_time: u8, _multi_tt: bool) -> Result<(), UsbError> {
        // Full-speed hubs need no translator; the hub only has to exist.
        self.devs.get(hub.0).map(drop).ok_or(UsbError::NoDevice)
    }
}

impl<D: DmaAllocator + ?Sized> Drop for Uhci<'_, D> {
    fn drop(&mut self) {
        // Stop the controller before its schedule is freed. One that does
        // not halt may still read it: the memory is leaked.
        self.regs.w16(USBCMD, 0);
        if !usbhc::wait(self.clock, 20_000_000, || self.regs.r16(USBSTS) & STS_HALTED != 0) {
            return;
        }
        // SAFETY: dropped once, here, and not used again.
        unsafe { ManuallyDrop::drop(&mut self.mem) };
    }
}

#[cfg(test)]
mod tests;
