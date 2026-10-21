//! EHCI USB 2.0 host controller (Enhanced Host Controller Interface 1.0,
//! PCI class 0c/03/20).
//!
//! [`Ehci`] resets the controller, builds a fixed schedule of queue heads
//! and implements [`UsbHost`] for high-speed devices on its root ports. The
//! registers are memory-mapped (PCI BAR 0) and the driver is polled.
//!
//! EHCI has no transaction translator of its own for the root ports:
//! low- and full-speed devices belong to the companion UHCI or OHCI
//! controller on the same chip. After a port reset finds no high-speed
//! device, the driver gives the port to its companion (`PORT_OWNER`) and
//! reports [`UsbError::Unsupported`]; the device then appears on the
//! companion controller's own port. Hubs are not supported, since a
//! low- or full-speed device behind a high-speed hub needs split
//! transactions.
//!
//! # Schedule
//!
//! The queue heads are linked once and never moved:
//!
//! ```text
//! asynchronous: head -> synchronous -> slot 0..3 -> head
//! periodic:     root -> slot 0..3                  (every frame list entry)
//! ```
//!
//! A transfer is a chain of queue element transfer descriptors (qTDs) given
//! to an idle queue head by filling in its overlay. A transfer that ends
//! normally, or with an error, leaves its queue head inactive and ready to
//! be filled in again. One that has to be abandoned is unlinked, and the
//! driver rings the asynchronous advance doorbell (or waits out a frame, for
//! the periodic list) before the memory is reused.
//!
//! Interrupt endpoints are polled once a frame, in microframe 0, whatever
//! their `bInterval`. A data stage is one qTD of at most 16 KiB, so longer
//! transfers run in pieces.
//!
//! Not supported: isochronous and split transactions, hubs, 64-bit
//! descriptors above 4 GiB and interrupt-driven completion.

use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::{ConfigAccess, Function};
use osmium_hal::timer::Clock;
use osmium_hal::usb::{DeviceId, EndpointDescriptor, PortStatus, SetupPacket, Speed, TransferType, UsbError, UsbHost};

use crate::usbhc::{
    self, BOUNCE_LEN, BULK_TIMEOUT_NS, CONTROL_TIMEOUT_NS, Data, DevTable, Hc, MAX_PENDING, MAX_SUBMIT_LEN, Pipe,
};

// Capability registers.
const CAPLENGTH: usize = 0x00;
const HCIVERSION: usize = 0x02;
const HCSPARAMS: usize = 0x04;
const HCCPARAMS: usize = 0x08;

// Operational registers, from CAPLENGTH.
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
const USBINTR: usize = 0x08;
const FRINDEX: usize = 0x0c;
const CTRLDSSEGMENT: usize = 0x10;
const PERIODICLISTBASE: usize = 0x14;
const ASYNCLISTADDR: usize = 0x18;
const CONFIGFLAG: usize = 0x40;
const PORTSC: usize = 0x44;

const CMD_RUN: u32 = 1 << 0;
const CMD_HCRESET: u32 = 1 << 1;
const CMD_PERIODIC_ENABLE: u32 = 1 << 4;
const CMD_ASYNC_ENABLE: u32 = 1 << 5;
const CMD_DOORBELL: u32 = 1 << 6;
/// Interrupt threshold of 8 microframes, the reset default.
const CMD_THRESHOLD: u32 = 8 << 16;
const STS_ASYNC_ADVANCE: u32 = 1 << 5;
const STS_HALTED: u32 = 1 << 12;
const STS_ALL: u32 = 0x3f;
const HCS_PORTS: u32 = 0xf;
const HCS_PORT_POWER_CONTROL: u32 = 1 << 4;
const HCC_64BIT: u32 = 1 << 0;

const PORT_CONNECTED: u32 = 1 << 0;
const PORT_CONNECT_CHANGE: u32 = 1 << 1;
const PORT_ENABLED: u32 = 1 << 2;
const PORT_ENABLE_CHANGE: u32 = 1 << 3;
const PORT_OVERCURRENT_CHANGE: u32 = 1 << 5;
const PORT_RESET: u32 = 1 << 8;
/// Line status "K": a low-speed device.
const PORT_LINE_K: u32 = 1 << 10;
const PORT_LINE_MASK: u32 = 3 << 10;
const PORT_POWER: u32 = 1 << 12;
const PORT_OWNER: u32 = 1 << 13;
/// The write-one-to-clear bits.
const PORT_CHANGES: u32 = PORT_CONNECT_CHANGE | PORT_ENABLE_CHANGE | PORT_OVERCURRENT_CHANGE;
const MAX_PORTS: u32 = 15;

// PCI configuration: the legacy support capability.
const EXT_CAP_LEGACY: u32 = 1;
const LEGACY_BIOS_OWNED: u32 = 1 << 16;
const LEGACY_OS_OWNED: u32 = 1 << 24;

// Link pointers.
const LINK_TERMINATE: u32 = 1 << 0;
const LINK_QH: u32 = 1 << 1;

// Queue head.
const QH_SIZE: usize = 64;
const QH_HEAD: u32 = 1 << 15;
const QH_DATA_TOGGLE_FROM_QTD: u32 = 1 << 14;
const QH_SPEED_HIGH: u32 = 2 << 12;
const QH_MULT_ONE: u32 = 1 << 30;
const QH_SMASK_UFRAME0: u32 = 0x01;

// Queue element transfer descriptor.
const QTD_SIZE: usize = 32;
const QTD_ACTIVE: u32 = 1 << 7;
const QTD_HALTED: u32 = 1 << 6;
const QTD_DATA_BUFFER_ERROR: u32 = 1 << 5;
const QTD_BABBLE: u32 = 1 << 4;
const QTD_TRANSACTION_ERROR: u32 = 1 << 3;
const QTD_MISSED_MICROFRAME: u32 = 1 << 2;
const QTD_ERRORS: u32 = QTD_DATA_BUFFER_ERROR | QTD_BABBLE | QTD_TRANSACTION_ERROR | QTD_MISSED_MICROFRAME;
const QTD_OUT: u32 = 0 << 8;
const QTD_IN: u32 = 1 << 8;
const QTD_SETUP: u32 = 2 << 8;
const QTD_THREE_ERRORS: u32 = 3 << 10;
const QTD_TOGGLE: u32 = 1 << 31;

/// Offset of the setup packet in a transfer's memory, after its qTDs.
const SETUP_OFFSET: usize = 4 * QTD_SIZE;
/// The most one qTD moves: four pages from a page boundary.
const PIECE: usize = 16 * 1024;

// Queue heads in the block, in list order.
const QH_ASYNC_HEAD: usize = 0;
const QH_SYNC: usize = 1;
const QH_ASYNC: usize = 2;
const QH_PERIODIC_ROOT: usize = QH_ASYNC + MAX_PENDING;
const QH_PERIODIC: usize = QH_PERIODIC_ROOT + 1;
const QH_COUNT: usize = QH_PERIODIC + MAX_PENDING;

const FRAMES: usize = 1024;

/// Why the controller could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EhciError {
    /// The registers do not look like an EHCI controller's.
    BadRegisters,
    /// The controller did not reset or start.
    Timeout,
    /// DMA memory could not be allocated.
    NoMemory,
    /// DMA memory lies above 4 GiB, which these descriptors do not address.
    HighMemory,
}

/// Memory for one transfer: qTDs, the setup packet and the data.
struct Xfer<'d, D: DmaAllocator + ?Sized> {
    mem: OwnedDma<'d, D>,
    buf: OwnedDma<'d, D>,
}

impl<'d, D: DmaAllocator + ?Sized> Xfer<'d, D> {
    fn new(dma: &'d D, buf_len: usize) -> Result<Self, UsbError> {
        let mem = OwnedDma::new(dma, SETUP_OFFSET + 16).ok_or(UsbError::NoResources)?;
        let buf = OwnedDma::new(dma, buf_len).ok_or(UsbError::NoResources)?;
        if !usbhc::below_4g(&mem) || !usbhc::below_4g(&buf) {
            return Err(UsbError::NoResources);
        }
        Ok(Self { mem, buf })
    }

    fn qtd_addr(&self, i: usize) -> u32 {
        (self.mem.device_addr().as_u64() + (i * QTD_SIZE) as u64) as u32
    }

    fn token(&self, i: usize) -> u32 {
        u32::from_le(self.mem.load(i * QTD_SIZE + 8))
    }

    fn buf_addr(&self) -> u64 {
        self.buf.device_addr().as_u64()
    }
}

/// A transfer built into an [`Xfer`].
#[derive(Clone, Copy)]
struct Plan {
    /// qTDs used.
    count: usize,
    /// The data qTD, if any, and its length.
    data: Option<usize>,
    len: usize,
    /// The queue head it runs in.
    qh: usize,
}

enum Progress {
    Running,
    Done(usize),
    Failed(UsbError),
}

struct Pending<'d, D: DmaAllocator + ?Sized> {
    xfer: Xfer<'d, D>,
    plan: Plan,
}

struct Mem<'d, D: DmaAllocator + ?Sized> {
    frames: OwnedDma<'d, D>,
    qhs: OwnedDma<'d, D>,
    sync: Xfer<'d, D>,
    pending: [Option<Pending<'d, D>>; MAX_PENDING],
}

/// An EHCI controller.
///
/// The DMA memory is freed on drop only once the controller has halted;
/// one that will not halt might still read it, so it is leaked.
pub struct Ehci<'d, D: DmaAllocator + ?Sized> {
    io: IoMem,
    clock: &'d dyn Clock,
    dma: &'d D,
    op: usize,
    ports: u8,
    devs: DevTable,
    mem: ManuallyDrop<Mem<'d, D>>,
}

/// Takes the controller of PCI function `func`, whose registers are `io`,
/// away from firmware (USB legacy support), so that the BIOS stops using
/// it and its SMIs. Call before [`Ehci::new`]. Firmware that never lets go
/// is waited for until `clock` says a second has passed, then ignored.
pub fn release_from_firmware<C: ConfigAccess + ?Sized>(func: &Function<'_, C>, io: &IoMem, clock: &dyn Clock) {
    let Ok(hccparams) = io.read::<u32>(HCCPARAMS) else { return };
    let mut off = (hccparams >> 8 & 0xff) as u16;
    // The capabilities are a list in configuration space; 0 ends it.
    for _ in 0..16 {
        if off < 0x40 {
            return;
        }
        let cap = func.read32(off);
        if cap & 0xff == EXT_CAP_LEGACY {
            if cap & LEGACY_BIOS_OWNED != 0 {
                func.write32(off, cap | LEGACY_OS_OWNED);
                usbhc::wait(clock, 1_000_000_000, || func.read32(off) & LEGACY_BIOS_OWNED == 0);
            }
            // No more SMIs for USB events.
            func.write32(off + 4, 0);
            return;
        }
        off = (cap >> 8 & 0xff) as u16;
    }
}

impl<'d, D: DmaAllocator + ?Sized> Ehci<'d, D> {
    /// Resets the controller whose registers are `io` and starts it with
    /// DMA memory from `dma`. `clock` times resets and the waits for
    /// transfers. All ports are routed to this controller; each device
    /// that turns out not to be high-speed is handed to the companion when
    /// its port is reset.
    pub fn new(io: IoMem, dma: &'d D, clock: &'d dyn Clock) -> Result<Self, EhciError> {
        let bad = EhciError::BadRegisters;
        let caplength = io.read::<u8>(CAPLENGTH).map_err(|_| bad)? as usize;
        let version = io.read::<u16>(HCIVERSION).map_err(|_| bad)?;
        let params = io.read::<u32>(HCSPARAMS).map_err(|_| bad)?;
        let ports = (params & HCS_PORTS).min(MAX_PORTS);
        if caplength < 0x0c || version < 0x0090 || ports == 0 || io.len() < caplength + PORTSC + 4 * ports as usize {
            return Err(bad);
        }

        let no_mem = EhciError::NoMemory;
        let frames = OwnedDma::new(dma, FRAMES * 4).ok_or(no_mem)?;
        let qhs = OwnedDma::new(dma, QH_COUNT * QH_SIZE).ok_or(no_mem)?;
        if !usbhc::below_4g(&frames) || !usbhc::below_4g(&qhs) {
            return Err(EhciError::HighMemory);
        }
        let sync = Xfer::new(dma, BOUNCE_LEN).map_err(|_| no_mem)?;

        let hc = Self {
            io,
            clock,
            dma,
            op: caplength,
            ports: ports as u8,
            devs: DevTable::new(),
            mem: ManuallyDrop::new(Mem { frames, qhs, sync, pending: [const { None }; MAX_PENDING] }),
        };
        hc.build_schedule();
        hc.reset()?;
        hc.start(params)?;
        Ok(hc)
    }

    /// Number of root ports.
    pub fn ports(&self) -> u8 {
        self.ports
    }

    fn r32(&self, off: usize) -> u32 {
        // `new` checked the window against every register used.
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

    fn qh_addr(&self, i: usize) -> u32 {
        (self.mem.qhs.device_addr().as_u64() + (i * QH_SIZE) as u64) as u32
    }

    fn qh_word(&self, qh: usize, n: usize) -> u32 {
        u32::from_le(self.mem.qhs.load(qh * QH_SIZE + n * 4))
    }

    fn set_qh_word(&self, qh: usize, n: usize, v: u32) {
        self.mem.qhs.store(qh * QH_SIZE + n * 4, v.to_le());
    }

    /// Links the queue heads in their lists, all idle.
    fn build_schedule(&self) {
        let idle = |qh: usize, link: u32, head: bool| {
            self.set_qh_word(qh, 0, link);
            self.set_qh_word(qh, 1, if head { QH_HEAD } else { 0 });
            self.set_qh_word(qh, 2, QH_MULT_ONE);
            self.set_qh_word(qh, 4, LINK_TERMINATE);
            self.set_qh_word(qh, 5, LINK_TERMINATE);
            self.set_qh_word(qh, 6, QTD_HALTED);
        };
        let link = |qh: usize| self.qh_addr(qh) | LINK_QH;
        let async_order: [usize; 2 + MAX_PENDING] = core::array::from_fn(|i| QH_ASYNC_HEAD + i);
        for (k, &qh) in async_order.iter().enumerate() {
            let next = async_order[(k + 1) % async_order.len()];
            idle(qh, link(next), qh == QH_ASYNC_HEAD);
        }
        idle(QH_PERIODIC_ROOT, link(QH_PERIODIC), false);
        for i in 0..MAX_PENDING {
            let next = if i + 1 < MAX_PENDING { link(QH_PERIODIC + i + 1) } else { LINK_TERMINATE };
            idle(QH_PERIODIC + i, next, false);
        }
        let first = link(QH_PERIODIC_ROOT).to_le();
        for i in 0..FRAMES {
            self.mem.frames.store(i * 4, first);
        }
    }

    fn reset(&self) -> Result<(), EhciError> {
        let timeout = EhciError::Timeout;
        self.op_write(USBINTR, 0);
        self.op_write(USBCMD, self.op_read(USBCMD) & !CMD_RUN);
        if !usbhc::wait(self.clock, 20_000_000, || self.op_read(USBSTS) & STS_HALTED != 0) {
            return Err(timeout);
        }
        self.op_write(USBCMD, CMD_HCRESET);
        if !usbhc::wait(self.clock, 250_000_000, || self.op_read(USBCMD) & CMD_HCRESET == 0) {
            return Err(timeout);
        }
        Ok(())
    }

    fn start(&self, params: u32) -> Result<(), EhciError> {
        if self.r32(HCCPARAMS) & HCC_64BIT != 0 {
            self.op_write(CTRLDSSEGMENT, 0);
        }
        self.op_write(USBSTS, STS_ALL);
        self.op_write(PERIODICLISTBASE, self.mem.frames.device_addr().as_u64() as u32);
        self.op_write(ASYNCLISTADDR, self.qh_addr(QH_ASYNC_HEAD));
        let schedules = CMD_ASYNC_ENABLE | CMD_PERIODIC_ENABLE;
        self.op_write(USBCMD, CMD_RUN | CMD_THRESHOLD | schedules);
        if !usbhc::wait(self.clock, 20_000_000, || self.op_read(USBSTS) & STS_HALTED == 0) {
            return Err(EhciError::Timeout);
        }
        // From here on the ports belong to this controller.
        self.op_write(CONFIGFLAG, 1);
        if params & HCS_PORT_POWER_CONTROL != 0 {
            for port in 1..=self.ports {
                let sc = self.portsc(port);
                self.set_portsc(port, (sc & !PORT_CHANGES) | PORT_POWER);
            }
            // The ports settle for 20 ms after power (USB 2.0 §11.11).
            usbhc::delay(self.clock, 20_000_000);
        }
        Ok(())
    }

    fn portsc(&self, port: u8) -> u32 {
        self.op_read(PORTSC + 4 * (port as usize - 1))
    }

    fn set_portsc(&self, port: u8, v: u32) {
        self.op_write(PORTSC + 4 * (port as usize - 1), v)
    }

    /// Waits for the controller to finish the frame it is in.
    fn next_frame(&self) {
        let start = self.op_read(FRINDEX) >> 3;
        usbhc::wait(self.clock, 3_000_000, || self.op_read(FRINDEX) >> 3 != start);
    }

    /// Writes qTD `i` of `x`, linked to `i + 1` unless `last`, with the
    /// buffer at device address `buffer` (page aligned, or for a short one
    /// anywhere within a page).
    fn put_qtd(x: &Xfer<'d, D>, i: usize, last: bool, alt: Option<usize>, token: u32, buffer: u64) {
        let off = i * QTD_SIZE;
        let next = if last { LINK_TERMINATE } else { x.qtd_addr(i + 1) };
        let alt = alt.map_or(LINK_TERMINATE, |a| x.qtd_addr(a));
        x.mem.store(off, next.to_le());
        x.mem.store(off + 4, alt.to_le());
        x.mem.store(off + 8, token.to_le());
        for k in 0..5 {
            let page = (buffer & !0xfff) + 0x1000 * k as u64;
            let ptr = if k == 0 { buffer } else { page };
            x.mem.store(off + 12 + 4 * k, (ptr as u32).to_le());
        }
    }

    fn token(pid: u32, bytes: usize, toggle: bool) -> u32 {
        QTD_ACTIVE | pid | QTD_THREE_ERRORS | (bytes as u32) << 16 | if toggle { QTD_TOGGLE } else { 0 }
    }

    /// qTDs for a control transfer: setup, data (if any), status.
    fn build_control(x: &Xfer<'d, D>, setup: SetupPacket, len: usize, dir_in: bool, qh: usize) -> Plan {
        x.mem.write(SETUP_OFFSET, &setup.to_bytes());
        let setup_addr = x.mem.device_addr().as_u64() + SETUP_OFFSET as u64;
        let has_data = len > 0;
        let status_index = if has_data { 2 } else { 1 };
        Self::put_qtd(x, 0, false, None, Self::token(QTD_SETUP, 8, false), setup_addr);
        let mut data = None;
        if has_data {
            // A short packet in the data stage goes straight to the status stage.
            let pid = if dir_in { QTD_IN } else { QTD_OUT };
            Self::put_qtd(x, 1, false, Some(status_index), Self::token(pid, len, true), x.buf_addr());
            data = Some(1);
        }
        let status_pid = if has_data && dir_in { QTD_OUT } else { QTD_IN };
        Self::put_qtd(x, status_index, true, None, Self::token(status_pid, 0, true), 0);
        Plan { count: status_index + 1, data, len, qh }
    }

    /// A single-qTD bulk or interrupt transfer of up to [`PIECE`] bytes.
    fn build_bulk(x: &Xfer<'d, D>, toggle: bool, len: usize, dir_in: bool, qh: usize) -> Plan {
        let pid = if dir_in { QTD_IN } else { QTD_OUT };
        Self::put_qtd(x, 0, true, None, Self::token(pid, len, toggle), x.buf_addr());
        Plan { count: 1, data: Some(0), len, qh }
    }

    /// Fills in the idle queue head `plan.qh` for `pipe` and `x`'s first
    /// qTD, which starts the transfer.
    fn start_transfer(&self, x: &Xfer<'d, D>, plan: &Plan, pipe: &Pipe) {
        let qh = plan.qh;
        let periodic = qh >= QH_PERIODIC;
        let chars = pipe.address as u32
            | (pipe.endpoint as u32 & 0xf) << 8
            | QH_SPEED_HIGH
            | QH_DATA_TOGGLE_FROM_QTD
            | (pipe.mps as u32 & 0x7ff) << 16;
        let caps = QH_MULT_ONE | if periodic { QH_SMASK_UFRAME0 } else { 0 };
        // The overlay stays halted until its status is cleared, last.
        self.set_qh_word(qh, 6, QTD_HALTED);
        self.set_qh_word(qh, 1, chars);
        self.set_qh_word(qh, 2, caps);
        self.set_qh_word(qh, 3, 0);
        self.set_qh_word(qh, 5, LINK_TERMINATE);
        self.set_qh_word(qh, 4, x.qtd_addr(0));
        osmium_arch::barrier::dma_wmb();
        self.set_qh_word(qh, 6, 0);
        osmium_arch::barrier::mb();
    }

    fn progress(&self, x: &Xfer<'d, D>, plan: &Plan) -> Progress {
        let mut bytes = 0;
        for i in 0..plan.count {
            let t = x.token(i);
            if t & QTD_ACTIVE != 0 {
                // A short data stage leaves the qTDs after it unrun; the
                // data qTD itself is not active then.
                return Progress::Running;
            }
            if t & QTD_HALTED != 0 {
                return Progress::Failed(if t & QTD_ERRORS == 0 { UsbError::Stall } else { UsbError::Transaction });
            }
            if plan.data == Some(i) {
                let left = (t >> 16 & 0x7fff) as usize;
                bytes = plan.len.saturating_sub(left);
            }
        }
        Progress::Done(bytes)
    }

    /// Takes the queue head `qh` off its list, waits until the controller
    /// cannot be reading it or its qTDs, and puts it back idle.
    fn abort(&self, qh: usize) {
        let periodic = qh >= QH_PERIODIC;
        // Each list is in index order, so the one before is the previous queue head.
        let (prev, next) = (qh - 1, self.qh_word(qh, 0));
        let own = self.qh_addr(qh) | LINK_QH;
        self.set_qh_word(prev, 0, next);
        osmium_arch::barrier::mb();
        if periodic {
            // Two frames: one for a traversal in progress, one for any the
            // controller started from a cached frame list entry.
            self.next_frame();
            self.next_frame();
        } else {
            // The status bit is clear: it is acknowledged after every use.
            self.op_write(USBCMD, self.op_read(USBCMD) | CMD_DOORBELL);
            usbhc::wait(self.clock, 20_000_000, || self.op_read(USBSTS) & STS_ASYNC_ADVANCE != 0);
            self.op_write(USBSTS, STS_ASYNC_ADVANCE);
        }
        self.set_qh_word(qh, 6, QTD_HALTED);
        self.set_qh_word(qh, 4, LINK_TERMINATE);
        osmium_arch::barrier::dma_wmb();
        self.set_qh_word(prev, 0, own);
    }

    /// Runs the transfer built into the synchronous `Xfer`.
    fn run_sync(&mut self, plan: Plan, pipe: &Pipe, timeout_ns: u64) -> Result<usize, UsbError> {
        self.start_transfer(&self.mem.sync, &plan, pipe);
        let mut outcome = Progress::Running;
        let done = usbhc::wait(self.clock, timeout_ns, || {
            outcome = self.progress(&self.mem.sync, &plan);
            !matches!(outcome, Progress::Running)
        });
        match outcome {
            _ if !done => {
                self.abort(plan.qh);
                Err(UsbError::Timeout)
            }
            Progress::Done(bytes) => Ok(bytes),
            Progress::Failed(e) => {
                // The controller halted the queue head on its own.
                Err(e)
            }
            Progress::Running => unreachable!("wait returned with the transfer running"),
        }
    }
}

impl<D: DmaAllocator + ?Sized> Hc for Ehci<'_, D> {
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
        let sc = self.portsc(port);
        // A port handed to the companion shows its device there.
        let connected = sc & PORT_CONNECTED != 0 && sc & PORT_OWNER == 0;
        let enabled = sc & PORT_ENABLED != 0;
        let speed = if enabled {
            Speed::High
        } else if sc & PORT_LINE_MASK == PORT_LINE_K {
            Speed::Low
        } else {
            Speed::Full
        };
        PortStatus { connected, enabled, speed: connected.then_some(speed) }
    }

    fn reset_port(&mut self, port: u8) -> Result<Speed, UsbError> {
        let keep = |sc: u32| sc & !PORT_CHANGES;
        let sc = self.portsc(port);
        if sc & PORT_CONNECTED == 0 || sc & PORT_OWNER != 0 {
            return Err(UsbError::NoDevice);
        }
        // A low-speed device pulls the line to "K" and is for the companion.
        if sc & PORT_LINE_MASK == PORT_LINE_K {
            self.set_portsc(port, keep(sc) | PORT_OWNER);
            return Err(UsbError::Unsupported);
        }
        // 50 ms of reset (USB 2.0 §7.1.7.5), during which a high-speed
        // device identifies itself, then 10 ms for it to recover.
        self.set_portsc(port, keep(sc & !PORT_ENABLED) | PORT_RESET);
        usbhc::delay(self.clock, 50_000_000);
        self.set_portsc(port, keep(self.portsc(port)) & !PORT_RESET);
        if !usbhc::wait(self.clock, 5_000_000, || self.portsc(port) & PORT_RESET == 0) {
            return Err(UsbError::Timeout);
        }
        usbhc::delay(self.clock, 10_000_000);
        let sc = self.portsc(port);
        self.set_portsc(port, sc | PORT_CHANGES);
        if sc & PORT_CONNECTED == 0 {
            return Err(UsbError::NoDevice);
        }
        if sc & PORT_ENABLED == 0 {
            // Full speed: not high-speed, so the companion's.
            self.set_portsc(port, keep(self.portsc(port)) | PORT_OWNER);
            return Err(UsbError::Unsupported);
        }
        Ok(Speed::High)
    }

    fn control(&mut self, pipe: &Pipe, setup: SetupPacket, data: Data<'_>) -> Result<usize, UsbError> {
        let len = data.len();
        if len > PIECE || pipe.mps == 0 {
            return Err(UsbError::NoResources);
        }
        let dir_in = matches!(data, Data::In(_));
        if let Data::Out(out) = &data {
            self.mem.sync.buf.write(0, out);
        }
        let plan = Self::build_control(&self.mem.sync, setup, len, dir_in, QH_SYNC);
        let moved = self.run_sync(plan, pipe, CONTROL_TIMEOUT_NS)?;
        if let Data::In(buf) = data {
            self.mem.sync.buf.read(0, &mut buf[..moved.min(len)]);
        }
        Ok(moved)
    }

    fn bulk(&mut self, pipe: &Pipe, toggle: bool, data: Data<'_>) -> Result<usize, UsbError> {
        if pipe.mps == 0 {
            return Err(UsbError::BadEndpoint);
        }
        let total = data.len();
        let mut done = 0;
        let mut toggle = toggle;
        let mut data = data;
        loop {
            let n = (total - done).min(PIECE);
            let dir_in = matches!(data, Data::In(_));
            if let Data::Out(out) = &data {
                self.mem.sync.buf.write(0, &out[done..done + n]);
            }
            let plan = Self::build_bulk(&self.mem.sync, toggle, n, dir_in, QH_SYNC);
            let moved = self.run_sync(plan, pipe, BULK_TIMEOUT_NS)?;
            if let Data::In(buf) = &mut data {
                self.mem.sync.buf.read(0, &mut buf[done..done + moved.min(n)]);
            }
            done += moved;
            toggle = usbhc::toggle_after(toggle, moved, pipe.mps);
            // A short packet ends an IN transfer; an empty OUT is one packet.
            if done >= total || moved < n {
                return Ok(done);
            }
        }
    }

    fn submit(&mut self, pipe: &Pipe, toggle: bool, len: usize) -> Result<usize, UsbError> {
        if len == 0 || len > MAX_SUBMIT_LEN || pipe.mps == 0 {
            return Err(UsbError::NoResources);
        }
        let slot = self.mem.pending.iter().position(Option::is_none).ok_or(UsbError::NoResources)?;
        let xfer = Xfer::new(self.dma, MAX_SUBMIT_LEN)?;
        let qh = if pipe.ttype == TransferType::Interrupt { QH_PERIODIC + slot } else { QH_ASYNC + slot };
        let plan = Self::build_bulk(&xfer, toggle, len, true, qh);
        self.start_transfer(&xfer, &plan, pipe);
        self.mem.pending[slot] = Some(Pending { xfer, plan });
        Ok(slot)
    }

    fn poll(&mut self, slot: usize, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
        let p = self.mem.pending.get(slot)?.as_ref()?;
        // Done or halted by the controller itself: either way it has let go.
        let result = match self.progress(&p.xfer, &p.plan) {
            Progress::Running => return None,
            Progress::Done(bytes) => {
                let n = bytes.min(buf.len());
                p.xfer.buf.read(0, &mut buf[..n]);
                Ok(n)
            }
            Progress::Failed(e) => Err(e),
        };
        self.mem.pending[slot] = None;
        Some(result)
    }

    fn cancel(&mut self, slot: usize) {
        if let Some(p) = self.mem.pending.get_mut(slot).and_then(Option::take) {
            self.abort(p.plan.qh);
        }
    }
}

impl<D: DmaAllocator + ?Sized> UsbHost for Ehci<'_, D> {
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
}

impl<D: DmaAllocator + ?Sized> Drop for Ehci<'_, D> {
    fn drop(&mut self) {
        // Stop the controller before its schedules are freed. One that does
        // not halt may still read them: the memory is leaked.
        self.op_write(USBCMD, self.op_read(USBCMD) & !(CMD_RUN | CMD_ASYNC_ENABLE | CMD_PERIODIC_ENABLE));
        if !usbhc::wait(self.clock, 20_000_000, || self.op_read(USBSTS) & STS_HALTED != 0) {
            return;
        }
        self.op_write(CONFIGFLAG, 0);
        // SAFETY: dropped once, here, and not used again.
        unsafe { ManuallyDrop::drop(&mut self.mem) };
    }
}

#[cfg(test)]
mod tests;
