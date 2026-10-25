//! OHCI USB 1.1 host controller (Open Host Controller Interface 1.0a, PCI
//! class 0c/03/10).
//!
//! [`Ohci`] resets the controller, builds a fixed schedule of endpoint
//! descriptors and implements [`UsbHost`] for low- and full-speed devices on
//! its root ports and on full-speed hubs. The registers are memory-mapped
//! (PCI BAR 0). It is polled unless [`Ohci::enable_interrupts`] is called.
//!
//! # Schedule
//!
//! The endpoint descriptors are linked once and never moved:
//!
//! ```text
//! control list:  root -> synchronous
//! bulk list:     root -> synchronous -> slot 0..3
//! periodic list: root -> slot 0..3         (every HCCA interrupt entry)
//! ```
//!
//! Each root is permanently skipped. A transfer arms a descriptor by
//! pointing its head at a chain of transfer descriptors and clearing its
//! skip bit; when the transfer ends the descriptor is skipped again and the
//! driver waits a frame before touching it, as OHCI requires of software
//! that modifies a descriptor the controller may be reading.
//!
//! A transfer's data stage is a single transfer descriptor of at most one
//! page, whatever the packet size: the controller splits it into packets,
//! and a short packet ends it. Longer transfers are run in pieces.
//! Interrupt endpoints are polled every frame rather than every `bInterval`
//! frames, which devices tolerate.
//!
//! # Interrupts
//!
//! [`Ohci::enable_interrupts`] unmasks the done-queue and root hub status
//! change interrupts, and the kernel's handler for the controller's line (a
//! PCI INTx, shared) must then call [`Ohci::handle_interrupt`]. The last
//! descriptor of every transfer asks for an interrupt; the controller
//! raises it at the end of the frame. Polled operations keep working: they
//! read the descriptors, and the done-queue status bit they acknowledge
//! is one the handler acknowledges too, which costs neither of them a
//! completion.
//!
//! Not supported: isochronous endpoints and suspend.

use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::timer::Clock;
use osmium_hal::usb::{DeviceId, EndpointDescriptor, PortStatus, SetupPacket, Speed, TransferType, UsbError, UsbHost};

use crate::usbhc::{
    self, BOUNCE_LEN, BULK_TIMEOUT_NS, CONTROL_TIMEOUT_NS, Data, DevTable, Hc, MAX_PENDING, MAX_SUBMIT_LEN, Pipe,
};

/// The PCI class of an OHCI controller.
pub const CLASS: osmium_hal::pci::Class = osmium_hal::pci::Class { class: 0x0c, subclass: 0x03, prog_if: 0x10 };

// Registers.
const REVISION: usize = 0x00;
const CONTROL: usize = 0x04;
const COMMAND_STATUS: usize = 0x08;
const INTERRUPT_STATUS: usize = 0x0c;
const INTERRUPT_ENABLE: usize = 0x10;
const INTERRUPT_DISABLE: usize = 0x14;
const HCCA: usize = 0x18;
const CONTROL_HEAD_ED: usize = 0x20;
const CONTROL_CURRENT_ED: usize = 0x24;
const BULK_HEAD_ED: usize = 0x28;
const BULK_CURRENT_ED: usize = 0x2c;
const FM_INTERVAL: usize = 0x34;
const FM_NUMBER: usize = 0x3c;
const PERIODIC_START: usize = 0x40;
const LS_THRESHOLD: usize = 0x44;
const RH_DESCRIPTOR_A: usize = 0x48;
const RH_STATUS: usize = 0x50;
const RH_PORT_STATUS: usize = 0x54;

const CTRL_CBSR_3_1: u32 = 3;
const CTRL_PLE: u32 = 1 << 2;
const CTRL_CLE: u32 = 1 << 4;
const CTRL_BLE: u32 = 1 << 5;
#[cfg(test)]
const CTRL_HCFS: u32 = 3 << 6;
const CTRL_OPERATIONAL: u32 = 2 << 6;
const CTRL_INTERRUPT_ROUTING: u32 = 1 << 8;

const CMD_HCR: u32 = 1 << 0;
const CMD_CLF: u32 = 1 << 1;
const CMD_BLF: u32 = 1 << 2;
const CMD_OCR: u32 = 1 << 3;

const INT_WDH: u32 = 1 << 1;
/// Root hub status change.
const INT_RHSC: u32 = 1 << 6;
/// Master interrupt enable.
const INT_MIE: u32 = 1 << 31;
/// What [`Ohci::enable_interrupts`] unmasks.
const INT_EVENTS: u32 = INT_WDH | INT_RHSC;
/// Every interrupt, and the master enable, for the disable register.
const INT_ALL: u32 = 0xc000_007f;

const FM_INTERVAL_TOGGLE: u32 = 1 << 31;
const DEFAULT_FRAME_INTERVAL: u32 = 0x2edf;
const LS_THRESHOLD_DEFAULT: u32 = 0x628;

const RH_NDP: u32 = 0xff;
const RH_POWER_ON_TO_GOOD_SHIFT: u32 = 24;
const RH_LOCAL_POWER_SET: u32 = 1 << 16;

const PORT_CONNECTED: u32 = 1 << 0;
const PORT_ENABLED: u32 = 1 << 1;
const PORT_SET_ENABLE: u32 = 1 << 1;
const PORT_SET_RESET: u32 = 1 << 4;
const PORT_SET_POWER: u32 = 1 << 8;
const PORT_LOW_SPEED: u32 = 1 << 9;
const PORT_RESET_CHANGE: u32 = 1 << 20;
/// Writing these clears the status changes.
const PORT_CHANGES: u32 = 0x1f << 16;
const MAX_PORTS: u32 = 15;

// Endpoint descriptor.
const ED_SIZE: usize = 16;
const ED_LOW_SPEED: u32 = 1 << 13;
const ED_SKIP: u32 = 1 << 14;
#[cfg(test)]
const ED_HALTED: u32 = 1 << 0;

// Transfer descriptor.
const TD_SIZE: usize = 16;
const TD_ROUNDING: u32 = 1 << 18;
const TD_SETUP: u32 = 0 << 19;
const TD_OUT: u32 = 1 << 19;
const TD_IN: u32 = 2 << 19;
/// No interrupt on completion.
const TD_NO_INTERRUPT: u32 = 7 << 21;
/// Use the toggle in the descriptor, not the endpoint's carry.
const TD_USE_TOGGLE: u32 = 1 << 25;
const TD_TOGGLE: u32 = 1 << 24;
const TD_NOT_ACCESSED: u32 = 0xf;

// Condition codes.
const CC_STALL: u32 = 4;

/// Offset of the setup packet in a transfer's memory, after its descriptors.
const SETUP_OFFSET: usize = 4 * TD_SIZE;
/// The most one data descriptor moves (one page).
const PIECE: usize = 4096;

// Endpoint descriptors in the block, in list order.
const ED_CONTROL_ROOT: usize = 0;
const ED_BULK_ROOT: usize = 1;
const ED_PERIODIC_ROOT: usize = 2;
const ED_SYNC_CONTROL: usize = 3;
const ED_SYNC_BULK: usize = 4;
const ED_PERIODIC: usize = 5;
const ED_BULK: usize = ED_PERIODIC + MAX_PENDING;
const ED_COUNT: usize = ED_BULK + MAX_PENDING;

/// Why the controller could not be brought up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OhciError {
    /// The registers do not look like an OHCI controller's.
    BadRegisters,
    /// The controller did not reset or start.
    Timeout,
    /// DMA memory could not be allocated.
    NoMemory,
    /// The controller addresses 32 bits and DMA memory lies above 4 GiB.
    HighMemory,
}

/// Memory for one transfer: descriptors, the setup packet and the data.
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

    fn td_addr(&self, i: usize) -> u32 {
        (self.mem.device_addr().as_u64() + (i * TD_SIZE) as u64) as u32
    }

    fn word(&self, i: usize, n: usize) -> u32 {
        u32::from_le(self.mem.load(i * TD_SIZE + n * 4))
    }

    fn buf_addr(&self) -> u32 {
        self.buf.device_addr().as_u64() as u32
    }
}

/// A transfer built into an [`Xfer`].
#[derive(Clone, Copy)]
struct Plan {
    /// Descriptors before the tail.
    count: usize,
    /// The data descriptor, if any, its direction and its length.
    data: Option<usize>,
    dir_in: bool,
    len: usize,
    /// The endpoint descriptor it runs on.
    ed: usize,
    /// Which list the controller must be told is filled.
    list: Option<u32>,
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
    hcca: OwnedDma<'d, D>,
    eds: OwnedDma<'d, D>,
    sync: Xfer<'d, D>,
    pending: [Option<Pending<'d, D>>; MAX_PENDING],
}

/// An OHCI controller.
///
/// The DMA memory is freed on drop only once the controller has stopped
/// processing its lists.
pub struct Ohci<'d, D: DmaAllocator + ?Sized> {
    io: IoMem,
    clock: &'d dyn Clock,
    dma: &'d D,
    ports: u8,
    devs: DevTable,
    /// The synchronous transfer's memory may still be in use by the controller.
    wedged: bool,
    /// The interrupts have been unmasked by [`Ohci::enable_interrupts`].
    interrupts_enabled: bool,
    /// Interrupts [`Ohci::handle_interrupt`] has serviced.
    interrupts: u64,
    mem: ManuallyDrop<Mem<'d, D>>,
}

impl<'d, D: DmaAllocator + ?Sized> Ohci<'d, D> {
    /// Takes the controller whose registers are `io` away from firmware,
    /// resets it and starts it with DMA memory from `dma`. `clock` times
    /// resets and the waits for transfers.
    pub fn new(io: IoMem, dma: &'d D, clock: &'d dyn Clock) -> Result<Self, OhciError> {
        let rd = |off| io.read::<u32>(off).map_err(|_| OhciError::BadRegisters);
        let revision = rd(REVISION)?;
        let ndp = (rd(RH_DESCRIPTOR_A)? & RH_NDP).min(MAX_PORTS) as u8;
        if revision & 0xff != 0x10 || ndp == 0 || io.len() < RH_PORT_STATUS + 4 * ndp as usize {
            return Err(OhciError::BadRegisters);
        }

        let no_mem = OhciError::NoMemory;
        let hcca = OwnedDma::new(dma, 4096).ok_or(no_mem)?;
        let eds = OwnedDma::new(dma, ED_COUNT * ED_SIZE).ok_or(no_mem)?;
        if !usbhc::below_4g(&hcca) || !usbhc::below_4g(&eds) {
            return Err(OhciError::HighMemory);
        }
        let sync = Xfer::new(dma, BOUNCE_LEN).map_err(|_| no_mem)?;

        let hc = Self {
            io,
            clock,
            dma,
            ports: ndp,
            devs: DevTable::new(),
            wedged: false,
            interrupts_enabled: false,
            interrupts: 0,
            mem: ManuallyDrop::new(Mem { hcca, eds, sync, pending: [const { None }; MAX_PENDING] }),
        };
        hc.build_schedule();
        hc.start()?;
        Ok(hc)
    }

    /// Lets the controller raise its interrupt line when a transfer retires
    /// and when the root hub's status changes. From now on the kernel's
    /// handler must call [`handle_interrupt`](Self::handle_interrupt).
    ///
    /// Polled operations keep working; see the module documentation. The
    /// caller serializes both with one lock (the driver is `&mut self`
    /// throughout), so the handler must not run on a CPU that holds it.
    pub fn enable_interrupts(&mut self) {
        self.w32(INTERRUPT_STATUS, INT_EVENTS);
        self.w32(INTERRUPT_ENABLE, INT_MIE | INT_EVENTS);
        self.interrupts_enabled = true;
    }

    /// Stops the controller from raising interrupts (polling still works).
    pub fn disable_interrupts(&mut self) {
        self.w32(INTERRUPT_DISABLE, INT_MIE | INT_EVENTS);
        self.interrupts_enabled = false;
    }

    /// Services the controller's interrupt by acknowledging it. Returns
    /// false, doing nothing, if interrupts are not enabled or the controller
    /// was not asserting one (a shared line).
    pub fn handle_interrupt(&mut self) -> bool {
        if !self.interrupts_enabled {
            return false;
        }
        let events = self.r32(INTERRUPT_STATUS) & INT_EVENTS;
        if events == 0 {
            return false;
        }
        // Write-one-to-clear. Acknowledging the done queue lets the
        // controller write the next one. The root hub's status bits stay
        // where `port_status` reads them.
        self.w32(INTERRUPT_STATUS, events);
        self.interrupts += 1;
        true
    }

    /// How many interrupts [`handle_interrupt`](Self::handle_interrupt) has
    /// serviced.
    pub fn interrupts_handled(&self) -> u64 {
        self.interrupts
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

    fn ed_addr(&self, i: usize) -> u32 {
        (self.mem.eds.device_addr().as_u64() + (i * ED_SIZE) as u64) as u32
    }

    fn ed_word(&self, ed: usize, n: usize) -> u32 {
        u32::from_le(self.mem.eds.load(ed * ED_SIZE + n * 4))
    }

    fn set_ed_word(&self, ed: usize, n: usize, v: u32) {
        self.mem.eds.store(ed * ED_SIZE + n * 4, v.to_le());
    }

    /// Links the endpoint descriptors into their lists, all skipped, and
    /// points every periodic table entry at the periodic root.
    fn build_schedule(&self) {
        let chain = |ed: usize, next: Option<usize>| {
            self.set_ed_word(ed, 0, ED_SKIP);
            self.set_ed_word(ed, 3, next.map_or(0, |n| self.ed_addr(n)));
        };
        chain(ED_CONTROL_ROOT, Some(ED_SYNC_CONTROL));
        chain(ED_SYNC_CONTROL, None);
        chain(ED_BULK_ROOT, Some(ED_SYNC_BULK));
        chain(ED_SYNC_BULK, Some(ED_BULK));
        for i in 0..MAX_PENDING {
            chain(ED_BULK + i, (i + 1 < MAX_PENDING).then_some(ED_BULK + i + 1));
            chain(ED_PERIODIC + i, (i + 1 < MAX_PENDING).then_some(ED_PERIODIC + i + 1));
        }
        chain(ED_PERIODIC_ROOT, Some(ED_PERIODIC));
        let periodic = self.ed_addr(ED_PERIODIC_ROOT).to_le();
        for i in 0..32 {
            self.mem.hcca.store(i * 4, periodic);
        }
    }

    fn start(&self) -> Result<(), OhciError> {
        let timeout = OhciError::Timeout;
        // Ask SMM firmware to let go of the controller.
        if self.r32(CONTROL) & CTRL_INTERRUPT_ROUTING != 0 {
            self.w32(COMMAND_STATUS, CMD_OCR);
            if !usbhc::wait(self.clock, 500_000_000, || self.r32(CONTROL) & CTRL_INTERRUPT_ROUTING == 0) {
                return Err(timeout);
            }
        }
        let interval = match self.r32(FM_INTERVAL) & 0x3fff {
            // A value too small for the largest-packet computation is as bad as none.
            fi if fi <= 210 => DEFAULT_FRAME_INTERVAL,
            fi => fi,
        };
        let toggle = !self.r32(FM_INTERVAL) & FM_INTERVAL_TOGGLE;

        self.w32(INTERRUPT_DISABLE, INT_ALL);
        self.w32(COMMAND_STATUS, CMD_HCR);
        if !usbhc::wait(self.clock, 10_000_000, || self.r32(COMMAND_STATUS) & CMD_HCR == 0) {
            return Err(timeout);
        }
        // The controller is suspended and must be operational within 2 ms.
        self.w32(HCCA, self.mem.hcca.device_addr().as_u64() as u32);
        self.w32(CONTROL_HEAD_ED, self.ed_addr(ED_CONTROL_ROOT));
        self.w32(CONTROL_CURRENT_ED, 0);
        self.w32(BULK_HEAD_ED, self.ed_addr(ED_BULK_ROOT));
        self.w32(BULK_CURRENT_ED, 0);
        let largest_packet = (interval - 210) * 6 / 7;
        self.w32(FM_INTERVAL, toggle | largest_packet << 16 | interval);
        self.w32(PERIODIC_START, interval * 9 / 10);
        self.w32(LS_THRESHOLD, LS_THRESHOLD_DEFAULT);
        self.w32(INTERRUPT_STATUS, 0x7f);
        self.w32(CONTROL, CTRL_OPERATIONAL | CTRL_CLE | CTRL_BLE | CTRL_PLE | CTRL_CBSR_3_1);

        // Power the ports and give them time to settle.
        self.w32(RH_STATUS, RH_LOCAL_POWER_SET);
        for port in 1..=self.ports {
            self.w32(Self::port_reg(port), PORT_SET_POWER);
        }
        let settle_ms = (self.r32(RH_DESCRIPTOR_A) >> RH_POWER_ON_TO_GOOD_SHIFT) * 2;
        usbhc::delay(self.clock, settle_ms.min(100) as u64 * 1_000_000);
        Ok(())
    }

    fn port_reg(port: u8) -> usize {
        RH_PORT_STATUS + 4 * (port as usize).saturating_sub(1)
    }

    /// Waits for the controller to finish the frame it is in, so that it no
    /// longer reads an endpoint descriptor that was just skipped.
    fn next_frame(&self) -> bool {
        let start = self.r32(FM_NUMBER) & 0xffff;
        usbhc::wait(self.clock, 3_000_000, || self.r32(FM_NUMBER) & 0xffff != start)
    }

    /// Writes descriptor `i` of `x`, linked to descriptor `i + 1`. `flags`
    /// say whether it interrupts when it retires: [`TD_NO_INTERRUPT`] for
    /// all but a transfer's last, which interrupts at the end of the frame.
    fn put_td(x: &Xfer<'d, D>, i: usize, flags: u32, buffer: u32, len: usize) {
        let end = if len == 0 { 0 } else { buffer.wrapping_add(len as u32 - 1) };
        let cbp = if len == 0 { 0 } else { buffer };
        let next = x.td_addr(i + 1);
        let off = i * TD_SIZE;
        x.mem.store(off, (flags | TD_NOT_ACCESSED << 28).to_le());
        x.mem.store(off + 4, cbp.to_le());
        x.mem.store(off + 8, next.to_le());
        x.mem.store(off + 12, end.to_le());
    }

    /// Descriptors for a control transfer: setup, data (if any), status.
    fn build_control(x: &Xfer<'d, D>, setup: SetupPacket, len: usize, dir_in: bool) -> Plan {
        x.mem.write(SETUP_OFFSET, &setup.to_bytes());
        let setup_addr = (x.mem.device_addr().as_u64() + SETUP_OFFSET as u64) as u32;
        Self::put_td(x, 0, TD_SETUP | TD_USE_TOGGLE | TD_NO_INTERRUPT, setup_addr, 8);
        let mut next = 1;
        let mut data = None;
        if len > 0 {
            let (dp, round) = if dir_in { (TD_IN, TD_ROUNDING) } else { (TD_OUT, 0) };
            Self::put_td(x, 1, dp | round | TD_USE_TOGGLE | TD_TOGGLE | TD_NO_INTERRUPT, x.buf_addr(), len);
            data = Some(1);
            next = 2;
        }
        let status = if len > 0 && dir_in { TD_OUT } else { TD_IN };
        Self::put_td(x, next, status | TD_USE_TOGGLE | TD_TOGGLE, 0, 0);
        Plan { count: next + 1, data, dir_in, len, ed: ED_SYNC_CONTROL, list: Some(CMD_CLF) }
    }

    /// A single-descriptor bulk or interrupt transfer of up to a page.
    fn build_bulk(x: &Xfer<'d, D>, toggle: bool, len: usize, dir_in: bool, ed: usize, list: Option<u32>) -> Plan {
        let (dp, round) = if dir_in { (TD_IN, TD_ROUNDING) } else { (TD_OUT, 0) };
        let t = if toggle { TD_TOGGLE } else { 0 };
        Self::put_td(x, 0, dp | round | TD_USE_TOGGLE | t, x.buf_addr(), len);
        Plan { count: 1, data: Some(0), dir_in, len, ed, list }
    }

    /// Hands the transfer in `x` to the controller on `plan.ed`.
    fn arm(&self, x: &Xfer<'d, D>, plan: &Plan, pipe: &Pipe) {
        let ed = plan.ed;
        let low = if usbhc::is_low(pipe.speed) { ED_LOW_SPEED } else { 0 };
        let flags = pipe.address as u32 | (pipe.endpoint as u32 & 0xf) << 7 | low | (pipe.mps as u32) << 16;
        self.set_ed_word(ed, 0, flags | ED_SKIP);
        self.set_ed_word(ed, 1, x.td_addr(plan.count));
        self.set_ed_word(ed, 2, x.td_addr(0));
        osmium_arch::barrier::dma_wmb();
        self.set_ed_word(ed, 0, flags);
        osmium_arch::barrier::mb();
        if let Some(list) = plan.list {
            self.w32(COMMAND_STATUS, list);
        }
    }

    /// Skips the endpoint descriptor again and waits until the controller
    /// has surely let go of it and the transfer's descriptors. False if the
    /// controller did not go on to another frame: it may still be using them,
    /// so the caller must not free or reuse their memory.
    fn disarm(&self, ed: usize) -> bool {
        self.set_ed_word(ed, 0, self.ed_word(ed, 0) | ED_SKIP);
        osmium_arch::barrier::mb();
        let quiet = self.next_frame();
        // Acknowledge the done queue the controller built, so that it
        // keeps no descriptor of ours for later.
        if self.r32(INTERRUPT_STATUS) & INT_WDH != 0 {
            self.w32(INTERRUPT_STATUS, INT_WDH);
        }
        quiet
    }

    /// How far the transfer has got, from its descriptors' condition codes.
    ///
    /// The condition code and the current buffer pointer are separate words,
    /// and the controller need not write them back together: QEMU's copies
    /// the descriptor while this CPU may be reading it, so a new condition
    /// code can come with the old buffer pointer and count nothing moved.
    /// The byte count is only trusted once [`Self::disarm`] has waited out
    /// the frame the descriptor retired in.
    fn progress(&self, x: &Xfer<'d, D>, plan: &Plan) -> Progress {
        let mut bytes = 0;
        for i in 0..plan.count {
            let cc = x.word(i, 0) >> 28;
            if cc >= 0xe {
                return Progress::Running;
            }
            if cc != 0 {
                return Progress::Failed(if cc == CC_STALL { UsbError::Stall } else { UsbError::Transaction });
            }
            if plan.data == Some(i) {
                bytes = if !plan.dir_in {
                    plan.len
                } else {
                    // The current buffer pointer is the next byte to move,
                    // and 0 when all of them were.
                    match x.word(i, 1) {
                        0 => plan.len,
                        cbp => (cbp.wrapping_sub(x.buf_addr()) as usize).min(plan.len),
                    }
                };
            }
        }
        Progress::Done(bytes)
    }

    /// Runs the transfer built into the synchronous `Xfer`.
    fn run_sync(&mut self, plan: Plan, pipe: &Pipe, timeout_ns: u64) -> Result<usize, UsbError> {
        if self.wedged {
            return Err(UsbError::Timeout);
        }
        self.arm(&self.mem.sync, &plan, pipe);
        let mut outcome = Progress::Running;
        let done = usbhc::wait(self.clock, timeout_ns, || {
            outcome = self.progress(&self.mem.sync, &plan);
            !matches!(outcome, Progress::Running)
        });
        // The synchronous memory is not reused if the controller may still use it.
        self.wedged |= !self.disarm(plan.ed);
        if done {
            // Read the result again now its frame has passed (see `progress`).
            outcome = self.progress(&self.mem.sync, &plan);
        }
        match outcome {
            Progress::Done(bytes) if done => Ok(bytes),
            Progress::Failed(e) if done => Err(e),
            _ => Err(UsbError::Timeout),
        }
    }
}

impl<D: DmaAllocator + ?Sized> Hc for Ohci<'_, D> {
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
        let sc = self.r32(Self::port_reg(port));
        let connected = sc & PORT_CONNECTED != 0;
        let speed = if sc & PORT_LOW_SPEED != 0 { Speed::Low } else { Speed::Full };
        PortStatus { connected, enabled: sc & PORT_ENABLED != 0, speed: connected.then_some(speed) }
    }

    fn reset_port(&mut self, port: u8) -> Result<Speed, UsbError> {
        let reg = Self::port_reg(port);
        if self.r32(reg) & PORT_CONNECTED == 0 {
            return Err(UsbError::NoDevice);
        }
        // The controller drives the reset for 10 ms and flags its end.
        self.w32(reg, PORT_SET_RESET);
        if !usbhc::wait(self.clock, 100_000_000, || self.r32(reg) & PORT_RESET_CHANGE != 0) {
            return Err(UsbError::Timeout);
        }
        self.w32(reg, PORT_CHANGES);
        usbhc::delay(self.clock, 10_000_000);
        if self.r32(reg) & PORT_ENABLED == 0 {
            self.w32(reg, PORT_SET_ENABLE);
        }
        let sc = self.r32(reg);
        if sc & PORT_CONNECTED == 0 {
            return Err(UsbError::NoDevice);
        }
        if sc & PORT_ENABLED == 0 {
            return Err(UsbError::Transaction);
        }
        Ok(if sc & PORT_LOW_SPEED != 0 { Speed::Low } else { Speed::Full })
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
        let plan = Self::build_control(&self.mem.sync, setup, len, dir_in);
        let moved = self.run_sync(plan, pipe, CONTROL_TIMEOUT_NS)?;
        if let Data::In(buf) = data
            && let Some(dst) = buf.get_mut(..moved.min(len))
        {
            self.mem.sync.buf.read(0, dst);
        }
        Ok(moved)
    }

    fn chunk_max(&self, _pipe: &Pipe) -> usize {
        PIECE
    }

    fn bulk_chunk(&mut self, pipe: &Pipe, toggle: bool, data: Data<'_>) -> Result<usize, UsbError> {
        let n = data.len();
        let dir_in = matches!(data, Data::In(_));
        if let Data::Out(out) = &data {
            self.mem.sync.buf.write(0, out);
        }
        let plan = Self::build_bulk(&self.mem.sync, toggle, n, dir_in, ED_SYNC_BULK, Some(CMD_BLF));
        let moved = self.run_sync(plan, pipe, BULK_TIMEOUT_NS)?;
        if let Data::In(buf) = data
            && let Some(dst) = buf.get_mut(..moved.min(n))
        {
            self.mem.sync.buf.read(0, dst);
        }
        Ok(moved)
    }

    fn submit(&mut self, pipe: &Pipe, toggle: bool, len: usize) -> Result<usize, UsbError> {
        if len == 0 || len > MAX_SUBMIT_LEN || pipe.mps == 0 {
            return Err(UsbError::NoResources);
        }
        let slot = self.mem.pending.iter().position(Option::is_none).ok_or(UsbError::NoResources)?;
        let xfer = Xfer::new(self.dma, MAX_SUBMIT_LEN)?;
        let (ed, list) = match pipe.ttype {
            TransferType::Interrupt => (ED_PERIODIC + slot, None),
            _ => (ED_BULK + slot, Some(CMD_BLF)),
        };
        let plan = Self::build_bulk(&xfer, toggle, len, true, ed, list);
        self.arm(&xfer, &plan, pipe);
        *self.mem.pending.get_mut(slot).ok_or(UsbError::NoResources)? = Some(Pending { xfer, plan });
        Ok(slot)
    }

    fn poll(&mut self, slot: usize, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
        let p = self.mem.pending.get(slot)?.as_ref()?;
        if matches!(self.progress(&p.xfer, &p.plan), Progress::Running) {
            return None;
        }
        // Read the result again now its frame has passed (see `progress`).
        let quiet = self.disarm(p.plan.ed);
        let result = match self.progress(&p.xfer, &p.plan) {
            // A retired descriptor going back to running means the controller is not to be trusted.
            Progress::Running => Err(UsbError::Transaction),
            Progress::Done(bytes) => {
                let n = bytes.min(buf.len());
                if let Some(dst) = buf.get_mut(..n) {
                    p.xfer.buf.read(0, dst);
                }
                Ok(n)
            }
            Progress::Failed(e) => Err(e),
        };
        // If the controller may still be using the memory, leak it.
        if let Some(p) = self.mem.pending.get_mut(slot).and_then(Option::take)
            && !quiet
        {
            core::mem::forget(p);
        }
        Some(result)
    }

    fn cancel(&mut self, slot: usize) {
        // If the controller may still be using the memory, leak it.
        if let Some(p) = self.mem.pending.get_mut(slot).and_then(Option::take)
            && !self.disarm(p.plan.ed)
        {
            core::mem::forget(p);
        }
    }
}

impl<D: DmaAllocator + ?Sized> UsbHost for Ohci<'_, D> {
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

impl<D: DmaAllocator + ?Sized> Drop for Ohci<'_, D> {
    fn drop(&mut self) {
        // Put the controller in reset: it processes no lists and reads no
        // memory of ours. Then the memory can go.
        self.w32(CONTROL, 0);
        self.w32(HCCA, 0);
        usbhc::delay(self.clock, 2_000_000);
        // SAFETY: dropped once, here, and not used again.
        unsafe { ManuallyDrop::drop(&mut self.mem) };
    }
}

#[cfg(test)]
mod tests;
