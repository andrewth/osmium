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
//! Not yet supported: interrupts, isochronous endpoints, hubs (route
//! strings), streams, and SuperSpeed burst sizes from companion descriptors.

pub mod ring;
pub mod trb;

use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::usb::{
    DeviceId, Direction, EndpointDescriptor, PortStatus, SetupPacket, Speed, TransferType, UsbError, UsbHost,
};

use ring::{EventRing, ProducerRing};
use trb::{Trb, completion, kind};

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

const CMD_RUN: u32 = 1 << 0;
const CMD_RESET: u32 = 1 << 1;
const STS_HALTED: u32 = 1 << 0;
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

// Interrupter 0, in the runtime registers.
const IMAN: usize = 0x20;
const ERSTSZ: usize = 0x28;
const ERSTBA: usize = 0x30;
const ERDP: usize = 0x38;
const ERDP_BUSY: u32 = 1 << 3;

const EXT_CAP_LEGACY: u32 = 1;
const LEGACY_BIOS_OWNED: u32 = 1 << 16;
const LEGACY_OS_OWNED: u32 = 1 << 24;

/// Devices this driver handles at once (slot IDs 1..=MAX_SLOTS).
pub const MAX_SLOTS: u8 = 8;

/// Size of the transfer bounce buffer. Being 16 KiB and 16 KiB-aligned, it
/// never crosses the 64 KiB boundary a TRB buffer must not span.
pub const BOUNCE_LEN: usize = 16 * 1024;

/// How many times a register or the event ring is polled before giving up.
const POLL_LIMIT: u32 = 20_000_000;

/// Endpoint context types.
const EP_TYPE_CONTROL: u32 = 4;

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
}

/// One addressed device.
struct Slot<'d, D: DmaAllocator + ?Sized> {
    output: OwnedDma<'d, D>,
    input: OwnedDma<'d, D>,
    /// Transfer rings by DCI - 1 (endpoint 0 is DCI 1).
    rings: [Option<ProducerRing<'d, D>>; 31],
    speed: Speed,
}

/// An xHCI controller.
pub struct Xhci<'d, D: DmaAllocator + ?Sized> {
    io: IoMem,
    op: usize,
    rt: usize,
    db: usize,
    ctx_size: usize,
    max_ports: u8,
    dma: &'d D,
    dcbaa: OwnedDma<'d, D>,
    _scratchpad: Option<(OwnedDma<'d, D>, OwnedDma<'d, D>)>,
    commands: ProducerRing<'d, D>,
    events: EventRing<'d, D>,
    bounce: OwnedDma<'d, D>,
    slots: [Option<Slot<'d, D>>; MAX_SLOTS as usize],
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

impl<'d, D: DmaAllocator + ?Sized> Xhci<'d, D> {
    /// Takes the controller whose registers are `io` away from firmware,
    /// resets it, and starts it with DMA memory from `dma`. Ports are left
    /// as the reset found them; [`UsbHost::attach`] resets each one.
    pub fn new(io: IoMem, dma: &'d D) -> Result<Self, XhciError> {
        let r = |off: usize| io.read::<u32>(off).map_err(|_| XhciError::BadRegisters);
        let cap = r(CAPLENGTH_HCIVERSION)?;
        let op = (cap & 0xff) as usize;
        let params1 = r(HCSPARAMS1)?;
        let params2 = r(HCSPARAMS2)?;
        let hccparams1 = r(HCCPARAMS1)?;
        let db = (r(DBOFF)? & !3) as usize;
        let rt = (r(RTSOFF)? & !0x1f) as usize;
        let max_ports = (params1 >> 24) as u8;
        if op < 0x20 || cap >> 16 < 0x0090 || max_ports == 0 || io.len() < (op + PORTSC).max(rt + 0x40).max(db + 4) {
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
            dma,
            dcbaa,
            _scratchpad: scratchpad,
            commands: ProducerRing::new(dma).ok_or(no_mem)?,
            events: EventRing::new(dma).ok_or(no_mem)?,
            bounce: OwnedDma::new(dma, BOUNCE_LEN).ok_or(no_mem)?,
            slots: [const { None }; MAX_SLOTS as usize],
            io,
        };
        if scratchpads > 0 && hc.op_read(PAGESIZE) & 1 == 0 {
            return Err(XhciError::Unsupported);
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
        hc.poll(|hc| hc.op_read(USBSTS) & STS_HALTED == 0).map_err(|_| XhciError::Timeout)?;
        for port in 1..=hc.max_ports {
            let sc = hc.portsc(port);
            if sc & PORT_POWER == 0 {
                hc.set_portsc(port, (sc & PORT_PRESERVE) | PORT_POWER);
            }
        }
        Ok(hc)
    }

    fn r32(&self, off: usize) -> u32 {
        self.io.read(off).expect("xHCI register outside window")
    }

    fn w32(&self, off: usize, v: u32) {
        self.io.write(off, v).expect("xHCI register outside window")
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
        self.op_read(PORTSC + (port as usize - 1) * PORT_STRIDE)
    }

    fn set_portsc(&self, port: u8, v: u32) {
        self.op_write(PORTSC + (port as usize - 1) * PORT_STRIDE, v)
    }

    fn poll(&self, mut done: impl FnMut(&Self) -> bool) -> Result<(), UsbError> {
        for _ in 0..POLL_LIMIT {
            if done(self) {
                return Ok(());
            }
            osmium_arch::cpu::spin_hint();
        }
        Err(UsbError::Timeout)
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
                    let _ = self.poll(|hc| hc.r32(off) & LEGACY_BIOS_OWNED == 0);
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
        self.poll(|hc| hc.op_read(USBSTS) & STS_NOT_READY == 0).map_err(timeout)?;
        self.op_write(USBCMD, self.op_read(USBCMD) & !CMD_RUN);
        self.poll(|hc| hc.op_read(USBSTS) & STS_HALTED != 0).map_err(timeout)?;
        self.op_write(USBCMD, CMD_RESET);
        self.poll(|hc| hc.op_read(USBCMD) & CMD_RESET == 0 && hc.op_read(USBSTS) & STS_NOT_READY == 0).map_err(timeout)
    }

    /// Waits for the event that `matches`, discarding others (port status
    /// changes are read from `PORTSC` instead).
    fn wait_event(&mut self, matches: impl Fn(&Trb) -> bool) -> Result<Trb, UsbError> {
        for _ in 0..POLL_LIMIT {
            if let Some(ev) = self.events.pop() {
                self.write_erdp();
                if matches(&ev) {
                    return Ok(ev);
                }
            } else {
                osmium_arch::cpu::spin_hint();
            }
        }
        Err(UsbError::Timeout)
    }

    /// Runs a command and returns its completion event.
    fn command(&mut self, cmd: Trb) -> Result<Trb, UsbError> {
        let addr = self.commands.push(cmd).as_u64();
        self.ring_doorbell(0, 0);
        let ev = self.wait_event(|e| e.kind() == kind::COMMAND_COMPLETION && e.param == addr)?;
        match ev.completion_code() {
            completion::SUCCESS => Ok(ev),
            code => Err(error_from(code)),
        }
    }

    /// Checks the controller answers commands.
    pub fn no_op(&mut self) -> Result<(), UsbError> {
        self.command(Trb::no_op_command()).map(drop)
    }

    fn slot(&mut self, dev: DeviceId) -> Result<&mut Slot<'d, D>, UsbError> {
        let i = (dev.0 as usize).wrapping_sub(1);
        self.slots.get_mut(i).and_then(Option::as_mut).ok_or(UsbError::NoDevice)
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
            self.poll(|hc| hc.portsc(port) & PORT_RESET_CHANGE != 0)?;
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
    fn init_input(&self, input: &DmaBuffer, port: u8, speed: Speed, ep0: &ProducerRing<'d, D>) {
        let c = self.ctx_size;
        ctx_set(input, 0, 1, 0b11); // add slot and endpoint 0
        ctx_set(input, c, 0, speed_id(speed) << 20 | 1 << 27); // one context entry
        ctx_set(input, c, 1, (port as u32) << 16);
        let ep0_ctx = 2 * c;
        let mps = speed.default_max_packet0() as u32;
        ctx_set(input, ep0_ctx, 1, 3 << 1 | EP_TYPE_CONTROL << 3 | mps << 16);
        let deq = ep0.base().as_u64() | ep0.cycle() as u64;
        ctx_set(input, ep0_ctx, 2, deq as u32);
        ctx_set(input, ep0_ctx, 3, (deq >> 32) as u32);
        ctx_set(input, ep0_ctx, 4, 8); // average TRB length
    }

    /// Recovers a halted endpoint: Reset Endpoint, then move its dequeue
    /// pointer past the failed transfer.
    fn recover(&mut self, dev: DeviceId, dci: usize) {
        let (addr, cycle) = match self.slot(dev).ok().and_then(|s| s.rings[dci - 1].as_ref()) {
            Some(r) => (r.enqueue_addr().as_u64(), r.cycle()),
            None => return,
        };
        let _ = self.command(Trb::reset_endpoint(dev.0, dci as u8));
        let _ = self.command(Trb::set_tr_dequeue(dev.0, dci as u8, addr, cycle));
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
        let ring = self.slot(dev)?.rings[0].as_mut().ok_or(UsbError::BadEndpoint)?;
        ring.push(Trb::setup_stage(&setup));
        let data = (len > 0).then(|| ring.push(Trb::data_stage(bounce, len as u32, dir_in)).as_u64());
        let status = ring.push(Trb::status_stage(!(len > 0 && dir_in))).as_u64();
        self.ring_doorbell(dev.0, 1);

        let mut moved = len;
        loop {
            let ev =
                self.wait_event(|e| e.kind() == kind::TRANSFER_EVENT && e.slot_id() == dev.0 && e.endpoint_id() == 1)?;
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
                    self.recover(dev, 1);
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
        let ring = self.slot(dev)?.rings.get_mut(i - 1).and_then(Option::as_mut).ok_or(UsbError::BadEndpoint)?;
        let trb = ring.push(Trb::normal(bounce, len as u32)).as_u64();
        self.ring_doorbell(dev.0, i as u32);
        let ev = self.wait_event(|e| e.kind() == kind::TRANSFER_EVENT && e.param == trb)?;
        match ev.completion_code() {
            completion::SUCCESS | completion::SHORT_PACKET => Ok(len - (ev.residual() as usize).min(len)),
            code => {
                self.recover(dev, i);
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
        let slot_id = self.command(Trb::enable_slot())?.slot_id();
        let dev = DeviceId(slot_id);
        if slot_id == 0 || slot_id > MAX_SLOTS {
            let _ = self.command(Trb::disable_slot(slot_id));
            return Err(UsbError::NoResources);
        }

        let alloc = |len| OwnedDma::new(self.dma, len).ok_or(UsbError::NoResources);
        let (output, input) = match (alloc(32 * self.ctx_size), alloc(33 * self.ctx_size)) {
            (Ok(o), Ok(i)) => (o, i),
            _ => {
                let _ = self.command(Trb::disable_slot(slot_id));
                return Err(UsbError::NoResources);
            }
        };
        let Some(ep0) = ProducerRing::new(self.dma) else {
            let _ = self.command(Trb::disable_slot(slot_id));
            return Err(UsbError::NoResources);
        };
        self.init_input(&input, port, speed, &ep0);
        self.dcbaa.store(slot_id as usize * 8, output.device_addr().as_u64().to_le());
        let input_addr = input.device_addr().as_u64();
        let mut rings = [const { None }; 31];
        rings[0] = Some(ep0);
        self.slots[slot_id as usize - 1] = Some(Slot { output, input, rings, speed });

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

    fn detach(&mut self, dev: DeviceId) {
        if self.slot(dev).is_ok() {
            let _ = self.command(Trb::disable_slot(dev.0));
            self.dcbaa.store(dev.0 as usize * 8, 0u64);
            self.slots[dev.0 as usize - 1] = None;
        }
    }

    fn configure_endpoints(&mut self, dev: DeviceId, endpoints: &[EndpointDescriptor]) -> Result<(), UsbError> {
        let c = self.ctx_size;
        let dma = self.dma;
        let slot = self.slot(dev)?;
        let speed = slot.speed;
        let mut new_rings: [Option<ProducerRing<'_, D>>; 31] = [const { None }; 31];
        let mut add = 1u32; // the slot context
        let mut last = 1;
        for ep in endpoints {
            let i = dci(ep.address);
            if i < 2 || ep.transfer_type() == TransferType::Isochronous {
                return Err(UsbError::BadEndpoint);
            }
            let ring = ProducerRing::new(dma).ok_or(UsbError::NoResources)?;
            let ty = match (ep.transfer_type(), ep.direction()) {
                (TransferType::Bulk, Direction::Out) => 2,
                (TransferType::Interrupt, Direction::Out) => 3,
                (TransferType::Bulk, Direction::In) => 6,
                _ => 7,
            };
            let mps = ep.max_packet_size() as u32;
            let mult = ep.extra_transactions() as u32;
            let ctx = (i + 1) * c;
            for n in 0..8 {
                ctx_set(&slot.input, ctx, n, 0);
            }
            ctx_set(&slot.input, ctx, 0, interval(ep, speed) << 16);
            ctx_set(&slot.input, ctx, 1, 3 << 1 | ty << 3 | mult << 8 | mps << 16);
            let deq = ring.base().as_u64() | ring.cycle() as u64;
            ctx_set(&slot.input, ctx, 2, deq as u32);
            ctx_set(&slot.input, ctx, 3, (deq >> 32) as u32);
            let periodic = ep.transfer_type() == TransferType::Interrupt;
            let esit = if periodic { mps * (mult + 1) } else { 0 };
            let avg = if periodic { mps } else { 3072 };
            ctx_set(&slot.input, ctx, 4, (esit & 0xffff) << 16 | avg);
            new_rings[i - 1] = Some(ring);
            add |= 1 << i;
            last = last.max(i);
        }
        // The slot context is copied from the output context with the
        // context-entry count raised to cover the new endpoints.
        ctx_set(&slot.input, 0, 0, 0);
        ctx_set(&slot.input, 0, 1, add);
        for n in 0..4 {
            ctx_set(&slot.input, c, n, ctx_get(&slot.output, 0, n));
        }
        let entries = (ctx_get(&slot.output, 0, 0) >> 27).max(last as u32);
        let dw0 = ctx_get(&slot.input, c, 0);
        ctx_set(&slot.input, c, 0, (dw0 & !(0x1f << 27)) | entries << 27);
        let input = slot.input.device_addr().as_u64();

        self.command(Trb::configure_endpoint(dev.0, input))?;
        let slot = self.slot(dev)?;
        for (i, ring) in new_rings.into_iter().enumerate() {
            if ring.is_some() {
                slot.rings[i] = ring;
            }
        }
        Ok(())
    }

    fn control_in(&mut self, dev: DeviceId, setup: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError> {
        let len = (setup.length as usize).min(buf.len());
        let n = self.control(dev, SetupPacket { length: len as u16, ..setup })?;
        self.bounce.read(0, &mut buf[..n]);
        Ok(n)
    }

    fn control_out(&mut self, dev: DeviceId, setup: SetupPacket, data: &[u8]) -> Result<(), UsbError> {
        let len = (setup.length as usize).min(data.len());
        if len > BOUNCE_LEN {
            return Err(UsbError::NoResources);
        }
        self.bounce.write(0, &data[..len]);
        self.control(dev, SetupPacket { length: len as u16, ..setup }).map(drop)
    }

    fn transfer_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Result<usize, UsbError> {
        let mut done = 0;
        while done < buf.len() {
            let want = (buf.len() - done).min(BOUNCE_LEN);
            let n = self.transfer_chunk(dev, endpoint | 0x80, want)?;
            self.bounce.read(0, &mut buf[done..done + n]);
            done += n;
            if n < want {
                break; // a short packet ends the transfer
            }
        }
        Ok(done)
    }

    fn transfer_out(&mut self, dev: DeviceId, endpoint: u8, data: &[u8]) -> Result<(), UsbError> {
        for chunk in data.chunks(BOUNCE_LEN) {
            self.bounce.write(0, chunk);
            self.transfer_chunk(dev, endpoint & 0x7f, chunk.len())?;
        }
        Ok(())
    }
}

impl<D: DmaAllocator + ?Sized> Drop for Xhci<'_, D> {
    fn drop(&mut self) {
        // Stop the controller before the rings and contexts are freed.
        self.op_write(USBCMD, self.op_read(USBCMD) & !CMD_RUN);
        let _ = self.poll(|hc| hc.op_read(USBSTS) & STS_HALTED != 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // High speed: 2^(bInterval-1) microframes.
        assert_eq!(interval(&ep(3, 4), Speed::High), 3);
        assert_eq!(interval(&ep(2, 0), Speed::High), 0);
    }

    #[test]
    fn rejects_non_xhci_registers() {
        let mut regs = [0u32; 64];
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), 256) };
        let dma = crate::virtio::testing::HostDma::default();
        assert_eq!(Xhci::new(io, &dma).err(), Some(XhciError::BadRegisters));
        assert_eq!(dma.live.get(), 0);
    }
}
