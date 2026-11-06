// SPDX-License-Identifier: GPL-2.0-only
//! A scripted xHCI controller for the tests, playing the part that
//! `usbhc::fakedev` plays for UHCI, OHCI and EHCI.
//!
//! The registers are plain memory and the controller is a simulation that
//! [`crate::usbhc::sim`] runs whenever the driver waits. It reads the
//! command ring and executes the commands (slots, Address Device with
//! `SET_ADDRESS` on the bus, endpoint contexts from Configure Endpoint,
//! Reset/Stop Endpoint, Set TR Dequeue Pointer), walks every transfer ring
//! and turns its TRBs into transactions on [`fakedev::Device`]s and on
//! [`HubDev`]s (USB 2 hubs, which route to the devices on their ports by the
//! slot's route string), and writes completion and transfer events. Data
//! toggles, halts and NAKs behave as on a bus, so a TRB the device NAKs
//! stays queued. All memory is reached through [`LowDma`], so a controller
//! that touched freed memory would panic.
//!
//! Commands can be made to hang ([`Model::hang_commands`]) and Command
//! Abort to fail ([`Model::abort_fails`]), which is how a controller that
//! may still run a command the driver gave up on is played.

use core::cell::RefCell;
use std::boxed::Box;
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use osmium_hal::usb::{EndpointDescriptor, Speed, UsbError, UsbHost, enumerate, read_configuration, set_configuration};

use super::trb::flag;
use super::*;
use crate::class::hub::{Hub, PortEvent};
use crate::usbhc::fakedev::{self, Device, IN, LowDma, OUT, Reply, SETUP, r32 as mem32, rbytes, w32 as put32, wbytes};
use crate::usbhc::sim;

const OP: usize = 0x20;
const DB: usize = 0x480;
const RT: usize = 0x500;
const WINDOW: usize = 0x600;
/// Root ports.
pub const PORTS: usize = 2;
/// Context size (HCCPARAMS1.CSZ clear).
const CTX: u64 = 32;

/// The register window.
#[derive(Clone, Copy)]
struct Win(*mut u32);

impl Win {
    fn r(self, off: usize) -> u32 {
        // SAFETY: `off` is inside the window `Rig` allocated, which outlives the simulation.
        unsafe { self.0.add(off / 4).read_volatile() }
    }

    fn w(self, off: usize, v: u32) {
        // SAFETY: as for `r`.
        unsafe { self.0.add(off / 4).write_volatile(v) }
    }

    fn r64(self, off: usize) -> u64 {
        self.r(off) as u64 | (self.r(off + 4) as u64) << 32
    }
}

fn mem64(addr: u64) -> u64 {
    mem32(addr) as u64 | (mem32(addr + 4) as u64) << 32
}

fn read_trb(addr: u64) -> Trb {
    Trb { param: mem64(addr), status: mem32(addr + 8), control: mem32(addr + 12) }
}

/// Something on a port: a device or a hub.
#[derive(Clone)]
pub enum Node {
    /// A function.
    Dev(Rc<RefCell<Device>>),
    /// A USB 2 hub.
    Hub(Rc<RefCell<HubDev>>),
}

impl Node {
    fn transact(&self, address: u8, endpoint: u8, pid: u8, toggle: bool, data: &[u8], max: usize) -> Reply {
        match self {
            Node::Dev(d) => d.borrow_mut().transact(address, endpoint, pid, toggle, data, max),
            Node::Hub(h) => h.borrow_mut().transact(address, endpoint, pid, data, max),
        }
    }

    fn reset(&self) {
        match self {
            Node::Dev(d) => d.borrow_mut().reset(),
            Node::Hub(h) => h.borrow_mut().reset(),
        }
    }

    /// The node on enabled hub port `port`.
    fn child(&self, port: u8) -> Option<Node> {
        let Node::Hub(h) = self else { return None };
        let h = h.borrow();
        let p = h.ports.get((port as usize).checked_sub(1)?)?;
        if p.status & hub_bits::ENABLE == 0 {
            return None;
        }
        p.child.clone()
    }
}

/// `wPortStatus` / `wPortChange` bits of a USB 2 hub.
mod hub_bits {
    pub const CONNECTION: u16 = 1 << 0;
    pub const ENABLE: u16 = 1 << 1;
    pub const RESET: u16 = 1 << 4;
    pub const POWER: u16 = 1 << 8;
    pub const LOW_SPEED: u16 = 1 << 9;
    pub const HIGH_SPEED: u16 = 1 << 10;
}

/// A hub's device descriptor: class 9, 64-byte endpoint 0.
const HUB_DEVICE: [u8; 18] = [18, 1, 0x00, 0x02, 9, 0, 1, 64, 0x09, 0x04, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 1];

/// A single-TT hub with its status-change endpoint 0x81.
const HUB_CONFIG: [u8; 25] = [
    9, 2, 25, 0, 1, 1, 0, 0xe0, 0, //
    9, 4, 0, 0, 1, 9, 0, 1, 0, //
    7, 5, 0x81, 3, 1, 0, 12,
];

/// One downstream port of a [`HubDev`].
pub struct HubPort {
    /// What is plugged in.
    pub child: Option<Node>,
    /// Its speed.
    pub speed: Speed,
    /// `wPortStatus`.
    pub status: u16,
    /// `wPortChange`.
    pub change: u16,
}

#[derive(PartialEq, Eq)]
enum Stage {
    Idle,
    DataIn,
    StatusIn,
    StatusOut,
}

/// A USB 2 high-speed hub model: standard and hub class requests, the
/// status-change endpoint, and port power, reset and connect state.
pub struct HubDev {
    /// Current address.
    pub address: u8,
    new_address: Option<u8>,
    /// Selected configuration.
    pub configured: u8,
    /// The downstream ports, port 1 first.
    pub ports: Vec<HubPort>,
    /// Every setup packet received.
    pub requests: Vec<[u8; 8]>,
    stage: Stage,
    reply: Vec<u8>,
}

impl HubDev {
    /// A hub with `ports` empty ports.
    pub fn new(ports: usize) -> Self {
        let ports = (0..ports).map(|_| HubPort { child: None, speed: Speed::Full, status: 0, change: 0 }).collect();
        Self {
            address: 0,
            new_address: None,
            configured: 0,
            ports,
            requests: Vec::new(),
            stage: Stage::Idle,
            reply: Vec::new(),
        }
    }

    /// Plugs `node` into `port` (from 1).
    pub fn plug(&mut self, port: usize, node: Node, speed: Speed) {
        let p = &mut self.ports[port - 1];
        p.child = Some(node);
        p.speed = speed;
        if p.status & hub_bits::POWER != 0 {
            p.status |= hub_bits::CONNECTION;
            p.change |= hub_bits::CONNECTION;
        }
    }

    /// Unplugs whatever is on `port`.
    pub fn unplug(&mut self, port: usize) {
        let p = &mut self.ports[port - 1];
        p.child = None;
        p.status &= !(hub_bits::CONNECTION | hub_bits::ENABLE | hub_bits::LOW_SPEED | hub_bits::HIGH_SPEED);
        p.change |= hub_bits::CONNECTION;
    }

    fn reset(&mut self) {
        self.address = 0;
        self.new_address = None;
        self.configured = 0;
        self.stage = Stage::Idle;
    }

    fn transact(&mut self, address: u8, endpoint: u8, pid: u8, data: &[u8], max: usize) -> Reply {
        if address != self.address {
            return Reply::None;
        }
        match (endpoint, pid) {
            (0, SETUP) => self.setup(data),
            (0, IN) => match self.stage {
                Stage::DataIn => {
                    let n = self.reply.len().min(max).min(64);
                    let chunk: Vec<u8> = self.reply.drain(..n).collect();
                    if self.reply.is_empty() && n < 64 {
                        self.stage = Stage::StatusOut;
                    }
                    Reply::Ack(chunk)
                }
                Stage::StatusIn => {
                    self.stage = Stage::Idle;
                    if let Some(a) = self.new_address.take() {
                        self.address = a;
                    }
                    Reply::Ack(Vec::new())
                }
                _ => Reply::Stall,
            },
            (0, OUT) => match self.stage {
                Stage::StatusOut | Stage::DataIn => {
                    self.stage = Stage::Idle;
                    Reply::Ack(Vec::new())
                }
                _ => Reply::Stall,
            },
            (0x81, IN) if self.configured != 0 => {
                let bitmap =
                    self.ports.iter().enumerate().fold(0u8, |m, (i, p)| m | ((p.change != 0) as u8) << (i + 1));
                if bitmap == 0 { Reply::Nak } else { Reply::Ack(vec![bitmap]) }
            }
            _ => Reply::Stall,
        }
    }

    fn setup(&mut self, data: &[u8]) -> Reply {
        let Ok(setup) = <[u8; 8]>::try_from(data) else { return Reply::Stall };
        self.requests.push(setup);
        let [rt, req, vl, vh, il, _, ll, lh] = setup;
        let length = u16::from_le_bytes([ll, lh]) as usize;
        let feature = u16::from_le_bytes([vl, vh]);
        let port = (il as usize).checked_sub(1).filter(|&p| p < self.ports.len());
        let reply: Option<Vec<u8>> = match (rt, req) {
            (0x80, 6) if vh == 1 => Some(HUB_DEVICE.to_vec()),
            (0x80, 6) if vh == 2 => Some(HUB_CONFIG.to_vec()),
            (0xa0, 6) if vh == 0x29 => Some(vec![9, 0x29, self.ports.len() as u8, 0, 0, 50, 0, 0, 0xff]),
            (0xa0, 0) => Some(vec![0; 4]),
            (0xa3, 0) => {
                let Some(p) = port.map(|p| &self.ports[p]) else { return Reply::Stall };
                let [a, b] = p.status.to_le_bytes();
                let [c, d] = p.change.to_le_bytes();
                Some(vec![a, b, c, d])
            }
            (0x00, 5) => {
                self.new_address = Some(vl);
                None
            }
            (0x00, 9) => {
                self.configured = vl;
                None
            }
            (0x23, 3) => {
                let Some(p) = port.map(|p| &mut self.ports[p]) else { return Reply::Stall };
                match feature {
                    8 => {
                        p.status |= hub_bits::POWER;
                        if p.child.is_some() {
                            p.status |= hub_bits::CONNECTION;
                            p.change |= hub_bits::CONNECTION;
                        }
                    }
                    4 => {
                        if let Some(c) = &p.child {
                            c.reset();
                            let speed = match p.speed {
                                Speed::Low => hub_bits::LOW_SPEED,
                                Speed::High => hub_bits::HIGH_SPEED,
                                _ => 0,
                            };
                            p.status |= hub_bits::ENABLE | speed;
                            p.change |= hub_bits::RESET;
                        }
                    }
                    _ => {}
                }
                None
            }
            (0x23, 1) => {
                let Some(p) = port.map(|p| &mut self.ports[p]) else { return Reply::Stall };
                match feature {
                    1 => p.status &= !hub_bits::ENABLE,
                    16..=20 => p.change &= !(1 << (feature - 16)),
                    _ => {}
                }
                None
            }
            _ => {
                self.stage = Stage::Idle;
                return Reply::Stall;
            }
        };
        match reply {
            Some(mut r) => {
                r.truncate(length);
                self.reply = r;
                self.stage = Stage::DataIn;
            }
            None => self.stage = Stage::StatusIn,
        }
        Reply::Ack(Vec::new())
    }
}

/// A root port.
pub struct RootPort {
    /// What is plugged in.
    pub node: Option<Node>,
    /// Its speed.
    pub speed: Speed,
    enabled: bool,
    powered: bool,
    change: u32,
}

impl RootPort {
    fn portsc(&self) -> u32 {
        let connected = self.node.is_some();
        let mut v = self.change | if self.powered { PORT_POWER } else { 0 };
        if connected {
            v |= PORT_CONNECTED | speed_id(self.speed) << 10;
        }
        if connected && self.enabled {
            v |= PORT_ENABLED;
        }
        v
    }
}

/// An endpoint the controller has a context for.
#[derive(Clone, Copy, Default)]
struct Ep {
    deq: u64,
    ccs: bool,
    mps: u16,
    halted: bool,
    stopped: bool,
    /// Its dequeue pointer names a stream array: not walked.
    streams: bool,
    toggle: bool,
    /// Bytes of the current TRB already moved (before a NAK).
    progress: usize,
}

struct SlotState {
    node: Option<Node>,
    address: u8,
    eps: [Option<Ep>; 32],
}

enum Outcome {
    /// The device NAKed: the TRB stays queued.
    Nak,
    /// Completed with this code and residual.
    Done(u8, usize),
}

/// The simulated controller's state.
pub struct Model {
    win: Win,
    /// The root ports, port 1 first.
    pub ports: Vec<RootPort>,
    last_portsc: [u32; PORTS],
    running: bool,
    dcbaap: u64,
    cmd_deq: u64,
    cmd_ccs: bool,
    crr: bool,
    ev_base: u64,
    ev_size: u32,
    ev_idx: u32,
    ev_pcs: bool,
    slots: [Option<SlotState>; MAX_SLOTS as usize + 1],
    /// Commands stay on the ring unexecuted, so they time out.
    pub hang_commands: bool,
    /// Command Abort is ignored: the command ring never stops.
    pub abort_fails: bool,
    /// The type of every command executed, in order.
    pub commands: Vec<u32>,
}

impl Model {
    fn new(win: Win, ports: Vec<(Option<Node>, Speed)>) -> Self {
        let ports: Vec<RootPort> = ports
            .into_iter()
            .map(|(node, speed)| {
                let change = if node.is_some() { 1 << 17 } else { 0 };
                RootPort { node, speed, enabled: false, powered: true, change }
            })
            .collect();
        let mut last_portsc = [0; PORTS];
        for (i, p) in ports.iter().enumerate() {
            last_portsc[i] = p.portsc();
            win.w(OP + PORTSC + PORT_STRIDE * i, last_portsc[i]);
        }
        Self {
            win,
            ports,
            last_portsc,
            running: false,
            dcbaap: 0,
            cmd_deq: 0,
            cmd_ccs: true,
            crr: false,
            ev_base: 0,
            ev_size: 0,
            ev_idx: 0,
            ev_pcs: true,
            slots: [const { None }; MAX_SLOTS as usize + 1],
            hang_commands: false,
            abort_fails: false,
            commands: Vec::new(),
        }
    }

    /// One turn of the controller.
    fn step(&mut self) {
        let cmd = self.win.r(OP + USBCMD);
        if cmd & CMD_RESET != 0 {
            self.running = false;
            self.slots = [const { None }; MAX_SLOTS as usize + 1];
            self.win.w(OP + USBCMD, 0);
        }
        let run = cmd & CMD_RUN != 0 && cmd & CMD_RESET == 0;
        if run && !self.running {
            self.start();
        }
        self.running = run;
        self.win.w(OP + USBSTS, if run { 0 } else { STS_HALTED });
        self.ports_step();
        if !self.running {
            return;
        }
        let mfindex = self.win.r(RT + MFINDEX).wrapping_add(8) & 0x3fff;
        self.win.w(RT + MFINDEX, mfindex);
        self.abort_step();
        if !self.hang_commands {
            self.run_commands();
        } else if read_trb(self.cmd_deq).cycle() == self.cmd_ccs {
            self.crr = true;
        }
        self.doorbells();
        for slot in 1..=MAX_SLOTS as usize {
            for i in 1..32 {
                self.run_endpoint(slot, i);
            }
        }
        self.win.w(OP + CRCR, if self.crr { CRCR_CRR } else { 0 });
    }

    /// The controller starts running: it takes the pointers it was given.
    fn start(&mut self) {
        self.dcbaap = self.win.r64(OP + DCBAAP);
        let crcr = self.win.r64(OP + CRCR);
        self.cmd_deq = crcr & !0x3f;
        self.cmd_ccs = crcr & 1 != 0;
        self.crr = false;
        let erst = self.win.r64(RT + ERSTBA);
        self.ev_base = mem64(erst);
        self.ev_size = mem32(erst + 8);
        self.ev_idx = 0;
        self.ev_pcs = true;
        self.win.w(OP + CRCR, 0);
        self.win.w(OP + CRCR + 4, 0);
    }

    fn ports_step(&mut self) {
        for i in 0..PORTS {
            let off = OP + PORTSC + PORT_STRIDE * i;
            let written = self.win.r(off);
            let p = &mut self.ports[i];
            if written != self.last_portsc[i] {
                if written & PORT_POWER != 0 {
                    p.powered = true;
                }
                if written & PORT_RESET != 0
                    && let Some(n) = &p.node
                {
                    n.reset();
                    p.enabled = true;
                    p.change |= PORT_RESET_CHANGE;
                }
                p.change &= !(written & PORT_CHANGES);
            }
            // SuperSpeed ports enable themselves.
            if p.node.is_some() && matches!(p.speed, Speed::Super | Speed::SuperPlus) {
                p.enabled = true;
            }
            let v = p.portsc();
            self.win.w(off, v);
            self.last_portsc[i] = v;
        }
    }

    fn abort_step(&mut self) {
        if self.win.r(OP + CRCR) & CRCR_CA == 0 || self.abort_fails {
            return;
        }
        self.crr = false;
        let stopped = completion::COMMAND_RING_STOPPED as u32;
        self.event(Trb { param: self.cmd_deq, status: stopped << 24, control: kind::COMMAND_COMPLETION << 10 });
    }

    /// A doorbell restarts a stopped endpoint.
    fn doorbells(&mut self) {
        for slot in 1..=MAX_SLOTS as usize {
            let target = self.win.r(DB + 4 * slot) as usize & 0xff;
            if target == 0 {
                continue;
            }
            self.win.w(DB + 4 * slot, 0);
            if let Some(Some(ep)) = self.slots[slot].as_mut().and_then(|s| s.eps.get_mut(target)) {
                ep.stopped = false;
            }
        }
    }

    fn event(&mut self, trb: Trb) {
        let at = self.ev_base + 16 * self.ev_idx as u64;
        put32(at, trb.param as u32);
        put32(at + 4, (trb.param >> 32) as u32);
        put32(at + 8, trb.status);
        put32(at + 12, trb.control & !flag::CYCLE | self.ev_pcs as u32);
        self.ev_idx += 1;
        if self.ev_idx == self.ev_size {
            self.ev_idx = 0;
            self.ev_pcs = !self.ev_pcs;
        }
    }

    fn run_commands(&mut self) {
        loop {
            let t = read_trb(self.cmd_deq);
            if t.cycle() != self.cmd_ccs {
                return;
            }
            self.crr = true;
            let addr = self.cmd_deq;
            if t.kind() == kind::LINK {
                self.cmd_deq = t.param & !0xf;
                if t.control & flag::TOGGLE_CYCLE != 0 {
                    self.cmd_ccs = !self.cmd_ccs;
                }
                continue;
            }
            self.cmd_deq += 16;
            self.commands.push(t.kind());
            let (code, slot) = self.command(&t);
            let control = kind::COMMAND_COMPLETION << 10 | (slot as u32) << 24;
            self.event(Trb { param: addr, status: (code as u32) << 24, control });
        }
    }

    fn output(&self, slot: usize) -> u64 {
        mem64(self.dcbaap + 8 * slot as u64)
    }

    fn command(&mut self, t: &Trb) -> (u8, u8) {
        let slot = t.slot_id();
        let s = slot as usize;
        let i = t.endpoint_id() as usize;
        let exists = self.slots.get(s).is_some_and(Option::is_some);
        match t.kind() {
            kind::NO_OP_COMMAND => (completion::SUCCESS, 0),
            kind::ENABLE_SLOT => match (1..=MAX_SLOTS as usize).find(|&k| self.slots[k].is_none()) {
                Some(k) => {
                    self.slots[k] = Some(SlotState { node: None, address: 0, eps: [None; 32] });
                    (completion::SUCCESS, k as u8)
                }
                None => (completion::NO_SLOTS, 0),
            },
            _ if !exists => (completion::SLOT_NOT_ENABLED, slot),
            kind::DISABLE_SLOT => {
                self.slots[s] = None;
                (completion::SUCCESS, slot)
            }
            kind::ADDRESS_DEVICE => (self.address_device(s, t.param & !0xf), slot),
            kind::CONFIGURE_ENDPOINT => (self.configure(s, t.param & !0xf), slot),
            kind::EVALUATE_CONTEXT => {
                let input = t.param & !0xf;
                if mem32(input + 4) & 2 != 0
                    && let Some(Some(ep)) = self.slots[s].as_mut().map(|st| &mut st.eps[1])
                {
                    ep.mps = (mem32(input + 2 * CTX + 4) >> 16) as u16;
                }
                (completion::SUCCESS, slot)
            }
            kind::RESET_ENDPOINT | kind::STOP_ENDPOINT | kind::SET_TR_DEQUEUE => {
                let Some(Some(ep)) = self.slots[s].as_mut().and_then(|st| st.eps.get_mut(i)) else {
                    return (completion::ENDPOINT_NOT_ENABLED, slot);
                };
                let ok = match t.kind() {
                    // Halted to Stopped, with the toggle reset.
                    kind::RESET_ENDPOINT if ep.halted => {
                        ep.halted = false;
                        ep.stopped = true;
                        ep.toggle = false;
                        true
                    }
                    kind::STOP_ENDPOINT if !ep.halted => {
                        ep.stopped = true;
                        true
                    }
                    kind::SET_TR_DEQUEUE if ep.stopped || ep.halted => {
                        ep.deq = t.param & !0xf;
                        ep.ccs = t.param & 1 != 0;
                        ep.progress = 0;
                        true
                    }
                    _ => false,
                };
                (if ok { completion::SUCCESS } else { completion::CONTEXT_STATE }, slot)
            }
            _ => (completion::TRB, slot),
        }
    }

    /// The node at `route` below root port `root`.
    fn find(&self, root: u8, route: u32) -> Option<Node> {
        let mut node = self.ports.get((root as usize).checked_sub(1)?)?.node.clone()?;
        for tier in 0..5 {
            match route >> (4 * tier) & 0xf {
                0 => break,
                port => node = node.child(port as u8)?,
            }
        }
        Some(node)
    }

    fn address_device(&mut self, s: usize, input: u64) -> u8 {
        let (dw0, dw1) = (mem32(input + CTX), mem32(input + CTX + 4));
        let Some(node) = self.find((dw1 >> 16) as u8, dw0 & 0xf_ffff) else { return completion::USB_TRANSACTION };
        let setup = [0, 5, s as u8, 0, 0, 0, 0, 0];
        if node.transact(0, 0, SETUP, false, &setup, 0) != Reply::Ack(Vec::new())
            || node.transact(0, 0, IN, true, &[], 0) != Reply::Ack(Vec::new())
        {
            return completion::USB_TRANSACTION;
        }
        let ep0 = input + 2 * CTX;
        let deq = mem64(ep0 + 8);
        let out = self.output(s);
        for n in 0..8 {
            put32(out + 4 * n, mem32(input + CTX + 4 * n));
            put32(out + CTX + 4 * n, mem32(ep0 + 4 * n));
        }
        // Addressed, with the USB address the controller chose.
        put32(out + 12, 2 << 27 | s as u32);
        put32(out + CTX, mem32(ep0) & !7 | 1);
        let ep = Ep { deq: deq & !0xf, ccs: deq & 1 != 0, mps: (mem32(ep0 + 4) >> 16) as u16, ..Ep::default() };
        if let Some(st) = self.slots[s].as_mut() {
            st.node = Some(node);
            st.address = s as u8;
            st.eps[1] = Some(ep);
        }
        completion::SUCCESS
    }

    fn configure(&mut self, s: usize, input: u64) -> u8 {
        let (drop, add) = (mem32(input), mem32(input + 4));
        let out = self.output(s);
        let Some(st) = self.slots[s].as_mut().filter(|st| st.node.is_some()) else { return completion::CONTEXT_STATE };
        for (i, ep) in st.eps.iter_mut().enumerate().skip(2) {
            if drop & 1 << i != 0 {
                *ep = None;
            }
        }
        for i in 2..32u64 {
            if add & 1 << i == 0 {
                continue;
            }
            let ctx = input + (i + 1) * CTX;
            let deq = mem64(ctx + 8);
            st.eps[i as usize] = Some(Ep {
                deq: deq & !0xf,
                ccs: deq & 1 != 0,
                mps: (mem32(ctx + 4) >> 16) as u16,
                streams: mem32(ctx) >> 10 & 0x1f != 0,
                ..Ep::default()
            });
            for n in 0..8 {
                put32(out + i * CTX + 4 * n, mem32(ctx + 4 * n));
            }
            put32(out + i * CTX, mem32(ctx) & !7 | 1);
        }
        if add & 1 != 0 {
            for n in 0..3 {
                put32(out + 4 * n, mem32(input + CTX + 4 * n));
            }
        }
        completion::SUCCESS
    }

    fn run_endpoint(&mut self, s: usize, i: usize) {
        loop {
            let Some(st) = self.slots[s].as_ref() else { return };
            let (Some(node), Some(mut ep)) = (st.node.clone(), st.eps[i]) else { return };
            let address = st.address;
            if ep.halted || ep.stopped || ep.streams {
                return;
            }
            let t = read_trb(ep.deq);
            if t.cycle() != ep.ccs {
                return;
            }
            if t.kind() == kind::LINK {
                ep.deq = t.param & !0xf;
                if t.control & flag::TOGGLE_CYCLE != 0 {
                    ep.ccs = !ep.ccs;
                }
                self.put_ep(s, i, ep);
                continue;
            }
            let outcome = transfer(&node, address, i, &mut ep, &t);
            let Outcome::Done(code, residual) = outcome else {
                self.put_ep(s, i, ep);
                return;
            };
            let at = ep.deq;
            ep.deq += 16;
            ep.progress = 0;
            let failed = !matches!(code, completion::SUCCESS | completion::SHORT_PACKET);
            ep.halted = failed;
            self.put_ep(s, i, ep);
            let short = code == completion::SHORT_PACKET && t.control & flag::ISP != 0;
            if failed || short || t.control & flag::IOC != 0 {
                let control = kind::TRANSFER_EVENT << 10 | (i as u32) << 16 | (s as u32) << 24;
                self.event(Trb { param: at, status: (code as u32) << 24 | residual as u32, control });
            }
        }
    }

    fn put_ep(&mut self, s: usize, i: usize, ep: Ep) {
        if let Some(st) = self.slots[s].as_mut() {
            st.eps[i] = Some(ep);
        }
    }

    /// Endpoint `i` of slot `s` exists on the controller's side.
    fn has_endpoint(&self, s: u8, i: usize) -> bool {
        self.slots.get(s as usize).and_then(Option::as_ref).is_some_and(|st| st.eps[i].is_some())
    }
}

/// Runs one transfer TRB on the bus.
fn transfer(node: &Node, address: u8, i: usize, ep: &mut Ep, t: &Trb) -> Outcome {
    let failed = |r: &Reply| match r {
        Reply::Nak => Outcome::Nak,
        Reply::Stall => Outcome::Done(completion::STALL, 0),
        _ => Outcome::Done(completion::USB_TRANSACTION, 0),
    };
    match t.kind() {
        kind::SETUP_STAGE => {
            ep.toggle = false;
            match node.transact(address, 0, SETUP, false, &t.param.to_le_bytes(), 0) {
                Reply::Ack(_) => {
                    ep.toggle = true;
                    Outcome::Done(completion::SUCCESS, 0)
                }
                r => failed(&r),
            }
        }
        kind::STATUS_STAGE => {
            let r = if t.control & flag::DIR_IN != 0 {
                node.transact(address, 0, IN, true, &[], 0)
            } else {
                node.transact(address, 0, OUT, true, &[], 0)
            };
            match r {
                Reply::Ack(_) => Outcome::Done(completion::SUCCESS, 0),
                r => failed(&r),
            }
        }
        kind::DATA_STAGE | kind::NORMAL => {
            let len = (t.status & 0x1_ffff) as usize;
            let dir_in = if t.kind() == kind::DATA_STAGE { t.control & flag::DIR_IN != 0 } else { i % 2 == 1 };
            let endpoint = if i == 1 { 0 } else { (i / 2) as u8 | if dir_in { 0x80 } else { 0 } };
            let mps = ep.mps.max(1) as usize;
            loop {
                let done = ep.progress;
                let want = (len - done).min(mps);
                let r = if dir_in {
                    node.transact(address, endpoint, IN, ep.toggle, &[], want)
                } else {
                    node.transact(address, endpoint, OUT, ep.toggle, &rbytes(t.param + done as u64, want), 0)
                };
                let Reply::Ack(data) = r else {
                    let out = failed(&r);
                    return match out {
                        Outcome::Done(code, _) => Outcome::Done(code, len - done),
                        nak => nak,
                    };
                };
                ep.toggle = !ep.toggle;
                let n = if dir_in { data.len().min(want) } else { want };
                if dir_in && n > 0 {
                    wbytes(t.param + done as u64, &data[..n]);
                }
                ep.progress += n;
                if ep.progress >= len || (dir_in && n < mps) {
                    let residual = len - ep.progress;
                    let code = if residual > 0 { completion::SHORT_PACKET } else { completion::SUCCESS };
                    return Outcome::Done(code, residual);
                }
            }
        }
        _ => Outcome::Done(completion::TRB, 0),
    }
}

/// A controller with `ports` behind its root ports, its registers and the
/// simulation that plays it.
pub struct Rig {
    regs: *mut [u32],
    /// The controller's state, for the test to inspect and script.
    pub model: Rc<RefCell<Model>>,
}

impl Rig {
    /// Builds the registers and installs the simulation for this thread.
    pub fn new(ports: Vec<(Option<Node>, Speed)>) -> Self {
        assert_eq!(ports.len(), PORTS);
        let regs = Box::into_raw(vec![0u32; WINDOW / 4].into_boxed_slice());
        let win = Win(regs.cast());
        win.w(CAPLENGTH_HCIVERSION, 0x0100_0000 | OP as u32);
        win.w(HCSPARAMS1, MAX_SLOTS as u32 | 1 << 8 | (PORTS as u32) << 24);
        win.w(HCCPARAMS1, HCC_AC64);
        win.w(DBOFF, DB as u32);
        win.w(RTSOFF, RT as u32);
        win.w(OP + USBSTS, STS_HALTED);
        let model = Rc::new(RefCell::new(Model::new(win, ports)));
        let m = model.clone();
        sim::install(move || m.borrow_mut().step());
        Self { regs, model }
    }

    /// A rig with `dev` on root port 1 at full speed and nothing on port 2.
    pub fn with_device(dev: &Rc<RefCell<Device>>) -> Self {
        Self::new(vec![(Some(Node::Dev(dev.clone())), Speed::Full), (None, Speed::Full)])
    }

    /// Starts the driver on the rig's registers.
    pub fn controller<'d>(&self, dma: &'d LowDma) -> Xhci<'d, LowDma> {
        // SAFETY: the window is the rig's allocation, which outlives the
        // controller (the tests declare the rig first).
        let io = unsafe { IoMem::new(self.regs.cast(), WINDOW) };
        Xhci::new(io, dma).expect("the controller starts")
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        sim::remove();
        // SAFETY: allocated by `Box::into_raw` in `new` and not freed since.
        drop(unsafe { Box::from_raw(self.regs) });
    }
}

#[test]
fn enumerates_and_moves_data() {
    let dev = Rc::new(RefCell::new(Device::new()));
    let rig = Rig::with_device(&dev);
    let dma = LowDma::default();
    let mut hc = rig.controller(&dma);
    let baseline = dma.live.get();
    assert!(hc.port_status(1).connected && !hc.port_status(2).connected);

    let mut config = [0u8; 256];
    let found = enumerate(&mut hc, 1, &mut config).expect("enumerate");
    assert_eq!(&config[..found.config_len], &fakedev::CONFIG);
    assert_eq!(dev.borrow().address, found.id.0, "the device took the address the controller chose");
    assert_eq!(dev.borrow().configured, 1);
    let commands = rig.model.borrow().commands.clone();
    // Full speed starts with 8-byte packets on endpoint 0: the real size takes an Evaluate Context.
    assert_eq!(commands, [kind::ENABLE_SLOT, kind::ADDRESS_DEVICE, kind::EVALUATE_CONTEXT, kind::CONFIGURE_ENDPOINT]);
    // Bulk IN 0x81, bulk OUT 0x02 and interrupt IN 0x83, in their contexts.
    for i in [3, 4, 7] {
        assert!(rig.model.borrow().has_endpoint(found.id.0, i), "endpoint context {i}");
    }

    fakedev::exercise_device(&mut hc, &dev, found.id);
    // The stall was recovered by Reset Endpoint and Set TR Dequeue Pointer.
    let commands = rig.model.borrow().commands.clone();
    assert!(commands.windows(2).any(|w| w == [kind::RESET_ENDPOINT, kind::SET_TR_DEQUEUE]));

    hc.detach(found.id);
    assert_eq!(rig.model.borrow().commands.last(), Some(&kind::DISABLE_SLOT));
    assert_eq!(hc.transfer_out(found.id, 0x02, &[1]), Err(UsbError::NoDevice));
    assert_eq!(dma.live.get(), baseline, "the slot's memory is freed");
    drop(hc);
    assert_eq!(dma.live.get(), 0, "and the controller's once it has halted");
}

#[test]
fn zero_length_packets_keep_the_toggles() {
    let dev = Rc::new(RefCell::new(Device::new()));
    let rig = Rig::with_device(&dev);
    let dma = LowDma::default();
    let mut hc = rig.controller(&dma);
    fakedev::zlp_terminated_in(&mut hc, &dev, 1);
}

#[test]
fn a_device_behind_a_hub_is_routed_and_released() {
    let dev = Rc::new(RefCell::new(Device::new()));
    let hub_dev = Rc::new(RefCell::new(HubDev::new(2)));
    hub_dev.borrow_mut().plug(2, Node::Dev(dev.clone()), Speed::Full);
    let rig = Rig::new(vec![(Some(Node::Hub(hub_dev.clone())), Speed::High), (None, Speed::Full)]);
    let dma = LowDma::default();
    let mut hc = rig.controller(&dma);

    let mut config = [0u8; 256];
    let found = enumerate(&mut hc, 1, &mut config).expect("enumerate the hub");
    let hub_id = found.id;
    let mut hub = Hub::new(&mut hc, hub_id, &config[..found.config_len], None).expect("hub driver");
    assert_eq!(hub.num_ports(), 2);
    hub.power_ports().unwrap();
    hub.scan();
    let Ok(Some(PortEvent::Connected { port: 2, device: child, speed: Speed::Full })) = hub.poll_events() else {
        panic!("the device on port 2 is found");
    };
    assert_eq!(hub.poll_events(), Ok(None));
    assert_eq!(dev.borrow().address, child.0);

    // The slot context names the route, the root port and the hub's TT.
    {
        let hc = hub.host();
        let slot = hc.slot(child).unwrap();
        assert_eq!(ctx_get(&slot.output, 0, 0) & 0xf_ffff, 2, "route string");
        assert_eq!(ctx_get(&slot.output, 0, 1) >> 16 & 0xff, 1, "root port");
        assert_eq!(ctx_get(&slot.output, 0, 2) & 0xffff, hub_id.0 as u32 | 2 << 8, "TT hub slot and port");
        let hub_slot = hc.slot(hub_id).unwrap();
        assert_ne!(ctx_get(&hub_slot.output, 0, 0) & 1 << 26, 0, "the hub's slot is marked as a hub");
        assert_eq!(ctx_get(&hub_slot.output, 0, 1) >> 24, 2, "with its port count");
    }

    let mut cfg = [0u8; 256];
    let n = read_configuration(hub.host(), child, 0, &mut cfg).unwrap();
    set_configuration(hub.host(), child, &cfg[..n]).unwrap();
    fakedev::exercise_device(hub.host(), &dev, child);

    // Unplugged: the status-change endpoint reports it and the slot goes.
    hub_dev.borrow_mut().unplug(2);
    let event = (0..100).find_map(|_| {
        sim::run();
        hub.poll_events().unwrap()
    });
    assert_eq!(event, Some(PortEvent::Disconnected { port: 2, device: Some(child) }));
    assert_eq!(hub.host().transfer_out(child, 0x02, &[1]), Err(UsbError::NoDevice));
    assert!(!rig.model.borrow().has_endpoint(child.0, 1), "the controller disabled the slot");

    // Plugged in again, it comes back.
    hub_dev.borrow_mut().plug(2, Node::Dev(dev.clone()), Speed::Full);
    let event = (0..100).find_map(|_| {
        sim::run();
        hub.poll_events().unwrap()
    });
    let Some(PortEvent::Connected { port: 2, device: again, .. }) = event else { panic!("reconnected: {event:?}") };

    // Detaching the hub takes its child with it.
    let hc = hub.into_host();
    hc.detach(hub_id);
    assert_eq!(hc.transfer_out(again, 0x02, &[1]), Err(UsbError::NoDevice));
    assert!(!rig.model.borrow().has_endpoint(again.0, 1) && !rig.model.borrow().has_endpoint(hub_id.0, 1));
}

/// A Configure Endpoint that times out, on a controller whose command ring
/// will not stop, may still run later and point the endpoints at the rings
/// built for it: they must not be freed.
#[test]
fn a_stuck_configure_endpoint_keeps_its_rings() {
    let dev = Rc::new(RefCell::new(Device::new()));
    let rig = Rig::with_device(&dev);
    let dma = LowDma::default();
    let mut hc = rig.controller(&dma);
    let mut config = [0u8; 256];
    let id = enumerate(&mut hc, 1, &mut config).expect("enumerate").id;

    {
        let mut m = rig.model.borrow_mut();
        m.hang_commands = true;
        m.abort_fails = true;
    }
    let live = dma.live.get();
    let bulk_in = EndpointDescriptor { address: 0x81, attributes: 2, max_packet_size_raw: 64, interval: 0 };
    assert_eq!(hc.configure_endpoints(id, &[bulk_in]), Err(UsbError::Timeout));
    assert!(hc.commands_stuck);
    assert_eq!(dma.live.get(), live + 1, "the new ring is kept");
    assert_eq!(hc.transfer_out(id, 0x02, &[1]), Err(UsbError::NoDevice), "the slot takes no more transfers");
    assert_eq!(hc.no_op(), Err(UsbError::Controller));

    // The controller gets round to the command after all, and walks the
    // ring it was given (a freed one would panic here).
    rig.model.borrow_mut().hang_commands = false;
    sim::run();
    assert_eq!(rig.model.borrow().commands.last(), Some(&kind::CONFIGURE_ENDPOINT));
    assert!(rig.model.borrow().has_endpoint(id.0, 3));
    sim::run();
}
