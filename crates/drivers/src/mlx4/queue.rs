//! What the ports are built on: a completion queue and one queue pair, with
//! their rings and buffers. A port owns one such set per queue pair it uses.
//!
//! The queue pair's send queue holds [`SQ_ENTRIES`] 128-byte entries, of
//! which at most [`TX_SLOTS`] are in flight: the device prefetches up to
//! 2 KiB past the last posted entry, so the rest stay unused headroom
//! (iPXE's arrangement). Each receive entry permanently points at its own
//! buffer slot, so reposting is just advancing the doorbell record. Both
//! directions complete into the set's own completion queue, sized so it
//! cannot overflow; receive completions found while reaping transmit ones
//! are queued in software until the port asks for them.
//!
//! With MSI-X enabled on the adapter the completion queue is created
//! disarmed and armed by doorbell whenever the port has reaped everything;
//! the completion event queue's interrupt then disarms it until the next
//! reap. Without MSI-X it is "fired" and only polled.
//!
//! What differs between the queue pair types is its service type and the
//! parameters of its transitions ([`QpSetup`]) and the send entries a port
//! builds; the rest lives here.
//!
//! Resource numbers follow from the set: a port's sets have consecutive
//! completion queues and MTT ranges ([`Queues::index`]); ordinary queue
//! pair numbers follow the special ones, and queue pairs 0 and 1 take the
//! special numbers.

use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};

use super::cmd::{Ctx, Input, op};
use super::{EQ_MTTS, MAX_PORTS, Mlx4, Mlx4Error, PAGE, PD, PORT_MTTS, UAR_PAGE, get32, log2_ceil, put32};

/// Send queue entries (a power of two).
pub const SQ_ENTRIES: u32 = 32;
pub(super) const SQ_STRIDE: usize = 128;
/// Receive queue entries and buffer slots (a power of two).
pub const RX_SLOTS: u32 = 16;
const RQ_STRIDE: usize = 32;
/// Transmit buffer slots: frames in flight at once.
pub const TX_SLOTS: u32 = 8;
const CQ_ENTRIES: u32 = 32;
const CQE_LEN: usize = 32;

/// Send entry opcode for an ordinary send.
pub(super) const OPCODE_SEND: u32 = 0x0a;
/// Send control flags: completion on every entry, solicited.
pub(super) const CTRL_COMPLETE: u32 = 3 << 2 | 1 << 1;
/// Bytes of a control or data segment.
pub(super) const SEG_LEN: usize = 16;

/// The set of a port's data queue pair: the Ethernet queue pair, or the
/// InfiniBand datagram queue pair.
pub(super) const SET_DATA: u8 = 0;
/// Queue pair 0 (subnet management) and 1 (general services).
pub(super) const SET_QP0: u8 = 1;
pub(super) const SET_QP1: u8 = 2;
/// The first of [`RC_QPS`] sets for reliable connections.
pub(super) const SET_RC: u8 = 3;
/// Reliable connections one port can have open.
pub const RC_QPS: u8 = 4;
/// Queue pair sets per port.
pub(super) const SETS_PER_PORT: u8 = SET_RC + RC_QPS;

/// Completion queue arm request: any completion.
const CQ_DB_REQ_NOT: u32 = 2 << 24;
/// Completion queue arm doorbell, in [`UAR_PAGE`].
const CQ_DOORBELL: usize = 0x20;

// Completion status bits (the CQE's big-endian 16-bit status word).
const STATUS_TCP: u16 = 1 << 10;
const STATUS_UDP: u16 = 1 << 11;
const STATUS_IPOK: u16 = 1 << 12;
/// The CQE checksum word when the device summed the whole TCP/UDP segment
/// correctly.
const CSUM_OK: u16 = 0xffff;
const CQE_OPCODE_ERROR: u32 = 0x1e;
/// A receive entry's terminating scatter entry.
const INVALID_LKEY: u32 = 0x100;
/// Send doorbell, in [`UAR_PAGE`].
const SEND_DOORBELL: usize = 0x14;

// Compile-time checks of the ring arithmetic.
const _: () = assert!(SQ_ENTRIES.is_power_of_two() && RX_SLOTS.is_power_of_two() && CQ_ENTRIES.is_power_of_two());
const _: () = assert!(TX_SLOTS < SQ_ENTRIES - (2048 / SQ_STRIDE) as u32);
const _: () = assert!(TX_SLOTS + RX_SLOTS <= CQ_ENTRIES);
const _: () = assert!(CQ_ENTRIES as usize * CQE_LEN <= PAGE);
const _: () =
    assert!((SQ_ENTRIES as usize * SQ_STRIDE + RX_SLOTS as usize * RQ_STRIDE).div_ceil(PAGE) < PORT_MTTS as usize);

/// Optional-parameter bits of the queue pair transition commands.
#[allow(dead_code)] // the reliable connection ones are used once those exist
pub(super) mod optpar {
    pub const RRE: u32 = 1 << 1;
    pub const RAE: u32 = 1 << 2;
    pub const RWE: u32 = 1 << 3;
    pub const PKEY_INDEX: u32 = 1 << 4;
    pub const Q_KEY: u32 = 1 << 5;
    pub const RNR_TIMEOUT: u32 = 1 << 6;
    pub const PRIMARY_ADDR_PATH: u32 = 1 << 7;
    pub const SRA_MAX: u32 = 1 << 8;
    pub const RRA_MAX: u32 = 1 << 9;
    pub const RETRY_COUNT: u32 = 1 << 12;
    pub const RNR_RETRY: u32 = 1 << 13;
    pub const ACK_TIMEOUT: u32 = 1 << 14;
    pub const SCHED_QUEUE: u32 = 1 << 16;
}

pub(super) struct Memory<'d, D: DmaAllocator + ?Sized> {
    cq: OwnedDma<'d, D>,
    /// Send queue, then receive queue.
    wq: OwnedDma<'d, D>,
    /// Completion queue doorbell record at 0, receive queue's at 64.
    doorbells: OwnedDma<'d, D>,
    pub rx: OwnedDma<'d, D>,
    pub tx: OwnedDma<'d, D>,
    /// Staging for segmentation frames; present if the port asked for it.
    pub lso: Option<OwnedDma<'d, D>>,
}

/// A received packet reaped from the completion queue but not yet taken.
#[derive(Clone, Copy, Default)]
pub(super) struct Received {
    pub slot: u16,
    /// Bytes the device wrote to the slot.
    pub len: u16,
    pub error: bool,
    pub checksum: bool,
    /// Datagram queue pairs: the sender's queue pair number, LID and
    /// service level, the destination LID's low bits, the partition key
    /// index, and whether a global route header came with it.
    pub src_qpn: u32,
    pub src_lid: u16,
    pub sl: u8,
    pub src_path_bits: u8,
    pub pkey_index: u8,
    pub grh: bool,
}

/// How far opening got, so closing undoes exactly that.
#[derive(Default)]
pub(super) struct Stage {
    cq_hw: bool,
    qp_hw: bool,
    pub port_up: bool,
}

/// Buffer sizes of a set.
#[derive(Clone, Copy)]
pub(super) struct Geometry {
    /// Bytes per receive slot.
    pub rx_slot: usize,
    /// Bytes per transmit slot.
    pub tx_slot: usize,
    /// Bytes of segmentation staging, 0 for none.
    pub lso: usize,
}

/// The parts of a queue pair's transitions that depend on its type. Each
/// closure edits the mailbox context of one transition on top of what every
/// transition carries.
pub(super) struct QpSetup<'f> {
    /// The context's service type: 0 reliable connection, 3 unreliable
    /// datagram, 7 raw Ethernet or "MLX" (the special queue pairs).
    pub service: u32,
    /// The context's MTU (high 3 bits) and maximum message size (low 5, as
    /// a power of two).
    pub mtu_msgmax: u32,
    /// Optional-parameter masks of the three transitions ([`optpar`]).
    pub init_optpar: u32,
    pub rtr_optpar: u32,
    pub rts_optpar: u32,
    pub init: &'f dyn Fn(&mut Ctx),
    pub rtr: &'f dyn Fn(&mut Ctx),
    pub rts: &'f dyn Fn(&mut Ctx),
}

pub(super) struct Queues<'h, 'd, D: DmaAllocator + ?Sized> {
    pub hca: &'h Mlx4<'d, D>,
    pub port: u8,
    pub qpn: u32,
    cqn: u32,
    set: u8,
    pub mem: ManuallyDrop<Memory<'d, D>>,
    pub stage: Stage,
    rx_slot: usize,
    tx_slot: usize,
    /// Completion queue consumer index.
    cq_ci: u32,
    /// Send entries posted and completed.
    pub tx_head: u32,
    pub tx_done: u32,
    /// Receive entries handed to the device.
    rx_posted: u32,
    /// Packets reaped from the completion queue but not yet taken,
    /// `rx_ready_count` of them from `rx_ready_head`.
    rx_ready: [Received; RX_SLOTS as usize],
    rx_ready_head: usize,
    pub rx_ready_count: usize,
    /// The arm count the completion queue was last armed with (MSI-X only).
    armed_sn: Option<u8>,
}

impl<'h, 'd, D: DmaAllocator + ?Sized> Queues<'h, 'd, D> {
    /// Allocates the rings and buffers of set `set` of `port` (1-based).
    /// Nothing is created in the device yet, and the port is not claimed.
    pub fn new(hca: &'h Mlx4<'d, D>, port: u8, set: u8, geometry: Geometry) -> Result<Self, Mlx4Error> {
        let Geometry { rx_slot, tx_slot, lso } = geometry;
        let alloc = |len: usize| OwnedDma::new(hca.dma, len).ok_or(Mlx4Error::NoMemory);
        let sq_len = SQ_ENTRIES as usize * SQ_STRIDE;
        let mem = Memory {
            cq: alloc(CQ_ENTRIES as usize * CQE_LEN)?,
            wq: alloc(sq_len + RX_SLOTS as usize * RQ_STRIDE)?,
            doorbells: alloc(128)?,
            rx: alloc(RX_SLOTS as usize * rx_slot)?,
            tx: alloc(TX_SLOTS as usize * tx_slot)?,
            lso: if lso > 0 { Some(alloc(lso)?) } else { None },
        };
        let port_index = (port - 1) as u32;
        let qpn = match set {
            SET_QP0 => hca.special_qpn() + port_index,
            SET_QP1 => hca.special_qpn() + 2 + port_index,
            SET_DATA => hca.qpn_base + port_index,
            rc => hca.qpn_base + (rc - SET_RC + 1) as u32 * MAX_PORTS as u32 + port_index,
        };
        let mut q = Self {
            hca,
            port,
            qpn,
            cqn: 0,
            set,
            mem: ManuallyDrop::new(mem),
            stage: Stage::default(),
            rx_slot,
            tx_slot,
            cq_ci: 0,
            tx_head: 0,
            tx_done: 0,
            rx_posted: 0,
            rx_ready: [Received::default(); RX_SLOTS as usize],
            rx_ready_head: 0,
            rx_ready_count: 0,
            armed_sn: None,
        };
        q.cqn = hca.caps.reserved_cqs + q.index() as u32;
        Ok(q)
    }

    /// The set's number among all the adapter's: consecutive for a port's
    /// sets, interleaved between the ports.
    pub fn index(&self) -> usize {
        self.set as usize * MAX_PORTS as usize + (self.port as usize - 1)
    }

    /// MTT entry of the completion queue; the queue pair's follows.
    pub fn cq_mtt(&self) -> u32 {
        EQ_MTTS + PORT_MTTS * self.index() as u32
    }

    /// Asks for an event on the next completion, if the adapter uses MSI-X.
    pub fn arm_cq(&mut self) {
        if self.hca.comp_eqn.is_none() {
            return;
        }
        let sn = self.hca.arm_sn[self.index()].get();
        let (word, ci) = ((sn as u32 & 3) << 28 | CQ_DB_REQ_NOT, self.cq_ci & 0xff_ffff);
        // The record first, then the doorbell that makes the device read it.
        put32(&self.mem.doorbells, 4, word | ci);
        // The doorbell is an MMIO write: only a full barrier orders the record before it.
        osmium_arch::barrier::mb();
        let doorbell = ((word | self.cqn) as u64) << 32 | ci as u64;
        let _ = self.hca.uar.write(UAR_PAGE as usize * PAGE + CQ_DOORBELL, doorbell.to_be());
        self.armed_sn = Some(sn);
    }

    /// Re-arms the completion queue if an event disarmed it.
    pub fn rearm_if_fired(&mut self) {
        if self.hca.comp_eqn.is_some() && self.armed_sn != Some(self.hca.arm_sn[self.index()].get()) {
            self.arm_cq();
        }
    }

    pub fn create_cq(&mut self) -> Result<(), Mlx4Error> {
        let mtt = self.cq_mtt();
        let cq = &self.mem.cq;
        for i in 0..CQ_ENTRIES as usize {
            put32(cq, i * CQE_LEN + 28, 0x80); // owned by hardware
        }
        self.hca.write_mtt(mtt, cq)?;
        let mut cqc = Ctx::new();
        // Polled: "fired", so it never raises an event. With MSI-X the
        // state stays 0 until the arm doorbell.
        if self.hca.comp_eqn.is_none() {
            cqc.set(0, 8, 4, 0xa);
        }
        cqc.set(3, 0, 24, UAR_PAGE).set(3, 24, 5, log2_ceil(CQ_ENTRIES));
        cqc.set(5, 0, 9, self.hca.comp_eqn.unwrap_or(self.hca.caps.eqn()));
        cqc.set_addr(6, self.hca.mtt_addr(mtt));
        cqc.set_addr(14, self.mem.doorbells.device_addr().as_u64());
        self.hca.hcr.exec(op::SW2HW_CQ, 0, self.cqn, Input::Mailbox(&cqc, 64))?;
        self.stage.cq_hw = true;
        Ok(())
    }

    /// The context every transition carries, as `mlx4_ib` fills it: the
    /// state being entered, the service type, the queues' geometry and
    /// completion queues.
    fn context(&self, setup: &QpSetup<'_>, state: u32) -> Ctx {
        let mut c = Ctx::new();
        c.set(2, 28, 4, state).set(2, 16, 4, setup.service).set(2, 11, 2, 3); // path migration: migrated
        c.set(3, 0, 24, PD);
        c.set(4, 24, 8, setup.mtu_msgmax);
        c.set(4, 19, 4, log2_ceil(RX_SLOTS)).set(4, 16, 3, RQ_STRIDE.trailing_zeros() - 4);
        c.set(4, 11, 4, log2_ceil(SQ_ENTRIES)).set(4, 8, 3, SQ_STRIDE.trailing_zeros() - 4);
        c.set(5, 0, 24, UAR_PAGE).set(6, 0, 24, self.qpn);
        // Request an acknowledgment every 8 packets; fast registration on.
        c.set(30, 28, 4, 8).set(30, 11, 1, 1);
        c.set(33, 0, 24, self.cqn).set(41, 0, 24, self.cqn);
        c
    }

    /// Resets the queue pair's rings and takes it from reset to INIT.
    pub fn qp_init(&mut self, setup: &QpSetup<'_>) -> Result<(), Mlx4Error> {
        let mtt = self.cq_mtt() + 1;
        let (wq, rx) = (&self.mem.wq, &self.mem.rx);
        let sq_len = SQ_ENTRIES as usize * SQ_STRIDE;
        // Send entries start invalid for the first pass (owner bit set).
        for off in (0..sq_len).step_by(4) {
            wq.store(off, !0u32);
        }
        let lkey = self.hca.lkey;
        for i in 0..RX_SLOTS as usize {
            let wqe = sq_len + i * RQ_STRIDE;
            put32(wq, wqe, self.rx_slot as u32);
            put32(wq, wqe + 4, lkey);
            wq.store(wqe + 8, (rx.device_addr().as_u64() + (i * self.rx_slot) as u64).to_be());
            put32(wq, wqe + 20, INVALID_LKEY);
        }
        self.hca.write_mtt(mtt, wq)?;

        let rq_db = self.mem.doorbells.device_addr().as_u64() + 64;
        let mut qpc = self.context(setup, 1);
        qpc.set(0, 0, 32, setup.init_optpar);
        qpc.set(4, 4, 1, 1); // "kernel" queue pair
        qpc.set_addr(42, rq_db);
        qpc.set_addr(52, self.hca.mtt_addr(mtt));
        (setup.init)(&mut qpc);
        self.hca.hcr.exec(op::RST2INIT_QP, 0, self.qpn, Input::Mailbox(&qpc, 512))?;
        self.stage.qp_hw = true;

        // Every receive entry is ready before the queue pair can receive.
        self.rx_posted = RX_SLOTS;
        osmium_arch::barrier::dma_wmb();
        put32(&self.mem.doorbells, 64, self.rx_posted & 0xffff);
        Ok(())
    }

    /// INIT to ready-to-receive.
    pub fn qp_rtr(&mut self, setup: &QpSetup<'_>) -> Result<(), Mlx4Error> {
        let mut c = self.context(setup, 2);
        c.set(0, 0, 32, setup.rtr_optpar);
        (setup.rtr)(&mut c);
        self.hca.hcr.exec(op::INIT2RTR_QP, 0, self.qpn, Input::Mailbox(&c, 512)).map(drop)
    }

    /// Ready-to-receive to ready-to-send.
    pub fn qp_rts(&mut self, setup: &QpSetup<'_>) -> Result<(), Mlx4Error> {
        let mut c = self.context(setup, 3);
        c.set(0, 0, 32, setup.rts_optpar);
        (setup.rts)(&mut c);
        self.hca.hcr.exec(op::RTR2RTS_QP, 0, self.qpn, Input::Mailbox(&c, 512)).map(drop)
    }

    /// Changes the queue key of a queue pair that is ready to send.
    pub fn qp_set_qkey(&mut self, setup: &QpSetup<'_>, qkey: u32) -> Result<(), Mlx4Error> {
        let mut c = self.context(setup, 3);
        c.set(0, 0, 32, optpar::Q_KEY).set(44, 0, 32, qkey);
        self.hca.hcr.exec(op::RTS2RTS_QP, 0, self.qpn, Input::Mailbox(&c, 512)).map(drop)
    }

    /// Creates the queue pair and takes it to ready-to-send, with every
    /// receive entry posted.
    pub fn create_qp(&mut self, setup: &QpSetup<'_>) -> Result<(), Mlx4Error> {
        self.qp_init(setup)?;
        self.qp_rtr(setup)?;
        self.qp_rts(setup)
    }

    /// Reaps every completion the device has written, then (with MSI-X)
    /// re-arms the queue, looking once more for one that raced the arming.
    pub fn poll_cq(&mut self) {
        loop {
            self.reap_cq();
            self.rearm_if_fired();
            if self.hca.comp_eqn.is_none() || !self.completion_ready() {
                break;
            }
        }
    }

    fn reap_cq(&mut self) {
        let cq = &self.mem.cq;
        let mut reaped = false;
        loop {
            let off = (self.cq_ci % CQ_ENTRIES) as usize * CQE_LEN;
            let tail = get32(cq, off + 28);
            if (tail >> 7) & 1 != (self.cq_ci / CQ_ENTRIES) & 1 {
                break;
            }
            osmium_arch::barrier::dma_rmb();
            let error = tail & 0x1f == CQE_OPCODE_ERROR;
            if tail & 0x40 != 0 {
                self.tx_done = self.tx_done.wrapping_add(1);
            } else {
                let slot = (get32(cq, off + 24) >> 16) as u16 % RX_SLOTS as u16;
                let len = get32(cq, off + 20).min(self.rx_slot as u32) as u16;
                let status = (get32(cq, off + 16) >> 16) as u16;
                let sum = get32(cq, off + 24) as u16;
                let l4 = status & (STATUS_TCP | STATUS_UDP) != 0;
                let checksum = !error && l4 && status & STATUS_IPOK != 0 && sum == CSUM_OK;
                let (source, route) = (get32(cq, off + 8), get32(cq, off + 12));
                // At most RX_SLOTS receives are outstanding, so this fits.
                let at = (self.rx_ready_head + self.rx_ready_count) % RX_SLOTS as usize;
                self.rx_ready[at] = Received {
                    slot,
                    len,
                    error,
                    checksum,
                    src_qpn: source & 0xff_ffff,
                    src_lid: route as u16,
                    sl: (route >> 28) as u8,
                    src_path_bits: (source >> 24 & 0x7f) as u8,
                    pkey_index: (get32(cq, off + 4) & 0x7f) as u8,
                    grh: source >> 31 != 0,
                };
                self.rx_ready_count += 1;
            }
            self.cq_ci = self.cq_ci.wrapping_add(1);
            reaped = true;
        }
        if reaped {
            put32(&self.mem.doorbells, 0, self.cq_ci & 0xff_ffff);
        }
    }

    /// True if the next completion queue entry is the device's.
    fn completion_ready(&self) -> bool {
        let tail = get32(&self.mem.cq, (self.cq_ci % CQ_ENTRIES) as usize * CQE_LEN + 28);
        (tail >> 7) & 1 == (self.cq_ci / CQ_ENTRIES) & 1
    }

    /// Returns true if the completion queue holds a send (`send`) or
    /// receive completion, without consuming anything.
    pub fn completion_waiting(&self, send: bool) -> bool {
        let cq = &self.mem.cq;
        let mut ci = self.cq_ci;
        for _ in 0..CQ_ENTRIES {
            let tail = get32(cq, (ci % CQ_ENTRIES) as usize * CQE_LEN + 28);
            if (tail >> 7) & 1 != (ci / CQ_ENTRIES) & 1 {
                return false;
            }
            if (tail & 0x40 != 0) == send {
                return true;
            }
            ci = ci.wrapping_add(1);
        }
        false
    }

    /// True if every transmit slot is in use.
    pub fn tx_full(&self) -> bool {
        self.tx_head.wrapping_sub(self.tx_done) == TX_SLOTS
    }

    /// True if a send can be posted now or after reaping.
    pub fn can_transmit(&self) -> bool {
        // A full ring may have completions waiting; the next send reaps them.
        self.tx_head.wrapping_sub(self.tx_done) < TX_SLOTS || self.completion_waiting(true)
    }

    /// True if a packet can be taken now or after reaping.
    pub fn can_receive(&self) -> bool {
        self.rx_ready_count > 0 || self.completion_waiting(false)
    }

    /// Starts the next send entry: returns the byte offsets of the entry in
    /// the work queue memory and of its buffer slot in the transmit buffer,
    /// with all of the entry but its first dword cleared. The caller fills
    /// the entry in and hands it over with [`finish_send`](Self::finish_send).
    pub fn begin_send(&mut self) -> (usize, usize) {
        let slot = (self.tx_head % TX_SLOTS) as usize * self.tx_slot;
        let wqe = (self.tx_head % SQ_ENTRIES) as usize * SQ_STRIDE;
        for off in (4..SQ_STRIDE).step_by(4) {
            self.mem.wq.store(wqe + off, 0u32);
        }
        (wqe, slot)
    }

    /// The send queue memory, to fill in an entry started by
    /// [`begin_send`](Self::begin_send).
    pub fn wq(&self) -> &DmaBuffer {
        &self.mem.wq
    }

    /// Hands the entry at `wqe` to the device and rings the doorbell.
    pub fn finish_send(&mut self, wqe: usize, opcode: u32) {
        // The entry must be complete before its owner bit hands it over.
        osmium_arch::barrier::dma_wmb();
        let owner = (self.tx_head / SQ_ENTRIES) & 1;
        put32(&self.mem.wq, wqe, owner << 31 | opcode);
        osmium_arch::barrier::mb();
        let _ = self.hca.uar.write(UAR_PAGE as usize * PAGE + SEND_DOORBELL, (self.qpn << 8).to_be());
        self.tx_head = self.tx_head.wrapping_add(1);
    }

    /// Takes the oldest reaped packet, reaping first if there is none.
    pub fn next_received(&mut self) -> Option<Received> {
        if self.rx_ready_count == 0 {
            self.poll_cq();
        }
        if self.rx_ready_count == 0 {
            return None;
        }
        let r = self.rx_ready[self.rx_ready_head];
        self.rx_ready_head = (self.rx_ready_head + 1) % RX_SLOTS as usize;
        self.rx_ready_count -= 1;
        Some(r)
    }

    /// Copies `dst.len()` bytes from `offset` into receive slot `slot`.
    pub fn read_rx(&self, slot: u16, offset: usize, dst: &mut [u8]) {
        self.mem.rx.read(slot as usize * self.rx_slot + offset, dst);
    }

    /// Hands the receive entry of the packet just taken back to the device.
    pub fn repost(&mut self) {
        // Completions arrive in order, so the entry just consumed is the
        // next to repost, and it still points at its own slot.
        self.rx_posted = self.rx_posted.wrapping_add(1);
        osmium_arch::barrier::dma_wmb();
        put32(&self.mem.doorbells, 64, self.rx_posted & 0xffff);
        // A completion event disarms the queue even if nothing was reaped
        // here (packets already queued in software).
        self.rearm_if_fired();
    }

    fn close(&mut self) {
        let hcr = &self.hca.hcr;
        let leak = |r: Result<u64, Mlx4Error>| {
            if r.is_err() {
                hcr.wedge();
            }
        };
        if self.stage.port_up {
            // A port that will not close stops delivering anyway once its
            // queue pair is reset.
            let _ = hcr.exec(op::CLOSE_PORT, 0, self.port as u32, Input::None);
        }
        if self.stage.qp_hw {
            leak(hcr.exec(op::TO_RST_QP, 3, self.qpn, Input::None));
        }
        if self.stage.cq_hw {
            let mut cqc = Ctx::new();
            leak(hcr.exec_out(op::HW2SW_CQ, 0, self.cqn, Input::None, &mut cqc, 64).map(|_| 0));
        }
    }
}

impl<D: DmaAllocator + ?Sized> Drop for Queues<'_, '_, D> {
    fn drop(&mut self) {
        self.close();
        if !self.hca.hcr.is_wedged() {
            // SAFETY: dropped once, here; the device no longer uses it.
            unsafe { ManuallyDrop::drop(&mut self.mem) }
        }
    }
}
