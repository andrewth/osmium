//! What an Ethernet or InfiniBand port is built on: one completion queue
//! and one queue pair, with their rings and buffers.
//!
//! The queue pair's send queue holds [`SQ_ENTRIES`] 128-byte entries, of
//! which at most [`TX_SLOTS`] are in flight: the device prefetches up to
//! 2 KiB past the last posted entry, so the rest stay unused headroom
//! (iPXE's arrangement). Each receive entry permanently points at its own
//! buffer slot, so reposting is just advancing the doorbell record. Both
//! directions complete into one completion queue, sized so it cannot
//! overflow; receive completions found while reaping transmit ones are
//! queued in software until the port asks for them.
//!
//! With MSI-X enabled on the adapter the completion queue is created
//! disarmed and armed by doorbell whenever the port has reaped everything;
//! the completion event queue's interrupt then disarms it until the next
//! reap. Without MSI-X it is "fired" and only polled.
//!
//! What differs between the port types is the queue pair's service type
//! and transition parameters ([`QpSetup`]) and the send entries a port
//! builds; the rest lives here.

use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};

use super::cmd::{Ctx, Input, op};
use super::{EQ_MTTS, Mlx4, Mlx4Error, PAGE, PD, PORT_MTTS, UAR_PAGE, get32, log2_ceil, put32};

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
pub(super) mod optpar {
    pub const PKEY_INDEX: u32 = 1 << 4;
    pub const Q_KEY: u32 = 1 << 5;
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
    /// service level, and whether a global route header came with it.
    pub src_qpn: u32,
    pub src_lid: u16,
    pub sl: u8,
    pub src_path_bits: u8,
    pub grh: bool,
}

/// How far opening got, so closing undoes exactly that.
#[derive(Default)]
pub(super) struct Stage {
    cq_hw: bool,
    qp_hw: bool,
    pub port_up: bool,
}

/// The parts of a queue pair's transitions that depend on its service type.
/// Each closure edits the (zeroed) mailbox context of one transition on top
/// of what every queue pair gets.
pub(super) struct QpSetup<'f> {
    /// The context's service type: 7 raw Ethernet, 3 unreliable datagram.
    pub service: u32,
    /// Optional-parameter mask for RST2INIT ([`optpar`]).
    pub init_optpar: u32,
    pub init: &'f dyn Fn(&mut Ctx),
    pub rtr: &'f dyn Fn(&mut Ctx),
    pub rts: &'f dyn Fn(&mut Ctx),
}

pub(super) struct Queues<'h, 'd, D: DmaAllocator + ?Sized> {
    pub hca: &'h Mlx4<'d, D>,
    pub port: u8,
    pub qpn: u32,
    cqn: u32,
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
    /// Allocates the rings and buffers of `port` (1-based) and claims the
    /// port: `rx_slot` and `tx_slot` bytes per buffer slot, and a staging
    /// buffer of `lso` bytes if nonzero. Nothing is created in the device
    /// yet.
    pub fn new(hca: &'h Mlx4<'d, D>, port: u8, rx_slot: usize, tx_slot: usize, lso: usize) -> Result<Self, Mlx4Error> {
        let index = (port - 1) as u32;
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
        let q = Self {
            hca,
            port,
            qpn: hca.qpn_base + index,
            cqn: hca.caps.reserved_cqs + index,
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
        hca.open.set(hca.open.get() | 1 << index);
        Ok(q)
    }

    /// MTT entry of the completion queue; the queue pair's follows.
    pub fn cq_mtt(&self) -> u32 {
        EQ_MTTS + PORT_MTTS * (self.port as u32 - 1)
    }

    /// Index of this port's completion queue in the adapter's counters.
    fn index(&self) -> usize {
        self.port as usize - 1
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

    /// Creates the queue pair and takes it to ready-to-send, with every
    /// receive entry posted.
    pub fn create_qp(&mut self, setup: &QpSetup<'_>) -> Result<(), Mlx4Error> {
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
        let mut qpc = Ctx::new();
        qpc.set(0, 0, 32, setup.init_optpar);
        qpc.set(2, 11, 2, 3).set(2, 16, 4, setup.service); // migrated
        qpc.set(3, 0, 24, PD);
        qpc.set(4, 19, 4, log2_ceil(RX_SLOTS)).set(4, 16, 3, RQ_STRIDE.trailing_zeros() - 4);
        qpc.set(4, 11, 4, log2_ceil(SQ_ENTRIES)).set(4, 8, 3, SQ_STRIDE.trailing_zeros() - 4);
        qpc.set(5, 0, 24, UAR_PAGE).set(6, 0, 24, self.qpn);
        qpc.set(33, 0, 24, self.cqn).set(41, 0, 24, self.cqn);
        qpc.set_addr(42, rq_db);
        qpc.set_addr(52, self.hca.mtt_addr(mtt));
        (setup.init)(&mut qpc);
        self.hca.hcr.exec(op::RST2INIT_QP, 0, self.qpn, Input::Mailbox(&qpc, 512))?;
        self.stage.qp_hw = true;

        let mut rtr = Ctx::new();
        (setup.rtr)(&mut rtr);
        self.hca.hcr.exec(op::INIT2RTR_QP, 0, self.qpn, Input::Mailbox(&rtr, 512))?;

        let mut rts = Ctx::new();
        (setup.rts)(&mut rts);
        self.hca.hcr.exec(op::RTR2RTS_QP, 0, self.qpn, Input::Mailbox(&rts, 512))?;

        self.rx_posted = RX_SLOTS;
        osmium_arch::barrier::dma_wmb();
        put32(&self.mem.doorbells, 64, self.rx_posted & 0xffff);
        Ok(())
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
        self.hca.open.set(self.hca.open.get() & !(1 << (self.port - 1)));
        if !self.hca.hcr.is_wedged() {
            // SAFETY: dropped once, here; the device no longer uses it.
            unsafe { ManuallyDrop::drop(&mut self.mem) }
        }
    }
}
