//! An Ethernet port: one completion queue and one raw Ethernet queue pair.
//!
//! The queue pair's send queue holds [`SQ_ENTRIES`] 128-byte entries, of
//! which at most [`TX_SLOTS`] are in flight: the device prefetches up to
//! 2 KiB past the last posted entry, so the rest stay unused headroom
//! (iPXE's arrangement). Each receive entry permanently points at its own
//! buffer slot, so reposting is just advancing the doorbell record. Both
//! directions complete into one completion queue, sized so it cannot
//! overflow; receive completions found while reaping transmit ones are
//! queued in software until [`receive`](NetDevice::receive) asks.

use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::net::{MacAddress, NetDevice, NetError};

use super::cmd::{Ctx, Input, op};
use super::{Mlx4, Mlx4Error, PAGE, PD, PORT_MTTS, UAR_PAGE, get32, log2_ceil, put32};

/// Send queue entries (a power of two).
pub const SQ_ENTRIES: u32 = 32;
const SQ_STRIDE: usize = 128;
/// Receive queue entries and buffer slots (a power of two).
pub const RX_SLOTS: u32 = 16;
const RQ_STRIDE: usize = 32;
/// Transmit buffer slots: frames in flight at once.
pub const TX_SLOTS: u32 = 8;
const CQ_ENTRIES: u32 = 32;
const CQE_LEN: usize = 32;
/// Bytes per buffer slot.
pub const SLOT_LEN: usize = 2048;

/// Largest frame: 1514 bytes plus a VLAN tag.
const MAX_FRAME: usize = 1518;
/// Port MTU as the firmware counts it: frame, VLAN tag and FCS (Linux's).
const PORT_MTU: u32 = 1500 + 14 + 4 + 4;

const OPCODE_SEND: u32 = 0x0a;
const CQE_OPCODE_ERROR: u32 = 0x1e;
/// A receive entry's terminating scatter entry.
const INVALID_LKEY: u32 = 0x100;
/// Send doorbell, in [`UAR_PAGE`].
const SEND_DOORBELL: usize = 0x14;

const SET_PORT_GENERAL: u32 = 0x0000;
const SET_PORT_RECEIVE_QP: u32 = 0x0100;

// Compile-time checks of the ring arithmetic.
const _: () = assert!(SQ_ENTRIES.is_power_of_two() && RX_SLOTS.is_power_of_two() && CQ_ENTRIES.is_power_of_two());
const _: () = assert!(TX_SLOTS < SQ_ENTRIES - (2048 / SQ_STRIDE) as u32);
const _: () = assert!(TX_SLOTS + RX_SLOTS <= CQ_ENTRIES);
const _: () = assert!(CQ_ENTRIES as usize * CQE_LEN <= PAGE);
const _: () =
    assert!((SQ_ENTRIES as usize * SQ_STRIDE + RX_SLOTS as usize * RQ_STRIDE).div_ceil(PAGE) < PORT_MTTS as usize);

struct Memory<'d, D: DmaAllocator + ?Sized> {
    cq: OwnedDma<'d, D>,
    /// Send queue, then receive queue.
    wq: OwnedDma<'d, D>,
    /// Completion queue doorbell record at 0, receive queue's at 64.
    doorbells: OwnedDma<'d, D>,
    rx: OwnedDma<'d, D>,
    tx: OwnedDma<'d, D>,
}

/// How far opening got, so closing undoes exactly that.
#[derive(Default)]
struct Stage {
    cq_hw: bool,
    qp_hw: bool,
    port_up: bool,
}

/// A port of an [`Mlx4`] in Ethernet mode. Dropping it closes the port and
/// frees its queues.
pub struct EthPort<'h, 'd, D: DmaAllocator + ?Sized> {
    hca: &'h Mlx4<'d, D>,
    port: u8,
    mac: MacAddress,
    qpn: u32,
    cqn: u32,
    mem: ManuallyDrop<Memory<'d, D>>,
    stage: Stage,
    /// Completion queue consumer index.
    cq_ci: u32,
    /// Send entries posted and completed.
    tx_head: u32,
    tx_done: u32,
    /// Receive entries handed to the device.
    rx_posted: u32,
    /// Received frames reaped from the completion queue but not yet taken:
    /// (slot, length, error), `rx_ready_count` of them from `rx_ready_head`.
    rx_ready: [(u16, u16, bool); RX_SLOTS as usize],
    rx_ready_head: usize,
    rx_ready_count: usize,
}

impl<'h, 'd, D: DmaAllocator + ?Sized> EthPort<'h, 'd, D> {
    pub(super) fn open(hca: &'h Mlx4<'d, D>, port: u8) -> Result<Self, Mlx4Error> {
        let index = (port - 1) as u32;
        let mut q = Ctx::new();
        hca.hcr.exec_out(op::QUERY_PORT, 0, port as u32, Input::None, &mut q, 64)?;
        let (ib, eth) = (q.get(0, 24, 1) != 0, q.get(0, 25, 1) != 0);
        let ethernet = match (ib, eth) {
            (_, false) => false,
            (true, true) if hca.caps.dpdp => hca.sense_ethernet(port)?,
            _ => true,
        };
        if !ethernet {
            return Err(Mlx4Error::NotEthernet);
        }
        let hi = q.get(4, 0, 16).to_be_bytes();
        let lo = q.dword(5).to_be_bytes();
        let mac = MacAddress([hi[2], hi[3], lo[0], lo[1], lo[2], lo[3]]);
        hca.set_link(port, q.get(0, 31, 1) != 0);

        let alloc = |len: usize| OwnedDma::new(hca.dma, len).ok_or(Mlx4Error::NoMemory);
        let sq_len = SQ_ENTRIES as usize * SQ_STRIDE;
        let mem = Memory {
            cq: alloc(CQ_ENTRIES as usize * CQE_LEN)?,
            wq: alloc(sq_len + RX_SLOTS as usize * RQ_STRIDE)?,
            doorbells: alloc(128)?,
            rx: alloc(RX_SLOTS as usize * SLOT_LEN)?,
            tx: alloc(TX_SLOTS as usize * SLOT_LEN)?,
        };
        let mut eth = Self {
            hca,
            port,
            mac,
            qpn: hca.qpn_base + index,
            cqn: hca.caps.reserved_cqs + index,
            mem: ManuallyDrop::new(mem),
            stage: Stage::default(),
            cq_ci: 0,
            tx_head: 0,
            tx_done: 0,
            rx_posted: 0,
            rx_ready: [(0, 0, false); RX_SLOTS as usize],
            rx_ready_head: 0,
            rx_ready_count: 0,
        };
        hca.open.set(hca.open.get() | 1 << index);
        eth.create_cq(1 + PORT_MTTS * index)?;
        eth.create_qp(2 + PORT_MTTS * index)?;
        eth.start_port()?;
        Ok(eth)
    }

    /// The port number (1-based).
    pub fn port(&self) -> u8 {
        self.port
    }

    fn create_cq(&mut self, mtt: u32) -> Result<(), Mlx4Error> {
        let cq = &self.mem.cq;
        for i in 0..CQ_ENTRIES as usize {
            put32(cq, i * CQE_LEN + 28, 0x80); // owned by hardware
        }
        self.hca.write_mtt(mtt, cq)?;
        let mut cqc = Ctx::new();
        cqc.set(0, 8, 4, 0xa); // "fired": never raises an event
        cqc.set(3, 0, 24, UAR_PAGE).set(3, 24, 5, log2_ceil(CQ_ENTRIES));
        cqc.set(5, 0, 9, self.hca.caps.eqn());
        cqc.set_addr(6, self.hca.mtt_addr(mtt));
        cqc.set_addr(14, self.mem.doorbells.device_addr().as_u64());
        self.hca.hcr.exec(op::SW2HW_CQ, 0, self.cqn, Input::Mailbox(&cqc, 64))?;
        self.stage.cq_hw = true;
        Ok(())
    }

    fn create_qp(&mut self, mtt: u32) -> Result<(), Mlx4Error> {
        let (wq, rx) = (&self.mem.wq, &self.mem.rx);
        let sq_len = SQ_ENTRIES as usize * SQ_STRIDE;
        // Send entries start invalid for the first pass (owner bit set).
        for off in (0..sq_len).step_by(4) {
            wq.store(off, !0u32);
        }
        let lkey = self.hca.lkey;
        for i in 0..RX_SLOTS as usize {
            let wqe = sq_len + i * RQ_STRIDE;
            put32(wq, wqe, SLOT_LEN as u32);
            put32(wq, wqe + 4, lkey);
            wq.store(wqe + 8, (rx.device_addr().as_u64() + (i * SLOT_LEN) as u64).to_be());
            put32(wq, wqe + 20, INVALID_LKEY);
        }
        self.hca.write_mtt(mtt, wq)?;

        let rq_db = self.mem.doorbells.device_addr().as_u64() + 64;
        let mut qpc = Ctx::new();
        qpc.set(2, 11, 2, 3).set(2, 16, 4, 7); // migrated; raw Ethernet ("MLX") service
        qpc.set(3, 0, 24, PD);
        qpc.set(4, 19, 4, log2_ceil(RX_SLOTS)).set(4, 16, 3, RQ_STRIDE.trailing_zeros() - 4);
        qpc.set(4, 11, 4, log2_ceil(SQ_ENTRIES)).set(4, 8, 3, SQ_STRIDE.trailing_zeros() - 4);
        qpc.set(5, 0, 24, UAR_PAGE).set(6, 0, 24, self.qpn);
        qpc.set(33, 0, 24, self.cqn).set(41, 0, 24, self.cqn);
        qpc.set_addr(42, rq_db);
        // Leave VLAN tags in received frames (Linux sets this whenever VLAN
        // stripping is off).
        qpc.set(50, 30, 1, 1);
        qpc.set_addr(52, self.hca.mtt_addr(mtt));
        self.hca.hcr.exec(op::RST2INIT_QP, 0, self.qpn, Input::Mailbox(&qpc, 512))?;
        self.stage.qp_hw = true;

        let mut rtr = Ctx::new();
        rtr.set(4, 29, 3, 7).set(4, 24, 5, 31); // Ethernet MTU, largest message
        rtr.set(16, 24, 8, 0x83 | (self.port as u32 - 1) << 6); // default schedule queue of this port
        self.hca.hcr.exec(op::INIT2RTR_QP, 0, self.qpn, Input::Mailbox(&rtr, 512))?;

        let mut rts = Ctx::new();
        rts.set(10, 27, 5, 14).set(30, 16, 3, 7).set(30, 13, 3, 7); // ack timeout and retries (unused)
        self.hca.hcr.exec(op::RTR2RTS_QP, 0, self.qpn, Input::Mailbox(&rts, 512))?;

        self.rx_posted = RX_SLOTS;
        osmium_arch::barrier::dma_wmb();
        put32(&self.mem.doorbells, 64, self.rx_posted & 0xffff);
        Ok(())
    }

    fn start_port(&mut self) -> Result<(), Mlx4Error> {
        let port = self.port as u32;
        let mut general = Ctx::new();
        general.set(0, 0, 3, 0b111).set(1, 0, 16, PORT_MTU); // MTU and pause settings valid; pause off
        self.hca.hcr.exec(op::SET_PORT, 1, SET_PORT_GENERAL | port, Input::Mailbox(&general, 16))?;

        // Every MAC and VLAN misses the (empty) tables, and misses go to
        // the promiscuous queue pair: this one.
        let mut rqp = Ctx::new();
        rqp.set(0, 0, 24, self.qpn).set(2, 0, 8, 128);
        rqp.set(3, 0, 7, 127).set(3, 16, 7, 126);
        rqp.set(5, 0, 24, self.qpn).set(5, 31, 1, 1); // unicast promiscuous
        rqp.set(6, 0, 24, self.qpn).set(6, 30, 2, 2); // every multicast
        self.hca.hcr.exec(op::SET_PORT, 1, SET_PORT_RECEIVE_QP | port, Input::Mailbox(&rqp, 32))?;

        self.hca.hcr.exec(op::INIT_PORT, 0, port, Input::None)?;
        self.stage.port_up = true;
        Ok(())
    }

    /// Reaps every completion the device has written.
    fn poll_cq(&mut self) {
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
                let len = get32(cq, off + 20).min(SLOT_LEN as u32) as u16;
                // At most RX_SLOTS receives are outstanding, so this fits.
                let at = (self.rx_ready_head + self.rx_ready_count) % RX_SLOTS as usize;
                self.rx_ready[at] = (slot, len, error);
                self.rx_ready_count += 1;
            }
            self.cq_ci = self.cq_ci.wrapping_add(1);
            reaped = true;
        }
        if reaped {
            put32(&self.mem.doorbells, 0, self.cq_ci & 0xff_ffff);
        }
    }

    /// Returns true if the completion queue holds a send (`send`) or
    /// receive completion, without consuming anything.
    fn completion_waiting(&self, send: bool) -> bool {
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

impl<D: DmaAllocator + ?Sized> NetDevice for EthPort<'_, '_, D> {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn max_frame_len(&self) -> usize {
        MAX_FRAME
    }

    fn link_up(&self) -> bool {
        self.hca.link_up(self.port)
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        if frame.len() > MAX_FRAME {
            return Err(NetError::TooLarge);
        }
        if self.tx_head.wrapping_sub(self.tx_done) == TX_SLOTS {
            self.poll_cq();
            if self.tx_head.wrapping_sub(self.tx_done) == TX_SLOTS {
                return Err(NetError::WouldBlock);
            }
        }
        let slot = (self.tx_head % TX_SLOTS) as usize * SLOT_LEN;
        self.mem.tx.write(slot, frame);

        let wq: &DmaBuffer = &self.mem.wq;
        let wqe = (self.tx_head % SQ_ENTRIES) as usize * SQ_STRIDE;
        for off in (4..SQ_STRIDE).step_by(4) {
            wq.store(wqe + off, 0u32);
        }
        put32(wq, wqe + 4, 2); // two 16-byte segments: control and data
        put32(wq, wqe + 8, 3 << 2 | 1 << 1); // always complete; solicited
        put32(wq, wqe + 16, frame.len() as u32);
        put32(wq, wqe + 20, self.hca.lkey);
        wq.store(wqe + 24, (self.mem.tx.device_addr().as_u64() + slot as u64).to_be());
        // The entry must be complete before its owner bit hands it over.
        osmium_arch::barrier::dma_wmb();
        let owner = (self.tx_head / SQ_ENTRIES) & 1;
        put32(wq, wqe, owner << 31 | OPCODE_SEND);
        osmium_arch::barrier::mb();
        let _ = self.hca.uar.write(UAR_PAGE as usize * PAGE + SEND_DOORBELL, (self.qpn << 8).to_be());
        self.tx_head = self.tx_head.wrapping_add(1);
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        if self.rx_ready_count == 0 {
            self.poll_cq();
        }
        if self.rx_ready_count == 0 {
            return Err(NetError::WouldBlock);
        }
        let (slot, len, error) = self.rx_ready[self.rx_ready_head];
        self.rx_ready_head = (self.rx_ready_head + 1) % RX_SLOTS as usize;
        self.rx_ready_count -= 1;
        let len = len as usize;
        let result = if error {
            Err(NetError::Io)
        } else if let Some(dst) = buf.get_mut(..len) {
            self.mem.rx.read(slot as usize * SLOT_LEN, dst);
            Ok(len)
        } else {
            Err(NetError::TooLarge)
        };
        // Completions arrive in order, so the entry just consumed is the
        // next to repost, and it still points at its own slot.
        self.rx_posted = self.rx_posted.wrapping_add(1);
        osmium_arch::barrier::dma_wmb();
        put32(&self.mem.doorbells, 64, self.rx_posted & 0xffff);
        result
    }

    fn can_receive(&self) -> bool {
        self.rx_ready_count > 0 || self.completion_waiting(false)
    }

    fn can_transmit(&self) -> bool {
        // A full ring may have completions waiting; transmit reaps them.
        self.tx_head.wrapping_sub(self.tx_done) < TX_SLOTS || self.completion_waiting(true)
    }
}

impl<D: DmaAllocator + ?Sized> Drop for EthPort<'_, '_, D> {
    fn drop(&mut self) {
        self.close();
        self.hca.open.set(self.hca.open.get() & !(1 << (self.port - 1)));
        if !self.hca.hcr.is_wedged() {
            // SAFETY: dropped once, here; the device no longer uses it.
            unsafe { ManuallyDrop::drop(&mut self.mem) }
        }
    }
}
