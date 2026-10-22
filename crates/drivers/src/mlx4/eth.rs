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
//!
//! With MSI-X enabled on the adapter the completion queue is created
//! disarmed and armed by doorbell whenever the port has reaped everything;
//! the completion event queue's interrupt then disarms it until the next
//! reap. Without MSI-X it is "fired" and only polled.
//!
//! Offloads are opt-in per frame through
//! [`transmit_offload`](EthPort::transmit_offload) and
//! [`receive_checked`](EthPort::receive_checked).
//! A segmentation (LSO) frame is staged in a dedicated buffer, one at a
//! time, since the regular transmit slots hold one Ethernet frame each.

use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, DmaBuffer, OwnedDma};
use osmium_hal::net::{MacAddress, NetDevice, NetError};

use super::cmd::{Ctx, Input, op};
use super::{EQ_MTTS, Mlx4, Mlx4Error, PAGE, PD, PORT_MTTS, UAR_PAGE, get32, log2_ceil, put32};

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
const OPCODE_LSO: u32 = 0x0e;
/// Send control flags: completion on every entry, solicited.
const CTRL_COMPLETE: u32 = 3 << 2 | 1 << 1;
const CTRL_IP_CSUM: u32 = 1 << 4;
const CTRL_L4_CSUM: u32 = 1 << 5;
/// Bytes of a control or data segment, and of the LSO segment's fixed part.
const SEG_LEN: usize = 16;
const LSO_FIXED: usize = 4;
/// Largest header the LSO segment can carry in a 128-byte entry with
/// a control segment and one data segment around it.
pub const TSO_MAX_HEADER: usize = SQ_STRIDE - 2 * SEG_LEN - LSO_FIXED;
/// Bytes of the buffer a segmentation frame is staged in.
const LSO_BUF_LEN: usize = 16 * 1024;

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

const SET_PORT_GENERAL: u32 = 0x0000;
const SET_PORT_RECEIVE_QP: u32 = 0x0100;

// Compile-time checks of the ring arithmetic.
const _: () = assert!(SQ_ENTRIES.is_power_of_two() && RX_SLOTS.is_power_of_two() && CQ_ENTRIES.is_power_of_two());
const _: () = assert!(TX_SLOTS < SQ_ENTRIES - (2048 / SQ_STRIDE) as u32);
const _: () = assert!(TX_SLOTS + RX_SLOTS <= CQ_ENTRIES);
const _: () = assert!(2 * SEG_LEN + (LSO_FIXED + TSO_MAX_HEADER).next_multiple_of(SEG_LEN) <= SQ_STRIDE);
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
    /// Staging for segmentation frames; present if the device does LSO.
    lso: Option<OwnedDma<'d, D>>,
}

/// What a port can offload to the adapter, from [`EthPort::offloads`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offloads {
    /// The adapter can fill in IPv4 header and TCP/UDP checksums on
    /// transmit ([`TxOffload::checksum`]).
    pub tx_checksum: bool,
    /// Received frames come with a verdict on their checksums
    /// ([`EthPort::receive_checked`]).
    pub rx_checksum: bool,
    /// Largest frame (headers included) [`Tso`] can take, or 0 if the
    /// adapter cannot segment.
    pub tso_max_frame: usize,
}

/// Whether the adapter verified a received frame's checksums.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxChecksum {
    /// No verdict: not IP over TCP or UDP, or the adapter found a problem.
    /// The stack must check for itself.
    Unverified,
    /// The IP header and the TCP or UDP checksum are both correct.
    Verified,
}

/// TCP segmentation (large send): the adapter cuts one big frame into
/// frames of `mss` payload bytes, copying `header_len` bytes of headers to
/// each and fixing up lengths and checksums.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tso {
    /// TCP payload bytes per segment.
    pub mss: u16,
    /// Bytes of Ethernet, IP and TCP headers at the start of the frame
    /// (at most [`TSO_MAX_HEADER`]).
    pub header_len: u16,
}

/// Offloads requested for one transmitted frame.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxOffload {
    /// Compute the IPv4 header checksum and the TCP/UDP checksum (the TCP
    /// or UDP checksum field must hold the pseudo-header sum).
    pub checksum: bool,
    /// Segment the frame. Implies `checksum`.
    pub tso: Option<Tso>,
}

/// Why [`EthPort::transmit_offload`] refused a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    /// The ordinary transmit errors (queue full, frame too large).
    Net(NetError),
    /// The adapter cannot segment.
    Unsupported,
    /// Zero MSS, or a header length that is zero, longer than
    /// [`TSO_MAX_HEADER`] or than the frame.
    BadSegmentation,
}

impl From<NetError> for TxError {
    fn from(e: NetError) -> Self {
        Self::Net(e)
    }
}

/// A received frame reaped from the completion queue but not yet taken.
#[derive(Clone, Copy, Default)]
struct Received {
    slot: u16,
    len: u16,
    error: bool,
    checksum: bool,
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
    /// Received frames reaped from the completion queue but not yet taken,
    /// `rx_ready_count` of them from `rx_ready_head`.
    rx_ready: [Received; RX_SLOTS as usize],
    /// The arm count the completion queue was last armed with (MSI-X only).
    armed_sn: Option<u8>,
    /// Segmentation frame in flight: the value of `tx_done` that frees the
    /// staging buffer.
    lso_until: Option<u32>,
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
            lso: if hca.caps.max_gso > 0 { Some(alloc(LSO_BUF_LEN)?) } else { None },
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
            rx_ready: [Received::default(); RX_SLOTS as usize],
            armed_sn: None,
            lso_until: None,
            rx_ready_head: 0,
            rx_ready_count: 0,
        };
        hca.open.set(hca.open.get() | 1 << index);
        eth.create_cq(EQ_MTTS + PORT_MTTS * index)?;
        eth.create_qp(EQ_MTTS + 1 + PORT_MTTS * index)?;
        eth.arm_cq();
        eth.start_port()?;
        Ok(eth)
    }

    /// What this port can offload to the adapter.
    pub fn offloads(&self) -> Offloads {
        Offloads {
            tx_checksum: true,
            rx_checksum: true,
            tso_max_frame: if self.mem.lso.is_some() { (self.hca.caps.max_gso as usize).min(LSO_BUF_LEN) } else { 0 },
        }
    }

    /// Index of this port's completion queue in the adapter's counters.
    fn index(&self) -> usize {
        self.port as usize - 1
    }

    /// Asks for an event on the next completion, if the adapter uses MSI-X.
    fn arm_cq(&mut self) {
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
    fn rearm_if_fired(&mut self) {
        if self.hca.comp_eqn.is_some() && self.armed_sn != Some(self.hca.arm_sn[self.index()].get()) {
            self.arm_cq();
        }
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

    /// Reaps every completion the device has written, then (with MSI-X)
    /// re-arms the queue, looking once more for one that raced the arming.
    fn poll_cq(&mut self) {
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
                let len = get32(cq, off + 20).min(SLOT_LEN as u32) as u16;
                let status = (get32(cq, off + 16) >> 16) as u16;
                let sum = get32(cq, off + 24) as u16;
                let l4 = status & (STATUS_TCP | STATUS_UDP) != 0;
                let checksum = !error && l4 && status & STATUS_IPOK != 0 && sum == CSUM_OK;
                // At most RX_SLOTS receives are outstanding, so this fits.
                let at = (self.rx_ready_head + self.rx_ready_count) % RX_SLOTS as usize;
                self.rx_ready[at] = Received { slot, len, error, checksum };
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

    /// Transmits `frame` with the offloads in `offload`.
    ///
    /// With [`TxOffload::checksum`] the adapter fills in the IPv4 header
    /// checksum and the TCP or UDP checksum. With [`TxOffload::tso`] the
    /// frame may be up to [`Offloads::tso_max_frame`] bytes and is cut into
    /// segments by the adapter; only one such frame is in flight at a time
    /// (the next returns [`NetError::WouldBlock`] until it completes).
    pub fn transmit_offload(&mut self, frame: &[u8], offload: TxOffload) -> Result<(), TxError> {
        let tso = offload.tso;
        let limit = if tso.is_some() { LSO_BUF_LEN } else { MAX_FRAME };
        if tso.is_some() && self.mem.lso.is_none() {
            return Err(TxError::Unsupported);
        }
        if frame.len() > limit || tso.is_some() && frame.len() > self.offloads().tso_max_frame {
            return Err(NetError::TooLarge.into());
        }
        if let Some(t) = tso {
            let h = t.header_len as usize;
            if t.mss == 0 || h == 0 || h > TSO_MAX_HEADER || h >= frame.len() {
                return Err(TxError::BadSegmentation);
            }
            // Each segment must be a legal frame.
            if h + t.mss as usize > MAX_FRAME {
                return Err(NetError::TooLarge.into());
            }
        }
        let lso = tso.is_some();
        if self.tx_head.wrapping_sub(self.tx_done) == TX_SLOTS || lso && self.lso_busy() {
            self.poll_cq();
            if self.tx_head.wrapping_sub(self.tx_done) == TX_SLOTS || lso && self.lso_busy() {
                return Err(NetError::WouldBlock.into());
            }
        }
        let slot = (self.tx_head % TX_SLOTS) as usize * SLOT_LEN;
        let wqe = (self.tx_head % SQ_ENTRIES) as usize * SQ_STRIDE;
        let wq: &DmaBuffer = &self.mem.wq;
        for off in (4..SQ_STRIDE).step_by(4) {
            wq.store(wqe + off, 0u32);
        }
        let mut flags = CTRL_COMPLETE;
        if offload.checksum || tso.is_some() {
            flags |= CTRL_IP_CSUM | CTRL_L4_CSUM;
        }
        let (opcode, segments, data_at, buf, data_off, data_len) = match (tso, &self.mem.lso) {
            (Some(t), Some(lso)) => {
                let h = t.header_len as usize;
                lso.write(0, frame);
                let hdr = (LSO_FIXED + h).next_multiple_of(SEG_LEN);
                put32(wq, wqe + SEG_LEN, (t.mss as u32) << 16 | h as u32);
                wq.write(wqe + SEG_LEN + LSO_FIXED, &frame[..h]);
                (OPCODE_LSO, 2 + hdr / SEG_LEN, wqe + SEG_LEN + hdr, lso, h, frame.len() - h)
            }
            _ => {
                self.mem.tx.write(slot, frame);
                (OPCODE_SEND, 2, wqe + SEG_LEN, &self.mem.tx, slot, frame.len())
            }
        };
        put32(wq, wqe + 4, segments as u32); // control, optional LSO header, data
        put32(wq, wqe + 8, flags);
        put32(wq, data_at, data_len as u32);
        put32(wq, data_at + 4, self.hca.lkey);
        wq.store(data_at + 8, (buf.device_addr().as_u64() + data_off as u64).to_be());
        // The entry must be complete before its owner bit hands it over.
        osmium_arch::barrier::dma_wmb();
        let owner = (self.tx_head / SQ_ENTRIES) & 1;
        put32(wq, wqe, owner << 31 | opcode);
        osmium_arch::barrier::mb();
        let _ = self.hca.uar.write(UAR_PAGE as usize * PAGE + SEND_DOORBELL, (self.qpn << 8).to_be());
        self.tx_head = self.tx_head.wrapping_add(1);
        if tso.is_some() {
            self.lso_until = Some(self.tx_head);
        }
        Ok(())
    }

    /// True while a segmentation frame still owns the staging buffer.
    fn lso_busy(&mut self) -> bool {
        match self.lso_until {
            // Wrapping comparison: `tx_done` has not reached `until` yet.
            Some(until) if (self.tx_done.wrapping_sub(until) as i32) < 0 => true,
            Some(_) => {
                self.lso_until = None;
                false
            }
            None => false,
        }
    }

    /// Like [`receive`](NetDevice::receive), also telling whether the
    /// adapter verified the frame's IP header and TCP/UDP checksum.
    pub fn receive_checked(&mut self, buf: &mut [u8]) -> Result<(usize, RxChecksum), NetError> {
        if self.rx_ready_count == 0 {
            self.poll_cq();
        }
        if self.rx_ready_count == 0 {
            return Err(NetError::WouldBlock);
        }
        let Received { slot, len, error, checksum } = self.rx_ready[self.rx_ready_head];
        self.rx_ready_head = (self.rx_ready_head + 1) % RX_SLOTS as usize;
        self.rx_ready_count -= 1;
        let len = len as usize;
        let result = if error {
            Err(NetError::Io)
        } else if let Some(dst) = buf.get_mut(..len) {
            self.mem.rx.read(slot as usize * SLOT_LEN, dst);
            Ok((len, if checksum { RxChecksum::Verified } else { RxChecksum::Unverified }))
        } else {
            Err(NetError::TooLarge)
        };
        // Completions arrive in order, so the entry just consumed is the
        // next to repost, and it still points at its own slot.
        self.rx_posted = self.rx_posted.wrapping_add(1);
        osmium_arch::barrier::dma_wmb();
        put32(&self.mem.doorbells, 64, self.rx_posted & 0xffff);
        // A completion event disarms the queue even if nothing was reaped
        // here (frames already queued in software).
        self.rearm_if_fired();
        result
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
        match self.transmit_offload(frame, TxOffload::default()) {
            Ok(()) => Ok(()),
            Err(TxError::Net(e)) => Err(e),
            Err(_) => Err(NetError::Io),
        }
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.receive_checked(buf).map(|(len, _)| len)
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
