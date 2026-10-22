//! Reliable connections: queue pairs that carry sends, RDMA writes and
//! RDMA reads to one peer, with the adapter doing the acknowledgments and
//! retransmissions.
//!
//! Making the connection is up to the caller: the two ends exchange the
//! numbers they need ([`RcInfo`], the LID and, if routed, the GIDs) by some
//! other means, for instance datagrams, and each passes the other's to
//! [`IbPort::rc_connect`]. Everything a peer may do to this machine is
//! confined to the connection's *window*: a few kilobytes of driver-owned
//! memory registered for remote access under a key of its own and taken
//! back, before the memory is freed, when the connection is destroyed. The
//! adapter's all-memory region has no remote permissions.
//!
//! A reliable connection fails as a whole: after the first error every
//! operation completes with a flush error, and the only way on is to
//! destroy it and make another.

use core::mem::ManuallyDrop;

use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::net::NetError;

use super::{IbPort, Route};
use crate::mlx4::cmd::Ctx;
use crate::mlx4::queue::{CTRL_COMPLETE, Geometry, QpSetup, Queues, SEG_LEN, SET_RC, SQ_ENTRIES, TX_SLOTS, optpar};
use crate::mlx4::{MAX_PORTS, Mlx4Error, put32};

/// Bytes of the window a peer can read and write.
pub const WINDOW_LEN: usize = 16 * 1024;
/// Largest message of one send, write or read.
pub const MAX_MESSAGE: usize = 4096;

const OPCODE_RDMA_WRITE: u32 = 0x08;
const OPCODE_SEND: u32 = 0x0a;
const OPCODE_RDMA_READ: u32 = 0x10;

/// Names a reliable connection of an [`IbPort`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RcId(pub(in crate::mlx4) u8);

/// What the other end of a connection needs to know about this end's side
/// of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RcInfo {
    /// The queue pair number.
    pub qpn: u32,
    /// The memory the peer may read and write.
    pub window: RcWindow,
}

/// Memory a peer may read and write with RDMA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RcWindow {
    /// The address the peer names (a bus address).
    pub addr: u64,
    /// The key it presents.
    pub rkey: u32,
    /// Its length in bytes.
    pub len: usize,
}

/// How to reach the peer and how the connection behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RcParams {
    /// The peer's LID.
    pub dest_lid: u16,
    /// The peer's queue pair number.
    pub dest_qpn: u32,
    /// The global route, if the peer is on another subnet.
    pub route: Option<Route>,
    /// Service level.
    pub sl: u8,
    /// The low LID bits to send from.
    pub path_bits: u8,
    /// The first packet number this end sends with (each end's `send_psn`
    /// is the other's `receive_psn`).
    pub send_psn: u32,
    /// The packet number this end expects the peer to start with.
    pub receive_psn: u32,
    /// The path's MTU as the IB enumeration (1 for 256 bytes … 5 for 4096).
    pub path_mtu: u32,
    /// Acknowledgment timeout: 4.096 µs × 2^`ack_timeout`.
    pub ack_timeout: u8,
    /// Retransmissions after a timeout (7 means without end).
    pub retry_count: u8,
    /// Retransmissions after the peer was not ready (7 means without end).
    pub rnr_retry: u8,
    /// How long this end tells the peer to wait when it has no receive
    /// ready (an IB code, 0–31).
    pub min_rnr_timer: u8,
    /// RDMA reads this end may have outstanding.
    pub max_rd_atomic: u8,
    /// RDMA reads the peer may have outstanding.
    pub max_dest_rd_atomic: u8,
}

impl RcParams {
    /// Parameters for a connection to queue pair `dest_qpn` at `dest_lid` on
    /// the local subnet, with the customary timeouts and retries.
    pub fn to(dest_lid: u16, dest_qpn: u32) -> Self {
        Self {
            dest_lid,
            dest_qpn,
            route: None,
            sl: 0,
            path_bits: 0,
            send_psn: 0,
            receive_psn: 0,
            path_mtu: 4,
            ack_timeout: 14,
            retry_count: 7,
            rnr_retry: 7,
            min_rnr_timer: 12,
            max_rd_atomic: 4,
            max_dest_rd_atomic: 4,
        }
    }
}

/// Where a connection is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcState {
    /// Created, waiting for [`IbPort::rc_connect`].
    Unconnected,
    /// Ready to send and receive.
    Connected,
    /// Failed; destroy it.
    Failed,
}

/// Why an operation, or the connection, failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcFailure {
    /// A message was longer than the receive entry it met.
    LocalLength,
    /// A local protection or access error.
    LocalProtection,
    /// The operation was discarded because an earlier one failed.
    Flushed,
    /// The peer's response was not valid.
    BadResponse,
    /// The peer found the request invalid.
    RemoteInvalidRequest,
    /// The peer refused the key or the range of an RDMA operation.
    RemoteAccess,
    /// The peer could not carry the operation out.
    RemoteOperation,
    /// The peer did not acknowledge in time, however often it was tried.
    RetryExceeded,
    /// The peer had no receive ready, however often it was tried.
    RnrRetryExceeded,
    /// The peer ended the operation.
    RemoteAborted,
    /// The caller's buffer was too small for what arrived.
    BufferTooSmall,
    /// Any other syndrome.
    Other(u8),
}

impl RcFailure {
    fn from_syndrome(syndrome: u8) -> Self {
        match syndrome {
            0x01 => Self::LocalLength,
            0x02 | 0x04 | 0x11 => Self::LocalProtection,
            0x05 => Self::Flushed,
            0x10 => Self::BadResponse,
            0x12 => Self::RemoteInvalidRequest,
            0x13 => Self::RemoteAccess,
            0x14 => Self::RemoteOperation,
            0x15 => Self::RetryExceeded,
            0x16 => Self::RnrRetryExceeded,
            0x22 => Self::RemoteAborted,
            other => Self::Other(other),
        }
    }
}

/// Something that happened on a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcEvent {
    /// A send was acknowledged.
    Sent,
    /// An RDMA write was acknowledged.
    Written,
    /// An RDMA read finished; its data is in the caller's buffer.
    Read {
        /// Bytes read.
        len: usize,
    },
    /// A message arrived; it is in the caller's buffer.
    Received {
        /// Bytes in the message.
        len: usize,
    },
    /// The connection failed.
    Failed(RcFailure),
}

#[derive(Clone, Copy)]
enum Op {
    Send,
    Write,
    Read { len: usize },
}

pub(super) struct Rc<'h, 'd, D: DmaAllocator + ?Sized> {
    q: Queues<'h, 'd, D>,
    window: ManuallyDrop<OwnedDma<'d, D>>,
    /// Which of the adapter's window registrations this is.
    slot: u32,
    rkey: u32,
    state: RcState,
    /// Operations posted, and reported to the caller; the send slot of
    /// operation `n` is `n % TX_SLOTS`, held until it is reported.
    posted: u32,
    reported: u32,
    ops: [Op; TX_SLOTS as usize],
}

impl<D: DmaAllocator + ?Sized> Drop for Rc<'_, '_, D> {
    fn drop(&mut self) {
        // The queue pair stops first so that nothing is in flight; then the
        // window is taken back, and only then may its memory go.
        self.q.shutdown();
        let hca = self.q.hca;
        if hca.unregister_window(self.slot).is_err() {
            hca.hcr.wedge(); // the peer may still be able to write there
        }
        if !hca.hcr.is_wedged() {
            // SAFETY: dropped once, here; the adapter no longer has the region.
            unsafe { ManuallyDrop::drop(&mut self.window) }
        }
    }
}

/// `ceil(log2(n))` for the resource counts in a context.
fn log2_count(n: u8) -> u32 {
    if n <= 1 { 0 } else { 8 - (n - 1).leading_zeros() }
}

/// Runs `f` with the transitions of a reliable connection. `params` is
/// absent before the connection is made.
fn with_setup<R>(params: Option<&RcParams>, port: u32, log_msg: u32, f: impl FnOnce(&QpSetup<'_>) -> R) -> R {
    let p = params.copied().unwrap_or(RcParams::to(0, 0));
    let msgmax = p.path_mtu << 5 | log_msg;
    let init = |c: &mut Ctx| {
        c.set(8, 0, 8, 0); // partition key index 0
        // Remote write only (bit 14 of the second parameter word): reads are
        // allowed once responder resources exist.
        c.set(38, 14, 1, 1);
    };
    let rtr = |c: &mut Ctx| {
        c.set(7, 0, 24, p.dest_qpn);
        c.set(9, 16, 8, (p.path_bits & 0x7f) as u32 | if p.route.is_some() { 0x80 } else { 0 });
        c.set(9, 0, 16, p.dest_lid as u32);
        if let Some(r) = &p.route {
            c.set(10, 16, 8, r.sgid_index as u32).set(10, 0, 8, r.hop_limit as u32);
            c.set(11, 0, 32, (r.traffic_class as u32) << 20 | r.flow_label & 0xf_ffff);
            for i in 0..4 {
                c.set(12 + i, 0, 32, u32::from_be_bytes(r.dgid.0[4 * i..4 * i + 4].try_into().expect("4 bytes")));
            }
        }
        c.set(16, 24, 8, (port - 1) << 6 | 0x83 | (p.sl as u32 & 0xf) << 2);
        c.set(38, 21, 3, log2_count(p.max_dest_rd_atomic));
        // Remote writes and reads (bits 14 and 15), now that there are
        // responder resources.
        c.set(38, 14, 2, 3);
        c.set(39, 0, 24, p.receive_psn).set(39, 24, 5, p.min_rnr_timer as u32);
    };
    let rts = |c: &mut Ctx| {
        c.set(10, 27, 5, p.ack_timeout as u32);
        c.set(30, 16, 3, p.retry_count as u32).set(30, 13, 3, p.rnr_retry as u32);
        c.set(30, 21, 3, log2_count(p.max_rd_atomic));
        c.set(32, 0, 24, p.send_psn);
    };
    f(&QpSetup {
        service: 0, // reliable connection
        init_mtu_msgmax: 0,
        mtu_msgmax: msgmax,
        init_optpar: optpar::PKEY_INDEX | optpar::RWE | optpar::RRE | optpar::RAE,
        rtr_optpar: optpar::PRIMARY_ADDR_PATH
            | optpar::SCHED_QUEUE
            | optpar::RNR_TIMEOUT
            | optpar::RRA_MAX
            | optpar::RWE
            | optpar::RRE
            | optpar::RAE,
        rts_optpar: optpar::ACK_TIMEOUT | optpar::RETRY_COUNT | optpar::RNR_RETRY | optpar::SRA_MAX,
        init: &init,
        rtr: &rtr,
        rts: &rts,
    })
}

impl<'h, 'd, D: DmaAllocator + ?Sized> IbPort<'h, 'd, D> {
    fn rc_ref(&self, id: RcId) -> Option<&Rc<'h, 'd, D>> {
        self.rc.get(id.0 as usize)?.as_ref()
    }

    fn rc_mut(&mut self, id: RcId) -> Option<&mut Rc<'h, 'd, D>> {
        self.rc.get_mut(id.0 as usize)?.as_mut()
    }

    /// Creates a reliable connection, not yet connected to anything.
    pub fn rc_create(&mut self) -> Result<(RcId, RcInfo), Mlx4Error> {
        let n = self.rc.iter().position(Option::is_none).ok_or(Mlx4Error::NoMemory)?;
        let (hca, port) = (self.ud.hca, self.ud.port);
        let geometry = Geometry { rx_slot: MAX_MESSAGE, tx_slot: MAX_MESSAGE, lso: 0 };
        let mut q = Queues::new(hca, port, SET_RC + n as u8, geometry)?;
        q.create_cq()?;
        let window = OwnedDma::new(hca.dma, WINDOW_LEN).ok_or(Mlx4Error::NoMemory)?;
        let addr = window.device_addr().as_u64();
        let slot = n as u32 * MAX_PORTS as u32 + (port as u32 - 1);
        let rkey = hca.register_window(slot, addr, WINDOW_LEN)?;
        let mut rc = Rc {
            q,
            window: ManuallyDrop::new(window),
            slot,
            rkey,
            state: RcState::Unconnected,
            posted: 0,
            reported: 0,
            ops: [Op::Send; TX_SLOTS as usize],
        };
        let log_msg = hca.caps.log_max_msg_sz;
        with_setup(None, port as u32, log_msg, |s| rc.q.qp_init(s))?;
        rc.q.arm_cq();
        let info = RcInfo { qpn: rc.q.qpn, window: RcWindow { addr, rkey, len: WINDOW_LEN } };
        self.rc[n] = Some(rc);
        Ok((RcId(n as u8), info))
    }

    /// Connects `id` to the peer described by `params`; afterwards it can
    /// send and receive.
    pub fn rc_connect(&mut self, id: RcId, params: &RcParams) -> Result<(), Mlx4Error> {
        let (hca, port, port_mtu, gids) = (self.ud.hca, self.ud.port, self.mtu, self.gids);
        let p = params;
        let route_ok = p.route.is_none_or(|r| (r.sgid_index as u16) < gids);
        let fits = |n: u8, log: u32| u32::from(n) <= 1 << log;
        if p.path_mtu == 0
            || p.path_mtu > port_mtu
            || p.sl > 15
            || p.path_bits > 127
            || p.retry_count > 7
            || p.rnr_retry > 7
            || p.min_rnr_timer > 31
            || p.ack_timeout > 31
            || p.dest_qpn > 0xff_ffff
            || p.send_psn > 0xff_ffff
            || p.receive_psn > 0xff_ffff
            || !route_ok
            || !fits(p.max_rd_atomic, hca.caps.log_max_req_rd)
            || !fits(p.max_dest_rd_atomic, hca.caps.log_max_res_rd)
        {
            return Err(Mlx4Error::BadParameter);
        }
        let log_msg = hca.caps.log_max_msg_sz;
        let rc = self.rc_mut(id).ok_or(Mlx4Error::BadParameter)?;
        if rc.state != RcState::Unconnected {
            return Err(Mlx4Error::BadParameter);
        }
        let result = with_setup(Some(p), port as u32, log_msg, |s| {
            rc.q.qp_rtr(s)?;
            rc.q.qp_rts(s)
        });
        rc.state = if result.is_ok() { RcState::Connected } else { RcState::Failed };
        result
    }

    /// Where `id` is.
    pub fn rc_state(&self, id: RcId) -> Option<RcState> {
        self.rc_ref(id).map(|rc| rc.state)
    }

    /// Posts an operation and keeps the book on it.
    fn rc_post(
        &mut self,
        id: RcId,
        op: Op,
        remote: Option<(u64, u32)>,
        data: Option<&[u8]>,
        len: usize,
    ) -> Result<(), NetError> {
        let rc = self.rc_mut(id).ok_or(NetError::Io)?;
        if rc.state != RcState::Connected {
            return Err(NetError::Io);
        }
        if len > MAX_MESSAGE {
            return Err(NetError::TooLarge);
        }
        if rc.posted.wrapping_sub(rc.reported) >= TX_SLOTS {
            rc.q.poll_cq();
            if rc.posted.wrapping_sub(rc.reported) >= TX_SLOTS || rc.q.tx_full() {
                return Err(NetError::WouldBlock);
            }
        }
        let (wqe, slot) = rc.q.begin_send();
        if let Some(d) = data {
            rc.q.mem.tx.write(slot, d);
        }
        let buf = rc.q.mem.tx.device_addr().as_u64() + slot as u64;
        let lkey = rc.q.hca.lkey;
        let wq = rc.q.wq();
        put32(wq, wqe + 8, CTRL_COMPLETE);
        let mut at = wqe + SEG_LEN;
        let opcode = match op {
            Op::Send => OPCODE_SEND,
            Op::Write => OPCODE_RDMA_WRITE,
            Op::Read { .. } => OPCODE_RDMA_READ,
        };
        if let Some((raddr, rkey)) = remote {
            wq.store(at, raddr.to_be());
            put32(wq, at + 8, rkey);
            at += SEG_LEN;
        }
        put32(wq, at, len as u32);
        put32(wq, at + 4, lkey);
        wq.store(at + 8, buf.to_be());
        let size = ((at + SEG_LEN - wqe) / SEG_LEN) as u32;
        put32(wq, wqe + 4, size);
        rc.q.finish_send(wqe, opcode);
        rc.ops[rc.posted as usize % TX_SLOTS as usize] = op;
        rc.posted = rc.posted.wrapping_add(1);
        Ok(())
    }

    /// Sends `data` as one message; the peer needs a receive ready.
    pub fn rc_send(&mut self, id: RcId, data: &[u8]) -> Result<(), NetError> {
        self.rc_post(id, Op::Send, None, Some(data), data.len())
    }

    /// Writes `data` at bus address `remote_addr` in the peer's window
    /// (`rkey` is the key it gave).
    pub fn rc_write(&mut self, id: RcId, remote_addr: u64, rkey: u32, data: &[u8]) -> Result<(), NetError> {
        self.rc_post(id, Op::Write, Some((remote_addr, rkey)), Some(data), data.len())
    }

    /// Reads `len` bytes at bus address `remote_addr` in the peer's window.
    /// They arrive with [`RcEvent::Read`].
    pub fn rc_read(&mut self, id: RcId, remote_addr: u64, rkey: u32, len: usize) -> Result<(), NetError> {
        self.rc_post(id, Op::Read { len }, Some((remote_addr, rkey)), None, len)
    }

    /// Reports the next thing that happened on `id`, if anything: a send,
    /// write or read finished, or a message arrived (into `buf`), or the
    /// connection failed.
    pub fn rc_poll(&mut self, id: RcId, buf: &mut [u8]) -> Option<RcEvent> {
        let rc = self.rc_mut(id)?;
        rc.q.poll_cq();
        if rc.reported != rc.q.tx_done {
            let n = rc.reported;
            rc.reported = n.wrapping_add(1);
            let syndrome = rc.q.tx_syndrome[n as usize % SQ_ENTRIES as usize];
            if syndrome != 0 {
                rc.state = RcState::Failed;
                return Some(RcEvent::Failed(RcFailure::from_syndrome(syndrome)));
            }
            return Some(match rc.ops[n as usize % TX_SLOTS as usize] {
                Op::Send => RcEvent::Sent,
                Op::Write => RcEvent::Written,
                Op::Read { len } => match buf.get_mut(..len) {
                    Some(dst) => {
                        rc.q.mem.tx.read((n as usize % TX_SLOTS as usize) * MAX_MESSAGE, dst);
                        RcEvent::Read { len }
                    }
                    None => RcEvent::Failed(RcFailure::BufferTooSmall),
                },
            });
        }
        let got = rc.q.next_received()?;
        let event = if got.error {
            rc.state = RcState::Failed;
            RcEvent::Failed(RcFailure::from_syndrome(got.syndrome))
        } else if let Some(dst) = buf.get_mut(..got.len as usize) {
            rc.q.read_rx(got.slot, 0, dst);
            RcEvent::Received { len: got.len as usize }
        } else {
            RcEvent::Failed(RcFailure::BufferTooSmall)
        };
        rc.q.repost();
        Some(event)
    }

    /// Copies `dst.len()` bytes from `offset` in the connection's window,
    /// where the peer's writes land.
    pub fn rc_window_read(&self, id: RcId, offset: usize, dst: &mut [u8]) -> Result<(), Mlx4Error> {
        let rc = self.rc_ref(id).ok_or(Mlx4Error::BadParameter)?;
        if offset.checked_add(dst.len()).is_none_or(|end| end > WINDOW_LEN) {
            return Err(Mlx4Error::BadParameter);
        }
        rc.window.read(offset, dst);
        Ok(())
    }

    /// Copies `src` to `offset` in the connection's window, where the peer's
    /// reads look.
    pub fn rc_window_write(&self, id: RcId, offset: usize, src: &[u8]) -> Result<(), Mlx4Error> {
        let rc = self.rc_ref(id).ok_or(Mlx4Error::BadParameter)?;
        if offset.checked_add(src.len()).is_none_or(|end| end > WINDOW_LEN) {
            return Err(Mlx4Error::BadParameter);
        }
        rc.window.write(offset, src);
        Ok(())
    }

    /// The window of `id`, for the peer.
    pub fn rc_window(&self, id: RcId) -> Option<RcWindow> {
        self.rc_ref(id).map(|rc| RcWindow { addr: rc.window.device_addr().as_u64(), rkey: rc.rkey, len: WINDOW_LEN })
    }

    /// Destroys `id`: the queue pair is reset and the window taken back.
    pub fn rc_destroy(&mut self, id: RcId) {
        if let Some(slot) = self.rc.get_mut(id.0 as usize) {
            *slot = None;
        }
    }
}
