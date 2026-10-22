//! An InfiniBand port: queue pair 0 and 1 for management, and an
//! unreliable datagram (UD) queue pair for data, each with its own
//! completion queue.
//!
//! The port is brought up the way `mlx4_ib` does: SET_PORT with the
//! capability mask the firmware already advertises, then queue pair 0 is
//! created and taken to ready-to-receive, which is when the port is
//! initialized (INIT_PORT) and the link starts to train. The firmware does
//! not answer subnet management packets on its own: they arrive on queue
//! pair 0, and [`IbPort::service`] hands each to the firmware's agent
//! (MAD_IFC) and sends its answer back. Until a subnet manager has
//! configured the port through those packets, it has no LID and stays in
//! the initializing state, so `service` must run regularly (from the idle
//! loop or after the completion interrupt) for the whole life of the port.
//!
//! A datagram goes out as a send entry of a control segment, a datagram
//! segment carrying the address vector, queue pair number and queue key,
//! and one data segment. Every received datagram is preceded in its buffer
//! by a 40-byte global route header slot, filled in only if the sender
//! used one. The special queue pairs build the local, global and transport
//! headers themselves ("MLX" send entries) and the device appends the
//! checksum. All of them share the rings of [`Queues`] with the Ethernet
//! port.
//!
//! Multicast groups are attached to the queue pair directly in the
//! adapter's group table, one hash bucket per group; a group whose bucket
//! another group holds cannot be attached (no chaining into the auxiliary
//! entries).

use osmium_hal::dma::DmaAllocator;
use osmium_hal::net::NetError;

use super::cmd::{Ctx, Input, op};
mod rc;

use super::mad::{self, CLASS_PERF, GrhFields, LID_PERMISSIVE, MAD_LEN, MadWc, QP1_QKEY, UdHeader};
use super::queue::{
    CTRL_COMPLETE, Geometry, OPCODE_SEND, QpSetup, Queues, RC_QPS, SEG_LEN, SET_DATA, SET_QP0, SET_QP1, optpar,
};
use super::{LOG_NUM_MCGS, MCG_ENTRY_LEN, Mlx4, Mlx4Error, PD, put32};

pub use super::mad::GRH_LEN;
pub use rc::{MAX_MESSAGE, RcEvent, RcFailure, RcId, RcInfo, RcParams, RcState, RcWindow, WINDOW_LEN};

/// The IB MTU enumeration value of 4096 bytes.
const IB_MTU_4096: u32 = 5;
/// Largest datagram payload the buffers hold.
pub const MAX_PAYLOAD: usize = 4096;
const RX_SLOT_LEN: usize = (GRH_LEN + MAX_PAYLOAD).next_multiple_of(64);
/// Receive slot of the special queue pairs: the header slot and a datagram.
const MAD_SLOT_LEN: usize = (GRH_LEN + MAD_LEN).next_multiple_of(64);
/// The context's MTU (4096) and maximum message size as `mlx4_ib` programs
/// them: 2^11 for the special queue pairs, 2^13 for datagram ones.
const MTU_MSGMAX_SPECIAL: u32 = IB_MTU_4096 << 5 | 11;
const MTU_MSGMAX_UD: u32 = IB_MTU_4096 << 5 | 13;
/// The schedule queue of a port's queue pair 0 and of the others (low bits;
/// the port selects bit 6, the service level bits 2–5).
const SCHED_QP0: u32 = 0x3f;
const SCHED_DEFAULT: u32 = 0x83;

// SET_PORT with operation modifier 0 (InfiniBand): which fields to change,
// and where the values sit.
const SET_PORT_INFINIBAND: u8 = 0;
const CHANGE_VL_CAP: u32 = 1 << 21;
const CHANGE_MTU_CAP: u32 = 1 << 22;
const SET_PORT_VL_CAP_SHIFT: u32 = 4;
const SET_PORT_MTU_CAP_SHIFT: u32 = 12;
/// The firmware's "exceeds device limits" status, which SET_PORT answers
/// when the port cannot do that many virtual lanes.
const STATUS_EXCEED_LIMITS: u8 = 0x08;

const SEND_SEGMENTS: usize = 5;
const DATAGRAM_SEG: usize = SEG_LEN;
const DATA_SEG: usize = DATAGRAM_SEG + 48;

// Send control flags of the "MLX" entries.
const MLX_VL15: u32 = 1 << 17;
const MLX_SLR: u32 = 1 << 16;
const INLINE: u32 = 1 << 31;

// Subnet management attributes.
const ATTR_NODE_INFO: u16 = 0x0011;
const ATTR_GUID_INFO: u16 = 0x0014;
const ATTR_PORT_INFO: u16 = 0x0015;
const ATTR_PKEY_TABLE: u16 = 0x0016;
/// The MAD status for an attribute modifier out of range, which is what the
/// agent would answer for a table index past the end.
const MAD_INVALID_FIELD: u16 = 0x001c;
/// Where a subnet management attribute's data starts in the reply.
const MAD_DATA: usize = 16;
const GUIDS_PER_BLOCK: u16 = 8;
const PKEYS_PER_BLOCK: u16 = 32;

/// Multicast groups one port tracks (and detaches on close).
const MAX_GROUPS: usize = 4;
/// Queue pairs one group table entry holds.
const MCG_QPS: usize = (MCG_ENTRY_LEN as usize - 32) / 4;
/// General services datagrams kept for the caller while `service` runs.
const BACKLOG: usize = 4;

const _: () = assert!(DATA_SEG + SEG_LEN <= 128);
const _: () = assert!(SEND_SEGMENTS * SEG_LEN == DATA_SEG + SEG_LEN);
const _: () = assert!(MCG_QPS == 8 && LOG_NUM_MCGS <= 16);

/// A 128-bit global identifier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Gid(pub [u8; 16]);

impl Gid {
    /// The GID made of a subnet prefix and an interface ID.
    pub fn new(prefix: u64, guid: u64) -> Self {
        let mut gid = [0; 16];
        gid[..8].copy_from_slice(&prefix.to_be_bytes());
        gid[8..].copy_from_slice(&guid.to_be_bytes());
        Self(gid)
    }

    /// The subnet prefix.
    pub fn prefix(&self) -> u64 {
        u64::from_be_bytes(self.0[..8].try_into().expect("8 bytes"))
    }

    /// The interface ID.
    pub fn guid(&self) -> u64 {
        u64::from_be_bytes(self.0[8..].try_into().expect("8 bytes"))
    }
}

/// A port's logical state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortState {
    /// No link.
    Down,
    /// Linked, waiting for the subnet manager.
    Initializing,
    /// Configured by the subnet manager, not yet carrying data traffic.
    Armed,
    /// Carrying traffic.
    Active,
    /// A value the specification does not define.
    Unknown(u8),
}

impl PortState {
    fn from_bits(bits: u32) -> Self {
        match bits {
            1 => Self::Down,
            2 => Self::Initializing,
            3 => Self::Armed,
            4 => Self::Active,
            other => Self::Unknown(other as u8),
        }
    }
}

/// What the port's subnet management agent reports about it (PortInfo).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortInfo {
    /// The LID the subnet manager assigned, 0 if none yet.
    pub lid: u16,
    /// The subnet manager's LID.
    pub sm_lid: u16,
    /// The subnet manager's service level.
    pub sm_sl: u8,
    /// Low bits of the LID that select among the port's paths.
    pub lmc: u8,
    /// The logical state.
    pub state: PortState,
    /// The physical link state (5 is link-up, 2 is polling).
    pub physical_state: u8,
    /// The advertised capability mask.
    pub capability_mask: u32,
    /// The subnet prefix half of GID 0.
    pub gid_prefix: u64,
    /// The negotiated MTU in bytes, or 0 if the port has not agreed one.
    pub mtu: usize,
}

/// A global route header's addressing, for datagrams that leave the subnet
/// or travel to a multicast group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// The destination GID.
    pub dgid: Gid,
    /// Which of the port's GIDs is the source.
    pub sgid_index: u8,
    /// Hop limit.
    pub hop_limit: u8,
    /// Traffic class.
    pub traffic_class: u8,
    /// Flow label (20 bits).
    pub flow_label: u32,
}

/// Where a datagram goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Destination {
    /// The destination LID (a multicast LID for a group).
    pub lid: u16,
    /// The destination queue pair number (`0xff_ffff` for a group).
    pub qpn: u32,
    /// The destination's queue key.
    pub qkey: u32,
    /// Service level.
    pub sl: u8,
    /// The low bits of the source LID to send from (see [`PortInfo::lmc`]).
    pub path_bits: u8,
    /// The global route, if the datagram carries a global route header.
    pub route: Option<Route>,
}

impl Destination {
    /// A destination on the local subnet: service level 0, no global route.
    pub fn local(lid: u16, qpn: u32, qkey: u32) -> Self {
        Self { lid, qpn, qkey, sl: 0, path_bits: 0, route: None }
    }
}

/// The global route header of a received datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalHeader {
    /// The sender's GID.
    pub src: Gid,
    /// The GID the datagram was addressed to.
    pub dst: Gid,
    /// Hop limit left.
    pub hop_limit: u8,
    /// Traffic class.
    pub traffic_class: u8,
    /// Flow label (20 bits).
    pub flow_label: u32,
}

/// A received datagram's sender and how it arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Datagram {
    /// Payload bytes copied to the caller's buffer.
    pub len: usize,
    /// The sender's LID.
    pub src_lid: u16,
    /// The sender's queue pair number.
    pub src_qpn: u32,
    /// The service level it travelled on.
    pub sl: u8,
    /// The destination LID's low bits it was sent to.
    pub path_bits: u8,
    /// The global route header, if the sender used one.
    pub grh: Option<GlobalHeader>,
}

/// What QUERY_PORT says an InfiniBand port can do.
#[derive(Clone, Copy)]
struct PortCaps {
    mtu: u32,
    gids: u16,
    pkeys: u16,
}

/// A management datagram taken from a special queue pair.
#[derive(Clone)]
pub(super) struct RxMad {
    pub mad: [u8; MAD_LEN],
    pub slid: u16,
    pub src_qpn: u32,
    pub sl: u8,
    pub path_bits: u8,
    pub pkey_index: u8,
    /// The global route header, if the sender used one.
    pub grh: Option<[u8; GRH_LEN]>,
}

/// Where a management datagram goes.
pub(super) struct MadDest {
    pub lid: u16,
    pub qpn: u32,
    pub qkey: u32,
    pub sl: u8,
    pub path_bits: u8,
    pub pkey: u16,
    pub grh: Option<GrhFields>,
}

/// Queue pair 0 or 1 of a port.
struct Special<'h, 'd, D: DmaAllocator + ?Sized> {
    q: Queues<'h, 'd, D>,
    /// The packet sequence number of the next send.
    psn: u32,
}

/// Runs `f` with the transitions of a special queue pair: queue key `qkey`
/// (0 for queue pair 0, [`QP1_QKEY`] for 1), schedule queue `sched`.
fn with_special_setup<R>(qkey: u32, sched: u32, port: u32, f: impl FnOnce(&QpSetup<'_>) -> R) -> R {
    let init = |c: &mut Ctx| {
        c.set(8, 0, 8, 0); // partition key index 0
        c.set(44, 0, 32, qkey);
    };
    let rtr = |c: &mut Ctx| {
        c.set(16, 24, 8, (port - 1) << 6 | sched);
    };
    f(&QpSetup {
        service: 7, // "MLX": the header is built in the send entry
        init_mtu_msgmax: MTU_MSGMAX_SPECIAL,
        mtu_msgmax: MTU_MSGMAX_SPECIAL,
        init_optpar: optpar::PKEY_INDEX | optpar::Q_KEY,
        rtr_optpar: 0,
        rts_optpar: 0,
        init: &init,
        rtr: &rtr,
        rts: &|_| {},
    })
}

/// Runs `f` with the transitions of the datagram queue pair: queue key
/// `qkey`.
fn with_ud_setup<R>(qkey: u32, port: u32, f: impl FnOnce(&QpSetup<'_>) -> R) -> R {
    let init = |c: &mut Ctx| {
        c.set(8, 0, 8, 0); // partition key index 0: the default partition
        c.set(44, 0, 32, qkey);
    };
    let rtr = |c: &mut Ctx| {
        c.set(16, 24, 8, (port - 1) << 6 | SCHED_DEFAULT);
    };
    f(&QpSetup {
        service: 3, // unreliable datagram
        init_mtu_msgmax: MTU_MSGMAX_UD,
        mtu_msgmax: MTU_MSGMAX_UD,
        init_optpar: optpar::PKEY_INDEX | optpar::Q_KEY,
        rtr_optpar: 0,
        rts_optpar: 0,
        init: &init,
        rtr: &rtr,
        rts: &|_| {},
    })
}

impl<'h, 'd, D: DmaAllocator + ?Sized> Special<'h, 'd, D> {
    fn new(hca: &'h Mlx4<'d, D>, port: u8, set: u8) -> Result<Self, Mlx4Error> {
        let geometry = Geometry { rx_slot: MAD_SLOT_LEN, tx_slot: MAD_LEN, lso: 0 };
        Ok(Self { q: Queues::new(hca, port, set, geometry)?, psn: 0 })
    }

    fn is_qp0(&self) -> bool {
        self.q.qpn == self.q.hca.special_qpn() + self.q.port as u32 - 1
    }

    /// (queue key, schedule queue, port) of this queue pair.
    fn params(&self) -> (u32, u32, u32) {
        if self.is_qp0() { (0, SCHED_QP0, self.q.port as u32) } else { (QP1_QKEY, SCHED_DEFAULT, self.q.port as u32) }
    }

    /// Takes the queue pair from reset to ready-to-receive.
    fn ready_to_receive(&mut self) -> Result<(), Mlx4Error> {
        let (qkey, sched, port) = self.params();
        with_special_setup(qkey, sched, port, |s| {
            self.q.qp_init(s)?;
            self.q.qp_rtr(s)
        })
    }

    fn ready_to_send(&mut self) -> Result<(), Mlx4Error> {
        let (qkey, sched, port) = self.params();
        with_special_setup(qkey, sched, port, |s| self.q.qp_rts(s))
    }

    /// Sends one management datagram as an "MLX" entry: a control segment
    /// holding the routing, the packed headers inline, the datagram, and an
    /// inline segment where the device puts the checksum.
    fn send(&mut self, vl: u8, dest: &MadDest, mad: &[u8; MAD_LEN]) -> Result<(), NetError> {
        if self.q.tx_full() {
            self.q.poll_cq();
            if self.q.tx_full() {
                return Err(NetError::WouldBlock);
            }
        }
        let permissive = dest.lid == LID_PERMISSIVE;
        let header = UdHeader {
            vl,
            sl: dest.sl,
            dlid: dest.lid,
            // The device fills in the LID; the packet carries the path bits
            // it is to be added to, or the permissive LID of a directed route.
            slid: if permissive { LID_PERMISSIVE } else { dest.path_bits as u16 & 0x7f },
            grh: dest.grh,
            pkey: dest.pkey,
            solicited: false,
            dest_qpn: dest.qpn,
            psn: self.psn,
            qkey: dest.qkey,
            src_qpn: self.q.qpn,
            payload: MAD_LEN,
        };
        self.psn = self.psn.wrapping_add(1) & 0xff_ffff;
        let mut packed = [0u8; mad::UD_HEADER_MAX];
        let n = header.pack(&mut packed);

        let (wqe, slot) = self.q.begin_send();
        self.q.mem.tx.write(slot, mad);
        let buf = self.q.mem.tx.device_addr().as_u64() + slot as u64;
        let lkey = self.q.hca.lkey;
        let wq = self.q.wq();

        // Inline segments may not cross a 64-byte boundary, so a header that
        // does not fit up to the next one takes two.
        let inline = wqe + SEG_LEN;
        let room = 64 - ((inline + 4) % 64);
        let seg_len = if n <= room {
            put32(wq, inline, INLINE | n as u32);
            wq.write(inline + 4, &packed[..n]);
            (4 + n).next_multiple_of(16)
        } else {
            put32(wq, inline, INLINE | room as u32);
            wq.write(inline + 4, &packed[..room]);
            let second = inline + 4 + room;
            wq.write(second + 4, &packed[room..n]);
            put32(wq, second, INLINE | (n - room) as u32);
            (8 + n).next_multiple_of(16)
        };
        let data = wqe + SEG_LEN + seg_len;
        put32(wq, data, MAD_LEN as u32);
        put32(wq, data + 4, lkey);
        wq.store(data + 8, buf.to_be());
        let icrc = data + SEG_LEN;
        put32(wq, icrc + 4, 0);
        put32(wq, icrc, INLINE | 4);

        let flags = CTRL_COMPLETE & !2 // completion, not solicited
            | if self.is_qp0() { MLX_VL15 } else { 0 }
            | if permissive { MLX_SLR } else { 0 }
            | (dest.sl as u32 & 0xf) << 8;
        put32(wq, wqe + 4, ((SEG_LEN + seg_len + 2 * SEG_LEN) / SEG_LEN) as u32);
        put32(wq, wqe + 8, flags);
        put32(wq, wqe + 12, (dest.lid as u32) << 16);
        self.q.finish_send(wqe, OPCODE_SEND);
        Ok(())
    }

    /// Takes the next received management datagram.
    fn receive(&mut self) -> Option<RxMad> {
        loop {
            let got = self.q.next_received()?;
            let ok = !got.error && got.len as usize >= GRH_LEN + MAD_LEN;
            let rx = ok.then(|| {
                let mut mad = [0u8; MAD_LEN];
                self.q.read_rx(got.slot, GRH_LEN, &mut mad);
                let grh = got.grh.then(|| {
                    let mut raw = [0u8; GRH_LEN];
                    self.q.read_rx(got.slot, 0, &mut raw);
                    raw
                });
                RxMad {
                    mad,
                    slid: got.src_lid,
                    src_qpn: got.src_qpn,
                    sl: got.sl,
                    path_bits: got.src_path_bits,
                    pkey_index: got.pkey_index,
                    grh,
                }
            });
            self.q.repost();
            if rx.is_some() {
                return rx;
            }
        }
    }
}

/// A port of an [`Mlx4`] in InfiniBand mode. Dropping it detaches its
/// multicast groups, closes the port and frees its queues.
pub struct IbPort<'h, 'd, D: DmaAllocator + ?Sized> {
    // Dropped in this order: queue pair 0 last, since resetting it is what
    // closes the port.
    ud: Queues<'h, 'd, D>,
    rc: [Option<rc::Rc<'h, 'd, D>>; RC_QPS as usize],
    gsi: Special<'h, 'd, D>,
    smi: Special<'h, 'd, D>,
    qkey: u32,
    mtu: u32,
    gids: u16,
    pkeys: u16,
    /// The SL-to-VL table (four bits per service level), as the subnet
    /// manager last set it.
    sl2vl: [u8; 8],
    groups: [Option<Gid>; MAX_GROUPS],
    backlog: [Option<RxMad>; BACKLOG],
}

impl<'h, 'd, D: DmaAllocator + ?Sized> IbPort<'h, 'd, D> {
    pub(super) fn open(hca: &'h Mlx4<'d, D>, port: u8, qkey: u32) -> Result<Self, Mlx4Error> {
        let mut query = Ctx::new();
        hca.hcr.exec_out(op::QUERY_PORT, 0, port as u32, Input::None, &mut query, 64)?;
        let (ib, eth) = (query.get(0, 24, 1) != 0, query.get(0, 25, 1) != 0);
        let infiniband = match (ib, eth) {
            (false, _) => false,
            (true, true) if hca.caps.dpdp => hca.sense_port(port)?.is_none_or(|sensed| !sensed.is_ethernet()),
            _ => true,
        };
        if !infiniband {
            return Err(Mlx4Error::NotInfiniBand);
        }
        hca.set_link(port, query.get(0, 31, 1) != 0);
        let caps = PortCaps {
            mtu: query.get(0, 16, 4).min(IB_MTU_4096),
            gids: 1 << query.get(1, 4, 4),
            pkeys: 1 << query.get(1, 0, 4),
        };
        if caps.mtu == 0 {
            return Err(Mlx4Error::BadDevice);
        }

        // The capability mask the port advertises is the one it already has.
        let capability_mask = hca.query_mad(port, ATTR_PORT_INFO, port as u32)?.dword(MAD_DATA + 5);
        Self::set_port(hca, port, &caps, capability_mask)?;

        // Queue pair 0 first: its transition to ready-to-receive starts the
        // port, and the others follow once it is up. The locals drop in the
        // reverse order, queue pair 0 last, if anything fails.
        let mut smi = Special::new(hca, port, SET_QP0)?;
        smi.q.create_cq()?;
        smi.ready_to_receive()?;
        hca.hcr.exec(op::INIT_PORT, 0, port as u32, Input::None)?;
        smi.q.stage.port_up = true;
        smi.ready_to_send()?;
        smi.q.arm_cq();

        let mut gsi = Special::new(hca, port, SET_QP1)?;
        gsi.q.create_cq()?;
        gsi.ready_to_receive()?;
        gsi.ready_to_send()?;
        gsi.q.arm_cq();

        let geometry = Geometry { rx_slot: RX_SLOT_LEN, tx_slot: MAX_PAYLOAD, lso: 0 };
        let mut ud = Queues::new(hca, port, SET_DATA, geometry)?;
        ud.create_cq()?;
        with_ud_setup(qkey, port as u32, |s| ud.create_qp(s))?;
        ud.arm_cq();

        let mut ib = Self {
            ud,
            rc: [const { None }; RC_QPS as usize],
            gsi,
            smi,
            qkey,
            mtu: caps.mtu,
            gids: caps.gids,
            pkeys: caps.pkeys,
            sl2vl: [0; 8],
            groups: [None; MAX_GROUPS],
            backlog: [const { None }; BACKLOG],
        };
        hca.open.set(hca.open.get() | 1 << (port - 1));
        ib.refresh_sl2vl();
        Ok(ib)
    }

    /// SET_PORT in InfiniBand mode: the capability mask, the MTU limit and the
    /// number of virtual lanes (as many as the port will take).
    fn set_port(hca: &Mlx4<'d, D>, port: u8, caps: &PortCaps, capability_mask: u32) -> Result<(), Mlx4Error> {
        let mut result = Ok(0);
        for vls in [8u32, 4, 2, 1] {
            let mut set = Ctx::new();
            set.set(
                0,
                0,
                32,
                CHANGE_MTU_CAP | CHANGE_VL_CAP | caps.mtu << SET_PORT_MTU_CAP_SHIFT | vls << SET_PORT_VL_CAP_SHIFT,
            );
            set.set(1, 0, 32, capability_mask);
            result = hca.hcr.exec(op::SET_PORT, SET_PORT_INFINIBAND, port as u32, Input::Mailbox(&set, 256));
            if !matches!(result, Err(Mlx4Error::Command { status: STATUS_EXCEED_LIMITS, .. })) {
                break;
            }
        }
        result.map(drop)
    }

    /// The port number (1-based).
    pub fn port(&self) -> u8 {
        self.ud.port
    }

    /// The queue pair number datagrams to this port are addressed to.
    pub fn qpn(&self) -> u32 {
        self.ud.qpn
    }

    /// The queue key datagrams must carry to be received.
    pub fn qkey(&self) -> u32 {
        self.qkey
    }

    /// Largest datagram payload, in bytes: the port's MTU limit.
    pub fn max_payload(&self) -> usize {
        128 << self.mtu
    }

    /// Entries in the port's GID table.
    pub fn gid_table_len(&self) -> u16 {
        self.gids
    }

    /// Entries in the port's partition key table.
    pub fn pkey_table_len(&self) -> u16 {
        self.pkeys
    }

    /// True if the port's link is up, as last reported by the adapter's
    /// events (the logical state is in [`query`](Self::query)).
    pub fn link_up(&self) -> bool {
        self.ud.hca.link_up(self.ud.port)
    }

    /// Asks the firmware's subnet management agent for the port's state,
    /// LID and the rest of PortInfo.
    pub fn query(&self) -> Result<PortInfo, Mlx4Error> {
        let m = self.ud.hca.query_mad(self.ud.port, ATTR_PORT_INFO, self.ud.port as u32)?;
        let d = |dw: usize| MAD_DATA + dw;
        let mtu = match m.get(d(9), 28, 4) {
            n @ 1..=5 => 128 << n,
            _ => 0,
        };
        Ok(PortInfo {
            gid_prefix: (m.dword(d(2)) as u64) << 32 | m.dword(d(3)) as u64,
            lid: m.get(d(4), 16, 16) as u16,
            sm_lid: m.get(d(4), 0, 16) as u16,
            capability_mask: m.dword(d(5)),
            state: PortState::from_bits(m.get(d(8), 24, 4)),
            physical_state: m.get(d(8), 20, 4) as u8,
            lmc: m.get(d(8), 8, 3) as u8,
            sm_sl: m.get(d(9), 24, 4) as u8,
            mtu,
        })
    }

    /// True once the subnet manager has made the port active.
    pub fn is_active(&self) -> Result<bool, Mlx4Error> {
        Ok(self.query()?.state == PortState::Active)
    }

    /// GID table entry `index`: the subnet prefix and the entry's GUID.
    pub fn gid(&self, index: u16) -> Result<Gid, Mlx4Error> {
        if index >= self.gids {
            return Err(Mlx4Error::Mad(MAD_INVALID_FIELD));
        }
        let guids = self.ud.hca.query_mad(self.ud.port, ATTR_GUID_INFO, (index / GUIDS_PER_BLOCK) as u32)?;
        let at = MAD_DATA + 2 * (index % GUIDS_PER_BLOCK) as usize;
        let guid = (guids.dword(at) as u64) << 32 | guids.dword(at + 1) as u64;
        Ok(Gid::new(self.query()?.gid_prefix, guid))
    }

    /// Partition key table entry `index`.
    pub fn pkey(&self, index: u16) -> Result<u16, Mlx4Error> {
        if index >= self.pkeys {
            return Err(Mlx4Error::Mad(MAD_INVALID_FIELD));
        }
        let keys = self.ud.hca.query_mad(self.ud.port, ATTR_PKEY_TABLE, (index / PKEYS_PER_BLOCK) as u32)?;
        let entry = (index % PKEYS_PER_BLOCK) as usize;
        Ok(keys.get(MAD_DATA + entry / 2, if entry % 2 == 0 { 16 } else { 0 }, 16) as u16)
    }

    /// The node GUID shared by the adapter's ports.
    pub fn node_guid(&self) -> Result<u64, Mlx4Error> {
        let m = self.ud.hca.query_mad(self.ud.port, ATTR_NODE_INFO, 0)?;
        Ok((m.dword(MAD_DATA + 3) as u64) << 32 | m.dword(MAD_DATA + 4) as u64)
    }

    /// Reads the SL-to-VL table the agent holds, for the special queue
    /// pairs' packets.
    fn refresh_sl2vl(&mut self) {
        if let Ok(m) = self.ud.hca.query_mad(self.ud.port, mad::ATTR_SL_TO_VL_TABLE, 0) {
            self.sl2vl[..4].copy_from_slice(&m.dword(MAD_DATA).to_be_bytes());
            self.sl2vl[4..].copy_from_slice(&m.dword(MAD_DATA + 1).to_be_bytes());
        }
    }

    /// The virtual lane service level `sl` maps to.
    fn vl_for(&self, sl: u8) -> u8 {
        let both = self.sl2vl[(sl >> 1 & 7) as usize];
        if sl & 1 != 0 { both & 0xf } else { both >> 4 }
    }

    /// Does the work the port needs done to stay on the fabric: answers the
    /// subnet manager's packets on queue pair 0 and performance queries on
    /// queue pair 1, and keeps other general services datagrams for
    /// the subnet administration client. Call it whenever a completion
    /// may have arrived (after an interrupt, or from the idle loop); a port
    /// whose queue pair 0 is not served cannot be configured and times out
    /// on the fabric.
    pub fn service(&mut self) {
        while let Some(rx) = self.smi.receive() {
            self.handle_subnet_management(rx);
        }
        while let Some(rx) = self.gsi.receive() {
            self.handle_general(rx);
        }
    }

    /// True if a management datagram is waiting for [`service`](Self::service).
    pub fn management_pending(&self) -> bool {
        self.smi.q.can_receive() || self.gsi.q.can_receive()
    }

    /// The adapter's clock.
    pub(super) fn now_ns(&self) -> u64 {
        self.ud.hca.clock.now_ns()
    }

    /// Changes the queue key of the datagram queue pair, as a multicast
    /// group's queue key (IPoIB's) requires after joining.
    pub fn set_qkey(&mut self, qkey: u32) -> Result<(), Mlx4Error> {
        let port = self.ud.port as u32;
        with_ud_setup(self.qkey, port, |s| self.ud.qp_set_qkey(s, qkey))?;
        self.qkey = qkey;
        Ok(())
    }

    /// Takes a general services datagram that `service` did not answer
    /// itself (a subnet administration reply, for example).
    pub(super) fn take_general(&mut self) -> Option<RxMad> {
        self.backlog.iter_mut().find_map(Option::take)
    }

    /// Sends a general services datagram from queue pair 1.
    pub(super) fn send_general(&mut self, dest: &MadDest, mad: &[u8; MAD_LEN]) -> Result<(), NetError> {
        let vl = self.vl_for(dest.sl);
        self.gsi.send(vl, dest, mad)
    }

    /// The reply address for a datagram received on a special queue pair.
    fn reply_to(&self, rx: &RxMad, qp0: bool) -> MadDest {
        let pkey = if qp0 { 0 } else { self.pkey(rx.pkey_index as u16).unwrap_or(0xffff) };
        let pkey = if qp0 { self.pkey(0).unwrap_or(0xffff) } else { pkey };
        MadDest {
            lid: rx.slid,
            qpn: rx.src_qpn,
            qkey: if qp0 { 0 } else { QP1_QKEY },
            sl: rx.sl,
            path_bits: rx.path_bits,
            pkey,
            grh: rx.grh.map(|raw| {
                let first = mad::be32(&raw, 0);
                GrhFields {
                    traffic_class: (first >> 20) as u8,
                    flow_label: first & 0xf_ffff,
                    hop_limit: raw[7],
                    source: raw[24..40].try_into().expect("16 bytes"),
                    dest: raw[8..24].try_into().expect("16 bytes"),
                }
            }),
        }
    }

    /// Passes a datagram to the firmware's management agent and returns its
    /// answer, if it has one.
    fn run_agent(&self, rx: &RxMad, qp0: bool) -> Option<[u8; MAD_LEN]> {
        let wc = MadWc {
            slid: rx.slid,
            my_qpn: if qp0 { self.smi.q.qpn } else { self.gsi.q.qpn },
            src_qpn: rx.src_qpn,
            sl: rx.sl,
            path_bits: rx.path_bits,
            pkey_index: rx.pkey_index,
            grh: rx.grh,
        };
        self.ud.hca.mad_ifc(self.ud.port, &rx.mad, Some(&wc)).ok()
    }

    fn handle_subnet_management(&mut self, rx: RxMad) {
        let mut request = rx.mad;
        let (class, method) = (request[1], request[3]);
        if method == mad::METHOD_TRAP && rx.slid == 0 {
            return; // a trap from a neighbor; this port has no subnet manager to tell
        }
        let routed = match class {
            mad::CLASS_SUBN_LID_ROUTED | mad::CLASS_SUBN_DIRECTED_ROUTE => {
                matches!(method, mad::METHOD_GET | mad::METHOD_SET | mad::METHOD_TRAP_REPRESS)
                    && mad::be16(&request, 16) != mad::ATTR_SM_INFO // the agent cannot answer SMInfo
            }
            _ => false,
        };
        if !routed {
            return;
        }
        let directed = class == mad::CLASS_SUBN_DIRECTED_ROUTE;
        if directed && !mad::dr_receive(&mut request, self.ud.port) {
            return;
        }
        let forwarded = RxMad { mad: request, ..rx.clone() };
        let Some(mut reply) = self.run_agent(&forwarded, true) else { return };
        if mad::be16(&reply, 4) == 0 {
            self.snoop(&request, &reply);
        }
        if directed && !mad::dr_respond(&mut reply, self.ud.port) {
            return;
        }
        if method == mad::METHOD_TRAP_REPRESS {
            return; // no answer to a repress
        }
        let dest = self.reply_to(&rx, true);
        let _ = self.smi.send(15, &dest, &reply);
    }

    /// Keeps up with what the subnet manager changes that this driver uses.
    fn snoop(&mut self, request: &[u8; MAD_LEN], reply: &[u8; MAD_LEN]) {
        if request[3] == mad::METHOD_SET && mad::be16(request, 16) == mad::ATTR_SL_TO_VL_TABLE {
            self.sl2vl.copy_from_slice(&reply[64..72]);
        }
    }

    fn handle_general(&mut self, rx: RxMad) {
        let (class, method) = (rx.mad[1], rx.mad[3]);
        if class == CLASS_PERF && matches!(method, mad::METHOD_GET | mad::METHOD_SET) {
            if let Some(reply) = self.run_agent(&rx, false) {
                let dest = self.reply_to(&rx, false);
                let vl = self.vl_for(dest.sl);
                let _ = self.gsi.send(vl, &dest, &reply);
            }
        } else if let Some(slot) = self.backlog.iter_mut().find(|s| s.is_none()) {
            *slot = Some(rx);
        }
    }

    /// Sends `payload` as one datagram to `dest`.
    ///
    /// The datagram is dropped by the fabric if the port is not active, the
    /// queue key is wrong or `payload` exceeds the path's MTU.
    pub fn send(&mut self, dest: &Destination, payload: &[u8]) -> Result<(), NetError> {
        if payload.len() > self.max_payload() {
            return Err(NetError::TooLarge);
        }
        if self.ud.tx_full() {
            self.ud.poll_cq();
            if self.ud.tx_full() {
                return Err(NetError::WouldBlock);
            }
        }
        let (wqe, slot) = self.ud.begin_send();
        self.ud.mem.tx.write(slot, payload);
        let buf = self.ud.mem.tx.device_addr().as_u64() + slot as u64;
        let lkey = self.ud.hca.lkey;
        let port = self.ud.port;
        let wq = self.ud.wq();
        put32(wq, wqe + 4, SEND_SEGMENTS as u32);
        put32(wq, wqe + 8, CTRL_COMPLETE);

        // The datagram segment: address vector, then queue pair and key.
        let av = wqe + DATAGRAM_SEG;
        let (route, grh) = (dest.route.unwrap_or(Route::NONE), dest.route.is_some());
        put32(wq, av, PD | (port as u32) << 24);
        let g_slid = (dest.path_bits & 0x7f) as u32 | if grh { 0x80 } else { 0 };
        put32(wq, av + 4, g_slid << 16 | dest.lid as u32);
        put32(wq, av + 8, (route.sgid_index as u32) << 16 | route.hop_limit as u32); // maximum static rate: 0
        let tclass_flow = (route.traffic_class as u32) << 20 | route.flow_label & 0xf_ffff;
        put32(wq, av + 12, (dest.sl as u32 & 0xf) << 28 | tclass_flow);
        wq.write(av + 16, &route.dgid.0);
        put32(wq, av + 32, dest.qpn & 0xff_ffff);
        put32(wq, av + 36, dest.qkey);

        let data = wqe + DATA_SEG;
        put32(wq, data, payload.len() as u32);
        put32(wq, data + 4, lkey);
        wq.store(data + 8, buf.to_be());
        self.ud.finish_send(wqe, OPCODE_SEND);
        Ok(())
    }

    /// Takes the next received datagram's payload into `buf`.
    ///
    /// A datagram larger than `buf` is dropped ([`NetError::TooLarge`]).
    pub fn receive(&mut self, buf: &mut [u8]) -> Result<Datagram, NetError> {
        let Some(got) = self.ud.next_received() else {
            return Err(NetError::WouldBlock);
        };
        // The device counts the header slot whether or not the sender used one.
        let result = match (got.len as usize).checked_sub(GRH_LEN) {
            Some(len) if !got.error => match buf.get_mut(..len) {
                Some(dst) => {
                    self.ud.read_rx(got.slot, GRH_LEN, dst);
                    Ok(Datagram {
                        len,
                        src_lid: got.src_lid,
                        src_qpn: got.src_qpn,
                        sl: got.sl,
                        path_bits: got.src_path_bits,
                        grh: got.grh.then(|| self.read_grh(got.slot)),
                    })
                }
                None => Err(NetError::TooLarge),
            },
            _ => Err(NetError::Io),
        };
        self.ud.repost();
        result
    }

    fn read_grh(&self, slot: u16) -> GlobalHeader {
        let mut raw = [0u8; GRH_LEN];
        self.ud.read_rx(slot, 0, &mut raw);
        let first = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
        let gid = |at: usize| Gid(raw[at..at + 16].try_into().expect("16 bytes"));
        GlobalHeader {
            src: gid(8),
            dst: gid(24),
            hop_limit: raw[7],
            traffic_class: (first >> 20) as u8,
            flow_label: first & 0xf_ffff,
        }
    }

    /// True if a datagram can be taken now (or after reaping).
    pub fn can_receive(&self) -> bool {
        self.ud.can_receive()
    }

    /// True if a datagram can be posted now (or after reaping).
    pub fn can_transmit(&self) -> bool {
        self.ud.can_transmit()
    }

    /// Attaches the queue pair to multicast group `mgid`, so that
    /// datagrams addressed to the group (and to the group's multicast LID,
    /// once the subnet manager has routed it here) reach this port.
    pub fn attach_multicast(&mut self, mgid: Gid) -> Result<(), Mlx4Error> {
        if self.groups.contains(&Some(mgid)) {
            return Ok(());
        }
        let slot = self.groups.iter().position(Option::is_none).ok_or(Mlx4Error::Multicast)?;
        self.update_group(mgid, true)?;
        self.groups[slot] = Some(mgid);
        Ok(())
    }

    /// Detaches the queue pair from `mgid`.
    pub fn detach_multicast(&mut self, mgid: Gid) -> Result<(), Mlx4Error> {
        let slot = self.groups.iter().position(|g| *g == Some(mgid)).ok_or(Mlx4Error::Multicast)?;
        self.update_group(mgid, false)?;
        self.groups[slot] = None;
        Ok(())
    }

    /// Adds this queue pair to (`attach`) or removes it from the group
    /// table entry of `mgid`.
    fn update_group(&self, mgid: Gid, attach: bool) -> Result<(), Mlx4Error> {
        let hcr = &self.ud.hca.hcr;
        let mut key = Ctx::new();
        for i in 0..4 {
            key.set(i, 0, 32, u32::from_be_bytes(mgid.0[4 * i..4 * i + 4].try_into().expect("4 bytes")));
        }
        let index = (hcr.exec(op::MGID_HASH, 0, 0, Input::Mailbox(&key, 16))? & 0xffff) as u32;
        if index >= 1 << LOG_NUM_MCGS {
            return Err(Mlx4Error::BadDevice);
        }
        let mut entry = Ctx::new();
        hcr.exec_out(op::READ_MCG, 0, index, Input::None, &mut entry, MCG_ENTRY_LEN as usize)?;

        // Dword 1: member count (the protocol bits above it stay zero:
        // InfiniBand). Dwords 4–7: the group's GID. Dwords 8 on: the member
        // queue pair numbers.
        let mut count = (entry.dword(1) & 0xff_ffff) as usize;
        if count > MCG_QPS {
            return Err(Mlx4Error::BadDevice);
        }
        if count > 0 && !(0..4).all(|i| entry.dword(4 + i) == key.dword(i)) {
            return Err(Mlx4Error::Multicast);
        }
        let mut members = [0u32; MCG_QPS];
        for (i, m) in members.iter_mut().enumerate().take(count) {
            *m = entry.dword(8 + i) & 0xff_ffff;
        }
        let found = members[..count].iter().position(|&m| m == self.ud.qpn);
        if attach {
            if found.is_some() {
                return Ok(());
            }
            if count == MCG_QPS {
                return Err(Mlx4Error::Multicast);
            }
            members[count] = self.ud.qpn;
            count += 1;
        } else {
            let at = found.ok_or(Mlx4Error::Multicast)?;
            count -= 1;
            members[at] = members[count];
            members[count] = 0;
        }

        // An empty entry is all zeros, so its bucket can be taken by any group.
        let mut out = Ctx::new();
        if count > 0 {
            out.set(1, 0, 24, count as u32);
            for i in 0..4 {
                out.set(4 + i, 0, 32, key.dword(i));
            }
            for (i, &m) in members.iter().enumerate().take(count) {
                out.set(8 + i, 0, 32, m);
            }
        }
        hcr.exec(op::WRITE_MCG, 0, index, Input::Mailbox(&out, MCG_ENTRY_LEN as usize)).map(drop)
    }
}

impl Route {
    /// What an address vector without a global route header carries.
    const NONE: Self = Self { dgid: Gid([0; 16]), sgid_index: 0, hop_limit: 0, traffic_class: 0, flow_label: 0 };
}

impl<D: DmaAllocator + ?Sized> Drop for IbPort<'_, '_, D> {
    fn drop(&mut self) {
        // The queue pair must not stay in a group table entry once it is gone.
        for group in self.groups.into_iter().flatten() {
            let _ = self.update_group(group, false);
        }
        self.ud.hca.open.set(self.ud.hca.open.get() & !(1 << (self.ud.port - 1)));
    }
}
