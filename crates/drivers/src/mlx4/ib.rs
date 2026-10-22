//! An InfiniBand port: one completion queue and one unreliable datagram
//! (UD) queue pair.
//!
//! The port is brought up the way `mlx4_ib` does: SET_PORT with the
//! capabilities this driver implements (none beyond the firmware's own),
//! INIT_PORT with the table sizes the port reported, then the queues. The
//! link trains and the subnet manager assigns a LID without further help
//! from here, because the subnet management agent (queue pair 0) lives in
//! the firmware; [`IbPort::query`] and friends ask it, through MAD_IFC, how
//! far that has got.
//!
//! A datagram goes out as a send entry of a control segment, a datagram
//! segment carrying the address vector, queue pair number and queue key,
//! and one data segment. Every received datagram is preceded in its buffer
//! by a 40-byte global route header slot, filled in only if the sender
//! used one. Both share the rings of [`Queues`] with the Ethernet port.
//!
//! Multicast groups are attached to the queue pair directly in the
//! adapter's group table, one hash bucket per group; a group whose bucket
//! another group holds cannot be attached (no chaining into the auxiliary
//! entries). Joining a group with the subnet administrator is up to the
//! caller, and needs queue pair 1, which this driver does not implement.

use osmium_hal::dma::DmaAllocator;
use osmium_hal::net::NetError;

use super::cmd::{Ctx, Input, op};
use super::queue::{CTRL_COMPLETE, OPCODE_SEND, QpSetup, Queues, SEG_LEN, optpar};
use super::{LOG_NUM_MCGS, MCG_ENTRY_LEN, Mlx4, Mlx4Error, PD, put32};

/// Bytes of the global route header slot ahead of every received datagram.
pub const GRH_LEN: usize = 40;
/// The IB MTU enumeration value the port is limited to: 2048 bytes.
const IB_MTU_2048: u32 = 4;
/// Largest datagram payload.
pub const MAX_PAYLOAD: usize = 2048;
const RX_SLOT_LEN: usize = (GRH_LEN + MAX_PAYLOAD).next_multiple_of(64);
/// The queue pair context's MTU (4096) and maximum message size (2^11) as
/// `mlx4_ib` programs them for datagram queue pairs.
const QP_MTU_MSGMAX: (u32, u32) = (5, 11);

const SET_PORT_INFINIBAND: u8 = 0;
const SEND_SEGMENTS: usize = 5;
const DATAGRAM_SEG: usize = SEG_LEN;
const DATA_SEG: usize = DATAGRAM_SEG + 48;

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
    width: u32,
    vls: u32,
    gids: u16,
    pkeys: u16,
}

/// A port of an [`Mlx4`] in InfiniBand mode. Dropping it detaches its
/// multicast groups, closes the port and frees its queues.
pub struct IbPort<'h, 'd, D: DmaAllocator + ?Sized> {
    q: Queues<'h, 'd, D>,
    qkey: u32,
    mtu: u32,
    gids: u16,
    pkeys: u16,
    groups: [Option<Gid>; MAX_GROUPS],
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
            mtu: query.get(0, 16, 4).min(IB_MTU_2048),
            width: query.get(1, 8, 4),
            vls: query.get(2, 0, 4),
            gids: 1 << query.get(1, 4, 4),
            pkeys: 1 << query.get(1, 0, 4),
        };
        if caps.mtu == 0 {
            return Err(Mlx4Error::BadDevice);
        }

        let mut ib = Self {
            q: Queues::new(hca, port, RX_SLOT_LEN, MAX_PAYLOAD, 0)?,
            qkey,
            mtu: caps.mtu,
            gids: caps.gids,
            pkeys: caps.pkeys,
            groups: [None; MAX_GROUPS],
        };
        ib.start_port(&caps)?;
        ib.q.create_cq()?;
        ib.create_qp()?;
        ib.q.arm_cq();
        Ok(ib)
    }

    fn start_port(&mut self, caps: &PortCaps) -> Result<(), Mlx4Error> {
        let (hcr, port) = (&self.q.hca.hcr, self.q.port as u32);
        // The capability mask the port advertises: dword 1. This driver
        // implements none of the optional management classes.
        let set = Ctx::new();
        hcr.exec(op::SET_PORT, SET_PORT_INFINIBAND, port, Input::Mailbox(&set, 256))?;

        if self.q.hca.caps.old_port_cmds {
            hcr.exec(op::INIT_PORT, 0, port, Input::None)?;
        } else {
            let mut init = Ctx::new();
            init.set(0, 4, 4, caps.vls).set(0, 8, 4, caps.width);
            init.set(1, 16, 16, 128 << caps.mtu).set(1, 0, 16, caps.gids as u32);
            init.set(2, 0, 16, caps.pkeys as u32);
            hcr.exec(op::INIT_PORT, 0, port, Input::Mailbox(&init, 256))?;
        }
        self.q.stage.port_up = true;
        Ok(())
    }

    fn create_qp(&mut self) -> Result<(), Mlx4Error> {
        let (port, qkey) = (self.q.port as u32, self.qkey);
        let (mtu, msgmax) = QP_MTU_MSGMAX;
        self.q.create_qp(&QpSetup {
            service: 3, // unreliable datagram
            init_optpar: optpar::PKEY_INDEX | optpar::Q_KEY,
            init: &|c| {
                c.set(4, 29, 3, mtu).set(4, 24, 5, msgmax);
                c.set(8, 0, 8, 0); // partition key index 0: the default partition
                c.set(44, 0, 32, qkey);
            },
            rtr: &|c| {
                c.set(4, 29, 3, mtu).set(4, 24, 5, msgmax);
                c.set(16, 24, 8, 0x83 | (port - 1) << 6); // default schedule queue of this port
            },
            rts: &|_| {},
        })
    }

    /// The port number (1-based).
    pub fn port(&self) -> u8 {
        self.q.port
    }

    /// The queue pair number datagrams to this port are addressed to.
    pub fn qpn(&self) -> u32 {
        self.q.qpn
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
        self.q.hca.link_up(self.q.port)
    }

    /// Asks the firmware's subnet management agent for the port's state,
    /// LID and the rest of PortInfo.
    pub fn query(&self) -> Result<PortInfo, Mlx4Error> {
        let m = self.q.hca.query_mad(self.q.port, ATTR_PORT_INFO, 0)?;
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
        let guids = self.q.hca.query_mad(self.q.port, ATTR_GUID_INFO, (index / GUIDS_PER_BLOCK) as u32)?;
        let at = MAD_DATA + 2 * (index % GUIDS_PER_BLOCK) as usize;
        let guid = (guids.dword(at) as u64) << 32 | guids.dword(at + 1) as u64;
        Ok(Gid::new(self.query()?.gid_prefix, guid))
    }

    /// Partition key table entry `index`.
    pub fn pkey(&self, index: u16) -> Result<u16, Mlx4Error> {
        if index >= self.pkeys {
            return Err(Mlx4Error::Mad(MAD_INVALID_FIELD));
        }
        let keys = self.q.hca.query_mad(self.q.port, ATTR_PKEY_TABLE, (index / PKEYS_PER_BLOCK) as u32)?;
        let entry = (index % PKEYS_PER_BLOCK) as usize;
        Ok(keys.get(MAD_DATA + entry / 2, if entry % 2 == 0 { 16 } else { 0 }, 16) as u16)
    }

    /// The node GUID shared by the adapter's ports.
    pub fn node_guid(&self) -> Result<u64, Mlx4Error> {
        let m = self.q.hca.query_mad(self.q.port, ATTR_NODE_INFO, 0)?;
        Ok((m.dword(MAD_DATA + 3) as u64) << 32 | m.dword(MAD_DATA + 4) as u64)
    }

    /// Sends `payload` as one datagram to `dest`.
    ///
    /// The datagram is dropped by the fabric if the port is not active, the
    /// queue key is wrong or `payload` exceeds the path's MTU.
    pub fn send(&mut self, dest: &Destination, payload: &[u8]) -> Result<(), NetError> {
        if payload.len() > self.max_payload() {
            return Err(NetError::TooLarge);
        }
        if self.q.tx_full() {
            self.q.poll_cq();
            if self.q.tx_full() {
                return Err(NetError::WouldBlock);
            }
        }
        let (wqe, slot) = self.q.begin_send();
        self.q.mem.tx.write(slot, payload);
        let buf = self.q.mem.tx.device_addr().as_u64() + slot as u64;
        let wq = self.q.wq();
        put32(wq, wqe + 4, SEND_SEGMENTS as u32);
        put32(wq, wqe + 8, CTRL_COMPLETE);

        // The datagram segment: address vector, then queue pair and key.
        let av = wqe + DATAGRAM_SEG;
        let (route, grh) = (dest.route.unwrap_or(Route::NONE), dest.route.is_some());
        put32(wq, av, PD | (self.q.port as u32) << 24);
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
        put32(wq, data + 4, self.q.hca.lkey);
        wq.store(data + 8, buf.to_be());
        self.q.finish_send(wqe, OPCODE_SEND);
        Ok(())
    }

    /// Takes the next received datagram's payload into `buf`.
    ///
    /// A datagram larger than `buf` is dropped ([`NetError::TooLarge`]).
    pub fn receive(&mut self, buf: &mut [u8]) -> Result<Datagram, NetError> {
        let Some(got) = self.q.next_received() else {
            return Err(NetError::WouldBlock);
        };
        // The device counts the header slot whether or not the sender used one.
        let result = match (got.len as usize).checked_sub(GRH_LEN) {
            Some(len) if !got.error => match buf.get_mut(..len) {
                Some(dst) => {
                    self.q.read_rx(got.slot, GRH_LEN, dst);
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
        self.q.repost();
        result
    }

    fn read_grh(&self, slot: u16) -> GlobalHeader {
        let mut raw = [0u8; GRH_LEN];
        self.q.read_rx(slot, 0, &mut raw);
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
        self.q.can_receive()
    }

    /// True if a datagram can be posted now (or after reaping).
    pub fn can_transmit(&self) -> bool {
        self.q.can_transmit()
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
        let hcr = &self.q.hca.hcr;
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
        let found = members[..count].iter().position(|&m| m == self.q.qpn);
        if attach {
            if found.is_some() {
                return Ok(());
            }
            if count == MCG_QPS {
                return Err(Mlx4Error::Multicast);
            }
            members[count] = self.q.qpn;
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
    }
}
