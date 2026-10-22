//! IP over InfiniBand (RFC 4391, 4392) as a [`NetDevice`].
//!
//! The stack above speaks Ethernet, so this device translates. A neighbor
//! is known by an invented MAC address derived from its GID, with the LID,
//! queue pair number and service level it was last seen at kept in a small
//! table; frames to a unicast MAC go to that queue pair, and frames to a
//! group address go to the IPoIB broadcast group (multicast addresses are
//! not mapped to groups of their own, so every member sees them). ARP is
//! rewritten between its Ethernet form and IPoIB's, whose hardware
//! addresses are twenty bytes: a flags byte and queue pair number, and the
//! GID.
//!
//! The interface comes up once the port is active and the broadcast group
//! has been joined with the subnet administrator; [`link_up`](NetDevice::link_up)
//! says when. All the work (answering the subnet manager, the join, its
//! retries) happens inside `transmit`, `receive` and `can_receive`, so the
//! stack has to keep calling them even when idle.

use osmium_hal::dma::DmaAllocator;
use osmium_hal::net::{MacAddress, NetDevice, NetError};

use super::ib::{Datagram, Destination, Gid, IbPort, MadDest, PortState, Route};
use super::mad::{self, QP1_QKEY};
use super::sa::{self, Group, JoinError};
use super::{Mlx4, Mlx4Error};

/// The queue key IPoIB starts with, until the broadcast group says otherwise.
pub const DEFAULT_QKEY: u32 = 0x0b1b;
/// The default partition: full membership.
pub const DEFAULT_PKEY: u16 = 0xffff;
/// Bytes of the IPoIB header: the ethertype and two reserved bytes.
const HEADER: usize = 4;
/// Bytes of an IPoIB hardware address.
const HW_LEN: usize = 20;
const ETH_HEADER: usize = 14;
/// The largest IP packet carried, whatever the group allows: what a 2048-byte
/// group (the usual one) leaves after the header.
pub const MTU: usize = 2048 - HEADER;
const ETHERTYPE_ARP: u16 = 0x0806;
const ARP_HARDWARE_ETHERNET: u16 = 1;
const ARP_HARDWARE_INFINIBAND: u16 = 32;
const ARP_REQUEST: u16 = 1;
/// The queue pair number of a multicast destination.
const MULTICAST_QPN: u32 = 0xff_ffff;
/// Neighbors remembered.
const NEIGHBORS: usize = 32;
/// How often to look at an unconfigured port, and to ask again, and to
/// wait for an answer.
const CHECK_NS: u64 = 100_000_000;
const RETRY_NS: u64 = 1_000_000_000;
const ANSWER_NS: u64 = 2_000_000_000;

/// The IPoIB broadcast group of partition `pkey`: `ff12:401b:<pkey>::ffff:ffff`.
pub fn broadcast_gid(pkey: u16) -> Gid {
    let mut gid = [0; 16];
    gid[..4].copy_from_slice(&[0xff, 0x12, 0x40, 0x1b]);
    gid[4..6].copy_from_slice(&pkey.to_be_bytes());
    gid[12..].fill(0xff);
    Gid(gid)
}

/// Where the interface is in coming up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Join {
    /// Waiting for the port to be active, or for a retry; ask at this time.
    Idle(u64),
    /// A join request is out: its transaction and when it was sent.
    Requested { tid: u64, sent: u64 },
    /// In the group.
    Joined,
}

#[derive(Clone, Copy)]
struct Neighbor {
    mac: MacAddress,
    lid: u16,
    qpn: u32,
    gid: Gid,
}

/// An InfiniBand port as an Ethernet-like interface.
pub struct IpoibPort<'h, 'd, D: DmaAllocator + ?Sized> {
    ib: IbPort<'h, 'd, D>,
    pkey: u16,
    gid: Gid,
    mac: MacAddress,
    join: Join,
    group: Group,
    tid: u32,
    neighbors: [Option<Neighbor>; NEIGHBORS],
    next_neighbor: usize,
}

/// The invented MAC address of the interface with GID `gid`.
fn mac_for(gid: &Gid) -> MacAddress {
    let g = gid.0;
    // Locally administered, unicast; the node-specific half of the GUID.
    MacAddress([0x02, g[11], g[12], g[13], g[14], g[15]])
}

/// The IPoIB hardware address of queue pair `qpn` with GID `gid`.
fn hardware_address(qpn: u32, gid: &Gid) -> [u8; HW_LEN] {
    let mut hw = [0u8; HW_LEN];
    hw[1..4].copy_from_slice(&qpn.to_be_bytes()[1..]);
    hw[4..].copy_from_slice(&gid.0);
    hw
}

impl<'h, 'd, D: DmaAllocator + ?Sized> IpoibPort<'h, 'd, D> {
    pub(super) fn open(hca: &'h Mlx4<'d, D>, port: u8) -> Result<Self, Mlx4Error> {
        let ib = hca.open_ib(port, DEFAULT_QKEY)?;
        let gid = ib.gid(0)?;
        Ok(Self {
            ib,
            pkey: DEFAULT_PKEY,
            gid,
            mac: mac_for(&gid),
            join: Join::Idle(0),
            group: Group::default(),
            tid: 0,
            neighbors: [None; NEIGHBORS],
            next_neighbor: 0,
        })
    }

    /// The InfiniBand port underneath.
    pub fn port(&mut self) -> &mut IbPort<'h, 'd, D> {
        &mut self.ib
    }

    /// The broadcast group, once joined.
    pub fn group(&self) -> Option<&Group> {
        (self.join == Join::Joined).then_some(&self.group)
    }

    /// The largest IP packet the group carries, once joined.
    pub fn mtu(&self) -> usize {
        match self.group() {
            Some(g) => g.mtu_bytes().min(self.ib.max_payload()) - HEADER,
            None => MTU,
        }
    }

    /// Does what the interface needs done: serves the subnet manager and
    /// general services, and drives the join of the broadcast group.
    pub fn poll(&mut self) {
        self.ib.service();
        let now = self.ib.now_ns();
        match self.join {
            Join::Idle(at) if now >= at => self.try_join(now),
            Join::Requested { tid, sent } => {
                while let Some(rx) = self.ib.take_general() {
                    match sa::join_response(tid, &rx.mad) {
                        Ok(group) => {
                            self.joined(group, now);
                            return;
                        }
                        Err(JoinError::Refused(_)) => {
                            self.join = Join::Idle(now + RETRY_NS);
                            return;
                        }
                        Err(JoinError::Malformed) => {}
                    }
                }
                if now >= sent + ANSWER_NS {
                    self.join = Join::Idle(now);
                }
            }
            Join::Joined if !self.ib.link_up() => {
                // The port went down; the group and its queue key come back with it.
                let _ = self.ib.detach_multicast(self.group.mgid);
                self.neighbors = [None; NEIGHBORS];
                self.join = Join::Idle(now);
            }
            _ => {}
        }
    }

    /// Asks the subnet administrator for the broadcast group if the port is
    /// ready for that.
    fn try_join(&mut self, now: u64) {
        let ready = match self.ib.query() {
            Ok(info) if info.state == PortState::Active && info.sm_lid != 0 => Some(info),
            _ => None,
        };
        let Some(info) = ready else {
            self.join = Join::Idle(now + CHECK_NS);
            return;
        };
        self.tid = self.tid.wrapping_add(1);
        let tid = sa::transaction(self.tid);
        let request = sa::join_request(tid, broadcast_gid(self.pkey), self.gid, self.pkey);
        let dest = MadDest {
            lid: info.sm_lid,
            qpn: 1,
            qkey: QP1_QKEY,
            sl: info.sm_sl,
            path_bits: 0,
            pkey: self.pkey,
            grh: None,
        };
        self.join = match self.ib.send_general(&dest, &request) {
            Ok(()) => Join::Requested { tid, sent: now },
            Err(_) => Join::Idle(now + CHECK_NS),
        };
    }

    /// The administrator put us in `group`: use its queue key, listen to it.
    fn joined(&mut self, group: Group, now: u64) {
        let usable = group.mtu_bytes() > HEADER
            && group.pkey == self.pkey
            && self.ib.set_qkey(group.qkey).is_ok()
            && self.ib.attach_multicast(group.mgid).is_ok();
        if usable {
            self.group = group;
            self.join = Join::Joined;
        } else {
            self.join = Join::Idle(now + RETRY_NS);
        }
    }

    fn neighbor_by_mac(&self, mac: MacAddress) -> Option<Neighbor> {
        self.neighbors.iter().flatten().find(|n| n.mac == mac).copied()
    }

    /// Remembers where `gid` was seen.
    fn learn(&mut self, lid: u16, qpn: u32, gid: Gid) -> MacAddress {
        let mac = mac_for(&gid);
        let entry = Neighbor { mac, lid, qpn, gid };
        let slot = self.neighbors.iter().position(|n| n.is_some_and(|n| n.mac == mac)).unwrap_or_else(|| {
            let free = self.neighbors.iter().position(Option::is_none);
            free.unwrap_or_else(|| {
                self.next_neighbor = (self.next_neighbor + 1) % NEIGHBORS;
                self.next_neighbor
            })
        });
        self.neighbors[slot] = Some(entry);
        mac
    }

    /// Where a datagram from queue pair `qpn` at `lid` came from, if known.
    fn neighbor_by_address(&self, lid: u16, qpn: u32) -> Option<Neighbor> {
        self.neighbors.iter().flatten().find(|n| n.lid == lid && n.qpn == qpn).copied()
    }

    /// Rewrites an Ethernet frame into the IPoIB datagram it stands for, in
    /// `out`; returns its length, or `None` if the frame has nowhere to go.
    fn encapsulate(&self, frame: &[u8], out: &mut [u8; HEADER + 4096]) -> Option<(usize, Destination)> {
        let dst = MacAddress(frame[..6].try_into().ok()?);
        let ethertype = mad::be16(frame, 12);
        let body = &frame[ETH_HEADER..];
        out[..2].copy_from_slice(&ethertype.to_be_bytes());
        out[2..HEADER].fill(0);
        let n = if ethertype == ETHERTYPE_ARP {
            // Ethernet ARP for IPv4: hardware 1, protocol 0x0800, 6 and 4 byte addresses.
            if body.len() < 28 || mad::be16(body, 0) != ARP_HARDWARE_ETHERNET || mad::be16(body, 2) != 0x0800 {
                return None;
            }
            let op = mad::be16(body, 6);
            let a = &mut out[HEADER..];
            a[0..2].copy_from_slice(&ARP_HARDWARE_INFINIBAND.to_be_bytes());
            a[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
            a[4] = HW_LEN as u8;
            a[5] = 4;
            a[6..8].copy_from_slice(&op.to_be_bytes());
            a[8..28].copy_from_slice(&hardware_address(self.ib.qpn(), &self.gid));
            a[28..32].copy_from_slice(&body[14..18]);
            let target = match (op, self.neighbor_by_mac(dst)) {
                (ARP_REQUEST, _) | (_, None) => [0; HW_LEN],
                (_, Some(n)) => hardware_address(n.qpn, &n.gid),
            };
            a[32..52].copy_from_slice(&target);
            a[52..56].copy_from_slice(&body[24..28]);
            HEADER + 56
        } else {
            out.get_mut(HEADER..HEADER + body.len())?.copy_from_slice(body);
            HEADER + body.len()
        };
        let g = &self.group;
        let dest = if dst.is_multicast() {
            let route = Route {
                dgid: g.mgid,
                sgid_index: 0,
                hop_limit: g.hop_limit,
                traffic_class: g.traffic_class,
                flow_label: g.flow_label,
            };
            Destination { lid: g.mlid, qpn: MULTICAST_QPN, qkey: g.qkey, sl: g.sl, path_bits: 0, route: Some(route) }
        } else {
            let n = self.neighbor_by_mac(dst)?;
            Destination { lid: n.lid, qpn: n.qpn, qkey: g.qkey, sl: g.sl, path_bits: 0, route: None }
        };
        Some((n, dest))
    }

    /// Rewrites a received datagram into an Ethernet frame in `out`; returns
    /// its length, or `None` if it is not for the stack.
    fn decapsulate(&mut self, d: &Datagram, payload: &[u8], out: &mut [u8]) -> Option<usize> {
        if payload.len() < HEADER || d.grh.is_some_and(|g| g.src == self.gid) {
            return None; // too short, or our own multicast coming back
        }
        let ethertype = mad::be16(payload, 0);
        let body = &payload[HEADER..];
        let multicast = d.grh.is_some_and(|g| g.dst.0[0] == 0xff);
        let dst = if multicast { MacAddress::BROADCAST } else { self.mac };
        let (src, n) = if ethertype == ETHERTYPE_ARP {
            if body.len() < 56 || mad::be16(body, 0) != ARP_HARDWARE_INFINIBAND || body[4] != HW_LEN as u8 {
                return None;
            }
            let op = mad::be16(body, 6);
            let sender = &body[8..28];
            let qpn = u32::from_be_bytes([0, sender[1], sender[2], sender[3]]);
            let src = self.learn(d.src_lid, qpn, Gid(sender[4..].try_into().ok()?));
            let a = out.get_mut(ETH_HEADER..ETH_HEADER + 28)?;
            a[0..2].copy_from_slice(&ARP_HARDWARE_ETHERNET.to_be_bytes());
            a[2..4].copy_from_slice(&0x0800u16.to_be_bytes());
            a[4] = 6;
            a[5] = 4;
            a[6..8].copy_from_slice(&op.to_be_bytes());
            a[8..14].copy_from_slice(&src.0);
            a[14..18].copy_from_slice(&body[28..32]);
            a[18..24].copy_from_slice(&if op == ARP_REQUEST { [0; 6] } else { self.mac.0 });
            a[24..28].copy_from_slice(&body[52..56]);
            (src, 28)
        } else {
            let known = self.neighbor_by_address(d.src_lid, d.src_qpn).map(|n| n.mac);
            let src = match (known, d.grh) {
                (Some(mac), _) => mac,
                (None, Some(g)) => self.learn(d.src_lid, d.src_qpn, g.src),
                (None, None) => return None, // never heard of it, and cannot tell who it is
            };
            out.get_mut(ETH_HEADER..ETH_HEADER + body.len())?.copy_from_slice(body);
            (src, body.len())
        };
        out[..6].copy_from_slice(&dst.0);
        out[6..12].copy_from_slice(&src.0);
        out[12..14].copy_from_slice(&ethertype.to_be_bytes());
        Some(ETH_HEADER + n)
    }
}

impl<D: DmaAllocator + ?Sized> NetDevice for IpoibPort<'_, '_, D> {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn max_frame_len(&self) -> usize {
        ETH_HEADER + MTU
    }

    fn link_up(&self) -> bool {
        self.join == Join::Joined
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        self.poll();
        if self.join != Join::Joined {
            return Err(NetError::LinkDown);
        }
        if frame.len() < ETH_HEADER {
            return Err(NetError::Io);
        }
        if frame.len() - ETH_HEADER > self.mtu() {
            return Err(NetError::TooLarge);
        }
        let mut datagram = [0u8; HEADER + 4096];
        match self.encapsulate(frame, &mut datagram) {
            Some((n, dest)) => self.ib.send(&dest, &datagram[..n]),
            None => Ok(()), // nowhere to send it; the stack will ask again
        }
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.poll();
        let mut datagram = [0u8; HEADER + 4096];
        loop {
            let d = self.ib.receive(&mut datagram)?;
            // (`ib.receive` reports a datagram too big for the buffer as an error.)
            let payload = &datagram[..d.len];
            if let Some(n) = self.decapsulate(&d, payload, buf) {
                return Ok(n);
            }
        }
    }

    fn can_receive(&self) -> bool {
        self.ib.can_receive() || self.ib.management_pending()
    }

    fn can_transmit(&self) -> bool {
        self.ib.can_transmit()
    }
}
