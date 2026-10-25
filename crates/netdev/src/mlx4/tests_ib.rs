//! InfiniBand ports against the simulated HCA: bring-up, the subnet
//! manager's management datagrams on queue pair 0, general services on
//! queue pair 1, datagrams and multicast.

use std::vec::Vec;

use osmium_hal::net::NetError;
use osmium_hal::pci::MsiMessage;

use super::fake::{self, FakeHca, PortKind, UdFrom};
use super::ib::MadDest;
use super::mad::{self, GrhFields, MAD_LEN, QP1_QKEY};
use super::queue;
use super::*;
use osmium_drivers::virtio::testing::HostDma;

pub(super) const IB: [Option<PortKind>; 2] = [Some(PortKind::InfiniBand), Some(PortKind::InfiniBand)];
pub(super) const QKEY: u32 = 0x1234_5678;
const PERMISSIVE: u16 = 0xffff;

pub(super) fn bring_up<'d>(hca: &'d FakeHca, dma: &'d HostDma) -> Result<Mlx4<'d, HostDma>, Mlx4Error> {
    let func = Function::new(hca, fake::ADDR).unwrap();
    Mlx4::new(&func, hca.config_io(), hca.uar_io(), dma, hca)
}

pub(super) fn peer(lid: u16, qpn: u32) -> UdFrom {
    UdFrom { lid, qpn, sl: 0, path_bits: 0 }
}

/// A global route header as the wire carries it.
pub(super) fn grh_bytes(h: &GlobalHeader) -> [u8; 40] {
    let mut raw = [0u8; 40];
    raw[..4].copy_from_slice(&(6u32 << 28 | (h.traffic_class as u32) << 20 | h.flow_label).to_be_bytes());
    raw[7] = h.hop_limit;
    raw[8..24].copy_from_slice(&h.src.0);
    raw[24..].copy_from_slice(&h.dst.0);
    raw
}

/// A subnet management packet, as a subnet manager would send it.
struct Smp {
    class: u8,
    method: u8,
    attr: u16,
    modifier: u32,
    status: u16,
    hop_ptr: u8,
    hop_cnt: u8,
    dr_slid: u16,
    dr_dlid: u16,
    data: [u8; 64],
    initial_path: [u8; 64],
}

impl Smp {
    fn lid_routed(method: u8, attr: u16, modifier: u32) -> Self {
        Self {
            class: mad::CLASS_SUBN_LID_ROUTED,
            method,
            attr,
            modifier,
            status: 0,
            hop_ptr: 0,
            hop_cnt: 0,
            dr_slid: 0,
            dr_dlid: 0,
            data: [0; 64],
            initial_path: [0; 64],
        }
    }

    /// A directed-route packet whose path has `hops` hops, arriving with the
    /// hop pointer the sender before it left it at.
    fn directed(method: u8, attr: u16, modifier: u32, hops: u8, hop_ptr: u8) -> Self {
        Self {
            class: mad::CLASS_SUBN_DIRECTED_ROUTE,
            hop_ptr,
            hop_cnt: hops,
            dr_slid: PERMISSIVE,
            dr_dlid: PERMISSIVE,
            ..Self::lid_routed(method, attr, modifier)
        }
    }

    fn build(&self) -> [u8; MAD_LEN] {
        let mut m = [0u8; MAD_LEN];
        m[0] = 1;
        m[1] = self.class;
        m[2] = 1;
        m[3] = self.method;
        m[4..6].copy_from_slice(&self.status.to_be_bytes());
        m[6] = self.hop_ptr;
        m[7] = self.hop_cnt;
        m[8..16].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_be_bytes());
        m[16..18].copy_from_slice(&self.attr.to_be_bytes());
        m[20..24].copy_from_slice(&self.modifier.to_be_bytes());
        m[32..34].copy_from_slice(&self.dr_slid.to_be_bytes());
        m[34..36].copy_from_slice(&self.dr_dlid.to_be_bytes());
        m[64..128].copy_from_slice(&self.data);
        m[128..192].copy_from_slice(&self.initial_path);
        m
    }
}

/// The PortInfo data of a Set from the subnet manager.
fn port_info_set(lid: u16, sm_lid: u16, state: u8, sm_sl: u8) -> [u8; 64] {
    let mut d = [0u8; 64];
    d[16..18].copy_from_slice(&lid.to_be_bytes());
    d[18..20].copy_from_slice(&sm_lid.to_be_bytes());
    d[32] = state;
    d[36] = sm_sl;
    d
}

type Port<'h, 'd> = IbPort<'h, 'd, HostDma>;

/// Delivers `mad` to queue pair 0 (`gsi` false) or 1 of `port`, lets the
/// port work on it, and returns what it sent back.
fn exchange(hca: &FakeHca, ib: &mut Port<'_, '_>, gsi: bool, from: UdFrom, mad: &[u8; MAD_LEN]) -> Vec<fake::Sent> {
    assert!(hca.deliver_mad(ib.port(), gsi, from, None, mad, 0), "received");
    ib.service();
    hca.sent_ex(hca.special_qpn(ib.port(), gsi))
}

fn ib_calls(hca: &FakeHca) -> usize {
    hca.state.borrow().fw.mad_ifc.len()
}

/// The last datagram the port passed to the agent (as opposed to its own queries).
fn last_forwarded(hca: &FakeHca) -> fake::MadIfcCall {
    hca.state.borrow().fw.mad_ifc.iter().rev().find(|c| c.op_mod == 4).cloned().expect("a forwarded datagram")
}

#[test]
fn port_opens_in_linux_order_and_reports() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let before = dma.live.get();
    let ib = mlx.open_ib(1, QKEY).unwrap();
    {
        let s = hca.state.borrow();
        let at = |o| s.log.iter().position(|&x| x == o).unwrap();
        // The advertised capabilities are read, then set back; the first
        // try asks for more virtual lanes than the port has.
        assert!(at(op::MAD_IFC) < at(op::SET_PORT));
        assert_eq!(s.log.iter().filter(|&&o| o == op::SET_PORT).count(), 2);
        assert_eq!(s.fw.ib_caps[0], Some(fake::IB_CAPS));
        assert_eq!(s.fw.ib_set[0], Some((4, 5)), "4 virtual lanes, 4096-byte MTU");
        // Queue pair 0 is ready to receive when the port starts, and only then.
        let started = &s.log[..at(op::INIT_PORT)];
        assert_eq!(started.iter().filter(|&&o| o == op::INIT2RTR_QP).count(), 1);
        assert_eq!(started.iter().filter(|&&o| o == op::RTR2RTS_QP).count(), 0);
        assert!(s.fw.port_up[0] && !s.fw.port_up[1] && s.fw.ib_init[0]);
    }
    // Queue pair 0 and 1 of port 1, then its datagram queue pair.
    assert_eq!(hca.qps(), [64, 66, 72]);
    assert_eq!(hca.cqs(), [128, 130, 132], "each queue pair has its own completion queue");
    assert_eq!((ib.port(), ib.qpn(), ib.qkey()), (1, 72, QKEY));
    assert_eq!(hca.ud_qp(72), (0, QKEY, 0x30), "partition key 0, our queue key");
    assert_eq!((ib.max_payload(), ib.gid_table_len(), ib.pkey_table_len()), (4096, 8, 16));

    assert_eq!(mlx.open_ib(1, QKEY).err(), Some(Mlx4Error::BadPort));
    assert_eq!(mlx.open_eth(1).err(), Some(Mlx4Error::BadPort), "open, whichever way");
    assert_eq!(
        (mlx.open_ib(0, 0).err(), mlx.open_ib(3, 0).err()),
        (Some(Mlx4Error::BadPort), Some(Mlx4Error::BadPort))
    );

    // Linked but unmanaged.
    let info = ib.query().unwrap();
    assert_eq!((info.state, info.lid, info.sm_lid, info.mtu), (PortState::Initializing, 0, 0, 0));
    assert_eq!((info.physical_state, info.capability_mask), (5, fake::IB_CAPS));
    assert_eq!(info.gid_prefix, fake::GID_PREFIX);
    assert!(!ib.is_active().unwrap());

    let guid = hca.ib_state(1).guids[0];
    assert_eq!(ib.gid(0).unwrap(), Gid::new(fake::GID_PREFIX, guid));
    assert_eq!((ib.gid(0).unwrap().prefix(), ib.gid(0).unwrap().guid()), (fake::GID_PREFIX, guid));
    assert_eq!(ib.gid(1).unwrap().guid(), 0, "an unset GUID");
    assert_eq!(ib.gid(8).err(), Some(Mlx4Error::Mad(0x1c)));
    assert_eq!((ib.pkey(0), ib.pkey(1)), (Ok(0xffff), Ok(0)));
    assert_eq!(ib.pkey(16).err(), Some(Mlx4Error::Mad(0x1c)));
    assert_eq!(ib.node_guid(), Ok(fake::NODE_GUID));

    drop(ib);
    assert!(hca.qps().is_empty() && hca.cqs().is_empty());
    assert!(!hca.state.borrow().fw.port_up[0]);
    assert_eq!(hca.ib_state(1).state, 1, "closing drops the link and the subnet manager's settings");
    assert_eq!(dma.live.get(), before);
    drop(mlx.open_ib(1, QKEY).unwrap());
    drop(mlx);
    assert_eq!(dma.live.get(), 0);
}

#[test]
fn each_port_has_its_own_queue_pairs() {
    let hca = FakeHca::new([Some(PortKind::Ethernet), Some(PortKind::InfiniBand)]);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let eth = mlx.open_eth(1).unwrap();
    let ib = mlx.open_ib(2, QKEY).unwrap();
    // The Ethernet queue pair is as it always was; port 2's are interleaved with port 1's.
    assert_eq!(hca.qps(), [65, 67, 72, 73]);
    assert_eq!(hca.cqs(), [128, 129, 131, 133]);
    assert_eq!(ib.qpn(), 73);
    drop((eth, ib));
    assert!(hca.qps().is_empty());
}

#[test]
fn infiniband_needs_an_infiniband_port() {
    let hca = FakeHca::new([Some(PortKind::Ethernet), Some(PortKind::InfiniBand)]);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    assert_eq!(mlx.open_ib(1, QKEY).err(), Some(Mlx4Error::NotInfiniBand));
    assert_eq!(mlx.open_eth(2).err(), Some(Mlx4Error::NotEthernet));
    // Neither attempt claimed the port.
    drop(mlx.open_eth(1).unwrap());
    drop(mlx.open_ib(2, QKEY).unwrap());

    // Dual-protocol ports go by the cable; an unsensed cable by the caller's choice.
    for (sensed, ib_ok, eth_ok) in [(1, true, false), (2, false, true), (0, true, true)] {
        let hca = FakeHca::new([Some(PortKind::Vpi { sense_after: 0, sensed }), None]);
        hca.state.borrow_mut().dpdp = true;
        let mlx = bring_up(&hca, &dma).unwrap();
        assert_eq!(mlx.open_ib(1, QKEY).is_ok(), ib_ok, "sensed {sensed}");
        assert_eq!(mlx.open_eth(1).is_ok(), eth_ok, "sensed {sensed}");
    }
}

#[test]
fn failed_open_unwinds() {
    let attempt = |opcode: u16, skip: u32| {
        let hca = FakeHca::new(IB);
        let dma = HostDma::default();
        let mlx = bring_up(&hca, &dma).unwrap();
        let before = dma.live.get();
        {
            let mut s = hca.state.borrow_mut();
            s.fail = Some((opcode, 0x10));
            s.fail_skip = skip;
        }
        let failed = mlx.open_ib(1, QKEY).err();
        assert_eq!(failed, Some(Mlx4Error::Command { opcode, status: 0x10 }), "{opcode:#x} after {skip}");
        hca.state.borrow_mut().fail = None;
        assert!(hca.qps().is_empty() && hca.cqs().is_empty(), "{opcode:#x} after {skip}");
        assert!(!hca.state.borrow().fw.port_up[0], "{opcode:#x} after {skip}: port closed");
        assert_eq!(dma.live.get(), before, "{opcode:#x} after {skip}");
        drop(mlx.open_ib(1, QKEY).unwrap());
    };
    for opcode in [op::SET_PORT, op::INIT_PORT, op::MAD_IFC] {
        attempt(opcode, 0);
    }
    // Each of the three queue pairs, at each step.
    for opcode in [op::SW2HW_CQ, op::RST2INIT_QP, op::INIT2RTR_QP, op::RTR2RTS_QP] {
        for skip in 0..3 {
            attempt(opcode, skip);
        }
    }
}

#[test]
fn subnet_manager_configures_the_port() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut ib = mlx.open_ib(1, QKEY).unwrap();
    let qp0 = hca.special_qpn(1, false);
    ib.service();
    assert!(hca.sent_ex(qp0).is_empty(), "nothing to answer yet");

    // The subnet manager, one cable away and without a LID, asks what is here.
    let from = peer(PERMISSIVE, 0);
    let node = Smp::directed(mad::METHOD_GET, 0x0011, 0, 0, 0).build();
    let sent = exchange(&hca, &mut ib, false, from, &node);
    assert_eq!(sent.len(), 1);
    let reply = sent[0].mlx.as_ref().expect("an \"MLX\" entry");
    let p = &reply.packet;
    assert!(reply.vl15 && reply.slr, "management virtual lane, source-LID routed");
    assert_eq!((p.vl, p.lnh, p.dlid, p.slid, p.sl), (15, 2, PERMISSIVE, PERMISSIVE, 0));
    assert_eq!((p.opcode, p.pkey, p.dest_qpn, p.qkey, p.src_qpn), (0x64, 0xffff, 0, 0, qp0));
    assert_eq!(p.length, (8 + 12 + 8 + 256 + 4usize).div_ceil(4) as u16);
    assert_eq!((p.pad, p.grh.is_none(), reply.size), (0, true, 5));
    let m = &reply.payload;
    assert_eq!((m[1], m[3]), (mad::CLASS_SUBN_DIRECTED_ROUTE, 0x81), "a response");
    assert_eq!(mad::be16(m, 4), 0x8000, "directed-route direction bit");
    assert_eq!((m[6], m[7]), (0, 0), "the hop pointer is back where the packet started");
    assert_eq!(mad::be16(m, 16), 0x0011);
    assert_eq!(u64::from_be_bytes(m[64 + 12..64 + 20].try_into().unwrap()), fake::NODE_GUID);
    // The agent saw the packet as it arrived: stepped past the end of its path.
    let call = last_forwarded(&hca);
    assert_eq!((call.port, call.mad[6]), (1, 1));
    assert_eq!(call.wc, Some((0xffff, qp0, 0, 0, 0, 0, [0; 40])));

    // A directed route of one hop: the way back is recorded, and the answer leaves the same way.
    let mut one_hop = Smp::directed(mad::METHOD_GET, 0x0015, 1, 1, 1);
    one_hop.initial_path[1] = 3;
    let sent = exchange(&hca, &mut ib, false, from, &one_hop.build());
    let m = &sent[0].mlx.as_ref().unwrap().payload;
    assert_eq!((m[6], m[7], m[192 + 1]), (1, 1, 1), "hop pointer stepped back; return path names this port");
    assert_eq!(mad::be16(m, 4), 0x8000);

    // Now over LID-routed packets: the subnet manager at LID 1 gives the port LID 7 and arms it.
    let sm = UdFrom { lid: 1, qpn: 0, sl: 2, path_bits: 0 };
    let mut set = Smp::lid_routed(mad::METHOD_SET, 0x0015, 1);
    set.data = port_info_set(7, 1, 3, 2);
    let sent = exchange(&hca, &mut ib, false, sm, &set.build());
    let reply = sent[0].mlx.as_ref().unwrap();
    assert!(reply.vl15 && !reply.slr, "LID-routed answers go to the sender's LID");
    assert_eq!((reply.packet.dlid, reply.packet.sl, reply.sl, reply.rlid), (1, 2, 2, 1));
    assert_eq!(reply.packet.slid, 0, "the device adds the port's LID to the path bits");
    assert_eq!(mad::be16(&reply.payload, 4), 0, "success");
    assert_eq!(reply.payload[64 + 32] & 0xf, 3, "armed");
    let info = ib.query().unwrap();
    assert_eq!((info.state, info.lid, info.sm_lid, info.sm_sl), (PortState::Armed, 7, 1, 2));
    assert_eq!(info.mtu, 4096);

    // Active: reported as a port event.
    set.data = port_info_set(7, 1, 4, 2);
    exchange(&hca, &mut ib, false, sm, &set.build());
    assert!(ib.is_active().unwrap() && ib.link_up());
    // An illegal state change is refused in the answer, and the port stays as it was.
    set.data = port_info_set(7, 1, 3, 2);
    set.data[32] = 3;
    hca.state.borrow_mut().ib[0].as_mut().unwrap().state = 2;
    let sent = exchange(&hca, &mut ib, false, sm, &set.build());
    assert_eq!(mad::be16(&sent[0].mlx.as_ref().unwrap().payload, 4), 0, "init to armed is fine");
    set.data[32] = 4;
    hca.state.borrow_mut().ib[0].as_mut().unwrap().state = 2;
    let sent = exchange(&hca, &mut ib, false, sm, &set.build());
    assert_eq!(mad::be16(&sent[0].mlx.as_ref().unwrap().payload, 4), 0x1c, "init to active is not");

    // Every answer used a send entry and a receive entry, around the rings several times.
    for n in 0..3 * queue::RX_SLOTS {
        let get = Smp::lid_routed(mad::METHOD_GET, 0x0011, 0).build();
        let sent = exchange(&hca, &mut ib, false, sm, &get);
        assert_eq!(sent.len(), 1, "get {n}");
    }
}

#[test]
fn management_datagrams_that_are_not_for_the_agent_are_dropped() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut ib = mlx.open_ib(1, QKEY).unwrap();
    let qp0 = hca.special_qpn(1, false);
    let sm = peer(1, 0);
    let calls = ib_calls(&hca);
    let mut silent = |smp: &Smp, from: UdFrom| {
        for _ in 0..2 * queue::RX_SLOTS {
            assert!(exchange(&hca, &mut ib, false, from, &smp.build()).is_empty());
        }
    };

    // Dropped before the agent sees them.
    silent(&Smp::directed(mad::METHOD_GET, 0x0015, 1, 1, 0), peer(PERMISSIVE, 0)); // hop pointer not stepped
    silent(&Smp::directed(mad::METHOD_GET, 0x0015, 1, 3, 1), peer(PERMISSIVE, 0)); // intermediate hop
    silent(&Smp { status: 0x8000, ..Smp::directed(mad::METHOD_GET, 0x0015, 1, 0, 0) }, peer(PERMISSIVE, 0)); // a response
    silent(&Smp { dr_dlid: 5, ..Smp::directed(mad::METHOD_GET, 0x0015, 1, 0, 0) }, peer(PERMISSIVE, 0)); // not for us
    silent(&Smp::directed(mad::METHOD_GET, 0x0015, 1, 64, 1), peer(PERMISSIVE, 0)); // path too long
    silent(&Smp::lid_routed(0x81, 0x0015, 1), sm); // already a response
    silent(&Smp::lid_routed(mad::METHOD_GET, mad::ATTR_SM_INFO, 0), sm); // the agent cannot answer SMInfo
    silent(&Smp::lid_routed(mad::METHOD_TRAP, 0x0002, 0), peer(0, 0)); // a trap with no sender
    silent(&Smp { class: 0x02, ..Smp::lid_routed(mad::METHOD_GET, 0x0015, 1) }, sm); // another class
    assert_eq!(ib_calls(&hca), calls, "none reached the agent");

    // Given to the agent, which has no answer for a trap repress.
    silent(&Smp::lid_routed(mad::METHOD_TRAP_REPRESS, 0x0002, 0), sm);
    assert_eq!(ib_calls(&hca), calls + 2 * queue::RX_SLOTS as usize);
    assert!(hca.sent_ex(qp0).is_empty());

    // The queue still works after all that.
    assert!(exchange(&hca, &mut ib, false, sm, &Smp::lid_routed(mad::METHOD_GET, 0x0011, 0).build()).len() == 1);
}

#[test]
fn general_services_on_queue_pair_1() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut ib = mlx.open_ib(1, QKEY).unwrap();
    let (qp0, qp1) = (hca.special_qpn(1, false), hca.special_qpn(1, true));
    assert_eq!((qp0, qp1), (64, 66));
    let sm = UdFrom { lid: 1, qpn: 0, sl: 0, path_bits: 0 };

    // The subnet manager maps service level 3 to virtual lane 5 (odd levels use the low nibble).
    let mut set = Smp::lid_routed(mad::METHOD_SET, mad::ATTR_SL_TO_VL_TABLE, 0);
    set.data[1] = 0x05;
    exchange(&hca, &mut ib, false, sm, &set.build());

    // A performance query is answered by the agent, from queue pair 1, on the virtual lane of its level.
    let from = UdFrom { lid: 9, qpn: 0x30, sl: 3, path_bits: 0 };
    let perf = Smp { class: mad::CLASS_PERF, ..Smp::lid_routed(mad::METHOD_GET, 0x0001, 0) }.build();
    let sent = exchange(&hca, &mut ib, true, from, &perf);
    assert_eq!(sent.len(), 1);
    let reply = sent[0].mlx.as_ref().unwrap();
    let p = &reply.packet;
    assert!(!reply.vl15 && !reply.slr);
    assert_eq!((p.vl, p.sl, p.dlid, p.dest_qpn, p.qkey, p.src_qpn, p.pkey), (5, 3, 9, 0x30, QP1_QKEY, qp1, 0xffff));
    assert_eq!((reply.payload[1], reply.payload[3]), (mad::CLASS_PERF, 0x81));
    assert_eq!(last_forwarded(&hca).wc.unwrap().1, qp1, "the agent knows it came in on queue pair 1");

    // Subnet administration traffic is kept for the caller, up to a point.
    let mut sa = [0u8; MAD_LEN];
    sa[1] = mad::CLASS_SUBN_ADM;
    sa[3] = 0x81;
    for n in 0..6u8 {
        sa[8] = n;
        assert!(hca.deliver_mad(1, true, UdFrom { lid: 1, qpn: 1, sl: 2, path_bits: 0 }, None, &sa, 0));
    }
    ib.service();
    assert!(hca.sent_ex(qp1).is_empty());
    let kept: Vec<u8> = core::iter::from_fn(|| ib.take_general()).map(|rx| rx.mad[8]).collect();
    assert_eq!(kept, [0, 1, 2, 3], "four are kept, the rest dropped");

    // Sending a general services datagram, with and without a global route header.
    let local = MadDest { lid: 5, qpn: 1, qkey: QP1_QKEY, sl: 0, path_bits: 0, pkey: 0xffff, grh: None };
    let payload = [0xa5u8; MAD_LEN];
    ib.send_general(&local, &payload).unwrap();
    let first = hca.sent_ex(qp1).remove(0).mlx.unwrap();
    assert_eq!((first.packet.vl, first.packet.dlid, first.packet.lnh, first.size), (0, 5, 2, 5));
    assert_eq!(first.payload, payload);
    let route =
        GrhFields { traffic_class: 0x12, flow_label: 0xa_bcde, hop_limit: 64, source: [0x11; 16], dest: [0x22; 16] };
    ib.send_general(&MadDest { grh: Some(route), sl: 3, ..local }, &payload).unwrap();
    let second = hca.sent_ex(qp1).remove(0).mlx.unwrap();
    let g = second.packet.grh.as_ref().unwrap();
    assert_eq!((second.packet.lnh, second.size, second.packet.vl), (3, 8, 5), "two inline segments");
    assert_eq!((g.traffic_class, g.flow_label, g.hop_limit, g.next_header), (0x12, 0xa_bcde, 64, 0x1b));
    assert_eq!((g.source, g.dest), ([0x11; 16], [0x22; 16]));
    assert_eq!(g.payload_length as usize, (12 + 8 + 256 + 4 + 3) & !3);
    assert_eq!(second.packet.length as usize, (8 + 40 + 12 + 8 + 256 + 4usize).div_ceil(4));
    assert_eq!(second.packet.psn, first.packet.psn + 1, "sequence numbers count up");
    assert_eq!(second.payload, payload);

    // A full send queue says so.
    for _ in 0..queue::TX_SLOTS {
        ib.send_general(&local, &payload).unwrap();
    }
    assert_eq!(ib.send_general(&local, &payload), Err(NetError::WouldBlock));
    assert_eq!(hca.sent_ex(qp1).len(), queue::TX_SLOTS as usize);
    ib.send_general(&local, &payload).unwrap();
}

#[test]
fn datagrams() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut ib = mlx.open_ib(1, QKEY).unwrap();
    let qpn = ib.qpn();
    let mut buf = [0u8; 8192];
    assert_eq!(ib.receive(&mut buf), Err(NetError::WouldBlock));
    assert!(!hca.deliver_ud(1, qpn, QKEY, peer(9, 0x55), None, b"early"), "port not active yet");
    hca.sm_configure(1, 7);

    // A local datagram: address vector without a global route header.
    let dest = Destination { lid: 9, qpn: 0x12_3456, qkey: 0x8765_4321, sl: 3, path_bits: 1, route: None };
    ib.send(&dest, b"hello").unwrap();
    let sent = hca.sent_ex(qpn);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].frame, b"hello");
    assert_eq!(
        sent[0].ud,
        Some(fake::UdSend {
            port: 1,
            pd: PD,
            dlid: 9,
            path_bits: 1,
            grh: false,
            sl: 3,
            sgid_index: 0,
            hop_limit: 0,
            traffic_class: 0,
            flow_label: 0,
            dgid: [0; 16],
            dqpn: 0x12_3456,
            qkey: 0x8765_4321,
        })
    );

    // A routed one.
    let route = Route {
        dgid: Gid::new(0xfe80_0000_0000_0001, 0x1122_3344_5566_7788),
        sgid_index: 2,
        hop_limit: 64,
        traffic_class: 0xa5,
        flow_label: 0xf_edcb,
    };
    ib.send(&Destination { route: Some(route), ..Destination::local(0x20, 0x77, QKEY) }, &[1; 4096]).unwrap();
    let ud = hca.sent_ex(qpn).remove(0).ud.unwrap();
    assert_eq!((ud.dlid, ud.dqpn, ud.grh, ud.sgid_index, ud.hop_limit), (0x20, 0x77, true, 2, 64));
    assert_eq!((ud.traffic_class, ud.flow_label, ud.dgid), (0xa5, 0xf_edcb, route.dgid.0));

    // Limits.
    assert_eq!(ib.send(&dest, &[0; 4097]), Err(NetError::TooLarge));
    assert!(ib.can_transmit());
    for _ in 0..queue::TX_SLOTS {
        ib.send(&dest, b"x").unwrap();
    }
    assert!(!ib.can_transmit());
    assert_eq!(ib.send(&dest, b"x"), Err(NetError::WouldBlock));
    assert_eq!(hca.sent_ex(qpn).len(), queue::TX_SLOTS as usize);
    assert!(ib.can_transmit());

    // Receiving: the payload without the header slot, and who sent it.
    let from = UdFrom { lid: 0x31, qpn: 0xab_cdef, sl: 5, path_bits: 2 };
    assert!(hca.deliver_ud(1, qpn, QKEY, from, None, b"reply"));
    assert!(ib.can_receive());
    let got = ib.receive(&mut buf).unwrap();
    assert_eq!(&buf[..got.len], b"reply");
    assert_eq!((got.src_lid, got.src_qpn, got.sl, got.path_bits, got.grh), (0x31, 0xab_cdef, 5, 2, None));
    assert_eq!(ib.receive(&mut buf), Err(NetError::WouldBlock));

    let header = GlobalHeader {
        src: Gid::new(0xfe80_0000_0000_0001, 0xaaaa_bbbb_cccc_dddd),
        dst: ib.gid(0).unwrap(),
        hop_limit: 7,
        traffic_class: 0x11,
        flow_label: 0x1_2345,
    };
    assert!(hca.deliver_ud(1, qpn, QKEY, from, Some(grh_bytes(&header)), &[9; 4096]));
    let got = ib.receive(&mut buf).unwrap();
    assert_eq!((got.len, got.grh), (4096, Some(header)));
    assert_eq!(buf[..4096], [9; 4096]);

    // Not for us: wrong key, wrong queue pair. Too big for the caller: dropped, entry reused.
    assert!(!hca.deliver_ud(1, qpn, QKEY ^ 1, from, None, b"x"));
    assert!(!hca.deliver_ud(1, qpn + 1, QKEY, from, None, b"x"));
    assert!(hca.deliver_ud(1, qpn, QKEY, from, None, &[3; 100]));
    assert_eq!(ib.receive(&mut buf[..99]), Err(NetError::TooLarge));
    assert_eq!(ib.receive(&mut buf), Err(NetError::WouldBlock));

    // Several laps of every ring, both ways.
    for n in 0..100u32 {
        let payload: Vec<u8> = (0..1 + n * 40).map(|b| (b + n) as u8).collect();
        assert!(hca.deliver_ud(1, qpn, QKEY, peer(n as u16 + 1, n), None, &payload));
        ib.send(&Destination::local(n as u16 + 1, n, QKEY), &payload[..1 + n as usize]).unwrap();
        let got = ib.receive(&mut buf).unwrap();
        assert_eq!((&buf[..got.len], got.src_lid, got.src_qpn), (&payload[..], n as u16 + 1, n), "datagram {n}");
        assert_eq!(hca.sent_ex(qpn)[0].frame, &payload[..1 + n as usize]);
    }
    // A burst fills every posted receive entry; the rest are dropped.
    for n in 0..queue::RX_SLOTS + 2 {
        assert_eq!(hca.deliver_ud(1, qpn, QKEY, from, None, &[n as u8; 64]), n < queue::RX_SLOTS);
    }
    for n in 0..queue::RX_SLOTS {
        assert_eq!(ib.receive(&mut buf).map(|d| d.len), Ok(64));
        assert_eq!(buf[0], n as u8);
    }

    drop(ib);
    drop(mlx);
    assert_eq!(dma.live.get(), 0);
}

#[test]
fn multicast() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut one = mlx.open_ib(1, QKEY).unwrap();
    let mut two = mlx.open_ib(2, QKEY).unwrap();
    hca.sm_configure(1, 7);
    hca.sm_configure(2, 8);
    let group = Gid::new(0xff12_601b_ffff_0000, 0x0000_0000_ffff_ffff);
    let note = |mgid: &Gid, to: u8| hca.deliver_multicast(to, &mgid.0, QKEY, peer(3, 4), [0; 40], b"all");
    let mut buf = [0u8; 64];

    assert_eq!(note(&group, 1), 0, "nobody is in the group yet");
    one.attach_multicast(group).unwrap();
    one.attach_multicast(group).unwrap(); // idempotent
    assert_eq!(hca.state.borrow().fw.mcg[&fake::mgid_hash(&group.0)][1] & 0xff_ffff, 1);
    assert_eq!(note(&group, 1), 1);
    assert_eq!(one.receive(&mut buf).map(|d| d.len), Ok(3));
    assert_eq!(one.receive(&mut buf), Err(NetError::WouldBlock));
    assert_eq!(note(&group, 2), 0, "port 2's queue pair is not a member");

    // Another queue pair joins the same entry.
    two.attach_multicast(group).unwrap();
    assert_eq!(hca.state.borrow().fw.mcg[&fake::mgid_hash(&group.0)][1] & 0xff_ffff, 2);
    assert_eq!((note(&group, 1), note(&group, 2)), (1, 1));
    assert_eq!(one.receive(&mut buf).map(|d| d.len), Ok(3));
    assert_eq!(two.receive(&mut buf).map(|d| d.len), Ok(3));

    // A different group sharing the bucket cannot be attached.
    let hash = fake::mgid_hash(&group.0);
    let rival = (0u64..)
        .map(|n| Gid::new(0xff12_601b_ffff_0000, n))
        .find(|g| *g != group && fake::mgid_hash(&g.0) == hash)
        .unwrap();
    assert_eq!(one.attach_multicast(rival), Err(Mlx4Error::Multicast));
    assert_eq!(one.detach_multicast(rival), Err(Mlx4Error::Multicast), "never attached");

    // Leaving: the entry empties only when the last member goes.
    one.detach_multicast(group).unwrap();
    assert_eq!((note(&group, 1), note(&group, 2)), (0, 1));
    assert_eq!(two.receive(&mut buf).map(|d| d.len), Ok(3));
    one.attach_multicast(rival).unwrap_err();
    two.detach_multicast(group).unwrap();
    assert!(hca.state.borrow().fw.mcg.is_empty());
    one.attach_multicast(rival).unwrap();
    one.detach_multicast(rival).unwrap();

    // At most MAX_GROUPS groups per port.
    let groups: Vec<Gid> = (1u64..)
        .map(|n| Gid::new(0xff12_601b_ffff_0000, n))
        .scan(Vec::new(), |taken: &mut Vec<u32>, g| {
            let h = fake::mgid_hash(&g.0);
            Some((!taken.contains(&h)).then(|| {
                taken.push(h);
                g
            }))
        })
        .flatten()
        .take(5)
        .collect();
    for g in &groups[..4] {
        one.attach_multicast(*g).unwrap();
    }
    assert_eq!(one.attach_multicast(groups[4]), Err(Mlx4Error::Multicast));
    // Dropping the port leaves every group; the fake rejects a queue pair destroyed while attached.
    two.attach_multicast(groups[0]).unwrap();
    drop(one);
    assert_eq!(hca.state.borrow().fw.mcg.len(), 1);
    drop(two);
    assert!(hca.state.borrow().fw.mcg.is_empty());
    drop(mlx);
    assert_eq!(dma.live.get(), 0);
}

fn msix_messages() -> [MsiMessage; 2] {
    [MsiMessage { address: 0xfee0_0000, data: 0x40 }, MsiMessage { address: 0xfee0_1000, data: 0x41 }]
}

#[test]
fn interrupts() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let func = Function::new(&hca, fake::ADDR).unwrap();
    let mut mlx = Mlx4::new(&func, hca.config_io(), hca.uar_io(), &dma, &hca).unwrap();
    mlx.enable_msix(&func, &hca.msix_io(), msix_messages()).unwrap();
    let mut ib = mlx.open_ib(1, QKEY).unwrap();
    let qpn = ib.qpn();
    let mut buf = [0u8; 64];

    // The subnet manager's activation is a port event on the other vector.
    hca.sm_configure(1, 7);
    assert_eq!(hca.take_interrupts(), [VECTOR_ASYNC]);
    assert_eq!(mlx.handle_interrupt(VECTOR_ASYNC), 0);
    assert!(ib.link_up());

    // One interrupt per reap, then the queue is armed again.
    for n in 0..10u8 {
        assert!(hca.deliver_ud(1, qpn, QKEY, peer(2, 3), None, &[n; 8]));
        assert_eq!(hca.take_interrupts(), [VECTOR_COMPLETION], "datagram {n}");
        assert_eq!(mlx.handle_interrupt(VECTOR_COMPLETION), 0b1);
        assert_eq!(ib.receive(&mut buf).map(|d| d.len), Ok(8));
    }
    ib.send(&Destination::local(2, 3, QKEY), b"ping").unwrap();
    assert_eq!(hca.sent(qpn).len(), 1);
    assert_eq!(hca.take_interrupts(), [VECTOR_COMPLETION], "send completion");
    assert_eq!(mlx.handle_interrupt(VECTOR_COMPLETION), 0b1);
    ib.service();

    // Management datagrams interrupt through their own completion queues.
    let get = Smp::lid_routed(mad::METHOD_GET, 0x0011, 0).build();
    for _ in 0..5 {
        assert!(hca.deliver_mad(1, false, peer(1, 0), None, &get, 0));
        assert_eq!(hca.take_interrupts(), [VECTOR_COMPLETION]);
        assert_eq!(mlx.handle_interrupt(VECTOR_COMPLETION), 0b1);
        ib.service();
        assert_eq!(hca.sent_ex(hca.special_qpn(1, false)).len(), 1);
        hca.take_interrupts(); // the send completion
        mlx.handle_interrupt(VECTOR_COMPLETION);
        ib.service(); // arms the queue again
    }
}
