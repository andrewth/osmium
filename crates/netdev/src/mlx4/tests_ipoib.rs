//! IP over InfiniBand against the simulated HCA and a pretend subnet
//! administrator.

use std::vec::Vec;

use osmium_hal::net::{MacAddress, NetDevice, NetError};

use super::fake::{self, FakeHca, UdFrom};
use super::ipoib::broadcast_gid;
use super::mad::{self, MAD_LEN, QP1_QKEY};
use super::tests_ib::{IB, bring_up, grh_bytes};
use super::*;
use osmium_drivers::virtio::testing::HostDma;

type Ip<'h, 'd> = IpoibPort<'h, 'd, HostDma>;

const SM: UdFrom = UdFrom { lid: fake::SM_LID, qpn: 1, sl: 0, path_bits: 0 };
const IPOIB_QPN: u32 = 72;

/// The broadcast group as the subnet administrator describes it.
fn group() -> Group {
    Group {
        mgid: broadcast_gid(0xffff),
        qkey: 0x00c0_ffee,
        mlid: 0xc001,
        mtu: 4,
        traffic_class: 0x10,
        pkey: 0xffff,
        rate: 6,
        sl: 3,
        flow_label: 0x1_0001,
        hop_limit: 5,
    }
}

/// The join request the port has sent, if any.
fn pending_join(hca: &FakeHca) -> Option<[u8; MAD_LEN]> {
    let sent = hca.sent_ex(hca.special_qpn(1, true));
    assert!(sent.len() <= 1, "one request at a time");
    sent.into_iter().next().map(|s| s.mlx.unwrap().payload.try_into().unwrap())
}

/// The administrator's answer to `request`.
fn answer(hca: &FakeHca, request: &[u8; MAD_LEN], g: &Group, status: u16) {
    let mut m = *request;
    m[3] = 0x81;
    m[4..6].copy_from_slice(&status.to_be_bytes());
    let r = &mut m[56..];
    r[32..36].copy_from_slice(&g.qkey.to_be_bytes());
    r[36..38].copy_from_slice(&g.mlid.to_be_bytes());
    r[38] = 2 << 6 | g.mtu;
    r[39] = g.traffic_class;
    r[40..42].copy_from_slice(&g.pkey.to_be_bytes());
    r[42] = 3 << 6 | g.rate;
    r[44..48].copy_from_slice(&((g.sl as u32) << 28 | g.flow_label << 8 | g.hop_limit as u32).to_be_bytes());
    assert!(hca.deliver_mad(1, true, SM, None, &m, 0));
}

/// Brings the interface up and returns the group it joined.
fn up(hca: &FakeHca, ip: &mut Ip<'_, '_>) -> Group {
    hca.sm_configure(1, 7);
    ip.poll();
    let request = pending_join(hca).expect("a join request");
    answer(hca, &request, &group(), 0);
    ip.poll();
    assert!(ip.link_up());
    group()
}

fn peer_gid(n: u64) -> Gid {
    Gid::new(fake::GID_PREFIX, 0x0002_c903_00aa_0000 + n)
}

/// The invented MAC address of the interface with this GID.
fn mac_of(gid: &Gid) -> MacAddress {
    MacAddress([0x02, gid.0[11], gid.0[12], gid.0[13], gid.0[14], gid.0[15]])
}

fn hw(qpn: u32, gid: &Gid) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[1..4].copy_from_slice(&qpn.to_be_bytes()[1..]);
    h[4..].copy_from_slice(&gid.0);
    h
}

fn eth(dst: MacAddress, src: MacAddress, ethertype: u16, body: &[u8]) -> Vec<u8> {
    [&dst.0[..], &src.0[..], &ethertype.to_be_bytes(), body].concat()
}

fn arp_eth(op: u16, sha: MacAddress, spa: [u8; 4], tha: MacAddress, tpa: [u8; 4]) -> Vec<u8> {
    [&[0, 1, 8, 0, 6, 4][..], &op.to_be_bytes(), &sha.0, &spa, &tha.0, &tpa].concat()
}

fn arp_ib(op: u16, sha: [u8; 20], spa: [u8; 4], tha: [u8; 20], tpa: [u8; 4]) -> Vec<u8> {
    [&[0, 32, 8, 0, 20, 4][..], &op.to_be_bytes(), &sha, &spa, &tha, &tpa].concat()
}

/// An IPoIB datagram: the encapsulation header, then the packet.
fn ipoib(ethertype: u16, body: &[u8]) -> Vec<u8> {
    [&ethertype.to_be_bytes()[..], &[0, 0], body].concat()
}

#[test]
fn joins_the_broadcast_group() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut ip = mlx.open_ipoib(1).unwrap();
    let own = Gid::new(fake::GID_PREFIX, hca.ib_state(1).guids[0]);
    assert_eq!(ip.mac_address(), mac_of(&own));
    assert!(ip.mac_address().is_local() && !ip.mac_address().is_multicast());
    assert_eq!(ip.max_frame_len(), 14 + 2044);

    // The subnet manager has not been by: nothing to do yet, and no way to send.
    ip.poll();
    assert!(!ip.link_up() && pending_join(&hca).is_none());
    assert_eq!(ip.transmit(&[0; 60]), Err(NetError::LinkDown));
    assert_eq!(ip.receive(&mut [0; 2048]), Err(NetError::WouldBlock));

    // Active: the request goes to the subnet administrator, once (after the next look at the port).
    hca.sm_configure(1, 7);
    hca.advance(100_000_000);
    ip.poll();
    let sent = hca.sent_ex(hca.special_qpn(1, true));
    assert_eq!(sent.len(), 1);
    let packet = &sent[0].mlx.as_ref().unwrap().packet;
    assert_eq!((packet.dlid, packet.dest_qpn, packet.qkey, packet.pkey), (fake::SM_LID, 1, QP1_QKEY, 0xffff));
    let request: [u8; MAD_LEN] = sent[0].mlx.as_ref().unwrap().payload.clone().try_into().unwrap();
    assert_eq!((request[1], request[2], request[3], mad::be16(&request, 16)), (3, 2, 2, 0x38));
    assert_eq!(u64::from_be_bytes(request[48..56].try_into().unwrap()), 1 << 0 | 1 << 1 | 1 << 7 | 1 << 16);
    let mgid = [0xff, 0x12, 0x40, 0x1b, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(request[56..72], mgid);
    assert_eq!(request[72..88], own.0, "joining from the port's own GID");
    assert_eq!((mad::be16(&request, 56 + 40), request[56 + 48]), (0xffff, 1), "partition key, full member");
    ip.poll();
    assert!(pending_join(&hca).is_none(), "not asked again while waiting");
    assert!(!ip.link_up());

    // The answer: the queue key changes and the queue pair listens to the group.
    answer(&hca, &request, &group(), 0);
    ip.poll();
    assert!(ip.link_up());
    assert_eq!(ip.group(), Some(&group()));
    assert_eq!(hca.ud_qp(IPOIB_QPN).1, 0x00c0_ffee, "the group's queue key");
    assert_eq!(hca.state.borrow().fw.mcg[&fake::mgid_hash(&mgid)][1] & 0xff_ffff, 1);
    assert_eq!(ip.mtu(), 2044);

    // Leaving takes the queue pair out of the group first.
    drop(ip);
    assert!(hca.state.borrow().fw.mcg.is_empty());
    drop(mlx);
    assert_eq!(dma.live.get(), 0);
}

#[test]
fn refused_lost_and_unusable_joins_are_retried() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut ip = mlx.open_ipoib(1).unwrap();
    hca.sm_configure(1, 7);
    ip.poll();
    let first = pending_join(&hca).unwrap();

    // Refused: wait a second before asking again.
    answer(&hca, &first, &group(), 0x0300);
    ip.poll();
    assert!(!ip.link_up() && pending_join(&hca).is_none());
    hca.advance(500_000_000);
    ip.poll();
    assert!(pending_join(&hca).is_none(), "backing off");
    hca.advance(600_000_000);
    ip.poll();
    let second = pending_join(&hca).expect("asked again");
    assert_ne!(first[8..16], second[8..16], "a new transaction");

    // An answer to the old transaction means nothing.
    answer(&hca, &first, &group(), 0);
    ip.poll();
    assert!(!ip.link_up());

    // Lost: ask again after two seconds.
    hca.advance(1_900_000_000);
    ip.poll();
    assert!(pending_join(&hca).is_none());
    hca.advance(200_000_000);
    ip.poll();
    ip.poll();
    let third = pending_join(&hca).expect("asked again");

    // A group this driver cannot use (the wrong partition, a tiny MTU) is left alone.
    answer(&hca, &third, &Group { pkey: 0x8001, ..group() }, 0);
    ip.poll();
    assert!(!ip.link_up() && hca.state.borrow().fw.mcg.is_empty());
    hca.advance(1_100_000_000);
    ip.poll();
    let fourth = pending_join(&hca).unwrap();
    answer(&hca, &fourth, &Group { mtu: 0, ..group() }, 0);
    ip.poll();
    assert!(!ip.link_up());
    hca.advance(1_100_000_000);
    ip.poll();
    let fifth = pending_join(&hca).unwrap();
    answer(&hca, &fifth, &group(), 0);
    ip.poll();
    assert!(ip.link_up());
}

#[test]
fn arp_and_unicast() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut ip = mlx.open_ipoib(1).unwrap();
    let g = up(&hca, &mut ip);
    let own = Gid::new(fake::GID_PREFIX, hca.ib_state(1).guids[0]);
    let mac = ip.mac_address();
    let (me, them) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let mut buf = [0u8; 2100];

    // An ARP request for a neighbor goes to the whole group, in IPoIB's form of ARP.
    let request = eth(MacAddress::BROADCAST, mac, 0x0806, &arp_eth(1, mac, me, MacAddress([0; 6]), them));
    ip.transmit(&request).unwrap();
    let sent = hca.sent_ex(IPOIB_QPN);
    assert_eq!(sent.len(), 1);
    let ud = sent[0].ud.as_ref().unwrap();
    assert_eq!((ud.dlid, ud.dqpn, ud.qkey, ud.sl), (0xc001, 0xff_ffff, 0x00c0_ffee, 3));
    assert!(ud.grh, "a group address needs a global route header");
    assert_eq!((ud.dgid, ud.hop_limit, ud.traffic_class, ud.flow_label), (g.mgid.0, 5, 0x10, 0x1_0001));
    assert_eq!(sent[0].frame, ipoib(0x0806, &arp_ib(1, hw(IPOIB_QPN, &own), me, [0; 20], them)));

    // The reply is unicast; its sender is learned from what the datagram says it is.
    let (lid, qpn, gid) = (9, 0x55, peer_gid(1));
    let reply = ipoib(0x0806, &arp_ib(2, hw(qpn, &gid), them, hw(IPOIB_QPN, &own), me));
    assert!(hca.deliver_ud(1, IPOIB_QPN, g.qkey, UdFrom { lid, qpn, sl: 3, path_bits: 0 }, None, &reply));
    assert!(ip.can_receive());
    let n = ip.receive(&mut buf).unwrap();
    let theirs = mac_of(&gid);
    assert_eq!(buf[..n], eth(mac, theirs, 0x0806, &arp_eth(2, theirs, them, mac, me))[..]);
    assert_eq!(ip.receive(&mut buf), Err(NetError::WouldBlock));

    // Now IP goes to that queue pair, with the group's queue key.
    let packet = [0x45u8; 100];
    ip.transmit(&eth(theirs, mac, 0x0800, &packet)).unwrap();
    let sent = hca.sent_ex(IPOIB_QPN);
    let ud = sent[0].ud.as_ref().unwrap();
    assert_eq!((ud.dlid, ud.dqpn, ud.qkey, ud.sl, ud.grh), (9, 0x55, 0x00c0_ffee, 3, false));
    assert_eq!(sent[0].frame, ipoib(0x0800, &packet));

    // And what comes back from it, with no global route header, is recognized by where it came from.
    let from = UdFrom { lid, qpn, sl: 3, path_bits: 0 };
    assert!(hca.deliver_ud(1, IPOIB_QPN, g.qkey, from, None, &ipoib(0x0800, &packet)));
    let n = ip.receive(&mut buf).unwrap();
    assert_eq!(buf[..n], eth(mac, theirs, 0x0800, &packet)[..]);
    // Somebody never heard from is not passed on.
    let stranger = UdFrom { lid: 10, qpn: 0x66, sl: 3, path_bits: 0 };
    assert!(hca.deliver_ud(1, IPOIB_QPN, g.qkey, stranger, None, &ipoib(0x0800, &packet)));
    assert_eq!(ip.receive(&mut buf), Err(NetError::WouldBlock));
    // ...unless the datagram says who it is.
    let known_by_route =
        grh_bytes(&GlobalHeader { src: peer_gid(2), dst: own, hop_limit: 64, traffic_class: 0, flow_label: 0 });
    assert!(hca.deliver_ud(1, IPOIB_QPN, g.qkey, stranger, Some(known_by_route), &ipoib(0x0800, &packet)));
    let n = ip.receive(&mut buf).unwrap();
    assert_eq!(buf[..n], eth(mac, mac_of(&peer_gid(2)), 0x0800, &packet)[..]);
}

#[test]
fn group_traffic_and_limits() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut ip = mlx.open_ipoib(1).unwrap();
    let g = up(&hca, &mut ip);
    let own = Gid::new(fake::GID_PREFIX, hca.ib_state(1).guids[0]);
    let mac = ip.mac_address();
    let mut buf = [0u8; 2100];

    // A request from a neighbor arrives by multicast and comes out as a broadcast.
    let gid = peer_gid(3);
    let asking = ipoib(0x0806, &arp_ib(1, hw(0x77, &gid), [10, 0, 0, 3], [0; 20], [10, 0, 0, 1]));
    let header = GlobalHeader { src: gid, dst: g.mgid, hop_limit: 64, traffic_class: 0, flow_label: 0 };
    let from = UdFrom { lid: 12, qpn: 0x77, sl: 3, path_bits: 0 };
    assert_eq!(hca.deliver_multicast(1, &g.mgid.0, g.qkey, from, grh_bytes(&header), &asking), 1);
    let n = ip.receive(&mut buf).unwrap();
    let theirs = mac_of(&gid);
    let want = eth(
        MacAddress::BROADCAST,
        theirs,
        0x0806,
        &arp_eth(1, theirs, [10, 0, 0, 3], MacAddress([0; 6]), [10, 0, 0, 1]),
    );
    assert_eq!(buf[..n], want[..]);
    // It was learned: a unicast reply finds its way.
    ip.transmit(&eth(theirs, mac, 0x0806, &arp_eth(2, mac, [10, 0, 0, 1], theirs, [10, 0, 0, 3]))).unwrap();
    let sent = hca.sent_ex(IPOIB_QPN);
    let ud = sent[0].ud.as_ref().unwrap();
    assert_eq!((ud.dlid, ud.dqpn, ud.grh), (12, 0x77, false));
    assert_eq!(
        sent[0].frame,
        ipoib(0x0806, &arp_ib(2, hw(IPOIB_QPN, &own), [10, 0, 0, 1], hw(0x77, &gid), [10, 0, 0, 3]))
    );

    // What this interface sends to the group comes back to it, and is ignored.
    let mine = GlobalHeader { src: own, ..header };
    assert_eq!(
        hca.deliver_multicast(
            1,
            &g.mgid.0,
            g.qkey,
            UdFrom { lid: 7, qpn: IPOIB_QPN, ..from },
            grh_bytes(&mine),
            &asking
        ),
        1
    );
    assert_eq!(ip.receive(&mut buf), Err(NetError::WouldBlock));

    // Other group addresses (IPv6 neighbor discovery, say) ride the same group.
    let v6 = MacAddress([0x33, 0x33, 0, 0, 0, 1]);
    ip.transmit(&eth(v6, mac, 0x86dd, &[0x60; 80])).unwrap();
    let sent = hca.sent_ex(IPOIB_QPN);
    assert_eq!((sent[0].ud.as_ref().unwrap().dqpn, sent[0].frame[..2].to_vec()), (0xff_ffff, [0x86, 0xdd].to_vec()));

    // Frames that cannot go anywhere.
    assert_eq!(ip.transmit(&[0; 10]), Err(NetError::Io));
    assert_eq!(ip.transmit(&eth(theirs, mac, 0x0800, &[0; 2045])), Err(NetError::TooLarge));
    ip.transmit(&eth(theirs, mac, 0x0800, &[0; 2044])).unwrap();
    assert_eq!(hca.sent_ex(IPOIB_QPN)[0].frame.len(), 4 + 2044);
    ip.transmit(&eth(MacAddress([2, 9, 9, 9, 9, 9]), mac, 0x0800, &[0; 50])).unwrap();
    assert!(hca.sent_ex(IPOIB_QPN).is_empty(), "an unknown neighbor gets nothing");
    let odd = ipoib(0x0806, &[0; 10]);
    assert!(hca.deliver_ud(1, IPOIB_QPN, g.qkey, from, None, &odd));
    assert!(hca.deliver_ud(1, IPOIB_QPN, g.qkey, from, None, &[0; 2]));
    assert_eq!(ip.receive(&mut buf), Err(NetError::WouldBlock), "malformed datagrams are dropped");

    // Many neighbors: the table replaces the oldest, and the recent ones keep working.
    for n in 10..60u64 {
        let g2 = peer_gid(n);
        let hello = ipoib(0x0806, &arp_ib(1, hw(0x100 + n as u32, &g2), [10, 0, 1, n as u8], [0; 20], [10, 0, 0, 1]));
        let h = GlobalHeader { src: g2, ..header };
        assert_eq!(
            hca.deliver_multicast(1, &g.mgid.0, g.qkey, UdFrom { lid: 100 + n as u16, ..from }, grh_bytes(&h), &hello),
            1
        );
        ip.receive(&mut buf).unwrap();
    }
    ip.transmit(&eth(mac_of(&peer_gid(59)), mac, 0x0800, &[0; 50])).unwrap();
    let ud = hca.sent_ex(IPOIB_QPN).remove(0).ud.unwrap();
    assert_eq!((ud.dlid, ud.dqpn), (159, 0x100 + 59));
}

#[test]
fn the_group_is_left_and_rejoined_with_the_link() {
    let hca = FakeHca::new(IB);
    let dma = HostDma::default();
    let mlx = bring_up(&hca, &dma).unwrap();
    let mut ip = mlx.open_ipoib(1).unwrap();
    let g = up(&hca, &mut ip);
    let mac = ip.mac_address();
    let gid = peer_gid(1);
    let from = UdFrom { lid: 9, qpn: 0x55, sl: 3, path_bits: 0 };
    assert!(hca.deliver_ud(
        1,
        IPOIB_QPN,
        g.qkey,
        from,
        None,
        &ipoib(0x0806, &arp_ib(2, hw(0x55, &gid), [10, 0, 0, 2], hw(IPOIB_QPN, &gid), [10, 0, 0, 1]))
    ));
    ip.receive(&mut [0; 2100]).unwrap();

    // The link drops: the interface says so, forgets its neighbors and leaves the group.
    hca.state.borrow_mut().ib[0].as_mut().unwrap().state = 1;
    hca.port_event(1, false);
    ip.poll();
    assert!(!ip.link_up() && ip.group().is_none());
    assert!(hca.state.borrow().fw.mcg.is_empty());
    assert_eq!(ip.transmit(&eth(mac_of(&gid), mac, 0x0800, &[0; 50])), Err(NetError::LinkDown));

    // And back: the same dance again.
    hca.sm_configure(1, 7);
    hca.advance(100_000_000);
    ip.poll();
    let request = pending_join(&hca).expect("joins again");
    answer(&hca, &request, &Group { mlid: 0xc002, ..group() }, 0);
    ip.poll();
    assert_eq!(ip.group().map(|g| g.mlid), Some(0xc002));
    assert_eq!(hca.state.borrow().fw.mcg.len(), 1);
    ip.transmit(&eth(mac_of(&gid), mac, 0x0800, &[0; 50])).unwrap();
    assert!(hca.sent_ex(IPOIB_QPN).is_empty(), "the neighbor has to be learned again");
}
