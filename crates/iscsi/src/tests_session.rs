//! Login redirection, several connections in a session, and several logical
//! units, against the fake target.

use std::vec;
use std::vec::Vec;

use osmium_hal::block::BlockDevice;
use osmium_net::SocketAddrV4;

use crate::session::parse_portal;
use crate::testing::{B_IP, PORTAL, Redirect, TargetConfig, TestNet};
use crate::tests::{BLOCKS, connect, options, pattern, sockets};
use crate::{IscsiDisk, IscsiError, IscsiSession, Options};

fn redirecting(address: &str, permanent: bool) -> TargetConfig {
    TargetConfig {
        redirect: Some(Redirect { address: address.into(), permanent }),
        extra_ports: vec![3261, 3262],
        ..TargetConfig::default()
    }
}

#[test]
fn portal_addresses() {
    let a = |s: &str| parse_portal(s);
    assert_eq!(a("10.0.0.5:3261,2"), Some(SocketAddrV4::new([10, 0, 0, 5].into(), 3261)));
    assert_eq!(a("10.0.0.5,1"), Some(SocketAddrV4::new([10, 0, 0, 5].into(), 3260)));
    assert_eq!(a("10.0.0.5"), Some(SocketAddrV4::new([10, 0, 0, 5].into(), 3260)));
    for bad in
        ["", "host.example:3260", "0.0.0.0:3260", "255.255.255.255:3260", "224.0.0.1", "10.0.0.5:0", "10.0.0.5:x"]
    {
        assert_eq!(a(bad), None, "{bad:?}");
    }
}

#[test]
fn login_redirection_is_followed() {
    for permanent in [false, true] {
        let mut net = TestNet::new(redirecting("192.168.1.2:3261,1", permanent), BLOCKS);
        let mut disk = connect(&mut net);
        assert_eq!(disk.portal(), Some(SocketAddrV4::new(B_IP, 3261)));
        assert_eq!(disk.moved_permanently(), permanent);
        let mut buf = vec![0u8; 4 * 512];
        disk.read_blocks(2, &mut buf).unwrap();
        assert_eq!(buf, disk.net_mut().target.disk[2 * 512..6 * 512]);
        assert_eq!(disk.net_mut().target.stats.redirects, 1);
        drop(disk);
        assert_eq!(sockets(&net), 0, "the sockets of the refused logins are gone");
    }
}

#[test]
fn redirections_that_cannot_be_followed_fail_the_login() {
    // No address, an address nobody can be reached at, and a target that
    // sends us back to where we started.
    for address in ["", "0.0.0.0:3260", "not an address", "224.0.0.1:3260"] {
        let mut net = TestNet::new(redirecting(address, false), BLOCKS);
        let r = IscsiDisk::connect(&mut net, PORTAL, &options()).err();
        assert_eq!(r, Some(IscsiError::Login { class: 1, detail: 1 }), "{address:?}");
        assert_eq!(sockets(&net), 0);
    }
    let mut net = TestNet::new(redirecting("192.168.1.2:3260", true), BLOCKS);
    let r = IscsiDisk::connect(&mut net, PORTAL, &options()).err();
    assert_eq!(r, Some(IscsiError::Protocol("too many login redirections")));
    assert!(net.target.stats.redirects > 1, "the redirection was followed until the limit");
    assert_eq!(sockets(&net), 0);
}

fn mcs(connections: u16, level: u8) -> Options {
    let mut o = options();
    o.offer.max_connections = connections;
    o.offer.error_recovery_level = level;
    o.snack_timeout = core::time::Duration::from_millis(30);
    o
}

#[test]
fn commands_run_in_parallel_over_several_connections() {
    // The target serves the newest connection first, so commands sent in
    // CmdSN order arrive out of it and are held back until their turn.
    let cfg = TargetConfig { reverse_conns: true, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = IscsiDisk::connect(&mut net, PORTAL, &mcs(3, 0)).unwrap();
    assert_eq!(disk.connections(), 3);
    assert_eq!(disk.params().max_connections, 3);

    // 1 MiB is four commands of MaxBurstLength.
    let data = pattern(BLOCKS * 512, 9);
    disk.write_blocks(0, &data).unwrap();
    let mut back = vec![0u8; data.len()];
    disk.read_blocks(0, &mut back).unwrap();
    assert!(back == data);
    disk.flush().unwrap();
    drop(disk);

    let s = &net.target.stats;
    assert_eq!((s.logins, s.additional_logins, s.logouts), (3, 2, 1));
    // CmdSN numbers the commands of all connections as one sequence.
    assert!(s.cmd_sns.windows(2).all(|w| w[1] == w[0] + 1), "{:?}", s.cmd_sns);
    for cid in 0..3 {
        assert!(s.rw_cids.contains(&cid), "connection {cid} carried a command: {:?}", s.rw_cids);
    }
    assert!(s.held_max > 0, "a command arrived before an earlier CmdSN");
    assert_eq!(s.exp_stat_sn_violations, 0, "every connection acknowledged its own StatSN");
    assert_eq!(sockets(&net), 0);
}

#[test]
fn the_target_decides_how_many_connections() {
    let cfg = TargetConfig { max_connections: 2, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = IscsiDisk::connect(&mut net, PORTAL, &mcs(5, 0)).unwrap();
    assert_eq!((disk.connections(), disk.params().max_connections), (2, 2));
    let mut buf = vec![0u8; 1024 * 512];
    disk.read_blocks(0, &mut buf).unwrap();
    drop(disk);

    // One connection unless asked for more.
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let disk = connect(&mut net);
    assert_eq!(disk.connections(), 1);
}

#[test]
fn a_refused_extra_login_leaves_a_smaller_session() {
    let cfg = TargetConfig { refuse_additional: true, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = IscsiDisk::connect(&mut net, PORTAL, &mcs(3, 0)).unwrap();
    assert_eq!((disk.connections(), disk.params().max_connections), (1, 3));
    let mut buf = vec![0u8; 1024 * 512];
    disk.read_blocks(0, &mut buf).unwrap();
    drop(disk);
    assert_eq!(sockets(&net), 0, "the refused connections' sockets are gone");
}

#[test]
fn a_lost_connection_ends_a_session_without_recovery() {
    use crate::testing::Kill;
    for level in [0, 1] {
        let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
        let mut disk = IscsiDisk::connect(&mut net, PORTAL, &mcs(2, level)).unwrap();
        disk.net_mut().target.kill = Some(Kill::AfterCommand);
        let mut buf = vec![0u8; 1024 * 512];
        assert!(disk.read_blocks(0, &mut buf).is_err(), "level {level}");
        assert!(!disk.is_logged_in());
        drop(disk);
        assert_eq!(sockets(&net), 0);
    }
}

fn lun_target(net: &mut TestNet) {
    net.target.add_lun(1, 256);
    net.target.add_lun(5, 1024);
    net.target.add_lun(300, 64);
}

#[test]
fn report_luns_and_a_block_device_per_lun() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    lun_target(&mut net);
    let mut session = IscsiSession::connect(&mut net, PORTAL, &options()).unwrap();
    assert_eq!(session.luns(), [0, 1, 5, 300]);

    let mut disks: Vec<IscsiDisk<&mut TestNet>> = session.luns().iter().map(|l| session.disk(*l).unwrap()).collect();
    let sizes: Vec<u64> = disks.iter().map(|d| d.num_blocks()).collect();
    assert_eq!(sizes, [BLOCKS as u64, 256, 1024, 64]);
    assert_eq!(disks[0].inquiry().product(), "FAKE DISK");
    assert_eq!(disks[1].inquiry().product(), "FAKE LUN 1");
    assert_eq!(disks[3].lun(), 300);

    // The units are separate disks that share a session: writes to one do
    // not show in another, and they interleave freely.
    let a = pattern(8 * 512, 1);
    let b = pattern(8 * 512, 2);
    disks[1].write_blocks(10, &a).unwrap();
    disks[2].write_blocks(10, &b).unwrap();
    let mut back = vec![0u8; 8 * 512];
    disks[2].read_blocks(10, &mut back).unwrap();
    assert!(back == b);
    disks[1].read_blocks(10, &mut back).unwrap();
    assert!(back == a);
    disks[3].read_blocks(0, &mut back).unwrap();
    assert!(back != a && back != b);
    // Past the end of the small one.
    assert_eq!(disks[3].read_blocks(60, &mut back), Err(osmium_hal::block::BlockError::OutOfRange));

    // A unit the target does not have.
    let missing = session.disk(9).err().unwrap();
    assert_eq!(missing.sense_key(), Some(crate::scsi::sense_key::ILLEGAL_REQUEST), "{missing}");

    // The session logs out when the last of its disks and the handle go.
    let target_disk_1 = session.with_net(|n| n.target.extra_luns[0].1[10 * 512..18 * 512].to_vec()).unwrap();
    assert!(target_disk_1 == a);
    drop(disks);
    drop(session);
    assert_eq!(net.target.stats.logouts, 1);
    assert_eq!(sockets(&net), 0);
}

#[test]
fn a_long_lun_list_is_fetched_whole() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    for l in 1..=100 {
        net.target.add_lun(l, 2);
    }
    let mut session = IscsiSession::connect(&mut net, PORTAL, &options()).unwrap();
    assert_eq!(session.luns().len(), 101);
    assert_eq!(session.luns().last(), Some(&100));
    assert_eq!(session.report_luns().unwrap().len(), 101);
    assert_eq!(session.disk(100).unwrap().num_blocks(), 2);
}

#[test]
fn luns_work_over_several_connections() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    lun_target(&mut net);
    let session = IscsiSession::connect(&mut net, PORTAL, &mcs(2, 0)).unwrap();
    assert_eq!(session.connections(), 2);
    let mut d5 = session.disk(5).unwrap();
    let data = pattern(1024 * 512, 5);
    d5.write_blocks(0, &data).unwrap();
    let mut back = vec![0u8; data.len()];
    d5.read_blocks(0, &mut back).unwrap();
    assert!(back == data);
}
