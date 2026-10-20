//! End-to-end tests: the initiator on one osmium-net interface against the
//! fake target in [`crate::testing`] on another.

use std::vec;
use std::vec::Vec;

use osmium_hal::block::{BlockDevice, BlockError};
use osmium_net::{Ipv4Addr, SocketAddrV4};

use crate::pdu::RESERVED_TAG;
use crate::scsi::{self, Sense, op, sense_key};
use crate::testing::{Fault, INITIATOR_NAME, PORTAL, TARGET_NAME, TargetConfig, TestNet};
use crate::{Data, IscsiDisk, IscsiError, Options, discover};

const BLOCKS: usize = 2048;

fn options() -> Options {
    Options::new(INITIATOR_NAME, TARGET_NAME)
}

fn connect(net: &mut TestNet) -> IscsiDisk<&mut TestNet> {
    IscsiDisk::connect(net, PORTAL, &options()).unwrap()
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31) ^ seed ^ (i >> 9) as u8).collect()
}

/// Sockets left in the initiator's set.
fn sockets(net: &TestNet) -> usize {
    net.a.sockets.iter().count()
}

#[test]
fn login_capacity_and_logout_on_drop() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let disk = connect(&mut net);
    assert_eq!((disk.block_size(), disk.num_blocks()), (512, BLOCKS as u64));
    let i = disk.inquiry();
    assert_eq!((i.device_type(), i.vendor(), i.product(), i.revision()), (0, "OSMIUM", "FAKE DISK", "0001"));
    let p = disk.params();
    assert_eq!((p.max_recv_data_segment_length, p.max_xmit_data_segment_length), (65536, 8192));
    assert_eq!((p.initial_r2t, p.immediate_data, p.first_burst_length), (false, true, 65536));
    assert_eq!(p.target_portal_group_tag, Some(1));
    assert!(disk.is_logged_in());
    drop(disk);

    let s = &net.target.stats;
    assert_eq!((s.logins, s.logouts), (1, 1));
    // TEST UNIT READY is retried after the UNIT ATTENTION.
    assert_eq!(s.commands, [op::TEST_UNIT_READY, op::TEST_UNIT_READY, op::INQUIRY, op::READ_CAPACITY_10]);
    assert_eq!(sockets(&net), 0, "the session's socket is removed");
}

#[test]
fn read_write_flush_round_trip() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let mut disk = connect(&mut net);
    let mut buf = vec![0u8; 4 * 512];
    disk.read_blocks(3, &mut buf).unwrap();
    assert_eq!(buf, disk.net_mut().target.disk[3 * 512..7 * 512]);

    // 8 KiB fits in the command as immediate data.
    let small = pattern(16 * 512, 1);
    disk.write_blocks(10, &small).unwrap();
    // 128 KiB: 8 KiB immediate, 56 KiB of unsolicited Data-Out up to
    // FirstBurstLength, then an R2T for the remaining 64 KiB.
    let big = pattern(256 * 512, 2);
    disk.write_blocks(100, &big).unwrap();
    disk.flush().unwrap();

    let mut back = vec![0u8; big.len()];
    disk.read_blocks(100, &mut back).unwrap();
    assert!(back == big);
    disk.read_blocks(10, &mut back[..small.len()]).unwrap();
    assert!(back[..small.len()] == small[..]);

    let t = &disk.net_mut().target;
    assert!(t.disk[100 * 512..356 * 512] == big[..]);
    let s = &t.stats;
    assert_eq!(s.immediate_bytes, 8192 * 2);
    assert_eq!(s.unsolicited_data_out, 7);
    assert_eq!(s.r2ts, 1);
    assert_eq!(s.data_out, 7 + 8);
    assert!(s.commands.contains(&op::SYNCHRONIZE_CACHE_10));
}

#[test]
fn multi_pdu_data_in_with_separate_status() {
    let cfg = TargetConfig { data_in_segment: 1024, status_in_data_in: false, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = connect(&mut net);
    let before = disk.net_mut().target.stats.data_in;
    let mut buf = vec![0u8; 64 * 512];
    disk.read_blocks(500, &mut buf).unwrap();
    let t = &disk.net_mut().target;
    assert!(buf == t.disk[500 * 512..564 * 512]);
    assert_eq!(t.stats.data_in - before, 32);
}

#[test]
fn r2t_driven_writes_with_small_segments() {
    let cfg = TargetConfig {
        mrdsl: 512,
        initial_r2t: true,
        immediate_data: false,
        max_burst: 4096,
        first_burst: 4096,
        ..TargetConfig::default()
    };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = connect(&mut net);
    let p = disk.params();
    assert_eq!(
        (p.initial_r2t, p.immediate_data, p.max_burst_length, p.max_xmit_data_segment_length),
        (true, false, 4096, 512)
    );
    let data = pattern(32 * 512, 3);
    disk.write_blocks(7, &data).unwrap();
    let mut back = vec![0u8; data.len()];
    disk.read_blocks(7, &mut back).unwrap();
    assert!(back == data);

    let s = &disk.net_mut().target.stats;
    // Four commands of MaxBurstLength, each one R2T answered by eight
    // 512-byte Data-Out PDUs.
    let writes = s.commands.iter().filter(|&&c| c == op::WRITE_10).count();
    assert_eq!((writes, s.r2ts, s.data_out), (4, 4, 32));
    assert_eq!((s.immediate_bytes, s.unsolicited_data_out), (0, 0));
}

#[test]
fn check_condition_fails_the_command_but_not_the_session() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let mut disk = connect(&mut net);
    let mut buf = vec![0u8; 512];

    let medium = Sense { key: sense_key::MEDIUM_ERROR, asc: 0x11, ascq: 0 };
    disk.net_mut().target.fail_next = Some((op::READ_10, medium));
    assert_eq!(disk.read_blocks(0, &mut buf), Err(BlockError::Io));
    disk.net_mut().target.fail_next = Some((op::READ_10, medium));
    let e = disk.execute(&scsi::read(0, 1), Data::In(&mut buf)).unwrap_err();
    assert_eq!(e, IscsiError::Scsi { status: scsi::status::CHECK_CONDITION, sense: Some(medium) });

    let protect = Sense { key: sense_key::DATA_PROTECT, asc: 0x27, ascq: 0 };
    disk.net_mut().target.fail_next = Some((op::WRITE_10, protect));
    assert_eq!(disk.write_blocks(0, &buf), Err(BlockError::ReadOnly));

    // The target's own range check, past the capacity we were told.
    let e = disk.execute(&scsi::read(BLOCKS as u64, 1), Data::In(&mut buf)).unwrap_err();
    assert_eq!(BlockError::from(e), BlockError::OutOfRange);
    // A unit attention is retried.
    let attention = Sense { key: sense_key::UNIT_ATTENTION, asc: 0x2a, ascq: 0x09 };
    disk.net_mut().target.fail_next = Some((op::READ_10, attention));
    disk.read_blocks(1, &mut buf).unwrap();

    assert!(disk.is_logged_in());
    disk.read_blocks(0, &mut buf).unwrap();
    assert!(buf == disk.net_mut().target.disk[..512]);
}

#[test]
fn target_pings_are_answered() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let mut disk = connect(&mut net);
    let mut buf = vec![0u8; 1024];
    disk.net_mut().target.ping = Some(0x55);
    disk.read_blocks(2, &mut buf).unwrap();
    assert_eq!(disk.net_mut().target.stats.pongs, 1);
    // A ping with the reserved tag wants no answer.
    disk.net_mut().target.ping = Some(RESERVED_TAG);
    disk.write_blocks(2, &buf).unwrap();
    let s = &disk.net_mut().target.stats;
    assert_eq!((s.pongs, s.unexpected_nop_outs), (1, 0));
}

#[test]
fn login_with_extra_rounds_and_target_offers() {
    let cfg = TargetConfig { extra_security_round: true, extra_operational_round: true, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let disk = connect(&mut net);
    drop(disk);
    let s = &net.target.stats;
    assert_eq!(s.logins, 1);
    assert_eq!(s.answers, [("X-org.osmium.Probe".into(), "NotUnderstood".into())]);
}

#[test]
fn login_refused() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let opts = Options::new(INITIATOR_NAME, "iqn.2026-10.org.osmium:nonesuch");
    let e = IscsiDisk::connect(&mut net, PORTAL, &opts).err().unwrap();
    assert_eq!(e, IscsiError::Login { class: 2, detail: 3 });
    assert_eq!(sockets(&net), 0);

    // Nobody listens on port 3261: the connection is refused.
    let e = IscsiDisk::connect(&mut net, SocketAddrV4::new(*PORTAL.ip(), 3261), &opts).err().unwrap();
    assert_eq!(e, IscsiError::Net(osmium_net::Error::ConnectionRefused));
    assert_eq!(sockets(&net), 0);
}

#[test]
fn large_disk_needs_read_capacity_16() {
    let cfg = TargetConfig { reported_blocks: Some(1 << 33), ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let disk = connect(&mut net);
    assert_eq!(disk.num_blocks(), 1 << 33);
    drop(disk);
    assert!(net.target.stats.commands.contains(&op::SERVICE_ACTION_IN_16));
}

#[test]
fn a_silent_target_times_out() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let opts = Options { timeout: core::time::Duration::from_millis(300), ..options() };
    let mut disk = IscsiDisk::connect(&mut net, PORTAL, &opts).unwrap();
    disk.net_mut().target.ignore_next = true;
    let start = disk.net_mut().now;
    let mut buf = [0u8; 512];
    assert_eq!(disk.execute(&scsi::read(0, 1), Data::In(&mut buf)), Err(IscsiError::TimedOut));
    assert!(disk.net_mut().now - start >= opts.timeout);
    assert!(!disk.is_logged_in(), "the session is dropped");
    drop(disk);
    assert_eq!(net.target.stats.logouts, 0);
    assert_eq!(sockets(&net), 0);
}

#[test]
fn explicit_logout() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let mut disk = connect(&mut net);
    disk.logout().unwrap();
    assert!(!disk.is_logged_in());
    let mut buf = [0u8; 512];
    assert_eq!(disk.read_blocks(0, &mut buf), Err(BlockError::Io));
    assert_eq!(disk.logout(), Err(IscsiError::NoSession));
    drop(disk);
    assert_eq!(net.target.stats.logouts, 1);
}

#[test]
fn send_targets_discovery() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let targets = discover(&mut net, PORTAL, &options()).unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0].name, TARGET_NAME);
    assert_eq!(targets[0].portals().collect::<Vec<_>>(), [PORTAL]);
    assert_eq!(targets[1].portals().collect::<Vec<_>>(), [SocketAddrV4::new(Ipv4Addr::new(10, 9, 8, 7), 3260)]);
    assert_eq!((net.target.stats.logins, net.target.stats.logouts), (1, 1));
    assert_eq!(sockets(&net), 0);
    // A normal session can follow on a new connection.
    let disk = connect(&mut net);
    assert_eq!(disk.num_blocks(), BLOCKS as u64);
}

#[test]
fn endless_login_text_is_refused() {
    // 4 KiB more each time: the text cap ends it.
    let cfg = TargetConfig { login_flood: Some(4096), ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let e = IscsiDisk::connect(&mut net, PORTAL, &options()).err().unwrap();
    assert_eq!(e, IscsiError::Protocol("login text too long"));
    // A little more each time: the exchange limit ends it.
    let cfg = TargetConfig { login_flood: Some(32), ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let e = IscsiDisk::connect(&mut net, PORTAL, &options()).err().unwrap();
    assert_eq!(e, IscsiError::Protocol("login did not finish"));
    assert_eq!(sockets(&net), 0);
}

#[test]
fn skipping_operational_negotiation_is_refused() {
    // We ask for LoginOperationalNegotiation next; the target may not go
    // further.
    let cfg = TargetConfig { skip_operational: true, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let e = IscsiDisk::connect(&mut net, PORTAL, &options()).err().unwrap();
    assert_eq!(e, IscsiError::Protocol("Login Response with a bad next stage"));
}

#[test]
fn endless_send_targets_text_is_refused() {
    let cfg = TargetConfig { text_flood: true, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    assert_eq!(discover(&mut net, PORTAL, &options()), Err(IscsiError::Protocol("SendTargets text too long")));
}

#[test]
fn a_trickling_target_times_out() {
    // Each Data-In comes well within the timeout, but the command as a
    // whole takes longer.
    let cfg = TargetConfig { trickle: 50, data_in_segment: 512, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let opts = Options { timeout: core::time::Duration::from_millis(500), ..options() };
    let mut disk = IscsiDisk::connect(&mut net, PORTAL, &opts).unwrap();
    let start = disk.net_mut().now;
    let mut buf = vec![0u8; 64 * 512];
    assert_eq!(disk.execute(&scsi::read(0, 64), Data::In(&mut buf)), Err(IscsiError::TimedOut));
    let took = disk.net_mut().now - start;
    assert!(took >= opts.timeout && took < opts.timeout * 2, "{took:?}");
    assert!(!disk.is_logged_in());
}

/// Runs a read or write against a target that misbehaves with `fault`,
/// returning the command's result and whether the session survived.
fn faulty(cfg: TargetConfig, fault: Fault, write: bool, blocks: u32) -> (Result<usize, IscsiError>, bool) {
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = connect(&mut net);
    disk.net_mut().target.fault = Some(fault);
    let mut buf = pattern(blocks as usize * 512, 4);
    let r = if write {
        disk.execute(&scsi::write(16, blocks), Data::Out(&buf))
    } else {
        disk.execute(&scsi::read(16, blocks), Data::In(&mut buf))
    };
    (r, disk.is_logged_in())
}

#[test]
fn data_in_out_of_order_or_short_fails() {
    let small = TargetConfig { data_in_segment: 1024, ..TargetConfig::default() };
    for (fault, why) in [
        (Fault::DataInLastOnly, "Data-In out of order"),
        (Fault::DataInSkipSn, "Data-In out of order"),
        (Fault::DataInShort, "residual does not match the data moved"),
    ] {
        assert_eq!(faulty(small.clone(), fault, false, 8), (Err(IscsiError::Protocol(why)), false), "{fault:?}");
    }
    // The same with the status in a separate SCSI Response.
    let separate = TargetConfig { status_in_data_in: false, ..small };
    let r = faulty(separate, Fault::DataInShort, false, 8);
    assert_eq!(r, (Err(IscsiError::Protocol("residual does not match the data moved")), false));
}

#[test]
fn underflows_are_short_and_fail_block_io() {
    // A reported underflow is no protocol error: the command moved less.
    assert_eq!(faulty(TargetConfig::default(), Fault::DataInUnderflow, false, 8), (Ok(7 * 512), true));
    assert_eq!(faulty(TargetConfig::default(), Fault::WriteUnderflow, true, 8), (Ok(7 * 512), true));
    // But a block read or write that comes up short fails.
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let mut disk = connect(&mut net);
    let mut buf = vec![0u8; 8 * 512];
    disk.net_mut().target.fault = Some(Fault::DataInUnderflow);
    assert_eq!(disk.read_blocks(0, &mut buf), Err(BlockError::Io));
    disk.net_mut().target.fault = Some(Fault::WriteUnderflow);
    assert_eq!(disk.write_blocks(0, &buf), Err(BlockError::Io));
    assert!(disk.is_logged_in());
    disk.read_blocks(0, &mut buf).unwrap();
}

#[test]
fn bad_r2ts_fail() {
    let cfg = TargetConfig {
        initial_r2t: true,
        immediate_data: false,
        max_burst: 4096,
        first_burst: 4096,
        ..TargetConfig::default()
    };
    for (fault, why) in [
        (Fault::R2tZeroLength, "R2T length outside 1..=MaxBurstLength"),
        (Fault::R2tReservedTtt, "R2T out of step"),
        (Fault::R2tSkipSn, "R2T out of step"),
        (Fault::R2tGap, "R2T out of step"),
        (Fault::R2tPastEnd, "R2T beyond the buffer"),
    ] {
        assert_eq!(faulty(cfg.clone(), fault, true, 4), (Err(IscsiError::Protocol(why)), false), "{fault:?}");
    }
}

#[test]
fn a_skipped_stat_sn_fails() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let mut disk = connect(&mut net);
    disk.net_mut().target.skip_stat_sn = true;
    let e = disk.execute(&scsi::test_unit_ready(), Data::None).unwrap_err();
    assert_eq!(e, IscsiError::Protocol("StatSN out of sequence"));
    assert!(!disk.is_logged_in());
}

#[test]
fn data_segments_are_held_to_our_mrdsl() {
    let cfg = TargetConfig { ignore_mrdsl: true, data_in_segment: 8192, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let offer = crate::Offer { max_recv_data_segment_length: 4096, ..crate::Offer::default() };
    let opts = Options { offer, ..options() };
    let mut disk = IscsiDisk::connect(&mut net, PORTAL, &opts).unwrap();
    let mut buf = vec![0u8; 16 * 512];
    let e = disk.execute(&scsi::read(0, 16), Data::In(&mut buf)).unwrap_err();
    assert_eq!(e, IscsiError::Protocol("data segment too long"));
}

#[test]
fn odd_block_sizes_are_refused() {
    for (size, ok) in [(300, false), (520, false), (256, false), (1 << 17, false), (4096, true)] {
        let cfg = TargetConfig { reported_block_size: Some(size), ..TargetConfig::default() };
        let mut net = TestNet::new(cfg, BLOCKS);
        match IscsiDisk::connect(&mut net, PORTAL, &options()) {
            Ok(d) => assert!(ok && d.block_size() == size as usize, "{size}"),
            Err(e) => assert!(!ok && e == IscsiError::Protocol("unusable capacity"), "{size}: {e:?}"),
        }
    }
}

/// The initiator against scripts/iscsi-target.py, over stdin/stdout as
/// QEMU's guestfwd runs it.
#[test]
fn against_the_python_target() {
    let image = std::env::temp_dir().join(std::format!("osmium-iscsi-test-{}.img", std::process::id()));
    std::fs::write(&image, pattern(BLOCKS * 512, 9)).unwrap();
    let Some(mut net) = TestNet::python(&image) else {
        std::eprintln!("python3 not found; skipping");
        return;
    };
    let targets = discover(&mut net, PORTAL, &options()).unwrap();
    assert_eq!(targets[0].name, TARGET_NAME);

    // Defaults (immediate and unsolicited data), then everything by R2T in
    // small bursts.
    let offers = [
        crate::Offer::default(),
        crate::Offer {
            initial_r2t: true,
            immediate_data: false,
            max_burst_length: 16384,
            max_recv_data_segment_length: 4096,
            ..crate::Offer::default()
        },
    ];
    for (n, offer) in offers.into_iter().enumerate() {
        let opts = Options { offer, ..options() };
        let mut disk = IscsiDisk::connect(&mut net, PORTAL, &opts).unwrap();
        assert_eq!((disk.block_size(), disk.num_blocks()), (512, BLOCKS as u64));
        assert_eq!(disk.inquiry().vendor(), "OSMIUM");
        let mut buf = vec![0u8; 8 * 512];
        disk.read_blocks(0, &mut buf).unwrap();
        assert!(buf[..] == pattern(BLOCKS * 512, 9)[..8 * 512]);
        let data = pattern(300 * 512, n as u8);
        disk.write_blocks(1000, &data).unwrap();
        disk.flush().unwrap();
        let mut back = vec![0u8; data.len()];
        disk.read_blocks(1000, &mut back).unwrap();
        assert!(back == data);
        let e = disk.execute(&scsi::read(BLOCKS as u64, 1), Data::In(&mut buf[..512])).unwrap_err();
        assert_eq!(e.sense_key(), Some(sense_key::ILLEGAL_REQUEST));
        drop(disk);
        let on_disk = std::fs::read(&image).unwrap();
        assert!(on_disk[1000 * 512..1300 * 512] == data[..]);
    }
    drop(net);
    let _ = std::fs::remove_file(&image);
}
