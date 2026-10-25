//! Error recovery levels 1 and 2 against the fake target, which loses
//! PDUs, fails digests, and drops connections on request.

use core::time::Duration;
use std::vec;
use std::vec::Vec;

use osmium_hal::block::BlockDevice;

use crate::params::DigestPolicy;
use crate::pdu::snack;
use crate::scsi;
use crate::testing::{Corrupt, Fault, Kill, Loss, PORTAL, TargetConfig, TestNet};
use crate::tests::{BLOCKS, options, pattern, sockets};
use crate::{Data, IscsiDisk, IscsiError, Options};

fn at_level(level: u8) -> Options {
    let mut o = options();
    o.offer.error_recovery_level = level;
    o.snack_timeout = Duration::from_millis(30);
    o
}

fn connect(net: &mut TestNet, level: u8) -> IscsiDisk<&mut TestNet> {
    IscsiDisk::connect(net, PORTAL, &at_level(level)).unwrap()
}

/// Segments of 1 KiB make a 32 KiB read 32 Data-In PDUs.
fn small_segments() -> TargetConfig {
    TargetConfig { data_in_segment: 1024, ..TargetConfig::default() }
}

fn read32k(disk: &mut IscsiDisk<&mut TestNet>) -> Result<Vec<u8>, osmium_hal::block::BlockError> {
    let mut buf = vec![0u8; 64 * 512];
    disk.read_blocks(100, &mut buf).map(|()| buf)
}

fn expected32k(disk: &mut IscsiDisk<&mut TestNet>) -> Vec<u8> {
    disk.net_mut().target.disk[100 * 512..164 * 512].to_vec()
}

#[test]
fn the_level_is_negotiated() {
    for (offered, agreed_by_a_level_1_target, want) in [(0, 2, 0), (1, 2, 1), (2, 2, 2), (2, 1, 1), (2, 0, 0)] {
        let cfg = TargetConfig { erl: agreed_by_a_level_1_target, ..TargetConfig::default() };
        let mut net = TestNet::new(cfg, BLOCKS);
        let disk = connect(&mut net, offered);
        assert_eq!(
            disk.params().error_recovery_level,
            want,
            "offered {offered}, target allows {agreed_by_a_level_1_target}"
        );
    }
}

#[test]
fn a_lost_data_in_is_asked_for_again() {
    let mut net = TestNet::new(small_segments(), BLOCKS);
    let mut disk = connect(&mut net, 1);
    let want = expected32k(&mut disk);
    disk.net_mut().target.lose.push(Loss::DataIn(2));
    assert!(read32k(&mut disk).unwrap() == want);
    let t = &disk.net_mut().target;
    // The Data-In after the gap showed it; everything from the gap on came again.
    assert_eq!(t.stats.snacks, [(snack::DATA_R2T, 2, 0)]);
    assert!(disk.is_logged_in());
}

#[test]
fn the_same_loss_ends_a_level_0_session() {
    let mut net = TestNet::new(small_segments(), BLOCKS);
    let mut disk = connect(&mut net, 0);
    disk.net_mut().target.lose.push(Loss::DataIn(2));
    assert!(read32k(&mut disk).is_err());
    assert!(!disk.is_logged_in());
    assert!(disk.net_mut().target.stats.snacks.is_empty());
}

#[test]
fn a_lost_last_data_in_is_found_by_the_status() {
    // The status comes in its own PDU, with ExpDataSN counting the Data-In
    // sent: the last of them was lost, so the status is held back (R-Data).
    let cfg = TargetConfig { status_in_data_in: false, ..small_segments() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = connect(&mut net, 1);
    let want = expected32k(&mut disk);
    disk.net_mut().target.lose.push(Loss::DataIn(31));
    assert!(read32k(&mut disk).unwrap() == want);
    assert_eq!(disk.net_mut().target.stats.snacks, [(snack::R_DATA, 31, 0)]);
}

#[test]
fn a_lost_status_is_asked_for_after_a_while() {
    let cfg = TargetConfig { status_in_data_in: false, ..small_segments() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = connect(&mut net, 1);
    let want = expected32k(&mut disk);
    disk.net_mut().target.lose.push(Loss::Response);
    assert!(read32k(&mut disk).unwrap() == want);
    let snacks = disk.net_mut().target.stats.snacks.clone();
    assert!(snacks.iter().any(|s| s.0 == snack::STATUS), "{snacks:?}");
    // And with the status in the last Data-In.
    let mut net = TestNet::new(small_segments(), BLOCKS);
    let mut disk = connect(&mut net, 1);
    disk.net_mut().target.lose.push(Loss::DataInWithStatus);
    assert!(read32k(&mut disk).unwrap() == expected32k(&mut disk));
    assert!(!disk.net_mut().target.stats.snacks.is_empty());
}

#[test]
fn a_status_sequence_gap_is_asked_for() {
    // An event the network lost takes a StatSN: the response after it is
    // ahead of the one expected, so it is set aside and the statuses from the
    // gap on are requested.
    let cfg = TargetConfig { status_in_data_in: false, ..small_segments() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = connect(&mut net, 1);
    let want = expected32k(&mut disk);
    disk.net_mut().target.lost_async = true;
    assert!(read32k(&mut disk).unwrap() == want);
    let snacks = disk.net_mut().target.stats.snacks.clone();
    assert_eq!(snacks.len(), 1, "{snacks:?}");
    assert_eq!((snacks[0].0, snacks[0].2), (snack::STATUS, 0));
    // The next command is in step.
    assert!(read32k(&mut disk).unwrap() == want);
}

#[test]
fn a_status_gap_ends_a_level_0_session() {
    let cfg = TargetConfig { status_in_data_in: false, ..small_segments() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = connect(&mut net, 0);
    disk.net_mut().target.lost_async = true;
    assert!(read32k(&mut disk).is_err());
    assert!(!disk.is_logged_in());
}

#[test]
fn a_lost_r2t_is_asked_for_again() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let mut disk = connect(&mut net, 1);
    // 128 KiB: 64 KiB go unsolicited, then the target must send an R2T.
    let data = pattern(256 * 512, 6);
    disk.net_mut().target.lose.push(Loss::R2t);
    disk.write_blocks(40, &data).unwrap();
    let t = &disk.net_mut().target;
    assert!(t.disk[40 * 512..296 * 512] == data[..]);
    assert_eq!(t.stats.snacks, [(snack::DATA_R2T, 0, 1)]);
}

#[test]
fn a_lost_command_is_sent_again() {
    for lost_to in [0, 1] {
        let mut net = TestNet::new(small_segments(), BLOCKS);
        let mut disk = connect(&mut net, 1);
        let want = expected32k(&mut disk);
        // Either the network lost it or the target rejected it for a digest error.
        if lost_to == 0 {
            disk.net_mut().target.drop_next_command = true;
        } else {
            disk.net_mut().target.reject_next_command = true;
        }
        assert!(read32k(&mut disk).unwrap() == want);
        let data = pattern(16 * 512, 7);
        if lost_to == 0 {
            disk.net_mut().target.drop_next_command = true;
        } else {
            disk.net_mut().target.reject_next_command = true;
        }
        disk.write_blocks(7, &data).unwrap();
        let t = &disk.net_mut().target;
        assert!(t.disk[7 * 512..23 * 512] == data[..]);
        assert_eq!(t.stats.duplicate_commands, 0, "the retry used the CmdSN the target was still waiting for");
        assert_eq!(t.stats.rejects, 2 * lost_to);
        // The two commands were not numbered twice.
        assert!(t.stats.cmd_sns.windows(2).all(|w| w[1] == w[0] + 1), "{:?}", t.stats.cmd_sns);
    }
}

#[test]
fn a_silent_target_is_given_up_on_at_level_1() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let mut o = at_level(1);
    o.timeout = Duration::from_secs(2);
    let mut disk = IscsiDisk::connect(&mut net, PORTAL, &o).unwrap();
    disk.net_mut().target.ignore_next = true;
    let r = disk.execute(&scsi::test_unit_ready(), Data::None);
    assert_eq!(r, Err(IscsiError::TimedOut));
}

#[test]
fn a_data_digest_error_is_asked_for_again() {
    let mut o = at_level(1);
    o.offer.data_digest = DigestPolicy::Require;
    let digests = TargetConfig { data_digest: "CRC32C", header_digest: "CRC32C", ..small_segments() };
    let mut net = TestNet::new(TargetConfig { header_digest: "None", ..digests.clone() }, BLOCKS);
    let mut disk = IscsiDisk::connect(&mut net, PORTAL, &o).unwrap();
    let want = expected32k(&mut disk);
    disk.net_mut().target.corrupt = Some(Corrupt::Data);
    assert!(read32k(&mut disk).unwrap() == want);
    assert!(!disk.net_mut().target.stats.snacks.is_empty());
    assert!(disk.is_logged_in());

    // A header digest error cannot be recovered at level 1: the length of
    // the PDU is not to be trusted.
    o.offer.header_digest = DigestPolicy::Require;
    let mut net = TestNet::new(digests, BLOCKS);
    let mut disk = IscsiDisk::connect(&mut net, PORTAL, &o).unwrap();
    disk.net_mut().target.corrupt = Some(Corrupt::Header);
    assert!(read32k(&mut disk).is_err());
    assert!(!disk.is_logged_in());
}

#[test]
fn a_data_out_digest_error_gets_a_recovery_r2t() {
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let mut disk = connect(&mut net, 1);
    // Unsolicited data up to FirstBurstLength, then 64 KiB solicited by R2T,
    // the first PDU of which the target says failed its digest.
    let data = pattern(256 * 512, 8);
    disk.net_mut().target.reject_next_data_out = true;
    disk.write_blocks(40, &data).unwrap();
    let t = &disk.net_mut().target;
    assert!(t.disk[40 * 512..296 * 512] == data[..]);
    assert_eq!(t.stats.rejects, 1);
    assert_eq!(t.stats.r2ts, 2, "the second R2T asks again for the range");
}

#[test]
fn data_ack_is_sent_when_the_target_asks() {
    // 4 KiB segments: eight PDUs.
    let cfg = TargetConfig { ack_every: Some(2), data_in_segment: 4096, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = connect(&mut net, 1);
    let want = expected32k(&mut disk);
    assert!(read32k(&mut disk).unwrap() == want);
    // Eight PDUs: asked after the 2nd, 4th and 6th (not the last).
    assert_eq!(disk.net_mut().target.stats.data_acks, 3);
    // Never at level 0.
    let cfg = TargetConfig { ack_every: Some(2), data_in_segment: 4096, ..TargetConfig::default() };
    let mut net = TestNet::new(cfg, BLOCKS);
    let mut disk = connect(&mut net, 0);
    read32k(&mut disk).unwrap();
    assert_eq!(disk.net_mut().target.stats.data_acks, 0);
}

#[test]
fn a_hostile_target_cannot_loop_a_level_1_initiator() {
    // Each of these is a fault in what the target sends; none may panic or
    // hang, and the initiator ends with an error.
    for fault in [
        Fault::R2tZeroLength,
        Fault::R2tReservedTtt,
        Fault::R2tSkipSn,
        Fault::R2tPastEnd,
        Fault::DataInSkipSn,
        Fault::DataInLastOnly,
    ] {
        let mut o = at_level(1);
        o.timeout = Duration::from_secs(2);
        let write = fault != Fault::DataInSkipSn && fault != Fault::DataInLastOnly;
        let mut net = TestNet::new(small_segments(), BLOCKS);
        let mut disk = IscsiDisk::connect(&mut net, PORTAL, &o).unwrap();
        disk.net_mut().target.fault = Some(fault);
        let mut buf = pattern(256 * 512, 4);
        let r = if write {
            disk.execute(&scsi::write(16, 256), Data::Out(&buf))
        } else {
            disk.execute(&scsi::read(16, 8), Data::In(&mut buf[..8 * 512]))
        };
        assert!(r.is_err(), "{fault:?}");
    }
}

// ---- Level 2: connection recovery ----

fn recovering(net: &mut TestNet) -> IscsiDisk<&mut TestNet> {
    connect(net, 2)
}

#[test]
fn a_read_survives_the_loss_of_its_connection() {
    let mut net = TestNet::new(small_segments(), BLOCKS);
    let mut disk = recovering(&mut net);
    let want = expected32k(&mut disk);
    // The target does everything for the command, then the connection is reset
    // before the initiator hears any of it.
    disk.net_mut().target.kill = Some(Kill::AfterCommand);
    assert!(read32k(&mut disk).unwrap() == want);
    let s = &disk.net_mut().target.stats;
    assert_eq!((s.logins, s.additional_logins, s.reassigns), (2, 1, 1));
    assert_eq!(s.exp_stat_sn_violations, 0);
    // The session carries on over the new connection, and logs out there.
    assert!(read32k(&mut disk).unwrap() == want);
    assert_eq!(disk.connections(), 1);
    drop(disk);
    assert_eq!(net.target.stats.logouts, 1);
    assert_eq!(sockets(&net), 0);
}

#[test]
fn a_command_the_target_never_saw_is_sent_again_on_the_new_connection() {
    let mut net = TestNet::new(small_segments(), BLOCKS);
    let mut disk = recovering(&mut net);
    let want = expected32k(&mut disk);
    disk.net_mut().target.kill = Some(Kill::BeforeCommand);
    assert!(read32k(&mut disk).unwrap() == want);
    let s = &disk.net_mut().target.stats;
    assert_eq!((s.reassigns, s.duplicate_commands), (0, 0));
    assert_eq!(s.additional_logins, 1);
    assert!(s.cmd_sns.windows(2).all(|w| w[1] == w[0] + 1), "{:?}", s.cmd_sns);
}

#[test]
fn a_write_is_resumed_after_the_loss_of_its_connection() {
    for kill_after in [1, 3, 7, 9] {
        let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
        let mut disk = recovering(&mut net);
        // 128 KiB: 8 KiB immediate, unsolicited Data-Out up to 64 KiB, then
        // an R2T for the rest. The connection goes after some of the Data-Out.
        let data = pattern(256 * 512, 3);
        disk.net_mut().target.kill = Some(Kill::DataOut(kill_after));
        disk.write_blocks(40, &data).unwrap();
        let t = &disk.net_mut().target;
        assert!(t.disk[40 * 512..296 * 512] == data[..], "killed after {kill_after} Data-Out");
        assert_eq!((t.stats.reassigns, t.stats.additional_logins), (1, 1));
        let mut back = vec![0u8; data.len()];
        disk.read_blocks(40, &mut back).unwrap();
        assert!(back == data);
    }
}

#[test]
fn the_target_asks_for_a_reconnection() {
    let mut net = TestNet::new(small_segments(), BLOCKS);
    let mut disk = recovering(&mut net);
    let want = expected32k(&mut disk);
    // The event comes right behind the first read's data; the next command
    // finds the connection going away and logs in again.
    disk.net_mut().target.async_drop = true;
    assert!(read32k(&mut disk).unwrap() == want);
    assert!(read32k(&mut disk).unwrap() == want);
    assert!(read32k(&mut disk).unwrap() == want);
    assert_eq!(disk.net_mut().target.stats.additional_logins, 1);
    // Below level 2 the same event ends the session.
    let mut net = TestNet::new(small_segments(), BLOCKS);
    let mut disk = connect(&mut net, 1);
    disk.net_mut().target.async_drop = true;
    let _ = read32k(&mut disk);
    assert!(read32k(&mut disk).is_err());
    assert!(!disk.is_logged_in());
}

#[test]
fn one_of_several_connections_is_recovered_while_the_others_carry_on() {
    let mut o = at_level(2);
    o.offer.max_connections = 3;
    let mut net = TestNet::new(TargetConfig::default(), BLOCKS);
    let mut disk = IscsiDisk::connect(&mut net, PORTAL, &o).unwrap();
    assert_eq!(disk.connections(), 3);
    let data = pattern(BLOCKS * 512, 2);
    disk.write_blocks(0, &data).unwrap();
    disk.net_mut().target.kill = Some(Kill::AfterCommand);
    let mut back = vec![0u8; data.len()];
    disk.read_blocks(0, &mut back).unwrap();
    assert!(back == data);
    let s = &disk.net_mut().target.stats;
    assert_eq!((s.logins, s.reassigns), (4, 1));
    assert_eq!(s.exp_stat_sn_violations, 0);
    assert_eq!(disk.connections(), 3);
}

#[test]
fn a_connection_that_cannot_be_replaced_ends_the_session() {
    let mut net = TestNet::new(small_segments(), BLOCKS);
    let mut disk = recovering(&mut net);
    disk.net_mut().target.cfg.refuse_additional = true;
    disk.net_mut().target.kill = Some(Kill::AfterCommand);
    assert!(read32k(&mut disk).is_err());
    assert!(!disk.is_logged_in());
    drop(disk);
    assert_eq!(sockets(&net), 0);
}

#[test]
fn a_task_the_target_has_forgotten_fails_alone() {
    // The target no longer has the task (TASK REASSIGN is answered "task
    // does not exist"): that command fails, the session lives.
    let mut net = TestNet::new(small_segments(), BLOCKS);
    let mut disk = recovering(&mut net);
    disk.net_mut().target.kill = Some(Kill::AfterCommand);
    disk.net_mut().target.forget_tasks = true;
    let r = read32k(&mut disk);
    assert!(r.is_err());
    assert!(disk.is_logged_in());
    assert!(read32k(&mut disk).is_ok());
}
