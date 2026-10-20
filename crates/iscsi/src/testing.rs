//! Test fixtures: two osmium-net interfaces joined by a simulated Ethernet
//! link (as in osmium-net's own tests), and a fake iSCSI target serving a
//! RAM disk from a TCP socket on the second one.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use osmium_hal::net::{MacAddress, NetDevice, NetError};
use osmium_net::{Config, Instant, Interface, Ipv4Addr, SocketAddrV4, SocketHandle, SocketSet, TcpSocket, TcpState};

use crate::Net;
use crate::pdu::*;
use crate::scsi::{self, Sense, op, sense_key};
use crate::text;

type Queue = Rc<RefCell<VecDeque<Vec<u8>>>>;

/// One end of the link.
pub(crate) struct Port {
    mac: MacAddress,
    rx: Queue,
    tx: Queue,
}

impl NetDevice for Port {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        assert!(frame.len() <= self.max_frame_len(), "oversized frame");
        self.tx.borrow_mut().push_back(frame.to_vec());
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        let frame = self.rx.borrow_mut().pop_front().ok_or(NetError::WouldBlock)?;
        buf[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }

    fn can_receive(&self) -> bool {
        !self.rx.borrow().is_empty()
    }

    fn can_transmit(&self) -> bool {
        true
    }
}

pub(crate) struct Host {
    pub(crate) iface: Interface,
    pub(crate) dev: Port,
    pub(crate) sockets: SocketSet,
}

impl Host {
    fn poll(&mut self, now: Instant) {
        self.iface.poll(now, &mut self.dev, &mut self.sockets);
    }
}

pub(crate) const A_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
pub(crate) const B_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 2);
pub(crate) const PORTAL: SocketAddrV4 = SocketAddrV4::new(B_IP, 3260);
pub(crate) const TARGET_NAME: &str = "iqn.2026-10.org.osmium:disk0";
pub(crate) const INITIATOR_NAME: &str = "iqn.2026-10.org.osmium:test";

/// Hosts A (192.168.1.1, the initiator) and B (192.168.1.2) on one /24.
fn pair() -> (Host, Host) {
    let (ab, ba): (Queue, Queue) = Default::default();
    let host = |n: u8, rx: &Queue, tx: &Queue, ip: Ipv4Addr| {
        let dev = Port { mac: MacAddress([2, 0, 0, 0, 0, n]), rx: rx.clone(), tx: tx.clone() };
        let mut iface = Interface::new(&dev, n.into());
        iface.set_config(Some(Config { address: ip, prefix_len: 24, gateway: None, dns: None }));
        Host { iface, dev, sockets: SocketSet::new() }
    };
    (host(1, &ba, &ab, A_IP), host(2, &ab, &ba, B_IP))
}

/// The initiator's view of the network: host A, with host B and the target
/// run on every poll. Each poll advances the clock by a millisecond.
pub(crate) struct TestNet {
    pub(crate) a: Host,
    pub(crate) b: Host,
    pub(crate) target: Target,
    /// Serves port 3260 from scripts/iscsi-target.py instead of `target`.
    relay: Option<Relay>,
    pub(crate) now: Instant,
}

impl TestNet {
    pub(crate) fn new(cfg: TargetConfig, blocks: usize) -> Self {
        let (a, b) = pair();
        Self { a, b, target: Target::new(cfg, blocks), relay: None, now: Instant::ZERO }
    }

    /// Port 3260 of host B relayed to scripts/iscsi-target.py serving
    /// `image`, one process per connection as QEMU's guestfwd runs it.
    /// Time is real, since the target is. `None` without python3.
    pub(crate) fn python(image: &std::path::Path) -> Option<Self> {
        let ok = std::process::Command::new("python3").arg("--version").output().is_ok_and(|o| o.status.success());
        if !ok {
            return None;
        }
        let mut net = Self::new(TargetConfig::default(), 0);
        net.relay =
            Some(Relay { image: image.into(), start: std::time::Instant::now(), listener: None, conns: Vec::new() });
        Some(net)
    }
}

impl Net for TestNet {
    fn poll(&mut self) -> Instant {
        self.a.poll(self.now);
        self.b.poll(self.now);
        match &mut self.relay {
            Some(r) => {
                r.step(&mut self.b.sockets);
                std::thread::yield_now();
                self.now = Instant::from_millis(r.start.elapsed().as_millis() as u64);
            }
            None => {
                self.target.step(&mut self.b.sockets);
                self.now = Instant::from_millis(self.now.as_millis() + 1);
            }
        }
        self.now
    }

    fn with_sockets<R>(&mut self, f: impl FnOnce(&mut SocketSet) -> R) -> R {
        f(&mut self.a.sockets)
    }
}

/// How the fake target behaves.
#[derive(Clone)]
pub(crate) struct TargetConfig {
    /// The MaxRecvDataSegmentLength the target declares.
    pub(crate) mrdsl: u32,
    /// The target's InitialR2T and ImmediateData offers.
    pub(crate) initial_r2t: bool,
    pub(crate) immediate_data: bool,
    pub(crate) max_burst: u32,
    pub(crate) first_burst: u32,
    /// Largest Data-In segment (also limited by the initiator's MRDSL).
    pub(crate) data_in_segment: usize,
    /// Status goes in the last Data-In rather than a SCSI Response.
    pub(crate) status_in_data_in: bool,
    /// The first command reports UNIT ATTENTION.
    pub(crate) unit_attention: bool,
    /// Hold the initiator in SecurityNegotiation for one more round.
    pub(crate) extra_security_round: bool,
    /// Stay in LoginOperationalNegotiation one more round, offering a key
    /// the initiator must answer.
    pub(crate) extra_operational_round: bool,
    /// The block count READ CAPACITY reports, if not the RAM disk's.
    pub(crate) reported_blocks: Option<u64>,
}

impl Default for TargetConfig {
    fn default() -> Self {
        Self {
            mrdsl: 8192,
            initial_r2t: false,
            immediate_data: true,
            max_burst: 262_144,
            first_burst: 65536,
            data_in_segment: 8192,
            status_in_data_in: true,
            unit_attention: true,
            extra_security_round: false,
            extra_operational_round: false,
            reported_blocks: None,
        }
    }
}

/// A write waiting for its data.
struct Write {
    itt: u32,
    lun: [u8; 8],
    at: usize,
    buf: Vec<u8>,
    got: usize,
    unsolicited_done: bool,
    /// The end of the outstanding R2T's range, if one is outstanding.
    r2t_end: Option<usize>,
    next_offset: usize,
    r2t_sn: u32,
}

/// What a connection waits for before it carries on.
enum Pending {
    None,
    Write(Write),
    /// A NOP-In went out; the command runs once the NOP-Out comes back.
    Pong {
        ttt: u32,
        cmd: ScsiCommand,
    },
}

struct Conn {
    socket: SocketHandle,
    reader: PduReader,
    out: Vec<u8>,
    stat_sn: u32,
    exp_cmd_sn: u32,
    /// The initiator's declared MaxRecvDataSegmentLength.
    initiator_mrdsl: usize,
    initial_r2t: bool,
    immediate_data: bool,
    first_burst: usize,
    max_burst: usize,
    security_rounds: usize,
    operational_rounds: usize,
    pending: Pending,
    closing: bool,
}

/// Counts of what the target saw.
#[derive(Default, Debug)]
pub(crate) struct Stats {
    pub(crate) logins: usize,
    pub(crate) logouts: usize,
    pub(crate) commands: Vec<u8>,
    pub(crate) data_out: usize,
    pub(crate) unsolicited_data_out: usize,
    pub(crate) immediate_bytes: usize,
    pub(crate) r2ts: usize,
    pub(crate) data_in: usize,
    pub(crate) pongs: usize,
    pub(crate) unexpected_nop_outs: usize,
    /// The initiator's answers to keys the target offered.
    pub(crate) answers: Vec<(String, String)>,
}

/// A fake iSCSI target on port 3260 of whichever host steps it.
pub(crate) struct Target {
    pub(crate) cfg: TargetConfig,
    pub(crate) disk: Vec<u8>,
    pub(crate) stats: Stats,
    /// The next command with this opcode fails with this sense.
    pub(crate) fail_next: Option<(u8, Sense)>,
    /// Before the next SCSI command, ping the initiator with this TTT and
    /// wait for its answer (or don't wait, for [`RESERVED_TAG`]).
    pub(crate) ping: Option<u32>,
    /// Ignore the next SCSI command.
    pub(crate) ignore_next: bool,
    attention_sent: bool,
    listener: Option<SocketHandle>,
    conns: Vec<Conn>,
}

const BLOCK: usize = 512;

impl Target {
    fn new(cfg: TargetConfig, blocks: usize) -> Self {
        Self {
            cfg,
            disk: (0..blocks * BLOCK).map(|i| (i / BLOCK) as u8 ^ (i % 251) as u8).collect(),
            stats: Stats::default(),
            fail_next: None,
            ping: None,
            ignore_next: false,
            attention_sent: false,
            listener: None,
            conns: Vec::new(),
        }
    }

    /// Accepts connections and serves every PDU that has arrived.
    fn step(&mut self, sockets: &mut SocketSet) {
        match self.listener {
            Some(h) if sockets.get::<TcpSocket>(h).state() != TcpState::Listen => {
                self.conns.push(Conn {
                    socket: h,
                    reader: PduReader::new(1 << 24),
                    out: Vec::new(),
                    stat_sn: 0x1000,
                    exp_cmd_sn: 0,
                    initiator_mrdsl: 8192,
                    initial_r2t: true,
                    immediate_data: true,
                    first_burst: 65536,
                    max_burst: 262_144,
                    security_rounds: 0,
                    operational_rounds: 0,
                    pending: Pending::None,
                    closing: false,
                });
                self.listener = None;
            }
            Some(_) => {}
            None => {}
        }
        if self.listener.is_none() {
            let h = sockets.add(TcpSocket::new(65535, 1 << 20));
            sockets.get_mut::<TcpSocket>(h).listen(3260).unwrap();
            self.listener = Some(h);
        }
        let mut conns = core::mem::take(&mut self.conns);
        for c in &mut conns {
            let s = sockets.get_mut::<TcpSocket>(c.socket);
            let mut buf = [0u8; 4096];
            while let Ok(n @ 1..) = s.recv(&mut buf) {
                c.reader.push(&buf[..n]);
            }
            while let Some(pdu) = c.reader.next_pdu().unwrap() {
                let m = Message::decode(pdu).expect("initiator sent an unknown PDU");
                self.handle(c, m);
            }
            let s = sockets.get_mut::<TcpSocket>(c.socket);
            if !c.out.is_empty()
                && let Ok(n) = s.send(&c.out)
            {
                c.out.drain(..n);
            }
            if c.closing && c.out.is_empty() {
                s.close();
                c.closing = false;
            }
        }
        self.conns = conns;
    }

    fn send(c: &mut Conn, m: Message) {
        c.out.extend_from_slice(&m.encode().to_bytes());
    }

    /// The next StatSN for a status-bearing PDU.
    fn stat_sn(c: &mut Conn) -> u32 {
        c.stat_sn += 1;
        c.stat_sn - 1
    }

    fn window(c: &Conn) -> (u32, u32) {
        (c.exp_cmd_sn, c.exp_cmd_sn.wrapping_add(7))
    }

    fn handle(&mut self, c: &mut Conn, m: Message) {
        match m {
            Message::LoginRequest(r) => self.login(c, r),
            Message::ScsiCommand(cmd) => {
                assert_eq!(cmd.cmd_sn, c.exp_cmd_sn, "CmdSN in order");
                assert!(matches!(c.pending, Pending::None), "one command at a time");
                c.exp_cmd_sn = cmd.cmd_sn.wrapping_add(1);
                if core::mem::take(&mut self.ignore_next) {
                    return;
                }
                match self.ping.take() {
                    Some(ttt) => {
                        let (exp, max) = Self::window(c);
                        let stat_sn = c.stat_sn;
                        Self::send(
                            c,
                            Message::NopIn(NopIn {
                                lun: cmd.lun,
                                itt: RESERVED_TAG,
                                ttt,
                                stat_sn,
                                exp_cmd_sn: exp,
                                max_cmd_sn: max,
                                data: if ttt == RESERVED_TAG { vec![] } else { b"ping".to_vec() },
                            }),
                        );
                        if ttt == RESERVED_TAG {
                            self.execute(c, cmd);
                        } else {
                            c.pending = Pending::Pong { ttt, cmd };
                        }
                    }
                    None => self.execute(c, cmd),
                }
            }
            Message::NopOut(n) => {
                assert_eq!(n.itt, RESERVED_TAG, "answers carry no ITT");
                match core::mem::replace(&mut c.pending, Pending::None) {
                    Pending::Pong { ttt, cmd } if ttt == n.ttt => {
                        assert_eq!(n.data, b"ping", "ping data echoed");
                        self.stats.pongs += 1;
                        self.execute(c, cmd);
                    }
                    other => {
                        c.pending = other;
                        self.stats.unexpected_nop_outs += 1;
                    }
                }
            }
            Message::DataOut(d) => self.data_out(c, d),
            Message::TextRequest(t) => {
                assert_eq!(t.cmd_sn, c.exp_cmd_sn);
                c.exp_cmd_sn = t.cmd_sn.wrapping_add(1);
                let keys = text::parse(&t.data).unwrap();
                assert_eq!(keys, [("SendTargets", "All")]);
                let mut data = Vec::new();
                text::push(&mut data, "TargetName", TARGET_NAME);
                text::push(&mut data, "TargetAddress", "192.168.1.2:3260,1");
                text::push(&mut data, "TargetName", "iqn.2026-10.org.osmium:other");
                text::push(&mut data, "TargetAddress", "10.9.8.7,1");
                let (exp, max) = Self::window(c);
                let stat_sn = Self::stat_sn(c);
                Self::send(
                    c,
                    Message::TextResponse(TextResponse {
                        final_pdu: true,
                        cont: false,
                        lun: [0; 8],
                        itt: t.itt,
                        ttt: RESERVED_TAG,
                        stat_sn,
                        exp_cmd_sn: exp,
                        max_cmd_sn: max,
                        data,
                    }),
                );
            }
            Message::LogoutRequest(l) => {
                self.stats.logouts += 1;
                let (exp, max) = Self::window(c);
                let stat_sn = Self::stat_sn(c);
                Self::send(
                    c,
                    Message::LogoutResponse(LogoutResponse {
                        response: 0,
                        itt: l.itt,
                        stat_sn,
                        exp_cmd_sn: exp,
                        max_cmd_sn: max,
                        time2wait: 0,
                        time2retain: 0,
                    }),
                );
                c.closing = true;
            }
            m => panic!("unexpected PDU from the initiator: {m:?}"),
        }
    }

    fn login(&mut self, c: &mut Conn, r: LoginRequest) {
        let keys: Vec<(String, String)> =
            text::parse(&r.data).unwrap().into_iter().map(|(k, v)| (k.into(), v.into())).collect();
        let get = |k: &str| keys.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str());
        let mut out = Vec::new();
        let mut class = 0;
        let mut transit = r.transit;
        let mut nsg = r.nsg;
        if r.csg == stage::SECURITY && c.security_rounds == 0 {
            c.exp_cmd_sn = r.cmd_sn;
            assert_eq!(get("InitiatorName"), Some(INITIATOR_NAME));
            match get("SessionType") {
                Some("Discovery") => {}
                _ if get("TargetName") != Some(TARGET_NAME) => class = 2,
                _ => {}
            }
        }
        match r.csg {
            stage::SECURITY => {
                c.security_rounds += 1;
                if c.security_rounds == 1 {
                    assert_eq!(get("AuthMethod"), Some("None"));
                    text::push(&mut out, "AuthMethod", "None");
                    text::push(&mut out, "TargetPortalGroupTag", "1");
                }
                if self.cfg.extra_security_round && c.security_rounds == 1 {
                    (transit, nsg) = (false, 0);
                }
            }
            stage::OPERATIONAL => {
                c.operational_rounds += 1;
                let cfg = &self.cfg;
                for (k, v) in &keys {
                    let num = || text::number(v).unwrap() as usize;
                    let yes = || text::boolean(v).unwrap();
                    let reply: String = match k.as_str() {
                        "HeaderDigest" | "DataDigest" => "None".into(),
                        "MaxRecvDataSegmentLength" => {
                            c.initiator_mrdsl = num();
                            continue;
                        }
                        "InitialR2T" => {
                            c.initial_r2t = yes() || cfg.initial_r2t;
                            text::yes_no(c.initial_r2t).into()
                        }
                        "ImmediateData" => {
                            c.immediate_data = yes() && cfg.immediate_data;
                            text::yes_no(c.immediate_data).into()
                        }
                        "MaxBurstLength" => {
                            c.max_burst = num().min(cfg.max_burst as usize);
                            c.max_burst.to_string()
                        }
                        "FirstBurstLength" => {
                            c.first_burst = num().min(cfg.first_burst as usize);
                            c.first_burst.to_string()
                        }
                        "X-org.osmium.Probe" => {
                            self.stats.answers.push((k.clone(), v.clone()));
                            continue;
                        }
                        _ => v.clone(),
                    };
                    text::push(&mut out, k, &reply);
                }
                if c.operational_rounds == 1 {
                    text::push(&mut out, "MaxRecvDataSegmentLength", &cfg.mrdsl.to_string());
                }
                if self.cfg.extra_operational_round && c.operational_rounds == 1 {
                    text::push(&mut out, "X-org.osmium.Probe", "1");
                    (transit, nsg) = (false, 0);
                }
            }
            s => panic!("login in stage {s}"),
        }
        if transit && nsg == stage::FULL_FEATURE {
            self.stats.logins += 1;
        }
        let (exp, max) = Self::window(c);
        let stat_sn = Self::stat_sn(c);
        Self::send(
            c,
            Message::LoginResponse(LoginResponse {
                transit: transit && class == 0,
                cont: false,
                csg: r.csg,
                nsg: if transit { nsg } else { 0 },
                isid: r.isid,
                tsih: if transit && nsg == stage::FULL_FEATURE { 7 } else { 0 },
                itt: r.itt,
                stat_sn,
                exp_cmd_sn: exp,
                max_cmd_sn: max,
                status_class: class,
                status_detail: if class == 0 { 0 } else { 3 },
                data: if class == 0 { out } else { vec![] },
            }),
        );
        if class != 0 {
            c.closing = true;
        }
    }

    fn blocks(&self) -> u64 {
        (self.disk.len() / BLOCK) as u64
    }

    fn execute(&mut self, c: &mut Conn, cmd: ScsiCommand) {
        let opcode = cmd.cdb[0];
        self.stats.commands.push(opcode);
        if let Some((op, sense)) = self.fail_next
            && op == opcode
        {
            self.fail_next = None;
            return self.respond(c, cmd.itt, scsi::status::CHECK_CONDITION, Some(sense), 0);
        }
        if self.cfg.unit_attention && !self.attention_sent {
            self.attention_sent = true;
            let sense = Sense { key: sense_key::UNIT_ATTENTION, asc: 0x29, ascq: 0 };
            return self.respond(c, cmd.itt, scsi::status::CHECK_CONDITION, Some(sense), 0);
        }
        let reported = self.cfg.reported_blocks.unwrap_or(self.blocks());
        match opcode {
            op::TEST_UNIT_READY => self.respond(c, cmd.itt, 0, None, 0),
            op::INQUIRY => {
                let mut d = vec![b' '; 36];
                d[..8].copy_from_slice(&[0, 0, 5, 2, 31, 0, 0, 0]);
                d[8..14].copy_from_slice(b"OSMIUM");
                d[16..25].copy_from_slice(b"FAKE DISK");
                d[32..36].copy_from_slice(b"0001");
                let len = u16::from_be_bytes([cmd.cdb[3], cmd.cdb[4]]) as usize;
                d.truncate(len);
                self.data_in(c, &cmd, d);
            }
            op::READ_CAPACITY_10 => {
                let last = (reported - 1).min(u32::MAX as u64) as u32;
                let mut d = last.to_be_bytes().to_vec();
                d.extend_from_slice(&(BLOCK as u32).to_be_bytes());
                self.data_in(c, &cmd, d);
            }
            op::SERVICE_ACTION_IN_16 if cmd.cdb[1] == scsi::SA_READ_CAPACITY_16 => {
                let mut d = vec![0; 32];
                d[..8].copy_from_slice(&(reported - 1).to_be_bytes());
                d[8..12].copy_from_slice(&(BLOCK as u32).to_be_bytes());
                self.data_in(c, &cmd, d);
            }
            op::READ_10 | op::READ_16 | op::WRITE_10 | op::WRITE_16 => {
                let (lba, n) = scsi::rw_range(&cmd.cdb).unwrap();
                if lba + n as u64 > self.blocks() {
                    let sense = Sense { key: sense_key::ILLEGAL_REQUEST, asc: scsi::ASC_LBA_OUT_OF_RANGE, ascq: 0 };
                    return self.respond(c, cmd.itt, scsi::status::CHECK_CONDITION, Some(sense), 0);
                }
                let (at, len) = (lba as usize * BLOCK, n as usize * BLOCK);
                assert_eq!(cmd.expected_len as usize, len);
                assert!(len <= c.max_burst, "commands split to MaxBurstLength");
                if cmd.read {
                    let d = self.disk[at..at + len].to_vec();
                    return self.data_in(c, &cmd, d);
                }
                assert!(cmd.write);
                assert!(cmd.data.len() <= c.first_burst.min(self.cfg.mrdsl as usize));
                assert!(c.immediate_data || cmd.data.is_empty());
                if c.initial_r2t {
                    assert!(cmd.final_pdu, "no unsolicited Data-Out with InitialR2T");
                }
                self.stats.immediate_bytes += cmd.data.len();
                let mut buf = vec![0; len];
                buf[..cmd.data.len()].copy_from_slice(&cmd.data);
                let w = Write {
                    itt: cmd.itt,
                    lun: cmd.lun,
                    at,
                    got: cmd.data.len(),
                    next_offset: cmd.data.len(),
                    buf,
                    unsolicited_done: cmd.final_pdu,
                    r2t_end: None,
                    r2t_sn: 0,
                };
                self.advance(c, w);
            }
            op::SYNCHRONIZE_CACHE_10 => self.respond(c, cmd.itt, 0, None, 0),
            _ => {
                let sense = Sense { key: sense_key::ILLEGAL_REQUEST, asc: 0x20, ascq: 0 };
                self.respond(c, cmd.itt, scsi::status::CHECK_CONDITION, Some(sense), 0);
            }
        }
    }

    fn data_out(&mut self, c: &mut Conn, d: DataOut) {
        let Pending::Write(mut w) = core::mem::replace(&mut c.pending, Pending::None) else {
            panic!("Data-Out without a write");
        };
        assert_eq!(d.itt, w.itt);
        assert!(d.data.len() <= self.cfg.mrdsl as usize, "Data-Out within the target's MRDSL");
        let at = d.offset as usize;
        assert_eq!(at, w.next_offset, "Data-Out in order");
        w.buf[at..at + d.data.len()].copy_from_slice(&d.data);
        w.got += d.data.len();
        w.next_offset += d.data.len();
        self.stats.data_out += 1;
        if d.ttt == RESERVED_TAG {
            assert!(!c.initial_r2t && !w.unsolicited_done, "unsolicited Data-Out allowed");
            assert!(w.got <= c.first_burst, "unsolicited data within FirstBurstLength");
            self.stats.unsolicited_data_out += 1;
            w.unsolicited_done = d.final_pdu;
        } else {
            assert_eq!(d.ttt, 0x100 + w.r2t_sn - 1, "Data-Out answers the R2T");
            let end = w.r2t_end.unwrap();
            assert!(w.next_offset <= end);
            if d.final_pdu {
                assert_eq!(w.next_offset, end, "F on the R2T's last PDU");
                w.r2t_end = None;
            }
        }
        self.advance(c, w);
    }

    /// Asks for more of a write's data, or completes it.
    fn advance(&mut self, c: &mut Conn, mut w: Write) {
        if w.got == w.buf.len() && w.r2t_end.is_none() {
            self.disk[w.at..w.at + w.buf.len()].copy_from_slice(&w.buf);
            return self.respond(c, w.itt, 0, None, 0);
        }
        if w.unsolicited_done && w.r2t_end.is_none() {
            let len = (w.buf.len() - w.next_offset).min(c.max_burst);
            let (exp, max) = Self::window(c);
            let stat_sn = c.stat_sn;
            Self::send(
                c,
                Message::R2t(R2t {
                    lun: w.lun,
                    itt: w.itt,
                    ttt: 0x100 + w.r2t_sn,
                    stat_sn,
                    exp_cmd_sn: exp,
                    max_cmd_sn: max,
                    r2t_sn: w.r2t_sn,
                    offset: w.next_offset as u32,
                    desired_len: len as u32,
                }),
            );
            self.stats.r2ts += 1;
            w.r2t_sn += 1;
            w.r2t_end = Some(w.next_offset + len);
        }
        c.pending = Pending::Write(w);
    }

    fn data_in(&mut self, c: &mut Conn, cmd: &ScsiCommand, mut d: Vec<u8>) {
        let expected = cmd.expected_len as usize;
        d.truncate(expected);
        let residual = (expected - d.len()) as u32;
        let seg = self.cfg.data_in_segment.min(c.initiator_mrdsl);
        let count = d.len().div_ceil(seg).max(1);
        for i in 0..count {
            let chunk = &d[(i * seg).min(d.len())..((i + 1) * seg).min(d.len())];
            let last = i + 1 == count;
            let with_status = last && self.cfg.status_in_data_in;
            let (exp, max) = Self::window(c);
            let stat_sn = if with_status { Self::stat_sn(c) } else { 0 };
            Self::send(
                c,
                Message::DataIn(DataIn {
                    final_pdu: last,
                    ack: false,
                    overflow: false,
                    underflow: with_status && residual > 0,
                    status: with_status.then_some(0),
                    lun: cmd.lun,
                    itt: cmd.itt,
                    ttt: RESERVED_TAG,
                    stat_sn,
                    exp_cmd_sn: exp,
                    max_cmd_sn: max,
                    data_sn: i as u32,
                    offset: (i * seg) as u32,
                    residual: if with_status { residual } else { 0 },
                    data: chunk.to_vec(),
                }),
            );
            self.stats.data_in += 1;
        }
        if !self.cfg.status_in_data_in {
            self.respond(c, cmd.itt, 0, None, residual);
        }
    }

    fn respond(&mut self, c: &mut Conn, itt: u32, status: u8, sense: Option<Sense>, residual: u32) {
        let data = match sense {
            Some(s) => {
                let mut d = vec![0, 18];
                d.extend_from_slice(&s.to_fixed());
                d
            }
            None => vec![],
        };
        let (exp, max) = Self::window(c);
        let stat_sn = Self::stat_sn(c);
        Self::send(
            c,
            Message::ScsiResponse(ScsiResponse {
                overflow: false,
                underflow: residual > 0,
                response: 0,
                status,
                itt,
                stat_sn,
                exp_cmd_sn: exp,
                max_cmd_sn: max,
                exp_data_sn: 0,
                residual,
                data,
            }),
        );
    }
}

/// Pipes TCP connections on port 3260 to and from a target process.
struct Relay {
    image: std::path::PathBuf,
    start: std::time::Instant,
    listener: Option<SocketHandle>,
    conns: Vec<Piped>,
}

/// One connection and its target process.
struct Piped {
    socket: SocketHandle,
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    from_target: std::sync::mpsc::Receiver<Vec<u8>>,
    pending: Vec<u8>,
    eof: bool,
}

impl Relay {
    fn step(&mut self, sockets: &mut SocketSet) {
        use std::io::Write;
        use std::process::{Command, Stdio};
        if let Some(h) = self.listener
            && sockets.get::<TcpSocket>(h).state() != TcpState::Listen
        {
            let script = concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/iscsi-target.py");
            let mut child = Command::new("python3")
                .arg(script)
                .arg(&self.image)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("python3 runs");
            let mut stdout = child.stdout.take().unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut buf = vec![0u8; 65536];
                while let Ok(n @ 1..) = std::io::Read::read(&mut stdout, &mut buf) {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            });
            let stdin = child.stdin.take();
            self.conns.push(Piped { socket: h, child, stdin, from_target: rx, pending: Vec::new(), eof: false });
            self.listener = None;
        }
        if self.listener.is_none() {
            let h = sockets.add(TcpSocket::new(65535, 1 << 20));
            sockets.get_mut::<TcpSocket>(h).listen(3260).unwrap();
            self.listener = Some(h);
        }
        for c in &mut self.conns {
            let s = sockets.get_mut::<TcpSocket>(c.socket);
            let mut buf = [0u8; 4096];
            loop {
                match s.recv(&mut buf) {
                    Ok(n @ 1..) => {
                        if let Some(stdin) = &mut c.stdin {
                            let _ = stdin.write_all(&buf[..n]).and_then(|_| stdin.flush());
                        }
                    }
                    Ok(0) => {
                        c.stdin = None; // the initiator closed: so does the target
                        break;
                    }
                    _ => break,
                }
            }
            loop {
                match c.from_target.try_recv() {
                    Ok(bytes) => c.pending.extend_from_slice(&bytes),
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        c.eof = true;
                        break;
                    }
                }
            }
            if !c.pending.is_empty()
                && let Ok(n) = s.send(&c.pending)
            {
                c.pending.drain(..n);
            }
            if c.eof && c.pending.is_empty() && s.may_send() {
                s.close();
            }
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        for c in &mut self.conns {
            c.stdin = None;
            let _ = c.child.kill();
            let _ = c.child.wait();
        }
    }
}
