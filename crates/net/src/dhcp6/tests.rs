use std::cell::RefCell;
use std::rc::Rc;
use std::vec;
use std::vec::Vec;

use super::*;
use crate::ipv6::{ETHERTYPE_IPV6, IPV6_HEADER_LEN, Ipv6Header};
use crate::testing::{Host, pair6};
use crate::wire::{ETH_HEADER_LEN, EthernetHeader, PROTO_UDP, UdpHeader};

const SERVER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x99]);
const SERVER_LL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);
const S1: [u8; 6] = [0, 1, 0, 1, 0xaa, 0xaa];
const S2: [u8; 6] = [0, 1, 0, 1, 0xbb, 0xbb];
const GLOBAL: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 0x1234);
const DNS: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);

type Log = Rc<RefCell<Vec<Vec<u8>>>>;

/// A client under test on host A, with a server we play by hand.
struct Fixture {
    a: Host,
    client: Dhcp6Client,
    /// Milliseconds.
    now: u64,
    log: Log,
    events: Vec<(u64, Dhcp6Event)>,
}

impl Fixture {
    fn new(mode: Mode) -> Self {
        let (mut a, _b, now) = pair6();
        let log: Log = Rc::default();
        let l = log.clone();
        a.set_filter(move |_, f| {
            l.borrow_mut().push(f.to_vec());
            true
        });
        let client = Dhcp6Client::new(&mut a.iface, &mut a.sockets, mode).unwrap();
        Self { a, client, now: now.as_millis(), log, events: Vec::new() }
    }

    fn instant(&self) -> Instant {
        Instant::from_millis(self.now)
    }

    /// Runs for `ms` milliseconds in steps of `step`.
    fn run(&mut self, ms: u64, step: u64) {
        let end = self.now + ms;
        while self.now < end {
            self.now += step;
            let now = self.instant();
            self.a.poll(now);
            if let Some(e) = self.client.poll(now, &mut self.a.iface, &mut self.a.sockets) {
                self.events.push((self.now, e));
            }
            self.a.poll(now);
        }
    }

    /// Runs in 1 ms steps until the client sends a message; returns it.
    fn next_sent(&mut self, limit_ms: u64) -> Option<Message> {
        self.next_sent_step(limit_ms, 1)
    }

    /// Like `next_sent`, in steps of `step` milliseconds.
    fn next_sent_step(&mut self, limit_ms: u64, step: u64) -> Option<Message> {
        let end = self.now + limit_ms;
        while self.now < end {
            self.run(step, step);
            if let Some(m) = self.sent().into_iter().next() {
                return Some(m);
            }
        }
        None
    }

    /// The DHCPv6 messages the client sent since last asked.
    fn sent(&mut self) -> Vec<Message> {
        let frames = core::mem::take(&mut *self.log.borrow_mut());
        frames
            .iter()
            .filter_map(|f| {
                let (_, p) = EthernetHeader::parse(f)?;
                let (ip, p) = Ipv6Header::parse(p)?;
                if ip.dst != ALL_SERVERS || ip.next_header != PROTO_UDP {
                    return None;
                }
                let (udp, body) = UdpHeader::parse(p, ip.src, ip.dst)?;
                assert_eq!((udp.src_port, udp.dst_port), (CLIENT_PORT, SERVER_PORT));
                Message::parse(body)
            })
            .collect()
    }

    fn deliver_raw(&mut self, src_port: u16, bytes: &[u8]) {
        let dst = self.a.iface.ipv6_link_local().unwrap();
        let udp = UdpHeader { src_port, dst_port: CLIENT_PORT }.emit(SERVER_LL, dst, bytes);
        let mut f = vec![0; ETH_HEADER_LEN + IPV6_HEADER_LEN + udp.len()];
        EthernetHeader { dst: self.a.iface.mac_address(), src: SERVER_MAC, ethertype: ETHERTYPE_IPV6 }.emit(&mut f);
        let h = Ipv6Header {
            src: SERVER_LL,
            dst,
            next_header: PROTO_UDP,
            hop_limit: 64,
            payload_len: udp.len(),
            fragment: None,
        };
        h.emit(&mut f[ETH_HEADER_LEN..]);
        f[ETH_HEADER_LEN + IPV6_HEADER_LEN..].copy_from_slice(&udp);
        self.a.inject(f);
    }

    fn deliver(&mut self, m: &Message) {
        self.deliver_raw(SERVER_PORT, &m.emit());
    }

    /// A message from the server `server` answering `to`.
    fn answer(&self, ty: u8, to: &Message, server: [u8; 6]) -> Message {
        Message {
            ty,
            xid: to.xid,
            client_id: to.client_id.clone(),
            server_id: Some(duid_ll(MacAddress(server))),
            ..Message::default()
        }
    }

    fn ia(&self, t1: u32, t2: u32, addrs: &[(Ipv6Addr, u32, u32)]) -> IaNa {
        IaNa {
            iaid: self.client.iaid,
            t1,
            t2,
            addrs: addrs
                .iter()
                .map(|&(addr, preferred, valid)| IaAddr { addr, preferred, valid, status: None })
                .collect(),
            status: None,
        }
    }

    /// Takes the client through Solicit, Advertise, Request and Reply to a
    /// lease of `GLOBAL` with the given timers, answered by server `S1`.
    fn bind(&mut self, t1: u32, t2: u32, preferred: u32, valid: u32) {
        let solicit = self.next_sent(2000).expect("a solicit");
        assert_eq!(solicit.ty, SOLICIT);
        let mut advert = self.answer(ADVERTISE, &solicit, S1);
        advert.ia_na.push(self.ia(t1, t2, &[(GLOBAL, preferred, valid)]));
        self.deliver(&advert);
        let request = loop {
            let m = self.next_sent(3000).expect("a request");
            if m.ty == REQUEST {
                break m;
            }
        };
        let mut reply = self.answer(REPLY, &request, S1);
        reply.ia_na.push(self.ia(t1, t2, &[(GLOBAL, preferred, valid)]));
        reply.dns = vec![DNS];
        self.deliver(&reply);
        self.run(5, 1);
        assert_eq!(self.client.state(), Dhcp6State::Bound);
        self.sent();
    }

    fn has_global(&self) -> bool {
        self.a.iface.ipv6_addresses().iter().any(|x| x.addr == GLOBAL)
    }
}

fn rich() -> Message {
    Message {
        ty: REPLY,
        xid: 0xabcdef,
        client_id: Some(duid_ll(MacAddress([2, 0, 0, 0, 0, 1]))),
        server_id: Some(duid_ll(MacAddress(S1))),
        ia_na: vec![
            IaNa {
                iaid: 7,
                t1: 100,
                t2: 160,
                addrs: vec![
                    IaAddr { addr: GLOBAL, preferred: 200, valid: 300, status: None },
                    IaAddr { addr: DNS, preferred: 1, valid: 2, status: Some(2) },
                ],
                status: Some(0),
            },
            IaNa::default(),
        ],
        status: Some(0),
        preference: 9,
        elapsed: Some(12),
        oro: vec![23, 32],
        dns: vec![DNS, GLOBAL],
        info_refresh: Some(7200),
        rapid_commit: true,
    }
}

#[test]
fn messages_round_trip() {
    let m = rich();
    assert_eq!(Message::parse(&m.emit()), Some(m));
    // An Advertise always carries a preference.
    let advert = Message { ty: ADVERTISE, ..Message::default() };
    assert!(advert.emit().windows(5).any(|w| w == [0, 7, 0, 1, 0]));
    assert_eq!(duid_ll(MacAddress([1, 2, 3, 4, 5, 6])), [0, 3, 0, 1, 1, 2, 3, 4, 5, 6]);
}

#[test]
fn hostile_messages_are_refused_or_trimmed_without_panics() {
    let good = rich().emit();
    // Every truncation either parses (cut at an option boundary) or fails.
    for n in 0..good.len() {
        let _ = Message::parse(&good[..n]);
    }
    // An option that claims more than the message holds.
    let mut b = vec![REPLY, 0, 0, 1, 0, OPT_CLIENTID as u8, 0xff, 0xff, 1, 2];
    assert_eq!(Message::parse(&b), None);
    // Short header.
    assert_eq!(Message::parse(&[REPLY, 0, 0]), None);
    assert_eq!(Message::parse(&[]), None);
    // Short IA_NA, short IAADDR, an IAADDR option that overruns the IA.
    let ia = |v: &[u8]| {
        let mut b = vec![REPLY, 0, 0, 1, 0, 3, 0, v.len() as u8];
        b.extend_from_slice(v);
        b
    };
    assert_eq!(Message::parse(&ia(&[0; 11])), None);
    assert_eq!(Message::parse(&ia(&[0; 12])).map(|m| m.ia_na.len()), Some(1));
    let mut short_addr = vec![0; 12];
    short_addr.extend_from_slice(&[0, 5, 0, 10]);
    short_addr.extend_from_slice(&[0; 10]);
    assert_eq!(Message::parse(&ia(&short_addr)), None);
    let mut overrun = vec![0; 12];
    overrun.extend_from_slice(&[0, 5, 0, 200]);
    assert_eq!(Message::parse(&ia(&overrun)), None);
    // DNS servers not a whole number of addresses; ORO of odd length.
    assert_eq!(Message::parse(&[REPLY, 0, 0, 1, 0, 23, 0, 3, 1, 2, 3]), None);
    assert_eq!(Message::parse(&[REPLY, 0, 0, 1, 0, 6, 0, 3, 1, 2, 3]), None);
    // A DUID that is empty or too long.
    assert_eq!(Message::parse(&[REPLY, 0, 0, 1, 0, 1, 0, 0]), None);
    let mut long = vec![REPLY, 0, 0, 1, 0, 1, 0, 131];
    long.extend_from_slice(&[0; 131]);
    assert_eq!(Message::parse(&long), None);
    // The first of repeated options counts.
    let m = Message::parse(&[REPLY, 0, 0, 1, 0, 1, 0, 2, 1, 1, 0, 1, 0, 2, 2, 2]).unwrap();
    assert_eq!(m.client_id, Some(vec![1, 1]));
    // Lists are trimmed rather than trusted.
    let many = Message {
        ia_na: (0..5)
            .map(|i| IaNa {
                iaid: i,
                addrs: (0..9).map(|n| IaAddr { addr: GLOBAL, preferred: n, valid: n, status: None }).collect(),
                ..IaNa::default()
            })
            .collect(),
        dns: (0..20).map(|_| DNS).collect(),
        ..Message::default()
    };
    let m = Message::parse(&many.emit()).unwrap();
    assert_eq!((m.ia_na.len(), m.ia_na[0].addrs.len(), m.dns.len()), (MAX_IA, MAX_IA_ADDRS, MAX_DNS_SERVERS));
    // Too many options, and too long a message.
    let opts: Vec<u8> = (0..300).flat_map(|_| [0, 99, 0, 0]).collect();
    b = vec![REPLY, 0, 0, 1];
    b.extend_from_slice(&opts);
    assert_eq!(Message::parse(&b), None);
    assert_eq!(Message::parse(&vec![0; MAX_MESSAGE + 1]), None);
    // Noise.
    let mut x = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..5000 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let n = (x % 90) as usize;
        let mut noise: Vec<u8> = (0..n).map(|i| (x >> (i % 7 * 8)) as u8 ^ i as u8).collect();
        if let Some(t) = noise.first_mut() {
            *t = REPLY;
        }
        let _ = Message::parse(&noise);
    }
}

#[test]
fn a_second_client_cannot_take_the_port() {
    let mut f = Fixture::new(Mode::Stateful);
    assert_eq!(Dhcp6Client::new(&mut f.a.iface, &mut f.a.sockets, Mode::Stateless).err(), Some(Error::InvalidAddress));
}

#[test]
fn solicits_back_off_with_one_transaction_id() {
    let mut f = Fixture::new(Mode::Stateful);
    let mut times = Vec::new();
    let mut xids = Vec::new();
    for _ in 0..6 {
        let m = f.next_sent_step(130_000, 5).expect("another solicit");
        assert_eq!(m.ty, SOLICIT);
        times.push(f.now);
        xids.push(m.xid);
        assert_eq!(m.client_id.as_deref(), Some(duid_ll(f.a.iface.mac_address()).as_slice()));
        assert_eq!(m.ia_na.len(), 1);
        assert!(m.ia_na[0].addrs.is_empty());
        assert!(m.oro.contains(&OPT_DNS_SERVERS));
        assert_eq!(m.server_id, None);
    }
    assert!(xids.iter().all(|&x| x == xids[0]), "one exchange, one transaction id");
    assert!(xids[0] <= 0xff_ffff);
    // Each gap is twice the one before, give or take the 10% jitter on each.
    let gaps: Vec<f64> = times.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
    assert!((900.0..=1100.0).contains(&gaps[0]), "{gaps:?}");
    for w in gaps.windows(2) {
        let ratio = w[1] / w[0];
        assert!((1.6..=2.4).contains(&ratio), "{gaps:?}");
    }
}

#[test]
fn the_most_preferred_server_wins_and_is_asked_for_its_address() {
    let mut f = Fixture::new(Mode::Stateful);
    let solicit = f.next_sent(2000).unwrap();
    // The first advertisement is not taken at once.
    let mut weak = f.answer(ADVERTISE, &solicit, S1);
    weak.preference = 10;
    weak.ia_na.push(f.ia(0, 0, &[(GLOBAL, 100, 200)]));
    f.deliver(&weak);
    f.run(100, 1);
    let other = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 0x4321);
    let mut strong = f.answer(ADVERTISE, &solicit, S2);
    strong.preference = 80;
    strong.ia_na.push(f.ia(0, 0, &[(other, 100, 200)]));
    f.deliver(&strong);
    // A bad one: no address available.
    let mut none = f.answer(ADVERTISE, &solicit, [9; 6]);
    none.preference = 200;
    none.status = Some(STATUS_NO_ADDRS_AVAIL);
    f.deliver(&none);
    f.run(10, 1);
    assert_eq!(f.client.state(), Dhcp6State::Soliciting, "waits out the first retransmission time");
    f.sent();
    let request = loop {
        let m = f.next_sent(3000).expect("a request");
        if m.ty == REQUEST {
            break m;
        }
    };
    assert_eq!(f.client.state(), Dhcp6State::Requesting);
    assert_eq!(request.server_id, Some(duid_ll(MacAddress(S2))));
    assert_ne!(request.xid, solicit.xid, "a new exchange");
    assert_eq!(request.ia_na[0].addrs.len(), 1);
    assert_eq!(request.ia_na[0].addrs[0].addr, other);
}

#[test]
fn preference_255_is_taken_at_once() {
    let mut f = Fixture::new(Mode::Stateful);
    let solicit = f.next_sent(2000).unwrap();
    let mut best = f.answer(ADVERTISE, &solicit, S2);
    best.preference = 255;
    best.ia_na.push(f.ia(0, 0, &[(GLOBAL, 100, 200)]));
    f.deliver(&best);
    f.run(5, 1);
    assert_eq!(f.client.state(), Dhcp6State::Requesting);
}

#[test]
fn a_lease_is_applied_renewed_rebound_and_lost() {
    let mut f = Fixture::new(Mode::Stateful);
    f.bind(1000, 1600, 2000, 3000);
    assert_eq!(f.events.last().map(|e| e.1), Some(Dhcp6Event::Configured));
    let bound_at = f.events.last().unwrap().0;
    assert!(f.has_global());
    assert_eq!(f.a.iface.ipv6_dns(), [DNS]);
    assert_eq!(f.client.dns(), [DNS]);
    let lease = f.client.lease().unwrap();
    assert_eq!((lease.addresses.len(), lease.server_id.as_slice()), (1, duid_ll(MacAddress(S1)).as_slice()));
    f.run(2000, 100);
    assert!(f.a.iface.ipv6_addresses().iter().any(|x| x.addr == GLOBAL && x.usable), "usable after detection");

    // Renew at T1 to the same server, with the address.
    f.run(1_000_000 - (f.now - bound_at) - 1000, 100);
    f.sent();
    let renew = f.next_sent(3000).expect("a renew");
    assert_eq!(renew.ty, RENEW);
    assert_eq!(renew.server_id, Some(duid_ll(MacAddress(S1))));
    assert_eq!(renew.ia_na[0].addrs[0].addr, GLOBAL);
    assert_eq!(f.client.state(), Dhcp6State::Renewing);
    assert!((f.now - bound_at).abs_diff(1_000_000) < 2000);
    let mut reply = f.answer(REPLY, &renew, S1);
    reply.ia_na.push(f.ia(1000, 1600, &[(GLOBAL, 2000, 3000)]));
    f.deliver(&reply);
    f.run(5, 1);
    assert_eq!(f.client.state(), Dhcp6State::Bound);
    assert_eq!(f.events.last().map(|e| e.1), Some(Dhcp6Event::Renewed));
    let renewed_at = f.now;
    // Unanswered from here on: renews until T2, then rebinds.
    f.sent();
    let mut renews = 0;
    let rebind = loop {
        let m = f.next_sent_step(2_000_000, 50).expect("renew then rebind");
        match m.ty {
            RENEW => renews += 1,
            REBIND => break m,
            ty => panic!("unexpected message {ty}"),
        }
    };
    assert!(renews >= 3, "{renews}");
    assert_eq!(rebind.server_id, None, "any server may answer a rebind");
    assert_eq!(rebind.ia_na[0].addrs[0].addr, GLOBAL);
    assert!((f.now - renewed_at).abs_diff(1_600_000) < 20_000, "at T2");
    assert_eq!(f.client.state(), Dhcp6State::Rebinding);
    // The renewal extended the lease past the original 3000 seconds.
    f.run(2_900_000 - (f.now - renewed_at), 500);
    assert!(f.now - bound_at > 3_000_000 && f.has_global());
    // Unanswered, the lease is lost when it expires.
    while f.events.last().map(|e| e.1) != Some(Dhcp6Event::Lost) {
        assert!(f.now - renewed_at < 3_200_000, "lost in time");
        f.run(500, 500);
    }
    assert!((f.now - renewed_at).abs_diff(3_000_000) < 2000, "when the valid lifetime ended");
    assert!(!f.has_global());
    assert!(f.client.lease().is_none());
    assert_eq!(f.client.state(), Dhcp6State::Soliciting);
    f.sent();
    assert_eq!(f.next_sent(5000).map(|m| m.ty), Some(SOLICIT));
}

#[test]
fn timers_default_from_the_preferred_lifetime_and_never_spin() {
    // T1 and T2 of 0: half and four fifths of the preferred lifetime.
    let mut f = Fixture::new(Mode::Stateful);
    f.bind(0, 0, 4000, 5000);
    let t0 = f.events.last().unwrap().0;
    assert_eq!(f.client.t1_at.map(|t| t.as_millis() - t0), Some(2_000_000));
    assert_eq!(f.client.t2_at.map(|t| t.as_millis() - t0), Some(3_200_000));
    // A server that asks for T1 of 1 second gets 30.
    let mut f = Fixture::new(Mode::Stateful);
    f.bind(1, 2, 4000, 5000);
    let t0 = f.events.last().unwrap().0;
    assert_eq!(f.client.t1_at.map(|t| t.as_millis() - t0), Some(30_000));
    // An infinite lease is never renewed or lost.
    let mut f = Fixture::new(Mode::Stateful);
    f.bind(0, 0, u32::MAX, u32::MAX);
    assert_eq!((f.client.t1_at, f.client.t2_at, f.client.expires_at), (None, None, None));
    f.run(100_000, 1000);
    assert_eq!(f.client.state(), Dhcp6State::Bound);
}

#[test]
fn replies_that_are_not_for_this_exchange_are_ignored() {
    let mut f = Fixture::new(Mode::Stateful);
    let solicit = f.next_sent(2000).unwrap();
    let mut advert = f.answer(ADVERTISE, &solicit, S1);
    advert.ia_na.push(f.ia(0, 0, &[(GLOBAL, 100, 200)]));
    f.deliver(&advert);
    let request = loop {
        let m = f.next_sent(3000).unwrap();
        if m.ty == REQUEST {
            break m;
        }
    };
    let good = |f: &Fixture| {
        let mut r = f.answer(REPLY, &request, S1);
        r.ia_na.push(f.ia(0, 0, &[(GLOBAL, 100, 200)]));
        r
    };
    // Wrong transaction, wrong client, wrong server, missing server.
    let mut bad = vec![Message { xid: request.xid ^ 1, ..good(&f) }];
    bad.push(Message { client_id: Some(duid_ll(MacAddress([9; 6]))), ..good(&f) });
    bad.push(Message { server_id: Some(duid_ll(MacAddress(S2))), ..good(&f) });
    bad.push(Message { server_id: None, ..good(&f) });
    bad.push(Message { client_id: None, ..good(&f) });
    // Wrong type for the state.
    bad.push(Message { ty: ADVERTISE, ..good(&f) });
    // Unusable addresses and timers, an association that is not ours.
    for a in [Ipv6Addr::UNSPECIFIED, Ipv6Addr::LOCALHOST, SERVER_LL, "ff02::1".parse().unwrap()] {
        let mut r = good(&f);
        r.ia_na = vec![f.ia(0, 0, &[(a, 100, 200)])];
        bad.push(r);
    }
    let mut r = good(&f);
    r.ia_na = vec![f.ia(0, 0, &[(GLOBAL, 300, 200)])];
    bad.push(r);
    let mut r = good(&f);
    r.ia_na = vec![f.ia(500, 100, &[(GLOBAL, 100, 200)])];
    bad.push(r);
    let mut r = good(&f);
    r.ia_na = vec![IaNa { iaid: f.client.iaid ^ 1, ..f.ia(0, 0, &[(GLOBAL, 100, 200)]) }];
    bad.push(r);
    let mut r = good(&f);
    r.ia_na = vec![IaNa { status: Some(1), ..f.ia(0, 0, &[(GLOBAL, 100, 200)]) }];
    bad.push(r);
    let mut r = good(&f);
    r.status = Some(1);
    bad.push(r);
    for m in &bad {
        f.deliver(m);
    }
    // From a port that is not a server's; and mangled.
    f.deliver_raw(1234, &good(&f).emit());
    f.deliver_raw(SERVER_PORT, &good(&f).emit()[..30]);
    f.deliver_raw(SERVER_PORT, &[REPLY]);
    f.run(50, 1);
    assert_eq!(f.client.state(), Dhcp6State::Requesting, "none of them was taken");
    assert!(!f.has_global() && f.client.lease().is_none());
    // The real thing.
    f.deliver(&good(&f));
    f.run(5, 1);
    assert_eq!(f.client.state(), Dhcp6State::Bound);
    assert!(f.has_global());
}

#[test]
fn a_server_without_addresses_sends_the_client_back_to_soliciting() {
    let mut f = Fixture::new(Mode::Stateful);
    let solicit = f.next_sent(2000).unwrap();
    let mut advert = f.answer(ADVERTISE, &solicit, S1);
    advert.ia_na.push(f.ia(0, 0, &[(GLOBAL, 100, 200)]));
    f.deliver(&advert);
    let request = loop {
        let m = f.next_sent(3000).unwrap();
        if m.ty == REQUEST {
            break m;
        }
    };
    let mut reply = f.answer(REPLY, &request, S1);
    reply.status = Some(STATUS_NO_ADDRS_AVAIL);
    f.deliver(&reply);
    f.run(10, 1);
    assert_eq!(f.client.state(), Dhcp6State::Soliciting);
    assert_eq!(f.next_sent(3000).map(|m| m.ty), Some(SOLICIT));
}

#[test]
fn an_unanswered_request_gives_up_after_ten_tries() {
    let mut f = Fixture::new(Mode::Stateful);
    let solicit = f.next_sent(2000).unwrap();
    let mut advert = f.answer(ADVERTISE, &solicit, S1);
    advert.ia_na.push(f.ia(0, 0, &[(GLOBAL, 100, 200)]));
    f.deliver(&advert);
    let mut requests = 0;
    while let Some(m) = f.next_sent_step(100_000, 10) {
        match m.ty {
            REQUEST => requests += 1,
            SOLICIT => break,
            ty => panic!("unexpected {ty}"),
        }
    }
    assert_eq!(requests, 10);
    assert_eq!(f.client.state(), Dhcp6State::Soliciting);
}

#[test]
fn a_server_that_forgot_the_lease_is_asked_again() {
    let mut f = Fixture::new(Mode::Stateful);
    f.bind(100, 160, 200, 300);
    let renew = loop {
        let m = f.next_sent_step(200_000, 20).expect("a renew");
        if m.ty == RENEW {
            break m;
        }
    };
    let mut reply = f.answer(REPLY, &renew, S1);
    reply.ia_na.push(IaNa { status: Some(STATUS_NO_BINDING), ..f.ia(0, 0, &[]) });
    f.deliver(&reply);
    f.run(5, 1);
    assert_eq!(f.client.state(), Dhcp6State::Requesting);
    let request = loop {
        let m = f.next_sent(3000).unwrap();
        if m.ty == REQUEST {
            break m;
        }
    };
    assert_eq!(request.server_id, Some(duid_ll(MacAddress(S1))));
    assert_eq!(request.ia_na[0].addrs[0].addr, GLOBAL);
    let mut reply = f.answer(REPLY, &request, S1);
    reply.ia_na.push(f.ia(100, 160, &[(GLOBAL, 200, 300)]));
    f.deliver(&reply);
    f.run(5, 1);
    assert_eq!(f.client.state(), Dhcp6State::Bound);
    // New addresses from a new request: configured again, not just renewed.
    assert_eq!(f.events.last().map(|e| e.1), Some(Dhcp6Event::Configured));
}

#[test]
fn an_address_the_server_takes_back_is_removed() {
    let mut f = Fixture::new(Mode::Stateful);
    f.bind(100, 160, 200, 300);
    let renew = loop {
        let m = f.next_sent_step(200_000, 20).expect("a renew");
        if m.ty == RENEW {
            break m;
        }
    };
    let other = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 0x777);
    let mut reply = f.answer(REPLY, &renew, S1);
    reply.ia_na.push(f.ia(100, 160, &[(GLOBAL, 0, 0), (other, 200, 300)]));
    f.deliver(&reply);
    f.run(5, 1);
    assert!(!f.has_global());
    let addrs: Vec<_> = f.client.lease().unwrap().addresses.iter().map(|a| a.addr).collect();
    assert_eq!(addrs, [other]);
}

#[test]
fn release_gives_the_addresses_back() {
    let mut f = Fixture::new(Mode::Stateful);
    f.bind(1000, 1600, 2000, 3000);
    assert!(f.has_global());
    let now = f.instant();
    f.client.release(now, &mut f.a.iface);
    assert!(!f.has_global());
    let release = f.next_sent(2000).expect("a release");
    assert_eq!(release.ty, RELEASE);
    assert_eq!(release.server_id, Some(duid_ll(MacAddress(S1))));
    assert_eq!(release.ia_na[0].addrs[0].addr, GLOBAL);
    let mut reply = f.answer(REPLY, &release, S1);
    reply.status = Some(STATUS_SUCCESS);
    f.deliver(&reply);
    f.run(5, 1);
    assert_eq!(f.client.state(), Dhcp6State::Released);
    assert_eq!(f.events.last().map(|e| e.1), Some(Dhcp6Event::Released));
    f.sent();
    f.run(60_000, 100);
    assert!(f.sent().is_empty(), "stopped");
    // It can start over.
    f.client.restart();
    assert_eq!(f.next_sent(5000).map(|m| m.ty), Some(SOLICIT));
}

#[test]
fn an_unanswered_release_is_sent_four_times() {
    let mut f = Fixture::new(Mode::Stateful);
    f.bind(1000, 1600, 2000, 3000);
    let now = f.instant();
    f.client.release(now, &mut f.a.iface);
    f.run(60_000, 100);
    let sent = f.sent();
    assert_eq!(sent.iter().filter(|m| m.ty == RELEASE).count(), 4);
    assert_eq!(f.client.state(), Dhcp6State::Released);
}

#[test]
fn stateless_mode_asks_for_configuration_and_refreshes_it() {
    let mut f = Fixture::new(Mode::Stateless);
    let info = f.next_sent(2000).expect("an information request");
    assert_eq!(info.ty, INFORMATION_REQUEST);
    assert!(info.ia_na.is_empty(), "no addresses asked for");
    assert!(info.oro.contains(&OPT_DNS_SERVERS) && info.oro.contains(&OPT_INFO_REFRESH_TIME));
    assert_eq!(info.server_id, None);
    // Answers that do not count, then one that does.
    let mut bad = f.answer(REPLY, &info, S1);
    bad.xid ^= 1;
    bad.dns = vec![DNS];
    f.deliver(&bad);
    let mut no_server = f.answer(REPLY, &info, S1);
    no_server.server_id = None;
    no_server.dns = vec![DNS];
    f.deliver(&no_server);
    f.run(20, 1);
    assert!(f.a.iface.ipv6_dns().is_empty());
    let mut reply = f.answer(REPLY, &info, S1);
    reply.dns = vec![DNS, Ipv6Addr::UNSPECIFIED];
    reply.info_refresh = Some(5); // under the 600 second minimum
    f.deliver(&reply);
    f.run(5, 1);
    assert_eq!(f.events.last().map(|e| e.1), Some(Dhcp6Event::Configured));
    assert_eq!(f.client.state(), Dhcp6State::Informed);
    assert_eq!(f.a.iface.ipv6_dns(), [DNS], "unusable servers are dropped");
    let at = f.now;
    f.sent();
    f.run(590_000, 1000);
    assert!(f.sent().is_empty());
    let again = f.next_sent(20_000).expect("a refresh");
    assert_eq!(again.ty, INFORMATION_REQUEST);
    assert!((f.now - at).abs_diff(600_000) < 2000);
    assert_ne!(again.xid, info.xid);
    let mut reply = f.answer(REPLY, &again, S1);
    reply.dns = vec![DNS];
    f.deliver(&reply);
    f.run(5, 1);
    assert_eq!(f.events.last().map(|e| e.1), Some(Dhcp6Event::Renewed));
    // No refresh time given: a day.
    let t = f.events.last().unwrap().0;
    assert_eq!(f.client.refresh_at.map(|r| r.as_millis() - t), Some(86_400_000));
}

#[test]
fn the_client_waits_for_ipv6_and_reports_what_is_offered() {
    let (mut a, _b) = crate::testing::link();
    let now = Instant::ZERO;
    let mut sockets = crate::SocketSet::new();
    let mut c = Dhcp6Client::new(&mut a.iface, &mut sockets, Mode::Stateful).unwrap();
    assert_eq!(c.poll_at(), Some(Instant::ZERO));
    assert_eq!(c.poll(now, &mut a.iface, &mut sockets), None);
    assert_eq!(c.state(), Dhcp6State::Idle);
    assert_eq!(a.iface.ipv6_ra_flags(), (false, false));
}

#[test]
fn leased_addresses_are_validated_by_the_interface() {
    let (mut a, _b, now) = pair6();
    let ll = a.iface.ipv6_link_local().unwrap();
    for bad in [Ipv6Addr::UNSPECIFIED, Ipv6Addr::LOCALHOST, ll, "ff02::1".parse().unwrap()] {
        assert_eq!(a.iface.add_dhcpv6_address(now, bad, 100), Err(Error::InvalidAddress));
    }
    assert_eq!(a.iface.add_dhcpv6_address(now, GLOBAL, 0), Err(Error::InvalidAddress));
    a.iface.add_dhcpv6_address(now, GLOBAL, 100).unwrap();
    // Adding it again only refreshes it.
    a.iface.add_dhcpv6_address(now, GLOBAL, 200).unwrap();
    assert_eq!(a.iface.ipv6_addresses().len(), 2);
    assert!(a.iface.remove_ipv6_address(GLOBAL));
    assert!(!a.iface.remove_ipv6_address(GLOBAL));
}
