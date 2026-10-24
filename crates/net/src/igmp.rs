//! IPv4 multicast group membership: IGMPv2 (RFC 2236) with the multicast
//! MAC mapping of RFC 1112.
//!
//! A host announces the groups it has joined so that a multicast router
//! (or an IGMP-snooping switch) forwards them to its link. On joining it
//! sends an unsolicited report, twice; it answers the router's queries with
//! a report after a random delay, unless it hears another member report the
//! same group first; and on leaving, if it was the last to report, it tells
//! all routers.
//!
//! The router's IGMPv1 queries (a zero maximum response time) are answered
//! with IGMPv1 reports and without leave messages for 400 seconds; IGMPv3
//! queries are answered as IGMPv2 queries, which routers accept.

use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::time::Duration;

use osmium_hal::net::MacAddress;

use crate::rng::Rng;
use crate::{Error, Instant};

/// IP protocol number of IGMP.
pub const PROTO_IGMP: u8 = 2;
/// Length of an IGMPv1/v2 message.
pub const IGMP_LEN: usize = 8;
/// IGMP type: membership query.
pub const IGMP_QUERY: u8 = 0x11;
/// IGMP type: IGMPv1 membership report.
pub const IGMP_REPORT_V1: u8 = 0x12;
/// IGMP type: IGMPv2 membership report.
pub const IGMP_REPORT_V2: u8 = 0x16;
/// IGMP type: leave group.
pub const IGMP_LEAVE: u8 = 0x17;

/// The all-hosts group, which every host is in and never reports.
pub const ALL_HOSTS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 1);
/// The all-routers group, where leave messages go.
pub const ALL_ROUTERS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 2);

/// Groups an interface can be a member of at once.
pub const MAX_GROUPS: usize = 32;
/// The gap between the two unsolicited reports of a new member.
const UNSOLICITED_INTERVAL: Duration = Duration::from_secs(10);
/// How long a router speaking IGMPv1 is remembered (RFC 2236 4).
const V1_ROUTER_PRESENT: Duration = Duration::from_secs(400);
/// The response time assumed for a query that gives none.
const DEFAULT_MAX_RESPONSE: Duration = Duration::from_secs(10);

/// The Ethernet address of an IPv4 multicast group: `01:00:5e` and the low
/// 23 bits of the address (RFC 1112 6.4). Thirty-two groups share each.
pub fn multicast_mac(group: Ipv4Addr) -> MacAddress {
    let o = group.octets();
    MacAddress([0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]])
}

/// An IGMPv1 or v2 message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IgmpPacket {
    /// [`IGMP_QUERY`], [`IGMP_REPORT_V1`], [`IGMP_REPORT_V2`] or
    /// [`IGMP_LEAVE`].
    pub ty: u8,
    /// For a query, the longest a member may wait before reporting, in
    /// tenths of a second; 0 in other messages (and in IGMPv1 queries).
    pub max_response: u8,
    /// The group, or 0.0.0.0 in a general query.
    pub group: Ipv4Addr,
}

impl IgmpPacket {
    /// Parses an IGMP message, verifying its checksum over all of `b`. An
    /// IGMPv3 query (twelve bytes or more) is read as the v2 query it
    /// resembles, with its response code decoded.
    pub fn parse(b: &[u8]) -> Option<Self> {
        let [ty, code, _, _, g0, g1, g2, g3, ..] = *b else { return None };
        if crate::wire::checksum::of(b) != 0 {
            return None;
        }
        let group = Ipv4Addr::new(g0, g1, g2, g3);
        let mut max_response = code;
        if ty == IGMP_QUERY && b.len() >= 12 && max_response >= 128 {
            // The floating-point code of RFC 3376 4.1.1, in tenths of a
            // second, clamped to what a v2 field holds.
            let (exp, mant) = (u32::from(max_response >> 4 & 7), u32::from(max_response & 0xf));
            max_response = ((mant | 0x10) << (exp + 3)).min(255) as u8;
        }
        Some(Self { ty, max_response, group })
    }

    /// Builds the message with its checksum.
    pub fn emit(&self) -> Vec<u8> {
        let mut b = alloc::vec![self.ty, self.max_response, 0, 0];
        b.extend_from_slice(&self.group.octets());
        let sum = crate::wire::checksum::of(&b);
        crate::wire::put(&mut b, 2, &sum.to_be_bytes());
        b
    }
}

struct Member {
    group: Ipv4Addr,
    /// Joins not yet matched by a leave.
    refs: u32,
    /// When to send a report, if one is due.
    report_at: Option<Instant>,
    /// Unsolicited reports still to follow the first.
    repeats: u8,
    /// This host sent the latest report for the group, so it must send the
    /// leave.
    last_reporter: bool,
}

/// An IGMP message to send: its IP destination and contents.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Outgoing {
    pub(crate) dst: Ipv4Addr,
    pub(crate) message: IgmpPacket,
}

/// The groups an interface belongs to and the timers for reporting them.
#[derive(Default)]
pub(crate) struct Igmp {
    members: Vec<Member>,
    /// An IGMPv1 router was heard until this time.
    v1_until: Option<Instant>,
}

impl Igmp {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns true if packets for `group` are wanted: it is the all-hosts
    /// group or one joined.
    pub(crate) fn is_member(&self, group: Ipv4Addr) -> bool {
        group == ALL_HOSTS || self.members.iter().any(|m| m.group == group)
    }

    pub(crate) fn groups(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.members.iter().map(|m| m.group)
    }

    fn v1(&self, now: Instant) -> bool {
        self.v1_until.is_some_and(|t| now < t)
    }

    /// Joins `group`; the first report goes out at the next poll.
    pub(crate) fn join(&mut self, group: Ipv4Addr, now: Instant) -> Result<(), Error> {
        if !group.is_multicast() {
            return Err(Error::InvalidAddress);
        }
        if group == ALL_HOSTS {
            return Ok(());
        }
        if let Some(m) = self.members.iter_mut().find(|m| m.group == group) {
            m.refs = m.refs.saturating_add(1);
            return Ok(());
        }
        if self.members.len() >= MAX_GROUPS {
            return Err(Error::WouldBlock);
        }
        self.members.push(Member { group, refs: 1, report_at: Some(now), repeats: 1, last_reporter: false });
        Ok(())
    }

    /// Leaves `group` once every join has been undone. Returns the leave
    /// message to send, if the host owes one.
    pub(crate) fn leave(&mut self, group: Ipv4Addr, now: Instant) -> Result<Option<Outgoing>, Error> {
        if group == ALL_HOSTS {
            return Ok(None);
        }
        let i = self.members.iter().position(|m| m.group == group).ok_or(Error::InvalidState)?;
        let member = self.members.get_mut(i).ok_or(Error::InvalidState)?;
        member.refs = member.refs.saturating_sub(1);
        if member.refs > 0 {
            return Ok(None);
        }
        let m = self.members.remove(i);
        let message = IgmpPacket { ty: IGMP_LEAVE, max_response: 0, group };
        Ok((m.last_reporter && !self.v1(now)).then_some(Outgoing { dst: ALL_ROUTERS, message }))
    }

    /// A query arrived: schedule reports for the groups it asks about, each
    /// after a random part of the response time.
    pub(crate) fn on_query(&mut self, query: IgmpPacket, now: Instant, rng: &mut Rng) {
        let max = if query.max_response == 0 {
            // An IGMPv1 router.
            self.v1_until = Some(now + V1_ROUTER_PRESENT);
            DEFAULT_MAX_RESPONSE
        } else {
            Duration::from_millis(u64::from(query.max_response) * 100)
        };
        for m in &mut self.members {
            if !(query.group.is_unspecified() || query.group == m.group) {
                continue;
            }
            let delay = Duration::from_millis(rng.next_u64() % (max.as_millis() as u64 + 1));
            let at = now + delay;
            // A report already due sooner stands (RFC 2236 3).
            if m.report_at.is_none_or(|t| at < t) {
                m.report_at = Some(at);
                m.repeats = 0;
            }
        }
    }

    /// Another host reported `group`: ours is unnecessary.
    pub(crate) fn on_report(&mut self, group: Ipv4Addr) {
        if let Some(m) = self.members.iter_mut().find(|m| m.group == group) {
            m.report_at = None;
            m.repeats = 0;
            m.last_reporter = false;
        }
    }

    /// The reports that are due.
    pub(crate) fn poll(&mut self, now: Instant) -> Vec<Outgoing> {
        let ty = if self.v1(now) { IGMP_REPORT_V1 } else { IGMP_REPORT_V2 };
        let mut out = Vec::new();
        for m in &mut self.members {
            if m.report_at.is_some_and(|t| t <= now) {
                out.push(Outgoing { dst: m.group, message: IgmpPacket { ty, max_response: 0, group: m.group } });
                m.last_reporter = true;
                m.report_at = if m.repeats > 0 { Some(now + UNSOLICITED_INTERVAL) } else { None };
                m.repeats = m.repeats.saturating_sub(1);
            }
        }
        out
    }

    pub(crate) fn poll_at(&self) -> Option<Instant> {
        self.members.iter().filter_map(|m| m.report_at).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: Ipv4Addr = Ipv4Addr::new(239, 1, 2, 3);

    #[test]
    fn mac_mapping() {
        assert_eq!(multicast_mac(G), MacAddress([1, 0, 0x5e, 1, 2, 3]));
        assert_eq!(multicast_mac(ALL_HOSTS), MacAddress([1, 0, 0x5e, 0, 0, 1]));
        // The high bit of the second octet is dropped: 32 groups per MAC.
        assert_eq!(multicast_mac(Ipv4Addr::new(239, 129, 2, 3)), multicast_mac(G));
        assert!(multicast_mac(G).is_multicast());
    }

    #[test]
    fn packet_round_trip() {
        let p = IgmpPacket { ty: IGMP_REPORT_V2, max_response: 0, group: G };
        let mut b = p.emit();
        assert_eq!(b.len(), IGMP_LEN);
        assert_eq!(IgmpPacket::parse(&b), Some(p));
        b[7] ^= 1;
        assert_eq!(IgmpPacket::parse(&b), None, "checksum");
        assert_eq!(IgmpPacket::parse(&b[..7]), None);
        // An IGMPv3 query with response code 0x80 | exp 1 << 4 | mant 5.
        let mut q = IgmpPacket { ty: IGMP_QUERY, max_response: 0xd5, group: Ipv4Addr::UNSPECIFIED }.emit();
        q.extend_from_slice(&[2, 125, 0, 0]);
        q[2..4].fill(0);
        let sum = crate::wire::checksum::of(&q);
        q[2..4].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(IgmpPacket::parse(&q).unwrap().max_response, 255, "(5 | 16) << 4 clamped");
    }

    #[test]
    fn join_reports_twice_and_leave_says_goodbye() {
        let mut igmp = Igmp::new();
        let mut now = Instant::ZERO;
        assert_eq!(igmp.join(Ipv4Addr::new(10, 0, 0, 1), now), Err(Error::InvalidAddress));
        igmp.join(G, now).unwrap();
        igmp.join(G, now).unwrap();
        assert!(igmp.is_member(G) && igmp.is_member(ALL_HOSTS) && !igmp.is_member(ALL_ROUTERS));
        let first = igmp.poll(now);
        assert_eq!((first.len(), first[0].dst, first[0].message.ty), (1, G, IGMP_REPORT_V2));
        assert!(igmp.poll(now).is_empty());
        assert_eq!(igmp.poll_at(), Some(now + UNSOLICITED_INTERVAL));
        now = now + UNSOLICITED_INTERVAL;
        assert_eq!(igmp.poll(now).len(), 1, "the repeat");
        assert_eq!(igmp.poll_at(), None);
        // Two joins need two leaves.
        assert!(igmp.leave(G, now).unwrap().is_none() && igmp.is_member(G));
        let bye = igmp.leave(G, now).unwrap().unwrap();
        assert_eq!((bye.dst, bye.message.ty, bye.message.group), (ALL_ROUTERS, IGMP_LEAVE, G));
        assert_eq!(igmp.leave(G, now), Err(Error::InvalidState));
    }

    #[test]
    fn queries_are_answered_and_reports_suppress() {
        let mut igmp = Igmp::new();
        let mut rng = Rng::new(5);
        let now = Instant::ZERO;
        let other = Ipv4Addr::new(239, 9, 9, 9);
        igmp.join(G, now).unwrap();
        igmp.join(other, now).unwrap();
        igmp.poll(now);
        igmp.poll(now + UNSOLICITED_INTERVAL);
        let t = now + UNSOLICITED_INTERVAL * 2;
        // A general query with 5 s to answer: both groups report within 5 s.
        let general = IgmpPacket { ty: IGMP_QUERY, max_response: 50, group: Ipv4Addr::UNSPECIFIED };
        igmp.on_query(general, t, &mut rng);
        let due = igmp.poll_at().unwrap();
        assert!(due - t <= Duration::from_secs(5));
        // Another member answers for G first.
        igmp.on_report(G);
        assert!(igmp.poll(t + Duration::from_secs(5)).iter().all(|o| o.dst == other));
        // Having been suppressed, we are not the last reporter: no leave.
        assert!(igmp.leave(G, t).unwrap().is_none());
        // A specific query for a group we are not in changes nothing.
        let specific = IgmpPacket { ty: IGMP_QUERY, max_response: 10, group: Ipv4Addr::new(239, 7, 7, 7) };
        igmp.on_query(specific, t, &mut rng);
        assert_eq!(igmp.poll_at(), None);
        // An IGMPv1 query: v1 reports, and no leave afterwards.
        let v1 = IgmpPacket { ty: IGMP_QUERY, max_response: 0, group: Ipv4Addr::UNSPECIFIED };
        igmp.on_query(v1, t, &mut rng);
        let out = igmp.poll(t + Duration::from_secs(10));
        assert_eq!(out[0].message.ty, IGMP_REPORT_V1);
        assert!(igmp.leave(other, t).unwrap().is_none());
    }

    #[test]
    fn group_table_is_bounded() {
        let mut igmp = Igmp::new();
        for i in 0..MAX_GROUPS as u8 {
            igmp.join(Ipv4Addr::new(239, 0, 0, i), Instant::ZERO).unwrap();
        }
        assert_eq!(igmp.join(Ipv4Addr::new(239, 1, 0, 0), Instant::ZERO), Err(Error::WouldBlock));
        assert!(igmp.join(Ipv4Addr::new(239, 0, 0, 3), Instant::ZERO).is_ok(), "a repeat join needs no slot");
    }

    #[test]
    fn truncated_messages_are_rejected() {
        let wire = IgmpPacket { ty: IGMP_QUERY, max_response: 10, group: Ipv4Addr::UNSPECIFIED }.emit();
        assert!(IgmpPacket::parse(&wire).is_some());
        for n in 0..IGMP_LEN {
            assert!(IgmpPacket::parse(&wire[..n]).is_none());
        }
    }
}
