//! Path MTU discovery (RFC 1191 for IPv4, RFC 8201 for IPv6): the cache of
//! what routers have said the path to a destination carries.
//!
//! An [`Interface`](crate::Interface) keeps one [`PathMtuCache`]. It learns
//! from ICMP "fragmentation needed" (IPv4) and ICMPv6 "packet too big"
//! messages, after checking that the packet they quote is one this host sent
//! recently: the quoted source is ours, and a TCP segment's sequence number
//! is in flight on a matching connection (a UDP or echo packet needs a
//! socket on the quoted port or identifier), and the quoted packet is larger
//! than the MTU reported. TCP then sizes its segments to the cached MTU and
//! resends what the smaller path dropped; datagrams larger than it are
//! fragmented (IPv4) or not sent (IPv6, which this stack does not
//! fragment).
//!
//! A cached MTU only ever falls, never below a floor ([`MIN_MTU_V4`],
//! [`MIN_MTU_V6`]): a router claiming less is taken to claim the floor. An
//! entry lives [`PMTU_TIMEOUT`] and then lapses, so that a path that has
//! improved is found again by new connections. (Connections already
//! running keep their smaller segments; no probing raises them.)

use alloc::vec::Vec;
use core::net::IpAddr;
use core::time::Duration;

use crate::Instant;

/// ICMP destination-unreachable code: fragmentation needed and DF set.
pub const ICMP_FRAGMENTATION_NEEDED: u8 = 4;
/// The least IPv4 path MTU accepted. A smaller figure in an ICMP message is
/// raised to this one, so that a forged message cannot make every segment
/// tiny. (RFC 791 only requires 68; 576 is the size every host must accept
/// reassembled.)
pub const MIN_MTU_V4: usize = 576;
/// The least IPv6 path MTU accepted: the minimum link MTU (RFC 8200).
pub const MIN_MTU_V6: usize = crate::ipv6::IPV6_MIN_MTU;
/// How long a learned MTU is kept (RFC 1191 suggests 10 minutes).
pub const PMTU_TIMEOUT: Duration = Duration::from_secs(600);
/// Destinations remembered; the entry nearest to expiry makes way for a new
/// one, so that a flood of forged destinations cannot grow the table.
pub const MAX_ENTRIES: usize = 64;

/// The MTU plateaus of RFC 1191 section 7.1, largest first, for routers that
/// report no next-hop MTU.
const PLATEAUS: [usize; 11] = [65535, 32000, 17914, 8166, 4352, 2002, 1492, 1006, 508, 296, 68];

/// The next MTU below `packet_len` from the plateau table: the guess for a
/// router that says only that a packet of that size was too big.
pub fn plateau_below(packet_len: usize) -> usize {
    PLATEAUS.iter().copied().find(|&p| p < packet_len).unwrap_or(68)
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    dst: IpAddr,
    mtu: usize,
    expires: Instant,
}

/// The path MTUs learned for destinations, with expiry.
#[derive(Debug, Default)]
pub struct PathMtuCache {
    entries: Vec<Entry>,
}

impl PathMtuCache {
    /// An empty cache.
    pub const fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// The least MTU accepted toward `dst`.
    pub const fn floor(dst: IpAddr) -> usize {
        if dst.is_ipv4() { MIN_MTU_V4 } else { MIN_MTU_V6 }
    }

    /// The MTU learned for `dst`, if an unexpired entry exists.
    pub fn lookup(&self, dst: IpAddr, now: Instant) -> Option<usize> {
        self.entries.iter().find(|e| e.dst == dst && now < e.expires).map(|e| e.mtu)
    }

    /// The MTU to use toward `dst` on a link of `link_mtu`.
    pub fn path_mtu(&self, dst: IpAddr, link_mtu: usize, now: Instant) -> usize {
        self.lookup(dst, now).map_or(link_mtu, |m| m.min(link_mtu))
    }

    /// Records that a router reported `reported` as the MTU toward `dst`.
    ///
    /// The figure is raised to the floor and ignored if it does not lower
    /// the path MTU on a link of `link_mtu` (a message cannot raise it).
    /// Returns the new path MTU if it fell.
    pub fn update(&mut self, dst: IpAddr, reported: usize, link_mtu: usize, now: Instant) -> Option<usize> {
        let mtu = reported.max(Self::floor(dst));
        if mtu >= self.path_mtu(dst, link_mtu, now) {
            return None;
        }
        let expires = now + PMTU_TIMEOUT;
        if let Some(e) = self.entries.iter_mut().find(|e| e.dst == dst) {
            e.mtu = mtu;
            e.expires = expires;
            return Some(mtu);
        }
        self.entries.retain(|e| now < e.expires);
        if self.entries.len() >= MAX_ENTRIES
            && let Some(i) = self.entries.iter().enumerate().min_by_key(|(_, e)| e.expires).map(|(i, _)| i)
        {
            self.entries.swap_remove(i);
        }
        self.entries.push(Entry { dst, mtu, expires });
        Some(mtu)
    }

    /// Forgets what is known about `dst`.
    pub fn remove(&mut self, dst: IpAddr) {
        self.entries.retain(|e| e.dst != dst);
    }

    /// Forgets everything.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Entries held, expired ones included until the next update.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if no entry is held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const D4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    const D6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9));

    fn at(secs: u64) -> Instant {
        Instant::from_millis(secs * 1000)
    }

    #[test]
    fn learns_only_decreases() {
        let mut c = PathMtuCache::new();
        assert_eq!(c.update(D4, 1400, 1500, at(0)), Some(1400));
        assert_eq!(c.lookup(D4, at(1)), Some(1400));
        assert_eq!(c.update(D4, 1450, 1500, at(1)), None, "a higher figure is not taken");
        assert_eq!(c.update(D4, 1400, 1500, at(1)), None);
        assert_eq!(c.update(D4, 1200, 1500, at(1)), Some(1200));
        assert_eq!(c.update(D4, 1600, 1500, at(1)), None, "above the link");
        assert_eq!(c.path_mtu(D4, 1500, at(1)), 1200);
        assert_eq!(c.path_mtu(D6, 1500, at(1)), 1500);
    }

    #[test]
    fn floor_applies_per_family() {
        let mut c = PathMtuCache::new();
        assert_eq!(c.update(D4, 68, 1500, at(0)), Some(MIN_MTU_V4));
        assert_eq!(c.update(D4, 0, 1500, at(0)), None, "already at the floor");
        assert_eq!(c.update(D6, 600, 1500, at(0)), Some(MIN_MTU_V6));
        // A link already at the floor gains nothing.
        assert_eq!(c.update(D6, 1000, 1280, at(0)), None);
    }

    #[test]
    fn entries_expire_and_can_be_relearned() {
        let mut c = PathMtuCache::new();
        c.update(D4, 1000, 1500, at(0));
        assert_eq!(c.lookup(D4, at(599)), Some(1000));
        assert_eq!(c.lookup(D4, at(600)), None);
        assert_eq!(c.path_mtu(D4, 1500, at(600)), 1500);
        assert_eq!(c.update(D4, 1200, 1500, at(700)), Some(1200));
        assert_eq!(c.lookup(D4, at(1299)), Some(1200));
        // A lower report refreshes the lifetime.
        assert_eq!(c.update(D4, 1100, 1500, at(1000)), Some(1100));
        assert_eq!(c.lookup(D4, at(1500)), Some(1100));
    }

    #[test]
    fn the_table_is_bounded() {
        let mut c = PathMtuCache::new();
        let ip = |n: u32| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n));
        let total = MAX_ENTRIES as u32 * 2;
        for n in 0..total {
            c.update(ip(n), 1000, 1500, at(u64::from(n)));
            assert!(c.len() <= MAX_ENTRIES);
        }
        // The oldest are gone, the newest kept.
        assert_eq!(c.lookup(ip(0), at(0)), None);
        assert_eq!(c.lookup(ip(total - 1), at(0)), Some(1000));
    }

    #[test]
    fn plateaus() {
        assert_eq!(plateau_below(1500), 1492);
        assert_eq!(plateau_below(1492), 1006);
        assert_eq!(plateau_below(576), 508);
        assert_eq!(plateau_below(60), 68);
        assert_eq!(plateau_below(70000), 65535);
    }
}
