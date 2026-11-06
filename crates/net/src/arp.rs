//! The neighbor cache: IPv4 to MAC mappings learned over ARP.

use alloc::vec::Vec;
use core::net::Ipv4Addr;
use core::time::Duration;

use osmium_hal::net::MacAddress;

use crate::Instant;

/// How long a learned mapping stays valid.
const LIFETIME: Duration = Duration::from_secs(60);
/// Entries kept; when the cache is full the one closest to expiry is
/// replaced, unless it is the protected one (the gateway).
const CAPACITY: usize = 32;

struct Entry {
    ip: Ipv4Addr,
    mac: MacAddress,
    expires: Instant,
}

pub(crate) struct ArpCache {
    entries: Vec<Entry>,
}

impl ArpCache {
    pub(crate) const fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub(crate) fn lookup(&self, ip: Ipv4Addr, now: Instant) -> Option<MacAddress> {
        self.entries.iter().find(|e| e.ip == ip && e.expires > now).map(|e| e.mac)
    }

    pub(crate) fn contains(&self, ip: Ipv4Addr) -> bool {
        self.entries.iter().any(|e| e.ip == ip)
    }

    /// Records `ip` at `mac`. When the cache is full this replaces the
    /// entry closest to expiry, never the one for `keep`.
    pub(crate) fn insert(&mut self, ip: Ipv4Addr, mac: MacAddress, now: Instant, keep: Option<Ipv4Addr>) {
        let expires = now + LIFETIME;
        if let Some(e) = self.entries.iter_mut().find(|e| e.ip == ip) {
            e.mac = mac;
            e.expires = expires;
        } else if self.entries.len() < CAPACITY {
            self.entries.push(Entry { ip, mac, expires });
        } else if let Some(e) = self.entries.iter_mut().filter(|e| Some(e.ip) != keep).min_by_key(|e| e.expires) {
            *e = Entry { ip, mac, expires };
        }
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_and_replacement() {
        let mut cache = ArpCache::new();
        let t0 = Instant::ZERO;
        for i in 0..CAPACITY as u8 {
            cache.insert(
                Ipv4Addr::new(10, 0, 0, i),
                MacAddress([2, 0, 0, 0, 0, i]),
                t0 + Duration::from_millis(i.into()),
                None,
            );
        }
        assert_eq!(cache.lookup(Ipv4Addr::new(10, 0, 0, 5), t0), Some(MacAddress([2, 0, 0, 0, 0, 5])));
        cache.insert(Ipv4Addr::new(10, 0, 1, 0), MacAddress([2, 0, 0, 0, 1, 0]), t0 + Duration::from_secs(1), None);
        assert!(!cache.contains(Ipv4Addr::new(10, 0, 0, 0)), "the oldest entry made room");
        assert_eq!(cache.lookup(Ipv4Addr::new(10, 0, 1, 0), t0 + LIFETIME + Duration::from_secs(1)), None, "expired");
    }

    #[test]
    fn the_protected_entry_survives_a_flood() {
        let mut cache = ArpCache::new();
        let t0 = Instant::ZERO;
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        cache.insert(gateway, MacAddress([2, 0, 0, 0, 0, 1]), t0, Some(gateway));
        for i in 0..200u8 {
            let at = t0 + Duration::from_millis(u64::from(i) + 1);
            cache.insert(Ipv4Addr::new(10, 0, 1, i), MacAddress([2, 0, 0, 0, 1, i]), at, Some(gateway));
        }
        assert_eq!(cache.lookup(gateway, t0 + Duration::from_secs(1)), Some(MacAddress([2, 0, 0, 0, 0, 1])));
        assert_eq!(cache.entries.len(), CAPACITY);
    }
}
