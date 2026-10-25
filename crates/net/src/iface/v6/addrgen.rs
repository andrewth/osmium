//! How an [`Interface`] forms its SLAAC addresses: from the MAC address
//! (the default), as opaque stable identifiers (RFC 7217), and with
//! temporary addresses beside them (RFC 4941). See [`privacy`].
//!
//! A temporary address is generated for each autonomous /64 prefix a router
//! advertises. It is preferred for outgoing connections until its preferred
//! lifetime (at most a day, less a random amount) runs out; a replacement
//! is generated shortly before, and the old address is kept, deprecated,
//! until its valid lifetime ends so that existing connections survive. An
//! address that duplicate address detection rejects is replaced by another
//! (up to [`privacy::RETRIES`] times).

use alloc::vec::Vec;
use core::net::Ipv6Addr;
use core::time::Duration;

use super::{Address, Dad, INFINITE, Interface, MAX_ADDRESSES, State, eui64, lifetime, with_prefix};
use crate::Instant;
use crate::privacy::{self, AddressGeneration};

/// A temporary address and what it takes to replace it.
struct Temp {
    addr: Ipv6Addr,
    prefix: Ipv6Addr,
    /// When the address stops being valid.
    valid_until: Option<Instant>,
    /// When the address stops being preferred.
    preferred_until: Instant,
    /// When the prefix it came from stops being valid and preferred, as of
    /// the last advertisement; `None` is forever.
    prefix_valid_until: Option<Instant>,
    prefix_preferred_until: Option<Instant>,
    /// Past its preferred lifetime: kept for existing connections only.
    deprecated: bool,
    /// A replacement has been generated.
    replaced: bool,
    /// Times duplicate address detection has rejected an address for this.
    collisions: u8,
}

/// The state of address generation.
#[derive(Default)]
pub(super) struct Privacy {
    generation: AddressGeneration,
    temporary: bool,
    /// The random amount preferred lifetimes are shortened by.
    desync: u32,
    /// `(prefix, collisions)` for stable addresses whose duplicate address
    /// detection failed.
    collisions: Vec<(Ipv6Addr, u8)>,
    temps: Vec<Temp>,
}

impl Privacy {
    /// The settings, with the addresses forgotten.
    pub(super) fn reset(self) -> Self {
        Self { generation: self.generation, temporary: self.temporary, desync: self.desync, ..Self::default() }
    }
}

/// A temporary address of an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemporaryAddress {
    /// The address.
    pub addr: Ipv6Addr,
    /// Duplicate address detection has passed.
    pub usable: bool,
    /// Past its preferred lifetime: not used for new connections.
    pub deprecated: bool,
}

impl State {
    /// The newest temporary address that is usable and not deprecated, the
    /// source for outgoing connections (RFC 6724 rule 7).
    pub(super) fn preferred_temp(&self) -> Option<Ipv6Addr> {
        self.privacy
            .temps
            .iter()
            .rev()
            .filter(|t| !t.deprecated)
            .find(|t| self.addrs.iter().any(|a| a.addr == t.addr && matches!(a.dad, Dad::Done)))
            .map(|t| t.addr)
    }

    /// When the next temporary address is due for replacement or
    /// deprecation.
    pub(super) fn privacy_poll_at(&self) -> Option<Instant> {
        self.privacy
            .temps
            .iter()
            .flat_map(|t| {
                let regen = (!t.replaced).then(|| regen_at(t.preferred_until));
                regen.into_iter().chain((!t.deprecated).then_some(t.preferred_until))
            })
            .min()
    }

    fn collisions(&self, prefix: Ipv6Addr) -> u8 {
        self.privacy.collisions.iter().find(|(p, _)| *p == prefix).map_or(0, |(_, n)| *n)
    }
}

fn regen_at(preferred_until: Instant) -> Instant {
    Instant::from_millis(preferred_until.as_millis().saturating_sub(u64::from(privacy::REGEN_ADVANCE) * 1000))
}

/// Seconds from `now` to `until`, "forever" for `None`.
fn remaining(now: Instant, until: Option<Instant>) -> u32 {
    until.map_or(INFINITE, |t| u32::try_from((t - now).as_secs()).unwrap_or(INFINITE - 1))
}

fn prefix_of(addr: Ipv6Addr) -> Ipv6Addr {
    with_prefix(addr, 64, [0; 8])
}

impl Interface {
    /// Chooses how the identifiers of autoconfigured addresses are formed
    /// (the MAC-derived default, or RFC 7217 opaque ones). It applies to
    /// addresses formed from then on.
    pub fn set_ipv6_address_generation(&mut self, generation: AddressGeneration) {
        self.v6.privacy.generation = generation;
    }

    /// The address generation in force.
    pub fn ipv6_address_generation(&self) -> AddressGeneration {
        self.v6.privacy.generation
    }

    /// Turns temporary addresses (RFC 4941) on or off. With them on, each
    /// autoconfigured prefix gets a randomly chosen, short-lived address,
    /// which outgoing connections use in preference to the stable one. Turning
    /// them off drops the temporary addresses.
    pub fn set_ipv6_temporary_addresses(&mut self, on: bool) {
        if on && !self.v6.privacy.temporary {
            self.v6.privacy.desync = self.rng.next_u32() % privacy::MAX_DESYNC_FACTOR;
        }
        self.v6.privacy.temporary = on;
        if !on {
            let temps = core::mem::take(&mut self.v6.privacy.temps);
            self.v6.addrs.retain(|a| !temps.iter().any(|t| t.addr == a.addr));
        }
    }

    /// The temporary addresses, oldest first.
    pub fn ipv6_temporary_addresses(&self) -> Vec<TemporaryAddress> {
        let usable = |addr| self.v6.addrs.iter().any(|a| a.addr == addr && matches!(a.dad, Dad::Done));
        self.v6
            .privacy
            .temps
            .iter()
            .map(|t| TemporaryAddress { addr: t.addr, usable: usable(t.addr), deprecated: t.deprecated })
            .collect()
    }

    /// The SLAAC address on the /64 `prefix`.
    pub(super) fn slaac_address(&self, prefix: Ipv6Addr) -> Ipv6Addr {
        let iid = match self.v6.privacy.generation {
            AddressGeneration::Eui64 => eui64(self.mac),
            AddressGeneration::StableOpaque { secret } => {
                privacy::stable_iid(&secret, prefix, 64, &self.mac.0, &[], self.v6.collisions(prefix))
            }
        };
        with_prefix(prefix, 64, iid)
    }

    /// A router advertised the autonomous /64 `prefix`: make sure a
    /// temporary address on it exists, and note how long the prefix lasts.
    pub(super) fn temp_for_prefix(&mut self, now: Instant, prefix: Ipv6Addr, valid: u32, preferred: u32) {
        if !self.v6.privacy.temporary || valid == 0 {
            return;
        }
        let (valid_until, preferred_until) = (lifetime(now, valid), lifetime(now, preferred));
        let mut live = false;
        for t in self.v6.privacy.temps.iter_mut().filter(|t| t.prefix == prefix) {
            t.prefix_valid_until = valid_until;
            t.prefix_preferred_until = preferred_until;
            live |= !t.replaced;
        }
        if !live {
            self.new_temp(now, prefix, valid_until, preferred_until);
        }
    }

    /// Generates a temporary address on `prefix`, which is valid and
    /// preferred until the given times. Returns false if it cannot.
    fn new_temp(&mut self, now: Instant, prefix: Ipv6Addr, valid: Option<Instant>, preferred: Option<Instant>) -> bool {
        let desync = self.v6.privacy.desync;
        let Some((valid_s, preferred_s)) =
            privacy::temporary_lifetimes(remaining(now, valid), remaining(now, preferred), desync)
        else {
            return false;
        };
        if self.v6.addrs.len() >= MAX_ADDRESSES {
            return false;
        }
        // A colliding choice is not tried again: it is unlikely, and the
        // next advertisement will make another.
        let addr = with_prefix(prefix, 64, privacy::temporary_iid(|| self.rng.next_u64()));
        if self.v6.is_tentative_or_ours(addr) {
            return false;
        }
        let valid_until = now + Duration::from_secs(u64::from(valid_s));
        self.v6.addrs.push(Address { addr, prefix_len: 64, dad: Dad::Idle, expires: Some(valid_until) });
        self.v6.privacy.temps.push(Temp {
            addr,
            prefix,
            valid_until: Some(valid_until),
            preferred_until: now + Duration::from_secs(u64::from(preferred_s)),
            prefix_valid_until: valid,
            prefix_preferred_until: preferred,
            deprecated: false,
            replaced: false,
            collisions: 0,
        });
        true
    }

    /// Deprecates temporary addresses past their preferred lifetime and
    /// generates replacements ahead of it.
    pub(super) fn privacy_poll(&mut self, now: Instant) {
        let v6 = &mut self.v6;
        let addrs = &v6.addrs;
        v6.privacy.temps.retain(|t| addrs.iter().any(|a| a.addr == t.addr));
        let mut due = Vec::new();
        for t in &mut v6.privacy.temps {
            t.deprecated |= t.preferred_until <= now;
            if !t.replaced && regen_at(t.preferred_until) <= now {
                t.replaced = true;
                due.push((t.prefix, t.prefix_valid_until, t.prefix_preferred_until));
            }
        }
        if !self.v6.privacy.temporary {
            return;
        }
        for (prefix, valid, preferred) in due {
            if valid.is_none_or(|t| t > now) {
                self.new_temp(now, prefix, valid, preferred);
            }
        }
    }

    /// Duplicate address detection found `addr` (valid until `expires`) in
    /// use. A stable address is formed again with the next counter, and a
    /// temporary one with another random identifier.
    pub(super) fn address_collided(&mut self, addr: Ipv6Addr, expires: Option<Instant>) {
        let prefix = prefix_of(addr);
        if let Some(i) = self.v6.privacy.temps.iter().position(|t| t.addr == addr) {
            let lost = self.v6.privacy.temps.remove(i);
            return self.retry_temp(lost);
        }
        if !matches!(self.v6.privacy.generation, AddressGeneration::StableOpaque { .. }) {
            return;
        }
        let tries = self.v6.collisions(prefix);
        if tries >= privacy::RETRIES || self.v6.addrs.len() >= MAX_ADDRESSES {
            return;
        }
        match self.v6.privacy.collisions.iter_mut().find(|(p, _)| *p == prefix) {
            Some((_, n)) => *n += 1,
            None => self.v6.privacy.collisions.push((prefix, 1)),
        }
        let retry = self.slaac_address(prefix);
        if !self.v6.is_tentative_or_ours(retry) {
            self.v6.addrs.push(Address { addr: retry, prefix_len: 64, dad: Dad::Idle, expires });
        }
    }

    fn retry_temp(&mut self, lost: Temp) {
        // The new address keeps the lifetimes of the one that was lost.
        if lost.collisions >= privacy::RETRIES {
            return;
        }
        let addr = with_prefix(lost.prefix, 64, privacy::temporary_iid(|| self.rng.next_u64()));
        if self.v6.addrs.len() >= MAX_ADDRESSES || self.v6.is_tentative_or_ours(addr) {
            return;
        }
        self.v6.addrs.push(Address { addr, prefix_len: 64, dad: Dad::Idle, expires: lost.valid_until });
        self.v6.privacy.temps.push(Temp { addr, collisions: lost.collisions + 1, ..lost });
    }
}

#[cfg(test)]
mod tests;
