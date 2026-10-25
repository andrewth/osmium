//! Interface identifiers that do not give a host away: semantically opaque
//! stable ones (RFC 7217) and temporary ones (RFC 4941).
//!
//! An EUI-64 identifier is the MAC address in disguise, so the same host is
//! recognizable on every network it visits. RFC 7217 replaces it with a
//! pseudo-random function of the network's prefix and a secret key: stable
//! on one network, unrelated across networks. RFC 4941 adds short-lived
//! addresses chosen at random, which a host prefers for outgoing
//! connections.
//!
//! The functions here are pure; an [`Interface`](crate::Interface) uses them
//! when [`set_ipv6_address_generation`](crate::Interface::set_ipv6_address_generation)
//! and [`set_ipv6_temporary_addresses`](crate::Interface::set_ipv6_temporary_addresses)
//! are set.
//!
//! The pseudo-random function is SipHash keyed by the secret, not the
//! HMAC-SHA-256 RFC 7217 names; RFC 7217 allows any function that is
//! pseudo-random to those who do not know the key.

use alloc::vec::Vec;
use core::net::Ipv6Addr;

use crate::rng::siphash;

/// The longest a temporary address stays valid (`TEMP_VALID_LIFETIME`, RFC
/// 4941 section 3.8), in seconds: 7 days.
pub const TEMP_VALID_LIFETIME: u32 = 7 * 24 * 3600;
/// The longest a temporary address stays preferred
/// (`TEMP_PREFERRED_LIFETIME`), in seconds: 1 day.
pub const TEMP_PREFERRED_LIFETIME: u32 = 24 * 3600;
/// A replacement is generated this many seconds before an address stops
/// being preferred (`REGEN_ADVANCE`).
pub const REGEN_ADVANCE: u32 = 5;
/// The upper bound, in seconds, of the random amount (`DESYNC_FACTOR`) by
/// which preferred lifetimes are shortened so that hosts do not renew in
/// step.
pub const MAX_DESYNC_FACTOR: u32 = 600;
/// Attempts to find a free address after duplicate address detection fails
/// (`DAD_Counter` retries in RFC 7217, `TEMP_IDGEN_RETRIES` in RFC 4941).
pub const RETRIES: u8 = 3;

/// How an interface forms the identifier of its autoconfigured addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AddressGeneration {
    /// Modified EUI-64 from the MAC address (RFC 4291). The default.
    #[default]
    Eui64,
    /// Semantically opaque and stable per prefix (RFC 7217), keyed by a
    /// secret that should be random, kept private and persist across boots.
    StableOpaque {
        /// The secret key.
        secret: [u8; 16],
    },
}

/// Returns true for an identifier that must not be an address's (RFC 5453,
/// RFC 7136, RFC 7217 section 5): the subnet-router anycast identifier
/// (all zero), the ISATAP forms `0200:5efe:...` and `0000:5efe:...`, and the reserved subnet
/// anycast range `fdff:ffff:ffff:ff80` to `ff`.
pub fn is_reserved_iid(iid: [u8; 8]) -> bool {
    let n = u64::from_be_bytes(iid);
    n == 0 || (n >> 32) | 0x0200_0000 == 0x0200_5efe || n >> 7 == 0xfdff_ffff_ffff_ffff_u64 >> 7
}

/// Appends `bytes` to `words`, length first so that different splits of the
/// same bytes hash differently.
fn pack(words: &mut Vec<u64>, bytes: &[u8]) {
    words.push(bytes.len() as u64);
    for chunk in bytes.chunks(8) {
        let mut w = [0u8; 8];
        for (d, s) in w.iter_mut().zip(chunk) {
            *d = *s;
        }
        words.push(u64::from_le_bytes(w));
    }
}

/// The stable identifier for the address on `prefix` (its first
/// `prefix_len` bits) of the interface `net_iface` (its MAC address or any
/// name that stays with the interface), on the network `network_id` (empty
/// if unknown; a Wi-Fi SSID would do), after `dad_counter` collisions
/// (RFC 7217 section 5).
pub fn stable_iid(
    secret: &[u8; 16],
    prefix: Ipv6Addr,
    prefix_len: u8,
    net_iface: &[u8],
    network_id: &[u8],
    dad_counter: u8,
) -> [u8; 8] {
    let [s0, s1] =
        [secret.first_chunk::<8>(), secret.last_chunk::<8>()].map(|c| u64::from_le_bytes(*c.unwrap_or(&[0; 8])));
    let mask = u128::MAX.checked_shl(128 - u32::from(prefix_len.min(128))).unwrap_or(0);
    let prefix = u128::from(prefix) & mask;
    let mut words = Vec::with_capacity(12);
    words.push(prefix_len as u64);
    words.push((prefix >> 64) as u64);
    words.push(prefix as u64);
    pack(&mut words, net_iface);
    pack(&mut words, network_id);
    // An identifier that is reserved is taken as a collision and the
    // counter moves on, as the RFC says.
    let mut counter = u64::from(dad_counter);
    loop {
        words.push(counter);
        let iid = siphash(s0, s1, &words).to_be_bytes();
        words.pop();
        if !is_reserved_iid(iid) {
            return iid;
        }
        counter += 256;
    }
}

/// A random identifier for a temporary address (RFC 4941 section 3.3.1):
/// `random` supplies 64 random bits at a time. The universal/local bit is
/// cleared, and reserved identifiers are skipped.
pub fn temporary_iid(mut random: impl FnMut() -> u64) -> [u8; 8] {
    loop {
        let iid = (random() & !(0x02 << 56)).to_be_bytes();
        if !is_reserved_iid(iid) {
            return iid;
        }
    }
}

/// The `(valid, preferred)` lifetimes in seconds of a temporary address on a
/// prefix advertised with `prefix_valid` and `prefix_preferred`, given the
/// host's `desync` (below [`MAX_DESYNC_FACTOR`]). `None` if the address
/// would be preferred for no longer than it takes to replace it
/// (RFC 4941 section 3.4).
pub fn temporary_lifetimes(prefix_valid: u32, prefix_preferred: u32, desync: u32) -> Option<(u32, u32)> {
    let valid = prefix_valid.min(TEMP_VALID_LIFETIME);
    let preferred = prefix_preferred.min(TEMP_PREFERRED_LIFETIME.saturating_sub(desync)).min(valid);
    (preferred > REGEN_ADVANCE).then_some((valid, preferred))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 16] = *b"0123456789abcdef";
    const NET: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 0);
    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

    #[test]
    fn stable_identifiers_depend_on_each_input_and_nothing_else() {
        let base = stable_iid(&SECRET, NET, 64, &MAC, b"", 0);
        assert_eq!(base, stable_iid(&SECRET, NET, 64, &MAC, b"", 0), "stable");
        // The host bits of the prefix do not matter; the prefix does.
        let noisy = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0xffff, 0, 0, 7);
        assert_eq!(base, stable_iid(&SECRET, noisy, 64, &MAC, b"", 0));
        let other_net = Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 0);
        let variants = [
            stable_iid(&SECRET, other_net, 64, &MAC, b"", 0),
            stable_iid(b"fedcba9876543210", NET, 64, &MAC, b"", 0),
            stable_iid(&SECRET, NET, 64, &[2, 0, 0, 0, 0, 2], b"", 0),
            stable_iid(&SECRET, NET, 64, &MAC, b"ssid", 0),
            stable_iid(&SECRET, NET, 64, &MAC, b"", 1),
            stable_iid(&SECRET, NET, 48, &MAC, b"", 0),
        ];
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(*v, base, "variant {i}");
            assert!(variants.iter().filter(|x| *x == v).count() == 1, "variant {i} is unique");
        }
        // Where the interface name ends and the network id begins matters.
        assert_ne!(stable_iid(&SECRET, NET, 64, b"ab", b"c", 0), stable_iid(&SECRET, NET, 64, b"a", b"bc", 0));
        // It does not leak the MAC address.
        assert!(!base.windows(3).any(|w| w == [0xff, 0xfe, MAC[3]]));
    }

    #[test]
    fn reserved_identifiers_are_recognized() {
        assert!(is_reserved_iid([0; 8]));
        assert!(is_reserved_iid([0x02, 0x00, 0x5e, 0xfe, 1, 2, 3, 4]));
        assert!(is_reserved_iid([0x00, 0x00, 0x5e, 0xfe, 1, 2, 3, 4]));
        assert!(is_reserved_iid([0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80]));
        assert!(is_reserved_iid([0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
        assert!(!is_reserved_iid([0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]));
        assert!(!is_reserved_iid([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn temporary_identifiers_are_random_local_and_not_reserved() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let a = temporary_iid(&mut rnd);
        let b = temporary_iid(&mut rnd);
        assert_ne!(a, b);
        assert_eq!(a[0] & 0x02, 0, "universal/local bit is local");
        // Reserved draws are skipped.
        let mut draws = [u64::MAX, 0, 0x0200_5efe_0000_0001, 0x1234_5678_9abc_def0].into_iter();
        let iid = temporary_iid(|| draws.next().unwrap());
        assert_eq!(iid, [0x10, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
    }

    #[test]
    fn temporary_lifetimes_follow_the_prefix_and_the_limits() {
        // A long prefix lifetime is capped at the defaults, less the desync.
        assert_eq!(
            temporary_lifetimes(u32::MAX, u32::MAX, 100),
            Some((TEMP_VALID_LIFETIME, TEMP_PREFERRED_LIFETIME - 100))
        );
        // A short one is respected.
        assert_eq!(temporary_lifetimes(3600, 1800, 100), Some((3600, 1800)));
        // Preferred never exceeds valid.
        assert_eq!(temporary_lifetimes(600, 1800, 0), Some((600, 600)));
        // Too short to be worth regenerating.
        assert_eq!(temporary_lifetimes(3600, 3, 0), None);
        assert_eq!(temporary_lifetimes(0, 0, 0), None);
    }
}
