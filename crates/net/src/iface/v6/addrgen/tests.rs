use std::vec;
use std::vec::Vec;

use osmium_hal::net::MacAddress;

use super::*;
use crate::ipv6::{
    ALL_NODES, ETHERTYPE_IPV6, ICMPV6_NEIGHBOR_ADVERT, ICMPV6_ROUTER_ADVERT, IPV6_HEADER_LEN, Icmpv6Header, Ipv6Header,
    NeighborAdvert, PROTO_ICMPV6, PrefixInfo, RouterAdvert, multicast_mac,
};
use crate::testing::{Host, pair6};
use crate::wire::{ETH_HEADER_LEN, EthernetHeader};

const ROUTER_MAC: MacAddress = MacAddress([2, 0, 0, 0, 0, 0x99]);
const ROUTER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);
const NET: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, 0);
const SECRET: [u8; 16] = *b"a very secret k!";

fn at(secs: u64) -> Instant {
    Instant::from_millis(secs * 1000)
}

fn icmp_frame(dst_mac: MacAddress, dst: Ipv6Addr, ty: u8, body: &[u8]) -> Vec<u8> {
    let payload = Icmpv6Header { ty, code: 0 }.emit(ROUTER, dst, body);
    let mut f = vec![0; ETH_HEADER_LEN + IPV6_HEADER_LEN + payload.len()];
    EthernetHeader { dst: dst_mac, src: ROUTER_MAC, ethertype: ETHERTYPE_IPV6 }.emit(&mut f);
    let h = Ipv6Header {
        src: ROUTER,
        dst,
        next_header: PROTO_ICMPV6,
        hop_limit: 255,
        payload_len: payload.len(),
        fragment: None,
    };
    h.emit(&mut f[ETH_HEADER_LEN..]);
    f[ETH_HEADER_LEN + IPV6_HEADER_LEN..].copy_from_slice(&payload);
    f
}

/// Delivers a router advertisement of `prefix` to `h` at `secs`.
fn advertise(h: &mut Host, secs: u64, prefix: Ipv6Addr, valid: u32, preferred: u32) {
    let ra = RouterAdvert {
        hop_limit: 64,
        managed: false,
        other: false,
        router_lifetime: 1800,
        source_ll: Some(ROUTER_MAC),
        mtu: None,
        prefixes: vec![PrefixInfo {
            prefix_len: 64,
            on_link: true,
            autonomous: true,
            valid_lifetime: valid,
            preferred_lifetime: preferred,
            prefix,
        }],
        dns: vec![],
        dns_lifetime: 0,
        dns_withdrawn: vec![],
    };
    h.inject(icmp_frame(multicast_mac(ALL_NODES), ALL_NODES, ICMPV6_ROUTER_ADVERT, &ra.emit()));
    h.poll(at(secs));
}

/// Polls `h` once a second from `from` to `to` seconds.
fn run_secs(h: &mut Host, from: u64, to: u64) {
    for s in from..=to {
        h.poll(at(s));
    }
}

/// Says that someone else has `addr`.
fn claim(h: &mut Host, secs: u64, addr: Ipv6Addr) {
    let na = NeighborAdvert {
        router: false,
        solicited: false,
        override_: true,
        target: addr,
        target_ll: Some(MacAddress([2, 0, 0, 0, 0, 0x77])),
    };
    h.inject(icmp_frame(multicast_mac(ALL_NODES), ALL_NODES, ICMPV6_NEIGHBOR_ADVERT, &na.emit()));
    h.poll(at(secs));
}

fn globals(h: &Host) -> Vec<Ipv6Addr> {
    h.iface.ipv6_addresses().into_iter().skip(1).map(|a| a.addr).collect()
}

fn is_eui64_of(h: &Host, a: Ipv6Addr) -> bool {
    a == with_prefix(NET, 64, eui64(h.iface.mac_address()))
}

#[test]
fn default_addresses_are_eui64_and_have_no_temporary_ones() {
    let (mut a, _b, _) = pair6();
    advertise(&mut a, 10, NET, 7200, 3600);
    assert_eq!(globals(&a).len(), 1);
    assert!(is_eui64_of(&a, globals(&a)[0]));
    assert!(a.iface.ipv6_temporary_addresses().is_empty());
    assert_eq!(a.iface.ipv6_address_generation(), AddressGeneration::Eui64);
}

#[test]
fn stable_opaque_addresses_hide_the_mac_and_stay_put() {
    let (mut a, _b, _) = pair6();
    a.iface.set_ipv6_address_generation(AddressGeneration::StableOpaque { secret: SECRET });
    advertise(&mut a, 10, NET, 7200, 3600);
    let mac = a.iface.mac_address();
    let want = with_prefix(NET, 64, privacy::stable_iid(&SECRET, NET, 64, &mac.0, &[], 0));
    assert_eq!(globals(&a), [want]);
    assert!(!is_eui64_of(&a, want));
    // The same on every advertisement, and after IPv6 is restarted.
    advertise(&mut a, 20, NET, 7200, 3600);
    assert_eq!(globals(&a), [want]);
    a.iface.disable_ipv6();
    a.iface.enable_ipv6().unwrap();
    assert_eq!(a.iface.ipv6_address_generation(), AddressGeneration::StableOpaque { secret: SECRET });
    run_secs(&mut a, 30, 33);
    advertise(&mut a, 34, NET, 7200, 3600);
    assert_eq!(globals(&a), [want]);
    // A different network gets an unrelated identifier.
    let other = Ipv6Addr::new(0x2001, 0xdb8, 9, 9, 0, 0, 0, 0);
    advertise(&mut a, 35, other, 7200, 3600);
    let all = globals(&a);
    assert_eq!(all.len(), 2);
    assert_ne!(all[0].octets()[8..], all[1].octets()[8..]);
}

#[test]
fn a_stable_address_in_use_is_replaced_up_to_three_times() {
    let (mut a, _b, _) = pair6();
    a.iface.set_ipv6_address_generation(AddressGeneration::StableOpaque { secret: SECRET });
    advertise(&mut a, 10, NET, 7200, 3600);
    let mac = a.iface.mac_address();
    let nth = |n: u8| with_prefix(NET, 64, privacy::stable_iid(&SECRET, NET, 64, &mac.0, &[], n));
    for n in 0..3u8 {
        assert_eq!(globals(&a), [nth(n)], "attempt {n}");
        claim(&mut a, 11 + u64::from(n), nth(n));
    }
    assert_eq!(globals(&a), [nth(3)]);
    // The fourth is the last: it is dropped and not replaced.
    claim(&mut a, 20, nth(3));
    assert!(globals(&a).is_empty());
    // The replacement keeps the lifetime of the first.
    let (mut a, _b, _) = pair6();
    a.iface.set_ipv6_address_generation(AddressGeneration::StableOpaque { secret: SECRET });
    advertise(&mut a, 10, NET, 100, 50);
    claim(&mut a, 11, nth(0));
    assert_eq!(globals(&a), [nth(1)]);
    run_secs(&mut a, 12, 111);
    assert!(globals(&a).is_empty());
}

#[test]
fn temporary_addresses_are_random_preferred_and_bounded() {
    let (mut a, mut b, _) = pair6();
    a.iface.set_ipv6_temporary_addresses(true);
    advertise(&mut a, 10, NET, u32::MAX, u32::MAX);
    let all = globals(&a);
    assert_eq!(all.len(), 2, "the public address and a temporary one");
    let temps = a.iface.ipv6_temporary_addresses();
    assert_eq!(temps.len(), 1);
    let temp = temps[0].addr;
    assert!(all.contains(&temp) && !is_eui64_of(&a, temp));
    assert_eq!(temp.octets()[8] & 2, 0);
    // Tentative until detection passes; then the preferred source.
    assert!(!temps[0].usable);
    assert_ne!(a.iface.v6.global(), Some(temp));
    run_secs(&mut a, 11, 13);
    assert!(a.iface.ipv6_temporary_addresses()[0].usable);
    assert_eq!(a.iface.v6.global(), Some(temp));
    // The lifetimes are capped at 7 days and 1 day less up to ten minutes.
    let t = &a.iface.v6.privacy.temps[0];
    assert_eq!(t.valid_until, Some(at(10 + 7 * 24 * 3600)));
    let preferred = (t.preferred_until - at(10)).as_secs();
    assert!(preferred > 24 * 3600 - 600 && preferred <= 24 * 3600, "{preferred}");
    // Another advertisement does not make another.
    advertise(&mut a, 20, NET, u32::MAX, u32::MAX);
    assert_eq!(a.iface.ipv6_temporary_addresses().len(), 1);
    // Two interfaces choose different identifiers (a different seed each).
    b.iface.set_ipv6_temporary_addresses(true);
    advertise(&mut b, 10, NET, u32::MAX, u32::MAX);
    assert_ne!(b.iface.ipv6_temporary_addresses()[0].addr, temp);
    // Turning them off drops them.
    a.iface.set_ipv6_temporary_addresses(false);
    assert!(a.iface.ipv6_temporary_addresses().is_empty());
    assert_eq!(globals(&a).len(), 1);
    assert!(is_eui64_of(&a, globals(&a)[0]));
}

#[test]
fn temporary_addresses_are_replaced_before_they_are_deprecated_and_expire() {
    let (mut a, _b, _) = pair6();
    a.iface.set_ipv6_temporary_addresses(true);
    advertise(&mut a, 10, NET, 5000, 2000);
    run_secs(&mut a, 11, 13);
    let first = a.iface.ipv6_temporary_addresses()[0].addr;
    assert_eq!(a.iface.v6.global(), Some(first));
    let due = a.iface.poll_at(&a.sockets).unwrap();
    assert!(due.as_millis() <= 10_000 + 1995 * 1000);
    // The router keeps advertising the prefix, so it is still preferred when
    // the address is due for replacement.
    run_secs(&mut a, 14, 1500);
    advertise(&mut a, 1500, NET, 5000, 2000);
    run_secs(&mut a, 1501, 2004);
    assert_eq!(a.iface.ipv6_temporary_addresses().len(), 1);
    // Five seconds before the preferred lifetime ends a replacement appears.
    a.poll(at(2005));
    let temps = a.iface.ipv6_temporary_addresses();
    assert_eq!(temps.len(), 2, "replacement generated");
    assert_eq!(temps[0].addr, first);
    assert!(!temps[0].deprecated);
    let second = temps[1].addr;
    assert_ne!(first, second);
    // The old one is deprecated at the end of its preferred lifetime, and
    // the new one is the source.
    run_secs(&mut a, 2006, 2008);
    // The replacement is the source as soon as detection has passed, while
    // the old address is still not deprecated.
    assert_eq!(a.iface.v6.global(), Some(second));
    assert!(!a.iface.ipv6_temporary_addresses()[0].deprecated);
    a.poll(at(2010));
    let temps = a.iface.ipv6_temporary_addresses();
    assert!(temps[0].deprecated && !temps[1].deprecated);
    assert_eq!(a.iface.v6.global(), Some(second));
    // The first expires when its valid lifetime does; none outlasts the
    // prefix.
    run_secs(&mut a, 2011, 5009);
    assert_eq!(a.iface.ipv6_temporary_addresses().len(), 2);
    a.poll(at(5010));
    assert_eq!(a.iface.ipv6_temporary_addresses().iter().map(|t| t.addr).collect::<Vec<_>>(), [second]);
    run_secs(&mut a, 5011, 6500);
    assert!(a.iface.ipv6_temporary_addresses().is_empty());
    assert!(a.iface.v6.privacy.temps.is_empty());
}

#[test]
fn no_temporary_address_for_a_dying_or_hopeless_prefix() {
    let (mut a, _b, _) = pair6();
    a.iface.set_ipv6_temporary_addresses(true);
    // Preferred for too short a time to be worth replacing.
    advertise(&mut a, 10, NET, 3600, 4);
    assert!(a.iface.ipv6_temporary_addresses().is_empty());
    // Not valid at all.
    advertise(&mut a, 11, NET, 0, 0);
    assert!(a.iface.ipv6_temporary_addresses().is_empty());
    // Temporary addresses off: none even for a good prefix.
    a.iface.set_ipv6_temporary_addresses(false);
    advertise(&mut a, 12, NET, 7200, 3600);
    assert!(a.iface.ipv6_temporary_addresses().is_empty());
}

#[test]
fn a_temporary_address_in_use_is_replaced_up_to_three_times() {
    let (mut a, _b, _) = pair6();
    a.iface.set_ipv6_temporary_addresses(true);
    advertise(&mut a, 10, NET, 7200, 3600);
    let mut seen = Vec::new();
    for n in 0..4u64 {
        let t = a.iface.ipv6_temporary_addresses();
        assert_eq!(t.len(), 1, "attempt {n}");
        assert!(!seen.contains(&t[0].addr));
        seen.push(t[0].addr);
        claim(&mut a, 11 + n, t[0].addr);
    }
    assert!(a.iface.ipv6_temporary_addresses().is_empty(), "gave up after three retries");
    // Lifetimes of the original carried over to the replacements.
    let (mut a, _b, _) = pair6();
    a.iface.set_ipv6_temporary_addresses(true);
    advertise(&mut a, 10, NET, 7200, 3600);
    let before = a.iface.v6.privacy.temps[0].valid_until;
    let addr = a.iface.ipv6_temporary_addresses()[0].addr;
    claim(&mut a, 11, addr);
    assert_eq!(a.iface.v6.privacy.temps[0].valid_until, before);
}
