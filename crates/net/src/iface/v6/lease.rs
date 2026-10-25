//! What a DHCPv6 client ([`Dhcp6Client`](crate::dhcp6::Dhcp6Client)) does to
//! an [`Interface`]: adds the addresses it leased, with their lifetimes, and
//! sets the DNS servers it learned.

use core::net::Ipv6Addr;

use super::{Address, Dad, Interface, MAX_ADDRESSES, MAX_DNS, is_link_local, lifetime};
use crate::{Error, Instant};

impl Interface {
    /// The managed (`M`) and other-configuration (`O`) flags of the last
    /// router advertisement: addresses, and other settings such as DNS
    /// servers, are available from DHCPv6. Both are false until an
    /// advertisement arrives.
    pub fn ipv6_ra_flags(&self) -> (bool, bool) {
        self.v6.ra_flags
    }

    /// Adds, or refreshes, an address leased by DHCPv6. It is used once
    /// duplicate address detection passes and removed when `valid` seconds
    /// (`u32::MAX` for forever) have passed. DHCPv6 gives no prefix length,
    /// so the address is a /128; hosts on the link are reached through the
    /// on-link prefixes router advertisements announce.
    pub fn add_dhcpv6_address(&mut self, now: Instant, addr: Ipv6Addr, valid: u32) -> Result<(), Error> {
        let unusable = addr.is_unspecified() || addr.is_multicast() || addr.is_loopback() || is_link_local(addr);
        if unusable || valid == 0 {
            return Err(Error::InvalidAddress);
        }
        let expires = lifetime(now, valid);
        if let Some(a) = self.v6.addrs.iter_mut().find(|a| a.addr == addr) {
            a.expires = expires;
            return Ok(());
        }
        if self.v6.is_tentative_or_ours(addr) {
            return Err(Error::InvalidAddress);
        }
        if self.v6.addrs.len() >= MAX_ADDRESSES {
            return Err(Error::WouldBlock);
        }
        self.v6.addrs.push(Address { addr, prefix_len: 128, dad: Dad::Idle, expires });
        Ok(())
    }

    /// Removes an address added with [`add_dhcpv6_address`](Self::add_dhcpv6_address)
    /// (or any global address). Returns whether there was one.
    pub fn remove_ipv6_address(&mut self, addr: Ipv6Addr) -> bool {
        let before = self.v6.addrs.len();
        self.v6.addrs.retain(|a| a.addr != addr);
        self.v6.addrs.len() != before
    }

    /// Sets the DNS servers DHCPv6 reported, for `valid` seconds (`u32::MAX`
    /// for forever), replacing those from router advertisements.
    pub fn set_dhcpv6_dns(&mut self, now: Instant, servers: &[Ipv6Addr], valid: u32) {
        let usable = |d: &&Ipv6Addr| !d.is_multicast() && !d.is_unspecified();
        self.v6.dns = servers.iter().filter(usable).copied().take(MAX_DNS).collect();
        self.v6.dns_expires = if self.v6.dns.is_empty() { None } else { lifetime(now, valid) };
    }
}
