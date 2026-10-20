//! Random numbers for TCP initial sequence numbers, DHCP transaction ids,
//! DNS query ids and ephemeral ports.

use core::net::{IpAddr, SocketAddr};

use crate::Instant;

/// SipHash-1-3 of `words` under the key `(k0, k1)`.
fn siphash(k0: u64, k1: u64, words: &[u64]) -> u64 {
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    fn round(v: &mut [u64; 4]) {
        v[0] = v[0].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(13) ^ v[0];
        v[0] = v[0].rotate_left(32);
        v[2] = v[2].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(16) ^ v[2];
        v[0] = v[0].wrapping_add(v[3]);
        v[3] = v[3].rotate_left(21) ^ v[0];
        v[2] = v[2].wrapping_add(v[1]);
        v[1] = v[1].rotate_left(17) ^ v[2];
        v[2] = v[2].rotate_left(32);
    }
    for &w in words {
        v[3] ^= w;
        round(&mut v);
        v[0] ^= w;
    }
    v[3] ^= (words.len() as u64 * 8) << 56;
    round(&mut v);
    v[0] ^= (words.len() as u64 * 8) << 56;
    v[2] ^= 0xff;
    for _ in 0..3 {
        round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

fn splitmix(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A keyed pseudo-random function in counter mode (SipHash). Its output is
/// unpredictable to anyone who does not know the key, which is only as
/// strong as the entropy the caller seeded it with.
pub(crate) struct Rng {
    k0: u64,
    k1: u64,
    counter: u64,
}

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        let mut s = seed;
        Self { k0: splitmix(&mut s), k1: splitmix(&mut s), counter: 0 }
    }

    /// Folds `entropy` into the key.
    pub(crate) fn mix(&mut self, entropy: &[u8]) {
        for chunk in entropy.chunks(8) {
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            let w = u64::from_le_bytes(word) ^ (chunk.len() as u64) << 59;
            let (k0, k1) = (self.k0, self.k1);
            self.k0 = siphash(k0, k1, &[w, 0]);
            self.k1 = siphash(k1, k0, &[w, 1]);
        }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.counter = self.counter.wrapping_add(1);
        siphash(self.k0, self.k1, &[self.counter])
    }

    pub(crate) fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// A port in the IANA dynamic range, 49152..=65535.
    pub(crate) fn ephemeral_port(&mut self) -> u16 {
        49152 + (self.next_u32() % 16384) as u16
    }

    /// An initial sequence number for the connection `local` to `remote`
    /// (RFC 6528): a keyed hash of the four-tuple plus a clock that ticks
    /// every 4 microseconds, here every 250 per millisecond.
    pub(crate) fn isn(&self, local: SocketAddr, remote: SocketAddr, now: Instant) -> u32 {
        // An IPv4 address is hashed as one word and an IPv6 address as two.
        let mut words = [0; 6];
        let mut n = 0;
        for ip in [local.ip(), remote.ip()] {
            match ip {
                IpAddr::V4(a) => {
                    words[n] = u64::from(u32::from(a));
                    n += 1;
                }
                IpAddr::V6(a) => {
                    let v = u128::from(a);
                    words[n] = (v >> 64) as u64;
                    words[n + 1] = v as u64;
                    n += 2;
                }
            }
        }
        words[n] = u64::from(local.port()) << 16 | u64::from(remote.port());
        let hash = siphash(self.k1, self.k0, &words[..=n]) as u32;
        hash.wrapping_add((now.as_millis() as u32).wrapping_mul(250))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_and_entropy_change_the_stream() {
        let (mut a, mut b, mut c) = (Rng::new(1), Rng::new(1), Rng::new(2));
        assert_eq!(a.next_u32(), b.next_u32());
        assert_ne!(a.next_u32(), c.next_u32());
        b.mix(b"entropy");
        assert_ne!(a.next_u64(), b.next_u64());
        let (l, r) = (SocketAddr::new([10, 0, 0, 1].into(), 1000), SocketAddr::new([10, 0, 0, 2].into(), 80));
        let t = Instant::ZERO;
        assert_ne!(a.isn(l, r, t), a.isn(r, l, t), "tuple dependent");
        assert_ne!(a.isn(l, r, t), c.isn(l, r, t), "key dependent");
        assert_eq!(a.isn(l, r, Instant::from_millis(4)).wrapping_sub(a.isn(l, r, t)), 1000, "clock driven");
    }

    #[test]
    fn ports_stay_in_range() {
        let mut r = Rng::new(0);
        for _ in 0..1000 {
            assert!(r.ephemeral_port() >= 49152);
        }
    }
}
