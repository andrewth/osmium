//! A small generator for TCP initial sequence numbers, DHCP transaction ids
//! and ephemeral ports.

/// xorshift64. Not cryptographic: callers that need unpredictable sequence
/// numbers should seed it from a hardware source.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) fn new(seed: u64) -> Self {
        // A zero state would stay zero.
        Self(if seed == 0 { 0x9e37_79b9_7f4a_7c15 } else { seed })
    }

    pub(crate) fn next_u32(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        (x >> 32) as u32
    }

    /// A port in the IANA dynamic range, 49152..=65535.
    pub(crate) fn ephemeral_port(&mut self) -> u16 {
        49152 + (self.next_u32() % 16384) as u16
    }
}
