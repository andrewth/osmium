// SPDX-License-Identifier: GPL-2.0-only
//! Random numbers for kernels: entropy sources and a ChaCha20 generator.
//!
//! - [`EntropySource`]: something that produces unpredictable bytes, slowly.
//!   [`CpuEntropy`] reads the CPU's random number instructions through
//!   `osmium_arch::rng`.
//! - [`ChaChaRng`]: a deterministic generator built on the ChaCha20 block
//!   function with fast key erasure: every refill replaces the key with
//!   generator output, so a key captured later can't reproduce earlier output.
//!   It is seeded by hashing entropy with [`Sha256`], which also conditions
//!   raw entropy-source bits such as RISC-V Zkr samples.
//! - [`SharedRng`]: a [`ChaChaRng`] behind an interrupt-safe lock, for use as a
//!   kernel's single system generator. It reseeds itself from its source as it
//!   is used.
//!
//! Nothing here allocates.
#![no_std]

#[cfg(test)]
extern crate std;

mod chacha;
mod sha256;

use osmium_sync::IrqSpinLock;

pub use sha256::Sha256;

/// The entropy source couldn't produce enough bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntropyError;

impl core::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("entropy source failed")
    }
}

/// A source of unpredictable bytes, used to seed a generator.
pub trait EntropySource: Sync {
    /// Fills `out` entirely, or fails.
    fn fill(&self, out: &mut [u8]) -> Result<(), EntropyError>;
}

/// The CPU's random number instructions (see `osmium_arch::rng`).
#[derive(Clone, Copy, Debug, Default)]
pub struct CpuEntropy;

impl CpuEntropy {
    /// Whether the CPU has random number instructions that this source can use.
    pub fn available() -> bool {
        osmium_arch::rng::available()
    }
}

impl EntropySource for CpuEntropy {
    fn fill(&self, out: &mut [u8]) -> Result<(), EntropyError> {
        for chunk in out.chunks_mut(8) {
            let mut v = osmium_arch::rng::seed().ok_or(EntropyError)?.to_le_bytes();
            for (d, s) in chunk.iter_mut().zip(v) {
                *d = s;
            }
            wipe(&mut v);
        }
        Ok(())
    }
}

/// Bytes of entropy read per seeding: twice the key size, so a source with
/// only half a bit of entropy per output bit still yields a full-strength key.
pub const SEED_LEN: usize = 64;

const BLOCKS: usize = 4;
const OUT_LEN: usize = 64 * BLOCKS - 32;

const SEED_DOMAIN: &[u8] = b"osmium-rand seed v1";
const RESEED_DOMAIN: &[u8] = b"osmium-rand reseed v1";

/// A ChaCha20 generator with fast key erasure.
///
/// Each refill runs ChaCha20 under the current key for four blocks: the first
/// 32 bytes become the next key and the other 224 are handed out, and each
/// byte is wiped from the buffer as it is handed out.
pub struct ChaChaRng {
    key: [u32; 8],
    buf: [u8; OUT_LEN],
    pos: usize,
}

impl ChaChaRng {
    /// A generator seeded from [`SEED_LEN`] bytes of `source`.
    pub fn new(source: &dyn EntropySource) -> Result<Self, EntropyError> {
        let mut seed = [0u8; SEED_LEN];
        source.fill(&mut seed)?;
        let mut h = Sha256::new();
        h.update(SEED_DOMAIN);
        h.update(&seed);
        wipe(&mut seed);
        let mut key = h.finish();
        let rng = Self::from_key(&key);
        wipe(&mut key);
        Ok(rng)
    }

    /// A generator whose output is fixed by `seed`, for tests and for
    /// reproducible runs. Never use a predictable seed for secrets.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut seed = seed;
        let rng = Self::from_key(&seed);
        wipe(&mut seed);
        rng
    }

    fn from_key(key: &[u8; 32]) -> Self {
        Self { key: chacha::key_words(key), buf: [0; OUT_LEN], pos: OUT_LEN }
    }

    /// Mixes [`SEED_LEN`] fresh bytes from `source` into the key. On failure
    /// the generator is unchanged and still safe to use.
    pub fn reseed(&mut self, source: &dyn EntropySource) -> Result<(), EntropyError> {
        let mut seed = [0u8; SEED_LEN];
        source.fill(&mut seed)?;
        let mut old = [0u8; 32];
        for (o, k) in old.as_chunks_mut::<4>().0.iter_mut().zip(self.key) {
            *o = k.to_le_bytes();
        }
        let mut h = Sha256::new();
        h.update(RESEED_DOMAIN);
        h.update(&old);
        h.update(&seed);
        wipe(&mut seed);
        wipe(&mut old);
        let mut key = h.finish();
        self.key = chacha::key_words(&key);
        wipe(&mut key);
        // Output buffered under the old key must not be handed out any more.
        wipe(&mut self.buf);
        self.pos = OUT_LEN;
        Ok(())
    }

    fn refill(&mut self) {
        let mut block = [0u8; 64];
        let mut next = [0u8; 32];
        let mut dst = self.buf.as_mut_slice();
        for i in 0..BLOCKS {
            chacha::block(&self.key, i as u32, &[0; 3], &mut block);
            let mut src = block.as_slice();
            if i == 0 {
                let (k, rest) = src.split_at(32);
                next.copy_from_slice(k);
                src = rest;
            }
            let (d, rest) = dst.split_at_mut(src.len());
            d.copy_from_slice(src);
            dst = rest;
        }
        self.key = chacha::key_words(&next);
        self.pos = 0;
        wipe(&mut block);
        wipe(&mut next);
    }

    /// Fills `out` with generator output.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut out = out;
        while !out.is_empty() {
            if self.pos == OUT_LEN {
                self.refill();
            }
            let take = (OUT_LEN - self.pos).min(out.len());
            let (dst, rest) = out.split_at_mut(take);
            if let Some(src) = self.buf.get_mut(self.pos..self.pos + take) {
                dst.copy_from_slice(src);
                wipe(src);
            }
            self.pos += take;
            out = rest;
        }
    }

    /// A random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }
}

impl Drop for ChaChaRng {
    fn drop(&mut self) {
        wipe_words(&mut self.key);
        wipe(&mut self.buf);
    }
}

/// [`SharedRng::fill`] was called before [`SharedRng::seed`] succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotSeeded;

impl core::fmt::Display for NotSeeded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("random number generator not seeded")
    }
}

/// Output bytes between automatic reseeds.
pub const RESEED_INTERVAL: usize = 1 << 20;

struct Shared {
    rng: Option<ChaChaRng>,
    source: Option<&'static dyn EntropySource>,
    since_reseed: usize,
}

/// A kernel-wide generator, safe to use from any CPU and from interrupt
/// handlers.
///
/// It refuses to produce output until it has been seeded. Afterwards it
/// reseeds from the same source every [`RESEED_INTERVAL`] bytes; if a reseed
/// fails it keeps going on its current key, which is still secure, and tries
/// again at the next interval.
pub struct SharedRng {
    inner: IrqSpinLock<Shared>,
}

impl Default for SharedRng {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedRng {
    /// An unseeded generator, for a `static`.
    pub const fn new() -> Self {
        Self { inner: IrqSpinLock::new(Shared { rng: None, source: None, since_reseed: 0 }) }
    }

    /// Seeds the generator from `source`, which it keeps for later reseeds. If
    /// it was already seeded, `source`'s bytes are mixed into the existing key.
    pub fn seed(&self, source: &'static dyn EntropySource) -> Result<(), EntropyError> {
        let mut s = self.inner.lock();
        match &mut s.rng {
            Some(rng) => rng.reseed(source)?,
            None => s.rng = Some(ChaChaRng::new(source)?),
        }
        s.source = Some(source);
        s.since_reseed = 0;
        Ok(())
    }

    /// Whether [`seed`](Self::seed) has succeeded.
    pub fn is_seeded(&self) -> bool {
        self.inner.lock().rng.is_some()
    }

    /// Fills `out`. The lock is dropped between chunks, so a long request
    /// doesn't keep interrupts masked for its whole length.
    pub fn fill(&self, out: &mut [u8]) -> Result<(), NotSeeded> {
        for chunk in out.chunks_mut(OUT_LEN) {
            let mut s = self.inner.lock();
            let Shared { rng, source, since_reseed } = &mut *s;
            let rng = rng.as_mut().ok_or(NotSeeded)?;
            if *since_reseed >= RESEED_INTERVAL {
                if let Some(src) = source {
                    // A failed reseed leaves the key as it was; retry at the next interval.
                    let _ = rng.reseed(*src);
                }
                *since_reseed = 0;
            }
            rng.fill(chunk);
            *since_reseed += chunk.len();
        }
        Ok(())
    }

    /// A random `u64`.
    pub fn next_u64(&self) -> Result<u64, NotSeeded> {
        let mut b = [0u8; 8];
        self.fill(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
}

/// Zeroes `buf` in a way the compiler won't remove as a dead store.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

fn wipe_words(buf: &mut [u32]) {
    for w in buf.iter_mut() {
        // SAFETY: `w` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests;
