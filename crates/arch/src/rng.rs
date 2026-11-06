// SPDX-License-Identifier: GPL-2.0-only
//! Hardware random numbers.
//!
//! | Architecture | [`random`] | [`seed`] | Detected by |
//! |---|---|---|---|
//! | x86_64 | `RDRAND` | `RDSEED` | CPUID |
//! | AArch64 | `RNDR` | `RNDRRS` | `ID_AA64ISAR0_EL1.RNDR` |
//! | RISC-V | `seed` CSR (Zkr) | `seed` CSR (Zkr) | `assume_seed_csr` |
//! | host | `/dev/urandom` | `/dev/urandom` | always present |
//!
//! [`random`] reads the CPU's own random number generator, which hardware
//! reseeds from its entropy source. [`seed`] reads closer to the entropy
//! source and is meant for seeding a software generator; it is slower and
//! fails more often under load. Neither output should be used directly as key
//! material: condition it first, as `osmium-rand` does.
//!
//! Both return `None` when the CPU has no random number instructions or the
//! hardware keeps failing. Callers should treat that as "no entropy now", not
//! as a reason to fall back to something predictable.

pub use imp::{available, random, seed};

#[cfg(target_arch = "riscv64")]
pub use imp::assume_seed_csr;

#[cfg(all(bare, target_arch = "x86_64"))]
mod imp {
    use core::arch::asm;
    use core::sync::atomic::{AtomicU8, Ordering};

    const UNKNOWN: u8 = 0;
    const RDRAND: u8 = 1 << 0;
    const RDSEED: u8 = 1 << 1;
    const PROBED: u8 = 1 << 7;

    static FEATURES: AtomicU8 = AtomicU8::new(UNKNOWN);

    /// CPUID once, then cached: in a guest every CPUID is a VM exit.
    fn features() -> u8 {
        let f = FEATURES.load(Ordering::Relaxed);
        if f != UNKNOWN {
            return f;
        }
        let mut f = PROBED;
        if crate::x86_64::cpuid(1, 0).ecx & (1 << 30) != 0 {
            f |= RDRAND;
        }
        if crate::x86_64::cpuid(0, 0).eax >= 7 && crate::x86_64::cpuid(7, 0).ebx & (1 << 18) != 0 {
            f |= RDSEED;
        }
        FEATURES.store(f, Ordering::Relaxed);
        f
    }

    /// Whether the CPU has `RDRAND`.
    pub fn available() -> bool {
        features() & RDRAND != 0
    }

    /// 64 bits from `RDRAND`, retried ten times as Intel recommends.
    pub fn random() -> Option<u64> {
        if features() & RDRAND == 0 {
            return None;
        }
        for _ in 0..10 {
            let (v, ok): (u64, u8);
            // SAFETY: CPUID says RDRAND exists; it only writes the named register and CF.
            unsafe { asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack)) }
            // Some AMD parts return all ones with CF set after a suspend; Linux treats that as a failure too.
            if ok != 0 && v != u64::MAX {
                return Some(v);
            }
        }
        None
    }

    /// 64 bits from `RDSEED`, or from [`random`] on CPUs without it.
    pub fn seed() -> Option<u64> {
        if features() & RDSEED == 0 {
            return random();
        }
        for _ in 0..100 {
            let (v, ok): (u64, u8);
            // SAFETY: CPUID says RDSEED exists; it only writes the named register and CF.
            unsafe { asm!("rdseed {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok, options(nomem, nostack)) }
            if ok != 0 && v != u64::MAX {
                return Some(v);
            }
            core::hint::spin_loop();
        }
        None
    }
}

#[cfg(all(bare, target_arch = "aarch64"))]
mod imp {
    use core::arch::asm;
    use core::sync::atomic::{AtomicU8, Ordering};

    const UNKNOWN: u8 = 0;
    const ABSENT: u8 = 1;
    const PRESENT: u8 = 2;

    static RNDR: AtomicU8 = AtomicU8::new(UNKNOWN);

    /// Whether the CPU implements FEAT_RNG (`ID_AA64ISAR0_EL1.RNDR` ≥ 1).
    pub fn available() -> bool {
        match RNDR.load(Ordering::Relaxed) {
            UNKNOWN => {
                let isar0: u64;
                // SAFETY: reading an ID register has no side effects.
                unsafe { asm!("mrs {}, id_aa64isar0_el1", out(reg) isar0, options(nomem, nostack, preserves_flags)) }
                let present = (isar0 >> 60) & 0xf != 0;
                RNDR.store(if present { PRESENT } else { ABSENT }, Ordering::Relaxed);
                present
            }
            v => v == PRESENT,
        }
    }

    /// 64 bits from `RNDR`.
    pub fn random() -> Option<u64> {
        if !available() {
            return None;
        }
        for _ in 0..10 {
            let (v, ok): (u64, u64);
            // SAFETY: FEAT_RNG is present. RNDR (s3_3_c2_c4_0) writes the register and NZCV; Z set means failure.
            unsafe {
                asm!("mrs {v}, s3_3_c2_c4_0", "cset {ok}, ne", v = out(reg) v, ok = out(reg) ok, options(nomem, nostack))
            }
            if ok != 0 {
                return Some(v);
            }
        }
        None
    }

    /// 64 bits from `RNDRRS`, which reseeds the generator before reading.
    pub fn seed() -> Option<u64> {
        if !available() {
            return None;
        }
        for _ in 0..100 {
            let (v, ok): (u64, u64);
            // SAFETY: as in `random`; RNDRRS is s3_3_c2_c4_1.
            unsafe {
                asm!("mrs {v}, s3_3_c2_c4_1", "cset {ok}, ne", v = out(reg) v, ok = out(reg) ok, options(nomem, nostack))
            }
            if ok != 0 {
                return Some(v);
            }
            core::hint::spin_loop();
        }
        None
    }
}

#[cfg(all(bare, target_arch = "riscv64"))]
mod imp {
    use core::arch::asm;
    use core::sync::atomic::{AtomicBool, Ordering};

    static SEED_CSR: AtomicBool = AtomicBool::new(false);

    /// Declares that this hart can read the Zkr `seed` CSR.
    ///
    /// The CSR can't be probed: reading it where it is absent, or from
    /// S-mode when M-mode hasn't set `mseccfg.SSEED`, raises an
    /// illegal-instruction exception. Call this once the ISA string
    /// (devicetree `riscv,isa-extensions` containing `zkr`) and the firmware
    /// say it is usable.
    ///
    /// # Safety
    /// Every hart that calls [`random`] or [`seed`] afterwards must be able to
    /// read `seed` at its current privilege level.
    pub unsafe fn assume_seed_csr() {
        SEED_CSR.store(true, Ordering::Relaxed);
    }

    /// Whether [`assume_seed_csr`] has been called.
    pub fn available() -> bool {
        SEED_CSR.load(Ordering::Relaxed)
    }

    /// One 16-bit `ES16` sample, waiting through `BIST` and `WAIT`.
    fn sample() -> Option<u16> {
        for _ in 0..10_000 {
            let v: usize;
            // SAFETY: `assume_seed_csr`'s contract. The spec requires a write
            // (csrrw), not csrr; the written value is ignored.
            unsafe { asm!("csrrw {}, 0x015, zero", out(reg) v, options(nomem, nostack, preserves_flags)) }
            match (v >> 30) & 0b11 {
                0b10 => return Some(v as u16), // ES16
                0b11 => return None,           // DEAD
                _ => core::hint::spin_loop(),  // BIST or WAIT
            }
        }
        None
    }

    /// 64 bits made of four `seed` samples.
    ///
    /// These are raw entropy-source bits, not generator output: Zkr requires
    /// them to be conditioned before use.
    pub fn seed() -> Option<u64> {
        if !available() {
            return None;
        }
        let mut v = 0u64;
        for _ in 0..4 {
            v = v << 16 | u64::from(sample()?);
        }
        Some(v)
    }

    /// The same as [`seed`]: Zkr has no generator of its own.
    pub fn random() -> Option<u64> {
        seed()
    }
}

#[cfg(all(bare, not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))))]
mod imp {
    /// No random number instructions on this architecture.
    pub fn available() -> bool {
        false
    }

    /// Always `None`.
    pub fn random() -> Option<u64> {
        None
    }

    /// Always `None`.
    pub fn seed() -> Option<u64> {
        None
    }
}

#[cfg(not(bare))]
mod imp {
    use std::io::Read;

    /// Always true on the host.
    pub fn available() -> bool {
        true
    }

    /// 64 bits from `/dev/urandom`.
    pub fn random() -> Option<u64> {
        let mut b = [0u8; 8];
        std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).ok()?;
        Some(u64::from_ne_bytes(b))
    }

    /// The same as [`random`].
    pub fn seed() -> Option<u64> {
        random()
    }

    /// Does nothing on the host.
    ///
    /// # Safety
    /// None; kept so RISC-V code compiles unchanged under host simulation.
    #[cfg(target_arch = "riscv64")]
    pub unsafe fn assume_seed_csr() {}
}

#[cfg(all(test, not(bare)))]
mod tests {
    #[test]
    fn host_simulation_returns_varying_values() {
        assert!(super::available());
        let a = super::random().expect("urandom");
        let b = super::seed().expect("urandom");
        let c = super::random().expect("urandom");
        // Three equal 64-bit draws would mean the source is broken.
        assert!(!(a == b && b == c));
    }
}
