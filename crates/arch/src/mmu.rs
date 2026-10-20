//! TLB maintenance for the current CPU's active translation regime.
//!
//! Installing a root table is architecture specific; see `x86_64::write_cr3`,
//! `aarch64::write_ttbr0_el1` and `riscv64::write_satp`.

pub use imp::{flush_all, flush_page};

#[cfg(all(bare, target_arch = "x86_64"))]
mod imp {
    use core::arch::asm;

    /// Invalidates the TLB entry for the page containing `va`.
    #[inline]
    pub fn flush_page(va: usize) {
        // SAFETY: invlpg only drops a cached translation.
        unsafe { asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags)) }
    }

    /// Invalidates all non-global TLB entries by reloading CR3.
    pub fn flush_all() {
        // SAFETY: rewriting CR3 with its own value keeps the same address space.
        unsafe { crate::x86_64::write_cr3(crate::x86_64::read_cr3()) }
    }
}

#[cfg(all(bare, target_arch = "aarch64"))]
mod imp {
    use core::arch::asm;

    /// The `tlbi` operand's VA field, bits 43:0 (VA[55:12]); the bits above
    /// are the ASID or TTL, which a sign-extended kernel VA must not set.
    const VA_FIELD: usize = (1 << 44) - 1;

    /// Invalidates the TLB entries for the page containing `va`, all ASIDs, inner shareable.
    #[inline]
    pub fn flush_page(va: usize) {
        // SAFETY: TLB maintenance only drops cached translations.
        #[cfg(not(feature = "aarch64-el2"))]
        unsafe {
            asm!("dsb ishst", "tlbi vaae1is, {}", "dsb ish", "isb", in(reg) (va >> 12) & VA_FIELD, options(nostack, preserves_flags))
        };
        // SAFETY: as above, for the EL2 regime.
        #[cfg(feature = "aarch64-el2")]
        unsafe {
            asm!("dsb ishst", "tlbi vae2is, {}", "dsb ish", "isb", in(reg) (va >> 12) & VA_FIELD, options(nostack, preserves_flags))
        };
    }

    /// Invalidates all TLB entries for the current regime, inner shareable.
    pub fn flush_all() {
        // SAFETY: TLB maintenance only drops cached translations.
        #[cfg(not(feature = "aarch64-el2"))]
        unsafe {
            asm!("dsb ishst", "tlbi vmalle1is", "dsb ish", "isb", options(nostack, preserves_flags))
        };
        // SAFETY: as above, for the EL2 regime.
        #[cfg(feature = "aarch64-el2")]
        unsafe {
            asm!("dsb ishst", "tlbi alle2is", "dsb ish", "isb", options(nostack, preserves_flags))
        };
    }
}

#[cfg(all(bare, target_arch = "riscv64"))]
mod imp {
    use core::arch::asm;

    /// Orders page-table writes and invalidates the translation for `va`.
    #[inline]
    pub fn flush_page(va: usize) {
        // SAFETY: sfence.vma only drops cached translations.
        unsafe { asm!("sfence.vma {}, zero", in(reg) va, options(nostack, preserves_flags)) }
    }

    /// Orders page-table writes and invalidates all translations.
    pub fn flush_all() {
        // SAFETY: sfence.vma only drops cached translations.
        unsafe { asm!("sfence.vma", options(nostack, preserves_flags)) }
    }
}

#[cfg(not(bare))]
mod imp {
    /// No-op on the host.
    pub fn flush_page(_va: usize) {}

    /// No-op on the host.
    pub fn flush_all() {}
}
