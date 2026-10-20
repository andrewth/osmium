//! CPU identity, idling and the monotonic counter.

pub use imp::{current_id, set_current_id, ticks, wait_for_interrupt};

/// Tells the CPU it is in a spin-wait loop.
#[inline]
pub fn spin_hint() {
    core::hint::spin_loop();
}

/// Disables interrupts and stops this CPU for good.
pub fn halt_forever() -> ! {
    crate::irq::disable();
    loop {
        wait_for_interrupt();
    }
}

#[cfg(all(bare, target_arch = "x86_64"))]
mod imp {
    use core::arch::asm;

    /// Returns the id that [`set_current_id`] stored for this CPU (0 until set).
    ///
    /// Reads `IA32_TSC_AUX` through `rdtscp`, as Linux does for `getcpu`.
    #[inline]
    pub fn current_id() -> usize {
        let aux: u32;
        // SAFETY: rdtscp has no side effects beyond writing the named registers.
        unsafe { asm!("rdtscp", out("eax") _, out("edx") _, out("ecx") aux, options(nomem, nostack, preserves_flags)) }
        aux as usize
    }

    /// Records `id` as this CPU's id.
    ///
    /// # Safety
    /// Ids must be unique across CPUs and below [`crate::MAX_CPUS`]; per-CPU
    /// data structures index arrays with them. The CPU must support `rdtscp`.
    pub unsafe fn set_current_id(id: usize) {
        // SAFETY: the caller upholds the contract; IA32_TSC_AUX holds no other state we use.
        unsafe { crate::x86_64::wrmsr(crate::x86_64::msr::IA32_TSC_AUX, id as u64) }
    }

    /// Halts until the next interrupt.
    #[inline]
    pub fn wait_for_interrupt() {
        // SAFETY: hlt only idles the CPU.
        unsafe { asm!("hlt", options(nomem, nostack, preserves_flags)) }
    }

    /// Reads the time-stamp counter.
    #[inline]
    pub fn ticks() -> u64 {
        let (lo, hi): (u32, u32);
        // SAFETY: rdtsc only reads the counter.
        unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) }
        (hi as u64) << 32 | lo as u64
    }
}

#[cfg(all(bare, target_arch = "aarch64"))]
mod imp {
    use core::arch::asm;

    /// Returns the id that [`set_current_id`] stored for this CPU (0 until set).
    #[inline]
    pub fn current_id() -> usize {
        let id: usize;
        // SAFETY: reads the software thread-id register.
        #[cfg(not(feature = "aarch64-el2"))]
        unsafe {
            asm!("mrs {}, tpidr_el1", out(reg) id, options(nomem, nostack, preserves_flags))
        };
        // SAFETY: as above, at EL2.
        #[cfg(feature = "aarch64-el2")]
        unsafe {
            asm!("mrs {}, tpidr_el2", out(reg) id, options(nomem, nostack, preserves_flags))
        };
        id
    }

    /// Records `id` as this CPU's id in `TPIDR_EL1` (`TPIDR_EL2` with `aarch64-el2`).
    ///
    /// # Safety
    /// Ids must be unique across CPUs and below [`crate::MAX_CPUS`].
    pub unsafe fn set_current_id(id: usize) {
        // SAFETY: the caller upholds the contract.
        #[cfg(not(feature = "aarch64-el2"))]
        unsafe {
            asm!("msr tpidr_el1, {}", in(reg) id, options(nomem, nostack, preserves_flags))
        };
        // SAFETY: the caller upholds the contract.
        #[cfg(feature = "aarch64-el2")]
        unsafe {
            asm!("msr tpidr_el2, {}", in(reg) id, options(nomem, nostack, preserves_flags))
        };
    }

    /// Waits for the next interrupt.
    #[inline]
    pub fn wait_for_interrupt() {
        // SAFETY: wfi only idles the CPU.
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) }
    }

    /// Reads the virtual counter (`CNTVCT_EL0`).
    #[inline]
    pub fn ticks() -> u64 {
        let t: u64;
        // SAFETY: reads the generic timer's counter.
        unsafe { asm!("isb", "mrs {}, cntvct_el0", out(reg) t, options(nomem, nostack, preserves_flags)) }
        t
    }
}

#[cfg(all(bare, target_arch = "riscv64"))]
mod imp {
    use core::arch::asm;

    /// Returns the id that [`set_current_id`] stored for this CPU (0 until set).
    ///
    /// Kept in the `tp` register, which freestanding Rust code does not use.
    #[inline]
    pub fn current_id() -> usize {
        let id: usize;
        // SAFETY: reads tp.
        unsafe { asm!("mv {}, tp", out(reg) id, options(nomem, nostack, preserves_flags)) }
        id
    }

    /// Records `id` as this CPU's id in `tp`.
    ///
    /// # Safety
    /// Ids must be unique across CPUs and below [`crate::MAX_CPUS`]. Trap
    /// handlers must preserve `tp`.
    pub unsafe fn set_current_id(id: usize) {
        // SAFETY: the caller upholds the contract.
        unsafe { asm!("mv tp, {}", in(reg) id, options(nomem, nostack, preserves_flags)) }
    }

    /// Waits for the next interrupt.
    #[inline]
    pub fn wait_for_interrupt() {
        // SAFETY: wfi only idles the hart.
        unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) }
    }

    /// Reads the `time` CSR.
    #[inline]
    pub fn ticks() -> u64 {
        let t: u64;
        // SAFETY: reads the time counter.
        unsafe { asm!("rdtime {}", out(reg) t, options(nomem, nostack, preserves_flags)) }
        t
    }
}

#[cfg(not(bare))]
mod imp {
    use core::cell::Cell;
    use std::sync::OnceLock;
    use std::time::Instant;

    std::thread_local! {
        static ID: Cell<usize> = const { Cell::new(0) };
    }

    /// Returns this thread's simulated CPU id (0 until set).
    pub fn current_id() -> usize {
        ID.with(|c| c.get())
    }

    /// Sets this thread's simulated CPU id.
    ///
    /// # Safety
    /// Ids must be unique among threads that use per-CPU data concurrently,
    /// and below [`crate::MAX_CPUS`].
    pub unsafe fn set_current_id(id: usize) {
        ID.with(|c| c.set(id));
    }

    /// Yields the host thread.
    pub fn wait_for_interrupt() {
        std::thread::yield_now();
    }

    /// Nanoseconds since the first call.
    pub fn ticks() -> u64 {
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_nanos() as u64
    }
}
