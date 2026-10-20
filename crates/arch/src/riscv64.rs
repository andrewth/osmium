//! RISC-V 64 CSRs, `satp` encoding and the Supervisor Binary Interface.

use core::arch::asm;

macro_rules! csr {
    ($read:ident, $write:ident, $csr:literal) => {
        #[doc = concat!("Reads `", $csr, "`.")]
        #[inline]
        pub fn $read() -> usize {
            let v: usize;
            // SAFETY: reading a CSR has no side effects.
            unsafe { asm!(concat!("csrr {}, ", $csr), out(reg) v, options(nomem, nostack, preserves_flags)) }
            v
        }

        #[doc = concat!("Writes `", $csr, "`.")]
        ///
        /// # Safety
        /// The CSR controls traps or translation; the new value must keep the
        /// running code correct.
        #[inline]
        pub unsafe fn $write(v: usize) {
            // SAFETY: the caller upholds the contract.
            unsafe { asm!(concat!("csrw ", $csr, ", {}"), in(reg) v, options(nostack, preserves_flags)) }
        }
    };
}

csr!(read_satp, write_satp_raw, "satp");
csr!(read_sstatus, write_sstatus, "sstatus");
csr!(read_sie, write_sie, "sie");
csr!(read_sip, write_sip, "sip");
csr!(read_stvec, write_stvec, "stvec");
csr!(read_sscratch, write_sscratch, "sscratch");
csr!(read_sepc, write_sepc, "sepc");
csr!(read_scause, write_scause, "scause");
csr!(read_stval, write_stval, "stval");

/// Translation mode field of `satp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SatpMode {
    /// No translation.
    Bare = 0,
    /// Three-level, 39-bit virtual addresses.
    Sv39 = 8,
    /// Four-level, 48-bit virtual addresses.
    Sv48 = 9,
}

/// Encodes a `satp` value.
pub const fn satp(mode: SatpMode, asid: u16, root_pa: u64) -> usize {
    ((mode as usize) << 60) | ((asid as usize) << 44) | (root_pa as usize >> 12)
}

/// Installs a root page table and flushes the TLB.
///
/// # Safety
/// The table at `root_pa` must map the currently executing code and stack.
pub unsafe fn write_satp(mode: SatpMode, asid: u16, root_pa: u64) {
    // SAFETY: the caller upholds the contract.
    unsafe {
        asm!("sfence.vma", "csrw satp, {}", "sfence.vma", in(reg) satp(mode, asid, root_pa), options(nostack))
    }
}

/// `sie`/`sip` bit for supervisor software interrupts.
pub const SIE_SSIE: usize = 1 << 1;
/// `sie`/`sip` bit for supervisor timer interrupts.
pub const SIE_STIE: usize = 1 << 5;
/// `sie`/`sip` bit for supervisor external interrupts.
pub const SIE_SEIE: usize = 1 << 9;

/// Supervisor Binary Interface calls into M-mode firmware (OpenSBI, RustSBI).
pub mod sbi {
    use core::arch::asm;

    /// An SBI error code.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SbiError(pub isize);

    /// Performs a raw SBI call.
    ///
    /// # Safety
    /// Some SBI calls start or stop harts or change machine state.
    pub unsafe fn call(eid: usize, fid: usize, args: [usize; 3]) -> Result<usize, SbiError> {
        let (err, val): (isize, usize);
        // SAFETY: ecall transfers to firmware, which follows the SBI calling convention.
        unsafe {
            asm!("ecall",
                inlateout("a0") args[0] => err, inlateout("a1") args[1] => val,
                in("a2") args[2], in("a6") fid, in("a7") eid, options(nostack))
        }
        if err == 0 { Ok(val) } else { Err(SbiError(err)) }
    }

    const EID_TIME: usize = 0x5449_4d45;
    const EID_HSM: usize = 0x0048_534d;
    const EID_SRST: usize = 0x5352_5354;
    const EID_IPI: usize = 0x0073_5049;
    const EID_LEGACY_PUTCHAR: usize = 0x01;

    /// Programs the next timer interrupt for absolute `time` value `deadline`.
    pub fn set_timer(deadline: u64) {
        // SAFETY: only arms this hart's timer.
        let _ = unsafe { call(EID_TIME, 0, [deadline as usize, 0, 0]) };
    }

    /// Writes a byte to the firmware console (legacy extension).
    pub fn console_putchar(c: u8) {
        // SAFETY: only writes to the firmware console.
        let _ = unsafe { call(EID_LEGACY_PUTCHAR, 0, [c as usize, 0, 0]) };
    }

    /// Starts `hartid` at physical address `start` with `opaque` in `a1`.
    ///
    /// # Safety
    /// `start` must be valid code that sets up its own stack.
    pub unsafe fn hart_start(hartid: usize, start: usize, opaque: usize) -> Result<(), SbiError> {
        // SAFETY: the caller upholds the contract.
        unsafe { call(EID_HSM, 0, [hartid, start, opaque]) }.map(|_| ())
    }

    /// Raises a supervisor software interrupt on each hart whose bit is set
    /// in `hart_mask` (bit 0 = hart `hart_mask_base`).
    pub fn send_ipi(hart_mask: usize, hart_mask_base: usize) -> Result<(), SbiError> {
        // SAFETY: only raises software interrupts.
        unsafe { call(EID_IPI, 0, [hart_mask, hart_mask_base, 0]) }.map(|_| ())
    }

    /// Shuts the system down.
    pub fn shutdown() -> ! {
        // SAFETY: system reset never returns on success.
        let _ = unsafe { call(EID_SRST, 0, [0, 0, 0]) };
        crate::cpu::halt_forever()
    }
}

/// `sstatus.SUM`: lets S-mode access user pages.
const SSTATUS_SUM: usize = 1 << 18;

/// Runs `f` with supervisor access to user pages enabled (`sstatus.SUM`),
/// for copying system-call buffers. Restores the previous setting.
pub fn with_user_access<R>(f: impl FnOnce() -> R) -> R {
    let was = read_sstatus() & SSTATUS_SUM;
    // SAFETY: SUM only widens what S-mode may access; restored below.
    unsafe { asm!("csrs sstatus, {}", in(reg) SSTATUS_SUM, options(nostack)) };
    let r = f();
    if was == 0 {
        // SAFETY: restores the previous setting.
        unsafe { asm!("csrc sstatus, {}", in(reg) SSTATUS_SUM, options(nostack)) };
    }
    r
}

/// Drops to user mode (U-mode) at `entry` with stack `user_sp` and
/// interrupts enabled. General-purpose registers are cleared. Does not
/// return: the next kernel entry is a trap, on the stack set with
/// `osmium_arch::trap::TrapCpu::set_kernel_stack`.
///
/// # Safety
/// `osmium_arch::trap::install` must have run on this CPU, the kernel stack
/// in its `TrapCpu` must be valid, and `entry`/`user_sp` must be mapped
/// user-accessible.
#[cfg(not(feature = "riscv-m-mode"))]
pub unsafe fn enter_user(entry: usize, user_sp: usize) -> ! {
    // SAFETY: the caller upholds the contract; sret switches to U-mode.
    unsafe {
        asm!(
            // Mask interrupts first: once sp is the user stack, a trap taken
            // in S-mode would try to save its frame there and fault forever.
            // SPIE re-enables them atomically at sret.
            "csrci sstatus, 0x2",
            // Consume both operands before clobbering any register.
            "csrw sepc, {entry}",
            "mv sp, {sp}",
            "li t0, 0x100",
            "csrc sstatus, t0", // SPP = U
            "li t0, 0x20",
            "csrs sstatus, t0", // SPIE: interrupts on after sret
            "li ra, 0", "li gp, 0", "li tp, 0", "li t0, 0", "li t1, 0", "li t2, 0",
            "li s0, 0", "li s1, 0", "li a0, 0", "li a1, 0", "li a2, 0", "li a3, 0",
            "li a4, 0", "li a5, 0", "li a6, 0", "li a7, 0", "li s2, 0", "li s3, 0",
            "li s4, 0", "li s5, 0", "li s6, 0", "li s7, 0", "li s8, 0", "li s9, 0",
            "li s10, 0", "li s11, 0", "li t3, 0", "li t4, 0", "li t5, 0", "li t6, 0",
            "sret",
            entry = in(reg) entry,
            sp = in(reg) user_sp,
            options(noreturn),
        )
    }
}
