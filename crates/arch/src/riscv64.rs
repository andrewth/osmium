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

    /// Shuts the system down.
    pub fn shutdown() -> ! {
        // SAFETY: system reset never returns on success.
        let _ = unsafe { call(EID_SRST, 0, [0, 0, 0]) };
        crate::cpu::halt_forever()
    }
}
