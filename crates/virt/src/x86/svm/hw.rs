//! SVM enablement and the VMRUN world switch (bare-metal x86_64).
//!
//! `osmium_svm_run` saves the host's callee-saved registers on its stack,
//! loads the guest's general-purpose registers (except `rax` and `rsp`,
//! which VMRUN takes from the VMCB), executes VMRUN with `rax` = the VMCB's
//! physical address, and on `#VMEXIT` stores the guest's registers and
//! restores the host's. The hardware saves and restores the rest of the
//! host state in the host save area. GIF is cleared around the switch so
//! no host interrupt lands in the middle of it.

use core::arch::{asm, global_asm};
use core::mem::offset_of;

use osmium_arch::x86_64::{self as x86, msr};

use super::{EFER_SVME, GuestRegs, SvmVcpu};

global_asm!(
    r#"
    .section .text.osmium_svm, "ax"
    .globl osmium_svm_run
osmium_svm_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    mov rax, rsi
    mov rbx, [rdi + {rbx}]
    mov rcx, [rdi + {rcx}]
    mov rdx, [rdi + {rdx}]
    mov rsi, [rdi + {rsi}]
    mov rbp, [rdi + {rbp}]
    mov r8, [rdi + {r8}]
    mov r9, [rdi + {r9}]
    mov r10, [rdi + {r10}]
    mov r11, [rdi + {r11}]
    mov r12, [rdi + {r12}]
    mov r13, [rdi + {r13}]
    mov r14, [rdi + {r14}]
    mov r15, [rdi + {r15}]
    mov rdi, [rdi + {rdi}]
    vmrun rax
    push rdi
    mov rdi, [rsp + 8]
    mov [rdi + {rbx}], rbx
    mov [rdi + {rcx}], rcx
    mov [rdi + {rdx}], rdx
    mov [rdi + {rsi}], rsi
    mov [rdi + {rbp}], rbp
    mov [rdi + {r8}], r8
    mov [rdi + {r9}], r9
    mov [rdi + {r10}], r10
    mov [rdi + {r11}], r11
    mov [rdi + {r12}], r12
    mov [rdi + {r13}], r13
    mov [rdi + {r14}], r14
    mov [rdi + {r15}], r15
    pop qword ptr [rdi + {rdi}]
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
"#,
    rbx = const offset_of!(GuestRegs, rbx),
    rcx = const offset_of!(GuestRegs, rcx),
    rdx = const offset_of!(GuestRegs, rdx),
    rsi = const offset_of!(GuestRegs, rsi),
    rdi = const offset_of!(GuestRegs, rdi),
    rbp = const offset_of!(GuestRegs, rbp),
    r8 = const offset_of!(GuestRegs, r8),
    r9 = const offset_of!(GuestRegs, r9),
    r10 = const offset_of!(GuestRegs, r10),
    r11 = const offset_of!(GuestRegs, r11),
    r12 = const offset_of!(GuestRegs, r12),
    r13 = const offset_of!(GuestRegs, r13),
    r14 = const offset_of!(GuestRegs, r14),
    r15 = const offset_of!(GuestRegs, r15),
);

unsafe extern "C" {
    fn osmium_svm_run(regs: *mut GuestRegs, vmcb_pa: u64);
}

/// `VM_CR` MSR: SVMDIS (bit 4) set means firmware disabled SVM.
const VM_CR: u32 = 0xc001_0114;
/// `VM_HSAVE_PA` MSR: the host save area.
const VM_HSAVE_PA: u32 = 0xc001_0117;

/// Why SVM could not be enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvmError {
    /// The CPU does not implement SVM.
    Unsupported,
    /// The CPU has no nested paging.
    NoNestedPaging,
    /// Firmware disabled SVM (`VM_CR.SVMDIS`).
    Disabled,
}

/// Turns on SVM on this CPU with the 4 KiB host save area at physical
/// address `hsave_pa`. Call once per CPU before running a vCPU on it.
pub fn enable(hsave_pa: u64) -> Result<(), SvmError> {
    if !x86::has_svm() {
        return Err(SvmError::Unsupported);
    }
    if x86::cpuid(0x8000_000a, 0).edx & 1 == 0 {
        return Err(SvmError::NoNestedPaging);
    }
    // SAFETY: SVM is implemented, so these MSRs exist.
    unsafe {
        if x86::rdmsr(VM_CR) & (1 << 4) != 0 {
            return Err(SvmError::Disabled);
        }
        x86::wrmsr(msr::IA32_EFER, x86::rdmsr(msr::IA32_EFER) | EFER_SVME);
        x86::wrmsr(VM_HSAVE_PA, hsave_pa);
        // CR4.OSFXSR and OSXMMEXCPT: FXSAVE/FXRSTOR then switch the guests'
        // SSE registers too.
        asm!("mov {t}, cr4", "or {t}, 0x600", "mov cr4, {t}", t = out(reg) _, options(nomem, nostack));
    }
    Ok(())
}

/// The VMCB each CPU last ran. Every vCPU uses ASID 1, so a CPU that runs
/// a different VMCB than last time (another vCPU or a new VM in a reused
/// page) flushes the guest TLB first, and so does a vCPU that last ran on
/// another CPU (its local INVLPGs there never reached this one's TLB).
static LAST_VMCB: [core::sync::atomic::AtomicU64; osmium_arch::MAX_CPUS] =
    [const { core::sync::atomic::AtomicU64::new(0) }; osmium_arch::MAX_CPUS];

/// The host's debug registers, around a guest run.
struct HostDr {
    addr: [u64; 4],
    dr6: u64,
    dr7: u64,
}

impl HostDr {
    const ZERO: Self = Self { addr: [0; 4], dr6: 0, dr7: 0 };

    /// Reads DR0-DR3, DR6 and DR7.
    ///
    /// # Safety
    /// Ring 0.
    unsafe fn save() -> Self {
        let (mut a, mut d6, mut d7) = ([0u64; 4], 0u64, 0u64);
        // SAFETY: reading debug registers has no side effects.
        unsafe {
            asm!("mov {}, dr0", out(reg) a[0], options(nomem, nostack, preserves_flags));
            asm!("mov {}, dr1", out(reg) a[1], options(nomem, nostack, preserves_flags));
            asm!("mov {}, dr2", out(reg) a[2], options(nomem, nostack, preserves_flags));
            asm!("mov {}, dr3", out(reg) a[3], options(nomem, nostack, preserves_flags));
            asm!("mov {}, dr6", out(reg) d6, options(nomem, nostack, preserves_flags));
            asm!("mov {}, dr7", out(reg) d7, options(nomem, nostack, preserves_flags));
        }
        Self { addr: a, dr6: d6, dr7: d7 }
    }

    /// Writes DR0-DR3 from `self`.
    ///
    /// # Safety
    /// Ring 0, with no host breakpoint of DR7 depending on the old values.
    unsafe fn load_addresses(&self) {
        // SAFETY: the caller is ring 0.
        unsafe {
            asm!("mov dr0, {}", in(reg) self.addr[0], options(nomem, nostack, preserves_flags));
            asm!("mov dr1, {}", in(reg) self.addr[1], options(nomem, nostack, preserves_flags));
            asm!("mov dr2, {}", in(reg) self.addr[2], options(nomem, nostack, preserves_flags));
            asm!("mov dr3, {}", in(reg) self.addr[3], options(nomem, nostack, preserves_flags));
        }
    }

    /// Puts the host's debug registers back, DR7 last so no breakpoint is
    /// armed while the addresses are in flux (and idle first, since the
    /// guest's DR7 is live after the exit).
    ///
    /// # Safety
    /// Ring 0.
    unsafe fn restore(&self) {
        // SAFETY: the caller is ring 0.
        unsafe {
            asm!("mov dr7, {}", in(reg) 0x400u64, options(nomem, nostack, preserves_flags));
            self.load_addresses();
            asm!("mov dr6, {}", in(reg) self.dr6, options(nomem, nostack, preserves_flags));
            asm!("mov dr7, {}", in(reg) self.dr7, options(nomem, nostack, preserves_flags));
        }
    }
}

/// Enters the guest and returns at its next `#VMEXIT`.
pub(super) fn run(v: &mut SvmVcpu) {
    let cpu = osmium_arch::cpu::current_id();
    let last = LAST_VMCB[cpu].swap(v.vmcb_pa, core::sync::atomic::Ordering::Relaxed);
    let last_cpu = core::mem::replace(&mut v.last_cpu, cpu);
    if crate::vcpu::tlb_may_be_stale(last, v.vmcb_pa, last_cpu, cpu) {
        v.write32(super::vmcb::TLB_CONTROL, 1);
    }
    let flags: u64;
    // SAFETY: reads RFLAGS.
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem, preserves_flags)) };
    let if_on = flags & (1 << 9) != 0;
    // SAFETY: CLGI holds host interrupts during the switch; with
    // V_INTR_MASKING the host's IF then decides whether physical interrupts
    // exit the guest. The assembly preserves every callee-saved register.
    unsafe {
        asm!("clgi", options(nomem, nostack));
        // An INTR raised since the interrupt setup was sampled is looked at
        // again now that nothing can slip in between.
        v.resample_irq();
        if if_on {
            asm!("sti", options(nomem, nostack));
        }
        // The state VMRUN does not switch: FS, GS, TR, LDTR, KernelGsBase
        // and the syscall MSRs.
        asm!("vmsave rax", in("rax") v.host_pa, options(nostack));
        asm!("vmload rax", in("rax") v.vmcb_pa, options(nostack));
        // TSC_AUX (what RDTSCP and RDPID return) is not in the VMCB: swap
        // the guest's in while GIF is clear, so no host code sees it.
        let host_aux = x86::rdmsr(msr::IA32_TSC_AUX);
        // The guest's DR7 is loaded by VMRUN, but DR0-DR3 (whose accesses
        // are intercepted and read as zero) would still hold the host's
        // addresses: a spurious #DB, and a guest-visible hit on a host
        // address. Zero them for the run; the host's DR7 and DR6 are not
        // saved by VMRUN either.
        let host_dr = HostDr::save();
        asm!("mov dr7, {}", in(reg) 0x400u64, options(nomem, nostack, preserves_flags));
        HostDr::ZERO.load_addresses();
        x86::wrmsr(msr::IA32_TSC_AUX, v.tsc_aux);
        // x87 and SSE state, if the vCPU has its own: loaded for the run and
        // saved after it. The host itself never uses these registers
        // (soft-float).
        if v.switch_fp {
            asm!("fxrstor64 [{}]", in(reg) v.fpu.0.as_ptr(), options(nostack, readonly));
        }
        osmium_svm_run(&mut v.regs, v.vmcb_pa);
        if v.switch_fp {
            asm!("fxsave64 [{}]", in(reg) v.fpu.0.as_mut_ptr(), options(nostack));
        }
        x86::wrmsr(msr::IA32_TSC_AUX, host_aux);
        host_dr.restore();
        asm!("vmsave rax", in("rax") v.vmcb_pa, options(nostack));
        asm!("vmload rax", in("rax") v.host_pa, options(nostack));
        asm!("cli", "stgi", options(nomem, nostack));
        if if_on {
            asm!("sti", options(nomem, nostack));
        }
    }
}
