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
    }
    Ok(())
}

/// Enters the guest and returns at its next `#VMEXIT`.
pub(super) fn run(v: &mut SvmVcpu) {
    let flags: u64;
    // SAFETY: reads RFLAGS.
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem, preserves_flags)) };
    let if_on = flags & (1 << 9) != 0;
    // SAFETY: CLGI holds host interrupts during the switch; with
    // V_INTR_MASKING the host's IF then decides whether physical interrupts
    // exit the guest. The assembly preserves every callee-saved register.
    unsafe {
        asm!("clgi", options(nomem, nostack));
        if if_on {
            asm!("sti", options(nomem, nostack));
        }
        // The state VMRUN does not switch: FS, GS, TR, LDTR, KernelGsBase
        // and the syscall MSRs.
        asm!("vmsave rax", in("rax") v.host_pa, options(nostack));
        asm!("vmload rax", in("rax") v.vmcb_pa, options(nostack));
        osmium_svm_run(&mut v.regs, v.vmcb_pa);
        asm!("vmsave rax", in("rax") v.vmcb_pa, options(nostack));
        asm!("vmload rax", in("rax") v.host_pa, options(nostack));
        asm!("cli", "stgi", options(nomem, nostack));
        if if_on {
            asm!("sti", options(nomem, nostack));
        }
    }
}
