//! VMX enablement and the VMLAUNCH/VMRESUME world switch (bare-metal x86_64).
//!
//! `osmium_vmx_run` saves the host's callee-saved registers on its stack,
//! records its stack pointer as the VMCS host `RSP`, loads the guest's
//! general-purpose registers, and executes VMLAUNCH or VMRESUME. On a VM
//! exit the CPU lands in `osmium_vmx_exit` with that stack pointer; it stores
//! the guest's registers and restores the host's. Host interrupts are off
//! from before the entry until the exit has been handled.

use core::arch::{asm, global_asm};
use core::mem::offset_of;
use core::sync::atomic::{AtomicU64, Ordering};

use osmium_arch::x86_64::{self as x86, msr};
use osmium_sync::Once;

use super::caps::{Caps, VmxError};
use super::{HOST_LIST, SWITCHED, VmxRegs, VmxVcpu, exit, vmcs};

global_asm!(
    r#"
    .section .text.osmium_vmx, "ax"
    .globl osmium_vmx_run
osmium_vmx_run:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    mov eax, {host_rsp}
    vmwrite rax, rsp
    test rsi, rsi
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
    mov rax, [rdi + {rax}]
    mov rdi, [rdi + {rdi}]
    jnz 1f
    vmlaunch
    jmp 2f
1:  vmresume
2:  // Falling through means the instruction failed.
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    mov eax, 1
    ret

    .globl osmium_vmx_exit
osmium_vmx_exit:
    xchg rdi, [rsp]
    mov [rdi + {rax}], rax
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
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    xor eax, eax
    ret
"#,
    host_rsp = const vmcs::HOST_RSP,
    rax = const offset_of!(VmxRegs, rax),
    rbx = const offset_of!(VmxRegs, rbx),
    rcx = const offset_of!(VmxRegs, rcx),
    rdx = const offset_of!(VmxRegs, rdx),
    rsi = const offset_of!(VmxRegs, rsi),
    rdi = const offset_of!(VmxRegs, rdi),
    rbp = const offset_of!(VmxRegs, rbp),
    r8 = const offset_of!(VmxRegs, r8),
    r9 = const offset_of!(VmxRegs, r9),
    r10 = const offset_of!(VmxRegs, r10),
    r11 = const offset_of!(VmxRegs, r11),
    r12 = const offset_of!(VmxRegs, r12),
    r13 = const offset_of!(VmxRegs, r13),
    r14 = const offset_of!(VmxRegs, r14),
    r15 = const offset_of!(VmxRegs, r15),
);

unsafe extern "C" {
    /// Returns 0 after a VM exit and 1 if VMLAUNCH/VMRESUME failed.
    fn osmium_vmx_run(regs: *mut VmxRegs, resume: u64) -> u64;
    fn osmium_vmx_exit();
}

/// The capabilities every CPU shares, found by the first [`enable`].
pub(super) static CAPS: Once<Caps> = Once::new();

/// `IA32_FEATURE_CONTROL`: lock (bit 0) and VMXON outside SMX (bit 2).
const FEATURE_LOCK: u64 = 1;
const FEATURE_VMXON: u64 = 1 << 2;

/// Turns on VMX on this CPU, with `region` (a page: host pointer and
/// physical address) as its VMXON region. Call once per CPU before running
/// a vCPU on it.
pub fn enable(region: (core::ptr::NonNull<u8>, u64)) -> Result<(), VmxError> {
    if !x86::has_vmx() {
        return Err(VmxError::Unsupported);
    }
    let tr: u16;
    // SAFETY: reading TR has no side effects.
    unsafe { asm!("str {:x}", out(reg) tr, options(nomem, nostack, preserves_flags)) };
    if tr & !7 == 0 {
        return Err(VmxError::NoTaskRegister);
    }
    // SAFETY: VMX is implemented, so these MSRs exist.
    let caps = unsafe {
        let fc = x86::rdmsr(msr::IA32_FEATURE_CONTROL);
        if fc & FEATURE_LOCK == 0 {
            x86::wrmsr(msr::IA32_FEATURE_CONTROL, fc | FEATURE_LOCK | FEATURE_VMXON);
        } else if fc & FEATURE_VMXON == 0 {
            return Err(VmxError::Disabled);
        }
        Caps::from_msrs(|m| x86::rdmsr(m))?
    };
    let caps = *CAPS.call_once(|| caps);
    // SAFETY: the caller hands over the page.
    unsafe {
        region.0.as_ptr().write_bytes(0, 4096);
        region.0.as_ptr().cast::<u32>().write(caps.revision);
        // CR4.VMXE, and OSFXSR/OSXMMEXCPT so FXSAVE/FXRSTOR switch the
        // guests' SSE registers; CR0 and CR4 within VMX's fixed bits.
        asm!("mov {t}, cr4", "or {t}, 0x2600", "mov cr4, {t}", t = out(reg) _, options(nomem, nostack));
        asm!(
            "mov {t}, cr0", "or {t}, {f0}", "and {t}, {f1}", "mov cr0, {t}",
            "mov {t}, cr4", "or {t}, {g0}", "and {t}, {g1}", "mov cr4, {t}",
            t = out(reg) _, f0 = in(reg) caps.cr0_fixed0, f1 = in(reg) caps.cr0_fixed1,
            g0 = in(reg) caps.cr4_fixed0, g1 = in(reg) caps.cr4_fixed1, options(nomem, nostack)
        );
        let failed: u8;
        asm!("vmxon [{}]", "setna {f}", in(reg) &region.1, f = out(reg_byte) failed, options(nostack));
        if failed != 0 {
            return Err(VmxError::Unsupported);
        }
        // Start with no stale translations from an earlier user of VMX.
        invept(2, 0);
        invvpid(2, 0, 0);
    }
    Ok(())
}

/// Invalidates EPT-derived translations (type 1: of `eptp`; 2: all).
///
/// # Safety
/// VMX operation must be on.
unsafe fn invept(ty: u64, eptp: u64) {
    let desc = [eptp, 0u64];
    // SAFETY: the caller upholds the contract; the descriptor is 16 bytes.
    unsafe { asm!("invept {}, [{}]", in(reg) ty, in(reg) desc.as_ptr(), options(nostack)) }
}

/// Invalidates translations tagged `vpid` (type 1) or all of them (type 2).
///
/// # Safety
/// VMX operation must be on.
unsafe fn invvpid(ty: u64, vpid: u16, linear: u64) {
    let desc = [vpid as u64, linear];
    // SAFETY: the caller upholds the contract; the descriptor is 16 bytes.
    unsafe { asm!("invvpid {}, [{}]", in(reg) ty, in(reg) desc.as_ptr(), options(nostack)) }
}

/// The VMCS each CPU has current (its physical address), or 0.
static CURRENT: [AtomicU64; osmium_arch::MAX_CPUS] = [const { AtomicU64::new(0) }; osmium_arch::MAX_CPUS];

/// Makes `pa` this CPU's current VMCS.
fn make_current(pa: u64) {
    let slot = &CURRENT[osmium_arch::cpu::current_id()];
    if slot.load(Ordering::Relaxed) != pa {
        // SAFETY: `pa` is a VMCS page with the right revision identifier.
        unsafe { asm!("vmptrld [{}]", in(reg) &pa, options(nostack)) };
        slot.store(pa, Ordering::Relaxed);
    }
}

/// Reads `field` of the VMCS at `pa`, making it current first.
pub(super) fn vmread(pa: u64, field: u32) -> u64 {
    make_current(pa);
    let v: u64;
    // SAFETY: a VMCS is current; a bad field only sets the error flags.
    unsafe { asm!("vmread {}, {}", out(reg) v, in(reg) field as u64, options(nomem, nostack)) };
    v
}

/// Writes `field` of the VMCS at `pa`, making it current first.
pub(super) fn vmwrite(pa: u64, field: u32, v: u64) {
    make_current(pa);
    // SAFETY: as above.
    unsafe { asm!("vmwrite {}, {}", in(reg) field as u64, in(reg) v, options(nomem, nostack)) };
}

/// Binds a vCPU's VMCS to this CPU: clears it, loads it, and copies in the
/// fields written so far.
fn load(v: &mut VmxVcpu) {
    let cpu = osmium_arch::cpu::current_id();
    let pa = v.vmcs.pa;
    // SAFETY: `pa` is a VMCS page with the right revision identifier.
    unsafe { asm!("vmclear [{}]", in(reg) &pa, options(nostack)) };
    CURRENT[cpu].store(0, Ordering::Relaxed);
    make_current(pa);
    v.vmcs.loaded = true;
    v.cpu = Some(cpu);
    for (f, val) in core::mem::take(&mut v.vmcs.pending) {
        vmwrite(pa, f, val);
    }
}

#[repr(C, packed)]
struct DescTable {
    limit: u16,
    base: u64,
}

fn segment_selectors() -> [u16; 6] {
    let s: [u16; 6];
    // SAFETY: reading segment registers has no side effects.
    unsafe {
        let (mut es, mut cs, mut ss, mut ds, mut fs, mut gs): (u16, u16, u16, u16, u16, u16);
        asm!("mov {:x}, es", "mov {:x}, cs", "mov {:x}, ss", "mov {:x}, ds", "mov {:x}, fs", "mov {:x}, gs",
            out(reg) es, out(reg) cs, out(reg) ss, out(reg) ds, out(reg) fs, out(reg) gs,
            options(nomem, nostack, preserves_flags));
        s = [es, cs, ss, ds, fs, gs];
    }
    s
}

/// Writes the host state a VM exit restores, and refreshes the host's MSR list.
/// Returns the GDTR and IDTR to put back (VM exit leaves their limits at 0xffff).
fn write_host_state(v: &mut VmxVcpu) -> (DescTable, DescTable) {
    let pa = v.vmcs.pa;
    let w = |f, x: u64| vmwrite(pa, f, x);
    let (mut gdt, mut idt) = (DescTable { limit: 0, base: 0 }, DescTable { limit: 0, base: 0 });
    let (cr0, cr3, cr4): (u64, u64, u64);
    let tr: u16;
    // SAFETY: reading descriptor-table registers, control registers and TR has no side effects.
    unsafe {
        asm!("sgdt [{}]", in(reg) &mut gdt, options(nostack, preserves_flags));
        asm!("sidt [{}]", in(reg) &mut idt, options(nostack, preserves_flags));
        asm!("mov {}, cr0", "mov {}, cr4", out(reg) cr0, out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("str {:x}", out(reg) tr, options(nomem, nostack, preserves_flags));
    }
    cr3 = x86::read_cr3();
    let sel = segment_selectors();
    for (i, s) in sel.into_iter().enumerate() {
        // The host selectors must have RPL 0 and TI 0 (CS is index 1).
        w(vmcs::HOST_ES_SEL + 2 * i as u32, (s & !7) as u64);
    }
    w(vmcs::HOST_ES_SEL + 12, tr as u64);
    // The TSS descriptor is 16 bytes in the GDT.
    let desc = (gdt.base + (tr & !7) as u64) as *const u64;
    // SAFETY: TR names a valid 64-bit TSS descriptor in the loaded GDT.
    let (lo, hi) = unsafe { (desc.read_unaligned(), desc.add(1).read_unaligned()) };
    let tr_base = (lo >> 16 & 0xff_ffff) | (lo >> 56) << 24 | (hi & 0xffff_ffff) << 32;
    w(vmcs::HOST_CR0, cr0);
    w(vmcs::HOST_CR3, cr3);
    w(vmcs::HOST_CR4, cr4);
    // SAFETY: these MSRs exist wherever VMX does.
    unsafe {
        w(vmcs::HOST_FS_BASE, x86::rdmsr(msr::IA32_FS_BASE));
        w(vmcs::HOST_GS_BASE, x86::rdmsr(msr::IA32_GS_BASE));
        w(vmcs::HOST_EFER, x86::rdmsr(msr::IA32_EFER));
        w(vmcs::HOST_PAT, x86::rdmsr(0x277));
        w(vmcs::HOST_SYSENTER_CS, x86::rdmsr(0x174) & 0xffff_ffff);
        w(vmcs::HOST_SYSENTER_ESP, x86::rdmsr(0x175));
        w(vmcs::HOST_SYSENTER_EIP, x86::rdmsr(0x176));
        for (i, m) in SWITCHED.into_iter().enumerate() {
            v.set_area(HOST_LIST, i, m, x86::rdmsr(m));
        }
    }
    w(vmcs::HOST_TR_BASE, tr_base);
    w(vmcs::HOST_GDTR_BASE, gdt.base);
    w(vmcs::HOST_IDTR_BASE, idt.base);
    w(vmcs::HOST_RIP, osmium_vmx_exit as *const () as u64);
    (gdt, idt)
}

/// Enters the guest and returns at its next VM exit; `Err` if the entry
/// instruction itself failed (see [`VmxVcpu::instruction_error`]).
pub(super) fn run(v: &mut VmxVcpu) -> Result<(), ()> {
    let cpu = osmium_arch::cpu::current_id();
    if !v.vmcs.loaded {
        load(v);
    }
    assert_eq!(v.cpu, Some(cpu), "a VMX vCPU runs only on the CPU it was first run on");
    let flags: u64;
    // SAFETY: reads RFLAGS.
    unsafe { asm!("pushfq", "pop {}", out(reg) flags, options(nomem, preserves_flags)) };
    let if_on = flags & (1 << 9) != 0;
    // SAFETY: interrupts stay off from here until the exit is handled, so no
    // other code on this CPU changes the current VMCS or the state written below.
    unsafe { asm!("cli", options(nomem, nostack)) };
    make_current(v.vmcs.pa);
    if core::mem::take(&mut v.flush) {
        // SAFETY: VMX operation is on.
        unsafe {
            invept(caps_invept(v), vmread(v.vmcs.pa, vmcs::EPTP));
            invvpid(v.caps.invvpid, v.vpid, 0);
        }
    }
    let (gdt, idt) = write_host_state(v);
    let resume = core::mem::replace(&mut v.launched, true) as u64;
    // SAFETY: the guest's registers are in `v.regs`; the assembly preserves
    // every callee-saved register. FXSAVE/FXRSTOR switch x87/SSE state, which
    // the soft-float host never uses itself.
    let failed = unsafe {
        if v.switch_fp {
            asm!("fxrstor64 [{}]", in(reg) v.fpu.0.as_ptr(), options(nostack, readonly));
        }
        let failed = osmium_vmx_run(&mut v.regs, resume) != 0;
        if v.switch_fp {
            asm!("fxsave64 [{}]", in(reg) v.fpu.0.as_mut_ptr(), options(nostack));
        }
        // VM exit leaves both table limits at 0xffff.
        asm!("lgdt [{}]", "lidt [{}]", in(reg) &gdt, in(reg) &idt, options(readonly, nostack));
        failed
    };
    if failed {
        v.launched = resume != 0;
        // SAFETY: restores the caller's interrupt state.
        unsafe {
            if if_on {
                asm!("sti", options(nomem, nostack))
            }
        };
        return Err(());
    }
    // An NMI that exited is the host's: run its handler (the vector is in the IDT).
    let info = vmread(v.vmcs.pa, vmcs::EXIT_INTR_INFO);
    if vmread(v.vmcs.pa, vmcs::EXIT_REASON) as u32 == exit::EXCEPTION_NMI && info & (1 << 31) != 0 && info >> 8 & 7 == 2
    {
        // SAFETY: vector 2 is the host's NMI gate.
        unsafe { asm!("int 2") };
    }
    // SAFETY: a host interrupt that arrived during the run is delivered now.
    unsafe {
        if if_on {
            asm!("sti", options(nomem, nostack))
        }
    };
    Ok(())
}

fn caps_invept(v: &VmxVcpu) -> u64 {
    v.caps.invept
}
