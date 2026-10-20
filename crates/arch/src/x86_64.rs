//! x86_64 registers and instructions: port I/O, MSRs, control registers, CPUID.
//!
//! Everything here is privileged; on a hosted target the functions compile
//! but fault if called.

use core::arch::asm;

/// Well-known model-specific register numbers.
pub mod msr {
    /// Local APIC base address and enable bits.
    pub const IA32_APIC_BASE: u32 = 0x1b;
    /// Extended feature enables (SCE, LME, NXE).
    pub const IA32_EFER: u32 = 0xc000_0080;
    /// FS segment base.
    pub const IA32_FS_BASE: u32 = 0xc000_0100;
    /// GS segment base.
    pub const IA32_GS_BASE: u32 = 0xc000_0101;
    /// Target of `swapgs`.
    pub const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;
    /// Value returned in ECX by `rdtscp`; Osmium stores the CPU id here.
    pub const IA32_TSC_AUX: u32 = 0xc000_0103;
    /// VMX capability reporting base.
    pub const IA32_VMX_BASIC: u32 = 0x480;
    /// Feature control (VMX enable lock).
    pub const IA32_FEATURE_CONTROL: u32 = 0x3a;
}

/// Reads a byte from an I/O port.
///
/// # Safety
/// Port I/O can reconfigure hardware; the caller must own the device.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: the caller owns the port.
    unsafe { asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}

/// Writes a byte to an I/O port.
///
/// # Safety
/// See [`inb`].
#[inline]
pub unsafe fn outb(port: u16, v: u8) {
    // SAFETY: the caller owns the port.
    unsafe { asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) }
}

/// Reads a 16-bit word from an I/O port.
///
/// # Safety
/// See [`inb`].
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    // SAFETY: the caller owns the port.
    unsafe { asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}

/// Writes a 16-bit word to an I/O port.
///
/// # Safety
/// See [`inb`].
#[inline]
pub unsafe fn outw(port: u16, v: u16) {
    // SAFETY: the caller owns the port.
    unsafe { asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)) }
}

/// Reads a 32-bit word from an I/O port.
///
/// # Safety
/// See [`inb`].
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: the caller owns the port.
    unsafe { asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}

/// Writes a 32-bit word to an I/O port.
///
/// # Safety
/// See [`inb`].
#[inline]
pub unsafe fn outl(port: u16, v: u32) {
    // SAFETY: the caller owns the port.
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)) }
}

/// Reads a model-specific register.
///
/// # Safety
/// Faults if the MSR does not exist; some MSRs have read side effects.
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: the caller guarantees the MSR exists.
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) }
    (hi as u64) << 32 | lo as u64
}

/// Writes a model-specific register.
///
/// # Safety
/// MSRs control fundamental CPU behaviour; the caller must know the effect.
#[inline]
pub unsafe fn wrmsr(msr: u32, v: u64) {
    // SAFETY: the caller upholds the contract.
    unsafe { asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nostack, preserves_flags)) }
}

/// Reads CR3 (the physical address of the root page table plus flags).
#[inline]
pub fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) }
    v
}

/// Writes CR3, switching address spaces and flushing non-global TLB entries.
///
/// # Safety
/// `v` must point at a valid root table that maps the currently executing
/// code and stack.
#[inline]
pub unsafe fn write_cr3(v: u64) {
    // SAFETY: the caller upholds the contract.
    unsafe { asm!("mov cr3, {}", in(reg) v, options(nostack, preserves_flags)) }
}

/// Reads CR2, the faulting address of the last page fault.
#[inline]
pub fn read_cr2() -> u64 {
    let v: u64;
    // SAFETY: reading CR2 has no side effects.
    unsafe { asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)) }
    v
}

/// Result of a `cpuid` query.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Executes `cpuid` with the given leaf and sub-leaf.
#[inline]
pub fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    #[allow(unused_unsafe)]
    // SAFETY: cpuid is always available in 64-bit mode.
    let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
    CpuidResult { eax: r.eax, ebx: r.ebx, ecx: r.ecx, edx: r.edx }
}

/// Returns true if the CPU supports VMX (Intel VT-x).
pub fn has_vmx() -> bool {
    cpuid(1, 0).ecx & (1 << 5) != 0
}

/// Returns true if the CPU supports SVM (AMD-V).
pub fn has_svm() -> bool {
    cpuid(0x8000_0000, 0).eax >= 0x8000_0001 && cpuid(0x8000_0001, 0).ecx & (1 << 2) != 0
}
