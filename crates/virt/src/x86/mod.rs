//! x86 hardware virtualization: AMD SVM ([`svm::SvmVcpu`]) and Intel VMX
//! ([`vmx::VmxVcpu`]), the instruction decoder both use for MMIO
//! ([`decode`]), and the PC machine model ([`pc`]).

pub mod decode;
pub mod pc;
pub mod svm;
pub mod vmx;

/// An FXSAVE/FXRSTOR image: x87, MMX and SSE state.
#[repr(C, align(16))]
pub(crate) struct FxArea(pub(crate) [u8; 512]);

impl FxArea {
    /// The state after reset: x87 control word 0x37f, MXCSR 0x1f80.
    pub(crate) fn reset() -> Self {
        let mut a = [0u8; 512];
        a[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
        a[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        Self(a)
    }
}

/// `IA32_APIC_BASE`: the bootstrap processor, and the APIC enabled.
pub(crate) const APIC_BASE_BSP: u64 = 1 << 8;
pub(crate) const APIC_BASE_ENABLE: u64 = 1 << 11;

/// What a guest sees of the host's CPUID `leaf` (`[eax, ebx, ecx, edx]`):
/// its own local APIC ID (leaf 1 EBX bits 31:24, leaf 0xB EDX), the
/// hypervisor-present bit (leaf 1 ECX bit 31), and neither x2APIC (only the
/// xAPIC is emulated) nor SVM (no nested virtualization).
pub fn patch_cpuid(leaf: u32, [mut a, mut b, mut c, mut d]: [u32; 4], apic_id: u8) -> [u32; 4] {
    match leaf {
        1 => {
            b = (b & 0x00ff_ffff) | (apic_id as u32) << 24;
            // No x2APIC or TSC-deadline timer (the emulated APIC is xAPIC
            // with one-shot and periodic modes), no XSAVE/OSXSAVE/AVX (XCR0
            // and XSETBV are the host's); the hypervisor bit is set.
            c = (c & !(1 << 21 | 1 << 24 | 1 << 26 | 1 << 27 | 1 << 28)) | 1 << 31;
        }
        7 => {
            // No AVX2/AVX-512, and none of the speculation-control MSRs
            // (IBRS/IBPB, STIBP, ARCH_CAPABILITIES, SSBD), which are not
            // emulated.
            b &= !(1 << 5 | 1 << 16 | 1 << 17 | 1 << 21 | 1 << 26 | 1 << 27 | 1 << 28 | 1 << 30 | 1 << 31);
            c &= !(1 << 1 | 1 << 6 | 1 << 11 | 1 << 12 | 1 << 14);
            d &= !(1 << 2 | 1 << 3 | 1 << 26 | 1 << 27 | 1 << 29 | 1 << 31);
        }
        0xd => [a, b, c, d] = [0; 4],
        0xb => d = apic_id as u32,
        0x8000_0001 => c &= !(1 << 2),
        // AMD's IBPB/IBRS/STIBP/SSBD bits.
        0x8000_0008 => b &= !(1 << 12 | 1 << 14 | 1 << 15 | 1 << 24 | 1 << 25 | 1 << 26),
        _ => {}
    }
    [a, b, c, d]
}
