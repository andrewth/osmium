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

/// A mask of the low `size` bytes of a register (`size` 0 gives 0; 8 or more
/// gives all ones), for access sizes the hardware or decoder reported.
pub(crate) fn size_mask(size: u8) -> u64 {
    1u64.checked_shl((size as u32).saturating_mul(8)).map_or(u64::MAX, |v| v - 1)
}

/// `IA32_APIC_BASE`: the bootstrap processor, and the APIC enabled.
pub(crate) const APIC_BASE_BSP: u64 = 1 << 8;
pub(crate) const APIC_BASE_ENABLE: u64 = 1 << 11;
/// The one place the emulated xAPIC can be.
pub(crate) const APIC_BASE_ADDR: u64 = 0xfee0_0000;

/// Whether a guest WRMSR of `v` to `IA32_APIC_BASE` is one this model
/// supports: the xAPIC stays enabled, at its default address, with x2APIC
/// off and the reserved bits (7:0, 9, 63:36) clear. The BSP bit (8) is
/// read-only and ignored. Anything else is a #GP, as on hardware.
pub(crate) fn apic_base_write_ok(v: u64) -> bool {
    const RESERVED: u64 = 0xff | 1 << 9 | 1 << 10 | !0 << 36;
    v & RESERVED == 0 && v & APIC_BASE_ENABLE != 0 && v & 0xf_ffff_f000 == APIC_BASE_ADDR
}

/// An event-injection word (the VMX interruption information with the error
/// code in bits 63:32, which is also SVM's `EVENTINJ`) as the CPU may take
/// it: in real mode (`CR0.PE` clear) an exception has no error code, and
/// asking for one fails the VM entry.
pub(crate) fn injectable(event: u64, cr0: u64) -> u64 {
    if cr0 & 1 == 0 { event & 0xffff_ffff & !(1 << 11) } else { event }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_mode_events_carry_no_error_code() {
        let gp = 13 | 3 << 8 | 1 << 11 | 1 << 31 | 5 << 32;
        assert_eq!(injectable(gp, 1), gp, "protected mode keeps it");
        assert_eq!(injectable(gp, 0), 13 | 3 << 8 | 1 << 31, "real mode drops it");
    }

    #[test]
    fn apic_base_writes_are_validated() {
        let ok = APIC_BASE_ADDR | APIC_BASE_ENABLE;
        assert!(apic_base_write_ok(ok));
        assert!(apic_base_write_ok(ok | APIC_BASE_BSP), "BSP is ignored, not rejected");
        assert!(!apic_base_write_ok(ok | 1 << 10), "x2APIC");
        assert!(!apic_base_write_ok(ok | 1 << 9), "reserved");
        assert!(!apic_base_write_ok(ok | 1), "reserved");
        assert!(!apic_base_write_ok(ok | 1 << 40), "reserved");
        assert!(!apic_base_write_ok(APIC_BASE_ADDR), "disabling is not supported");
        assert!(!apic_base_write_ok(0xfee0_1000 | APIC_BASE_ENABLE), "relocation is not supported");
    }
}
