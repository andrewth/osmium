//! x86 hardware virtualization: AMD SVM ([`svm::SvmVcpu`]) and Intel VMX
//! ([`vmx::VmxVcpu`]), the instruction decoder both use for MMIO
//! ([`decode`]), and the PC machine model ([`pc`]).

pub mod decode;
pub mod pc;
pub mod svm;
pub mod vmx;

use crate::memory::{GuestMemory, GuestPhysAddr};

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

/// The guest registers that select and locate its page tables, for [`translate`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Paging {
    pub(crate) cr0: u64,
    pub(crate) cr3: u64,
    pub(crate) cr4: u64,
    pub(crate) efer: u64,
    /// The four PAE page-directory-pointer entries, where the CPU caches
    /// them (VMX keeps them in the VMCS); `None` reads them from CR3.
    pub(crate) pdptes: Option<[u64; 4]>,
}

const CR0_PG: u64 = 1 << 31;
const CR4_PSE: u64 = 1 << 4;
const CR4_PAE: u64 = 1 << 5;
const EFER_LMA: u64 = 1 << 10;
const PTE_PRESENT: u64 = 1;
const PTE_LARGE: u64 = 1 << 7;
/// Address bits 51:12 of a 64-bit (PAE or long-mode) entry.
const ADDR_52: u64 = 0x000f_ffff_ffff_f000;

/// Translates guest linear address `linear` through the guest's page tables
/// in `mem`, in the paging mode `p` selects: none (`CR0.PG` clear: the
/// address is returned as it is), 32-bit paging (two levels, 4 MiB pages
/// with `CR4.PSE`, including PSE-36's address bits 39:32), PAE paging (three
/// levels, 2 MiB pages) or 4-level long-mode paging (`EFER.LMA`; 2 MiB and
/// 1 GiB pages). Only presence is checked, not permissions: this is for
/// fetching the instruction the guest is executing.
pub(crate) fn translate(mem: &GuestMemory, p: &Paging, linear: u64) -> Option<u64> {
    if p.cr0 & CR0_PG == 0 {
        return Some(linear);
    }
    if p.efer & EFER_LMA != 0 {
        return translate_long(mem, p.cr3, linear);
    }
    let linear = linear & 0xffff_ffff;
    if p.cr4 & CR4_PAE == 0 {
        let pde = mem.read_obj::<u32>(GuestPhysAddr((p.cr3 & 0xffff_f000) + (linear >> 22) * 4)).ok()? as u64;
        if pde & PTE_PRESENT == 0 {
            return None;
        }
        if pde & PTE_LARGE != 0 && p.cr4 & CR4_PSE != 0 {
            // 4 MiB page; bits 20:13 of the PDE are address bits 39:32.
            let base = (pde & 0xffc0_0000) | (pde >> 13 & 0xff) << 32;
            return Some(base | (linear & 0x3f_ffff));
        }
        let pte = mem.read_obj::<u32>(GuestPhysAddr((pde & 0xffff_f000) + (linear >> 12 & 0x3ff) * 4)).ok()? as u64;
        return (pte & PTE_PRESENT != 0).then_some((pte & 0xffff_f000) | (linear & 0xfff));
    }
    let i = (linear >> 30) as usize;
    let pdpte = match p.pdptes {
        Some(cached) => *cached.get(i)?,
        None => mem.read_obj::<u64>(GuestPhysAddr((p.cr3 & 0xffff_ffe0) + i as u64 * 8)).ok()?,
    };
    if pdpte & PTE_PRESENT == 0 {
        return None;
    }
    let pde = mem.read_obj::<u64>(GuestPhysAddr((pdpte & ADDR_52) + (linear >> 21 & 0x1ff) * 8)).ok()?;
    if pde & PTE_PRESENT == 0 {
        return None;
    }
    if pde & PTE_LARGE != 0 {
        return Some((pde & 0x000f_ffff_ffe0_0000) | (linear & 0x1f_ffff));
    }
    let pte = mem.read_obj::<u64>(GuestPhysAddr((pde & ADDR_52) + (linear >> 12 & 0x1ff) * 8)).ok()?;
    (pte & PTE_PRESENT != 0).then_some((pte & ADDR_52) | (linear & 0xfff))
}

/// Walks the 4-level long-mode tables at `cr3`.
fn translate_long(mem: &GuestMemory, cr3: u64, linear: u64) -> Option<u64> {
    let mut table = cr3 & ADDR_52;
    for level in (0..4).rev() {
        let index = (linear >> (12 + 9 * level)) & 0x1ff;
        let pte: u64 = mem.read_obj(GuestPhysAddr(table.wrapping_add(index * 8))).ok()?;
        if pte & PTE_PRESENT == 0 {
            return None;
        }
        let addr = pte & ADDR_52;
        // A large page at level 1 (2 MiB) or 2 (1 GiB).
        if level == 0 || (level <= 2 && pte & PTE_LARGE != 0) {
            let mask = (1u64 << (12 + 9 * level)) - 1;
            return Some((addr & !mask) | (linear & mask));
        }
        table = addr;
    }
    None
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
/// xAPIC is emulated), SVM (no nested virtualization) nor MONITOR/MWAIT
/// (both backends make them raise `#UD`, so a halted guest always exits
/// through `HLT`).
pub fn patch_cpuid(leaf: u32, [mut a, mut b, mut c, mut d]: [u32; 4], apic_id: u8) -> [u32; 4] {
    match leaf {
        1 => {
            b = (b & 0x00ff_ffff) | (apic_id as u32) << 24;
            // No MONITOR/MWAIT, no x2APIC or TSC-deadline timer (the
            // emulated APIC is xAPIC with one-shot and periodic modes), no
            // XSAVE/OSXSAVE/AVX (XCR0 and XSETBV are the host's); the
            // hypervisor bit is set.
            c = (c & !(1 << 3 | 1 << 21 | 1 << 24 | 1 << 26 | 1 << 27 | 1 << 28)) | 1 << 31;
        }
        // The MONITOR/MWAIT leaf.
        5 => [a, b, c, d] = [0; 4],
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
        // No SVM, and no MONITORX/MWAITX.
        0x8000_0001 => c &= !(1 << 2 | 1 << 29),
        // AMD's IBPB/IBRS/STIBP/SSBD bits.
        0x8000_0008 => b &= !(1 << 12 | 1 << 14 | 1 << 15 | 1 << 24 | 1 << 25 | 1 << 26),
        _ => {}
    }
    [a, b, c, d]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guest RAM at 0 for the page-walk tests.
    pub(crate) fn ram(len: usize) -> (alloc::vec::Vec<u8>, GuestMemory) {
        let mut ram = alloc::vec![0u8; len];
        let mut mem = GuestMemory::new();
        // SAFETY: the caller keeps `ram` alive (and untouched) as long as `mem`.
        unsafe { mem.add_region(GuestPhysAddr(0), ram.as_mut_ptr(), len as u64) };
        (ram, mem)
    }

    /// 32-bit paging: PD at 0x1000; PDE 0 points at a page table at 0x2000
    /// whose entry 3 maps 0x7000; PDE 1 is a 4 MiB page at 0x40_0000 (with
    /// PSE) whose PSE-36 bits say 0x1_0000_0000 above that.
    pub(crate) fn legacy_tables(mem: &GuestMemory) {
        mem.write_obj(GuestPhysAddr(0x1000), 0x2003u32).unwrap();
        mem.write_obj(GuestPhysAddr(0x2000 + 3 * 4), 0x7003u32).unwrap();
        mem.write_obj(GuestPhysAddr(0x1004), 0x0040_0083u32 | 1 << 13).unwrap();
        // PAE: PDPT at 0x3000; PDPTE 1 -> PD 0x4000; PDE 0 -> PT 0x5000 whose
        // entry 2 maps 0x8000; PDE 1 is a 2 MiB page at 0x20_0000.
        mem.write_obj(GuestPhysAddr(0x3008), 0x4001u64).unwrap();
        mem.write_obj(GuestPhysAddr(0x4000), 0x5003u64).unwrap();
        mem.write_obj(GuestPhysAddr(0x4008), 0x20_0083u64).unwrap();
        mem.write_obj(GuestPhysAddr(0x5000 + 2 * 8), 0x8003u64).unwrap();
    }

    #[test]
    fn legacy_paging_walks() {
        let (ram, mem) = ram(0x10000);
        legacy_tables(&mem);
        let pg = 1 << 31 | 1;
        let mut p = Paging { cr0: pg, cr3: 0x1000, cr4: 0, efer: 0, pdptes: None };
        assert_eq!(translate(&mem, &p, 0x3abc), Some(0x7abc), "32-bit, 4 KiB page");
        assert_eq!(translate(&mem, &p, 0x4abc), None, "not present");
        assert_eq!(translate(&mem, &p, 0x40_1234), None, "PS without CR4.PSE is a table pointer to nothing");
        p.cr4 = CR4_PSE;
        assert_eq!(translate(&mem, &p, 0x41_2345), Some(0x1_0041_2345), "4 MiB page, PSE-36");
        assert_eq!(translate(&mem, &p, 0x1_0000_3abc), Some(0x7abc), "linear addresses are 32 bits");
        p = Paging { cr0: pg, cr3: 0x3000, cr4: CR4_PAE, efer: 0, pdptes: None };
        assert_eq!(translate(&mem, &p, 0x4000_2abc), Some(0x8abc), "PAE, 4 KiB page");
        assert_eq!(translate(&mem, &p, 0x4030_1234), Some(0x30_1234), "PAE, 2 MiB page");
        assert_eq!(translate(&mem, &p, 0x2abc), None, "PDPTE 0 not present");
        // Cached PDPTEs (VMX) win over the table in memory.
        p.pdptes = Some([0x4001, 0, 0, 0]);
        assert_eq!(translate(&mem, &p, 0x2abc), Some(0x8abc));
        assert_eq!(translate(&mem, &p, 0x4000_2abc), None);
        p.cr0 = 1;
        assert_eq!(translate(&mem, &p, 0x1234_5678), Some(0x1234_5678), "paging off");
        drop(mem);
        drop(ram);
    }

    #[test]
    fn monitor_and_mwait_are_hidden() {
        assert_eq!(patch_cpuid(1, [0, 0, 1 << 3, 0], 0)[2] & 1 << 3, 0, "MONITOR");
        assert_eq!(patch_cpuid(5, [0x40, 0x40, 3, 0x1120], 0), [0; 4], "MONITOR leaf");
        assert_eq!(patch_cpuid(0x8000_0001, [0, 0, 1 << 29, 0], 0)[2], 0, "MONITORX");
    }

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
