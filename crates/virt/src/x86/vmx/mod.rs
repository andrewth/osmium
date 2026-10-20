//! An Intel VMX vCPU.
//!
//! [`VmxVcpu`] owns a VMCS and runs a guest with EPT, VPID and unrestricted
//! guest mode, so guests start the way [`SvmVcpu`](super::SvmVcpu) guests do:
//! in 32-bit protected mode ([`VmxVcpu::new`]), in real mode like an AP after
//! STARTUP ([`VmxVcpu::set_real_mode`]) or in 64-bit mode on their own page
//! tables ([`VmxVcpu::set_long_mode`]). Every I/O port and MSR access exits.
//! Exits become a [`VmExit`]:
//!
//! | Exit reason | Exit |
//! |---|---|
//! | I/O instruction (non-string) | [`VmExit::PioIn`] / [`VmExit::PioOut`] |
//! | `HLT` | [`VmExit::Halt`] |
//! | `VMCALL` | [`VmExit::Hypercall`]: `nr` = `rax`, `args` = `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `r8` |
//! | EPT violation on an unmapped page | [`VmExit::MmioRead`] / [`VmExit::MmioWrite`], from the instruction ([`decode`]) |
//! | External interrupt, NMI | [`VmExit::ExternalInterrupt`] |
//! | Triple fault | [`VmExit::Shutdown`] |
//! | Anything else | [`VmExit::Unhandled`] with the exit reason |
//!
//! Unlike SVM, VMX has no decode assists, so MMIO instructions are always
//! fetched through the guest's page tables. A guest cannot see VMX
//! ([`patch_cpuid`]), and its VMX instructions, `XSETBV` and `MWAIT` raise
//! `#UD`.
//!
//! The VMCS is bound to the host CPU that first runs the vCPU, because it is
//! `VMPTRLD`ed there and stays active; use the vCPU only from that CPU. Fields
//! written before then are kept in memory and copied in.
//!
//! The host's `STAR`, `LSTAR`, `SFMASK`, `KernelGsBase` and `TSC_AUX` are
//! swapped with the guest's by the VM-entry and VM-exit MSR lists; the
//! rest of the host state comes back from the VMCS's host-state area. The host
//! must not use hardware debug registers (the CPU clears `DR7` on every exit).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use super::FxArea;
use super::decode::{self, Access, Operand};
use crate::memory::{GuestMemory, GuestPhysAddr};
use crate::vcpu::{Vcpu, VmExit};

pub mod caps;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod hw;

pub use caps::{Caps, VmxError};
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use hw::enable;

/// VMCS field encodings (Intel SDM vol. 3D, appendix B).
pub mod vmcs {
    /// Virtual-processor identifier.
    pub const VPID: u32 = 0x0000;
    /// Guest ES selector; the other segments follow at +2 ([`Seg`](super::Seg)).
    pub const GUEST_SEL: u32 = 0x0800;
    /// Host ES selector.
    pub const HOST_ES_SEL: u32 = 0x0c00;
    /// MSR bitmap address.
    pub const MSR_BITMAP: u32 = 0x2004;
    /// VM-exit MSR-store address.
    pub const EXIT_MSR_STORE_ADDR: u32 = 0x2006;
    /// VM-exit MSR-load address.
    pub const EXIT_MSR_LOAD_ADDR: u32 = 0x2008;
    /// VM-entry MSR-load address.
    pub const ENTRY_MSR_LOAD_ADDR: u32 = 0x200a;
    /// EPT pointer.
    pub const EPTP: u32 = 0x201a;
    /// Guest-physical address of an EPT violation.
    pub const GUEST_PHYS_ADDR: u32 = 0x2400;
    /// VMCS link pointer.
    pub const LINK_POINTER: u32 = 0x2800;
    /// Guest `IA32_DEBUGCTL`.
    pub const GUEST_DEBUGCTL: u32 = 0x2802;
    /// Guest `IA32_PAT`.
    pub const GUEST_PAT: u32 = 0x2804;
    /// Guest `IA32_EFER`.
    pub const GUEST_EFER: u32 = 0x2806;
    /// Guest PDPTE0 (1-3 follow).
    pub const GUEST_PDPTE0: u32 = 0x280a;
    /// Host `IA32_PAT`.
    pub const HOST_PAT: u32 = 0x2c00;
    /// Host `IA32_EFER`.
    pub const HOST_EFER: u32 = 0x2c02;
    /// Pin-based controls.
    pub const PIN_CTLS: u32 = 0x4000;
    /// Primary processor-based controls.
    pub const PROC_CTLS: u32 = 0x4002;
    /// Exception bitmap.
    pub const EXCEPTION_BITMAP: u32 = 0x4004;
    /// Page-fault error-code mask.
    pub const PF_MASK: u32 = 0x4006;
    /// Page-fault error-code match.
    pub const PF_MATCH: u32 = 0x4008;
    /// CR3-target count.
    pub const CR3_TARGET_COUNT: u32 = 0x400a;
    /// VM-exit controls.
    pub const EXIT_CTLS: u32 = 0x400c;
    /// VM-exit MSR-store count.
    pub const EXIT_MSR_STORE_COUNT: u32 = 0x400e;
    /// VM-exit MSR-load count.
    pub const EXIT_MSR_LOAD_COUNT: u32 = 0x4010;
    /// VM-entry controls.
    pub const ENTRY_CTLS: u32 = 0x4012;
    /// VM-entry MSR-load count.
    pub const ENTRY_MSR_LOAD_COUNT: u32 = 0x4014;
    /// VM-entry interruption information.
    pub const ENTRY_INTR_INFO: u32 = 0x4016;
    /// VM-entry exception error code.
    pub const ENTRY_ERRCODE: u32 = 0x4018;
    /// VM-entry instruction length.
    pub const ENTRY_INSN_LEN: u32 = 0x401a;
    /// Secondary processor-based controls.
    pub const PROC2_CTLS: u32 = 0x401e;
    /// VM-instruction error.
    pub const INSN_ERROR: u32 = 0x4400;
    /// Exit reason.
    pub const EXIT_REASON: u32 = 0x4402;
    /// VM-exit interruption information.
    pub const EXIT_INTR_INFO: u32 = 0x4404;
    /// VM-exit interruption error code.
    pub const EXIT_INTR_ERRCODE: u32 = 0x4406;
    /// IDT-vectoring information.
    pub const IDT_VECTORING_INFO: u32 = 0x4408;
    /// IDT-vectoring error code.
    pub const IDT_VECTORING_ERRCODE: u32 = 0x440a;
    /// VM-exit instruction length.
    pub const EXIT_INSN_LEN: u32 = 0x440c;
    /// Guest ES limit.
    pub const GUEST_LIMIT: u32 = 0x4800;
    /// Guest GDTR limit.
    pub const GUEST_GDTR_LIMIT: u32 = 0x4810;
    /// Guest IDTR limit.
    pub const GUEST_IDTR_LIMIT: u32 = 0x4812;
    /// Guest ES access rights.
    pub const GUEST_AR: u32 = 0x4814;
    /// Guest interruptibility state.
    pub const GUEST_INTERRUPTIBILITY: u32 = 0x4824;
    /// Guest activity state.
    pub const GUEST_ACTIVITY: u32 = 0x4826;
    /// Guest `IA32_SYSENTER_CS`.
    pub const GUEST_SYSENTER_CS: u32 = 0x482a;
    /// Host `IA32_SYSENTER_CS`.
    pub const HOST_SYSENTER_CS: u32 = 0x4c00;
    /// CR0 guest/host mask.
    pub const CR0_MASK: u32 = 0x6000;
    /// CR4 guest/host mask.
    pub const CR4_MASK: u32 = 0x6002;
    /// CR0 read shadow.
    pub const CR0_SHADOW: u32 = 0x6004;
    /// CR4 read shadow.
    pub const CR4_SHADOW: u32 = 0x6006;
    /// Exit qualification.
    pub const EXIT_QUAL: u32 = 0x6400;
    /// Guest CR0.
    pub const GUEST_CR0: u32 = 0x6800;
    /// Guest CR3.
    pub const GUEST_CR3: u32 = 0x6802;
    /// Guest CR4.
    pub const GUEST_CR4: u32 = 0x6804;
    /// Guest ES base.
    pub const GUEST_BASE: u32 = 0x6806;
    /// Guest GDTR base.
    pub const GUEST_GDTR_BASE: u32 = 0x6816;
    /// Guest IDTR base.
    pub const GUEST_IDTR_BASE: u32 = 0x6818;
    /// Guest DR7.
    pub const GUEST_DR7: u32 = 0x681a;
    /// Guest RSP.
    pub const GUEST_RSP: u32 = 0x681c;
    /// Guest RIP.
    pub const GUEST_RIP: u32 = 0x681e;
    /// Guest RFLAGS.
    pub const GUEST_RFLAGS: u32 = 0x6820;
    /// Guest pending debug exceptions.
    pub const GUEST_PENDING_DBG: u32 = 0x6822;
    /// Guest `IA32_SYSENTER_ESP`.
    pub const GUEST_SYSENTER_ESP: u32 = 0x6824;
    /// Guest `IA32_SYSENTER_EIP`.
    pub const GUEST_SYSENTER_EIP: u32 = 0x6826;
    /// Host CR0.
    pub const HOST_CR0: u32 = 0x6c00;
    /// Host CR3.
    pub const HOST_CR3: u32 = 0x6c02;
    /// Host CR4.
    pub const HOST_CR4: u32 = 0x6c04;
    /// Host FS base.
    pub const HOST_FS_BASE: u32 = 0x6c06;
    /// Host GS base.
    pub const HOST_GS_BASE: u32 = 0x6c08;
    /// Host TR base.
    pub const HOST_TR_BASE: u32 = 0x6c0a;
    /// Host GDTR base.
    pub const HOST_GDTR_BASE: u32 = 0x6c0c;
    /// Host IDTR base.
    pub const HOST_IDTR_BASE: u32 = 0x6c0e;
    /// Host `IA32_SYSENTER_ESP`.
    pub const HOST_SYSENTER_ESP: u32 = 0x6c10;
    /// Host `IA32_SYSENTER_EIP`.
    pub const HOST_SYSENTER_EIP: u32 = 0x6c12;
    /// Host RSP.
    pub const HOST_RSP: u32 = 0x6c14;
    /// Host RIP.
    pub const HOST_RIP: u32 = 0x6c16;
}

/// Basic exit reasons.
pub mod exit {
    /// Exception or NMI.
    pub const EXCEPTION_NMI: u32 = 0;
    /// External interrupt.
    pub const EXTERNAL_INTERRUPT: u32 = 1;
    /// Triple fault.
    pub const TRIPLE_FAULT: u32 = 2;
    /// The guest can take an interrupt.
    pub const INTERRUPT_WINDOW: u32 = 7;
    /// CPUID.
    pub const CPUID: u32 = 10;
    /// HLT.
    pub const HLT: u32 = 12;
    /// INVD.
    pub const INVD: u32 = 13;
    /// RDPMC.
    pub const RDPMC: u32 = 15;
    /// VMCALL.
    pub const VMCALL: u32 = 18;
    /// VMCLEAR, the first of the VMX instructions (through VMXON, 27).
    pub const VMCLEAR: u32 = 19;
    /// VMXON, the last of them.
    pub const VMXON: u32 = 27;
    /// MOV to or from a control register, CLTS, LMSW.
    pub const CR_ACCESS: u32 = 28;
    /// MOV to or from a debug register.
    pub const DR_ACCESS: u32 = 29;
    /// I/O instruction.
    pub const IO: u32 = 30;
    /// RDMSR.
    pub const MSR_READ: u32 = 31;
    /// WRMSR.
    pub const MSR_WRITE: u32 = 32;
    /// MWAIT.
    pub const MWAIT: u32 = 36;
    /// MONITOR.
    pub const MONITOR: u32 = 39;
    /// EPT violation.
    pub const EPT_VIOLATION: u32 = 48;
    /// INVEPT.
    pub const INVEPT: u32 = 50;
    /// INVVPID.
    pub const INVVPID: u32 = 53;
    /// WBINVD.
    pub const WBINVD: u32 = 54;
    /// XSETBV.
    pub const XSETBV: u32 = 55;
    /// Set in the exit reason when VM entry failed.
    pub const ENTRY_FAILURE: u32 = 1 << 31;
}

/// A guest segment register, in VMCS field order.
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
#[allow(missing_docs)]
pub enum Seg {
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
    Ldtr,
    Tr,
}

/// A segment as (selector, access rights, limit, base). Access rights use
/// the VMCS layout: type, S, DPL and P in bits 7:0, AVL, L, D/B and G in bits
/// 15:12, "unusable" in bit 16.
pub type Segment = (u16, u32, u32, u64);

/// Guest general-purpose registers other than `rsp`, which lives in the
/// VMCS. The layout is shared with the world-switch assembly.
#[repr(C)]
#[derive(Clone, Debug, Default)]
#[allow(missing_docs)]
pub struct VmxRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Memory the vCPU needs from the host: a VMCS, an MSR bitmap and a page
/// for the MSR load/store lists, each one page, page aligned and physically
/// contiguous, given as (host pointer, physical address).
pub struct VmxPages {
    /// The VMCS.
    pub vmcs: (NonNull<u8>, u64),
    /// The MSR bitmap.
    pub msr_bitmap: (NonNull<u8>, u64),
    /// The guest's and host's values of the MSRs the CPU switches.
    pub msr_area: (NonNull<u8>, u64),
}

/// The MSRs the VM-entry and VM-exit lists switch, in list order.
const SWITCHED: [u32; 5] = [0xc000_0081, 0xc000_0082, 0xc000_0084, 0xc000_0102, 0xc000_0103];
/// Offset of the host values (the VM-exit load list) in the MSR page.
const HOST_LIST: usize = 0x100;

const EVENT_VALID: u64 = 1 << 31;
const RFLAGS_IF: u64 = 1 << 9;
const APIC_BASE_BSP: u64 = 1 << 8;
const APIC_BASE_ENABLE: u64 = 1 << 11;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;
const CR0_PE: u64 = 1;
const CR0_PG: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;
const CR4_VMXE: u64 = 1 << 13;
/// #UD, #GP(0) and #DB in the form of [`VmxVcpu::pending_exception`]: the
/// interruption information in the low half and the error code in the high.
const UD: u64 = 6 | 3 << 8 | EVENT_VALID;
const GP: u64 = 13 | 3 << 8 | 1 << 11 | EVENT_VALID;

type Ack = Box<dyn Fn() -> Option<u8> + Send + Sync>;

/// What a guest sees of the host's CPUID `leaf` (`[eax, ebx, ecx, edx]`):
/// [`patch_cpuid`](super::patch_cpuid)'s view, without VMX or SMX, MONITOR,
/// INVPCID, performance counters or processor trace.
pub fn patch_cpuid(leaf: u32, regs: [u32; 4], apic_id: u8) -> [u32; 4] {
    let [mut a, mut b, mut c, mut d] = super::patch_cpuid(leaf, regs, apic_id);
    match leaf {
        1 => c &= !(1 << 3 | 1 << 5 | 1 << 6),
        7 => b &= !(1 << 10 | 1 << 25),
        0xa | 0x14 => [a, b, c, d] = [0; 4],
        _ => {}
    }
    [a, b, c, d]
}

fn canonical(v: u64) -> bool {
    ((v << 16) as i64 >> 16) as u64 == v
}

/// The VMCS: its memory, and writes made before it is loaded on a CPU.
struct Vmcs {
    pa: u64,
    /// Fields written before the VMCS was loaded (and all of them, off
    /// bare metal).
    pending: BTreeMap<u32, u64>,
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    loaded: bool,
}

impl Vmcs {
    fn read(&self, field: u32) -> u64 {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        if self.loaded {
            return hw::vmread(self.pa, field);
        }
        self.pending.get(&field).copied().unwrap_or(0)
    }

    fn write(&mut self, field: u32, v: u64) {
        #[cfg(all(target_arch = "x86_64", target_os = "none"))]
        if self.loaded {
            return hw::vmwrite(self.pa, field, v);
        }
        self.pending.insert(field, v);
    }
}

/// A virtual x86 CPU on Intel VMX.
pub struct VmxVcpu {
    vmcs: Vmcs,
    caps: Caps,
    msr_area: NonNull<u8>,
    /// General-purpose registers other than `rsp`.
    pub regs: VmxRegs,
    pending_in: Option<(u8, u64)>,
    pending_mmio: Option<Access>,
    mem: Option<Arc<GuestMemory>>,
    irq: Arc<AtomicBool>,
    ack: Option<Ack>,
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    flush: bool,
    /// Whether the VMCS has been launched (VMRESUME rather than VMLAUNCH).
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    launched: bool,
    /// The IDT-vectoring information of the last exit was already used.
    vectoring_done: bool,
    /// The VPID tagging this vCPU's translations.
    vpid: u16,
    /// The guest's x87/SSE state (an FXSAVE image), loaded around entry.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    pub(crate) fpu: Box<FxArea>,
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    pub(crate) switch_fp: bool,
    /// The host CPU running this vCPU's guest code, for kicks.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    pub(crate) running: Option<Arc<core::sync::atomic::AtomicUsize>>,
    apic_base: u64,
    apic_id: u8,
    /// An exception to raise in the guest at the next entry.
    pending_exception: Option<u64>,
    /// State the hardware does not keep for the guest.
    dr6: u64,
    dr7: u64,
    cr8: u64,
    cstar: u64,
    /// Bare-metal only: the host CPU the VMCS is bound to.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    cpu: Option<usize>,
}

// SAFETY: the vCPU owns its VMCS and MSR pages exclusively.
unsafe impl Send for VmxVcpu {}

impl VmxVcpu {
    /// A vCPU in 32-bit protected mode with paging off and flat 4 GiB
    /// segments, starting at `entry` with stack `rsp`, translating guest
    /// physical addresses through the EPT with pointer `eptp` (see
    /// [`stage2::eptp`](crate::stage2::eptp)). Intercepts every I/O port and MSR.
    ///
    /// On bare metal `enable` must have run on some CPU already.
    ///
    /// # Safety
    /// `pages` must be valid, exclusively owned memory of the stated sizes
    /// that outlives the vCPU.
    pub unsafe fn new(pages: VmxPages, eptp: u64, entry: u32, rsp: u32) -> Self {
        let caps = caps();
        // SAFETY: the caller hands over the pages.
        unsafe {
            pages.vmcs.0.as_ptr().write_bytes(0, 4096);
            pages.vmcs.0.as_ptr().cast::<u32>().write(caps.revision);
            pages.msr_bitmap.0.as_ptr().write_bytes(0xff, 4096);
            pages.msr_area.0.as_ptr().write_bytes(0, 4096);
        }
        let mut v = Self {
            vmcs: Vmcs { pa: pages.vmcs.1, pending: BTreeMap::new(), loaded: false },
            caps,
            msr_area: pages.msr_area.0,
            regs: VmxRegs::default(),
            pending_in: None,
            pending_mmio: None,
            mem: None,
            irq: Arc::new(AtomicBool::new(false)),
            ack: None,
            flush: true,
            launched: false,
            vectoring_done: true,
            vpid: (crate::vcpu::new_vcpu_id() % 0xffff) as u16 + 1,
            fpu: Box::new(FxArea::reset()),
            switch_fp: false,
            running: None,
            apic_base: 0xfee0_0000 | APIC_BASE_ENABLE | APIC_BASE_BSP,
            apic_id: 0,
            pending_exception: None,
            dr6: 0xffff_0ff0,
            dr7: 0x400,
            cr8: 0,
            cstar: 0,
            cpu: None,
        };
        use vmcs::*;
        for (i, m) in SWITCHED.into_iter().enumerate() {
            v.set_area(0, i, m, 0);
            v.set_area(HOST_LIST, i, m, 0);
        }
        let n = SWITCHED.len() as u64;
        v.vmcs.write(MSR_BITMAP, pages.msr_bitmap.1);
        v.vmcs.write(ENTRY_MSR_LOAD_ADDR, pages.msr_area.1);
        v.vmcs.write(EXIT_MSR_STORE_ADDR, pages.msr_area.1);
        v.vmcs.write(EXIT_MSR_LOAD_ADDR, pages.msr_area.1 + HOST_LIST as u64);
        for f in [ENTRY_MSR_LOAD_COUNT, EXIT_MSR_STORE_COUNT, EXIT_MSR_LOAD_COUNT] {
            v.vmcs.write(f, n);
        }
        v.vmcs.write(PIN_CTLS, caps.pin as u64);
        v.vmcs.write(PROC_CTLS, caps.proc as u64);
        v.vmcs.write(PROC2_CTLS, caps.proc2 as u64);
        v.vmcs.write(EXIT_CTLS, caps.exit as u64);
        v.vmcs.write(ENTRY_CTLS, caps.entry as u64);
        // #DB and #AC: a guest whose delivery of these faults loops would
        // otherwise hold the host CPU forever; they are reflected back.
        v.vmcs.write(EXCEPTION_BITMAP, 1 << 1 | 1 << 17);
        for f in [PF_MASK, PF_MATCH, CR3_TARGET_COUNT, ENTRY_INTR_INFO, ENTRY_ERRCODE, ENTRY_INSN_LEN] {
            v.vmcs.write(f, 0);
        }
        v.vmcs.write(VPID, v.vpid as u64);
        v.vmcs.write(EPTP, eptp);
        v.vmcs.write(LINK_POINTER, u64::MAX);
        // The bits CR0 and CR4 must have set in VMX operation belong to the
        // host; the guest sees them as the shadows say.
        v.vmcs.write(CR0_MASK, v.cr0_owned());
        v.vmcs.write(CR4_MASK, caps.cr4_fixed0);
        let code = (0x08, 0xc09b, u32::MAX, 0); // 32-bit, readable, accessed, G
        let data = (0x10, 0xc093, u32::MAX, 0);
        v.segment(Seg::Cs, code);
        for s in [Seg::Es, Seg::Ss, Seg::Ds, Seg::Fs, Seg::Gs] {
            v.segment(s, data);
        }
        v.vmcs.write(GUEST_GDTR_BASE, 0);
        v.vmcs.write(GUEST_GDTR_LIMIT, 0xffff);
        v.vmcs.write(GUEST_IDTR_BASE, 0);
        v.vmcs.write(GUEST_IDTR_LIMIT, 0xffff);
        v.segment(Seg::Ldtr, (0, 0x82, 0xffff, 0));
        v.segment(Seg::Tr, (0, 0x8b, 0xffff, 0));
        v.set_cr0(0x11); // PE, ET
        v.set_cr4(0);
        v.vmcs.write(GUEST_CR3, 0);
        v.vmcs.write(GUEST_EFER, 0);
        v.vmcs.write(GUEST_PAT, 0x0007_0406_0007_0406);
        v.vmcs.write(GUEST_DEBUGCTL, 0);
        v.vmcs.write(GUEST_DR7, 0x400);
        v.vmcs.write(GUEST_RFLAGS, 2);
        v.vmcs.write(GUEST_RIP, entry as u64);
        v.vmcs.write(GUEST_RSP, rsp as u64);
        v.vmcs.write(GUEST_ACTIVITY, 0);
        v.vmcs.write(GUEST_INTERRUPTIBILITY, 0);
        v.vmcs.write(GUEST_PENDING_DBG, 0);
        v.vmcs.write(GUEST_SYSENTER_CS, 0);
        v.vmcs.write(GUEST_SYSENTER_ESP, 0);
        v.vmcs.write(GUEST_SYSENTER_EIP, 0);
        for i in 0..4 {
            v.vmcs.write(GUEST_PDPTE0 + 2 * i, 0);
        }
        v
    }

    /// CR0 bits the CPU insists are set that the guest may not change
    /// (`PE` and `PG` may be clear under unrestricted guest).
    fn cr0_owned(&self) -> u64 {
        self.caps.cr0_fixed0 & !(CR0_PE | CR0_PG)
    }

    fn set_cr0(&mut self, v: u64) {
        let owned = self.cr0_owned();
        self.vmcs.write(vmcs::CR0_SHADOW, v);
        self.vmcs.write(vmcs::GUEST_CR0, v | owned);
    }

    fn set_cr4(&mut self, v: u64) {
        self.vmcs.write(vmcs::CR4_SHADOW, v);
        self.vmcs.write(vmcs::GUEST_CR4, v | self.caps.cr4_fixed0);
    }

    /// The guest's view of CR0.
    pub fn cr0(&self) -> u64 {
        self.vmcs.read(vmcs::CR0_SHADOW)
    }

    /// The guest's view of CR4.
    pub fn cr4(&self) -> u64 {
        self.vmcs.read(vmcs::CR4_SHADOW)
    }

    fn area_entry(&self, base: usize, i: usize) -> *mut u8 {
        // SAFETY: five 16-byte entries at each of two offsets in the owned page.
        unsafe { self.msr_area.as_ptr().add(base + 16 * i) }
    }

    fn set_area(&mut self, base: usize, i: usize, msr: u32, value: u64) {
        let p = self.area_entry(base, i);
        // SAFETY: as above.
        unsafe {
            p.cast::<u32>().write_volatile(msr);
            p.add(4).cast::<u32>().write_volatile(0);
            p.add(8).cast::<u64>().write_volatile(value);
        }
    }

    fn area(&self, msr: u32) -> u64 {
        let i = SWITCHED.iter().position(|&m| m == msr).expect("a switched MSR");
        // SAFETY: as above.
        unsafe { self.area_entry(0, i).add(8).cast::<u64>().read_volatile() }
    }

    fn set_guest_area(&mut self, msr: u32, v: u64) {
        let i = SWITCHED.iter().position(|&m| m == msr).expect("a switched MSR");
        self.set_area(0, i, msr, v);
    }

    /// Sets a segment register.
    pub fn segment(&mut self, seg: Seg, (sel, ar, limit, base): Segment) {
        let i = seg as u32;
        self.vmcs.write(vmcs::GUEST_SEL + 2 * i, sel as u64);
        self.vmcs.write(vmcs::GUEST_LIMIT + 2 * i, limit as u64);
        self.vmcs.write(vmcs::GUEST_AR + 2 * i, ar as u64);
        self.vmcs.write(vmcs::GUEST_BASE + 2 * i, base);
    }

    fn seg_ar(&self, seg: Seg) -> u64 {
        self.vmcs.read(vmcs::GUEST_AR + 2 * seg as u32)
    }

    fn seg_base(&self, seg: Seg) -> u64 {
        self.vmcs.read(vmcs::GUEST_BASE + 2 * seg as u32)
    }

    /// Starts the guest in real mode instead, at `page << 12` (CS =
    /// `page << 8`, IP = 0): the state a STARTUP IPI with vector `page`
    /// leaves an application processor in. The real-mode IDT is at 0.
    pub fn set_real_mode(&mut self, page: u8) {
        let sel = (page as u16) << 8;
        self.segment(Seg::Cs, (sel, 0x9b, 0xffff, (page as u64) << 12));
        for s in [Seg::Es, Seg::Ss, Seg::Ds, Seg::Fs, Seg::Gs] {
            self.segment(s, (0, 0x93, 0xffff, 0));
        }
        self.vmcs.write(vmcs::GUEST_IDTR_LIMIT, 0x3ff);
        self.set_cr0(0x10); // ET
        self.vmcs.write(vmcs::GUEST_RIP, 0);
        self.vmcs.write(vmcs::GUEST_RSP, 0);
    }

    /// Starts the guest in 64-bit mode instead, with paging on through the
    /// 4-level tables at guest-physical `cr3` (and NX enabled).
    pub fn set_long_mode(&mut self, cr3: u64) {
        self.segment(Seg::Cs, (0x08, 0xa09b, u32::MAX, 0)); // L = 1
        self.set_cr0(0x8001_0011); // PG, WP, ET, PE
        self.set_cr4(CR4_PAE);
        self.vmcs.write(vmcs::GUEST_CR3, cr3);
        self.vmcs.write(vmcs::GUEST_EFER, EFER_LME | EFER_LMA | 1 << 11); // LME, LMA, NXE
    }

    /// Translates a guest linear address through the guest's 4-level page
    /// tables (long mode), or returns it unchanged with paging off.
    pub fn translate(&self, linear: u64) -> Option<u64> {
        if self.cr0() & CR0_PG == 0 {
            return Some(linear);
        }
        if self.vmcs.read(vmcs::GUEST_EFER) & EFER_LMA == 0 {
            return None; // 32-bit paging is not walked
        }
        let mem = self.mem.as_ref()?;
        let mut table = self.vmcs.read(vmcs::GUEST_CR3) & 0x000f_ffff_ffff_f000;
        for level in (0..4).rev() {
            let index = (linear >> (12 + 9 * level)) & 0x1ff;
            let pte: u64 = mem.read_obj(GuestPhysAddr(table + index * 8)).ok()?;
            if pte & 1 == 0 {
                return None;
            }
            let addr = pte & 0x000f_ffff_ffff_f000;
            // A large page at level 1 (2 MiB) or 2 (1 GiB).
            if level == 0 || (level <= 2 && pte & (1 << 7) != 0) {
                let mask = (1u64 << (12 + 9 * level)) - 1;
                return Some((addr & !mask) | (linear & mask));
            }
            table = addr;
        }
        None
    }

    /// Lets the vCPU read instructions from guest memory to emulate MMIO.
    pub fn with_memory(mut self, mem: Arc<GuestMemory>) -> Self {
        self.mem = Some(mem);
        self
    }

    /// Reads general-purpose register `n` (0 = rax ... 15 = r15).
    pub fn reg(&self, n: u8) -> u64 {
        let r = &self.regs;
        match n {
            0 => r.rax,
            1 => r.rcx,
            2 => r.rdx,
            3 => r.rbx,
            4 => self.vmcs.read(vmcs::GUEST_RSP),
            5 => r.rbp,
            6 => r.rsi,
            7 => r.rdi,
            8 => r.r8,
            9 => r.r9,
            10 => r.r10,
            11 => r.r11,
            12 => r.r12,
            13 => r.r13,
            14 => r.r14,
            _ => r.r15,
        }
    }

    /// Writes general-purpose register `n`.
    pub fn set_reg(&mut self, n: u8, v: u64) {
        let r = &mut self.regs;
        let slot = match n {
            0 => &mut r.rax,
            1 => &mut r.rcx,
            2 => &mut r.rdx,
            3 => &mut r.rbx,
            4 => return self.vmcs.write(vmcs::GUEST_RSP, v),
            5 => &mut r.rbp,
            6 => &mut r.rsi,
            7 => &mut r.rdi,
            8 => &mut r.r8,
            9 => &mut r.r9,
            10 => &mut r.r10,
            11 => &mut r.r11,
            12 => &mut r.r12,
            13 => &mut r.r13,
            14 => &mut r.r14,
            _ => &mut r.r15,
        };
        *slot = v;
    }

    /// The default operand size of the code segment: 16, 32 or 64.
    fn code_bits(&self) -> u8 {
        let ar = self.seg_ar(Seg::Cs);
        let lma = self.vmcs.read(vmcs::GUEST_EFER) & EFER_LMA != 0;
        if lma && ar & (1 << 13) != 0 {
            64
        } else if ar & (1 << 14) != 0 {
            32
        } else {
            16
        }
    }

    /// The faulting instruction's bytes, from guest memory at CS.base + RIP.
    fn insn_bytes(&self) -> Option<([u8; 15], usize)> {
        let mut buf = [0u8; 15];
        let mem = self.mem.as_ref()?;
        // In 64-bit mode CS has no base.
        let base = if self.code_bits() == 64 { 0 } else { self.seg_base(Seg::Cs) };
        let linear = base.wrapping_add(self.rip());
        // Byte by byte through the guest's tables (the instruction may cross
        // a page); stop at the first byte that cannot be read.
        let mut n = 0;
        while n < 15 {
            let Some(gpa) = self.translate(linear + n as u64) else { break };
            if mem.read(GuestPhysAddr(gpa), &mut buf[n..n + 1]).is_err() {
                break;
            }
            n += 1;
        }
        (n > 0).then_some((buf, n))
    }

    /// Reads the value a byte/word/dword/qword register operand names.
    fn operand_value(&self, a: &Access) -> u64 {
        match a.operand {
            Operand::Imm(v) => v,
            Operand::Reg(r) if a.high_byte && (4..8).contains(&r) => self.reg(r - 4) >> 8,
            Operand::Reg(r) => self.reg(r),
        }
    }

    /// The vCPU's INTR line, for an interrupt controller to drive.
    pub fn irq_line(&self) -> Arc<AtomicBool> {
        self.irq.clone()
    }

    /// Uses `line` as the INTR line, for a controller created before the vCPU.
    pub fn with_irq_line(mut self, line: Arc<AtomicBool>) -> Self {
        self.irq = line;
        self
    }

    /// Sets how to acknowledge an interrupt when it is delivered (the INTA
    /// cycle): returns the vector.
    pub fn connect_intr(&mut self, ack: impl Fn() -> Option<u8> + Send + Sync + 'static) {
        self.ack = Some(Box::new(ack));
    }

    /// Whether a vCPU halted in `hlt` should run again: its INTR line is up
    /// and the guest has interrupts enabled.
    pub fn interrupt_pending(&self) -> bool {
        self.irq.load(Ordering::Acquire) && self.rflags() & RFLAGS_IF != 0
    }

    /// Marks this vCPU as an application processor: `IA32_APIC_BASE.BSP`
    /// reads as 0.
    pub fn set_application_processor(&mut self) {
        self.apic_base &= !APIC_BASE_BSP;
    }

    /// Gives the guest x87/SSE registers of its own, loaded before each
    /// entry and saved after it (FXSAVE/FXRSTOR), so several vCPUs can share
    /// a host CPU.
    pub fn with_fp_switching(mut self) -> Self {
        self.switch_fp = true;
        self
    }

    /// Sets the local APIC ID CPUID reports to the guest.
    pub fn set_apic_id(&mut self, id: u8) {
        self.apic_id = id;
    }

    /// Guest `rip`.
    pub fn rip(&self) -> u64 {
        self.vmcs.read(vmcs::GUEST_RIP)
    }

    /// Guest `rax`.
    pub fn rax(&self) -> u64 {
        self.regs.rax
    }

    /// Guest `rflags`.
    pub fn rflags(&self) -> u64 {
        self.vmcs.read(vmcs::GUEST_RFLAGS)
    }

    /// Reads a VMCS field of the guest's.
    pub fn read(&self, field: u32) -> u64 {
        self.vmcs.read(field)
    }

    /// Writes a VMCS field.
    pub fn write(&mut self, field: u32, v: u64) {
        self.vmcs.write(field, v);
    }

    /// Physical address of the VMCS.
    pub fn vmcs_pa(&self) -> u64 {
        self.vmcs.pa
    }

    /// The VM-instruction error after a failed VM entry.
    pub fn instruction_error(&self) -> u64 {
        self.vmcs.read(vmcs::INSN_ERROR)
    }

    /// Moves the guest past an instruction the hypervisor completed for it.
    /// Like the CPU retiring it, this ends an STI or MOV SS interrupt shadow
    /// (`sti; hlt` would otherwise never let an interrupt in).
    fn skip_to(&mut self, rip: u64) {
        self.vmcs.write(vmcs::GUEST_RIP, rip);
        let i = self.vmcs.read(vmcs::GUEST_INTERRUPTIBILITY);
        self.vmcs.write(vmcs::GUEST_INTERRUPTIBILITY, i & !3);
    }

    /// Moves the guest past the instruction that exited, by its length.
    fn skip(&mut self) {
        let len = self.vmcs.read(vmcs::EXIT_INSN_LEN);
        let rip = self.rip();
        self.skip_to(rip.wrapping_add(len));
    }

    fn inject_gp(&mut self) {
        self.pending_exception = Some(GP);
    }

    /// Prepares the next entry: the IA-32e control follows the guest's
    /// EFER.LMA, and interrupt delivery is arranged: an event whose delivery
    /// the last exit interrupted is injected again; otherwise a queued
    /// exception, or the PIC's interrupt if the guest can take it now, or
    /// else an exit is requested for when it can.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    fn prepare_entry(&mut self) {
        use vmcs::*;
        let lma = self.vmcs.read(GUEST_EFER) & EFER_LMA != 0;
        let entry = self.caps.entry | if lma { caps::entry_ctl::IA32E_GUEST } else { 0 };
        self.vmcs.write(ENTRY_CTLS, entry as u64);

        let mut window = false;
        let mut info = 0u64;
        let mut code = 0u64;
        let vectoring = self.vmcs.read(IDT_VECTORING_INFO);
        if !core::mem::replace(&mut self.vectoring_done, true)
            && vectoring & EVENT_VALID != 0
            && !(4..=6).contains(&(vectoring >> 8 & 7))
        {
            // A software interrupt or exception is not injected again: RIP
            // still points at its instruction, which runs again.
            info = vectoring & 0xffff_ffff;
            code = self.vmcs.read(IDT_VECTORING_ERRCODE);
            window = self.irq.load(Ordering::Acquire);
        } else if let Some(e) = self.pending_exception.take() {
            info = e & 0xffff_ffff;
            code = e >> 32;
        } else if self.irq.load(Ordering::Acquire) {
            let open = self.rflags() & RFLAGS_IF != 0 && self.vmcs.read(GUEST_INTERRUPTIBILITY) & 3 == 0;
            if !open {
                window = true;
            } else if let Some(vector) = self.ack.as_ref().and_then(|a| a()) {
                info = vector as u64 | EVENT_VALID; // type 0: external interrupt
            }
        }
        self.vmcs.write(ENTRY_INTR_INFO, info);
        self.vmcs.write(ENTRY_ERRCODE, code);
        let proc = self.caps.proc | if window { caps::proc::INTERRUPT_WINDOW } else { 0 };
        self.vmcs.write(PROC_CTLS, proc as u64);
    }

    /// Answers the CPUID that caused a `CPUID` exit from the host's, as
    /// [`patch_cpuid`] adjusts it, and steps past it.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    fn emulate_cpuid(&mut self) {
        let (leaf, sub) = (self.regs.rax as u32, self.regs.rcx as u32);
        let r = osmium_arch::x86_64::cpuid(leaf, sub);
        let [a, b, c, d] = patch_cpuid(leaf, [r.eax, r.ebx, r.ecx, r.edx], self.apic_id);
        self.regs.rax = a as u64;
        self.regs.rbx = b as u64;
        self.regs.rcx = c as u64;
        self.regs.rdx = d as u64;
        self.skip();
    }

    /// Emulates the RDMSR or WRMSR that caused an `MSR` exit and steps past
    /// it. The syscall MSRs and `TSC_AUX` are in the MSR lists, the SYSENTER
    /// MSRs, FS/GS bases, PAT and EFER in the VMCS; APIC_BASE reports the
    /// xAPIC at its default address. Other MSRs read as zero and ignore
    /// writes. Values the CPU would refuse to load raise `#GP` in the guest.
    pub fn emulate_msr(&mut self) {
        use vmcs::*;
        let write = self.vmcs.read(EXIT_REASON) as u32 == exit::MSR_WRITE;
        let msr = self.regs.rcx as u32;
        let field = match msr {
            0xc000_0100 => Some(GUEST_BASE + 2 * Seg::Fs as u32),
            0xc000_0101 => Some(GUEST_BASE + 2 * Seg::Gs as u32),
            0x174 => Some(GUEST_SYSENTER_CS),
            0x175 => Some(GUEST_SYSENTER_ESP),
            0x176 => Some(GUEST_SYSENTER_EIP),
            0x277 => Some(GUEST_PAT),
            _ => None,
        };
        if write {
            let v = (self.regs.rax & 0xffff_ffff) | self.regs.rdx << 32;
            // EFER: SCE, LME, NXE; LMA only follows paging, and LME cannot
            // change while paging is on.
            const EFER_WRITABLE: u64 = 1 | EFER_LME | 1 << 11;
            let efer = self.vmcs.read(GUEST_EFER);
            let pat_ok = |v: u64| v.to_le_bytes().iter().all(|&t| matches!(t, 0 | 1 | 4 | 5 | 6 | 7));
            let bad = match msr {
                0xc000_0080 => {
                    v & !(EFER_WRITABLE | EFER_LMA) != 0 || (self.cr0() & CR0_PG != 0 && (v ^ efer) & EFER_LME != 0)
                }
                0x277 => !pat_ok(v),
                0xc000_0082 | 0xc000_0102 | 0xc000_0100 | 0xc000_0101 | 0x175 | 0x176 => !canonical(v),
                _ => false,
            };
            if bad {
                self.inject_gp();
                return;
            }
            match msr {
                0xc000_0080 => self.vmcs.write(GUEST_EFER, (v & EFER_WRITABLE) | (efer & EFER_LMA)),
                0xc000_0103 => self.set_guest_area(msr, v & 0xffff_ffff),
                0xc000_0081 | 0xc000_0082 | 0xc000_0084 | 0xc000_0102 => self.set_guest_area(msr, v),
                0xc000_0083 => self.cstar = v,
                0x174 => self.vmcs.write(GUEST_SYSENTER_CS, v & 0xffff_ffff),
                0x1b => self.apic_base = (v & !APIC_BASE_BSP) | (self.apic_base & APIC_BASE_BSP),
                _ => {
                    if let Some(f) = field {
                        self.vmcs.write(f, v);
                    }
                }
            }
        } else {
            let v = match msr {
                0xc000_0080 => self.vmcs.read(GUEST_EFER),
                0xc000_0081 | 0xc000_0082 | 0xc000_0084 | 0xc000_0102 | 0xc000_0103 => self.area(msr),
                0xc000_0083 => self.cstar,
                0x1b => self.apic_base,
                _ => field.map_or(0, |f| self.vmcs.read(f)),
            };
            self.regs.rax = v & 0xffff_ffff;
            self.regs.rdx = v >> 32;
        }
        self.skip();
    }

    /// Emulates a MOV to or from CR0, CR4 or CR8, CLTS or LMSW. Returns
    /// whether it did; CR3 does not exit under EPT.
    pub fn emulate_cr(&mut self) -> bool {
        let q = self.vmcs.read(vmcs::EXIT_QUAL);
        let (cr, ty, gpr) = (q & 0xf, q >> 4 & 3, (q >> 8 & 0xf) as u8);
        let cr0 = self.cr0();
        match (ty, cr) {
            (0, 0) => self.write_cr0(self.reg(gpr)),
            (0, 4) => self.write_cr4(self.reg(gpr)),
            (0, 8) => {
                let v = self.reg(gpr);
                if v > 0xf {
                    self.inject_gp();
                    return true;
                }
                self.cr8 = v;
            }
            (1, 8) => self.set_reg(gpr, self.cr8),
            (2, _) => self.set_cr0(cr0 & !8),
            // LMSW loads the low four bits, but cannot clear PE.
            (3, _) => self.write_cr0((cr0 & !0xe) | (q >> 16 & 0xe) | (cr0 | q >> 16) & 1),
            _ => return false,
        }
        if self.pending_exception.is_none() {
            self.skip();
        }
        true
    }

    fn write_cr0(&mut self, v: u64) {
        use vmcs::*;
        let old = self.cr0();
        let efer = self.vmcs.read(GUEST_EFER);
        let pg = v & CR0_PG != 0;
        let nw_without_cd = v & (1 << 29) != 0 && v & (1 << 30) == 0;
        let long_without_pae = pg && efer & EFER_LME != 0 && self.cr4() & CR4_PAE == 0;
        if v >> 32 != 0
            || v & !self.caps.cr0_fixed1 != 0
            || (pg && v & CR0_PE == 0)
            || nw_without_cd
            || long_without_pae
        {
            return self.inject_gp();
        }
        if pg && old & CR0_PG == 0 && efer & EFER_LME != 0 {
            self.vmcs.write(GUEST_EFER, efer | EFER_LMA);
        } else if !pg && old & CR0_PG != 0 {
            self.vmcs.write(GUEST_EFER, efer & !EFER_LMA);
        }
        self.set_cr0(v);
    }

    fn write_cr4(&mut self, v: u64) {
        let lma = self.vmcs.read(vmcs::GUEST_EFER) & EFER_LMA != 0;
        // The guest has no VMX (CPUID says so).
        if v >> 32 != 0 || v & !self.caps.cr4_fixed1 != 0 || v & CR4_VMXE != 0 || (lma && v & CR4_PAE == 0) {
            return self.inject_gp();
        }
        self.set_cr4(v);
    }

    /// Emulates the debug-register access that caused a `MOV DR` exit and
    /// steps past it. Breakpoint addresses (DR0-DR3) read as zero and
    /// ignore writes, and no breakpoint ever fires; DR6 and DR7 are kept.
    fn emulate_dr(&mut self) {
        let q = self.vmcs.read(vmcs::EXIT_QUAL);
        let (dr, read, gpr) = (q & 7, q & 0x10 != 0, (q >> 8 & 0xf) as u8);
        if read {
            let v = match dr {
                6 | 4 => self.dr6,
                7 | 5 => self.dr7,
                _ => 0,
            };
            self.set_reg(gpr, v);
        } else {
            let v = self.reg(gpr);
            match dr {
                6 | 4 => self.dr6 = 0xffff_0ff0 | (v & 0xe00f),
                7 | 5 => self.dr7 = (v & 0xffff_ffff) | 0x400,
                _ => {}
            }
        }
        self.skip();
    }

    /// Handles the exits the guest must never see the host for: VMX
    /// instructions, `XSETBV`, `MWAIT`/`MONITOR` and `RDPMC` raise `#UD`,
    /// `INVD` and `WBINVD` retire as no-ops, `VMCALL` outside ring 0 raises
    /// `#UD`, and intercepted `#DB`/`#AC` are reflected back. Returns whether
    /// it did.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    fn reflect(&mut self, code: u32) -> bool {
        match code {
            exit::VMCLEAR..=exit::VMXON
            | exit::INVEPT
            | exit::INVVPID
            | exit::XSETBV
            | exit::MWAIT
            | exit::MONITOR
            | exit::RDPMC => self.pending_exception = Some(UD),
            exit::DR_ACCESS => self.emulate_dr(),
            exit::INVD | exit::WBINVD => self.skip(),
            exit::VMCALL if self.cpl() != 0 => self.pending_exception = Some(UD),
            exit::EXCEPTION_NMI => {
                let info = self.vmcs.read(vmcs::EXIT_INTR_INFO);
                match (info >> 8 & 7, info & 0xff) {
                    (3, 1) => {
                        let q = self.vmcs.read(vmcs::EXIT_QUAL);
                        self.dr6 = 0xffff_0ff0 | (q & 0x600f);
                        self.pending_exception = Some(1 | 3 << 8 | EVENT_VALID);
                    }
                    (3, 17) => {
                        // #AC has an error code (always 0).
                        let e = self.vmcs.read(vmcs::EXIT_INTR_ERRCODE) & 0xffff_ffff;
                        self.pending_exception = Some(17 | 3 << 8 | 1 << 11 | EVENT_VALID | e << 32);
                    }
                    _ => return false,
                }
            }
            _ => return false,
        }
        true
    }

    /// The guest's current privilege level.
    fn cpl(&self) -> u64 {
        self.seg_ar(Seg::Ss) >> 5 & 3
    }

    /// Turns the VM exit recorded in the VMCS into an exit.
    pub fn classify(&mut self) -> VmExit {
        let raw = self.vmcs.read(vmcs::EXIT_REASON);
        let reason = raw as u32;
        if reason & exit::ENTRY_FAILURE != 0 {
            return VmExit::Unhandled { reason: raw & 0xffff_ffff };
        }
        let q = self.vmcs.read(vmcs::EXIT_QUAL);
        let len = self.vmcs.read(vmcs::EXIT_INSN_LEN);
        let rip = self.rip();
        match reason {
            exit::IO if q & (1 << 4) == 0 => {
                // Size - 1 (bits 2:0), direction (bit 3: in), port (bits 31:16).
                let size = (q & 7) as u8 + 1;
                let port = (q >> 16) as u16;
                if q & 8 != 0 {
                    self.pending_in = Some((size, rip.wrapping_add(len)));
                    VmExit::PioIn { port, size }
                } else {
                    let data = (self.rax() & (u32::MAX as u64 >> (32 - 8 * size as u32))) as u32;
                    self.skip();
                    VmExit::PioOut { port, size, data }
                }
            }
            exit::HLT => {
                self.skip();
                VmExit::Halt
            }
            exit::VMCALL => {
                self.skip();
                let r = &self.regs;
                VmExit::Hypercall { nr: r.rax, args: [r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.r8] }
            }
            // An access to an address nothing is mapped at (the entry grants
            // no permission at all).
            exit::EPT_VIOLATION if q & 3 != 0 && q & 0x38 == 0 => {
                let addr = GuestPhysAddr(self.vmcs.read(vmcs::GUEST_PHYS_ADDR));
                let Some(a) = self.insn_bytes().and_then(|(b, n)| decode::decode(&b[..n], self.code_bits())) else {
                    return VmExit::Unhandled { reason: reason as u64 };
                };
                if a.store {
                    let data = self.operand_value(&a) & (u64::MAX >> (64 - 8 * a.size as u32));
                    self.skip_to(rip.wrapping_add(a.len as u64));
                    VmExit::MmioWrite { addr, size: a.size, data }
                } else {
                    self.pending_mmio = Some(a);
                    VmExit::MmioRead { addr, size: a.size }
                }
            }
            exit::EXTERNAL_INTERRUPT => VmExit::ExternalInterrupt,
            exit::EXCEPTION_NMI if self.vmcs.read(vmcs::EXIT_INTR_INFO) >> 8 & 7 == 2 => VmExit::ExternalInterrupt,
            exit::TRIPLE_FAULT => VmExit::Shutdown,
            _ => VmExit::Unhandled { reason: reason as u64 },
        }
    }
}

/// The capabilities `enable` found.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
fn caps() -> Caps {
    *hw::CAPS.get().expect("vmx::enable ran")
}

/// A CPU that allows everything.
#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
fn caps() -> Caps {
    Caps::permissive()
}

impl Vcpu for VmxVcpu {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    fn run(&mut self) -> VmExit {
        if let Some(r) = &self.running {
            r.store(osmium_arch::cpu::current_id(), Ordering::Release);
        }
        let exit = loop {
            self.prepare_entry();
            if hw::run(self).is_err() {
                break VmExit::Unhandled { reason: u64::MAX };
            }
            self.vectoring_done = false;
            let raw = self.vmcs.read(vmcs::EXIT_REASON);
            if raw as u32 & exit::ENTRY_FAILURE != 0 {
                break self.classify();
            }
            match raw as u32 {
                exit::INTERRUPT_WINDOW => {}
                exit::MSR_READ | exit::MSR_WRITE => self.emulate_msr(),
                exit::CPUID => self.emulate_cpuid(),
                exit::CR_ACCESS if self.emulate_cr() => {}
                code => match self.reflect(code) {
                    true => {}
                    false => break self.classify(),
                },
            }
        };
        if let Some(r) = &self.running {
            r.store(crate::smp::NOT_RUNNING, Ordering::Release);
        }
        exit
    }

    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    fn run(&mut self) -> VmExit {
        unimplemented!("VMX guests need a bare-metal x86_64 build")
    }

    fn complete_read(&mut self, value: u64) {
        if let Some(a) = self.pending_mmio.take() {
            let value = value & (u64::MAX >> (64 - 8 * a.size as u32));
            if a.test {
                // TEST: flags from value & operand; CF and OF clear.
                let bits = 8 * a.size as u32;
                let r = value & self.operand_value(&a) & (u64::MAX >> (64 - bits));
                let (cf, pf, zf, sf, of) = (1 << 0, 1 << 2, 1 << 6, 1 << 7, 1 << 11);
                let mut f = self.rflags() & !(cf | pf | zf | sf | of);
                if (r as u8).count_ones() % 2 == 0 {
                    f |= pf;
                }
                if r == 0 {
                    f |= zf;
                }
                if r >> (bits - 1) & 1 != 0 {
                    f |= sf;
                }
                self.vmcs.write(vmcs::GUEST_RFLAGS, f);
                let rip = self.rip();
                self.skip_to(rip.wrapping_add(a.len as u64));
                return;
            }
            let Operand::Reg(r) = a.operand else { return };
            if a.high_byte && (4..8).contains(&r) {
                let old = self.reg(r - 4);
                self.set_reg(r - 4, (old & !0xff00) | value << 8);
            } else if a.dest_size >= 4 {
                // 32-bit destinations zero the upper half.
                self.set_reg(r, value);
            } else {
                let mask = u64::MAX >> (64 - 8 * a.dest_size as u32);
                let old = self.reg(r);
                self.set_reg(r, (old & !mask) | value);
            }
            let rip = self.rip();
            self.skip_to(rip.wrapping_add(a.len as u64));
            return;
        }
        if let Some((size, next)) = self.pending_in.take() {
            let mask = u64::MAX >> (64 - 8 * size as u32);
            // 32-bit results zero the upper half; 8/16-bit ones merge.
            let rax = if size == 4 { value & mask } else { (self.rax() & !mask) | (value & mask) };
            self.regs.rax = rax;
            self.skip_to(next);
        }
    }

    fn complete_hypercall(&mut self, ret: u64) {
        self.regs.rax = ret;
    }
}

#[cfg(test)]
mod tests;
