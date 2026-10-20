//! An AMD SVM vCPU.
//!
//! [`SvmVcpu`] owns a VMCB and runs a guest with nested paging (NPT). Every
//! I/O port and MSR access is intercepted. Exits become a [`VmExit`]:
//!
//! | `#VMEXIT` code | Exit |
//! |---|---|
//! | `IOIO` (non-string) | [`VmExit::PioIn`] / [`VmExit::PioOut`] |
//! | `HLT` | [`VmExit::Halt`] |
//! | `VMMCALL` | [`VmExit::Hypercall`]: `nr` = `rax`, `args` = `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `r8` |
//! | Nested page fault on an unmapped page | [`VmExit::MmioRead`] / [`VmExit::MmioWrite`], from the instruction ([`decode`]) |
//! | `INTR` | [`VmExit::ExternalInterrupt`] |
//! | `SHUTDOWN` (triple fault) | [`VmExit::Shutdown`] |
//! | Anything else | [`VmExit::Unhandled`] with the exit code |
//!
//! FS, GS, TR, LDTR, `KernelGsBase` and the syscall MSRs are switched with
//! VMLOAD/VMSAVE around every run, keeping the host's in a page of its own.
//! Guests start in 32-bit protected mode ([`SvmVcpu::new`]), in real mode
//! like an AP after STARTUP ([`SvmVcpu::set_real_mode`]) or, after
//! [`SvmVcpu::set_long_mode`], in 64-bit mode on their own page tables;
//! MMIO instructions are fetched through those tables when the CPU has no
//! decode assists.

pub mod decode;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod hw;
pub mod pc;
pub mod vmx;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use hw::{SvmError, enable};

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::memory::{GuestMemory, GuestPhysAddr};
use crate::vcpu::{Vcpu, VmExit};
use decode::{Access, Operand};

/// An FXSAVE/FXRSTOR image: x87, MMX and SSE state.
#[repr(C, align(16))]
pub(crate) struct FxArea(pub(crate) [u8; 512]);

impl FxArea {
    /// The state after reset: x87 control word 0x37f, MXCSR 0x1f80.
    fn reset() -> Self {
        let mut a = [0u8; 512];
        a[0..2].copy_from_slice(&0x037fu16.to_le_bytes());
        a[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        Self(a)
    }
}

/// `IA32_APIC_BASE`: the bootstrap processor, and the APIC enabled.
const APIC_BASE_BSP: u64 = 1 << 8;
const APIC_BASE_ENABLE: u64 = 1 << 11;

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

/// VMCB offsets (AMD64 APM vol. 2, appendix B).
pub mod vmcb {
    /// Intercepted debug-register reads (bits 15:0) and writes (31:16).
    pub const INTERCEPT_DR: usize = 0x004;
    /// Intercepted exceptions (bit per vector).
    pub const INTERCEPT_EXCEPTIONS: usize = 0x008;
    /// Intercepts: INTR, NMI, ... SHUTDOWN (bit per event).
    pub const INTERCEPT_MISC1: usize = 0x00c;
    /// Intercepts: VMRUN, VMMCALL, ...
    pub const INTERCEPT_MISC2: usize = 0x010;
    /// Physical address of the I/O permission map.
    pub const IOPM_BASE_PA: usize = 0x040;
    /// Physical address of the MSR permission map.
    pub const MSRPM_BASE_PA: usize = 0x048;
    /// Guest ASID.
    pub const GUEST_ASID: usize = 0x058;
    /// TLB control (1 = flush everything on VMRUN).
    pub const TLB_CONTROL: usize = 0x05c;
    /// Virtual interrupt control: V_IRQ (bit 8), V_INTR_MASKING (bit 24),
    /// vector (bits 39:32).
    pub const V_INTR: usize = 0x060;
    /// Interrupt shadow (bit 0): the guest just executed STI or MOV SS.
    pub const INT_STATE: usize = 0x068;
    /// Exit code.
    pub const EXITCODE: usize = 0x070;
    /// Exit information 1.
    pub const EXITINFO1: usize = 0x078;
    /// Exit information 2.
    pub const EXITINFO2: usize = 0x080;
    /// An event whose delivery the exit interrupted.
    pub const EXITINTINFO: usize = 0x088;
    /// Nested paging enable (bit 0).
    pub const NP_ENABLE: usize = 0x090;
    /// Event to inject on the next VMRUN.
    pub const EVENTINJ: usize = 0x0a8;
    /// Nested page table root (N_CR3).
    pub const N_CR3: usize = 0x0b0;
    /// Clean bits.
    pub const CLEAN: usize = 0x0c0;
    /// Save area: segment registers, 16 bytes each.
    pub const ES: usize = 0x400;
    /// CS.
    pub const CS: usize = 0x410;
    /// SS.
    pub const SS: usize = 0x420;
    /// DS.
    pub const DS: usize = 0x430;
    /// FS.
    pub const FS: usize = 0x440;
    /// GS.
    pub const GS: usize = 0x450;
    /// GDTR.
    pub const GDTR: usize = 0x460;
    /// LDTR.
    pub const LDTR: usize = 0x470;
    /// IDTR.
    pub const IDTR: usize = 0x480;
    /// TR.
    pub const TR: usize = 0x490;
    /// Current privilege level.
    pub const CPL: usize = 0x4cb;
    /// EFER.
    pub const EFER: usize = 0x4d0;
    /// CR4.
    pub const CR4: usize = 0x548;
    /// CR3.
    pub const CR3: usize = 0x550;
    /// CR0.
    pub const CR0: usize = 0x558;
    /// DR7.
    pub const DR7: usize = 0x560;
    /// DR6.
    pub const DR6: usize = 0x568;
    /// RFLAGS.
    pub const RFLAGS: usize = 0x570;
    /// RIP.
    pub const RIP: usize = 0x578;
    /// RSP.
    pub const RSP: usize = 0x5d8;
    /// RAX.
    pub const RAX: usize = 0x5f8;
    /// Guest PAT.
    pub const G_PAT: usize = 0x668;
    /// STAR, LSTAR, CSTAR, SFMASK, KernelGsBase (switched by VMLOAD/VMSAVE).
    pub const STAR: usize = 0x600;
    /// LSTAR.
    pub const LSTAR: usize = 0x608;
    /// CSTAR.
    pub const CSTAR: usize = 0x610;
    /// SFMASK.
    pub const SFMASK: usize = 0x618;
    /// KernelGsBase.
    pub const KERNEL_GS_BASE: usize = 0x620;
    /// SYSENTER_CS, _ESP, _EIP.
    pub const SYSENTER_CS: usize = 0x628;
    /// Instruction bytes fetched by decode assists: count, then 15 bytes.
    pub const INSN_LEN: usize = 0x0d0;
    /// The fetched bytes.
    pub const INSN_BYTES: usize = 0x0d1;
}

/// `#VMEXIT` codes.
pub mod exit {
    /// Exception with vector `v`: `EXCEPTION + v`.
    pub const EXCEPTION: u64 = 0x40;
    /// Physical interrupt.
    pub const INTR: u64 = 0x60;
    /// Physical NMI.
    pub const NMI: u64 = 0x61;
    /// INVD.
    pub const INVD: u64 = 0x76;
    /// INVLPGA.
    pub const INVLPGA: u64 = 0x7a;
    /// VMRUN.
    pub const VMRUN: u64 = 0x80;
    /// VMLOAD, VMSAVE, STGI, CLGI, SKINIT.
    pub const VMLOAD: u64 = 0x82;
    /// SKINIT, the last SVM instruction.
    pub const SKINIT: u64 = 0x86;
    /// XSETBV.
    pub const XSETBV: u64 = 0x8d;
    /// MOV from DR0 (DRn: + n); MOV to DR0 is `DR_READ + 0x10`.
    pub const DR_READ: u64 = 0x20;
    /// The guest can take a virtual interrupt (interrupt window).
    pub const VINTR: u64 = 0x64;
    /// CPUID.
    pub const CPUID: u64 = 0x72;
    /// HLT.
    pub const HLT: u64 = 0x78;
    /// I/O port access.
    pub const IOIO: u64 = 0x7b;
    /// RDMSR/WRMSR.
    pub const MSR: u64 = 0x7c;
    /// Triple fault.
    pub const SHUTDOWN: u64 = 0x7f;
    /// VMMCALL.
    pub const VMMCALL: u64 = 0x81;
    /// Nested page fault.
    pub const NPF: u64 = 0x400;
    /// VMRUN failed its consistency checks.
    pub const INVALID: u64 = u64::MAX;
}

/// `EFER.SVME`, which must also be set in the guest's EFER.
pub const EFER_SVME: u64 = 1 << 12;

/// Guest general-purpose registers other than `rax` and `rsp` (which live
/// in the VMCB), followed by the host's callee-saved registers. The layout
/// is shared with the world-switch assembly.
#[repr(C)]
#[derive(Clone, Debug, Default)]
#[allow(missing_docs)]
pub struct GuestRegs {
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

/// Memory the vCPU needs from the host: a VMCB page, a 12 KiB I/O
/// permission map and an 8 KiB MSR permission map, each physically
/// contiguous and page aligned, given as (host pointer, physical address).
pub struct SvmPages {
    /// The VMCB.
    pub vmcb: (NonNull<u8>, u64),
    /// The I/O permission map (3 pages).
    pub iopm: (NonNull<u8>, u64),
    /// The MSR permission map (2 pages).
    pub msrpm: (NonNull<u8>, u64),
    /// A page where VMSAVE keeps the host's FS, GS, TR, LDTR and syscall
    /// state while the guest runs.
    pub host: (NonNull<u8>, u64),
}

type Ack = Box<dyn Fn() -> Option<u8> + Send + Sync>;

const INTERCEPT_VINTR: u32 = 1 << 4;
const EVENT_VALID: u64 = 1 << 31;
const RFLAGS_IF: u64 = 1 << 9;

/// A virtual x86 CPU on AMD SVM.
pub struct SvmVcpu {
    vmcb: NonNull<u8>,
    vmcb_pa: u64,
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    host_pa: u64,
    /// General-purpose registers other than `rax`/`rsp`.
    pub regs: GuestRegs,
    pending_in: Option<u8>,
    pending_mmio: Option<Access>,
    mem: Option<Arc<GuestMemory>>,
    irq: Arc<AtomicBool>,
    ack: Option<Ack>,
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    flush: bool,
    /// The guest's x87/SSE state (an FXSAVE image), loaded around VMRUN.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    pub(crate) fpu: Box<FxArea>,
    /// The guest's `IA32_TSC_AUX`, swapped in around VMRUN.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    pub(crate) tsc_aux: u64,
    /// The guest's `IA32_APIC_BASE`.
    apic_base: u64,
    /// The local APIC ID CPUID reports.
    apic_id: u8,
    /// An exception to raise in the guest at the next entry (EVENTINJ form).
    pending_exception: Option<u64>,
    /// Whether `fpu` is switched around VMRUN.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    pub(crate) switch_fp: bool,
    /// The host CPU running this vCPU's guest code, for kicks.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    pub(crate) running: Option<Arc<core::sync::atomic::AtomicUsize>>,
}

// SAFETY: the vCPU owns its VMCB page exclusively.
unsafe impl Send for SvmVcpu {}

impl SvmVcpu {
    /// A vCPU in 32-bit protected mode with paging off and flat 4 GiB
    /// segments, starting at `entry` with stack `rsp`, translating guest
    /// physical addresses through the nested table at `ncr3` (an
    /// `X86_64`-format table whose entries have `USER` set). Intercepts
    /// every I/O port and MSR.
    ///
    /// # Safety
    /// `pages` must be valid, exclusively owned memory of the stated sizes
    /// that outlives the vCPU.
    pub unsafe fn new(pages: SvmPages, ncr3: u64, entry: u32, rsp: u32) -> Self {
        // SAFETY: the caller hands over the pages.
        unsafe {
            pages.vmcb.0.as_ptr().write_bytes(0, 4096);
            pages.iopm.0.as_ptr().write_bytes(0xff, 3 * 4096);
            pages.msrpm.0.as_ptr().write_bytes(0xff, 2 * 4096);
        }
        let mut v = Self {
            vmcb: pages.vmcb.0,
            vmcb_pa: pages.vmcb.1,
            host_pa: pages.host.1,
            regs: GuestRegs::default(),
            pending_in: None,
            pending_mmio: None,
            mem: None,
            irq: Arc::new(AtomicBool::new(false)),
            ack: None,
            flush: true,
            running: None,
            tsc_aux: 0,
            fpu: Box::new(FxArea::reset()),
            apic_base: 0xfee0_0000 | APIC_BASE_ENABLE | APIC_BASE_BSP,
            apic_id: 0,
            switch_fp: false,
            pending_exception: None,
        };
        use vmcb::*;
        // INTR, NMI, CPUID, INVD, HLT, INVLPGA, IOIO, MSR, SHUTDOWN; and every
        // SVM instruction: VMRUN (required), VMMCALL, VMLOAD, VMSAVE, STGI,
        // CLGI, SKINIT. Unintercepted, VMLOAD/VMSAVE would reach host
        // memory, CLGI would take the host CPU, and INVD would discard the
        // host's dirty cache lines.
        let misc1 = 1 << 0 | 1 << 1 | 1 << 18 | 1 << 22 | 1 << 24 | 1 << 26 | 1 << 27 | 1 << 28 | 1 << 31;
        v.write32(INTERCEPT_MISC1, misc1);
        // XSETBV too: the guest is not offered XSAVE (XCR0 is the host's).
        v.write32(INTERCEPT_MISC2, 0x7f | 1 << 13);
        // DR0-DR3 reads and writes (DR6/DR7 are in the VMCB): no breakpoint
        // addresses pass between VMs or to the host.
        v.write32(INTERCEPT_DR, 0x000f_000f);
        // #DB and #AC: a guest whose delivery of these faults loops would
        // otherwise hold the host CPU forever; they are reflected back.
        v.write32(INTERCEPT_EXCEPTIONS, 1 << 1 | 1 << 17);
        v.write64(IOPM_BASE_PA, pages.iopm.1);
        v.write64(MSRPM_BASE_PA, pages.msrpm.1);
        v.write32(GUEST_ASID, 1);
        v.write64(V_INTR, 1 << 24); // V_INTR_MASKING
        v.write64(NP_ENABLE, 1);
        v.write64(N_CR3, ncr3);
        let code = (0x08, 0xc9b, u32::MAX, 0); // 32-bit, readable, accessed, G
        let data = (0x10, 0xc93, u32::MAX, 0);
        v.segment(CS, code);
        for s in [ES, SS, DS, FS, GS] {
            v.segment(s, data);
        }
        v.segment(GDTR, (0, 0, 0xffff, 0));
        v.segment(IDTR, (0, 0, 0xffff, 0));
        v.segment(LDTR, (0, 0x82, 0xffff, 0));
        v.segment(TR, (0, 0x8b, 0xffff, 0));
        v.write64(CR0, 0x11); // PE, ET
        v.write64(EFER, EFER_SVME);
        v.write64(RFLAGS, 2);
        v.write64(RIP, entry as u64);
        v.write64(RSP, rsp as u64);
        v.write64(DR6, 0xffff_0ff0);
        v.write64(DR7, 0x400);
        v.write64(G_PAT, 0x0007_0406_0007_0406);
        v
    }

    fn at(&self, off: usize) -> *mut u8 {
        // SAFETY: offsets are inside the 4 KiB VMCB.
        unsafe { self.vmcb.as_ptr().add(off) }
    }

    /// Reads a 64-bit VMCB field.
    pub fn read64(&self, off: usize) -> u64 {
        // SAFETY: an aligned field of the owned VMCB.
        unsafe { self.at(off).cast::<u64>().read_volatile() }
    }

    /// Writes a 64-bit VMCB field.
    pub fn write64(&mut self, off: usize, v: u64) {
        // SAFETY: as above.
        unsafe { self.at(off).cast::<u64>().write_volatile(v) }
    }

    fn write32(&mut self, off: usize, v: u32) {
        // SAFETY: as above.
        unsafe { self.at(off).cast::<u32>().write_volatile(v) }
    }

    /// Sets a segment register: (selector, attributes, limit, base).
    pub fn segment(&mut self, off: usize, (sel, attr, limit, base): (u16, u16, u32, u64)) {
        // SAFETY: a 16-byte segment field of the owned VMCB.
        unsafe {
            self.at(off).cast::<u16>().write_volatile(sel);
            self.at(off + 2).cast::<u16>().write_volatile(attr);
            self.at(off + 4).cast::<u32>().write_volatile(limit);
            self.at(off + 8).cast::<u64>().write_volatile(base);
        }
    }

    /// Starts the guest in real mode instead, at `page << 12` (CS =
    /// `page << 8`, IP = 0): the state a STARTUP IPI with vector `page`
    /// leaves an application processor in. The real-mode IDT is at 0.
    pub fn set_real_mode(&mut self, page: u8) {
        let sel = (page as u16) << 8;
        self.segment(vmcb::CS, (sel, 0x9b, 0xffff, (page as u64) << 12));
        for s in [vmcb::ES, vmcb::SS, vmcb::DS, vmcb::FS, vmcb::GS] {
            self.segment(s, (0, 0x93, 0xffff, 0));
        }
        self.segment(vmcb::IDTR, (0, 0, 0x3ff, 0));
        self.write64(vmcb::CR0, 0x10); // ET
        self.write64(vmcb::RIP, 0);
        self.write64(vmcb::RSP, 0);
    }

    /// Starts the guest in 64-bit mode instead, with paging on through the
    /// 4-level tables at guest-physical `cr3` (and NX enabled).
    pub fn set_long_mode(&mut self, cr3: u64) {
        self.segment(vmcb::CS, (0x08, 0xa9b, u32::MAX, 0)); // L = 1
        self.write64(vmcb::CR0, 0x8001_0011); // PG, WP, ET, PE
        self.write64(vmcb::CR4, 1 << 5); // PAE
        self.write64(vmcb::CR3, cr3);
        self.write64(vmcb::EFER, EFER_SVME | 1 << 8 | 1 << 10 | 1 << 11); // LME, LMA, NXE
    }

    /// Translates a guest linear address through the guest's 4-level page
    /// tables (long mode), or returns it unchanged with paging off.
    pub fn translate(&self, linear: u64) -> Option<u64> {
        if self.read64(vmcb::CR0) & (1 << 31) == 0 {
            return Some(linear);
        }
        if self.read64(vmcb::EFER) & (1 << 10) == 0 {
            return None; // 32-bit paging is not walked
        }
        let mem = self.mem.as_ref()?;
        let mut table = self.read64(vmcb::CR3) & 0x000f_ffff_ffff_f000;
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

    /// Lets the vCPU read instructions from guest memory to emulate MMIO
    /// when the CPU has no decode assists (guest paging must be off).
    pub fn with_memory(mut self, mem: Arc<GuestMemory>) -> Self {
        self.mem = Some(mem);
        self
    }

    /// Reads general-purpose register `n` (0 = rax ... 15 = r15).
    pub fn reg(&self, n: u8) -> u64 {
        let r = &self.regs;
        match n {
            0 => self.rax(),
            1 => r.rcx,
            2 => r.rdx,
            3 => r.rbx,
            4 => self.read64(vmcb::RSP),
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
            0 => None,
            4 => None,
            1 => Some(&mut r.rcx),
            2 => Some(&mut r.rdx),
            3 => Some(&mut r.rbx),
            5 => Some(&mut r.rbp),
            6 => Some(&mut r.rsi),
            7 => Some(&mut r.rdi),
            8 => Some(&mut r.r8),
            9 => Some(&mut r.r9),
            10 => Some(&mut r.r10),
            11 => Some(&mut r.r11),
            12 => Some(&mut r.r12),
            13 => Some(&mut r.r13),
            14 => Some(&mut r.r14),
            _ => Some(&mut r.r15),
        };
        match slot {
            Some(s) => *s = v,
            None => self.write64(if n == 0 { vmcb::RAX } else { vmcb::RSP }, v),
        }
    }

    /// The default operand size of the code segment: 16, 32 or 64.
    fn code_bits(&self) -> u8 {
        let attr = self.read64(vmcb::CS) >> 16 & 0xfff;
        let lma = self.read64(vmcb::EFER) & (1 << 10) != 0;
        if lma && attr & (1 << 9) != 0 {
            64
        } else if attr & (1 << 10) != 0 {
            32
        } else {
            16
        }
    }

    /// The faulting instruction's bytes: from decode assists, or from guest
    /// memory at CS.base + RIP while paging is off.
    fn insn_bytes(&self) -> Option<([u8; 15], usize)> {
        let mut buf = [0u8; 15];
        // SAFETY: the decode-assist bytes are inside the VMCB.
        let n = unsafe { self.at(vmcb::INSN_LEN).read_volatile() } as usize;
        if n > 0 {
            for (i, b) in buf.iter_mut().enumerate().take(n.min(15)) {
                // SAFETY: as above.
                *b = unsafe { self.at(vmcb::INSN_BYTES + i).read_volatile() };
            }
            return Some((buf, n.min(15)));
        }
        self.fetch_insn()
    }

    /// The instruction at CS.base + RIP, read from guest memory through the
    /// guest's tables (never from the decode-assist bytes, which hardware
    /// writes only for nested and ordinary page faults).
    fn fetch_insn(&self) -> Option<([u8; 15], usize)> {
        let mut buf = [0u8; 15];
        let mem = self.mem.as_ref()?;
        // In 64-bit mode CS has no base; otherwise addresses wrap at 4 GiB.
        let (base, wrap) =
            if self.code_bits() == 64 { (0, u64::MAX) } else { (self.read64(vmcb::CS + 8), u32::MAX as u64) };
        // CS.base + RIP is guest-chosen: wrap rather than overflow.
        let linear = base.wrapping_add(self.rip()) & wrap;
        // Byte by byte through the guest's tables (the instruction may cross
        // a page); stop at the first byte that cannot be read.
        let mut n = 0;
        while n < 15 {
            let Some(gpa) = self.translate(linear.wrapping_add(n as u64) & wrap) else { break };
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

    /// The vCPU's INTR line, for an interrupt controller (a
    /// [`VirtualPic`](crate::devices::VirtualPic) output) to drive.
    pub fn irq_line(&self) -> Arc<AtomicBool> {
        self.irq.clone()
    }

    /// Uses `line` as the INTR line, for a controller created before the vCPU.
    pub fn with_irq_line(mut self, line: Arc<AtomicBool>) -> Self {
        self.irq = line;
        self
    }

    /// Sets how to acknowledge an interrupt when it is delivered (the INTA
    /// cycle): returns the vector, e.g. [`VirtualPic::acknowledge`](crate::devices::VirtualPic::acknowledge).
    pub fn connect_intr(&mut self, ack: impl Fn() -> Option<u8> + Send + Sync + 'static) {
        self.ack = Some(Box::new(ack));
    }

    /// Whether a vCPU halted in `hlt` should run again: its INTR line is up
    /// and the guest has interrupts enabled.
    pub fn interrupt_pending(&self) -> bool {
        self.irq.load(Ordering::Acquire) && self.read64(vmcb::RFLAGS) & RFLAGS_IF != 0
    }

    fn intercepts(&self) -> u32 {
        // SAFETY: a field of the owned VMCB.
        unsafe { self.at(vmcb::INTERCEPT_MISC1).cast::<u32>().read_volatile() }
    }

    /// Prepares interrupt delivery for the next entry: re-injects an event
    /// the last exit interrupted, injects the PIC's interrupt if the guest
    /// can take it now, or else asks for an exit when it can.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    fn prepare_interrupts(&mut self) {
        // An undelivered injection comes back in EXITINTINFO, never here.
        self.write64(vmcb::EVENTINJ, 0);
        let pending = self.read64(vmcb::EXITINTINFO);
        self.write64(vmcb::EXITINTINFO, 0);
        // A software interrupt (type 4) is not re-injected: RIP still points
        // at its INTn, which runs again.
        if pending & EVENT_VALID != 0 && (pending >> 8) & 7 != 4 {
            self.write64(vmcb::EVENTINJ, pending);
            return;
        }
        if let Some(e) = self.pending_exception.take() {
            self.write64(vmcb::EVENTINJ, e);
            return;
        }
        let mut window = false;
        if self.irq.load(Ordering::Acquire) {
            let open = self.read64(vmcb::RFLAGS) & RFLAGS_IF != 0 && self.read64(vmcb::INT_STATE) & 1 == 0;
            if open {
                if let Some(vector) = self.ack.as_ref().and_then(|a| a()) {
                    self.write64(vmcb::EVENTINJ, vector as u64 | EVENT_VALID); // type 0: external interrupt
                }
            } else {
                window = true;
            }
        }
        // A virtual interrupt is taken (and VINTR fires) only when V_INTR_PRIO
        // exceeds V_TPR, so the window request uses the highest priority.
        let v = self.read64(vmcb::V_INTR) & !(1 << 8);
        let v = if window { v & !(0xf << 16) | 1 << 8 | 0xf << 16 } else { v };
        self.write64(vmcb::V_INTR, v);
        let i = self.intercepts() & !INTERCEPT_VINTR;
        self.write32(vmcb::INTERCEPT_MISC1, if window { i | INTERCEPT_VINTR } else { i });
    }

    /// Marks this vCPU as an application processor: `IA32_APIC_BASE.BSP`
    /// reads as 0.
    pub fn set_application_processor(&mut self) {
        self.apic_base &= !APIC_BASE_BSP;
    }

    /// Gives the guest x87/SSE registers of its own, loaded before each
    /// VMRUN and saved after it (FXSAVE/FXRSTOR), so several vCPUs can
    /// share a host CPU. Without it the guest uses the host CPU's registers
    /// as they are, which suits one vCPU per host CPU on a soft-float host.
    pub fn with_fp_switching(mut self) -> Self {
        self.switch_fp = true;
        self
    }

    /// Sets the local APIC ID CPUID reports to the guest (leaf 1 EBX bits 31:24
    /// and leaf 0xB EDX); it should match the vCPU's emulated APIC.
    pub fn set_apic_id(&mut self, id: u8) {
        self.apic_id = id;
    }

    /// Answers the CPUID that caused a `CPUID` exit from the host's, as
    /// [`patch_cpuid`] adjusts it, and steps past it.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    fn emulate_cpuid(&mut self) {
        let (leaf, sub) = (self.read64(vmcb::RAX) as u32, self.regs.rcx as u32);
        let r = osmium_arch::x86_64::cpuid(leaf, sub);
        let [a, b, c, d] = patch_cpuid(leaf, [r.eax, r.ebx, r.ecx, r.edx], self.apic_id);
        self.write64(vmcb::RAX, a as u64);
        self.regs.rbx = b as u64;
        self.regs.rcx = c as u64;
        self.regs.rdx = d as u64;
        let rip = self.rip();
        self.skip_to(rip.wrapping_add(2)); // 0F A2
    }

    /// Emulates the RDMSR or WRMSR that caused an `MSR` exit and steps
    /// past it. The syscall MSRs, FS/GS bases and PAT live in the VMCB;
    /// EFER keeps SVME set (VMRUN requires it); TSC_AUX is per vCPU;
    /// APIC_BASE reports the xAPIC at its default address. Other MSRs read
    /// as zero and ignore writes.
    pub fn emulate_msr(&mut self) {
        use vmcb::*;
        let write = self.read64(EXITINFO1) & 1 != 0;
        let msr = self.regs.rcx as u32;
        let field = match msr {
            0xc000_0081 => Some(STAR),
            0xc000_0082 => Some(LSTAR),
            0xc000_0083 => Some(CSTAR),
            0xc000_0084 => Some(SFMASK),
            0xc000_0100 => Some(FS + 8),
            0xc000_0101 => Some(GS + 8),
            0xc000_0102 => Some(KERNEL_GS_BASE),
            0x174..=0x176 => Some(SYSENTER_CS + 8 * (msr - 0x174) as usize),
            0x277 => Some(G_PAT),
            _ => None,
        };
        if write {
            let v = (self.read64(RAX) & 0xffff_ffff) | self.regs.rdx << 32;
            // Values VMRUN would reject raise #GP in the guest instead.
            const EFER_VALID: u64 = 1 | 1 << 8 | 1 << 10 | 1 << 11 | 1 << 12 | 1 << 13 | 1 << 14 | 1 << 15;
            let pat_ok = |v: u64| v.to_le_bytes().iter().all(|&t| matches!(t, 0 | 1 | 4 | 5 | 6 | 7));
            if (msr == 0xc000_0080 && v & !EFER_VALID != 0) || (msr == 0x277 && !pat_ok(v)) {
                self.pending_exception = Some(13 | 3 << 8 | 1 << 11 | EVENT_VALID); // #GP(0)
                return;
            }
            match msr {
                0xc000_0080 => self.write64(EFER, v | EFER_SVME),
                0xc000_0103 => self.tsc_aux = v & 0xffff_ffff,
                0x1b => self.apic_base = (v & !APIC_BASE_BSP) | (self.apic_base & APIC_BASE_BSP),
                _ => {
                    if let Some(f) = field {
                        self.write64(f, v);
                    }
                }
            }
        } else {
            let v = match msr {
                0xc000_0080 => self.read64(EFER) & !EFER_SVME,
                0xc000_0103 => self.tsc_aux,
                0x1b => self.apic_base,
                _ => field.map_or(0, |f| self.read64(f)),
            };
            self.write64(RAX, v & 0xffff_ffff);
            self.regs.rdx = v >> 32;
        }
        let rip = self.rip();
        self.skip_to(rip.wrapping_add(2)); // RDMSR and WRMSR are 0F 32 and 0F 30
    }

    /// Moves the guest past an instruction the hypervisor completed for it.
    /// Like the CPU retiring it, this ends an STI or MOV SS interrupt shadow
    /// (`sti; hlt` would otherwise never let an interrupt in).
    fn skip_to(&mut self, rip: u64) {
        self.write64(vmcb::RIP, rip);
        self.write64(vmcb::INT_STATE, 0);
    }

    /// Requests a flush of the guest's TLB entries (`TLB_CONTROL`) on the
    /// next `VMRUN`. Call it after editing the guest's nested page tables:
    /// the CPU keeps nested translations across runs and only the first run
    /// flushes.
    pub fn flush_stage2(&mut self) {
        self.flush = true;
    }

    /// Physical address of the VMCB.
    pub fn vmcb_pa(&self) -> u64 {
        self.vmcb_pa
    }

    /// Guest `rax`.
    pub fn rax(&self) -> u64 {
        self.read64(vmcb::RAX)
    }

    /// Guest `rip`.
    pub fn rip(&self) -> u64 {
        self.read64(vmcb::RIP)
    }

    /// Requests (or withdraws) a virtual interrupt with `vector`, delivered
    /// when the guest has interrupts enabled.
    pub fn set_virtual_irq(&mut self, vector: Option<u8>) {
        let v = self.read64(vmcb::V_INTR) & !(1 << 8 | 0xff << 32);
        let v = match vector {
            Some(vec) => v | 1 << 8 | 0xf << 16 | (vec as u64) << 32,
            None => v,
        };
        self.write64(vmcb::V_INTR, v);
    }

    /// Handles the exits the guest must never see the host for: SVM
    /// instructions (and VMMCALL outside ring 0) raise #UD in the guest,
    /// INVD retires as a no-op, and intercepted #DB/#AC are reflected
    /// back. Returns whether it did.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    fn reflect(&mut self, code: u64) -> bool {
        const UD: u64 = 6 | 3 << 8 | EVENT_VALID; // #UD, type 3 (exception)
        let cpl = self.read64(vmcb::CPL & !7) >> (8 * (vmcb::CPL & 7)) & 3;
        match code {
            exit::VMRUN | exit::INVLPGA | exit::VMLOAD..=exit::SKINIT | exit::XSETBV => {
                self.pending_exception = Some(UD)
            }
            // MOV to or from DR0-DR3: read as zero, writes ignored.
            c if (exit::DR_READ..exit::DR_READ + 0x20).contains(&c) => {
                let read = c < exit::DR_READ + 0x10;
                // Decode assists write INSN_BYTES only for #NPF and #PF, so
                // for a DR intercept it is stale: fetch from guest memory.
                let Some((b, n)) = self.fetch_insn() else { return false };
                // [REX] 0F 21/23 modrm: the GPR is modrm.rm (+ REX.B).
                let (rex, i) = if n > 0 && b[0] & 0xf0 == 0x40 { (b[0], 1) } else { (0, 0) };
                if n < i + 3 || b[i] != 0x0f {
                    return false;
                }
                if read {
                    let r = (b[i + 2] & 7) | (rex & 1) << 3;
                    self.set_reg(r, 0);
                }
                let rip = self.rip();
                self.skip_to(rip.wrapping_add(i as u64 + 3));
            }
            exit::VMMCALL if cpl != 0 => self.pending_exception = Some(UD),
            exit::INVD => {
                let rip = self.rip();
                self.skip_to(rip.wrapping_add(2)); // 0F 08
            }
            c if c == exit::EXCEPTION + 1 => self.pending_exception = Some(1 | 3 << 8 | EVENT_VALID),
            c if c == exit::EXCEPTION + 17 => {
                // #AC has an error code (always 0).
                let e = self.read64(vmcb::EXITINFO1) & 0xffff_ffff;
                self.pending_exception = Some(17 | 3 << 8 | 1 << 11 | EVENT_VALID | e << 32);
            }
            _ => return false,
        }
        true
    }

    /// Turns the `#VMEXIT` recorded in the VMCB into an exit.
    pub fn classify(&mut self) -> VmExit {
        let code = self.read64(vmcb::EXITCODE);
        let info1 = self.read64(vmcb::EXITINFO1);
        let rip = self.rip();
        match code {
            exit::IOIO if info1 & (1 << 2) == 0 => {
                // TYPE (bit 0: in), SZ8/16/32 (bits 4-6), port (bits 31:16).
                let size = ((info1 >> 4) & 7) as u8;
                let port = (info1 >> 16) as u16;
                let next = self.read64(vmcb::EXITINFO2);
                if info1 & 1 != 0 {
                    self.pending_in = Some(size);
                    VmExit::PioIn { port, size }
                } else {
                    let data = (self.rax() & (u32::MAX as u64 >> (32 - 8 * size as u32))) as u32;
                    self.skip_to(next);
                    VmExit::PioOut { port, size, data }
                }
            }
            exit::HLT => {
                self.skip_to(rip.wrapping_add(1));
                VmExit::Halt
            }
            exit::VMMCALL => {
                self.skip_to(rip.wrapping_add(3));
                let r = &self.regs;
                VmExit::Hypercall { nr: self.rax(), args: [r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.r8] }
            }
            // Not-present nested fault: an access to an unbacked address.
            exit::NPF if info1 & 1 == 0 => {
                let addr = GuestPhysAddr(self.read64(vmcb::EXITINFO2));
                let Some(a) = self.insn_bytes().and_then(|(b, n)| decode::decode(&b[..n], self.code_bits())) else {
                    return VmExit::Unhandled { reason: code };
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
            exit::INTR | exit::NMI => VmExit::ExternalInterrupt,
            exit::SHUTDOWN => VmExit::Shutdown,
            _ => VmExit::Unhandled { reason: code },
        }
    }
}

impl Vcpu for SvmVcpu {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    fn run(&mut self) -> VmExit {
        if let Some(r) = &self.running {
            r.store(osmium_arch::cpu::current_id(), Ordering::Release);
        }
        let exit = loop {
            let flush = core::mem::take(&mut self.flush);
            self.write32(vmcb::TLB_CONTROL, flush as u32);
            self.write32(vmcb::CLEAN, 0);
            self.prepare_interrupts();
            hw::run(self);
            match self.read64(vmcb::EXITCODE) {
                // An interrupt window opened: deliver on the next entry.
                exit::VINTR => {}
                exit::MSR => self.emulate_msr(),
                exit::CPUID => self.emulate_cpuid(),
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
        unimplemented!("SVM guests need a bare-metal x86_64 build")
    }

    fn complete_read(&mut self, value: u64) {
        if let Some(a) = self.pending_mmio.take() {
            let value = value & (u64::MAX >> (64 - 8 * a.size as u32));
            if a.test {
                // TEST: flags from value & operand; CF and OF clear.
                let bits = 8 * a.size as u32;
                let r = value & self.operand_value(&a) & (u64::MAX >> (64 - bits));
                let (cf, pf, zf, sf, of) = (1 << 0, 1 << 2, 1 << 6, 1 << 7, 1 << 11);
                let mut f = self.read64(vmcb::RFLAGS) & !(cf | pf | zf | sf | of);
                if (r as u8).count_ones() % 2 == 0 {
                    f |= pf;
                }
                if r == 0 {
                    f |= zf;
                }
                if r >> (bits - 1) & 1 != 0 {
                    f |= sf;
                }
                self.write64(vmcb::RFLAGS, f);
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
        if let Some(size) = self.pending_in.take() {
            let mask = u64::MAX >> (64 - 8 * size as u32);
            // 32-bit results zero the upper half; 8/16-bit ones merge.
            let rax = if size == 4 { value & mask } else { (self.rax() & !mask) | (value & mask) };
            self.write64(vmcb::RAX, rax);
            let next = self.read64(vmcb::EXITINFO2);
            self.skip_to(next);
        }
    }

    fn complete_hypercall(&mut self, ret: u64) {
        self.write64(vmcb::RAX, ret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    #[repr(C, align(4096))]
    struct Page([u8; 4096]);

    fn vcpu() -> SvmVcpu {
        let p = |n: usize| {
            let b: Box<[Page]> = (0..n).map(|_| Page([0; 4096])).collect();
            let ptr = Box::leak(b).as_mut_ptr().cast::<u8>();
            (NonNull::new(ptr).unwrap(), ptr as u64)
        };
        // SAFETY: leaked, exclusively owned test pages.
        unsafe {
            SvmVcpu::new(SvmPages { vmcb: p(1), iopm: p(3), msrpm: p(2), host: p(1) }, 0x1000, 0x10_0000, 0x20_0000)
        }
    }

    #[test]
    fn svm_instructions_and_exceptions_are_reflected() {
        let mut v = vcpu();
        let set_cpl = |v: &mut SvmVcpu, cpl: u64| {
            let w = v.read64(vmcb::CPL & !7) & !(0xff << 24);
            v.write64(vmcb::CPL & !7, w | cpl << 24);
        };
        for code in [exit::VMRUN, exit::VMLOAD, exit::VMLOAD + 1, exit::VMLOAD + 3, exit::SKINIT, exit::INVLPGA] {
            assert!(v.reflect(code));
            assert_eq!(v.pending_exception.take(), Some(6 | 3 << 8 | EVENT_VALID), "#UD for {code:#x}");
        }
        set_cpl(&mut v, 0);
        assert!(!v.reflect(exit::VMMCALL), "a hypercall from ring 0");
        set_cpl(&mut v, 3);
        assert!(v.reflect(exit::VMMCALL));
        assert_eq!(v.pending_exception.take(), Some(6 | 3 << 8 | EVENT_VALID), "#UD from user mode");
        let rip = v.rip();
        assert!(v.reflect(exit::INVD));
        assert_eq!(v.rip(), rip + 2, "INVD retires as a no-op");
        assert!(v.reflect(exit::EXCEPTION + 17));
        assert_eq!(v.pending_exception.take(), Some(17 | 3 << 8 | 1 << 11 | EVENT_VALID), "#AC with its error code");
        assert!(!v.reflect(exit::HLT));
        // A reflected exception is injected at the next entry.
        v.pending_exception = Some(6 | 3 << 8 | EVENT_VALID);
        v.prepare_interrupts();
        assert_eq!(v.read64(vmcb::EVENTINJ), 6 | 3 << 8 | EVENT_VALID);
    }

    #[test]
    fn bad_efer_pat_and_debug_registers() {
        let mut v = vcpu();
        let wrmsr = |v: &mut SvmVcpu, msr: u32, val: u64| {
            v.regs.rcx = msr as u64;
            v.write64(vmcb::RAX, val & 0xffff_ffff);
            v.regs.rdx = val >> 32;
            v.write64(vmcb::EXITINFO1, 1);
            v.emulate_msr();
        };
        let (rip, efer) = (v.rip(), v.read64(vmcb::EFER));
        wrmsr(&mut v, 0xc000_0080, 1 << 3); // reserved
        assert_eq!(v.pending_exception.take(), Some(13 | 3 << 8 | 1 << 11 | EVENT_VALID), "#GP(0)");
        assert_eq!((v.rip(), v.read64(vmcb::EFER)), (rip, efer), "faults on the WRMSR, EFER unchanged");
        wrmsr(&mut v, 0x277, 0x0007_0406_0007_0402); // memory type 2 is reserved
        assert!(v.pending_exception.take().is_some());
        // mov rbx, dr0 (0F 21 C3). The decode-assist bytes are stale for a DR
        // intercept (hardware fills them for #NPF/#PF only), so the
        // instruction is read from guest memory instead.
        let mut ram = alloc::vec![0u8; 0x1000];
        let mut mem = GuestMemory::new();
        // SAFETY: `ram` outlives the vCPU's use of `mem` in this test.
        unsafe { mem.add_region(GuestPhysAddr(0x10_0000), ram.as_mut_ptr(), 0x1000) };
        mem.write(GuestPhysAddr(0x10_0000), &[0x0f, 0x21, 0xc3]).unwrap();
        let mut v = v.with_memory(Arc::new(mem));
        v.regs.rbx = 0x1234;
        // SAFETY: the instruction bytes field of the owned VMCB.
        unsafe {
            v.at(vmcb::INSN_LEN).write_volatile(3);
            for (k, b) in [0x90, 0x90, 0x90].into_iter().enumerate() {
                v.at(vmcb::INSN_BYTES + k).write_volatile(b);
            }
        }
        let rip = v.rip();
        assert!(v.reflect(exit::DR_READ));
        assert_eq!((v.regs.rbx, v.rip()), (0, rip + 3));
        assert!(v.reflect(exit::XSETBV));
        assert_eq!(v.pending_exception.take(), Some(6 | 3 << 8 | EVENT_VALID));
    }

    #[test]
    fn cpuid_view() {
        let host = [0x000a_0f10, 0x0102_0800, 0x80a0_2201 | 1 << 21, 0x0789_3fff];
        let [_, b, c, _] = patch_cpuid(1, host, 3);
        assert_eq!(b, 0x0302_0800, "the vCPU's APIC ID");
        assert_eq!(c & (1 << 21), 0, "no x2APIC");
        assert_ne!(c & (1 << 31), 0, "hypervisor present");
        assert_eq!(patch_cpuid(0xb, [0, 0, 0, 7], 3)[3], 3);
        assert_eq!(patch_cpuid(0x8000_0001, [0, 0, 0b111, 0], 3)[2], 0b011, "no SVM");
        assert_eq!(patch_cpuid(0, host, 3), host);
    }

    #[test]
    fn msrs() {
        let mut v = vcpu();
        let wrmsr = |v: &mut SvmVcpu, msr: u32, val: u64| {
            v.regs.rcx = msr as u64;
            v.write64(vmcb::RAX, val & 0xffff_ffff);
            v.regs.rdx = val >> 32;
            v.write64(vmcb::EXITINFO1, 1);
            v.emulate_msr();
        };
        let rdmsr = |v: &mut SvmVcpu, msr: u32| {
            v.regs.rcx = msr as u64;
            v.write64(vmcb::EXITINFO1, 0);
            v.emulate_msr();
            v.read64(vmcb::RAX) | v.regs.rdx << 32
        };
        let rip = v.rip();
        wrmsr(&mut v, 0xc000_0082, 0xffff_8000_0012_3456); // LSTAR
        assert_eq!(v.read64(vmcb::LSTAR), 0xffff_8000_0012_3456, "in the VMCB, for VMLOAD");
        assert_eq!(rdmsr(&mut v, 0xc000_0082), 0xffff_8000_0012_3456);
        assert_eq!(v.rip(), rip + 4, "stepped past both");
        // EFER: the guest sees and sets its own bits; SVME stays on.
        wrmsr(&mut v, 0xc000_0080, 1 << 0);
        assert_eq!(v.read64(vmcb::EFER), 1 | EFER_SVME);
        assert_eq!(rdmsr(&mut v, 0xc000_0080), 1);
        wrmsr(&mut v, 0xc000_0103, 3); // TSC_AUX
        assert_eq!((v.tsc_aux, rdmsr(&mut v, 0xc000_0103)), (3, 3));
        assert_eq!(rdmsr(&mut v, 0x1b), 0xfee0_0900, "xAPIC enabled, BSP");
        v.set_application_processor();
        assert_eq!(rdmsr(&mut v, 0x1b), 0xfee0_0800);
        assert_eq!(rdmsr(&mut v, 0x8b), 0, "unknown MSRs read as zero");
    }

    #[test]
    fn setup() {
        let v = vcpu();
        assert_eq!(v.read64(vmcb::EFER), EFER_SVME);
        assert_eq!(v.rip(), 0x10_0000);
        assert_eq!(v.read64(vmcb::N_CR3), 0x1000);
        assert_eq!(v.read64(vmcb::CS) >> 16 & 0xffff, 0xc9b, "CS attributes");
    }

    #[test]
    fn io_hlt_vmmcall() {
        let mut v = vcpu();
        // out dx, al with al = 0x41 to port 0x3f8 (1 byte); next rip +1.
        v.write64(vmcb::RAX, 0xdead_be41);
        v.write64(vmcb::EXITCODE, exit::IOIO);
        v.write64(vmcb::EXITINFO1, 0x3f8 << 16 | 1 << 4);
        v.write64(vmcb::EXITINFO2, 0x10_0001);
        assert_eq!(v.classify(), VmExit::PioOut { port: 0x3f8, size: 1, data: 0x41 });
        assert_eq!(v.rip(), 0x10_0001);

        // in al, dx from 0x3fd; the result merges into rax.
        v.write64(vmcb::EXITINFO1, 0x3fd << 16 | 1 << 4 | 1);
        v.write64(vmcb::EXITINFO2, 0x10_0002);
        assert_eq!(v.classify(), VmExit::PioIn { port: 0x3fd, size: 1 });
        assert_eq!(v.rip(), 0x10_0001, "advanced on completion");
        v.complete_read(0x60);
        assert_eq!((v.rax(), v.rip()), (0xdead_be60, 0x10_0002));

        // String I/O is not emulated.
        v.write64(vmcb::EXITINFO1, 0x3f8 << 16 | 1 << 4 | 1 << 2);
        assert_eq!(v.classify(), VmExit::Unhandled { reason: exit::IOIO });

        v.write64(vmcb::EXITCODE, exit::HLT);
        assert_eq!(v.classify(), VmExit::Halt);
        assert_eq!(v.rip(), 0x10_0003);

        v.write64(vmcb::EXITCODE, exit::VMMCALL);
        v.write64(vmcb::RAX, 7);
        v.regs.rbx = 1;
        assert_eq!(v.classify(), VmExit::Hypercall { nr: 7, args: [1, 0, 0, 0, 0, 0] });
        assert_eq!(v.rip(), 0x10_0006);
        v.complete_hypercall(42);
        assert_eq!(v.rax(), 42);

        // mov %al, (%ebx) to an unbacked address, bytes from guest memory.
        let mut ram = alloc::vec![0u8; 0x1000];
        let mut mem = GuestMemory::new();
        // SAFETY: `ram` outlives the vCPU's use of `mem` in this test.
        unsafe { mem.add_region(GuestPhysAddr(0x10_0000), ram.as_mut_ptr(), 0x1000) };
        mem.write(GuestPhysAddr(0x10_0006), &[0x88, 0x03, 0x0f, 0xb6, 0x4b, 0x05]).unwrap();
        let mut v = v.with_memory(Arc::new(mem));
        v.write64(vmcb::RAX, 0x4d);
        v.write64(vmcb::EXITCODE, exit::NPF);
        v.write64(vmcb::EXITINFO1, 0b110);
        v.write64(vmcb::EXITINFO2, 0xfed0_0000);
        assert_eq!(v.classify(), VmExit::MmioWrite { addr: GuestPhysAddr(0xfed0_0000), size: 1, data: 0x4d });
        assert_eq!(v.rip(), 0x10_0008);
        // movzbl 5(%ebx), %ecx
        v.regs.rcx = u64::MAX;
        v.write64(vmcb::EXITINFO2, 0xfed0_0005);
        assert_eq!(v.classify(), VmExit::MmioRead { addr: GuestPhysAddr(0xfed0_0005), size: 1 });
        v.complete_read(0x60);
        assert_eq!((v.regs.rcx, v.rip()), (0x60, 0x10_000c));
        drop(v);
        drop(ram);
        let mut v = vcpu();

        v.write64(vmcb::EXITCODE, exit::INVALID);
        assert_eq!(v.classify(), VmExit::Unhandled { reason: exit::INVALID });
    }

    #[test]
    fn long_mode_page_walk() {
        let mut ram = alloc::vec![0u8; 0x20_0000];
        let mut mem = GuestMemory::new();
        // SAFETY: `ram` outlives the vCPU's use of `mem` in this test.
        unsafe { mem.add_region(GuestPhysAddr(0), ram.as_mut_ptr(), 0x20_0000) };
        // PML4 0x1000 -> PDPT 0x2000 -> PD 0x3000; PD[0] maps 2 MiB at 0, PD[1]
        // points at a page table 0x4000 whose entry 5 maps 0x5000.
        mem.write_obj(GuestPhysAddr(0x1000), 0x2003u64).unwrap();
        mem.write_obj(GuestPhysAddr(0x2000), 0x3003u64).unwrap();
        mem.write_obj(GuestPhysAddr(0x3000), 0x83u64).unwrap();
        mem.write_obj(GuestPhysAddr(0x3008), 0x4003u64).unwrap();
        mem.write_obj(GuestPhysAddr(0x4000 + 5 * 8), 0x5003u64).unwrap();
        let mut v = vcpu().with_memory(Arc::new(mem));
        v.set_long_mode(0x1000);
        assert_eq!(v.code_bits(), 64);
        assert_eq!(v.translate(0x12_3456), Some(0x12_3456), "2 MiB page");
        assert_eq!(v.translate(0x20_5abc), Some(0x5abc), "4 KiB page");
        assert_eq!(v.translate(0x20_6000), None, "not present");
        drop(v);
        drop(ram);
    }

    #[test]
    fn interrupt_injection() {
        let mut v = vcpu();
        let next = Arc::new(core::sync::atomic::AtomicU8::new(0x24));
        let n = next.clone();
        v.connect_intr(move || Some(n.load(Ordering::SeqCst)));
        let line = v.irq_line();

        // Nothing pending: nothing injected, no window requested.
        v.prepare_interrupts();
        assert_eq!(v.read64(vmcb::EVENTINJ), 0);

        // Pending but IF clear: ask for an interrupt window.
        line.store(true, Ordering::SeqCst);
        assert!(!v.interrupt_pending());
        v.prepare_interrupts();
        assert_eq!(v.read64(vmcb::EVENTINJ), 0);
        assert_ne!(v.read64(vmcb::V_INTR) & 1 << 8, 0);
        assert_ne!(v.intercepts() & INTERCEPT_VINTR, 0);

        // IF set: inject vector 0x24 and drop the window request.
        v.write64(vmcb::RFLAGS, 2 | RFLAGS_IF);
        assert!(v.interrupt_pending());
        v.prepare_interrupts();
        assert_eq!(v.read64(vmcb::EVENTINJ), 0x24 | EVENT_VALID);
        assert_eq!(v.intercepts() & INTERCEPT_VINTR, 0);

        // An injection cut short by an exit is re-injected first.
        v.write64(vmcb::EVENTINJ, 0);
        v.write64(vmcb::EXITINTINFO, 0x30 | EVENT_VALID);
        v.prepare_interrupts();
        assert_eq!(v.read64(vmcb::EVENTINJ), 0x30 | EVENT_VALID);
        assert_eq!(v.read64(vmcb::EXITINTINFO), 0);
    }

    #[test]
    fn instruction_fetch_wraps_instead_of_overflowing() {
        let mut ram = alloc::vec![0u8; 0x1000];
        let mut mem = GuestMemory::new();
        // SAFETY: `ram` outlives the vCPU's use of `mem` in this test.
        unsafe { mem.add_region(GuestPhysAddr(0), ram.as_mut_ptr(), 0x1000) };
        mem.write(GuestPhysAddr(0), &[0x90]).unwrap();
        let mut v = vcpu().with_memory(Arc::new(mem));
        // 32-bit code at the top of the address space wraps to 0.
        v.write64(vmcb::RIP, 0xffff_ffff);
        assert_eq!(v.fetch_insn().map(|(_, n)| n), None, "0xffffffff is unmapped");
        v.write64(vmcb::RIP, 0xffff_fffe);
        assert_eq!(v.fetch_insn().map(|(_, n)| n), None);
        // 64-bit code at u64::MAX - 1: the linear address wraps past 2^64.
        v.set_long_mode(0x1000);
        v.write64(vmcb::RIP, u64::MAX);
        assert_eq!(v.fetch_insn().map(|(_, n)| n), None, "no panic, and a clean failure");
        drop(v);
        drop(ram);
    }

    #[test]
    fn interrupt_window_uses_a_priority_above_the_task_priority() {
        let mut v = vcpu();
        v.connect_intr(|| Some(0x24));
        v.irq_line().store(true, Ordering::SeqCst);
        v.prepare_interrupts();
        let vi = v.read64(vmcb::V_INTR);
        assert_ne!(vi & 1 << 8, 0, "V_IRQ");
        assert_eq!(vi >> 16 & 0xf, 0xf, "V_INTR_PRIO");
    }

    #[test]
    fn stage2_flush_is_requested() {
        let mut v = vcpu();
        v.flush = false;
        v.flush_stage2();
        assert!(v.flush);
    }
}
