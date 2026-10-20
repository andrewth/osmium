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
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use hw::{SvmError, enable};

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::memory::{GuestMemory, GuestPhysAddr};
use crate::vcpu::{Vcpu, VmExit};
use decode::{Access, Operand};

/// `IA32_APIC_BASE`: the bootstrap processor, and the APIC enabled.
const APIC_BASE_BSP: u64 = 1 << 8;
const APIC_BASE_ENABLE: u64 = 1 << 11;

/// VMCB offsets (AMD64 APM vol. 2, appendix B).
pub mod vmcb {
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
    /// Physical interrupt.
    pub const INTR: u64 = 0x60;
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
    /// The guest's `IA32_TSC_AUX`, swapped in around VMRUN.
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    pub(crate) tsc_aux: u64,
    /// The guest's `IA32_APIC_BASE`.
    apic_base: u64,
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
            apic_base: 0xfee0_0000 | APIC_BASE_ENABLE | APIC_BASE_BSP,
        };
        use vmcb::*;
        // INTR, NMI, HLT, IOIO, MSR, SHUTDOWN; VMRUN (required), VMMCALL.
        v.write32(INTERCEPT_MISC1, 1 << 0 | 1 << 1 | 1 << 24 | 1 << 27 | 1 << 28 | 1 << 31);
        v.write32(INTERCEPT_MISC2, 1 << 0 | 1 << 1);
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
        let mem = self.mem.as_ref()?;
        let linear = (self.read64(vmcb::CS + 8)).wrapping_add(self.rip());
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
        if pending & EVENT_VALID != 0 {
            self.write64(vmcb::EVENTINJ, pending);
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
        let v = self.read64(vmcb::V_INTR) & !(1 << 8);
        self.write64(vmcb::V_INTR, if window { v | 1 << 8 } else { v });
        let i = self.intercepts() & !INTERCEPT_VINTR;
        self.write32(vmcb::INTERCEPT_MISC1, if window { i | INTERCEPT_VINTR } else { i });
    }

    /// Moves the guest past an instruction the hypervisor completed for it.
    /// Like the CPU retiring it, this ends an STI or MOV SS interrupt shadow
    /// (`sti; hlt` would otherwise never let an interrupt in).
    /// Marks this vCPU as an application processor: `IA32_APIC_BASE.BSP`
    /// reads as 0.
    pub fn set_application_processor(&mut self) {
        self.apic_base &= !APIC_BASE_BSP;
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
        self.skip_to(rip + 2); // RDMSR and WRMSR are 0F 32 and 0F 30
    }

    fn skip_to(&mut self, rip: u64) {
        self.write64(vmcb::RIP, rip);
        self.write64(vmcb::INT_STATE, 0);
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
                self.skip_to(rip + 1);
                VmExit::Halt
            }
            exit::VMMCALL => {
                self.skip_to(rip + 3);
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
                    self.skip_to(rip + a.len as u64);
                    VmExit::MmioWrite { addr, size: a.size, data }
                } else {
                    self.pending_mmio = Some(a);
                    VmExit::MmioRead { addr, size: a.size }
                }
            }
            exit::INTR => VmExit::ExternalInterrupt,
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
                _ => break self.classify(),
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
                self.skip_to(rip + a.len as u64);
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
            self.skip_to(rip + a.len as u64);
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
}
