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
//! | `INTR` | [`VmExit::ExternalInterrupt`] |
//! | `SHUTDOWN` (triple fault) | [`VmExit::Shutdown`] |
//! | Anything else | [`VmExit::Unhandled`] with the exit code |
//!
//! FS, GS, TR, LDTR and the syscall MSRs are not switched (no
//! VMLOAD/VMSAVE), so guests must not depend on them yet.

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
mod hw;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use hw::{SvmError, enable};

use core::ptr::NonNull;

use crate::vcpu::{Vcpu, VmExit};

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
    /// Exit code.
    pub const EXITCODE: usize = 0x070;
    /// Exit information 1.
    pub const EXITINFO1: usize = 0x078;
    /// Exit information 2.
    pub const EXITINFO2: usize = 0x080;
    /// Nested paging enable (bit 0).
    pub const NP_ENABLE: usize = 0x090;
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
}

/// `#VMEXIT` codes.
pub mod exit {
    /// Physical interrupt.
    pub const INTR: u64 = 0x60;
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
}

/// A virtual x86 CPU on AMD SVM.
pub struct SvmVcpu {
    vmcb: NonNull<u8>,
    vmcb_pa: u64,
    /// General-purpose registers other than `rax`/`rsp`.
    pub regs: GuestRegs,
    pending_in: Option<u8>,
    #[cfg_attr(not(all(target_arch = "x86_64", target_os = "none")), allow(dead_code))]
    flush: bool,
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
        let mut v = Self { vmcb: pages.vmcb.0, vmcb_pa: pages.vmcb.1, regs: GuestRegs::default(), pending_in: None, flush: true };
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
                    self.write64(vmcb::RIP, next);
                    VmExit::PioOut { port, size, data }
                }
            }
            exit::HLT => {
                self.write64(vmcb::RIP, rip + 1);
                VmExit::Halt
            }
            exit::VMMCALL => {
                self.write64(vmcb::RIP, rip + 3);
                let r = &self.regs;
                VmExit::Hypercall { nr: self.rax(), args: [r.rbx, r.rcx, r.rdx, r.rsi, r.rdi, r.r8] }
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
        if core::mem::take(&mut self.flush) {
            self.write32(vmcb::TLB_CONTROL, 1);
        } else {
            self.write32(vmcb::TLB_CONTROL, 0);
        }
        self.write32(vmcb::CLEAN, 0);
        hw::run(self);
        self.classify()
    }

    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    fn run(&mut self) -> VmExit {
        unimplemented!("SVM guests need a bare-metal x86_64 build")
    }

    fn complete_read(&mut self, value: u64) {
        if let Some(size) = self.pending_in.take() {
            let mask = u64::MAX >> (64 - 8 * size as u32);
            // 32-bit results zero the upper half; 8/16-bit ones merge.
            let rax = if size == 4 { value & mask } else { (self.rax() & !mask) | (value & mask) };
            self.write64(vmcb::RAX, rax);
            let next = self.read64(vmcb::EXITINFO2);
            self.write64(vmcb::RIP, next);
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
        unsafe { SvmVcpu::new(SvmPages { vmcb: p(1), iopm: p(3), msrpm: p(2) }, 0x1000, 0x10_0000, 0x20_0000) }
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

        v.write64(vmcb::EXITCODE, exit::INVALID);
        assert_eq!(v.classify(), VmExit::Unhandled { reason: exit::INVALID });
    }
}
