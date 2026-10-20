//! The hypervisor's choice between AMD SVM and Intel VMX. The first CPU
//! picks whichever extension the processor has; everything else (page
//! tables, vCPU pages and the vCPU itself) follows through the types here,
//! so the demos and the guest-kernel runner are written once.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ptr::NonNull;

use osmium::arch::x86_64 as x86;
use osmium::mm::paging::formats::{Ept, X86_64};
use osmium::mm::{FrameAllocator, MapFlags, PageTable, PhysAddr, VirtAddr};
use osmium::sync::Once;
use osmium::virt::smp::GuestCpus;
use osmium::virt::stage2::eptp;
use osmium::virt::x86::vmx::{self, VmxPages, VmxVcpu};
use osmium::virt::x86::{self as svm, SvmPages, SvmVcpu};
use osmium::virt::{GuestMemory, GuestPhysAddr, Vcpu, VmExit};

use crate::{FRAMES, Frames, block};

/// Which virtualization extension this machine's CPUs use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// AMD SVM with nested paging.
    Svm,
    /// Intel VMX with EPT.
    Vmx,
}

static BACKEND: Once<Backend> = Once::new();

/// The extension in use; [`enable`] must have run on some CPU.
pub fn backend() -> Backend {
    *BACKEND.get().expect("backend::enable ran")
}

/// Turns virtualization on for this CPU, picking the extension on the
/// first call: SVM if the CPU has it, otherwise VMX. The error says why not.
pub fn enable() -> Result<Backend, alloc::string::String> {
    let b = *BACKEND.call_once(|| if x86::has_svm() { Backend::Svm } else { Backend::Vmx });
    match b {
        Backend::Svm => {
            let hsave = block(0);
            svm::enable(hsave.1).map_err(|e| alloc::format!("cannot enable SVM: {e:?} (run QEMU with -cpu max)"))?;
        }
        Backend::Vmx => {
            // VM exit restores the host's task register, so every CPU needs a TSS.
            let tables = Box::leak(Box::new(x86::CpuTables::new()));
            // SAFETY: this CPU's own tables, loaded once.
            unsafe { tables.load() };
            vmx::enable(block(0))
                .map_err(|e| alloc::format!("cannot enable VMX: {e:?} (run QEMU with -accel kvm -cpu host)"))?;
        }
    }
    Ok(b)
}

/// The second-stage page table: nested (NPT) or extended (EPT).
pub enum Stage2 {
    /// AMD nested page table.
    Npt(PageTable<X86_64, &'static Frames>),
    /// Intel extended page table.
    Ept(PageTable<Ept, &'static Frames>),
}

impl Stage2 {
    /// An empty table.
    pub fn new() -> Self {
        match backend() {
            Backend::Svm => Self::Npt(PageTable::new(&FRAMES).expect("NPT root")),
            Backend::Vmx => Self::Ept(PageTable::new(&FRAMES).expect("EPT root")),
        }
    }

    /// Guest RAM at `ga..ga + len` onto the host block at `pa`, read/write/execute
    /// (NPT walks are user accesses, so the leaves get USER).
    pub fn map_ram(&mut self, ga: u64, pa: u64, len: u64) {
        let flags = MapFlags::RW | MapFlags::EXEC | MapFlags::USER;
        let (va, pa) = (VirtAddr::new(ga), PhysAddr::new(pa));
        match self {
            Self::Npt(t) => t.map_range(va, pa, len, flags),
            Self::Ept(t) => t.map_range(va, pa, len, flags),
        }
        .expect("map_range failed");
    }

    /// What the vCPU is given: `nCR3` or the EPT pointer.
    pub fn root(&self) -> u64 {
        match self {
            Self::Npt(t) => t.root().0,
            Self::Ept(t) => eptp(t.root()),
        }
    }
}

/// The host pages one vCPU owns.
#[derive(Clone, Copy)]
pub enum Pages {
    /// VMCB, I/O and MSR permission maps, host save area.
    Svm { vmcb: Page, iopm: Page, msrpm: Page, host: Page },
    /// VMCS, MSR bitmap, MSR switch lists.
    Vmx { vmcs: Page, msr_bitmap: Page, msr_area: Page },
}

/// A block as (host pointer, physical address).
pub type Page = (NonNull<u8>, u64);

impl Pages {
    /// Allocates the pages the active backend needs.
    pub fn alloc() -> Self {
        match backend() {
            Backend::Svm => Self::Svm { vmcb: block(0), iopm: block(2), msrpm: block(1), host: block(0) },
            Backend::Vmx => Self::Vmx { vmcs: block(0), msr_bitmap: block(0), msr_area: block(0) },
        }
    }

    /// Returns the pages to the allocator.
    ///
    /// # Safety
    /// The vCPU that owned them is gone.
    pub unsafe fn free(self) {
        let mut f = FRAMES.lock();
        let list: &[(Page, u32)] = match &self {
            Self::Svm { vmcb, iopm, msrpm, host } => &[(*vmcb, 0), (*iopm, 2), (*msrpm, 1), (*host, 0)],
            Self::Vmx { vmcs, msr_bitmap, msr_area } => &[(*vmcs, 0), (*msr_bitmap, 0), (*msr_area, 0)],
        };
        for &(p, order) in list {
            // SAFETY: as the caller says.
            unsafe { f.dealloc(PhysAddr::new(p.1), order) };
        }
    }
}

/// A vCPU of either backend.
pub enum Cpu {
    /// AMD SVM.
    Svm(Box<SvmVcpu>),
    /// Intel VMX.
    Vmx(Box<VmxVcpu>),
}

macro_rules! each {
    ($self:expr, $v:ident => $e:expr) => {
        match $self {
            Cpu::Svm($v) => $e,
            Cpu::Vmx($v) => $e,
        }
    };
}

impl Cpu {
    /// A vCPU in 32-bit protected mode at `entry` with stack `rsp`.
    ///
    /// # Safety
    /// `pages` must be exclusively owned by the vCPU and outlive it.
    pub unsafe fn new(pages: Pages, stage2: u64, entry: u32, rsp: u32) -> Self {
        // SAFETY: as the caller says.
        unsafe {
            match pages {
                Pages::Svm { vmcb, iopm, msrpm, host } => {
                    Self::Svm(Box::new(SvmVcpu::new(SvmPages { vmcb, iopm, msrpm, host }, stage2, entry, rsp)))
                }
                Pages::Vmx { vmcs, msr_bitmap, msr_area } => {
                    Self::Vmx(Box::new(VmxVcpu::new(VmxPages { vmcs, msr_bitmap, msr_area }, stage2, entry, rsp)))
                }
            }
        }
    }

    pub fn with_memory(self, mem: Arc<GuestMemory>) -> Self {
        match self {
            Self::Svm(v) => Self::Svm(Box::new(v.with_memory(mem))),
            Self::Vmx(v) => Self::Vmx(Box::new(v.with_memory(mem))),
        }
    }

    pub fn with_irq_line(self, line: Arc<core::sync::atomic::AtomicBool>) -> Self {
        match self {
            Self::Svm(v) => Self::Svm(Box::new(v.with_irq_line(line))),
            Self::Vmx(v) => Self::Vmx(Box::new(v.with_irq_line(line))),
        }
    }

    /// Lets the vCPU move between host CPUs (VMX binds a vCPU to the CPU that runs it).
    pub fn with_migration(self) -> Self {
        match self {
            Self::Svm(v) => Self::Svm(v),
            Self::Vmx(v) => Self::Vmx(Box::new(v.with_migration())),
        }
    }

    pub fn with_fp_switching(self) -> Self {
        match self {
            Self::Svm(v) => Self::Svm(Box::new(v.with_fp_switching())),
            Self::Vmx(v) => Self::Vmx(Box::new(v.with_fp_switching())),
        }
    }

    pub fn connect_intr(&mut self, ack: impl Fn() -> Option<u8> + Send + Sync + 'static) {
        each!(self, v => v.connect_intr(ack))
    }

    pub fn interrupt_pending(&self) -> bool {
        each!(self, v => v.interrupt_pending())
    }

    pub fn set_apic_id(&mut self, id: u8) {
        each!(self, v => v.set_apic_id(id))
    }

    pub fn set_real_mode(&mut self, page: u8) {
        each!(self, v => v.set_real_mode(page))
    }

    pub fn set_long_mode(&mut self, cr3: u64) {
        each!(self, v => v.set_long_mode(cr3))
    }

    pub fn set_application_processor(&mut self) {
        each!(self, v => v.set_application_processor())
    }

    /// General-purpose register `n` in x86 encoding order (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8...).
    pub fn reg(&self, n: u8) -> u64 {
        each!(self, v => v.reg(n))
    }

    pub fn set_reg(&mut self, n: u8, value: u64) {
        each!(self, v => v.set_reg(n, value))
    }

    /// Connects this vCPU as guest CPU `cpu`, so kicks find it.
    pub fn attach(&mut self, cpus: &GuestCpus, cpu: usize) {
        match self {
            Self::Svm(v) => cpus.attach_svm(cpu, v),
            Self::Vmx(v) => cpus.attach_vmx(cpu, v),
        }
    }

    /// Where and why the vCPU stopped, for a diagnostic.
    pub fn describe(&self) -> alloc::string::String {
        match self {
            Self::Svm(v) => {
                use osmium::virt::x86::vmcb;
                alloc::format!(
                    "rip {:#x}, info1 {:#x}, info2 {:#x}, cr3 {:#x}",
                    v.rip(),
                    v.read64(vmcb::EXITINFO1),
                    v.read64(vmcb::EXITINFO2),
                    v.read64(vmcb::CR3)
                )
            }
            Self::Vmx(v) => {
                use osmium::virt::x86::vmx::vmcs;
                alloc::format!(
                    "rip {:#x}, qualification {:#x}, guest-physical {:#x}, cr3 {:#x}",
                    v.rip(),
                    v.read(vmcs::EXIT_QUAL),
                    v.read(vmcs::GUEST_PHYS_ADDR),
                    v.read(vmcs::GUEST_CR3)
                )
            }
        }
    }
}

impl Vcpu for Cpu {
    fn run(&mut self) -> VmExit {
        each!(self, v => v.run())
    }

    fn complete_read(&mut self, value: u64) {
        each!(self, v => v.complete_read(value))
    }

    fn complete_hypercall(&mut self, ret: u64) {
        each!(self, v => v.complete_hypercall(ret))
    }
}

/// Copies a guest image to guest-physical `gpa`. The images call the
/// hypervisor with AMD's `vmmcall`; on Intel the same three bytes become `vmcall`.
pub fn load(mem: &GuestMemory, gpa: u64, image: &[u8]) {
    let mut bytes = alloc::vec::Vec::from(image);
    if backend() == Backend::Vmx {
        for i in 0..bytes.len().saturating_sub(2) {
            if bytes[i..i + 3] == [0x0f, 0x01, 0xd9] {
                bytes[i + 2] = 0xc1;
            }
        }
    }
    mem.write(GuestPhysAddr(gpa), &bytes).expect("write failed");
}
