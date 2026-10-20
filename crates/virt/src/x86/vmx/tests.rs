use super::caps::{self, adjust, msr};
use super::*;
use alloc::boxed::Box;

#[repr(C, align(4096))]
struct Page([u8; 4096]);

fn vcpu() -> VmxVcpu {
    let p = || {
        let b: Box<[Page]> = (0..1).map(|_| Page([0; 4096])).collect();
        let ptr = Box::leak(b).as_mut_ptr().cast::<u8>();
        (NonNull::new(ptr).unwrap(), ptr as u64)
    };
    // SAFETY: leaked, exclusively owned test pages.
    unsafe { VmxVcpu::new(VmxPages { vmcs: p(), msr_bitmap: p(), msr_area: p() }, 0x1000 | 0x1e, 0x10_0000, 0x20_0000) }
}

fn exit_with(v: &mut VmxVcpu, reason: u32, qual: u64, len: u64) {
    v.write(vmcs::EXIT_REASON, reason as u64);
    v.write(vmcs::EXIT_QUAL, qual);
    v.write(vmcs::EXIT_INSN_LEN, len);
}

fn wrmsr(v: &mut VmxVcpu, msr: u32, val: u64) {
    v.regs.rcx = msr as u64;
    v.regs.rax = val & 0xffff_ffff;
    v.regs.rdx = val >> 32;
    exit_with(v, exit::MSR_WRITE, 0, 2);
    v.emulate_msr();
}

fn rdmsr(v: &mut VmxVcpu, msr: u32) -> u64 {
    v.regs.rcx = msr as u64;
    exit_with(v, exit::MSR_READ, 0, 2);
    v.emulate_msr();
    v.regs.rax | v.regs.rdx << 32
}

#[test]
fn controls_are_adjusted_to_the_cpu() {
    // Bits 0 and 1 forced to 1, bits 1, 2 and 4 settable.
    let cap = 0x16u64 << 32 | 0x3;
    assert_eq!(adjust(0x4, cap), Some(0x7));
    assert_eq!(adjust(0x8, cap), None, "a control the CPU lacks");
    let rd = |m| match m {
        msr::BASIC => 0x1234 | 1 << 55,
        msr::EPT_VPID_CAP => 1 << 6 | 1 << 14 | 1 << 20 | 1 << 32 | 1 << 26 | 1 << 42,
        msr::TRUE_PROCBASED => (u32::MAX as u64) << 32, // everything allowed, nothing forced
        msr::CR0_FIXED0 => 0x21,
        _ => u64::MAX << 32,
    };
    let c = Caps::from_msrs(rd).unwrap();
    assert_eq!(c.revision, 0x1234);
    assert_eq!((c.invept, c.invvpid), (2, 2), "all-context invalidation when single-context is missing");
    assert_eq!(c.pin & caps::pin::NMI, caps::pin::NMI);
    // Without unrestricted guest the vCPU cannot run.
    let no_ug = |m| if m == msr::PROCBASED2 { ((!caps::proc2::UNRESTRICTED_GUEST) as u64) << 32 } else { rd(m) };
    assert_eq!(Caps::from_msrs(no_ug), Err(VmxError::MissingControl(msr::PROCBASED2)));
    let no_ept = |m| if m == msr::EPT_VPID_CAP { 1 << 6 } else { rd(m) };
    assert_eq!(Caps::from_msrs(no_ept), Err(VmxError::NoEpt));
}

#[test]
fn setup() {
    let v = vcpu();
    assert_eq!(v.rip(), 0x10_0000);
    assert_eq!(v.read(vmcs::EPTP), 0x101e);
    assert_eq!(v.read(vmcs::LINK_POINTER), u64::MAX);
    assert_eq!(v.cr0(), 0x11);
    assert_eq!(v.read(vmcs::GUEST_CR0) & 0x21, 0x21, "NE is the host's to keep set");
    assert_eq!(v.read(vmcs::CR4_MASK) & CR4_VMXE, CR4_VMXE);
    assert_eq!(v.read(vmcs::GUEST_AR + 2) & 0xffff, 0xc09b, "CS access rights");
    assert_eq!(v.read(vmcs::GUEST_SEL + 2), 8);
    assert_ne!(v.read(vmcs::PROC_CTLS) & caps::proc::UNCONDITIONAL_IO as u64, 0);
    assert_eq!(v.read(vmcs::ENTRY_MSR_LOAD_COUNT), 5);
}

#[test]
fn io_hlt_vmcall() {
    let mut v = vcpu();
    // out dx, al with al = 0x41 to port 0x3f8 (1 byte, 1-byte instruction).
    v.regs.rax = 0xdead_be41;
    exit_with(&mut v, exit::IO, 0x3f8 << 16, 1);
    assert_eq!(v.classify(), VmExit::PioOut { port: 0x3f8, size: 1, data: 0x41 });
    assert_eq!(v.rip(), 0x10_0001);

    // in al, dx from 0x3fd; the result merges into rax once supplied.
    exit_with(&mut v, exit::IO, 0x3fd << 16 | 8, 1);
    assert_eq!(v.classify(), VmExit::PioIn { port: 0x3fd, size: 1 });
    assert_eq!(v.rip(), 0x10_0001, "advanced on completion");
    v.complete_read(0x60);
    assert_eq!((v.rax(), v.rip()), (0xdead_be60, 0x10_0002));

    // in eax, dx zeroes the upper half; string I/O is not emulated.
    exit_with(&mut v, exit::IO, 0x10 << 16 | 8 | 3, 1);
    assert_eq!(v.classify(), VmExit::PioIn { port: 0x10, size: 4 });
    v.complete_read(0x1_2345_6789);
    assert_eq!(v.rax(), 0x2345_6789);
    exit_with(&mut v, exit::IO, 1 << 4, 2);
    assert_eq!(v.classify(), VmExit::Unhandled { reason: exit::IO as u64 });

    exit_with(&mut v, exit::HLT, 0, 1);
    let rip = v.rip();
    assert_eq!(v.classify(), VmExit::Halt);
    assert_eq!(v.rip(), rip + 1);

    exit_with(&mut v, exit::VMCALL, 0, 3);
    v.regs.rax = 7;
    v.regs.rbx = 1;
    assert_eq!(v.classify(), VmExit::Hypercall { nr: 7, args: [1, 0, 0, 0, 0, 0] });
    v.complete_hypercall(42);
    assert_eq!(v.rax(), 42);

    v.write(vmcs::EXIT_REASON, (exit::ENTRY_FAILURE | 33) as u64);
    assert_eq!(v.classify(), VmExit::Unhandled { reason: 0x8000_0021 });
}

#[test]
fn mmio_through_ept_violations() {
    let mut ram = alloc::vec![0u8; 0x1000];
    let mut mem = GuestMemory::new();
    // SAFETY: `ram` outlives the vCPU's use of `mem` in this test.
    unsafe { mem.add_region(GuestPhysAddr(0x10_0000), ram.as_mut_ptr(), 0x1000) };
    // mov %al, (%ebx); movzbl 5(%ebx), %ecx
    mem.write(GuestPhysAddr(0x10_0000), &[0x88, 0x03, 0x0f, 0xb6, 0x4b, 0x05]).unwrap();
    let mut v = vcpu().with_memory(Arc::new(mem));
    v.regs.rax = 0x4d;
    // A write (bit 1) to a page with no permissions at all.
    exit_with(&mut v, exit::EPT_VIOLATION, 0b10, 0);
    v.write(vmcs::GUEST_PHYS_ADDR, 0xfed0_0000);
    assert_eq!(v.classify(), VmExit::MmioWrite { addr: GuestPhysAddr(0xfed0_0000), size: 1, data: 0x4d });
    assert_eq!(v.rip(), 0x10_0002);
    v.regs.rcx = u64::MAX;
    exit_with(&mut v, exit::EPT_VIOLATION, 0b01, 0);
    v.write(vmcs::GUEST_PHYS_ADDR, 0xfed0_0005);
    assert_eq!(v.classify(), VmExit::MmioRead { addr: GuestPhysAddr(0xfed0_0005), size: 1 });
    v.complete_read(0x60);
    assert_eq!((v.regs.rcx, v.rip()), (0x60, 0x10_0006));
    // A write to a read-only page (bit 3: readable) is not MMIO.
    exit_with(&mut v, exit::EPT_VIOLATION, 0b1010, 0);
    assert_eq!(v.classify(), VmExit::Unhandled { reason: exit::EPT_VIOLATION as u64 });
    drop(v);
    drop(ram);
}

#[test]
fn msrs() {
    let mut v = vcpu();
    let rip = v.rip();
    wrmsr(&mut v, 0xc000_0082, 0xffff_8000_0012_3456); // LSTAR
    assert_eq!(v.area(0xc000_0082), 0xffff_8000_0012_3456, "in the entry list, for the CPU to load");
    assert_eq!(rdmsr(&mut v, 0xc000_0082), 0xffff_8000_0012_3456);
    assert_eq!(v.rip(), rip + 4, "stepped past both");
    wrmsr(&mut v, 0x175, 0xffff_8000_0000_1000);
    assert_eq!(v.read(vmcs::GUEST_SYSENTER_ESP), 0xffff_8000_0000_1000);
    wrmsr(&mut v, 0xc000_0100, 0x1234);
    assert_eq!(v.read(vmcs::GUEST_BASE + 2 * Seg::Fs as u32), 0x1234);
    wrmsr(&mut v, 0xc000_0103, 0x1_0000_0003);
    assert_eq!(rdmsr(&mut v, 0xc000_0103), 3, "TSC_AUX is 32 bits");
    assert_eq!(rdmsr(&mut v, 0x1b), 0xfee0_0900, "xAPIC enabled, BSP");
    v.set_application_processor();
    assert_eq!(rdmsr(&mut v, 0x1b), 0xfee0_0800);
    assert_eq!(rdmsr(&mut v, 0x8b), 0, "unknown MSRs read as zero");
    // EFER: the guest sets its own bits; LMA is not writable.
    wrmsr(&mut v, 0xc000_0080, 1 | EFER_LME | EFER_LMA);
    assert_eq!(rdmsr(&mut v, 0xc000_0080), 1 | EFER_LME);
    assert!(v.pending_exception.is_none());
}

#[test]
fn values_the_cpu_would_refuse_raise_gp() {
    let mut v = vcpu();
    let rip = v.rip();
    for (m, val) in [
        (0xc000_0080, 1 << 3),
        (0x277, 0x0007_0406_0007_0402),
        (0xc000_0082, 0x0000_8000_0000_0000),
        (0x176, 1 << 63 >> 8),
    ] {
        wrmsr(&mut v, m, val);
        assert_eq!(v.pending_exception.take(), Some(GP), "{m:#x}");
        assert_eq!(v.rip(), rip, "faults on the WRMSR");
    }
    // LME cannot change while paging is on.
    v.set_long_mode(0x1000);
    wrmsr(&mut v, 0xc000_0080, 0);
    assert_eq!(v.pending_exception.take(), Some(GP));
}

#[test]
fn control_registers() {
    let mut v = vcpu();
    let q = |cr: u64, ty: u64, gpr: u64| cr | ty << 4 | gpr << 8;
    // mov cr0, rcx with paging on while EFER.LME is set turns long mode on.
    v.write(vmcs::GUEST_EFER, EFER_LME);
    v.set_cr4(CR4_PAE);
    v.regs.rcx = 0x8001_0033;
    exit_with(&mut v, exit::CR_ACCESS, q(0, 0, 1), 3);
    let rip = v.rip();
    assert!(v.emulate_cr());
    assert_eq!(v.cr0(), 0x8001_0033);
    assert_eq!(v.read(vmcs::GUEST_EFER) & EFER_LMA, EFER_LMA);
    assert_eq!(v.rip(), rip + 3);
    // Clearing paging clears LMA; the CPU's fixed bits stay set in the real CR0.
    v.regs.rcx = 0x11;
    assert!(v.emulate_cr());
    assert_eq!(v.read(vmcs::GUEST_EFER) & EFER_LMA, 0);
    assert_eq!(v.read(vmcs::GUEST_CR0) & 0x21, 0x21);
    // Paging without protection, and a CR4 with VMXE, are #GP.
    v.regs.rcx = 0x8000_0000;
    assert!(v.emulate_cr());
    assert_eq!(v.pending_exception.take(), Some(GP));
    v.regs.rcx = CR4_VMXE;
    exit_with(&mut v, exit::CR_ACCESS, q(4, 0, 1), 3);
    assert!(v.emulate_cr());
    assert_eq!(v.pending_exception.take(), Some(GP));
    // CR8 is the vCPU's own; CLTS and LMSW edit CR0.
    v.regs.rcx = 5;
    exit_with(&mut v, exit::CR_ACCESS, q(8, 0, 1), 3);
    assert!(v.emulate_cr());
    exit_with(&mut v, exit::CR_ACCESS, q(8, 1, 2), 3);
    assert!(v.emulate_cr());
    assert_eq!(v.regs.rdx, 5);
    v.set_cr0(0x19);
    exit_with(&mut v, exit::CR_ACCESS, q(0, 2, 0), 2);
    assert!(v.emulate_cr());
    assert_eq!(v.cr0(), 0x11, "CLTS clears TS");
    exit_with(&mut v, exit::CR_ACCESS, 3 << 4 | 0x8 << 16, 3);
    assert!(v.emulate_cr());
    assert_eq!(v.cr0(), 0x19, "LMSW sets TS and cannot clear PE");
}

#[test]
fn debug_registers_and_reflected_exits() {
    let mut v = vcpu();
    // Until the guest touches a debug register, MOV DR exits.
    let no_exit = |v: &VmxVcpu| v.read(vmcs::PROC_CTLS) & caps::proc::MOV_DR as u64 == 0;
    v.prepare_entry();
    assert!(!no_exit(&v));
    // mov dr0, rbx; mov rax, dr0; mov dr7, rcx.
    v.regs.rbx = 0x1234;
    exit_with(&mut v, exit::DR_ACCESS, 3 << 8, 3);
    assert!(v.reflect(exit::DR_ACCESS));
    exit_with(&mut v, exit::DR_ACCESS, 0x10, 3);
    assert!(v.reflect(exit::DR_ACCESS));
    assert_eq!(v.regs.rax, 0x1234);
    v.regs.rcx = 0x455;
    exit_with(&mut v, exit::DR_ACCESS, 7 | 1 << 8, 3);
    assert!(v.reflect(exit::DR_ACCESS));
    assert_eq!(v.read(vmcs::GUEST_DR7), 0x455);
    assert_eq!(v.debug_registers().0[0], 0x1234);
    // The registers are the hardware's from then on.
    v.prepare_entry();
    assert!(no_exit(&v));
    // A non-canonical breakpoint address and a wide DR7 are #GP.
    v.regs.rbx = 1 << 50;
    exit_with(&mut v, exit::DR_ACCESS, 3 << 8, 3);
    assert!(v.reflect(exit::DR_ACCESS));
    assert_eq!(v.pending_exception.take(), Some(GP));
    v.regs.rcx = 1 << 32;
    exit_with(&mut v, exit::DR_ACCESS, 7 | 1 << 8, 3);
    assert!(v.reflect(exit::DR_ACCESS));
    assert_eq!(v.pending_exception.take(), Some(GP));

    for code in [exit::VMCLEAR, exit::VMXON, exit::INVEPT, exit::INVVPID, exit::XSETBV, exit::MWAIT, exit::MONITOR] {
        assert!(v.reflect(code));
        assert_eq!(v.pending_exception.take(), Some(UD), "#UD for {code}");
    }
    v.write(vmcs::GUEST_AR + 2 * Seg::Ss as u32, 0x93);
    assert!(!v.reflect(exit::VMCALL), "a hypercall from ring 0");
    v.write(vmcs::GUEST_AR + 2 * Seg::Ss as u32, 0x93 | 3 << 5);
    assert!(v.reflect(exit::VMCALL));
    assert_eq!(v.pending_exception.take(), Some(UD));
    exit_with(&mut v, exit::WBINVD, 0, 2);
    let rip = v.rip();
    assert!(v.reflect(exit::WBINVD));
    assert_eq!(v.rip(), rip + 2);
    // #AC comes back with its error code; an NMI is the host's.
    v.write(vmcs::EXIT_INTR_INFO, EVENT_VALID | 3 << 8 | 17);
    assert!(v.reflect(exit::EXCEPTION_NMI));
    assert_eq!(v.pending_exception.take(), Some(17 | 3 << 8 | 1 << 11 | EVENT_VALID));
    v.write(vmcs::EXIT_REASON, exit::EXCEPTION_NMI as u64);
    v.write(vmcs::EXIT_INTR_INFO, EVENT_VALID | 2 << 8 | 2);
    assert!(!v.reflect(exit::EXCEPTION_NMI));
    assert_eq!(v.classify(), VmExit::ExternalInterrupt);
    assert!(!v.reflect(exit::HLT));
}

#[test]
fn guest_breakpoints_are_reflected() {
    let mut v = vcpu();
    // DR0 armed for execution (L0, RW0 = 0) and DR1 for writes (L1, RW1 = 1).
    v.set_debug_registers([0x1000, 0x2000, 0, 0], 0, 0x1 | 0x4 | 1 << 20);
    assert_eq!(v.read(vmcs::GUEST_DR7), 0x1 | 0x4 | 1 << 20 | 0x400);
    v.prepare_entry();
    assert_eq!(v.read(vmcs::PROC_CTLS) & caps::proc::MOV_DR as u64, 0);
    let db = |v: &mut VmxVcpu, q: u64| {
        v.write(vmcs::EXIT_INTR_INFO, EVENT_VALID | 3 << 8 | 1);
        v.write(vmcs::EXIT_QUAL, q);
        assert!(v.reflect(exit::EXCEPTION_NMI));
        assert_eq!(v.pending_exception.take(), Some(1 | 3 << 8 | EVENT_VALID));
    };
    // The instruction breakpoint is a fault, so RF keeps it from firing again.
    db(&mut v, 1);
    assert_eq!(v.debug_registers().1 & 0xf, 1);
    assert_ne!(v.rflags() & RFLAGS_RF, 0);
    // A data breakpoint is a trap.
    v.write(vmcs::GUEST_RFLAGS, 2);
    db(&mut v, 2);
    assert_eq!(v.rflags() & RFLAGS_RF, 0);
    // General detect disarms itself.
    v.write(vmcs::GUEST_DR7, 0x400 | 1 << 13);
    db(&mut v, 1 << 13);
    assert_eq!(v.read(vmcs::GUEST_DR7), 0x400);
}

#[test]
fn interrupt_injection() {
    let mut v = vcpu();
    let next = Arc::new(core::sync::atomic::AtomicU8::new(0x24));
    let n = next.clone();
    v.connect_intr(move || Some(n.load(Ordering::SeqCst)));
    let line = v.irq_line();
    let window = |v: &VmxVcpu| v.read(vmcs::PROC_CTLS) & caps::proc::INTERRUPT_WINDOW as u64 != 0;

    // Nothing pending: nothing injected, no window requested.
    v.prepare_entry();
    assert_eq!(v.read(vmcs::ENTRY_INTR_INFO), 0);
    assert!(!window(&v));

    // Pending but IF clear: ask for an interrupt window.
    line.store(true, Ordering::SeqCst);
    assert!(!v.interrupt_pending());
    v.prepare_entry();
    assert_eq!(v.read(vmcs::ENTRY_INTR_INFO), 0);
    assert!(window(&v));

    // IF set but the guest just executed STI: still not.
    v.write(vmcs::GUEST_RFLAGS, 2 | RFLAGS_IF);
    v.write(vmcs::GUEST_INTERRUPTIBILITY, 1);
    v.prepare_entry();
    assert_eq!(v.read(vmcs::ENTRY_INTR_INFO), 0);
    assert!(window(&v));

    // Open: inject vector 0x24 and drop the window request.
    v.write(vmcs::GUEST_INTERRUPTIBILITY, 0);
    assert!(v.interrupt_pending());
    v.prepare_entry();
    assert_eq!(v.read(vmcs::ENTRY_INTR_INFO), 0x24 | EVENT_VALID);
    assert!(!window(&v));

    // An injection cut short by an exit is injected again first, with its
    // error code, and only once; software interrupts are not.
    v.write(vmcs::IDT_VECTORING_INFO, 14 | 3 << 8 | 1 << 11 | EVENT_VALID);
    v.write(vmcs::IDT_VECTORING_ERRCODE, 2);
    v.vectoring_done = false;
    v.prepare_entry();
    assert_eq!(v.read(vmcs::ENTRY_INTR_INFO), 14 | 3 << 8 | 1 << 11 | EVENT_VALID);
    assert_eq!(v.read(vmcs::ENTRY_ERRCODE), 2);
    assert!(window(&v), "the pending interrupt waits for an exit");
    v.prepare_entry();
    assert_eq!(v.read(vmcs::ENTRY_INTR_INFO), 0x24 | EVENT_VALID, "the stale vectoring info is not reused");
    v.write(vmcs::IDT_VECTORING_INFO, 0x80 | 4 << 8 | EVENT_VALID);
    v.vectoring_done = false;
    line.store(false, Ordering::SeqCst);
    v.prepare_entry();
    assert_eq!(v.read(vmcs::ENTRY_INTR_INFO), 0);

    // Queued exceptions go in with their error code.
    v.pending_exception = Some(GP | 5 << 32);
    v.prepare_entry();
    assert_eq!(v.read(vmcs::ENTRY_INTR_INFO), GP & 0xffff_ffff);
    assert_eq!(v.read(vmcs::ENTRY_ERRCODE), 5);
}

#[test]
fn entry_follows_long_mode() {
    let mut v = vcpu();
    v.prepare_entry();
    assert_eq!(v.read(vmcs::ENTRY_CTLS) & caps::entry_ctl::IA32E_GUEST as u64, 0);
    v.set_long_mode(0x1000);
    assert_eq!(v.code_bits(), 64);
    v.prepare_entry();
    assert_ne!(v.read(vmcs::ENTRY_CTLS) & caps::entry_ctl::IA32E_GUEST as u64, 0);
}

#[test]
fn long_mode_page_walk() {
    let mut ram = alloc::vec![0u8; 0x20_0000];
    let mut mem = GuestMemory::new();
    // SAFETY: `ram` outlives the vCPU's use of `mem` in this test.
    unsafe { mem.add_region(GuestPhysAddr(0), ram.as_mut_ptr(), 0x20_0000) };
    mem.write_obj(GuestPhysAddr(0x1000), 0x2003u64).unwrap();
    mem.write_obj(GuestPhysAddr(0x2000), 0x3003u64).unwrap();
    mem.write_obj(GuestPhysAddr(0x3000), 0x83u64).unwrap();
    mem.write_obj(GuestPhysAddr(0x3008), 0x4003u64).unwrap();
    mem.write_obj(GuestPhysAddr(0x4000 + 5 * 8), 0x5003u64).unwrap();
    let mut v = vcpu().with_memory(Arc::new(mem));
    assert_eq!(v.translate(0x1234), Some(0x1234), "paging off");
    v.set_long_mode(0x1000);
    assert_eq!(v.translate(0x12_3456), Some(0x12_3456), "2 MiB page");
    assert_eq!(v.translate(0x20_5abc), Some(0x5abc), "4 KiB page");
    assert_eq!(v.translate(0x20_6000), None, "not present");
    drop(v);
    drop(ram);
}

#[test]
fn real_mode_start() {
    let mut v = vcpu();
    v.set_real_mode(0x8);
    assert_eq!(v.read(vmcs::GUEST_SEL + 2), 0x800);
    assert_eq!(v.read(vmcs::GUEST_BASE + 2), 0x8000);
    assert_eq!((v.rip(), v.cr0()), (0, 0x10));
}

#[test]
fn cpuid_view() {
    let host = [0x000a_0f10, 0x0102_0800, 0x80a0_2201 | 1 << 21 | 1 << 5 | 1 << 3, 0x0789_3fff];
    let [_, b, c, _] = patch_cpuid(1, host, 3);
    assert_eq!(b, 0x0302_0800, "the vCPU's APIC ID");
    assert_eq!(c & (1 << 21 | 1 << 5 | 1 << 3), 0, "no x2APIC, VMX or MONITOR");
    assert_ne!(c & (1 << 31), 0, "hypervisor present");
    assert_eq!(patch_cpuid(7, [0, 1 << 10 | 1 << 3, 0, 0], 0)[1], 1 << 3, "no INVPCID");
    assert_eq!(patch_cpuid(0xa, [1, 2, 3, 4], 0), [0; 4], "no performance counters");
}

#[test]
fn guest_visible_cr0_and_cr4_follow_native_writes() {
    let mut v = vcpu();
    // The guest sets CR4.PAE and CR0.PG itself (neither is intercepted):
    // only the real registers change, not the shadows.
    let cr4 = v.read(vmcs::GUEST_CR4);
    v.write(vmcs::GUEST_CR4, cr4 | CR4_PAE);
    let cr0 = v.read(vmcs::GUEST_CR0);
    v.write(vmcs::GUEST_CR0, cr0 | CR0_PG);
    assert_ne!(v.cr4() & CR4_PAE, 0);
    assert_ne!(v.cr0() & CR0_PG, 0);
    // Bits the host owns still read as the shadow says.
    let owned = v.cr0_owned();
    assert_eq!(v.cr0() & owned, v.read(vmcs::CR0_SHADOW) & owned);
}

#[test]
fn native_pae_then_emulated_paging_is_not_refused() {
    let mut v = vcpu();
    let cr4 = v.read(vmcs::GUEST_CR4);
    v.write(vmcs::GUEST_CR4, cr4 | CR4_PAE); // a native write
    v.write(vmcs::GUEST_EFER, EFER_LME);
    let q = 1 << 8;
    v.regs.rcx = 0x8001_0033;
    exit_with(&mut v, exit::CR_ACCESS, q, 3);
    assert!(v.emulate_cr());
    assert_eq!(v.pending_exception.take(), None, "LME paging with PAE set natively is legal");
    assert_eq!(v.read(vmcs::GUEST_EFER) & EFER_LMA, EFER_LMA);
}

#[test]
fn pae_paging_loads_the_pdptes() {
    let mut ram = alloc::vec![0u8; 0x2000];
    let mut mem = GuestMemory::new();
    // SAFETY: `ram` outlives the vCPU's use of `mem` in this test.
    unsafe { mem.add_region(GuestPhysAddr(0), ram.as_mut_ptr(), 0x2000) };
    for i in 0..4u64 {
        mem.write_obj(GuestPhysAddr(0x1000 + 8 * i), (0x5000 + 0x1000 * i) | 1).unwrap();
    }
    mem.write_obj(GuestPhysAddr(0x1020), 0u64).unwrap();
    let mem = Arc::new(mem);
    let mut v = vcpu().with_memory(mem.clone());
    v.write(vmcs::GUEST_CR3, 0x1000);
    v.set_cr4(CR4_PAE);
    let q = 1 << 8;
    v.regs.rcx = 0x8001_0033;
    exit_with(&mut v, exit::CR_ACCESS, q, 3);
    assert!(v.emulate_cr());
    assert_eq!(v.pending_exception.take(), None);
    for i in 0..4u32 {
        assert_eq!(v.read(vmcs::GUEST_PDPTE0 + 2 * i), (0x5000 + 0x1000 * i as u64) | 1);
    }
    // A present entry with a reserved bit is #GP(0) and changes nothing.
    mem.write_obj(GuestPhysAddr(0x1008), 0x6000u64 | 1 | 1 << 1).unwrap();
    v.set_cr0(0x11);
    v.regs.rcx = 0x8001_0033;
    exit_with(&mut v, exit::CR_ACCESS, q, 3);
    assert!(v.emulate_cr());
    assert_eq!(v.pending_exception.take(), Some(GP));
    assert_eq!(v.cr0(), 0x11);
    drop(v);
    drop(mem);
    drop(ram);
}

#[test]
fn mov_dr_needs_ring_0() {
    let mut v = vcpu();
    v.regs.rcx = 0x455;
    v.write(vmcs::GUEST_AR + 2 * Seg::Ss as u32, 0x93 | 3 << 5);
    exit_with(&mut v, exit::DR_ACCESS, 7 | 1 << 8, 3);
    let rip = v.rip();
    assert!(v.reflect(exit::DR_ACCESS));
    assert_eq!(v.pending_exception.take(), Some(GP));
    assert_eq!((v.read(vmcs::GUEST_DR7), v.rip()), (0x400, rip), "nothing changed, not stepped over");
    // With CR4.DE, DR4 and DR5 do not exist.
    v.write(vmcs::GUEST_AR + 2 * Seg::Ss as u32, 0x93);
    v.set_cr4(CR4_DE);
    exit_with(&mut v, exit::DR_ACCESS, 4 | 1 << 8, 3);
    assert!(v.reflect(exit::DR_ACCESS));
    assert_eq!(v.pending_exception.take(), Some(UD));
}

#[test]
fn control_register_moves_use_the_operand_size() {
    let mut v = vcpu();
    // 32-bit code: the upper half of the register is not part of the value.
    v.regs.rcx = 0xdead_beef_0000_0033;
    exit_with(&mut v, exit::CR_ACCESS, 1 << 8, 3);
    assert!(v.emulate_cr());
    assert_eq!(v.pending_exception.take(), None);
    assert_eq!(v.cr0(), 0x33);
    // In 64-bit mode the same value has reserved bits set.
    v.set_long_mode(0x1000);
    assert_eq!(v.code_bits(), 64);
    exit_with(&mut v, exit::CR_ACCESS, 1 << 8, 3);
    assert!(v.emulate_cr());
    assert_eq!(v.pending_exception.take(), Some(GP));
}

#[test]
fn instruction_fetch_wraps_instead_of_overflowing() {
    let mut ram = alloc::vec![0u8; 0x1000];
    let mut mem = GuestMemory::new();
    // SAFETY: `ram` outlives the vCPU's use of `mem` in this test.
    unsafe { mem.add_region(GuestPhysAddr(0), ram.as_mut_ptr(), 0x1000) };
    let mut v = vcpu().with_memory(Arc::new(mem));
    v.write(vmcs::GUEST_RIP, 0xffff_ffff);
    assert!(v.insn_bytes().is_none());
    v.set_long_mode(0x1000);
    v.write(vmcs::GUEST_RIP, u64::MAX);
    assert!(v.insn_bytes().is_none(), "no overflow panic");
    drop(v);
    drop(ram);
}

#[test]
fn stage2_flush_is_requested() {
    let mut v = vcpu();
    v.flush = false;
    v.flush_stage2();
    assert!(v.flush);
}
