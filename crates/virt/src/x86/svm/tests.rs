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
    unsafe { SvmVcpu::new(SvmPages { vmcb: p(1), iopm: p(3), msrpm: p(2), host: p(1) }, 0x1000, 0x10_0000, 0x20_0000) }
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
    // Relocating, disabling or x2APIC-enabling the APIC is not supported: #GP.
    for bad in [0xfee0_1800, 0xfee0_0000, 0xfee0_0800 | 1 << 10, 0xfee0_0800 | 1 << 9] {
        wrmsr(&mut v, 0x1b, bad);
        assert_eq!(v.pending_exception.take(), Some(13 | 3 << 8 | 1 << 11 | EVENT_VALID), "{bad:#x}");
    }
    wrmsr(&mut v, 0x1b, 0xfee0_0800);
    assert!(v.pending_exception.is_none());
    assert_eq!(rdmsr(&mut v, 0x1b), 0xfee0_0900, "BSP is read-only");
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
    // A fault in the walk of the guest's own page tables (EXITINFO1 bit 33)
    // is not an access by the instruction.
    v.write64(vmcb::RIP, 0x10_0006);
    v.write64(vmcb::EXITINFO1, 0b110 | 1 << 33);
    assert_eq!(v.classify(), VmExit::Unhandled { reason: exit::NPF });
    v.write64(vmcb::EXITINFO1, 0b110 | 1 << 32);
    assert!(matches!(v.classify(), VmExit::MmioWrite { .. }), "the final translation is the instruction's");
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

#[test]
fn virtual_irq_survives_interrupt_setup() {
    let mut v = vcpu();
    v.set_virtual_irq(Some(0x41));
    v.prepare_interrupts();
    let vi = v.read64(vmcb::V_INTR);
    assert_ne!(vi & 1 << 8, 0, "V_IRQ stays armed");
    assert_eq!(vi >> 32 & 0xff, 0x41);
    assert_eq!(vi >> 16 & 0xf, 0xf);
    v.set_virtual_irq(None);
    v.prepare_interrupts();
    assert_eq!(v.read64(vmcb::V_INTR) & 1 << 8, 0);
}

#[test]
fn reflected_exception_during_delivery_is_taken_at_once() {
    let mut v = vcpu();
    // An interrupt's delivery was cut short by an intercepted #AC: the #AC
    // is injected now, not queued behind the re-injected event.
    v.write64(vmcb::EXITINTINFO, 0x30 | EVENT_VALID);
    assert!(v.reflect(exit::EXCEPTION + 17));
    v.prepare_interrupts();
    assert_eq!(v.read64(vmcb::EVENTINJ), 17 | 3 << 8 | 1 << 11 | EVENT_VALID);
    assert!(v.pending_exception.is_none());
}

#[test]
fn real_mode_exceptions_have_no_error_code() {
    let mut v = vcpu();
    v.write64(vmcb::CR0, 0x10);
    v.pending_exception = Some(13 | 3 << 8 | 1 << 11 | EVENT_VALID);
    v.prepare_interrupts();
    assert_eq!(v.read64(vmcb::EVENTINJ), 13 | 3 << 8 | EVENT_VALID);
}

#[test]
fn irq_raised_after_sampling_requests_a_window() {
    let mut v = vcpu();
    v.prepare_interrupts();
    v.resample_irq();
    assert_eq!(v.intercepts() & INTERCEPT_VINTR, 0);
    v.irq_line().store(true, Ordering::SeqCst);
    v.resample_irq();
    assert_ne!(v.intercepts() & INTERCEPT_VINTR, 0);
    assert_ne!(v.read64(vmcb::V_INTR) & 1 << 8, 0);
}
