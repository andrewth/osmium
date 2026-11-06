#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Each architecture's Linux signal frame, built from and restored into a
//! stand-in with that architecture's trap-frame fields: the same register
//! code the kernels run, on whatever the host is.

use super::sigthread::{HANDLER, STACK, bit, handler, sigaction};
use super::*;
use crate::signal::{self, sa, sig::*};
use crate::uregs::UserRegs;
use crate::uregs::frames::{Aarch64, Riscv64, X86_64};

/// Delivers `SIGUSR1` (with `SA_SIGINFO`, blocking `SIGUSR2` in the handler)
/// to a fresh process whose thread has registers `regs`, and returns the
/// process with the handler about to run.
fn deliver<R: UserRegs>(name: &'static str, regs: &mut R) -> Arc<Process> {
    let (p, _) = process(name);
    assert_eq!(sigaction(&p, SIGUSR1, handler(sa::SIGINFO, bit(SIGUSR2))), 0);
    call(&p, Sys::Kill, &[p.pid().0 as u64, SIGUSR1 as u64]);
    assert_eq!(signal::deliver_to(&p, &p.leader(), regs), None);
    assert_eq!(regs.user_pc(), HANDLER);
    p
}

fn i32_at(p: &Process, va: u64) -> i32 {
    i32::from_ne_bytes(get(p, va, 4).try_into().unwrap())
}

/// The `siginfo_t` at `info` is a `kill` of `SIGUSR1` by `p` itself.
fn check_info(p: &Process, info: u64) {
    assert_eq!(i32_at(p, info), SIGUSR1 as i32, "si_signo");
    assert_eq!(i32_at(p, info + 8), 0, "si_code SI_USER");
    assert_eq!(i32_at(p, info + 16), p.pid().0 as i32, "si_pid");
    assert_eq!(i32_at(p, info + 20), 0, "si_uid");
}

#[test]
fn x86_64_frame_is_linux_rt_sigframe() {
    let mut r = X86_64 { cs: 0x33, ss: 0x2b, rflags: 0x202 | 0x1, rip: 0x40_0000, rsp: STACK, ..Default::default() };
    for (i, g) in [&mut r.r8, &mut r.r9, &mut r.r10, &mut r.r11, &mut r.r12, &mut r.r13, &mut r.r14, &mut r.r15]
        .into_iter()
        .enumerate()
    {
        *g = 0x800 + i as u64;
    }
    (r.rdi, r.rsi, r.rbp, r.rbx, r.rdx, r.rax, r.rcx) = (0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17);
    let before = r.clone();
    let p = deliver("frame-x86", &mut r);
    let frame = r.rsp;
    assert_eq!(frame % 16, 8, "as if called: the return address is pushed");
    assert!(frame + 440 <= STACK - 128, "below the red zone");
    let (uc, info) = (frame + 8, frame + 312);
    assert_eq!((r.rdi, r.rsi, r.rdx), (SIGUSR1 as u64, info, uc));
    assert_eq!(r.rax, 0);
    check_info(&p, info);
    assert_eq!(word(&p, frame), word(&p, frame), "pretcode");
    assert!((0x100_0000..0x110_0000).contains(&word(&p, frame)), "pretcode is the trampoline");
    assert_eq!(word(&p, uc), 6, "uc_flags: UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS");
    // uc_mcontext (struct sigcontext) at uc + 40.
    let mc = uc + 40;
    assert_eq!(word(&p, mc), 0x800, "r8");
    assert_eq!(word(&p, mc + 7 * 8), 0x807, "r15");
    assert_eq!(word(&p, mc + 13 * 8), 0x16, "rax");
    assert_eq!(word(&p, mc + 15 * 8), STACK, "rsp");
    assert_eq!(word(&p, mc + 16 * 8), 0x40_0000, "rip");
    assert_eq!(word(&p, mc + 17 * 8), 0x203, "eflags");
    assert_eq!(get(&p, mc + 144, 2), 0x33u16.to_ne_bytes(), "cs");
    assert_eq!(get(&p, mc + 150, 2), 0x2bu16.to_ne_bytes(), "ss");
    assert_eq!(word(&p, mc + 184), 0, "no fpstate");
    assert_eq!(word(&p, uc + 296), 0, "uc_sigmask");

    // The handler changes a register and the flags (privileged bits too), and returns.
    let th = p.leader();
    put(&p, mc + 12 * 8, &0xbeefu64.to_ne_bytes());
    put(&p, mc + 17 * 8, &(0x3000u64 | 0x100 | 0x40).to_ne_bytes());
    r.rbx = 0;
    r.rsp = frame + 8;
    assert_eq!(signal::sigreturn(&p, &th, &mut r), None);
    assert_eq!(r.rdx, 0xbeef, "a changed register comes back");
    assert_eq!(r.rflags, 0x202 | 0x40, "ZF; not IOPL or TF");
    assert_eq!((r.cs, r.ss, r.rip, r.rsp, r.rbx), (before.cs, before.ss, before.rip, before.rsp, before.rbx));
    assert_eq!(th.signal_mask(), 0);
}

#[test]
fn aarch64_frame_is_linux_rt_sigframe() {
    let mut r = Aarch64 { sp: STACK, elr: 0x40_0000, spsr: 0x2000_0000, ..Default::default() };
    for (i, x) in r.x.iter_mut().enumerate() {
        *x = 0x900 + i as u64;
    }
    let before = r.clone();
    let p = deliver("frame-a64", &mut r);
    let frame = r.sp;
    assert_eq!(frame % 16, 0);
    assert!(frame + 4704 <= STACK);
    let (info, uc) = (frame, frame + 128);
    assert_eq!(r.x[..3], [SIGUSR1 as u64, info, uc]);
    check_info(&p, info);
    // sigcontext at uc + 176: fault_address, regs[31], sp, pc, pstate.
    let mc = uc + 176;
    assert_eq!(word(&p, mc), 0, "fault_address");
    assert_eq!(word(&p, mc + 8), 0x900, "x0");
    assert_eq!(word(&p, mc + 8 + 30 * 8), 0x900 + 30, "x30");
    assert_eq!(word(&p, mc + 256), STACK, "sp");
    assert_eq!(word(&p, mc + 264), 0x40_0000, "pc");
    assert_eq!(word(&p, mc + 272), 0x2000_0000, "pstate");
    assert_eq!(get(&p, mc + 288, 8), [0; 8], "the records end at once");
    assert_eq!(word(&p, uc + 40), 0, "uc_sigmask");
    // The frame record after the rt_sigframe, which x29 points at.
    assert_eq!(r.x[29], frame + 4688);
    assert_eq!((word(&p, frame + 4688), word(&p, frame + 4696)), (0x900 + 29, 0x900 + 30));
    assert!((0x100_0000..0x110_0000).contains(&r.x[30]), "the link register is the trampoline");

    let th = p.leader();
    put(&p, mc + 8 + 5 * 8, &0xbeefu64.to_ne_bytes());
    put(&p, mc + 272, &(0xf000_0000u64 | 0x3c5).to_ne_bytes());
    assert_eq!(signal::sigreturn(&p, &th, &mut r), None);
    assert_eq!(r.x[5], 0xbeef);
    assert_eq!(r.spsr, 0xf000_0000, "only NZCV changes: no exception level or masks");
    assert_eq!((r.sp, r.elr, r.x[4]), (before.sp, before.elr, before.x[4]));
    assert_eq!(th.signal_mask(), 0);
}

#[test]
fn riscv64_frame_is_linux_rt_sigframe() {
    let mut r = Riscv64 { epc: 0x40_0000, ..Default::default() };
    for (i, x) in r.x.iter_mut().enumerate().skip(1) {
        *x = 0xa00 + i as u64;
    }
    r.x[2] = STACK;
    let before = r.clone();
    let p = deliver("frame-rv", &mut r);
    let frame = r.x[2];
    assert_eq!(frame % 16, 0);
    assert!(frame + 1088 <= STACK);
    let (info, uc) = (frame, frame + 128);
    assert_eq!(r.x[10..13], [SIGUSR1 as u64, info, uc]);
    check_info(&p, info);
    // sigcontext at uc + 176: pc, then x1..x31, then FP state.
    let mc = uc + 176;
    assert_eq!(word(&p, mc), 0x40_0000, "pc");
    assert_eq!(word(&p, mc + 8), 0xa01, "ra");
    assert_eq!(word(&p, mc + 2 * 8), STACK, "sp");
    assert_eq!(word(&p, mc + 31 * 8), 0xa00 + 31, "t6");
    assert_eq!(get(&p, mc + 256, 528), [0; 528], "no FP state");
    assert!((0x100_0000..0x110_0000).contains(&r.x[1]), "ra is the trampoline");

    let th = p.leader();
    put(&p, mc + 8 * 8, &0xbeefu64.to_ne_bytes());
    assert_eq!(signal::sigreturn(&p, &th, &mut r), None);
    assert_eq!(r.x[8], 0xbeef);
    assert_eq!((r.epc, r.x[0], r.x[2], r.x[9]), (before.epc, 0, before.x[2], before.x[9]));
}

#[test]
fn a_handler_can_change_the_mask_and_alternate_stack_it_returns_to() {
    let mut r = Riscv64 { epc: 0x40_0000, ..Default::default() };
    r.x[2] = STACK;
    let p = deliver("frame-uc", &mut r);
    let th = p.leader();
    let uc = r.x[2] + 128;
    // uc_sigmask, and uc_stack { ss_sp, ss_flags, ss_size }.
    put(&p, uc + 40, &(bit(SIGUSR2) | bit(SIGKILL)).to_ne_bytes());
    put(&p, uc + 16, &(DATA + 0x1000).to_ne_bytes());
    put(&p, uc + 24, &0i32.to_ne_bytes());
    put(&p, uc + 32, &0x1800u64.to_ne_bytes());
    assert_eq!(signal::sigreturn(&p, &th, &mut r), None);
    assert_eq!(th.signal_mask(), bit(SIGUSR2), "SIGKILL cannot be blocked");
    assert_eq!(th.sig.alt_state(STACK), (DATA + 0x1000, 0, 0x1800), "the alternate stack is set");
}

#[test]
fn the_register_setters_reach_each_architecture() {
    let mut x = X86_64::default();
    x.set_ret(1);
    x.set_user_sp(2);
    x.set_tls(3);
    assert_eq!((x.rax, x.rsp), (1, 2));
    let mut a = Aarch64::default();
    a.set_ret(1);
    a.set_user_sp(2);
    a.set_tls(3);
    assert_eq!((a.x[0], a.sp, a.tpidrro), (1, 2, 3));
    let mut v = Riscv64::default();
    v.set_ret(1);
    v.set_user_sp(2);
    v.set_tls(3);
    assert_eq!((v.x[10], v.x[2], v.x[4]), (1, 2, 3));
    // A restarted call goes back over its instruction.
    (x.rip, a.elr, v.epc) = (0x1002, 0x1004, 0x1004);
    x.rewind_syscall(7, 9);
    a.rewind_syscall(7, 9);
    v.rewind_syscall(7, 9);
    assert_eq!((x.rip, x.rax), (0x1000, 7));
    assert_eq!((a.elr, a.x[8], a.x[0]), (0x1000, 7, 9));
    assert_eq!((v.epc, v.x[17], v.x[10]), (0x1000, 7, 9));
    assert!(X86_64::valid_pc(0x7fff_ffff_f000) && !X86_64::valid_pc(0x8000_0000_0000));
}

#[test]
fn sigchld_carries_how_the_child_ended() {
    platform();
    let (p, _) = process("frame-chld");
    assert_eq!(sigaction(&p, SIGCHLD, handler(sa::SIGINFO, 0)), 0);
    let Outcome::Fork { child, .. } = dispatch(&p, Sys::Fork.number(), [0; 6]) else { panic!("no fork") };
    Process::find(child).unwrap().set_exited(ExitStatus::Code(3));
    let mut r = Riscv64 { epc: 0x40_0000, ..Default::default() };
    r.x[2] = STACK;
    assert_eq!(signal::deliver_to(&p, &p.leader(), &mut r), None);
    let info = r.x[11];
    assert_eq!(i32_at(&p, info), SIGCHLD as i32);
    assert_eq!(i32_at(&p, info + 8), 1, "CLD_EXITED");
    assert_eq!(i32_at(&p, info + 16), child.0 as i32, "si_pid");
    assert_eq!(i32_at(&p, info + 24), 3, "si_status");
    assert_eq!(call(&p, Sys::Wait4, &[child.0 as u64, 0, 0, 0]), child.0 as i64);
}

/// FP/SIMD state, set as the calling thread's registers for one test.
fn fp_regs(len: usize, xfeatures: u64, fill: impl Fn(&mut [u8])) -> Vec<u8> {
    let mut b: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
    fill(&mut b);
    crate::sigfp::test_regs::set(Some(crate::sigfp::Image::new(&b, xfeatures).unwrap()));
    b
}

fn x86_regs() -> X86_64 {
    X86_64 { cs: 0x33, ss: 0x2b, rflags: 0x202, rip: 0x40_0000, rsp: STACK, ..Default::default() }
}

/// An x86_64 FXSAVE image with a valid MXCSR.
fn fxsave(b: &mut [u8]) {
    b[24..28].copy_from_slice(&0x1f80u32.to_ne_bytes());
}

#[test]
fn x86_64_frames_point_at_an_fxsave_area() {
    let regs = fp_regs(512, 0, fxsave);
    let mut r = x86_regs();
    let p = deliver("fp-fx", &mut r);
    let (frame, mc) = (r.rsp, r.rsp + 8 + 40);
    let area = word(&p, mc + 184);
    assert_eq!(area % 64, 0, "fpstate is 64-byte aligned");
    assert!(frame + 440 <= area && area + 512 <= STACK - 128, "between the frame and the red zone");
    assert_eq!(get(&p, area, 464), regs[..464], "the FXSAVE image");
    assert_eq!(get(&p, area + 464, 48), [0; 48], "no fpx_sw_bytes");
    assert_eq!(word(&p, frame + 8), 6, "uc_flags without UC_FP_XSTATE");
    assert_eq!(crate::sigfp::test_regs::loaded(), [None], "the handler starts with the registers reset");

    // The handler changes xmm0; the change comes back.
    put(&p, area + 160, &[0xee; 16]);
    r.rsp = frame + 8;
    assert_eq!(signal::sigreturn(&p, &p.leader(), &mut r), None);
    let mut want = regs.clone();
    want[160..176].fill(0xee);
    want[464..].fill(0);
    assert_eq!(crate::sigfp::test_regs::loaded().last().unwrap().as_deref(), Some(&want[..]));
    crate::sigfp::test_regs::set(None);
}

#[test]
fn x86_64_frames_carry_an_xsave_area_with_its_software_bytes() {
    let regs = fp_regs(832, 7, |b| {
        fxsave(b);
        b[512..576].fill(0);
        b[512..520].copy_from_slice(&7u64.to_ne_bytes());
    });
    let mut r = x86_regs();
    let p = deliver("fp-xsave", &mut r);
    let (frame, mc) = (r.rsp, r.rsp + 8 + 40);
    let area = word(&p, mc + 184);
    assert_eq!(area % 64, 0);
    assert!(frame + 440 <= area && area + 836 <= STACK - 128);
    assert_eq!(get(&p, area + 464, 4), 0x4650_5853u32.to_ne_bytes(), "FP_XSTATE_MAGIC1");
    assert_eq!(get(&p, area + 468, 4), 836u32.to_ne_bytes(), "extended_size");
    assert_eq!(word(&p, area + 472), 7, "xfeatures");
    assert_eq!(get(&p, area + 480, 4), 832u32.to_ne_bytes(), "xstate_size");
    assert_eq!(get(&p, area + 512, 320), regs[512..], "the XSAVE header and AVX state");
    assert_eq!(get(&p, area + 832, 4), 0x4650_5845u32.to_ne_bytes(), "FP_XSTATE_MAGIC2");
    assert_eq!(word(&p, frame + 8), 7, "uc_flags with UC_FP_XSTATE");
    let th = p.leader();

    // Returned as it was, the whole area comes back.
    r.rsp = frame + 8;
    assert_eq!(signal::sigreturn(&p, &th, &mut r), None);
    let loaded = crate::sigfp::test_regs::loaded().last().cloned().flatten().unwrap();
    assert_eq!((&loaded[..464], &loaded[512..]), (&regs[..464], &regs[512..]));

    // Without valid software bytes, only x87 and SSE come back; AVX is reset.
    let mut r = x86_regs();
    let p = deliver("fp-xsave-legacy", &mut r);
    let (frame, area) = (r.rsp, word(&p, r.rsp + 8 + 40 + 184));
    put(&p, area + 464, &0u32.to_ne_bytes());
    r.rsp = frame + 8;
    assert_eq!(signal::sigreturn(&p, &p.leader(), &mut r), None);
    let loaded = crate::sigfp::test_regs::loaded().last().cloned().flatten().unwrap();
    assert_eq!(loaded[..464], regs[..464]);
    assert_eq!(u64::from_ne_bytes(loaded[512..520].try_into().unwrap()), 3, "XSTATE_BV: x87 | SSE");
    assert!(loaded[520..].iter().all(|&b| b == 0), "the rest reset");

    // A null fpstate resets the registers.
    let mut r = x86_regs();
    let p = deliver("fp-null", &mut r);
    let frame = r.rsp;
    put(&p, frame + 8 + 40 + 184, &0u64.to_ne_bytes());
    r.rsp = frame + 8;
    assert_eq!(signal::sigreturn(&p, &p.leader(), &mut r), None);
    assert_eq!(crate::sigfp::test_regs::loaded().last(), Some(&None));
    crate::sigfp::test_regs::set(None);
}

#[test]
fn x86_64_sigreturn_refuses_fp_state_that_would_fault() {
    fp_regs(512, 0, fxsave);
    for (what, forge) in [
        ("a reserved MXCSR bit", (24usize, 0x1_1f80u32.to_ne_bytes().to_vec())),
        ("DAZ where the CPU lacks it", (24, 0x1fc0u32.to_ne_bytes().to_vec())),
    ] {
        let mut r = x86_regs();
        let p = deliver("fp-forged", &mut r);
        let (frame, area) = (r.rsp, word(&p, r.rsp + 8 + 40 + 184));
        put(&p, area + forge.0 as u64, &forge.1);
        r.rsp = frame + 8;
        assert_eq!(signal::sigreturn(&p, &p.leader(), &mut r), Some(ExitStatus::Signal(SIGSEGV)), "{what}");
    }
    // An fpstate that is not mapped.
    let mut r = x86_regs();
    let p = deliver("fp-unmapped", &mut r);
    let frame = r.rsp;
    put(&p, frame + 8 + 40 + 184, &0x7777_0000u64.to_ne_bytes());
    r.rsp = frame + 8;
    assert_eq!(signal::sigreturn(&p, &p.leader(), &mut r), Some(ExitStatus::Signal(SIGSEGV)));
    crate::sigfp::test_regs::set(None);
}

#[test]
fn aarch64_frames_carry_an_fpsimd_record() {
    let regs = fp_regs(528, 0, |b| {
        b[512..520].copy_from_slice(&0x0300_0000u64.to_ne_bytes());
        b[520..528].copy_from_slice(&0x1fu64.to_ne_bytes());
    });
    let mut r = Aarch64 { sp: STACK, elr: 0x40_0000, ..Default::default() };
    let p = deliver("fp-a64", &mut r);
    let rec = r.sp + 128 + 176 + 288;
    assert_eq!(get(&p, rec, 4), 0x4650_8001u32.to_ne_bytes(), "FPSIMD_MAGIC");
    assert_eq!(get(&p, rec + 4, 4), 528u32.to_ne_bytes(), "size");
    assert_eq!(get(&p, rec + 8, 4), 0x1fu32.to_ne_bytes(), "fpsr");
    assert_eq!(get(&p, rec + 12, 4), 0x0300_0000u32.to_ne_bytes(), "fpcr");
    assert_eq!(get(&p, rec + 16, 512), regs[..512], "vregs");
    assert_eq!(get(&p, rec + 528, 8), [0; 8], "then the terminating record");
    assert!(crate::sigfp::test_regs::loaded().is_empty(), "the handler keeps the registers");

    put(&p, rec + 16 + 3 * 16, &[0xee; 16]);
    put(&p, rec + 12, &0x0040_0000u32.to_ne_bytes());
    assert_eq!(signal::sigreturn(&p, &p.leader(), &mut r), None);
    let mut want = regs.clone();
    want[48..64].fill(0xee);
    want[512..520].copy_from_slice(&0x0040_0000u64.to_ne_bytes());
    assert_eq!(crate::sigfp::test_regs::loaded().last().unwrap().as_deref(), Some(&want[..]), "q3 and FPCR changed");

    // Forged records end the program.
    for (what, at, bytes) in [
        ("no fpsimd_context", 0u64, [0u8; 8]),
        ("an unknown record", 0, [1, 0, 0, 0, 16, 0, 0, 0]),
        ("a wrong size", 4, [0, 1, 0, 0, 0, 0, 0, 0]),
        ("an unterminated list", 528, [0, 0, 0, 0, 16, 0, 0, 0]),
    ] {
        let mut r = Aarch64 { sp: STACK, elr: 0x40_0000, ..Default::default() };
        let p = deliver("fp-a64-forged", &mut r);
        let rec = r.sp + 128 + 176 + 288;
        put(&p, rec + at, &bytes);
        assert_eq!(signal::sigreturn(&p, &p.leader(), &mut r), Some(ExitStatus::Signal(SIGSEGV)), "{what}");
    }
    // With FP off there is no record, and none is needed.
    crate::sigfp::test_regs::set(None);
    let mut r = Aarch64 { sp: STACK, elr: 0x40_0000, ..Default::default() };
    let p = deliver("fp-a64-off", &mut r);
    assert_eq!(get(&p, r.sp + 128 + 176 + 288, 8), [0; 8]);
    assert_eq!(signal::sigreturn(&p, &p.leader(), &mut r), None);
}

#[test]
fn riscv64_frames_carry_the_d_state() {
    let regs = fp_regs(264, 0, |b| {
        b[256..264].copy_from_slice(&0xe5u64.to_ne_bytes());
    });
    let mut r = Riscv64 { epc: 0x40_0000, ..Default::default() };
    r.x[2] = STACK;
    let p = deliver("fp-rv", &mut r);
    let fp = r.x[2] + 128 + 176 + 256;
    assert_eq!(get(&p, fp, 256), regs[..256], "f0..f31");
    assert_eq!(get(&p, fp + 256, 4), 0xe5u32.to_ne_bytes(), "fcsr");
    assert_eq!(get(&p, fp + 260, 268), [0; 268], "the rest, and the terminating extension header");

    put(&p, fp + 8, &[0xee; 8]);
    assert_eq!(signal::sigreturn(&p, &p.leader(), &mut r), None);
    let mut want = regs.clone();
    want[8..16].fill(0xee);
    assert_eq!(crate::sigfp::test_regs::loaded().last().unwrap().as_deref(), Some(&want[..]), "f1 changed");

    for (what, at) in [("a reserved word", 516u64), ("an extension header", 520)] {
        let mut r = Riscv64 { epc: 0x40_0000, ..Default::default() };
        r.x[2] = STACK;
        let p = deliver("fp-rv-forged", &mut r);
        put(&p, r.x[2] + 128 + 176 + 256 + at, &1u32.to_ne_bytes());
        assert_eq!(signal::sigreturn(&p, &p.leader(), &mut r), Some(ExitStatus::Signal(SIGSEGV)), "{what}");
    }
    crate::sigfp::test_regs::set(None);
}
