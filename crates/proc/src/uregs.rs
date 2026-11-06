//! The user-visible registers of a trap frame, as signals and threads need
//! them, behind one portable trait, and each architecture's Linux signal
//! frame (`struct rt_sigframe`).
//!
//! The register code of each architecture is written once, as a macro over
//! a type with that architecture's trap-frame fields, and applied both to
//! the real [`osmium_arch::trap::TrapFrame`] and, in tests, to a stand-in
//! with the same fields, so every architecture's frame layout is exercised
//! by host tests whatever the host is.
// Each build uses one architecture's frame and macro; tests use them all.
#![cfg_attr(not(test), allow(dead_code, unused_macros))]

use crate::bytes::{put, u64_at};

/// Where an architecture's `struct rt_sigframe` puts things, as Linux lays
/// it out. Offsets are in bytes from the start of the frame, or of the
/// `ucontext` for its fields.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SigFrame {
    /// Bytes of the whole frame.
    pub size: u64,
    /// Bytes from its start that the kernel builds and writes in one piece:
    /// at most [`HEAD_MAX`]. The rest of the frame (AArch64's unused record
    /// space) is left as it was, as on Linux.
    pub head: usize,
    /// The `siginfo_t`.
    pub info: usize,
    /// The `ucontext_t`.
    pub uc: usize,
    /// `uc_sigmask`, within the `ucontext_t`.
    pub sigmask: usize,
    /// `uc_mcontext`, within the `ucontext_t`.
    pub mcontext: usize,
    /// The frame starts this far below a 16-byte boundary: x86_64's
    /// handler starts as if called, with its return address pushed.
    pub misalign: u64,
    /// The return address the handler's `ret` pops (x86_64's `pretcode`),
    /// if it returns through the stack rather than a link register.
    pub ret_slot: Option<usize>,
    /// `rt_sigreturn` finds the frame this far below the stack pointer it
    /// is called with (x86_64's `ret` popped `pretcode`).
    pub sigreturn_back: u64,
    /// `uc_flags`.
    pub uc_flags: u64,
}

/// Most bytes of a frame built at once (RISC-V's whole frame).
pub(crate) const HEAD_MAX: usize = 1088;

/// x86_64: `pretcode`, then `ucontext` (flags, link, `stack_t`, 256 bytes of
/// `sigcontext`, an 8-byte `sigset_t`), then `siginfo`. No FP state follows
/// (`fpstate` is null).
pub(crate) const X86_64_FRAME: SigFrame = SigFrame {
    size: 440,
    head: 440,
    info: 312,
    uc: 8,
    sigmask: 296,
    mcontext: 40,
    misalign: 8,
    ret_slot: Some(0),
    sigreturn_back: 8,
    // UC_SIGCONTEXT_SS | UC_STRICT_RESTORE_SS.
    uc_flags: 0x6,
};

/// AArch64: `siginfo`, then `ucontext` (flags, link, `stack_t`, a 128-byte
/// `sigset_t` area, then at 176 the `sigcontext`: `fault_address`,
/// `regs[31]`, `sp`, `pc`, `pstate` and 4096 bytes of records, here only the
/// terminating null record), then the frame record `{ fp, lr }` that `x29`
/// points at.
pub(crate) const AARCH64_FRAME: SigFrame = SigFrame {
    size: 128 + 4560 + 16,
    head: 128 + 176 + 288 + 16,
    info: 0,
    uc: 128,
    sigmask: 40,
    mcontext: 176,
    misalign: 0,
    ret_slot: None,
    sigreturn_back: 0,
    uc_flags: 0,
};

/// Offset of AArch64's frame record, after the `rt_sigframe`.
pub(crate) const AARCH64_RECORD: usize = 128 + 4560;

/// RISC-V: `siginfo`, then `ucontext` (flags, link, `stack_t`, a 128-byte
/// `sigset_t` area, then at 176 the `sigcontext`: `pc`, `x1`..`x31`, and
/// 528 bytes of FP state, here zero).
pub(crate) const RISCV64_FRAME: SigFrame = SigFrame {
    size: 1088,
    head: 1088,
    info: 0,
    uc: 128,
    sigmask: 40,
    mcontext: 176,
    misalign: 0,
    ret_slot: None,
    sigreturn_back: 0,
    uc_flags: 0,
};

/// The user registers of a trap frame, without anything privileged: what a
/// forged signal frame may and may not restore is decided here, per
/// architecture.
pub(crate) trait UserRegs {
    /// Bytes below the stack pointer that user code may be using.
    const RED_ZONE: u64;
    /// The signal frame's layout.
    const FRAME: SigFrame;

    /// The program counter user mode resumes at.
    fn user_pc(&self) -> u64;
    /// Whether the CPU can resume user mode at `pc` without faulting in the
    /// kernel: x86_64 refuses non-canonical addresses at `iretq`.
    fn valid_pc(pc: u64) -> bool;
    fn user_sp(&self) -> u64;
    fn set_user_sp(&mut self, sp: u64);
    /// Sets the system-call return value register.
    fn set_ret(&mut self, v: u64);
    /// Sets the user thread-pointer register, where the frame has one.
    fn set_tls(&mut self, tls: u64);
    /// Writes the registers into `mc`, the frame's `uc_mcontext` up to the
    /// end of the frame's head (zeroed). `fault` is the address a fault
    /// signal reports (0 otherwise) and `mask` the signal mask saved with
    /// the frame, for the architectures whose `sigcontext` has them.
    fn save_mcontext(&self, mc: &mut [u8], fault: u64, mask: u64);
    /// Restores the unprivileged registers from `mc`, as `save_mcontext`
    /// wrote it or as a handler changed it.
    fn restore_mcontext(&mut self, mc: &[u8]);
    /// The words to store at an offset of the frame other than its head,
    /// before entering the handler: AArch64's frame record.
    fn frame_record(&self) -> Option<(usize, [u64; 2])> {
        None
    }
    /// Arranges to run `pc` as a signal handler: with its frame at `sp`
    /// (the stack pointer), return address `ra` (for architectures that use
    /// a link register) and arguments `args`.
    fn enter_handler(&mut self, pc: u64, sp: u64, ra: u64, args: [u64; 3]);
    /// Arranges for the system-call instruction that just trapped to run
    /// again as call `nr` with first argument `arg0`: the program counter
    /// goes back over the instruction, and the registers the call's result
    /// overwrote (the number on x86_64, the first argument elsewhere) are
    /// restored.
    fn rewind_syscall(&mut self, nr: u64, arg0: u64);
}

/// Reads word `i` of `mc`, 0 past its end.
pub(crate) fn word(mc: &[u8], i: usize) -> u64 {
    u64_at(mc, i * 8).unwrap_or(0)
}

/// Writes word `i` of `mc`; nothing past its end.
pub(crate) fn set_word(mc: &mut [u8], i: usize, v: u64) {
    let _ = put(mc, i * 8, &v.to_ne_bytes());
}

/// The RISC-V registers: `sigcontext` is `pc`, then `x1`..`x31`.
macro_rules! riscv64_user_regs {
    ($frame:ty) => {
        impl $crate::uregs::UserRegs for $frame {
            const RED_ZONE: u64 = 0;
            const FRAME: $crate::uregs::SigFrame = $crate::uregs::RISCV64_FRAME;

            fn user_pc(&self) -> u64 {
                self.epc
            }
            fn valid_pc(_pc: u64) -> bool {
                true
            }
            fn user_sp(&self) -> u64 {
                self.x[2]
            }
            fn set_user_sp(&mut self, sp: u64) {
                self.x[2] = sp;
            }
            fn set_ret(&mut self, v: u64) {
                self.x[10] = v;
            }
            fn set_tls(&mut self, tls: u64) {
                self.x[4] = tls;
            }
            fn save_mcontext(&self, mc: &mut [u8], _fault: u64, _mask: u64) {
                $crate::uregs::set_word(mc, 0, self.epc);
                for (i, &r) in self.x.iter().enumerate().skip(1) {
                    $crate::uregs::set_word(mc, i, r);
                }
            }
            fn restore_mcontext(&mut self, mc: &[u8]) {
                self.epc = $crate::uregs::word(mc, 0);
                for (i, r) in self.x.iter_mut().enumerate() {
                    // `x0` is hard-wired to zero; the `pc` takes its slot.
                    *r = if i == 0 { 0 } else { $crate::uregs::word(mc, i) };
                }
            }
            fn enter_handler(&mut self, pc: u64, sp: u64, ra: u64, args: [u64; 3]) {
                self.epc = pc;
                self.x[2] = sp;
                self.x[1] = ra;
                self.x[10..13].copy_from_slice(&args);
            }
            fn rewind_syscall(&mut self, nr: u64, arg0: u64) {
                // `ecall` is 4 bytes.
                self.epc = self.epc.wrapping_sub(4);
                self.x[10] = arg0;
                self.x[17] = nr;
            }
        }
    };
}

/// The AArch64 registers: `sigcontext` is `fault_address`, `regs[31]`,
/// `sp`, `pc`, `pstate`, then the records.
macro_rules! aarch64_user_regs {
    ($frame:ty) => {
        impl $crate::uregs::UserRegs for $frame {
            const RED_ZONE: u64 = 0;
            const FRAME: $crate::uregs::SigFrame = $crate::uregs::AARCH64_FRAME;

            fn user_pc(&self) -> u64 {
                self.elr
            }
            fn valid_pc(_pc: u64) -> bool {
                true
            }
            fn user_sp(&self) -> u64 {
                self.sp
            }
            fn set_user_sp(&mut self, sp: u64) {
                self.sp = sp;
            }
            fn set_ret(&mut self, v: u64) {
                self.x[0] = v;
            }
            fn set_tls(&mut self, tls: u64) {
                self.tpidrro = tls;
            }
            fn save_mcontext(&self, mc: &mut [u8], fault: u64, _mask: u64) {
                $crate::uregs::set_word(mc, 0, fault);
                for (i, &r) in self.x.iter().enumerate() {
                    $crate::uregs::set_word(mc, 1 + i, r);
                }
                $crate::uregs::set_word(mc, 32, self.sp);
                $crate::uregs::set_word(mc, 33, self.elr);
                $crate::uregs::set_word(mc, 34, self.spsr);
                // `__reserved` (at 288) starts with the terminating record:
                // magic 0, size 0, which the zeroed buffer already holds.
            }
            fn restore_mcontext(&mut self, mc: &[u8]) {
                for (i, r) in self.x.iter_mut().enumerate() {
                    *r = $crate::uregs::word(mc, 1 + i);
                }
                self.sp = $crate::uregs::word(mc, 32);
                self.elr = $crate::uregs::word(mc, 33);
                // Only the condition flags are the program's to change.
                const NZCV: u64 = 0xf << 28;
                self.spsr = self.spsr & !NZCV | $crate::uregs::word(mc, 34) & NZCV;
            }
            fn frame_record(&self) -> Option<(usize, [u64; 2])> {
                Some(($crate::uregs::AARCH64_RECORD, [self.x[29], self.x[30]]))
            }
            fn enter_handler(&mut self, pc: u64, sp: u64, ra: u64, args: [u64; 3]) {
                self.elr = pc;
                self.sp = sp;
                self.x[29] = sp.wrapping_add($crate::uregs::AARCH64_RECORD as u64);
                self.x[30] = ra;
                self.x[..3].copy_from_slice(&args);
            }
            fn rewind_syscall(&mut self, nr: u64, arg0: u64) {
                // `svc` is 4 bytes.
                self.elr = self.elr.wrapping_sub(4);
                self.x[0] = arg0;
                self.x[8] = nr;
            }
        }
    };
}

/// The x86_64 registers: `sigcontext` is `r8`..`r15`, `rdi`, `rsi`, `rbp`,
/// `rbx`, `rdx`, `rax`, `rcx`, `rsp`, `rip`, `eflags`, the selectors, `err`,
/// `trapno`, `oldmask`, `cr2`, `fpstate` (null here) and reserved words.
macro_rules! x86_64_user_regs {
    ($frame:ty) => {
        impl $crate::uregs::UserRegs for $frame {
            const RED_ZONE: u64 = 128;
            const FRAME: $crate::uregs::SigFrame = $crate::uregs::X86_64_FRAME;

            fn user_pc(&self) -> u64 {
                self.rip
            }
            fn valid_pc(pc: u64) -> bool {
                // Canonical, user half: the high bits are all clear.
                pc >> 47 == 0
            }
            fn user_sp(&self) -> u64 {
                self.rsp
            }
            fn set_user_sp(&mut self, sp: u64) {
                self.rsp = sp;
            }
            fn set_ret(&mut self, v: u64) {
                self.rax = v;
            }
            fn set_tls(&mut self, _tls: u64) {
                // FS.base is not part of the frame: see `thread::tls_for`.
            }
            fn save_mcontext(&self, mc: &mut [u8], fault: u64, mask: u64) {
                let f = self;
                let gregs = [
                    f.r8, f.r9, f.r10, f.r11, f.r12, f.r13, f.r14, f.r15, f.rdi, f.rsi, f.rbp, f.rbx, f.rdx, f.rax,
                    f.rcx, f.rsp, f.rip, f.rflags,
                ];
                for (i, r) in gregs.into_iter().enumerate() {
                    $crate::uregs::set_word(mc, i, r);
                }
                // cs, gs, fs and ss, 16 bits each; gs and fs are not used.
                $crate::uregs::set_word(mc, 18, f.cs & 0xffff | (f.ss & 0xffff) << 48);
                $crate::uregs::set_word(mc, 19, f.error_code);
                $crate::uregs::set_word(mc, 20, f.vector);
                $crate::uregs::set_word(mc, 21, mask);
                $crate::uregs::set_word(mc, 22, fault);
            }
            fn restore_mcontext(&mut self, mc: &[u8]) {
                let w = |i| $crate::uregs::word(mc, i);
                let f = self;
                [f.r8, f.r9, f.r10, f.r11, f.r12, f.r13, f.r14, f.r15] =
                    [w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7)];
                [f.rdi, f.rsi, f.rbp, f.rbx, f.rdx, f.rax, f.rcx] = [w(8), w(9), w(10), w(11), w(12), w(13), w(14)];
                (f.rsp, f.rip) = (w(15), w(16));
                // Arithmetic flags and DF only; IF stays set, IOPL, NT, TF
                // and the rest stay clear. The selectors are the kernel's.
                const USER_FLAGS: u64 = 0xcd5;
                f.rflags = w(17) & USER_FLAGS | 0x202;
            }
            fn enter_handler(&mut self, pc: u64, sp: u64, _ra: u64, args: [u64; 3]) {
                self.rip = pc;
                self.rsp = sp;
                // The handler starts with DF clear, as the ABI requires.
                self.rflags &= !0x400;
                [self.rdi, self.rsi, self.rdx] = args;
                // A syscall number left in rax must not leak into the handler.
                self.rax = 0;
            }
            fn rewind_syscall(&mut self, nr: u64, _arg0: u64) {
                // `syscall` is 2 bytes, and leaves `rdi` alone.
                self.rip = self.rip.wrapping_sub(2);
                self.rax = nr;
            }
        }
    };
}

#[cfg(target_arch = "riscv64")]
riscv64_user_regs!(osmium_arch::trap::TrapFrame);
#[cfg(target_arch = "aarch64")]
aarch64_user_regs!(osmium_arch::trap::TrapFrame);
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
x86_64_user_regs!(osmium_arch::trap::TrapFrame);

/// Stand-ins with each architecture's trap-frame fields, so the register
/// code above runs on any host.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod frames {
    /// RISC-V's trap frame fields.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Riscv64 {
        pub x: [u64; 32],
        pub epc: u64,
    }
    riscv64_user_regs!(Riscv64);

    /// AArch64's trap frame fields.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub(crate) struct Aarch64 {
        pub x: [u64; 31],
        pub sp: u64,
        pub elr: u64,
        pub spsr: u64,
        pub tpidrro: u64,
    }
    aarch64_user_regs!(Aarch64);

    /// x86_64's trap frame fields.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub(crate) struct X86_64 {
        pub r15: u64,
        pub r14: u64,
        pub r13: u64,
        pub r12: u64,
        pub r11: u64,
        pub r10: u64,
        pub r9: u64,
        pub r8: u64,
        pub rbp: u64,
        pub rdi: u64,
        pub rsi: u64,
        pub rdx: u64,
        pub rcx: u64,
        pub rbx: u64,
        pub rax: u64,
        pub vector: u64,
        pub error_code: u64,
        pub rip: u64,
        pub cs: u64,
        pub rflags: u64,
        pub rsp: u64,
        pub ss: u64,
    }
    x86_64_user_regs!(X86_64);
}
