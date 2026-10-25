//! The user-visible registers of a trap frame, as signals and threads need
//! them, behind one portable trait.
#![cfg_attr(
    not(any(target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64"))),
    allow(dead_code)
)]

/// Words in a saved register set; every architecture uses a prefix.
pub(crate) const NREGS: usize = 34;

/// The user registers of a trap frame, without anything privileged: what a
/// forged signal frame may and may not restore is decided here, per
/// architecture.
pub(crate) trait UserRegs {
    /// Bytes below the stack pointer that user code may be using.
    const RED_ZONE: u64;
    /// Whether a call pushes its return address (x86) instead of setting a
    /// link register.
    const RET_ON_STACK: bool;

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
    fn save_user(&self) -> [u64; NREGS];
    fn restore_user(&mut self, saved: &[u64; NREGS]);
    /// Arranges to run `pc` as a signal handler: with stack `sp`, return
    /// address `ra` (for architectures that use a link register) and
    /// arguments `args`.
    fn enter_handler(&mut self, pc: u64, sp: u64, ra: u64, args: [u64; 3]);
    /// Arranges for the system-call instruction that just trapped to run
    /// again as call `nr` with first argument `arg0`: the program counter
    /// goes back over the instruction, and the registers the call's result
    /// overwrote (the number on x86_64, the first argument elsewhere) are
    /// restored.
    fn rewind_syscall(&mut self, nr: u64, arg0: u64);
}

#[cfg(target_arch = "riscv64")]
impl UserRegs for osmium_arch::trap::TrapFrame {
    const RED_ZONE: u64 = 0;
    const RET_ON_STACK: bool = false;

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
    fn save_user(&self) -> [u64; NREGS] {
        let mut s = [0; NREGS];
        s[..32].copy_from_slice(&self.x);
        s[32] = self.epc;
        s
    }
    fn restore_user(&mut self, s: &[u64; NREGS]) {
        self.x.copy_from_slice(&s[..32]);
        self.x[0] = 0;
        self.epc = s[32];
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

#[cfg(target_arch = "aarch64")]
impl UserRegs for osmium_arch::trap::TrapFrame {
    const RED_ZONE: u64 = 0;
    const RET_ON_STACK: bool = false;

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
    fn save_user(&self) -> [u64; NREGS] {
        let mut s = [0; NREGS];
        s[..31].copy_from_slice(&self.x);
        (s[31], s[32], s[33]) = (self.sp, self.elr, self.spsr);
        s
    }
    fn restore_user(&mut self, s: &[u64; NREGS]) {
        self.x.copy_from_slice(&s[..31]);
        (self.sp, self.elr) = (s[31], s[32]);
        // Only the condition flags are the program's to change.
        const NZCV: u64 = 0xf << 28;
        self.spsr = self.spsr & !NZCV | s[33] & NZCV;
    }
    fn enter_handler(&mut self, pc: u64, sp: u64, ra: u64, args: [u64; 3]) {
        self.elr = pc;
        self.sp = sp;
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

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl UserRegs for osmium_arch::trap::TrapFrame {
    const RED_ZONE: u64 = 128;
    const RET_ON_STACK: bool = true;

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
    fn save_user(&self) -> [u64; NREGS] {
        let mut s = [0; NREGS];
        let f = self;
        let regs = [
            f.rax, f.rbx, f.rcx, f.rdx, f.rsi, f.rdi, f.rbp, f.r8, f.r9, f.r10, f.r11, f.r12, f.r13, f.r14, f.r15,
            f.rip, f.rsp, f.rflags,
        ];
        for (d, r) in s.iter_mut().zip(regs) {
            *d = r;
        }
        s
    }
    fn restore_user(&mut self, s: &[u64; NREGS]) {
        let f = self;
        [f.rax, f.rbx, f.rcx, f.rdx, f.rsi, f.rdi, f.rbp] = [s[0], s[1], s[2], s[3], s[4], s[5], s[6]];
        [f.r8, f.r9, f.r10, f.r11, f.r12, f.r13, f.r14, f.r15] = [s[7], s[8], s[9], s[10], s[11], s[12], s[13], s[14]];
        (f.rip, f.rsp) = (s[15], s[16]);
        // Arithmetic flags and DF only; IF stays set, IOPL, NT, TF and the rest stay clear.
        const USER_FLAGS: u64 = 0xcd5;
        f.rflags = s[17] & USER_FLAGS | 0x202;
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
