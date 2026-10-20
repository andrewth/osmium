//! Saved CPU state and the context switch.
//!
//! Only callee-saved registers are saved: a switch is an ordinary function
//! call from the compiler's point of view, so everything else is already
//! spilled by the caller. Interrupt and user-mode state belongs to trap
//! frames, not here.

/// Callee-saved registers of a switched-out task.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Default)]
pub struct Context {
    rsp: u64,
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

#[cfg(target_arch = "x86_64")]
impl Context {
    /// A context that starts executing `entry` on the stack ending at
    /// `stack_top` (16-byte aligned).
    ///
    /// # Safety
    /// The stack must be writable and large enough for `entry`.
    ///
    /// # Panics
    ///
    /// If `stack_top` is not 16-byte aligned.
    pub unsafe fn new(stack_top: usize, entry: extern "C" fn() -> !) -> Self {
        assert_eq!(stack_top % 16, 0);
        // `switch` ends in `ret`, which pops this slot. Afterwards rsp is
        // 8 mod 16, exactly as if `entry` had been called.
        let slot = stack_top - 16;
        // SAFETY: the slot is inside the caller-provided stack.
        unsafe { (slot as *mut u64).write(entry as usize as u64) };
        Self { rsp: slot as u64, ..Self::default() }
    }
}

/// Saves the current registers into `from` and resumes `to`.
///
/// # Safety
/// `to` must hold a context saved by `switch` or built by [`Context::new`],
/// whose stack is still alive; `from` must be writable.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
pub unsafe extern "C" fn switch(from: *mut Context, to: *const Context) {
    core::arch::naked_asm!(
        "mov [rdi + 0x00], rsp",
        "mov [rdi + 0x08], rbx",
        "mov [rdi + 0x10], rbp",
        "mov [rdi + 0x18], r12",
        "mov [rdi + 0x20], r13",
        "mov [rdi + 0x28], r14",
        "mov [rdi + 0x30], r15",
        "mov rsp, [rsi + 0x00]",
        "mov rbx, [rsi + 0x08]",
        "mov rbp, [rsi + 0x10]",
        "mov r12, [rsi + 0x18]",
        "mov r13, [rsi + 0x20]",
        "mov r14, [rsi + 0x28]",
        "mov r15, [rsi + 0x30]",
        "ret",
    )
}

/// Callee-saved registers of a switched-out task.
#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Default)]
pub struct Context {
    /// x19..=x28, x29 (fp), x30 (lr).
    x: [u64; 12],
    sp: u64,
    /// d8..=d15, saved only when the target has FP registers.
    d: [u64; 8],
}

#[cfg(target_arch = "aarch64")]
impl Context {
    /// A context that starts executing `entry` on the stack ending at
    /// `stack_top` (16-byte aligned).
    ///
    /// # Safety
    /// The stack must be writable and large enough for `entry`.
    ///
    /// # Panics
    ///
    /// If `stack_top` is not 16-byte aligned.
    pub unsafe fn new(stack_top: usize, entry: extern "C" fn() -> !) -> Self {
        assert_eq!(stack_top % 16, 0);
        let mut c = Self::default();
        c.x[11] = entry as usize as u64;
        c.sp = stack_top as u64;
        c
    }
}

/// Saves the current registers into `from` and resumes `to`.
///
/// # Safety
/// `to` must hold a context saved by `switch` or built by [`Context::new`],
/// whose stack is still alive; `from` must be writable.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
pub unsafe extern "C" fn switch(from: *mut Context, to: *const Context) {
    #[cfg(target_feature = "neon")]
    core::arch::naked_asm!(
        "stp x19, x20, [x0, #0]",
        "stp x21, x22, [x0, #16]",
        "stp x23, x24, [x0, #32]",
        "stp x25, x26, [x0, #48]",
        "stp x27, x28, [x0, #64]",
        "stp x29, x30, [x0, #80]",
        "mov x9, sp",
        "str x9, [x0, #96]",
        "stp d8, d9, [x0, #104]",
        "stp d10, d11, [x0, #120]",
        "stp d12, d13, [x0, #136]",
        "stp d14, d15, [x0, #152]",
        "ldp x19, x20, [x1, #0]",
        "ldp x21, x22, [x1, #16]",
        "ldp x23, x24, [x1, #32]",
        "ldp x25, x26, [x1, #48]",
        "ldp x27, x28, [x1, #64]",
        "ldp x29, x30, [x1, #80]",
        "ldr x9, [x1, #96]",
        "mov sp, x9",
        "ldp d8, d9, [x1, #104]",
        "ldp d10, d11, [x1, #120]",
        "ldp d12, d13, [x1, #136]",
        "ldp d14, d15, [x1, #152]",
        "ret",
    );
    #[cfg(not(target_feature = "neon"))]
    core::arch::naked_asm!(
        "stp x19, x20, [x0, #0]",
        "stp x21, x22, [x0, #16]",
        "stp x23, x24, [x0, #32]",
        "stp x25, x26, [x0, #48]",
        "stp x27, x28, [x0, #64]",
        "stp x29, x30, [x0, #80]",
        "mov x9, sp",
        "str x9, [x0, #96]",
        "ldp x19, x20, [x1, #0]",
        "ldp x21, x22, [x1, #16]",
        "ldp x23, x24, [x1, #32]",
        "ldp x25, x26, [x1, #48]",
        "ldp x27, x28, [x1, #64]",
        "ldp x29, x30, [x1, #80]",
        "ldr x9, [x1, #96]",
        "mov sp, x9",
        "ret",
    );
}

/// Callee-saved registers of a switched-out task.
#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Debug, Default)]
pub struct Context {
    ra: u64,
    sp: u64,
    /// s0..=s11.
    s: [u64; 12],
    /// fs0..=fs11, saved only when the target has the D extension.
    fs: [u64; 12],
}

#[cfg(target_arch = "riscv64")]
impl Context {
    /// A context that starts executing `entry` on the stack ending at
    /// `stack_top` (16-byte aligned).
    ///
    /// # Safety
    /// The stack must be writable and large enough for `entry`.
    ///
    /// # Panics
    ///
    /// If `stack_top` is not 16-byte aligned.
    pub unsafe fn new(stack_top: usize, entry: extern "C" fn() -> !) -> Self {
        assert_eq!(stack_top % 16, 0);
        Self { ra: entry as usize as u64, sp: stack_top as u64, ..Self::default() }
    }
}

#[cfg(target_arch = "riscv64")]
macro_rules! riscv_switch {
    ($($fp:literal),*) => {
        core::arch::naked_asm!(
            "sd ra, 0(a0)", "sd sp, 8(a0)",
            "sd s0, 16(a0)", "sd s1, 24(a0)", "sd s2, 32(a0)", "sd s3, 40(a0)",
            "sd s4, 48(a0)", "sd s5, 56(a0)", "sd s6, 64(a0)", "sd s7, 72(a0)",
            "sd s8, 80(a0)", "sd s9, 88(a0)", "sd s10, 96(a0)", "sd s11, 104(a0)",
            $($fp,)*
            "ld ra, 0(a1)", "ld sp, 8(a1)",
            "ld s0, 16(a1)", "ld s1, 24(a1)", "ld s2, 32(a1)", "ld s3, 40(a1)",
            "ld s4, 48(a1)", "ld s5, 56(a1)", "ld s6, 64(a1)", "ld s7, 72(a1)",
            "ld s8, 80(a1)", "ld s9, 88(a1)", "ld s10, 96(a1)", "ld s11, 104(a1)",
            "ret",
        )
    };
}

/// Saves the current registers into `from` and resumes `to`.
///
/// # Safety
/// `to` must hold a context saved by `switch` or built by [`Context::new`],
/// whose stack is still alive; `from` must be writable.
#[cfg(target_arch = "riscv64")]
#[unsafe(naked)]
pub unsafe extern "C" fn switch(from: *mut Context, to: *const Context) {
    #[cfg(target_feature = "d")]
    riscv_switch!(
        "fsd fs0, 112(a0)",
        "fsd fs1, 120(a0)",
        "fsd fs2, 128(a0)",
        "fsd fs3, 136(a0)",
        "fsd fs4, 144(a0)",
        "fsd fs5, 152(a0)",
        "fsd fs6, 160(a0)",
        "fsd fs7, 168(a0)",
        "fsd fs8, 176(a0)",
        "fsd fs9, 184(a0)",
        "fsd fs10, 192(a0)",
        "fsd fs11, 200(a0)",
        "fld fs0, 112(a1)",
        "fld fs1, 120(a1)",
        "fld fs2, 128(a1)",
        "fld fs3, 136(a1)",
        "fld fs4, 144(a1)",
        "fld fs5, 152(a1)",
        "fld fs6, 160(a1)",
        "fld fs7, 168(a1)",
        "fld fs8, 176(a1)",
        "fld fs9, 184(a1)",
        "fld fs10, 192(a1)",
        "fld fs11, 200(a1)"
    );
    #[cfg(not(target_feature = "d"))]
    riscv_switch!();
}
