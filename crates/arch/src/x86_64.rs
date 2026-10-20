//! x86_64 registers and instructions: port I/O, MSRs, control registers, CPUID.
//!
//! Everything here is privileged; on a hosted target the functions compile
//! but fault if called.

use core::arch::asm;

/// Well-known model-specific register numbers.
pub mod msr {
    /// Local APIC base address and enable bits.
    pub const IA32_APIC_BASE: u32 = 0x1b;
    /// Extended feature enables (SCE, LME, NXE).
    pub const IA32_EFER: u32 = 0xc000_0080;
    /// FS segment base.
    pub const IA32_FS_BASE: u32 = 0xc000_0100;
    /// GS segment base.
    pub const IA32_GS_BASE: u32 = 0xc000_0101;
    /// Target of `swapgs`.
    pub const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;
    /// Value returned in ECX by `rdtscp`; Osmium stores the CPU id here.
    pub const IA32_TSC_AUX: u32 = 0xc000_0103;
    /// `syscall` segment selectors.
    pub const IA32_STAR: u32 = 0xc000_0081;
    /// `syscall` entry point.
    pub const IA32_LSTAR: u32 = 0xc000_0082;
    /// RFLAGS bits cleared on `syscall`.
    pub const IA32_FMASK: u32 = 0xc000_0084;
    /// VMX capability reporting base.
    pub const IA32_VMX_BASIC: u32 = 0x480;
    /// Feature control (VMX enable lock).
    pub const IA32_FEATURE_CONTROL: u32 = 0x3a;
}

/// Reads a byte from an I/O port.
///
/// # Safety
/// Port I/O can reconfigure hardware; the caller must own the device.
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: the caller owns the port.
    unsafe { asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}

/// Writes a byte to an I/O port.
///
/// # Safety
/// See [`inb`].
#[inline]
pub unsafe fn outb(port: u16, v: u8) {
    // SAFETY: the caller owns the port.
    unsafe { asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack, preserves_flags)) }
}

/// Reads a 16-bit word from an I/O port.
///
/// # Safety
/// See [`inb`].
#[inline]
pub unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    // SAFETY: the caller owns the port.
    unsafe { asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}

/// Writes a 16-bit word to an I/O port.
///
/// # Safety
/// See [`inb`].
#[inline]
pub unsafe fn outw(port: u16, v: u16) {
    // SAFETY: the caller owns the port.
    unsafe { asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack, preserves_flags)) }
}

/// Reads a 32-bit word from an I/O port.
///
/// # Safety
/// See [`inb`].
#[inline]
pub unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    // SAFETY: the caller owns the port.
    unsafe { asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack, preserves_flags)) }
    v
}

/// Writes a 32-bit word to an I/O port.
///
/// # Safety
/// See [`inb`].
#[inline]
pub unsafe fn outl(port: u16, v: u32) {
    // SAFETY: the caller owns the port.
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack, preserves_flags)) }
}

/// Reads a model-specific register.
///
/// # Safety
/// Faults if the MSR does not exist; some MSRs have read side effects.
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: the caller guarantees the MSR exists.
    unsafe { asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags)) }
    (hi as u64) << 32 | lo as u64
}

/// Writes a model-specific register.
///
/// # Safety
/// MSRs control fundamental CPU behaviour; the caller must know the effect.
#[inline]
pub unsafe fn wrmsr(msr: u32, v: u64) {
    // SAFETY: the caller upholds the contract.
    unsafe { asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32, options(nostack, preserves_flags)) }
}

/// Reads CR3 (the physical address of the root page table plus flags).
#[inline]
pub fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) }
    v
}

/// Writes CR3, switching address spaces and flushing non-global TLB entries.
///
/// # Safety
/// `v` must point at a valid root table that maps the currently executing
/// code and stack.
#[inline]
pub unsafe fn write_cr3(v: u64) {
    // SAFETY: the caller upholds the contract.
    unsafe { asm!("mov cr3, {}", in(reg) v, options(nostack, preserves_flags)) }
}

/// Reads CR2, the faulting address of the last page fault.
#[inline]
pub fn read_cr2() -> u64 {
    let v: u64;
    // SAFETY: reading CR2 has no side effects.
    unsafe { asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)) }
    v
}

/// Result of a `cpuid` query.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Executes `cpuid` with the given leaf and sub-leaf.
#[inline]
pub fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    #[allow(unused_unsafe)]
    // SAFETY: cpuid is always available in 64-bit mode.
    let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
    CpuidResult { eax: r.eax, ebx: r.ebx, ecx: r.ecx, edx: r.edx }
}

/// Returns true if the CPU supports VMX (Intel VT-x).
pub fn has_vmx() -> bool {
    cpuid(1, 0).ecx & (1 << 5) != 0
}

/// Returns true if the CPU supports SVM (AMD-V).
pub fn has_svm() -> bool {
    cpuid(0x8000_0000, 0).eax >= 0x8000_0001 && cpuid(0x8000_0001, 0).ecx & (1 << 2) != 0
}

/// Segment selectors of the GDT built by [`CpuTables`]. The order (kernel
/// code, kernel data, user data, user code) is what `syscall`/`sysret`
/// require.
pub mod selectors {
    /// Kernel 64-bit code.
    pub const KERNEL_CODE: u16 = 0x08;
    /// Kernel data.
    pub const KERNEL_DATA: u16 = 0x10;
    /// User data (RPL 3).
    pub const USER_DATA: u16 = 0x18 | 3;
    /// User 64-bit code (RPL 3).
    pub const USER_CODE: u16 = 0x20 | 3;
    /// The task-state segment.
    pub const TSS: u16 = 0x28;
}

/// The 64-bit task-state segment: the stacks the CPU switches to on a
/// privilege change (`rsp`) or for IST interrupt gates (`ist`).
#[repr(C, packed(4))]
#[derive(Clone, Copy, Debug, Default)]
pub struct Tss {
    _reserved0: u32,
    /// Stack pointers loaded on entry to rings 0–2 from a less privileged ring.
    pub rsp: [u64; 3],
    _reserved1: u64,
    /// Interrupt stack table: `ist[n - 1]` is used by gates with IST index `n`.
    pub ist: [u64; 7],
    _reserved2: u64,
    _reserved3: u16,
    /// Offset of the I/O permission bitmap (beyond the limit = none).
    pub iomap_base: u16,
}

const _: () = assert!(size_of::<Tss>() == 104);

/// One CPU's GDT and TSS. Each CPU needs its own, because the TSS holds
/// per-CPU stacks and `ltr` marks its descriptor busy.
///
/// After `CpuTables::enable_syscall` (bare-metal builds), `IA32_KERNEL_GS_BASE` points here:
/// the `syscall` entry stub uses `scratch` and reads the kernel stack from
/// `tss.rsp[0]`.
#[repr(C, align(16))]
pub struct CpuTables {
    /// Scratch slot for the `syscall` entry stub (the user's `rsp`).
    scratch: u64,
    gdt: [u64; 7],
    /// This CPU's task-state segment.
    pub tss: Tss,
}

impl CpuTables {
    /// Flat kernel and user segments, and an empty TSS.
    pub const fn new() -> Self {
        Self {
            scratch: 0,
            gdt: [
                0,
                0x00af_9a00_0000_ffff, // kernel code: present, DPL 0, 64-bit
                0x00cf_9200_0000_ffff, // kernel data
                0x00cf_f200_0000_ffff, // user data: DPL 3
                0x00af_fa00_0000_ffff, // user code: DPL 3, 64-bit
                0,
                0, // TSS descriptor, filled in by `load`
            ],
            tss: Tss {
                _reserved0: 0,
                rsp: [0; 3],
                _reserved1: 0,
                ist: [0; 7],
                _reserved2: 0,
                _reserved3: 0,
                iomap_base: size_of::<Tss>() as u16,
            },
        }
    }

    /// Loads the GDT and TSS on this CPU and reloads every segment register.
    ///
    /// # Safety
    /// Must run on the CPU that will use these tables, with interrupts
    /// disabled; the tables must never be loaded on another CPU.
    pub unsafe fn load(&'static mut self) {
        let base = &raw const self.tss as u64;
        let limit = size_of::<Tss>() as u64 - 1;
        // Available 64-bit TSS (type 9), present.
        self.gdt[5] = limit & 0xffff | (base & 0xff_ffff) << 16 | 0x89 << 40 | (base >> 24 & 0xff) << 56;
        self.gdt[6] = base >> 32;
        #[repr(C, packed)]
        struct Pointer {
            limit: u16,
            base: u64,
        }
        let ptr = Pointer { limit: (size_of::<[u64; 7]>() - 1) as u16, base: self.gdt.as_ptr() as u64 };
        // SAFETY: the GDT is valid and 'static; the far return reloads CS
        // with the kernel code selector it contains.
        unsafe {
            asm!(
                "lgdt [{ptr}]",
                "push {cs}",
                "lea {tmp}, [rip + 2f]",
                "push {tmp}",
                "retfq",
                "2:",
                "mov ds, {ds:x}",
                "mov es, {ds:x}",
                "mov ss, {ds:x}",
                "ltr {tss:x}",
                ptr = in(reg) &ptr,
                cs = in(reg) selectors::KERNEL_CODE as u64,
                ds = in(reg) selectors::KERNEL_DATA as u64,
                tss = in(reg) selectors::TSS as u64,
                tmp = out(reg) _,
            );
        }
    }
}

impl CpuTables {
    /// Enables the `syscall` instruction on this CPU. Its entry stub
    /// switches to `tss.rsp[0]` (keep it on the running task's kernel stack,
    /// as for interrupts from ring 3), builds the same frame as `int 0x80`
    /// (vector `trap::SYSCALL_VECTOR`), and goes through the normal trap
    /// handler, so handlers treat both entry paths alike. The return is via
    /// `iretq`.
    ///
    /// # Safety
    /// [`CpuTables::load`] must have run on this CPU for these tables, and
    /// `trap::install` must have run. GS is reserved for the stub's `swapgs`
    /// (the kernel must not use the GS base itself).
    #[cfg(bare)]
    pub unsafe fn enable_syscall(&'static self) {
        unsafe extern "C" {
            fn osmium_syscall_entry();
        }
        const EFER_SCE: u64 = 1 << 0;
        // SAFETY: standard syscall MSR setup for the segments CpuTables defines.
        unsafe {
            wrmsr(msr::IA32_EFER, rdmsr(msr::IA32_EFER) | EFER_SCE);
            // sysret would load CS = STAR[63:48] + 16 and SS = + 8 (user
            // code/data); syscall loads CS = STAR[47:32], SS = + 8.
            wrmsr(msr::IA32_STAR, (selectors::KERNEL_DATA as u64) << 48 | (selectors::KERNEL_CODE as u64) << 32);
            wrmsr(msr::IA32_LSTAR, osmium_syscall_entry as *const () as u64);
            // Clear IF, TF, DF and AC on entry.
            wrmsr(msr::IA32_FMASK, 0x4_0700);
            wrmsr(msr::IA32_KERNEL_GS_BASE, self as *const Self as u64);
        }
    }
}

/// Offset of `tss.rsp[0]` within [`CpuTables`], used by the syscall stub.
#[doc(hidden)]
pub const SYSCALL_KERNEL_RSP: usize = core::mem::offset_of!(CpuTables, tss) + 4;

// Bare-metal only: it jumps into the trap entry path of `trap::x86_64`.
#[cfg(bare)]
core::arch::global_asm!(
    ".section .text.osmium_trap, \"ax\", @progbits",
    ".globl osmium_syscall_entry",
    "osmium_syscall_entry:",
    // Interrupts are masked (FMASK). rcx = user rip, r11 = user rflags.
    "    swapgs",
    "    mov gs:[0], rsp",
    "    mov rsp, gs:[{krsp}]",
    "    push {uds}",                 // ss
    "    push qword ptr gs:[0]",      // rsp
    "    swapgs",
    "    push r11",                   // rflags
    "    push {ucs}",                 // cs
    "    push rcx",                   // rip
    "    push 0",                     // error code
    "    push {vector}",              // vector: same as int 0x80
    "    jmp osmium_trap_common",
    krsp = const SYSCALL_KERNEL_RSP,
    uds = const selectors::USER_DATA as u64,
    ucs = const selectors::USER_CODE as u64,
    vector = const 0x80u64,
);

impl Default for CpuTables {
    fn default() -> Self {
        Self::new()
    }
}

/// Drops to user mode (ring 3) at `entry` with stack `stack_top` and
/// interrupts enabled, using the segments of [`CpuTables`]. General-purpose
/// registers are cleared so no kernel values leak. Does not return: the
/// next kernel entry is a trap or interrupt, on the stack in the TSS's `rsp[0]`.
///
/// # Safety
/// [`CpuTables`] must be loaded on this CPU with `tss.rsp[0]` set to a valid
/// kernel stack, and `entry`/`stack_top` must be mapped user-accessible.
pub unsafe fn enter_user(entry: u64, stack_top: u64) -> ! {
    // SAFETY: the caller upholds the contract; iretq loads the user context.
    unsafe {
        asm!(
            "mov ds, {ds:x}",
            "mov es, {ds:x}",
            "push {ss}",
            "push {sp}",
            "push 0x202",
            "push {cs}",
            "push {ip}",
            "xor eax, eax", "xor ebx, ebx", "xor ecx, ecx", "xor edx, edx",
            "xor esi, esi", "xor edi, edi", "xor ebp, ebp",
            "xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d", "xor r11d, r11d",
            "xor r12d, r12d", "xor r13d, r13d", "xor r14d, r14d", "xor r15d, r15d",
            "iretq",
            ds = in(reg) selectors::USER_DATA as u64,
            ss = in(reg) selectors::USER_DATA as u64,
            sp = in(reg) stack_top,
            cs = in(reg) selectors::USER_CODE as u64,
            ip = in(reg) entry,
            options(noreturn),
        )
    }
}
