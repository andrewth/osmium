#[cfg(bare)]
use core::cell::UnsafeCell;

use super::{Access, Interrupt, Trap};
use crate::x86_64::read_cr2;

// Hosted test builds compile this module only to unit-test the frame decoding; the stubs (which call into
// the bare-metal dispatcher) are left out.
#[cfg(bare)]
core::arch::global_asm!(include_str!("x86_64.S"));

/// Vector used for `int 0x80` system calls.
pub const SYSCALL_VECTOR: u8 = 0x80;

/// Registers saved on interrupt or exception entry, lowest address first.
#[repr(C)]
#[derive(Clone, Debug, Default)]
#[allow(missing_docs)]
pub struct TrapFrame {
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
    /// CR2 at entry, captured for page faults (vector 14); 0 for every other
    /// vector.
    pub cr2: u64,
    _pad: u64,
    /// Interrupt vector (0–255).
    pub vector: u64,
    /// CPU-pushed error code, or 0 for vectors without one.
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const _: () = assert!(size_of::<TrapFrame>() == 24 * 8);
// The layout `osmium_trap_common` builds, lowest address first: its fifteen pushes (r15 last), the two zeroed
// slots for cr2 and padding, then what the stub (vector, error code) and the CPU pushed.
const _: () = {
    use core::mem::offset_of;
    assert!(offset_of!(TrapFrame, r15) == 0);
    assert!(offset_of!(TrapFrame, rax) == 14 * 8);
    assert!(offset_of!(TrapFrame, cr2) == 15 * 8);
    assert!(offset_of!(TrapFrame, _pad) == 16 * 8);
    assert!(offset_of!(TrapFrame, vector) == 17 * 8);
    assert!(offset_of!(TrapFrame, error_code) == 18 * 8);
    assert!(offset_of!(TrapFrame, rip) == 19 * 8);
    assert!(offset_of!(TrapFrame, ss) == 23 * 8);
};

/// Whether `addr` is canonical for 4-level paging (bits 63:47 all equal).
pub(super) fn is_canonical(addr: u64) -> bool {
    ((addr as i64) << 16 >> 16) as u64 == addr
}

impl TrapFrame {
    /// The program counter the trap returns to. For a breakpoint this is the
    /// `int3` itself (as on other architectures), so a handler that wants to
    /// continue must advance past it (1 byte).
    pub fn pc(&self) -> usize {
        self.rip as usize
    }

    /// Changes where the trap returns to.
    pub fn set_pc(&mut self, pc: usize) {
        self.rip = pc as u64;
    }

    /// The stack pointer at the time of the trap.
    pub fn sp(&self) -> usize {
        self.rsp as usize
    }

    /// Returns true if the trap came from user mode (ring 3).
    pub fn from_user(&self) -> bool {
        self.cs & 3 == 3
    }

    /// The interrupt vector.
    pub fn vector(&self) -> u8 {
        self.vector as u8
    }

    /// System-call number (`rax`) and arguments (`rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`), Linux order.
    ///
    /// The shape differs per architecture; portable decoders must
    /// special-case it:
    ///
    /// | Arch    | Returns       | Linux call number      |
    /// |---------|---------------|------------------------|
    /// | x86_64  | `[u64; 7]`: `rax`, then six arguments | element 0 (`rax`) |
    /// | RISC-V  | `[u64; 8]`: `a0..=a7` | element 7 (`a7`) |
    /// | AArch64 | `[u64; 8]`: `x0..=x7` | not included: read `frame.x[8]` |
    pub fn syscall_args(&self) -> [u64; 7] {
        [self.rax, self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]
    }

    /// Sets the return value register `rax`.
    pub fn set_return(&mut self, v: u64) {
        self.rax = v;
    }

    /// Decodes the cause. Vectors 32 and up are [`Interrupt::External`];
    /// use [`TrapFrame::vector`] to tell them apart.
    pub fn cause(&self) -> Trap {
        match self.vector as u8 {
            3 => Trap::Breakpoint,
            6 => Trap::IllegalInstruction,
            14 => {
                let access = if self.error_code & (1 << 4) != 0 {
                    Access::Execute
                } else if self.error_code & (1 << 1) != 0 {
                    Access::Write
                } else {
                    Access::Read
                };
                Trap::PageFault { addr: self.cr2 as usize, access }
            }
            // #AC reports no data address; the instruction address is all there is.
            17 => Trap::Misaligned { addr: self.rip as usize },
            SYSCALL_VECTOR => Trap::Syscall,
            v if v >= 32 => Trap::Interrupt(Interrupt::External),
            v => Trap::Other { raw: v as u64 | self.error_code << 32 },
        }
    }

    /// Called by the entry stub before the handler.
    pub(super) fn on_entry(&mut self) {
        match self.vector {
            // int3 is a trap: rip already points past it. This assumes the
            // one-byte 0xCC encoding (the two-byte `int 0x03` is not used);
            // the instruction's own bytes are not read, since from user mode
            // that could fault inside the handler. A corrupt rip of 0 wraps
            // rather than panicking.
            3 => self.rip = self.rip.wrapping_sub(1),
            14 => self.cr2 = read_cr2(),
            _ => {}
        }
    }
}

/// Makes `vector` switch to stack `ist` (1–7) from the TSS on entry, on
/// every CPU. Use it for faults that can happen with a broken stack, such as
/// double fault (8), NMI (2) and machine check (18).
///
/// # Safety
/// [`install`] must have run, and every CPU that can take `vector` must
/// have loaded a TSS whose `ist[ist - 1]` points at a valid stack, for
/// example with `osmium_arch::x86_64::CpuTables`.
///
/// # Panics
///
/// If `ist` is not in `1..=7`.
#[cfg(bare)]
pub unsafe fn set_ist(vector: u8, ist: u8) {
    assert!((1..=7).contains(&ist), "IST indices are 1-7");
    let gate = IDT.0.get().cast::<u64>().wrapping_add(2 * vector as usize);
    // SAFETY: the IDT is built (per the contract); the write is one aligned
    // u64, and gates are only consulted by the CPU on interrupt delivery.
    unsafe { gate.write_volatile(gate.read_volatile() & !(0b111 << 32) | (ist as u64) << 32) };
}

/// Lets user mode raise `vector` with `int` (gate DPL 3), for system calls
/// such as [`SYSCALL_VECTOR`]. Other vectors stay kernel-only, so `int n`
/// from user mode raises a general-protection fault instead.
///
/// # Safety
/// [`install`] must have run, and the handler must treat the vector as
/// untrusted input from user mode.
#[cfg(bare)]
pub unsafe fn allow_from_user(vector: u8) {
    let gate = IDT.0.get().cast::<u64>().wrapping_add(2 * vector as usize);
    // SAFETY: as in `set_ist`.
    unsafe { gate.write_volatile(gate.read_volatile() | 3 << 45) };
}

#[cfg(bare)]
#[repr(C, align(16))]
struct Idt(UnsafeCell<[u64; 512]>);

// SAFETY: written once under `BUILT`, then only read by the CPU.
#[cfg(bare)]
unsafe impl Sync for Idt {}

#[cfg(bare)]
static IDT: Idt = Idt(UnsafeCell::new([0; 512]));
#[cfg(bare)]
static BUILT: crate::trap::OnceFlag = crate::trap::OnceFlag::new();

#[cfg(bare)]
#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

/// Loads the Osmium IDT on this CPU, building it on first use. Every vector
/// gets an interrupt gate (interrupts masked on entry) in the current code
/// segment. Call on every CPU.
///
/// # Safety
/// Replaces the current IDT. Traps from ring 0 are handled on the current
/// stack, which must be valid whenever one can occur, unless the vector has
/// been given an IST stack with [`set_ist`]. Traps from ring 3 switch to the
/// TSS's `rsp[0]` (see `osmium_arch::x86_64::CpuTables`), which must then be
/// loaded.
#[cfg(bare)]
pub unsafe fn install() {
    unsafe extern "C" {
        static osmium_trap_stub_table: [u64; 256];
    }
    let cs: u16;
    // SAFETY: reads the code-segment selector.
    unsafe { core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags)) };
    BUILT.call_once(|| {
        // SAFETY: the stub table is immutable data emitted alongside the stubs.
        let stubs = unsafe { &osmium_trap_stub_table };
        // SAFETY: exclusive while building, guarded by `BUILT`.
        let idt = unsafe { &mut *IDT.0.get() };
        for ([lo, hi], &stub) in idt.as_chunks_mut::<2>().0.iter_mut().zip(stubs.iter()) {
            // Present, DPL 0, 64-bit interrupt gate.
            *lo = (stub & 0xffff) | (cs as u64) << 16 | 0x8e << 40 | (stub >> 16 & 0xffff) << 48;
            *hi = stub >> 32;
        }
    });
    let ptr = IdtPointer { limit: (512 * 8 - 1) as u16, base: IDT.0.get() as u64 };
    // SAFETY: the IDT is fully built and lives forever.
    unsafe { core::arch::asm!("lidt [{}]", in(reg) &ptr, options(readonly, nostack, preserves_flags)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(vector: u64, error_code: u64) -> TrapFrame {
        TrapFrame { vector, error_code, rip: 0x40_1000, cs: 0x08, ..TrapFrame::default() }
    }

    #[test]
    fn canonical_addresses() {
        assert!(is_canonical(0x0000_7fff_ffff_ffff));
        assert!(is_canonical(0xffff_8000_0000_0000));
        assert!(!is_canonical(0x0000_8000_0000_0000));
        assert!(!is_canonical(0xffff_7fff_ffff_ffff));
    }

    #[test]
    fn page_fault_access_from_error_code() {
        let mut f = frame(14, 0);
        f.cr2 = 0xdead_b000;
        assert_eq!(f.cause(), Trap::PageFault { addr: 0xdead_b000, access: Access::Read });
        f.error_code = 1 << 1;
        assert_eq!(f.cause(), Trap::PageFault { addr: 0xdead_b000, access: Access::Write });
        // Instruction fetch wins over the write bit.
        f.error_code = 1 << 4 | 1 << 1;
        assert_eq!(f.cause(), Trap::PageFault { addr: 0xdead_b000, access: Access::Execute });
    }

    #[test]
    fn other_vectors_decode() {
        assert_eq!(frame(3, 0).cause(), Trap::Breakpoint);
        assert_eq!(frame(6, 0).cause(), Trap::IllegalInstruction);
        assert_eq!(frame(17, 0).cause(), Trap::Misaligned { addr: 0x40_1000 });
        assert_eq!(frame(SYSCALL_VECTOR as u64, 0).cause(), Trap::Syscall);
        assert_eq!(frame(32, 0).cause(), Trap::Interrupt(Interrupt::External));
        assert_eq!(frame(13, 0x18).cause(), Trap::Other { raw: 13 | 0x18 << 32 });
    }

    #[test]
    fn breakpoint_entry_points_at_int3() {
        let mut f = frame(3, 0);
        f.on_entry();
        assert_eq!(f.pc(), 0x40_0fff);
        let mut f = frame(3, 0);
        f.rip = 0;
        f.on_entry();
        assert_eq!(f.rip, u64::MAX, "wraps instead of panicking");
    }

    #[test]
    fn syscall_args_and_privilege() {
        let mut f = frame(SYSCALL_VECTOR as u64, 0);
        (f.rax, f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9) = (60, 1, 2, 3, 4, 5, 6);
        assert_eq!(f.syscall_args(), [60, 1, 2, 3, 4, 5, 6]);
        f.set_return(7);
        assert_eq!(f.rax, 7);
        assert!(!f.from_user());
        f.cs = 0x23;
        assert!(f.from_user());
    }
}
