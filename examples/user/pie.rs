//! A position-independent executable (RISC-V only). It keeps pointers in
//! static data, which only work once something has applied its relative
//! relocations: the kernel, for a static PIE, or the interpreter named in
//! `PT_INTERP` (`ld.rs`), when built as a dynamically linked program. The
//! same source is both; it reports which one ran, by `AT_BASE`.
#![no_std]
#![no_main]

use core::fmt::Write;

const WRITE: u64 = 64;
const EXIT: u64 = 93;
const AT_BASE: u64 = 7;
const AT_PHDR: u64 = 3;

fn syscall(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret;
    // SAFETY: a7 = number, a0-a2 = arguments, a0 = result.
    unsafe {
        core::arch::asm!("ecall", in("a7") nr, inlateout("a0") a0 => ret, in("a1") a1, in("a2") a2, options(nostack))
    };
    ret
}

struct Buf {
    bytes: [u8; 160],
    len: usize,
}

impl Write for Buf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let end = self.len + s.len();
        self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?.copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// Each of these is a pointer stored in data: `R_RISCV_RELATIVE` entries.
static WORDS: [&str; 3] = ["position", "independent", "code"];
static HOOK: fn(u64) -> u64 = triple;

fn triple(x: u64) -> u64 {
    x * 3
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!("mv a0, sp", "tail {}", sym main)
}

/// # Safety
/// `sp` must be the initial stack pointer the kernel set up.
unsafe extern "C" fn main(sp: *const u64) -> ! {
    // SAFETY: the kernel laid out argc, argv, NULL, envp, NULL, auxv at `sp`.
    let (base, phdr) = unsafe {
        let argc = *sp as usize;
        let mut at = sp.add(argc + 2);
        while *at != 0 {
            at = at.add(1);
        }
        at = at.add(1);
        let (mut base, mut phdr) = (0, 0);
        while *at != 0 {
            match *at {
                AT_BASE => base = *at.add(1),
                AT_PHDR => phdr = *at.add(1),
                _ => {}
            }
            at = at.add(2);
        }
        (base, phdr)
    };
    let mut buf = Buf { bytes: [0; 160], len: 0 };
    let words = WORDS.iter().map(|w| w.len()).sum::<usize>();
    let who = if base != 0 { "interpreter relocated us" } else { "kernel relocated us" };
    let _ = write!(
        buf,
        "PIE: {} {} {}; {words} letters, function pointer says {}; AT_PHDR {phdr:#x}; {who}",
        WORDS[0],
        WORDS[1],
        WORDS[2],
        HOOK(14)
    );
    syscall(WRITE, 1, buf.bytes.as_ptr() as u64, buf.len as u64);
    syscall(EXIT, 0, 0, 0);
    loop {}
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    syscall(EXIT, 101, 0, 0);
    loop {}
}
