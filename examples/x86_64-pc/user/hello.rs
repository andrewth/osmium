//! A user program: an ordinary `no_std` Rust binary, compiled to an ELF by
//! the example's build script and loaded by the kernel with
//! `osmium_boot::elf`. It talks to the kernel through `syscall`.
#![no_std]
#![no_main]

use core::arch::asm;
use core::fmt::Write;

fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret;
    // SAFETY: the kernel's syscall ABI: rax = number, rdi/rsi/rdx = args;
    // the CPU clobbers rcx and r11.
    unsafe {
        asm!("syscall", inlateout("rax") nr => ret, in("rdi") a0, in("rsi") a1, in("rdx") a2,
             out("rcx") _, out("r11") _, options(nostack))
    };
    ret
}

fn write(bytes: &[u8]) {
    syscall3(1, 1, bytes.as_ptr() as u64, bytes.len() as u64);
}

fn exit(code: u64) -> ! {
    syscall3(60, code, 0, 0);
    loop {}
}

/// Formats into a fixed buffer (there is no heap here).
struct Buf {
    bytes: [u8; 96],
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

/// Lives in the writable data segment.
static mut CALLS: u64 = 0;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let primes = (2u64..200).filter(|n| (2..*n).take_while(|d| d * d <= *n).all(|d| n % d != 0)).count();
    // SAFETY: single-threaded program.
    unsafe { CALLS += 1 };
    let mut buf = Buf { bytes: [0; 96], len: 0 };
    let _ = write!(buf, "hello from a Rust ELF: {primes} primes below 200, data segment says {}", unsafe { CALLS });
    write(&buf.bytes[..buf.len]);
    exit(0)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(101)
}
