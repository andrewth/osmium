//! A minimal program interpreter (RISC-V only), the `PT_INTERP` of
//! `/bin/dyn`. The kernel loads it beside the program, with `AT_BASE` set to
//! its own load address, and starts it instead of the program. It relocates
//! itself, then the program (found through `AT_PHDR`), then jumps to the
//! program's `AT_ENTRY` with the stack as the kernel left it. It handles
//! only `R_RISCV_RELATIVE`, and loads no libraries.
#![no_std]
#![no_main]

use core::fmt::Write;

const AT_PHDR: u64 = 3;
const AT_PHNUM: u64 = 5;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const PT_DYNAMIC: u32 = 2;
const PT_PHDR: u32 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const R_RISCV_RELATIVE: u64 = 3;

fn syscall(nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let ret;
    // SAFETY: a7 = number, a0-a2 = arguments, a0 = result.
    unsafe {
        core::arch::asm!("ecall", in("a7") nr, inlateout("a0") a0 => ret, in("a1") a1, in("a2") a2, options(nostack))
    };
    ret
}

fn exit(code: u64) -> ! {
    syscall(93, code, 0, 0);
    loop {}
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

#[repr(C)]
struct Phdr {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    paddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

/// Applies the `R_RISCV_RELATIVE` relocations of the image whose program
/// headers are `phdrs` and whose load bias is `bias`; returns how many, or
/// `None` for a relocation of another kind. Uses no data that itself needs
/// relocating, so it can relocate the interpreter it is part of.
///
/// # Safety
/// `phdrs` and the image they describe must be mapped, with the relocated
/// words writable.
#[inline(never)]
unsafe fn relocate(bias: u64, phdrs: *const Phdr, phnum: u64) -> Option<u64> {
    let (mut rela, mut size) = (0u64, 0u64);
    for i in 0..phnum as usize {
        // SAFETY: the caller promises the headers are mapped.
        let ph = unsafe { &*phdrs.add(i) };
        if ph.kind != PT_DYNAMIC {
            continue;
        }
        let mut entry = (bias + ph.vaddr) as *const u64;
        // SAFETY: PT_DYNAMIC is mapped and ends with DT_NULL.
        unsafe {
            while *entry != 0 {
                match *entry {
                    DT_RELA => rela = *entry.add(1),
                    DT_RELASZ => size = *entry.add(1),
                    _ => {}
                }
                entry = entry.add(2);
            }
        }
    }
    let mut count = 0;
    for i in 0..size / 24 {
        // SAFETY: the table is in the mapped image; the target is writable.
        unsafe {
            let r = (bias + rela + i * 24) as *const u64;
            let (offset, info, addend) = (*r, *r.add(1), *r.add(2));
            if info & 0xffff_ffff != R_RISCV_RELATIVE {
                return None;
            }
            *((bias + offset) as *mut u64) = bias.wrapping_add(addend);
        }
        count += 1;
    }
    Some(count)
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
    let aux = |wanted: u64| unsafe {
        let mut at = sp.add(*sp as usize + 2);
        while *at != 0 {
            at = at.add(1);
        }
        at = at.add(1);
        while *at != 0 {
            if *at == wanted {
                return *at.add(1);
            }
            at = at.add(2);
        }
        0
    };
    let base = aux(AT_BASE);
    // Our own headers are at the start of our image: relocate ourselves
    // first, before touching anything that holds an address.
    let ehdr = base as *const u8;
    // SAFETY: the kernel mapped our ELF header and program headers at AT_BASE.
    let own = unsafe {
        let phoff = *(ehdr.add(32) as *const u64);
        let phnum = u64::from(*(ehdr.add(56) as *const u16));
        relocate(base, ehdr.add(phoff as usize) as *const Phdr, phnum)
    };
    if own.is_none() {
        exit(110);
    }

    let (phdr, phnum, entry) = (aux(AT_PHDR), aux(AT_PHNUM), aux(AT_ENTRY));
    // The program's bias: where its headers are, less where it says they go.
    let phdrs = phdr as *const Phdr;
    // SAFETY: the kernel mapped the program's headers at AT_PHDR.
    let bias = (0..phnum as usize)
        .map(|i| unsafe { &*phdrs.add(i) })
        .find(|ph| ph.kind == PT_PHDR)
        .map_or(0, |ph| phdr.wrapping_sub(ph.vaddr));
    // SAFETY: as above; the program's writable segments are mapped.
    let relocated = unsafe { relocate(bias, phdrs, phnum) };
    let mut buf = Buf { bytes: [0; 160], len: 0 };
    let _ = write!(
        buf,
        "ld: loaded at {base:#x}, relocated {} entries of the program (bias {bias:#x}), entering {entry:#x}",
        relocated.unwrap_or(u64::MAX)
    );
    syscall(64, 1, buf.bytes.as_ptr() as u64, buf.len as u64);
    if relocated.is_none() || entry == 0 {
        exit(111);
    }
    // SAFETY: jumps to the program's entry with the kernel's stack.
    unsafe { core::arch::asm!("mv sp, {sp}", "jr {entry}", sp = in(reg) sp, entry = in(reg) entry, options(noreturn)) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    exit(101)
}
