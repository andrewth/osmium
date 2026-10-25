//! Relocating a position-independent executable that has no interpreter
//! (a "static PIE"): the kernel applies its `RELA` relocations once the
//! image is loaded at its bias. An image with an interpreter relocates
//! itself, through that program.

use osmium_boot::elf::{Dynamic, Elf, Machine};
use osmium_fs::Errno;

use crate::memory::UserMemory;

/// Size of an `Elf64_Rela`.
const RELA_SIZE: u64 = 24;
/// Size of an `Elf64_Sym`.
const SYM_SIZE: u64 = 24;

/// What a relocation computes, by the architecture's type number.
enum Kind {
    /// Nothing (`R_*_NONE`).
    None,
    /// `B + A`.
    Relative,
    /// `S + A` (`R_*_64`).
    Absolute,
    /// `S` (`GLOB_DAT`, `JUMP_SLOT`).
    Symbol,
}

fn kind(machine: Machine, typ: u32) -> Option<Kind> {
    let k = match (machine, typ) {
        (_, 0) => Kind::None,
        (Machine::X86_64, 8) | (Machine::AARCH64, 1027) | (Machine::RISCV, 3) => Kind::Relative,
        (Machine::X86_64, 1) | (Machine::AARCH64, 257) | (Machine::RISCV, 2) => Kind::Absolute,
        (Machine::X86_64, 6 | 7) | (Machine::AARCH64, 1025 | 1026) | (Machine::RISCV, 5) => Kind::Symbol,
        _ => return None,
    };
    Some(k)
}

/// Applies the `RELA` relocations of `elf`, loaded in `mem` at `bias`:
/// relative ones, and 64-bit absolute and GOT/PLT slot ones against symbols
/// the image itself defines. Anything else (a symbol it does not define, a
/// type this does not know, `REL` or `RELR` tables, needed libraries) is
/// `ENOEXEC`, as is a relocation that does not land in writable image memory
/// or whose value overflows.
pub(crate) fn apply(mem: &dyn UserMemory, elf: &Elf<'_>, machine: Machine, bias: u64) -> Result<(), Errno> {
    let d = elf.dynamic().map_err(|_| Errno::ENOEXEC)?;
    if d.needed || d.rel || d.relr || d.rela_ent != RELA_SIZE || d.sym_ent != SYM_SIZE {
        return Err(Errno::ENOEXEC);
    }
    table(mem, elf, machine, bias, &d, d.rela, d.rela_size)?;
    table(mem, elf, machine, bias, &d, d.jmprel, d.jmprel_size)
}

fn table(
    mem: &dyn UserMemory,
    elf: &Elf<'_>,
    machine: Machine,
    bias: u64,
    d: &Dynamic,
    addr: u64,
    size: u64,
) -> Result<(), Errno> {
    if size == 0 {
        return Ok(());
    }
    if !size.is_multiple_of(RELA_SIZE) {
        return Err(Errno::ENOEXEC);
    }
    let bytes = elf.bytes_at(addr, size).ok_or(Errno::ENOEXEC)?;
    for entry in bytes.as_chunks::<{ RELA_SIZE as usize }>().0.iter() {
        let word = |at: usize| entry.get(at..at + 8).and_then(|b| b.first_chunk::<8>()).map(|&b| u64::from_le_bytes(b));
        let (Some(offset), Some(info), Some(addend)) = (word(0), word(8), word(16)) else {
            return Err(Errno::ENOEXEC);
        };
        let kind = kind(machine, info as u32).ok_or(Errno::ENOEXEC)?;
        let value = match kind {
            Kind::None => continue,
            Kind::Relative => bias.checked_add_signed(addend as i64),
            Kind::Absolute => symbol(elf, d, bias, info >> 32)?.checked_add_signed(addend as i64),
            Kind::Symbol => Some(symbol(elf, d, bias, info >> 32)?),
        }
        .ok_or(Errno::ENOEXEC)?;
        let target = offset.checked_add(bias).ok_or(Errno::ENOEXEC)?;
        mem.write(target, &value.to_le_bytes()).map_err(|_| Errno::ENOEXEC)?;
    }
    Ok(())
}

/// The run-time address of symbol `index`, which the image must define.
fn symbol(elf: &Elf<'_>, d: &Dynamic, bias: u64, index: u64) -> Result<u64, Errno> {
    let at = index.checked_mul(SYM_SIZE).and_then(|o| o.checked_add(d.symtab)).ok_or(Errno::ENOEXEC)?;
    if d.symtab == 0 {
        return Err(Errno::ENOEXEC);
    }
    let sym = elf.bytes_at(at, SYM_SIZE).ok_or(Errno::ENOEXEC)?;
    let shndx =
        sym.get(6..8).and_then(|b| b.first_chunk::<2>()).map(|&b| u16::from_le_bytes(b)).ok_or(Errno::ENOEXEC)?;
    let value =
        sym.get(8..16).and_then(|b| b.first_chunk::<8>()).map(|&b| u64::from_le_bytes(b)).ok_or(Errno::ENOEXEC)?;
    // SHN_UNDEF: another object defines it, and there is none.
    if shndx == 0 {
        return Err(Errno::ENOEXEC);
    }
    value.checked_add(bias).ok_or(Errno::ENOEXEC)
}
