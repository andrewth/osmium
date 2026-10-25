//! Position-independent and dynamically linked executables: load bias,
//! relocation by the kernel, interpreters and the auxiliary vector, and
//! hostile variants of each.

use super::*;

/// How to build a test PIE: a x86_64 `ET_DYN` file with a code segment
/// (headers, code, relocation and symbol tables) at 0 and a data segment at
/// 0x1300 holding `PT_DYNAMIC` and the relocation targets at 0x1380.
struct Opts {
    /// The raw `PT_INTERP` contents, terminator included.
    interp: Option<&'static [u8]>,
    /// `(r_offset, r_info, r_addend)`.
    relocs: &'static [(u64, u64, u64)],
    /// Whether symbol 1 is undefined.
    undefined: bool,
    /// Whether to claim a needed library.
    needed: bool,
    /// The lowest segment's address.
    base: u64,
}

const GOOD_RELOCS: &[(u64, u64, u64)] = &[
    (0x1380, 8, 0x1300),      // R_X86_64_RELATIVE
    (0x1388, 1 | 1 << 32, 8), // R_X86_64_64, symbol 1
    (0x1390, 6 | 1 << 32, 0), // R_X86_64_GLOB_DAT, symbol 1
    (0x1398, 0, 0),           // R_X86_64_NONE
];

const PLAIN: Opts = Opts { interp: None, relocs: &[], undefined: false, needed: false, base: 0 };

fn build(o: &Opts) -> &'static [u8] {
    let mut f = alloc::vec![0u8; 0x400];
    let put = |f: &mut Vec<u8>, at: usize, bytes: &[u8]| f[at..at + bytes.len()].copy_from_slice(bytes);
    put(&mut f, 0, b"\x7fELF\x02\x01\x01");
    put(&mut f, 16, &3u16.to_le_bytes());
    put(&mut f, 18, &62u16.to_le_bytes());
    put(&mut f, 24, &(o.base + 0x180).to_le_bytes());
    put(&mut f, 32, &64u64.to_le_bytes());
    put(&mut f, 52, &64u16.to_le_bytes());
    put(&mut f, 54, &56u16.to_le_bytes());
    let phnum = if o.interp.is_some() { 4u16 } else { 3 };
    put(&mut f, 56, &phnum.to_le_bytes());
    let ph = |f: &mut Vec<u8>, i: usize, typ: u32, flags: u32, off: u64, va: u64, filesz: u64, memsz: u64| {
        let at = 64 + i * 56;
        put(f, at, &typ.to_le_bytes());
        put(f, at + 4, &flags.to_le_bytes());
        put(f, at + 8, &off.to_le_bytes());
        put(f, at + 16, &(o.base + va).to_le_bytes());
        put(f, at + 32, &filesz.to_le_bytes());
        put(f, at + 40, &memsz.to_le_bytes());
        put(f, at + 48, &0x1000u64.to_le_bytes());
    };
    ph(&mut f, 0, 1, 5, 0, 0, 0x300, 0x300);
    ph(&mut f, 1, 1, 6, 0x300, 0x1300, 0x100, 0x200);
    ph(&mut f, 2, 2, 6, 0x300, 0x1300, 0x80, 0x80);
    if let Some(interp) = o.interp {
        ph(&mut f, 3, 3, 4, 0x120, 0x120, interp.len() as u64, interp.len() as u64);
        put(&mut f, 0x120, interp);
    }
    put(&mut f, 0x180, &[0x90, 0x90, 0x0f, 0x05]);
    for (i, &(off, info, addend)) in o.relocs.iter().enumerate() {
        let at = 0x200 + i * 24;
        put(&mut f, at, &off.to_le_bytes());
        put(&mut f, at + 8, &info.to_le_bytes());
        put(&mut f, at + 16, &addend.to_le_bytes());
    }
    // Symbol 1, at 0x280 + 24: section 1 (or undefined), value 0x180.
    put(&mut f, 0x298 + 6, &(if o.undefined { 0u16 } else { 1 }).to_le_bytes());
    put(&mut f, 0x298 + 8, &0x180u64.to_le_bytes());
    let mut dynamic = Vec::new();
    if o.needed {
        dynamic.push((1u64, 1u64));
    }
    dynamic.extend([(7, 0x200), (8, 24 * o.relocs.len() as u64), (9, 24), (6, 0x280), (11, 24), (0, 0)]);
    for (i, (tag, val)) in dynamic.into_iter().enumerate() {
        put(&mut f, 0x300 + i * 16, &tag.to_le_bytes());
        put(&mut f, 0x308 + i * 16, &val.to_le_bytes());
    }
    f.leak()
}

/// The files the tests execute, for `/bin`.
pub(super) fn images() -> Vec<(&'static str, Arc<dyn File>)> {
    let file = |o: Opts, ino| Arc::new(Bytes(build(&o), ino)) as Arc<dyn File>;
    let reloc = |relocs| Opts { relocs, ..PLAIN };
    let dynamic = |interp: &'static [u8]| Opts { interp: Some(interp), ..PLAIN };
    alloc::vec![
        ("pie", file(Opts { relocs: GOOD_RELOCS, ..PLAIN }, 10)),
        ("plainpie", file(PLAIN, 11)),
        // The interpreter: a PIE that is itself loaded at a bias.
        ("ld", file(PLAIN, 12)),
        ("dyn", file(Opts { relocs: GOOD_RELOCS, ..dynamic(b"/bin/ld\0") }, 13)),
        ("nointerp", file(dynamic(b"/bin/missing\0"), 14)),
        ("relinterp", file(dynamic(b"bin/ld\0"), 15)),
        ("unterminated", file(dynamic(b"/bin/ld"), 16)),
        ("emptyinterp", file(dynamic(b"\0"), 17)),
        ("nested", file(dynamic(b"/bin/dyn\0"), 18)),
        ("badsym", file(Opts { undefined: true, relocs: GOOD_RELOCS, ..PLAIN }, 19)),
        ("badtype", file(reloc(&[(0x1380, 99, 0)]), 20)),
        ("badtarget", file(reloc(&[(0x9000, 8, 0)]), 21)),
        ("texttarget", file(reloc(&[(0x180, 8, 0)]), 22)),
        ("overflow", file(reloc(&[(0x1380, 8, 1 << 63), (0x1388, 8, 1 << 63)]), 23)),
        ("needed", file(Opts { needed: true, ..PLAIN }, 24)),
        ("lowbase", file(Opts { base: 0x2000_0000, ..PLAIN }, 25)),
        ("badsymidx", file(reloc(&[(0x1380, 1 | 77 << 32, 0)]), 26)),
        ("hugeoffset", file(reloc(&[(u64::MAX - 3, 8, 0)]), 27)),
    ]
}

/// The auxiliary vector at `sp`, which points at `argc`.
fn auxv(p: &Process, sp: u64) -> std::collections::BTreeMap<u64, u64> {
    let argc = word(p, sp);
    // argv, its NULL, envp (none here), its NULL.
    let mut at = sp + 8 * (argc + 3);
    let mut aux = std::collections::BTreeMap::new();
    while word(p, at) != 0 {
        aux.insert(word(p, at), word(p, at + 8));
        at += 16;
    }
    aux
}

const AT_PHDR: u64 = 3;
const AT_PHNUM: u64 = 5;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;

const LOAD_BASE: u64 = 0x1000_0000;

#[test]
fn a_pie_is_loaded_at_the_platform_base_and_relocated() {
    platform();
    let (p, _) = process("pie");
    let entry = p.exec("/bin/pie", &[b"pie"], &[]).unwrap();
    assert_eq!(entry.pc, LOAD_BASE + 0x180);
    assert_eq!(get(&p, entry.pc, 4), [0x90, 0x90, 0x0f, 0x05]);
    let slot = |i: u64| word(&p, LOAD_BASE + 0x1380 + i * 8);
    assert_eq!(slot(0), LOAD_BASE + 0x1300, "RELATIVE: B + A");
    assert_eq!(slot(1), LOAD_BASE + 0x180 + 8, "64: S + A");
    assert_eq!(slot(2), LOAD_BASE + 0x180, "GLOB_DAT: S");
    assert_eq!(slot(3), 0, "NONE does nothing");
    let aux = auxv(&p, entry.sp);
    assert_eq!((aux[&AT_PHDR], aux[&AT_PHNUM], aux[&AT_ENTRY], aux[&AT_BASE]), (LOAD_BASE + 64, 3, entry.pc, 0));
    assert_eq!(call(&p, Sys::Brk, &[0]), (LOAD_BASE + 0x2000) as i64, "the break starts above the image");
    assert_eq!(p.name(), "pie");
}

#[test]
fn an_interpreter_is_loaded_and_started_first() {
    platform();
    let (p, _) = process("dyn");
    let entry = p.exec("/bin/dyn", &[b"dyn"], &[]).unwrap();
    let interp = LOAD_BASE + crate::INTERP_OFFSET;
    assert_eq!(entry.pc, interp + 0x180, "the interpreter's entry point");
    assert_eq!(get(&p, entry.pc, 4), [0x90, 0x90, 0x0f, 0x05], "the interpreter is loaded");
    let aux = auxv(&p, entry.sp);
    assert_eq!(aux[&AT_BASE], interp);
    assert_eq!(aux[&AT_ENTRY], LOAD_BASE + 0x180, "the program's own entry point");
    assert_eq!((aux[&AT_PHDR], aux[&AT_PHNUM]), (LOAD_BASE + 64, 4));
    assert_eq!(get(&p, aux[&AT_PHDR], 4), 1u32.to_le_bytes(), "the program headers are readable");
    assert_eq!(get(&p, aux[&AT_ENTRY], 4), [0x90, 0x90, 0x0f, 0x05], "the program is loaded");
    // The interpreter relocates the program; the kernel does not.
    assert_eq!(word(&p, LOAD_BASE + 0x1380), 0);
    assert_eq!(call(&p, Sys::Brk, &[0]), (LOAD_BASE + 0x2000) as i64);
}

#[test]
fn a_pie_without_relocations_loads() {
    platform();
    let (p, _) = process("plain");
    assert_eq!(p.exec("/bin/plainpie", &[b"plainpie"], &[]).unwrap().pc, LOAD_BASE + 0x180);
}

#[test]
fn hostile_pies_and_interpreters_fail_cleanly() {
    platform();
    let enoexec = Errno::ENOEXEC;
    for (name, error) in [
        ("nointerp", Errno::ENOENT),
        ("relinterp", enoexec),
        ("unterminated", enoexec),
        ("emptyinterp", enoexec),
        ("nested", enoexec),
        ("badsym", enoexec),
        ("badtype", enoexec),
        ("badtarget", enoexec),
        ("texttarget", enoexec),
        ("overflow", enoexec),
        ("needed", enoexec),
        ("lowbase", enoexec),
        ("badsymidx", enoexec),
        ("hugeoffset", enoexec),
    ] {
        let (p, _) = process("victim");
        put(&p, DATA, b"before");
        let path = alloc::format!("/bin/{name}");
        assert_eq!(p.exec(&path, &[b"x"], &[]), Err(error), "{name}");
        assert_eq!(p.name(), "victim", "{name}: the process is unchanged");
        assert_eq!(get(&p, DATA, 6), b"before", "{name}: and so is its memory");
    }
}
