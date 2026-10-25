//! `execve`: replacing a process's program with an ELF file from the VFS,
//! and the kernel hooks that `fork` and `execve` need.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::Range;
use core::sync::atomic::{AtomicU64, Ordering};

use osmium_arch::trap::TrapFrame;
use osmium_boot::elf::{Elf, Machine};
use osmium_fs::{Errno, FileKind, OpenFlags};
use osmium_mm::addr::PhysAddr;
use osmium_mm::paging::MapFlags;
use osmium_sync::Once;

use crate::memory::UserMemory;
use crate::mmap::MmapArea;
use crate::process::{Process, intern};

/// What `fork` and `execve` need from the kernel: how to make address
/// spaces and switch to them, how to start a forked child, and where a new
/// program's stack and `mmap` area go. Without it ([`set_platform`]) both
/// calls fail with `ENOSYS`.
pub struct Platform {
    /// A new, empty user address space that shares the kernel's mappings,
    /// like those the kernel builds for its first processes.
    pub new_memory: fn() -> Result<Box<dyn UserMemory>, Errno>,
    /// Makes `root` the user page table on this CPU, as the scheduler's
    /// switch hook would, and makes code just loaded visible to instruction
    /// fetch here (`fence.i` on RISC-V). Called by `execve` on the calling
    /// task, before the old table is freed.
    pub activate: fn(PhysAddr),
    /// Starts a forked child: runs first thing on the child's new task (so
    /// its table is active) and returns to user mode with `frame`, for
    /// example with `osmium_arch::riscv64::resume_user`.
    pub resume: fn(TrapFrame) -> !,
    /// The top of a new program's stack (exclusive, 16-byte aligned).
    pub stack_top: u64,
    /// Bytes mapped below `stack_top` for it.
    pub stack_size: u64,
    /// Where `mmap` places anonymous memory for it.
    pub mmap_area: Range<u64>,
    /// Where a position-independent (`ET_DYN`) program is loaded: its
    /// lowest address goes here (page-aligned). Its interpreter, if it has
    /// one, goes [`INTERP_OFFSET`] above. Both must be in the user half,
    /// clear of `stack_top`, the stack and `mmap_area`.
    pub load_base: u64,
}

/// How far above [`Platform::load_base`] a position-independent interpreter
/// is loaded. A program image may not span more than this.
pub const INTERP_OFFSET: u64 = 1 << 30;

static PLATFORM: Once<Platform> = Once::new();

/// Gives `fork` and `execve` what they need from the kernel. Panics if
/// called twice.
pub fn set_platform(platform: Platform) {
    assert!(PLATFORM.set(platform).is_ok(), "platform already set");
}

pub(crate) fn platform() -> Result<&'static Platform, Errno> {
    PLATFORM.get().ok_or(Errno::ENOSYS)
}

/// Where a program starts: the entry point and the initial stack pointer,
/// which points at `argc`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserEntry {
    /// The entry point.
    pub pc: u64,
    /// The initial stack pointer.
    pub sp: u64,
}

/// Most bytes of arguments and environment, strings and pointers together
/// (Linux's minimum `ARG_MAX`).
pub const ARG_MAX: usize = 128 * 1024;

/// Largest executable `execve` reads.
const IMAGE_MAX: u64 = 64 << 20;

#[cfg(target_arch = "x86_64")]
const MACHINE: Machine = Machine::X86_64;
#[cfg(target_arch = "aarch64")]
const MACHINE: Machine = Machine::AARCH64;
#[cfg(target_arch = "riscv64")]
const MACHINE: Machine = Machine::RISCV;

mod at {
    pub const NULL: u64 = 0;
    pub const PHDR: u64 = 3;
    pub const BASE: u64 = 7;
    pub const PHENT: u64 = 4;
    pub const PHNUM: u64 = 5;
    pub const PAGESZ: u64 = 6;
    pub const ENTRY: u64 = 9;
    pub const HWCAP: u64 = 16;
    pub const UID: u64 = 11;
    pub const EUID: u64 = 12;
    pub const GID: u64 = 13;
    pub const EGID: u64 = 14;
    pub const SECURE: u64 = 23;
    pub const RANDOM: u64 = 25;
}

impl Process {
    /// `execve`: replaces the program with the ELF executable at the
    /// absolute `path`, with arguments `argv` and environment `envp`, and
    /// returns where it starts. Descriptors marked close-on-exec are closed,
    /// and the break and `mmap` area start afresh. Call it on the process's
    /// own task (the new table is activated there), then enter user mode at
    /// the returned entry; `syscall::handle` does both for the
    /// system call.
    ///
    /// On failure the process is unchanged.
    pub fn exec(&self, path: &str, argv: &[&[u8]], envp: &[&[u8]]) -> Result<UserEntry, Errno> {
        let prepared = self.exec_prepare(path, argv, envp)?;
        Ok(self.exec_commit(prepared))
    }

    /// The first half of [`exec`](Self::exec): reads and validates the
    /// executable and builds the complete new image (memory, break, stack)
    /// without touching the process, so that a failure leaves it, and its
    /// other threads, alone.
    pub(crate) fn exec_prepare(&self, path: &str, argv: &[&[u8]], envp: &[&[u8]]) -> Result<Prepared, Errno> {
        let platform = platform()?;
        let size = argv.iter().chain(envp).fold(0usize, |n, a| n.saturating_add(a.len()).saturating_add(1 + 8));
        if size > ARG_MAX {
            return Err(Errno::E2BIG);
        }
        let image = read_executable(path)?;
        let elf = Elf::new(&image).map_err(|_| Errno::ENOEXEC)?;
        if elf.machine() != MACHINE {
            return Err(Errno::ENOEXEC);
        }
        // A dynamically linked program names an interpreter, which the
        // kernel loads beside it and starts first.
        let interp_image = match elf.interp().map_err(|_| Errno::ENOEXEC)? {
            Some(interp) => {
                let interp = core::str::from_utf8(interp).map_err(|_| Errno::ENOEXEC)?;
                if !interp.starts_with('/') {
                    return Err(Errno::ENOEXEC);
                }
                Some(read_executable(interp)?)
            }
            None => None,
        };
        let interp_elf = match &interp_image {
            Some(image) => {
                let interp = Elf::new(image).map_err(|_| Errno::ENOEXEC)?;
                // One level only: the interpreter is not itself interpreted.
                if interp.machine() != MACHINE || interp.interp().map_err(|_| Errno::ENOEXEC)?.is_some() {
                    return Err(Errno::ENOEXEC);
                }
                Some(interp)
            }
            None => None,
        };
        // Where each image goes: a position-independent one at the
        // platform's base, any other where it says.
        let place = |elf: &Elf<'_>, at: u64| -> Result<u64, Errno> {
            if elf.is_pie() { at.checked_sub(elf.lowest_address()).ok_or(Errno::ENOEXEC) } else { Ok(0) }
        };
        let bias = place(&elf, platform.load_base)?;
        let interp_bias = match &interp_elf {
            Some(i) => place(i, platform.load_base.checked_add(INTERP_OFFSET).ok_or(Errno::ENOEXEC)?)?,
            None => 0,
        };
        let span = elf.span_at(bias).ok_or(Errno::ENOEXEC)?;
        let interp_span = match &interp_elf {
            Some(i) => i.span_at(interp_bias).ok_or(Errno::ENOEXEC)?,
            None => 0..0,
        };
        let brk_limit = brk_limit_for(span, interp_span, platform)?;
        let entry = elf.entry().checked_add(bias).ok_or(Errno::ENOEXEC)?;
        let phdr = match phdr_address(&image, &elf) {
            0 => 0,
            at => at.checked_add(bias).ok_or(Errno::ENOEXEC)?,
        };
        let pc = match &interp_elf {
            Some(i) => i.entry().checked_add(interp_bias).ok_or(Errno::ENOEXEC)?,
            None => entry,
        };
        // Build the new image completely before touching the process.
        let memory = (platform.new_memory)()?;
        let brk = memory.load_elf_at(&elf, bias)?;
        if let Some(i) = &interp_elf {
            memory.load_elf_at(i, interp_bias)?;
        } else if elf.is_pie() {
            // Nobody else will relocate it.
            crate::reloc::apply(&*memory, &elf, MACHINE, bias)?;
        }
        let stack_lo = platform.stack_top.checked_sub(platform.stack_size).ok_or(Errno::ENOEXEC)?;
        memory.map_anon(stack_lo, platform.stack_size, MapFlags::RW)?;
        let aux = [
            (at::PHDR, phdr),
            (at::PHENT, u64::from(le16(&image, 54))),
            (at::PHNUM, u64::from(le16(&image, 56))),
            (at::PAGESZ, 4096),
            (at::BASE, interp_bias),
            (at::ENTRY, entry),
            (at::HWCAP, hwcap()),
            (at::UID, 0),
            (at::EUID, 0),
            (at::GID, 0),
            (at::EGID, 0),
            (at::SECURE, 0),
        ];
        let sp = build_stack(&*memory, platform.stack_top, stack_lo, argv, envp, &aux, self.pid().0)?;

        let name = path.rsplit('/').next().unwrap_or(path);
        let memory: Arc<dyn UserMemory> = memory.into();
        // Everything the commit needs is made here, where memory running out
        // is an error.
        let name = intern(name).map_err(|_| Errno::ENOMEM)?;
        let mmap = MmapArea::new(platform.mmap_area.clone()).map_err(|_| Errno::ENOMEM)?;
        Ok(Prepared { name, memory, mmap, brk, brk_limit, activate: platform.activate, entry: UserEntry { pc, sp } })
    }

    /// The second half of [`exec`](Self::exec): switches the process to the
    /// image built by [`exec_prepare`](Self::exec_prepare). Cannot fail.
    pub(crate) fn exec_commit(&self, prepared: Prepared) -> UserEntry {
        let Prepared { name, memory, mmap, brk, brk_limit, activate, entry } = prepared;
        let root = memory.root();
        let old = self.replace_image(name, memory, brk, brk_limit, mmap);
        activate(root);
        drop(old);
        if osmium_arch::fp::enabled() {
            // The new program starts with cleared FP/SIMD registers.
            // SAFETY: we run on the process's own task, whose registers these
            // are; a kernel that enabled FP enables it on every CPU.
            unsafe { osmium_arch::fp::FpState::new().restore() };
        }
        entry
    }
}

/// A new program image built by [`Process::exec_prepare`], not yet in use.
pub(crate) struct Prepared {
    name: &'static str,
    memory: Arc<dyn UserMemory>,
    mmap: MmapArea,
    brk: u64,
    brk_limit: u64,
    /// The platform's `activate`, kept so that committing cannot fail.
    activate: fn(PhysAddr),
    entry: UserEntry,
}

/// Whether the non-empty ranges `a` and `b` share an address.
fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    !a.is_empty() && !b.is_empty() && a.start < b.end && b.start < a.end
}

/// Checks that the ELF image, the stack and the `mmap` area are disjoint
/// (`ENOEXEC` if not), and returns where the program break must stop: at
/// its usual limit above the image, or at the next of those that is in the
/// way. For an image loaded without a bias.
#[cfg(test)]
pub(crate) fn brk_limit(elf: &Elf<'_>, platform: &Platform) -> Result<u64, Errno> {
    brk_limit_for(elf.span_at(0).ok_or(Errno::ENOEXEC)?, 0..0, platform)
}

/// [`brk_limit`] for a program covering `span` (and an interpreter covering
/// `interp`, empty if none), as loaded.
fn brk_limit_for(span: Range<u64>, interp: Range<u64>, platform: &Platform) -> Result<u64, Errno> {
    let stack_lo = platform.stack_top.checked_sub(platform.stack_size).ok_or(Errno::ENOEXEC)?;
    let others = [stack_lo..platform.stack_top, platform.mmap_area.clone(), interp];
    let all = [span.clone(), others[0].clone(), others[1].clone(), others[2].clone()];
    for (i, a) in all.iter().enumerate() {
        if all.iter().skip(i + 1).any(|b| overlaps(a, b)) {
            return Err(Errno::ENOEXEC);
        }
    }
    let hi = span.end;
    let limit = hi.saturating_add(crate::process::BRK_MAX);
    Ok(others.iter().filter(|r| r.start >= hi && !r.is_empty()).map(|r| r.start).fold(limit, u64::min))
}

/// `AT_HWCAP` in Linux's encoding. FP/SIMD is listed only once
/// [`osmium_arch::fp::enable`] has run: until then FP instructions trap.
fn hwcap() -> u64 {
    let fp = osmium_arch::fp::enabled();
    let ext = |s: &[u8]| s.iter().map(|c| 1 << (c - b'a')).sum::<u64>();
    if cfg!(target_arch = "x86_64") {
        // CPUID.1:EDX: FPU, FXSR, SSE, SSE2.
        if fp { 1 | 1 << 24 | 1 << 25 | 1 << 26 } else { 0 }
    } else if cfg!(target_arch = "aarch64") {
        // HWCAP_FP, HWCAP_ASIMD.
        if fp { 0b11 } else { 0 }
    } else {
        // One bit per single-letter extension.
        ext(b"imac") | if fp { ext(b"fd") } else { 0 }
    }
}

/// Reads the whole regular, executable file at `path`.
fn read_executable(path: &str) -> Result<Vec<u8>, Errno> {
    let vfs = crate::vfs().ok_or(Errno::ENOENT)?;
    let file = vfs.open(path, OpenFlags::READ, 0)?;
    let st = file.try_stat()?;
    if st.kind != FileKind::Regular || st.mode & 0o111 == 0 {
        return Err(Errno::EACCES);
    }
    if st.size > IMAGE_MAX {
        return Err(Errno::ENOMEM);
    }
    // Fallibly: a large executable must fail `execve`, not the kernel.
    let mut image = Vec::new();
    image.try_reserve_exact(st.size as usize).map_err(|_| Errno::ENOMEM)?;
    image.resize(st.size as usize, 0);
    let mut done = 0;
    while let Some(rest) = image.get_mut(done..).filter(|r| !r.is_empty()) {
        match file.read(done as u64, rest)? {
            0 => return Err(Errno::ENOEXEC),
            n => done = done.saturating_add(n),
        }
    }
    Ok(image)
}

fn le16(b: &[u8], off: usize) -> u16 {
    crate::bytes::slice(b, off, 2).ok().and_then(|s| s.first_chunk::<2>()).map_or(0, |&s| u16::from_le_bytes(s))
}

/// Where the program headers appear in memory (`AT_PHDR`): inside whichever
/// segment loads the bytes at their file offset, or 0 if none does.
pub(crate) fn phdr_address(image: &[u8], elf: &Elf<'_>) -> u64 {
    let phoff = crate::bytes::array::<8>(image, 32).map_or(0, u64::from_le_bytes);
    elf.segments()
        .find_map(|s| {
            let off = (s.data.as_ptr() as u64).wrapping_sub(image.as_ptr() as u64);
            (off..off.saturating_add(s.data.len() as u64)).contains(&phoff).then(|| s.vaddr.wrapping_add(phoff - off))
        })
        .unwrap_or(0)
}

/// Lays out the initial stack below `top` as the Linux ABI has it, and
/// returns the stack pointer, 16-byte aligned:
///
/// ```text
/// sp -> argc, argv[0..argc], NULL, envp[..], NULL, (type, value) auxv pairs, AT_NULL
///       ... then the 16 AT_RANDOM bytes and the strings themselves, up to `top`.
/// ```
fn build_stack(
    mem: &dyn UserMemory,
    top: u64,
    lo: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    aux: &[(u64, u64)],
    seed: u32,
) -> Result<u64, Errno> {
    let mut sp = top;
    let mut push = |bytes: &[u8]| -> Result<u64, Errno> {
        sp = sp.checked_sub(bytes.len() as u64 + 1).filter(|&s| s >= lo).ok_or(Errno::E2BIG)?;
        mem.write(sp, bytes)?;
        mem.write(sp + bytes.len() as u64, &[0])?;
        Ok(sp)
    };
    let mut pointers = |strings: &[&[u8]]| -> Result<Vec<u64>, Errno> {
        let mut out = Vec::new();
        out.try_reserve_exact(strings.len()).map_err(|_| Errno::ENOMEM)?;
        for s in strings {
            out.push(push(s)?);
        }
        Ok(out)
    };
    let argp = pointers(argv)?;
    let envp = pointers(envp)?;
    let random = (sp & !15).checked_sub(16).filter(|&s| s >= lo).ok_or(Errno::E2BIG)?;
    mem.write(random, &random_bytes(seed))?;

    let mut words = Vec::new();
    words.try_reserve_exact(argp.len() + envp.len() + aux.len() * 2 + 6).map_err(|_| Errno::ENOMEM)?;
    words.push(argp.len() as u64);
    words.extend(&argp);
    words.push(0);
    words.extend(&envp);
    words.push(0);
    for &(key, value) in aux.iter().chain(&[(at::RANDOM, random), (at::NULL, 0)]) {
        words.extend([key, value]);
    }
    let sp = random.checked_sub(words.len() as u64 * 8).map(|s| s & !15).filter(|&s| s >= lo).ok_or(Errno::E2BIG)?;
    for (i, w) in words.iter().enumerate() {
        mem.write(sp + i as u64 * 8, &w.to_ne_bytes())?;
    }
    Ok(sp)
}

/// Sixteen bytes for `AT_RANDOM`: stack-canary and pointer-guard seeds for
/// the C library. Not cryptographic; there is no entropy source.
fn random_bytes(seed: u32) -> [u8; 16] {
    static COUNTER: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);
    let mut x = COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed) ^ u64::from(seed);
    let mut out = [0; 16];
    for chunk in out.chunks_mut(8) {
        // splitmix64
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_ne_bytes());
    }
    out
}
