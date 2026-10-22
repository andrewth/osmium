//! `execve`: replacing a process's program with an ELF file from the VFS,
//! and the kernel hooks that `fork` and `execve` need.

use alloc::boxed::Box;
use alloc::string::String;
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
use crate::process::Process;

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
}

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
    /// `execve`: replaces the program with the static ELF executable at the
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
        let size = argv.iter().chain(envp).map(|a| a.len() + 1 + 8).sum::<usize>();
        if size > ARG_MAX {
            return Err(Errno::E2BIG);
        }
        let image = read_executable(path)?;
        let elf = Elf::new(&image).map_err(|_| Errno::ENOEXEC)?;
        if elf.machine() != MACHINE || elf.is_pie() {
            return Err(Errno::ENOEXEC);
        }
        let brk_limit = brk_limit(&elf, platform)?;
        // Build the new image completely before touching the process.
        let memory = (platform.new_memory)()?;
        let brk = memory.load_elf(&elf)?;
        let stack_lo = platform.stack_top - platform.stack_size;
        memory.map_anon(stack_lo, platform.stack_size, MapFlags::RW)?;
        let aux = [
            (at::PHDR, phdr_address(&image, &elf)),
            (at::PHENT, u64::from(le16(&image, 54))),
            (at::PHNUM, u64::from(le16(&image, 56))),
            (at::PAGESZ, 4096),
            (at::ENTRY, elf.entry()),
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
        Ok(Prepared { name: String::from(name), memory, brk, brk_limit, entry: UserEntry { pc: elf.entry(), sp } })
    }

    /// The second half of [`exec`](Self::exec): switches the process to the
    /// image built by [`exec_prepare`](Self::exec_prepare). Cannot fail.
    pub(crate) fn exec_commit(&self, prepared: Prepared) -> UserEntry {
        let platform = platform().expect("the image was built for a platform");
        let Prepared { name, memory, brk, brk_limit, entry } = prepared;
        let root = memory.root();
        let old = self.replace_image(&name, memory, brk, brk_limit, platform.mmap_area.clone());
        (platform.activate)(root);
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
    name: String,
    memory: Arc<dyn UserMemory>,
    brk: u64,
    brk_limit: u64,
    entry: UserEntry,
}

/// Whether the non-empty ranges `a` and `b` share an address.
fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    !a.is_empty() && !b.is_empty() && a.start < b.end && b.start < a.end
}

/// Checks that the ELF image, the stack and the `mmap` area are disjoint
/// (`ENOEXEC` if not), and returns where the program break must stop: at
/// its usual limit above the image, or at the next of those that is in the
/// way.
fn brk_limit(elf: &Elf<'_>, platform: &Platform) -> Result<u64, Errno> {
    let loaded = || elf.segments().filter(|s| s.mem_size != 0);
    let lo = loaded().map(|s| s.vaddr).min().unwrap_or(0) & !0xfff;
    let hi = loaded().map(|s| s.vaddr.saturating_add(s.mem_size)).max().unwrap_or(0);
    let hi = hi.checked_next_multiple_of(4096).ok_or(Errno::ENOEXEC)?;
    let stack_lo = platform.stack_top.checked_sub(platform.stack_size).ok_or(Errno::ENOEXEC)?;
    let others = [stack_lo..platform.stack_top, platform.mmap_area.clone()];
    if overlaps(&others[0], &others[1]) || others.iter().any(|r| overlaps(r, &(lo..hi))) {
        return Err(Errno::ENOEXEC);
    }
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
    let st = file.stat();
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
    while done < image.len() {
        match file.read(done as u64, &mut image[done..])? {
            0 => return Err(Errno::ENOEXEC),
            n => done += n,
        }
    }
    Ok(image)
}

fn le16(b: &[u8], off: usize) -> u16 {
    b.get(off..off + 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

/// Where the program headers appear in memory (`AT_PHDR`): inside whichever
/// segment loads the bytes at their file offset, or 0 if none does.
fn phdr_address(image: &[u8], elf: &Elf<'_>) -> u64 {
    let phoff = image.get(32..40).map_or(0, |b| u64::from_le_bytes(b.try_into().expect("fixed-width slice")));
    elf.segments()
        .find_map(|s| {
            let off = s.data.as_ptr() as u64 - image.as_ptr() as u64;
            (off..off + s.data.len() as u64).contains(&phoff).then(|| s.vaddr + (phoff - off))
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
    let argp = argv.iter().map(|a| push(a)).collect::<Result<Vec<_>, _>>()?;
    let envp = envp.iter().map(|e| push(e)).collect::<Result<Vec<_>, _>>()?;
    let random = (sp & !15).checked_sub(16).filter(|&s| s >= lo).ok_or(Errno::E2BIG)?;
    mem.write(random, &random_bytes(seed))?;

    let mut words = Vec::with_capacity(argp.len() + envp.len() + aux.len() * 2 + 6);
    words.push(argp.len() as u64);
    words.extend(&argp);
    words.push(0);
    words.extend(&envp);
    words.push(0);
    for &(key, value) in aux.iter().chain(&[(at::RANDOM, random), (at::NULL, 0)]) {
        words.extend([key, value]);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    let sp = random.checked_sub(bytes.len() as u64).map(|s| s & !15).filter(|&s| s >= lo).ok_or(Errno::E2BIG)?;
    mem.write(sp, &bytes)?;
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
