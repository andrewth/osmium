//! The system-call layer: Linux numbers and structure layouts for each
//! architecture, decoded once and handled by portable code.

use alloc::string::String;
use alloc::vec;

#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64")))]
use osmium_arch::trap::TrapFrame;
use osmium_fs::{Errno, FileKind, OpenFlags, PATH_MAX, Stat};
use osmium_mm::paging::MapFlags;

use crate::fd::{Access, OpenFile};
use crate::process::{ExitStatus, Process};

/// The calls this layer implements, independent of their numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Sys {
    Read,
    Write,
    Readv,
    Writev,
    Openat,
    Close,
    Lseek,
    Fstat,
    Newfstatat,
    Getdents64,
    Ioctl,
    Getcwd,
    Chdir,
    Mkdirat,
    Unlinkat,
    Exit,
    ExitGroup,
    Getpid,
    Getppid,
    Gettid,
    Brk,
    Mmap,
    Munmap,
    SchedYield,
    Uname,
}

/// Linux system-call numbers for x86_64.
#[cfg(target_arch = "x86_64")]
const NUMBERS: &[(u64, Sys)] = &[
    (0, Sys::Read),
    (1, Sys::Write),
    (3, Sys::Close),
    (5, Sys::Fstat),
    (8, Sys::Lseek),
    (9, Sys::Mmap),
    (11, Sys::Munmap),
    (12, Sys::Brk),
    (16, Sys::Ioctl),
    (19, Sys::Readv),
    (20, Sys::Writev),
    (24, Sys::SchedYield),
    (39, Sys::Getpid),
    (60, Sys::Exit),
    (63, Sys::Uname),
    (79, Sys::Getcwd),
    (80, Sys::Chdir),
    (110, Sys::Getppid),
    (186, Sys::Gettid),
    (217, Sys::Getdents64),
    (231, Sys::ExitGroup),
    (257, Sys::Openat),
    (258, Sys::Mkdirat),
    (262, Sys::Newfstatat),
    (263, Sys::Unlinkat),
];

/// Linux system-call numbers for RISC-V and AArch64 (asm-generic).
#[cfg(not(target_arch = "x86_64"))]
const NUMBERS: &[(u64, Sys)] = &[
    (17, Sys::Getcwd),
    (29, Sys::Ioctl),
    (34, Sys::Mkdirat),
    (35, Sys::Unlinkat),
    (49, Sys::Chdir),
    (56, Sys::Openat),
    (57, Sys::Close),
    (61, Sys::Getdents64),
    (62, Sys::Lseek),
    (63, Sys::Read),
    (64, Sys::Write),
    (65, Sys::Readv),
    (66, Sys::Writev),
    (79, Sys::Newfstatat),
    (80, Sys::Fstat),
    (93, Sys::Exit),
    (94, Sys::ExitGroup),
    (124, Sys::SchedYield),
    (160, Sys::Uname),
    (172, Sys::Getpid),
    (173, Sys::Getppid),
    (178, Sys::Gettid),
    (214, Sys::Brk),
    (215, Sys::Munmap),
    (222, Sys::Mmap),
];

impl Sys {
    /// Decodes this architecture's Linux system-call number.
    pub fn from_number(nr: u64) -> Option<Sys> {
        NUMBERS.iter().find(|(n, _)| *n == nr).map(|&(_, s)| s)
    }

    /// This architecture's Linux number for the call.
    pub fn number(self) -> u64 {
        NUMBERS.iter().find(|(_, s)| *s == self).map(|&(n, _)| n).expect("every call has a number")
    }
}

/// `open` flags as Linux encodes them. AArch64 moves `O_DIRECTORY` and
/// `O_NOFOLLOW`.
mod oflag {
    pub const ACCMODE: u64 = 3;
    pub const WRONLY: u64 = 1;
    pub const RDWR: u64 = 2;
    pub const CREAT: u64 = 0o100;
    pub const EXCL: u64 = 0o200;
    pub const TRUNC: u64 = 0o1000;
    pub const APPEND: u64 = 0o2000;
    #[cfg(target_arch = "aarch64")]
    pub const DIRECTORY: u64 = 0o40000;
    #[cfg(not(target_arch = "aarch64"))]
    pub const DIRECTORY: u64 = 0o200000;
    #[cfg(target_arch = "aarch64")]
    pub const NOFOLLOW: u64 = 0o100000;
    #[cfg(not(target_arch = "aarch64"))]
    pub const NOFOLLOW: u64 = 0o400000;
}

const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_REMOVEDIR: u64 = 0x200;
const AT_EMPTY_PATH: u64 = 0x1000;

/// What the caller of [`dispatch`] does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Return this value to user mode (negative values are `-errno`).
    Return(i64),
    /// The process asked to exit: end it with [`crate::exit`].
    Exit(ExitStatus),
}

type SysResult = Result<u64, Errno>;

/// Handles system call `nr` with arguments `a` on behalf of `p`, the
/// calling process. Calls may block.
pub fn dispatch(p: &Process, nr: u64, a: [u64; 6]) -> Outcome {
    let Some(sys) = Sys::from_number(nr) else { return Outcome::Return(-(Errno::ENOSYS.0 as i64)) };
    let fd = a[0] as i32;
    let r = match sys {
        Sys::Exit | Sys::ExitGroup => return Outcome::Exit(ExitStatus::Code(a[0] as i32)),
        Sys::Read => read(p, fd, a[1], a[2]),
        Sys::Write => write(p, fd, a[1], a[2]),
        Sys::Readv => vectored(p, fd, a[1], a[2], read),
        Sys::Writev => vectored(p, fd, a[1], a[2], write),
        Sys::Openat => openat(p, fd, a[1], a[2], a[3] as u32),
        Sys::Close => p.files().lock().close(fd).map(|()| 0),
        Sys::Lseek => lseek(p, fd, a[1] as i64, a[2]),
        Sys::Fstat => p.files().lock().get(fd).and_then(|f| put_stat(p, a[1], &f.file().stat())),
        Sys::Newfstatat => newfstatat(p, fd, a[1], a[2], a[3]),
        Sys::Getdents64 => getdents64(p, fd, a[1], a[2]),
        Sys::Ioctl => {
            p.files().lock().get(fd).and_then(|f| f.file().ioctl(a[1] as u32, a[2] as usize).map(|v| v as u64))
        }
        Sys::Getcwd => getcwd(p, a[0], a[1]),
        Sys::Chdir => chdir(p, a[0]),
        Sys::Mkdirat => {
            path_at(p, fd, a[1]).and_then(|path| vfs()?.mkdir(&path, a[2] as u32 & 0o7777 & !p.umask())).map(|()| 0)
        }
        Sys::Unlinkat => unlinkat(p, fd, a[1], a[2]),
        Sys::Getpid | Sys::Gettid => Ok(p.pid().0 as u64),
        Sys::Getppid => Ok(p.parent().map_or(0, |pid| pid.0 as u64)),
        Sys::Brk => Ok(p.brk(a[0])),
        Sys::Mmap => mmap(p, a[1], a[2], a[3], a[4] as i32),
        Sys::Munmap => munmap(p, a[0], a[1]),
        Sys::SchedYield => {
            osmium_sched::yield_now();
            Ok(0)
        }
        Sys::Uname => uname(p, a[0]),
    };
    Outcome::Return(match r {
        Ok(v) => v as i64,
        Err(e) => -(e.0 as i64),
    })
}

/// Bytes moved per copy between user memory and a file.
const CHUNK: usize = 4096;

fn read(p: &Process, fd: i32, buf: u64, len: u64) -> SysResult {
    let f = p.files().lock().get(fd)?;
    let mut kbuf = vec![0u8; (len as usize).min(CHUNK)];
    let mut done = 0;
    while done < len {
        let want = ((len - done) as usize).min(CHUNK);
        let n = f.read(&mut kbuf[..want])?;
        p.memory().write(buf + done, &kbuf[..n])?;
        done += n as u64;
        // A short read (a console line, the end of a file) ends the call.
        if n < want {
            break;
        }
    }
    Ok(done)
}

fn write(p: &Process, fd: i32, buf: u64, len: u64) -> SysResult {
    let f = p.files().lock().get(fd)?;
    let mut kbuf = vec![0u8; (len as usize).min(CHUNK)];
    let mut done = 0;
    while done < len {
        let want = ((len - done) as usize).min(CHUNK);
        p.memory().read(buf + done, &mut kbuf[..want])?;
        let n = f.write(&kbuf[..want])?;
        done += n as u64;
        if n < want {
            break;
        }
    }
    Ok(done)
}

/// `readv`/`writev`: `op` over each `struct iovec { base, len }`.
fn vectored(p: &Process, fd: i32, iov: u64, count: u64, op: fn(&Process, i32, u64, u64) -> SysResult) -> SysResult {
    if count > 1024 {
        return Err(Errno::EINVAL);
    }
    let mut total = 0;
    for i in 0..count {
        let [base, len] = [get_u64(p, iov + i * 16)?, get_u64(p, iov + i * 16 + 8)?];
        let n = op(p, fd, base, len)?;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(total)
}

fn get_u64(p: &Process, va: u64) -> Result<u64, Errno> {
    let mut b = [0; 8];
    p.memory().read(va, &mut b)?;
    Ok(u64::from_ne_bytes(b))
}

/// Reads a NUL-terminated path from user memory.
fn get_path(p: &Process, va: u64) -> Result<String, Errno> {
    let mut bytes = alloc::vec::Vec::new();
    let mut addr = va;
    loop {
        // Never read past a page boundary before checking for the NUL.
        let n = 4096 - (addr % 4096) as usize;
        let mut chunk = [0u8; 4096];
        p.memory().read(addr, &mut chunk[..n])?;
        if let Some(end) = chunk[..n].iter().position(|&b| b == 0) {
            bytes.extend_from_slice(&chunk[..end]);
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() >= PATH_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        addr += n as u64;
    }
    String::from_utf8(bytes).map_err(|_| Errno::EINVAL)
}

fn vfs() -> Result<&'static osmium_fs::Vfs, Errno> {
    crate::vfs().ok_or(Errno::ENOENT)
}

/// The absolute path for `path` relative to `dirfd`.
fn path_at(p: &Process, dirfd: i32, path: u64) -> Result<String, Errno> {
    let path = get_path(p, path)?;
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if path.starts_with('/') {
        return Ok(path);
    }
    let base =
        if dirfd == AT_FDCWD { p.cwd() } else { p.files().lock().get(dirfd)?.path().ok_or(Errno::ENOTDIR)?.into() };
    Ok(join(&base, &path))
}

fn join(base: &str, rel: &str) -> String {
    let mut s = String::from(base.trim_end_matches('/'));
    s.push('/');
    s.push_str(rel);
    s
}

fn openat(p: &Process, dirfd: i32, path: u64, flags: u64, mode: u32) -> SysResult {
    let path = path_at(p, dirfd, path)?;
    let access = match flags & oflag::ACCMODE {
        0 => Access { read: true, write: false, append: false },
        oflag::WRONLY => Access { read: false, write: true, append: false },
        oflag::RDWR => Access { read: true, write: true, append: false },
        _ => return Err(Errno::EINVAL),
    };
    let access = Access { append: flags & oflag::APPEND != 0, ..access };
    let mut of = OpenFlags::empty();
    for (bit, f) in [
        (oflag::CREAT, OpenFlags::CREATE),
        (oflag::EXCL, OpenFlags::EXCL),
        (oflag::TRUNC, OpenFlags::TRUNC),
        (oflag::APPEND, OpenFlags::APPEND),
        (oflag::DIRECTORY, OpenFlags::DIRECTORY),
        (oflag::NOFOLLOW, OpenFlags::NOFOLLOW),
    ] {
        if flags & bit != 0 {
            of |= f;
        }
    }
    if access.read {
        of |= OpenFlags::READ;
    }
    if access.write {
        of |= OpenFlags::WRITE;
    }
    let file = vfs()?.open(&path, of, mode & 0o7777 & !p.umask())?;
    if access.write && file.stat().kind == FileKind::Directory {
        return Err(Errno::EISDIR);
    }
    let open = OpenFile::with_path(file, access, path);
    p.files().lock().insert(open).map(|fd| fd as u64)
}

fn lseek(p: &Process, fd: i32, off: i64, whence: u64) -> SysResult {
    let f = p.files().lock().get(fd)?;
    let st = f.file().stat();
    if matches!(st.kind, FileKind::CharDevice | FileKind::Fifo | FileKind::Socket) {
        return Err(Errno::ESPIPE);
    }
    let base = match whence {
        0 => 0,
        1 => f.offset() as i64,
        2 => st.size as i64,
        _ => return Err(Errno::EINVAL),
    };
    let new = base.checked_add(off).filter(|&n| n >= 0).ok_or(Errno::EINVAL)?;
    f.set_offset(new as u64);
    Ok(new as u64)
}

fn newfstatat(p: &Process, dirfd: i32, path: u64, buf: u64, flags: u64) -> SysResult {
    let st = if flags & AT_EMPTY_PATH != 0 && get_path(p, path)?.is_empty() {
        let f = if dirfd == AT_FDCWD { None } else { Some(p.files().lock().get(dirfd)?) };
        match f {
            Some(f) => f.file().stat(),
            None => vfs()?.stat(&p.cwd(), true)?,
        }
    } else {
        vfs()?.stat(&path_at(p, dirfd, path)?, flags & AT_SYMLINK_NOFOLLOW == 0)?
    };
    put_stat(p, buf, &st)
}

/// Writes `st` as this architecture's `struct stat`.
fn put_stat(p: &Process, buf: u64, st: &Stat) -> SysResult {
    let mode = st.kind.mode_bits() | (st.mode & 0o7777);
    let blocks = st.size.div_ceil(512);
    let mut b = [0u8; 144];
    let mut put = |off: usize, bytes: &[u8]| b[off..off + bytes.len()].copy_from_slice(bytes);
    put(0, &st.dev.to_ne_bytes());
    put(8, &st.ino.to_ne_bytes());
    #[cfg(target_arch = "x86_64")]
    let len = {
        put(16, &(st.nlink as u64).to_ne_bytes());
        put(24, &mode.to_ne_bytes());
        put(40, &st.rdev.to_ne_bytes());
        put(48, &st.size.to_ne_bytes());
        put(56, &4096u64.to_ne_bytes());
        put(64, &blocks.to_ne_bytes());
        144
    };
    #[cfg(not(target_arch = "x86_64"))]
    let len = {
        put(16, &mode.to_ne_bytes());
        put(20, &st.nlink.to_ne_bytes());
        put(32, &st.rdev.to_ne_bytes());
        put(48, &st.size.to_ne_bytes());
        put(56, &4096u32.to_ne_bytes());
        put(64, &blocks.to_ne_bytes());
        128
    };
    p.memory().write(buf, &b[..len])?;
    Ok(0)
}

fn getdents64(p: &Process, fd: i32, buf: u64, len: u64) -> SysResult {
    let f = p.files().lock().get(fd)?;
    let st = f.file().stat();
    let mut out = alloc::vec::Vec::new();
    // Position 0 is ".", 1 is "..", and n + 2 is the file system's entry n.
    let mut pos = f.offset();
    loop {
        let (ino, kind, name) = match pos {
            0 => (st.ino, FileKind::Directory, String::from(".")),
            1 => (st.ino, FileKind::Directory, String::from("..")),
            n => match f.file().readdir(n as usize - 2)? {
                Some(e) => (e.ino, e.kind, e.name),
                None => break,
            },
        };
        // struct linux_dirent64 { u64 ino; i64 off; u16 reclen; u8 type; char name[]; }
        let reclen = (19 + name.len() + 1).next_multiple_of(8);
        if (out.len() + reclen) as u64 > len {
            if out.is_empty() {
                return Err(Errno::EINVAL);
            }
            break;
        }
        let start = out.len();
        out.extend_from_slice(&ino.to_ne_bytes());
        out.extend_from_slice(&(pos + 1).to_ne_bytes());
        out.extend_from_slice(&(reclen as u16).to_ne_bytes());
        out.push(kind.dirent_type());
        out.extend_from_slice(name.as_bytes());
        out.resize(start + reclen, 0);
        pos += 1;
    }
    p.memory().write(buf, &out)?;
    f.set_offset(pos);
    Ok(out.len() as u64)
}

fn getcwd(p: &Process, buf: u64, size: u64) -> SysResult {
    let mut cwd = p.cwd().into_bytes();
    cwd.push(0);
    if cwd.len() as u64 > size {
        return Err(Errno::ERANGE);
    }
    p.memory().write(buf, &cwd)?;
    Ok(cwd.len() as u64)
}

fn chdir(p: &Process, path: u64) -> SysResult {
    let path = path_at(p, AT_FDCWD, path)?;
    let vfs = vfs()?;
    if vfs.stat(&path, true)?.kind != FileKind::Directory {
        return Err(Errno::ENOTDIR);
    }
    p.set_cwd(vfs.canonicalize(&path)?);
    Ok(0)
}

fn unlinkat(p: &Process, dirfd: i32, path: u64, flags: u64) -> SysResult {
    let path = path_at(p, dirfd, path)?;
    let vfs = vfs()?;
    if flags & AT_REMOVEDIR != 0 { vfs.rmdir(&path) } else { vfs.unlink(&path) }.map(|()| 0)
}

fn mmap(p: &Process, len: u64, prot: u64, flags: u64, fd: i32) -> SysResult {
    const MAP_PRIVATE: u64 = 0x02;
    const MAP_FIXED: u64 = 0x10;
    const MAP_ANONYMOUS: u64 = 0x20;
    if flags & MAP_ANONYMOUS == 0 || fd != -1 {
        return Err(Errno::ENODEV);
    }
    if flags & MAP_PRIVATE == 0 || flags & MAP_FIXED != 0 {
        return Err(Errno::EINVAL);
    }
    let mut mf = MapFlags::NONE;
    for (bit, f) in [(1, MapFlags::READ), (2, MapFlags::WRITE), (4, MapFlags::EXEC)] {
        if prot & bit != 0 {
            mf = mf | f;
        }
    }
    p.mmap_anon(len, mf)
}

fn munmap(p: &Process, addr: u64, len: u64) -> SysResult {
    if !addr.is_multiple_of(4096) || len == 0 {
        return Err(Errno::EINVAL);
    }
    p.memory().unmap(addr, len.next_multiple_of(4096));
    Ok(0)
}

fn uname(p: &Process, buf: u64) -> SysResult {
    let machine = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "riscv64"
    };
    // struct utsname: sysname, nodename, release, version, machine and
    // domainname, 65 bytes each.
    let mut b = [0u8; 65 * 6];
    for (i, s) in ["Osmium", "osmium", env!("CARGO_PKG_VERSION"), "", machine, ""].iter().enumerate() {
        b[i * 65..i * 65 + s.len()].copy_from_slice(s.as_bytes());
    }
    p.memory().write(buf, &b)?;
    Ok(0)
}

#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64")))]
/// Handles a system-call trap from user mode: decodes this architecture's
/// registers, runs the call for the current process, and stores the result.
/// Returns `Some` if the process asked to exit; the caller then ends it with
/// [`crate::exit`] (after any logging of its own).
///
/// Call it only for [`osmium_arch::trap::Trap::Syscall`] from user mode.
/// (Not on hosted x86_64, whose simulated frames carry no registers.)
pub fn handle(frame: &mut TrapFrame) -> Option<ExitStatus> {
    let (nr, args) = decode(frame);
    let Some(p) = crate::current() else {
        frame.set_return(-(Errno::ENOSYS.0 as i64) as u64);
        return None;
    };
    match dispatch(&p, nr, args) {
        Outcome::Return(v) => {
            frame.set_return(v as u64);
            None
        }
        Outcome::Exit(status) => Some(status),
    }
}

/// The call number and six arguments, and on RISC-V steps the PC past the
/// `ecall` (`svc` and `syscall` leave it past the instruction already).
#[cfg(target_arch = "riscv64")]
fn decode(frame: &mut TrapFrame) -> (u64, [u64; 6]) {
    let a = frame.syscall_args();
    frame.set_pc(frame.pc() + 4);
    (a[7], [a[0], a[1], a[2], a[3], a[4], a[5]])
}

#[cfg(target_arch = "aarch64")]
fn decode(frame: &mut TrapFrame) -> (u64, [u64; 6]) {
    let x = frame.syscall_args();
    (frame.x[8], [x[0], x[1], x[2], x[3], x[4], x[5]])
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn decode(frame: &mut TrapFrame) -> (u64, [u64; 6]) {
    let [nr, a0, a1, a2, a3, a4, a5] = frame.syscall_args();
    (nr, [a0, a1, a2, a3, a4, a5])
}
