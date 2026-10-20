//! The system-call layer: Linux numbers and structure layouts for each
//! architecture, decoded once and handled by portable code.

use alloc::string::String;
use alloc::vec;

#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64")))]
use osmium_arch::trap::TrapFrame;
use osmium_fs::{Errno, FileKind, OpenFlags, PATH_MAX, Stat};
use osmium_mm::paging::MapFlags;

use crate::fd::{Access, OpenFile};
use crate::process::{ExitStatus, Pid, Process};
use crate::thread::Thread;

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
    Clone,
    Fork,
    Vfork,
    Execve,
    Wait4,
    Dup,
    Dup2,
    Dup3,
    Fcntl,
    Socket,
    Bind,
    Listen,
    Accept,
    Accept4,
    Connect,
    Sendto,
    Recvfrom,
    Shutdown,
    Getsockname,
    Getpeername,
    Setsockopt,
    Getsockopt,
    Sendmsg,
    Recvmsg,
    Socketpair,
    Ppoll,
    Pselect6,
    EpollCreate1,
    EpollCtl,
    EpollPwait,
    /// x86_64 only (the generic table has only the `p` variants).
    #[cfg(target_arch = "x86_64")]
    Poll,
    #[cfg(target_arch = "x86_64")]
    Select,
    #[cfg(target_arch = "x86_64")]
    EpollCreate,
    #[cfg(target_arch = "x86_64")]
    EpollWait,
    RtSigaction,
    RtSigprocmask,
    RtSigreturn,
    RtSigpending,
    Kill,
    Tkill,
    Tgkill,
    Futex,
    SetTidAddress,
    SetRobustList,
    GetRobustList,
    /// x86_64 only: sets the thread pointer (`FS.base`).
    #[cfg(target_arch = "x86_64")]
    ArchPrctl,
}

/// Linux system-call numbers for x86_64.
#[cfg(target_arch = "x86_64")]
const NUMBERS: &[(u64, Sys)] = &[
    (0, Sys::Read),
    (1, Sys::Write),
    (32, Sys::Dup),
    (33, Sys::Dup2),
    (56, Sys::Clone),
    (57, Sys::Fork),
    (58, Sys::Vfork),
    (59, Sys::Execve),
    (61, Sys::Wait4),
    (72, Sys::Fcntl),
    (292, Sys::Dup3),
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
    (41, Sys::Socket),
    (42, Sys::Connect),
    (43, Sys::Accept),
    (44, Sys::Sendto),
    (45, Sys::Recvfrom),
    (48, Sys::Shutdown),
    (49, Sys::Bind),
    (50, Sys::Listen),
    (51, Sys::Getsockname),
    (52, Sys::Getpeername),
    (54, Sys::Setsockopt),
    (55, Sys::Getsockopt),
    (288, Sys::Accept4),
    (46, Sys::Sendmsg),
    (47, Sys::Recvmsg),
    (53, Sys::Socketpair),
    (7, Sys::Poll),
    (23, Sys::Select),
    (270, Sys::Pselect6),
    (271, Sys::Ppoll),
    (213, Sys::EpollCreate),
    (291, Sys::EpollCreate1),
    (233, Sys::EpollCtl),
    (232, Sys::EpollWait),
    (281, Sys::EpollPwait),
    (13, Sys::RtSigaction),
    (14, Sys::RtSigprocmask),
    (15, Sys::RtSigreturn),
    (127, Sys::RtSigpending),
    (62, Sys::Kill),
    (200, Sys::Tkill),
    (234, Sys::Tgkill),
    (202, Sys::Futex),
    (218, Sys::SetTidAddress),
    (158, Sys::ArchPrctl),
    (273, Sys::SetRobustList),
    (274, Sys::GetRobustList),
];

/// Linux system-call numbers for RISC-V and AArch64 (asm-generic).
#[cfg(not(target_arch = "x86_64"))]
const NUMBERS: &[(u64, Sys)] = &[
    (17, Sys::Getcwd),
    (23, Sys::Dup),
    (24, Sys::Dup3),
    (25, Sys::Fcntl),
    (220, Sys::Clone),
    (221, Sys::Execve),
    (260, Sys::Wait4),
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
    (198, Sys::Socket),
    (200, Sys::Bind),
    (201, Sys::Listen),
    (202, Sys::Accept),
    (203, Sys::Connect),
    (204, Sys::Getsockname),
    (205, Sys::Getpeername),
    (206, Sys::Sendto),
    (207, Sys::Recvfrom),
    (208, Sys::Setsockopt),
    (209, Sys::Getsockopt),
    (210, Sys::Shutdown),
    (242, Sys::Accept4),
    (211, Sys::Sendmsg),
    (212, Sys::Recvmsg),
    (199, Sys::Socketpair),
    (72, Sys::Pselect6),
    (73, Sys::Ppoll),
    (20, Sys::EpollCreate1),
    (21, Sys::EpollCtl),
    (22, Sys::EpollPwait),
    (134, Sys::RtSigaction),
    (135, Sys::RtSigprocmask),
    (139, Sys::RtSigreturn),
    (136, Sys::RtSigpending),
    (129, Sys::Kill),
    (130, Sys::Tkill),
    (131, Sys::Tgkill),
    (98, Sys::Futex),
    (96, Sys::SetTidAddress),
    (99, Sys::SetRobustList),
    (100, Sys::GetRobustList),
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
    pub const CLOEXEC: u64 = 0o2000000;
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
    /// The process forked `child` (see [`Process::fork`]). Return the
    /// child's pid to the parent, and spawn the child's task resuming from a
    /// copy of the parent's registers with a return value of 0 and, if
    /// `stack` is not 0, that stack pointer.
    Fork {
        /// The new process, held by its parent until reaped.
        child: Pid,
        /// The child's stack pointer, or 0 to keep the parent's.
        stack: u64,
    },
    /// The process replaced its program: resume user mode at `pc` with
    /// stack `sp` and every other register cleared.
    Exec {
        /// The new program's entry point.
        pc: u64,
        /// Its initial stack pointer.
        sp: u64,
    },
    /// The process cloned a thread (see [`crate::thread`]). Return `tid` to
    /// the caller, and start a task that resumes from a copy of its
    /// registers with a return value of 0, stack pointer `stack` and, if
    /// `tls` is not 0, that thread pointer.
    Thread {
        /// The new thread's id.
        tid: u32,
        /// Its stack pointer.
        stack: u64,
        /// Its thread pointer, or 0.
        tls: u64,
    },
}

type SysResult = Result<u64, Errno>;

/// Handles system call `nr` with arguments `a` on behalf of `p`, the
/// calling process, as its first thread. Calls may block.
pub fn dispatch(p: &Process, nr: u64, a: [u64; 6]) -> Outcome {
    dispatch_as(p, &p.leader(), nr, a)
}

/// [`dispatch`] on behalf of thread `th` of `p`.
pub fn dispatch_as(p: &Process, th: &Thread, nr: u64, a: [u64; 6]) -> Outcome {
    let Some(sys) = Sys::from_number(nr) else { return Outcome::Return(-(Errno::ENOSYS.0 as i64)) };
    let fd = a[0] as i32;
    let r = match sys {
        Sys::Exit => return Outcome::Exit(ExitStatus::Code(a[0] as i32)),
        Sys::ExitGroup => {
            crate::thread::exit_group(p, ExitStatus::Code(a[0] as i32));
            return Outcome::Exit(ExitStatus::Code(a[0] as i32));
        }
        Sys::Read => read(p, fd, a[1], a[2]),
        Sys::Write => write(p, fd, a[1], a[2]),
        Sys::Readv => readv(p, fd, a[1], a[2]),
        Sys::Writev => writev(p, fd, a[1], a[2]),
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
        Sys::Getpid => Ok(p.pid().0 as u64),
        Sys::Gettid => Ok(th.tid() as u64),
        Sys::Getppid => Ok(p.parent().map_or(0, |pid| pid.0 as u64)),
        Sys::Brk => Ok(p.brk(a[0])),
        Sys::Mmap => mmap(p, a[1], a[2], a[3], a[4] as i32),
        Sys::Munmap => munmap(p, a[0], a[1]),
        Sys::SchedYield => {
            osmium_sched::yield_now();
            Ok(0)
        }
        Sys::Uname => uname(p, a[0]),
        Sys::Fork | Sys::Vfork => return crate::thread::forked(p, th, outcome(fork(p, SIGCHLD, [0; 4]))),
        // asm-generic: (flags, stack, parent_tid, tls, child_tid);
        // x86_64: (flags, stack, parent_tid, child_tid, tls).
        #[cfg(target_arch = "x86_64")]
        Sys::Clone => return crate::thread::clone(p, th, a[0], [a[1], a[2], a[3], a[4]]),
        #[cfg(not(target_arch = "x86_64"))]
        Sys::Clone => return crate::thread::clone(p, th, a[0], [a[1], a[2], a[4], a[3]]),
        Sys::Execve => return outcome(execve(p, th, a[0], a[1], a[2])),
        Sys::Wait4 => wait4(p, a[0] as i32, a[1], a[2], a[3]),
        Sys::Dup => dup(p, fd),
        Sys::Dup2 => dup3(p, fd, a[1] as i32, 0, true),
        Sys::Dup3 => dup3(p, fd, a[1] as i32, a[2], false),
        Sys::Fcntl => fcntl(p, fd, a[1], a[2]),
        Sys::Socket => crate::socket::socket(p, a[0], a[1], a[2]),
        Sys::Bind => crate::socket::bind(p, fd, a[1], a[2]),
        Sys::Listen => crate::socket::listen(p, fd, a[1]),
        Sys::Accept => crate::socket::accept(p, fd, a[1], a[2], 0),
        Sys::Accept4 => crate::socket::accept(p, fd, a[1], a[2], a[3]),
        Sys::Connect => crate::socket::connect(p, fd, a[1], a[2]),
        Sys::Sendto => crate::socket::sendto(p, fd, a[1], a[2], a[3], a[4], a[5]),
        Sys::Recvfrom => crate::socket::recvfrom(p, fd, a[1], a[2], a[3], a[4], a[5]),
        Sys::Shutdown => crate::socket::shutdown(p, fd, a[1]),
        Sys::Getsockname => crate::socket::getsockname(p, fd, a[1], a[2]),
        Sys::Getpeername => crate::socket::getpeername(p, fd, a[1], a[2]),
        Sys::Setsockopt => crate::socket::setsockopt(p, fd, a[1], a[2], a[3], a[4]),
        Sys::Getsockopt => crate::socket::getsockopt(p, fd, a[1], a[2], a[3], a[4]),
        Sys::Sendmsg => crate::socket::sendmsg(p, fd, a[1], a[2]),
        Sys::Recvmsg => crate::socket::recvmsg(p, fd, a[1], a[2]),
        Sys::Socketpair => crate::socket::socketpair(p, a[0], a[1], a[2], a[3]),
        Sys::Ppoll => crate::poll::ppoll(p, a[0], a[1], a[2], a[3], a[4]),
        Sys::Pselect6 => crate::poll::pselect6(p, a[0], a[1], a[2], a[3], a[4], a[5]),
        Sys::EpollCreate1 => crate::epoll::create1(p, a[0]),
        Sys::EpollCtl => crate::epoll::ctl(p, fd, a[1], a[2] as i32, a[3]),
        Sys::EpollPwait => crate::epoll::pwait(p, fd, a[1], a[2], a[3], a[4], a[5]),
        #[cfg(target_arch = "x86_64")]
        Sys::Poll => crate::poll::poll(p, a[0], a[1], a[2]),
        #[cfg(target_arch = "x86_64")]
        Sys::Select => crate::poll::select(p, a[0], a[1], a[2], a[3], a[4]),
        #[cfg(target_arch = "x86_64")]
        Sys::EpollCreate => crate::epoll::create(p, a[0]),
        #[cfg(target_arch = "x86_64")]
        Sys::EpollWait => crate::epoll::wait_events(p, fd, a[1], a[2], a[3]),
        Sys::RtSigaction => crate::signal::sigaction(p, a[0], a[1], a[2], a[3]),
        Sys::RtSigprocmask => crate::signal::sigprocmask(p, th, a[0], a[1], a[2], a[3]),
        Sys::RtSigpending => crate::signal::sigpending(p, th, a[0], a[1]),
        // `handle` restores the registers; there is nothing to return to here.
        Sys::RtSigreturn => Err(Errno::EINVAL),
        Sys::Kill => crate::signal::kill(p, fd, a[1]),
        Sys::Tkill => crate::signal::tkill(p, fd, a[1]),
        Sys::Tgkill => crate::signal::tgkill(p, fd, a[1] as i32, a[2]),
        Sys::Futex => crate::futex::futex(p, th, a),
        Sys::SetRobustList => crate::futex::set_robust_list(th, a[0], a[1]),
        Sys::GetRobustList => crate::futex::get_robust_list(p, th, a[0], a[1], a[2]),
        Sys::SetTidAddress => {
            th.set_clear_tid(a[0]);
            Ok(th.tid() as u64)
        }
        #[cfg(target_arch = "x86_64")]
        Sys::ArchPrctl => crate::thread::arch_prctl(p, th, a[0], a[1]),
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

/// The `struct iovec { base, len }` array at `iov`.
fn iovecs(p: &Process, iov: u64, count: u64) -> Result<alloc::vec::Vec<(u64, u64)>, Errno> {
    if count > 1024 {
        return Err(Errno::EINVAL);
    }
    (0..count).map(|i| Ok((user_u64(p, iov + i * 16)?, user_u64(p, iov + i * 16 + 8)?))).collect()
}

fn readv(p: &Process, fd: i32, iov: u64, count: u64) -> SysResult {
    let mut total = 0;
    for (base, len) in iovecs(p, iov, count)? {
        let n = read(p, fd, base, len)?;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(total)
}

/// Gathers the pieces and writes them together (in chunks of up to 64 KiB),
/// so a short `writev` reaches a console or pipe as one write.
fn writev(p: &Process, fd: i32, iov: u64, count: u64) -> SysResult {
    const GATHER: usize = 64 * 1024;
    let f = p.files().lock().get(fd)?;
    let mut pending = alloc::vec::Vec::new();
    let mut total = 0;
    let mut flush = |pending: &mut alloc::vec::Vec<u8>| -> Result<bool, Errno> {
        let n = if pending.is_empty() { 0 } else { f.write(pending)? };
        total += n as u64;
        let complete = n == pending.len();
        pending.clear();
        Ok(complete)
    };
    for (base, len) in iovecs(p, iov, count)? {
        let mut done = 0;
        while done < len {
            let n = ((len - done) as usize).min(GATHER - pending.len());
            let start = pending.len();
            pending.resize(start + n, 0);
            p.memory().read(base + done, &mut pending[start..])?;
            done += n as u64;
            if pending.len() == GATHER && !flush(&mut pending)? {
                return Ok(total);
            }
        }
    }
    flush(&mut pending)?;
    Ok(total)
}

fn user_u64(p: &Process, va: u64) -> Result<u64, Errno> {
    let mut b = [0; 8];
    p.memory().read(va, &mut b)?;
    Ok(u64::from_ne_bytes(b))
}

/// Reads a NUL-terminated path from user memory.
fn user_path(p: &Process, va: u64) -> Result<String, Errno> {
    String::from_utf8(user_cstr(p, va, PATH_MAX, Errno::ENAMETOOLONG)?).map_err(|_| Errno::EINVAL)
}

/// Reads a NUL-terminated string from user memory, failing with `too_long`
/// once it reaches `max` bytes.
fn user_cstr(p: &Process, va: u64, max: usize, too_long: Errno) -> Result<alloc::vec::Vec<u8>, Errno> {
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
        if bytes.len() >= max {
            return Err(too_long);
        }
        addr += n as u64;
    }
    Ok(bytes)
}

fn vfs() -> Result<&'static osmium_fs::Vfs, Errno> {
    crate::vfs().ok_or(Errno::ENOENT)
}

/// The absolute path for `path` relative to `dirfd`.
fn path_at(p: &Process, dirfd: i32, path: u64) -> Result<String, Errno> {
    let path = user_path(p, path)?;
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
    p.files().lock().insert_from(0, open, flags & oflag::CLOEXEC != 0).map(|fd| fd as u64)
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
    let st = if flags & AT_EMPTY_PATH != 0 && user_path(p, path)?.is_empty() {
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
    let len = len.checked_next_multiple_of(4096).ok_or(Errno::EINVAL)?;
    if !addr.is_multiple_of(4096) || len == 0 {
        return Err(Errno::EINVAL);
    }
    p.memory().unmap(addr, len);
    Ok(0)
}

pub(crate) fn outcome(r: Result<Outcome, Errno>) -> Outcome {
    r.unwrap_or_else(|e| Outcome::Return(-(e.0 as i64)))
}

const SIGCHLD: u64 = 17;

mod clone_flag {
    /// The signal sent to the parent when the child exits (ignored).
    pub const EXIT_SIGNAL: u64 = 0xff;
    pub const VM: u64 = 0x100;
    pub const VFORK: u64 = 0x4000;
    pub const PARENT_SETTID: u64 = 0x10_0000;
    pub const CHILD_CLEARTID: u64 = 0x20_0000;
    pub const CHILD_SETTID: u64 = 0x100_0000;
}

/// `fork`, `vfork`, and `clone` as C libraries use it to fork: a new
/// process, never a thread. `vfork` (`CLONE_VM | CLONE_VFORK`) gets a copy
/// too, which programs that follow vfork's rules cannot tell apart, except
/// that the parent does not wait. `CLONE_CHILD_CLEARTID` is accepted and
/// ignored: it matters only to other threads, and there are none.
/// `tids` is (stack, parent_tid, child_tid, tls).
pub(crate) fn fork(p: &Process, flags: u64, [stack, ptid, ctid, _tls]: [u64; 4]) -> Result<Outcome, Errno> {
    use clone_flag::*;
    crate::exec::platform()?;
    let flags = flags & !EXIT_SIGNAL;
    let vfork = flags & (VM | VFORK) == VM | VFORK;
    if flags & !(VM | VFORK | PARENT_SETTID | CHILD_CLEARTID | CHILD_SETTID) != 0 || (flags & VM != 0 && !vfork) {
        return Err(Errno::EINVAL);
    }
    // Fail before the child exists: once registered, it would linger as a
    // child that never runs, so `wait4` could block on it for ever. Writing
    // the bytes back unchanged checks the parent's page, and the child's is
    // a copy of it.
    for (flag, va) in [(PARENT_SETTID, ptid), (CHILD_SETTID, ctid)] {
        if flags & flag != 0 {
            let mut old = [0; 4];
            p.memory().read(va, &mut old)?;
            p.memory().write(va, &old)?;
        }
    }
    let child = p.fork()?;
    let tid = child.pid().0.to_ne_bytes();
    if flags & PARENT_SETTID != 0 {
        p.memory().write(ptid, &tid)?;
    }
    if flags & CHILD_SETTID != 0 {
        child.memory().write(ctid, &tid)?;
    }
    Ok(Outcome::Fork { child: child.pid(), stack })
}

/// The NULL-terminated array of string pointers at `va` (NULL itself is an
/// empty array), at most [`crate::exec::ARG_MAX`] bytes in all.
fn user_strings(p: &Process, va: u64, total: &mut usize) -> Result<alloc::vec::Vec<alloc::vec::Vec<u8>>, Errno> {
    let mut out = alloc::vec::Vec::new();
    if va == 0 {
        return Ok(out);
    }
    loop {
        let ptr = user_u64(p, va + out.len() as u64 * 8)?;
        if ptr == 0 {
            return Ok(out);
        }
        let s = user_cstr(p, ptr, crate::exec::ARG_MAX, Errno::E2BIG)?;
        *total += s.len() + 1 + 8;
        if *total > crate::exec::ARG_MAX {
            return Err(Errno::E2BIG);
        }
        out.push(s);
    }
}

fn execve(p: &Process, th: &Thread, path: u64, argv: u64, envp: u64) -> Result<Outcome, Errno> {
    crate::exec::platform()?;
    let path = path_at(p, AT_FDCWD, path)?;
    let mut total = 0;
    let argv = user_strings(p, argv, &mut total)?;
    let envp = user_strings(p, envp, &mut total)?;
    let argv: alloc::vec::Vec<&[u8]> = argv.iter().map(|a| a.as_slice()).collect();
    let envp: alloc::vec::Vec<&[u8]> = envp.iter().map(|e| e.as_slice()).collect();
    if p.group.live() > 1 {
        crate::thread::exec_begin(p, th)?;
    }
    let entry = p.exec(&path, &argv, &envp)?;
    crate::signal::on_exec(p);
    Ok(Outcome::Exec { pc: entry.pc, sp: entry.sp })
}

/// `wait4(pid, wstatus, options, rusage)`. Without process groups, `pid` 0
/// and below -1 mean any child, like -1. Resource usage reads as zero.
fn wait4(p: &Process, pid: i32, wstatus: u64, options: u64, rusage: u64) -> SysResult {
    const WNOHANG: u64 = 1;
    let which = (pid > 0).then_some(Pid(pid as u32));
    let Some((pid, status)) = p.wait_child(which, options & WNOHANG != 0)? else { return Ok(0) };
    if wstatus != 0 {
        p.memory().write(wstatus, &status.wait_status().to_ne_bytes())?;
    }
    if rusage != 0 {
        p.memory().write(rusage, &[0; 144])?;
    }
    Ok(pid.0 as u64)
}

fn dup(p: &Process, fd: i32) -> SysResult {
    let mut files = p.files().lock();
    let f = files.get(fd)?;
    files.insert(f).map(|fd| fd as u64)
}

/// `dup3`, or `dup2` when `dup2`: the same, except that `old == new` is
/// allowed and there are no flags.
fn dup3(p: &Process, old: i32, new: i32, flags: u64, dup2: bool) -> SysResult {
    let mut files = p.files().lock();
    let f = files.get(old)?;
    if old == new {
        return if dup2 { Ok(new as u64) } else { Err(Errno::EINVAL) };
    }
    if flags & !oflag::CLOEXEC != 0 {
        return Err(Errno::EINVAL);
    }
    files.insert_at(new, f, flags & oflag::CLOEXEC != 0)?;
    Ok(new as u64)
}

fn fcntl(p: &Process, fd: i32, cmd: u64, arg: u64) -> SysResult {
    const F_DUPFD: u64 = 0;
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3;
    const F_SETFL: u64 = 4;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const FD_CLOEXEC: u64 = 1;
    let mut files = p.files().lock();
    let f = files.get(fd)?;
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let min = usize::try_from(arg).map_err(|_| Errno::EINVAL)?;
            files.insert_from(min, f, cmd == F_DUPFD_CLOEXEC).map(|fd| fd as u64)
        }
        F_GETFD => Ok(if files.cloexec(fd)? { FD_CLOEXEC } else { 0 }),
        F_SETFD => files.set_cloexec(fd, arg & FD_CLOEXEC != 0).map(|()| 0),
        F_GETFL => {
            let a = f.access();
            let mode = match (a.read, a.write) {
                (true, true) => oflag::RDWR,
                (false, true) => oflag::WRONLY,
                _ => 0,
            };
            Ok(mode | if a.append { oflag::APPEND } else { 0 } | crate::socket::status_flags(f.file()))
        }
        // Only a socket's O_NONBLOCK can be changed so far.
        F_SETFL => {
            crate::socket::set_status_flags(f.file(), arg);
            Ok(0)
        }
        _ => Err(Errno::EINVAL),
    }
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
    let th = crate::thread::current_thread(&p);
    if Sys::from_number(nr) == Some(Sys::RtSigreturn) {
        // The saved registers include the interrupted call's result.
        return crate::signal::sigreturn(&p, &th, frame).or_else(|| crate::signal::deliver_to(&p, &th, frame));
    }
    match dispatch_as(&p, &th, nr, args) {
        Outcome::Return(v) => frame.set_return(v as u64),
        Outcome::Exit(status) => return Some(status),
        Outcome::Fork { child, stack } => {
            let mut regs = frame.clone();
            regs.set_return(0);
            if stack != 0 {
                set_sp(&mut regs, stack);
            }
            // `fork` checked both: the parent holds the child, and the
            // platform is set.
            let child = Process::find(child).expect("the parent holds its child");
            let resume = crate::exec::platform().expect("fork needs a platform").resume;
            // The child continues with the parent's FP registers, which are
            // still live: the kernel never uses them.
            let fp = if osmium_arch::fp::enabled() {
                // SAFETY: a kernel that enables FP enables it on every CPU.
                unsafe { osmium_arch::fp::FpState::capture() }
            } else {
                osmium_arch::fp::FpState::new()
            };
            child.spawn_with_fp(osmium_sched::TaskBuilder::new(child.name()), fp, move || resume(regs));
            frame.set_return(child.pid().0 as u64);
        }
        Outcome::Exec { pc, sp } => start(frame, pc, sp),
        Outcome::Thread { tid, stack, tls } => crate::thread::start(&p, tid, frame, stack, tls),
    }
    crate::signal::deliver_to(&p, &th, frame)
}

/// Points `frame` at a new program's entry and stack, other registers clear.
#[cfg(target_arch = "riscv64")]
fn start(frame: &mut TrapFrame, pc: u64, sp: u64) {
    frame.x = [0; 32];
    frame.x[2] = sp;
    frame.epc = pc;
}

#[cfg(target_arch = "riscv64")]
fn set_sp(frame: &mut TrapFrame, sp: u64) {
    frame.x[2] = sp;
}

#[cfg(target_arch = "aarch64")]
fn start(frame: &mut TrapFrame, pc: u64, sp: u64) {
    frame.x = [0; 31];
    frame.sp = sp;
    frame.elr = pc;
    // EL0t, interrupts unmasked; no user thread pointer.
    frame.spsr = 0;
    frame.tpidrro = 0;
}

#[cfg(target_arch = "aarch64")]
fn set_sp(frame: &mut TrapFrame, sp: u64) {
    frame.sp = sp;
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn start(frame: &mut TrapFrame, pc: u64, sp: u64) {
    let f = frame;
    for r in [
        &mut f.rax, &mut f.rbx, &mut f.rcx, &mut f.rdx, &mut f.rsi, &mut f.rdi, &mut f.rbp, &mut f.r8, &mut f.r9,
        &mut f.r10, &mut f.r11, &mut f.r12, &mut f.r13, &mut f.r14, &mut f.r15,
    ] {
        *r = 0;
    }
    f.rip = pc;
    f.rsp = sp;
    f.rflags = 0x202;
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn set_sp(frame: &mut TrapFrame, sp: u64) {
    frame.rsp = sp;
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
