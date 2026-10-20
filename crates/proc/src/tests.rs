use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::alloc::{Layout, alloc, dealloc};
use std::sync::{Mutex as StdMutex, OnceLock};

use osmium_fs::{DirEntry, Errno, File, FileKind, Stat, Vfs};
use osmium_mm::addr::PhysAddr;
use osmium_mm::frame::PhysMapper;
use osmium_mm::paging::formats::Sv39;
use osmium_mm::paging::{MapFlags, PageTable, TableAlloc};

use super::*;

/// Page frames from the host heap; "physical" addresses are host pointers.
#[derive(Default)]
struct HeapFrames {
    live: StdMutex<usize>,
}

const PAGE_LAYOUT: Layout = match Layout::from_size_align(4096, 4096) {
    Ok(l) => l,
    Err(_) => panic!(),
};

// SAFETY: identity mapping of host allocations.
unsafe impl PhysMapper for HeapFrames {
    fn phys_to_virt(&self, pa: PhysAddr) -> *mut u8 {
        pa.0 as *mut u8
    }
}

// SAFETY: every frame is a fresh, exclusively owned, page-aligned allocation.
unsafe impl TableAlloc for HeapFrames {
    fn alloc_table(&self) -> Option<PhysAddr> {
        *self.live.lock().unwrap() += 1;
        // SAFETY: non-zero size.
        Some(PhysAddr(unsafe { alloc(PAGE_LAYOUT) } as u64))
    }
    unsafe fn free_table(&self, pa: PhysAddr) {
        *self.live.lock().unwrap() -= 1;
        // SAFETY: allocated by `alloc_table` with the same layout.
        unsafe { dealloc(pa.0 as *mut u8, PAGE_LAYOUT) }
    }
}

impl HeapFrames {
    fn live(&self) -> usize {
        *self.live.lock().unwrap()
    }
}

fn leaked_frames() -> &'static HeapFrames {
    Box::leak(Box::new(HeapFrames::default()))
}

fn space(frames: &'static HeapFrames) -> AddressSpace<Sv39, &'static HeapFrames> {
    let kernel: &'static PageTable<Sv39, &'static HeapFrames> = Box::leak(Box::new(PageTable::new(frames).unwrap()));
    // SAFETY: the kernel table is leaked.
    unsafe { AddressSpace::new(frames, kernel, 0..0) }.unwrap()
}

use alloc::boxed::Box;

#[test]
fn user_copies_check_the_page_table() {
    let frames = leaked_frames();
    let s = space(frames);
    s.map_anon(0x1000, 0x2000, MapFlags::RW).unwrap();
    s.map_anon(0x5000, 0x1000, MapFlags::READ).unwrap();

    // Straddles the two writable pages.
    s.write(0x1ffc, b"abcdefgh").unwrap();
    let mut buf = [0; 8];
    s.read(0x1ffc, &mut buf).unwrap();
    assert_eq!(&buf, b"abcdefgh");

    assert_eq!(s.read(0x2ffc, &mut buf), Err(Errno::EFAULT), "runs into an unmapped page");
    assert_eq!(s.write(0x5000, b"x"), Err(Errno::EFAULT), "read-only");
    s.read(0x5000, &mut buf).unwrap();
    assert_eq!(buf, [0; 8], "fresh pages are zeroed");
    assert_eq!(s.read(u64::MAX - 2, &mut buf), Err(Errno::EFAULT), "wraps");

    s.load_flat(0x8000, b"code", MapFlags::RX).unwrap();
    s.read(0x8000, &mut buf[..4]).unwrap();
    assert_eq!(&buf[..4], b"code");

    let before = frames.live();
    s.unmap(0x1000, 0x2000);
    assert_eq!(frames.live(), before - 2);
    assert_eq!(s.read(0x1000, &mut buf), Err(Errno::EFAULT));
    drop(s);
    assert_eq!(frames.live(), 1, "only the leaked kernel root remains");
}

/// Captures console output.
#[derive(Default)]
struct Console(StdMutex<Vec<u8>>);

impl File for Console {
    fn write(&self, _off: u64, buf: &[u8]) -> Result<usize, Errno> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn read(&self, _off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let line = b"typed\n";
        buf[..line.len()].copy_from_slice(line);
        Ok(line.len())
    }
    fn stat(&self) -> Stat {
        Stat { kind: FileKind::CharDevice, mode: 0o620, ..Stat::default() }
    }
}

/// A read-only directory of fixed files.
struct Dir(Vec<(&'static str, Arc<dyn File>)>);
struct Text(&'static str, u64);

impl File for Text {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let rest = self.0.as_bytes().get(off as usize..).unwrap_or(&[]);
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(n)
    }
    fn stat(&self) -> Stat {
        Stat { ino: self.1, size: self.0.len() as u64, mode: 0o644, nlink: 1, ..Stat::default() }
    }
}

impl File for Dir {
    fn stat(&self) -> Stat {
        Stat { ino: 1, kind: FileKind::Directory, mode: 0o755, nlink: 2, ..Stat::default() }
    }
    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        Ok(self.0.get(index).map(|(n, f)| DirEntry { ino: f.stat().ino, kind: f.stat().kind, name: String::from(*n) }))
    }
    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        self.0.iter().find(|(n, _)| *n == name).map(|(_, f)| f.clone()).ok_or(Errno::ENOENT)
    }
}

fn console() -> &'static Arc<Console> {
    static C: OnceLock<Arc<Console>> = OnceLock::new();
    C.get_or_init(|| {
        let c = Arc::new(Console::default());
        set_console(c.clone());
        let etc: Arc<dyn File> = Arc::new(Dir(alloc::vec![("motd", Arc::new(Text("welcome\n", 3)) as Arc<dyn File>)]));
        let root = Dir(alloc::vec![("hello.txt", Arc::new(Text("hello, file\n", 2)) as Arc<dyn File>), ("etc", etc)]);
        set_vfs(Box::leak(Box::new(Vfs::new(Arc::new(root)))));
        c
    })
}

const DATA: u64 = 0x10_0000;

fn process(name: &'static str) -> (Arc<Process>, &'static HeapFrames) {
    console();
    let frames = leaked_frames();
    let s = space(frames);
    s.map_anon(DATA, 0x4000, MapFlags::RW).unwrap();
    let p = Process::new(name, s, 0x40_0000);
    p.set_mmap_area(0x100_0000..0x110_0000);
    (p, frames)
}

fn call(p: &Process, sys: Sys, args: &[u64]) -> i64 {
    let mut a = [0; 6];
    a[..args.len()].copy_from_slice(args);
    match dispatch(p, sys.number(), a) {
        Outcome::Return(v) => v,
        Outcome::Exit(s) => panic!("unexpected exit {s:?}"),
    }
}

fn put(p: &Process, va: u64, bytes: &[u8]) {
    p.memory().write(va, bytes).unwrap();
}

fn get(p: &Process, va: u64, len: usize) -> Vec<u8> {
    let mut v = alloc::vec![0; len];
    p.memory().read(va, &mut v).unwrap();
    v
}

#[test]
fn console_io_and_identity() {
    let (p, _) = process("io");
    put(&p, DATA, b"hi there");
    assert_eq!(call(&p, Sys::Write, &[1, DATA, 8]), 8);
    assert!(console().0.lock().unwrap().windows(8).any(|w| w == b"hi there"));
    assert_eq!(call(&p, Sys::Write, &[1, 0xdead_0000, 8]), -(Errno::EFAULT.0 as i64));
    assert_eq!(call(&p, Sys::Write, &[7, DATA, 8]), -(Errno::EBADF.0 as i64));

    // writev of two pieces.
    put(&p, DATA + 0x100, b"ab");
    put(&p, DATA + 0x200, b"cde");
    let iov: Vec<u8> = [DATA + 0x100, 2, DATA + 0x200, 3].iter().flat_map(|v| v.to_ne_bytes()).collect();
    put(&p, DATA + 0x300, &iov);
    assert_eq!(call(&p, Sys::Writev, &[2, DATA + 0x300, 2]), 5);

    assert_eq!(call(&p, Sys::Read, &[0, DATA + 0x400, 100]), 6);
    assert_eq!(get(&p, DATA + 0x400, 6), b"typed\n");

    assert_eq!(call(&p, Sys::Getpid, &[]), p.pid().0 as i64);
    assert_eq!(call(&p, Sys::Getppid, &[]), 0);
    assert_eq!(call(&p, Sys::Uname, &[DATA]), 0);
    assert_eq!(&get(&p, DATA, 6), b"Osmium");
    assert_eq!(call(&p, Sys::Close, &[2]), 0);
    assert_eq!(call(&p, Sys::Close, &[2]), -(Errno::EBADF.0 as i64));
    assert_eq!(dispatch(&p, 9999, [0; 6]), Outcome::Return(-(Errno::ENOSYS.0 as i64)));
    assert_eq!(dispatch(&p, Sys::ExitGroup.number(), [3, 0, 0, 0, 0, 0]), Outcome::Exit(ExitStatus::Code(3)));
    assert_eq!(ExitStatus::Code(3).wait_status(), 0x300);
}

#[test]
fn brk_and_mmap_map_memory() {
    let (p, frames) = process("mem");
    let start = call(&p, Sys::Brk, &[0]) as u64;
    assert_eq!(start, 0x40_0000);
    assert_eq!(call(&p, Sys::Brk, &[start + 0x1800]) as u64, start + 0x1800);
    put(&p, start + 0x17ff, b"z");
    let live = frames.live();
    assert_eq!(call(&p, Sys::Brk, &[start + 0x10]) as u64, start + 0x10);
    assert_eq!(frames.live(), live - 1, "the second heap page is freed");
    assert_eq!(call(&p, Sys::Brk, &[start - 0x1000]) as u64, start + 0x10, "below the start: unchanged");

    let a = call(&p, Sys::Mmap, &[0, 0x3000, 3, 0x22, u64::MAX, 0]);
    assert_eq!(a, 0x100_0000);
    put(&p, a as u64 + 0x2fff, b"m");
    assert_eq!(call(&p, Sys::Mmap, &[0, 0x1000, 3, 0x22, u64::MAX, 0]), 0x100_3000);
    assert_eq!(call(&p, Sys::Mmap, &[0, 0x1000, 3, 0x02, 3, 0]), -(Errno::ENODEV.0 as i64), "file mappings");
    assert_eq!(call(&p, Sys::Munmap, &[a as u64, 0x3000]), 0);
    assert!(p.memory().read(a as u64, &mut [0]).is_err());
}

#[test]
fn files_through_the_vfs() {
    let (p, _) = process("fs");
    put(&p, DATA, b"/hello.txt\0");
    let fd = call(&p, Sys::Openat, &[-100i64 as u64, DATA, 0, 0]);
    assert_eq!(fd, 3, "lowest free descriptor after the console");
    assert_eq!(call(&p, Sys::Read, &[3, DATA + 0x100, 5]), 5);
    assert_eq!(call(&p, Sys::Read, &[3, DATA + 0x105, 100]), 7);
    assert_eq!(get(&p, DATA + 0x100, 12), b"hello, file\n");
    assert_eq!(call(&p, Sys::Read, &[3, DATA + 0x100, 100]), 0, "end of file");
    assert_eq!(call(&p, Sys::Lseek, &[3, 7, 0]), 7);
    assert_eq!(call(&p, Sys::Lseek, &[3, -2i64 as u64, 2]), 10);
    assert_eq!(call(&p, Sys::Lseek, &[1, 0, 0]), -(Errno::ESPIPE.0 as i64), "the console");

    assert_eq!(call(&p, Sys::Fstat, &[3, DATA + 0x200]), 0);
    let st = get(&p, DATA + 0x200, 64);
    assert_eq!(u64::from_ne_bytes(st[8..16].try_into().unwrap()), 2, "st_ino");
    assert_eq!(u64::from_ne_bytes(st[48..56].try_into().unwrap()), 12, "st_size");

    // Relative paths, chdir and getcwd.
    put(&p, DATA, b"etc\0");
    assert_eq!(call(&p, Sys::Chdir, &[DATA]), 0);
    assert_eq!(call(&p, Sys::Getcwd, &[DATA + 0x100, 64]), 5);
    assert_eq!(get(&p, DATA + 0x100, 5), b"/etc\0");
    put(&p, DATA, b"motd\0");
    let motd = call(&p, Sys::Openat, &[-100i64 as u64, DATA, 0, 0]);
    assert_eq!(call(&p, Sys::Read, &[motd as u64, DATA + 0x100, 100]), 8);
    put(&p, DATA, b"missing\0");
    assert_eq!(call(&p, Sys::Openat, &[-100i64 as u64, DATA, 0, 0]), -(Errno::ENOENT.0 as i64));
    assert_eq!(call(&p, Sys::Getcwd, &[DATA, 3]), -(Errno::ERANGE.0 as i64));

    // getdents64 on "/": ".", "..", "hello.txt", "etc".
    put(&p, DATA, b"/\0");
    let dir = call(&p, Sys::Openat, &[-100i64 as u64, DATA, 0, 0]) as u64;
    let n = call(&p, Sys::Getdents64, &[dir, DATA + 0x1000, 0x1000]) as usize;
    let buf = get(&p, DATA + 0x1000, n);
    let mut names = Vec::new();
    let mut off = 0;
    while off < n {
        let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
        let name = &buf[off + 19..off + reclen];
        names.push(String::from_utf8(name[..name.iter().position(|&b| b == 0).unwrap()].to_vec()).unwrap());
        off += reclen;
    }
    assert_eq!(names, [".", "..", "hello.txt", "etc"]);
    assert_eq!(call(&p, Sys::Getdents64, &[dir, DATA + 0x1000, 0x1000]), 0, "exhausted");
}

#[test]
fn processes_are_found_by_pid_until_dropped() {
    let (p, _) = process("find");
    let pid = p.pid();
    assert!(Process::find(pid).is_some_and(|q| Arc::ptr_eq(&q, &p)));
    p.set_exited(ExitStatus::Signal(11));
    assert_eq!(p.wait(), ExitStatus::Signal(11), "already exited: no blocking");
    assert_eq!(ExitStatus::Signal(11).wait_status(), 11);
    drop(p);
    assert!(Process::find(pid).is_none());
}
