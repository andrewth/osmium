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
        // SAFETY: non-zero size.
        let frame = unsafe { alloc(PAGE_LAYOUT) };
        if frame.is_null() {
            return None;
        }
        *self.live.lock().unwrap() += 1;
        Some(PhysAddr(frame as u64))
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
        let n = line.len().min(buf.len());
        buf[..n].copy_from_slice(&line[..n]);
        Ok(n)
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
        let bin: Arc<dyn File> = Arc::new(Dir(alloc::vec![("prog", Arc::new(Bytes(program(), 5)) as Arc<dyn File>)]));
        let root = Dir(alloc::vec![
            ("hello.txt", Arc::new(Text("hello, file\n", 2)) as Arc<dyn File>),
            ("etc", etc),
            ("bin", bin),
        ]);
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
        o => panic!("unexpected {o:?}"),
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

    // PROT_NONE reserves without mapping, so access faults rather than
    // leaving an entry with no permissions that the table walk misreads.
    let live = frames.live();
    let none = call(&p, Sys::Mmap, &[0, 0x2000, 0, 0x22, u64::MAX, 0]);
    assert_eq!(none, 0x100_0000, "the freed range is reused");
    assert_eq!(frames.live(), live);
    assert!(p.memory().read(none as u64, &mut [0]).is_err());
    assert_eq!(call(&p, Sys::Munmap, &[none as u64, 0x2000]), 0);
    // A length spanning the address space visits only mapped pages.
    assert_eq!(call(&p, Sys::Munmap, &[0, u64::MAX - 0xfff]), 0);
    assert_eq!(call(&p, Sys::Munmap, &[0, u64::MAX]), -(Errno::EINVAL.0 as i64), "rounds past 2^64");
}

#[test]
fn mmap_reuses_unmapped_ranges_for_ever() {
    let (p, frames) = process("mmap-reuse");
    let mmap = |len: u64| call(&p, Sys::Mmap, &[0, len, 3, 0x22, u64::MAX, 0]);
    let munmap = |a: i64, len: u64| call(&p, Sys::Munmap, &[a as u64, len]);
    let enomem = -(Errno::ENOMEM.0 as i64);
    // (Page tables made by the first mapping stay.)
    assert_eq!(munmap(mmap(0x8_0000), 0x8_0000), 0);
    let live = frames.live();
    // The area is 1 MiB: far more cumulative mappings than that must work.
    for _ in 0..1000 {
        let a = mmap(0x8_0000);
        assert_eq!(a, 0x100_0000);
        assert_eq!(munmap(a, 0x8_0000), 0);
    }
    assert_eq!(frames.live(), live);

    // First fit, and neighbours merge: free in an order that needs every kind of merge.
    let (a, b, c, d) = (mmap(0x4_0000), mmap(0x4_0000), mmap(0x4_0000), mmap(0x4_0000));
    assert_eq!((a, b, c, d), (0x100_0000, 0x104_0000, 0x108_0000, 0x10c_0000));
    assert_eq!(mmap(0x1000), enomem, "the area is full");
    assert_eq!(munmap(a, 0x4_0000), 0);
    assert_eq!(munmap(c, 0x4_0000), 0);
    assert_eq!(mmap(0x8_0000), enomem, "two separate holes");
    assert_eq!(munmap(b, 0x4_0000), 0);
    assert_eq!(munmap(b, 0x4_0000), 0, "unmapping twice frees nothing more");
    assert_eq!(mmap(0xc_0000), a, "a, b and c merged into one hole");
    assert_eq!(mmap(0x4_0000), enomem, "d is still mapped");
    assert_eq!(munmap(d, 0x4_0000), 0);
    assert_eq!(mmap(0x4_0000), d);

    // A partial unmap frees just that part, in the middle of a mapping.
    assert_eq!(munmap(a + 0x1000, 0x1000), 0);
    assert_eq!(mmap(0x2000), enomem, "one page is free");
    assert_eq!(mmap(0x1000), a + 0x1000);
    // Unmapping outside the area (the break, say) does not add to it.
    assert_eq!(munmap(0x40_0000, 0x1000), 0);
    assert_eq!(mmap(0x1000), enomem);
}

#[test]
fn mmap_limit_caps_mapped_memory() {
    let (p, _) = process("mmap-limit");
    p.set_mmap_limit(0x3000);
    let mmap = |len: u64| call(&p, Sys::Mmap, &[0, len, 3, 0x22, u64::MAX, 0]);
    let a = mmap(0x2000);
    assert_eq!(a, 0x100_0000);
    assert_eq!(mmap(0x2000), -(Errno::ENOMEM.0 as i64), "over the cap");
    let b = mmap(0x1000);
    assert!(b > 0);
    assert_eq!(call(&p, Sys::Munmap, &[a as u64, 0x2000]), 0);
    assert!(mmap(0x2000) > 0, "unmapping makes room");
}

#[test]
fn programs_cannot_load_into_kernel_mappings() {
    let frames = leaked_frames();
    let kernel: &'static mut PageTable<Sv39, &'static HeapFrames> =
        Box::leak(Box::new(PageTable::new(frames).unwrap()));
    let page = frames.alloc_table().unwrap();
    // SAFETY: a fresh host page.
    unsafe { frames.phys_to_virt(page).write_bytes(0x5a, 4096) };
    let va = osmium_mm::addr::VirtAddr::new(0x40_0000);
    kernel.map(va, page, osmium_mm::paging::PageSize::Size4K, MapFlags::RW).unwrap().ignore();
    // SAFETY: the kernel table is leaked. Root entry 0 (the first GiB) is
    // the kernel's, as the program's segments are.
    let s = unsafe { AddressSpace::new(frames, kernel, 0..1) }.unwrap();
    let elf = osmium_boot::elf::Elf::new(program()).unwrap();
    assert_eq!(s.load_elf(&elf), Err(Errno::ENOEXEC));
    // SAFETY: the page is still mapped, and only read here.
    assert!(unsafe { core::slice::from_raw_parts(frames.phys_to_virt(page), 4096) }.iter().all(|&b| b == 0x5a));
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

    // getdents64 on "/": ".", "..", "hello.txt", "etc", "bin".
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
    assert_eq!(names, [".", "..", "hello.txt", "etc", "bin"]);
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

/// An executable file.
struct Bytes(&'static [u8], u64);

impl File for Bytes {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let rest = self.0.get(off as usize..).unwrap_or(&[]);
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(n)
    }
    fn stat(&self) -> Stat {
        Stat { ino: self.1, size: self.0.len() as u64, mode: 0o755, nlink: 1, ..Stat::default() }
    }
}

const ENTRY: u64 = 0x40_0180;

/// A static x86_64 ELF executable: an RX segment loading the first 0x200
/// bytes of the file (headers included) at 0x40_0000, and an RW segment
/// with 2 bytes of data and .bss at 0x40_2000.
fn program() -> &'static [u8] {
    let mut f = alloc::vec![0u8; 0x300];
    f[..4].copy_from_slice(b"\x7fELF");
    f[4] = 2;
    f[5] = 1;
    f[6] = 1;
    f[16..18].copy_from_slice(&2u16.to_le_bytes());
    f[18..20].copy_from_slice(&62u16.to_le_bytes());
    f[24..32].copy_from_slice(&ENTRY.to_le_bytes());
    f[32..40].copy_from_slice(&64u64.to_le_bytes());
    f[52..54].copy_from_slice(&64u16.to_le_bytes());
    f[54..56].copy_from_slice(&56u16.to_le_bytes());
    f[56..58].copy_from_slice(&2u16.to_le_bytes());
    let ph = |f: &mut Vec<u8>, at: usize, flags: u32, off: u64, va: u64, filesz: u64, memsz: u64| {
        f[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        f[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        f[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
        f[at + 16..at + 24].copy_from_slice(&va.to_le_bytes());
        f[at + 32..at + 40].copy_from_slice(&filesz.to_le_bytes());
        f[at + 40..at + 48].copy_from_slice(&memsz.to_le_bytes());
        f[at + 48..at + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    };
    ph(&mut f, 64, 5, 0, 0x40_0000, 0x200, 0x200);
    ph(&mut f, 120, 6, 0x200, 0x40_2000, 2, 0x100);
    f[0x180..0x184].copy_from_slice(&[0x90, 0x90, 0x0f, 0x05]);
    f[0x200..0x202].copy_from_slice(&[0xaa, 0xbb]);
    f.leak()
}

/// Frames for address spaces `execve` creates.
fn exec_frames() -> &'static HeapFrames {
    static F: OnceLock<&'static HeapFrames> = OnceLock::new();
    F.get_or_init(leaked_frames)
}

static ACTIVATED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

const STACK_TOP: u64 = 0x7000_0000;

#[allow(clippy::unreachable)] // test-only: host tests never resume user mode.
fn platform() {
    static P: OnceLock<()> = OnceLock::new();
    P.get_or_init(|| {
        set_platform(Platform {
            new_memory: || Ok(Box::new(space(exec_frames()))),
            activate: |root| ACTIVATED.store(root.0, std::sync::atomic::Ordering::SeqCst),
            resume: |_| unreachable!("host tests never resume user mode"),
            stack_top: STACK_TOP,
            stack_size: 0x4000,
            mmap_area: 0x200_0000..0x210_0000,
        })
    });
}

#[test]
fn fork_copies_memory_and_shares_open_files() {
    platform();
    let (p, frames) = process("parent");
    put(&p, DATA, b"before");
    put(&p, DATA + 0x100, b"/hello.txt\0");
    let fd = call(&p, Sys::Openat, &[-100i64 as u64, DATA + 0x100, 0, 0]) as u64;
    assert_eq!(call(&p, Sys::Read, &[fd, DATA + 0x200, 3]), 3);
    let brk = call(&p, Sys::Brk, &[0x40_2000]) as u64;
    put(&p, 0x40_1000, b"heap");

    let live = frames.live();
    let Outcome::Fork { child, stack: 0 } = dispatch(&p, Sys::Fork.number(), [0; 6]) else { panic!("no fork") };
    let c = Process::find(child).unwrap();
    assert_eq!(frames.live(), live + 4, "pages are shared: only a root, an L1 and two L0 tables are new");
    assert_eq!((c.parent(), p.children()), (Some(p.pid()), alloc::vec![child]));
    assert_eq!(call(&c, Sys::Getppid, &[]), p.pid().0 as i64);
    assert_eq!(c.name(), "parent");

    // Same contents, separate pages.
    assert_eq!(get(&c, DATA, 6), b"before");
    assert_eq!(get(&c, 0x40_1000, 4), b"heap");
    put(&c, DATA, b"child!");
    assert_eq!(frames.live(), live + 4 + 1, "the write copied one page");
    assert_eq!(get(&p, DATA, 6), b"before");
    assert_eq!(call(&c, Sys::Brk, &[0]) as u64, brk);

    // The descriptor shares its offset.
    assert_eq!(call(&c, Sys::Read, &[fd, DATA + 0x200, 3]), 3);
    assert_eq!(call(&p, Sys::Read, &[fd, DATA + 0x200, 100]), 6);
    assert_eq!(get(&p, DATA + 0x200, 6), b" file\n");

    // Threads are not supported; vfork's flags are.
    assert_eq!(call(&p, Sys::Clone, &[0x100 | 17]), -(Errno::EINVAL.0 as i64), "CLONE_VM alone is a thread");
    let Outcome::Fork { child: v, .. } = dispatch(&p, Sys::Clone.number(), [0x4100 | 17, 0, 0, 0, 0, 0]) else {
        panic!("no vfork")
    };

    // Reaping: the children are gone once waited for.
    let wnohang = call(&p, Sys::Wait4, &[-1i64 as u64, DATA + 0x300, 1, 0]);
    assert_eq!(wnohang, 0, "nobody has exited");
    c.set_exited(ExitStatus::Code(7));
    drop(c);
    assert_eq!(call(&p, Sys::Wait4, &[-1i64 as u64, DATA + 0x300, 0, DATA + 0x400]), child.0 as i64);
    assert_eq!(get(&p, DATA + 0x300, 4), 0x700i32.to_ne_bytes());
    assert!(Process::find(child).is_none(), "reaped and freed");
    assert_eq!(frames.live(), live + 4 + 1, "the vfork child's tables, and the page the parent copied from it");
    assert_eq!(call(&p, Sys::Wait4, &[child.0 as u64, 0, 1, 0]), -(Errno::ECHILD.0 as i64), "already reaped");
    Process::find(v).unwrap().set_exited(ExitStatus::Signal(11));
    assert_eq!(call(&p, Sys::Wait4, &[v.0 as u64, DATA + 0x300, 0, 0]), v.0 as i64);
    assert_eq!(get(&p, DATA + 0x300, 4), 11i32.to_ne_bytes());
    assert_eq!(call(&p, Sys::Wait4, &[-1i64 as u64, 0, 0, 0]), -(Errno::ECHILD.0 as i64));
    assert_eq!(frames.live(), live);
}

/// The NUL-terminated string at `va`.
fn cstr(p: &Process, va: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = get(p, va + out.len() as u64, 1)[0];
        if b == 0 {
            return out;
        }
        out.push(b);
    }
}

fn word(p: &Process, va: u64) -> u64 {
    u64::from_ne_bytes(get(p, va, 8).try_into().unwrap())
}

#[test]
fn execve_loads_a_program_with_its_arguments() {
    platform();
    let (p, frames) = process("old");
    // A pointer array: argv = ["prog", "-x"], envp = ["HOME=/"].
    put(&p, DATA, b"/bin/prog\0prog\0-x\0HOME=/\0");
    let argv: Vec<u8> = [DATA + 10, DATA + 15, 0].iter().flat_map(|v| v.to_ne_bytes()).collect();
    let envp: Vec<u8> = [DATA + 18, 0].iter().flat_map(|v| v.to_ne_bytes()).collect();
    put(&p, DATA + 0x100, &argv);
    put(&p, DATA + 0x200, &envp);
    put(&p, DATA + 0x300, b"/hello.txt\0");
    let kept = call(&p, Sys::Openat, &[-100i64 as u64, DATA + 0x300, 0, 0]) as u64;
    let closed = call(&p, Sys::Openat, &[-100i64 as u64, DATA + 0x300, 0o2000000, 0]) as u64;
    assert_eq!(call(&p, Sys::Fcntl, &[closed, 1, 0]), 1, "FD_CLOEXEC");

    // Failures leave the process as it was.
    put(&p, DATA + 0x400, b"/hello.txt\0/missing\0");
    assert_eq!(call(&p, Sys::Execve, &[DATA + 0x400, 0, 0]), -(Errno::EACCES.0 as i64), "not executable");
    assert_eq!(call(&p, Sys::Execve, &[DATA + 0x40b, 0, 0]), -(Errno::ENOENT.0 as i64));
    assert_eq!(get(&p, DATA + 10, 4), b"prog");

    let Outcome::Exec { pc, sp } = dispatch(&p, Sys::Execve.number(), [DATA, DATA + 0x100, DATA + 0x200, 0, 0, 0])
    else {
        panic!("no exec")
    };
    assert_eq!(pc, ENTRY);
    assert_eq!(ACTIVATED.load(std::sync::atomic::Ordering::SeqCst), p.root().0);
    assert_eq!(frames.live(), 1, "the old space is freed; its kernel root was leaked");
    assert_eq!(p.name(), "prog");
    assert_eq!(get(&p, ENTRY, 4), [0x90, 0x90, 0x0f, 0x05]);
    assert_eq!(get(&p, 0x40_2000, 3), [0xaa, 0xbb, 0], "data, then .bss");
    assert_eq!(call(&p, Sys::Brk, &[0]), 0x40_3000);
    assert!(p.memory().read(DATA, &mut [0]).is_err(), "the old program's memory is gone");

    // The initial stack.
    assert!(sp.is_multiple_of(16) && sp < STACK_TOP);
    assert_eq!(word(&p, sp), 2, "argc");
    assert_eq!(cstr(&p, word(&p, sp + 8)), b"prog");
    assert_eq!(cstr(&p, word(&p, sp + 16)), b"-x");
    assert_eq!(word(&p, sp + 24), 0);
    assert_eq!(cstr(&p, word(&p, sp + 32)), b"HOME=/");
    assert_eq!(word(&p, sp + 40), 0);
    let mut aux = std::collections::BTreeMap::new();
    let mut at = sp + 48;
    loop {
        let (k, v) = (word(&p, at), word(&p, at + 8));
        if k == 0 {
            break;
        }
        aux.insert(k, v);
        at += 16;
    }
    assert_eq!((aux[&3], aux[&4], aux[&5], aux[&6], aux[&9]), (0x40_0040, 56, 2, 4096, ENTRY));
    assert_eq!(get(&p, aux[&3], 4), 1u32.to_le_bytes(), "AT_PHDR points at the first program header");
    get(&p, aux[&25], 16);
    assert!(aux.contains_key(&16), "AT_HWCAP");

    // Descriptors survive unless close-on-exec.
    assert_eq!(call(&p, Sys::Read, &[kept, sp, 0]), 0);
    assert_eq!(call(&p, Sys::Read, &[closed, sp, 0]), -(Errno::EBADF.0 as i64));
    assert_eq!(call(&p, Sys::Mmap, &[0, 0x1000, 3, 0x22, u64::MAX, 0]), 0x200_0000, "the platform's mmap area");
}

#[test]
fn dup_and_fcntl() {
    let (p, _) = process("dup");
    assert_eq!(call(&p, Sys::Dup, &[1]), 3);
    assert_eq!(call(&p, Sys::Dup2, &[1, 9]), 9);
    assert_eq!(call(&p, Sys::Dup2, &[9, 9]), 9);
    assert_eq!(call(&p, Sys::Dup3, &[9, 9, 0]), -(Errno::EINVAL.0 as i64));
    assert_eq!(call(&p, Sys::Dup3, &[1, 5, 0o2000000]), 5);
    assert_eq!(call(&p, Sys::Fcntl, &[5, 1, 0]), 1);
    assert_eq!(call(&p, Sys::Fcntl, &[5, 2, 0]), 0);
    assert_eq!(call(&p, Sys::Fcntl, &[5, 1, 0]), 0);
    assert_eq!(call(&p, Sys::Fcntl, &[1, 0, 7]), 7, "F_DUPFD from 7");
    assert_eq!(call(&p, Sys::Fcntl, &[1, 1030, 0]), 4, "F_DUPFD_CLOEXEC");
    assert_eq!(call(&p, Sys::Fcntl, &[4, 1, 0]), 1);
    assert_eq!(call(&p, Sys::Fcntl, &[1, 3, 0]), 2, "O_RDWR");
    assert_eq!(call(&p, Sys::Dup, &[42]), -(Errno::EBADF.0 as i64));
    assert_eq!(p.files().lock().len(), 3 + 5);
}

fn fork_child(p: &Arc<Process>) -> Arc<Process> {
    platform();
    let Outcome::Fork { child, .. } = dispatch(p, Sys::Fork.number(), [0; 6]) else { panic!("no fork") };
    Process::find(child).unwrap()
}

#[test]
fn write_faults_copy_shared_pages_and_reclaim_unshared_ones() {
    let (p, frames) = process("cow");
    p.memory().map_anon(0x20_0000, 0x1000, MapFlags::READ).unwrap();
    put(&p, DATA, b"parent");
    let live = frames.live();
    let c = fork_child(&p);
    let forked = frames.live();
    assert_eq!(forked, live + 4, "no page was copied");

    // Only a write to a copy-on-write page is resolved.
    assert!(!p.handle_page_fault(DATA, false), "reads do not fault");
    assert!(!p.handle_page_fault(0x20_0000, true), "read-only pages stay so");
    assert!(!p.handle_page_fault(0x30_0000, true), "unmapped");
    assert!(p.handle_page_fault(DATA + 0x10, true));
    assert_eq!(frames.live(), forked + 1, "the parent got a copy");
    assert!(!p.handle_page_fault(DATA, true), "and now it is writable");
    assert!(c.handle_page_fault(DATA, true));
    assert_eq!(frames.live(), forked + 1, "the child was the last sharer: it reclaims the page");
    assert!(!c.handle_page_fault(DATA, true));

    // Each side has its own page now.
    put(&c, DATA, b"child ");
    assert_eq!(get(&p, DATA, 6), b"parent");
    assert_eq!(get(&c, DATA, 6), b"child ");
    // Untouched pages are still shared.
    assert_eq!(get(&c, DATA + 0x1000, 4), [0; 4]);
    assert_eq!(frames.live(), forked + 1);
}

#[test]
fn kernel_copies_to_shared_pages_copy_them_first() {
    let (p, frames) = process("cow-sys");
    put(&p, DATA, b"/hello.txt\0");
    let fd = call(&p, Sys::Openat, &[-100i64 as u64, DATA, 0, 0]) as u64;
    let live = frames.live();
    let c = fork_child(&p);
    // read(2) into a shared page, in the child, then in the parent.
    assert_eq!(call(&c, Sys::Read, &[fd, DATA + 0x800, 4]), 4);
    assert_eq!(frames.live(), live + 3 + 1, "the child copied the page");
    assert_eq!(get(&p, DATA + 0x800, 4), [0; 4], "the parent's page is untouched");
    assert_eq!(call(&p, Sys::Read, &[fd, DATA + 0x800, 4]), 4);
    assert_eq!(frames.live(), live + 3 + 1, "the parent reclaimed its page");
    assert_eq!(get(&c, DATA + 0x800, 4), b"hell");
    // A write that spans two shared pages copies both.
    let g = fork_child(&c);
    let before = frames.live();
    put(&g, DATA + 0xffe, b"abcd");
    assert_eq!(frames.live(), before + 2);
    assert_eq!(get(&c, DATA + 0xffe, 4), [0; 4]);
    assert_eq!(get(&g, DATA + 0xffe, 4), b"abcd");
}

#[test]
fn shared_pages_are_freed_with_the_last_owner_in_any_order() {
    for order in [[0, 1, 2], [2, 1, 0], [1, 0, 2], [1, 2, 0]] {
        let (p, frames) = process("cow-exit");
        put(&p, DATA, b"x");
        put(&p, DATA + 0x2000, b"y");
        let c = fork_child(&p);
        let g = fork_child(&c);
        put(&g, DATA, b"g");
        assert!(c.handle_page_fault(DATA + 0x2000, true));
        let mut procs = [Some(p), Some(c), Some(g)];
        for i in order {
            drop(procs[i].take());
            // The survivors still read and write all their pages.
            for q in procs.iter().flatten() {
                put(q, DATA + 0x2000, b"z");
                put(q, DATA + 0x3000, b"w");
                assert_eq!(get(q, DATA + 0x2000, 1), b"z");
            }
        }
        assert_eq!(frames.live(), 1, "only the kernel table is left: {order:?}");
    }
}

#[test]
fn unmapping_and_remapping_forgets_copy_on_write() {
    let (p, frames) = process("cow-unmap");
    let c = fork_child(&p);
    let live = frames.live();
    p.memory().unmap(DATA, 0x1000);
    assert_eq!(frames.live(), live, "the child still holds the page");
    p.memory().map_anon(DATA, 0x1000, MapFlags::RW).unwrap();
    assert_eq!(frames.live(), live + 1);
    assert!(!p.handle_page_fault(DATA, true), "a fresh page is not copy-on-write");
    put(&p, DATA, b"new");
    assert_eq!(get(&c, DATA, 3), [0; 3]);
    drop((p, c));
    assert_eq!(frames.live(), 1);
}
#[test]
fn iovec_arithmetic_is_checked() {
    let (p, _) = process("iov-overflow");
    let efault = -(Errno::EFAULT.0 as i64);
    let einval = -(Errno::EINVAL.0 as i64);
    // The array itself wraps past the top of the address space.
    assert_eq!(call(&p, Sys::Readv, &[0, u64::MAX - 7, 2]), efault);
    assert_eq!(call(&p, Sys::Writev, &[1, u64::MAX - 7, 2]), efault);
    // Lengths that add up to more than a signed size.
    let iov: Vec<u8> = [DATA, u64::MAX / 2, DATA, u64::MAX / 2].iter().flat_map(|v| v.to_ne_bytes()).collect();
    put(&p, DATA + 0x300, &iov);
    assert_eq!(call(&p, Sys::Readv, &[0, DATA + 0x300, 2]), einval);
    assert_eq!(call(&p, Sys::Writev, &[1, DATA + 0x300, 2]), einval);
    // A buffer that wraps.
    assert_eq!(call(&p, Sys::Write, &[1, u64::MAX - 3, 8]), efault);
    assert_eq!(call(&p, Sys::Read, &[0, u64::MAX - 3, 8]), efault);
}

#[test]
fn a_child_that_never_got_a_task_can_be_forgotten() {
    let (p, _) = process("forget");
    let child = p.fork().unwrap();
    assert_eq!(p.children(), [child.pid()]);
    p.forget_child(child.pid());
    assert!(p.children().is_empty(), "wait4 no longer waits for it");
    assert_eq!(call(&p, Sys::Wait4, &[u64::MAX, 0, 1, 0]), -(Errno::ECHILD.0 as i64));
}

mod blocked;
mod hostile;
mod oom;
mod sigthread;
mod smp;
