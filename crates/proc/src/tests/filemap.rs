#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! File-backed `mmap`: demand paging, private copies, shared write-back
//! through `msync` and `munmap`, `mprotect`, and hostile arguments.

use super::*;
use crate::failing::every_failure;
use crate::fd::Access;
use core::sync::atomic::Ordering;

const P: u64 = 0x1000;
const MAP_SHARED: u64 = 1;
const MAP_PRIVATE: u64 = 2;
const MAP_ANON: u64 = 0x20;
const READ: u64 = 1;
const RW: u64 = 3;
const MS_SYNC: u64 = 4;

fn err(e: Errno) -> i64 {
    -(e.0 as i64)
}

/// A regular file in memory that counts the writes it gets.
#[derive(Default)]
struct MemFile {
    data: StdMutex<Vec<u8>>,
    writes: core::sync::atomic::AtomicUsize,
    syncs: core::sync::atomic::AtomicUsize,
}

impl MemFile {
    fn new(data: Vec<u8>) -> Arc<Self> {
        Arc::new(Self { data: StdMutex::new(data), ..Self::default() })
    }
    fn bytes(&self) -> Vec<u8> {
        self.data.lock().unwrap().clone()
    }
    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }
}

impl File for MemFile {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let d = self.data.lock().unwrap();
        let rest = d.get(off as usize..).unwrap_or(&[]);
        let n = rest.len().min(buf.len());
        buf[..n].copy_from_slice(&rest[..n]);
        Ok(n)
    }
    fn write(&self, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        let mut d = self.data.lock().unwrap();
        let end = off as usize + buf.len();
        if d.len() < end {
            d.resize(end, 0);
        }
        d[off as usize..end].copy_from_slice(buf);
        Ok(buf.len())
    }
    fn sync(&self) -> Result<(), Errno> {
        self.syncs.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn stat(&self) -> Stat {
        Stat { ino: 77, size: self.data.lock().unwrap().len() as u64, mode: 0o644, nlink: 1, ..Stat::default() }
    }
}

/// Page `i` of the file is filled with the byte `b'a' + i`; the last has `tail` bytes.
fn pages(n: usize, tail: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for i in 0..n {
        v.extend(core::iter::repeat_n(b'a' + i as u8, if i + 1 == n { tail } else { P as usize }));
    }
    v
}

fn open(p: &Process, f: &Arc<MemFile>, access: Access) -> u64 {
    p.files().lock().insert(OpenFile::new(f.clone(), access)).unwrap() as u64
}

const RO: Access = Access { read: true, write: false, append: false };

fn mmap(p: &Process, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    call(p, Sys::Mmap, &[0, len, prot, flags, fd, off])
}

/// Makes the page tables the `mmap` area needs, which stay once made.
fn warm(p: &Process) {
    let a = mmap(p, P, RW, MAP_PRIVATE | MAP_ANON, u64::MAX, 0) as u64;
    put(p, a, b"w");
    assert_eq!(call(p, Sys::Munmap, &[a, P]), 0);
}

fn remap(p: &Process, f: &Arc<MemFile>, va: u64, off: u64) {
    let map = crate::FileMapping { file: f.clone(), offset: off, shared: true, prot: MapFlags::RW, writable: true };
    p.memory().map_file(va, P, map).unwrap();
}

#[test]
fn private_mappings_load_on_touch_and_never_write_back() {
    let (p, frames) = process("private");
    warm(&p);
    let f = MemFile::new(pages(3, 100));
    let fd = open(&p, &f, Access::RW);
    let live = frames.live();
    let a = mmap(&p, 3 * P, RW, MAP_PRIVATE, fd, 0);
    assert!(a > 0, "{a}");
    let a = a as u64;
    assert_eq!(frames.live(), live, "nothing is read yet");
    // Touching page 1 loads only it.
    assert_eq!(get(&p, a + P + 5, 3), b"bbb");
    assert_eq!(frames.live(), live + 1);
    // The tail of the last page past the end of the file is zero.
    assert_eq!(get(&p, a + 2 * P + 98, 4), [b'c', b'c', 0, 0]);
    // A store changes the copy only.
    put(&p, a + P, b"XY");
    assert_eq!(get(&p, a + P, 4), b"XYbb");
    assert!(p.handle_page_fault(a, true), "a store to an unloaded page loads it");
    assert_eq!(get(&p, a, 2), b"aa");
    assert!(!p.handle_page_fault(a, true), "now it is a plain page: nothing more to do");
    assert_eq!(call(&p, Sys::Msync, &[a, 3 * P, MS_SYNC]), 0);
    assert_eq!(call(&p, Sys::Munmap, &[a, 3 * P]), 0);
    assert_eq!(f.writes(), 0);
    assert_eq!(f.bytes(), pages(3, 100));
    assert_eq!(frames.live(), live, "every loaded page is freed");
}

#[test]
fn pages_past_the_end_of_the_file_fault() {
    let (p, _) = process("eof");
    let f = MemFile::new(pages(1, 10));
    let fd = open(&p, &f, RO);
    let a = mmap(&p, 3 * P, READ, MAP_PRIVATE, fd, 0) as u64;
    assert_eq!(get(&p, a, 1), b"a");
    assert!(!p.handle_page_fault(a + P, false));
    assert!(p.memory().read(a + P, &mut [0]).is_err());
    // An offset into the file shifts what is seen.
    let g = MemFile::new(pages(3, P as usize));
    let fd = open(&p, &g, RO);
    let b = mmap(&p, P, READ, MAP_PRIVATE, fd, 2 * P) as u64;
    assert_eq!(get(&p, b, 1), b"c");
}

#[test]
fn shared_mappings_write_back_on_msync_and_munmap() {
    let (p, _) = process("shared");
    let f = MemFile::new(pages(3, 100));
    let fd = open(&p, &f, Access::RW);
    let a = mmap(&p, 3 * P, RW, MAP_SHARED, fd, 0) as u64;
    // Reading does not dirty anything.
    assert_eq!(get(&p, a, 2), b"aa");
    assert_eq!(call(&p, Sys::Msync, &[a, 3 * P, MS_SYNC]), 0);
    assert_eq!(f.writes(), 0, "clean pages are not written");
    // A store through the fault path.
    assert!(p.handle_page_fault(a, true));
    put(&p, a + 1, b"ZZ");
    assert_eq!(f.bytes()[..4], *b"aaaa", "not yet");
    assert_eq!(call(&p, Sys::Msync, &[a, 3 * P, MS_SYNC]), 0);
    assert_eq!(f.bytes()[..5], *b"aZZaa");
    assert_eq!(f.writes(), 1);
    assert_eq!(f.syncs.load(Ordering::SeqCst), 2, "one for each SYNC so far");
    // The page is clean again: syncing writes nothing, and a new store is noticed.
    assert_eq!(call(&p, Sys::Msync, &[a, 3 * P, MS_SYNC]), 0);
    assert_eq!(f.writes(), 1);
    put(&p, a + 4, b"Q");
    // Past the end of the file within the last page: never written, never extends it.
    put(&p, a + 2 * P + 99, b"1");
    put(&p, a + 2 * P + 100, b"2");
    assert_eq!(call(&p, Sys::Munmap, &[a, 3 * P]), 0);
    let bytes = f.bytes();
    assert_eq!(bytes[4], b'Q');
    assert_eq!(bytes.len(), 2 * P as usize + 100, "the file did not grow");
    assert_eq!(bytes[2 * P as usize + 99], b'1');
    // Mapped again, the file's contents show.
    let b = mmap(&p, P, READ, MAP_SHARED, fd, 0) as u64;
    assert_eq!(get(&p, b, 6), b"aZZaQa");
}

#[test]
fn msync_flags_and_ranges_are_checked() {
    let (p, _) = process("msync");
    let f = MemFile::new(pages(1, 10));
    let fd = open(&p, &f, Access::RW);
    let a = mmap(&p, P, RW, MAP_SHARED, fd, 0) as u64;
    assert_eq!(call(&p, Sys::Msync, &[a, P, 1 | 4]), err(Errno::EINVAL), "ASYNC and SYNC");
    assert_eq!(call(&p, Sys::Msync, &[a, P, 8]), err(Errno::EINVAL));
    assert_eq!(call(&p, Sys::Msync, &[a + 1, P, 4]), err(Errno::EINVAL));
    assert_eq!(call(&p, Sys::Msync, &[0x7000_0000, P, 4]), err(Errno::ENOMEM));
    assert_eq!(call(&p, Sys::Msync, &[a, u64::MAX, 4]), err(Errno::ENOMEM), "length rounds past 2^64");
    assert_eq!(call(&p, Sys::Msync, &[a, P, 1]), 0);
}

#[test]
fn shared_pages_stay_shared_across_fork_and_private_ones_copy() {
    let (p, _) = process("fork");
    let f = MemFile::new(pages(2, P as usize));
    let fd = open(&p, &f, Access::RW);
    let sh = mmap(&p, P, RW, MAP_SHARED, fd, 0) as u64;
    let pr = mmap(&p, P, RW, MAP_PRIVATE, fd, P) as u64;
    put(&p, sh, b"1");
    put(&p, pr, b"1");
    let child = p.memory().fork().unwrap();
    child.write(sh, b"2").unwrap();
    child.write(pr, b"2").unwrap();
    assert_eq!(get(&p, sh, 1), b"2", "a shared page is one page");
    assert_eq!(get(&p, pr, 1), b"1", "a private page was copied");
    // The child's untouched pages come from the file too.
    let mut b = [0];
    child.read(sh + 1, &mut b).unwrap();
    assert_eq!(b, *b"a");
    // Either side's stores reach the file.
    assert_eq!(call(&p, Sys::Msync, &[sh, P, MS_SYNC]), 0);
    assert_eq!(f.bytes()[0], b'2');
    child.msync(sh, P, true).unwrap();
    drop(child);
}

#[test]
fn file_arguments_are_validated() {
    let (p, _) = process("args");
    let f = MemFile::new(pages(2, P as usize));
    let rw = open(&p, &f, Access::RW);
    let ro = open(&p, &f, RO);
    let wo = open(&p, &f, Access { read: false, write: true, append: false });
    let ap = open(&p, &f, Access { read: true, write: true, append: true });
    assert_eq!(mmap(&p, P, RW, MAP_PRIVATE, rw, 1), err(Errno::EINVAL), "unaligned offset");
    assert_eq!(mmap(&p, 0, RW, MAP_PRIVATE, rw, 0), err(Errno::EINVAL), "empty");
    assert_eq!(mmap(&p, u64::MAX, RW, MAP_PRIVATE, rw, 0), err(Errno::EINVAL), "length rounds past 2^64");
    assert_eq!(mmap(&p, P, RW, MAP_PRIVATE, rw, u64::MAX - 0xfff), err(Errno::EOVERFLOW), "offset + length");
    assert_eq!(mmap(&p, 2 * P, RW, MAP_PRIVATE, rw, (i64::MAX as u64 + 1) - P), err(Errno::EOVERFLOW));
    assert_eq!(mmap(&p, P, RW, MAP_PRIVATE | MAP_SHARED, rw, 0), err(Errno::EINVAL), "both");
    assert_eq!(mmap(&p, P, RW, 0, rw, 0), err(Errno::EINVAL), "neither");
    assert_eq!(mmap(&p, P, RW, MAP_PRIVATE | 0x10, rw, 0), err(Errno::EINVAL), "MAP_FIXED");
    assert_eq!(mmap(&p, P, 8, MAP_PRIVATE, rw, 0), err(Errno::EINVAL), "unknown protection");
    assert_eq!(mmap(&p, P, RW, MAP_SHARED | MAP_ANON, u64::MAX, 0), err(Errno::EINVAL), "shared anonymous");
    assert_eq!(mmap(&p, P, RW, MAP_PRIVATE, 99, 0), err(Errno::EBADF));
    assert_eq!(mmap(&p, P, READ, MAP_PRIVATE, wo, 0), err(Errno::EACCES), "not open for reading");
    assert_eq!(mmap(&p, P, RW, MAP_SHARED, ro, 0), err(Errno::EACCES), "shared and writable needs write access");
    assert_eq!(mmap(&p, P, RW, MAP_SHARED, ap, 0), err(Errno::EACCES), "append-only");
    // The failed calls left the area alone: the first success gets its start.
    assert_eq!(mmap(&p, P, READ, MAP_SHARED, ro, 0), 0x100_0000);
    assert!(mmap(&p, P, RW, MAP_PRIVATE, ro, 0) > 0, "private copies need no write access");
    // A directory cannot be mapped.
    let dir = p.files().lock().insert(OpenFile::new(Arc::new(Dir(Vec::new())), RO)).unwrap() as u64;
    assert_eq!(mmap(&p, P, READ, MAP_PRIVATE, dir, 0), err(Errno::ENODEV));
}

#[test]
fn mprotect_changes_loaded_and_unloaded_pages() {
    let (p, _) = process("mprotect");
    let f = MemFile::new(pages(3, P as usize));
    let fd = open(&p, &f, Access::RW);
    let a = mmap(&p, 3 * P, RW, MAP_PRIVATE, fd, 0) as u64;
    put(&p, a, b"x");
    put(&p, a + P, b"x");
    // Page 1 alone becomes read-only; the mapping splits in three.
    assert_eq!(call(&p, Sys::Mprotect, &[a + P, P, READ]), 0);
    assert!(p.memory().write(a + P, b"y").is_err());
    assert!(!p.handle_page_fault(a + P, true));
    assert_eq!(get(&p, a + P, 1), b"x");
    put(&p, a, b"y");
    // Page 2 was never loaded: it loads read-only.
    assert_eq!(call(&p, Sys::Mprotect, &[a + 2 * P, P, READ]), 0);
    assert_eq!(get(&p, a + 2 * P, 1), b"c");
    assert!(p.memory().write(a + 2 * P, b"y").is_err());
    assert_eq!(call(&p, Sys::Mprotect, &[a, 3 * P, RW]), 0);
    put(&p, a + 2 * P, b"z");
    assert_eq!(get(&p, a + 2 * P, 1), b"z");
    // Execute only is accepted too, and holes and bad arguments are not.
    assert_eq!(call(&p, Sys::Mprotect, &[a, 3 * P, 4]), 0);
    assert_eq!(call(&p, Sys::Mprotect, &[a + 1, P, READ]), err(Errno::EINVAL));
    assert_eq!(call(&p, Sys::Mprotect, &[a, P, 16]), err(Errno::EINVAL));
    assert_eq!(call(&p, Sys::Mprotect, &[0x7000_0000, P, READ]), err(Errno::ENOMEM));
    assert_eq!(call(&p, Sys::Mprotect, &[a, u64::MAX, READ]), err(Errno::ENOMEM));
    assert_eq!(call(&p, Sys::Mprotect, &[a, 0, READ]), 0);
    assert_eq!(f.bytes(), pages(3, P as usize), "private stores never reach the file");
}

#[test]
fn mprotect_cannot_grant_write_to_a_shared_mapping_of_a_read_only_file() {
    let (p, _) = process("mprotect-ro");
    let f = MemFile::new(pages(2, P as usize));
    let fd = open(&p, &f, RO);
    let a = mmap(&p, 2 * P, READ, MAP_SHARED, fd, 0) as u64;
    assert_eq!(call(&p, Sys::Mprotect, &[a, 2 * P, RW]), err(Errno::EACCES));
    assert!(p.memory().write(a, b"x").is_err());
    // Private is another matter.
    let b = mmap(&p, P, READ, MAP_PRIVATE, fd, 0) as u64;
    assert_eq!(call(&p, Sys::Mprotect, &[b, P, RW]), 0);
    put(&p, b, b"x");
    assert_eq!(f.writes(), 0);
}

#[test]
fn mprotect_on_shared_mappings_keeps_dirty_pages_for_write_back() {
    let (p, _) = process("mprotect-shared");
    let f = MemFile::new(pages(2, P as usize));
    let fd = open(&p, &f, Access::RW);
    let a = mmap(&p, 2 * P, RW, MAP_SHARED, fd, 0) as u64;
    put(&p, a, b"D");
    assert_eq!(call(&p, Sys::Mprotect, &[a, 2 * P, READ]), 0);
    assert!(p.memory().write(a, b"E").is_err(), "no longer writable");
    assert_eq!(call(&p, Sys::Msync, &[a, 2 * P, MS_SYNC]), 0);
    assert_eq!(f.bytes()[0], b'D', "what was stored before is still saved");
    // PROT_NONE saves the pages and drops them; the mapping reloads on a later grant.
    assert_eq!(call(&p, Sys::Mprotect, &[a, 2 * P, RW]), 0);
    put(&p, a + 1, b"F");
    assert_eq!(call(&p, Sys::Mprotect, &[a, 2 * P, 0]), 0);
    assert_eq!(f.bytes()[1], b'F');
    assert!(p.memory().read(a, &mut [0]).is_err());
    assert_eq!(call(&p, Sys::Mprotect, &[a, 2 * P, READ]), 0);
    assert_eq!(get(&p, a, 2), b"DF");
}

#[test]
fn no_access_cannot_discard_private_pages() {
    let (p, _) = process("none");
    let f = MemFile::new(pages(1, P as usize));
    let fd = open(&p, &f, Access::RW);
    let a = mmap(&p, P, RW, MAP_PRIVATE, fd, 0) as u64;
    // Not loaded yet: the access can go.
    assert_eq!(call(&p, Sys::Mprotect, &[a, P, 0]), 0);
    assert!(p.memory().read(a, &mut [0]).is_err());
    assert_eq!(call(&p, Sys::Mprotect, &[a, P, RW]), 0);
    put(&p, a, b"mine");
    assert_eq!(call(&p, Sys::Mprotect, &[a, P, 0]), err(Errno::EINVAL), "its data would be lost");
    assert_eq!(get(&p, a, 4), b"mine");
}

#[test]
fn reserved_memory_can_be_made_usable() {
    let (p, frames) = process("reserve");
    warm(&p);
    let live = frames.live();
    let a = mmap(&p, 2 * P, 0, MAP_PRIVATE | MAP_ANON, u64::MAX, 0) as u64;
    assert_eq!(frames.live(), live);
    assert!(p.memory().write(a, b"x").is_err());
    assert_eq!(call(&p, Sys::Mprotect, &[a, 2 * P, RW]), 0);
    assert_eq!(get(&p, a + 5, 2), [0, 0], "zero-filled");
    put(&p, a + P, b"ok");
    assert_eq!(get(&p, a + P, 2), b"ok");
    assert_eq!(call(&p, Sys::Munmap, &[a, 2 * P]), 0);
    assert_eq!(frames.live(), live);
    assert!(p.memory().read(a, &mut [0]).is_err());
}

#[test]
fn munmap_of_part_of_a_mapping_saves_it_and_leaves_the_rest() {
    let (p, frames) = process("munmap");
    warm(&p);
    let f = MemFile::new(pages(4, P as usize));
    let fd = open(&p, &f, Access::RW);
    let live = frames.live();
    let a = mmap(&p, 4 * P, RW, MAP_SHARED, fd, 0) as u64;
    put(&p, a + P, b"1");
    put(&p, a + 2 * P, b"2");
    put(&p, a + 3 * P, b"3");
    // The middle two pages go: their stores are saved, the others are not yet.
    assert_eq!(call(&p, Sys::Munmap, &[a + P, 2 * P]), 0);
    let bytes = f.bytes();
    assert_eq!((bytes[P as usize], bytes[2 * P as usize], bytes[3 * P as usize]), (b'1', b'2', b'd'));
    assert!(p.memory().read(a + P, &mut [0]).is_err());
    assert!(!p.handle_page_fault(a + P, false));
    // The ends are still mapped, and still demand-paged and dirty.
    assert_eq!(get(&p, a, 1), b"a");
    assert_eq!(get(&p, a + 3 * P, 1), b"3");
    assert_eq!(call(&p, Sys::Munmap, &[a, 4 * P]), 0, "the whole range, hole included");
    assert_eq!(f.bytes()[3 * P as usize], b'3');
    assert_eq!(frames.live(), live);
    // The addresses can be used for something else.
    let b = mmap(&p, 4 * P, RW, MAP_PRIVATE | MAP_ANON, u64::MAX, 0) as u64;
    assert_eq!(b, a);
    assert_eq!(get(&p, b + P, 1), [0]);
}

#[test]
fn the_end_of_a_process_writes_shared_mappings_back() {
    let (p, _) = process("exit");
    let f = MemFile::new(pages(1, P as usize));
    let fd = open(&p, &f, Access::RW);
    let a = mmap(&p, P, RW, MAP_SHARED, fd, 0) as u64;
    put(&p, a, b"bye");
    assert_eq!(f.bytes()[..3], *b"aaa");
    p.memory().sync_files().unwrap();
    assert_eq!(f.bytes()[..3], *b"bye");
}

#[test]
fn faulting_and_unmapping_survive_running_out_of_memory() {
    let (p, frames) = process("oom");
    let f = MemFile::new(pages(3, P as usize));
    let fd = open(&p, &f, Access::RW);
    let a = mmap(&p, 3 * P, RW, MAP_SHARED, fd, 0) as u64;
    // Warm the page tables.
    put(&p, a + P, b"w");
    assert_eq!(call(&p, Sys::Munmap, &[a, 3 * P]), 0);
    let a = mmap(&p, 3 * P, RW, MAP_SHARED, fd, 0) as u64;
    let live = frames.live();
    let failures = every_failure(
        || p.handle_page_fault(a + P, true),
        |ok, _| {
            assert_eq!(frames.live(), if ok { live + 1 } else { live }, "a fault loads a page or leaves nothing");
            // Put the page back as it was.
            p.memory().unmap(a + P, P);
            remap(&p, &f, a + P, P);
            assert_eq!(frames.live(), live);
        },
    );
    assert!(failures > 0);
    // Splitting a mapping in `munmap` fails whole or not at all.
    let failures = every_failure(
        || call(&p, Sys::Munmap, &[a + P, P]),
        |r, _| {
            if r == err(Errno::ENOMEM) {
                assert_eq!(get(&p, a + P, 1), b"w", "still mapped, with what was saved");
            } else {
                assert_eq!(r, 0);
                assert!(p.memory().read(a + P, &mut [0]).is_err());
                remap(&p, &f, a + P, P);
            }
        },
    );
    assert!(failures > 0);
}

#[test]
fn mprotect_write_on_a_page_shared_by_fork_copies_it() {
    let (p, _) = process("mprotect-fork-share");
    let f = MemFile::new(pages(1, P as usize));
    let fd = open(&p, &f, Access::RW);
    let a = mmap(&p, P, READ, MAP_PRIVATE, fd, 0) as u64;
    assert_eq!(get(&p, a, 1), b"a");
    let child = p.memory().fork().unwrap();
    child.mprotect(a, P, MapFlags::READ | MapFlags::WRITE).unwrap();
    child.write(a, b"c").unwrap();
    assert_eq!(get(&p, a, 1), b"a", "the parent still sees the original");
    let mut b = [0];
    child.read(a, &mut b).unwrap();
    assert_eq!(b, *b"c");
}

#[test]
fn copy_on_write_does_not_undo_mprotect_read() {
    let (p, _) = process("mprotect-cow-ro");
    // Pages mapped this way belong to no file mapping or lazy area.
    let a = 0x5000_0000;
    p.memory().map_anon(a, P, MapFlags::READ | MapFlags::WRITE).unwrap();
    put(&p, a, b"x");
    let child = p.memory().fork().unwrap();
    child.mprotect(a, P, MapFlags::READ).unwrap();
    assert!(child.write(a, b"y").is_err(), "a kernel copy respects mprotect");
    assert!(!child.page_fault(a, true), "so does a user store");
    child.mprotect(a, P, MapFlags::READ | MapFlags::WRITE).unwrap();
    child.write(a, b"z").unwrap();
    assert_eq!(get(&p, a, 1), b"x");
}
