#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Running out of memory in the middle of a FAT call is `ENOMEM`, and leaves
//! the volume as it was: no entry, no node, no cluster leaked. Each test
//! fails every allocation of a call in turn.

use std::sync::{Arc, Mutex};

use osmium_fs::{Errno, FileKind, OpenFlags, Vfs};
use osmium_fs_fat::FatFs;
use osmium_hal::block::{BlockDevice, BlockError};

#[path = "../../proc/src/failing.rs"]
mod failing;

#[global_allocator]
static ALLOCATOR: failing::Failing = failing::Failing;

use failing::every_failure;

/// A disk in memory, made once, so reading and writing it allocates nothing.
#[derive(Clone)]
struct MemDisk(Arc<Mutex<Vec<u8>>>);

impl BlockDevice for MemDisk {
    fn block_size(&self) -> usize {
        512
    }
    fn num_blocks(&self) -> u64 {
        (self.0.lock().unwrap().len() / 512) as u64
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let off = lba as usize * 512;
        buf.copy_from_slice(&self.0.lock().unwrap()[off..off + buf.len()]);
        Ok(())
    }
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let off = lba as usize * 512;
        self.0.lock().unwrap()[off..off + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

/// An empty FAT16 volume: one-sector clusters, two FATs of 32 sectors, a
/// 32-sector root directory and 8000 clusters.
fn fat16() -> MemDisk {
    let total = 1 + 64 + 32 + 8000;
    let mut disk = vec![0u8; total * 512];
    disk[11..13].copy_from_slice(&512u16.to_le_bytes());
    disk[13] = 1;
    disk[14..16].copy_from_slice(&1u16.to_le_bytes());
    disk[16] = 2;
    disk[17..19].copy_from_slice(&512u16.to_le_bytes());
    disk[19..21].copy_from_slice(&(total as u16).to_le_bytes());
    disk[21] = 0xf8;
    disk[22..24].copy_from_slice(&32u16.to_le_bytes());
    disk[510..512].copy_from_slice(&[0x55, 0xaa]);
    for copy in 0..2 {
        let at = 512 + copy * 32 * 512;
        disk[at..at + 4].copy_from_slice(&[0xf8, 0xff, 0xff, 0xff]);
    }
    MemDisk(Arc::new(Mutex::new(disk)))
}

const RW: OpenFlags = OpenFlags::READ.union(OpenFlags::WRITE);

fn ok_or_enomem<T: std::fmt::Debug>(r: &Result<T, Errno>, injected: bool) -> bool {
    match r {
        Ok(_) => true,
        Err(e) => {
            assert!(injected && *e == Errno::ENOMEM, "{r:?}, injected: {injected}");
            false
        }
    }
}

#[test]
fn mounting_fails_cleanly() {
    let disk = fat16();
    let n = every_failure(
        || FatFs::mount(disk.clone(), 1).map(drop),
        |r, injected| {
            ok_or_enomem(&r, injected);
        },
    );
    assert!(n >= 2, "{n}");
}

#[test]
fn creating_writing_and_listing_fail_cleanly_and_leak_no_cluster() {
    let fs = FatFs::mount(fat16(), 1).unwrap();
    let vfs = Vfs::new(fs.root());
    let free = || fs.free_bytes().unwrap();
    let start = free();

    // A short name, and a long one that needs long-name entries and a
    // generated short name.
    for (name, kind) in [("/short.txt", FileKind::Regular), ("/A Rather Long File Name.text", FileKind::Regular)] {
        let n = every_failure(
            || vfs.open(name, RW | OpenFlags::CREATE | OpenFlags::EXCL, 0o644).map(drop),
            |r, injected| {
                if ok_or_enomem(&r, injected) {
                    vfs.unlink(name).unwrap();
                } else {
                    assert_eq!(vfs.stat(name, true).unwrap_err(), Errno::ENOENT, "{name} was not created");
                }
                assert_eq!(free(), start, "{name}: no cluster leaked");
            },
        );
        assert!(n >= 3, "{name}: {n}");
        let _ = kind;
    }

    // A directory takes a cluster for `.` and `..` as well.
    let n = every_failure(
        || vfs.mkdir("/dir", 0o755),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                vfs.rmdir("/dir").unwrap();
            } else {
                assert_eq!(vfs.stat("/dir", true).unwrap_err(), Errno::ENOENT);
            }
            assert_eq!(free(), start, "no cluster leaked");
        },
    );
    assert!(n >= 3, "mkdir: {n}");

    // Writing grows the file by clusters.
    let f = vfs.open("/data", RW | OpenFlags::CREATE, 0o644).unwrap();
    let block = vec![0xa5u8; 1500];
    let n = every_failure(
        || f.write(0, &block),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), 1500);
            }
            // Whatever was written, truncating gives it all back.
            f.truncate(0).unwrap();
            assert_eq!(free(), start, "no cluster leaked");
        },
    );
    assert!(n >= 2, "write: {n}");

    // Reading back, and listing.
    f.write(0, &block).unwrap();
    let mut buf = vec![0u8; 1500];
    let n = every_failure(
        || f.read(0, &mut buf),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), 1500);
            }
        },
    );
    assert!(n >= 1, "read: {n}");
    assert!(buf.iter().all(|&b| b == 0xa5));
    vfs.open("/second file with a long name", RW | OpenFlags::CREATE, 0o644).unwrap();
    let root = vfs.lookup("/").unwrap();
    let n = every_failure(
        || {
            let mut seen = 0;
            for i in 0.. {
                match root.readdir(i)? {
                    Some(_) => seen += 1,
                    None => break,
                }
            }
            Ok::<_, Errno>(seen)
        },
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), 2);
            }
        },
    );
    assert!(n >= 2, "readdir: {n}");

    // Removing, with the file open: the clusters go when it is dropped.
    let n = every_failure(
        || vfs.lookup("/second file with a long name").map(drop),
        |r, injected| {
            ok_or_enomem(&r, injected);
        },
    );
    assert!(n >= 2, "lookup: {n}");
}
