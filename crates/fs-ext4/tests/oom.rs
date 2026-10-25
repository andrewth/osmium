#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Running out of memory in the middle of an ext2/3/4 call is `ENOMEM`, and
//! leaves a file system `e2fsck` finds clean: no leaked block or inode.
//! Each test fails every allocation of a call in turn on an image made by
//! `mkfs.ext*` (skipped, with a note, if e2fsprogs is missing).

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use osmium_fs::{Errno, FileKind, OpenFlags, Vfs, XattrSet};
use osmium_fs_ext4::Ext2;
use osmium_hal::block::{BlockDevice, BlockError};

#[path = "../../proc/src/failing.rs"]
mod failing;

#[global_allocator]
static ALLOCATOR: failing::Failing = failing::Failing;

use failing::every_failure;

/// A disk in memory that reading and writing allocates nothing from.
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

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("osmium-ext4-oom-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// A fresh image of `mib` MiB made by `mkfs.<kind>`, or `None` if it is not
/// installed.
fn mkfs(kind: &str, mib: usize) -> Option<(PathBuf, MemDisk)> {
    let path = scratch(&format!("{kind}.img"));
    std::fs::write(&path, vec![0u8; mib << 20]).unwrap();
    let status = Command::new(format!("mkfs.{kind}"))
        // A fixed hash seed, so that a directory grows after the same names every time.
        .args(["-q", "-F", "-b", "1024", "-I", "256", "-E", "hash_seed=01234567-89ab-cdef-0123-456789abcdef"])
        .arg(&path)
        .status()
        .ok()?;
    assert!(status.success());
    Some((path.clone(), MemDisk(Arc::new(Mutex::new(std::fs::read(&path).unwrap())))))
}

/// Runs `e2fsck -fn` on what the disk holds.
fn fsck(path: &PathBuf, disk: &MemDisk) -> String {
    std::fs::write(path, &*disk.0.lock().unwrap()).unwrap();
    let out = Command::new("e2fsck").args(["-fn"]).arg(path).output().expect("e2fsck");
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "e2fsck found problems:\n{text}");
    text
}

fn ok_or_enomem<T: std::fmt::Debug>(r: &Result<T, Errno>, injected: bool) -> bool {
    match r {
        Ok(_) => true,
        Err(e) => {
            assert!(injected && *e == Errno::ENOMEM, "{r:?}, injected: {injected}");
            false
        }
    }
}

const RW: OpenFlags = OpenFlags::READ.union(OpenFlags::WRITE);

/// Walks the file system's calls through every allocation failure.
fn run(kind: &str) {
    let Some((path, disk)) = mkfs(kind, 32) else {
        eprintln!("mkfs.{kind} not found; skipping");
        return;
    };
    // Mounting.
    let n = every_failure(
        || Ext2::mount(disk.clone(), 1).map(drop),
        |r, injected| {
            ok_or_enomem(&r, injected);
        },
    );
    assert!(n >= 5, "{kind} mount: {n}");

    let fs = Ext2::mount(disk.clone(), 1).unwrap();
    let vfs = Vfs::new(fs.root().unwrap());

    // Creating a file, a directory and a symbolic link.
    for (what, path_) in [("file", "/f"), ("directory", "/d"), ("symlink", "/s")] {
        let n = every_failure(
            || match what {
                "file" => vfs.open(path_, RW | OpenFlags::CREATE | OpenFlags::EXCL, 0o644).map(drop),
                "directory" => vfs.mkdir(path_, 0o755),
                _ => vfs.symlink("f", path_),
            },
            |r, injected| {
                if ok_or_enomem(&r, injected) {
                    if what == "directory" { vfs.rmdir(path_) } else { vfs.unlink(path_) }.unwrap();
                } else if what == "file" {
                    // `open` creates the file, then needs memory to look at
                    // it: like Linux, it may fail with the file made.
                    let _ = vfs.unlink(path_);
                } else {
                    assert_eq!(vfs.stat(path_, false).unwrap_err(), Errno::ENOENT, "{what} is not there");
                }
            },
        );
        assert!(n >= 3, "{kind} {what}: {n}");
    }

    // Writing, growing, reading back, shrinking.
    let f = vfs.open("/data", RW | OpenFlags::CREATE, 0o644).unwrap();
    let block = (0..5000u32).map(|i| i as u8).collect::<Vec<_>>();
    let n = every_failure(
        || f.write(0, &block),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), 5000);
            }
            f.truncate(0).unwrap();
        },
    );
    assert!(n >= 3, "{kind} write: {n}");
    assert_eq!(f.write(0, &block).unwrap(), 5000);
    let mut buf = vec![0u8; 5000];
    let n = every_failure(
        || f.read(0, &mut buf),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), 5000);
            }
        },
    );
    assert!(n >= 1, "{kind} read: {n}");
    assert_eq!(buf, block);
    let n = every_failure(
        || f.truncate(100),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                f.write(0, &block).unwrap();
            } else {
                assert_eq!(f.stat().size, 5000, "a failed truncate keeps the size");
            }
        },
    );
    assert!(n >= 1, "{kind} truncate: {n}");

    // Looking up, listing, removing.
    vfs.mkdir("/dir", 0o755).unwrap();
    vfs.open("/dir/inner", RW | OpenFlags::CREATE, 0o644).unwrap();
    vfs.symlink("/dir/inner", "/link").unwrap();
    let n = every_failure(
        || vfs.stat("/link", true).map(|s| s.kind),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), FileKind::Regular);
            }
        },
    );
    assert!(n >= 3, "{kind} lookup: {n}");
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
            ok_or_enomem(&r, injected);
        },
    );
    assert!(n >= 2, "{kind} readdir: {n}");
    let n = every_failure(
        || vfs.readlink("/link"),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), "/dir/inner");
            }
        },
    );
    assert!(n >= 1, "{kind} readlink: {n}");
    let n = every_failure(
        || vfs.unlink("/dir/inner"),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                vfs.open("/dir/inner", RW | OpenFlags::CREATE, 0o644).unwrap();
            } else {
                assert!(vfs.stat("/dir/inner", true).is_ok(), "a failed unlink removes nothing");
            }
        },
    );
    assert!(n >= 1, "{kind} unlink: {n}");

    // Extended attributes: in the inode, in a block, and removed again.
    for (what, value) in [("inode", vec![3u8; 30]), ("block", vec![4u8; 300])] {
        let n = every_failure(
            || f.xattr_set(b"user.k", &value, XattrSet::Any),
            |r, injected| {
                if ok_or_enomem(&r, injected) {
                    assert_eq!(f.xattr_get(b"user.k").unwrap(), value);
                    f.xattr_remove(b"user.k").unwrap();
                } else {
                    assert_eq!(f.xattr_get(b"user.k").unwrap_err(), Errno::ENODATA, "a failed set stores nothing");
                }
            },
        );
        assert!(n >= 1, "{kind} xattr {what}: {n}");
    }
    f.xattr_set(b"user.k", &[5u8; 300], XattrSet::Any).unwrap();
    let n = every_failure(
        || f.xattr_remove(b"user.k"),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                f.xattr_set(b"user.k", &[5u8; 300], XattrSet::Any).unwrap();
            } else {
                assert_eq!(f.xattr_get(b"user.k").unwrap(), [5u8; 300], "a failed remove keeps the value");
            }
        },
    );
    assert!(n >= 1, "{kind} xattr remove: {n}");
    let n = every_failure(
        || f.xattr_get(b"user.k"),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), [5u8; 300]);
            }
        },
    );
    assert!(n >= 1, "{kind} xattr get: {n}");
    let n = every_failure(
        || f.xattr_list(),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), [b"user.k".to_vec()]);
            }
        },
    );
    assert!(n >= 1, "{kind} xattr list: {n}");

    // Growing a directory: the creation that gives it an index, the one that
    // splits a leaf, and the one that adds a level to the index. A directory
    // like it is made first to find the creations by the size it jumps to.
    let name = |d: &str, i: usize| format!("/{d}/entry-with-a-longish-name-{i:04}");
    let size = |d: &str| vfs.stat(&format!("/{d}"), true).unwrap().size;
    vfs.mkdir("/probe", 0o755).unwrap();
    let mut growth = Vec::new();
    let mut last = size("probe");
    for i in 0..3000 {
        vfs.mkdir(&name("probe", i), 0o755).unwrap();
        let now = size("probe");
        if now > last {
            growth.push((i, (now - last) / 1024));
            last = now;
        }
    }
    let first = growth.iter().position(|g| g.1 == 1).expect("a leaf split");
    let by = growth.iter().skip(first).find(|g| g.1 == 2).expect("a new index level");
    for (what, brink) in [("index", growth[0].0), ("split", growth[first].0), ("level", by.0)] {
        let d = format!("grow-{what}");
        vfs.mkdir(&format!("/{d}"), 0o755).unwrap();
        for i in 0..brink {
            vfs.mkdir(&name(&d, i), 0o755).unwrap();
        }
        let before = size(&d);
        let path_ = name(&d, brink);
        let n = every_failure(
            || vfs.mkdir(&path_, 0o755),
            |r, injected| {
                if ok_or_enomem(&r, injected) {
                    // (The last failure injected may be one it got through.)
                    if injected {
                        vfs.rmdir(&path_).unwrap();
                    }
                } else {
                    assert_eq!(vfs.stat(&path_, false).unwrap_err(), Errno::ENOENT, "{what} is not there");
                    assert_eq!(size(&d), before, "{what}: a failed creation leaves the directory as it was");
                }
            },
        );
        assert!(n >= 3, "{kind} {what}: {n}");
        assert!(size(&d) > before, "{kind} {what}: the directory did not grow");
        for i in (0..=brink).step_by(5) {
            assert!(vfs.stat(&name(&d, i), true).is_ok(), "{kind} {what}: {i} lost");
        }
    }

    // Unmount cleanly, and the file system must still be consistent.
    drop((f, root, vfs));
    let Ok(_dev) = fs.into_device() else { panic!("a node is still open") };
    fsck(&path, &disk);
}

#[test]
fn ext2_fails_cleanly_and_stays_consistent() {
    run("ext2");
}

#[test]
fn ext4_with_a_journal_fails_cleanly_and_stays_consistent() {
    run("ext4");
}
