#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Balance: block groups emptied into others and their chunks deleted, checked
//! by `btrfs check --check-data-csum`, by reading everything back and, for a
//! crash at every device write, by both. Skipped, with a note, without
//! btrfs-progs.

mod common;

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use common::*;
use osmium_fs::{OpenFlags, Vfs};
use osmium_fs_btrfs::{BalanceFilter, BtrfsFs};

const DATA: u64 = 1;
const METADATA: u64 = 4;

fn groups(fs: &BtrfsFs<Disk>, ty: u64) -> Vec<(u64, u64)> {
    fs.chunks().unwrap().iter().filter(|c| c.flags & 7 == ty).map(|c| (c.logical, c.length)).collect()
}

/// Files that survive, with their contents.
type Kept = Vec<(String, Vec<u8>)>;

/// A volume whose data is spread over several chunks, most of it deleted
/// again: `keep` files survive.
fn fragmented(dir: &Path, args: &[&str]) -> Option<(PathBuf, Kept)> {
    let img = mkfs(dir, 128 << 20, args)?;
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    let mut keep = Vec::new();
    for i in 0..48 {
        let data = distinct(900_000 + i * 1000, i as u32);
        put(&vfs, &format!("/f{i}"), &data);
        if i % 6 == 0 {
            keep.push((format!("/f{i}"), data));
        }
    }
    // Split extents: one extent two file extents refer to, the second twice.
    let f = vfs.open("/f0", OpenFlags::WRITE, 0).unwrap();
    let patch = distinct(40_000, 1234);
    f.write(300_000, &patch).unwrap();
    keep[0].1[300_000..340_000].copy_from_slice(&patch);
    vfs.mkdir("/small", 0o755).unwrap();
    for i in 0..60 {
        put(&vfs, &format!("/small/s{i}"), &pattern(300 + i * 77, i as u8));
    }
    for i in 0..48 {
        if i % 6 != 0 {
            vfs.unlink(&format!("/f{i}")).unwrap();
        }
    }
    drop(vfs);
    Some((img, keep))
}

fn verify(img: &Path, keep: &[(String, Vec<u8>)]) {
    let fs = mount(img);
    let vfs = Vfs::new(fs.root());
    for (name, data) in keep {
        assert!(cat(&vfs, name) == *data, "{name} differs");
    }
    for i in 0..60 {
        assert_eq!(cat(&vfs, &format!("/small/s{i}")), pattern(300 + i * 77, i as u8));
    }
    let rep = fs.scrub(false).unwrap();
    assert!(rep.is_clean(), "{rep:?}");
}

#[test]
fn compacts_sparse_data_chunks() {
    let dir = scratch("bal-compact");
    let Some((img, keep)) = fragmented(&dir, &[]) else { return };
    check(&img);
    let fs = mount(&img);
    let before = groups(&fs, DATA);
    assert!(before.len() >= 3, "{before:?}");
    let used_before = fs.chunks().unwrap().len();

    // Nothing is below 1 percent full: nothing moves.
    let rep = fs.balance(&BalanceFilter { usage_below: Some(0), metadata: false, ..Default::default() }).unwrap();
    assert_eq!((rep.relocated, rep.bytes_moved), (0, 0), "{rep:?}");

    let rep = fs.balance(&BalanceFilter { usage_below: Some(60), metadata: false, ..Default::default() }).unwrap();
    assert!(rep.relocated > 0 && rep.freed > 0 && rep.skipped.is_empty(), "{rep:?}");
    let after = groups(&fs, DATA);
    assert!(after.len() < before.len(), "{before:?} -> {after:?}");
    assert!(fs.chunks().unwrap().len() < used_before);
    drop(fs);
    check(&img);
    verify(&img, &keep);
}

#[test]
fn moves_everything() {
    let dir = scratch("bal-all");
    let Some((img, keep)) = fragmented(&dir, &["-n", "4096"]) else { return };
    let fs = mount(&img);
    let before = fs.chunks().unwrap();
    let rep = fs.balance(&BalanceFilter::default()).unwrap();
    assert!(rep.relocated >= 2 && rep.skipped.is_empty() && rep.busy.is_empty(), "{rep:?}");
    let after = fs.chunks().unwrap();
    // Every data and metadata chunk is a new one, at new addresses.
    for c in after.iter().filter(|c| c.flags & 2 == 0) {
        assert!(before.iter().all(|b| b.logical != c.logical), "{c:?} is old");
    }
    // The system chunk stays.
    assert!(after.iter().any(|c| c.flags & 2 != 0));
    // Still usable: write more.
    {
        let vfs = Vfs::new(fs.root());
        put(&vfs, "/after", &distinct(3 << 20, 99));
    }
    drop(fs);
    check(&img);
    verify(&img, &keep);
    assert_eq!(cat(&Vfs::new(mount(&img).root()), "/after"), distinct(3 << 20, 99));
}

#[test]
fn moves_metadata() {
    let dir = scratch("bal-meta");
    let Some(img) = mkfs(&dir, 128 << 20, &["-n", "4096"]) else { return };
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    for d in 0..10 {
        vfs.mkdir(&format!("/d{d}"), 0o755).unwrap();
        for i in 0..80 {
            put(&vfs, &format!("/d{d}/file-with-a-longish-name-{i}"), &pattern(i * 40, i as u8));
        }
    }
    let before = groups(&fs, METADATA);
    let rep = fs.balance(&BalanceFilter { data: false, ..Default::default() }).unwrap();
    assert!(rep.relocated > 0 && rep.skipped.is_empty(), "{rep:?}");
    let after = groups(&fs, METADATA);
    assert!(after.iter().all(|a| before.iter().all(|b| b.0 != a.0)), "{before:?} -> {after:?}");
    for d in 0..10 {
        for i in 0..80 {
            assert_eq!(cat(&vfs, &format!("/d{d}/file-with-a-longish-name-{i}")), pattern(i * 40, i as u8));
        }
    }
    drop(vfs);
    drop(fs);
    check(&img);
}

/// An image made by `mkfs.btrfs --rootdir` with compressed, sparse and
/// preallocated-looking files, a symlink and a subvolume.
#[test]
fn moves_what_mkfs_made() {
    let dir = scratch("bal-rootdir");
    let (Some(mkfs), Some(_)) = (tool("mkfs.btrfs"), tool("btrfs")) else { return };
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("vol")).unwrap();
    std::fs::write(src.join("text"), "compress me, please ".repeat(30_000)).unwrap();
    std::fs::write(src.join("vol/v"), distinct(200_000, 5)).unwrap();
    std::fs::write(src.join("plain"), distinct(1_000_000, 6)).unwrap();
    let sparse = std::fs::File::create(src.join("sparse")).unwrap();
    sparse.set_len(5 << 20).unwrap();
    std::os::unix::fs::FileExt::write_all_at(&sparse, b"tail", (5 << 20) - 4).unwrap();
    symlink("plain", src.join("l")).unwrap();
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
    let out = Command::new(mkfs)
        .args(["-q", "-u", "vol", "--compress", "zstd", "--rootdir"])
        .arg(&src)
        .arg(&img)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    check(&img);
    let want = snapshot(&img);
    let fs = BtrfsFs::mount(Disk::open(&img), 1).unwrap();
    assert!(!fs.is_read_only());
    let rep = fs.balance(&BalanceFilter::default()).unwrap();
    // Subvolume trees written by mkfs have no snapshot sharing: all can move.
    assert!(rep.relocated > 0, "{rep:?}");
    assert!(rep.skipped.is_empty(), "{rep:?}");
    drop(fs);
    check(&img);
    assert!(snapshot(&img) == want);
}

/// A crash at every device write of a balance leaves the volume as it was.
#[test]
fn crash_at_every_write() {
    let dir = scratch("bal-crash");
    let Some(img) = mkfs(&dir, 128 << 20, &["-n", "4096"]) else { return };
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        for i in 0..12 {
            put(&vfs, &format!("/f{i}"), &distinct(300_000, i));
        }
        for i in 0..12 {
            if i % 3 != 0 {
                vfs.unlink(&format!("/f{i}")).unwrap();
            }
        }
        // Split extents, too.
        vfs.open("/f0", osmium_fs::OpenFlags::WRITE, 0).unwrap().write(100_000, &distinct(50_000, 77)).unwrap();
        vfs.mkdir("/d", 0o755).unwrap();
        for i in 0..30 {
            put(&vfs, &format!("/d/x{i}"), &pattern(100 + i * 31, i as u8));
        }
    }
    check(&img);
    let before = snapshot(&img);
    let base = dir.join("base");
    assert!(Command::new("cp").arg("--sparse=always").arg(&img).arg(&base).status().unwrap().success());
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let rep = {
        let fs = BtrfsFs::mount(Disk::logged(&img, 0, Some(log.clone())), 1).unwrap();
        fs.balance(&BalanceFilter { usage_below: Some(90), ..Default::default() }).unwrap()
    };
    assert!(rep.relocated > 0 && rep.skipped.is_empty(), "{rep:?}");
    assert!(snapshot(&img) == before);
    let log = log.lock().unwrap();
    eprintln!("balance made {} device writes", log.len());
    let crashed = dir.join("crashed");
    let f = |n: usize| {
        assert!(Command::new("cp").arg("--sparse=always").arg(&base).arg(&crashed).status().unwrap().success());
        for (_, lba, data) in &log[..n] {
            write_at(&crashed, lba * B as u64, data);
        }
        if let Err(text) = try_check(&crashed) {
            panic!("crash after {n} of {} writes fails btrfs check:\n{text}", log.len());
        }
        assert!(snapshot(&crashed) == before, "crash after {n} of {} writes changed the files", log.len());
    };
    for n in 0..=log.len() {
        f(n);
    }
}

/// A read-only subvolume (not a snapshot, so nothing is shared) is moved
/// like any other, and stays read-only.
#[test]
fn moves_read_only_subvolume() {
    let dir = scratch("bal-ro");
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("ro/d")).unwrap();
    std::fs::create_dir_all(src.join("rw")).unwrap();
    let mut files = Vec::new();
    for i in 0..40 {
        let (path, data) = (format!("ro/d/f{i}"), distinct(20_000 + i * 4096, i as u32));
        std::fs::write(src.join(&path), &data).unwrap();
        files.push((format!("/{path}"), data));
    }
    std::fs::write(src.join("rw/x"), b"rw").unwrap();
    let Some(img) = mkfs(&dir, 128 << 20, &["-n", "4096", "--rootdir", src.to_str().unwrap(), "--subvol", "ro:ro"])
    else {
        return;
    };
    check(&img);
    let fs = mount(&img);
    let before = fs.chunks().unwrap();
    let rep = fs.balance(&BalanceFilter::default()).unwrap();
    assert!(rep.relocated >= 2 && rep.skipped.is_empty() && rep.busy.is_empty(), "{rep:?}");
    let after = fs.chunks().unwrap();
    for c in after.iter().filter(|c| c.flags & 2 == 0) {
        assert!(before.iter().all(|b| b.logical != c.logical), "{c:?} is old");
    }
    let vfs = Vfs::new(fs.root());
    let write = vfs.open("/ro/d/f0", OpenFlags::WRITE, 0).and_then(|f| f.write(0, b"no"));
    assert_eq!(write.err(), Some(osmium_fs::Errno::EROFS));
    assert_eq!(vfs.open("/ro/new", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).err(), Some(osmium_fs::Errno::EROFS));
    drop(vfs);
    drop(fs);
    check(&img);
    let vfs = Vfs::new(mount(&img).root());
    for (path, data) in &files {
        assert!(cat(&vfs, path) == *data, "{path} differs");
    }
    assert_eq!(cat(&vfs, "/rw/x"), b"rw");
}
