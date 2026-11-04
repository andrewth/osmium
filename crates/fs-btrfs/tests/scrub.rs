#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Scrub: finds and repairs bad copies of `DUP` chunks, and says so when it
//! cannot. Skipped, with a note, without btrfs-progs.

mod common;

use std::path::{Path, PathBuf};

use common::*;
use osmium_fs::{Errno, OpenFlags, Vfs};
use osmium_fs_btrfs::{BtrfsFs, MountOptions, ScrubErrorKind};

/// A volume with `DUP` data and metadata and a few files.
fn volume(dir: &Path) -> Option<PathBuf> {
    let img = mkfs(dir, 256 << 20, &["-d", "dup", "-m", "dup"])?;
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    put(&vfs, "/small", b"hello, scrub");
    put(&vfs, "/big", &distinct(1 << 20, 7));
    vfs.mkdir("/d", 0o755).unwrap();
    for i in 0..40 {
        put(&vfs, &format!("/d/f{i}"), &pattern(5000 + i * 100, i as u8));
    }
    Some(img)
}

/// The physical offsets of both copies of the first sector of `/big`.
fn big_copies(img: &Path) -> (u64, u64) {
    let want = &distinct(1 << 20, 7)[..4096];
    let all = std::fs::read(img).unwrap();
    let hits: Vec<usize> = all.chunks(4096).enumerate().filter(|(_, w)| *w == want).map(|(i, _)| i * 4096).collect();
    assert_eq!(hits.len(), 2, "two copies of the first sector");
    (hits[0] as u64, hits[1] as u64)
}

#[test]
fn clean_volume() {
    let dir = scratch("scrub-clean");
    let Some(img) = volume(&dir) else { return };
    let fs = mount(&img);
    let rep = fs.scrub(false).unwrap();
    assert!(rep.is_clean(), "{rep:?}");
    assert!(rep.tree_blocks > 3 && rep.data_sectors > 256, "{rep:?}");
    // Both copies of everything were read.
    assert!(rep.copies_read >= 2 * rep.tree_blocks, "{rep:?}");
    let rep = fs.scrub(true).unwrap();
    assert!(rep.is_clean() && rep.repaired == 0);
}

#[test]
fn repairs_a_bad_copy() {
    let dir = scratch("scrub-repair");
    let Some(img) = volume(&dir) else { return };
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    let (a, b) = big_copies(&img);
    // Damage one data copy each way round, and a copy of the root tree block.
    write_at(&img, a + 100, &[0xAA; 16]);
    write_at(&img, b + 4096 + 7, &[0x55; 3]);
    let root = root_addr(&img);
    let rp = phys(&fs, root, 1);
    let mut blk = read_at(&img, rp, 16384);
    blk[200] ^= 0xFF;
    write_at(&img, rp, &blk);

    let rep = fs.scrub(false).unwrap();
    assert_eq!(rep.bad_copies, 3, "{rep:?}");
    assert_eq!((rep.repaired, rep.uncorrectable), (0, 0), "{rep:?}");
    assert!(rep.errors.iter().any(|e| e.kind == ScrubErrorKind::TreeBlock && e.physical == rp));
    assert!(rep.errors.iter().any(|e| e.kind == ScrubErrorKind::DataChecksum && e.physical == a));
    // Reading still works, from the good copy.
    assert_eq!(cat(&vfs, "/big"), distinct(1 << 20, 7));
    // Report-only left the damage.
    assert_eq!(read_at(&img, rp, 16384), blk);

    let rep = fs.scrub(true).unwrap();
    assert_eq!((rep.bad_copies, rep.repaired, rep.uncorrectable), (3, 3, 0), "{rep:?}");
    assert!(rep.errors.iter().all(|e| e.repaired));
    let rep = fs.scrub(false).unwrap();
    assert!(rep.is_clean(), "{rep:?}");
    drop(vfs);
    drop(fs);
    check(&img);
    let (a, b) = big_copies(&img);
    assert_eq!(read_at(&img, a, 1 << 20), read_at(&img, b, 1 << 20));
}

#[test]
fn reports_what_it_cannot_repair() {
    let dir = scratch("scrub-lost");
    let Some(img) = volume(&dir) else { return };
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    let (a, b) = big_copies(&img);
    write_at(&img, a + 8192, &[1; 4]);
    write_at(&img, b + 8192, &[2; 4]);
    let rep = fs.scrub(true).unwrap();
    assert_eq!((rep.bad_copies, rep.repaired, rep.uncorrectable), (2, 0, 1), "{rep:?}");
    // The file reads as an I/O error, not as wrong data.
    let f = vfs.open("/big", OpenFlags::READ, 0).unwrap();
    let mut buf = vec![0u8; 3 * 4096];
    assert_eq!(f.read(0, &mut buf).err(), Some(Errno::EIO));
    drop(f);
    drop(vfs);
    drop(fs);
    // A read-only mount scrubs but does not repair.
    let ro = BtrfsFs::mount_with(Disk::open(&img), 1, MountOptions { subvol: None, read_only: true }).unwrap();
    assert_eq!(ro.scrub(true).err(), Some(Errno::EROFS));
    assert_eq!(ro.scrub(false).unwrap().uncorrectable, 1);
}
