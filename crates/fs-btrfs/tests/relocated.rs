// SPDX-License-Identifier: GPL-2.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! A volume Linux has balanced: its relocation leaves blocks of a snapshotted
//! subvolume flagged `RELOC`, written after the last snapshot yet shared, owned
//! by another tree and `FULL_BACKREF`. The driver must treat them as shared
//! (as Linux's `btrfs_block_can_be_shared` does) and change files across them.
//!
//! `images/linux-balanced.img.zst` is what `linux_balance_then_write` in
//! `linux.rs` leaves after Linux's balance (`OSMIUM_LINUX_KEEP=<path>`),
//! compressed with `zstd --ultra -22 --long=27`: 300 files in `top`, a
//! subvolume `sv` of 800 files and a 1 MB `big`, a snapshot `snap` of it, one
//! file of `sv` changed, a read-only snapshot `rosnap`, then two full balances.
//! Skipped, with a note, without `zstd` or btrfs-progs.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::*;
use osmium_fs::{Errno, OpenFlags, Vfs};

/// The image, uncompressed into `dir`.
fn image(dir: &Path) -> Option<PathBuf> {
    let zstd = tool("zstd")?;
    tool("btrfs")?;
    let img = dir.join("img");
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/images/linux-balanced.img.zst");
    let ok = Command::new(zstd).args(["-d", "-q", "-f", "--long=27", "-o"]).arg(&img).arg(src).status().unwrap();
    assert!(ok.success());
    Some(img)
}

/// What Linux wrote: path to contents.
fn linux_wrote() -> Snapshot {
    let mut want = Snapshot::new();
    let name = |i: u32| format!("file-with-a-long-name-{i}");
    for d in ["/top", "/sv", "/sv/d", "/snap", "/snap/d", "/rosnap", "/rosnap/d"] {
        want.insert(d.into(), None);
    }
    for i in 0..300 {
        want.insert(format!("/top/{}", name(i)), Some(format!("top file {i}\n").into_bytes()));
    }
    let big: Vec<u8> = b"big file\n".iter().copied().cycle().take(1_000_000).collect();
    for s in ["sv", "snap", "rosnap"] {
        for i in 0..800 {
            let data = if i == 17 && s != "snap" { b"changed\n".to_vec() } else { format!("file number {i}\n").into() };
            want.insert(format!("/{s}/d/{}", name(i)), Some(data));
        }
        want.insert(format!("/{s}/big"), Some(big.clone()));
    }
    want
}

#[test]
fn writes_across_linux_relocated_blocks() {
    let dir = scratch("relocated");
    let Some(img) = image(&dir) else { return };
    check(&img);
    let mut want = linux_wrote();
    {
        let fs = mount(&img);
        assert_eq!(snapshot_fs(fs.root()), want);
        let vfs = Vfs::new(fs.root());
        assert_eq!(
            vfs.open("/rosnap/big", OpenFlags::WRITE, 0).and_then(|f| f.write(0, b"no")).err(),
            Some(Errno::EROFS)
        );
        // Every file of the writable subvolumes changed, so that every leaf
        // and node of theirs is copied.
        for (path, data) in want.iter_mut() {
            let Some(data) = data else { continue };
            if path.starts_with("/rosnap/") {
                continue;
            }
            let f = vfs.open(path, OpenFlags::WRITE, 0).unwrap();
            f.write(0, b"OSMIUM").unwrap_or_else(|e| panic!("writing {path}: {e:?}"));
            let n = data.len().min(6);
            data[..n].copy_from_slice(&b"OSMIUM"[..n]);
            data.extend_from_slice(&b"OSMIUM"[n..]);
        }
        for i in (0..800).step_by(7) {
            for s in ["sv", "snap"] {
                let path = format!("/{s}/d/file-with-a-long-name-{i}");
                vfs.unlink(&path).unwrap();
                want.remove(&path);
            }
        }
        put(&vfs, "/snap/new", &pattern(50_000, 1));
        want.insert("/snap/new".into(), Some(pattern(50_000, 1)));
    }
    check(&img);
    {
        // Deleting the snapshots drops the blocks they share with `sv`.
        let fs = mount(&img);
        assert_eq!(snapshot_fs(fs.root()), want);
        let vfs = Vfs::new(fs.root());
        let root = vfs.lookup("/").unwrap();
        for s in ["rosnap", "snap"] {
            fs.delete_subvolume(&*root, s).unwrap();
            want.retain(|k, _| !k.starts_with(&format!("/{s}")));
        }
    }
    check(&img);
    assert_eq!(snapshot_fs(mount(&img).root()), want);
}
