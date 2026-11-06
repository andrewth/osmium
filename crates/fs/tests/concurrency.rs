#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! The VFS and RamFs under real threads: path walks, creation races, renames
//! and removals at once, through a mount point too.

use std::sync::Arc;

use osmium_fs::{FileKind, OpenFlags, RamFs, Vfs};

#[path = "shared/hammer.rs"]
mod hammer;

#[test]
fn ramfs_under_many_threads() {
    let vfs = Arc::new(Vfs::new(RamFs::new(1).root()));
    vfs.mkdir("/work", 0o755).unwrap();
    hammer::hammer(vfs.clone(), "/work", 8, 300);
    assert_eq!(vfs.stat("/work/shared", true).err(), Some(osmium_fs::Errno::ENOENT));
}

#[test]
fn across_a_mount_point() {
    let vfs = Arc::new(Vfs::new(RamFs::new(1).root()));
    vfs.mkdir("/mnt", 0o755).unwrap();
    vfs.mount("/mnt", RamFs::new(2).root()).unwrap();
    hammer::hammer(vfs.clone(), "/mnt", 6, 200);
    assert_eq!(vfs.stat("/mnt", true).unwrap().dev, 2);
    vfs.unmount("/mnt").unwrap();
}

#[test]
fn every_creator_of_one_name_gets_the_same_file() {
    for _ in 0..50 {
        let vfs = Arc::new(Vfs::new(RamFs::new(1).root()));
        let start = Arc::new(std::sync::Barrier::new(8));
        let inos: Vec<u64> = (0..8)
            .map(|t| {
                let (vfs, start) = (vfs.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    let f = vfs.open("/one", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
                    f.write(t, &[t as u8]).unwrap();
                    f.stat().ino
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        assert!(inos.iter().all(|&i| i == inos[0]), "{inos:?}");
        let st = vfs.stat("/one", true).unwrap();
        assert_eq!((st.kind, st.size), (FileKind::Regular, 8));
    }
}
