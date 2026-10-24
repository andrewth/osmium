#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Running out of memory in the middle of a file system call is `ENOMEM`,
//! and leaves the file system as it was. Each test fails every allocation of
//! a call in turn.

use std::sync::Arc;

use osmium_fs::{Errno, File, FileKind, OpenFlags, RamFs, Vfs};

#[path = "../../proc/src/failing.rs"]
mod failing;

#[global_allocator]
static ALLOCATOR: failing::Failing = failing::Failing;

use failing::every_failure;

const RW: OpenFlags = OpenFlags::READ.union(OpenFlags::WRITE);

fn vfs() -> Vfs {
    Vfs::new(RamFs::new(1).root())
}

/// A call that fails does so with `ENOMEM`.
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
fn creating_files_and_directories_fails_cleanly() {
    let vfs = vfs();
    vfs.mkdir("/d", 0o755).unwrap();
    let mut n = 0;
    for (what, path) in [("file", "/d/f"), ("directory", "/d/sub")] {
        let failures = every_failure(
            || {
                if what == "file" {
                    vfs.open(path, RW | OpenFlags::CREATE | OpenFlags::EXCL, 0o644).map(drop)
                } else {
                    vfs.mkdir(path, 0o755)
                }
            },
            |r, injected| {
                if !ok_or_enomem(&r, injected) {
                    assert_eq!(vfs.stat(path, true).unwrap_err(), Errno::ENOENT, "a failed {what} is not there");
                }
            },
        );
        n += failures;
        assert!(vfs.stat(path, true).is_ok());
    }
    assert!(n >= 6, "{n}");
}

#[test]
fn resolving_paths_fails_cleanly() {
    let vfs = vfs();
    vfs.mkdir("/a", 0o755).unwrap();
    vfs.mkdir("/a/b", 0o755).unwrap();
    vfs.open("/a/b/file", RW | OpenFlags::CREATE, 0o644).unwrap().write(0, b"data").unwrap();
    vfs.symlink("b/file", "/a/link").unwrap();
    vfs.symlink("/a", "/abs").unwrap();
    for (path, canonical) in [
        ("/a/b/file", "/a/b/file"),
        ("/a/link", "/a/b/file"),
        ("/abs/b/../b/./file", "/a/b/file"),
        ("//a///b/", "/a/b"),
    ] {
        let n = every_failure(
            || vfs.canonicalize(path),
            |r, injected| {
                if ok_or_enomem(&r, injected) {
                    assert_eq!(r.unwrap(), canonical, "{path}");
                }
            },
        );
        assert!(n >= 2, "{path}: {n}");
        let n = every_failure(
            || vfs.stat(path, true),
            |r, injected| {
                ok_or_enomem(&r, injected);
            },
        );
        assert!(n >= 1, "{path}: {n}");
    }
    let n = every_failure(
        || vfs.readlink("/a/link"),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), "b/file");
            }
        },
    );
    assert!(n >= 1, "{n}");
    // open: through a link, and a read of the data
    let n = every_failure(
        || vfs.open("/a/link", OpenFlags::READ, 0).map(|f| f.stat().size),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), 4);
            }
        },
    );
    assert!(n >= 2, "{n}");
}

#[test]
fn removing_listing_and_mounting_fail_cleanly() {
    let vfs = vfs();
    vfs.mkdir("/m", 0o755).unwrap();
    let other = RamFs::new(2).root();
    other.create("inside", FileKind::Regular, 0o644).unwrap();
    // mount, then unmount, each failing at every point and then succeeding
    let n = every_failure(
        || vfs.mount("/m", other.clone()),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert!(vfs.stat("/m/inside", true).is_ok());
                vfs.unmount("/m").unwrap();
            } else {
                assert_eq!(vfs.stat("/m/inside", true).unwrap_err(), Errno::ENOENT, "not mounted");
            }
        },
    );
    assert!(n >= 2, "mount: {n}");
    vfs.mount("/m", other.clone()).unwrap();
    let n = every_failure(
        || vfs.unmount("/m"),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                vfs.mount("/m", other.clone()).unwrap();
            } else {
                assert!(vfs.stat("/m/inside", true).is_ok(), "still mounted");
            }
        },
    );
    assert!(n >= 2, "unmount: {n}");

    // readdir and removal on the root
    let root: Arc<dyn File> = vfs.lookup("/").unwrap();
    vfs.open("/gone", RW | OpenFlags::CREATE, 0o644).unwrap();
    let n = every_failure(
        || {
            let mut found = false;
            for i in 0.. {
                match root.readdir(i)? {
                    Some(e) => found |= e.name == "gone",
                    None => break,
                }
            }
            Ok::<_, Errno>(found)
        },
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert!(r.unwrap());
            }
        },
    );
    assert!(n >= 1, "readdir: {n}");
    let n = every_failure(
        || vfs.unlink("/gone"),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(vfs.stat("/gone", true).unwrap_err(), Errno::ENOENT);
                vfs.open("/gone", RW | OpenFlags::CREATE, 0o644).unwrap();
            } else {
                assert!(vfs.stat("/gone", true).is_ok(), "a failed unlink removes nothing");
            }
        },
    );
    assert!(n >= 1, "unlink: {n}");
}
