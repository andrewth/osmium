// SPDX-License-Identifier: GPL-2.0-only
//! A multi-threaded workout for any file system behind a [`Vfs`], shared by
//! the concurrency tests of `osmium-fs` and the disk file systems (each
//! includes it with `#[path]`). Real threads create, write, read back,
//! rename, list and remove files at once, in directories of their own and in
//! one they all share, so that every lock in the path (the VFS's, the file
//! system's, a node's) is contended. Each thread checks what it alone owns
//! as it goes; the caller checks the disk afterwards (with fsck, say).

use std::format;
use std::string::String;
use std::sync::{Arc, Barrier};
use std::vec::Vec;

use osmium_fs::{Errno, FileKind, OpenFlags, Vfs};

const RW: OpenFlags = OpenFlags::READ.union(OpenFlags::WRITE);

/// The bytes thread `t` writes in round `r`.
fn pattern(t: usize, r: usize) -> Vec<u8> {
    let len = 1 + (r * 977 + t * 131) % 5000;
    (0..len).map(|i| (i as u32).wrapping_mul(2654435761).rotate_left((t + r) as u32) as u8).collect()
}

/// Whether `e` is an error a call on the shared directory may meet because
/// another thread got there first.
fn raced(e: Errno) -> bool {
    matches!(e, Errno::ENOENT | Errno::EEXIST | Errno::ENOTEMPTY)
}

/// Runs `threads` threads for `rounds` rounds each under `base` (an existing
/// directory), and checks that every thread's own files hold what it last
/// wrote to them.
pub fn hammer(vfs: Arc<Vfs>, base: &str, threads: usize, rounds: usize) {
    let shared = format!("{base}/shared");
    vfs.mkdir(&shared, 0o755).unwrap();
    let start = Arc::new(Barrier::new(threads));
    let workers: Vec<_> = (0..threads)
        .map(|t| {
            let (vfs, start, shared) = (vfs.clone(), start.clone(), shared.clone());
            let own = format!("{base}/t{t}");
            std::thread::spawn(move || {
                vfs.mkdir(&own, 0o755).unwrap();
                start.wait();
                let mut last: [Option<Vec<u8>>; 4] = Default::default();
                for r in 0..rounds {
                    let slot = r % 4;
                    // A file of its own: written, read back, moved, read again.
                    let (from, to) = (format!("{own}/new{slot}"), format!("{own}/file{slot}"));
                    let data = pattern(t, r);
                    let f = vfs.open(&from, RW | OpenFlags::CREATE | OpenFlags::TRUNC, 0o644).unwrap();
                    assert_eq!(f.write(0, &data).unwrap(), data.len());
                    let mut back = vec![0; data.len() + 10];
                    assert_eq!(f.read(0, &mut back).unwrap(), data.len(), "thread {t} round {r}");
                    assert_eq!(back[..data.len()], data[..]);
                    // Over the previous one, if any.
                    vfs.rename(&from, &to).unwrap();
                    let moved = vfs.open(&to, OpenFlags::READ, 0).unwrap();
                    assert_eq!(moved.stat().size, data.len() as u64);
                    drop((f, moved));
                    last[slot] = Some(data);

                    // The shared directory: the same few names for everyone.
                    let name = format!("{shared}/s{}", r % 3);
                    match vfs.open(&name, RW | OpenFlags::CREATE, 0o644) {
                        Ok(f) => {
                            // Its own byte, and a read whatever others did.
                            f.write(t as u64, &[t as u8]).unwrap();
                            let mut b = [0u8; 64];
                            f.read(0, &mut b).unwrap();
                            if r % 5 == t % 5 {
                                // Unlinked while others may hold it open.
                                if let Err(e) = vfs.unlink(&name) {
                                    assert!(raced(e), "unlink: {e:?}");
                                }
                            }
                        }
                        Err(e) => assert!(raced(e), "open: {e:?}"),
                    }
                    if r % 7 == 0 {
                        let dir = format!("{shared}/d{}", r % 2);
                        if let Err(e) = vfs.mkdir(&dir, 0o755) {
                            assert!(raced(e), "mkdir: {e:?}");
                        }
                        if let Err(e) = vfs.rename(&format!("{shared}/s{}", (r + 1) % 3), &format!("{dir}/moved")) {
                            assert!(raced(e) || e == Errno::EISDIR, "rename: {e:?}");
                        }
                        if let Err(e) = vfs.rmdir(&dir) {
                            assert!(raced(e), "rmdir: {e:?}");
                        }
                    }
                    // Listing a directory that changes under it never fails.
                    let dir = vfs.lookup(&shared).unwrap();
                    for i in 0.. {
                        match dir.readdir(i) {
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(e) => panic!("readdir: {e:?}"),
                        }
                    }
                }
                // Its own directory holds what it last wrote, and nothing else.
                let dir = vfs.lookup(&own).unwrap();
                let mut names: Vec<String> = (0..).map_while(|i| dir.readdir(i).unwrap()).map(|e| e.name).collect();
                names.retain(|n| n != "." && n != "..");
                names.sort();
                let expected: Vec<String> = (0..4.min(rounds)).map(|s| format!("file{s}")).collect();
                assert_eq!(names, expected, "thread {t}");
                for (slot, data) in last.iter().enumerate() {
                    let Some(data) = data else { continue };
                    let f = vfs.open(&format!("{own}/file{slot}"), OpenFlags::READ, 0).unwrap();
                    let mut back = vec![0; data.len() + 10];
                    assert_eq!(f.read(0, &mut back).unwrap(), data.len());
                    assert_eq!(back[..data.len()], data[..], "thread {t} slot {slot}");
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    // Whatever is left in the shared directory can be looked up and removed.
    remove_tree(&vfs, &shared);
}

/// Removes the directory `path` and everything in it.
fn remove_tree(vfs: &Vfs, path: &str) {
    let dir = vfs.lookup(path).unwrap();
    let entries: Vec<_> =
        (0..).map_while(|i| dir.readdir(i).unwrap()).filter(|e| e.name != "." && e.name != "..").collect();
    for e in entries {
        let child = format!("{path}/{}", e.name);
        if e.kind == FileKind::Directory { remove_tree(vfs, &child) } else { vfs.unlink(&child).unwrap() }
    }
    vfs.rmdir(path).unwrap();
}
