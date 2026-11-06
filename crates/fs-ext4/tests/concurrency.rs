// SPDX-License-Identifier: GPL-2.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! ext2 and ext4 under real threads: creation races, renames over targets,
//! files unlinked while others hold them open (the orphan list), and nodes
//! dropped by one thread while another looks them up. `e2fsck` checks the
//! result. Images come from `mkfs.ext*` (failing if e2fsprogs is missing,
//! unless `OSMIUM_SKIP_TOOL_TESTS=1`).

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Barrier, Mutex};

use osmium_fs::{OpenFlags, Vfs};
use osmium_fs_ext4::Ext2;
use osmium_hal::block::{BlockDevice, BlockError};

#[path = "../../fs/tests/shared/hammer.rs"]
mod hammer;

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
    let dir = std::env::temp_dir().join(format!("osmium-ext4-concurrency-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// A fresh image made by `mkfs.<kind>`, or `None` if it is missing and
/// `OSMIUM_SKIP_TOOL_TESTS=1` is set.
fn mkfs(kind: &str, name: &str) -> Option<(PathBuf, MemDisk)> {
    let path = scratch(&format!("{name}-{kind}.img"));
    std::fs::write(&path, vec![0u8; 32 << 20]).unwrap();
    let Ok(status) =
        Command::new(format!("mkfs.{kind}")).args(["-q", "-F", "-b", "1024", "-I", "256"]).arg(&path).status()
    else {
        if std::env::var_os("OSMIUM_SKIP_TOOL_TESTS").is_some_and(|v| v == "1") {
            eprintln!("mkfs.{kind} not installed; skipping (OSMIUM_SKIP_TOOL_TESTS=1)");
            return None;
        }
        panic!("mkfs.{kind} not installed: install it, or set OSMIUM_SKIP_TOOL_TESTS=1 to skip the tests that need it");
    };
    assert!(status.success());
    Some((path.clone(), MemDisk(Arc::new(Mutex::new(std::fs::read(&path).unwrap())))))
}

/// Runs `e2fsck -fn` on what the disk holds.
fn fsck(path: &PathBuf, disk: &MemDisk) {
    std::fs::write(path, &*disk.0.lock().unwrap()).unwrap();
    let out = Command::new("e2fsck").args(["-fn"]).arg(path).output().expect("e2fsck");
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "e2fsck found problems:\n{text}");
}

#[test]
fn many_threads_at_once_leave_a_clean_file_system() {
    for kind in ["ext2", "ext4"] {
        let Some((path, disk)) = mkfs(kind, "hammer") else { return };
        let ext2 = Ext2::mount(disk.clone(), 1).unwrap();
        let vfs = Arc::new(Vfs::new(ext2.root().unwrap()));
        vfs.mkdir("/work", 0o755).unwrap();
        hammer::hammer(vfs.clone(), "/work", 6, 120);
        drop(vfs);
        ext2.into_device().map_err(|(_, e)| e).unwrap();
        fsck(&path, &disk);
    }
}

#[test]
fn nodes_dropped_while_others_look_them_up() {
    let Some((path, disk)) = mkfs("ext4", "drops") else { return };
    let ext2 = Ext2::mount(disk.clone(), 1).unwrap();
    let vfs = Arc::new(Vfs::new(ext2.root().unwrap()));
    vfs.open("/shared", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap().write(0, b"shared").unwrap();
    let start = Arc::new(Barrier::new(8));
    let workers: Vec<_> = (0..8)
        .map(|t| {
            let (vfs, start) = (vfs.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                for r in 0..400 {
                    // Each lookup may find the node another thread is
                    // dropping, and must get a live one.
                    let f = vfs.open("/shared", OpenFlags::READ, 0).unwrap();
                    let mut buf = [0; 6];
                    assert_eq!(f.read(0, &mut buf).unwrap(), 6);
                    assert_eq!(&buf, b"shared");
                    drop(f);
                    // And a file of its own, unlinked while still open.
                    if r % 10 == 0 {
                        let name = format!("/gone{t}");
                        let g = vfs.open(&name, OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
                        g.write(0, &[t as u8; 3000]).unwrap();
                        vfs.unlink(&name).unwrap();
                        assert_eq!(g.stat().nlink, 0);
                    }
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    drop(vfs);
    ext2.into_device().map_err(|(_, e)| e).unwrap();
    fsck(&path, &disk);
}
