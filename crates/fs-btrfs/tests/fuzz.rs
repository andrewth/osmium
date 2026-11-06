// SPDX-License-Identifier: GPL-2.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! A hostile btrfs image must not panic or hang the driver. A valid image is
//! made with `mkfs.btrfs`, random bytes of its tree blocks are changed (fixed
//! seed) and their checksums recomputed, so the damage gets past checksum
//! verification to the parsers. Each damaged image is mounted, walked and read.
//! Skipped, with a note, if `mkfs.btrfs` is missing.

use std::collections::HashMap;
use std::os::unix::fs::{FileExt, symlink};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use osmium_fs::{File, FileKind};
use osmium_fs_btrfs::BtrfsFs;
use osmium_hal::block::{BlockDevice, BlockError};

const NODE: usize = 4096;

/// An image file with some blocks replaced in memory.
#[derive(Clone)]
struct PatchedDisk {
    file: Arc<std::fs::File>,
    len: u64,
    patches: Arc<HashMap<u64, Vec<u8>>>,
}

impl BlockDevice for PatchedDisk {
    fn block_size(&self) -> usize {
        NODE
    }
    fn num_blocks(&self) -> u64 {
        self.len / NODE as u64
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        for (i, chunk) in buf.chunks_mut(NODE).enumerate() {
            let at = (lba + i as u64) * NODE as u64;
            match self.patches.get(&at) {
                Some(p) => chunk.copy_from_slice(p),
                None => self.file.read_exact_at(chunk, at).map_err(|_| BlockError::Io)?,
            }
        }
        Ok(())
    }
    fn write_blocks(&mut self, _lba: u64, _buf: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { crc >> 1 ^ 0x82f6_3b78 } else { crc >> 1 };
        }
    }
    !crc
}

/// Walks everything under `dir`, reading a bounded amount of each file.
fn walk(dir: &dyn File, depth: usize) {
    if depth > 12 {
        return;
    }
    for i in 0..200 {
        let Ok(Some(e)) = dir.readdir(i) else { break };
        let Ok(node) = dir.lookup(&e.name) else { continue };
        let _ = node.try_stat();
        let _ = node.xattr_list();
        let _ = node.xattr_get(b"user.comment");
        match node.stat().kind {
            FileKind::Directory => walk(&*node, depth + 1),
            FileKind::Symlink => _ = node.readlink(),
            _ => {
                let mut buf = vec![0u8; 64 * 1024];
                let mut off = 0u64;
                for _ in 0..8 {
                    match node.read(off, &mut buf) {
                        Ok(n) if n > 0 => off += n as u64,
                        _ => break,
                    }
                }
                // A read far into the file, past any real data.
                let _ = node.read(1 << 40, &mut buf);
            }
        }
    }
}

#[test]
fn damaged_tree_blocks() {
    let Some(mkfs) =
        ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|d| Path::new(d).join("mkfs.btrfs")).find(|p| p.exists())
    else {
        eprintln!("mkfs.btrfs not found; skipping");
        return;
    };
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-fuzz-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("d/e")).unwrap();
    std::fs::create_dir_all(src.join("vol")).unwrap();
    std::fs::write(src.join("a.txt"), b"hello").unwrap();
    std::fs::write(src.join("d/big"), (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect::<Vec<_>>()).unwrap();
    std::fs::write(src.join("d/e/f"), b"deep").unwrap();
    std::fs::write(src.join("vol/v"), b"in vol").unwrap();
    for i in 0..60 {
        std::fs::write(src.join(format!("d/n{i}")), format!("{i}")).unwrap();
    }
    symlink("a.txt", src.join("l")).unwrap();
    let _ = Command::new("python3")
        .args(["-c", "import os,sys; os.setxattr(sys.argv[1], 'user.comment', b'x')"])
        .arg(src.join("a.txt"))
        .status();
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
    let out = Command::new(&mkfs)
        .args(["-q", "-n", "4096", "--compress", "zstd", "-u", "vol", "--rootdir"])
        .arg(&src)
        .arg(&img)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    // Every tree block: the superblock's fsid at offset 32 and its own address at 48.
    let file = Arc::new(std::fs::File::open(&img).unwrap());
    // The open file keeps the image; the directory can go.
    let _ = std::fs::remove_dir_all(&dir);
    let len = file.metadata().unwrap().len();
    let mut sb = vec![0u8; 4096];
    file.read_exact_at(&mut sb, 64 * 1024).unwrap();
    let fsid = sb[32..48].to_vec();
    let mut blocks = Vec::new();
    let mut b = vec![0u8; NODE];
    for at in (0..len).step_by(NODE) {
        file.read_exact_at(&mut b, at).unwrap();
        if b[32..48] == fsid[..] && at != 64 * 1024 {
            blocks.push((at, b.clone()));
        }
    }
    assert!(blocks.len() > 10, "found {} tree blocks", blocks.len());

    let disk = PatchedDisk { file: file.clone(), len, patches: Arc::new(HashMap::new()) };
    walk(&*BtrfsFs::mount(disk, 1).unwrap().root(), 0);

    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for _ in 0..3000 {
        let mut patches = HashMap::new();
        for _ in 0..1 + rng.below(2) {
            let (at, orig) = &blocks[rng.below(blocks.len())];
            let mut p = patches.get(at).cloned().unwrap_or_else(|| orig.clone());
            for _ in 0..1 + rng.below(4) {
                // Mostly item headers and small fields near the start; sometimes anywhere.
                let i = if rng.below(4) == 0 { 56 + rng.below(NODE - 56) } else { 56 + rng.below(600) };
                p[i] = match rng.below(4) {
                    0 => 0,
                    1 => 0xff,
                    _ => rng.next() as u8,
                };
            }
            let sum = crc32c(&p[32..]);
            p[..4].copy_from_slice(&sum.to_le_bytes());
            patches.insert(*at, p);
        }
        let disk = PatchedDisk { file: file.clone(), len, patches: Arc::new(patches) };
        if let Ok(fs) = BtrfsFs::mount(disk, 1) {
            walk(&*fs.root(), 0);
        }
    }
}
