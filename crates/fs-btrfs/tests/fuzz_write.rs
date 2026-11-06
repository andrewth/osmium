// SPDX-License-Identifier: GPL-2.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! A hostile btrfs image must not panic the driver's write path either. A
//! valid image is made with `mkfs.btrfs`; random bytes of blocks of its extent,
//! checksum and free space trees (mostly), of its other trees, and of the
//! space accounting in its superblock are changed (fixed seed) and their
//! checksums recomputed, so the damage gets past verification to the code
//! that updates them. Each damaged image is mounted writable, and files are created,
//! written, overwritten, truncated, renamed and deleted; any of that may fail,
//! none of it may panic (tests build with overflow checks, so arithmetic on
//! what the disk says that wraps is caught here). Then the same with balance
//! and scrub. Writes go to memory, not to the image. `OSMIUM_FUZZ_SEED` and
//! `OSMIUM_FUZZ_ROUNDS` choose another seed and number of rounds. Skipped,
//! with a note, if `mkfs.btrfs` is missing.

use std::collections::HashMap;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use osmium_fs::{OpenFlags, Vfs};
use osmium_fs_btrfs::{BalanceFilter, BtrfsFs};
use osmium_hal::block::{BlockDevice, BlockError};

const NODE: usize = 4096;

/// An image file read through an overlay of changed blocks, which writes go to.
#[derive(Clone)]
struct OverlayDisk {
    file: Arc<std::fs::File>,
    len: u64,
    blocks: Arc<Mutex<HashMap<u64, Vec<u8>>>>,
}

impl BlockDevice for OverlayDisk {
    fn block_size(&self) -> usize {
        NODE
    }
    fn num_blocks(&self) -> u64 {
        self.len / NODE as u64
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let blocks = self.blocks.lock().unwrap();
        for (i, chunk) in buf.chunks_mut(NODE).enumerate() {
            let at = (lba + i as u64) * NODE as u64;
            match blocks.get(&at) {
                Some(p) => chunk.copy_from_slice(p),
                None => self.file.read_exact_at(chunk, at).map_err(|_| BlockError::Io)?,
            }
        }
        Ok(())
    }
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let mut blocks = self.blocks.lock().unwrap();
        for (i, chunk) in buf.chunks(NODE).enumerate() {
            blocks.insert((lba + i as u64) * NODE as u64, chunk.to_vec());
        }
        Ok(())
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

fn data(len: usize, seed: u32) -> Vec<u8> {
    (0..len as u32).map(|i| (i.wrapping_mul(2_654_435_761) ^ seed).rotate_left(5) as u8).collect()
}

/// Changes of every kind the write path makes, their errors ignored.
fn churn(fs: &BtrfsFs<OverlayDisk>, round: u32) {
    let vfs = Vfs::new(fs.root());
    let flags = OpenFlags::WRITE | OpenFlags::CREATE;
    if let Ok(f) = vfs.open("/new", flags, 0o644) {
        let _ = f.write(0, &data(200_000, round));
        let _ = f.write(4096 * 7, &data(10_000, round + 1));
    }
    if let Ok(f) = vfs.open("/small", flags, 0o644) {
        let _ = f.write(0, b"inline data");
    }
    if let Ok(f) = vfs.open("/d/big", OpenFlags::WRITE, 0) {
        let _ = f.write(50_000, &data(120_000, round + 2));
        let _ = f.truncate(100_000);
    }
    for i in (0..40).step_by(3) {
        let _ = vfs.unlink(&format!("/d/n{i}"));
    }
    let _ = vfs.mkdir("/made", 0o755);
    let _ = vfs.rename("/d/n1", "/made/n1");
    let _ = vfs.unlink("/new");
    let _ = fs.sync();
}

#[test]
fn damaged_trees_written() {
    let Some(mkfs) =
        ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|d| Path::new(d).join("mkfs.btrfs")).find(|p| p.exists())
    else {
        eprintln!("mkfs.btrfs not found; skipping");
        return;
    };
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-fuzzw-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("d")).unwrap();
    std::fs::write(src.join("d/big"), data(400_000, 9)).unwrap();
    for i in 0..40 {
        std::fs::write(src.join(format!("d/n{i}")), data(5000 + i * 300, i as u32)).unwrap();
    }
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
    let out = Command::new(&mkfs).args(["-q", "-n", "4096", "--rootdir"]).arg(&src).arg(&img).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let file = Arc::new(std::fs::File::open(&img).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    let len = file.metadata().unwrap().len();
    let disk = || OverlayDisk { file: file.clone(), len, blocks: Arc::new(Mutex::new(HashMap::new())) };

    // The blocks of the extent (2), checksum (7) and free space (10) trees, and
    // of the others: root (1), chunk (3), device (4) and file system (5).
    let mut sb = vec![0u8; 4096];
    file.read_exact_at(&mut sb, 64 * 1024).unwrap();
    let fsid = sb[32..48].to_vec();
    let mut blocks = Vec::new();
    let mut b = vec![0u8; NODE];
    for at in (0..len).step_by(NODE) {
        file.read_exact_at(&mut b, at).unwrap();
        let owner = u64::from_le_bytes(b[88..96].try_into().unwrap());
        if b[32..48] == fsid[..] && at != 64 * 1024 && (1..=10).contains(&owner) {
            blocks.push((at, b.clone()));
        }
    }
    let owners: Vec<u64> = blocks.iter().map(|(_, b)| u64::from_le_bytes(b[88..96].try_into().unwrap())).collect();
    for o in [2, 7, 10] {
        assert!(owners.contains(&o), "no block of tree {o}");
    }

    // Undamaged, it all works.
    let fs = BtrfsFs::mount(disk(), 1).unwrap();
    assert!(!fs.is_read_only());
    churn(&fs, 0);
    drop(fs);

    let (space, other): (Vec<_>, Vec<_>) =
        blocks.into_iter().partition(|(_, b)| [2, 7, 10].contains(&u64::from_le_bytes(b[88..96].try_into().unwrap())));

    // Another seed, or more rounds, from the environment to look further.
    let env = |name: &str| std::env::var(name).ok().and_then(|v| v.parse::<u64>().ok());
    let mut rng = Rng(env("OSMIUM_FUZZ_SEED").unwrap_or(0x9e37_79b9_7f4a_7c15) | 1);
    for round in 0..env("OSMIUM_FUZZ_ROUNDS").unwrap_or(1000) as u32 {
        let d = disk();
        {
            let mut over = d.blocks.lock().unwrap();
            if rng.below(8) == 0 {
                // The superblock's total and used bytes, and the device item's.
                let mut s = sb.clone();
                let i = [112, 120, 201 + 8, 201 + 16][rng.below(4)];
                let v = if rng.below(2) == 0 { u64::MAX - rng.below(1 << 20) as u64 } else { rng.next() };
                s[i..i + 8].copy_from_slice(&v.to_le_bytes());
                let sum = crc32c(&s[32..]);
                s[..4].copy_from_slice(&sum.to_le_bytes());
                over.insert(64 * 1024, s);
            }
            for _ in 0..1 + rng.below(2) {
                let from = if rng.below(4) == 0 { &other } else { &space };
                let (at, orig) = &from[rng.below(from.len())];
                let mut p = over.get(at).cloned().unwrap_or_else(|| orig.clone());
                let items = u32::from_le_bytes(p[96..100].try_into().unwrap()) as usize;
                for _ in 0..1 + rng.below(4) {
                    // Item keys and sizes, the data at the end of the block (where
                    // leaves keep it), or anywhere.
                    let i = match rng.below(3) {
                        0 => 101 + rng.below((items * 25).clamp(1, NODE - 101)),
                        1 => NODE - 1 - rng.below(1024),
                        _ => 56 + rng.below(NODE - 56),
                    };
                    match rng.below(6) {
                        0 => p[i] = 0,
                        1 => p[i] = 0xff,
                        2 => p[i] ^= 0x80,
                        // A field (key offset, extent length, ...) near the top of its range.
                        3 => {
                            let i = i.min(NODE - 8);
                            let v = u64::MAX - rng.below(1 << 24) as u64;
                            p[i..i + 8].copy_from_slice(&v.to_le_bytes());
                        }
                        _ => p[i] = rng.next() as u8,
                    }
                }
                let sum = crc32c(&p[32..]);
                p[..4].copy_from_slice(&sum.to_le_bytes());
                over.insert(*at, p);
            }
        }
        let Ok(fs) = BtrfsFs::mount(d, 1) else { continue };
        churn(&fs, round);
        if round % 10 == 0 {
            let _ = fs.balance(&BalanceFilter { usage_below: Some(90), ..Default::default() });
            let _ = fs.scrub(true);
        }
    }
}
