#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! A hostile disk image must not panic or hang the driver. Valid FAT12 and
//! FAT16 volumes are made through the driver, then random bytes of their
//! metadata are flipped (fixed seed), and each damaged image is mounted,
//! walked, read and written.

use std::sync::{Arc, Mutex};

use osmium_fs::{File, FileKind};
use osmium_fs_fat::FatFs;
use osmium_hal::block::{BlockDevice, BlockError};

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

/// xorshift64, seeded.
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

const ROOT_SECTORS: usize = 32;

/// An empty volume of `clusters` one-sector clusters; returns it and the
/// number of metadata bytes before the data area.
fn blank(clusters: usize, fat16: bool) -> (Vec<u8>, usize) {
    let fat = if fat16 { (clusters + 2) * 2 } else { ((clusters + 2) * 3).div_ceil(2) }.div_ceil(512);
    let total = 1 + 2 * fat + ROOT_SECTORS + clusters;
    let mut disk = vec![0u8; total * 512];
    disk[11..13].copy_from_slice(&512u16.to_le_bytes());
    disk[13] = 1;
    disk[14..16].copy_from_slice(&1u16.to_le_bytes());
    disk[16] = 2;
    disk[17..19].copy_from_slice(&512u16.to_le_bytes());
    disk[19..21].copy_from_slice(&(total as u16).to_le_bytes());
    disk[21] = 0xf8;
    disk[22..24].copy_from_slice(&(fat as u16).to_le_bytes());
    disk[510..512].copy_from_slice(&[0x55, 0xaa]);
    for copy in 0..2 {
        let at = 512 + copy * fat * 512;
        disk[at..at + 4].copy_from_slice(&[0xf8, 0xff, 0xff, 0xff]);
    }
    (disk, (1 + 2 * fat + ROOT_SECTORS) * 512)
}

/// Fills a volume with a few files and directories, including a long name,
/// a multi-cluster file and a nested directory.
fn populate(disk: &MemDisk) {
    let fs = FatFs::mount(disk.clone(), 1).unwrap();
    let root = fs.root();
    let big = root.create("A Rather Long File Name.text", FileKind::Regular, 0o644).unwrap();
    big.write(0, &[7u8; 3000]).unwrap();
    root.create("SHORT.TXT", FileKind::Regular, 0o644).unwrap().write(0, b"hello").unwrap();
    let sub = root.create("sub", FileKind::Directory, 0o755).unwrap();
    sub.create("inner.bin", FileKind::Regular, 0o644).unwrap().write(0, &[1u8; 700]).unwrap();
    let deeper = sub.create("Deeper Directory", FileKind::Directory, 0o755).unwrap();
    deeper.create("x", FileKind::Regular, 0o644).unwrap().write(0, &[2u8; 50]).unwrap();
    root.sync().unwrap();
}

/// Walks the tree to `depth`, reading every file and probing writes, with
/// `budget` bounding the total number of nodes visited.
fn walk(dir: &Arc<dyn File>, depth: usize, budget: &mut usize) {
    for i in 0..4096 {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let Ok(Some(e)) = dir.readdir(i) else { return };
        let Ok(node) = dir.lookup(&e.name) else { continue };
        let st = node.stat();
        let _ = node.try_stat();
        if e.kind == FileKind::Directory {
            if depth < 5 {
                walk(&node, depth + 1, budget);
            }
            let _ = dir.remove(&e.name, true);
        } else {
            let mut buf = [0u8; 1500];
            let mut off = 0;
            for _ in 0..64 {
                match node.read(off, &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => off += n as u64,
                }
            }
            let _ = node.read(st.size.saturating_sub(10), &mut buf);
            let _ = node.write(0, &[9u8; 600]);
            let _ = node.write(st.size, &[9u8; 700]);
            let _ = node.truncate(5);
            let _ = node.truncate(2000);
            let _ = dir.remove(&e.name, false);
        }
    }
}

fn exercise(disk: MemDisk) -> bool {
    let Ok(fs) = FatFs::mount(disk, 1) else { return false };
    let root = fs.root();
    let mut budget = 400;
    walk(&root, 0, &mut budget);
    for name in ["fuzz.txt", "A Fuzz Long Name.txt", "dir"] {
        let kind = if name == "dir" { FileKind::Directory } else { FileKind::Regular };
        if let Ok(f) = root.create(name, kind, 0o644) {
            let _ = f.write(0, &[3u8; 5000]);
            let _ = f.write(70_000, &[3u8; 10]);
            let _ = f.create("inner", FileKind::Regular, 0o644);
        }
    }
    walk(&root, 0, &mut budget);
    let _ = root.sync();
    true
}

fn fuzz(clusters: usize, fat16: bool, rounds: usize, seed: u64) {
    let (blank, meta) = blank(clusters, fat16);
    let disk = MemDisk(Arc::new(Mutex::new(blank)));
    populate(&disk);
    let pristine = disk.0.lock().unwrap().clone();
    // The undamaged image mounts and walks.
    assert!(exercise(MemDisk(Arc::new(Mutex::new(pristine.clone())))));
    let mut mounted = 0;
    let mut rng = Rng(seed);
    for round in 0..rounds {
        let mut img = pristine.clone();
        for _ in 0..1 + rng.below(6) {
            // Mostly the boot sector, the start of the FAT, the root
            // directory and the first data clusters, where the files are.
            let at = match rng.below(4) {
                0 => rng.below(64),
                1 => 512 + rng.below(1024),
                2 => meta - ROOT_SECTORS * 512 + rng.below(512),
                _ => meta + rng.below(24 * 512),
            };
            if at < img.len() {
                img[at] = match rng.below(3) {
                    0 => 0,
                    1 => 0xff,
                    _ => rng.next() as u8,
                };
            }
        }
        mounted += exercise(MemDisk(Arc::new(Mutex::new(img)))) as usize;
        let _ = round;
    }
    assert!(mounted > rounds / 4, "{mounted} of {rounds} damaged images mounted");
}

#[test]
fn damaged_fat12_images() {
    fuzz(1000, false, 1500, 0x1234_5678_9abc_def1);
}

#[test]
fn damaged_fat16_images() {
    fuzz(4200, true, 300, 0x0fed_cba9_8765_4321);
}

#[test]
fn garbage_boot_sectors_do_not_mount() {
    let mut rng = Rng(42);
    for _ in 0..500 {
        let mut img = vec![0u8; 64 * 512];
        for b in img.iter_mut().take(512) {
            *b = rng.next() as u8;
        }
        img[510..512].copy_from_slice(&[0x55, 0xaa]);
        let _ = exercise(MemDisk(Arc::new(Mutex::new(img))));
    }
}
