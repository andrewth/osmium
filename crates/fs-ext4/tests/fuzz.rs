#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Mounting an image with corrupted metadata, then walking and reading the
//! whole tree and trying writes, fails with an error at worst: no panic and
//! no endless loop. Images come from `mkfs.ext*` and are filled by the driver
//! itself (skipped, with a note, if e2fsprogs is missing); the corruption is
//! pseudo-random from a fixed seed, so a failure repeats.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use osmium_fs::{Errno, File, FileKind};
use osmium_fs_ext4::Ext2;
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

/// xorshift64*: enough randomness for flipping bytes, and the same every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("osmium-ext4-fuzz-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// A fresh image made by `mkfs.<kind>`, or `None` if it is not installed.
fn mkfs(name: &str, kind: &str, args: &[&str]) -> Option<Vec<u8>> {
    let path = scratch(&format!("{name}.img"));
    std::fs::write(&path, vec![0u8; 16 << 20]).unwrap();
    let status = Command::new(format!("mkfs.{kind}"))
        .args(["-q", "-F", "-b", "1024", "-I", "256"])
        .args(args)
        .arg(&path)
        .status()
        .ok()?;
    assert!(status.success());
    Some(std::fs::read(&path).unwrap())
}

fn populate(disk: &MemDisk, clean: bool) {
    let fs = Ext2::mount(disk.clone(), 1).unwrap();
    let root = fs.root().unwrap();
    let file = |dir: &Arc<dyn File>, name: &str, len: usize, at: u64| {
        let f = dir.create(name, FileKind::Regular, 0o644).unwrap();
        let data: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        assert_eq!(f.write(at, &data).unwrap(), len);
    };
    file(&root, "small", 100, 0);
    file(&root, "big", 300 << 10, 0);
    file(&root, "sparse", 3000, 5 << 20);
    root.create("fast", FileKind::Symlink, 0o777).unwrap().write(0, b"small").unwrap();
    root.create("slow", FileKind::Symlink, 0o777).unwrap().write(0, &[b'a'; 100]).unwrap();
    let many = root.create("many", FileKind::Directory, 0o755).unwrap();
    for i in 0..80 {
        file(&many, &format!("file-number-{i:04}-with-a-longish-name"), 10 + i, 0);
    }
    let sub = many.create("sub", FileKind::Directory, 0o755).unwrap();
    file(&sub, "inner", 5000, 0);
    many.remove("file-number-0003-with-a-longish-name", false).unwrap();
    drop((root, many, sub));
    if clean {
        let Ok(_) = fs.into_device() else { panic!("a node is still open") };
    }
    // Otherwise the journal is left for the next mount to replay.
}

static ITERATION: AtomicUsize = AtomicUsize::new(0);
static MOUNTED: AtomicUsize = AtomicUsize::new(0);

/// Walks the whole tree, reading everything, with every loop capped.
fn walk(dir: &Arc<dyn File>, depth: usize, budget: &mut usize) {
    for i in 0..400 {
        let Ok(Some(entry)) = dir.readdir(i) else { break };
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let Ok(node) = dir.lookup(&entry.name) else { continue };
        let _ = node.try_stat();
        match entry.kind {
            FileKind::Directory if depth < 8 => walk(&node, depth + 1, budget),
            FileKind::Symlink => {
                let _ = node.readlink();
            }
            FileKind::Regular => {
                let mut buf = vec![0u8; 4096];
                let mut off = 0u64;
                for _ in 0..600 {
                    match node.read(off, &mut buf) {
                        Ok(n) if n > 0 => off += n as u64,
                        _ => break,
                    }
                }
                // A far-away read, which crosses holes and indirect blocks.
                let _ = node.read(5 << 20, &mut buf);
            }
            _ => {}
        }
    }
}

/// Tries every kind of write in the tree.
fn mutate(root: &Arc<dyn File>, budget: &mut usize) {
    for i in 0..60 {
        let Ok(Some(entry)) = root.readdir(i) else { break };
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let Ok(node) = root.lookup(&entry.name) else { continue };
        match entry.kind {
            FileKind::Regular => {
                let _ = node.write(0, &[1; 3000]);
                let _ = node.write(1 << 20, &[2; 100]);
                let _ = node.truncate(10);
                let _ = node.truncate(40_000);
                let _ = node.truncate(0);
            }
            FileKind::Directory => {
                let _ = node.create("fuzz-file", FileKind::Regular, 0o600).map(|f| f.write(0, &[3; 5000]));
                let _ = node.create("fuzz-dir", FileKind::Directory, 0o700);
                let _ = node.remove("fuzz-dir", true);
                let _ = node.remove("fuzz-file", false);
                let _ = mutate_dir(&node, budget);
            }
            _ => {}
        }
        let _ = root.remove(&entry.name, entry.kind == FileKind::Directory);
    }
    let _ = root.create("after", FileKind::Regular, 0o644).map(|f| f.write(0, &[4; 70_000]));
    let _ = root.create("link", FileKind::Symlink, 0o777).map(|f| f.write(0, b"x"));
}

fn mutate_dir(dir: &Arc<dyn File>, budget: &mut usize) -> Result<(), Errno> {
    for i in 0..10 {
        let Some(entry) = dir.readdir(i)? else { break };
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let _ = dir.remove(&entry.name, entry.kind == FileKind::Directory);
    }
    Ok(())
}

fn exercise(image: Vec<u8>) {
    let disk = MemDisk(Arc::new(Mutex::new(image)));
    let Ok(fs) = Ext2::mount(disk, 1) else { return };
    MOUNTED.fetch_add(1, Ordering::SeqCst);
    let Ok(root) = fs.root() else { return };
    let mut budget = 3000;
    walk(&root, 0, &mut budget);
    let mut budget = 300;
    mutate(&root, &mut budget);
    let mut budget = 3000;
    walk(&root, 0, &mut budget);
    drop(root);
    let _ = fs.into_device();
}

/// Flips bytes of `image` in places that hold metadata or data.
fn corrupt(image: &mut [u8], used: &[usize], rng: &mut Rng) {
    let n = 1 + rng.below(6);
    for _ in 0..n {
        let at = match rng.below(4) {
            // The superblock and group descriptors.
            0 => 1024 + rng.below(4096),
            // The first blocks, with bitmaps and inode tables.
            1 => rng.below(96 << 10),
            // Any block that holds something.
            _ => used[rng.below(used.len())] * 1024 + rng.below(1024),
        };
        let Some(b) = image.get_mut(at) else { continue };
        *b = match rng.below(4) {
            0 => !*b,
            1 => 0,
            2 => 0xff,
            _ => rng.next() as u8,
        };
    }
}

fn fuzz(name: &str, kind: &str, args: &[&str], clean: bool, seed: u64, iterations: usize) {
    let Some(image) = mkfs(name, kind, args) else {
        eprintln!("mkfs.{kind} not found; skipping");
        return;
    };
    let disk = MemDisk(Arc::new(Mutex::new(image)));
    populate(&disk, clean);
    let image = disk.0.lock().unwrap().clone();
    // The untouched image mounts and walks without trouble.
    exercise(image.clone());
    let used: Vec<usize> =
        (0..image.len() / 1024).filter(|&b| image[b * 1024..(b + 1) * 1024].iter().any(|&x| x != 0)).collect();
    let mut rng = Rng(seed);
    for i in 0..iterations {
        ITERATION.store(i, Ordering::SeqCst);
        let mut bad = image.clone();
        corrupt(&mut bad, &used, &mut rng);
        let dump = bad.clone();
        if std::panic::catch_unwind(|| exercise(bad)).is_err() {
            let path = scratch(&format!("{name}-{clean}-{i}.img"));
            std::fs::write(&path, dump).unwrap();
            panic!("{name} (clean: {clean}) iteration {i} panicked; image saved at {}", path.display());
        }
    }
    eprintln!("{name}: {} of {iterations} corrupted images mounted", MOUNTED.swap(0, Ordering::SeqCst));
}

/// An endless loop would hang the test run; this turns it into a failure.
fn watchdog() {
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(600));
        eprintln!("hung at iteration {}", ITERATION.load(Ordering::SeqCst));
        std::process::abort();
    });
}

/// Iterations per image; set `OSMIUM_FUZZ_ITERS` to search longer, and
/// `OSMIUM_FUZZ_SEED` to search elsewhere.
fn iterations() -> usize {
    std::env::var("OSMIUM_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(400)
}

fn seed(base: u64) -> u64 {
    base ^ std::env::var("OSMIUM_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        .wrapping_mul(0x9e37_79b9)
}

#[test]
fn corrupted_ext2_never_panics() {
    watchdog();
    fuzz("ext2", "ext2", &[], true, seed(0x5eed_0001), iterations());
}

#[test]
fn corrupted_ext3_never_panics() {
    watchdog();
    fuzz("ext3", "ext3", &[], false, seed(0x5eed_0002), iterations());
}

#[test]
fn corrupted_ext4_never_panics() {
    watchdog();
    fuzz("ext4", "ext4", &["-O", "^metadata_csum,^64bit"], false, seed(0x5eed_0003), iterations());
    fuzz("ext4-clean", "ext4", &["-O", "^metadata_csum,^64bit"], true, seed(0x5eed_0004), iterations());
}

#[test]
fn corrupted_ext4_with_checksums_never_panics() {
    watchdog();
    fuzz("ext4csum", "ext4", &["-O", "metadata_csum,64bit"], false, seed(0x5eed_0005), iterations());
}

#[test]
fn corrupted_ext4_with_meta_bg_never_panics() {
    watchdog();
    fuzz(
        "ext4meta",
        "ext4",
        &["-O", "^metadata_csum,meta_bg,^resize_inode,uninit_bg"],
        true,
        seed(0x5eed_0006),
        iterations(),
    );
}
