#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Helpers shared by the maintenance tests (scrub, balance, devices): image
//! files as block devices, `mkfs.btrfs` and `btrfs check`.

use std::collections::BTreeMap;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use osmium_fs::{File, FileKind, OpenFlags, Vfs};
use osmium_fs_btrfs::{BtrfsFs, MountOptions};
use osmium_hal::block::{BlockDevice, BlockError};

pub const B: usize = 4096;

/// Device writes in order: which device, block address and data.
pub type Log = Arc<Mutex<Vec<(usize, u64, Vec<u8>)>>>;

/// An image file, read and written in 4 KiB blocks; its writes are also
/// logged, in order, if it has a log.
#[derive(Clone)]
pub struct Disk {
    file: Arc<std::fs::File>,
    len: u64,
    tag: usize,
    log: Option<Log>,
}

impl Disk {
    pub fn open(path: &Path) -> Self {
        Self::logged(path, 0, None)
    }

    pub fn logged(path: &Path, tag: usize, log: Option<Log>) -> Self {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        let len = file.metadata().unwrap().len();
        Disk { file: Arc::new(file), len, tag, log }
    }
}

impl BlockDevice for Disk {
    fn block_size(&self) -> usize {
        B
    }
    fn num_blocks(&self) -> u64 {
        self.len / B as u64
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.file.read_exact_at(buf, lba * B as u64).map_err(|_| BlockError::Io)
    }
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        if let Some(log) = &self.log {
            log.lock().unwrap().push((self.tag, lba, buf.to_vec()));
        }
        self.file.write_all_at(buf, lba * B as u64).map_err(|_| BlockError::Io)
    }
}

pub fn tool(name: &str) -> Option<PathBuf> {
    let found = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|d| Path::new(d).join(name)).find(|p| p.exists());
    if found.is_none() {
        eprintln!("{name} not found; skipping");
    }
    found
}

/// A directory of its own for one test, removed when dropped.
pub struct Scratch(pub PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if std::env::var_os("OSMIUM_KEEP_SCRATCH").is_none() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

pub fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-m-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// A fresh `size`-byte image `name` in `dir`, made with `args`.
pub fn mkfs_named(dir: &Path, name: &str, size: u64, args: &[&str]) -> Option<PathBuf> {
    let mkfs = tool("mkfs.btrfs")?;
    tool("btrfs")?;
    let img = dir.join(name);
    let _ = std::fs::remove_file(&img);
    std::fs::File::create(&img).unwrap().set_len(size).unwrap();
    let out = Command::new(mkfs).arg("-q").args(args).arg(&img).output().unwrap();
    assert!(out.status.success(), "mkfs.btrfs {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    Some(img)
}

pub fn mkfs(dir: &Path, size: u64, args: &[&str]) -> Option<PathBuf> {
    mkfs_named(dir, "img", size, args)
}

/// An empty image file, to add as a device.
pub fn blank(dir: &Path, name: &str, size: u64) -> PathBuf {
    let img = dir.join(name);
    std::fs::File::create(&img).unwrap().set_len(size).unwrap();
    img
}

/// `btrfs check` output: `Ok` if it found nothing wrong.
pub fn try_check(img: &Path) -> Result<(), String> {
    let out = Command::new(tool("btrfs").unwrap())
        .args(["check", "--readonly", "--check-data-csum"])
        .arg(img)
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() && !text.contains("ERROR") { Ok(()) } else { Err(text) }
}

/// `btrfs check` must find nothing wrong.
pub fn check(img: &Path) {
    if let Err(text) = try_check(img) {
        panic!("btrfs check:\n{text}");
    }
}

pub fn mount(img: &Path) -> BtrfsFs<Disk> {
    let fs = BtrfsFs::mount(Disk::open(img), 9).unwrap();
    assert!(!fs.is_read_only());
    fs
}

pub fn read_all(f: &dyn File) -> Vec<u8> {
    let mut out = vec![0u8; f.stat().size as usize];
    let mut done = 0;
    while done < out.len() {
        let n = f.read(done as u64, &mut out[done..]).unwrap();
        assert!(n > 0, "short file");
        done += n;
    }
    out
}

pub fn cat(vfs: &Vfs, path: &str) -> Vec<u8> {
    read_all(&*vfs.open(path, OpenFlags::READ, 0).unwrap())
}

pub fn put(vfs: &Vfs, path: &str, data: &[u8]) {
    let f = vfs.open(path, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNC, 0o644).unwrap();
    assert_eq!(f.write(0, data).unwrap(), data.len());
}

pub fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 11) as u8).collect()
}

/// Everything under `/`: path to contents (`None` for a directory).
pub type Snapshot = BTreeMap<String, Option<Vec<u8>>>;

pub fn snapshot_fs(root: Arc<dyn File>) -> Snapshot {
    fn walk(dir: &dyn File, path: &str, out: &mut Snapshot) {
        for e in (0..).map_while(|i| dir.readdir(i).unwrap()) {
            let p = format!("{path}/{}", e.name);
            let node = dir.lookup(&e.name).unwrap();
            if e.kind == FileKind::Directory {
                walk(&*node, &p, out);
                out.insert(p, None);
            } else if e.kind == FileKind::Symlink {
                out.insert(p, Some(node.readlink().unwrap().into_bytes()));
            } else {
                out.insert(p, Some(read_all(&*node)));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(&*root, "", &mut out);
    out
}

/// `snapshot_fs` of the image read-only.
pub fn snapshot(img: &Path) -> Snapshot {
    let opts = MountOptions { subvol: None, read_only: true, ..Default::default() };
    let fs = BtrfsFs::mount_with(Disk::open(img), 1, opts).unwrap();
    snapshot_fs(fs.root())
}

/// Bytes `len` at `off` of an image.
pub fn read_at(img: &Path, off: u64, len: usize) -> Vec<u8> {
    let f = std::fs::File::open(img).unwrap();
    let mut b = vec![0u8; len];
    f.read_exact_at(&mut b, off).unwrap();
    b
}

pub fn write_at(img: &Path, off: u64, data: &[u8]) {
    let f = std::fs::OpenOptions::new().write(true).open(img).unwrap();
    f.write_all_at(data, off).unwrap();
}

/// Physical offset in `img` (single device) of logical `addr`, copy `copy`.
pub fn phys(fs: &BtrfsFs<Disk>, addr: u64, copy: usize) -> u64 {
    let c = fs.chunks().unwrap().into_iter().find(|c| c.logical <= addr && addr < c.logical + c.length).unwrap();
    c.stripes[copy].1 + (addr - c.logical)
}

/// The root tree's logical address, from the superblock.
pub fn root_addr(img: &Path) -> u64 {
    u64::from_le_bytes(read_at(img, 65536 + 80, 8).try_into().unwrap())
}

/// Bytes no two 4 KiB sectors of which are alike.
pub fn distinct(len: usize, seed: u32) -> Vec<u8> {
    (0..len / 4).flat_map(|i| (i as u32 ^ seed).wrapping_mul(2654435761).rotate_left(7).to_le_bytes()).collect()
}

/// `btrfs check` of the metadata only, which for a volume with a device
/// missing (`btrfs check` cannot open the other image of two) is as much as it
/// can look at; the warning that the device is missing is expected.
pub fn try_check_metadata(img: &Path) -> Result<(), String> {
    let out = Command::new(tool("btrfs").unwrap()).args(["check", "--readonly"]).arg(img).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() && !text.contains("ERROR") { Ok(()) } else { Err(text) }
}
