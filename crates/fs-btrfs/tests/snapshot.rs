// SPDX-License-Identifier: GPL-2.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Snapshots and subvolumes: created, written, and deleted through the
//! driver, checked by `btrfs check` and read back. Skipped, with a note, if
//! btrfs-progs is missing.

use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use osmium_fs::{Errno, File, FileKind, OpenFlags, Vfs};
use osmium_fs_btrfs::BtrfsFs;
use osmium_hal::block::{BlockDevice, BlockError};

/// An image file, read and written in `block`-byte blocks.
#[derive(Clone)]
struct FileDisk {
    file: Arc<std::fs::File>,
    block: usize,
    len: u64,
}

impl FileDisk {
    fn open(path: &Path, block: usize) -> Self {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        let len = file.metadata().unwrap().len();
        FileDisk { file: Arc::new(file), block, len }
    }
}

impl BlockDevice for FileDisk {
    fn block_size(&self) -> usize {
        self.block
    }
    fn num_blocks(&self) -> u64 {
        self.len / self.block as u64
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.file.read_exact_at(buf, lba * self.block as u64).map_err(|_| BlockError::Io)
    }
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.file.write_all_at(buf, lba * self.block as u64).map_err(|_| BlockError::Io)
    }
}

fn tool(name: &str) -> Option<PathBuf> {
    let found = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|d| Path::new(d).join(name)).find(|p| p.exists());
    if found.is_none() {
        eprintln!("{name} not found; skipping");
    }
    found
}

/// A directory of its own for one test, removed when dropped.
struct Scratch(PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // OSMIUM_KEEP_SCRATCH keeps the images for a look with `btrfs inspect-internal`.
        if std::env::var_os("OSMIUM_KEEP_SCRATCH").is_none() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-w-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// A fresh `size`-byte image made with `args`.
fn mkfs(dir: &Path, size: u64, args: &[&str]) -> Option<PathBuf> {
    let mkfs = tool("mkfs.btrfs")?;
    tool("btrfs")?;
    let img = dir.join("img");
    let _ = std::fs::remove_file(&img);
    std::fs::File::create(&img).unwrap().set_len(size).unwrap();
    let out = Command::new(mkfs).arg("-q").args(args).arg(&img).output().unwrap();
    assert!(out.status.success(), "mkfs.btrfs {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    Some(img)
}

/// `btrfs check` must find nothing wrong.
fn check(img: &Path) {
    let out = Command::new(tool("btrfs").unwrap())
        .args(["check", "--readonly", "--check-data-csum"])
        .arg(img)
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && !text.contains("ERROR"), "btrfs check:\n{text}");
}

fn mount(img: &Path) -> BtrfsFs<FileDisk> {
    let fs = BtrfsFs::mount(FileDisk::open(img, 4096), 9).unwrap();
    assert!(!fs.is_read_only());
    fs
}

fn read_all(f: &dyn File) -> Vec<u8> {
    let mut out = vec![0u8; f.stat().size as usize];
    let mut done = 0;
    while done < out.len() {
        let n = f.read(done as u64, &mut out[done..]).unwrap();
        assert!(n > 0, "short file");
        done += n;
    }
    out
}

fn cat(vfs: &Vfs, path: &str) -> Vec<u8> {
    read_all(&*vfs.open(path, OpenFlags::READ, 0).unwrap())
}

fn names(dir: &dyn File) -> Vec<String> {
    let mut v: Vec<String> = (0..).map_while(|i| dir.readdir(i).unwrap()).map(|e| e.name).collect();
    v.sort();
    v
}

fn put(vfs: &Vfs, path: &str, data: &[u8]) {
    let f = vfs.open(path, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNC, 0o644).unwrap();
    assert_eq!(f.write(0, data).unwrap(), data.len());
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 11) as u8).collect()
}

/// What the tree should hold.
#[derive(Clone, Debug, PartialEq)]
enum Want {
    File(Vec<u8>),
    Dir,
    Link(String),
    Fifo,
}

type Model = std::collections::BTreeMap<String, Want>;

/// Checks the tree under `/` against `model`, through the driver.
fn compare(vfs: &Vfs, model: &Model) {
    fn walk(vfs: &Vfs, dir: &str, out: &mut Model) {
        let d = vfs.lookup(if dir.is_empty() { "/" } else { dir }).unwrap();
        for name in names(&*d) {
            let path = format!("{dir}/{name}");
            let st = vfs.stat(&path, false).unwrap();
            let w = match st.kind {
                FileKind::Directory => {
                    walk(vfs, &path, out);
                    Want::Dir
                }
                FileKind::Symlink => Want::Link(vfs.readlink(&path).unwrap()),
                FileKind::Fifo => Want::Fifo,
                _ => Want::File(cat(vfs, &path)),
            };
            out.insert(path, w);
        }
    }
    let mut got = Model::new();
    walk(vfs, "", &mut got);
    assert_eq!(got.keys().collect::<Vec<_>>(), model.keys().collect::<Vec<_>>());
    for (k, v) in model {
        assert!(got[k] == *v, "{k} differs");
    }
}

/// The root directory of the subvolume named `path`, as a tree of its own.
fn sub(vfs: &Vfs, path: &str) -> Vfs {
    Vfs::new(vfs.lookup(path).unwrap())
}

/// Mutates `model` and the tree under `vfs` alike: overwrites, new files,
/// removals.
fn churn(vfs: &Vfs, model: &mut Model, seed: u8) {
    let files: Vec<String> = model.iter().filter(|(_, v)| matches!(v, Want::File(_))).map(|(k, _)| k.clone()).collect();
    for (n, path) in files.iter().enumerate() {
        match n % 7 {
            0 => {
                let data = pattern(n % 5000 + 1, seed.wrapping_add(n as u8));
                put(vfs, path, &data);
                model.insert(path.clone(), Want::File(data));
            }
            1 => {
                vfs.unlink(path).unwrap();
                model.remove(path);
            }
            2 => {
                let f = vfs.open(path, OpenFlags::WRITE, 0).unwrap();
                let Want::File(d) = model.get_mut(path).unwrap() else { unreachable!() };
                let patch = pattern(50, seed);
                let at = d.len() / 2;
                f.write(at as u64, &patch).unwrap();
                if d.len() < at + 50 {
                    d.resize(at + 50, 0);
                }
                d[at..at + 50].copy_from_slice(&patch);
            }
            _ => {}
        }
    }
    for i in 0..40 {
        let path = format!("/new-{seed}-{i}");
        let data = pattern(i * 300 + 10, seed);
        put(vfs, &path, &data);
        model.insert(path, Want::File(data));
    }
}

/// A subvolume with a thousand files, in tree blocks small enough to make
/// the tree several levels deep.
fn populate(vfs: &Vfs, model: &mut Model) {
    vfs.mkdir("/dir", 0o755).unwrap();
    model.insert("/dir".into(), Want::Dir);
    for i in 0..1200 {
        let path = format!("/dir/file-with-a-long-name-{i:05}");
        let data = pattern(i % 700 + 1, i as u8);
        put(vfs, &path, &data);
        model.insert(path, Want::File(data));
    }
    let big = pattern(2 << 20, 7);
    put(vfs, "/big", &big);
    model.insert("/big".into(), Want::File(big));
}

#[test]
fn create_subvolume() {
    let dir = scratch("create");
    let Some(img) = mkfs(&dir, 128 << 20, &[]) else { return };
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        put(&vfs, "/top", b"in the top level");
        let root = vfs.lookup("/").unwrap();
        let id = fs.create_subvolume(&*root, "vol").unwrap();
        assert!(id >= 256);
        assert_eq!(fs.create_subvolume(&*root, "vol").err(), Some(Errno::EEXIST));
        assert_eq!(vfs.stat("/vol", true).unwrap().kind, FileKind::Directory);
        put(&vfs, "/vol/inside", b"in the subvolume");
        vfs.mkdir("/vol/sub", 0o755).unwrap();
        put(&vfs, "/vol/sub/deeper", &pattern(100_000, 1));
        let nested = fs.create_subvolume(&*vfs.lookup("/vol/sub").unwrap(), "nested").unwrap();
        assert_eq!(nested, id + 1);
        put(&vfs, "/vol/sub/nested/x", b"nested");
        assert_eq!(fs.subvolume_id(&*vfs.lookup("/vol").unwrap()).unwrap(), id);
        assert_eq!(fs.subvolume_id(&*vfs.lookup("/vol/inside").unwrap()).err(), Some(Errno::EINVAL));
    }
    check(&img);
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    assert_eq!(cat(&vfs, "/vol/inside"), b"in the subvolume");
    assert_eq!(cat(&vfs, "/vol/sub/nested/x"), b"nested");
    assert_eq!(cat(&vfs, "/vol/sub/deeper"), pattern(100_000, 1));
    // A subvolume with another in it cannot be deleted; the inner one can.
    let root = vfs.lookup("/").unwrap();
    assert_eq!(fs.delete_subvolume(&*root, "vol").err(), Some(Errno::ENOTEMPTY));
    fs.delete_subvolume(&*vfs.lookup("/vol/sub").unwrap(), "nested").unwrap();
    fs.delete_subvolume(&*root, "vol").unwrap();
    assert_eq!(fs.delete_subvolume(&*root, "vol").err(), Some(Errno::ENOENT));
    drop(root);
    drop(vfs);
    drop(fs);
    check(&img);
}

#[test]
fn snapshot_small() {
    let dir = scratch("small");
    let Some(img) = mkfs(&dir, 128 << 20, &[]) else { return };
    let mut orig = Model::new();
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        let root = vfs.lookup("/").unwrap();
        fs.create_subvolume(&*root, "vol").unwrap();
        let v = sub(&vfs, "/vol");
        for i in 0..20 {
            let path = format!("/f{i}");
            let data = pattern(i * 1000 + 1, i as u8);
            put(&v, &path, &data);
            orig.insert(path, Want::File(data));
        }
        fs.create_snapshot(&*vfs.lookup("/vol").unwrap(), &*root, "snap", false).unwrap();
        fs.create_snapshot(&*vfs.lookup("/vol").unwrap(), &*root, "ro", true).unwrap();
        assert_eq!(fs.create_snapshot(&*vfs.lookup("/vol").unwrap(), &*root, "snap", false).err(), Some(Errno::EEXIST));
    }
    check(&img);
    let mut snap_model = orig.clone();
    let mut vol_model = orig.clone();
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        compare(&sub(&vfs, "/vol"), &orig);
        compare(&sub(&vfs, "/snap"), &orig);
        compare(&sub(&vfs, "/ro"), &orig);
        // Writing one leaves the others alone.
        let new = pattern(7777, 99);
        put(&sub(&vfs, "/vol"), "/f3", &new);
        vol_model.insert("/f3".into(), Want::File(new));
        put(&sub(&vfs, "/snap"), "/g", b"only in the snapshot");
        snap_model.insert("/g".into(), Want::File(b"only in the snapshot".to_vec()));
        sub(&vfs, "/snap").unlink("/f5").unwrap();
        snap_model.remove("/f5");
        let ro = sub(&vfs, "/ro");
        assert_eq!(ro.open("/f1", OpenFlags::WRITE, 0).and_then(|f| f.write(0, b"x")).err(), Some(Errno::EROFS));
        assert_eq!(ro.unlink("/f1").err(), Some(Errno::EROFS));
    }
    check(&img);
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    compare(&sub(&vfs, "/vol"), &vol_model);
    compare(&sub(&vfs, "/snap"), &snap_model);
    compare(&sub(&vfs, "/ro"), &orig);
    let root = vfs.lookup("/").unwrap();
    fs.delete_subvolume(&*root, "vol").unwrap();
    check(&img);
    compare(&sub(&vfs, "/snap"), &snap_model);
    fs.delete_subvolume(&*root, "ro").unwrap();
    fs.delete_subvolume(&*root, "snap").unwrap();
    drop(root);
    drop(vfs);
    drop(fs);
    check(&img);
}

/// Snapshots a big subvolume, writes to both sides, and deletes them in the
/// order given.
fn diverge(name: &str, mkfs_args: &[&str], delete_source_first: bool) {
    let dir = scratch(name);
    let Some(img) = mkfs(&dir, 256 << 20, mkfs_args) else { return };
    let mut a = Model::new();
    let mut b;
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        let root = vfs.lookup("/").unwrap();
        fs.create_subvolume(&*root, "a").unwrap();
        populate(&sub(&vfs, "/a"), &mut a);
    }
    check(&img);
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        let root = vfs.lookup("/").unwrap();
        fs.create_snapshot(&*vfs.lookup("/a").unwrap(), &*root, "b", false).unwrap();
        b = a.clone();
    }
    check(&img);
    // Several rounds, each committing separately, on each side in turn.
    for round in 0..3u8 {
        {
            let fs = mount(&img);
            let vfs = Vfs::new(fs.root());
            churn(&sub(&vfs, "/a"), &mut a, round * 2 + 1);
        }
        check(&img);
        if round == 0
            && let Some(p) = std::env::var_os("OSMIUM_SNAP_DUMP_MID")
        {
            std::fs::copy(&img, p).unwrap();
        }
        {
            let fs = mount(&img);
            let vfs = Vfs::new(fs.root());
            compare(&sub(&vfs, "/a"), &a);
            compare(&sub(&vfs, "/b"), &b);
            churn(&sub(&vfs, "/b"), &mut b, round * 2 + 2);
        }
        check(&img);
    }
    if let Some(p) = std::env::var_os("OSMIUM_SNAP_DUMP") {
        std::fs::copy(&img, p).unwrap();
    }
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    compare(&sub(&vfs, "/a"), &a);
    compare(&sub(&vfs, "/b"), &b);
    let root = vfs.lookup("/").unwrap();
    let (first, second, rest) = if delete_source_first { ("a", "b", &b) } else { ("b", "a", &a) };
    fs.delete_subvolume(&*root, first).unwrap();
    drop(root);
    drop(vfs);
    drop(fs);
    check(&img);
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    compare(&sub(&vfs, &format!("/{second}")), rest);
    // The survivor can still be written, which copies what the dead one owned.
    let mut rest = rest.clone();
    churn(&sub(&vfs, &format!("/{second}")), &mut rest, 77);
    drop(vfs);
    drop(fs);
    check(&img);
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    compare(&sub(&vfs, &format!("/{second}")), &rest);
    let root = vfs.lookup("/").unwrap();
    fs.delete_subvolume(&*root, second).unwrap();
    drop(root);
    drop(vfs);
    drop(fs);
    check(&img);
}

#[test]
fn diverge_delete_source() {
    diverge("div-src", &["-n", "4096"], true);
}

#[test]
fn diverge_delete_snapshot() {
    diverge("div-snap", &["-n", "4096"], false);
}

#[test]
fn snapshot_inside_itself() {
    let dir = scratch("inside");
    let Some(img) = mkfs(&dir, 128 << 20, &["-n", "4096"]) else { return };
    let mut model = Model::new();
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        fs.create_subvolume(&*vfs.lookup("/").unwrap(), "vol").unwrap();
        populate(&sub(&vfs, "/vol"), &mut model);
        // The snapshot goes into the tree it copies, after the copy was made.
        let vol = vfs.lookup("/vol").unwrap();
        fs.create_snapshot(&*vol, &*vol, "inner", false).unwrap();
        fs.create_snapshot(&*vol, &*vfs.lookup("/vol/dir").unwrap(), "deeper", true).unwrap();
        assert!(vfs.lookup("/vol/inner/dir/file-with-a-long-name-00001").is_ok());
        assert!(vfs.lookup("/vol/inner/inner").is_err());
        assert!(vfs.lookup("/vol/dir/deeper/dir").is_ok());
    }
    check(&img);
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    let mut inner = Model::new();
    for (k, v) in &model {
        inner.insert(k.clone(), v.clone());
    }
    compare(&sub(&vfs, "/vol/inner"), &inner);
    // Both sides change, then the snapshots go.
    churn(&sub(&vfs, "/vol/inner"), &mut inner, 5);
    churn(&sub(&vfs, "/vol"), &mut model, 6);
    drop(vfs);
    drop(fs);
    check(&img);
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    fs.delete_subvolume(&*vfs.lookup("/vol/dir").unwrap(), "deeper").unwrap();
    fs.delete_subvolume(&*vfs.lookup("/vol").unwrap(), "inner").unwrap();
    drop(vfs);
    drop(fs);
    check(&img);
}
