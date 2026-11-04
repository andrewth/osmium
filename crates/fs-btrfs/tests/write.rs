#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Writing: changes made through the driver to images from `mkfs.btrfs`,
//! checked by `btrfs check` and read back, by this driver and by
//! `btrfs restore`. Skipped, with a note, if the tools are missing.

use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use osmium_fs::{Errno, File, FileKind, OpenFlags, Vfs};
use osmium_fs_btrfs::{BtrfsFs, MountOptions};
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

#[test]
fn first_file() {
    let dir = scratch("first");
    let Some(img) = mkfs(&dir, 128 << 20, &[]) else { return };
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        put(&vfs, "/hello.txt", b"hello from osmium\n");
        assert_eq!(cat(&vfs, "/hello.txt"), b"hello from osmium\n");
    }
    check(&img);
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    assert_eq!(names(&*vfs.lookup("/").unwrap()), ["hello.txt"]);
    assert_eq!(cat(&vfs, "/hello.txt"), b"hello from osmium\n");
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

/// Checks `btrfs restore`'s copy of the volume against `model`.
fn restore_matches(dir: &Path, img: &Path, model: &Model) {
    let out = dir.join("restored");
    let _ = std::fs::remove_dir_all(&out);
    std::fs::create_dir_all(&out).unwrap();
    let r = Command::new(tool("btrfs").unwrap()).args(["restore", "-S"]).arg(img).arg(&out).output().unwrap();
    assert!(r.status.success(), "btrfs restore: {}", String::from_utf8_lossy(&r.stderr));
    for (k, v) in model {
        let p = out.join(k.trim_start_matches('/'));
        match v {
            Want::File(data) => assert!(std::fs::read(&p).unwrap() == *data, "restored {k} differs"),
            Want::Dir => assert!(p.is_dir(), "restored {k} is not a directory"),
            Want::Link(t) => assert_eq!(std::fs::read_link(&p).unwrap().to_str().unwrap(), t),
            Want::Fifo => {}
        }
    }
    std::fs::remove_dir_all(&out).unwrap();
}

/// Checks the image three ways: `btrfs check`, a fresh mount, `btrfs restore`.
fn verify(dir: &Path, img: &Path, model: &Model) {
    check(img);
    let fs = mount(img);
    compare(&Vfs::new(fs.root()), model);
    drop(fs);
    restore_matches(dir, img, model);
}

#[test]
fn many_operations() {
    let dir = scratch("many");
    // Small tree blocks so that leaves and nodes split and merge often.
    let Some(img) = mkfs(&dir, 256 << 20, &["-n", "4096"]) else { return };
    let mut model = Model::new();

    // Phase 1: directories and many files.
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        for d in ["/a", "/a/b", "/a/b/c", "/many"] {
            vfs.mkdir(d, 0o755).unwrap();
            model.insert(d.into(), Want::Dir);
        }
        for i in 0..1500 {
            let path = format!("/many/file-with-a-long-name-{i:05}");
            let data = pattern(i % 300 + 1, i as u8);
            put(&vfs, &path, &data);
            model.insert(path, Want::File(data));
        }
        let big = pattern(3 << 20, 9);
        put(&vfs, "/a/big", &big);
        model.insert("/a/big".into(), Want::File(big));
        put(&vfs, "/a/b/c/small", b"tiny");
        model.insert("/a/b/c/small".into(), Want::File(b"tiny".to_vec()));
        vfs.symlink("../big", "/a/b/up").unwrap();
        model.insert("/a/b/up".into(), Want::Link("../big".into()));
        vfs.mknod("/fifo", FileKind::Fifo, 0o600).unwrap();
        model.insert("/fifo".into(), Want::Fifo);
    }
    verify(&dir, &img, &model);

    // Phase 2: overwrite, extend, truncate, holes.
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        let f = vfs.open("/a/big", OpenFlags::READ | OpenFlags::WRITE, 0).unwrap();
        let Want::File(big) = model.get_mut("/a/big").unwrap() else { unreachable!() };
        for (off, len, seed) in [
            (5000usize, 100usize, 1u8),
            (4096, 4096, 2),
            (1 << 20, 300_000, 3),
            (3 << 20, 10, 4),
            ((3 << 20) + 9000, 5, 5),
        ] {
            let data = pattern(len, seed);
            assert_eq!(f.write(off as u64, &data).unwrap(), len);
            if big.len() < off + len {
                big.resize(off + len, 0);
            }
            big[off..off + len].copy_from_slice(&data);
        }
        f.truncate(2_000_001).unwrap();
        big.truncate(2_000_001);
        f.truncate(2_100_000).unwrap();
        big.resize(2_100_000, 0);
        assert_eq!(read_all(&*f), *big);
        // A small file grows past its inline size, and one shrinks to nothing.
        let s = vfs.open("/a/b/c/small", OpenFlags::WRITE, 0).unwrap();
        s.write(10_000, b"far").unwrap();
        let mut want = b"tiny".to_vec();
        want.resize(10_003, 0);
        want[10_000..].copy_from_slice(b"far");
        model.insert("/a/b/c/small".into(), Want::File(want));
        vfs.open("/many/file-with-a-long-name-00007", OpenFlags::WRITE | OpenFlags::TRUNC, 0).unwrap();
        model.insert("/many/file-with-a-long-name-00007".into(), Want::File(Vec::new()));
    }
    verify(&dir, &img, &model);

    // Phase 3: unlink, rmdir, rename, hard links, xattrs.
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        for i in (0..1500).step_by(3) {
            let path = format!("/many/file-with-a-long-name-{i:05}");
            vfs.unlink(&path).unwrap();
            model.remove(&path);
        }
        assert_eq!(vfs.rmdir("/a/b").err(), Some(Errno::ENOTEMPTY));
        vfs.rename("/a/b/c", "/c").unwrap();
        let moved: Vec<_> = model.keys().filter(|k| k.starts_with("/a/b/c")).cloned().collect();
        for k in moved {
            let v = model.remove(&k).unwrap();
            model.insert(k.replacen("/a/b/c", "/c", 1), v);
        }
        assert_eq!(vfs.rename("/a", "/a/b/inside").err(), Some(Errno::EINVAL));
        vfs.rename("/many/file-with-a-long-name-00001", "/many/file-with-a-long-name-00002").unwrap();
        let v = model.remove("/many/file-with-a-long-name-00001").unwrap();
        model.insert("/many/file-with-a-long-name-00002".into(), v);
        vfs.link("/c/small", "/a/hard").unwrap();
        let v = model["/c/small"].clone();
        model.insert("/a/hard".into(), v);
        assert_eq!(vfs.stat("/a/hard", true).unwrap().nlink, 2);
        vfs.unlink("/a/b/up").unwrap();
        model.remove("/a/b/up");
        vfs.rmdir("/a/b").unwrap();
        model.remove("/a/b");
        let f = vfs.lookup("/a/big").unwrap();
        f.xattr_set(b"user.one", b"1", osmium_fs::XattrSet::Any).unwrap();
        f.xattr_set(b"user.two", &pattern(500, 1), osmium_fs::XattrSet::Create).unwrap();
        assert_eq!(f.xattr_set(b"user.two", b"x", osmium_fs::XattrSet::Create).err(), Some(Errno::EEXIST));
        f.xattr_set(b"user.two", b"replaced", osmium_fs::XattrSet::Replace).unwrap();
        f.xattr_remove(b"user.one").unwrap();
        assert_eq!(f.xattr_get(b"user.two").unwrap(), b"replaced");
        assert_eq!(f.xattr_get(b"user.one").err(), Some(Errno::ENODATA));
    }
    verify(&dir, &img, &model);

    // Phase 4: delete nearly everything.
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        let files: Vec<_> = model.iter().filter(|(_, v)| !matches!(v, Want::Dir)).map(|(k, _)| k.clone()).collect();
        for k in files {
            vfs.unlink(&k).unwrap();
            model.remove(&k);
        }
        let mut dirs: Vec<_> = model.keys().cloned().collect();
        dirs.sort_by_key(|d| std::cmp::Reverse(d.len()));
        for d in dirs {
            vfs.rmdir(&d).unwrap();
            model.remove(&d);
        }
        assert!(names(&*vfs.lookup("/").unwrap()).is_empty());
    }
    verify(&dir, &img, &model);
    let _ = MountOptions::default();
}

#[test]
fn fills_up_and_frees() {
    let dir = scratch("full");
    // An 8 MiB data chunk to start with: writing needs new chunks.
    let Some(img) = mkfs(&dir, 160 << 20, &[]) else { return };
    let mut model = Model::new();
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        let mut i = 0;
        loop {
            let path = format!("/f{i}");
            let data = pattern(4 << 20, i as u8);
            let f = vfs.open(&path, OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
            match f.write(0, &data) {
                Ok(_) => {
                    model.insert(path, Want::File(data));
                    i += 1;
                }
                Err(Errno::ENOSPC) => {
                    model.insert(path, Want::File(Vec::new()));
                    break;
                }
                Err(e) => panic!("write {i}: {e:?}"),
            }
            assert!(i < 100, "never full");
        }
        assert!(i > 10, "full after {i} files");
    }
    verify(&dir, &img, &model);
    {
        // Free half, then fill again.
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        let paths: Vec<String> = model.keys().cloned().collect();
        for p in paths.iter().step_by(2) {
            vfs.unlink(p).unwrap();
            model.remove(p);
        }
        for i in 0..5 {
            let path = format!("/again{i}");
            let data = pattern(4 << 20, 100 + i as u8);
            put(&vfs, &path, &data);
            model.insert(path, Want::File(data));
        }
    }
    verify(&dir, &img, &model);
}

/// The tree `mkfs --rootdir` gets in `edit_existing`.
fn source(dir: &Path) -> (PathBuf, Model) {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("d")).unwrap();
    let mut model = Model::new();
    model.insert("/d".into(), Want::Dir);
    let text: Vec<u8> = (0..).flat_map(|i| format!("line {i} of text\n").into_bytes()).take(900_000).collect();
    for (name, data) in
        [("inline", b"short".to_vec()), ("text", text), ("d/pat", pattern(400_000, 3)), ("empty", Vec::new())]
    {
        std::fs::write(src.join(name), &data).unwrap();
        model.insert(format!("/{name}"), Want::File(data));
    }
    std::os::unix::fs::symlink("text", src.join("link")).unwrap();
    model.insert("/link".into(), Want::Link("text".into()));
    (src, model)
}

/// Overwrites, extends, truncates and deletes in a volume `mkfs --rootdir`
/// filled (inline, compressed and plain extents).
fn edit_existing(name: &str, args: &[&str]) {
    let dir = scratch(name);
    let (src, mut model) = source(&dir);
    let mut a = vec!["--rootdir", src.to_str().unwrap()];
    a.extend_from_slice(args);
    let Some(img) = mkfs(&dir, 128 << 20, &a) else { return };
    check(&img);
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        compare(&vfs, &model);
        let edit = |model: &mut Model, path: &str, off: usize, data: &[u8]| {
            let f = vfs.open(path, OpenFlags::WRITE, 0).unwrap();
            f.write(off as u64, data).unwrap();
            let Some(Want::File(v)) = model.get_mut(path) else { unreachable!() };
            if v.len() < off + data.len() {
                v.resize(off + data.len(), 0);
            }
            v[off..off + data.len()].copy_from_slice(data);
        };
        edit(&mut model, "/inline", 2, b"ORT and longer");
        edit(&mut model, "/text", 200_000, &pattern(1000, 7));
        edit(&mut model, "/text", 899_990, b"past the old end");
        edit(&mut model, "/d/pat", 0, b"start");
        edit(&mut model, "/empty", 70_000, b"x");
        let t = vfs.open("/text", OpenFlags::WRITE, 0).unwrap();
        t.truncate(333_333).unwrap();
        let Some(Want::File(v)) = model.get_mut("/text") else { unreachable!() };
        v.truncate(333_333);
        vfs.unlink("/d/pat").unwrap();
        model.remove("/d/pat");
    }
    verify(&dir, &img, &model);
}

#[test]
fn edits_plain_images() {
    edit_existing("plain", &[]);
}

#[test]
fn edits_compressed_images() {
    for algo in ["zlib", "lzo", "zstd"] {
        eprintln!("--compress {algo}");
        edit_existing(&format!("compressed-{algo}"), &["--compress", algo]);
    }
}

#[test]
fn edits_other_layouts() {
    for args in [
        &["--csum", "xxhash"][..],
        &["-n", "65536"],
        &["-d", "dup"],
        &["-m", "single"],
        &["-O", "^free-space-tree"],
        &["-O", "block-group-tree"],
    ] {
        eprintln!("{args:?}");
        edit_existing(&format!("layout{}", args.join("").replace(['-', '^'], "")), args);
    }
}

#[test]
fn open_files_outlive_unlink() {
    let dir = scratch("orphan");
    let Some(img) = mkfs(&dir, 128 << 20, &[]) else { return };
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        put(&vfs, "/kept", &pattern(100_000, 1));
        let f = vfs.lookup("/kept").unwrap();
        vfs.unlink("/kept").unwrap();
        assert_eq!(vfs.lookup("/kept").err(), Some(Errno::ENOENT));
        // Still readable and writable while open.
        assert_eq!(read_all(&*f), pattern(100_000, 1));
        f.write(0, b"still here").unwrap();
        assert_eq!(f.stat().nlink, 0);
        // The orphan item is on disk meanwhile.
        check(&img);
        drop(f);
    }
    check(&img);
    {
        // An orphan left by a "crash" is deleted at the next mount.
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        put(&vfs, "/lost", &pattern(50_000, 2));
        let f = vfs.lookup("/lost").unwrap();
        vfs.unlink("/lost").unwrap();
        std::mem::forget(f);
    }
    let fs = mount(&img);
    drop(fs);
    check(&img);
    let fs = mount(&img);
    assert!(names(&*fs.root()).is_empty());
}

#[test]
fn read_only_mounts_and_subvolumes() {
    let dir = scratch("ro");
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("ro")).unwrap();
    std::fs::create_dir_all(src.join("rw")).unwrap();
    std::fs::write(src.join("ro/f"), b"frozen").unwrap();
    let Some(img) = mkfs(&dir, 128 << 20, &["--rootdir", src.to_str().unwrap(), "-u", "ro:ro", "-u", "rw:rw"]) else {
        return;
    };
    {
        let fs =
            BtrfsFs::mount_with(FileDisk::open(&img, 4096), 9, MountOptions { subvol: None, read_only: true }).unwrap();
        assert!(fs.is_read_only());
        let vfs = Vfs::new(fs.root());
        assert_eq!(vfs.mkdir("/x", 0o755).err(), Some(Errno::EROFS));
    }
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    // A read-only subvolume refuses changes; a writable one takes them.
    assert_eq!(vfs.open("/ro/g", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).err(), Some(Errno::EROFS));
    assert_eq!(vfs.open("/ro/f", OpenFlags::WRITE, 0).unwrap().write(0, b"x").err(), Some(Errno::EROFS));
    put(&vfs, "/rw/new", b"fresh");
    vfs.mkdir("/top", 0o755).unwrap();
    // Subvolumes cannot be renamed or removed here.
    assert_eq!(vfs.rename("/rw", "/rw2").err(), Some(Errno::EPERM));
    assert_eq!(vfs.rmdir("/rw").err(), Some(Errno::EPERM));
    // Nor can files move between subvolumes.
    assert_eq!(vfs.rename("/rw/new", "/top/new").err(), Some(Errno::EXDEV));
    drop(vfs);
    drop(fs);
    check(&img);
    let fs = mount(&img);
    let vfs = Vfs::new(fs.root());
    assert_eq!(cat(&vfs, "/rw/new"), b"fresh");
    assert_eq!(cat(&vfs, "/ro/f"), b"frozen");
}

#[test]
fn metadata_full_can_still_delete() {
    let dir = scratch("metafull");
    // Files with big extended attributes fill metadata, not data: with 64 KiB
    // tree blocks, a leaf each.
    let Some(img) = mkfs(&dir, 128 << 20, &["-n", "65536"]) else { return };
    let mut made = Vec::new();
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        // Most of the device goes to data first, so metadata fills sooner.
        put(&vfs, "/bulk", &pattern(30 << 20, 1));
        made.push("/bulk".to_string());
        let long = "n".repeat(200);
        let mut full = false;
        for i in 0..200_000 {
            let path = format!("/{long}{i}");
            match vfs.open(&path, OpenFlags::WRITE | OpenFlags::CREATE, 0o644) {
                Ok(f) => {
                    made.push(path);
                    if let Err(e) = f.xattr_set(b"user.pad", &[1u8; 60_000], osmium_fs::XattrSet::Any) {
                        assert_eq!(e, Errno::ENOSPC);
                        full = true;
                        break;
                    }
                }
                Err(e) => {
                    assert_eq!(e, Errno::ENOSPC);
                    full = true;
                    break;
                }
            }
        }
        assert!(full, "never ran out of space");
        // Deleting must work even so.
        for p in &made {
            vfs.unlink(p).unwrap();
        }
        assert!(names(&*vfs.lookup("/").unwrap()).is_empty());
        put(&vfs, "/after", b"room again");
    }
    check(&img);
    let fs = mount(&img);
    assert_eq!(cat(&Vfs::new(fs.root()), "/after"), b"room again");
}

#[test]
fn removed_open_directory_takes_no_new_names() {
    let dir = scratch("rmdir-open");
    let Some(img) = mkfs(&dir, 128 << 20, &[]) else { return };
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        vfs.mkdir("/d", 0o755).unwrap();
        put(&vfs, "/f", b"file");
        let d = vfs.lookup("/d").unwrap();
        vfs.rmdir("/d").unwrap();
        // Still open, but gone: nothing may be named in it.
        assert_eq!(d.create("x", FileKind::Regular, 0o644).err(), Some(Errno::ENOENT));
        let root = vfs.lookup("/").unwrap();
        assert_eq!(root.rename("f", &*d, "g").err(), Some(Errno::ENOENT));
        assert_eq!(d.link("h", &*vfs.lookup("/f").unwrap()).err(), Some(Errno::ENOENT));
        drop(d);
    }
    check(&img);
    let fs = mount(&img);
    assert_eq!(names(&*fs.root()), ["f"]);
}

/// The file extent types in the default tree, as `btrfs inspect-internal
/// dump-tree` shows them: (inline, regular, prealloc).
fn extent_types(img: &Path) -> (usize, usize, usize) {
    let out = Command::new(tool("btrfs").unwrap())
        .args(["inspect-internal", "dump-tree", "-t", "5"])
        .arg(img)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let n = |ty: &str| text.matches(&format!("({ty})")).count();
    (n("inline"), n("regular"), n("prealloc"))
}

fn set(model: &mut Model, path: &str, off: usize, data: &[u8]) {
    let Want::File(v) = model.entry(path.into()).or_insert(Want::File(Vec::new())) else { unreachable!() };
    if v.len() < off + data.len() {
        v.resize(off + data.len(), 0);
    }
    v[off..off + data.len()].copy_from_slice(data);
}

fn resize(model: &mut Model, path: &str, len: usize) {
    let Some(Want::File(v)) = model.get_mut(path) else { unreachable!() };
    v.resize(len, 0);
}

#[test]
fn inline_extents() {
    let dir = scratch("inline");
    let Some(img) = mkfs(&dir, 128 << 20, &[]) else { return };
    let mut model = Model::new();
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        for (i, len) in [1usize, 100, 2047, 2048].into_iter().enumerate() {
            let p = format!("/small{i}");
            put(&vfs, &p, &pattern(len, i as u8));
            set(&mut model, &p, 0, &pattern(len, i as u8));
        }
        put(&vfs, "/big", &pattern(2049, 9));
        set(&mut model, "/big", 0, &pattern(2049, 9));
        put(&vfs, "/empty", b"");
        set(&mut model, "/empty", 0, b"");
        // Appends and overwrites that stay inline.
        let f = vfs.open("/small0", OpenFlags::WRITE, 0).unwrap();
        f.write(1, b"appended").unwrap();
        set(&mut model, "/small0", 1, b"appended");
        f.write(3, b"XY").unwrap();
        set(&mut model, "/small0", 3, b"XY");
        // Truncating down stays inline; to zero removes the extent.
        vfs.open("/small1", OpenFlags::WRITE, 0).unwrap().truncate(40).unwrap();
        resize(&mut model, "/small1", 40);
        let f = vfs.open("/small2", OpenFlags::WRITE, 0).unwrap();
        f.truncate(0).unwrap();
        resize(&mut model, "/small2", 0);
        f.write(0, b"again").unwrap();
        set(&mut model, "/small2", 0, b"again");
    }
    check(&img);
    // small0..small3 are inline; `big` and `empty` are not.
    assert_eq!(extent_types(&img).0, 4, "inline extents");
    verify(&dir, &img, &model);
    {
        // Transitions to regular extents: past the limit, past a hole,
        // truncating up, and a write inside a file that was inline.
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        vfs.open("/small3", OpenFlags::WRITE, 0).unwrap().write(2048, &pattern(3000, 4)).unwrap();
        set(&mut model, "/small3", 2048, &pattern(3000, 4));
        vfs.open("/small0", OpenFlags::WRITE, 0).unwrap().write(10_000, b"far").unwrap();
        set(&mut model, "/small0", 10_000, b"far");
        vfs.open("/small1", OpenFlags::WRITE, 0).unwrap().truncate(9000).unwrap();
        resize(&mut model, "/small1", 9000);
    }
    verify(&dir, &img, &model);
    assert_eq!(extent_types(&img).0, 1);
}

#[test]
fn preallocation() {
    let dir = scratch("prealloc");
    let Some(img) = mkfs(&dir, 128 << 20, &[]) else { return };
    let mut model = Model::new();
    {
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        let create = |p: &str| vfs.open(p, OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
        // Preallocate a new file, write into it and across its end.
        let f = create("/pre");
        fs.fallocate(&*f, 0, 1 << 20).unwrap();
        set(&mut model, "/pre", 0, &vec![0; 1 << 20]);
        assert_eq!(f.stat().size, 1 << 20);
        f.write(5000, &pattern(10_000, 1)).unwrap();
        set(&mut model, "/pre", 5000, &pattern(10_000, 1));
        f.write(1 << 19, &pattern(4096, 2)).unwrap();
        set(&mut model, "/pre", 1 << 19, &pattern(4096, 2));
        f.write((1 << 20) - 10, &pattern(100, 3)).unwrap();
        set(&mut model, "/pre", (1 << 20) - 10, &pattern(100, 3));
        // A range partly with data: the data stays.
        let g = create("/mixed");
        g.write(0, &pattern(8192, 5)).unwrap();
        set(&mut model, "/mixed", 0, &pattern(8192, 5));
        g.write(40_000, &pattern(100, 6)).unwrap();
        set(&mut model, "/mixed", 40_000, &pattern(100, 6));
        fs.fallocate(&*g, 4096, 100_000).unwrap();
        resize(&mut model, "/mixed", 104_096);
        // An inline file, preallocated.
        let h = create("/small");
        h.write(0, b"tiny").unwrap();
        set(&mut model, "/small", 0, b"tiny");
        fs.fallocate(&*h, 0, 20_000).unwrap();
        resize(&mut model, "/small", 20_000);
        assert_eq!(fs.fallocate(&*vfs.lookup("/").unwrap(), 0, 10), Err(Errno::EISDIR));
        // Punch holes: whole sectors, partial ends, inside one sector.
        let p = create("/punch");
        p.write(0, &pattern(200_000, 8)).unwrap();
        set(&mut model, "/punch", 0, &pattern(200_000, 8));
        fs.punch_hole(&*p, 10_000, 100_000).unwrap();
        set(&mut model, "/punch", 10_000, &vec![0; 100_000]);
        fs.punch_hole(&*p, 150_000, 50).unwrap();
        set(&mut model, "/punch", 150_000, &[0; 50]);
        fs.punch_hole(&*p, 190_000, 1_000_000).unwrap();
        set(&mut model, "/punch", 190_000, &vec![0; 10_000]);
        assert_eq!(p.stat().size, 200_000);
        let s = create("/punch-small");
        s.write(0, b"0123456789").unwrap();
        fs.punch_hole(&*s, 2, 3).unwrap();
        set(&mut model, "/punch-small", 0, b"01\0\0\x0056789");
        compare(&vfs, &model);
    }
    verify(&dir, &img, &model);
    assert!(extent_types(&img).2 > 0, "prealloc extents");
    {
        // Truncate through preallocated ranges, remove a file with them.
        let fs = mount(&img);
        let vfs = Vfs::new(fs.root());
        vfs.open("/pre", OpenFlags::WRITE, 0).unwrap().truncate(300_001).unwrap();
        resize(&mut model, "/pre", 300_001);
        vfs.open("/mixed", OpenFlags::WRITE, 0).unwrap().truncate(0).unwrap();
        resize(&mut model, "/mixed", 0);
        vfs.unlink("/small").unwrap();
        model.remove("/small");
    }
    verify(&dir, &img, &model);
}
