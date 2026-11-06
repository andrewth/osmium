// SPDX-License-Identifier: GPL-2.0-only
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Owners, access times, mount options, caches and batching, on images from
//! `mkfs.btrfs`, checked by `btrfs check`. Skipped, with a note, if the tools
//! are missing. (Crashes during batching are in `crash.rs`.)

use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use osmium_fs::{Errno, File, FileKind, ManualClock, OpenFlags, Timestamp, Vfs};
use osmium_fs_btrfs::{Atime, BtrfsFs, MountOptions};
use osmium_hal::block::{BlockDevice, BlockError};

const B: usize = 4096;

/// What a [`CountDisk`] has done.
#[derive(Default)]
struct Counts {
    reads: AtomicU64,
    flushes: AtomicU64,
}

/// An image file that counts reads and flushes.
#[derive(Clone)]
struct CountDisk {
    file: Arc<std::fs::File>,
    len: u64,
    counts: Arc<Counts>,
}

impl CountDisk {
    fn open(path: &Path) -> Self {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        let len = file.metadata().unwrap().len();
        CountDisk { file: Arc::new(file), len, counts: Arc::default() }
    }
}

impl BlockDevice for CountDisk {
    fn block_size(&self) -> usize {
        B
    }
    fn num_blocks(&self) -> u64 {
        self.len / B as u64
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.counts.reads.fetch_add(1, Ordering::Relaxed);
        self.file.read_exact_at(buf, lba * B as u64).map_err(|_| BlockError::Io)
    }
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.file.write_all_at(buf, lba * B as u64).map_err(|_| BlockError::Io)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        self.counts.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
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
        if std::env::var_os("OSMIUM_KEEP_SCRATCH").is_none() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-f-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// A fresh 128 MiB image made with `args`.
fn mkfs(dir: &Path, args: &[&str]) -> Option<PathBuf> {
    let mkfs = tool("mkfs.btrfs")?;
    tool("btrfs")?;
    let img = dir.join("img");
    let _ = std::fs::remove_file(&img);
    std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
    let out = Command::new(mkfs).arg("-q").args(args).arg(&img).output().unwrap();
    assert!(out.status.success(), "mkfs.btrfs {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    Some(img)
}

fn check(img: &Path) {
    let out = Command::new(tool("btrfs").unwrap())
        .args(["check", "--readonly", "--check-data-csum"])
        .arg(img)
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && !text.contains("ERROR"), "btrfs check:\n{text}");
}

fn mount_with(img: &Path, opts: MountOptions<'_>) -> (BtrfsFs<CountDisk>, Arc<Counts>) {
    let disk = CountDisk::open(img);
    let counts = disk.counts.clone();
    (BtrfsFs::mount_with(disk, 9, opts).unwrap(), counts)
}

fn put(vfs: &Vfs, path: &str, data: &[u8]) {
    let f = vfs.open(path, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNC, 0o644).unwrap();
    assert_eq!(f.write(0, data).unwrap(), data.len());
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

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 11) as u8).collect()
}

#[test]
fn owners_and_modes() {
    let dir = scratch("owners");
    let Some(img) = mkfs(&dir, &[]) else { return };
    {
        let (fs, _) = mount_with(&img, MountOptions::default());
        let vfs = Vfs::new(fs.root());
        // A file made by a caller with an owner has it from the start.
        let f = vfs.open_as("/mine", OpenFlags::WRITE | OpenFlags::CREATE, 0o640, Some((1000, 100))).unwrap();
        f.write(0, b"owned").unwrap();
        let st = f.stat();
        assert_eq!((st.uid, st.gid, st.mode), (1000, 100, 0o640));
        // Without one, the file is root's.
        put(&vfs, "/theirs", b"x");
        let st = vfs.stat("/theirs", true).unwrap();
        assert_eq!((st.uid, st.gid), (0, 0));
        // Other kinds of node.
        let d = vfs.mknod_dev_as("/dir", FileKind::Directory, 0o750, 0, Some((7, 8))).unwrap();
        assert_eq!((d.stat().uid, d.stat().gid, d.stat().mode), (7, 8, 0o750));
        let fifo = vfs.mknod_dev_as("/fifo", FileKind::Fifo, 0o600, 0, Some((9, 10))).unwrap();
        assert_eq!((fifo.stat().uid, fifo.stat().gid), (9, 10));
        // A directory's own `mknod_as` works the same.
        let sub = d.mknod_as("inner", FileKind::Regular, 0o600, 0, 11, 12).unwrap();
        assert_eq!((sub.stat().uid, sub.stat().gid), (11, 12));

        // chown changes one or both; chmod keeps the type bits.
        let theirs = vfs.lookup("/theirs").unwrap();
        theirs.chown(Some(42), None).unwrap();
        assert_eq!((theirs.stat().uid, theirs.stat().gid), (42, 0));
        theirs.chown(None, Some(43)).unwrap();
        assert_eq!((theirs.stat().uid, theirs.stat().gid), (42, 43));
        theirs.chmod(0o4755).unwrap();
        let st = theirs.stat();
        assert_eq!((st.mode, st.kind), (0o4755, FileKind::Regular));
        d.chmod(0o700).unwrap();
        assert_eq!((d.stat().mode, d.stat().kind), (0o700, FileKind::Directory));
        assert!(theirs.stat().ctime >= st.mtime);
    }
    // Durable, and valid.
    check(&img);
    let (fs, _) = mount_with(&img, MountOptions { read_only: true, ..MountOptions::default() });
    let vfs = Vfs::new(fs.root());
    let st = vfs.stat("/mine", true).unwrap();
    assert_eq!((st.uid, st.gid, st.mode), (1000, 100, 0o640));
    let st = vfs.stat("/theirs", true).unwrap();
    assert_eq!((st.uid, st.gid, st.mode), (42, 43, 0o4755));
    assert_eq!((vfs.stat("/dir/inner", true).unwrap().uid, vfs.stat("/dir", true).unwrap().gid), (11, 8));
    // And as btrfs-progs reads it.
    let out = Command::new(tool("btrfs").unwrap())
        .args(["inspect-internal", "dump-tree", "-t", "5"])
        .arg(&img)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("uid 1000 gid 100"), "{text}");
    assert!(text.contains("uid 42 gid 43"), "{text}");
    // A read-only mount refuses.
    assert_eq!(vfs.lookup("/mine").unwrap().chown(Some(1), None), Err(Errno::EROFS));
    assert_eq!(vfs.lookup("/mine").unwrap().chmod(0o777), Err(Errno::EROFS));
}

#[test]
fn owners_of_files_made_by_mkfs() {
    let dir = scratch("mkfsowner");
    let Some(mkfs_bin) = tool("mkfs.btrfs") else { return };
    tool("btrfs").unwrap();
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"hi").unwrap();
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
    assert!(Command::new(mkfs_bin).arg("-q").arg("-r").arg(&src).arg(&img).status().unwrap().success());
    let (fs, _) = mount_with(&img, MountOptions { read_only: true, ..MountOptions::default() });
    let st = Vfs::new(fs.root()).stat("/f", true).unwrap();
    // mkfs.btrfs -r keeps the owner of the source, which is whoever runs the tests.
    let meta = std::fs::metadata(src.join("f")).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!((st.uid, st.gid), (meta.uid(), meta.gid()));
}

fn at(sec: i64) -> Timestamp {
    Timestamp { sec, nsec: 0 }
}

/// Mounts with `atime`, a clock at 1000 s, a file written at 1000 s.
fn atime_fs(img: &Path, atime: Atime) -> (BtrfsFs<CountDisk>, Vfs, Arc<ManualClock>) {
    let (fs, _) = mount_with(img, MountOptions { atime, ..MountOptions::default() });
    let clock = Arc::new(ManualClock::new(at(1000)));
    fs.set_clock_source(clock.clone());
    let vfs = Vfs::new(fs.root());
    (fs, vfs, clock)
}

#[test]
fn atime_policies() {
    let dir = scratch("atime");
    let Some(img) = mkfs(&dir, &[]) else { return };
    let day = 24 * 60 * 60;

    // The default never touches it: reading changes nothing at all.
    {
        let (fs, vfs, clock) = atime_fs(&img, Atime::NoAtime);
        put(&vfs, "/f", b"data");
        vfs.mkdir("/d", 0o755).unwrap();
        let generation0 = fs.generation();
        clock.advance(5 * day);
        assert_eq!(cat(&vfs, "/f"), b"data");
        assert_eq!(fs.generation(), generation0);
        assert_eq!(vfs.stat("/f", true).unwrap().atime, at(1000));
    }

    // Relatime: the first read after a write, then not for a day.
    {
        let (fs, vfs, clock) = atime_fs(&img, Atime::Relatime);
        let f = vfs.open("/f", OpenFlags::READ, 0).unwrap();
        assert_eq!(f.stat().atime, at(1000));
        assert_eq!(f.stat().mtime, at(1000));
        clock.set(at(2000));
        let generation0 = fs.generation();
        assert_eq!(read_all(&*f), b"data");
        // atime (1000) was not after mtime (1000): updated.
        assert_eq!(f.stat().atime, at(2000));
        assert_eq!(f.stat().mtime, at(1000));
        assert_eq!(f.stat().ctime, at(1000));
        assert_eq!(fs.generation(), generation0 + 1);
        // Later the same day: left alone, and nothing is written.
        clock.set(at(3000));
        read_all(&*f);
        assert_eq!(f.stat().atime, at(2000));
        assert_eq!(fs.generation(), generation0 + 1);
        // A day after the last access: updated.
        clock.set(at(2000 + day));
        read_all(&*f);
        assert_eq!(f.stat().atime, at(2000 + day));
        assert_eq!(fs.generation(), generation0 + 2);
        // A write makes the next read update it again.
        clock.set(at(2000 + day + 10));
        f.write(0, b"DATA").unwrap();
        assert_eq!(f.stat().mtime, at(2000 + day + 10));
        clock.set(at(2000 + day + 20));
        let generation0 = fs.generation();
        assert_eq!(read_all(&*f), b"DATA");
        assert_eq!(f.stat().atime, at(2000 + day + 20));
        assert_eq!(fs.generation(), generation0 + 1);
        // A directory's listing is a read too, once; the entries are not.
        let d = vfs.lookup("/d").unwrap();
        assert_eq!(d.stat().atime, at(1000));
        assert_eq!(d.readdir(0).unwrap(), None);
        assert_eq!(d.stat().atime, at(2000 + day + 20));
    }

    // Strict: every read, not twice for the same instant.
    {
        let (fs, vfs, clock) = atime_fs(&img, Atime::StrictAtime);
        let f = vfs.open("/f", OpenFlags::READ, 0).unwrap();
        for t in [5000, 5001, 5002] {
            clock.set(at(t));
            read_all(&*f);
            assert_eq!(f.stat().atime, at(t));
        }
        let generation0 = fs.generation();
        read_all(&*f);
        assert_eq!(fs.generation(), generation0);
    }

    // A read-only mount, whatever it asks, writes nothing.
    {
        let opts = MountOptions { atime: Atime::StrictAtime, read_only: true, ..MountOptions::default() };
        let (fs, _) = mount_with(&img, opts);
        let vfs = Vfs::new(fs.root());
        let before = vfs.stat("/f", true).unwrap().atime;
        assert_eq!(cat(&vfs, "/f"), b"DATA");
        assert_eq!(vfs.stat("/f", true).unwrap().atime, before);
    }
    check(&img);
}

#[test]
fn subvolume_by_path() {
    let dir = scratch("subvolpath");
    let Some(mkfs_bin) = tool("mkfs.btrfs") else { return };
    tool("btrfs").unwrap();
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("plain/dir")).unwrap();
    std::fs::create_dir_all(src.join("vol/inner")).unwrap();
    std::fs::write(src.join("vol/in.txt"), b"in vol\n").unwrap();
    std::fs::write(src.join("vol/inner/x"), b"in inner\n").unwrap();
    std::fs::write(src.join("plain/dir/y"), b"y").unwrap();
    std::fs::write(src.join("top.txt"), b"top\n").unwrap();
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
    let out = Command::new(mkfs_bin)
        .args(["-q", "-r"])
        .arg(&src)
        .args(["-u", "vol", "-u", "vol/inner"])
        .arg(&img)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let by = |path| {
        let opts = MountOptions { subvol_path: Some(path), read_only: true, ..MountOptions::default() };
        BtrfsFs::mount_with(CountDisk::open(&img), 9, opts)
    };
    let names = |fs: &BtrfsFs<CountDisk>| {
        let root = fs.root();
        let mut v: Vec<String> = (0..).map_while(|i| root.readdir(i).unwrap()).map(|e| e.name).collect();
        v.sort();
        v
    };
    let fs = by("/vol").unwrap();
    assert_eq!(names(&fs), ["in.txt", "inner"]);
    assert_eq!(fs.subvol(), by("vol/").unwrap().subvol());
    let inner = by("/vol/inner").unwrap();
    assert_eq!(names(&inner), ["x"]);
    assert_eq!(Vfs::new(inner.root()).stat("/x", true).unwrap().size, 9);
    // The top level, by any spelling.
    for p in ["/", "", "//"] {
        let top = by(p).unwrap();
        assert_eq!(top.subvol(), 5);
        assert!(names(&top).contains(&"top.txt".to_string()));
    }
    // Not subvolumes, not there, or not paths.
    assert_eq!(by("/plain").err(), Some(Errno::EINVAL));
    assert_eq!(by("/plain/dir").err(), Some(Errno::EINVAL));
    assert_eq!(by("/top.txt").err(), Some(Errno::EINVAL));
    assert_eq!(by("/nope").err(), Some(Errno::ENOENT));
    assert_eq!(by("/vol/missing").err(), Some(Errno::ENOENT));
    assert_eq!(by("/vol/../vol").err(), Some(Errno::EINVAL));
    // Both ways of naming one is a mistake.
    let both = MountOptions { subvol: Some(5), subvol_path: Some("/vol"), read_only: true, ..MountOptions::default() };
    assert_eq!(BtrfsFs::mount_with(CountDisk::open(&img), 9, both).err(), Some(Errno::EINVAL));
    // Writable, by path.
    let opts = MountOptions { subvol_path: Some("/vol"), ..MountOptions::default() };
    let fs = BtrfsFs::mount_with(CountDisk::open(&img), 9, opts).unwrap();
    let vfs = Vfs::new(fs.root());
    put(&vfs, "/new", b"written in vol");
    drop(vfs);
    drop(fs);
    check(&img);
    assert_eq!(cat(&Vfs::new(by("/vol").unwrap().root()), "/new"), b"written in vol");
}

/// Reads of the device while `f` runs.
fn reads(counts: &Counts, f: impl FnOnce()) -> u64 {
    let before = counts.reads.load(Ordering::Relaxed);
    f();
    counts.reads.load(Ordering::Relaxed) - before
}

#[test]
fn data_cache_serves_repeat_reads() {
    let dir = scratch("datacache");
    let Some(img) = mkfs(&dir, &[]) else { return };
    {
        let (fs, _) = mount_with(&img, MountOptions::default());
        let vfs = Vfs::new(fs.root());
        put(&vfs, "/f", &pattern(1 << 20, 3));
    }
    let data = pattern(1 << 20, 3);

    // Without a cache every read goes to the device.
    let (fs, counts) = mount_with(&img, MountOptions { read_only: true, ..MountOptions::default() });
    let f = Vfs::new(fs.root()).open("/f", OpenFlags::READ, 0).unwrap();
    let mut buf = vec![0u8; 1 << 20];
    f.read(0, &mut buf).unwrap();
    let again = reads(&counts, || {
        f.read(0, &mut buf).unwrap();
    });
    assert!(again > 0);
    assert_eq!(buf, data);

    // With one, the second read of the data does not.
    let opts = MountOptions { read_only: true, data_cache_bytes: 4 << 20, ..MountOptions::default() };
    let (fs, counts) = mount_with(&img, opts);
    let f = Vfs::new(fs.root()).open("/f", OpenFlags::READ, 0).unwrap();
    f.read(0, &mut buf).unwrap();
    assert_eq!(buf, data);
    buf.fill(0);
    let cached = reads(&counts, || {
        f.read(0, &mut buf).unwrap();
    });
    assert_eq!(buf, data);
    assert!(cached < again, "cached {cached} vs {again} device reads");
    assert_eq!(cached, 0);
    // A part of it too.
    let part = reads(&counts, || {
        let mut p = vec![0u8; 5000];
        f.read(12_345, &mut p).unwrap();
        assert_eq!(p, data[12_345..17_345]);
    });
    assert_eq!(part, 0);

    // A cache too small for the file still reads it right.
    let opts = MountOptions { read_only: true, data_cache_bytes: 3 * 4096, ..MountOptions::default() };
    let (fs, _) = mount_with(&img, opts);
    let f = Vfs::new(fs.root()).open("/f", OpenFlags::READ, 0).unwrap();
    for _ in 0..3 {
        buf.fill(0);
        f.read(0, &mut buf).unwrap();
        assert_eq!(buf, data);
    }
}

#[test]
fn caches_stay_coherent_with_writes() {
    let dir = scratch("coherent");
    let Some(img) = mkfs(&dir, &[]) else { return };
    // Tiny caches evict all the time; big ones never do. Both match a model.
    for (name, tree, data) in [("tiny", 1, 3 * 4096), ("big", 1000, 8 << 20)] {
        let img = {
            let copy = dir.join(name);
            std::fs::copy(&img, &copy).unwrap();
            copy
        };
        let opts = MountOptions { tree_cache_blocks: tree, data_cache_bytes: data, ..MountOptions::default() };
        let (fs, _) = mount_with(&img, opts);
        let vfs = Vfs::new(fs.root());
        let mut model: Vec<(String, Vec<u8>)> = Vec::new();
        let mut seed = 0x1234_5678u32;
        let mut next = move || {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (seed >> 8) as usize
        };
        for round in 0..150 {
            match next() % 6 {
                0 | 1 if model.len() < 12 => {
                    let path = format!("/f{round}");
                    let content = pattern(next() % 90_000 + 1, round as u8);
                    put(&vfs, &path, &content);
                    model.push((path, content));
                }
                2 if !model.is_empty() => {
                    let i = next() % model.len();
                    let (path, content) = &mut model[i];
                    let off = next() % (content.len() + 1);
                    let patch = pattern(next() % 20_000 + 1, round as u8 ^ 0x55);
                    vfs.open(path, OpenFlags::WRITE, 0).unwrap().write(off as u64, &patch).unwrap();
                    if content.len() < off + patch.len() {
                        content.resize(off + patch.len(), 0);
                    }
                    content[off..off + patch.len()].copy_from_slice(&patch);
                }
                3 if !model.is_empty() => {
                    let i = next() % model.len();
                    let (path, _) = model.swap_remove(i);
                    vfs.unlink(&path).unwrap();
                }
                4 if !model.is_empty() => {
                    let i = next() % model.len();
                    let (path, content) = &mut model[i];
                    let len = next() % (content.len() + 5000);
                    vfs.open(path, OpenFlags::WRITE, 0).unwrap().truncate(len as u64).unwrap();
                    content.resize(len, 0);
                }
                _ => {}
            }
            // Read everything, twice, so that the second pass is from the caches.
            for _ in 0..2 {
                for (path, content) in &model {
                    assert_eq!(&cat(&vfs, path), content, "{name}: round {round}: {path}");
                }
            }
        }
        drop(vfs);
        drop(fs);
        check(&img);
    }
}

#[test]
fn bigger_tree_cache_reads_less() {
    let dir = scratch("treecache");
    let Some(img) = mkfs(&dir, &["-n", "4096"]) else { return };
    {
        let (fs, _) = mount_with(&img, MountOptions::default());
        let vfs = Vfs::new(fs.root());
        vfs.mkdir("/many", 0o755).unwrap();
        // Enough small files that the trees are several levels and many leaves.
        fs.batch(|| {
            for i in 0..1500 {
                put(&vfs, &format!("/many/file-{i:05}"), format!("{i}").as_bytes());
            }
        })
        .unwrap();
    }
    let run = |blocks: usize| {
        let opts = MountOptions { read_only: true, tree_cache_blocks: blocks, ..MountOptions::default() };
        let (fs, counts) = mount_with(&img, opts);
        let vfs = Vfs::new(fs.root());
        reads(&counts, || {
            for round in 0..3 {
                for i in (0..1500).step_by(7) {
                    let want = format!("{i}");
                    assert_eq!(cat(&vfs, &format!("/many/file-{i:05}")), want.as_bytes(), "{round}");
                }
            }
        })
    };
    let (small, default, large) = (run(1), run(0), run(4096));
    assert!(large < small, "large {large} vs small {small}");
    assert!(large <= default, "large {large} vs default {default}");
    assert!(default < small, "default {default} vs small {small}");
}

#[test]
fn batch_writes_one_superblock() {
    let dir = scratch("batch");
    let Some(img) = mkfs(&dir, &[]) else { return };
    let (fs, counts) = mount_with(&img, MountOptions::default());
    let vfs = Vfs::new(fs.root());
    let one_by_one = {
        let before = counts.flushes.load(Ordering::Relaxed);
        for i in 0..10 {
            put(&vfs, &format!("/a{i}"), &pattern(5000, i as u8));
        }
        counts.flushes.load(Ordering::Relaxed) - before
    };
    let (batched, generation0) = {
        let before = counts.flushes.load(Ordering::Relaxed);
        let generation0 = fs.generation();
        let r = fs
            .batch(|| {
                for i in 0..10 {
                    put(&vfs, &format!("/b{i}"), &pattern(5000, i as u8));
                }
                // Visible to readers at once, durable or not.
                assert_eq!(cat(&vfs, "/b9"), pattern(5000, 9));
                7
            })
            .unwrap();
        assert_eq!(r, 7);
        (counts.flushes.load(Ordering::Relaxed) - before, generation0)
    };
    // Each change took a flush before its superblock and two after; a batch
    // does that once.
    assert!(one_by_one >= 20 * 3, "{one_by_one}");
    assert!(batched <= 3, "{batched} flushes for the batch, {one_by_one} for ten changes");
    assert!(fs.generation() >= generation0 + 20);

    // Nested: only the outermost syncs.
    let before = counts.flushes.load(Ordering::Relaxed);
    fs.batch(|| {
        fs.batch(|| put(&vfs, "/n1", b"1")).unwrap();
        assert_eq!(counts.flushes.load(Ordering::Relaxed), before, "inner batch synced");
        put(&vfs, "/n2", b"2");
    })
    .unwrap();
    assert!(counts.flushes.load(Ordering::Relaxed) - before <= 3);

    // An empty batch, and a batch of reads, write nothing.
    let before = counts.flushes.load(Ordering::Relaxed);
    fs.batch(|| cat(&vfs, "/n1")).unwrap();
    fs.sync().unwrap();
    assert_eq!(counts.flushes.load(Ordering::Relaxed), before);
    drop(vfs);
    drop(fs);
    check(&img);

    // A read-only volume just runs it.
    let (ro, _) = mount_with(&img, MountOptions { read_only: true, ..MountOptions::default() });
    assert_eq!(ro.batch(|| 5).unwrap(), 5);
}

#[test]
fn batch_with_failures_keeps_the_rest() {
    let dir = scratch("batchfail");
    let Some(img) = mkfs(&dir, &[]) else { return };
    let (fs, _) = mount_with(&img, MountOptions::default());
    let vfs = Vfs::new(fs.root());
    put(&vfs, "/exists", b"old");
    fs.batch(|| {
        put(&vfs, "/ok1", b"one");
        assert_eq!(vfs.mkdir("/exists", 0o755).err(), Some(Errno::EEXIST));
        assert_eq!(vfs.unlink("/missing").err(), Some(Errno::ENOENT));
        put(&vfs, "/ok2", b"two");
    })
    .unwrap();
    drop(vfs);
    drop(fs);
    check(&img);
    let (fs, _) = mount_with(&img, MountOptions { read_only: true, ..MountOptions::default() });
    let vfs = Vfs::new(fs.root());
    assert_eq!(
        (cat(&vfs, "/ok1"), cat(&vfs, "/ok2"), cat(&vfs, "/exists")),
        (b"one".to_vec(), b"two".to_vec(), b"old".to_vec())
    );
}

#[test]
fn commit_batch_defers_the_superblock() {
    let dir = scratch("commitbatch");
    let Some(img) = mkfs(&dir, &[]) else { return };
    let super_gen = |img: &Path| {
        // The generation in the primary superblock, as the next mount would see.
        let mut sb = [0u8; 8];
        std::fs::File::open(img).unwrap().read_exact_at(&mut sb, 65536 + 72).unwrap();
        u64::from_le_bytes(sb)
    };
    let start = super_gen(&img);
    let opts = MountOptions { commit_batch: 8, ..MountOptions::default() };
    {
        let (fs, counts) = mount_with(&img, opts);
        let vfs = Vfs::new(fs.root());
        let flushes = counts.flushes.load(Ordering::Relaxed);
        // Three changes (create, write, create): none is durable yet.
        put(&vfs, "/a", &pattern(20_000, 1));
        vfs.mkdir("/d", 0o755).unwrap();
        assert_eq!(super_gen(&img), start);
        assert_eq!(counts.flushes.load(Ordering::Relaxed), flushes);
        assert!(fs.generation() > start);
        // Readers see them nonetheless, and they can be changed again.
        assert_eq!(cat(&vfs, "/a"), pattern(20_000, 1));
        put(&vfs, "/a", &pattern(30_000, 2));
        assert_eq!(cat(&vfs, "/a"), pattern(30_000, 2));
        // File::sync is what makes them so.
        vfs.lookup("/a").unwrap().sync().unwrap();
        assert_eq!(super_gen(&img), fs.generation());
        // The eighth since then is.
        let synced = super_gen(&img);
        for i in 0..7 {
            vfs.mkdir(&format!("/d/x{i}"), 0o755).unwrap();
            assert_eq!(super_gen(&img), synced, "after {i}");
        }
        vfs.mkdir("/d/x7", 0o755).unwrap();
        assert_eq!(super_gen(&img), fs.generation());
        // And what is pending when the volume goes is written with it.
        put(&vfs, "/last", b"written at drop");
        assert_ne!(super_gen(&img), fs.generation());
    }
    check(&img);
    let (fs, _) = mount_with(&img, MountOptions { read_only: true, ..MountOptions::default() });
    let vfs = Vfs::new(fs.root());
    assert_eq!(cat(&vfs, "/a"), pattern(30_000, 2));
    assert_eq!(cat(&vfs, "/last"), b"written at drop");
    assert!(vfs.lookup("/d/x7").is_ok());
}

/// Space freed while commits are deferred is not reused before they are
/// durable: freed and rewritten over and over, with a crash model of "the
/// device holds the last durable state's blocks untouched", the image stays
/// valid at every durable point.
#[test]
fn deferred_commits_do_not_reuse_durable_space() {
    let dir = scratch("reuse");
    let Some(img) = mkfs(&dir, &[]) else { return };
    let opts = MountOptions { commit_batch: 1000, ..MountOptions::default() };
    let (fs, _) = mount_with(&img, opts);
    let vfs = Vfs::new(fs.root());
    put(&vfs, "/victim", &pattern(2 << 20, 1));
    fs.sync().unwrap();
    // The durable state now has /victim's extents. Delete it, then write
    // plenty of new data that would take its space if it were free.
    vfs.unlink("/victim").unwrap();
    for i in 0..6 {
        put(&vfs, &format!("/n{i}"), &pattern(1 << 20, i as u8));
    }
    // Nothing has been made durable since the copy, so the image on disk
    // (superblock and everything it points to) is still that state: /victim's
    // blocks must be intact, though the volume has since freed and reused
    // much space.
    let crashed = dir.join("crashed");
    std::fs::copy(&img, &crashed).unwrap();
    check(&crashed);
    let (old, _) = mount_with(&crashed, MountOptions { read_only: true, ..MountOptions::default() });
    assert_eq!(cat(&Vfs::new(old.root()), "/victim"), pattern(2 << 20, 1));
    drop(old);
    drop(vfs);
    drop(fs);
    check(&img);
}
