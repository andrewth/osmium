#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! End-to-end tests against images made by `mkfs.btrfs --rootdir`. Each test
//! is skipped, with a note, if the tool is missing.

use std::collections::BTreeSet;
use std::os::unix::fs::{FileExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use osmium_fs::{Errno, File, FileKind, OpenFlags, Vfs};
use osmium_fs_btrfs::{BtrfsFs, MountOptions};
use osmium_hal::block::{BlockDevice, BlockError};

/// An image file, read on demand in `block`-byte blocks (the images are
/// sparse and mostly empty).
struct FileDisk {
    file: Arc<std::fs::File>,
    block: usize,
    len: u64,
}

impl FileDisk {
    fn open(path: &Path, block: usize) -> Self {
        let file = std::fs::File::open(path).unwrap();
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
    fn write_blocks(&mut self, _lba: u64, _buf: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
}

fn mkfs() -> Option<PathBuf> {
    let found =
        ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|d| Path::new(d).join("mkfs.btrfs")).find(|p| p.exists());
    if found.is_none() {
        eprintln!("mkfs.btrfs not found; skipping");
    }
    found
}

/// A directory of its own for one test, removed when dropped (the images
/// are sparse, but `mkfs.btrfs` still writes megabytes into each).
struct Scratch(PathBuf);

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 11) as u8).collect()
}

/// Bytes that do not compress: xorshift output.
fn noise(len: usize, mut seed: u64) -> Vec<u8> {
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect()
}

fn text(len: usize) -> Vec<u8> {
    (0..).flat_map(|i| format!("line {i}: the quick brown fox\n").into_bytes()).take(len).collect()
}

/// A source tree: small and large files, noise, text, a sparse file, a
/// symbolic link, a FIFO, an extended attribute, an empty file and nesting.
fn tree(dir: &Path) -> PathBuf {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("docs/deep/er")).unwrap();
    std::fs::create_dir_all(src.join("vol/inner")).unwrap();
    std::fs::write(src.join("hello.txt"), b"hello, btrfs\n").unwrap();
    std::fs::write(src.join("docs/big.bin"), pattern(3 << 20, 2)).unwrap();
    std::fs::write(src.join("docs/noise"), noise(700_000, 7)).unwrap();
    std::fs::write(src.join("docs/text"), text(1_000_000)).unwrap();
    std::fs::write(src.join("docs/empty"), b"").unwrap();
    std::fs::write(src.join("docs/deep/er/bottom.txt"), b"three levels down\n").unwrap();
    std::fs::write(src.join("vol/in.txt"), b"inside the subvolume\n").unwrap();
    std::fs::write(src.join("vol/inner/x"), b"x").unwrap();
    // 8 MiB with a byte at 5 MB and a tail.
    let sparse = std::fs::File::create(src.join("sparse")).unwrap();
    sparse.set_len(8 << 20).unwrap();
    sparse.write_all_at(b"x", 5_000_000).unwrap();
    sparse.write_all_at(b"end", (8 << 20) - 3).unwrap();
    std::fs::set_permissions(src.join("hello.txt"), std::fs::Permissions::from_mode(0o640)).unwrap();
    symlink("hello.txt", src.join("link")).unwrap();
    symlink("/usr/lib/../share/x", src.join("abs")).unwrap();
    assert!(Command::new("mkfifo").arg(src.join("fifo")).status().unwrap().success());
    let xattr = Command::new("python3")
        .args(["-c", "import os,sys; os.setxattr(sys.argv[1], 'user.comment', b'hi there')"])
        .arg(src.join("hello.txt"))
        .status();
    assert!(xattr.unwrap().success(), "python3 could not set an xattr");
    src
}

/// Runs `mkfs.btrfs` with `args` over `src` into a 128 MiB (sparse) image.
fn image(mkfs: &Path, dir: &Path, src: &Path, args: &[&str]) -> PathBuf {
    let img = dir.join("img");
    let _ = std::fs::remove_file(&img);
    std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
    let out = Command::new(mkfs).arg("-q").arg("--rootdir").arg(src).args(args).arg(&img).output().unwrap();
    assert!(out.status.success(), "mkfs.btrfs {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    img
}

/// Mounted read-only: these tests check what was on the image.
fn mount(img: &Path, block: usize) -> BtrfsFs<FileDisk> {
    let fs = BtrfsFs::mount_with(FileDisk::open(img, block), 9, RO).unwrap();
    assert!(fs.is_read_only());
    fs
}

const RO: MountOptions<'static> = MountOptions {
    subvol: None,
    subvol_path: None,
    read_only: true,
    atime: osmium_fs_btrfs::Atime::NoAtime,
    tree_cache_blocks: 0,
    data_cache_bytes: 0,
    commit_batch: 0,
    compress: osmium_fs_btrfs::Compression::None,
};

fn ro_subvol(id: u64) -> MountOptions<'static> {
    MountOptions { subvol: Some(id), read_only: true, ..MountOptions::default() }
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

/// Reads in `chunk`-byte pieces, as a program with a small buffer would.
fn read_chunked(f: &dyn File, chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; chunk];
    loop {
        let n = f.read(out.len() as u64, &mut buf).unwrap();
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buf[..n]);
    }
}

fn names(dir: &dyn File) -> Vec<String> {
    let mut v: Vec<String> = (0..).map_while(|i| dir.readdir(i).unwrap()).map(|e| e.name).collect();
    v.sort();
    v
}

fn cat(vfs: &Vfs, path: &str) -> Vec<u8> {
    read_all(&*vfs.open(path, OpenFlags::READ, 0).unwrap())
}

/// Everything the tree from [`tree`] should hold, read through `vfs`.
fn check_tree(vfs: &Vfs, with_vol: bool) {
    let root = vfs.lookup("/").unwrap();
    let mut want = vec!["abs", "docs", "fifo", "hello.txt", "link", "sparse"];
    if with_vol {
        want.push("vol");
    }
    want.sort();
    assert_eq!(names(&*root), want);
    assert_eq!(names(&*vfs.lookup("/docs").unwrap()), ["big.bin", "deep", "empty", "noise", "text"]);

    assert_eq!(cat(vfs, "/hello.txt"), b"hello, btrfs\n");
    assert_eq!(cat(vfs, "/docs/big.bin"), pattern(3 << 20, 2));
    assert_eq!(cat(vfs, "/docs/noise"), noise(700_000, 7));
    let t = vfs.open("/docs/text", OpenFlags::READ, 0).unwrap();
    assert_eq!(read_chunked(&*t, 4096), text(1_000_000));
    // Reads that start and end inside extents.
    let mut buf = vec![0u8; 200_000];
    assert_eq!(t.read(123_457, &mut buf).unwrap(), 200_000);
    assert_eq!(buf, text(1_000_000)[123_457..323_457]);
    assert_eq!(cat(vfs, "/docs/empty"), b"");
    assert_eq!(cat(vfs, "/docs/deep/er/bottom.txt"), b"three levels down\n");

    let sparse = cat(vfs, "/sparse");
    assert_eq!(sparse.len(), 8 << 20);
    assert_eq!(sparse[5_000_000], b'x');
    assert_eq!(&sparse[(8 << 20) - 3..], b"end");
    assert_eq!(sparse.iter().filter(|&&b| b != 0).count(), 4);

    let st = vfs.stat("/hello.txt", true).unwrap();
    assert_eq!((st.kind, st.mode, st.size, st.nlink, st.dev), (FileKind::Regular, 0o640, 13, 1, 9));
    assert!(st.mtime.sec > 1_600_000_000);
    assert_eq!(vfs.stat("/docs", true).unwrap().kind, FileKind::Directory);
    assert_eq!(vfs.stat("/fifo", false).unwrap().kind, FileKind::Fifo);
    let link = vfs.stat("/link", false).unwrap();
    assert_eq!((link.kind, link.size), (FileKind::Symlink, 9));
    assert_eq!(vfs.readlink("/link").unwrap(), "hello.txt");
    assert_eq!(vfs.readlink("/abs").unwrap(), "/usr/lib/../share/x");
    assert_eq!(cat(vfs, "/link"), b"hello, btrfs\n");

    let hello = vfs.lookup("/hello.txt").unwrap();
    assert_eq!(hello.xattr_get(b"user.comment").unwrap(), b"hi there");
    assert_eq!(hello.xattr_get(b"user.nope").err(), Some(Errno::ENODATA));
    assert!(hello.xattr_list().unwrap().contains(&b"user.comment".to_vec()));

    // Inode numbers are distinct and readdir agrees with stat.
    let mut seen = BTreeSet::new();
    for e in (0..).map_while(|i| root.readdir(i).unwrap()) {
        let st = root.lookup(&e.name).unwrap().stat();
        assert_eq!((st.ino, st.kind), (e.ino, e.kind), "{}", e.name);
        assert!(seen.insert(e.ino), "{} repeats inode {}", e.name, e.ino);
    }

    assert_eq!(vfs.lookup("/missing").err(), Some(Errno::ENOENT));
    assert_eq!(vfs.lookup("/hello.txt/x").err(), Some(Errno::ENOTDIR));
    assert_eq!(vfs.open("/new", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).err(), Some(Errno::EROFS));
    assert_eq!(hello.write(0, b"x").err(), Some(Errno::EROFS));
    assert_eq!(vfs.mkdir("/d", 0o755).err(), Some(Errno::EROFS));
    assert_eq!(vfs.unlink("/hello.txt").err(), Some(Errno::EROFS));
}

#[test]
fn rejects_non_btrfs() {
    let dir = scratch("reject");
    let img = dir.join("zero");
    std::fs::File::create(&img).unwrap().set_len(1 << 20).unwrap();
    assert_eq!(BtrfsFs::mount_with(FileDisk::open(&img, 512), 1, RO).err(), Some(Errno::EINVAL));
    std::fs::File::create(&img).unwrap().set_len(4096).unwrap();
    assert_eq!(BtrfsFs::mount_with(FileDisk::open(&img, 512), 1, RO).err(), Some(Errno::EINVAL));
}

#[test]
fn plain() {
    let Some(mkfs) = mkfs() else { return };
    let dir = scratch("plain");
    let src = tree(&dir);
    let img = image(&mkfs, &dir, &src, &["-L", "osmium"]);
    // A disk's 512-byte blocks and 4 KiB blocks read the same.
    for block in [512, 4096] {
        let fs = mount(&img, block);
        assert_eq!((fs.label(), fs.subvol()), ("osmium", 5));
        check_tree(&Vfs::new(fs.root()), true);
    }
}

#[test]
fn compressed() {
    let Some(mkfs) = mkfs() else { return };
    for algo in ["zlib", "lzo", "zstd", "zstd:15", "zlib:9"] {
        let dir = scratch(&format!("compress-{}", algo.replace(':', "-")));
        let src = tree(&dir);
        let img = image(&mkfs, &dir, &src, &["--compress", algo]);
        // Compression must actually have happened for the test to mean anything.
        let used = std::fs::metadata(&img).map(|m| std::os::unix::fs::MetadataExt::blocks(&m) * 512).unwrap();
        assert!(used < 8 << 20, "{algo}: {used} bytes allocated; was anything compressed?");
        eprintln!("checking --compress {algo}");
        let fs = mount(&img, 4096);
        check_tree(&Vfs::new(fs.root()), true);
    }
}

#[test]
fn checksums_and_sizes() {
    let Some(mkfs) = mkfs() else { return };
    for args in [&["--csum", "xxhash"][..], &["-n", "4096"], &["-n", "65536"], &["-m", "single", "-d", "single"]] {
        let dir = scratch(&format!("variant-{}", args.join("").replace('-', "")));
        let src = tree(&dir);
        let img = image(&mkfs, &dir, &src, args);
        eprintln!("checking {args:?}");
        let fs = mount(&img, 4096);
        check_tree(&Vfs::new(fs.root()), true);
    }
    // SHA-256 and BLAKE2b are not read.
    let dir = scratch("sha256");
    let src = tree(&dir);
    let img = image(&mkfs, &dir, &src, &["--csum", "sha256"]);
    assert_eq!(BtrfsFs::mount_with(FileDisk::open(&img, 4096), 1, RO).err(), Some(Errno::EINVAL));
}

#[test]
fn subvolumes() {
    let Some(mkfs) = mkfs() else { return };
    let dir = scratch("subvol");
    let src = tree(&dir);
    let img = image(&mkfs, &dir, &src, &["-u", "vol"]);
    let fs = mount(&img, 4096);
    let vfs = Vfs::new(fs.root());
    check_tree(&vfs, true);
    assert_eq!(cat(&vfs, "/vol/in.txt"), b"inside the subvolume\n");
    assert_eq!(cat(&vfs, "/vol/inner/x"), b"x");
    assert_eq!(names(&*vfs.lookup("/vol").unwrap()), ["in.txt", "inner"]);
    // The subvolume's root has its own inode number, not the top level's.
    let (top, vol) = (vfs.stat("/", true).unwrap(), vfs.stat("/vol", true).unwrap());
    assert_eq!(top.ino, 256);
    assert_ne!(vol.ino, top.ino);

    // Mounted by id, the subvolume is the root.
    let sub = BtrfsFs::mount_with(FileDisk::open(&img, 4096), 9, ro_subvol(256)).unwrap();
    let sv = Vfs::new(sub.root());
    assert_eq!(names(&*sv.lookup("/").unwrap()), ["in.txt", "inner"]);
    assert_eq!(sv.stat("/", true).unwrap().ino, 256);
    assert_eq!(BtrfsFs::mount_with(FileDisk::open(&img, 4096), 9, ro_subvol(999)).err(), Some(Errno::ENOENT));

    // A default subvolume is what `mount` picks.
    let img = image(&mkfs, &dir, &src, &["-u", "default:vol"]);
    let fs = mount(&img, 4096);
    assert_eq!(fs.subvol(), 256);
    assert_eq!(names(&*fs.root()), ["in.txt", "inner"]);
    let top = BtrfsFs::mount_with(FileDisk::open(&img, 4096), 9, ro_subvol(5)).unwrap();
    check_tree(&Vfs::new(top.root()), true);
}

#[test]
fn big_directory() {
    let Some(mkfs) = mkfs() else { return };
    let dir = scratch("bigdir");
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("many")).unwrap();
    let mut want: Vec<String> = (0..3000).map(|i| format!("file-with-a-longish-name-{i:05}")).collect();
    for name in &want {
        std::fs::write(src.join("many").join(name), name.as_bytes()).unwrap();
    }
    want.sort();
    // Small tree blocks make the file system tree several levels deep.
    let img = image(&mkfs, &dir, &src, &["-n", "4096"]);
    let fs = mount(&img, 4096);
    let vfs = Vfs::new(fs.root());
    let many = vfs.lookup("/many").unwrap();
    assert_eq!(names(&*many), want);
    for name in want.iter().step_by(97) {
        assert_eq!(cat(&vfs, &format!("/many/{name}")), name.as_bytes());
    }
    // Random access into the listing restarts from the beginning.
    assert!(many.readdir(2999).unwrap().is_some());
    assert_eq!(many.readdir(3000).unwrap(), None);
    assert!(many.readdir(5).unwrap().is_some());
}

/// The byte offset in `img` of each sector-aligned copy of `needle`.
fn find_copies(img: &Path, needle: &[u8]) -> Vec<u64> {
    let bytes = std::fs::read(img).unwrap();
    bytes.chunks(4096).enumerate().filter(|(_, c)| *c == needle).map(|(i, _)| i as u64 * 4096).collect()
}

fn corrupt(img: &Path, at: u64) {
    let f = std::fs::OpenOptions::new().write(true).read(true).open(img).unwrap();
    let mut b = [0u8; 1];
    f.read_exact_at(&mut b, at).unwrap();
    f.write_all_at(&[b[0] ^ 0xff], at).unwrap();
}

#[test]
fn checksum_failures_and_mirrors() {
    let Some(mkfs) = mkfs() else { return };
    let dir = scratch("mirror");
    let src = tree(&dir);
    let needle = noise(700_000, 7)[4096 * 10..4096 * 11].to_vec();

    // One copy: a flipped byte is an I/O error, not bad data.
    let img = image(&mkfs, &dir, &src, &["-d", "single"]);
    let copies = find_copies(&img, &needle);
    assert_eq!(copies.len(), 1);
    corrupt(&img, copies[0] + 100);
    let fs = mount(&img, 4096);
    let f = Vfs::new(fs.root()).lookup("/docs/noise").unwrap();
    let mut buf = vec![0u8; 4096];
    assert_eq!(f.read(4096 * 10, &mut buf).err(), Some(Errno::EIO));
    assert_eq!(f.read(4096 * 9, &mut buf).unwrap(), 4096);

    // Two copies: the good one is read.
    let img = image(&mkfs, &dir, &src, &["-d", "dup", "-m", "dup"]);
    let copies = find_copies(&img, &needle);
    assert_eq!(copies.len(), 2);
    corrupt(&img, copies[0] + 100);
    let fs = mount(&img, 4096);
    let f = Vfs::new(fs.root()).lookup("/docs/noise").unwrap();
    assert_eq!(read_all(&*f), noise(700_000, 7));
    corrupt(&img, copies[1] + 100);
    let fs = mount(&img, 4096);
    let f = Vfs::new(fs.root()).lookup("/docs/noise").unwrap();
    assert_eq!(f.read(4096 * 10, &mut buf).err(), Some(Errno::EIO));
}
