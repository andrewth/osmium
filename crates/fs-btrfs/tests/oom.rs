#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Running out of memory in the middle of a btrfs call is `ENOMEM`. Each
//! test fails every allocation of a call in turn, on a small image made by
//! `mkfs.btrfs` (skipped, with a note, if it is missing).

use std::os::unix::fs::{FileExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use osmium_fs::{Errno, Vfs};
use osmium_fs_btrfs::BtrfsFs;
use osmium_hal::block::{BlockDevice, BlockError};

#[path = "../../proc/src/failing.rs"]
mod failing;

#[global_allocator]
static ALLOCATOR: failing::Failing = failing::Failing;

use failing::every_failure;

/// An image file; reading it allocates nothing.
#[derive(Clone)]
struct FileDisk {
    file: Arc<std::fs::File>,
    len: u64,
}

impl BlockDevice for FileDisk {
    fn block_size(&self) -> usize {
        4096
    }
    fn num_blocks(&self) -> u64 {
        self.len / 4096
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.file.read_exact_at(buf, lba * 4096).map_err(|_| BlockError::Io)
    }
    fn write_blocks(&mut self, _lba: u64, _buf: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
}

fn ok_or_enomem<T: std::fmt::Debug>(r: &Result<T, Errno>, injected: bool) -> bool {
    match r {
        Ok(_) => true,
        Err(e) => {
            assert!(injected && *e == Errno::ENOMEM, "{r:?}, injected: {injected}");
            false
        }
    }
}

/// A small image with a file, a symbolic link, an xattr, a subvolume and,
/// with `compress`, compressed data.
fn image(name: &str, compress: Option<&str>) -> Option<FileDisk> {
    let mkfs =
        ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|d| Path::new(d).join("mkfs.btrfs")).find(|p| p.exists());
    let Some(mkfs) = mkfs else {
        eprintln!("mkfs.btrfs not found; skipping");
        return None;
    };
    let dir: PathBuf = std::env::temp_dir().join(format!("osmium-fs-btrfs-oom-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("vol")).unwrap();
    std::fs::write(src.join("a.txt"), b"hello world").unwrap();
    std::fs::write(src.join("text"), "compress me ".repeat(20_000)).unwrap();
    std::fs::write(src.join("vol/v"), b"in vol").unwrap();
    symlink("a.txt", src.join("l")).unwrap();
    let _ = Command::new("python3")
        .args(["-c", "import os,sys; os.setxattr(sys.argv[1], 'user.k', b'v')"])
        .arg(src.join("a.txt"))
        .status();
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
    let mut cmd = Command::new(&mkfs);
    cmd.args(["-q", "-u", "vol", "--rootdir"]).arg(&src);
    if let Some(algo) = compress {
        cmd.args(["--compress", algo]);
    }
    let out = cmd.arg(&img).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let file = std::fs::File::open(&img).unwrap();
    let len = file.metadata().unwrap().len();
    // The open file keeps the image; the directory can go.
    let _ = std::fs::remove_dir_all(&dir);
    Some(FileDisk { file: Arc::new(file), len })
}

/// Folds `b` into the running hash `h` (FNV-1a), so that checking what was
/// read allocates nothing.
fn fold(h: &mut u64, b: &[u8]) {
    for &x in b {
        *h = (*h ^ x as u64).wrapping_mul(0x100_0000_01b3);
    }
}

/// Mounts and reads everything, from a fresh mount each time so that no
/// cache hides an allocation; returns a hash of what it read.
fn everything(disk: &FileDisk) -> Result<u64, Errno> {
    let fs = BtrfsFs::mount(disk.clone(), 1)?;
    let root = fs.root();
    let mut h = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while let Some(e) = root.readdir(i)? {
        fold(&mut h, e.name.as_bytes());
        i += 1;
    }
    let a = root.lookup("a.txt")?;
    let mut buf = [0u8; 16];
    let n = a.read(0, &mut buf)?;
    fold(&mut h, &buf[..n]);
    fold(&mut h, &a.xattr_get(b"user.k")?);
    for name in a.xattr_list()? {
        fold(&mut h, &name);
    }
    fold(&mut h, root.lookup("l")?.readlink()?.as_bytes());
    let text = root.lookup("text")?;
    let mut big = [0u8; 8192];
    for off in [0u64, 100_000, 200_000] {
        let n = text.read(off, &mut big)?;
        fold(&mut h, &big[..n]);
    }
    let v = root.lookup("vol")?.lookup("v")?;
    let n = v.read(0, &mut buf)?;
    fold(&mut h, &buf[..n]);
    Ok(h)
}

fn fails_cleanly(disk: FileDisk) {
    let want = everything(&disk).unwrap();
    let n = every_failure(
        || everything(&disk),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), want);
            }
        },
    );
    assert!(n >= 20, "{n} allocations");

    // A mount that stays up: every call fails cleanly and the next succeeds.
    let fs = BtrfsFs::mount(disk, 1).unwrap();
    let vfs = Vfs::new(fs.root());
    every_failure(
        || {
            let f = vfs.lookup("/text")?;
            let mut buf = [0u8; 64];
            f.read(150_000, &mut buf)?;
            Ok::<_, Errno>(buf)
        },
        |r, injected| _ = ok_or_enomem(&r, injected),
    );
}

#[test]
fn plain_volume_fails_cleanly() {
    if let Some(disk) = image("plain", None) {
        fails_cleanly(disk);
    }
}

#[test]
fn compressed_volumes_fail_cleanly() {
    for algo in ["zlib", "lzo", "zstd"] {
        if let Some(disk) = image(algo, Some(algo)) {
            fails_cleanly(disk);
        }
    }
}
