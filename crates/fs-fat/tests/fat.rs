//! End-to-end tests against volumes made by `mkfs.fat` and checked with
//! `fsck.fat` (dosfstools). Skipped, with a note, if those are missing.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use osmium_fs::{Errno, File, FileKind, OpenFlags, Vfs};
use osmium_fs_fat::FatFs;
use osmium_hal::block::{BlockDevice, BlockError};

/// A disk in memory that the test can inspect after the file system is done
/// with it.
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

fn tool(name: &str) -> Option<PathBuf> {
    [Path::new("/usr/sbin"), Path::new("/sbin"), Path::new("/usr/bin")]
        .iter()
        .map(|d| d.join(name))
        .find(|p| p.exists())
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("osmium-fs-fat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// A fresh FAT32 image with 512-byte clusters (so files span many), or
/// `None` if dosfstools is not installed.
fn mkfs(name: &str) -> Option<(PathBuf, MemDisk)> {
    let Some(mkfs) = tool("mkfs.fat") else {
        eprintln!("mkfs.fat not found; skipping");
        return None;
    };
    let path = scratch(name);
    let _ = std::fs::remove_file(&path);
    // 40 MiB: just over the 65525 clusters that make a volume FAT32.
    let out = Command::new(mkfs).args(["-F", "32", "-s", "1", "-C"]).arg(&path).arg("40000").output().unwrap();
    assert!(out.status.success(), "mkfs.fat: {}", String::from_utf8_lossy(&out.stderr));
    let bytes = std::fs::read(&path).unwrap();
    Some((path, MemDisk(Arc::new(Mutex::new(bytes)))))
}

/// Writes the image back and runs `fsck.fat -n` on it; returns its output.
fn fsck(path: &Path, disk: &MemDisk) -> String {
    std::fs::write(path, &*disk.0.lock().unwrap()).unwrap();
    // -l lists every file, so the report shows how fsck decoded our names.
    let out = Command::new(tool("fsck.fat").expect("fsck.fat")).args(["-n", "-l"]).arg(path).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "fsck.fat found problems:\n{text}");
    text
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

fn names(dir: &dyn File) -> Vec<String> {
    let mut v: Vec<String> = (0..).map_while(|i| dir.readdir(i).unwrap()).map(|e| e.name).collect();
    v.sort();
    v
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

const RW: OpenFlags = OpenFlags::READ.union(OpenFlags::WRITE);
const NEW: OpenFlags = RW.union(OpenFlags::CREATE);

#[test]
fn rejects_non_fat32() {
    let disk = MemDisk(Arc::new(Mutex::new(vec![0u8; 1 << 20])));
    assert_eq!(FatFs::mount(disk, 1).err(), Some(Errno::EINVAL));
}

#[test]
fn files_directories_and_persistence() {
    let Some((path, disk)) = mkfs("main.img") else { return };
    let fs = FatFs::mount(disk.clone(), 7).unwrap();
    let free_at_start = fs.free_bytes();
    let vfs = Vfs::new(fs.root());

    // Names: exact 8.3 (stored without a long name), and long ones.
    vfs.open("/hello.txt", NEW, 0o644).unwrap().write(0, b"hello, fat\n").unwrap();
    let long = vfs.open("/A Long File Name.data", NEW, 0o644).unwrap();
    let data = pattern(5000, 1); // ten 512-byte clusters
    assert_eq!(long.write(0, &data), Ok(5000));
    vfs.mkdir("/Sub Dir", 0o755).unwrap();
    vfs.open("/Sub Dir/inner.bin", NEW, 0o644).unwrap().write(0, &pattern(700, 2)).unwrap();
    assert_eq!(names(&*vfs.lookup("/").unwrap()), ["A Long File Name.data", "Sub Dir", "hello.txt"]);

    // Reads at odd offsets, and lookups are case-insensitive and shared.
    let mut buf = [0u8; 100];
    assert_eq!(long.read(4950, &mut buf), Ok(50));
    assert_eq!(&buf[..50], &data[4950..]);
    assert_eq!(long.read(5000, &mut buf), Ok(0));
    let again = vfs.open("/a long file NAME.DATA", OpenFlags::READ, 0).unwrap();
    assert_eq!(again.stat().ino, long.stat().ino);
    assert!(Arc::ptr_eq(&again, &long), "one node per file");
    assert_eq!(long.stat().dev, 7);

    // Writing past the end leaves zeroes in the gap.
    let hello = vfs.open("/HELLO.TXT", RW, 0).unwrap();
    hello.write(600, b"!").unwrap();
    let h = read_all(&*hello);
    assert_eq!((h.len(), &h[..11], h[11..600].iter().all(|&b| b == 0)), (601, &b"hello, fat\n"[..], true));

    // Truncate down then up: the regrown tail reads as zeroes.
    long.truncate(1000).unwrap();
    long.truncate(3000).unwrap();
    let t = read_all(&*long);
    assert_eq!(&t[..1000], &data[..1000]);
    assert!(t[1000..].iter().all(|&b| b == 0), "old data must not reappear");

    // A directory that outgrows its first cluster (16 entries per cluster).
    vfs.mkdir("/many", 0o755).unwrap();
    for i in 0..60 {
        vfs.open(&format!("/many/file number {i}.txt"), NEW, 0o644).unwrap().write(0, &[i as u8; 3]).unwrap();
    }
    let many = vfs.lookup("/many").unwrap();
    assert_eq!(names(&*many).len(), 60);
    assert!(many.stat().size > 512);
    assert_eq!(read_all(&*vfs.lookup("/many/file number 42.txt").unwrap()), [42; 3]);

    // The same error codes as other file systems.
    assert_eq!(vfs.open("/hello.txt", NEW | OpenFlags::EXCL, 0).err(), Some(Errno::EEXIST));
    assert_eq!(vfs.rmdir("/Sub Dir").err(), Some(Errno::ENOTEMPTY));
    assert_eq!(vfs.unlink("/Sub Dir").err(), Some(Errno::EISDIR));
    assert_eq!(vfs.rmdir("/hello.txt").err(), Some(Errno::ENOTDIR));
    assert_eq!(vfs.lookup("/nope").err(), Some(Errno::ENOENT));
    assert_eq!(vfs.mknod("/fifo", FileKind::Fifo, 0o644).err(), Some(Errno::EPERM));
    assert_eq!(vfs.open("/bad:name", NEW, 0).err(), Some(Errno::EINVAL));
    assert_eq!(long.read(0, &mut buf).map(|n| n > 0), Ok(true));
    assert_eq!(many.read(0, &mut buf).err(), Some(Errno::EISDIR));

    // Removing an open file: its data stays readable through the node, and
    // a new file reusing the directory slot is a different node.
    let doomed = vfs.open("/doomed", NEW, 0o644).unwrap();
    doomed.write(0, &pattern(2000, 3)).unwrap();
    vfs.unlink("/doomed").unwrap();
    assert_eq!(vfs.lookup("/doomed").err(), Some(Errno::ENOENT));
    let reborn = vfs.open("/doomed", NEW, 0o644).unwrap();
    reborn.write(0, b"new").unwrap();
    assert!(!Arc::ptr_eq(&reborn, &doomed));
    assert_eq!(read_all(&*doomed), pattern(2000, 3));
    drop(doomed); // frees its clusters now
    vfs.unlink("/doomed").unwrap();
    drop(reborn);

    // Emptying and removing a directory.
    for i in 0..60 {
        vfs.unlink(&format!("/many/file number {i}.txt")).unwrap();
    }
    drop(many);
    vfs.rmdir("/many").unwrap();

    let root = vfs.lookup("/").unwrap();
    root.sync().unwrap();
    drop((root, long, again, hello));
    drop(vfs);
    let report = fsck(&path, &disk);
    assert!(!report.contains("Free cluster summary wrong"), "{report}");
    // An independent implementation reads our long names and the short
    // names generated beside them. Plain 8.3 names it shows upper case, as
    // it ignores the NT lower-case flags.
    for name in ["/A Long File Name.data (ALONGF~1.DAT)", "/Sub Dir (SUBDIR~1)", "/Sub Dir/INNER.BIN", "/HELLO.TXT"] {
        assert!(report.contains(name), "fsck.fat did not list {name}:\n{report}");
    }

    // Mount the image afresh: everything is still there.
    let fs2 = FatFs::mount(disk.clone(), 8).unwrap();
    let vfs = Vfs::new(fs2.root());
    assert_eq!(names(&*vfs.lookup("/").unwrap()), ["A Long File Name.data", "Sub Dir", "hello.txt"]);
    assert_eq!(read_all(&*vfs.lookup("/A Long File Name.data").unwrap()).len(), 3000);
    assert_eq!(read_all(&*vfs.lookup("/sub dir/INNER.BIN").unwrap()), pattern(700, 2));
    // What was freed came back: only the surviving files use space.
    let used = free_at_start.unwrap() - fs2.free_bytes().unwrap();
    assert!(used > 0 && used <= 16 * 1024, "{used} bytes still in use");
    let _ = std::fs::remove_file(&path);
}
