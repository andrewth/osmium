#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! End-to-end tests against FAT12, FAT16 and FAT32 volumes made by
//! `mkfs.fat` and checked with `fsck.fat` (dosfstools), and against
//! hand-made ones. The dosfstools tests are skipped, with a note, if the
//! tools are missing.

use std::collections::BTreeMap;
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

/// A fresh image of `kib` KiB with 512-byte clusters (so files span many),
/// of FAT type `fat` (12, 16 or 32), or `None` if dosfstools is not
/// installed.
fn mkfs(name: &str, fat: &str, kib: &str) -> Option<(PathBuf, MemDisk)> {
    let Some(mkfs) = tool("mkfs.fat") else {
        eprintln!("mkfs.fat not found; skipping");
        return None;
    };
    let path = scratch(name);
    let _ = std::fs::remove_file(&path);
    let out = Command::new(mkfs).args(["-F", fat, "-s", "1", "-C"]).arg(&path).arg(kib).output().unwrap();
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
fn rejects_blank_disks() {
    let disk = MemDisk(Arc::new(Mutex::new(vec![0u8; 1 << 20])));
    assert_eq!(FatFs::mount(disk, 1).err(), Some(Errno::EINVAL));
}

#[test]
fn fat32_files_directories_and_persistence() {
    // 40 MiB: just over the 65525 clusters that make a volume FAT32.
    full_cycle("fat32.img", "32", "40000");
}

#[test]
fn fat16_files_directories_and_persistence() {
    // 16 MB of 512-byte clusters: 32000 of them.
    full_cycle("fat16.img", "16", "16000");
}

#[test]
fn fat12_files_directories_and_persistence() {
    // A floppy-sized volume: 2847 clusters.
    full_cycle("fat12.img", "12", "1440");
}

fn full_cycle(image: &str, fat: &str, kib: &str) {
    let Some((path, disk)) = mkfs(image, fat, kib) else { return };
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

#[test]
fn fat32_rename_and_timestamps() {
    rename_cycle("fat32r.img", "32", "40000");
}

#[test]
fn fat16_rename_and_timestamps() {
    rename_cycle("fat16r.img", "16", "16000");
}

#[test]
fn fat12_rename_and_timestamps() {
    rename_cycle("fat12r.img", "12", "1440");
}

fn rename_cycle(image: &str, fat: &str, kib: &str) {
    use osmium_fs::{ManualClock, Timestamp};
    let Some((path, disk)) = mkfs(image, fat, kib) else { return };
    let fs = FatFs::mount(disk.clone(), 7).unwrap();
    let clock = Arc::new(ManualClock::new(Timestamp::from_civil(2024, 5, 6, 7, 8, 10)));
    fs.set_clock(clock.clone());
    let vfs = Vfs::new(fs.root());

    // Times follow the clock (to DOS's two seconds), and a write moves the
    // write and access times but not the creation time.
    let f = vfs.open("/first.txt", NEW, 0o644).unwrap();
    f.write(0, b"payload").unwrap();
    let st = vfs.stat("/first.txt", true).unwrap();
    assert_eq!(st.mtime, Timestamp::from_civil(2024, 5, 6, 7, 8, 10));
    assert_eq!(st.atime, Timestamp::from_civil(2024, 5, 6, 0, 0, 0));
    clock.advance(3600);
    f.write(0, b"PAYLOAD").unwrap();
    assert_eq!(vfs.stat("/first.txt", true).unwrap().mtime, Timestamp::from_civil(2024, 5, 6, 8, 8, 10));
    clock.advance(86_400);
    f.truncate(3).unwrap();
    assert_eq!(vfs.stat("/first.txt", true).unwrap().mtime, Timestamp::from_civil(2024, 5, 7, 8, 8, 10));
    assert_eq!(vfs.stat("/first.txt", true).unwrap().atime, Timestamp::from_civil(2024, 5, 7, 0, 0, 0));

    // Hard links do not exist on FAT.
    assert_eq!(vfs.link("/first.txt", "/second.txt").err(), Some(Errno::EPERM));

    // A rename within a directory (short to long name) keeps the node, the
    // data and the times, and an open handle follows it.
    vfs.rename("/first.txt", "/A Much Longer Name.text").unwrap();
    assert_eq!(vfs.lookup("/first.txt").err(), Some(Errno::ENOENT));
    let moved = vfs.lookup("/a much longer name.TEXT").unwrap();
    assert_eq!(read_all(&*moved), b"PAY");
    assert!(Arc::ptr_eq(&moved, &f), "the open node is the renamed file");
    assert_eq!(moved.stat().mtime, Timestamp::from_civil(2024, 5, 7, 8, 8, 10));
    f.write(3, b"!").unwrap();
    assert_eq!(read_all(&*vfs.lookup("/A Much Longer Name.text").unwrap()), b"PAY!");

    // Case-only change, across directories, and over an existing file.
    vfs.rename("/A Much Longer Name.text", "/a much longer name.text").unwrap();
    assert_eq!(names(&*vfs.lookup("/").unwrap()), ["a much longer name.text"]);
    vfs.mkdir("/dir", 0o755).unwrap();
    vfs.mkdir("/dir/inner", 0o755).unwrap();
    vfs.open("/dir/inner/deep.txt", NEW, 0o644).unwrap().write(0, b"deep").unwrap();
    vfs.open("/other.txt", NEW, 0o644).unwrap().write(0, &pattern(3000, 4)).unwrap();
    vfs.rename("/a much longer name.text", "/dir/x.txt").unwrap();
    vfs.rename("/dir/x.txt", "/other.txt").unwrap();
    assert_eq!(read_all(&*vfs.lookup("/other.txt").unwrap()), b"PAY!");
    assert_eq!(names(&*vfs.lookup("/").unwrap()), ["dir", "other.txt"]);

    // Directories: moved with their contents, `..` follows, and nothing
    // moves into itself or over something it cannot replace.
    vfs.mkdir("/dest", 0o755).unwrap();
    vfs.rename("/dir/inner", "/dest/inner2").unwrap();
    assert_eq!(read_all(&*vfs.lookup("/dest/inner2/deep.txt").unwrap()), b"deep");
    assert_eq!(vfs.canonicalize("/dest/inner2/..").unwrap(), "/dest");
    assert_eq!(vfs.rename("/dest", "/dest/inner2/dest").err(), Some(Errno::EINVAL));
    assert_eq!(vfs.rename("/dest", "/other.txt").err(), Some(Errno::ENOTDIR));
    assert_eq!(vfs.rename("/other.txt", "/dest").err(), Some(Errno::EISDIR));
    assert_eq!(vfs.rename("/dir", "/dest").err(), Some(Errno::ENOTEMPTY));
    vfs.rename("/dest/inner2", "/inner3").unwrap();
    assert_eq!(vfs.canonicalize("/inner3/..").unwrap(), "/");
    vfs.rename("/dest", "/dir").unwrap(); // over the now empty /dir
    assert_eq!(names(&*vfs.lookup("/").unwrap()), ["dir", "inner3", "other.txt"]);
    assert_eq!(vfs.rename("/nope", "/x").err(), Some(Errno::ENOENT));

    // A removed-while-open file replaced by a rename keeps its data.
    let held = vfs.open("/other.txt", OpenFlags::READ, 0).unwrap();
    vfs.open("/new.txt", NEW, 0o644).unwrap().write(0, b"new").unwrap();
    vfs.rename("/new.txt", "/other.txt").unwrap();
    assert_eq!(read_all(&*held), b"PAY!");
    assert_eq!(read_all(&*vfs.lookup("/other.txt").unwrap()), b"new");
    drop((held, moved, f));

    vfs.lookup("/").unwrap().sync().unwrap();
    drop(vfs);
    let report = fsck(&path, &disk);
    assert!(!report.contains("Free cluster summary wrong"), "{report}");
    // Everything is where it was left after a fresh mount, with its times.
    let fs2 = FatFs::mount(disk.clone(), 8).unwrap();
    let vfs = Vfs::new(fs2.root());
    assert_eq!(read_all(&*vfs.lookup("/other.txt").unwrap()), b"new");
    assert_eq!(read_all(&*vfs.lookup("/inner3/deep.txt").unwrap()), b"deep");
    assert_eq!(vfs.stat("/other.txt", true).unwrap().mtime, Timestamp::from_civil(2024, 5, 7, 8, 8, 10));
    let _ = std::fs::remove_file(&path);
}

// --- Crafted volumes -------------------------------------------------------

/// A disk in memory that stores only the sectors written to it (the rest
/// read as zeroes), with any block size, for hand-made volumes.
#[derive(Clone)]
struct Sparse {
    block: usize,
    bytes: u64,
    sectors: Arc<Mutex<BTreeMap<u64, [u8; 512]>>>,
}

impl Sparse {
    /// Copies between `buf` and the disk at byte `at`.
    fn copy(&self, at: u64, buf: &mut [u8], write: bool) {
        let mut sectors = self.sectors.lock().unwrap();
        let mut done = 0;
        while done < buf.len() {
            let pos = at + done as u64;
            let (s, within) = (pos / 512, (pos % 512) as usize);
            let n = (512 - within).min(buf.len() - done);
            if write {
                sectors.entry(s).or_insert([0; 512])[within..within + n].copy_from_slice(&buf[done..done + n]);
            } else {
                let sector = sectors.get(&s).copied().unwrap_or([0; 512]);
                buf[done..done + n].copy_from_slice(&sector[within..within + n]);
            }
            done += n;
        }
    }

    fn put(&self, at: u64, data: &[u8]) {
        self.copy(at, &mut data.to_vec(), true);
    }
}

impl BlockDevice for Sparse {
    fn block_size(&self) -> usize {
        self.block
    }
    fn num_blocks(&self) -> u64 {
        self.bytes / self.block as u64
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.copy(lba * self.block as u64, buf, false);
        Ok(())
    }
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.put(lba * self.block as u64, buf);
        Ok(())
    }
}

/// Layout of [`crafted`]: one-sector clusters, two FATs of 513 sectors
/// after 32 reserved, then 65536 clusters.
const FAT_START: u64 = 32 * 512;
const FAT_BYTES: u64 = 513 * 512;
const DATA_START: u64 = FAT_START + 2 * FAT_BYTES;

/// A minimal FAT32 volume with an empty root directory in cluster 2, whose
/// FSInfo claims `free` free clusters.
fn crafted(free: u32) -> Sparse {
    let total = DATA_START / 512 + 65536;
    let disk = Sparse { block: 512, bytes: total * 512, sectors: Default::default() };
    let mut b = [0u8; 512];
    b[11..13].copy_from_slice(&512u16.to_le_bytes());
    b[13] = 1;
    b[14..16].copy_from_slice(&32u16.to_le_bytes());
    b[16] = 2;
    b[32..36].copy_from_slice(&(total as u32).to_le_bytes());
    b[36..40].copy_from_slice(&513u32.to_le_bytes());
    b[44..48].copy_from_slice(&2u32.to_le_bytes());
    b[48..50].copy_from_slice(&1u16.to_le_bytes());
    b[510..512].copy_from_slice(&[0x55, 0xaa]);
    disk.put(0, &b);
    let mut info = [0u8; 512];
    info[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    info[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    info[488..492].copy_from_slice(&free.to_le_bytes());
    info[492..496].copy_from_slice(&3u32.to_le_bytes());
    info[508..512].copy_from_slice(&0xaa55_0000u32.to_le_bytes());
    disk.put(512, &info);
    set_fat(&disk, 0, 0x0fff_fff8);
    set_fat(&disk, 1, 0x0fff_ffff);
    set_fat(&disk, 2, 0x0fff_ffff);
    disk
}

fn set_fat(disk: &Sparse, c: u32, value: u32) {
    for copy in 0..2 {
        disk.put(FAT_START + copy * FAT_BYTES + c as u64 * 4, &value.to_le_bytes());
    }
}

/// Puts short entry number `i` of the root directory.
fn root_entry(disk: &Sparse, i: u64, name: &[u8; 11], attr: u8, first: u32, size: u32) {
    let mut e = [0u8; 32];
    e[..11].copy_from_slice(name);
    e[11] = attr;
    e[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    disk.put(DATA_START + i * 32, &e);
}

#[test]
fn crafted_volume_mounts() {
    let fs = FatFs::mount(crafted(65535), 1).unwrap();
    assert!(names(&*fs.root()).is_empty());
}

#[test]
fn rejects_odd_block_sizes() {
    for block in [300, 768] {
        let disk = Sparse { block, ..crafted(65535) };
        assert_eq!(FatFs::mount(disk, 1).err(), Some(Errno::EINVAL), "{block}-byte blocks");
    }
}

#[test]
fn fsinfo_free_count_is_only_a_hint() {
    let fs = FatFs::mount(crafted(0), 1).unwrap();
    let f = fs.root().create("file", FileKind::Regular, 0o644).unwrap();
    assert_eq!(f.write(0, b"room after all"), Ok(14));
    assert_eq!(read_all(&*f), b"room after all");
}

#[test]
fn creating_in_a_directory_without_a_chain_leaks_nothing() {
    let disk = crafted(65535);
    root_entry(&disk, 0, b"BADDIR     ", 0x10, 0, 0);
    let fs = FatFs::mount(disk.clone(), 1).unwrap();
    let bad = fs.root().lookup("baddir").unwrap();
    for kind in [FileKind::Regular, FileKind::Directory] {
        assert_eq!(bad.create("x", kind, 0o644).err(), Some(Errno::EIO));
    }
    drop(fs);
    // Cluster 3 onwards is still free.
    let mut fat = [0u8; 16];
    disk.copy(FAT_START + 12, &mut fat, false);
    assert_eq!(fat, [0; 16]);
}

#[test]
fn cluster_cycles_are_errors() {
    let disk = crafted(65535);
    root_entry(&disk, 0, b"LOOP       ", 0x20, 3, 100);
    set_fat(&disk, 3, 3);
    root_entry(&disk, 1, b"DIRLOOP    ", 0x10, 4, 0);
    set_fat(&disk, 4, 4);
    let fs = FatFs::mount(disk, 1).unwrap();
    let root = fs.root();
    let f = root.lookup("loop").unwrap();
    // Past the end there is nothing to read, so the chain is not walked.
    assert_eq!(f.read(1 << 40, &mut [0u8; 16]), Ok(0));
    assert_eq!(f.read(0, &mut [0u8; 16]), Ok(16));
    // Further along the chain than the volume has clusters.
    assert_eq!(f.write(40_000_000, b"x"), Err(Errno::EIO));
    let d = root.lookup("dirloop").unwrap();
    assert_eq!(d.readdir(0).err(), Some(Errno::EIO));
    assert_eq!(d.lookup("x").err(), Some(Errno::EIO));
}

#[test]
fn directories_have_a_size_limit() {
    // A root directory of 4097 clusters: one more than 65536 entries need.
    let disk = crafted(65535);
    for c in 2..4098 {
        set_fat(&disk, c, c + 1);
    }
    set_fat(&disk, 4098, 0x0fff_ffff);
    let fs = FatFs::mount(disk.clone(), 1).unwrap();
    assert_eq!(fs.root().readdir(0).err(), Some(Errno::EIO));
    drop(fs);

    // At the limit it reads, but a full one does not grow past it.
    set_fat(&disk, 4097, 0x0fff_ffff);
    for i in 0..65536 {
        root_entry(&disk, i, b"LABEL      ", 0x08, 0, 0);
    }
    let fs = FatFs::mount(disk, 1).unwrap();
    let root = fs.root();
    assert!(root.readdir(0).unwrap().is_none());
    assert_eq!(root.create("new", FileKind::Regular, 0o644).err(), Some(Errno::ENOSPC));
}

// --- Hand-made FAT12 and FAT16 volumes --------------------------------------

/// A small volume with one-sector clusters, one reserved sector, two FATs
/// and a fixed root directory, laid out like a floppy (FAT12) or a small
/// disk (FAT16).
#[derive(Clone, Copy)]
struct Small {
    fat12: bool,
    fat_sectors: u64,
    root_entries: u64,
    clusters: u64,
}

const FLOPPY: Small = Small { fat12: true, fat_sectors: 9, root_entries: 224, clusters: 2847 };
const DISK16: Small = Small { fat12: false, fat_sectors: 20, root_entries: 512, clusters: 5000 };

impl Small {
    fn root_start(&self) -> u64 {
        1 + 2 * self.fat_sectors
    }

    fn data_start(&self) -> u64 {
        self.root_start() + self.root_entries * 32 / 512
    }

    fn eoc(&self) -> u32 {
        if self.fat12 { 0xfff } else { 0xffff }
    }

    fn make(&self) -> Sparse {
        let total = self.data_start() + self.clusters;
        let disk = Sparse { block: 512, bytes: total * 512, sectors: Default::default() };
        let mut b = [0u8; 512];
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = 1;
        b[14..16].copy_from_slice(&1u16.to_le_bytes());
        b[16] = 2;
        b[17..19].copy_from_slice(&(self.root_entries as u16).to_le_bytes());
        b[19..21].copy_from_slice(&(total as u16).to_le_bytes());
        b[22..24].copy_from_slice(&(self.fat_sectors as u16).to_le_bytes());
        b[510..512].copy_from_slice(&[0x55, 0xaa]);
        disk.put(0, &b);
        self.set(&disk, 0, self.eoc() - 7);
        self.set(&disk, 1, self.eoc());
        disk
    }

    fn entry_at(&self, c: u64) -> u64 {
        if self.fat12 { c + c / 2 } else { c * 2 }
    }

    /// Sets FAT entry `c` in both copies, packing it the way the format says.
    fn set(&self, disk: &Sparse, c: u32, value: u32) {
        for copy in 0..2 {
            let at = 512 + copy * self.fat_sectors * 512 + self.entry_at(c as u64);
            if self.fat12 {
                let mut cur = [0u8; 2];
                disk.copy(at, &mut cur, false);
                let old = u16::from_le_bytes(cur);
                let v = value as u16;
                let new = if c % 2 == 1 { (old & 0xf) | v << 4 } else { (old & 0xf000) | v };
                disk.put(at, &new.to_le_bytes());
            } else {
                disk.put(at, &(value as u16).to_le_bytes());
            }
        }
    }

    /// FAT entry `c` as stored in copy `copy`.
    fn get(&self, disk: &Sparse, copy: u64, c: u32) -> u32 {
        let at = 512 + copy * self.fat_sectors * 512 + self.entry_at(c as u64);
        let mut cur = [0u8; 2];
        disk.copy(at, &mut cur, false);
        let v = u16::from_le_bytes(cur) as u32;
        match (self.fat12, c % 2) {
            (false, _) => v,
            (true, 1) => v >> 4,
            (true, _) => v & 0xfff,
        }
    }

    /// Puts short entry number `i` of the root directory.
    fn root_entry(&self, disk: &Sparse, i: u64, name: &[u8; 11], attr: u8, first: u32, size: u32) {
        let mut e = [0u8; 32];
        e[..11].copy_from_slice(name);
        e[11] = attr;
        e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        e[28..32].copy_from_slice(&size.to_le_bytes());
        disk.put(self.root_start() * 512 + i * 32, &e);
    }

    /// The clusters of the chain from `first`, read straight off the disk.
    fn chain(&self, disk: &Sparse, first: u32) -> Vec<u32> {
        let mut out = vec![first];
        loop {
            let last = *out.last().unwrap();
            let next = self.get(disk, 0, last);
            assert_eq!(next, self.get(disk, 1, last), "FAT copies differ");
            if next >= self.eoc() - 7 {
                return out;
            }
            assert!(next >= 2 && out.len() <= self.clusters as usize, "bad chain");
            out.push(next);
        }
    }
}

#[test]
fn small_volumes_mount_as_the_right_type() {
    for small in [FLOPPY, DISK16] {
        let fs = FatFs::mount(small.make(), 1).unwrap();
        let root = fs.root();
        assert!(names(&*root).is_empty());
        assert_eq!(root.stat().kind, FileKind::Directory);
        assert_eq!(root.stat().size, small.root_entries * 32, "the fixed root's size");
        assert_eq!(fs.free_bytes(), Some(small.clusters * 512));
    }
}

#[test]
fn existing_chains_across_fat12_sector_boundaries() {
    // Cluster 341's 12 bits straddle FAT sectors 0 and 1 (bytes 511 and 512).
    let disk = FLOPPY.make();
    let (a, b, c) = (340, 341, 342);
    FLOPPY.set(&disk, a, b);
    FLOPPY.set(&disk, b, c);
    FLOPPY.set(&disk, c, 0xfff);
    assert_eq!(FLOPPY.get(&disk, 0, b), c);
    FLOPPY.root_entry(&disk, 0, b"SPAN    BIN", 0x20, a, 1500);
    let content = pattern(1500, 9);
    for (i, cl) in [a, b, c].into_iter().enumerate() {
        let end = ((i + 1) * 512).min(1500);
        disk.put((FLOPPY.data_start() + cl as u64 - 2) * 512, &content[i * 512..end]);
    }
    let fs = FatFs::mount(disk.clone(), 1).unwrap();
    let f = fs.root().lookup("span.bin").unwrap();
    assert_eq!(read_all(&*f), content);
    // The neighbours' entries survive a rewrite of the straddling one.
    f.truncate(600).unwrap();
    assert_eq!(FLOPPY.chain(&disk, a), [a, b]);
    assert_eq!(FLOPPY.get(&disk, 0, c), 0, "the freed cluster reads free");
    assert_eq!(read_all(&*f), content[..600]);
}

fn write_and_check_large(small: Small, len: usize) {
    let disk = small.make();
    let fs = FatFs::mount(disk.clone(), 1).unwrap();
    let vfs = Vfs::new(fs.root());
    let data = pattern(len, 5);
    vfs.open("/big.dat", NEW, 0o644).unwrap().write(0, &data).unwrap();
    vfs.mkdir("/sub", 0o755).unwrap();
    vfs.open("/sub/small.txt", NEW, 0o644).unwrap().write(0, b"inside").unwrap();
    assert_eq!(fs.free_bytes(), Some((small.clusters - len.div_ceil(512) as u64 - 2) * 512));
    drop(vfs);
    drop(fs);

    // Everything is on disk: the chain read without this crate is intact and
    // starts where the root directory entry says.
    let mut e = [0u8; 32];
    disk.copy(small.root_start() * 512, &mut e, false);
    assert_eq!(&e[..11], b"BIG     DAT");
    let first = u16::from_le_bytes([e[26], e[27]]) as u32;
    assert_eq!(u32::from_le_bytes(e[28..32].try_into().unwrap()), len as u32);
    let chain = small.chain(&disk, first);
    assert_eq!(chain.len(), len.div_ceil(512));
    let mut sorted = chain.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), chain.len(), "no cluster twice");

    let fs = FatFs::mount(disk.clone(), 1).unwrap();
    let vfs = Vfs::new(fs.root());
    assert_eq!(read_all(&*vfs.lookup("/big.dat").unwrap()), data);
    assert_eq!(read_all(&*vfs.lookup("/sub/small.txt").unwrap()), b"inside");
    // Removing frees the whole chain in both FAT copies.
    vfs.unlink("/big.dat").unwrap();
    for cl in chain {
        assert_eq!((small.get(&disk, 0, cl), small.get(&disk, 1, cl)), (0, 0));
    }
    assert_eq!(fs.free_bytes(), Some((small.clusters - 2) * 512));
}

#[test]
fn fat12_large_file_round_trip() {
    // 400 clusters, crossing FAT sector boundaries several times.
    write_and_check_large(FLOPPY, 400 * 512 - 100);
}

#[test]
fn fat16_large_file_round_trip() {
    write_and_check_large(DISK16, 700 * 512 + 3);
}

#[test]
fn fixed_root_directory_fills_up() {
    for small in [FLOPPY, DISK16] {
        let fs = FatFs::mount(small.make(), 1).unwrap();
        let root = fs.root();
        let mut made = 0;
        let err = loop {
            match root.create(&format!("f{made}"), FileKind::Regular, 0o644) {
                Ok(_) => made += 1,
                Err(e) => break e,
            }
            assert!(made <= small.root_entries, "no limit");
        };
        assert_eq!((err, made), (Errno::ENOSPC, small.root_entries));
        assert_eq!(names(&*root).len() as u64, made);
        // Subdirectories are chains and still grow; freeing a root slot
        // makes room again.
        root.remove("f3", false).unwrap();
        let again = root.create("again", FileKind::Directory, 0o755).unwrap();
        for i in 0..40 {
            again.create(&format!("long file name {i}"), FileKind::Regular, 0o644).unwrap();
        }
        assert_eq!(names(&*again).len(), 40);
        assert_eq!(root.create("one more", FileKind::Regular, 0o644).err(), Some(Errno::ENOSPC));
    }
}

#[test]
fn bad_chains_in_small_fats_are_errors() {
    for small in [FLOPPY, DISK16] {
        let disk = small.make();
        // A bad-cluster mark, a link outside the volume, a link to a free
        // cluster and one to the reserved cluster 1, each after one cluster.
        let links = [small.eoc() - 8, small.clusters as u32 + 2, 0, 1];
        for (i, link) in links.into_iter().enumerate() {
            let c = 10 + i as u32 * 2;
            small.set(&disk, c, link);
            let name = format!("BAD{i}       ");
            small.root_entry(&disk, i as u64, name.as_bytes().try_into().unwrap(), 0x20, c, 2000);
        }
        let fs = FatFs::mount(disk, 1).unwrap();
        for i in 0..4 {
            let f = fs.root().lookup(&format!("bad{i}")).unwrap();
            assert_eq!(f.read(0, &mut [0u8; 16]), Ok(16));
            assert_eq!(f.read(600, &mut [0u8; 16]), Err(Errno::EIO), "link {i}");
        }
    }
}

#[test]
fn fat16_entry_high_word_is_ignored() {
    // Old systems keep an EA index where FAT32 has the cluster's high word.
    let disk = DISK16.make();
    DISK16.set(&disk, 5, 0xffff);
    DISK16.root_entry(&disk, 0, b"EA      BIN", 0x20, 5, 4);
    disk.put(DISK16.root_start() * 512 + 20, &0x1234u16.to_le_bytes());
    disk.put((DISK16.data_start() + 3) * 512, b"data");
    let fs = FatFs::mount(disk, 1).unwrap();
    assert_eq!(read_all(&*fs.root().lookup("ea.bin").unwrap()), b"data");
}

#[test]
fn a_full_mkfs_floppy_stays_consistent() {
    // Fill a FAT12 floppy to the brim, then free it again.
    let Some((path, disk)) = mkfs("full12.img", "12", "1440") else { return };
    let fs = FatFs::mount(disk.clone(), 1).unwrap();
    let vfs = Vfs::new(fs.root());
    let f = vfs.open("/fill", NEW, 0o644).unwrap();
    let chunk = pattern(512, 1);
    let mut off = 0u64;
    let err = loop {
        match f.write(off, &chunk) {
            Ok(_) => off += 512,
            Err(e) => break e,
        }
    };
    assert_eq!(err, Errno::ENOSPC);
    assert!(off > 1_000_000, "{off}");
    assert_eq!(fs.free_bytes(), Some(0));
    drop(f);
    fsck(&path, &disk);
    vfs.unlink("/fill").unwrap();
    assert!(fs.free_bytes().unwrap() >= off);
    drop(vfs);
    fsck(&path, &disk);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn rmdir_counts_entries_that_cannot_be_listed() {
    let disk = crafted(65535);
    root_entry(&disk, 0, b"SUB        ", 0x10, 3, 0);
    set_fat(&disk, 3, 0x0fff_ffff);
    // Cluster 3 holds `.`, `..` and a name with a slash, which no lookup finds.
    let mut e = [0u8; 96];
    e[..11].copy_from_slice(b".          ");
    e[11] = 0x10;
    e[32..43].copy_from_slice(b"..         ");
    e[43] = 0x10;
    e[64..75].copy_from_slice(b"A/B     TXT");
    disk.put(DATA_START + 512, &e);
    let fs = FatFs::mount(disk, 1).unwrap();
    let root = fs.root();
    assert!(names(&*root.lookup("sub").unwrap()).is_empty());
    assert_eq!(root.remove("sub", true).err(), Some(Errno::ENOTEMPTY));
}

#[test]
fn readdir_sees_changes_made_after_it_was_cached() {
    let fs = FatFs::mount(crafted(65535), 1).unwrap();
    let root = fs.root();
    root.create("one", FileKind::Regular, 0o644).unwrap();
    assert_eq!(names(&*root), ["one"]);
    root.create("two", FileKind::Regular, 0o644).unwrap();
    assert_eq!(names(&*root), ["one", "two"]);
    root.remove("one", false).unwrap();
    assert_eq!(names(&*root), ["two"]);
}
