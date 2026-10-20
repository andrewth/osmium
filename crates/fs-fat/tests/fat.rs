//! End-to-end tests against volumes made by `mkfs.fat` and checked with
//! `fsck.fat` (dosfstools). Skipped, with a note, if those are missing.

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
