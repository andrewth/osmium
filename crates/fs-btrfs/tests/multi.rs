#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Volumes over several devices (RAID0, RAID1, RAID1C3, RAID1C4, RAID10,
//! RAID5, RAID6, degraded and with damaged devices), and the SHA-256 and
//! BLAKE2b checksums, on images made by `mkfs.btrfs`. Skipped, with a note,
//! if the tools are missing.

use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use osmium_fs::{Errno, File, OpenFlags, Vfs};
use osmium_fs_btrfs::{BtrfsFs, MountOptions, MultiDevice};
use osmium_hal::block::{BlockDevice, BlockError};

#[derive(Clone)]
struct FileDisk {
    file: Arc<std::fs::File>,
    len: u64,
}

impl FileDisk {
    fn open(path: &Path) -> Self {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        let len = file.metadata().unwrap().len();
        FileDisk { file: Arc::new(file), len }
    }
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
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        self.file.write_all_at(buf, lba * 4096).map_err(|_| BlockError::Io)
    }
}

fn tool(name: &str) -> Option<PathBuf> {
    let found = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|d| Path::new(d).join(name)).find(|p| p.exists());
    if found.is_none() {
        eprintln!("{name} not found; skipping");
    }
    found
}

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
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-m-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 11) as u8).collect()
}

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

/// Files to put on the volume, with several stripes' worth in the big ones.
fn files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("hello.txt", b"hello, btrfs\n".to_vec()),
        ("big.bin", pattern(3 << 20, 2)),
        ("noise", noise(700_000, 7)),
        ("odd", pattern(65_536 * 3 + 123, 9)),
        ("docs/deep/bottom.txt", b"three levels down\n".to_vec()),
        ("docs/more", noise(300_000, 11)),
    ]
}

const SIZE: u64 = 256 << 20;

fn sparse_images(dir: &Path, n: usize) -> Vec<PathBuf> {
    let imgs: Vec<PathBuf> = (1..=n).map(|i| dir.join(format!("dev{i}"))).collect();
    for img in &imgs {
        let _ = std::fs::remove_file(img);
        std::fs::File::create(img).unwrap().set_len(SIZE).unwrap();
    }
    imgs
}

/// An empty volume of `n` devices made with `args` (`mkfs.btrfs --rootdir`
/// takes one device only).
fn mkfs(dir: &Path, n: usize, args: &[&str]) -> Option<Vec<PathBuf>> {
    let mkfs = tool("mkfs.btrfs")?;
    tool("btrfs")?;
    let imgs = sparse_images(dir, n);
    let out = Command::new(mkfs).arg("-q").arg("-f").args(args).args(&imgs).output().unwrap();
    assert!(out.status.success(), "mkfs.btrfs {args:?} over {n}: {}", String::from_utf8_lossy(&out.stderr));
    Some(imgs)
}

const RO: MountOptions = MountOptions { subvol: None, read_only: true };

fn mount(imgs: &[&Path], opts: MountOptions) -> Result<BtrfsFs<FileDisk>, Errno> {
    let mut md = MultiDevice::new();
    for i in imgs {
        md.add(FileDisk::open(i))?;
    }
    BtrfsFs::mount_multi(md, 9, opts)
}

fn paths(imgs: &[PathBuf]) -> Vec<&Path> {
    imgs.iter().map(|p| &**p).collect()
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

/// Writes [`files`] through the driver.
fn populate(fs: &BtrfsFs<FileDisk>) {
    let vfs = Vfs::new(fs.root());
    let _ = vfs.mkdir("/docs", 0o755);
    let _ = vfs.mkdir("/docs/deep", 0o755);
    for (name, data) in files() {
        let f = vfs.open(&format!("/{name}"), OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNC, 0o644).unwrap();
        assert_eq!(f.write(0, &data).unwrap(), data.len(), "{name}");
    }
}

/// Every file of [`files`] reads back.
fn verify(fs: &BtrfsFs<FileDisk>) {
    let vfs = Vfs::new(fs.root());
    for (name, data) in files() {
        let got = cat(&vfs, &format!("/{name}"));
        assert!(got == data, "{name} differs ({} bytes, want {})", got.len(), data.len());
    }
}

/// Everything under the root directory is listed and the volume is whole as
/// far as the trees go (an empty volume, from `mkfs.btrfs`).
fn touch(fs: &BtrfsFs<FileDisk>) {
    let root = fs.root();
    assert!(root.readdir(0).unwrap().is_none());
}

fn check(img: &Path, data: bool) {
    let mut cmd = Command::new(tool("btrfs").unwrap());
    cmd.args(["check", "--readonly"]);
    if data {
        cmd.arg("--check-data-csum");
    }
    let out = cmd.arg(img).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && !text.contains("ERROR"), "btrfs check {}:\n{text}", img.display());
}

fn is_parity(d: &str, m: &str) -> bool {
    [d, m].iter().any(|p| p.starts_with("raid5") || p.starts_with("raid6"))
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { crc >> 1 ^ 0x82f6_3b78 } else { crc >> 1 };
        }
    }
    !crc
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn put64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn seal(b: &mut [u8]) {
    let c = crc32c(&b[32..]);
    b[..4].copy_from_slice(&c.to_le_bytes());
    b[4..32].fill(0);
}

const STRIP: usize = 64 << 10;

/// GF(2^8) multiply by 2 (polynomial 0x11d).
fn mul2(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1d } else { 0 }
}

/// A RAID5 (`parity` 1) or RAID6 (`parity` 2) volume of `n` devices with
/// [`files`] on it, made from a populated single-device image by laying its
/// data chunk out in stripes (metadata stays on the first device): `mkfs`
/// does not populate a volume of several devices. The strips and the parity
/// are made here, by the textbook definition of the layout.
fn parity_volume(dir: &Path, n: usize, parity: usize) -> Option<Vec<PathBuf>> {
    let mkfs = tool("mkfs.btrfs")?;
    tool("btrfs")?;
    let src = dir.join("src");
    for (name, data) in files() {
        let p = src.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }
    let imgs = sparse_images(dir, n);
    let out = Command::new(mkfs)
        .args(["-q", "-f", "-d", "single", "-m", "single", "--rootdir"])
        .arg(&src)
        .arg(&imgs[0])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let single = std::fs::read(&imgs[0]).unwrap();
    let mut sb = single[65536..65536 + 4096].to_vec();
    let nodesize = u32::from_le_bytes(sb[148..152].try_into().unwrap()) as usize;

    // Logical to physical, through the system chunk of the superblock.
    let sys = u32::from_le_bytes(sb[160..164].try_into().unwrap()) as usize;
    let arr = &sb[811..811 + sys];
    let (sys_logical, sys_len, sys_phys) = (le64(arr, 9), le64(arr, 17), le64(arr, 17 + 48 + 8));
    let phys = |logical: u64| {
        assert!(logical >= sys_logical && logical < sys_logical + sys_len, "chunk tree outside the system chunk");
        (sys_phys + logical - sys_logical) as usize
    };

    // The chunk tree: a single leaf. Find the data chunk and give it stripes.
    let root = phys(le64(&sb, 88));
    let mut leaf = single[root..root + nodesize].to_vec();
    assert_eq!(leaf[100], 0, "the chunk tree is more than a leaf");
    let count = u32::from_le_bytes(leaf[96..100].try_into().unwrap()) as usize;
    let mut items = Vec::new();
    let mut data_chunks = Vec::new();
    for i in 0..count {
        let at = 101 + i * 25;
        let key = leaf[at..at + 17].to_vec();
        let off = u32::from_le_bytes(leaf[at + 17..at + 21].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(leaf[at + 21..at + 25].try_into().unwrap()) as usize;
        let body = leaf[101 + off..101 + off + size].to_vec();
        if key[8] == 228 && le64(&body, 24) & 1 != 0 {
            data_chunks.push((i, le64(&body, 0), le64(&body, 48 + 8)));
        }
        items.push((key, body));
    }
    assert!(!data_chunks.is_empty(), "a data chunk");
    let nd = n - parity;
    let ty = 1 | if parity == 1 { 1 << 7 } else { 1 << 8 };
    for &(at, _, base) in &data_chunks {
        let mut body = items[at].1[..48].to_vec();
        put64(&mut body, 16, STRIP as u64);
        put64(&mut body, 24, ty);
        body[44..46].copy_from_slice(&(n as u16).to_le_bytes());
        body[46..48].copy_from_slice(&1u16.to_le_bytes());
        for d in 0..n {
            let mut stripe = vec![0u8; 32];
            put64(&mut stripe, 0, d as u64 + 1);
            put64(&mut stripe, 8, base);
            body.extend_from_slice(&stripe);
        }
        items[at].1 = body;
    }
    // Items go back to the end of the block in order.
    let mut end = nodesize - 101;
    for (i, (key, body)) in items.iter().enumerate() {
        end -= body.len();
        let at = 101 + i * 25;
        leaf[at..at + 17].copy_from_slice(key);
        leaf[at + 17..at + 21].copy_from_slice(&(end as u32).to_le_bytes());
        leaf[at + 21..at + 25].copy_from_slice(&(body.len() as u32).to_le_bytes());
        leaf[101 + end..101 + end + body.len()].copy_from_slice(body);
    }
    assert!(101 + count * 25 <= 101 + end);
    seal(&mut leaf);
    std::fs::OpenOptions::new().write(true).open(&imgs[0]).unwrap().write_all_at(&leaf, root as u64).unwrap();

    // The data, strip by strip.
    let dev_files: Vec<std::fs::File> =
        imgs.iter().map(|p| std::fs::OpenOptions::new().write(true).open(p).unwrap()).collect();
    for &(_, length, base) in &data_chunks {
        let rows = (length as usize).div_ceil(STRIP * nd);
        for row in 0..rows {
            let mut strips: Vec<Vec<u8>> = (0..nd)
                .map(|i| {
                    let from = base as usize + (row * nd + i) * STRIP;
                    let mut v = single.get(from..from + STRIP).map(<[u8]>::to_vec).unwrap_or_default();
                    v.resize(STRIP, 0);
                    // Only the chunk's own bytes are data.
                    let first = (row * nd + i) * STRIP;
                    if first + STRIP > length as usize {
                        v[(length as usize).saturating_sub(first).min(STRIP)..].fill(0);
                    }
                    v
                })
                .collect();
            let mut p = vec![0u8; STRIP];
            let mut q = vec![0u8; STRIP];
            for s in &strips {
                for (a, b) in p.iter_mut().zip(s) {
                    *a ^= b;
                }
            }
            // Horner: Q = ((D[nd-1] * g + D[nd-2]) * g + ...) + D[0].
            for s in strips.iter().rev() {
                for (a, b) in q.iter_mut().zip(s) {
                    *a = mul2(*a) ^ b;
                }
            }
            strips.push(p);
            if parity == 2 {
                strips.push(q);
            }
            for (role, s) in strips.iter().enumerate() {
                dev_files[(role + row) % n].write_all_at(s, base + (row * STRIP) as u64).unwrap();
            }
        }
    }

    // The superblock of each device: the number of devices, and its own id.
    put64(&mut sb, 136, n as u64);
    for (d, dev) in dev_files.iter().enumerate() {
        let mut b = sb.clone();
        put64(&mut b, 201, d as u64 + 1);
        seal(&mut b);
        dev.write_all_at(&b, 65536).unwrap();
    }
    Some(imgs)
}

/// (data profile, metadata profile, devices)
const LAYOUTS: &[(&str, &str, usize)] = &[
    ("single", "single", 3),
    ("single", "raid1", 2),
    ("raid0", "raid1", 2),
    ("raid0", "raid0", 3),
    ("raid0", "raid1c3", 3),
    ("raid1", "raid1", 2),
    ("raid1c3", "raid1c3", 3),
    ("raid1c4", "raid1c4", 4),
    ("raid10", "raid10", 4),
    ("raid10", "raid1", 2),
    ("raid10", "raid10", 5),
];

/// (parity profile, devices)
const PARITY: &[(usize, usize)] = &[(1, 3), (1, 5), (2, 4), (2, 5)];

/// A volume with [`files`] on it: made, then written through the driver where
/// it can be, else laid out by [`parity_volume`].
fn populated(dir: &Path, d: &str, m: &str, n: usize) -> Option<Vec<PathBuf>> {
    if d.starts_with("raid5") || d.starts_with("raid6") {
        return parity_volume(dir, n, if d == "raid5" { 1 } else { 2 });
    }
    let imgs = mkfs(dir, n, &["-d", d, "-m", m])?;
    let fs = mount(&paths(&imgs), MountOptions::default()).unwrap();
    assert!(!fs.is_read_only(), "-d {d} -m {m} over {n} should be writable");
    populate(&fs);
    Some(imgs)
}

fn layouts() -> impl Iterator<Item = (&'static str, &'static str, usize)> {
    LAYOUTS
        .iter()
        .copied()
        .chain(PARITY.iter().map(|&(p, n)| if p == 1 { ("raid5", "single", n) } else { ("raid6", "single", n) }))
}

/// Volumes `mkfs` made empty: the trees it wrote are read from the layout it
/// chose, and, where there is redundancy, with devices missing.
#[test]
fn empty_volumes_from_mkfs() {
    let all: Vec<(&str, &str, usize)> = LAYOUTS
        .iter()
        .copied()
        .chain([("raid5", "raid5", 3), ("raid5", "raid5", 5), ("raid6", "raid6", 4), ("raid6", "raid6", 5)])
        .chain([("raid5", "raid1", 3), ("raid6", "raid1c3", 4)])
        .collect();
    for (d, m, n) in all {
        let dir = scratch(&format!("empty-{d}-{m}-{n}"));
        let Some(imgs) = mkfs(&dir, n, &["-d", d, "-m", m]) else { return };
        eprintln!("-d {d} -m {m} over {n} devices, empty");
        let fs = mount(&paths(&imgs), RO).unwrap();
        touch(&fs);
        let rw = mount(&paths(&imgs), MountOptions::default()).unwrap();
        assert_eq!(rw.is_read_only(), is_parity(d, m));
        // Any device gone, if the profiles cover it.
        let lost = match (d, m) {
            ("raid1" | "raid5" | "raid10", "raid1" | "raid5" | "raid10") if n > 2 || d == "raid1" => 1,
            ("raid6", "raid6") => 2,
            _ => 0,
        };
        for mask in 1u32..(1 << n) {
            if lost == 0 || mask.count_ones() as usize > lost {
                continue;
            }
            // RAID10 survives a device gone from each pair only.
            let have: Vec<&Path> = (0..n).filter(|i| mask >> i & 1 == 0).map(|i| &*imgs[i]).collect();
            if d == "raid10" && mask.count_ones() > 1 {
                continue;
            }
            let fs = mount(&have, MountOptions::default()).unwrap();
            assert!(fs.is_read_only());
            touch(&fs);
        }
    }
}

#[test]
fn read_every_profile() {
    for (d, m, n) in layouts() {
        let dir = scratch(&format!("read-{d}-{m}-{n}"));
        let Some(imgs) = populated(&dir, d, m, n) else { return };
        eprintln!("reading -d {d} -m {m} over {n} devices");
        let fs = mount(&paths(&imgs), RO).unwrap();
        assert!(fs.is_read_only());
        verify(&fs);
        // Any order.
        let rev: Vec<&Path> = paths(&imgs).into_iter().rev().collect();
        verify(&mount(&rev, RO).unwrap());
        let rw = mount(&paths(&imgs), MountOptions::default()).unwrap();
        assert_eq!(rw.is_read_only(), is_parity(d, m));
        verify(&rw);
    }
}

/// Devices missing: what the copies or the parity allow is still read, and
/// the volume is read-only.
#[test]
fn degraded() {
    // (data, metadata, devices, how many may go)
    for &(d, m, n, lost) in &[
        ("raid1", "raid1", 2, 1),
        ("raid1c3", "raid1c3", 3, 2),
        ("raid1c4", "raid1c4", 4, 3),
        ("raid10", "raid10", 4, 1),
        ("raid5", "single", 3, 1),
        ("raid5", "single", 5, 1),
        ("raid6", "single", 4, 2),
        ("raid6", "single", 5, 2),
    ] {
        let dir = scratch(&format!("deg-{d}-{n}"));
        let Some(imgs) = populated(&dir, d, m, n) else { return };
        for mask in 1u32..(1 << n) {
            // The first device holds the metadata of a laid-out parity volume.
            if mask.count_ones() as usize > lost || (m == "single" && mask & 1 != 0) {
                continue;
            }
            let have: Vec<&Path> = (0..n).filter(|i| mask >> i & 1 == 0).map(|i| &*imgs[i]).collect();
            eprintln!("-d {d} over {n}, devices missing {mask:0n$b}");
            let fs = mount(&have, MountOptions::default()).unwrap();
            assert!(fs.is_read_only(), "a degraded volume is not written");
            verify(&fs);
        }
        // More than the profile covers: whatever reads must be right.
        if d == "raid5" || d == "raid6" {
            let have: Vec<&Path> = [0].into_iter().chain(lost + 1..n).map(|i| &*imgs[i]).collect();
            let fs = mount(&have, RO).unwrap();
            let vfs = Vfs::new(fs.root());
            for (name, data) in files() {
                if let Ok(f) = vfs.open(&format!("/{name}"), OpenFlags::READ, 0) {
                    let mut buf = vec![0u8; data.len()];
                    if f.read(0, &mut buf).is_ok_and(|got| got == data.len()) {
                        assert!(buf == data, "{name}: wrong data from too few devices");
                    }
                }
            }
        }
    }
}

/// A device whose contents are garbage: checksums catch it and another copy,
/// or the parity, supplies the data.
#[test]
fn damaged_device() {
    for &(d, m, n) in &[
        ("raid1", "raid1", 2),
        ("raid1c3", "raid1c3", 3),
        ("raid10", "raid10", 4),
        ("raid5", "single", 3),
        ("raid6", "single", 4),
    ] {
        for victim in 0..n {
            // The first device holds the metadata of a laid-out parity volume.
            if m == "single" && victim == 0 {
                continue;
            }
            let dir = scratch(&format!("dmg-{d}-{n}-{victim}"));
            let Some(imgs) = populated(&dir, d, m, n) else { return };
            eprintln!("-d {d} over {n}, device {victim} overwritten");
            let f = std::fs::OpenOptions::new().write(true).open(&imgs[victim]).unwrap();
            let junk = noise(1 << 20, 5);
            // After the first megabyte and the superblock; across what was written.
            for i in 0..40u64 {
                f.write_all_at(&junk, (1 << 20) + i * (1 << 20)).unwrap();
            }
            verify(&mount(&paths(&imgs), RO).unwrap());
        }
    }
}

#[test]
fn bad_sets() {
    let dir = scratch("bad-sets");
    let Some(imgs) = mkfs(&dir, 2, &["-d", "raid1", "-m", "raid1"]) else { return };
    // The same device twice.
    assert_eq!(mount(&[&imgs[0], &imgs[0]], RO).err(), Some(Errno::EINVAL));
    // A device of another volume.
    let dir2 = scratch("bad-sets-2");
    let Some(other) = mkfs(&dir2, 1, &["-d", "single", "-m", "single"]) else { return };
    assert_eq!(mount(&[&imgs[0], &other[0]], RO).err(), Some(Errno::EINVAL));
    // A devid that is not what the superblock says.
    let mut md = MultiDevice::new();
    md.add_with_devid(2, FileDisk::open(&imgs[0])).unwrap();
    assert_eq!(BtrfsFs::mount_multi(md, 9, RO).err(), Some(Errno::EINVAL));
    let mut md = MultiDevice::new();
    md.add_with_devid(1, FileDisk::open(&imgs[0])).unwrap();
    md.add_with_devid(2, FileDisk::open(&imgs[1])).unwrap();
    touch(&BtrfsFs::mount_multi(md, 9, RO).unwrap());
    assert!(MultiDevice::<FileDisk>::new().is_empty());
    assert_eq!(BtrfsFs::<FileDisk>::mount_multi(MultiDevice::new(), 9, RO).err(), Some(Errno::EINVAL));
}

#[test]
fn checksum_types() {
    for csum in ["sha256", "blake2", "xxhash", "crc32c"] {
        let dir = scratch(&format!("csum-{csum}"));
        let Some(imgs) = mkfs(&dir, 1, &["--csum", csum]) else { return };
        eprintln!("--csum {csum}");
        {
            let fs = mount(&[&imgs[0]], MountOptions::default()).unwrap();
            assert!(!fs.is_read_only());
            populate(&fs);
            let vfs = Vfs::new(fs.root());
            vfs.mkdir("/dir", 0o755).unwrap();
            let f = vfs.open("/dir/small", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
            f.write(0, b"small").unwrap();
            vfs.unlink("/hello.txt").unwrap();
        }
        check(&imgs[0], true);
        let fs = mount(&[&imgs[0]], RO).unwrap();
        let vfs = Vfs::new(fs.root());
        assert_eq!(cat(&vfs, "/dir/small"), b"small");
        assert!(vfs.lookup("/hello.txt").is_err());
        assert_eq!(cat(&vfs, "/big.bin"), pattern(3 << 20, 2));
    }
}

/// Writing over several devices, onto the block groups there are.
#[test]
fn write_multi() {
    for &(d, m, n) in &[
        ("raid1", "raid1", 2),
        ("raid0", "raid1", 2),
        ("raid10", "raid1", 2),
        ("single", "raid1", 2),
        ("raid1c3", "raid1c3", 3),
        ("raid0", "raid0", 3),
    ] {
        let dir = scratch(&format!("write-{d}-{m}-{n}"));
        let Some(imgs) = populated(&dir, d, m, n) else { return };
        eprintln!("writing -d {d} -m {m} over {n} devices");
        let big = pattern(2 << 20, 77);
        {
            let fs = mount(&paths(&imgs), MountOptions::default()).unwrap();
            assert!(!fs.is_read_only());
            let vfs = Vfs::new(fs.root());
            for round in 0..3 {
                let f = vfs.open("/written", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
                assert_eq!(f.write(round * 700_000, &big[..700_000]).unwrap(), 700_000);
            }
            vfs.mkdir("/dir", 0o755).unwrap();
            for i in 0..20 {
                let f = vfs.open(&format!("/dir/f{i}"), OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
                f.write(0, &noise(1000 * (i + 1), i as u64 + 1)).unwrap();
            }
            vfs.unlink("/hello.txt").unwrap();
            let f = vfs.open("/big.bin", OpenFlags::WRITE, 0).unwrap();
            f.write(100_000, &big[..300_000]).unwrap();
        }
        let verify_after = |fs: &BtrfsFs<FileDisk>| {
            let vfs = Vfs::new(fs.root());
            let written = cat(&vfs, "/written");
            assert_eq!(written.len(), 2_100_000);
            for round in 0..3 {
                assert!(written[round * 700_000..(round + 1) * 700_000] == big[..700_000]);
            }
            for i in 0..20 {
                assert_eq!(cat(&vfs, &format!("/dir/f{i}")), noise(1000 * (i + 1), i as u64 + 1));
            }
            assert!(vfs.lookup("/hello.txt").is_err());
            let mut want = pattern(3 << 20, 2);
            want[100_000..400_000].copy_from_slice(&big[..300_000]);
            assert!(cat(&vfs, "/big.bin") == want);
            assert!(cat(&vfs, "/odd") == pattern(65_536 * 3 + 123, 9));
            assert!(cat(&vfs, "/docs/more") == noise(300_000, 11));
        };
        verify_after(&mount(&paths(&imgs), RO).unwrap());
        // Metadata is mirrored on each device, so btrfs check can go by one of
        // them (it reports the others missing); data is checked where it is
        // whole there.
        if m != "raid0" {
            for img in &imgs {
                check(img, d.starts_with("raid1"));
            }
        }
        // Each device's superblock has its own device item.
        for (i, img) in imgs.iter().enumerate() {
            let out = Command::new(tool("btrfs").unwrap())
                .args(["inspect-internal", "dump-super", "-a"])
                .arg(img)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(out.status.success() && text.contains(&format!("dev_item.devid\t\t{}", i + 1)), "{text}");
            assert!(!text.contains("FAILED") && !text.contains("bad"), "{text}");
        }
        // A device lost from a mirrored volume after the writes.
        if d.starts_with("raid1") || d == "raid10" {
            verify_after(&mount(&paths(&imgs)[1..], RO).unwrap());
        }
    }
}

#[test]
fn parity_is_read_only() {
    let dir = scratch("parity-ro");
    let Some(imgs) = populated(&dir, "raid5", "single", 3) else { return };
    let fs = mount(&paths(&imgs), MountOptions::default()).unwrap();
    assert!(fs.is_read_only());
    let vfs = Vfs::new(fs.root());
    assert_eq!(vfs.open("/new", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).err(), Some(Errno::EROFS));
}
