#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! A crash at any point of a change leaves the volume as it was before the
//! change or as it is after it. Each test records the device writes of one
//! change, then for every prefix of them rebuilds the image as a crash at
//! that point would leave it, runs `btrfs check` on it and reads it back.
//! Skipped, with a note, without btrfs-progs.

use std::collections::BTreeMap;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use osmium_fs::{File, FileKind, OpenFlags, Vfs};
use osmium_fs_btrfs::{BtrfsFs, MountOptions};
use osmium_hal::block::{BlockDevice, BlockError};

const B: usize = 4096;

/// Device writes in order: block address and data.
type Log = Arc<Mutex<Vec<(u64, Vec<u8>)>>>;

/// An image file whose writes are also logged, in order.
#[derive(Clone)]
struct LogDisk {
    file: Arc<std::fs::File>,
    len: u64,
    log: Option<Log>,
}

impl LogDisk {
    fn open(path: &Path, log: Option<Log>) -> Self {
        let file = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        let len = file.metadata().unwrap().len();
        LogDisk { file: Arc::new(file), len, log }
    }
}

impl BlockDevice for LogDisk {
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
            log.lock().unwrap().push((lba, buf.to_vec()));
        }
        self.file.write_all_at(buf, lba * B as u64).map_err(|_| BlockError::Io)
    }
}

fn tool(name: &str) -> Option<PathBuf> {
    let found = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"].iter().map(|d| Path::new(d).join(name)).find(|p| p.exists());
    if found.is_none() {
        eprintln!("{name} not found; skipping");
    }
    found
}

fn check(img: &Path) -> Result<(), String> {
    let out = Command::new(tool("btrfs").unwrap())
        .args(["check", "--readonly", "--check-data-csum"])
        .arg(img)
        .output()
        .unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() && !text.contains("ERROR") { Ok(()) } else { Err(text) }
}

/// Everything under `/`: path to contents (`None` for a directory).
fn snapshot(img: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    fn walk(dir: &dyn File, path: &str, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for e in (0..).map_while(|i| dir.readdir(i).unwrap()) {
            let p = format!("{path}/{}", e.name);
            let node = dir.lookup(&e.name).unwrap();
            if e.kind == FileKind::Directory {
                walk(&*node, &p, out);
                out.insert(p, None);
            } else {
                let mut buf = vec![0u8; node.stat().size as usize];
                let mut done = 0;
                while done < buf.len() {
                    done += node.read(done as u64, &mut buf[done..]).unwrap();
                }
                out.insert(p, Some(buf));
            }
        }
    }
    let opts = MountOptions { read_only: true, ..MountOptions::default() };
    let fs = BtrfsFs::mount_with(LogDisk::open(img, None), 1, opts).unwrap();
    let mut out = BTreeMap::new();
    walk(&*fs.root(), "", &mut out);
    out
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 11) as u8).collect()
}

type Step<'a> = &'a dyn Fn(&BtrfsFs<LogDisk>, &Vfs);

/// Runs `setup`, then `change` with its writes logged, then checks every
/// crash point of `change`.
fn crash_points(name: &str, mkfs_args: &[&str], setup: impl Fn(&Vfs), change: impl Fn(&Vfs)) {
    crash_steps(name, mkfs_args, MountOptions::default(), setup, &[&|_, vfs| change(vfs)]);
}

/// Runs `setup`, then each of `steps` with the writes logged, mounted with
/// `opts`. A step but the last must leave its changes durable (by `sync`, by
/// `batch` or by reaching `commit_batch`); the last is made so when the
/// volume is dropped. Every crash point must leave the volume as it was
/// before the first step or after one of them, never between.
fn crash_steps(name: &str, mkfs_args: &[&str], opts: MountOptions<'_>, setup: impl Fn(&Vfs), steps: &[Step<'_>]) {
    let (Some(mkfs), Some(_)) = (tool("mkfs.btrfs"), tool("btrfs")) else { return };
    let dir = std::env::temp_dir().join(format!("osmium-fs-btrfs-crash-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let img = dir.join("img");
    std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
    assert!(Command::new(mkfs).arg("-q").args(mkfs_args).arg(&img).status().unwrap().success());
    {
        let fs = BtrfsFs::mount(LogDisk::open(&img, None), 1).unwrap();
        setup(&Vfs::new(fs.root()));
    }
    let before = snapshot(&img);
    let base = dir.join("base");
    assert!(Command::new("cp").arg("--sparse=always").arg(&img).arg(&base).status().unwrap().success());
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut states = vec![before.clone()];
    {
        let fs = BtrfsFs::mount_with(LogDisk::open(&img, Some(log.clone())), 1, opts).unwrap();
        let vfs = Vfs::new(fs.root());
        for (i, step) in steps.iter().enumerate() {
            step(&fs, &vfs);
            if i + 1 < steps.len() {
                states.push(snapshot(&img));
            }
        }
    }
    states.push(snapshot(&img));
    let after = states.last().unwrap().clone();
    assert_ne!(before, after, "the change changed nothing");
    let log = log.lock().unwrap();
    assert!(!log.is_empty());
    let crashed = dir.join("crashed");
    let (mut olds, mut news) = (0, 0);
    for n in 0..=log.len() {
        assert!(Command::new("cp").arg("--sparse=always").arg(&base).arg(&crashed).status().unwrap().success());
        let f = std::fs::OpenOptions::new().write(true).open(&crashed).unwrap();
        for (lba, data) in &log[..n] {
            f.write_all_at(data, lba * B as u64).unwrap();
        }
        drop(f);
        if let Err(text) = check(&crashed) {
            panic!("{name}: crash after {n} of {} writes fails btrfs check:\n{text}", log.len());
        }
        let now = snapshot(&crashed);
        match states.iter().position(|s| *s == now) {
            Some(0) => olds += 1,
            Some(i) if i + 1 == states.len() => news += 1,
            Some(_) => {}
            None => panic!("{name}: crash after {n} of {} writes is neither before nor after", log.len()),
        }
    }
    // Before the superblock, the old state; from it on, the new.
    assert!(olds > 0 && news > 0, "{name}: {olds} old, {news} new");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn overwrite_and_extend() {
    crash_points(
        "overwrite",
        &[],
        |vfs| {
            let f = vfs.open("/f", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
            f.write(0, &pattern(300_000, 1)).unwrap();
        },
        |vfs| {
            let f = vfs.open("/f", OpenFlags::WRITE, 0).unwrap();
            f.write(100_000, &pattern(400_000, 2)).unwrap();
        },
    );
}

#[test]
fn rename_over() {
    crash_points(
        "rename",
        &["-n", "4096"],
        |vfs| {
            vfs.mkdir("/d", 0o755).unwrap();
            for i in 0..200 {
                vfs.open(&format!("/d/f{i}"), OpenFlags::WRITE | OpenFlags::CREATE, 0o644)
                    .unwrap()
                    .write(0, &pattern(i * 50, i as u8))
                    .unwrap();
            }
        },
        |vfs| vfs.rename("/d/f7", "/d/f150").unwrap(),
    );
}

#[test]
fn delete_big_file() {
    crash_points(
        "unlink",
        &[],
        |vfs| {
            vfs.open("/big", OpenFlags::WRITE | OpenFlags::CREATE, 0o644)
                .unwrap()
                .write(0, &pattern(6 << 20, 3))
                .unwrap();
            vfs.open("/keep", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap().write(0, b"keep").unwrap();
        },
        |vfs| vfs.unlink("/big").unwrap(),
    );
}

#[test]
fn new_chunk() {
    // The first data chunk is 8 MiB; this write needs another.
    crash_points(
        "chunk",
        &[],
        |vfs| {
            vfs.open("/a", OpenFlags::WRITE | OpenFlags::CREATE, 0o644)
                .unwrap()
                .write(0, &pattern(6 << 20, 4))
                .unwrap();
            vfs.open("/b", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
        },
        |vfs| {
            vfs.open("/b", OpenFlags::WRITE, 0).unwrap().write(0, &pattern(5 << 20, 5)).unwrap();
        },
    );
}

fn put(vfs: &Vfs, path: &str, data: &[u8]) {
    let f = vfs.open(path, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNC, 0o644).unwrap();
    assert_eq!(f.write(0, data).unwrap(), data.len());
}

/// Several changes in one `batch` are one change to a crash: all or none.
#[test]
fn batch_is_all_or_nothing() {
    crash_steps(
        "batch",
        &[],
        MountOptions::default(),
        |vfs| put(vfs, "/old", &pattern(100_000, 9)),
        &[&|fs, vfs| {
            fs.batch(|| {
                vfs.mkdir("/d", 0o755).unwrap();
                for i in 0..6 {
                    put(vfs, &format!("/d/f{i}"), &pattern(30_000 + i * 7000, i as u8));
                }
                vfs.rename("/d/f1", "/d/g1").unwrap();
                vfs.unlink("/old").unwrap();
                put(vfs, "/d/f0", &pattern(500_000, 77));
            })
            .unwrap();
        }],
    );
}

/// `sync`, `File::sync` and the drop of the volume each end a unit; a crash
/// at any write shows the volume at the end of one of them.
#[test]
fn deferred_commits_are_all_or_nothing() {
    let opts = MountOptions { commit_batch: 1000, ..MountOptions::default() };
    crash_steps(
        "deferred",
        &["-n", "4096"],
        opts,
        |vfs| {
            vfs.mkdir("/d", 0o755).unwrap();
            put(vfs, "/d/keep", &pattern(200_000, 5));
        },
        &[
            &|fs, vfs| {
                put(vfs, "/a", &pattern(10_000, 1));
                put(vfs, "/d/keep", &pattern(300_000, 2));
                vfs.unlink("/a").unwrap();
                fs.sync().unwrap();
            },
            &|_, vfs| {
                for i in 0..20 {
                    put(vfs, &format!("/d/n{i}"), &pattern(5000 * (i + 1), i as u8));
                }
                vfs.open("/d/keep", OpenFlags::WRITE, 0).unwrap().sync().unwrap();
            },
            &|_, vfs| put(vfs, "/after", b"after the sync"),
        ],
    );
}

/// The superblock is written on every `commit_batch`th change.
#[test]
fn threshold_commits_are_whole_groups() {
    // Creating and writing a file are two changes; two files are a group.
    let opts = MountOptions { commit_batch: 4, ..MountOptions::default() };
    crash_steps(
        "threshold",
        &[],
        opts,
        |_| {},
        &[
            &|_, vfs| {
                put(vfs, "/a", &pattern(40_000, 1));
                put(vfs, "/b", &pattern(40_000, 2));
            },
            &|_, vfs| {
                put(vfs, "/c", &pattern(40_000, 3));
                put(vfs, "/d", &pattern(40_000, 4));
            },
        ],
    );
}
