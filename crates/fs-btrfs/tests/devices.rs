#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable, clippy::string_slice)]
//! Devices: adding, removing and replacing them under a mounted volume.
//! `btrfs check` reads a volume of image files only if it has one device, so
//! the states with two are looked at through the superblocks
//! (`btrfs inspect-internal dump-super`) and through this driver, and the
//! states with one, before and after, are checked in full. Skipped, with a
//! note, without btrfs-progs.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use common::*;
use osmium_fs::{Errno, Vfs};
use osmium_fs_btrfs::{BalanceFilter, BtrfsFs};

/// `dump-super` of an image: the text, or `None` if it holds no superblock.
fn dump_super(img: &Path) -> Option<String> {
    let out = Command::new(tool("btrfs").unwrap()).args(["inspect-internal", "dump-super"]).arg(img).output().unwrap();
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A field of `dump-super`'s output.
fn field(text: &str, name: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix(name).filter(|r| r.starts_with(char::is_whitespace)).map(|r| r.trim().to_string()))
        .unwrap_or_else(|| panic!("no {name} in\n{text}"))
}

/// The superblock must be valid (checksum and magic match).
fn assert_super_ok(img: &Path) -> String {
    let text = dump_super(img).unwrap_or_else(|| panic!("{} has no superblock", img.display()));
    assert!(text.contains("[match]") && !text.contains("DON'T MATCH"), "{text}");
    text
}

fn files(vfs: &Vfs, n: usize, seed: u32) -> Vec<(String, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let data = distinct(1_500_000 + i * 4096, seed + i as u32);
            let name = format!("/big{seed}-{i}");
            put(vfs, &name, &data);
            (name, data)
        })
        .collect()
}

fn assert_files(vfs: &Vfs, want: &[(String, Vec<u8>)]) {
    for (name, data) in want {
        assert!(cat(vfs, name) == *data, "{name} differs");
    }
}

fn on_dev(fs: &BtrfsFs<Disk>, devid: u64) -> usize {
    fs.chunks().unwrap().iter().filter(|c| c.stripes.iter().any(|s| s.0 == devid)).count()
}

#[test]
fn add_use_and_remove() {
    let dir = scratch("dev-add");
    let Some(img1) = mkfs_named(&dir, "d1", 128 << 20, &[]) else { return };
    let img2 = blank(&dir, "d2", 128 << 20);
    let fs = mount(&img1);
    let vfs = Vfs::new(fs.root());
    let early = files(&vfs, 2, 1);

    let devid = fs.add_device(Disk::open(&img2)).unwrap();
    assert_eq!(devid, 2);
    let devs = fs.devices().unwrap();
    assert_eq!(devs.len(), 2);
    assert_eq!(devs[1].total_bytes, 128 << 20);
    assert_ne!(devs[0].uuid, devs[1].uuid);
    // Both superblocks are there, describe both devices, and agree.
    let (s1, s2) = (assert_super_ok(&img1), assert_super_ok(&img2));
    for s in [&s1, &s2] {
        assert_eq!(field(s, "num_devices"), "2");
        assert_eq!(field(s, "total_bytes"), (256u64 << 20).to_string());
    }
    assert_eq!(field(&s1, "dev_item.devid"), "1");
    assert_eq!(field(&s2, "dev_item.devid"), "2");
    assert_eq!(field(&s1, "generation"), field(&s2, "generation"));
    assert_eq!(field(&s2, "fsid"), field(&s1, "fsid"));
    assert_eq!(field(&s2, "dev_item.uuid"), uuid_text(&devs[1].uuid));

    // New chunks go to the device with room.
    let later = files(&vfs, 6, 2);
    assert!(on_dev(&fs, 2) > 0, "{:?}", fs.chunks().unwrap());
    assert_files(&vfs, &early);
    assert_files(&vfs, &later);
    let rep = fs.scrub(false).unwrap();
    assert!(rep.is_clean() && rep.data_sectors > 1000, "{rep:?}");
    // The statistics follow the chunks.
    let used: u64 = fs.devices().unwrap().iter().map(|d| d.bytes_used).sum();
    let chunks: u64 = fs.chunks().unwrap().iter().map(|c| c.length * c.stripes.len() as u64).sum();
    assert_eq!(used, chunks);

    // A balance of a device's chunks works the same with two devices.
    let rep = fs.balance(&BalanceFilter { devid: Some(2), data: false, ..Default::default() }).unwrap();
    assert!(rep.skipped.is_empty(), "{rep:?}");
    assert_files(&vfs, &early);

    // Removing it moves its chunks to the first and wipes it.
    let back = fs.remove_device(2).unwrap();
    drop(back);
    assert_eq!(fs.devices().unwrap().len(), 1);
    assert_eq!(on_dev(&fs, 2), 0);
    assert!(dump_super(&img2).is_none(), "the removed device still has a superblock");
    assert_eq!(fs.remove_device(2).err(), Some(Errno::ENOENT));
    assert_eq!(fs.remove_device(1).err(), Some(Errno::EOPNOTSUPP));
    assert_files(&vfs, &early);
    assert_files(&vfs, &later);
    drop(vfs);
    drop(fs);
    let s1 = assert_super_ok(&img1);
    assert_eq!(field(&s1, "num_devices"), "1");
    assert_eq!(field(&s1, "total_bytes"), (128u64 << 20).to_string());
    check(&img1);
    let vfs = Vfs::new(mount(&img1).root());
    assert_files(&vfs, &early);
    assert_files(&vfs, &later);
}

fn uuid_text(u: &[u8; 16]) -> String {
    let h: String = u.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

#[test]
fn refuses_what_it_cannot_do() {
    let dir = scratch("dev-refuse");
    let Some(img1) = mkfs_named(&dir, "d1", 128 << 20, &[]) else { return };
    let fs = mount(&img1);
    // Too small, and read-only volumes.
    let tiny = blank(&dir, "tiny", 4 << 20);
    assert_eq!(fs.add_device(Disk::open(&tiny)).err(), Some(Errno::EINVAL));
    assert_eq!(fs.replace_device(1, Disk::open(&tiny)).err(), Some(Errno::ENOSPC));
    assert_eq!(fs.replace_device(7, Disk::open(&tiny)).err(), Some(Errno::ENOENT));
    drop(fs);
    let ro = BtrfsFs::mount_with(Disk::open(&img1), 1, osmium_fs_btrfs::MountOptions { subvol: None, read_only: true })
        .unwrap();
    assert_eq!(ro.add_device(Disk::open(&blank(&dir, "d2", 128 << 20))).err(), Some(Errno::EROFS));
    assert_eq!(ro.remove_device(2).err(), Some(Errno::EROFS));
    // A volume with a second device mounts read-only here.
    drop(ro);
    let fs = mount(&img1);
    fs.add_device(Disk::open(&dir.join("d2"))).unwrap();
    drop(fs);
    let again = BtrfsFs::mount(Disk::open(&img1), 1).unwrap();
    assert!(again.is_read_only());
    assert_eq!(again.devices().unwrap().len(), 2);
}

#[test]
fn remove_runs_out_of_room() {
    let dir = scratch("dev-full");
    let Some(img1) = mkfs_named(&dir, "d1", 128 << 20, &[]) else { return };
    let fs = mount(&img1);
    let vfs = Vfs::new(fs.root());
    fs.add_device(Disk::open(&blank(&dir, "d2", 128 << 20))).unwrap();
    // More than the first device could take back.
    let want = files(&vfs, 48, 3);
    assert!(on_dev(&fs, 2) > 0);
    assert_eq!(fs.remove_device(2).err(), Some(Errno::ENOSPC));
    // Nothing was lost; the device is still part of the volume and usable.
    assert_eq!(fs.devices().unwrap().len(), 2);
    assert_files(&vfs, &want);
    assert!(fs.scrub(false).unwrap().is_clean());
    for (name, _) in want.iter().step_by(2) {
        vfs.unlink(name).unwrap();
    }
    put(&vfs, "/after", &distinct(2 << 20, 5));
    assert_eq!(cat(&vfs, "/after"), distinct(2 << 20, 5));
}

#[test]
fn replace_devices() {
    let dir = scratch("dev-replace2");
    let Some(img1) = mkfs_named(&dir, "d1", 128 << 20, &[]) else { return };
    let img3 = blank(&dir, "d3", 192 << 20);
    let img4 = blank(&dir, "d4", 128 << 20);
    let fs = mount(&img1);
    let vfs = Vfs::new(fs.root());
    let early = files(&vfs, 2, 1);
    let uuid1 = fs.devices().unwrap()[0].uuid;
    let old = fs.replace_device(1, Disk::open(&img3)).unwrap();
    drop(old);
    assert!(dump_super(&img1).is_none(), "the old device still has a superblock");
    assert_eq!(fs.devices().unwrap()[0].uuid, uuid1);
    assert_files(&vfs, &early);
    let more = files(&vfs, 1, 2);
    drop(vfs);
    drop(fs);
    check(&img3);
    let vfs = Vfs::new(mount(&img3).root());
    assert_files(&vfs, &early);
    assert_files(&vfs, &more);
    drop(vfs);

    // A device added and then replaced.
    let fs = mount(&img3);
    let vfs = Vfs::new(fs.root());
    fs.add_device(Disk::open(&blank(&dir, "d2", 128 << 20))).unwrap();
    let on_two = files(&vfs, 6, 7);
    assert!(on_dev(&fs, 2) > 0);
    let before = fs.devices().unwrap();
    fs.replace_device(2, Disk::open(&img4)).unwrap();
    assert_eq!(fs.devices().unwrap(), before);
    assert_super_ok(&img4);
    assert_files(&vfs, &on_two);
    assert!(fs.scrub(false).unwrap().is_clean());
    // Everything back on the first device, and the second out.
    fs.remove_device(2).unwrap();
    assert_files(&vfs, &on_two);
    drop(vfs);
    drop(fs);
    check(&img3);
}

/// Where each device's writes end up.
fn replay(base: &[PathBuf], work: &[PathBuf], log: &[(usize, u64, Vec<u8>)], n: usize) {
    for (b, w) in base.iter().zip(work) {
        assert!(Command::new("cp").arg("--sparse=always").arg(b).arg(w).status().unwrap().success());
    }
    for (dev, lba, data) in &log[..n] {
        write_at(&work[*dev], lba * B as u64, data);
    }
}

fn copy_all(from: &[PathBuf], to: &Path, tag: &str) -> Vec<PathBuf> {
    from.iter()
        .enumerate()
        .map(|(i, f)| {
            let t = to.join(format!("{tag}{i}"));
            assert!(Command::new("cp").arg("--sparse=always").arg(f).arg(&t).status().unwrap().success());
            t
        })
        .collect()
}

/// A crash at every device write of adding a device: the first device is
/// either the volume as it was, whole, or has the new device's superblock to
/// go with it.
#[test]
fn crash_while_adding() {
    let dir = scratch("dev-crash-add");
    let Some(img1) = mkfs_named(&dir, "d1", 128 << 20, &[]) else { return };
    let img2 = blank(&dir, "d2", 128 << 20);
    {
        let fs = mount(&img1);
        let vfs = Vfs::new(fs.root());
        files(&vfs, 2, 1);
    }
    let before = snapshot(&img1);
    let base = copy_all(&[img1.clone(), img2.clone()], &dir, "base");
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    {
        let fs = BtrfsFs::mount(Disk::logged(&img1, 0, Some(log.clone())), 1).unwrap();
        fs.add_device(Disk::logged(&img2, 1, Some(log.clone()))).unwrap();
    }
    let log = log.lock().unwrap();
    eprintln!("add made {} device writes", log.len());
    let work = [dir.join("w0"), dir.join("w1")];
    let (mut olds, mut news) = (0, 0);
    for n in 0..=log.len() {
        replay(&base, &work, &log, n);
        let sb = assert_super_ok(&work[0]);
        if field(&sb, "num_devices") == "1" {
            olds += 1;
            if let Err(t) = try_check(&work[0]) {
                panic!("crash after {n} of {} writes fails btrfs check:\n{t}", log.len());
            }
            assert!(snapshot(&work[0]) == before, "crash after {n} changed the files");
        } else {
            news += 1;
            if let Err(t) = try_check_metadata(&work[0]) {
                panic!("crash after {n} of {} writes fails btrfs check of the metadata:\n{t}", log.len());
            }
            // The second device was written first: it is there and the same generation.
            let sb2 = assert_super_ok(&work[1]);
            assert_eq!(field(&sb2, "generation"), field(&sb, "generation"), "after {n}");
            assert_eq!(field(&sb2, "num_devices"), "2");
            let ro = osmium_fs_btrfs::MountOptions { subvol: None, read_only: true };
            let fs = BtrfsFs::mount_with(Disk::open(&work[0]), 1, ro).unwrap();
            assert_eq!(fs.devices().unwrap().len(), 2);
        }
    }
    assert!(olds > 0 && news > 0, "{olds} old, {news} new");
}

/// A crash at every device write of removing a device again: the volume has
/// two devices until the commit that drops one, and one after; every step is a
/// whole volume.
#[test]
fn crash_while_removing() {
    let dir = scratch("dev-crash-rm");
    let Some(img1) = mkfs_named(&dir, "d1", 128 << 20, &[]) else { return };
    let img2 = blank(&dir, "d2", 128 << 20);
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let fs = BtrfsFs::mount(Disk::logged(&img1, 0, Some(log.clone())), 1).unwrap();
    let vfs = Vfs::new(fs.root());
    fs.add_device(Disk::logged(&img2, 1, Some(log.clone()))).unwrap();
    let want = files(&vfs, 8, 1);
    assert!(on_dev(&fs, 2) > 0);
    let expect: Snapshot = want.iter().map(|(n, d)| (n.clone(), Some(d.clone()))).collect();
    // The state to start from, and only the removal in the log.
    let base = copy_all(&[img1.clone(), img2.clone()], &dir, "base");
    log.lock().unwrap().clear();
    fs.remove_device(2).unwrap();
    drop(vfs);
    drop(fs);
    let log = log.lock().unwrap();
    eprintln!("remove made {} device writes", log.len());
    let work = [dir.join("w0"), dir.join("w1")];
    let (mut twos, mut ones) = (0, 0);
    for n in 0..=log.len() {
        replay(&base, &work, &log, n);
        let sb = assert_super_ok(&work[0]);
        if field(&sb, "num_devices") == "1" {
            ones += 1;
            if let Err(t) = try_check(&work[0]) {
                panic!("crash after {n} of {} writes fails btrfs check:\n{t}", log.len());
            }
            assert!(snapshot(&work[0]) == expect, "crash after {n} changed the files");
        } else {
            twos += 1;
            if let Err(t) = try_check_metadata(&work[0]) {
                panic!("crash after {n} of {} writes fails btrfs check of the metadata:\n{t}", log.len());
            }
            let ro = osmium_fs_btrfs::MountOptions { subvol: None, read_only: true };
            let fs = BtrfsFs::mount_with(Disk::open(&work[0]), 1, ro).unwrap();
            assert_eq!(fs.devices().unwrap().len(), 2);
            assert_super_ok(&work[1]);
        }
    }
    assert!(twos > 0 && ones > 0, "{twos} with two devices, {ones} with one");
}

/// A crash at the writes of replacing the mounted device: the old device is
/// the volume until the new one has its superblock, and the new one after.
/// The copy that comes first leaves the old device alone, so only every 32nd
/// write of it is tried; every write after it is.
#[test]
fn crash_while_replacing() {
    let dir = scratch("dev-crash-rep");
    let Some(img1) = mkfs_named(&dir, "d1", 128 << 20, &["-m", "single"]) else { return };
    let img2 = blank(&dir, "d2", 128 << 20);
    let want;
    {
        let fs = mount(&img1);
        want = files(&Vfs::new(fs.root()), 3, 1);
    }
    let expect: Snapshot = want.iter().map(|(n, d)| (n.clone(), Some(d.clone()))).collect();
    let base = copy_all(&[img1.clone(), img2.clone()], &dir, "base");
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    {
        let fs = BtrfsFs::mount(Disk::logged(&img1, 0, Some(log.clone())), 1).unwrap();
        fs.replace_device(1, Disk::logged(&img2, 1, Some(log.clone()))).unwrap();
    }
    let log = log.lock().unwrap();
    eprintln!("replace made {} device writes", log.len());
    let first_super = log.iter().position(|(d, lba, _)| *d == 1 && *lba == 16).expect("the new device's superblock");
    let work = [dir.join("w0"), dir.join("w1")];
    let (mut olds, mut news) = (0, 0);
    for n in 0..=log.len() {
        if n < first_super.saturating_sub(40) && n % 32 != 0 {
            continue;
        }
        replay(&base, &work, &log, n);
        // The newer of the two superblocks is the volume.
        let (img, count) = match dump_super(&work[1]).filter(|t| t.contains("magic") && !t.contains("DON'T MATCH")) {
            Some(_) => (&work[1], &mut news),
            None => (&work[0], &mut olds),
        };
        *count += 1;
        if let Err(t) = try_check(img) {
            panic!("crash after {n} of {} writes fails btrfs check of {}:\n{t}", log.len(), img.display());
        }
        assert!(snapshot(img) == expect, "crash after {n} of {} writes changed the files", log.len());
    }
    assert!(olds > 0 && news > 0, "{olds} old, {news} new");
}
