#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! Running out of memory in the middle of an ISO 9660 call is `ENOMEM`.
//! Each test fails every allocation of a call in turn, on a small image made
//! here: plain, then with Rock Ridge names and a symbolic link.

use std::sync::Arc;

use osmium_fs::{Errno, FileKind, Vfs};
use osmium_fs_iso9660::IsoFs;
use osmium_hal::block::{BlockDevice, BlockError};

#[path = "../../proc/src/failing.rs"]
mod failing;

#[global_allocator]
static ALLOCATOR: failing::Failing = failing::Failing;

use failing::every_failure;

const B: usize = 2048;

/// An image in memory that reading allocates nothing from.
#[derive(Clone)]
struct MemDisk(Arc<Vec<u8>>);

impl BlockDevice for MemDisk {
    fn block_size(&self) -> usize {
        B
    }
    fn num_blocks(&self) -> u64 {
        (self.0.len() / B) as u64
    }
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let off = lba as usize * B;
        buf.copy_from_slice(&self.0[off..off + buf.len()]);
        Ok(())
    }
    fn write_blocks(&mut self, _lba: u64, _buf: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::ReadOnly)
    }
}

/// A directory record with a system use area.
fn record(name: &[u8], extent: u32, size: u32, flags: u8, system_use: &[u8]) -> Vec<u8> {
    let pad = (name.len() + 1) % 2;
    let mut len = 33 + name.len() + pad + system_use.len();
    len += len % 2;
    let mut r = vec![0u8; len];
    r[0] = len as u8;
    r[2..6].copy_from_slice(&extent.to_le_bytes());
    r[10..14].copy_from_slice(&size.to_le_bytes());
    r[25] = flags;
    r[32] = name.len() as u8;
    r[33..33 + name.len()].copy_from_slice(name);
    let at = 33 + name.len() + pad;
    r[at..at + system_use.len()].copy_from_slice(system_use);
    r
}

/// A Rock Ridge entry.
fn susp(sig: &[u8; 2], body: &[u8]) -> Vec<u8> {
    let mut e = sig.to_vec();
    e.push(4 + body.len() as u8);
    e.push(1);
    e.extend_from_slice(body);
    e
}

fn px(mode: u32) -> Vec<u8> {
    let mut body = vec![0u8; 32];
    body[..4].copy_from_slice(&mode.to_le_bytes());
    body[8..12].copy_from_slice(&1u32.to_le_bytes());
    susp(b"PX", &body)
}

/// A volume whose root (block 18) holds a file `a.txt` (data at block 20), and
/// with `rock_ridge`, a symbolic link `l` to `a.txt` and long names.
fn image(rock_ridge: bool) -> MemDisk {
    let mut img = vec![0u8; 64 * B];
    let root = record(&[0], 18, B as u32, 2, &[]);
    let pvd = &mut img[16 * B..17 * B];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[40..72].fill(b' ');
    pvd[128..130].copy_from_slice(&2048u16.to_le_bytes());
    pvd[156..156 + 34].copy_from_slice(&root[..34]);
    let term = &mut img[17 * B..18 * B];
    term[0] = 255;
    term[1..6].copy_from_slice(b"CD001");
    term[6] = 1;
    let sp = if rock_ridge { susp(b"SP", &[0xbe, 0xef, 0]) } else { vec![] };
    let mut dir = record(&[0], 18, B as u32, 2, &sp);
    dir.extend(record(&[1], 18, B as u32, 2, &[]));
    if rock_ridge {
        let mut su = susp(b"NM", b"\0A Long Rock Ridge Name.txt");
        su.extend(px(0o100644));
        dir.extend(record(b"A.TXT;1", 20, 11, 0, &su));
        let mut su = susp(b"NM", b"\0l");
        su.extend(px(0o120777));
        let target = b"A Long Rock Ridge Name.txt";
        let mut sl = vec![0, 0, target.len() as u8];
        sl.extend_from_slice(target);
        su.extend(susp(b"SL", &sl));
        dir.extend(record(b"L.;1", 0, 0, 0, &su));
    } else {
        dir.extend(record(b"A.TXT;1", 20, 11, 0, &[]));
    }
    img[18 * B..18 * B + dir.len()].copy_from_slice(&dir);
    img[20 * B..20 * B + 11].copy_from_slice(b"hello world");
    MemDisk(Arc::new(img))
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

#[test]
fn plain_volumes_fail_cleanly() {
    let disk = image(false);
    let n = every_failure(
        || IsoFs::mount(disk.clone(), 1).map(drop),
        |r, injected| {
            ok_or_enomem(&r, injected);
        },
    );
    assert!(n >= 4, "mount: {n}");

    let fs = IsoFs::mount(disk, 1).unwrap();
    let vfs = Vfs::new(fs.root());
    let root = vfs.lookup("/").unwrap();
    // The first listing parses and caches the directory; so does a failed one
    // leave nothing behind that stops the next from working.
    let n = every_failure(
        || {
            let mut names = 0;
            for i in 0.. {
                match root.readdir(i)? {
                    Some(_) => names += 1,
                    None => break,
                }
            }
            Ok::<_, Errno>(names)
        },
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), 1);
            }
        },
    );
    assert!(n >= 3, "readdir: {n}");
    let n = every_failure(
        || {
            let f = vfs.lookup("/a.txt")?;
            let mut buf = [0u8; 16];
            let got = f.read(0, &mut buf)?;
            Ok::<_, Errno>((got, buf))
        },
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                let (got, buf) = r.unwrap();
                assert_eq!(&buf[..got], b"hello world");
            }
        },
    );
    assert!(n >= 3, "lookup and read: {n}");
}

#[test]
fn rock_ridge_volumes_fail_cleanly() {
    let disk = image(true);
    let n = every_failure(
        || IsoFs::mount(disk.clone(), 1).map(drop),
        |r, injected| {
            ok_or_enomem(&r, injected);
        },
    );
    assert!(n >= 5, "mount: {n}");

    let fs = IsoFs::mount(disk, 1).unwrap();
    let vfs = Vfs::new(fs.root());
    let n = every_failure(
        || vfs.stat("/A Long Rock Ridge Name.txt", true).map(|s| (s.kind, s.size)),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), (FileKind::Regular, 11));
            }
        },
    );
    assert!(n >= 4, "stat: {n}");
    // Through the link, which is a Rock Ridge `SL` target.
    let n = every_failure(
        || vfs.readlink("/l"),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), "A Long Rock Ridge Name.txt");
            }
        },
    );
    assert!(n >= 4, "readlink: {n}");
    let n = every_failure(
        || vfs.canonicalize("/l"),
        |r, injected| {
            if ok_or_enomem(&r, injected) {
                assert_eq!(r.unwrap(), "/A Long Rock Ridge Name.txt");
            }
        },
    );
    assert!(n >= 4, "canonicalize: {n}");
}
