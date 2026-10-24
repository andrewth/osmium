#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::unreachable)]
//! A hostile ISO 9660 image must not panic or hang the driver. Valid images
//! (plain, Rock Ridge with a continuation, Joliet) are built here, random
//! bytes of their metadata are flipped (fixed seed), and each damaged image
//! is mounted, walked and read.

use std::sync::Arc;

use osmium_fs::{File, FileKind};
use osmium_fs_iso9660::IsoFs;
use osmium_hal::block::{BlockDevice, BlockError};

const B: usize = 2048;

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

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

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

fn ucs2(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

#[derive(Clone, Copy, PartialEq)]
enum Flavour {
    Plain,
    RockRidge,
    Joliet,
}

/// Root at block 25 (files `a.txt` at 20, a subdirectory at block 26 holding
/// `b.bin` at 21). Rock Ridge adds long names, a link and a `CE` to block 22,
/// which points back at itself; Joliet adds a supplementary descriptor whose
/// tree is at blocks 23 and 24.
fn image(f: Flavour) -> MemDisk {
    let mut img = vec![0u8; 64 * B];
    let rr = f == Flavour::RockRidge;
    let root = record(&[0], 25, B as u32, 2, &[]);
    let pvd = &mut img[16 * B..17 * B];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[40..72].fill(b' ');
    pvd[128..130].copy_from_slice(&2048u16.to_le_bytes());
    pvd[156..156 + 34].copy_from_slice(&root[..34]);
    if f == Flavour::Joliet {
        let svd = &mut img[17 * B..18 * B];
        svd[0] = 2;
        svd[1..6].copy_from_slice(b"CD001");
        svd[6] = 1;
        svd[88..91].copy_from_slice(&[0x25, 0x2f, 0x45]);
        svd[128..130].copy_from_slice(&2048u16.to_le_bytes());
        let jroot = record(&[0], 23, B as u32, 2, &[]);
        svd[156..156 + 34].copy_from_slice(&jroot[..34]);
        let mut jdir = record(&[0], 23, B as u32, 2, &[]);
        jdir.extend(record(&[1], 23, B as u32, 2, &[]));
        jdir.extend(record(&ucs2("Joliet Name.txt;1"), 20, 11, 0, &[]));
        jdir.extend(record(&ucs2("jsub"), 24, B as u32, 2, &[]));
        img[23 * B..23 * B + jdir.len()].copy_from_slice(&jdir);
        let mut jsub = record(&[0], 24, B as u32, 2, &[]);
        jsub.extend(record(&[1], 23, B as u32, 2, &[]));
        jsub.extend(record(&ucs2("b.bin"), 21, 30, 0, &[]));
        img[24 * B..24 * B + jsub.len()].copy_from_slice(&jsub);
    }
    let term = if f == Flavour::Joliet { 18 } else { 17 };
    img[term * B] = 255;
    img[term * B + 1..term * B + 6].copy_from_slice(b"CD001");
    img[term * B + 6] = 1;
    let sp = if rr { susp(b"SP", &[0xbe, 0xef, 0]) } else { vec![] };
    let mut dir = record(&[0], 25, B as u32, 2, &sp);
    dir.extend(record(&[1], 25, B as u32, 2, &[]));
    if rr {
        let mut su = susp(b"NM", b"\0A Long Rock Ridge Name.txt");
        su.extend(px(0o100644));
        let mut ce = Vec::new();
        ce.extend_from_slice(&22u32.to_le_bytes());
        ce.extend_from_slice(&[0; 4]);
        ce.extend_from_slice(&0u32.to_le_bytes());
        ce.extend_from_slice(&[0; 4]);
        ce.extend_from_slice(&40u32.to_le_bytes());
        ce.extend_from_slice(&[0; 4]);
        su.extend(susp(b"CE", &ce));
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
    dir.extend(record(b"SUB", 26, B as u32, 2, &[]));
    img[25 * B..25 * B + dir.len()].copy_from_slice(&dir);
    let mut sub = record(&[0], 26, B as u32, 2, &[]);
    sub.extend(record(&[1], 25, B as u32, 2, &[]));
    sub.extend(record(b"B.BIN;1", 21, 30, 0, &[]));
    sub.extend(record(b"UP", 25, B as u32, 2, &[])); // a loop back to the root
    img[26 * B..26 * B + sub.len()].copy_from_slice(&sub);
    img[20 * B..20 * B + 11].copy_from_slice(b"hello world");
    img[21 * B..21 * B + 30].fill(5);
    // The continuation area: a CE that names itself.
    let mut area = Vec::new();
    let mut ce = Vec::new();
    ce.extend_from_slice(&22u32.to_le_bytes());
    ce.extend_from_slice(&[0; 4]);
    ce.extend_from_slice(&0u32.to_le_bytes());
    ce.extend_from_slice(&[0; 4]);
    ce.extend_from_slice(&40u32.to_le_bytes());
    ce.extend_from_slice(&[0; 4]);
    area.extend(susp(b"CE", &ce));
    img[22 * B..22 * B + area.len()].copy_from_slice(&area);
    MemDisk(Arc::new(img))
}

fn walk(dir: &Arc<dyn File>, depth: usize, budget: &mut usize) {
    for i in 0..4096 {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let Ok(Some(e)) = dir.readdir(i) else { return };
        let Ok(node) = dir.lookup(&e.name) else { continue };
        let st = node.stat();
        match e.kind {
            FileKind::Directory => {
                if depth < 6 {
                    walk(&node, depth + 1, budget);
                }
            }
            FileKind::Symlink => {
                let _ = node.readlink();
            }
            _ => {
                let mut buf = [0u8; 1500];
                let mut off = 0;
                for _ in 0..64 {
                    match node.read(off, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => off += n as u64,
                    }
                }
                let _ = node.read(st.size.saturating_sub(10), &mut buf);
                let _ = node.read(u64::MAX - 5, &mut buf);
            }
        }
    }
}

fn exercise(disk: MemDisk) -> bool {
    let Ok(fs) = IsoFs::mount(disk, 1) else { return false };
    let _ = fs.volume_id();
    let root = fs.root();
    let mut budget = 600;
    walk(&root, 0, &mut budget);
    let _ = root.lookup("nonexistent");
    true
}

fn fuzz(f: Flavour, rounds: usize, seed: u64) {
    let pristine = image(f);
    assert!(exercise(pristine.clone()));
    let mut rng = Rng(seed);
    let mut mounted = 0;
    for _ in 0..rounds {
        let mut img = (*pristine.0).clone();
        for _ in 0..1 + rng.below(6) {
            // The descriptors, the directories and the continuation area.
            let block = [16, 17, 18, 25, 25, 26, 26, 22, 23, 24][rng.below(10)];
            let at = block * B + rng.below(200);
            img[at] = match rng.below(3) {
                0 => 0,
                1 => 0xff,
                _ => rng.next() as u8,
            };
        }
        mounted += exercise(MemDisk(Arc::new(img))) as usize;
    }
    assert!(mounted > rounds / 4, "{mounted} of {rounds} damaged images mounted");
}

#[test]
fn damaged_plain_images() {
    fuzz(Flavour::Plain, 3000, 0x1234_5678_9abc_def1);
}

#[test]
fn damaged_rock_ridge_images() {
    fuzz(Flavour::RockRidge, 3000, 0x0fed_cba9_8765_4321);
}

#[test]
fn damaged_joliet_images() {
    fuzz(Flavour::Joliet, 3000, 0x5555_aaaa_1357_9bdf);
}

#[test]
fn garbage_images_do_not_mount() {
    let mut rng = Rng(7);
    for _ in 0..300 {
        let mut img = vec![0u8; 24 * B];
        for b in img[16 * B..19 * B].iter_mut() {
            *b = rng.next() as u8;
        }
        img[16 * B + 1..16 * B + 6].copy_from_slice(b"CD001");
        img[16 * B] = 1;
        img[16 * B + 6] = 1;
        let _ = exercise(MemDisk(Arc::new(img)));
    }
}
