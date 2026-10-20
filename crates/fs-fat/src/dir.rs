//! Directory entries (Microsoft FAT specification §6, §7).

use alloc::string::String;
use alloc::vec::Vec;

use crate::name::{checksum, lfn_units, short_to_string};

/// Bytes per directory entry.
pub const ENTRY_SIZE: usize = 32;

/// Attribute bits.
pub mod attr {
    #![allow(missing_docs, dead_code)]
    pub const READ_ONLY: u8 = 0x01;
    pub const HIDDEN: u8 = 0x02;
    pub const SYSTEM: u8 = 0x04;
    pub const VOLUME_ID: u8 = 0x08;
    pub const DIRECTORY: u8 = 0x10;
    pub const ARCHIVE: u8 = 0x20;
    pub const LONG_NAME: u8 = 0x0f;
}

/// First name byte of a free entry.
pub const FREE: u8 = 0xe5;
/// First name byte of the entry after the last one in use.
pub const END: u8 = 0x00;

/// A directory entry in use, with its long name assembled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The long name, or the short name if there is none.
    pub name: String,
    /// The 8.3 name as stored.
    pub short: [u8; 11],
    /// Attribute bits.
    pub attr: u8,
    /// First cluster (0 for an empty file).
    pub first: u32,
    /// Size in bytes (0 for directories).
    pub size: u32,
    /// Offset of the short entry within the directory.
    pub offset: usize,
    /// Offset of the first long-name entry (= `offset` if none).
    pub start: usize,
}

impl Entry {
    /// True for a directory.
    pub fn is_dir(&self) -> bool {
        self.attr & attr::DIRECTORY != 0
    }

    /// Number of 32-byte slots it occupies.
    pub fn slots(&self) -> usize {
        (self.offset - self.start) / ENTRY_SIZE + 1
    }
}

/// First cluster recorded in short entry `e`.
pub fn first_cluster(e: &[u8]) -> u32 {
    (u16::from_le_bytes([e[20], e[21]]) as u32) << 16 | u16::from_le_bytes([e[26], e[27]]) as u32
}

/// Stores first cluster `c` in short entry `e`.
pub fn set_first_cluster(e: &mut [u8], c: u32) {
    e[20..22].copy_from_slice(&((c >> 16) as u16).to_le_bytes());
    e[26..28].copy_from_slice(&(c as u16).to_le_bytes());
}

/// A fixed timestamp for new entries, as osmium has no wall clock here:
/// 2026-01-01 00:00. (Date bits: years since 1980, month, day.)
const DATE: u16 = (2026 - 1980) << 9 | 1 << 5 | 1;

/// Builds a short entry.
pub fn short_entry(short: &[u8; 11], ntres: u8, attr: u8, first: u32, size: u32) -> [u8; ENTRY_SIZE] {
    let mut e = [0u8; ENTRY_SIZE];
    e[..11].copy_from_slice(short);
    e[11] = attr;
    e[12] = ntres;
    for at in [16, 18, 24] {
        // Creation, access and write dates.
        e[at..at + 2].copy_from_slice(&DATE.to_le_bytes());
    }
    set_first_cluster(&mut e, first);
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// The `.` and `..` entries that start a new directory's first cluster.
/// `parent` is the parent's first cluster, or 0 for the root.
pub fn dot_entries(own: u32, parent: u32) -> [u8; 2 * ENTRY_SIZE] {
    let mut out = [0u8; 2 * ENTRY_SIZE];
    out[..32].copy_from_slice(&short_entry(b".          ", 0, attr::DIRECTORY, own, 0));
    out[32..].copy_from_slice(&short_entry(b"..         ", 0, attr::DIRECTORY, parent, 0));
    out
}

/// Parses the entries in use in directory contents `bytes`, skipping `.`,
/// `..`, volume labels and free slots. Long names whose checksum does not
/// match the short entry that follows them are ignored, as the
/// specification requires, and so are long names no path could reach.
pub fn parse(bytes: &[u8]) -> Vec<Entry> {
    let mut out = Vec::new();
    // Long-name parts collected so far: (expected next ordinal, checksum,
    // first slot offset, units in on-disk order, one Vec per part).
    let mut lfn: Option<(u8, u8, usize, Vec<Vec<u16>>)> = None;
    for (i, e) in bytes.as_chunks::<ENTRY_SIZE>().0.iter().enumerate() {
        let offset = i * ENTRY_SIZE;
        match e[0] {
            END => break,
            FREE => {
                lfn = None;
                continue;
            }
            _ => {}
        }
        if e[11] & 0x3f == attr::LONG_NAME {
            let ord = e[0] & 0x1f;
            let part: Vec<u16> = lfn_units(e).collect();
            lfn = match lfn.take() {
                _ if e[0] & 0x40 != 0 && ord > 0 => Some((ord - 1, e[13], offset, alloc::vec![part])),
                Some((want, sum, start, mut parts)) if ord == want && ord > 0 && e[13] == sum => {
                    parts.push(part);
                    Some((ord - 1, sum, start, parts))
                }
                _ => None,
            };
            continue;
        }
        let short: [u8; 11] = e[..11].try_into().expect("fixed-width slice");
        let pending = lfn.take();
        if e[11] & attr::VOLUME_ID != 0 || short[0] == b'.' {
            continue;
        }
        let (name, start) = match pending {
            Some((0, sum, start, parts)) if sum == checksum(&short) => {
                let units: Vec<u16> = parts.iter().rev().flatten().copied().collect();
                match String::from_utf16(&units) {
                    Ok(n) if units.len() <= MAX_LONG && usable(&n) => (n, start),
                    _ => (short_to_string(&short, e[12]), offset),
                }
            }
            _ => (short_to_string(&short, e[12]), offset),
        };
        out.push(Entry {
            name,
            short,
            attr: e[11],
            first: first_cluster(e),
            size: u32::from_le_bytes(e[28..32].try_into().expect("fixed-width slice")),
            offset,
            start,
        });
    }
    out
}

/// Most UTF-16 units in a long name (§7).
const MAX_LONG: usize = 255;

/// True if long name `n` can be a path component.
fn usable(n: &str) -> bool {
    !matches!(n, "" | "." | "..") && !n.contains(['/', '\0'])
}

/// Every short name in use in `bytes`, for picking a unique new one.
pub fn short_names(bytes: &[u8]) -> Vec<[u8; 11]> {
    bytes
        .as_chunks::<ENTRY_SIZE>()
        .0
        .iter()
        .take_while(|e| e[0] != END)
        .filter(|e| e[0] != FREE && e[11] & 0x3f != attr::LONG_NAME)
        .map(|e| e[..11].try_into().expect("fixed-width slice"))
        .collect()
}

/// Offset of the first run of `n` free slots in `bytes`, or of the end of
/// the entries in use (where the directory may need to grow).
pub fn find_free(bytes: &[u8], n: usize) -> usize {
    let mut run = 0;
    for (i, e) in bytes.as_chunks::<ENTRY_SIZE>().0.iter().enumerate() {
        if e[0] == END {
            // Everything from here on is free.
            return (i - run) * ENTRY_SIZE;
        }
        if e[0] == FREE {
            run += 1;
            if run == n {
                return (i + 1 - n) * ENTRY_SIZE;
            }
        } else {
            run = 0;
        }
    }
    bytes.len() - run * ENTRY_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::{generate_short, lfn_entries};

    fn dir(entries: &[[u8; 32]]) -> Vec<u8> {
        let mut v: Vec<u8> = entries.iter().flatten().copied().collect();
        v.resize(v.len() + 64, 0);
        v
    }

    #[test]
    fn parse_long_and_short_names() {
        let short = generate_short("Long File Name.html", &[]).unwrap();
        let mut es = lfn_entries("Long File Name.html", checksum(&short)).to_vec();
        es.push(short_entry(&short, 0, attr::ARCHIVE, 9, 1234));
        es.push(short_entry(b"README  TXT", crate::name::LOWER_BASE, attr::ARCHIVE, 0, 0));
        es.push(short_entry(b"SUB        ", 0, attr::DIRECTORY, 12, 0));
        let mut v = dot_entries(5, 0).to_vec();
        v.extend(dir(&es));
        let got = parse(&v);
        assert_eq!(got.len(), 3);
        assert_eq!(
            (got[0].name.as_str(), got[0].first, got[0].size, got[0].slots()),
            ("Long File Name.html", 9, 1234, 3)
        );
        assert_eq!(got[0].start, 64);
        assert_eq!(got[1].name, "readme.TXT");
        assert!(got[2].is_dir());
    }

    #[test]
    fn orphaned_long_name_is_ignored() {
        let mut es = lfn_entries("Something else", 0x42).to_vec();
        es.push(short_entry(b"PLAIN   TXT", 0, 0, 0, 0));
        let got = parse(&dir(&es));
        assert_eq!(got[0].name, "PLAIN.TXT", "checksum mismatch falls back to the short name");
        assert_eq!(got[0].slots(), 1);
    }

    #[test]
    fn unusable_long_names_are_ignored() {
        let long = "x".repeat(MAX_LONG + 5); // 20 parts: the ordinals allow 31
        for name in ["", ".", "..", "a/b", &long] {
            let short = *b"SAFE    TXT";
            let mut es = lfn_entries(name, checksum(&short)).to_vec();
            es.push(short_entry(&short, 0, 0, 0, 0));
            let got = parse(&dir(&es));
            assert_eq!((got[0].name.as_str(), got[0].slots()), ("SAFE.TXT", 1), "{name:?}");
        }
        assert!(usable("a.b") && !usable("a\0b"));
    }

    #[test]
    fn free_slot_search() {
        let a = short_entry(b"A          ", 0, 0, 0, 0);
        let mut free = a;
        free[0] = FREE;
        let v = dir(&[a, free, free, a, free]);
        assert_eq!(find_free(&v, 2), 32);
        assert_eq!(find_free(&v, 3), 4 * 32, "the trailing free slot joins the end");
        let full: Vec<u8> = [a, a].iter().flatten().copied().collect();
        assert_eq!(find_free(&full, 1), 64, "a full directory must grow");
        assert_eq!(short_names(&v), [*b"A          ", *b"A          "]);
    }
}
