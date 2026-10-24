//! Directory entries (Microsoft FAT specification §6, §7).

use alloc::string::String;
use alloc::vec::Vec;

use osmium_sync::fallible::{OutOfMemory, try_push};

use crate::name::{LFN_CHARS, checksum, lfn_units, short_to_string};

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
    let half = |at: usize| e.get(at..).and_then(|t| t.first_chunk::<2>()).map_or(0, |c| u16::from_le_bytes(*c) as u32);
    half(20) << 16 | half(26)
}

/// Stores first cluster `c` in short entry `e`.
pub fn set_first_cluster(e: &mut [u8], c: u32) {
    if let Some(t) = e.get_mut(20..22) {
        t.copy_from_slice(&((c >> 16) as u16).to_le_bytes());
    }
    if let Some(t) = e.get_mut(26..28) {
        t.copy_from_slice(&(c as u16).to_le_bytes());
    }
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
        if let Some(t) = e.get_mut(at..at + 2) {
            t.copy_from_slice(&DATE.to_le_bytes());
        }
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

/// Most long-name entries a name can span: the ordinal has five bits.
const MAX_PARTS: usize = 31;

/// Long-name entries collected so far, last part first, for the short entry
/// that follows them.
struct Lfn {
    /// The ordinal the next entry must have.
    want: u8,
    sum: u8,
    /// Offset of the first (last-ordinal) entry.
    start: usize,
    /// The units of part `n` (ordinal `n + 1`) at `units[n]`, and how many.
    units: [[u16; LFN_CHARS]; MAX_PARTS],
    lens: [u8; MAX_PARTS],
    /// The highest ordinal.
    parts: u8,
}

impl Lfn {
    /// Stores part `ord` (1-based); false if `ord` is out of range.
    fn set(&mut self, ord: u8, part: ([u16; LFN_CHARS], u8)) -> bool {
        let n = (ord as usize).wrapping_sub(1);
        match (self.units.get_mut(n), self.lens.get_mut(n)) {
            (Some(u), Some(l)) => {
                *u = part.0;
                *l = part.1;
                true
            }
            _ => false,
        }
    }
}

/// The entries in use in directory contents, one by one; see [`entries`].
pub struct Entries<'bytes> {
    chunks: &'bytes [[u8; ENTRY_SIZE]],
    next: usize,
    /// The long-name entries seen so far, valid while `live`. Kept in place
    /// (it is big): copying it for each entry would make a scan quadratic.
    lfn: Lfn,
    live: bool,
}

/// Parses the entries in use in directory contents `bytes`, skipping `.`,
/// `..`, volume labels and free slots. Long names whose checksum does not
/// match the short entry that follows them are ignored, as the
/// specification requires, and so are long names no path could reach. Each
/// entry's name is allocated as it is reached, which can fail.
pub fn entries(bytes: &[u8]) -> Entries<'_> {
    let lfn = Lfn { want: 0, sum: 0, start: 0, units: [[0; LFN_CHARS]; MAX_PARTS], lens: [0; MAX_PARTS], parts: 0 };
    Entries { chunks: bytes.as_chunks::<ENTRY_SIZE>().0, next: 0, lfn, live: false }
}

/// [`entries`], collected.
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry>, OutOfMemory> {
    let mut out = Vec::new();
    for e in entries(bytes) {
        try_push(&mut out, e?)?;
    }
    Ok(out)
}

/// The long name in `lfn`, if it is one a path could reach.
fn long_name(lfn: &Lfn) -> Result<Option<String>, OutOfMemory> {
    let units = || {
        lfn.units
            .iter()
            .zip(&lfn.lens)
            .take(lfn.parts as usize)
            .flat_map(|(part, &len)| part.iter().copied().take(len as usize))
    };
    let count = units().count();
    if count > MAX_LONG || char::decode_utf16(units()).any(|c| c.is_err()) {
        return Ok(None);
    }
    let mut name = String::new();
    // At most three UTF-8 bytes for each UTF-16 unit.
    name.try_reserve_exact(count * 3)?;
    name.extend(char::decode_utf16(units()).filter_map(Result::ok));
    Ok(usable(&name).then_some(name))
}

impl Iterator for Entries<'_> {
    type Item = Result<Entry, OutOfMemory>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(e) = self.chunks.get(self.next) {
            let offset = self.next * ENTRY_SIZE;
            self.next += 1;
            match e[0] {
                END => {
                    self.next = self.chunks.len();
                    return None;
                }
                FREE => {
                    self.live = false;
                    continue;
                }
                _ => {}
            }
            if e[11] & 0x3f == attr::LONG_NAME {
                let ord = e[0] & 0x1f;
                let mut part = ([0u16; LFN_CHARS], 0u8);
                for (slot, u) in part.0.iter_mut().zip(lfn_units(e)) {
                    *slot = u;
                    part.1 += 1;
                }
                if e[0] & 0x40 != 0 && ord > 0 {
                    // The last part comes first.
                    self.lfn.want = ord - 1;
                    self.lfn.sum = e[13];
                    self.lfn.start = offset;
                    self.lfn.parts = ord;
                    self.live = self.lfn.set(ord, part);
                } else if self.live && ord == self.lfn.want && ord > 0 && e[13] == self.lfn.sum {
                    self.live = self.lfn.set(ord, part);
                    self.lfn.want = ord - 1;
                } else {
                    self.live = false;
                }
                continue;
            }
            let mut short = [0u8; 11];
            short.copy_from_slice(&e[..11]);
            let pending = core::mem::replace(&mut self.live, false);
            if e[11] & attr::VOLUME_ID != 0 || short[0] == b'.' {
                continue;
            }
            let long = if pending && self.lfn.want == 0 && self.lfn.sum == checksum(&short) {
                match long_name(&self.lfn) {
                    Ok(name) => name.map(|n| (n, self.lfn.start)),
                    Err(e) => return Some(Err(e)),
                }
            } else {
                None
            };
            let (name, start) = match long {
                Some(found) => found,
                None => match short_to_string(&short, e[12]) {
                    Ok(n) => (n, offset),
                    Err(e) => return Some(Err(e)),
                },
            };
            // A short name no path could reach is skipped, like such a long one.
            if !usable(&name) {
                continue;
            }
            return Some(Ok(Entry {
                name,
                short,
                attr: e[11],
                first: first_cluster(e),
                size: u32::from_le_bytes([e[28], e[29], e[30], e[31]]),
                offset,
                start,
            }));
        }
        None
    }
}

/// True if directory contents `bytes` hold nothing but `.`, `..` and free
/// slots. Judged on raw slots, so an entry `parse` hides still counts.
pub fn is_empty(bytes: &[u8]) -> bool {
    for e in bytes.as_chunks::<ENTRY_SIZE>().0 {
        match e[0] {
            END => return true,
            FREE => {}
            _ if e[11] & 0x3f != attr::LONG_NAME && matches!(&e[..2], b". " | b"..") && e[2..11] == [b' '; 9] => {}
            _ => return false,
        }
    }
    true
}

/// Most UTF-16 units in a long name (§7).
const MAX_LONG: usize = 255;

/// True if long name `n` can be a path component.
fn usable(n: &str) -> bool {
    !matches!(n, "" | "." | "..") && !n.contains(['/', '\0'])
}

/// Every short name in use in `bytes`, for picking a unique new one.
pub fn short_names(bytes: &[u8]) -> Result<Vec<[u8; 11]>, OutOfMemory> {
    let mut out = Vec::new();
    let used = bytes
        .as_chunks::<ENTRY_SIZE>()
        .0
        .iter()
        .take_while(|e| e[0] != END)
        .filter(|e| e[0] != FREE && e[11] & 0x3f != attr::LONG_NAME);
    for e in used {
        let mut short = [0u8; 11];
        short.copy_from_slice(&e[..11]);
        try_push(&mut out, short)?;
    }
    Ok(out)
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
        let mut es = lfn_entries("Long File Name.html", checksum(&short)).unwrap();
        es.push(short_entry(&short, 0, attr::ARCHIVE, 9, 1234));
        es.push(short_entry(b"README  TXT", crate::name::LOWER_BASE, attr::ARCHIVE, 0, 0));
        es.push(short_entry(b"SUB        ", 0, attr::DIRECTORY, 12, 0));
        let mut v = dot_entries(5, 0).to_vec();
        v.extend(dir(&es));
        let got = parse(&v).unwrap();
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
        let mut es = lfn_entries("Something else", 0x42).unwrap();
        es.push(short_entry(b"PLAIN   TXT", 0, 0, 0, 0));
        let got = parse(&dir(&es)).unwrap();
        assert_eq!(got[0].name, "PLAIN.TXT", "checksum mismatch falls back to the short name");
        assert_eq!(got[0].slots(), 1);
    }

    #[test]
    fn unusable_long_names_are_ignored() {
        let long = "x".repeat(MAX_LONG + 5); // 20 parts: the ordinals allow 31
        for name in ["", ".", "..", "a/b", &long] {
            let short = *b"SAFE    TXT";
            let mut es = lfn_entries(name, checksum(&short)).unwrap();
            es.push(short_entry(&short, 0, 0, 0, 0));
            let got = parse(&dir(&es)).unwrap();
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
        assert_eq!(short_names(&v).unwrap(), [*b"A          ", *b"A          "]);
    }

    #[test]
    fn unreachable_short_names_are_skipped() {
        let es = [
            short_entry(b"A/B     TXT", 0, 0, 0, 0),
            short_entry(b"           ", 0, 0, 0, 0),
            short_entry(b"A\0B     TXT", 0, 0, 0, 0),
            short_entry(b"OK      TXT", 0, 0, 0, 0),
        ];
        let got = parse(&dir(&es)).unwrap();
        assert_eq!(got.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(), ["OK.TXT"]);
    }

    #[test]
    fn emptiness_is_judged_on_raw_slots() {
        let mut free = short_entry(b"GONE       ", 0, 0, 0, 0);
        free[0] = FREE;
        let dots = dot_entries(5, 0);
        let dots: Vec<[u8; 32]> = dots.as_chunks::<32>().0.to_vec();
        assert!(is_empty(&dir(&dots)));
        assert!(is_empty(&dir(&[free])));
        // Hidden from `parse`, but still an entry.
        let hidden = short_entry(b"A/B     TXT", 0, 0, 0, 0);
        assert!(parse(&dir(&[hidden])).unwrap().is_empty());
        assert!(!is_empty(&dir(&[hidden])));
        assert!(!is_empty(&dir(&lfn_entries("orphan", 1).unwrap())));
    }
}
