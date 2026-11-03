//! File system operations, each run inside a transaction.

use alloc::vec::Vec;

use osmium_fs::{Errno, FileKind, Timestamp, XattrSet};
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_push, try_to_vec, try_zeroed};

use crate::csum;
use crate::disk::{self, FileExtent, Key, byte, item, le16, le32, le64, put, put32, put64, tree};
use crate::node::ITEM;
use crate::write::{DataRef, Tx};

/// Largest piece of a write handled at once (each gets its own extent).
const MAX_PIECE: u64 = 1 << 20;

/// Inode flags a new inode takes from its directory.
const INHERITED: u64 = 1 << 0 | 1 << 1;

/// `BTRFS_FT_XATTR`.
const FT_XATTR: u8 = 8;

/// Offsets in an inode item.
mod ino {
    pub const GENERATION: usize = 0;
    pub const TRANSID: usize = 8;
    pub const SIZE: usize = 16;
    pub const NBYTES: usize = 24;
    pub const NLINK: usize = 40;
    pub const MODE: usize = 52;
    pub const RDEV: usize = 56;
    pub const FLAGS: usize = 64;
    pub const SEQUENCE: usize = 72;
    pub const ATIME: usize = 112;
    pub const CTIME: usize = 124;
    pub const MTIME: usize = 136;
    pub const OTIME: usize = 148;
    pub const LEN: usize = 160;
}

/// The `BTRFS_FT_*` of a kind.
pub fn ft_of(kind: FileKind) -> u8 {
    match kind {
        FileKind::Regular => 1,
        FileKind::Directory => 2,
        FileKind::CharDevice => 3,
        FileKind::BlockDevice => 4,
        FileKind::Fifo => 5,
        FileKind::Socket => 6,
        FileKind::Symlink => 7,
    }
}

fn put_time(b: &mut [u8], at: usize, t: Timestamp) -> Result<(), Errno> {
    put64(b, at, t.sec as u64)?;
    put32(b, at + 8, t.nsec)
}

/// A directory entry or extended attribute as stored.
fn entry(location: Key, transid: u64, name: &[u8], data: &[u8], ft: u8) -> Result<Vec<u8>, Errno> {
    let mut e = Vec::new();
    e.try_reserve_exact(30 + name.len() + data.len()).map_err(|_| Errno::ENOMEM)?;
    e.extend_from_slice(&crate::node::key_bytes(&location));
    e.extend_from_slice(&transid.to_le_bytes());
    e.extend_from_slice(&(data.len() as u16).to_le_bytes());
    e.extend_from_slice(&(name.len() as u16).to_le_bytes());
    e.push(ft);
    e.extend_from_slice(name);
    e.extend_from_slice(data);
    Ok(e)
}

/// The packed entries of a dir or xattr item: each one's range and name.
/// An entry's start and end in its item, and its name.
type Entry<'d> = (usize, usize, &'d [u8]);

fn entries(d: &[u8]) -> Result<Vec<Entry<'_>>, Errno> {
    let mut v = Vec::new();
    let mut p = 0;
    while p < d.len() {
        let rest = d.get(p..).ok_or(Errno::EIO)?;
        let (dl, nl) = (le16(rest, 25)? as usize, le16(rest, 27)? as usize);
        let len = 30 + nl + dl;
        try_push(&mut v, (p, p + len, disk::bytes(rest, 30, nl)?))?;
        p += len;
    }
    Ok(v)
}

/// `d` without bytes `from..to`.
fn without(d: &[u8], from: usize, to: usize) -> Result<Vec<u8>, Errno> {
    let mut v = Vec::new();
    v.try_reserve_exact(d.len() - (to - from)).map_err(|_| Errno::ENOMEM)?;
    v.extend_from_slice(d.get(..from).ok_or(Errno::EIO)?);
    v.extend_from_slice(d.get(to..).ok_or(Errno::EIO)?);
    Ok(v)
}

/// `d` with `more` after it.
fn with(d: &[u8], more: &[u8]) -> Result<Vec<u8>, Errno> {
    let mut v = Vec::new();
    v.try_reserve_exact(d.len() + more.len()).map_err(|_| Errno::ENOMEM)?;
    v.extend_from_slice(d);
    v.extend_from_slice(more);
    Ok(v)
}

/// An inode's `INODE_EXTREF` key offset for `name` in `parent`.
fn extref_hash(parent: u64, name: &[u8]) -> u64 {
    csum::crc32c(parent as u32, name) as u64
}

/// The device number btrfs stores (Linux's kernel encoding) for `st_rdev`.
fn kernel_rdev(rdev: u64) -> u64 {
    let major = (rdev >> 8) & 0xfff | (rdev >> 32) & !0xfff;
    let minor = rdev & 0xff | (rdev >> 12) & !0xff;
    major << 20 | minor & 0xf_ffff
}

impl<D: BlockDevice + Send + 'static> Tx<'_, D> {
    pub(crate) fn inode(&mut self, t: u64, ino: u64) -> Result<Vec<u8>, Errno> {
        let d = self.find(t, Key::new(ino, item::INODE_ITEM, 0))?.ok_or(Errno::ENOENT)?;
        if d.len() < ino::LEN {
            return Err(Errno::EIO);
        }
        Ok(d)
    }

    fn set_inode(&mut self, t: u64, ino: u64, d: &[u8]) -> Result<(), Errno> {
        self.update(t, Key::new(ino, item::INODE_ITEM, 0), d)
    }

    /// Marks inode data `d` changed now: its change time, and with `modify`
    /// its modification time.
    fn stamp(&self, d: &mut [u8], modify: bool) -> Result<(), Errno> {
        let now = self.sh.now();
        put_time(d, ino::CTIME, now)?;
        if modify {
            put_time(d, ino::MTIME, now)?;
        }
        put64(d, ino::TRANSID, self.transid)?;
        put64(d, ino::SEQUENCE, le64(d, ino::SEQUENCE)?.wrapping_add(1))
    }

    fn kind(d: &[u8]) -> Result<FileKind, Errno> {
        crate::kind_of(le32(d, ino::MODE)?).ok_or(Errno::EIO)
    }

    /// A new inode number in tree `t`.
    fn next_ino(&mut self, t: u64) -> Result<u64, Errno> {
        let cached = self.w.next_ino.iter().find(|(id, _)| *id == t).map(|&(_, n)| n);
        let n = match cached {
            Some(n) => n,
            None => {
                let last = self.prev_item(t, Key::new(tree::LAST_FREE, 0xff, u64::MAX))?;
                last.map_or(tree::FIRST_FREE, |(k, _)| k.objectid.max(tree::FIRST_FREE - 1) + 1)
            }
        };
        if n > tree::LAST_FREE {
            return Err(Errno::ENOSPC);
        }
        match self.w.next_ino.iter_mut().find(|(id, _)| *id == t) {
            Some(e) => e.1 = n + 1,
            None => try_push(&mut self.w.next_ino, (t, n + 1))?,
        }
        Ok(n)
    }

    /// The next free `DIR_INDEX` position in directory `dir`.
    fn next_index(&mut self, t: u64, dir: u64) -> Result<u64, Errno> {
        match self.prev_item(t, Key::new(dir, item::DIR_INDEX, u64::MAX))? {
            Some((k, _)) if k.objectid == dir && k.ty == item::DIR_INDEX => {
                k.offset.max(1).checked_add(1).ok_or(Errno::ENOSPC)
            }
            _ => Ok(2),
        }
    }

    /// The entry `name` of directory `dir`: where it points and its type.
    pub(crate) fn dir_lookup(&mut self, t: u64, dir: u64, name: &[u8]) -> Result<Option<(Key, u8)>, Errno> {
        let Some(d) = self.find(t, Key::new(dir, item::DIR_ITEM, csum::name_hash(name)))? else { return Ok(None) };
        for (from, _, n) in entries(&d)? {
            if n == name {
                let e = d.get(from..).ok_or(Errno::EIO)?;
                return Ok(Some((Key::parse(e, 0)?, byte(e, 29)?)));
            }
        }
        Ok(None)
    }

    /// Adds `name` to directory `dir`, at index `idx`.
    fn dir_add(&mut self, t: u64, dir: u64, name: &[u8], loc: Key, ft: u8, idx: u64) -> Result<(), Errno> {
        let e = entry(loc, self.transid, name, &[], ft)?;
        let key = Key::new(dir, item::DIR_ITEM, csum::name_hash(name));
        match self.find(t, key)? {
            Some(d) => self.update(t, key, &with(&d, &e)?)?,
            None => self.insert(t, key, &e)?,
        }
        self.insert(t, Key::new(dir, item::DIR_INDEX, idx), &e)?;
        let mut d = self.inode(t, dir)?;
        let size = le64(&d, ino::SIZE)? + 2 * name.len() as u64;
        put64(&mut d, ino::SIZE, size)?;
        self.stamp(&mut d, true)?;
        self.set_inode(t, dir, &d)
    }

    /// Takes `name`, at index `idx`, out of directory `dir`.
    fn dir_del(&mut self, t: u64, dir: u64, name: &[u8], idx: u64) -> Result<(), Errno> {
        let key = Key::new(dir, item::DIR_ITEM, csum::name_hash(name));
        let d = self.find(t, key)?.ok_or(Errno::EIO)?;
        let (from, to, _) = entries(&d)?.into_iter().find(|e| e.2 == name).ok_or(Errno::EIO)?;
        if to - from == d.len() {
            self.delete(t, key)?;
        } else {
            self.update(t, key, &without(&d, from, to)?)?;
        }
        self.delete(t, Key::new(dir, item::DIR_INDEX, idx))?;
        let mut d = self.inode(t, dir)?;
        let size = le64(&d, ino::SIZE)?.saturating_sub(2 * name.len() as u64);
        put64(&mut d, ino::SIZE, size)?;
        self.stamp(&mut d, true)?;
        self.set_inode(t, dir, &d)
    }

    /// Records that `ino` is called `name` in `parent`, at index `idx`.
    fn inode_ref_add(&mut self, t: u64, ino: u64, parent: u64, idx: u64, name: &[u8]) -> Result<(), Errno> {
        let mut e = Vec::new();
        e.try_reserve_exact(10 + name.len()).map_err(|_| Errno::ENOMEM)?;
        e.extend_from_slice(&idx.to_le_bytes());
        e.extend_from_slice(&(name.len() as u16).to_le_bytes());
        e.extend_from_slice(name);
        let key = Key::new(ino, item::INODE_REF, parent);
        let d = match self.find(t, key)? {
            Some(d) => with(&d, &e)?,
            None => e,
        };
        if ITEM + d.len() > self.leaf_space() {
            return Err(Errno::EMLINK);
        }
        self.put(t, key, &d)
    }

    /// Forgets that `ino` is called `name` in `parent`; returns its index.
    fn inode_ref_del(&mut self, t: u64, ino: u64, parent: u64, name: &[u8]) -> Result<u64, Errno> {
        let key = Key::new(ino, item::INODE_REF, parent);
        if let Some(d) = self.find(t, key)? {
            let mut p = 0;
            while p < d.len() {
                let nl = le16(&d, p + 8)? as usize;
                if disk::bytes(&d, p + 10, nl)? == name {
                    let idx = le64(&d, p)?;
                    if nl + 10 == d.len() {
                        self.delete(t, key)?;
                    } else {
                        self.update(t, key, &without(&d, p, p + 10 + nl)?)?;
                    }
                    return Ok(idx);
                }
                p += 10 + nl;
            }
        }
        let key = Key::new(ino, item::INODE_EXTREF, extref_hash(parent, name));
        let d = self.find(t, key)?.ok_or(Errno::EIO)?;
        let mut p = 0;
        while p < d.len() {
            let nl = le16(&d, p + 16)? as usize;
            if le64(&d, p)? == parent && disk::bytes(&d, p + 18, nl)? == name {
                let idx = le64(&d, p + 8)?;
                if nl + 18 == d.len() {
                    self.delete(t, key)?;
                } else {
                    self.update(t, key, &without(&d, p, p + 18 + nl)?)?;
                }
                return Ok(idx);
            }
            p += 18 + nl;
        }
        Err(Errno::EIO)
    }

    /// Creates `name` in directory `dir`; returns the new inode number.
    pub(crate) fn create(
        &mut self,
        t: u64,
        dir: u64,
        name: &[u8],
        kind: FileKind,
        mode: u32,
        rdev: u64,
    ) -> Result<u64, Errno> {
        let parent = self.inode(t, dir)?;
        if Self::kind(&parent)? != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        if le32(&parent, ino::NLINK)? == 0 {
            return Err(Errno::ENOENT);
        }
        if self.dir_lookup(t, dir, name)?.is_some() {
            return Err(Errno::EEXIST);
        }
        let ino = self.next_ino(t)?;
        let now = self.sh.now();
        let mut d = [0u8; ino::LEN];
        put64(&mut d, ino::GENERATION, self.transid)?;
        put64(&mut d, ino::TRANSID, self.transid)?;
        put32(&mut d, ino::NLINK, 1)?;
        put32(&mut d, ino::MODE, kind.mode_bits() | mode & 0o7777)?;
        if matches!(kind, FileKind::CharDevice | FileKind::BlockDevice) {
            put64(&mut d, ino::RDEV, kernel_rdev(rdev))?;
        }
        put64(&mut d, ino::FLAGS, le64(&parent, ino::FLAGS)? & INHERITED)?;
        for at in [ino::ATIME, ino::CTIME, ino::MTIME, ino::OTIME] {
            put_time(&mut d, at, now)?;
        }
        self.insert(t, Key::new(ino, item::INODE_ITEM, 0), &d)?;
        let idx = self.next_index(t, dir)?;
        self.inode_ref_add(t, ino, dir, idx, name)?;
        self.dir_add(t, dir, name, Key::new(ino, item::INODE_ITEM, 0), ft_of(kind), idx)?;
        Ok(ino)
    }

    /// Removes `name` from `dir`, which must (`want_dir`) or must not be a
    /// directory. `open` says whether a node of an inode is still in use.
    pub(crate) fn remove(
        &mut self,
        t: u64,
        dir: u64,
        name: &[u8],
        want_dir: bool,
        open: &dyn Fn(u64, u64) -> bool,
    ) -> Result<(), Errno> {
        self.frees = true;
        let (loc, _) = self.dir_lookup(t, dir, name)?.ok_or(Errno::ENOENT)?;
        if loc.ty != item::INODE_ITEM {
            // A subvolume.
            return Err(Errno::EPERM);
        }
        let d = self.inode(t, loc.objectid)?;
        let is_dir = Self::kind(&d)? == FileKind::Directory;
        match (want_dir, is_dir) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            (true, true) if le64(&d, ino::SIZE)? != 0 => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        self.unlink(t, dir, name, loc.objectid, open)
    }

    fn unlink(
        &mut self,
        t: u64,
        dir: u64,
        name: &[u8],
        ino: u64,
        open: &dyn Fn(u64, u64) -> bool,
    ) -> Result<(), Errno> {
        let idx = self.inode_ref_del(t, ino, dir, name)?;
        self.dir_del(t, dir, name, idx)?;
        let mut d = self.inode(t, ino)?;
        let nlink = if Self::kind(&d)? == FileKind::Directory { 0 } else { le32(&d, ino::NLINK)?.saturating_sub(1) };
        put32(&mut d, ino::NLINK, nlink)?;
        self.stamp(&mut d, false)?;
        self.set_inode(t, ino, &d)?;
        if nlink == 0 {
            if open(t, ino) {
                self.insert(t, Key::new(tree::ORPHAN, item::ORPHAN_ITEM, ino), &[])?;
                try_push(&mut self.orphans_added, (t, ino))?;
            } else {
                self.delete_inode(t, ino)?;
            }
        }
        Ok(())
    }

    /// Deletes inode `ino` of tree `t` and its data.
    pub(crate) fn delete_inode(&mut self, t: u64, ino: u64) -> Result<(), Errno> {
        self.frees = true;
        self.drop_extents(t, ino, 0, u64::MAX)?;
        self.delete_range(t, Key::new(ino, 0, 0), Key::new(ino, 0xff, u64::MAX))?;
        let orphan = Key::new(tree::ORPHAN, item::ORPHAN_ITEM, ino);
        if self.find(t, orphan)?.is_some() {
            self.delete(t, orphan)?;
        }
        Ok(())
    }

    /// Adds `name` in `dir` for the existing inode `target`.
    pub(crate) fn link(&mut self, t: u64, dir: u64, name: &[u8], target: u64) -> Result<(), Errno> {
        let parent = self.inode(t, dir)?;
        if Self::kind(&parent)? != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        if le32(&parent, ino::NLINK)? == 0 {
            return Err(Errno::ENOENT);
        }
        if self.dir_lookup(t, dir, name)?.is_some() {
            return Err(Errno::EEXIST);
        }
        let mut d = self.inode(t, target)?;
        let kind = Self::kind(&d)?;
        if kind == FileKind::Directory {
            return Err(Errno::EPERM);
        }
        let nlink = le32(&d, ino::NLINK)?;
        if nlink == 0 {
            return Err(Errno::ENOENT);
        }
        put32(&mut d, ino::NLINK, nlink.checked_add(1).ok_or(Errno::EMLINK)?)?;
        self.stamp(&mut d, false)?;
        self.set_inode(t, target, &d)?;
        let idx = self.next_index(t, dir)?;
        self.inode_ref_add(t, target, dir, idx, name)?;
        self.dir_add(t, dir, name, Key::new(target, item::INODE_ITEM, 0), ft_of(kind), idx)
    }

    /// Moves `oname` of `odir` to `nname` of `ndir`, as `rename(2)`.
    pub(crate) fn rename(
        &mut self,
        t: u64,
        odir: u64,
        oname: &[u8],
        ndir: u64,
        nname: &[u8],
        open: &dyn Fn(u64, u64) -> bool,
    ) -> Result<(), Errno> {
        self.frees = true;
        let (src, ft) = self.dir_lookup(t, odir, oname)?.ok_or(Errno::ENOENT)?;
        if src.ty != item::INODE_ITEM {
            return Err(Errno::EPERM);
        }
        if odir == ndir && oname == nname {
            return Ok(());
        }
        let nparent = self.inode(t, ndir)?;
        if Self::kind(&nparent)? != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        if le32(&nparent, ino::NLINK)? == 0 {
            return Err(Errno::ENOENT);
        }
        let src_dir = Self::kind(&self.inode(t, src.objectid)?)? == FileKind::Directory;
        let dst = self.dir_lookup(t, ndir, nname)?;
        if let Some((dloc, _)) = dst {
            if dloc == src {
                return Ok(());
            }
            if dloc.ty != item::INODE_ITEM {
                return Err(Errno::EPERM);
            }
            let dd = self.inode(t, dloc.objectid)?;
            let dst_dir = Self::kind(&dd)? == FileKind::Directory;
            match (src_dir, dst_dir) {
                (true, false) => return Err(Errno::ENOTDIR),
                (false, true) => return Err(Errno::EISDIR),
                (true, true) if le64(&dd, ino::SIZE)? != 0 => return Err(Errno::ENOTEMPTY),
                _ => {}
            }
        }
        if src_dir && odir != ndir {
            // Not into itself: walk up from the new parent.
            let mut cur = ndir;
            for _ in 0..4096 {
                if cur == src.objectid {
                    return Err(Errno::EINVAL);
                }
                match self.next_item(t, Key::new(cur, item::INODE_REF, 0))? {
                    Some((k, _)) if k.objectid == cur && k.ty == item::INODE_REF && k.offset != cur => cur = k.offset,
                    _ => break,
                }
            }
        }
        if let Some((dloc, _)) = dst {
            self.unlink(t, ndir, nname, dloc.objectid, open)?;
        }
        let idx = self.inode_ref_del(t, src.objectid, odir, oname)?;
        self.dir_del(t, odir, oname, idx)?;
        let nidx = self.next_index(t, ndir)?;
        self.inode_ref_add(t, src.objectid, ndir, nidx, nname)?;
        self.dir_add(t, ndir, nname, src, ft, nidx)?;
        let mut d = self.inode(t, src.objectid)?;
        self.stamp(&mut d, false)?;
        self.set_inode(t, src.objectid, &d)
    }

    /// Takes the file range `p..q` out of inode `ino`'s extents, trimming or
    /// splitting those that cross its ends; returns the bytes it held.
    fn drop_extents(&mut self, t: u64, ino: u64, p: u64, q: u64) -> Result<u64, Errno> {
        let mut removed = 0;
        let ours = |k: &Key| k.objectid == ino && k.ty == item::EXTENT_DATA;
        // One that starts before `p`.
        if let Some(before) = p.checked_sub(1)
            && let Some((k, mut d)) = self.prev_item(t, Key::new(ino, item::EXTENT_DATA, before))?
            && ours(&k)
        {
            let (s, info) = (k.offset, extent_info(&d)?);
            let end = s.saturating_add(info.len);
            if end > p {
                let Some((bytenr, disk_len, off)) = info.disk else { return Err(Errno::EIO) };
                if end > q {
                    let mut tail = try_to_vec(&d)?;
                    put64(&mut tail, 37, off.checked_add(q - s).ok_or(Errno::EIO)?)?;
                    put64(&mut tail, 45, end - q)?;
                    self.insert(t, Key::new(ino, item::EXTENT_DATA, q), &tail)?;
                    if bytenr != 0 {
                        self.data_ref(bytenr, disk_len, t, ino, s.wrapping_sub(off), 1, false)?;
                        removed += q - p;
                    }
                } else if bytenr != 0 {
                    removed += end - p;
                }
                put64(&mut d, 45, p - s)?;
                self.update(t, k, &d)?;
            }
        }
        // Those that start in `p..q`.
        while let Some((k, d)) = self.next_item(t, Key::new(ino, item::EXTENT_DATA, p))? {
            if !ours(&k) || k.offset >= q {
                break;
            }
            let (s, info) = (k.offset, extent_info(&d)?);
            let end = s.saturating_add(info.len);
            self.delete(t, k)?;
            let Some((bytenr, disk_len, off)) = info.disk else {
                // Inline.
                removed += info.len;
                continue;
            };
            if end > q {
                let mut tail = d;
                put64(&mut tail, 37, off.checked_add(q - s).ok_or(Errno::EIO)?)?;
                put64(&mut tail, 45, end - q)?;
                self.insert(t, Key::new(ino, item::EXTENT_DATA, q), &tail)?;
                if bytenr != 0 {
                    removed += q - s;
                }
            } else if bytenr != 0 {
                removed += end - s;
                self.data_ref(bytenr, disk_len, t, ino, s.wrapping_sub(off), -1, false)?;
            }
        }
        Ok(removed)
    }

    #[allow(clippy::too_many_arguments)]
    fn data_ref(
        &mut self,
        bytenr: u64,
        len: u64,
        root: u64,
        ino: u64,
        offset: u64,
        delta: i64,
        new: bool,
    ) -> Result<(), Errno> {
        Ok(try_push(&mut self.data_refs, DataRef { bytenr, len, root, ino, offset, delta, new })?)
    }

    /// Writes `buf` (whole sectors) as new extents at file offset `at` of
    /// `ino`, replacing what was there; returns bytes added to `nbytes`
    /// less those dropped.
    fn put_extents(&mut self, t: u64, ino: u64, mut at: u64, mut buf: &[u8], sums: bool) -> Result<i64, Errno> {
        let (ss, cs) = (self.sh.sectorsize, self.sh.csum_size);
        let mut delta = 0i64;
        while !buf.is_empty() {
            let (start, got) = self.alloc_data(buf.len() as u64)?;
            let (data, rest) = buf.split_at_checked(got as usize).ok_or(Errno::EIO)?;
            let chunks = self.new_chunks.as_ref().unwrap_or(&self.base.chunks);
            self.sh.write_logical(chunks, start, data)?;
            if sums {
                let mut s = Vec::new();
                s.try_reserve_exact(data.len() / ss as usize * cs).map_err(|_| Errno::ENOMEM)?;
                for sector in data.chunks(ss as usize) {
                    s.extend_from_slice(csum::compute(self.sh.csum_type, sector).get(..cs).ok_or(Errno::EIO)?);
                }
                self.csum_insert(start, &s)?;
            }
            delta -= self.drop_extents(t, ino, at, at + got)? as i64;
            let mut fe = [0u8; 53];
            put64(&mut fe, 0, self.transid)?;
            put64(&mut fe, 8, got)?;
            put(&mut fe, 20, &[1])?;
            put64(&mut fe, 21, start)?;
            put64(&mut fe, 29, got)?;
            put64(&mut fe, 45, got)?;
            self.insert(t, Key::new(ino, item::EXTENT_DATA, at), &fe)?;
            self.data_ref(start, got, t, ino, at, 1, true)?;
            delta += got as i64;
            at += got;
            buf = rest;
        }
        Ok(delta)
    }

    /// Reads committed bytes of the file into `buf` (zeroes past its end).
    fn read_old(&mut self, t: u64, ino: u64, off: u64, buf: &mut [u8]) -> Result<(), Errno> {
        buf.fill(0);
        let base = self.base.clone();
        let root = self.sh.fs_root(&base, t)?.ok_or(Errno::EIO)?;
        let inode = self.sh.read_inode(&base, (root.bytenr, root.level), ino)?;
        self.sh.read_file(&base, (root.bytenr, root.level), ino, &inode, off, buf, None)?;
        Ok(())
    }

    /// Turns an inline extent at the start of `ino` into a regular one, so
    /// that the file can be changed anywhere; returns the `nbytes` change.
    fn uninline(&mut self, t: u64, ino: u64, nodatasum: bool) -> Result<i64, Errno> {
        let Some(d) = self.find(t, Key::new(ino, item::EXTENT_DATA, 0))? else { return Ok(0) };
        if extent_info(&d)?.disk.is_some() {
            return Ok(0);
        }
        let mut buf = try_zeroed(self.sh.sectorsize as usize)?;
        self.read_old(t, ino, 0, &mut buf)?;
        self.put_extents(t, ino, 0, &buf, !nodatasum)
    }

    /// Writes `data` at `off` of file `ino`; returns the bytes written.
    pub(crate) fn write(&mut self, t: u64, ino: u64, off: u64, data: &[u8]) -> Result<usize, Errno> {
        let mut d = self.inode(t, ino)?;
        let size = le64(&d, ino::SIZE)?;
        match Self::kind(&d)? {
            FileKind::Regular => {}
            FileKind::Directory => return Err(Errno::EISDIR),
            FileKind::Symlink => return self.write_symlink(t, ino, off, data, d),
            _ => return Err(Errno::EINVAL),
        }
        if data.is_empty() {
            return Ok(0);
        }
        let end = off.checked_add(data.len() as u64).filter(|&e| e <= i64::MAX as u64).ok_or(Errno::EFBIG)?;
        let ss = self.sh.sectorsize;
        let sums = le64(&d, ino::FLAGS)? & disk::INODE_NODATASUM == 0;
        let mut nbytes = le64(&d, ino::NBYTES)? as i64 + self.uninline(t, ino, !sums)?;
        let mut pos = off;
        while pos < end {
            // One piece: whole sectors, old bytes around the new ones.
            let a = pos & !(ss - 1);
            let piece_end = end.min(a + MAX_PIECE);
            let e = piece_end.next_multiple_of(ss);
            let mut buf = try_zeroed((e - a) as usize)?;
            if a < pos {
                let head = buf.get_mut(..(pos - a) as usize).ok_or(Errno::EIO)?;
                self.read_old(t, ino, a, head)?;
            }
            if piece_end < e && piece_end < size {
                let tail = buf.get_mut((piece_end - a) as usize..).ok_or(Errno::EIO)?;
                self.read_old(t, ino, piece_end, tail)?;
            }
            let src = data.get((pos - off) as usize..(piece_end - off) as usize).ok_or(Errno::EIO)?;
            buf.get_mut((pos - a) as usize..(piece_end - a) as usize).ok_or(Errno::EIO)?.copy_from_slice(src);
            nbytes += self.put_extents(t, ino, a, &buf, sums)?;
            pos = piece_end;
        }
        put64(&mut d, ino::SIZE, size.max(end))?;
        put64(&mut d, ino::NBYTES, nbytes.max(0) as u64)?;
        self.stamp(&mut d, true)?;
        self.set_inode(t, ino, &d)?;
        Ok(data.len())
    }

    /// A symbolic link's target: written once, whole, at offset 0, inline.
    fn write_symlink(&mut self, t: u64, ino: u64, off: u64, data: &[u8], mut d: Vec<u8>) -> Result<usize, Errno> {
        if off != 0 || le64(&d, ino::SIZE)? != 0 || data.is_empty() {
            return Err(Errno::EINVAL);
        }
        let max = (self.leaf_space() - ITEM - 21).min(self.sh.sectorsize as usize - 1);
        if data.len() > max {
            return Err(Errno::ENAMETOOLONG);
        }
        let mut fe = Vec::new();
        fe.try_reserve_exact(21 + data.len()).map_err(|_| Errno::ENOMEM)?;
        fe.extend_from_slice(&self.transid.to_le_bytes());
        fe.extend_from_slice(&(data.len() as u64).to_le_bytes());
        fe.extend_from_slice(&[0; 5]);
        fe.extend_from_slice(data);
        self.insert(t, Key::new(ino, item::EXTENT_DATA, 0), &fe)?;
        put64(&mut d, ino::SIZE, data.len() as u64)?;
        put64(&mut d, ino::NBYTES, data.len() as u64)?;
        self.stamp(&mut d, true)?;
        self.set_inode(t, ino, &d)?;
        Ok(data.len())
    }

    /// Sets the size of file `ino` to `len`.
    pub(crate) fn truncate(&mut self, t: u64, ino: u64, len: u64) -> Result<(), Errno> {
        let mut d = self.inode(t, ino)?;
        match Self::kind(&d)? {
            FileKind::Regular => {}
            FileKind::Directory => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
        if len > i64::MAX as u64 {
            return Err(Errno::EFBIG);
        }
        let size = le64(&d, ino::SIZE)?;
        if len == size {
            return Ok(());
        }
        self.frees = len < size;
        let ss = self.sh.sectorsize;
        let sums = le64(&d, ino::FLAGS)? & disk::INODE_NODATASUM == 0;
        let mut nbytes = le64(&d, ino::NBYTES)? as i64 + self.uninline(t, ino, !sums)?;
        if len < size {
            nbytes -= self.drop_extents(t, ino, len.next_multiple_of(ss), u64::MAX)? as i64;
            if !len.is_multiple_of(ss) {
                // Zero the rest of the last sector, so that growing the file
                // again shows zeroes there.
                let s0 = len & !(ss - 1);
                let mut buf = try_zeroed(ss as usize)?;
                self.read_old(t, ino, s0, buf.get_mut(..(len - s0) as usize).ok_or(Errno::EIO)?)?;
                nbytes += self.put_extents(t, ino, s0, &buf, sums)?;
            }
        }
        put64(&mut d, ino::SIZE, len)?;
        put64(&mut d, ino::NBYTES, nbytes.max(0) as u64)?;
        self.stamp(&mut d, true)?;
        self.set_inode(t, ino, &d)
    }

    /// Sets extended attribute `name` of `ino`.
    pub(crate) fn xattr_set(
        &mut self,
        t: u64,
        ino: u64,
        name: &[u8],
        value: &[u8],
        how: XattrSet,
    ) -> Result<(), Errno> {
        if name.is_empty() || name.len() > 255 {
            return Err(Errno::ERANGE);
        }
        if ITEM + 30 + name.len() + value.len() > self.leaf_space() {
            return Err(Errno::E2BIG);
        }
        let key = Key::new(ino, item::XATTR_ITEM, csum::name_hash(name));
        let old = self.find(t, key)?;
        let mut kept = match &old {
            Some(d) => match entries(d)?.into_iter().find(|e| e.2 == name) {
                Some((from, to, _)) => {
                    if how == XattrSet::Create {
                        return Err(Errno::EEXIST);
                    }
                    without(d, from, to)?
                }
                None => try_to_vec(d)?,
            },
            None => Vec::new(),
        };
        if how == XattrSet::Replace && kept.len() == old.as_ref().map_or(0, |d| d.len()) {
            return Err(Errno::ENODATA);
        }
        let e = entry(Key::new(0, 0, 0), self.transid, name, value, FT_XATTR)?;
        kept = with(&kept, &e)?;
        if ITEM + kept.len() > self.leaf_space() {
            return Err(Errno::ENOSPC);
        }
        self.put(t, key, &kept)?;
        let mut d = self.inode(t, ino)?;
        self.stamp(&mut d, false)?;
        self.set_inode(t, ino, &d)
    }

    /// Removes extended attribute `name` of `ino`.
    pub(crate) fn xattr_remove(&mut self, t: u64, ino: u64, name: &[u8]) -> Result<(), Errno> {
        self.frees = true;
        let key = Key::new(ino, item::XATTR_ITEM, csum::name_hash(name));
        let d = self.find(t, key)?.ok_or(Errno::ENODATA)?;
        let (from, to, _) = entries(&d)?.into_iter().find(|e| e.2 == name).ok_or(Errno::ENODATA)?;
        if to - from == d.len() {
            self.delete(t, key)?;
        } else {
            self.update(t, key, &without(&d, from, to)?)?;
        }
        let mut d = self.inode(t, ino)?;
        self.stamp(&mut d, false)?;
        self.set_inode(t, ino, &d)
    }
}

/// What `drop_extents` needs of a file extent item.
struct ExtentInfo {
    /// Bytes of the file it covers.
    len: u64,
    /// For a regular or preallocated extent: its address (0 for a hole),
    /// length on disk, and offset into it. `None` for inline data.
    disk: Option<(u64, u64, u64)>,
}

fn extent_info(d: &[u8]) -> Result<ExtentInfo, Errno> {
    let fe = FileExtent::parse(d)?;
    let disk = match fe.data {
        disk::ExtentData::Inline(_) => None,
        _ => Some((le64(d, 21)?, le64(d, 29)?, le64(d, 37)?)),
    };
    Ok(ExtentInfo { len: fe.len(), disk })
}
