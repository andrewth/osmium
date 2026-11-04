//! File system operations, each run inside a transaction.

use alloc::vec::Vec;

use osmium_fs::{Errno, FileKind, Timestamp, XattrSet};
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_push, try_to_vec, try_zeroed};

use crate::disk::{self, FileExtent, Key, byte, compress, item, le16, le32, le64, put, put32, put64, tree};
use crate::node::ITEM;
use crate::write::{DataRef, Tx};
use crate::{MAX_COMPRESSED, csum, deflate, lzo_comp, zstd};

/// Largest piece of a write handled at once (each gets its own extent).
const MAX_PIECE: u64 = 1 << 20;

/// Linux's default `max_inline`: the most file data kept in the tree.
const MAX_INLINE: usize = 2048;

/// Most bytes one preallocated extent covers.
const MAX_PREALLOC: u64 = 128 << 20;

/// Inode flags a new inode takes from its directory.
const INHERITED: u64 = disk::INODE_NODATASUM | disk::INODE_NODATACOW | disk::INODE_NOCOMPRESS | disk::INODE_COMPRESS;

/// `BTRFS_FT_XATTR`.
const FT_XATTR: u8 = 8;

/// Offsets in an inode item.
pub(crate) mod ino {
    pub const GENERATION: usize = 0;
    pub const TRANSID: usize = 8;
    pub const SIZE: usize = 16;
    pub const NBYTES: usize = 24;
    pub const NLINK: usize = 40;
    pub const UID: usize = 44;
    pub const GID: usize = 48;
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

/// What a new inode is.
pub(crate) struct NewInode {
    pub kind: FileKind,
    /// Permission bits.
    pub mode: u32,
    /// Device number of a device node.
    pub rdev: u64,
    pub uid: u32,
    pub gid: u32,
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

pub(crate) fn put_time(b: &mut [u8], at: usize, t: Timestamp) -> Result<(), Errno> {
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

pub(crate) fn entries(d: &[u8]) -> Result<Vec<Entry<'_>>, Errno> {
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

    pub(crate) fn set_inode(&mut self, t: u64, ino: u64, d: &[u8]) -> Result<(), Errno> {
        self.update(t, Key::new(ino, item::INODE_ITEM, 0), d)
    }

    /// Marks inode data `d` changed now: its change time, and with `modify`
    /// its modification time.
    pub(crate) fn stamp(&self, d: &mut [u8], modify: bool) -> Result<(), Errno> {
        let now = self.sh.now();
        put_time(d, ino::CTIME, now)?;
        if modify {
            put_time(d, ino::MTIME, now)?;
        }
        put64(d, ino::TRANSID, self.transid)?;
        put64(d, ino::SEQUENCE, le64(d, ino::SEQUENCE)?.wrapping_add(1))
    }

    pub(crate) fn kind(d: &[u8]) -> Result<FileKind, Errno> {
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
    pub(crate) fn next_index(&mut self, t: u64, dir: u64) -> Result<u64, Errno> {
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
    pub(crate) fn dir_add(&mut self, t: u64, dir: u64, name: &[u8], loc: Key, ft: u8, idx: u64) -> Result<(), Errno> {
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
    pub(crate) fn dir_del(&mut self, t: u64, dir: u64, name: &[u8], idx: u64) -> Result<(), Errno> {
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
        if ITEM + d.len() <= self.leaf_space() {
            return self.put(t, key, &d);
        }
        // The `INODE_REF` item is full: the name goes in an `INODE_EXTREF`.
        let mut x = Vec::new();
        x.try_reserve_exact(18 + name.len()).map_err(|_| Errno::ENOMEM)?;
        x.extend_from_slice(&parent.to_le_bytes());
        x.extend_from_slice(&idx.to_le_bytes());
        x.extend_from_slice(&(name.len() as u16).to_le_bytes());
        x.extend_from_slice(name);
        let key = Key::new(ino, item::INODE_EXTREF, extref_hash(parent, name));
        let d = match self.find(t, key)? {
            Some(d) => with(&d, &x)?,
            None => x,
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
    pub(crate) fn create(&mut self, t: u64, dir: u64, name: &[u8], new: NewInode) -> Result<u64, Errno> {
        let NewInode { kind, mode, rdev, uid, gid } = new;
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
        put32(&mut d, ino::UID, uid)?;
        put32(&mut d, ino::GID, gid)?;
        put32(&mut d, ino::MODE, kind.mode_bits() | mode & 0o7777)?;
        if matches!(kind, FileKind::CharDevice | FileKind::BlockDevice) {
            put64(&mut d, ino::RDEV, kernel_rdev(rdev))?;
        }
        let mut flags = le64(&parent, ino::FLAGS)? & INHERITED;
        if flags & disk::INODE_NODATACOW != 0 && kind == FileKind::Regular {
            // As Linux: a nodatacow file has no checksums either.
            flags |= disk::INODE_NODATASUM;
        }
        put64(&mut d, ino::FLAGS, flags)?;
        for at in [ino::ATIME, ino::CTIME, ino::MTIME, ino::OTIME] {
            put_time(&mut d, at, now)?;
        }
        self.insert(t, Key::new(ino, item::INODE_ITEM, 0), &d)?;
        let idx = self.next_index(t, dir)?;
        self.inode_ref_add(t, ino, dir, idx, name)?;
        self.dir_add(t, dir, name, Key::new(ino, item::INODE_ITEM, 0), ft_of(kind), idx)?;
        Ok(ino)
    }

    /// Sets the permission bits of inode `ino`.
    pub(crate) fn chmod(&mut self, t: u64, ino: u64, mode: u32) -> Result<(), Errno> {
        let mut d = self.inode(t, ino)?;
        let kept = le32(&d, ino::MODE)? & !0o7777;
        put32(&mut d, ino::MODE, kept | mode & 0o7777)?;
        self.stamp(&mut d, false)?;
        self.set_inode(t, ino, &d)
    }

    /// Sets the owner and/or group of inode `ino`.
    pub(crate) fn chown(&mut self, t: u64, ino: u64, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        let mut d = self.inode(t, ino)?;
        if let Some(u) = uid {
            put32(&mut d, ino::UID, u)?;
        }
        if let Some(g) = gid {
            put32(&mut d, ino::GID, g)?;
        }
        self.stamp(&mut d, false)?;
        self.set_inode(t, ino, &d)
    }

    /// Sets the access time of inode `ino` to now if `policy` says it is due;
    /// changes nothing (and so commits nothing) otherwise.
    pub(crate) fn touch_atime(&mut self, t: u64, ino: u64, policy: crate::Atime) -> Result<(), Errno> {
        let mut d = self.inode(t, ino)?;
        let now = self.sh.now();
        let time = |off| -> Result<Timestamp, Errno> {
            Ok(Timestamp { sec: le64(&d, off)? as i64, nsec: le32(&d, off + 8)? })
        };
        if !policy.due(time(ino::ATIME)?, time(ino::MTIME)?, time(ino::CTIME)?, now) {
            return Ok(());
        }
        put_time(&mut d, ino::ATIME, now)?;
        self.set_inode(t, ino, &d)
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
        Ok(try_push(&mut self.data_refs, DataRef { bytenr, len, root, ino, offset, delta, new, parent: 0 })?)
    }

    /// Writes `buf` (whole sectors) as new extents at file offset `at` of
    /// `ino`, replacing what was there, compressed with `comp` where that
    /// saves at least a sector; returns bytes added to `nbytes` less those
    /// dropped.
    fn put_extents(
        &mut self,
        t: u64,
        ino: u64,
        at: u64,
        buf: &[u8],
        sums: bool,
        comp: u8,
    ) -> Result<i64, Errno> {
        match self.put_extents_part(t, ino, at, buf, sums, comp)? {
            (delta, done) if done == buf.len() as u64 => Ok(delta),
            _ => Err(Errno::ENOSPC),
        }
    }

    /// As `put_extents`, but if data space runs out, stops there: returns the
    /// `nbytes` change and the bytes of `buf` written.
    fn put_extents_part(
        &mut self,
        t: u64,
        ino: u64,
        mut at: u64,
        mut buf: &[u8],
        sums: bool,
        comp: u8,
    ) -> Result<(i64, u64), Errno> {
        let ss = self.sh.sectorsize;
        let mut delta = 0i64;
        let total = buf.len() as u64;
        while !buf.is_empty() {
            if comp != compress::NONE {
                let chunk = buf.get(..buf.len().min(MAX_COMPRESSED as usize)).ok_or(Errno::EIO)?;
                if let Some(done) = self.put_compressed(t, ino, at, chunk, sums, comp)? {
                    delta += done;
                    at += chunk.len() as u64;
                    buf = buf.get(chunk.len()..).ok_or(Errno::EIO)?;
                    continue;
                }
            }
            // Stored as is; with compression on, a chunk at a time so that
            // the next one gets its try.
            let want = if comp == compress::NONE { buf.len() } else { buf.len().min(MAX_COMPRESSED as usize) };
            let (start, got) = match self.alloc_data(want as u64) {
                Ok(r) => r,
                Err(Errno::ENOSPC) => break,
                Err(e) => return Err(e),
            };
            let (data, rest) = buf.split_at_checked(got as usize).ok_or(Errno::EIO)?;
            let chunks = self.new_chunks.as_ref().unwrap_or(&self.base.chunks);
            self.sh.write_logical(chunks, start, data)?;
            if sums {
                self.sum_extent(start, data, ss)?;
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
        Ok((delta, total - buf.len() as u64))
    }

    /// Where on disk file range `a..e` of `ino` can be overwritten in place:
    /// it lies in one plain regular extent that only this file refers to, and
    /// that no snapshot can share.
    fn nocow_target(&mut self, t: u64, ino: u64, a: u64, e: u64) -> Result<Option<u64>, Errno> {
        let Some((k, d)) = self.prev_item(t, Key::new(ino, item::EXTENT_DATA, a))? else { return Ok(None) };
        if k.objectid != ino || k.ty != item::EXTENT_DATA || d.len() < 53 {
            return Ok(None);
        }
        // Regular, and not compressed, encrypted or otherwise encoded.
        if byte(&d, 20)? != 1 || byte(&d, 16)? != 0 || byte(&d, 17)? != 0 || le16(&d, 18)? != 0 {
            return Ok(None);
        }
        let (bytenr, disk_len, off, num) = (le64(&d, 21)?, le64(&d, 29)?, le64(&d, 37)?, le64(&d, 45)?);
        let end = k.offset.checked_add(num).ok_or(Errno::EIO)?;
        let snapshot = self.root(t)?.last_snapshot;
        if bytenr == 0 || a < k.offset || e > end || (snapshot != 0 && le64(&d, 0)? <= snapshot) {
            return Ok(None);
        }
        if self.data_refs.iter().any(|r| r.bytenr == bytenr) {
            return Ok(None);
        }
        // Exactly one reference to the extent: ours.
        let Some(x) = self.find(tree::EXTENT, Key::new(bytenr, item::EXTENT_ITEM, disk_len))? else { return Ok(None) };
        if le64(&x, 0)? != 1 {
            return Ok(None);
        }
        let at = off.checked_add(a - k.offset).ok_or(Errno::EIO)?;
        Ok(bytenr.checked_add(at))
    }

    /// Checksums `data`, which starts at logical address `start`.
    fn sum_extent(&mut self, start: u64, data: &[u8], ss: u64) -> Result<(), Errno> {
        let cs = self.sh.csum_size;
        let mut s = Vec::new();
        s.try_reserve_exact(data.len() / ss as usize * cs).map_err(|_| Errno::ENOMEM)?;
        for sector in data.chunks(ss as usize) {
            s.extend_from_slice(csum::compute(self.sh.csum_type, sector).get(..cs).ok_or(Errno::EIO)?);
        }
        self.csum_insert(start, &s)
    }

    /// Tries to write `chunk` (whole sectors, at most [`MAX_COMPRESSED`]) at
    /// `at` as one extent compressed with `comp`. `None`, and nothing
    /// changed, if the result would not be a sector smaller or the space for
    /// it is not in one piece.
    fn put_compressed(
        &mut self,
        t: u64,
        ino: u64,
        at: u64,
        chunk: &[u8],
        sums: bool,
        comp: u8,
    ) -> Result<Option<i64>, Errno> {
        let ss = self.sh.sectorsize;
        let Some(limit) = chunk.len().checked_sub(ss as usize).filter(|&l| l > 0) else { return Ok(None) };
        let packed = match comp {
            compress::ZLIB => deflate::compress(chunk, limit)?,
            compress::LZO => lzo_comp::compress(chunk, ss as usize, limit)?,
            compress::ZSTD => zstd::compress(chunk, limit)?,
            _ => None,
        };
        let Some(mut packed) = packed else { return Ok(None) };
        // The extent takes whole sectors, zero-padded.
        let disk_len = (packed.len() as u64).next_multiple_of(ss);
        if disk_len > limit as u64 {
            return Ok(None);
        }
        packed.try_reserve_exact((disk_len as usize).saturating_sub(packed.len())).map_err(|_| Errno::ENOMEM)?;
        packed.resize(disk_len as usize, 0);
        let (start, got) = self.alloc_data(disk_len)?;
        if got < disk_len {
            // Fragmented free space: give it back and store the chunk as is.
            self.unalloc(start);
            return Ok(None);
        }
        let chunks = self.new_chunks.as_ref().unwrap_or(&self.base.chunks);
        self.sh.write_logical(chunks, start, &packed)?;
        if sums {
            self.sum_extent(start, &packed, ss)?;
        }
        let len = chunk.len() as u64;
        let removed = self.drop_extents(t, ino, at, at + len)? as i64;
        let mut fe = [0u8; 53];
        put64(&mut fe, 0, self.transid)?;
        put64(&mut fe, 8, len)?;
        put(&mut fe, 16, &[comp])?;
        put(&mut fe, 20, &[1])?;
        put64(&mut fe, 21, start)?;
        put64(&mut fe, 29, disk_len)?;
        put64(&mut fe, 45, len)?;
        self.insert(t, Key::new(ino, item::EXTENT_DATA, at), &fe)?;
        self.data_ref(start, disk_len, t, ino, at, 1, true)?;
        match comp {
            compress::LZO => self.incompat |= disk::incompat::COMPRESS_LZO,
            compress::ZSTD => self.incompat |= disk::incompat::COMPRESS_ZSTD,
            _ => {}
        }
        Ok(Some(len as i64 - removed))
    }

    /// The algorithm for new data of an inode with `flags`.
    fn algorithm(&self, flags: u64) -> u8 {
        if flags & (disk::INODE_NODATACOW | disk::INODE_NOCOMPRESS) != 0 {
            return compress::NONE;
        }
        match self.sh.compress {
            compress::NONE if flags & disk::INODE_COMPRESS != 0 => compress::ZLIB,
            c => c,
        }
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
        self.put_extents(t, ino, 0, &buf, !nodatasum, compress::NONE)
    }

    /// The most data an inline extent holds: like Linux, `max_inline` (2048),
    /// less than a sector and what fits in a leaf.
    fn max_inline(&self) -> usize {
        let room = self.leaf_space().saturating_sub(ITEM + 21);
        MAX_INLINE.min(self.sh.sectorsize as usize - 1).min(room)
    }

    /// The uncompressed inline extent that is all of file `ino`, if so: its data.
    fn inline_data(&mut self, t: u64, ino: u64, size: u64) -> Result<Option<Vec<u8>>, Errno> {
        let Some(d) = self.find(t, Key::new(ino, item::EXTENT_DATA, 0))? else { return Ok(None) };
        let fe = FileExtent::parse(&d)?;
        match fe.data {
            disk::ExtentData::Inline(data) if fe.compression == 0 && data.len() as u64 == size => {
                Ok(Some(try_to_vec(data)?))
            }
            _ => Ok(None),
        }
    }

    /// Stores `data` as the inline extent of file `ino`, whose inode is `d`.
    fn set_inline(&mut self, t: u64, ino: u64, data: &[u8], d: &mut [u8]) -> Result<(), Errno> {
        let mut fe = Vec::new();
        fe.try_reserve_exact(21 + data.len()).map_err(|_| Errno::ENOMEM)?;
        fe.extend_from_slice(&self.transid.to_le_bytes());
        fe.extend_from_slice(&(data.len() as u64).to_le_bytes());
        fe.extend_from_slice(&[0; 5]);
        fe.extend_from_slice(data);
        self.put(t, Key::new(ino, item::EXTENT_DATA, 0), &fe)?;
        put64(d, ino::SIZE, data.len() as u64)?;
        put64(d, ino::NBYTES, data.len() as u64)?;
        self.stamp(d, true)
    }

    /// Handles a write that leaves the whole file small enough to be one
    /// inline extent: a write at 0 of an empty file, or one that touches or
    /// extends an inline file. Updates inode `d` (not stored); `false` if
    /// the write is not of that kind and nothing changed.
    fn write_inline(
        &mut self,
        t: u64,
        ino: u64,
        off: u64,
        data: &[u8],
        size: u64,
        d: &mut [u8],
    ) -> Result<bool, Errno> {
        let end = off.saturating_add(data.len() as u64);
        if end > self.max_inline() as u64 || off > size {
            return Ok(false);
        }
        let mut file = if size == 0 {
            // Only if there is no extent at all (a preallocated one may be left).
            match self.next_item(t, Key::new(ino, item::EXTENT_DATA, 0))? {
                Some((k, _)) if k.objectid == ino && k.ty == item::EXTENT_DATA => return Ok(false),
                _ => Vec::new(),
            }
        } else {
            match self.inline_data(t, ino, size)? {
                Some(old) => old,
                None => return Ok(false),
            }
        };
        let (o, e) = (off as usize, end as usize);
        if file.len() < e {
            file.try_reserve_exact(e - file.len()).map_err(|_| Errno::ENOMEM)?;
            file.resize(e, 0);
        }
        file.get_mut(o..e).ok_or(Errno::EIO)?.copy_from_slice(data);
        self.set_inline(t, ino, &file, d)?;
        Ok(true)
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
        let flags = le64(&d, ino::FLAGS)?;
        let sums = flags & disk::INODE_NODATASUM == 0;
        let nocow = !sums && flags & disk::INODE_NODATACOW != 0;
        let comp = self.algorithm(flags);
        if self.write_inline(t, ino, off, data, size, &mut d)? {
            self.set_inode(t, ino, &d)?;
            return Ok(data.len());
        }
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
            let target = if nocow { self.nocow_target(t, ino, a, e)? } else { None };
            let done = if let Some(addr) = target {
                // Overwritten where it lies: no new extent, no new space.
                let chunks = self.new_chunks.as_ref().unwrap_or(&self.base.chunks);
                self.sh.write_logical(chunks, addr, &buf)?;
                e - a
            } else {
                let (delta, done) = self.put_extents_part(t, ino, a, &buf, sums, comp)?;
                nbytes += delta;
                done
            };
            let reached = a.saturating_add(done).min(piece_end);
            if reached <= pos {
                if pos == off {
                    return Err(Errno::ENOSPC);
                }
                break;
            }
            pos = reached;
            if done < e - a {
                // Out of space: a short write.
                break;
            }
        }
        put64(&mut d, ino::SIZE, size.max(pos))?;
        put64(&mut d, ino::NBYTES, nbytes.max(0) as u64)?;
        self.stamp(&mut d, true)?;
        self.set_inode(t, ino, &d)?;
        Ok((pos - off) as usize)
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
        if len < size
            && let Some(mut file) = self.inline_data(t, ino, size)?
        {
            // Stays inline, shorter.
            if len == 0 {
                self.delete(t, Key::new(ino, item::EXTENT_DATA, 0))?;
                put64(&mut d, ino::SIZE, 0)?;
                put64(&mut d, ino::NBYTES, 0)?;
                self.stamp(&mut d, true)?;
            } else {
                file.truncate(len as usize);
                self.set_inline(t, ino, &file, &mut d)?;
            }
            return self.set_inode(t, ino, &d);
        }
        let ss = self.sh.sectorsize;
        let flags = le64(&d, ino::FLAGS)?;
        let sums = flags & disk::INODE_NODATASUM == 0;
        let mut nbytes = le64(&d, ino::NBYTES)? as i64 + self.uninline(t, ino, !sums)?;
        if len < size {
            nbytes -= self.drop_extents(t, ino, len.next_multiple_of(ss), u64::MAX)? as i64;
            if !len.is_multiple_of(ss) {
                // Zero the rest of the last sector, so that growing the file
                // again shows zeroes there.
                let s0 = len & !(ss - 1);
                let mut buf = try_zeroed(ss as usize)?;
                self.read_old(t, ino, s0, buf.get_mut(..(len - s0) as usize).ok_or(Errno::EIO)?)?;
                nbytes += self.put_extents(t, ino, s0, &buf, sums, compress::NONE)?;
            }
        }
        put64(&mut d, ino::SIZE, len)?;
        put64(&mut d, ino::NBYTES, nbytes.max(0) as u64)?;
        self.stamp(&mut d, true)?;
        self.set_inode(t, ino, &d)
    }

    /// The parts of the sector-aligned file range `a..e` of `ino` that hold
    /// no data (no extent, or a hole), as `(start, end)`.
    fn gaps(&mut self, t: u64, ino: u64, a: u64, e: u64) -> Result<Vec<(u64, u64)>, Errno> {
        let ours = |k: &Key| k.objectid == ino && k.ty == item::EXTENT_DATA;
        let mut gaps = Vec::new();
        let mut pos = a;
        let mut from = a;
        let mut pending = self.prev_item(t, Key::new(ino, item::EXTENT_DATA, a))?.filter(|(k, _)| ours(k));
        loop {
            let (k, d) = match pending.take() {
                Some(x) => x,
                None => match self.next_item(t, Key::new(ino, item::EXTENT_DATA, from))? {
                    Some(x) if ours(&x.0) && x.0.offset < e => x,
                    _ => break,
                },
            };
            from = k.offset.saturating_add(1);
            let info = extent_info(&d)?;
            if !info.disk.is_some_and(|(bytenr, _, _)| bytenr != 0) {
                // A hole: no data. (Inline data was turned into an extent.)
                if info.disk.is_none() {
                    return Err(Errno::EIO);
                }
                continue;
            }
            if k.offset > pos {
                try_push(&mut gaps, (pos, k.offset.min(e)))?;
            }
            pos = pos.max(k.offset.saturating_add(info.len));
        }
        if pos < e {
            try_push(&mut gaps, (pos, e))?;
        }
        Ok(gaps)
    }

    /// Preallocates the file range `off..off + len` of `ino`, as
    /// `fallocate(2)` does: what has no data gets preallocated extents (read
    /// as zeroes until written), what has is kept, and the file grows to
    /// `off + len` if it is shorter.
    pub(crate) fn fallocate(&mut self, t: u64, ino: u64, off: u64, len: u64) -> Result<(), Errno> {
        let mut d = self.inode(t, ino)?;
        match Self::kind(&d)? {
            FileKind::Regular => {}
            FileKind::Directory => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        let end = off.checked_add(len).filter(|&e| e <= i64::MAX as u64).ok_or(Errno::EFBIG)?;
        let ss = self.sh.sectorsize;
        let size = le64(&d, ino::SIZE)?;
        let sums = le64(&d, ino::FLAGS)? & disk::INODE_NODATASUM == 0;
        let (a, e) = (off & !(ss - 1), end.next_multiple_of(ss));
        let mut nbytes = le64(&d, ino::NBYTES)? as i64;
        if a == 0 {
            nbytes += self.uninline(t, ino, !sums)?;
        }
        for (g0, g1) in self.gaps(t, ino, a, e)? {
            let mut at = g0;
            while at < g1 {
                let (start, got) = self.alloc_data((g1 - at).min(MAX_PREALLOC))?;
                // Whatever is in the range now is a hole; clear its item.
                self.drop_extents(t, ino, at, at + got)?;
                let mut fe = [0u8; 53];
                put64(&mut fe, 0, self.transid)?;
                put64(&mut fe, 8, got)?;
                put(&mut fe, 20, &[2])?;
                put64(&mut fe, 21, start)?;
                put64(&mut fe, 29, got)?;
                put64(&mut fe, 45, got)?;
                self.insert(t, Key::new(ino, item::EXTENT_DATA, at), &fe)?;
                self.data_ref(start, got, t, ino, at, 1, true)?;
                nbytes += got as i64;
                at += got;
            }
        }
        put64(&mut d, ino::SIZE, size.max(end))?;
        put64(&mut d, ino::NBYTES, nbytes.max(0) as u64)?;
        self.stamp(&mut d, true)?;
        self.set_inode(t, ino, &d)
    }

    /// Deallocates the file range `off..off + len` of `ino`, which then reads
    /// as zeroes; the size stays. Whole sectors become holes, the partial
    /// ones at the ends are zeroed.
    pub(crate) fn punch_hole(&mut self, t: u64, ino: u64, off: u64, len: u64) -> Result<(), Errno> {
        let d = self.inode(t, ino)?;
        match Self::kind(&d)? {
            FileKind::Regular => {}
            FileKind::Directory => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
        let end = off.checked_add(len).filter(|&e| e <= i64::MAX as u64).ok_or(Errno::EFBIG)?;
        let size = le64(&d, ino::SIZE)?;
        let ss = self.sh.sectorsize;
        // Data exists only below the size.
        let (off, end) = (off.min(size), end.min(size));
        if off >= end {
            return Ok(());
        }
        self.frees = true;
        let (ia, ib) = (off.next_multiple_of(ss), end & !(ss - 1));
        let zero = |tx: &mut Self, from: u64, to: u64| -> Result<(), Errno> {
            if from < to {
                let z = try_zeroed((to - from) as usize)?;
                tx.write(t, ino, from, &z)?;
            }
            Ok(())
        };
        if ia >= ib {
            zero(self, off, end)?;
        } else {
            zero(self, off, ia)?;
            zero(self, ib, end)?;
        }
        if ia < ib {
            let removed = self.drop_extents(t, ino, ia, ib)?;
            let mut d = self.inode(t, ino)?;
            let nbytes = le64(&d, ino::NBYTES)?.saturating_sub(removed);
            put64(&mut d, ino::NBYTES, nbytes)?;
            self.stamp(&mut d, true)?;
            self.set_inode(t, ino, &d)?;
        }
        Ok(())
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
pub(crate) struct ExtentInfo {
    /// Bytes of the file it covers.
    pub(crate) len: u64,
    /// For a regular or preallocated extent: its address (0 for a hole),
    /// length on disk, and offset into it. `None` for inline data.
    pub(crate) disk: Option<(u64, u64, u64)>,
}

pub(crate) fn extent_info(d: &[u8]) -> Result<ExtentInfo, Errno> {
    let fe = FileExtent::parse(d)?;
    let disk = match fe.data {
        disk::ExtentData::Inline(_) => None,
        _ => Some((le64(d, 21)?, le64(d, 29)?, le64(d, 37)?)),
    };
    Ok(ExtentInfo { len: fe.len(), disk })
}
