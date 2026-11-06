// SPDX-License-Identifier: GPL-2.0-only
//! Replaying the fsync log.
//!
//! `fsync` on Linux does not commit a transaction: it writes the inodes it
//! needs to a log tree per subvolume, points the superblock's `log_root` at
//! the tree of those roots, and returns. A crash leaves the volume as the
//! last commit made it plus that log. Mounting replays the log into the
//! subvolume trees, in one transaction whose superblock also clears
//! `log_root`.
//!
//! The log holds, per inode: the inode item, its names (`INODE_REF` and
//! `INODE_EXTREF`), the directory entries logged (`DIR_INDEX`) with the index
//! ranges that were logged completely (`DIR_LOG_INDEX`, so that an entry in a
//! range but not in the log was deleted), extended attributes and file
//! extents; and under `EXTENT_CSUM` the checksums of the data those extents
//! point to. Replay goes in Linux's order: every inode item first, then
//! directory entries, then names, file extents and attributes. Whatever
//! derives from the items (link counts, directory sizes, `nbytes`) is then
//! counted again for the inodes touched rather than taken from the log. Data
//! extents the log points to that the extent tree does not know yet (they
//! were allocated by the transaction that never committed) are allocated
//! here.
//!
//! A log this does not understand is an error, and the volume is then
//! mounted read-only with the log left alone.

use alloc::vec::Vec;

use osmium_fs::{Errno, FileKind};
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::try_to_vec;

use crate::csum;
use crate::disk::{self, FileExtent, Key, bytes, item, le16, le32, le64, put64, tree};
use crate::ops::{entries, entry, extref_hash, ft_of, ino, with, without};
use crate::space::kind;
use crate::write::{Tx, succ};

/// A directory range logged completely: the first index is the key offset.
const DIR_LOG_INDEX: u8 = 72;

/// `S_IFMT` and the file types replay needs.
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;

/// Items of a log tree, in key order.
pub(crate) type Items = Vec<(Key, Vec<u8>)>;

/// One subvolume's log tree.
pub(crate) struct LogTree {
    /// The subvolume.
    pub id: u64,
    /// Its items.
    pub items: Items,
}

/// Inodes whose derived fields are to be counted again.
#[derive(Default)]
struct Touched {
    /// Names may have changed: link count.
    links: Vec<u64>,
    /// Entries may have changed (directories): size.
    dirs: Vec<u64>,
    /// Extents may have changed (files): `nbytes`.
    data: Vec<u64>,
    /// Inodes the log has nothing to say about (it holds them unlinked).
    ignored: Vec<u64>,
}

fn add(v: &mut Vec<u64>, x: u64) -> Result<(), Errno> {
    if let Err(at) = v.binary_search(&x) {
        v.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        v.insert(at, x);
    }
    Ok(())
}

/// The items of `items` from `from` to `to`.
fn span(items: &[(Key, Vec<u8>)], from: Key, to: Key) -> &[(Key, Vec<u8>)] {
    let a = items.partition_point(|i| i.0 < from);
    let b = items.partition_point(|i| i.0 <= to);
    items.get(a..b).unwrap_or(&[])
}

/// The data of item `key` in `items`.
fn find_in(items: &[(Key, Vec<u8>)], key: Key) -> Option<&[u8]> {
    let i = items.binary_search_by_key(&key, |i| i.0).ok()?;
    items.get(i).map(|i| i.1.as_slice())
}

/// The name of the (only) entry in the directory item `d`.
fn entry_name(d: &[u8]) -> Result<&[u8], Errno> {
    let nl = le16(d, 27)? as usize;
    bytes(d, 30, nl)
}

/// Whether directory items `a` and `b` name the same thing.
fn same_entry(a: &[u8], b: &[u8]) -> Result<bool, Errno> {
    Ok(a.get(..Key::SIZE) == b.get(..Key::SIZE) && entry_name(a)? == entry_name(b)?)
}

/// The names in an `INODE_REF` or `INODE_EXTREF` item: parent, index, name.
fn refs_in(k: &Key, d: &[u8]) -> Result<Vec<(u64, u64, Vec<u8>)>, Errno> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < d.len() {
        let (parent, idx, nl, at) = if k.ty == item::INODE_REF {
            (k.offset, le64(d, p)?, le16(d, p + 8)? as usize, p + 10)
        } else {
            (le64(d, p)?, le64(d, p + 8)?, le16(d, p + 16)? as usize, p + 18)
        };
        let name = try_to_vec(bytes(d, at, nl)?)?;
        out.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        out.push((parent, idx, name));
        p = at + nl;
    }
    Ok(out)
}

impl<D: BlockDevice + Send + 'static> Tx<'_, D> {
    /// Replays the log trees `logs` into their subvolumes.
    pub(crate) fn replay_log(&mut self, logs: &[LogTree]) -> Result<(), Errno> {
        // The superblock is written even if the log changes nothing.
        self.force = true;
        for log in logs {
            self.replay_tree(log)?;
        }
        Ok(())
    }

    fn replay_tree(&mut self, log: &LogTree) -> Result<(), Errno> {
        let t = log.id;
        let items = log.items.as_slice();
        let mut tc = Touched::default();

        // The inodes the log mentions, and nothing it could mean but what is known.
        let mut inodes: Vec<u64> = Vec::new();
        for (k, _) in items {
            if k.objectid == tree::EXTENT_CSUM {
                if k.ty != item::EXTENT_CSUM {
                    return Err(Errno::EOPNOTSUPP);
                }
                continue;
            }
            let known = [
                item::INODE_ITEM,
                item::INODE_REF,
                item::INODE_EXTREF,
                item::XATTR_ITEM,
                DIR_LOG_INDEX,
                item::DIR_ITEM,
                item::DIR_INDEX,
                item::EXTENT_DATA,
            ];
            if !(tree::FIRST_FREE..=tree::LAST_FREE).contains(&k.objectid) || !known.contains(&k.ty) {
                return Err(Errno::EOPNOTSUPP);
            }
            if inodes.last() != Some(&k.objectid) {
                inodes.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                inodes.push(k.objectid);
            }
        }
        let csums = span(
            items,
            Key::new(tree::EXTENT_CSUM, item::EXTENT_CSUM, 0),
            Key::new(tree::EXTENT_CSUM, item::EXTENT_CSUM, u64::MAX),
        );
        let of = |ino: u64| span(items, Key::new(ino, 0, 0), Key::new(ino, u8::MAX, u64::MAX));

        // Inode items, with the entries and attributes they supersede.
        for &n in &inodes {
            let r = of(n);
            if let Some(d) = find_in(r, Key::new(n, item::INODE_ITEM, 0)) {
                self.replay_inode(t, n, d, r, &mut tc)?;
            }
        }
        // Directory entries.
        for &n in &inodes {
            if tc.ignored.contains(&n) {
                continue;
            }
            let r = of(n);
            for (k, d) in span(r, Key::new(n, item::DIR_INDEX, 0), Key::new(n, item::DIR_INDEX, u64::MAX)) {
                self.ensure_link(t, n, k.offset, d, &mut tc)?;
            }
        }
        // Names, extents and attributes.
        for &n in &inodes {
            if tc.ignored.contains(&n) {
                continue;
            }
            let r = of(n);
            self.replay_refs(t, n, r, &mut tc)?;
            for (k, d) in span(r, Key::new(n, item::EXTENT_DATA, 0), Key::new(n, item::EXTENT_DATA, u64::MAX)) {
                self.replay_extent(t, n, k.offset, d, csums, &mut tc)?;
            }
            for (k, d) in span(r, Key::new(n, item::XATTR_ITEM, 0), Key::new(n, item::XATTR_ITEM, u64::MAX)) {
                if self.find(t, Key::new(n, item::INODE_ITEM, 0))?.is_some() {
                    self.put(t, *k, d)?;
                }
            }
        }

        // Counted again, not copied.
        for &n in &tc.links {
            self.fix_links(t, n)?;
        }
        for &n in &tc.data {
            self.fix_nbytes(t, n)?;
        }
        for &n in &tc.dirs {
            self.fix_dir_size(t, n)?;
        }
        Ok(())
    }

    /// Replays inode item `log_ino` of `n`; `r` are the log's items of `n`.
    fn replay_inode(
        &mut self,
        t: u64,
        n: u64,
        log_ino: &[u8],
        r: &[(Key, Vec<u8>)],
        tc: &mut Touched,
    ) -> Result<(), Errno> {
        if log_ino.len() != ino::LEN {
            return Err(Errno::EIO);
        }
        // An inode logged without links (an `O_TMPFILE`) is not replayed.
        if le32(log_ino, ino::NLINK)? == 0 {
            return add(&mut tc.ignored, n);
        }
        let key = Key::new(n, item::INODE_ITEM, 0);
        let mode = le32(log_ino, ino::MODE)?;
        let size = le64(log_ino, ino::SIZE)?;
        // Generation 0: logged only to say that the inode exists.
        let exists_only = le64(log_ino, ino::GENERATION)? == 0;
        match self.find(t, key)? {
            None => {
                self.insert(t, key, log_ino)?;
                add(&mut tc.data, n)?;
            }
            Some(mut cur) => {
                if le32(&cur, ino::MODE)? & S_IFMT != mode & S_IFMT {
                    return Err(Errno::EOPNOTSUPP);
                }
                // The ranges the log covers say which entries are gone, however much of the inode it holds.
                if mode & S_IFMT == S_IFDIR {
                    self.replay_dir_deletes(t, n, r, tc)?;
                }
                if exists_only {
                    // Nothing but a size, and not one that says "unknown".
                    if mode & S_IFMT == S_IFREG && size != 0 && le64(&cur, ino::SIZE)? != size {
                        put64(&mut cur, ino::SIZE, size)?;
                        self.update(t, key, &cur)?;
                    }
                } else {
                    self.replay_xattr_deletes(t, n, r)?;
                    self.update(t, key, log_ino)?;
                    // The log leaves `nbytes` for replay to count.
                    add(&mut tc.data, n)?;
                    cur = try_to_vec(log_ino)?;
                }
                if mode & S_IFMT == S_IFREG {
                    // Extents past the end the file has now (preallocated ones, say) go before the logged ones come.
                    let keep = le64(&cur, ino::SIZE)?.checked_next_multiple_of(self.sh.sectorsize).ok_or(Errno::EIO)?;
                    if self.drop_extents(t, n, keep, u64::MAX)? != 0 {
                        add(&mut tc.data, n)?;
                    }
                }
            }
        }
        add(&mut tc.links, n)
    }

    /// Removes the attributes of `n` that the log, which holds all of them, does not.
    fn replay_xattr_deletes(&mut self, t: u64, n: u64, r: &[(Key, Vec<u8>)]) -> Result<(), Errno> {
        let mut at = Key::new(n, item::XATTR_ITEM, 0);
        while let Some((k, _)) = self.next_item(t, at)? {
            if k.objectid != n || k.ty != item::XATTR_ITEM {
                break;
            }
            if find_in(r, k).is_none() {
                self.delete(t, k)?;
            }
            at = succ(k).ok_or(Errno::EIO)?;
        }
        Ok(())
    }

    /// Removes the entries of directory `dir` that lie in a range the log
    /// covers completely and do not appear in it.
    fn replay_dir_deletes(&mut self, t: u64, dir: u64, r: &[(Key, Vec<u8>)], tc: &mut Touched) -> Result<(), Errno> {
        for (k, d) in span(r, Key::new(dir, DIR_LOG_INDEX, 0), Key::new(dir, DIR_LOG_INDEX, u64::MAX)) {
            let end = le64(d, 0)?;
            let mut at = Key::new(dir, item::DIR_INDEX, k.offset);
            while let Some((fk, fd)) = self.next_item(t, at)? {
                if fk.objectid != dir || fk.ty != item::DIR_INDEX || fk.offset > end {
                    break;
                }
                let kept = match find_in(r, fk) {
                    Some(ld) => same_entry(ld, &fd)?,
                    None => false,
                };
                if !kept {
                    self.drop_entry(t, dir, Some(fk.offset), &fd, tc)?;
                }
                at = succ(fk).ok_or(Errno::EIO)?;
            }
        }
        Ok(())
    }

    /// The index at which `n` is called `name` in `dir`, if it is.
    fn ref_find(&mut self, t: u64, n: u64, dir: u64, name: &[u8]) -> Result<Option<u64>, Errno> {
        if let Some(d) = self.find(t, Key::new(n, item::INODE_REF, dir))? {
            for (parent, idx, nm) in refs_in(&Key::new(n, item::INODE_REF, dir), &d)? {
                if parent == dir && nm == name {
                    return Ok(Some(idx));
                }
            }
        }
        let k = Key::new(n, item::INODE_EXTREF, extref_hash(dir, name));
        if let Some(d) = self.find(t, k)? {
            for (parent, idx, nm) in refs_in(&k, &d)? {
                if parent == dir && nm == name {
                    return Ok(Some(idx));
                }
            }
        }
        Ok(None)
    }

    /// Takes the directory entry `ent` of `dir` (at index `idx`, if known) out, and the name from the inode it
    /// names.
    fn drop_entry(&mut self, t: u64, dir: u64, idx: Option<u64>, ent: &[u8], tc: &mut Touched) -> Result<(), Errno> {
        let loc = Key::parse(ent, 0)?;
        if loc.ty != item::INODE_ITEM {
            // A subvolume.
            return Err(Errno::EOPNOTSUPP);
        }
        let name = entry_name(ent)?;
        if let Some(i) = idx {
            let k = Key::new(dir, item::DIR_INDEX, i);
            if self.find(t, k)?.is_some() {
                self.delete(t, k)?;
            }
        }
        let hk = Key::new(dir, item::DIR_ITEM, csum::name_hash(name));
        if let Some(d) = self.find(t, hk)?
            && let Some((from, to, _)) = entries(&d)?.into_iter().find(|e| e.2 == name)
        {
            if to - from == d.len() {
                self.delete(t, hk)?;
            } else {
                self.update(t, hk, &without(&d, from, to)?)?;
            }
        }
        if self.ref_find(t, loc.objectid, dir, name)?.is_some() {
            self.inode_ref_del(t, loc.objectid, dir, name)?;
        }
        add(&mut tc.dirs, dir)?;
        add(&mut tc.links, loc.objectid)
    }

    /// Makes `dir` hold the entry `ent` at index `idx`, with its name in the
    /// `DIR_ITEM` and in the target's references, replacing what is in the
    /// way. Does nothing if the directory or the target is not there.
    fn ensure_link(&mut self, t: u64, dir: u64, idx: u64, ent: &[u8], tc: &mut Touched) -> Result<(), Errno> {
        if entries(ent)?.len() != 1 {
            return Err(Errno::EIO);
        }
        let loc = Key::parse(ent, 0)?;
        if loc.ty != item::INODE_ITEM {
            return Err(Errno::EOPNOTSUPP);
        }
        let name = entry_name(ent)?;
        let target = loc.objectid;
        if self.find(t, Key::new(dir, item::INODE_ITEM, 0))?.is_none()
            || self.find(t, Key::new(target, item::INODE_ITEM, 0))?.is_none()
        {
            return Ok(());
        }
        // Something else at this index goes.
        let ik = Key::new(dir, item::DIR_INDEX, idx);
        if let Some(old) = self.find(t, ik)?
            && !same_entry(&old, ent)?
        {
            self.drop_entry(t, dir, Some(idx), &old, tc)?;
        }
        // So does the name, if it is somewhere else or points elsewhere.
        if let Some((old_loc, ft)) = self.dir_lookup(t, dir, name)? {
            let at = if old_loc.ty == item::INODE_ITEM { self.ref_find(t, old_loc.objectid, dir, name)? } else { None };
            if old_loc != loc || at != Some(idx) {
                let old = entry(old_loc, self.transid, name, &[], ft)?;
                self.drop_entry(t, dir, at, &old, tc)?;
            }
        }
        if self.find(t, ik)?.is_none() {
            self.insert(t, ik, ent)?;
        }
        let hk = Key::new(dir, item::DIR_ITEM, csum::name_hash(name));
        match self.find(t, hk)? {
            Some(d) => {
                if !entries(&d)?.iter().any(|e| e.2 == name) {
                    self.update(t, hk, &with(&d, ent)?)?;
                }
            }
            None => self.insert(t, hk, ent)?,
        }
        match self.ref_find(t, target, dir, name)? {
            Some(i) if i == idx => {}
            Some(_) => {
                self.inode_ref_del(t, target, dir, name)?;
                self.inode_ref_add(t, target, dir, idx, name)?;
            }
            None => self.inode_ref_add(t, target, dir, idx, name)?,
        }
        add(&mut tc.dirs, dir)?;
        add(&mut tc.links, target)
    }

    /// Replays the names of `n` in the log.
    fn replay_refs(&mut self, t: u64, n: u64, r: &[(Key, Vec<u8>)], tc: &mut Touched) -> Result<(), Errno> {
        let all = span(r, Key::new(n, item::INODE_REF, 0), Key::new(n, item::INODE_EXTREF, u64::MAX));
        if all.is_empty() {
            return Ok(());
        }
        let Some(cur) = self.find(t, Key::new(n, item::INODE_ITEM, 0))? else { return Ok(()) };
        let ft = ft_of(crate::kind_of(le32(&cur, ino::MODE)?).ok_or(Errno::EIO)?);
        let full = find_in(r, Key::new(n, item::INODE_ITEM, 0))
            .is_some_and(|d| le64(d, ino::GENERATION).is_ok_and(|g| g != 0));
        let mut logged: Vec<(u64, u64, Vec<u8>)> = Vec::new();
        for (k, d) in all {
            for rf in refs_in(k, d)? {
                logged.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                logged.push(rf);
            }
        }
        for (parent, idx, name) in &logged {
            // Index 0 is the root directory's `..`, which has no entries.
            if *idx == 0 {
                continue;
            }
            let ent = entry(Key::new(n, item::INODE_ITEM, 0), self.transid, name, &[], ft)?;
            self.ensure_link(t, *parent, *idx, &ent, tc)?;
        }
        if !full {
            return Ok(());
        }
        // An inode logged whole has the names it has now; the others in the
        // parents it names are gone.
        for (parent, _, _) in &logged {
            let k = Key::new(n, item::INODE_REF, *parent);
            let Some(d) = self.find(t, k)? else { continue };
            for (p, idx, name) in refs_in(&k, &d)? {
                if !logged.iter().any(|l| l.0 == p && l.2 == name) {
                    let ent = entry(Key::new(n, item::INODE_ITEM, 0), self.transid, &name, &[], ft)?;
                    self.drop_entry(t, p, Some(idx), &ent, tc)?;
                }
            }
        }
        Ok(())
    }

    /// Replays the file extent item `d` at `off` of `n`.
    fn replay_extent(
        &mut self,
        t: u64,
        n: u64,
        off: u64,
        d: &[u8],
        csums: &[(Key, Vec<u8>)],
        tc: &mut Touched,
    ) -> Result<(), Errno> {
        let Some(cur) = self.find(t, Key::new(n, item::INODE_ITEM, 0))? else { return Ok(()) };
        let key = Key::new(n, item::EXTENT_DATA, off);
        if self.find(t, key)?.as_deref() == Some(d) {
            return Ok(());
        }
        let (ss, cs) = (self.sh.sectorsize, self.sh.csum_size);
        let fe = FileExtent::parse(d)?;
        let len = fe.len();
        let mut end = off.checked_add(len).ok_or(Errno::EIO)?;
        if len == 0 {
            return Err(Errno::EIO);
        }
        let ty = disk::byte(d, 20)?;
        if ty == 0 {
            end = end.checked_next_multiple_of(ss).ok_or(Errno::EIO)?;
        }
        self.drop_extents(t, n, off, end)?;
        self.insert(t, key, d)?;
        add(&mut tc.data, n)?;
        if ty == 0 {
            return Ok(());
        }
        let (bytenr, disk_len, eoff) = (le64(d, 21)?, le64(d, 29)?, le64(d, 37)?);
        if bytenr == 0 {
            return Ok(());
        }
        if bytenr % ss != 0 || disk_len == 0 || disk_len % ss != 0 || bytenr.checked_add(disk_len).is_none() {
            return Err(Errno::EIO);
        }
        // Allocated by the transaction that never committed, or not. An
        // extent that overlaps one met already without being the same (start
        // and length) is not something Linux logs: not replayed.
        let end = bytenr + disk_len;
        let overlap = |s: u64, l: u64| s < end && bytenr < s.saturating_add(l) && (s, l) != (bytenr, disk_len);
        if self.data_refs.iter().any(|r| overlap(r.bytenr, r.len)) {
            return Err(Errno::EOPNOTSUPP);
        }
        let seen = self.data_refs.iter().any(|r| r.bytenr == bytenr);
        let new = if seen {
            self.data_refs.iter().any(|r| r.bytenr == bytenr && r.new)
        } else if self.find(tree::EXTENT, Key::new(bytenr, item::EXTENT_ITEM, disk_len))?.is_some() {
            false
        } else {
            let g = self.w.group_mut(bytenr).ok_or(Errno::EIO)?;
            if g.flags & kind::MASK != kind::DATA || end > g.start.saturating_add(g.len) {
                return Err(Errno::EIO);
            }
            self.claim(bytenr, disk_len)?;
            true
        };
        self.data_ref(bytenr, disk_len, t, n, off.wrapping_sub(eoff), 1, new)?;

        // Checksums, from the log, over the part of the extent this item uses.
        if ty != 1 || le64(&cur, ino::FLAGS)? & disk::INODE_NODATASUM != 0 {
            return Ok(());
        }
        let (from, to) = if fe.compression == disk::compress::NONE {
            (bytenr.checked_add(eoff).ok_or(Errno::EIO)?, bytenr.saturating_add(eoff).saturating_add(le64(d, 45)?))
        } else {
            (bytenr, end)
        };
        let (from, to) = (from & !(ss - 1), to.checked_next_multiple_of(ss).ok_or(Errno::EIO)?);
        let mut i = csums.partition_point(|c| c.0.offset <= from).saturating_sub(1);
        while let Some((ck, cd)) = csums.get(i) {
            i += 1;
            if ck.offset >= to {
                break;
            }
            let cend = ck.offset.saturating_add((cd.len() / cs) as u64 * ss);
            let (lo, hi) = (ck.offset.max(from), cend.min(to));
            if lo >= hi {
                continue;
            }
            let a = ((lo - ck.offset) / ss) as usize * cs;
            let b = ((hi - ck.offset) / ss) as usize * cs;
            let sums = cd.get(a..b).ok_or(Errno::EIO)?;
            self.csum_delete(lo, hi - lo)?;
            self.csum_insert(lo, sums)?;
        }
        Ok(())
    }

    /// Sets the link count of `n` to the names it has; an inode with none is deleted.
    fn fix_links(&mut self, t: u64, n: u64) -> Result<(), Errno> {
        let key = Key::new(n, item::INODE_ITEM, 0);
        let Some(mut cur) = self.find(t, key)? else { return Ok(()) };
        let is_dir = le32(&cur, ino::MODE)? & S_IFMT == S_IFDIR;
        let mut count = 0u64;
        for ty in [item::INODE_REF, item::INODE_EXTREF] {
            let mut at = Key::new(n, ty, 0);
            while let Some((k, d)) = self.next_item(t, at)? {
                if k.objectid != n || k.ty != ty {
                    break;
                }
                count += refs_in(&k, &d)?.len() as u64;
                at = succ(k).ok_or(Errno::EIO)?;
            }
        }
        if count == 0 {
            return self.delete_inode(t, n);
        }
        if is_dir {
            // A directory has one link however many names (one) it has.
            return Ok(());
        }
        let count = u32::try_from(count).map_err(|_| Errno::EIO)?;
        if le32(&cur, ino::NLINK)? != count {
            disk::put32(&mut cur, ino::NLINK, count)?;
            self.update(t, key, &cur)?;
        }
        Ok(())
    }

    /// Sets `nbytes` of file `n` to the bytes its extents hold.
    fn fix_nbytes(&mut self, t: u64, n: u64) -> Result<(), Errno> {
        let key = Key::new(n, item::INODE_ITEM, 0);
        let Some(mut cur) = self.find(t, key)? else { return Ok(()) };
        if crate::kind_of(le32(&cur, ino::MODE)?).is_none_or(|k| k == FileKind::Directory) {
            return Ok(());
        }
        let mut total = 0u64;
        let mut at = Key::new(n, item::EXTENT_DATA, 0);
        while let Some((k, d)) = self.next_item(t, at)? {
            if k.objectid != n || k.ty != item::EXTENT_DATA {
                break;
            }
            let fe = FileExtent::parse(&d)?;
            let held = match fe.data {
                disk::ExtentData::Inline(_) => fe.len(),
                _ if le64(&d, 21)? == 0 => 0,
                _ => fe.len(),
            };
            total = total.checked_add(held).ok_or(Errno::EIO)?;
            at = succ(k).ok_or(Errno::EIO)?;
        }
        if le64(&cur, ino::NBYTES)? != total {
            put64(&mut cur, ino::NBYTES, total)?;
            self.update(t, key, &cur)?;
        }
        Ok(())
    }

    /// Sets the size of directory `n` to twice the length of its names.
    fn fix_dir_size(&mut self, t: u64, n: u64) -> Result<(), Errno> {
        let key = Key::new(n, item::INODE_ITEM, 0);
        let Some(mut cur) = self.find(t, key)? else { return Ok(()) };
        if le32(&cur, ino::MODE)? & S_IFMT != S_IFDIR {
            return Ok(());
        }
        let mut total = 0u64;
        let mut at = Key::new(n, item::DIR_INDEX, 0);
        while let Some((k, d)) = self.next_item(t, at)? {
            if k.objectid != n || k.ty != item::DIR_INDEX {
                break;
            }
            for e in entries(&d)? {
                total = total.checked_add(2 * e.2.len() as u64).ok_or(Errno::EIO)?;
            }
            at = succ(k).ok_or(Errno::EIO)?;
        }
        if le64(&cur, ino::SIZE)? != total {
            put64(&mut cur, ino::SIZE, total)?;
            self.update(t, key, &cur)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::BtrfsFs;
    use alloc::sync::Arc;
    use alloc::vec;
    use osmium_hal::block::BlockError;
    use std::os::unix::fs::FileExt;
    use std::path::Path;
    use std::process::Command;

    #[derive(Clone)]
    struct FileDisk(Arc<std::fs::File>, u64);

    impl BlockDevice for FileDisk {
        fn block_size(&self) -> usize {
            4096
        }
        fn num_blocks(&self) -> u64 {
            self.1 / 4096
        }
        fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            self.check_range(lba, buf.len())?;
            self.0.read_exact_at(buf, lba * 4096).map_err(|_| BlockError::Io)
        }
        fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
            self.check_range(lba, buf.len())?;
            self.0.write_all_at(buf, lba * 4096).map_err(|_| BlockError::Io)
        }
    }

    /// A regular file extent item: `len` bytes of the extent at `bytenr` of `disk_len`.
    fn extent(bytenr: u64, disk_len: u64, len: u64) -> Vec<u8> {
        let mut d = vec![0u8; 53];
        d[8..16].copy_from_slice(&disk_len.to_le_bytes());
        d[20] = 1;
        d[21..29].copy_from_slice(&bytenr.to_le_bytes());
        d[29..37].copy_from_slice(&disk_len.to_le_bytes());
        d[45..53].copy_from_slice(&len.to_le_bytes());
        d
    }

    /// Log extents that overlap without being the same extent are not
    /// replayed: `EOPNOTSUPP` (a log this does not understand), not `EIO`.
    #[test]
    fn overlapping_log_extents() {
        let Some(mkfs) = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
            .iter()
            .map(|d| Path::new(d).join("mkfs.btrfs"))
            .find(|p| p.exists())
        else {
            std::eprintln!("mkfs.btrfs not found; skipping");
            return;
        };
        let dir = std::env::temp_dir().join(std::format!("osmium-fs-btrfs-replay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/f"), b"a file").unwrap();
        let img = dir.join("img");
        std::fs::File::create(&img).unwrap().set_len(128 << 20).unwrap();
        let ok = Command::new(mkfs).args(["-q", "--rootdir"]).arg(dir.join("src")).arg(&img).status().unwrap();
        assert!(ok.success());
        let file = std::fs::OpenOptions::new().read(true).write(true).open(&img).unwrap();
        let len = file.metadata().unwrap().len();
        let fs = BtrfsFs::mount(FileDisk(Arc::new(file), len), 1).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        // Two extents of 8 KiB in free data space 4 KiB apart, or two at the
        // same start of different lengths.
        for second in [4096, 0] {
            let r = fs.shared.transact(|tx| {
                let g = tx.w.groups.iter().find(|g| g.flags & kind::MASK == kind::DATA).ok_or(Errno::ENOSPC)?;
                let &(at, _) = g.free.iter().find(|r| r.1 >= 1 << 20).ok_or(Errno::ENOSPC)?;
                let ino = tree::FIRST_FREE + 1;
                assert!(tx.find(tree::FS, Key::new(ino, item::INODE_ITEM, 0))?.is_some());
                let items = vec![
                    (Key::new(ino, item::EXTENT_DATA, 0), extent(at, 8192, 8192)),
                    (Key::new(ino, item::EXTENT_DATA, 8192), extent(at + second, 4096 << (second / 4096), 4096)),
                ];
                tx.replay_log(&[LogTree { id: tree::FS, items }])
            });
            assert_eq!(r.err(), Some(Errno::EOPNOTSUPP), "second extent at +{second}");
        }
    }
}
