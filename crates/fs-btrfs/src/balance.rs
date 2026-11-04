//! Balance: moving the contents of block groups to other ones and deleting
//! the emptied chunks.
//!
//! A data extent is copied to a new address outside the group (its checksums
//! with it), the file extent items that refer to it are pointed at the copy,
//! and the extent tree's references move to the new extent, all in one
//! transaction. A tree block is moved by copying it on write, which the
//! transaction machinery already does for any block it changes, with the
//! group kept out of the allocator. When nothing is left in a group, one more
//! transaction deletes its block group item, chunk item, device extents and
//! free space entries.
//!
//! Every transaction leaves the volume consistent, so a crash anywhere leaves
//! a volume that checks clean with the group partly emptied, and balancing
//! again carries on. The new copy is written before the transaction that
//! refers to it, into space the committed state calls free.
//!
//! Not moved: system chunks (their items are in the superblock), extents
//! shared through snapshots (shared references, or blocks other subvolumes
//! share), and striped or mirrored chunks (the volume is read-only with them).
//! Such a group is left alone and reported as skipped, `EOPNOTSUPP`.

use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_push, try_zeroed};

use crate::disk::{Key, byte, item, le32, le64, put64, tree};
use crate::space::{carve, kind, super_ranges};
use crate::tree::Cursor;
use crate::write::{DataRef, Tx, Writer, succ};
use crate::{Shared, State, csum};

/// Data copied in one transaction, at most.
const BATCH_BYTES: u64 = 8 << 20;

/// Tree blocks moved in one transaction, at most.
const BATCH_BLOCKS: usize = 32;

/// Bytes copied at a time.
const SLICE: u64 = 1 << 20;

/// Which block groups [`crate::BtrfsFs::balance`] moves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceFilter {
    /// Data block groups.
    pub data: bool,
    /// Metadata block groups.
    pub metadata: bool,
    /// Only groups less than this many percent full; `Some(0)` means only
    /// those with nothing in them.
    pub usage_below: Option<u8>,
    /// Only chunks with a stripe on this device.
    pub devid: Option<u64>,
}

impl Default for BalanceFilter {
    fn default() -> Self {
        BalanceFilter { data: true, metadata: true, usage_below: None, devid: None }
    }
}

/// What [`crate::BtrfsFs::balance`] did.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BalanceReport {
    /// Block groups that matched the filter.
    pub considered: u32,
    /// Groups whose contents were moved out.
    pub relocated: u32,
    /// Chunks deleted.
    pub freed: u32,
    /// Bytes of data and tree blocks copied.
    pub bytes_moved: u64,
    /// Groups emptied but not deleted yet because a reader of an older state
    /// may still read them; balancing again with `usage_below: Some(0)`
    /// deletes them.
    pub busy: Vec<u64>,
    /// Groups left alone, and why.
    pub skipped: Vec<(u64, Errno)>,
}

/// A data extent's reference from a file: root, inode, offset, count.
type FileRef = (u64, u64, u64, u32);

/// The data extents `(address, length)` and tree blocks of a range.
type Extents = (Vec<(u64, u64)>, Vec<u64>);

impl<D: BlockDevice + Send + 'static> Shared<D> {
    /// The checksums of `n` sectors from logical `at`, and which of the
    /// sectors have one (data without checksums is preallocated or belongs to
    /// a `nodatasum` file).
    pub(crate) fn csums_partial(&self, st: &State, at: u64, n: usize) -> Result<(Vec<u8>, Vec<u8>), Errno> {
        let (cs, ss) = (self.csum_size, self.sectorsize);
        let mut sums = try_zeroed(n.checked_mul(cs).ok_or(Errno::EIO)?)?;
        let mut have = try_zeroed(n)?;
        let end = at.checked_add(n as u64 * ss).ok_or(Errno::EIO)?;
        let mut c = Cursor::new(self, &st.chunks, st.csum_tree.ok_or(Errno::EIO)?);
        let ours = |k: &Key| k.objectid == tree::EXTENT_CSUM && k.ty == item::EXTENT_CSUM;
        let key = Key::new(tree::EXTENT_CSUM, item::EXTENT_CSUM, at);
        let mut cur = c.seek_back(key)?;
        if !cur.is_some_and(|(k, _)| ours(&k)) {
            cur = c.seek(key)?;
        }
        while let Some((k, data)) = cur {
            if !ours(&k) || k.offset >= end {
                break;
            }
            let count = (data.len() / cs) as u64;
            let item_end = k.offset.saturating_add(count * ss);
            let (from, to) = (at.max(k.offset), end.min(item_end));
            if from < to && (from - k.offset) % ss == 0 {
                let (first, n_sec) = ((from - k.offset) / ss, ((to - from) / ss) as usize);
                let dst = ((from - at) / ss) as usize;
                let src = data.get(first as usize * cs..(first as usize + n_sec) * cs).ok_or(Errno::EIO)?;
                sums.get_mut(dst * cs..(dst + n_sec) * cs).ok_or(Errno::EIO)?.copy_from_slice(src);
                have.get_mut(dst..dst + n_sec).ok_or(Errno::EIO)?.fill(1);
            }
            cur = c.next()?;
        }
        Ok((sums, have))
    }

    /// Reads the data at logical `at` into `buf`, from copies whose sectors
    /// match the checksums that `have` says exist.
    fn read_checked(&self, st: &State, at: u64, buf: &mut [u8], sums: &[u8], have: &[u8]) -> Result<(), Errno> {
        let (ss, cs, ty) = (self.sectorsize as usize, self.csum_size, self.csum_type);
        let ok = |i: usize, sector: &[u8]| {
            have.get(i).is_none_or(|&h| h == 0)
                || sums.get(i * cs..(i + 1) * cs).is_some_and(|sum| csum::matches(ty, sector, sum))
        };
        let whole = self.read_logical(&st.chunks, at, buf, &mut |off, b| {
            b.chunks(ss).enumerate().all(|(i, s)| ok(off / ss + i, s))
        });
        if whole.is_ok() {
            return Ok(());
        }
        for (i, sector) in buf.chunks_mut(ss).enumerate() {
            let sector_at = at.checked_add((i * ss) as u64).ok_or(Errno::EIO)?;
            self.read_logical(&st.chunks, sector_at, sector, &mut |_, b| ok(i, b))?;
        }
        Ok(())
    }

    /// The data extents `(address, length)` and tree blocks in `start..end`.
    fn list_extents(&self, st: &State, start: u64, end: u64) -> Result<Extents, Errno> {
        let root = self.tree_root(st, tree::EXTENT)?.ok_or(Errno::EIO)?;
        let mut c = Cursor::new(self, &st.chunks, (root.bytenr, root.level));
        let (mut data, mut meta) = (Vec::new(), Vec::new());
        let mut cur = c.seek(Key::new(start, 0, 0))?;
        while let Some((k, d)) = cur {
            if k.objectid >= end {
                break;
            }
            match k.ty {
                item::EXTENT_ITEM if le64(d, 16)? & 1 != 0 => try_push(&mut data, (k.objectid, k.offset))?,
                item::EXTENT_ITEM if le64(d, 16)? & 2 != 0 => try_push(&mut meta, k.objectid)?,
                item::METADATA_ITEM => try_push(&mut meta, k.objectid)?,
                _ => {}
            }
            cur = c.next()?;
        }
        Ok((data, meta))
    }

    /// Moves everything out of the block group at `start` and deletes its
    /// chunk. The writer is locked throughout.
    fn relocate_group(&self, w: &mut Writer, start: u64, rep: &mut BalanceReport) -> Result<(), Errno> {
        let group = w.groups.iter().find(|g| g.start == start).ok_or(Errno::ENOENT)?;
        let end = start + group.len;
        let st = self.state();
        let (data, meta) = self.list_extents(&st, start, end)?;
        drop(st);
        if !data.is_empty() || !meta.is_empty() {
            rep.relocated += 1;
        }

        // Data, a few extents to a transaction.
        let mut next = 0;
        while next < data.len() {
            let from = next;
            let moved = self.transact_locked(w, |tx| {
                try_push(&mut tx.avoid, start)?;
                tx.frees = true;
                let mut moved = 0;
                let mut i = from;
                while let Some(&(bytenr, _)) = data.get(i)
                    && (moved < BATCH_BYTES || i == from)
                {
                    moved += tx.relocate_data(bytenr)?;
                    i += 1;
                }
                Ok((moved, i))
            })?;
            rep.bytes_moved += moved.0;
            next = moved.1;
        }

        // Tree blocks, by copying them on write.
        let mut passes = meta.len() + 1;
        loop {
            let st = self.state();
            let (_, left) = self.list_extents(&st, start, end)?;
            drop(st);
            if left.is_empty() {
                break;
            }
            passes = passes.checked_sub(1).ok_or(Errno::EIO)?;
            let nodesize = self.nodesize as u64;
            let moved = self.transact_locked(w, |tx| {
                try_push(&mut tx.avoid, start)?;
                tx.frees = true;
                let mut moved = 0;
                for &addr in left.iter().take(BATCH_BLOCKS) {
                    if tx.relocate_block(addr)? {
                        moved += nodesize;
                    }
                }
                Ok(moved)
            })?;
            rep.bytes_moved += moved;
        }

        let st = self.state();
        let (data, meta) = self.list_extents(&st, start, end)?;
        drop(st);
        if !data.is_empty() || !meta.is_empty() {
            return Err(Errno::EIO);
        }
        match self.transact_locked(w, |tx| {
            // Nothing new may land in the chunk that is going.
            try_push(&mut tx.avoid, start)?;
            tx.frees = true;
            tx.delete_group(start)
        }) {
            Ok(()) => rep.freed += 1,
            Err(Errno::EBUSY) => try_push(&mut rep.busy, start)?,
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// Moves the contents of the block groups `f` picks. A group that cannot
    /// be moved is reported and left as it was; the others are still tried.
    pub(crate) fn balance(&self, f: &BalanceFilter) -> Result<BalanceReport, Errno> {
        let writer = self.writer.as_ref().ok_or(Errno::EROFS)?;
        let mut rep = BalanceReport::default();
        let mut starts: Vec<u64> = Vec::new();
        {
            let w = writer.lock();
            let st = self.state();
            for g in &w.groups {
                let wanted = (g.flags & kind::DATA != 0 && f.data) || (g.flags & kind::METADATA != 0 && f.metadata);
                let thin = f.usage_below.is_none_or(|p| g.used < (g.len / 100 * p as u64).max(1));
                let on_dev = match f.devid {
                    None => true,
                    Some(id) => st.chunks.find(g.start, 1)?.stripes.iter().any(|s| s.devid == id),
                };
                if wanted && thin && on_dev {
                    try_push(&mut starts, g.start)?;
                }
            }
        }
        rep.considered = starts.len() as u32;
        for start in starts {
            let mut w = writer.lock();
            if w.broken {
                return Err(Errno::EIO);
            }
            match self.relocate_group(&mut w, start, &mut rep) {
                Ok(()) => {}
                Err(Errno::ENOMEM) => return Err(Errno::ENOMEM),
                Err(e) => try_push(&mut rep.skipped, (start, e))?,
            }
        }
        Ok(rep)
    }
}

impl<D: BlockDevice + Send + 'static> Tx<'_, D> {
    /// The references from files to data extent `bytenr`, from its extent
    /// item; `EOPNOTSUPP` if anything else refers to it.
    fn file_refs(&mut self, bytenr: u64, item_data: &[u8]) -> Result<Vec<FileRef>, Errno> {
        let mut refs = Vec::new();
        let mut p = 24;
        while p < item_data.len() {
            if byte(item_data, p)? != item::EXTENT_DATA_REF {
                return Err(Errno::EOPNOTSUPP);
            }
            let count = le32(item_data, p + 25)?;
            try_push(&mut refs, (le64(item_data, p + 1)?, le64(item_data, p + 9)?, le64(item_data, p + 17)?, count))?;
            p += 29;
        }
        let mut at = Key::new(bytenr, item::EXTENT_DATA_REF, 0);
        while let Some((k, d)) = self.next_item(tree::EXTENT, at)? {
            if k.objectid != bytenr {
                break;
            }
            // The block group item of a group starting here ends the references.
            if k.ty >= item::BLOCK_GROUP_ITEM {
                break;
            }
            if k.ty != item::EXTENT_DATA_REF {
                return Err(Errno::EOPNOTSUPP);
            }
            try_push(&mut refs, (le64(&d, 0)?, le64(&d, 8)?, le64(&d, 16)?, le32(&d, 24)?))?;
            at = succ(k).ok_or(Errno::EIO)?;
        }
        Ok(refs)
    }

    /// Points the `count` file extent items of inode `ino` of tree `root`
    /// that refer to `old` (through offset `refoff`) at `new`.
    fn retarget(&mut self, (root, ino, refoff, count): FileRef, old: u64, new: u64) -> Result<(), Errno> {
        let mut found = 0;
        let mut at = Key::new(ino, item::EXTENT_DATA, refoff);
        while found < count {
            let Some((k, mut d)) = self.next_item(root, at)? else { break };
            if k.objectid != ino || k.ty != item::EXTENT_DATA {
                break;
            }
            // A regular or preallocated extent of `old`, by the offset that
            // makes it this reference.
            if byte(&d, 20).is_ok_and(|t| t == 1 || t == 2)
                && le64(&d, 21)? == old
                && k.offset.wrapping_sub(le64(&d, 37)?) == refoff
            {
                put64(&mut d, 21, new)?;
                self.update(root, k, &d)?;
                found += 1;
            }
            at = succ(k).ok_or(Errno::EIO)?;
        }
        if found != count {
            return Err(Errno::EIO);
        }
        Ok(())
    }

    /// Copies data extent `bytenr` to a new address outside the groups being
    /// emptied, with its checksums, and moves its references there. Returns
    /// the bytes copied (0 if the extent is no longer there).
    pub(crate) fn relocate_data(&mut self, bytenr: u64) -> Result<u64, Errno> {
        let Some((k, d)) = self
            .next_item(tree::EXTENT, Key::new(bytenr, item::EXTENT_ITEM, 0))?
            .filter(|(k, _)| k.objectid == bytenr && k.ty == item::EXTENT_ITEM)
        else {
            return Ok(0);
        };
        let len = k.offset;
        let (ss, cs) = (self.sh.sectorsize, self.sh.csum_size);
        if le64(&d, 16)? & 1 == 0 || len == 0 || !len.is_multiple_of(ss) || !bytenr.is_multiple_of(ss) {
            return Err(Errno::EIO);
        }
        let refs = self.file_refs(bytenr, &d)?;
        // A tree that has been snapshotted shares leaves with its snapshots,
        // and the extents they hold: moving those needs every sharer changed.
        for r in &refs {
            if self.root(r.0)?.last_snapshot != 0 {
                return Err(Errno::EOPNOTSUPP);
            }
        }
        let total: u64 = refs.iter().map(|r| r.3 as u64).sum();
        if total != le64(&d, 0)? || refs.is_empty() {
            return Err(Errno::EIO);
        }
        let base = self.base.clone();
        let sectors = (len / ss) as usize;
        let (sums, have) = self.sh.csums_partial(&base, bytenr, sectors)?;

        let new = self.alloc_data_exact(len)?;
        let mut off = 0;
        while off < len {
            let n = (len - off).min(SLICE);
            let mut buf = try_zeroed(n as usize)?;
            let (first, count) = ((off / ss) as usize, (n / ss) as usize);
            let (s, h) = (
                sums.get(first * cs..(first + count) * cs).ok_or(Errno::EIO)?,
                have.get(first..first + count).ok_or(Errno::EIO)?,
            );
            self.sh.read_checked(&base, bytenr + off, &mut buf, s, h)?;
            self.sh.write_logical(self.chunks(), new + off, &buf)?;
            off += n;
        }
        // The checksums, for the runs of sectors that have them.
        let mut i = 0;
        while i < sectors {
            if have.get(i) != Some(&1) {
                i += 1;
                continue;
            }
            let j = (i..sectors).find(|&j| have.get(j) != Some(&1)).unwrap_or(sectors);
            let run = sums.get(i * cs..j * cs).ok_or(Errno::EIO)?;
            self.csum_insert(new + i as u64 * ss, run)?;
            i = j;
        }
        for &r in &refs {
            self.retarget(r, bytenr, new)?;
            let (root, ino, offset, count) = r;
            let delta = count as i64;
            try_push(
                &mut self.data_refs,
                DataRef { bytenr: new, len, root, ino, offset, parent: 0, delta, new: true },
            )?;
            try_push(
                &mut self.data_refs,
                DataRef { bytenr, len, root, ino, offset, parent: 0, delta: -delta, new: false },
            )?;
        }
        Ok(len)
    }

    /// Moves tree block `addr` by copying it, and the blocks above it, on
    /// write. `false` if this transaction has moved it already.
    pub(crate) fn relocate_block(&mut self, addr: u64) -> Result<bool, Errno> {
        if self.pinned.iter().any(|p| p.0 == addr) {
            return Ok(false);
        }
        let (owner, first, generation) = {
            let n = self.load(addr)?;
            (n.owner, n.first_key(), n.generation)
        };
        // A block a snapshot may share cannot be moved for one tree alone.
        if self.root(owner)?.last_snapshot >= generation && self.root(owner)?.last_snapshot != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        self.path(owner, first.unwrap_or(Key::new(0, 0, 0)), 0)?;
        Ok(true)
    }

    /// Deletes the (empty) block group at `start` with its chunk: the items
    /// that describe it and the device space it held. `EBUSY` if a reader of
    /// an older state may still read what was in it, or if it is the last
    /// group of its type; `EOPNOTSUPP` for a system group.
    pub(crate) fn delete_group(&mut self, start: u64) -> Result<(), Errno> {
        let g = self.w.groups.iter().find(|g| g.start == start).ok_or(Errno::ENOENT)?;
        let (len, flags) = (g.len, g.flags);
        if flags & kind::SYSTEM != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        if !self.w.groups.iter().any(|o| o.start != start && o.flags & kind::MASK == flags & kind::MASK) {
            return Err(Errno::EBUSY);
        }
        // Everything free but the superblock copies, none still in limbo.
        let chunk = self.chunks().find(start, 1)?;
        let mut want = Vec::new();
        try_push(&mut want, (start, len))?;
        for (s, l) in super_ranges(chunk) {
            carve(&mut want, s, l)?;
        }
        if g.used != 0 || g.free != want {
            return Err(Errno::EBUSY);
        }
        let mut stripes = Vec::new();
        for s in &chunk.stripes {
            try_push(&mut stripes, (s.devid, s.offset))?;
        }
        let bg_tree = self.w.bg_tree;
        self.delete(bg_tree, Key::new(start, item::BLOCK_GROUP_ITEM, len))?;
        self.delete(tree::CHUNK, Key::new(tree::FIRST_CHUNK, item::CHUNK_ITEM, start))?;
        for (devid, off) in stripes {
            self.delete(tree::DEV, Key::new(devid, item::DEV_EXTENT, off))?;
            let key = Key::new(1, item::DEV_ITEM, devid);
            let mut di = self.find(tree::CHUNK, key)?.ok_or(Errno::EIO)?;
            let used = le64(&di, 16)?.checked_sub(len).ok_or(Errno::EIO)?;
            put64(&mut di, 16, used)?;
            self.update(tree::CHUNK, key, &di)?;
        }
        if self.w.fst {
            let mut at = Key::new(start, 0, 0);
            while let Some((k, _)) = self.next_item(tree::FREE_SPACE, at)? {
                if k.objectid >= start + len {
                    break;
                }
                self.delete(tree::FREE_SPACE, k)?;
                at = succ(k).ok_or(Errno::EIO)?;
            }
        }
        let mut map = match self.new_chunks.take() {
            Some(m) => m,
            None => self.base.chunks.try_clone()?,
        };
        map.remove(start);
        self.new_chunks = Some(map);
        try_push(&mut self.dropped_groups, start)?;
        Ok(())
    }
}
