// SPDX-License-Identifier: GPL-2.0-only
//! Committing a transaction: the extent tree, data checksums, block groups,
//! the free space tree and root items brought up to date, then the new
//! blocks written, then the superblock.

use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_arc, try_push, try_to_vec};

use crate::csum;
use crate::disk::{Key, byte, incompat, item, le32, le64, put32, put64, tree};
use crate::node::ITEM;
use crate::write::{MAX_ROUNDS, Tx, succ};
use crate::{State, disk};

/// Merges sorted-or-not ranges into sorted, non-touching ones.
fn normalize(v: &mut Vec<(u64, u64)>) {
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    // Merging only ever shrinks the list, so this reuses `v`'s memory.
    for &(s, l) in v.iter() {
        if l == 0 {
            continue;
        }
        match out.last_mut() {
            Some(last) if last.0.saturating_add(last.1) >= s => last.1 = last.1.max(s.saturating_add(l) - last.0),
            _ => {
                if out.try_reserve(1).is_err() {
                    return;
                }
                out.push((s, l));
            }
        }
    }
    *v = out;
}

impl<D: BlockDevice + Send + 'static> Tx<'_, D> {
    /// Inserts the checksums `sums` (one per sector) of the data at logical `start`.
    pub(crate) fn csum_insert(&mut self, mut start: u64, sums: &[u8]) -> Result<(), Errno> {
        let cs = self.sh.csum_size;
        let per = ((self.leaf_space() / 2 - ITEM) / cs).max(1);
        for chunk in sums.chunks(per * cs) {
            self.insert(tree::CSUM, Key::new(tree::EXTENT_CSUM, item::EXTENT_CSUM, start), chunk)?;
            start = start.checked_add((chunk.len() / cs) as u64 * self.sh.sectorsize).ok_or(Errno::EIO)?;
        }
        Ok(())
    }

    /// Deletes the checksums of logical `start..start + len`.
    pub(crate) fn csum_delete(&mut self, start: u64, len: u64) -> Result<(), Errno> {
        let (cs, ss) = (self.sh.csum_size, self.sh.sectorsize);
        let end = start.checked_add(len).ok_or(Errno::EIO)?;
        let ours = |k: &Key| k.objectid == tree::EXTENT_CSUM && k.ty == item::EXTENT_CSUM;
        let span = |k: &Key, d: &[u8]| k.offset.saturating_add((d.len() / cs) as u64 * ss);
        let key = Key::new(tree::EXTENT_CSUM, item::EXTENT_CSUM, start);
        if let Some((k, d)) = self.prev_item(tree::CSUM, key)?
            && ours(&k)
            && k.offset < start
            && span(&k, &d) > start
        {
            let iend = span(&k, &d);
            let head = ((start - k.offset) / ss) as usize * cs;
            if iend > end {
                let tail = ((end - k.offset) / ss) as usize * cs;
                let rest = try_to_vec(d.get(tail..).ok_or(Errno::EIO)?)?;
                self.insert(tree::CSUM, Key::new(tree::EXTENT_CSUM, item::EXTENT_CSUM, end), &rest)?;
            }
            self.update(tree::CSUM, k, d.get(..head).ok_or(Errno::EIO)?)?;
        }
        while let Some((k, d)) = self.next_item(tree::CSUM, key)? {
            if !ours(&k) || k.offset >= end {
                break;
            }
            let iend = span(&k, &d);
            self.delete(tree::CSUM, k)?;
            if iend > end {
                let tail = ((end - k.offset) / ss) as usize * cs;
                self.insert(
                    tree::CSUM,
                    Key::new(tree::EXTENT_CSUM, item::EXTENT_CSUM, end),
                    d.get(tail..).ok_or(Errno::EIO)?,
                )?;
            }
        }
        Ok(())
    }

    /// Bytes this transaction takes from (positive) or gives back to block
    /// group `g`, and the ranges free in it once committed.
    fn group_change(&self, gstart: u64, gend: u64) -> i64 {
        let inside = |s: u64| s >= gstart && s < gend;
        let taken =
            self.allocs.iter().filter(|a| !a.dead && inside(a.start)).fold(0u64, |t, a| t.saturating_add(a.len));
        let given = self.pinned.iter().filter(|p| inside(p.0)).fold(0u64, |t, p| t.saturating_add(p.1));
        (taken as i64).saturating_sub(given as i64)
    }

    /// The block groups this transaction touched.
    fn touched_groups(&self) -> Result<Vec<u64>, Errno> {
        let mut v = Vec::new();
        let starts = self
            .allocs
            .iter()
            .map(|a| a.start)
            .chain(self.pinned.iter().map(|p| p.0))
            .chain(self.new_groups.iter().copied());
        for s in starts {
            let i = self.w.groups.partition_point(|g| g.start <= s).checked_sub(1).ok_or(Errno::EIO)?;
            let g = self.w.groups.get(i).ok_or(Errno::EIO)?.start;
            if !v.contains(&g) {
                try_push(&mut v, g)?;
            }
        }
        Ok(v)
    }

    /// Brings the block group items and the free space tree up to date.
    fn apply_groups(&mut self) -> Result<Vec<(u64, u64)>, Errno> {
        let mut used_after = Vec::new();
        for gs in self.touched_groups()? {
            if self.pending_chunks.iter().any(|c| c.logical() == gs) {
                // Its items go in at the start of the next round.
                continue;
            }
            let g = self.w.groups.iter().find(|g| g.start == gs).ok_or(Errno::EIO)?;
            let (start, len) = (g.start, g.len);
            let used =
                (g.used as i64).saturating_add(self.group_change(start, start.saturating_add(len))).max(0) as u64;
            try_push(&mut used_after, (start, used))?;
            let bg_tree = self.w.bg_tree;
            let key = Key::new(start, item::BLOCK_GROUP_ITEM, len);
            let mut d = self.find(bg_tree, key)?.ok_or(Errno::EIO)?;
            if le64(&d, 0)? != used {
                put64(&mut d, 0, used)?;
                self.update(bg_tree, key, &d)?;
            }
            if self.w.fst {
                self.apply_free_space(start, len)?;
            }
        }
        Ok(used_after)
    }

    /// Rewrites block group `start`'s free space tree entries where they
    /// differ from what will be free after the commit.
    fn apply_free_space(&mut self, start: u64, len: u64) -> Result<(), Errno> {
        let end = start + len;
        let inside = |s: u64| s >= start && s < end;
        let g = self.w.groups.iter().find(|g| g.start == start).ok_or(Errno::EIO)?;
        let mut want = try_to_vec(&g.free)?;
        for &r in self.w.limbo.iter().chain(self.pinned.iter()).filter(|r| inside(r.0)) {
            try_push(&mut want, r)?;
        }
        for a in self.allocs.iter().filter(|a| a.dead && inside(a.start)) {
            try_push(&mut want, (a.start, a.len))?;
        }
        normalize(&mut want);

        let fst = tree::FREE_SPACE;
        let info_key = Key::new(start, item::FREE_SPACE_INFO, len);
        let info = self.find(fst, info_key)?;
        let mut have = Vec::new();
        let mut bitmaps = Vec::new();
        let mut at = Key::new(start, item::FREE_SPACE_EXTENT, 0);
        while let Some((k, d)) = self.next_item(fst, at)? {
            if k.objectid >= end {
                break;
            }
            match k.ty {
                item::FREE_SPACE_EXTENT => try_push(&mut have, (k.objectid, k.offset))?,
                item::FREE_SPACE_BITMAP => {
                    try_push(&mut bitmaps, k)?;
                    let ss = self.sh.sectorsize;
                    if k.offset > end - k.objectid.min(end) {
                        return Err(Errno::EIO);
                    }
                    for bit in 0..(k.offset / ss) as usize {
                        if byte(&d, bit / 8)? >> (bit % 8) & 1 != 0 {
                            try_push(&mut have, (k.objectid + bit as u64 * ss, ss))?;
                        }
                    }
                }
                _ => {}
            }
            at = succ(k).ok_or(Errno::EIO)?;
        }
        let mut merged = try_to_vec(&have)?;
        normalize(&mut merged);
        let count = want.len() as u32;
        let info_ok = info.as_ref().is_some_and(|i| le32(i, 0).ok() == Some(count) && le32(i, 4).ok() == Some(0));
        if merged == want && bitmaps.is_empty() && info_ok {
            return Ok(());
        }
        // Back to extents: drop the bitmaps and the extents not wanted, add the missing.
        for k in bitmaps {
            self.delete(fst, k)?;
            have.clear();
        }
        for &(s, l) in &have {
            if !want.contains(&(s, l)) {
                self.delete(fst, Key::new(s, item::FREE_SPACE_EXTENT, l))?;
            }
        }
        for &(s, l) in &want {
            if !have.contains(&(s, l)) {
                self.insert(fst, Key::new(s, item::FREE_SPACE_EXTENT, l), &[])?;
            }
        }
        let mut d = [0u8; 8];
        put32(&mut d, 0, count)?;
        self.put(fst, info_key, &d)
    }

    /// Points the root items of the trees that moved at their new roots.
    fn apply_roots(&mut self) -> Result<(), Errno> {
        let now = self.sh.now();
        let mut i = 0;
        while let Some(r) = self.roots.get(i).copied() {
            i += 1;
            if r.id == tree::ROOT || r.id == tree::CHUNK || r.addr == r.orig {
                continue;
            }
            let (k, mut d) = self.next_item(tree::ROOT, Key::new(r.id, item::ROOT_ITEM, 0))?.ok_or(Errno::EIO)?;
            if k.objectid != r.id || k.ty != item::ROOT_ITEM {
                return Err(Errno::EIO);
            }
            let before = try_to_vec(&d)?;
            put64(&mut d, 160, self.transid)?;
            put64(&mut d, 176, r.addr)?;
            disk::put(&mut d, 238, &[r.level])?;
            if d.len() >= 247 {
                put64(&mut d, 239, self.transid)?;
            }
            if (r.id == tree::FS || r.id >= tree::FIRST_FREE) && d.len() >= 339 {
                put64(&mut d, 295, self.transid)?;
                put64(&mut d, 327, now.sec as u64)?;
                put32(&mut d, 335, now.nsec)?;
            }
            if d != before {
                self.update(tree::ROOT, k, &d)?;
            }
        }
        Ok(())
    }

    /// Records this commit's roots in the superblock's next backup slot, as
    /// Linux does, for `usebackuproot` recovery.
    fn backup_roots(
        &mut self,
        sb: &mut [u8],
        root: u64,
        root_level: u8,
        chunk: u64,
        chunk_level: u8,
    ) -> Result<(), Errno> {
        const AT: usize = 2859;
        const SLOT: usize = 168;
        let current = le64(sb, 72)?;
        // The slot after the one holding the previous commit's roots.
        let newest = (0..4).find(|&i| le64(sb, AT + i * SLOT + 8).ok() == Some(current.wrapping_sub(1)));
        let at = AT + newest.map_or(0, |i| (i + 1) % 4) * SLOT;
        let mut fields = [
            (root, self.transid, root_level),
            (chunk, le64(sb, 164)?, chunk_level),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
            (0, 0, 0),
        ];
        if let Some(f) = fields.get_mut(1)
            && chunk != self.root(tree::CHUNK)?.orig
        {
            f.1 = self.transid;
        }
        for (i, id) in [tree::EXTENT, tree::FS, tree::DEV, tree::CSUM].into_iter().enumerate() {
            let r = self.root(id)?;
            let generation = if r.addr != r.orig {
                self.transid
            } else {
                let (_, d) = self.next_item(tree::ROOT, Key::new(id, item::ROOT_ITEM, 0))?.ok_or(Errno::EIO)?;
                le64(&d, 160)?
            };
            if let Some(f) = fields.get_mut(i + 2) {
                *f = (r.addr, generation, r.level);
            }
        }
        for (i, &(addr, generation, level)) in fields.iter().enumerate() {
            put64(sb, at + i * 16, addr)?;
            put64(sb, at + i * 16 + 8, generation)?;
            disk::put(sb, at + 152 + i, &[level])?;
        }
        put64(sb, at + 96, le64(sb, 112)?)?;
        put64(sb, at + 104, le64(sb, 120)?)?;
        put64(sb, at + 112, le64(sb, 136)?)
    }

    /// Commits: settles the trees, writes the changed blocks, then the
    /// superblock, and makes the new state current.
    pub(crate) fn commit(mut self) -> Result<(), Errno> {
        let mut used_after = Vec::new();
        let mut settled = false;
        for _ in 0..MAX_ROUNDS {
            let before = self.edits;
            self.apply_pending_chunks()?;
            self.apply_data_refs()?;
            self.apply_tree_refs()?;
            used_after = self.apply_groups()?;
            self.apply_roots()?;
            if self.edits == before
                && self.tree_refs.is_empty()
                && self.data_refs.is_empty()
                && self.pending_chunks.is_empty()
            {
                settled = true;
                break;
            }
        }
        if !settled {
            return Err(Errno::EIO);
        }
        if self.dirty.is_empty() && self.allocs.is_empty() && !self.force {
            return Ok(());
        }

        // Everything that could fail for memory, before the first write.
        let sh = self.sh;
        let mut blocks = Vec::new();
        blocks.try_reserve_exact(self.dirty.len()).map_err(|_| Errno::ENOMEM)?;
        let chunk_uuid = self.w.chunk_uuid;
        for n in &self.dirty {
            blocks.push((n.addr, n.encode(sh.nodesize, &sh.meta_uuid, &chunk_uuid, sh.csum_type)?));
        }
        let root_tree = self.root(tree::ROOT)?;
        let chunk_root = self.root(tree::CHUNK)?;
        let csum_root = self.root(tree::CSUM)?;
        let mut sb = try_to_vec(&self.w.sb)?;
        // Before anything is written: writing the superblocks may not fail for want of memory.
        let mut others = sh.super_buffers()?;
        let taken = self.allocs.iter().filter(|a| !a.dead).fold(0u64, |t, a| t.saturating_add(a.len));
        let given = self.pinned.iter().fold(0u64, |t, p| t.saturating_add(p.1));
        let bytes_used = le64(&sb, 120)?.saturating_add(taken).saturating_sub(given);
        put64(&mut sb, 72, self.transid)?;
        put64(&mut sb, 80, root_tree.addr)?;
        disk::put(&mut sb, 198, &[root_tree.level])?;
        if chunk_root.addr != chunk_root.orig {
            put64(&mut sb, 88, chunk_root.addr)?;
            disk::put(&mut sb, 199, &[chunk_root.level])?;
            put64(&mut sb, 164, self.transid)?;
        }
        put64(&mut sb, 120, bytes_used)?;
        // The size of the volume and its device count are the chunk tree's.
        let (mut total, mut devices) = (0u64, 0u64);
        let mut at = Key::new(1, item::DEV_ITEM, 0);
        while let Some((k, d)) = self.next_item(tree::CHUNK, at)? {
            if k.objectid != 1 || k.ty != item::DEV_ITEM {
                break;
            }
            total = total.saturating_add(le64(&d, 8)?);
            devices += 1;
            at = succ(k).ok_or(Errno::EIO)?;
        }
        put64(&mut sb, 112, total)?;
        put64(&mut sb, 136, devices)?;
        // Holes are left implicit.
        let flags = le64(&sb, 188)? | incompat::NO_HOLES | self.incompat;
        put64(&mut sb, 188, flags)?;
        self.backup_roots(&mut sb, root_tree.addr, root_tree.level, chunk_root.addr, chunk_root.level)?;
        // Each device's superblocks carry the chunk tree's item for it; a
        // device without one (being removed) gets none.
        let mut items: Vec<(u64, [u8; crate::DEV_ITEM_SIZE])> = Vec::new();
        for id in sh.dev_ids()? {
            let Some(di) = self.find(tree::CHUNK, Key::new(1, item::DEV_ITEM, id))? else { continue };
            try_push(&mut items, (id, disk::array(&di, 0)?))?;
            if id == sh.devid {
                disk::put(&mut sb, crate::DEV_ITEM_AT, di.get(..crate::DEV_ITEM_SIZE).ok_or(Errno::EIO)?)?;
            }
        }
        let chunks = match self.new_chunks.take() {
            Some(m) => try_arc(m)?,
            None => self.base.chunks.clone(),
        };
        let state = try_arc(State {
            generation: self.transid,
            root_tree: (root_tree.addr, root_tree.level),
            chunk_root: (chunk_root.addr, chunk_root.level),
            csum_tree: Some((csum_root.addr, csum_root.level)),
            chunks: chunks.clone(),
            pinned: osmium_sync::SpinLock::new(Vec::new()),
            release: self.w.release.clone(),
            next: osmium_sync::SpinLock::new(None),
        })?;
        self.w.limbo.try_reserve(self.pinned.len()).map_err(|_| Errno::ENOMEM)?;
        self.base.pinned.lock().try_reserve(self.pinned.len() + self.w.held.len()).map_err(|_| Errno::ENOMEM)?;
        // Room for the ranges a deferred commit sets aside or remembers; the
        // free list `fresh` grows by one at most per allocation.
        self.w.held.try_reserve(self.pinned.len()).map_err(|_| Errno::ENOMEM)?;
        self.w.fresh.try_reserve(self.allocs.len()).map_err(|_| Errno::ENOMEM)?;
        let dead = self.allocs.iter().filter(|a| a.dead).count();
        for a in self.allocs.iter().filter(|a| a.dead) {
            if let Some(g) = self.w.group_mut(a.start) {
                g.free.try_reserve(dead).map_err(|_| Errno::ENOMEM)?;
            }
        }

        // The new blocks, then the superblock that points at them.
        for (addr, b) in &blocks {
            sh.write_logical(&chunks, *addr, b)?;
        }
        sh.set_dev_items(&items);
        // A deferred commit stops here: the blocks are written, and nothing
        // points at them until `sync_locked` writes a superblock that does.
        // The superblock of the last sync stays valid meanwhile, as the
        // space it uses is held back (see `Writer::held`).
        if !self.defer {
            sh.flush()?;
            if let Err(e) = sh.write_super(&mut sb, &mut others) {
                self.w.broken = true;
                return Err(e);
            }
        }

        // Committed: nothing below may fail.
        self.w.sb = sb;
        sh.forget(blocks.iter().map(|(a, _)| *a));
        for (start, used) in used_after {
            if let Some(g) = self.w.groups.iter_mut().find(|g| g.start == start) {
                g.used = used;
            }
        }
        let allocs = core::mem::take(&mut self.allocs);
        // Freed ranges no superblock uses are reusable once readers let go;
        // the others, only once a superblock without them is written.
        let pinned = core::mem::take(&mut self.pinned);
        self.w.limbo.extend_from_slice(&pinned);
        let mut readers = self.base.pinned.lock();
        if self.defer {
            for (start, len) in pinned {
                if self.w.is_fresh(start, len) {
                    readers.push((start, len));
                } else {
                    self.w.held.push((start, len));
                }
            }
            self.w.deferred = self.w.deferred.saturating_add(1);
        } else {
            readers.extend(pinned);
            readers.append(&mut self.w.held);
            self.w.fresh.clear();
            self.w.deferred = 0;
        }
        drop(readers);
        for a in allocs {
            if a.dead {
                if let Some(g) = self.w.group_mut(a.start) {
                    let _ = g.give(a.start, a.len);
                }
            } else if self.defer {
                self.w.add_fresh((a.start, a.len));
            }
        }
        self.new_groups.clear();
        for start in core::mem::take(&mut self.dropped_groups) {
            if let Some(i) = self.w.groups.iter().position(|g| g.start == start) {
                self.w.groups.remove(i);
            }
        }
        *self.base.next.lock() = Some(state.clone());
        *sh.state.lock() = state;
        Ok(())
    }
}

impl<D: BlockDevice + Send + 'static> Drop for Tx<'_, D> {
    fn drop(&mut self) {
        // Anything still allocated belongs to a transaction that did not commit.
        self.undo_allocs();
    }
}

impl<D: BlockDevice + Send + 'static> crate::Shared<D> {
    /// One buffer for each device but the first, for [`Self::write_super`].
    pub(crate) fn super_buffers(&self) -> Result<Vec<Vec<u8>>, Errno> {
        let mut v = Vec::new();
        let devs = self.devs.lock();
        v.try_reserve_exact(devs.len()).map_err(|_| Errno::ENOMEM)?;
        for _ in devs.iter().filter(|d| d.devid != self.devid) {
            v.push(osmium_sync::fallible::try_zeroed(disk::SUPER_SIZE)?);
        }
        Ok(v)
    }

    /// Makes every deferred commit durable: flushes their blocks, then writes
    /// the superblock that points at them.
    pub(crate) fn sync_locked(&self, w: &mut crate::write::Writer) -> Result<(), Errno> {
        if w.deferred == 0 {
            return Ok(());
        }
        if w.broken {
            return Err(Errno::EIO);
        }
        let mut others = self.super_buffers()?;
        let mut sb = try_to_vec(&w.sb)?;
        if let Err(e) = self.flush().and_then(|()| self.write_super(&mut sb, &mut others)) {
            w.broken = true;
            return Err(e);
        }
        w.sb = sb;
        w.deferred = 0;
        w.fresh.clear();
        // What the deferred commits freed is free of the superblock now, and
        // goes once the readers of every state so far have: the current
        // state is the last of them to be dropped.
        if !w.held.is_empty() {
            let st = self.state();
            let mut pinned = st.pinned.lock();
            if pinned.try_reserve(w.held.len()).is_ok() {
                pinned.append(&mut w.held);
            }
        }
        Ok(())
    }

    /// Writes superblock `sb` (whose generation and roots are set) to every
    /// copy on every device, flushing before and after. Each device's copies
    /// carry its own `dev_item`; `sb` has the mounted device's. Devices added
    /// since the mount go first, so that a crash in between leaves a volume
    /// the newest superblock describes whole. A device with no item (being
    /// removed) gets nothing. `others` come from [`Self::super_buffers`].
    pub(crate) fn write_super(&self, sb: &mut [u8], others: &mut [Vec<u8>]) -> Result<(), Errno> {
        for (i, at) in [disk::SUPER_OFFSET, 64 << 20, 256 << 30].into_iter().enumerate() {
            let mut next = others.iter_mut();
            // The devices added since the mount, then the mounted one; the
            // list is not held across the writes.
            let count = self.devs.lock().len();
            for n in 0..count {
                let d = {
                    let devs = self.devs.lock();
                    let others = devs.iter().filter(|d| d.devid != self.devid);
                    let first = devs.iter().filter(|d| d.devid == self.devid);
                    others.chain(first).nth(n).cloned().ok_or(Errno::EIO)?
                };
                let item = *d.dev_item.lock();
                if item.iter().all(|&b| b == 0) {
                    continue;
                }
                // `sb` itself for the device it was read from; for the others a
                // copy with that device's own `dev_item`.
                let img: &mut [u8] = if d.devid == self.devid {
                    &mut *sb
                } else {
                    let img = next.next().ok_or(Errno::EIO)?;
                    img.copy_from_slice(sb);
                    disk::put(img, crate::DEV_ITEM_AT, &item)?;
                    img
                };
                let size = d.dev.lock().num_blocks().saturating_mul(d.block_size as u64);
                if at + disk::SUPER_SIZE as u64 > size {
                    continue;
                }
                put64(img, 48, at)?;
                let sum = csum::compute(self.csum_type, img.get(disk::CSUM_SPACE..).ok_or(Errno::EIO)?);
                disk::put(img, 0, &sum)?;
                self.write_phys(d.devid, at, img)?;
            }
            if i == 0 {
                self.flush()?;
            }
        }
        put64(sb, 48, disk::SUPER_OFFSET)?;
        let sum = csum::compute(self.csum_type, sb.get(disk::CSUM_SPACE..).ok_or(Errno::EIO)?);
        disk::put(sb, 0, &sum)?;
        self.flush()
    }

    /// Records each device's `dev_item` for its superblocks; a device not in
    /// `items` has none and is left out of them.
    pub(crate) fn set_dev_items(&self, items: &[(u64, [u8; crate::DEV_ITEM_SIZE])]) {
        for d in self.devs.lock().iter() {
            *d.dev_item.lock() = items.iter().find(|i| i.0 == d.devid).map_or([0; crate::DEV_ITEM_SIZE], |i| i.1);
        }
    }
}

/// Keeps the import of `Arc` meaningful where `State` is built.
#[allow(dead_code)]
fn _arc(_: Arc<State>) {}
