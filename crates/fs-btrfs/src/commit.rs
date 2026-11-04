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

/// Extent item flags.
const EXTENT_DATA: u64 = 1;
const EXTENT_TREE_BLOCK: u64 = 2;
const EXTENT_FULL_BACKREF: u64 = 1 << 8;

/// Bytes of an extent item before its inline references.
const EXTENT_ITEM: usize = 24;

/// The key offset of a keyed data reference (`hash_extent_data_ref`).
fn data_ref_hash(root: u64, ino: u64, offset: u64) -> u64 {
    let high = csum::crc32c(!0, &root.to_le_bytes());
    let low = csum::crc32c(!0, &ino.to_le_bytes());
    let low = csum::crc32c(low, &offset.to_le_bytes());
    (high as u64) << 31 ^ low as u64
}

/// The fields of an `EXTENT_DATA_REF`.
fn data_ref(root: u64, ino: u64, offset: u64, count: u32) -> [u8; 28] {
    let mut b = [0u8; 28];
    let _ = put64(&mut b, 0, root);
    let _ = put64(&mut b, 8, ino);
    let _ = put64(&mut b, 16, offset);
    let _ = put32(&mut b, 24, count);
    b
}

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
            Some(last) if last.0 + last.1 >= s => last.1 = last.1.max(s + l - last.0),
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
            start += (chunk.len() / cs) as u64 * self.sh.sectorsize;
        }
        Ok(())
    }

    /// Deletes the checksums of logical `start..start + len`.
    pub(crate) fn csum_delete(&mut self, start: u64, len: u64) -> Result<(), Errno> {
        let (cs, ss) = (self.sh.csum_size, self.sh.sectorsize);
        let end = start + len;
        let ours = |k: &Key| k.objectid == tree::EXTENT_CSUM && k.ty == item::EXTENT_CSUM;
        let span = |k: &Key, d: &[u8]| k.offset + (d.len() / cs) as u64 * ss;
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

    /// Adds `delta` to data extent `bytenr`'s keyed reference by `(root, ino,
    /// offset)`; returns `false` if there is none to take from. Colliding
    /// references take the next free key offsets, so a reference is looked
    /// for among all of the extent's keyed references from its hash on.
    fn keyed_data_ref(&mut self, bytenr: u64, root: u64, ino: u64, offset: u64, delta: i64) -> Result<bool, Errno> {
        let hash = data_ref_hash(root, ino, offset);
        let mut at = Key::new(bytenr, item::EXTENT_DATA_REF, hash);
        let mut free = None;
        loop {
            let found = self
                .next_item(tree::EXTENT, at)?
                .filter(|(k, _)| k.objectid == bytenr && k.ty == item::EXTENT_DATA_REF);
            let Some((key, d)) = found else { break };
            if free.is_none() && key.offset != at.offset {
                free = Some(at);
            }
            if (le64(&d, 0)?, le64(&d, 8)?, le64(&d, 16)?) == (root, ino, offset) {
                let count = le32(&d, 24)? as i64 + delta;
                match count {
                    ..0 => return Err(Errno::EIO),
                    0 => self.delete(tree::EXTENT, key)?,
                    _ => {
                        let c = u32::try_from(count).map_err(|_| Errno::EIO)?;
                        self.update(tree::EXTENT, key, &data_ref(root, ino, offset, c))?;
                    }
                }
                return Ok(true);
            }
            at = succ(key).ok_or(Errno::EIO)?;
        }
        if delta < 0 {
            return Ok(false);
        }
        let count = u32::try_from(delta).map_err(|_| Errno::EIO)?;
        self.insert(tree::EXTENT, free.unwrap_or(at), &data_ref(root, ino, offset, count))?;
        Ok(true)
    }

    /// Applies the pending data extent reference changes to the extent tree.
    fn apply_data_refs(&mut self) -> Result<(), Errno> {
        let mut refs = core::mem::take(&mut self.data_refs);
        refs.sort_unstable_by_key(|r| (r.bytenr, r.root, r.ino, r.offset));
        let mut i = 0;
        while let Some(first) = refs.get(i).copied() {
            let n = refs.get(i..).unwrap_or(&[]).iter().take_while(|r| r.bytenr == first.bytenr).count();
            let group = refs.get(i..i + n).ok_or(Errno::EIO)?;
            i += n;
            // Net change per referrer.
            let mut net: Vec<(u64, u64, u64, i64)> = Vec::new();
            for r in group {
                match net.last_mut() {
                    Some(l) if (l.0, l.1, l.2) == (r.root, r.ino, r.offset) => l.3 += r.delta,
                    _ => try_push(&mut net, (r.root, r.ino, r.offset, r.delta))?,
                }
            }
            net.retain(|r| r.3 != 0);
            let new = group.iter().any(|r| r.new);
            let (bytenr, len) = (first.bytenr, first.len);
            let key = Key::new(bytenr, item::EXTENT_ITEM, len);
            if new {
                if net.iter().any(|r| r.3 < 0) {
                    return Err(Errno::EIO);
                }
                let total: i64 = net.iter().map(|r| r.3).sum();
                let Some(&(root, ino, offset, count)) = net.first() else {
                    // Written and dropped in this transaction.
                    self.csum_delete(bytenr, len)?;
                    self.unalloc(bytenr);
                    continue;
                };
                let mut d = [0u8; EXTENT_ITEM + 29];
                put64(&mut d, 0, total as u64)?;
                put64(&mut d, 8, self.transid)?;
                put64(&mut d, 16, EXTENT_DATA)?;
                disk::put(&mut d, 24, &[item::EXTENT_DATA_REF])?;
                disk::put(&mut d, 25, &data_ref(root, ino, offset, u32::try_from(count).map_err(|_| Errno::EIO)?))?;
                self.insert(tree::EXTENT, key, &d)?;
                for &(root, ino, offset, count) in net.get(1..).unwrap_or(&[]) {
                    self.keyed_data_ref(bytenr, root, ino, offset, count)?;
                }
                continue;
            }
            let mut d = self.find(tree::EXTENT, key)?.ok_or(Errno::EIO)?;
            if le64(&d, 16)? & EXTENT_DATA == 0 {
                return Err(Errno::EIO);
            }
            let mut total = le64(&d, 0)? as i64;
            for &(root, ino, offset, delta) in &net {
                total += delta;
                // An inline reference, else a keyed one.
                let mut p = EXTENT_ITEM;
                let mut found = false;
                while p < d.len() {
                    let size = match byte(&d, p)? {
                        item::TREE_BLOCK_REF | item::SHARED_BLOCK_REF => 9,
                        item::EXTENT_DATA_REF => 29,
                        item::SHARED_DATA_REF => 13,
                        _ => return Err(Errno::EIO),
                    };
                    if byte(&d, p)? == item::EXTENT_DATA_REF
                        && (le64(&d, p + 1)?, le64(&d, p + 9)?, le64(&d, p + 17)?) == (root, ino, offset)
                    {
                        let count = le32(&d, p + 25)? as i64 + delta;
                        if count < 0 {
                            return Err(Errno::EIO);
                        }
                        if count == 0 {
                            d.drain(p..p + 29);
                        } else {
                            put32(&mut d, p + 25, u32::try_from(count).map_err(|_| Errno::EIO)?)?;
                        }
                        found = true;
                        break;
                    }
                    p += size;
                }
                if !found && !self.keyed_data_ref(bytenr, root, ino, offset, delta)? {
                    // Referred to through a shared leaf (a snapshot or relocation).
                    return Err(Errno::EOPNOTSUPP);
                }
            }
            match total {
                ..0 => return Err(Errno::EIO),
                0 => {
                    self.delete(tree::EXTENT, key)?;
                    self.csum_delete(bytenr, len)?;
                    try_push(&mut self.pinned, (bytenr, len))?;
                }
                _ => {
                    put64(&mut d, 0, total as u64)?;
                    self.update(tree::EXTENT, key, &d)?;
                }
            }
        }
        Ok(())
    }

    /// Applies the pending tree block reference changes to the extent tree.
    fn apply_tree_refs(&mut self) -> Result<(), Errno> {
        let refs = core::mem::take(&mut self.tree_refs);
        for r in refs {
            let key = Key::new(r.addr, item::METADATA_ITEM, r.level as u64);
            if r.add {
                let mut d = [0u8; EXTENT_ITEM + 9];
                put64(&mut d, 0, 1)?;
                put64(&mut d, 8, self.transid)?;
                put64(&mut d, 16, EXTENT_TREE_BLOCK)?;
                disk::put(&mut d, 24, &[item::TREE_BLOCK_REF])?;
                put64(&mut d, 25, r.owner)?;
                self.insert(tree::EXTENT, key, &d)?;
                continue;
            }
            // Only a block its own tree alone refers to can go.
            let (key, refs_at) = match self.find(tree::EXTENT, key)? {
                Some(d) => (key, (d, EXTENT_ITEM)),
                None => {
                    let fat = Key::new(r.addr, item::EXTENT_ITEM, self.sh.nodesize as u64);
                    (fat, (self.find(tree::EXTENT, fat)?.ok_or(Errno::EIO)?, EXTENT_ITEM + Key::SIZE + 1))
                }
            };
            let (d, p) = refs_at;
            let flags = le64(&d, 16)?;
            if le64(&d, 0)? != 1
                || flags & EXTENT_FULL_BACKREF != 0
                || d.len() != p + 9
                || byte(&d, p)? != item::TREE_BLOCK_REF
                || le64(&d, p + 1)? != r.owner
            {
                return Err(Errno::EOPNOTSUPP);
            }
            self.delete(tree::EXTENT, key)?;
        }
        Ok(())
    }

    /// Bytes this transaction takes from (positive) or gives back to block
    /// group `g`, and the ranges free in it once committed.
    fn group_change(&self, gstart: u64, gend: u64) -> i64 {
        let inside = |s: u64| s >= gstart && s < gend;
        let taken: u64 = self.allocs.iter().filter(|a| !a.dead && inside(a.start)).map(|a| a.len).sum();
        let given: u64 = self.pinned.iter().filter(|p| inside(p.0)).map(|p| p.1).sum();
        taken as i64 - given as i64
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
            let used = (g.used as i64 + self.group_change(start, start + len)).max(0) as u64;
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
        if self.dirty.is_empty() && self.allocs.is_empty() {
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
        let taken: u64 = self.allocs.iter().filter(|a| !a.dead).map(|a| a.len).sum();
        let given: u64 = self.pinned.iter().map(|p| p.1).sum();
        let bytes_used = (le64(&sb, 120)? + taken).saturating_sub(given);
        put64(&mut sb, 72, self.transid)?;
        put64(&mut sb, 80, root_tree.addr)?;
        disk::put(&mut sb, 198, &[root_tree.level])?;
        if chunk_root.addr != chunk_root.orig {
            put64(&mut sb, 88, chunk_root.addr)?;
            disk::put(&mut sb, 199, &[chunk_root.level])?;
            put64(&mut sb, 164, self.transid)?;
        }
        put64(&mut sb, 120, bytes_used)?;
        let dev_used = le64(&sb, 201 + 16)? + self.dev_used;
        put64(&mut sb, 201 + 16, dev_used)?;
        // Holes are left implicit.
        let flags = le64(&sb, 188)? | incompat::NO_HOLES | self.incompat;
        put64(&mut sb, 188, flags)?;
        self.backup_roots(&mut sb, root_tree.addr, root_tree.level, chunk_root.addr, chunk_root.level)?;
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
        // A deferred commit stops here: the blocks are written, and nothing
        // points at them until `sync_locked` writes a superblock that does.
        // The superblock of the last sync stays valid meanwhile, as the
        // space it uses is held back (see `Writer::held`).
        if !self.defer {
            sh.flush()?;
            if let Err(e) = sh.write_super(&mut sb) {
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
    /// Makes every deferred commit durable: flushes their blocks, then writes
    /// the superblock that points at them.
    pub(crate) fn sync_locked(&self, w: &mut crate::write::Writer) -> Result<(), Errno> {
        if w.deferred == 0 {
            return Ok(());
        }
        if w.broken {
            return Err(Errno::EIO);
        }
        let mut sb = try_to_vec(&w.sb)?;
        if let Err(e) = self.flush().and_then(|()| self.write_super(&mut sb)) {
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
    /// copy on the device, flushing before and after.
    pub(crate) fn write_super(&self, sb: &mut [u8]) -> Result<(), Errno> {
        let size = self.dev.lock().num_blocks().saturating_mul(self.block_size as u64);
        for (i, at) in [disk::SUPER_OFFSET, 64 << 20, 256 << 30].into_iter().enumerate() {
            if at + disk::SUPER_SIZE as u64 > size {
                continue;
            }
            put64(sb, 48, at)?;
            let sum = csum::compute(self.csum_type, sb.get(disk::CSUM_SPACE..).ok_or(Errno::EIO)?);
            disk::put(sb, 0, &sum)?;
            self.write_phys(at, sb)?;
            if i == 0 {
                self.flush()?;
            }
        }
        put64(sb, 48, disk::SUPER_OFFSET)?;
        let sum = csum::compute(self.csum_type, sb.get(disk::CSUM_SPACE..).ok_or(Errno::EIO)?);
        disk::put(sb, 0, &sum)?;
        self.flush()
    }
}

/// Keeps the import of `Arc` meaningful where `State` is built.
#[allow(dead_code)]
fn _arc(_: Arc<State>) {}
