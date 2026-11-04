//! Space: block groups, their free ranges, and new chunks when they run out.
//!
//! Free ranges live in memory, built at mount from the block group items and
//! the extent tree. A transaction takes ranges out as it allocates and logs
//! each one, so that dropping it puts them back in reverse order; every
//! allocation first reserves the one extra slot that putting it back can
//! need, so undoing never allocates.

use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::try_push;

use crate::disk::{Chunk, Key, Stripe, item, le64, profile, put, tree};
use crate::tree::Cursor;
use crate::write::{Alloc, Tx, Writer};
use crate::{Shared, State};

/// Block group type bits.
pub mod kind {
    /// File data.
    pub const DATA: u64 = 1 << 0;
    /// The chunk tree.
    pub const SYSTEM: u64 = 1 << 1;
    /// Every other tree.
    pub const METADATA: u64 = 1 << 2;
    /// All three.
    pub const MASK: u64 = DATA | SYSTEM | METADATA;
}

/// Superblock copies inside block groups are never allocated.
const SUPER_MIRRORS: [u64; 3] = [64 * 1024, 64 << 20, 256 << 30];

/// Bytes kept free at each superblock copy: a stripe, as Linux keeps.
const MIRROR_EXCLUDE: u64 = 64 * 1024;

/// Device bytes before the first chunk.
const DEV_RESERVED: u64 = 1 << 20;

/// Metadata blocks kept for transactions that free space.
pub const RESERVE_NODES: u64 = 64;

/// Alignment of new chunks on the device and in logical addresses.
const CHUNK_ALIGN: u64 = 64 * 1024;

/// A device and its free ranges.
struct DevRoom {
    devid: u64,
    total: u64,
    gaps: Vec<(u64, u64)>,
}

/// A block group.
pub struct Group {
    /// First logical address.
    pub start: u64,
    /// Length.
    pub len: u64,
    /// Type and profile.
    pub flags: u64,
    /// Bytes in use as of the last commit.
    pub used: u64,
    /// Free ranges `(start, len)`, sorted and not touching.
    pub free: Vec<(u64, u64)>,
}

impl Group {
    fn end(&self) -> u64 {
        self.start + self.len
    }

    /// Takes `start..start + len`, which must be free.
    fn take(&mut self, start: u64, len: u64) -> Result<(), Errno> {
        let i = self.free.partition_point(|&(s, _)| s <= start).checked_sub(1).ok_or(Errno::EIO)?;
        let &(s, l) = self.free.get(i).ok_or(Errno::EIO)?;
        if start + len > s + l {
            return Err(Errno::EIO);
        }
        self.free.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let (head, tail) = (start - s, s + l - (start + len));
        let slot = self.free.get_mut(i).ok_or(Errno::EIO)?;
        match (head, tail) {
            (0, 0) => _ = self.free.remove(i),
            (0, _) => *slot = (start + len, tail),
            (_, 0) => *slot = (s, head),
            _ => {
                *slot = (s, head);
                self.free.insert(i + 1, (start + len, tail));
            }
        }
        Ok(())
    }

    /// Gives back `start..start + len`; fails only if a new entry needs
    /// memory that is not there (never when undoing in order).
    pub fn give(&mut self, start: u64, len: u64) -> Result<(), Errno> {
        let i = self.free.partition_point(|&(s, _)| s < start);
        let prev = i.checked_sub(1).filter(|&p| self.free.get(p).is_some_and(|&(s, l)| s + l == start));
        let next = Some(i).filter(|&n| self.free.get(n).is_some_and(|&(s, _)| start + len == s));
        match (prev, next) {
            (Some(p), Some(n)) => {
                let (_, nl) = self.free.remove(n);
                self.free.get_mut(p).ok_or(Errno::EIO)?.1 += len + nl;
            }
            (Some(p), None) => self.free.get_mut(p).ok_or(Errno::EIO)?.1 += len,
            (None, Some(n)) => {
                let r = self.free.get_mut(n).ok_or(Errno::EIO)?;
                *r = (start, r.1 + len);
            }
            (None, None) => {
                self.free.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                self.free.insert(i, (start, len));
            }
        }
        Ok(())
    }
}

/// The logical ranges of `chunk` holding a superblock copy.
pub fn super_ranges(chunk: &Chunk) -> impl Iterator<Item = (u64, u64)> + '_ {
    chunk.stripes.iter().enumerate().flat_map(move |(i, s)| {
        SUPER_MIRRORS.iter().filter_map(move |&m| {
            let (logical, room) = chunk.rmap(i, m.checked_sub(s.offset)?)?;
            Some((logical, MIRROR_EXCLUDE.min(room)))
        })
    })
}

impl<D: BlockDevice + Send + 'static> Shared<D> {
    /// The block groups and their free space, from the committed state.
    pub(crate) fn load_groups(&self, st: &State, bg_tree: u64) -> Result<Vec<Group>, Errno> {
        let bg_root = self.tree_root(st, bg_tree)?.ok_or(Errno::EIO)?;
        let mut groups: Vec<Group> = Vec::new();
        let mut c = Cursor::new(self, &st.chunks, (bg_root.bytenr, bg_root.level));
        let mut cur = c.seek(Key::new(0, item::BLOCK_GROUP_ITEM, 0))?;
        while let Some((k, data)) = cur {
            if k.ty == item::BLOCK_GROUP_ITEM {
                if k.objectid.checked_add(k.offset).is_none() || k.offset == 0 {
                    return Err(Errno::EIO);
                }
                let g = Group {
                    start: k.objectid,
                    len: k.offset,
                    flags: le64(data, 16)?,
                    used: le64(data, 0)?,
                    free: Vec::new(),
                };
                try_push(&mut groups, g)?;
            }
            cur = c.next()?;
        }
        groups.sort_unstable_by_key(|g| g.start);
        // Free space: what no extent item covers.
        let extent_root = self.tree_root(st, tree::EXTENT)?.ok_or(Errno::EIO)?;
        let mut c = Cursor::new(self, &st.chunks, (extent_root.bytenr, extent_root.level));
        let mut cur = c.seek(Key::new(0, 0, 0))?;
        let nodesize = self.nodesize as u64;
        let mut gi = 0;
        let mut pos = groups.first().map_or(0, |g| g.start);
        loop {
            let ext = match cur {
                Some((k, _)) if k.ty == item::EXTENT_ITEM => Some((k.objectid, k.offset)),
                Some((k, _)) if k.ty == item::METADATA_ITEM => Some((k.objectid, nodesize)),
                Some(_) => {
                    cur = c.next()?;
                    continue;
                }
                None => None,
            };
            // Close the groups that end at or before this extent (all of them at the end).
            while let Some(g) = groups.get_mut(gi) {
                if ext.is_some_and(|(s, _)| s < g.end()) {
                    break;
                }
                let end = g.end();
                if pos < end {
                    try_push(&mut g.free, (pos, end - pos))?;
                }
                gi += 1;
                pos = groups.get(gi).map_or(0, |g| g.start);
            }
            let Some((s, l)) = ext else { break };
            if let Some(g) = groups.get_mut(gi)
                && s >= g.start
            {
                if s > pos {
                    try_push(&mut g.free, (pos, s - pos))?;
                }
                pos = pos.max(s.saturating_add(l));
            }
            cur = c.next()?;
        }
        // Superblock copies are never free.
        for chunk in st.chunks.iter() {
            for (s, l) in super_ranges(chunk) {
                if let Some(g) = groups.iter_mut().find(|g| g.start <= s && s < g.end()) {
                    carve(&mut g.free, s, l)?;
                }
            }
        }
        Ok(groups)
    }
}

/// Removes `start..start + len` from the ranges `free`, wherever it overlaps.
pub fn carve(free: &mut Vec<(u64, u64)>, start: u64, len: u64) -> Result<(), Errno> {
    let end = start + len;
    let mut out = Vec::new();
    out.try_reserve_exact(free.len() + 1).map_err(|_| Errno::ENOMEM)?;
    for &(s, l) in free.iter() {
        let e = s + l;
        if e <= start || s >= end {
            out.push((s, l));
            continue;
        }
        if s < start {
            out.push((s, start - s));
        }
        if e > end {
            out.push((end, e - end));
        }
    }
    *free = out;
    Ok(())
}

impl Writer {
    /// The group holding `addr`.
    pub fn group_mut(&mut self, addr: u64) -> Option<&mut Group> {
        let i = self.groups.partition_point(|g| g.start <= addr).checked_sub(1)?;
        self.groups.get_mut(i).filter(|g| addr < g.end())
    }

    /// Puts ranges that readers have let go of back into the free lists.
    pub fn reclaim(&mut self) {
        let ranges: Vec<(u64, u64)> = core::mem::take(&mut *self.release.lock());
        let mut kept = Vec::new();
        for (s, l) in ranges {
            let ok = match self.group_mut(s) {
                Some(g) => g.give(s, l).is_ok(),
                None => true,
            };
            if ok {
                if let Some(i) = self.limbo.iter().position(|&r| r == (s, l)) {
                    self.limbo.swap_remove(i);
                }
            } else if kept.try_reserve(1).is_ok() {
                kept.push((s, l));
            }
        }
        if !kept.is_empty() {
            let mut q = self.release.lock();
            if q.try_reserve(kept.len()).is_ok() {
                q.extend(kept);
            }
        }
    }
}

impl<D: BlockDevice + Send + 'static> Tx<'_, D> {
    /// The type of block group tree `owner`'s blocks go in.
    fn meta_kind(owner: u64) -> u64 {
        if owner == tree::CHUNK { kind::SYSTEM } else { kind::METADATA }
    }

    /// Takes the first free range of `len` bytes, aligned to `align`, from a
    /// block group of type `ty`; with `partial`, a shorter one (whole
    /// `align` units) if none is that long. Returns its start and length.
    fn take(&mut self, ty: u64, len: u64, align: u64, partial: bool) -> Result<Option<(u64, u64)>, Errno> {
        let mut best: Option<(u64, u64)> = None;
        for g in self.w.groups.iter().filter(|g| g.flags & kind::MASK == ty && self.may_allocate(g.start)) {
            for &(s, l) in &g.free {
                let a = s.next_multiple_of(align);
                let avail = (s + l).saturating_sub(a) / align * align;
                if avail >= len {
                    return self.claim(a, len).map(Some);
                }
                if partial && avail > best.map_or(0, |b| b.1) {
                    best = Some((a, avail));
                }
            }
        }
        match best {
            Some((a, l)) => self.claim(a, l).map(Some),
            None => Ok(None),
        }
    }

    /// Whether new allocations may go in the block group at `start`: it is
    /// not being emptied, and none of its stripes is on a device being
    /// removed.
    fn may_allocate(&self, start: u64) -> bool {
        !self.avoid.contains(&start)
            && (self.w.no_alloc.is_empty()
                || self
                    .chunks()
                    .find(start, 1)
                    .is_ok_and(|c| c.stripes.iter().all(|s| !self.w.no_alloc.contains(&s.devid))))
    }

    pub(crate) fn claim(&mut self, start: u64, len: u64) -> Result<(u64, u64), Errno> {
        self.allocs.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        self.w.group_mut(start).ok_or(Errno::EIO)?.take(start, len)?;
        self.allocs.push(Alloc { start, len, dead: false });
        Ok((start, len))
    }

    /// A tree block for tree `owner`. Unless the transaction frees space,
    /// the last [`RESERVE_NODES`] blocks of metadata are kept for one that
    /// does, so that a full volume can still be emptied.
    pub(crate) fn alloc_meta(&mut self, owner: u64) -> Result<u64, Errno> {
        let ty = Self::meta_kind(owner);
        let n = self.sh.nodesize as u64;
        if ty == kind::METADATA && !self.frees {
            let free: u64 = self
                .w
                .groups
                .iter()
                .filter(|g| g.flags & kind::MASK == ty && self.may_allocate(g.start))
                .flat_map(|g| g.free.iter())
                .map(|r| r.1)
                .sum();
            if free < (RESERVE_NODES + 1) * n && !self.alloc_chunk(ty)? {
                return Err(Errno::ENOSPC);
            }
        }
        if let Some((a, _)) = self.take(ty, n, n, false)? {
            return Ok(a);
        }
        if ty == kind::SYSTEM {
            return Err(Errno::ENOSPC);
        }
        if !self.alloc_chunk(ty)? {
            return Err(Errno::ENOSPC);
        }
        self.take(ty, n, n, false)?.map(|(a, _)| a).ok_or(Errno::ENOSPC)
    }

    /// Up to `len` bytes (a multiple of the sector size) for file data.
    pub(crate) fn alloc_data(&mut self, len: u64) -> Result<(u64, u64), Errno> {
        let ss = self.sh.sectorsize;
        if let Some(r) = self.take(kind::DATA, len, ss, false)? {
            return Ok(r);
        }
        // A new chunk if there is room for one, else whatever is left.
        self.alloc_chunk(kind::DATA)?;
        self.take(kind::DATA, len, ss, true)?.ok_or(Errno::ENOSPC)
    }

    /// `len` bytes (a multiple of the sector size) in one piece for file
    /// data, with a new chunk if no block group has room; `ENOSPC` if not even
    /// that gives room.
    pub(crate) fn alloc_data_exact(&mut self, len: u64) -> Result<u64, Errno> {
        let ss = self.sh.sectorsize;
        if let Some((a, _)) = self.take(kind::DATA, len, ss, false)? {
            return Ok(a);
        }
        self.alloc_chunk(kind::DATA)?;
        self.take(kind::DATA, len, ss, false)?.map(|(a, _)| a).ok_or(Errno::ENOSPC)
    }

    /// Frees a range this transaction allocated: it is free again once the
    /// transaction commits.
    pub(crate) fn unalloc(&mut self, start: u64) {
        if let Some(a) = self.allocs.iter_mut().find(|a| a.start == start && !a.dead) {
            a.dead = true;
        }
    }

    /// Puts back everything this transaction took (it is being dropped).
    pub(crate) fn undo_allocs(&mut self) {
        while let Some(a) = self.allocs.pop() {
            if let Some(g) = self.w.group_mut(a.start) {
                let _ = g.give(a.start, a.len);
            }
        }
        for start in self.new_groups.drain(..) {
            if let Some(i) = self.w.groups.iter().position(|g| g.start == start) {
                self.w.groups.remove(i);
            }
        }
    }

    /// Adds a chunk and block group of type `ty` (with the profile the
    /// volume's other groups of that type have), sized like Linux's: up to
    /// 1 GiB for data, 256 MiB for metadata, and no more than a tenth of the
    /// device. `false` if there is no room for one, and nothing changed;
    /// any error leaves the transaction unusable.
    fn alloc_chunk(&mut self, ty: u64) -> Result<bool, Errno> {
        let Some(flags) = self.w.groups.iter().find(|g| g.flags & kind::MASK == ty).map(|g| g.flags) else {
            return Ok(false);
        };
        let copies: u64 = if flags & profile::DUP != 0 { 2 } else { 1 };
        if flags & (profile::STRIPED | profile::MIRRORED) != 0 {
            return Ok(false);
        }
        let cap = if ty == kind::DATA { 1 << 30 } else { 256 << 20 };

        // The devices that may take it, the one with most room first.
        let mut cands: Vec<DevRoom> = Vec::new();
        let mut at = Key::new(1, item::DEV_ITEM, 0);
        while let Some((k, d)) = self.next_item(tree::CHUNK, at)? {
            if k.objectid != 1 || k.ty != item::DEV_ITEM {
                break;
            }
            at = crate::write::succ(k).ok_or(Errno::EIO)?;
            if self.w.no_alloc.contains(&k.offset) || !self.sh.has_dev(k.offset) {
                continue;
            }
            let total = le64(&d, 8)?;
            let gaps = self.dev_gaps(k.offset, total)?;
            try_push(&mut cands, DevRoom { devid: k.offset, total, gaps })?;
        }
        cands.sort_by_key(|c| core::cmp::Reverse(c.gaps.iter().map(|g| g.1).sum::<u64>()));

        // Shrink to what fits: one gap for both copies, else one per copy.
        let mut found: Option<(u64, u64, Vec<u64>)> = None;
        for DevRoom { devid, total, gaps } in &cands {
            let tenth = (total / 10) / CHUNK_ALIGN * CHUNK_ALIGN;
            let mut size = cap.min(tenth).max(8 << 20);
            let fits = |size: u64| -> Option<Vec<u64>> {
                if let Some(&(s, _)) = gaps.iter().find(|&&(_, l)| l >= size * copies) {
                    return Some((0..copies).map(|i| s + i * size).collect());
                }
                let found: Vec<u64> =
                    gaps.iter().filter(|&&(_, l)| l >= size).map(|&(s, _)| s).take(copies as usize).collect();
                (found.len() as u64 == copies).then_some(found)
            };
            let offsets = loop {
                if let Some(o) = fits(size) {
                    break Some(o);
                }
                size = (size / 2) / CHUNK_ALIGN * CHUNK_ALIGN;
                if size < (1 << 20) {
                    break None;
                }
            };
            if let Some(o) = offsets {
                found = Some((*devid, size, o));
                break;
            }
        }
        let Some((devid, size, offsets)) = found else { return Ok(false) };

        let logical =
            self.chunks().iter().map(|c| c.logical + c.length).max().unwrap_or(0).next_multiple_of(CHUNK_ALIGN);
        let mut stripes = Vec::new();
        for &o in &offsets {
            try_push(&mut stripes, Stripe { devid, offset: o })?;
        }
        let mut pending = Vec::new();
        pending.try_reserve_exact(offsets.len()).map_err(|_| Errno::ENOMEM)?;
        pending.extend_from_slice(&offsets);
        self.pending_chunks.try_reserve(1).map_err(|_| Errno::ENOMEM)?;

        // In memory: the chunk, for reads and writes, and the group.
        let chunk = Chunk { logical, length: size, ty: flags, stripe_len: 64 << 10, sub_stripes: 1, stripes };
        let mut free = Vec::new();
        try_push(&mut free, (logical, size))?;
        for (s, l) in super_ranges(&chunk) {
            carve(&mut free, s, l)?;
        }
        let mut map = match self.new_chunks.take() {
            Some(m) => m,
            None => self.base.chunks.try_clone()?,
        };
        let res = map.insert(chunk);
        self.new_chunks = Some(map);
        res?;
        let gi = self.w.groups.partition_point(|g| g.start < logical);
        self.w.groups.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        self.new_groups.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        self.w.groups.insert(gi, Group { start: logical, len: size, flags, used: 0, free });
        self.new_groups.push(logical);
        // Its items go in when the transaction commits: putting them in may
        // need the space it brings.
        self.pending_chunks.push(PendingChunk { logical, size, flags, devid, offsets: pending });
        Ok(true)
    }

    /// The free ranges of device `devid`, which is `total` bytes: between its
    /// device extents (and the chunks this transaction added), aligned for
    /// chunks.
    fn dev_gaps(&mut self, devid: u64, total: u64) -> Result<Vec<(u64, u64)>, Errno> {
        let mut gaps: Vec<(u64, u64)> = Vec::new();
        let mut pos = DEV_RESERVED;
        let mut at = Key::new(devid, item::DEV_EXTENT, 0);
        while let Some((k, data)) = self.next_item(tree::DEV, at)? {
            if k.objectid != devid || k.ty != item::DEV_EXTENT {
                break;
            }
            if k.offset > pos {
                try_push(&mut gaps, (pos, k.offset - pos))?;
            }
            pos = pos.max(k.offset.saturating_add(le64(&data, 24)?));
            at = crate::write::succ(k).ok_or(Errno::EIO)?;
        }
        if total > pos {
            try_push(&mut gaps, (pos, total - pos))?;
        }
        // Chunks this transaction added may not be in the device tree yet.
        for &logical in &self.new_groups {
            let c = self.chunks().find(logical, 1)?;
            for s in c.stripes.iter().filter(|s| s.devid == devid) {
                carve(&mut gaps, s.offset, c.length)?;
            }
        }
        for g in gaps.iter_mut() {
            let s = g.0.next_multiple_of(CHUNK_ALIGN);
            *g = (s, (g.0 + g.1).saturating_sub(s) / CHUNK_ALIGN * CHUNK_ALIGN);
        }
        Ok(gaps)
    }

    /// Puts the items of the chunks this transaction added into the chunk,
    /// device and block group trees.
    pub(crate) fn apply_pending_chunks(&mut self) -> Result<(), Errno> {
        while let Some(c) = self.pending_chunks.pop() {
            let devid = c.devid;
            let dev_key = Key::new(1, item::DEV_ITEM, devid);
            let mut dev_item = self.find(tree::CHUNK, dev_key)?.ok_or(Errno::EIO)?;
            let dev_uuid: [u8; 16] = crate::disk::array(&dev_item, 66)?;
            // The chunk item, as Linux writes it.
            let mut ci = Vec::new();
            ci.try_reserve_exact(48 + 32 * c.offsets.len()).map_err(|_| Errno::ENOMEM)?;
            ci.extend_from_slice(&c.size.to_le_bytes());
            ci.extend_from_slice(&tree::EXTENT.to_le_bytes());
            ci.extend_from_slice(&65536u64.to_le_bytes());
            ci.extend_from_slice(&c.flags.to_le_bytes());
            ci.extend_from_slice(&65536u32.to_le_bytes());
            ci.extend_from_slice(&65536u32.to_le_bytes());
            ci.extend_from_slice(&(self.sh.sectorsize as u32).to_le_bytes());
            ci.extend_from_slice(&(c.offsets.len() as u16).to_le_bytes());
            ci.extend_from_slice(&1u16.to_le_bytes());
            for &o in &c.offsets {
                ci.extend_from_slice(&devid.to_le_bytes());
                ci.extend_from_slice(&o.to_le_bytes());
                ci.extend_from_slice(&dev_uuid);
            }
            self.insert(tree::CHUNK, Key::new(tree::FIRST_CHUNK, item::CHUNK_ITEM, c.logical), &ci)?;
            for &o in &c.offsets {
                let mut de = [0u8; 48];
                put(&mut de, 0, &tree::CHUNK.to_le_bytes())?;
                put(&mut de, 8, &tree::FIRST_CHUNK.to_le_bytes())?;
                put(&mut de, 16, &c.logical.to_le_bytes())?;
                put(&mut de, 24, &c.size.to_le_bytes())?;
                put(&mut de, 32, &self.w.chunk_uuid)?;
                self.insert(tree::DEV, Key::new(devid, item::DEV_EXTENT, o), &de)?;
            }
            let used = le64(&dev_item, 16)? + c.size * c.offsets.len() as u64;
            put(&mut dev_item, 16, &used.to_le_bytes())?;
            self.update(tree::CHUNK, dev_key, &dev_item)?;
            let mut bg = [0u8; 24];
            put(&mut bg, 8, &tree::FIRST_CHUNK.to_le_bytes())?;
            put(&mut bg, 16, &c.flags.to_le_bytes())?;
            let bg_tree = self.w.bg_tree;
            self.insert(bg_tree, Key::new(c.logical, item::BLOCK_GROUP_ITEM, c.size), &bg)?;
        }
        Ok(())
    }
}

/// A chunk added in memory whose items are still to be inserted.
pub struct PendingChunk {
    logical: u64,
    size: u64,
    flags: u64,
    /// The device holding its stripes.
    devid: u64,
    /// Device offsets of its stripes.
    offsets: Vec<u64>,
}

impl PendingChunk {
    /// Its first logical address.
    pub fn logical(&self) -> u64 {
        self.logical
    }
}
