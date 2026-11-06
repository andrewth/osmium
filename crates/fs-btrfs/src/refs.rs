// SPDX-License-Identifier: GPL-2.0-only
//! The extent tree's references: a transaction's pending changes to the
//! reference counts of tree blocks and data extents, applied to the extent
//! items and the keyed references beside them.
//!
//! A tree block is referred to by its tree (`TREE_BLOCK_REF`, by the id in
//! the owner field of its parent) or by its parent block (`SHARED_BLOCK_REF`,
//! when the parent is flagged `FULL_BACKREF`). A data extent is referred to by
//! a file (`EXTENT_DATA_REF`, by tree, inode and offset) or by the leaf holding
//! the file extent item (`SHARED_DATA_REF`). The first reference of a new item
//! is stored in it, the rest as items of their own.

use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_push, try_zeroed};

use crate::csum;
use crate::disk::{Key, byte, item, le32, le64, put32, put64, tree};
use crate::write::{Tx, succ};

/// Extent item flags.
pub(crate) const EXTENT_DATA: u64 = 1;
pub(crate) const EXTENT_TREE_BLOCK: u64 = 2;
pub(crate) const EXTENT_FULL_BACKREF: u64 = 1 << 8;

/// Bytes of an extent item before its inline references.
const EXTENT_ITEM: usize = 24;

/// Bytes of an inline tree block reference (either kind).
const BLOCK_REF: usize = 9;

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

/// One referrer's net change.
#[derive(Clone, Copy)]
struct Net {
    root: u64,
    ino: u64,
    offset: u64,
    parent: u64,
    delta: i64,
}

impl Net {
    /// The inline reference for `count` references, type byte first.
    fn inline(&self, count: u32) -> Result<Vec<u8>, Errno> {
        let mut v = Vec::new();
        v.try_reserve_exact(29).map_err(|_| Errno::ENOMEM)?;
        if self.parent != 0 {
            v.push(item::SHARED_DATA_REF);
            v.extend_from_slice(&self.parent.to_le_bytes());
            v.extend_from_slice(&count.to_le_bytes());
        } else {
            v.push(item::EXTENT_DATA_REF);
            v.extend_from_slice(&data_ref(self.root, self.ino, self.offset, count));
        }
        Ok(v)
    }
}

/// Where the references start in the extent item `d` of a tree block, and
/// the size of the inline reference of type `ty`.
fn inline_size(ty: u8) -> Result<usize, Errno> {
    match ty {
        item::TREE_BLOCK_REF | item::SHARED_BLOCK_REF => Ok(BLOCK_REF),
        item::EXTENT_DATA_REF => Ok(29),
        item::SHARED_DATA_REF => Ok(13),
        _ => Err(Errno::EIO),
    }
}

/// The position of the inline block reference `(ty, offset)` in `d`, whose
/// references start at `from`.
fn find_block_ref(d: &[u8], from: usize, ty: u8, offset: u64) -> Result<Option<usize>, Errno> {
    let mut p = from;
    while p < d.len() {
        let t = byte(d, p)?;
        if t == ty && le64(d, p + 1)? == offset {
            return Ok(Some(p));
        }
        p += inline_size(t)?;
    }
    Ok(None)
}

impl<D: BlockDevice + Send + 'static> Tx<'_, D> {
    /// Adds `delta` to data extent `bytenr`'s keyed reference `r`; returns
    /// `false` if there is none to take from. Colliding references take the
    /// next free key offsets, so a reference is looked for among all of the
    /// extent's keyed references from its hash on.
    fn keyed_data_ref(&mut self, bytenr: u64, r: &Net) -> Result<bool, Errno> {
        if r.parent != 0 {
            let key = Key::new(bytenr, item::SHARED_DATA_REF, r.parent);
            let Some(d) = self.find(tree::EXTENT, key)? else {
                if r.delta < 0 {
                    return Ok(false);
                }
                let count = u32::try_from(r.delta).map_err(|_| Errno::EIO)?;
                self.insert(tree::EXTENT, key, &count.to_le_bytes())?;
                return Ok(true);
            };
            let count = le32(&d, 0)? as i64 + r.delta;
            match count {
                ..0 => return Err(Errno::EIO),
                0 => self.delete(tree::EXTENT, key)?,
                _ => self.update(tree::EXTENT, key, &u32::try_from(count).map_err(|_| Errno::EIO)?.to_le_bytes())?,
            }
            return Ok(true);
        }
        let (root, ino, offset, delta) = (r.root, r.ino, r.offset, r.delta);
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

    /// Applies `r` to the inline references of the data extent item `d`;
    /// `false` if it has none like it.
    fn inline_data_ref(d: &mut Vec<u8>, r: &Net) -> Result<bool, Errno> {
        let mut p = EXTENT_ITEM;
        while p < d.len() {
            let ty = byte(d, p)?;
            let size = inline_size(ty)?;
            let (same, count_at) = match ty {
                item::EXTENT_DATA_REF => (
                    r.parent == 0 && (le64(d, p + 1)?, le64(d, p + 9)?, le64(d, p + 17)?) == (r.root, r.ino, r.offset),
                    p + 25,
                ),
                item::SHARED_DATA_REF => (r.parent != 0 && le64(d, p + 1)? == r.parent, p + 9),
                _ => (false, 0),
            };
            if same {
                let count = le32(d, count_at)? as i64 + r.delta;
                match count {
                    ..0 => return Err(Errno::EIO),
                    0 => _ = d.drain(p..p + size),
                    _ => put32(d, count_at, u32::try_from(count).map_err(|_| Errno::EIO)?)?,
                }
                return Ok(true);
            }
            p += size;
        }
        Ok(false)
    }

    /// Applies the pending data extent reference changes to the extent tree.
    pub(crate) fn apply_data_refs(&mut self) -> Result<(), Errno> {
        let mut refs = core::mem::take(&mut self.data_refs);
        refs.sort_unstable_by_key(|r| (r.bytenr, r.parent, r.root, r.ino, r.offset));
        let mut i = 0;
        while let Some(first) = refs.get(i).copied() {
            let n = refs.get(i..).unwrap_or(&[]).iter().take_while(|r| r.bytenr == first.bytenr).count();
            let group = refs.get(i..i + n).ok_or(Errno::EIO)?;
            i += n;
            // Net change per referrer.
            let mut net: Vec<Net> = Vec::new();
            for r in group {
                match net.last_mut() {
                    Some(l) if (l.parent, l.root, l.ino, l.offset) == (r.parent, r.root, r.ino, r.offset) => {
                        l.delta += r.delta
                    }
                    _ => try_push(
                        &mut net,
                        Net { root: r.root, ino: r.ino, offset: r.offset, parent: r.parent, delta: r.delta },
                    )?,
                }
            }
            net.retain(|r| r.delta != 0);
            let new = group.iter().any(|r| r.new);
            let (bytenr, len) = (first.bytenr, first.len);
            let key = Key::new(bytenr, item::EXTENT_ITEM, len);
            if new {
                if net.iter().any(|r| r.delta < 0) {
                    return Err(Errno::EIO);
                }
                let total: i64 = net.iter().map(|r| r.delta).sum();
                let Some(head) = net.first().copied() else {
                    // Written and dropped in this transaction.
                    self.csum_delete(bytenr, len)?;
                    self.unalloc(bytenr);
                    continue;
                };
                let mut d = try_zeroed(EXTENT_ITEM)?;
                put64(&mut d, 0, total as u64)?;
                put64(&mut d, 8, self.transid)?;
                put64(&mut d, 16, EXTENT_DATA)?;
                let inline = head.inline(u32::try_from(head.delta).map_err(|_| Errno::EIO)?)?;
                d.try_reserve_exact(inline.len()).map_err(|_| Errno::ENOMEM)?;
                d.extend_from_slice(&inline);
                self.insert(tree::EXTENT, key, &d)?;
                for r in net.get(1..).unwrap_or(&[]) {
                    self.keyed_data_ref(bytenr, r)?;
                }
                continue;
            }
            let mut d = self.find(tree::EXTENT, key)?.ok_or(Errno::EIO)?;
            if le64(&d, 16)? & EXTENT_DATA == 0 {
                return Err(Errno::EIO);
            }
            let mut total = le64(&d, 0)? as i64;
            for r in &net {
                total += r.delta;
                // An inline reference, else a keyed one.
                if !Self::inline_data_ref(&mut d, r)? && !self.keyed_data_ref(bytenr, r)? {
                    return Err(Errno::EIO);
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

    /// The extent item of tree block `addr`: its key, data, and where its
    /// references start.
    fn block_item(&mut self, addr: u64, level: u8) -> Result<Option<(Key, Vec<u8>, usize)>, Errno> {
        let skinny = Key::new(addr, item::METADATA_ITEM, level as u64);
        if let Some(d) = self.find(tree::EXTENT, skinny)? {
            return Ok(Some((skinny, d, EXTENT_ITEM)));
        }
        let fat = Key::new(addr, item::EXTENT_ITEM, self.sh.nodesize as u64);
        Ok(self.find(tree::EXTENT, fat)?.map(|d| (fat, d, EXTENT_ITEM + Key::SIZE + 1)))
    }

    /// Applies the pending tree block reference changes to the extent tree.
    pub(crate) fn apply_tree_refs(&mut self) -> Result<(), Errno> {
        for (addr, level) in core::mem::take(&mut self.flag_ops) {
            let (key, mut d, _) = self.block_item(addr, level)?.ok_or(Errno::EIO)?;
            let flags = le64(&d, 16)?;
            if flags & EXTENT_FULL_BACKREF == 0 {
                put64(&mut d, 16, flags | EXTENT_FULL_BACKREF)?;
                self.update(tree::EXTENT, key, &d)?;
            }
        }
        let mut refs = core::mem::take(&mut self.tree_refs);
        // Stable, so that a block's changes keep their order.
        refs.sort_by_key(|r| r.addr);
        let mut i = 0;
        while let Some(first) = refs.get(i).copied() {
            let n = refs.get(i..).unwrap_or(&[]).iter().take_while(|r| r.addr == first.addr).count();
            let group = refs.get(i..i + n).ok_or(Errno::EIO)?;
            i += n;
            let addr = first.addr;
            let (key, mut d, from, exists) = match self.block_item(addr, first.level)? {
                Some((k, d, from)) => (k, d, from, true),
                None => {
                    let mut d = try_zeroed(EXTENT_ITEM)?;
                    put64(&mut d, 8, self.transid)?;
                    put64(&mut d, 16, EXTENT_TREE_BLOCK)?;
                    (Key::new(addr, item::METADATA_ITEM, first.level as u64), d, EXTENT_ITEM, false)
                }
            };
            let mut count = le64(&d, 0)?;
            // Adds first, so that a block never sits at no references between.
            for r in group.iter().filter(|r| r.add) {
                let (ty, offset) =
                    if r.parent != 0 { (item::SHARED_BLOCK_REF, r.parent) } else { (item::TREE_BLOCK_REF, r.owner) };
                if count == 0 && d.len() == from {
                    d.try_reserve_exact(BLOCK_REF).map_err(|_| Errno::ENOMEM)?;
                    d.push(ty);
                    d.extend_from_slice(&offset.to_le_bytes());
                } else if find_block_ref(&d, from, ty, offset)?.is_some() {
                    return Err(Errno::EIO);
                } else {
                    self.insert(tree::EXTENT, Key::new(addr, ty, offset), &[])?;
                }
                count += 1;
            }
            for r in group.iter().filter(|r| !r.add) {
                let (ty, offset) =
                    if r.parent != 0 { (item::SHARED_BLOCK_REF, r.parent) } else { (item::TREE_BLOCK_REF, r.owner) };
                match find_block_ref(&d, from, ty, offset)? {
                    Some(p) => _ = d.drain(p..p + BLOCK_REF),
                    None => self.delete(tree::EXTENT, Key::new(addr, ty, offset)).map_err(|e| match e {
                        Errno::ENOENT => Errno::EIO,
                        e => e,
                    })?,
                }
                count = count.checked_sub(1).ok_or(Errno::EIO)?;
            }
            if count == 0 {
                if exists {
                    self.delete(tree::EXTENT, key)?;
                }
                continue;
            }
            put64(&mut d, 0, count)?;
            if exists {
                self.update(tree::EXTENT, key, &d)?;
            } else {
                self.insert(tree::EXTENT, key, &d)?;
            }
        }
        Ok(())
    }
}
