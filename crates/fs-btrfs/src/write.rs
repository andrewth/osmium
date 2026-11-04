//! Transactions: copy-on-write edits of the trees.
//!
//! A [`Tx`] copies each tree block it changes to a newly allocated address
//! (keeping its decoded form in memory), records the reference changes that
//! implies, and on commit brings the extent tree, the block groups, the free
//! space tree and the root items up to date before writing the new blocks and
//! then the superblock. Until the superblock is written nothing the last
//! commit points at has changed, so a transaction that fails is dropped
//! without a trace on disk.

use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_push, try_to_vec};

use crate::disk::{Key, item, le64, tree};
use crate::node::{Body, ITEM, Item, PTR, Ptr, TNode};
use crate::{Shared, State, tree::ChunkMap};

/// Commit iterations before a transaction that will not settle is abandoned.
pub const MAX_ROUNDS: usize = 64;

/// A tree's root during a transaction.
#[derive(Clone, Copy)]
pub struct RootPtr {
    /// The tree.
    pub id: u64,
    /// Its root block's address and level now.
    pub addr: u64,
    /// Its level now.
    pub level: u8,
    /// Address when the transaction began, to tell whether it moved.
    pub orig: u64,
    /// Blocks written at or before this generation may be shared with a
    /// snapshot.
    pub last_snapshot: u64,
}

/// A pending change to a tree block's reference.
#[derive(Clone, Copy)]
pub struct TreeRef {
    /// The block.
    pub addr: u64,
    /// Its tree.
    pub owner: u64,
    /// Its level.
    pub level: u8,
    /// `true` for a new block, `false` for one dropped.
    pub add: bool,
}

/// A pending change to a data extent's reference by `(root, ino, offset)`.
#[derive(Clone, Copy)]
pub struct DataRef {
    /// The extent's logical address.
    pub bytenr: u64,
    /// Its length on disk.
    pub len: u64,
    /// The subvolume referring to it.
    pub root: u64,
    /// The inode.
    pub ino: u64,
    /// The file offset minus the offset into the extent.
    pub offset: u64,
    /// The change in the count.
    pub delta: i64,
    /// Whether this transaction allocated the extent.
    pub new: bool,
}

/// A range allocated in this transaction.
#[derive(Clone, Copy)]
pub struct Alloc {
    /// Start.
    pub start: u64,
    /// Length.
    pub len: u64,
    /// Freed again in this transaction: free once it commits.
    pub dead: bool,
}

/// The write side of a mounted volume.
pub struct Writer {
    /// The superblock as last written.
    pub sb: Vec<u8>,
    /// The chunk tree's UUID, which every tree block carries.
    pub chunk_uuid: [u8; 16],
    /// Block groups, by start.
    pub groups: Vec<crate::space::Group>,
    /// Ranges freed by a commit that a reader of an older state may still read.
    pub limbo: Vec<(u64, u64)>,
    /// Where dropped states leave the ranges in `limbo` they no longer need.
    pub release: Arc<osmium_sync::SpinLock<Vec<(u64, u64)>>>,
    /// The next free inode number, per tree.
    pub next_ino: Vec<(u64, u64)>,
    /// The tree holding the block group items (extent tree or block group tree).
    pub bg_tree: u64,
    /// Whether the volume has a free space tree.
    pub fst: bool,
    /// Unlinked inodes still open: deleted when the last node goes.
    pub orphans: Vec<(u64, u64)>,
    /// Set if a commit failed after it began writing the superblock; no
    /// more writes are attempted.
    pub broken: bool,
    /// Commits since the superblock was last written: their blocks are on the
    /// device but nothing points at them yet.
    pub deferred: u32,
    /// Ranges the deferred commits freed that the last superblock written
    /// still uses: not reusable before the next superblock replaces it.
    pub held: Vec<(u64, u64)>,
    /// Ranges the deferred commits allocated, sorted and apart: no superblock
    /// uses them, so freeing one needs no waiting for one.
    pub fresh: Vec<(u64, u64)>,
    /// Open [`BtrfsFs::batch`](crate::BtrfsFs::batch) calls.
    pub batch_depth: u32,
    /// Commits to defer at most (`MountOptions::commit_batch`).
    pub commit_batch: u32,
}

impl Writer {
    /// Whether all of `start..start + len` was allocated by a deferred commit.
    pub fn is_fresh(&self, start: u64, len: u64) -> bool {
        let i = self.fresh.partition_point(|r| r.0 <= start);
        i.checked_sub(1)
            .and_then(|i| self.fresh.get(i))
            .is_some_and(|r| start.checked_add(len).is_some_and(|end| end <= r.0.saturating_add(r.1)))
    }

    /// Adds `r` to `fresh`, whose room is reserved already; merges what touches.
    pub fn add_fresh(&mut self, r: (u64, u64)) {
        if r.1 == 0 {
            return;
        }
        let at = self.fresh.partition_point(|x| x.0 < r.0);
        self.fresh.insert(at, r);
        // Merge in place: `out` is how many are kept.
        let mut out = 0usize;
        for i in 0..self.fresh.len() {
            let Some(&(s, l)) = self.fresh.get(i) else { break };
            if let Some(last) = out.checked_sub(1).and_then(|o| self.fresh.get_mut(o))
                && last.0.saturating_add(last.1) >= s
            {
                last.1 = last.1.max(s.saturating_add(l).saturating_sub(last.0));
                continue;
            }
            if let Some(slot) = self.fresh.get_mut(out) {
                *slot = (s, l);
            }
            out += 1;
        }
        self.fresh.truncate(out);
    }
}

/// One transaction.
pub struct Tx<'a, D: BlockDevice + Send + 'static> {
    pub(crate) sh: &'a Shared<D>,
    pub(crate) w: &'a mut Writer,
    pub(crate) base: Arc<State>,
    /// This transaction's generation.
    pub transid: u64,
    /// The chunk map, copied if this transaction adds a chunk.
    pub(crate) new_chunks: Option<ChunkMap>,
    /// Blocks changed, by address.
    pub(crate) dirty: Vec<TNode>,
    /// Committed blocks read and decoded, by address.
    clean: Vec<TNode>,
    pub(crate) roots: Vec<RootPtr>,
    pub(crate) tree_refs: Vec<TreeRef>,
    pub(crate) data_refs: Vec<DataRef>,
    pub(crate) allocs: Vec<Alloc>,
    /// Committed ranges freed by this transaction.
    pub(crate) pinned: Vec<(u64, u64)>,
    /// Block groups this transaction created, by start.
    pub(crate) new_groups: Vec<u64>,
    /// Device bytes taken by new chunks.
    pub(crate) dev_used: u64,
    /// Tree edits, to tell when a commit round changed nothing.
    pub(crate) edits: u64,
    /// Chunks added in memory, their items still to insert.
    pub(crate) pending_chunks: Vec<crate::space::PendingChunk>,
    /// Whether this transaction frees space, and may use the metadata reserve.
    pub(crate) frees: bool,
    /// Inodes this transaction made orphans, and orphans it deleted.
    pub(crate) orphans_added: Vec<(u64, u64)>,
    pub(crate) orphans_removed: Vec<(u64, u64)>,
    /// Incompatible feature flags this transaction's data needs set.
    pub(crate) incompat: u64,
    /// Whether to leave the superblock for a later [`Shared::sync_locked`].
    pub(crate) defer: bool,
}

/// The key just after `k`.
pub fn succ(k: Key) -> Option<Key> {
    if let Some(o) = k.offset.checked_add(1) {
        return Some(Key::new(k.objectid, k.ty, o));
    }
    if let Some(t) = k.ty.checked_add(1) {
        return Some(Key::new(k.objectid, t, 0));
    }
    Some(Key::new(k.objectid.checked_add(1)?, 0, 0))
}

impl<'a, D: BlockDevice + Send + 'static> Tx<'a, D> {
    pub(crate) fn new(sh: &'a Shared<D>, w: &'a mut Writer, base: Arc<State>) -> Self {
        let transid = base.generation + 1;
        Tx {
            sh,
            w,
            base,
            transid,
            new_chunks: None,
            dirty: Vec::new(),
            clean: Vec::new(),
            roots: Vec::new(),
            tree_refs: Vec::new(),
            data_refs: Vec::new(),
            allocs: Vec::new(),
            pinned: Vec::new(),
            new_groups: Vec::new(),
            dev_used: 0,
            edits: 0,
            pending_chunks: Vec::new(),
            frees: false,
            orphans_added: Vec::new(),
            orphans_removed: Vec::new(),
            incompat: 0,
            defer: false,
        }
    }

    /// The chunk map as of this transaction.
    pub(crate) fn chunks(&self) -> &ChunkMap {
        self.new_chunks.as_ref().unwrap_or(&self.base.chunks)
    }

    /// Bytes of items a leaf can hold.
    pub(crate) fn leaf_space(&self) -> usize {
        self.sh.nodesize - crate::disk::header::SIZE
    }

    fn max_ptrs(&self) -> usize {
        self.leaf_space() / PTR
    }

    fn dirty_at(&self, addr: u64) -> Option<usize> {
        self.dirty.binary_search_by_key(&addr, |n| n.addr).ok()
    }

    pub(crate) fn dirty_mut(&mut self, addr: u64) -> Result<&mut TNode, Errno> {
        let i = self.dirty_at(addr).ok_or(Errno::EIO)?;
        self.dirty.get_mut(i).ok_or(Errno::EIO)
    }

    fn add_dirty(&mut self, n: TNode) -> Result<(), Errno> {
        let at = self.dirty.partition_point(|d| d.addr < n.addr);
        self.dirty.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        self.dirty.insert(at, n);
        Ok(())
    }

    /// The block at `addr`, as this transaction sees it.
    pub(crate) fn load(&mut self, addr: u64) -> Result<&TNode, Errno> {
        if let Some(i) = self.dirty_at(addr) {
            return self.dirty.get(i).ok_or(Errno::EIO);
        }
        let i = match self.clean.binary_search_by_key(&addr, |n| n.addr) {
            Ok(i) => i,
            Err(i) => {
                let b = self.sh.block(self.chunks(), addr)?;
                let n = TNode::decode(&b)?;
                if n.addr != addr {
                    return Err(Errno::EIO);
                }
                self.clean.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                self.clean.insert(i, n);
                i
            }
        };
        self.clean.get(i).ok_or(Errno::EIO)
    }

    /// The root of tree `id`.
    pub(crate) fn root(&mut self, id: u64) -> Result<RootPtr, Errno> {
        if let Some(r) = self.roots.iter().find(|r| r.id == id) {
            return Ok(*r);
        }
        let (addr, level, last_snapshot) = match id {
            tree::ROOT => (self.base.root_tree.0, self.base.root_tree.1, 0),
            tree::CHUNK => (self.base.chunk_root.0, self.base.chunk_root.1, 0),
            _ => {
                let key = Key::new(id, item::ROOT_ITEM, 0);
                let (k, data) = self.next_item(tree::ROOT, key)?.ok_or(Errno::ENOENT)?;
                if k.objectid != id || k.ty != item::ROOT_ITEM {
                    return Err(Errno::ENOENT);
                }
                if id == tree::FS || id >= tree::FIRST_FREE {
                    // A read-only subvolume (`btrfs property set ro`).
                    if le64(&data, 208)? & 1 != 0 {
                        return Err(Errno::EROFS);
                    }
                }
                (le64(&data, 176)?, crate::disk::byte(&data, 238)?, le64(&data, 200)?)
            }
        };
        let r = RootPtr { id, addr, level, orig: addr, last_snapshot };
        try_push(&mut self.roots, r)?;
        Ok(r)
    }

    fn set_root(&mut self, id: u64, addr: u64, level: u8) -> Result<(), Errno> {
        let r = self.roots.iter_mut().find(|r| r.id == id).ok_or(Errno::EIO)?;
        r.addr = addr;
        r.level = level;
        Ok(())
    }

    /// The first item at or after `key` in tree `id`.
    pub(crate) fn next_item(&mut self, id: u64, key: Key) -> Result<Option<(Key, Vec<u8>)>, Errno> {
        let r = self.root(id)?;
        self.first_ge(r.addr, key, 0)
    }

    /// The last item at or before `key` in tree `id`.
    pub(crate) fn prev_item(&mut self, id: u64, key: Key) -> Result<Option<(Key, Vec<u8>)>, Errno> {
        let r = self.root(id)?;
        self.last_le(r.addr, key, 0)
    }

    /// The data of the item with exactly `key` in tree `id`.
    pub(crate) fn find(&mut self, id: u64, key: Key) -> Result<Option<Vec<u8>>, Errno> {
        Ok(self.next_item(id, key)?.filter(|(k, _)| *k == key).map(|(_, d)| d))
    }

    fn first_ge(&mut self, addr: u64, key: Key, depth: usize) -> Result<Option<(Key, Vec<u8>)>, Errno> {
        if depth > 8 {
            return Err(Errno::EIO);
        }
        let children = match &self.load(addr)?.body {
            Body::Leaf(items) => {
                let i = items.partition_point(|it| it.key < key);
                return match items.get(i) {
                    Some(it) => Ok(Some((it.key, try_to_vec(&it.data)?))),
                    None => Ok(None),
                };
            }
            Body::Node(ptrs) => {
                let start = ptrs.partition_point(|p| p.key <= key).saturating_sub(1);
                child_addrs(ptrs.get(start..).unwrap_or(&[]))?
            }
        };
        for c in children {
            if let Some(found) = self.first_ge(c, key, depth + 1)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    fn last_le(&mut self, addr: u64, key: Key, depth: usize) -> Result<Option<(Key, Vec<u8>)>, Errno> {
        if depth > 8 {
            return Err(Errno::EIO);
        }
        let children = match &self.load(addr)?.body {
            Body::Leaf(items) => {
                let i = items.partition_point(|it| it.key <= key);
                return match i.checked_sub(1).and_then(|i| items.get(i)) {
                    Some(it) => Ok(Some((it.key, try_to_vec(&it.data)?))),
                    None => Ok(None),
                };
            }
            Body::Node(ptrs) => {
                let end = ptrs.partition_point(|p| p.key <= key);
                child_addrs(ptrs.get(..end).unwrap_or(&[]))?
            }
        };
        for c in children.into_iter().rev() {
            if let Some(found) = self.last_le(c, key, depth + 1)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// A new, empty block of tree `owner` at `level`.
    fn new_block(&mut self, owner: u64, level: u8, body: Body) -> Result<u64, Errno> {
        let addr = self.alloc_meta(owner)?;
        let n = TNode { addr, owner, level, generation: self.transid, body };
        if let Err(e) = self.add_dirty(n) {
            self.unalloc(addr);
            return Err(e);
        }
        try_push(&mut self.tree_refs, TreeRef { addr, owner, level, add: true })?;
        Ok(addr)
    }

    /// Lets go of block `addr` of tree `owner`.
    pub(crate) fn free_block(&mut self, addr: u64, owner: u64, level: u8) -> Result<(), Errno> {
        let fresh = self.allocs.iter().any(|a| a.start == addr && !a.dead);
        if fresh {
            if let Some(i) = self.dirty_at(addr) {
                self.dirty.remove(i);
            }
            match self.tree_refs.iter().position(|r| r.addr == addr && r.add) {
                Some(i) => _ = self.tree_refs.remove(i),
                None => try_push(&mut self.tree_refs, TreeRef { addr, owner, level, add: false })?,
            }
            self.unalloc(addr);
        } else {
            try_push(&mut self.tree_refs, TreeRef { addr, owner, level, add: false })?;
            try_push(&mut self.pinned, (addr, self.sh.nodesize as u64))?;
        }
        Ok(())
    }

    /// Copies block `addr` of tree `id` for writing, unless this transaction
    /// already has; returns its address from now on.
    fn cow(&mut self, id: u64, addr: u64, level: u8) -> Result<u64, Errno> {
        if self.dirty_at(addr).is_some() {
            return Ok(addr);
        }
        // Decoded already if it was read in this transaction.
        let mut n = match self.clean.binary_search_by_key(&addr, |n| n.addr) {
            Ok(i) => self.clean.remove(i),
            Err(_) => TNode::decode(&self.sh.block(self.chunks(), addr)?)?,
        };
        if n.addr != addr {
            return Err(Errno::EIO);
        }
        let r = self.root(id)?;
        // A block another tree may share (a snapshot's) needs reference
        // counting this driver does not do.
        if n.owner != id || n.level != level || (r.last_snapshot != 0 && n.generation <= r.last_snapshot) {
            return Err(Errno::EOPNOTSUPP);
        }
        let new = self.alloc_meta(id)?;
        n.addr = new;
        n.generation = self.transid;
        if let Err(e) = self.add_dirty(n) {
            self.unalloc(new);
            return Err(e);
        }
        try_push(&mut self.tree_refs, TreeRef { addr: new, owner: id, level, add: true })?;
        self.free_block(addr, id, level)?;
        Ok(new)
    }

    /// Copies tree `id`'s root for writing.
    fn cow_root(&mut self, id: u64) -> Result<(u64, u8), Errno> {
        let r = self.root(id)?;
        let new = self.cow(id, r.addr, r.level)?;
        if new != r.addr {
            self.set_root(id, new, r.level)?;
        }
        Ok((new, r.level))
    }

    /// Descends tree `id` to the leaf for `key`, copying every block on the
    /// way, and returns the path: each block and the slot taken, the leaf's
    /// slot being where `key` is or would go. With `extra`, the leaf is split
    /// as needed to have that many bytes free, and full nodes on the way are
    /// split beforehand so that a split below always has room in its parent.
    pub(crate) fn path(&mut self, id: u64, key: Key, extra: usize) -> Result<Vec<(u64, usize)>, Errno> {
        if extra > self.leaf_space() {
            return Err(Errno::E2BIG);
        }
        let mut path: Vec<(u64, usize)> = Vec::new();
        path.try_reserve(9).map_err(|_| Errno::ENOMEM)?;
        'retry: for _ in 0..64 {
            path.clear();
            let (mut addr, mut level) = self.cow_root(id)?;
            loop {
                let max_ptrs = self.max_ptrs();
                let space = self.leaf_space();
                let n = self.dirty_mut(addr)?;
                match &n.body {
                    Body::Node(ptrs) => {
                        if extra > 0 && ptrs.len() >= max_ptrs - 1 {
                            self.split_node(id, &path, addr)?;
                            continue 'retry;
                        }
                        let slot = ptrs.partition_point(|p| p.key <= key).saturating_sub(1);
                        let child = ptrs.get(slot).ok_or(Errno::EIO)?.addr;
                        let below = level.checked_sub(1).ok_or(Errno::EIO)?;
                        let new = self.cow(id, child, below)?;
                        let transid = self.transid;
                        let p = self.dirty_mut(addr)?.ptrs_mut()?.get_mut(slot).ok_or(Errno::EIO)?;
                        p.addr = new;
                        p.generation = transid;
                        path.push((addr, slot));
                        addr = new;
                        level = below;
                    }
                    Body::Leaf(items) => {
                        let slot = items.partition_point(|it| it.key < key);
                        let used: usize = items.iter().map(|it| ITEM + it.data.len()).sum();
                        if extra > 0 && used + extra > space {
                            self.split_leaf(id, &path, addr, slot, key)?;
                            continue 'retry;
                        }
                        path.push((addr, slot));
                        return Ok(path);
                    }
                }
            }
        }
        Err(Errno::EIO)
    }

    /// Splits node `addr` (whose parents are `path`) in two.
    fn split_node(&mut self, id: u64, path: &[(u64, usize)], addr: u64) -> Result<(), Errno> {
        let (parent, slot) = self.parent_for_split(id, path, addr)?;
        let n = self.dirty_mut(addr)?;
        let level = n.level;
        let ptrs = n.ptrs_mut()?;
        let mid = ptrs.len() / 2;
        let mut right = Vec::new();
        right.try_reserve_exact(ptrs.len() - mid).map_err(|_| Errno::ENOMEM)?;
        let first = ptrs.get(mid).ok_or(Errno::EIO)?.key;
        let new = self.new_block(id, level, Body::Node(Vec::new()))?;
        let ptrs = self.dirty_mut(addr)?.ptrs_mut()?;
        right.extend(ptrs.drain(mid..));
        *self.dirty_mut(new)?.ptrs_mut()? = right;
        self.insert_ptr(parent, slot + 1, Ptr { key: first, addr: new, generation: self.transid })
    }

    /// Splits leaf `addr` so that an item for `key` at `slot` has room.
    fn split_leaf(&mut self, id: u64, path: &[(u64, usize)], addr: u64, slot: usize, key: Key) -> Result<(), Errno> {
        let (parent, pslot) = self.parent_for_split(id, path, addr)?;
        let items = self.dirty_mut(addr)?.items()?;
        let len = items.len();
        let mid = if slot == len {
            len
        } else if slot == 0 {
            0
        } else {
            let total: usize = items.iter().map(|i| ITEM + i.data.len()).sum();
            let mut acc = 0;
            let mut m = len;
            for (i, it) in items.iter().enumerate() {
                acc += ITEM + it.data.len();
                if acc * 2 >= total {
                    m = i + 1;
                    break;
                }
            }
            m.clamp(1, len - 1)
        };
        let first = items.get(mid).map_or(key, |i| i.key);
        let mut right = Vec::new();
        right.try_reserve_exact(len - mid).map_err(|_| Errno::ENOMEM)?;
        let new = self.new_block(id, 0, Body::Leaf(Vec::new()))?;
        right.extend(self.dirty_mut(addr)?.items_mut()?.drain(mid..));
        *self.dirty_mut(new)?.items_mut()? = right;
        self.insert_ptr(parent, pslot + 1, Ptr { key: first, addr: new, generation: self.transid })
    }

    /// The parent of `addr` and its slot there; a new root above it if it is
    /// the root.
    fn parent_for_split(&mut self, id: u64, path: &[(u64, usize)], addr: u64) -> Result<(u64, usize), Errno> {
        if let Some(&(parent, slot)) = path.last() {
            return Ok((parent, slot));
        }
        let n = self.dirty_mut(addr)?;
        let level = n.level.checked_add(1).filter(|&l| l < 8).ok_or(Errno::ENOSPC)?;
        let first = n.first_key().unwrap_or(Key::new(0, 0, 0));
        let mut ptrs = Vec::new();
        try_push(&mut ptrs, Ptr { key: first, addr, generation: self.transid })?;
        let root = self.new_block(id, level, Body::Node(ptrs))?;
        self.set_root(id, root, level)?;
        Ok((root, 0))
    }

    fn insert_ptr(&mut self, node: u64, slot: usize, p: Ptr) -> Result<(), Errno> {
        let ptrs = self.dirty_mut(node)?.ptrs_mut()?;
        if slot > ptrs.len() {
            return Err(Errno::EIO);
        }
        ptrs.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        ptrs.insert(slot, p);
        Ok(())
    }

    /// After the first key of the block at the end of `path` changed, fixes
    /// the keys in its parents.
    fn fix_keys(&mut self, path: &[(u64, usize)]) -> Result<(), Errno> {
        let Some(&(leaf, _)) = path.last() else { return Ok(()) };
        let Some(mut key) = self.dirty_mut(leaf)?.first_key() else { return Ok(()) };
        for &(node, slot) in path.iter().rev().skip(1) {
            let p = self.dirty_mut(node)?.ptrs_mut()?.get_mut(slot).ok_or(Errno::EIO)?;
            p.key = key;
            if slot != 0 {
                break;
            }
            key = self.dirty_mut(node)?.first_key().ok_or(Errno::EIO)?;
        }
        Ok(())
    }

    /// Inserts item `key` with `data` into tree `id`; `EEXIST` if present.
    pub(crate) fn insert(&mut self, id: u64, key: Key, data: &[u8]) -> Result<(), Errno> {
        let mut v = Vec::new();
        v.try_reserve_exact(data.len()).map_err(|_| Errno::ENOMEM)?;
        v.extend_from_slice(data);
        let path = self.path(id, key, ITEM + data.len())?;
        let &(leaf, slot) = path.last().ok_or(Errno::EIO)?;
        let items = self.dirty_mut(leaf)?.items_mut()?;
        if items.get(slot).is_some_and(|i| i.key == key) {
            return Err(Errno::EEXIST);
        }
        items.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        items.insert(slot, Item { key, data: v });
        self.edits += 1;
        if slot == 0 {
            self.fix_keys(&path)?;
        }
        Ok(())
    }

    /// Replaces the data of item `key` of tree `id`, which must exist.
    pub(crate) fn update(&mut self, id: u64, key: Key, data: &[u8]) -> Result<(), Errno> {
        let path = self.path(id, key, 0)?;
        let &(leaf, slot) = path.last().ok_or(Errno::EIO)?;
        let space = self.leaf_space();
        let items = self.dirty_mut(leaf)?.items_mut()?;
        let used: usize = items.iter().map(|i| ITEM + i.data.len()).sum();
        let it = items.get_mut(slot).filter(|i| i.key == key).ok_or(Errno::ENOENT)?;
        if it.data == data {
            return Ok(());
        }
        if data.len() <= it.data.len() || used + data.len() - it.data.len() <= space {
            it.data.clear();
            it.data.try_reserve_exact(data.len()).map_err(|_| Errno::ENOMEM)?;
            it.data.extend_from_slice(data);
            self.edits += 1;
            return Ok(());
        }
        // Too big for its leaf: move it to one with room.
        self.delete(id, key)?;
        self.insert(id, key, data)
    }

    /// Inserts or replaces item `key` of tree `id`.
    pub(crate) fn put(&mut self, id: u64, key: Key, data: &[u8]) -> Result<(), Errno> {
        if self.find(id, key)?.is_some() { self.update(id, key, data) } else { self.insert(id, key, data) }
    }

    /// Deletes item `key` of tree `id`; `ENOENT` if absent.
    pub(crate) fn delete(&mut self, id: u64, key: Key) -> Result<(), Errno> {
        let mut path = self.path(id, key, 0)?;
        let &(leaf, slot) = path.last().ok_or(Errno::EIO)?;
        let items = self.dirty_mut(leaf)?.items_mut()?;
        if !items.get(slot).is_some_and(|i| i.key == key) {
            return Err(Errno::ENOENT);
        }
        items.remove(slot);
        let empty = items.is_empty();
        self.edits += 1;
        if !empty {
            if slot == 0 {
                self.fix_keys(&path)?;
            }
            return Ok(());
        }
        // Take empty blocks out of their parents; an empty root leaf stays.
        while let Some((node, _)) = path.pop() {
            let Some(&(parent, pslot)) = path.last() else { break };
            let n = self.dirty_mut(node)?;
            let (owner, level) = (n.owner, n.level);
            self.dirty_mut(parent)?.ptrs_mut()?.remove(pslot);
            self.free_block(node, owner, level)?;
            let p = self.dirty_mut(parent)?;
            if p.len() != 0 {
                if pslot == 0 {
                    self.fix_keys(&path)?;
                }
                break;
            }
            if path.len() == 1 {
                // The root lost its last child: the tree is empty.
                let (owner, level) = (p.owner, p.level);
                let leaf = self.new_block(id, 0, Body::Leaf(Vec::new()))?;
                self.free_block(parent, owner, level)?;
                self.set_root(id, leaf, 0)?;
                break;
            }
        }
        Ok(())
    }

    /// Deletes every item of tree `id` from `from` up to and including `to`.
    pub(crate) fn delete_range(&mut self, id: u64, from: Key, to: Key) -> Result<(), Errno> {
        let mut at = from;
        while let Some((k, _)) = self.next_item(id, at)? {
            if k > to {
                break;
            }
            self.delete(id, k)?;
            at = match succ(k) {
                Some(n) => n,
                None => break,
            };
        }
        Ok(())
    }
}

/// The child addresses of `ptrs`.
fn child_addrs(ptrs: &[Ptr]) -> Result<Vec<u64>, Errno> {
    let mut v = Vec::new();
    v.try_reserve_exact(ptrs.len()).map_err(|_| Errno::ENOMEM)?;
    v.extend(ptrs.iter().map(|p| p.addr));
    Ok(v)
}
