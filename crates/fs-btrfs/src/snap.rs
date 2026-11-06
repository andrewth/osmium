//! Subvolumes and snapshots: creating them, and deleting them, which unlinks
//! the subvolume at once and then drops its tree a few blocks per transaction.
//!
//! A snapshot is a copy of the source's root block whose children gain a
//! reference for the new tree (see the `cow` method for what a later write
//! to either tree does with the blocks they share). Dropping a tree walks it
//! the way Linux does: blocks that only it refers to are freed, shared ones
//! lose its reference, and a shared block the tree owns is first given
//! references by block address (`FULL_BACKREF`) along with the blocks below it
//! that it owns, so that the trees still using them can copy them later. The
//! walk's position is kept in the root item (`drop_progress`, `drop_level`)
//! between transactions, so that a crash, or Linux, can carry on.

use alloc::vec::Vec;

use osmium_fs::{Errno, FileKind};
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_push, try_to_vec};

use crate::disk::{Key, byte, item, le32, le64, put, put32, put64, tree};
use crate::node::{Body, Ptr, TNode};
use crate::ops::{ft_of, ino, put_time};
use crate::write::{RefMode, Tx};
use crate::xxhash::xxh64;

/// Offsets in a root item.
pub(crate) mod root {
    pub const GENERATION: usize = 160;
    pub const DIRID: usize = 168;
    pub const BYTENR: usize = 176;
    pub const BYTES_USED: usize = 192;
    pub const LAST_SNAPSHOT: usize = 200;
    pub const FLAGS: usize = 208;
    pub const REFS: usize = 216;
    pub const DROP_PROGRESS: usize = 220;
    pub const DROP_LEVEL: usize = 237;
    pub const LEVEL: usize = 238;
    pub const GENERATION_V2: usize = 239;
    pub const UUID: usize = 247;
    pub const PARENT_UUID: usize = 263;
    pub const RECEIVED_UUID: usize = 279;
    pub const CTRANSID: usize = 295;
    pub const OTRANSID: usize = 303;
    pub const STRANSID: usize = 311;
    pub const RTRANSID: usize = 319;
    pub const CTIME: usize = 327;
    pub const OTIME: usize = 339;
    pub const STIME: usize = 351;
    pub const RTIME: usize = 363;
    pub const LEN: usize = 439;
    /// `BTRFS_ROOT_SUBVOL_RDONLY`.
    pub const RDONLY: u64 = 1;
}

/// Blocks and extents one transaction of a tree drop looks at, about.
const DROP_BUDGET: usize = 256;

/// A node of the tree being dropped, partly walked.
struct Frame {
    addr: u64,
    level: u8,
    /// The tree that owns the block.
    owner: u64,
    /// Whether the block's children are referred to by its address.
    full: bool,
    ptrs: Vec<Ptr>,
    /// The child to look at next; while that one is being walked, the frame
    /// above it.
    slot: usize,
}

impl<D: BlockDevice + Send + 'static> Tx<'_, D> {
    /// A UUID for subvolume `id`, made from this volume's, the transaction and
    /// the time.
    fn new_uuid(&self, id: u64) -> Result<[u8; 16], Errno> {
        let now = self.sh.now();
        let mut seed = [0u8; 40];
        put(&mut seed, 0, &self.sh.fsid)?;
        put64(&mut seed, 16, id)?;
        put64(&mut seed, 24, self.transid)?;
        put64(&mut seed, 32, now.sec as u64 ^ (now.nsec as u64) << 32)?;
        let a = xxh64(&seed, 0x6f73_6d69_756d);
        let b = xxh64(&seed, a);
        let mut u = [0u8; 16];
        put64(&mut u, 0, a)?;
        put64(&mut u, 8, b)?;
        // A version 4 (random) UUID of the RFC 4122 variant.
        let (v, var) = (byte(&u, 6)? & 0x0f | 0x40, byte(&u, 8)? & 0x3f | 0x80);
        put(&mut u, 6, &[v])?;
        put(&mut u, 8, &[var])?;
        Ok(u)
    }

    /// The first unused subvolume id.
    fn free_root_id(&mut self) -> Result<u64, Errno> {
        let last = self.prev_item(tree::ROOT, Key::new(tree::LAST_FREE, 0xff, u64::MAX))?;
        let id = last.map_or(tree::FIRST_FREE, |(k, _)| k.objectid.max(tree::FIRST_FREE - 1) + 1);
        if id > tree::LAST_FREE { Err(Errno::ENOSPC) } else { Ok(id) }
    }

    /// Whether the volume has a UUID tree.
    fn has_uuid_tree(&mut self) -> Result<bool, Errno> {
        let found = self.next_item(tree::ROOT, Key::new(tree::UUID, item::ROOT_ITEM, 0))?;
        Ok(found.is_some_and(|(k, _)| k.objectid == tree::UUID && k.ty == item::ROOT_ITEM))
    }

    /// Records in the UUID tree (if there is one) that `uuid` names subvolume `id`.
    fn uuid_add(&mut self, ty: u8, uuid: &[u8; 16], id: u64) -> Result<(), Errno> {
        if !self.has_uuid_tree()? {
            return Ok(());
        }
        let key = Key::new(le64(uuid, 0)?, ty, le64(uuid, 8)?);
        match self.insert(tree::UUID, key, &id.to_le_bytes()) {
            Err(Errno::EEXIST) => self.update(tree::UUID, key, &id.to_le_bytes()),
            r => r,
        }
    }

    /// Takes `uuid` out of the UUID tree.
    fn uuid_remove(&mut self, ty: u8, uuid: &[u8; 16]) -> Result<(), Errno> {
        if !self.has_uuid_tree()? {
            return Ok(());
        }
        match self.delete(tree::UUID, Key::new(le64(uuid, 0)?, ty, le64(uuid, 8)?)) {
            Err(Errno::ENOENT) => Ok(()),
            r => r,
        }
    }

    /// Checks that `name` can be added to directory `dir` of tree `t`.
    fn check_new_name(&mut self, t: u64, dir: u64, name: &[u8]) -> Result<(), Errno> {
        if name.is_empty() || name.contains(&b'/') || name == b"." || name == b".." {
            return Err(Errno::EINVAL);
        }
        if name.len() > 255 {
            return Err(Errno::ENAMETOOLONG);
        }
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
        Ok(())
    }

    /// Names subvolume `id` `name` in directory `dir` of tree `t`.
    fn link_subvolume(&mut self, t: u64, dir: u64, name: &[u8], id: u64, offset: u64) -> Result<(), Errno> {
        let idx = self.next_index(t, dir)?;
        self.dir_add(t, dir, name, Key::new(id, item::ROOT_ITEM, offset), ft_of(FileKind::Directory), idx)?;
        let mut r = Vec::new();
        r.try_reserve_exact(18 + name.len()).map_err(|_| Errno::ENOMEM)?;
        r.extend_from_slice(&dir.to_le_bytes());
        r.extend_from_slice(&idx.to_le_bytes());
        r.extend_from_slice(&(name.len() as u16).to_le_bytes());
        r.extend_from_slice(name);
        self.insert(tree::ROOT, Key::new(t, item::ROOT_REF, id), &r)?;
        self.insert(tree::ROOT, Key::new(id, item::ROOT_BACKREF, t), &r)
    }

    /// Creates an empty subvolume `name` in directory `dir` of tree `t`;
    /// returns its id.
    pub(crate) fn create_subvolume(&mut self, t: u64, dir: u64, name: &[u8]) -> Result<u64, Errno> {
        self.check_new_name(t, dir, name)?;
        let id = self.free_root_id()?;
        let now = self.sh.now();
        let leaf = self.new_block(id, 0, Body::Leaf(Vec::new()))?;
        let uuid = self.new_uuid(id)?;
        let mut r = [0u8; root::LEN];
        put64(&mut r, ino::GENERATION, self.transid)?;
        put32(&mut r, ino::NLINK, 1)?;
        put32(&mut r, ino::MODE, FileKind::Directory.mode_bits() | 0o755)?;
        put64(&mut r, root::GENERATION, self.transid)?;
        put64(&mut r, root::DIRID, tree::FIRST_FREE)?;
        put64(&mut r, root::BYTENR, leaf)?;
        put64(&mut r, root::BYTES_USED, self.sh.nodesize as u64)?;
        put32(&mut r, root::REFS, 1)?;
        put64(&mut r, root::GENERATION_V2, self.transid)?;
        put(&mut r, root::UUID, &uuid)?;
        put64(&mut r, root::CTRANSID, self.transid)?;
        put64(&mut r, root::OTRANSID, self.transid)?;
        put_time(&mut r, root::CTIME, now)?;
        put_time(&mut r, root::OTIME, now)?;
        self.insert(tree::ROOT, Key::new(id, item::ROOT_ITEM, 0), &r)?;
        // Its root directory.
        let mut d = [0u8; ino::LEN];
        put64(&mut d, ino::GENERATION, self.transid)?;
        put64(&mut d, ino::TRANSID, self.transid)?;
        put32(&mut d, ino::NLINK, 1)?;
        put32(&mut d, ino::MODE, FileKind::Directory.mode_bits() | 0o755)?;
        for at in [ino::ATIME, ino::CTIME, ino::MTIME, ino::OTIME] {
            put_time(&mut d, at, now)?;
        }
        self.insert(id, Key::new(tree::FIRST_FREE, item::INODE_ITEM, 0), &d)?;
        let mut up = [0u8; 12];
        put(&mut up, 8, &2u16.to_le_bytes())?;
        put(&mut up, 10, b"..")?;
        self.insert(id, Key::new(tree::FIRST_FREE, item::INODE_REF, tree::FIRST_FREE), &up)?;
        self.link_subvolume(t, dir, name, id, 0)?;
        self.uuid_add(item::UUID_SUBVOL, &uuid, id)?;
        Ok(id)
    }

    /// Snapshots subvolume `src` as `name` in directory `dir` of tree `t`;
    /// returns the snapshot's id.
    pub(crate) fn create_snapshot(
        &mut self,
        src: u64,
        t: u64,
        dir: u64,
        name: &[u8],
        read_only: bool,
    ) -> Result<u64, Errno> {
        if src != tree::FS && !(tree::FIRST_FREE..=tree::LAST_FREE).contains(&src) {
            return Err(Errno::EINVAL);
        }
        self.check_new_name(t, dir, name)?;
        let (skey, sdata) = self.next_item(tree::ROOT, Key::new(src, item::ROOT_ITEM, 0))?.ok_or(Errno::ENOENT)?;
        if skey.objectid != src || skey.ty != item::ROOT_ITEM {
            return Err(Errno::ENOENT);
        }
        if sdata.len() < root::LEN
            || le32(&sdata, root::REFS)? == 0
            || self.roots.iter().any(|r| r.id == src && r.addr != r.orig)
        {
            return Err(Errno::EOPNOTSUPP);
        }
        let id = self.free_root_id()?;
        let now = self.sh.now();
        let (addr, level) = (le64(&sdata, root::BYTENR)?, byte(&sdata, root::LEVEL)?);
        let copy = self.copy_root(id, addr, level)?;
        // From now on the source's blocks written before this transaction
        // are shared.
        let mut s = try_to_vec(&sdata)?;
        put64(&mut s, root::LAST_SNAPSHOT, self.transid)?;
        self.update(tree::ROOT, skey, &s)?;
        self.note_snapshot(src);

        let uuid = self.new_uuid(id)?;
        let parent_uuid: [u8; 16] = crate::disk::array(&s, root::UUID)?;
        let flags = le64(&s, root::FLAGS)? & !root::RDONLY | if read_only { root::RDONLY } else { 0 };
        put64(&mut s, root::GENERATION, self.transid)?;
        put64(&mut s, root::BYTENR, copy)?;
        put64(&mut s, root::FLAGS, flags)?;
        put32(&mut s, root::REFS, 1)?;
        put(&mut s, root::DROP_PROGRESS, &[0; 17])?;
        put(&mut s, root::DROP_LEVEL, &[0])?;
        put64(&mut s, root::GENERATION_V2, self.transid)?;
        put(&mut s, root::UUID, &uuid)?;
        put(&mut s, root::PARENT_UUID, &parent_uuid)?;
        put(&mut s, root::RECEIVED_UUID, &[0; 16])?;
        put64(&mut s, root::CTRANSID, self.transid)?;
        put64(&mut s, root::OTRANSID, self.transid)?;
        put64(&mut s, root::STRANSID, 0)?;
        put64(&mut s, root::RTRANSID, 0)?;
        put_time(&mut s, root::CTIME, now)?;
        put_time(&mut s, root::OTIME, now)?;
        put(&mut s, root::STIME, &[0; 12])?;
        put(&mut s, root::RTIME, &[0; 12])?;
        self.insert(tree::ROOT, Key::new(id, item::ROOT_ITEM, self.transid), &s)?;
        self.link_subvolume(t, dir, name, id, u64::MAX)?;
        self.uuid_add(item::UUID_SUBVOL, &uuid, id)?;
        Ok(id)
    }

    /// Unlinks subvolume `name` of directory `dir` in tree `t`, and marks it
    /// dead: its blocks are dropped by [`Tx::drop_tree`]. Returns its id.
    pub(crate) fn unlink_subvolume(&mut self, t: u64, dir: u64, name: &[u8]) -> Result<u64, Errno> {
        self.frees = true;
        let (loc, _) = self.dir_lookup(t, dir, name)?.ok_or(Errno::ENOENT)?;
        if loc.ty != item::ROOT_ITEM {
            return Err(Errno::ENOTDIR);
        }
        let id = loc.objectid;
        if id == tree::FS {
            return Err(Errno::EPERM);
        }
        // Nested subvolumes keep their parent.
        if self
            .next_item(tree::ROOT, Key::new(id, item::ROOT_REF, 0))?
            .is_some_and(|(k, _)| k.objectid == id && k.ty == item::ROOT_REF)
        {
            return Err(Errno::ENOTEMPTY);
        }
        let (rkey, mut r) = self.next_item(tree::ROOT, Key::new(id, item::ROOT_ITEM, 0))?.ok_or(Errno::EIO)?;
        if rkey.objectid != id || rkey.ty != item::ROOT_ITEM || r.len() < root::LEN {
            return Err(Errno::EIO);
        }
        let idx = match self.find(tree::ROOT, Key::new(t, item::ROOT_REF, id))? {
            Some(d) if le64(&d, 0)? == dir => le64(&d, 8)?,
            _ => self.index_of(t, dir, name)?,
        };
        self.dir_del(t, dir, name, idx)?;
        for k in [Key::new(t, item::ROOT_REF, id), Key::new(id, item::ROOT_BACKREF, t)] {
            if self.find(tree::ROOT, k)?.is_some() {
                self.delete(tree::ROOT, k)?;
            }
        }
        put32(&mut r, root::REFS, 0)?;
        self.update(tree::ROOT, rkey, &r)?;
        self.insert(tree::ROOT, Key::new(tree::ORPHAN, item::ORPHAN_ITEM, id), &[])?;
        if let Some(i) = self.w.next_ino.iter().position(|e| e.0 == id) {
            self.w.next_ino.swap_remove(i);
        }
        Ok(id)
    }

    /// The `DIR_INDEX` of `name` in directory `dir`, found by looking.
    fn index_of(&mut self, t: u64, dir: u64, name: &[u8]) -> Result<u64, Errno> {
        let mut at = Key::new(dir, item::DIR_INDEX, 0);
        while let Some((k, d)) = self.next_item(t, at)? {
            if k.objectid != dir || k.ty != item::DIR_INDEX {
                break;
            }
            if crate::ops::entries(&d)?.iter().any(|e| e.2 == name) {
                return Ok(k.offset);
            }
            at = crate::write::succ(k).ok_or(Errno::EIO)?;
        }
        Err(Errno::EIO)
    }

    /// Gives block `c`'s children references by its address and takes away
    /// the ones by its tree, then does the same to the blocks below that
    /// belong to the same tree. Linux calls this updating the back references.
    fn make_full_backref(&mut self, c: &TNode) -> Result<(), Errno> {
        self.ref_children(c, RefMode::Shared(c.addr), 1)?;
        self.ref_children(c, RefMode::Owner(c.owner), -1)?;
        self.set_full_backref(c.addr, c.level)?;
        if let Body::Node(ptrs) = &c.body {
            let level = c.level.checked_sub(1).ok_or(Errno::EIO)?;
            for p in ptrs.iter().copied() {
                let (_, full) = self.block_refs(p.addr, level)?;
                if full {
                    continue;
                }
                let child = TNode::decode(&self.sh.block(self.chunks(), p.addr)?)?;
                if child.addr == p.addr && child.owner == c.owner {
                    self.make_full_backref(&child)?;
                }
            }
        }
        Ok(())
    }

    /// Drops one transaction's worth of dead subvolume `id`'s tree; `true`
    /// once all of it, and the root item, are gone.
    pub(crate) fn drop_tree(&mut self, id: u64) -> Result<bool, Errno> {
        self.frees = true;
        let (rkey, mut r) = self.next_item(tree::ROOT, Key::new(id, item::ROOT_ITEM, 0))?.ok_or(Errno::ENOENT)?;
        if rkey.objectid != id || rkey.ty != item::ROOT_ITEM || r.len() < root::LEN || le32(&r, root::REFS)? != 0 {
            return Err(Errno::EIO);
        }
        let (addr, level) = (le64(&r, root::BYTENR)?, byte(&r, root::LEVEL)?);
        let origin = le64(&r, root::OTRANSID)?;
        let progress = Key::parse(&r, root::DROP_PROGRESS)?;
        let drop_level = byte(&r, root::DROP_LEVEL)?;

        let root_block = TNode::decode(&self.sh.block(self.chunks(), addr)?)?;
        if root_block.addr != addr || root_block.level != level {
            return Err(Errno::EIO);
        }
        let (_, full) = self.block_refs(addr, level)?;
        let mut stack: Vec<Frame> = Vec::new();
        let mut budget = DROP_BUDGET;
        if let Body::Node(_) = root_block.body {
            let mut f = frame_of(root_block, full);
            if progress.objectid != 0 {
                f.slot = slot_for(&f.ptrs, progress);
            }
            try_push(&mut stack, f)?;
            // Back to where the last transaction stopped.
            while progress.objectid != 0 && stack.last().is_some_and(|f| f.level > drop_level) {
                let Some(top) = stack.last() else { break };
                let Some(p) = top.ptrs.get(top.slot).copied() else { return Err(Errno::EIO) };
                let child = TNode::decode(&self.sh.block(self.chunks(), p.addr)?)?;
                let (_, full) = self.block_refs(p.addr, child.level)?;
                let mut f = frame_of(child, full);
                f.slot = slot_for(&f.ptrs, progress);
                try_push(&mut stack, f)?;
            }
        } else {
            // A tree of one leaf.
            let mode = if full { RefMode::Shared(addr) } else { RefMode::Owner(root_block.owner) };
            self.ref_children(&root_block, mode, -1)?;
            self.release_block(addr, root_block.owner, level, 0, true)?;
            self.finish_drop(rkey, &r)?;
            return Ok(true);
        }

        while let Some(top) = stack.last() {
            if top.slot >= top.ptrs.len() {
                // All of its children are gone: let go of the block.
                let Some(done) = stack.pop() else { break };
                match stack.last_mut() {
                    Some(parent) => {
                        let (owner, by) = if parent.full { (0, parent.addr) } else { (parent.owner, 0) };
                        self.release_block(done.addr, owner, done.level, by, true)?;
                        parent.slot += 1;
                    }
                    None => self.release_block(done.addr, done.owner, done.level, 0, true)?,
                }
                continue;
            }
            if budget == 0 {
                // Stop here; the next transaction starts at this child.
                let key = top.ptrs.get(top.slot).ok_or(Errno::EIO)?.key;
                put(&mut r, root::DROP_PROGRESS, &crate::node::key_bytes(&key))?;
                put(&mut r, root::DROP_LEVEL, &[top.level])?;
                self.update(tree::ROOT, rkey, &r)?;
                return Ok(false);
            }
            let Some(p) = top.ptrs.get(top.slot).copied() else { return Err(Errno::EIO) };
            let (parent_addr, parent_owner, parent_full, plevel) = (top.addr, top.owner, top.full, top.level);
            let clevel = plevel.checked_sub(1).ok_or(Errno::EIO)?;
            let (owner, by) = if parent_full { (0, parent_addr) } else { (parent_owner, 0) };
            let (refs, cfull) = self.block_refs(p.addr, clevel)?;
            budget = budget.saturating_sub(1);
            if refs == 0 {
                return Err(Errno::EIO);
            }
            if refs > 1 {
                // Shared: it stays, for whoever else has it.
                if !cfull && p.generation >= origin {
                    let child = TNode::decode(&self.sh.block(self.chunks(), p.addr)?)?;
                    if child.addr == p.addr && child.owner == id {
                        self.make_full_backref(&child)?;
                        budget = budget.saturating_sub(child.len());
                    }
                }
                self.release_block(p.addr, owner, clevel, by, false)?;
                if let Some(t) = stack.last_mut() {
                    t.slot += 1;
                }
                continue;
            }
            let child = TNode::decode(&self.sh.block(self.chunks(), p.addr)?)?;
            if child.addr != p.addr || child.level != clevel {
                return Err(Errno::EIO);
            }
            if clevel == 0 {
                let mode = if cfull { RefMode::Shared(p.addr) } else { RefMode::Owner(child.owner) };
                self.ref_children(&child, mode, -1)?;
                budget = budget.saturating_sub(child.len());
                self.release_block(p.addr, owner, 0, by, true)?;
                if let Some(t) = stack.last_mut() {
                    t.slot += 1;
                }
            } else {
                try_push(&mut stack, frame_of(child, cfull))?;
            }
        }
        self.finish_drop(rkey, &r)?;
        Ok(true)
    }

    /// The tree is gone: takes its root item and the rest of its records.
    fn finish_drop(&mut self, rkey: Key, r: &[u8]) -> Result<(), Errno> {
        self.delete(tree::ROOT, rkey)?;
        let orphan = Key::new(tree::ORPHAN, item::ORPHAN_ITEM, rkey.objectid);
        if self.find(tree::ROOT, orphan)?.is_some() {
            self.delete(tree::ROOT, orphan)?;
        }
        let uuid: [u8; 16] = crate::disk::array(r, root::UUID)?;
        let received: [u8; 16] = crate::disk::array(r, root::RECEIVED_UUID)?;
        self.uuid_remove(item::UUID_SUBVOL, &uuid)?;
        if received != [0; 16] {
            self.uuid_remove(item::UUID_RECEIVED, &received)?;
        }
        Ok(())
    }
}

/// The frame for a decoded node.
fn frame_of(n: TNode, full: bool) -> Frame {
    let ptrs = match n.body {
        Body::Node(p) => p,
        Body::Leaf(_) => Vec::new(),
    };
    Frame { addr: n.addr, level: n.level, owner: n.owner, full, ptrs, slot: 0 }
}

/// The slot in `ptrs` of the child that holds `key`.
fn slot_for(ptrs: &[Ptr], key: Key) -> usize {
    ptrs.partition_point(|p| p.key <= key).saturating_sub(1)
}
