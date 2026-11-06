// SPDX-License-Identifier: GPL-2.0-only
//! Reading the volume: physical reads, the chunk map from logical to
//! physical addresses, checked tree blocks with a small cache, and cursors
//! that walk a tree in key order.

use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_arc, try_push, try_zeroed};

use crate::disk::{Chunk, Key, header, le64};
use crate::raid::Place;
use crate::{Dev, MAX_RUN, Shared, csum};

/// Deepest tree (`BTRFS_MAX_LEVEL`).
const MAX_LEVEL: u8 = 8;

/// Bytes of a leaf's item header: key, data offset, data size.
const ITEM: usize = Key::SIZE + 8;
/// Bytes of a node's pointer: key, child address, generation.
const PTR: usize = Key::SIZE + 16;

/// Logical to physical addresses, by chunk.
#[derive(Default)]
pub struct ChunkMap(Vec<Chunk>);

impl ChunkMap {
    /// Adds `chunk`, keeping the map sorted; a chunk already known is kept.
    pub fn insert(&mut self, chunk: Chunk) -> Result<(), Errno> {
        let at = self.0.partition_point(|c| c.logical < chunk.logical);
        if self.0.get(at).is_some_and(|c| c.logical == chunk.logical) {
            return Ok(());
        }
        self.0.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        self.0.insert(at, chunk);
        Ok(())
    }

    /// Forgets the chunk at `logical`.
    pub fn remove(&mut self, logical: u64) {
        if let Ok(i) = self.0.binary_search_by_key(&logical, |c| c.logical) {
            self.0.remove(i);
        }
    }

    /// A copy, failing instead of panicking if memory runs out.
    pub fn try_clone(&self) -> Result<Self, Errno> {
        let mut v = Vec::new();
        v.try_reserve_exact(self.0.len()).map_err(|_| Errno::ENOMEM)?;
        for c in &self.0 {
            let stripes = osmium_sync::fallible::try_to_vec(&c.stripes)?;
            try_push(
                &mut v,
                Chunk {
                    logical: c.logical,
                    length: c.length,
                    ty: c.ty,
                    stripe_len: c.stripe_len,
                    sub_stripes: c.sub_stripes,
                    stripes,
                },
            )?;
        }
        Ok(ChunkMap(v))
    }

    /// The chunks, by logical address.
    pub fn iter(&self) -> impl Iterator<Item = &Chunk> {
        self.0.iter()
    }

    /// The chunk holding all of `logical..logical + len`.
    pub fn find(&self, logical: u64, len: u64) -> Result<&Chunk, Errno> {
        let at = self.0.partition_point(|c| c.logical <= logical).checked_sub(1).ok_or(Errno::EIO)?;
        let c = self.0.get(at).ok_or(Errno::EIO)?;
        let end = logical.checked_add(len).ok_or(Errno::EIO)?;
        if end > c.logical + c.length {
            return Err(Errno::EIO);
        }
        Ok(c)
    }

    /// Parses the bootstrap chunks of the superblock's `sys_chunk_array`.
    pub fn bootstrap(sys: &[u8]) -> Result<Self, Errno> {
        let mut map = ChunkMap::default();
        let mut rest = sys;
        while !rest.is_empty() {
            let key = Key::parse(rest, 0)?;
            if key.ty != crate::disk::item::CHUNK_ITEM {
                return Err(Errno::EINVAL);
            }
            let (chunk, len) = Chunk::parse(rest.get(Key::SIZE..).ok_or(Errno::EINVAL)?, key.offset)?;
            map.insert(chunk)?;
            rest = rest.get(Key::SIZE + len..).ok_or(Errno::EINVAL)?;
        }
        Ok(map)
    }
}

/// A checked tree block.
pub type Block = Arc<Vec<u8>>;

/// The fields of a block header.
fn nritems(b: &[u8]) -> usize {
    crate::disk::le32(b, header::NRITEMS).unwrap_or(0) as usize
}

fn level(b: &[u8]) -> u8 {
    b.get(header::LEVEL).copied().unwrap_or(0)
}

/// The key of item or pointer `slot`.
fn slot_key(b: &[u8], slot: usize) -> Result<Key, Errno> {
    let size = if level(b) == 0 { ITEM } else { PTR };
    Key::parse(b, header::SIZE + slot * size)
}

/// The data of leaf item `slot`.
fn item_data(b: &[u8], slot: usize) -> Result<&[u8], Errno> {
    let at = header::SIZE + slot * ITEM + Key::SIZE;
    let off = crate::disk::le32(b, at)? as usize;
    let size = crate::disk::le32(b, at + 4)? as usize;
    crate::disk::bytes(b, header::SIZE.checked_add(off).ok_or(Errno::EIO)?, size)
}

/// The child address of node pointer `slot`.
fn child(b: &[u8], slot: usize) -> Result<u64, Errno> {
    le64(b, header::SIZE + slot * PTR + Key::SIZE)
}

impl<D: BlockDevice + Send + 'static> Dev<D> {
    /// Reads `buf.len()` bytes at byte offset `off` of the device.
    pub(crate) fn read(&self, mut off: u64, mut buf: &mut [u8]) -> Result<(), Errno> {
        let bs = self.block_size;
        let mut dev = self.dev.lock();
        let mut bounce = Vec::new();
        while !buf.is_empty() {
            let lba = off / bs as u64;
            let skip = (off % bs as u64) as usize;
            let n = if skip == 0 && buf.len() >= bs {
                let n = (buf.len() / bs * bs).min(MAX_RUN / bs * bs);
                dev.read_blocks(lba, buf.get_mut(..n).ok_or(Errno::EIO)?).map_err(|_| Errno::EIO)?;
                n
            } else {
                if bounce.is_empty() {
                    bounce = try_zeroed(bs)?;
                }
                dev.read_blocks(lba, &mut bounce).map_err(|_| Errno::EIO)?;
                let n = (bs - skip).min(buf.len());
                let src = bounce.get(skip..skip + n).ok_or(Errno::EIO)?;
                buf.get_mut(..n).ok_or(Errno::EIO)?.copy_from_slice(src);
                n
            };
            off = off.checked_add(n as u64).ok_or(Errno::EIO)?;
            buf = buf.get_mut(n..).ok_or(Errno::EIO)?;
        }
        Ok(())
    }
}

impl<D: BlockDevice + Send + 'static> Shared<D> {
    /// The device with id `devid`, if it is present.
    pub(crate) fn dev(&self, devid: u64) -> Option<Arc<Dev<D>>> {
        self.devs.lock().iter().find(|d| d.devid == devid).cloned()
    }

    /// Whether device `devid` is part of the open volume.
    pub(crate) fn has_dev(&self, devid: u64) -> bool {
        self.devs.lock().iter().any(|d| d.devid == devid)
    }

    /// The ids of the open devices, the mounted one last.
    pub(crate) fn dev_ids(&self) -> Result<Vec<u64>, Errno> {
        let devs = self.devs.lock();
        let mut v = Vec::new();
        v.try_reserve_exact(devs.len()).map_err(|_| Errno::ENOMEM)?;
        v.extend(devs.iter().filter(|d| d.devid != self.devid).map(|d| d.devid));
        v.push(self.devid);
        Ok(v)
    }

    /// Reads `buf.len()` bytes at byte offset `off` of device `devid`.
    pub(crate) fn read_phys(&self, devid: u64, off: u64, buf: &mut [u8]) -> Result<(), Errno> {
        self.dev(devid).ok_or(Errno::EIO)?.read(off, buf)
    }

    /// Reads logical `logical..logical + buf.len()` a run at a time (a run
    /// lies within one stripe element), each from the first copy that reads
    /// and that `good` accepts; `good` is given a run and its byte offset in
    /// `buf`. A RAID5 or RAID6 strip that does not read or check is rebuilt
    /// from the rest of its row.
    pub(crate) fn read_logical(
        &self,
        chunks: &ChunkMap,
        logical: u64,
        buf: &mut [u8],
        good: &mut dyn FnMut(usize, &[u8]) -> bool,
    ) -> Result<(), Errno> {
        let chunk = chunks.find(logical, buf.len() as u64)?;
        let mut done = 0usize;
        while done < buf.len() {
            let within = (logical - chunk.logical).checked_add(done as u64).ok_or(Errno::EIO)?;
            let piece = chunk.piece(within, (buf.len() - done) as u64)?;
            let end = done.checked_add(piece.len as usize).ok_or(Errno::EIO)?;
            let part = buf.get_mut(done..end).ok_or(Errno::EIO)?;
            let at = done;
            self.read_piece(chunk, &piece.place, part, &mut |p| good(at, p))?;
            done = end;
        }
        Ok(())
    }

    /// Writes `buf`, whole device blocks, at byte offset `off` of device `devid`.
    pub(crate) fn write_phys(&self, devid: u64, mut off: u64, mut buf: &[u8]) -> Result<(), Errno> {
        let d = self.dev(devid).ok_or(Errno::EIO)?;
        let bs = d.block_size as u64;
        if !off.is_multiple_of(bs) || !(buf.len() as u64).is_multiple_of(bs) {
            return Err(Errno::EIO);
        }
        let mut dev = d.dev.lock();
        while !buf.is_empty() {
            let n = buf.len().min(MAX_RUN / bs as usize * bs as usize);
            dev.write_blocks(off / bs, buf.get(..n).ok_or(Errno::EIO)?).map_err(|_| Errno::EIO)?;
            off = off.checked_add(n as u64).ok_or(Errno::EIO)?;
            buf = buf.get(n..).ok_or(Errno::EIO)?;
        }
        Ok(())
    }

    /// Writes `buf` at logical `logical`, to every copy. Parity profiles are
    /// not written.
    pub(crate) fn write_logical(&self, chunks: &ChunkMap, logical: u64, buf: &[u8]) -> Result<(), Errno> {
        let chunk = chunks.find(logical, buf.len() as u64)?;
        if chunk.parity() != 0 {
            return Err(Errno::EIO);
        }
        // Nothing cached for these addresses is current once they are written.
        self.data_cache.lock().forget_range(logical, logical.saturating_add(buf.len() as u64));
        let mut done = 0usize;
        while done < buf.len() {
            let within = (logical - chunk.logical).checked_add(done as u64).ok_or(Errno::EIO)?;
            let piece = chunk.piece(within, (buf.len() - done) as u64)?;
            let end = done.checked_add(piece.len as usize).ok_or(Errno::EIO)?;
            let part = buf.get(done..end).ok_or(Errno::EIO)?;
            let Place::Copies { first, count, off } = piece.place else { return Err(Errno::EIO) };
            for s in chunk.stripes.iter().skip(first).take(count) {
                self.write_phys(s.devid, s.offset.checked_add(off).ok_or(Errno::EIO)?, part)?;
            }
            done = end;
        }
        Ok(())
    }

    /// Makes previous writes durable, on every device.
    pub(crate) fn flush(&self) -> Result<(), Errno> {
        for d in self.devs.lock().iter() {
            d.dev.lock().flush().map_err(|_| Errno::EIO)?;
        }
        Ok(())
    }

    /// Forgets cached copies of the blocks at `addrs`, which are about to be
    /// rewritten.
    pub(crate) fn forget(&self, addrs: impl Iterator<Item = u64> + Clone) {
        let mut cache = self.cache.lock();
        for a in addrs {
            cache.forget_range(a, a.saturating_add(1));
        }
    }

    /// The tree block at `logical`, checked against its checksum, address and
    /// fsid.
    pub(crate) fn block(&self, chunks: &ChunkMap, logical: u64) -> Result<Block, Errno> {
        if let Some(b) = self.cache.lock().get(logical) {
            return Ok(b);
        }
        let mut b = try_zeroed(self.nodesize)?;
        let (ty, uuid) = (self.csum_type, self.meta_uuid);
        let want = self.nodesize;
        self.read_logical(chunks, logical, &mut b, &mut |_, b| {
            if b.len() != want {
                return false;
            }
            let (stored, rest) = b.split_at_checked(crate::disk::CSUM_SPACE).unwrap_or((&[], &[]));
            csum::matches(ty, rest, stored)
                && le64(b, header::BYTENR).ok() == Some(logical)
                && b.get(header::FSID..header::FSID + 16) == Some(&uuid[..])
        })?;
        let n = nritems(&b);
        let per = if level(&b) == 0 { ITEM } else { PTR };
        if level(&b) >= MAX_LEVEL || n.checked_mul(per).is_none_or(|s| s > self.nodesize - header::SIZE) {
            return Err(Errno::EIO);
        }
        let b = try_arc(b)?;
        self.cache.lock().insert(logical, b.clone());
        Ok(b)
    }

    /// The tree block at `logical`, which must be at `want` level.
    fn block_at(&self, chunks: &ChunkMap, logical: u64, want: u8) -> Result<Block, Errno> {
        let b = self.block(chunks, logical)?;
        if level(&b) != want || (want > 0 && nritems(&b) == 0) {
            return Err(Errno::EIO);
        }
        Ok(b)
    }

    /// Reads every item of the tree rooted at `root` (in key order) into
    /// `items`, and the address of each of its blocks into `blocks`.
    pub(crate) fn read_tree(
        &self,
        chunks: &ChunkMap,
        root: (u64, u8),
        items: &mut Vec<(Key, Vec<u8>)>,
        blocks: &mut Vec<u64>,
    ) -> Result<(), Errno> {
        if root.1 >= MAX_LEVEL {
            return Err(Errno::EIO);
        }
        let start = items.len();
        self.read_subtree(chunks, root.0, root.1, items, blocks)?;
        // Keys must ascend, or the tree is not what it claims to be.
        let read = items.get(start..).ok_or(Errno::EIO)?;
        if read.windows(2).any(|w| w.first().map(|a| a.0) >= w.get(1).map(|b| b.0)) {
            return Err(Errno::EIO);
        }
        Ok(())
    }

    fn read_subtree(
        &self,
        chunks: &ChunkMap,
        addr: u64,
        want: u8,
        items: &mut Vec<(Key, Vec<u8>)>,
        blocks: &mut Vec<u64>,
    ) -> Result<(), Errno> {
        let b = self.block_at(chunks, addr, want)?;
        try_push(blocks, addr)?;
        for slot in 0..nritems(&b) {
            if want == 0 {
                try_push(items, (slot_key(&b, slot)?, osmium_sync::fallible::try_to_vec(item_data(&b, slot)?)?))?;
            } else {
                let below = want.checked_sub(1).ok_or(Errno::EIO)?;
                self.read_subtree(chunks, child(&b, slot)?, below, items, blocks)?;
            }
        }
        Ok(())
    }

    /// The data of the item with exactly `key` in the tree rooted at `root`.
    pub(crate) fn lookup<R>(
        &self,
        chunks: &ChunkMap,
        root: (u64, u8),
        key: Key,
        f: impl FnOnce(&[u8]) -> Result<R, Errno>,
    ) -> Result<Option<R>, Errno> {
        let mut c = Cursor::new(self, chunks, root);
        match c.seek(key)? {
            Some((k, data)) if k == key => Ok(Some(f(data)?)),
            _ => Ok(None),
        }
    }
}

/// A position in a tree: the block and slot at each level, root first.
pub struct Cursor<'s, D: BlockDevice + Send + 'static> {
    shared: &'s Shared<D>,
    chunks: &'s ChunkMap,
    root: (u64, u8),
    path: Vec<(Block, usize)>,
    /// The key last returned, which the next must strictly follow so that a
    /// corrupt tree cannot make a walk loop.
    last: Option<Key>,
}

impl<'s, D: BlockDevice + Send + 'static> Cursor<'s, D> {
    /// A cursor over the tree whose root block is at `root.0`, level `root.1`.
    pub fn new(shared: &'s Shared<D>, chunks: &'s ChunkMap, root: (u64, u8)) -> Self {
        Cursor { shared, chunks, root, path: Vec::new(), last: None }
    }

    /// The current item, if the leaf slot is in range.
    fn current(&self) -> Result<Option<(Key, &[u8])>, Errno> {
        let Some((leaf, slot)) = self.path.last() else { return Ok(None) };
        if *slot >= nritems(leaf) {
            return Ok(None);
        }
        Ok(Some((slot_key(leaf, *slot)?, item_data(leaf, *slot)?)))
    }

    /// Moves to the first item at or after `key` and returns it.
    pub fn seek(&mut self, key: Key) -> Result<Option<(Key, &[u8])>, Errno> {
        self.descend(key, false)
    }

    /// Moves to the last item at or before `key` and returns it.
    pub fn seek_back(&mut self, key: Key) -> Result<Option<(Key, &[u8])>, Errno> {
        self.descend(key, true)
    }

    /// Descends to `key`'s leaf and moves to the first item at or after it,
    /// or with `back` the last at or before it.
    fn descend(&mut self, key: Key, back: bool) -> Result<Option<(Key, &[u8])>, Errno> {
        if self.root.1 >= MAX_LEVEL {
            return Err(Errno::EIO);
        }
        self.path.clear();
        self.path.try_reserve(self.root.1 as usize + 1).map_err(|_| Errno::ENOMEM)?;
        self.last = None;
        let (mut at, mut lvl) = self.root;
        loop {
            let b = self.shared.block_at(self.chunks, at, lvl)?;
            let n = nritems(&b);
            // The first slot whose key is after `key`; keys are sorted.
            let mut after = n;
            for i in 0..n {
                if slot_key(&b, i)? > key {
                    after = i;
                    break;
                }
            }
            if lvl == 0 {
                if back {
                    // The item before `after`, or the previous leaf's last.
                    let slot = after.checked_sub(1);
                    self.path.push((b, slot.unwrap_or(0)));
                    if slot.is_none() || n == 0 {
                        return self.step(false);
                    }
                    return self.checked();
                }
                // The first item at or after `key`.
                let mut slot = after;
                while slot > 0 && slot_key(&b, slot - 1)? >= key {
                    slot -= 1;
                }
                self.path.push((b, slot));
                break;
            }
            // The last pointer whose key is not after `key`.
            let slot = after.saturating_sub(1);
            at = child(&b, slot)?;
            self.path.push((b, slot));
            lvl -= 1;
        }
        if self.current()?.is_none() {
            return self.step(true);
        }
        self.checked()
    }

    /// The next item.
    pub fn next(&mut self) -> Result<Option<(Key, &[u8])>, Errno> {
        if self.path.is_empty() {
            return Ok(None);
        }
        self.step(true)
    }

    /// Steps one item forward or back, across blocks as needed.
    fn step(&mut self, forward: bool) -> Result<Option<(Key, &[u8])>, Errno> {
        // Climb to the lowest level that has a slot to move to.
        let mut depth = self.path.len();
        loop {
            let Some(d) = depth.checked_sub(1) else {
                self.path.clear();
                return Ok(None);
            };
            let Some((b, slot)) = self.path.get_mut(d) else { return Err(Errno::EIO) };
            let n = nritems(b);
            let moved = if forward { slot.checked_add(1).filter(|&s| s < n) } else { slot.checked_sub(1) };
            match moved {
                Some(s) => {
                    *slot = s.min(n.saturating_sub(1));
                    break;
                }
                None => depth = d,
            }
        }
        // Descend to the leaf along the first (or last) pointers.
        self.path.truncate(depth);
        while self.path.len() <= self.root.1 as usize {
            let Some((b, slot)) = self.path.last() else { return Err(Errno::EIO) };
            let (at, lvl) = (child(b, *slot)?, level(b) - 1);
            let c = self.shared.block_at(self.chunks, at, lvl)?;
            let n = nritems(&c);
            if n == 0 {
                // Only a root leaf may be empty.
                return Err(Errno::EIO);
            }
            self.path.push((c, if forward { 0 } else { n - 1 }));
        }
        if self.current()?.is_none() {
            return Err(Errno::EIO);
        }
        let key = self.current()?.ok_or(Errno::EIO)?.0;
        if let Some(last) = self.last
            && ((forward && key <= last) || (!forward && key >= last))
        {
            return Err(Errno::EIO);
        }
        self.checked()
    }

    /// Records and returns the current item.
    fn checked(&mut self) -> Result<Option<(Key, &[u8])>, Errno> {
        let key = self.current()?.map(|(k, _)| k);
        self.last = key;
        self.current()
    }
}
