//! Reading the volume: physical reads, the chunk map from logical to
//! physical addresses, checked tree blocks with a small cache, and cursors
//! that walk a tree in key order.

use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_arc, try_push, try_zeroed};

use crate::disk::{Chunk, Key, header, le64, profile};
use crate::{MAX_RUN, Shared, csum};

/// Tree blocks kept in memory.
const CACHE_BLOCKS: usize = 32;

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

    /// The chunk holding all of `logical..logical + len`.
    fn find(&self, logical: u64, len: u64) -> Result<&Chunk, Errno> {
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

impl<D: BlockDevice + Send + 'static> Shared<D> {
    /// Reads `buf.len()` bytes at byte offset `off` of the device.
    pub(crate) fn read_phys(&self, mut off: u64, mut buf: &mut [u8]) -> Result<(), Errno> {
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

    /// Reads logical `logical..logical + buf.len()` from the first copy that
    /// reads and that `good` accepts. Only copies on this device are tried;
    /// striped profiles (RAID0, RAID10, RAID5, RAID6) are `EIO`.
    pub(crate) fn read_logical(
        &self,
        logical: u64,
        buf: &mut [u8],
        good: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<(), Errno> {
        let chunk = self.chunks.find(logical, buf.len() as u64)?;
        if chunk.ty & profile::STRIPED != 0 {
            return Err(Errno::EIO);
        }
        let within = logical - chunk.logical;
        for s in chunk.stripes.iter().filter(|s| s.devid == self.devid) {
            let Some(at) = s.offset.checked_add(within) else { continue };
            if self.read_phys(at, buf).is_ok() && good(buf) {
                return Ok(());
            }
        }
        Err(Errno::EIO)
    }

    /// The tree block at `logical`, checked against its checksum, address and
    /// fsid.
    pub(crate) fn block(&self, logical: u64) -> Result<Block, Errno> {
        if let Some((_, b)) = self.cache.lock().0.iter().find(|(at, _)| *at == logical) {
            return Ok(b.clone());
        }
        let mut b = try_zeroed(self.nodesize)?;
        let (ty, uuid) = (self.csum_type, self.meta_uuid);
        self.read_logical(logical, &mut b, &mut |b| {
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
        let mut cache = self.cache.lock();
        let (slots, hand) = &mut *cache;
        if slots.len() < CACHE_BLOCKS {
            // A full cache never grows, so this push is the only allocation.
            if try_push(slots, (logical, b.clone())).is_err() {
                return Ok(b);
            }
        } else if let Some(slot) = slots.get_mut(*hand % CACHE_BLOCKS) {
            *slot = (logical, b.clone());
            *hand = hand.wrapping_add(1);
        }
        Ok(b)
    }

    /// The tree block at `logical`, which must be at `want` level.
    fn block_at(&self, logical: u64, want: u8) -> Result<Block, Errno> {
        let b = self.block(logical)?;
        if level(&b) != want || (want > 0 && nritems(&b) == 0) {
            return Err(Errno::EIO);
        }
        Ok(b)
    }

    /// The data of the item with exactly `key` in the tree rooted at `root`.
    pub(crate) fn lookup<R>(
        &self,
        root: (u64, u8),
        key: Key,
        f: impl FnOnce(&[u8]) -> Result<R, Errno>,
    ) -> Result<Option<R>, Errno> {
        let mut c = Cursor::new(self, root);
        match c.seek(key)? {
            Some((k, data)) if k == key => Ok(Some(f(data)?)),
            _ => Ok(None),
        }
    }
}

/// A position in a tree: the block and slot at each level, root first.
pub struct Cursor<'s, D: BlockDevice + Send + 'static> {
    shared: &'s Shared<D>,
    root: (u64, u8),
    path: Vec<(Block, usize)>,
    /// The key last returned, which the next must strictly follow so that a
    /// corrupt tree cannot make a walk loop.
    last: Option<Key>,
}

impl<'s, D: BlockDevice + Send + 'static> Cursor<'s, D> {
    /// A cursor over the tree whose root block is at `root.0`, level `root.1`.
    pub fn new(shared: &'s Shared<D>, root: (u64, u8)) -> Self {
        Cursor { shared, root, path: Vec::new(), last: None }
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
            let b = self.shared.block_at(at, lvl)?;
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
            let c = self.shared.block_at(at, lvl)?;
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
