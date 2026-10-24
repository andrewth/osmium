//! ext4 extent trees: lookup, insertion with node splits, conversion of
//! uninitialized extents on write, and truncation.
//!
//! The root lives in the inode's 60-byte block map and holds four entries;
//! every other node is one block with a checksummed tail. Index entries
//! point down a level, and leaf entries map a run of logical blocks to a run
//! of physical ones. Each node's first key equals its parent entry's key.

use alloc::vec::Vec;

use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_to_vec, try_zeroed};

use super::{Csum, Fs, Inode, get16, get32, ino, put_bytes, put16, put32, sub};
use osmium_fs::Errno;

const MAGIC: u16 = 0xf30a;
const HEADER: usize = 12;
const ENTRY: usize = 12;
/// Root entries in the inode's block map.
const ROOT_MAX: u16 = 4;
/// Linux's limit on the tree's depth.
const MAX_DEPTH: u16 = 5;
/// The longest initialized extent; a longer length marks an uninitialized
/// one, of `len - INIT_MAX` blocks.
const INIT_MAX: u32 = 32768;
/// One past the last mappable logical block.
pub const MAX_BLOCKS: u64 = u32::MAX as u64;

fn entries(d: &[u8]) -> usize {
    get16(d, 2) as usize
}

fn set_entries(d: &mut [u8], n: usize) {
    put16(d, 2, n as u16);
}

fn max(d: &[u8]) -> usize {
    get16(d, 4) as usize
}

fn depth(d: &[u8]) -> u16 {
    get16(d, 6)
}

fn key(d: &[u8], i: usize) -> u32 {
    get32(d, HEADER + ENTRY * i)
}

fn child(d: &[u8], i: usize) -> u64 {
    let o = HEADER + ENTRY * i;
    (get16(d, o + 8) as u64) << 32 | get32(d, o + 4) as u64
}

fn index_entry(key: u32, child: u64) -> [u8; ENTRY] {
    let mut e = [0; ENTRY];
    put32(&mut e, 0, key);
    put32(&mut e, 4, child as u32);
    put16(&mut e, 8, (child >> 32) as u16);
    e
}

fn header(d: &mut [u8], max: usize, depth: u16) {
    put16(d, 0, MAGIC);
    set_entries(d, 0);
    put16(d, 4, max as u16);
    put16(d, 6, depth);
    put32(d, 8, 0);
}

/// Writes an empty root into a new inode's block map.
pub fn init_root(inode: &mut Inode) {
    if let Some(root) = inode.raw.get_mut(ino::BLOCK..ino::BLOCK + 60) {
        header(root, ROOT_MAX as usize, 0);
    }
}

/// The inode's block map, where the root of the tree lives.
fn root_bytes(inode: &Inode) -> &[u8] {
    sub(&inode.raw, ino::BLOCK..ino::BLOCK + 60)
}

/// One leaf entry.
#[derive(Clone, Copy)]
struct Extent {
    block: u32,
    len: u32,
    start: u64,
    uninit: bool,
}

impl Extent {
    fn get(d: &[u8], i: usize) -> Self {
        let o = HEADER + ENTRY * i;
        let raw = get16(d, o + 4) as u32;
        let (len, uninit) = if raw > INIT_MAX { (raw - INIT_MAX, true) } else { (raw, false) };
        let start = (get16(d, o + 6) as u64) << 32 | get32(d, o + 8) as u64;
        Extent { block: get32(d, o), len, start, uninit }
    }

    fn bytes(self) -> [u8; ENTRY] {
        let mut e = [0; ENTRY];
        put32(&mut e, 0, self.block);
        put16(&mut e, 4, (if self.uninit { self.len + INIT_MAX } else { self.len }) as u16);
        put16(&mut e, 6, (self.start >> 32) as u16);
        put32(&mut e, 8, self.start as u32);
        e
    }

    fn put(self, d: &mut [u8], i: usize) -> Result<(), Errno> {
        put_bytes(d, HEADER + ENTRY * i, &self.bytes())
    }

    fn end(self) -> u64 {
        self.block as u64 + self.len as u64
    }

    /// Whether `next` continues `self` and the two fit in one extent.
    fn joins(self, next: Extent) -> bool {
        let limit = if self.uninit { INIT_MAX - 1 } else { INIT_MAX };
        self.end() == next.block as u64
            && self.start + self.len as u64 == next.start
            && self.uninit == next.uninit
            && self.len + next.len <= limit
    }
}

fn put_entry(d: &mut [u8], pos: usize, entry: &[u8; ENTRY]) -> Result<(), Errno> {
    let n = entries(d);
    let at = HEADER + ENTRY * pos;
    let end = HEADER + ENTRY * n;
    if pos > n || end + ENTRY > d.len() {
        return Err(Errno::EIO);
    }
    d.copy_within(at..end, at + ENTRY);
    put_bytes(d, at, entry)?;
    set_entries(d, n + 1);
    Ok(())
}

fn remove_entry(d: &mut [u8], pos: usize) -> Result<(), Errno> {
    let n = entries(d);
    let at = HEADER + ENTRY * pos;
    let end = HEADER + ENTRY * n;
    if pos >= n || end > d.len() {
        return Err(Errno::EIO);
    }
    d.copy_within(at + ENTRY..end, at);
    set_entries(d, n - 1);
    Ok(())
}

/// A node on the way down: its block (0 for the root) and bytes.
struct Node {
    block: u64,
    data: Vec<u8>,
}

/// The nodes from the root to a leaf, each with the entry chosen in it.
type Path = Vec<(Node, usize)>;

/// The block ranges a truncate frees. A dry run only counts them, so that
/// room for the real run is reserved before anything is changed.
struct Frees {
    list: Vec<(u64, u64)>,
    dry: bool,
    count: usize,
    /// Nodes still allowed to be read: a sound tree has no more than the
    /// file system has blocks, so a corrupt one that revisits blocks stops.
    budget: u64,
}

impl Frees {
    fn push(&mut self, range: (u64, u64)) -> Result<(), Errno> {
        if self.dry {
            self.count += 1;
        } else if self.list.len() < self.list.capacity() {
            // Within the capacity the dry run counted.
            self.list.push(range);
        } else {
            return Err(Errno::EIO);
        }
        Ok(())
    }
}

fn check_root(data: &[u8]) -> Result<(), Errno> {
    if get16(data, 0) != MAGIC || max(data) > ROOT_MAX as usize || entries(data) > max(data) || depth(data) > MAX_DEPTH
    {
        return Err(Errno::EIO);
    }
    Ok(())
}

/// The new nodes an insertion through `path` takes: one for each full node
/// from the leaf up, the last of them the root growing a level.
fn blocks_needed(path: &Path) -> Result<usize, Errno> {
    let mut need = 0;
    for (level, (node, _)) in path.iter().enumerate().rev() {
        if entries(&node.data) < max(&node.data) {
            break;
        }
        if level == 0 && depth(&node.data) + 1 > MAX_DEPTH {
            return Err(Errno::EFBIG);
        }
        need += 1;
    }
    Ok(need)
}

impl<D: BlockDevice + Send + 'static> Fs<D> {
    fn ext_seed(&self, ino: u32, inode: &Inode) -> u32 {
        if self.csum == Csum::Crc32c { self.inode_seed(ino, inode) } else { 0 }
    }

    fn tail(&self, d: &[u8]) -> usize {
        HEADER + ENTRY * max(d)
    }

    fn read_node(&mut self, seed: u32, b: u64, want_depth: u16) -> Result<Vec<u8>, Errno> {
        let data = self.read_block(b)?;
        let limit = self.block_size.saturating_sub(HEADER) / ENTRY;
        if get16(&data, 0) != MAGIC || max(&data) > limit || entries(&data) > max(&data) || depth(&data) != want_depth {
            return Err(Errno::EIO);
        }
        if self.csum == Csum::Crc32c {
            let tail = self.tail(&data);
            if get32(&data, tail) != super::csum::crc32c(seed, sub(&data, 0..tail)) {
                return Err(Errno::EIO);
            }
        }
        Ok(data)
    }

    fn write_ext_block(&mut self, seed: u32, b: u64, data: &mut [u8]) -> Result<(), Errno> {
        if self.csum == Csum::Crc32c {
            let tail = self.tail(data);
            let sum = super::csum::crc32c(seed, sub(data, 0..tail));
            put32(data, tail, sum);
        }
        self.write_block(b, data)
    }

    /// Writes a node back: the root into the inode (which the caller
    /// writes), any other node to its block.
    fn write_node(&mut self, seed: u32, inode: &mut Inode, node: &mut Node) -> Result<(), Errno> {
        if node.block == 0 {
            put_bytes(&mut inode.raw, ino::BLOCK, &node.data)
        } else {
            self.write_ext_block(seed, node.block, &mut node.data)
        }
    }

    /// Walks from the root to the leaf whose range holds `lblk`, choosing
    /// in each node the last entry at or before it (or the first).
    fn ext_path(&mut self, seed: u32, inode: &Inode, lblk: u32) -> Result<Path, Errno> {
        let data = try_to_vec(root_bytes(inode))?;
        check_root(&data)?;
        // One more than the tree is deep, and room for the level that
        // growing the tree at the root adds.
        let mut path = Vec::new();
        path.try_reserve_exact(usize::from(depth(&data)) + 2).map_err(|_| Errno::ENOMEM)?;
        let mut node = Node { block: 0, data };
        loop {
            let n = entries(&node.data);
            let mut i = 0;
            while i + 1 < n && key(&node.data, i + 1) <= lblk {
                i += 1;
            }
            let d = depth(&node.data);
            if d == 0 {
                path.push((node, i));
                return Ok(path);
            }
            if n == 0 {
                return Err(Errno::EIO);
            }
            let b = child(&node.data, i);
            path.push((node, i));
            let data = self.read_node(seed, b, d - 1)?;
            node = Node { block: b, data };
        }
    }

    /// The extent version of [`Fs::bmap`].
    pub(super) fn ext_map(&mut self, ino: u32, inode: &mut Inode, lblk: u64, alloc: bool) -> Result<u64, Errno> {
        if lblk >= MAX_BLOCKS {
            return Err(Errno::EFBIG);
        }
        let lblk = lblk as u32;
        let seed = self.ext_seed(ino, inode);
        let path = self.ext_path(seed, inode, lblk)?;
        let Some((leaf, i)) = path.last() else { return Err(Errno::EIO) };
        let near = (entries(&leaf.data) > 0).then(|| Extent::get(&leaf.data, *i));
        let mut goal = self.group_start(self.group_of(ino));
        if let Some(e) = near
            && e.block <= lblk
        {
            let p = e.start + (lblk - e.block) as u64;
            if (lblk as u64) < e.end() {
                if !e.uninit {
                    return Ok(p);
                }
                if !alloc {
                    // Allocated but never written: reads as a hole.
                    return Ok(0);
                }
                self.ext_convert(seed, inode, path, lblk)?;
                let zero = try_zeroed(self.block_size)?;
                self.write_data_block(p, &zero)?;
                return Ok(p);
            }
            goal = p;
        }
        if !alloc {
            return Ok(0);
        }
        let p = self.alloc_block(goal)?;
        let sectors = (self.block_size / 512) as i64;
        inode.add_sectors(sectors);
        let mut spare = Vec::new();
        let result =
            self.ext_insert(seed, inode, path, Extent { block: lblk, len: 1, start: p, uninit: false }, &mut spare);
        self.release(spare)?;
        if let Err(e) = result {
            self.free_run(p, 1)?;
            inode.add_sectors(-sectors);
            return Err(e);
        }
        Ok(p)
    }

    /// Frees tree blocks reserved but not used.
    fn release(&mut self, spare: Vec<u64>) -> Result<(), Errno> {
        for b in spare {
            self.free_run(b, 1)?;
        }
        Ok(())
    }

    /// Adds `ext` to the tree, extending a neighbour when it continues one.
    /// `path` leads to the leaf for `ext.block`, which is not mapped. New
    /// nodes come from `spare`, topped up before anything changes so that a
    /// full disk leaves the tree as it was; the caller releases what is left.
    fn ext_insert(
        &mut self,
        seed: u32,
        inode: &mut Inode,
        mut path: Path,
        ext: Extent,
        spare: &mut Vec<u64>,
    ) -> Result<(), Errno> {
        let level = path.len().checked_sub(1).ok_or(Errno::EIO)?;
        let (leaf, i) = path.get_mut(level).ok_or(Errno::EIO)?;
        let (n, i) = (entries(&leaf.data), *i);
        let pos = if n == 0 {
            0
        } else if Extent::get(&leaf.data, i).block < ext.block {
            let prev = Extent::get(&leaf.data, i);
            if prev.joins(ext) {
                Extent { len: prev.len + ext.len, ..prev }.put(&mut leaf.data, i)?;
                return self.write_node(seed, inode, leaf);
            }
            if i + 1 < n {
                let next = Extent::get(&leaf.data, i + 1);
                if ext.joins(next) {
                    Extent { len: ext.len + next.len, ..ext }.put(&mut leaf.data, i + 1)?;
                    return self.write_node(seed, inode, leaf);
                }
            }
            i + 1
        } else {
            // Before every entry of the leftmost leaf.
            let next = Extent::get(&leaf.data, 0);
            if ext.joins(next) {
                Extent { len: ext.len + next.len, ..ext }.put(&mut leaf.data, 0)?;
                self.write_node(seed, inode, leaf)?;
                return self.fix_keys(seed, inode, &mut path, level);
            }
            0
        };
        let need = blocks_needed(&path)?;
        // Before the first block is taken, so a failure here leaks none.
        spare.try_reserve(need.saturating_sub(spare.len())).map_err(|_| Errno::ENOMEM)?;
        while spare.len() < need {
            let b = self.alloc_block(self.group_start(0))?;
            spare.push(b);
        }
        self.insert_entry(seed, inode, &mut path, level, pos, ext.bytes(), spare)
    }

    /// Puts `entry` at `pos` in the node at `level`, splitting full nodes
    /// (and growing the tree at the root) as needed, with new nodes from
    /// `spare`.
    #[allow(clippy::too_many_arguments)]
    fn insert_entry(
        &mut self,
        seed: u32,
        inode: &mut Inode,
        path: &mut Path,
        level: usize,
        pos: usize,
        entry: [u8; ENTRY],
        spare: &mut Vec<u64>,
    ) -> Result<(), Errno> {
        let node = &mut path.get_mut(level).ok_or(Errno::EIO)?.0;
        let n = entries(&node.data);
        if n < max(&node.data) {
            put_entry(&mut node.data, pos, &entry)?;
            self.write_node(seed, inode, node)?;
            return if pos == 0 { self.fix_keys(seed, inode, path, level) } else { Ok(()) };
        }
        let block_max = self.block_size.saturating_sub(HEADER) / ENTRY;
        let sectors = (self.block_size / 512) as i64;
        if level == 0 {
            // Grow: the root's entries move into a new node below it.
            let d = depth(&node.data);
            if d + 1 > MAX_DEPTH {
                return Err(Errno::EFBIG);
            }
            let mut data = try_zeroed(self.block_size)?;
            let b = spare.pop().ok_or(Errno::EIO)?;
            inode.add_sectors(sectors);
            header(&mut data, block_max, d);
            put_bytes(&mut data, HEADER, sub(&node.data, HEADER..HEADER + ENTRY * n))?;
            set_entries(&mut data, n);
            let first = key(&data, 0);
            let mut below = Node { block: b, data };
            self.write_node(seed, inode, &mut below)?;
            let (root, chosen) = path.get_mut(0).ok_or(Errno::EIO)?;
            let chosen = core::mem::replace(chosen, 0);
            header(&mut root.data, ROOT_MAX as usize, d + 1);
            put_entry(&mut root.data, 0, &index_entry(first, b))?;
            self.write_node(seed, inode, root)?;
            // Room was reserved for the level this adds (see `ext_path`).
            path.insert(1, (below, chosen));
            return self.insert_entry(seed, inode, path, 1, pos, entry, spare);
        }
        // Split: the upper entries move to a new node to the right. An
        // append starts the new node empty, which keeps sequential files'
        // nodes full.
        let mid = if pos == n { n } else { n / 2 };
        let mut data = try_zeroed(self.block_size)?;
        let b = spare.pop().ok_or(Errno::EIO)?;
        inode.add_sectors(sectors);
        let node = &mut path.get_mut(level).ok_or(Errno::EIO)?.0;
        header(&mut data, block_max, depth(&node.data));
        put_bytes(&mut data, HEADER, sub(&node.data, HEADER + ENTRY * mid..HEADER + ENTRY * n))?;
        set_entries(&mut data, n - mid);
        set_entries(&mut node.data, mid);
        let mut right = Node { block: b, data };
        if pos >= mid {
            put_entry(&mut right.data, pos - mid, &entry)?;
        } else {
            put_entry(&mut node.data, pos, &entry)?;
        }
        self.write_node(seed, inode, &mut right)?;
        let node = &mut path.get_mut(level).ok_or(Errno::EIO)?.0;
        self.write_node(seed, inode, node)?;
        if pos == 0 {
            self.fix_keys(seed, inode, path, level)?;
        }
        let parent = level.checked_sub(1).ok_or(Errno::EIO)?;
        let at = path.get(parent).ok_or(Errno::EIO)?.1 + 1;
        self.insert_entry(seed, inode, path, parent, at, index_entry(key(&right.data, 0), b), spare)
    }

    /// After the first key of the node at `level` changed, updates the
    /// parent entries above it.
    fn fix_keys(&mut self, seed: u32, inode: &mut Inode, path: &mut Path, mut level: usize) -> Result<(), Errno> {
        while level > 0 {
            let first = key(&path.get(level).ok_or(Errno::EIO)?.0.data, 0);
            let (parent, i) = path.get_mut(level - 1).ok_or(Errno::EIO)?;
            let o = HEADER + ENTRY * *i;
            if get32(&parent.data, o) == first {
                return Ok(());
            }
            put32(&mut parent.data, o, first);
            let i = *i;
            self.write_node(seed, inode, parent)?;
            if i != 0 {
                return Ok(());
            }
            level -= 1;
        }
        Ok(())
    }

    /// Marks block `lblk` of the uninitialized extent chosen in `path`'s
    /// leaf initialized, splitting the extent around it.
    fn ext_convert(&mut self, seed: u32, inode: &mut Inode, path: Path, lblk: u32) -> Result<(), Errno> {
        // Up to two entries go into this leaf. Without room for them, take
        // enough nodes for two splits to the root (and a level more) first.
        let leaf = &path.last().ok_or(Errno::EIO)?.0;
        let mut spare = Vec::new();
        spare.try_reserve_exact(2 * (path.len() + 1)).map_err(|_| Errno::ENOMEM)?;
        if max(&leaf.data).saturating_sub(entries(&leaf.data)) < 2 {
            for _ in 0..2 * (path.len() + 1) {
                match self.alloc_block(self.group_start(0)) {
                    Ok(b) => spare.push(b),
                    Err(e) => {
                        self.release(spare)?;
                        return Err(e);
                    }
                }
            }
        }
        let result = self.ext_split_uninit(seed, inode, path, lblk, &mut spare);
        self.release(spare)?;
        result
    }

    fn ext_split_uninit(
        &mut self,
        seed: u32,
        inode: &mut Inode,
        mut path: Path,
        lblk: u32,
        spare: &mut Vec<u64>,
    ) -> Result<(), Errno> {
        let (leaf, i) = path.last_mut().ok_or(Errno::EIO)?;
        let i = *i;
        let e = Extent::get(&leaf.data, i);
        // The path was chosen for `lblk`, inside the extent; a corrupt tree may say otherwise.
        let off = lblk.checked_sub(e.block).filter(|&off| off < e.len).ok_or(Errno::EIO)?;
        let one = Extent { block: lblk, len: 1, start: e.start + off as u64, uninit: false };
        let rest = Extent { block: lblk + 1, len: e.len - off - 1, start: one.start + 1, uninit: true };
        // `one` and `rest`, at most.
        let mut pending = Vec::new();
        pending.try_reserve_exact(2).map_err(|_| Errno::ENOMEM)?;
        if off > 0 {
            Extent { len: off, ..e }.put(&mut leaf.data, i)?;
            pending.push(one);
        } else if i > 0 && Extent::get(&leaf.data, i - 1).joins(one) {
            // Writing on through preallocated space grows the extent before.
            let prev = Extent::get(&leaf.data, i - 1);
            Extent { len: prev.len + 1, ..prev }.put(&mut leaf.data, i - 1)?;
            if rest.len > 0 {
                rest.put(&mut leaf.data, i)?;
            } else {
                remove_entry(&mut leaf.data, i)?;
            }
            return self.write_node(seed, inode, leaf);
        } else {
            one.put(&mut leaf.data, i)?;
        }
        if rest.len > 0 {
            pending.push(rest);
        }
        self.write_node(seed, inode, leaf)?;
        for ext in pending {
            let path = self.ext_path(seed, inode, ext.block)?;
            self.ext_insert(seed, inode, path, ext, spare)?;
        }
        Ok(())
    }

    /// The extent version of [`Fs::truncate_blocks`]. Blocks are freed
    /// only once no node and not the inode itself refers to them, so a
    /// failure part way leaks blocks rather than leaving a reference to a
    /// free one.
    pub(super) fn ext_truncate(&mut self, ino: u32, inode: &mut Inode, keep: u64) -> Result<(), Errno> {
        let seed = self.ext_seed(ino, inode);
        let mut root = try_to_vec(root_bytes(inode))?;
        check_root(&root)?;
        // A sound tree has no more nodes than the file system has blocks.
        let budget = self.blocks_count();
        // A dry run counts what will be freed, so the list is reserved before
        // any node is changed: running out of memory after would leak blocks.
        let mut frees = Frees { list: Vec::new(), dry: true, count: 0, budget };
        self.trunc_node(seed, &mut try_to_vec(&root)?, keep, &mut frees)?;
        frees.list.try_reserve_exact(frees.count).map_err(|_| Errno::ENOMEM)?;
        frees.dry = false;
        frees.budget = budget;
        self.trunc_node(seed, &mut root, keep, &mut frees)?;
        if entries(&root) == 0 {
            put16(&mut root, 6, 0);
        }
        put_bytes(&mut inode.raw, ino::BLOCK, &root)?;
        let freed = frees.list.iter().fold(0u64, |sum, &(_, n)| sum.saturating_add(n));
        inode.add_sectors(-(freed.saturating_mul((self.block_size / 512) as u64).min(i64::MAX as u64) as i64));
        self.write_inode(ino, inode)?;
        for (start, n) in frees.list {
            self.free_run(start, n)?;
        }
        Ok(())
    }

    /// Drops the mappings under a node from logical block `keep` on, and
    /// the children left empty, noting the blocks to free in `frees`;
    /// returns whether the node changed. Changed children are written.
    fn trunc_node(&mut self, seed: u32, data: &mut [u8], keep: u64, frees: &mut Frees) -> Result<bool, Errno> {
        let d = depth(data);
        // Only a run of trailing entries is ever removed: `n` is how many
        // stay.
        let (mut n, mut i) = (entries(data), entries(data));
        let mut changed = false;
        while i > 0 {
            i -= 1;
            let k = key(data, i) as u64;
            if d == 0 {
                let e = Extent::get(data, i);
                if e.end() <= keep {
                    break;
                }
                changed = true;
                if k >= keep {
                    frees.push((e.start, e.len as u64))?;
                    n = i;
                    continue;
                }
                let cut = (e.end() - keep) as u32;
                frees.push((e.start + (e.len - cut) as u64, cut as u64))?;
                Extent { len: e.len - cut, ..e }.put(data, i)?;
                break;
            }
            let b = child(data, i);
            frees.budget = frees.budget.checked_sub(1).ok_or(Errno::EIO)?;
            let mut below = self.read_node(seed, b, d.saturating_sub(1))?;
            if self.trunc_node(seed, &mut below, keep, frees)? {
                changed = true;
                if entries(&below) == 0 {
                    frees.push((b, 1))?;
                    n = i;
                    continue;
                }
                if !frees.dry {
                    self.write_ext_block(seed, b, &mut below)?;
                }
            }
            if k >= keep {
                // A child keyed past `keep` kept something: out of order.
                return Err(Errno::EIO);
            }
            // The children before this one end before `keep`.
            break;
        }
        set_entries(data, n);
        Ok(changed)
    }
}
