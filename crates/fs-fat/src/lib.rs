//! A FAT12, FAT16 or FAT32 file system on any [`BlockDevice`], for the `osmium-fs` VFS.
//!
//! [`FatFs::mount`] reads the volume and [`FatFs::root`] hands out its root
//! directory as an [`osmium_fs::File`], ready for `Vfs::mount`. Long (VFAT)
//! names are read and written; new names that do not fit 8.3 get a
//! generated `NAME~N.EXT` short name alongside.
//!
//! The device and all volume state sit behind one lock, and every node is
//! known by the disk position of its directory entry, which serves as its
//! inode number. Nodes are shared: looking a name up twice yields the same
//! node, so a file removed while open keeps its clusters until the last
//! reference goes.
//!
//! The variant is told from the boot sector by its cluster count, as the
//! Microsoft specification requires. FAT12 and FAT16 keep their root
//! directory in a fixed region before the data, so it cannot grow: creating
//! an entry in a full one fails with `ENOSPC`.
//!
//! Not supported: exFAT, timestamps (new entries get a fixed date),
//! rename, and permissions beyond the read-only attribute. The volume's
//! sector size must be a multiple of the device's block size.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod dir;
mod layout;
mod name;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, Ordering};

use osmium_fs::{DirEntry, Errno, File, FileKind, Stat};
use osmium_hal::block::{BlockDevice, BlockError};
use osmium_sync::SpinLock;
use osmium_sync::arc::ArcTree;
use osmium_sync::fallible::{try_arc, try_string, try_zeroed};
use osmium_sync::intrusive::{Adapter, KeyAdapter, Registry, Shared as SharedLink, TreeLink};

use dir::{ENTRY_SIZE, Entry, attr};
use layout::{FatKind, FsInfo, Geometry, ROOT_FIXED};

/// A free cluster's FAT entry.
const FAT_FREE: u32 = 0;

/// Inode number of the root directory, which has no directory entry.
const ROOT_INO: u64 = 1;

/// Largest file FAT can hold.
const MAX_SIZE: u64 = u32::MAX as u64;

/// Largest directory FAT allows: 65536 entries (§6).
const MAX_DIR: u64 = 65536 * ENTRY_SIZE as u64;

fn io_error(e: BlockError) -> Errno {
    match e {
        BlockError::ReadOnly => Errno::EROFS,
        _ => Errno::EIO,
    }
}

/// What the volume knows about a node that is in use.
struct NodeState<D: BlockDevice + Send + 'static> {
    node: Weak<Node<D>>,
    /// Disk position of the directory entry (the inode number).
    ino: u64,
    kind: FileKind,
    read_only: bool,
    first: u32,
    size: u32,
    /// Removed from its directory while open: free the clusters when the
    /// last reference goes.
    orphan: bool,
}

/// A node in use, as the volume keeps it: its state, linked into the volume's
/// tables by id and (while it is still in a directory) by inode number.
struct NodeEntry<D: BlockDevice + Send + 'static> {
    id: u64,
    /// The state; only touched with the volume locked (see [`Volume::state`]).
    state: UnsafeCell<NodeState<D>>,
    /// The inode number `Volume::by_ino` orders by; set before it is linked.
    ino_key: UnsafeCell<u64>,
    by_id: SharedLink<TreeLink>,
    by_ino: SharedLink<TreeLink>,
}

// SAFETY: the state and key are only accessed with the volume's lock held.
unsafe impl<D: BlockDevice + Send + 'static> Sync for NodeEntry<D> {}

struct ById<D>(core::marker::PhantomData<D>);

// SAFETY: `offset_of!` of a `SharedLink<TreeLink>`, which is a `TreeLink`.
unsafe impl<D: BlockDevice + Send + 'static> Adapter<TreeLink> for ById<D> {
    type Value = NodeEntry<D>;
    const OFFSET: usize = offset_of!(NodeEntry<D>, by_id);
}

impl<D: BlockDevice + Send + 'static> KeyAdapter<TreeLink> for ById<D> {
    type Key = u64;

    fn key(e: &NodeEntry<D>) -> &u64 {
        &e.id
    }
}

struct ByIno<D>(core::marker::PhantomData<D>);

// SAFETY: as for `ById`.
unsafe impl<D: BlockDevice + Send + 'static> Adapter<TreeLink> for ByIno<D> {
    type Value = NodeEntry<D>;
    const OFFSET: usize = offset_of!(NodeEntry<D>, by_ino);
}

impl<D: BlockDevice + Send + 'static> KeyAdapter<TreeLink> for ByIno<D> {
    type Key = u64;

    fn key(e: &NodeEntry<D>) -> &u64 {
        // SAFETY: see `NodeEntry`; only used to compare, with the volume locked.
        unsafe { &*e.ino_key.get() }
    }
}

/// The memory a new node needs, made before anything is committed.
struct Prepared<D: BlockDevice + Send + 'static> {
    node: Arc<Node<D>>,
    entry: Arc<NodeEntry<D>>,
}

struct Volume<D: BlockDevice + Send + 'static> {
    dev: D,
    geo: Geometry,
    /// Device blocks per sector.
    blocks_per_sector: u64,
    info: Option<FsInfo>,
    /// The FAT sector last read, for walking chains without rereading it.
    fat_cache: Option<(u32, Vec<u8>)>,
    /// The last directory parsed by `readdir` (by first cluster), so that
    /// walking it by index parses it once; any write clears it.
    dir_cache: Option<(u32, Vec<dir::Entry>)>,
    /// Nodes in use, by node id.
    nodes: ArcTree<ById<D>>,
    /// The nodes still linked into a directory, by inode number. A removed
    /// but open node leaves this index, so a new entry in the same slot
    /// (same inode number) gets a node of its own. It does not own the
    /// entries: `nodes` does, and an entry leaves this index first.
    by_ino: Registry<ByIno<D>>,
    next_id: u64,
}

struct Shared<D: BlockDevice + Send + 'static> {
    vol: SpinLock<Volume<D>>,
    dev_id: u64,
}

/// A mounted FAT12, FAT16 or FAT32 volume.
pub struct FatFs<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
    /// The root directory's node, made at mount so that handing it out cannot fail.
    root: Arc<dyn File>,
}

/// One file or directory of a [`FatFs`].
pub struct Node<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
    id: u64,
    /// Whether the volume knows this node: not for one made ahead of time
    /// (see `Volume::prepare`) and dropped unused, which must not take the
    /// lock its owner may be holding.
    armed: AtomicBool,
}

impl<D: BlockDevice + Send + 'static> FatFs<D> {
    /// Mounts the FAT volume on `dev`. `dev_id` becomes `Stat::dev` of
    /// every node. Fails with `EINVAL` if the device does not hold FAT12,
    /// FAT16 or FAT32.
    pub fn mount(mut dev: D, dev_id: u64) -> Result<Self, Errno> {
        let bs = dev.block_size();
        // A power of two, so it divides or is a multiple of every sector size.
        if !bs.is_power_of_two() || bs > 4096 {
            return Err(Errno::EINVAL);
        }
        let mut boot = try_zeroed(512.max(bs))?;
        dev.read_blocks(0, &mut boot).map_err(io_error)?;
        let geo = Geometry::parse(&boot)?;
        if !(geo.sector_size as usize).is_multiple_of(bs) {
            return Err(Errno::EINVAL);
        }
        let mut vol = Volume {
            dev,
            blocks_per_sector: (geo.sector_size as usize / bs) as u64,
            geo,
            info: None,
            fat_cache: None,
            dir_cache: None,
            nodes: ArcTree::new(),
            by_ino: Registry::new(),
            next_id: 0,
        };
        let end = geo.data_start as u64 + geo.cluster_count as u64 * geo.sectors_per_cluster as u64;
        if end * vol.blocks_per_sector > vol.dev.num_blocks() {
            return Err(Errno::EINVAL);
        }
        if geo.fsinfo_sector != 0 {
            let mut s = vol.sector_buf()?;
            vol.read_sector(geo.fsinfo_sector, &mut s)?;
            vol.info = FsInfo::parse(&s, &geo);
        } else if geo.kind != FatKind::Fat32 {
            // No FSInfo: count the free clusters once, for allocation hints.
            let mut free = 0;
            for c in 2..geo.cluster_count + 2 {
                if vol.fat_entry(c)? == FAT_FREE {
                    free += 1;
                }
            }
            vol.info = Some(FsInfo { free: Some(free), next_free: 2 });
        }
        let shared = try_arc(Shared { vol: SpinLock::new(vol), dev_id })?;
        let root = {
            let mut vol = shared.vol.lock();
            let state = Probe { kind: FileKind::Directory, read_only: false, first: vol.geo.root_cluster, size: 0 };
            vol.node(&shared, ROOT_INO, state, None)?
        };
        Ok(Self { shared, root })
    }

    /// The root directory, to mount in a `Vfs`.
    pub fn root(&self) -> Arc<dyn File> {
        self.root.clone()
    }

    /// Free space in bytes, if the volume's FSInfo records it.
    pub fn free_bytes(&self) -> Option<u64> {
        let vol = self.shared.vol.lock();
        vol.info?.free.map(|f| f as u64 * vol.geo.cluster_size() as u64)
    }
}

/// What a directory entry says about a node, before it is registered.
struct Probe {
    kind: FileKind,
    read_only: bool,
    first: u32,
    size: u32,
}

impl Probe {
    fn of(e: &Entry) -> Self {
        Probe {
            kind: if e.is_dir() { FileKind::Directory } else { FileKind::Regular },
            read_only: e.attr & attr::READ_ONLY != 0,
            first: e.first,
            size: e.size,
        }
    }
}

impl<D: BlockDevice + Send + 'static> Volume<D> {
    fn sector_buf(&self) -> Result<Vec<u8>, Errno> {
        Ok(try_zeroed(self.geo.sector_size as usize)?)
    }

    /// The state of node `id`, if it is in use. The volume is borrowed for as
    /// long as the state is, so only one is out at a time.
    fn state(&mut self, id: u64) -> Option<&mut NodeState<D>> {
        let entry = self.nodes.find(&id)?;
        // SAFETY: the state is only reachable through this volume, which the
        // caller has exclusively (`&mut self`) for as long as the result lives.
        Some(unsafe { &mut *entry.state.get() })
    }

    /// The memory for a node, made before anything is committed.
    fn prepare(&mut self, shared: &Arc<Shared<D>>) -> Result<Prepared<D>, Errno> {
        let id = self.next_id;
        self.next_id += 1;
        let node = try_arc(Node { shared: shared.clone(), id, armed: AtomicBool::new(false) })?;
        let placeholder = NodeState {
            node: Weak::new(),
            ino: 0,
            kind: FileKind::Regular,
            read_only: false,
            first: 0,
            size: 0,
            orphan: false,
        };
        let entry = try_arc(NodeEntry {
            id,
            state: UnsafeCell::new(placeholder),
            ino_key: UnsafeCell::new(0),
            by_id: SharedLink::new(TreeLink::new()),
            by_ino: SharedLink::new(TreeLink::new()),
        })?;
        Ok(Prepared { node, entry })
    }

    fn read_sector(&mut self, sector: u32, buf: &mut [u8]) -> Result<(), Errno> {
        self.dev.read_blocks(sector as u64 * self.blocks_per_sector, buf).map_err(io_error)
    }

    fn write_sector(&mut self, sector: u32, buf: &[u8]) -> Result<(), Errno> {
        self.dir_cache = None;
        self.dev.write_blocks(sector as u64 * self.blocks_per_sector, buf).map_err(io_error)
    }

    /// The node for `ino`, shared with any existing reference. `spare` is
    /// the memory for a new one, if the caller made it first.
    ///
    /// Called with the lock held; it only ever creates `Arc`s, never drops
    /// one, so a node's `Drop` (which takes the lock) cannot run here.
    fn node(
        &mut self,
        shared: &Arc<Shared<D>>,
        ino: u64,
        probe: Probe,
        spare: Option<Prepared<D>>,
    ) -> Result<Arc<dyn File>, Errno> {
        if let Some(id) = self.by_ino.find(&ino).map(|e| e.id) {
            let state = self.state(id).ok_or(Errno::EIO)?;
            if let Some(existing) = state.node.upgrade() {
                return Ok(existing);
            }
            // Its last reference is being dropped right now, and its Drop
            // waits for this lock. The state is still current, so a new
            // node takes it over (that Drop then sees it is not the owner).
            let node = try_arc(Node { shared: shared.clone(), id, armed: AtomicBool::new(true) })?;
            self.state(id).ok_or(Errno::EIO)?.node = Arc::downgrade(&node);
            return Ok(node);
        }
        let Prepared { node, entry } = match spare {
            Some(p) => p,
            None => self.prepare(shared)?,
        };
        let Probe { kind, read_only, first, size } = probe;
        node.armed.store(true, Ordering::Relaxed);
        // SAFETY: the entry is not in any table yet, so nothing else sees it.
        unsafe {
            *entry.state.get() =
                NodeState { node: Arc::downgrade(&node), ino, kind, read_only, first, size, orphan: false };
            *entry.ino_key.get() = ino;
        }
        // SAFETY: the entry is owned by `nodes`, which outlives its place in
        // `by_ino`: it leaves `by_ino` first (see `Volume::forget`).
        let indexed = unsafe { self.by_ino.insert(&entry) };
        assert!(indexed, "inode numbers are indexed once");
        assert!(self.nodes.insert(entry).is_ok(), "node ids are never reused");
        Ok(node)
    }

    /// Takes node `id` out of the inode index, so a new entry in its slot
    /// gets a node of its own.
    fn unindex(&mut self, id: u64) {
        if let Some(entry) = self.nodes.find(&id) {
            // SAFETY: linked, if at all, in `by_ino`.
            unsafe { self.by_ino.remove(entry) };
        }
    }

    /// Takes node `id` out of both tables and returns its state. Whatever
    /// owned the entry lets go of it here.
    fn forget(&mut self, id: u64) -> Option<NodeState<D>> {
        let entry = self.nodes.take_key(&id)?;
        // SAFETY: linked, if at all, in `by_ino`.
        unsafe { self.by_ino.remove(&entry) };
        // SAFETY: it is out of every table, so nothing else sees the state.
        Some(core::mem::replace(
            unsafe { &mut *entry.state.get() },
            NodeState {
                node: Weak::new(),
                ino: 0,
                kind: FileKind::Regular,
                read_only: false,
                first: 0,
                size: 0,
                orphan: false,
            },
        ))
    }

    // --- The FAT ---------------------------------------------------------

    /// Loads FAT sector `sector` (relative to the first FAT) into the cache.
    fn load_fat(&mut self, sector: u32) -> Result<&[u8], Errno> {
        if self.fat_cache.as_ref().is_none_or(|(s, _)| *s != sector) {
            let mut buf = self.sector_buf()?;
            let at = self.geo.fat_start.checked_add(sector).ok_or(Errno::EIO)?;
            self.read_sector(at, &mut buf)?;
            self.fat_cache = Some((sector, buf));
        }
        self.fat_cache.as_ref().map(|(_, b)| b.as_slice()).ok_or(Errno::EIO)
    }

    /// Reads `N` bytes of the first FAT at byte offset `off`; they may
    /// straddle a sector boundary.
    fn fat_bytes<const N: usize>(&mut self, off: u64) -> Result<[u8; N], Errno> {
        let ss = self.geo.sector_size as u64;
        if off.checked_add(N as u64).is_none_or(|end| end > self.geo.fat_sectors as u64 * ss) {
            return Err(Errno::EIO);
        }
        let mut out = [0u8; N];
        let mut done = 0;
        while done < N {
            let pos = off + done as u64;
            let (sector, within) = ((pos / ss) as u32, (pos % ss) as usize);
            let buf = self.load_fat(sector)?;
            let n = (ss as usize - within).min(N - done);
            let (dst, src) = (out.get_mut(done..done + n), buf.get(within..within + n));
            dst.zip(src).ok_or(Errno::EIO)?.0.copy_from_slice(src.ok_or(Errno::EIO)?);
            done += n;
        }
        Ok(out)
    }

    /// Writes `data` at byte offset `off` of every copy of the FAT.
    fn put_fat_bytes(&mut self, off: u64, data: &[u8]) -> Result<(), Errno> {
        let ss = self.geo.sector_size as u64;
        let mut done = 0;
        while done < data.len() {
            let pos = off + done as u64;
            let (sector, within) = ((pos / ss) as u32, (pos % ss) as usize);
            self.load_fat(sector)?;
            let n = (ss as usize - within).min(data.len() - done);
            let (_, mut buf) = self.fat_cache.take().ok_or(Errno::EIO)?;
            let dst = buf.get_mut(within..within + n).ok_or(Errno::EIO)?;
            dst.copy_from_slice(data.get(done..done + n).ok_or(Errno::EIO)?);
            let mut result = Ok(());
            for copy in 0..self.geo.fats {
                if result.is_ok() {
                    let at = copy
                        .checked_mul(self.geo.fat_sectors)
                        .and_then(|o| o.checked_add(sector))
                        .and_then(|o| o.checked_add(self.geo.fat_start));
                    result = at.ok_or(Errno::EIO).and_then(|at| self.write_sector(at, &buf));
                }
            }
            // A sector whose writes failed is not what the disk holds.
            if result.is_ok() {
                self.fat_cache = Some((sector, buf));
            }
            result?;
            done += n;
        }
        Ok(())
    }

    /// Byte offset of cluster `c`'s entry in the FAT.
    fn fat_offset(&self, c: u32) -> Result<u64, Errno> {
        if c >= self.geo.cluster_count + 2 {
            return Err(Errno::EIO);
        }
        Ok(match self.geo.kind {
            FatKind::Fat12 => c as u64 + c as u64 / 2,
            FatKind::Fat16 => c as u64 * 2,
            FatKind::Fat32 => c as u64 * 4,
        })
    }

    fn fat_entry(&mut self, c: u32) -> Result<u32, Errno> {
        let off = self.fat_offset(c)?;
        Ok(match self.geo.kind {
            FatKind::Fat12 => {
                let v = u16::from_le_bytes(self.fat_bytes::<2>(off)?) as u32;
                if c & 1 == 1 { v >> 4 } else { v & 0x0fff }
            }
            FatKind::Fat16 => u16::from_le_bytes(self.fat_bytes::<2>(off)?) as u32,
            FatKind::Fat32 => u32::from_le_bytes(self.fat_bytes::<4>(off)?) & FatKind::Fat32.mask(),
        })
    }

    /// Sets cluster `c`'s FAT entry in every copy of the FAT.
    fn set_fat_entry(&mut self, c: u32, value: u32) -> Result<(), Errno> {
        let off = self.fat_offset(c)?;
        let mask = self.geo.kind.mask();
        match self.geo.kind {
            FatKind::Fat12 => {
                // Two entries share three bytes: keep the neighbour's nibble.
                let old = u16::from_le_bytes(self.fat_bytes::<2>(off)?);
                let v = (value & mask) as u16;
                let new = if c & 1 == 1 { (old & 0x000f) | v << 4 } else { (old & 0xf000) | v };
                self.put_fat_bytes(off, &new.to_le_bytes())
            }
            FatKind::Fat16 => self.put_fat_bytes(off, &(value as u16).to_le_bytes()),
            FatKind::Fat32 => {
                let old = u32::from_le_bytes(self.fat_bytes::<4>(off)?);
                // The top four bits are reserved and must be preserved.
                self.put_fat_bytes(off, &((old & !mask) | (value & mask)).to_le_bytes())
            }
        }
    }

    /// The cluster after `c`, or `None` at the end of the chain. A chain
    /// that points outside the volume is reported as `EIO`.
    fn next(&mut self, c: u32) -> Result<Option<u32>, Errno> {
        match self.fat_entry(c)? {
            v if v > self.geo.kind.bad() => Ok(None),
            v if self.geo.is_data_cluster(v) => Ok(Some(v)),
            _ => Err(Errno::EIO),
        }
    }

    /// Allocates a zeroed cluster, linking it after `prev` if given. The
    /// FSInfo free count is only a hint, so even at 0 the FAT is searched.
    fn alloc_cluster(&mut self, prev: Option<u32>) -> Result<u32, Errno> {
        let count = self.geo.cluster_count;
        let start = self.info.map_or(2, |i| i.next_free);
        let mut found = None;
        for i in 0..count {
            let c = 2 + ((start.saturating_sub(2) as u64 + i as u64) % count as u64) as u32;
            if self.fat_entry(c)? == FAT_FREE {
                found = Some(c);
                break;
            }
        }
        let c = found.ok_or(Errno::ENOSPC)?;
        let zero = self.sector_buf()?;
        let first = self.geo.cluster_sector(c);
        for s in 0..self.geo.sectors_per_cluster {
            self.write_sector(first + s, &zero)?;
        }
        self.set_fat_entry(c, self.geo.kind.eoc())?;
        if let Some(p) = prev
            && let Err(e) = self.set_fat_entry(p, c)
        {
            // Do not leave the new cluster marked in use and unreachable.
            let _ = self.set_fat_entry(c, FAT_FREE);
            return Err(e);
        }
        if let Some(info) = &mut self.info {
            // A count that was wrong becomes unknown.
            info.free = info.free.and_then(|f| f.checked_sub(1));
            info.next_free = if c + 1 < count + 2 { c + 1 } else { 2 };
        }
        Ok(c)
    }

    /// Frees the chain starting at `first` (0 means no chain).
    fn free_chain(&mut self, first: u32) -> Result<(), Errno> {
        let mut c = first;
        let mut steps = 0;
        while self.geo.is_data_cluster(c) && steps <= self.geo.cluster_count {
            let next = self.fat_entry(c)?;
            if next == FAT_FREE || next == self.geo.kind.bad() {
                break; // already free: a damaged chain, stop here
            }
            self.set_fat_entry(c, FAT_FREE)?;
            if let Some(info) = &mut self.info {
                info.free = info.free.map(|f| f + 1).filter(|&f| f <= self.geo.cluster_count);
            }
            c = next;
            steps += 1;
        }
        Ok(())
    }

    /// The `n`th cluster of the chain at `first`, if the chain is that long.
    /// A chain longer than the volume (a cycle) is `EIO`.
    fn nth(&mut self, first: u32, n: u64) -> Result<Option<u32>, Errno> {
        if !self.geo.is_data_cluster(first) {
            return Ok(None);
        }
        let mut c = first;
        for i in 0..n {
            if i >= self.geo.cluster_count as u64 {
                return Err(Errno::EIO);
            }
            match self.next(c)? {
                Some(next) => c = next,
                None => return Ok(None),
            }
        }
        Ok(Some(c))
    }

    /// Clusters in the chain at `first`; `EIO` if there are more than `max`.
    fn chain_len(&mut self, first: u32, max: u64) -> Result<u64, Errno> {
        let max = max.min(self.geo.cluster_count as u64); // any more is a cycle
        let mut n = 0;
        let mut c = if self.geo.is_data_cluster(first) { Some(first) } else { None };
        while let Some(cur) = c {
            n += 1;
            if n > max {
                return Err(Errno::EIO);
            }
            c = self.next(cur)?;
        }
        Ok(n)
    }

    // --- Bytes in a chain --------------------------------------------------

    /// Reads up to `buf.len()` bytes at `off` of the chain at `first`,
    /// stopping at `limit` bytes or the chain's end; returns the count.
    fn read_chain(&mut self, first: u32, off: u64, buf: &mut [u8], limit: u64) -> Result<usize, Errno> {
        if first == ROOT_FIXED {
            return self.read_root(off, buf, limit);
        }
        let cs = self.geo.cluster_size() as u64;
        let ss = self.geo.sector_size as u64;
        let want = (buf.len() as u64).min(limit.saturating_sub(off)) as usize;
        if want == 0 {
            return Ok(0); // without walking the chain to `off`
        }
        let mut done = 0;
        let mut cluster = self.nth(first, off / cs)?;
        let mut sector = self.sector_buf()?;
        while done < want {
            let Some(c) = cluster else { break };
            let pos = off + done as u64;
            let in_cluster = pos % cs;
            let s = self.geo.cluster_sector(c) + (in_cluster / ss) as u32;
            let in_sector = (in_cluster % ss) as usize;
            let n = (ss as usize - in_sector).min(want - done);
            let dst = buf.get_mut(done..done + n).ok_or(Errno::EIO)?;
            if in_sector == 0 && n == ss as usize {
                self.read_sector(s, dst)?;
            } else {
                self.read_sector(s, &mut sector)?;
                dst.copy_from_slice(sector.get(in_sector..in_sector + n).ok_or(Errno::EIO)?);
            }
            done += n;
            if (off + done as u64).is_multiple_of(cs) {
                cluster = self.next(c)?;
            }
        }
        Ok(done)
    }

    /// Like `read_chain`, for the fixed root directory of FAT12/16.
    fn read_root(&mut self, off: u64, buf: &mut [u8], limit: u64) -> Result<usize, Errno> {
        let ss = self.geo.sector_size as u64;
        let limit = limit.min(self.geo.root_bytes());
        let want = (buf.len() as u64).min(limit.saturating_sub(off)) as usize;
        let mut done = 0;
        let mut sector = self.sector_buf()?;
        while done < want {
            let pos = off + done as u64;
            let s = self.geo.root_start + (pos / ss) as u32;
            let in_sector = (pos % ss) as usize;
            let n = (ss as usize - in_sector).min(want - done);
            self.read_sector(s, &mut sector)?;
            let dst = buf.get_mut(done..done + n).ok_or(Errno::EIO)?;
            dst.copy_from_slice(sector.get(in_sector..in_sector + n).ok_or(Errno::EIO)?);
            done += n;
        }
        Ok(done)
    }

    /// Like `write_chain`, for the fixed root directory, which cannot grow.
    fn write_root(&mut self, off: u64, data: &[u8]) -> Result<(), Errno> {
        let ss = self.geo.sector_size as u64;
        if off.checked_add(data.len() as u64).is_none_or(|end| end > self.geo.root_bytes()) {
            return Err(Errno::ENOSPC);
        }
        let mut done = 0;
        let mut sector = self.sector_buf()?;
        while done < data.len() {
            let pos = off + done as u64;
            let s = self.geo.root_start + (pos / ss) as u32;
            let in_sector = (pos % ss) as usize;
            let n = (ss as usize - in_sector).min(data.len() - done);
            self.read_sector(s, &mut sector)?;
            let dst = sector.get_mut(in_sector..in_sector + n).ok_or(Errno::EIO)?;
            dst.copy_from_slice(data.get(done..done + n).ok_or(Errno::EIO)?);
            self.write_sector(s, &sector)?;
            done += n;
        }
        Ok(())
    }

    /// Writes `data` at `off` of the chain at `*first`, allocating clusters
    /// (zeroed) as needed; `*first` changes if the chain was empty.
    fn write_chain(&mut self, first: &mut u32, off: u64, data: &[u8]) -> Result<(), Errno> {
        if data.is_empty() {
            return Ok(());
        }
        if *first == ROOT_FIXED {
            return self.write_root(off, data);
        }
        let cs = self.geo.cluster_size() as u64;
        let ss = self.geo.sector_size as u64;
        // Find (or grow to) the cluster holding `off`.
        if !self.geo.is_data_cluster(*first) {
            *first = self.alloc_cluster(None)?;
        }
        let mut c = *first;
        for i in 0..off / cs {
            if i >= self.geo.cluster_count as u64 {
                return Err(Errno::EIO); // a cycle
            }
            c = match self.next(c)? {
                Some(n) => n,
                None => self.alloc_cluster(Some(c))?,
            };
        }
        let mut done = 0;
        let mut sector = self.sector_buf()?;
        loop {
            let pos = off + done as u64;
            let in_cluster = pos % cs;
            let s = self.geo.cluster_sector(c) + (in_cluster / ss) as u32;
            let in_sector = (in_cluster % ss) as usize;
            let n = (ss as usize - in_sector).min(data.len() - done);
            let src = data.get(done..done + n).ok_or(Errno::EIO)?;
            if in_sector == 0 && n == ss as usize {
                self.write_sector(s, src)?;
            } else {
                self.read_sector(s, &mut sector)?;
                sector.get_mut(in_sector..in_sector + n).ok_or(Errno::EIO)?.copy_from_slice(src);
                self.write_sector(s, &sector)?;
            }
            done += n;
            if done == data.len() {
                return Ok(());
            }
            if (off + done as u64).is_multiple_of(cs) {
                c = match self.next(c)? {
                    Some(n) => n,
                    None => self.alloc_cluster(Some(c))?,
                };
            }
        }
    }

    /// Fills `[from, to)` of the chain at `*first` with zeroes, but only
    /// where clusters already exist (new clusters are zeroed when
    /// allocated).
    fn zero_range(&mut self, first: &mut u32, from: u64, to: u64) -> Result<(), Errno> {
        let cs = self.geo.cluster_size() as u64;
        let allocated = self.chain_len(*first, u64::MAX)? * cs;
        let end = to.min(allocated);
        let zeros = try_zeroed(cs as usize)?;
        let mut pos = from;
        while pos < end {
            let n = (end - pos).min(cs - pos % cs);
            self.write_chain(first, pos, zeros.get(..n as usize).ok_or(Errno::EIO)?)?;
            pos += n;
        }
        Ok(())
    }

    /// Writes zeroes over `[from, to)` of the chain at `*first`, growing it
    /// as needed.
    fn write_zeros(&mut self, first: &mut u32, from: u64, to: u64) -> Result<(), Errno> {
        let cs = self.geo.cluster_size() as u64;
        let zeros = try_zeroed(cs as usize)?;
        let mut pos = from;
        while pos < to {
            let n = (to - pos).min(cs - pos % cs);
            self.write_chain(first, pos, zeros.get(..n as usize).ok_or(Errno::EIO)?)?;
            pos += n;
        }
        Ok(())
    }

    /// Cuts the chain at `*first` to the clusters needed for `len` bytes.
    fn shrink_chain(&mut self, first: &mut u32, len: u64) -> Result<(), Errno> {
        let cs = self.geo.cluster_size() as u64;
        let keep = len.div_ceil(cs);
        if keep == 0 {
            let old = core::mem::replace(first, 0);
            return self.free_chain(old);
        }
        if let Some(last) = self.nth(*first, keep - 1)?
            && let Some(rest) = self.next(last)?
        {
            self.set_fat_entry(last, self.geo.kind.eoc())?;
            self.free_chain(rest)?;
        }
        Ok(())
    }

    // --- Directories -------------------------------------------------------

    /// A directory's whole contents; `EIO` if it is larger than FAT allows.
    fn dir_bytes(&mut self, first: u32) -> Result<Vec<u8>, Errno> {
        if first == ROOT_FIXED {
            let mut buf = try_zeroed(self.geo.root_bytes() as usize)?;
            let n = self.read_root(0, &mut buf, u64::MAX)?;
            buf.truncate(n);
            return Ok(buf);
        }
        let cs = self.geo.cluster_size() as u64;
        let len = self.chain_len(first, MAX_DIR.div_ceil(cs))? * cs;
        let mut buf = try_zeroed(len as usize)?;
        let n = self.read_chain(first, 0, &mut buf, len)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// The disk position of byte `off` of directory `first`: the inode
    /// number of the entry there.
    fn entry_ino(&mut self, first: u32, off: usize) -> Result<u64, Errno> {
        if first == ROOT_FIXED {
            if off as u64 >= self.geo.root_bytes() {
                return Err(Errno::EIO);
            }
            return Ok(self.geo.root_start as u64 * self.geo.sector_size as u64 + off as u64);
        }
        let cs = self.geo.cluster_size() as u64;
        let c = self.nth(first, off as u64 / cs)?.ok_or(Errno::EIO)?;
        Ok(self.geo.cluster_sector(c) as u64 * self.geo.sector_size as u64 + off as u64 % cs)
    }

    /// Rewrites the first cluster and size in node `id`'s directory entry.
    fn update_entry(&mut self, id: u64) -> Result<(), Errno> {
        let Some(state) = self.state(id) else { return Ok(()) };
        if state.ino == ROOT_INO || state.orphan {
            return Ok(());
        }
        let (ino, first, size, is_dir) = (state.ino, state.first, state.size, state.kind == FileKind::Directory);
        let ss = self.geo.sector_size as u64;
        let sector = (ino / ss) as u32;
        let at = (ino % ss) as usize;
        let mut buf = self.sector_buf()?;
        self.read_sector(sector, &mut buf)?;
        let entry = buf.get_mut(at..at + ENTRY_SIZE).ok_or(Errno::EIO)?;
        dir::set_first_cluster(entry, first);
        let size = if is_dir { 0 } else { size };
        entry.get_mut(28..32).ok_or(Errno::EIO)?.copy_from_slice(&size.to_le_bytes());
        self.write_sector(sector, &buf)
    }

    /// Writes the FSInfo hints and flushes the device.
    fn sync(&mut self) -> Result<(), Errno> {
        if let Some(info) = self.info.filter(|_| self.geo.fsinfo_sector != 0) {
            let mut s = self.sector_buf()?;
            self.read_sector(self.geo.fsinfo_sector, &mut s)?;
            info.store(&mut s);
            self.write_sector(self.geo.fsinfo_sector, &s)?;
        }
        self.dev.flush().map_err(io_error)
    }
}

impl<D: BlockDevice + Send + 'static> Node<D> {
    fn state<'v>(&self, vol: &'v mut Volume<D>) -> Result<&'v mut NodeState<D>, Errno> {
        vol.state(self.id).ok_or(Errno::EIO)
    }

    /// This directory's first cluster, or `ENOTDIR`.
    fn dir_cluster(&self, vol: &mut Volume<D>) -> Result<u32, Errno> {
        let s = self.state(vol)?;
        if s.kind != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        Ok(s.first)
    }

    fn find(vol: &mut Volume<D>, dir: u32, name: &str) -> Result<Option<Entry>, Errno> {
        let bytes = vol.dir_bytes(dir)?;
        let mut found = None;
        for e in dir::entries(&bytes) {
            let e = e?;
            if name::same(&e.name, name) {
                found = Some(e);
                break;
            }
        }
        if vol.geo.kind != FatKind::Fat32 {
            // The high word of the cluster is not part of the entry here.
            if let Some(e) = &mut found {
                e.first &= 0xffff;
            }
        }
        Ok(found)
    }
}

impl<D: BlockDevice + Send + 'static> File for Node<D> {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut vol = self.shared.vol.lock();
        let s = self.state(&mut vol)?;
        if s.kind == FileKind::Directory {
            return Err(Errno::EISDIR);
        }
        let (first, size) = (s.first, s.size as u64);
        vol.read_chain(first, off, buf, size)
    }

    fn write(&self, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        let mut vol = self.shared.vol.lock();
        let s = self.state(&mut vol)?;
        if s.kind == FileKind::Directory {
            return Err(Errno::EISDIR);
        }
        if s.read_only {
            return Err(Errno::EACCES);
        }
        let end = off.checked_add(buf.len() as u64).filter(|&e| e <= MAX_SIZE).ok_or(Errno::EFBIG)?;
        let (mut first, size) = (s.first, s.size as u64);
        // Bytes between the old end and `off` must read back as zeroes.
        let result = (|| {
            if off > size {
                vol.zero_range(&mut first, size, off)?;
            }
            vol.write_chain(&mut first, off, buf)
        })();
        // Record whatever was allocated even if the write failed part way.
        let s = self.state(&mut vol)?;
        s.first = first;
        if result.is_ok() && end > size {
            s.size = end as u32;
        }
        vol.update_entry(self.id)?;
        result.map(|()| buf.len())
    }

    fn stat(&self) -> Stat {
        // An I/O error leaves only what is known without the disk.
        self.try_stat().unwrap_or_else(|_| {
            let mut vol = self.shared.vol.lock();
            match self.state(&mut vol) {
                Ok(s) => Stat { dev: self.shared.dev_id, ino: s.ino, kind: s.kind, ..Stat::default() },
                Err(_) => Stat { dev: self.shared.dev_id, ..Stat::default() },
            }
        })
    }

    fn try_stat(&self) -> Result<Stat, Errno> {
        let mut vol = self.shared.vol.lock();
        let s = self.state(&mut vol)?;
        let (ino, kind, first, read_only, size) = (s.ino, s.kind, s.first, s.read_only, s.size);
        let size = match kind {
            // A directory's size is the space its chain occupies.
            FileKind::Directory if first == ROOT_FIXED => vol.geo.root_bytes(),
            FileKind::Directory => vol.chain_len(first, u64::MAX)? * vol.geo.cluster_size() as u64,
            _ => size as u64,
        };
        let mode = match (kind, read_only) {
            (FileKind::Directory, _) => 0o755,
            (_, true) => 0o444,
            _ => 0o644,
        };
        Ok(Stat {
            dev: self.shared.dev_id,
            ino,
            kind,
            mode,
            nlink: if kind == FileKind::Directory { 2 } else { 1 },
            size,
            rdev: 0,
        })
    }

    fn truncate(&self, len: u64) -> Result<(), Errno> {
        let mut vol = self.shared.vol.lock();
        let s = self.state(&mut vol)?;
        if s.kind == FileKind::Directory {
            return Err(Errno::EISDIR);
        }
        if s.read_only {
            return Err(Errno::EACCES);
        }
        if len > MAX_SIZE {
            return Err(Errno::EFBIG);
        }
        let (mut first, size) = (s.first, s.size as u64);
        // Also when `len == size`: a write that failed part way may have left
        // clusters past the size, which this gives back.
        let result = if len <= size {
            vol.shrink_chain(&mut first, len)
        } else {
            // FAT has no holes: growing writes the zeroes out.
            vol.write_zeros(&mut first, size, len)
        };
        let s = self.state(&mut vol)?;
        s.first = first;
        if result.is_ok() {
            s.size = len as u32;
        }
        vol.update_entry(self.id)?;
        result
    }

    fn sync(&self) -> Result<(), Errno> {
        self.shared.vol.lock().sync()
    }

    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        let mut vol = self.shared.vol.lock();
        let first = self.dir_cluster(&mut vol)?;
        if vol.dir_cache.as_ref().is_none_or(|(f, _)| *f != first) {
            let bytes = vol.dir_bytes(first)?;
            vol.dir_cache = Some((first, dir::parse(&bytes)?));
        }
        let Some((offset, is_dir, name)) = vol
            .dir_cache
            .as_ref()
            .and_then(|(_, entries)| entries.get(index).map(|e| (e.offset, e.is_dir(), try_string(&e.name))))
        else {
            return Ok(None);
        };
        let ino = vol.entry_ino(first, offset)?;
        let kind = if is_dir { FileKind::Directory } else { FileKind::Regular };
        Ok(Some(DirEntry { ino, kind, name: name? }))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        let mut vol = self.shared.vol.lock();
        let first = self.dir_cluster(&mut vol)?;
        let e = Self::find(&mut vol, first, name)?.ok_or(Errno::ENOENT)?;
        let ino = vol.entry_ino(first, e.offset)?;
        vol.node(&self.shared, ino, Probe::of(&e), None)
    }

    fn create(&self, name: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
        let _ = mode; // FAT keeps no permission bits
        if !matches!(kind, FileKind::Regular | FileKind::Directory) {
            return Err(Errno::EPERM);
        }
        name::validate(name)?;
        let mut vol = self.shared.vol.lock();
        let dir_first = self.dir_cluster(&mut vol)?;
        // A damaged directory (first cluster 0, say) has no chain to grow:
        // writing would start one that nothing links to.
        if dir_first != ROOT_FIXED && !vol.geo.is_data_cluster(dir_first) {
            return Err(Errno::EIO);
        }
        // The memory for the new node, before the disk is touched.
        let spare = vol.prepare(&self.shared)?;
        let bytes = vol.dir_bytes(dir_first)?;
        for e in dir::entries(&bytes) {
            if name::same(&e?.name, name) {
                return Err(Errno::EEXIST);
            }
        }

        // The short name, and long-name entries unless it fits 8.3 exactly.
        let taken = dir::short_names(&bytes)?;
        let (short, ntres, mut slots) = match name::exact_short(name) {
            Some((short, ntres)) if !taken.contains(&short) => (short, ntres, Vec::new()),
            _ => {
                let short = name::generate_short(name, &taken)?;
                (short, 0, name::lfn_entries(name, name::checksum(&short))?)
            }
        };

        // Where the entries go (with the short entry last); a directory may
        // grow only so far.
        let at = dir::find_free(&bytes, slots.len() + 1);
        if (at + (slots.len() + 1) * ENTRY_SIZE) as u64 > MAX_DIR {
            return Err(Errno::ENOSPC);
        }

        // The memory for the entries, before a cluster is taken that a failure
        // here would have to give back.
        slots.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
        let mut flat = Vec::new();
        flat.try_reserve_exact((slots.len() + 1) * ENTRY_SIZE).map_err(|_| Errno::ENOMEM)?;

        // A directory gets its first cluster, with `.` and `..`, up front.
        let mut first = 0;
        if kind == FileKind::Directory {
            let parent = if self.state(&mut vol)?.ino == ROOT_INO { 0 } else { dir_first };
            let made = vol.write_chain(&mut first, 0, &dir::dot_entries(0, parent)).and_then(|()| {
                // Now that the cluster is known, record it in `.`.
                let dot = dir::short_entry(b".          ", 0, attr::DIRECTORY, first, 0);
                vol.write_chain(&mut first, 0, &dot)
            });
            if let Err(e) = made {
                let _ = vol.free_chain(first);
                return Err(e);
            }
        }
        let attr_bits = if kind == FileKind::Directory { attr::DIRECTORY } else { attr::ARCHIVE };
        slots.push(dir::short_entry(&short, ntres, attr_bits, first, 0));
        flat.extend(slots.iter().flatten().copied());
        let mut dir_first_mut = dir_first;
        if let Err(e) = vol.write_chain(&mut dir_first_mut, at as u64, &flat) {
            let _ = vol.free_chain(first);
            return Err(e);
        }
        let ino = match vol.entry_ino(dir_first, at + flat.len() - ENTRY_SIZE) {
            Ok(ino) => ino,
            Err(e) => {
                // Take the entries back out before freeing what they name.
                let mut freed = flat;
                for slot in freed.as_chunks_mut::<ENTRY_SIZE>().0 {
                    slot[0] = dir::FREE;
                }
                let _ = vol.write_chain(&mut dir_first_mut, at as u64, &freed);
                let _ = vol.free_chain(first);
                return Err(e);
            }
        };
        let probe = Probe { kind, read_only: false, first, size: 0 };
        vol.node(&self.shared, ino, probe, Some(spare))
    }

    fn remove(&self, name: &str, dir: bool) -> Result<(), Errno> {
        let mut vol = self.shared.vol.lock();
        let dir_first = self.dir_cluster(&mut vol)?;
        let e = Self::find(&mut vol, dir_first, name)?.ok_or(Errno::ENOENT)?;
        match (dir, e.is_dir()) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            _ => {}
        }
        if e.is_dir() {
            let contents = vol.dir_bytes(e.first)?;
            if !dir::is_empty(&contents) {
                return Err(Errno::ENOTEMPTY);
            }
        }
        // Mark every slot (long-name parts and the short entry) free.
        let mut freed = try_zeroed(e.slots() * ENTRY_SIZE)?;
        let mut current = try_zeroed(freed.len())?;
        vol.read_chain(dir_first, e.start as u64, &mut current, u64::MAX)?;
        for (slot, old) in freed.as_chunks_mut::<ENTRY_SIZE>().0.iter_mut().zip(current.as_chunks::<ENTRY_SIZE>().0) {
            slot.copy_from_slice(old);
            slot[0] = dir::FREE;
        }
        let mut d = dir_first;
        vol.write_chain(&mut d, e.start as u64, &freed)?;

        // An open node keeps its clusters until its last reference drops.
        let ino = vol.entry_ino(dir_first, e.offset)?;
        let open = vol.by_ino.find(&ino).map(|e| e.id);
        match open {
            Some(id) if vol.state(id).is_some_and(|s| s.node.strong_count() > 0) => {
                // Out of the index, so a new entry in the slot gets a node
                // of its own; the node keeps its clusters until it is dropped.
                vol.unindex(id);
                if let Some(s) = vol.state(id) {
                    s.orphan = true;
                }
                Ok(())
            }
            other => {
                if let Some(id) = other {
                    drop(vol.forget(id));
                }
                vol.free_chain(e.first)
            }
        }
    }
}

impl<D: BlockDevice + Send + 'static> Drop for Node<D> {
    fn drop(&mut self) {
        if !self.armed.load(Ordering::Relaxed) {
            return;
        }
        let mut vol = self.shared.vol.lock();
        let ours = vol.state(self.id).is_some_and(|s| core::ptr::eq(s.node.as_ptr(), self));
        if !ours {
            return; // another node took over this state (see `Volume::node`)
        }
        let Some(state) = vol.forget(self.id) else { return };
        if state.orphan {
            let _ = vol.free_chain(state.first);
        }
    }
}
