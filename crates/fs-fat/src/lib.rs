//! A FAT32 file system on any [`BlockDevice`], for the `osmium-fs` VFS.
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
//! Not supported: FAT12/16, timestamps (new entries get a fixed date),
//! rename, and permissions beyond the read-only attribute. The volume's
//! sector size must be a multiple of the device's block size.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod dir;
mod layout;
mod name;

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use osmium_fs::{DirEntry, Errno, File, FileKind, Stat};
use osmium_hal::block::{BlockDevice, BlockError};
use osmium_sync::SpinLock;

use dir::{ENTRY_SIZE, Entry, attr};
use layout::{FsInfo, Geometry};

/// FAT entry values.
const FAT_MASK: u32 = 0x0fff_ffff;
const FAT_FREE: u32 = 0;
const FAT_BAD: u32 = 0x0fff_fff7;
const FAT_EOC: u32 = 0x0fff_ffff;

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

struct Volume<D: BlockDevice + Send + 'static> {
    dev: D,
    geo: Geometry,
    /// Device blocks per sector.
    blocks_per_sector: u64,
    info: Option<FsInfo>,
    /// The FAT sector last read, for walking chains without rereading it.
    fat_cache: Option<(u32, Vec<u8>)>,
    /// Nodes in use, by node id.
    nodes: BTreeMap<u64, NodeState<D>>,
    /// Node id by inode number, for nodes still linked into a directory.
    /// A removed but open node leaves this index, so a new entry in the
    /// same slot (same inode number) gets a node of its own.
    by_ino: BTreeMap<u64, u64>,
    next_id: u64,
}

struct Shared<D: BlockDevice + Send + 'static> {
    vol: SpinLock<Volume<D>>,
    dev_id: u64,
}

/// A mounted FAT32 volume.
pub struct FatFs<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
}

/// One file or directory of a [`FatFs`].
pub struct Node<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
    id: u64,
}

impl<D: BlockDevice + Send + 'static> FatFs<D> {
    /// Mounts the FAT32 volume on `dev`. `dev_id` becomes `Stat::dev` of
    /// every node. Fails with `EINVAL` if the device does not hold FAT32.
    pub fn mount(mut dev: D, dev_id: u64) -> Result<Self, Errno> {
        let bs = dev.block_size();
        // A power of two, so it divides or is a multiple of every sector size.
        if !bs.is_power_of_two() || bs > 4096 {
            return Err(Errno::EINVAL);
        }
        let mut boot = vec![0u8; 512.max(bs)];
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
            nodes: BTreeMap::new(),
            by_ino: BTreeMap::new(),
            next_id: 0,
        };
        let end = geo.data_start as u64 + geo.cluster_count as u64 * geo.sectors_per_cluster as u64;
        if end * vol.blocks_per_sector > vol.dev.num_blocks() {
            return Err(Errno::EINVAL);
        }
        if geo.fsinfo_sector != 0 {
            let mut s = vol.sector_buf();
            vol.read_sector(geo.fsinfo_sector, &mut s)?;
            vol.info = FsInfo::parse(&s, &geo);
        }
        Ok(Self { shared: Arc::new(Shared { vol: SpinLock::new(vol), dev_id }) })
    }

    /// The root directory, to mount in a `Vfs`.
    pub fn root(&self) -> Arc<dyn File> {
        let mut vol = self.shared.vol.lock();
        let root = vol.geo.root_cluster;
        let state = Probe { kind: FileKind::Directory, read_only: false, first: root, size: 0 };
        vol.node(&self.shared, ROOT_INO, state)
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
    fn sector_buf(&self) -> Vec<u8> {
        vec![0u8; self.geo.sector_size as usize]
    }

    fn read_sector(&mut self, sector: u32, buf: &mut [u8]) -> Result<(), Errno> {
        self.dev.read_blocks(sector as u64 * self.blocks_per_sector, buf).map_err(io_error)
    }

    fn write_sector(&mut self, sector: u32, buf: &[u8]) -> Result<(), Errno> {
        self.dev.write_blocks(sector as u64 * self.blocks_per_sector, buf).map_err(io_error)
    }

    /// The node for `ino`, shared with any existing reference.
    ///
    /// Called with the lock held; it only ever creates `Arc`s, never drops
    /// one, so a node's `Drop` (which takes the lock) cannot run here.
    fn node(&mut self, shared: &Arc<Shared<D>>, ino: u64, probe: Probe) -> Arc<dyn File> {
        if let Some(&id) = self.by_ino.get(&ino) {
            let state = self.nodes.get_mut(&id).expect("indexed node without state");
            if let Some(existing) = state.node.upgrade() {
                return existing;
            }
            // Its last reference is being dropped right now, and its Drop
            // waits for this lock. The state is still current, so a new
            // node takes it over (that Drop then sees it is not the owner).
            let node = Arc::new(Node { shared: shared.clone(), id });
            state.node = Arc::downgrade(&node);
            return node;
        }
        let id = self.next_id;
        self.next_id += 1;
        let node = Arc::new(Node { shared: shared.clone(), id });
        let Probe { kind, read_only, first, size } = probe;
        let state = NodeState { node: Arc::downgrade(&node), ino, kind, read_only, first, size, orphan: false };
        self.nodes.insert(id, state);
        self.by_ino.insert(ino, id);
        node
    }

    // --- The FAT ---------------------------------------------------------

    fn fat_entry(&mut self, c: u32) -> Result<u32, Errno> {
        let ss = self.geo.sector_size as u64;
        let sector = self.geo.fat_start + (c as u64 * 4 / ss) as u32;
        let at = (c as u64 * 4 % ss) as usize;
        if self.fat_cache.as_ref().is_none_or(|(s, _)| *s != sector) {
            let mut buf = self.sector_buf();
            self.read_sector(sector, &mut buf)?;
            self.fat_cache = Some((sector, buf));
        }
        let (_, buf) = self.fat_cache.as_ref().unwrap();
        Ok(u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) & FAT_MASK)
    }

    /// Sets cluster `c`'s FAT entry in every copy of the FAT.
    fn set_fat_entry(&mut self, c: u32, value: u32) -> Result<(), Errno> {
        self.fat_entry(c)?; // loads the sector into the cache
        let at = (c as u64 * 4 % self.geo.sector_size as u64) as usize;
        let (sector, mut buf) = self.fat_cache.take().unwrap();
        let old = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap());
        // The top four bits are reserved and must be preserved.
        buf[at..at + 4].copy_from_slice(&((old & !FAT_MASK) | (value & FAT_MASK)).to_le_bytes());
        let mut result = Ok(());
        for copy in 0..self.geo.fats {
            if result.is_ok() {
                result = self.write_sector(sector + copy * self.geo.fat_sectors, &buf);
            }
        }
        self.fat_cache = Some((sector, buf));
        result
    }

    /// The cluster after `c`, or `None` at the end of the chain. A chain
    /// that points outside the volume is reported as `EIO`.
    fn next(&mut self, c: u32) -> Result<Option<u32>, Errno> {
        match self.fat_entry(c)? {
            v if v >= 0x0fff_fff8 => Ok(None),
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
            let c = 2 + ((start as u64 - 2 + i as u64) % count as u64) as u32;
            if self.fat_entry(c)? == FAT_FREE {
                found = Some(c);
                break;
            }
        }
        let c = found.ok_or(Errno::ENOSPC)?;
        let zero = self.sector_buf();
        let first = self.geo.cluster_sector(c);
        for s in 0..self.geo.sectors_per_cluster {
            self.write_sector(first + s, &zero)?;
        }
        self.set_fat_entry(c, FAT_EOC)?;
        if let Some(p) = prev {
            self.set_fat_entry(p, c)?;
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
            if next == FAT_FREE || next == FAT_BAD {
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
        let cs = self.geo.cluster_size() as u64;
        let ss = self.geo.sector_size as u64;
        let want = (buf.len() as u64).min(limit.saturating_sub(off)) as usize;
        if want == 0 {
            return Ok(0); // without walking the chain to `off`
        }
        let mut done = 0;
        let mut cluster = self.nth(first, off / cs)?;
        let mut sector = self.sector_buf();
        while done < want {
            let Some(c) = cluster else { break };
            let pos = off + done as u64;
            let in_cluster = pos % cs;
            let s = self.geo.cluster_sector(c) + (in_cluster / ss) as u32;
            let in_sector = (in_cluster % ss) as usize;
            let n = (ss as usize - in_sector).min(want - done);
            if in_sector == 0 && n == ss as usize {
                self.read_sector(s, &mut buf[done..done + n])?;
            } else {
                self.read_sector(s, &mut sector)?;
                buf[done..done + n].copy_from_slice(&sector[in_sector..in_sector + n]);
            }
            done += n;
            if (off + done as u64).is_multiple_of(cs) {
                cluster = self.next(c)?;
            }
        }
        Ok(done)
    }

    /// Writes `data` at `off` of the chain at `*first`, allocating clusters
    /// (zeroed) as needed; `*first` changes if the chain was empty.
    fn write_chain(&mut self, first: &mut u32, off: u64, data: &[u8]) -> Result<(), Errno> {
        if data.is_empty() {
            return Ok(());
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
        let mut sector = self.sector_buf();
        loop {
            let pos = off + done as u64;
            let in_cluster = pos % cs;
            let s = self.geo.cluster_sector(c) + (in_cluster / ss) as u32;
            let in_sector = (in_cluster % ss) as usize;
            let n = (ss as usize - in_sector).min(data.len() - done);
            if in_sector == 0 && n == ss as usize {
                self.write_sector(s, &data[done..done + n])?;
            } else {
                self.read_sector(s, &mut sector)?;
                sector[in_sector..in_sector + n].copy_from_slice(&data[done..done + n]);
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
        let zeros = vec![0u8; cs as usize];
        let mut pos = from;
        while pos < end {
            let n = (end - pos).min(cs - pos % cs);
            self.write_chain(first, pos, &zeros[..n as usize])?;
            pos += n;
        }
        Ok(())
    }

    /// Writes zeroes over `[from, to)` of the chain at `*first`, growing it
    /// as needed.
    fn write_zeros(&mut self, first: &mut u32, from: u64, to: u64) -> Result<(), Errno> {
        let cs = self.geo.cluster_size() as u64;
        let zeros = vec![0u8; cs as usize];
        let mut pos = from;
        while pos < to {
            let n = (to - pos).min(cs - pos % cs);
            self.write_chain(first, pos, &zeros[..n as usize])?;
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
            self.set_fat_entry(last, FAT_EOC)?;
            self.free_chain(rest)?;
        }
        Ok(())
    }

    // --- Directories -------------------------------------------------------

    /// A directory's whole contents; `EIO` if it is larger than FAT allows.
    fn dir_bytes(&mut self, first: u32) -> Result<Vec<u8>, Errno> {
        let cs = self.geo.cluster_size() as u64;
        let len = self.chain_len(first, MAX_DIR.div_ceil(cs))? * cs;
        let mut buf = vec![0u8; len as usize];
        let n = self.read_chain(first, 0, &mut buf, len)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// The disk position of byte `off` of directory `first`: the inode
    /// number of the entry there.
    fn entry_ino(&mut self, first: u32, off: usize) -> Result<u64, Errno> {
        let cs = self.geo.cluster_size() as u64;
        let c = self.nth(first, off as u64 / cs)?.ok_or(Errno::EIO)?;
        Ok(self.geo.cluster_sector(c) as u64 * self.geo.sector_size as u64 + off as u64 % cs)
    }

    /// Rewrites the first cluster and size in node `id`'s directory entry.
    fn update_entry(&mut self, id: u64) -> Result<(), Errno> {
        let Some(state) = self.nodes.get(&id) else { return Ok(()) };
        if state.ino == ROOT_INO || state.orphan {
            return Ok(());
        }
        let (ino, first, size, is_dir) = (state.ino, state.first, state.size, state.kind == FileKind::Directory);
        let ss = self.geo.sector_size as u64;
        let sector = (ino / ss) as u32;
        let at = (ino % ss) as usize;
        let mut buf = self.sector_buf();
        self.read_sector(sector, &mut buf)?;
        dir::set_first_cluster(&mut buf[at..at + ENTRY_SIZE], first);
        let size = if is_dir { 0 } else { size };
        buf[at + 28..at + 32].copy_from_slice(&size.to_le_bytes());
        self.write_sector(sector, &buf)
    }

    /// Writes the FSInfo hints and flushes the device.
    fn sync(&mut self) -> Result<(), Errno> {
        if let Some(info) = self.info {
            let mut s = self.sector_buf();
            self.read_sector(self.geo.fsinfo_sector, &mut s)?;
            info.store(&mut s);
            self.write_sector(self.geo.fsinfo_sector, &s)?;
        }
        self.dev.flush().map_err(io_error)
    }
}

impl<D: BlockDevice + Send + 'static> Node<D> {
    fn state<'v>(&self, vol: &'v mut Volume<D>) -> &'v mut NodeState<D> {
        vol.nodes.get_mut(&self.id).expect("live node without state")
    }

    /// This directory's first cluster, or `ENOTDIR`.
    fn dir_cluster(&self, vol: &mut Volume<D>) -> Result<u32, Errno> {
        let s = self.state(vol);
        if s.kind != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        Ok(s.first)
    }

    fn find(vol: &mut Volume<D>, dir: u32, name: &str) -> Result<Option<Entry>, Errno> {
        let bytes = vol.dir_bytes(dir)?;
        Ok(dir::parse(&bytes).into_iter().find(|e| name::same(&e.name, name)))
    }
}

impl<D: BlockDevice + Send + 'static> File for Node<D> {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut vol = self.shared.vol.lock();
        let s = self.state(&mut vol);
        if s.kind == FileKind::Directory {
            return Err(Errno::EISDIR);
        }
        let (first, size) = (s.first, s.size as u64);
        vol.read_chain(first, off, buf, size)
    }

    fn write(&self, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        let mut vol = self.shared.vol.lock();
        let s = self.state(&mut vol);
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
        let s = self.state(&mut vol);
        s.first = first;
        if result.is_ok() && end > size {
            s.size = end as u32;
        }
        vol.update_entry(self.id)?;
        result.map(|()| buf.len())
    }

    fn stat(&self) -> Stat {
        let mut vol = self.shared.vol.lock();
        let s = self.state(&mut vol);
        let (ino, kind, first, read_only, size) = (s.ino, s.kind, s.first, s.read_only, s.size);
        let size = match kind {
            // A directory's size is the space its chain occupies.
            FileKind::Directory => vol.chain_len(first, u64::MAX).unwrap_or(0) * vol.geo.cluster_size() as u64,
            _ => size as u64,
        };
        let mode = match (kind, read_only) {
            (FileKind::Directory, _) => 0o755,
            (_, true) => 0o444,
            _ => 0o644,
        };
        Stat {
            dev: self.shared.dev_id,
            ino,
            kind,
            mode,
            nlink: if kind == FileKind::Directory { 2 } else { 1 },
            size,
            rdev: 0,
        }
    }

    fn truncate(&self, len: u64) -> Result<(), Errno> {
        let mut vol = self.shared.vol.lock();
        let s = self.state(&mut vol);
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
        let result = if len < size {
            vol.shrink_chain(&mut first, len)
        } else {
            // FAT has no holes: growing writes the zeroes out.
            vol.write_zeros(&mut first, size, len)
        };
        let s = self.state(&mut vol);
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
        let bytes = vol.dir_bytes(first)?;
        let Some(e) = dir::parse(&bytes).into_iter().nth(index) else { return Ok(None) };
        let ino = vol.entry_ino(first, e.offset)?;
        let kind = if e.is_dir() { FileKind::Directory } else { FileKind::Regular };
        Ok(Some(DirEntry { ino, kind, name: e.name }))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        let mut vol = self.shared.vol.lock();
        let first = self.dir_cluster(&mut vol)?;
        let e = Self::find(&mut vol, first, name)?.ok_or(Errno::ENOENT)?;
        let ino = vol.entry_ino(first, e.offset)?;
        Ok(vol.node(&self.shared, ino, Probe::of(&e)))
    }

    fn create(&self, name: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
        let _ = mode; // FAT keeps no permission bits
        if !matches!(kind, FileKind::Regular | FileKind::Directory) {
            return Err(Errno::EPERM);
        }
        name::validate(name)?;
        let mut vol = self.shared.vol.lock();
        let dir_first = self.dir_cluster(&mut vol)?;
        let bytes = vol.dir_bytes(dir_first)?;
        if dir::parse(&bytes).iter().any(|e| name::same(&e.name, name)) {
            return Err(Errno::EEXIST);
        }

        // The short name, and long-name entries unless it fits 8.3 exactly.
        let (short, ntres, mut slots) = match name::exact_short(name) {
            Some((short, ntres)) if !dir::short_names(&bytes).contains(&short) => (short, ntres, Vec::new()),
            _ => {
                let short = name::generate_short(name, &dir::short_names(&bytes))?;
                (short, 0, name::lfn_entries(name, name::checksum(&short)))
            }
        };

        // Where the entries go (with the short entry last); a directory may
        // grow only so far.
        let at = dir::find_free(&bytes, slots.len() + 1);
        if (at + (slots.len() + 1) * ENTRY_SIZE) as u64 > MAX_DIR {
            return Err(Errno::ENOSPC);
        }

        // A directory gets its first cluster, with `.` and `..`, up front.
        let first = if kind == FileKind::Directory {
            let mut c = 0;
            let parent = if self.state(&mut vol).ino == ROOT_INO { 0 } else { dir_first };
            vol.write_chain(&mut c, 0, &dir::dot_entries(0, parent))?;
            // Now that the cluster is known, record it in `.`.
            let dot = dir::short_entry(b".          ", 0, attr::DIRECTORY, c, 0);
            vol.write_chain(&mut c, 0, &dot)?;
            c
        } else {
            0
        };
        let attr_bits = if kind == FileKind::Directory { attr::DIRECTORY } else { attr::ARCHIVE };
        slots.push(dir::short_entry(&short, ntres, attr_bits, first, 0));
        let flat: Vec<u8> = slots.iter().flatten().copied().collect();
        let mut dir_first_mut = dir_first;
        if let Err(e) = vol.write_chain(&mut dir_first_mut, at as u64, &flat) {
            let _ = vol.free_chain(first);
            return Err(e);
        }
        let ino = vol.entry_ino(dir_first, at + flat.len() - ENTRY_SIZE)?;
        let probe = Probe { kind, read_only: false, first, size: 0 };
        Ok(vol.node(&self.shared, ino, probe))
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
            if !dir::parse(&contents).is_empty() {
                return Err(Errno::ENOTEMPTY);
            }
        }
        // Mark every slot (long-name parts and the short entry) free.
        let mut freed = vec![0u8; e.slots() * ENTRY_SIZE];
        let mut current = vec![0u8; freed.len()];
        vol.read_chain(dir_first, e.start as u64, &mut current, u64::MAX)?;
        for (slot, old) in freed.as_chunks_mut::<ENTRY_SIZE>().0.iter_mut().zip(current.as_chunks::<ENTRY_SIZE>().0) {
            slot.copy_from_slice(old);
            slot[0] = dir::FREE;
        }
        let mut d = dir_first;
        vol.write_chain(&mut d, e.start as u64, &freed)?;

        // An open node keeps its clusters until its last reference drops.
        let ino = vol.entry_ino(dir_first, e.offset)?;
        match vol.by_ino.remove(&ino) {
            Some(id) if vol.nodes[&id].node.strong_count() > 0 => {
                vol.nodes.get_mut(&id).unwrap().orphan = true;
                Ok(())
            }
            other => {
                if let Some(id) = other {
                    vol.nodes.remove(&id);
                }
                vol.free_chain(e.first)
            }
        }
    }
}

impl<D: BlockDevice + Send + 'static> Drop for Node<D> {
    fn drop(&mut self) {
        let mut vol = self.shared.vol.lock();
        let ours = vol.nodes.get(&self.id).is_some_and(|s| core::ptr::eq(s.node.as_ptr(), self));
        if !ours {
            return; // another node took over this state (see `Volume::node`)
        }
        let state = vol.nodes.remove(&self.id).unwrap();
        if vol.by_ino.get(&state.ino) == Some(&self.id) {
            vol.by_ino.remove(&state.ino);
        }
        if state.orphan {
            let _ = vol.free_chain(state.first);
        }
    }
}
