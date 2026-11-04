//! A btrfs file system on any [`BlockDevice`], read and write, for the
//! `osmium-fs` VFS.
//!
//! [`BtrfsFs::mount`] reads the superblock and the chunk tree and hands out
//! the default subvolume's root directory as an [`osmium_fs::File`] with
//! [`BtrfsFs::root`], ready for `Vfs::mount`; [`BtrfsFs::mount_with`] picks
//! another subvolume by id, or mounts read-only. Other subvolumes and
//! snapshots show up as directories, as on Linux.
//!
//! Reading: every tree block and data sector is checked against its checksum
//! (CRC32C or xxHash64) unless the file has `nodatasum`, and a block or
//! sector that fails is read from its other copy if there is one (`DUP`,
//! `RAID1`, `RAID1C3`, `RAID1C4`). Extents may be inline, regular,
//! preallocated or holes (implicit with `no-holes`), and compressed with
//! zlib, LZO or zstd. Extended attributes, symbolic links and device nodes
//! are read too.
//!
//! Writing: each change (a write, a truncation, a new or removed name, an
//! extended attribute, an owner or mode) is a transaction of its own,
//! committed before the call returns. [`MountOptions::commit_batch`] and
//! [`BtrfsFs::batch`] defer the superblock write over several changes, so
//! that they become durable together (all of them, or none after a crash);
//! the space the last durable state uses is not reused until then.
//!
//! Tree blocks are copied on write; the extent tree (with its
//! reference counts), data checksums, block group usage, the free space tree
//! and root items are kept up to date, and the superblock is written last,
//! after a flush, so that a crash leaves the volume as it was before the call
//! or after it. File data goes to new extents (never compressed, never
//! inline except for symbolic links), with checksums unless the file has
//! `nodatasum`; new data and metadata chunks are added when the block groups
//! fill up. Unlinked files that are still open are kept as orphans and
//! deleted when their last node goes, or at the next mount.
//!
//! A volume is mounted read-only (see [`BtrfsFs::is_read_only`]) if it spans
//! several devices, has quotas, an fsync log to replay, mixed or zoned block
//! groups, no skinny metadata, a free space tree Linux marked invalid, or
//! read-only compatible features this driver does not know. Writing in a
//! subvolume that shares blocks with a snapshot fails with `EOPNOTSUPP`, as
//! does dropping a data extent another subvolume shares; read-only
//! subvolumes are `EROFS`.
//!
//! Readers see the last commit: each call takes the current state, and the
//! space a commit frees is not reused until no reader can still be reading it.
//!
//! Owners: `Stat` reports each node's user and group id, new nodes take the
//! owner of [`File::mknod_as`] (or none: root's), and `chown` and `chmod`
//! change them. Nothing is checked: the caller decides who may.
//!
//! Access times are not updated by reads unless [`MountOptions::atime`] says
//! so (`relatime` or every read). A tree-block cache (by default
//! [`DEFAULT_TREE_CACHE_BLOCKS`] blocks) and an optional data cache
//! ([`MountOptions::data_cache_bytes`]) save repeat reads.
//!
//! Inode numbers: the mounted subvolume's are btrfs's own; another
//! subvolume's are mixed with its id so they do not collide with them (Linux
//! gives each subvolume its own `st_dev` instead).
//!
//! Not supported: file systems over several devices (only the copies on the
//! device given are read, and striped chunks, RAID0, RAID10, RAID5 and RAID6,
//! fail with `EIO`); SHA-256 and BLAKE2b checksums; `extent-tree-v2` and the
//! RAID stripe tree; replaying the fsync log; creating subvolumes or
//! snapshots; and encrypted or verity files.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod cache;
mod commit;
mod csum;
mod disk;
mod lzo;
mod node;
mod ops;
mod space;
mod tree;
mod write;
mod xxhash;
mod zlib;
mod zstd;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_fs::dev::makedev;
use osmium_fs::{Clock, ClockSlot, DirEntry, Errno, File, FileKind, PATH_MAX, Stat, Timestamp, XattrSet};
use osmium_hal::block::BlockDevice;
use osmium_sync::SpinLock;
use osmium_sync::fallible::{try_arc, try_push, try_to_vec, try_zeroed};

use cache::Cache;
use disk::{DirItems, ExtentData, FileExtent, Inode, Key, Root, Super, compress, item};
use ops::NewInode;
use tree::{Block, ChunkMap, Cursor};
use write::{Tx, Writer};

/// Largest single device transfer, so drivers see bounded requests.
const MAX_RUN: usize = 64 * 1024;

/// Largest compressed extent, before and after decompression
/// (`BTRFS_MAX_COMPRESSED`).
const MAX_COMPRESSED: u64 = 128 * 1024;

/// Superblock flags this driver writes under: `WRITTEN` only.
const SUPER_FLAGS_OK: u64 = 1;

/// Read-only compatible features this driver keeps: the free space tree (and
/// its valid bit) and the block group tree.
const COMPAT_RO_OK: u64 = 1 << 0 | 1 << 1 | 1 << 3;

/// Why a decompressor stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// The data is not valid, or decompresses to more than it should.
    Corrupt,
    /// No memory for the decoder's tables.
    OutOfMemory,
}

impl From<DecodeError> for Errno {
    fn from(e: DecodeError) -> Self {
        match e {
            DecodeError::Corrupt => Errno::EIO,
            DecodeError::OutOfMemory => Errno::ENOMEM,
        }
    }
}

/// When reading updates a node's access time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Atime {
    /// Never (`noatime`). Reading writes nothing. This is the default, unlike
    /// Linux's, so that a volume mounted as before behaves as before.
    #[default]
    NoAtime,
    /// As `relatime`: when the access time is not after the modification or
    /// change time, or is a day or more old.
    Relatime,
    /// On every read (`strictatime`).
    StrictAtime,
}

impl Atime {
    /// Whether a node with these times is due an update at `now`.
    pub(crate) fn due(self, atime: Timestamp, mtime: Timestamp, ctime: Timestamp, now: Timestamp) -> bool {
        match self {
            Atime::NoAtime => false,
            Atime::StrictAtime => atime != now,
            Atime::Relatime => atime <= mtime || atime <= ctime || now.sec.saturating_sub(atime.sec) >= 24 * 60 * 60,
        }
    }
}

/// Tree blocks cached unless [`MountOptions::tree_cache_blocks`] says otherwise.
pub const DEFAULT_TREE_CACHE_BLOCKS: usize = 128;

/// How to mount.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MountOptions<'path> {
    /// The subvolume to mount (5 is the top level); the default subvolume if
    /// `None`. Not with [`subvol_path`](MountOptions::subvol_path).
    pub subvol: Option<u64>,
    /// The subvolume to mount by its path from the top level, such as
    /// `"/data/home"` (`subvol=` on Linux); `ENOENT` if there is none, and
    /// `EINVAL` if the path names an ordinary directory, or `subvol` is also
    /// set.
    pub subvol_path: Option<&'path str>,
    /// Never write, even if the volume could be written.
    pub read_only: bool,
    /// When reads update access times; never by default. Ignored on a volume
    /// that is read-only.
    pub atime: Atime,
    /// Tree blocks to keep in memory; [`DEFAULT_TREE_CACHE_BLOCKS`] if 0.
    pub tree_cache_blocks: usize,
    /// Bytes of file data to keep in memory, after checking, for reads; none
    /// if 0 (the default). Rounded down to whole sectors.
    pub data_cache_bytes: usize,
    /// Changes to commit together: a change is written out at once, but the
    /// superblock that makes it durable only on every `commit_batch`th, or at
    /// [`BtrfsFs::sync`], [`File::sync`], [`BtrfsFs::batch`]'s end or when the
    /// volume is dropped, whichever comes first. A crash in between loses
    /// the changes since the last of those, all of them, never some. 0 and 1
    /// make every change durable before its call returns (the default).
    pub commit_batch: u32,
}

/// A node's last decompressed extent: its address, the generation of the
/// state it was read in, and its data.
type ExtentCache = SpinLock<Option<(u64, u64, Arc<Vec<u8>>)>>;

/// A committed state of the volume: what readers read.
pub(crate) struct State {
    generation: u64,
    root_tree: (u64, u8),
    chunk_root: (u64, u8),
    csum_tree: Option<(u64, u8)>,
    chunks: Arc<ChunkMap>,
    /// Ranges the commit after this state freed: reusable once no reader
    /// holds this state.
    pinned: SpinLock<Vec<(u64, u64)>>,
    /// Where `pinned` goes then.
    release: Arc<SpinLock<Vec<(u64, u64)>>>,
    /// The state that replaced this one. Each state keeps the newer ones
    /// alive, so that what a newer commit frees, and an older reader may still
    /// reach, is released only once every older state is gone.
    next: SpinLock<Option<Arc<State>>>,
}

impl Drop for State {
    fn drop(&mut self) {
        let pinned = core::mem::take(&mut *self.pinned.lock());
        if !pinned.is_empty() {
            let mut q = self.release.lock();
            // Without memory the ranges stay in limbo until the next mount.
            if q.try_reserve(pinned.len()).is_ok() {
                q.extend(pinned);
            }
        }
        // Drop the newer states this one alone kept, in a loop rather than
        // by recursion: a long-lived reader can hold a long chain.
        let mut next = self.next.lock().take();
        while let Some(n) = next {
            match Arc::try_unwrap(n) {
                Ok(st) => next = st.next.lock().take(),
                Err(_) => break,
            }
        }
    }
}

impl<D: BlockDevice + Send + 'static> Drop for Shared<D> {
    fn drop(&mut self) {
        // Commits still deferred go out with the volume.
        let _ = self.sync();
    }
}

struct Shared<D: BlockDevice + Send + 'static> {
    dev: SpinLock<D>,
    block_size: usize,
    dev_id: u64,
    /// This device's id within the file system.
    devid: u64,
    nodesize: usize,
    sectorsize: u64,
    csum_type: u16,
    /// Bytes of each data checksum.
    csum_size: usize,
    /// The UUID every tree block carries.
    meta_uuid: [u8; 16],
    fsid: [u8; 16],
    label: String,
    /// Recently read tree blocks by address.
    cache: SpinLock<Cache<Block>>,
    /// Checked data sectors by logical address, and whether each was checked
    /// against a checksum.
    data_cache: SpinLock<Cache<(bool, Arc<Vec<u8>>)>>,
    atime: Atime,
    /// The mounted subvolume.
    top: u64,
    /// The last commit.
    state: SpinLock<Arc<State>>,
    /// The write side; `None` when mounted read-only.
    writer: Option<SpinLock<Writer>>,
    clock: ClockSlot,
    /// Nodes in use, by tree and inode, with their counts.
    open: SpinLock<Vec<(u64, u64, usize)>>,
}

/// A mounted btrfs volume.
pub struct BtrfsFs<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
    /// The root directory's node, made at mount so that handing it out cannot fail.
    root: Arc<dyn File>,
}

/// One file or directory of a [`BtrfsFs`].
pub struct Node<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
    /// The subvolume holding it.
    tree: u64,
    objectid: u64,
    kind: FileKind,
    /// The inode as last read.
    inode: SpinLock<Inode>,
    /// The last compressed extent read: its address, the state it was read
    /// in, and its data.
    extent: ExtentCache,
    /// Where the last `readdir` stopped: the state, the next index asked
    /// for, and the `DIR_INDEX` key offset to resume at.
    dir_hint: SpinLock<(u64, usize, u64)>,
    /// Whether the node is counted in `Shared::open`.
    counted: bool,
}

pub(crate) fn kind_of(mode: u32) -> Option<FileKind> {
    Some(match mode & 0o170000 {
        0o010000 => FileKind::Fifo,
        0o020000 => FileKind::CharDevice,
        0o040000 => FileKind::Directory,
        0o060000 => FileKind::BlockDevice,
        0o100000 => FileKind::Regular,
        0o120000 => FileKind::Symlink,
        0o140000 => FileKind::Socket,
        _ => return None,
    })
}

/// The kind a directory entry's `BTRFS_FT_*` type names.
fn kind_of_ft(ft: u8) -> FileKind {
    match ft {
        2 => FileKind::Directory,
        3 => FileKind::CharDevice,
        4 => FileKind::BlockDevice,
        5 => FileKind::Fifo,
        6 => FileKind::Socket,
        7 => FileKind::Symlink,
        _ => FileKind::Regular,
    }
}

/// Whether a name on disk can be a path component here.
fn usable(name: &[u8]) -> Option<&str> {
    let s = core::str::from_utf8(name).ok()?;
    (!s.is_empty() && s != "." && s != ".." && !s.contains(['/', '\0'])).then_some(s)
}

/// Why a volume cannot be written, if it cannot.
fn read_only_reason(sb: &[u8], st: &State, quota: bool, block_size: usize, sectorsize: u64) -> Result<bool, Errno> {
    let flags = disk::le64(sb, 56)?;
    let compat_ro = disk::le64(sb, 180)?;
    let incompat = disk::le64(sb, 188)?;
    let fst_invalid = compat_ro & 1 != 0 && compat_ro & 2 == 0;
    let unwritable_incompat = disk::incompat::MIXED_GROUPS | disk::incompat::RAID56 | disk::incompat::ZONED;
    let odd_chunks = st.chunks.iter().any(|c| c.ty & (disk::profile::STRIPED | disk::profile::MIRRORED) != 0);
    Ok(flags & !SUPER_FLAGS_OK != 0
        || compat_ro & !COMPAT_RO_OK != 0
        || fst_invalid
        || incompat & unwritable_incompat != 0
        || incompat & disk::incompat::SKINNY_METADATA == 0
        || disk::le64(sb, 96)? != 0
        || disk::le64(sb, 136)? != 1
        || quota
        || odd_chunks
        || block_size as u64 > sectorsize
        || !sectorsize.is_multiple_of(block_size as u64))
}

impl<D: BlockDevice + Send + 'static> BtrfsFs<D> {
    /// Mounts the btrfs volume on `dev` at its default subvolume, read-write
    /// if it can be written. `dev_id` becomes `Stat::dev` of every node.
    /// Fails with `EINVAL` if the device does not hold a volume this driver
    /// can read.
    pub fn mount(dev: D, dev_id: u64) -> Result<Self, Errno> {
        Self::mount_with(dev, dev_id, MountOptions::default())
    }

    /// Mounts subvolume `subvol` (5 is the top level) of the btrfs volume on
    /// `dev`; `ENOENT` if there is no such subvolume.
    pub fn mount_subvol(dev: D, dev_id: u64, subvol: u64) -> Result<Self, Errno> {
        Self::mount_with(dev, dev_id, MountOptions { subvol: Some(subvol), ..MountOptions::default() })
    }

    /// Mounts the btrfs volume on `dev` as `opts` say.
    pub fn mount_with(dev: D, dev_id: u64, opts: MountOptions<'_>) -> Result<Self, Errno> {
        let block_size = dev.block_size();
        if block_size == 0 || block_size > MAX_RUN {
            return Err(Errno::EINVAL);
        }
        let end = disk::SUPER_OFFSET + disk::SUPER_SIZE as u64;
        if (dev.num_blocks() as u128) * (block_size as u128) < end as u128 {
            return Err(Errno::EINVAL);
        }
        let release = try_arc(SpinLock::new(Vec::new()))?;
        let empty_state = |chunks: ChunkMap| -> Result<Arc<State>, Errno> {
            Ok(try_arc(State {
                generation: 0,
                root_tree: (0, 0),
                chunk_root: (0, 0),
                csum_tree: None,
                chunks: try_arc(chunks)?,
                pinned: SpinLock::new(Vec::new()),
                release: release.clone(),
                next: SpinLock::new(None),
            })?)
        };
        let mut shared = Shared {
            dev: SpinLock::new(dev),
            block_size,
            dev_id,
            devid: 0,
            nodesize: 0,
            sectorsize: 0,
            csum_type: 0,
            csum_size: 0,
            meta_uuid: [0; 16],
            fsid: [0; 16],
            label: String::new(),
            cache: SpinLock::new(Cache::new(match opts.tree_cache_blocks {
                0 => DEFAULT_TREE_CACHE_BLOCKS,
                n => n,
            })?),
            data_cache: SpinLock::new(Cache::new(0)?),
            atime: opts.atime,
            top: disk::tree::FS,
            state: SpinLock::new(empty_state(ChunkMap::default())?),
            writer: None,
            clock: ClockSlot::new(),
            open: SpinLock::new(Vec::new()),
        };

        let mut b = try_zeroed(disk::SUPER_SIZE)?;
        shared.read_phys(disk::SUPER_OFFSET, &mut b).map_err(|_| Errno::EINVAL)?;
        let sb = Super::parse(&b)?;
        let csum_size = csum::size(sb.csum_type).ok_or(Errno::EINVAL)?;
        let (stored, rest) = b.split_at_checked(disk::CSUM_SPACE).ok_or(Errno::EINVAL)?;
        if !csum::matches(sb.csum_type, rest, stored) || sb.incompat & !disk::incompat::SUPPORTED != 0 {
            return Err(Errno::EINVAL);
        }
        shared.devid = sb.devid;
        shared.nodesize = sb.nodesize as usize;
        shared.sectorsize = sb.sectorsize as u64;
        shared.csum_type = sb.csum_type;
        shared.csum_size = csum_size;
        shared.meta_uuid = sb.meta_uuid;
        shared.fsid = sb.fsid;
        shared.label = String::from_utf8(sb.label).unwrap_or_default();
        if opts.data_cache_bytes != 0 {
            let sectors = opts.data_cache_bytes / shared.sectorsize.max(1) as usize;
            shared.data_cache = SpinLock::new(Cache::new(sectors)?);
        }

        // The chunk tree maps everything else.
        let mut chunks = ChunkMap::bootstrap(&sb.sys_chunks)?;
        let mut found = Vec::new();
        {
            let mut c = Cursor::new(&shared, &chunks, sb.chunk_root);
            let mut at = c.seek(Key::new(disk::tree::FIRST_CHUNK, item::CHUNK_ITEM, 0))?;
            while let Some((k, data)) = at {
                if k.objectid != disk::tree::FIRST_CHUNK || k.ty != item::CHUNK_ITEM {
                    break;
                }
                try_push(&mut found, disk::Chunk::parse(data, k.offset)?.0)?;
                at = c.next()?;
            }
        }
        for chunk in found {
            chunks.insert(chunk)?;
        }
        let mut st = State {
            generation: disk::le64(&b, 72)?,
            root_tree: sb.root,
            chunk_root: sb.chunk_root,
            csum_tree: None,
            chunks: try_arc(chunks)?,
            pinned: SpinLock::new(Vec::new()),
            release: release.clone(),
            next: SpinLock::new(None),
        };
        st.csum_tree = shared.tree_root(&st, disk::tree::CSUM)?.map(|r| (r.bytenr, r.level));
        let top = match (opts.subvol, opts.subvol_path) {
            (Some(_), Some(_)) => return Err(Errno::EINVAL),
            (Some(id), None) => id,
            (None, Some(path)) => shared.resolve_subvol(&st, path)?,
            (None, None) => shared.default_subvol(&st)?,
        };
        shared.top = top;
        shared.fs_root(&st, top)?.ok_or(Errno::ENOENT)?;

        let quota = shared.tree_root(&st, disk::tree::QUOTA)?.is_some();
        if !opts.read_only && !read_only_reason(&b, &st, quota, block_size, shared.sectorsize)? {
            let compat_ro = disk::le64(&b, 180)?;
            let bg_tree = if compat_ro & 1 << 3 != 0 { disk::tree::BLOCK_GROUP } else { disk::tree::EXTENT };
            let first = shared.block(&st.chunks, sb.root.0)?;
            let groups = shared.load_groups(&st, bg_tree)?;
            shared.writer = Some(SpinLock::new(Writer {
                sb: b,
                chunk_uuid: disk::array(&first, 64)?,
                groups,
                limbo: Vec::new(),
                release,
                next_ino: Vec::new(),
                bg_tree,
                fst: compat_ro & 1 != 0,
                orphans: Vec::new(),
                broken: false,
                deferred: 0,
                held: Vec::new(),
                fresh: Vec::new(),
                batch_depth: 0,
                commit_batch: opts.commit_batch,
            }));
        }
        shared.state = SpinLock::new(try_arc(st)?);
        let shared = try_arc(shared)?;
        shared.delete_orphans(top);
        let root = shared.node(top, disk::tree::FIRST_FREE)?;
        if root.kind != FileKind::Directory {
            return Err(Errno::EIO);
        }
        Ok(BtrfsFs { shared, root: try_arc(root)? })
    }

    /// The root directory, to mount in a `Vfs`.
    pub fn root(&self) -> Arc<dyn File> {
        self.root.clone()
    }

    /// The label, empty if it has none (or one that is not UTF-8).
    pub fn label(&self) -> &str {
        &self.shared.label
    }

    /// The file system's UUID.
    pub fn fsid(&self) -> [u8; 16] {
        self.shared.fsid
    }

    /// The id of the subvolume mounted.
    pub fn subvol(&self) -> u64 {
        self.shared.top
    }

    /// Whether changes are refused (with `EROFS`): asked for, or the volume
    /// has something this driver does not write.
    pub fn is_read_only(&self) -> bool {
        self.shared.writer.is_none()
    }

    /// The generation of the last commit.
    pub fn generation(&self) -> u64 {
        self.shared.state().generation
    }

    /// Makes every change so far durable. Only has work to do with
    /// [`MountOptions::commit_batch`] or inside [`batch`](BtrfsFs::batch);
    /// otherwise each change was durable when its call returned.
    pub fn sync(&self) -> Result<(), Errno> {
        self.shared.sync()
    }

    /// Runs `f`, which makes changes to this volume's files and directories
    /// (through any node of it), as one unit of durability: they are written
    /// out as they happen, but the superblock that makes them durable is
    /// written once, when the outermost `f` returns (and an earlier
    /// [`sync`](BtrfsFs::sync) or `File::sync` from anywhere makes what is
    /// done so far durable at that point). A crash before then leaves the
    /// volume as it was before `f`; a crash after leaves all of `f`'s changes.
    ///
    /// A change `f` makes that fails is not rolled back, and the others
    /// still take effect together. Space that changes free is not reused
    /// until the batch ends, so a very large batch can run out of space.
    /// Returns what `f` returns, or the error making the batch durable.
    pub fn batch<R>(&self, f: impl FnOnce() -> R) -> Result<R, Errno> {
        let Some(w) = &self.shared.writer else { return Ok(f()) };
        w.lock().batch_depth += 1;
        let r = f();
        let mut w = w.lock();
        w.batch_depth = w.batch_depth.saturating_sub(1);
        if w.batch_depth == 0 {
            self.shared.sync_locked(&mut w)?;
        }
        Ok(r)
    }

    /// Takes timestamps from `clock` instead of the global
    /// [`osmium_fs::clock`].
    pub fn set_clock_source(&self, clock: Arc<dyn Clock>) {
        self.shared.clock.set(clock);
    }
}

impl<D: BlockDevice + Send + 'static> Shared<D> {
    /// The last commit.
    fn state(&self) -> Arc<State> {
        self.state.lock().clone()
    }

    pub(crate) fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Makes deferred commits durable.
    fn sync(&self) -> Result<(), Errno> {
        let Some(w) = &self.writer else { return Ok(()) };
        let mut w = w.lock();
        self.sync_locked(&mut w)
    }

    /// The subvolume at `path` from the top level.
    fn resolve_subvol(&self, st: &State, path: &str) -> Result<u64, Errno> {
        let (mut tree, mut dir, mut is_subvol) = (disk::tree::FS, disk::tree::FIRST_FREE, true);
        for name in path.split('/').filter(|c| !c.is_empty()) {
            if name == "." || name == ".." {
                return Err(Errno::EINVAL);
            }
            let root = self.fs_root(st, tree)?.ok_or(Errno::ENOENT)?;
            let key = Key::new(dir, item::DIR_ITEM, csum::name_hash(name.as_bytes()));
            let found = self.lookup(&st.chunks, (root.bytenr, root.level), key, |data| {
                for e in DirItems::new(data) {
                    let e = e?;
                    if e.name == name.as_bytes() {
                        return Ok(Some(e.location));
                    }
                }
                Ok(None)
            })?;
            let location = found.flatten().ok_or(Errno::ENOENT)?;
            match location.ty {
                item::ROOT_ITEM => (tree, dir, is_subvol) = (location.objectid, disk::tree::FIRST_FREE, true),
                item::INODE_ITEM => (dir, is_subvol) = (location.objectid, false),
                _ => return Err(Errno::EIO),
            }
        }
        if is_subvol { Ok(tree) } else { Err(Errno::EINVAL) }
    }

    /// The root of tree `id`, from the root tree.
    fn tree_root(&self, st: &State, id: u64) -> Result<Option<Root>, Errno> {
        let mut c = Cursor::new(self, &st.chunks, st.root_tree);
        match c.seek(Key::new(id, item::ROOT_ITEM, 0))? {
            Some((k, data)) if k.objectid == id && k.ty == item::ROOT_ITEM => Ok(Some(Root::parse(data, id)?)),
            _ => Ok(None),
        }
    }

    /// The root of subvolume `id`; `None` if there is none.
    pub(crate) fn fs_root(&self, st: &State, id: u64) -> Result<Option<Root>, Errno> {
        if id != disk::tree::FS && !(disk::tree::FIRST_FREE..=disk::tree::LAST_FREE).contains(&id) {
            return Ok(None);
        }
        let root = self.tree_root(st, id)?;
        if root.is_some_and(|r| r.dirid != disk::tree::FIRST_FREE) {
            return Err(Errno::EIO);
        }
        Ok(root)
    }

    /// The subvolume `btrfs subvolume set-default` chose, else the top level.
    fn default_subvol(&self, st: &State) -> Result<u64, Errno> {
        let key = Key::new(disk::tree::ROOT_DIR, item::DIR_ITEM, csum::name_hash(b"default"));
        let found = self.lookup(&st.chunks, st.root_tree, key, |data| {
            for e in DirItems::new(data) {
                let e = e?;
                if e.name == b"default" {
                    return Ok(Some(e.location.objectid));
                }
            }
            Ok(None)
        })?;
        Ok(found.flatten().unwrap_or(disk::tree::FS))
    }

    /// Inode `ino` of the tree rooted at `root`; `ENOENT` if it is gone.
    pub(crate) fn read_inode(&self, st: &State, root: (u64, u8), ino: u64) -> Result<Inode, Errno> {
        let key = Key::new(ino, item::INODE_ITEM, 0);
        self.lookup(&st.chunks, root, key, Inode::parse)?.ok_or(Errno::ENOENT)
    }

    /// The node for inode `objectid` of subvolume `tree`, as of the last
    /// commit. It is counted as open before the inode is read, so that an
    /// unlink racing with it either sees it open or deletes the inode first
    /// (and this fails with `ENOENT`).
    fn node(self: &Arc<Self>, tree: u64, objectid: u64) -> Result<Node<D>, Errno> {
        let counted = self.writer.is_some();
        if counted {
            let mut open = self.open.lock();
            match open.iter_mut().find(|e| (e.0, e.1) == (tree, objectid)) {
                Some(e) => e.2 += 1,
                None => try_push(&mut open, (tree, objectid, 1))?,
            }
        }
        let read = || -> Result<Inode, Errno> {
            let st = self.state();
            let root = self.fs_root(&st, tree)?.ok_or(Errno::ENOENT)?;
            self.read_inode(&st, (root.bytenr, root.level), objectid)
        };
        let inode = match read().and_then(|i| kind_of(i.mode).map(|k| (i, k)).ok_or(Errno::EIO)) {
            Ok(v) => v,
            Err(e) => {
                if counted {
                    self.unregister(tree, objectid);
                }
                return Err(e);
            }
        };
        Ok(Node {
            shared: self.clone(),
            tree,
            objectid,
            kind: inode.1,
            inode: SpinLock::new(inode.0),
            extent: SpinLock::new(None),
            dir_hint: SpinLock::new((0, 0, 0)),
            counted,
        })
    }

    /// Takes one off the open count of `(tree, ino)`; whether it was the last.
    fn unregister(&self, tree: u64, ino: u64) -> bool {
        let mut open = self.open.lock();
        let Some(i) = open.iter().position(|e| (e.0, e.1) == (tree, ino)) else { return false };
        let left = open.get_mut(i).map_or(0, |e| {
            e.2 = e.2.saturating_sub(1);
            e.2
        });
        if left == 0 {
            open.swap_remove(i);
        }
        left == 0
    }

    /// Whether a node of inode `ino` of tree `tree` is in use.
    fn is_open(&self, tree: u64, ino: u64) -> bool {
        self.open.lock().iter().any(|e| (e.0, e.1) == (tree, ino) && e.2 > 0)
    }

    /// The inode number shown for `objectid` of subvolume `tree`.
    fn ino(&self, tree: u64, objectid: u64) -> u64 {
        if tree == self.top { objectid } else { objectid ^ tree.rotate_right(16) }
    }

    /// Runs `f` in a transaction and commits it; `EROFS` if read-only.
    fn transact<R>(&self, f: impl FnOnce(&mut Tx<'_, D>) -> Result<R, Errno>) -> Result<R, Errno> {
        let w = self.writer.as_ref().ok_or(Errno::EROFS)?;
        let mut w = w.lock();
        self.transact_locked(&mut w, f)
    }

    fn transact_locked<R>(
        &self,
        w: &mut Writer,
        f: impl FnOnce(&mut Tx<'_, D>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        if w.broken {
            return Err(Errno::EIO);
        }
        w.reclaim();
        // Defer the superblock inside a batch, and until `commit_batch`
        // commits have gone by otherwise.
        let defer = w.batch_depth > 0 || (w.commit_batch > 1 && w.deferred.saturating_add(1) < w.commit_batch);
        let (added, removed, r) = {
            let mut tx = Tx::new(self, w, self.state());
            tx.defer = defer;
            let r = f(&mut tx)?;
            let added = core::mem::take(&mut tx.orphans_added);
            let removed = core::mem::take(&mut tx.orphans_removed);
            tx.commit()?;
            (added, removed, r)
        };
        // Bookkeeping after the commit; an orphan that cannot be recorded is
        // deleted at the next mount instead.
        w.orphans.retain(|o| !removed.contains(o));
        if w.orphans.try_reserve(added.len()).is_ok() {
            w.orphans.extend(added);
        }
        Ok(r)
    }

    /// Deletes the orphans a previous mount left in subvolume `tree`.
    fn delete_orphans(&self, tree: u64) {
        let Some(w) = &self.writer else { return };
        let mut w = w.lock();
        let _ = self.transact_locked(&mut w, |tx| {
            let mut at = Key::new(disk::tree::ORPHAN, item::ORPHAN_ITEM, 0);
            while let Some((k, _)) = tx.next_item(tree, at)? {
                if k.objectid != disk::tree::ORPHAN || k.ty != item::ORPHAN_ITEM {
                    break;
                }
                // Linux leaves orphan items for truncations too: only an
                // inode without links goes.
                if let Some(d) = tx.find(tree, Key::new(k.offset, item::INODE_ITEM, 0))?
                    && disk::le32(&d, 40)? == 0
                {
                    tx.delete_inode(tree, k.offset)?;
                }
                if tx.find(tree, k)?.is_some() {
                    tx.delete(tree, k)?;
                }
                at = write::succ(k).ok_or(Errno::EIO)?;
            }
            Ok(())
        });
    }

    /// The data checksums of `n` sectors from logical `at`; `EIO` if any is
    /// missing.
    fn csums(&self, st: &State, at: u64, n: usize) -> Result<Vec<u8>, Errno> {
        let (cs, ss) = (self.csum_size, self.sectorsize);
        let mut out = try_zeroed(n.checked_mul(cs).ok_or(Errno::EIO)?)?;
        let mut c = Cursor::new(self, &st.chunks, st.csum_tree.ok_or(Errno::EIO)?);
        let ours = |k: &Key| k.objectid == disk::tree::EXTENT_CSUM && k.ty == item::EXTENT_CSUM;
        let key = Key::new(disk::tree::EXTENT_CSUM, item::EXTENT_CSUM, at);
        let mut cur = c.seek_back(key)?;
        if !cur.is_some_and(|(k, _)| ours(&k)) {
            cur = c.seek(key)?;
        }
        let mut have = 0;
        while have < n {
            let Some((k, data)) = cur else { break };
            let want = at.checked_add(have as u64 * ss).ok_or(Errno::EIO)?;
            if !ours(&k) || k.offset > want {
                break;
            }
            let count = (data.len() / cs) as u64;
            let skip = want - k.offset;
            if skip % ss != 0 {
                return Err(Errno::EIO);
            }
            if skip / ss < count {
                let first = (skip / ss) as usize;
                let take = (count as usize - first).min(n - have);
                let src = data.get(first * cs..(first + take) * cs).ok_or(Errno::EIO)?;
                out.get_mut(have * cs..(have + take) * cs).ok_or(Errno::EIO)?.copy_from_slice(src);
                have += take;
            }
            cur = c.next()?;
        }
        if have < n {
            return Err(Errno::EIO);
        }
        Ok(out)
    }

    /// Reads whole data sectors at logical `at` into `buf`, checking them
    /// against the checksum tree if `verify`.
    fn read_sectors(&self, st: &State, at: u64, buf: &mut [u8], verify: bool) -> Result<(), Errno> {
        if !verify {
            return self.read_logical(&st.chunks, at, buf, &mut |_| true);
        }
        let ss = self.sectorsize as usize;
        let sums = self.csums(st, at, buf.len() / ss)?;
        let (ty, cs) = (self.csum_type, self.csum_size);
        self.read_logical(&st.chunks, at, buf, &mut |b| {
            b.chunks(ss).zip(sums.chunks(cs)).all(|(sector, sum)| csum::matches(ty, sector, sum))
        })
    }

    /// Fills `buf` (whole sectors at logical `at`) from the data cache; false,
    /// with `buf` unspecified, unless every sector is there.
    fn read_cached(&self, at: u64, buf: &mut [u8], verify: bool) -> bool {
        let ss = self.sectorsize;
        let cache = self.data_cache.lock();
        if cache.capacity() == 0 {
            return false;
        }
        for (i, sector) in buf.chunks_mut(ss as usize).enumerate() {
            let Some(addr) = at.checked_add(i as u64 * ss) else { return false };
            match cache.get(addr) {
                Some((checked, data)) if (checked || !verify) && data.len() == sector.len() => {
                    sector.copy_from_slice(&data);
                }
                _ => return false,
            }
        }
        true
    }

    /// Keeps the sectors just read at logical `at` in the data cache.
    fn keep_cached(&self, at: u64, buf: &[u8], verified: bool) {
        let ss = self.sectorsize;
        if self.data_cache.lock().capacity() == 0 {
            return;
        }
        for (i, sector) in buf.chunks(ss as usize).enumerate() {
            let Some(addr) = at.checked_add(i as u64 * ss) else { return };
            // Allocated before taking the lock.
            let Some(copy) = try_to_vec(sector).ok().and_then(|v| try_arc(v).ok()) else { return };
            self.data_cache.lock().insert(addr, (verified, copy));
        }
    }

    /// Reads `out.len()` bytes of data at logical `at`, a whole sector at a
    /// time.
    fn read_data(&self, st: &State, mut at: u64, mut out: &mut [u8], verify: bool) -> Result<(), Errno> {
        let ss = self.sectorsize;
        while !out.is_empty() {
            let start = at & !(ss - 1);
            let skip = (at - start) as usize;
            let span = (skip + out.len()).min(MAX_RUN);
            let n = span - skip;
            let mut tmp = try_zeroed(span.next_multiple_of(ss as usize))?;
            if !self.read_cached(start, &mut tmp, verify) {
                self.read_sectors(st, start, &mut tmp, verify)?;
                self.keep_cached(start, &tmp, verify);
            }
            out.get_mut(..n).ok_or(Errno::EIO)?.copy_from_slice(tmp.get(skip..span).ok_or(Errno::EIO)?);
            at = at.checked_add(n as u64).ok_or(Errno::EIO)?;
            out = out.get_mut(n..).ok_or(Errno::EIO)?;
        }
        Ok(())
    }

    /// Reads bytes `skip..skip + out.len()` of the file range extent `fe` covers.
    fn read_extent(
        &self,
        st: &State,
        fe: &FileExtent<'_>,
        skip: u64,
        out: &mut [u8],
        verify: bool,
        cache: Option<&ExtentCache>,
    ) -> Result<(), Errno> {
        match fe.data {
            ExtentData::Prealloc { .. } | ExtentData::Regular { disk_bytenr: 0, .. } => out.fill(0),
            ExtentData::Inline(data) if fe.compression == compress::NONE => copy_from(data, skip, out),
            ExtentData::Inline(data) => {
                let plain = decompress(fe.compression, data, fe.ram_bytes, self.sectorsize as usize)?;
                copy_from(&plain, skip, out);
            }
            ExtentData::Regular { disk_bytenr, offset, .. } if fe.compression == compress::NONE => {
                let at = disk_bytenr.checked_add(offset).and_then(|a| a.checked_add(skip)).ok_or(Errno::EIO)?;
                self.read_data(st, at, out, verify)?;
            }
            ExtentData::Regular { disk_bytenr, disk_num_bytes, offset, .. } => {
                let cached = cache.and_then(|c| {
                    c.lock().as_ref().filter(|e| (e.0, e.1) == (disk_bytenr, st.generation)).map(|e| e.2.clone())
                });
                let plain = match cached {
                    Some(plain) => plain,
                    None => {
                        let ss = self.sectorsize;
                        if disk_num_bytes > MAX_COMPRESSED
                            || !disk_num_bytes.is_multiple_of(ss)
                            || !disk_bytenr.is_multiple_of(ss)
                        {
                            return Err(Errno::EIO);
                        }
                        let mut raw = try_zeroed(disk_num_bytes as usize)?;
                        self.read_sectors(st, disk_bytenr, &mut raw, verify)?;
                        let plain = try_arc(decompress(fe.compression, &raw, fe.ram_bytes, ss as usize)?)?;
                        if let Some(c) = cache {
                            *c.lock() = Some((disk_bytenr, st.generation, plain.clone()));
                        }
                        plain
                    }
                };
                copy_from(&plain, offset.checked_add(skip).ok_or(Errno::EIO)?, out);
            }
        }
        Ok(())
    }

    /// Reads bytes of file `ino` (of the tree rooted at `root`) at `off`;
    /// returns how many, 0 at its end.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn read_file(
        &self,
        st: &State,
        root: (u64, u8),
        ino: u64,
        inode: &Inode,
        off: u64,
        buf: &mut [u8],
        cache: Option<&ExtentCache>,
    ) -> Result<usize, Errno> {
        let size = inode.size;
        if off >= size {
            return Ok(0);
        }
        let verify = inode.flags & disk::INODE_NODATASUM == 0;
        let want = buf.len().min((size - off).min(usize::MAX as u64) as usize);
        let buf = buf.get_mut(..want).ok_or(Errno::EIO)?;
        let ours = |k: &Key| k.objectid == ino && k.ty == item::EXTENT_DATA;
        let key = Key::new(ino, item::EXTENT_DATA, off);
        let mut c = Cursor::new(self, &st.chunks, root);
        // The extent at or before `off` may cover it; else the first after.
        let mut cur = c.seek_back(key)?;
        if !cur.is_some_and(|(k, _)| ours(&k)) {
            cur = c.seek(key)?;
        }
        let mut done = 0;
        while done < want {
            let Some((k, data)) = cur else { break };
            if !ours(&k) {
                break;
            }
            let pos = off + done as u64;
            let left = (want - done) as u64;
            if k.offset > pos {
                // A hole before this extent.
                let n = (k.offset - pos).min(left) as usize;
                buf.get_mut(done..done + n).ok_or(Errno::EIO)?.fill(0);
                done += n;
                continue;
            }
            let fe = FileExtent::parse(data)?;
            let end = k.offset.saturating_add(fe.len());
            if pos < end {
                let n = (end - pos).min(left) as usize;
                let out = buf.get_mut(done..done + n).ok_or(Errno::EIO)?;
                self.read_extent(st, &fe, pos - k.offset, out, verify, cache)?;
                done += n;
            }
            cur = c.next()?;
        }
        // A hole up to the end of the file.
        buf.get_mut(done..).ok_or(Errno::EIO)?.fill(0);
        Ok(want)
    }
}

/// Decompresses `src` with `algorithm` into a buffer of `ram_bytes`; what the
/// data does not fill is zeroes.
fn decompress(algorithm: u8, src: &[u8], ram_bytes: u64, sectorsize: usize) -> Result<Vec<u8>, Errno> {
    if ram_bytes > MAX_COMPRESSED {
        return Err(Errno::EIO);
    }
    let mut out = try_zeroed(ram_bytes as usize)?;
    match algorithm {
        compress::ZLIB => zlib::decompress(src, &mut out)?,
        compress::LZO => lzo::decompress(src, &mut out, sectorsize)?,
        compress::ZSTD => zstd::decompress(src, &mut out)?,
        _ => return Err(Errno::EIO),
    };
    Ok(out)
}

/// Copies `src` from `from` into `out`, zero-filling what `src` lacks.
fn copy_from(src: &[u8], from: u64, out: &mut [u8]) {
    let src = usize::try_from(from).ok().and_then(|f| src.get(f..)).unwrap_or(&[]);
    let n = src.len().min(out.len());
    let (head, tail) = out.split_at_mut(n);
    head.copy_from_slice(src.get(..n).unwrap_or(&[]));
    tail.fill(0);
}

impl<D: BlockDevice + Send + 'static> Node<D> {
    /// The subvolume's root in state `st`.
    fn root(&self, st: &State) -> Result<(u64, u8), Errno> {
        let r = self.shared.fs_root(st, self.tree)?.ok_or(Errno::ENOENT)?;
        Ok((r.bytenr, r.level))
    }

    /// The inode as of state `st`, also kept for `stat`.
    fn fresh_inode(&self, st: &State) -> Result<Inode, Errno> {
        let i = self.shared.read_inode(st, self.root(st)?, self.objectid)?;
        *self.inode.lock() = i;
        Ok(i)
    }

    /// The node a directory entry's location names.
    fn open(&self, location: Key) -> Result<Node<D>, Errno> {
        match location.ty {
            item::INODE_ITEM => self.shared.node(self.tree, location.objectid),
            item::ROOT_ITEM => self.shared.node(location.objectid, disk::tree::FIRST_FREE),
            _ => Err(Errno::EIO),
        }
    }

    /// The inode number a directory entry's location gives its node.
    fn entry_ino(&self, location: Key) -> u64 {
        match location.ty {
            item::ROOT_ITEM => self.shared.ino(location.objectid, disk::tree::FIRST_FREE),
            _ => self.shared.ino(self.tree, location.objectid),
        }
    }

    /// The value of the `XATTR_ITEM` entry `name`, given to `f`.
    fn xattr<R>(&self, name: &[u8], f: impl FnOnce(&[u8]) -> Result<R, Errno>) -> Result<Option<R>, Errno> {
        let st = self.shared.state();
        let key = Key::new(self.objectid, item::XATTR_ITEM, csum::name_hash(name));
        let found = self.shared.lookup(&st.chunks, self.root(&st)?, key, |data| {
            for e in DirItems::new(data) {
                let e = e?;
                if e.name == name {
                    return f(e.data).map(Some);
                }
            }
            Ok(None)
        })?;
        Ok(found.flatten())
    }

    /// Updates the access time as the mount's policy says, once a read is
    /// done with `inode`. A failure leaves it as it was: the read stands.
    fn touch_atime(&self, inode: &Inode) {
        let sh = &self.shared;
        if sh.atime == Atime::NoAtime
            || sh.writer.is_none()
            || !sh.atime.due(inode.atime, inode.mtime, inode.ctime, sh.now())
        {
            return;
        }
        let (tree, ino, policy) = (self.tree, self.objectid, sh.atime);
        if sh.transact(|tx| tx.touch_atime(tree, ino, policy)).is_ok() {
            self.inode.lock().atime = sh.now();
        }
    }

    /// [`touch_atime`](Node::touch_atime) for a listing, which has not read
    /// the inode: the copy kept says whether to look at it afresh.
    fn touch_atime_cached(&self) {
        let sh = &self.shared;
        let cached = *self.inode.lock();
        if sh.atime == Atime::NoAtime
            || sh.writer.is_none()
            || !sh.atime.due(cached.atime, cached.mtime, cached.ctime, sh.now())
        {
            return;
        }
        let st = sh.state();
        if let Ok(fresh) = self.fresh_inode(&st) {
            drop(st);
            self.touch_atime(&fresh);
        }
    }

    fn dir(&self) -> Result<(), Errno> {
        if self.kind == FileKind::Directory { Ok(()) } else { Err(Errno::ENOTDIR) }
    }

    /// Another node, if it is a directory of this same mount.
    fn same_fs<'o>(&self, other: &'o dyn File) -> Result<&'o Node<D>, Errno> {
        let other = other.as_any().and_then(|a| a.downcast_ref::<Node<D>>()).ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&self.shared, &other.shared) || other.tree != self.tree {
            return Err(Errno::EXDEV);
        }
        Ok(other)
    }

    /// A node for `ino`, just created in this node's subvolume.
    fn new_node(&self, ino: u64) -> Result<Arc<dyn File>, Errno> {
        Ok(try_arc(self.shared.node(self.tree, ino)?)?)
    }
}

impl<D: BlockDevice + Send + 'static> Drop for Node<D> {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let Some(w) = &self.shared.writer else { return };
        // Under the writer's lock, so that an unlink sees the count it acts on.
        let mut w = w.lock();
        let last = self.shared.unregister(self.tree, self.objectid);
        let (tree, ino) = (self.tree, self.objectid);
        if last && w.orphans.contains(&(tree, ino)) {
            let _ = self.shared.transact_locked(&mut w, |tx| {
                tx.delete_inode(tree, ino)?;
                Ok(try_push(&mut tx.orphans_removed, (tree, ino))?)
            });
        }
    }
}

impl<D: BlockDevice + Send + 'static> File for Node<D> {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        match self.kind {
            FileKind::Regular => {}
            FileKind::Directory => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
        let st = self.shared.state();
        let inode = self.fresh_inode(&st)?;
        let n = self.shared.read_file(&st, self.root(&st)?, self.objectid, &inode, off, buf, Some(&self.extent))?;
        drop(st);
        self.touch_atime(&inode);
        Ok(n)
    }

    fn write(&self, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        if self.kind == FileKind::Directory {
            return Err(Errno::EISDIR);
        }
        let (tree, ino) = (self.tree, self.objectid);
        self.shared.transact(|tx| tx.write(tree, ino, off, buf))
    }

    fn stat(&self) -> Stat {
        self.try_stat().unwrap_or_else(|_| self.stat_of(&self.inode.lock()))
    }

    fn try_stat(&self) -> Result<Stat, Errno> {
        let st = self.shared.state();
        let i = self.fresh_inode(&st)?;
        Ok(self.stat_of(&i))
    }

    fn truncate(&self, len: u64) -> Result<(), Errno> {
        let (tree, ino) = (self.tree, self.objectid);
        self.shared.transact(|tx| tx.truncate(tree, ino, len))
    }

    fn sync(&self) -> Result<(), Errno> {
        // Every change is committed before its call returns, unless the mount
        // defers superblocks; then this writes the one that covers them.
        self.shared.sync()
    }

    fn chmod(&self, mode: u32) -> Result<(), Errno> {
        let (tree, ino) = (self.tree, self.objectid);
        self.shared.transact(|tx| tx.chmod(tree, ino, mode))
    }

    fn chown(&self, uid: Option<u32>, gid: Option<u32>) -> Result<(), Errno> {
        let (tree, ino) = (self.tree, self.objectid);
        self.shared.transact(|tx| tx.chown(tree, ino, uid, gid))
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        self.dir()?;
        self.touch_atime_cached();
        let st = self.shared.state();
        // Resume where the last call stopped if it is at or before `index`.
        let (mut i, from) = match *self.dir_hint.lock() {
            (g, i, from) if g == st.generation && i <= index => (i, from),
            _ => (0, 0),
        };
        let mut c = Cursor::new(&self.shared, &st.chunks, self.root(&st)?);
        let mut cur = c.seek(Key::new(self.objectid, item::DIR_INDEX, from))?;
        while let Some((k, data)) = cur {
            if k.objectid != self.objectid || k.ty != item::DIR_INDEX {
                break;
            }
            let e = DirItems::new(data).next().ok_or(Errno::EIO)??;
            if let Some(name) = usable(e.name) {
                if i == index {
                    *self.dir_hint.lock() = (st.generation, index.saturating_add(1), k.offset.saturating_add(1));
                    let kind = match e.location.ty {
                        item::ROOT_ITEM => FileKind::Directory,
                        _ => kind_of_ft(e.ty),
                    };
                    let mut s = String::new();
                    s.try_reserve_exact(name.len()).map_err(|_| Errno::ENOMEM)?;
                    s.push_str(name);
                    return Ok(Some(DirEntry { ino: self.entry_ino(e.location), kind, name: s }));
                }
                i += 1;
            }
            cur = c.next()?;
        }
        Ok(None)
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        self.dir()?;
        let st = self.shared.state();
        let key = Key::new(self.objectid, item::DIR_ITEM, csum::name_hash(name.as_bytes()));
        let location = self.shared.lookup(&st.chunks, self.root(&st)?, key, |data| {
            for e in DirItems::new(data) {
                let e = e?;
                if e.name == name.as_bytes() {
                    return Ok(Some(e.location));
                }
            }
            Ok(None)
        })?;
        let location = location.flatten().ok_or(Errno::ENOENT)?;
        drop(st);
        Ok(try_arc(self.open(location)?)?)
    }

    fn create(&self, name: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
        self.mknod(name, kind, mode, 0)
    }

    fn mknod(&self, name: &str, kind: FileKind, mode: u32, rdev: u64) -> Result<Arc<dyn File>, Errno> {
        self.mknod_as(name, kind, mode, rdev, 0, 0)
    }

    fn mknod_as(
        &self,
        name: &str,
        kind: FileKind,
        mode: u32,
        rdev: u64,
        uid: u32,
        gid: u32,
    ) -> Result<Arc<dyn File>, Errno> {
        self.dir()?;
        if name.len() > 255 {
            return Err(Errno::ENAMETOOLONG);
        }
        let (tree, dir) = (self.tree, self.objectid);
        let ino = self
            .shared
            .transact(|tx| tx.create(tree, dir, name.as_bytes(), NewInode { kind, mode, rdev, uid, gid }))?;
        self.new_node(ino)
    }

    fn remove(&self, name: &str, dir: bool) -> Result<(), Errno> {
        self.dir()?;
        let (tree, parent) = (self.tree, self.objectid);
        let shared = &self.shared;
        shared.transact(|tx| tx.remove(tree, parent, name.as_bytes(), dir, &|t, i| shared.is_open(t, i)))
    }

    fn link(&self, name: &str, target: &dyn File) -> Result<(), Errno> {
        self.dir()?;
        if name.len() > 255 {
            return Err(Errno::ENAMETOOLONG);
        }
        let target = self.same_fs(target)?;
        let (tree, dir, ino) = (self.tree, self.objectid, target.objectid);
        self.shared.transact(|tx| tx.link(tree, dir, name.as_bytes(), ino))
    }

    fn rename(&self, old_name: &str, new_dir: &dyn File, new_name: &str) -> Result<(), Errno> {
        self.dir()?;
        if new_name.len() > 255 {
            return Err(Errno::ENAMETOOLONG);
        }
        let new_dir = self.same_fs(new_dir)?;
        new_dir.dir()?;
        let (tree, odir, ndir) = (self.tree, self.objectid, new_dir.objectid);
        let shared = &self.shared;
        shared.transact(|tx| {
            tx.rename(tree, odir, old_name.as_bytes(), ndir, new_name.as_bytes(), &|t, i| shared.is_open(t, i))
        })
    }

    fn readlink(&self) -> Result<String, Errno> {
        if self.kind != FileKind::Symlink {
            return Err(Errno::EINVAL);
        }
        let st = self.shared.state();
        let inode = self.fresh_inode(&st)?;
        if inode.size > PATH_MAX as u64 {
            return Err(Errno::EIO);
        }
        let mut target = try_zeroed(inode.size as usize)?;
        self.shared.read_file(&st, self.root(&st)?, self.objectid, &inode, 0, &mut target, None)?;
        drop(st);
        self.touch_atime(&inode);
        String::from_utf8(target).map_err(|_| Errno::EIO)
    }

    fn xattr_get(&self, name: &[u8]) -> Result<Vec<u8>, Errno> {
        self.xattr(name, |v| Ok(try_to_vec(v)?))?.ok_or(Errno::ENODATA)
    }

    fn xattr_set(&self, name: &[u8], value: &[u8], how: XattrSet) -> Result<(), Errno> {
        let (tree, ino) = (self.tree, self.objectid);
        self.shared.transact(|tx| tx.xattr_set(tree, ino, name, value, how))
    }

    fn xattr_remove(&self, name: &[u8]) -> Result<(), Errno> {
        let (tree, ino) = (self.tree, self.objectid);
        self.shared.transact(|tx| tx.xattr_remove(tree, ino, name))
    }

    fn xattr_list(&self) -> Result<Vec<Vec<u8>>, Errno> {
        let st = self.shared.state();
        let mut out = Vec::new();
        let mut c = Cursor::new(&self.shared, &st.chunks, self.root(&st)?);
        let mut cur = c.seek(Key::new(self.objectid, item::XATTR_ITEM, 0))?;
        while let Some((k, data)) = cur {
            if k.objectid != self.objectid || k.ty != item::XATTR_ITEM {
                break;
            }
            for e in DirItems::new(data) {
                try_push(&mut out, try_to_vec(e?.name)?)?;
            }
            cur = c.next()?;
        }
        Ok(out)
    }
}

impl<D: BlockDevice + Send + 'static> Node<D> {
    fn stat_of(&self, i: &Inode) -> Stat {
        let rdev = match self.kind {
            FileKind::CharDevice | FileKind::BlockDevice => makedev((i.rdev >> 20) as u32, (i.rdev & 0xf_ffff) as u32),
            _ => 0,
        };
        Stat {
            dev: self.shared.dev_id,
            ino: self.shared.ino(self.tree, self.objectid),
            kind: self.kind,
            mode: i.mode & 0o7777,
            uid: i.uid,
            gid: i.gid,
            nlink: i.nlink,
            size: i.size,
            rdev,
            atime: i.atime,
            mtime: i.mtime,
            ctime: i.ctime,
        }
    }
}
