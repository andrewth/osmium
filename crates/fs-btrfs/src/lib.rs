//! A read-only btrfs file system on any [`BlockDevice`], for the `osmium-fs`
//! VFS.
//!
//! [`BtrfsFs::mount`] reads the superblock and the chunk tree and hands out
//! the default subvolume's root directory as an [`osmium_fs::File`] with
//! [`BtrfsFs::root`], ready for `Vfs::mount`; [`BtrfsFs::mount_subvol`]
//! picks another subvolume by id. Other subvolumes and snapshots show up as
//! directories, as on Linux.
//!
//! Every tree block and data sector is checked against its checksum (CRC32C
//! or xxHash64) unless the file has `nodatasum`, and a block or sector that
//! fails is read from its other copy if there is one (`DUP`, `RAID1`,
//! `RAID1C3`, `RAID1C4`). Extents may be inline, regular, preallocated or
//! holes (implicit with `no-holes`), and compressed with zlib, LZO or zstd.
//! Extended attributes, symbolic links and device nodes are read too.
//!
//! The volume is not written, so nodes hold no shared state; each read walks
//! the trees from their roots, helped by a small cache of tree blocks and,
//! per file, the last extent decompressed.
//!
//! Inode numbers: the mounted subvolume's are btrfs's own; another
//! subvolume's are mixed with its id so they do not collide with them (Linux
//! gives each subvolume its own `st_dev` instead).
//!
//! Not supported: writing; file systems over several devices (only the
//! copies on the device given are read, and striped chunks, RAID0, RAID10,
//! RAID5 and RAID6, fail with `EIO`); SHA-256 and BLAKE2b checksums;
//! `extent-tree-v2` and the RAID stripe tree; replaying the fsync log (data
//! fsynced after the last commit is missing, as with Linux's `nologreplay`);
//! owners, which `Stat` has no room for; and encrypted or verity files.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod csum;
mod disk;
mod lzo;
mod tree;
mod xxhash;
mod zlib;
mod zstd;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_fs::dev::makedev;
use osmium_fs::{DirEntry, Errno, File, FileKind, PATH_MAX, Stat};
use osmium_hal::block::BlockDevice;
use osmium_sync::SpinLock;
use osmium_sync::fallible::{try_arc, try_push, try_to_vec, try_zeroed};

use disk::{DirItems, ExtentData, FileExtent, Inode, Key, Root, Super, compress, item};
use tree::{Block, ChunkMap, Cursor};

/// Largest single device read, so drivers see bounded transfers.
const MAX_RUN: usize = 64 * 1024;

/// Largest compressed extent, before and after decompression
/// (`BTRFS_MAX_COMPRESSED`).
const MAX_COMPRESSED: u64 = 128 * 1024;

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
    chunks: ChunkMap,
    /// Recently read tree blocks by address, and the next slot to replace.
    cache: SpinLock<(Vec<(u64, Block)>, usize)>,
    /// The root tree's root block and level.
    root_tree: (u64, u8),
    /// The checksum tree's, if it has one.
    csum_tree: Option<(u64, u8)>,
    /// The mounted subvolume.
    top: u64,
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
    tree: Root,
    objectid: u64,
    inode: Inode,
    kind: FileKind,
    /// The last compressed extent read, by address, decompressed.
    extent: SpinLock<Option<(u64, Arc<Vec<u8>>)>>,
    /// Where the last `readdir` stopped: the next index asked for, and the
    /// `DIR_INDEX` key offset to resume at.
    dir_hint: SpinLock<(usize, u64)>,
}

fn kind_of(mode: u32) -> Option<FileKind> {
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

impl<D: BlockDevice + Send + 'static> BtrfsFs<D> {
    /// Mounts the btrfs volume on `dev` at its default subvolume. `dev_id`
    /// becomes `Stat::dev` of every node. Fails with `EINVAL` if the device
    /// does not hold one this driver can read.
    pub fn mount(dev: D, dev_id: u64) -> Result<Self, Errno> {
        Self::open(dev, dev_id, None)
    }

    /// Mounts subvolume `subvol` (5 is the top level) of the btrfs volume on
    /// `dev`; `ENOENT` if there is no such subvolume.
    pub fn mount_subvol(dev: D, dev_id: u64, subvol: u64) -> Result<Self, Errno> {
        Self::open(dev, dev_id, Some(subvol))
    }

    fn open(dev: D, dev_id: u64, subvol: Option<u64>) -> Result<Self, Errno> {
        let block_size = dev.block_size();
        if block_size == 0 || block_size > MAX_RUN {
            return Err(Errno::EINVAL);
        }
        let end = disk::SUPER_OFFSET + disk::SUPER_SIZE as u64;
        if (dev.num_blocks() as u128) * (block_size as u128) < end as u128 {
            return Err(Errno::EINVAL);
        }
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
            chunks: ChunkMap::default(),
            cache: SpinLock::new((Vec::new(), 0)),
            root_tree: (0, 0),
            csum_tree: None,
            top: disk::tree::FS,
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
        shared.root_tree = sb.root;
        shared.chunks = ChunkMap::bootstrap(&sb.sys_chunks)?;

        // The chunk tree maps everything else.
        let mut chunks = Vec::new();
        {
            let mut c = Cursor::new(&shared, sb.chunk_root);
            let mut at = c.seek(Key::new(disk::tree::FIRST_CHUNK, item::CHUNK_ITEM, 0))?;
            while let Some((k, data)) = at {
                if k.objectid != disk::tree::FIRST_CHUNK || k.ty != item::CHUNK_ITEM {
                    break;
                }
                try_push(&mut chunks, disk::Chunk::parse(data, k.offset)?.0)?;
                at = c.next()?;
            }
        }
        for chunk in chunks {
            shared.chunks.insert(chunk)?;
        }

        shared.csum_tree = shared.tree_root(disk::tree::CSUM)?.map(|r| (r.bytenr, r.level));
        let top = match subvol {
            Some(id) => id,
            None => shared.default_subvol()?,
        };
        shared.top = top;
        let root = shared.fs_root(top)?.ok_or(Errno::ENOENT)?;
        let shared = try_arc(shared)?;
        let root = shared.node(root, disk::tree::FIRST_FREE)?;
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
}

impl<D: BlockDevice + Send + 'static> Shared<D> {
    /// The root of tree `id`, from the root tree.
    fn tree_root(&self, id: u64) -> Result<Option<Root>, Errno> {
        let mut c = Cursor::new(self, self.root_tree);
        match c.seek(Key::new(id, item::ROOT_ITEM, 0))? {
            Some((k, data)) if k.objectid == id && k.ty == item::ROOT_ITEM => Ok(Some(Root::parse(data, id)?)),
            _ => Ok(None),
        }
    }

    /// The root of subvolume `id`; `None` if there is none.
    fn fs_root(&self, id: u64) -> Result<Option<Root>, Errno> {
        if id != disk::tree::FS && !(disk::tree::FIRST_FREE..=disk::tree::LAST_FREE).contains(&id) {
            return Ok(None);
        }
        let root = self.tree_root(id)?;
        if root.is_some_and(|r| r.dirid != disk::tree::FIRST_FREE) {
            return Err(Errno::EIO);
        }
        Ok(root)
    }

    /// The subvolume `btrfs subvolume set-default` chose, else the top level.
    fn default_subvol(&self) -> Result<u64, Errno> {
        let key = Key::new(disk::tree::ROOT_DIR, item::DIR_ITEM, csum::name_hash(b"default"));
        let found = self.lookup(self.root_tree, key, |data| {
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

    /// The node for inode `objectid` of subvolume `tree`.
    fn node(self: &Arc<Self>, tree: Root, objectid: u64) -> Result<Node<D>, Errno> {
        let key = Key::new(objectid, item::INODE_ITEM, 0);
        let inode = self.lookup((tree.bytenr, tree.level), key, Inode::parse)?.ok_or(Errno::EIO)?;
        Ok(Node {
            shared: self.clone(),
            tree,
            objectid,
            kind: kind_of(inode.mode).ok_or(Errno::EIO)?,
            inode,
            extent: SpinLock::new(None),
            dir_hint: SpinLock::new((0, 0)),
        })
    }

    /// The inode number shown for `objectid` of subvolume `tree`.
    fn ino(&self, tree: u64, objectid: u64) -> u64 {
        if tree == self.top { objectid } else { objectid ^ tree.rotate_right(16) }
    }

    /// The data checksums of `n` sectors from logical `at`; `EIO` if any is
    /// missing.
    fn csums(&self, at: u64, n: usize) -> Result<Vec<u8>, Errno> {
        let (cs, ss) = (self.csum_size, self.sectorsize);
        let mut out = try_zeroed(n.checked_mul(cs).ok_or(Errno::EIO)?)?;
        let mut c = Cursor::new(self, self.csum_tree.ok_or(Errno::EIO)?);
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
    fn read_sectors(&self, at: u64, buf: &mut [u8], verify: bool) -> Result<(), Errno> {
        if !verify {
            return self.read_logical(at, buf, &mut |_| true);
        }
        let ss = self.sectorsize as usize;
        let sums = self.csums(at, buf.len() / ss)?;
        let (ty, cs) = (self.csum_type, self.csum_size);
        self.read_logical(at, buf, &mut |b| {
            b.chunks(ss).zip(sums.chunks(cs)).all(|(sector, sum)| csum::matches(ty, sector, sum))
        })
    }

    /// Reads `out.len()` bytes of data at logical `at`, a whole sector at a
    /// time.
    fn read_data(&self, mut at: u64, mut out: &mut [u8], verify: bool) -> Result<(), Errno> {
        let ss = self.sectorsize;
        while !out.is_empty() {
            let start = at & !(ss - 1);
            let skip = (at - start) as usize;
            let span = (skip + out.len()).min(MAX_RUN);
            let n = span - skip;
            let mut tmp = try_zeroed(span.next_multiple_of(ss as usize))?;
            self.read_sectors(start, &mut tmp, verify)?;
            out.get_mut(..n).ok_or(Errno::EIO)?.copy_from_slice(tmp.get(skip..span).ok_or(Errno::EIO)?);
            at = at.checked_add(n as u64).ok_or(Errno::EIO)?;
            out = out.get_mut(n..).ok_or(Errno::EIO)?;
        }
        Ok(())
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
    fn tree(&self) -> (u64, u8) {
        (self.tree.bytenr, self.tree.level)
    }

    /// Reads bytes `skip..skip + out.len()` of the file range extent `fe` covers.
    fn read_extent(&self, fe: &FileExtent<'_>, skip: u64, out: &mut [u8]) -> Result<(), Errno> {
        let shared = &self.shared;
        let verify = self.inode.flags & disk::INODE_NODATASUM == 0;
        match fe.data {
            ExtentData::Prealloc { .. } | ExtentData::Regular { disk_bytenr: 0, .. } => out.fill(0),
            ExtentData::Inline(data) if fe.compression == compress::NONE => copy_from(data, skip, out),
            ExtentData::Inline(data) => {
                let plain = decompress(fe.compression, data, fe.ram_bytes, shared.sectorsize as usize)?;
                copy_from(&plain, skip, out);
            }
            ExtentData::Regular { disk_bytenr, offset, .. } if fe.compression == compress::NONE => {
                let at = disk_bytenr.checked_add(offset).and_then(|a| a.checked_add(skip)).ok_or(Errno::EIO)?;
                shared.read_data(at, out, verify)?;
            }
            ExtentData::Regular { disk_bytenr, disk_num_bytes, offset, .. } => {
                let cached = self.extent.lock().as_ref().filter(|(at, _)| *at == disk_bytenr).map(|(_, d)| d.clone());
                let plain = match cached {
                    Some(plain) => plain,
                    None => {
                        let ss = shared.sectorsize;
                        if disk_num_bytes > MAX_COMPRESSED || disk_num_bytes % ss != 0 || disk_bytenr % ss != 0 {
                            return Err(Errno::EIO);
                        }
                        let mut raw = try_zeroed(disk_num_bytes as usize)?;
                        shared.read_sectors(disk_bytenr, &mut raw, verify)?;
                        let plain = try_arc(decompress(fe.compression, &raw, fe.ram_bytes, ss as usize)?)?;
                        *self.extent.lock() = Some((disk_bytenr, plain.clone()));
                        plain
                    }
                };
                copy_from(&plain, offset.checked_add(skip).ok_or(Errno::EIO)?, out);
            }
        }
        Ok(())
    }

    /// Reads the file's bytes at `off`, whatever its kind.
    fn read_bytes(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let size = self.inode.size;
        if off >= size {
            return Ok(0);
        }
        let want = buf.len().min((size - off).min(usize::MAX as u64) as usize);
        let buf = buf.get_mut(..want).ok_or(Errno::EIO)?;
        let ours = |k: &Key| k.objectid == self.objectid && k.ty == item::EXTENT_DATA;
        let key = Key::new(self.objectid, item::EXTENT_DATA, off);
        let mut c = Cursor::new(&self.shared, self.tree());
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
                self.read_extent(&fe, pos - k.offset, buf.get_mut(done..done + n).ok_or(Errno::EIO)?)?;
                done += n;
            }
            cur = c.next()?;
        }
        // A hole up to the end of the file.
        buf.get_mut(done..).ok_or(Errno::EIO)?.fill(0);
        Ok(want)
    }

    /// The node a directory entry's location names.
    fn open(&self, location: Key) -> Result<Node<D>, Errno> {
        match location.ty {
            item::INODE_ITEM => self.shared.node(self.tree, location.objectid),
            item::ROOT_ITEM => {
                let root = self.shared.fs_root(location.objectid)?.ok_or(Errno::ENOENT)?;
                self.shared.node(root, disk::tree::FIRST_FREE)
            }
            _ => Err(Errno::EIO),
        }
    }

    /// The inode number a directory entry's location gives its node.
    fn entry_ino(&self, location: Key) -> u64 {
        match location.ty {
            item::ROOT_ITEM => self.shared.ino(location.objectid, disk::tree::FIRST_FREE),
            _ => self.shared.ino(self.tree.id, location.objectid),
        }
    }

    /// The value of the `XATTR_ITEM` entry `name`, given to `f`.
    fn xattr<R>(&self, name: &[u8], f: impl FnOnce(&[u8]) -> Result<R, Errno>) -> Result<Option<R>, Errno> {
        let key = Key::new(self.objectid, item::XATTR_ITEM, csum::name_hash(name));
        let found = self.shared.lookup(self.tree(), key, |data| {
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

    fn dir(&self) -> Result<(), Errno> {
        if self.kind == FileKind::Directory { Ok(()) } else { Err(Errno::ENOTDIR) }
    }
}

impl<D: BlockDevice + Send + 'static> File for Node<D> {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        match self.kind {
            FileKind::Regular => self.read_bytes(off, buf),
            FileKind::Directory => Err(Errno::EISDIR),
            _ => Err(Errno::EINVAL),
        }
    }

    fn write(&self, _off: u64, _buf: &[u8]) -> Result<usize, Errno> {
        match self.kind {
            FileKind::Directory => Err(Errno::EISDIR),
            _ => Err(Errno::EROFS),
        }
    }

    fn stat(&self) -> Stat {
        let i = &self.inode;
        let rdev = match self.kind {
            FileKind::CharDevice | FileKind::BlockDevice => makedev((i.rdev >> 20) as u32, (i.rdev & 0xf_ffff) as u32),
            _ => 0,
        };
        Stat {
            dev: self.shared.dev_id,
            ino: self.shared.ino(self.tree.id, self.objectid),
            kind: self.kind,
            mode: i.mode & 0o7777,
            nlink: i.nlink,
            size: i.size,
            rdev,
            atime: i.atime,
            mtime: i.mtime,
            ctime: i.ctime,
        }
    }

    fn truncate(&self, _len: u64) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }

    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        self.dir()?;
        // Resume where the last call stopped if it is at or before `index`.
        let (mut i, from) = match *self.dir_hint.lock() {
            (i, from) if i <= index => (i, from),
            _ => (0, 0),
        };
        let mut c = Cursor::new(&self.shared, self.tree());
        let mut cur = c.seek(Key::new(self.objectid, item::DIR_INDEX, from))?;
        while let Some((k, data)) = cur {
            if k.objectid != self.objectid || k.ty != item::DIR_INDEX {
                break;
            }
            let e = DirItems::new(data).next().ok_or(Errno::EIO)??;
            if let Some(name) = usable(e.name) {
                if i == index {
                    *self.dir_hint.lock() = (index.saturating_add(1), k.offset.saturating_add(1));
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
        let key = Key::new(self.objectid, item::DIR_ITEM, csum::name_hash(name.as_bytes()));
        let location = self.shared.lookup(self.tree(), key, |data| {
            for e in DirItems::new(data) {
                let e = e?;
                if e.name == name.as_bytes() {
                    return Ok(Some(e.location));
                }
            }
            Ok(None)
        })?;
        let location = location.flatten().ok_or(Errno::ENOENT)?;
        Ok(try_arc(self.open(location)?)?)
    }

    fn create(&self, _name: &str, _kind: FileKind, _mode: u32) -> Result<Arc<dyn File>, Errno> {
        self.dir()?;
        Err(Errno::EROFS)
    }

    fn remove(&self, _name: &str, _dir: bool) -> Result<(), Errno> {
        self.dir()?;
        Err(Errno::EROFS)
    }

    fn readlink(&self) -> Result<String, Errno> {
        if self.kind != FileKind::Symlink {
            return Err(Errno::EINVAL);
        }
        if self.inode.size > PATH_MAX as u64 {
            return Err(Errno::EIO);
        }
        let mut target = try_zeroed(self.inode.size as usize)?;
        self.read_bytes(0, &mut target)?;
        String::from_utf8(target).map_err(|_| Errno::EIO)
    }

    fn xattr_get(&self, name: &[u8]) -> Result<Vec<u8>, Errno> {
        self.xattr(name, |v| Ok(try_to_vec(v)?))?.ok_or(Errno::ENODATA)
    }

    fn xattr_set(&self, _name: &[u8], _value: &[u8], _how: osmium_fs::XattrSet) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }

    fn xattr_remove(&self, _name: &[u8]) -> Result<(), Errno> {
        Err(Errno::EROFS)
    }

    fn xattr_list(&self) -> Result<Vec<Vec<u8>>, Errno> {
        let mut out = Vec::new();
        let mut c = Cursor::new(&self.shared, self.tree());
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
