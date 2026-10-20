//! The second extended file system, read and write, over any
//! [`BlockDevice`].
//!
//! Supported: revisions 0 and 1, block sizes from 1 KiB to 32 KiB, any inode
//! size, direct and indirect block maps, sparse files, fast and slow
//! symbolic links, the `filetype`, `sparse_super` and `large_file` features.
//! A file system with an incompatible feature (extents, 64-bit, journal
//! recovery, compression) is refused; one with an unknown read-only feature
//! mounts read-only. Hashed directory indexes are ignored for lookup and
//! dropped (the flag is cleared) when a directory changes, as Linux's ext2
//! driver does.
//!
//! All state lives behind one spin lock held across device I/O, and there is
//! no block cache: simple and correct, not fast. Nothing is journaled; call
//! [`File::sync`] to flush the device.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use osmium_hal::block::{BlockDevice, BlockError};
use osmium_sync::SpinLock;

use crate::dev::makedev;
use crate::{DirEntry, Errno, File, FileKind, NAME_MAX, Stat};

const MAGIC: u16 = 0xef53;
const ROOT_INO: u32 = 2;
const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_LEN: usize = 1024;
const GROUP_DESC_LEN: usize = 32;
const NDIR_BLOCKS: usize = 12;

const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_SUPPORTED: u32 = INCOMPAT_FILETYPE;
const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
const RO_COMPAT_BTREE_DIR: u32 = 0x0004;
const RO_COMPAT_SUPPORTED: u32 = RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE | RO_COMPAT_BTREE_DIR;

/// Inode flags.
const INDEX_FL: u32 = 0x1000;
const EXTENTS_FL: u32 = 0x8_0000;

/// Extended attribute block header magic.
const XATTR_MAGIC: u32 = 0xea02_0000;

/// Superblock field offsets.
mod sb {
    pub const INODES_COUNT: usize = 0;
    pub const BLOCKS_COUNT: usize = 4;
    pub const FREE_BLOCKS: usize = 12;
    pub const FREE_INODES: usize = 16;
    pub const FIRST_DATA_BLOCK: usize = 20;
    pub const LOG_BLOCK_SIZE: usize = 24;
    pub const BLOCKS_PER_GROUP: usize = 32;
    pub const INODES_PER_GROUP: usize = 40;
    pub const WTIME: usize = 48;
    pub const MAGIC: usize = 56;
    pub const REV_LEVEL: usize = 76;
    pub const FIRST_INO: usize = 84;
    pub const INODE_SIZE: usize = 88;
    pub const FEATURE_INCOMPAT: usize = 96;
    pub const FEATURE_RO_COMPAT: usize = 100;
    pub const WANT_EXTRA_ISIZE: usize = 0x15e;
}

/// Group descriptor field offsets.
mod gd {
    pub const BLOCK_BITMAP: usize = 0;
    pub const INODE_BITMAP: usize = 4;
    pub const INODE_TABLE: usize = 8;
    pub const FREE_BLOCKS: usize = 12;
    pub const FREE_INODES: usize = 14;
    pub const USED_DIRS: usize = 16;
}

/// Inode field offsets.
mod ino {
    pub const MODE: usize = 0;
    pub const SIZE: usize = 4;
    pub const ATIME: usize = 8;
    pub const CTIME: usize = 12;
    pub const MTIME: usize = 16;
    pub const DTIME: usize = 20;
    pub const LINKS: usize = 26;
    pub const BLOCKS: usize = 28;
    pub const FLAGS: usize = 32;
    pub const BLOCK: usize = 40;
    pub const FILE_ACL: usize = 104;
    pub const SIZE_HIGH: usize = 108;
    pub const EXTRA_ISIZE: usize = 128;
}

fn get16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn get32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

fn put16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

fn put32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn io_error(e: BlockError) -> Errno {
    match e {
        BlockError::ReadOnly => Errno::EROFS,
        _ => Errno::EIO,
    }
}

fn kind_of(mode: u16) -> FileKind {
    match mode & 0o170000 {
        0o010000 => FileKind::Fifo,
        0o020000 => FileKind::CharDevice,
        0o040000 => FileKind::Directory,
        0o060000 => FileKind::BlockDevice,
        0o120000 => FileKind::Symlink,
        0o140000 => FileKind::Socket,
        _ => FileKind::Regular,
    }
}

/// The directory entry `file_type` byte.
fn dirent_type(kind: FileKind) -> u8 {
    match kind {
        FileKind::Regular => 1,
        FileKind::Directory => 2,
        FileKind::CharDevice => 3,
        FileKind::BlockDevice => 4,
        FileKind::Fifo => 5,
        FileKind::Socket => 6,
        FileKind::Symlink => 7,
    }
}

/// The length of a directory record holding a name of `len` bytes.
fn rec_len_for(len: usize) -> usize {
    (8 + len).next_multiple_of(4)
}

/// An inode's on-disk bytes.
struct Inode {
    raw: Vec<u8>,
}

impl Inode {
    fn mode(&self) -> u16 {
        get16(&self.raw, ino::MODE)
    }

    fn kind(&self) -> FileKind {
        kind_of(self.mode())
    }

    fn size(&self) -> u64 {
        let high = if self.kind() == FileKind::Regular { get32(&self.raw, ino::SIZE_HIGH) } else { 0 };
        (high as u64) << 32 | get32(&self.raw, ino::SIZE) as u64
    }

    fn set_size(&mut self, size: u64) {
        put32(&mut self.raw, ino::SIZE, size as u32);
        if self.kind() == FileKind::Regular {
            put32(&mut self.raw, ino::SIZE_HIGH, (size >> 32) as u32);
        }
    }

    fn links(&self) -> u16 {
        get16(&self.raw, ino::LINKS)
    }

    fn set_links(&mut self, links: u16) {
        put16(&mut self.raw, ino::LINKS, links);
    }

    fn flags(&self) -> u32 {
        get32(&self.raw, ino::FLAGS)
    }

    fn block(&self, i: usize) -> u32 {
        get32(&self.raw, ino::BLOCK + 4 * i)
    }

    fn set_block(&mut self, i: usize, b: u32) {
        put32(&mut self.raw, ino::BLOCK + 4 * i, b);
    }

    /// Allocated 512-byte sectors, including indirect and xattr blocks.
    fn sectors(&self) -> u32 {
        get32(&self.raw, ino::BLOCKS)
    }

    fn add_sectors(&mut self, delta: i64) {
        let v = (self.sectors() as i64 + delta).max(0) as u32;
        put32(&mut self.raw, ino::BLOCKS, v);
    }

    fn file_acl(&self) -> u32 {
        get32(&self.raw, ino::FILE_ACL)
    }

    fn set_times(&mut self, now: u32, fields: &[usize]) {
        for &f in fields {
            put32(&mut self.raw, f, now);
        }
    }
}

struct Fs<D: BlockDevice + Send + 'static> {
    dev: D,
    /// Device blocks per file system block.
    dev_per_block: u64,
    block_size: usize,
    /// The primary superblock's bytes.
    sb: Vec<u8>,
    /// Every group descriptor's bytes, back to back.
    groups: Vec<u8>,
    group_count: u32,
    /// Block of the primary group descriptor table.
    gdt_block: u32,
    inode_size: usize,
    first_ino: u32,
    filetype: bool,
    read_only: bool,
    clock: fn() -> u32,
    /// One node per in-use inode, so an unlinked file is freed when its
    /// last reference goes.
    nodes: BTreeMap<u32, Weak<Node<D>>>,
    st_dev: u64,
}

/// An ext2 file system on a block device.
pub struct Ext2<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
}

struct Shared<D: BlockDevice + Send + 'static> {
    fs: SpinLock<Fs<D>>,
}

/// One inode, as a [`File`].
struct Node<D: BlockDevice + Send + 'static> {
    shared: Arc<Shared<D>>,
    ino: u32,
}

fn no_clock() -> u32 {
    0
}

impl<D: BlockDevice + Send + 'static> Ext2<D> {
    /// Mounts the ext2 file system on `dev`, reporting `st_dev` as `devno`.
    /// Fails with `EINVAL` if `dev` holds no ext2 file system and `ENOSYS`
    /// for unsupported features.
    pub fn mount(dev: D, devno: u64) -> Result<Self, Errno> {
        let dev_bs = dev.block_size();
        let mut fs = Fs {
            dev,
            dev_per_block: 1,
            block_size: dev_bs,
            sb: vec![0; SUPERBLOCK_LEN],
            groups: Vec::new(),
            group_count: 0,
            gdt_block: 0,
            inode_size: 128,
            first_ino: 11,
            filetype: false,
            read_only: false,
            clock: no_clock,
            nodes: BTreeMap::new(),
            st_dev: devno,
        };
        let mut sbuf = vec![0; SUPERBLOCK_LEN];
        fs.read_bytes(SUPERBLOCK_OFFSET, &mut sbuf)?;
        fs.sb = sbuf;
        if get16(&fs.sb, sb::MAGIC) != MAGIC {
            return Err(Errno::EINVAL);
        }
        let log = get32(&fs.sb, sb::LOG_BLOCK_SIZE);
        // Record lengths are 16 bits, so a block holds at most 32 KiB.
        if log > 5 {
            return Err(Errno::EINVAL);
        }
        fs.block_size = 1024 << log;
        if dev_bs == 0 || fs.block_size % dev_bs != 0 {
            return Err(Errno::EINVAL);
        }
        fs.dev_per_block = (fs.block_size / dev_bs) as u64;
        if get32(&fs.sb, sb::REV_LEVEL) >= 1 {
            fs.first_ino = get32(&fs.sb, sb::FIRST_INO);
            fs.inode_size = get16(&fs.sb, sb::INODE_SIZE) as usize;
            let incompat = get32(&fs.sb, sb::FEATURE_INCOMPAT);
            if incompat & !INCOMPAT_SUPPORTED != 0 {
                return Err(Errno::ENOSYS);
            }
            fs.filetype = incompat & INCOMPAT_FILETYPE != 0;
            fs.read_only = get32(&fs.sb, sb::FEATURE_RO_COMPAT) & !RO_COMPAT_SUPPORTED != 0;
        }
        let per_group = get32(&fs.sb, sb::BLOCKS_PER_GROUP);
        let inodes_per_group = get32(&fs.sb, sb::INODES_PER_GROUP);
        let blocks = get32(&fs.sb, sb::BLOCKS_COUNT);
        let first = get32(&fs.sb, sb::FIRST_DATA_BLOCK);
        if fs.inode_size < 128 || !fs.inode_size.is_power_of_two() || fs.inode_size > fs.block_size {
            return Err(Errno::EINVAL);
        }
        if per_group == 0 || inodes_per_group == 0 || blocks <= first {
            return Err(Errno::EINVAL);
        }
        fs.group_count = (blocks - first).div_ceil(per_group);
        if get32(&fs.sb, sb::INODES_COUNT) != fs.group_count * inodes_per_group {
            return Err(Errno::EINVAL);
        }
        fs.gdt_block = first + 1;
        let mut groups = vec![0; fs.group_count as usize * GROUP_DESC_LEN];
        fs.read_bytes(fs.gdt_block as u64 * fs.block_size as u64, &mut groups)?;
        fs.groups = groups;
        let shared = Arc::new(Shared { fs: SpinLock::new(fs) });
        Ok(Ext2 { shared })
    }

    /// Sets the clock that stamps access, change and modification times, in
    /// seconds since 1970. Without one, new times are 0.
    pub fn set_clock(&self, clock: fn() -> u32) {
        self.shared.fs.lock().clock = clock;
    }

    /// Whether writes fail with `EROFS` (an unknown read-only feature).
    pub fn is_read_only(&self) -> bool {
        self.shared.fs.lock().read_only
    }

    /// The root directory, to pass to [`Vfs::mount`](crate::Vfs::mount).
    pub fn root(&self) -> Arc<dyn File> {
        let mut fs = self.shared.fs.lock();
        fs.node(&self.shared, ROOT_INO)
    }

    /// Unmounts, returning the device once no node is in use; otherwise
    /// `EBUSY` with the file system unchanged.
    pub fn into_device(self) -> Result<D, (Self, Errno)> {
        match Arc::try_unwrap(self.shared) {
            Ok(shared) => {
                let mut fs = shared.fs.into_inner();
                let _ = fs.dev.flush();
                Ok(fs.dev)
            }
            Err(shared) => Err((Ext2 { shared }, Errno::EBUSY)),
        }
    }
}

impl<D: BlockDevice + Send + 'static> Fs<D> {
    fn node(&mut self, shared: &Arc<Shared<D>>, ino: u32) -> Arc<dyn File> {
        if let Some(node) = self.nodes.get(&ino).and_then(Weak::upgrade) {
            return node;
        }
        let node = Arc::new(Node { shared: shared.clone(), ino });
        self.nodes.insert(ino, Arc::downgrade(&node));
        node
    }

    fn writable(&self) -> Result<(), Errno> {
        if self.read_only { Err(Errno::EROFS) } else { Ok(()) }
    }

    fn now(&self) -> u32 {
        (self.clock)()
    }

    // ---- Raw I/O ----

    /// Reads bytes at any offset, a device block at a time.
    fn read_bytes(&mut self, off: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let bs = self.dev.block_size() as u64;
        let mut tmp = vec![0; bs as usize];
        let mut done = 0;
        while done < buf.len() {
            let pos = off + done as u64;
            let (lba, skip) = (pos / bs, (pos % bs) as usize);
            let n = (bs as usize - skip).min(buf.len() - done);
            self.dev.read_blocks(lba, &mut tmp).map_err(io_error)?;
            buf[done..done + n].copy_from_slice(&tmp[skip..skip + n]);
            done += n;
        }
        Ok(())
    }

    /// Writes bytes at any offset, reading back partial device blocks.
    fn write_bytes(&mut self, off: u64, buf: &[u8]) -> Result<(), Errno> {
        let bs = self.dev.block_size() as u64;
        let mut tmp = vec![0; bs as usize];
        let mut done = 0;
        while done < buf.len() {
            let pos = off + done as u64;
            let (lba, skip) = (pos / bs, (pos % bs) as usize);
            let n = (bs as usize - skip).min(buf.len() - done);
            if n < bs as usize {
                self.dev.read_blocks(lba, &mut tmp).map_err(io_error)?;
            }
            tmp[skip..skip + n].copy_from_slice(&buf[done..done + n]);
            self.dev.write_blocks(lba, &tmp).map_err(io_error)?;
            done += n;
        }
        Ok(())
    }

    fn read_block(&mut self, b: u32) -> Result<Vec<u8>, Errno> {
        if b == 0 || b >= get32(&self.sb, sb::BLOCKS_COUNT) {
            return Err(Errno::EIO);
        }
        let mut buf = vec![0; self.block_size];
        self.dev.read_blocks(b as u64 * self.dev_per_block, &mut buf).map_err(io_error)?;
        Ok(buf)
    }

    fn write_block(&mut self, b: u32, buf: &[u8]) -> Result<(), Errno> {
        if b == 0 || b >= get32(&self.sb, sb::BLOCKS_COUNT) {
            return Err(Errno::EIO);
        }
        self.dev.write_blocks(b as u64 * self.dev_per_block, buf).map_err(io_error)
    }

    fn write_super(&mut self) -> Result<(), Errno> {
        let now = self.now();
        put32(&mut self.sb, sb::WTIME, now);
        let sbuf = core::mem::take(&mut self.sb);
        let result = self.write_bytes(SUPERBLOCK_OFFSET, &sbuf);
        self.sb = sbuf;
        result
    }

    fn write_group(&mut self, g: u32) -> Result<(), Errno> {
        let start = g as usize * GROUP_DESC_LEN;
        let desc: Vec<u8> = self.groups[start..start + GROUP_DESC_LEN].to_vec();
        self.write_bytes(self.gdt_block as u64 * self.block_size as u64 + start as u64, &desc)
    }

    fn group_field(&self, g: u32, field: usize) -> u32 {
        let off = g as usize * GROUP_DESC_LEN + field;
        match field {
            gd::FREE_BLOCKS | gd::FREE_INODES | gd::USED_DIRS => get16(&self.groups, off) as u32,
            _ => get32(&self.groups, off),
        }
    }

    fn adjust_group(&mut self, g: u32, field: usize, delta: i32) {
        let off = g as usize * GROUP_DESC_LEN + field;
        let v = get16(&self.groups, off) as i32 + delta;
        put16(&mut self.groups, off, v as u16);
    }

    fn adjust_super(&mut self, field: usize, delta: i32) {
        let v = get32(&self.sb, field) as i64 + delta as i64;
        put32(&mut self.sb, field, v as u32);
    }

    // ---- Inodes ----

    fn inode_offset(&self, ino: u32) -> Result<u64, Errno> {
        if ino == 0 || ino > get32(&self.sb, sb::INODES_COUNT) {
            return Err(Errno::EIO);
        }
        let per_group = get32(&self.sb, sb::INODES_PER_GROUP);
        let (g, i) = ((ino - 1) / per_group, (ino - 1) % per_group);
        let table = self.group_field(g, gd::INODE_TABLE) as u64;
        Ok(table * self.block_size as u64 + i as u64 * self.inode_size as u64)
    }

    fn read_inode(&mut self, ino: u32) -> Result<Inode, Errno> {
        let off = self.inode_offset(ino)?;
        let mut raw = vec![0; self.inode_size];
        self.read_bytes(off, &mut raw)?;
        Ok(Inode { raw })
    }

    fn write_inode(&mut self, ino: u32, inode: &Inode) -> Result<(), Errno> {
        let off = self.inode_offset(ino)?;
        self.write_bytes(off, &inode.raw)
    }

    // ---- Allocation ----

    /// Finds and sets a clear bit in a group's bitmap; returns its index.
    fn take_bit(&mut self, bitmap: u32, limit: u32) -> Result<Option<u32>, Errno> {
        let mut bits = self.read_block(bitmap)?;
        for (i, byte) in bits.iter_mut().enumerate() {
            if *byte == 0xff {
                continue;
            }
            let bit = byte.trailing_ones();
            let index = i as u32 * 8 + bit;
            if index >= limit {
                return Ok(None);
            }
            *byte |= 1 << bit;
            self.write_block(bitmap, &bits)?;
            return Ok(Some(index));
        }
        Ok(None)
    }

    fn clear_bit(&mut self, bitmap: u32, index: u32) -> Result<(), Errno> {
        let mut bits = self.read_block(bitmap)?;
        let byte = &mut bits[index as usize / 8];
        if *byte & (1 << (index % 8)) == 0 {
            return Err(Errno::EIO);
        }
        *byte &= !(1 << (index % 8));
        self.write_block(bitmap, &bits)
    }

    /// Allocates a zeroed block, preferring group `goal`.
    fn alloc_block(&mut self, goal: u32) -> Result<u32, Errno> {
        if get32(&self.sb, sb::FREE_BLOCKS) == 0 {
            return Err(Errno::ENOSPC);
        }
        let per_group = get32(&self.sb, sb::BLOCKS_PER_GROUP);
        let first = get32(&self.sb, sb::FIRST_DATA_BLOCK);
        let total = get32(&self.sb, sb::BLOCKS_COUNT);
        for k in 0..self.group_count {
            let g = (goal + k) % self.group_count;
            if self.group_field(g, gd::FREE_BLOCKS) == 0 {
                continue;
            }
            let start = first + g * per_group;
            let limit = per_group.min(total - start);
            let bitmap = self.group_field(g, gd::BLOCK_BITMAP);
            if let Some(i) = self.take_bit(bitmap, limit)? {
                self.adjust_group(g, gd::FREE_BLOCKS, -1);
                self.adjust_super(sb::FREE_BLOCKS, -1);
                self.write_group(g)?;
                self.write_super()?;
                let b = start + i;
                let zero = vec![0; self.block_size];
                self.write_block(b, &zero)?;
                return Ok(b);
            }
        }
        Err(Errno::ENOSPC)
    }

    fn free_block(&mut self, b: u32) -> Result<(), Errno> {
        let per_group = get32(&self.sb, sb::BLOCKS_PER_GROUP);
        let first = get32(&self.sb, sb::FIRST_DATA_BLOCK);
        if b < first || b >= get32(&self.sb, sb::BLOCKS_COUNT) {
            return Err(Errno::EIO);
        }
        let (g, i) = ((b - first) / per_group, (b - first) % per_group);
        let bitmap = self.group_field(g, gd::BLOCK_BITMAP);
        self.clear_bit(bitmap, i)?;
        self.adjust_group(g, gd::FREE_BLOCKS, 1);
        self.adjust_super(sb::FREE_BLOCKS, 1);
        self.write_group(g)?;
        self.write_super()
    }

    /// Allocates an inode of `mode`, preferring group `goal`, and writes it
    /// out fresh with one link.
    fn alloc_inode(&mut self, goal: u32, mode: u16) -> Result<(u32, Inode), Errno> {
        if get32(&self.sb, sb::FREE_INODES) == 0 {
            return Err(Errno::ENOSPC);
        }
        let per_group = get32(&self.sb, sb::INODES_PER_GROUP);
        for k in 0..self.group_count {
            let g = (goal + k) % self.group_count;
            if self.group_field(g, gd::FREE_INODES) == 0 {
                continue;
            }
            let bitmap = self.group_field(g, gd::INODE_BITMAP);
            let Some(i) = self.take_bit(bitmap, per_group)? else { continue };
            let ino = g * per_group + i + 1;
            if ino < self.first_ino {
                // A reserved inode marked free: the bitmap is corrupt.
                self.clear_bit(bitmap, i)?;
                return Err(Errno::EIO);
            }
            self.adjust_group(g, gd::FREE_INODES, -1);
            self.adjust_super(sb::FREE_INODES, -1);
            if kind_of(mode) == FileKind::Directory {
                self.adjust_group(g, gd::USED_DIRS, 1);
            }
            self.write_group(g)?;
            self.write_super()?;
            let mut inode = Inode { raw: vec![0; self.inode_size] };
            put16(&mut inode.raw, ino::MODE, mode);
            inode.set_links(1);
            let now = self.now();
            inode.set_times(now, &[ino::ATIME, ino::CTIME, ino::MTIME]);
            if self.inode_size > 128 {
                let extra = get16(&self.sb, sb::WANT_EXTRA_ISIZE).min((self.inode_size - 128) as u16);
                put16(&mut inode.raw, ino::EXTRA_ISIZE, extra);
            }
            self.write_inode(ino, &inode)?;
            return Ok((ino, inode));
        }
        Err(Errno::ENOSPC)
    }

    /// Frees an inode with no links: its blocks, its xattr block and its
    /// bitmap bit.
    fn free_inode(&mut self, ino: u32) -> Result<(), Errno> {
        let mut inode = self.read_inode(ino)?;
        let dir = inode.kind() == FileKind::Directory;
        if !self.is_inline(&inode) {
            self.truncate_blocks(&mut inode, 0)?;
        }
        let acl = inode.file_acl();
        if acl != 0 {
            let mut block = self.read_block(acl)?;
            let refs = if get32(&block, 0) == XATTR_MAGIC { get32(&block, 4) } else { 1 };
            if refs <= 1 {
                self.free_block(acl)?;
            } else {
                put32(&mut block, 4, refs - 1);
                self.write_block(acl, &block)?;
            }
            put32(&mut inode.raw, ino::FILE_ACL, 0);
            inode.add_sectors(-((self.block_size / 512) as i64));
        }
        // e2fsck reads a deletion time below the inode count as an orphan
        // list link, so without a clock pick one above it.
        let now = self.now().max(get32(&self.sb, sb::INODES_COUNT) + 1);
        inode.set_times(now, &[ino::DTIME]);
        inode.set_size(0);
        self.write_inode(ino, &inode)?;
        let per_group = get32(&self.sb, sb::INODES_PER_GROUP);
        let (g, i) = ((ino - 1) / per_group, (ino - 1) % per_group);
        let bitmap = self.group_field(g, gd::INODE_BITMAP);
        self.clear_bit(bitmap, i)?;
        self.adjust_group(g, gd::FREE_INODES, 1);
        self.adjust_super(sb::FREE_INODES, 1);
        if dir {
            self.adjust_group(g, gd::USED_DIRS, -1);
        }
        self.write_group(g)?;
        self.write_super()
    }

    fn group_of(&self, ino: u32) -> u32 {
        (ino - 1) / get32(&self.sb, sb::INODES_PER_GROUP)
    }

    // ---- Block maps ----

    /// Whether a symbolic link keeps its target in the block map's bytes.
    fn is_inline(&self, inode: &Inode) -> bool {
        let xattr = if inode.file_acl() != 0 { (self.block_size / 512) as u32 } else { 0 };
        inode.kind() == FileKind::Symlink && inode.sectors() == xattr
    }

    fn ptrs_per_block(&self) -> u64 {
        (self.block_size / 4) as u64
    }

    /// The physical block holding logical block `lblk`, 0 for a hole. With
    /// `alloc`, missing blocks (and indirect blocks) are allocated.
    fn bmap(&mut self, ino: u32, inode: &mut Inode, lblk: u64, alloc: bool) -> Result<u32, Errno> {
        if inode.flags() & EXTENTS_FL != 0 {
            return Err(Errno::EOPNOTSUPP);
        }
        let per = self.ptrs_per_block();
        let goal = self.group_of(ino);
        let sectors = (self.block_size / 512) as i64;
        // The slot in the inode, then indexes in each indirect level.
        let (slot, path): (usize, Vec<u64>) = if lblk < NDIR_BLOCKS as u64 {
            (lblk as usize, Vec::new())
        } else {
            let mut rest = lblk - NDIR_BLOCKS as u64;
            let mut found = None;
            let mut span = per;
            for depth in 1..=3u32 {
                if rest < span {
                    found = Some(depth);
                    break;
                }
                rest -= span;
                span = span.saturating_mul(per);
            }
            let depth = found.ok_or(Errno::EFBIG)?;
            let mut path = vec![0; depth as usize];
            for level in (0..depth as usize).rev() {
                path[level] = rest % per;
                rest /= per;
            }
            (NDIR_BLOCKS + depth as usize - 1, path)
        };
        let mut b = inode.block(slot);
        if b == 0 {
            if !alloc {
                return Ok(0);
            }
            b = self.alloc_block(goal)?;
            inode.set_block(slot, b);
            inode.add_sectors(sectors);
        }
        for &index in &path {
            let mut table = self.read_block(b)?;
            let mut next = get32(&table, index as usize * 4);
            if next == 0 {
                if !alloc {
                    return Ok(0);
                }
                next = self.alloc_block(goal)?;
                put32(&mut table, index as usize * 4, next);
                self.write_block(b, &table)?;
                inode.add_sectors(sectors);
            }
            b = next;
        }
        Ok(b)
    }

    /// Frees every block from logical block `keep` on.
    fn truncate_blocks(&mut self, inode: &mut Inode, keep: u64) -> Result<(), Errno> {
        let per = self.ptrs_per_block();
        let mut freed = 0u64;
        for i in 0..NDIR_BLOCKS {
            let b = inode.block(i);
            if b != 0 && i as u64 >= keep {
                self.free_block(b)?;
                inode.set_block(i, 0);
                freed += 1;
            }
        }
        let mut start = NDIR_BLOCKS as u64;
        let mut span = per;
        for depth in 1..=3u32 {
            let slot = NDIR_BLOCKS + depth as usize - 1;
            let b = inode.block(slot);
            if b != 0 && self.truncate_tree(b, depth, keep.saturating_sub(start), &mut freed)? {
                inode.set_block(slot, 0);
            }
            start = start.saturating_add(span);
            span = span.saturating_mul(per);
        }
        inode.add_sectors(-((freed * (self.block_size / 512) as u64) as i64));
        Ok(())
    }

    /// Frees the blocks below `b` (an indirect block of `depth`, or a data
    /// block at depth 0) from relative block `keep` on; returns whether `b`
    /// itself was freed.
    fn truncate_tree(&mut self, b: u32, depth: u32, keep: u64, freed: &mut u64) -> Result<bool, Errno> {
        if depth == 0 {
            if keep > 0 {
                return Ok(false);
            }
            self.free_block(b)?;
            *freed += 1;
            return Ok(true);
        }
        let per = self.ptrs_per_block();
        let span = per.pow(depth - 1);
        let mut table = self.read_block(b)?;
        let (mut changed, mut left) = (false, false);
        for i in 0..per as usize {
            let child = get32(&table, i * 4);
            if child == 0 {
                continue;
            }
            let child_keep = keep.saturating_sub(i as u64 * span);
            if child_keep >= span {
                left = true;
            } else if self.truncate_tree(child, depth - 1, child_keep, freed)? {
                put32(&mut table, i * 4, 0);
                changed = true;
            } else {
                left = true;
            }
        }
        if !left {
            self.free_block(b)?;
            *freed += 1;
            return Ok(true);
        }
        if changed {
            self.write_block(b, &table)?;
        }
        Ok(false)
    }

    // ---- Data ----

    fn read_data(&mut self, ino: u32, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let mut inode = self.read_inode(ino)?;
        let size = inode.size();
        if off >= size {
            return Ok(0);
        }
        let len = ((size - off) as usize).min(buf.len());
        if self.is_inline(&inode) {
            let start = ino::BLOCK + off as usize;
            buf[..len].copy_from_slice(&inode.raw[start..start + len]);
            return Ok(len);
        }
        let bs = self.block_size as u64;
        let mut done = 0;
        while done < len {
            let pos = off + done as u64;
            let skip = (pos % bs) as usize;
            let n = (bs as usize - skip).min(len - done);
            let b = self.bmap(ino, &mut inode, pos / bs, false)?;
            if b == 0 {
                buf[done..done + n].fill(0);
            } else {
                let block = self.read_block(b)?;
                buf[done..done + n].copy_from_slice(&block[skip..skip + n]);
            }
            done += n;
        }
        Ok(len)
    }

    fn write_data(&mut self, ino: u32, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        self.writable()?;
        let mut inode = self.read_inode(ino)?;
        let kind = inode.kind();
        if kind == FileKind::Directory {
            return Err(Errno::EISDIR);
        }
        if kind != FileKind::Regular && kind != FileKind::Symlink {
            return Err(Errno::EINVAL);
        }
        off.checked_add(buf.len() as u64).ok_or(Errno::EFBIG)?;
        if kind == FileKind::Symlink && inode.size() == 0 && off == 0 && buf.len() < 60 {
            // A fast symbolic link: the target lives in the block map.
            inode.raw[ino::BLOCK..ino::BLOCK + buf.len()].copy_from_slice(buf);
            inode.set_size(buf.len() as u64);
            self.write_inode(ino, &inode)?;
            return Ok(buf.len());
        }
        if self.is_inline(&inode) && inode.size() > 0 {
            return Err(Errno::EINVAL);
        }
        let bs = self.block_size as u64;
        let mut done = 0;
        let result = loop {
            if done == buf.len() {
                break Ok(());
            }
            let pos = off + done as u64;
            let skip = (pos % bs) as usize;
            let n = (bs as usize - skip).min(buf.len() - done);
            let b = match self.bmap(ino, &mut inode, pos / bs, true) {
                Ok(b) => b,
                Err(e) => break Err(e),
            };
            let step = if n == bs as usize {
                self.write_block(b, &buf[done..done + n])
            } else {
                self.read_block(b).and_then(|mut block| {
                    block[skip..skip + n].copy_from_slice(&buf[done..done + n]);
                    self.write_block(b, &block)
                })
            };
            if let Err(e) = step {
                break Err(e);
            }
            done += n;
        };
        let new_end = off + done as u64;
        if new_end > inode.size() {
            inode.set_size(new_end);
            if new_end > i32::MAX as u64 && get32(&self.sb, sb::FEATURE_RO_COMPAT) & RO_COMPAT_LARGE_FILE == 0 {
                let ro = get32(&self.sb, sb::FEATURE_RO_COMPAT) | RO_COMPAT_LARGE_FILE;
                put32(&mut self.sb, sb::FEATURE_RO_COMPAT, ro);
                self.write_super()?;
            }
        }
        let now = self.now();
        inode.set_times(now, &[ino::MTIME, ino::CTIME]);
        self.write_inode(ino, &inode)?;
        match result {
            // A partial write (out of space, say) reports what was written.
            Err(e) if done == 0 => Err(e),
            _ => Ok(done),
        }
    }

    fn truncate(&mut self, ino: u32, len: u64) -> Result<(), Errno> {
        self.writable()?;
        let mut inode = self.read_inode(ino)?;
        match inode.kind() {
            FileKind::Regular => {}
            FileKind::Directory => return Err(Errno::EISDIR),
            _ => return Err(Errno::EINVAL),
        }
        let bs = self.block_size as u64;
        if len < inode.size() {
            self.truncate_blocks(&mut inode, len.div_ceil(bs))?;
            // Zero the tail of the new last block, so that growing the file
            // again reads zeroes.
            if !len.is_multiple_of(bs) {
                let b = self.bmap(ino, &mut inode, len / bs, false)?;
                if b != 0 {
                    let mut block = self.read_block(b)?;
                    block[(len % bs) as usize..].fill(0);
                    self.write_block(b, &block)?;
                }
            }
        } else {
            // Check the size is reachable by the block map.
            if len > 0 {
                let last = (len - 1) / bs;
                let per = self.ptrs_per_block();
                if last >= NDIR_BLOCKS as u64 + per + per * per + per * per * per {
                    return Err(Errno::EFBIG);
                }
            }
        }
        inode.set_size(len);
        let now = self.now();
        inode.set_times(now, &[ino::MTIME, ino::CTIME]);
        self.write_inode(ino, &inode)
    }

    // ---- Directories ----

    /// Calls `f(block number within the directory, physical block, data)`
    /// for each of a directory's blocks until it returns `Some`.
    fn scan_dir<T>(
        &mut self,
        ino: u32,
        mut f: impl FnMut(&mut Self, u32, &mut Vec<u8>) -> Result<Option<T>, Errno>,
    ) -> Result<Option<T>, Errno> {
        let mut inode = self.read_inode(ino)?;
        if inode.kind() != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        let blocks = inode.size().div_ceil(self.block_size as u64);
        for lblk in 0..blocks {
            let b = self.bmap(ino, &mut inode, lblk, false)?;
            if b == 0 {
                continue;
            }
            let mut data = self.read_block(b)?;
            if let Some(found) = f(self, b, &mut data)? {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// Parses the record at `off`: (inode, rec_len, name).
    fn record<'b>(&self, data: &'b [u8], off: usize) -> Result<(u32, usize, &'b [u8]), Errno> {
        if off + 8 > data.len() {
            return Err(Errno::EIO);
        }
        let ino = get32(data, off);
        let rec_len = get16(data, off + 4) as usize;
        let name_len = if self.filetype { data[off + 6] as usize } else { get16(data, off + 6) as usize };
        if rec_len < 8 || off + rec_len > data.len() || 8 + name_len > rec_len {
            return Err(Errno::EIO);
        }
        Ok((ino, rec_len, &data[off + 8..off + 8 + name_len]))
    }

    fn find_entry(&mut self, dir: u32, name: &str) -> Result<Option<u32>, Errno> {
        self.scan_dir(dir, |fs, _, data| {
            let mut off = 0;
            while off < data.len() {
                let (ino, rec_len, entry) = fs.record(data, off)?;
                if ino != 0 && entry == name.as_bytes() {
                    return Ok(Some(ino));
                }
                off += rec_len;
            }
            Ok(None)
        })
    }

    fn dir_entry(&mut self, dir: u32, index: usize) -> Result<Option<DirEntry>, Errno> {
        let mut seen = 0;
        let found = self.scan_dir(dir, |fs, _, data| {
            let mut off = 0;
            while off < data.len() {
                let (ino, rec_len, name) = fs.record(data, off)?;
                off += rec_len;
                if ino == 0 || name == b"." || name == b".." {
                    continue;
                }
                if seen == index {
                    let name = String::from_utf8_lossy(name).into_owned();
                    let ftype = if fs.filetype { data[off - rec_len + 7] } else { 0 };
                    return Ok(Some((ino, name, ftype)));
                }
                seen += 1;
            }
            Ok(None)
        })?;
        let Some((ino, name, ftype)) = found else { return Ok(None) };
        let kind = match ftype {
            1 => FileKind::Regular,
            2 => FileKind::Directory,
            3 => FileKind::CharDevice,
            4 => FileKind::BlockDevice,
            5 => FileKind::Fifo,
            6 => FileKind::Socket,
            7 => FileKind::Symlink,
            _ => self.read_inode(ino)?.kind(),
        };
        Ok(Some(DirEntry { ino: ino as u64, kind, name }))
    }

    fn write_record(&self, data: &mut [u8], off: usize, ino: u32, rec_len: usize, name: &str, kind: FileKind) {
        put32(data, off, ino);
        put16(data, off + 4, rec_len as u16);
        if self.filetype {
            data[off + 6] = name.len() as u8;
            data[off + 7] = dirent_type(kind);
        } else {
            put16(data, off + 6, name.len() as u16);
        }
        data[off + 8..off + 8 + name.len()].copy_from_slice(name.as_bytes());
    }

    /// Clears a directory's hash index flag before changing it.
    fn drop_index(&mut self, dir: u32) -> Result<(), Errno> {
        let mut inode = self.read_inode(dir)?;
        let flags = inode.flags();
        if flags & INDEX_FL != 0 {
            put32(&mut inode.raw, ino::FLAGS, flags & !INDEX_FL);
            self.write_inode(dir, &inode)?;
        }
        Ok(())
    }

    fn add_entry(&mut self, dir: u32, name: &str, ino: u32, kind: FileKind) -> Result<(), Errno> {
        self.drop_index(dir)?;
        let need = rec_len_for(name.len());
        let placed = self.scan_dir(dir, |fs, b, data| {
            let mut off = 0;
            while off < data.len() {
                let (used_ino, rec_len, used_name) = fs.record(data, off)?;
                let used = if used_ino == 0 { 0 } else { rec_len_for(used_name.len()) };
                if rec_len - used >= need {
                    if used_ino == 0 {
                        fs.write_record(data, off, ino, rec_len, name, kind);
                    } else {
                        put16(data, off + 4, used as u16);
                        fs.write_record(data, off + used, ino, rec_len - used, name, kind);
                    }
                    fs.write_block(b, data)?;
                    return Ok(Some(()));
                }
                off += rec_len;
            }
            Ok(None)
        })?;
        if placed.is_some() {
            return Ok(());
        }
        // No room: append a block.
        let mut inode = self.read_inode(dir)?;
        let size = inode.size();
        let b = self.bmap(dir, &mut inode, size / self.block_size as u64, true)?;
        let mut data = vec![0; self.block_size];
        self.write_record(&mut data, 0, ino, self.block_size, name, kind);
        self.write_block(b, &data)?;
        inode.set_size(size + self.block_size as u64);
        self.write_inode(dir, &inode)
    }

    fn remove_entry(&mut self, dir: u32, name: &str) -> Result<(), Errno> {
        self.drop_index(dir)?;
        let removed = self.scan_dir(dir, |fs, b, data| {
            let (mut off, mut prev) = (0, None);
            while off < data.len() {
                let (ino, rec_len, entry) = fs.record(data, off)?;
                if ino != 0 && entry == name.as_bytes() {
                    match prev {
                        Some(p) => {
                            let merged = get16(data, p + 4) as usize + rec_len;
                            put16(data, p + 4, merged as u16);
                        }
                        None => put32(data, off, 0),
                    }
                    fs.write_block(b, data)?;
                    return Ok(Some(()));
                }
                prev = Some(off);
                off += rec_len;
            }
            Ok(None)
        })?;
        removed.ok_or(Errno::ENOENT)
    }

    fn is_empty_dir(&mut self, dir: u32) -> Result<bool, Errno> {
        Ok(self.dir_entry(dir, 0)?.is_none())
    }

    fn create(&mut self, dir: u32, name: &str, kind: FileKind, mode: u32) -> Result<u32, Errno> {
        self.writable()?;
        if name.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(Errno::EINVAL);
        }
        let parent = self.read_inode(dir)?;
        if parent.kind() != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        if parent.links() == 0 {
            // Creating in a removed directory.
            return Err(Errno::ENOENT);
        }
        if self.find_entry(dir, name)?.is_some() {
            return Err(Errno::EEXIST);
        }
        if kind == FileKind::Directory && parent.links() == u16::MAX {
            return Err(Errno::EMLINK);
        }
        let goal = if kind == FileKind::Directory { (dir + 1) % self.group_count } else { self.group_of(dir) };
        let (ino, mut inode) = self.alloc_inode(goal, kind.mode_bits() as u16 | (mode & 0o7777) as u16)?;
        if kind == FileKind::Directory {
            let b = match self.bmap(ino, &mut inode, 0, true) {
                Ok(b) => b,
                Err(e) => {
                    inode.set_links(0);
                    self.write_inode(ino, &inode)?;
                    self.free_inode(ino)?;
                    return Err(e);
                }
            };
            let mut data = vec![0; self.block_size];
            self.write_record(&mut data, 0, ino, 12, ".", FileKind::Directory);
            self.write_record(&mut data, 12, dir, self.block_size - 12, "..", FileKind::Directory);
            self.write_block(b, &data)?;
            inode.set_size(self.block_size as u64);
            inode.set_links(2);
            self.write_inode(ino, &inode)?;
        }
        if let Err(e) = self.add_entry(dir, name, ino, kind) {
            let mut inode = self.read_inode(ino)?;
            inode.set_links(0);
            self.write_inode(ino, &inode)?;
            self.free_inode(ino)?;
            return Err(e);
        }
        // Adding the entry may have grown the directory.
        let mut parent = self.read_inode(dir)?;
        if kind == FileKind::Directory {
            parent.set_links(parent.links() + 1);
        }
        let now = self.now();
        parent.set_times(now, &[ino::MTIME, ino::CTIME]);
        self.write_inode(dir, &parent)?;
        Ok(ino)
    }

    fn remove(&mut self, dir: u32, name: &str, want_dir: bool) -> Result<(), Errno> {
        self.writable()?;
        if name == "." || name == ".." {
            return Err(Errno::EINVAL);
        }
        let ino = self.find_entry(dir, name)?.ok_or(Errno::ENOENT)?;
        let mut inode = self.read_inode(ino)?;
        let is_dir = inode.kind() == FileKind::Directory;
        match (want_dir, is_dir) {
            (true, false) => return Err(Errno::ENOTDIR),
            (false, true) => return Err(Errno::EISDIR),
            (true, true) if !self.is_empty_dir(ino)? => return Err(Errno::ENOTEMPTY),
            _ => {}
        }
        self.remove_entry(dir, name)?;
        let now = self.now();
        let mut parent = self.read_inode(dir)?;
        if is_dir {
            parent.set_links(parent.links().saturating_sub(1));
            inode.set_links(0);
        } else {
            inode.set_links(inode.links().saturating_sub(1));
        }
        parent.set_times(now, &[ino::MTIME, ino::CTIME]);
        self.write_inode(dir, &parent)?;
        inode.set_times(now, &[ino::CTIME]);
        self.write_inode(ino, &inode)?;
        // An open file is freed when its last reference goes.
        let open = self.nodes.get(&ino).is_some_and(|w| w.strong_count() > 0);
        if inode.links() == 0 && !open {
            self.free_inode(ino)?;
        }
        Ok(())
    }

    fn stat(&mut self, ino: u32) -> Result<Stat, Errno> {
        let inode = self.read_inode(ino)?;
        let kind = inode.kind();
        let rdev = if matches!(kind, FileKind::CharDevice | FileKind::BlockDevice) {
            let (old, new) = (inode.block(0), inode.block(1));
            if old != 0 {
                makedev((old >> 8) & 0xff, old & 0xff)
            } else {
                makedev((new & 0xfff00) >> 8, (new & 0xff) | ((new >> 12) & 0xfff00))
            }
        } else {
            0
        };
        Ok(Stat {
            dev: self.st_dev,
            ino: ino as u64,
            kind,
            mode: (inode.mode() & 0o7777) as u32,
            nlink: inode.links() as u32,
            size: inode.size(),
            rdev,
        })
    }
}

impl<D: BlockDevice + Send + 'static> Node<D> {
    fn with<T>(&self, f: impl FnOnce(&mut Fs<D>) -> Result<T, Errno>) -> Result<T, Errno> {
        f(&mut self.shared.fs.lock())
    }
}

impl<D: BlockDevice + Send + 'static> File for Node<D> {
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        self.with(|fs| {
            if fs.read_inode(self.ino)?.kind() == FileKind::Directory {
                return Err(Errno::EISDIR);
            }
            fs.read_data(self.ino, off, buf)
        })
    }

    fn write(&self, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        self.with(|fs| fs.write_data(self.ino, off, buf))
    }

    fn stat(&self) -> Stat {
        // An I/O error leaves only what is known without the disk.
        self.with(|fs| fs.stat(self.ino)).unwrap_or(Stat { ino: self.ino as u64, ..Stat::default() })
    }

    fn truncate(&self, len: u64) -> Result<(), Errno> {
        self.with(|fs| fs.truncate(self.ino, len))
    }

    fn sync(&self) -> Result<(), Errno> {
        self.with(|fs| fs.dev.flush().map_err(io_error))
    }

    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        self.with(|fs| fs.dir_entry(self.ino, index))
    }

    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        let mut fs = self.shared.fs.lock();
        let ino = fs.find_entry(self.ino, name)?.ok_or(Errno::ENOENT)?;
        Ok(fs.node(&self.shared, ino))
    }

    fn create(&self, name: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
        let mut fs = self.shared.fs.lock();
        let ino = fs.create(self.ino, name, kind, mode)?;
        Ok(fs.node(&self.shared, ino))
    }

    fn remove(&self, name: &str, dir: bool) -> Result<(), Errno> {
        self.with(|fs| fs.remove(self.ino, name, dir))
    }

    fn readlink(&self) -> Result<String, Errno> {
        self.with(|fs| {
            let inode = fs.read_inode(self.ino)?;
            if inode.kind() != FileKind::Symlink {
                return Err(Errno::EINVAL);
            }
            let mut target = vec![0; inode.size() as usize];
            let n = fs.read_data(self.ino, 0, &mut target)?;
            target.truncate(n);
            String::from_utf8(target).map_err(|_| Errno::EINVAL)
        })
    }
}

impl<D: BlockDevice + Send + 'static> Drop for Node<D> {
    fn drop(&mut self) {
        let mut fs = self.shared.fs.lock();
        // Another lookup may have replaced the map entry with a live node.
        if fs.nodes.get(&self.ino).is_some_and(|w| w.strong_count() == 0) {
            fs.nodes.remove(&self.ino);
        } else {
            return;
        }
        if fs.read_only {
            return;
        }
        if let Ok(inode) = fs.read_inode(self.ino)
            && inode.links() == 0
            && inode.mode() != 0
            && get32(&inode.raw, ino::DTIME) == 0
        {
            // Nowhere to report an error from a drop.
            let _ = fs.free_inode(self.ino);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{OpenFlags, Vfs};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::{format, fs, string::ToString};

    struct VecDisk(Vec<u8>);

    impl BlockDevice for VecDisk {
        fn block_size(&self) -> usize {
            512
        }

        fn num_blocks(&self) -> u64 {
            (self.0.len() / 512) as u64
        }

        fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            self.check_range(lba, buf.len())?;
            let off = lba as usize * 512;
            buf.copy_from_slice(&self.0[off..off + buf.len()]);
            Ok(())
        }

        fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
            self.check_range(lba, buf.len())?;
            let off = lba as usize * 512;
            self.0[off..off + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    /// A scratch directory removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("osmium-ext2-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u32).wrapping_mul(2654435761).rotate_left(seed as u32) as u8).collect()
    }

    /// Runs `mkfs.<kind>` on a fresh image of `size` bytes, filled from
    /// `tree` if given; `None` if e2fsprogs is not installed.
    fn mkfs(scratch: &Scratch, kind: &str, block: usize, size: usize, tree: Option<&Path>) -> Option<Vec<u8>> {
        let img = scratch.0.join("image");
        fs::write(&img, vec![0u8; size]).unwrap();
        let mut cmd = Command::new(format!("mkfs.{kind}"));
        cmd.args(["-q", "-F", "-b", &block.to_string(), "-I", "256"]);
        if let Some(tree) = tree {
            cmd.arg("-d").arg(tree);
        }
        let Ok(status) = cmd.arg(&img).status() else {
            std::eprintln!("mkfs.{kind} not installed; skipping");
            return None;
        };
        assert!(status.success(), "mkfs.{kind} failed");
        Some(fs::read(&img).unwrap())
    }

    /// Checks the image with `e2fsck -fn`, and returns `debugfs`'s `cat` of
    /// each of `paths`.
    fn fsck(scratch: &Scratch, image: &[u8], paths: &[&str]) -> Vec<Vec<u8>> {
        let img = scratch.0.join("check");
        fs::write(&img, image).unwrap();
        let out = Command::new("e2fsck").arg("-fn").arg(&img).output().unwrap();
        assert!(
            out.status.success(),
            "e2fsck found errors:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        paths
            .iter()
            .map(|p| Command::new("debugfs").arg("-R").arg(format!("cat {p}")).arg(&img).output().unwrap().stdout)
            .collect()
    }

    fn read_all(file: &dyn File) -> Vec<u8> {
        let mut buf = vec![0; file.stat().size as usize];
        let n = file.read(0, &mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    fn names(dir: &dyn File) -> Vec<String> {
        (0..).map_while(|i| dir.readdir(i).unwrap()).map(|e| e.name).collect()
    }

    fn unmount(ext2: Ext2<VecDisk>) -> Vec<u8> {
        ext2.into_device().map_err(|(_, e)| e).unwrap().0
    }

    const LONG_TARGET: &str = "a/very/long/symbolic/link/target/that/does/not/fit/in/the/block/map/at/all";

    #[test]
    fn reads_mkfs_tree() {
        let scratch = Scratch::new("read");
        let tree = scratch.0.join("tree");
        fs::create_dir_all(tree.join("sub/deeper")).unwrap();
        fs::write(tree.join("small"), b"hello, ext2\n").unwrap();
        fs::write(tree.join("sub/big"), pattern(300_000, 3)).unwrap();
        fs::write(tree.join("empty"), b"").unwrap();
        std::os::unix::fs::symlink("sub/big", tree.join("fast")).unwrap();
        std::os::unix::fs::symlink(LONG_TARGET, tree.join("slow")).unwrap();
        for block in [1024, 4096] {
            let Some(image) = mkfs(&scratch, "ext2", block, 4 << 20, Some(&tree)) else { return };
            let ext2 = Ext2::mount(VecDisk(image), 7).unwrap();
            let root = ext2.root();
            let mut top = names(&*root);
            top.sort();
            assert_eq!(top, ["empty", "fast", "lost+found", "slow", "small", "sub"]);
            assert_eq!(read_all(&*root.lookup("small").unwrap()), b"hello, ext2\n");
            assert_eq!(read_all(&*root.lookup("sub").unwrap().lookup("big").unwrap()), pattern(300_000, 3));
            assert_eq!(root.lookup("empty").unwrap().stat().size, 0);
            assert_eq!(root.lookup("fast").unwrap().readlink().unwrap(), "sub/big");
            assert_eq!(root.lookup("slow").unwrap().readlink().unwrap(), LONG_TARGET);
            assert_eq!(root.lookup("nope").err(), Some(Errno::ENOENT));
            let st = root.lookup("sub").unwrap().stat();
            assert_eq!((st.kind, st.nlink, st.dev), (FileKind::Directory, 3, 7));
            assert_eq!(root.read(0, &mut [0; 4]).err(), Some(Errno::EISDIR));

            // Through the VFS, following the fast link.
            let vfs = Vfs::new(crate::RamFs::new(1).root());
            vfs.mkdir("/mnt", 0o755).unwrap();
            vfs.mount("/mnt", root).unwrap();
            let big = vfs.open("/mnt/fast", OpenFlags::READ, 0).unwrap();
            let mut buf = [0; 100];
            assert_eq!(big.read(299_950, &mut buf).unwrap(), 50);
            assert_eq!(buf[..50], pattern(300_000, 3)[299_950..]);
            assert_eq!(vfs.stat("/mnt/sub/deeper/..", true).unwrap().ino, st.ino);
        }
    }

    #[test]
    fn writes_pass_fsck() {
        let scratch = Scratch::new("write");
        for block in [1024, 4096] {
            let Some(image) = mkfs(&scratch, "ext2", block, 8 << 20, None) else { return };
            let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
            let vfs = Vfs::new(ext2.root());
            let rw = OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE;

            // Big enough for double-indirect blocks with 1 KiB blocks.
            let big = vfs.open("/big", rw, 0o644).unwrap();
            let data = pattern(700_000, 5);
            for (i, chunk) in data.chunks(65_000).enumerate() {
                assert_eq!(big.write(i as u64 * 65_000, chunk).unwrap(), chunk.len());
            }
            assert_eq!(read_all(&*big), data);

            // A sparse file and a partial overwrite.
            let sparse = vfs.open("/sparse", rw, 0o600).unwrap();
            sparse.write(5_000_000, b"tail").unwrap();
            sparse.write(10, b"head").unwrap();
            let mut buf = [0xff; 16];
            sparse.read(2_000_000, &mut buf).unwrap();
            assert_eq!(buf, [0; 16]);
            assert_eq!(sparse.stat().size, 5_000_004);

            vfs.mkdir("/a", 0o755).unwrap();
            vfs.mkdir("/a/b", 0o750).unwrap();
            vfs.open("/a/b/note", rw, 0o644).unwrap().write(0, b"nested").unwrap();
            vfs.symlink("/a/b/note", "/fast").unwrap();
            vfs.symlink(LONG_TARGET, "/slow").unwrap();
            assert_eq!(read_all(&*vfs.open("/fast", OpenFlags::READ, 0).unwrap()), b"nested");
            assert_eq!(vfs.readlink("/slow").unwrap(), LONG_TARGET);
            assert_eq!(vfs.stat("/a", true).unwrap().nlink, 3);

            // Enough names to need several directory blocks, then remove
            // every other one.
            vfs.mkdir("/many", 0o755).unwrap();
            for i in 0..300 {
                vfs.open(&format!("/many/entry-with-a-longish-name-{i:04}"), rw, 0o644).unwrap();
            }
            for i in (0..300).step_by(2) {
                vfs.unlink(&format!("/many/entry-with-a-longish-name-{i:04}")).unwrap();
            }
            assert_eq!(names(&*vfs.lookup("/many").unwrap()).len(), 150);
            vfs.open("/many/reused", rw, 0o644).unwrap();

            // Truncation within a block, then growing again reads zeroes.
            let t = vfs.open("/trunc", rw, 0o644).unwrap();
            t.write(0, &pattern(5000, 1)).unwrap();
            t.truncate(1500).unwrap();
            t.truncate(3000).unwrap();
            let got = read_all(&*t);
            assert_eq!(got[..1500], pattern(5000, 1)[..1500]);
            assert!(got[1500..].iter().all(|&b| b == 0));
            big.truncate(100_000).unwrap();

            assert_eq!(vfs.rmdir("/a").err(), Some(Errno::ENOTEMPTY));
            vfs.mkdir("/gone", 0o755).unwrap();
            vfs.rmdir("/gone").unwrap();
            assert_eq!(vfs.unlink("/a").err(), Some(Errno::EISDIR));
            assert_eq!(vfs.mkdir("/a", 0o755).err(), Some(Errno::EEXIST));
            drop((big, sparse, t, vfs));

            let image = unmount(ext2);
            let cats = fsck(&scratch, &image, &["/big", "/a/b/note", "/trunc"]);
            assert_eq!(cats[0], data[..100_000]);
            assert_eq!(cats[1], b"nested");
            assert_eq!(cats[2].len(), 3000);

            // Everything is still there after mounting again.
            let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
            let vfs = Vfs::new(ext2.root());
            assert_eq!(read_all(&*vfs.lookup("/sparse").unwrap())[10..14], *b"head");
            assert!(vfs.lookup("/many/entry-with-a-longish-name-0001").is_ok());
            assert_eq!(vfs.lookup("/many/entry-with-a-longish-name-0000").err(), Some(Errno::ENOENT));
        }
    }

    #[test]
    fn changes_large_directory() {
        let scratch = Scratch::new("large");
        let tree = scratch.0.join("tree");
        fs::create_dir_all(tree.join("big")).unwrap();
        for i in 0..2000 {
            fs::write(tree.join(format!("big/file-{i}")), format!("{i}")).unwrap();
        }
        let Some(image) = mkfs(&scratch, "ext2", 1024, 16 << 20, Some(&tree)) else { return };
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        let vfs = Vfs::new(ext2.root());
        assert_eq!(names(&*vfs.lookup("/big").unwrap()).len(), 2000);
        assert_eq!(read_all(&*vfs.lookup("/big/file-1234").unwrap()), b"1234");
        for i in (0..2000).step_by(3) {
            vfs.unlink(&format!("/big/file-{i}")).unwrap();
        }
        vfs.open("/big/new", OpenFlags::CREATE, 0o644).unwrap();
        drop(vfs);
        let image = unmount(ext2);
        assert_eq!(fsck(&scratch, &image, &["/big/file-1999"])[0], b"1999");
    }

    #[test]
    fn unlinked_open_file_is_freed_on_drop() {
        let scratch = Scratch::new("orphan");
        let Some(image) = mkfs(&scratch, "ext2", 1024, 2 << 20, None) else { return };
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        let free = |e: &Ext2<VecDisk>| {
            let fs = e.shared.fs.lock();
            (get32(&fs.sb, sb::FREE_BLOCKS), get32(&fs.sb, sb::FREE_INODES))
        };
        let before = free(&ext2);
        let vfs = Vfs::new(ext2.root());
        let f = vfs.open("/orphan", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
        f.write(0, &pattern(50_000, 2)).unwrap();
        vfs.unlink("/orphan").unwrap();
        assert_eq!(f.stat().nlink, 0);
        assert_eq!(read_all(&*f), pattern(50_000, 2));
        assert_ne!(free(&ext2), before);
        drop(f);
        assert_eq!(free(&ext2), before);
        drop(vfs);
        fsck(&scratch, &unmount(ext2), &[]);
    }

    #[test]
    fn full_disk() {
        let scratch = Scratch::new("full");
        let Some(image) = mkfs(&scratch, "ext2", 1024, 1 << 20, None) else { return };
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        let vfs = Vfs::new(ext2.root());
        let f = vfs.open("/fill", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
        let chunk = vec![0xa5; 64 * 1024];
        let mut total = 0;
        loop {
            match f.write(total, &chunk) {
                Ok(n) if n == chunk.len() => total += n as u64,
                Ok(n) => {
                    total += n as u64;
                    assert_eq!(f.write(total, &chunk).err(), Some(Errno::ENOSPC));
                    break;
                }
                Err(e) => {
                    assert_eq!(e, Errno::ENOSPC);
                    break;
                }
            }
        }
        assert!(total > 500_000, "only {total} bytes fit");
        assert_eq!(f.stat().size, total);
        drop((f, vfs));
        fsck(&scratch, &unmount(ext2), &[]);
    }

    #[test]
    fn refuses_ext4_and_garbage() {
        let scratch = Scratch::new("ext4");
        let Some(image) = mkfs(&scratch, "ext4", 1024, 2 << 20, None) else { return };
        assert_eq!(Ext2::mount(VecDisk(image), 1).err(), Some(Errno::ENOSYS));
        assert_eq!(Ext2::mount(VecDisk(vec![0; 64 * 1024]), 1).err(), Some(Errno::EINVAL));
    }
}
