//! The second extended file system and its successors ext3 and ext4, read
//! and write, over any [`BlockDevice`].
//!
//! Supported: revisions 0 and 1, block sizes from 1 KiB to 32 KiB, any inode
//! size, direct and indirect block maps, extent trees, sparse files, fast and
//! slow symbolic links, and the `filetype`, `sparse_super`, `sparse_super2`,
//! `large_file`, `meta_bg`, `extent`, `64bit`, `flex_bg`, `uninit_bg`, `metadata_csum`,
//! `metadata_csum_seed`, `huge_file`, `dir_nlink` and `extra_isize`
//! features. With `extent`, new files get extent trees; uninitialized
//! (preallocated) extents read as zeroes and are split as they are written.
//! Every checksum is verified on read and kept current on write.
//!
//! A journal is left alone. A clean one is fine, since each change is
//! written in place, but one that needs recovery is refused, as are the
//! other incompatible features (`inline_data`, `largedir`,
//! `ea_inode`, encryption, casefolding, compression). A file system with an
//! unknown read-only feature (`quota`, `bigalloc`, ...) mounts read-only.
//! Hashed directory indexes are ignored for lookup and dropped (the flag is
//! cleared) when a directory changes, as Linux's ext2 driver does; with
//! `metadata_csum` the index blocks become empty, checksummed directory
//! blocks.
//!
//! All state lives behind one spin lock held across device I/O, and there is
//! no block cache: simple and correct, not fast. Nothing is journaled; call
//! [`File::sync`] to flush the device.

mod csum;
mod extent;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use osmium_hal::block::{BlockDevice, BlockError};
use osmium_sync::SpinLock;

use crate::dev::makedev;
use crate::{DirEntry, Errno, File, FileKind, NAME_MAX, Stat};
use csum::{crc16, crc32c};

const MAGIC: u16 = 0xef53;
const ROOT_INO: u32 = 2;
const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_LEN: usize = 1024;
const NDIR_BLOCKS: usize = 12;
/// The most subdirectories' `..` links a directory counts; past it, with
/// `dir_nlink`, the count stays at 1.
const LINK_MAX: u16 = 65000;

const COMPAT_SPARSE_SUPER2: u32 = 0x0200;
const INCOMPAT_FILETYPE: u32 = 0x0002;
const INCOMPAT_META_BG: u32 = 0x0010;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_FLEX_BG: u32 = 0x0200;
const INCOMPAT_CSUM_SEED: u32 = 0x2000;
const INCOMPAT_SUPPORTED: u32 =
    INCOMPAT_FILETYPE | INCOMPAT_META_BG | INCOMPAT_EXTENTS | INCOMPAT_64BIT | INCOMPAT_FLEX_BG | INCOMPAT_CSUM_SEED;
const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;
const RO_COMPAT_LARGE_FILE: u32 = 0x0002;
const RO_COMPAT_BTREE_DIR: u32 = 0x0004;
const RO_COMPAT_HUGE_FILE: u32 = 0x0008;
const RO_COMPAT_GDT_CSUM: u32 = 0x0010;
const RO_COMPAT_DIR_NLINK: u32 = 0x0020;
const RO_COMPAT_EXTRA_ISIZE: u32 = 0x0040;
const RO_COMPAT_METADATA_CSUM: u32 = 0x0400;
const RO_COMPAT_SUPPORTED: u32 = RO_COMPAT_SPARSE_SUPER
    | RO_COMPAT_LARGE_FILE
    | RO_COMPAT_BTREE_DIR
    | RO_COMPAT_HUGE_FILE
    | RO_COMPAT_GDT_CSUM
    | RO_COMPAT_DIR_NLINK
    | RO_COMPAT_EXTRA_ISIZE
    | RO_COMPAT_METADATA_CSUM;

/// Inode flags.
const INDEX_FL: u32 = 0x1000;
const HUGE_FILE_FL: u32 = 0x4_0000;
const EXTENTS_FL: u32 = 0x8_0000;

/// Group descriptor flags: the inode or block bitmap was never written and
/// reads as empty (apart from the group's own metadata).
const BG_INODE_UNINIT: u16 = 0x0001;
const BG_BLOCK_UNINIT: u16 = 0x0002;

/// Extended attribute block header magic.
const XATTR_MAGIC: u32 = 0xea02_0000;

/// The fake directory entry at the end of a checksummed directory block.
const DIR_TAIL_LEN: usize = 12;
const DIR_TAIL_TYPE: u8 = 0xde;

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
    pub const FEATURE_COMPAT: usize = 92;
    pub const FEATURE_INCOMPAT: usize = 96;
    pub const FEATURE_RO_COMPAT: usize = 100;
    pub const UUID: usize = 0x68;
    pub const RESERVED_GDT_BLOCKS: usize = 0xce;
    pub const DESC_SIZE: usize = 0xfe;
    pub const FIRST_META_BG: usize = 0x104;
    pub const BLOCKS_COUNT_HI: usize = 0x150;
    pub const FREE_BLOCKS_HI: usize = 0x158;
    pub const WANT_EXTRA_ISIZE: usize = 0x15e;
    pub const CHECKSUM_TYPE: usize = 0x175;
    pub const BACKUP_BGS: usize = 0x24c;
    pub const CHECKSUM_SEED: usize = 0x270;
    pub const CHECKSUM: usize = 0x3fc;
}

/// Group descriptor field offsets.
mod gd {
    /// A field's low half, its high half (in 64-byte descriptors) and the
    /// width of each half in bytes.
    pub type Field = (usize, usize, usize);
    pub const BLOCK_BITMAP: Field = (0x00, 0x20, 4);
    pub const INODE_BITMAP: Field = (0x04, 0x24, 4);
    pub const INODE_TABLE: Field = (0x08, 0x28, 4);
    pub const FREE_BLOCKS: Field = (0x0c, 0x2c, 2);
    pub const FREE_INODES: Field = (0x0e, 0x2e, 2);
    pub const USED_DIRS: Field = (0x10, 0x30, 2);
    pub const BLOCK_BITMAP_CSUM: Field = (0x18, 0x38, 2);
    pub const INODE_BITMAP_CSUM: Field = (0x1a, 0x3a, 2);
    pub const ITABLE_UNUSED: Field = (0x1c, 0x32, 2);
    pub const FLAGS: usize = 0x12;
    pub const CHECKSUM: usize = 0x1e;
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
    pub const GENERATION: usize = 100;
    pub const FILE_ACL: usize = 104;
    pub const SIZE_HIGH: usize = 108;
    pub const BLOCKS_HIGH: usize = 0x74;
    pub const FILE_ACL_HIGH: usize = 0x76;
    pub const CHECKSUM_LO: usize = 0x7c;
    pub const EXTRA_ISIZE: usize = 128;
    pub const CHECKSUM_HI: usize = 0x82;
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

/// Sets `count` bits from `start` in a bitmap.
fn set_bits(bits: &mut [u8], start: usize, count: usize) {
    for i in start..start + count {
        bits[i / 8] |= 1 << (i % 8);
    }
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

    fn set_flags(&mut self, flags: u32) {
        put32(&mut self.raw, ino::FLAGS, flags);
    }

    fn generation(&self) -> u32 {
        get32(&self.raw, ino::GENERATION)
    }

    fn block(&self, i: usize) -> u32 {
        get32(&self.raw, ino::BLOCK + 4 * i)
    }

    fn set_block(&mut self, i: usize, b: u32) {
        put32(&mut self.raw, ino::BLOCK + 4 * i, b);
    }

    /// Allocated 512-byte sectors, including indirect, extent tree and
    /// xattr blocks. The high 16 bits are `huge_file`'s; ext2 leaves them
    /// zero.
    fn sectors(&self) -> u64 {
        (get16(&self.raw, ino::BLOCKS_HIGH) as u64) << 32 | get32(&self.raw, ino::BLOCKS) as u64
    }

    fn add_sectors(&mut self, delta: i64) {
        let v = (self.sectors() as i64 + delta).max(0) as u64;
        put32(&mut self.raw, ino::BLOCKS, v as u32);
        put16(&mut self.raw, ino::BLOCKS_HIGH, (v >> 32) as u16);
    }

    fn file_acl(&self) -> u64 {
        (get16(&self.raw, ino::FILE_ACL_HIGH) as u64) << 32 | get32(&self.raw, ino::FILE_ACL) as u64
    }

    fn set_times(&mut self, now: u32, fields: &[usize]) {
        for &f in fields {
            put32(&mut self.raw, f, now);
        }
    }

    /// Whether `i_extra_isize` covers the high half of the checksum.
    fn has_checksum_hi(&self) -> bool {
        self.raw.len() > 128 && get16(&self.raw, ino::EXTRA_ISIZE) >= 4
    }
}

/// Which checksums the file system keeps.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Csum {
    None,
    /// `uninit_bg`: CRC16 over group descriptors only.
    Crc16,
    /// `metadata_csum`: CRC32C over every metadata block.
    Crc32c,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bitmap {
    Block,
    Inode,
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
    desc_size: usize,
    /// Block of the primary group descriptor table.
    gdt_block: u64,
    /// Under `meta_bg`, the first descriptor block kept in its own meta
    /// group rather than in the primary table.
    first_meta_bg: Option<u32>,
    inode_size: usize,
    first_ino: u32,
    filetype: bool,
    /// `64bit`: block counts and numbers have high halves.
    wide: bool,
    extents: bool,
    dir_nlink: bool,
    csum: Csum,
    /// The CRC32C seed every `metadata_csum` checksum starts from.
    csum_seed: u32,
    read_only: bool,
    clock: fn() -> u32,
    /// One node per in-use inode, so an unlinked file is freed when its
    /// last reference goes.
    nodes: BTreeMap<u32, Weak<Node<D>>>,
    st_dev: u64,
}

/// An ext2, ext3 or ext4 file system on a block device.
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
    /// Mounts the ext2, ext3 or ext4 file system on `dev`, reporting
    /// `st_dev` as `devno`. Fails with `EINVAL` if `dev` holds no such file
    /// system (or its superblock or group descriptors fail their checksums)
    /// and `ENOSYS` for unsupported features, including a journal that needs
    /// recovery.
    pub fn mount(dev: D, devno: u64) -> Result<Self, Errno> {
        let dev_bs = dev.block_size();
        let mut fs = Fs {
            dev,
            dev_per_block: 1,
            block_size: dev_bs,
            sb: vec![0; SUPERBLOCK_LEN],
            groups: Vec::new(),
            group_count: 0,
            desc_size: 32,
            gdt_block: 0,
            first_meta_bg: None,
            inode_size: 128,
            first_ino: 11,
            filetype: false,
            wide: false,
            extents: false,
            dir_nlink: false,
            csum: Csum::None,
            csum_seed: 0,
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
            if incompat & INCOMPAT_META_BG != 0 {
                fs.first_meta_bg = Some(get32(&fs.sb, sb::FIRST_META_BG));
            }
            fs.extents = incompat & INCOMPAT_EXTENTS != 0;
            fs.wide = incompat & INCOMPAT_64BIT != 0;
            if fs.wide {
                fs.desc_size = get16(&fs.sb, sb::DESC_SIZE) as usize;
                if fs.desc_size < 64 || !fs.desc_size.is_power_of_two() || fs.desc_size > fs.block_size {
                    return Err(Errno::EINVAL);
                }
            }
            let ro = get32(&fs.sb, sb::FEATURE_RO_COMPAT);
            fs.read_only = ro & !RO_COMPAT_SUPPORTED != 0;
            fs.dir_nlink = ro & RO_COMPAT_DIR_NLINK != 0;
            if ro & RO_COMPAT_METADATA_CSUM != 0 {
                // 1 is CRC32C, the only type there is.
                if fs.sb[sb::CHECKSUM_TYPE] != 1 {
                    return Err(Errno::ENOSYS);
                }
                if get32(&fs.sb, sb::CHECKSUM) != crc32c(!0, &fs.sb[..sb::CHECKSUM]) {
                    return Err(Errno::EINVAL);
                }
                fs.csum = Csum::Crc32c;
                fs.csum_seed = if incompat & INCOMPAT_CSUM_SEED != 0 {
                    get32(&fs.sb, sb::CHECKSUM_SEED)
                } else {
                    crc32c(!0, &fs.sb[sb::UUID..sb::UUID + 16])
                };
            } else if ro & RO_COMPAT_GDT_CSUM != 0 {
                fs.csum = Csum::Crc16;
            }
        }
        let per_group = get32(&fs.sb, sb::BLOCKS_PER_GROUP);
        let inodes_per_group = get32(&fs.sb, sb::INODES_PER_GROUP);
        let blocks = fs.blocks_count();
        let first = get32(&fs.sb, sb::FIRST_DATA_BLOCK) as u64;
        if fs.inode_size < 128 || !fs.inode_size.is_power_of_two() || fs.inode_size > fs.block_size {
            return Err(Errno::EINVAL);
        }
        if per_group == 0 || inodes_per_group == 0 || blocks <= first || per_group as usize > 8 * fs.block_size {
            return Err(Errno::EINVAL);
        }
        let groups = (blocks - first).div_ceil(per_group as u64);
        if get32(&fs.sb, sb::INODES_COUNT) as u64 != groups * inodes_per_group as u64 {
            return Err(Errno::EINVAL);
        }
        fs.group_count = groups as u32;
        fs.gdt_block = first + 1;
        fs.groups = vec![0; fs.group_count as usize * fs.desc_size];
        // A descriptor block at a time, since `meta_bg` scatters them.
        let per_block = (fs.block_size / fs.desc_size) as u32;
        for first in (0..fs.group_count).step_by(per_block as usize) {
            let n = per_block.min(fs.group_count - first) as usize * fs.desc_size;
            let mut descs = vec![0; n];
            fs.read_bytes(fs.desc_offset(first), &mut descs)?;
            let start = first as usize * fs.desc_size;
            fs.groups[start..start + n].copy_from_slice(&descs);
        }
        if fs.csum != Csum::None && (0..fs.group_count).any(|g| fs.group_csum(g) != get16(fs.desc(g), gd::CHECKSUM)) {
            return Err(Errno::EINVAL);
        }
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

    fn read_block(&mut self, b: u64) -> Result<Vec<u8>, Errno> {
        if b == 0 || b >= self.blocks_count() {
            return Err(Errno::EIO);
        }
        let mut buf = vec![0; self.block_size];
        self.dev.read_blocks(b * self.dev_per_block, &mut buf).map_err(io_error)?;
        Ok(buf)
    }

    fn write_block(&mut self, b: u64, buf: &[u8]) -> Result<(), Errno> {
        if b == 0 || b >= self.blocks_count() {
            return Err(Errno::EIO);
        }
        self.dev.write_blocks(b * self.dev_per_block, buf).map_err(io_error)
    }

    // ---- Superblock and group descriptors ----

    /// A superblock count with a high half under `64bit`.
    fn sb_wide(&self, lo: usize, hi: usize) -> u64 {
        let high = if self.wide { get32(&self.sb, hi) } else { 0 };
        (high as u64) << 32 | get32(&self.sb, lo) as u64
    }

    fn blocks_count(&self) -> u64 {
        self.sb_wide(sb::BLOCKS_COUNT, sb::BLOCKS_COUNT_HI)
    }

    fn free_blocks(&self) -> u64 {
        self.sb_wide(sb::FREE_BLOCKS, sb::FREE_BLOCKS_HI)
    }

    fn adjust_free_blocks(&mut self, delta: i64) {
        let v = (self.free_blocks() as i64 + delta) as u64;
        put32(&mut self.sb, sb::FREE_BLOCKS, v as u32);
        if self.wide {
            put32(&mut self.sb, sb::FREE_BLOCKS_HI, (v >> 32) as u32);
        }
    }

    fn adjust_super(&mut self, field: usize, delta: i32) {
        let v = get32(&self.sb, field) as i64 + delta as i64;
        put32(&mut self.sb, field, v as u32);
    }

    fn write_super(&mut self) -> Result<(), Errno> {
        let now = self.now();
        put32(&mut self.sb, sb::WTIME, now);
        if self.csum == Csum::Crc32c {
            let sum = crc32c(!0, &self.sb[..sb::CHECKSUM]);
            put32(&mut self.sb, sb::CHECKSUM, sum);
        }
        let sbuf = core::mem::take(&mut self.sb);
        let result = self.write_bytes(SUPERBLOCK_OFFSET, &sbuf);
        self.sb = sbuf;
        result
    }

    fn desc(&self, g: u32) -> &[u8] {
        let start = g as usize * self.desc_size;
        &self.groups[start..start + self.desc_size]
    }

    fn group_csum(&self, g: u32) -> u16 {
        let d = self.desc(g);
        let rest = &d[gd::CHECKSUM + 2..];
        match self.csum {
            Csum::None => 0,
            Csum::Crc16 => {
                let mut crc = crc16(!0, &self.sb[sb::UUID..sb::UUID + 16]);
                crc = crc16(crc, &g.to_le_bytes());
                crc = crc16(crc, &d[..gd::CHECKSUM]);
                crc16(crc, rest)
            }
            Csum::Crc32c => {
                let mut crc = crc32c(self.csum_seed, &g.to_le_bytes());
                crc = crc32c(crc, &d[..gd::CHECKSUM]);
                crc = crc32c(crc, &[0, 0]);
                crc32c(crc, rest) as u16
            }
        }
    }

    fn write_group(&mut self, g: u32) -> Result<(), Errno> {
        let start = g as usize * self.desc_size;
        if self.csum != Csum::None {
            let sum = self.group_csum(g);
            put16(&mut self.groups, start + gd::CHECKSUM, sum);
        }
        let desc: Vec<u8> = self.desc(g).to_vec();
        self.write_bytes(self.desc_offset(g), &desc)
    }

    /// The byte offset of group `g`'s descriptor.
    fn desc_offset(&self, g: u32) -> u64 {
        let per_block = (self.block_size / self.desc_size) as u32;
        let (k, i) = (g / per_block, g % per_block);
        let block = match self.first_meta_bg {
            Some(first) if k >= first => {
                // In the first group of its meta group, after any
                // superblock backup.
                let lead = k * per_block;
                self.group_start(lead) + self.has_super(lead) as u64
            }
            _ => self.gdt_block + k as u64,
        };
        block * self.block_size as u64 + (i as usize * self.desc_size) as u64
    }

    /// Blocks at the start of group `g` holding a superblock backup and
    /// descriptor blocks (with their reserve), as e2fsprogs lays them out.
    fn base_meta_blocks(&self, g: u32) -> u64 {
        let has_super = self.has_super(g) as u64;
        let per_block = (self.block_size / self.desc_size) as u32;
        match self.first_meta_bg {
            Some(first) if g / per_block >= first => {
                let i = g % per_block;
                has_super + (i == 0 || i == 1 || i == per_block - 1) as u64
            }
            _ if has_super == 0 => 0,
            Some(first) => 1 + first as u64,
            None => {
                let gdt = (self.group_count as usize * self.desc_size).div_ceil(self.block_size) as u64;
                1 + gdt + get16(&self.sb, sb::RESERVED_GDT_BLOCKS) as u64
            }
        }
    }

    fn group_get(&self, g: u32, (lo, hi, width): gd::Field) -> u64 {
        let d = self.desc(g);
        let get = |off| if width == 4 { get32(d, off) as u64 } else { get16(d, off) as u64 };
        let high = if hi + width <= self.desc_size { get(hi) } else { 0 };
        high << (8 * width) | get(lo)
    }

    fn group_set(&mut self, g: u32, (lo, hi, width): gd::Field, v: u64) {
        let start = g as usize * self.desc_size;
        let d = &mut self.groups[start..start + self.desc_size];
        let mut put = |off, v: u64| if width == 4 { put32(d, off, v as u32) } else { put16(d, off, v as u16) };
        put(lo, v);
        if hi + width <= self.desc_size {
            put(hi, v >> (8 * width));
        }
    }

    fn adjust_group(&mut self, g: u32, field: gd::Field, delta: i64) {
        let v = (self.group_get(g, field) as i64 + delta) as u64;
        self.group_set(g, field, v);
    }

    fn group_flags(&self, g: u32) -> u16 {
        get16(self.desc(g), gd::FLAGS)
    }

    fn set_group_flags(&mut self, g: u32, flags: u16) {
        put16(&mut self.groups, g as usize * self.desc_size + gd::FLAGS, flags);
    }

    fn group_start(&self, g: u32) -> u64 {
        get32(&self.sb, sb::FIRST_DATA_BLOCK) as u64 + g as u64 * get32(&self.sb, sb::BLOCKS_PER_GROUP) as u64
    }

    /// Blocks in group `g`: all but the last group are full.
    fn group_blocks(&self, g: u32) -> u64 {
        (get32(&self.sb, sb::BLOCKS_PER_GROUP) as u64).min(self.blocks_count() - self.group_start(g))
    }

    /// Whether group `g` holds a superblock backup and descriptor table.
    fn has_super(&self, g: u32) -> bool {
        if g == 0 {
            return true;
        }
        if get32(&self.sb, sb::FEATURE_COMPAT) & COMPAT_SPARSE_SUPER2 != 0 {
            return g == get32(&self.sb, sb::BACKUP_BGS) || g == get32(&self.sb, sb::BACKUP_BGS + 4);
        }
        if get32(&self.sb, sb::FEATURE_RO_COMPAT) & RO_COMPAT_SPARSE_SUPER == 0 {
            return true;
        }
        let power_of = |base: u32| {
            let mut n = 1;
            while n < g {
                n *= base;
            }
            n == g
        };
        g == 1 || power_of(3) || power_of(5) || power_of(7)
    }

    // ---- Checksums ----

    /// The seed of an inode's own checksums (inode, extent tree,
    /// directory blocks).
    fn inode_seed(&self, ino: u32, inode: &Inode) -> u32 {
        crc32c(crc32c(self.csum_seed, &ino.to_le_bytes()), &inode.generation().to_le_bytes())
    }

    fn inode_csum(&self, ino: u32, inode: &Inode) -> u32 {
        let mut raw = inode.raw.clone();
        put16(&mut raw, ino::CHECKSUM_LO, 0);
        if inode.has_checksum_hi() {
            put16(&mut raw, ino::CHECKSUM_HI, 0);
        }
        crc32c(self.inode_seed(ino, inode), &raw)
    }

    fn bitmap_csum(&self, kind: Bitmap, bits: &[u8]) -> u32 {
        let per_group = match kind {
            Bitmap::Block => get32(&self.sb, sb::BLOCKS_PER_GROUP),
            Bitmap::Inode => get32(&self.sb, sb::INODES_PER_GROUP),
        };
        crc32c(self.csum_seed, &bits[..per_group as usize / 8])
    }

    /// Whether a directory block ends in a checksum tail.
    fn has_dir_tail(&self, data: &[u8]) -> bool {
        let t = data.len() - DIR_TAIL_LEN;
        self.csum == Csum::Crc32c
            && get32(data, t) == 0
            && get16(data, t + 4) as usize == DIR_TAIL_LEN
            && data[t + 6] == 0
            && data[t + 7] == DIR_TAIL_TYPE
    }

    /// The bytes of a directory block that hold records.
    fn dir_space(&self, data: &[u8]) -> usize {
        if self.has_dir_tail(data) { data.len() - DIR_TAIL_LEN } else { data.len() }
    }

    /// A new, empty directory block and the bytes free for records in it.
    fn new_dir_block(&self) -> (Vec<u8>, usize) {
        let mut data = vec![0; self.block_size];
        if self.csum != Csum::Crc32c {
            return (data, self.block_size);
        }
        let t = self.block_size - DIR_TAIL_LEN;
        put16(&mut data, t + 4, DIR_TAIL_LEN as u16);
        data[t + 7] = DIR_TAIL_TYPE;
        (data, t)
    }

    /// Writes a block of directory `dir`, checksumming its tail.
    fn write_dir_block(&mut self, dir: u32, b: u64, data: &mut [u8]) -> Result<(), Errno> {
        if self.has_dir_tail(data) {
            let inode = self.read_inode(dir)?;
            let seed = self.inode_seed(dir, &inode);
            let t = data.len() - DIR_TAIL_LEN;
            let sum = crc32c(seed, &data[..t]);
            put32(data, t + 8, sum);
        }
        self.write_block(b, data)
    }

    // ---- Inodes ----

    fn inode_offset(&self, ino: u32) -> Result<u64, Errno> {
        if ino == 0 || ino > get32(&self.sb, sb::INODES_COUNT) {
            return Err(Errno::EIO);
        }
        let per_group = get32(&self.sb, sb::INODES_PER_GROUP);
        let (g, i) = ((ino - 1) / per_group, (ino - 1) % per_group);
        let table = self.group_get(g, gd::INODE_TABLE);
        Ok(table * self.block_size as u64 + i as u64 * self.inode_size as u64)
    }

    fn read_inode(&mut self, ino: u32) -> Result<Inode, Errno> {
        let off = self.inode_offset(ino)?;
        let mut raw = vec![0; self.inode_size];
        self.read_bytes(off, &mut raw)?;
        let inode = Inode { raw };
        if self.csum == Csum::Crc32c {
            let sum = self.inode_csum(ino, &inode);
            let lo = get16(&inode.raw, ino::CHECKSUM_LO) as u32;
            let stored =
                if inode.has_checksum_hi() { (get16(&inode.raw, ino::CHECKSUM_HI) as u32) << 16 | lo } else { lo };
            let mask = if inode.has_checksum_hi() { u32::MAX } else { 0xffff };
            if sum & mask != stored {
                return Err(Errno::EIO);
            }
        }
        Ok(inode)
    }

    fn write_inode(&mut self, ino: u32, inode: &Inode) -> Result<(), Errno> {
        let off = self.inode_offset(ino)?;
        if self.csum != Csum::Crc32c {
            return self.write_bytes(off, &inode.raw);
        }
        let sum = self.inode_csum(ino, inode);
        let mut raw = inode.raw.clone();
        put16(&mut raw, ino::CHECKSUM_LO, sum as u16);
        if inode.has_checksum_hi() {
            put16(&mut raw, ino::CHECKSUM_HI, (sum >> 16) as u16);
        }
        self.write_bytes(off, &raw)
    }

    // ---- Allocation ----

    /// A group's bitmap. An uninitialized one is built: empty but for the
    /// padding past the group's end and, for blocks, the metadata in it.
    fn load_bitmap(&mut self, g: u32, kind: Bitmap) -> Result<Vec<u8>, Errno> {
        let (loc, csum, flag) = match kind {
            Bitmap::Block => (gd::BLOCK_BITMAP, gd::BLOCK_BITMAP_CSUM, BG_BLOCK_UNINIT),
            Bitmap::Inode => (gd::INODE_BITMAP, gd::INODE_BITMAP_CSUM, BG_INODE_UNINIT),
        };
        if self.csum != Csum::None && self.group_flags(g) & flag != 0 {
            return Ok(self.init_bitmap(g, kind));
        }
        let bits = self.read_block(self.group_get(g, loc))?;
        if self.csum == Csum::Crc32c {
            let wide = csum.1 + csum.2 <= self.desc_size;
            let mask = if wide { u32::MAX } else { 0xffff };
            if self.bitmap_csum(kind, &bits) & mask != self.group_get(g, csum) as u32 {
                return Err(Errno::EIO);
            }
        }
        Ok(bits)
    }

    fn init_bitmap(&self, g: u32, kind: Bitmap) -> Vec<u8> {
        let mut bits = vec![0; self.block_size];
        let used = match kind {
            Bitmap::Block => self.group_blocks(g) as usize,
            Bitmap::Inode => get32(&self.sb, sb::INODES_PER_GROUP) as usize,
        };
        set_bits(&mut bits, used, 8 * self.block_size - used);
        if kind == Bitmap::Inode {
            return bits;
        }
        let start = self.group_start(g);
        set_bits(&mut bits, 0, self.base_meta_blocks(g) as usize);
        // Under flex_bg any group's bitmaps and inode table may live here.
        let itable = (get32(&self.sb, sb::INODES_PER_GROUP) as usize * self.inode_size).div_ceil(self.block_size);
        for h in 0..self.group_count {
            for (field, len) in [(gd::BLOCK_BITMAP, 1), (gd::INODE_BITMAP, 1), (gd::INODE_TABLE, itable as u64)] {
                let loc = self.group_get(h, field);
                let (from, to) = (loc.max(start), (loc + len).min(start + used as u64));
                if from < to {
                    set_bits(&mut bits, (from - start) as usize, (to - from) as usize);
                }
            }
        }
        bits
    }

    /// Writes a group's bitmap back, marking it initialized and updating
    /// its checksum; the caller writes the group descriptor.
    fn store_bitmap(&mut self, g: u32, kind: Bitmap, bits: &[u8]) -> Result<(), Errno> {
        let (loc, csum, flag) = match kind {
            Bitmap::Block => (gd::BLOCK_BITMAP, gd::BLOCK_BITMAP_CSUM, BG_BLOCK_UNINIT),
            Bitmap::Inode => (gd::INODE_BITMAP, gd::INODE_BITMAP_CSUM, BG_INODE_UNINIT),
        };
        self.write_block(self.group_get(g, loc), bits)?;
        let flags = self.group_flags(g);
        if flags & flag != 0 {
            self.set_group_flags(g, flags & !flag);
        }
        if self.csum == Csum::Crc32c {
            let sum = self.bitmap_csum(kind, bits);
            self.group_set(g, csum, sum as u64);
        }
        Ok(())
    }

    /// Finds and sets a clear bit below `limit` in a group's bitmap,
    /// searching from `from`; returns its index.
    fn take_bit(&mut self, g: u32, kind: Bitmap, from: u32, limit: u32) -> Result<Option<u32>, Errno> {
        let mut bits = self.load_bitmap(g, kind)?;
        let clear = |i: u32| bits[i as usize / 8] & (1 << (i % 8)) == 0;
        let Some(index) = (from.min(limit)..limit).chain(0..from.min(limit)).find(|&i| clear(i)) else {
            return Ok(None);
        };
        bits[index as usize / 8] |= 1 << (index % 8);
        self.store_bitmap(g, kind, &bits)?;
        Ok(Some(index))
    }

    /// Allocates a zeroed block, as near after block `goal` as it can.
    fn alloc_block(&mut self, goal: u64) -> Result<u64, Errno> {
        if self.free_blocks() == 0 {
            return Err(Errno::ENOSPC);
        }
        let per_group = get32(&self.sb, sb::BLOCKS_PER_GROUP) as u64;
        let first = get32(&self.sb, sb::FIRST_DATA_BLOCK) as u64;
        let goal = if goal >= first && goal < self.blocks_count() { goal - first } else { 0 };
        let (goal_g, goal_i) = ((goal / per_group) as u32, (goal % per_group) as u32);
        for k in 0..self.group_count {
            let g = (goal_g + k) % self.group_count;
            if self.group_get(g, gd::FREE_BLOCKS) == 0 {
                continue;
            }
            let from = if k == 0 { goal_i } else { 0 };
            let limit = self.group_blocks(g) as u32;
            if let Some(i) = self.take_bit(g, Bitmap::Block, from, limit)? {
                self.adjust_group(g, gd::FREE_BLOCKS, -1);
                self.adjust_free_blocks(-1);
                self.write_group(g)?;
                self.write_super()?;
                let b = self.group_start(g) + i as u64;
                let zero = vec![0; self.block_size];
                self.write_block(b, &zero)?;
                return Ok(b);
            }
        }
        Err(Errno::ENOSPC)
    }

    /// Frees `count` blocks from `start`, a bitmap at a time.
    fn free_run(&mut self, start: u64, count: u64) -> Result<(), Errno> {
        let per_group = get32(&self.sb, sb::BLOCKS_PER_GROUP) as u64;
        let first = get32(&self.sb, sb::FIRST_DATA_BLOCK) as u64;
        let end = start.checked_add(count).ok_or(Errno::EIO)?;
        if start < first || end > self.blocks_count() {
            return Err(Errno::EIO);
        }
        let mut b = start;
        while b < end {
            let (g, i) = (((b - first) / per_group) as u32, (b - first) % per_group);
            let n = (per_group - i).min(end - b);
            let mut bits = self.load_bitmap(g, Bitmap::Block)?;
            for j in i..i + n {
                let byte = &mut bits[j as usize / 8];
                if *byte & (1 << (j % 8)) == 0 {
                    return Err(Errno::EIO);
                }
                *byte &= !(1 << (j % 8));
            }
            self.store_bitmap(g, Bitmap::Block, &bits)?;
            self.adjust_group(g, gd::FREE_BLOCKS, n as i64);
            self.adjust_free_blocks(n as i64);
            self.write_group(g)?;
            b += n;
        }
        self.write_super()
    }

    fn free_block(&mut self, b: u64) -> Result<(), Errno> {
        self.free_run(b, 1)
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
            if self.group_get(g, gd::FREE_INODES) == 0 {
                continue;
            }
            let Some(i) = self.take_bit(g, Bitmap::Inode, 0, per_group)? else { continue };
            let ino = g * per_group + i + 1;
            if ino < self.first_ino {
                // A reserved inode marked free: the bitmap is corrupt.
                return Err(Errno::EIO);
            }
            self.adjust_group(g, gd::FREE_INODES, -1);
            self.adjust_super(sb::FREE_INODES, -1);
            if kind_of(mode) == FileKind::Directory {
                self.adjust_group(g, gd::USED_DIRS, 1);
            }
            // The inode table past the last inode ever used may be garbage.
            if self.csum != Csum::None && i as u64 >= per_group as u64 - self.group_get(g, gd::ITABLE_UNUSED) {
                self.group_set(g, gd::ITABLE_UNUSED, (per_group - i - 1) as u64);
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
                // Linux's default when the superblock does not say.
                let extra = if extra == 0 { 32.min((self.inode_size - 128) as u16) } else { extra };
                put16(&mut inode.raw, ino::EXTRA_ISIZE, extra);
            }
            if self.extents && matches!(kind_of(mode), FileKind::Regular | FileKind::Directory | FileKind::Symlink) {
                inode.set_flags(EXTENTS_FL);
                extent::init_root(&mut inode);
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
            self.truncate_blocks(ino, &mut inode, 0)?;
        }
        let acl = inode.file_acl();
        if acl != 0 {
            let mut block = self.read_block(acl)?;
            let refs = if get32(&block, 0) == XATTR_MAGIC { get32(&block, 4) } else { 1 };
            if refs <= 1 {
                self.free_block(acl)?;
            } else {
                put32(&mut block, 4, refs - 1);
                if self.csum == Csum::Crc32c {
                    put32(&mut block, 0x10, 0);
                    let sum = crc32c(crc32c(self.csum_seed, &acl.to_le_bytes()), &block);
                    put32(&mut block, 0x10, sum);
                }
                self.write_block(acl, &block)?;
            }
            put32(&mut inode.raw, ino::FILE_ACL, 0);
            put16(&mut inode.raw, ino::FILE_ACL_HIGH, 0);
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
        let mut bits = self.load_bitmap(g, Bitmap::Inode)?;
        let byte = &mut bits[i as usize / 8];
        if *byte & (1 << (i % 8)) == 0 {
            return Err(Errno::EIO);
        }
        *byte &= !(1 << (i % 8));
        self.store_bitmap(g, Bitmap::Inode, &bits)?;
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
        let xattr = if inode.file_acl() != 0 { (self.block_size / 512) as u64 } else { 0 };
        inode.kind() == FileKind::Symlink && inode.sectors() == xattr
    }

    fn ptrs_per_block(&self) -> u64 {
        (self.block_size / 4) as u64
    }

    /// One past the last logical block an inode can map.
    fn max_blocks(&self, inode: &Inode) -> u64 {
        if inode.flags() & EXTENTS_FL != 0 {
            return extent::MAX_BLOCKS;
        }
        let per = self.ptrs_per_block();
        NDIR_BLOCKS as u64 + per + per * per + per * per * per
    }

    /// The physical block holding logical block `lblk`, 0 for a hole. With
    /// `alloc`, missing blocks (and indirect or extent tree blocks) are
    /// allocated.
    fn bmap(&mut self, ino: u32, inode: &mut Inode, lblk: u64, alloc: bool) -> Result<u64, Errno> {
        if alloc && inode.flags() & HUGE_FILE_FL != 0 {
            // Counted in blocks rather than sectors: a file over 2 TiB.
            return Err(Errno::EFBIG);
        }
        if inode.flags() & EXTENTS_FL != 0 {
            return self.ext_map(ino, inode, lblk, alloc);
        }
        let per = self.ptrs_per_block();
        let goal = self.group_start(self.group_of(ino));
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
        // Block map pointers are 32 bits.
        let alloc32 = |fs: &mut Self| {
            let b = fs.alloc_block(goal)?;
            if b > u32::MAX as u64 {
                fs.free_block(b)?;
                return Err(Errno::EFBIG);
            }
            Ok(b as u32)
        };
        let mut b = inode.block(slot);
        if b == 0 {
            if !alloc {
                return Ok(0);
            }
            b = alloc32(self)?;
            inode.set_block(slot, b);
            inode.add_sectors(sectors);
        }
        for &index in &path {
            let mut table = self.read_block(b as u64)?;
            let mut next = get32(&table, index as usize * 4);
            if next == 0 {
                if !alloc {
                    return Ok(0);
                }
                next = alloc32(self)?;
                put32(&mut table, index as usize * 4, next);
                self.write_block(b as u64, &table)?;
                inode.add_sectors(sectors);
            }
            b = next;
        }
        Ok(b as u64)
    }

    /// Frees every block from logical block `keep` on.
    fn truncate_blocks(&mut self, ino: u32, inode: &mut Inode, keep: u64) -> Result<(), Errno> {
        if inode.flags() & EXTENTS_FL != 0 {
            return self.ext_truncate(ino, inode, keep);
        }
        let per = self.ptrs_per_block();
        let mut freed = 0u64;
        for i in 0..NDIR_BLOCKS {
            let b = inode.block(i);
            if b != 0 && i as u64 >= keep {
                self.free_block(b as u64)?;
                inode.set_block(i, 0);
                freed += 1;
            }
        }
        let mut start = NDIR_BLOCKS as u64;
        let mut span = per;
        for depth in 1..=3u32 {
            let slot = NDIR_BLOCKS + depth as usize - 1;
            let b = inode.block(slot);
            if b != 0 && self.truncate_tree(b as u64, depth, keep.saturating_sub(start), &mut freed)? {
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
    fn truncate_tree(&mut self, b: u64, depth: u32, keep: u64, freed: &mut u64) -> Result<bool, Errno> {
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
            let child = get32(&table, i * 4) as u64;
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
            // A fast symbolic link: the target lives in the block map, in
            // place of any extent tree.
            inode.set_flags(inode.flags() & !EXTENTS_FL);
            inode.raw[ino::BLOCK..ino::BLOCK + 60].fill(0);
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
            if inode.flags() & HUGE_FILE_FL != 0 {
                return Err(Errno::EFBIG);
            }
            self.truncate_blocks(ino, &mut inode, len.div_ceil(bs))?;
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
        } else if len > 0 && (len - 1) / bs >= self.max_blocks(&inode) {
            // Beyond what the block map or extent tree can reach.
            return Err(Errno::EFBIG);
        }
        inode.set_size(len);
        let now = self.now();
        inode.set_times(now, &[ino::MTIME, ino::CTIME]);
        self.write_inode(ino, &inode)
    }

    // ---- Directories ----

    /// Calls `f(block number within the directory, physical block, data)`
    /// for each of a directory's blocks until it returns `Some`. Blocks
    /// with a checksum tail are verified.
    fn scan_dir<T>(
        &mut self,
        ino: u32,
        mut f: impl FnMut(&mut Self, u64, &mut Vec<u8>) -> Result<Option<T>, Errno>,
    ) -> Result<Option<T>, Errno> {
        let mut inode = self.read_inode(ino)?;
        if inode.kind() != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        let seed = if self.csum == Csum::Crc32c { self.inode_seed(ino, &inode) } else { 0 };
        let blocks = inode.size().div_ceil(self.block_size as u64);
        for lblk in 0..blocks {
            let b = self.bmap(ino, &mut inode, lblk, false)?;
            if b == 0 {
                continue;
            }
            let mut data = self.read_block(b)?;
            if self.has_dir_tail(&data) {
                let t = data.len() - DIR_TAIL_LEN;
                if get32(&data, t + 8) != crc32c(seed, &data[..t]) {
                    return Err(Errno::EIO);
                }
            }
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
            let (mut off, space) = (0, fs.dir_space(data));
            while off < space {
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
            let (mut off, space) = (0, fs.dir_space(data));
            while off < space {
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

    /// Clears a directory's hash index flag before changing it. Under
    /// `metadata_csum` the index blocks, which have no directory tail,
    /// become empty directory blocks with one.
    fn drop_index(&mut self, dir: u32) -> Result<(), Errno> {
        let mut inode = self.read_inode(dir)?;
        let flags = inode.flags();
        if flags & INDEX_FL == 0 {
            return Ok(());
        }
        inode.set_flags(flags & !INDEX_FL);
        self.write_inode(dir, &inode)?;
        if self.csum != Csum::Crc32c {
            return Ok(());
        }
        self.scan_dir(dir, |fs, b, data| {
            if fs.has_dir_tail(data) {
                return Ok(None::<()>);
            }
            // The root's `..` record or an interior node's empty record
            // spans the index; shrink the block's last record to make room.
            let (mut off, mut last) = (0, 0);
            while off < data.len() {
                last = off;
                off += fs.record(data, off)?.1;
            }
            let (ino, rec_len, name) = fs.record(data, last)?;
            let used = rec_len_for(name.len());
            let used = if ino == 0 { 8 } else { used };
            if rec_len < used + DIR_TAIL_LEN {
                return Err(Errno::EIO);
            }
            put16(data, last + 4, (rec_len - DIR_TAIL_LEN) as u16);
            let t = data.len() - DIR_TAIL_LEN;
            data[last + used..].fill(0);
            put16(data, t + 4, DIR_TAIL_LEN as u16);
            data[t + 7] = DIR_TAIL_TYPE;
            fs.write_dir_block(dir, b, data)?;
            Ok(None)
        })?;
        Ok(())
    }

    fn add_entry(&mut self, dir: u32, name: &str, ino: u32, kind: FileKind) -> Result<(), Errno> {
        self.drop_index(dir)?;
        let need = rec_len_for(name.len());
        let placed = self.scan_dir(dir, |fs, b, data| {
            let (mut off, space) = (0, fs.dir_space(data));
            while off < space {
                let (used_ino, rec_len, used_name) = fs.record(data, off)?;
                let used = if used_ino == 0 { 0 } else { rec_len_for(used_name.len()) };
                if rec_len - used >= need {
                    if used_ino == 0 {
                        fs.write_record(data, off, ino, rec_len, name, kind);
                    } else {
                        put16(data, off + 4, used as u16);
                        fs.write_record(data, off + used, ino, rec_len - used, name, kind);
                    }
                    fs.write_dir_block(dir, b, data)?;
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
        inode.set_size(size + self.block_size as u64);
        self.write_inode(dir, &inode)?;
        let (mut data, space) = self.new_dir_block();
        self.write_record(&mut data, 0, ino, space, name, kind);
        self.write_dir_block(dir, b, &mut data)
    }

    fn remove_entry(&mut self, dir: u32, name: &str) -> Result<(), Errno> {
        self.drop_index(dir)?;
        let removed = self.scan_dir(dir, |fs, b, data| {
            let (mut off, mut prev, space) = (0, None, fs.dir_space(data));
            while off < space {
                let (ino, rec_len, entry) = fs.record(data, off)?;
                if ino != 0 && entry == name.as_bytes() {
                    match prev {
                        Some(p) => {
                            let merged = get16(data, p + 4) as usize + rec_len;
                            put16(data, p + 4, merged as u16);
                        }
                        None => put32(data, off, 0),
                    }
                    fs.write_dir_block(dir, b, data)?;
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
        // With `dir_nlink` a count of 1 means "too many to count".
        let uncounted = self.dir_nlink && parent.links() == 1;
        if kind == FileKind::Directory && !self.dir_nlink && parent.links() >= LINK_MAX {
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
            inode.set_size(self.block_size as u64);
            inode.set_links(2);
            self.write_inode(ino, &inode)?;
            let (mut data, space) = self.new_dir_block();
            self.write_record(&mut data, 0, ino, 12, ".", FileKind::Directory);
            self.write_record(&mut data, 12, dir, space - 12, "..", FileKind::Directory);
            self.write_dir_block(ino, b, &mut data)?;
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
        if kind == FileKind::Directory && !uncounted {
            let links = parent.links() + 1;
            parent.set_links(if links >= LINK_MAX && self.dir_nlink { 1 } else { links });
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
            // A parent counted as 1 under `dir_nlink` stays at 1.
            if parent.links() > 2 {
                parent.set_links(parent.links() - 1);
            }
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

    /// A file system flavour to test: `mkfs.<kind>` with extra options.
    #[derive(Clone, Copy)]
    struct Kind(&'static str, &'static [&'static str]);

    const EXT2: Kind = Kind("ext2", &[]);
    const EXT3: Kind = Kind("ext3", &[]);
    /// The default ext4: extents, 64bit, flex_bg, metadata_csum, a journal.
    const EXT4: Kind = Kind("ext4", &[]);
    /// Small groups, so that flex_bg puts metadata in other groups and
    /// leaves uninitialized bitmaps to build.
    const EXT4_GROUPS: Kind = Kind("ext4", &["-g", "1024"]);
    /// `uninit_bg`'s CRC16 group descriptors without `metadata_csum`.
    const EXT4_CRC16: Kind = Kind("ext4", &["-g", "1024", "-O", "^metadata_csum,uninit_bg"]);

    /// Runs `mkfs` on a fresh image of `size` bytes, filled from `tree` if
    /// given; `None` if e2fsprogs is not installed.
    fn mkfs(scratch: &Scratch, kind: Kind, block: usize, size: usize, tree: Option<&Path>) -> Option<Vec<u8>> {
        let img = scratch.0.join("image");
        fs::write(&img, vec![0u8; size]).unwrap();
        let mut cmd = Command::new(format!("mkfs.{}", kind.0));
        cmd.args(["-q", "-F", "-b", &block.to_string(), "-I", "256"]).args(kind.1);
        if let Some(tree) = tree {
            cmd.arg("-d").arg(tree);
        }
        let Ok(status) = cmd.arg(&img).status() else {
            std::eprintln!("mkfs.{} not installed; skipping", kind.0);
            return None;
        };
        assert!(status.success(), "mkfs.{} {:?} failed", kind.0, kind.1);
        Some(fs::read(&img).unwrap())
    }

    /// Runs `debugfs -w` commands on an image.
    fn debugfs(scratch: &Scratch, image: Vec<u8>, cmds: &[&str]) -> Vec<u8> {
        let img = scratch.0.join("debugfs");
        fs::write(&img, image).unwrap();
        for cmd in cmds {
            let out = Command::new("debugfs").arg("-w").arg("-R").arg(cmd).arg(&img).output().unwrap();
            assert!(out.status.success(), "debugfs {cmd}: {}", String::from_utf8_lossy(&out.stderr));
        }
        fs::read(&img).unwrap()
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
        for kind in [EXT2, EXT3, EXT4, EXT4_CRC16] {
            for block in [1024, 4096] {
                let Some(image) = mkfs(&scratch, kind, block, 8 << 20, Some(&tree)) else { return };
                let ext2 = Ext2::mount(VecDisk(image), 7).unwrap();
                assert!(!ext2.is_read_only());
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
    }

    #[test]
    fn writes_pass_fsck() {
        let scratch = Scratch::new("write");
        for kind in [EXT2, EXT3, EXT4, EXT4_GROUPS, EXT4_CRC16] {
            for block in [1024, 4096] {
                let Some(image) = mkfs(&scratch, kind, block, 8 << 20, None) else { return };
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

                // Enough names to need several directory blocks (and, with
                // small groups, inodes from several groups), then remove
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
    }

    #[test]
    fn changes_large_directory() {
        let scratch = Scratch::new("large");
        let tree = scratch.0.join("tree");
        fs::create_dir_all(tree.join("big")).unwrap();
        for i in 0..2000 {
            fs::write(tree.join(format!("big/file-{i}")), format!("{i}")).unwrap();
        }
        // The last pass gives the directory a hash index (`e2fsck -D`).
        for (kind, index) in [(EXT2, false), (EXT4, false), (EXT3, true), (EXT4, true)] {
            let Some(mut image) = mkfs(&scratch, kind, 1024, 16 << 20, Some(&tree)) else { return };
            if index {
                let img = scratch.0.join("index");
                fs::write(&img, &image).unwrap();
                Command::new("e2fsck").arg("-fyD").arg(&img).output().unwrap();
                image = fs::read(&img).unwrap();
            }
            let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
            let vfs = Vfs::new(ext2.root());
            let big = vfs.lookup("/big").unwrap();
            let ino = big.stat().ino as u32;
            let indexed = ext2.shared.fs.lock().read_inode(ino).unwrap().flags() & INDEX_FL != 0;
            assert_eq!(indexed, index);
            assert_eq!(names(&*big).len(), 2000);
            assert_eq!(read_all(&*vfs.lookup("/big/file-1234").unwrap()), b"1234");
            for i in (0..2000).step_by(3) {
                vfs.unlink(&format!("/big/file-{i}")).unwrap();
            }
            vfs.open("/big/new", OpenFlags::CREATE, 0o644).unwrap();
            assert_eq!(names(&*big).len(), 2000 - 667 + 1);
            drop((big, vfs));
            let image = unmount(ext2);
            assert_eq!(fsck(&scratch, &image, &["/big/file-1999"])[0], b"1999");
        }
    }

    #[test]
    fn unlinked_open_file_is_freed_on_drop() {
        let scratch = Scratch::new("orphan");
        for kind in [EXT2, EXT4] {
            let Some(image) = mkfs(&scratch, kind, 1024, 4 << 20, None) else { return };
            let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
            let free = |e: &Ext2<VecDisk>| {
                let fs = e.shared.fs.lock();
                (fs.free_blocks(), get32(&fs.sb, sb::FREE_INODES))
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
    }

    #[test]
    fn full_disk() {
        let scratch = Scratch::new("full");
        for kind in [EXT2, Kind("ext4", &["-g", "256"])] {
            let Some(image) = mkfs(&scratch, kind, 1024, 1 << 20, None) else { return };
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
    }

    #[test]
    fn extent_tree_grows_and_shrinks() {
        let scratch = Scratch::new("extents");
        for block in [1024, 4096] {
            let Some(image) = mkfs(&scratch, EXT4, block, 16 << 20, None) else { return };
            let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
            let vfs = Vfs::new(ext2.root());
            let rw = OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE;
            let bs = block as u64;
            // Every other block, so that no two extents merge: forwards,
            // and backwards to insert before the first key every time.
            let n = 1200u64;
            let fwd = vfs.open("/forwards", rw, 0o644).unwrap();
            let back = vfs.open("/backwards", rw, 0o644).unwrap();
            for i in 0..n {
                fwd.write(2 * i * bs, &pattern(100, i as u8)).unwrap();
                back.write(2 * (n - 1 - i) * bs, &pattern(100, (n - 1 - i) as u8)).unwrap();
            }
            let depth = |f: &dyn File| {
                let ino = f.stat().ino as u32;
                get16(&ext2.shared.fs.lock().read_inode(ino).unwrap().raw, ino::BLOCK + 6)
            };
            assert!(depth(&*fwd) >= 1 && depth(&*back) >= 1);
            if block == 1024 {
                // 1200 extents at 84 a leaf need more than the root's four.
                assert_eq!((depth(&*fwd), depth(&*back)), (2, 2));
            }
            let expect = |len: u64| {
                let mut v = vec![0; len as usize];
                for i in 0..len.div_ceil(2 * bs) {
                    let at = (2 * i * bs) as usize;
                    let end = (at + 100).min(len as usize);
                    v[at..end].copy_from_slice(&pattern(100, i as u8)[..end - at]);
                }
                v
            };
            let full = (2 * (n - 1)) * bs + 100;
            assert_eq!(read_all(&*fwd), expect(full));
            assert_eq!(read_all(&*back), expect(full));
            // Filling a hole between two extents joins them.
            fwd.write(bs, &vec![7; block]).unwrap();
            drop((fwd, back, vfs));
            let image = unmount(ext2);
            let cats = fsck(&scratch, &image, &["/backwards"]);
            assert_eq!(cats[0], expect(full));

            let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
            let vfs = Vfs::new(ext2.root());
            let fwd = vfs.lookup("/forwards").unwrap();
            let back = vfs.lookup("/backwards").unwrap();
            let half = n * bs + 50;
            fwd.truncate(half).unwrap();
            back.truncate(10).unwrap();
            let free_before = ext2.shared.fs.lock().free_blocks();
            vfs.unlink("/forwards").unwrap();
            drop(fwd);
            assert!(ext2.shared.fs.lock().free_blocks() > free_before + n / 2);
            assert_eq!(read_all(&*back), pattern(10, 0));
            drop((back, vfs));
            let cats = fsck(&scratch, &unmount(ext2), &["/backwards"]);
            assert_eq!(cats[0], pattern(10, 0));
        }
    }

    #[test]
    fn writes_into_preallocated_extents() {
        let scratch = Scratch::new("prealloc");
        let Some(image) = mkfs(&scratch, EXT4, 1024, 8 << 20, None) else { return };
        // 300 blocks of uninitialized extents, and a size to cover them.
        let image = debugfs(&scratch, image, &["write /dev/null pre", "fallocate /pre 0 299", "sif /pre size 307200"]);
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        let vfs = Vfs::new(ext2.root());
        let pre = vfs.open("/pre", OpenFlags::READ | OpenFlags::WRITE, 0).unwrap();
        assert!(read_all(&*pre).iter().all(|&b| b == 0));
        let mut want = vec![0; 307_200];
        // The middle, then a run on from the start, then the very end.
        for (off, len, seed) in [(150_000, 10, 1), (0, 20_000, 2), (307_190, 10, 3)] {
            pre.write(off as u64, &pattern(len, seed)).unwrap();
            want[off..off + len].copy_from_slice(&pattern(len, seed));
        }
        assert_eq!(read_all(&*pre), want);
        drop((pre, vfs));
        assert_eq!(fsck(&scratch, &unmount(ext2), &["/pre"])[0], want);
    }

    #[test]
    fn refuses_unsupported_and_garbage() {
        let scratch = Scratch::new("refuse");
        let Some(image) = mkfs(&scratch, EXT4, 1024, 4 << 20, None) else { return };
        let dirty = debugfs(&scratch, image.clone(), &["feature needs_recovery"]);
        assert_eq!(Ext2::mount(VecDisk(dirty), 1).err(), Some(Errno::ENOSYS));
        let mut bad = image.clone();
        bad[1024 + sb::WTIME] ^= 1;
        assert_eq!(Ext2::mount(VecDisk(bad), 1).err(), Some(Errno::EINVAL));
        let Some(inline) = mkfs(&scratch, Kind("ext4", &["-O", "inline_data"]), 1024, 4 << 20, None) else { return };
        assert_eq!(Ext2::mount(VecDisk(inline), 1).err(), Some(Errno::ENOSYS));
        assert_eq!(Ext2::mount(VecDisk(vec![0; 64 * 1024]), 1).err(), Some(Errno::EINVAL));

        // An unknown read-only feature: reads work, writes fail.
        let Some(quota) = mkfs(&scratch, Kind("ext4", &["-O", "quota"]), 1024, 4 << 20, None) else { return };
        let ext2 = Ext2::mount(VecDisk(quota), 1).unwrap();
        assert!(ext2.is_read_only());
        assert_eq!(ext2.root().create("x", FileKind::Regular, 0o644).err(), Some(Errno::EROFS));
    }
}
