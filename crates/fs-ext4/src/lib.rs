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
//! A JBD2 journal inside the file system (ext3's or ext4's) is used. Each
//! operation writes its metadata changes to the log and commits them before
//! they go to their places, and file data is written first (`data=ordered`),
//! so a crash leaves the file system as it was before the operation or after
//! it. Mounting replays what a crash left in the log, including logs written
//! by Linux (revoke records, `64bit` tags, `csum_v3` checksums). Without a
//! journal, or with one of a kind this driver does not understand (on
//! another device, `csum_v2`, `async_commit`, fast commits), changes are
//! written in place and are not crash safe; if such a journal needs
//! recovery the mount fails with `ENOSYS`. An operation too large for the
//! journal is logged as several transactions. The other incompatible
//! features (`inline_data`, `largedir`, `ea_inode`, encryption, casefolding,
//! compression) are refused. A file system with an unknown read-only
//! feature (`quota`, `bigalloc`, ...) mounts read-only.
//! Hashed directory indexes are ignored for lookup and dropped (the flag is
//! cleared) when a directory changes, as Linux's ext2 driver does; with
//! `metadata_csum` the index blocks become empty, checksummed directory
//! blocks.
//!
//! All state lives behind one spin lock held across device I/O, and there is
//! no block cache: simple and correct, not fast. A journaled operation
//! flushes the device three times. Call [`Ext2::into_device`] to unmount:
//! it marks the journal empty and the file system clean. Dropping an
//! [`Ext2`] instead leaves the journal for the next mount to replay.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod csum;
mod extent;
mod journal;

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::{MaybeUninit, offset_of};

use osmium_hal::block::{BlockDevice, BlockError};
use osmium_sync::arc::ArcTree;
use osmium_sync::fallible::{OutOfMemory, init_arc, try_arc, try_arc_uninit, try_to_vec, try_zeroed};
use osmium_sync::intrusive::{Adapter, KeyAdapter, Registry, Shared as SharedLink, TreeLink};
use osmium_sync::{Once, SpinLock};

use csum::{crc16, crc32c};
use journal::Journal;
use osmium_fs::dev::makedev;
use osmium_fs::{Clock, ClockSlot, DirEntry, Errno, File, FileKind, NAME_MAX, PATH_MAX, Stat, Timestamp};

const MAGIC: u16 = 0xef53;
const ROOT_INO: u32 = 2;
const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_LEN: usize = 1024;
const NDIR_BLOCKS: usize = 12;
/// The most subdirectories' `..` links a directory counts; past it, with
/// `dir_nlink`, the count stays at 1.
const LINK_MAX: u16 = 65000;

const COMPAT_HAS_JOURNAL: u32 = 0x0004;
const COMPAT_SPARSE_SUPER2: u32 = 0x0200;
const INCOMPAT_FILETYPE: u32 = 0x0002;
/// The journal holds transactions to replay.
const INCOMPAT_RECOVER: u32 = 0x0004;
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
    pub const JOURNAL_INUM: usize = 0xe0;
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

/// Little-endian field readers and writers. A field past the end of its
/// buffer reads as zero and ignores writes: callers size buffers from
/// validated geometry, and a hostile image must not turn a short buffer into
/// a panic.
fn get16(buf: &[u8], off: usize) -> u16 {
    off.checked_add(2)
        .and_then(|end| buf.get(off..end))
        .and_then(|b| b.first_chunk::<2>())
        .map_or(0, |b| u16::from_le_bytes(*b))
}

fn get32(buf: &[u8], off: usize) -> u32 {
    off.checked_add(4)
        .and_then(|end| buf.get(off..end))
        .and_then(|b| b.first_chunk::<4>())
        .map_or(0, |b| u32::from_le_bytes(*b))
}

fn put16(buf: &mut [u8], off: usize, val: u16) {
    if let Some(dst) = off.checked_add(2).and_then(|end| buf.get_mut(off..end)) {
        dst.copy_from_slice(&val.to_le_bytes());
    }
}

fn put32(buf: &mut [u8], off: usize, val: u32) {
    if let Some(dst) = off.checked_add(4).and_then(|end| buf.get_mut(off..end)) {
        dst.copy_from_slice(&val.to_le_bytes());
    }
}

/// `buf[range]`, or nothing if the range is not inside it.
fn sub(buf: &[u8], range: core::ops::Range<usize>) -> &[u8] {
    buf.get(range).unwrap_or(&[])
}

/// The byte at `off`, or zero past the end.
fn byte(buf: &[u8], off: usize) -> u8 {
    buf.get(off).copied().unwrap_or(0)
}

/// Copies `src` to `dst[at..]`; `EIO` if it does not fit.
fn put_bytes(dst: &mut [u8], at: usize, src: &[u8]) -> Result<(), Errno> {
    let end = at.checked_add(src.len()).ok_or(Errno::EIO)?;
    dst.get_mut(at..end).ok_or(Errno::EIO)?.copy_from_slice(src);
    Ok(())
}

/// Sets `buf[range]` to `value`; `EIO` if the range is not inside it.
fn fill_range(buf: &mut [u8], range: core::ops::Range<usize>, value: u8) -> Result<(), Errno> {
    buf.get_mut(range).ok_or(Errno::EIO)?.fill(value);
    Ok(())
}

/// ORs `mask` into `buf[at]`; `EIO` past the end.
fn or_byte(buf: &mut [u8], at: usize, mask: u8) -> Result<(), Errno> {
    *buf.get_mut(at).ok_or(Errno::EIO)? |= mask;
    Ok(())
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
    for i in start..start.saturating_add(count) {
        match bits.get_mut(i / 8) {
            Some(b) => *b |= 1 << (i % 8),
            None => break,
        }
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
        let v = (self.sectors() as i64).saturating_add(delta).max(0) as u64;
        put32(&mut self.raw, ino::BLOCKS, v as u32);
        put16(&mut self.raw, ino::BLOCKS_HIGH, (v >> 32) as u16);
    }

    fn file_acl(&self) -> u64 {
        (get16(&self.raw, ino::FILE_ACL_HIGH) as u64) << 32 | get32(&self.raw, ino::FILE_ACL) as u64
    }

    fn time(&self, field: usize) -> Timestamp {
        Timestamp::from_secs(get32(&self.raw, field) as i64)
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
    /// A device block of scratch for `dev_read_bytes`, reserved at mount so
    /// that undoing an operation (see `Fs::abort`) cannot run out of memory.
    bounce: Vec<u8>,
    /// Buffers for rewriting the superblock on disk, which committing the
    /// first transaction does: reserved at mount, since a commit must not
    /// allocate.
    sb_copy: Vec<u8>,
    write_scratch: Vec<u8>,
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
    clock: ClockSlot,
    /// One node per in-use inode, so an unlinked file is freed when its
    /// last reference goes. It does not own them: each leaves it when it is
    /// dropped.
    nodes: Registry<ByIno<D>>,
    st_dev: u64,
    /// Sorted, disjoint block ranges `[start, end)` holding superblock
    /// backups, descriptors, bitmaps and inode tables, which file data and
    /// block maps must never name.
    meta_zones: Vec<(u64, u64)>,
    /// The journal, when there is one this driver can write. Metadata
    /// writes then collect in `tx` until the operation ends.
    journal: Option<journal::Journal>,
    /// The metadata blocks the operation in progress has changed, by block.
    tx: ArcTree<ByBlock>,
    /// Block ranges `[start, end)` the operation has freed, which it must
    /// not allocate again: until the transaction commits, a crash brings
    /// them back as they were.
    tx_freed: ArcTree<ByStart>,
}

/// A metadata block the operation in progress has changed.
struct TxBlock {
    blk: u64,
    /// The new contents, a whole block; only touched with the file system's
    /// lock held (see [`Fs::tx_block_mut`]).
    data: UnsafeCell<Vec<u8>>,
    link: SharedLink<TreeLink>,
}

// SAFETY: the data is only accessed with the file system's lock held.
unsafe impl Sync for TxBlock {}

impl TxBlock {
    /// A block over a copy of `data`, made before it is needed.
    fn new(blk: u64, data: &[u8]) -> Result<Arc<Self>, OutOfMemory> {
        try_arc(TxBlock { blk, data: UnsafeCell::new(try_to_vec(data)?), link: SharedLink::new(TreeLink::new()) })
    }

    /// A block over `data`, which it keeps.
    fn from_vec(blk: u64, data: Vec<u8>) -> Result<Arc<Self>, OutOfMemory> {
        try_arc(TxBlock { blk, data: UnsafeCell::new(data), link: SharedLink::new(TreeLink::new()) })
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: see the type's documentation; no `&mut` is out while the
        // caller has `&self` of the file system.
        unsafe { &*self.data.get() }
    }
}

struct ByBlock;

// SAFETY: `offset_of!` of a `SharedLink<TreeLink>`, which is a `TreeLink`.
unsafe impl Adapter<TreeLink> for ByBlock {
    type Value = TxBlock;
    const OFFSET: usize = offset_of!(TxBlock, link);
}

impl KeyAdapter<TreeLink> for ByBlock {
    type Key = u64;

    fn key(t: &TxBlock) -> &u64 {
        &t.blk
    }
}

/// A block range the operation in progress has freed.
struct Freed {
    start: u64,
    end: u64,
    link: SharedLink<TreeLink>,
}

struct ByStart;

// SAFETY: as for `ByBlock`.
unsafe impl Adapter<TreeLink> for ByStart {
    type Value = Freed;
    const OFFSET: usize = offset_of!(Freed, link);
}

impl KeyAdapter<TreeLink> for ByStart {
    type Key = u64;

    fn key(f: &Freed) -> &u64 {
        &f.start
    }
}

struct ByIno<D>(core::marker::PhantomData<D>);

// SAFETY: as for `ByBlock`.
unsafe impl<D: BlockDevice + Send + 'static> Adapter<TreeLink> for ByIno<D> {
    type Value = Node<D>;
    const OFFSET: usize = offset_of!(Node<D>, link);
}

impl<D: BlockDevice + Send + 'static> KeyAdapter<TreeLink> for ByIno<D> {
    type Key = u32;

    fn key(n: &Node<D>) -> &u32 {
        &n.ino
    }
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
    /// Itself, for [`Fs::nodes`] to hand out references without allocating.
    me: Once<Weak<Node<D>>>,
    link: SharedLink<TreeLink>,
}

/// `raw` as text, with anything that is not UTF-8 replaced (like
/// `String::from_utf8_lossy`), failing instead of panicking if memory runs out.
fn lossy(raw: &[u8]) -> Result<String, OutOfMemory> {
    let mut s = String::new();
    // An invalid byte becomes a three-byte replacement character.
    s.try_reserve_exact(raw.len().saturating_mul(3))?;
    for chunk in raw.utf8_chunks() {
        s.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            s.push(char::REPLACEMENT_CHARACTER);
        }
    }
    Ok(s)
}

/// Bytes of device blocks that hold the superblock.
fn super_span(dev_bs: usize) -> usize {
    let bs = dev_bs.max(1);
    let (first, last) = (SUPERBLOCK_OFFSET as usize / bs, (SUPERBLOCK_OFFSET as usize + SUPERBLOCK_LEN - 1) / bs);
    (last - first + 1) * bs
}

/// A plain function as a [`Clock`], for [`Ext2::set_clock`].
struct FnClock(fn() -> u32);

impl Clock for FnClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_secs((self.0)() as i64)
    }
}

impl<D: BlockDevice + Send + 'static> Ext2<D> {
    /// Mounts the ext2, ext3 or ext4 file system on `dev`, reporting
    /// `st_dev` as `devno`. Fails with `EINVAL` if `dev` holds no such file
    /// system (or its superblock or group descriptors fail their checksums)
    /// and `ENOSYS` for unsupported features, including a journal that needs
    /// recovery but that this driver cannot read. A journal that needs
    /// recovery is replayed, so mounting writes to the device.
    pub fn mount(dev: D, devno: u64) -> Result<Self, Errno> {
        let dev_bs = dev.block_size();
        if dev_bs == 0 {
            return Err(Errno::EINVAL);
        }
        let mut fs = Fs {
            dev,
            dev_per_block: 1,
            block_size: dev_bs,
            sb: try_zeroed(SUPERBLOCK_LEN)?,
            bounce: try_zeroed(dev_bs)?,
            sb_copy: try_zeroed(SUPERBLOCK_LEN)?,
            write_scratch: try_zeroed(super_span(dev_bs))?,
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
            clock: ClockSlot::new(),
            nodes: Registry::new(),
            st_dev: devno,
            meta_zones: Vec::new(),
            journal: None,
            tx: ArcTree::new(),
            tx_freed: ArcTree::new(),
        };
        fs.load()?;
        let mut journal = Journal::open(&mut fs)?;
        if get32(&fs.sb, sb::FEATURE_INCOMPAT) & INCOMPAT_RECOVER != 0 {
            let mut replaying = journal.ok_or(Errno::ENOSYS)?;
            replaying.replay(&mut fs)?;
            fs.set_disk_needs_recovery(false)?;
            // Replay may have rewritten the superblock and descriptors.
            fs.load()?;
            journal = Journal::open(&mut fs)?;
        }
        if !fs.read_only
            && let Some(journal) = journal
        {
            // The superblock the journal logs says the journal is in use;
            // the one on disk says so once the first transaction is in the
            // log.
            let flags = get32(&fs.sb, sb::FEATURE_INCOMPAT) | INCOMPAT_RECOVER;
            put32(&mut fs.sb, sb::FEATURE_INCOMPAT, flags);
            fs.journal = Some(journal);
        }
        let shared = try_arc(Shared { fs: SpinLock::new(fs) })?;
        Ok(Ext2 { shared })
    }

    /// Sets the clock that stamps access, change and modification times, in
    /// seconds since 1970. Without one, the global [`osmium_fs::clock`] is
    /// used, and without that new times are 0. See also
    /// [`set_clock_source`](Ext2::set_clock_source).
    pub fn set_clock(&self, clock: fn() -> u32) {
        self.set_clock_source(Arc::new(FnClock(clock)));
    }

    /// Takes the time from `clock` (to the second: inodes without the extra
    /// time fields have no more, and the extra fields are not written).
    pub fn set_clock_source(&self, clock: Arc<dyn Clock>) {
        self.shared.fs.lock().clock.set(clock);
    }

    /// Whether changes are journaled: the file system has an internal JBD2
    /// journal this driver understands, and is writable.
    pub fn is_journaled(&self) -> bool {
        self.shared.fs.lock().journal.is_some()
    }

    /// Whether writes fail with `EROFS` (an unknown read-only feature).
    pub fn is_read_only(&self) -> bool {
        self.shared.fs.lock().read_only
    }

    /// The root directory, to pass to [`Vfs::mount`](osmium_fs::Vfs::mount).
    ///
    /// Fails with `ENOMEM` if memory runs out.
    pub fn root(&self) -> Result<Arc<dyn File>, Errno> {
        let mut fs = self.shared.fs.lock();
        fs.node(&self.shared, ROOT_INO, None)
    }

    /// Unmounts, returning the device once no node is in use; otherwise
    /// `EBUSY` with the file system unchanged.
    pub fn into_device(self) -> Result<D, (Self, Errno)> {
        match Arc::try_unwrap(self.shared) {
            Ok(shared) => {
                let mut fs = shared.fs.into_inner();
                fs.close_journal();
                let _ = fs.dev.flush();
                Ok(fs.dev)
            }
            Err(shared) => Err((Ext2 { shared }, Errno::EBUSY)),
        }
    }
}

impl<D: BlockDevice + Send + 'static> Fs<D> {
    /// Reads the superblock and group descriptors and checks them, setting
    /// every field derived from them. Safe to call again after the journal
    /// has been replayed.
    fn load(&mut self) -> Result<(), Errno> {
        let dev_bs = self.dev.block_size();
        self.filetype = false;
        self.wide = false;
        self.extents = false;
        self.dir_nlink = false;
        self.csum = Csum::None;
        self.csum_seed = 0;
        self.read_only = false;
        self.desc_size = 32;
        self.first_meta_bg = None;
        self.inode_size = 128;
        self.first_ino = 11;
        self.groups.clear();
        let mut sbuf = try_zeroed(SUPERBLOCK_LEN)?;
        self.read_bytes(SUPERBLOCK_OFFSET, &mut sbuf)?;
        self.sb = sbuf;
        if get16(&self.sb, sb::MAGIC) != MAGIC {
            return Err(Errno::EINVAL);
        }
        let log = get32(&self.sb, sb::LOG_BLOCK_SIZE);
        // Record lengths are 16 bits, so a block holds at most 32 KiB.
        if log > 5 {
            return Err(Errno::EINVAL);
        }
        self.block_size = 1024 << log;
        if dev_bs == 0 || !self.block_size.is_multiple_of(dev_bs) {
            return Err(Errno::EINVAL);
        }
        self.dev_per_block = (self.block_size / dev_bs) as u64;
        if get32(&self.sb, sb::REV_LEVEL) >= 1 {
            self.first_ino = get32(&self.sb, sb::FIRST_INO);
            self.inode_size = get16(&self.sb, sb::INODE_SIZE) as usize;
            let incompat = get32(&self.sb, sb::FEATURE_INCOMPAT);
            if incompat & !(INCOMPAT_SUPPORTED | INCOMPAT_RECOVER) != 0 {
                return Err(Errno::ENOSYS);
            }
            self.filetype = incompat & INCOMPAT_FILETYPE != 0;
            if incompat & INCOMPAT_META_BG != 0 {
                self.first_meta_bg = Some(get32(&self.sb, sb::FIRST_META_BG));
            }
            self.extents = incompat & INCOMPAT_EXTENTS != 0;
            self.wide = incompat & INCOMPAT_64BIT != 0;
            if self.wide {
                self.desc_size = get16(&self.sb, sb::DESC_SIZE) as usize;
                if self.desc_size < 64 || !self.desc_size.is_power_of_two() || self.desc_size > self.block_size {
                    return Err(Errno::EINVAL);
                }
            }
            let ro = get32(&self.sb, sb::FEATURE_RO_COMPAT);
            self.read_only = ro & !RO_COMPAT_SUPPORTED != 0;
            self.dir_nlink = ro & RO_COMPAT_DIR_NLINK != 0;
            if ro & RO_COMPAT_METADATA_CSUM != 0 {
                // 1 is CRC32C, the only type there is.
                if byte(&self.sb, sb::CHECKSUM_TYPE) != 1 {
                    return Err(Errno::ENOSYS);
                }
                if get32(&self.sb, sb::CHECKSUM) != crc32c(!0, sub(&self.sb, 0..sb::CHECKSUM)) {
                    return Err(Errno::EINVAL);
                }
                self.csum = Csum::Crc32c;
                self.csum_seed = if incompat & INCOMPAT_CSUM_SEED != 0 {
                    get32(&self.sb, sb::CHECKSUM_SEED)
                } else {
                    crc32c(!0, sub(&self.sb, sb::UUID..sb::UUID + 16))
                };
            } else if ro & RO_COMPAT_GDT_CSUM != 0 {
                self.csum = Csum::Crc16;
            }
        }
        let per_group = get32(&self.sb, sb::BLOCKS_PER_GROUP);
        let inodes_per_group = get32(&self.sb, sb::INODES_PER_GROUP);
        let blocks = self.blocks_count();
        let first = get32(&self.sb, sb::FIRST_DATA_BLOCK) as u64;
        if self.inode_size < 128 || !self.inode_size.is_power_of_two() || self.inode_size > self.block_size {
            return Err(Errno::EINVAL);
        }
        // Each group's bitmaps are one block, and every count a whole
        // number of bitmap bytes.
        let bits = 8 * self.block_size as u32;
        if per_group == 0 || per_group > bits || per_group % 8 != 0 {
            return Err(Errno::EINVAL);
        }
        if inodes_per_group == 0 || inodes_per_group > bits || inodes_per_group % 8 != 0 {
            return Err(Errno::EINVAL);
        }
        // Bounding the size by the device bounds the descriptor table too.
        let dev_blocks = self.dev.num_blocks().saturating_mul(dev_bs as u64) / self.block_size as u64;
        if blocks <= first || blocks > dev_blocks {
            return Err(Errno::EINVAL);
        }
        let groups = (blocks - first).div_ceil(per_group as u64);
        if groups > u32::MAX as u64 || get32(&self.sb, sb::INODES_COUNT) as u64 != groups * inodes_per_group as u64 {
            return Err(Errno::EINVAL);
        }
        self.group_count = groups as u32;
        self.gdt_block = first + 1;
        let len = self.group_count as usize * self.desc_size;
        self.groups.try_reserve_exact(len).map_err(|_| Errno::ENOMEM)?;
        self.groups.resize(len, 0);
        // A descriptor block at a time, since `meta_bg` scatters them.
        let per_block = (self.block_size / self.desc_size) as u32;
        for first in (0..self.group_count).step_by(per_block as usize) {
            let n = per_block.min(self.group_count - first) as usize * self.desc_size;
            let mut descs = try_zeroed(n)?;
            self.read_bytes(self.desc_offset(first), &mut descs)?;
            let start = first as usize * self.desc_size;
            put_bytes(&mut self.groups, start, &descs)?;
        }
        if self.csum != Csum::None
            && (0..self.group_count).any(|g| self.group_csum(g) != get16(self.desc(g), gd::CHECKSUM))
        {
            return Err(Errno::EINVAL);
        }
        self.check_layout()?;
        self.meta_zones = self.compute_meta_zones()?;
        Ok(())
    }

    /// The node for `ino`. `spare` is the memory for a new one, if the caller
    /// reserved it first (so that nothing can fail once an inode exists).
    fn node(
        &mut self,
        shared: &Arc<Shared<D>>,
        ino: u32,
        spare: Option<Arc<MaybeUninit<Node<D>>>>,
    ) -> Result<Arc<dyn File>, Errno> {
        if let Some(node) = self.nodes.find(&ino).and_then(|n| n.me.get()?.upgrade()) {
            return Ok(node);
        }
        // Only the root is reachable among the reserved inodes (the journal,
        // the resize inode and the like), and nothing is past the last one.
        if ino == 0 || ino > get32(&self.sb, sb::INODES_COUNT) || (ino < self.first_ino && ino != ROOT_INO) {
            return Err(Errno::EIO);
        }
        let slot = match spare {
            Some(slot) => slot,
            None => try_arc_uninit()?,
        };
        let node = init_arc(
            slot,
            Node { shared: shared.clone(), ino, me: Once::new(), link: SharedLink::new(TreeLink::new()) },
        );
        let _ = node.me.set(Arc::downgrade(&node));
        // One whose last reference is going (its `Drop` waits for this lock)
        // may still be indexed: this node replaces it.
        self.nodes.take(&ino);
        // SAFETY: the node takes itself out when dropped, and its inode
        // number never changes.
        let indexed = unsafe { self.nodes.insert(&node) };
        // The key was just freed, so this holds.
        if !indexed {
            return Err(Errno::EIO);
        }
        Ok(node)
    }

    /// Undoes what the operation in progress changed: drops its transaction
    /// and re-reads the superblock and descriptors, which memory holds ahead
    /// of the disk. Allocates nothing, so it works when memory has run out.
    fn abort(&mut self) {
        self.tx.clear();
        self.tx_freed.clear();
        if self.reload_metadata().is_err() {
            // Memory is ahead of the disk and cannot be put right.
            self.read_only = true;
            if let Some(journal) = &mut self.journal {
                journal.failed = true;
            }
        }
    }

    fn reload_metadata(&mut self) -> Result<(), Errno> {
        let mut sbuf = core::mem::take(&mut self.sb);
        let result = self.dev_read_bytes(SUPERBLOCK_OFFSET, &mut sbuf);
        self.sb = sbuf;
        result?;
        if self.journal.is_some() {
            // As at mount: the superblock the journal logs says it is in use.
            let flags = get32(&self.sb, sb::FEATURE_INCOMPAT) | INCOMPAT_RECOVER;
            put32(&mut self.sb, sb::FEATURE_INCOMPAT, flags);
        }
        let mut groups = core::mem::take(&mut self.groups);
        let per_block = (self.block_size / self.desc_size) as u32;
        let mut result = Ok(());
        for first in (0..self.group_count).step_by(per_block as usize) {
            let n = per_block.min(self.group_count - first) as usize * self.desc_size;
            let start = first as usize * self.desc_size;
            result = match groups.get_mut(start..start + n) {
                Some(dst) => self.read_bytes(self.desc_offset(first), dst),
                None => Err(Errno::EIO),
            };
            if result.is_err() {
                break;
            }
        }
        self.groups = groups;
        result
    }

    fn writable(&self) -> Result<(), Errno> {
        if self.read_only { Err(Errno::EROFS) } else { Ok(()) }
    }

    fn now(&self) -> u32 {
        // Times are 32 bits here: before 1970 and after 2106 saturate.
        self.clock.now().sec.clamp(0, u32::MAX as i64) as u32
    }

    // ---- Raw I/O ----

    /// Reads bytes at any offset, seeing what the operation in progress has
    /// changed.
    fn read_bytes(&mut self, off: u64, buf: &mut [u8]) -> Result<(), Errno> {
        if self.tx.is_empty() {
            return self.dev_read_bytes(off, buf);
        }
        let bs = self.block_size as u64;
        let mut done = 0;
        while done < buf.len() {
            let pos = off.checked_add(done as u64).ok_or(Errno::EIO)?;
            let (b, skip) = (pos / bs, (pos % bs) as usize);
            let n = (bs as usize - skip).min(buf.len() - done);
            let dst = buf.get_mut(done..done + n).ok_or(Errno::EIO)?;
            match self.tx.find(&b) {
                Some(block) => dst.copy_from_slice(block.bytes().get(skip..skip + n).ok_or(Errno::EIO)?),
                None => self.dev_read_bytes(pos, dst)?,
            }
            done += n;
        }
        Ok(())
    }

    /// Writes metadata bytes at any offset, into the operation's
    /// transaction: they reach the disk when the operation ends.
    fn write_bytes(&mut self, off: u64, buf: &[u8]) -> Result<(), Errno> {
        let bs = self.block_size as u64;
        let mut done = 0;
        while done < buf.len() {
            let pos = off.checked_add(done as u64).ok_or(Errno::EIO)?;
            let (b, skip) = (pos / bs, (pos % bs) as usize);
            let n = (bs as usize - skip).min(buf.len() - done);
            if self.tx.find(&b).is_none() {
                let block = self.dev_read_block(b)?;
                let node = TxBlock::from_vec(b, block)?;
                // Not logged until now, so the insert cannot collide.
                self.tx.insert(node).map_err(|_| Errno::EIO)?;
            }
            if let Some(block) = self.tx_block_mut(b) {
                put_bytes(block, skip, buf.get(done..done + n).ok_or(Errno::EIO)?)?;
            }
            done += n;
        }
        Ok(())
    }

    /// The contents of the block the operation has logged, to change.
    fn tx_block_mut(&mut self, b: u64) -> Option<&mut [u8]> {
        let node = self.tx.find(&b)?;
        // SAFETY: the data is only reachable through the file system, which
        // the caller has exclusively (`&mut self`) while the result lives.
        Some(unsafe { &mut *node.data.get() })
    }

    /// Reads bytes at any offset straight from the device, a device block
    /// at a time.
    fn dev_read_bytes(&mut self, off: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let bs = self.dev.block_size() as u64;
        if bs == 0 {
            return Err(Errno::EIO);
        }
        // The scratch block is out of `self` while it is used.
        let mut tmp = core::mem::take(&mut self.bounce);
        if tmp.len() != bs as usize {
            tmp = try_zeroed(bs as usize)?;
        }
        let result = (|| {
            let mut done = 0;
            while done < buf.len() {
                let pos = off.checked_add(done as u64).ok_or(Errno::EIO)?;
                let (lba, skip) = (pos / bs, (pos % bs) as usize);
                let n = (bs as usize - skip).min(buf.len() - done);
                self.dev.read_blocks(lba, &mut tmp).map_err(io_error)?;
                let src = tmp.get(skip..skip + n).ok_or(Errno::EIO)?;
                buf.get_mut(done..done + n).ok_or(Errno::EIO)?.copy_from_slice(src);
                done += n;
            }
            Ok(())
        })();
        self.bounce = tmp;
        result
    }

    /// Writes bytes at any offset straight to the device, as one request so
    /// that a crash does not leave half of them, reading back the device
    /// blocks at its ends that the bytes only partly cover.
    fn dev_write_bytes(&mut self, off: u64, buf: &[u8]) -> Result<(), Errno> {
        if buf.is_empty() {
            return Ok(());
        }
        let bs = self.dev.block_size() as u64;
        if bs == 0 {
            return Err(Errno::EIO);
        }
        let end = off.checked_add(buf.len() as u64).ok_or(Errno::EIO)?;
        let (first, last) = (off / bs, (end - 1) / bs);
        let len = usize::try_from((last - first + 1).checked_mul(bs).ok_or(Errno::EIO)?).map_err(|_| Errno::EIO)?;
        // The scratch reserved for the superblock does for that; anything
        // bigger needs memory of its own.
        let mut tmp = core::mem::take(&mut self.write_scratch);
        if tmp.len() < len {
            tmp = try_zeroed(len)?;
        }
        let result = (|| {
            let tmp = tmp.get_mut(..len).ok_or(Errno::EIO)?;
            let skip = (off % bs) as usize;
            if skip != 0 || buf.len() < len {
                self.dev.read_blocks(first, tmp.get_mut(..bs as usize).ok_or(Errno::EIO)?).map_err(io_error)?;
                let tail = len - bs as usize;
                self.dev.read_blocks(last, tmp.get_mut(tail..).ok_or(Errno::EIO)?).map_err(io_error)?;
            }
            put_bytes(tmp, skip, buf)?;
            self.dev.write_blocks(first, tmp).map_err(io_error)
        })();
        self.write_scratch = tmp;
        result
    }

    /// Whether block `b` lies in a metadata zone found by `check_layout`.
    fn in_meta_zone(&self, b: u64) -> bool {
        let i = self.meta_zones.partition_point(|&(start, _)| start <= b);
        i > 0 && self.meta_zones.get(i - 1).is_some_and(|&(_, end)| b < end)
    }

    /// Whether any block in `start..end` lies in a metadata zone.
    fn meta_overlaps(&self, start: u64, end: u64) -> bool {
        let i = self.meta_zones.partition_point(|&(zs, _)| zs < end);
        i > 0 && self.meta_zones.get(i - 1).is_some_and(|&(_, ze)| ze > start)
    }

    /// The merged metadata zones: every group's superblock backup and
    /// descriptors, bitmaps and inode table.
    fn compute_meta_zones(&self) -> Result<Vec<(u64, u64)>, Errno> {
        let itable =
            (get32(&self.sb, sb::INODES_PER_GROUP) as u64 * self.inode_size as u64).div_ceil(self.block_size as u64);
        let mut zones = Vec::new();
        zones.try_reserve_exact(self.group_count as usize * 4).map_err(|_| Errno::ENOMEM)?;
        for g in 0..self.group_count {
            let start = self.group_start(g);
            zones.push((start, start.saturating_add(self.base_meta_blocks(g))));
            for (field, len) in [(gd::BLOCK_BITMAP, 1), (gd::INODE_BITMAP, 1), (gd::INODE_TABLE, itable)] {
                let loc = self.group_get(g, field);
                zones.push((loc, loc.saturating_add(len)));
            }
        }
        zones.retain(|&(start, end)| start < end);
        zones.sort_unstable();
        // Merged in place: the merged list is never longer.
        let mut merged = 0usize;
        for i in 0..zones.len() {
            let Some(&(start, end)) = zones.get(i) else { break };
            if let Some(last) = merged.checked_sub(1).and_then(|m| zones.get_mut(m))
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                if let Some(slot) = zones.get_mut(merged) {
                    *slot = (start, end);
                }
                merged += 1;
            }
        }
        zones.truncate(merged);
        Ok(zones)
    }

    /// Reads a data, directory, indirect or extent block; refuses metadata
    /// zones, which only a corrupt image would name.
    fn read_block(&mut self, b: u64) -> Result<Vec<u8>, Errno> {
        if self.in_meta_zone(b) {
            return Err(Errno::EIO);
        }
        self.read_raw_block(b)
    }

    fn read_raw_block(&mut self, b: u64) -> Result<Vec<u8>, Errno> {
        if b == 0 || b >= self.blocks_count() {
            return Err(Errno::EIO);
        }
        match self.tx.find(&b) {
            Some(block) => Ok(try_to_vec(block.bytes())?),
            None => self.dev_read_block(b),
        }
    }

    fn dev_read_block(&mut self, b: u64) -> Result<Vec<u8>, Errno> {
        let mut buf = try_zeroed(self.block_size)?;
        self.dev.read_blocks(b.checked_mul(self.dev_per_block).ok_or(Errno::EIO)?, &mut buf).map_err(io_error)?;
        Ok(buf)
    }

    fn dev_write_block(&mut self, b: u64, buf: &[u8]) -> Result<(), Errno> {
        self.dev.write_blocks(b.checked_mul(self.dev_per_block).ok_or(Errno::EIO)?, buf).map_err(io_error)
    }

    /// Writes a directory, indirect or extent block; refuses metadata
    /// zones, so a crafted image cannot make a write clobber them.
    fn write_block(&mut self, b: u64, buf: &[u8]) -> Result<(), Errno> {
        if self.in_meta_zone(b) {
            return Err(Errno::EIO);
        }
        self.write_raw_block(b, buf)
    }

    /// Writes a block of file data, in place even when journaled: the
    /// transaction that makes it reachable commits after it.
    fn write_data_block(&mut self, b: u64, buf: &[u8]) -> Result<(), Errno> {
        if self.in_meta_zone(b) || b == 0 || b >= self.blocks_count() {
            return Err(Errno::EIO);
        }
        self.dev_write_block(b, buf)
    }

    /// Writes a metadata block, into the operation's transaction.
    fn write_raw_block(&mut self, b: u64, buf: &[u8]) -> Result<(), Errno> {
        if b == 0 || b >= self.blocks_count() {
            return Err(Errno::EIO);
        }
        if buf.len() != self.block_size {
            return Err(Errno::EIO);
        }
        match self.tx_block_mut(b) {
            Some(logged) => put_bytes(logged, 0, buf)?,
            None => {
                let node = TxBlock::new(b, buf)?;
                // Not logged, as just seen, so the insert cannot collide.
                self.tx.insert(node).map_err(|_| Errno::EIO)?;
            }
        }
        Ok(())
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
        let v = (self.free_blocks() as i64).wrapping_add(delta) as u64;
        put32(&mut self.sb, sb::FREE_BLOCKS, v as u32);
        if self.wide {
            put32(&mut self.sb, sb::FREE_BLOCKS_HI, (v >> 32) as u32);
        }
    }

    fn adjust_super(&mut self, field: usize, delta: i32) {
        let v = (get32(&self.sb, field) as i64).wrapping_add(delta as i64);
        put32(&mut self.sb, field, v as u32);
    }

    fn write_super(&mut self) -> Result<(), Errno> {
        let now = self.now();
        put32(&mut self.sb, sb::WTIME, now);
        if self.csum == Csum::Crc32c {
            let sum = crc32c(!0, sub(&self.sb, 0..sb::CHECKSUM));
            put32(&mut self.sb, sb::CHECKSUM, sum);
        }
        let sbuf = core::mem::take(&mut self.sb);
        let result = self.write_bytes(SUPERBLOCK_OFFSET, &sbuf);
        self.sb = sbuf;
        result
    }

    fn desc(&self, g: u32) -> &[u8] {
        let start = g as usize * self.desc_size;
        sub(&self.groups, start..start + self.desc_size)
    }

    fn group_csum(&self, g: u32) -> u16 {
        let d = self.desc(g);
        let rest = d.get(gd::CHECKSUM + 2..).unwrap_or(&[]);
        match self.csum {
            Csum::None => 0,
            Csum::Crc16 => {
                let mut crc = crc16(!0, sub(&self.sb, sb::UUID..sb::UUID + 16));
                crc = crc16(crc, &g.to_le_bytes());
                crc = crc16(crc, sub(d, 0..gd::CHECKSUM));
                crc16(crc, rest)
            }
            Csum::Crc32c => {
                let mut crc = crc32c(self.csum_seed, &g.to_le_bytes());
                crc = crc32c(crc, sub(d, 0..gd::CHECKSUM));
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
        let desc = try_to_vec(self.desc(g))?;
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
        block.saturating_mul(self.block_size as u64).saturating_add((i as usize * self.desc_size) as u64)
    }

    /// Checks that the primary superblock and descriptors fit in group 0,
    /// and that every group's bitmaps and inode table lie past them and
    /// inside the file system, as Linux's `ext4_check_descriptors` does.
    fn check_layout(&self) -> Result<(), Errno> {
        if self.base_meta_blocks(0) >= self.group_blocks(0) {
            return Err(Errno::EINVAL);
        }
        let meta_end = self.group_start(0) + self.base_meta_blocks(0);
        let itable =
            (get32(&self.sb, sb::INODES_PER_GROUP) as u64 * self.inode_size as u64).div_ceil(self.block_size as u64);
        for g in 0..self.group_count {
            for (field, len) in [(gd::BLOCK_BITMAP, 1), (gd::INODE_BITMAP, 1), (gd::INODE_TABLE, itable)] {
                let loc = self.group_get(g, field);
                if loc < meta_end || loc.checked_add(len).is_none_or(|end| end > self.blocks_count()) {
                    return Err(Errno::EINVAL);
                }
            }
        }
        Ok(())
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
        let Some(d) = self.groups.get_mut(start..start + self.desc_size) else { return };
        let mut put = |off, v: u64| if width == 4 { put32(d, off, v as u32) } else { put16(d, off, v as u16) };
        put(lo, v);
        if hi + width <= self.desc_size {
            put(hi, v >> (8 * width));
        }
    }

    fn adjust_group(&mut self, g: u32, field: gd::Field, delta: i64) {
        let v = (self.group_get(g, field) as i64).wrapping_add(delta) as u64;
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
        (get32(&self.sb, sb::BLOCKS_PER_GROUP) as u64).min(self.blocks_count().saturating_sub(self.group_start(g)))
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
        let power_of = |base: u64| {
            let mut n = 1u64;
            while n < g as u64 {
                n *= base;
            }
            n == g as u64
        };
        g == 1 || power_of(3) || power_of(5) || power_of(7)
    }

    // ---- Checksums ----

    /// The seed of an inode's own checksums (inode, extent tree,
    /// directory blocks).
    fn inode_seed(&self, ino: u32, inode: &Inode) -> u32 {
        crc32c(crc32c(self.csum_seed, &ino.to_le_bytes()), &inode.generation().to_le_bytes())
    }

    fn inode_csum(&self, ino: u32, inode: &Inode) -> Result<u32, Errno> {
        let mut raw = try_to_vec(&inode.raw)?;
        put16(&mut raw, ino::CHECKSUM_LO, 0);
        if inode.has_checksum_hi() {
            put16(&mut raw, ino::CHECKSUM_HI, 0);
        }
        Ok(crc32c(self.inode_seed(ino, inode), &raw))
    }

    fn bitmap_csum(&self, kind: Bitmap, bits: &[u8]) -> u32 {
        let per_group = match kind {
            Bitmap::Block => get32(&self.sb, sb::BLOCKS_PER_GROUP),
            Bitmap::Inode => get32(&self.sb, sb::INODES_PER_GROUP),
        };
        crc32c(self.csum_seed, sub(bits, 0..per_group as usize / 8))
    }

    /// Whether a directory block ends in a checksum tail.
    fn has_dir_tail(&self, data: &[u8]) -> bool {
        let t = data.len().saturating_sub(DIR_TAIL_LEN);
        self.csum == Csum::Crc32c
            && data.len() >= DIR_TAIL_LEN
            && get32(data, t) == 0
            && get16(data, t + 4) as usize == DIR_TAIL_LEN
            && byte(data, t + 6) == 0
            && byte(data, t + 7) == DIR_TAIL_TYPE
    }

    /// The bytes of a directory block that hold records.
    fn dir_space(&self, data: &[u8]) -> usize {
        if self.has_dir_tail(data) { data.len() - DIR_TAIL_LEN } else { data.len() }
    }

    /// A new, empty directory block and the bytes free for records in it.
    fn new_dir_block(&self) -> Result<(Vec<u8>, usize), Errno> {
        let mut data = try_zeroed(self.block_size)?;
        if self.csum != Csum::Crc32c {
            return Ok((data, self.block_size));
        }
        let t = self.block_size - DIR_TAIL_LEN;
        put16(&mut data, t + 4, DIR_TAIL_LEN as u16);
        put_bytes(&mut data, t + 7, &[DIR_TAIL_TYPE])?;
        Ok((data, t))
    }

    /// Writes a block of directory `dir`, checksumming its tail.
    fn write_dir_block(&mut self, dir: u32, b: u64, data: &mut [u8]) -> Result<(), Errno> {
        if self.has_dir_tail(data) {
            let inode = self.read_inode(dir)?;
            let seed = self.inode_seed(dir, &inode);
            let t = data.len() - DIR_TAIL_LEN;
            let sum = crc32c(seed, sub(data, 0..t));
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
        table
            .checked_mul(self.block_size as u64)
            .and_then(|at| at.checked_add(i as u64 * self.inode_size as u64))
            .ok_or(Errno::EIO)
    }

    fn read_inode(&mut self, ino: u32) -> Result<Inode, Errno> {
        let off = self.inode_offset(ino)?;
        let mut raw = try_zeroed(self.inode_size)?;
        self.read_bytes(off, &mut raw)?;
        let inode = Inode { raw };
        if self.csum == Csum::Crc32c {
            let sum = self.inode_csum(ino, &inode)?;
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
        let sum = self.inode_csum(ino, inode)?;
        let mut raw = try_to_vec(&inode.raw)?;
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
            return self.init_bitmap(g, kind);
        }
        let bits = self.read_raw_block(self.group_get(g, loc))?;
        if self.csum == Csum::Crc32c {
            let wide = csum.1 + csum.2 <= self.desc_size;
            let mask = if wide { u32::MAX } else { 0xffff };
            if self.bitmap_csum(kind, &bits) & mask != self.group_get(g, csum) as u32 {
                return Err(Errno::EIO);
            }
        }
        Ok(bits)
    }

    fn init_bitmap(&self, g: u32, kind: Bitmap) -> Result<Vec<u8>, Errno> {
        let mut bits = try_zeroed(self.block_size)?;
        let used = match kind {
            Bitmap::Block => self.group_blocks(g) as usize,
            Bitmap::Inode => get32(&self.sb, sb::INODES_PER_GROUP) as usize,
        };
        set_bits(&mut bits, used, 8 * self.block_size - used);
        if kind == Bitmap::Inode {
            return Ok(bits);
        }
        let start = self.group_start(g);
        set_bits(&mut bits, 0, (self.base_meta_blocks(g) as usize).min(used));
        // Under flex_bg any group's bitmaps and inode table may live here.
        let itable = (get32(&self.sb, sb::INODES_PER_GROUP) as usize * self.inode_size).div_ceil(self.block_size);
        for h in 0..self.group_count {
            for (field, len) in [(gd::BLOCK_BITMAP, 1), (gd::INODE_BITMAP, 1), (gd::INODE_TABLE, itable as u64)] {
                let loc = self.group_get(h, field);
                let (from, to) = (loc.max(start), loc.saturating_add(len).min(start + used as u64));
                if from < to {
                    set_bits(&mut bits, (from - start) as usize, (to - from) as usize);
                }
            }
        }
        Ok(bits)
    }

    /// Writes a group's bitmap back, marking it initialized and updating
    /// its checksum; the caller writes the group descriptor.
    fn store_bitmap(&mut self, g: u32, kind: Bitmap, bits: &[u8]) -> Result<(), Errno> {
        let (loc, csum, flag) = match kind {
            Bitmap::Block => (gd::BLOCK_BITMAP, gd::BLOCK_BITMAP_CSUM, BG_BLOCK_UNINIT),
            Bitmap::Inode => (gd::INODE_BITMAP, gd::INODE_BITMAP_CSUM, BG_INODE_UNINIT),
        };
        self.write_raw_block(self.group_get(g, loc), bits)?;
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
        let start = self.group_start(g);
        let reusable = |i: u32| kind == Bitmap::Inode || !self.freed_in_tx(start + i as u64);
        let clear = |i: u32| bits.get(i as usize / 8).is_some_and(|b| b & (1 << (i % 8)) == 0) && reusable(i);
        let Some(index) = (from.min(limit)..limit).chain(0..from.min(limit)).find(|&i| clear(i)) else {
            return Ok(None);
        };
        or_byte(&mut bits, index as usize / 8, 1 << (index % 8))?;
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
        // `per_group` was checked at mount, but never divide by a field of the image unchecked.
        let (goal_g, goal_i) =
            (goal.checked_div(per_group).unwrap_or(0) as u32, goal.checked_rem(per_group).unwrap_or(0) as u32);
        for k in 0..self.group_count {
            let g = ((goal_g as u64 + k as u64) % self.group_count as u64) as u32;
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
                let b = self.group_start(g).saturating_add(i as u64);
                let zero = try_zeroed(self.block_size)?;
                self.write_data_block(b, &zero)?;
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
        if start < first || end > self.blocks_count() || self.meta_overlaps(start, end) {
            return Err(Errno::EIO);
        }
        {
            // What the operation had logged for these blocks must not
            // overwrite them if they are allocated again.
            let freed = try_arc(Freed { start, end, link: SharedLink::new(TreeLink::new()) })?;
            while let Some(b) = self.tx.lower_bound(&start).map(|t| t.blk).filter(|&b| b < end) {
                drop(self.tx.take_key(&b));
            }
            drop(self.tx_freed.take_key(&start));
            // The start was just freed, so the insert cannot collide.
            self.tx_freed.insert(freed).map_err(|_| Errno::EIO)?;
        }
        let mut b = start;
        while b < end {
            let (g, i) = (((b - first) / per_group) as u32, (b - first) % per_group);
            let n = (per_group - i).min(end - b);
            let mut bits = self.load_bitmap(g, Bitmap::Block)?;
            for j in i..i + n {
                let byte = bits.get_mut(j as usize / 8).ok_or(Errno::EIO)?;
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

    /// Whether the operation in progress has freed block `b`.
    fn freed_in_tx(&self, b: u64) -> bool {
        self.tx_freed.floor(&b).is_some_and(|f| b < f.end)
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
            let g = ((goal as u64 + k as u64) % self.group_count as u64) as u32;
            if self.group_get(g, gd::FREE_INODES) == 0 {
                continue;
            }
            let Some(i) = self.take_bit(g, Bitmap::Inode, 0, per_group)? else { continue };
            let ino = g.saturating_mul(per_group).saturating_add(i).saturating_add(1);
            if ino < self.first_ino {
                // A reserved inode marked free: the bitmap is corrupt. Put
                // the bit back as it was; no counter has changed yet.
                let mut bits = self.load_bitmap(g, Bitmap::Inode)?;
                *bits.get_mut(i as usize / 8).ok_or(Errno::EIO)? &= !(1 << (i % 8));
                self.store_bitmap(g, Bitmap::Inode, &bits)?;
                return Err(Errno::EIO);
            }
            self.adjust_group(g, gd::FREE_INODES, -1);
            self.adjust_super(sb::FREE_INODES, -1);
            if kind_of(mode) == FileKind::Directory {
                self.adjust_group(g, gd::USED_DIRS, 1);
            }
            // The inode table past the last inode ever used may be garbage.
            if self.csum != Csum::None
                && i as u64 >= (per_group as u64).saturating_sub(self.group_get(g, gd::ITABLE_UNUSED))
            {
                self.group_set(g, gd::ITABLE_UNUSED, (per_group - i - 1) as u64);
            }
            self.write_group(g)?;
            self.write_super()?;
            let mut inode = Inode { raw: try_zeroed(self.inode_size)? };
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
        if self.has_block_map(&inode) {
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
        let now = self.now().max(get32(&self.sb, sb::INODES_COUNT).saturating_add(1));
        inode.set_times(now, &[ino::DTIME]);
        inode.set_size(0);
        self.write_inode(ino, &inode)?;
        let per_group = get32(&self.sb, sb::INODES_PER_GROUP);
        let (g, i) = ((ino - 1) / per_group, (ino - 1) % per_group);
        let mut bits = self.load_bitmap(g, Bitmap::Inode)?;
        let byte = bits.get_mut(i as usize / 8).ok_or(Errno::EIO)?;
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
        ino.saturating_sub(1).checked_div(get32(&self.sb, sb::INODES_PER_GROUP)).unwrap_or(0)
    }

    // ---- Block maps ----

    /// Whether the inode's `i_block` is a block map or extent tree. Device
    /// inodes keep their number there and fast symbolic links their target.
    fn has_block_map(&self, inode: &Inode) -> bool {
        matches!(inode.kind(), FileKind::Regular | FileKind::Directory | FileKind::Symlink) && !self.is_inline(inode)
    }

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
        let (slot, path, depth): (usize, [u64; 3], usize) = if lblk < NDIR_BLOCKS as u64 {
            (lblk as usize, [0; 3], 0)
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
            let mut path = [0u64; 3];
            for slot in path.iter_mut().take(depth as usize).rev() {
                *slot = rest % per;
                rest /= per;
            }
            (NDIR_BLOCKS + depth as usize - 1, path, depth as usize)
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
        for &index in path.iter().take(depth) {
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
        inode.add_sectors(-((freed.saturating_mul((self.block_size / 512) as u64)).min(i64::MAX as u64) as i64));
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
        if !matches!(inode.kind(), FileKind::Regular | FileKind::Directory | FileKind::Symlink) {
            return Err(Errno::EINVAL);
        }
        if self.is_inline(&inode) {
            // The target must fit the 60-byte block map.
            if size >= 60 {
                return Err(Errno::EIO);
            }
            let start = ino::BLOCK + off as usize;
            let src = inode.raw.get(start..start + len).ok_or(Errno::EIO)?;
            buf.get_mut(..len).ok_or(Errno::EIO)?.copy_from_slice(src);
            return Ok(len);
        }
        let bs = self.block_size as u64;
        let mut done = 0;
        while done < len {
            let pos = off.checked_add(done as u64).ok_or(Errno::EIO)?;
            let skip = (pos % bs) as usize;
            let n = (bs as usize - skip).min(len - done);
            let b = self.bmap(ino, &mut inode, pos / bs, false)?;
            let dst = buf.get_mut(done..done + n).ok_or(Errno::EIO)?;
            if b == 0 {
                dst.fill(0);
            } else {
                let block = self.read_block(b)?;
                dst.copy_from_slice(block.get(skip..skip + n).ok_or(Errno::EIO)?);
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
            fill_range(&mut inode.raw, ino::BLOCK..ino::BLOCK + 60, 0)?;
            put_bytes(&mut inode.raw, ino::BLOCK, buf)?;
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
            let pos = off.saturating_add(done as u64);
            let skip = (pos % bs) as usize;
            let n = (bs as usize - skip).min(buf.len() - done);
            let b = match self.bmap(ino, &mut inode, pos / bs, true) {
                Ok(b) => b,
                Err(e) => break Err(e),
            };
            let Some(chunk) = buf.get(done..done + n) else { break Err(Errno::EIO) };
            let step = if n == bs as usize {
                self.write_data_block(b, chunk)
            } else {
                self.read_block(b).and_then(|mut block| {
                    put_bytes(&mut block, skip, chunk)?;
                    self.write_data_block(b, &block)
                })
            };
            if let Err(e) = step {
                break Err(e);
            }
            done += n;
        };
        // Out of memory part way may have left a block allocated but not
        // mapped: report it, so that the operation is undone as a whole (see
        // `Fs::transact`), rather than recording a short write over that.
        if result == Err(Errno::ENOMEM) {
            return Err(Errno::ENOMEM);
        }
        let new_end = off.saturating_add(done as u64);
        if new_end > inode.size() {
            inode.set_size(new_end);
            self.note_file_size(new_end)?;
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

    /// Sets RO_COMPAT_LARGE_FILE (and persists the superblock) before a file
    /// first grows past 2 GiB.
    fn note_file_size(&mut self, size: u64) -> Result<(), Errno> {
        if size > i32::MAX as u64 && get32(&self.sb, sb::FEATURE_RO_COMPAT) & RO_COMPAT_LARGE_FILE == 0 {
            let ro = get32(&self.sb, sb::FEATURE_RO_COMPAT) | RO_COMPAT_LARGE_FILE;
            put32(&mut self.sb, sb::FEATURE_RO_COMPAT, ro);
            self.write_super()?;
        }
        Ok(())
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
                    let tail = (len % bs) as usize;
                    fill_range(&mut block, tail..self.block_size, 0)?;
                    self.write_data_block(b, &block)?;
                }
            }
        } else if len > 0 && (len - 1) / bs >= self.max_blocks(&inode) {
            // Beyond what the block map or extent tree can reach.
            return Err(Errno::EFBIG);
        }
        self.note_file_size(len)?;
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
                if get32(&data, t + 8) != crc32c(seed, sub(&data, 0..t)) {
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
        if off.checked_add(8).is_none_or(|end| end > data.len()) {
            return Err(Errno::EIO);
        }
        let ino = get32(data, off);
        let rec_len = get16(data, off + 4) as usize;
        let name_len = if self.filetype { byte(data, off + 6) as usize } else { get16(data, off + 6) as usize };
        if rec_len % 4 != 0 || rec_len < rec_len_for(name_len) || off + rec_len > data.len() {
            return Err(Errno::EIO);
        }
        let name = data.get(off + 8..off + 8 + name_len).ok_or(Errno::EIO)?;
        Ok((ino, rec_len, name))
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
                // A name that could not be a path component is skipped, as
                // lookups could never reach it.
                if ino == 0
                    || name == b"."
                    || name == b".."
                    || name.is_empty()
                    || name.contains(&b'/')
                    || name.contains(&0)
                {
                    continue;
                }
                if seen == index {
                    let name = lossy(name)?;
                    let ftype = if fs.filetype { byte(data, off - rec_len + 7) } else { 0 };
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
            let _ = put_bytes(data, off + 6, &[name.len() as u8, dirent_type(kind)]);
        } else {
            put16(data, off + 6, name.len() as u16);
        }
        // The caller sized the record for the name; a record that does not fit is left unwritten.
        let _ = put_bytes(data, off + 8, name.as_bytes());
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
            fill_range(data, last + used..t + DIR_TAIL_LEN, 0)?;
            put16(data, t + 4, DIR_TAIL_LEN as u16);
            put_bytes(data, t + 7, &[DIR_TAIL_TYPE])?;
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
        // A size that is not a block multiple still ends in a partial block.
        let next = inode.size().div_ceil(self.block_size as u64);
        let b = self.bmap(dir, &mut inode, next, true)?;
        inode.set_size(next.saturating_add(1).saturating_mul(self.block_size as u64));
        self.write_inode(dir, &inode)?;
        let (mut data, space) = self.new_dir_block()?;
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
        // Judge on raw records: an entry `dir_entry` hides (an odd name)
        // still keeps the directory from being removed.
        let found = self.scan_dir(dir, |fs, _, data| {
            let (mut off, space) = (0, fs.dir_space(data));
            while off < space {
                let (ino, rec_len, name) = fs.record(data, off)?;
                if ino != 0 && name != b"." && name != b".." {
                    return Ok(Some(()));
                }
                off += rec_len;
            }
            Ok(None)
        })?;
        Ok(found.is_none())
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
        let goal = if kind == FileKind::Directory {
            dir.wrapping_add(1) % self.group_count.max(1)
        } else {
            self.group_of(dir)
        };
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
            let (mut data, space) = self.new_dir_block()?;
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
            let links = parent.links().saturating_add(1);
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
        let open = self.nodes.find(&ino).is_some_and(|n| n.me.get().is_some_and(|w| w.strong_count() > 0));
        if inode.links() == 0 && !open {
            self.free_inode(ino)?;
        }
        Ok(())
    }

    /// Checks a name for a new entry.
    fn check_new_name(name: &str) -> Result<(), Errno> {
        if name.len() > NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    /// A directory that can take new entries: `ENOTDIR`, or `ENOENT` if it
    /// has been removed.
    fn live_dir(&mut self, dir: u32) -> Result<Inode, Errno> {
        let parent = self.read_inode(dir)?;
        if parent.kind() != FileKind::Directory {
            return Err(Errno::ENOTDIR);
        }
        if parent.links() == 0 {
            return Err(Errno::ENOENT);
        }
        Ok(parent)
    }

    /// Adds the entry `name` in `dir` for the existing non-directory `ino`.
    fn link(&mut self, dir: u32, name: &str, ino: u32) -> Result<(), Errno> {
        self.writable()?;
        Self::check_new_name(name)?;
        self.live_dir(dir)?;
        let mut inode = self.read_inode(ino)?;
        let kind = inode.kind();
        if kind == FileKind::Directory {
            return Err(Errno::EPERM);
        }
        // An unlinked file stays unlinked (it may already be queued to be freed).
        if inode.links() == 0 {
            return Err(Errno::ENOENT);
        }
        if inode.links() >= LINK_MAX {
            return Err(Errno::EMLINK);
        }
        if self.find_entry(dir, name)?.is_some() {
            return Err(Errno::EEXIST);
        }
        self.add_entry(dir, name, ino, kind)?;
        let now = self.now();
        inode.set_links(inode.links() + 1);
        inode.set_times(now, &[ino::CTIME]);
        self.write_inode(ino, &inode)?;
        // Adding the entry may have grown the directory.
        let mut parent = self.read_inode(dir)?;
        parent.set_times(now, &[ino::MTIME, ino::CTIME]);
        self.write_inode(dir, &parent)
    }

    /// Points directory `ino`'s `..` entry at `parent`.
    fn set_dotdot(&mut self, ino: u32, parent: u32) -> Result<(), Errno> {
        let done = self.scan_dir(ino, |fs, b, data| {
            let (mut off, space) = (0, fs.dir_space(data));
            while off < space {
                let (used, rec_len, name) = fs.record(data, off)?;
                if used != 0 && name == b".." {
                    put32(data, off, parent);
                    fs.write_dir_block(ino, b, data)?;
                    return Ok(Some(()));
                }
                off += rec_len;
            }
            Ok(None)
        })?;
        done.ok_or(Errno::EIO)
    }

    /// Whether directory `ancestor` is `dir` or above it, by walking `..`.
    fn is_ancestor(&mut self, ancestor: u32, dir: u32) -> Result<bool, Errno> {
        let mut cur = dir;
        // A loop in a damaged image ends the walk with an error.
        for _ in 0..4096 {
            if cur == ancestor {
                return Ok(true);
            }
            if cur == ROOT_INO {
                return Ok(false);
            }
            cur = self.find_entry(cur, "..")?.ok_or(Errno::EIO)?;
        }
        Err(Errno::EIO)
    }

    /// Moves `old_dir/old_name` to `new_dir/new_name`, replacing a target as
    /// `rename(2)` does.
    fn rename(&mut self, old_dir: u32, old_name: &str, new_dir: u32, new_name: &str) -> Result<(), Errno> {
        self.writable()?;
        Self::check_new_name(new_name)?;
        if old_name == "." || old_name == ".." {
            return Err(Errno::EINVAL);
        }
        self.live_dir(old_dir)?;
        let new_parent = self.live_dir(new_dir)?;
        let ino = self.find_entry(old_dir, old_name)?.ok_or(Errno::ENOENT)?;
        let inode = self.read_inode(ino)?;
        let kind = inode.kind();
        let is_dir = kind == FileKind::Directory;
        let across = old_dir != new_dir;
        if is_dir && across && self.is_ancestor(ino, new_dir)? {
            return Err(Errno::EINVAL);
        }
        if let Some(existing) = self.find_entry(new_dir, new_name)? {
            if existing == ino {
                return Ok(());
            }
            let target_is_dir = self.read_inode(existing)?.kind() == FileKind::Directory;
            match (is_dir, target_is_dir) {
                (true, false) => return Err(Errno::ENOTDIR),
                (false, true) => return Err(Errno::EISDIR),
                _ => {}
            }
            // Fails with `ENOTEMPTY` for a directory with entries.
            self.remove(new_dir, new_name, target_is_dir)?;
        }
        let uncounted = self.dir_nlink && new_parent.links() == 1;
        if is_dir && across && !self.dir_nlink && !uncounted && self.read_inode(new_dir)?.links() >= LINK_MAX {
            return Err(Errno::EMLINK);
        }
        self.add_entry(new_dir, new_name, ino, kind)?;
        self.remove_entry(old_dir, old_name)?;
        let now = self.now();
        if is_dir && across {
            self.set_dotdot(ino, new_dir)?;
            let mut np = self.read_inode(new_dir)?;
            if !(self.dir_nlink && np.links() == 1) {
                let links = np.links().saturating_add(1);
                np.set_links(if links >= LINK_MAX && self.dir_nlink { 1 } else { links });
            }
            self.write_inode(new_dir, &np)?;
            let mut op = self.read_inode(old_dir)?;
            if op.links() > 2 {
                op.set_links(op.links() - 1);
            }
            self.write_inode(old_dir, &op)?;
        }
        let mut moved = self.read_inode(ino)?;
        moved.set_times(now, &[ino::CTIME]);
        self.write_inode(ino, &moved)?;
        for d in [old_dir, new_dir] {
            let mut p = self.read_inode(d)?;
            p.set_times(now, &[ino::MTIME, ino::CTIME]);
            self.write_inode(d, &p)?;
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
            atime: inode.time(ino::ATIME),
            mtime: inode.time(ino::MTIME),
            ctime: inode.time(ino::CTIME),
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
        self.with(|fs| fs.transact(|fs| fs.write_data(self.ino, off, buf)))
    }

    fn stat(&self) -> Stat {
        // An I/O error leaves only what is known without the disk.
        self.try_stat().unwrap_or(Stat { ino: self.ino as u64, ..Stat::default() })
    }

    fn try_stat(&self) -> Result<Stat, Errno> {
        self.with(|fs| fs.stat(self.ino))
    }

    fn truncate(&self, len: u64) -> Result<(), Errno> {
        self.with(|fs| fs.transact(|fs| fs.truncate(self.ino, len)))
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
        fs.node(&self.shared, ino, None)
    }

    fn create(&self, name: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
        let mut fs = self.shared.fs.lock();
        // Reserved first: once the inode is on disk, nothing may fail.
        let slot = try_arc_uninit()?;
        let ino = fs.transact(|fs| fs.create(self.ino, name, kind, mode))?;
        fs.node(&self.shared, ino, Some(slot))
    }

    fn remove(&self, name: &str, dir: bool) -> Result<(), Errno> {
        self.with(|fs| fs.transact(|fs| fs.remove(self.ino, name, dir)))
    }

    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

    fn link(&self, name: &str, target: &dyn File) -> Result<(), Errno> {
        let target = target.as_any().and_then(|a| a.downcast_ref::<Node<D>>()).ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&target.shared, &self.shared) {
            return Err(Errno::EXDEV);
        }
        self.with(|fs| fs.transact(|fs| fs.link(self.ino, name, target.ino)))
    }

    fn rename(&self, old_name: &str, new_dir: &dyn File, new_name: &str) -> Result<(), Errno> {
        let dst = new_dir.as_any().and_then(|a| a.downcast_ref::<Node<D>>()).ok_or(Errno::EXDEV)?;
        if !Arc::ptr_eq(&dst.shared, &self.shared) {
            return Err(Errno::EXDEV);
        }
        self.with(|fs| fs.transact(|fs| fs.rename(self.ino, old_name, dst.ino, new_name)))
    }

    fn readlink(&self) -> Result<String, Errno> {
        self.with(|fs| {
            let inode = fs.read_inode(self.ino)?;
            if inode.kind() != FileKind::Symlink {
                return Err(Errno::EINVAL);
            }
            // Linux keeps targets under a block (and PATH_MAX).
            if inode.size() > fs.block_size.min(PATH_MAX) as u64 {
                return Err(Errno::EIO);
            }
            let mut target = try_zeroed(inode.size() as usize)?;
            let n = fs.read_data(self.ino, 0, &mut target)?;
            target.truncate(n);
            String::from_utf8(target).map_err(|_| Errno::EINVAL)
        })
    }
}

impl<D: BlockDevice + Send + 'static> Drop for Node<D> {
    fn drop(&mut self) {
        let mut fs = self.shared.fs.lock();
        // Another lookup may have replaced this node in the index with a live
        // one, which then owns the inode.
        if !self.link.is_linked() {
            return;
        }
        // SAFETY: linked, as just checked, in `nodes`.
        unsafe { fs.nodes.remove(self) };
        if fs.read_only {
            return;
        }
        if let Ok(inode) = fs.read_inode(self.ino)
            && inode.links() == 0
            && inode.mode() != 0
            && get32(&inode.raw, ino::DTIME) == 0
        {
            // Nowhere to report an error from a drop.
            let _ = fs.transact(|fs| fs.free_inode(self.ino));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use osmium_fs::{OpenFlags, RamFs, Vfs};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::{boxed::Box, format, fs, string::ToString};

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
                let root = ext2.root().unwrap();
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
                let vfs = Vfs::new(RamFs::new(1).root());
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
                let vfs = Vfs::new(ext2.root().unwrap());
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
                let vfs = Vfs::new(ext2.root().unwrap());
                assert_eq!(read_all(&*vfs.lookup("/sparse").unwrap())[10..14], *b"head");
                assert!(vfs.lookup("/many/entry-with-a-longish-name-0001").is_ok());
                assert_eq!(vfs.lookup("/many/entry-with-a-longish-name-0000").err(), Some(Errno::ENOENT));
            }
        }
    }

    #[test]
    fn links_renames_and_times_pass_fsck() {
        let scratch = Scratch::new("rename");
        for kind in [EXT2, EXT3, EXT4, EXT4_GROUPS] {
            let Some(image) = mkfs(&scratch, kind, 1024, 8 << 20, None) else { return };
            let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
            let clock = Arc::new(osmium_fs::ManualClock::new(Timestamp::from_secs(1_700_000_000)));
            ext2.set_clock_source(clock.clone());
            let vfs = Vfs::new(ext2.root().unwrap());
            let rw = OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE;

            vfs.open("/a", rw, 0o644).unwrap().write(0, b"alpha").unwrap();
            let st = vfs.stat("/a", true).unwrap();
            assert_eq!((st.mtime.sec, st.ctime.sec, st.atime.sec), (1_700_000_000, 1_700_000_000, 1_700_000_000));

            // Hard links: same inode, counted, and the data outlives a name.
            clock.advance(10);
            vfs.link("/a", "/b").unwrap();
            let (a, b) = (vfs.stat("/a", true).unwrap(), vfs.stat("/b", true).unwrap());
            assert_eq!((a.ino, a.nlink, b.nlink), (b.ino, 2, 2));
            assert_eq!((a.mtime.sec, a.ctime.sec), (1_700_000_000, 1_700_000_010));
            assert_eq!(vfs.link("/a", "/b").err(), Some(Errno::EEXIST));
            vfs.mkdir("/d", 0o755).unwrap();
            assert_eq!(vfs.link("/d", "/d2").err(), Some(Errno::EPERM));
            vfs.unlink("/a").unwrap();
            assert_eq!(read_all(&*vfs.lookup("/b").unwrap()), b"alpha");
            assert_eq!(vfs.stat("/b", true).unwrap().nlink, 1);

            // Rename a file into a directory, over another, and back.
            clock.advance(10);
            vfs.rename("/b", "/d/c").unwrap();
            assert_eq!(vfs.lookup("/b").err(), Some(Errno::ENOENT));
            assert_eq!(vfs.stat("/d/c", true).unwrap().ctime.sec, 1_700_000_020);
            assert_eq!(vfs.stat("/d", true).unwrap().mtime.sec, 1_700_000_020);
            vfs.open("/over", rw, 0o644).unwrap().write(0, b"old").unwrap();
            vfs.rename("/d/c", "/over").unwrap();
            assert_eq!(read_all(&*vfs.lookup("/over").unwrap()), b"alpha");
            vfs.rename("/over", "/over").unwrap();

            // Directories: across parents (".." and link counts follow),
            // over an empty one, and refused into themselves.
            vfs.mkdir("/p", 0o755).unwrap();
            vfs.mkdir("/q", 0o755).unwrap();
            vfs.mkdir("/p/sub", 0o755).unwrap();
            vfs.open("/p/sub/f", rw, 0o644).unwrap().write(0, b"deep").unwrap();
            let (p, q) = (vfs.stat("/p", true).unwrap().nlink, vfs.stat("/q", true).unwrap().nlink);
            vfs.rename("/p/sub", "/q/moved").unwrap();
            assert_eq!(vfs.stat("/p", true).unwrap().nlink, p - 1);
            assert_eq!(vfs.stat("/q", true).unwrap().nlink, q + 1);
            assert_eq!(read_all(&*vfs.lookup("/q/moved/f").unwrap()), b"deep");
            assert_eq!(vfs.canonicalize("/q/moved/..").unwrap(), "/q");
            assert_eq!(vfs.rename("/q", "/q/moved/q").err(), Some(Errno::EINVAL));
            vfs.mkdir("/empty", 0o755).unwrap();
            vfs.rename("/q/moved", "/empty").unwrap();
            assert_eq!(read_all(&*vfs.lookup("/empty/f").unwrap()), b"deep");
            vfs.open("/q/keep", rw, 0o644).unwrap();
            assert_eq!(vfs.rename("/empty", "/q").err(), Some(Errno::ENOTEMPTY));
            assert_eq!(vfs.rename("/empty", "/over").err(), Some(Errno::ENOTDIR));
            assert_eq!(vfs.rename("/over", "/empty").err(), Some(Errno::EISDIR));

            // An open file renamed over is freed when its handle goes.
            let held = vfs.open("/over", OpenFlags::READ, 0).unwrap();
            vfs.open("/fresh", rw, 0o644).unwrap();
            vfs.rename("/fresh", "/over").unwrap();
            assert_eq!(read_all(&*held), b"alpha");
            drop((held, vfs));

            let image = unmount(ext2);
            fsck(&scratch, &image, &[]);
            let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
            let vfs = Vfs::new(ext2.root().unwrap());
            assert_eq!(read_all(&*vfs.lookup("/empty/f").unwrap()), b"deep");
            assert_eq!(vfs.stat("/q", true).unwrap().nlink, 2);
            assert_eq!(vfs.stat("/over", true).unwrap().size, 0);
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
            let vfs = Vfs::new(ext2.root().unwrap());
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
            let vfs = Vfs::new(ext2.root().unwrap());
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
            let vfs = Vfs::new(ext2.root().unwrap());
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
            let vfs = Vfs::new(ext2.root().unwrap());
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
            let vfs = Vfs::new(ext2.root().unwrap());
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
        let vfs = Vfs::new(ext2.root().unwrap());
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
    fn growing_past_2gib_sets_large_file() {
        let scratch = Scratch::new("largefile");
        let Some(image) = mkfs(&scratch, Kind("ext4", &["-O", "^large_file"]), 1024, 4 << 20, None) else { return };
        assert_eq!(get32(&image[1024..2048], sb::FEATURE_RO_COMPAT) & RO_COMPAT_LARGE_FILE, 0);
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        let vfs = Vfs::new(ext2.root().unwrap());
        let f = vfs.open("/big", OpenFlags::CREATE | OpenFlags::WRITE, 0o644).unwrap();
        f.truncate(3 << 30).unwrap();
        drop((f, vfs));
        let image = unmount(ext2);
        assert_ne!(get32(&image[1024..2048], sb::FEATURE_RO_COMPAT) & RO_COMPAT_LARGE_FILE, 0);
        fsck(&scratch, &image, &[]);
    }

    #[test]
    fn refuses_unsupported_and_garbage() {
        let scratch = Scratch::new("refuse");
        let Some(image) = mkfs(&scratch, EXT4, 1024, 4 << 20, None) else { return };
        // The flag with nothing in the journal: mounting clears it.
        let dirty = debugfs(&scratch, image.clone(), &["feature needs_recovery"]);
        let image_after = unmount(Ext2::mount(VecDisk(dirty), 1).unwrap());
        assert_eq!(get32(&image_after[1024..2048], sb::FEATURE_INCOMPAT) & INCOMPAT_RECOVER, 0);
        // A journal this driver cannot read, which needs recovery.
        let journal0 = journal_block(&journal_map(&scratch, &image), 0);
        let mut odd = image.clone();
        put_be32(&mut odd[journal0 as usize * 1024..], 0x28, 0x20);
        let odd_dirty = debugfs(&scratch, odd.clone(), &["feature needs_recovery"]);
        assert_eq!(Ext2::mount(VecDisk(odd_dirty), 1).err(), Some(Errno::ENOSYS));
        // The same journal when clean is left alone.
        let ext2 = Ext2::mount(VecDisk(odd), 1).unwrap();
        assert!(!ext2.is_journaled());
        ext2.root().unwrap().create("unjournaled", FileKind::Regular, 0o644).unwrap();
        let ext2 = Ext2::mount(VecDisk(unmount(ext2)), 1).unwrap();
        assert!(names(&*ext2.root().unwrap()).contains(&"unjournaled".to_string()));
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
        assert_eq!(ext2.root().unwrap().create("x", FileKind::Regular, 0o644).err(), Some(Errno::EROFS));
    }

    /// Edits the primary superblock of an image, keeping its checksum.
    fn edit_super(mut image: Vec<u8>, f: impl FnOnce(&mut [u8])) -> Vec<u8> {
        let sb = &mut image[1024..2048];
        f(sb);
        let sum = csum::crc32c(!0, &sb[..sb::CHECKSUM]);
        put32(sb, sb::CHECKSUM, sum);
        image
    }

    #[test]
    fn corrupt_images_fail_cleanly() {
        let scratch = Scratch::new("corrupt");
        let Some(image) = mkfs(&scratch, EXT4, 1024, 4 << 20, None) else { return };

        // Layout fields that would index past a bitmap or the device.
        let bad_super: [fn(&mut [u8]); 4] = [
            |sb| {
                put32(sb, sb::INODES_PER_GROUP, 20_000);
                let groups = get32(sb, sb::BLOCKS_COUNT).div_ceil(get32(sb, sb::BLOCKS_PER_GROUP));
                put32(sb, sb::INODES_COUNT, groups * 20_000);
            },
            |sb| put16(sb, sb::RESERVED_GDT_BLOCKS, 60_000),
            |sb| put32(sb, sb::BLOCKS_COUNT, u32::MAX),
            |sb| put32(sb, sb::BLOCKS_PER_GROUP, 1),
        ];
        for edit in bad_super {
            let bad = edit_super(image.clone(), edit);
            assert_eq!(Ext2::mount(VecDisk(bad), 1).err(), Some(Errno::EINVAL));
        }

        // An inode table over the superblock.
        let ext2 = Ext2::mount(VecDisk(image.clone()), 1).unwrap();
        {
            let mut fs = ext2.shared.fs.lock();
            fs.group_set(0, gd::INODE_TABLE, 1);
            fs.write_group(0).unwrap();
        }
        assert_eq!(Ext2::mount(VecDisk(unmount(ext2)), 1).err(), Some(Errno::EINVAL));

        // Inodes and directory records corrupted after mounting, with their
        // checksums kept valid so that only the values are wrong.
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        let vfs = Vfs::new(ext2.root().unwrap());
        vfs.symlink("x", "/fast").unwrap();
        vfs.open("/file", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap().write(0, b"data").unwrap();
        vfs.mkdir("/dir", 0o755).unwrap();
        let ino_of = |name: &str| ext2.root().unwrap().lookup(name).unwrap().stat().ino as u32;
        let (fast, file, dir) = (ino_of("fast"), ino_of("file"), ino_of("dir"));
        let edit_inode = |ino: u32, f: &dyn Fn(&mut Inode)| {
            let mut fs = ext2.shared.fs.lock();
            let mut inode = fs.read_inode(ino).unwrap();
            f(&mut inode);
            fs.write_inode(ino, &inode).unwrap();
        };
        edit_inode(fast, &|i| i.set_size(200));
        edit_inode(file, &|i| put16(&mut i.raw, ino::BLOCK + 2, 50));
        {
            let mut fs = ext2.shared.fs.lock();
            let mut inode = fs.read_inode(dir).unwrap();
            let b = fs.bmap(dir, &mut inode, 0, false).unwrap();
            let mut data = fs.read_block(b).unwrap();
            // `.` claims 9 bytes, which no record can.
            put16(&mut data, 4, 9);
            fs.write_dir_block(dir, b, &mut data).unwrap();
        }
        assert_eq!(vfs.readlink("/fast").err(), Some(Errno::EIO));
        assert_eq!(vfs.open("/fast", OpenFlags::READ, 0).err(), Some(Errno::EIO));
        assert_eq!(vfs.lookup("/file").unwrap().read(0, &mut [0; 4]).err(), Some(Errno::EIO));
        assert_eq!(vfs.unlink("/file").err(), Some(Errno::EIO));
        assert_eq!(vfs.lookup("/dir").unwrap().readdir(0).err(), Some(Errno::EIO));
        assert_eq!(vfs.open("/dir/new", OpenFlags::CREATE, 0o644).err(), Some(Errno::EIO));
    }

    #[test]
    fn extent_splits_on_a_full_disk_leave_it_consistent() {
        let scratch = Scratch::new("split-full");
        let Some(image) = mkfs(&scratch, Kind("ext4", &["-g", "256"]), 1024, 1 << 20, None) else { return };
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        let vfs = Vfs::new(ext2.root().unwrap());
        let f = vfs.open("/holes", OpenFlags::READ | OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
        // One block in every two: each write is a new extent, so the tree
        // keeps splitting until a split finds the disk full.
        let mut i = 0;
        let err = loop {
            if let Err(e) = f.write(2 * i * 1024, &[(i % 251) as u8 + 1]) {
                break e;
            }
            i += 1;
        };
        assert_eq!(err, Errno::ENOSPC);
        assert!(i > 300, "only {i} extents fit");
        for j in [0, i / 2, i - 1] {
            let mut b = [0];
            f.read(2 * j * 1024, &mut b).unwrap();
            assert_eq!(b[0], (j % 251) as u8 + 1);
        }
        drop((f, vfs));
        let image = unmount(ext2);
        fsck(&scratch, &image, &[]);

        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        ext2.root().unwrap().lookup("holes").unwrap().truncate(0).unwrap();
        fsck(&scratch, &unmount(ext2), &[]);
    }

    /// Free-block counts: the superblock's, then each group's.
    fn free_counts(ext2: &Ext2<VecDisk>) -> Vec<u64> {
        let fs = ext2.shared.fs.lock();
        let mut counts = vec![fs.free_blocks()];
        counts.extend((0..fs.group_count).map(|g| fs.group_get(g, gd::FREE_BLOCKS)));
        counts
    }

    #[test]
    fn unlinking_a_device_inode_leaves_the_bitmaps_alone() {
        let scratch = Scratch::new("devnode");
        for kind in [EXT2, EXT4_GROUPS] {
            let Some(image) = mkfs(&scratch, kind, 1024, 8 << 20, None) else { return };
            // Major 1, minor 3 is i_block[0] = 0x103: block 259.
            let image = debugfs(&scratch, image, &["mknod null c 1 3", "mknod fifo p"]);
            let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
            let before = free_counts(&ext2);
            let vfs = Vfs::new(ext2.root().unwrap());
            assert_eq!(vfs.stat("/null", true).unwrap().rdev, makedev(1, 3));
            vfs.unlink("/null").unwrap();
            vfs.unlink("/fifo").unwrap();
            drop(vfs);
            assert_eq!(before, free_counts(&ext2));
            fsck(&scratch, &unmount(ext2), &[]);
        }
    }

    #[test]
    fn data_blocks_in_metadata_zones_are_refused() {
        let scratch = Scratch::new("metazone");
        let Some(image) = mkfs(&scratch, EXT2, 1024, 4 << 20, None) else { return };
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        let vfs = Vfs::new(ext2.root().unwrap());
        vfs.open("/f", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap().write(0, b"data").unwrap();
        let ino = ext2.root().unwrap().lookup("f").unwrap().stat().ino as u32;
        {
            let mut fs = ext2.shared.fs.lock();
            let table = fs.group_get(0, gd::INODE_TABLE);
            assert!(fs.in_meta_zone(table) && fs.in_meta_zone(1) && !fs.in_meta_zone(0));
            // Point the file's first block at the inode table.
            let mut inode = fs.read_inode(ino).unwrap();
            inode.set_block(0, table as u32);
            fs.write_inode(ino, &inode).unwrap();
        }
        let f = vfs.lookup("/f").unwrap();
        assert_eq!(f.write(0, b"x").err(), Some(Errno::EIO));
        assert_eq!(f.read(0, &mut [0; 4]).err(), Some(Errno::EIO));
    }

    #[test]
    fn directory_emptiness_counts_unlistable_names() {
        let scratch = Scratch::new("emptydir");
        let Some(image) = mkfs(&scratch, EXT2, 1024, 4 << 20, None) else { return };
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        let vfs = Vfs::new(ext2.root().unwrap());
        vfs.mkdir("/d", 0o755).unwrap();
        let d = ext2.root().unwrap().lookup("d").unwrap().stat().ino as u32;
        {
            let mut fs = ext2.shared.fs.lock();
            assert!(fs.is_empty_dir(d).unwrap());
            // A name with a slash can never be listed or looked up.
            fs.add_entry(d, "a/b", 12, FileKind::Regular).unwrap();
            assert!(!fs.is_empty_dir(d).unwrap());
        }
        assert_eq!(vfs.rmdir("/d").err(), Some(Errno::ENOTEMPTY));
    }
    fn put_be32(buf: &mut [u8], off: usize, val: u32) {
        buf[off..off + 4].copy_from_slice(&val.to_be_bytes());
    }

    fn be32(buf: &[u8], off: usize) -> u32 {
        u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
    }

    /// Where the journal's blocks are: `(first journal block, last, file
    /// system block of the first)` for each extent of its inode.
    fn journal_map(scratch: &Scratch, image: &[u8]) -> Vec<(u32, u32, u64)> {
        let img = scratch.0.join("locate");
        fs::write(&img, image).unwrap();
        let out = Command::new("debugfs").arg("-R").arg("stat <8>").arg(&img).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let list = text.split("EXTENTS:").nth(1).expect("an extent list").trim();
        list.split(", ")
            .map(|extent| {
                let (logical, physical) = extent.trim().split_once(':').unwrap();
                let (l0, l1) = logical.trim_matches(['(', ')']).split_once('-').unwrap();
                let p0 = physical.split('-').next().unwrap();
                (l0.parse().unwrap(), l1.parse().unwrap(), p0.parse().unwrap())
            })
            .collect()
    }

    /// The file system block of journal block `l`.
    fn journal_block(map: &[(u32, u32, u64)], l: u32) -> u64 {
        let &(l0, _, p0) = map.iter().find(|&&(l0, l1, _)| (l0..=l1).contains(&l)).unwrap();
        p0 + (l - l0) as u64
    }

    /// Writes `blocks` to a transaction in the journal with debugfs, leaving
    /// the file system needing recovery.
    fn journal_write(scratch: &Scratch, image: Vec<u8>, csum: bool, blocks: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut script = String::from(if csum { "jo -c\n" } else { "jo\n" });
        for (i, (b, data)) in blocks.iter().enumerate() {
            let path = scratch.0.join(format!("block{i}"));
            fs::write(&path, data).unwrap();
            script.push_str(&format!("jw -b {b} {}\n", path.display()));
        }
        script.push_str("jc\n");
        let cmds = scratch.0.join("journal-script");
        fs::write(&cmds, script).unwrap();
        let img = scratch.0.join("journal");
        fs::write(&img, image).unwrap();
        let out = Command::new("debugfs").arg("-w").arg("-f").arg(&cmds).arg(&img).output().unwrap();
        assert!(out.status.success(), "debugfs: {}", String::from_utf8_lossy(&out.stderr));
        fs::read(&img).unwrap()
    }

    fn incompat(image: &[u8]) -> u32 {
        get32(&image[1024..2048], sb::FEATURE_INCOMPAT)
    }

    #[test]
    fn a_directory_entry_cannot_reach_a_reserved_inode() {
        let scratch = Scratch::new("reserved");
        let tree = scratch.0.join("tree");
        fs::create_dir_all(&tree).unwrap();
        fs::write(tree.join("zz"), b"data").unwrap();
        for kind in [EXT2, EXT4] {
            let Some(mut image) = mkfs(&scratch, kind, 1024, 8 << 20, Some(&tree)) else { return };
            // The entry for "zz": inode, record length, name length 2, regular file.
            let at = image.windows(4).position(|w| w == [2, 1, b'z', b'z']).expect("the root directory entry") - 6;
            for target in [1u32, 7, 8, 0x7fff_ffff] {
                image[at..at + 4].copy_from_slice(&target.to_le_bytes());
                let ext2 = Ext2::mount(VecDisk(image.clone()), 1).unwrap();
                let root = ext2.root().unwrap();
                assert!(root.lookup("zz").is_err(), "inode {target}");
            }
        }
    }

    #[test]
    fn journals_changes_and_unmounts_clean() {
        let scratch = Scratch::new("journaled");
        for kind in [EXT3, EXT4, EXT4_GROUPS] {
            for block in [1024, 4096] {
                let Some(image) = mkfs(&scratch, kind, block, 8 << 20, None) else { return };
                let ext2 = Ext2::mount(VecDisk(image.clone()), 1).unwrap();
                assert!(ext2.is_journaled());
                // Mounting and unmounting alone changes nothing.
                assert!(unmount(ext2) == image);

                let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
                let root = ext2.root().unwrap();
                let d = root.create("d", FileKind::Directory, 0o755).unwrap();
                let f = d.create("f", FileKind::Regular, 0o644).unwrap();
                f.write(0, &pattern(100_000, 4)).unwrap();
                for i in 0..50 {
                    d.create(&format!("file-{i}"), FileKind::Regular, 0o644).unwrap();
                }
                f.truncate(30_000).unwrap();
                d.remove("file-3", false).unwrap();
                drop((f, d, root));
                let image = unmount(ext2);
                assert_eq!(incompat(&image) & INCOMPAT_RECOVER, 0);
                let cats = fsck(&scratch, &image, &["/d/f"]);
                assert_eq!(cats[0], pattern(100_000, 4)[..30_000]);

                // The journal is empty: debugfs finds nothing to replay.
                let img = scratch.0.join("empty");
                fs::write(&img, &image).unwrap();
                let out = Command::new("debugfs").arg("-R").arg("logdump").arg(&img).output().unwrap();
                assert!(String::from_utf8_lossy(&out.stdout).contains("Journal starts at block 0"));
            }
        }
    }

    #[test]
    fn replays_journals_written_by_debugfs() {
        let scratch = Scratch::new("replay");
        for csum in [true, false] {
            for block in [1024, 4096] {
                let Some(image) = mkfs(&scratch, EXT4, block, 8 << 20, None) else { return };
                let end = (8 << 20) / block as u64;
                // Free blocks at the end of the file system, one of which
                // looks like a journal block and so is escaped in the log.
                let mut magic = pattern(block, 9);
                magic[..4].copy_from_slice(&0xc03b_3998u32.to_be_bytes());
                let blocks = [(end - 20, pattern(block, 7)), (end - 19, magic), (end - 18, pattern(block, 8))];
                let dirty = journal_write(&scratch, image, csum, &blocks);
                assert_ne!(incompat(&dirty) & INCOMPAT_RECOVER, 0);
                let ext2 = Ext2::mount(VecDisk(dirty), 1).unwrap();
                assert!(ext2.is_journaled());
                let image = unmount(ext2);
                for (b, data) in &blocks {
                    let at = *b as usize * block;
                    assert!(image[at..at + block] == data[..], "block {b} (checksums: {csum}, block size {block})");
                }
                assert_eq!(incompat(&image) & INCOMPAT_RECOVER, 0);
                fsck(&scratch, &image, &[]);
            }
        }
    }

    /// A log built by hand: transactions with revoke records, started near
    /// the end of the journal so that it wraps.
    #[test]
    fn replays_revokes_and_wraps() {
        let scratch = Scratch::new("revoke");
        let block = 1024;
        let Some(image) = mkfs(&scratch, EXT4, block, 8 << 20, None) else { return };
        let map = journal_map(&scratch, &image);
        let jsb = journal_block(&map, 0) as usize * block;
        let (first, len) = (be32(&image[jsb..], 0x14), be32(&image[jsb..], 0x10));
        let end = (8 << 20) / block as u64;
        let (x, y, z) = (end - 30, end - 29, end - 28);
        let fill = |b: u8| vec![b; block];

        let mut log: Vec<Vec<u8>> = Vec::new();
        let header = |kind: u32, id: u32| {
            let mut b = vec![0; block];
            put_be32(&mut b, 0, 0xc03b_3998);
            put_be32(&mut b, 4, kind);
            put_be32(&mut b, 8, id);
            b
        };
        let mut txn = |id: u32, writes: &[(u64, u8)], revokes: &[u64]| {
            if !writes.is_empty() {
                // Tags are 8 bytes; the first is followed by a UUID, and the
                // others say it is the same.
                let mut packed = header(1, id);
                let mut off = 12;
                for (i, (b, _)) in writes.iter().enumerate() {
                    put_be32(&mut packed, off, *b as u32);
                    let flags = if i == 0 { 0 } else { 2 } | if i + 1 == writes.len() { 8 } else { 0 };
                    packed[off + 6..off + 8].copy_from_slice(&(flags as u16).to_be_bytes());
                    off += 8;
                    if i == 0 {
                        off += 16;
                    }
                }
                log.push(packed);
                log.extend(writes.iter().map(|&(_, v)| fill(v)));
            }
            if !revokes.is_empty() {
                let mut r = header(5, id);
                put_be32(&mut r, 12, 16 + 4 * revokes.len() as u32);
                for (i, b) in revokes.iter().enumerate() {
                    put_be32(&mut r, 16 + 4 * i, *b as u32);
                }
                log.push(r);
            }
            log.push(header(2, id));
        };
        // 10 writes x and y. 11 revokes x, which undoes 10's write of it, and
        // revokes w too early to matter to 12's write of it, and rewrites y.
        // 13 revokes z, which undoes the write in 12.
        let w = end - 27;
        txn(10, &[(x, 0xa1), (y, 0xa2)], &[]);
        txn(11, &[(y, 0xb2)], &[x, w]);
        txn(12, &[(z, 0xc3), (w, 0xc4)], &[]);
        txn(13, &[], &[z]);

        let mut dirty = image.clone();
        let span = (len - first) as usize;
        let start = len - 3;
        for (i, b) in log.iter().enumerate() {
            let l = first as usize + ((start - first) as usize + i) % span;
            let at = journal_block(&map, l as u32) as usize * block;
            dirty[at..at + block].copy_from_slice(b);
        }
        // The journal superblock: the log starts at `start` with transaction 10.
        put_be32(&mut dirty[jsb..], 0x1c, start);
        put_be32(&mut dirty[jsb..], 0x18, 10);
        let dirty = debugfs(&scratch, dirty, &["feature needs_recovery"]);

        let ext2 = Ext2::mount(VecDisk(dirty), 1).unwrap();
        let after = unmount(ext2);
        let blk = |b: u64| after[b as usize * block..(b as usize + 1) * block].to_vec();
        let was = |b: u64| image[b as usize * block..(b as usize + 1) * block].to_vec();
        assert!(blk(x) == was(x), "x was revoked");
        assert!(blk(y) == fill(0xb2), "y was rewritten by transaction 11");
        assert!(blk(w) == fill(0xc4), "w was written after it was revoked");
        assert!(blk(z) == was(z), "z was revoked by a later transaction");
        fsck(&scratch, &after, &[]);
    }

    #[test]
    fn transactions_larger_than_the_journal_are_split() {
        let scratch = Scratch::new("split");
        let Some(image) = mkfs(&scratch, EXT4, 1024, 16 << 20, None) else { return };
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        // Free blocks at the end, well away from the journal.
        let blocks: Vec<u64> = (13_000..15_500).collect();
        {
            let mut fs = ext2.shared.fs.lock();
            for &b in &blocks {
                fs.write_raw_block(b, &pattern(1024, b as u8)).unwrap();
            }
            fs.commit().unwrap();
        }
        let after = unmount(ext2);
        for &b in &blocks {
            let at = b as usize * 1024;
            assert!(after[at..at + 1024] == pattern(1024, b as u8)[..], "block {b}");
        }
        fsck(&scratch, &after, &[]);
    }

    #[test]
    fn blocks_freed_by_an_operation_are_not_reused_by_it() {
        let scratch = Scratch::new("freed");
        let Some(image) = mkfs(&scratch, EXT4, 1024, 8 << 20, None) else { return };
        let ext2 = Ext2::mount(VecDisk(image), 1).unwrap();
        {
            let mut fs = ext2.shared.fs.lock();
            let b = fs.transact(|fs| fs.alloc_block(0)).unwrap();
            let (freed, again, other) = fs
                .transact(|fs| {
                    fs.free_block(b)?;
                    let again = fs.alloc_block(b)?;
                    Ok((b, again, fs.alloc_block(b)?))
                })
                .unwrap();
            assert!(again != freed && other != freed);
            // The next operation may have it.
            assert_eq!(fs.transact(|fs| fs.alloc_block(b)).unwrap(), freed);
            fs.transact(|fs| {
                fs.free_run(freed, 1).and_then(|()| fs.free_run(again, 1)).and_then(|()| fs.free_run(other, 1))
            })
            .unwrap();
        }
        fsck(&scratch, &unmount(ext2), &[]);
    }

    /// A disk that logs every write and flush, so that what a crash would
    /// leave behind can be rebuilt.
    enum Event {
        Write(usize, Vec<u8>),
        Flush,
    }

    struct CrashDisk {
        data: Vec<u8>,
        events: std::sync::Arc<std::sync::Mutex<Vec<Event>>>,
    }

    impl BlockDevice for CrashDisk {
        fn block_size(&self) -> usize {
            512
        }

        fn num_blocks(&self) -> u64 {
            (self.data.len() / 512) as u64
        }

        fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            self.check_range(lba, buf.len())?;
            let off = lba as usize * 512;
            buf.copy_from_slice(&self.data[off..off + buf.len()]);
            Ok(())
        }

        fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
            self.check_range(lba, buf.len())?;
            let off = lba as usize * 512;
            self.data[off..off + buf.len()].copy_from_slice(buf);
            self.events.lock().unwrap().push(Event::Write(off, buf.to_vec()));
            Ok(())
        }

        fn flush(&mut self) -> Result<(), BlockError> {
            self.events.lock().unwrap().push(Event::Flush);
            Ok(())
        }
    }

    /// Every file, directory and symbolic link below `dir`, with contents.
    fn snapshot(dir: &dyn File) -> std::collections::BTreeMap<String, Vec<u8>> {
        fn walk(dir: &dyn File, path: &str, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
            for name in names(dir) {
                let child = dir.lookup(&name).unwrap();
                let path = format!("{path}/{name}");
                match child.stat().kind {
                    FileKind::Directory => {
                        out.insert(path.clone(), Vec::new());
                        walk(&*child, &path, out);
                    }
                    FileKind::Symlink => {
                        out.insert(path, child.readlink().unwrap().into_bytes());
                    }
                    _ => {
                        out.insert(path, read_all(&*child));
                    }
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        walk(dir, "", &mut out);
        out
    }

    /// One call on the root directory.
    type Step = Box<dyn Fn(&Arc<dyn File>)>;

    /// Runs `e2fsck -fy` on an image, which replays a journal that needs it.
    fn fsck_repair(scratch: &Scratch, image: &[u8]) -> Vec<u8> {
        let img = scratch.0.join("repair");
        fs::write(&img, image).unwrap();
        let out = Command::new("e2fsck").arg("-fy").arg(&img).output().unwrap();
        assert!(
            out.status.code().is_some_and(|c| c <= 1),
            "e2fsck failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        fs::read(&img).unwrap()
    }

    /// Crashes the disk after every write of a series of operations, in
    /// several ways, and checks that recovery finds the file system as it
    /// was before the operation or after it, and that e2fsprogs agrees.
    #[test]
    fn crashes_leave_the_file_system_consistent() {
        let scratch = Scratch::new("crash");
        for (kind, block) in [(EXT4, 1024), (EXT3, 4096), (EXT4_GROUPS, 1024)] {
            let Some(image) = mkfs(&scratch, kind, block, 8 << 20, None) else { return };
            let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let ext2 = Ext2::mount(CrashDisk { data: image.clone(), events: events.clone() }, 1).unwrap();
            let root = ext2.root().unwrap();

            // Each step is one call, which is one transaction.
            let mut steps: Vec<Step> = Vec::new();
            steps.push(Box::new(|r| drop(r.create("d", FileKind::Directory, 0o755).unwrap())));
            steps.push(Box::new(|r| drop(r.lookup("d").unwrap().create("a", FileKind::Regular, 0o644).unwrap())));
            steps.push(Box::new(move |r| {
                r.lookup("d").unwrap().lookup("a").unwrap().write(0, &pattern(20 * block, 1)).unwrap();
            }));
            for i in 0..24 {
                steps.push(Box::new(move |r| {
                    drop(
                        r.lookup("d")
                            .unwrap()
                            .create(&format!("entry-with-a-longish-name-{i}"), FileKind::Regular, 0o644)
                            .unwrap(),
                    )
                }));
            }
            for i in (0..24).step_by(3) {
                steps.push(Box::new(move |r| {
                    r.lookup("d").unwrap().remove(&format!("entry-with-a-longish-name-{i}"), false).unwrap()
                }));
            }
            steps.push(Box::new(move |r| {
                r.lookup("d")
                    .unwrap()
                    .lookup("a")
                    .unwrap()
                    .write(20 * block as u64, &pattern(5 * block + 100, 2))
                    .unwrap();
            }));
            steps.push(Box::new(move |r| {
                r.lookup("d").unwrap().lookup("a").unwrap().truncate(4 * block as u64).unwrap()
            }));
            steps.push(Box::new(|r| drop(r.create("link", FileKind::Symlink, 0o777).unwrap())));
            steps.push(Box::new(|r| {
                r.lookup("link").unwrap().write(0, LONG_TARGET.as_bytes()).unwrap();
            }));
            steps.push(Box::new(|r| r.lookup("d").unwrap().remove("a", false).unwrap()));

            let mut states = vec![snapshot(&*root)];
            let mut ends = vec![0];
            for step in &steps {
                step(&root);
                states.push(snapshot(&*root));
                ends.push(events.lock().unwrap().len());
            }
            drop(root);
            let events = events.lock().unwrap();

            let mut checked = 0;
            for crash in 0..=events.len() {
                // The step the crash fell in.
                let step = (1..ends.len()).find(|&i| crash <= ends[i]).unwrap();
                let flushed = events[..crash].iter().rposition(|e| matches!(e, Event::Flush)).map_or(0, |i| i + 1);
                // Variants: everything written; only what was flushed; and,
                // where the most writes are in flight (just before a flush),
                // everything but one of them.
                let before_flush = events.get(crash).is_none_or(|e| matches!(e, Event::Flush));
                let unflushed: Vec<usize> =
                    (flushed..crash).filter(|&i| matches!(events[i], Event::Write(..))).collect();
                let variants = if before_flush { 2 + unflushed.len() } else { 2 };
                for variant in 0..variants {
                    let mut disk = image.clone();
                    for (i, event) in events[..crash].iter().enumerate() {
                        let keep = match variant {
                            0 => true,
                            1 => i < flushed,
                            v => i != unflushed[v - 2],
                        };
                        if let (true, Event::Write(off, data)) = (keep, event) {
                            disk[*off..*off + data.len()].copy_from_slice(data);
                        }
                    }
                    let interesting = variant < 2
                        && (crash == 0
                            || matches!(events[crash - 1], Event::Flush)
                            || events.get(crash).is_some_and(|e| matches!(e, Event::Flush)));
                    let recovered = Ext2::mount(VecDisk(disk.clone()), 1)
                        .unwrap_or_else(|e| panic!("mount after crash {crash} variant {variant}: {e:?}"));
                    let state = snapshot(&*recovered.root().unwrap());
                    assert!(
                        state == states[step - 1] || state == states[step],
                        "crash {crash} variant {variant} in step {step} (block size {block}): neither before nor after"
                    );
                    // A symbolic link is made empty, and then given its target.
                    let empty_link = state.get("/link").is_some_and(|target| target.is_empty());
                    if interesting && !empty_link {
                        let clean = unmount(recovered);
                        fsck(&scratch, &clean, &[]);
                        // e2fsprogs replays the same log to the same result.
                        if variant == 0 && incompat(&disk) & INCOMPAT_RECOVER != 0 {
                            let theirs = fsck_repair(&scratch, &disk);
                            let theirs = Ext2::mount(VecDisk(theirs), 1).unwrap();
                            assert!(snapshot(&*theirs.root().unwrap()) == state, "crash {crash}: e2fsck disagrees");
                        }
                        checked += 1;
                    }
                }
            }
            assert!(checked > 100, "{checked}");
        }
    }
}
