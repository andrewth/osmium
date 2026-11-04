//! On-disk structures: the superblock, keys, tree block headers and the items
//! this driver reads. Every field is little-endian; every parser checks its
//! lengths and fails with `EIO` on a short or inconsistent structure.

use alloc::vec::Vec;

use osmium_fs::{Errno, Timestamp};
use osmium_sync::fallible::{try_push, try_to_vec};

/// Byte offset of the primary superblock.
pub const SUPER_OFFSET: u64 = 64 * 1024;
/// Bytes in a superblock.
pub const SUPER_SIZE: usize = 4096;
/// `_BHRfS_M`.
const MAGIC: u64 = 0x4d5f_5366_5248_425f;
/// Bytes of checksum space at the start of the superblock and of every tree block.
pub const CSUM_SPACE: usize = 32;
/// Largest `sys_chunk_array`.
const SYS_CHUNK_ARRAY_MAX: usize = 2048;

/// Tree ids (the `objectid` of a `ROOT_ITEM` in the root tree).
pub mod tree {
    /// The root tree.
    pub const ROOT: u64 = 1;
    /// The extent tree.
    pub const EXTENT: u64 = 2;
    /// The chunk tree.
    pub const CHUNK: u64 = 3;
    /// The device tree.
    pub const DEV: u64 = 4;
    /// The quota tree.
    pub const QUOTA: u64 = 8;
    /// The UUID tree.
    pub const UUID: u64 = 9;
    /// The free space tree.
    pub const FREE_SPACE: u64 = 10;
    /// The block group tree.
    pub const BLOCK_GROUP: u64 = 11;
    /// Objectid of orphan items (`-5`).
    pub const ORPHAN: u64 = -5i64 as u64;
    /// The tree of fsync log roots, whose items point at each subvolume's log (`-6`).
    pub const LOG: u64 = -6i64 as u64;
    /// The chunk tree's items live under this objectid.
    pub const FIRST_CHUNK: u64 = 256;
    /// The data checksum tree.
    pub const CSUM: u64 = 7;
    /// The top-level subvolume.
    pub const FS: u64 = 5;
    /// The directory in the root tree holding the `default` entry.
    pub const ROOT_DIR: u64 = 6;
    /// Objectid of every data checksum item (`-10`).
    pub const EXTENT_CSUM: u64 = -10i64 as u64;
    /// First objectid free for files; a subvolume's root directory.
    pub const FIRST_FREE: u64 = 256;
    /// Last objectid a subvolume may have.
    pub const LAST_FREE: u64 = -256i64 as u64;
}

/// Item types (the `type` of a key).
pub mod item {
    /// An inode.
    pub const INODE_ITEM: u8 = 1;
    /// An inode's names, keyed by the parent directory.
    pub const INODE_REF: u8 = 12;
    /// More names, keyed by a hash of the parent and the name.
    pub const INODE_EXTREF: u8 = 13;
    /// An unlinked inode still to be deleted.
    pub const ORPHAN_ITEM: u8 = 48;
    /// A data extent and its references.
    pub const EXTENT_ITEM: u8 = 168;
    /// A tree block and its references (skinny metadata).
    pub const METADATA_ITEM: u8 = 169;
    /// Inline reference from a tree block to its tree.
    pub const TREE_BLOCK_REF: u8 = 176;
    /// A data extent's reference from a file.
    pub const EXTENT_DATA_REF: u8 = 178;
    /// A tree block's reference from a parent block.
    pub const SHARED_BLOCK_REF: u8 = 182;
    /// A data extent's reference from a leaf.
    pub const SHARED_DATA_REF: u8 = 184;
    /// A block group.
    pub const BLOCK_GROUP_ITEM: u8 = 192;
    /// A block group's free space summary.
    pub const FREE_SPACE_INFO: u8 = 198;
    /// A free range.
    pub const FREE_SPACE_EXTENT: u8 = 199;
    /// Free sectors as a bitmap.
    pub const FREE_SPACE_BITMAP: u8 = 200;
    /// A device range holding a chunk stripe.
    pub const DEV_EXTENT: u8 = 204;
    /// A device.
    pub const DEV_ITEM: u8 = 216;
    /// An extended attribute, keyed by the hash of its name.
    pub const XATTR_ITEM: u8 = 24;
    /// A directory entry, keyed by the hash of its name.
    pub const DIR_ITEM: u8 = 84;
    /// A directory entry, keyed by its position in the directory.
    pub const DIR_INDEX: u8 = 96;
    /// A file extent, keyed by its offset in the file.
    pub const EXTENT_DATA: u8 = 108;
    /// Data checksums, keyed by the logical address of the first sector.
    pub const EXTENT_CSUM: u8 = 128;
    /// A tree's root.
    pub const ROOT_ITEM: u8 = 132;
    /// A subvolume's name in its parent, keyed by the parent subvolume.
    pub const ROOT_REF: u8 = 156;
    /// A subvolume's parent, keyed by the subvolume.
    pub const ROOT_BACKREF: u8 = 144;
    /// A subvolume's UUID in the UUID tree.
    pub const UUID_SUBVOL: u8 = 251;
    /// A received subvolume's UUID in the UUID tree.
    pub const UUID_RECEIVED: u8 = 252;
    /// A chunk: a range of logical addresses and where it is stored.
    pub const CHUNK_ITEM: u8 = 228;
}

/// Incompatible features this driver can read.
pub mod incompat {
    /// Back references of the mixed kind (every file system since 2.6.31).
    pub const MIXED_BACKREF: u64 = 1 << 0;
    /// A default subvolume other than the top level may be set.
    pub const DEFAULT_SUBVOL: u64 = 1 << 1;
    /// Data and metadata share block groups.
    pub const MIXED_GROUPS: u64 = 1 << 2;
    /// LZO-compressed extents.
    pub const COMPRESS_LZO: u64 = 1 << 3;
    /// Zstd-compressed extents.
    pub const COMPRESS_ZSTD: u64 = 1 << 4;
    /// Tree blocks larger than a page.
    pub const BIG_METADATA: u64 = 1 << 5;
    /// Inode references in their own items (many hard links).
    pub const EXTENDED_IREF: u64 = 1 << 6;
    /// RAID5 or RAID6 chunks; their reads fail, the rest still work.
    pub const RAID56: u64 = 1 << 7;
    /// Smaller extent tree items.
    pub const SKINNY_METADATA: u64 = 1 << 8;
    /// Holes are not recorded as extents.
    pub const NO_HOLES: u64 = 1 << 9;
    /// Tree blocks carry `metadata_uuid` instead of the fsid.
    pub const METADATA_UUID: u64 = 1 << 10;
    /// Three- and four-copy RAID1.
    pub const RAID1C34: u64 = 1 << 11;
    /// Zoned devices (only allocation differs).
    pub const ZONED: u64 = 1 << 12;
    /// Squota (only accounting differs).
    pub const SIMPLE_QUOTA: u64 = 1 << 16;
    /// Every bit above.
    pub const SUPPORTED: u64 = MIXED_BACKREF
        | DEFAULT_SUBVOL
        | MIXED_GROUPS
        | COMPRESS_LZO
        | COMPRESS_ZSTD
        | BIG_METADATA
        | EXTENDED_IREF
        | RAID56
        | SKINNY_METADATA
        | NO_HOLES
        | METADATA_UUID
        | RAID1C34
        | ZONED
        | SIMPLE_QUOTA;
}

/// Block group profile bits of a chunk's type. Single, DUP, RAID1, RAID1C3
/// and RAID1C4 keep a whole copy of the chunk in each stripe.
pub mod profile {
    /// Striped across devices.
    pub const RAID0: u64 = 1 << 3;
    /// Two copies on one device.
    pub const DUP: u64 = 1 << 5;
    /// Copies on other devices: RAID1, RAID1C3, RAID1C4.
    pub const MIRRORED: u64 = 1 << 4 | 1 << 9 | 1 << 10;
    /// Striped mirrors.
    pub const RAID10: u64 = 1 << 6;
    /// Striped with parity.
    pub const RAID5: u64 = 1 << 7;
    /// Striped with double parity.
    pub const RAID6: u64 = 1 << 8;
    /// The profiles whose stripes are each a whole copy of the chunk.
    pub const STRIPED: u64 = RAID0 | RAID10 | RAID5 | RAID6;
}

/// The little-endian `u16` at `off`.
pub fn le16(b: &[u8], off: usize) -> Result<u16, Errno> {
    Ok(u16::from_le_bytes(array(b, off)?))
}

/// The little-endian `u32` at `off`.
pub fn le32(b: &[u8], off: usize) -> Result<u32, Errno> {
    Ok(u32::from_le_bytes(array(b, off)?))
}

/// The little-endian `u64` at `off`.
pub fn le64(b: &[u8], off: usize) -> Result<u64, Errno> {
    Ok(u64::from_le_bytes(array(b, off)?))
}

/// The byte at `off`.
pub fn byte(b: &[u8], off: usize) -> Result<u8, Errno> {
    b.get(off).copied().ok_or(Errno::EIO)
}

/// Writes `v` at `off` of `b`.
pub fn put(b: &mut [u8], off: usize, v: &[u8]) -> Result<(), Errno> {
    b.get_mut(off..off.checked_add(v.len()).ok_or(Errno::EIO)?).ok_or(Errno::EIO)?.copy_from_slice(v);
    Ok(())
}

/// Writes `v` little-endian at `off` of `b`.
pub fn put64(b: &mut [u8], off: usize, v: u64) -> Result<(), Errno> {
    put(b, off, &v.to_le_bytes())
}

/// Writes `v` little-endian at `off` of `b`.
pub fn put32(b: &mut [u8], off: usize, v: u32) -> Result<(), Errno> {
    put(b, off, &v.to_le_bytes())
}

/// The `N` bytes at `off`.
pub fn array<const N: usize>(b: &[u8], off: usize) -> Result<[u8; N], Errno> {
    b.get(off..off.checked_add(N).ok_or(Errno::EIO)?).and_then(|s| s.try_into().ok()).ok_or(Errno::EIO)
}

/// `len` bytes at `off`.
pub fn bytes(b: &[u8], off: usize, len: usize) -> Result<&[u8], Errno> {
    b.get(off..off.checked_add(len).ok_or(Errno::EIO)?).ok_or(Errno::EIO)
}

/// A key: items in every tree are sorted by it, field by field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    /// The object (an inode, a tree, a chunk tree's device...).
    pub objectid: u64,
    /// The [`item`] type.
    pub ty: u8,
    /// Meaning depends on the type: a file offset, a name hash, an address.
    pub offset: u64,
}

impl Key {
    /// Bytes in a key on disk.
    pub const SIZE: usize = 17;

    /// A key from its fields.
    pub const fn new(objectid: u64, ty: u8, offset: u64) -> Self {
        Key { objectid, ty, offset }
    }

    /// The key at `off`.
    pub fn parse(b: &[u8], off: usize) -> Result<Self, Errno> {
        Ok(Key { objectid: le64(b, off)?, ty: byte(b, off + 8)?, offset: le64(b, off + 9)? })
    }
}

/// What the driver uses of the superblock.
pub struct Super {
    /// Checksum algorithm (`BTRFS_CSUM_TYPE_*`).
    pub csum_type: u16,
    /// The file system's UUID.
    pub fsid: [u8; 16],
    /// The UUID tree blocks carry: the fsid, or `metadata_uuid` if that
    /// feature is on.
    pub meta_uuid: [u8; 16],
    /// Logical address and level of the root tree's root.
    pub root: (u64, u8),
    /// Logical address and level of the chunk tree's root.
    pub chunk_root: (u64, u8),
    /// The data block size.
    pub sectorsize: u32,
    /// The tree block size.
    pub nodesize: u32,
    /// Incompatible feature bits.
    pub incompat: u64,
    /// This device's id within the file system.
    pub devid: u64,
    /// The bootstrap chunks, enough to read the chunk tree.
    pub sys_chunks: Vec<u8>,
    /// The label, up to its first NUL.
    pub label: Vec<u8>,
}

impl Super {
    /// Parses and checks the magic, sizes and position of a superblock. The
    /// checksum is the caller's (it knows the algorithms).
    pub fn parse(b: &[u8]) -> Result<Self, Errno> {
        if b.len() < SUPER_SIZE || le64(b, 64)? != MAGIC || le64(b, 48)? != SUPER_OFFSET {
            return Err(Errno::EINVAL);
        }
        let sectorsize = le32(b, 144)?;
        let nodesize = le32(b, 148)?;
        let pow2 = |v: u32, lo: u32| v.is_power_of_two() && (lo..=65536).contains(&v);
        if !pow2(sectorsize, 4096) || !pow2(nodesize, sectorsize) {
            return Err(Errno::EINVAL);
        }
        let incompat = le64(b, 188)?;
        let fsid = array(b, 32)?;
        let meta_uuid = if incompat & incompat::METADATA_UUID != 0 { array(b, 571)? } else { fsid };
        let sys_len = le32(b, 160)? as usize;
        if sys_len > SYS_CHUNK_ARRAY_MAX {
            return Err(Errno::EINVAL);
        }
        let label = bytes(b, 299, 256)?;
        let label = label.get(..label.iter().position(|&c| c == 0).unwrap_or(label.len())).unwrap_or(&[]);
        Ok(Super {
            csum_type: le16(b, 196)?,
            fsid,
            meta_uuid,
            root: (le64(b, 80)?, byte(b, 198)?),
            chunk_root: (le64(b, 88)?, byte(b, 199)?),
            sectorsize,
            nodesize,
            incompat,
            devid: le64(b, 201)?,
            sys_chunks: try_to_vec(bytes(b, 811, sys_len)?)?,
            label: try_to_vec(label)?,
        })
    }
}

/// One copy (or stripe) of a chunk.
#[derive(Clone, Copy)]
pub struct Stripe {
    /// The device holding it.
    pub devid: u64,
    /// Its byte offset on that device.
    pub offset: u64,
}

/// A chunk: logical addresses `logical..logical + length` and where they live.
pub struct Chunk {
    /// First logical address.
    pub logical: u64,
    /// Bytes mapped.
    pub length: u64,
    /// Block group type and [`profile`] bits.
    pub ty: u64,
    /// Bytes of each stripe element, for the striped profiles.
    pub stripe_len: u64,
    /// Stripes per mirrored group (RAID10).
    pub sub_stripes: u16,
    /// The stripes, one per copy for the mirrored profiles.
    pub stripes: Vec<Stripe>,
}

impl Chunk {
    /// Bytes of a chunk item with no stripes.
    const FIXED: usize = 48;
    /// Bytes of each stripe.
    const STRIPE: usize = 32;

    /// The chunk item at the start of `b` for the chunk at `logical`, and its
    /// size in bytes.
    pub fn parse(b: &[u8], logical: u64) -> Result<(Self, usize), Errno> {
        let length = le64(b, 0)?;
        let n = le16(b, 44)? as usize;
        let (ty, stripe_len, sub_stripes) = (le64(b, 24)?, le64(b, 16)?, le16(b, 46)?);
        if length == 0 || n == 0 || logical.checked_add(length).is_none() {
            return Err(Errno::EIO);
        }
        // The striped profiles divide by these.
        let sub = sub_stripes as usize;
        if ty & profile::STRIPED != 0 && stripe_len == 0
            || ty & profile::RAID10 != 0 && (sub == 0 || !n.is_multiple_of(sub))
            || ty & profile::RAID5 != 0 && n < 2
            || ty & profile::RAID6 != 0 && n < 3
        {
            return Err(Errno::EIO);
        }
        let mut stripes = Vec::new();
        stripes.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
        for i in 0..n {
            let at = Self::FIXED + i * Self::STRIPE;
            try_push(&mut stripes, Stripe { devid: le64(b, at)?, offset: le64(b, at + 8)? })?;
        }
        Ok((Chunk { logical, length, ty, stripe_len, sub_stripes, stripes }, Self::FIXED + n * Self::STRIPE))
    }
}

/// A tree block's header.
pub mod header {
    /// Bytes in the header.
    pub const SIZE: usize = 101;
    /// The fsid (or metadata UUID).
    pub const FSID: usize = 32;
    /// The block's own logical address.
    pub const BYTENR: usize = 48;
    /// Items (leaf) or pointers (node) in the block.
    pub const NRITEMS: usize = 96;
    /// 0 for a leaf.
    pub const LEVEL: usize = 100;
}

/// A tree's root, from its `ROOT_ITEM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root {
    /// The tree's id.
    pub id: u64,
    /// Logical address of its root block.
    pub bytenr: u64,
    /// Level of its root block.
    pub level: u8,
    /// Objectid of its root directory (subvolumes).
    pub dirid: u64,
    /// Names it has; none once it is deleted.
    pub refs: u32,
}

impl Root {
    /// The `ROOT_ITEM` `b` of tree `id`.
    pub fn parse(b: &[u8], id: u64) -> Result<Self, Errno> {
        // An inode item, then generation, root_dirid, bytenr, byte_limit,
        // bytes_used, last_snapshot, flags, refs, drop_progress, drop_level, level.
        Ok(Root { id, bytenr: le64(b, 176)?, level: byte(b, 238)?, dirid: le64(b, 168)?, refs: le32(b, 216)? })
    }
}

/// Inode flag: data has no checksums.
pub const INODE_NODATASUM: u64 = 1 << 0;
/// Inode flag: data is overwritten in place.
pub const INODE_NODATACOW: u64 = 1 << 1;
/// Inode flag: data is never compressed.
pub const INODE_NOCOMPRESS: u64 = 1 << 3;
/// Inode flag: data is compressed.
pub const INODE_COMPRESS: u64 = 1 << 11;


/// An inode item.
#[derive(Clone, Copy, Debug, Default)]
pub struct Inode {
    /// Size in bytes.
    pub size: u64,
    /// Hard links.
    pub nlink: u32,
    /// `st_mode`, type and permissions.
    pub mode: u32,
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Device number, as Linux's kernel encodes it (`major << 20 | minor`).
    pub rdev: u64,
    /// `BTRFS_INODE_*` flags.
    pub flags: u64,
    /// Last access.
    pub atime: Timestamp,
    /// Last change.
    pub ctime: Timestamp,
    /// Last modification.
    pub mtime: Timestamp,
}

impl Inode {
    /// The inode item `b`.
    pub fn parse(b: &[u8]) -> Result<Self, Errno> {
        let time = |off| -> Result<Timestamp, Errno> {
            // A corrupt nanosecond field is clamped rather than refused.
            Ok(Timestamp { sec: le64(b, off)? as i64, nsec: le32(b, off + 8)?.min(999_999_999) })
        };
        Ok(Inode {
            size: le64(b, 16)?,
            nlink: le32(b, 40)?,
            mode: le32(b, 52)?,
            uid: le32(b, 44)?,
            gid: le32(b, 48)?,
            rdev: le64(b, 56)?,
            flags: le64(b, 64)?,
            atime: time(112)?,
            ctime: time(124)?,
            mtime: time(136)?,
        })
    }
}

/// One entry of a `DIR_ITEM`, `DIR_INDEX` or `XATTR_ITEM`; several can share
/// an item when their names' hashes collide.
pub struct DirItem<'src> {
    /// What the entry points at: an `INODE_ITEM` key, or a `ROOT_ITEM` key for
    /// a subvolume.
    pub location: Key,
    /// `BTRFS_FT_*`.
    pub ty: u8,
    /// The name.
    pub name: &'src [u8],
    /// The value (extended attributes).
    pub data: &'src [u8],
}

/// The entries packed in one item.
pub struct DirItems<'src>(&'src [u8]);

impl<'src> DirItems<'src> {
    /// The entries of item data `b`.
    pub fn new(b: &'src [u8]) -> Self {
        DirItems(b)
    }
}

impl<'src> Iterator for DirItems<'src> {
    type Item = Result<DirItem<'src>, Errno>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let b = self.0;
        let parse = || -> Result<(DirItem<'src>, usize), Errno> {
            // location (17), transid (8), data_len (2), name_len (2), type (1).
            let data_len = le16(b, 25)? as usize;
            let name_len = le16(b, 27)? as usize;
            let name = bytes(b, 30, name_len)?;
            let data = bytes(b, 30 + name_len, data_len)?;
            let item = DirItem { location: Key::parse(b, 0)?, ty: byte(b, 29)?, name, data };
            Ok((item, 30 + name_len + data_len))
        };
        match parse() {
            Ok((item, len)) => {
                self.0 = b.get(len..).unwrap_or(&[]);
                Some(Ok(item))
            }
            Err(e) => {
                self.0 = &[];
                Some(Err(e))
            }
        }
    }
}

/// Compression of an extent.
pub mod compress {
    /// Stored as is.
    pub const NONE: u8 = 0;
    /// zlib.
    pub const ZLIB: u8 = 1;
    /// LZO, in btrfs's segment framing.
    pub const LZO: u8 = 2;
    /// Zstandard.
    pub const ZSTD: u8 = 3;
}

/// Where a file extent's data is.
pub enum ExtentData<'src> {
    /// In the item itself.
    Inline(&'src [u8]),
    /// Elsewhere; `disk_bytenr` 0 is a hole.
    Regular {
        /// Logical address of the (possibly compressed) data.
        disk_bytenr: u64,
        /// Bytes it takes on disk.
        disk_num_bytes: u64,
        /// Where in the uncompressed data this file range starts.
        offset: u64,
        /// Bytes of the file this extent covers.
        num_bytes: u64,
    },
    /// Allocated but never written: reads as zeroes.
    Prealloc {
        /// Bytes of the file this extent covers.
        num_bytes: u64,
    },
}

/// A file extent item.
pub struct FileExtent<'src> {
    /// Bytes of the uncompressed data.
    pub ram_bytes: u64,
    /// The [`compress`] algorithm.
    pub compression: u8,
    /// The data.
    pub data: ExtentData<'src>,
}

impl<'src> FileExtent<'src> {
    /// The file extent item `b`. Encrypted or otherwise encoded extents are `EIO`.
    pub fn parse(b: &'src [u8]) -> Result<Self, Errno> {
        if byte(b, 17)? != 0 || le16(b, 18)? != 0 {
            return Err(Errno::EIO);
        }
        let data = match byte(b, 20)? {
            0 => ExtentData::Inline(b.get(21..).ok_or(Errno::EIO)?),
            1 => ExtentData::Regular {
                disk_bytenr: le64(b, 21)?,
                disk_num_bytes: le64(b, 29)?,
                offset: le64(b, 37)?,
                num_bytes: le64(b, 45)?,
            },
            2 => ExtentData::Prealloc { num_bytes: le64(b, 45)? },
            _ => return Err(Errno::EIO),
        };
        Ok(FileExtent { ram_bytes: le64(b, 8)?, compression: byte(b, 16)?, data })
    }

    /// Bytes of the file this extent covers.
    pub fn len(&self) -> u64 {
        match self.data {
            ExtentData::Inline(_) => self.ram_bytes,
            ExtentData::Regular { num_bytes, .. } | ExtentData::Prealloc { num_bytes } => num_bytes,
        }
    }
}
