//! Extended attributes: those in the inode's spare space after its fixed
//! fields, and those in its external block.
//!
//! Each change reads every attribute, applies the change, and lays them all
//! out again: the first ones in the inode while they fit, the rest in a
//! block, sorted, hashed and checksummed as Linux and e2fsck expect. A block
//! shared with other inodes (a reference count above one) is left to them
//! and a new one made.
//!
//! An attribute's name is stored as a one-byte index for its prefix and the
//! rest of the name: `user.`, `trusted.`, `security.` and `system.` are
//! stored. The two POSIX ACL names are kept in ext4's own encoding, which
//! this driver does not translate, so they can be read, listed and removed
//! but not set. Values over 64 KiB, and the `ea_inode` feature that would
//! keep big ones in inodes of their own, are not supported.

use alloc::vec::Vec;

use osmium_fs::{Errno, XattrSet};
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_push, try_to_vec, try_zeroed};

use super::{
    COMPAT_EXT_ATTR, Csum, Fs, Inode, XATTR_MAGIC, byte, crc32c, fill_range, get16, get32, ino, put_bytes, put16,
    put32, sb, sub,
};

const ENTRY_HEADER: usize = 16;
const BLOCK_HEADER: usize = 32;
/// Where a block's checksum is.
const BLOCK_CHECKSUM: usize = 0x10;
/// The first inode field past the fixed ones.
const OLD_INODE_SIZE: usize = 128;
/// Largest value kept.
const VALUE_MAX: usize = 65536;
const NAME_MAX: usize = 255;

/// Name indexes and the prefixes they stand for; the ACL ones are whole
/// names.
const PREFIXES: [(u8, &[u8], bool); 6] = [
    (1, b"user.", false),
    (2, b"system.posix_acl_access", true),
    (3, b"system.posix_acl_default", true),
    (4, b"trusted.", false),
    (6, b"security.", false),
    (7, b"system.", false),
];

/// An attribute: its name index (the prefix), the rest of its name, and its
/// value.
struct Xattr {
    index: u8,
    name: Vec<u8>,
    value: Vec<u8>,
}

impl Xattr {
    /// The full name ("user.comment").
    fn full_name(&self) -> Result<Vec<u8>, Errno> {
        let prefix = PREFIXES.iter().find(|p| p.0 == self.index).map_or(&b""[..], |p| p.1);
        let mut full = Vec::new();
        full.try_reserve_exact(prefix.len() + self.name.len()).map_err(|_| Errno::ENOMEM)?;
        full.extend_from_slice(prefix);
        full.extend_from_slice(&self.name);
        Ok(full)
    }

    /// The index and the rest of a full name: by the longest prefix that
    /// matches (an ACL name has to match whole).
    fn split(full: &[u8]) -> Option<(u8, &[u8])> {
        let (index, prefix, _) = PREFIXES
            .iter()
            .filter(|(_, p, whole)| if *whole { full == *p } else { full.starts_with(p) })
            .max_by_key(|(_, p, _)| p.len())?;
        Some((*index, full.get(prefix.len()..)?))
    }

    fn entry_len(&self) -> usize {
        (ENTRY_HEADER + self.name.len()).next_multiple_of(4)
    }

    /// Bytes the value takes in its container.
    fn value_len(&self) -> usize {
        self.value.len().next_multiple_of(4)
    }

    /// Linux's entry hash, over the name and the value's words.
    fn hash(&self) -> u32 {
        let mut h = 0u32;
        for &c in &self.name {
            // (`char` is signed.)
            h = (h << 5) ^ (h >> 27) ^ c as i8 as i32 as u32;
        }
        for w in self.value.chunks(4) {
            let mut word = [0u8; 4];
            word.iter_mut().zip(w).for_each(|(d, s)| *d = *s);
            h = (h << 16) ^ (h >> 16) ^ u32::from_le_bytes(word);
        }
        h
    }
}

/// Entries in `b` from `first` (up to `end`); value offsets are from
/// `base`.
fn parse(b: &[u8], first: usize, end: usize, base: usize) -> Result<Vec<Xattr>, Errno> {
    let mut out = Vec::new();
    let mut e = first;
    while e.checked_add(4).is_some_and(|x| x <= end) && get32(b, e) != 0 {
        if e + ENTRY_HEADER > end {
            return Err(Errno::EIO);
        }
        let name_len = byte(b, e) as usize;
        let (voff, inum, vsize) = (get16(b, e + 2) as usize, get32(b, e + 4), get32(b, e + 8) as usize);
        // Values in inodes of their own need a feature this driver refuses.
        if inum != 0 {
            return Err(Errno::EIO);
        }
        let name_end = e + ENTRY_HEADER + name_len;
        let name = b.get(e + ENTRY_HEADER..name_end.min(end)).filter(|n| n.len() == name_len).ok_or(Errno::EIO)?;
        let value = if vsize == 0 {
            &[][..]
        } else {
            let start = base.checked_add(voff).ok_or(Errno::EIO)?;
            let stop = start.checked_add(vsize).filter(|&s| s <= end).ok_or(Errno::EIO)?;
            b.get(start..stop).ok_or(Errno::EIO)?
        };
        try_push(&mut out, Xattr { index: byte(b, e + 1), name: try_to_vec(name)?, value: try_to_vec(value)? })?;
        e += (ENTRY_HEADER + name_len).next_multiple_of(4);
    }
    Ok(out)
}

/// Writes `list` as entries at `first`, values packed down from `end`
/// (offsets from `base`). The caller has checked that they fit.
fn pack(b: &mut [u8], first: usize, end: usize, base: usize, list: &[Xattr]) -> Result<(), Errno> {
    fill_range(b, first..end, 0)?;
    let (mut e, mut vend) = (first, end);
    for x in list {
        let voff = if x.value.is_empty() {
            0
        } else {
            vend = vend.checked_sub(x.value_len()).ok_or(Errno::EIO)?;
            put_bytes(b, vend, &x.value)?;
            vend.checked_sub(base).ok_or(Errno::EIO)?
        };
        put_bytes(b, e, &[x.name.len() as u8, x.index])?;
        put16(b, e + 2, voff as u16);
        put32(b, e + 4, 0);
        put32(b, e + 8, x.value.len() as u32);
        put32(b, e + 12, x.hash());
        put_bytes(b, e + ENTRY_HEADER, &x.name)?;
        e += x.entry_len();
    }
    Ok(())
}

/// Bytes `list` takes: entries, the 4-byte end marker, values.
fn space(list: &[Xattr]) -> usize {
    list.iter().map(|x| x.entry_len() + x.value_len()).sum::<usize>() + 4
}

impl<D: BlockDevice + Send + 'static> Fs<D> {
    /// Where an inode's own attributes are: `(start of the entry table, end)`;
    /// None if it has no room for any.
    fn xattr_area(&self, inode: &Inode) -> Option<(usize, usize)> {
        let extra = get16(&inode.raw, ino::EXTRA_ISIZE) as usize;
        if inode.raw.len() <= OLD_INODE_SIZE || extra == 0 || extra % 4 != 0 {
            return None;
        }
        let first = OLD_INODE_SIZE + extra + 4;
        (first <= inode.raw.len()).then_some((first, inode.raw.len()))
    }

    /// The checksum of attribute block `b`.
    fn xattr_block_csum(&self, b: u64, blk: &[u8]) -> u32 {
        let c = crc32c(self.csum_seed, &b.to_le_bytes());
        let c = crc32c(c, sub(blk, 0..BLOCK_CHECKSUM));
        let c = crc32c(c, &[0; 4]);
        crc32c(c, sub(blk, BLOCK_CHECKSUM + 4..blk.len()))
    }

    /// Sets the checksum of attribute block `b`.
    pub(super) fn seal_xattr_block(&self, b: u64, blk: &mut [u8]) {
        if self.csum == Csum::Crc32c {
            let sum = self.xattr_block_csum(b, blk);
            put32(blk, BLOCK_CHECKSUM, sum);
        }
    }

    /// Reads attribute block `b`, checking its header and checksum.
    fn read_xattr_block(&mut self, b: u64) -> Result<Vec<u8>, Errno> {
        let blk = self.read_block(b)?;
        if get32(&blk, 0) != XATTR_MAGIC || get32(&blk, 8) != 1 {
            return Err(Errno::EIO);
        }
        if self.csum == Csum::Crc32c && get32(&blk, BLOCK_CHECKSUM) != self.xattr_block_csum(b, &blk) {
            return Err(Errno::EIO);
        }
        Ok(blk)
    }

    /// All of an inode's extended attributes.
    fn xattrs(&mut self, inode: &Inode) -> Result<Vec<Xattr>, Errno> {
        let mut list = match self.xattr_area(inode) {
            Some((first, end)) if get32(&inode.raw, first - 4) == XATTR_MAGIC => parse(&inode.raw, first, end, first)?,
            _ => Vec::new(),
        };
        let b = inode.file_acl();
        if b != 0 {
            let blk = self.read_xattr_block(b)?;
            for x in parse(&blk, BLOCK_HEADER, blk.len(), 0)? {
                try_push(&mut list, x)?;
            }
        }
        Ok(list)
    }

    /// Lets go of an inode's attribute block: frees it, or, if other inodes
    /// share it, drops this one's reference.
    pub(super) fn release_xattr_block(&mut self, inode: &mut Inode) -> Result<(), Errno> {
        let acl = inode.file_acl();
        if acl == 0 {
            return Ok(());
        }
        let mut block = self.read_block(acl)?;
        let refs = if get32(&block, 0) == XATTR_MAGIC { get32(&block, 4) } else { 1 };
        if refs <= 1 {
            self.free_block(acl)?;
        } else {
            put32(&mut block, 4, refs - 1);
            self.seal_xattr_block(acl, &mut block);
            self.write_block(acl, &block)?;
        }
        put32(&mut inode.raw, ino::FILE_ACL, 0);
        put16(&mut inode.raw, ino::FILE_ACL_HIGH, 0);
        inode.add_sectors(-((self.block_size / 512) as i64));
        Ok(())
    }

    /// Stores `list` as the inode's extended attributes. The inode is
    /// changed in memory only; the caller writes it. Nothing is changed if
    /// the attributes do not fit.
    fn store_xattrs(&mut self, ino: u32, inode: &mut Inode, list: Vec<Xattr>) -> Result<(), Errno> {
        let area = self.xattr_area(inode);
        // The inode's own space: after the extra fields and the magic.
        let room = area.map_or(0, |(first, end)| end - first);
        let mut inside = Vec::new();
        let mut rest = Vec::new();
        let mut used = 4;
        for x in list {
            let need = x.entry_len() + x.value_len();
            if rest.is_empty() && used + need <= room {
                used += need;
                try_push(&mut inside, x)?;
            } else {
                try_push(&mut rest, x)?;
            }
        }
        if !rest.is_empty() && BLOCK_HEADER + space(&rest) > self.block_size {
            return Err(Errno::ENOSPC);
        }
        // The block, if one is needed, before anything changes: kept if
        // this inode alone has it, else a new one (made before a shared
        // one is let go, so that failing leaves things as they were).
        let old = inode.file_acl();
        let block = if rest.is_empty() {
            None
        } else if old != 0 && get32(&self.read_xattr_block(old)?, 4) == 1 {
            Some(old)
        } else {
            let b = self.alloc_block(self.group_start(self.group_of(ino)))?;
            self.release_xattr_block(inode)?;
            inode.add_sectors((self.block_size / 512) as i64);
            put32(&mut inode.raw, ino::FILE_ACL, b as u32);
            put16(&mut inode.raw, ino::FILE_ACL_HIGH, (b >> 32) as u16);
            Some(b)
        };
        if let Some((first, end)) = area {
            if inside.is_empty() {
                fill_range(&mut inode.raw, first - 4..end, 0)?;
            } else {
                put32(&mut inode.raw, first - 4, XATTR_MAGIC);
                pack(&mut inode.raw, first, end, first, &inside)?;
            }
        }
        let Some(b) = block else { return self.release_xattr_block(inode) };
        // Sorted as Linux keeps a block: by index, name length, name.
        rest.sort_unstable_by(|a, b| (a.index, a.name.len(), &a.name).cmp(&(b.index, b.name.len(), &b.name)));
        let mut blk = try_zeroed(self.block_size)?;
        put32(&mut blk, 0, XATTR_MAGIC);
        put32(&mut blk, 4, 1); // refcount
        put32(&mut blk, 8, 1); // blocks
        let len = blk.len();
        pack(&mut blk, BLOCK_HEADER, len, 0, &rest)?;
        let h = rest.iter().fold(0u32, |h, x| (h << 16) ^ (h >> 16) ^ x.hash());
        put32(&mut blk, 12, h);
        self.seal_xattr_block(b, &mut blk);
        self.write_block(b, &blk)
    }

    /// Makes sure the superblock says the file system has extended
    /// attributes.
    fn set_ext_attr_feature(&mut self) -> Result<(), Errno> {
        let compat = get32(&self.sb, sb::FEATURE_COMPAT);
        if compat & COMPAT_EXT_ATTR == 0 {
            put32(&mut self.sb, sb::FEATURE_COMPAT, compat | COMPAT_EXT_ATTR);
            self.write_super()?;
        }
        Ok(())
    }

    /// The value of the attribute `name` of inode `ino`.
    pub(super) fn xattr_get(&mut self, ino: u32, name: &[u8]) -> Result<Vec<u8>, Errno> {
        let (index, short) = Xattr::split(name).ok_or(Errno::ENODATA)?;
        let inode = self.read_inode(ino)?;
        let list = self.xattrs(&inode)?;
        let x = list.into_iter().find(|x| x.index == index && x.name == short).ok_or(Errno::ENODATA)?;
        Ok(x.value)
    }

    /// The full names of inode `ino`'s attributes.
    pub(super) fn xattr_list(&mut self, ino: u32) -> Result<Vec<Vec<u8>>, Errno> {
        let inode = self.read_inode(ino)?;
        let mut names = Vec::new();
        for x in self.xattrs(&inode)? {
            try_push(&mut names, x.full_name()?)?;
        }
        Ok(names)
    }

    /// Sets the attribute `name` of inode `ino`.
    pub(super) fn xattr_set(&mut self, ino: u32, name: &[u8], value: &[u8], how: XattrSet) -> Result<(), Errno> {
        self.writable()?;
        let (index, short) = Xattr::split(name).ok_or(Errno::EOPNOTSUPP)?;
        if matches!(index, 2 | 3) {
            return Err(Errno::EOPNOTSUPP);
        }
        if short.len() > NAME_MAX {
            return Err(Errno::ERANGE);
        }
        if value.len() > VALUE_MAX {
            return Err(Errno::E2BIG);
        }
        let mut inode = self.read_inode(ino)?;
        let mut list = self.xattrs(&inode)?;
        let at = list.iter().position(|x| x.index == index && x.name == short);
        match (how, at) {
            (XattrSet::Create, Some(_)) => return Err(Errno::EEXIST),
            (XattrSet::Replace, None) => return Err(Errno::ENODATA),
            _ => {}
        }
        if let Some(at) = at {
            list.remove(at);
        }
        try_push(&mut list, Xattr { index, name: try_to_vec(short)?, value: try_to_vec(value)? })?;
        self.set_ext_attr_feature()?;
        self.store_xattrs(ino, &mut inode, list)?;
        let now = self.now();
        inode.set_times(now, &[ino::CTIME]);
        self.write_inode(ino, &inode)
    }

    /// Removes the attribute `name` of inode `ino`.
    pub(super) fn xattr_remove(&mut self, ino: u32, name: &[u8]) -> Result<(), Errno> {
        self.writable()?;
        let (index, short) = Xattr::split(name).ok_or(Errno::ENODATA)?;
        let mut inode = self.read_inode(ino)?;
        let mut list = self.xattrs(&inode)?;
        let at = list.iter().position(|x| x.index == index && x.name == short).ok_or(Errno::ENODATA)?;
        list.remove(at);
        self.store_xattrs(ino, &mut inode, list)?;
        let now = self.now();
        inode.set_times(now, &[ino::CTIME]);
        self.write_inode(ino, &inode)
    }
}
