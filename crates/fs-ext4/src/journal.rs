//! The JBD2 journal: replay at mount, and write-ahead logging of metadata.
//!
//! Every operation collects the metadata blocks it changes in memory (`Fs::tx`).
//! When the operation ends they are written to the log as one transaction: a
//! descriptor block naming the destinations, the blocks themselves, and a
//! commit block, with the device flushed before the commit block and again
//! after it. Only then are the blocks written to their places and the device
//! flushed once more (the checkpoint). File data is not logged: it is
//! written in place before the commit (`data=ordered`), and a block freed by
//! a transaction is not reused until it commits.
//!
//! Because a transaction is checkpointed before the next begins, the log
//! always starts at its first block, and the only transaction a crash can
//! leave to replay is the last one, whose replay changes nothing if the
//! checkpoint had finished. Each transaction rewrites the journal superblock
//! with its sequence number, so that blocks of earlier ones are never taken
//! for part of it. A clean unmount marks the journal empty and clears the
//! file system's `needs_recovery` flag.
//!
//! Replay accepts logs written by Linux: revoke records, escaped blocks, the
//! `64bit` tag format and `csum_v3` checksums, any number of transactions
//! and a log that wraps. Journals with other features (external journals,
//! `csum_v2`, `async_commit`, fast commits) are not understood.

use alloc::vec::Vec;

use osmium_fs::{Errno, FileKind};
use osmium_hal::block::BlockDevice;
use osmium_sync::arc::ArcTree;
use osmium_sync::fallible::{try_push, try_zeroed};

use super::{ByBlock, COMPAT_HAS_JOURNAL, Fs, SUPERBLOCK_OFFSET, byte, crc32c, get32, or_byte, put_bytes, sb, sub};

const MAGIC: u32 = 0xc03b_3998;

const DESCRIPTOR: u32 = 1;
const COMMIT: u32 = 2;
const SUPER_V1: u32 = 3;
const SUPER_V2: u32 = 4;
const REVOKE: u32 = 5;

/// Journal superblock field offsets (big endian).
mod jsb {
    pub const BLOCK_SIZE: usize = 0x0c;
    pub const MAX_LEN: usize = 0x10;
    pub const FIRST: usize = 0x14;
    pub const SEQUENCE: usize = 0x18;
    pub const START: usize = 0x1c;
    pub const INCOMPAT: usize = 0x28;
    pub const RO_COMPAT: usize = 0x2c;
    pub const UUID: usize = 0x30;
    pub const NR_USERS: usize = 0x40;
    pub const CHECKSUM_TYPE: usize = 0x50;
    pub const CHECKSUM: usize = 0xfc;
    /// The part of the superblock the checksum covers.
    pub const LEN: usize = 1024;
}

const INCOMPAT_REVOKE: u32 = 0x1;
const INCOMPAT_64BIT: u32 = 0x2;
const INCOMPAT_CSUM_V3: u32 = 0x10;
const INCOMPAT_SUPPORTED: u32 = INCOMPAT_REVOKE | INCOMPAT_64BIT | INCOMPAT_CSUM_V3;

/// The checksum type of `csum_v3` journals: CRC32C.
const CRC32C_TYPE: u8 = 4;

const FLAG_ESCAPE: u16 = 1;
const FLAG_SAME_UUID: u16 = 2;
const FLAG_LAST_TAG: u16 = 8;

/// Linux refuses journals smaller than this many blocks.
const MIN_BLOCKS: u64 = 1024;

/// Big-endian fields. As in the file system proper, a field past the end of
/// its block reads as zero and ignores writes.
fn be32(buf: &[u8], off: usize) -> u32 {
    off.checked_add(4)
        .and_then(|end| buf.get(off..end))
        .and_then(|b| b.first_chunk::<4>())
        .map_or(0, |b| u32::from_be_bytes(*b))
}

fn be16(buf: &[u8], off: usize) -> u16 {
    off.checked_add(2)
        .and_then(|end| buf.get(off..end))
        .and_then(|b| b.first_chunk::<2>())
        .map_or(0, |b| u16::from_be_bytes(*b))
}

fn put_be32(buf: &mut [u8], off: usize, val: u32) {
    let _ = put_bytes(buf, off, &val.to_be_bytes());
}

fn put_be16(buf: &mut [u8], off: usize, val: u16) {
    let _ = put_bytes(buf, off, &val.to_be_bytes());
}

/// Starts a descriptor, commit or revoke block.
fn put_header(buf: &mut [u8], kind: u32, sequence: u32) {
    put_be32(buf, 0, MAGIC);
    put_be32(buf, 4, kind);
    put_be32(buf, 8, sequence);
}

/// One block a descriptor names.
struct Tag {
    block: u64,
    flags: u16,
    csum: u32,
}

/// An internal journal, open for replay or logging.
pub(super) struct Journal {
    /// `(first journal block, file system block, length)`, sorted.
    runs: Vec<(u64, u64, u64)>,
    /// The journal superblock's block, as last written.
    sb: Vec<u8>,
    first: u32,
    len: u32,
    /// The ID of the next transaction.
    sequence: u32,
    /// Block numbers are 64 bits.
    wide: bool,
    /// `csum_v3`: descriptors, commits and data blocks carry checksums.
    csum: bool,
    seed: u32,
    /// The file system's `needs_recovery` flag is on disk.
    dirty: bool,
    /// A transaction failed to reach the disk. The log may hold a committed
    /// transaction that was not checkpointed, so it must stay for the next
    /// mount to replay.
    pub(super) failed: bool,
    /// Room for a transaction's descriptor block, commit block and an
    /// escaped copy of a data block, reserved here so that committing never
    /// has to allocate.
    scratch: Vec<u8>,
}

impl Journal {
    /// Finds the journal of a file system and reads its superblock. `None`
    /// if there is none or it is of a kind this driver does not understand.
    pub(super) fn open<D: BlockDevice + Send + 'static>(fs: &mut Fs<D>) -> Result<Option<Self>, Errno> {
        if get32(&fs.sb, sb::FEATURE_COMPAT) & COMPAT_HAS_JOURNAL == 0 {
            return Ok(None);
        }
        let inum = get32(&fs.sb, sb::JOURNAL_INUM);
        if inum == 0 {
            // A journal on another device.
            return Ok(None);
        }
        let mut inode = fs.read_inode(inum)?;
        let blocks = (inode.size() / fs.block_size as u64).min(u32::MAX as u64);
        if inode.kind() != FileKind::Regular || blocks < MIN_BLOCKS {
            return Err(Errno::EINVAL);
        }
        let usable = |fs: &Fs<D>, p: u64| p != 0 && p < fs.blocks_count() && !fs.in_meta_zone(p);
        let head = fs.bmap(inum, &mut inode, 0, false)?;
        if !usable(fs, head) {
            return Err(Errno::EINVAL);
        }
        let block = fs.dev_read_block(head)?;
        if be32(&block, 0) != MAGIC {
            return Err(Errno::EINVAL);
        }
        let (incompat, ro_compat) = match be32(&block, 4) {
            SUPER_V2 => (be32(&block, jsb::INCOMPAT), be32(&block, jsb::RO_COMPAT)),
            SUPER_V1 => (0, 0),
            _ => return Err(Errno::EINVAL),
        };
        let (len, first) = (be32(&block, jsb::MAX_LEN), be32(&block, jsb::FIRST));
        if be32(&block, jsb::BLOCK_SIZE) as usize != fs.block_size
            || (len as u64) < MIN_BLOCKS
            || len as u64 > blocks
            || first == 0
            || first >= len
        {
            return Err(Errno::EINVAL);
        }
        if incompat & !INCOMPAT_SUPPORTED != 0
            || ro_compat != 0
            || (be32(&block, 4) == SUPER_V2 && be32(&block, jsb::NR_USERS) > 1)
            || (incompat & INCOMPAT_CSUM_V3 != 0 && byte(&block, jsb::CHECKSUM_TYPE) != CRC32C_TYPE)
        {
            return Ok(None);
        }
        let csum = incompat & INCOMPAT_CSUM_V3 != 0;
        let seed = crc32c(!0, sub(&block, jsb::UUID..jsb::UUID + 16));
        let mut journal = Journal {
            runs: Vec::new(),
            sb: block,
            first,
            len,
            sequence: 0,
            wide: incompat & INCOMPAT_64BIT != 0,
            csum,
            seed,
            dirty: false,
            failed: false,
            scratch: try_zeroed(3 * fs.block_size)?,
        };
        if csum && journal.super_csum() != be32(&journal.sb, jsb::CHECKSUM) {
            return Err(Errno::EINVAL);
        }
        for l in 0..len as u64 {
            let p = if l == 0 { head } else { fs.bmap(inum, &mut inode, l, false)? };
            if !usable(fs, p) {
                return Err(Errno::EINVAL);
            }
            match journal.runs.last_mut() {
                Some((lstart, pstart, n)) if *lstart + *n == l && *pstart + *n == p => *n += 1,
                _ => try_push(&mut journal.runs, (l, p, 1))?,
            }
        }
        journal.sequence = be32(&journal.sb, jsb::SEQUENCE).wrapping_add(1);
        Ok(Some(journal))
    }

    /// The checksum of the journal superblock.
    fn super_csum(&self) -> u32 {
        // Over the superblock with its checksum field read as zero.
        let (at, end) = (jsb::CHECKSUM, jsb::CHECKSUM + 4);
        crc32c(crc32c(crc32c(!0, sub(&self.sb, 0..at)), &[0; 4]), sub(&self.sb, end..jsb::LEN))
    }

    /// The file system block holding journal block `l`.
    fn phys(&self, l: u32) -> Result<u64, Errno> {
        let l = l as u64;
        let i = self.runs.partition_point(|&(start, _, _)| start <= l);
        let &(start, p, n) = i.checked_sub(1).and_then(|i| self.runs.get(i)).ok_or(Errno::EIO)?;
        if l - start >= n {
            return Err(Errno::EIO);
        }
        p.checked_add(l - start).ok_or(Errno::EIO)
    }

    fn read_log<D: BlockDevice + Send + 'static>(&self, fs: &mut Fs<D>, l: u32) -> Result<Vec<u8>, Errno> {
        fs.dev_read_block(self.phys(l)?)
    }

    fn write_log<D: BlockDevice + Send + 'static>(&self, fs: &mut Fs<D>, l: u32, buf: &[u8]) -> Result<(), Errno> {
        fs.dev_write_block(self.phys(l)?, buf)
    }

    /// The log position `n` blocks after `pos`, wrapping past the end.
    fn advance(&self, pos: u32, n: u64) -> u32 {
        let span = u64::from(self.len.saturating_sub(self.first)).max(1);
        let from = u64::from(pos.saturating_sub(self.first));
        self.first.wrapping_add((from.wrapping_add(n) % span) as u32)
    }

    /// Rewrites the journal superblock to say the log starts at `start`
    /// (0 for an empty one) with transaction `sequence` first.
    fn update_super<D: BlockDevice + Send + 'static>(
        &mut self,
        fs: &mut Fs<D>,
        start: u32,
        sequence: u32,
    ) -> Result<(), Errno> {
        put_be32(&mut self.sb, jsb::START, start);
        put_be32(&mut self.sb, jsb::SEQUENCE, sequence);
        if self.csum {
            put_be32(&mut self.sb, jsb::CHECKSUM, 0);
            let sum = self.super_csum();
            put_be32(&mut self.sb, jsb::CHECKSUM, sum);
        }
        self.write_log(fs, 0, &self.sb)
    }

    // ---- Block formats ----

    fn tag_bytes(&self) -> usize {
        if self.csum {
            16
        } else if self.wide {
            12
        } else {
            8
        }
    }

    /// The bytes at the end of a descriptor or revoke block holding its
    /// checksum.
    fn tail_bytes(&self) -> usize {
        if self.csum { 4 } else { 0 }
    }

    /// Whether a descriptor or revoke block's checksum is right.
    fn tail_ok(&self, block: &[u8]) -> bool {
        if !self.csum {
            return true;
        }
        let end = block.len().saturating_sub(4);
        crc32c(crc32c(self.seed, sub(block, 0..end)), &[0; 4]) == be32(block, end)
    }

    fn commit_csum(&self, block: &[u8]) -> u32 {
        // Over the block with the checksum field read as zero.
        crc32c(crc32c(crc32c(self.seed, sub(block, 0..16)), &[0; 4]), block.get(20..).unwrap_or(&[]))
    }

    /// The tags in a descriptor block.
    fn tags(&self, block: &[u8]) -> Result<Vec<Tag>, Errno> {
        let tag_bytes = self.tag_bytes();
        let end = block.len().saturating_sub(self.tail_bytes());
        let mut tags = Vec::new();
        let mut off = 12;
        while off + tag_bytes <= end {
            let flags = be16(block, off + 6);
            let high = if self.wide { (be32(block, off + 8) as u64) << 32 } else { 0 };
            let csum = if self.csum { be32(block, off + 12) } else { 0 };
            try_push(&mut tags, Tag { block: be32(block, off) as u64 | high, flags, csum })?;
            off += tag_bytes;
            if flags & FLAG_SAME_UUID == 0 {
                off += 16;
            }
            if flags & FLAG_LAST_TAG != 0 {
                break;
            }
        }
        Ok(tags)
    }

    /// The checksum of a data block as the log holds it.
    fn data_csum(&self, sequence: u32, data: &[u8]) -> u32 {
        crc32c(crc32c(self.seed, &sequence.to_be_bytes()), data)
    }

    // ---- Replay ----

    /// Replays the transactions in the log, then marks the journal empty.
    pub(super) fn replay<D: BlockDevice + Send + 'static>(&mut self, fs: &mut Fs<D>) -> Result<(), Errno> {
        let start = be32(&self.sb, jsb::START);
        let first_id = be32(&self.sb, jsb::SEQUENCE);
        let mut end_id = first_id;
        if start != 0 {
            if start < self.first || start >= self.len {
                return Err(Errno::EINVAL);
            }
            // Find the end of the log: the first transaction with no
            // valid commit block.
            let span = (self.len - self.first) as u64;
            let (mut id, mut pos, mut used) = (first_id, start, 0u64);
            loop {
                let block = self.read_log(fs, pos)?;
                if be32(&block, 0) != MAGIC || be32(&block, 8) != id {
                    break;
                }
                let blocks = match be32(&block, 4) {
                    DESCRIPTOR if self.tail_ok(&block) => 1 + self.tags(&block)?.len() as u64,
                    REVOKE if self.tail_ok(&block) => 1,
                    COMMIT if self.csum_ok_commit(&block) => {
                        id = id.wrapping_add(1);
                        1
                    }
                    _ => break,
                };
                used += blocks;
                if used > span {
                    return Err(Errno::EINVAL);
                }
                pos = self.advance(pos, blocks);
            }
            end_id = id;
            let revoked = self.revocations(fs, start, first_id, end_id)?;
            self.replay_blocks(fs, start, first_id, end_id, &revoked)?;
            fs.flush()?;
        }
        // Stale blocks of the transaction that did not commit must not
        // pass for a later one.
        self.sequence = end_id.wrapping_add(1);
        self.update_super(fs, 0, end_id.wrapping_add(1))?;
        fs.flush()
    }

    fn csum_ok_commit(&self, block: &[u8]) -> bool {
        !self.csum || self.commit_csum(block) == be32(block, 16)
    }

    /// The revoked blocks of the transactions `first_id..end_id`, each with
    /// the last transaction to revoke it.
    fn revocations<D: BlockDevice + Send + 'static>(
        &self,
        fs: &mut Fs<D>,
        start: u32,
        first_id: u32,
        end_id: u32,
    ) -> Result<Vec<(u64, u32)>, Errno> {
        // Sorted by block.
        let mut revoked: Vec<(u64, u32)> = Vec::new();
        let record = if self.wide { 8 } else { 4 };
        let (mut id, mut pos) = (first_id, start);
        while id != end_id {
            let block = self.read_log(fs, pos)?;
            let mut blocks = 1;
            match be32(&block, 4) {
                DESCRIPTOR => blocks += self.tags(&block)?.len() as u64,
                COMMIT => id = id.wrapping_add(1),
                REVOKE => {
                    let used = (be32(&block, 12) as usize).min(block.len().saturating_sub(self.tail_bytes()));
                    for off in (16..used.saturating_sub(record - 1)).step_by(record) {
                        let b = if self.wide {
                            (be32(&block, off) as u64) << 32 | be32(&block, off + 4) as u64
                        } else {
                            be32(&block, off) as u64
                        };
                        match revoked.binary_search_by_key(&b, |&(block, _)| block) {
                            Ok(i) => {
                                if let Some(slot) = revoked.get_mut(i) {
                                    slot.1 = id;
                                }
                            }
                            Err(i) => {
                                revoked.try_reserve(1).map_err(|_| Errno::ENOMEM)?;
                                revoked.insert(i, (b, id));
                            }
                        }
                    }
                }
                _ => return Err(Errno::EINVAL),
            }
            pos = self.advance(pos, blocks);
        }
        Ok(revoked)
    }

    /// Writes every logged block, unless a later transaction revoked it, to
    /// its place.
    fn replay_blocks<D: BlockDevice + Send + 'static>(
        &self,
        fs: &mut Fs<D>,
        start: u32,
        first_id: u32,
        end_id: u32,
        revoked: &[(u64, u32)],
    ) -> Result<(), Errno> {
        let (mut id, mut pos) = (first_id, start);
        while id != end_id {
            let block = self.read_log(fs, pos)?;
            let mut blocks = 1;
            match be32(&block, 4) {
                DESCRIPTOR => {
                    let tags = self.tags(&block)?;
                    blocks += tags.len() as u64;
                    for (i, tag) in tags.iter().enumerate() {
                        // Block 0 holds the superblock when blocks are over 1 KiB.
                        if tag.block >= fs.blocks_count() {
                            return Err(Errno::EINVAL);
                        }
                        let revoked_at = revoked.binary_search_by_key(&tag.block, |&(block, _)| block).ok();
                        if revoked_at.and_then(|i| revoked.get(i)).is_some_and(|r| r.1.wrapping_sub(id) as i32 >= 0) {
                            continue;
                        }
                        let mut data = self.read_log(fs, self.advance(pos, 1 + i as u64))?;
                        if self.csum && self.data_csum(id, &data) != tag.csum {
                            return Err(Errno::EIO);
                        }
                        if tag.flags & FLAG_ESCAPE != 0 {
                            put_be32(&mut data, 0, MAGIC);
                        }
                        fs.dev_write_block(tag.block, &data)?;
                    }
                }
                COMMIT => id = id.wrapping_add(1),
                _ => {}
            }
            pos = self.advance(pos, blocks);
        }
        Ok(())
    }

    // ---- Logging ----

    /// How many of `n` blocks fit in the log with their descriptors and a
    /// commit block.
    fn fit(&self, n: usize, block_size: usize) -> usize {
        let per_descriptor = (block_size.saturating_sub(12 + self.tail_bytes() + 16) / self.tag_bytes()).max(1);
        let space = (self.len - self.first) as usize;
        let cost = |k: usize| k + k.div_ceil(per_descriptor) + 1;
        let mut k = n.min(space);
        while k > 1 && cost(k) > space {
            k -= 1;
        }
        k
    }

    /// Logs and checkpoints the blocks of `tx`, as one transaction if they
    /// fit the log and as several in turn if they do not. Allocates nothing.
    pub(super) fn commit<D: BlockDevice + Send + 'static>(
        &mut self,
        fs: &mut Fs<D>,
        tx: &ArcTree<ByBlock>,
    ) -> Result<(), Errno> {
        let total = tx.len();
        let mut done = 0;
        while done < total {
            let n = self.fit(total - done, fs.block_size);
            self.transaction(fs, tx, done, n)?;
            done += n;
        }
        Ok(())
    }

    /// `data` as the log holds it: escaped, in `scratch`, if it starts like a
    /// journal block (replay must not mistake it for one); and whether it was.
    fn escape<'a>(data: &'a [u8], scratch: &'a mut [u8]) -> Result<(&'a [u8], bool), Errno> {
        if be32(data, 0) != MAGIC {
            return Ok((data, false));
        }
        let copy = scratch.get_mut(..data.len()).ok_or(Errno::EIO)?;
        copy.copy_from_slice(data);
        put_bytes(copy, 0, &[0; 4])?;
        Ok((copy, true))
    }

    /// Logs the `count` blocks of `tx` after the first `skip`, as one
    /// transaction.
    fn transaction<D: BlockDevice + Send + 'static>(
        &mut self,
        fs: &mut Fs<D>,
        tx: &ArcTree<ByBlock>,
        skip: usize,
        count: usize,
    ) -> Result<(), Errno> {
        // Out of `self` while it is used, so the journal can still be read.
        let mut scratch = core::mem::take(&mut self.scratch);
        let result = self.log_transaction(fs, tx, skip, count, &mut scratch);
        self.scratch = scratch;
        result
    }

    fn log_transaction<D: BlockDevice + Send + 'static>(
        &mut self,
        fs: &mut Fs<D>,
        tx: &ArcTree<ByBlock>,
        skip: usize,
        count: usize,
        scratch: &mut [u8],
    ) -> Result<(), Errno> {
        let bs = fs.block_size;
        let id = self.sequence;
        let tag_bytes = self.tag_bytes();
        let limit = bs - self.tail_bytes();
        let (descriptor, rest) = scratch.split_at_mut_checked(bs).ok_or(Errno::EIO)?;
        let (commit, escaped) = rest.split_at_mut_checked(bs).ok_or(Errno::EIO)?;
        if !self.dirty {
            fs.set_disk_needs_recovery(true)?;
            self.dirty = true;
        }
        self.update_super(fs, self.first, id)?;
        let mut pos = self.first;
        let mut next = 0;
        while next < count {
            descriptor.fill(0);
            put_header(descriptor, DESCRIPTOR, id);
            let (mut off, mut last) = (12, 12);
            // The blocks this descriptor names.
            let mut batch = 0;
            for t in tx.iter().skip(skip + next).take(count - next) {
                if off + tag_bytes + if batch == 0 { 16 } else { 0 } > limit {
                    break;
                }
                let b = t.blk;
                if !self.wide && b > u32::MAX as u64 {
                    return Err(Errno::EIO);
                }
                let (data, escape) = Self::escape(t.bytes(), escaped)?;
                let mut flags = if batch == 0 { 0 } else { FLAG_SAME_UUID };
                if escape {
                    flags |= FLAG_ESCAPE;
                }
                put_be32(descriptor, off, b as u32);
                if self.csum {
                    put_be32(descriptor, off + 4, flags as u32);
                    put_be32(descriptor, off + 8, (b >> 32) as u32);
                    put_be32(descriptor, off + 12, self.data_csum(id, data));
                } else {
                    put_be16(descriptor, off + 6, flags);
                    if self.wide {
                        put_be32(descriptor, off + 8, (b >> 32) as u32);
                    }
                }
                last = off;
                off += tag_bytes;
                if batch == 0 {
                    put_bytes(descriptor, off, sub(&self.sb, jsb::UUID..jsb::UUID + 16))?;
                    off += 16;
                }
                batch += 1;
            }
            if batch == 0 {
                // The transaction names fewer blocks than it was sized for.
                return Err(Errno::EIO);
            }
            or_byte(descriptor, last + 7, FLAG_LAST_TAG as u8)?;
            if self.csum {
                let sum = crc32c(self.seed, descriptor);
                put_be32(descriptor, bs - 4, sum);
            }
            self.write_log(fs, pos, descriptor)?;
            pos = self.advance(pos, 1);
            for t in tx.iter().skip(skip + next).take(batch) {
                let (data, _) = Self::escape(t.bytes(), escaped)?;
                self.write_log(fs, pos, data)?;
                pos = self.advance(pos, 1);
            }
            next += batch;
        }
        // The commit block must not reach the disk before what it commits.
        fs.flush()?;
        commit.fill(0);
        put_header(commit, COMMIT, id);
        put_bytes(commit, 48, &(fs.now() as u64).to_be_bytes())?;
        if self.csum {
            let sum = self.commit_csum(commit);
            put_be32(commit, 16, sum);
        }
        self.write_log(fs, pos, commit)?;
        fs.flush()?;
        for t in tx.iter().skip(skip).take(count) {
            fs.dev_write_block(t.blk, t.bytes())?;
        }
        fs.flush()?;
        self.sequence = id.wrapping_add(1);
        Ok(())
    }

    /// Marks the journal empty and the file system clean, as unmounting does.
    pub(super) fn close<D: BlockDevice + Send + 'static>(&mut self, fs: &mut Fs<D>) -> Result<(), Errno> {
        if !self.dirty || self.failed {
            return Ok(());
        }
        self.update_super(fs, 0, self.sequence)?;
        fs.flush()?;
        fs.set_disk_needs_recovery(false)?;
        fs.flush()?;
        self.dirty = false;
        Ok(())
    }
}

impl<D: BlockDevice + Send + 'static> Fs<D> {
    /// Sets or clears the `needs_recovery` flag in the superblock on disk,
    /// leaving the rest of it as the last checkpoint wrote it.
    pub(super) fn set_disk_needs_recovery(&mut self, on: bool) -> Result<(), Errno> {
        // The buffer is out of `self` while it is used.
        let mut disk = core::mem::take(&mut self.sb_copy);
        let result = self.set_disk_flag(&mut disk, on);
        self.sb_copy = disk;
        result
    }

    fn set_disk_flag(&mut self, disk: &mut [u8], on: bool) -> Result<(), Errno> {
        self.dev_read_bytes(SUPERBLOCK_OFFSET, disk)?;
        let flags = get32(disk, sb::FEATURE_INCOMPAT);
        let flags = if on { flags | super::INCOMPAT_RECOVER } else { flags & !super::INCOMPAT_RECOVER };
        super::put32(disk, sb::FEATURE_INCOMPAT, flags);
        if self.csum == super::Csum::Crc32c {
            let sum = crc32c(!0, sub(disk, 0..sb::CHECKSUM));
            super::put32(disk, sb::CHECKSUM, sum);
        }
        self.dev_write_bytes(SUPERBLOCK_OFFSET, disk)?;
        self.flush()
    }

    pub(super) fn flush(&mut self) -> Result<(), Errno> {
        self.dev.flush().map_err(super::io_error)
    }

    /// Ends the transaction in progress: writes what it changed to the log
    /// and then in place. A failure leaves the file system read-only, since
    /// memory may then be ahead of the disk.
    pub(super) fn commit(&mut self) -> Result<(), Errno> {
        self.tx_freed.clear();
        let tx = core::mem::take(&mut self.tx);
        let Some(mut journal) = self.journal.take() else {
            // No journal: the blocks go straight to their places.
            for t in tx.iter() {
                self.dev_write_block(t.blk, t.bytes())?;
            }
            return Ok(());
        };
        let result = if journal.failed { Err(Errno::EIO) } else { journal.commit(self, &tx) };
        if result.is_err() {
            journal.failed = true;
            self.read_only = true;
        }
        self.journal = Some(journal);
        result
    }

    /// Runs `f` as one transaction, which commits whether it succeeds or
    /// not: what an operation leaves half done is consistent block by
    /// block, as it was when changes went straight to the disk.
    pub(super) fn transact<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, Errno>) -> Result<T, Errno> {
        let result = f(self);
        if matches!(result, Err(Errno::ENOMEM)) {
            // Out of memory part way: the operation had half-done effects
            // that nothing can finish. Undo them all, so it is as if it never
            // began.
            self.abort();
            return result;
        }
        let committed = self.commit();
        let value = result?;
        committed.map(|()| value)
    }

    /// Commits what is pending and marks the journal clean.
    pub(super) fn close_journal(&mut self) {
        // Nowhere to report an error from an unmount: the journal then
        // stays dirty, and the next mount replays it.
        let _ = self.commit();
        if let Some(mut journal) = self.journal.take() {
            if journal.close(self).is_ok() {
                let flags = get32(&self.sb, sb::FEATURE_INCOMPAT) & !super::INCOMPAT_RECOVER;
                super::put32(&mut self.sb, sb::FEATURE_INCOMPAT, flags);
            }
            self.journal = Some(journal);
        }
    }
}
