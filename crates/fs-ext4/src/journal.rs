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

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use osmium_fs::{Errno, FileKind};
use osmium_hal::block::BlockDevice;

use super::{COMPAT_HAS_JOURNAL, Fs, SUPERBLOCK_LEN, SUPERBLOCK_OFFSET, crc32c, get32, sb};

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

fn be32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off + 4].try_into().expect("four bytes"))
}

fn be16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

fn put_be32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_be_bytes());
}

fn put_be16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_be_bytes());
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
    failed: bool,
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
            || (incompat & INCOMPAT_CSUM_V3 != 0 && block[jsb::CHECKSUM_TYPE] != CRC32C_TYPE)
        {
            return Ok(None);
        }
        let csum = incompat & INCOMPAT_CSUM_V3 != 0;
        let seed = crc32c(!0, &block[jsb::UUID..jsb::UUID + 16]);
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
                _ => journal.runs.push((l, p, 1)),
            }
        }
        journal.sequence = be32(&journal.sb, jsb::SEQUENCE).wrapping_add(1);
        Ok(Some(journal))
    }

    /// The checksum of the journal superblock.
    fn super_csum(&self) -> u32 {
        let mut copy = self.sb[..jsb::LEN].to_vec();
        copy[jsb::CHECKSUM..jsb::CHECKSUM + 4].fill(0);
        crc32c(!0, &copy)
    }

    /// The file system block holding journal block `l`.
    fn phys(&self, l: u32) -> u64 {
        let l = l as u64;
        let i = self.runs.partition_point(|&(start, _, _)| start <= l);
        let (start, p, _) = self.runs[i - 1];
        p + (l - start)
    }

    fn read_log<D: BlockDevice + Send + 'static>(&self, fs: &mut Fs<D>, l: u32) -> Result<Vec<u8>, Errno> {
        fs.dev_read_block(self.phys(l))
    }

    fn write_log<D: BlockDevice + Send + 'static>(&self, fs: &mut Fs<D>, l: u32, buf: &[u8]) -> Result<(), Errno> {
        fs.dev_write_block(self.phys(l), buf)
    }

    /// The log position `n` blocks after `pos`, wrapping past the end.
    fn advance(&self, pos: u32, n: u64) -> u32 {
        let span = (self.len - self.first) as u64;
        self.first + (((pos - self.first) as u64 + n) % span) as u32
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
        let end = block.len() - 4;
        let mut copy = block.to_vec();
        copy[end..].fill(0);
        crc32c(self.seed, &copy) == be32(block, end)
    }

    fn commit_csum(&self, block: &[u8]) -> u32 {
        let mut copy = block.to_vec();
        copy[16..20].fill(0);
        crc32c(self.seed, &copy)
    }

    /// The tags in a descriptor block.
    fn tags(&self, block: &[u8]) -> Vec<Tag> {
        let tag_bytes = self.tag_bytes();
        let end = block.len() - self.tail_bytes();
        let mut tags = Vec::new();
        let mut off = 12;
        while off + tag_bytes <= end {
            let flags = be16(block, off + 6);
            let high = if self.wide { (be32(block, off + 8) as u64) << 32 } else { 0 };
            let csum = if self.csum { be32(block, off + 12) } else { 0 };
            tags.push(Tag { block: be32(block, off) as u64 | high, flags, csum });
            off += tag_bytes;
            if flags & FLAG_SAME_UUID == 0 {
                off += 16;
            }
            if flags & FLAG_LAST_TAG != 0 {
                break;
            }
        }
        tags
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
                    DESCRIPTOR if self.tail_ok(&block) => 1 + self.tags(&block).len() as u64,
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
    ) -> Result<BTreeMap<u64, u32>, Errno> {
        let mut revoked = BTreeMap::new();
        let record = if self.wide { 8 } else { 4 };
        let (mut id, mut pos) = (first_id, start);
        while id != end_id {
            let block = self.read_log(fs, pos)?;
            let mut blocks = 1;
            match be32(&block, 4) {
                DESCRIPTOR => blocks += self.tags(&block).len() as u64,
                COMMIT => id = id.wrapping_add(1),
                REVOKE => {
                    let used = (be32(&block, 12) as usize).min(block.len() - self.tail_bytes());
                    for off in (16..used.saturating_sub(record - 1)).step_by(record) {
                        let b = if self.wide {
                            u64::from_be_bytes(block[off..off + 8].try_into().expect("eight bytes"))
                        } else {
                            be32(&block, off) as u64
                        };
                        revoked.insert(b, id);
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
        revoked: &BTreeMap<u64, u32>,
    ) -> Result<(), Errno> {
        let (mut id, mut pos) = (first_id, start);
        while id != end_id {
            let block = self.read_log(fs, pos)?;
            let mut blocks = 1;
            match be32(&block, 4) {
                DESCRIPTOR => {
                    let tags = self.tags(&block);
                    blocks += tags.len() as u64;
                    for (i, tag) in tags.iter().enumerate() {
                        // Block 0 holds the superblock when blocks are over 1 KiB.
                        if tag.block >= fs.blocks_count() {
                            return Err(Errno::EINVAL);
                        }
                        if revoked.get(&tag.block).is_some_and(|&r| r.wrapping_sub(id) as i32 >= 0) {
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
        let per_descriptor = (block_size - 12 - self.tail_bytes() - 16) / self.tag_bytes();
        let space = (self.len - self.first) as usize;
        let cost = |k: usize| k + k.div_ceil(per_descriptor) + 1;
        let mut k = n.min(space);
        while k > 1 && cost(k) > space {
            k -= 1;
        }
        k
    }

    /// Logs and checkpoints `blocks`, as one transaction if they fit the
    /// log and as several in turn if they do not.
    pub(super) fn commit<D: BlockDevice + Send + 'static>(
        &mut self,
        fs: &mut Fs<D>,
        mut blocks: &[(u64, Vec<u8>)],
    ) -> Result<(), Errno> {
        while !blocks.is_empty() {
            let n = self.fit(blocks.len(), fs.block_size);
            self.transaction(fs, &blocks[..n])?;
            blocks = &blocks[n..];
        }
        Ok(())
    }

    fn transaction<D: BlockDevice + Send + 'static>(
        &mut self,
        fs: &mut Fs<D>,
        blocks: &[(u64, Vec<u8>)],
    ) -> Result<(), Errno> {
        let bs = fs.block_size;
        let id = self.sequence;
        let tag_bytes = self.tag_bytes();
        let limit = bs - self.tail_bytes();
        if !self.dirty {
            fs.set_disk_needs_recovery(true)?;
            self.dirty = true;
        }
        self.update_super(fs, self.first, id)?;
        let mut pos = self.first;
        let mut next = 0;
        while next < blocks.len() {
            let mut descriptor = vec![0; bs];
            put_header(&mut descriptor, DESCRIPTOR, id);
            let mut logged: Vec<Vec<u8>> = Vec::new();
            let (mut off, mut last) = (12, 12);
            while next < blocks.len() && off + tag_bytes + if logged.is_empty() { 16 } else { 0 } <= limit {
                let (b, data) = &blocks[next];
                if !self.wide && *b > u32::MAX as u64 {
                    return Err(Errno::EIO);
                }
                let mut data = data.clone();
                let mut flags = if logged.is_empty() { 0 } else { FLAG_SAME_UUID };
                if be32(&data, 0) == MAGIC {
                    // Replay must not mistake the block for a journal block.
                    data[..4].fill(0);
                    flags |= FLAG_ESCAPE;
                }
                put_be32(&mut descriptor, off, *b as u32);
                if self.csum {
                    put_be32(&mut descriptor, off + 4, flags as u32);
                    put_be32(&mut descriptor, off + 8, (*b >> 32) as u32);
                    put_be32(&mut descriptor, off + 12, self.data_csum(id, &data));
                } else {
                    put_be16(&mut descriptor, off + 6, flags);
                    if self.wide {
                        put_be32(&mut descriptor, off + 8, (*b >> 32) as u32);
                    }
                }
                last = off;
                off += tag_bytes;
                if logged.is_empty() {
                    descriptor[off..off + 16].copy_from_slice(&self.sb[jsb::UUID..jsb::UUID + 16]);
                    off += 16;
                }
                logged.push(data);
                next += 1;
            }
            descriptor[last + 7] |= FLAG_LAST_TAG as u8;
            if self.csum {
                let sum = crc32c(self.seed, &descriptor);
                put_be32(&mut descriptor, bs - 4, sum);
            }
            self.write_log(fs, pos, &descriptor)?;
            pos = self.advance(pos, 1);
            for data in &logged {
                self.write_log(fs, pos, data)?;
                pos = self.advance(pos, 1);
            }
        }
        // The commit block must not reach the disk before what it commits.
        fs.flush()?;
        let mut commit = vec![0; bs];
        put_header(&mut commit, COMMIT, id);
        commit[48..56].copy_from_slice(&(fs.now() as u64).to_be_bytes());
        if self.csum {
            let sum = self.commit_csum(&commit);
            put_be32(&mut commit, 16, sum);
        }
        self.write_log(fs, pos, &commit)?;
        fs.flush()?;
        for (b, data) in blocks {
            fs.dev_write_block(*b, data)?;
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
        let mut disk = vec![0; SUPERBLOCK_LEN];
        self.dev_read_bytes(SUPERBLOCK_OFFSET, &mut disk)?;
        let flags = get32(&disk, sb::FEATURE_INCOMPAT);
        let flags = if on { flags | super::INCOMPAT_RECOVER } else { flags & !super::INCOMPAT_RECOVER };
        super::put32(&mut disk, sb::FEATURE_INCOMPAT, flags);
        if self.csum == super::Csum::Crc32c {
            let sum = crc32c(!0, &disk[..sb::CHECKSUM]);
            super::put32(&mut disk, sb::CHECKSUM, sum);
        }
        self.dev_write_bytes(SUPERBLOCK_OFFSET, &disk)?;
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
        let Some(mut journal) = self.journal.take() else { return Ok(()) };
        let blocks: Vec<(u64, Vec<u8>)> = core::mem::take(&mut self.tx).into_iter().collect();
        let result = if journal.failed { Err(Errno::EIO) } else { journal.commit(self, &blocks) };
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
