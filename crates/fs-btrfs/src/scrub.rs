// SPDX-License-Identifier: GPL-2.0-only
//! Scrub: reading every copy of every tree block and every checksummed data
//! sector, reporting the copies that do not match their checksums, and
//! rewriting each bad copy from a good one.
//!
//! Tree blocks are found through the extent tree and data through the
//! checksum tree, so data without checksums (`nodatasum` files, preallocated
//! space) is not looked at. Copies are the stripes of `single`, `DUP` and
//! mirrored chunks; striped chunks (RAID0, RAID10, RAID5, RAID6) are skipped
//! and counted. Superblock copies are not scrubbed.
//!
//! A repair overwrites a bad copy in place with the bytes of a good one.
//! That is idempotent, so a crash at any point leaves the volume valid, with
//! each copy either as it was or repaired.

use alloc::vec::Vec;

use osmium_fs::Errno;
use osmium_hal::block::BlockDevice;
use osmium_sync::fallible::{try_push, try_zeroed};

use crate::disk::{CSUM_SPACE, Chunk, Key, header, item, le64, profile, tree};
use crate::tree::Cursor;
use crate::{MAX_RUN, Shared, csum};

/// Most individual errors a report lists; the counters keep counting.
const MAX_LISTED: usize = 1024;

/// What was wrong with a copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrubErrorKind {
    /// The copy could not be read.
    Io,
    /// A data sector does not match its checksum.
    DataChecksum,
    /// A tree block does not match its checksum, address or fsid.
    TreeBlock,
}

/// One bad copy found by a scrub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScrubError {
    /// Logical address of the sector or tree block.
    pub logical: u64,
    /// The device holding the copy.
    pub devid: u64,
    /// Byte offset of the copy on that device.
    pub physical: u64,
    /// What was wrong.
    pub kind: ScrubErrorKind,
    /// Whether it was rewritten from a good copy.
    pub repaired: bool,
}

/// The outcome of [`crate::BtrfsFs::scrub`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScrubReport {
    /// Tree blocks checked (once per block, not per copy).
    pub tree_blocks: u64,
    /// Data sectors with checksums checked (once per sector).
    pub data_sectors: u64,
    /// Copies read and compared.
    pub copies_read: u64,
    /// Copies found bad: unreadable or not matching their checksum.
    pub bad_copies: u64,
    /// Bad copies rewritten from a good one.
    pub repaired: u64,
    /// Blocks and sectors with no good copy at all (or a bad copy and no
    /// other to repair it from).
    pub uncorrectable: u64,
    /// Chunks skipped because their profile is striped.
    pub skipped_chunks: u64,
    /// The first bad copies found.
    pub errors: Vec<ScrubError>,
}

impl ScrubReport {
    /// Whether every copy checked was good.
    pub fn is_clean(&self) -> bool {
        self.bad_copies == 0 && self.uncorrectable == 0
    }
}

/// One copy of a range: a device and the byte offset there.
#[derive(Clone, Copy)]
struct Copy {
    devid: u64,
    off: u64,
}

/// The copies of `logical` in `chunk`.
fn copies(chunk: &Chunk, logical: u64) -> Result<Vec<Copy>, Errno> {
    let within = logical.checked_sub(chunk.logical).ok_or(Errno::EIO)?;
    let mut v = Vec::new();
    v.try_reserve_exact(chunk.stripes.len()).map_err(|_| Errno::ENOMEM)?;
    for s in &chunk.stripes {
        v.push(Copy { devid: s.devid, off: s.offset.checked_add(within).ok_or(Errno::EIO)? });
    }
    Ok(v)
}

impl<D: BlockDevice + Send + 'static> Shared<D> {
    /// Notes a bad copy in `rep`.
    fn note(rep: &mut ScrubReport, logical: u64, c: Copy, kind: ScrubErrorKind, repaired: bool) {
        rep.bad_copies += 1;
        if repaired {
            rep.repaired += 1;
        }
        if rep.errors.len() < MAX_LISTED {
            let _ = try_push(&mut rep.errors, ScrubError { logical, devid: c.devid, physical: c.off, kind, repaired });
        }
    }

    /// Whether `b` is the tree block at `logical`.
    fn block_ok(&self, b: &[u8], logical: u64) -> bool {
        let Some((stored, rest)) = b.split_at_checked(CSUM_SPACE) else { return false };
        csum::matches(self.csum_type, rest, stored)
            && le64(b, header::BYTENR).ok() == Some(logical)
            && b.get(header::FSID..header::FSID + 16) == Some(&self.meta_uuid[..])
    }

    /// Scrubs the tree block at `logical`.
    fn scrub_block(&self, st: &crate::State, logical: u64, repair: bool, rep: &mut ScrubReport) -> Result<(), Errno> {
        let chunk = st.chunks.find(logical, self.nodesize as u64)?;
        if chunk.ty & profile::STRIPED != 0 {
            return Ok(());
        }
        rep.tree_blocks += 1;
        let cs = copies(chunk, logical)?;
        let mut good: Option<Vec<u8>> = None;
        let mut bad: Vec<(Copy, ScrubErrorKind)> = Vec::new();
        for &c in &cs {
            let mut b = try_zeroed(self.nodesize)?;
            rep.copies_read += 1;
            match self.read_phys(c.devid, c.off, &mut b) {
                Err(_) => try_push(&mut bad, (c, ScrubErrorKind::Io))?,
                Ok(()) if self.block_ok(&b, logical) => {
                    if good.is_none() {
                        good = Some(b);
                    }
                }
                Ok(()) => try_push(&mut bad, (c, ScrubErrorKind::TreeBlock))?,
            }
        }
        self.settle(logical, good.as_deref(), &bad, repair, rep);
        Ok(())
    }

    /// Repairs the copies in `bad` from `good`, or counts the range as
    /// uncorrectable if there is no good copy.
    fn settle(
        &self,
        logical: u64,
        good: Option<&[u8]>,
        bad: &[(Copy, ScrubErrorKind)],
        repair: bool,
        rep: &mut ScrubReport,
    ) {
        if bad.is_empty() {
            return;
        }
        if good.is_none() {
            rep.uncorrectable += 1;
        }
        for &(c, kind) in bad {
            let fixed = repair && good.is_some_and(|g| self.write_phys(c.devid, c.off, g).is_ok());
            Self::note(rep, logical, c, kind, fixed);
        }
        if repair && good.is_some() {
            let _ = self.flush();
        }
    }

    /// Scrubs `n` checksummed sectors from logical `at`, all in one chunk.
    fn scrub_run(
        &self,
        st: &crate::State,
        at: u64,
        sums: &[u8],
        repair: bool,
        rep: &mut ScrubReport,
    ) -> Result<(), Errno> {
        let (ss, cs) = (self.sectorsize as usize, self.csum_size);
        let n = sums.len() / cs;
        let chunk = st.chunks.find(at, (n * ss) as u64)?;
        if chunk.ty & profile::STRIPED != 0 {
            return Ok(());
        }
        rep.data_sectors += n as u64;
        let copy_list = copies(chunk, at)?;
        // Per sector: the first good copy's bytes, and the bad copies.
        let mut bufs: Vec<Option<Vec<u8>>> = Vec::new();
        for _ in 0..copy_list.len() {
            try_push(&mut bufs, None)?;
        }
        for (slot, &c) in bufs.iter_mut().zip(&copy_list) {
            let mut b = try_zeroed(n * ss)?;
            rep.copies_read += 1;
            if self.read_phys(c.devid, c.off, &mut b).is_ok() {
                *slot = Some(b);
            }
        }
        for i in 0..n {
            let want = sums.get(i * cs..(i + 1) * cs).ok_or(Errno::EIO)?;
            fn sector(b: &Option<Vec<u8>>, i: usize, ss: usize) -> Option<&[u8]> {
                b.as_deref().and_then(|b| b.get(i * ss..(i + 1) * ss))
            }
            let good = bufs.iter().find_map(|b| sector(b, i, ss).filter(|s| csum::matches(self.csum_type, s, want)));
            let mut bad: Vec<(Copy, ScrubErrorKind)> = Vec::new();
            for (b, &c) in bufs.iter().zip(&copy_list) {
                let c = Copy { devid: c.devid, off: c.off + (i * ss) as u64 };
                match sector(b, i, ss) {
                    None => try_push(&mut bad, (c, ScrubErrorKind::Io))?,
                    Some(s) if csum::matches(self.csum_type, s, want) => {}
                    Some(_) => try_push(&mut bad, (c, ScrubErrorKind::DataChecksum))?,
                }
            }
            self.settle(at + (i * ss) as u64, good, &bad, repair, rep);
        }
        Ok(())
    }

    /// Scrubs the whole volume as of the last commit. With `repair`, bad
    /// copies are rewritten from good ones (`EROFS` if the volume is
    /// read-only). Transactions are held off while it runs.
    pub(crate) fn scrub(&self, repair: bool) -> Result<ScrubReport, Errno> {
        if repair && self.writer.is_none() {
            return Err(Errno::EROFS);
        }
        let guard = self.writer.as_ref().map(|w| w.lock());
        if guard.as_ref().is_some_and(|w| w.broken) {
            return Err(Errno::EIO);
        }
        let st = self.state();
        let skipped_chunks = st.chunks.iter().filter(|c| c.ty & profile::STRIPED != 0).count() as u64;
        let mut rep = ScrubReport { skipped_chunks, ..ScrubReport::default() };

        // Tree blocks: everything the extent tree lists as one.
        let extent = self.tree_root(&st, tree::EXTENT)?.ok_or(Errno::EIO)?;
        let mut c = Cursor::new(self, &st.chunks, (extent.bytenr, extent.level));
        let mut cur = c.seek(Key::new(0, 0, 0))?;
        let mut blocks: Vec<u64> = Vec::new();
        while let Some((k, data)) = cur {
            let is_block = match k.ty {
                item::METADATA_ITEM => true,
                item::EXTENT_ITEM => le64(data, 16)? & 2 != 0,
                _ => false,
            };
            if is_block {
                try_push(&mut blocks, k.objectid)?;
            }
            cur = c.next()?;
        }
        for b in blocks {
            self.scrub_block(&st, b, repair, &mut rep)?;
        }

        // Data: everything the checksum tree has a checksum for.
        let (cs, ss) = (self.csum_size, self.sectorsize);
        let csum_root = st.csum_tree.ok_or(Errno::EIO)?;
        let mut c = Cursor::new(self, &st.chunks, csum_root);
        let mut cur = c.seek(Key::new(tree::EXTENT_CSUM, item::EXTENT_CSUM, 0))?;
        let per_run = (MAX_RUN / ss as usize).max(1);
        while let Some((k, data)) = cur {
            if k.objectid != tree::EXTENT_CSUM || k.ty != item::EXTENT_CSUM {
                break;
            }
            let total = data.len() / cs;
            let mut done = 0;
            while done < total {
                let at = k.offset.checked_add(done as u64 * ss).ok_or(Errno::EIO)?;
                let chunk = st.chunks.find(at, ss)?;
                let room = ((chunk.logical + chunk.length - at) / ss) as usize;
                let n = (total - done).min(per_run).min(room).max(1);
                let sums = data.get(done * cs..(done + n) * cs).ok_or(Errno::EIO)?;
                self.scrub_run(&st, at, sums, repair, &mut rep)?;
                done += n;
            }
            cur = c.next()?;
        }
        drop(guard);
        Ok(rep)
    }
}
