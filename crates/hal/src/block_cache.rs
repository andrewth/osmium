//! A block cache that sits between a file system and a [`BlockDevice`].
//!
//! [`CachedDevice`] wraps any device and is itself a [`BlockDevice`], so every
//! file system driver gets caching by being handed the wrapper. All its memory
//! (the data, the lookup table and the replacement list) is allocated once in
//! [`CachedDevice::new`], so a read or write never fails for lack of memory.
//!
//! Replacement is least-recently-used. Two write policies are available:
//!
//! - [`WritePolicy::WriteThrough`]: a write goes to the device at once and also
//!   updates a cached copy. The device is always current; only reads gain.
//! - [`WritePolicy::WriteBack`]: a write stays in the cache, marked dirty, until
//!   the block is evicted or [`flush`](BlockDevice::flush) is called, which
//!   writes dirty blocks back in ascending order, merging neighbours into one
//!   request. A crash loses unflushed writes, so a file system that orders
//!   its writes (a journal) must call `flush` where it needs ordering.
//!
//! A failed write-back leaves the block dirty and reports the error from the
//! operation that triggered it.

use alloc::vec::Vec;

use crate::block::{BlockDevice, BlockError};

/// When a write reaches the underlying device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WritePolicy {
    /// Immediately, as well as updating the cache.
    WriteThrough,
    /// Later: on eviction or [`flush`](BlockDevice::flush).
    WriteBack,
}

/// Counters of what the cache has done.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Blocks read from the cache.
    pub hits: u64,
    /// Blocks read from the device.
    pub misses: u64,
    /// Dirty blocks written to the device.
    pub write_backs: u64,
    /// Blocks dropped to make room.
    pub evictions: u64,
}

/// "No slot" in the links.
const NIL: u32 = u32::MAX;
/// Most blocks merged into one write-back request.
const MAX_RUN: usize = 64;

#[derive(Clone, Copy)]
struct Slot {
    lba: u64,
    dirty: bool,
    /// Next slot in the same hash bucket, or on the free list.
    next: u32,
    /// Towards the most recently used.
    newer: u32,
    /// Towards the least recently used.
    older: u32,
}

/// A caching layer over a block device. See the [module](self) docs.
pub struct CachedDevice<D: BlockDevice> {
    dev: D,
    policy: WritePolicy,
    block_size: usize,
    slots: Vec<Slot>,
    /// `slots.len() * block_size` bytes: slot `i` owns bytes `i*bs..(i+1)*bs`.
    data: Vec<u8>,
    /// Bucket heads (power-of-two count), each the first slot of a chain.
    buckets: Vec<u32>,
    free: u32,
    newest: u32,
    oldest: u32,
    /// Scratch for merging write-backs.
    run: Vec<u8>,
    stats: CacheStats,
}

fn reserve<T: Clone>(v: &mut Vec<T>, len: usize, fill: T) -> Result<(), BlockError> {
    v.try_reserve_exact(len).map_err(|_| BlockError::Io)?;
    v.resize(len, fill);
    Ok(())
}

impl<D: BlockDevice> CachedDevice<D> {
    /// Wraps `dev` with a cache of `capacity` blocks. Fails with
    /// [`BlockError::BadBuffer`] for a zero block size or capacity and
    /// [`BlockError::Io`] if the memory cannot be had.
    pub fn new(dev: D, capacity: usize, policy: WritePolicy) -> Result<Self, BlockError> {
        let block_size = dev.block_size();
        let cap = u32::try_from(capacity).ok().filter(|&c| c > 0 && c < NIL).ok_or(BlockError::BadBuffer)?;
        if block_size == 0 {
            return Err(BlockError::BadBuffer);
        }
        let bytes = capacity.checked_mul(block_size).ok_or(BlockError::Io)?;
        let mut data = Vec::new();
        reserve(&mut data, bytes, 0u8)?;
        let mut run = Vec::new();
        reserve(&mut run, block_size.checked_mul(MAX_RUN).ok_or(BlockError::Io)?, 0u8)?;
        let mut slots = Vec::new();
        // Every slot starts on the free list, chained in order.
        let blank = Slot { lba: 0, dirty: false, next: NIL, newer: NIL, older: NIL };
        reserve(&mut slots, capacity, blank)?;
        for (i, s) in slots.iter_mut().enumerate() {
            s.next = if (i as u32 + 1) < cap { i as u32 + 1 } else { NIL };
        }
        let mut buckets = Vec::new();
        reserve(&mut buckets, capacity.next_power_of_two().max(2), NIL)?;
        Ok(CachedDevice {
            dev,
            policy,
            block_size,
            slots,
            data,
            buckets,
            free: 0,
            newest: NIL,
            oldest: NIL,
            run,
            stats: CacheStats::default(),
        })
    }

    /// The write policy.
    pub fn policy(&self) -> WritePolicy {
        self.policy
    }

    /// What the cache has done so far.
    pub fn stats(&self) -> CacheStats {
        self.stats
    }

    /// Blocks currently held.
    pub fn len(&self) -> usize {
        let mut n = 0;
        let mut i = self.newest;
        while let Some(s) = self.slots.get(i as usize) {
            n += 1;
            i = s.older;
        }
        n
    }

    /// Whether no block is held.
    pub fn is_empty(&self) -> bool {
        self.newest == NIL
    }

    /// Blocks held that the device does not have yet.
    pub fn dirty_blocks(&self) -> usize {
        let mut n = 0;
        let mut i = self.newest;
        while let Some(s) = self.slots.get(i as usize) {
            n += usize::from(s.dirty);
            i = s.older;
        }
        n
    }

    /// The underlying device, to look at. Its contents lag the cache under
    /// [`WritePolicy::WriteBack`] until a flush.
    pub fn device(&self) -> &D {
        &self.dev
    }

    /// Writes everything back and returns the device; on failure, the cache
    /// is returned with the error so that nothing is lost.
    #[allow(clippy::result_large_err)] // the cache comes back whole so nothing is lost
    pub fn into_inner(mut self) -> Result<D, (Self, BlockError)> {
        match self.flush() {
            Ok(()) => Ok(self.take_device()),
            Err(e) => Err((self, e)),
        }
    }

    fn take_device(self) -> D {
        let mut this = core::mem::ManuallyDrop::new(self);
        // SAFETY: `this` is never used or dropped again, so reading each
        // field out exactly once moves it; the buffers are dropped here and
        // the device is returned. (`Drop` forbids moving fields normally.)
        unsafe {
            let dev = core::ptr::read(&this.dev);
            core::ptr::drop_in_place(&mut this.slots);
            core::ptr::drop_in_place(&mut this.data);
            core::ptr::drop_in_place(&mut this.buckets);
            core::ptr::drop_in_place(&mut this.run);
            dev
        }
    }

    fn bucket(&self, lba: u64) -> usize {
        // Fibonacci hashing; the bucket count is a power of two.
        let h = lba.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 32;
        (h as usize) & (self.buckets.len() - 1)
    }

    fn find(&self, lba: u64) -> Option<u32> {
        let mut i = *self.buckets.get(self.bucket(lba))?;
        while let Some(s) = self.slots.get(i as usize) {
            if s.lba == lba {
                return Some(i);
            }
            i = s.next;
        }
        None
    }

    fn block(&self, i: u32) -> Option<&[u8]> {
        let at = (i as usize).checked_mul(self.block_size)?;
        self.data.get(at..at.checked_add(self.block_size)?)
    }

    fn block_mut(&mut self, i: u32) -> Option<&mut [u8]> {
        let at = (i as usize).checked_mul(self.block_size)?;
        self.data.get_mut(at..at.checked_add(self.block_size)?)
    }

    fn unlink_lru(&mut self, i: u32) {
        let Some(&Slot { newer, older, .. }) = self.slots.get(i as usize) else { return };
        match self.slots.get_mut(newer as usize) {
            Some(n) => n.older = older,
            None => self.newest = older,
        }
        match self.slots.get_mut(older as usize) {
            Some(o) => o.newer = newer,
            None => self.oldest = newer,
        }
    }

    fn push_newest(&mut self, i: u32) {
        let old_newest = self.newest;
        if let Some(s) = self.slots.get_mut(i as usize) {
            s.newer = NIL;
            s.older = old_newest;
        }
        match self.slots.get_mut(old_newest as usize) {
            Some(n) => n.newer = i,
            None => self.oldest = i,
        }
        self.newest = i;
    }

    fn touch(&mut self, i: u32) {
        if self.newest != i {
            self.unlink_lru(i);
            self.push_newest(i);
        }
    }

    /// Takes slot `i` (cached) out of its hash chain.
    fn unhash(&mut self, i: u32) {
        let Some(&Slot { lba, next, .. }) = self.slots.get(i as usize) else { return };
        let b = self.bucket(lba);
        let head = self.buckets.get(b).copied().unwrap_or(NIL);
        if head == i {
            if let Some(h) = self.buckets.get_mut(b) {
                *h = next;
            }
            return;
        }
        let mut p = head;
        while let Some(s) = self.slots.get_mut(p as usize) {
            if s.next == i {
                s.next = next;
                return;
            }
            p = s.next;
        }
    }

    /// Writes slot `i` to the device if it is dirty.
    fn write_back(&mut self, i: u32) -> Result<(), BlockError> {
        let Some(s) = self.slots.get(i as usize).copied() else { return Ok(()) };
        if !s.dirty {
            return Ok(());
        }
        let at = (i as usize).checked_mul(self.block_size).ok_or(BlockError::Io)?;
        let block = self.data.get(at..at + self.block_size).ok_or(BlockError::Io)?;
        self.dev.write_blocks(s.lba, block)?;
        self.stats.write_backs += 1;
        if let Some(s) = self.slots.get_mut(i as usize) {
            s.dirty = false;
        }
        Ok(())
    }

    /// A slot for `lba`, which must not be cached: a free one, or the least
    /// recently used one after writing it back. The slot is hashed under
    /// `lba` and made the newest; its data is for the caller to fill.
    fn claim(&mut self, lba: u64) -> Result<u32, BlockError> {
        let i = if self.free != NIL {
            let i = self.free;
            self.free = self.slots.get(i as usize).map_or(NIL, |s| s.next);
            i
        } else {
            let i = self.oldest;
            self.write_back(i)?;
            self.unlink_lru(i);
            self.unhash(i);
            self.stats.evictions += 1;
            i
        };
        let b = self.bucket(lba);
        let head = self.buckets.get(b).copied().unwrap_or(NIL);
        if let Some(s) = self.slots.get_mut(i as usize) {
            *s = Slot { lba, dirty: false, next: head, newer: NIL, older: NIL };
        }
        if let Some(h) = self.buckets.get_mut(b) {
            *h = i;
        }
        self.push_newest(i);
        Ok(i)
    }

    /// Caches `lba` with contents `data` (clean).
    fn fill(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
        let i = self.claim(lba)?;
        self.block_mut(i).ok_or(BlockError::Io)?.copy_from_slice(data);
        Ok(())
    }

    /// Writes the slots in `order` (ascending by block), merging adjacent
    /// blocks into requests of up to [`MAX_RUN`].
    fn write_runs(&mut self, order: &[u32]) -> Result<(), BlockError> {
        let bs = self.block_size;
        let mut at = 0;
        while let Some(&first) = order.get(at) {
            let start = self.slots.get(first as usize).map_or(0, |s| s.lba);
            let mut len = 1;
            while len < MAX_RUN {
                let Some(&next) = order.get(at + len) else { break };
                if self.slots.get(next as usize).map(|s| s.lba) != start.checked_add(len as u64) {
                    break;
                }
                len += 1;
            }
            for (j, &i) in order.iter().skip(at).take(len).enumerate() {
                let at = i as usize * bs;
                let src = self.data.get(at..at + bs).ok_or(BlockError::Io)?;
                self.run.get_mut(j * bs..(j + 1) * bs).ok_or(BlockError::Io)?.copy_from_slice(src);
            }
            let out = self.run.get(..len * bs).ok_or(BlockError::Io)?;
            self.dev.write_blocks(start, out)?;
            self.stats.write_backs += len as u64;
            for &i in order.iter().skip(at).take(len) {
                if let Some(s) = self.slots.get_mut(i as usize) {
                    s.dirty = false;
                }
            }
            at += len;
        }
        Ok(())
    }
}

impl<D: BlockDevice> BlockDevice for CachedDevice<D> {
    fn block_size(&self) -> usize {
        self.block_size
    }

    fn num_blocks(&self) -> u64 {
        self.dev.num_blocks()
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let n = self.check_range(lba, buf.len())?;
        let bs = self.block_size;
        let mut k = 0u64;
        while k < n {
            let off = (k as usize) * bs;
            if let Some(i) = self.find(lba + k) {
                self.stats.hits += 1;
                self.touch(i);
                let src = self.block(i).ok_or(BlockError::Io)?;
                buf.get_mut(off..off + bs).ok_or(BlockError::Io)?.copy_from_slice(src);
                k += 1;
                continue;
            }
            // A run of blocks that are all missing goes to the device in one
            // request, straight into the caller's buffer.
            let mut end = k + 1;
            while end < n && self.find(lba + end).is_none() {
                end += 1;
            }
            let span = buf.get_mut(off..(end as usize) * bs).ok_or(BlockError::Io)?;
            self.dev.read_blocks(lba + k, span)?;
            self.stats.misses += end - k;
            // Cache them, unless the run would only push itself out again.
            if ((end - k) as usize) <= self.slots.len() {
                for j in k..end {
                    let at = (j as usize) * bs;
                    let src = buf.get(at..at + bs).ok_or(BlockError::Io)?;
                    self.fill(lba + j, src)?;
                }
            }
            k = end;
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        let n = self.check_range(lba, buf.len())?;
        let bs = self.block_size;
        if self.policy == WritePolicy::WriteThrough {
            self.dev.write_blocks(lba, buf)?;
        }
        for k in 0..n {
            let at = (k as usize) * bs;
            let src = buf.get(at..at + bs).ok_or(BlockError::Io)?;
            let i = match self.find(lba + k) {
                Some(i) => {
                    self.touch(i);
                    i
                }
                // Write-through does not allocate on a write.
                None if self.policy == WritePolicy::WriteThrough => continue,
                None => self.claim(lba + k)?,
            };
            self.block_mut(i).ok_or(BlockError::Io)?.copy_from_slice(src);
            if let (WritePolicy::WriteBack, Some(s)) = (self.policy, self.slots.get_mut(i as usize)) {
                s.dirty = true;
            }
        }
        Ok(())
    }

    /// Writes every dirty block back, then flushes the device.
    fn flush(&mut self) -> Result<(), BlockError> {
        if self.dirty_blocks() > 0 {
            let mut dirty: Vec<u32> = Vec::new();
            if dirty.try_reserve_exact(self.slots.len()).is_ok() {
                let mut i = self.newest;
                while let Some(s) = self.slots.get(i as usize) {
                    if s.dirty {
                        dirty.push(i);
                    }
                    i = s.older;
                }
                dirty.sort_unstable_by_key(|&i| self.slots.get(i as usize).map_or(0, |s| s.lba));
                self.write_runs(&dirty)?;
            } else {
                // No room to sort: one block per request.
                let mut i = self.newest;
                while let Some(s) = self.slots.get(i as usize).copied() {
                    self.write_back(i)?;
                    i = s.older;
                }
            }
        }
        self.dev.flush()
    }
}

impl<D: BlockDevice> Drop for CachedDevice<D> {
    /// Writes dirty blocks back, ignoring errors: call
    /// [`flush`](BlockDevice::flush) or [`into_inner`](Self::into_inner) to
    /// learn of them.
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::rc::Rc;
    use alloc::vec;
    use core::cell::RefCell;

    #[derive(Default)]
    struct Log {
        reads: Vec<(u64, usize)>,
        writes: Vec<(u64, usize)>,
        flushes: usize,
    }

    struct Disk {
        bytes: Vec<u8>,
        log: Rc<RefCell<Log>>,
    }

    const BS: usize = 16;

    impl Disk {
        fn new(blocks: usize) -> (Self, Rc<RefCell<Log>>) {
            let log = Rc::new(RefCell::new(Log::default()));
            let bytes = (0..blocks * BS).map(|i| (i / BS) as u8).collect();
            (Disk { bytes, log: log.clone() }, log)
        }
    }

    impl BlockDevice for Disk {
        fn block_size(&self) -> usize {
            BS
        }
        fn num_blocks(&self) -> u64 {
            (self.bytes.len() / BS) as u64
        }
        fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            self.check_range(lba, buf.len())?;
            self.log.borrow_mut().reads.push((lba, buf.len() / BS));
            buf.copy_from_slice(&self.bytes[lba as usize * BS..][..buf.len()]);
            Ok(())
        }
        fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
            self.check_range(lba, buf.len())?;
            self.log.borrow_mut().writes.push((lba, buf.len() / BS));
            self.bytes[lba as usize * BS..][..buf.len()].copy_from_slice(buf);
            Ok(())
        }
        fn flush(&mut self) -> Result<(), BlockError> {
            self.log.borrow_mut().flushes += 1;
            Ok(())
        }
    }

    fn read(c: &mut impl BlockDevice, lba: u64, n: usize) -> Vec<u8> {
        let mut v = vec![0; n * BS];
        c.read_blocks(lba, &mut v).unwrap();
        v
    }

    #[test]
    fn rejects_bad_parameters() {
        let (d, _) = Disk::new(4);
        assert!(CachedDevice::new(d, 0, WritePolicy::WriteBack).is_err());
    }

    #[test]
    fn reads_hit_after_the_first() {
        let (d, log) = Disk::new(8);
        let mut c = CachedDevice::new(d, 4, WritePolicy::WriteThrough).unwrap();
        assert_eq!(read(&mut c, 2, 2), [vec![2; BS], vec![3; BS]].concat());
        assert_eq!(read(&mut c, 2, 2), [vec![2; BS], vec![3; BS]].concat());
        assert_eq!(log.borrow().reads, [(2, 2)]);
        assert_eq!(c.stats().hits, 2);
        assert_eq!(c.stats().misses, 2);
        // A partly cached range reads only the missing run.
        read(&mut c, 3, 3);
        assert_eq!(log.borrow().reads, [(2, 2), (4, 2)]);
    }

    #[test]
    fn evicts_least_recently_used() {
        let (d, log) = Disk::new(8);
        let mut c = CachedDevice::new(d, 2, WritePolicy::WriteThrough).unwrap();
        read(&mut c, 0, 1);
        read(&mut c, 1, 1);
        read(&mut c, 0, 1); // 1 is now the oldest
        read(&mut c, 2, 1); // evicts 1
        read(&mut c, 0, 1);
        assert_eq!(log.borrow().reads, [(0, 1), (1, 1), (2, 1)]);
        read(&mut c, 1, 1);
        assert_eq!(log.borrow().reads.len(), 4);
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn write_through_hits_the_device_and_keeps_the_cache_current() {
        let (d, log) = Disk::new(4);
        let mut c = CachedDevice::new(d, 4, WritePolicy::WriteThrough).unwrap();
        read(&mut c, 1, 1);
        c.write_blocks(1, &[9; BS]).unwrap();
        assert_eq!(log.borrow().writes, [(1, 1)]);
        assert_eq!(read(&mut c, 1, 1), vec![9; BS]);
        assert_eq!(log.borrow().reads.len(), 1);
        assert_eq!(c.dirty_blocks(), 0);
    }

    #[test]
    fn write_back_defers_and_merges() {
        let (d, log) = Disk::new(16);
        let mut c = CachedDevice::new(d, 8, WritePolicy::WriteBack).unwrap();
        c.write_blocks(5, &[5; BS]).unwrap();
        c.write_blocks(3, &[3; BS]).unwrap();
        c.write_blocks(4, &[4; BS]).unwrap();
        c.write_blocks(9, &[9; BS]).unwrap();
        assert!(log.borrow().writes.is_empty());
        assert_eq!(c.dirty_blocks(), 4);
        // Reads see the unflushed data without touching the device.
        assert_eq!(read(&mut c, 4, 1), vec![4; BS]);
        assert!(log.borrow().reads.is_empty());
        c.flush().unwrap();
        assert_eq!(log.borrow().writes, [(3, 3), (9, 1)]);
        assert_eq!(log.borrow().flushes, 1);
        assert_eq!(c.dirty_blocks(), 0);
        c.flush().unwrap();
        assert_eq!(log.borrow().writes.len(), 2);
    }

    #[test]
    fn write_back_evicts_dirty_blocks_to_the_device() {
        let (d, log) = Disk::new(8);
        let mut c = CachedDevice::new(d, 2, WritePolicy::WriteBack).unwrap();
        c.write_blocks(0, &[7; BS]).unwrap();
        c.write_blocks(1, &[8; BS]).unwrap();
        c.write_blocks(2, &[9; BS]).unwrap(); // evicts block 0
        assert_eq!(log.borrow().writes, [(0, 1)]);
        assert_eq!(read(&mut c, 0, 1), vec![7; BS]);
        let d = c.into_inner().ok().unwrap();
        // Everything reached the disk by the time the device came back.
        assert_eq!(&d.bytes[..BS], &[7; BS]);
        assert_eq!(&d.bytes[BS..2 * BS], &[8; BS]);
        assert_eq!(&d.bytes[2 * BS..3 * BS], &[9; BS]);
    }

    #[test]
    fn drop_writes_back() {
        let (d, log) = Disk::new(4);
        let c = {
            let mut c = CachedDevice::new(d, 4, WritePolicy::WriteBack).unwrap();
            c.write_blocks(2, &[1; BS]).unwrap();
            c
        };
        drop(c);
        assert_eq!(log.borrow().writes, [(2, 1)]);
    }

    #[test]
    fn range_errors_pass_through() {
        let (d, _) = Disk::new(4);
        let mut c = CachedDevice::new(d, 4, WritePolicy::WriteBack).unwrap();
        assert_eq!(c.read_blocks(4, &mut [0; BS]), Err(BlockError::OutOfRange));
        assert_eq!(c.write_blocks(0, &[0; 5]), Err(BlockError::BadBuffer));
    }

    #[test]
    fn behaves_like_the_bare_disk() {
        for policy in [WritePolicy::WriteThrough, WritePolicy::WriteBack] {
            let (d, _) = Disk::new(32);
            let mut model = d.bytes.clone();
            let mut c = CachedDevice::new(d, 5, policy).unwrap();
            let mut x = 12345u64;
            let mut next = move || {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                x >> 33
            };
            for step in 0..2000u64 {
                let lba = next() % 32;
                let n = (next() % 4).min(32 - lba - 1) + 1;
                let len = n as usize * BS;
                match next() % 4 {
                    0 | 1 => {
                        let want = &model[lba as usize * BS..][..len];
                        assert_eq!(read(&mut c, lba, n as usize), want, "step {step}");
                    }
                    2 => {
                        let data: Vec<u8> = (0..len).map(|i| (step as usize + i) as u8).collect();
                        c.write_blocks(lba, &data).unwrap();
                        model[lba as usize * BS..][..len].copy_from_slice(&data);
                    }
                    _ => c.flush().unwrap(),
                }
            }
            let d = c.into_inner().ok().unwrap();
            assert_eq!(d.bytes, model);
        }
    }

    #[test]
    fn long_reads_bypass_a_small_cache() {
        let (d, log) = Disk::new(16);
        let mut c = CachedDevice::new(d, 2, WritePolicy::WriteThrough).unwrap();
        let v = read(&mut c, 0, 8);
        assert_eq!(v.len(), 8 * BS);
        assert_eq!(log.borrow().reads, [(0, 8)]);
        assert!(c.is_empty());
    }
}
