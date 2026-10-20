//! A submission/completion queue pair.
//!
//! The driver writes 64-byte commands at the submission queue's tail; the
//! controller writes 16-byte completions at the completion queue's tail and
//! flips their phase tag each time it wraps, so an entry is new when its
//! phase tag matches the one the driver expects (starting at 1 over zeroed
//! memory). The caller rings the doorbells: [`Queue::push`] and
//! [`Queue::pop`] only move the indices.

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, OwnedDma};

use super::{NvmeError, PAGE, alloc};

/// Bytes per submission queue entry (CC.IOSQES = 6).
pub const SQE_LEN: usize = 64;
/// Bytes per completion queue entry (CC.IOCQES = 4).
pub const CQE_LEN: usize = 16;

/// Status code (bits 7:0) and status code type (bits 10:8) of the status
/// field.
const STATUS_MASK: u32 = 0x7ff;

/// A command, as the sixteen dwords of a submission queue entry.
pub type Sqe = [u32; 16];

/// What the controller reported for one command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    /// Dword 0, command-specific.
    pub result: u32,
    /// The submission queue the command came from.
    pub sqid: u16,
    /// The command identifier the driver chose.
    pub cid: u16,
    /// Status code type and status code (dword 3 bits 27:17): 0 for
    /// success, else the type in bits 10:8 and the code in bits 7:0. The
    /// CRD, More and Do Not Retry bits above them are left out.
    pub status: u16,
}

/// A queue pair of `depth` entries each, in page-aligned DMA memory.
pub struct Queue<'d, D: DmaAllocator + ?Sized> {
    sq: OwnedDma<'d, D>,
    cq: OwnedDma<'d, D>,
    qid: u16,
    depth: u16,
    tail: u16,
    head: u16,
    phase: bool,
}

impl<'d, D: DmaAllocator + ?Sized> Queue<'d, D> {
    /// Allocates queue pair `qid` with `depth` (at least 2) entries.
    pub fn new(dma: &'d D, qid: u16, depth: u16) -> Result<Self, NvmeError> {
        debug_assert!(depth >= 2 && depth as usize * SQE_LEN <= PAGE);
        Ok(Self {
            sq: alloc(dma, depth as usize * SQE_LEN)?,
            cq: alloc(dma, depth as usize * CQE_LEN)?,
            qid,
            depth,
            tail: 0,
            head: 0,
            phase: true,
        })
    }

    /// The queue identifier.
    pub fn qid(&self) -> u16 {
        self.qid
    }

    /// Entries in each queue.
    pub fn depth(&self) -> u16 {
        self.depth
    }

    /// Device addresses of the submission and completion queues.
    pub fn addrs(&self) -> (u64, u64) {
        (self.sq.device_addr().as_u64(), self.cq.device_addr().as_u64())
    }

    /// Writes `sqe` at the tail and returns the new tail, for the doorbell.
    /// The caller keeps no more than `depth - 1` commands outstanding.
    pub fn push(&mut self, sqe: &Sqe) -> u16 {
        let off = self.tail as usize * SQE_LEN;
        for (i, dw) in sqe.iter().enumerate() {
            self.sq.store(off + 4 * i, dw.to_le());
        }
        self.tail = (self.tail + 1) % self.depth;
        self.tail
    }

    /// Takes the completion at the head, if the controller has posted one;
    /// the caller then writes [`head`](Self::head) to the doorbell.
    pub fn pop(&mut self) -> Option<Completion> {
        let off = self.head as usize * CQE_LEN;
        let dw3 = u32::from_le(self.cq.load(off + 12));
        if (dw3 >> 16 & 1 != 0) != self.phase {
            return None;
        }
        // The phase tag is written last; read the rest after it.
        barrier::dma_rmb();
        let dw3 = u32::from_le(self.cq.load(off + 12));
        let dw2 = u32::from_le(self.cq.load::<u32>(off + 8));
        let result = u32::from_le(self.cq.load(off));
        self.head += 1;
        if self.head == self.depth {
            self.head = 0;
            self.phase = !self.phase;
        }
        let status = (dw3 >> 17 & STATUS_MASK) as u16;
        Some(Completion { result, sqid: (dw2 >> 16) as u16, cid: dw3 as u16, status })
    }

    /// The completion queue head, for the doorbell.
    pub fn head(&self) -> u16 {
        self.head
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::testing::HostDma;

    /// Posts a completion the way a controller does.
    fn post(q: &Queue<'_, HostDma>, slot: u16, cid: u16, phase: bool, status: u16) {
        let off = slot as usize * CQE_LEN;
        q.cq.store(off, 0xabcd_u32);
        q.cq.store(off + 8, (q.qid as u32) << 16);
        q.cq.store(off + 12, cid as u32 | (phase as u32) << 16 | (status as u32) << 17);
    }

    #[test]
    fn phase_tags_flip_on_wrap() {
        let dma = HostDma::default();
        let mut q = Queue::new(&dma, 1, 3).unwrap();
        assert_eq!(q.pop(), None, "zeroed memory holds nothing new");
        for (round, phase) in [(0, true), (1, false), (2, true)] {
            for slot in 0..3u16 {
                let cid = round * 3 + slot;
                assert_eq!(q.push(&[0; 16]), (slot + 1) % 3);
                assert_eq!(q.pop(), None, "an old entry is not new");
                post(&q, slot, cid, phase, 0x0281 * (slot == 1) as u16);
                let c = q.pop().unwrap();
                assert_eq!((c.cid, c.sqid, c.result), (cid, 1, 0xabcd));
                assert_eq!(c.status, if slot == 1 { 0x0281 } else { 0 });
                assert_eq!(q.head(), (slot + 1) % 3);
            }
        }
        drop(q);
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn status_leaves_out_more_and_do_not_retry() {
        let dma = HostDma::default();
        let mut q = Queue::new(&dma, 1, 4).unwrap();
        // CRD (bits 12:11), More (13) and DNR (14) of the status field.
        for (slot, status, expected) in [(0, 1 << 13, 0), (1, 0x6000 | 0x0281, 0x0281), (2, 0x1800 | 0x0101, 0x0101)] {
            q.push(&[0; 16]);
            post(&q, slot, slot, true, status);
            assert_eq!(q.pop().unwrap().status, expected);
        }
    }
}
