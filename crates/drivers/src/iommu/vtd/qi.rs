//! Queued invalidation: a ring of descriptors the unit executes in order,
//! each submission followed by an invalidation-wait descriptor that writes a
//! status word so the driver knows the earlier ones are done.

use core::sync::atomic::Ordering;

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::iommu::IommuError;

use super::{CAP_DRD, CAP_DWD, ECAP_QI, ECAP_SMTS, FSTS, FSTS_QI_ERRORS, IQA, IQH, IQT, QIE, State, Vtd};

/// Bytes of the ring (one page, the smallest size: `IQA.QS` = 0).
const RING_LEN: usize = 4096;
/// Offset of the status word the wait descriptor writes, after the ring.
const STATUS: usize = RING_LEN;
/// `IQA.DW`: 256-bit descriptors.
const IQA_DW: u64 = 1 << 11;

// Descriptor types (bits 3:0 of the low quadword).
/// Context-cache invalidate.
const TYPE_CONTEXT: u64 = 1;
/// IOTLB invalidate.
const TYPE_IOTLB: u64 = 2;
/// Interrupt-entry-cache invalidate.
const TYPE_IEC: u64 = 4;
/// Invalidation wait.
const TYPE_WAIT: u64 = 5;
/// PASID-cache invalidate.
const TYPE_PASID: u64 = 7;
/// Wait descriptor: write the status data (bits 63:32) to the address in the high quadword.
const WAIT_SW: u64 = 1 << 5;

/// Granularity of the context-cache and IOTLB descriptors (bits 5:4): global.
pub(super) const GRAN_GLOBAL: u64 = 1;
/// Domain-selective.
pub(super) const GRAN_DOMAIN: u64 = 2;
/// Device-selective (context cache only).
pub(super) const GRAN_DEVICE: u64 = 3;

/// The invalidation queue and its completion word.
pub(super) struct Queue<'d, D: DmaAllocator + ?Sized> {
    /// The ring at 0 and the status word at [`STATUS`].
    mem: OwnedDma<'d, D>,
    /// 32-byte descriptors rather than 16.
    wide: bool,
    /// Index of the next free slot.
    tail: usize,
    /// Status data of the last submission.
    seq: u32,
}

impl<D: DmaAllocator + ?Sized> Queue<'_, D> {
    fn desc_len(&self) -> usize {
        if self.wide { 32 } else { 16 }
    }

    fn slots(&self) -> usize {
        RING_LEN / self.desc_len()
    }
}

impl<'d, D: DmaAllocator + Sync + ?Sized> Vtd<'d, D> {
    /// Whether invalidations go through the queue.
    pub(super) fn qi_active(&self) -> bool {
        self.qi_on.load(Ordering::Acquire)
    }

    /// Switches the unit to queued invalidation. Does nothing if it is on.
    pub(super) fn enable_qi(&self, st: &mut State<'d, D>) -> Result<(), IommuError> {
        if self.qi_active() {
            return Ok(());
        }
        if self.ecap & ECAP_QI == 0 {
            return Err(IommuError::Unsupported);
        }
        let mem = OwnedDma::new(self.dma, RING_LEN + 4096).ok_or(IommuError::OutOfMemory)?;
        // Scalable-mode units want 256-bit descriptors, as Linux uses them.
        let wide = self.ecap & ECAP_SMTS != 0;
        let base = mem.device_addr().as_u64();
        *self.qi.lock() = Some(Queue { mem, wide, tail: 0, seq: 0 });
        self.regs.w64(IQT, 0);
        self.regs.w64(IQA, base | if wide { IQA_DW } else { 0 });
        barrier::mb();
        if let Err(e) = self.set_enabled(st, QIE, true) {
            // The unit may still read the ring: keep it.
            core::mem::forget(self.qi.lock().take());
            return Err(e);
        }
        self.qi_on.store(true, Ordering::Release);
        Ok(())
    }

    /// Switches queued invalidation off and frees the queue (or leaks it if
    /// the unit does not stop).
    pub(super) fn disable_qi(&self, st: &mut State<'d, D>) -> Result<(), IommuError> {
        self.qi_on.store(false, Ordering::Release);
        let queue = self.qi.lock().take();
        match self.set_enabled(st, QIE, false) {
            Ok(()) => Ok(()),
            Err(e) => {
                core::mem::forget(queue);
                Err(e)
            }
        }
    }

    /// Runs `desc` and waits for it to complete.
    pub(super) fn qi_submit(&self, desc: [u64; 2]) -> Result<(), IommuError> {
        let mut guard = self.qi.lock();
        let q = guard.as_mut().ok_or(IommuError::Unsupported)?;
        q.seq = q.seq.wrapping_add(1).max(1);
        let (len, slots) = (q.desc_len(), q.slots());
        let wait = [TYPE_WAIT | WAIT_SW | (q.seq as u64) << 32, q.mem.device_addr().as_u64() + STATUS as u64];
        q.mem.store::<u32>(STATUS, 0);
        // Slots are used in pairs and the ring holds an even number of them.
        for (i, d) in [desc, wait].into_iter().enumerate() {
            let at = (q.tail + i) % slots * len;
            q.mem.store::<u64>(at, d[0]);
            q.mem.store::<u64>(at + 8, d[1]);
            if q.wide {
                q.mem.store::<u64>(at + 16, 0);
                q.mem.store::<u64>(at + 24, 0);
            }
        }
        q.tail = (q.tail + 2) % slots;
        barrier::dma_wmb();
        // The tail register holds the byte offset of the next free slot.
        self.regs.w64(IQT, (q.tail * len) as u64);
        let seq = q.seq;
        let result = self.wait(|| {
            self.regs.r32(FSTS) & FSTS_QI_ERRORS != 0 || {
                barrier::dma_rmb();
                q.mem.load::<u32>(STATUS) == seq
            }
        });
        if self.regs.r32(FSTS) & FSTS_QI_ERRORS != 0 {
            // The unit stopped at the bad descriptor: acknowledge, and resume
            // submitting from where it stands.
            self.regs.w32(FSTS, FSTS_QI_ERRORS);
            q.tail = (self.regs.r64(IQH) as usize / len) % slots;
            return Err(IommuError::Hardware);
        }
        result
    }

    /// Context-cache invalidation: global, or of the requester `sid` in `domain`.
    pub(super) fn qi_context(&self, gran: u64, domain: u16, sid: u16) -> Result<(), IommuError> {
        self.qi_submit([TYPE_CONTEXT | gran << 4 | (domain as u64) << 16 | (sid as u64) << 32, 0])
    }

    /// IOTLB invalidation, global or of `domain`, draining reads and writes where the unit asks.
    pub(super) fn qi_iotlb(&self, gran: u64, domain: u16) -> Result<(), IommuError> {
        let drain = (self.cap & CAP_DRD != 0) as u64 | ((self.cap & CAP_DWD != 0) as u64) << 1;
        self.qi_submit([TYPE_IOTLB | gran << 4 | drain << 6 | (domain as u64) << 16, 0])
    }

    /// PASID-cache invalidation: everything (`pasid` is `None`) or one PASID of `domain`.
    pub(super) fn qi_pasid_cache(&self, domain: u16, pasid: Option<u32>) -> Result<(), IommuError> {
        let (gran, pasid) = match pasid {
            Some(p) => (1, p as u64 & 0xf_ffff),
            None => (3, 0),
        };
        self.qi_submit([TYPE_PASID | gran << 4 | (domain as u64) << 16 | pasid << 32, 0])
    }

    /// Interrupt-entry-cache invalidation: all entries (`index` is `None`) or one.
    pub(super) fn qi_iec(&self, index: Option<u16>) -> Result<(), IommuError> {
        match index {
            Some(i) => self.qi_submit([TYPE_IEC | 1 << 4 | (i as u64) << 32, 0]),
            None => self.qi_submit([TYPE_IEC, 0]),
        }
    }
}
