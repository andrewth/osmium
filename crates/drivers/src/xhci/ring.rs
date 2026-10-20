//! Command, transfer and event rings (xHCI 1.2 §4.9).
//!
//! Each ring is one page-sized segment of [`RING_TRBS`] TRBs. Producer rings
//! end in a Link TRB back to their start that toggles the cycle state, so
//! the controller sees which entries are new by their cycle bit. The event
//! ring is described to the controller by a one-entry segment table.

use osmium_arch::barrier;
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_mm::PhysAddr;

use super::trb::{Trb, flag};

/// TRBs per ring segment (one 4 KiB page).
pub const RING_TRBS: usize = 256;
const TRB_SIZE: usize = 16;

fn load(mem: &OwnedDma<'_, impl DmaAllocator + ?Sized>, i: usize) -> Trb {
    let off = i * TRB_SIZE;
    let control = u32::from_le(mem.load(off + 12));
    // The rest of the TRB only after its cycle bit says it is complete.
    barrier::dma_rmb();
    Trb { param: u64::from_le(mem.load(off)), status: u32::from_le(mem.load(off + 8)), control }
}

fn store(mem: &OwnedDma<'_, impl DmaAllocator + ?Sized>, i: usize, trb: Trb) {
    let off = i * TRB_SIZE;
    mem.store(off, trb.param.to_le());
    mem.store(off + 8, trb.status.to_le());
    // The control word carries the cycle bit that hands the TRB to the
    // controller, so it must land last.
    barrier::dma_wmb();
    mem.store(off + 12, trb.control.to_le());
}

/// A ring the driver produces into: the command ring or an endpoint's
/// transfer ring.
pub struct ProducerRing<'d, D: DmaAllocator + ?Sized> {
    mem: OwnedDma<'d, D>,
    enqueue: usize,
    cycle: bool,
}

impl<'d, D: DmaAllocator + ?Sized> ProducerRing<'d, D> {
    /// Allocates an empty ring.
    pub fn new(dma: &'d D) -> Option<Self> {
        let mem = OwnedDma::new(dma, RING_TRBS * TRB_SIZE)?;
        let ring = Self { mem, enqueue: 0, cycle: true };
        // The link's cycle bit is set on each pass, like any other TRB.
        store(&ring.mem, RING_TRBS - 1, Trb::link(ring.base().as_u64()));
        Some(ring)
    }

    /// Address of the first TRB, for `CRCR` or an endpoint context's
    /// dequeue pointer (with [`cycle`](Self::cycle) as its DCS bit).
    pub fn base(&self) -> PhysAddr {
        self.mem.device_addr()
    }

    /// The producer cycle state: the cycle bit the next TRB will carry.
    pub fn cycle(&self) -> bool {
        self.cycle
    }

    /// Address the next TRB will be written to.
    pub fn enqueue_addr(&self) -> PhysAddr {
        self.base() + (self.enqueue * TRB_SIZE) as u64
    }

    /// Writes `trb` (its cycle bit replaced) and returns its address. The
    /// caller rings the doorbell. The ring does not track the controller's
    /// dequeue pointer: callers wait for each request to complete before the
    /// ring could wrap onto it.
    pub fn push(&mut self, trb: Trb) -> PhysAddr {
        let addr = self.enqueue_addr();
        let control = (trb.control & !flag::CYCLE) | self.cycle as u32;
        store(&self.mem, self.enqueue, Trb { control, ..trb });
        self.enqueue += 1;
        if self.enqueue == RING_TRBS - 1 {
            let link = Trb::link(self.base().as_u64());
            store(&self.mem, self.enqueue, Trb { control: link.control | self.cycle as u32, ..link });
            self.enqueue = 0;
            self.cycle = !self.cycle;
        }
        addr
    }

    /// Turns the TRB at `addr`, which the controller has not run, into a No
    /// Op Command with the same cycle bit. Only the control word changes, so
    /// a controller fetching it meanwhile sees either the old TRB or the No
    /// Op. Does nothing if `addr` is not in this ring.
    pub fn cancel(&mut self, addr: PhysAddr) {
        let off = addr.as_u64().wrapping_sub(self.base().as_u64());
        if !off.is_multiple_of(TRB_SIZE as u64) || off >= ((RING_TRBS - 1) * TRB_SIZE) as u64 {
            return;
        }
        let i = off as usize / TRB_SIZE;
        let cycle = load(&self.mem, i).control & flag::CYCLE;
        self.mem.store(i * TRB_SIZE + 12, (Trb::no_op_command().control | cycle).to_le());
    }

    /// The TRB at index `i`, for tests.
    #[cfg(test)]
    pub(crate) fn get(&self, i: usize) -> Trb {
        load(&self.mem, i)
    }
}

/// The ring the controller produces events into, with its one-entry
/// Event Ring Segment Table.
pub struct EventRing<'d, D: DmaAllocator + ?Sized> {
    mem: OwnedDma<'d, D>,
    erst: OwnedDma<'d, D>,
    dequeue: usize,
    cycle: bool,
}

impl<'d, D: DmaAllocator + ?Sized> EventRing<'d, D> {
    /// Allocates an empty event ring and its segment table.
    pub fn new(dma: &'d D) -> Option<Self> {
        let mem = OwnedDma::new(dma, RING_TRBS * TRB_SIZE)?;
        let erst = OwnedDma::new(dma, 64)?;
        erst.store(0, mem.device_addr().as_u64().to_le());
        erst.store(8, (RING_TRBS as u32).to_le());
        Some(Self { mem, erst, dequeue: 0, cycle: true })
    }

    /// Address of the segment table, for `ERSTBA`.
    pub fn table(&self) -> PhysAddr {
        self.erst.device_addr()
    }

    /// Address of the next event, for `ERDP`.
    pub fn dequeue_addr(&self) -> PhysAddr {
        self.mem.device_addr() + (self.dequeue * TRB_SIZE) as u64
    }

    /// Writes `trb` at index `i` with the producer's current cycle bit,
    /// as the controller would, for tests.
    #[cfg(test)]
    pub(crate) fn controller_write(&mut self, i: usize, mut trb: Trb) {
        trb.control = trb.control & !flag::CYCLE | self.cycle as u32;
        store(&self.mem, i, trb);
    }

    /// Takes the next event, if the controller has written one. Tell the
    /// controller how far the ring was consumed by writing
    /// [`dequeue_addr`](Self::dequeue_addr) to `ERDP` afterwards.
    pub fn pop(&mut self) -> Option<Trb> {
        let trb = load(&self.mem, self.dequeue);
        if trb.cycle() != self.cycle {
            return None;
        }
        self.dequeue += 1;
        if self.dequeue == RING_TRBS {
            self.dequeue = 0;
            self.cycle = !self.cycle;
        }
        Some(trb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::testing::HostDma;

    fn raw(mem: &OwnedDma<'_, HostDma>, i: usize) -> Trb {
        let off = i * TRB_SIZE;
        Trb { param: mem.load(off), status: mem.load(off + 8), control: mem.load(off + 12) }
    }

    #[test]
    fn producer_wraps_through_link() {
        let dma = HostDma::default();
        let mut ring = ProducerRing::new(&dma).unwrap();
        let base = ring.base().as_u64();
        assert_eq!(ring.push(Trb::no_op_command()), ring.base());
        assert_eq!(raw(&ring.mem, 0).control & flag::CYCLE, 1);

        for _ in 1..RING_TRBS - 1 {
            ring.push(Trb::no_op_command());
        }
        // The link was handed over with the old cycle bit and the state flipped.
        let link = raw(&ring.mem, RING_TRBS - 1);
        assert_eq!((link.param, link.control & flag::CYCLE), (base, 1));
        assert!(!ring.cycle());
        assert_eq!(ring.push(Trb::no_op_command()).as_u64(), base);
        assert_eq!(raw(&ring.mem, 0).control & flag::CYCLE, 0);
    }

    #[test]
    fn event_ring_follows_cycle_bit() {
        let dma = HostDma::default();
        let mut ev = EventRing::new(&dma).unwrap();
        assert_eq!(ev.erst.load::<u64>(0), ev.mem.device_addr().as_u64());
        assert_eq!(ev.erst.load::<u32>(8), RING_TRBS as u32);
        assert_eq!(ev.pop(), None);

        // The controller writes a full lap with cycle 1, then one with cycle 0.
        for lap in [1u32, 0] {
            for i in 0..RING_TRBS {
                store(&ev.mem, i, Trb { param: i as u64, status: 0, control: (33 << 10) | lap });
            }
            for i in 0..RING_TRBS {
                assert_eq!(ev.pop().map(|t| t.param), Some(i as u64));
            }
            assert_eq!(ev.pop(), None, "stale entries from the previous lap are ignored");
        }
        assert_eq!(ev.dequeue_addr(), ev.mem.device_addr());
    }
}
