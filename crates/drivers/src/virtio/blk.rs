//! virtio-blk.
//!
//! Every request is three descriptors: a 16-byte header (type, sector) the
//! device reads, the data the device reads or writes, and a status byte the
//! device writes. Data is bounced through a DMA buffer of [`DATA_LEN`] bytes
//! (larger transfers are split) and requests are synchronous: one is in
//! flight at a time and the driver polls the used ring until it completes.

use osmium_hal::block::{BlockDevice, BlockError};
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::virtio::blk;

use super::queue::{Segment, VirtQueue};
use core::mem::ManuallyDrop;

use super::{DeviceType, POLL_LIMIT, Transport, VirtioError, driver_ok, negotiate, reset};

/// Bytes of DMA bounce buffer, and so the most one request transfers.
pub const DATA_LEN: usize = 64 * 1024;

/// Entries used in the request queue, at most (a request needs three).
pub const MAX_QUEUE_SIZE: u16 = 8;

const STATUS_OFFSET: usize = blk::HEADER_LEN;

/// A virtio block device. Dropping it resets the device and frees its memory.
pub struct VirtioBlk<'d, T: Transport, D: DmaAllocator + ?Sized> {
    transport: T,
    // Freed in `drop` only once the device has acknowledged its reset.
    queue: ManuallyDrop<VirtQueue<'d, D>>,
    /// Request header and status byte.
    req: ManuallyDrop<OwnedDma<'d, D>>,
    data: ManuallyDrop<OwnedDma<'d, D>>,
    sectors: u64,
    read_only: bool,
    has_flush: bool,
}

impl<'d, T: Transport, D: DmaAllocator + ?Sized> VirtioBlk<'d, T, D> {
    /// Initializes the device behind `transport`, allocating its queue and
    /// buffers from `dma`.
    pub fn new(transport: T, dma: &'d D) -> Result<Self, VirtioError> {
        if transport.device_type() != DeviceType::Block {
            return Err(VirtioError::WrongDevice);
        }
        let features = negotiate(&transport, 0, blk::F_RO | blk::F_FLUSH)?;
        let size = match transport.max_queue_size(blk::REQUEST_QUEUE).min(MAX_QUEUE_SIZE) {
            // Split queues come in powers of two; a request needs three.
            n if n >= 4 => 1 << n.ilog2(),
            _ => return Err(VirtioError::BadQueue),
        };
        let sectors = u64::from_le_bytes(core::array::from_fn(|i| transport.config_read8(blk::CONFIG_CAPACITY + i)));
        // Plain values until all succeed, so a failure frees the others.
        let queue = VirtQueue::new(dma, blk::REQUEST_QUEUE, size)?;
        let req = OwnedDma::new(dma, 64).ok_or(VirtioError::NoMemory)?;
        let data = OwnedDma::new(dma, DATA_LEN).ok_or(VirtioError::NoMemory)?;
        let blk = Self {
            queue: ManuallyDrop::new(queue),
            req: ManuallyDrop::new(req),
            data: ManuallyDrop::new(data),
            sectors,
            read_only: features & blk::F_RO != 0,
            has_flush: features & blk::F_FLUSH != 0,
            transport,
        };
        blk.transport.setup_queue(blk::REQUEST_QUEUE, size, blk.queue.addrs());
        // Completions are polled.
        blk.queue.set_interrupts(false);
        driver_ok(&blk.transport);
        Ok(blk)
    }

    /// The transport, e.g. for [`Transport::ack_interrupt`].
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// True if the device refuses writes.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Runs one request of type `ty` at `sector` over the first `len` bytes
    /// of the bounce buffer, waiting for the device to finish it. The
    /// caller has filled the buffer for writes and reads it after reads.
    fn request(&mut self, ty: u32, sector: u64, len: usize) -> Result<(), BlockError> {
        let mut header = [0u8; blk::HEADER_LEN];
        header[..4].copy_from_slice(&ty.to_le_bytes());
        header[8..].copy_from_slice(&sector.to_le_bytes());
        self.req.write(0, &header);
        // Anything but a status the device wrote reads as an error.
        self.req.write(STATUS_OFFSET, &[0xff]);

        let seg = |buf: &ManuallyDrop<OwnedDma<'d, D>>, offset: usize, len: usize, device_writes: bool| Segment {
            addr: buf.device_addr() + offset as u64,
            len: len as u32,
            device_writes,
        };
        let header_seg = seg(&self.req, 0, blk::HEADER_LEN, false);
        let status_seg = seg(&self.req, STATUS_OFFSET, 1, true);
        let segments = [header_seg, seg(&self.data, 0, len, ty == blk::T_IN), status_seg];
        // Requests without data skip the middle descriptor.
        let chain = if len == 0 { &[header_seg, status_seg][..] } else { &segments[..] };
        let head = self.queue.add(chain).map_err(|_| BlockError::Io)?;
        if self.queue.needs_notify() {
            self.transport.notify(blk::REQUEST_QUEUE);
        }
        // Nothing else is in flight, so the first completion is ours. A
        // device that never answers (or breaks the queue) fails the request;
        // the queue then stays unusable.
        match self.queue.wait_used(POLL_LIMIT) {
            Some((done, _)) if done == head => {}
            _ => return Err(BlockError::Io),
        }

        let mut status = [0xff];
        self.req.read(STATUS_OFFSET, &mut status);
        match status[0] {
            blk::S_OK => Ok(()),
            _ => Err(BlockError::Io),
        }
    }
}

impl<T: Transport, D: DmaAllocator + ?Sized> BlockDevice for VirtioBlk<'_, T, D> {
    fn block_size(&self) -> usize {
        blk::SECTOR_SIZE
    }

    fn num_blocks(&self) -> u64 {
        self.sectors
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        for (i, chunk) in buf.chunks_mut(DATA_LEN).enumerate() {
            let sector = lba + (i * DATA_LEN / blk::SECTOR_SIZE) as u64;
            self.request(blk::T_IN, sector, chunk.len())?;
            self.data.read(0, chunk);
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        for (i, chunk) in buf.chunks(DATA_LEN).enumerate() {
            let sector = lba + (i * DATA_LEN / blk::SECTOR_SIZE) as u64;
            self.data.write(0, chunk);
            self.request(blk::T_OUT, sector, chunk.len())?;
        }
        Ok(())
    }

    /// Flushes the device's write cache; a no-op for devices that do not
    /// offer one (they write through).
    fn flush(&mut self) -> Result<(), BlockError> {
        if self.read_only || !self.has_flush {
            return Ok(());
        }
        self.request(blk::T_FLUSH, 0, 0)
    }
}

impl<T: Transport, D: DmaAllocator + ?Sized> Drop for VirtioBlk<'_, T, D> {
    fn drop(&mut self) {
        // Stop the device before freeing memory it may still be writing; if
        // it never stops, leak the memory instead.
        if reset(&self.transport) {
            // SAFETY: dropped once, here; the device is reset.
            unsafe {
                ManuallyDrop::drop(&mut self.queue);
                ManuallyDrop::drop(&mut self.req);
                ManuallyDrop::drop(&mut self.data);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::queue::tests::DeviceSide;
    use crate::virtio::testing::{FakeTransport, HostDma};
    use crate::virtio::{feature, status};
    use core::sync::atomic::{AtomicBool, Ordering};
    use osmium_hal::virtio::queue::DESC_F_WRITE;
    use std::vec;
    use std::vec::Vec;

    const SECTORS: u64 = 1000;

    fn device(features: u64, sectors: u64) -> FakeTransport {
        let mut t = FakeTransport::new(DeviceType::Block, features, &sectors.to_le_bytes());
        t.max_queue = 16;
        t
    }

    fn mem(addr: u64, len: usize) -> &'static mut [u8] {
        // SAFETY: test DMA memory is identity-mapped and outlives the call.
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) }
    }

    /// What the fake disk saw: (type, sector, data length).
    type Log = Vec<(u32, u64, u32)>;

    /// Plays the device on its own thread over a RAM disk, failing sectors
    /// at or above `bad_from` with IOERR, until `stop` is set.
    fn serve(mut dev: DeviceSide, disk: &mut [u8], stop: &AtomicBool, bad_from: u64, reject_flush: bool) -> Log {
        let mut log = Log::new();
        while !stop.load(Ordering::Acquire) {
            let Some((head, chain)) = dev.pop_avail() else {
                std::thread::yield_now();
                continue;
            };
            let hdr = mem(chain[0].0, 16);
            let ty = u32::from_le_bytes(hdr[..4].try_into().unwrap());
            let sector = u64::from_le_bytes(hdr[8..].try_into().unwrap());
            assert_eq!(chain[0].1, 16);
            assert_eq!(chain[0].2 & DESC_F_WRITE, 0, "header is device-readable");
            let (status_addr, status_len, status_flags) = *chain.last().unwrap();
            assert_eq!((status_len, status_flags & DESC_F_WRITE), (1, DESC_F_WRITE));
            let data_len = if chain.len() == 3 { chain[1].1 } else { 0 };
            log.push((ty, sector, data_len));
            let off = sector as usize * 512;
            let mut written = 1;
            let st = if sector >= bad_from || (ty == blk::T_FLUSH && reject_flush) {
                blk::S_IOERR
            } else {
                match ty {
                    blk::T_IN => {
                        assert_ne!(chain[1].2 & DESC_F_WRITE, 0);
                        mem(chain[1].0, data_len as usize).copy_from_slice(&disk[off..off + data_len as usize]);
                        written += data_len;
                        blk::S_OK
                    }
                    blk::T_OUT => {
                        assert_eq!(chain[1].2 & DESC_F_WRITE, 0);
                        disk[off..off + data_len as usize].copy_from_slice(mem(chain[1].0, data_len as usize));
                        blk::S_OK
                    }
                    blk::T_FLUSH => blk::S_OK,
                    _ => blk::S_UNSUPP,
                }
            };
            mem(status_addr, 1)[0] = st;
            dev.push_used(head, written);
        }
        log
    }

    /// Runs `body` against a driver on `t` while a device thread serves it;
    /// returns the device's request log.
    fn with_disk(
        t: FakeTransport,
        disk: &mut [u8],
        bad_from: u64,
        reject_flush: bool,
        body: impl FnOnce(&mut VirtioBlk<'_, FakeTransport, HostDma>),
    ) -> Log {
        let dma = HostDma::default();
        let mut blk = VirtioBlk::new(t, &dma).unwrap();
        let (size, addrs) = blk.transport().queue(0);
        let stop = AtomicBool::new(false);
        std::thread::scope(|s| {
            let dev = DeviceSide::new(size, addrs);
            let server = s.spawn(|| serve(dev, disk, &stop, bad_from, reject_flush));
            body(&mut blk);
            stop.store(true, Ordering::Release);
            server.join().unwrap()
        })
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(7).wrapping_add(seed)).collect()
    }

    #[test]
    fn init_reads_capacity_and_features() {
        let dma = HostDma::default();
        let t = device(feature::VERSION_1 | blk::F_FLUSH | blk::F_BLK_SIZE, SECTORS);
        let b = VirtioBlk::new(t, &dma).unwrap();
        assert_eq!((b.block_size(), b.num_blocks()), (512, SECTORS));
        assert!(!b.is_read_only());
        let t = b.transport();
        assert_eq!(t.status() & status::DRIVER_OK, status::DRIVER_OK);
        assert_eq!(t.accepted.get(), feature::VERSION_1 | blk::F_FLUSH, "BLK_SIZE not taken");
        assert_eq!(t.queue(0).0, MAX_QUEUE_SIZE);
        drop(b);
        assert_eq!(dma.live.get(), 0);

        let mut tiny = device(0, 1);
        tiny.max_queue = 2;
        assert_eq!(VirtioBlk::new(tiny, &dma).err(), Some(VirtioError::BadQueue));
        let net = FakeTransport::new(DeviceType::Net, 0, &[]);
        assert_eq!(VirtioBlk::new(net, &dma).err(), Some(VirtioError::WrongDevice));
        assert_eq!(dma.live.get(), 0, "failed probes leak nothing");
    }

    #[test]
    fn read_write_and_flush() {
        for features in [0, feature::VERSION_1 | blk::F_FLUSH] {
            let mut disk = pattern(SECTORS as usize * 512, 1);
            let original = disk.clone();
            let new = pattern(1024, 99);
            let log = with_disk(device(features, SECTORS), &mut disk, u64::MAX, false, |b| {
                let mut buf = [0u8; 1024];
                b.read_blocks(10, &mut buf).unwrap();
                assert_eq!(buf[..], original[10 * 512..12 * 512]);
                b.write_blocks(20, &new).unwrap();
                b.read_blocks(20, &mut buf).unwrap();
                assert_eq!(buf[..], new[..]);
                b.flush().unwrap();
                b.read_blocks(0, &mut []).unwrap();
            });
            let flushes = if features & blk::F_FLUSH != 0 { vec![(blk::T_FLUSH, 0, 0)] } else { vec![] };
            let expected = [(blk::T_IN, 10, 1024), (blk::T_OUT, 20, 1024), (blk::T_IN, 20, 1024)];
            assert_eq!(log, [&expected[..], &flushes[..]].concat());
            assert_eq!(disk[20 * 512..22 * 512], new[..]);
            assert_eq!(disk[..20 * 512], original[..20 * 512], "nothing else touched");
        }
    }

    #[test]
    fn large_transfers_are_split() {
        let sectors = 400u64; // 200 KiB
        let mut disk = vec![0u8; sectors as usize * 512];
        let data = pattern(sectors as usize * 512, 5);
        let log = with_disk(device(feature::VERSION_1, sectors), &mut disk, u64::MAX, false, |b| {
            b.write_blocks(0, &data).unwrap();
            let mut back = vec![0u8; data.len()];
            b.read_blocks(0, &mut back).unwrap();
            assert!(back == data);
        });
        assert!(disk == data);
        let chunk = (DATA_LEN / 512) as u64;
        let sectors_of = |ty| log.iter().filter(|r| r.0 == ty).map(|r| r.1).collect::<Vec<_>>();
        assert_eq!(sectors_of(blk::T_OUT), [0, chunk, 2 * chunk, 3 * chunk]);
        assert_eq!(sectors_of(blk::T_IN), [0, chunk, 2 * chunk, 3 * chunk]);
        assert_eq!(log[3].2 as usize, 400 * 512 - 3 * DATA_LEN, "short last chunk");
    }

    #[test]
    fn read_only_rejects_writes() {
        let mut disk = vec![7u8; 512 * 4];
        let log =
            with_disk(device(feature::VERSION_1 | blk::F_RO | blk::F_FLUSH, 4), &mut disk, u64::MAX, false, |b| {
                assert!(b.is_read_only());
                assert_eq!(b.write_blocks(0, &[0; 512]), Err(BlockError::ReadOnly));
                assert_eq!(b.flush(), Ok(()));
                let mut buf = [0u8; 512];
                b.read_blocks(3, &mut buf).unwrap();
                assert_eq!(buf, [7; 512]);
            });
        assert_eq!(log, [(blk::T_IN, 3, 512)], "the device never saw a write or flush");
        assert_eq!(disk, vec![7u8; 512 * 4]);
    }

    #[test]
    fn device_errors_and_range_checks() {
        let mut disk = vec![0u8; 512 * 8];
        let log = with_disk(device(feature::VERSION_1 | blk::F_FLUSH, 8), &mut disk, 6, true, |b| {
            let mut buf = [0u8; 512];
            assert_eq!(b.read_blocks(6, &mut buf), Err(BlockError::Io));
            assert_eq!(b.write_blocks(7, &buf), Err(BlockError::Io));
            assert_eq!(b.flush(), Err(BlockError::Io));
            // The driver recovers: later requests still work.
            assert_eq!(b.read_blocks(5, &mut buf), Ok(()));
            assert_eq!(b.queue.num_free(), b.queue.size());

            assert_eq!(b.read_blocks(8, &mut buf), Err(BlockError::OutOfRange));
            assert_eq!(b.write_blocks(7, &[0; 1024]), Err(BlockError::OutOfRange));
            assert_eq!(b.read_blocks(u64::MAX, &mut buf), Err(BlockError::OutOfRange));
            assert_eq!(b.read_blocks(0, &mut [0; 100]), Err(BlockError::BadBuffer));
        });
        assert_eq!(log.len(), 4, "rejected requests never reach the device");
    }

    #[test]
    fn timeout_breaks_the_queue() {
        let dma = HostDma::default();
        let mut b = VirtioBlk::new(device(feature::VERSION_1, SECTORS), &dma).unwrap();
        let mut buf = [0u8; 512];
        assert_eq!(b.read_blocks(0, &mut buf), Err(BlockError::Io));
        assert!(b.queue.is_broken(), "the device may still own the bounce buffers");
        let in_flight = b.queue.in_flight();
        assert_eq!(b.read_blocks(1, &mut buf), Err(BlockError::Io));
        assert_eq!(b.queue.in_flight(), in_flight, "nothing new was queued");
    }

    #[test]
    fn drop_resets_the_device() {
        let dma = HostDma::default();
        let b = VirtioBlk::new(device(feature::VERSION_1, 1), &dma).unwrap();
        assert_eq!(dma.live.get(), 3);
        drop(b);
        assert_eq!(dma.live.get(), 0);
    }
}
