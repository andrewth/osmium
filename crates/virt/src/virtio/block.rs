//! virtio-blk (device ID 2) over any [`BlockDevice`].

use alloc::vec;

use osmium_hal::block::{BlockDevice, BlockError};

use super::{DescChain, DeviceCtx, VirtioDevice};
use crate::memory::GuestMemory;

use osmium_hal::virtio::blk::{
    CONFIG_BLK_SIZE, CONFIG_CAPACITY, F_BLK_SIZE, F_FLUSH, F_RO, HEADER_LEN as HEADER, S_IOERR, S_OK, S_UNSUPP,
    SECTOR_SIZE, T_FLUSH, T_GET_ID, T_IN, T_OUT,
};

/// virtio-blk addresses the disk in 512-byte sectors whatever the block size.
const SECTOR: u64 = SECTOR_SIZE as u64;
const ID: &[u8; 20] = b"osmium-virtio-blk\0\0\0";
/// Bytes moved per step of a read or write, so the guest's descriptor
/// lengths never size a host allocation.
const CHUNK: usize = 64 * 1024;

/// A virtio block device that serves guest requests from a host
/// [`BlockDevice`]. Requests are handled synchronously on notify.
pub struct VirtioBlock<B> {
    disk: B,
    read_only: bool,
}

impl<B: BlockDevice + Send> VirtioBlock<B> {
    /// Exposes `disk` to the guest read/write.
    pub fn new(disk: B) -> Self {
        Self { disk, read_only: false }
    }

    /// Exposes `disk` to the guest read-only.
    pub fn read_only(disk: B) -> Self {
        Self { disk, read_only: true }
    }

    /// The backing disk.
    pub fn disk(&mut self) -> &mut B {
        &mut self.disk
    }

    /// Serves one request; returns the number of bytes written to the guest.
    fn handle(&mut self, mem: &GuestMemory, chain: &DescChain) -> u32 {
        let wlen = chain.writable_len();
        let mut hdr = [0u8; HEADER];
        if wlen == 0 || chain.read(mem, 0, &mut hdr) != Ok(HEADER) {
            // No status byte to report into, or no header: drop it.
            return 0;
        }
        let ty = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let sector = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        let status_at = wlen - 1;

        let (status, data) = match ty {
            T_IN => match self.transfer(mem, chain, sector, status_at, false) {
                Ok(n) => (S_OK, n),
                Err(_) => (S_IOERR, 0),
            },
            T_OUT if self.read_only => (S_IOERR, 0),
            T_OUT => {
                let r = self.transfer(mem, chain, sector, chain.readable_len() - HEADER, true);
                (if r.is_ok() { S_OK } else { S_IOERR }, 0)
            }
            T_FLUSH => (if self.disk.flush().is_ok() { S_OK } else { S_IOERR }, 0),
            T_GET_ID => {
                let n = status_at.min(ID.len());
                match chain.write(mem, 0, &ID[..n]) {
                    Ok(n) => (S_OK, n),
                    Err(_) => (S_IOERR, 0),
                }
            }
            _ => (S_UNSUPP, 0),
        };
        if chain.write(mem, status_at, &[status]).is_err() {
            return data as u32;
        }
        data as u32 + 1
    }

    /// Moves `len` bytes between the disk at `sector` and the chain's data
    /// buffers (the writable ones for a read, the readable ones after the
    /// header for a write), [`CHUNK`] bytes at a time. Returns the bytes moved.
    fn transfer(
        &mut self,
        mem: &GuestMemory,
        chain: &DescChain,
        sector: u64,
        len: usize,
        write: bool,
    ) -> Result<usize, BlockError> {
        let bs = self.disk.block_size();
        if !len.is_multiple_of(bs) {
            return Err(BlockError::BadBuffer);
        }
        let lba = self.lba(sector)?;
        let step = (CHUNK / bs).max(1) * bs;
        let mut buf = vec![0u8; step.min(len)];
        let mut done = 0;
        while done < len {
            let n = step.min(len - done);
            let at = lba.checked_add((done / bs) as u64).ok_or(BlockError::OutOfRange)?;
            if write {
                if chain.read(mem, HEADER + done, &mut buf[..n]) != Ok(n) {
                    return Err(BlockError::Io);
                }
                self.disk.write_blocks(at, &buf[..n])?;
            } else {
                self.disk.read_blocks(at, &mut buf[..n])?;
                if chain.write(mem, done, &buf[..n]) != Ok(n) {
                    return Err(BlockError::Io);
                }
            }
            done += n;
        }
        Ok(done)
    }

    /// Converts a 512-byte sector to a disk block, which must be aligned.
    fn lba(&self, sector: u64) -> Result<u64, BlockError> {
        let bs = self.disk.block_size() as u64;
        let byte = sector.checked_mul(SECTOR).ok_or(BlockError::OutOfRange)?;
        if byte % bs != 0 {
            return Err(BlockError::BadBuffer);
        }
        Ok(byte / bs)
    }
}

impl<B: BlockDevice + Send> VirtioDevice for VirtioBlock<B> {
    fn device_id(&self) -> u32 {
        super::device_id::BLOCK
    }

    fn features(&self) -> u64 {
        let mut f = F_FLUSH | F_BLK_SIZE;
        if self.read_only {
            f |= F_RO;
        }
        f
    }

    fn num_queues(&self) -> usize {
        1
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        // capacity (u64, sectors) and blk_size (u32).
        let bs = self.disk.block_size() as u64;
        let mut cfg = [0u8; 24];
        cfg[CONFIG_CAPACITY..CONFIG_CAPACITY + 8]
            .copy_from_slice(&(self.disk.num_blocks() * bs / SECTOR).to_le_bytes());
        cfg[CONFIG_BLK_SIZE..CONFIG_BLK_SIZE + 4].copy_from_slice(&(bs as u32).to_le_bytes());
        for (i, d) in data.iter_mut().enumerate() {
            *d = cfg.get(offset as usize + i).copied().unwrap_or(0);
        }
    }

    fn notify(&mut self, queue: usize, ctx: &mut DeviceCtx<'_>) {
        if queue != 0 {
            return;
        }
        while let Some(chain) = ctx.pop(0) {
            let Ok(chain) = chain else { continue };
            let len = self.handle(ctx.mem(), &chain);
            let _ = ctx.add_used(0, chain.head, len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::BusDevice;
    use crate::memory::GuestPhysAddr;
    use crate::virtio::VirtioMmio;
    use crate::virtio::mmio::tests::{bring_up, notify};
    use crate::virtio::queue::tests::{DATA, Driver, guest};
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    /// 4 KiB blocks, so sector-to-block conversion is exercised.
    struct Disk(Vec<u8>);
    impl BlockDevice for Disk {
        fn block_size(&self) -> usize {
            4096
        }
        fn num_blocks(&self) -> u64 {
            (self.0.len() / 4096) as u64
        }
        fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            self.check_range(lba, buf.len())?;
            let at = lba as usize * 4096;
            buf.copy_from_slice(&self.0[at..at + buf.len()]);
            Ok(())
        }
        fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
            self.check_range(lba, buf.len())?;
            let at = lba as usize * 4096;
            self.0[at..at + buf.len()].copy_from_slice(buf);
            Ok(())
        }
    }

    const HDR: u64 = DATA;
    const BUF: u64 = DATA + 0x1000;
    const STATUS: u64 = DATA + 0x3000;

    fn header(mem: &GuestMemory, ty: u32, sector: u64) {
        let mut h = [0u8; 16];
        h[0..4].copy_from_slice(&ty.to_le_bytes());
        h[8..16].copy_from_slice(&sector.to_le_bytes());
        mem.write_obj(GuestPhysAddr(HDR), h).unwrap();
    }

    fn status(mem: &GuestMemory) -> u8 {
        mem.read_obj(GuestPhysAddr(STATUS)).unwrap()
    }

    #[test]
    fn read_write_flush_id() {
        let mut ram = vec![0u8; 0x10000];
        let mem = Arc::new(guest(&mut ram));
        let mut image = vec![0u8; 4 * 4096];
        image[4096..4096 + 5].copy_from_slice(b"blk 1");
        let blk = VirtioMmio::new(VirtioBlock::new(Disk(image)), mem.clone(), |_| {});
        bring_up(&blk, &[(0, 0)]);
        let mut d = Driver::new(8);

        let mut cap = [0u8; 8];
        blk.read(0x100, &mut cap);
        assert_eq!(u64::from_le_bytes(cap), 32, "16 KiB in 512-byte sectors");

        // Read block 1 (sector 8).
        header(&mem, T_IN, 8);
        d.post(&mem, &[(HDR, 16, false), (BUF, 4096, true), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_OK);
        assert_eq!(d.used(&mem, 0).1, 4097);
        let mut got = [0u8; 5];
        mem.read(GuestPhysAddr(BUF), &mut got).unwrap();
        assert_eq!(&got, b"blk 1");

        // Write block 3, then check the disk.
        mem.write(GuestPhysAddr(BUF), b"written").unwrap();
        header(&mem, T_OUT, 24);
        d.post(&mem, &[(HDR, 16, false), (BUF, 4096, false), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_OK);
        assert_eq!(d.used(&mem, 1).1, 1);
        blk.with_device(|b, _| assert_eq!(&b.disk().0[3 * 4096..3 * 4096 + 7], b"written"));

        // Unaligned sector and past-the-end requests fail.
        header(&mem, T_IN, 1);
        d.post(&mem, &[(HDR, 16, false), (BUF, 4096, true), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_IOERR);
        header(&mem, T_IN, 32);
        d.post(&mem, &[(HDR, 16, false), (BUF, 4096, true), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_IOERR);

        header(&mem, T_FLUSH, 0);
        d.post(&mem, &[(HDR, 16, false), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_OK);

        header(&mem, T_GET_ID, 0);
        d.post(&mem, &[(HDR, 16, false), (BUF, 20, true), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_OK);
        assert_eq!(d.used(&mem, 5).1, 21);

        header(&mem, 99, 0);
        d.post(&mem, &[(HDR, 16, false), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_UNSUPP);
    }

    #[test]
    fn large_requests_in_chunks() {
        let mut ram = vec![0u8; 0x40000];
        let mem = Arc::new(guest(&mut ram));
        let blk = VirtioMmio::new(VirtioBlock::new(Disk(vec![0; 64 * 4096])), mem.clone(), |_| {});
        bring_up(&blk, &[(0, 0)]);
        let mut d = Driver::new(8);
        // 128 KiB, twice CHUNK, written and read back.
        const BIG: u64 = 0x10000;
        let pattern: Vec<u8> = (0..0x20000u32).map(|i| (i % 251) as u8).collect();
        mem.write(GuestPhysAddr(BIG), &pattern).unwrap();
        header(&mem, T_OUT, 8);
        d.post(&mem, &[(HDR, 16, false), (BIG, 0x20000, false), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_OK);
        blk.with_device(|b, _| assert_eq!(&b.disk().0[4096..4096 + 0x20000], &pattern[..]));
        mem.write(GuestPhysAddr(BIG), &[0; 0x20000]).unwrap();
        header(&mem, T_IN, 8);
        d.post(&mem, &[(HDR, 16, false), (BIG, 0x20000, true), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_OK);
        assert_eq!(d.used(&mem, 1).1, 0x20001);
        let mut back = vec![0u8; 0x20000];
        mem.read(GuestPhysAddr(BIG), &mut back).unwrap();
        assert_eq!(back, pattern);

        // A 4 GiB buffer claim fails at the disk's end without the host
        // allocating anything near that size.
        header(&mem, T_IN, 0);
        d.post(&mem, &[(HDR, 16, false), (BIG, 0xffff_f000, true), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_IOERR);
        assert_eq!(d.used(&mem, 2).1, 1);
    }

    #[test]
    fn read_only_rejects_writes() {
        let mut ram = vec![0u8; 0x10000];
        let mem = Arc::new(guest(&mut ram));
        let blk = VirtioMmio::new(VirtioBlock::read_only(Disk(vec![0; 4096])), mem.clone(), |_| {});
        assert_ne!(blk.with_device(|b, _| b.features()) & F_RO, 0);
        bring_up(&blk, &[(0, 0)]);
        let mut d = Driver::new(8);
        mem.write(GuestPhysAddr(BUF), &[0xaa; 4096]).unwrap();
        header(&mem, T_OUT, 0);
        d.post(&mem, &[(HDR, 16, false), (BUF, 4096, false), (STATUS, 1, true)]);
        notify(&blk, 0);
        assert_eq!(status(&mem), S_IOERR);
        blk.with_device(|b, _| assert!(b.disk().0.iter().all(|&x| x == 0)));
    }
}
