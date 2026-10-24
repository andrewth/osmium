//! A memory-backed block device.

use osmium_hal::block::{BlockDevice, BlockError};

/// A disk stored in a byte slice (an initrd, a test image, a RAM-backed
/// scratch disk).
pub struct RamDisk<'disk> {
    data: &'disk mut [u8],
    block_size: usize,
    read_only: bool,
}

impl<'disk> RamDisk<'disk> {
    /// Uses `data` as the disk. A trailing partial block of `data` is
    /// ignored, and a `block_size` of 0 is taken as 1.
    pub fn new(data: &'disk mut [u8], block_size: usize) -> Self {
        let block_size = block_size.max(1);
        let whole = data.len() - data.len() % block_size;
        let (data, _) = data.split_at_mut(whole);
        Self { data, block_size, read_only: false }
    }

    /// `len` bytes from block `lba`, if they lie inside the disk.
    fn range(&self, lba: u64, len: usize) -> Option<&[u8]> {
        let off = usize::try_from(lba).ok()?.checked_mul(self.block_size)?;
        self.data.get(off..off.checked_add(len)?)
    }

    /// Rejects writes from now on.
    pub fn set_read_only(&mut self) {
        self.read_only = true;
    }
}

impl BlockDevice for RamDisk<'_> {
    fn block_size(&self) -> usize {
        self.block_size
    }

    fn num_blocks(&self) -> u64 {
        (self.data.len() / self.block_size) as u64
    }

    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.check_range(lba, buf.len())?;
        let src = self.range(lba, buf.len()).ok_or(BlockError::OutOfRange)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        self.check_range(lba, buf.len())?;
        let off =
            usize::try_from(lba).ok().and_then(|l| l.checked_mul(self.block_size)).ok_or(BlockError::OutOfRange)?;
        let dst =
            off.checked_add(buf.len()).and_then(|end| self.data.get_mut(off..end)).ok_or(BlockError::OutOfRange)?;
        dst.copy_from_slice(buf);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_bounds() {
        let mut backing = [0u8; 2048];
        let mut disk = RamDisk::new(&mut backing, 512);
        assert_eq!(disk.num_blocks(), 4);
        disk.write_blocks(1, &[7u8; 1024]).unwrap();
        let mut buf = [0u8; 512];
        disk.read_blocks(2, &mut buf).unwrap();
        assert_eq!(buf, [7u8; 512]);
        assert_eq!(disk.read_blocks(3, &mut [0u8; 1024]), Err(BlockError::OutOfRange));
        assert_eq!(disk.read_blocks(0, &mut [0u8; 100]), Err(BlockError::BadBuffer));
        disk.set_read_only();
        assert_eq!(disk.write_blocks(0, &buf), Err(BlockError::ReadOnly));
    }

    #[test]
    fn odd_construction_and_huge_lba_do_not_panic() {
        let mut backing = [0u8; 1100];
        let mut disk = RamDisk::new(&mut backing, 512);
        assert_eq!(disk.num_blocks(), 2, "trailing partial block ignored");
        assert_eq!(disk.read_blocks(u64::MAX, &mut [0u8; 512]), Err(BlockError::OutOfRange));
        assert_eq!(disk.write_blocks(u64::MAX, &[0u8; 512]), Err(BlockError::OutOfRange));
        let zero = RamDisk::new(&mut [], 0);
        assert_eq!(zero.num_blocks(), 0);
    }
}
