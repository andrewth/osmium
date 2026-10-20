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
    /// Uses `data` as the disk. Panics unless `data` is a whole number of
    /// `block_size` blocks.
    pub fn new(data: &'disk mut [u8], block_size: usize) -> Self {
        assert!(block_size > 0 && data.len().is_multiple_of(block_size));
        Self { data, block_size, read_only: false }
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
        let off = lba as usize * self.block_size;
        buf.copy_from_slice(&self.data[off..off + buf.len()]);
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        if self.read_only {
            return Err(BlockError::ReadOnly);
        }
        self.check_range(lba, buf.len())?;
        let off = lba as usize * self.block_size;
        self.data[off..off + buf.len()].copy_from_slice(buf);
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
}
