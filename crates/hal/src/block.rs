//! Block storage.

/// Why a block operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// The range extends beyond the device.
    OutOfRange,
    /// The buffer is not a whole number of blocks.
    BadBuffer,
    /// The device reported an I/O error.
    Io,
    /// The device is read-only.
    ReadOnly,
}

/// A device addressed in fixed-size blocks.
pub trait BlockDevice {
    /// Bytes per block.
    fn block_size(&self) -> usize;

    /// Number of blocks.
    fn num_blocks(&self) -> u64;

    /// Reads `buf.len() / block_size()` blocks starting at `lba`.
    fn read_blocks(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError>;

    /// Writes `buf.len() / block_size()` blocks starting at `lba`.
    fn write_blocks(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlockError>;

    /// Makes previous writes durable.
    fn flush(&mut self) -> Result<(), BlockError> {
        Ok(())
    }

    /// Checks that `buf` covers whole blocks inside the device; returns the
    /// block count. A helper for implementations. A device reporting a block
    /// size of 0 has no whole blocks, so every buffer is
    /// [`BlockError::BadBuffer`].
    fn check_range(&self, lba: u64, buf_len: usize) -> Result<u64, BlockError> {
        let bs = self.block_size();
        if bs == 0 || !buf_len.is_multiple_of(bs) {
            return Err(BlockError::BadBuffer);
        }
        let n = (buf_len / bs) as u64;
        match lba.checked_add(n) {
            Some(end) if end <= self.num_blocks() => Ok(n),
            _ => Err(BlockError::OutOfRange),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(usize, u64);

    impl BlockDevice for Fake {
        fn block_size(&self) -> usize {
            self.0
        }
        fn num_blocks(&self) -> u64 {
            self.1
        }
        fn read_blocks(&mut self, _: u64, _: &mut [u8]) -> Result<(), BlockError> {
            Ok(())
        }
        fn write_blocks(&mut self, _: u64, _: &[u8]) -> Result<(), BlockError> {
            Ok(())
        }
    }

    #[test]
    fn check_range() {
        let d = Fake(512, 4);
        assert_eq!(d.check_range(2, 1024), Ok(2));
        assert_eq!(d.check_range(3, 1024), Err(BlockError::OutOfRange));
        assert_eq!(d.check_range(u64::MAX, 512), Err(BlockError::OutOfRange));
        assert_eq!(d.check_range(0, 100), Err(BlockError::BadBuffer));
        let zero = Fake(0, 4);
        assert_eq!(zero.check_range(0, 0), Err(BlockError::BadBuffer));
        assert_eq!(zero.check_range(0, 512), Err(BlockError::BadBuffer));
    }
}
