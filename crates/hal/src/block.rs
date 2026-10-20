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
    /// block count. A helper for implementations.
    fn check_range(&self, lba: u64, buf_len: usize) -> Result<u64, BlockError> {
        let bs = self.block_size();
        if !buf_len.is_multiple_of(bs) {
            return Err(BlockError::BadBuffer);
        }
        let n = (buf_len / bs) as u64;
        match lba.checked_add(n) {
            Some(end) if end <= self.num_blocks() => Ok(n),
            _ => Err(BlockError::OutOfRange),
        }
    }
}
