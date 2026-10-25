//! A bounds-checked reader over AML bytes.

use super::error::AmlError;

/// A position in a block of AML with an end it may not read past.
#[derive(Clone, Copy)]
pub(crate) struct Cursor<'code> {
    pub data: &'code [u8],
    pub pos: usize,
    pub end: usize,
}

impl<'code> Cursor<'code> {
    pub fn new(data: &'code [u8], pos: usize, end: usize) -> Self {
        Self { data, pos, end: end.min(data.len()) }
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.end
    }

    pub fn peek(&self) -> Option<u8> {
        if self.pos < self.end { self.data.get(self.pos).copied() } else { None }
    }

    pub fn byte(&mut self) -> Result<u8, AmlError> {
        let b = self.peek().ok_or(AmlError::UnexpectedEnd)?;
        self.pos += 1;
        Ok(b)
    }

    pub fn take(&mut self, n: usize) -> Result<&'code [u8], AmlError> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.end).ok_or(AmlError::UnexpectedEnd)?;
        let s = self.data.get(self.pos..end).ok_or(AmlError::UnexpectedEnd)?;
        self.pos = end;
        Ok(s)
    }

    pub fn word(&mut self) -> Result<u16, AmlError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes(*b.first_chunk().ok_or(AmlError::UnexpectedEnd)?))
    }

    pub fn dword(&mut self) -> Result<u32, AmlError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(*b.first_chunk().ok_or(AmlError::UnexpectedEnd)?))
    }

    pub fn qword(&mut self) -> Result<u64, AmlError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes(*b.first_chunk().ok_or(AmlError::UnexpectedEnd)?))
    }

    /// Reads a `PkgLength` and returns the absolute offset where the package ends. The package must lie
    /// within the cursor's own bounds and cannot end before its own length field does.
    pub fn pkg_length(&mut self) -> Result<usize, AmlError> {
        let start = self.pos;
        let lead = self.byte()?;
        let extra = usize::from(lead >> 6);
        let mut len = if extra == 0 { usize::from(lead & 0x3f) } else { usize::from(lead & 0x0f) };
        for i in 0..extra {
            len |= usize::from(self.byte()?) << (4 + 8 * i);
        }
        let end = start.checked_add(len).ok_or(AmlError::InvalidPkgLength)?;
        if end > self.end || end < self.pos {
            return Err(AmlError::InvalidPkgLength);
        }
        Ok(end)
    }

    /// Reads a `PkgLength` as a plain number, as field elements use it: the value is a size, not a span of
    /// the enclosing code.
    pub fn raw_pkg_length(&mut self) -> Result<u64, AmlError> {
        let lead = self.byte()?;
        let extra = usize::from(lead >> 6);
        let mut len = if extra == 0 { u64::from(lead & 0x3f) } else { u64::from(lead & 0x0f) };
        for i in 0..extra {
            len |= u64::from(self.byte()?) << (4 + 8 * i);
        }
        Ok(len)
    }

    /// A cursor over `self.pos..end` of the same code.
    pub fn until(&self, end: usize) -> Cursor<'code> {
        Cursor { data: self.data, pos: self.pos, end: end.min(self.end) }
    }
}
