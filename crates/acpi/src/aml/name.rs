//! Namespace names: four-character segments and the paths built from them.

use core::fmt;

use super::cursor::Cursor;
use super::error::AmlError;

/// One four-character name segment, such as `_SB_` or `PCI0`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NameSeg(pub [u8; 4]);

impl NameSeg {
    /// Whether `b` may start a name segment.
    pub fn is_lead(b: u8) -> bool {
        b.is_ascii_uppercase() || b == b'_'
    }

    /// Validates four bytes as a name segment.
    pub fn new(bytes: [u8; 4]) -> Option<Self> {
        let [lead, rest @ ..] = bytes;
        (Self::is_lead(lead) && rest.iter().all(|&b| Self::is_lead(b) || b.is_ascii_digit())).then_some(Self(bytes))
    }

    /// The segment as text (it is always ASCII).
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.0).unwrap_or("????")
    }
}

impl fmt::Display for NameSeg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for NameSeg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

/// A `NameString` as it appears in AML: an optional root or parent prefixes, then zero or more segments.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NameString<'code> {
    /// Began with `\`.
    pub root: bool,
    /// Number of `^` prefixes.
    pub parents: usize,
    /// The segments, `4 * n` validated bytes.
    pub segs: &'code [u8],
}

impl<'code> NameString<'code> {
    /// The segments in order.
    pub fn segments(&self) -> impl Iterator<Item = NameSeg> + 'code {
        self.segs.as_chunks::<4>().0.iter().filter_map(|s| NameSeg::new(*s))
    }

    /// Number of segments.
    pub fn len(&self) -> usize {
        self.segs.len() / 4
    }

    /// Whether this is a single bare segment, which is looked up through enclosing scopes.
    pub fn is_simple(&self) -> bool {
        !self.root && self.parents == 0 && self.len() == 1
    }

    /// Whether `b` can begin a `NameString`.
    pub fn starts_with(b: u8) -> bool {
        matches!(b, b'\\' | b'^' | 0x2e | 0x2f) || NameSeg::is_lead(b)
    }

    /// Reads a `NameString`.
    pub fn parse(c: &mut Cursor<'code>) -> Result<Self, AmlError> {
        let mut root = false;
        let mut parents = 0;
        if c.peek() == Some(b'\\') {
            root = true;
            c.pos += 1;
        } else {
            while c.peek() == Some(b'^') {
                parents += 1;
                c.pos += 1;
            }
        }
        let lead = c.byte()?;
        let count = match lead {
            0x00 => 0,
            0x2e => 2,
            0x2f => usize::from(c.byte()?),
            b if NameSeg::is_lead(b) => {
                c.pos -= 1;
                1
            }
            _ => return Err(AmlError::InvalidName),
        };
        if count > MAX_SEGMENTS {
            return Err(AmlError::InvalidName);
        }
        let segs = c.take(count * 4)?;
        for s in segs.as_chunks::<4>().0 {
            if NameSeg::new(*s).is_none() {
                return Err(AmlError::InvalidName);
            }
        }
        Ok(Self { root, parents, segs })
    }
}

/// Most segments a path may have. Real namespaces are a handful deep.
pub(crate) const MAX_SEGMENTS: usize = 32;
