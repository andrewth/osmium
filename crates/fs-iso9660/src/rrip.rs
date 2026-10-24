//! The System Use Sharing Protocol and the Rock Ridge entries carried in it
//! (IEEE P1281 and P1282).

use alloc::string::String;
use alloc::vec::Vec;

use osmium_sync::fallible::{OutOfMemory, try_extend_from_slice};

use crate::name::lossy;

/// What Rock Ridge says about one directory record.
#[derive(Default)]
pub struct RockRidge {
    /// `NM`: the POSIX name, pieces joined.
    name: Option<Vec<u8>>,
    /// `PX`: `st_mode`, type bits included.
    pub mode: Option<u32>,
    /// `PX`: `st_nlink`.
    pub nlink: Option<u32>,
    /// `PN`: the device number, as Linux encodes `dev_t`.
    pub rdev: Option<u64>,
    /// `SL`: the symbolic link's target.
    link: Option<String>,
    /// The last `SL` component said it continues in the next one.
    link_continues: bool,
    /// `CL`: a directory relocated to this logical block.
    pub child: Option<u32>,
    /// `RE`: this is the relocated directory itself, listed elsewhere.
    pub relocated: bool,
}

/// A `CE` entry: more entries in another block.
pub struct Continuation {
    /// Logical block.
    pub block: u32,
    /// Byte offset within the block.
    pub offset: u32,
    /// Length in bytes.
    pub len: u32,
}

/// Little-endian `u32` at `at`; 0 past the end (callers check the length).
fn le32(b: &[u8], at: usize) -> u32 {
    b.get(at..).and_then(|t| t.first_chunk::<4>()).map_or(0, |c| u32::from_le_bytes(*c))
}

/// The `SP` entry that starts the root's `.` record on a SUSP volume:
/// returns how many bytes to skip at the start of every system use area.
pub fn sp_skip(area: &[u8]) -> Option<usize> {
    let &[b'S', b'P', len, _, 0xbe, 0xef, skip] = area.first_chunk::<7>()? else { return None };
    (len >= 7).then_some(skip as usize)
}

impl RockRidge {
    /// Adds the entries in `area`; returns the continuation if there is one.
    pub fn parse(&mut self, area: &[u8]) -> Result<Option<Continuation>, OutOfMemory> {
        let mut more = None;
        let mut pos = 0;
        while pos + 4 <= area.len() {
            let Some(&len) = area.get(pos + 2) else { break };
            let len = len as usize;
            let Some(e) = area.get(pos..pos + len).filter(|_| len >= 4) else { break };
            pos += len;
            let Some(sig) = e.get(..2) else { break };
            // Only entries that have a flags byte look at it.
            let flags = e.get(4).copied().unwrap_or(0);
            match sig {
                b"CE" if len >= 28 => {
                    more = Some(Continuation { block: le32(e, 4), offset: le32(e, 12), len: le32(e, 20) })
                }
                b"PX" if len >= 36 => {
                    self.mode = Some(le32(e, 4));
                    self.nlink = Some(le32(e, 12));
                }
                b"PN" if len >= 20 => {
                    let (major, minor) = (le32(e, 4) as u64, le32(e, 12) as u64);
                    // A zero high word means the low word is a whole dev_t.
                    self.rdev = Some(match major {
                        0 => minor,
                        _ => {
                            (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12) | ((major & !0xfff) << 32)
                        }
                    });
                }
                // Flags 2 and 4 name `.` and `..`, which are not shown.
                b"NM" if len >= 5 && flags & 0x06 == 0 => {
                    try_extend_from_slice(self.name.get_or_insert_default(), e.get(5..).unwrap_or(&[]))?
                }
                b"SL" if len >= 5 => self.symlink(e.get(5..).unwrap_or(&[]))?,
                b"CL" if len >= 12 => self.child = Some(le32(e, 4)),
                b"RE" => self.relocated = true,
                b"ST" => break,
                _ => {}
            }
        }
        Ok(more)
    }

    /// Appends one `SL` entry's components to the link target.
    fn symlink(&mut self, mut comps: &[u8]) -> Result<(), OutOfMemory> {
        let target = self.link.get_or_insert_default();
        while let Some((&[flags, len], rest)) = comps.split_first_chunk::<2>() {
            let Some((text, after)) = rest.split_at_checked(len as usize) else { break };
            let len = len as usize;
            // Room for a separator and the component, even if it is all
            // replacement characters.
            target.try_reserve(1 + 3 * len.max(2))?;
            if !self.link_continues && !target.is_empty() && !target.ends_with('/') {
                target.push('/');
            }
            match flags {
                f if f & 0x08 != 0 => target.push('/'),
                f if f & 0x04 != 0 => target.push_str(".."),
                f if f & 0x02 != 0 => target.push('.'),
                _ => target.push_str(&lossy(text)?),
            }
            self.link_continues = flags & 0x01 != 0;
            comps = after;
        }
        Ok(())
    }

    /// The `NM` name, if there was one.
    pub fn name(&self) -> Result<Option<String>, OutOfMemory> {
        self.name.as_ref().map(|n| lossy(n)).transpose()
    }

    /// The `SL` target, if there was one.
    pub fn take_link(&mut self) -> Option<String> {
        self.link.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(sig: &[u8; 2], body: &[u8]) -> Vec<u8> {
        let mut e = Vec::from(&sig[..]);
        e.push(4 + body.len() as u8);
        e.push(1);
        e.extend_from_slice(body);
        e
    }

    #[test]
    fn names_and_links() {
        let mut area = entry(b"NM", b"\x01long na");
        area.extend(entry(b"NM", b"\x00me"));
        // /usr/lib/../x, with "lib" split across two components and the
        // whole link across two SL entries.
        area.extend(entry(b"SL", b"\x01\x08\x00\x00\x03usr\x01\x02li"));
        area.extend(entry(b"SL", b"\x00\x00\x01b\x04\x00\x00\x01x"));
        area.extend(entry(b"ST", b""));
        area.extend(entry(b"RE", b""));
        let mut rr = RockRidge::default();
        assert!(rr.parse(&area).unwrap().is_none());
        assert_eq!(rr.name().unwrap().as_deref(), Some("long name"));
        assert_eq!(rr.take_link().as_deref(), Some("/usr/lib/../x"));
        assert!(!rr.relocated, "entries after ST are ignored");
    }

    #[test]
    fn device_numbers() {
        let mut rr = RockRidge::default();
        let mut body = [0u8; 16];
        body[..4].copy_from_slice(&259u32.to_le_bytes());
        body[8..12].copy_from_slice(&300u32.to_le_bytes());
        rr.parse(&entry(b"PN", &body)).unwrap();
        // makedev(259, 300): minor 300 = 0x12c.
        assert_eq!(rr.rdev, Some(0x2c | (259 << 8) | (0x100 << 12)));
    }

    #[test]
    fn sp() {
        assert_eq!(sp_skip(b"SP\x07\x01\xbe\xef\x00"), Some(0));
        assert_eq!(sp_skip(b"SP\x07\x01\xbe\xee\x00"), None);
        assert_eq!(sp_skip(b"SP"), None);
    }
}
