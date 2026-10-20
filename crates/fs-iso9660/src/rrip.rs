//! The System Use Sharing Protocol and the Rock Ridge entries carried in it
//! (IEEE P1281 and P1282).

use alloc::string::String;
use alloc::vec::Vec;

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

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("fixed-width slice"))
}

/// The `SP` entry that starts the root's `.` record on a SUSP volume:
/// returns how many bytes to skip at the start of every system use area.
pub fn sp_skip(area: &[u8]) -> Option<usize> {
    let sp = area.get(..7)?;
    (&sp[..2] == b"SP" && sp[2] >= 7 && sp[4] == 0xbe && sp[5] == 0xef).then_some(sp[6] as usize)
}

impl RockRidge {
    /// Adds the entries in `area`; returns the continuation if there is one.
    pub fn parse(&mut self, area: &[u8]) -> Option<Continuation> {
        let mut more = None;
        let mut pos = 0;
        while pos + 4 <= area.len() {
            let len = area[pos + 2] as usize;
            if len < 4 || pos + len > area.len() {
                break;
            }
            let e = &area[pos..pos + len];
            pos += len;
            match &e[..2] {
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
                b"NM" if len >= 5 && e[4] & 0x06 == 0 => self.name.get_or_insert_default().extend_from_slice(&e[5..]),
                b"SL" if len >= 5 => self.symlink(&e[5..]),
                b"CL" if len >= 12 => self.child = Some(le32(e, 4)),
                b"RE" => self.relocated = true,
                b"ST" => break,
                _ => {}
            }
        }
        more
    }

    /// Appends one `SL` entry's components to the link target.
    fn symlink(&mut self, mut comps: &[u8]) {
        let target = self.link.get_or_insert_default();
        while comps.len() >= 2 {
            let (flags, len) = (comps[0], comps[1] as usize);
            let Some(text) = comps.get(2..2 + len) else { break };
            if !self.link_continues && !target.is_empty() && !target.ends_with('/') {
                target.push('/');
            }
            match flags {
                f if f & 0x08 != 0 => target.push('/'),
                f if f & 0x04 != 0 => target.push_str(".."),
                f if f & 0x02 != 0 => target.push('.'),
                _ => target.push_str(&String::from_utf8_lossy(text)),
            }
            self.link_continues = flags & 0x01 != 0;
            comps = &comps[2 + len..];
        }
    }

    /// The `NM` name, if there was one.
    pub fn name(&self) -> Option<String> {
        self.name.as_ref().map(|n| String::from_utf8_lossy(n).into_owned())
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
        assert!(rr.parse(&area).is_none());
        assert_eq!(rr.name().as_deref(), Some("long name"));
        assert_eq!(rr.take_link().as_deref(), Some("/usr/lib/../x"));
        assert!(!rr.relocated, "entries after ST are ignored");
    }

    #[test]
    fn device_numbers() {
        let mut rr = RockRidge::default();
        let mut body = [0u8; 16];
        body[..4].copy_from_slice(&259u32.to_le_bytes());
        body[8..12].copy_from_slice(&300u32.to_le_bytes());
        rr.parse(&entry(b"PN", &body));
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
