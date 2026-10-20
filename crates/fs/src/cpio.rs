//! `newc` cpio archives, the format of a Linux initramfs.

use alloc::string::String;
use core::str;

use crate::{Errno, FileKind, OpenFlags, Vfs};

const HEADER_LEN: usize = 110;
const TRAILER: &str = "TRAILER!!!";

/// One member of a cpio archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'src> {
    /// Path inside the archive, without a leading `./` or `/`; empty for the
    /// archive's root (`.`).
    pub name: &'src str,
    /// The member's kind.
    pub kind: FileKind,
    /// Permission bits (`0o7777`).
    pub mode: u32,
    /// The file's contents, or a symbolic link's target.
    pub data: &'src [u8],
}

/// Iterates over the members of a `newc` (`070701`) or `newc` with
/// checksums (`070702`) archive, up to its trailer. Hard links are not
/// recognized: each name is a separate member, and only the last of a set
/// of links carries the data.
pub fn entries(archive: &[u8]) -> Entries<'_> {
    Entries { rest: archive, done: false }
}

/// The iterator returned by [`entries`].
pub struct Entries<'src> {
    rest: &'src [u8],
    done: bool,
}

/// Parses one 8-digit hexadecimal header field.
fn field(header: &[u8], index: usize) -> Result<u32, Errno> {
    let start = 6 + index * 8;
    let digits = str::from_utf8(&header[start..start + 8]).map_err(|_| Errno::EINVAL)?;
    u32::from_str_radix(digits, 16).map_err(|_| Errno::EINVAL)
}

fn align4(n: usize) -> usize {
    n.next_multiple_of(4)
}

impl<'src> Entries<'src> {
    fn parse(&mut self) -> Result<Option<Entry<'src>>, Errno> {
        // Several archives may be concatenated, with zero padding between.
        while self.rest.len() >= 4 && self.rest[..4] == [0; 4] {
            self.rest = &self.rest[4..];
        }
        if self.rest.is_empty() {
            return Ok(None);
        }
        let header = self.rest.get(..HEADER_LEN).ok_or(Errno::EINVAL)?;
        if &header[..6] != b"070701" && &header[..6] != b"070702" {
            return Err(Errno::EINVAL);
        }
        let mode = field(header, 1)?;
        let size = field(header, 6)? as usize;
        let name_size = field(header, 11)? as usize;
        let name_end = HEADER_LEN.checked_add(name_size).ok_or(Errno::EINVAL)?;
        let data_start = align4(name_end);
        let data_end = data_start.checked_add(size).ok_or(Errno::EINVAL)?;
        if name_size == 0 || data_end > self.rest.len() {
            return Err(Errno::EINVAL);
        }
        // The name is NUL-terminated.
        let name = &self.rest[HEADER_LEN..name_end - 1];
        let name = str::from_utf8(name).map_err(|_| Errno::EINVAL)?;
        let data = &self.rest[data_start..data_end];
        self.rest = &self.rest[align4(data_end).min(self.rest.len())..];
        if name == TRAILER {
            // Another archive may follow (an early microcode cpio, say).
            return self.parse();
        }
        let kind = match mode & 0o170000 {
            0o010000 => FileKind::Fifo,
            0o020000 => FileKind::CharDevice,
            0o040000 => FileKind::Directory,
            0o060000 => FileKind::BlockDevice,
            0o100000 => FileKind::Regular,
            0o120000 => FileKind::Symlink,
            0o140000 => FileKind::Socket,
            _ => return Err(Errno::EINVAL),
        };
        let name = name.trim_start_matches("./").trim_start_matches('/');
        let name = if name == "." { "" } else { name.trim_end_matches('/') };
        Ok(Some(Entry { name, kind, mode: mode & 0o7777, data }))
    }
}

impl<'src> Iterator for Entries<'src> {
    type Item = Result<Entry<'src>, Errno>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let entry = self.parse().transpose();
        if !matches!(entry, Some(Ok(_))) {
            self.done = true;
        }
        entry
    }
}

/// Unpacks `archive` into the existing directory `at` of `vfs`, creating
/// missing parent directories and replacing existing files; returns the
/// number of members. Device nodes get no device number: bind real devices
/// with a [`DevDir`](crate::dev::DevDir) instead.
pub fn unpack(vfs: &Vfs, at: &str, archive: &[u8]) -> Result<usize, Errno> {
    let mut count = 0;
    for entry in entries(archive) {
        let entry = entry?;
        count += 1;
        if entry.name.is_empty() {
            continue;
        }
        if entry.name.split('/').any(|c| c == "..") {
            return Err(Errno::EINVAL);
        }
        let mut path = String::from(at.trim_end_matches('/'));
        path.push('/');
        path.push_str(entry.name);
        mkdir_parents(vfs, &path)?;
        match entry.kind {
            FileKind::Directory => match vfs.mkdir(&path, entry.mode) {
                Err(Errno::EEXIST) if vfs.stat(&path, false)?.kind == FileKind::Directory => {}
                result => result?,
            },
            FileKind::Regular => {
                let flags = OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNC | OpenFlags::NOFOLLOW;
                let file = vfs.open(&path, flags, entry.mode)?;
                if file.write(0, entry.data)? != entry.data.len() {
                    return Err(Errno::EIO);
                }
            }
            FileKind::Symlink => {
                let target = str::from_utf8(entry.data).map_err(|_| Errno::EINVAL)?;
                remove_existing(vfs, &path)?;
                vfs.symlink(target, &path)?;
            }
            kind => {
                remove_existing(vfs, &path)?;
                vfs.mknod(&path, kind, entry.mode)?;
            }
        }
    }
    Ok(count)
}

/// `mkdir -p` of everything above `path`'s last component.
fn mkdir_parents(vfs: &Vfs, path: &str) -> Result<(), Errno> {
    for (i, _) in path.match_indices('/').skip(1) {
        match vfs.mkdir(&path[..i], 0o755) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Unlinks a non-directory at `path`, if there is one.
fn remove_existing(vfs: &Vfs, path: &str) -> Result<(), Errno> {
    match vfs.unlink(path) {
        Ok(()) | Err(Errno::ENOENT) => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RamFs;
    use alloc::vec::Vec;
    use std::format;

    /// Appends a `newc` member.
    fn member(out: &mut Vec<u8>, name: &str, mode: u32, data: &[u8]) {
        let header = format!(
            "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            out.len(),
            mode,
            0,
            0,
            1,
            0,
            data.len(),
            0,
            0,
            0,
            0,
            name.len() + 1,
            0
        );
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.resize(align4(out.len()), 0);
        out.extend_from_slice(data);
        out.resize(align4(out.len()), 0);
    }

    fn archive() -> Vec<u8> {
        let mut out = Vec::new();
        member(&mut out, ".", 0o040755, b"");
        member(&mut out, "bin", 0o040755, b"");
        member(&mut out, "bin/init", 0o100755, b"\x7fELF...");
        member(&mut out, "./etc/motd", 0o100644, b"hello\n");
        member(&mut out, "sbin", 0o120777, b"bin");
        member(&mut out, "dev/console", 0o020600, b"");
        member(&mut out, TRAILER, 0, b"");
        out
    }

    fn read_all(vfs: &Vfs, path: &str) -> Vec<u8> {
        let file = vfs.open(path, OpenFlags::READ, 0).unwrap();
        let mut buf = alloc::vec![0; file.stat().size as usize];
        file.read(0, &mut buf).unwrap();
        buf
    }

    #[test]
    fn parse_members() {
        let archive = archive();
        let names: Vec<&str> = entries(&archive).map(|e| e.unwrap().name).collect();
        assert_eq!(names, ["", "bin", "bin/init", "etc/motd", "sbin", "dev/console"]);
        let motd = entries(&archive).nth(3).unwrap().unwrap();
        assert_eq!((motd.kind, motd.mode, motd.data), (FileKind::Regular, 0o644, &b"hello\n"[..]));
        assert_eq!(entries(&archive[..200]).last().unwrap(), Err(Errno::EINVAL));
        assert_eq!(entries(b"not an archive").next(), Some(Err(Errno::EINVAL)));
    }

    #[test]
    fn unpack_into_ramfs() {
        let vfs = Vfs::new(RamFs::new(1).root());
        let mut archive = archive();
        // A second archive concatenated after padding replaces a file.
        archive.extend_from_slice(&[0; 8]);
        member(&mut archive, "etc/motd", 0o100600, b"bye\n");
        member(&mut archive, TRAILER, 0, b"");
        assert_eq!(unpack(&vfs, "/", &archive).unwrap(), 7);
        assert_eq!(read_all(&vfs, "/sbin/init"), b"\x7fELF...");
        assert_eq!(vfs.stat("/bin/init", true).unwrap().mode, 0o755);
        assert_eq!(read_all(&vfs, "/etc/motd"), b"bye\n");
        assert_eq!(vfs.stat("/etc", true).unwrap().mode, 0o755);
        assert_eq!(vfs.readlink("/sbin").unwrap(), "bin");
        assert_eq!(vfs.stat("/dev/console", false).unwrap().kind, FileKind::CharDevice);
        // Unpacking again over the same tree works.
        unpack(&vfs, "/", &archive).unwrap();

        let mut evil = Vec::new();
        member(&mut evil, "../escape", 0o100644, b"");
        assert_eq!(unpack(&vfs, "/etc", &evil), Err(Errno::EINVAL));
    }

    /// An archive written by GNU cpio, if it is installed.
    #[test]
    fn gnu_cpio() {
        use std::process::{Command, Stdio};
        use std::{fs, io::Write};
        let dir = std::env::temp_dir().join(format!("osmium-fs-cpio-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("a/b")).unwrap();
        fs::write(dir.join("a/b/file"), b"from gnu cpio").unwrap();
        std::os::unix::fs::symlink("b/file", dir.join("a/link")).unwrap();
        let Ok(mut child) = Command::new("cpio")
            .args(["-o", "-H", "newc", "--quiet"])
            .current_dir(&dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
        else {
            std::eprintln!("cpio not installed; skipping");
            return;
        };
        child.stdin.take().unwrap().write_all(b".\na\na/b\na/b/file\na/link\n").unwrap();
        let archive = child.wait_with_output().unwrap().stdout;
        fs::remove_dir_all(&dir).unwrap();

        let vfs = Vfs::new(RamFs::new(1).root());
        assert_eq!(unpack(&vfs, "/", &archive).unwrap(), 5);
        assert_eq!(read_all(&vfs, "/a/link"), b"from gnu cpio");
    }
}
