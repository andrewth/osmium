//! The [`File`] trait: one node (file, directory or device) of a file system.

use alloc::string::String;
use alloc::sync::Arc;
use core::ops::{BitAnd, BitOr, BitOrAssign};

use crate::Errno;

/// What kind of node a [`File`] is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// A regular file.
    #[default]
    Regular,
    /// A directory.
    Directory,
    /// A character device, such as a console.
    CharDevice,
    /// A block device.
    BlockDevice,
    /// A FIFO (named or anonymous pipe).
    Fifo,
    /// A symbolic link.
    Symlink,
    /// A socket.
    Socket,
}

impl FileKind {
    /// The file-type bits of `st_mode` (`S_IFREG` and so on).
    pub const fn mode_bits(self) -> u32 {
        match self {
            FileKind::Fifo => 0o010000,
            FileKind::CharDevice => 0o020000,
            FileKind::Directory => 0o040000,
            FileKind::BlockDevice => 0o060000,
            FileKind::Regular => 0o100000,
            FileKind::Symlink => 0o120000,
            FileKind::Socket => 0o140000,
        }
    }

    /// The `d_type` value for `getdents64` (`DT_REG` and so on).
    pub const fn dirent_type(self) -> u8 {
        match self {
            FileKind::Fifo => 1,
            FileKind::CharDevice => 2,
            FileKind::Directory => 4,
            FileKind::BlockDevice => 6,
            FileKind::Regular => 8,
            FileKind::Symlink => 10,
            FileKind::Socket => 12,
        }
    }
}

/// A node's metadata, enough to fill a `struct stat`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    /// Identifies the file system (`st_dev`).
    pub dev: u64,
    /// Inode number, unique within `dev`.
    pub ino: u64,
    /// The node's kind; `st_mode`'s type bits are [`FileKind::mode_bits`].
    pub kind: FileKind,
    /// Permission bits only (`0o7777`).
    pub mode: u32,
    /// Hard link count.
    pub nlink: u32,
    /// Size in bytes (for a symlink, the target's length).
    pub size: u64,
    /// Device number for character and block devices (`st_rdev`).
    pub rdev: u64,
}

/// One directory entry, returned by [`File::readdir`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    /// The entry's inode number.
    pub ino: u64,
    /// The entry's kind.
    pub kind: FileKind,
    /// The entry's name, without any `/`.
    pub name: String,
}

/// A node of a file system: a file, directory, device or anything else
/// reachable through a file descriptor.
///
/// Nodes are stateless and offset-based, like `pread`/`pwrite`: the file
/// offset, `O_APPEND` and the access mode belong to whoever opened the node.
/// No permission checks happen here; the caller does them from [`Stat`].
///
/// Every method but [`stat`](File::stat) has a default, so a device only
/// implements what it supports. Directory operations default to `ENOTDIR`.
pub trait File: Send + Sync {
    /// Reads at byte offset `off` into `buf`; returns the bytes read, 0 at
    /// end of file. A directory returns `EISDIR`.
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<usize, Errno> {
        let _ = (off, buf);
        Err(Errno::EINVAL)
    }

    /// Writes `buf` at byte offset `off`, extending the file if needed;
    /// returns the bytes written.
    fn write(&self, off: u64, buf: &[u8]) -> Result<usize, Errno> {
        let _ = (off, buf);
        Err(Errno::EINVAL)
    }

    /// The node's metadata.
    fn stat(&self) -> Stat;

    /// Sets the size to `len`, dropping data past it or filling with zeroes.
    fn truncate(&self, len: u64) -> Result<(), Errno> {
        let _ = len;
        Err(Errno::EINVAL)
    }

    /// Makes previous writes durable.
    fn sync(&self) -> Result<(), Errno> {
        Ok(())
    }

    /// The node as [`Any`](core::any::Any), for a layer that needs operations
    /// specific to its type (the socket calls); `None` by default.
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        None
    }

    /// Device-specific control (`ioctl`); returns the call's result.
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<usize, Errno> {
        let _ = (cmd, arg);
        Err(Errno::ENOTTY)
    }

    /// The `index`th entry of a directory, or `None` past the last.
    ///
    /// `.` and `..` are not included; `getdents64` adds them itself. Indexes
    /// are stable while the directory is unchanged.
    fn readdir(&self, index: usize) -> Result<Option<DirEntry>, Errno> {
        let _ = index;
        Err(Errno::ENOTDIR)
    }

    /// Finds the directory entry `name` (never `.`, `..` or containing `/`).
    fn lookup(&self, name: &str) -> Result<Arc<dyn File>, Errno> {
        let _ = name;
        Err(Errno::ENOTDIR)
    }

    /// Creates the entry `name` of `kind` with permission bits `mode`;
    /// `EEXIST` if it exists. A symbolic link is created empty and its
    /// target set with [`write`](File::write) at offset 0.
    fn create(&self, name: &str, kind: FileKind, mode: u32) -> Result<Arc<dyn File>, Errno> {
        let _ = (name, kind, mode);
        Err(Errno::ENOTDIR)
    }

    /// Removes the entry `name`. With `dir`, it must be an empty directory
    /// (`ENOTDIR`, `ENOTEMPTY`); without, it must not be one (`EISDIR`).
    fn remove(&self, name: &str, dir: bool) -> Result<(), Errno> {
        let _ = (name, dir);
        Err(Errno::ENOTDIR)
    }

    /// The target of a symbolic link.
    fn readlink(&self) -> Result<String, Errno> {
        Err(Errno::EINVAL)
    }
}

/// How to open a path: osmium's own bits, not any architecture's `O_*`
/// values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct OpenFlags(u32);

impl OpenFlags {
    /// Open for reading.
    pub const READ: OpenFlags = OpenFlags(1 << 0);
    /// Open for writing.
    pub const WRITE: OpenFlags = OpenFlags(1 << 1);
    /// Create the file if it does not exist (`O_CREAT`).
    pub const CREATE: OpenFlags = OpenFlags(1 << 2);
    /// With `CREATE`, fail with `EEXIST` if it exists (`O_EXCL`).
    pub const EXCL: OpenFlags = OpenFlags(1 << 3);
    /// Truncate a regular file opened for writing to zero length (`O_TRUNC`).
    pub const TRUNC: OpenFlags = OpenFlags(1 << 4);
    /// Fail with `ENOTDIR` unless the path is a directory (`O_DIRECTORY`).
    pub const DIRECTORY: OpenFlags = OpenFlags(1 << 5);
    /// Do not follow a symbolic link in the last component (`O_NOFOLLOW`).
    pub const NOFOLLOW: OpenFlags = OpenFlags(1 << 6);
    /// Writes go to the end of the file (`O_APPEND`); the opener applies it.
    pub const APPEND: OpenFlags = OpenFlags(1 << 7);

    /// No flags.
    pub const fn empty() -> Self {
        OpenFlags(0)
    }

    /// The raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// The flags in either (`|` in a `const`).
    pub const fn union(self, other: OpenFlags) -> OpenFlags {
        OpenFlags(self.0 | other.0)
    }

    /// Whether every flag in `other` is set.
    pub const fn contains(self, other: OpenFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for OpenFlags {
    type Output = OpenFlags;
    fn bitor(self, rhs: OpenFlags) -> OpenFlags {
        OpenFlags(self.0 | rhs.0)
    }
}

impl BitOrAssign for OpenFlags {
    fn bitor_assign(&mut self, rhs: OpenFlags) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for OpenFlags {
    type Output = OpenFlags;
    fn bitand(self, rhs: OpenFlags) -> OpenFlags {
        OpenFlags(self.0 & rhs.0)
    }
}
