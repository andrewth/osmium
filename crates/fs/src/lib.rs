//! The file system layer: a virtual file system that resolves paths across
//! mounted file systems.
//!
//! - [`File`]: one node (regular file, directory, device, symlink). Nodes are
//!   stateless and offset-based like `pread`/`pwrite`; the open-file
//!   description (offset, `O_APPEND`, access mode) belongs to the caller.
//! - [`Vfs`]: a namespace of mounts, looked up by absolute path, with
//!   `open`, `mkdir`, `unlink`, `rmdir`, `symlink`, `link`, `rename` and
//!   `stat`.
//! - [`Clock`]: where timestamps come from; platforms supply one with
//!   [`clock::set_clock`] and a file system may take its own.
//! - [`RamFs`]: a file system kept in memory (tmpfs).
//! - [`cpio`]: reads `newc` cpio archives and unpacks an initramfs.
//! - [`dev`]: [`DevDir`](dev::DevDir) for `/dev`, plus null and zero devices.
//! - [`Errno`]: Linux error numbers, which system calls return negated.
//! - [`OpenFlags`]: osmium's own open flags; system call layers translate
//!   each architecture's `O_*` values into them.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod clock;
pub mod cpio;
pub mod dev;
mod errno;
mod file;
mod ramfs;
mod vfs;

pub use clock::{Clock, ClockSlot, ManualClock, Timestamp};
pub use errno::Errno;
pub use file::{DirEntry, File, FileKind, OpenFlags, POLLERR, POLLHUP, POLLIN, POLLOUT, POLLRDHUP, Stat};
pub use ramfs::RamFs;
pub use vfs::{NAME_MAX, PATH_MAX, Vfs};
