//! The file system layer: a virtual file system that resolves paths across
//! mounted file systems.
//!
//! - [`File`]: one node (regular file, directory, device, symlink). Nodes are
//!   stateless and offset-based like `pread`/`pwrite`; the open-file
//!   description (offset, `O_APPEND`, access mode) belongs to the caller.
//! - [`Vfs`]: a namespace of mounts, looked up by absolute path, with
//!   `open`, `mkdir`, `unlink`, `rmdir`, `symlink` and `stat`.
//! - [`Errno`]: Linux error numbers, which system calls return negated.
//! - [`OpenFlags`]: osmium's own open flags; system call layers translate
//!   each architecture's `O_*` values into them.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod errno;
mod file;
mod vfs;

pub use errno::Errno;
pub use file::{DirEntry, File, FileKind, OpenFlags, Stat};
pub use vfs::{NAME_MAX, PATH_MAX, Vfs};
