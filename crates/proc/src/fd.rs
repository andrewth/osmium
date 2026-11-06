// SPDX-License-Identifier: GPL-2.0-only
//! File descriptors.
//!
//! # Locking
//!
//! A process's [`FdTable`] sits behind a lock that is held only to look up
//! or change a slot. Callers clone the [`OpenFile`] out of it and drop the
//! lock before any file I/O, so I/O never runs under the table lock.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use osmium_sched::{Mutex, MutexGuard};
use osmium_sync::Once;
use osmium_sync::fallible::{OutOfMemory, try_arc};

use osmium_fs::{Errno, File, FileKind};

/// Most descriptors a process may have open (Linux's default soft limit).
pub const MAX_FDS: usize = 1024;

/// How an open file may be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Access {
    /// Reads allowed.
    pub read: bool,
    /// Writes allowed.
    pub write: bool,
    /// Every write goes to the end of the file.
    pub append: bool,
}

impl Access {
    /// Read and write.
    pub const RW: Self = Self { read: true, write: true, append: false };
}

/// The file status flags of an open file description, in Linux's encoding:
/// the ones `fcntl(F_SETFL)` may change.
pub(crate) mod status {
    pub const APPEND: u32 = 0o2000;
    pub const NONBLOCK: u32 = 0o4000;
    pub const ASYNC: u32 = 0o20000;
    #[cfg(target_arch = "aarch64")]
    pub const DIRECT: u32 = 0o200000;
    #[cfg(not(target_arch = "aarch64"))]
    pub const DIRECT: u32 = 0o40000;
    pub const NOATIME: u32 = 0o1000000;
    /// What `F_SETFL` changes; it ignores every other bit, as Linux does.
    pub const SETTABLE: u32 = APPEND | NONBLOCK | ASYNC | DIRECT | NOATIME;
}

/// [`OpenFile::kind`]: not yet known.
const KIND_UNKNOWN: u8 = 0;
/// A stream (pipe, socket, device), which has no position.
const KIND_STREAM: u8 = 1;
/// A file with a position.
const KIND_SEEKABLE: u8 = 2;

/// An open file description: a file, a position, an access mode and status
/// flags, shared by every descriptor duplicated from the same open.
pub struct OpenFile {
    file: Arc<dyn File>,
    /// Read and write; append lives in `status`, which `F_SETFL` changes.
    access: Access,
    /// [`status`] flags. `O_NONBLOCK` of a pipe or socket is kept by the
    /// pipe or socket itself; for other files it is only recorded, as are
    /// `O_ASYNC` (there is no `F_SETOWN`, so no `SIGIO` is ever sent, as on
    /// Linux without an owner), `O_DIRECT` and `O_NOATIME`.
    status: AtomicU32,
    /// Whether the file is a stream, found out once: a file's kind never
    /// changes, and asking it costs a `stat` on every read and write.
    kind: AtomicU8,
    /// Shared by every descriptor duplicated from this open (including across
    /// `fork`), so it is only ever advanced with an atomic read-modify-write.
    offset: AtomicU64,
    /// Held across a read or write of a seekable file, so two descriptors
    /// sharing the description cannot both use the same offset.
    io: Mutex<()>,
    /// The absolute path it was opened by, for `*at` calls relative to it.
    path: Option<String>,
}

impl OpenFile {
    /// Opens `file` at offset 0.
    ///
    /// # Panics
    /// If memory runs out: [`OpenFile::try_new`] reports that instead.
    #[allow(clippy::expect_used)] // documented `# Panics` on OOM; `try_new` is the fallible form.
    pub fn new(file: Arc<dyn File>, access: Access) -> Arc<Self> {
        Self::try_new(file, access).expect("out of memory for an open file")
    }

    /// [`OpenFile::new`], failing with `ENOMEM` instead of panicking.
    pub fn try_new(file: Arc<dyn File>, access: Access) -> Result<Arc<Self>, Errno> {
        Self::build(file, access, 0, None)
    }

    fn build(file: Arc<dyn File>, access: Access, flags: u32, path: Option<String>) -> Result<Arc<Self>, Errno> {
        let append = if access.append { status::APPEND } else { 0 };
        try_arc(Self {
            file,
            access: Access { append: false, ..access },
            status: AtomicU32::new((flags | append) & status::SETTABLE),
            kind: AtomicU8::new(KIND_UNKNOWN),
            offset: AtomicU64::new(0),
            io: Mutex::new(()),
            path,
        })
        .map_err(crate::oom)
    }

    /// [`OpenFile::try_with_path`] that also records the open's [`status`]
    /// flags (`O_NONBLOCK`, `O_DIRECT`, `O_NOATIME`, ...), as `F_GETFL`
    /// reports them.
    pub(crate) fn try_opened(
        file: Arc<dyn File>,
        access: Access,
        path: String,
        flags: u32,
    ) -> Result<Arc<Self>, Errno> {
        Self::build(file, access, flags, Some(path))
    }

    /// Opens `file`, found at the absolute `path`, at offset 0.
    ///
    /// # Panics
    /// If memory runs out: [`OpenFile::try_with_path`] reports that instead.
    #[allow(clippy::expect_used)] // documented `# Panics` on OOM; `try_with_path` is the fallible form.
    pub fn with_path(file: Arc<dyn File>, access: Access, path: String) -> Arc<Self> {
        Self::try_with_path(file, access, path).expect("out of memory for an open file")
    }

    /// [`OpenFile::with_path`], failing with `ENOMEM` instead of panicking.
    pub fn try_with_path(file: Arc<dyn File>, access: Access, path: String) -> Result<Arc<Self>, Errno> {
        Self::build(file, access, 0, Some(path))
    }

    /// The path it was opened by, if any.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// The underlying file.
    pub fn file(&self) -> &Arc<dyn File> {
        &self.file
    }

    /// The access mode.
    pub fn access(&self) -> Access {
        Access { append: self.status.load(Ordering::Relaxed) & status::APPEND != 0, ..self.access }
    }

    /// The [`status`] flags recorded for this description.
    pub(crate) fn status_flags(&self) -> u32 {
        self.status.load(Ordering::Relaxed)
    }

    /// `F_SETFL`: replaces the settable [`status`] flags with those in
    /// `flags`, ignoring the rest.
    pub(crate) fn set_status_flags(&self, flags: u32) {
        self.status.store(flags & status::SETTABLE, Ordering::Relaxed);
    }

    /// The current position.
    pub fn offset(&self) -> u64 {
        self.offset.load(Ordering::Relaxed)
    }

    /// Moves the position.
    pub fn set_offset(&self, off: u64) {
        self.offset.store(off, Ordering::Relaxed);
    }

    /// Moves the position forward by `n` bytes.
    fn advance(&self, n: usize) -> Result<(), Errno> {
        let mut cur = self.offset.load(Ordering::Relaxed);
        loop {
            let next = cur.checked_add(n as u64).ok_or(Errno::EOVERFLOW)?;
            match self.offset.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Ok(()),
                Err(now) => cur = now,
            }
        }
    }

    /// Serialises use of the offset, for a file that has one. Streams
    /// (pipes, sockets, devices) can block indefinitely and ignore the
    /// offset, so they are not serialised.
    fn position_lock(&self) -> Result<Option<MutexGuard<'_, ()>>, Errno> {
        let kind = match self.kind.load(Ordering::Relaxed) {
            KIND_UNKNOWN => {
                let stream =
                    matches!(self.file.try_stat()?.kind, FileKind::CharDevice | FileKind::Fifo | FileKind::Socket);
                let kind = if stream { KIND_STREAM } else { KIND_SEEKABLE };
                self.kind.store(kind, Ordering::Relaxed);
                kind
            }
            kind => kind,
        };
        Ok((kind == KIND_SEEKABLE).then(|| self.io.lock()))
    }

    /// Reads at the current position and advances it.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if !self.access.read {
            return Err(Errno::EBADF);
        }
        let _pos = self.position_lock()?;
        let n = self.file.read(self.offset(), buf)?;
        self.advance(n)?;
        Ok(n)
    }

    /// Writes at the current position (or the end, for append) and advances
    /// it.
    pub fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        if !self.access.write {
            return Err(Errno::EBADF);
        }
        let _pos = self.position_lock()?;
        if self.access().append {
            // An append lands at the end and leaves the position just past it.
            let off = self.file.try_stat()?.size;
            let n = self.file.write(off, buf)?;
            self.set_offset(off.checked_add(n as u64).ok_or(Errno::EOVERFLOW)?);
            return Ok(n);
        }
        let n = self.file.write(self.offset(), buf)?;
        self.advance(n)?;
        Ok(n)
    }
}

/// A process's descriptor table. Cloning it (for `fork`) shares every open
/// file description, offsets included, as POSIX requires.
#[derive(Clone)]
pub struct FdTable {
    slots: Vec<Option<Slot>>,
}

/// One descriptor: an open file and its close-on-exec flag.
#[derive(Clone)]
struct Slot {
    file: Arc<OpenFile>,
    cloexec: bool,
}

static CONSOLE: Once<Arc<dyn File>> = Once::new();

/// Sets the file every new process gets as descriptors 0, 1 and 2. Panics if
/// called twice.
pub fn set_console(console: Arc<dyn File>) {
    assert!(CONSOLE.set(console).is_ok(), "console already set");
}

impl FdTable {
    /// [`Clone::clone`], failing instead of panicking if memory runs out.
    pub fn try_clone(&self) -> Result<Self, OutOfMemory> {
        let mut slots = Vec::new();
        slots.try_reserve_exact(self.slots.len())?;
        slots.extend(self.slots.iter().cloned());
        Ok(Self { slots })
    }

    /// An empty table.
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// A table with the console (see [`set_console`]) on 0, 1 and 2, or an
    /// empty one if there is no console.
    pub fn with_console() -> Self {
        let mut t = Self::new();
        if let Some(Ok(open)) = CONSOLE.get().map(|c| OpenFile::try_new(c.clone(), Access::RW)) {
            let slot = Slot { file: open, cloexec: false };
            t.slots = alloc::vec![Some(slot.clone()), Some(slot.clone()), Some(slot)];
        }
        t
    }

    /// The open file behind `fd`.
    pub fn get(&self, fd: i32) -> Result<Arc<OpenFile>, Errno> {
        self.slot(fd).map(|s| s.file.clone())
    }

    fn slot(&self, fd: i32) -> Result<&Slot, Errno> {
        usize::try_from(fd).ok().and_then(|i| self.slots.get(i)?.as_ref()).ok_or(Errno::EBADF)
    }

    /// Makes room for `len` descriptors.
    fn grow(&mut self, len: usize) -> Result<(), Errno> {
        self.slots.try_reserve(len.saturating_sub(self.slots.len())).map_err(|_| Errno::ENOMEM)?;
        self.slots.resize(len, None);
        Ok(())
    }

    /// Installs `file` at the lowest free descriptor and returns it.
    pub fn insert(&mut self, file: Arc<OpenFile>) -> Result<i32, Errno> {
        self.insert_from(0, file, false)
    }

    /// Installs `file` at the lowest free descriptor not below `min`, closed
    /// by `execve` if `cloexec`, and returns it.
    pub fn insert_from(&mut self, min: usize, file: Arc<OpenFile>, cloexec: bool) -> Result<i32, Errno> {
        let fd = match self.slots.iter().skip(min).position(Option::is_none) {
            Some(i) => min + i,
            None if self.slots.len().max(min) < MAX_FDS => {
                let fd = self.slots.len().max(min);
                self.grow(fd + 1)?;
                fd
            }
            None => return Err(if min >= MAX_FDS { Errno::EINVAL } else { Errno::EMFILE }),
        };
        *self.slots.get_mut(fd).ok_or(Errno::EBADF)? = Some(Slot { file, cloexec });
        Ok(fd as i32)
    }

    /// Makes `new` refer to `file` (closing whatever it referred to), as
    /// `dup2` and `dup3` do.
    pub fn insert_at(&mut self, new: i32, file: Arc<OpenFile>, cloexec: bool) -> Result<(), Errno> {
        let i = usize::try_from(new).ok().filter(|&i| i < MAX_FDS).ok_or(Errno::EBADF)?;
        if i >= self.slots.len() {
            self.grow(i + 1)?;
        }
        *self.slots.get_mut(i).ok_or(Errno::EBADF)? = Some(Slot { file, cloexec });
        Ok(())
    }

    /// Whether `execve` closes `fd`.
    pub fn cloexec(&self, fd: i32) -> Result<bool, Errno> {
        self.slot(fd).map(|s| s.cloexec)
    }

    /// Sets whether `execve` closes `fd`.
    pub fn set_cloexec(&mut self, fd: i32, on: bool) -> Result<(), Errno> {
        let slot = usize::try_from(fd).ok().and_then(|i| self.slots.get_mut(i)?.as_mut()).ok_or(Errno::EBADF)?;
        slot.cloexec = on;
        Ok(())
    }

    /// Closes every descriptor marked close-on-exec.
    pub fn close_on_exec(&mut self) {
        for slot in &mut self.slots {
            if slot.as_ref().is_some_and(|s| s.cloexec) {
                *slot = None;
            }
        }
    }

    /// Closes `fd`.
    pub fn close(&mut self, fd: i32) -> Result<(), Errno> {
        let slot = usize::try_from(fd).ok().and_then(|i| self.slots.get_mut(i)).ok_or(Errno::EBADF)?;
        slot.take().map(drop).ok_or(Errno::EBADF)
    }

    /// Number of open descriptors.
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// Returns true if nothing is open.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}
