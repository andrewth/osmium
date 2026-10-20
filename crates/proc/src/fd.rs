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
use core::sync::atomic::{AtomicU64, Ordering};

use osmium_sync::Once;

use osmium_fs::{Errno, File};

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

/// An open file description: a file, a position and an access mode, shared
/// by every descriptor duplicated from the same open.
pub struct OpenFile {
    file: Arc<dyn File>,
    access: Access,
    /// Shared by every descriptor duplicated from this open (including across
    /// `fork`), so it is only ever advanced with an atomic read-modify-write.
    offset: AtomicU64,
    /// The absolute path it was opened by, for `*at` calls relative to it.
    path: Option<String>,
}

impl OpenFile {
    /// Opens `file` at offset 0.
    pub fn new(file: Arc<dyn File>, access: Access) -> Arc<Self> {
        Arc::new(Self { file, access, offset: AtomicU64::new(0), path: None })
    }

    /// Opens `file`, found at the absolute `path`, at offset 0.
    pub fn with_path(file: Arc<dyn File>, access: Access, path: String) -> Arc<Self> {
        Arc::new(Self { file, access, offset: AtomicU64::new(0), path: Some(path) })
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
        self.access
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

    /// Reads at the current position and advances it.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if !self.access.read {
            return Err(Errno::EBADF);
        }
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
        if self.access.append {
            // An append lands at the end and leaves the position just past it.
            let off = self.file.stat().size;
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
    /// An empty table.
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// A table with the console (see [`set_console`]) on 0, 1 and 2, or an
    /// empty one if there is no console.
    pub fn with_console() -> Self {
        let mut t = Self::new();
        if let Some(c) = CONSOLE.get() {
            let open = OpenFile::new(c.clone(), Access::RW);
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
                self.slots.resize(fd + 1, None);
                fd
            }
            None => return Err(if min >= MAX_FDS { Errno::EINVAL } else { Errno::EMFILE }),
        };
        self.slots[fd] = Some(Slot { file, cloexec });
        Ok(fd as i32)
    }

    /// Makes `new` refer to `file` (closing whatever it referred to), as
    /// `dup2` and `dup3` do.
    pub fn insert_at(&mut self, new: i32, file: Arc<OpenFile>, cloexec: bool) -> Result<(), Errno> {
        let i = usize::try_from(new).ok().filter(|&i| i < MAX_FDS).ok_or(Errno::EBADF)?;
        if i >= self.slots.len() {
            self.slots.resize(i + 1, None);
        }
        self.slots[i] = Some(Slot { file, cloexec });
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
