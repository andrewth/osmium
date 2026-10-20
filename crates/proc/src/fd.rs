//! File descriptors.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_sync::{IrqSpinLock, Once};

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
    offset: IrqSpinLock<u64>,
    /// The absolute path it was opened by, for `*at` calls relative to it.
    path: Option<String>,
}

impl OpenFile {
    /// Opens `file` at offset 0.
    pub fn new(file: Arc<dyn File>, access: Access) -> Arc<Self> {
        Arc::new(Self { file, access, offset: IrqSpinLock::new(0), path: None })
    }

    /// Opens `file`, found at the absolute `path`, at offset 0.
    pub fn with_path(file: Arc<dyn File>, access: Access, path: String) -> Arc<Self> {
        Arc::new(Self { file, access, offset: IrqSpinLock::new(0), path: Some(path) })
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
        *self.offset.lock()
    }

    /// Moves the position.
    pub fn set_offset(&self, off: u64) {
        *self.offset.lock() = off;
    }

    /// Reads at the current position and advances it.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Errno> {
        if !self.access.read {
            return Err(Errno::EBADF);
        }
        let off = self.offset();
        let n = self.file.read(off, buf)?;
        self.set_offset(off + n as u64);
        Ok(n)
    }

    /// Writes at the current position (or the end, for append) and advances
    /// it.
    pub fn write(&self, buf: &[u8]) -> Result<usize, Errno> {
        if !self.access.write {
            return Err(Errno::EBADF);
        }
        let off = if self.access.append { self.file.stat().size } else { self.offset() };
        let n = self.file.write(off, buf)?;
        self.set_offset(off + n as u64);
        Ok(n)
    }
}

/// A process's descriptor table.
pub struct FdTable {
    slots: Vec<Option<Arc<OpenFile>>>,
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
            t.slots = alloc::vec![Some(open.clone()), Some(open.clone()), Some(open)];
        }
        t
    }

    /// The open file behind `fd`.
    pub fn get(&self, fd: i32) -> Result<Arc<OpenFile>, Errno> {
        usize::try_from(fd).ok().and_then(|i| self.slots.get(i)?.clone()).ok_or(Errno::EBADF)
    }

    /// Installs `file` at the lowest free descriptor and returns it.
    pub fn insert(&mut self, file: Arc<OpenFile>) -> Result<i32, Errno> {
        let fd = match self.slots.iter().position(Option::is_none) {
            Some(i) => i,
            None if self.slots.len() < MAX_FDS => {
                self.slots.push(None);
                self.slots.len() - 1
            }
            None => return Err(Errno::EMFILE),
        };
        self.slots[fd] = Some(file);
        Ok(fd as i32)
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
