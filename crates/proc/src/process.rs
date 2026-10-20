//! Processes: an address space, open files and an exit status, attached to
//! the task that runs them.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU32, Ordering};

use osmium_mm::addr::{PAGE_SIZE, PhysAddr};
use osmium_mm::paging::MapFlags;
use osmium_sched::{Mutex, Task, TaskBuilder, WaitQueue};
use osmium_sync::{IrqSpinLock, Once};

use osmium_fs::Errno;

use crate::fd::FdTable;
use crate::memory::UserMemory;

const PAGE: u64 = PAGE_SIZE as u64;

/// A process id. Pid 0 is never used; the first process is 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pid(pub u32);

/// How a process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitStatus {
    /// It called `exit` or `exit_group` with this code (only the low 8 bits
    /// reach a waiting parent, as on Linux).
    Code(i32),
    /// The kernel ended it, as if by this signal (11 = `SIGSEGV` for a fault).
    Signal(u8),
}

impl ExitStatus {
    /// The status word `wait4` stores: the code in bits 8-15, or the signal
    /// number in bits 0-6.
    pub fn wait_status(self) -> i32 {
        match self {
            ExitStatus::Code(c) => (c & 0xff) << 8,
            ExitStatus::Signal(s) => (s & 0x7f) as i32,
        }
    }
}

/// The program break: `brk` grows the heap from `start` up to `limit`.
struct Brk {
    start: u64,
    end: u64,
    limit: u64,
}

/// A process: one user address space and one task running in it.
///
/// Build it with [`Process::new`], then [`Process::spawn`] its task. The task
/// holds the only long-lived reference, so the address space is freed once
/// the task has exited and its CPU has switched away from it, unless a
/// waiter still holds the process.
pub struct Process {
    pid: Pid,
    parent: Option<Pid>,
    name: &'static str,
    memory: Box<dyn UserMemory>,
    brk: IrqSpinLock<Brk>,
    /// Next address `mmap` hands out (growing upwards), and its end.
    mmap: IrqSpinLock<(u64, u64)>,
    files: Mutex<FdTable>,
    cwd: IrqSpinLock<String>,
    umask: u32,
    status: Once<ExitStatus>,
    exited: WaitQueue,
}

static NEXT_PID: AtomicU32 = AtomicU32::new(1);
static TABLE: IrqSpinLock<BTreeMap<Pid, Weak<Process>>> = IrqSpinLock::new(BTreeMap::new());

/// Default cap on the program break, above its start.
const BRK_MAX: u64 = 64 << 20;

impl Process {
    /// Creates a process over `memory`. The program break starts at
    /// `brk_start` (page-aligned; typically from
    /// [`crate::AddressSpace::load_elf`]). Its descriptors 0, 1 and 2 are
    /// the console set with [`crate::set_console`], if any.
    pub fn new(name: &'static str, memory: impl UserMemory + 'static, brk_start: u64) -> Arc<Self> {
        let pid = Pid(NEXT_PID.fetch_add(1, Ordering::Relaxed));
        let p = Arc::new(Self {
            pid,
            parent: None,
            name,
            memory: Box::new(memory),
            brk: IrqSpinLock::new(Brk { start: brk_start, end: brk_start, limit: brk_start.saturating_add(BRK_MAX) }),
            mmap: IrqSpinLock::new((0, 0)),
            files: Mutex::new(FdTable::with_console()),
            cwd: IrqSpinLock::new(String::from("/")),
            umask: 0o022,
            status: Once::new(),
            exited: WaitQueue::new(),
        });
        TABLE.lock().insert(pid, Arc::downgrade(&p));
        p
    }

    /// Lets `mmap` place anonymous mappings in `range` (page-aligned).
    /// Without it, `mmap` fails with `ENOMEM`.
    pub fn set_mmap_area(&self, range: core::ops::Range<u64>) {
        *self.mmap.lock() = (range.start, range.end);
    }

    /// Creates the process's task from `builder` and makes it runnable.
    /// `entry` runs in the kernel on the task's stack and normally drops to
    /// user mode (`enter_user`).
    pub fn spawn(self: &Arc<Self>, builder: TaskBuilder, entry: impl FnOnce() + Send + 'static) -> Arc<Task> {
        builder.data(self.clone()).spawn(entry)
    }

    /// Finds a live process by id.
    pub fn find(pid: Pid) -> Option<Arc<Process>> {
        TABLE.lock().get(&pid)?.upgrade()
    }

    /// The process id.
    pub fn pid(&self) -> Pid {
        self.pid
    }

    /// The id of the process that created this one; `None` for processes
    /// the kernel created.
    pub fn parent(&self) -> Option<Pid> {
        self.parent
    }

    /// The name given to [`Process::new`].
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The process's memory.
    pub fn memory(&self) -> &dyn UserMemory {
        &*self.memory
    }

    /// The root page table to activate when switching to this process.
    pub fn root(&self) -> PhysAddr {
        self.memory.root()
    }

    /// The open-file table.
    pub fn files(&self) -> &Mutex<FdTable> {
        &self.files
    }

    /// The working directory, an absolute path.
    pub fn cwd(&self) -> String {
        self.cwd.lock().clone()
    }

    /// Changes the working directory to `path`, which must be absolute.
    pub fn set_cwd(&self, path: String) {
        debug_assert!(path.starts_with('/'));
        *self.cwd.lock() = path;
    }

    /// The file-creation mask (always `0o022`).
    pub fn umask(&self) -> u32 {
        self.umask
    }

    /// How the process ended, once it has.
    pub fn exit_status(&self) -> Option<ExitStatus> {
        self.status.get().copied()
    }

    /// Blocks until the process has ended, and returns how.
    pub fn wait(&self) -> ExitStatus {
        self.exited.wait_until(|| self.exit_status())
    }

    /// Records the exit status (the first one wins) and wakes waiters. Does
    /// not stop the task; see [`exit`].
    pub fn set_exited(&self, status: ExitStatus) {
        let _ = self.status.set(status);
        self.exited.wake_all();
    }

    /// `brk(addr)`: moves the program break to `addr` if it is within
    /// bounds, mapping or unmapping whole pages, and returns the (possibly
    /// unchanged) break. `addr == 0` just queries it.
    pub fn brk(&self, addr: u64) -> u64 {
        let mut brk = self.brk.lock();
        if addr < brk.start || addr > brk.limit {
            return brk.end;
        }
        let (old, new) = (brk.end.next_multiple_of(PAGE), addr.next_multiple_of(PAGE));
        if new > old {
            if self.memory.map_anon(old, new - old, MapFlags::RW).is_err() {
                self.memory.unmap(old, new - old);
                return brk.end;
            }
        } else if new < old {
            self.memory.unmap(new, old - new);
        }
        brk.end = addr;
        brk.end
    }

    /// `mmap` for private anonymous memory: maps `len` bytes of zeroed
    /// pages and returns their address.
    pub fn mmap_anon(&self, len: u64, flags: MapFlags) -> Result<u64, Errno> {
        let len = len.checked_next_multiple_of(PAGE).filter(|&l| l != 0).ok_or(Errno::EINVAL)?;
        let mut area = self.mmap.lock();
        let va = area.0;
        if va.checked_add(len).is_none_or(|end| end > area.1) {
            return Err(Errno::ENOMEM);
        }
        self.memory.map_anon(va, len, flags)?;
        area.0 += len;
        Ok(va)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        TABLE.lock().remove(&self.pid);
    }
}

/// The process the running task belongs to, if it is a user task.
pub fn current() -> Option<Arc<Process>> {
    osmium_sched::current().data::<Arc<Process>>().cloned()
}

/// The root table to activate for `next`, for the scheduler's switch hook
/// ([`osmium_sched::set_switch_hook`]). `None` means `next` is a kernel task,
/// which may keep running on whichever table is active, provided every
/// process table shares the kernel's mappings.
pub fn root_for(next: &Task) -> Option<PhysAddr> {
    next.data::<Arc<Process>>().map(|p| p.root())
}

/// Ends the calling process with `status`, wakes anyone waiting for it, and
/// ends its task. Kernel tasks just exit.
pub fn exit(status: ExitStatus) -> ! {
    if let Some(p) = current() {
        p.set_exited(status);
    }
    osmium_sched::exit()
}
