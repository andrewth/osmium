//! Processes: an address space, open files and an exit status, attached to
//! the task that runs them.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use osmium_arch::fp::FpState;
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
#[derive(Clone, Copy)]
struct Brk {
    start: u64,
    end: u64,
    limit: u64,
}

/// A process: one user address space and one task running in it.
///
/// Build it with [`Process::new`], then [`Process::spawn`] its task, or
/// [`Process::fork`] an existing one. The task holds a reference, and so
/// does the parent of a forked process until it reaps the child with
/// [`Process::wait_child`]. The address space is freed once both are gone:
/// the task has exited and its CPU has switched away from it, and (for a
/// forked process) the parent has reaped it or ended itself. Until then an
/// exited child, a zombie, keeps its whole address space.
pub struct Process {
    pid: Pid,
    parent: Option<Pid>,
    name: IrqSpinLock<&'static str>,
    /// Replaced by `execve`, which is why it is shared and locked.
    memory: IrqSpinLock<Arc<dyn UserMemory>>,
    brk: IrqSpinLock<Brk>,
    /// Next address `mmap` hands out (growing upwards), and its end.
    mmap: IrqSpinLock<(u64, u64)>,
    files: Mutex<FdTable>,
    cwd: IrqSpinLock<String>,
    umask: u32,
    status: Once<ExitStatus>,
    exited: WaitQueue,
    /// Forked children not yet reaped.
    children: IrqSpinLock<Vec<Arc<Process>>>,
    /// Woken whenever one of `children` exits.
    pub(crate) child_exited: WaitQueue,
    pub(crate) group: crate::thread::ThreadGroup,
    pub(crate) signals: crate::signal::Signals,
}

impl core::fmt::Debug for Process {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Process").field("pid", &self.pid).field("name", &self.name()).finish_non_exhaustive()
    }
}

static NEXT_PID: AtomicU32 = AtomicU32::new(1);

/// A fresh process or thread id; both come from one sequence.
pub(crate) fn alloc_id() -> u32 {
    NEXT_PID.fetch_add(1, Ordering::Relaxed)
}
static TABLE: IrqSpinLock<BTreeMap<Pid, Weak<Process>>> = IrqSpinLock::new(BTreeMap::new());

/// Default cap on the program break, above its start.
const BRK_MAX: u64 = 64 << 20;

impl Process {
    /// Creates a process over `memory`. The program break starts at
    /// `brk_start` (page-aligned; typically from
    /// [`crate::AddressSpace::load_elf`]). Its descriptors 0, 1 and 2 are
    /// the console set with [`crate::set_console`], if any.
    pub fn new(name: &'static str, memory: impl UserMemory + 'static, brk_start: u64) -> Arc<Self> {
        Self::new_boxed(name, Box::new(memory), brk_start)
    }

    /// [`Process::new`] for memory that is already boxed, such as an empty
    /// space from [`crate::Platform::new_memory`] that [`Process::exec`]
    /// will fill.
    pub fn new_boxed(name: &'static str, memory: Box<dyn UserMemory>, brk_start: u64) -> Arc<Self> {
        let brk = Brk { start: brk_start, end: brk_start, limit: brk_start.saturating_add(BRK_MAX) };
        Self::register(Self::with(None, name, memory.into(), brk, (0, 0), FdTable::with_console(), String::from("/")))
    }

    fn with(
        parent: Option<Pid>,
        name: &'static str,
        memory: Arc<dyn UserMemory>,
        brk: Brk,
        mmap: (u64, u64),
        files: FdTable,
        cwd: String,
    ) -> Self {
        let pid = Pid(alloc_id());
        Self {
            pid,
            parent,
            name: IrqSpinLock::new(name),
            memory: IrqSpinLock::new(memory),
            brk: IrqSpinLock::new(brk),
            mmap: IrqSpinLock::new(mmap),
            files: Mutex::new(files),
            cwd: IrqSpinLock::new(cwd),
            umask: 0o022,
            status: Once::new(),
            exited: WaitQueue::new(),
            children: IrqSpinLock::new(Vec::new()),
            child_exited: WaitQueue::new(),
            group: crate::thread::ThreadGroup::new(pid),
            signals: crate::signal::Signals::new(),
        }
    }

    fn register(p: Self) -> Arc<Self> {
        let p = Arc::new(p);
        TABLE.lock().insert(p.pid, Arc::downgrade(&p));
        p
    }

    /// `fork`: a new process with a copy of this one's memory, sharing its
    /// open files (and their offsets), with the same working directory,
    /// break and `mmap` area, and this one as its parent. The child has no
    /// task yet: spawn one that resumes user mode where the parent called
    /// `fork`, with a return value of 0 (see `syscall::handle`).
    pub fn fork(&self) -> Result<Arc<Process>, Errno> {
        let memory: Arc<dyn UserMemory> = self.memory().fork()?.into();
        let files = self.files.lock().clone();
        let child = Self::register(Self::with(
            Some(self.pid),
            self.name(),
            memory,
            *self.brk.lock(),
            *self.mmap.lock(),
            files,
            self.cwd(),
        ));
        self.children.lock().push(child.clone());
        Ok(child)
    }

    /// `wait4`: reaps an exited child, `pid` or any if `None`, and returns
    /// its id and status. Blocks until one exits, unless `nohang`, when it
    /// returns `Ok(None)` instead. Fails with `ECHILD` if there is no such
    /// child.
    pub fn wait_child(&self, pid: Option<Pid>, nohang: bool) -> Result<Option<(Pid, ExitStatus)>, Errno> {
        let matches = |c: &Arc<Process>| pid.is_none_or(|pid| c.pid == pid);
        let reaped = self.child_exited.wait_until(|| {
            let mut children = self.children.lock();
            if !children.iter().any(matches) {
                return Some(Err(Errno::ECHILD));
            }
            match children.iter().position(|c| matches(c) && c.exit_status().is_some()) {
                // Hand the child out: dropping it may free its memory, which
                // must not happen here, under the queue's lock.
                Some(i) => Some(Ok(Some(children.swap_remove(i)))),
                None if nohang => Some(Ok(None)),
                None => None,
            }
        })?;
        Ok(reaped.map(|c| (c.pid, c.exit_status().expect("reaped children have exited"))))
    }

    /// Forked children that have not been reaped, exited or not.
    pub fn children(&self) -> Vec<Pid> {
        self.children.lock().iter().map(|c| c.pid).collect()
    }

    /// Lets `mmap` place anonymous mappings in `range` (page-aligned).
    /// Without it, `mmap` fails with `ENOMEM`.
    pub fn set_mmap_area(&self, range: core::ops::Range<u64>) {
        *self.mmap.lock() = (range.start, range.end);
    }

    /// Creates the process's task from `builder` and makes it runnable.
    /// `entry` runs in the kernel on the task's stack and normally drops to
    /// user mode (`enter_user`). Once [`osmium_arch::fp::enable`] has run,
    /// the task gets its own FP/SIMD registers, starting cleared.
    pub fn spawn(self: &Arc<Self>, builder: TaskBuilder, entry: impl FnOnce() + Send + 'static) -> Arc<Task> {
        self.spawn_with_fp(builder, FpState::new(), entry)
    }

    /// [`Process::spawn`], with the FP/SIMD registers starting as `fp`.
    pub(crate) fn spawn_with_fp(
        self: &Arc<Self>,
        builder: TaskBuilder,
        fp: FpState,
        entry: impl FnOnce() + Send + 'static,
    ) -> Arc<Task> {
        let builder = if osmium_arch::fp::enabled() { builder.fp_state(fp) } else { builder };
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

    /// The name given to [`Process::new`], or after [`Process::exec`] the
    /// program's file name.
    pub fn name(&self) -> &'static str {
        *self.name.lock()
    }

    /// The process's memory.
    pub fn memory(&self) -> Arc<dyn UserMemory> {
        self.memory.lock().clone()
    }

    /// Handles a user page fault at `addr`. A write to a copy-on-write page
    /// (shared by `fork`) gets its own copy and returns true: return to user
    /// mode and the instruction runs again. Any other fault returns false,
    /// and ends the process (see [`handle_page_fault`]).
    pub fn handle_page_fault(&self, addr: u64, write: bool) -> bool {
        write && self.memory().cow_fault(addr)
    }

    /// The root page table to activate when switching to this process.
    pub fn root(&self) -> PhysAddr {
        self.memory.lock().root()
    }

    /// Replaces the program: the memory, its break and `mmap` area, and the
    /// name, closing descriptors marked close-on-exec. Returns the old
    /// memory, which must stay alive until its table is no longer active.
    pub(crate) fn replace_image(
        &self,
        name: &str,
        memory: Arc<dyn UserMemory>,
        brk_start: u64,
        mmap: core::ops::Range<u64>,
    ) -> Arc<dyn UserMemory> {
        *self.brk.lock() = Brk { start: brk_start, end: brk_start, limit: brk_start.saturating_add(BRK_MAX) };
        *self.mmap.lock() = (mmap.start, mmap.end);
        *self.name.lock() = intern(name);
        self.files.lock().close_on_exec();
        core::mem::replace(&mut *self.memory.lock(), memory)
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

    /// Records the exit status (the first one wins) and wakes waiters,
    /// including a parent in `wait4`, which also gets `SIGCHLD`. Does not
    /// stop the task; see [`exit`].
    pub fn set_exited(&self, status: ExitStatus) {
        let _ = self.status.set(status);
        self.exited.wake_all();
        if let Some(parent) = self.parent.and_then(Process::find) {
            parent.child_exited.wake_all();
            crate::signal::child_exited(&parent, self.pid);
        }
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
        let memory = self.memory();
        if new > old {
            if memory.map_anon(old, new - old, MapFlags::RW).is_err() {
                memory.unmap(old, new - old);
                return brk.end;
            }
        } else if new < old {
            memory.unmap(new, old - new);
        }
        brk.end = addr;
        brk.end
    }

    /// `mmap` for private anonymous memory: maps `len` bytes of zeroed
    /// pages and returns their address. With no access at all (`PROT_NONE`)
    /// the range is only reserved: left unmapped, any access faults.
    pub fn mmap_anon(&self, len: u64, flags: MapFlags) -> Result<u64, Errno> {
        let len = len.checked_next_multiple_of(PAGE).filter(|&l| l != 0).ok_or(Errno::EINVAL)?;
        let mut area = self.mmap.lock();
        let va = area.0;
        if va.checked_add(len).is_none_or(|end| end > area.1) {
            return Err(Errno::ENOMEM);
        }
        if flags != MapFlags::NONE {
            self.memory().map_anon(va, len, flags)?;
        }
        area.0 += len;
        Ok(va)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        TABLE.lock().remove(&self.pid);
    }
}

/// A `'static` copy of `name`, shared by every process with that name: one
/// small leak per distinct program name, so [`Process::name`] can stay
/// `&'static str`.
fn intern(name: &str) -> &'static str {
    static NAMES: IrqSpinLock<BTreeSet<&'static str>> = IrqSpinLock::new(BTreeSet::new());
    let mut names = NAMES.lock();
    if let Some(&n) = names.get(name) {
        return n;
    }
    let n: &'static str = String::from(name).leak();
    names.insert(n);
    n
}

/// The process the running task belongs to, if it is a user task.
pub fn current() -> Option<Arc<Process>> {
    osmium_sched::current().data::<Arc<Process>>().cloned()
}

/// [`Process::handle_page_fault`] for the calling task's process. A trap
/// handler calls it for a page fault taken in user mode, before killing the
/// process; false if the task is not a user task or the fault is not one to
/// resolve.
pub fn handle_page_fault(addr: u64, write: bool) -> bool {
    current().is_some_and(|p| p.handle_page_fault(addr, write))
}

/// The root table to activate for `next`, for the scheduler's switch hook
/// ([`osmium_sched::set_switch_hook`]). `None` means `next` is a kernel task,
/// which may keep running on whichever table is active, provided every
/// process table shares the kernel's mappings.
pub fn root_for(next: &Task) -> Option<PhysAddr> {
    next.data::<Arc<Process>>().map(|p| p.root())
}

/// Ends the calling thread with `status`, and its process with it unless
/// other threads remain (a `Signal` status, or an earlier `exit_group`, ends
/// them all), wakes anyone waiting, and ends its task. Kernel tasks just
/// exit.
pub fn exit(status: ExitStatus) -> ! {
    if let Some(p) = current() {
        crate::thread::exiting(&p, status);
    }
    osmium_sched::exit()
}
