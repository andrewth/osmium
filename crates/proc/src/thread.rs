//! Threads: tasks that share one process's address space, files and signal
//! dispositions.
//!
//! A [`crate::Process`] is a thread group. Its first thread, the leader, has
//! the process id as its thread id; `clone` with `CLONE_THREAD` adds threads,
//! each with its own task, signal mask, pending signals and thread pointer.
//! `exit` ends the calling thread; the process ends when its last thread
//! does, or at once with `exit_group` or a fatal signal, which stops the
//! other threads the next time each is in the kernel (a timer interrupt is
//! enough, if the kernel calls `signal::deliver` on it).
//!
//! All of a process's threads run on one CPU: unmapping memory does not shoot
//! down other CPUs' TLB entries yet. Joining uses `CLONE_CHILD_CLEARTID` and
//! `futex`, as `pthread_join` does.
#![cfg_attr(
    not(any(test, target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64"))),
    allow(dead_code)
)]

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use osmium_fs::Errno;
use osmium_sched::WaitQueue;
use osmium_sync::{IrqSpinLock, Once};

use crate::process::{ExitStatus, Pid, Process};
use crate::syscall::Outcome;

/// "No such process", which `osmium_fs::Errno` does not name.
pub(crate) const ESRCH: Errno = Errno(3);

/// Most threads in one process.
const THREADS_MAX: usize = 1024;

/// One thread of a process.
pub struct Thread {
    /// Changes once, when a non-leader thread's `execve` makes it the leader.
    tid: AtomicU32,
    leader: AtomicBool,
    /// The task running it, plus one; 0 until it is known.
    task: AtomicU64,
    pub(crate) mask: AtomicU64,
    pub(crate) pending: AtomicU64,
    clear_tid: AtomicU64,
    robust_list: AtomicU64,
    /// Another thread's `execve` is ending this one.
    pub(crate) doomed: AtomicBool,
    tls: AtomicU64,
    fault: IrqSpinLock<Option<(u8, u64)>>,
    alive: AtomicBool,
}

impl Thread {
    fn new(tid: u32, leader: bool) -> Self {
        Self {
            tid: AtomicU32::new(tid),
            leader: AtomicBool::new(leader),
            task: AtomicU64::new(0),
            mask: AtomicU64::new(0),
            pending: AtomicU64::new(0),
            clear_tid: AtomicU64::new(0),
            robust_list: AtomicU64::new(0),
            doomed: AtomicBool::new(false),
            tls: AtomicU64::new(0),
            fault: IrqSpinLock::new(None),
            alive: AtomicBool::new(true),
        }
    }

    /// The thread id: the process id for the first thread.
    pub fn tid(&self) -> u32 {
        self.tid.load(Ordering::SeqCst)
    }

    /// The signals this thread blocks.
    pub fn signal_mask(&self) -> u64 {
        self.mask.load(Ordering::SeqCst)
    }

    /// The user thread pointer last set for it (`CLONE_SETTLS`, `arch_prctl`).
    pub fn tls(&self) -> u64 {
        self.tls.load(Ordering::SeqCst)
    }

    pub(crate) fn robust_list(&self) -> u64 {
        self.robust_list.load(Ordering::SeqCst)
    }

    pub(crate) fn set_robust_list(&self, head: u64) {
        self.robust_list.store(head, Ordering::SeqCst);
    }

    pub(crate) fn set_clear_tid(&self, addr: u64) {
        self.clear_tid.store(addr, Ordering::SeqCst);
    }

    pub(crate) fn set_fault(&self, sig: u8, addr: u64) {
        *self.fault.lock() = Some((sig, addr));
    }

    pub(crate) fn take_fault(&self, sig: u8) -> Option<u64> {
        let mut f = self.fault.lock();
        match *f {
            Some((s, addr)) if s == sig => f.take().map(|_| addr),
            _ => None,
        }
    }
}

/// The threads of a process, and how it is ending.
pub(crate) struct ThreadGroup {
    threads: IrqSpinLock<Vec<Arc<Thread>>>,
    /// Set once the whole process is ending: by `exit_group` or a fatal
    /// signal. Every thread then stops with this status.
    pub(crate) exiting: Once<ExitStatus>,
    /// Woken whenever a thread ends: `execve` waits for the others here.
    ended: WaitQueue,
}

impl ThreadGroup {
    pub(crate) fn new(pid: Pid) -> Self {
        Self {
            threads: IrqSpinLock::new(alloc::vec![Arc::new(Thread::new(pid.0, true))]),
            exiting: Once::new(),
            ended: WaitQueue::new(),
        }
    }

    pub(crate) fn leader(&self) -> Arc<Thread> {
        self.threads
            .lock()
            .iter()
            .find(|t| t.leader.load(Ordering::SeqCst))
            .expect("the leader is never removed")
            .clone()
    }

    pub(crate) fn find(&self, tid: u32) -> Option<Arc<Thread>> {
        self.threads.lock().iter().find(|t| t.tid() == tid).cloned()
    }

    /// Threads that have not exited.
    pub(crate) fn live(&self) -> usize {
        self.threads.lock().iter().filter(|t| t.alive.load(Ordering::SeqCst)).count()
    }

    pub(crate) fn reset_on_exec(&self) {
        for t in self.threads.lock().iter() {
            t.tls.store(0, Ordering::SeqCst);
            t.clear_tid.store(0, Ordering::SeqCst);
            t.robust_list.store(0, Ordering::SeqCst);
        }
    }
}

impl Process {
    /// The process's first thread, whose id is the process id.
    pub fn leader(&self) -> Arc<Thread> {
        self.group.leader()
    }

    /// The ids of the process's live threads.
    pub fn threads(&self) -> Vec<u32> {
        self.group.threads.lock().iter().filter(|t| t.alive.load(Ordering::SeqCst)).map(|t| t.tid()).collect()
    }
}

/// Non-leader threads by thread id; leaders are found by process id.
static TIDS: IrqSpinLock<BTreeMap<u32, Weak<Process>>> = IrqSpinLock::new(BTreeMap::new());

/// The live thread with id `tid` and its process.
pub(crate) fn find(tid: u32) -> Option<(Arc<Process>, Arc<Thread>)> {
    let p = Process::find(Pid(tid)).or_else(|| TIDS.lock().get(&tid)?.upgrade())?;
    let th = p.group.find(tid).filter(|t| t.alive.load(Ordering::SeqCst))?;
    Some((p, th))
}

/// The running thread of `p`, which must be the current task's process.
/// A new process's first task claims the leader thread the first time it
/// asks.
pub(crate) fn current_thread(p: &Process) -> Arc<Thread> {
    let id = osmium_sched::current().id().0 + 1;
    let threads = p.group.threads.lock();
    if let Some(t) = threads.iter().find(|t| t.task.load(Ordering::SeqCst) == id) {
        return t.clone();
    }
    let leader = threads.iter().find(|t| t.leader.load(Ordering::SeqCst)).expect("the leader is never removed");
    // The first thread's task is spawned before it can run and cannot be
    // named until then, so it is recognised by being the first to ask.
    let _ = leader.task.compare_exchange(0, id, Ordering::SeqCst, Ordering::SeqCst);
    leader.clone()
}

/// The thread pointer for the thread running `task`, if it is one of a
/// process's threads. For a kernel's switch hook on architectures where it
/// is not part of the trap frame (x86_64: load it into `FS.base`).
pub fn tls_for(task: &osmium_sched::Task) -> Option<u64> {
    let p = task.data::<Arc<Process>>()?;
    let id = task.id().0 + 1;
    let threads = p.group.threads.lock();
    threads.iter().find(|t| t.task.load(Ordering::SeqCst) == id).map(|t| t.tls())
}

mod flag {
    pub const EXIT_SIGNAL: u64 = 0xff;
    pub const VM: u64 = 0x100;
    pub const FS: u64 = 0x200;
    pub const FILES: u64 = 0x400;
    pub const SIGHAND: u64 = 0x800;
    pub const DETACHED: u64 = 0x40_0000;
    pub const THREAD: u64 = 0x1_0000;
    pub const SYSVSEM: u64 = 0x4_0000;
    pub const SETTLS: u64 = 0x8_0000;
    pub const PARENT_SETTID: u64 = 0x10_0000;
    pub const CHILD_CLEARTID: u64 = 0x20_0000;
    pub const CHILD_SETTID: u64 = 0x100_0000;
}

/// `clone`: a thread if `CLONE_THREAD` is set, otherwise a new process.
/// `args` is (stack, parent_tid, child_tid, tls).
pub(crate) fn clone(p: &Process, th: &Thread, flags: u64, args: [u64; 4]) -> Outcome {
    if flags & flag::THREAD == 0 {
        return forked(
            p,
            th,
            crate::syscall::outcome(crate::syscall::fork(p, flags, [args[0], args[1], args[2], args[3]])),
        );
    }
    crate::syscall::outcome(new_thread(p, th, flags, args))
}

/// What a forked child inherits from the calling thread: the signal
/// dispositions, mask and thread pointer.
pub(crate) fn forked(p: &Process, th: &Thread, outcome: Outcome) -> Outcome {
    if let Outcome::Fork { child, .. } = outcome
        && let Some(c) = Process::find(child)
    {
        c.signals.inherit_from(&p.signals);
        let leader = c.group.leader();
        leader.mask.store(th.signal_mask(), Ordering::SeqCst);
        leader.tls.store(th.tls(), Ordering::SeqCst);
    }
    outcome
}

/// `CLONE_THREAD`: registers the new thread and says how to start it. The
/// new thread has no task yet: spawn one (see `syscall::handle`).
fn new_thread(p: &Process, caller: &Thread, flags: u64, [stack, ptid, ctid, tls]: [u64; 4]) -> Result<Outcome, Errno> {
    use flag::*;
    const REQUIRED: u64 = VM | FS | FILES | SIGHAND | THREAD;
    const ALLOWED: u64 = REQUIRED | SYSVSEM | SETTLS | PARENT_SETTID | CHILD_CLEARTID | CHILD_SETTID | DETACHED;
    if flags & REQUIRED != REQUIRED || flags & !ALLOWED != 0 || flags & EXIT_SIGNAL != 0 || stack == 0 {
        return Err(Errno::EINVAL);
    }
    crate::exec::platform()?;
    // Fail before the thread exists, as `fork` does.
    for (f, va) in [(PARENT_SETTID, ptid), (CHILD_SETTID, ctid)] {
        if flags & f != 0 {
            let mut old = [0; 4];
            p.memory().read(va, &mut old)?;
            p.memory().write(va, &old)?;
        }
    }
    let me = Process::find(p.pid()).ok_or(ESRCH)?;
    let tid = crate::process::alloc_id();
    let th = Arc::new(Thread::new(tid, false));
    th.mask.store(caller.signal_mask(), Ordering::SeqCst);
    if flags & SETTLS != 0 {
        th.tls.store(tls, Ordering::SeqCst);
    }
    if flags & CHILD_CLEARTID != 0 {
        th.clear_tid.store(ctid, Ordering::SeqCst);
    }
    {
        let mut threads = p.group.threads.lock();
        // `doom_others` snapshots the list under this lock, so a thread added
        // after it would never be doomed and `execve` would wait for it forever.
        if caller.doomed.load(Ordering::SeqCst)
            || p.group.exiting.get().is_some()
            || threads.iter().any(|t| t.doomed.load(Ordering::SeqCst))
        {
            return Err(Errno::EINTR);
        }
        if threads.len() >= THREADS_MAX {
            return Err(Errno::EAGAIN);
        }
        threads.push(th);
    }
    TIDS.lock().insert(tid, Arc::downgrade(&me));
    let bytes = tid.to_ne_bytes();
    if flags & PARENT_SETTID != 0 {
        p.memory().write(ptid, &bytes)?;
    }
    if flags & CHILD_SETTID != 0 {
        p.memory().write(ctid, &bytes)?;
    }
    Ok(Outcome::Thread { tid, stack, tls: if flags & SETTLS != 0 { tls } else { 0 } })
}

/// Starts the thread `tid` made by `clone`: a new task in `p` that returns
/// to user mode with a copy of the caller's registers, a return value of 0,
/// and the new stack and thread pointer.
#[cfg(any(target_arch = "riscv64", target_arch = "aarch64", all(target_os = "none", target_arch = "x86_64")))]
pub(crate) fn start(
    p: &alloc::sync::Arc<Process>,
    tid: u32,
    frame: &mut osmium_arch::trap::TrapFrame,
    stack: u64,
    tls: u64,
) {
    use crate::uregs::UserRegs;
    let th = p.group.find(tid).expect("clone registered the thread");
    let mut regs = frame.clone();
    UserRegs::set_ret(&mut regs, 0);
    UserRegs::set_user_sp(&mut regs, stack);
    if tls != 0 {
        UserRegs::set_tls(&mut regs, tls);
    }
    let resume = crate::exec::platform().expect("clone needs a platform").resume;
    let fp = if osmium_arch::fp::enabled() {
        // SAFETY: a kernel that enables FP enables it on every CPU; the
        // registers are the caller's, still live.
        unsafe { osmium_arch::fp::FpState::capture() }
    } else {
        osmium_arch::fp::FpState::new()
    };
    // Threads share one CPU until unmapping shoots down TLBs elsewhere.
    let me = osmium_sched::current();
    let cpu = me.cpu();
    me.pin(cpu);
    drop(me);
    let t = th.clone();
    let task = p.spawn_with_fp(osmium_sched::TaskBuilder::new(p.name()).cpu(cpu), fp, move || {
        // The spawner records the task's id as soon as it has it.
        while t.task.load(Ordering::SeqCst) == 0 {
            osmium_sched::yield_now();
        }
        drop(t);
        resume(regs)
    });
    th.task.store(task.id().0 + 1, Ordering::SeqCst);
    UserRegs::set_ret(frame, tid as u64);
}

/// Ends the current thread of the current process, as [`crate::exit`] does.
pub(crate) fn exiting(p: &Process, status: ExitStatus) {
    let th = current_thread(p);
    exit_thread(p, &th, status);
}

/// `th` ends with `status`. A fatal signal or `exit_group` ends every
/// thread; otherwise the process ends with its last thread.
pub(crate) fn exit_thread(p: &Process, th: &Arc<Thread>, status: ExitStatus) {
    if matches!(status, ExitStatus::Signal(_)) {
        let _ = p.group.exiting.set(status);
    }
    let group_wide = p.group.exiting.get().copied();
    let status = group_wide.unwrap_or(status);
    crate::futex::exit_robust_list(p, th);
    // Wake whoever waits for this thread, as `pthread_join` does.
    let addr = th.clear_tid.swap(0, Ordering::SeqCst);
    if addr != 0 {
        let _ = p.memory().write(addr, &0u32.to_ne_bytes());
        crate::futex::wake(p.pid(), addr, 1);
    }
    let live = {
        let mut threads = p.group.threads.lock();
        th.alive.store(false, Ordering::SeqCst);
        if !th.leader.load(Ordering::SeqCst) {
            threads.retain(|t| !Arc::ptr_eq(t, th));
        }
        threads.iter().filter(|t| t.alive.load(Ordering::SeqCst)).count()
    };
    TIDS.lock().remove(&th.tid());
    p.group.ended.wake_all();
    if live == 0 {
        p.set_exited(status);
    } else if group_wide.is_some() {
        crate::signal::wake_blocked();
    }
}

/// `execve` from a thread of a multi-threaded process: ends every other
/// thread, waits until they are gone, and makes the caller the leader (it
/// takes the process id as its thread id). `EINTR` if the process is ending
/// anyway, or another thread's `execve` got there first.
pub(crate) fn exec_begin(p: &Process, th: &Thread) -> Result<(), Errno> {
    if !doom_others(p, th) {
        return Err(Errno::EINTR);
    }
    crate::signal::wake_blocked();
    p.child_exited.wake_all();
    p.group.ended.wait_until(|| {
        if th.doomed.load(Ordering::SeqCst) || p.group.exiting.get().is_some() {
            Some(Err(Errno::EINTR))
        } else if p.group.live() == 1 {
            Some(Ok(()))
        } else {
            None
        }
    })?;
    promote(p, th);
    Ok(())
}

/// Marks every thread but `th` to end, unless `th` was itself marked.
/// Returns whether it did.
pub(crate) fn doom_others(p: &Process, th: &Thread) -> bool {
    let threads = p.group.threads.lock();
    if th.doomed.load(Ordering::SeqCst) {
        return false;
    }
    for t in threads.iter().filter(|t| !core::ptr::eq(&***t, th)) {
        t.doomed.store(true, Ordering::SeqCst);
    }
    true
}

/// Makes `th`, the only live thread, the leader.
pub(crate) fn promote(p: &Process, th: &Thread) {
    let old = th.tid();
    let mut threads = p.group.threads.lock();
    if th.leader.load(Ordering::SeqCst) {
        return;
    }
    threads.retain(|t| core::ptr::eq(&**t, th));
    th.tid.store(p.pid().0, Ordering::SeqCst);
    th.leader.store(true, Ordering::SeqCst);
    drop(threads);
    TIDS.lock().remove(&old);
}

/// `exit_group`: ends every thread of `p`.
pub(crate) fn exit_group(p: &Process, status: ExitStatus) {
    crate::signal::kill_group(p, status);
}

/// `arch_prctl` (x86_64): the only call that sets `FS.base`.
#[cfg(target_arch = "x86_64")]
pub(crate) fn arch_prctl(p: &Process, th: &Thread, code: u64, addr: u64) -> Result<u64, Errno> {
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    match code {
        ARCH_SET_FS => {
            // Canonical user addresses only: a bad base would fault in the kernel.
            if addr >> 47 != 0 {
                return Err(Errno::EPERM);
            }
            th.tls.store(addr, Ordering::SeqCst);
            #[cfg(target_os = "none")]
            // SAFETY: a canonical user address; the base belongs to the running thread.
            unsafe {
                osmium_arch::x86_64::wrmsr(osmium_arch::x86_64::msr::IA32_FS_BASE, addr)
            };
            Ok(0)
        }
        ARCH_GET_FS => p.memory().write(addr, &th.tls().to_ne_bytes()).map(|()| 0),
        _ => Err(Errno::EINVAL),
    }
}
