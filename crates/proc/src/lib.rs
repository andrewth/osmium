//! Processes, user address spaces and a portable system-call layer.
//!
//! A [`Process`] is a user address space ([`UserMemory`], usually an
//! [`AddressSpace`]), a descriptor table of [`osmium_fs::File`]s, a working
//! directory and an exit status, attached to the task that runs it. System
//! calls use each architecture's Linux numbers, registers and structure
//! layouts, so ordinary statically linked programs can run, and are handled
//! by one portable [`dispatch`]:
//!
//! ```ignore
//! fn on_trap(frame: &mut TrapFrame) {
//!     if frame.from_user() && frame.cause() == Trap::Syscall {
//!         if let Some(status) = osmium_proc::syscall::handle(frame) {
//!             osmium_proc::exit(status);
//!         }
//!         return;
//!     }
//!     // ...
//! }
//!
//! fn on_switch(next: &Task) {
//!     let root = osmium_proc::root_for(next).unwrap_or(KERNEL_ROOT);
//!     // ... load satp / TTBR0 / CR3 with `root` ...
//! }
//!
//! fn spawn(image: &[u8]) -> Arc<Task> {
//!     let elf = Elf::new(image).unwrap();
//!     // SAFETY: the kernel table lives for the whole run.
//!     let space = unsafe { AddressSpace::new(&FRAMES, &KERNEL_PT, 0..1) }.unwrap();
//!     let brk = space.load_elf(&elf).unwrap();
//!     space.map_anon(STACK_TOP - STACK_LEN, STACK_LEN, MapFlags::RW).unwrap();
//!     let entry = elf.entry();
//!     let p = Process::new("init", space, brk);
//!     p.spawn(TaskBuilder::new("init"), move || unsafe { enter_user(entry, STACK_TOP) })
//! }
//! ```
//!
//! # Integration points
//!
//! - [`set_console`] gives every new process descriptors 0, 1 and 2, and
//!   [`set_vfs`] the namespace that `openat` and friends resolve paths in.
//! - Copies to and from user memory walk the process's own page table and
//!   go through the frame allocator's physical mapping, so the kernel needs
//!   no SUM, PAN or SMAP handling for system calls.
//! - A process is freed when its task has exited and its CPU has switched
//!   away; until then its address space may still be active.
//!
//! - [`set_platform`] enables `fork` and `execve`: it tells them how to make
//!   and activate address spaces, how to resume a forked child in user mode
//!   (`resume_user` in `osmium_arch::riscv64` / `aarch64`), and where a new
//!   program's stack and `mmap` area go.
//!
//! A process is a group of [`Thread`]s, each with its own task: `clone` makes
//! processes (`fork`, `vfork`) or, with `CLONE_THREAD`, threads (see
//! [`thread`]), and [`signal`] delivers signals to user handlers. Forked
//! memory is shared copy-on-write: a trap handler passes user write faults to
//! [`handle_page_fault`] before raising a signal, and copies to user memory
//! break the sharing themselves. `execve` loads static, non-PIE ELF
//! executables only.
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod exec;
pub mod fd;
mod futex;
mod memory;
mod process;
pub mod signal;
pub mod syscall;
pub mod net;
pub mod socket;
pub mod thread;
mod uregs;

pub use exec::{ARG_MAX, Platform, UserEntry, set_platform};
pub use fd::{FdTable, OpenFile, set_console};
pub use memory::{AddressSpace, UserMemory};
pub use process::{ExitStatus, Pid, Process, current, exit, handle_page_fault, root_for};
pub use syscall::{Outcome, Sys, dispatch, dispatch_as};
pub use thread::Thread;

use osmium_fs::Vfs;
use osmium_sync::Once;

static VFS: Once<&'static Vfs> = Once::new();

/// Sets the namespace that path-based system calls resolve in. Without one
/// they fail with `ENOENT`. Panics if called twice.
pub fn set_vfs(vfs: &'static Vfs) {
    assert!(VFS.set(vfs).is_ok(), "VFS already set");
}

pub(crate) fn vfs() -> Option<&'static Vfs> {
    VFS.get().copied()
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod net_tests;
