// SPDX-License-Identifier: GPL-2.0-only
//! What the example hypervisors share: a console for guests' UARTs, guest
//! images placed by QEMU's loader or linked into the host, and the
//! bookkeeping of a guest whose vCPUs run on several host CPUs.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use osmium::boot::elf::Elf;
use osmium::hal::println;
use osmium::sync::IrqSpinLock;
use osmium::virt::VmExit;
use osmium::virt::smp::GuestCpus;

/// A guest UART's output: bytes are collected into lines (carriage returns
/// dropped) and each line is printed whole, after `prefix` (`"| "` sets a
/// guest kernel's log apart from the host's), so lines from several vCPUs
/// do not interleave. `on_line` sees each line first.
pub fn console_with(prefix: &'static str, on_line: fn(&str)) -> impl Fn(u8) + Clone + Send + Sync + 'static {
    let line = Arc::new(IrqSpinLock::new(Vec::new()));
    move |b| {
        let mut l = line.lock();
        match b {
            b'\n' => {
                let s = core::str::from_utf8(&l).unwrap_or("?");
                on_line(s);
                println!("{prefix}{s}");
                l.clear();
            }
            b'\r' => {}
            _ => l.push(b),
        }
    }
}

/// [`console_with`] without a hook.
pub fn console(prefix: &'static str) -> impl Fn(u8) + Clone + Send + Sync + 'static {
    console_with(prefix, |_| {})
}

/// The bytes between two linker symbols, such as a guest image in the
/// host's `.rodata`.
///
/// # Safety
/// `start..end` must bound initialised data that is never written.
pub unsafe fn image(start: &'static u8, end: &'static u8) -> &'static [u8] {
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts(start, (end as *const u8).offset_from(start) as usize) }
}

/// The ELF image in `base..base + len`, where QEMU's loader puts a guest
/// kernel (`-device loader,file=...,addr=...,force-raw=on`), if there is one.
///
/// # Safety
/// The window must be RAM that nothing else uses or writes (the loader
/// filled it or left it zero) for as long as the image is in use.
pub unsafe fn loaded_elf(base: u64, len: u64) -> Option<Elf<'static>> {
    // SAFETY: the caller's contract.
    let window = unsafe { core::slice::from_raw_parts(base as *const u8, len as usize) };
    Elf::new(window).ok()
}

/// How one start of a vCPU ended, for [`GuestRun::vcpu_loop`].
pub enum Ran {
    /// The guest stopped the vCPU (PSCI `CPU_OFF`, SBI `hart_stop`): run it
    /// again when the guest starts it again.
    Stopped,
    /// The vCPU exited for good.
    Exited {
        /// Why it exited.
        exit: VmExit,
        /// The guest address it exited at, if known.
        pc: Option<u64>,
    },
}

/// A guest whose vCPUs each run on a host CPU of their own: whether it is
/// done, and how many vCPU loops have not returned yet.
pub struct GuestRun {
    done: AtomicBool,
    running: AtomicUsize,
    vcpus: usize,
}

impl GuestRun {
    /// A guest with `vcpus` vCPUs, numbered from 0, each to be run by
    /// [`vcpu_loop`](Self::vcpu_loop) on its own host CPU.
    pub const fn new(vcpus: usize) -> Self {
        Self { done: AtomicBool::new(false), running: AtomicUsize::new(vcpus), vcpus }
    }

    /// How many vCPUs the guest has.
    pub fn vcpus(&self) -> usize {
        self.vcpus
    }

    /// Whether a vCPU (or [`end`](Self::end)) has ended the guest.
    pub fn done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Ends the guest from outside its vCPU loops, as an emulated power-off
    /// register does. The loops see it at their next exit; kick vCPUs that
    /// may be in guest code.
    pub fn end(&self) {
        self.done.store(true, Ordering::Release);
    }

    /// Runs vCPU `me` each time the guest starts it (`cpus` says when, with
    /// its entry point and context), with `run`, until some vCPU ends the
    /// guest. The vCPU that does gets the others out of guest code. Returns
    /// the exit that ended the guest, if it was this vCPU's.
    ///
    /// A host CPU without a vCPU of this guest (`me` past the last one)
    /// returns at once.
    pub fn vcpu_loop(&self, cpus: &GuestCpus, me: usize, mut run: impl FnMut(u64, u64) -> Ran) -> Option<VmExit> {
        if me >= self.vcpus {
            return None;
        }
        let mut last = None;
        while !self.done() {
            let Some((entry, context)) = cpus.take_start(me) else {
                core::hint::spin_loop();
                continue;
            };
            let Ran::Exited { exit, pc } = run(entry, context) else { continue };
            if !self.done.swap(true, Ordering::AcqRel) {
                (0..self.vcpus).for_each(|i| cpus.kick(i));
                if exit != VmExit::Shutdown {
                    match pc {
                        Some(pc) => println!("[hyp]   vCPU {me} stopped the guest: {exit:?} at pc {pc:#x}"),
                        None => println!("[hyp]   vCPU {me} stopped the guest: {exit:?}"),
                    }
                }
                last = Some(exit);
            }
        }
        self.running.fetch_sub(1, Ordering::AcqRel);
        last
    }

    /// Waits until every vCPU loop has returned.
    pub fn wait_all(&self) {
        while self.running.load(Ordering::Acquire) > 0 {
            core::hint::spin_loop();
        }
    }
}
