// SPDX-License-Identifier: GPL-2.0-only
//! Virtual CPUs and exit handling.

use alloc::sync::Arc;
use core::ops::ControlFlow;
use core::sync::atomic::AtomicBool;

use crate::bus::Bus;
use crate::memory::GuestPhysAddr;
use crate::smp::CpuLink;

/// Why a virtual CPU stopped running guest code, independent of the
/// virtualization extension that reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmExit {
    /// The guest read `size` bytes of unbacked guest-physical memory. Supply
    /// the value with [`Vcpu::complete_read`].
    MmioRead {
        /// Address accessed.
        addr: GuestPhysAddr,
        /// Access size in bytes.
        size: u8,
    },
    /// The guest wrote `data` (low `size` bytes) to unbacked memory.
    MmioWrite {
        /// Address accessed.
        addr: GuestPhysAddr,
        /// Access size in bytes.
        size: u8,
        /// Value written.
        data: u64,
    },
    /// The guest executed `IN`. Supply the value with [`Vcpu::complete_read`].
    PioIn {
        /// Port accessed.
        port: u16,
        /// Access size in bytes.
        size: u8,
    },
    /// The guest executed `OUT`.
    PioOut {
        /// Port accessed.
        port: u16,
        /// Access size in bytes.
        size: u8,
        /// Value written.
        data: u32,
    },
    /// The guest made a hypercall (VMCALL, HVC, SBI ecall).
    ///
    /// `nr` follows each architecture's calling convention, so a host that
    /// serves several backends decodes it per backend:
    ///
    /// | Backend | `nr` | `args` |
    /// |---|---|---|
    /// | x86 (SVM `VMMCALL`, VMX `VMCALL`) | `rax` | `rbx`, `rcx`, `rdx`, `rsi`, `rdi`, `r8` |
    /// | AArch64 (`HVC`, trapped `SMC`) | `x0`, the SMCCC function ID | `x1`..`x6` |
    /// | RISC-V (`ecall`) | SBI EID (`a7`) in bits 31:0, FID (`a6`) in bits 63:32 | `a0`..`a5` |
    Hypercall {
        /// Call number (see above).
        nr: u64,
        /// Arguments.
        args: [u64; 6],
    },
    /// The guest halted (HLT, WFI) and waits for an interrupt.
    Halt,
    /// A host interrupt arrived while the guest ran.
    ExternalInterrupt,
    /// The guest powered off or reset.
    Shutdown,
    /// An exit this layer does not model, with the raw reason code.
    Unhandled {
        /// Architecture-specific reason.
        reason: u64,
    },
}

/// A fresh, never reused identity for a vCPU: a CPU that runs a vCPU with
/// a different identity than last time flushes its stage-2 translations, so
/// a new VM that happens to get an old one's VMID and table root never sees
/// its stale TLB entries.
pub(crate) fn new_vcpu_id() -> u64 {
    static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// "No CPU yet": the initial value of a vCPU's last-run CPU.
pub(crate) const NO_CPU: usize = usize::MAX;

/// Whether the translations cached on `cpu` may be stale for a vCPU about to
/// run there. The CPU's TLB is tagged with the guest's ASID/VMID/VPID, which
/// does not tell vCPUs apart (they may share a tag, and a new VM may reuse an
/// old one's), and a vCPU that ran elsewhere in between may have done local
/// invalidations that never reached `cpu`. So flush if the vCPU that last
/// ran on `cpu` was another (`last_on_cpu` against `this`), or if this vCPU
/// last ran on another CPU (`last_cpu` against `cpu`).
///
/// Only the world switches use it: SVM's on bare-metal x86_64, the AArch64
/// one (`aarch64_hw`) and the RISC-V one (`riscv64-hs`).
#[cfg_attr(
    not(any(
        test,
        all(target_arch = "x86_64", target_os = "none"),
        aarch64_hw,
        all(target_arch = "riscv64", feature = "riscv64-hs")
    )),
    allow(dead_code)
)]
pub(crate) fn tlb_may_be_stale<T: PartialEq>(last_on_cpu: T, this: T, last_cpu: usize, cpu: usize) -> bool {
    last_on_cpu != this || last_cpu != cpu
}

/// A virtual CPU that a hardware backend (VMX, SVM, EL2, H-extension)
/// implements.
///
/// The trait covers what a backend-generic host loop needs: running the
/// guest, completing the exits [`run_vcpu`] does not finish itself, waking a
/// halted vCPU, flushing stage-2 translations after the tables change, the
/// interrupt line a controller model drives, and the link to the guest's
/// [`GuestCpus`](crate::smp::GuestCpus) (made by
/// [`GuestCpus::attach`](crate::smp::GuestCpus::attach)). Setup (entry state,
/// memory, interrupt-controller attachments) stays with each backend's own
/// constructor and builder methods.
pub trait Vcpu {
    /// Runs guest code until the next exit.
    fn run(&mut self) -> VmExit;

    /// Completes an [`VmExit::MmioRead`] or [`VmExit::PioIn`] with `value`,
    /// writing it to the destination register and advancing the guest.
    fn complete_read(&mut self, value: u64);

    /// Completes a [`VmExit::Hypercall`] with return value `ret`.
    fn complete_hypercall(&mut self, ret: u64);

    /// Whether a vCPU that exited with [`VmExit::Halt`] has a reason to run
    /// again: an interrupt it can take is pending. `now` is the clock the
    /// guest's own timer compares against (the counter on AArch64, the
    /// `time` CSR on RISC-V); x86 vCPUs, whose timers are device models that
    /// raise the interrupt line, ignore it.
    fn interrupt_pending(&self, now: u64) -> bool;

    /// Arranges for the guest's cached stage-2 translations to be flushed
    /// before the next entry. Call it after editing the guest's stage-2
    /// tables (unmapping a page or reducing its permissions).
    fn flush_stage2(&mut self);

    /// The vCPU's interrupt line, for an interrupt-controller model to drive:
    /// INTR on x86, the IRQ line (`HCR_EL2.VI`) on AArch64, the supervisor
    /// external interrupt (`hvip.VSEIP`) on RISC-V.
    fn irq_line(&self) -> Arc<AtomicBool>;

    /// Connects the vCPU to its slot of a [`GuestCpus`](crate::smp::GuestCpus):
    /// the record of which host CPU runs it (for kicks) and, on backends that
    /// use them, the slot's IPI and remote-fence lines. Called by
    /// [`GuestCpus::attach`](crate::smp::GuestCpus::attach).
    fn connect_cpu(&mut self, link: CpuLink);
}

/// Runs `vcpu`, servicing device exits from `mmio` and `pio`, and passes
/// every other exit to `handle`, which decides whether to continue.
///
/// Reads from addresses no device claims return all ones, as on real
/// hardware with nothing decoding the address; writes to them are dropped.
pub fn run_vcpu<V: Vcpu + ?Sized>(
    vcpu: &mut V,
    mmio: &Bus,
    pio: &Bus,
    mut handle: impl FnMut(&mut V, VmExit) -> ControlFlow<VmExit>,
) -> VmExit {
    loop {
        match vcpu.run() {
            VmExit::MmioRead { addr, size } => {
                let v = read(mmio, addr.0, size);
                vcpu.complete_read(v);
            }
            VmExit::MmioWrite { addr, size, data } => {
                let _ = mmio.write(addr.0, data.to_le_bytes().get(..size.min(8) as usize).unwrap_or_default());
            }
            VmExit::PioIn { port, size } => {
                let v = read(pio, port as u64, size);
                vcpu.complete_read(v);
            }
            VmExit::PioOut { port, size, data } => {
                let _ = pio.write(port as u64, data.to_le_bytes().get(..size.min(4) as usize).unwrap_or_default());
            }
            other => {
                if let ControlFlow::Break(e) = handle(vcpu, other) {
                    return e;
                }
            }
        }
    }
}

fn read(bus: &Bus, addr: u64, size: u8) -> u64 {
    let n = size.clamp(1, 8) as usize;
    let mut buf = [0xffu8; 8];
    let _ = bus.read(addr, buf.get_mut(..n).unwrap_or_default());
    let mut out = [0u8; 8];
    for (o, b) in out.iter_mut().zip(&buf).take(n) {
        *o = *b;
    }
    u64::from_le_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrating_vcpu_flushes_even_if_it_was_the_last_one_here() {
        // First run anywhere.
        assert!(tlb_may_be_stale(0, 7, NO_CPU, 0));
        // Same vCPU, same CPU: keep the TLB.
        assert!(!tlb_may_be_stale(7, 7, 0, 0));
        // Another vCPU ran here since.
        assert!(tlb_may_be_stale(8, 7, 0, 0));
        // vCPU 7 ran on CPU 1 meanwhile (and may have flushed locally there),
        // and nothing else ran on CPU 0: its entries on CPU 0 are stale.
        assert!(tlb_may_be_stale(7, 7, 1, 0));
    }
}
