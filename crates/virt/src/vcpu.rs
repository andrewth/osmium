//! Virtual CPUs and exit handling.

use core::ops::ControlFlow;

use crate::bus::Bus;
use crate::memory::GuestPhysAddr;

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
    Hypercall {
        /// Call number.
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
#[cfg_attr(not(any(target_os = "none", target_arch = "aarch64", target_arch = "riscv64")), allow(dead_code))]
pub(crate) const NO_CPU: usize = usize::MAX;

/// Whether the translations cached on `cpu` may be stale for a vCPU about to
/// run there. The CPU's TLB is tagged with the guest's ASID/VMID/VPID, which
/// does not tell vCPUs apart (they may share a tag, and a new VM may reuse an
/// old one's), and a vCPU that ran elsewhere in between may have done local
/// invalidations that never reached `cpu`. So flush if the vCPU that last
/// ran on `cpu` was another (`last_on_cpu` against `this`), or if this vCPU
/// last ran on another CPU (`last_cpu` against `cpu`).
#[cfg_attr(not(any(target_os = "none", target_arch = "aarch64", target_arch = "riscv64")), allow(dead_code))]
pub(crate) fn tlb_may_be_stale<T: PartialEq>(last_on_cpu: T, this: T, last_cpu: usize, cpu: usize) -> bool {
    last_on_cpu != this || last_cpu != cpu
}

/// A virtual CPU that a hardware backend (VMX, SVM, EL2, H-extension)
/// implements.
pub trait Vcpu {
    /// Runs guest code until the next exit.
    fn run(&mut self) -> VmExit;

    /// Completes an [`VmExit::MmioRead`] or [`VmExit::PioIn`] with `value`,
    /// writing it to the destination register and advancing the guest.
    fn complete_read(&mut self, value: u64);

    /// Completes a [`VmExit::Hypercall`] with return value `ret`.
    fn complete_hypercall(&mut self, ret: u64);
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
                let _ = mmio.write(addr.0, &data.to_le_bytes()[..size.min(8) as usize]);
            }
            VmExit::PioIn { port, size } => {
                let v = read(pio, port as u64, size);
                vcpu.complete_read(v);
            }
            VmExit::PioOut { port, size, data } => {
                let _ = pio.write(port as u64, &data.to_le_bytes()[..size.min(4) as usize]);
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
    let _ = bus.read(addr, &mut buf[..n]);
    let mut out = [0u8; 8];
    out[..n].copy_from_slice(&buf[..n]);
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
