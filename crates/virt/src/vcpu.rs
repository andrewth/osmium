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
