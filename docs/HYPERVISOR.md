# Building a hypervisor with osmium-virt

`osmium-virt` gives you the parts of a type-1 hypervisor and leaves the
policy to you: how many VMs, where their memory comes from, which devices
they see, what happens when they halt. The three `*-hyp` examples
(`examples/riscv-virt/src/hyp.rs`, `examples/aarch64-hyp`,
`examples/x86_64-hyp`) put the pieces together; this page explains them.

## The pieces

| Piece | What it does |
|---|---|
| `GuestMemory` | Guest-physical RAM as regions of host memory; bounds-checked `read`/`write`/`read_obj`/`write_obj` |
| Stage-2 tables (`stage2`) | Guest-physical to host-physical translation: `GStageTable` (RISC-V Sv39x4), `Stage2Table` (Arm), `EptTable`, or plain `X86_64` tables for AMD NPT; `map_guest_memory` maps a `GuestMemory` |
| `Bus` | MMIO and port-I/O address spaces of `BusDevice`s |
| `Vcpu` + `VmExit` | A backend runs guest code until the next exit, normalized into `MmioRead`, `MmioWrite`, `PioIn`, `PioOut`, `Hypercall`, `Halt`, `ExternalInterrupt`, `Shutdown` or `Unhandled` |
| `run_vcpu` | The loop: services MMIO and port I/O from the buses and hands every other exit to your closure |
| Devices (`devices`, `virtio`) | 16550 UART, PLIC, GICv2, 8259 PIC pair; virtio-mmio console, block and net |

## The run loop

```rust
let exit = run_vcpu(&mut vcpu, &mmio_bus, &pio_bus, |vcpu, exit| match exit {
    VmExit::Hypercall { .. } => /* SBI, PSCI or your own ABI */,
    VmExit::Halt => /* wait for vcpu.interrupt_pending(..), or yield the host CPU */,
    VmExit::ExternalInterrupt => ControlFlow::Continue(()), // the host already handled it
    other => ControlFlow::Break(other),
});
```

Device accesses never reach the closure. A read from an address no device
claims returns all ones; a write to one is dropped, as on real hardware.

## Backends

| | RISC-V (`riscv::RiscvVcpu`) | AArch64 (`aarch64::Aarch64Vcpu`) | x86 (`x86::SvmVcpu`) |
|---|---|---|---|
| Host runs in | HS-mode | EL2, non-VHE | long mode with SVM on |
| Feature | `riscv64-hs` (osmium-arch and osmium-virt) | `aarch64-el2` | none (bare-metal x86_64) |
| Guest entry/exit | `sret` / the trap entry's guest-exit hook | `eret` / lower-EL vectors 8-11 | `VMRUN` / `#VMEXIT` |
| Second stage | G-stage, `hgatp_sv39x4` | stage 2, `vttbr`; `init_cpu` sets `VTCR_EL2` | NPT, `X86_64` tables with `USER` leaves |
| MMIO exits from | guest-page faults, decoded from `htinst` or the instruction (`hlvx`) | data aborts with a valid syndrome | nested page faults, decoded by `x86::decode` |
| Hypercalls | `ecall` (SBI: `riscv::sbi`) | `hvc` (PSCI: `aarch64::psci`) | `vmmcall` |
| Interrupt input | `external_irq()` line, becomes `hvip.VSEIP` | `irq_line()`, becomes `HCR_EL2.VI` | `irq_line()` plus `connect_intr` (injected through `EVENTINJ`) |
| Interrupt controller to emulate | `VirtualPlic` | `VirtualGicV2` | `VirtualPic` |
| Guest timer | Sstc `vstimecmp`, switched per vCPU | virtual timer; `connect_timer` feeds it to the GIC | (none yet) |

Each backend saves the host's callee-saved registers, runs the guest, and
returns to the caller of `Vcpu::run` with interrupts restored. A host
interrupt that arrives while the guest runs exits with
`ExternalInterrupt`; the host takes it as soon as `run` returns.

## Interrupts: wiring a device to a guest

Devices have an output line (`Uart16550::with_irq`, `VirtioMmio::new`'s
`irq` callback). Connect it to an emulated interrupt controller's input,
and connect the controller's output to the vCPU:

```rust
let vcpu = RiscvVcpu::new(entry, hartid, dtb, hgatp);
let eip = vcpu.external_irq();
let plic = Arc::new(VirtualPlic::new(32, 2, move |ctx, level| {
    if ctx == 1 { eip.store(level, Ordering::Release) } // hart 0's S-mode context
}));
let p = plic.clone();
let uart = Uart16550::new(console).with_irq(move |level| p.set_level(10, level));
```

The guest programs the controller through MMIO (or ports, for the PIC)
exactly as on hardware; osmium's own `Plic`, `GicV2` and driver code works
unchanged inside a guest.

## Several vCPUs

On RISC-V, `riscv::harts::GuestHarts` holds a guest's per-hart state. Run
each vCPU in its own host task (pinned with `TaskBuilder::cpu`), take
start requests with `take_start`, connect each vCPU with `attach`, and
pass the harts to `sbi::handle_smp`, which implements SBI HSM, IPI and
RFENCE. Created with `GuestHarts::with_kick`, an IPI or fence aimed at a
vCPU that is running guest code on another host CPU interrupts that CPU so
the vCPU exits and notices at once.

## Describing the machine

`riscv::fdt::GuestMachine` writes a device tree for a RISC-V guest (harts,
memory, PLIC, UARTs, virtio-mmio slots) in the layout Linux expects from
QEMU `virt`; pass its address in `a1`. For other guests,
`osmium_boot::fdt::FdtWriter` builds any tree, and `osmium_boot::elf`
loads a kernel image.

## Current limits

- AArch64 and x86 guests are single-vCPU. x86 MMIO emulation without
  decode assists walks 4-level (long-mode) guest page tables, or none; 32-bit
  paging is not walked.
- No VMX backend (QEMU's TCG does not emulate VMX).
- AArch64 FP/SIMD registers are not switched; leave the guest's `CPACR_EL1`
  FP access off, or run one guest per CPU.
