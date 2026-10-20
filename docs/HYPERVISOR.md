# Building a hypervisor with osmium-virt

`osmium-virt` gives you the parts of a type-1 hypervisor and leaves the
policy to you: how many VMs, where their memory comes from, which devices
they see, what happens when they halt. The three `*-hyp` examples
(`examples/riscv-virt/src/hyp.rs`, `examples/aarch64-hyp`,
`examples/x86_64-hyp`) put the pieces together; this page explains them.
`examples/riscv-hyp`, and `examples/aarch64-hyp` and `examples/x86_64-hyp`
when QEMU's loader provides an image, go further and boot a whole kernel
from ELF with one vCPU per host CPU: Osmium's own `riscv-virt` (with a
virtio-blk disk and a virtio-net card bridged to the host's network card)
and `aarch64-virt` under a generated device tree, and `x86_64-pc` through
PVH with generated ACPI tables.

## The pieces

| Piece | What it does |
|---|---|
| `GuestMemory` | Guest-physical RAM as regions of host memory; bounds-checked `read`/`write`/`read_obj`/`write_obj` |
| Stage-2 tables (`stage2`) | Guest-physical to host-physical translation: `GStageTable` (RISC-V Sv39x4), `Stage2Table` (Arm), `EptTable`, or plain `X86_64` tables for AMD NPT; `map_guest_memory` maps a `GuestMemory` |
| `Bus` | MMIO and port-I/O address spaces of `BusDevice`s |
| `Vcpu` + `VmExit` | A backend runs guest code until the next exit, normalized into `MmioRead`, `MmioWrite`, `PioIn`, `PioOut`, `Hypercall`, `Halt`, `ExternalInterrupt`, `Shutdown` or `Unhandled` |
| `run_vcpu` | The loop: services MMIO and port I/O from the buses and hands every other exit to your closure |
| Devices (`devices`, `virtio`) | 16550 UART, PLIC, GICv2, 8259 PIC pair, 8254 PIT, local APIC; virtio-mmio console, block and net |

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
| Interrupt controller to emulate | `VirtualPlic` | `VirtualGicV2` | `VirtualPic`, or `VirtualLapic` per vCPU plus `VirtualIoApic` |
| Guest timer | Sstc `vstimecmp`, switched per vCPU | virtual timer; `connect_timer` feeds it to the GIC | `VirtualPit` on the PIC's IRQ 0, or the `VirtualLapic` timer; either driven by `poll` at its `next_deadline` |

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

`smp::GuestCpus` holds a guest's per-CPU start/stop state. Run each vCPU on
its own host CPU (a pinned task with `TaskBuilder::cpu`, or a dedicated
CPU loop), take start requests with `take_start`, and connect the vCPU
(`attach` on RISC-V, `attach_arm` on AArch64). Then:

- RISC-V: `riscv::sbi::handle_smp` implements SBI HSM, IPI (injected as
  `VSSIP`) and RFENCE. Created with `GuestCpus::with_kick`, an IPI or fence
  aimed at a vCPU that is running guest code on another host CPU interrupts
  that CPU so the vCPU exits and notices at once.
- AArch64: `aarch64::psci::handle_smp` implements `CPU_ON`, `CPU_OFF` and
  `AFFINITY_INFO`; build the GIC with `VirtualGicV2::with_cpus` and give
  each vCPU's bus its own `distributor_for`/`cpu_interface_for` views. SGIs
  between vCPUs go through the emulated `GICD_SGIR`. To deliver an
  interrupt to a vCPU running guest code on another host CPU at once,
  create the `GuestCpus` with `with_kick` (send that CPU a physical SGI;
  `HCR_EL2.IMO` makes it exit the guest), call `kick` from the GIC's output
  callback when a CPU's line rises, and acknowledge the SGI on the
  `ExternalInterrupt` exit.

- x86: guests start their APs the PC way, with INIT and STARTUP through
  `VirtualLapic` (decode the hook's ICR with `decode_icr`); start the AP's
  vCPU with `SvmVcpu::set_real_mode` and `set_application_processor`, and
  give each vCPU its APIC ID with `set_apic_id` so CPUID agrees. Kick as on
  the other architectures: `GuestCpus::with_kick` sends the host CPU a
  physical IPI, which exits the guest (the host runs with interrupts on, so
  `VMRUN` honours them), and `attach_svm` records where it runs.

## Describing the machine

`riscv::fdt::GuestMachine` writes a device tree for a RISC-V guest (harts,
memory, PLIC, UARTs, virtio-mmio slots) in the layout Linux expects from
QEMU `virt`; pass its address in `a1`. `aarch64::fdt::ArmMachine` does the
same for an AArch64 guest (PSCI over `hvc`, GICv2, timer, PL011s,
virtio-mmio); pass it in `x0`. On x86, `x86::pc::PcBoot` writes what a PVH
kernel boots from: the `hvm_start_info` (pass it in `ebx`), its memory map
and ACPI tables with a MADT; `x86::pc::pvh_entry` finds the kernel's
32-bit entry. `osmium_boot::fdt::FdtWriter` builds any other tree.

## Booting a whole kernel

The three `*-hyp` examples boot Osmium's own kernels as guests, and the
recipe is the same on each:

1. Allocate guest RAM, add it to a `GuestMemory`, and copy in each ELF
   segment (`osmium_boot::elf`) at its address, zeroing the rest of its
   memory size.
2. Write the machine description into guest RAM where the kernel expects
   it, and map the RAM in the second-stage table.
3. Put the devices on the buses at the addresses the description gives,
   wired to the interrupt controller, and the controller to each vCPU.
4. Start vCPU 0 at the entry with the boot register set (`a1`, `x0` or
   `ebx`), and the others when the guest asks (`GuestCpus`), one host CPU
   each.
5. Answer hypercalls (SBI, PSCI) and power-off, wait in `Halt` until
   `interrupt_pending`, and make a guest that never exits do so
   periodically (a host timer, or the timer PPI) so its timers and device
   interrupts arrive.

## Current limits

- x86 MMIO emulation decodes moves, `MOVZX` and `TEST`; without decode
  assists it walks 4-level (long-mode) guest page tables, or none; 32-bit
  paging is not walked. MSRs other than the syscall ones, EFER, PAT,
  `TSC_AUX` and `APIC_BASE` read as zero.
- No VMX backend (QEMU's TCG does not emulate VMX).
- FP/SIMD state is switched per vCPU on the assumption that the host
  kernel itself never uses those registers (soft-float targets): always on
  RISC-V and AArch64 (where SVE is not switched and traps), and on x86 for
  vCPUs built `with_fp_switching` (x87 and SSE through FXSAVE/FXRSTOR, not
  AVX). Without it an x86 guest uses the host CPU's registers as they are,
  which is enough for one vCPU per host CPU; the whole-kernel x86 guest runs
  that way because, under QEMU's multi-threaded TCG, switching around VMRUN
  made it take spurious page faults that single-threaded TCG never showed.
