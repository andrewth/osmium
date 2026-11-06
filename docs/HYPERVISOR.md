# Building a hypervisor with osmium-virt

`osmium-virt` gives you the parts of a type-1 hypervisor and leaves the
policy to you: how many VMs, where their memory comes from, which devices
they see, what happens when they halt. The three `*-hyp` examples
(`examples/riscv-hyp`, `examples/aarch64-hyp`, `examples/x86_64-hyp`) put
the pieces together; this page explains them. `examples/aarch64-vhe` is a
smaller one for an AArch64 VHE host, and `examples/riscv-virt` runs small
H-extension guests of its own (`src/hyp.rs`). The `*-hyp` examples run small
demo guests and, when QEMU's loader provides an image, boot a whole kernel
from ELF with one vCPU per host CPU: osmium's own `riscv-virt` (with a
virtio-blk disk and a virtio-net card bridged to the host's network card)
and `aarch64-virt` under a generated device tree, and `x86_64-pc` through
PVH with generated ACPI tables. Their shared plumbing (guest consoles,
images, the per-CPU run loop of a multi-vCPU guest) is in
`examples/demos/src/guest.rs`.

## The pieces

| Piece | What it does |
|---|---|
| `GuestMemory` | Guest-physical RAM as regions of host memory (`add_region`); bounds-checked `read`/`write`/`read_obj`/`write_obj`, and `load_elf` for a kernel image |
| Stage-2 tables (`stage2`) | Guest-physical to host-physical translation: `GStageTable` (RISC-V Sv39x4) or `GStage48Table` (Sv48x4), `Stage2Table` (Arm), `EptTable` (Intel), or plain `X86_64` tables for AMD NPT; `map_guest_memory` maps a `GuestMemory`; `hgatp_sv39x4`, `vttbr` and `eptp` encode the root |
| `Bus` | MMIO and port-I/O address spaces of `BusDevice`s |
| `Vcpu` + `VmExit` | A backend runs guest code until the next exit, normalized into `MmioRead`, `MmioWrite`, `PioIn`, `PioOut`, `Hypercall`, `Halt`, `ExternalInterrupt`, `Shutdown` or `Unhandled` (methods below) |
| `run_vcpu` | The loop: services MMIO and port I/O from the buses and hands every other exit to your closure |
| Devices (`devices`, `virtio`) | 16550 UART (`Uart16550`), PL011 UART (`Pl011`), PLIC, APLIC and IMSIC, GICv2, GICv3 (no LPIs or ITS in the model; GICv4 virtual LPIs go through the host's ITS, below), 8259 PIC pair, 8254 PIT, local APIC (`VirtualLapic`), I/O APIC (`VirtualIoApic`); virtio-mmio (`VirtioMmio`) console, block and net |

## The run loop

```rust
let exit = run_vcpu(&mut vcpu, &mmio_bus, &pio_bus, |vcpu, exit| match exit {
    VmExit::Hypercall { nr, args } => {
        vcpu.complete_hypercall(my_abi(nr, args)); // or riscv::sbi / aarch64::psci
        ControlFlow::Continue(())
    }
    VmExit::Halt => {
        while !vcpu.interrupt_pending(now()) { /* wait, or yield the host CPU */ }
        ControlFlow::Continue(())
    }
    VmExit::ExternalInterrupt => ControlFlow::Continue(()), // the host already handled it
    other => ControlFlow::Break(other),
});
```

Device accesses never reach the closure. A read from an address no device
claims returns all ones; a write to one is dropped, as on real hardware.

## Backends

| | RISC-V (`riscv::RiscvVcpu`) | AArch64 (`aarch64::Aarch64Vcpu`) | AMD (`x86::svm::SvmVcpu`) | Intel (`x86::vmx::VmxVcpu`) |
|---|---|---|---|---|
| Host runs in | HS-mode | EL2, non-VHE or VHE | long mode with SVM on (`svm::enable`) | long mode in VMX root operation (`vmx::enable`) |
| Feature | `riscv64-hs` (osmium-arch and osmium-virt) | `aarch64-el2` (non-VHE) or `aarch64-vhe` (VHE) | none (bare-metal x86_64) | none (bare-metal x86_64) |
| Guest entry/exit | `sret` / the trap entry's guest-exit hook | `eret` / lower-EL vectors 8-11 | `VMRUN` / `#VMEXIT` | `VMLAUNCH` or `VMRESUME` / VM exit |
| Second stage | G-stage, `hgatp_sv39x4` | stage 2, `vttbr`; `init_cpu` sets `VTCR_EL2` | NPT, `X86_64` tables with `USER` leaves | EPT, `EptTable` and `eptp`; VPID |
| MMIO exits from | guest-page faults, decoded from `htinst` or the instruction (`hlvx`) | data aborts with a valid syndrome | nested page faults, decoded by `x86::decode` | EPT violations, decoded by `x86::decode` |
| Hypercalls | `ecall` (SBI: `riscv::sbi`) | `hvc` (PSCI: `aarch64::psci`) | `vmmcall` | `vmcall` |
| Interrupt input | `external_irq()` (the same line as `irq_line()`), becomes `hvip.VSEIP` | `irq_line()`, becomes `HCR_EL2.VI` | `irq_line()` plus `connect_intr` or `connect_lapic` (injected through `EVENTINJ`) | `irq_line()` plus `connect_intr` or `connect_lapic` (injected through the VM-entry interruption field) |
| Interrupt controller to emulate | `VirtualPlic`, or `VirtualAplic` + `VirtualImsic` | `VirtualGicV2`, or `VirtualGicV3` | `VirtualPic`, or `VirtualLapic` per vCPU plus `VirtualIoApic` | as SVM |
| Guest timer | Sstc `vstimecmp`, switched per vCPU | virtual timer; `connect_timer` feeds it to the GIC | `VirtualPit` on the PIC's IRQ 0, or the `VirtualLapic` timer; either driven by `poll` at its `next_deadline` | as SVM |

Each backend saves the host's callee-saved registers, runs the guest, and
returns to the caller of `Vcpu::run` with interrupts restored. A host
interrupt that arrives while the guest runs exits with
`ExternalInterrupt`; the host takes it as soon as `run` returns.

The `Vcpu` trait is what a backend-generic host loop needs:

| Method | What it does |
|---|---|
| `run(&mut self) -> VmExit` | Runs guest code until the next exit |
| `complete_read(&mut self, value: u64)` | Finishes an `MmioRead` or `PioIn` (`run_vcpu` calls it) |
| `complete_hypercall(&mut self, ret: u64)` | Finishes a `Hypercall` with its return value |
| `interrupt_pending(&self, now: u64) -> bool` | Whether a halted vCPU has an interrupt it can take; `now` is the clock the guest's timer compares against (the counter on AArch64, `time` on RISC-V; ignored on x86) |
| `flush_stage2(&mut self)` | Flushes the guest's cached stage-2 translations before the next entry; call it after unmapping a page or reducing its permissions |
| `irq_line(&self) -> Arc<AtomicBool>` | The vCPU's interrupt line, for a controller model to drive: INTR on x86, `HCR_EL2.VI` on AArch64, `hvip.VSEIP` on RISC-V |
| `connect_cpu(&mut self, link: CpuLink)` | Links the vCPU to its `GuestCpus` slot; `GuestCpus::attach` calls it |

Entry state, guest memory (`with_memory`) and interrupt-controller
attachments stay with each backend's constructor and builder methods.
Given its guest memory with `with_memory`, every backend reports a
second-stage fault on an address inside guest RAM (a permission fault, or
a fault in the guest's own page-table walk) as `Unhandled`, not as MMIO.

### AArch64 VHE hosts

A host that runs at EL2 with `HCR_EL2.E2H` set (VHE) builds with
`aarch64-vhe` instead of `aarch64-el2`. The two are mutually exclusive
(`aarch64-el2` wins if both are on). Such a host is an ordinary EL1 kernel as
far as `osmium-arch` is concerned: VHE redirects the `_EL1` register names
it uses to EL2, it can run user programs at EL0, and its lower-EL vectors take
both their traps and guest exits (a hook sends an exception to the vCPU when
one is running on that CPU, as with `riscv64-hs`). The host must:

1. Set `HCR_EL2` to at least `E2H | TGE | RW` (`aarch64::HCR_E2H`,
   `HCR_TGE`, bit 31) before `cpu::set_current_id` and `trap::install`. With
   `aarch64-vhe` those use `TPIDR_EL2` and `VBAR_EL2`: VHE does not
   redirect `TPIDR_EL1`, which the guest owns.
2. Program its stage 1 through the EL1 names (`TCR_EL1` layout, `T1SZ` and
   `EPD1` included), with the EL1 page-table format
   (`osmium_mm::paging::formats::Aarch64`), since the EL2&0 regime has EL0
   permissions.
3. Optionally call `aarch64::init_cpu` (`VTCR_EL2`, `VPIDR_EL2`,
   `CNTVOFF_EL2`); `run` does it on a CPU that has not been prepared.

`Aarch64Vcpu::new(entry, x0, vttbr(root, vmid))` and the rest of the API are
the same as without VHE. Each `run` masks interrupts, saves the host's
`HCR_EL2` and sets `HCR_GUEST | E2H` (TGE clear), switches the guest's EL1
registers through `SCTLR_EL12`, `TTBR0_EL12`, `VBAR_EL12` and the like, and on
exit puts back the host's `HCR_EL2` (so `TGE` is set again), `CPTR_EL2`,
`MDCR_EL2`, `TPIDR_EL0`, `PAR_EL1`, `CSSELR_EL1` and, if `CPTR_EL2.FPEN` let
the host use them, its FP/SIMD registers. `CNTHCTL_EL2`'s EL1 bits (10 and 11
with `E2H`) are set on each entry, leaving the host's EL0 bits alone.

## Interrupts: wiring a device to a guest

Devices have an output line (`Uart16550::with_irq`, `Pl011::with_irq`,
`VirtioMmio::new`'s `irq` callback). Connect it to an emulated interrupt controller's input,
and connect the controller's output to the vCPU:

```rust
let vcpu = RiscvVcpu::new(entry, HartId(hartid), dtb, hgatp);
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
with `GuestCpus::attach(cpu, &mut vcpu)` (any backend). Then:

- RISC-V: `riscv::sbi::handle_smp` implements SBI HSM, IPI (injected as
  `VSSIP`) and RFENCE (`riscv::harts::GuestHarts` is `GuestCpus` under its
  RISC-V name). Created with `GuestCpus::with_kick`, an IPI or fence
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
  vCPU with `set_real_mode` and `set_application_processor` (on `SvmVcpu`
  or `VmxVcpu`), and give each vCPU its APIC ID with `set_apic_id` so CPUID
  agrees. Kick as on the other architectures: `GuestCpus::with_kick` sends
  the host CPU a physical IPI, which exits the guest with
  `ExternalInterrupt`, and `GuestCpus::attach` records where each vCPU
  runs.

## Advanced interrupt controllers

**GICv3** (`devices::VirtualGicV3`). Distributor and redistributors in
software; one distributor view and one redistributor region for every vCPU's
bus. The guest's CPU interface is the *host's* virtual one (`ICV_*` through
`HCR_EL2.IMO`), so this needs a GICv3 host with `ICC_SRE_EL2.Enable` (the
`osmium-drivers` `GicV3::init_cpu(true)` does that). Attach a vCPU with
`Aarch64Vcpu::with_vgic_v3(gic, cpu)`: around every run it loads the GIC's
pending interrupts into `ICH_LR<n>_EL2` and reads the acknowledged and
completed state back (`fill_list_registers` / `sync_list_registers`); guest
`ICC_SGI1R_EL1` writes trap and call `send_sgi`; the guest's `MPIDR_EL1` is
`vcpu_mpidr(cpu)` so it finds its redistributor by affinity. Not modeled:
LPIs and the ITS (see GICv4 below), message-based SPIs, and the
GICv2-compatibility mode. If more interrupts are pending than list registers, the rest wait for
the next exit; the vCPU asks for a maintenance interrupt
(`ICH_HCR_EL2.UIE`), which only helps if the host enables that PPI.
`ArmGic::V3` in the device-tree writer describes it to a guest.

**GICv4 virtual LPIs** (`osmium_sysdrv::gicv3::v4`). On a GICv4 host a
guest's LPIs need no model: the host's ITS delivers them. The hypervisor
gives each vCPU a vPE (`Vpe`, its virtual pending table, mapped with
`Its::map_vpe`, `VMAPP`) and the VM a virtual LPI property table
(`VlpiTables`), maps device events to virtual LPIs with
`Its::map_virtual_event` (`VMAPTI`), and makes the vPE resident on its
redistributor around guest runs (`GicV3::make_vpe_resident` and
`make_vpe_nonresident`; `Its::move_vpe` follows a vCPU to another CPU).
While it is resident the guest acknowledges the virtual LPI through its CPU
interface with no list register and no exit; while it is not, the ITS
raises the event's doorbell, a physical LPI the hypervisor chose.
`examples/aarch64-hyp/src/vlpi.rs` runs this under QEMU
`-machine virt,virtualization=on,gic-version=4`. GICv4.1 (vSGIs) is not
implemented.

**APLIC and IMSIC** (`devices::VirtualAplic`, `VirtualImsic`). One APLIC
domain, in MSI or direct delivery mode, forwarding messages through a
callback to the IMSIC interrupt files (one per hart); the IMSIC reports each
hart's external-interrupt line, wired to `RiscvVcpu::external_irq`. The
guest's `siselect` is the VS CSR, but `sireg` and `stopei` raise
virtual-instruction traps because the host has no guest interrupt file
(`hstatus.VGEIN` = 0); `RiscvVcpu::with_imsic` completes them against the
model. The host needs Ssaia (QEMU `-cpu rv64,ssaia=true`) and calls
`riscv::enable_aia` per hart. Not modeled: machine-level domains and
delegation, guest interrupt files (`hgeip`) for nested guests, and wired
sources in a second domain. `riscv::fdt::Aia` adds the `riscv,aplic` and
`riscv,imsics` nodes to a guest's device tree.

## Describing the machine

`riscv::fdt::GuestMachine` writes a device tree for a RISC-V guest (harts,
memory, PLIC or APLIC and IMSIC, UARTs, virtio-mmio slots) in the layout Linux expects from
QEMU `virt`; pass its address in `a1`. `aarch64::fdt::ArmMachine` does the
same for an AArch64 guest (PSCI over `hvc`, GICv2 or GICv3, timer, PL011s,
virtio-mmio); pass it in `x0`. On x86, `x86::pc::PcBoot::build` writes what
a PVH kernel boots from: the `hvm_start_info` (the blob's `start_info`
address goes in `ebx`), its memory map and ACPI tables with a MADT listing
the local APICs and the I/O APIC; `x86::pc::pvh_entry` finds the kernel's
32-bit entry. `osmium_boot::fdt::FdtWriter` builds any other tree.

## Booting a whole kernel

The three `*-hyp` examples boot osmium's own kernels as guests, and the
recipe is the same on each:

1. Allocate guest RAM, add it to a `GuestMemory` (`add_region`), and load
   the kernel with `GuestMemory::load_elf`, which copies each segment
   (`osmium_boot::elf`) to its address and zeroes the rest of its memory
   size.
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

- Nothing has run on physical hardware; every backend has only run under
  QEMU.
- x86 MMIO emulation decodes moves (including the `moffs` forms), `MOVZX`
  and `TEST`. The instruction comes from SVM's decode assists when the CPU
  has them, and otherwise is fetched through the guest's page tables in
  whatever mode it runs (no paging, 32-bit with PSE, PAE or 4-level long
  mode), so MMIO works from 32-bit and PAE guests on both backends.
- x86 MSRs: every access exits. EFER, STAR, LSTAR, CSTAR, SFMASK, FS and GS
  base, `KernelGsBase`, `SYSENTER_CS`/`ESP`/`EIP`, PAT, `TSC_AUX` and
  `APIC_BASE` (the xAPIC at its default address) are emulated; a value the
  hardware would reject raises `#GP`. Other MSRs read as zero and ignore
  writes.
- x86 CPUID hides MONITOR/MWAIT, x2APIC, XSAVE and AVX
  (`x86::patch_cpuid`), and the backend's own SVM or VMX. On both SVM and
  VMX the guest's SVM or VMX instructions, `XSETBV`, `MONITOR` and `MWAIT`
  raise `#UD`, so a halted guest always exits through `HLT`. With `connect_lapic` the guest's `CR8`
  is its local APIC's task priority (SVM through `V_TPR`, VMX by exiting on
  `MOV CR8`); without an APIC `CR8` gates nothing.
- `x86::vmx::VmxVcpu` is the Intel backend: EPT (`stage2::eptp`), VPID and
  unrestricted guest mode, so guests start as under SVM (protected mode, real
  mode or long mode). It differs from SVM in four ways: no decode assists (MMIO
  instructions are always fetched from guest memory), `vmcall` for hypercalls,
  EPT violations for MMIO, and the host's task register (`CpuTables::load`) must
  be loaded before `vmx::enable`. The VMCS is bound to the host CPU that
  runs the vCPU; `with_migration` (or `unbind`, on that CPU) releases it so
  another CPU can run the vCPU next, at the cost of a `VMCLEAR` and a
  `VMLAUNCH` per run. The guest's debug registers work: the first `MOV DR` is
  emulated and from then on each run swaps `DR0`-`DR3`, `DR6`, `DR7` and
  `IA32_DEBUGCTL` with the host's, so hardware breakpoints fire in the guest
  and the host's are disarmed meanwhile. A host NMI during a guest run is
  delivered to the host's IDT vector 2 with an NMI-style stack frame (the
  gate's IST slot is not used). `examples/x86_64-hyp` picks SVM or VMX at
  boot (`backend.rs`) and runs all of its demos and the x86_64-pc guest kernel
  on either; QEMU's TCG does not emulate VMX, so VMX has only run under nested
  KVM (`examples/x86_64-hyp` with `-accel kvm -cpu host`).
- FP/SIMD state is switched per vCPU on the assumption that the host
  kernel itself never uses those registers (soft-float targets): always on
  RISC-V and AArch64, and on x86 for
  vCPUs built `with_fp_switching` (x87 and SSE through FXSAVE/FXRSTOR, not
  AVX). Without it an x86 guest uses the host CPU's registers as they are,
  which is enough for one vCPU per host CPU; the whole-kernel x86 guest runs
  that way because, under QEMU's multi-threaded TCG, switching around VMRUN
  made it take spurious page faults that single-threaded TCG never showed.
- AArch64 guests do not see SVE, SME, MTE or pointer authentication: their
  state is not switched and their instructions trap, and `HCR_EL2.TID3`
  traps the ID registers so `Aarch64Vcpu::emulate_sysreg` returns the
  host's values with those features hidden (`aarch64::guest_id_register`).
  A VHE host's own `q` registers are kept if its FP was on, but not the
  upper bits of SVE `z` registers.
- virtio devices: the transport registers sit behind a short IRQ-off lock,
  but a device's work (a disk read, a frame handed to a NIC backend) runs
  under a second lock that does not mask interrupts, so a backend may block
  or wait for its own interrupt. A notify that finds the device busy on
  another CPU leaves a request for the busy context instead of waiting.
  `VirtioMmio::with_device` does wait for a busy device, so do not call it
  from an interrupt handler.
- `VirtioBlock` serves requests synchronously on notify, at most 4 MiB of
  data each: it advertises `size_max` 64 KiB and `seg_max` 64, and a larger
  request fails with `VIRTIO_BLK_S_IOERR`.
