<p><img src="docs/logo/osmium-horizontal-reversed.svg" alt="osmium" width="360"></p>

```sh
cargo add osmium
```

![no_std](https://img.shields.io/badge/no__std-yes-4E6984)
![architectures](https://img.shields.io/badge/arch-x86__64%20%7C%20aarch64%20%7C%20riscv64-4E6984)
![license](https://img.shields.io/badge/license-GPL--2.0--only-4E6984)

A separable Rust toolkit for building operating systems, firmware and
hypervisors: CPU primitives, synchronization, memory management, a hardware
abstraction layer, drivers, scheduling, boot-protocol parsing and
virtualization support. It runs on x86_64, AArch64 and RISC-V 64.

osmium takes its structure from [OSKit](https://www-old.cs.utah.edu/flux/oskit/)
(independent components you link only as needed) and its safety model from
[OSTD](https://asterinas.github.io/api-docs/) (a small `unsafe` core under
sound, safe APIs, with policy injected by the OS). See
[docs/FEATURES.md](docs/FEATURES.md) for the survey of prior art, the design
principles and the full feature list with status, [DESIGN.md](DESIGN.md) for the logo,
colors and type, and [docs/HYPERVISOR.md](docs/HYPERVISOR.md) for building a
hypervisor with `osmium-virt`.

## Crates

| Crate | What it provides | Needs `alloc` |
|---|---|---|
| `osmium-arch` | IRQ flag control, CPU id, trap entry with a portable `Trap` cause, per-task FP/SIMD state, wait-for-interrupt, counters, TLB maintenance, x86 port I/O/MSRs/CRs, AArch64 sysregs and PSCI, RISC-V CSRs and SBI | no |
| `osmium-sync` | ticket `SpinLock` generic over IRQ/preemption guards, `RwSpinLock`, `Once`, `Lazy`, `PerCpu`, `PerCpuCell`, lock-free SPSC ring | no |
| `osmium-mm` | `PhysAddr`/`VirtAddr`, `MemoryMap`, buddy and bitmap frame allocators, generic `PageTable` (x86_64, AArch64, Sv39/Sv48, EPT, Arm stage 2, RISC-V G-stage, AArch64 EL2), slab heap as `#[global_allocator]` | no |
| `osmium-hal` | MMIO register cells and bounds-checked `IoMem`, x86 `Port<T>`, device traits (serial, IRQ controller, clock, block, DMA, display), linear framebuffers with pixel formats, `IrqTable`, global console with `println!` | no |
| `osmium-drivers` | NS16550A, PL011, RISC-V PLIC and CLINT, GICv2, x86 local APIC (with INIT/SIPI), x86 I/O APIC, i8254 PIT, RAM disk, Mellanox ConnectX-3 (mlx4) Ethernet, virtio-net and virtio-blk (MMIO, legacy and 1.x), xHCI USB host controller (interrupt-driven), USB mass storage, HID boot keyboards and CDC-ECM Ethernet, AHCI (SATA) and NVMe disks, virtio-pci transport, virtio-gpu (also as virtio-vga), Bochs DISPI (QEMU std VGA, bochs-display) and VESA BIOS (VBE) mode setting | no |
| `osmium-boot` | zero-copy FDT parser, FDT writer, Multiboot2 and PVH parsers (all fill a `MemoryMap`), ACPI MADT/MCFG reader, ELF64 loader, UEFI system table and GOP | writer only |
| `osmium-sched` | context switch, `Task`, injectable `Scheduler` (FIFO and priority policies included), `WaitQueue`, `Mutex`, `Semaphore`, `TimerQueue` | yes |
| `osmium-virt` | `GuestMemory`, stage-2 table helpers, MMIO/PIO `Bus`, normalized `VmExit`, `Vcpu` trait and `run_vcpu` loop, emulated 16550, virtio-mmio console and block devices, RISC-V H-extension, AArch64 EL2 and AMD SVM vCPUs with SBI and PSCI (multi-vCPU guests), emulated PLIC, GICv2, 8259 PIC, 8254 PIT and local APIC, virtio-net | yes |
| `osmium-exec` | heap-free async executor (fixed task slots, interrupt-safe wakers), `Signal`, `StaticCell` | no |
| `osmium-fs` | `File` trait and `Vfs` namespace (mounts, `..` across mounts, symlinks), Linux `Errno`, RAM file system, `/dev` nodes, cpio initramfs unpacking | yes |
| `osmium-proc` | `Process` (address space, fd table, cwd, exit status, `wait`), `AddressSpace` with page-table-checked user copies, and one portable system-call dispatcher using each architecture's Linux numbers and structure layouts | yes |
| `osmium-fs-fat` | FAT32 for the `osmium-fs` VFS over any `BlockDevice`: long (VFAT) names, create, write, truncate, remove | yes |
| `osmium-net` | Polled IPv4 stack over any `NetDevice`: ARP, ICMP echo, UDP, TCP, DHCP client | yes |
| `osmium-iscsi` | iSCSI initiator over `osmium-net` TCP as a `BlockDevice`: login and negotiation, R2T and immediate-data writes, SendTargets discovery | yes |
| `osmium-fs-ext4` | ext2/ext3/ext4 (read and write) for the `osmium-fs` VFS over any `BlockDevice` | yes |
| `osmium-fs-iso9660` | read-only ISO 9660 for the `osmium-fs` VFS over any `BlockDevice`: Rock Ridge, Joliet, deep-directory relocation, multi-extent files | yes |
| `osmium` | re-exports everything behind features of the same names (`full` enables all) | |

The library never defines an entry point, panic handler or global allocator;
your OS assembles those from the parts it uses.

## Examples: the same kernel on three architectures

[`examples/riscv-virt`](examples/riscv-virt) and
[`examples/aarch64-virt`](examples/aarch64-virt) boot on QEMU's `virt`
machines with four CPUs, and [`examples/x86_64-pc`](examples/x86_64-pc) on
QEMU's q35 PC (PVH boot, ACPI MADT, local APIC timer calibrated with the
PIT, INIT/SIPI bring-up through a real-mode trampoline). Each discovers hardware from the device tree, builds
a memory map, feeds the buddy allocator, turns on the heap, enables W^X
paging (Sv39 or AArch64 stage 1), moves the console to the UART driver
(16550 or PL011), brings up the other CPUs (SBI HSM or PSCI), and runs the
shared demos in [`examples/demos`](examples/demos): tasks with timer
preemption, a sleeping mutex, timer sleeps, cross-CPU wake-ups by IPI, task
migration, and recovery from a breakpoint and a page fault:

```console
$ cd examples/riscv-virt && cargo run --release
osmium riscv-virt example (hart 0)
[fdt]   riscv-virtio,qemu, 9271 bytes, bootargs ""
[uart]  ns16550a at 0x10000000, console switched from SBI
[frame] buddy allocator: 32625 free frames (127 MiB)
[mmu]   Sv39 on, root 0x80062000; kmain mapped R|X|G via Size4K page
[sched] FIFO scheduler, 10 ms tick
[smp]   hart 0 online as CPU 1
[smp]   hart 2 online as CPU 2
[smp]   hart 3 online as CPU 3
[smp]   4 CPUs online
[task]  A0
...
[mutex] 4 tasks x 1000 increments across yields = 4000
[preempt] busy-looping task was preempted after 2 ticks
[timer] slept 51 ms (asked for 50)
[smp]   8 tasks on 4 CPUs (ran on mask 0b1111), mutex total 2000
[smp]   migrating task visited CPUs [0, 1, 2, 3, 0]
[trap]  recovered from Breakpoint
[trap]  recovered from PageFault { addr: 4096, access: Read }
[done]  10 timer ticks, 32545 free frames; shutting down
```

(Press `Ctrl-A X` to leave QEMU if it does not exit on its own.)

[`examples/riscv-firmware`](examples/riscv-firmware) shows the other end of
the range: machine-mode firmware started with `-bios none`, with no heap and
no scheduler. Two async tasks on the heap-free `osmium-exec` executor await
CLINT timer interrupts and UART input routed through the PLIC, then the
firmware powers off. The binary links no allocator.

## Testing

Every crate builds and runs its tests on the host. `osmium-arch` replaces
privileged instructions with a simulation there: a per-thread IRQ flag and
CPU id. Memory code runs against simulated physical memory, and the context
switch is the real one, running on host threads.

```sh
cargo test --workspace --all-features
./scripts/check.sh   # tests, clippy, rustdoc, all bare-metal targets, QEMU boot
```

Requires a nightly toolchain (pinned in `rust-toolchain.toml`) for the
example and the bare-metal targets; the crates themselves use only stable
features.

## Current limitations

- User mode works on all three architectures: the examples run the same
  user programs, each in its own address space (sharing the kernel's root
  page-table entries), with system calls, and all three load the same
  Rust user program from an ELF file as an `osmium-proc` process, which
  opens, writes and lists files in an `osmium-fs` RAM file system. On
  all three an init program also forks, waits and execs; `fork` copies
  memory eagerly (no copy-on-write), and a process has one thread. Kernel stack overflows are caught on all three
  architectures when task stacks have guard pages.
- SMP has been exercised under QEMU (4 CPUs, multi-threaded TCG) but not on
  physical hardware. Load balancing (`with_stealing`) is opt-in; by default tasks
  move only when `Task::set_cpu` asks.
- The context switch saves FP registers only on targets that have them
  enabled (`neon`, `d`). Soft-float kernels are unaffected.
- The hypervisor has RISC-V H, AArch64 EL2 and AMD SVM backends, but no
  Intel VMX backend (QEMU's TCG does not emulate VMX). None of the backends
  has run on physical hardware.
- When the heap is backed by `LockedFrames`, it can return large blocks to
  the frame allocator only if the mapper implements `virt_to_phys`
  (`OffsetMapper` does).

## License

osmium is licensed under the GNU General Public License, version 2 only
(`GPL-2.0-only`). See [LICENSE](LICENSE).
