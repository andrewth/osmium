# Osmium: prior art and feature list

Osmium is a set of Rust crates for building operating systems, firmware and
hypervisors. This document records what we learned from earlier toolkits and
the feature list that came out of it.

## Prior art

### OSKit (University of Utah Flux group, 1997–2002)

A C framework of 34 component libraries for building OS kernels. Its main
ideas were:

- **Separability.** Each library (boot support, list-based memory manager
  `LMM`, address-map manager `AMM`, minimal C library, threads, filesystems,
  network stack, gdb stub) can be used without the others. A kernel links only
  what it needs, and dependencies between components are explicit.
- **Ready-made defaults you can override.** The library supplies a working
  "base environment" (GDT/IDT, page tables, console), and any part of it can
  be replaced.
- **Encapsulated legacy code.** Linux and BSD drivers, filesystems and the
  network stack were wrapped behind COM interfaces, so a kernel could reuse
  them without taking on their internals.
- **Run on the host for development.** Most kernels could run on top of Unix
  for debugging.
- **Weaknesses we want to avoid:** C gave no memory safety at component
  boundaries, the COM glue was heavy, and the code was tied to i386.

### OSTD (Asterinas framework, 2024–)

The Rust framework under the Asterinas "framekernel". Its main ideas are:

- **A minimal, audited unsafe core.** All `unsafe` that touches the machine
  (page tables, frames, context switch, I/O memory, traps) lives in OSTD. The
  APIs above it are designed to be sound, so the kernel and its drivers can be
  written entirely in safe Rust (`#![deny(unsafe_code)]`).
- **Module set:** `arch`, `boot`, `bus`, `console`, `cpu` (CPU-local
  variables), `io` (`IoMem`/`IoPort` with bounds-checked accessors), `mm`
  (typed frames with metadata, `VmSpace`, heap/frame allocator injection),
  `sync` (`SpinLock` generic over an IRQ/preemption guard, `Mutex`, `RwLock`,
  `WaitQueue`, RCU), `task` (tasks plus an *injectable* scheduler), `timer`,
  `trap`, `user`, `smp`, `logger`, `panic`.
- **Policy is injected, not built in.** The framework provides mechanism
  (context switch, run-queue hooks); the kernel provides the scheduler and the
  frame and heap allocators through traits or attribute macros.
- **Runs on Linux** so that filesystems and network stacks can be unit-tested
  in user mode.
- **Gaps for our goals:** OSTD is built for one kernel (a Linux-ABI
  framekernel). It assumes a heap, owns the boot path and `main`, has no
  hypervisor-specific support, and targets x86_64 first.

### Other references

| Project | Idea we borrow |
|---|---|
| rust-osdev `x86_64`, `uefi`, `bootloader` | Typed addresses and page-table entries; small, focused crates |
| Theseus | Fine-grained crates as the unit of isolation |
| Tock | Works without a heap; static allocation for firmware |
| Hubris | Static, build-time configuration; no dynamic task creation needed |
| Embassy | Device traits with blocking and async variants |
| rust-vmm (`vm-memory`, `vm-device`) | Guest memory abstraction; MMIO/PIO bus with device dispatch |
| RustSBI / Hyperlight / Cloud Hypervisor | Normalized VM-exit handling; small hypervisor cores |

## Design principles

1. **Separable crates (OSKit).** Each subsystem is its own crate with an
   explicit dependency graph. A UART-only firmware pulls in `osmium-hal` and
   `osmium-drivers`; it never compiles the scheduler.
2. **Mechanism in the library, policy injected (OSTD).** Scheduling policy,
   frame sources and IRQ routing are traits. Ready-made policies are provided
   but optional.
3. **A small unsafe core under safe APIs (OSTD).** `unsafe` is confined to
   constructors that state their invariants (for example, "this MMIO range is
   mapped and exclusively owned"). Everything above them is safe.
4. **No hidden globals, no owned `main`.** The library never defines a
   `_start`, panic handler or global allocator. The OS does, using the
   building blocks.
5. **`no_std` first, `alloc` optional where possible.** `sync`, `mm` (except
   the heap front-end), `hal`, `drivers` and `boot` parsing work without a
   heap. `sched` and the `virt` buses need `alloc`.
6. **Host-testable.** Every crate also builds for the host. Arch primitives
   fall back to a simulation (per-thread IRQ flag, thread-local CPU id), and
   memory code runs against simulated physical memory. Context switching is
   real on the host, because it only touches callee-saved registers and stacks.
7. **Multi-architecture from day one:** x86_64, AArch64 and RISC-V 64.
8. **Hypervisors are first-class.** Stage-2 page-table formats (EPT, Arm
   stage 2), guest memory, device buses and VM-exit dispatch share the same
   code as the host kernel.

## Feature list

Status: ✅ implemented in this release · 🗺 roadmap

### `osmium-arch`: CPU primitives
- ✅ Interrupt flag control: `enable`, `disable`, `save_and_disable`/`restore`, `enable_and_wait` (atomic `sti; hlt` and its equivalents)
- ✅ CPU identity: `current_id` / `set_current_id` (TSC_AUX on x86, TPIDR_EL1 on AArch64, `tp` on RISC-V, thread-local on the host)
- ✅ Wait-for-interrupt, spin hint, monotonic cycle counter
- ✅ MMU control: activate a root table, flush one page, flush all
- ✅ x86_64: port I/O, MSRs, CR3, CPUID; AArch64: system registers, `MAIR` constant; RISC-V: `satp`, CSRs
- ✅ Host simulation backend
- 🗺 Trap/exception entry stubs and trap-frame layout per arch
- 🗺 FPU/SIMD state save and restore; user-mode entry/return

### `osmium-sync`: synchronization
- ✅ `SpinLock<T, G>`: a fair ticket lock, generic over a *guardian* (`PreemptDisabled` by default, `IrqDisabled`, `NoGuard`)
- ✅ `RwSpinLock<T, G>`
- ✅ `Once<T>`, `Lazy<T>`
- ✅ Per-CPU storage: `PerCpu<T>` (shared, `Sync` data) and `PerCpuCell<T>` (CPU-private mutable data, IRQ-masked access, re-entrancy checked), plus a per-CPU preemption counter
- ✅ Lock-free SPSC ring buffer (for IRQ-to-task data such as UART receive)
- 🗺 RCU, sequence locks, MCS/queued spinlocks

### `osmium-mm`: memory management
- ✅ Typed `PhysAddr`/`VirtAddr` with alignment helpers and canonical-address checks
- ✅ `MemoryMap`: a fixed-capacity, heap-free region list that merges, carves and reserves (OSKit's LMM/AMM role, used at boot)
- ✅ Frame allocators: a bitmap allocator, and a buddy allocator (orders 0–N, intrusive free lists, coalescing)
- ✅ Generic multi-level page table `PageTable<F, A>` with map, unmap, translate and protect, huge pages (2 MiB / 1 GiB), and freeing of intermediate tables
- ✅ PTE formats: x86_64 4-level, AArch64 stage 1 (4 KiB granule), RISC-V Sv39/Sv48, Intel EPT, AArch64 stage 2
- ✅ Heap: a size-class slab front-end plus a large-allocation path over any `PageSource`; `LockedHeap` implements `GlobalAlloc`; works from a static arena (firmware) or the frame allocator (kernels)
- 🗺 Virtual memory areas (VMA tree), demand paging, copy-on-write, typed frame metadata (as in OSTD's `Frame<M>`), 5-level paging, IOMMU tables

### `osmium-hal`: hardware abstraction
- ✅ MMIO: `ReadOnly`/`WriteOnly`/`ReadWrite<T>` register cells for `#[repr(C)]` register blocks, and a bounds-checked `IoMem` window (safe after an `unsafe` constructor)
- ✅ x86 `Port<T>` I/O
- ✅ Device-class traits: `SerialPort`, `InterruptController`, `Clock`/`OneShotTimer`, `BlockDevice`
- ✅ IRQ dispatch table: register handlers by number, dispatch from the trap path
- ✅ Global console with `print!`/`println!` that can be swapped at runtime
- ✅ DMA buffer descriptor (`DmaBuffer` with CPU and device addresses)
- 🗺 Async variants of device traits, PCI(e) enumeration, ACPI tables

### `osmium-drivers`: reference drivers
- ✅ NS16550A UART (port I/O and MMIO backends)
- ✅ Arm PL011 UART
- ✅ RISC-V PLIC
- ✅ Arm GICv2 (distributor + CPU interface)
- ✅ x86 local APIC (xAPIC MMIO)
- ✅ RAM disk `BlockDevice`
- 🗺 virtio (MMIO/PCI): blk, net, console; GICv3; IO-APIC; HPET; NVMe

### `osmium-sched`: tasks and scheduling
- ✅ Real context switch for x86_64, AArch64 and RISC-V 64 (naked functions; callee-saved registers only)
- ✅ `Task`, built with `TaskBuilder` (name, priority, stack size, home CPU)
- ✅ Injectable `Scheduler` trait (as in OSTD) and the core operations: `yield_now`, `block`/`wake`, `exit`, tick-driven preemption, and `on_cpu` hand-off so global run queues are safe on SMP
- ✅ Ready-made policies: `FifoScheduler` (round-robin with a time slice) and `PriorityScheduler` (O(1) bitmap, 64 levels)
- ✅ `WaitQueue` (no lost wake-ups), sleeping `Mutex`, `Semaphore`
- ✅ `TimerQueue`: deadline-ordered callbacks driven by the timer IRQ
- 🗺 Heap-free static tasks (Hubris/Tock style), async executor, load balancing, EDF policy

### `osmium-boot`: boot protocols
- ✅ Flattened Device Tree (DTB) parser: zero-copy nodes and properties, `reg` decoding with `#address-cells`/`#size-cells`, `compatible` search
- ✅ FDT writer (`alloc`), for hypervisors that generate guest device trees
- ✅ Multiboot2 parser: memory map, command line, modules
- ✅ Conversion of firmware memory maps into `osmium_mm::MemoryMap`
- 🗺 UEFI boot services wrapper, Limine protocol, ACPI RSDP discovery

### `osmium-virt`: hypervisor building blocks
- ✅ `GuestPhysAddr`, and `GuestMemory`: a GPA-to-host region map with bounds-checked `read`/`write`/`read_obj`/`write_obj` and a `Pod` marker
- ✅ Stage-2 page tables: `osmium_mm` `PageTable` with the `Ept` and `Aarch64Stage2` formats
- ✅ `MmioBus` / `PioBus` device dispatch (as in rust-vmm `vm-device`)
- ✅ Normalized `VmExit` enum, `Vcpu` trait, and a generic `run_vcpu` loop that services MMIO and PIO exits
- ✅ An emulated 16550 UART device
- 🗺 VMX/SVM, Arm EL2 and RISC-V H-extension `Vcpu` backends, virtual interrupt controllers, virtio device models

### `osmium`: the umbrella crate
- ✅ Re-exports every component, each behind a Cargo feature of the same name

### Tooling and examples
- ✅ Host unit and integration tests for every crate
- ✅ Builds for `x86_64-unknown-none`, `aarch64-unknown-none-softfloat` and `riscv64imac-unknown-none-elf`
- ✅ `examples/riscv-virt`: a bootable kernel for QEMU `virt` that uses the FDT, the memory map, the buddy allocator, the heap, W^X Sv39 paging, the 16550 driver, the scheduler with timer-interrupt preemption, and `TimerQueue` sleeps
- ✅ `scripts/check.sh`: tests, clippy, rustdoc, all targets, and the QEMU boot test
