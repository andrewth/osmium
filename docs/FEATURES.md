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
- ✅ DMA memory barriers (`dma_wmb`, `dma_rmb`, `mb`)
- ✅ Trap entry (RISC-V S/M-mode, AArch64 EL1/EL2): full `TrapFrame`, registered handler, portable `Trap` cause decoding
- ✅ AArch64 PSCI (CPU on, system off/reset) and generic-timer registers; RISC-V SBI IPIs
- ✅ x86_64 IDT/trap entry (all 256 vectors, interrupt gates, `int3` normalized to point at the instruction), per-CPU GDT/TSS (`CpuTables`) with IST stacks (`trap::set_ist`)
- ✅ Per-process address spaces: `PageTable::share_root_entries` shares the kernel's root entries; the examples switch CR3/satp/TTBR0 in the context-switch hook from per-task data, and free each address space with its task
- ✅ AArch64 user mode (EL1 kernels): `aarch64::enter_user` (eret to EL0t), lower-EL vectors save and restore `SP_EL0` and `TPIDRRO_EL0` in the frame, `TrapFrame::from_user`
- ✅ RISC-V user mode: `riscv64::enter_user` (sret to U-mode), traps from U-mode land on `TrapCpu`'s kernel stack with the kernel's `tp` restored, `with_user_access` (SUM) for copying user buffers, `TrapFrame::from_user`
- ✅ x86_64 user mode: `enter_user` (ring 3 via `iretq`), system calls by `syscall` (`CpuTables::enable_syscall`; the stub builds the same frame as `int 0x80`) or `int 0x80` (`trap::allow_from_user`), `TrapFrame::from_user`
- ✅ RISC-V trap entry swaps through `sscratch` to a per-CPU `TrapCpu`: an exception stack when the interrupted kernel stack overflowed, a kernel stack for traps from U-mode, and a hook point for hypervisor guest exits
- ✅ AArch64 current-EL vectors check `sp` against the same per-CPU `TrapCpu` before the first store and move to an exception stack on overflow (vector sizes enforced at assembly time)
- 🗺 FPU/SIMD state save and restore; user-mode entry/return

### `osmium-sync`: synchronization
- ✅ `SpinLock<T, G>`: a fair ticket lock, generic over a *guardian* (`PreemptDisabled` by default, `IrqDisabled`, `NoGuard`)
- ✅ `RwSpinLock<T, G>`
- ✅ `Once<T>`, `Lazy<T>`
- ✅ Per-CPU storage: `PerCpu<T>` (shared, `Sync` data) and `PerCpuCell<T>` (CPU-private mutable data, IRQ-masked access, re-entrancy checked), plus a per-CPU preemption counter
- ✅ Lock-free SPSC ring buffer (for IRQ-to-task data such as UART receive)
- ✅ `SeqLock<T>`: readers retry instead of blocking the writer; byte-wise atomic copies keep racing reads sound
- 🗺 RCU, MCS/queued spinlocks

### `osmium-mm`: memory management
- ✅ Typed `PhysAddr`/`VirtAddr` with alignment helpers and canonical-address checks
- ✅ `MemoryMap`: a fixed-capacity, heap-free region list that merges, carves and reserves (OSKit's LMM/AMM role, used at boot)
- ✅ Frame allocators: a bitmap allocator, and a buddy allocator (orders 0–N, intrusive free lists, coalescing)
- ✅ Generic multi-level page table `PageTable<F, A>` with map, unmap, translate, protect, huge-page `split` and `unmap_4k`, huge pages (2 MiB / 1 GiB), and freeing of intermediate tables
- ✅ PTE formats: x86_64 4-level, AArch64 stage 1 (4 KiB granule), RISC-V Sv39/Sv48, Intel EPT, AArch64 stage 2, AArch64 EL2 stage 1 (`Aarch64El2`), RISC-V G-stage Sv39x4/Sv48x4 (multi-page roots via `PageTableFormat::ROOT_PAGES` and `TableAlloc::alloc_root`)
- ✅ Heap: a size-class slab front-end plus a large-allocation path over any `PageSource`; `LockedHeap` implements `GlobalAlloc`; works from a static arena (firmware) or the frame allocator (kernels)
- 🗺 Virtual memory areas (VMA tree), demand paging, copy-on-write, typed frame metadata (as in OSTD's `Frame<M>`), 5-level paging, IOMMU tables

### `osmium-hal`: hardware abstraction
- ✅ MMIO: `ReadOnly`/`WriteOnly`/`ReadWrite<T>` register cells for `#[repr(C)]` register blocks, and a bounds-checked `IoMem` window (safe after an `unsafe` constructor)
- ✅ x86 `Port<T>` I/O
- ✅ Device-class traits: `SerialPort`, `InterruptController`, `Clock`/`OneShotTimer`, `BlockDevice`
- ✅ IRQ dispatch table: register handlers by number, dispatch from the trap path
- ✅ Global console with `print!`/`println!` that can be swapped at runtime
- ✅ DMA buffer descriptor (`DmaBuffer` with CPU and device addresses), self-freeing `OwnedDma`, and a `DmaAllocator` over any `LockedFrames`
- ✅ `NetDevice` trait and `MacAddress`
- ✅ PCI: `ConfigAccess` over ECAM or x86 port I/O, brute-force enumeration, BAR probing and assignment (`BarAllocator`), capability lists
- ✅ USB: setup packets, standard descriptor parsing, the `UsbHost` host-controller trait, and generic device enumeration
- ✅ virtio constants and split-ring layout shared by drivers and device models
- 🗺 Async variants of device traits, PCI bridge walking, MSI/MSI-X

### `osmium-drivers`: reference drivers
- ✅ NS16550A UART (port I/O and MMIO backends)
- ✅ Arm PL011 UART
- ✅ RISC-V CLINT (machine timer and software interrupts, for M-mode firmware)
- ✅ RISC-V PLIC
- ✅ Arm GICv2 (distributor + CPU interface, SGIs with correct source-CPU EOI)
- ✅ x86 local APIC (xAPIC MMIO, INIT/STARTUP IPIs)
- ✅ Intel 8254 PIT (calibration delays)
- ✅ x86 I/O APIC (GSI routing, polarity/trigger, masking); the x86_64 example routes COM1's receive interrupt through it into an `SpscRing`
- ✅ RAM disk `BlockDevice`
- ✅ virtio-mmio transport (legacy and 1.x), split virtqueue, virtio-net `NetDevice`
- ✅ xHCI USB host controller (`UsbHost`): polled command and event rings, root-port reset, control, bulk and interrupt transfers, interrupt endpoints that stay armed (`submit_in`/`poll_in`)
- ✅ USB class drivers on any `UsbHost`: mass storage (SCSI over Bulk-Only) as a `BlockDevice`, and HID boot keyboards with US-layout key translation
- ✅ Mellanox ConnectX-2/-3 (mlx4) Ethernet: reset, firmware start, ICM, polled raw Ethernet queue pair per port as a `NetDevice`; tested against a simulated HCA
- 🗺 virtio-pci transport; virtio blk, console; xHCI interrupts, hubs and isochronous transfers; USB CDC-ECM networking and HID report descriptors; GICv3; HPET; NVMe

### `osmium-sched`: tasks and scheduling
- ✅ Real context switch for x86_64, AArch64 and RISC-V 64 (naked functions; callee-saved registers only)
- ✅ `Task`, built with `TaskBuilder` (name, priority, stack size, home CPU)
- ✅ Injectable `Scheduler` trait (as in OSTD) and the core operations: `yield_now`, `block`/`wake`, `exit`, tick-driven preemption, and `on_cpu` hand-off so global run queues are safe on SMP
- ✅ Pluggable `StackAllocator` (for example, stacks with guard pages; the x86_64 example kills a task that overflows into its guard page and keeps running)
- ✅ Context-switch hook (`set_switch_hook`) and `Task::kernel_stack_top`, for per-task CPU state such as the x86 TSS stack, address space or FPU
- ✅ Remote-wake hook so kernels can IPI a CPU when work is queued there; task migration with `Task::set_cpu`
- ✅ Ready-made policies: `FifoScheduler` (round-robin with a time slice) and `PriorityScheduler` (O(1) bitmap, 64 levels)
- ✅ `WaitQueue` (no lost wake-ups), sleeping `Mutex`, `Semaphore`
- ✅ `TimerQueue`: deadline-ordered callbacks driven by the timer IRQ
- ✅ `osmium-exec`: heap-free async executor (fixed task slots, interrupt-safe wakers, idle-until-interrupt without lost wake-ups, `run_with` for stack-pinned `async fn`s), `Signal`, `AtomicWaker`, `StaticCell`
- 🗺 Load balancing, EDF policy

### `osmium-boot`: boot protocols
- ✅ Flattened Device Tree (DTB) parser: zero-copy nodes and properties, `reg` decoding with `#address-cells`/`#size-cells`, `compatible` search
- ✅ FDT writer (`alloc`), for hypervisors that generate guest device trees
- ✅ Multiboot2 parser: memory map, command line, modules
- ✅ Conversion of firmware memory maps into `osmium_mm::MemoryMap`
- ✅ ELF64 executables: validated parsing of loadable segments, and `Elf::load_into` any `PageTable` (per-segment permissions, zeroed `.bss`, shared pages merged); all three examples run the same Rust user program (`examples/user/hello.rs`) built as an ELF
- ✅ PVH start-info parser and the `pvh_entry_note!` ELF-note macro
- ✅ ACPI: RSDP/RSDT/XSDT with checksums, MADT (local APICs, x2APICs, I/O APICs), MCFG (PCI ECAM windows)
- 🗺 UEFI boot services wrapper, Limine protocol, AML

### `osmium-fs`: file systems
- ✅ `File` trait: one node (file, directory, device, symlink), stateless and offset-based like `pread`/`pwrite`, with defaults so a device implements only what it supports; `Stat`, `DirEntry`, `FileKind`
- ✅ `Errno` with Linux numbers, and osmium's own `OpenFlags` for system call layers to translate into
- ✅ `Vfs`: absolute-path lookup across mounts (`..` leaves a mount at its root), symbolic links (40 deep), trailing-`/` rules, `open` with create/exclusive/truncate, `mkdir`, `mknod`, `unlink`, `rmdir`, `symlink`, `readlink`, `stat`/`lstat`, `canonicalize`, copy-on-write mount table
- ✅ `RamFs` (tmpfs), with unlinked-but-open files kept alive
- ✅ `DevDir` for a kernel-populated `/dev`, plus null and zero devices
- ✅ cpio `newc` archives: zero-copy iteration and initramfs unpacking (concatenated archives, `..` refused), tested against GNU cpio
- ✅ ext2, read and write, over any `BlockDevice`: indirect block maps, sparse files, fast and slow symlinks, allocation, truncation, orphaned open files; tested with `mkfs.ext2 -d`, `e2fsck` and `debugfs`
- ✅ FAT32 (`osmium-fs-fat`), read and write, over any `BlockDevice`: VFAT long names with generated `~N` short names, case-insensitive lookup, every FAT copy and the FSInfo free count kept current, orphaned open files; tested with `mkfs.fat` and `fsck.fat`
- 🗺 A block cache, rename and hard links, timestamps from a clock in the VFS

### `osmium-virt`: hypervisor building blocks
- ✅ `GuestPhysAddr`, and `GuestMemory`: a GPA-to-host region map with bounds-checked `read`/`write`/`read_obj`/`write_obj` and a `Pod` marker
- ✅ Stage-2 page tables: `osmium_mm` `PageTable` with the `Ept`, `Aarch64Stage2` and `Sv39x4`/`Sv48x4` formats; EPTP, VTTBR and hgatp encoders
- ✅ `MmioBus` / `PioBus` device dispatch (as in rust-vmm `vm-device`)
- ✅ Normalized `VmExit` enum, `Vcpu` trait, and a generic `run_vcpu` loop that services MMIO and PIO exits
- ✅ An emulated 16550 UART device, with an optional receive-interrupt line
- ✅ An emulated 8259A PIC pair (`VirtualPic`: init sequence, masks, IRR/ISR, EOI, cascade) whose output and INTA drive the SVM vCPU
- ✅ An emulated GICv2 (`VirtualGicV2`: distributor and CPU interface, priorities, PMR, acknowledge/EOI) driving the AArch64 vCPU's virtual IRQ; the guest's virtual timer feeds it, with expiries during a guest run exiting through the host GIC
- ✅ An emulated PLIC (`VirtualPlic`, QEMU `virt` register layout) whose S-mode context outputs drive vCPU external-interrupt lines (`hvip.VSEIP`)
- ✅ RISC-V guest device trees (`riscv::fdt::GuestMachine`): harts, memory, PLIC, 16550s and virtio-mmio, in the layout Linux expects
- ✅ virtio device models: split virtqueue over `GuestMemory`, the virtio-mmio (v2) transport as a bus device, virtio-console, virtio-blk (over any `BlockDevice`) and virtio-net (over a pluggable `NetBackend`), sharing `osmium_hal::virtio` definitions with the drivers
- ✅ RISC-V H-extension `Vcpu` (`riscv64-hs`): world switch through the trap entry's guest-exit hook, VS CSR switching, MMIO emulation from guest-page faults (`htinst` or `hlvx`-fetched instruction, compressed forms included), `wfi` halts, host-interrupt exits, and a minimal SBI (BASE, TIME, SRST, DBCN, legacy), and multi-vCPU guests (`GuestHarts`: SBI HSM start/stop/status, IPIs injected as `VSSIP`, RFENCE as deferred `fence.i`/`hfence.vvma`, and kicks of vCPUs running on other host CPUs), and guest floating-point state (D) switched per run
- ✅ AMD SVM `Vcpu`: VMCB setup for a 32-bit flat guest, nested paging with `X86_64` tables, VMRUN world switch under CLGI/STGI, port I/O, `hlt`, `vmmcall` and interrupt exits, MMIO from nested page faults (a decoder for the MOV/MOVZX forms drivers use, with decode assists or a fetch from guest memory), interrupt injection through `EVENTINJ` with interrupt-window exits and re-injection of interrupted events
- ✅ AArch64 EL2 `Vcpu` (`aarch64-el2`, non-VHE): world switch through guest-exit hooks in the lower-EL vectors, EL1 system-register switching, stage 2 via `VTTBR_EL2`, MMIO emulation from data-abort syndromes, trapped `wfi`, IRQ exits, a virtual-IRQ line (`HCR_EL2.VI`), and PSCI for guests
- 🗺 VMX `Vcpu` backend, SVM VMLOAD/VMSAVE state and MMIO under guest paging, virtual interrupt controllers (APLIC/IMSIC, vGIC)

### `osmium-proc`: processes and system calls
- ✅ `Process`: a user address space, a descriptor table of `osmium_fs::File`s, working directory, program break, `mmap` area and exit status, attached to its task through `TaskBuilder::data`; `current`, `root_for` (the switch hook's table), `exit`, `wait`, lookup by `Pid`
- ✅ `AddressSpace<F, A>`: shares the kernel's root entries, loads ELF or flat images, maps and unmaps anonymous memory, and frees its pages with the process; user copies walk the process's own table (user-accessible, writable for stores) and go through the physical mapping, so no SUM/PAN/SMAP handling is needed
- ✅ One portable dispatcher with each architecture's Linux numbers, open flags and `struct stat`: `read`, `write`, `readv`, `writev`, `openat`, `close`, `lseek`, `fstat`, `newfstatat`, `getdents64`, `ioctl`, `getcwd`, `chdir`, `mkdirat`, `unlinkat`, `exit`, `exit_group`, `getpid`, `getppid`, `gettid`, `brk`, `mmap` (anonymous), `munmap`, `sched_yield`, `uname`; `syscall::handle` decodes the trap frame on RISC-V, AArch64 and x86_64
- ✅ All three examples run their user programs as processes; the Rust user program exercises `getpid`, `uname`, `brk`, `mmap` and `writev`
- 🗺 `fork`/`clone`, `execve`, `wait4`, signals, multi-threaded processes, file-backed `mmap`

### `osmium`: the umbrella crate
- ✅ Re-exports every component, each behind a Cargo feature of the same name

### Tooling and examples
- ✅ Host unit and integration tests for every crate
- ✅ Builds for `x86_64-unknown-none`, `aarch64-unknown-none-softfloat` and `riscv64imac-unknown-none-elf`
- ✅ `examples/riscv-virt`: a bootable kernel for QEMU `virt` that uses the FDT, the memory map, the buddy allocator, the heap, W^X Sv39 paging, the 16550 driver, the scheduler with timer-interrupt preemption, and `TimerQueue` sleeps; it also runs two guests in VS-mode under the H extension, the second built from osmium's own UART, PLIC and virtio-net drivers, taking timer, UART and virtio interrupts through the emulated PLIC, and a third with two vCPUs on two host harts that start each other through SBI HSM and exchange an IPI
- ✅ `examples/aarch64-virt`: the same on QEMU AArch64 `virt` (GICv2, PL011, generic timer, stage-1 paging, PSCI)
- ✅ `examples/aarch64-hyp`: a hypervisor that stays at EL2 (QEMU `virtualization=on`), turns on the EL2 MMU and runs EL1 guests under stage 2, one of which takes its virtual timer and a UART interrupt through the emulated GICv2
- ✅ `examples/x86_64-hyp`: enables AMD SVM (TCG with `-cpu max`) and runs a 32-bit guest under nested paging that talks to emulated 16550s over port I/O and MMIO and takes COM1's interrupt through an emulated PIC
- ✅ `examples/x86_64-pc`: the same on QEMU q35 (PVH boot, COM1, local APIC timer, 4-level paging, ACPI MADT, INIT/SIPI trampoline)
- ✅ `examples/riscv-firmware`: M-mode firmware with `-bios none`, no heap and no scheduler: async tasks on `osmium-exec` await CLINT timer and PLIC/UART interrupts, then power off
- ✅ All three examples bring up 4 CPUs and run shared SMP demos (cross-CPU mutex wake-ups by IPI, task migration)
- ✅ `scripts/check.sh`: tests, clippy, rustdoc, all targets, and the QEMU boot test
