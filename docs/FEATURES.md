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
- ✅ x86_64 BIOS calls from long mode (`x86_64::bios`): a thunk at 0x7000 drops to real mode, runs one software interrupt and comes back, restoring GDT, IDT, CR0/CR3, EFER and the FS/GS bases; the x86_64 example sets a VESA mode with it
- ✅ Per-process address spaces: `PageTable::share_root_entries` shares the kernel's root entries; the examples switch CR3/satp/TTBR0 in the context-switch hook from per-task data, and free each address space with its task
- ✅ AArch64 user mode (EL1 kernels): `aarch64::enter_user` (eret to EL0t), lower-EL vectors save and restore `SP_EL0` and `TPIDRRO_EL0` in the frame, `TrapFrame::from_user`
- ✅ RISC-V user mode: `riscv64::enter_user` (sret to U-mode), traps from U-mode land on `TrapCpu`'s kernel stack with the kernel's `tp` restored, `with_user_access` (SUM) for copying user buffers, `TrapFrame::from_user`
- ✅ x86_64 user mode: `enter_user` (ring 3 via `iretq`), system calls by `syscall` (`CpuTables::enable_syscall`; the stub builds the same frame as `int 0x80`) or `int 0x80` (`trap::allow_from_user`), `TrapFrame::from_user`
- ✅ RISC-V trap entry swaps through `sscratch` to a per-CPU `TrapCpu`: an exception stack when the interrupted kernel stack overflowed, a kernel stack for traps from U-mode, and a hook point for hypervisor guest exits
- ✅ AArch64 current-EL vectors check `sp` against the same per-CPU `TrapCpu` before the first store and move to an exception stack on overflow (vector sizes enforced at assembly time)
- ✅ Per-task FP/SIMD state (`fp::FpState`: x87/SSE by FXSAVE, AArch64 `q0`–`q31` with FPCR/FPSR, RISC-V D with `fcsr`) and `fp::enable` per CPU; the scheduler switches it for tasks built with `TaskBuilder::fp_state`, `osmium-proc` gives every process one (copied by `fork`, cleared by `execve`, advertised in `AT_HWCAP`), and all three examples' `init` checks it
- ✅ x86_64 AVX via XSAVE: `fp::enable` turns on `CR4.OSXSAVE` and `XCR0` x87|SSE|AVX when the CPU has them, and `FpState` then switches with `XSAVE`/`XRSTOR` (upper halves of `ymm0`–`ymm15` kept; `fp::avx_enabled`), else falls back to FXSAVE. `examples/x86_64-pc` checks `ymm0` round-trips under QEMU TCG. Not done: AVX-512, PKRU, AMX, `XSAVEOPT`/`XSAVEC`; the `osmium-virt` x86 hypervisors hide XSAVE from guests (guests use FXSAVE)
- ✅ AArch64 SVE: `fp::sve::enable` (CPACR `ZEN`, `ZCR_EL1` at the longest vector length) and `fp::SveState` (`z0`–`z31`, `p0`–`p15`, `FFR`, `FPCR`/`FPSR`, sized for 2048-bit vectors) switched by the scheduler for tasks built with `TaskBuilder::sve_state` (replaces `fp_state`). Checked under QEMU `-cpu max` (2048-bit vectors) by `examples/aarch64-virt`; `osmium-proc` processes do not get SVE state yet, `aarch64-hyp` traps SVE for guests, SME is not supported, and all CPUs must have the same vector length
- 🗺 Lazy FP switching (`CR0.TS`/`#NM`, `CPACR_EL1.FPEN` traps, with cross-CPU owner tracking); FP/SIMD state is still switched eagerly on every context switch

### `osmium-sync`: synchronization
- ✅ `SpinLock<T, G>`: a fair ticket lock, generic over a *guardian* (`PreemptDisabled` by default, `IrqDisabled`, `NoGuard`)
- ✅ `RwSpinLock<T, G>`
- ✅ `Once<T>`, `Lazy<T>`
- ✅ Per-CPU storage: `PerCpu<T>` (shared, `Sync` data) and `PerCpuCell<T>` (CPU-private mutable data, IRQ-masked access, re-entrancy checked), plus a per-CPU preemption counter
- ✅ Lock-free SPSC ring buffer (for IRQ-to-task data such as UART receive)
- ✅ `SeqLock<T>`: readers retry instead of blocking the writer; byte-wise atomic copies keep racing reads sound
- ✅ `McsLock<T, G>` (also `IrqMcsLock`, `RawMcsLock`): an MCS queued spin lock, FIFO, each waiter spins on a flag in its own stack-allocated node; closure-based API (`with`, `try_with`) because nodes must not move, releases on unwind
- ✅ `Rcu` domain with `RcuCell<T>` (`alloc`): sleepable (SRCU-style) RCU with per-CPU two-slot reader counters, so it needs no scheduler hooks and works under host threads; readers may be preempted, migrate or block; `synchronize`/`synchronize_with` (caller-supplied wait, e.g. a yield) are blocking and serialized. Not supported: `call_rcu` callbacks, expedited grace periods, RCU-protected lists, and classic non-counting read sides (a read lock costs a SeqCst fence and two atomic increments)

### `osmium-mm`: memory management
- ✅ Typed `PhysAddr`/`VirtAddr` with alignment helpers and canonical-address checks
- ✅ `MemoryMap`: a fixed-capacity, heap-free region list that merges, carves and reserves (OSKit's LMM/AMM role, used at boot)
- ✅ Frame allocators: a bitmap allocator, and a buddy allocator (orders 0–N, intrusive free lists, coalescing)
- ✅ Generic multi-level page table `PageTable<F, A>` with map, unmap, translate, protect, huge-page `split` and `unmap_4k`, huge pages (2 MiB / 1 GiB), and freeing of intermediate tables
- ✅ PTE formats: x86_64 4-level and 5-level (`X86_64La57`), AArch64 stage 1 (4 KiB granule), RISC-V Sv39/Sv48/Sv57, Intel EPT, AArch64 stage 2, AArch64 EL2 stage 1 (`Aarch64El2`), RISC-V G-stage Sv39x4/Sv48x4 (multi-page roots via `PageTableFormat::ROOT_PAGES` and `TableAlloc::alloc_root`)
- ✅ IOMMU page-table formats: Intel VT-d second level (`VtdSecondLevel`), AMD-Vi I/O tables (`AmdVi`, 4 KiB pages; its entries record the child level, hence the level-aware `PageTableFormat::table_at` hook) and RISC-V IOMMU first stage (`Sv39Io`: Sv39 with `U` in every entry, which QEMU's model requires); Arm SMMUv3 stage 2 and RISC-V G-stage reuse `Aarch64Stage2` and `Sv39x4`
- ✅ Heap: a size-class slab front-end plus a large-allocation path over any `PageSource`; `LockedHeap` implements `GlobalAlloc`; works from a static arena (firmware) or the frame allocator (kernels)
- ✅ Virtual memory areas (`vma::VmaTree`, feature `alloc`): non-overlapping `start..end` ranges with `MapFlags`, in a fallible-allocation tree; `find`, `first_overlap`, `find_gap` (first fit), `insert` (extends an equal neighbour instead of allocating), `protect` (splits at both edges, nodes allocated before anything changes), `remove` (trim, split or delete; infallible given a preallocated `VmaSpare`), `try_clone` for fork
- ✅ 5-level paging page-table formats: `X86_64La57` (57-bit, `CR4.LA57`) and `Sv57` (`SatpMode::Sv57`), exercised by the generic `PageTable` tests. Not wired into any example kernel: LA57 can only be enabled before long mode is entered, and QEMU boots use 4 levels. AArch64 has no equivalent here (52-bit VA needs LPA2/LVA)
- 🗺 Typed frame metadata (as in OSTD's `Frame<M>`); `mprotect`/`mremap` and file-backed or swap-backed demand paging on top of the VMA tree

### `osmium-hal`: hardware abstraction
- ✅ MMIO: `ReadOnly`/`WriteOnly`/`ReadWrite<T>` register cells for `#[repr(C)]` register blocks, and a bounds-checked `IoMem` window (safe after an `unsafe` constructor)
- ✅ x86 `Port<T>` I/O
- ✅ Device-class traits: `SerialPort`, `InterruptController`, `Clock`/`OneShotTimer`, `BlockDevice`
- ✅ IRQ dispatch table: register handlers by number, dispatch from the trap path
- ✅ Global console with `print!`/`println!` that can be swapped at runtime
- ✅ DMA buffer descriptor (`DmaBuffer` with CPU and device addresses), self-freeing `OwnedDma`, and a `DmaAllocator` over any `LockedFrames`
- ✅ IOMMU model (`hal::iommu`): the `Iommu` trait (attach a device to a domain's page table, detach, invalidate a domain, `take_fault`), `IoDomain` (a table plus the devices attached to it; detaches before freeing, and leaks the table if a device will not detach), a page-granular `IovaAllocator`, and `IommuDma`, a `DmaAllocator` whose buffers a device reaches only at an I/O virtual address; host-tested with a fake unit
- ✅ `NetDevice` trait and `MacAddress`
- ✅ PCI: `ConfigAccess` over ECAM or x86 port I/O, brute-force enumeration, BAR probing and assignment (`BarAllocator`), capability lists
- ✅ PCI MSI and MSI-X: an architecture-neutral `MsiMessage`, MSI programming (32/64-bit, multiple vectors, per-vector masks), MSI-X tables and pending bits in a BAR window, entry and function masks, all bounds-checked against the device; x86 messages from `lapic::msi_message`
- ✅ USB: setup packets, standard descriptor parsing, the `UsbHost` host-controller trait, and generic device enumeration
- ✅ virtio constants and split-ring layout shared by drivers and device models (including virtio-pci capabilities and virtio-gpu commands)
- ✅ Displays: `Framebuffer` over any `IoMem` (16/24/32 bpp, any channel layout from VBE, GOP or virtio-gpu; fill, per-pixel drawing, 1-bpp bitmaps for fonts, scrolling) and the `Display` trait, whose `flush` serves devices that copy from guest memory
- ✅ Framebuffer text console (`osmium_hal::fbcon`): `FbConsole` implements `Console` on any `Framebuffer` (so any pixel format incl. 32-bit RGB/BGR), with an original 5x7 ASCII font in an 8x8 cell (integer scaling), cursor, wrapping, scrolling, `\n \r \b \t` and ANSI CSI cursor movement, erase (`J`, `K`) and 16-colour SGR; host-tested on Vec-backed framebuffers, not yet booted in an example
- ✅ Async device traits (`hal::asynch`): `AsyncBlockDevice`, `AsyncSerialPort` and `AsyncNetDevice` (not `Send`-bounded, no executor dependency; interrupt-driven drivers wake the task's waker, e.g. an `osmium-exec` `AtomicWaker`), plus `Blocking` (run a blocking `BlockDevice` to completion in one poll) and `Polled` (retry a serial port or `NetDevice` on "not ready", yielding between tries) adapters; host-tested. No driver implements the async traits natively yet, and there is no async timer or USB trait
- ✅ PCI bridge walking (`pci::walk`, `Bridge`): depth-first enumeration through PCI-to-PCI bridges that assigns primary/secondary/subordinate bus numbers, places unassigned memory BARs from a `BarAllocator` and programs each bridge's 1 MiB-granular non-prefetchable memory window around its subtree; host-tested against a simulated three-level hierarchy. Not done: I/O and prefetchable bridge windows (left closed), 64-bit windows above 4 GiB, hot-plug, ARI/SR-IOV bus reservation, and the examples still use the brute-force `for_each_function`

### `osmium-drivers`: reference drivers
- ✅ virtio-mmio transport (legacy and 1.x), split virtqueue
- ✅ IP over InfiniBand (`Mlx4::open_ipoib` → `IpoibPort`, a `NetDevice`): joins the broadcast group with the subnet administrator (retried with backoff), adopts the group's queue key, rewrites ARP and frames between Ethernet and IPoIB with invented MACs for neighbors; every unicast datagram uses the broadcast group's service level (no path record queries); simulator-tested only
- ✅ virtio-pci transport (modern, capability-located registers); tested against a fake function and on QEMU `virtio-gpu-pci`/`virtio-vga`
- 🗺 virtio-console emergency write and per-port names; virtio-gpu control-command completion by interrupt (a driver-level `handle_interrupt` exists, but no example routes the device's IRQ); xHCI streams and SuperSpeed burst sizes from companion descriptors; GICv3 ITS and LPIs; HPET message (FSB) interrupt delivery; an MSI-X vector per NVMe I/O queue

### `osmium-display`: display drivers
- ✅ virtio-gpu 2D as a `Display` (display info, resource create, attach backing, set scanout, transfer and flush), over MMIO or PCI; `virtio-vga` is a VGA (Bochs DISPI) until it takes over; checked by QEMU screendumps
- ✅ virtio-gpu cursor queue (`set_cursor` with a 64x64 ARGB image, `move_cursor`, `hide_cursor`/`show_cursor`; fire-and-forget, reaped by polling or the interrupt handler), `GET_EDID` (`VIRTIO_GPU_F_EDID`) parsed by `display::edid` (preferred mode, physical size, name; checked against hostile input), and `enable_interrupts`/`handle_interrupt` (acknowledge, reap cursor commands, flag display changes); control commands are still completed by polling; tested against a fake host (interrupts only there), and the cursor and EDID on QEMU `virtio-gpu-pci` and `virtio-gpu-device`
- ✅ virtio-console (`VirtioConsole`), MMIO or PCI transport, legacy or 1.x: a single port, or multiport with the control queues (`DEVICE_ADD`/`REMOVE`, `PORT_READY`/`PORT_OPEN`, console resize) for up to 4 ports; non-blocking reads and synchronous writes per port, port 0 as a `SerialPort` (so `SerialConsole` makes it the global console); tested against a simulated device, and on QEMU `virtio-serial-device` with `virtconsole` (riscv-virt writes a line the host reads from a chardev file); the PCI transport is shared with virtio-gpu but not booted with a console
- ✅ Bochs DISPI display (`BochsVbe`): QEMU std VGA, `bochs-display` and `virtio-vga` modes over MMIO on any architecture or ports on x86
- ✅ VESA BIOS Extensions: controller and mode information, mode search and LFB mode setting through a `VideoBios` (x86's real-mode thunk, or a fake in tests)

### `osmium-sysdrv`: UARTs, timers, `fw_cfg`, interrupt controllers and IOMMUs
- ✅ NS16550A UART (port I/O and MMIO backends)
- ✅ Arm PL011 UART
- ✅ Intel 8254 PIT (calibration delays)
- ✅ x86 HPET (`Hpet`: capability checks and a checked femtosecond period, the main counter as a `Clock` with 32-bit wrap extension, comparators as `OneShotTimer`s or periodic timers, legacy-replacement or I/O APIC routing, level acknowledgement; `boot::acpi::HpetTable` finds it). Host-tested against simulated registers; `x86_64-pc` boots it from the ACPI table under QEMU (agreement with the PIT, one-shot and periodic comparator interrupts through the I/O APIC)
- ✅ RISC-V CLINT (machine timer and software interrupts, for M-mode firmware)
- ✅ RISC-V PLIC
- ✅ Arm GICv2 (distributor + CPU interface, SGIs with correct source-CPU EOI)
- ✅ Arm GICv3 (distributor with affinity routing, per-CPU redistributors found by MPIDR affinity and woken, CPU interface through `ICC_*` system registers behind a `CpuInterface` trait, SPIs/PPIs/SGIs, priority, enable, pending, edge/level, SPI routing, SGIs by affinity, combined or split EOI); `aarch64-virt` probes `arm,gic-v3` and boots on either GIC. No ITS/LPIs, no secure-state or group 0 setup, no GICv4; QEMU only
- ✅ x86 local APIC (xAPIC MMIO, INIT/STARTUP IPIs)
- ✅ x86 I/O APIC (GSI routing, polarity/trigger, masking); the x86_64 example routes COM1's receive interrupt through it into an `SpscRing`
- ✅ Intel VT-d (`iommu::vtd::Vtd`): legacy-mode root and context tables, 48-bit four-level second-level tables, register-based context-cache and IOTLB invalidation (a firmware-enabled invalidation queue is switched off), fault-recording registers; refuses units without `ECAP.C` unless the caller vouches for coherency (`new_assuming_coherent`); boots against QEMU `intel-iommu` and `iommu-testdev`
- ✅ VT-d scalable mode (`Vtd::new_scalable`): scalable root table (two 128-function context tables per bus, 256-bit context entries), a PASID directory and table per device holding the `RID_PASID` (0) entry in second-level-only translation over the same `VtdSecondLevel` tables, all invalidation through a queued-invalidation ring (context, PASID-cache and IOTLB descriptors, 256-bit descriptors, wait-descriptor completion, error recovery); PASIDs other than 0, first-level and nested translation are not used; the QEMU boot (`intel-iommu,x-scalable-mode=on`) attaches and detaches the test device through it
- ✅ VT-d interrupt remapping (`iommu::vtd::remap`): interrupt remapping table sized 2 to 65536 entries, IRTE programming (`Irte`: vector, destination, delivery mode, logical or physical, trigger, redirection hint, source-ID verification by function or bus range) with index-selective interrupt-entry-cache invalidation through the queue, extended interrupt mode for x2APIC destinations, compatibility-format interrupts blocked or allowed, remappable-format MSI messages (`msi_message`, with sub-handles) and I/O APIC entries (`IoApic::route_remapped`); the QEMU boot (`intremap=on`) enables the table, programs and clears an entry through the real invalidation path and disables it, but no remapped interrupt is raised yet
- ✅ AMD-Vi (`iommu::amdvi::AmdVi`): device table, command buffer (device-table and page invalidations, completion waits) and event log, four-level I/O tables; the first attach blocks every other requester ID with an explicit entry, since an invalid entry passes DMA through; boots against QEMU `amd-iommu,dma-remap=on`
- ✅ Arm SMMUv3 (`iommu::smmuv3::Smmuv3`): linear or two-level stream table (64-entry level-2 pages allocated on first attach, `StreamTableLayout`), command and event queues, stage-2 contexts over `Aarch64Stage2`, stage-1 contexts (`Smmuv3::stage1`: one context descriptor per stream, ASID = domain, `Aarch64Stage1Io` tables) and nested stage 1 + 2 entries (`attach_nested`) (`CFGI_STE`, `CFGI_CD`, `TLBI_S12_VMALL`, `TLBI_NH_ASID`, `CMD_SYNC`), command-error recovery; host-tested against a simulated unit, and the aarch64-virt boot runs the stage-2 and the stage-1 two-level paths against QEMU `virt,iommu=smmuv3` (the stage-1 boot lines have not been run: this QEMU build lacks `iommu-testdev`)
- ✅ RISC-V IOMMU (`iommu::riscv::RiscvIommu`): two-level device directory with base or extended device contexts, first-stage Sv39 contexts (`PSCID` = domain), command queue (`IODIR.INVAL_DDT`, `IOTINVAL.VMA`, `IOFENCE.C`) and fault queue, `Bare` until the first attach; boots against QEMU `riscv-iommu-pci`, with NVMe running through it
- ✅ IOMMU huge mappings: `IoDomain::map` uses 2 MiB and 1 GiB block entries where the IOVA, physical address and length are aligned and the unit allows (`Iommu::max_leaf_size`: VT-d from `CAP.SLLPS`, SMMUv3 always; the other units stay on 4 KiB), `unmap` splits a block when only part of it goes, a failed map rolls back at block granularity, and `IovaAllocator::alloc_aligned` lets `IommuDma` line big buffers up for blocks; host-tested with a fake unit (no QEMU boot maps a block)
- ✅ PASIDs and ATS, generic half: PCIe PASID and ATS capability enable (`Function::pasid`, `Function::ats`), the `Pasid` type, default-methods on `Iommu` (`bind_pasid`, `unbind_pasid`, `max_pasid_bits`, `supports_ats`, `invalidate_device_tlb`), `IoDomain` bookkeeping (`bind_pasid`, `enable_ats`; unmap and drop invalidate the device caches of ATS devices, detach refuses while ATS is on), and wire-format builders for the VT-d device-TLB descriptors and SMMUv3 `CMD_ATC_INV` (`iommu::ats`). No driver implements the PASID or device-TLB methods yet (VT-d needs scalable mode and an invalidation queue, SMMUv3 needs ATS enabled in its stream table entries), so only the host fake exercises them and the descriptor layouts are unchecked against hardware
- 🗺 IOMMU: driver-side PASID tables and ATS invalidation queues (VT-d PASIDs other than 0 and first-level translation on top of scalable mode, SMMUv3) using the generic API, AMD-Vi interrupt remapping, large-page use on AMD-Vi and the RISC-V IOMMU, RISC-V G-stage and MSI page tables, and cache maintenance for units that do not snoop the CPU caches (VT-d without `ECAP.C` is still refused: the tree has no cache-flush primitive)

### `osmium-storage`: storage drivers
- ✅ RAM disk `BlockDevice`
- ✅ virtio-blk `BlockDevice` (read-only and flush features, requests split at 64 KiB)
- ✅ AHCI (SATA): HBA handoff and port bring-up, IDENTIFY, READ/WRITE DMA EXT and FLUSH CACHE EXT, native command queuing (up to 8 commands in flight), interrupt-driven completion (INTx or MSI, polled fallback kept), ATAPI optical drives as read-only block devices (IDENTIFY PACKET DEVICE, READ(10), READ CAPACITY) for `osmium-fs-iso9660`; each disk is its own `BlockDevice` that outlives the HBA; error recovery with CLO or COMRESET; boots against QEMU `ich9-ahci` + `ide-hd`
- ✅ NVMe: admin and one or several I/O queue pairs (Set Features / Number of Queues negotiated, up to eight, each with its own bounce buffers, command identifiers and spin lock, so `read_blocks_on`/`write_blocks_on`/`flush_on` and `Nvme::queue` handles run concurrently on different queues; `Nvme::new` keeps one pair, `Nvme::with_queues` asks for more and falls back to one if the controller refuses; phase tags, doorbell stride), IDENTIFY controller and namespaces, PRP lists, MDTS-limited splitting with up to four commands in flight (out-of-order completions), optional MSI-X completion interrupts (`Nvme::with_interrupts`, all queues sharing one vector; polling remains the default), normal shutdown on drop; a `BlockDevice` over the chosen namespace; boots against QEMU `nvme`

### `osmium-usb`: USB host controllers and class drivers

- ✅ xHCI USB host controller (`UsbHost`): polled command and event rings, root-port reset, control, bulk and interrupt transfers, interrupt endpoints that stay armed (`submit_in`/`poll_in`); interrupter 0 interrupts (`enable_interrupts`, `handle_interrupt`) file events with no one polling
- ✅ xHCI message interrupts: `enable_message_interrupts` programs MSI-X entry 0 (or a single MSI vector) on the PCI function through `hal::pci::msi`, falling back to INTx; `handle_interrupt` services every message since they are unshared
- ✅ UHCI, OHCI and EHCI host controllers (`UsbHost`), polled or interrupt-driven (`enable_interrupts`, `handle_interrupt`), sharing a device table and enumeration (`usbhc`): control, bulk and interrupt transfers; UHCI (I/O ports or MMIO) and OHCI serve low- and full-speed devices and full-speed hubs, and EHCI serves high-speed root ports and hands the other devices to its companion controller. Under QEMU, EHCI and OHCI run on riscv-virt and UHCI on x86_64-pc, each with a FAT32 USB stick, and on x86_64-pc an ICH9 EHCI hands a full-speed CDC-ECM adapter to its companion UHCI. Not supported: isochronous endpoints, hubs behind EHCI (split transactions)
- ✅ USB hubs: the `class::hub::Hub` class driver reads the hub descriptor, powers ports, resets a port that gets a device and reports connect/disconnect events from the status-change endpoint (or a `scan`); `UsbHost::attach_hub_port` and `configure_hub` give the xHCI slot context its route string, root port, hub/multi-TT/think-time fields and, for low/full-speed devices below a high-speed hub, the transaction translator; detaching a hub detaches what is behind it; USB 3 hubs get `SET_HUB_DEPTH`
- ✅ USB isochronous endpoints (`IsochHost` on xHCI): isoch endpoint contexts and Isoch TRBs (TBC/TLBPC), up to four queued one-interval transfers per endpoint started ASAP, in a given frame or one interval after the previous (`IsochStart::Next`), completions that report missed service intervals without halting the endpoint; `class::isoch::{IsochIn, IsochOut}` keep a stream queued for a class driver
- ✅ USB class drivers on any `UsbHost`: mass storage (SCSI over Bulk-Only) as a `BlockDevice`, and HID boot keyboards with US-layout key translation
- ✅ USB HID report descriptors (`class::hid`): `ReportDescriptor::parse` runs the short-item state machine (global/local/main items, `Push`/`Pop`, usage ranges and lists, extended 32-bit usages, delimiters, collections, report IDs, array vs variable, relative, null state, signed logical and physical ranges, units) into a fixed-capacity field table with no allocation; `HidDevice` fetches the descriptor from the interface and reads input reports; `Field::read`/`write` and `InputReport::for_each`/`value` extract and pack fields with checked bit arithmetic; `HidKeyboard` decodes any keyboard layout the descriptor can express (boot array, NKRO bitmaps, report IDs) and sets LEDs from the output report; `HidMouse` decodes relative and absolute pointers, buttons and wheels. Malformed descriptors are errors, never panics (fuzz-style tests); boots under QEMU `usb-kbd` and `usb-mouse`. Limits: 40 data fields, 128 listed usages, 4 KiB reports and a 1 KiB descriptor (the table is about 3 KiB, so it stays off small stacks); no gamepad class (reports decode through `InputReport`); no string/designator items; reports shorter than the descriptor says are dropped

### `osmium-netdev`: network device drivers

- ✅ virtio-net `NetDevice` (MMIO or PCI transport, legacy and 1.x), over the transports and queues of `osmium-drivers`
- ✅ Mellanox ConnectX-2/-3 (mlx4) Ethernet: reset, firmware start, ICM, raw Ethernet queue pair per port as a `NetDevice`, polled or interrupt-driven (`enable_msix`: async and completion event queues on two MSI-X vectors, `handle_interrupt`), IPv4/TCP/UDP checksum offload both ways and TCP segmentation offload through `EthPort::transmit_offload`/`receive_checked`/`offloads`; tested against a simulated HCA, not yet on hardware. Not supported: RSS, per-CPU completion vectors, MAC/VLAN steering, VLAN tag offload
- ✅ mlx4 InfiniBand (`Mlx4::open_ib` → `IbPort`): port bring-up as `mlx4_ib` does it (SET_PORT, queue pair 0 to RTR then INIT_PORT), queue pair 0 and 1 with the subnet manager's packets handed to the firmware agent (`service`: LID-routed and directed-route, including the end-node hop rules), PortInfo/GID/P_Key queries (MAD_IFC), an unreliable-datagram queue pair per port with `send`/`receive` addressed by LID, queue pair number and queue key (optional global route header), hardware multicast attach/detach, up to four reliable connections per port (`rc_create`/`rc_connect`/`rc_send`/`rc_write`/`rc_read`/`rc_poll`) with remote access confined to a per-connection registered window, polled or MSI-X, and VPI ports by what the cable senses; tested against a simulated HCA, not yet on hardware. Not supported: atomics, SRQ/XRC, alternate paths, RoCE, SR-IOV
- ✅ USB Ethernet (CDC-ECM) as a `NetDevice` on any `UsbHost`: functional-descriptor probing, MAC from the string descriptor, alternate-setting selection, notification-driven link state; boots under QEMU `usb-net` (its second configuration) and resolves ARP
- ✅ USB Ethernet (CDC-NCM) as a `NetDevice` on any `UsbHost`: shares ECM's descriptor probing, reads the NTB parameters, caps the device's NTBs at 4 KiB, receives every datagram of a 16-bit NTB (following NDP chains) and sends one frame per NTB, aligned as the device asks. Tested against a simulated device only, since QEMU has no NCM device. Not supported: 32-bit NTBs, CRC mode, batching several frames into one transmitted NTB

### `osmium-sched`: tasks and scheduling
- ✅ Real context switch for x86_64, AArch64 and RISC-V 64 (naked functions; callee-saved registers only)
- ✅ `Task`, built with `TaskBuilder` (name, priority, stack size, home CPU)
- ✅ Injectable `Scheduler` trait (as in OSTD) and the core operations: `yield_now`, `block`/`wake`, `exit`, tick-driven preemption, and `on_cpu` hand-off so global run queues are safe on SMP
- ✅ Pluggable `StackAllocator` (for example, stacks with guard pages; the x86_64 example kills a task that overflows into its guard page and keeps running)
- ✅ Context-switch hook (`set_switch_hook`) and `Task::kernel_stack_top`, for per-task CPU state such as the x86 TSS stack, address space or FPU
- ✅ Remote-wake hook so kernels can IPI a CPU when work is queued there; task migration with `Task::set_cpu`
- ✅ Ready-made policies: `FifoScheduler` (round-robin with a time slice) and `PriorityScheduler` (O(1) bitmap, 64 levels)
- ✅ CPU affinity masks (`Task::set_affinity`, `pin`, `TaskBuilder::affinity`; `TaskBuilder::cpu` pins) and opt-in load balancing (`with_stealing`): idle CPUs steal queued tasks they may run, new and woken tasks are placed on idle CPUs, and a task still saving its registers is never stolen
- ✅ `WaitQueue` (no lost wake-ups), sleeping `Mutex`, `Semaphore`
- ✅ `TimerQueue`: deadline-ordered callbacks driven by the timer IRQ
- ✅ `osmium-exec`: heap-free async executor (fixed task slots, interrupt-safe wakers, idle-until-interrupt without lost wake-ups, `run_with` for stack-pinned `async fn`s), `Signal`, `AtomicWaker`, `StaticCell`
- ✅ `EdfScheduler`: earliest-deadline-first (per-task relative deadline and period via `TaskBuilder`/`Task` setters, preempts on an earlier-deadline wake at the next tick, FIFO ties, optional stealing that respects affinity)

### `osmium-boot`: boot protocols
- ✅ Flattened Device Tree (DTB) parser: zero-copy nodes and properties, `reg` decoding with `#address-cells`/`#size-cells`, `compatible` search
- ✅ FDT writer (`alloc`), for hypervisors that generate guest device trees
- ✅ Multiboot2 parser: memory map, command line, modules
- ✅ Conversion of firmware memory maps into `osmium_mm::MemoryMap`
- ✅ ELF64 executables: validated parsing of loadable segments, and `Elf::load_into` any `PageTable` (per-segment permissions, zeroed `.bss`, shared pages merged); all three examples run the same Rust user program (`examples/user/hello.rs`) built as an ELF
- ✅ PVH start-info parser and the `pvh_entry_note!` ELF-note macro
- ✅ ACPI: RSDP/RSDT/XSDT with checksums, MADT (local APICs, x2APICs, I/O APICs), MCFG (PCI ECAM windows), DMAR (VT-d units), IVRS (AMD IOMMUs)
- ✅ UEFI: system table, console output, `LocateProtocol`, `Stall`, `ResetSystem`, and the Graphics Output Protocol (mode list, mode set, framebuffer as `FramebufferInfo`, `Blt` fill for framebuffer-less modes)
- 🗺 Fuller UEFI boot services (memory map, `ExitBootServices`), Limine protocol

### `osmium-acpi`: ACPI and AML
- ✅ FADT: the DSDT address (64-bit field preferred), SCI interrupt, SMI command port and enable/disable values, PM1a/PM1b event and control blocks, PM timer, GPE blocks 0 and 1, reset register, sleep control/status registers of hardware-reduced machines, fixed-feature flags; legacy I/O-port blocks and the extended Generic Address Structures are both understood
- ✅ AML interpreter (`aml::Interpreter`): loads the DSDT and SSDTs/PSDTs into a namespace (creation-ordered, so `_INI` runs in the order the firmware declared), runs control methods, and reaches the machine through the `Host` trait (memory, port I/O, PCI configuration space, other address spaces such as the embedded controller, `Sleep`/`Stall`/`Timer`, `Notify`, `Debug`, `Fatal`, `_OSI`)
- ✅ The whole of the term language of ACPI 6: integers (32-bit in revision 1 tables, 64-bit from 2), strings, buffers and packages, all arithmetic, logical and bitwise operators, `Concatenate`, `Mid`, `Match`, `Index`, `RefOf`/`DerefOf`/`CondRefOf`/`CopyObject`, the `To*` conversions with the implicit-conversion rules, `ObjectType`, `SizeOf`, `If`/`Else`/`While`/`Break`/`Continue`/`Return` (and `Switch`, which the compiler lowers to those), method calls with recursion, method-local named objects that go away with the call, mutexes and events, `Alias`, `Device`/`Processor`/`ThermalZone`/`PowerResource` scopes, `ConcatenateResTemplate`
- ✅ Operation regions and fields: system memory, system I/O, PCI configuration (the device is found through `_ADR`, `_BBN` and `_SEG`, and through the secondary bus numbers of any PCI-to-PCI bridges above it) and any other space through the host; `Field`, `IndexField` and `BankField`; access widths (byte to qword, and the narrowest aligned unit for `AnyAcc`); `Preserve`, `WriteAsOnes` and `WriteAsZeros`; fields wider than an integer as buffers; `CreateBitField` to `CreateQWordField` and `CreateField`; accesses are checked against the region's length
- ✅ Initialization in the specified order (`_REG` for the spaces the host serves, `\_SB._INI`, then `_STA` and `_INI` down the device tree, skipping the children of devices that are neither present nor functioning); `Name` initializers are evaluated when first used so a table can refer to names declared after it; a name declared twice (across SSDTs) is skipped with a warning
- ✅ Hostile-firmware discipline: every parse is bounds-checked; nesting depth, term count and sleep time are budgeted per call (`Config`); buffers, packages and fields have size limits; a table that fails stops loading at that point and a method that fails fails that call; nothing panics (mutation-fuzzed in debug builds, which also trap arithmetic overflow)
- ✅ Devices: identity (`_HID` with compressed EISA ids decoded, `_CID`, `_UID`, `_ADR`, `_STA`) and search by hardware id; `_CRS`/`_PRS` decoded into `Resource` (IRQ, DMA, I/O, fixed I/O, 24- and 32-bit memory, Word/DWord/QWord/Extended address spaces, extended interrupts, generic registers, vendor and raw descriptors) and `_SRS` set from them
- ✅ PCI interrupt routing: `_PRT` read into rows and resolved to a GSI with trigger and polarity, directly or through interrupt link devices' `_CRS`
- ✅ Power management (`pm::Pm`): entering ACPI mode through the SMI command port, sleep types from `_S0_`..`_S5_`, `enter_sleep_state` (`_TTS`, `_PTS`, `_GTS`, `SLP_TYP` then `SLP_EN` on PM1a/PM1b or the hardware-reduced sleep control register, the wait for `WAK_STS` and `_WAK` for S1 to S3), `power_off`, `reset` through the reset register (memory, I/O or PCI configuration space), the PM timer
- ✅ The SCI: fixed events (power and sleep buttons, RTC alarm, timer, global lock) enabled and cleared, and GPEs from both blocks dispatched to `_Exx` (cleared first) and `_Lxx` (masked while the method runs), with unhandled GPEs disabled so they cannot storm
- ✅ Tested on the host with ASL compiled by `iasl` (`crates/acpi/tests/asl`, which also has the script to rebuild them): self-checking language tests, field layout and access-sequence tests against a recording host, device and routing tests, a FADT-driven power-management test against emulated registers; against QEMU's q35 DSDT in `examples/x86_64-pc` (devices, resources, `_PRT`, `_S5_`, and the machine powered off through it under check.sh); and against any machine's own tables with `ACPI_TABLES_DIR` (`tests/real_firmware.rs`)
- 🗺 `Load`, `LoadTable`, `Unload` and `DataTableRegion`; the Global Lock handshake with the firmware (`Acquire(\_GL_)` succeeds at once, and the lock rule of a field is ignored); mutex ownership and timeouts and blocking event waits (the interpreter is single-threaded); buffer-access (SMBus, IPMI, GenericSerialBus) fields; packages and buffers passed to a method are copies, so a method cannot modify its caller's package through `Index`; GPIO and serial-bus descriptors are kept as raw bytes; wake-capable devices (`_PRW`); processor power states and performance control (`_CST`, `_PSS`); thermal zones and battery methods are plain methods the caller evaluates

### `osmium-fs`: file systems
- ✅ `File` trait: one node (file, directory, device, symlink), stateless and offset-based like `pread`/`pwrite`, with defaults so a device implements only what it supports; `Stat`, `DirEntry`, `FileKind`
- ✅ `Errno` with Linux numbers, and osmium's own `OpenFlags` for system call layers to translate into
- ✅ `Vfs`: absolute-path lookup across mounts (`..` leaves a mount at its root), symbolic links (40 deep), trailing-`/` rules, `open` with create/exclusive/truncate, `mkdir`, `mknod`, `unlink`, `rmdir`, `symlink`, `readlink`, `stat`/`lstat`, `canonicalize`, copy-on-write mount table
- ✅ `RamFs` (tmpfs), with unlinked-but-open files kept alive
- ✅ `DevDir` for a kernel-populated `/dev`, plus null and zero devices
- ✅ cpio `newc` archives: zero-copy iteration and initramfs unpacking (concatenated archives, `..` refused), tested against GNU cpio
- ✅ ext2/3/4 (`osmium-fs-ext4`), read and write, over any `BlockDevice`: indirect block maps, sparse files, fast and slow symlinks, allocation, truncation, orphaned open files; tested with `mkfs.ext2 -d`, `e2fsck` and `debugfs`
- ✅ ext3 and ext4 through the same driver: extent trees (lookup, insertion with node splits, truncation; new files get extents), preallocated extents split as they are written, `64bit`, `flex_bg`, `meta_bg`, uninitialized bitmaps and inode tables, `metadata_csum` (superblock, group descriptors, bitmaps, inodes, extent and directory blocks) and `uninit_bg` checksums verified on read and kept on write, `huge_file`, `dir_nlink`; hashed directory indexes dropped on change. The JBD2 journal is replayed at mount and used for every change (metadata logged and committed before it is written in place, data ordered before the commit, blocks freed by an operation not reused by it), including logs from Linux with revoke records, `64bit` tags and `csum_v3`; a journal of another kind is left alone when clean. `inline_data`, encryption and casefolding are refused. Tested with default `mkfs.ext4` images, `e2fsck -fD`, `debugfs fallocate`, journals written by `debugfs` and crashes injected after every device write, checked by our own recovery and by `e2fsck`
- ✅ FAT12, FAT16 and FAT32 (`osmium-fs-fat`), type told by cluster count, 12-bit packed entries and the fixed root directory of FAT12/16 handled, read and write, over any `BlockDevice`: VFAT long names with generated `~N` short names, case-insensitive lookup, every FAT copy and the FSInfo free count kept current, orphaned open files; tested with `mkfs.fat` and `fsck.fat`
- ✅ ISO 9660 (`osmium-fs-iso9660`), read-only, over any `BlockDevice` of any block size: Rock Ridge (names, modes, link counts, symlinks, device nodes, `CE` continuations, `CL`/`RE` deep-directory relocation), else Joliet Unicode names, else plain names shown like Linux `map=normal`; multi-extent (over 4 GiB) and interleaved files; tested with `xorriso` and `genisoimage` images
- 🗺 A block cache, rename and hard links, timestamps from a clock in the VFS

### `osmium-virt`: hypervisor building blocks
- ✅ `GuestPhysAddr`, and `GuestMemory`: a GPA-to-host region map with bounds-checked `read`/`write`/`read_obj`/`write_obj` and a `Pod` marker
- ✅ Stage-2 page tables: `osmium_mm` `PageTable` with the `Ept`, `Aarch64Stage2` and `Sv39x4`/`Sv48x4` formats; EPTP, VTTBR and hgatp encoders
- ✅ `MmioBus` / `PioBus` device dispatch (as in rust-vmm `vm-device`)
- ✅ Normalized `VmExit` enum, `Vcpu` trait, and a generic `run_vcpu` loop that services MMIO and PIO exits
- ✅ An emulated 16550 UART device, with an optional receive-interrupt line
- ✅ An emulated 8259A PIC pair (`VirtualPic`: init sequence, masks, IRR/ISR, EOI, cascade) whose output and INTA drive the SVM vCPU
- ✅ An emulated 8254 PIT (`VirtualPit`: modes 0, 2, 3 and 4, counter latch, read-back) counting in host time, channel 0 on IRQ 0; `poll` and `next_deadline` let the host deliver ticks on time
- ✅ An emulated xAPIC local APIC (`VirtualLapic`: TPR/PPR, IRR/ISR, EOI, SVR, one-shot and periodic timer, self IPIs and an IPI hook for other vCPUs); the 64-bit x86_64-hyp guest takes its timer through a 64-bit IDT
- ✅ An emulated I/O APIC (`VirtualIoApic`: 24 redirection entries, edge and level inputs, remote IRR cleared by the local APIC's EOI through `VirtualLapic::with_eoi`); the 64-bit x86_64-hyp guest takes COM1's IRQ 4 through it
- ✅ Multi-vCPU x86 guests: INIT/STARTUP decoded from the vLAPIC's ICR (`decode_icr`) into `GuestCpus` start requests, APs started in real mode (`SvmVcpu::set_real_mode`), fixed IPIs between vCPUs' APICs; x86_64-hyp starts a second host CPU and runs a two-vCPU guest whose AP goes from real to protected mode and IPIs the BSP, which waits in guest code and is reached by a host IPI kick
- ✅ An emulated GICv2 (`VirtualGicV2`: distributor and per-CPU interfaces for up to 8 vCPUs, banked SGIs/PPIs, SPI targets, `GICD_SGIR`, priorities, PMR, acknowledge/EOI) driving the AArch64 vCPU's virtual IRQ; the guest's virtual timer feeds it, with expiries during a guest run exiting through the host GIC
- ✅ An emulated PLIC (`VirtualPlic`, QEMU `virt` register layout) whose S-mode context outputs drive vCPU external-interrupt lines (`hvip.VSEIP`)
- ✅ RISC-V guest device trees (`riscv::fdt::GuestMachine`): harts, memory, PLIC, 16550s and virtio-mmio, in the layout Linux expects
- ✅ virtio device models: split virtqueue over `GuestMemory`, the virtio-mmio (v2) transport as a bus device, virtio-console, virtio-blk (over any `BlockDevice`) and virtio-net (over a pluggable `NetBackend`), sharing `osmium_hal::virtio` definitions (including `blk`) with the drivers
- ✅ RISC-V H-extension `Vcpu` (`riscv64-hs`): world switch through the trap entry's guest-exit hook, VS CSR switching, MMIO emulation from guest-page faults (`htinst` or `hlvx`-fetched instruction, compressed forms included), `wfi` halts, host-interrupt exits, and a minimal SBI (BASE, TIME, SRST, DBCN, legacy), and multi-vCPU guests (`GuestHarts`: SBI HSM start/stop/status, IPIs injected as `VSSIP`, RFENCE as deferred `fence.i`/`hfence.vvma`, and kicks of vCPUs running on other host CPUs), and guest floating-point state (D) switched per run
- ✅ AMD SVM `Vcpu`: VMCB setup for a 32-bit flat guest, nested paging with `X86_64` tables, VMRUN world switch under CLGI/STGI, port I/O, `hlt`, `vmmcall` and interrupt exits, MMIO from nested page faults (a decoder for the MOV/MOVZX forms drivers use, with decode assists or a fetch from guest memory), interrupt injection through `EVENTINJ` with interrupt-window exits and re-injection of interrupted events, 64-bit guests on their own page tables (MMIO instructions fetched through a guest page walk), and FS/GS/TR/syscall state switched with VMLOAD/VMSAVE
- ✅ AArch64 EL2 `Vcpu` (`aarch64-el2`, non-VHE): world switch through guest-exit hooks in the lower-EL vectors, EL1 system-register switching, stage 2 via `VTTBR_EL2`, MMIO emulation from data-abort syndromes, trapped `wfi`, IRQ exits, a virtual-IRQ line (`HCR_EL2.VI`), and PSCI for guests, including `CPU_ON`/`CPU_OFF`/`AFFINITY_INFO` for multi-vCPU guests (`smp::GuestCpus`, shared with RISC-V), and guest FP/SIMD state switched per run
- ✅ Intel VMX `Vcpu` (`x86::vmx`): capability-checked controls, EPT with VPID and unrestricted guest, VMLAUNCH/VMRESUME world switch, port I/O, `hlt`, `vmcall`, CPUID, MSR (syscall MSRs and `TSC_AUX` through the entry/exit MSR lists), CR0/CR4/CR8 exits, guest hardware breakpoints (debug registers swapped with the host's), MMIO from EPT violations, event injection with interrupt-window exits and re-injection of interrupted events, VMX hidden from the guest, guest FP state switched per run, vCPU migration between host CPUs (`with_migration`), and host NMIs delivered with a hardware-style frame; run under nested KVM, chosen at boot next to SVM, in `examples/x86_64-hyp` (all its demos and the x86_64-pc guest kernel)
- 🗺 Virtual interrupt controllers (APLIC/IMSIC, GICv3)

### `osmium-proc`: processes and system calls
- ✅ `Process`: a user address space, a descriptor table of `osmium_fs::File`s, working directory, program break, `mmap` area and exit status, attached to its task through `TaskBuilder::data`; `current`, `root_for` (the switch hook's table), `exit`, `wait`, lookup by `Pid`
- ✅ `AddressSpace<F, A>`: shares the kernel's root entries, loads ELF or flat images, maps and unmaps anonymous memory, and frees its pages with the process; user copies walk the process's own table (user-accessible, writable for stores) and go through the physical mapping, so no SUM/PAN/SMAP handling is needed
- ✅ One portable dispatcher with each architecture's Linux numbers, open flags and `struct stat`: `read`, `write`, `readv`, `writev`, `openat`, `close`, `lseek`, `fstat`, `newfstatat`, `getdents64`, `ioctl`, `getcwd`, `chdir`, `mkdirat`, `unlinkat`, `exit`, `exit_group`, `getpid`, `getppid`, `gettid`, `brk`, `mmap` (anonymous), `munmap`, `sched_yield`, `uname`; `syscall::handle` decodes the trap frame on RISC-V, AArch64 and x86_64
- ✅ All three examples run their user programs as processes; the Rust user program exercises `getpid`, `uname`, `brk`, `mmap` and `writev`
- ✅ `fork`, `vfork` and `clone` (processes, `CLONE_PARENT_SETTID`/`CLONE_CHILD_SETTID`; threads below), with copy-on-write sharing of the address space (per-frame reference counts; write faults reach `osmium_proc::handle_page_fault` from the kernel's trap handler, and kernel copies to user memory copy shared pages first). `mmap` of private anonymous memory is demand-paged: it reserves a VMA (`UserMemory::map_lazy`) and the first touch, by user code through the page-fault path (`handle_page_fault` for reads, fetches and writes) or by a kernel copy (`read`/`write`), allocates and zeroes the page; `munmap` cuts the area, and `fork` clones the areas and shares the pages already there copy-on-write and shared open file descriptions; `execve` of static ELF executables from the VFS, with argv, envp and auxv (`AT_PHDR`, `AT_ENTRY`, `AT_RANDOM`, ...) on a fresh stack; `wait4` (pid or any, `WNOHANG`); `dup`, `dup2`, `dup3`, `fcntl` and close-on-exec. The kernel supplies a `Platform` (address-space factory, table activation, child resume via `resume_user` in `osmium-arch`); riscv-virt, aarch64-virt and x86_64-pc run an init that forks, waits and execs itself
- ✅ Threads: `clone` with `CLONE_THREAD` (`CLONE_VM|FS|FILES|SIGHAND`, `SETTLS`, `PARENT_SETTID`, `CHILD_SETTID`, `CHILD_CLEARTID`) adds a task to the process with its own thread id, signal mask and thread pointer (trap-frame register on RISC-V and AArch64, `FS.base` through `arch_prctl` and the switch hook on x86_64); `exit` ends one thread, `exit_group` or a fatal signal all of them, and the process ends with its last thread; `set_tid_address`, `gettid`, and `set_robust_list`/`get_robust_list` (a dying thread marks the futexes it owns `FUTEX_OWNER_DIED` and wakes a waiter), and `futex` with `WAIT`/`WAKE`, `REQUEUE`/`CMP_REQUEUE`, `WAKE_OP`, the `_BITSET` variants and timeouts (given a clock with `futex::set_clock` and a `futex::tick` from the timer interrupt; otherwise a timed wait is `ENOSYS`); priority-inheritance futexes are `ENOSYS`. `execve` from any thread ends the others, and the caller takes the process id as its thread id; `wait4` sees a process only once its last thread has gone. `init` also sleeps three threads on one futex, requeues and wakes them All threads of a process share one CPU until unmapping shoots down TLBs
- ✅ Signals: `rt_sigaction`, `rt_sigprocmask`, `rt_sigpending`, `kill`, `tkill`, `tgkill`, default actions (terminate, or ignore), delivery to a user handler on a signal frame when returning to user mode, `rt_sigreturn` through a kernel-mapped trampoline (or `SA_RESTORER` on x86_64), `SIGCHLD` to the parent when a child exits, `SIGSEGV` (and `SIGBUS`/`SIGILL`) for user faults; the three examples' `init` runs handlers, joins a thread with `futex` and stops a spinning thread with `exit_group`
- ✅ Queued signals and job control: real-time signals (32 and up) queue per send, with `rt_sigqueueinfo`/`rt_tgsigqueueinfo` carrying `si_code` and `si_value` (128 entries per process and per thread, then `EAGAIN`); `sigaltstack` with `SA_ONSTACK`; `rt_sigsuspend`; `SIGSTOP`/`SIGTSTP`/`SIGTTIN`/`SIGTTOU` stop the process and `SIGCONT` resumes it, reported by `wait4` with `WUNTRACED`/`WCONTINUED` and by `SIGCHLD` (unless `SA_NOCLDSTOP`). A stop takes effect when a thread next enters the kernel; there are no process groups or terminals, so `SIGTTIN`/`SIGTTOU` come only from `kill`. `init` runs all four on every example
- ✅ `AF_INET` sockets as files in the descriptor table (so `dup`, `fork`, `read`, `write` and `close` work): `socket`, `bind`, `listen`, `accept`/`accept4`, `connect`, `sendto`, `recvfrom`, `shutdown`, `getsockname`, `getpeername`, `setsockopt`/`getsockopt` (`SO_RCVTIMEO`/`SO_SNDTIMEO`, `SO_ERROR`, `SO_TYPE`; others accepted and ignored) for `SOCK_STREAM` and `SOCK_DGRAM`, with `O_NONBLOCK`/`SOCK_NONBLOCK`/`MSG_DONTWAIT`. The kernel hands over a `NetStack` (an `osmium-net` interface, any `NetDevice` and a socket set) with `net::set_stack` and polls it; blocked tasks sleep on its wait queue. `sendmsg`/`recvmsg` (iovec scatter/gather, `msg_name`, `MSG_TRUNC` reported; no ancillary data), `MSG_PEEK`, and `socketpair` (`AF_UNIX` stream or datagram pairs in memory, unnamed). Traffic to 127.0.0.0/8 is delivered inside the `NetStack` with no device, even before the interface has an address. `poll`/`ppoll`/`select`/`pselect6` and `epoll` (`epoll_create1`, `epoll_ctl`, `epoll_wait`/`epoll_pwait`; level-triggered, `EPOLLET` approximated as new-since-last-check, `EPOLLONESHOT`, one level of epoll nesting) read a new `File::poll` readiness method (default: always ready) on any descriptor. Timeouts need a clock (`poll::set_clock` or the network stack's); the signal-mask arguments are validated and ignored. riscv-virt runs `examples/user/net.rs`: a TCP echo round trip, a TFTP read over UDP, a socketpair with `sendmsg`/`recvmsg`/`epoll`, and UDP over loopback with `MSG_PEEK`. Not yet: listen-socket address reuse, listeners bound to one address (a loopback-only listener also accepts from the network), `AF_UNIX` names and `SCM_RIGHTS`, `epoll_pwait2`
- ✅ Pipes: `pipe` (x86_64) and `pipe2` (`O_NONBLOCK`, `O_CLOEXEC`) make a read end and a write end, each its own open file description with its own `O_NONBLOCK` (`fcntl`); 64 KiB buffer, writes up to `PIPE_BUF` (4 KiB) all or nothing, end of file once the write end is closed, `EPIPE` plus `SIGPIPE` with no reader, `poll` readiness (`POLLIN`/`POLLHUP`, `POLLOUT`/`POLLERR`). Not yet: `O_DIRECT` packet mode, `splice`/`tee`, named FIFOs
- 🗺 Restartable system calls, priority-inheritance futexes, threads on several CPUs, PIE and dynamically linked executables, file-backed `mmap`

### `osmium-net`: IPv4 networking
- ✅ A polled `Interface` over any `NetDevice`: ARP with a neighbor cache, retries and a queue for unresolved packets, IPv4 routing to on-link hosts or the gateway, ICMP echo replies and port-unreachable errors; the caller supplies the time and decides when to poll (`poll_at`)
- ✅ Sockets in a `SocketSet`: `TcpSocket` (RFC 9293 state machine, RFC 6298 retransmission timing with backoff, zero-window probes, MSS option, RFC 5961 reset and SYN checks), `UdpSocket`, `IcmpSocket` (ping) and `DhcpClient` (discover, request, renew at T1, NAK and expiry), which configures the interface itself
- ✅ TCP receive reassembly: data past a gap is held inside the window (merged ranges, bounded) and delivered in order once the gap fills, an early FIN waits for its data, and every out-of-order segment is acknowledged at once
- ✅ TCP congestion control (RFC 5681, 6582, 6928): ten-segment initial window, slow start, congestion avoidance, fast retransmit and NewReno fast recovery with partial ACKs, and a one-segment restart after a timeout
- ✅ TCP window scaling (RFC 7323, up to a 1 GiB receive buffer) and SACK (RFC 2018 blocks from the reassembly queue, a sender scoreboard and RFC 6675-style recovery that resends exactly the reported holes), both negotiated in the handshake
- ✅ `DnsClient`: a pollable stub resolver for A records over a `UdpSocket`, using the DHCP-reported server or explicit ones, with random ids, question/source validation, CNAME chains, retries with backoff across servers, a TTL cache and short negative caching
- ✅ IPv4 fragment reassembly (timeouts, bounded buffers, overlaps condemn the datagram) and send-side fragmentation of UDP and ICMP datagrams larger than the MTU
- ✅ TCP initial sequence numbers follow RFC 6528 (a keyed SipHash of the four-tuple plus a clock); the generator is keyed from the seed and any entropy the caller supplies (`Interface::new_with_entropy`, `add_entropy`)
- ✅ IPv6 beside IPv4 (`Interface::enable_ipv6`): link-local address from the MAC (EUI-64), duplicate address detection, neighbor discovery in place of ARP (solicitation and advertisement, hop-limit 255 checks, a neighbor cache with a queue for unresolved packets), router solicitation and advertisement for SLAAC (/64 prefixes, lifetimes, default router, MTU and RDNSS options), static addresses and gateway, ICMPv6 echo and port-unreachable errors, UDP and TCP over IPv6 with pseudo-header checksums, and IPv6 header parsing that walks extension headers safely (bounded, option and length checked, routing headers with hops left refused). Sockets take `SocketAddr`, so a `UdpSocket`, `TcpSocket` or `IcmpSocket` is v4 or v6; `DnsClient::resolve6` asks for AAAA records, including through IPv6 servers. IPv6 fragments are not reassembled and large datagrams are not fragmented on send
- ✅ `wire`: Ethernet, ARP, IPv4 (with fragment fields), ICMP, UDP and TCP headers (MSS, window scale, SACK and timestamp options), IPv4 options and IGMP and the Internet checksum, usable on their own
- ✅ Tested on the host over a simulated link that drops, duplicates and reorders frames (TCP bulk transfers, fragments, DNS), and under QEMU against the user-mode network (DHCP lease, ping, DNS lookup, TCP echo)
- ✅ IPv4 header options are validated on receive (lengths walked, unknown options skipped, source-routed packets dropped, no panics on malformed headers); fragments are bounded in count as well as in datagrams, so a stream of tiny fragments cannot grow the bookkeeping
- ✅ IPv4 multicast: `join_multicast_group` / `leave_multicast_group`, IGMPv2 (unsolicited reports, randomly delayed answers to queries, report suppression, leave messages, IGMPv1 router compatibility, router alert option), the RFC 1112 multicast MAC mapping, multicast UDP send (TTL 1 by default) and receive on joined groups
- ✅ TCP timestamps (RFC 7323): negotiated in the handshake, a round-trip sample from every ACK of new data (also for retransmissions), PAWS against old duplicates, and the MSS reduced by the option
- ✅ DNS over TCP (RFC 7766): a truncated UDP response is retried over a TCP connection to the same server with length-prefixed framing, falling back to the partial answer if the connection fails
- 🗺 IPv6 fragmentation, privacy addresses and DHCPv6

### `osmium-iscsi`: iSCSI initiator
- ✅ RFC 7143 login (AuthMethod None, operational negotiation honouring the target's answers), SendTargets discovery, full-feature phase with immediate data, unsolicited Data-Out and R2T-driven writes, multi-PDU Data-In, NOP-In replies and logout; SCSI INQUIRY, TEST UNIT READY, READ CAPACITY(10/16), READ/WRITE(10/16) and SYNCHRONIZE CACHE as a `BlockDevice` over an `osmium-net` TCP socket
- ✅ Tested on the host against an in-process target and `scripts/iscsi-target.py` (a stdlib-only target), and under QEMU through a user-network `guestfwd` to that script
- ✅ CHAP-MD5 authentication (one-way and mutual, credentials in `Options::chap`; local no_std MD5) and CRC32C header/data digests (`Offer::header_digest`/`data_digest`: off, prefer or require), tested against the in-process target and `scripts/iscsi-target.py` (`--chap`, `--mutual-chap`, `--digests`)
- 🗺 Login redirection, error recovery levels above 0, multiple connections and LUNs per session

### `osmium`: the umbrella crate
- ✅ Re-exports every component, each behind a Cargo feature of the same name

### Tooling and examples
- ✅ Host unit and integration tests for every crate
- ✅ Builds for `x86_64-unknown-none`, `aarch64-unknown-none-softfloat` and `riscv64imac-unknown-none-elf`
- ✅ `examples/riscv-virt`: a bootable kernel for QEMU `virt` that uses the FDT, the memory map, the buddy allocator, the heap, W^X Sv39 paging, the 16550 driver, the scheduler with timer-interrupt preemption, and `TimerQueue` sleeps; it also runs two guests in VS-mode under the H extension, the second built from osmium's own UART, PLIC, virtio-net and virtio-blk drivers, taking timer, UART and virtio interrupts through the emulated PLIC and writing a sector the host then reads off its RAM disk, and a third with two vCPUs on two host harts that start each other through SBI HSM and exchange an IPI
- ✅ `examples/aarch64-virt`: the same on QEMU AArch64 `virt` (GICv2 or GICv3, PL011, generic timer, stage-1 paging, PSCI)
- ✅ `examples/aarch64-hyp`: a hypervisor that stays at EL2 (QEMU `virtualization=on`), turns on the EL2 MMU and runs EL1 guests under stage 2, one of which takes its virtual timer and a UART interrupt through the emulated GICv2; brings up a second host CPU at EL2 and runs a two-vCPU guest that starts its CPU with PSCI and signals it with an SGI
- ✅ `examples/x86_64-hyp` also boots a whole guest kernel when QEMU's loader provides one: Osmium's own `x86_64-pc` runs as a two-vCPU PVH guest (`x86::pc::PcBoot`: start info, memory map, RSDP/XSDT/MADT) with a local APIC per vCPU, the I/O APIC, COM1, the PIT with port 0x61, emulated MSRs (`SvmVcpu::emulate_msr`, TSC_AUX switched around VMRUN), x87/SSE state switched per vCPU with FXSAVE/FXRSTOR when asked (`with_fp_switching`: two SSE guests interleaved on one CPU keep their registers), and a host tick for its timers; SMP scheduling, ring-3 processes, fork/execve and interrupt-driven COM1 input pass inside it
- ✅ `examples/aarch64-hyp` also boots a whole guest kernel when QEMU's loader provides one: Osmium's own `aarch64-virt` runs as a two-vCPU EL1 guest under a generated device tree (`aarch64::fdt::ArmMachine`), the emulated GICv2 and PL011 (`devices::Pl011`), the virtual timer and PSCI, with SGIs between its CPUs, preemption, migration, load balancing, EL0 processes and fork/execve/wait4
- ✅ `examples/riscv-hyp`: boots a whole guest kernel from an ELF image QEMU's loader places in RAM, with a generated device tree, an emulated 16550 and PLIC, and SBI from the hypervisor, one vCPU per host hart (kicked with host IPIs), a virtio-blk disk over a host RAM disk and a virtio-net card bridged to the host's own virtio-net. Under check.sh the guest is Osmium's own `riscv-virt` kernel on two vCPUs, which runs its scheduler, timer preemption, cross-CPU migration and load balancing, DHCP, ping and a TCP echo through the bridged network, a block round trip the host then finds on its RAM disk, fault and stack-guard demos, U-mode processes and fork/execve/wait4 in VS-mode, skips its own hypervisor demos (no `h` in its `riscv,isa`) and shuts down through SBI
- ✅ `examples/x86_64-hyp`: enables AMD SVM (TCG with `-cpu max`) and runs a 32-bit guest under nested paging that talks to emulated 16550s over port I/O and MMIO and takes COM1's interrupt through an emulated PIC, then a 64-bit guest with paging on
- ✅ `examples/x86_64-pc`: the same on QEMU q35 (PVH boot, COM1, local APIC timer, 4-level paging, ACPI MADT, the DSDT run by the AML interpreter with the machine powered off through its `_S5_`, INIT/SIPI trampoline), plus a VESA mode set through the video BIOS in real mode and colour bars on `virtio-vga`
- ✅ `examples/uefi`: a UEFI application for x86_64 (OVMF) and AArch64 (AAVMF) that sets a GOP mode and draws colour bars on its framebuffer (or with `Blt` on virtio-gpu); check.sh verifies the screen
- ✅ `examples/riscv-firmware`: M-mode firmware with `-bios none`, no heap and no scheduler: async tasks on `osmium-exec` await CLINT timer and PLIC/UART interrupts, then power off
- ✅ All three examples bring up 4 CPUs and run shared SMP demos (cross-CPU mutex wake-ups by IPI, task migration)
- ✅ IOMMU boots in `scripts/check.sh`: QEMU's `iommu-testdev` behind `riscv-iommu-pci`, `intel-iommu`, `amd-iommu` and `virt,iommu=smmuv3` (`demos::iommu::testdev`: a DMA through a mapping reaches memory, an unmapped IOVA and a detached device are blocked); the RISC-V boot also runs the NVMe driver on IOVAs from an `IommuDma`
- ✅ `scripts/check.sh`: tests, clippy, rustdoc, all targets, and the QEMU boot test
