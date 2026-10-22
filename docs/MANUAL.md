# osmium user manual

This manual is for people building an operating system, firmware or
hypervisor with osmium. It covers getting the toolkit running, choosing the
crates you need, and wiring them into a kernel in the right order. Each part
uses code from the examples, so you can compare what you write with a kernel
that boots.

For the background and design principles, see [FEATURES.md](FEATURES.md).
For hypervisors, see [HYPERVISOR.md](HYPERVISOR.md). The rustdoc for each
crate is the API reference (`cargo doc --workspace --all-features --open`).

- [1. What osmium is](#1-what-osmium-is)
- [2. Getting started](#2-getting-started)
- [3. The examples](#3-the-examples)
- [4. Choosing crates and features](#4-choosing-crates-and-features)
- [5. Assembling a kernel](#5-assembling-a-kernel)
- [6. Tasks and scheduling](#6-tasks-and-scheduling)
- [7. Interrupts and drivers](#7-interrupts-and-drivers)
- [8. Heap-free firmware with osmium-exec](#8-heap-free-firmware-with-osmium-exec)
- [9. File systems](#9-file-systems)
- [10. Processes and system calls](#10-processes-and-system-calls)
- [11. Networking](#11-networking)
- [12. Hypervisors](#12-hypervisors)
- [13. Testing your code](#13-testing-your-code)
- [14. Limitations and troubleshooting](#14-limitations-and-troubleshooting)
- [Appendix: system call numbers](#appendix-system-call-numbers)

## 1. What osmium is

osmium is a set of `no_std` Rust crates for low-level system software on
x86_64, AArch64 and RISC-V 64. It is a library, not a kernel:

- **You own `main`.** osmium never defines an entry point, a panic handler or
  a `#[global_allocator]`. Your OS writes those from the parts osmium
  provides.
- **Policy is injected.** The scheduling policy, where page frames come
  from, which stack allocator tasks use and how IRQs are routed are all
  supplied by your OS, through traits and `set_*`/`inject_*` calls.
- **`unsafe` lives in constructors.** A function such as `IoMem::new` or
  `OffsetMapper::new` is `unsafe` and states its invariant once. The objects
  it returns have safe methods.
- **Link only what you use.** Each subsystem is its own crate. The
  `osmium` facade re-exports them behind Cargo features.

## 2. Getting started

### Prerequisites

| Need | For | Notes |
|---|---|---|
| rustup | everything | `rust-toolchain.toml` pins nightly with `rust-src`, `clippy` and `rustfmt`, plus the three bare-metal targets and the two UEFI targets. rustup installs them on first use. |
| `aarch64-unknown-linux-musl`, `riscv64gc-unknown-linux-musl` targets | `scripts/check.sh` only | Not in the toolchain file. Install them with `rustup target add aarch64-unknown-linux-musl riscv64gc-unknown-linux-musl`. |
| `qemu-system-riscv64`, `qemu-system-aarch64`, `qemu-system-x86_64` | running the examples | Must support RISC-V `virt` with the H extension, AArch64 `virt,virtualization=on`, x86 `q35` with `-cpu max` (TCG exposes AMD SVM), PVH `-kernel` loading, and `qemu-xhci`, `usb-*` and `virtio-*-device` devices. |
| dosfstools (`mkfs.fat`, `fsck.fat`) | FAT32 tests, the USB-stick boot check | Optional: tests skip without them |
| e2fsprogs (`mkfs.ext2`, `e2fsck`, `debugfs`) | ext2/3/4 tests | Optional |
| GNU `cpio` | cpio round-trip test | Optional |
| `python3` | the iSCSI test target (`scripts/iscsi-target.py`) and the screen checks (`scripts/screen.py`) | Optional: standard library only |
| OVMF (`/usr/share/ovmf/OVMF.fd`), AAVMF (`/usr/share/AAVMF/AAVMF_CODE.no-secboot.fd`) | the UEFI example | Optional |

The library crates use only stable Rust features (MSRV 1.88, edition 2024).
Nightly is needed for the examples and for building for bare-metal targets.

### Build, test, run

```sh
cargo test --workspace --all-features          # host unit and integration tests
cd examples/riscv-virt && cargo run --release  # boot a kernel under QEMU
./scripts/check.sh                             # the full gate (section 13)
```

The examples are not workspace members. Each has its own `Cargo.lock`, and
its `.cargo/config.toml` sets the target and uses QEMU as the `runner`. That
means `cargo run` must be run **inside the example directory**. Press
`Ctrl-A X` to quit QEMU if the kernel does not power off by itself.

### Adding osmium to your own project

```toml
[dependencies]
osmium = { version = "0.1", features = ["full"] }

[profile.dev]
panic = "abort"
[profile.release]
panic = "abort"
```

A bare-metal kernel also needs a target (e.g. `riscv64imac-unknown-none-elf`),
a linker script passed through `build.rs` (`-T link.x`), and `_start`
assembly. Copy them from whichever example is closest to your platform:

| Example | Target | Load address |
|---|---|---|
| riscv-virt | `riscv64imac-unknown-none-elf` | `0x8020_0000` (OpenSBI payload) |
| riscv-hyp | `riscv64imac-unknown-none-elf` | `0x8020_0000` (OpenSBI payload; guest image at `0x9800_0000`) |
| riscv-firmware | `riscv64imac-unknown-none-elf` | `0x8000_0000` (`-bios none`) |
| aarch64-virt, aarch64-hyp | `aarch64-unknown-none-softfloat` | `0x4020_0000` (aarch64-hyp's guest image at `0x5800_0000`) |
| uefi | `x86_64-unknown-uefi` (default) or `aarch64-unknown-uefi` | a PE image the firmware loads from `EFI/BOOT/` |
| x86_64-pc, x86_64-hyp | `x86_64-unknown-none` with `-C relocation-model=static` | `0x20_0000` (PVH, keeps `.note.Xen`; x86_64-hyp's guest image at `0x1800_0000`) |

## 3. The examples

| Example | Run | What it shows |
|---|---|---|
| `riscv-virt` | `cargo run --release` | The most complete one. S-mode under OpenSBI, FDT discovery, W^X Sv39, 4 harts via SBI HSM, the shared scheduler demos, guard-page overflow detection, virtio-net with DHCP/ping/TCP, virtio-blk, AHCI, NVMe and iSCSI disks, colour bars on virtio-gpu (MMIO and PCI) and bochs-display, xHCI with USB keyboard, storage (FAT32) and CDC-ECM, EHCI and OHCI with USB storage, user processes with fork/exec/wait, and H-extension guests (`src/hyp.rs`). |
| `aarch64-virt` | `cargo run --release` | The same kernel at EL1: PL011, GICv2, generic timer, PSCI CPU_ON, user processes with fork/exec. |
| `x86_64-pc` | `cargo run --release` | PVH boot, ACPI MADT, COM1 over port I/O with IRQ 4 through the I/O APIC, local APIC timer calibrated by the PIT, INIT/SIPI AP bring-up, the shared demos, user processes with fork/exec, a VESA mode set through the BIOS followed by virtio-vga (run with `-vga none -device virtio-vga`), and UHCI and EHCI with USB storage, an EHCI handing full-speed devices to its UHCI companions (see the x86_64-pc command line in `scripts/check.sh`). |
| `uefi` | see below | A UEFI application for OVMF (x86_64) and AAVMF (AArch64): sets a GOP mode and draws colour bars on the framebuffer, or with Blt where the GOP has no framebuffer. |
| `riscv-firmware` | `cargo run --release` | M-mode firmware with no heap and no scheduler: two async tasks on `osmium-exec` await CLINT timer and UART interrupts. |
| `aarch64-hyp` | `cargo run --release` (add `-smp 2` for the SMP guest), or see below | An EL2 hypervisor: emulated 16550 and GICv2, a virtual timer, PSCI, a 2-vCPU guest. Given the aarch64-virt image and 512 MiB, it boots that kernel as a two-vCPU guest instead. |
| `x86_64-hyp` | `cargo run --release` | AMD SVM with nested paging (or Intel VMX with EPT, chosen at boot; VMX needs `-accel kvm -cpu host`): port-I/O and MMIO UARTs, an 8259 PIC pair with an 8254 PIT, a local APIC timer and COM1 through the I/O APIC for the 64-bit guest, and a 2-vCPU guest (add `-smp 2`). Given the x86_64-pc image and 512 MiB, it boots that kernel as a two-vCPU PVH guest instead. |
| `riscv-hyp` | see below | A RISC-V hypervisor that boots the riscv-virt kernel itself as a guest: generated device tree, emulated 16550 and PLIC, SBI, virtio-blk and a virtio-net card bridged to the host NIC, one vCPU per host hart (up to 4). Guest lines start with `\| `. |

Shared code lives in two places:

- `examples/demos` is a library with the scheduler, SMP, network, storage and
  USB demos, plus `demos::user` (a console device and the RAM file system the
  user programs see).
- `examples/user` holds `hello.rs` and `init.rs`, two `no_std` user programs
  that make raw Linux-numbered system calls. Each kernel's `build.rs`
  compiles them with `rustc` and embeds the result with
  `include_bytes!(concat!(env!("OUT_DIR"), "/hello.elf"))`. Each kernel
  installs `init` as `/bin/init`, which forks, execs itself and waits.

All three hypervisor examples can boot the matching osmium kernel as their
guest. QEMU loads the guest image beside the hypervisor, so build both and
start QEMU yourself:

```sh
(cd examples/riscv-virt && cargo build --release)
(cd examples/riscv-hyp && cargo build --release)
truncate -s 8M iscsi.img   # the disk the guest reaches over iSCSI
qemu-system-riscv64 -machine virt -bios default -smp 2 -accel tcg,thread=multi -m 512M -nographic \
  -kernel examples/riscv-hyp/target/riscv64imac-unknown-none-elf/release/riscv-hyp \
  -device loader,file=examples/riscv-virt/target/riscv64imac-unknown-none-elf/release/riscv-virt,addr=0x98000000,force-raw=on \
  -netdev user,id=n0,guestfwd=tcp:10.0.2.100:7-cmd:cat,guestfwd=tcp:10.0.2.100:3260-cmd:"python3 scripts/iscsi-target.py iscsi.img" \
  -device virtio-net-device,netdev=n0

(cd examples/aarch64-virt && cargo build --release)
(cd examples/aarch64-hyp && cargo build --release)
qemu-system-aarch64 -machine virt,virtualization=on,gic-version=2 -cpu max -smp 2 -accel tcg,thread=multi -m 512M -nographic \
  -kernel examples/aarch64-hyp/target/aarch64-unknown-none-softfloat/release/aarch64-hyp \
  -device loader,file=examples/aarch64-virt/target/aarch64-unknown-none-softfloat/release/aarch64-virt,addr=0x58000000,force-raw=on

(cd examples/x86_64-pc && cargo build --release)
(cd examples/x86_64-hyp && cargo build --release)
qemu-system-x86_64 -machine q35 -cpu max -smp 2 -accel tcg,thread=multi -m 512M -nographic -no-reboot \
  -kernel examples/x86_64-hyp/target/x86_64-unknown-none/release/x86_64-hyp \
  -device loader,file=examples/x86_64-pc/target/x86_64-unknown-none/release/x86_64-pc,addr=0x18000000,force-raw=on
```

Without the loader device, or with less than 512 MiB, aarch64-hyp and
x86_64-hyp run their own small guests instead.

**uefi** is an application, not a kernel. Put it on a FAT directory as the
firmware's default boot file and let OVMF or AAVMF start it:

```sh
(cd examples/uefi && cargo build --release)       # add --target aarch64-unknown-uefi for AArch64
mkdir -p esp/EFI/BOOT && cp examples/uefi/target/x86_64-unknown-uefi/release/uefi.efi esp/EFI/BOOT/BOOTX64.EFI
qemu-system-x86_64 -machine q35 -bios /usr/share/ovmf/OVMF.fd -m 256M \
  -drive if=none,id=esp,format=raw,file=fat:rw:esp -device virtio-blk-pci,drive=esp
```

On AArch64, name the file `BOOTAA64.EFI` and use `qemu-system-aarch64
-machine virt -cpu cortex-a72` with the AAVMF code and vars files as two
`-drive if=pflash` drives (copy the vars file first, since it is written)
and `-device virtio-gpu-pci`. That GOP has no framebuffer, only Blt; use
`-device ramfb` instead if you want a framebuffer.

**Devices.** Each example probes for its devices and prints `no ... device`
for any that are missing. The `cargo run` runner for riscv-virt has virtio-net,
an xHCI controller and a USB keyboard. To see the disk, USB-stick, USB-net,
AHCI, NVMe, iSCSI and display demos as well, use the full QEMU command line from
`scripts/check.sh`, run from the repository root:

```sh
truncate -s 8M vdisk.img sata.img nvme.img iscsi.img
truncate -s 40000K stick.img; mkfs.fat -F 32 -s 1 stick.img
qemu-system-riscv64 -machine virt -bios default -smp 4 -accel tcg,thread=multi -m 128M -nographic \
  -netdev user,id=n0,guestfwd=tcp:10.0.2.100:7-cmd:cat,guestfwd=tcp:10.0.2.100:3260-cmd:"python3 scripts/iscsi-target.py iscsi.img" \
  -device virtio-net-device,netdev=n0 \
  -device qemu-xhci -device usb-kbd \
  -drive if=none,id=vd0,format=raw,file=vdisk.img -device virtio-blk-device,drive=vd0 \
  -netdev user,id=n1 -device usb-net,netdev=n1 \
  -drive if=none,id=stick,format=raw,file=stick.img -device usb-storage,drive=stick \
  -device ahci,id=ahci0 -drive if=none,id=sd0,format=raw,file=sata.img -device ide-hd,drive=sd0,bus=ahci0.0 \
  -drive if=none,id=nv0,format=raw,file=nvme.img -device nvme,serial=osmium0,drive=nv0 \
  -device virtio-gpu-device -device virtio-gpu-pci,id=gpu -device bochs-display \
  -kernel examples/riscv-virt/target/riscv64imac-unknown-none-elf/release/riscv-virt
```

## 4. Choosing crates and features

You can depend on the individual crates (`osmium-mm`, `osmium-sched`, …) or
on the `osmium` facade, which re-exports them as `osmium::mm`,
`osmium::sched` and so on. `osmium::arch` is always present.

| Feature | Crate | Needs `alloc` | Use it for |
|---|---|---|---|
| `sync` | osmium-sync | no | Spin locks, `Once`, `Lazy`, per-CPU data, SPSC ring, `SeqLock` |
| `mm` | osmium-mm | no | Addresses, memory maps, frame allocators, page tables, the heap |
| `hal` | osmium-hal | no | MMIO and port I/O, device traits (including `Display` and `Framebuffer`), `IrqTable`, the console and `println!` |
| `drivers` | osmium-drivers | no | UARTs, interrupt controllers, timers, virtio (MMIO and PCI), xHCI/USB, AHCI, NVMe, displays, mlx4, RAM disk |
| `boot` | osmium-boot | `FdtWriter` only | FDT, Multiboot2, PVH, UEFI (system table, GOP), ACPI, ELF loading |
| `exec` | osmium-exec | no | A heap-free async executor |
| `sched` | osmium-sched | yes | Tasks, context switch, scheduler, `Mutex`, `WaitQueue`, timers |
| `fs` | osmium-fs | yes | VFS, RamFs, `/dev`, cpio, ext2/ext3/ext4 |
| `fs-fat` | osmium-fs-fat | yes | FAT12/16/32 (enables `fs`) |
| `fs-iso9660` | osmium-fs-iso9660 | yes | Read-only ISO 9660 with Rock Ridge and Joliet (enables `fs`) |
| `proc` | osmium-proc | yes | Processes and the system-call dispatcher (enables `sched`, `fs`, `mm`, `boot`) |
| `net` | osmium-net | yes | IPv4, IPv6, ARP, ICMP, UDP, TCP, DHCP |
| `iscsi` | osmium-iscsi | yes | iSCSI initiator: a remote disk over TCP as a `BlockDevice` (enables `net`) |
| `virt` | osmium-virt | yes | Hypervisor building blocks |

`default` is `sync`, `mm`, `hal`, `drivers` and `boot`. `full` turns on all
of the above.

Three features choose the privilege level the arch code runs at:

| Feature | Effect |
|---|---|
| `riscv-m-mode` | Use M-mode CSRs (`mstatus`, `mtvec`, …) for firmware. |
| `riscv64-hs` | The RISC-V trap entry recognises guest exits and enables the H-extension vCPU. Only on CPUs with the H extension. |
| `aarch64-el2` | Use EL2 registers and enable the EL2 vCPU. |

As an example, here is how riscv-firmware selects a heap-free subset:

```toml
osmium = { path = "../../crates/osmium", default-features = false,
           features = ["sync", "hal", "drivers", "exec", "riscv-m-mode"] }
```

## 5. Assembling a kernel

This section follows `examples/riscv-virt/src/main.rs` from `kmain` to a
running scheduler. The AArch64 and x86_64 examples follow the same order with
their own hardware.

### 5.1 CPU identity and traps first

Before anything can fault, give the CPU an id and install a trap handler:

```rust
unsafe { cpu::set_current_id(0) };
trap::set_handler(on_trap);
// SAFETY: we run on a valid kernel stack from here on.
unsafe { trap::install() };
```

- `set_current_id` must give each CPU a unique id below `MAX_CPUS` (64).
  On RISC-V it lives in `tp`, so nothing may clobber `tp`.
- `trap::install` takes over the trap vector on this CPU. Every CPU calls
  both functions itself, the boot CPU first. If a trap arrives before a
  handler is set, it panics.

The handler gets a `&mut TrapFrame` and decides what to do from the portable
`Trap` cause:

```rust
fn on_trap(frame: &mut TrapFrame) {
    match frame.cause() {
        Trap::Interrupt(Interrupt::Timer) => { on_timer(); osmium::sched::preempt_if_needed(); }
        Trap::Interrupt(Interrupt::External) => { if let Some(plic) = PLIC.get() { IRQS.handle_pending(plic); } }
        Trap::Syscall => return syscall(frame),
        Trap::PageFault { addr, access } if frame.from_user() => osmium::proc::exit(ExitStatus::Signal(11)),
        Trap::Breakpoint => frame.set_pc(frame.pc() + 4),  // skip ebreak (2 bytes if compressed)
        other => panic!("unexpected trap {other:?} at {:#x}", frame.pc()),
    }
}
```

### 5.2 A console

`osmium::hal::println!` writes to whatever `Console` is installed. Until one
is installed, output is dropped. Install a firmware console early, then swap
in a real UART once you have found it:

```rust
struct SbiConsole;
impl Console for SbiConsole {
    fn write_str(&self, s: &str) { for b in s.bytes() { if b == b'\n' { sbi::console_putchar(b'\r'); } sbi::console_putchar(b); } }
}
set_console(&SbiConsole);

static UART: Once<SerialConsole<Uart16550<Mmio>>> = Once::new();
let io = unsafe { IoMem::new(uart_base as *mut u8, uart_len) };
let mut uart = Uart16550::new(Mmio::new(io, shift));
uart.init(None);                     // None keeps the firmware's baud rate
set_console(UART.call_once(|| SerialConsole::new(uart)));
```

`SerialConsole` translates `\n` to `\r\n` and puts the port behind a lock.
Read input through `.port()`. Your panic handler should fall back to the
firmware console, because the UART lock may be held when the panic happens.

### 5.3 Boot information and the memory map

Parse whatever the loader handed you into a `MemoryMap`:

| Loader | Parser |
|---|---|
| Device tree (OpenSBI, QEMU `virt`, U-Boot) | `osmium::boot::fdt::Fdt::from_ptr(dtb)` |
| Multiboot2 (GRUB) | `osmium::boot::multiboot2::BootInfo::from_ptr(info)` |
| UEFI application (OVMF, AAVMF, real firmware) | `osmium::boot::uefi::Uefi::new(system_table)`, then `gop()` for the screen. See `examples/uefi`. |
| PVH (QEMU/Xen/Firecracker `-kernel`) | `osmium::boot::pvh::StartInfo::from_ptr(start_info)`. Declare the entry with `pvh_start!(kmain, ap: ap_main)`. |

```rust
let fdt = unsafe { Fdt::from_ptr(dtb as *const u8) }.expect("bad device tree");
let timebase = fdt.find_node("/cpus").and_then(|c| c.property("timebase-frequency")).and_then(|p| p.as_u32());
RATE.call_once(|| TickRate::new(timebase.unwrap_or(10_000_000) as u64));

let mut map = MemoryMap::<32>::new();
fdt.fill_memory_map(&mut map, Some(PhysAddr::new(dtb as u64))).unwrap(); // also reserves the blob
map.reserve(PhysAddr::new(kstart), PhysAddr::new(kend), RegionKind::Kernel).unwrap();
map.page_align_usable();
```

To find devices, use `fdt.find_compatible(&["ns16550a"])` together with `Node::reg()` and
`Node::interrupts()`. On ACPI machines, use `acpi::Acpi::new(rsdp, read)`
followed by `Madt::parse` (CPUs, I/O APICs) and `Mcfg::parse` (PCIe ECAM).

### 5.4 Frames, heap and page tables

A single static `LockedFrames` can hand out page-table pages, back the heap
and supply DMA memory to drivers:

```rust
type Frames = LockedFrames<BuddyAllocator<OffsetMapper>, OffsetMapper>;
// SAFETY: RAM is identity-mapped (offset 0) for as long as these frames are used.
static FRAMES: Frames = unsafe { LockedFrames::new(BuddyAllocator::new(OffsetMapper::new(0)), OffsetMapper::new(0)) };

#[global_allocator]
static HEAP: LockedHeap<&'static Frames> = LockedHeap::new();

{
    let mut buddy = FRAMES.lock();
    for r in map.usable() { unsafe { buddy.add_region(r.start, r.end) }; }
}
HEAP.init(&FRAMES);   // allocations return null until this point
```

- `OffsetMapper::new(off)` promises that all RAM is mapped read-write at
  `pa + off`. Use `0` while identity-mapped, or your direct-map base once
  you have one.
- If there are no frames yet, `StaticArena<PAGES>` provides a heap from
  `.bss`:
  `static HEAP: LockedHeap<&StaticArena<1024>>` with `HEAP.init(&ARENA)`.
- `BitmapAllocator` is the alternative to buddy when you want the metadata
  to live in a fixed array.

Build page tables with `PageTable<Format, Alloc>`. Here is the W^X kernel map
from riscv-virt:

```rust
let mut pt: PageTable<Sv39, &'static Frames> = PageTable::new(&FRAMES).unwrap();
let k = |f| f | MapFlags::GLOBAL;
pt.map_range(va(kstart), pa(kstart), etext - kstart, k(MapFlags::RX)).unwrap();
pt.map_range(va(etext), pa(etext), erodata - etext, k(MapFlags::READ)).unwrap();
pt.map_range(va(erodata), pa(erodata), ram_end - erodata, k(MapFlags::RW)).unwrap();
pt.map_range(va(uart_page), pa(uart_page), PAGE_SIZE as u64, k(MapFlags::RW | MapFlags::DEVICE)).unwrap();
unsafe { riscv64::write_satp(SatpMode::Sv39, 0, pt.root().0) };
```

- The formats are `X86_64`, `Aarch64`, `Aarch64El2`, `Sv39`, `Sv48`, and
  the stage-2 formats `Sv39x4`, `Sv48x4`, `Ept` and `Aarch64Stage2`.
- `map_range` uses the largest pages that fit and does **not** flush the
  TLB. It is meant for building a table before you switch to it.
- `map`, `unmap` and `protect` return a `#[must_use] Flush`. Call
  `.flush()` if the table is live, or `.ignore()` if it is not.
- Every mapping must grant at least one of `READ`, `WRITE` or `EXEC`;
  `map` and `protect` refuse anything else with `NoAccess`. For an
  inaccessible page (e.g. `PROT_NONE`), leave it unmapped.
- Dropping a `PageTable` frees its intermediate tables but not the frames
  you mapped.

### 5.5 Synchronization

| Type | Use when |
|---|---|
| `SpinLock<T>` | Short critical sections between CPUs. Disables preemption. |
| `IrqSpinLock<T>` | The data is also touched by an IRQ handler. Disables interrupts. |
| `RawSpinLock<T>` | IRQs are already masked, or there is only one CPU. |
| `RwSpinLock`, `SeqLock` | Read-mostly data |
| `Once`, `Lazy` | Statics that are initialised at boot |
| `PerCpu<T>`, `PerCpuCell<T>` | Per-CPU state. `PerCpuCell::with` masks IRQs and panics on re-entry. |
| `SpscRing<T, N>` | IRQ handler to task, lock-free |
| `osmium::sched::{Mutex, Semaphore, WaitQueue}` | Sleeping primitives for task context only, never under a spin lock or in an IRQ |

A common pattern is a driver created at boot, shared with its IRQ handler:

```rust
static XHCI: Once<IrqSpinLock<Xhci<'static, Frames>>> = Once::new();
fn xhci_irq(_irq: u32) { if let Some(x) = XHCI.get() { x.lock().handle_interrupt(); } }
```

### 5.6 Bringing up the other CPUs

Start each secondary CPU with the platform's mechanism:

| Platform | Mechanism |
|---|---|
| RISC-V | `sbi::hart_start` |
| AArch64 | PSCI `CPU_ON` |
| x86 | `osmium::arch::x86_64::smp` trampoline plus `LocalApic::start_ap` |

On x86, osmium provides the real-mode trampoline. Install it once, then
start the APs one at a time, because they share the trampoline's slots:

```rust
unsafe { x86::smp::install() };   // copies the trampoline to smp::TRAMPOLINE (0x8000)
for (cpu, apic_id) in APIC_IDS.iter().enumerate().take(ncpus).skip(1) {
    let stack = alloc::vec![0u8; 64 * 1024].leak();
    let boot = x86::smp::ApBoot {
        cr3: &raw const boot_pml4 as u64,          // identity-maps the trampoline and entry
        stack_top: (stack.as_ptr() as u64 + stack.len() as u64) & !15,
        entry: ap_start64 as *const () as u64,     // from pvh_start!(kmain, ap: ap_main)
        cpu,
    };
    unsafe { apic.start_ap(apic_id.load(Relaxed) as u8, &boot, |ns| pit.wait_ns(ns)) };
    while ONLINE.load(Acquire) <= cpu { core::hint::spin_loop(); }  // wait for it to check in
}
```

On each secondary, repeat the per-CPU steps: `set_current_id`,
`trap::install`, load the kernel page table, `osmium::sched::init_cpu()`,
enable its timer, and finally call `osmium::sched::exit()`. That call hands
the CPU to the scheduler for good.

## 6. Tasks and scheduling

### Wiring

```rust
static SCHED: FifoScheduler = FifoScheduler::new(2).with_stealing(); // 2-tick slices
static TIMERS: TimerQueue = TimerQueue::new();

osmium::sched::set_stack_allocator(&GuardedStacks);  // optional: default is the heap
osmium::sched::set_switch_hook(on_switch);           // optional: per-task page table, kernel stack
osmium::sched::inject_scheduler(&SCHED);
osmium::sched::set_remote_wake_hook(|cpu| { let _ = sbi::send_ipi(1, HARTS[cpu].load(Relaxed)); });
osmium::sched::init_cpu();                           // on every CPU
```

From the timer interrupt:

```rust
fn on_timer() {
    sbi::set_timer(cpu::ticks() + RATE.get().unwrap().ns_to_ticks(TICK_NS));
    TIMERS.process(now_ns());
    osmium::sched::tick();
}
// ...then call osmium::sched::preempt_if_needed() on the way out of every interrupt.
```

Each `inject_*` and `set_*_hook` function may be called only once.

- **Policies.** `FifoScheduler` and `PriorityScheduler` are included. To
  write your own, implement `Scheduler`
  (`enqueue`, `pick_next(cpu)`, `tick(cpu, &current) -> bool`).
- **Load balancing** is opt-in through `.with_stealing()`. With it, idle
  CPUs steal queued tasks they are allowed to run, and new or woken tasks go
  to idle CPUs. `SCHED.steals()` counts the steals.
- **Stack guards.** Implement `StackAllocator` to give each task a stack
  with an unmapped guard page below it. riscv-virt's `GuardedStacks` does
  this, and `TrapCpu::overflowed` then reports overflows instead of
  corrupting memory.

### Spawning and affinity

```rust
let t = TaskBuilder::new("worker")
    .stack_size(16 * 1024)   // default 64 KiB
    .priority(3)             // used by PriorityScheduler
    .cpu(1)                  // pin to CPU 1; .affinity(mask) for a set; default ALL_CPUS
    .spawn(move || { /* ... */ osmium::sched::yield_now(); });
t.join();
```

A task can move itself with `osmium::sched::current().set_cpu(n)`, which
takes effect the next time it is queued. `Task::pin` and `Task::set_affinity`
change the allowed CPUs. Kernels that run user tasks keep them pinned with
`.cpu(n)`.

### Blocking

```rust
static COUNTER: Mutex<u64> = Mutex::new(0);
*COUNTER.lock() += 1;

static RX_READY: WaitQueue = WaitQueue::new();
let byte = RX_READY.wait_until(|| rx.pop());   // sleeps until the closure returns Some
// in the IRQ handler: RX_READY.wake_all();

TIMERS.sleep_until(now_ns() + 50_000_000);      // 50 ms
let id = TIMERS.add(deadline, || { /* runs in the timer IRQ */ });
TIMERS.cancel(id);
```

`TimerQueue` does not choose a time unit. Use the same one everywhere; the
examples use nanoseconds.

## 7. Interrupts and drivers

### The IRQ path

```rust
static IRQS: IrqTable<64> = IrqTable::new();

let plic = PLIC.call_once(|| Plic::new(io, |cpu| Plic::supervisor_context(HARTS[cpu].load(Relaxed))));
IRQS.register(irq, &xhci_irq).unwrap();    // any Fn(u32) + Sync is a handler
plic.set_threshold(0);
plic.enable(irq);
unsafe { riscv64::write_sie(riscv64::read_sie() | riscv64::SIE_SEIE) };

// in the external-interrupt trap:
IRQS.handle_pending(plic);                 // claim, dispatch, complete until none are left
```

Handlers run with IRQs masked. `IrqTable` works with any
`InterruptController`, whether that is the PLIC, GICv2 or your own. On x86,
the local APIC and I/O APIC route vectors instead
(`IoApic::route(gsi, vector, dest, LineMode)`).

### Writing to hardware

`IoMem::new(base, len)` is the one `unsafe` step. Its contract is that the
range is mapped (as device memory) and aliases nothing Rust owns. After that,
`read::<u32>(off)` and `write` are bounds-checked. For a struct-shaped
register block, use `as_regs::<R>()` with a `#[repr(C)]` struct made of
`ReadOnly`, `WriteOnly` and `ReadWrite<T>` cells. On x86, `Port<T>` covers
port I/O.

### Driver catalogue

| Category | Drivers |
|---|---|
| Serial | `uart16550::Uart16550` (MMIO or `Pio`), `pl011::Pl011` |
| Interrupt controllers | `plic::Plic`, `gicv2::GicV2`, `lapic::LocalApic`, `ioapic::IoApic` |
| Timers | `clint::Clint`, `pit::Pit` |
| Block | `ramdisk::RamDisk`, `virtio::blk::VirtioBlk`, `usb::storage::UsbStorage` (fewer than 2^32 blocks, so under 2 TiB at 512 B; block sizes a power of two from 512 B to 64 KiB), `ahci::Ahci`, `nvme::Nvme`; iSCSI in `osmium::iscsi` |
| Network | `virtio::net::VirtioNet`, `usb::ecm::UsbEthernet`, `usb::ncm::UsbNcm`, `mlx4::Mlx4` (polled, or MSI-X via `enable_msix`; checksum and segmentation offloads are inherent `EthPort` methods, since `NetDevice` has no offload flags; InfiniBand ports are `IbPort`, which sends and receives UD datagrams and is not a `NetDevice`) |
| USB | `xhci::Xhci` (polled, INTx, MSI or MSI-X via `enable_message_interrupts`), `ehci::Ehci` (high-speed only; low- and full-speed devices go to the companion), `ohci::Ohci` and `uhci::Uhci` (low/full speed, hubs; all three polled, no isochronous), `usb::hid::BootKeyboard`, `usb::hub::Hub`, `usb::isoch::{IsochIn, IsochOut}` |
| Display | `virtio::gpu::VirtioGpu` (virtio-gpu and virtio-vga, MMIO or PCI), `display::bochs::BochsVbe` (QEMU std VGA, bochs-display, virtio-vga in VGA mode), `display::vbe::Vbe` (VESA BIOS Extensions, x86) |

Drivers that do DMA take a `DmaAllocator`, and `LockedFrames` is one.
Its `free_coherent` is `unsafe`: free a buffer only once the device can no
longer touch it. `OwnedDma` does this on drop, after you reset the device. Block
devices implement `osmium::hal::block::BlockDevice`, network devices
`osmium::hal::net::NetDevice`. That is how the file systems and the network
stack connect to them. A virtio probe looks like this:

```rust
let t = MmioTransport::new(unsafe { IoMem::new(base as *mut u8, len) }).ok()?;
if t.device_type() == DeviceType::Net {
    let mut net = VirtioNet::new(t, &FRAMES).expect("virtio-net init failed");
}
```

PCIe devices are found through `osmium::hal::pci::Ecam` (`for_each_function`),
and their BARs are assigned with `BarAllocator`. Virtio devices on PCI use
`virtio::pci::PciTransport`; it drives the same device drivers as
`MmioTransport`.

The virtio drivers don't trust the device. A request the device never
completes, or answers outside the protocol, fails with an error
(`BlockError::Io`, `DisplayError::Device`, …) instead of hanging. Once a
device has broken a queue's protocol, `VirtQueue::is_broken()` reports it and
the queue takes no more requests until you reset the device. Call
`enable_memory_and_dma()` on the function before handing its BAR to a
driver. riscv-virt's `find_pci` shows the whole sequence.

The two PCIe storage drivers are polled and have one command in flight.
For their timeouts they take an `osmium::hal::timer::Clock` (anything with
`now_ns()`):

| Driver | Finds | Use |
|---|---|---|
| `ahci::Ahci` | class 01/06/01, registers in BAR 5 | `Ahci::new(io, &dma, Some(&clock))` brings the ports up; with `None`, its timeouts count polls instead of time. `disks()` lists the SATA disk ports, and `take_disk(port)` returns an `AhciDisk`, a `BlockDevice` with `model()` and `serial()` that outlives the HBA. With both the HBA and the disk supporting it, NCQ keeps up to 8 commands in flight per call. `Ahci::enable_interrupts()` and `AhciDisk::enable_interrupts(idle)` wait for completions by sleeping in `idle` instead of spinning; the kernel's IRQ handler (INTx or MSI) calls `Ahci::irq().handle()`. `atapi_drives()` and `take_atapi(port)` give an `AhciAtapi`, a read-only `BlockDevice` over a disc (2048-byte blocks, `reload()` after a disc change) that `osmium_fs_iso9660` can mount. Not supported: port multipliers, hot plug, queued or interrupt-driven ATAPI. |
| `nvme::Nvme` | class 01/08/02, BAR 0 (64-bit) | `Nvme::new(io, &dma, &clock)` is a `BlockDevice` on the first active namespace. Use `select_namespace(nsid)` to pick another. It has `model()`, `serial()` and `firmware()`, uses one I/O queue pair with up to four commands in flight for transfers that split, and shuts the controller down on drop. `Nvme::with_interrupts(io, &dma, &clock, Interrupts { vector, signal, idle })` creates the I/O completion queue on an MSI-X table entry you have set up; your handler calls `IrqSignal::notify()` and the driver sleeps in `idle` between completions (admin commands are still polled). |

### Displays

Every display driver ends in an `osmium::hal::display::Framebuffer`, which
you draw on with `set_pixel`, `fill_rect`, `draw`, `draw_bitmap` (glyphs) and
`scroll_up`. Pixels are given as `Rgb`, and `PixelFormat` encodes them for
16, 24 and 32 bpp. Drivers that need to be told what changed (virtio-gpu)
implement the `Display` trait: draw on `framebuffer()`, then call
`flush(rect)` or `flush_all()`.

| Driver | Mode set | Notes |
|---|---|---|
| `VirtioGpu::new(transport, &dma)` | `set_mode(scanout, w, h)` | 2D. The framebuffer is guest memory; `flush` sends it to the host. |
| `BochsVbe::new_mmio(mmio, vram, vga)` / `new_ports(vram)` (x86 only) | `set_mode(w, h, bpp)` | Bochs DISPI registers, no BIOS needed |
| `Vbe::new(bios)` | `modes()`, then `set_mode(&mode)` | VESA through a `VideoBios`. On x86, `RealModeBios` calls the real BIOS through `osmium::arch::x86_64::bios`, a thunk that drops to real mode and back. Call it in early boot: only the boot CPU may be running, and the PIC, IVT and APIC timers must still be as the BIOS left them. |
| `uefi::Gop` (in osmium-boot) | `find_mode(w, h)`, `set_mode(n)` | `framebuffer()` when the GOP has one, `fill` (Blt) otherwise |

`examples/demos/src/display.rs` probes all of these and draws the same eight
colour bars, which `check.sh` reads back from QEMU's screen.

## 8. Heap-free firmware with osmium-exec

When there is no heap and no threads, `osmium-exec` runs `async` tasks from
fixed slots, and interrupt handlers wake them through `Signal`:

```rust
static EXEC: Executor<4> = Executor::new();
static TICKS: Signal<u64> = Signal::new();

async fn ticker() { for _ in 0..5 { let n = TICKS.wait().await; println!("tick {n}"); } }

// in the timer trap:
TICKS.signal(TICK_COUNT.fetch_add(1, Relaxed) + 1);

// in main:
// SAFETY: this firmware is built with panic = "abort".
unsafe { EXEC.run_to_completion(&mut [pin!(ticker()), pin!(console(consumer))]) };
```

- When nothing is ready, the executor sleeps with `irq::enable_and_wait`,
  which cannot lose a wake-up.
- `run_with` and `run_to_completion` are `unsafe fn`s: they keep the futures
  in your stack frame, so the caller must guarantee `panic = "abort"`.
- `StaticCell` gives you a `&'static mut` without a heap.

## 9. File systems

Everything is an `Arc<dyn File>`. A node is stateless and offset-based:
`read(off, buf)`, `write(off, buf)`, `stat()`, `readdir(i)`, `lookup(name)`,
`create`, `remove`, `truncate`, `sync`. Only `stat` is required, and the
other methods default to an error. Open-file state such as the current
offset lives in `osmium-proc`'s fd table.

### A namespace

```rust
let vfs: &'static Vfs = Box::leak(Box::new(Vfs::new(RamFs::new(1).root())));
vfs.mkdir("/etc", 0o755).unwrap();
let motd = vfs.open("/etc/motd", OpenFlags::WRITE | OpenFlags::CREATE, 0o644).unwrap();
motd.write(0, b"welcome to osmium\n").unwrap();

let dev = DevDir::new(2);
dev.insert("console", console.clone());          // your own File impl
dev.insert("null", Arc::new(Null::new()));
dev.insert("zero", Arc::new(Zero::new()));
vfs.mkdir("/dev", 0o755).unwrap();
vfs.mount("/dev", Arc::new(dev)).unwrap();
```

- Paths are absolute. `..` crosses mount points, and symlinks are followed
  unless you pass `OpenFlags::NOFOLLOW`.
- The VFS checks no permissions.
- Errors are Linux `Errno` values (`Errno::ENOENT`, …), so they can be
  passed straight back to user space.

### Disk file systems

Each one mounts any `BlockDevice` and returns a root that you can mount
anywhere:

```rust
let ext = Ext2::mount(disk, 3)?;           // ext2, ext3 or ext4; EINVAL if not ext*, ENOSYS if unsupported
vfs.mount("/mnt", ext.root())?;

let fat = osmium::fs_fat::FatFs::mount(stick, 4)?;   // FAT12, FAT16 or FAT32
vfs.mount("/usb", fat.root())?;

let iso = osmium::fs_iso9660::IsoFs::mount(cdrom, 5)?;
println!("disc {:?}, names from {:?}", iso.volume_id(), iso.names());
vfs.mount("/cdrom", iso.root())?;
```

| | ext2/3/4 (`osmium::fs::Ext2`) | FAT12/16/32 (`osmium::fs_fat::FatFs`) | ISO 9660 (`osmium::fs_iso9660::IsoFs`) |
|---|---|---|---|
| Read/write | yes, or read-only if the volume has an unknown read-only feature (`quota`, `bigalloc`, …) | yes | read-only |
| Names | ext directories; hashed indexes are scanned linearly and dropped on change | VFAT long names, generated 8.3 aliases | Rock Ridge if present, else Joliet, else lower-cased ISO names (`names()` says which) |
| Extras | extents, `64bit`, `flex_bg`, `metadata_csum` (verified and kept); `set_clock` for timestamps; `into_device` to unmount | `free_bytes` from FSInfo | Symlinks and device nodes via Rock Ridge; files over 4 GiB; any device block size |
| Not supported | journal replay (a clean journal is left alone; a dirty one fails with `ENOSYS`), `inline_data`, encryption, casefolding, rename, hard links | exFAT, timestamps, rename; a FAT12/16 root directory cannot grow (`ENOSPC` when full); device block sizes that are not a power of two up to 4 KiB; directories over 65536 entries | timestamps, multi-session beyond the first, UDF |

The ext driver writes changes in place and journals nothing, and there is
no block cache. Call `sync()` before removing the device. A corrupt layout
(including a bad superblock or group-descriptor checksum) fails the mount
with `EINVAL`. Corrupt metadata found later (a bad checksum, a
damaged inode or directory record) returns `EIO` for that access.

To unpack an initramfs, use `osmium::fs::cpio::unpack(vfs, "/", archive)`,
which reads the newc format.

## 10. Processes and system calls

`osmium-proc` adds processes on top of tasks. A `Process` holds an address
space (`UserMemory`), an fd table, a cwd, a umask, its children and an exit
status. One portable dispatcher implements Linux system calls with each
architecture's own numbers and structure layouts. That lets a static Linux
binary for the right architecture run unchanged, as long as it sticks to the
supported calls.

### Setup

```rust
osmium::proc::set_vfs(vfs);          // where openat and execve look up paths
osmium::proc::set_console(console);  // what FdTable::with_console() puts on fds 0, 1, 2
osmium::proc::set_platform(platform()); // only needed for fork, clone and execve
```

`Platform` tells proc how to create and activate an address space and how to
resume a forked child:

```rust
pub struct Platform {
    pub new_memory: fn() -> Result<Box<dyn UserMemory>, Errno>,
    pub activate: fn(PhysAddr),       // switch to this root
    pub resume: fn(TrapFrame) -> !,   // e.g. osmium::arch::riscv64::resume_user
    pub stack_top: u64, pub stack_size: u64, pub mmap_area: Range<u64>,
}
```

Without a platform, fork and execve return `ENOSYS`.

If your kernel is soft-float, nothing saves FP/SIMD registers between
processes. On x86_64 and AArch64, call `osmium::arch::x86_64::trap_fp()` or
`osmium::arch::aarch64::trap_fp()` on every CPU so that user FP/SIMD
instructions fault instead. The kernel itself must not use them afterwards.

Your switch hook also has to load each task's page table:

```rust
fn on_switch(next: &Task) {
    if let Some(root) = osmium::proc::root_for(next) { /* write satp / TTBR0 / CR3 */ }
    // and point TrapCpu at next.kernel_stack_range()
}
```

### Starting a process

Starting from an ELF image already in memory:

```rust
let space = unsafe { AddressSpace::new(&FRAMES, &KERNEL_PT, 0..64) }.unwrap(); // shares kernel root entries
let elf = Elf::new(HELLO_ELF).unwrap();
let brk = space.load_elf(&elf).unwrap();
space.map_anon(stack_va, stack_len, MapFlags::RW).unwrap();
let process = Process::new("hello", space, brk);
process.spawn(TaskBuilder::new("hello").cpu(1), move || unsafe {
    riscv64::enter_user(elf.entry() as usize, stack_top)
});
```

Starting from a path in the VFS, the way `init` is started:

```rust
let process = Process::new_boxed("init", (platform().new_memory)().unwrap(), 0);
process.spawn(TaskBuilder::new("init").cpu(cpu), || {
    let e = osmium::proc::current().unwrap().exec("/bin/init", &[b"init"], &[]).expect("exec");
    unsafe { riscv64::enter_user(e.pc as usize, e.sp as usize) }
});
```

`process.wait()` blocks until the process exits and returns an `ExitStatus`
(`Code(i32)` or `Signal(u8)`).

### The syscall trap

```rust
fn syscall(frame: &mut TrapFrame) {
    if let Some(status) = osmium::proc::syscall::handle(frame) {
        osmium::proc::exit(status);
    }
}
```

`handle` decodes the registers, runs the call, writes the result back,
starts forked children through `Platform::resume` and sets up the new image
on `execve`. If you need your own register handling, call
`syscall::dispatch(&process, nr, args) -> Outcome` instead.

The supported calls are listed in the [appendix](#appendix-system-call-numbers).
Unknown numbers return `-ENOSYS`. Some limits apply:

- `fork` shares memory copy-on-write.
- `clone` creates processes, or threads with `CLONE_THREAD` (which needs `CLONE_VM|FS|FILES|SIGHAND`); all threads of a process share one CPU. `futex` has wait, wake, requeue, `WAKE_OP`, bitsets, timeouts (once the kernel gives `osmium_proc::futex::set_clock` a clock and calls `futex::tick`) and robust lists, but no priority-inheritance operations (`ENOSYS`).
- `execve` loads only static, non-PIE ELF files. It refuses an image whose
  segments reach kernel address ranges (`ENOEXEC`) or need more than 1 GiB
  in total (`ENOMEM`).
- `mmap` with `PROT_NONE` reserves the range without mapping anything.
- There are no signals.

## 11. Networking

`osmium-net` is a polled IPv4 and IPv6 stack over any `NetDevice`. It has no globals
and never reads a clock: you pass in the time and decide when to poll.

```rust
let now = || Instant::from_nanos(now_ns());
let mut iface = Interface::new(dev, now_ns());          // seed for ports and ISNs
let mut sockets = SocketSet::new();
let dhcp = sockets.add(DhcpClient::new());
let tcp  = sockets.add(TcpSocket::new(1024, 1024));      // rx/tx buffer sizes
let udp  = sockets.add(UdpSocket::new(4, 4));            // rx/tx packet slots
let ping = sockets.add(IcmpSocket::new(0x05ef, 2));

loop {
    iface.poll(now(), dev, &mut sockets);
    if let Some(DhcpEvent::Configured(cfg)) = sockets.get_mut::<DhcpClient>(dhcp).take_event() {
        sockets.get_mut::<TcpSocket>(tcp).connect(SocketAddrV4::new(server, 7), 0).unwrap();
    }
    let s = sockets.get_mut::<TcpSocket>(tcp);
    if s.can_send() { s.send(b"hello over TCP").ok(); }
    if let Ok(n) = s.recv(&mut buf) { /* ... */ }
    // sleep for iface.poll_delay(now(), &sockets), or until the NIC interrupts
}
```

- `DhcpClient` applies its lease to the interface by itself. To use a
  static address instead, call
  `iface.set_config(Some(Config { address, prefix_len, gateway, dns }))`.
- UDP: `bind(port)`, `send_to(data, addr)`, `recv_from(&mut buf) -> (n, from)`.
- TCP: `listen(port)` or `connect(remote, 0)`, then `send`, `recv`, `close`
  and `state()`. Errors are `Error::WouldBlock`, `ConnectionRefused`, and so
  on.
- Multicast: `iface.join_multicast_group(now, group)` makes the interface
  accept the group and report it with IGMPv2; a `UdpSocket` bound to the port
  then receives it, and `send_to` a group address sends to the group's MAC
  with TTL 1 (`set_multicast_ttl` changes that). `leave_multicast_group`
  undoes a join.
- A truncated DNS answer is retried over TCP by `DnsClient` itself; TCP
  connections negotiate timestamps (RFC 7323) when the peer offers them.
- IPv6: call `iface.enable_ipv6()`. The interface then derives a link-local
  address, checks it for duplicates, and solicits a router for SLAAC
  addresses; `add_ipv6_address` and `set_ipv6_gateway` configure it by hand,
  and `ipv6_addresses()` lists what is in use. Sockets take `SocketAddr`: bind
  a `UdpSocket` with `bind_addr` (or a `TcpSocket` with `listen_on`) to a
  `[::]:port` address for IPv6, and `connect` or `send_to` an IPv6 remote.
  A socket serves one family. `DnsClient::resolve6` looks up AAAA records
  (collect with `result_ip`). IPv6 fragments are dropped, and datagrams over
  the MTU are not fragmented on send.
- Not supported: IPv6 fragmentation, privacy addresses, DHCPv6, forwarding,
  IGMPv3 membership reports (IGMPv3 queries are answered with v2 reports).
- `osmium-proc` exposes this stack as sockets: `net::set_stack` takes a
  `NetStack`, and `socket`, `sendmsg`/`recvmsg`, `socketpair`, `poll`,
  `select` and `epoll` work on descriptors. 127.0.0.0/8 is delivered inside
  the stack without a device. A file reports readiness through
  `osmium_fs::File::poll` (default: always ready); call `poll::tick()` from a
  timer, and `poll::set_clock` if there is no stack, so timeouts are noticed.

### iSCSI

`osmium-iscsi` (feature `iscsi`) logs in to an iSCSI target over an
osmium-net TCP socket and gives you the LUN as a `BlockDevice`. You can then
mount any of the file systems in section 9 on it:

```rust
use osmium::iscsi::{IscsiDisk, Options, Stack};
let net = Stack { iface: &mut iface, dev, sockets: &mut sockets, now_ns };
let opts = Options::new("iqn.2026-10.org.osmium:riscv-virt", "iqn.2026-10.org.osmium:disk0");
let disk = IscsiDisk::connect(net, SocketAddrV4::new(portal, 3260), &opts)?;
```

`Stack` is the ready-made `iscsi::Net` for an osmium-net interface.
`iscsi::discover` lists the targets on a portal (SendTargets). There is no
CHAP and no header or data digests, and error recovery is level 0.

For testing, `scripts/iscsi-target.py IMAGE` is a small target that needs
only the Python standard library. Under QEMU, attach it with
`guestfwd=tcp:10.0.2.100:3260-cmd:"python3 scripts/iscsi-target.py IMAGE"`
(see section 3). To run it standalone, use `--listen 3260`; it binds 127.0.0.1 unless you
pass `--bind ADDR`. It also takes
`--read-only`, `--log FILE` and `--self-test`.

## 12. Hypervisors

`osmium-virt` reuses the kernel parts (page tables, buses, drivers, tasks) to
run guests:

```rust
let exit = run_vcpu(&mut vcpu, &mmio_bus, &pio_bus, |v, exit| match exit {
    VmExit::Hypercall { .. } => /* SBI, PSCI or your own ABI */,
    VmExit::Halt => /* wait for v.interrupt_pending(..) */,
    VmExit::ExternalInterrupt => ControlFlow::Continue(()),
    other => ControlFlow::Break(other),
});
```

| Backend | Feature | Host mode | Guest interrupt controller |
|---|---|---|---|
| `riscv::RiscvVcpu` | `riscv64-hs` | HS-mode | `VirtualPlic` |
| `aarch64::Aarch64Vcpu` | `aarch64-el2` | EL2 (non-VHE) | `VirtualGicV2` |
| `x86::svm::SvmVcpu` | none | long mode + AMD SVM | `VirtualPic`, or a `VirtualLapic` per vCPU plus `VirtualIoApic` |

Device models are an emulated 16550, an 8254 PIT, and virtio-mmio console,
block and net. Multi-vCPU guests run on all three architectures through
`smp::GuestCpus`, with each vCPU in a task pinned to its own host CPU. Create
it with `with_kick` so that an interrupt aimed at a vCPU running on another
host CPU makes that vCPU exit at once (an IPI on RISC-V and x86, a host SGI
on AArch64). x86 guests start their APs the PC way, with INIT and STARTUP
through the `VirtualLapic` (`decode_icr`, then `SvmVcpu::set_real_mode`), and
`attach_svm` records which host CPU each vCPU runs on.
`examples/riscv-hyp`, `examples/aarch64-hyp` and `examples/x86_64-hyp` show
the whole path: each boots an unmodified osmium kernel (riscv-virt,
aarch64-virt or x86_64-pc) as an SMP guest, with a generated device tree on
RISC-V and AArch64 and PVH start info on x86. HYPERVISOR.md's
[Booting a whole kernel](HYPERVISOR.md#booting-a-whole-kernel) gives the
recipe they share, and
[Describing the machine](HYPERVISOR.md#describing-the-machine) covers the
guest descriptions (`GuestMachine`, `ArmMachine`, `PcBoot`).
[HYPERVISOR.md](HYPERVISOR.md) explains guest memory, stage-2 tables, wiring
interrupts and SMP guests in detail.

## 13. Testing your code

### On the host

When the target OS is not `none` or `uefi`, `osmium-arch` swaps privileged
instructions for a simulation:

- IRQ flags and the CPU id are per-thread.
- TLB flushes do nothing.
- Memory code runs on simulated physical memory.
- The context switch is the real one, running on host threads.

That means your own scheduler policy, file system or driver logic can be
unit-tested with plain `cargo test`. For traps, `osmium::arch::trap::simulate(trap, pc)`
runs your registered handler on a synthetic frame and returns the frame, so
you can check where it set the PC.

```sh
cargo test --workspace --all-features
cargo test -p osmium-net               # one crate
```

The ext2, FAT and cpio tests check their output against the real host tools
when those are installed.

### scripts/check.sh

This is the gate every change to main passes. It takes no arguments:

1. `cargo test` for the workspace with all features
2. `cargo clippy -- -D warnings`, including all targets
3. `cargo doc` with `RUSTDOCFLAGS="-D warnings"`
4. `cargo build` for the three bare-metal targets
5. `cargo check` for the two musl targets, which builds the FP-saving context switch
6. Each example is built and booted under QEMU with a 60-second timeout,
   and its serial log is grepped for expected lines. For riscv-virt, the FAT32
   image it wrote is afterwards checked with `fsck.fat`.
7. Where an example draws, `scripts/screen.py` takes screendumps over
   QEMU's QMP socket until the expected colour bars appear. This covers
   riscv-virt, x86_64-pc and the UEFI app on OVMF and AAVMF.

If a QEMU binary or optional tool is missing, that step is skipped with a
message rather than failing. If an expected line is missing, the script
prints the log and exits non-zero.

If you add a feature to an example, add its log line to the `EXPECT` list
for that boot in `check.sh`. Match on what was delivered or the order it
happened in, never on counts that depend on timing: multi-threaded TCG makes
those flaky. Serial logs end lines with `\r\n`, so don't anchor patterns
with `$`.

### Formatting

The repository has no `rustfmt.toml`, and existing code is formatted by hand
to about 120 columns. Don't run `cargo fmt` across the workspace. Format only
the files you wrote:

```sh
rustfmt --edition 2024 --config max_width=120,use_small_heuristics=Max path/to/file.rs
```

## 14. Limitations and troubleshooting

### Current limitations

- Only QEMU has been tested (TCG, up to 4 CPUs), never physical hardware.
- All threads of a process run on one CPU.
- FP/SIMD registers are switched per task only when the kernel calls
  `osmium_arch::fp::enable` on every CPU and gives user tasks an `FpState`
  (`TaskBuilder::fp_state`). Kernels are soft-float and never touch them.
  AVX stays off on x86_64, and SVE and SME are not enabled on AArch64.
- The heap can return large blocks to the frame allocator only if the
  mapper implements `virt_to_phys` (`OffsetMapper` does).
- The Intel VMX backend has only run under nested KVM, and x86 MMIO emulation does not
  walk 32-bit guest page tables. Guest FP/SIMD state is switched only on the
  assumption that the host kernel is soft-float. On x86 that switching is
  opt-in (`with_fp_switching`: x87 and SSE, not AVX), and SVE is not
  switched on AArch64. See HYPERVISOR.md's
  [current limits](HYPERVISOR.md#current-limits).
- USB hubs (`usb::hub`) and isochronous endpoints (`IsochHost`, `usb::isoch`)
  have only been tested against a simulated xHCI controller. Isochronous
  transfers carry at most 4 KiB per service interval, SuperSpeed burst sizes
  from companion descriptors are ignored, and a SuperSpeed hub port that
  needs a warm reset is not recovered.
- UHCI, OHCI and EHCI are polled only, without isochronous endpoints, and
  EHCI supports no hubs.
- CDC-NCM Ethernet (`usb::ncm`) has only been tested against a simulated
  device, since QEMU's `usb-net` offers only ECM and RNDIS. It uses 16-bit
  NTBs of at most 4 KiB without CRCs and sends one frame per NTB.

### Troubleshooting

| Symptom | Likely cause |
|---|---|
| No output at all | No console is installed yet, or the UART is not mapped `DEVICE` in your page table. Install a firmware console (`SbiConsole`) before anything else. |
| Panic "unhandled trap … (no handler registered)" | `trap::set_handler` was not called before `trap::install`, or a secondary CPU skipped `install`. |
| Allocation returns null / `alloc` error before paging | `HEAP.init` has not run yet, or no frames were added to the allocator. |
| Hang after `write_satp` / enabling the MMU | The new table does not map the code, stack or console you are currently using. |
| Hang on a secondary CPU | It did not call `set_current_id`, `install`, `init_cpu` and `osmium::sched::exit()` in that order, or its timer was not enabled. |
| `fork`/`execve` return `ENOSYS` | `osmium::proc::set_platform` was never called. |
| `no virtio-blk device` / `no xHCI controller` | That device is not on the QEMU command line. See [section 3](#3-the-examples). |
| `cannot enable SVM` in x86_64-hyp | Run QEMU with `-cpu max`. |
| `check.sh` fails at `cargo check` for musl | Install the two musl targets (section 2). |
| A `check.sh` expectation fails only sometimes | The pattern depends on timing under multi-threaded TCG. Assert on what was delivered instead. |

## Appendix: system call numbers

`osmium::proc::syscall::Sys` covers these calls. The numbers are Linux's: the
x86_64 table, and the asm-generic table that RISC-V and AArch64 share.

| Call | x86_64 | riscv64 / aarch64 |
|---|---|---|
| read, write | 0, 1 | 63, 64 |
| readv, writev | 19, 20 | 65, 66 |
| openat, close | 257, 3 | 56, 57 |
| lseek | 8 | 62 |
| fstat, newfstatat | 5, 262 | 80, 79 |
| getdents64 | 217 | 61 |
| ioctl | 16 | 29 |
| getcwd, chdir | 79, 80 | 17, 49 |
| mkdirat, unlinkat | 258, 263 | 34, 35 |
| exit, exit_group | 60, 231 | 93, 94 |
| getpid, getppid, gettid | 39, 110, 186 | 172, 173, 178 |
| brk, mmap, munmap | 12, 9, 11 | 214, 222, 215 |
| sched_yield | 24 | 124 |
| uname | 63 | 160 |
| clone, execve, wait4 | 56, 59, 61 | 220, 221, 260 |
| fork, vfork | 57, 58 | — |
| dup, dup3, fcntl | 32, 292, 72 | 23, 24, 25 |
| dup2 | 33 | — |
