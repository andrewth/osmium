// SPDX-License-Identifier: GPL-2.0-only
//! Osmium: a separable toolkit for building operating systems, firmware and
//! hypervisors.
//!
//! Each subsystem is its own crate, re-exported here behind a Cargo feature of
//! the same name:
//!
//! | Module | Crate | Contents |
//! |---|---|---|
//! | [`arch`] | `osmium-arch` | IRQ flags, CPU id, traps, TLB maintenance, MMU and system registers |
//! | `sync` | `osmium-sync` | ticket, MCS, reader/writer and sequence locks, RCU, once cells, per-CPU data, SPSC ring, intrusive lists and trees |
//! | `mm` | `osmium-mm` | addresses, memory maps, frame allocators, page tables, heap, VMAs, swap |
//! | `hal` | `osmium-hal` | MMIO/port I/O, device-class traits, IRQ dispatch, console, PCI, USB and virtio definitions, DMA and IOMMU model |
//! | `drivers` | `osmium-drivers` | the virtio core: MMIO and PCI transports, split virtqueues, virtio console |
//! | `sysdrv` | `osmium-sysdrv` | 16550 and PL011 UARTs, `fw_cfg`, PIT, HPET, PLIC, CLINT, GICv2, GICv3, local APIC, I/O APIC, VT-d, AMD-Vi, SMMUv3, RISC-V IOMMU |
//! | `storage` | `osmium-storage` | virtio-blk, AHCI, NVMe, RAM disk |
//! | `display` | `osmium-display` | virtio-gpu, Bochs DISPI, VESA BIOS Extensions, EDID |
//! | `usb` | `osmium-usb` | xHCI, EHCI, OHCI and UHCI host controllers; mass-storage and HID class drivers |
//! | `netdev` | `osmium-netdev` | virtio-net, mlx4 (Ethernet and IPoIB), USB CDC-ECM and CDC-NCM network drivers |
//! | `boot` | `osmium-boot` | FDT parsing and writer, Multiboot2, PVH, ELF64, PE32+, UEFI, static ACPI tables (RSDP, MADT, MCFG) |
//! | `sched` | `osmium-sched` | tasks, context switch, schedulers, wait queues, timers |
//! | `virt` | `osmium-virt` | guest memory, stage-2 tables, device buses and emulated devices, virtio models, RISC-V H, AArch64 EL2, AMD SVM and Intel VMX vCPUs |
//! | `exec` | `osmium-exec` | heap-free async executor for firmware |
//! | `fs` | `osmium-fs` | virtual file system, mounts, RAM file system, overlay, synthetic trees, `/dev`, cpio initramfs |
//! | `fs_fat` | `osmium-fs-fat` | FAT12, FAT16 and FAT32 with long names on any block device |
//! | `fs_ext4` | `osmium-fs-ext4` | ext2, ext3 and ext4, read and write, on any block device |
//! | `fs_iso9660` | `osmium-fs-iso9660` | read-only ISO 9660 with Rock Ridge and Joliet on any block device |
//! | `fs_btrfs` | `osmium-fs-btrfs` | btrfs, read and write: subvolumes, checksums, zlib, LZO and zstd, on any block device |
//! | `proc` | `osmium-proc` | processes, user address spaces, fd tables, Linux-numbered system calls |
//! | `net` | `osmium-net` | IPv4 and IPv6 stack: ARP and neighbor discovery, ICMP, UDP, TCP, DHCP and DHCPv6, DNS, multicast |
//! | `iscsi` | `osmium-iscsi` | iSCSI initiator: a remote SCSI disk over TCP as a block device |
//! | `rand` | `osmium-rand` | entropy sources, SHA-256, ChaCha20 random number generator |
//! | `tls` | `osmium-tls` | TLS 1.3 servers over rustls, self-signed certificates |
//! | `http` | `osmium-http` | sans-I/O HTTP/1.1 server |
//! | `acpi` | `osmium-acpi` | ACPI: FADT, AML interpreter, devices, resources, PCI routing, sleep states, SCI and GPE events |
//!
//! The library never defines an entry point, panic handler or global
//! allocator: the OS assembles those from the parts it uses.
#![no_std]

pub use osmium_arch as arch;
#[cfg(feature = "acpi")]
pub use osmium_acpi as acpi;
#[cfg(feature = "boot")]
pub use osmium_boot as boot;
#[cfg(feature = "drivers")]
pub use osmium_drivers as drivers;
#[cfg(feature = "usb")]
pub use osmium_usb as usb;
#[cfg(feature = "sysdrv")]
pub use osmium_sysdrv as sysdrv;
#[cfg(feature = "display")]
pub use osmium_display as display;
#[cfg(feature = "storage")]
pub use osmium_storage as storage;
#[cfg(feature = "netdev")]
pub use osmium_netdev as netdev;
#[cfg(feature = "exec")]
pub use osmium_exec as exec;
#[cfg(feature = "fs")]
pub use osmium_fs as fs;
#[cfg(feature = "proc")]
pub use osmium_proc as proc;
#[cfg(feature = "rand")]
pub use osmium_rand as rand;
#[cfg(feature = "tls")]
pub use osmium_tls as tls;
#[cfg(feature = "http")]
pub use osmium_http as http;
#[cfg(feature = "fs-fat")]
pub use osmium_fs_fat as fs_fat;
#[cfg(feature = "net")]
pub use osmium_net as net;
#[cfg(feature = "fs-ext4")]
pub use osmium_fs_ext4 as fs_ext4;
#[cfg(feature = "fs-iso9660")]
pub use osmium_fs_iso9660 as fs_iso9660;
#[cfg(feature = "fs-btrfs")]
pub use osmium_fs_btrfs as fs_btrfs;
#[cfg(feature = "iscsi")]
pub use osmium_iscsi as iscsi;
#[cfg(feature = "hal")]
pub use osmium_hal as hal;
#[cfg(feature = "mm")]
pub use osmium_mm as mm;
#[cfg(feature = "sched")]
pub use osmium_sched as sched;
#[cfg(feature = "sync")]
pub use osmium_sync as sync;
#[cfg(feature = "virt")]
pub use osmium_virt as virt;
