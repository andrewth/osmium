//! Osmium: a separable toolkit for building operating systems, firmware and
//! hypervisors.
//!
//! Each subsystem is its own crate, re-exported here behind a Cargo feature of
//! the same name:
//!
//! | Module | Crate | Contents |
//! |---|---|---|
//! | [`arch`] | `osmium-arch` | IRQ flags, CPU id, TLB maintenance, arch registers |
//! | `sync` | `osmium-sync` | spin locks, once cells, per-CPU data, SPSC ring |
//! | `mm` | `osmium-mm` | addresses, memory maps, frame allocators, page tables, heap |
//! | `hal` | `osmium-hal` | MMIO/port I/O, device traits, IRQ dispatch, console |
//! | `drivers` | `osmium-drivers` | 16550, PL011, PLIC, GICv2, local APIC, RAM disk |
//! | `boot` | `osmium-boot` | FDT and Multiboot2 parsing, FDT writer |
//! | `sched` | `osmium-sched` | tasks, context switch, schedulers, wait queues, timers |
//! | `virt` | `osmium-virt` | guest memory, stage-2 tables, device buses, VM exits |
//! | `exec` | `osmium-exec` | heap-free async executor for firmware |
//! | `fs` | `osmium-fs` | virtual file system, mounts, RAM file system, initramfs |
//! | `fs_fat` | `osmium-fs-fat` | FAT32 with long names on any block device |
//! | `fs_ext4` | `osmium-fs-ext4` | ext2, ext3 and ext4, read and write, on any block device |
//! | `fs_iso9660` | `osmium-fs-iso9660` | read-only ISO 9660 with Rock Ridge and Joliet on any block device |
//! | `proc` | `osmium-proc` | processes, user address spaces, fd tables, Linux-numbered system calls |
//! | `net` | `osmium-net` | IPv4 stack: ARP, ICMP echo, UDP, TCP, DHCP client |
//! | `iscsi` | `osmium-iscsi` | iSCSI initiator: a remote SCSI disk over TCP as a block device |
//!
//! The library never defines an entry point, panic handler or global
//! allocator: the OS assembles those from the parts it uses.
#![no_std]

pub use osmium_arch as arch;
#[cfg(feature = "boot")]
pub use osmium_boot as boot;
#[cfg(feature = "drivers")]
pub use osmium_drivers as drivers;
#[cfg(feature = "exec")]
pub use osmium_exec as exec;
#[cfg(feature = "fs")]
pub use osmium_fs as fs;
#[cfg(feature = "proc")]
pub use osmium_proc as proc;
#[cfg(feature = "fs-fat")]
pub use osmium_fs_fat as fs_fat;
#[cfg(feature = "net")]
pub use osmium_net as net;
#[cfg(feature = "fs-ext4")]
pub use osmium_fs_ext4 as fs_ext4;
#[cfg(feature = "fs-iso9660")]
pub use osmium_fs_iso9660 as fs_iso9660;
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
