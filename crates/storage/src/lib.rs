//! Storage drivers built on `osmium-hal`, each a [`BlockDevice`](osmium_hal::block::BlockDevice).
//!
//! | Driver | Device | Implements |
//! |---|---|---|
//! | [`ramdisk::RamDisk`] | Memory-backed disk | `BlockDevice` |
//! | [`virtio_blk::VirtioBlk`] | virtio block device (MMIO or PCI, legacy and 1.x) | `BlockDevice` |
//! | [`ahci::AhciDisk`] | SATA disk on an AHCI HBA (PCI; polled or interrupt-driven, NCQ) | `BlockDevice` per port |
//! | [`ahci::AhciAtapi`] | ATAPI optical drive on an AHCI HBA (polled, read-only) | `BlockDevice` |
//! | [`nvme::Nvme`] | NVM Express SSD (PCI; polled or MSI-X, multiple I/O queues) | `BlockDevice` |
//!
//! The virtio driver runs over the transports and queues of `osmium-drivers`.
#![no_std]

#[cfg(test)]
extern crate std;

pub mod ahci;
pub mod nvme;
pub mod ramdisk;
pub mod virtio_blk;
