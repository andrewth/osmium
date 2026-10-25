//! The virtio core shared by the device drivers: the [`virtio::Transport`] trait, its MMIO and PCI
//! implementations ([`virtio::mmio`], [`virtio::pci`]) and the split virtqueue ([`virtio::queue`]).
//!
//! The device drivers themselves live in `osmium-storage` (virtio-blk), `osmium-netdev` (virtio-net)
//! and `osmium-display` (virtio-gpu).
#![no_std]

#[cfg(any(test, feature = "testing"))]
extern crate std;

pub mod virtio;
