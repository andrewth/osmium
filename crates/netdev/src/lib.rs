//! Network device drivers built on `osmium-hal`, each a [`NetDevice`](osmium_hal::net::NetDevice).
//!
//! | Driver | Device | Implements |
//! |---|---|---|
//! | [`virtio_net::VirtioNet`] | virtio network card (MMIO or PCI, legacy and 1.x) | `NetDevice` |
//! | [`mlx4::Mlx4`] | Mellanox ConnectX-2/-3 Ethernet, InfiniBand and IPoIB (PCI, polled or MSI-X) | `NetDevice` per Ethernet port or IPoIB interface; UD datagrams and reliable connections per InfiniBand port |
//! | [`usb::ecm::UsbEthernet`] | USB Ethernet (CDC-ECM) on any `UsbHost` | `NetDevice` |
//! | [`usb::ncm::UsbNcm`] | USB Ethernet (CDC-NCM; simulator-tested only) on any `UsbHost` | `NetDevice` |
//!
//! The virtio driver runs over the transports and queues of `osmium-drivers`; the USB ones run over
//! any [`UsbHost`](osmium_hal::usb::UsbHost), such as the controllers of `osmium-usb`.
#![no_std]

#[cfg(test)]
extern crate std;

pub mod mlx4;
pub mod usb;
pub mod virtio_net;
