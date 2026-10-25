//! Hardware abstraction: register access, device-class traits, interrupt
//! dispatch and the console.
//!
//! The pattern throughout is OSTD's: an `unsafe` constructor states the
//! hardware invariant once ("this range is a device's registers and nobody
//! else touches it"), and every operation afterwards is safe.
//!
//! - [`mmio`]: register cells for `#[repr(C)]` register blocks, and the
//!   bounds-checked [`mmio::IoMem`] window.
//! - [`port`]: typed x86 I/O ports.
//! - [`serial`], [`irq`], [`timer`], [`block`], [`net`]: device-class traits
//!   that drivers implement and kernels consume.
//! - [`asynch`]: async counterparts of the block, serial and network traits,
//!   and adapters from the blocking ones.
//! - [`usb`]: USB descriptors and requests, the [`usb::UsbHost`]
//!   host-controller trait and device enumeration.
//! - [`pci`]: configuration space (ECAM), enumeration, BARs, capabilities.
//! - [`virtio`]: virtio register, feature and ring-layout definitions shared
//!   by drivers and device models.
//! - [`irq::IrqTable`]: maps interrupt numbers to handlers.
//! - [`console`]: a swappable global console behind `print!`/`println!`.
//! - [`dma`]: DMA buffer descriptors.
//! - [`iommu`]: the IOMMU model: domains, IOVA allocation and DMA through
//!   an IOMMU.
//! - [`display`]: linear framebuffers, pixel formats and the
//!   [`display::Display`] trait.
#![no_std]

#[cfg(test)]
extern crate std;

pub mod asynch;
pub mod block;
pub mod console;
pub mod display;
pub mod fbcon;
pub mod dma;
pub mod iommu;
pub mod ioext;
pub mod irq;
pub mod mmio;
pub mod net;
pub mod pci;
#[cfg(target_arch = "x86_64")]
pub mod port;
pub mod serial;
pub mod timer;
pub mod usb;
pub mod virtio;
