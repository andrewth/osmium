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
//! - [`serial`], [`irq`], [`timer`], [`block`]: device-class traits that
//!   drivers implement and kernels consume.
//! - [`irq::IrqTable`]: maps interrupt numbers to handlers.
//! - [`console`]: a swappable global console behind `print!`/`println!`.
//! - [`dma`]: DMA buffer descriptors.
#![no_std]

#[cfg(test)]
extern crate std;

pub mod block;
pub mod console;
pub mod dma;
pub mod irq;
pub mod mmio;
#[cfg(target_arch = "x86_64")]
pub mod port;
pub mod serial;
pub mod timer;
