//! Emulated devices.

mod gic;
mod plic;
mod uart;

pub use gic::{GIC_WINDOW, SPURIOUS, VirtualGicV2};
pub use plic::VirtualPlic;
pub use uart::Uart16550;
