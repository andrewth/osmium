//! Emulated devices.

mod plic;
mod uart;

pub use plic::VirtualPlic;
pub use uart::Uart16550;
