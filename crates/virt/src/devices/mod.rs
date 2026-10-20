//! Emulated devices.

mod gic;
mod lapic;
mod pic;
mod pit;
mod plic;
mod uart;

pub use gic::{GIC_WINDOW, SPURIOUS, VirtualGicV2};
pub use lapic::{LAPIC_WINDOW, VirtualLapic};
pub use pic::VirtualPic;
pub use pit::{PIT_HZ, VirtualPit};
pub use plic::VirtualPlic;
pub use uart::Uart16550;
