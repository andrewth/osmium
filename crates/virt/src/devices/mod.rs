//! Emulated devices.

mod gic;
mod gicv3;
mod ioapic;
mod lapic;
mod pic;
mod pl011;
mod pit;
mod plic;
mod uart;

pub use gic::{GIC_WINDOW, SPURIOUS, VirtualGicV2};
pub use gicv3::{GICD_V3_WINDOW, GICR_STRIDE, VirtualGicV3, vcpu_affinity, vcpu_mpidr};
pub use ioapic::{IOAPIC_WINDOW, IoApicMessage, VirtualIoApic};
pub use lapic::{IpiKind, IpiTarget, LAPIC_WINDOW, VirtualLapic, decode_icr};
pub use pic::VirtualPic;
pub use pl011::{PL011_WINDOW, Pl011};
pub use pit::{PIT_HZ, VirtualPit};
pub use plic::VirtualPlic;
pub use uart::Uart16550;
