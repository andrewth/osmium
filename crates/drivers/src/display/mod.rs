//! Display controllers.
//!
//! Each driver ends in an [`osmium_hal::display::Display`]: a linear
//! framebuffer, plus a flush for devices that copy from guest memory.
//!
//! - [`bochs::BochsVbe`]: the Bochs VBE ("DISPI") registers of QEMU's
//!   standard VGA, `bochs-display` and `virtio-vga`, which set VESA modes
//!   without the BIOS.
//! - [`vbe`]: VESA BIOS Extensions mode lists and mode information, for
//!   kernels that can call the video BIOS.
//! - [`VirtioGpu`](crate::virtio::gpu::VirtioGpu): virtio-gpu.
//!
//! A UEFI GOP framebuffer needs no driver: `osmium_boot::uefi` turns the
//! GOP mode into a [`osmium_hal::display::FramebufferInfo`].

use osmium_hal::pci::{ConfigAccess, Function};

pub mod bochs;
pub mod vbe;

/// A display adapter recognized on PCI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PciDisplay {
    /// QEMU/Bochs standard VGA (1234:1111, VGA class): DISPI at BAR 2 +
    /// 0x500, framebuffer at BAR 0.
    StdVga,
    /// QEMU `bochs-display` (1234:1111, display class 03/80): as
    /// [`PciDisplay::StdVga`] without the VGA registers.
    BochsDisplay,
    /// `virtio-vga` (1af4:1050, VGA class): a standard VGA (BAR 0 and the
    /// DISPI registers in BAR 2) until a virtio-gpu driver sets a scanout.
    VirtioVga,
    /// `virtio-gpu-pci` (1af4:1050, display class 03/80).
    VirtioGpu,
}

impl PciDisplay {
    /// Identifies `func`, or `None` if it is none of the above.
    pub fn identify<C: ConfigAccess + ?Sized>(func: &Function<'_, C>) -> Option<Self> {
        let class = func.class();
        let vga = class.class == 0x03 && class.subclass == 0x00;
        match (func.vendor_id(), func.device_id()) {
            (0x1234, 0x1111) if vga => Some(Self::StdVga),
            (0x1234, 0x1111) => Some(Self::BochsDisplay),
            (0x1af4, 0x1050) if vga => Some(Self::VirtioVga),
            (0x1af4, 0x1050) => Some(Self::VirtioGpu),
            _ => None,
        }
    }

    /// True for devices with Bochs DISPI registers.
    pub fn has_dispi(self) -> bool {
        !matches!(self, Self::VirtioGpu)
    }

    /// True for devices that decode the legacy VGA ports.
    pub fn is_vga(self) -> bool {
        matches!(self, Self::StdVga | Self::VirtioVga)
    }
}
