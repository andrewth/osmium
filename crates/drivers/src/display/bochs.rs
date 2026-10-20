//! The Bochs VBE ("DISPI") display interface.
//!
//! This is the hardware behind QEMU's VESA BIOS: Bochs and QEMU's standard
//! VGA (`-vga std`, PCI 1234:1111), `bochs-display`, and `virtio-vga`
//! before its virtio-gpu driver takes over. The VGA BIOS's VBE functions
//! just program these registers, so a kernel can set the same linear
//! framebuffer modes without calling the BIOS, on any architecture.
//!
//! Registers are 16 bits, reached either through the index/data port pair
//! 0x1ce/0x1cf (x86 only) or, on the PCI devices, memory-mapped at offset
//! 0x500 of BAR 2 (index × 2). BAR 0 is the framebuffer. QEMU's VGA devices
//! also map the legacy VGA ports 0x3c0–0x3df at BAR 2 + 0x400, which the
//! driver uses to unblank the screen.

use osmium_hal::display::{Display, DisplayError, Framebuffer, FramebufferInfo, PixelFormat};
use osmium_hal::mmio::IoMem;

/// DISPI register indices.
pub mod reg {
    #![allow(missing_docs)]
    pub const ID: u16 = 0;
    pub const XRES: u16 = 1;
    pub const YRES: u16 = 2;
    pub const BPP: u16 = 3;
    pub const ENABLE: u16 = 4;
    pub const BANK: u16 = 5;
    pub const VIRT_WIDTH: u16 = 6;
    pub const VIRT_HEIGHT: u16 = 7;
    pub const X_OFFSET: u16 = 8;
    pub const Y_OFFSET: u16 = 9;
    /// Video memory size in 64 KiB units (QEMU).
    pub const VIDEO_MEMORY_64K: u16 = 10;
}

/// `ENABLE` bits.
pub mod enable {
    #![allow(missing_docs)]
    pub const ENABLED: u16 = 0x01;
    pub const GETCAPS: u16 = 0x02;
    pub const LFB_ENABLED: u16 = 0x40;
    pub const NOCLEARMEM: u16 = 0x80;
}

/// Oldest and newest `ID` values; 0xb0c5 is current QEMU.
pub const ID_RANGE: core::ops::RangeInclusive<u16> = 0xb0c0..=0xb0c5;

/// Offset of the DISPI registers in a PCI device's MMIO BAR.
pub const MMIO_DISPI: usize = 0x500;
/// Offset of the VGA ports 0x3c0–0x3df in a PCI device's MMIO BAR.
pub const MMIO_VGA: usize = 0x400;

/// x86 index and data ports.
pub const PORT_INDEX: u16 = 0x1ce;
/// See [`PORT_INDEX`].
pub const PORT_DATA: u16 = 0x1cf;

/// How the registers are reached.
enum Regs {
    Mmio(IoMem),
    #[cfg(target_arch = "x86_64")]
    Ports,
}

/// A Bochs VBE display controller.
pub struct BochsVbe {
    regs: Regs,
    /// True if the device has VGA ports to unblank.
    vga: bool,
    vram: IoMem,
    fb: Framebuffer,
}

impl BochsVbe {
    /// The controller whose MMIO BAR (BAR 2) is `mmio` and framebuffer BAR
    /// (BAR 0) is `vram`. Set `vga` for devices with legacy VGA ports in the
    /// BAR (std VGA, `virtio-vga`), clear it for `bochs-display`.
    pub fn new_mmio(mmio: IoMem, vram: IoMem, vga: bool) -> Result<Self, DisplayError> {
        if mmio.len() < MMIO_DISPI + 0x20 {
            return Err(DisplayError::BadGeometry);
        }
        Self::probe(Regs::Mmio(mmio), vram, vga)
    }

    /// The controller behind ports 0x1ce/0x1cf, with its framebuffer at
    /// `vram` (the VGA device's BAR 0).
    ///
    /// # Safety
    /// The caller owns the ports, and the legacy VGA ports 0x3c0 and 0x3da.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn new_ports(vram: IoMem) -> Result<Self, DisplayError> {
        Self::probe(Regs::Ports, vram, true)
    }

    fn probe(regs: Regs, vram: IoMem, vga: bool) -> Result<Self, DisplayError> {
        let mut dev = Self {
            regs,
            vga,
            fb: Framebuffer::new(vram.slice(0, 0)?, FramebufferInfo::packed(0, 0, PixelFormat::XRGB8888))?,
            vram,
        };
        if !ID_RANGE.contains(&dev.read(reg::ID)) {
            return Err(DisplayError::Unsupported);
        }
        if dev.read(reg::ENABLE) & enable::ENABLED != 0 {
            // Keep the firmware's mode (set through the VBE BIOS, say). One this driver cannot
            // describe leaves the placeholder framebuffer: `set_mode` still works.
            if let Ok(fb) = dev.current() {
                dev.fb = fb;
            }
        }
        Ok(dev)
    }

    /// Reads DISPI register `index`.
    pub fn read(&self, index: u16) -> u16 {
        match &self.regs {
            Regs::Mmio(io) => io.read(MMIO_DISPI + 2 * index as usize).unwrap_or(0),
            #[cfg(target_arch = "x86_64")]
            // SAFETY: `new_ports` made the caller vouch for the ports.
            Regs::Ports => unsafe {
                osmium_arch::x86_64::outw(PORT_INDEX, index);
                osmium_arch::x86_64::inw(PORT_DATA)
            },
        }
    }

    /// Writes DISPI register `index`.
    pub fn write(&self, index: u16, value: u16) {
        match &self.regs {
            Regs::Mmio(io) => {
                let _ = io.write(MMIO_DISPI + 2 * index as usize, value);
            }
            #[cfg(target_arch = "x86_64")]
            // SAFETY: as in `read`.
            Regs::Ports => unsafe {
                osmium_arch::x86_64::outw(PORT_INDEX, index);
                osmium_arch::x86_64::outw(PORT_DATA, value);
            },
        }
    }

    /// The `ID` register: the interface version.
    pub fn version(&self) -> u16 {
        self.read(reg::ID)
    }

    /// Bytes of video memory: the device's count, capped at the BAR.
    pub fn vram_size(&self) -> usize {
        match self.read(reg::VIDEO_MEMORY_64K) as usize * 0x10000 {
            0 => self.vram.len(),
            n => n.min(self.vram.len()),
        }
    }

    /// Sets the VGA attribute controller's palette-address-source bit,
    /// without which a VGA device shows a black screen.
    fn unblank(&self) {
        if !self.vga {
            return;
        }
        match &self.regs {
            Regs::Mmio(io) => {
                // Reading input status 1 (0x3da) resets the index/data
                // flip-flop of the attribute controller (0x3c0).
                let _ = io.read::<u8>(MMIO_VGA + 0x1a);
                let _ = io.write::<u8>(MMIO_VGA, 0x20);
            }
            #[cfg(target_arch = "x86_64")]
            // SAFETY: `new_ports` made the caller vouch for the VGA ports.
            Regs::Ports => unsafe {
                osmium_arch::x86_64::inb(0x3da);
                osmium_arch::x86_64::outb(0x3c0, 0x20);
            },
        }
    }

    /// The framebuffer of the mode the registers hold.
    fn current(&self) -> Result<Framebuffer, DisplayError> {
        let format = match self.read(reg::BPP) {
            32 => PixelFormat::XRGB8888,
            24 => PixelFormat::RGB888,
            16 => PixelFormat::RGB565,
            _ => return Err(DisplayError::Unsupported),
        };
        let stride = self.read(reg::VIRT_WIDTH) as u32 * format.bytes_per_pixel() as u32;
        let info =
            FramebufferInfo { width: self.read(reg::XRES) as u32, height: self.read(reg::YRES) as u32, stride, format };
        let off = self.read(reg::Y_OFFSET) as usize * stride as usize
            + self.read(reg::X_OFFSET) as usize * format.bytes_per_pixel();
        Framebuffer::new(self.vram.slice(off, self.vram_size().saturating_sub(off))?, info)
    }

    /// Switches to a `width` by `height` linear framebuffer mode of `bpp`
    /// (16, 24 or 32) bits per pixel. The screen is cleared.
    pub fn set_mode(&mut self, width: u16, height: u16, bpp: u16) -> Result<FramebufferInfo, DisplayError> {
        if !matches!(bpp, 16 | 24 | 32) || width == 0 || height == 0 {
            return Err(DisplayError::Unsupported);
        }
        if width as usize * height as usize * (bpp as usize / 8) > self.vram_size() {
            return Err(DisplayError::NoMemory);
        }
        self.unblank();
        self.write(reg::ENABLE, 0);
        self.write(reg::BPP, bpp);
        self.write(reg::XRES, width);
        self.write(reg::YRES, height);
        self.write(reg::BANK, 0);
        self.write(reg::VIRT_WIDTH, width);
        self.write(reg::VIRT_HEIGHT, height);
        self.write(reg::X_OFFSET, 0);
        self.write(reg::Y_OFFSET, 0);
        self.write(reg::ENABLE, enable::ENABLED | enable::LFB_ENABLED);
        if (self.read(reg::XRES), self.read(reg::YRES), self.read(reg::BPP)) != (width, height, bpp) {
            self.write(reg::ENABLE, 0);
            return Err(DisplayError::Unsupported);
        }
        self.fb = self.current()?;
        Ok(self.fb.info())
    }

    /// Switches the linear framebuffer off (back to VGA text mode, if the
    /// device has one and the VGA registers still hold it).
    pub fn disable(&mut self) {
        self.write(reg::ENABLE, 0);
        self.fb = Framebuffer::new(
            self.vram.slice(0, 0).expect("empty slice"),
            FramebufferInfo::packed(0, 0, PixelFormat::XRGB8888),
        )
        .expect("empty framebuffer");
    }
}

impl Display for BochsVbe {
    /// The current mode's framebuffer; 0 by 0 if none is set.
    fn framebuffer(&self) -> &Framebuffer {
        &self.fb
    }
}

#[cfg(test)]
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use osmium_hal::display::{Rect, Rgb};
    use std::vec;

    /// A fake MMIO BAR: plain memory, so registers read back what was
    /// written, which is what the device does for supported modes.
    fn mmio(regs: &mut [u16]) -> IoMem {
        regs[MMIO_DISPI / 2] = 0xb0c5;
        regs[MMIO_DISPI / 2 + reg::VIDEO_MEMORY_64K as usize] = 1;
        // SAFETY: the window covers a local array.
        unsafe { IoMem::new(regs.as_mut_ptr().cast(), regs.len() * 2) }
    }

    #[test]
    fn set_mode() {
        let mut regs = vec![0u16; 0x800];
        let mut vram = vec![0u32; 0x8000]; // 128 KiB, of which the device reports 64
        // SAFETY: as above.
        let vram_io = unsafe { IoMem::new(vram.as_mut_ptr().cast(), vram.len() * 4) };
        let mut vbe = BochsVbe::new_mmio(mmio(&mut regs), vram_io, true).unwrap();
        assert_eq!(vbe.version(), 0xb0c5);
        assert_eq!(vbe.vram_size(), 0x10000);
        assert_eq!(vbe.info().width, 0, "no mode yet");
        assert_eq!(vbe.set_mode(256, 256, 32), Err(DisplayError::NoMemory));
        assert_eq!(vbe.set_mode(64, 64, 8), Err(DisplayError::Unsupported));

        let info = vbe.set_mode(128, 64, 32).unwrap();
        assert_eq!((info.width, info.height, info.stride, info.format), (128, 64, 512, PixelFormat::XRGB8888));
        vbe.framebuffer().fill_rect(Rect::new(1, 1, 1, 1), Rgb::new(0xff, 0, 0));
        vbe.flush_all().unwrap();
        drop(vbe);
        assert_eq!(vram[128 + 1], 0xff_0000);
        let dispi = &regs[MMIO_DISPI / 2..];
        assert_eq!(dispi[reg::ENABLE as usize], enable::ENABLED | enable::LFB_ENABLED);
        assert_eq!(dispi[reg::VIRT_WIDTH as usize], 128);
        assert_eq!(regs[MMIO_VGA / 2] & 0xff, 0x20, "unblanked");
    }

    #[test]
    fn keeps_firmware_mode_and_rejects_others() {
        let mut regs = vec![0u16; 0x800];
        let mut vram = vec![0u32; 0x4000];
        let io = mmio(&mut regs);
        let d = |r: u16, v: u16| io.write(MMIO_DISPI + 2 * r as usize, v).unwrap();
        d(reg::XRES, 64);
        d(reg::YRES, 32);
        d(reg::BPP, 16);
        d(reg::VIRT_WIDTH, 80);
        d(reg::Y_OFFSET, 2);
        d(reg::ENABLE, enable::ENABLED | enable::LFB_ENABLED);
        // SAFETY: as above.
        let vram_io = unsafe { IoMem::new(vram.as_mut_ptr().cast(), vram.len() * 4) };
        let vbe = BochsVbe::new_mmio(io.clone(), vram_io.clone(), false).unwrap();
        let info = vbe.info();
        assert_eq!((info.width, info.height, info.stride, info.format), (64, 32, 160, PixelFormat::RGB565));
        vbe.framebuffer().set_pixel(0, 0, Rgb::WHITE);
        drop(vbe);
        assert_eq!(vram[2 * 160 / 4], 0xffff, "panned by Y_OFFSET");

        d(reg::ID, 0x1234);
        assert!(BochsVbe::new_mmio(io, vram_io, false).is_err());
    }

    #[test]
    fn unsupported_firmware_mode_is_no_mode() {
        let mut regs = vec![0u16; 0x800];
        let mut vram = vec![0u32; 0x4000];
        let io = mmio(&mut regs);
        io.write(MMIO_DISPI + 2 * reg::BPP as usize, 8u16).unwrap();
        io.write(MMIO_DISPI + 2 * reg::ENABLE as usize, enable::ENABLED).unwrap();
        // SAFETY: as above.
        let vram_io = unsafe { IoMem::new(vram.as_mut_ptr().cast(), vram.len() * 4) };
        let mut vbe = BochsVbe::new_mmio(io, vram_io, false).unwrap();
        assert_eq!(vbe.info().width, 0);
        assert!(vbe.set_mode(64, 32, 32).is_ok());
    }
}
