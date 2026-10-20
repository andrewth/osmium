//! Linear framebuffers.
//!
//! Every display driver ends in the same place: a block of memory the CPU
//! writes pixels into, `stride` bytes per row, in some packed RGB format. A
//! VESA or GOP framebuffer is that memory on the graphics card and needs
//! nothing more. A virtio-gpu framebuffer is guest RAM that the device copies
//! from when told, so [`Display::flush`] exists for drivers like it.
//!
//! [`PixelFormat`] describes a format the way VBE mode info, GOP's
//! `PixelBitMask`, Multiboot2 and virtio-gpu all can: bits per pixel and the
//! position and width of each colour channel.

use crate::mmio::{IoMem, IoMemError};

/// An 8-bit-per-channel colour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rgb {
    /// Red.
    pub r: u8,
    /// Green.
    pub g: u8,
    /// Blue.
    pub b: u8,
}

impl Rgb {
    /// Black.
    pub const BLACK: Self = Self::new(0, 0, 0);
    /// White.
    pub const WHITE: Self = Self::new(0xff, 0xff, 0xff);

    /// The colour `(r, g, b)`.
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }
}

/// Where one colour channel sits in a pixel value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Channel {
    /// Bit position of the channel's least significant bit.
    pub shift: u8,
    /// Width in bits (1–8).
    pub bits: u8,
}

impl Channel {
    const fn new(shift: u8, bits: u8) -> Self {
        Self { shift, bits }
    }

    /// The channel of a contiguous `mask`, or `None` if it is empty, has
    /// gaps or is wider than 8 bits.
    pub const fn from_mask(mask: u32) -> Option<Self> {
        if mask == 0 {
            return None;
        }
        let shift = mask.trailing_zeros();
        let bits = (mask >> shift).trailing_ones();
        if mask >> shift >> bits != 0 || bits > 8 {
            return None;
        }
        Some(Self::new(shift as u8, bits as u8))
    }

    /// The channel's bits within a pixel value.
    pub const fn mask(&self) -> u32 {
        ((1u32 << self.bits) - 1) << self.shift
    }

    /// True if 1–8 bits wide and inside a `bpp`-bit pixel.
    const fn fits(&self, bpp: u8) -> bool {
        self.bits >= 1 && self.bits <= 8 && self.shift as u32 + self.bits as u32 <= bpp as u32
    }

    fn encode(&self, v: u8) -> u32 {
        (v as u32 >> (8 - self.bits)) << self.shift
    }

    fn decode(&self, pixel: u32) -> u8 {
        let v = (pixel >> self.shift) & ((1 << self.bits) - 1);
        // Replicate the high bits into the low ones, so full scale stays
        // full scale (0x1f in 5 bits reads back as 0xff).
        let mut out = v << (8 - self.bits);
        let mut have = self.bits;
        while have < 8 {
            out |= out >> have;
            have *= 2;
        }
        out as u8
    }
}

/// A packed RGB pixel format, stored little-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PixelFormat {
    /// Bits per pixel: 16, 24 or 32.
    pub bpp: u8,
    /// Red channel.
    pub red: Channel,
    /// Green channel.
    pub green: Channel,
    /// Blue channel.
    pub blue: Channel,
}

impl PixelFormat {
    /// 32 bits, bytes B, G, R, X in memory (VBE and GOP `BGRReserved`, DRM
    /// `XRGB8888`, virtio-gpu `B8G8R8X8`).
    pub const XRGB8888: Self = Self::rgb(32, 16, 8, 0, 8);
    /// 32 bits, bytes R, G, B, X in memory (GOP `RGBReserved`, DRM
    /// `XBGR8888`, virtio-gpu `R8G8B8X8`).
    pub const XBGR8888: Self = Self::rgb(32, 0, 8, 16, 8);
    /// 24 bits, bytes B, G, R in memory.
    pub const RGB888: Self = Self::rgb(24, 16, 8, 0, 8);
    /// 16 bits, 5:6:5.
    pub const RGB565: Self =
        Self { bpp: 16, red: Channel::new(11, 5), green: Channel::new(5, 6), blue: Channel::new(0, 5) };

    const fn rgb(bpp: u8, r: u8, g: u8, b: u8, bits: u8) -> Self {
        Self { bpp, red: Channel::new(r, bits), green: Channel::new(g, bits), blue: Channel::new(b, bits) }
    }

    /// The format with these channel masks, or `None` if `bpp` is not 16,
    /// 24 or 32 or a mask is unusable.
    pub const fn from_masks(bpp: u8, red: u32, green: u32, blue: u32) -> Option<Self> {
        if !matches!(bpp, 16 | 24 | 32) {
            return None;
        }
        let (Some(red), Some(green), Some(blue)) =
            (Channel::from_mask(red), Channel::from_mask(green), Channel::from_mask(blue))
        else {
            return None;
        };
        if (red.mask() | green.mask() | blue.mask()) as u64 >> bpp != 0 {
            return None;
        }
        Some(Self { bpp, red, green, blue })
    }

    /// True if `bpp` is 16, 24 or 32 and every channel is 1–8 bits wide and
    /// inside the pixel. Formats from [`PixelFormat::from_masks`] and the
    /// constants always are; [`Framebuffer::new`] rejects others.
    pub const fn is_valid(&self) -> bool {
        matches!(self.bpp, 16 | 24 | 32)
            && self.red.fits(self.bpp)
            && self.green.fits(self.bpp)
            && self.blue.fits(self.bpp)
    }

    /// Bytes per pixel.
    pub const fn bytes_per_pixel(&self) -> usize {
        self.bpp as usize / 8
    }

    /// The pixel value of `c`.
    pub fn encode(&self, c: Rgb) -> u32 {
        self.red.encode(c.r) | self.green.encode(c.g) | self.blue.encode(c.b)
    }

    /// The colour of pixel value `pixel`.
    pub fn decode(&self, pixel: u32) -> Rgb {
        Rgb::new(self.red.decode(pixel), self.green.decode(pixel), self.blue.decode(pixel))
    }
}

/// A rectangle of pixels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    /// Left column.
    pub x: u32,
    /// Top row.
    pub y: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
}

impl Rect {
    /// The rectangle at `(x, y)` of `width` by `height` pixels.
    pub const fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self { x, y, width, height }
    }

    /// True if it covers no pixels.
    pub const fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// The part of `self` inside `other` (empty if they do not overlap).
    pub fn intersect(&self, other: &Rect) -> Rect {
        let x0 = self.x.max(other.x);
        let y0 = self.y.max(other.y);
        let x1 = (self.x as u64 + self.width as u64).min(other.x as u64 + other.width as u64);
        let y1 = (self.y as u64 + self.height as u64).min(other.y as u64 + other.height as u64);
        if x1 <= x0 as u64 || y1 <= y0 as u64 {
            return Rect::default();
        }
        Rect::new(x0, y0, (x1 - x0 as u64) as u32, (y1 - y0 as u64) as u32)
    }
}

/// The geometry and format of a framebuffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramebufferInfo {
    /// Visible width in pixels.
    pub width: u32,
    /// Visible height in pixels.
    pub height: u32,
    /// Bytes from one row to the next (at least `width` pixels).
    pub stride: u32,
    /// Pixel format.
    pub format: PixelFormat,
}

impl FramebufferInfo {
    /// A tightly packed framebuffer (`stride` is exactly one row; it
    /// saturates, which [`Framebuffer::new`] then rejects).
    pub const fn packed(width: u32, height: u32, format: PixelFormat) -> Self {
        Self { width, height, stride: width.saturating_mul(format.bytes_per_pixel() as u32), format }
    }

    /// Bytes the framebuffer covers.
    pub const fn size(&self) -> usize {
        self.stride as usize * self.height as usize
    }

    /// The whole visible area.
    pub const fn bounds(&self) -> Rect {
        Rect::new(0, 0, self.width, self.height)
    }
}

/// Why a display operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayError {
    /// No such mode, or the hardware cannot do what was asked.
    Unsupported,
    /// The framebuffer memory is smaller than its geometry says, or rows
    /// overlap.
    BadGeometry,
    /// Memory for the framebuffer could not be allocated.
    NoMemory,
    /// The device reported an error.
    Device,
}

impl From<IoMemError> for DisplayError {
    fn from(_: IoMemError) -> Self {
        DisplayError::BadGeometry
    }
}

/// A linear framebuffer in memory the CPU can write.
///
/// Drawing clips to the visible area. Methods take `&self`: the memory is
/// written with volatile stores, like any other [`IoMem`].
pub struct Framebuffer {
    mem: IoMem,
    info: FramebufferInfo,
}

impl Framebuffer {
    /// The framebuffer described by `info` in `mem`, which must be at least
    /// [`FramebufferInfo::size`] bytes, with rows that hold `width` pixels,
    /// a valid format and a base and stride aligned for its pixels.
    pub fn new(mem: IoMem, info: FramebufferInfo) -> Result<Self, DisplayError> {
        let bpp = info.format.bytes_per_pixel();
        let row = info.width as usize * bpp;
        let align = if bpp == 3 { 1 } else { bpp };
        if !info.format.is_valid()
            || row > info.stride as usize
            || mem.len() < info.size()
            || !(mem.base() as usize).is_multiple_of(align)
            || !(info.stride as usize).is_multiple_of(align)
        {
            return Err(DisplayError::BadGeometry);
        }
        Ok(Self { mem: mem.slice(0, info.size())?, info })
    }

    /// Its geometry and format.
    pub fn info(&self) -> FramebufferInfo {
        self.info
    }

    /// The memory behind it.
    pub fn mem(&self) -> &IoMem {
        &self.mem
    }

    fn offset(&self, x: u32, y: u32) -> usize {
        y as usize * self.info.stride as usize + x as usize * self.info.format.bytes_per_pixel()
    }

    fn store(&self, off: usize, v: u32) {
        // Offsets come from clipped coordinates; `new` checked the size.
        let _ = match self.info.format.bpp {
            32 if off.is_multiple_of(4) => self.mem.write(off, v),
            16 if off.is_multiple_of(2) => self.mem.write(off, v as u16),
            bpp => (0..bpp as usize / 8).try_for_each(|i| self.mem.write(off + i, (v >> (8 * i)) as u8)),
        };
    }

    fn load(&self, off: usize) -> u32 {
        match self.info.format.bpp {
            32 if off.is_multiple_of(4) => self.mem.read::<u32>(off).unwrap_or(0),
            16 if off.is_multiple_of(2) => self.mem.read::<u16>(off).unwrap_or(0) as u32,
            bpp => {
                (0..bpp as usize / 8).fold(0, |v, i| v | (self.mem.read::<u8>(off + i).unwrap_or(0) as u32) << (8 * i))
            }
        }
    }

    /// Sets the pixel at `(x, y)`; outside the visible area does nothing.
    pub fn set_pixel(&self, x: u32, y: u32, c: Rgb) {
        if x < self.info.width && y < self.info.height {
            self.store(self.offset(x, y), self.info.format.encode(c));
        }
    }

    /// The pixel at `(x, y)`, or `None` outside the visible area.
    pub fn pixel(&self, x: u32, y: u32) -> Option<Rgb> {
        (x < self.info.width && y < self.info.height).then(|| self.info.format.decode(self.load(self.offset(x, y))))
    }

    /// Fills `rect` with `c`.
    pub fn fill_rect(&self, rect: Rect, c: Rgb) {
        let v = self.info.format.encode(c);
        self.for_each_pixel(rect, |off, _, _| self.store(off, v));
    }

    /// Fills the visible area with `c`.
    pub fn clear(&self, c: Rgb) {
        self.fill_rect(self.info.bounds(), c);
    }

    /// Sets every pixel of `rect` to `f(x, y)`.
    pub fn draw(&self, rect: Rect, mut f: impl FnMut(u32, u32) -> Rgb) {
        self.for_each_pixel(rect, |off, x, y| self.store(off, self.info.format.encode(f(x, y))));
    }

    /// Draws a `width`-pixel wide bitmap (one bit per pixel, most
    /// significant bit leftmost, rows padded to whole bytes) at `(x, y)`:
    /// set bits in `fg`, clear bits in `bg`, or left alone if `bg` is
    /// `None`. This is how a bitmap font is drawn.
    pub fn draw_bitmap(&self, x: u32, y: u32, width: u32, bits: &[u8], fg: Rgb, bg: Option<Rgb>) {
        let row_bytes = width.div_ceil(8) as usize;
        if row_bytes == 0 {
            return;
        }
        let height = (bits.len() / row_bytes) as u32;
        let (fg, bg) = (self.info.format.encode(fg), bg.map(|c| self.info.format.encode(c)));
        self.for_each_pixel(Rect::new(x, y, width, height), |off, px, py| {
            let (col, row) = ((px - x) as usize, (py - y) as usize);
            match (bits[row * row_bytes + col / 8] & (0x80 >> (col % 8)) != 0, bg) {
                (true, _) => self.store(off, fg),
                (false, Some(bg)) => self.store(off, bg),
                (false, None) => {}
            }
        });
    }

    /// Moves the visible area up by `rows` and fills the uncovered rows at
    /// the bottom with `fill`, as a text console scrolls.
    pub fn scroll_up(&self, rows: u32, fill: Rgb) {
        let rows = rows.min(self.info.height);
        let row = self.info.width as usize * self.info.format.bytes_per_pixel();
        let stride = self.info.stride as usize;
        for y in 0..(self.info.height - rows) as usize {
            let (dst, src) = (y * stride, (y + rows as usize) * stride);
            if row.is_multiple_of(4) && stride.is_multiple_of(4) {
                for i in (0..row).step_by(4) {
                    let _ = self.mem.write(dst + i, self.mem.read::<u32>(src + i).unwrap_or(0));
                }
            } else {
                for i in 0..row {
                    let _ = self.mem.write(dst + i, self.mem.read::<u8>(src + i).unwrap_or(0));
                }
            }
        }
        self.fill_rect(Rect::new(0, self.info.height - rows, self.info.width, rows), fill);
    }

    /// Calls `f(offset, x, y)` for each visible pixel of `rect`, row by row.
    fn for_each_pixel(&self, rect: Rect, mut f: impl FnMut(usize, u32, u32)) {
        let r = rect.intersect(&self.info.bounds());
        for y in r.y..r.y + r.height {
            let mut off = self.offset(r.x, y);
            for x in r.x..r.x + r.width {
                f(off, x, y);
                off += self.info.format.bytes_per_pixel();
            }
        }
    }
}

/// A screen: a framebuffer to draw in, and a way to make what was drawn
/// visible.
pub trait Display {
    /// The framebuffer.
    fn framebuffer(&self) -> &Framebuffer;

    /// Makes what was drawn in `rect` visible. Scanned-out memory (VESA,
    /// GOP) shows writes at once, so the default does nothing.
    fn flush(&mut self, rect: Rect) -> Result<(), DisplayError> {
        let _ = rect;
        Ok(())
    }

    /// Its geometry and format.
    fn info(&self) -> FramebufferInfo {
        self.framebuffer().info()
    }

    /// Flushes the whole visible area.
    fn flush_all(&mut self) -> Result<(), DisplayError> {
        let bounds = self.info().bounds();
        self.flush(bounds)
    }
}

impl Display for Framebuffer {
    fn framebuffer(&self) -> &Framebuffer {
        self
    }
}

#[cfg(test)]
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn fb(mem: &mut [u32], info: FramebufferInfo) -> Framebuffer {
        // SAFETY: the window covers a local buffer that outlives the test.
        Framebuffer::new(unsafe { IoMem::new(mem.as_mut_ptr().cast(), mem.len() * 4) }, info).unwrap()
    }

    #[test]
    fn formats() {
        let red = Rgb::new(0xff, 0, 0);
        assert_eq!(PixelFormat::XRGB8888.encode(red), 0x00ff_0000);
        assert_eq!(PixelFormat::XBGR8888.encode(red), 0x0000_00ff);
        assert_eq!(PixelFormat::RGB565.encode(Rgb::new(0xff, 0x80, 0x08)), 0xfc01);
        assert_eq!(PixelFormat::RGB565.decode(0xffff), Rgb::WHITE);
        assert_eq!(PixelFormat::RGB565.decode(0xf800), red);
        assert_eq!(PixelFormat::from_masks(32, 0xff_0000, 0xff00, 0xff), Some(PixelFormat::XRGB8888));
        assert_eq!(PixelFormat::from_masks(16, 0xf800, 0x07e0, 0x001f), Some(PixelFormat::RGB565));
        assert_eq!(PixelFormat::from_masks(16, 0xff_0000, 0xff00, 0xff), None, "red mask beyond 16 bits");
        assert_eq!(PixelFormat::from_masks(32, 0xf0f, 0xff00, 0xff), None, "gap in mask");
        assert_eq!(PixelFormat::from_masks(8, 0xe0, 0x1c, 3), None);
        for f in [PixelFormat::XRGB8888, PixelFormat::XBGR8888, PixelFormat::RGB888] {
            let c = Rgb::new(0x12, 0x34, 0x56);
            assert_eq!(f.decode(f.encode(c)), c);
        }
    }

    #[test]
    fn rects() {
        let screen = Rect::new(0, 0, 640, 480);
        assert_eq!(Rect::new(600, 470, 100, 100).intersect(&screen), Rect::new(600, 470, 40, 10));
        assert!(Rect::new(640, 0, 10, 10).intersect(&screen).is_empty());
        assert!(Rect::new(u32::MAX, u32::MAX, u32::MAX, 1).intersect(&screen).is_empty());
    }

    #[test]
    fn draw_32bpp() {
        // 4x3 visible, 6 pixels per row.
        let mut mem = vec![0u32; 6 * 3];
        let info = FramebufferInfo { width: 4, height: 3, stride: 24, format: PixelFormat::XRGB8888 };
        let f = fb(&mut mem, info);
        f.clear(Rgb::new(0, 0, 0xff));
        f.fill_rect(Rect::new(2, 1, 10, 10), Rgb::new(0xff, 0, 0));
        f.set_pixel(0, 0, Rgb::WHITE);
        f.set_pixel(4, 0, Rgb::WHITE);
        assert_eq!(f.pixel(2, 2), Some(Rgb::new(0xff, 0, 0)));
        assert_eq!(f.pixel(4, 0), None);
        drop(f);
        assert_eq!(mem[..6], [0xff_ffff, 0xff, 0xff, 0xff, 0, 0], "padding untouched");
        assert_eq!(mem[6..12], [0xff, 0xff, 0xff_0000, 0xff_0000, 0, 0]);
    }

    #[test]
    fn draw_24_and_16bpp() {
        let mut mem = vec![0u32; 3];
        let f = fb(&mut mem, FramebufferInfo::packed(4, 1, PixelFormat::RGB888));
        f.set_pixel(1, 0, Rgb::new(0x11, 0x22, 0x33));
        assert_eq!(f.pixel(1, 0), Some(Rgb::new(0x11, 0x22, 0x33)));
        drop(f);
        assert_eq!(mem[0], 0x3300_0000);
        assert_eq!(mem[1], 0x1122);

        let mut mem = vec![0u32; 2];
        let f = fb(&mut mem, FramebufferInfo::packed(4, 1, PixelFormat::RGB565));
        f.fill_rect(Rect::new(1, 0, 2, 1), Rgb::WHITE);
        drop(f);
        assert_eq!(mem, [0xffff_0000, 0x0000_ffff]);
    }

    #[test]
    fn bitmap_and_scroll() {
        let mut mem = vec![0u32; 8 * 4];
        let f = fb(&mut mem, FramebufferInfo::packed(8, 4, PixelFormat::XRGB8888));
        f.draw_bitmap(0, 1, 8, &[0b1000_0001, 0b0100_0000], Rgb::WHITE, Some(Rgb::new(0, 0, 1)));
        assert_eq!(f.pixel(0, 1), Some(Rgb::WHITE));
        assert_eq!(f.pixel(1, 1), Some(Rgb::new(0, 0, 1)));
        assert_eq!(f.pixel(1, 2), Some(Rgb::WHITE));
        f.draw_bitmap(6, 3, 8, &[0xff], Rgb::new(9, 9, 9), None);
        assert_eq!(f.pixel(7, 3), Some(Rgb::new(9, 9, 9)), "clipped at the right edge");
        f.scroll_up(1, Rgb::new(0, 1, 0));
        assert_eq!(f.pixel(0, 0), Some(Rgb::WHITE));
        assert_eq!(f.pixel(1, 1), Some(Rgb::WHITE));
        assert_eq!(f.pixel(7, 2), Some(Rgb::new(9, 9, 9)));
        assert_eq!(f.pixel(3, 3), Some(Rgb::new(0, 1, 0)));
        drop(f);
        let filled: Vec<_> = mem[24..].to_vec();
        assert_eq!(filled, [0x100; 8]);
    }

    #[test]
    fn rejects_bad_geometry() {
        let mut mem = vec![0u32; 4];
        // SAFETY: the window covers a local buffer.
        let io = unsafe { IoMem::new(mem.as_mut_ptr().cast(), 16) };
        let fmt = PixelFormat::XRGB8888;
        assert!(Framebuffer::new(io.clone(), FramebufferInfo::packed(2, 3, fmt)).is_err(), "too small");
        assert!(Framebuffer::new(io.clone(), FramebufferInfo { width: 2, height: 1, stride: 4, format: fmt }).is_err());
        assert!(Framebuffer::new(io.clone(), FramebufferInfo::packed(2, 2, fmt)).is_ok());
        assert!(Framebuffer::new(io.slice(2, 8).unwrap(), FramebufferInfo::packed(1, 1, fmt)).is_err(), "misaligned");
        let mut bad = fmt;
        bad.red.bits = 0;
        assert!(!bad.is_valid());
        assert!(Framebuffer::new(io.clone(), FramebufferInfo::packed(1, 1, bad)).is_err(), "empty channel");
        bad.red = Channel { shift: 30, bits: 8 };
        assert!(Framebuffer::new(io, FramebufferInfo::packed(1, 1, bad)).is_err(), "channel outside the pixel");
        assert_eq!(FramebufferInfo::packed(u32::MAX, 1, fmt).stride, u32::MAX);
    }
}
