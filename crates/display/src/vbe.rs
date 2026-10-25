//! VESA BIOS Extensions (VBE 2.0/3.0): linear framebuffer modes through the
//! video BIOS's `int 10h` functions 4F00h–4F02h.
//!
//! Calling the BIOS needs real mode, which only the kernel can arrange, so
//! the BIOS is reached through the [`VideoBios`] trait. An x86 kernel
//! implements it with a real-mode thunk (`osmium_arch::x86_64::bios`, via
//! `RealModeBios`); tests implement it with a fake. Everything else here
//! is parsing: the controller information block, the mode list and each
//! mode's information block.

use osmium_hal::display::{FramebufferInfo, PixelFormat};
use osmium_mm::PhysAddr;

/// Bytes of the buffer the BIOS fills (the controller information block;
/// a mode information block uses the first 256).
pub const BUF_LEN: usize = 512;

/// Most modes read from the BIOS's mode list.
pub const MAX_MODES: usize = 128;

/// Registers passed to and returned from `int 10h`. `es:di` is set by the
/// [`VideoBios`] implementation to point at its buffer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BiosRegs {
    /// AX: function in, status out (0x004f is success).
    pub ax: u16,
    /// BX.
    pub bx: u16,
    /// CX.
    pub cx: u16,
    /// DX.
    pub dx: u16,
}

/// A way to call the video BIOS.
pub trait VideoBios {
    /// Calls `int 10h` with `regs` and `es:di` pointing at a copy of `buf`
    /// in low memory, then copies the buffer back into `buf`.
    fn int10(&mut self, regs: &mut BiosRegs, buf: &mut [u8; BUF_LEN]);

    /// Reads `dst.len()` bytes at real-mode address `seg:off` (`far` holds
    /// `seg << 16 | off`), such as the mode list the BIOS points to.
    fn read_far(&self, far: u32, dst: &mut [u8]);
}

/// The [`VideoBios`] of the machine, called through
/// `osmium_arch::x86_64::bios`'s real-mode thunk.
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub struct RealModeBios {
    _private: (),
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl RealModeBios {
    /// The machine's video BIOS.
    ///
    /// # Safety
    /// See `osmium_arch::x86_64::bios::int`: the thunk is installed, the low
    /// megabyte is identity-mapped, and nothing has replaced the BIOS's view
    /// of the machine (interrupt controllers, IVT).
    pub unsafe fn new() -> Self {
        Self { _private: () }
    }

    /// The machine's video BIOS, if there is one: `int 10h` must be set
    /// and a VGA option ROM (the 55aa signature) must sit at C000:0. The
    /// vector need not point into the ROM: SeaBIOS routes `int 10h` through
    /// its own handler in segment F000. A PVH kernel started by a
    /// hypervisor rather than a BIOS finds neither.
    ///
    /// # Safety
    /// As [`RealModeBios::new`], except that the BIOS may be absent; the
    /// low megabyte must be readable.
    pub unsafe fn probe() -> Option<Self> {
        // SAFETY: the IVT and option ROM area are in the identity-mapped,
        // readable low megabyte (the caller's contract).
        let (vector, rom) = unsafe { ((0x40 as *const u32).read_volatile(), (0xc0000 as *const u16).read_volatile()) };
        // SAFETY: a video BIOS is present; the rest is the caller's contract.
        (vector != 0 && rom == 0xaa55).then(|| unsafe { Self::new() })
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "none"))]
impl VideoBios for RealModeBios {
    fn int10(&mut self, regs: &mut BiosRegs, buf: &mut [u8; BUF_LEN]) {
        use osmium_arch::x86_64::bios;
        let mut r = bios::Regs {
            eax: regs.ax as u32,
            ebx: regs.bx as u32,
            ecx: regs.cx as u32,
            edx: regs.dx as u32,
            ..Default::default()
        };
        // SAFETY: `new`'s contract.
        unsafe { bios::int_with_buffer(0x10, &mut r, buf) };
        (regs.ax, regs.bx, regs.cx, regs.dx) = (r.eax as u16, r.ebx as u16, r.ecx as u16, r.edx as u16);
    }

    fn read_far(&self, far: u32, dst: &mut [u8]) {
        let linear = (far >> 16) as usize * 16 + (far & 0xffff) as usize;
        // SAFETY: real-mode addresses are in the identity-mapped low
        // megabyte (`new`'s contract); a byte copy has no alignment needs.
        unsafe {
            core::ptr::copy_nonoverlapping(
                linear as *const u8,
                dst.as_mut_ptr(),
                dst.len().min(0x10_0000 - linear.min(0x10_0000)),
            )
        }
    }
}

/// Why a VBE call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VbeError {
    /// No VBE: AX did not come back 0x004f, or no "VESA" signature.
    NotSupported,
    /// The call failed; holds the AX the BIOS returned.
    Failed(u16),
    /// The mode is not a linear-framebuffer direct-colour mode.
    UnusableMode,
}

/// Function numbers.
mod func {
    pub const CONTROLLER_INFO: u16 = 0x4f00;
    pub const MODE_INFO: u16 = 0x4f01;
    pub const SET_MODE: u16 = 0x4f02;
    pub const SUCCESS: u16 = 0x004f;
}

/// Mode number flag: use the linear framebuffer.
pub const MODE_LFB: u16 = 1 << 14;
/// Mode number flag: do not clear the screen.
pub const MODE_NO_CLEAR: u16 = 1 << 15;

/// Mode attribute bits.
pub mod attr {
    #![allow(missing_docs)]
    pub const SUPPORTED: u16 = 1 << 0;
    pub const COLOR: u16 = 1 << 3;
    pub const GRAPHICS: u16 = 1 << 4;
    pub const LINEAR: u16 = 1 << 7;
}

/// Memory model: direct colour.
const DIRECT_COLOR: u8 = 6;

/// One mode, from function 4F01h.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeInfo {
    /// The mode number.
    pub mode: u16,
    /// Mode attributes ([`attr`]).
    pub attributes: u16,
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
    /// Bits per pixel.
    pub bpp: u8,
    /// Bytes per row of the linear framebuffer.
    pub pitch: u16,
    /// Physical address of the linear framebuffer.
    pub framebuffer: PhysAddr,
    /// The pixel format, for direct-colour 16/24/32-bit modes.
    pub format: Option<PixelFormat>,
}

impl ModeInfo {
    /// Parses a 256-byte mode information block.
    pub fn parse(mode: u16, b: &[u8]) -> Self {
        // A short block reads as zero padded.
        let mut block = [0u8; 256];
        for (dst, src) in block.iter_mut().zip(b) {
            *dst = *src;
        }
        let b = &block;
        let w = |at: usize| block.get(at..).and_then(|s| s.first_chunk::<2>()).map_or(0, |&c| u16::from_le_bytes(c));
        let mask = |size: u8, pos: u8| {
            // An empty, wide or out-of-range field makes the format unusable.
            if !(1..=8).contains(&size) || pos as u32 + size as u32 > 32 { 0 } else { ((1u32 << size) - 1) << pos }
        };
        let (bpp, model) = (b[25], b[27]);
        // VBE 3.0 has a separate linear pitch; 2.0 uses the banked one.
        let pitch = match w(50) {
            0 => w(16),
            p => p,
        };
        let format = (model == DIRECT_COLOR)
            .then(|| PixelFormat::from_masks(bpp, mask(b[31], b[32]), mask(b[33], b[34]), mask(b[35], b[36])))
            .flatten();
        Self {
            mode,
            attributes: w(0),
            width: w(18),
            height: w(20),
            bpp,
            pitch,
            framebuffer: PhysAddr::new(u32::from_le_bytes([b[40], b[41], b[42], b[43]]) as u64),
            format,
        }
    }

    /// True for a supported graphics mode with a linear framebuffer in a
    /// format [`osmium_hal::display::Framebuffer`] can draw in.
    pub fn is_usable(&self) -> bool {
        let need = attr::SUPPORTED | attr::GRAPHICS | attr::LINEAR;
        self.attributes & need == need && self.format.is_some() && self.framebuffer.as_u64() != 0
    }

    /// The framebuffer geometry, for a usable mode.
    pub fn framebuffer_info(&self) -> Option<FramebufferInfo> {
        let format = self.format.filter(|_| self.is_usable())?;
        Some(FramebufferInfo {
            width: self.width as u32,
            height: self.height as u32,
            stride: self.pitch as u32,
            format,
        })
    }
}

/// The video BIOS's VBE interface.
pub struct Vbe<B: VideoBios> {
    bios: B,
    version: u16,
    memory: usize,
    modes: [u16; MAX_MODES],
    num_modes: usize,
}

impl<B: VideoBios> Vbe<B> {
    /// Asks the BIOS for its controller information (4F00h) and copies its
    /// mode list.
    pub fn new(mut bios: B) -> Result<Self, VbeError> {
        let mut buf = [0u8; BUF_LEN];
        buf[..4].copy_from_slice(b"VBE2");
        let mut regs = BiosRegs { ax: func::CONTROLLER_INFO, ..Default::default() };
        bios.int10(&mut regs, &mut buf);
        if regs.ax != func::SUCCESS || &buf[..4] != b"VESA" {
            return Err(VbeError::NotSupported);
        }
        let version = u16::from_le_bytes([buf[4], buf[5]]);
        let memory = u16::from_le_bytes([buf[18], buf[19]]) as usize * 0x10000;
        // The list may live in `buf`'s low-memory copy, which the next call
        // overwrites: read it all now.
        let list = u32::from_le_bytes([buf[14], buf[15], buf[16], buf[17]]);
        let mut raw = [0u8; 2 * MAX_MODES];
        bios.read_far(list, &mut raw);
        let mut modes = [0u16; MAX_MODES];
        let mut num_modes = 0;
        for m in raw.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).take_while(|&m| m != 0xffff) {
            let Some(slot) = modes.get_mut(num_modes) else { break };
            *slot = m;
            num_modes += 1;
        }
        Ok(Self { bios, version, memory, modes, num_modes })
    }

    /// The VBE version, BCD (0x0300 is 3.0).
    pub fn version(&self) -> u16 {
        self.version
    }

    /// Bytes of video memory.
    pub fn memory(&self) -> usize {
        self.memory
    }

    /// The mode numbers the BIOS lists.
    pub fn modes(&self) -> &[u16] {
        self.modes.get(..self.num_modes).unwrap_or(&[])
    }

    /// Information on `mode` (4F01h).
    pub fn mode_info(&mut self, mode: u16) -> Result<ModeInfo, VbeError> {
        let mut buf = [0u8; BUF_LEN];
        let mut regs = BiosRegs { ax: func::MODE_INFO, cx: mode, ..Default::default() };
        self.bios.int10(&mut regs, &mut buf);
        match regs.ax {
            func::SUCCESS => Ok(ModeInfo::parse(mode, &buf)),
            ax => Err(VbeError::Failed(ax)),
        }
    }

    /// The listed mode of exactly `width` by `height` with the most bits
    /// per pixel up to `max_bpp`, among the usable ones.
    pub fn find_mode(&mut self, width: u16, height: u16, max_bpp: u8) -> Option<ModeInfo> {
        let mut best: Option<ModeInfo> = None;
        let modes = self.modes;
        for &listed in modes.iter().take(self.num_modes) {
            let Ok(m) = self.mode_info(listed) else { continue };
            if m.is_usable()
                && (m.width, m.height) == (width, height)
                && m.bpp <= max_bpp
                && best.is_none_or(|b| m.bpp > b.bpp)
            {
                best = Some(m);
            }
        }
        best
    }

    /// Switches to `mode` with its linear framebuffer (4F02h), and returns
    /// where that is.
    pub fn set_mode(&mut self, mode: &ModeInfo) -> Result<(PhysAddr, FramebufferInfo), VbeError> {
        let info = mode.framebuffer_info().ok_or(VbeError::UnusableMode)?;
        let mut regs = BiosRegs { ax: func::SET_MODE, bx: mode.mode | MODE_LFB, ..Default::default() };
        self.bios.int10(&mut regs, &mut [0; BUF_LEN]);
        match regs.ax {
            func::SUCCESS => Ok((mode.framebuffer, info)),
            ax => Err(VbeError::Failed(ax)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// A BIOS with three modes: 0x112 (640x480x32), 0x111 (640x480x16) and
    /// 0x101 (640x480x8, palette), its mode list inside the info block.
    #[derive(Default)]
    struct FakeBios {
        low: Vec<u8>,
        set: Vec<u16>,
    }

    const BUF_AT: usize = 0x7000;

    fn mode_block(bpp: u8, attributes: u16, model: u8, masks: [(u8, u8); 3]) -> [u8; 256] {
        let mut b = [0u8; 256];
        b[..2].copy_from_slice(&attributes.to_le_bytes());
        b[16..18].copy_from_slice(&(640u16 * bpp as u16 / 8).to_le_bytes());
        b[18..20].copy_from_slice(&640u16.to_le_bytes());
        b[20..22].copy_from_slice(&480u16.to_le_bytes());
        b[25] = bpp;
        b[27] = model;
        for (i, (size, pos)) in masks.into_iter().enumerate() {
            b[31 + 2 * i] = size;
            b[32 + 2 * i] = pos;
        }
        b[40..44].copy_from_slice(&0xfd00_0000u32.to_le_bytes());
        b
    }

    impl VideoBios for FakeBios {
        fn int10(&mut self, regs: &mut BiosRegs, buf: &mut [u8; BUF_LEN]) {
            if self.low.is_empty() {
                self.low = std::vec![0; 0x10000];
            }
            let all = attr::SUPPORTED | attr::COLOR | attr::GRAPHICS | attr::LINEAR;
            self.low[BUF_AT..BUF_AT + BUF_LEN].copy_from_slice(buf);
            let out = &mut self.low[BUF_AT..BUF_AT + BUF_LEN];
            regs.ax = match (regs.ax, regs.cx) {
                (func::CONTROLLER_INFO, _) => {
                    assert_eq!(&out[..4], b"VBE2");
                    out[..4].copy_from_slice(b"VESA");
                    out[4..6].copy_from_slice(&0x0300u16.to_le_bytes());
                    // Mode list at 0700:0022, inside this block.
                    out[14..18].copy_from_slice(&(0x0700u32 << 16 | 0x22).to_le_bytes());
                    out[18..20].copy_from_slice(&256u16.to_le_bytes());
                    for (i, m) in [0x112u16, 0x111, 0x101, 0xffff].into_iter().enumerate() {
                        out[0x22 + 2 * i..0x24 + 2 * i].copy_from_slice(&m.to_le_bytes());
                    }
                    func::SUCCESS
                }
                (func::MODE_INFO, mode) => {
                    out.fill(0);
                    let b = match mode {
                        0x112 => mode_block(32, all, DIRECT_COLOR, [(8, 16), (8, 8), (8, 0)]),
                        0x111 => mode_block(16, all, DIRECT_COLOR, [(5, 11), (6, 5), (5, 0)]),
                        0x101 => mode_block(8, all, 4, [(0, 0); 3]),
                        _ => return regs.ax = 0x014f,
                    };
                    out[..256].copy_from_slice(&b);
                    func::SUCCESS
                }
                (func::SET_MODE, _) => {
                    self.set.push(regs.bx);
                    func::SUCCESS
                }
                _ => 0x0100,
            };
            buf.copy_from_slice(&self.low[BUF_AT..BUF_AT + BUF_LEN]);
        }

        fn read_far(&self, far: u32, dst: &mut [u8]) {
            let at = (far >> 16) as usize * 16 + (far & 0xffff) as usize;
            let n = dst.len().min(self.low.len() - at);
            dst[..n].copy_from_slice(&self.low[at..at + n]);
        }
    }

    #[test]
    fn modes() {
        let mut vbe = Vbe::new(FakeBios::default()).unwrap();
        assert_eq!(vbe.version(), 0x0300);
        assert_eq!(vbe.memory(), 16 << 20);
        assert_eq!(vbe.modes(), [0x112, 0x111, 0x101]);

        let m = vbe.mode_info(0x111).unwrap();
        assert_eq!(m.format, Some(PixelFormat::RGB565));
        assert_eq!(m.pitch, 1280);
        assert!(!vbe.mode_info(0x101).unwrap().is_usable(), "palette mode");
        assert_eq!(vbe.mode_info(0x200), Err(VbeError::Failed(0x014f)));

        let best = vbe.find_mode(640, 480, 32).unwrap();
        assert_eq!((best.mode, best.format), (0x112, Some(PixelFormat::XRGB8888)));
        assert_eq!(vbe.find_mode(640, 480, 24).map(|m| m.mode), Some(0x111));
        assert!(vbe.find_mode(800, 600, 32).is_none());

        let (addr, info) = vbe.set_mode(&best).unwrap();
        assert_eq!(addr, PhysAddr::new(0xfd00_0000));
        assert_eq!((info.width, info.height, info.stride), (640, 480, 2560));
        let palette = vbe.mode_info(0x101).unwrap();
        assert_eq!(vbe.set_mode(&palette), Err(VbeError::UnusableMode));
        assert_eq!(vbe.bios.set, [0x112 | MODE_LFB]);
    }

    #[test]
    fn no_vbe() {
        struct Dead;
        impl VideoBios for Dead {
            fn int10(&mut self, regs: &mut BiosRegs, _: &mut [u8; BUF_LEN]) {
                regs.ax = 0x0100;
            }
            fn read_far(&self, _: u32, _: &mut [u8]) {}
        }
        assert!(matches!(Vbe::new(Dead), Err(VbeError::NotSupported)));
    }

    #[test]
    fn short_mode_block_parses_without_panicking() {
        let m = ModeInfo::parse(0x112, &[0xff; 10]);
        assert!(!m.is_usable());
        let m = ModeInfo::parse(0x112, &[]);
        assert_eq!((m.width, m.height, m.bpp), (0, 0, 0));
    }
}
