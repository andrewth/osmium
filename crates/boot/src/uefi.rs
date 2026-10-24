//! UEFI: just enough of the system table for a UEFI application or loader
//! to print, find the Graphics Output Protocol (GOP), set a mode and take
//! its linear framebuffer, and shut down.
//!
//! GOP is the UEFI replacement for VESA: the firmware's display driver
//! (QEMU's std VGA, virtio-gpu, a real graphics card's option ROM) sets the
//! mode and reports where the framebuffer is. A framebuffer from
//! [`Gop::framebuffer`] stays valid after `ExitBootServices`, so a kernel
//! keeps drawing on it with no driver of its own, as long as nothing
//! reprograms the device.
//!
//! Only the table layouts are `unsafe` to trust; [`Uefi::new`] takes the
//! system table pointer the firmware passed to `efi_main` and everything
//! after it is safe while boot services last.

use core::ffi::c_void;

use osmium_hal::display::{FramebufferInfo, PixelFormat};
use osmium_mm::PhysAddr;

/// An opaque firmware handle.
pub type Handle = *mut c_void;

/// A UEFI status code: 0 is success, the high bit marks errors.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status(pub usize);

impl Status {
    /// Success.
    pub const SUCCESS: Self = Self(0);
    const ERROR: usize = 1 << (usize::BITS - 1);
    /// The firmware does not support the request.
    pub const UNSUPPORTED: Self = Self(Self::ERROR | 3);
    /// No such item.
    pub const NOT_FOUND: Self = Self(Self::ERROR | 14);

    /// True for an error (a warning is not one).
    pub fn is_error(self) -> bool {
        self.0 & Self::ERROR != 0
    }

    /// `Ok(())` unless this is an error.
    pub fn ok(self) -> Result<(), Status> {
        if self.is_error() { Err(self) } else { Ok(()) }
    }
}

/// A protocol GUID.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);

/// `EFI_TABLE_HEADER`.
#[repr(C)]
#[derive(Debug)]
pub struct TableHeader {
    /// Identifies the table.
    pub signature: u64,
    /// UEFI revision: major in the high half, minor × 10 in the low.
    pub revision: u32,
    /// Bytes of the table, header included.
    pub header_size: u32,
    /// CRC-32 of the table.
    pub crc32: u32,
    reserved: u32,
}

/// `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL`, the parts used here.
#[repr(C)]
pub struct TextOutput {
    reset: unsafe extern "efiapi" fn(*mut TextOutput, bool) -> Status,
    output_string: unsafe extern "efiapi" fn(*mut TextOutput, *const u16) -> Status,
}

/// `EFI_SYSTEM_TABLE`.
#[repr(C)]
pub struct SystemTable {
    /// Table header; signature "IBI SYST".
    pub hdr: TableHeader,
    firmware_vendor: *const u16,
    /// Firmware revision.
    pub firmware_revision: u32,
    console_in_handle: Handle,
    con_in: *mut c_void,
    console_out_handle: Handle,
    con_out: *mut TextOutput,
    standard_error_handle: Handle,
    std_err: *mut TextOutput,
    runtime_services: *const RuntimeServices,
    boot_services: *const BootServices,
    number_of_table_entries: usize,
    configuration_table: *const c_void,
}

/// `EFI_SYSTEM_TABLE` signature.
pub const SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;

/// `EFI_BOOT_SERVICES`, up to `LocateProtocol`. Services this module does
/// not call are left as opaque pointers.
#[repr(C)]
pub struct BootServices {
    hdr: TableHeader,
    _tpl: [usize; 2],
    _pages: [usize; 3],
    allocate_pool: usize,
    free_pool: unsafe extern "efiapi" fn(*mut c_void) -> Status,
    _events: [usize; 6],
    _protocol_interfaces: [usize; 3],
    _handle_protocol: usize,
    _reserved: usize,
    _register_protocol_notify: usize,
    _locate: [usize; 3],
    _images: [usize; 4],
    _exit_boot_services: usize,
    _get_next_monotonic_count: usize,
    stall: unsafe extern "efiapi" fn(usize) -> Status,
    _set_watchdog_timer: usize,
    _controllers: [usize; 2],
    _open_close_protocol: [usize; 3],
    _protocols_per_handle: usize,
    _locate_handle_buffer: usize,
    locate_protocol: unsafe extern "efiapi" fn(*const Guid, *mut c_void, *mut *mut c_void) -> Status,
}

/// `EFI_RUNTIME_SERVICES`, up to `ResetSystem`.
#[repr(C)]
pub struct RuntimeServices {
    hdr: TableHeader,
    _time: [usize; 4],
    _virtual_memory: [usize; 2],
    _variables: [usize; 3],
    _get_next_high_monotonic_count: usize,
    reset_system: unsafe extern "efiapi" fn(u32, Status, usize, *const c_void) -> !,
}

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL` GUID.
pub const GOP_GUID: Guid = Guid(0x9042_a9de, 0x23dc, 0x4a38, [0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a]);

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL`.
#[repr(C)]
pub struct GraphicsOutput {
    query_mode: unsafe extern "efiapi" fn(*mut GraphicsOutput, u32, *mut usize, *mut *const ModeInfo) -> Status,
    set_mode: unsafe extern "efiapi" fn(*mut GraphicsOutput, u32) -> Status,
    blt: unsafe extern "efiapi" fn(
        *mut GraphicsOutput,
        *mut u32,
        u32,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
    ) -> Status,
    mode: *const GopMode,
}

/// `EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE`.
#[repr(C)]
pub struct GopMode {
    /// Number of modes.
    pub max_mode: u32,
    /// The current mode.
    pub mode: u32,
    info: *const ModeInfo,
    size_of_info: usize,
    /// The framebuffer's physical address.
    pub frame_buffer_base: u64,
    /// The framebuffer's size in bytes.
    pub frame_buffer_size: usize,
}

/// `EFI_GRAPHICS_OUTPUT_MODE_INFORMATION`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeInfo {
    /// Structure version (0).
    pub version: u32,
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// `EFI_GRAPHICS_PIXEL_FORMAT`: see [`gop_format`].
    pub pixel_format: u32,
    /// Red, green, blue and reserved masks, for `PixelBitMask`.
    pub masks: [u32; 4],
    /// Pixels from one row to the next.
    pub pixels_per_scan_line: u32,
}

/// `EFI_GRAPHICS_PIXEL_FORMAT` values.
pub mod gop_format {
    /// Bytes R, G, B, X.
    pub const RGB_RESERVED_8BIT: u32 = 0;
    /// Bytes B, G, R, X.
    pub const BGR_RESERVED_8BIT: u32 = 1;
    /// Described by [`super::ModeInfo::masks`].
    pub const BIT_MASK: u32 = 2;
    /// No framebuffer; only the protocol's `Blt` draws.
    pub const BLT_ONLY: u32 = 3;
}

impl ModeInfo {
    /// The pixel format, or `None` for a `Blt`-only mode or masks the
    /// framebuffer cannot draw.
    pub fn format(&self) -> Option<PixelFormat> {
        match self.pixel_format {
            gop_format::RGB_RESERVED_8BIT => Some(PixelFormat::XBGR8888),
            gop_format::BGR_RESERVED_8BIT => Some(PixelFormat::XRGB8888),
            gop_format::BIT_MASK => {
                let [r, g, b, x] = self.masks;
                let bpp = 32 - (r | g | b | x).leading_zeros();
                PixelFormat::from_masks(bpp.next_multiple_of(8) as u8, r, g, b)
            }
            _ => None,
        }
    }

    /// The framebuffer geometry, if the mode has a framebuffer.
    pub fn framebuffer_info(&self) -> Option<FramebufferInfo> {
        let format = self.format()?;
        if self.width > self.pixels_per_scan_line {
            return None;
        }
        let stride = self.pixels_per_scan_line.checked_mul(format.bytes_per_pixel() as u32)?;
        Some(FramebufferInfo { width: self.width, height: self.height, stride, format })
    }
}

/// UEFI reset types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ResetType {
    /// Power cycle.
    Cold = 0,
    /// Reset the CPUs.
    Warm = 1,
    /// Power off.
    Shutdown = 2,
}

/// The firmware's services, while boot services last.
#[derive(Clone, Copy)]
pub struct Uefi {
    st: &'static SystemTable,
}

impl Uefi {
    /// Wraps the system table passed to `efi_main`.
    ///
    /// # Safety
    /// `st` is the firmware's system table, and boot services have not been
    /// exited (the boot services methods may not be called after that).
    pub unsafe fn new(st: *const SystemTable) -> Option<Self> {
        // SAFETY: the caller's contract.
        let st = unsafe { &*st };
        (st.hdr.signature == SYSTEM_TABLE_SIGNATURE).then_some(Self { st })
    }

    /// The system table.
    pub fn system_table(&self) -> &'static SystemTable {
        self.st
    }

    fn bs(&self) -> &'static BootServices {
        // SAFETY: valid while boot services last (`new`).
        unsafe { &*self.st.boot_services }
    }

    /// The UEFI revision as `(major, minor)`.
    pub fn revision(&self) -> (u16, u16) {
        ((self.st.hdr.revision >> 16) as u16, (self.st.hdr.revision & 0xffff) as u16 / 10)
    }

    /// Writes `s` to the console (ConOut), translating `\n` to CRLF.
    /// Characters outside the Basic Multilingual Plane print as `?`.
    pub fn print(&self, s: &str) {
        let out = self.st.con_out;
        if out.is_null() {
            return;
        }
        let mut buf = [0u16; 65];
        let mut n = 0;
        let flush = |buf: &mut [u16; 65], n: &mut usize| {
            if let Some(slot) = buf.get_mut(*n) {
                *slot = 0;
            }
            // SAFETY: ConOut is valid while boot services last; the string
            // is NUL-terminated.
            unsafe { ((*out).output_string)(out, buf.as_ptr()) };
            *n = 0;
        };
        // The flush below keeps two slots free, so the slot always exists.
        let push = |buf: &mut [u16; 65], n: &mut usize, v: u16| {
            if let Some(slot) = buf.get_mut(*n) {
                *slot = v;
                *n += 1;
            }
        };
        for c in s.chars() {
            if n + 2 >= buf.len() - 1 {
                flush(&mut buf, &mut n);
            }
            if c == '\n' {
                push(&mut buf, &mut n, b'\r' as u16);
            }
            push(&mut buf, &mut n, u16::try_from(c as u32).unwrap_or(b'?' as u16));
        }
        flush(&mut buf, &mut n);
    }

    /// Waits `us` microseconds.
    pub fn stall(&self, us: usize) {
        // SAFETY: a boot service with no memory effects.
        unsafe { (self.bs().stall)(us) };
    }

    /// The first instance of the protocol `guid`.
    ///
    /// # Safety
    /// `T` must be the protocol's interface structure.
    pub unsafe fn locate_protocol<T>(&self, guid: &Guid) -> Result<*mut T, Status> {
        let mut out = core::ptr::null_mut();
        // SAFETY: a boot service; `out` is written on success.
        unsafe { (self.bs().locate_protocol)(guid, core::ptr::null_mut(), &mut out) }.ok()?;
        Ok(out.cast())
    }

    /// The Graphics Output Protocol of the console's display.
    pub fn gop(&self) -> Result<Gop, Status> {
        // SAFETY: `GraphicsOutput` is the GOP interface.
        let proto = unsafe { self.locate_protocol::<GraphicsOutput>(&GOP_GUID)? };
        Ok(Gop { proto, uefi: *self })
    }

    /// Resets or powers off the machine.
    pub fn reset(&self, kind: ResetType) -> ! {
        // SAFETY: runtime services stay valid for the life of the system.
        unsafe { ((*self.st.runtime_services).reset_system)(kind as u32, Status::SUCCESS, 0, core::ptr::null()) }
    }
}

/// The Graphics Output Protocol.
pub struct Gop {
    proto: *mut GraphicsOutput,
    uefi: Uefi,
}

impl Gop {
    fn mode(&self) -> &GopMode {
        // SAFETY: the protocol and its mode structure are valid while boot
        // services last.
        unsafe { &*(*self.proto).mode }
    }

    /// Number of modes.
    pub fn num_modes(&self) -> u32 {
        self.mode().max_mode
    }

    /// The current mode number.
    pub fn current_mode(&self) -> u32 {
        self.mode().mode
    }

    /// Information on mode `n`.
    pub fn query_mode(&self, n: u32) -> Result<ModeInfo, Status> {
        let (mut size, mut info) = (0usize, core::ptr::null());
        // SAFETY: a protocol call; on success `info` is pool memory of
        // `size` bytes holding at least a `ModeInfo`.
        unsafe {
            ((*self.proto).query_mode)(self.proto, n, &mut size, &mut info).ok()?;
            if size < size_of::<ModeInfo>() {
                return Err(Status::UNSUPPORTED);
            }
            let copy = info.read_unaligned();
            (self.uefi.bs().free_pool)(info as *mut c_void);
            Ok(copy)
        }
    }

    /// Every mode, as `(number, info)`.
    pub fn modes(&self) -> impl Iterator<Item = (u32, ModeInfo)> + '_ {
        (0..self.num_modes()).filter_map(|n| self.query_mode(n).ok().map(|i| (n, i)))
    }

    /// The mode of exactly `width` by `height` with a framebuffer.
    pub fn find_mode(&self, width: u32, height: u32) -> Option<u32> {
        self.modes().find(|(_, i)| (i.width, i.height) == (width, height) && i.format().is_some()).map(|(n, _)| n)
    }

    /// Switches to mode `n`; the screen is cleared.
    pub fn set_mode(&mut self, n: u32) -> Result<(), Status> {
        // SAFETY: a protocol call.
        unsafe { ((*self.proto).set_mode)(self.proto, n) }.ok()
    }

    /// Fills `rect` of the screen with `c` through the protocol's `Blt`
    /// (`EfiBltVideoFill`), which works in every mode, including `Blt`-only
    /// ones such as virtio-gpu's.
    pub fn fill(&mut self, rect: osmium_hal::display::Rect, c: osmium_hal::display::Rgb) -> Result<(), Status> {
        // EFI_GRAPHICS_OUTPUT_BLT_PIXEL: bytes blue, green, red, reserved.
        let mut pixel = u32::from_le_bytes([c.b, c.g, c.r, 0]);
        let r = rect;
        // SAFETY: a protocol call reading one pixel.
        unsafe {
            ((*self.proto).blt)(
                self.proto,
                &mut pixel,
                0,
                0,
                0,
                r.x as usize,
                r.y as usize,
                r.width as usize,
                r.height as usize,
                0,
            )
        }
        .ok()
    }

    /// The current mode's geometry, from the protocol (whether or not it
    /// has a framebuffer).
    pub fn current_info(&self) -> Option<ModeInfo> {
        // SAFETY: as in `framebuffer`.
        unsafe { self.mode().info.as_ref() }.copied()
    }

    /// The current mode's framebuffer, or `None` for a `Blt`-only mode.
    pub fn framebuffer(&self) -> Option<(PhysAddr, FramebufferInfo)> {
        let m = self.mode();
        // SAFETY: the current mode's info, valid while boot services last.
        let info = unsafe { m.info.as_ref()? }.framebuffer_info()?;
        (info.size() <= m.frame_buffer_size).then_some((PhysAddr::new(m.frame_buffer_base), info))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts() {
        // Offsets from the UEFI 2.10 specification (64-bit).
        assert_eq!(core::mem::offset_of!(SystemTable, con_out), 64);
        assert_eq!(core::mem::offset_of!(SystemTable, boot_services), 96);
        assert_eq!(core::mem::offset_of!(BootServices, free_pool), 72);
        assert_eq!(core::mem::offset_of!(BootServices, stall), 248);
        assert_eq!(core::mem::offset_of!(BootServices, locate_protocol), 320);
        assert_eq!(core::mem::offset_of!(RuntimeServices, reset_system), 104);
        assert_eq!(core::mem::offset_of!(GopMode, frame_buffer_base), 24);
        assert_eq!(size_of::<ModeInfo>(), 36);
    }

    #[test]
    fn formats() {
        let mut m =
            ModeInfo { version: 0, width: 800, height: 600, pixel_format: 1, masks: [0; 4], pixels_per_scan_line: 832 };
        let fb = m.framebuffer_info().unwrap();
        assert_eq!((fb.format, fb.stride), (PixelFormat::XRGB8888, 3328));
        m.pixel_format = gop_format::RGB_RESERVED_8BIT;
        assert_eq!(m.format(), Some(PixelFormat::XBGR8888));
        m.pixel_format = gop_format::BIT_MASK;
        m.masks = [0xf800, 0x07e0, 0x001f, 0];
        assert_eq!(m.format(), Some(PixelFormat::RGB565));
        m.masks = [0xff_0000, 0xff00, 0xff, 0xff00_0000];
        assert_eq!(m.format(), Some(PixelFormat::XRGB8888));
        m.pixel_format = gop_format::BLT_ONLY;
        assert_eq!(m.framebuffer_info(), None);
        assert!(Status::NOT_FOUND.is_error() && Status::SUCCESS.ok().is_ok());
    }
}
