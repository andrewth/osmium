// SPDX-License-Identifier: GPL-2.0-only
//! UEFI: enough of the system table for a UEFI application or loader to
//! print, find the Graphics Output Protocol (GOP), set a mode and take its
//! linear framebuffer, read files from the volume it was loaded from,
//! allocate pages, take the memory map, exit boot services and shut down.
//!
//! GOP is the UEFI replacement for VESA: the firmware's display driver
//! (QEMU's std VGA, virtio-gpu, a real graphics card's option ROM) sets the
//! mode and reports where the framebuffer is. A framebuffer from
//! [`Gop::framebuffer`] stays valid after `ExitBootServices`, so a kernel
//! keeps drawing on it with no driver of its own, as long as nothing
//! reprograms the device.
//!
//! A loader's path through the boot services:
//!
//! 1. [`Uefi::set_watchdog_timer`]`(0)`, or the firmware resets the machine
//!    five minutes after it started the application.
//! 2. [`Uefi::boot_volume`] opens the root directory of the file system the
//!    application was loaded from; [`File::open`], [`File::size`] and
//!    [`File::read`] read files from it into pages from
//!    [`Uefi::allocate_pages`] or, at a fixed address,
//!    [`Uefi::allocate_pages_at`].
//! 3. [`Uefi::configuration_table`] finds the ACPI RSDP, the devicetree and
//!    the SMBIOS entry point.
//! 4. [`Uefi::memory_map_size`] says how big a buffer the memory map needs;
//!    allocate it (with some slack, since allocating changes the map) and
//!    everything else the kernel needs, then
//!    [`Uefi::exit_boot_services_with_map`] reads the final map and exits,
//!    rereading the map while its key goes stale.
//!
//! Only the table layouts are `unsafe` to trust; [`Uefi::new`] takes the
//! system table pointer the firmware passed to `efi_main` and everything
//! after it is safe while boot services last, apart from the calls that
//! give memory back to the firmware or end boot services.

use core::ffi::c_void;

use osmium_hal::display::{FramebufferInfo, PixelFormat};
use osmium_mm::PhysAddr;

use crate::{le32, le64};

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
    /// The image could not be loaded, or the firmware returned something
    /// unusable.
    pub const LOAD_ERROR: Self = Self(Self::ERROR | 1);
    /// A parameter was wrong; from `ExitBootServices`, the memory map key is
    /// stale.
    pub const INVALID_PARAMETER: Self = Self(Self::ERROR | 2);
    /// The firmware does not support the request.
    pub const UNSUPPORTED: Self = Self(Self::ERROR | 3);
    /// The buffer is too small; the size needed was returned.
    pub const BUFFER_TOO_SMALL: Self = Self(Self::ERROR | 5);
    /// The device reported an error.
    pub const DEVICE_ERROR: Self = Self(Self::ERROR | 7);
    /// Out of memory, or the requested pages are not free.
    pub const OUT_OF_RESOURCES: Self = Self(Self::ERROR | 9);
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
    configuration_table: *const ConfigurationTable,
}

/// `EFI_SYSTEM_TABLE` signature.
pub const SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;

/// `EFI_CONFIGURATION_TABLE`: a table the firmware publishes, such as the
/// ACPI RSDP or the devicetree, named by a GUID.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ConfigurationTable {
    /// What the table is: [`ACPI_20_TABLE_GUID`], [`DEVICE_TREE_GUID`] and so on.
    pub guid: Guid,
    table: *const c_void,
}

impl ConfigurationTable {
    /// The table's physical address (UEFI identity-maps memory).
    pub fn address(&self) -> PhysAddr {
        PhysAddr::new(self.table as u64)
    }
}

/// `EFI_ALLOCATE_TYPE`.
#[repr(u32)]
#[derive(Clone, Copy)]
enum AllocateType {
    AnyPages = 0,
    MaxAddress = 1,
    Address = 2,
}

/// `EFI_BOOT_SERVICES`, up to `LocateProtocol`. Services this module does
/// not call are left as opaque pointers.
#[repr(C)]
pub struct BootServices {
    hdr: TableHeader,
    _tpl: [usize; 2],
    allocate_pages: unsafe extern "efiapi" fn(AllocateType, MemoryType, usize, *mut u64) -> Status,
    free_pages: unsafe extern "efiapi" fn(u64, usize) -> Status,
    get_memory_map: unsafe extern "efiapi" fn(*mut usize, *mut c_void, *mut usize, *mut usize, *mut u32) -> Status,
    allocate_pool: usize,
    free_pool: unsafe extern "efiapi" fn(*mut c_void) -> Status,
    _events: [usize; 6],
    _protocol_interfaces: [usize; 3],
    handle_protocol: unsafe extern "efiapi" fn(Handle, *const Guid, *mut *mut c_void) -> Status,
    _reserved: usize,
    _register_protocol_notify: usize,
    _locate: [usize; 3],
    _images: [usize; 4],
    exit_boot_services: unsafe extern "efiapi" fn(Handle, usize) -> Status,
    _get_next_monotonic_count: usize,
    stall: unsafe extern "efiapi" fn(usize) -> Status,
    set_watchdog_timer: unsafe extern "efiapi" fn(usize, u64, usize, *const u16) -> Status,
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

/// `EFI_LOADED_IMAGE_PROTOCOL` GUID.
pub const LOADED_IMAGE_GUID: Guid = Guid(0x5b1b_31a1, 0x9562, 0x11d2, [0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);
/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` GUID.
pub const SIMPLE_FILE_SYSTEM_GUID: Guid =
    Guid(0x964e_5b22, 0x6459, 0x11d2, [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);
/// `EFI_FILE_INFO` GUID.
pub const FILE_INFO_GUID: Guid = Guid(0x0957_6e92, 0x6d3f, 0x11d2, [0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b]);

/// Configuration table: the ACPI 2.0+ RSDP.
pub const ACPI_20_TABLE_GUID: Guid =
    Guid(0x8868_e871, 0xe4f1, 0x11d3, [0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81]);
/// Configuration table: the ACPI 1.0 RSDP.
pub const ACPI_TABLE_GUID: Guid = Guid(0xeb9d_2d30, 0x2d88, 0x11d3, [0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d]);
/// Configuration table: a flattened devicetree.
pub const DEVICE_TREE_GUID: Guid = Guid(0xb1b6_21d5, 0xf19c, 0x41a5, [0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0]);
/// Configuration table: the SMBIOS 3.0 (64-bit) entry point.
pub const SMBIOS3_TABLE_GUID: Guid =
    Guid(0xf2fd_1544, 0x9794, 0x4a2c, [0x99, 0x2e, 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94]);
/// Configuration table: the SMBIOS 2.x (32-bit) entry point.
pub const SMBIOS_TABLE_GUID: Guid = Guid(0xeb9d_2d31, 0x2d88, 0x11d3, [0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d]);

/// The size of a UEFI page, whatever the CPU's page size.
pub const PAGE_SIZE: u64 = 4096;

/// The number of UEFI pages `bytes` bytes need.
pub fn pages_for(bytes: u64) -> u64 {
    bytes.div_ceil(PAGE_SIZE)
}

/// `EFI_MEMORY_TYPE`: what a range of the memory map holds, and the type
/// given to an allocation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryType(pub u32);

impl MemoryType {
    /// Not usable.
    pub const RESERVED: Self = Self(0);
    /// A UEFI application's or loader's code.
    pub const LOADER_CODE: Self = Self(1);
    /// A UEFI application's or loader's data, and what it allocates.
    pub const LOADER_DATA: Self = Self(2);
    /// Boot services drivers' code; free once boot services are exited.
    pub const BOOT_SERVICES_CODE: Self = Self(3);
    /// Boot services drivers' data; free once boot services are exited.
    pub const BOOT_SERVICES_DATA: Self = Self(4);
    /// Runtime services code, kept for the life of the system.
    pub const RUNTIME_SERVICES_CODE: Self = Self(5);
    /// Runtime services data, kept for the life of the system.
    pub const RUNTIME_SERVICES_DATA: Self = Self(6);
    /// Free memory.
    pub const CONVENTIONAL: Self = Self(7);
    /// Memory with errors.
    pub const UNUSABLE: Self = Self(8);
    /// ACPI tables; free once they have been read.
    pub const ACPI_RECLAIM: Self = Self(9);
    /// ACPI firmware storage, kept for the life of the system.
    pub const ACPI_NVS: Self = Self(10);
    /// Device registers that runtime services use.
    pub const MMIO: Self = Self(11);
    /// I/O port space that runtime services use (Itanium).
    pub const MMIO_PORT_SPACE: Self = Self(12);
    /// Processor firmware code (Itanium).
    pub const PAL_CODE: Self = Self(13);
    /// Persistent (non-volatile) memory.
    pub const PERSISTENT: Self = Self(14);
    /// Memory that must be accepted before use (confidential VMs).
    pub const UNACCEPTED: Self = Self(15);
}

/// One `EFI_MEMORY_DESCRIPTOR` of a [`MemoryMap`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryDescriptor {
    /// What the range holds.
    pub memory_type: MemoryType,
    /// Its first byte, page-aligned.
    pub physical_start: PhysAddr,
    /// Where runtime services expect it after `SetVirtualAddressMap`.
    pub virtual_start: u64,
    /// Its length in UEFI pages.
    pub number_of_pages: u64,
    /// Capabilities (`EFI_MEMORY_WB`, `EFI_MEMORY_RUNTIME` and so on).
    pub attribute: u64,
}

impl MemoryDescriptor {
    /// `EFI_MEMORY_RUNTIME`: runtime services use the range.
    pub const RUNTIME: u64 = 1 << 63;

    /// The length in bytes (saturating, since the count is untrusted).
    pub fn size(&self) -> u64 {
        self.number_of_pages.saturating_mul(PAGE_SIZE)
    }
}

/// The opaque key of a memory map, which `ExitBootServices` checks to make
/// sure the caller saw the latest one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryMapKey(usize);

/// How much room the memory map takes, from [`Uefi::memory_map_size`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryMapSize {
    /// Bytes of the map as it is now.
    pub bytes: usize,
    /// Bytes of one descriptor (often more than the 40 the structure takes).
    pub descriptor_size: usize,
}

impl MemoryMapSize {
    /// A buffer size with room for `extra` more descriptors (and the 8 bytes
    /// [`Uefi::memory_map`] may skip to align the buffer), since allocating
    /// the buffer, or anything else, can split a range of the map.
    pub fn with_slack(&self, extra: usize) -> usize {
        self.bytes.saturating_add(extra.saturating_mul(self.descriptor_size)).saturating_add(8)
    }
}

/// The memory map, as `GetMemoryMap` wrote it into the caller's buffer.
#[derive(Clone, Copy, Debug)]
pub struct MemoryMap<'buf> {
    bytes: &'buf [u8],
    key: MemoryMapKey,
    descriptor_size: usize,
    version: u32,
}

/// The fixed part of `EFI_MEMORY_DESCRIPTOR` this module reads.
const MEMORY_DESCRIPTOR_SIZE: usize = 40;

impl<'buf> MemoryMap<'buf> {
    /// The descriptors as raw bytes, `descriptor_size` apart.
    pub fn bytes(&self) -> &'buf [u8] {
        self.bytes
    }

    /// The key to pass to [`Uefi::exit_boot_services`].
    pub fn key(&self) -> MemoryMapKey {
        self.key
    }

    /// Bytes from one descriptor to the next.
    pub fn descriptor_size(&self) -> usize {
        self.descriptor_size
    }

    /// The descriptor version (1).
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The number of descriptors.
    pub fn len(&self) -> usize {
        if self.descriptor_size < MEMORY_DESCRIPTOR_SIZE { 0 } else { self.bytes.len() / self.descriptor_size }
    }

    /// True if the map has no descriptors.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The descriptors, in the firmware's order. A descriptor size smaller
    /// than the structure yields none.
    pub fn iter(&self) -> impl Iterator<Item = MemoryDescriptor> + 'buf {
        let step = self.descriptor_size.max(MEMORY_DESCRIPTOR_SIZE);
        let bytes = if self.descriptor_size < MEMORY_DESCRIPTOR_SIZE { &[][..] } else { self.bytes };
        bytes.chunks_exact(step).filter_map(|d| {
            Some(MemoryDescriptor {
                memory_type: MemoryType(le32(d, 0)?),
                physical_start: PhysAddr::new(le64(d, 8)?),
                virtual_start: le64(d, 16)?,
                number_of_pages: le64(d, 24)?,
                attribute: le64(d, 32)?,
            })
        })
    }
}

/// What a `GetMemoryMap` call reported, before it is tied to the buffer.
#[derive(Clone, Copy)]
struct RawMap {
    /// Where the map starts in the caller's buffer (aligned to 8).
    offset: usize,
    used: usize,
    key: usize,
    descriptor_size: usize,
    version: u32,
}

impl RawMap {
    fn into_map(self, buf: &[u8]) -> MemoryMap<'_> {
        let end = self.offset.saturating_add(self.used);
        MemoryMap {
            bytes: buf.get(self.offset..end).unwrap_or(&[]),
            key: MemoryMapKey(self.key),
            descriptor_size: self.descriptor_size,
            version: self.version,
        }
    }
}

/// How often [`Uefi::exit_boot_services_with_map`] rereads the map when
/// `ExitBootServices` says its key went stale.
const EXIT_ATTEMPTS: usize = 8;

/// `EFI_LOADED_IMAGE_PROTOCOL`: where an image came from and where it was
/// loaded.
#[repr(C)]
pub struct LoadedImage {
    revision: u32,
    parent_handle: Handle,
    system_table: *const SystemTable,
    device_handle: Handle,
    file_path: *const c_void,
    reserved: *const c_void,
    load_options_size: u32,
    load_options: *const c_void,
    image_base: *const c_void,
    image_size: u64,
    image_code_type: MemoryType,
    image_data_type: MemoryType,
    unload: usize,
}

impl LoadedImage {
    /// The device the image was loaded from, for [`Uefi::open_volume`].
    pub fn device(&self) -> Handle {
        self.device_handle
    }

    /// Where the image was loaded.
    pub fn image_base(&self) -> PhysAddr {
        PhysAddr::new(self.image_base as u64)
    }

    /// The image's size in memory, in bytes.
    pub fn image_size(&self) -> u64 {
        self.image_size
    }

    /// The load options (for a boot option, its optional data; for the
    /// UEFI shell, the command line in UCS-2).
    pub fn load_options(&self) -> &'static [u8] {
        if self.load_options.is_null() {
            return &[];
        }
        // SAFETY: the firmware's buffer of `load_options_size` bytes, which
        // lives as long as the image.
        unsafe { core::slice::from_raw_parts(self.load_options.cast(), self.load_options_size as usize) }
    }
}

/// `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`.
#[repr(C)]
struct SimpleFileSystem {
    revision: u64,
    open_volume: unsafe extern "efiapi" fn(*mut SimpleFileSystem, *mut *mut FileProtocol) -> Status,
}

/// `EFI_FILE_PROTOCOL`, up to `GetInfo`.
#[repr(C)]
struct FileProtocol {
    revision: u64,
    open: unsafe extern "efiapi" fn(*mut FileProtocol, *mut *mut FileProtocol, *const u16, u64, u64) -> Status,
    close: unsafe extern "efiapi" fn(*mut FileProtocol) -> Status,
    _delete: usize,
    read: unsafe extern "efiapi" fn(*mut FileProtocol, *mut usize, *mut c_void) -> Status,
    _write: usize,
    _get_position: usize,
    _set_position: usize,
    get_info: unsafe extern "efiapi" fn(*mut FileProtocol, *const Guid, *mut usize, *mut c_void) -> Status,
}

/// `EFI_FILE_MODE_READ`.
const FILE_MODE_READ: u64 = 1;

/// What `EFI_FILE_INFO` says about a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileInfo {
    /// The file's size in bytes.
    pub size: u64,
    /// The bytes it takes on the volume.
    pub physical_size: u64,
    /// `EFI_FILE_READ_ONLY`, `EFI_FILE_DIRECTORY` and so on.
    pub attribute: u64,
}

impl FileInfo {
    /// `EFI_FILE_DIRECTORY`.
    pub const DIRECTORY: u64 = 0x10;

    /// True for a directory.
    pub fn is_directory(&self) -> bool {
        self.attribute & Self::DIRECTORY != 0
    }
}

/// An open file or directory on a UEFI volume, closed on drop. Like the
/// rest of this module, it may only be used while boot services last, so
/// drop every `File` before exiting them.
pub struct File {
    proto: *mut FileProtocol,
}

impl File {
    /// The longest path [`File::open`] takes, in UTF-16 code units.
    pub const MAX_PATH: usize = 255;

    fn from_raw(proto: *mut FileProtocol) -> Result<Self, Status> {
        if proto.is_null() { Err(Status::LOAD_ERROR) } else { Ok(Self { proto }) }
    }

    /// Opens `path` for reading. It is relative to this directory unless it
    /// starts with a separator; `\` and `/` both separate components.
    /// A missing file is [`Status::NOT_FOUND`].
    pub fn open(&self, path: &str) -> Result<File, Status> {
        let mut name = [0u16; Self::MAX_PATH + 1];
        // Leave room for the terminating NUL.
        if path.encode_utf16().count() > Self::MAX_PATH {
            return Err(Status::INVALID_PARAMETER);
        }
        for (slot, c) in name.iter_mut().zip(path.encode_utf16()) {
            *slot = if c == u16::from(b'/') { u16::from(b'\\') } else { c };
        }
        let mut out = core::ptr::null_mut();
        // SAFETY: a protocol call on an open file; `name` is NUL-terminated.
        unsafe { ((*self.proto).open)(self.proto, &mut out, name.as_ptr(), FILE_MODE_READ, 0) }.ok()?;
        Self::from_raw(out)
    }

    /// The file's size and attributes, from `EFI_FILE_INFO`.
    pub fn info(&self) -> Result<FileInfo, Status> {
        // EFI_FILE_INFO: Size, FileSize, PhysicalSize, three EFI_TIMEs,
        // Attribute, then the name, which is at most MAX_PATH units long.
        let mut info = [0u64; 10 + (Self::MAX_PATH + 1) / 4 + 1];
        let mut len = size_of_val(&info);
        // SAFETY: a protocol call writing at most `len` bytes to `info`.
        unsafe { ((*self.proto).get_info)(self.proto, &FILE_INFO_GUID, &mut len, info.as_mut_ptr().cast()) }.ok()?;
        let [_, size, physical_size, _, _, _, _, _, _, attribute, ..] = info;
        Ok(FileInfo { size, physical_size, attribute })
    }

    /// The file's size in bytes.
    pub fn size(&self) -> Result<u64, Status> {
        self.info().map(|i| i.size)
    }

    /// Reads from the current position into `buf` until it is full or the
    /// file ends, and returns the bytes read.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Status> {
        let mut done = 0;
        while let Some(rest) = buf.get_mut(done..).filter(|r| !r.is_empty()) {
            let mut n = rest.len();
            // SAFETY: a protocol call writing at most `n` bytes to `rest`.
            unsafe { ((*self.proto).read)(self.proto, &mut n, rest.as_mut_ptr().cast()) }.ok()?;
            if n == 0 {
                break;
            }
            done += n.min(rest.len());
        }
        Ok(done)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        // SAFETY: the file is open and not used again.
        unsafe { ((*self.proto).close)(self.proto) };
    }
}

/// Boot services for loaders: pages, the memory map, `ExitBootServices`,
/// files and the configuration tables.
impl Uefi {
    /// The configuration tables the firmware publishes. The system table and
    /// these stay valid after `ExitBootServices`.
    pub fn configuration_tables(&self) -> &'static [ConfigurationTable] {
        let st = self.st;
        if st.configuration_table.is_null() {
            return &[];
        }
        // SAFETY: the firmware's array of `number_of_table_entries`
        // entries, which lives as long as the system table.
        unsafe { core::slice::from_raw_parts(st.configuration_table, st.number_of_table_entries) }
    }

    /// The address of the configuration table `guid`, if the firmware
    /// published one.
    pub fn configuration_table(&self, guid: &Guid) -> Option<PhysAddr> {
        self.configuration_tables().iter().find(|t| t.guid == *guid).map(ConfigurationTable::address)
    }

    /// Sets the watchdog to reset the machine in `seconds`, or with 0 turns
    /// it off. The boot manager arms it for five minutes before it starts an
    /// application, which a loader that takes its time must turn off.
    pub fn set_watchdog_timer(&self, seconds: usize) -> Result<(), Status> {
        // Watchdog codes up to 0xffff are the firmware's.
        // SAFETY: a boot service with no memory effects.
        unsafe { (self.bs().set_watchdog_timer)(seconds, 0x1_0000, 0, core::ptr::null()) }.ok()
    }

    fn allocate(&self, kind: AllocateType, memory_type: MemoryType, pages: u64, addr: u64) -> Result<PhysAddr, Status> {
        let n = usize::try_from(pages).map_err(|_| Status::OUT_OF_RESOURCES)?;
        let mut at = addr;
        // SAFETY: a boot service; it reads `at` for `MaxAddress` and
        // `Address`, and writes the allocation's address there on success.
        unsafe { (self.bs().allocate_pages)(kind, memory_type, n, &mut at) }.ok()?;
        Ok(PhysAddr::new(at))
    }

    /// Allocates `pages` UEFI pages of `memory_type` (usually
    /// [`MemoryType::LOADER_DATA`]) anywhere, and returns their address.
    pub fn allocate_pages(&self, pages: u64, memory_type: MemoryType) -> Result<PhysAddr, Status> {
        self.allocate(AllocateType::AnyPages, memory_type, pages, 0)
    }

    /// Allocates `pages` UEFI pages of `memory_type` that end at or below
    /// `max` (the address of the last byte they may use).
    pub fn allocate_pages_below(&self, max: PhysAddr, pages: u64, memory_type: MemoryType) -> Result<PhysAddr, Status> {
        self.allocate(AllocateType::MaxAddress, memory_type, pages, max.0)
    }

    /// Allocates `pages` UEFI pages of `memory_type` at exactly `addr`
    /// (page-aligned). Fails with [`Status::NOT_FOUND`] or
    /// [`Status::OUT_OF_RESOURCES`] if they are not all free memory.
    pub fn allocate_pages_at(&self, addr: PhysAddr, pages: u64, memory_type: MemoryType) -> Result<(), Status> {
        self.allocate(AllocateType::Address, memory_type, pages, addr.0).map(|_| ())
    }

    /// Gives back pages from one of the `allocate_pages` calls.
    ///
    /// # Safety
    /// `addr` and `pages` are a whole earlier allocation, and nothing refers
    /// to the pages any more: the firmware reuses them.
    pub unsafe fn free_pages(&self, addr: PhysAddr, pages: u64) -> Result<(), Status> {
        let n = usize::try_from(pages).map_err(|_| Status::INVALID_PARAMETER)?;
        // SAFETY: a boot service; the caller's contract.
        unsafe { (self.bs().free_pages)(addr.0, n) }.ok()
    }

    /// How big the memory map is now.
    pub fn memory_map_size(&self) -> Result<MemoryMapSize, Status> {
        let (mut size, mut key, mut descriptor_size, mut version) = (0, 0, 0, 0);
        // SAFETY: a boot service; with a zero size it writes nothing but
        // the sizes.
        let s = unsafe {
            (self.bs().get_memory_map)(&mut size, core::ptr::null_mut(), &mut key, &mut descriptor_size, &mut version)
        };
        match s {
            Status::BUFFER_TOO_SMALL | Status::SUCCESS => Ok(MemoryMapSize { bytes: size, descriptor_size }),
            e => Err(e),
        }
    }

    fn read_memory_map(&self, buf: &mut [u8]) -> Result<RawMap, Status> {
        // Descriptors hold 64-bit fields: start the map 8-aligned.
        let offset = buf.as_ptr().align_offset(8);
        let Some(aligned) = buf.get_mut(offset..) else { return Err(Status::BUFFER_TOO_SMALL) };
        let (mut size, mut key, mut descriptor_size, mut version) = (aligned.len(), 0, 0, 0);
        // SAFETY: a boot service writing at most `size` bytes to `aligned`.
        unsafe {
            (self.bs().get_memory_map)(
                &mut size,
                aligned.as_mut_ptr().cast(),
                &mut key,
                &mut descriptor_size,
                &mut version,
            )
        }
        .ok()?;
        Ok(RawMap { offset, used: size.min(aligned.len()), key, descriptor_size, version })
    }

    /// Reads the memory map into `buf`. Too small a buffer is
    /// [`Status::BUFFER_TOO_SMALL`]; size it with [`Uefi::memory_map_size`].
    pub fn memory_map<'buf>(&self, buf: &'buf mut [u8]) -> Result<MemoryMap<'buf>, Status> {
        let raw = self.read_memory_map(buf)?;
        Ok(raw.into_map(buf))
    }

    /// Ends boot services, if `key` is that of the current memory map.
    /// A stale key is [`Status::INVALID_PARAMETER`]; then only the memory
    /// map may be read (and this called again).
    ///
    /// # Safety
    /// `image` is this image's handle. On success boot services are gone:
    /// nothing may call a method of this module again except
    /// [`Uefi::configuration_tables`], [`Uefi::configuration_table`],
    /// [`Uefi::system_table`] and [`Uefi::reset`], firmware console and
    /// protocol pointers are dead, and memory the firmware owned as boot
    /// services memory may be reused (and no [`File`] may be dropped). The
    /// caller must also not rely on interrupts or timers the firmware set
    /// up.
    pub unsafe fn exit_boot_services(&self, image: Handle, key: MemoryMapKey) -> Result<(), Status> {
        // SAFETY: a boot service; the caller's contract covers what follows.
        unsafe { (self.bs().exit_boot_services)(image, key.0) }.ok()
    }

    /// Reads the final memory map into `buf` and ends boot services,
    /// rereading the map while `ExitBootServices` reports it changed (a
    /// timer event can allocate between the two calls), up to 8 times.
    /// Size `buf` with [`Uefi::memory_map_size`] and
    /// [`MemoryMapSize::with_slack`], and allocate it, and everything else
    /// the kernel needs, first.
    ///
    /// On error, boot services may have been partly shut down, so all the
    /// caller can do safely is report the failure in some other way or
    /// reset.
    ///
    /// # Safety
    /// As for [`Uefi::exit_boot_services`].
    pub unsafe fn exit_boot_services_with_map<'buf>(
        &self,
        image: Handle,
        buf: &'buf mut [u8],
    ) -> Result<MemoryMap<'buf>, Status> {
        for _ in 0..EXIT_ATTEMPTS {
            let raw = self.read_memory_map(buf)?;
            // SAFETY: the caller's contract.
            match unsafe { self.exit_boot_services(image, MemoryMapKey(raw.key)) } {
                Ok(()) => return Ok(raw.into_map(buf)),
                // The map changed between reading it and exiting.
                Err(Status::INVALID_PARAMETER) => {}
                Err(e) => return Err(e),
            }
        }
        Err(Status::INVALID_PARAMETER)
    }

    /// The protocol `guid` on `handle`.
    ///
    /// # Safety
    /// `T` must be the protocol's interface structure.
    pub unsafe fn handle_protocol<T>(&self, handle: Handle, guid: &Guid) -> Result<*mut T, Status> {
        let mut out = core::ptr::null_mut();
        // SAFETY: a boot service; `out` is written on success.
        unsafe { (self.bs().handle_protocol)(handle, guid, &mut out) }.ok()?;
        if out.is_null() { Err(Status::UNSUPPORTED) } else { Ok(out.cast()) }
    }

    /// The loaded image protocol of `image` (this application's handle, from
    /// `efi_main`).
    // The handle is never dereferenced here: the firmware looks it up in its
    // handle database and rejects one it does not know.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn loaded_image(&self, image: Handle) -> Result<&'static LoadedImage, Status> {
        // SAFETY: `LoadedImage` is the protocol's interface.
        let li = unsafe { self.handle_protocol::<LoadedImage>(image, &LOADED_IMAGE_GUID)? };
        // SAFETY: the firmware's structure, valid while boot services last.
        unsafe { li.as_ref() }.ok_or(Status::UNSUPPORTED)
    }

    /// The root directory of the file system on `device`.
    // The handle is never dereferenced here: the firmware looks it up in its
    // handle database and rejects one it does not know.
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    pub fn open_volume(&self, device: Handle) -> Result<File, Status> {
        // SAFETY: `SimpleFileSystem` is the protocol's interface.
        let fs = unsafe { self.handle_protocol::<SimpleFileSystem>(device, &SIMPLE_FILE_SYSTEM_GUID)? };
        let mut root = core::ptr::null_mut();
        // SAFETY: a protocol call; `root` is written on success.
        unsafe { ((*fs).open_volume)(fs, &mut root) }.ok()?;
        File::from_raw(root)
    }

    /// The root directory of the file system `image` (this application) was
    /// loaded from, usually the EFI system partition.
    pub fn boot_volume(&self, image: Handle) -> Result<File, Status> {
        self.open_volume(self.loaded_image(image)?.device())
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
        assert_eq!(core::mem::offset_of!(SystemTable, configuration_table), 112);
        assert_eq!(size_of::<ConfigurationTable>(), 24);
        assert_eq!(core::mem::offset_of!(BootServices, allocate_pages), 40);
        assert_eq!(core::mem::offset_of!(BootServices, get_memory_map), 56);
        assert_eq!(core::mem::offset_of!(BootServices, free_pool), 72);
        assert_eq!(core::mem::offset_of!(BootServices, handle_protocol), 152);
        assert_eq!(core::mem::offset_of!(BootServices, exit_boot_services), 232);
        assert_eq!(core::mem::offset_of!(BootServices, stall), 248);
        assert_eq!(core::mem::offset_of!(BootServices, set_watchdog_timer), 256);
        assert_eq!(core::mem::offset_of!(BootServices, locate_protocol), 320);
        assert_eq!(core::mem::offset_of!(RuntimeServices, reset_system), 104);
        assert_eq!(core::mem::offset_of!(GopMode, frame_buffer_base), 24);
        assert_eq!(size_of::<ModeInfo>(), 36);
        assert_eq!(core::mem::offset_of!(LoadedImage, device_handle), 24);
        assert_eq!(core::mem::offset_of!(LoadedImage, load_options), 56);
        assert_eq!(core::mem::offset_of!(LoadedImage, image_base), 64);
        assert_eq!(core::mem::offset_of!(LoadedImage, image_size), 72);
        assert_eq!(core::mem::offset_of!(SimpleFileSystem, open_volume), 8);
        assert_eq!(core::mem::offset_of!(FileProtocol, read), 32);
        assert_eq!(core::mem::offset_of!(FileProtocol, get_info), 64);
    }

    fn descriptor(memory_type: u32, start: u64, pages: u64, size: usize) -> std::vec::Vec<u8> {
        let mut d = std::vec![0u8; size];
        d[..4].copy_from_slice(&memory_type.to_le_bytes());
        d[8..16].copy_from_slice(&start.to_le_bytes());
        d[16..24].copy_from_slice(&start.to_le_bytes());
        d[24..32].copy_from_slice(&pages.to_le_bytes());
        d[32..40].copy_from_slice(&0xfu64.to_le_bytes());
        d
    }

    #[test]
    fn memory_map() {
        // EDK2 uses 48-byte descriptors.
        let mut bytes = descriptor(7, 0x10_0000, 0x100, 48);
        bytes.extend(descriptor(4, 0x20_0000, u64::MAX, 48));
        bytes.extend([0; 20]);
        let raw = RawMap { offset: 0, used: bytes.len(), key: 42, descriptor_size: 48, version: 1 };
        let map = raw.into_map(&bytes);
        assert_eq!((map.len(), map.key(), map.version()), (2, MemoryMapKey(42), 1));
        let d: std::vec::Vec<_> = map.iter().collect();
        assert_eq!(d.len(), 2);
        assert_eq!(
            (d[0].memory_type, d[0].physical_start, d[0].size()),
            (MemoryType::CONVENTIONAL, PhysAddr::new(0x10_0000), 0x10_0000)
        );
        assert_eq!((d[1].memory_type, d[1].size(), d[1].attribute), (MemoryType::BOOT_SERVICES_DATA, u64::MAX, 0xf));
        // A descriptor size below the structure's is refused, not misread.
        let map = RawMap { descriptor_size: 24, ..raw }.into_map(&bytes);
        assert!(map.is_empty() && map.iter().next().is_none());
        // The used length is clamped to the buffer.
        let map = RawMap { offset: 8, used: 1 << 20, ..raw }.into_map(&bytes);
        assert!(map.bytes().is_empty());
        let size = MemoryMapSize { bytes: 480, descriptor_size: 48 };
        assert_eq!(size.with_slack(4), 480 + 4 * 48 + 8);
        assert_eq!(pages_for(0), 0);
        assert_eq!(pages_for(4097), 2);
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
