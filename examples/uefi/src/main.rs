//! A UEFI application: finds the Graphics Output Protocol, switches to an
//! 800x600 mode (or keeps the current one) and draws colour bars on the linear framebuffer. Then it
//! does what a loader does: finds the ACPI RSDP among the configuration tables, reads
//! `\osmium\hello.txt` from the volume it was loaded from into pages of its own, allocates pages
//! below 4 GiB and at a fixed address, reads the memory map, exits boot services and, with only
//! the serial port and the runtime services left, reports the final map and powers off. It builds
//! for `x86_64-unknown-uefi` (OVMF) and `aarch64-unknown-uefi` (AAVMF); `scripts/check.sh` boots
//! both, with the file on the ESP, and checks the screen with `scripts/screen.py`.
#![no_std]
#![no_main]

use core::fmt::Write;

use osmium_boot::uefi::{
    ACPI_20_TABLE_GUID, DEVICE_TREE_GUID, Handle, MemoryMap, MemoryType, PAGE_SIZE, ResetType, Status, SystemTable,
    Uefi, pages_for,
};
use osmium_hal::display::{Display, Framebuffer, Rect, Rgb};
use osmium_hal::mmio::IoMem;
use osmium_hal::serial::SerialWriter;
use osmium_mm::PhysAddr;

/// The bars of `examples/demos/src/display.rs`, left to right.
const BARS: [Rgb; 8] = [
    Rgb::new(0xff, 0xff, 0xff),
    Rgb::new(0xff, 0xff, 0x00),
    Rgb::new(0x00, 0xff, 0xff),
    Rgb::new(0x00, 0xff, 0x00),
    Rgb::new(0xff, 0x00, 0xff),
    Rgb::new(0xff, 0x00, 0x00),
    Rgb::new(0x00, 0x00, 0xff),
    Rgb::new(0x00, 0x00, 0x00),
];

#[cfg(target_arch = "x86_64")]
const ARCH: &str = "x86_64";
#[cfg(target_arch = "aarch64")]
const ARCH: &str = "aarch64";

struct Console(Uefi);

impl Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0.print(s);
        Ok(())
    }
}

/// The file `scripts/check.sh` puts on the ESP.
const HELLO_PATH: &str = "\\osmium\\hello.txt";

/// Extra descriptors to leave room for in the memory map buffer.
const MAP_SLACK: usize = 16;

#[unsafe(export_name = "efi_main")]
extern "efiapi" fn efi_main(image: Handle, st: *const SystemTable) -> Status {
    // SAFETY: the firmware passes its system table, with boot services up.
    let Some(uefi) = (unsafe { Uefi::new(st) }) else { return Status::UNSUPPORTED };
    let mut out = Console(uefi);
    let (major, minor) = uefi.revision();
    let _ = writeln!(out, "\nosmium UEFI example on {} (UEFI {major}.{minor})", ARCH);
    let _ = uefi.set_watchdog_timer(0);
    let gop_ok = gop_demo(&uefi, &mut out);
    // Leave the picture up long enough for a screendump.
    uefi.stall(3_000_000);
    let loader_ok = tables_demo(&uefi, &mut out) & file_demo(&uefi, image, &mut out) & pages_demo(&uefi, &mut out);
    let map_ok = memory_map_demo(&uefi, &mut out);
    let ok = gop_ok && loader_ok && map_ok;
    if !ok {
        let _ = writeln!(out, "[done]  {}", if gop_ok { "loader services failed" } else { "GOP demo failed" });
        uefi.reset(ResetType::Shutdown)
    }
    exit_demo(&uefi, image, &mut out)
}

/// Finds the ACPI RSDP (and a devicetree, if there is one) among the
/// configuration tables.
fn tables_demo(uefi: &Uefi, out: &mut Console) -> bool {
    let n = uefi.configuration_tables().len();
    let Some(rsdp) = uefi.configuration_table(&ACPI_20_TABLE_GUID) else {
        let _ = writeln!(out, "[tables] {n} configuration tables, no ACPI 2.0 RSDP");
        return false;
    };
    // SAFETY: the firmware published an RSDP there; UEFI identity-maps memory.
    let signature = unsafe { (rsdp.0 as *const [u8; 8]).read_unaligned() };
    let ok = &signature == b"RSD PTR ";
    let dt = if uefi.configuration_table(&DEVICE_TREE_GUID).is_some() { "a devicetree" } else { "no devicetree" };
    let _ = writeln!(
        out,
        "[tables] {n} configuration tables: ACPI 2.0 RSDP at {:#x}, signature {}; {dt}",
        rsdp.0,
        if ok { "ok" } else { "BAD" }
    );
    ok
}

/// Reads `HELLO_PATH` from the boot volume into pages of its own.
fn file_demo(uefi: &Uefi, image: Handle, out: &mut Console) -> bool {
    let read = || -> Result<(PhysAddr, u64, usize), (&'static str, Status)> {
        let root = uefi.boot_volume(image).map_err(|e| ("no file system on the boot device", e))?;
        let mut file = root.open(HELLO_PATH).map_err(|e| ("open", e))?;
        let size = file.size().map_err(|e| ("size", e))?.min(PAGE_SIZE);
        let pages = pages_for(size).max(1);
        let addr = uefi.allocate_pages(pages, MemoryType::LOADER_DATA).map_err(|e| ("allocate", e))?;
        // SAFETY: just allocated, and only used here.
        let buf = unsafe { core::slice::from_raw_parts_mut(addr.0 as *mut u8, size as usize) };
        let n = file.read(buf);
        Ok((addr, pages, n.map_err(|e| ("read", e))?))
    };
    match read() {
        Ok((addr, pages, n)) => {
            // SAFETY: `read` filled `n` bytes of these pages.
            let bytes = unsafe { core::slice::from_raw_parts(addr.0 as *const u8, n) };
            let text = core::str::from_utf8(bytes).unwrap_or("(not UTF-8)").trim_end();
            let _ = writeln!(out, "[file]  {HELLO_PATH}: {n} bytes at {:#x}: \"{text}\"", addr.0);
            // SAFETY: the whole allocation from `read`, no longer used.
            unsafe { uefi.free_pages(addr, pages) }.is_ok()
        }
        Err((what, e)) => {
            let _ = writeln!(out, "[file]  {HELLO_PATH}: {what} failed: {e:?}");
            false
        }
    }
}

/// Allocates pages below 4 GiB, gives them back and claims the same address
/// again; claiming it twice must fail.
fn pages_demo(uefi: &Uefi, out: &mut Console) -> bool {
    const PAGES: u64 = 4;
    let below = PhysAddr::new(0xffff_ffff);
    let Ok(addr) = uefi.allocate_pages_below(below, PAGES, MemoryType::LOADER_DATA) else {
        let _ = writeln!(out, "[pages] no pages below 4 GiB");
        return false;
    };
    // SAFETY: allocated just above and not used.
    let freed = unsafe { uefi.free_pages(addr, PAGES) }.is_ok();
    let again = freed && uefi.allocate_pages_at(addr, PAGES, MemoryType::LOADER_DATA).is_ok();
    let twice = again && uefi.allocate_pages_at(addr, PAGES, MemoryType::LOADER_DATA).is_err();
    // SAFETY: the allocation at `addr`, not used.
    let ok = twice && unsafe { uefi.free_pages(addr, PAGES) }.is_ok() && addr.0 < 1 << 32;
    let _ = writeln!(
        out,
        "[pages] {PAGES} pages below 4 GiB at {:#x}; freed, claimed again at that address, a second claim refused: {}",
        addr.0,
        if ok { "ok" } else { "FAILED" }
    );
    ok
}

/// What a memory map holds: descriptors, and free and boot services memory
/// in MiB.
fn summary(map: &MemoryMap<'_>) -> (usize, u64, u64) {
    let mib = |t: MemoryType| map.iter().filter(|d| d.memory_type == t).map(|d| d.size()).sum::<u64>() >> 20;
    let boot = mib(MemoryType::BOOT_SERVICES_CODE) + mib(MemoryType::BOOT_SERVICES_DATA);
    (map.len(), mib(MemoryType::CONVENTIONAL), boot)
}

/// Reads the memory map while boot services are up.
fn memory_map_demo(uefi: &Uefi, out: &mut Console) -> bool {
    let size = match uefi.memory_map_size() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(out, "[memmap] GetMemoryMap: {e:?}");
            return false;
        }
    };
    let bytes = size.with_slack(MAP_SLACK) as u64;
    let Ok(addr) = uefi.allocate_pages(pages_for(bytes), MemoryType::LOADER_DATA) else { return false };
    // SAFETY: just allocated, and only used here.
    let buf = unsafe { core::slice::from_raw_parts_mut(addr.0 as *mut u8, bytes as usize) };
    let ok = match uefi.memory_map(buf) {
        Ok(map) => {
            let (n, free, boot) = summary(&map);
            let _ = writeln!(
                out,
                "[memmap] {n} descriptors of {} bytes: {free} MiB free, {boot} MiB boot services",
                map.descriptor_size()
            );
            n > 0 && free > 0
        }
        Err(e) => {
            let _ = writeln!(out, "[memmap] GetMemoryMap: {e:?}");
            false
        }
    };
    // SAFETY: the allocation above, no longer used.
    unsafe { uefi.free_pages(addr, pages_for(bytes)) }.is_ok() && ok
}

/// Exits boot services, then reports the final memory map on the serial
/// port, the only console left, and powers off through the runtime services.
fn exit_demo(uefi: &Uefi, image: Handle, out: &mut Console) -> ! {
    let buf = uefi.memory_map_size().ok().and_then(|size| {
        let bytes = size.with_slack(MAP_SLACK) as u64;
        let addr = uefi.allocate_pages(pages_for(bytes), MemoryType::LOADER_DATA).ok()?;
        // SAFETY: just allocated; the firmware does not touch loader data
        // after ExitBootServices.
        Some(unsafe { core::slice::from_raw_parts_mut(addr.0 as *mut u8, bytes as usize) })
    });
    let Some(buf) = buf else {
        let _ = writeln!(out, "[exit]  no memory for the memory map\n[done]  loader services failed");
        uefi.reset(ResetType::Shutdown)
    };
    let _ = writeln!(out, "[exit]  exiting boot services");
    // SAFETY: `image` is this application's handle. On success nothing below
    // calls a boot service: it writes to the serial port and resets through
    // the runtime services.
    match unsafe { uefi.exit_boot_services_with_map(image, buf) } {
        Ok(map) => {
            let (n, free, boot) = summary(&map);
            let mut serial = serial::port();
            let mut w = SerialWriter(&mut serial);
            let _ =
                writeln!(w, "[exit]  boot services exited: final map has {n} descriptors, {} MiB usable", free + boot);
            let _ = writeln!(w, "[done]  shutting down");
        }
        Err(e) => {
            // Boot services may be half gone: try the serial port too.
            let mut serial = serial::port();
            let _ = writeln!(SerialWriter(&mut serial), "[exit]  ExitBootServices failed: {e:?}");
        }
    }
    uefi.reset(ResetType::Shutdown)
}

fn gop_demo(uefi: &Uefi, out: &mut Console) -> bool {
    let mut gop = match uefi.gop() {
        Ok(g) => g,
        Err(e) => {
            let _ = writeln!(out, "[gop]   no Graphics Output Protocol: {e:?}");
            return false;
        }
    };
    let _ = writeln!(out, "[gop]   {} modes, current mode {}", gop.num_modes(), gop.current_mode());
    // 800x600 where offered; otherwise keep the firmware's mode.
    let mode = gop.find_mode(800, 600).unwrap_or(gop.current_mode());
    if let Err(e) = gop.set_mode(mode) {
        let _ = writeln!(out, "[gop]   set mode {mode}: {e:?}");
        return false;
    }
    let Some((addr, info)) = gop.framebuffer() else {
        return blt_bars(&mut gop, mode, out);
    };
    // SAFETY: UEFI identity-maps memory; GOP reported the framebuffer, and
    // nothing else draws on it while this application runs.
    let mem = unsafe { IoMem::new(addr.0 as *mut u8, info.size()) };
    let Ok(mut fb) = Framebuffer::new(mem, info) else { return false };
    let w = info.width / BARS.len() as u32;
    for (i, &c) in BARS.iter().enumerate() {
        let x = i as u32 * w;
        let width = if i == BARS.len() - 1 { info.width - x } else { w };
        fb.fill_rect(Rect::new(x, 0, width, info.height), c);
    }
    let _ = fb.flush_all();
    let ok = BARS.iter().enumerate().all(|(i, &c)| fb.pixel(i as u32 * w + w / 2, info.height / 2) == Some(c));
    let _ = writeln!(
        out,
        "[gop]   {}x{} {}bpp: colour bars {}",
        info.width,
        info.height,
        info.format.bpp,
        if ok { "drawn" } else { "FAILED" }
    );
    ok
}

/// Draws the bars with GOP's `Blt`, for modes without a framebuffer.
fn blt_bars(gop: &mut osmium_boot::uefi::Gop, mode: u32, out: &mut Console) -> bool {
    let Some(info) = gop.current_info() else { return false };
    let w = info.width / BARS.len() as u32;
    let ok = BARS.iter().enumerate().all(|(i, &c)| {
        let x = i as u32 * w;
        let width = if i == BARS.len() - 1 { info.width - x } else { w };
        gop.fill(Rect::new(x, 0, width, info.height), c).is_ok()
    });
    let _ = writeln!(
        out,
        "[gop]   mode {mode}: {}x{}, Blt only: colour bars {}",
        info.width,
        info.height,
        if ok { "drawn" } else { "FAILED" }
    );
    ok
}

/// The serial port the firmware's console used, written to directly once
/// boot services are gone.
mod serial {
    use osmium_hal::serial::SerialPort;

    /// COM1, as the firmware left it.
    #[cfg(target_arch = "x86_64")]
    pub fn port() -> impl SerialPort {
        use osmium_sysdrv::uart16550::{Pio, Uart16550};
        // SAFETY: the firmware's console is gone, so the application owns COM1.
        Uart16550::new(unsafe { Pio::new(0x3f8) })
    }

    /// QEMU virt's PL011, as the firmware left it.
    #[cfg(target_arch = "aarch64")]
    pub fn port() -> impl SerialPort {
        // SAFETY: the firmware's console is gone, so the application owns the
        // UART, which the firmware's page tables still map.
        let io = unsafe { osmium_hal::mmio::IoMem::new(0x0900_0000 as *mut u8, 0x1000) };
        Pl011(osmium_sysdrv::pl011::Pl011::new(io).ok())
    }

    /// The PL011, if its register window was accepted.
    #[cfg(target_arch = "aarch64")]
    struct Pl011(Option<osmium_sysdrv::pl011::Pl011>);

    #[cfg(target_arch = "aarch64")]
    impl SerialPort for Pl011 {
        fn write_byte(&mut self, byte: u8) {
            if let Some(p) = &mut self.0 {
                p.write_byte(byte);
            }
        }
        fn read_byte(&mut self) -> Option<u8> {
            self.0.as_mut()?.read_byte()
        }
    }
}

/// Reports the panic on the serial port, then halts. The port is written
/// directly, not through the firmware's console: that works whether or not
/// boot services are still up, and the panic may have come from inside a
/// console write.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    let mut serial = serial::port();
    let _ = writeln!(SerialWriter(&mut serial), "\n[panic] {info}");
    loop {
        core::hint::spin_loop();
    }
}
