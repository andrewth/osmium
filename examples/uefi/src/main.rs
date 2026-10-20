//! A UEFI application: finds the Graphics Output Protocol, switches to an
//! 800x600 mode (or keeps the current one), draws colour bars on the linear framebuffer and powers
//! off. It builds for `x86_64-unknown-uefi` (OVMF) and
//! `aarch64-unknown-uefi` (AAVMF); `scripts/check.sh` boots both and checks
//! the screen with `scripts/screen.py`.
#![no_std]
#![no_main]

use core::fmt::Write;

use osmium_boot::uefi::{Handle, ResetType, Status, SystemTable, Uefi};
use osmium_hal::display::{Display, Framebuffer, Rect, Rgb};
use osmium_hal::mmio::IoMem;

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

#[unsafe(export_name = "efi_main")]
extern "efiapi" fn efi_main(_image: Handle, st: *const SystemTable) -> Status {
    // SAFETY: the firmware passes its system table, with boot services up.
    let Some(uefi) = (unsafe { Uefi::new(st) }) else { return Status::UNSUPPORTED };
    let mut out = Console(uefi);
    let (major, minor) = uefi.revision();
    let _ = writeln!(out, "\nosmium UEFI example on {} (UEFI {major}.{minor})", ARCH);
    let ok = gop_demo(&uefi, &mut out);
    // Leave the picture up long enough for a screendump.
    uefi.stall(3_000_000);
    let _ = writeln!(out, "[done]  {}", if ok { "shutting down" } else { "GOP demo failed" });
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

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
