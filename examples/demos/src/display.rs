//! Display demos: find a PCI display adapter, set a mode and draw colour
//! bars that `scripts/screen.py` can check in a QEMU screendump.

use osmium::display::PciDisplay;
use osmium::display::bochs::BochsVbe;
use osmium::drivers::virtio::Transport;
use osmium::display::virtio_gpu::VirtioGpu;
use osmium::drivers::virtio::pci::PciTransport;
use osmium::hal::display::{Display, Rect, Rgb};
use osmium::hal::dma::DmaAllocator;
use osmium::hal::mmio::IoMem;
use osmium::hal::pci::{self, ConfigAccess, Function};
use osmium::hal::println;

/// The bars, left to right: the classic SMPTE order.
pub const BARS: [Rgb; 8] = [
    Rgb::new(0xff, 0xff, 0xff),
    Rgb::new(0xff, 0xff, 0x00),
    Rgb::new(0x00, 0xff, 0xff),
    Rgb::new(0x00, 0xff, 0x00),
    Rgb::new(0xff, 0x00, 0xff),
    Rgb::new(0xff, 0x00, 0x00),
    Rgb::new(0x00, 0x00, 0xff),
    Rgb::new(0x00, 0x00, 0x00),
];

/// Draws eight vertical colour bars over the whole screen, flushes them,
/// and checks the middle of each bar reads back. Returns the check.
pub fn bars(d: &mut impl Display) -> bool {
    let info = d.info();
    let w = info.width / BARS.len() as u32;
    for (i, &c) in BARS.iter().enumerate() {
        let x = i as u32 * w;
        let width = if i == BARS.len() - 1 { info.width - x } else { w };
        d.framebuffer().fill_rect(Rect::new(x, 0, width, info.height), c);
    }
    let flushed = d.flush_all().is_ok();
    flushed
        && BARS
            .iter()
            .enumerate()
            .all(|(i, &c)| d.framebuffer().pixel(i as u32 * w + w / 2, info.height / 2) == Some(c))
}

/// Prints `d`'s mode and draws [`bars`] on it.
pub fn show(tag: &str, d: &mut impl Display) -> bool {
    let info = d.info();
    let ok = bars(d);
    println!(
        "[{tag}] {}x{} {}bpp, stride {}: colour bars {}",
        info.width,
        info.height,
        info.format.bpp,
        info.stride,
        if ok { "drawn" } else { "FAILED" }
    );
    ok
}

/// Probes every display adapter on `cfg` and puts colour bars on it: a Bochs DISPI mode of `width` by `height` on standard
/// VGA, `bochs-display` and `virtio-vga`, then virtio-gpu on `virtio-vga`
/// and `virtio-gpu-pci`. BARs come from `bars` where firmware leaves them
/// unassigned, and `map(address, size)` maps one for the CPU. Returns the
/// number of displays that showed the bars.
pub fn pci<C: ConfigAccess + ?Sized, D: DmaAllocator + ?Sized>(
    cfg: &C,
    first_bus: u8,
    width: u16,
    height: u16,
    mut bars: Option<&mut pci::BarAllocator>,
    map: &mut dyn FnMut(u64, u64) -> IoMem,
    dma: &D,
) -> usize {
    let mut found = [None; 4];
    let mut n = 0;
    pci::for_each_function(cfg, first_bus, |f| {
        if let Some(kind) = PciDisplay::identify(&f)
            && n < found.len()
        {
            found[n] = Some((f.address(), kind));
            n += 1;
        }
    });
    let mut shown = 0;
    for (addr, kind) in found.into_iter().flatten() {
        let Some(f) = Function::new(cfg, addr) else { continue };
        if let Some(bars) = bars.as_deref_mut()
            && bars.assign(&f).is_err()
        {
            println!("[display] {addr:?}: no room for its BARs");
            continue;
        }
        let tag = match kind {
            PciDisplay::StdVga => "vga",
            PciDisplay::BochsDisplay => "bochs",
            PciDisplay::VirtioVga => "virtio-vga",
            PciDisplay::VirtioGpu => "virtio-gpu",
        };
        println!(
            "[{tag}] {:02x}:{:02x}.{} {:04x}:{:04x}",
            addr.bus,
            addr.device,
            addr.function,
            f.vendor_id(),
            f.device_id()
        );
        if kind.has_dispi() {
            shown += dispi(tag, &f, kind, width, height, map) as usize;
        }
        if matches!(kind, PciDisplay::VirtioVga | PciDisplay::VirtioGpu) {
            match PciTransport::new(&f, |bar| Some(map(bar.address, bar.size))) {
                Ok(t) => shown += virtio_gpu(tag, t, dma) as usize,
                Err(e) => println!("[{tag}] virtio-pci: {e:?}"),
            }
        }
    }
    shown
}

fn dispi<C: ConfigAccess + ?Sized>(
    tag: &str,
    f: &Function<'_, C>,
    kind: PciDisplay,
    width: u16,
    height: u16,
    map: &mut dyn FnMut(u64, u64) -> IoMem,
) -> bool {
    // virtio-vga keeps the DISPI registers in its virtio BAR (2) too.
    let (Some(vram), Some(mmio)) = (f.bar(0), f.bar(2)) else {
        println!("[{tag}] missing BAR 0 or 2");
        return false;
    };
    f.enable_memory_and_dma();
    let vbe = BochsVbe::new_mmio(map(mmio.address, mmio.size), map(vram.address, vram.size), kind.is_vga());
    let mut vbe = match vbe {
        Ok(v) => v,
        Err(e) => {
            println!("[{tag}] no DISPI: {e:?}");
            return false;
        }
    };
    let before = vbe.info();
    if before.width != 0 {
        println!(
            "[{tag}] DISPI {:#x}: firmware left {}x{} {}bpp",
            vbe.version(),
            before.width,
            before.height,
            before.format.bpp
        );
    }
    match vbe.set_mode(width, height, 32) {
        Ok(_) => show(tag, &mut vbe),
        Err(e) => {
            println!("[{tag}] DISPI {:#x}: {width}x{height} failed: {e:?}", vbe.version());
            false
        }
    }
}

/// Drives the virtio GPU behind `transport` (any transport): a mode of half
/// its preferred size on its first scanout, with [`bars`] on it. The device
/// is left running so the picture stays up.
pub fn virtio_gpu<T: Transport, D: DmaAllocator + ?Sized>(tag: &str, transport: T, dma: &D) -> bool {
    let mut gpu = match VirtioGpu::new(transport, dma) {
        Ok(g) => g,
        Err(e) => {
            println!("[{tag}] virtio-gpu: {e:?}");
            return false;
        }
    };
    let (scanout, mode) = match gpu.display_info().map(|i| i.first_enabled()) {
        Ok(Some(m)) => m,
        other => {
            println!("[{tag}] no enabled scanout: {other:?}");
            return false;
        }
    };
    println!(
        "[{tag}] virtio-gpu: {} scanout(s); scanout {scanout} prefers {}x{}",
        gpu.num_scanouts(),
        mode.width,
        mode.height
    );
    // Half the preferred size keeps the framebuffer small.
    match gpu.set_mode(scanout, mode.width / 2, mode.height / 2) {
        Ok(_) => {
            let ok = show(tag, &mut gpu);
            // Leave the device running so the picture stays up.
            core::mem::forget(gpu);
            ok
        }
        Err(e) => {
            println!("[{tag}] set_mode: {e:?}");
            false
        }
    }
}
