//! virtio-gpu, 2D: a framebuffer in guest RAM that the device scans out.
//!
//! The driver keeps one host resource per mode. [`VirtioGpu::set_mode`]
//! allocates the framebuffer from DMA memory, creates a 2D resource of the
//! same size (`RESOURCE_CREATE_2D`), attaches the memory as its backing
//! store (`RESOURCE_ATTACH_BACKING`) and points a scanout at it
//! (`SET_SCANOUT`). Drawing goes to guest memory; [`Display::flush`] copies
//! the changed rectangle to the host (`TRANSFER_TO_HOST_2D`) and shows it
//! (`RESOURCE_FLUSH`).
//!
//! The same driver serves `virtio-gpu-device` (MMIO), `virtio-gpu-pci` and
//! `virtio-vga`, whose PCI function adds a VGA-compatible framebuffer that
//! works until the first `SET_SCANOUT` (see [`crate::display::bochs`]).
//! Commands are synchronous, like [`super::blk`]'s requests: one is in
//! flight at a time and the driver polls for its response.

use osmium_hal::display::{Display, DisplayError, Framebuffer, FramebufferInfo, PixelFormat, Rect};
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::virtio::gpu::*;

use super::queue::{Segment, VirtQueue};
use core::mem::ManuallyDrop;

use super::{DeviceType, POLL_LIMIT, Transport, VirtioError, driver_ok, negotiate, reset};

/// Entries used in the control queue, at most (a command needs two).
pub const MAX_QUEUE_SIZE: u16 = 4;

/// Bytes of the request and response buffers.
const CMD_LEN: usize = 4096;

/// Largest framebuffer side the driver asks for.
pub const MAX_SIDE: u32 = 16384;

/// The format of every framebuffer: bytes B, G, R, X.
pub const FORMAT: PixelFormat = PixelFormat::XRGB8888;

/// One scanout's preferred mode, from `GET_DISPLAY_INFO`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scanout {
    /// Position and size the host suggests.
    pub rect: Rect,
    /// True if a display is connected.
    pub enabled: bool,
}

/// What `GET_DISPLAY_INFO` reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayInfo {
    /// Each scanout, up to the device's `num_scanouts`.
    pub scanouts: [Scanout; MAX_SCANOUTS],
    /// How many entries of `scanouts` exist.
    pub count: usize,
}

impl DisplayInfo {
    /// The first scanout with a display connected, as `(index, mode)`.
    pub fn first_enabled(&self) -> Option<(u32, Rect)> {
        self.scanouts[..self.count].iter().position(|s| s.enabled).map(|i| (i as u32, self.scanouts[i].rect))
    }
}

/// A virtio GPU driving one scanout. Dropping it resets the device and
/// frees the framebuffer.
pub struct VirtioGpu<'d, T: Transport, D: DmaAllocator + ?Sized> {
    transport: T,
    dma: &'d D,
    // Freed in `drop` only once the device has acknowledged its reset.
    queue: ManuallyDrop<VirtQueue<'d, D>>,
    req: ManuallyDrop<OwnedDma<'d, D>>,
    resp: ManuallyDrop<OwnedDma<'d, D>>,
    num_scanouts: u32,
    // The current mode: its memory, resource ID and scanout.
    fb: Framebuffer,
    backing: ManuallyDrop<Option<OwnedDma<'d, D>>>,
    resource: u32,
    scanout: u32,
}

/// Little-endian request builder.
struct Cmd {
    buf: [u8; 64],
    len: usize,
}

impl Cmd {
    fn new(ty: u32) -> Self {
        let mut c = Self { buf: [0; 64], len: HDR_LEN };
        c.buf[..4].copy_from_slice(&ty.to_le_bytes());
        c
    }

    fn u32(mut self, v: u32) -> Self {
        self.buf[self.len..self.len + 4].copy_from_slice(&v.to_le_bytes());
        self.len += 4;
        self
    }

    fn u64(self, v: u64) -> Self {
        self.u32(v as u32).u32((v >> 32) as u32)
    }

    fn rect(self, r: Rect) -> Self {
        self.u32(r.x).u32(r.y).u32(r.width).u32(r.height)
    }
}

impl<'d, T: Transport, D: DmaAllocator + ?Sized> VirtioGpu<'d, T, D> {
    /// Initializes the device behind `transport`, allocating its control
    /// queue and command buffers from `dma`. No scanout shows anything
    /// until [`VirtioGpu::set_mode`].
    pub fn new(transport: T, dma: &'d D) -> Result<Self, VirtioError> {
        if transport.device_type() != DeviceType::Gpu {
            return Err(VirtioError::WrongDevice);
        }
        negotiate(&transport, 0, 0)?;
        let size = match transport.max_queue_size(CONTROL_QUEUE).min(MAX_QUEUE_SIZE) {
            // Split queues come in powers of two.
            n if n >= 2 => 1 << n.ilog2(),
            _ => return Err(VirtioError::BadQueue),
        };
        let num_scanouts =
            u32::from_le_bytes(core::array::from_fn(|i| transport.config_read8(CONFIG_NUM_SCANOUTS + i)));
        // Plain values until all succeed, so a failure frees the others.
        let queue = VirtQueue::new(dma, CONTROL_QUEUE, size)?;
        let req = OwnedDma::new(dma, CMD_LEN).ok_or(VirtioError::NoMemory)?;
        let resp = OwnedDma::new(dma, CMD_LEN).ok_or(VirtioError::NoMemory)?;
        let gpu = Self {
            queue: ManuallyDrop::new(queue),
            req: ManuallyDrop::new(req),
            resp: ManuallyDrop::new(resp),
            num_scanouts: num_scanouts.min(MAX_SCANOUTS as u32),
            // SAFETY: an empty window touches no memory.
            fb: Framebuffer::new(
                unsafe { IoMem::new(core::ptr::NonNull::<u32>::dangling().as_ptr().cast(), 0) },
                FramebufferInfo::packed(0, 0, FORMAT),
            )
            .expect("empty framebuffer"),
            backing: ManuallyDrop::new(None),
            resource: 0,
            scanout: 0,
            dma,
            transport,
        };
        gpu.transport.setup_queue(CONTROL_QUEUE, size, gpu.queue.addrs());
        // Responses are polled.
        gpu.queue.set_interrupts(false);
        driver_ok(&gpu.transport);
        Ok(gpu)
    }

    /// The transport, e.g. for [`Transport::ack_interrupt`].
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Number of scanouts (display outputs) the device has.
    pub fn num_scanouts(&self) -> u32 {
        self.num_scanouts
    }

    /// Sends the request built in `cmd` (with `extra` bytes appended) and
    /// waits for a response of up to `resp_len` bytes; returns its type and
    /// how many bytes the device says it wrote.
    fn command(&mut self, cmd: Cmd, extra: &[u8], resp_len: usize) -> Result<(u32, usize), DisplayError> {
        self.req.write(0, &cmd.buf[..cmd.len]);
        self.req.write(cmd.len, extra);
        self.resp.write(0, &[0; HDR_LEN]);
        let segments = [
            Segment { addr: self.req.device_addr(), len: (cmd.len + extra.len()) as u32, device_writes: false },
            Segment { addr: self.resp.device_addr(), len: resp_len as u32, device_writes: true },
        ];
        let head = self.queue.add(&segments).map_err(|_| DisplayError::Device)?;
        if self.queue.needs_notify() {
            self.transport.notify(CONTROL_QUEUE);
        }
        // Nothing else is in flight, so the first completion is ours. A
        // device that never answers (or breaks the queue) fails the
        // command, and the queue then stays unusable.
        match self.queue.wait_used(POLL_LIMIT) {
            Some((done, len)) if done == head && len as usize >= HDR_LEN => {
                Ok((self.resp.load::<u32>(0), (len as usize).min(resp_len)))
            }
            _ => Err(DisplayError::Device),
        }
    }

    /// Sends a command whose only answer is `OK_NODATA`.
    fn command_nodata(&mut self, cmd: Cmd, extra: &[u8]) -> Result<(), DisplayError> {
        match self.command(cmd, extra, HDR_LEN)?.0 {
            RESP_OK_NODATA => Ok(()),
            RESP_ERR_INVALID_SCANOUT_ID | RESP_ERR_INVALID_PARAMETER => Err(DisplayError::Unsupported),
            RESP_ERR_OUT_OF_MEMORY => Err(DisplayError::NoMemory),
            _ => Err(DisplayError::Device),
        }
    }

    /// Asks the device for each scanout's preferred mode.
    pub fn display_info(&mut self) -> Result<DisplayInfo, DisplayError> {
        if self.command(Cmd::new(CMD_GET_DISPLAY_INFO), &[], RESP_DISPLAY_INFO_LEN)?
            != (RESP_OK_DISPLAY_INFO, RESP_DISPLAY_INFO_LEN)
        {
            return Err(DisplayError::Device);
        }
        let mut info = DisplayInfo { scanouts: [Scanout::default(); MAX_SCANOUTS], count: self.num_scanouts as usize };
        for (i, s) in info.scanouts.iter_mut().enumerate() {
            let at = HDR_LEN + i * DISPLAY_ONE_LEN;
            let w = |n: usize| self.resp.load::<u32>(at + 4 * n);
            *s = Scanout { rect: Rect::new(w(0), w(1), w(2), w(3)), enabled: w(4) != 0 };
        }
        Ok(info)
    }

    /// Shows a new `width` by `height` framebuffer on `scanout`, replacing
    /// the current one. The new framebuffer starts black.
    pub fn set_mode(&mut self, scanout: u32, width: u32, height: u32) -> Result<FramebufferInfo, DisplayError> {
        if scanout >= self.num_scanouts || width == 0 || height == 0 {
            return Err(DisplayError::Unsupported);
        }
        let (width, height) = (width.min(MAX_SIDE), height.min(MAX_SIDE));
        let info = FramebufferInfo::packed(width, height, FORMAT);
        let backing = OwnedDma::new(self.dma, info.size()).ok_or(DisplayError::NoMemory)?;
        // SAFETY: DMA memory owned by `backing`, which outlives the window:
        // both are replaced together below, and the device only reads it.
        let fb = Framebuffer::new(unsafe { IoMem::new(backing.cpu_ptr().as_ptr(), info.size()) }, info)?;
        fb.clear(osmium_hal::display::Rgb::BLACK);

        let id = self.resource + 1;
        let full = info.bounds();
        self.command_nodata(
            Cmd::new(CMD_RESOURCE_CREATE_2D).u32(id).u32(FORMAT_B8G8R8X8_UNORM).u32(width).u32(height),
            &[],
        )?;
        let mut entry = [0u8; MEM_ENTRY_LEN];
        entry[..8].copy_from_slice(&backing.device_addr().as_u64().to_le_bytes());
        entry[8..12].copy_from_slice(&(info.size() as u32).to_le_bytes());
        let attached = self
            .command_nodata(Cmd::new(CMD_RESOURCE_ATTACH_BACKING).u32(id).u32(1), &entry)
            .and_then(|()| self.command_nodata(Cmd::new(CMD_SET_SCANOUT).rect(full).u32(scanout).u32(id), &[]));
        if let Err(e) = attached {
            // Unreferencing detaches the backing; if even that fails, the
            // host may still hold it, so it is leaked rather than freed.
            if self.command_nodata(Cmd::new(CMD_RESOURCE_UNREF).u32(id).u32(0), &[]).is_err() {
                core::mem::forget(backing);
            }
            return Err(e);
        }
        let old = self.resource;
        self.fb = fb;
        let old_backing = self.backing.replace(backing);
        (self.resource, self.scanout) = (id, scanout);
        // The old resource is no longer scanned out. Unreferencing it
        // detaches its backing, which is freed only after that succeeds.
        let unref = |gpu: &mut Self| match old {
            0 => Ok(()),
            old => gpu.command_nodata(Cmd::new(CMD_RESOURCE_UNREF).u32(old).u32(0), &[]),
        };
        match unref(self) {
            Ok(()) => drop(old_backing),
            Err(e) => {
                core::mem::forget(old_backing);
                return Err(e);
            }
        }
        self.flush_all()?;
        Ok(info)
    }

    /// Switches the scanout off.
    pub fn disable(&mut self) -> Result<(), DisplayError> {
        if self.resource != 0 {
            self.command_nodata(Cmd::new(CMD_SET_SCANOUT).rect(Rect::default()).u32(self.scanout).u32(0), &[])?;
        }
        Ok(())
    }
}

impl<T: Transport, D: DmaAllocator + ?Sized> Display for VirtioGpu<'_, T, D> {
    /// The current framebuffer; 0 by 0 before [`VirtioGpu::set_mode`].
    fn framebuffer(&self) -> &Framebuffer {
        &self.fb
    }

    fn flush(&mut self, rect: Rect) -> Result<(), DisplayError> {
        let info = self.fb.info();
        let r = rect.intersect(&info.bounds());
        if r.is_empty() || self.resource == 0 {
            return Ok(());
        }
        let offset = r.y as u64 * info.stride as u64 + r.x as u64 * FORMAT.bytes_per_pixel() as u64;
        let id = self.resource;
        self.command_nodata(Cmd::new(CMD_TRANSFER_TO_HOST_2D).rect(r).u64(offset).u32(id).u32(0), &[])?;
        self.command_nodata(Cmd::new(CMD_RESOURCE_FLUSH).rect(r).u32(id).u32(0), &[])
    }
}

impl<T: Transport, D: DmaAllocator + ?Sized> Drop for VirtioGpu<'_, T, D> {
    fn drop(&mut self) {
        // Stop the device before freeing memory it may still read; if it
        // never stops, leak the memory instead.
        if reset(&self.transport) {
            // SAFETY: dropped once, here; the device is reset.
            unsafe {
                ManuallyDrop::drop(&mut self.queue);
                ManuallyDrop::drop(&mut self.req);
                ManuallyDrop::drop(&mut self.resp);
                ManuallyDrop::drop(&mut self.backing);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::virtio::queue::tests::DeviceSide;
    use crate::virtio::testing::{FakeTransport, HostDma};
    use crate::virtio::{feature, status};
    use core::sync::atomic::{AtomicBool, Ordering};
    use osmium_hal::display::Rgb;
    use osmium_hal::virtio::queue::DESC_F_WRITE;
    use std::collections::BTreeMap;
    use std::vec;
    use std::vec::Vec;

    fn mem(addr: u64, len: usize) -> &'static mut [u8] {
        // SAFETY: test DMA memory is identity-mapped and outlives the call.
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) }
    }

    fn le(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }

    /// A 2D resource on the fake host.
    #[derive(Default)]
    struct Resource {
        width: u32,
        height: u32,
        backing: Option<(u64, u32)>,
        pixels: Vec<u32>,
    }

    /// The fake host: resources, what each scanout shows, and the commands
    /// it saw.
    #[derive(Default)]
    struct Host {
        resources: BTreeMap<u32, Resource>,
        scanout: Option<(u32, Rect)>,
        flushed: Vec<Rect>,
        log: Vec<u32>,
    }

    impl Host {
        fn handle(&mut self, req: &[u8]) -> (u32, Vec<u8>) {
            let ty = le(req, 0);
            self.log.push(ty);
            let w = |n: usize| le(req, HDR_LEN + 4 * n);
            let rect = || Rect::new(w(0), w(1), w(2), w(3));
            let ok = (RESP_OK_NODATA, vec![]);
            let invalid = (RESP_ERR_INVALID_RESOURCE_ID, vec![]);
            match ty {
                CMD_GET_DISPLAY_INFO => {
                    let mut body = vec![0u8; MAX_SCANOUTS * DISPLAY_ONE_LEN];
                    for (i, v) in [0u32, 0, 1280, 800, 1, 0].into_iter().enumerate() {
                        body[4 * i..][..4].copy_from_slice(&v.to_le_bytes());
                    }
                    (RESP_OK_DISPLAY_INFO, body)
                }
                CMD_RESOURCE_CREATE_2D => {
                    assert_eq!(w(1), FORMAT_B8G8R8X8_UNORM);
                    let (width, height) = (w(2), w(3));
                    let r = Resource { width, height, backing: None, pixels: vec![0; (width * height) as usize] };
                    self.resources.insert(w(0), r);
                    ok
                }
                CMD_RESOURCE_ATTACH_BACKING => {
                    assert_eq!(w(1), 1, "one contiguous entry");
                    let Some(r) = self.resources.get_mut(&w(0)) else { return invalid };
                    let e = &req[RESOURCE_ATTACH_BACKING_LEN..];
                    r.backing = Some((u64::from_le_bytes(e[..8].try_into().unwrap()), le(e, 8)));
                    ok
                }
                CMD_SET_SCANOUT => {
                    if w(4) != 0 {
                        return (RESP_ERR_INVALID_SCANOUT_ID, vec![]);
                    }
                    if w(5) != 0 && !self.resources.contains_key(&w(5)) {
                        return invalid;
                    }
                    self.scanout = (w(5) != 0).then(|| (w(5), rect()));
                    ok
                }
                CMD_TRANSFER_TO_HOST_2D => {
                    let (r, offset, id) = (rect(), w(4) as u64 | (w(5) as u64) << 32, w(6));
                    let Some(res) = self.resources.get_mut(&id) else { return invalid };
                    let (addr, len) = res.backing.expect("transfer without backing");
                    let src = mem(addr, len as usize);
                    let stride = res.width as usize * 4;
                    assert_eq!(offset as usize, r.y as usize * stride + r.x as usize * 4);
                    for y in r.y..r.y + r.height {
                        for x in r.x..r.x + r.width {
                            let at = y as usize * stride + x as usize * 4;
                            res.pixels[(y * res.width + x) as usize] = le(src, at);
                        }
                    }
                    ok
                }
                CMD_RESOURCE_FLUSH => {
                    self.flushed.push(rect());
                    ok
                }
                CMD_RESOURCE_UNREF => {
                    if self.resources.remove(&w(0)).is_none() {
                        return invalid;
                    }
                    ok
                }
                _ => (RESP_ERR_UNSPEC, vec![]),
            }
        }
    }

    fn serve(mut dev: DeviceSide, host: &mut Host, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) {
            let Some((head, chain)) = dev.pop_avail() else {
                std::thread::yield_now();
                continue;
            };
            assert_eq!(chain.len(), 2);
            assert_eq!(chain[0].2 & DESC_F_WRITE, 0, "request is device-readable");
            assert_eq!(chain[1].2 & DESC_F_WRITE, DESC_F_WRITE, "response is device-writable");
            let (ty, body) = host.handle(mem(chain[0].0, chain[0].1 as usize));
            let resp = mem(chain[1].0, chain[1].1 as usize);
            assert!(resp.len() >= HDR_LEN + body.len());
            resp[..HDR_LEN].fill(0);
            resp[..4].copy_from_slice(&ty.to_le_bytes());
            resp[HDR_LEN..HDR_LEN + body.len()].copy_from_slice(&body);
            dev.push_used(head, (HDR_LEN + body.len()) as u32);
        }
    }

    fn device() -> FakeTransport {
        let mut config = vec![0u8; 16];
        config[CONFIG_NUM_SCANOUTS] = 1;
        FakeTransport::new(DeviceType::Gpu, feature::VERSION_1 | F_EDID, &config)
    }

    fn with_host(body: impl FnOnce(&mut VirtioGpu<'_, FakeTransport, HostDma>)) -> Host {
        let dma = HostDma::default();
        let mut gpu = VirtioGpu::new(device(), &dma).unwrap();
        let (size, addrs) = gpu.transport().queue(CONTROL_QUEUE);
        let stop = AtomicBool::new(false);
        let mut host = Host::default();
        std::thread::scope(|s| {
            let server = s.spawn(|| serve(DeviceSide::new(size, addrs), &mut host, &stop));
            // Stop the device even if `body` panics, so the scope can end.
            struct Stop<'flag>(&'flag AtomicBool);
            impl Drop for Stop<'_> {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let guard = Stop(&stop);
            body(&mut gpu);
            drop(guard);
            server.join().unwrap();
        });
        drop(gpu);
        assert_eq!(dma.live.get(), 0, "everything freed");
        host
    }

    #[test]
    fn init() {
        let dma = HostDma::default();
        let gpu = VirtioGpu::new(device(), &dma).unwrap();
        let t = gpu.transport();
        assert_eq!(t.status() & status::DRIVER_OK, status::DRIVER_OK);
        assert_eq!(t.accepted.get(), feature::VERSION_1, "no optional features taken");
        assert_eq!(t.queue(CONTROL_QUEUE).0, MAX_QUEUE_SIZE);
        assert_eq!(gpu.num_scanouts(), 1);
        assert_eq!(gpu.info().width, 0, "no mode yet");
        drop(gpu);
        let blk = FakeTransport::new(DeviceType::Block, 0, &[0; 16]);
        assert_eq!(VirtioGpu::new(blk, &dma).err(), Some(VirtioError::WrongDevice));
        assert_eq!(dma.live.get(), 0);
    }

    #[test]
    fn mode_draw_flush() {
        let host = with_host(|gpu| {
            let info = gpu.display_info().unwrap();
            assert_eq!(info.count, 1);
            assert_eq!(info.first_enabled(), Some((0, Rect::new(0, 0, 1280, 800))));
            assert_eq!(gpu.set_mode(1, 64, 48), Err(DisplayError::Unsupported), "no such scanout");

            let fb = gpu.set_mode(0, 64, 48).unwrap();
            assert_eq!((fb.width, fb.height, fb.stride), (64, 48, 256));
            gpu.framebuffer().fill_rect(Rect::new(10, 10, 4, 4), Rgb::new(0xff, 0, 0));
            gpu.flush(Rect::new(8, 8, 100, 4)).unwrap();
            gpu.flush(Rect::new(64, 0, 1, 1)).unwrap();

            // A second mode replaces the first resource.
            gpu.set_mode(0, 32, 32).unwrap();
            gpu.framebuffer().set_pixel(31, 31, Rgb::WHITE);
            gpu.flush_all().unwrap();
        });
        assert_eq!(host.resources.len(), 1, "the first resource was unreferenced");
        let res = &host.resources[&2];
        assert_eq!((res.width, res.height), (32, 32));
        assert_eq!(res.pixels[31 * 32 + 31], 0x00ff_ffff);
        assert_eq!(host.scanout, Some((2, Rect::new(0, 0, 32, 32))));
        assert_eq!(
            host.flushed,
            [Rect::new(0, 0, 64, 48), Rect::new(8, 8, 56, 4), Rect::new(0, 0, 32, 32), Rect::new(0, 0, 32, 32)],
            "clipped, and the empty flush never reached the device"
        );
        let creates = host.log.iter().filter(|&&c| c == CMD_RESOURCE_CREATE_2D).count();
        assert_eq!(creates, 2);
    }

    #[test]
    fn transfer_copies_the_rectangle() {
        let host = with_host(|gpu| {
            gpu.set_mode(0, 16, 16).unwrap();
            gpu.framebuffer().fill_rect(Rect::new(0, 0, 16, 16), Rgb::new(0, 0xff, 0));
            gpu.flush(Rect::new(4, 4, 2, 2)).unwrap();
        });
        let px = &host.resources[&1].pixels;
        let green: Vec<_> = (0..256).filter(|&i| px[i] == 0xff00).map(|i| (i % 16, i / 16)).collect();
        assert_eq!(green, [(4, 4), (5, 4), (4, 5), (5, 5)]);
    }

    #[test]
    fn silent_device_fails_instead_of_hanging() {
        let dma = HostDma::default();
        let mut gpu = VirtioGpu::new(device(), &dma).unwrap();
        assert_eq!(gpu.display_info(), Err(DisplayError::Device));
        drop(gpu);
        assert_eq!(dma.live.get(), 0, "reset acknowledged, so everything freed");
    }

    #[test]
    fn failed_mode_leaves_the_old_one() {
        with_host(|gpu| {
            gpu.set_mode(0, 8, 8).unwrap();
            gpu.num_scanouts = 2;
            assert_eq!(gpu.set_mode(1, 4, 4), Err(DisplayError::Unsupported));
            assert_eq!(gpu.info().width, 8);
            gpu.flush_all().unwrap();
            gpu.disable().unwrap();
        });
    }
}
