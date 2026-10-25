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
//! works until the first `SET_SCANOUT` (see [`crate::bochs`]).
//! Commands are synchronous, like the block driver's requests: one is in
//! flight at a time and the driver polls for its response.
//!
//! Beyond the 2D path the driver offers:
//!
//! - a hardware cursor on the cursor queue ([`VirtioGpu::set_cursor`],
//!   [`VirtioGpu::move_cursor`], [`VirtioGpu::hide_cursor`]): a 64 by 64
//!   ARGB image the host composites, so moving it costs one small
//!   fire-and-forget command and no framebuffer redraw;
//! - the monitor's EDID (`VIRTIO_GPU_F_EDID`, [`VirtioGpu::edid`]), parsed by
//!   [`crate::edid`];
//! - interrupts ([`VirtioGpu::enable_interrupts`] and
//!   [`VirtioGpu::handle_interrupt`]). Cursor commands complete
//!   asynchronously and the interrupt handler reaps them; it also notes a
//!   display change (the configuration-change interrupt). Control commands
//!   are still waited for by polling, which works with interrupts on or
//!   off: a caller holding the driver in an `IrqSpinLock` has the interrupt
//!   held off until the command is done.

use osmium_hal::display::{Display, DisplayError, Framebuffer, FramebufferInfo, PixelFormat, Rect};
use osmium_hal::dma::{DmaAllocator, OwnedDma};
use osmium_hal::mmio::IoMem;
use osmium_hal::virtio::gpu::*;
use osmium_mm::PhysAddr;

use core::mem::ManuallyDrop;
use osmium_drivers::virtio::queue::{Segment, VirtQueue};

use crate::edid::{Edid, EdidError};
use core::sync::atomic::{AtomicU32, Ordering};
use osmium_drivers::virtio::{DeviceType, POLL_LIMIT, Transport, VirtioError, driver_ok, negotiate, reset};

/// Entries used in the control queue, at most (a command needs two).
pub const MAX_QUEUE_SIZE: u16 = 4;

/// Bytes of the request and response buffers.
const CMD_LEN: usize = 4096;

/// Entries used in the cursor queue, at most.
pub const MAX_CURSOR_QUEUE_SIZE: u16 = 4;

/// Bytes of each cursor request slot (a command is [`CURSOR_CMD_LEN`]).
const CURSOR_SLOT: usize = 64;

/// Bytes of a cursor image: [`CURSOR_SIDE`] squared ARGB pixels.
pub const CURSOR_BYTES: usize = (CURSOR_SIDE * CURSOR_SIDE) as usize * 4;

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
        self.scanouts.iter().take(self.count).enumerate().find(|(_, s)| s.enabled).map(|(i, s)| (i as u32, s.rect))
    }
}

/// Why [`VirtioGpu::edid`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdidFetchError {
    /// The device did not offer `VIRTIO_GPU_F_EDID`, or has no such scanout.
    Unsupported,
    /// The command failed.
    Device,
    /// The device answered with an EDID that does not parse.
    Invalid(EdidError),
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
    // Resource IDs handed out so far (modes and cursor images share them).
    last_id: u32,
    edid: bool,
    cursor: Option<Cursor<'d, D>>,
    irqs: AtomicU32,
    config_changed: bool,
}

/// The cursor queue, its request slots and the current cursor image.
struct Cursor<'d, D: DmaAllocator + ?Sized> {
    queue: ManuallyDrop<VirtQueue<'d, D>>,
    // One `CURSOR_SLOT` per descriptor: a request lives in the slot of its head.
    slots: ManuallyDrop<OwnedDma<'d, D>>,
    // The image's resource (0 for none), its memory, and where it shows.
    resource: u32,
    backing: ManuallyDrop<Option<OwnedDma<'d, D>>>,
    pos: (u32, u32),
    hot: (u32, u32),
    visible: bool,
}

/// Little-endian request builder.
struct Cmd {
    buf: [u8; 64],
    len: usize,
}

impl Cmd {
    fn new(ty: u32) -> Self {
        let mut c = Self { buf: [0; 64], len: HDR_LEN };
        if let Some(dst) = c.buf.first_chunk_mut::<4>() {
            *dst = ty.to_le_bytes();
        }
        c
    }

    fn u32(mut self, v: u32) -> Self {
        // Every command is built from fixed fields that fit the buffer; an
        // overlong one would be truncated, not overrun.
        if let Some(dst) = self.buf.get_mut(self.len..).and_then(|b| b.first_chunk_mut::<4>()) {
            *dst = v.to_le_bytes();
            self.len += 4;
        }
        self
    }

    /// The bytes built so far.
    fn bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
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
        let features = negotiate(&transport, 0, F_EDID)?;
        let size = match transport.max_queue_size(CONTROL_QUEUE).min(MAX_QUEUE_SIZE) {
            // Split queues come in powers of two.
            n if n >= 2 => 1 << n.ilog2(),
            _ => return Err(VirtioError::BadQueue),
        };
        let num_scanouts =
            u32::from_le_bytes(core::array::from_fn(|i| transport.config_read8(CONFIG_NUM_SCANOUTS + i)));
        // Plain values until all succeed, so a failure frees the others.
        let queue = VirtQueue::new(dma, CONTROL_QUEUE, size)?;
        // The cursor queue is optional: without it there is no hardware cursor.
        let cursor = match transport.max_queue_size(CURSOR_QUEUE).min(MAX_CURSOR_QUEUE_SIZE) {
            n if n >= 2 => {
                let size = 1 << n.ilog2();
                let queue = VirtQueue::new(dma, CURSOR_QUEUE, size)?;
                let slots = OwnedDma::new(dma, CURSOR_SLOT * size as usize).ok_or(VirtioError::NoMemory)?;
                Some(Cursor {
                    queue: ManuallyDrop::new(queue),
                    slots: ManuallyDrop::new(slots),
                    resource: 0,
                    backing: ManuallyDrop::new(None),
                    pos: (0, 0),
                    hot: (0, 0),
                    visible: false,
                })
            }
            _ => None,
        };
        let req = OwnedDma::new(dma, CMD_LEN).ok_or(VirtioError::NoMemory)?;
        let resp = OwnedDma::new(dma, CMD_LEN).ok_or(VirtioError::NoMemory)?;
        // SAFETY: an empty window touches no memory.
        let empty = unsafe { IoMem::new(core::ptr::NonNull::<u32>::dangling().as_ptr().cast(), 0) };
        let fb = Framebuffer::new(empty, FramebufferInfo::packed(0, 0, FORMAT)).map_err(|_| VirtioError::NoMemory)?;
        let gpu = Self {
            queue: ManuallyDrop::new(queue),
            req: ManuallyDrop::new(req),
            resp: ManuallyDrop::new(resp),
            num_scanouts: num_scanouts.min(MAX_SCANOUTS as u32),
            fb,
            backing: ManuallyDrop::new(None),
            resource: 0,
            scanout: 0,
            last_id: 0,
            edid: features & F_EDID != 0,
            cursor,
            irqs: AtomicU32::new(0),
            config_changed: false,
            dma,
            transport,
        };
        gpu.transport.setup_queue(CONTROL_QUEUE, size, gpu.queue.addrs());
        if let Some(c) = &gpu.cursor {
            gpu.transport.setup_queue(CURSOR_QUEUE, c.queue.size(), c.queue.addrs());
            c.queue.set_interrupts(false);
        }
        // Responses are polled until `enable_interrupts`.
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

    /// True if the device offers `GET_EDID`.
    pub fn has_edid(&self) -> bool {
        self.edid
    }

    /// True if the device has a cursor queue.
    pub fn has_cursor(&self) -> bool {
        self.cursor.is_some()
    }

    /// Asks the device to interrupt when it completes commands. Call this
    /// after routing the device's interrupt to [`VirtioGpu::handle_interrupt`].
    /// Polling for control responses still works.
    pub fn enable_interrupts(&mut self) {
        self.queue.set_interrupts(true);
        if let Some(c) = &self.cursor {
            c.queue.set_interrupts(true);
        }
    }

    /// Goes back to polling: the device is asked not to interrupt.
    pub fn disable_interrupts(&mut self) {
        self.queue.set_interrupts(false);
        if let Some(c) = &self.cursor {
            c.queue.set_interrupts(false);
        }
    }

    /// Handles the device's interrupt: acknowledges it, reaps finished
    /// cursor commands and notes a display configuration change. Returns
    /// true if the interrupt was this device's.
    pub fn handle_interrupt(&mut self) -> bool {
        let isr = self.transport.ack_interrupt();
        if isr == 0 {
            return false;
        }
        self.irqs.fetch_add(1, Ordering::Relaxed);
        if let Some(c) = &mut self.cursor {
            while c.queue.pop_used().is_some() {}
        }
        if isr & u32::from(osmium_hal::virtio::pci::ISR_CONFIG) != 0 {
            self.config_changed = true;
        }
        true
    }

    /// How many interrupts [`VirtioGpu::handle_interrupt`] has taken as the
    /// device's.
    pub fn interrupts_handled(&self) -> u32 {
        self.irqs.load(Ordering::Relaxed)
    }

    /// True once if the host reported a display change (new size, a monitor
    /// plugged in) since the last call. Fetch [`VirtioGpu::display_info`]
    /// and [`VirtioGpu::edid`] to see what changed.
    pub fn take_display_changed(&mut self) -> bool {
        core::mem::take(&mut self.config_changed)
    }

    fn next_id(&mut self) -> u32 {
        self.last_id = self.last_id.wrapping_add(1).max(1);
        self.last_id
    }

    /// Fetches and parses the EDID of `scanout`'s monitor.
    pub fn edid(&mut self, scanout: u32) -> Result<Edid, EdidFetchError> {
        if !self.edid || scanout >= self.num_scanouts {
            return Err(EdidFetchError::Unsupported);
        }
        let cmd = Cmd::new(CMD_GET_EDID).u32(scanout).u32(0);
        let (ty, written) = self.command(cmd, &[], RESP_EDID_LEN).map_err(|_| EdidFetchError::Device)?;
        if ty != RESP_OK_EDID || written < HDR_LEN + 8 {
            return Err(EdidFetchError::Device);
        }
        // The device says how many bytes it wrote; it may lie. Take no more
        // than it wrote, than a buffer holds, and than it claims is EDID.
        let claimed = self.resp.load::<u32>(HDR_LEN) as usize;
        let len = claimed.min(EDID_MAX).min(written - HDR_LEN - 8);
        let mut buf = [0u8; EDID_MAX];
        if let Some(dst) = buf.get_mut(..len) {
            self.resp.read(HDR_LEN + 8, dst);
        }
        Edid::parse(buf.get(..len).unwrap_or(&[])).map_err(EdidFetchError::Invalid)
    }

    /// Sends the request built in `cmd` (with `extra` bytes appended) and
    /// waits for a response of up to `resp_len` bytes; returns its type and
    /// how many bytes the device says it wrote.
    fn command(&mut self, cmd: Cmd, extra: &[u8], resp_len: usize) -> Result<(u32, usize), DisplayError> {
        self.req.write(0, cmd.bytes());
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

        let id = self.next_id();
        let full = info.bounds();
        self.command_nodata(
            Cmd::new(CMD_RESOURCE_CREATE_2D).u32(id).u32(FORMAT_B8G8R8X8_UNORM).u32(width).u32(height),
            &[],
        )?;
        let mut entry = [0u8; MEM_ENTRY_LEN];
        let (addr, len) = (backing.device_addr().as_u64().to_le_bytes(), (info.size() as u32).to_le_bytes());
        for (dst, src) in entry.iter_mut().zip(addr.iter().chain(len.iter())) {
            *dst = *src;
        }
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
        // detaches its backing, which is freed only after that succeeds. If
        // it fails the host may still hold the backing, so it is leaked; the
        // new mode is already live, so that is not an error of this call.
        let unref = |gpu: &mut Self| match old {
            0 => Ok(()),
            old => gpu.command_nodata(Cmd::new(CMD_RESOURCE_UNREF).u32(old).u32(0), &[]),
        };
        match unref(self) {
            Ok(()) => drop(old_backing),
            Err(_) => core::mem::forget(old_backing),
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

    /// Queues one cursor command on the cursor queue; it has no response.
    /// Finished commands are reaped here and by [`VirtioGpu::handle_interrupt`].
    fn cursor_command(&mut self, ty: u32) -> Result<(), DisplayError> {
        let scanout = self.scanout;
        let notify = {
            let c = self.cursor.as_mut().ok_or(DisplayError::Unsupported)?;
            while c.queue.pop_used().is_some() {}
            if c.queue.is_broken() {
                return Err(DisplayError::Device);
            }
            // A full ring: wait for the device to take one.
            if c.queue.next_head().is_none() {
                c.queue.wait_used(POLL_LIMIT).ok_or(DisplayError::Device)?;
            }
            let head = c.queue.next_head().ok_or(DisplayError::Device)?;
            let (id, visible) = (c.resource, c.visible);
            let cmd = Cmd::new(ty)
                .u32(scanout)
                .u32(c.pos.0)
                .u32(c.pos.1)
                .u32(0)
                // Hidden means no image.
                .u32(if visible { id } else { 0 })
                .u32(c.hot.0)
                .u32(c.hot.1)
                .u32(0);
            c.slots.write(usize::from(head) * CURSOR_SLOT, cmd.bytes());
            let seg = Segment {
                addr: PhysAddr::new(c.slots.device_addr().as_u64() + usize::from(head) as u64 * CURSOR_SLOT as u64),
                len: cmd.len as u32,
                device_writes: false,
            };
            c.queue.add(&[seg]).map_err(|_| DisplayError::Device)?;
            c.queue.needs_notify()
        };
        if notify {
            self.transport.notify(CURSOR_QUEUE);
        }
        Ok(())
    }

    /// Sets the cursor image to `argb`, [`CURSOR_SIDE`] by [`CURSOR_SIDE`]
    /// pixels of `0xAARRGGBB`, row by row, with the hot spot (the pixel that
    /// sits on the pointer position) at `(hot_x, hot_y)`, and shows it at
    /// its current position. The previous image is released.
    pub fn set_cursor(&mut self, argb: &[u32], hot_x: u32, hot_y: u32) -> Result<(), DisplayError> {
        if self.cursor.is_none() || argb.len() != (CURSOR_SIDE * CURSOR_SIDE) as usize {
            return Err(DisplayError::Unsupported);
        }
        if hot_x >= CURSOR_SIDE || hot_y >= CURSOR_SIDE {
            return Err(DisplayError::Unsupported);
        }
        let backing = OwnedDma::new(self.dma, CURSOR_BYTES).ok_or(DisplayError::NoMemory)?;
        for (i, px) in argb.iter().enumerate() {
            backing.write(i * 4, &px.to_le_bytes());
        }
        let id = self.next_id();
        self.command_nodata(
            Cmd::new(CMD_RESOURCE_CREATE_2D).u32(id).u32(FORMAT_B8G8R8A8_UNORM).u32(CURSOR_SIDE).u32(CURSOR_SIDE),
            &[],
        )?;
        let mut entry = [0u8; MEM_ENTRY_LEN];
        let (addr, len) = (backing.device_addr().as_u64().to_le_bytes(), (CURSOR_BYTES as u32).to_le_bytes());
        for (dst, src) in entry.iter_mut().zip(addr.iter().chain(len.iter())) {
            *dst = *src;
        }
        let full = Rect::new(0, 0, CURSOR_SIDE, CURSOR_SIDE);
        let ready = self.command_nodata(Cmd::new(CMD_RESOURCE_ATTACH_BACKING).u32(id).u32(1), &entry).and_then(|()| {
            self.command_nodata(Cmd::new(CMD_TRANSFER_TO_HOST_2D).rect(full).u64(0).u32(id).u32(0), &[])
        });
        if let Err(e) = ready {
            // As in `set_mode`: if the host may still hold the backing, leak it.
            if self.command_nodata(Cmd::new(CMD_RESOURCE_UNREF).u32(id).u32(0), &[]).is_err() {
                core::mem::forget(backing);
            }
            return Err(e);
        }
        let Some(c) = self.cursor.as_mut() else { return Err(DisplayError::Unsupported) };
        let old = core::mem::replace(&mut c.resource, id);
        let old_backing = c.backing.replace(backing);
        (c.hot, c.visible) = ((hot_x, hot_y), true);
        let shown = self.cursor_command(CMD_UPDATE_CURSOR);
        // The host no longer uses the old image once the update is done;
        // unreferencing detaches its backing, which is freed only if that
        // worked.
        if old != 0 {
            match self.command_nodata(Cmd::new(CMD_RESOURCE_UNREF).u32(old).u32(0), &[]) {
                Ok(()) => drop(old_backing),
                Err(_) => core::mem::forget(old_backing),
            }
        }
        shown
    }

    /// Moves the cursor to `(x, y)` on the scanout. Fire and forget: the
    /// command completes asynchronously.
    pub fn move_cursor(&mut self, x: u32, y: u32) -> Result<(), DisplayError> {
        let c = self.cursor.as_mut().ok_or(DisplayError::Unsupported)?;
        c.pos = (x, y);
        self.cursor_command(CMD_MOVE_CURSOR)
    }

    /// Hides the cursor; [`VirtioGpu::move_cursor`] does not show it again,
    /// [`VirtioGpu::show_cursor`] does.
    pub fn hide_cursor(&mut self) -> Result<(), DisplayError> {
        let c = self.cursor.as_mut().ok_or(DisplayError::Unsupported)?;
        c.visible = false;
        self.cursor_command(CMD_UPDATE_CURSOR)
    }

    /// Shows the cursor image again after [`VirtioGpu::hide_cursor`].
    pub fn show_cursor(&mut self) -> Result<(), DisplayError> {
        let c = self.cursor.as_mut().ok_or(DisplayError::Unsupported)?;
        if c.resource == 0 {
            return Err(DisplayError::Unsupported);
        }
        c.visible = true;
        self.cursor_command(CMD_UPDATE_CURSOR)
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
                if let Some(c) = &mut self.cursor {
                    ManuallyDrop::drop(&mut c.queue);
                    ManuallyDrop::drop(&mut c.slots);
                    ManuallyDrop::drop(&mut c.backing);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicBool, Ordering};
    use osmium_drivers::virtio::queue::tests::DeviceSide;
    use osmium_drivers::virtio::testing::{FakeTransport, HostDma};
    use osmium_drivers::virtio::{feature, status};
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
        /// Fails the unreference of this resource.
        fail_unref: Option<u32>,
        /// The EDID `GET_EDID` returns, and the size it claims for it.
        edid: Vec<u8>,
        edid_claim: u32,
        /// Cursor commands seen: (type, scanout, x, y, resource, hot_x, hot_y).
        cursor: Vec<(u32, u32, u32, u32, u32, u32, u32)>,
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
                CMD_GET_EDID => {
                    if w(0) != 0 {
                        return (RESP_ERR_INVALID_SCANOUT_ID, vec![]);
                    }
                    let mut body = self.edid_claim.to_le_bytes().to_vec();
                    body.extend_from_slice(&[0; 4]);
                    body.extend_from_slice(&self.edid);
                    (RESP_OK_EDID, body)
                }
                CMD_RESOURCE_CREATE_2D => {
                    assert!(w(1) == FORMAT_B8G8R8X8_UNORM || w(1) == FORMAT_B8G8R8A8_UNORM);
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
                    if self.fail_unref == Some(w(0)) {
                        return (RESP_ERR_UNSPEC, vec![]);
                    }
                    if self.resources.remove(&w(0)).is_none() {
                        return invalid;
                    }
                    ok
                }
                _ => (RESP_ERR_UNSPEC, vec![]),
            }
        }
    }

    fn serve(mut dev: DeviceSide, mut cursor: DeviceSide, host: &mut Host, stop: &AtomicBool) {
        while !stop.load(Ordering::Acquire) {
            if let Some((head, chain)) = cursor.pop_avail() {
                assert_eq!(chain.len(), 1, "cursor commands have no response");
                assert_eq!(chain[0].2 & DESC_F_WRITE, 0);
                assert_eq!(chain[0].1 as usize, CURSOR_CMD_LEN);
                let req = mem(chain[0].0, chain[0].1 as usize);
                let w = |n: usize| le(req, HDR_LEN + 4 * n);
                assert_eq!(w(3), 0);
                host.cursor.push((le(req, 0), w(0), w(1), w(2), w(4), w(5), w(6)));
                cursor.push_used(head, 0);
            }
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
        let (host, live) = run_host(Host::default(), body);
        assert_eq!(live, 0, "everything freed");
        host
    }

    /// Runs `body` against `host`; returns it and how many DMA buffers are still live.
    fn run_host(mut host: Host, body: impl FnOnce(&mut VirtioGpu<'_, FakeTransport, HostDma>)) -> (Host, usize) {
        let dma = HostDma::default();
        let mut gpu = VirtioGpu::new(device(), &dma).unwrap();
        let (size, addrs) = gpu.transport().queue(CONTROL_QUEUE);
        let (csize, caddrs) = gpu.transport().queue(CURSOR_QUEUE);
        let stop = AtomicBool::new(false);
        std::thread::scope(|s| {
            let server =
                s.spawn(|| serve(DeviceSide::new(size, addrs), DeviceSide::new(csize, caddrs), &mut host, &stop));
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
        (host, dma.live.get())
    }

    #[test]
    fn init() {
        let dma = HostDma::default();
        let gpu = VirtioGpu::new(device(), &dma).unwrap();
        let t = gpu.transport();
        assert_eq!(t.status() & status::DRIVER_OK, status::DRIVER_OK);
        assert_eq!(t.accepted.get(), feature::VERSION_1 | F_EDID, "only EDID taken");
        assert_eq!(t.queue(CURSOR_QUEUE).0, MAX_CURSOR_QUEUE_SIZE);
        assert!(gpu.has_edid() && gpu.has_cursor());
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
        assert!(gpu.queue.is_broken());
        let in_flight = gpu.queue.in_flight();
        assert_eq!(gpu.display_info(), Err(DisplayError::Device));
        assert_eq!(gpu.queue.in_flight(), in_flight, "nothing new was queued");
        drop(gpu);
        assert_eq!(dma.live.get(), 0, "reset acknowledged, so everything freed");
    }

    #[test]
    fn failed_unref_of_the_old_mode_still_switches() {
        let host = Host { fail_unref: Some(1), ..Host::default() };
        let (host, live) = run_host(host, |gpu| {
            gpu.set_mode(0, 8, 8).unwrap();
            // The old resource cannot be released: the new mode is live regardless.
            assert_eq!(gpu.set_mode(0, 16, 16).unwrap().width, 16);
            assert_eq!(gpu.info().width, 16);
        });
        assert_eq!(host.scanout.map(|(id, _)| id), Some(2));
        assert_eq!(live, 1, "the old backing is leaked, not freed under the host");
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

    fn host_with_edid() -> Host {
        let edid = crate::edid::tests::sample().to_vec();
        Host { edid_claim: edid.len() as u32, edid, ..Host::default() }
    }

    #[test]
    fn edid_is_fetched_and_parsed() {
        let (_, live) = run_host(host_with_edid(), |gpu| {
            let e = gpu.edid(0).unwrap();
            assert_eq!(e.preferred_size(), Some((1920, 1080)));
            assert_eq!(e.size_mm(), Some((527, 296)));
            assert_eq!(gpu.edid(1), Err(EdidFetchError::Unsupported), "no such scanout");
        });
        assert_eq!(live, 0);
    }

    #[test]
    fn hostile_edid_is_rejected() {
        let mut host = host_with_edid();
        host.edid[100] ^= 0xff;
        run_host(host, |gpu| {
            assert_eq!(gpu.edid(0), Err(EdidFetchError::Invalid(EdidError::BadChecksum)));
        });
        // Claims more than it sent, and more than the protocol allows.
        for claim in [u32::MAX, 5000, 64] {
            let host = Host { edid_claim: claim, ..host_with_edid() };
            run_host(host, |gpu| {
                let r = gpu.edid(0);
                if claim == 64 {
                    assert_eq!(r, Err(EdidFetchError::Invalid(EdidError::TooShort)));
                } else {
                    assert!(r.is_ok(), "clamped to what was sent");
                }
            });
        }
        // A device that did not offer EDID.
        let dma = HostDma::default();
        let mut t = device();
        t.offered &= !F_EDID;
        let mut gpu = VirtioGpu::new(t, &dma).unwrap();
        assert!(!gpu.has_edid());
        assert_eq!(gpu.edid(0), Err(EdidFetchError::Unsupported));
    }

    #[test]
    fn cursor_image_move_hide() {
        let mut image = std::vec![0u32; 64 * 64];
        image[65] = 0x80ff_0000;
        let (host, live) = run_host(Host::default(), |gpu| {
            assert_eq!(gpu.set_cursor(&image[..10], 0, 0), Err(DisplayError::Unsupported), "wrong size");
            assert_eq!(gpu.set_cursor(&image, 64, 0), Err(DisplayError::Unsupported), "hot spot outside");
            gpu.set_mode(0, 32, 32).unwrap();
            gpu.move_cursor(5, 6).unwrap();
            gpu.set_cursor(&image, 2, 3).unwrap();
            gpu.move_cursor(10, 20).unwrap();
            gpu.hide_cursor().unwrap();
            gpu.move_cursor(11, 21).unwrap();
            gpu.show_cursor().unwrap();
            // More commands than the ring holds: completions are reaped.
            for i in 0..20 {
                gpu.move_cursor(i, i).unwrap();
            }
            // A new image replaces and releases the old one.
            gpu.set_cursor(&image, 0, 0).unwrap();
            assert!(gpu.cursor.as_ref().unwrap().queue.in_flight() <= MAX_CURSOR_QUEUE_SIZE);
            // Let the fake device finish before the test body ends.
            while gpu.cursor.as_ref().unwrap().queue.in_flight() > 0 {
                gpu.handle_interrupt();
                std::thread::yield_now();
            }
        });
        assert_eq!(live, 0);
        let c = &host.cursor;
        // Resource 1 is the mode, 2 the first cursor image, 3 the second.
        assert_eq!(c[0], (CMD_MOVE_CURSOR, 0, 5, 6, 0, 0, 0), "no image yet");
        assert_eq!(c[1], (CMD_UPDATE_CURSOR, 0, 5, 6, 2, 2, 3));
        assert_eq!(c[2], (CMD_MOVE_CURSOR, 0, 10, 20, 2, 2, 3));
        assert_eq!(c[3], (CMD_UPDATE_CURSOR, 0, 10, 20, 0, 2, 3), "hidden: resource 0");
        assert_eq!(c[4].4, 0, "moving a hidden cursor keeps it hidden");
        assert_eq!(c[5], (CMD_UPDATE_CURSOR, 0, 11, 21, 2, 2, 3));
        assert_eq!(c.last().copied(), Some((CMD_UPDATE_CURSOR, 0, 19, 19, 3, 0, 0)));
        assert_eq!(host.resources.len(), 2, "mode and the new cursor image; the old one was unreferenced");
        let img = &host.resources[&3];
        assert_eq!((img.width, img.height), (64, 64));
        assert_eq!(img.pixels[65], 0x80ff_0000, "the image reached the host");
    }

    #[test]
    fn interrupts_ack_and_flag_display_changes() {
        let dma = HostDma::default();
        let mut gpu = VirtioGpu::new(device(), &dma).unwrap();
        assert!(!gpu.cursor.as_ref().unwrap().queue.has_used());
        gpu.enable_interrupts();
        // FakeTransport acknowledges queue interrupts only.
        assert!(gpu.handle_interrupt());
        assert_eq!(gpu.interrupts_handled(), 1);
        assert!(!gpu.take_display_changed());
        gpu.config_changed = true;
        assert!(gpu.take_display_changed());
        assert!(!gpu.take_display_changed(), "reported once");
        gpu.disable_interrupts();
    }

    #[test]
    fn no_cursor_queue_is_unsupported() {
        let dma = HostDma::default();
        let mut t = device();
        t.max_queue = 1;
        // A queue size of one is unusable for the control queue too.
        assert_eq!(VirtioGpu::new(t, &dma).err(), Some(VirtioError::BadQueue));
        let mut gpu = VirtioGpu::new(device(), &dma).unwrap();
        gpu.cursor = None;
        assert_eq!(gpu.move_cursor(0, 0), Err(DisplayError::Unsupported));
        assert_eq!(gpu.hide_cursor(), Err(DisplayError::Unsupported));
        assert_eq!(gpu.set_cursor(&[0; 4096], 0, 0), Err(DisplayError::Unsupported));
    }
}
