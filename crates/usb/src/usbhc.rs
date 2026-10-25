//! What the UHCI, OHCI and EHCI drivers share: the table of addressed
//! devices, the enumeration steps that need only control transfers, data
//! toggle bookkeeping and bounded waits.
//!
//! A controller implements [`Hc`], the handful of operations that differ
//! (reset a port, run a control transfer, run a bulk or interrupt transfer,
//! start one without waiting). The free functions here turn those into the
//! [`UsbHost`](osmium_hal::usb::UsbHost) methods, so the three drivers
//! agree on addressing, endpoint bookkeeping and error reporting.
//!
//! A device's [`DeviceId`] is its USB address, which is its table index plus
//! one.

use osmium_hal::dma::DmaBuffer;
use osmium_hal::timer::Clock;
use osmium_hal::usb::{
    DeviceId, EndpointDescriptor, PortStatus, Recipient, RequestKind, SetupPacket, Speed, TransferType, UsbError,
    descriptor_type, request,
};

/// Devices a controller addresses at once, hubs included.
pub const MAX_DEVICES: usize = 8;

/// Non-control endpoints configured per device.
pub const MAX_ENDPOINTS: usize = 8;

/// Transfers a controller can have started by `submit_in` at once.
pub const MAX_PENDING: usize = 4;

/// Largest transfer `submit_in` accepts (one page).
pub const MAX_SUBMIT_LEN: usize = 4096;

/// Size of the bounce buffer that synchronous transfers go through. Being
/// 16 KiB and page-aligned, it is made of whole pages for controllers that
/// take page lists.
pub const BOUNCE_LEN: usize = 16 * 1024;

/// How long a control transfer may take (USB 2.0 §9.2.6.1 allows five
/// seconds for a request to complete).
pub const CONTROL_TIMEOUT_NS: u64 = if cfg!(test) { 50_000_000 } else { 5_000_000_000 };

/// How long a bulk or interrupt transfer may keep being NAKed.
pub const BULK_TIMEOUT_NS: u64 = if cfg!(test) { 50_000_000 } else { 5_000_000_000 };

/// Time a device gets to recover after the reset of a hub port.
const RESET_RECOVERY_NS: u64 = 10_000_000;

/// Time a device gets to settle after `SET_ADDRESS` (USB 2.0 §9.2.6.3).
const SET_ADDRESS_RECOVERY_NS: u64 = 10_000_000;

/// One non-control endpoint of an addressed device.
#[derive(Clone, Copy, Debug)]
pub struct Ep {
    /// Endpoint address, direction bit included.
    pub address: u8,
    /// Its transfer type (bulk or interrupt).
    pub ttype: TransferType,
    /// Maximum packet size in bytes.
    pub mps: u16,
    /// The DATA0/DATA1 value the next packet carries.
    pub toggle: bool,
    /// The slot of a transfer started by `submit_in`.
    pub pending: Option<usize>,
    /// The length that transfer was started with.
    pub pending_len: usize,
}

/// An addressed device.
#[derive(Clone, Copy, Debug)]
pub struct Dev {
    /// Its speed.
    pub speed: Speed,
    /// Endpoint 0's maximum packet size.
    pub mps0: u16,
    /// The hub it hangs off, if not on a root port.
    pub parent: Option<u8>,
    /// Its configured endpoints.
    pub eps: [Option<Ep>; MAX_ENDPOINTS],
}

/// The addressed devices of one controller.
#[derive(Debug)]
pub struct DevTable {
    devs: [Option<Dev>; MAX_DEVICES],
}

impl DevTable {
    /// An empty table.
    pub const fn new() -> Self {
        Self { devs: [None; MAX_DEVICES] }
    }

    /// The device with USB address `address`.
    pub fn get(&mut self, address: u8) -> Option<&mut Dev> {
        self.devs.get_mut((address as usize).checked_sub(1)?)?.as_mut()
    }

    fn insert(&mut self, dev: Dev) -> Option<u8> {
        let i = self.devs.iter().position(Option::is_none)?;
        *self.devs.get_mut(i)? = Some(dev);
        Some(i as u8 + 1)
    }

    fn remove(&mut self, address: u8) {
        if let Some(slot) = self.devs.get_mut((address as usize).wrapping_sub(1)) {
            *slot = None;
        }
    }

    /// The addresses of the devices plugged into hub `hub`.
    fn children(&self, hub: u8) -> impl Iterator<Item = u8> + '_ {
        self.devs
            .iter()
            .enumerate()
            .filter(move |(_, d)| d.is_some_and(|d| d.parent == Some(hub)))
            .map(|(i, _)| i as u8 + 1)
    }
}

impl Default for DevTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a transfer goes.
#[derive(Clone, Copy, Debug)]
pub struct Pipe {
    /// USB address, 0 before `SET_ADDRESS`.
    pub address: u8,
    /// Speed of the device.
    pub speed: Speed,
    /// Endpoint address, direction bit included (0 for the control pipe).
    pub endpoint: u8,
    /// Transfer type.
    pub ttype: TransferType,
    /// Maximum packet size.
    pub mps: u16,
}

/// The data stage of a transfer.
pub enum Data<'buf> {
    /// None.
    None,
    /// Device to host, into the buffer.
    In(&'buf mut [u8]),
    /// Host to device, from the buffer.
    Out(&'buf [u8]),
}

impl Data<'_> {
    /// Bytes the stage can move.
    pub fn len(&self) -> usize {
        match self {
            Data::None => 0,
            Data::In(b) => b.len(),
            Data::Out(b) => b.len(),
        }
    }
}

/// What a host controller provides to [`attach`] and the other functions
/// here.
pub trait Hc {
    /// The controller's device table.
    fn devices(&mut self) -> &mut DevTable;

    /// Its time source.
    fn clock(&self) -> &dyn Clock;

    /// Number of root-hub ports.
    fn root_ports(&self) -> u8;

    /// State of root port `port` (1-based).
    fn root_port_status(&self, port: u8) -> PortStatus;

    /// Resets root port `port` and returns the speed of the device on it,
    /// which is then ready to answer at address 0.
    fn reset_port(&mut self, port: u8) -> Result<Speed, UsbError>;

    /// Runs a control transfer on `pipe`, endpoint 0, and returns the bytes
    /// moved by the data stage.
    fn control(&mut self, pipe: &Pipe, setup: SetupPacket, data: Data<'_>) -> Result<usize, UsbError>;

    /// The most bytes one [`bulk_chunk`](Self::bulk_chunk) takes on `pipe`; a
    /// multiple of the packet size.
    fn chunk_max(&self, pipe: &Pipe) -> usize;

    /// Runs one piece (at most [`chunk_max`](Self::chunk_max) bytes) of a bulk
    /// or interrupt transfer starting at data toggle `toggle` and returns the
    /// bytes moved. An empty `Data::Out` sends one zero-length packet. An IN
    /// piece ends at a short packet, which may be a zero-length one.
    fn bulk_chunk(&mut self, pipe: &Pipe, toggle: bool, data: Data<'_>) -> Result<usize, UsbError>;

    /// Starts an IN transfer of up to `len` bytes and returns the slot to
    /// pass to [`poll`](Self::poll).
    fn submit(&mut self, pipe: &Pipe, toggle: bool, len: usize) -> Result<usize, UsbError>;

    /// Collects the transfer in `slot`: `None` while it runs, else its
    /// result, which frees the slot.
    fn poll(&mut self, slot: usize, buf: &mut [u8]) -> Option<Result<usize, UsbError>>;

    /// Abandons the transfer in `slot`.
    fn cancel(&mut self, slot: usize);
}

/// Packets a transfer of `len` bytes takes on an endpoint of `mps`: a
/// zero-length transfer is one empty packet.
pub fn packets(len: usize, mps: u16) -> usize {
    len.div_ceil(mps.max(1) as usize).max(1)
}

/// The data toggle after a transfer that started at `toggle`, asked for
/// `requested` bytes and moved `moved`. An IN transfer that stops short of
/// `requested` on a whole number of packets was ended by a zero-length packet,
/// which carries a toggle of its own.
pub fn toggle_after(toggle: bool, moved: usize, requested: usize, mps: u16) -> bool {
    let zlp = moved > 0 && moved < requested && moved.is_multiple_of(mps.max(1) as usize);
    toggle ^ ((packets(moved, mps) + zlp as usize) % 2 == 1)
}

/// Runs a bulk or interrupt transfer in pieces the controller takes. Returns
/// the bytes moved and the toggle the next packet carries.
pub fn bulk<H: Hc + ?Sized>(
    hc: &mut H,
    pipe: &Pipe,
    toggle: bool,
    mut data: Data<'_>,
) -> Result<(usize, bool), UsbError> {
    if pipe.mps == 0 {
        return Err(UsbError::BadEndpoint);
    }
    let total = data.len();
    let chunk_max = hc.chunk_max(pipe).max(1);
    let mut done = 0;
    let mut toggle = toggle;
    loop {
        let n = (total - done).min(chunk_max);
        let piece = match &mut data {
            Data::None => Data::None,
            Data::In(buf) => Data::In(buf.get_mut(done..done + n).ok_or(UsbError::BadEndpoint)?),
            Data::Out(buf) => Data::Out(buf.get(done..done + n).ok_or(UsbError::BadEndpoint)?),
        };
        let moved = hc.bulk_chunk(pipe, toggle, piece)?.min(n);
        done += moved;
        toggle = toggle_after(toggle, moved, n, pipe.mps);
        // A short packet ends an IN transfer; an empty OUT is one packet.
        if done >= total || moved < n {
            return Ok((done, toggle));
        }
    }
}

/// Whether the whole of `buf` lies below 4 GiB, as the 32-bit pointers of
/// UHCI, OHCI and the EHCI structures here require. Also checks the
/// alignment `DmaAllocator::alloc_coherent` promises, which they rely on.
pub fn below_4g(buf: &DmaBuffer) -> bool {
    // An unaligned buffer (which `alloc_coherent` promises not to return) is as unusable as a high one.
    buf.device_addr().as_u64() % 4096 == 0
        && buf.device_addr().as_u64().checked_add(buf.len() as u64).is_some_and(|end| end <= 1 << 32)
}

/// Gives the controller's simulation a turn in tests; spins otherwise.
#[inline]
pub fn pause() {
    #[cfg(test)]
    sim::run();
    osmium_arch::cpu::spin_hint();
}

/// Polls `done` until it holds, for at most `ns` by `clock`. True if it held.
pub fn wait(clock: &dyn Clock, ns: u64, mut done: impl FnMut() -> bool) -> bool {
    let end = clock.now_ns().saturating_add(ns);
    loop {
        if done() {
            return true;
        }
        if clock.now_ns() > end {
            return false;
        }
        pause();
    }
}

/// Waits `ns` by `clock`.
pub fn delay(clock: &dyn Clock, ns: u64) {
    wait(clock, ns, || false);
}

fn pipe0(address: u8, dev: &Dev) -> Pipe {
    Pipe { address, speed: dev.speed, endpoint: 0, ttype: TransferType::Control, mps: dev.mps0 }
}

fn pipe_for(address: u8, dev: &Dev, ep: &Ep) -> Pipe {
    Pipe { address, speed: dev.speed, endpoint: ep.address, ttype: ep.ttype, mps: ep.mps }
}

fn device_pipe<H: Hc + ?Sized>(hc: &mut H, dev: DeviceId) -> Result<(Pipe, Dev), UsbError> {
    let d = *hc.devices().get(dev.0).ok_or(UsbError::NoDevice)?;
    Ok((pipe0(dev.0, &d), d))
}

fn endpoint<H: Hc + ?Sized>(hc: &mut H, dev: DeviceId, endpoint: u8) -> Result<(Pipe, Ep), UsbError> {
    let d = *hc.devices().get(dev.0).ok_or(UsbError::NoDevice)?;
    let ep = d.eps.iter().flatten().find(|e| e.address == endpoint).ok_or(UsbError::BadEndpoint)?;
    Ok((pipe_for(dev.0, &d, ep), *ep))
}

fn ep_mut<H: Hc + ?Sized>(hc: &mut H, dev: DeviceId, endpoint: u8) -> Option<&mut Ep> {
    hc.devices().get(dev.0)?.eps.iter_mut().flatten().find(|e| e.address == endpoint)
}

/// Reads endpoint 0's packet size, then gives the device the next free
/// address. `parent` is the hub it hangs off.
fn address_device<H: Hc + ?Sized>(hc: &mut H, speed: Speed, parent: Option<u8>) -> Result<DeviceId, UsbError> {
    let mps0 = speed.default_max_packet0();
    let blank = Dev { speed, mps0, parent, eps: [None; MAX_ENDPOINTS] };
    let default = pipe0(0, &blank);

    // The packet size is in byte 7 of the device descriptor, so ask for 8
    // bytes with the size every device of this speed can manage.
    let mut head = [0u8; 8];
    let setup = SetupPacket::get_descriptor(descriptor_type::DEVICE, 0, 8);
    let n = hc.control(&default, setup, Data::In(&mut head))?;
    let [_, _, _, _, _, _, _, mps] = head;
    let mps = mps as u16;
    let valid = match speed {
        Speed::Low => mps == 8,
        Speed::Full => matches!(mps, 8 | 16 | 32 | 64),
        _ => mps == 64,
    };
    if n < 8 || !valid {
        return Err(UsbError::BadDescriptor);
    }

    let address = hc.devices().insert(Dev { mps0: mps, ..blank }).ok_or(UsbError::NoResources)?;
    let pipe = Pipe { mps, ..default };
    let result = hc.control(&pipe, SetupPacket::set_address(address), Data::None);
    if let Err(e) = result {
        hc.devices().remove(address);
        return Err(e);
    }
    delay(hc.clock(), SET_ADDRESS_RECOVERY_NS);
    Ok(DeviceId(address))
}

/// [`UsbHost::attach`](osmium_hal::usb::UsbHost::attach).
pub fn attach<H: Hc + ?Sized>(hc: &mut H, port: u8) -> Result<DeviceId, UsbError> {
    if port == 0 || port > hc.root_ports() {
        return Err(UsbError::NoDevice);
    }
    let speed = hc.reset_port(port)?;
    address_device(hc, speed, None)
}

/// [`UsbHost::attach_hub_port`](osmium_hal::usb::UsbHost::attach_hub_port)
/// for controllers whose hubs are full speed and carry no translator.
pub fn attach_hub_port<H: Hc + ?Sized>(hc: &mut H, hub: DeviceId, speed: Speed) -> Result<DeviceId, UsbError> {
    hc.devices().get(hub.0).ok_or(UsbError::NoDevice)?;
    if !matches!(speed, Speed::Low | Speed::Full) {
        return Err(UsbError::Unsupported);
    }
    // The hub class driver has no clock: the device's 10 ms recovery from
    // its port reset (USB 2.0 §9.2.6.2) is given here.
    delay(hc.clock(), RESET_RECOVERY_NS);
    address_device(hc, speed, Some(hub.0))
}

/// [`UsbHost::detach`](osmium_hal::usb::UsbHost::detach), also detaching
/// whatever hangs off the device.
pub fn detach<H: Hc + ?Sized>(hc: &mut H, dev: DeviceId) {
    let children: [Option<u8>; MAX_DEVICES] = {
        let mut out = [None; MAX_DEVICES];
        for (slot, child) in out.iter_mut().zip(hc.devices().children(dev.0)) {
            *slot = Some(child);
        }
        out
    };
    for child in children.into_iter().flatten() {
        detach(hc, DeviceId(child));
    }
    let Some(d) = hc.devices().get(dev.0).copied() else { return };
    for slot in d.eps.iter().flatten().filter_map(|e| e.pending) {
        hc.cancel(slot);
    }
    hc.devices().remove(dev.0);
}

/// [`UsbHost::configure_endpoints`](osmium_hal::usb::UsbHost::configure_endpoints).
/// Isochronous endpoints are skipped, since these controllers do not
/// schedule them.
pub fn configure_endpoints<H: Hc + ?Sized>(
    hc: &mut H,
    dev: DeviceId,
    endpoints: &[EndpointDescriptor],
) -> Result<(), UsbError> {
    let d = *hc.devices().get(dev.0).ok_or(UsbError::NoDevice)?;
    let mut eps = [None; MAX_ENDPOINTS];
    let mut next = 0;
    for e in endpoints {
        let ttype = e.transfer_type();
        if matches!(ttype, TransferType::Isochronous | TransferType::Control) {
            continue;
        }
        if e.number() == 0 || e.max_packet_size() == 0 {
            return Err(UsbError::BadDescriptor);
        }
        // A later descriptor for an address replaces an earlier one.
        let slot = match eps.iter().flatten().position(|x: &Ep| x.address == e.address) {
            Some(i) => i,
            None => {
                next += 1;
                next - 1
            }
        };
        let Some(entry) = eps.get_mut(slot) else { return Err(UsbError::NoResources) };
        *entry = Some(Ep {
            address: e.address,
            ttype,
            mps: e.max_packet_size(),
            toggle: false,
            pending: None,
            pending_len: 0,
        });
    }
    // Only now that the new table is known good are the old transfers
    // abandoned; the new table has none pending.
    for slot in d.eps.iter().flatten().filter_map(|e| e.pending) {
        hc.cancel(slot);
    }
    hc.devices().get(dev.0).ok_or(UsbError::NoDevice)?.eps = eps;
    Ok(())
}

/// Resets the data toggles a control request resets on the device.
fn after_control<H: Hc + ?Sized>(hc: &mut H, dev: DeviceId, setup: &SetupPacket) {
    let Some(d) = hc.devices().get(dev.0) else { return };
    let recipient = setup.request_type & 0x1f;
    let standard = setup.request_type >> 5 & 3 == RequestKind::Standard as u8;
    if !standard {
        return;
    }
    match (setup.request, recipient) {
        // The endpoint halt is cleared: the next packet is DATA0.
        (request::CLEAR_FEATURE, r) if r == Recipient::Endpoint as u8 && setup.value == 0 => {
            if let Some(e) = d.eps.iter_mut().flatten().find(|e| e.address == setup.index as u8) {
                e.toggle = false;
            }
        }
        // A new configuration or alternate setting starts every endpoint over.
        (request::SET_CONFIGURATION | request::SET_INTERFACE, _) => {
            for e in d.eps.iter_mut().flatten() {
                e.toggle = false;
            }
        }
        _ => {}
    }
}

/// [`UsbHost::control_in`](osmium_hal::usb::UsbHost::control_in).
pub fn control_in<H: Hc + ?Sized>(
    hc: &mut H,
    dev: DeviceId,
    setup: SetupPacket,
    buf: &mut [u8],
) -> Result<usize, UsbError> {
    let (pipe, _) = device_pipe(hc, dev)?;
    let len = (setup.length as usize).min(buf.len());
    let setup = SetupPacket { length: len as u16, ..setup };
    let data = match buf.get_mut(..len) {
        Some(b) if len != 0 => Data::In(b),
        _ => Data::None,
    };
    hc.control(&pipe, setup, data)
}

/// [`UsbHost::control_out`](osmium_hal::usb::UsbHost::control_out).
pub fn control_out<H: Hc + ?Sized>(hc: &mut H, dev: DeviceId, setup: SetupPacket, data: &[u8]) -> Result<(), UsbError> {
    let (pipe, _) = device_pipe(hc, dev)?;
    let len = (setup.length as usize).min(data.len());
    let setup = SetupPacket { length: len as u16, ..setup };
    let stage = match data.get(..len) {
        Some(b) if len != 0 => Data::Out(b),
        _ => Data::None,
    };
    hc.control(&pipe, setup, stage)?;
    after_control(hc, dev, &setup);
    Ok(())
}

/// [`UsbHost::transfer_in`](osmium_hal::usb::UsbHost::transfer_in).
pub fn transfer_in<H: Hc + ?Sized>(
    hc: &mut H,
    dev: DeviceId,
    endpoint_addr: u8,
    buf: &mut [u8],
) -> Result<usize, UsbError> {
    let (pipe, ep) = endpoint(hc, dev, endpoint_addr | 0x80)?;
    if ep.pending.is_some() {
        return Err(UsbError::Busy);
    }
    if buf.is_empty() {
        return Ok(0);
    }
    let (n, toggle) = bulk(hc, &pipe, ep.toggle, Data::In(buf))?;
    if let Some(e) = ep_mut(hc, dev, ep.address) {
        e.toggle = toggle;
    }
    Ok(n)
}

/// [`UsbHost::transfer_out`](osmium_hal::usb::UsbHost::transfer_out).
pub fn transfer_out<H: Hc + ?Sized>(hc: &mut H, dev: DeviceId, endpoint_addr: u8, data: &[u8]) -> Result<(), UsbError> {
    let (pipe, ep) = endpoint(hc, dev, endpoint_addr & 0x7f)?;
    if ep.pending.is_some() {
        return Err(UsbError::Busy);
    }
    let (_, toggle) = bulk(hc, &pipe, ep.toggle, Data::Out(data))?;
    if let Some(e) = ep_mut(hc, dev, ep.address) {
        e.toggle = toggle;
    }
    Ok(())
}

/// [`UsbHost::submit_in`](osmium_hal::usb::UsbHost::submit_in).
pub fn submit_in<H: Hc + ?Sized>(hc: &mut H, dev: DeviceId, endpoint_addr: u8, len: usize) -> Result<(), UsbError> {
    if len == 0 || len > MAX_SUBMIT_LEN {
        return Err(UsbError::NoResources);
    }
    let (pipe, ep) = endpoint(hc, dev, endpoint_addr | 0x80)?;
    if ep.pending.is_some() {
        return Err(UsbError::Busy);
    }
    let slot = hc.submit(&pipe, ep.toggle, len)?;
    if let Some(e) = ep_mut(hc, dev, ep.address) {
        e.pending = Some(slot);
        e.pending_len = len;
    }
    Ok(())
}

/// [`UsbHost::poll_in`](osmium_hal::usb::UsbHost::poll_in).
pub fn poll_in<H: Hc + ?Sized>(
    hc: &mut H,
    dev: DeviceId,
    endpoint_addr: u8,
    buf: &mut [u8],
) -> Option<Result<usize, UsbError>> {
    let (_, ep) = match endpoint(hc, dev, endpoint_addr | 0x80) {
        _ if endpoint_addr & 0xf == 0 => return Some(Err(UsbError::BadEndpoint)),
        Ok(found) => found,
        Err(e) => return Some(Err(e)),
    };
    let Some(slot) = ep.pending else { return Some(Err(UsbError::BadEndpoint)) };
    let done = hc.poll(slot, buf)?;
    if let Some(e) = ep_mut(hc, dev, ep.address) {
        e.pending = None;
        if let Ok(n) = done {
            e.toggle = toggle_after(ep.toggle, n, ep.pending_len, ep.mps);
        }
    }
    Some(done)
}

/// A speed for the transfer direction's sake: low-speed devices take the
/// preamble, which UHCI and OHCI set per transfer.
pub fn is_low(speed: Speed) -> bool {
    speed == Speed::Low
}

/// A test hook that plays the controller: it runs whenever a driver waits.
#[cfg(test)]
pub mod sim {
    use core::cell::RefCell;
    use std::boxed::Box;

    std::thread_local! {
        static SIM: RefCell<Option<Box<dyn FnMut()>>> = const { RefCell::new(None) };
    }

    /// Installs `f` as this thread's controller simulation.
    pub fn install(f: impl FnMut() + 'static) {
        SIM.with(|s| *s.borrow_mut() = Some(Box::new(f)));
    }

    /// Removes the simulation.
    pub fn remove() {
        SIM.with(|s| *s.borrow_mut() = None);
    }

    /// Gives the simulation a turn.
    pub fn run() {
        // Taken out while it runs, so that it may itself wait.
        let taken = SIM.with(|s| s.borrow_mut().take());
        if let Some(mut f) = taken {
            f();
            SIM.with(|s| {
                let mut slot = s.borrow_mut();
                if slot.is_none() {
                    *slot = Some(f);
                }
            });
        }
    }
}

/// A scripted USB device and a clock, for the controller simulations.
#[cfg(test)]
pub mod fakedev {
    use core::cell::{Cell, RefCell};
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::rc::Rc;
    use std::vec;
    use std::vec::Vec;

    use osmium_hal::dma::{DmaAllocator, DmaBuffer};
    use osmium_hal::timer::Clock;
    use osmium_hal::usb::{DeviceDescriptor, EndpointDescriptor, SetupPacket, UsbError, UsbHost, enumerate};
    use osmium_mm::PhysAddr;

    std::thread_local! {
        /// (device address, CPU address, length) of every live [`LowDma`] buffer.
        static REGIONS: RefCell<Vec<(u64, usize, usize)>> = const { RefCell::new(Vec::new()) };
    }

    /// DMA memory whose device addresses are below 4 GiB, which a host heap
    /// is not, kept apart from the CPU addresses: a simulated controller
    /// reaches it through [`ptr`] and friends.
    #[derive(Default)]
    pub struct LowDma {
        next: Cell<u64>,
        /// Buffers allocated and not yet freed.
        pub live: Cell<usize>,
    }

    impl DmaAllocator for LowDma {
        fn alloc_coherent(&self, len: usize) -> Option<DmaBuffer> {
            let layout = Layout::from_size_align(len.max(1), 4096).ok()?;
            // SAFETY: non-zero size.
            let cpu = NonNull::new(unsafe { alloc_zeroed(layout) })?;
            if self.next.get() == 0 {
                self.next.set(0x1000_0000);
            }
            let device = self.next.get();
            self.next.set(device + (len as u64).div_ceil(4096) * 4096 + 4096);
            REGIONS.with(|r| r.borrow_mut().push((device, cpu.as_ptr() as usize, len)));
            self.live.set(self.live.get() + 1);
            // SAFETY: fresh memory, owned by the buffer; `device` is where the
            // simulated controller finds it.
            Some(unsafe { DmaBuffer::new(cpu, PhysAddr::new(device), len) })
        }

        unsafe fn free_coherent(&self, buf: DmaBuffer) {
            let device = buf.device_addr().as_u64();
            REGIONS.with(|r| r.borrow_mut().retain(|x| x.0 != device));
            self.live.set(self.live.get() - 1);
            let layout = Layout::from_size_align(buf.len().max(1), 4096).unwrap();
            // SAFETY: allocated above with this layout.
            unsafe { dealloc(buf.cpu_ptr().as_ptr(), layout) }
        }
    }

    /// The CPU address of device address `addr` in a live [`LowDma`] buffer.
    pub fn ptr(addr: u64) -> *mut u8 {
        let hit = REGIONS.with(|r| r.borrow().iter().find(|x| (x.0..x.0 + x.2 as u64).contains(&addr)).copied());
        let (device, cpu, _) = hit.unwrap_or_else(|| panic!("device address {addr:#x} is not in DMA memory"));
        (cpu + (addr - device) as usize) as *mut u8
    }

    /// Reads the dword at device address `addr`.
    pub fn r32(addr: u64) -> u32 {
        // SAFETY: inside a live buffer (`ptr` checked), 4-aligned by the caller.
        unsafe { ptr(addr).cast::<u32>().read_volatile() }
    }

    /// Writes the dword at device address `addr`.
    pub fn w32(addr: u64, v: u32) {
        // SAFETY: as for `r32`.
        unsafe { ptr(addr).cast::<u32>().write_volatile(v) }
    }

    /// Reads `len` bytes at device address `addr`.
    pub fn rbytes(addr: u64, len: usize) -> Vec<u8> {
        // SAFETY: inside a live buffer (`ptr` checked on the first byte).
        (0..len).map(|i| unsafe { ptr(addr).add(i).read_volatile() }).collect()
    }

    /// Writes `data` at device address `addr`.
    pub fn wbytes(addr: u64, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            // SAFETY: as for `rbytes`.
            unsafe { ptr(addr).add(i).write_volatile(*b) };
        }
    }

    /// A clock that moves on 1 µs each time it is read.
    #[derive(Default)]
    pub struct TickClock(AtomicU64);

    impl Clock for TickClock {
        fn now_ns(&self) -> u64 {
            self.0.fetch_add(1000, Ordering::Relaxed) + 1000
        }
    }

    /// The device descriptor of a mass-storage stick with an interrupt IN
    /// endpoint (0x83), 64-byte packets.
    pub const DEVICE: [u8; 18] = [18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x81, 0x07, 0x81, 0x55, 0x00, 0x01, 1, 2, 3, 1];

    /// A configuration with bulk IN 0x81, bulk OUT 0x02 and interrupt IN 0x83.
    pub const CONFIG: [u8; 39] = [
        9, 2, 39, 0, 1, 1, 0, 0x80, 50, // configuration
        9, 4, 0, 0, 3, 8, 6, 0x50, 0, // interface 0
        7, 5, 0x81, 2, 0x40, 0x00, 0, // bulk IN 64
        7, 5, 0x02, 2, 0x40, 0x00, 0, // bulk OUT 64
        7, 5, 0x83, 3, 0x08, 0x00, 4, // interrupt IN 8
    ];

    /// What a device does with one transaction.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Reply {
        /// Accepted (OUT, SETUP) or answered with this data (IN).
        Ack(Vec<u8>),
        /// Not ready.
        Nak,
        /// The endpoint is halted.
        Stall,
        /// No answer: a wrong address, say.
        None,
    }

    /// A USB device model: address, control requests, a bulk loopback
    /// (OUT 0x02 feeds IN 0x81) and an interrupt report on 0x83. It checks
    /// data toggles as a real device does.
    pub struct Device {
        /// Current address, 0 after a reset.
        pub address: u8,
        /// Full-speed packet size of endpoint 0 (the descriptor says 64).
        pub mps0: usize,
        /// Selected configuration.
        pub configured: u8,
        /// Bytes received on OUT 0x02, in order.
        pub received: Vec<u8>,
        /// Bytes waiting to be read on IN 0x81.
        pub loopback: Vec<u8>,
        /// A report for the interrupt endpoint, if any.
        pub report: Option<Vec<u8>>,
        /// Endpoints whose halt feature is set.
        pub halted: Vec<u8>,
        /// Toggle expected next, per endpoint address.
        pub toggles: [bool; 256],
        /// Toggle mismatches seen on OUT packets.
        pub toggle_errors: usize,
        /// Transactions seen: (endpoint address, PID).
        pub log: Vec<(u8, u8)>,
        /// An IN transfer that ends on a full packet is terminated by a
        /// zero-length packet, as a gadget does.
        pub zlp_after_full: bool,
        zlp_pending: bool,
        setup: [u8; 8],
        control_in: Vec<u8>,
        control_out_len: usize,
        new_address: Option<u8>,
        stage: Stage,
    }

    #[derive(PartialEq, Eq)]
    enum Stage {
        Idle,
        DataIn,
        DataOut,
        StatusIn,
        StatusOut,
    }

    /// PIDs.
    pub const SETUP: u8 = 0x2d;
    /// PIDs.
    pub const IN: u8 = 0x69;
    /// PIDs.
    pub const OUT: u8 = 0xe1;

    impl Default for Device {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Device {
        /// A fresh device at address 0.
        pub fn new() -> Self {
            Self {
                address: 0,
                mps0: 64,
                configured: 0,
                received: Vec::new(),
                loopback: Vec::new(),
                report: None,
                halted: Vec::new(),
                toggles: [false; 256],
                toggle_errors: 0,
                log: Vec::new(),
                zlp_after_full: false,
                zlp_pending: false,
                setup: [0; 8],
                control_in: Vec::new(),
                control_out_len: 0,
                new_address: None,
                stage: Stage::Idle,
            }
        }

        /// The bus reset: back to address 0, unconfigured.
        pub fn reset(&mut self) {
            let (received, loopback) = (core::mem::take(&mut self.received), core::mem::take(&mut self.loopback));
            *self = Self { received, loopback, ..Self::new() };
        }

        /// One transaction. `data` is what an OUT or SETUP packet carries;
        /// `toggle` is its DATA0/DATA1 PID; `max` the size the host accepts
        /// for an IN.
        pub fn transact(&mut self, address: u8, endpoint: u8, pid: u8, toggle: bool, data: &[u8], max: usize) -> Reply {
            if address != self.address {
                return Reply::None;
            }
            self.log.push((endpoint, pid));
            if endpoint == 0 { self.control(pid, data, max) } else { self.data(endpoint, pid, toggle, data, max) }
        }

        fn control(&mut self, pid: u8, data: &[u8], max: usize) -> Reply {
            match pid {
                SETUP => {
                    self.setup.copy_from_slice(data);
                    let [rt, req, vl, vh, il, ih, ll, lh] = self.setup;
                    let value = u16::from_le_bytes([vl, vh]);
                    let length = u16::from_le_bytes([ll, lh]) as usize;
                    self.control_out_len = length;
                    if rt & 0x80 != 0 {
                        let reply = match (req, value >> 8) {
                            (6, 1) => Some(DEVICE.to_vec()),
                            (6, 2) => Some(CONFIG.to_vec()),
                            _ => None,
                        };
                        let Some(mut reply) = reply else {
                            self.stage = Stage::Idle;
                            return Reply::Stall;
                        };
                        reply.truncate(length);
                        self.control_in = reply;
                        self.stage = Stage::DataIn;
                    } else {
                        match req {
                            // The new address takes effect after the status stage.
                            5 => self.new_address = Some(vl),
                            9 => self.configured = vl,
                            1 if rt == 2 => {
                                let ep = u16::from_le_bytes([il, ih]) as u8;
                                self.halted.retain(|&e| e != ep);
                                self.toggles[ep as usize] = false;
                            }
                            _ => {}
                        }
                        self.stage = if length == 0 { Stage::StatusIn } else { Stage::DataOut };
                    }
                    Reply::Ack(Vec::new())
                }
                IN => match self.stage {
                    Stage::DataIn => {
                        let n = self.control_in.len().min(max).min(self.mps0);
                        let chunk: Vec<u8> = self.control_in.drain(..n).collect();
                        if self.control_in.is_empty() && n < self.mps0 {
                            self.stage = Stage::StatusOut;
                        }
                        Reply::Ack(chunk)
                    }
                    Stage::StatusIn => {
                        self.stage = Stage::Idle;
                        if let Some(a) = self.new_address.take() {
                            self.address = a;
                        }
                        Reply::Ack(Vec::new())
                    }
                    _ => Reply::Stall,
                },
                OUT => match self.stage {
                    Stage::DataOut => {
                        self.control_out_len = self.control_out_len.saturating_sub(data.len());
                        if self.control_out_len == 0 {
                            self.stage = Stage::StatusIn;
                        }
                        Reply::Ack(Vec::new())
                    }
                    Stage::StatusOut | Stage::DataIn => {
                        // A status stage may cut the data stage short.
                        self.stage = Stage::Idle;
                        Reply::Ack(Vec::new())
                    }
                    _ => Reply::Stall,
                },
                _ => Reply::None,
            }
        }

        /// Counts a packet whose toggle is not the one this end expects, then
        /// advances the expectation.
        fn check_toggle(&mut self, endpoint: u8, toggle: bool) {
            if self.toggles[endpoint as usize] != toggle {
                self.toggle_errors += 1;
            }
            self.toggles[endpoint as usize] = !self.toggles[endpoint as usize];
        }

        fn data(&mut self, endpoint: u8, pid: u8, toggle: bool, data: &[u8], max: usize) -> Reply {
            if self.configured == 0 {
                return Reply::None;
            }
            if self.halted.contains(&endpoint) {
                return Reply::Stall;
            }
            match (endpoint, pid) {
                (0x02, OUT) => {
                    // A repeated packet is acknowledged, then dropped.
                    let fresh = self.toggles[0x02] == toggle;
                    self.check_toggle(endpoint, toggle);
                    if fresh {
                        self.received.extend_from_slice(data);
                        self.loopback.extend_from_slice(data);
                    }
                    Reply::Ack(Vec::new())
                }
                (0x81, IN) => {
                    if self.loopback.is_empty() {
                        if !self.zlp_pending {
                            return Reply::Nak;
                        }
                        self.zlp_pending = false;
                        self.check_toggle(endpoint, toggle);
                        return Reply::Ack(Vec::new());
                    }
                    self.check_toggle(endpoint, toggle);
                    let n = self.loopback.len().min(max).min(64);
                    let chunk: Vec<u8> = self.loopback.drain(..n).collect();
                    self.zlp_pending = self.zlp_after_full && n == 64 && self.loopback.is_empty();
                    Reply::Ack(chunk)
                }
                (0x83, IN) => match self.report.take() {
                    Some(r) => {
                        self.check_toggle(endpoint, toggle);
                        Reply::Ack(r)
                    }
                    None => Reply::Nak,
                },
                _ => Reply::Stall,
            }
        }
    }

    /// A bulk IN transfer larger than the data, which ends on a full packet
    /// and a zero-length one, must leave the data toggle where the device has
    /// it: the next transfer arrives intact and every packet is in step.
    pub fn zlp_terminated_in<H: UsbHost>(host: &mut H, dev: &Rc<RefCell<Device>>, port: u8) {
        let mut config = [0u8; 256];
        let id = enumerate(host, port, &mut config).expect("enumerate").id;
        dev.borrow_mut().zlp_after_full = true;
        let full: Vec<u8> = (0..64).collect();
        for round in 0..3u8 {
            host.transfer_out(id, 0x02, &full).unwrap();
            let mut buf = [0u8; 256];
            assert_eq!(host.transfer_in(id, 0x81, &mut buf), Ok(64), "round {round}");
            assert_eq!(&buf[..64], &full[..]);
            // The next transfer, which a wrong toggle would lose.
            host.transfer_out(id, 0x02, &[round + 1; 5]).unwrap();
            let mut small = [0u8; 16];
            assert_eq!(host.transfer_in(id, 0x81, &mut small), Ok(5), "round {round}");
            assert_eq!(&small[..5], &[round + 1; 5]);
        }
        assert_eq!(dev.borrow().toggle_errors, 0, "every packet carried the toggle the device expected");
    }

    /// Drives a controller through the whole `UsbHost` surface against the
    /// device on `port`: enumeration, bulk transfers across packet and
    /// toggle boundaries, a zero-length packet, a stall and its recovery,
    /// and an interrupt transfer that is started before its data exists.
    pub fn exercise<H: UsbHost>(host: &mut H, dev: &Rc<RefCell<Device>>, port: u8) {
        assert!(host.port_status(port).connected);
        let mut config = [0u8; 256];
        let found = enumerate(host, port, &mut config).expect("enumerate");
        let d = DeviceDescriptor::parse(&DEVICE).unwrap();
        assert_eq!((found.device.vendor_id, found.device.product_id), (d.vendor_id, d.product_id));
        assert_eq!(found.config_len, CONFIG.len());
        assert_eq!(&config[..found.config_len], &CONFIG);
        assert_eq!(dev.borrow().address, found.id.0, "the device took the address it was given");
        assert_eq!(dev.borrow().configured, 1);
        let id = found.id;

        // Bulk OUT then IN, with sizes on both sides of the packet size.
        for len in [1usize, 63, 64, 65, 200, 1000] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
            host.transfer_out(id, 0x02, &data).expect("bulk out");
            let mut back = vec![0u8; len];
            let mut got = 0;
            while got < len {
                got += host.transfer_in(id, 0x81, &mut back[got..]).expect("bulk in");
            }
            assert_eq!(back, data, "{len} bytes round trip");
        }
        // A zero-length packet in the middle of the stream keeps the toggles in step.
        host.transfer_out(id, 0x02, &[]).expect("zero-length packet");
        host.transfer_out(id, 0x02, &[9; 3]).expect("bulk out after it");
        let mut three = [0u8; 8];
        assert_eq!(host.transfer_in(id, 0x81, &mut three), Ok(3));
        assert_eq!(&three[..3], &[9; 3]);
        assert_eq!(dev.borrow().toggle_errors, 0, "every packet carried the toggle the device expected");

        // A halted endpoint stalls until the halt is cleared.
        dev.borrow_mut().halted.push(0x81);
        assert_eq!(host.transfer_in(id, 0x81, &mut three), Err(UsbError::Stall));
        host.control_out(id, SetupPacket::clear_halt(0x81), &[]).expect("clear halt");
        host.transfer_out(id, 0x02, &[5]).unwrap();
        assert_eq!(host.transfer_in(id, 0x81, &mut three), Ok(1));
        assert_eq!(dev.borrow().toggle_errors, 0, "clearing the halt restarted the toggle");

        // An interrupt transfer waits for its data without blocking.
        host.submit_in(id, 0x83, 8).expect("submit");
        assert_eq!(host.submit_in(id, 0x83, 8), Err(UsbError::Busy));
        let mut report = [0u8; 8];
        for _ in 0..3 {
            assert!(host.poll_in(id, 0x83, &mut report).is_none());
        }
        dev.borrow_mut().report = Some(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let mut n = None;
        for _ in 0..1000 {
            super::sim::run();
            if let Some(r) = host.poll_in(id, 0x83, &mut report) {
                n = Some(r);
                break;
            }
        }
        assert_eq!(n, Some(Ok(8)));
        assert_eq!(report, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(host.poll_in(id, 0x83, &mut report), Some(Err(UsbError::BadEndpoint)), "nothing pending");
        // And again, which uses the other data toggle.
        host.submit_in(id, 0x83, 8).unwrap();
        dev.borrow_mut().report = Some(vec![8; 8]);
        let again = (0..1000).find_map(|_| {
            super::sim::run();
            host.poll_in(id, 0x83, &mut report)
        });
        assert_eq!(again, Some(Ok(8)));
        assert_eq!(dev.borrow().toggle_errors, 0);

        // Endpoints that were never configured, and a device that is gone.
        assert_eq!(host.transfer_in(id, 0x84, &mut three), Err(UsbError::BadEndpoint));
        let eps: [EndpointDescriptor; 0] = [];
        host.configure_endpoints(id, &eps).unwrap();
        assert_eq!(host.transfer_out(id, 0x02, &[1]), Err(UsbError::BadEndpoint));
        host.detach(id);
        assert_eq!(host.transfer_out(id, 0x02, &[1]), Err(UsbError::NoDevice));
    }
}
