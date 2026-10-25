//! HID devices driven by their report descriptors: a generic [`HidDevice`]
//! that fetches and parses the descriptor and reads input reports, and on
//! top of it [`HidKeyboard`] and [`HidMouse`], which turn reports into key
//! and pointer events whatever layout the device uses (NKRO bitmaps, report
//! IDs, absolute pointers). The boot-protocol [`BootKeyboard`](super::BootKeyboard)
//! remains for devices and firmware that cannot parse descriptors.

use super::KeyEvent;
use super::descriptor::{ReportDescriptor, ReportKind, id_of, page_of, usages};
use osmium_hal::usb::{Descriptor, Descriptors, find_interface, request};
use osmium_hal::usb::{DeviceId, Direction, Recipient, RequestKind, SetupPacket, TransferType, UsbError, UsbHost};

const GET_REPORT: u8 = 0x01;
const SET_REPORT: u8 = 0x09;
const SET_IDLE: u8 = 0x0a;
const SET_PROTOCOL: u8 = 0x0b;
const HID_DESCRIPTOR: u8 = 0x21;
const REPORT_DESCRIPTOR: u8 = 0x22;
/// The longest report descriptor fetched (it lives on the stack).
pub const MAX_DESCRIPTOR_LEN: usize = 2048;
/// The longest input report read.
pub const MAX_REPORT_LEN: usize = 128;

/// The interface numbers of the HID interfaces (class 3, alternate setting
/// 0) in a configuration descriptor set.
pub fn hid_interfaces(config: &[u8]) -> impl Iterator<Item = u8> + '_ {
    Descriptors::new(config).map_while(Result::ok).filter_map(|d| match d {
        Descriptor::Interface(i) if i.class == 3 && i.alternate == 0 => Some(i.number),
        _ => None,
    })
}

/// The length of the report descriptor that the HID class descriptor of
/// interface `interface` announces.
pub fn report_descriptor_len(config: &[u8], interface: u8) -> Option<u16> {
    let mut current = None;
    for d in Descriptors::new(config).map_while(Result::ok) {
        match d {
            Descriptor::Interface(i) => current = (i.alternate == 0).then_some(i.number),
            Descriptor::Other(b) if current == Some(interface) && b.get(1) == Some(&HID_DESCRIPTOR) => {
                let count = *b.get(5)? as usize;
                // Each entry: type, length (little-endian).
                let entries = b.get(6..)?;
                return entries.as_chunks::<3>().0.iter().take(count).find_map(|e| match *e {
                    [REPORT_DESCRIPTOR, lo, hi] => Some(u16::from_le_bytes([lo, hi])),
                    _ => None,
                });
            }
            _ => {}
        }
    }
    None
}

/// Fetches and parses the report descriptor of HID interface `interface`
/// (`GET_DESCRIPTOR` of the class's report descriptor, with the length the
/// HID descriptor in `config` announces).
pub fn fetch_report_descriptor<U: UsbHost + ?Sized>(
    host: &mut U,
    dev: DeviceId,
    config: &[u8],
    interface: u8,
) -> Result<ReportDescriptor, UsbError> {
    let len = report_descriptor_len(config, interface).ok_or(UsbError::BadDescriptor)? as usize;
    if len == 0 || len > MAX_DESCRIPTOR_LEN {
        return Err(UsbError::BadDescriptor);
    }
    let mut raw = [0u8; MAX_DESCRIPTOR_LEN];
    let window = raw.get_mut(..len).ok_or(UsbError::BadDescriptor)?;
    let setup = SetupPacket::new(
        Direction::In,
        RequestKind::Standard,
        Recipient::Interface,
        request::GET_DESCRIPTOR,
        (REPORT_DESCRIPTOR as u16) << 8,
        interface as u16,
        len as u16,
    );
    let got = host.control_in(dev, setup, window)?.min(len);
    if got == 0 {
        return Err(UsbError::BadDescriptor);
    }
    let descriptor =
        ReportDescriptor::parse(raw.get(..got).ok_or(UsbError::BadDescriptor)?).map_err(|_| UsbError::BadDescriptor)?;
    // A descriptor with no data fields describes nothing to read.
    if descriptor.fields().is_empty() {
        return Err(UsbError::BadDescriptor);
    }
    Ok(descriptor)
}

/// A HID interface whose report descriptor has been fetched and parsed.
pub struct HidDevice<H: UsbHost> {
    pub(super) host: H,
    dev: DeviceId,
    interface: u8,
    endpoint: u8,
    max_packet: usize,
    descriptor: ReportDescriptor,
    submitted: bool,
    buf: [u8; MAX_REPORT_LEN],
    len: usize,
}

impl<H: UsbHost> HidDevice<H> {
    /// Drives HID interface `interface` of the enumerated device `dev`,
    /// whose configuration descriptor set is `config`: fetches the report
    /// descriptor, parses it, selects the report protocol and asks the
    /// device to report only on change.
    pub fn new(mut host: H, dev: DeviceId, config: &[u8], interface: u8) -> Result<Self, UsbError> {
        let descriptor = fetch_report_descriptor(&mut host, dev, config, interface)?;
        Self::with_descriptor(host, dev, config, interface, descriptor)
    }

    /// Like [`new`](Self::new) for a report descriptor already fetched with
    /// [`fetch_report_descriptor`].
    pub fn with_descriptor(
        mut host: H,
        dev: DeviceId,
        config: &[u8],
        interface: u8,
        descriptor: ReportDescriptor,
    ) -> Result<Self, UsbError> {
        let iface = find_interface(config, |i| i.class == 3 && i.number == interface).ok_or(UsbError::BadDescriptor)?;
        let ep = iface.endpoint(TransferType::Interrupt, Direction::In).ok_or(UsbError::BadDescriptor)?;
        let class = |request, value| {
            SetupPacket::new(
                Direction::Out,
                RequestKind::Class,
                Recipient::Interface,
                request,
                value,
                interface as u16,
                0,
            )
        };
        // Devices start in the report protocol; boot-capable ones may have
        // been left in the boot protocol by firmware. Both are optional.
        if iface.descriptor.subclass == 1 {
            let _ = host.control_out(dev, class(SET_PROTOCOL, 1), &[]);
        }
        let _ = host.control_out(dev, class(SET_IDLE, 0), &[]);
        Ok(Self {
            host,
            dev,
            interface,
            endpoint: ep.address,
            max_packet: (ep.max_packet_size() as usize).clamp(1, MAX_REPORT_LEN),
            descriptor,
            submitted: false,
            buf: [0; MAX_REPORT_LEN],
            len: 0,
        })
    }

    /// The device handle.
    pub fn device(&self) -> DeviceId {
        self.dev
    }

    /// The interface number.
    pub fn interface(&self) -> u8 {
        self.interface
    }

    /// The parsed report descriptor.
    pub fn descriptor(&self) -> &ReportDescriptor {
        &self.descriptor
    }

    /// Checks for a new input report without waiting; true if one arrived,
    /// in which case [`report`](Self::report) returns it. Keeps one interrupt
    /// IN transfer outstanding.
    pub fn poll(&mut self) -> Result<bool, UsbError> {
        if !self.submitted {
            self.host.submit_in(self.dev, self.endpoint, self.max_packet)?;
            self.submitted = true;
        }
        match self.host.poll_in(self.dev, self.endpoint, &mut self.buf) {
            None => Ok(false),
            Some(got) => {
                self.submitted = false;
                self.len = got?.min(MAX_REPORT_LEN);
                Ok(true)
            }
        }
    }

    /// The input report [`poll`](Self::poll) last received, including its
    /// report ID byte if the descriptor uses report IDs.
    pub fn report(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or(&[])
    }

    /// Sends an output or feature report with `GET`/`SET_REPORT`. `data`
    /// includes the report ID byte if `id` is not 0.
    pub fn set_report(&mut self, kind: ReportKind, id: u8, data: &[u8]) -> Result<(), UsbError> {
        let ty: u16 = match kind {
            ReportKind::Input => 1,
            ReportKind::Output => 2,
            ReportKind::Feature => 3,
        };
        let setup = SetupPacket::new(
            Direction::Out,
            RequestKind::Class,
            Recipient::Interface,
            SET_REPORT,
            ty << 8 | id as u16,
            self.interface as u16,
            u16::try_from(data.len()).map_err(|_| UsbError::NoResources)?,
        );
        self.host.control_out(self.dev, setup, data)
    }

    /// Reads a feature or input report over the control pipe into `buf`;
    /// returns the length.
    pub fn get_report(&mut self, kind: ReportKind, id: u8, buf: &mut [u8]) -> Result<usize, UsbError> {
        let ty: u16 = match kind {
            ReportKind::Input => 1,
            ReportKind::Output => 2,
            ReportKind::Feature => 3,
        };
        let setup = SetupPacket::new(
            Direction::In,
            RequestKind::Class,
            Recipient::Interface,
            GET_REPORT,
            ty << 8 | id as u16,
            self.interface as u16,
            u16::try_from(buf.len()).map_err(|_| UsbError::NoResources)?,
        );
        self.host.control_in(self.dev, setup, buf)
    }
}

/// Most keys tracked as pressed at once.
const MAX_KEYS: usize = 32;

/// Turns keyboard input reports into key events by comparing each with the
/// last. Works for any keyboard layout a descriptor can express: the boot
/// array, NKRO bitmaps, several report IDs.
#[derive(Clone, Debug, Default)]
pub struct KeyboardDecoder {
    keys: [u8; MAX_KEYS],
    n: usize,
    modifiers: u8,
}

impl KeyboardDecoder {
    /// A decoder with no keys down.
    pub const fn new() -> Self {
        Self { keys: [0; MAX_KEYS], n: 0, modifiers: 0 }
    }

    /// Decodes `report` (with its report ID byte, if the descriptor uses
    /// them) and writes the events that turn the last keyboard state into
    /// the new one to `out`: releases first, then presses. Returns how many
    /// were written; events beyond `out`'s length are dropped, but the state
    /// still advances. Reports that carry no keyboard fields, and rollover
    /// error reports, produce nothing and leave the state alone. At most
    /// 32 simultaneous keys are tracked.
    pub fn update(&mut self, desc: &ReportDescriptor, report: &[u8], out: &mut [KeyEvent]) -> usize {
        let Some(r) = desc.input_report(report) else { return 0 };
        if !r.has_page(usages::PAGE_KEYBOARD) {
            return 0;
        }
        let mut cur = [0u8; MAX_KEYS];
        let mut n = 0;
        let mut mods = 0u8;
        let mut rollover = false;
        r.for_each(|item| {
            if page_of(item.usage) != usages::PAGE_KEYBOARD || item.value == 0 {
                return;
            }
            match id_of(item.usage) {
                1 => rollover = true,
                2 | 3 => {}
                id @ 0xe0..=0xe7 => mods |= 1 << (id - 0xe0),
                id @ 4..=0xdf => {
                    let seen = cur.get(..n).unwrap_or(&[]).contains(&(id as u8));
                    if let Some(slot) = cur.get_mut(n).filter(|_| !seen) {
                        *slot = id as u8;
                        n += 1;
                    }
                }
                _ => {}
            }
        });
        if rollover {
            return 0;
        }
        let prev = self.keys.get(..self.n).unwrap_or(&[]);
        let now = cur.get(..n).unwrap_or(&[]);
        let mut written = 0;
        let mut push = |usage: u8, pressed: bool| {
            if let Some(slot) = out.get_mut(written) {
                *slot = KeyEvent { usage, pressed, modifiers: mods };
                written += 1;
            }
        };
        for &k in prev.iter().filter(|k| !now.contains(k)) {
            push(k, false);
        }
        for &k in now.iter().filter(|k| !prev.contains(k)) {
            push(k, true);
        }
        self.keys = cur;
        self.n = n;
        self.modifiers = mods;
        written
    }

    /// The modifier bits (as in [`modifier`](super::modifier)) of the last report.
    pub fn modifiers(&self) -> u8 {
        self.modifiers
    }
}

/// A keyboard driven through its report descriptor.
pub struct HidKeyboard<H: UsbHost> {
    pub(super) device: HidDevice<H>,
    decoder: KeyboardDecoder,
    queue: [KeyEvent; 2 * MAX_KEYS],
    queued: usize,
    head: usize,
}

impl<H: UsbHost> HidKeyboard<H> {
    /// Drives the first HID interface of `dev` whose report descriptor has a
    /// keyboard or keypad application collection.
    pub fn new(mut host: H, dev: DeviceId, config: &[u8]) -> Result<Self, UsbError> {
        for interface in hid_interfaces(config) {
            if let Ok(d) = fetch_report_descriptor(&mut host, dev, config, interface)
                && (d.has_application(usages::KEYBOARD) || d.has_application(usages::KEYPAD))
            {
                return Ok(Self::from_device(HidDevice::with_descriptor(host, dev, config, interface, d)?));
            }
        }
        Err(UsbError::BadDescriptor)
    }

    /// Wraps an already-opened HID interface.
    pub fn from_device(device: HidDevice<H>) -> Self {
        let empty = KeyEvent { usage: 0, pressed: false, modifiers: 0 };
        Self { device, decoder: KeyboardDecoder::new(), queue: [empty; 2 * MAX_KEYS], queued: 0, head: 0 }
    }

    /// The underlying device.
    pub fn device(&self) -> &HidDevice<H> {
        &self.device
    }

    /// The next key event, if any, without waiting.
    pub fn poll(&mut self) -> Result<Option<KeyEvent>, UsbError> {
        if self.head >= self.queued {
            self.head = 0;
            self.queued = 0;
            if self.device.poll()? {
                self.queued = self.decoder.update(&self.device.descriptor, self.device.report(), &mut self.queue);
            }
        }
        let ev = self.queue.get(self.head).copied().filter(|_| self.head < self.queued);
        self.head += usize::from(ev.is_some());
        Ok(ev)
    }

    /// Sets the keyboard's Num Lock, Caps Lock and Scroll Lock LEDs through
    /// its LED output report. `Unsupported` if the descriptor has none.
    pub fn set_leds(&mut self, num: bool, caps: bool, scroll: bool) -> Result<(), UsbError> {
        let desc = &self.device.descriptor;
        let is_led = |f: &&super::descriptor::Field| {
            f.kind == ReportKind::Output && f.flags.is_variable() && f.usage_page(desc) == Some(usages::PAGE_LED)
        };
        let id = desc.fields().iter().find(is_led).map(|f| f.report_id).ok_or(UsbError::Unsupported)?;
        let len = desc.report_len(ReportKind::Output, id).ok_or(UsbError::Unsupported)?;
        let mut buf = [0u8; 64];
        let packet = buf.get_mut(..len).ok_or(UsbError::NoResources)?;
        let body = if desc.uses_report_ids() {
            let (first, body) = packet.split_first_mut().ok_or(UsbError::NoResources)?;
            *first = id;
            body
        } else {
            &mut *packet
        };
        for f in desc.fields_of(ReportKind::Output, id).filter(|f| is_led(f)) {
            for i in 0..f.report_count as u32 {
                let on = match desc.field_usage(f, i) {
                    Some(usages::LED_NUM_LOCK) => num,
                    Some(usages::LED_CAPS_LOCK) => caps,
                    Some(usages::LED_SCROLL_LOCK) => scroll,
                    _ => continue,
                };
                f.write(body, i, i64::from(on)).ok_or(UsbError::BadDescriptor)?;
            }
        }
        let packet = buf.get(..len).ok_or(UsbError::NoResources)?;
        self.device.set_report(ReportKind::Output, id, packet)
    }
}

/// A pointer report decoded.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PointerEvent {
    /// Relative X motion (0 for an absolute pointer).
    pub dx: i32,
    /// Relative Y motion.
    pub dy: i32,
    /// Vertical wheel motion, positive away from the user.
    pub wheel: i32,
    /// Horizontal wheel motion.
    pub pan: i32,
    /// Absolute X (0 for a relative pointer), in the descriptor's logical range.
    pub x: i32,
    /// Absolute Y.
    pub y: i32,
    /// Whether `x` and `y` are absolute positions (a tablet or touchscreen).
    pub absolute: bool,
    /// Pressed buttons, bit 0 being button 1 (usually left).
    pub buttons: u32,
}

/// Decodes a mouse, trackball or tablet report. `None` if the report (with
/// its report ID byte, if the descriptor uses them) is not a pointer report.
pub fn decode_pointer(desc: &ReportDescriptor, report: &[u8]) -> Option<PointerEvent> {
    let r = desc.input_report(report)?;
    if !r.has_page(usages::PAGE_GENERIC_DESKTOP) && !r.has_page(usages::PAGE_BUTTON) {
        return None;
    }
    let mut ev = PointerEvent::default();
    let clamp = |v: i64| i32::try_from(v).unwrap_or(if v < 0 { i32::MIN } else { i32::MAX });
    r.for_each(|item| match item.usage {
        usages::X if item.relative => ev.dx = ev.dx.saturating_add(clamp(item.value)),
        usages::Y if item.relative => ev.dy = ev.dy.saturating_add(clamp(item.value)),
        usages::X => (ev.x, ev.absolute) = (clamp(item.value), true),
        usages::Y => (ev.y, ev.absolute) = (clamp(item.value), true),
        usages::WHEEL => ev.wheel = ev.wheel.saturating_add(clamp(item.value)),
        usages::AC_PAN => ev.pan = ev.pan.saturating_add(clamp(item.value)),
        u if page_of(u) == usages::PAGE_BUTTON && item.value != 0 => {
            if let Some(bit) = id_of(u).checked_sub(1).filter(|&b| b < 32) {
                ev.buttons |= 1 << bit;
            }
        }
        _ => {}
    });
    Some(ev)
}

/// A mouse, trackball or tablet driven through its report descriptor.
pub struct HidMouse<H: UsbHost> {
    pub(super) device: HidDevice<H>,
}

impl<H: UsbHost> HidMouse<H> {
    /// Drives the first HID interface of `dev` whose report descriptor has a
    /// mouse or pointer application collection.
    pub fn new(mut host: H, dev: DeviceId, config: &[u8]) -> Result<Self, UsbError> {
        for interface in hid_interfaces(config) {
            if let Ok(d) = fetch_report_descriptor(&mut host, dev, config, interface)
                && (d.has_application(usages::MOUSE) || d.has_application(usages::POINTER))
            {
                return Ok(Self { device: HidDevice::with_descriptor(host, dev, config, interface, d)? });
            }
        }
        Err(UsbError::BadDescriptor)
    }

    /// Wraps an already-opened HID interface.
    pub fn from_device(device: HidDevice<H>) -> Self {
        Self { device }
    }

    /// The underlying device.
    pub fn device(&self) -> &HidDevice<H> {
        &self.device
    }

    /// The logical range of the X and Y axes, which tells an absolute
    /// pointer's coordinate space.
    pub fn range(&self) -> Option<((i64, i64), (i64, i64))> {
        let d = self.device.descriptor();
        Some((d.logical_range(usages::X)?, d.logical_range(usages::Y)?))
    }

    /// The next pointer event, if a report arrived, without waiting.
    pub fn poll(&mut self) -> Result<Option<PointerEvent>, UsbError> {
        if !self.device.poll()? {
            return Ok(None);
        }
        Ok(decode_pointer(self.device.descriptor(), self.device.report()))
    }
}
