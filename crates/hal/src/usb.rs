//! USB: wire formats and the host-controller interface.
//!
//! The types here are the USB 2.0/3.x chapter 9 formats (setup packets and
//! standard descriptors), parsed from and serialized to bytes so they never
//! depend on struct layout. [`UsbHost`] is what a host-controller driver
//! (xHCI, EHCI, DWC2) offers to class drivers, and [`enumerate`] runs the
//! standard device bring-up on any of them.

use core::fmt;

/// Data stage direction of a control transfer, or direction of an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Host to device.
    Out,
    /// Device to host.
    In,
}

/// Bits 5–6 of `bmRequestType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestKind {
    /// Defined by chapter 9.
    Standard = 0,
    /// Defined by a device class.
    Class = 1,
    /// Vendor specific.
    Vendor = 2,
}

/// Bits 0–4 of `bmRequestType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    /// The device.
    Device = 0,
    /// An interface (`wIndex` holds its number).
    Interface = 1,
    /// An endpoint (`wIndex` holds its address).
    Endpoint = 2,
    /// Something else.
    Other = 3,
}

/// Standard request codes (`bRequest`).
pub mod request {
    #![allow(missing_docs)]
    pub const GET_STATUS: u8 = 0;
    pub const CLEAR_FEATURE: u8 = 1;
    pub const SET_FEATURE: u8 = 3;
    pub const SET_ADDRESS: u8 = 5;
    pub const GET_DESCRIPTOR: u8 = 6;
    pub const SET_DESCRIPTOR: u8 = 7;
    pub const GET_CONFIGURATION: u8 = 8;
    pub const SET_CONFIGURATION: u8 = 9;
    pub const GET_INTERFACE: u8 = 10;
    pub const SET_INTERFACE: u8 = 11;
}

/// Descriptor type codes (`bDescriptorType`).
pub mod descriptor_type {
    #![allow(missing_docs)]
    pub const DEVICE: u8 = 1;
    pub const CONFIGURATION: u8 = 2;
    pub const STRING: u8 = 3;
    pub const INTERFACE: u8 = 4;
    pub const ENDPOINT: u8 = 5;
    pub const DEVICE_QUALIFIER: u8 = 6;
    pub const INTERFACE_ASSOCIATION: u8 = 11;
    pub const BOS: u8 = 15;
    pub const SS_ENDPOINT_COMPANION: u8 = 48;
}

/// The 8-byte SETUP stage of a control transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetupPacket {
    /// `bmRequestType`.
    pub request_type: u8,
    /// `bRequest`.
    pub request: u8,
    /// `wValue`.
    pub value: u16,
    /// `wIndex`.
    pub index: u16,
    /// `wLength`: bytes in the data stage.
    pub length: u16,
}

impl SetupPacket {
    /// Builds a request from its parts.
    pub const fn new(
        dir: Direction,
        kind: RequestKind,
        recipient: Recipient,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> Self {
        let dir_bit = match dir {
            Direction::Out => 0,
            Direction::In => 0x80,
        };
        Self { request_type: dir_bit | (kind as u8) << 5 | recipient as u8, request, value, index, length }
    }

    /// `GET_DESCRIPTOR` for descriptor `ty`, index `index`, `length` bytes.
    pub const fn get_descriptor(ty: u8, index: u8, length: u16) -> Self {
        let value = (ty as u16) << 8 | index as u16;
        Self::new(Direction::In, RequestKind::Standard, Recipient::Device, request::GET_DESCRIPTOR, value, 0, length)
    }

    /// `SET_ADDRESS`.
    pub const fn set_address(address: u8) -> Self {
        Self::new(Direction::Out, RequestKind::Standard, Recipient::Device, request::SET_ADDRESS, address as u16, 0, 0)
    }

    /// `SET_CONFIGURATION`.
    pub const fn set_configuration(value: u8) -> Self {
        let req = request::SET_CONFIGURATION;
        Self::new(Direction::Out, RequestKind::Standard, Recipient::Device, req, value as u16, 0, 0)
    }

    /// `SET_INTERFACE` (selects an alternate setting).
    pub const fn set_interface(interface: u8, alternate: u8) -> Self {
        let req = request::SET_INTERFACE;
        Self::new(
            Direction::Out,
            RequestKind::Standard,
            Recipient::Interface,
            req,
            alternate as u16,
            interface as u16,
            0,
        )
    }

    /// `CLEAR_FEATURE(ENDPOINT_HALT)` for endpoint address `endpoint`.
    pub const fn clear_halt(endpoint: u8) -> Self {
        let req = request::CLEAR_FEATURE;
        Self::new(Direction::Out, RequestKind::Standard, Recipient::Endpoint, req, 0, endpoint as u16, 0)
    }

    /// Direction of the data stage.
    pub const fn direction(&self) -> Direction {
        if self.request_type & 0x80 != 0 { Direction::In } else { Direction::Out }
    }

    /// The packet as sent on the wire (little-endian).
    pub const fn to_bytes(&self) -> [u8; 8] {
        let [v0, v1] = self.value.to_le_bytes();
        let [i0, i1] = self.index.to_le_bytes();
        let [l0, l1] = self.length.to_le_bytes();
        [self.request_type, self.request, v0, v1, i0, i1, l0, l1]
    }

    /// The packet as a little-endian `u64`, the form xHCI Setup Stage TRBs
    /// carry it in.
    pub const fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.to_bytes())
    }
}

/// Bus speed of an attached device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Speed {
    /// 1.5 Mb/s.
    Low,
    /// 12 Mb/s.
    Full,
    /// 480 Mb/s.
    High,
    /// 5 Gb/s.
    Super,
    /// 10 Gb/s or more.
    SuperPlus,
}

impl Speed {
    /// Default `bMaxPacketSize0` before the device descriptor is read.
    pub const fn default_max_packet0(self) -> u16 {
        match self {
            Speed::Low | Speed::Full => 8,
            Speed::High => 64,
            Speed::Super | Speed::SuperPlus => 512,
        }
    }
}

/// A descriptor was shorter than its type requires, or the wrong type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadDescriptor;

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn check(bytes: &[u8], ty: u8, len: usize) -> Result<(), BadDescriptor> {
    if bytes.len() < len || (bytes[0] as usize) < len || bytes[1] != ty {
        return Err(BadDescriptor);
    }
    Ok(())
}

/// The standard device descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceDescriptor {
    /// `bcdUSB`.
    pub usb_version: u16,
    /// `bDeviceClass`.
    pub class: u8,
    /// `bDeviceSubClass`.
    pub subclass: u8,
    /// `bDeviceProtocol`.
    pub protocol: u8,
    /// `bMaxPacketSize0`: a byte count before USB 3, an exponent from USB 3
    /// (use [`DeviceDescriptor::max_packet_size0`]).
    pub max_packet_size0_raw: u8,
    /// `idVendor`.
    pub vendor_id: u16,
    /// `idProduct`.
    pub product_id: u16,
    /// `bcdDevice`.
    pub device_version: u16,
    /// `iManufacturer`.
    pub manufacturer_index: u8,
    /// `iProduct`.
    pub product_index: u8,
    /// `iSerialNumber`.
    pub serial_index: u8,
    /// `bNumConfigurations`.
    pub num_configurations: u8,
}

impl DeviceDescriptor {
    /// Bytes on the wire.
    pub const LEN: usize = 18;

    /// Parses a device descriptor.
    pub fn parse(b: &[u8]) -> Result<Self, BadDescriptor> {
        check(b, descriptor_type::DEVICE, Self::LEN)?;
        Ok(Self {
            usb_version: le16(b, 2),
            class: b[4],
            subclass: b[5],
            protocol: b[6],
            max_packet_size0_raw: b[7],
            vendor_id: le16(b, 8),
            product_id: le16(b, 10),
            device_version: le16(b, 12),
            manufacturer_index: b[14],
            product_index: b[15],
            serial_index: b[16],
            num_configurations: b[17],
        })
    }

    /// Endpoint 0's maximum packet size in bytes.
    pub fn max_packet_size0(&self) -> u16 {
        if self.usb_version >= 0x0300 {
            1 << self.max_packet_size0_raw.min(15)
        } else {
            self.max_packet_size0_raw as u16
        }
    }
}

/// The 9-byte header of a configuration descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigurationDescriptor {
    /// `wTotalLength`: the header plus every interface, endpoint and class
    /// descriptor that follows it.
    pub total_length: u16,
    /// `bNumInterfaces`.
    pub num_interfaces: u8,
    /// `bConfigurationValue`, the argument to `SET_CONFIGURATION`.
    pub value: u8,
    /// `iConfiguration`.
    pub string_index: u8,
    /// `bmAttributes`.
    pub attributes: u8,
    /// `bMaxPower`, in 2 mA units (8 mA for SuperSpeed).
    pub max_power: u8,
}

impl ConfigurationDescriptor {
    /// Bytes on the wire.
    pub const LEN: usize = 9;

    /// Parses the header of a configuration descriptor.
    pub fn parse(b: &[u8]) -> Result<Self, BadDescriptor> {
        check(b, descriptor_type::CONFIGURATION, Self::LEN)?;
        Ok(Self {
            total_length: le16(b, 2),
            num_interfaces: b[4],
            value: b[5],
            string_index: b[6],
            attributes: b[7],
            max_power: b[8],
        })
    }
}

/// An interface descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfaceDescriptor {
    /// `bInterfaceNumber`.
    pub number: u8,
    /// `bAlternateSetting`.
    pub alternate: u8,
    /// `bNumEndpoints`, not counting endpoint 0.
    pub num_endpoints: u8,
    /// `bInterfaceClass`.
    pub class: u8,
    /// `bInterfaceSubClass`.
    pub subclass: u8,
    /// `bInterfaceProtocol`.
    pub protocol: u8,
    /// `iInterface`.
    pub string_index: u8,
}

impl InterfaceDescriptor {
    /// Bytes on the wire.
    pub const LEN: usize = 9;

    /// Parses an interface descriptor.
    pub fn parse(b: &[u8]) -> Result<Self, BadDescriptor> {
        check(b, descriptor_type::INTERFACE, Self::LEN)?;
        Ok(Self {
            number: b[2],
            alternate: b[3],
            num_endpoints: b[4],
            class: b[5],
            subclass: b[6],
            protocol: b[7],
            string_index: b[8],
        })
    }
}

/// Transfer type of an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferType {
    /// Control.
    Control,
    /// Isochronous.
    Isochronous,
    /// Bulk.
    Bulk,
    /// Interrupt.
    Interrupt,
}

/// An endpoint descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointDescriptor {
    /// `bEndpointAddress`: number in bits 0–3, bit 7 set for IN.
    pub address: u8,
    /// `bmAttributes`.
    pub attributes: u8,
    /// `wMaxPacketSize`, including the high-bandwidth bits 11–12.
    pub max_packet_size_raw: u16,
    /// `bInterval`.
    pub interval: u8,
}

impl EndpointDescriptor {
    /// Bytes on the wire.
    pub const LEN: usize = 7;

    /// Parses an endpoint descriptor.
    pub fn parse(b: &[u8]) -> Result<Self, BadDescriptor> {
        check(b, descriptor_type::ENDPOINT, Self::LEN)?;
        Ok(Self { address: b[2], attributes: b[3], max_packet_size_raw: le16(b, 4), interval: b[6] })
    }

    /// Endpoint number, 1–15.
    pub const fn number(&self) -> u8 {
        self.address & 0xf
    }

    /// Direction of data flow.
    pub const fn direction(&self) -> Direction {
        if self.address & 0x80 != 0 { Direction::In } else { Direction::Out }
    }

    /// Transfer type.
    pub const fn transfer_type(&self) -> TransferType {
        match self.attributes & 3 {
            0 => TransferType::Control,
            1 => TransferType::Isochronous,
            2 => TransferType::Bulk,
            _ => TransferType::Interrupt,
        }
    }

    /// Maximum packet size in bytes.
    pub const fn max_packet_size(&self) -> u16 {
        self.max_packet_size_raw & 0x7ff
    }

    /// Additional transactions per microframe for high-speed periodic
    /// endpoints (0–2).
    pub const fn extra_transactions(&self) -> u8 {
        (self.max_packet_size_raw >> 11 & 3) as u8
    }
}

/// One descriptor from a configuration descriptor set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Descriptor<'src> {
    /// The configuration header.
    Configuration(ConfigurationDescriptor),
    /// An interface.
    Interface(InterfaceDescriptor),
    /// An endpoint of the most recent interface.
    Endpoint(EndpointDescriptor),
    /// Anything else (class-specific, companion, association), as raw bytes
    /// including the two-byte header.
    Other(&'src [u8]),
}

/// Walks the descriptors in a configuration descriptor set (the bytes
/// returned by `GET_DESCRIPTOR(CONFIGURATION)` with `wTotalLength` bytes).
///
/// Iteration stops at the end of the buffer or at a malformed descriptor
/// (a length below 2 or past the end), which it yields as `Err` once.
#[derive(Clone)]
pub struct Descriptors<'src> {
    rest: &'src [u8],
}

impl<'src> Descriptors<'src> {
    /// Iterates over `bytes`.
    pub fn new(bytes: &'src [u8]) -> Self {
        Self { rest: bytes }
    }
}

impl<'src> Iterator for Descriptors<'src> {
    type Item = Result<Descriptor<'src>, BadDescriptor>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let len = self.rest[0] as usize;
        if len < 2 || len > self.rest.len() {
            self.rest = &[];
            return Some(Err(BadDescriptor));
        }
        let (d, rest) = self.rest.split_at(len);
        self.rest = rest;
        Some(match d[1] {
            descriptor_type::CONFIGURATION => ConfigurationDescriptor::parse(d).map(Descriptor::Configuration),
            descriptor_type::INTERFACE => InterfaceDescriptor::parse(d).map(Descriptor::Interface),
            descriptor_type::ENDPOINT => EndpointDescriptor::parse(d).map(Descriptor::Endpoint),
            _ => Ok(Descriptor::Other(d)),
        })
    }
}

/// Why a USB operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbError {
    /// The device returned STALL; for a control transfer the request is not
    /// supported, for others the endpoint must be cleared.
    Stall,
    /// No response, CRC error or babble.
    Transaction,
    /// The device was unplugged or the slot is not enabled.
    NoDevice,
    /// The controller has no free slots, ring space or buffers.
    NoResources,
    /// The endpoint already has an outstanding transfer.
    Busy,
    /// The endpoint has not been configured.
    BadEndpoint,
    /// The device or its descriptors are malformed.
    BadDescriptor,
    /// The operation did not complete in time.
    Timeout,
    /// The controller reported an internal error.
    Controller,
}

impl From<BadDescriptor> for UsbError {
    fn from(_: BadDescriptor) -> Self {
        UsbError::BadDescriptor
    }
}

impl fmt::Display for UsbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Handle for an addressed device on one [`UsbHost`]. Its meaning belongs to
/// the controller (an xHCI slot id, an EHCI device address).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceId(pub u8);

/// State of a root-hub port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortStatus {
    /// A device is attached.
    pub connected: bool,
    /// The port is enabled (reset completed).
    pub enabled: bool,
    /// Speed of the attached device, if known.
    pub speed: Option<Speed>,
}

/// A USB host controller, as class drivers see it.
///
/// Transfers are synchronous: they return when the controller reports
/// completion. Ports are numbered from 1, as in the xHCI and USB hub
/// specifications.
pub trait UsbHost {
    /// Number of root-hub ports.
    fn num_ports(&self) -> u8;

    /// State of root-hub port `port`.
    fn port_status(&self, port: u8) -> PortStatus;

    /// Resets the device on `port`, assigns it an address and returns its
    /// handle. Endpoint 0 is usable afterwards.
    fn attach(&mut self, port: u8) -> Result<DeviceId, UsbError>;

    /// Releases a device's resources (after unplug or before re-attaching).
    fn detach(&mut self, dev: DeviceId);

    /// Makes `endpoints` usable on `dev`. Call after `SET_CONFIGURATION` (or
    /// `SET_INTERFACE`) with the endpoints of the selected interfaces.
    fn configure_endpoints(&mut self, dev: DeviceId, endpoints: &[EndpointDescriptor]) -> Result<(), UsbError>;

    /// Control transfer on endpoint 0 with an IN or no data stage; returns
    /// the bytes received. `buf.len()` must be at least `setup.length`.
    fn control_in(&mut self, dev: DeviceId, setup: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError>;

    /// Control transfer on endpoint 0 with an OUT or no data stage. `data`
    /// must be `setup.length` bytes.
    fn control_out(&mut self, dev: DeviceId, setup: SetupPacket, data: &[u8]) -> Result<(), UsbError>;

    /// Bulk or interrupt IN transfer on endpoint address `endpoint`; returns
    /// the bytes received, which may be fewer than `buf.len()`.
    fn transfer_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Result<usize, UsbError>;

    /// Bulk or interrupt OUT transfer on endpoint address `endpoint`. Empty
    /// `data` sends one zero-length packet, which ends a transfer whose last
    /// packet was full (CDC-ECM frames, for one).
    fn transfer_out(&mut self, dev: DeviceId, endpoint: u8, data: &[u8]) -> Result<(), UsbError>;

    /// Starts a bulk or interrupt IN transfer of up to `len` bytes on
    /// endpoint address `endpoint` without waiting for it, as a keyboard's
    /// interrupt endpoint needs. One may be outstanding per endpoint; other
    /// transfers on it fail with [`UsbError::Busy`] until it is collected.
    fn submit_in(&mut self, dev: DeviceId, endpoint: u8, len: usize) -> Result<(), UsbError>;

    /// Collects the transfer started by [`submit_in`](Self::submit_in):
    /// `None` while it is still pending, else the bytes copied into `buf`.
    /// Returns `Some(Err(BadEndpoint))` if none was submitted.
    fn poll_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>>;
}

/// A borrowed host controller, so a class driver can use one it does not own.
impl<H: UsbHost + ?Sized> UsbHost for &mut H {
    fn num_ports(&self) -> u8 {
        (**self).num_ports()
    }
    fn port_status(&self, port: u8) -> PortStatus {
        (**self).port_status(port)
    }
    fn attach(&mut self, port: u8) -> Result<DeviceId, UsbError> {
        (**self).attach(port)
    }
    fn detach(&mut self, dev: DeviceId) {
        (**self).detach(dev)
    }
    fn configure_endpoints(&mut self, dev: DeviceId, endpoints: &[EndpointDescriptor]) -> Result<(), UsbError> {
        (**self).configure_endpoints(dev, endpoints)
    }
    fn control_in(&mut self, dev: DeviceId, setup: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError> {
        (**self).control_in(dev, setup, buf)
    }
    fn control_out(&mut self, dev: DeviceId, setup: SetupPacket, data: &[u8]) -> Result<(), UsbError> {
        (**self).control_out(dev, setup, data)
    }
    fn transfer_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Result<usize, UsbError> {
        (**self).transfer_in(dev, endpoint, buf)
    }
    fn transfer_out(&mut self, dev: DeviceId, endpoint: u8, data: &[u8]) -> Result<(), UsbError> {
        (**self).transfer_out(dev, endpoint, data)
    }
    fn submit_in(&mut self, dev: DeviceId, endpoint: u8, len: usize) -> Result<(), UsbError> {
        (**self).submit_in(dev, endpoint, len)
    }
    fn poll_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
        (**self).poll_in(dev, endpoint, buf)
    }
}

/// A host controller behind a lock, so that several class drivers (a disk
/// and a keyboard, say) can each hold the controller they share. Every
/// call holds the lock for its whole duration.
impl<H: UsbHost + ?Sized, G: osmium_sync::Guardian> UsbHost for &osmium_sync::SpinLock<H, G> {
    fn num_ports(&self) -> u8 {
        self.lock().num_ports()
    }
    fn port_status(&self, port: u8) -> PortStatus {
        self.lock().port_status(port)
    }
    fn attach(&mut self, port: u8) -> Result<DeviceId, UsbError> {
        self.lock().attach(port)
    }
    fn detach(&mut self, dev: DeviceId) {
        self.lock().detach(dev)
    }
    fn configure_endpoints(&mut self, dev: DeviceId, endpoints: &[EndpointDescriptor]) -> Result<(), UsbError> {
        self.lock().configure_endpoints(dev, endpoints)
    }
    fn control_in(&mut self, dev: DeviceId, setup: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError> {
        self.lock().control_in(dev, setup, buf)
    }
    fn control_out(&mut self, dev: DeviceId, setup: SetupPacket, data: &[u8]) -> Result<(), UsbError> {
        self.lock().control_out(dev, setup, data)
    }
    fn transfer_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Result<usize, UsbError> {
        self.lock().transfer_in(dev, endpoint, buf)
    }
    fn transfer_out(&mut self, dev: DeviceId, endpoint: u8, data: &[u8]) -> Result<(), UsbError> {
        self.lock().transfer_out(dev, endpoint, data)
    }
    fn submit_in(&mut self, dev: DeviceId, endpoint: u8, len: usize) -> Result<(), UsbError> {
        self.lock().submit_in(dev, endpoint, len)
    }
    fn poll_in(&mut self, dev: DeviceId, endpoint: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
        self.lock().poll_in(dev, endpoint, buf)
    }
}

/// An interface's alternate setting 0 and its endpoints, as found by
/// [`find_interface`].
#[derive(Clone, Copy, Debug)]
pub struct Interface {
    /// The interface descriptor.
    pub descriptor: InterfaceDescriptor,
    endpoints: [Option<EndpointDescriptor>; 16],
}

impl Interface {
    /// The interface's endpoints.
    pub fn endpoints(&self) -> impl Iterator<Item = EndpointDescriptor> + '_ {
        self.endpoints.iter().flatten().copied()
    }

    /// The first endpoint of type `ty` in direction `dir`.
    pub fn endpoint(&self, ty: TransferType, dir: Direction) -> Option<EndpointDescriptor> {
        self.endpoints().find(|e| e.transfer_type() == ty && e.direction() == dir)
    }
}

/// Finds the first interface (alternate setting 0) in a configuration
/// descriptor set for which `matches` holds, with its endpoints.
pub fn find_interface(config: &[u8], matches: impl Fn(&InterfaceDescriptor) -> bool) -> Option<Interface> {
    let mut found: Option<Interface> = None;
    for d in Descriptors::new(config) {
        match d.ok()? {
            // The next interface (or alternate setting) starts: the
            // endpoints that follow are not ours.
            Descriptor::Interface(_) if found.is_some() => break,
            Descriptor::Interface(i) if i.alternate == 0 && matches(&i) => {
                found = Some(Interface { descriptor: i, endpoints: [None; 16] });
            }
            Descriptor::Endpoint(e) => {
                if let Some(slot) = found.as_mut().and_then(|f| f.endpoints.iter_mut().find(|s| s.is_none())) {
                    *slot = Some(e);
                }
            }
            _ => {}
        }
    }
    found
}

/// A device after [`enumerate`]: addressed, configured, and with the
/// endpoints of its first configuration's default interfaces enabled.
#[derive(Clone, Copy, Debug)]
pub struct Enumerated {
    /// Handle for further transfers.
    pub id: DeviceId,
    /// Its device descriptor.
    pub device: DeviceDescriptor,
    /// Header of the selected configuration.
    pub config: ConfigurationDescriptor,
    /// Bytes of the configuration descriptor set written to the caller's
    /// buffer (walk them with [`Descriptors`] to find interfaces).
    pub config_len: usize,
}

/// Attaches the device on `port`, reads its descriptors, selects its first
/// configuration and enables the endpoints of every interface's alternate
/// setting 0.
///
/// `config_buf` receives the configuration descriptor set; if it is shorter
/// than `wTotalLength`, only endpoints described within it are enabled.
pub fn enumerate<H: UsbHost + ?Sized>(host: &mut H, port: u8, config_buf: &mut [u8]) -> Result<Enumerated, UsbError> {
    let id = host.attach(port)?;
    let result = configure(host, id, config_buf);
    if result.is_err() {
        host.detach(id);
    }
    result
}

/// Reads the configuration descriptor set at `index` (0 to
/// `bNumConfigurations` - 1) into `config_buf` and returns its length, which
/// is `wTotalLength` or `config_buf.len()` if that is shorter. Does not
/// select it: for a device with several configurations, pass the set you
/// want to [`set_configuration`].
pub fn read_configuration<H: UsbHost + ?Sized>(
    host: &mut H,
    dev: DeviceId,
    index: u8,
    config_buf: &mut [u8],
) -> Result<usize, UsbError> {
    let mut header = [0u8; ConfigurationDescriptor::LEN];
    let setup = SetupPacket::get_descriptor(descriptor_type::CONFIGURATION, index, header.len() as u16);
    let n = host.control_in(dev, setup, &mut header)?;
    let config = ConfigurationDescriptor::parse(&header[..n])?;
    let want = (config.total_length as usize).min(config_buf.len());
    let setup = SetupPacket::get_descriptor(descriptor_type::CONFIGURATION, index, want as u16);
    host.control_in(dev, setup, &mut config_buf[..want])
}

/// Selects the configuration whose descriptor set is `config` (as returned
/// by [`read_configuration`]) and enables the endpoints of every interface's
/// alternate setting 0. [`enumerate`] does this for configuration 0; call it
/// again to switch to another. Endpoints the previous configuration enabled
/// are not disabled.
pub fn set_configuration<H: UsbHost + ?Sized>(
    host: &mut H,
    dev: DeviceId,
    config: &[u8],
) -> Result<ConfigurationDescriptor, UsbError> {
    let header = ConfigurationDescriptor::parse(config)?;
    host.control_out(dev, SetupPacket::set_configuration(header.value), &[])?;

    const MAX_ENDPOINTS: usize = 30;
    let mut endpoints =
        [EndpointDescriptor { address: 0, attributes: 0, max_packet_size_raw: 0, interval: 0 }; MAX_ENDPOINTS];
    let mut count = 0;
    let mut in_default = false;
    for d in Descriptors::new(config) {
        match d? {
            Descriptor::Interface(i) => in_default = i.alternate == 0,
            Descriptor::Endpoint(e) if in_default && count < MAX_ENDPOINTS => {
                endpoints[count] = e;
                count += 1;
            }
            _ => {}
        }
    }
    if count > 0 {
        host.configure_endpoints(dev, &endpoints[..count])?;
    }
    Ok(header)
}

fn configure<H: UsbHost + ?Sized>(host: &mut H, id: DeviceId, config_buf: &mut [u8]) -> Result<Enumerated, UsbError> {
    let mut buf = [0u8; DeviceDescriptor::LEN];
    let setup = SetupPacket::get_descriptor(descriptor_type::DEVICE, 0, buf.len() as u16);
    let n = host.control_in(id, setup, &mut buf)?;
    let device = DeviceDescriptor::parse(&buf[..n])?;

    let config_len = read_configuration(host, id, 0, config_buf)?;
    let config = set_configuration(host, id, &config_buf[..config_len])?;
    Ok(Enumerated { id, device, config, config_len })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    // A USB 2.0 mass-storage stick: one interface, bulk IN 0x81 and OUT 0x02,
    // plus an alternate setting whose endpoint must be ignored.
    const DEVICE: [u8; 18] = [18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x81, 0x07, 0x81, 0x55, 0x00, 0x01, 1, 2, 3, 1];
    const CONFIG: [u8; 48] = [
        9, 2, 48, 0, 1, 1, 0, 0x80, 50, // configuration
        9, 4, 0, 0, 2, 8, 6, 0x50, 0, // interface 0 alt 0: mass storage BOT
        7, 5, 0x81, 2, 0x00, 0x02, 0, // bulk IN 512
        7, 5, 0x02, 2, 0x00, 0x02, 0, // bulk OUT 512
        9, 4, 0, 1, 1, 8, 6, 0x62, 0, // interface 0 alt 1: UAS
        7, 5, 0x83, 2, 0x00, 0x02, 0, // bulk IN (alt 1 only)
    ];

    #[test]
    fn setup_packet_encoding() {
        let s = SetupPacket::get_descriptor(descriptor_type::DEVICE, 0, 18);
        assert_eq!(s.to_bytes(), [0x80, 6, 0, 1, 0, 0, 18, 0]);
        assert_eq!(s.direction(), Direction::In);
        assert_eq!(SetupPacket::set_address(5).to_bytes(), [0, 5, 5, 0, 0, 0, 0, 0]);
        assert_eq!(SetupPacket::clear_halt(0x81).to_bytes(), [2, 1, 0, 0, 0x81, 0, 0, 0]);
        assert_eq!(SetupPacket::set_interface(1, 2).request_type, 1);
        assert_eq!(s.to_u64() & 0xff, 0x80);
    }

    #[test]
    fn parse_descriptors() {
        let d = DeviceDescriptor::parse(&DEVICE).unwrap();
        assert_eq!((d.vendor_id, d.product_id, d.max_packet_size0()), (0x0781, 0x5581, 64));
        let mut usb3 = DEVICE;
        usb3[2..4].copy_from_slice(&[0x20, 0x03]);
        usb3[7] = 9;
        assert_eq!(DeviceDescriptor::parse(&usb3).unwrap().max_packet_size0(), 512);
        assert_eq!(DeviceDescriptor::parse(&DEVICE[..10]), Err(BadDescriptor));
        assert_eq!(ConfigurationDescriptor::parse(&DEVICE), Err(BadDescriptor));

        let all: Vec<_> = Descriptors::new(&CONFIG).map(Result::unwrap).collect();
        assert_eq!(all.len(), 6);
        let Descriptor::Endpoint(ep) = all[2] else { panic!() };
        assert_eq!(
            (ep.number(), ep.direction(), ep.transfer_type(), ep.max_packet_size()),
            (1, Direction::In, TransferType::Bulk, 512)
        );
        let Descriptor::Interface(alt) = all[4] else { panic!() };
        assert_eq!((alt.alternate, alt.protocol), (1, 0x62));
    }

    #[test]
    fn truncated_descriptor_set() {
        let mut it = Descriptors::new(&CONFIG[..12]);
        assert!(matches!(it.next(), Some(Ok(Descriptor::Configuration(_)))));
        assert_eq!(it.next(), Some(Err(BadDescriptor)));
        assert_eq!(it.next(), None);
        assert_eq!(Descriptors::new(&[0, 4]).next(), Some(Err(BadDescriptor)));
    }

    #[derive(Default)]
    struct FakeHost {
        configured: Vec<u8>,
        set_config: Option<u16>,
        detached: bool,
    }

    impl UsbHost for FakeHost {
        fn num_ports(&self) -> u8 {
            1
        }
        fn port_status(&self, _: u8) -> PortStatus {
            PortStatus { connected: true, enabled: false, speed: Some(Speed::High) }
        }
        fn attach(&mut self, port: u8) -> Result<DeviceId, UsbError> {
            if port == 1 { Ok(DeviceId(1)) } else { Err(UsbError::NoDevice) }
        }
        fn detach(&mut self, _: DeviceId) {
            self.detached = true;
        }
        fn configure_endpoints(&mut self, _: DeviceId, eps: &[EndpointDescriptor]) -> Result<(), UsbError> {
            self.configured.extend(eps.iter().map(|e| e.address));
            Ok(())
        }
        fn control_in(&mut self, _: DeviceId, s: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError> {
            let src: &[u8] = match s.value >> 8 {
                1 => &DEVICE,
                2 => &CONFIG,
                _ => return Err(UsbError::Stall),
            };
            let n = src.len().min(s.length as usize);
            buf[..n].copy_from_slice(&src[..n]);
            Ok(n)
        }
        fn control_out(&mut self, _: DeviceId, s: SetupPacket, _: &[u8]) -> Result<(), UsbError> {
            assert_eq!(s.request, request::SET_CONFIGURATION);
            self.set_config = Some(s.value);
            Ok(())
        }
        fn transfer_in(&mut self, _: DeviceId, _: u8, _: &mut [u8]) -> Result<usize, UsbError> {
            unimplemented!()
        }
        fn transfer_out(&mut self, _: DeviceId, _: u8, _: &[u8]) -> Result<(), UsbError> {
            unimplemented!()
        }
        fn submit_in(&mut self, _: DeviceId, _: u8, _: usize) -> Result<(), UsbError> {
            unimplemented!()
        }
        fn poll_in(&mut self, _: DeviceId, _: u8, _: &mut [u8]) -> Option<Result<usize, UsbError>> {
            unimplemented!()
        }
    }

    #[test]
    fn find_interface_and_endpoints() {
        let msc = find_interface(&CONFIG, |i| i.class == 8 && i.protocol == 0x50).unwrap();
        assert_eq!(msc.endpoints().count(), 2, "alternate setting 1's endpoint is excluded");
        assert_eq!(msc.endpoint(TransferType::Bulk, Direction::In).map(|e| e.address), Some(0x81));
        assert_eq!(msc.endpoint(TransferType::Bulk, Direction::Out).map(|e| e.address), Some(0x02));
        assert!(msc.endpoint(TransferType::Interrupt, Direction::In).is_none());
        assert!(find_interface(&CONFIG, |i| i.class == 3).is_none());
    }

    #[test]
    fn enumerate_selects_first_configuration() {
        let mut host = FakeHost::default();
        let mut buf = [0u8; 256];
        let dev = enumerate(&mut host, 1, &mut buf).unwrap();
        assert_eq!(dev.id, DeviceId(1));
        assert_eq!(dev.config_len, CONFIG.len());
        assert_eq!(host.set_config, Some(1));
        assert_eq!(host.configured, [0x81, 0x02], "alternate setting 1 is not enabled");
        assert!(enumerate(&mut host, 2, &mut buf).is_err());
    }
}
