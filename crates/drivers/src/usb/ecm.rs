//! USB Ethernet, CDC Ethernet Control Model (communications class 02/06/00).
//!
//! An ECM function is two interfaces: a communications interface carrying
//! the class-specific functional descriptors (a Union naming the data
//! interface, and an Ethernet Networking descriptor holding the MAC address
//! as a string index and the maximum frame size) plus an interrupt IN
//! endpoint for notifications, and a data interface (class 0a) whose
//! alternate setting 0 has no endpoints and whose alternate setting 1 has a
//! bulk IN and a bulk OUT endpoint. Each Ethernet frame is one bulk
//! transfer, ended by a short packet.
//!
//! [`UsbEthernet::new`] selects alternate setting 1, enables its bulk
//! endpoints, opens the packet filter and leaves one bulk IN transfer
//! outstanding; [`NetDevice::receive`] collects it without waiting. Link
//! state comes from the interrupt endpoint's `NETWORK_CONNECTION`
//! notifications (the device is assumed up until one says otherwise).
//!
//! Transmitting a frame whose length is a multiple of the endpoint's packet
//! size sends an empty packet after it, through
//! [`UsbHost::transfer_out`] with no data; hosts must send a zero-length
//! packet for that (xHCI does).

use osmium_hal::net::{MacAddress, NetDevice, NetError};
use osmium_hal::usb::{
    Descriptor, Descriptors, DeviceId, Direction, EndpointDescriptor, Recipient, RequestKind, SetupPacket,
    TransferType, UsbError, UsbHost, descriptor_type,
};

/// Class code of a communications interface.
pub const CLASS_COMMUNICATIONS: u8 = 0x02;
/// Subclass code of the Ethernet Control Model.
pub const SUBCLASS_ECM: u8 = 0x06;
/// Class code of a CDC data interface.
pub const CLASS_DATA: u8 = 0x0a;

/// `bDescriptorType` of class-specific interface descriptors.
const CS_INTERFACE: u8 = 0x24;
const SUBTYPE_UNION: u8 = 0x06;
const SUBTYPE_ETHERNET: u8 = 0x0f;

const SET_ETHERNET_PACKET_FILTER: u8 = 0x43;
/// Packet filter bits (CDC ECM table 62).
pub mod filter {
    #![allow(missing_docs)]
    pub const PROMISCUOUS: u16 = 1 << 0;
    pub const ALL_MULTICAST: u16 = 1 << 1;
    pub const DIRECTED: u16 = 1 << 2;
    pub const BROADCAST: u16 = 1 << 3;
    pub const MULTICAST: u16 = 1 << 4;
}

/// Notification codes (`bNotificationCode`).
const NETWORK_CONNECTION: u8 = 0x00;

/// Bytes of the receive buffer, which bounds the frame size.
pub const RX_BUF_LEN: usize = 2048;

/// Largest frame accepted if the device does not say.
const DEFAULT_SEGMENT: u16 = 1514;

/// A data interface alternate setting being collected: interface, alternate,
/// bulk IN, bulk OUT.
type Candidate = Option<(u8, u8, Option<EndpointDescriptor>, Option<EndpointDescriptor>)>;

/// The parts of a CDC-ECM function found in a configuration descriptor set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcmFunction {
    /// Number of the communications interface (`wIndex` of class requests).
    pub control_interface: u8,
    /// Number of the data interface.
    pub data_interface: u8,
    /// The data interface's alternate setting with the bulk endpoints.
    pub data_alternate: u8,
    /// `iMACAddress`: index of the string holding the MAC address.
    pub mac_string: u8,
    /// `wMaxSegmentSize`: the largest frame the device handles.
    pub max_segment: u16,
    /// The notification endpoint, if the communications interface has one.
    pub interrupt: Option<EndpointDescriptor>,
    /// Bulk IN endpoint of the data interface.
    pub bulk_in: EndpointDescriptor,
    /// Bulk OUT endpoint of the data interface.
    pub bulk_out: EndpointDescriptor,
}

impl EcmFunction {
    /// Finds an ECM function in the configuration descriptor set `config`:
    /// a 02/06 communications interface whose Ethernet Networking descriptor
    /// is present and whose Union descriptor (if any) names a data interface
    /// with an alternate setting that has a bulk IN and a bulk OUT endpoint.
    /// Returns `None` for anything else, including truncated descriptors.
    pub fn parse(config: &[u8]) -> Option<Self> {
        let mut control: Option<u8> = None;
        let mut in_control = false;
        let mut union_data: Option<u8> = None;
        let mut ethernet: Option<(u8, u16)> = None;
        let mut interrupt = None;
        // The data interface alternate settings seen so far, with their bulk
        // endpoints; the first complete one for the right interface wins.
        let mut candidate: Candidate = None;
        let mut data: Option<(u8, u8, EndpointDescriptor, EndpointDescriptor)> = None;
        // Closes the alternate setting being collected: it is the data
        // interface if complete, and the union (if any) names its interface.
        fn finish(
            c: &mut Candidate,
            union_data: Option<u8>,
            data: &mut Option<(u8, u8, EndpointDescriptor, EndpointDescriptor)>,
        ) {
            if let Some((n, alt, Some(i), Some(o))) = c.take()
                && data.is_none()
                && union_data.is_none_or(|u| u == n)
            {
                *data = Some((n, alt, i, o));
            }
        }
        for d in Descriptors::new(config) {
            match d.ok()? {
                Descriptor::Interface(i) => {
                    finish(&mut candidate, union_data, &mut data);
                    in_control = i.class == CLASS_COMMUNICATIONS && i.subclass == SUBCLASS_ECM && i.alternate == 0;
                    if in_control && control.is_none() {
                        control = Some(i.number);
                    } else {
                        in_control &= control == Some(i.number);
                    }
                    if i.class == CLASS_DATA && i.alternate != 0 {
                        candidate = Some((i.number, i.alternate, None, None));
                    }
                }
                Descriptor::Endpoint(e) => {
                    if in_control && e.transfer_type() == TransferType::Interrupt && e.direction() == Direction::In {
                        interrupt.get_or_insert(e);
                    }
                    if let Some((_, _, i, o)) = &mut candidate
                        && e.transfer_type() == TransferType::Bulk
                    {
                        match e.direction() {
                            Direction::In => _ = i.get_or_insert(e),
                            Direction::Out => _ = o.get_or_insert(e),
                        }
                    }
                }
                Descriptor::Other(d) if in_control && d[1] == CS_INTERFACE && d.len() >= 3 => match d[2] {
                    SUBTYPE_UNION if d.len() >= 5 && union_data.is_none() => union_data = Some(d[4]),
                    SUBTYPE_ETHERNET if d.len() >= 13 && ethernet.is_none() => {
                        ethernet = Some((d[3], u16::from_le_bytes([d[8], d[9]])));
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        finish(&mut candidate, union_data, &mut data);
        let (mac_string, max_segment) = ethernet?;
        let (data_interface, data_alternate, bulk_in, bulk_out) = data?;
        Some(Self {
            control_interface: control?,
            data_interface,
            data_alternate,
            mac_string,
            max_segment: if max_segment == 0 { DEFAULT_SEGMENT } else { max_segment },
            interrupt,
            bulk_in,
            bulk_out,
        })
    }
}

/// Parses a string descriptor holding a MAC address as 12 hexadecimal
/// UTF-16 characters (`"525400123456"`, upper or lower case).
pub fn parse_mac_string(descriptor: &[u8]) -> Option<MacAddress> {
    if descriptor.len() < 2 + 24 || descriptor[1] != descriptor_type::STRING || descriptor[0] as usize != 2 + 24 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        let digit = |k: usize| {
            let at = 2 + (i * 2 + k) * 2;
            match (descriptor[at], descriptor[at + 1]) {
                (c, 0) => (c as char).to_digit(16),
                _ => None,
            }
        };
        *byte = (digit(0)? << 4 | digit(1)?) as u8;
    }
    Some(MacAddress(mac))
}

/// A device notification from the interrupt endpoint (CDC 6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notification {
    /// `NETWORK_CONNECTION`: the carrier is up or down.
    NetworkConnection(bool),
    /// Another notification, by code.
    Other(u8),
}

/// Parses the 8-byte header of a notification.
pub fn parse_notification(b: &[u8]) -> Option<Notification> {
    // bmRequestType 0xa1 (class, interface, device to host).
    if b.len() < 8 || b[0] != 0xa1 {
        return None;
    }
    Some(match b[1] {
        NETWORK_CONNECTION => Notification::NetworkConnection(u16::from_le_bytes([b[2], b[3]]) != 0),
        code => Notification::Other(code),
    })
}

fn bad(e: UsbError) -> NetError {
    match e {
        UsbError::NoDevice => NetError::LinkDown,
        _ => NetError::Io,
    }
}

/// A CDC-ECM network adapter.
pub struct UsbEthernet<H: UsbHost> {
    host: H,
    dev: DeviceId,
    function: EcmFunction,
    mac: MacAddress,
    link: bool,
    /// Bytes of each bulk IN transfer requested: `wMaxSegmentSize` rounded
    /// up to whole packets, so a full-sized frame ends in a short packet.
    rx_len: usize,
    rx_submitted: bool,
    rx: [u8; RX_BUF_LEN],
    /// Length of the frame waiting in `rx`.
    rx_frame: Option<usize>,
    notify_submitted: bool,
}

impl<H: UsbHost> UsbEthernet<H> {
    /// Brings up the ECM function of the enumerated device `dev`, whose
    /// currently selected configuration's descriptor set is `config` (use
    /// [`osmium_hal::usb::set_configuration`] first if it is not the
    /// device's first). Reads the MAC address, selects the data interface's
    /// bulk alternate setting, enables its endpoints and starts receiving.
    ///
    /// Fails with [`UsbError::BadDescriptor`] if `config` has no ECM
    /// function (see [`EcmFunction::parse`]) or the MAC string is malformed.
    pub fn new(mut host: H, dev: DeviceId, config: &[u8]) -> Result<Self, UsbError> {
        let function = EcmFunction::parse(config).ok_or(UsbError::BadDescriptor)?;
        let mac = read_mac(&mut host, dev, function.mac_string)?;

        let set = SetupPacket::set_interface(function.data_interface, function.data_alternate);
        host.control_out(dev, set, &[])?;
        host.configure_endpoints(dev, &[function.bulk_in, function.bulk_out])?;

        // Accept everything addressed to us, broadcasts (ARP, DHCP) and all
        // multicasts (IPv6 neighbour discovery). Some devices (QEMU's) have
        // no filter and stall the request, which is harmless.
        let accept = filter::DIRECTED | filter::BROADCAST | filter::ALL_MULTICAST;
        let setup = SetupPacket::new(
            Direction::Out,
            RequestKind::Class,
            Recipient::Interface,
            SET_ETHERNET_PACKET_FILTER,
            accept,
            function.control_interface as u16,
            0,
        );
        let _ = host.control_out(dev, setup, &[]);

        let mps = (function.bulk_in.max_packet_size() as usize).max(1);
        let rx_len = (function.max_segment as usize).div_ceil(mps).saturating_mul(mps).clamp(mps, RX_BUF_LEN);
        let mut eth = Self {
            host,
            dev,
            function,
            mac,
            link: true,
            rx_len,
            rx_submitted: false,
            rx: [0; RX_BUF_LEN],
            rx_frame: None,
            notify_submitted: false,
        };
        eth.service().map_err(|_| UsbError::Controller)?;
        Ok(eth)
    }

    /// The device handle.
    pub fn device(&self) -> DeviceId {
        self.dev
    }

    /// The function's descriptors.
    pub fn function(&self) -> &EcmFunction {
        &self.function
    }

    /// Moves along anything the device has finished: notifications, and the
    /// bulk IN transfer into the receive buffer, starting a new one when
    /// the buffer is free. Called by [`receive`](NetDevice::receive) and
    /// [`transmit`](NetDevice::transmit); call it too to keep
    /// [`can_receive`](NetDevice::can_receive) and
    /// [`link_up`](NetDevice::link_up) current without receiving.
    pub fn service(&mut self) -> Result<(), NetError> {
        if let Some(ep) = self.function.interrupt {
            let mut note = [0u8; 16];
            if !self.notify_submitted {
                match self.host.submit_in(self.dev, ep.address, note.len()) {
                    Ok(()) => self.notify_submitted = true,
                    // Notifications are optional; do not fail the link over them.
                    Err(_) => self.function.interrupt = None,
                }
            }
            if self.notify_submitted
                && let Some(done) = self.host.poll_in(self.dev, ep.address, &mut note)
            {
                self.notify_submitted = false;
                if let Ok(n) = done
                    && let Some(Notification::NetworkConnection(up)) = parse_notification(&note[..n.min(16)])
                {
                    self.link = up;
                }
            }
        }
        if self.rx_frame.is_some() {
            return Ok(());
        }
        let ep = self.function.bulk_in.address;
        if !self.rx_submitted {
            self.host.submit_in(self.dev, ep, self.rx_len).map_err(bad)?;
            self.rx_submitted = true;
        }
        if let Some(done) = self.host.poll_in(self.dev, ep, &mut self.rx) {
            self.rx_submitted = false;
            let n = done.map_err(bad)?;
            // An empty packet terminates a frame that filled its last
            // packet; it carries nothing.
            if n > 0 {
                self.rx_frame = Some(n);
            }
        }
        Ok(())
    }
}

/// Reads string `index` and parses it as a MAC address.
fn read_mac<H: UsbHost>(host: &mut H, dev: DeviceId, index: u8) -> Result<MacAddress, UsbError> {
    // String 0 lists the supported language IDs; use the first.
    let mut buf = [0u8; 255];
    let get =
        |index, lang| SetupPacket { index: lang, ..SetupPacket::get_descriptor(descriptor_type::STRING, index, 255) };
    let n = host.control_in(dev, get(0, 0), &mut buf)?;
    let lang = if n >= 4 && buf[1] == descriptor_type::STRING { u16::from_le_bytes([buf[2], buf[3]]) } else { 0x0409 };
    let n = host.control_in(dev, get(index, lang), &mut buf)?;
    parse_mac_string(&buf[..n]).ok_or(UsbError::BadDescriptor)
}

impl<H: UsbHost> NetDevice for UsbEthernet<H> {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn max_frame_len(&self) -> usize {
        (self.function.max_segment as usize).min(self.rx_len)
    }

    fn link_up(&self) -> bool {
        self.link
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError> {
        if frame.len() > self.max_frame_len() {
            return Err(NetError::TooLarge);
        }
        if !self.link {
            return Err(NetError::LinkDown);
        }
        let ep = self.function.bulk_out;
        self.host.transfer_out(self.dev, ep.address, frame).map_err(bad)?;
        if !frame.is_empty() && frame.len().is_multiple_of((ep.max_packet_size() as usize).max(1)) {
            // The transfer ends with a short packet; send an empty one.
            self.host.transfer_out(self.dev, ep.address, &[]).map_err(bad)?;
        }
        // The call blocked for a while: note what arrived meanwhile.
        self.service()
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.service()?;
        let n = self.rx_frame.take().ok_or(NetError::WouldBlock)?;
        let fits = buf.len() >= n;
        if fits {
            buf[..n].copy_from_slice(&self.rx[..n]);
        }
        // Start the next transfer before the caller digests this frame (and
        // after the copy: it may complete into the same buffer).
        let next = self.service();
        if !fits {
            return Err(NetError::TooLarge);
        }
        next.map(|()| n)
    }

    /// True if a frame was already collected by the last call to
    /// [`receive`](Self::receive), [`transmit`](Self::transmit) or
    /// [`service`](UsbEthernet::service). A frame the device finished since
    /// is found by the next `receive`, which returns
    /// [`NetError::WouldBlock`] if there is none.
    fn can_receive(&self) -> bool {
        self.rx_frame.is_some()
    }

    fn can_transmit(&self) -> bool {
        self.link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osmium_hal::usb::PortStatus;
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// QEMU's `usb-net` CDC configuration, as read from it by the demo, with
    /// an interrupt endpoint 0x81 of 16 bytes and bulk 0x02 / 0x83 of 512.
    #[rustfmt::skip]
    const CONFIG: [u8; 80] = [
        9, 2, 80, 0, 2, 1, 0, 0xc0, 50, // configuration 1, two interfaces
        9, 4, 0, 0, 1, 2, 6, 0, 0, // interface 0: CDC ECM control, one endpoint
        5, 0x24, 0x00, 0x10, 0x01, // header
        5, 0x24, 0x06, 0, 1, // union: master 0, slave 1
        13, 0x24, 0x0f, 4, 0, 0, 0, 0, 0xea, 0x05, 0, 0, 0, // Ethernet: iMAC 4, 1514 bytes
        7, 5, 0x81, 3, 16, 0, 11, // interrupt IN
        9, 4, 1, 0, 0, 10, 0, 0, 0, // interface 1 alt 0: no endpoints
        9, 4, 1, 1, 2, 10, 0, 0, 0, // interface 1 alt 1
        7, 5, 0x02, 2, 0x00, 0x02, 0, // bulk OUT 512
        7, 5, 0x83, 2, 0x00, 0x02, 0, // bulk IN 512
    ];

    #[test]
    fn parses_function() {
        assert_eq!(CONFIG.len(), 80);
        let f = EcmFunction::parse(&CONFIG).unwrap();
        assert_eq!((f.control_interface, f.data_interface, f.data_alternate), (0, 1, 1));
        assert_eq!((f.mac_string, f.max_segment), (4, 1514));
        assert_eq!(f.interrupt.map(|e| e.address), Some(0x81));
        assert_eq!((f.bulk_in.address, f.bulk_out.address), (0x83, 0x02));
    }

    #[test]
    fn rejects_non_ecm() {
        // Truncated before the data interface's endpoints.
        assert_eq!(EcmFunction::parse(&CONFIG[..CONFIG.len() - 14]), None);
        // Mass storage.
        let msc = [9, 2, 25, 0, 1, 1, 0, 0x80, 50, 9, 4, 0, 0, 1, 8, 6, 0x50, 0, 7, 5, 0x81, 2, 0, 2, 0];
        assert_eq!(EcmFunction::parse(&msc), None);
        // No Ethernet Networking descriptor (subtype 0x0e is Ethernet's
        // neighbour in the table, the Telephone Call State one).
        let mut no_eth = CONFIG;
        no_eth[30] = 0x0e;
        assert_eq!(EcmFunction::parse(&no_eth), None);
    }

    #[test]
    fn union_picks_the_named_data_interface() {
        // A decoy class-0a interface with bulk endpoints sits before the real
        // one; the union decides which counts.
        let decoy: [u8; 23] = [9, 4, 2, 1, 2, 10, 0, 0, 0, 7, 5, 0x04, 2, 0, 2, 0, 7, 5, 0x85, 2, 0, 2, 0];
        let at = 9 + 9 + 5 + 5 + 13 + 7 + 9;
        let mut c = Vec::from(&CONFIG[..]);
        c.splice(at..at, decoy);
        let f = EcmFunction::parse(&c).unwrap();
        assert_eq!((f.data_interface, f.bulk_in.address, f.bulk_out.address), (1, 0x83, 0x02));
        c[9 + 9 + 5 + 4] = 2; // the union now names interface 2
        let f = EcmFunction::parse(&c).unwrap();
        assert_eq!((f.data_interface, f.bulk_in.address, f.bulk_out.address), (2, 0x85, 0x04));
    }

    fn utf16(s: &str) -> Vec<u8> {
        let mut d = std::vec![0, descriptor_type::STRING];
        for c in s.encode_utf16() {
            d.extend(c.to_le_bytes());
        }
        d[0] = d.len() as u8;
        d
    }

    #[test]
    fn mac_strings() {
        assert_eq!(parse_mac_string(&utf16("525400123456")), Some(MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56])));
        assert_eq!(parse_mac_string(&utf16("AbCdEf012345")), Some(MacAddress([0xab, 0xcd, 0xef, 0x01, 0x23, 0x45])));
        assert_eq!(parse_mac_string(&utf16("52540012345")), None, "too short");
        assert_eq!(parse_mac_string(&utf16("52540012345g")), None, "not hex");
        assert_eq!(parse_mac_string(&utf16("5254001234567")), None, "too long");
        let mut wide = utf16("525400123456");
        wide[3] = 1;
        assert_eq!(parse_mac_string(&wide), None, "non-ASCII code unit");
        let mut not_string = utf16("525400123456");
        not_string[1] = 2;
        assert_eq!(parse_mac_string(&not_string), None);
    }

    #[test]
    fn notifications() {
        let up = [0xa1, 0x00, 1, 0, 1, 0, 0, 0];
        assert_eq!(parse_notification(&up), Some(Notification::NetworkConnection(true)));
        assert_eq!(parse_notification(&[0xa1, 0, 0, 0, 1, 0, 0, 0]), Some(Notification::NetworkConnection(false)));
        assert_eq!(parse_notification(&[0xa1, 0x2a, 0, 0, 1, 0, 8, 0]), Some(Notification::Other(0x2a)));
        assert_eq!(parse_notification(&up[..7]), None);
        assert_eq!(parse_notification(&[0x21, 0, 1, 0, 1, 0, 0, 0]), None);
    }

    /// A device with queues of frames to deliver on bulk IN and notifications
    /// on the interrupt endpoint, recording what the driver does.
    #[derive(Default)]
    struct FakeNic {
        frames: VecDeque<Vec<u8>>,
        notes: VecDeque<[u8; 8]>,
        outstanding: [bool; 2],
        sent: Vec<Vec<u8>>,
        requests: Vec<SetupPacket>,
        configured: Vec<u8>,
        reject_filter: bool,
        submit_lens: Vec<usize>,
    }

    impl UsbHost for FakeNic {
        fn num_ports(&self) -> u8 {
            1
        }
        fn port_status(&self, _: u8) -> PortStatus {
            unimplemented!()
        }
        fn attach(&mut self, _: u8) -> Result<DeviceId, UsbError> {
            unimplemented!()
        }
        fn detach(&mut self, _: DeviceId) {}
        fn configure_endpoints(&mut self, _: DeviceId, eps: &[EndpointDescriptor]) -> Result<(), UsbError> {
            self.configured.extend(eps.iter().map(|e| e.address));
            Ok(())
        }
        fn control_in(&mut self, _: DeviceId, s: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError> {
            self.requests.push(s);
            assert_eq!(s.value >> 8, 3);
            let d = match s.value & 0xff {
                0 => std::vec![4, 3, 0x09, 0x04],
                4 => {
                    assert_eq!(s.index, 0x0409, "the language the device listed");
                    utf16("525400123456")
                }
                _ => return Err(UsbError::Stall),
            };
            buf[..d.len()].copy_from_slice(&d);
            Ok(d.len())
        }
        fn control_out(&mut self, _: DeviceId, s: SetupPacket, _: &[u8]) -> Result<(), UsbError> {
            self.requests.push(s);
            if s.request == SET_ETHERNET_PACKET_FILTER && self.reject_filter { Err(UsbError::Stall) } else { Ok(()) }
        }
        fn transfer_in(&mut self, _: DeviceId, _: u8, _: &mut [u8]) -> Result<usize, UsbError> {
            unimplemented!()
        }
        fn transfer_out(&mut self, _: DeviceId, ep: u8, data: &[u8]) -> Result<(), UsbError> {
            assert_eq!(ep, 0x02);
            self.sent.push(data.to_vec());
            Ok(())
        }
        fn submit_in(&mut self, _: DeviceId, ep: u8, len: usize) -> Result<(), UsbError> {
            let i = (ep == 0x83) as usize;
            assert!(!self.outstanding[i], "one transfer per endpoint");
            self.outstanding[i] = true;
            if i == 1 {
                self.submit_lens.push(len);
            }
            Ok(())
        }
        fn poll_in(&mut self, _: DeviceId, ep: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
            let i = (ep == 0x83) as usize;
            assert!(self.outstanding[i]);
            let data = if i == 1 { self.frames.pop_front()? } else { self.notes.pop_front()?.to_vec() };
            self.outstanding[i] = false;
            buf[..data.len()].copy_from_slice(&data);
            Some(Ok(data.len()))
        }
    }

    fn nic() -> UsbEthernet<FakeNic> {
        UsbEthernet::new(FakeNic::default(), DeviceId(3), &CONFIG).unwrap()
    }

    #[test]
    fn bring_up() {
        let eth = nic();
        assert_eq!(eth.mac_address(), MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]));
        assert_eq!(eth.max_frame_len(), 1514);
        assert!(eth.link_up() && !eth.can_receive());
        let h = &eth.host;
        assert_eq!(h.configured, [0x83, 0x02], "only the data interface's endpoints");
        let sets: Vec<_> = h.requests.iter().filter(|r| r.request_type & 0x80 == 0).map(|r| r.to_bytes()).collect();
        assert_eq!(
            sets,
            [
                [0x01, 0x0b, 1, 0, 1, 0, 0, 0],    // SET_INTERFACE interface 1, alternate 1
                [0x21, 0x43, 0x0e, 0, 0, 0, 0, 0]  // packet filter: directed, broadcast, all multicast
            ]
        );
        assert_eq!(h.outstanding, [true, true], "interrupt and bulk IN transfers are waiting");
        // 1514 rounded up to whole 512-byte packets.
        assert_eq!(h.submit_lens, [1536]);
    }

    #[test]
    fn filter_failure_is_not_fatal() {
        let host = FakeNic { reject_filter: true, ..Default::default() };
        assert!(UsbEthernet::new(host, DeviceId(3), &CONFIG).is_ok());
    }

    #[test]
    fn not_an_ecm_device() {
        assert_eq!(
            UsbEthernet::new(FakeNic::default(), DeviceId(3), &CONFIG[..9]).err(),
            Some(UsbError::BadDescriptor)
        );
    }

    #[test]
    fn transmit_frames() {
        let mut eth = nic();
        eth.transmit(&[1; 60]).unwrap();
        assert_eq!(eth.host.sent.len(), 1);
        assert_eq!(eth.transmit(&[0; 1515]), Err(NetError::TooLarge));
        // A frame that is a whole number of packets needs an empty one after
        // it, or the device cannot tell where it ends.
        eth.host.sent.clear();
        eth.transmit(&[2; 1024]).unwrap();
        assert_eq!(eth.host.sent.iter().map(Vec::len).collect::<Vec<_>>(), [1024, 0]);
        eth.host.sent.clear();
        eth.transmit(&[2; 1000]).unwrap();
        assert_eq!(eth.host.sent.len(), 1);
    }

    #[test]
    fn receive_frames() {
        let mut eth = nic();
        let mut buf = [0u8; 1514];
        assert_eq!(eth.receive(&mut buf), Err(NetError::WouldBlock));
        assert!(eth.host.outstanding[1], "still waiting for one");

        eth.host.frames.push_back((0..100).collect());
        eth.host.frames.push_back(std::vec![0; 0]); // an empty packet is skipped
        eth.host.frames.push_back(std::vec![7; 1514]);
        assert_eq!(eth.receive(&mut buf), Ok(100));
        assert_eq!(buf[..100], (0..100).collect::<Vec<u8>>()[..]);
        // The next transfer was started at once (and here, completed by the
        // empty packet, which yields no frame).
        assert_eq!(eth.host.frames.len(), 1);
        assert_eq!(eth.receive(&mut buf), Ok(1514));
        assert_eq!(buf[1513], 7);
        assert_eq!(eth.receive(&mut buf), Err(NetError::WouldBlock));
    }

    #[test]
    fn oversized_frame_is_dropped() {
        let mut eth = nic();
        eth.host.frames.push_back(std::vec![1; 200]);
        eth.host.frames.push_back(std::vec![2; 50]);
        let mut small = [0u8; 100];
        assert_eq!(eth.receive(&mut small), Err(NetError::TooLarge));
        assert_eq!(eth.receive(&mut small), Ok(50));
        assert_eq!(small[0], 2);
    }

    #[test]
    fn can_receive_tracks_collected_frames() {
        let mut eth = nic();
        eth.host.frames.push_back(std::vec![9; 60]);
        assert!(!eth.can_receive(), "nothing has looked yet");
        eth.service().unwrap();
        assert!(eth.can_receive());
        // A frame is held, so another is not requested over it.
        eth.host.frames.push_back(std::vec![8; 60]);
        let mut buf = [0u8; 1514];
        assert_eq!(eth.receive(&mut buf), Ok(60));
        assert_eq!(buf[0], 9);
        // The next transfer was started at once, and this fake completes
        // instantly, so the second frame is already held.
        assert!(eth.can_receive());
        assert_eq!(eth.receive(&mut buf), Ok(60));
        assert_eq!(buf[0], 8);
        assert!(!eth.can_receive());
    }

    #[test]
    fn link_follows_notifications() {
        let mut eth = nic();
        eth.host.notes.push_back([0xa1, 0, 0, 0, 0, 0, 0, 0]);
        eth.service().unwrap();
        assert!(!eth.link_up());
        assert_eq!(eth.transmit(&[0; 60]), Err(NetError::LinkDown));
        assert!(!eth.can_transmit());
        eth.host.notes.push_back([0xa1, 0, 1, 0, 0, 0, 0, 0]);
        eth.service().unwrap();
        assert!(eth.link_up());
        eth.transmit(&[0; 60]).unwrap();
    }
}
