//! USB Ethernet, CDC Network Control Model (communications class 02/0d/00).
//!
//! An NCM function is laid out like an [ECM](super::ecm) one: a
//! communications interface with Union and Ethernet Networking descriptors
//! (plus an NCM functional descriptor) and an interrupt IN endpoint for
//! notifications, and a data interface whose alternate setting 1 has a bulk
//! IN and a bulk OUT endpoint. The difference is on the bulk pipes: each
//! transfer is an NCM Transfer Block (NTB), a header followed by datagram
//! pointer tables (NDPs) that locate any number of Ethernet frames in it.
//!
//! [`UsbNcm::new`] reads the function's NTB parameters, limits the size of
//! the NTBs the device sends to [`RX_NTB_LEN`] while the data interface is
//! still in alternate setting 0 (the only time the device accepts that),
//! then selects alternate setting 1 and leaves one bulk IN transfer
//! outstanding. Received NTBs are taken apart one datagram per
//! [`NetDevice::receive`]; each transmitted frame goes out in an NTB of its
//! own. Only the 16-bit NTB format is used, without CRCs.
//!
//! No QEMU device speaks NCM, so this driver has only run against the
//! simulated device in its tests.

use core::ops::Range;

use osmium_hal::net::{MacAddress, NetDevice, NetError};
use osmium_hal::usb::{DeviceId, Direction, Recipient, RequestKind, SetupPacket, UsbError, UsbHost};

use super::ecm::{self, EcmFunction, Notification, bad, filter, parse_notification, read_mac};

/// Subclass code of the Network Control Model.
pub const SUBCLASS_NCM: u8 = 0x0d;

const SUBTYPE_NCM: u8 = 0x1a;

/// NCM class requests (NCM table 6-2).
const GET_NTB_PARAMETERS: u8 = 0x80;
const SET_NTB_FORMAT: u8 = 0x84;
const SET_NTB_INPUT_SIZE: u8 = 0x86;

/// `bmNetworkCapabilities` bits (NCM table 5-2).
pub mod capability {
    #![allow(missing_docs)]
    pub const PACKET_FILTER: u8 = 1 << 0;
    pub const NET_ADDRESS: u8 = 1 << 1;
    pub const ENCAPSULATED_COMMAND: u8 = 1 << 2;
    pub const MAX_DATAGRAM_SIZE: u8 = 1 << 3;
    pub const CRC_MODE: u8 = 1 << 4;
    /// `SET_NTB_INPUT_SIZE` takes 8 bytes (with a datagram count), not 4.
    pub const NTB_INPUT_SIZE_8: u8 = 1 << 5;
}

/// `bmNtbFormatsSupported` bits.
const FORMAT_NTB16: u16 = 1 << 0;
const FORMAT_NTB32: u16 = 1 << 1;

/// "NCMH": the 16-bit NTB header's signature.
const NTH16_SIGNATURE: [u8; 4] = *b"NCMH";
/// "NCM0": a 16-bit NDP whose datagrams carry no CRC.
const NDP16_SIGNATURE: [u8; 4] = *b"NCM0";
const NTH16_LEN: usize = 12;
/// An NDP16 holding one datagram pointer and the terminating null entry.
const NDP16_ONE_LEN: usize = 8 + 2 * 4;
/// The most NDPs followed in one NTB, which also stops a chain that loops.
const MAX_NDPS: u8 = 16;

/// Bytes of the receive buffer: the largest NTB the device is asked to
/// send. NCM requires a function to accept anything from 2048 up.
pub const RX_NTB_LEN: usize = 4096;
/// Bytes of the transmit buffer, which holds one frame's NTB.
pub const TX_NTB_LEN: usize = 2048;

/// An NCM function found in a configuration descriptor set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NcmFunction {
    /// The interfaces and endpoints, which NCM shares with ECM.
    pub cdc: EcmFunction,
    /// `bcdNcmVersion` of the NCM functional descriptor (0 if it is absent).
    pub version: u16,
    /// `bmNetworkCapabilities` (see [`capability`]).
    pub capabilities: u8,
}

impl NcmFunction {
    /// Finds an NCM function in the configuration descriptor set `config`:
    /// a 02/0d communications interface with an Ethernet Networking
    /// descriptor and a data interface with bulk IN and OUT endpoints, as
    /// [`EcmFunction::parse`] requires for ECM. A missing NCM functional
    /// descriptor counts as no capabilities.
    pub fn parse(config: &[u8]) -> Option<Self> {
        let mut ncm = None;
        let cdc = ecm::parse_cdc(config, SUBCLASS_NCM, |d| {
            if let [_, _, SUBTYPE_NCM, v0, v1, caps, ..] = *d
                && ncm.is_none()
            {
                ncm = Some((u16::from_le_bytes([v0, v1]), caps));
            }
        })?;
        let (version, capabilities) = ncm.unwrap_or((0, 0));
        Some(Self { cdc, version, capabilities })
    }
}

/// The little-endian `u16` at `at` in `b`, if `b` is long enough.
fn le16(b: &[u8], at: usize) -> Option<usize> {
    b.get(at..)?.first_chunk::<2>().map(|c| u16::from_le_bytes(*c) as usize)
}

/// The little-endian `u32` at `at` in `b`, if `b` is long enough.
fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..)?.first_chunk::<4>().map(|c| u32::from_le_bytes(*c))
}

/// Copies `v` to offset `at` of `b`, if it fits.
fn put(b: &mut [u8], at: usize, v: &[u8]) -> Option<()> {
    b.get_mut(at..at.checked_add(v.len())?)?.copy_from_slice(v);
    Some(())
}

/// The function's NTB parameters (`GET_NTB_PARAMETERS`, NCM table 6-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NtbParameters {
    /// `bmNtbFormatsSupported`: bit 0 for 16-bit NTBs, bit 1 for 32-bit.
    pub formats: u16,
    /// `dwNtbInMaxSize`: the largest NTB the device sends by default.
    pub in_max_size: u32,
    /// `dwNtbOutMaxSize`: the largest NTB the device accepts.
    pub out_max_size: u32,
    /// `wNdpOutDivisor`: each datagram should start at an offset that is
    /// [`out_remainder`](Self::out_remainder) modulo this.
    pub out_divisor: u16,
    /// `wNdpOutPayloadRemainder`.
    pub out_remainder: u16,
    /// `wNdpOutAlignment`: the alignment of an NDP in the NTB.
    pub out_alignment: u16,
}

impl NtbParameters {
    /// Parses the 28-byte reply to `GET_NTB_PARAMETERS`.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < 28 || le16(b, 0)? < 28 {
            return None;
        }
        Some(Self {
            formats: le16(b, 2)? as u16,
            in_max_size: le32(b, 4)?,
            out_max_size: le32(b, 16)?,
            out_divisor: le16(b, 20)? as u16,
            out_remainder: le16(b, 22)? as u16,
            out_alignment: le16(b, 24)? as u16,
        })
    }
}

/// Where a transmitted NTB puts its parts, from the device's parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxLayout {
    /// Offset of the NDP.
    pub ndp: usize,
    /// Offset of the frame.
    pub datagram: usize,
    /// The largest NTB to send: the device's limit or [`TX_NTB_LEN`].
    pub max_len: usize,
}

impl TxLayout {
    /// Places the NDP right after the header and the frame right after the
    /// NDP, each moved up to satisfy the device's alignment rules. Rules
    /// that are not powers of two (or are absurdly large) are replaced by
    /// 4-byte alignment, as Linux does.
    pub fn new(p: &NtbParameters) -> Self {
        let sane = |v: u16| v.is_power_of_two() && (4..=256).contains(&v);
        let align = if sane(p.out_alignment) { p.out_alignment as usize } else { 4 };
        let (divisor, remainder) = if sane(p.out_divisor) && p.out_remainder < p.out_divisor {
            (p.out_divisor as usize, p.out_remainder as usize)
        } else {
            (4, 0)
        };
        let ndp = NTH16_LEN.next_multiple_of(align);
        let after = ndp + NDP16_ONE_LEN;
        let datagram = after + (remainder + divisor - after % divisor) % divisor;
        Self { ndp, datagram, max_len: (p.out_max_size as usize).min(TX_NTB_LEN) }
    }

    /// Bytes left in an NTB for the frame.
    pub fn max_frame_len(&self) -> usize {
        self.max_len.saturating_sub(self.datagram)
    }

    /// Writes an NTB carrying `frame` into `buf` and returns its length, or
    /// `None` if it does not fit.
    pub fn build(&self, buf: &mut [u8], sequence: u16, frame: &[u8]) -> Option<usize> {
        let len = self.datagram.checked_add(frame.len()).filter(|&n| n <= self.max_len && n <= buf.len())?;
        let len16 = |n: usize| (n as u16).to_le_bytes();
        let (head, tail) = buf.get_mut(..len)?.split_at_mut_checked(self.datagram)?;
        head.fill(0);
        put(head, 0, &NTH16_SIGNATURE)?;
        put(head, 4, &len16(NTH16_LEN))?;
        put(head, 6, &sequence.to_le_bytes())?;
        put(head, 8, &len16(len))?;
        put(head, 10, &len16(self.ndp))?;
        let ndp = head.get_mut(self.ndp..self.ndp.checked_add(NDP16_ONE_LEN)?)?;
        put(ndp, 0, &NDP16_SIGNATURE)?;
        put(ndp, 4, &len16(NDP16_ONE_LEN))?;
        // wNextNdpIndex and the terminating entry stay zero.
        put(ndp, 8, &len16(self.datagram))?;
        put(ndp, 10, &len16(frame.len()))?;
        tail.copy_from_slice(frame);
        Some(len)
    }
}

/// A received NTB that is malformed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadNtb;

/// Walks the datagrams of a received 16-bit NTB, following its NDP chain.
/// It holds offsets rather than a borrow, so the NTB's buffer can be read
/// between calls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NtbReader {
    /// `wBlockLength`: the bytes that belong to the NTB.
    block_len: usize,
    /// Offset of the current NDP; 0 once there are no more.
    ndp: usize,
    /// Index of the next pointer in the current NDP.
    entry: usize,
    ndps: u8,
    /// Offsets of the NDPs already walked, the first `ndps` of them.
    seen: [u16; MAX_NDPS as usize],
}

impl NtbReader {
    /// Checks the NTB header at the start of `ntb`, the bytes received.
    pub fn new(ntb: &[u8]) -> Result<Self, BadNtb> {
        if ntb.len() < NTH16_LEN || ntb.first_chunk::<4>() != Some(&NTH16_SIGNATURE) || le16(ntb, 4) != Some(NTH16_LEN)
        {
            return Err(BadNtb);
        }
        let block_len = le16(ntb, 8).ok_or(BadNtb)?;
        if !(NTH16_LEN..=ntb.len()).contains(&block_len) {
            return Err(BadNtb);
        }
        let ndp = le16(ntb, 10).ok_or(BadNtb)?;
        Ok(Self { block_len, ndp, entry: 0, ndps: 0, seen: [0; MAX_NDPS as usize] })
    }

    /// The range of `ntb` holding the next datagram, `None` after the last.
    /// A malformed NDP or datagram pointer ends the walk with [`BadNtb`];
    /// the datagrams before it were good.
    pub fn next(&mut self, ntb: &[u8]) -> Result<Option<Range<usize>>, BadNtb> {
        let r = self.step(ntb);
        if r.is_err() {
            self.ndp = 0;
        }
        r
    }

    fn step(&mut self, ntb: &[u8]) -> Result<Option<Range<usize>>, BadNtb> {
        let ntb = ntb.get(..self.block_len).ok_or(BadNtb)?;
        let u16_at = |at: usize| le16(ntb, at).ok_or(BadNtb);
        while self.ndp != 0 {
            let ndp = self.ndp;
            // A chain that comes back to an NDP would deliver its datagrams again.
            if self.seen.get(..usize::from(self.ndps)).is_none_or(|s| s.contains(&(ndp as u16))) {
                return Err(BadNtb);
            }
            if ndp < NTH16_LEN || ndp + NDP16_ONE_LEN > ntb.len() || ntb.get(ndp..ndp + 4) != Some(&NDP16_SIGNATURE[..])
            {
                return Err(BadNtb);
            }
            let ndp_len = u16_at(ndp + 4)?;
            if ndp_len < NDP16_ONE_LEN || ndp + ndp_len > ntb.len() {
                return Err(BadNtb);
            }
            let at = ndp + 8 + 4 * self.entry;
            if at + 4 <= ndp + ndp_len {
                let (index, len) = (u16_at(at)?, u16_at(at + 2)?);
                if index != 0 && len != 0 {
                    self.entry += 1;
                    if index < NTH16_LEN || index + len > ntb.len() {
                        return Err(BadNtb);
                    }
                    return Ok(Some(index..index + len));
                }
            }
            // A null entry (or the end of the table) ends this NDP.
            *self.seen.get_mut(usize::from(self.ndps)).ok_or(BadNtb)? = ndp as u16;
            self.ndps += 1;
            if self.ndps >= MAX_NDPS {
                return Err(BadNtb);
            }
            self.ndp = u16_at(ndp + 6)?;
            self.entry = 0;
        }
        Ok(None)
    }
}

/// A CDC-NCM network adapter.
pub struct UsbNcm<H: UsbHost> {
    host: H,
    dev: DeviceId,
    function: NcmFunction,
    mac: MacAddress,
    link: bool,
    tx: TxLayout,
    tx_sequence: u16,
    tx_buf: [u8; TX_NTB_LEN],
    /// Bytes of each bulk IN transfer: the NTB input size the device agreed to.
    rx_len: usize,
    rx_submitted: bool,
    rx: [u8; RX_NTB_LEN],
    /// The NTB in `rx` being taken apart.
    rx_reader: NtbReader,
    /// Where its next datagram is in `rx`.
    rx_next: Option<Range<usize>>,
    bad_ntbs: u32,
    notify_submitted: bool,
}

impl<H: UsbHost> UsbNcm<H> {
    /// Brings up the NCM function of the enumerated device `dev`, whose
    /// currently selected configuration's descriptor set is `config` (use
    /// [`osmium_hal::usb::set_configuration`] first if it is not the
    /// device's first). Reads the MAC address and NTB parameters, selects
    /// 16-bit NTBs of at most [`RX_NTB_LEN`] bytes, then selects the data
    /// interface's bulk alternate setting, enables its endpoints and starts
    /// receiving.
    ///
    /// Fails with [`UsbError::BadDescriptor`] if `config` has no NCM
    /// function (see [`NcmFunction::parse`]), the MAC string or the NTB
    /// parameters are malformed, the device lacks 16-bit NTBs, or its NTBs
    /// cannot hold a full frame.
    pub fn new(mut host: H, dev: DeviceId, config: &[u8]) -> Result<Self, UsbError> {
        let function = NcmFunction::parse(config).ok_or(UsbError::BadDescriptor)?;
        let cdc = function.cdc;
        let mac = read_mac(&mut host, dev, cdc.mac_string)?;
        let class = |direction, request, value, length| {
            SetupPacket::new(
                direction,
                RequestKind::Class,
                Recipient::Interface,
                request,
                value,
                cdc.control_interface as u16,
                length,
            )
        };

        // The data interface starts in alternate setting 0, where the NTB
        // format and input size may be changed.
        let mut reply = [0u8; 28];
        let n = host.control_in(dev, class(Direction::In, GET_NTB_PARAMETERS, 0, 28), &mut reply)?;
        let params =
            NtbParameters::parse(reply.get(..n).ok_or(UsbError::BadDescriptor)?).ok_or(UsbError::BadDescriptor)?;
        if params.formats & FORMAT_NTB16 == 0 {
            return Err(UsbError::BadDescriptor);
        }
        if params.formats & FORMAT_NTB32 != 0 {
            // 16-bit is the default, but say so to a device that has both.
            host.control_out(dev, class(Direction::Out, SET_NTB_FORMAT, 0, 0), &[])?;
        }
        let rx_len = (params.in_max_size as usize).min(RX_NTB_LEN);
        if rx_len < (params.in_max_size as usize) {
            let size = (rx_len as u32).to_le_bytes();
            let mut data = [0u8; 8];
            data[..4].copy_from_slice(&size);
            // Some devices take a datagram count too; 0 is "no limit".
            let len = if function.capabilities & capability::NTB_INPUT_SIZE_8 != 0 { 8 } else { 4 };
            let data = data.get(..len).ok_or(UsbError::BadDescriptor)?;
            host.control_out(dev, class(Direction::Out, SET_NTB_INPUT_SIZE, 0, len as u16), data)?;
        }
        // Both directions must at least carry a full-sized Ethernet frame.
        let frame = (cdc.max_segment as usize).min(1514);
        let tx = TxLayout::new(&params);
        if rx_len < NTH16_LEN + NDP16_ONE_LEN + frame || tx.max_frame_len() < frame {
            return Err(UsbError::BadDescriptor);
        }

        host.control_out(dev, SetupPacket::set_interface(cdc.data_interface, cdc.data_alternate), &[])?;
        host.configure_endpoints(dev, &[cdc.bulk_in, cdc.bulk_out])?;
        // As for ECM; a device without a filter may stall this.
        let accept = filter::DIRECTED | filter::BROADCAST | filter::ALL_MULTICAST;
        let _ = host.control_out(dev, class(Direction::Out, ecm::SET_ETHERNET_PACKET_FILTER, accept, 0), &[]);

        let mut ncm = Self {
            host,
            dev,
            function,
            mac,
            link: true,
            tx,
            tx_sequence: 0,
            tx_buf: [0; TX_NTB_LEN],
            rx_len,
            rx_submitted: false,
            rx: [0; RX_NTB_LEN],
            rx_reader: NtbReader::default(),
            rx_next: None,
            bad_ntbs: 0,
            notify_submitted: false,
        };
        ncm.service().map_err(|_| UsbError::Controller)?;
        Ok(ncm)
    }

    /// The device handle.
    pub fn device(&self) -> DeviceId {
        self.dev
    }

    /// The function's descriptors.
    pub fn function(&self) -> &NcmFunction {
        &self.function
    }

    /// Received NTBs dropped, wholly or after their good datagrams, because
    /// they were malformed.
    pub fn bad_ntbs(&self) -> u32 {
        self.bad_ntbs
    }

    /// Moves to the next datagram of the NTB in the receive buffer.
    fn advance(&mut self) {
        self.rx_next = self.rx_reader.next(&self.rx).unwrap_or_else(|BadNtb| {
            self.bad_ntbs = self.bad_ntbs.wrapping_add(1);
            None
        });
    }

    /// Moves along anything the device has finished: notifications, and the
    /// bulk IN transfer into the receive buffer, starting a new one once
    /// every datagram of the last NTB has been received. Called by
    /// [`receive`](NetDevice::receive) and [`transmit`](NetDevice::transmit);
    /// call it too to keep [`can_receive`](NetDevice::can_receive) and
    /// [`link_up`](NetDevice::link_up) current without receiving.
    pub fn service(&mut self) -> Result<(), NetError> {
        if let Some(ep) = self.function.cdc.interrupt {
            let mut note = [0u8; 16];
            if !self.notify_submitted {
                match self.host.submit_in(self.dev, ep.address, note.len()) {
                    Ok(()) => self.notify_submitted = true,
                    // Notifications are optional; do not fail the link over them.
                    Err(_) => self.function.cdc.interrupt = None,
                }
            }
            if self.notify_submitted
                && let Some(done) = self.host.poll_in(self.dev, ep.address, &mut note)
            {
                self.notify_submitted = false;
                if let Ok(n) = done
                    && let Some(Notification::NetworkConnection(up)) = note.get(..n).and_then(parse_notification)
                {
                    self.link = up;
                }
            }
        }
        if self.rx_next.is_some() {
            return Ok(());
        }
        let ep = self.function.cdc.bulk_in.address;
        if !self.rx_submitted {
            self.host.submit_in(self.dev, ep, self.rx_len).map_err(bad)?;
            self.rx_submitted = true;
        }
        if let Some(done) = self.host.poll_in(self.dev, ep, &mut self.rx) {
            self.rx_submitted = false;
            let n = done.map_err(bad)?.min(self.rx.len());
            // An empty packet ends an NTB that filled its last packet.
            if n > 0 {
                match self.rx.get(..n).ok_or(BadNtb).and_then(NtbReader::new) {
                    Ok(reader) => {
                        self.rx_reader = reader;
                        self.advance();
                    }
                    Err(BadNtb) => self.bad_ntbs = self.bad_ntbs.wrapping_add(1),
                }
            }
            if self.rx_next.is_none() {
                // Nothing in it to hold the buffer for: ask for the next one.
                self.host.submit_in(self.dev, ep, self.rx_len).map_err(bad)?;
                self.rx_submitted = true;
            }
        }
        Ok(())
    }
}

impl<H: UsbHost> NetDevice for UsbNcm<H> {
    fn mac_address(&self) -> MacAddress {
        self.mac
    }

    fn max_frame_len(&self) -> usize {
        (self.function.cdc.max_segment as usize).min(self.tx.max_frame_len())
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
        let len = self.tx.build(&mut self.tx_buf, self.tx_sequence, frame).ok_or(NetError::TooLarge)?;
        self.tx_sequence = self.tx_sequence.wrapping_add(1);
        let ep = self.function.cdc.bulk_out;
        self.host.transfer_out(self.dev, ep.address, self.tx_buf.get(..len).ok_or(NetError::TooLarge)?).map_err(bad)?;
        // An NTB of exactly the device's maximum size needs no terminator;
        // a shorter one that fills its last packet does.
        if len < self.tx.max_len && len.is_multiple_of((ep.max_packet_size() as usize).max(1)) {
            self.host.transfer_out(self.dev, ep.address, &[]).map_err(bad)?;
        }
        self.service()
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError> {
        self.service()?;
        let range = self.rx_next.take().ok_or(NetError::WouldBlock)?;
        let n = range.len();
        let fits = match (buf.get_mut(..n), self.rx.get(range)) {
            (Some(dst), Some(src)) => {
                dst.copy_from_slice(src);
                true
            }
            _ => false,
        };
        self.advance();
        // Once the NTB is used up, start the next transfer before the caller
        // digests this frame.
        let next = self.service();
        if !fits {
            return Err(NetError::TooLarge);
        }
        next.map(|()| n)
    }

    /// True if a datagram is waiting in the NTB already received. One the
    /// device finished since is found by the next
    /// [`receive`](Self::receive), which returns [`NetError::WouldBlock`]
    /// if there is none.
    fn can_receive(&self) -> bool {
        self.rx_next.is_some()
    }

    fn can_transmit(&self) -> bool {
        self.link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use osmium_hal::usb::{EndpointDescriptor, PortStatus, descriptor_type};
    use std::collections::VecDeque;
    use std::vec::Vec;

    /// An NCM function shaped like Linux's `f_ncm` gadget: interrupt 0x81,
    /// bulk IN 0x82 and OUT 0x01 of 512 bytes, MAC in string 4.
    #[rustfmt::skip]
    const CONFIG: [u8; 86] = [
        9, 2, 86, 0, 2, 1, 0, 0xc0, 50, // configuration 1, two interfaces
        9, 4, 0, 0, 1, 2, 0x0d, 0, 0, // interface 0: CDC NCM control, one endpoint
        5, 0x24, 0x00, 0x10, 0x01, // header
        5, 0x24, 0x06, 0, 1, // union: master 0, slave 1
        13, 0x24, 0x0f, 4, 0, 0, 0, 0, 0xea, 0x05, 0, 0, 0, // Ethernet: iMAC 4, 1514 bytes
        6, 0x24, 0x1a, 0x00, 0x01, 0x01, // NCM 1.00, packet filter
        7, 5, 0x81, 3, 16, 0, 9, // interrupt IN
        9, 4, 1, 0, 0, 10, 0, 1, 0, // interface 1 alt 0: no endpoints
        9, 4, 1, 1, 2, 10, 0, 1, 0, // interface 1 alt 1: NTB protocol
        7, 5, 0x82, 2, 0x00, 0x02, 0, // bulk IN 512
        7, 5, 0x01, 2, 0x00, 0x02, 0, // bulk OUT 512
    ];

    fn params(in_max: u32, out_max: u32, divisor: u16, remainder: u16, alignment: u16) -> [u8; 28] {
        let mut p = [0u8; 28];
        p[0..2].copy_from_slice(&28u16.to_le_bytes());
        p[2..4].copy_from_slice(&(FORMAT_NTB16 | FORMAT_NTB32).to_le_bytes());
        p[4..8].copy_from_slice(&in_max.to_le_bytes());
        p[8..10].copy_from_slice(&4u16.to_le_bytes());
        p[12..14].copy_from_slice(&4u16.to_le_bytes());
        p[16..20].copy_from_slice(&out_max.to_le_bytes());
        p[20..22].copy_from_slice(&divisor.to_le_bytes());
        p[22..24].copy_from_slice(&remainder.to_le_bytes());
        p[24..26].copy_from_slice(&alignment.to_le_bytes());
        p
    }

    fn layout(divisor: u16, remainder: u16, alignment: u16) -> TxLayout {
        TxLayout::new(&NtbParameters::parse(&params(16384, 16384, divisor, remainder, alignment)).unwrap())
    }

    /// Builds an NTB16 holding `frames`: header, then the frames 4-aligned,
    /// then one NDP pointing at them.
    fn ntb(frames: &[&[u8]]) -> Vec<u8> {
        let mut b = std::vec![0u8; NTH16_LEN];
        let mut pointers = Vec::new();
        for f in frames {
            b.resize(b.len().next_multiple_of(4), 0);
            pointers.push((b.len() as u16, f.len() as u16));
            b.extend_from_slice(f);
        }
        b.resize(b.len().next_multiple_of(4), 0);
        let ndp = b.len();
        b.extend_from_slice(&NDP16_SIGNATURE);
        // At least 16 bytes, as NCM requires, even with no datagrams.
        let entries = frames.len().max(1) + 1;
        b.extend_from_slice(&(8 + 4 * entries as u16).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        for (i, l) in pointers {
            b.extend_from_slice(&i.to_le_bytes());
            b.extend_from_slice(&l.to_le_bytes());
        }
        b.resize(ndp + 8 + 4 * entries, 0);
        let len = b.len() as u16;
        b[0..4].copy_from_slice(&NTH16_SIGNATURE);
        b[4..6].copy_from_slice(&12u16.to_le_bytes());
        b[8..10].copy_from_slice(&len.to_le_bytes());
        b[10..12].copy_from_slice(&(ndp as u16).to_le_bytes());
        b
    }

    fn datagrams(b: &[u8]) -> Result<Vec<Vec<u8>>, BadNtb> {
        let mut r = NtbReader::new(b)?;
        let mut out = Vec::new();
        while let Some(range) = r.next(b)? {
            out.push(b[range].to_vec());
        }
        Ok(out)
    }

    #[test]
    fn parses_function() {
        let f = NcmFunction::parse(&CONFIG).unwrap();
        assert_eq!((f.version, f.capabilities), (0x0100, capability::PACKET_FILTER));
        let c = f.cdc;
        assert_eq!((c.control_interface, c.data_interface, c.data_alternate), (0, 1, 1));
        assert_eq!((c.mac_string, c.max_segment), (4, 1514));
        assert_eq!(c.interrupt.map(|e| e.address), Some(0x81));
        assert_eq!((c.bulk_in.address, c.bulk_out.address), (0x82, 0x01));
        // NCM and ECM do not take each other's functions.
        assert_eq!(EcmFunction::parse(&CONFIG), None);
        let mut as_ecm = CONFIG;
        as_ecm[9 + 6] = ecm::SUBCLASS_ECM;
        assert_eq!(NcmFunction::parse(&as_ecm), None);
        assert!(EcmFunction::parse(&as_ecm).is_some());
        // The NCM functional descriptor is optional.
        let mut no_ncm = CONFIG;
        no_ncm[9 + 9 + 5 + 5 + 13 + 2] = 0x1b;
        assert_eq!(NcmFunction::parse(&no_ncm).map(|f| (f.version, f.capabilities)), Some((0, 0)));
    }

    #[test]
    fn ntb_parameters() {
        let p = NtbParameters::parse(&params(16384, 8192, 4, 0, 4)).unwrap();
        assert_eq!((p.formats, p.in_max_size, p.out_max_size), (3, 16384, 8192));
        assert_eq!((p.out_divisor, p.out_remainder, p.out_alignment), (4, 0, 4));
        assert_eq!(NtbParameters::parse(&params(16384, 8192, 4, 0, 4)[..27]), None);
        let mut short = params(16384, 8192, 4, 0, 4);
        short[0] = 20;
        assert_eq!(NtbParameters::parse(&short), None);
    }

    #[test]
    fn tx_layout_follows_alignment_rules() {
        let l = layout(4, 0, 4);
        assert_eq!((l.ndp, l.datagram, l.max_len), (12, 28, TX_NTB_LEN));
        // Linux's f_ncm: frames at 2 modulo 4, so the IP header is aligned.
        assert_eq!(layout(4, 2, 4).datagram, 30);
        assert_eq!(layout(32, 0, 4).datagram, 32);
        assert_eq!(layout(32, 6, 16), TxLayout { ndp: 16, datagram: 38, max_len: TX_NTB_LEN });
        // Nonsense falls back to 4-byte alignment.
        assert_eq!(layout(3, 1, 0), layout(4, 0, 4));
        assert_eq!(layout(4, 4, 4).datagram, 28, "remainder not below divisor");
        let small = TxLayout::new(&NtbParameters::parse(&params(16384, 1000, 4, 0, 4)).unwrap());
        assert_eq!(small.max_frame_len(), 1000 - 28);
    }

    #[test]
    fn built_ntbs_read_back() {
        for l in [layout(4, 0, 4), layout(32, 6, 16), layout(4, 2, 64)] {
            let mut buf = [0u8; TX_NTB_LEN];
            let frame: Vec<u8> = (0..100).collect();
            let n = l.build(&mut buf, 7, &frame).unwrap();
            assert_eq!(n, l.datagram + 100);
            assert_eq!(u16::from_le_bytes([buf[6], buf[7]]), 7, "sequence");
            assert_eq!(datagrams(&buf[..n]), Ok(std::vec![frame.clone()]));
            assert_eq!(l.build(&mut buf, 0, &[0; TX_NTB_LEN]), None);
        }
    }

    #[test]
    fn reads_datagrams() {
        let frames: [&[u8]; 3] = [&[1; 60], &[2; 61], &[3; 1514]];
        let b = ntb(&frames);
        assert_eq!(datagrams(&b).unwrap(), frames.map(|f| f.to_vec()));
        assert_eq!(datagrams(&ntb(&[])).unwrap(), Vec::<Vec<u8>>::new());
        // Bytes past wBlockLength (padding to a packet) are ignored.
        let mut padded = b.clone();
        padded.resize(b.len() + 50, 0xee);
        assert_eq!(datagrams(&padded).unwrap().len(), 3);
    }

    #[test]
    fn follows_ndp_chain() {
        // Two NTBs' worth of NDPs: point the first NDP at a second one
        // appended after it, which holds one more frame.
        let mut b = ntb(&[&[1; 20]]);
        let first = u16::from_le_bytes([b[10], b[11]]) as usize;
        let frame_at = b.len();
        b.extend_from_slice(&[9; 16]);
        let second = b.len();
        b.extend_from_slice(&NDP16_SIGNATURE);
        b.extend_from_slice(&16u16.to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&(frame_at as u16).to_le_bytes());
        b.extend_from_slice(&16u16.to_le_bytes());
        b.extend_from_slice(&[0; 4]);
        b[first + 6..first + 8].copy_from_slice(&(second as u16).to_le_bytes());
        let len = b.len() as u16;
        b[8..10].copy_from_slice(&len.to_le_bytes());
        assert_eq!(datagrams(&b).unwrap(), [std::vec![1; 20], std::vec![9; 16]]);
        // A chain that loops back on itself is cut off.
        b[second + 6..second + 8].copy_from_slice(&(first as u16).to_le_bytes());
        assert_eq!(datagrams(&b), Err(BadNtb));
    }

    #[test]
    fn rejects_malformed_ntbs() {
        let good = ntb(&[&[1; 60], &[2; 60]]);
        let ndp = u16::from_le_bytes([good[10], good[11]]) as usize;
        let bad = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut b = good.clone();
            f(&mut b);
            datagrams(&b)
        };
        assert_eq!(bad(&|b| b[0] = b'X'), Err(BadNtb), "header signature");
        assert_eq!(bad(&|b| b[4] = 16), Err(BadNtb), "header length");
        assert_eq!(bad(&|b| b.truncate(b.len() - 1)), Err(BadNtb), "block longer than received");
        assert_eq!(bad(&|b| b[10..12].copy_from_slice(&4u16.to_le_bytes())), Err(BadNtb), "NDP inside the header");
        assert_eq!(bad(&|b| b[10..12].copy_from_slice(&0xfff0u16.to_le_bytes())), Err(BadNtb), "NDP past the end");
        assert_eq!(bad(&|b| b[ndp + 3] = b'1'), Err(BadNtb), "CRC NDPs");
        assert_eq!(bad(&|b| b[ndp + 4] = 8), Err(BadNtb), "NDP too short");
        assert_eq!(bad(&|b| b[ndp + 4] = 0xf0), Err(BadNtb), "NDP past the block");
        assert_eq!(bad(&|b| b[ndp + 12 + 2] = 0xff), Err(BadNtb), "datagram past the block");
        assert_eq!(datagrams(&good[..11]), Err(BadNtb));
        // The datagrams before a bad pointer are delivered.
        let mut b = good.clone();
        b[ndp + 12 + 2..ndp + 12 + 4].copy_from_slice(&0x7fffu16.to_le_bytes());
        let mut r = NtbReader::new(&b).unwrap();
        assert_eq!(r.next(&b).map(|d| d.map(|d| d.len())), Ok(Some(60)));
        assert_eq!(r.next(&b), Err(BadNtb));
        assert_eq!(r.next(&b), Ok(None), "and nothing after");
    }

    #[test]
    fn an_ndp_chain_that_revisits_an_ndp_delivers_nothing_twice() {
        let mut b = ntb(&[&[1; 60], &[2; 60]]);
        let ndp = u16::from_le_bytes([b[10], b[11]]);
        b[ndp as usize + 6..ndp as usize + 8].copy_from_slice(&ndp.to_le_bytes());
        let mut r = NtbReader::new(&b).unwrap();
        let mut delivered = 0;
        loop {
            match r.next(&b) {
                Ok(Some(_)) => delivered += 1,
                Ok(None) => panic!("a looping chain must be rejected"),
                Err(BadNtb) => break,
            }
        }
        assert_eq!(delivered, 2);
    }

    fn utf16(s: &str) -> Vec<u8> {
        let mut d = std::vec![0, descriptor_type::STRING];
        for c in s.encode_utf16() {
            d.extend(c.to_le_bytes());
        }
        d[0] = d.len() as u8;
        d
    }

    /// A device with queues of NTBs to deliver on bulk IN and notifications
    /// on the interrupt endpoint, recording what the driver does.
    struct FakeNcm {
        params: [u8; 28],
        caps_ntb_input_8: bool,
        ntbs: VecDeque<Vec<u8>>,
        notes: VecDeque<[u8; 8]>,
        outstanding: [bool; 2],
        sent: Vec<Vec<u8>>,
        requests: Vec<(SetupPacket, Vec<u8>)>,
        configured: Vec<u8>,
        submit_lens: Vec<usize>,
        /// The data interface's alternate setting.
        alternate: u8,
    }

    impl Default for FakeNcm {
        fn default() -> Self {
            Self {
                params: params(16384, 16384, 4, 0, 4),
                caps_ntb_input_8: false,
                ntbs: VecDeque::new(),
                notes: VecDeque::new(),
                outstanding: [false; 2],
                sent: Vec::new(),
                requests: Vec::new(),
                configured: Vec::new(),
                submit_lens: Vec::new(),
                alternate: 0,
            }
        }
    }

    impl UsbHost for FakeNcm {
        fn num_ports(&self) -> u8 {
            1
        }
        fn port_status(&self, _: u8) -> PortStatus {
            panic!("not used by this test")
        }
        fn attach(&mut self, _: u8) -> Result<DeviceId, UsbError> {
            panic!("not used by this test")
        }
        fn detach(&mut self, _: DeviceId) {}
        fn configure_endpoints(&mut self, _: DeviceId, eps: &[EndpointDescriptor]) -> Result<(), UsbError> {
            self.configured.extend(eps.iter().map(|e| e.address));
            Ok(())
        }
        fn control_in(&mut self, _: DeviceId, s: SetupPacket, buf: &mut [u8]) -> Result<usize, UsbError> {
            self.requests.push((s, Vec::new()));
            let d = match (s.request_type, s.request) {
                (0x80, 6) => match s.value {
                    0x0300 => std::vec![4, 3, 0x09, 0x04],
                    0x0304 => utf16("0200005e1001"),
                    _ => return Err(UsbError::Stall),
                },
                (0xa1, GET_NTB_PARAMETERS) => self.params.to_vec(),
                _ => return Err(UsbError::Stall),
            };
            let n = d.len().min(s.length as usize);
            buf[..n].copy_from_slice(&d[..n]);
            Ok(n)
        }
        fn control_out(&mut self, _: DeviceId, s: SetupPacket, data: &[u8]) -> Result<(), UsbError> {
            assert_eq!(data.len(), s.length as usize);
            self.requests.push((s, data.to_vec()));
            match s.request {
                SET_NTB_FORMAT | SET_NTB_INPUT_SIZE => {
                    assert_eq!(self.alternate, 0, "NTB settings only change in alternate setting 0");
                    if s.request == SET_NTB_INPUT_SIZE {
                        assert_eq!(data.len(), if self.caps_ntb_input_8 { 8 } else { 4 });
                    }
                }
                11 => self.alternate = s.value as u8,
                _ => {}
            }
            Ok(())
        }
        fn transfer_in(&mut self, _: DeviceId, _: u8, _: &mut [u8]) -> Result<usize, UsbError> {
            panic!("not used by this test")
        }
        fn transfer_out(&mut self, _: DeviceId, ep: u8, data: &[u8]) -> Result<(), UsbError> {
            assert_eq!(ep, 0x01);
            self.sent.push(data.to_vec());
            Ok(())
        }
        fn submit_in(&mut self, _: DeviceId, ep: u8, len: usize) -> Result<(), UsbError> {
            let i = (ep == 0x82) as usize;
            assert!(!self.outstanding[i], "one transfer per endpoint");
            self.outstanding[i] = true;
            if i == 1 {
                assert_eq!(self.alternate, 1);
                self.submit_lens.push(len);
            }
            Ok(())
        }
        fn poll_in(&mut self, _: DeviceId, ep: u8, buf: &mut [u8]) -> Option<Result<usize, UsbError>> {
            let i = (ep == 0x82) as usize;
            assert!(self.outstanding[i]);
            let data = if i == 1 { self.ntbs.pop_front()? } else { self.notes.pop_front()?.to_vec() };
            self.outstanding[i] = false;
            buf[..data.len()].copy_from_slice(&data);
            Some(Ok(data.len()))
        }
    }

    fn nic() -> UsbNcm<FakeNcm> {
        UsbNcm::new(FakeNcm::default(), DeviceId(2), &CONFIG).unwrap()
    }

    #[test]
    fn bring_up() {
        let eth = nic();
        assert_eq!(eth.mac_address(), MacAddress([0x02, 0x00, 0x00, 0x5e, 0x10, 0x01]));
        assert_eq!(eth.max_frame_len(), 1514);
        assert!(eth.link_up() && !eth.can_receive());
        let h = &eth.host;
        assert_eq!(h.configured, [0x82, 0x01]);
        let class: Vec<_> =
            h.requests.iter().filter(|(r, _)| r.request_type & 0x60 == 0x20).map(|(r, d)| (r.to_bytes(), d)).collect();
        let size = (RX_NTB_LEN as u32).to_le_bytes().to_vec();
        assert_eq!(
            class,
            [
                ([0xa1, 0x80, 0, 0, 0, 0, 28, 0], &Vec::new()),   // GET_NTB_PARAMETERS
                ([0x21, 0x84, 0, 0, 0, 0, 0, 0], &Vec::new()),    // SET_NTB_FORMAT 16-bit
                ([0x21, 0x86, 0, 0, 0, 0, 4, 0], &size),          // SET_NTB_INPUT_SIZE 4096
                ([0x21, 0x43, 0x0e, 0, 0, 0, 0, 0], &Vec::new())  // packet filter
            ]
        );
        assert_eq!(h.alternate, 1);
        assert_eq!(h.outstanding, [true, true]);
        assert_eq!(h.submit_lens, [RX_NTB_LEN]);
    }

    #[test]
    fn small_devices_keep_their_sizes() {
        // A device whose NTBs already fit, with only 16-bit NTBs, is not
        // told about either.
        let mut p = params(2048, 2048, 4, 0, 4);
        p[2] = FORMAT_NTB16 as u8;
        let eth = UsbNcm::new(FakeNcm { params: p, ..Default::default() }, DeviceId(2), &CONFIG).unwrap();
        assert!(!eth.host.requests.iter().any(|(r, _)| matches!(r.request, SET_NTB_FORMAT | SET_NTB_INPUT_SIZE)));
        assert_eq!(eth.host.submit_lens, [2048]);
    }

    #[test]
    fn eight_byte_input_size() {
        let mut config = CONFIG;
        config[9 + 9 + 5 + 5 + 13 + 5] |= capability::NTB_INPUT_SIZE_8;
        let host = FakeNcm { caps_ntb_input_8: true, ..Default::default() };
        let eth = UsbNcm::new(host, DeviceId(2), &config).unwrap();
        let (_, data) = eth.host.requests.iter().find(|(r, _)| r.request == SET_NTB_INPUT_SIZE).unwrap();
        assert_eq!(data[..], [0x00, 0x10, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn rejects_unusable_devices() {
        let new = |host| UsbNcm::new(host, DeviceId(2), &CONFIG).err();
        let mut p = params(16384, 16384, 4, 0, 4);
        p[2] = FORMAT_NTB32 as u8;
        assert_eq!(new(FakeNcm { params: p, ..Default::default() }), Some(UsbError::BadDescriptor), "no NTB16");
        let p = params(16384, 1024, 4, 0, 4);
        assert_eq!(new(FakeNcm { params: p, ..Default::default() }), Some(UsbError::BadDescriptor), "tiny NTBs");
        let mut p = params(16384, 16384, 4, 0, 4);
        p[0] = 0;
        assert_eq!(new(FakeNcm { params: p, ..Default::default() }), Some(UsbError::BadDescriptor));
        assert_eq!(UsbNcm::new(FakeNcm::default(), DeviceId(2), &CONFIG[..9]).err(), Some(UsbError::BadDescriptor));
    }

    #[test]
    fn transmit_frames() {
        let mut eth = nic();
        let frame: Vec<u8> = (0..60).collect();
        eth.transmit(&frame).unwrap();
        eth.transmit(&frame).unwrap();
        let sent = core::mem::take(&mut eth.host.sent);
        assert_eq!(sent.len(), 2);
        for (seq, ntb) in sent.iter().enumerate() {
            assert_eq!(u16::from_le_bytes([ntb[6], ntb[7]]), seq as u16);
            assert_eq!(datagrams(ntb), Ok(std::vec![frame.clone()]));
        }
        assert_eq!(eth.transmit(&[0; 1515]), Err(NetError::TooLarge));
        // An NTB that fills its last packet is followed by an empty one.
        eth.transmit(&[5; 512 - 28]).unwrap();
        assert_eq!(eth.host.sent.iter().map(Vec::len).collect::<Vec<_>>(), [512, 0]);
    }

    #[test]
    fn receive_datagrams() {
        let mut eth = nic();
        let mut buf = [0u8; 1514];
        assert_eq!(eth.receive(&mut buf), Err(NetError::WouldBlock));

        eth.host.ntbs.push_back(ntb(&[&[1; 60], &[2; 1514], &[3; 42]]));
        eth.host.ntbs.push_back(std::vec![]); // an empty packet is skipped
        eth.host.ntbs.push_back(ntb(&[&[4; 64]]));
        assert_eq!(eth.receive(&mut buf), Ok(60));
        assert!(eth.can_receive());
        assert!(!eth.host.outstanding[1], "the NTB still holds the buffer");
        assert_eq!(eth.receive(&mut buf), Ok(1514));
        assert_eq!(buf[1513], 2);
        assert_eq!(eth.receive(&mut buf), Ok(42));
        assert_eq!(buf[..42], [3; 42]);
        // The last datagram freed the buffer, and the fake completes the
        // transfers at once: the empty packet, then the next NTB.
        assert_eq!(eth.receive(&mut buf), Ok(64));
        assert_eq!(eth.receive(&mut buf), Err(NetError::WouldBlock));
        assert_eq!(eth.host.submit_lens.len(), 4);
        assert_eq!(eth.bad_ntbs(), 0);
    }

    #[test]
    fn bad_ntbs_are_counted_and_skipped() {
        let mut eth = nic();
        eth.host.ntbs.push_back(std::vec![0x55; 100]);
        eth.host.ntbs.push_back(ntb(&[&[7; 60]]));
        let mut buf = [0u8; 1514];
        assert_eq!(eth.receive(&mut buf), Err(NetError::WouldBlock));
        assert_eq!(eth.bad_ntbs(), 1);
        assert_eq!(eth.receive(&mut buf), Ok(60));
    }

    #[test]
    fn oversized_datagram_is_dropped() {
        let mut eth = nic();
        eth.host.ntbs.push_back(ntb(&[&[1; 200], &[2; 50]]));
        let mut small = [0u8; 100];
        assert_eq!(eth.receive(&mut small), Err(NetError::TooLarge));
        assert_eq!(eth.receive(&mut small), Ok(50));
        assert_eq!(small[0], 2);
    }

    #[test]
    fn link_follows_notifications() {
        let mut eth = nic();
        eth.host.notes.push_back([0xa1, 0, 0, 0, 0, 0, 0, 0]);
        eth.service().unwrap();
        assert!(!eth.link_up());
        assert_eq!(eth.transmit(&[0; 60]), Err(NetError::LinkDown));
        // CONNECTION_SPEED_CHANGE, which NCM devices send too, is ignored.
        eth.host.notes.push_back([0xa1, 0x2a, 0, 0, 0, 0, 8, 0]);
        eth.service().unwrap();
        assert!(!eth.link_up());
        eth.host.notes.push_back([0xa1, 0, 1, 0, 0, 0, 0, 0]);
        eth.service().unwrap();
        assert!(eth.link_up());
        eth.transmit(&[0; 60]).unwrap();
    }

    #[test]
    fn hostile_input_never_panics() {
        // Every prefix of a good NTB, and of the config and parameters, is
        // handled; corrupting each byte of an NTB in turn is too.
        let good = ntb(&[&[1; 60], &[2; 61]]);
        for n in 0..good.len() {
            let _ = datagrams(&good[..n]);
        }
        for at in 0..good.len() {
            for v in [0u8, 1, 0x7f, 0xff] {
                let mut b = good.clone();
                b[at] = v;
                let _ = datagrams(&b);
            }
        }
        for n in 0..CONFIG.len() {
            let _ = NcmFunction::parse(&CONFIG[..n]);
        }
        let p = params(16384, 16384, 4, 0, 4);
        for n in 0..p.len() {
            assert_eq!(NtbParameters::parse(&p[..n]), None);
        }
        // A reader used with a buffer shorter than its NTB ends the walk.
        let mut r = NtbReader::new(&good).unwrap();
        assert_eq!(r.next(&good[..14]), Err(BadNtb));
    }
}
