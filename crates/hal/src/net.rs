//! Network interfaces.
//!
//! [`NetDevice`] moves whole Ethernet frames (destination MAC through
//! payload, without the FCS) by copying, in the style of [`BlockDevice`]:
//! the driver owns its DMA buffers and the caller owns its slices. A network
//! stack adapts this to its own buffer model (smoltcp's `phy::Device`, for
//! one, maps onto it directly).
//!
//! [`BlockDevice`]: crate::block::BlockDevice

use core::fmt;

/// A 48-bit IEEE 802 MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// Returns true for group (multicast and broadcast) addresses.
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 1 != 0
    }

    /// Returns true for locally administered addresses.
    pub const fn is_local(self) -> bool {
        self.0[0] & 2 != 0
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// Why a network operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetError {
    /// Nothing to receive, or no room to transmit; try again later.
    WouldBlock,
    /// The frame is larger than the device accepts, or the receive buffer is
    /// smaller than the frame (the frame is dropped).
    TooLarge,
    /// The link is down.
    LinkDown,
    /// The device reported an error.
    Io,
}

/// An Ethernet interface.
pub trait NetDevice {
    /// The interface's MAC address.
    fn mac_address(&self) -> MacAddress;

    /// Largest frame accepted by [`transmit`](Self::transmit) and returned by
    /// [`receive`](Self::receive), in bytes, including the 14-byte Ethernet
    /// header.
    fn max_frame_len(&self) -> usize {
        1514
    }

    /// Returns true if the link is up. Devices that cannot tell report up.
    fn link_up(&self) -> bool {
        true
    }

    /// Queues `frame` for transmission. Returns [`NetError::WouldBlock`] if
    /// the transmit queue is full.
    fn transmit(&mut self, frame: &[u8]) -> Result<(), NetError>;

    /// Copies the next received frame into `buf` and returns its length.
    /// Returns [`NetError::WouldBlock`] if no frame is waiting.
    fn receive(&mut self, buf: &mut [u8]) -> Result<usize, NetError>;

    /// Returns true if a frame is waiting to be received.
    fn can_receive(&self) -> bool;

    /// Returns true if [`transmit`](Self::transmit) would accept a frame now.
    fn can_transmit(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::MacAddress;
    use std::format;

    #[test]
    fn mac_address() {
        let mac = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(format!("{mac}"), "52:54:00:12:34:56");
        assert!(!mac.is_multicast() && mac.is_local(), "QEMU's prefix is locally administered");
        assert!(MacAddress::BROADCAST.is_multicast());
        assert!(!MacAddress([0x00, 0x1b, 0x21, 0, 0, 1]).is_local());
    }
}
