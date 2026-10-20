//! virtio wire formats shared by drivers and device models.
//!
//! Constants and layout arithmetic from the virtio 1.2 specification (and
//! the legacy interface where it differs), with no driver or device state:
//! `osmium-drivers` builds the driver side on them and `osmium-virt` the
//! device side.

/// Device type IDs (§5).
pub mod device_id {
    #![allow(missing_docs)]
    pub const NET: u32 = 1;
    pub const BLOCK: u32 = 2;
    pub const CONSOLE: u32 = 3;
    pub const RNG: u32 = 4;
}

/// Device status bits (§2.1).
pub mod status {
    #![allow(missing_docs)]
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

/// Feature bits common to all device types (§6).
pub mod feature {
    /// Driver may use indirect descriptor tables.
    pub const INDIRECT_DESC: u64 = 1 << 28;
    /// `used_event`/`avail_event` notification suppression.
    pub const EVENT_IDX: u64 = 1 << 29;
    /// Descriptors may split headers and data any way (always true for 1.x).
    pub const ANY_LAYOUT: u64 = 1 << 27;
    /// The device follows the 1.x specification.
    pub const VERSION_1: u64 = 1 << 32;
    /// The device can access only some of memory (needs an IOMMU or
    /// bounce buffers).
    pub const ACCESS_PLATFORM: u64 = 1 << 33;
}

/// virtio-mmio registers (§4.2.2; legacy §4.2.4).
pub mod mmio {
    #![allow(missing_docs)]
    /// Contents of `MAGIC_VALUE`: "virt", little-endian.
    pub const MAGIC: u32 = 0x7472_6976;
    pub const VERSION_LEGACY: u32 = 1;
    pub const VERSION_MODERN: u32 = 2;

    pub const MAGIC_VALUE: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const VENDOR_ID: usize = 0x00c;
    pub const DEVICE_FEATURES: usize = 0x010;
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    pub const DRIVER_FEATURES: usize = 0x020;
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    /// Legacy only.
    pub const GUEST_PAGE_SIZE: usize = 0x028;
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM_MAX: usize = 0x034;
    pub const QUEUE_NUM: usize = 0x038;
    /// Legacy only.
    pub const QUEUE_ALIGN: usize = 0x03c;
    /// Legacy only.
    pub const QUEUE_PFN: usize = 0x040;
    /// Modern only.
    pub const QUEUE_READY: usize = 0x044;
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const INTERRUPT_STATUS: usize = 0x060;
    pub const INTERRUPT_ACK: usize = 0x064;
    pub const STATUS: usize = 0x070;
    /// Modern only (as are the five below).
    pub const QUEUE_DESC_LOW: usize = 0x080;
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    pub const QUEUE_DRIVER_LOW: usize = 0x090;
    pub const QUEUE_DRIVER_HIGH: usize = 0x094;
    pub const QUEUE_DEVICE_LOW: usize = 0x0a0;
    pub const QUEUE_DEVICE_HIGH: usize = 0x0a4;
    pub const CONFIG_GENERATION: usize = 0x0fc;
    pub const CONFIG: usize = 0x100;

    /// `INTERRUPT_STATUS` bit: a used ring was updated.
    pub const USED_BUFFER: u32 = 1;
    /// `INTERRUPT_STATUS` bit: the configuration changed.
    pub const CONFIG_CHANGE: u32 = 2;
}

/// Split virtqueue layout (§2.7; legacy §2.7.2 "Legacy Interfaces").
///
/// Descriptor: `addr: le64, len: le32, flags: le16, next: le16`.
/// Available ring: `flags: le16, idx: le16, ring: [le16; size], used_event: le16`.
/// Used ring: `flags: le16, idx: le16, ring: [{id: le32, len: le32}; size], avail_event: le16`.
pub mod queue {
    /// Bytes per descriptor.
    pub const DESC_SIZE: usize = 16;
    /// Descriptor continues via `next`.
    pub const DESC_F_NEXT: u16 = 1;
    /// Buffer is device-writable.
    pub const DESC_F_WRITE: u16 = 2;
    /// Buffer holds a table of indirect descriptors.
    pub const DESC_F_INDIRECT: u16 = 4;
    /// Driver: do not interrupt when consuming buffers.
    pub const AVAIL_F_NO_INTERRUPT: u16 = 1;
    /// Device: do not notify when adding buffers.
    pub const USED_F_NO_NOTIFY: u16 = 1;
    /// Alignment of the used ring in the legacy contiguous layout (and the
    /// page size legacy MMIO drivers report).
    pub const LEGACY_ALIGN: usize = 4096;

    /// Bytes of the descriptor table.
    pub const fn desc_table_size(size: u16) -> usize {
        DESC_SIZE * size as usize
    }

    /// Bytes of the available ring, including `used_event`.
    pub const fn avail_size(size: u16) -> usize {
        6 + 2 * size as usize
    }

    /// Bytes of the used ring, including `avail_event`.
    pub const fn used_size(size: u16) -> usize {
        6 + 8 * size as usize
    }

    /// Offset of `avail.ring[slot]` from the start of the available ring.
    pub const fn avail_entry(slot: u16) -> usize {
        4 + 2 * slot as usize
    }

    /// Offset of `used.ring[slot]` from the start of the used ring.
    pub const fn used_entry(slot: u16) -> usize {
        4 + 8 * slot as usize
    }

    /// Offset of the available ring in the legacy contiguous layout.
    pub const fn legacy_avail_offset(size: u16) -> usize {
        desc_table_size(size)
    }

    /// Offset of the used ring in the legacy contiguous layout.
    pub const fn legacy_used_offset(size: u16) -> usize {
        (legacy_avail_offset(size) + avail_size(size)).next_multiple_of(LEGACY_ALIGN)
    }

    /// Total bytes of a queue in the legacy contiguous layout.
    pub const fn legacy_size(size: u16) -> usize {
        legacy_used_offset(size) + used_size(size)
    }
}

/// virtio-net (§5.1).
pub mod net {
    /// Configuration space holds the MAC address.
    pub const F_MAC: u64 = 1 << 5;
    /// Configuration space holds the link status.
    pub const F_STATUS: u64 = 1 << 16;
    /// Receive buffers may be merged.
    pub const F_MRG_RXBUF: u64 = 1 << 15;

    /// Configuration space: MAC address offset.
    pub const CONFIG_MAC: usize = 0;
    /// Configuration space: status word offset.
    pub const CONFIG_STATUS: usize = 6;
    /// Status word: link is up.
    pub const STATUS_LINK_UP: u16 = 1;

    /// Receive queue index (single queue pair).
    pub const RX_QUEUE: u16 = 0;
    /// Transmit queue index.
    pub const TX_QUEUE: u16 = 1;

    /// Length of `struct virtio_net_hdr` preceding every frame.
    pub const fn header_len(version_1: bool, mrg_rxbuf: bool) -> usize {
        if version_1 || mrg_rxbuf { 12 } else { 10 }
    }
}

#[cfg(test)]
mod tests {
    use super::queue::*;

    #[test]
    fn legacy_layout() {
        // Linux's vring_size(256, 4096).
        assert_eq!(legacy_size(256), 10246);
        assert_eq!(legacy_used_offset(8), 4096);
        assert_eq!(legacy_avail_offset(8), 128);
    }
}
