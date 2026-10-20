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
    pub const GPU: u32 = 16;
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

/// virtio-blk (§5.2).
pub mod blk {
    #![allow(missing_docs)]

    /// Device is read-only.
    pub const F_RO: u64 = 1 << 5;
    /// `blk_size` in configuration space is the preferred block size.
    pub const F_BLK_SIZE: u64 = 1 << 6;
    /// The device has a write cache and handles [`T_FLUSH`].
    pub const F_FLUSH: u64 = 1 << 9;

    /// Request type: read.
    pub const T_IN: u32 = 0;
    /// Request type: write.
    pub const T_OUT: u32 = 1;
    /// Request type: flush the write cache.
    pub const T_FLUSH: u32 = 4;
    /// Request type: read the device ID string.
    pub const T_GET_ID: u32 = 8;

    /// Request status: success.
    pub const S_OK: u8 = 0;
    /// Request status: I/O error.
    pub const S_IOERR: u8 = 1;
    /// Request status: request type not supported.
    pub const S_UNSUPP: u8 = 2;

    /// Configuration space: capacity in 512-byte sectors (le64).
    pub const CONFIG_CAPACITY: usize = 0;

    /// Configuration space: preferred block size in bytes (le32), with
    /// [`F_BLK_SIZE`].
    pub const CONFIG_BLK_SIZE: usize = 20;

    /// Bytes in a sector, the unit of `capacity` and request addresses.
    pub const SECTOR_SIZE: usize = 512;
    /// Length of the request header (type, reserved, sector).
    pub const HEADER_LEN: usize = 16;
    /// The request queue's index.
    pub const REQUEST_QUEUE: u16 = 0;
}

/// virtio over PCI (§4.1): vendor-specific capabilities locate the
/// register structures in the device's BARs.
pub mod pci {
    #![allow(missing_docs)]

    /// PCI vendor ID of every virtio device.
    pub const VENDOR_ID: u16 = 0x1af4;
    /// Device IDs from 0x1040 are modern devices: `0x1040 + device type`.
    pub const MODERN_DEVICE_ID_BASE: u16 = 0x1040;
    /// Device IDs 0x1000–0x103f are transitional devices; the PCI subsystem
    /// device ID holds the device type.
    pub const TRANSITIONAL_DEVICE_IDS: core::ops::RangeInclusive<u16> = 0x1000..=0x103f;

    /// `virtio_pci_cap` fields, as offsets from the capability.
    pub const CAP_CFG_TYPE: u16 = 3;
    pub const CAP_BAR: u16 = 4;
    pub const CAP_OFFSET: u16 = 8;
    pub const CAP_LENGTH: u16 = 12;
    /// `virtio_pci_notify_cap.notify_off_multiplier`.
    pub const CAP_NOTIFY_OFF_MULTIPLIER: u16 = 16;

    /// `cfg_type` values.
    pub const CAP_COMMON_CFG: u8 = 1;
    pub const CAP_NOTIFY_CFG: u8 = 2;
    pub const CAP_ISR_CFG: u8 = 3;
    pub const CAP_DEVICE_CFG: u8 = 4;
    pub const CAP_PCI_CFG: u8 = 5;

    /// `virtio_pci_common_cfg` fields.
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    pub const DEVICE_FEATURE: usize = 0x04;
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    pub const DRIVER_FEATURE: usize = 0x0c;
    pub const CONFIG_MSIX_VECTOR: usize = 0x10;
    pub const NUM_QUEUES: usize = 0x12;
    pub const DEVICE_STATUS: usize = 0x14;
    pub const CONFIG_GENERATION: usize = 0x15;
    pub const QUEUE_SELECT: usize = 0x16;
    pub const QUEUE_SIZE: usize = 0x18;
    pub const QUEUE_MSIX_VECTOR: usize = 0x1a;
    pub const QUEUE_ENABLE: usize = 0x1c;
    pub const QUEUE_NOTIFY_OFF: usize = 0x1e;
    pub const QUEUE_DESC: usize = 0x20;
    pub const QUEUE_DRIVER: usize = 0x28;
    pub const QUEUE_DEVICE: usize = 0x30;
    /// Bytes of the common configuration structure the driver uses.
    pub const COMMON_CFG_LEN: usize = 0x38;

    /// ISR status bit: a used ring was updated.
    pub const ISR_QUEUE: u8 = 1;
    /// ISR status bit: the configuration changed.
    pub const ISR_CONFIG: u8 = 2;
}

/// virtio-gpu (§5.7): 2D commands on the control queue.
///
/// Every request and response starts with the 24-byte control header
/// `type: le32, flags: le32, fence_id: le64, ctx_id: le32, ring_idx: u8,
/// padding: [u8; 3]`. Rectangles are `x, y, width, height: le32`.
pub mod gpu {
    #![allow(missing_docs)]

    /// The device supports 3D (virgl) commands.
    pub const F_VIRGL: u64 = 1 << 0;
    /// The device answers `GET_EDID`.
    pub const F_EDID: u64 = 1 << 1;

    /// Configuration space: pending events (le32).
    pub const CONFIG_EVENTS_READ: usize = 0;
    /// Configuration space: write 1s to clear events (le32).
    pub const CONFIG_EVENTS_CLEAR: usize = 4;
    /// Configuration space: number of scanouts (le32).
    pub const CONFIG_NUM_SCANOUTS: usize = 8;
    /// Event: the display configuration changed.
    pub const EVENT_DISPLAY: u32 = 1;

    pub const CONTROL_QUEUE: u16 = 0;
    pub const CURSOR_QUEUE: u16 = 1;

    /// Most scanouts a device has.
    pub const MAX_SCANOUTS: usize = 16;

    // Commands.
    pub const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
    pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
    pub const CMD_RESOURCE_UNREF: u32 = 0x0102;
    pub const CMD_SET_SCANOUT: u32 = 0x0103;
    pub const CMD_RESOURCE_FLUSH: u32 = 0x0104;
    pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
    pub const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
    pub const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
    pub const CMD_GET_EDID: u32 = 0x010a;
    pub const CMD_UPDATE_CURSOR: u32 = 0x0300;
    pub const CMD_MOVE_CURSOR: u32 = 0x0301;

    // Responses.
    pub const RESP_OK_NODATA: u32 = 0x1100;
    pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
    pub const RESP_OK_EDID: u32 = 0x1104;
    pub const RESP_ERR_UNSPEC: u32 = 0x1200;
    pub const RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
    pub const RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
    pub const RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
    pub const RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

    /// Header flag: `fence_id` is valid; respond only once the command has
    /// finished.
    pub const FLAG_FENCE: u32 = 1;

    // Formats (`enum virtio_gpu_formats`), named by byte order in memory.
    pub const FORMAT_B8G8R8A8_UNORM: u32 = 1;
    pub const FORMAT_B8G8R8X8_UNORM: u32 = 2;
    pub const FORMAT_A8R8G8B8_UNORM: u32 = 3;
    pub const FORMAT_X8R8G8B8_UNORM: u32 = 4;
    pub const FORMAT_R8G8B8A8_UNORM: u32 = 67;
    pub const FORMAT_X8B8G8R8_UNORM: u32 = 68;
    pub const FORMAT_A8B8G8R8_UNORM: u32 = 121;
    pub const FORMAT_R8G8B8X8_UNORM: u32 = 134;

    /// Bytes of the control header.
    pub const HDR_LEN: usize = 24;
    /// Bytes of one `virtio_gpu_display_one` (rect, enabled, flags).
    pub const DISPLAY_ONE_LEN: usize = 24;
    /// Bytes of `virtio_gpu_resp_display_info`.
    pub const RESP_DISPLAY_INFO_LEN: usize = HDR_LEN + MAX_SCANOUTS * DISPLAY_ONE_LEN;
    /// `resource_create_2d`: header, resource_id, format, width, height.
    pub const RESOURCE_CREATE_2D_LEN: usize = HDR_LEN + 16;
    /// `resource_attach_backing`: header, resource_id, nr_entries, then
    /// [`MEM_ENTRY_LEN`]-byte entries.
    pub const RESOURCE_ATTACH_BACKING_LEN: usize = HDR_LEN + 8;
    /// `virtio_gpu_mem_entry`: addr le64, length le32, padding.
    pub const MEM_ENTRY_LEN: usize = 16;
    /// `set_scanout`: header, rect, scanout_id, resource_id.
    pub const SET_SCANOUT_LEN: usize = HDR_LEN + 24;
    /// `transfer_to_host_2d`: header, rect, offset le64, resource_id, padding.
    pub const TRANSFER_TO_HOST_2D_LEN: usize = HDR_LEN + 32;
    /// `resource_flush`: header, rect, resource_id, padding.
    pub const RESOURCE_FLUSH_LEN: usize = HDR_LEN + 24;
    /// `resource_unref` and `resource_detach_backing`: header,
    /// resource_id, padding.
    pub const RESOURCE_UNREF_LEN: usize = HDR_LEN + 8;
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
