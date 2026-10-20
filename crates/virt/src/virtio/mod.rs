//! virtio device models: the split virtqueue, the virtio-mmio transport,
//! and devices that plug into it.
//!
//! A device implements [`VirtioDevice`]; [`VirtioMmio`] wraps it as a
//! [`BusDevice`](crate::BusDevice) that handles feature negotiation, queue
//! setup, notifications and interrupts.

mod block;
mod console;
mod mmio;
mod net;
pub mod queue;

pub use block::VirtioBlock;
pub use console::VirtioConsole;
pub use mmio::{DeviceCtx, MMIO_SIZE, VirtioMmio};
pub use net::{NetBackend, VirtioNetDevice};
pub use queue::{Desc, DescChain, QueueError, SplitQueue};

pub use osmium_hal::virtio::{device_id, feature, status};

/// A virtio device model, independent of the transport.
pub trait VirtioDevice: Send {
    /// virtio device ID (1 net, 2 block, 3 console, ...).
    fn device_id(&self) -> u32;

    /// Device-specific feature bits offered to the driver. The transport
    /// adds [`feature::VERSION_1`].
    fn features(&self) -> u64 {
        0
    }

    /// Called with the features the driver accepted, once negotiation succeeds.
    fn ack_features(&mut self, _features: u64) {}

    /// Number of virtqueues.
    fn num_queues(&self) -> usize;

    /// Largest queue size the device supports.
    fn queue_max_size(&self) -> u16 {
        256
    }

    /// Reads device-specific config space.
    fn read_config(&self, _offset: u64, data: &mut [u8]) {
        data.fill(0);
    }

    /// Writes device-specific config space.
    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    /// The driver notified queue `queue`: process its available buffers.
    fn notify(&mut self, queue: usize, ctx: &mut DeviceCtx<'_>);

    /// The driver reset the device.
    fn reset(&mut self) {}
}
