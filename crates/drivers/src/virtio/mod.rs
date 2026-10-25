//! virtio devices.
//!
//! A virtio driver is split the way the specification is: a [`Transport`]
//! ([`mmio::MmioTransport`] or [`pci::PciTransport`]) reaches the device's registers, a
//! [`queue::VirtQueue`] shares buffers with it through DMA memory, and the
//! device driver (such as `osmium_netdev::virtio_net::VirtioNet` or `osmium_storage::virtio_blk::VirtioBlk`) speaks the device type's protocol over
//! both.
//!
//! Both the legacy (0.9.5) and modern (1.x) interfaces are supported, since
//! QEMU still offers legacy virtio-mmio devices by default. Register offsets,
//! feature bits and ring layout come from [`osmium_hal::virtio`], which
//! device models share.

use osmium_hal::virtio::device_id;
use osmium_mm::PhysAddr;

pub mod mmio;
pub mod pci;
pub mod queue;

/// Device type IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceType {
    /// Network card.
    Net,
    /// Block device.
    Block,
    /// Console.
    Console,
    /// Entropy source.
    Rng,
    /// Graphics adapter.
    Gpu,
    /// Any other ID (0 means no device behind this transport).
    Other(u32),
}

impl From<u32> for DeviceType {
    fn from(id: u32) -> Self {
        match id {
            device_id::NET => DeviceType::Net,
            device_id::BLOCK => DeviceType::Block,
            device_id::CONSOLE => DeviceType::Console,
            device_id::RNG => DeviceType::Rng,
            device_id::GPU => DeviceType::Gpu,
            other => DeviceType::Other(other),
        }
    }
}

pub use osmium_hal::virtio::{feature, status};

/// Why a virtio operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioError {
    /// The registers do not belong to a virtio device, or no device is
    /// behind them.
    NotPresent,
    /// The device is not of the type the driver handles.
    WrongDevice,
    /// The device lacks a feature the driver needs, or rejected the
    /// negotiated set.
    Unsupported,
    /// A queue is missing or too small.
    BadQueue,
    /// DMA memory could not be allocated.
    NoMemory,
    /// The queue has no free descriptors.
    QueueFull,
}

/// Device addresses of a split virtqueue's three parts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueAddrs {
    /// Descriptor table. For legacy devices, the whole queue starts here
    /// (page aligned), with the used ring on the next page boundary after
    /// the available ring.
    pub desc: PhysAddr,
    /// Available (driver) ring.
    pub avail: PhysAddr,
    /// Used (device) ring.
    pub used: PhysAddr,
}

/// How a driver reaches a virtio device's registers.
pub trait Transport {
    /// The device type, or `Other(0)` if no device is present.
    fn device_type(&self) -> DeviceType;

    /// True for a legacy (pre-1.0) interface.
    fn is_legacy(&self) -> bool;

    /// The features the device offers.
    fn device_features(&self) -> u64;

    /// Accepts `features`.
    fn set_driver_features(&self, features: u64);

    /// The device status byte.
    fn status(&self) -> u8;

    /// Writes the device status byte; 0 resets the device.
    fn set_status(&self, status: u8);

    /// Largest size queue `index` supports (0 if it does not exist).
    fn max_queue_size(&self, index: u16) -> u16;

    /// Hands queue `index`, with `size` entries at `addrs`, to the device and
    /// enables it.
    fn setup_queue(&self, index: u16, size: u16, addrs: QueueAddrs);

    /// Tells the device that queue `index` has new available buffers.
    fn notify(&self, index: u16);

    /// Reads and acknowledges the interrupt status (bit 0: a used ring was
    /// updated, bit 1: the configuration changed).
    fn ack_interrupt(&self) -> u32;

    /// Reads a byte of device-specific configuration; 0 beyond what the
    /// device provides.
    fn config_read8(&self, offset: usize) -> u8;

    /// Reads a little-endian word of device-specific configuration.
    fn config_read16(&self, offset: usize) -> u16 {
        u16::from_le_bytes([self.config_read8(offset), self.config_read8(offset + 1)])
    }
}

/// Resets the device and negotiates features (spec 3.1.1 steps 1–6).
///
/// The device must offer every bit of `required`; bits of `optional` are
/// taken where offered. [`feature::VERSION_1`] is accepted whenever offered.
/// Returns the negotiated set. Finish initialization by setting up the
/// queues and calling [`driver_ok`].
pub fn negotiate<T: Transport + ?Sized>(t: &T, required: u64, optional: u64) -> Result<u64, VirtioError> {
    t.set_status(0);
    t.set_status(status::ACKNOWLEDGE);
    t.set_status(status::ACKNOWLEDGE | status::DRIVER);
    let offered = t.device_features();
    if offered & required != required {
        t.set_status(status::FAILED);
        return Err(VirtioError::Unsupported);
    }
    let features = offered & (required | optional | feature::VERSION_1);
    t.set_driver_features(features);
    if !t.is_legacy() {
        // A modern interface must offer VERSION_1 (§6.1).
        if features & feature::VERSION_1 == 0 {
            t.set_status(status::FAILED);
            return Err(VirtioError::Unsupported);
        }
        t.set_status(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);
        if t.status() & status::FEATURES_OK == 0 {
            t.set_status(status::FAILED);
            return Err(VirtioError::Unsupported);
        }
    }
    Ok(features)
}

/// How many times [`reset`] polls the status, and drivers poll a queue for
/// a synchronous request's completion, before giving up on the device.
pub const POLL_LIMIT: u32 = 50_000_000;

/// Resets the device and waits until it reads back status 0, as the driver
/// must before freeing memory the device may use (§4.1.4.3.2). Returns
/// false if it never did: the device may still be using the queues, which
/// must then be leaked rather than freed.
pub fn reset<T: Transport + ?Sized>(t: &T) -> bool {
    t.set_status(0);
    (0..POLL_LIMIT).any(|_| {
        let done = t.status() == 0;
        core::hint::spin_loop();
        done
    })
}

/// Marks the device live after its queues are set up.
pub fn driver_ok<T: Transport + ?Sized>(t: &T) {
    t.set_status(t.status() | status::DRIVER_OK);
}

#[cfg(any(test, feature = "testing"))]
#[allow(missing_docs, dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
pub mod testing {
    //! A host-memory DMA allocator and a scriptable transport, so tests can
    //! play the device's side of a virtqueue. Other crates get it through the
    //! `testing` feature.

    use core::cell::{Cell, RefCell};
    use core::ptr::NonNull;
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::vec::Vec;

    use osmium_hal::dma::{DmaAllocator, DmaBuffer};
    use osmium_mm::PhysAddr;

    use super::*;

    /// Page-aligned heap memory whose device address is its host address.
    #[derive(Default)]
    pub struct HostDma {
        pub live: Cell<usize>,
    }

    impl DmaAllocator for HostDma {
        fn alloc_coherent(&self, len: usize) -> Option<DmaBuffer> {
            let layout = Layout::from_size_align(len.max(1), 4096).ok()?;
            // SAFETY: non-zero size.
            let p = NonNull::new(unsafe { alloc_zeroed(layout) })?;
            self.live.set(self.live.get() + 1);
            // SAFETY: fresh, exclusively owned memory; identity-mapped.
            Some(unsafe { DmaBuffer::new(p, PhysAddr::new(p.as_ptr() as u64), len) })
        }

        unsafe fn free_coherent(&self, buf: DmaBuffer) {
            self.live.set(self.live.get() - 1);
            let layout = Layout::from_size_align(buf.len().max(1), 4096).unwrap();
            // SAFETY: allocated above with this layout.
            unsafe { dealloc(buf.cpu_ptr().as_ptr(), layout) }
        }
    }

    /// A transport whose device state lives in plain fields.
    pub struct FakeTransport {
        pub device: DeviceType,
        pub legacy: bool,
        pub offered: u64,
        pub accepted: Cell<u64>,
        pub status: Cell<u8>,
        pub reject_features: bool,
        pub max_queue: u16,
        pub queues: RefCell<Vec<(u16, u16, QueueAddrs)>>,
        pub notified: RefCell<Vec<u16>>,
        pub config: Vec<u8>,
    }

    impl FakeTransport {
        pub fn new(device: DeviceType, offered: u64, config: &[u8]) -> Self {
            Self {
                device,
                legacy: offered & feature::VERSION_1 == 0,
                offered,
                accepted: Cell::new(0),
                status: Cell::new(0),
                reject_features: false,
                max_queue: 256,
                queues: RefCell::new(Vec::new()),
                notified: RefCell::new(Vec::new()),
                config: config.to_vec(),
            }
        }

        pub fn queue(&self, index: u16) -> (u16, QueueAddrs) {
            let q = self.queues.borrow();
            let &(_, size, addrs) = q.iter().find(|q| q.0 == index).expect("queue not set up");
            (size, addrs)
        }
    }

    impl Transport for FakeTransport {
        fn device_type(&self) -> DeviceType {
            self.device
        }
        fn is_legacy(&self) -> bool {
            self.legacy
        }
        fn device_features(&self) -> u64 {
            self.offered
        }
        fn set_driver_features(&self, f: u64) {
            self.accepted.set(f);
        }
        fn status(&self) -> u8 {
            self.status.get()
        }
        fn set_status(&self, s: u8) {
            let s = if self.reject_features { s & !status::FEATURES_OK } else { s };
            self.status.set(s);
        }
        fn max_queue_size(&self, _: u16) -> u16 {
            self.max_queue
        }
        fn setup_queue(&self, index: u16, size: u16, addrs: QueueAddrs) {
            self.queues.borrow_mut().push((index, size, addrs));
        }
        fn notify(&self, index: u16) {
            self.notified.borrow_mut().push(index);
        }
        fn ack_interrupt(&self) -> u32 {
            1
        }
        fn config_read8(&self, offset: usize) -> u8 {
            self.config.get(offset).copied().unwrap_or(0)
        }
    }

    #[test]
    fn negotiation() {
        let t = FakeTransport::new(DeviceType::Net, feature::VERSION_1 | 0b1011, &[]);
        assert_eq!(negotiate(&t, 0b1, 0b110), Ok(feature::VERSION_1 | 0b11));
        assert_eq!(t.status(), status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);
        driver_ok(&t);
        assert_eq!(t.status() & status::DRIVER_OK, status::DRIVER_OK);

        assert_eq!(negotiate(&t, 0b100, 0), Err(VirtioError::Unsupported));
        assert_eq!(t.status(), status::FAILED);

        let mut no_v1 = FakeTransport::new(DeviceType::Net, 0b1, &[]);
        no_v1.legacy = false;
        assert_eq!(negotiate(&no_v1, 0, 0), Err(VirtioError::Unsupported), "modern without VERSION_1");
        assert!(reset(&no_v1));

        let mut picky = FakeTransport::new(DeviceType::Net, feature::VERSION_1, &[]);
        picky.reject_features = true;
        assert_eq!(negotiate(&picky, 0, 0), Err(VirtioError::Unsupported));

        let legacy = FakeTransport::new(DeviceType::Net, 0b1, &[]);
        assert_eq!(negotiate(&legacy, 0b1, 0), Ok(0b1));
        assert_eq!(legacy.status() & status::FEATURES_OK, 0, "legacy devices have no FEATURES_OK step");
    }
}
