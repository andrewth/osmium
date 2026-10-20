//! The virtio-mmio transport (device tree `virtio,mmio`), versions 1
//! (legacy) and 2.

use osmium_hal::mmio::IoMem;
use osmium_hal::virtio::mmio::*;
use osmium_hal::virtio::queue::LEGACY_ALIGN;

use super::{DeviceType, QueueAddrs, Transport, VirtioError};

const PAGE: u32 = LEGACY_ALIGN as u32;

/// A virtio-mmio register window.
pub struct MmioTransport {
    io: IoMem,
    legacy: bool,
}

impl MmioTransport {
    /// Checks the magic number and version of the registers in `io` (at
    /// least 0x200 bytes). A window with device ID 0 is a valid but empty
    /// slot; [`Transport::device_type`] reports it as `Other(0)`.
    pub fn new(io: IoMem) -> Result<Self, VirtioError> {
        if io.len() < CONFIG || io.read::<u32>(MAGIC_VALUE) != Ok(MAGIC) {
            return Err(VirtioError::NotPresent);
        }
        let legacy = match io.read::<u32>(VERSION) {
            Ok(VERSION_LEGACY) => true,
            Ok(VERSION_MODERN) => false,
            _ => return Err(VirtioError::NotPresent),
        };
        Ok(Self { io, legacy })
    }

    fn r(&self, off: usize) -> u32 {
        self.io.read(off).expect("virtio-mmio register outside window")
    }

    fn w(&self, off: usize, v: u32) {
        self.io.write(off, v).expect("virtio-mmio register outside window")
    }
}

impl Transport for MmioTransport {
    fn device_type(&self) -> DeviceType {
        self.r(DEVICE_ID).into()
    }

    fn is_legacy(&self) -> bool {
        self.legacy
    }

    fn device_features(&self) -> u64 {
        self.w(DEVICE_FEATURES_SEL, 0);
        let lo = self.r(DEVICE_FEATURES);
        if self.legacy {
            return lo as u64;
        }
        self.w(DEVICE_FEATURES_SEL, 1);
        (self.r(DEVICE_FEATURES) as u64) << 32 | lo as u64
    }

    fn set_driver_features(&self, features: u64) {
        self.w(DRIVER_FEATURES_SEL, 0);
        self.w(DRIVER_FEATURES, features as u32);
        if !self.legacy {
            self.w(DRIVER_FEATURES_SEL, 1);
            self.w(DRIVER_FEATURES, (features >> 32) as u32);
        }
    }

    fn status(&self) -> u8 {
        self.r(STATUS) as u8
    }

    fn set_status(&self, status: u8) {
        self.w(STATUS, status as u32);
    }

    fn max_queue_size(&self, index: u16) -> u16 {
        self.w(QUEUE_SEL, index as u32);
        self.r(QUEUE_NUM_MAX).min(u16::MAX as u32) as u16
    }

    fn setup_queue(&self, index: u16, size: u16, addrs: QueueAddrs) {
        self.w(QUEUE_SEL, index as u32);
        self.w(QUEUE_NUM, size as u32);
        if self.legacy {
            // The legacy device derives the ring addresses from the
            // descriptor table's page number and the alignment.
            assert!(addrs.desc.is_aligned(PAGE as u64));
            self.w(GUEST_PAGE_SIZE, PAGE);
            self.w(QUEUE_ALIGN, PAGE);
            let pfn = addrs.desc.as_u64() / PAGE as u64;
            self.w(QUEUE_PFN, u32::try_from(pfn).expect("legacy virtqueue above 16 TiB"));
        } else {
            let regs = [
                (QUEUE_DESC_LOW, QUEUE_DESC_HIGH, addrs.desc),
                (QUEUE_DRIVER_LOW, QUEUE_DRIVER_HIGH, addrs.avail),
                (QUEUE_DEVICE_LOW, QUEUE_DEVICE_HIGH, addrs.used),
            ];
            for (low, high, addr) in regs {
                self.w(low, addr.as_u64() as u32);
                self.w(high, (addr.as_u64() >> 32) as u32);
            }
            self.w(QUEUE_READY, 1);
        }
    }

    fn notify(&self, index: u16) {
        self.w(QUEUE_NOTIFY, index as u32);
    }

    fn ack_interrupt(&self) -> u32 {
        let pending = self.r(INTERRUPT_STATUS);
        if pending != 0 {
            self.w(INTERRUPT_ACK, pending);
        }
        pending
    }

    fn config_read8(&self, offset: usize) -> u8 {
        self.io.read(CONFIG + offset).unwrap_or(0)
    }
}

#[cfg(test)]
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use osmium_mm::PhysAddr;

    fn window(regs: &mut [u32; 0x80], version: u32) -> MmioTransport {
        regs[MAGIC_VALUE / 4] = MAGIC;
        regs[VERSION / 4] = version;
        regs[DEVICE_ID / 4] = 1;
        regs[DEVICE_FEATURES / 4] = 0x20;
        regs[CONFIG / 4] = 0x0012_5452;
        // SAFETY: the window covers a local array.
        MmioTransport::new(unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x200) }).unwrap()
    }

    #[test]
    fn probe() {
        let mut regs = [0u32; 0x80];
        // SAFETY: the window covers a local array.
        let io = unsafe { IoMem::new(regs.as_mut_ptr().cast(), 0x200) };
        assert!(MmioTransport::new(io).is_err(), "no magic");
        let t = window(&mut regs, 2);
        assert_eq!(t.device_type(), DeviceType::Net);
        assert!(!t.is_legacy());
        assert_eq!(t.config_read8(1), 0x54);
        assert_eq!(t.config_read16(0), 0x5452);
    }

    #[test]
    fn modern_queue_setup() {
        let mut regs = [0u32; 0x80];
        let t = window(&mut regs, 2);
        let addrs = QueueAddrs {
            desc: PhysAddr::new(0x1_2345_0000),
            avail: PhysAddr::new(0x8000_0100),
            used: PhysAddr::new(0x8000_1000),
        };
        t.setup_queue(1, 64, addrs);
        t.set_driver_features(1 << 32 | 0x20);
        drop(t);
        assert_eq!(regs[QUEUE_SEL / 4], 1);
        assert_eq!(regs[QUEUE_NUM / 4], 64);
        assert_eq!((regs[QUEUE_DESC_LOW / 4], regs[QUEUE_DESC_HIGH / 4]), (0x2345_0000, 1));
        assert_eq!(regs[QUEUE_DRIVER_LOW / 4], 0x8000_0100);
        assert_eq!(regs[QUEUE_DEVICE_LOW / 4], 0x8000_1000);
        assert_eq!(regs[QUEUE_READY / 4], 1);
        // The high word was written last.
        assert_eq!((regs[DRIVER_FEATURES_SEL / 4], regs[DRIVER_FEATURES / 4]), (1, 1));
    }

    #[test]
    fn legacy_queue_setup() {
        let mut regs = [0u32; 0x80];
        let t = window(&mut regs, 1);
        assert!(t.is_legacy());
        assert_eq!(t.device_features(), 0x20);
        let addrs = QueueAddrs { desc: PhysAddr::new(0x8020_0000), avail: PhysAddr::new(0), used: PhysAddr::new(0) };
        t.setup_queue(0, 128, addrs);
        drop(t);
        assert_eq!(regs[QUEUE_PFN / 4], 0x80200);
        assert_eq!(regs[GUEST_PAGE_SIZE / 4], 4096);
        assert_eq!(regs[QUEUE_READY / 4], 0, "no QueueReady in legacy");
    }
}
