//! The virtio-pci transport, modern interface (virtio 1.x §4.1).
//!
//! A modern virtio PCI function describes its register structures with
//! vendor-specific capabilities: each names a BAR, an offset and a length
//! for the common configuration, the notification area, the ISR status byte
//! and the device-specific configuration. [`PciTransport::new`] walks them
//! and keeps an [`IoMem`] for each; the caller maps the BARs, since only it
//! knows how bus addresses reach the CPU.
//!
//! Transitional devices also work, through the same capabilities; the
//! legacy I/O BAR interface is not supported.

use crate::ioext::IoMemExt;
use osmium_hal::mmio::IoMem;
use osmium_hal::pci::{Bar, BarKind, ConfigAccess, Function, cap};
use osmium_hal::virtio::pci::*;

use super::{DeviceType, QueueAddrs, Transport, VirtioError};

/// A modern virtio PCI function's registers.
pub struct PciTransport {
    device_type: DeviceType,
    common: IoMem,
    notify: IoMem,
    notify_multiplier: u32,
    isr: IoMem,
    device: Option<IoMem>,
}

/// The device type of a virtio PCI function, from its IDs, or `None` if it
/// is not a virtio device.
pub fn device_type<C: ConfigAccess + ?Sized>(func: &Function<'_, C>) -> Option<DeviceType> {
    if func.vendor_id() != VENDOR_ID {
        return None;
    }
    match func.device_id() {
        id if TRANSITIONAL_DEVICE_IDS.contains(&id) => {
            Some(DeviceType::from(func.read16(osmium_hal::pci::reg::SUBSYSTEM + 2) as u32))
        }
        id if (MODERN_DEVICE_ID_BASE..=MODERN_DEVICE_ID_BASE + 0x3f).contains(&id) => {
            Some(DeviceType::from((id - MODERN_DEVICE_ID_BASE) as u32))
        }
        _ => None,
    }
}

impl PciTransport {
    /// Finds the register structures of virtio function `func` and enables
    /// its memory decoding and bus mastering. `map` returns a window onto a
    /// memory BAR, which the caller has assigned an address; it is called
    /// at most once per BAR.
    pub fn new<C: ConfigAccess + ?Sized>(
        func: &Function<'_, C>,
        mut map: impl FnMut(&Bar) -> Option<IoMem>,
    ) -> Result<Self, VirtioError> {
        let device_type = device_type(func).ok_or(VirtioError::NotPresent)?;
        // Probe the BARs before enabling decoding: probing switches it off.
        let mut bars: [Option<Bar>; 6] = [None; 6];
        for (i, bar) in bars.iter_mut().enumerate() {
            *bar = func.bar(i as u8);
        }
        let mut windows: [Option<IoMem>; 6] = Default::default();
        // Whether `map` was already tried for each BAR, so a failure is not retried.
        let mut mapped = [false; 6];
        let mut found: [Option<IoMem>; 5] = Default::default();
        let mut notify_multiplier = 0;
        for (_, cap) in func.capabilities().filter(|&(id, _)| id == cap::VENDOR) {
            let typ = func.read8(cap + CAP_CFG_TYPE);
            let bar = func.read8(cap + CAP_BAR) as usize;
            if !matches!(typ, CAP_COMMON_CFG..=CAP_DEVICE_CFG) {
                continue;
            }
            let Some(slot) = found.get_mut(typ as usize).filter(|s| s.is_none()) else { continue };
            let Some(b) = bars.get(bar).copied().flatten().filter(|b| b.kind != BarKind::Io) else { continue };
            let (Some(window_slot), Some(tried)) = (windows.get_mut(bar), mapped.get_mut(bar)) else { continue };
            if !*tried {
                *tried = true;
                *window_slot = map(&b);
            }
            let (offset, length) = (func.read32(cap + CAP_OFFSET) as usize, func.read32(cap + CAP_LENGTH) as usize);
            let Some(window) = window_slot.as_ref().and_then(|w| w.slice(offset, length).ok()) else { continue };
            if typ == CAP_NOTIFY_CFG {
                notify_multiplier = func.read32(cap + CAP_NOTIFY_OFF_MULTIPLIER);
            }
            *slot = Some(window);
        }
        let [_, common, notify, isr, device] = found;
        let (Some(common), Some(notify), Some(isr)) = (common, notify, isr) else {
            return Err(VirtioError::NotPresent);
        };
        if common.len() < COMMON_CFG_LEN {
            return Err(VirtioError::NotPresent);
        }
        func.enable_memory_and_dma();
        let t = Self { device_type, common, notify, notify_multiplier, isr, device };
        // Every queue's doorbell must lie in the notification window.
        for q in 0..t.num_queues() {
            if t.notify_offset(q).is_none() {
                return Err(VirtioError::BadQueue);
            }
        }
        Ok(t)
    }

    fn r16(&self, off: usize) -> u16 {
        self.common.rd(off)
    }

    fn r32(&self, off: usize) -> u32 {
        self.common.rd(off)
    }

    fn w8(&self, off: usize, v: u8) {
        self.common.wr(off, v)
    }

    fn w16(&self, off: usize, v: u16) {
        self.common.wr(off, v)
    }

    fn w32(&self, off: usize, v: u32) {
        self.common.wr(off, v)
    }

    /// Writes a 64-bit field as two dwords, low first (§4.1.3.1).
    fn w64(&self, off: usize, v: u64) {
        self.w32(off, v as u32);
        self.w32(off + 4, (v >> 32) as u32);
    }

    /// Offset of queue `q`'s doorbell in the notification window, if it is
    /// inside it and aligned.
    fn notify_offset(&self, q: u16) -> Option<usize> {
        self.w16(QUEUE_SELECT, q);
        let off = (self.r16(QUEUE_NOTIFY_OFF) as usize).checked_mul(self.notify_multiplier as usize)?;
        (off.is_multiple_of(2) && off.checked_add(2)? <= self.notify.len()).then_some(off)
    }

    /// Number of virtqueues the device has.
    pub fn num_queues(&self) -> u16 {
        self.r16(NUM_QUEUES)
    }
}

impl Transport for PciTransport {
    fn device_type(&self) -> DeviceType {
        self.device_type
    }

    fn is_legacy(&self) -> bool {
        false
    }

    fn device_features(&self) -> u64 {
        self.w32(DEVICE_FEATURE_SELECT, 0);
        let lo = self.r32(DEVICE_FEATURE);
        self.w32(DEVICE_FEATURE_SELECT, 1);
        (self.r32(DEVICE_FEATURE) as u64) << 32 | lo as u64
    }

    fn set_driver_features(&self, features: u64) {
        self.w32(DRIVER_FEATURE_SELECT, 0);
        self.w32(DRIVER_FEATURE, features as u32);
        self.w32(DRIVER_FEATURE_SELECT, 1);
        self.w32(DRIVER_FEATURE, (features >> 32) as u32);
    }

    fn status(&self) -> u8 {
        self.common.rd(DEVICE_STATUS)
    }

    fn set_status(&self, status: u8) {
        self.w8(DEVICE_STATUS, status);
    }

    fn max_queue_size(&self, index: u16) -> u16 {
        if index >= self.num_queues() {
            return 0;
        }
        self.w16(QUEUE_SELECT, index);
        self.r16(QUEUE_SIZE)
    }

    fn setup_queue(&self, index: u16, size: u16, addrs: QueueAddrs) {
        self.w16(QUEUE_SELECT, index);
        self.w16(QUEUE_SIZE, size);
        self.w64(QUEUE_DESC, addrs.desc.as_u64());
        self.w64(QUEUE_DRIVER, addrs.avail.as_u64());
        self.w64(QUEUE_DEVICE, addrs.used.as_u64());
        self.w16(QUEUE_ENABLE, 1);
    }

    fn notify(&self, index: u16) {
        // `new` checked every queue's offset; a device that changes it
        // later gets no doorbell, and its driver times out.
        if let Some(off) = self.notify_offset(index) {
            let _ = self.notify.write(off, index);
        }
    }

    fn ack_interrupt(&self) -> u32 {
        // Reading the ISR byte clears it.
        self.isr.read::<u8>(0).unwrap_or(0) as u32
    }

    fn config_read8(&self, offset: usize) -> u8 {
        self.device.as_ref().and_then(|d| d.read(offset).ok()).unwrap_or(0)
    }
}

#[cfg(test)]
#[allow(clippy::drop_non_drop)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use osmium_hal::pci::Address;
    use osmium_mm::PhysAddr;
    use std::vec;
    use std::vec::Vec;

    /// One function's configuration space, with a 64-bit memory BAR 4 of
    /// 16 KiB at 0x4000_0000 and the four virtio capabilities in it.
    struct Config(RefCell<Vec<u32>>);

    const BAR_ADDR: u64 = 0x4000_0000;
    const BAR_SIZE: u32 = 0x4000;

    impl Config {
        fn new(device_id: u16) -> Self {
            let mut c = vec![0u32; 64];
            c[0] = (device_id as u32) << 16 | VENDOR_ID as u32;
            c[1] = 1 << 20; // capability list present
            c[2] = 0x0300_0001; // VGA
            c[4 + 4] = BAR_ADDR as u32 | 0b1100;
            // Capabilities from 0x40: (cfg_type, offset, length), then the
            // notify multiplier.
            let caps = [
                (CAP_COMMON_CFG, 0, 0x38),
                (CAP_ISR_CFG, 0x1000, 4),
                (CAP_DEVICE_CFG, 0x2000, 16),
                (CAP_NOTIFY_CFG, 0x3000, 0x1000),
            ];
            c[0x34 / 4] = 0x40;
            for (i, (typ, off, len)) in caps.into_iter().enumerate() {
                let at = 0x40 / 4 + i * 5;
                let next = if i + 1 < caps.len() { 0x40 + (i + 1) * 20 } else { 0 };
                c[at] = (typ as u32) << 24 | 0x14 << 16 | (next as u32) << 8 | cap::VENDOR as u32;
                c[at + 1] = 4; // BAR 4
                c[at + 2] = off;
                c[at + 3] = len;
                c[at + 4] = 4; // notify_off_multiplier
            }
            Self(RefCell::new(c))
        }
    }

    impl ConfigAccess for Config {
        fn read32(&self, addr: Address, offset: u16) -> u32 {
            if addr != Address::new(0, 1, 0) {
                return !0;
            }
            self.0.borrow()[offset as usize / 4]
        }

        fn write32(&self, _: Address, offset: u16, value: u32) {
            let mut c = self.0.borrow_mut();
            let i = offset as usize / 4;
            c[i] = match i {
                // Status bits are read-only.
                1 => value & 0xffff | c[1] & 0xffff_0000,
                // BAR 4 decodes only the address bits above its size.
                8 => value & !(BAR_SIZE - 1) | 0b1100,
                _ => value,
            };
        }
    }

    #[test]
    fn transport() {
        let cfg = Config::new(0x1050);
        let func = Function::new(&cfg, Address::new(0, 1, 0)).unwrap();
        assert_eq!(device_type(&func), Some(DeviceType::Gpu));
        let mut bar = vec![0u32; BAR_SIZE as usize / 4];
        let base = bar.as_mut_ptr();
        let mut mapped = Vec::new();
        let t = PciTransport::new(&func, |b| {
            mapped.push((b.index, b.address, b.size));
            // SAFETY: the window covers a local array.
            Some(unsafe { IoMem::new(base.cast(), BAR_SIZE as usize) })
        })
        .unwrap();
        assert_eq!(mapped, [(4, BAR_ADDR, BAR_SIZE as u64)], "BAR 4 mapped once");
        assert_eq!(cfg.0.borrow()[1] & 6, 6, "memory and bus mastering on");

        // SAFETY: as above; the transport only does volatile accesses.
        let regs = |i: usize| unsafe { base.add(i).read_volatile() };
        // SAFETY: as above.
        let set = |i: usize, v: u32| unsafe { base.add(i).write_volatile(v) };
        set(NUM_QUEUES / 4, 2 << 16);
        set(QUEUE_SIZE / 4, 64);
        set(QUEUE_NOTIFY_OFF / 4, 3 << 16);
        set(0x2000 / 4, 0x0000_0201);
        set(0x1000 / 4, 3);
        assert_eq!(t.max_queue_size(1), 64);
        assert_eq!(t.max_queue_size(2), 0);
        let addrs = QueueAddrs {
            desc: PhysAddr::new(0x1_2345_0000),
            avail: PhysAddr::new(0x8000_0100),
            used: PhysAddr::new(0x8000_1000),
        };
        t.setup_queue(1, 32, addrs);
        t.notify(1);
        assert_eq!(regs(QUEUE_SELECT / 4) >> 16, 1);
        assert_eq!(regs(QUEUE_SIZE / 4) & 0xffff, 32);
        assert_eq!((regs(QUEUE_DESC / 4), regs(QUEUE_DESC / 4 + 1)), (0x2345_0000, 1));
        assert_eq!(regs(QUEUE_DRIVER / 4), 0x8000_0100);
        assert_eq!(regs(QUEUE_DEVICE / 4), 0x8000_1000);
        assert_eq!(regs(QUEUE_ENABLE / 4) & 0xffff, 1);
        assert_eq!(regs((0x3000 + 3 * 4) / 4) & 0xffff, 1, "notify at queue_notify_off * multiplier");
        assert_eq!(t.config_read16(0), 0x201);
        assert_eq!(t.ack_interrupt(), 3);

        t.set_driver_features(1 << 32 | 3);
        assert_eq!((regs(DRIVER_FEATURE_SELECT / 4), regs(DRIVER_FEATURE / 4)), (1, 1));
        t.set_status(7);
        assert_eq!(t.status(), 7);
        drop(t);
        assert_eq!(regs(DEVICE_STATUS / 4) & 0xff, 7);
    }

    #[test]
    fn notify_offset_outside_window() {
        let cfg = Config::new(0x1050);
        let func = Function::new(&cfg, Address::new(0, 1, 0)).unwrap();
        let mut bar = vec![0u32; BAR_SIZE as usize / 4];
        // One queue whose doorbell would be at 0x400 * 4, past the 4 KiB window.
        bar[NUM_QUEUES / 4] = 1 << 16;
        bar[QUEUE_NOTIFY_OFF / 4] = 0x400 << 16;
        let base = bar.as_mut_ptr();
        // SAFETY: the window covers a local array.
        let t = PciTransport::new(&func, |_| Some(unsafe { IoMem::new(base.cast(), BAR_SIZE as usize) }));
        assert_eq!(t.err(), Some(VirtioError::BadQueue));
        // And no panic reading configuration past the device's window.
        bar[QUEUE_NOTIFY_OFF / 4] = 0;
        // SAFETY: as above.
        let t = PciTransport::new(&func, |_| Some(unsafe { IoMem::new(base.cast(), BAR_SIZE as usize) })).unwrap();
        assert_eq!(t.config_read8(0x100), 0);
    }

    #[test]
    fn not_virtio() {
        let cfg = Config::new(0x1050);
        cfg.0.borrow_mut()[0] = 0x1111_1234;
        let func = Function::new(&cfg, Address::new(0, 1, 0)).unwrap();
        assert_eq!(device_type(&func), None);
        assert!(PciTransport::new(&func, |_| None).is_err());

        // Modern IDs but nothing mapped: no common configuration.
        let cfg = Config::new(0x1041);
        let func = Function::new(&cfg, Address::new(0, 1, 0)).unwrap();
        assert_eq!(device_type(&func), Some(DeviceType::Net));
        assert!(PciTransport::new(&func, |_| None).is_err());
    }
}
