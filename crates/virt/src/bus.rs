//! Routing guest MMIO and port I/O to emulated devices.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use osmium_sync::RwSpinLock;

/// An emulated device on a [`Bus`]. Offsets are relative to the device's
/// base address; `data` is 1, 2, 4 or 8 bytes, little-endian.
pub trait BusDevice: Send + Sync {
    /// Handles a guest read.
    fn read(&self, offset: u64, data: &mut [u8]);
    /// Handles a guest write.
    fn write(&self, offset: u64, data: &[u8]);
}

/// Fills a guest read buffer with `value` in little-endian order, zero-extended
/// (or truncated) to the buffer's length, whatever its size.
pub(crate) fn put_le(data: &mut [u8], value: u64) {
    let bytes = value.to_le_bytes();
    for (i, d) in data.iter_mut().enumerate() {
        *d = bytes.get(i).copied().unwrap_or(0);
    }
}

/// The little-endian value of a guest write buffer, of any length (bytes past
/// the eighth are ignored).
pub(crate) fn get_le(data: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    for (d, s) in b.iter_mut().zip(data) {
        *d = *s;
    }
    u64::from_le_bytes(b)
}

/// Why a bus operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusError {
    /// The new range overlaps a registered device.
    Overlap,
    /// No device claims the address.
    Unmapped(u64),
}

#[derive(Clone)]
struct Entry {
    len: u64,
    device: Arc<dyn BusDevice>,
}

/// An address space of devices: one for MMIO, another for port I/O.
#[derive(Default)]
pub struct Bus {
    devices: RwSpinLock<BTreeMap<u64, Entry>>,
}

impl Bus {
    /// Creates an empty bus.
    pub fn new() -> Self {
        Self::default()
    }

    /// Places `device` at `[base, base + len)`.
    pub fn insert(&self, base: u64, len: u64, device: Arc<dyn BusDevice>) -> Result<(), BusError> {
        let end = base.checked_add(len).ok_or(BusError::Overlap)?;
        let mut devs = self.devices.write();
        let before = devs.range(..end).next_back();
        if before.is_some_and(|(&b, e)| b + e.len > base) {
            return Err(BusError::Overlap);
        }
        devs.insert(base, Entry { len, device });
        Ok(())
    }

    /// Removes the device at `base`.
    pub fn remove(&self, base: u64) -> Option<Arc<dyn BusDevice>> {
        self.devices.write().remove(&base).map(|e| e.device)
    }

    fn lookup(&self, addr: u64) -> Option<(u64, Arc<dyn BusDevice>)> {
        let devs = self.devices.read();
        let (&base, e) = devs.range(..=addr).next_back()?;
        (addr < base + e.len).then(|| (addr - base, e.device.clone()))
    }

    /// Dispatches a read. The device runs without the bus lock held.
    pub fn read(&self, addr: u64, data: &mut [u8]) -> Result<(), BusError> {
        let (off, dev) = self.lookup(addr).ok_or(BusError::Unmapped(addr))?;
        dev.read(off, data);
        Ok(())
    }

    /// Dispatches a write. The device runs without the bus lock held.
    pub fn write(&self, addr: u64, data: &[u8]) -> Result<(), BusError> {
        let (off, dev) = self.lookup(addr).ok_or(BusError::Unmapped(addr))?;
        dev.write(off, data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    struct Reg(AtomicU64);
    impl BusDevice for Reg {
        fn read(&self, offset: u64, data: &mut [u8]) {
            let v = self.0.load(Ordering::Relaxed) + offset;
            data.copy_from_slice(&v.to_le_bytes()[..data.len()]);
        }
        fn write(&self, _offset: u64, data: &[u8]) {
            let mut b = [0u8; 8];
            b[..data.len()].copy_from_slice(data);
            self.0.store(u64::from_le_bytes(b), Ordering::Relaxed);
        }
    }

    #[test]
    fn routing_and_overlap() {
        let bus = Bus::new();
        bus.insert(0x1000, 0x100, Arc::new(Reg(AtomicU64::new(0)))).unwrap();
        bus.insert(0x2000, 0x100, Arc::new(Reg(AtomicU64::new(0)))).unwrap();
        assert_eq!(bus.insert(0x10ff, 0x10, Arc::new(Reg(AtomicU64::new(0)))), Err(BusError::Overlap));
        assert_eq!(bus.insert(0xff0, 0x11, Arc::new(Reg(AtomicU64::new(0)))), Err(BusError::Overlap));
        bus.insert(0x1100, 0x10, Arc::new(Reg(AtomicU64::new(0)))).unwrap();

        bus.write(0x2000, &500u32.to_le_bytes()).unwrap();
        let mut buf = [0u8; 4];
        bus.read(0x2004, &mut buf).unwrap();
        assert_eq!(u32::from_le_bytes(buf), 504);
        assert_eq!(bus.read(0x3000, &mut buf), Err(BusError::Unmapped(0x3000)));
        assert!(bus.remove(0x2000).is_some());
        assert!(bus.read(0x2000, &mut buf).is_err());
    }
}
