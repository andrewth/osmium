//! The virtio-mmio transport, version 2 (virtio 1.x §4.2), as a [`BusDevice`].

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_sync::IrqSpinLock;

use super::queue::{DescChain, QueueError, SplitQueue};
use osmium_hal::virtio::feature::VERSION_1;
use osmium_hal::virtio::mmio::*;
use osmium_hal::virtio::status;

use super::VirtioDevice;
use crate::bus::BusDevice;
use crate::memory::{GuestMemory, GuestPhysAddr};

/// Vendor ID reported to the guest ("OSMI").
const VENDOR: u32 = 0x494d_534f;

/// Size of the register window, including 3.75 KiB of config space.
pub const MMIO_SIZE: u64 = 0x1000;

/// What a device sees while it services a queue: the queues, guest memory,
/// and a way to raise the used-buffer interrupt.
pub struct DeviceCtx<'a> {
    queues: &'a mut [SplitQueue],
    mem: &'a GuestMemory,
    interrupt: bool,
}

impl DeviceCtx<'_> {
    /// Guest memory.
    pub fn mem(&self) -> &GuestMemory {
        self.mem
    }

    /// Pops the next chain from queue `q`, if the queue is ready and has one.
    pub fn pop(&mut self, q: usize) -> Option<Result<DescChain, QueueError>> {
        self.queues.get_mut(q)?.pop(self.mem)
    }

    /// Returns chain `head` on queue `q` with `len` bytes written, and
    /// raises the used-buffer interrupt unless the driver suppressed it.
    pub fn add_used(&mut self, q: usize, head: u16, len: u32) -> Result<(), QueueError> {
        if let Some(queue) = self.queues.get_mut(q) {
            self.interrupt |= queue.add_used(self.mem, head, len)?;
        }
        Ok(())
    }

    /// Whether queue `q` has been enabled by the driver.
    pub fn ready(&self, q: usize) -> bool {
        self.queues.get(q).is_some_and(|q| q.ready)
    }
}

struct Inner<D> {
    device: D,
    queues: Vec<SplitQueue>,
    status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,
    queue_sel: u32,
    interrupt_status: u32,
    config_generation: u32,
}

/// A virtio device behind a virtio-mmio register window. Place it on the
/// MMIO [`Bus`](crate::Bus) with length [`MMIO_SIZE`].
///
/// `irq` is called with the new level of the device's interrupt line
/// whenever it changes.
pub struct VirtioMmio<D> {
    inner: IrqSpinLock<Inner<D>>,
    mem: Arc<GuestMemory>,
    irq: Box<dyn Fn(bool) + Send + Sync>,
}

impl<D: VirtioDevice> VirtioMmio<D> {
    /// Wraps `device`, which accesses the guest through `mem`.
    pub fn new(device: D, mem: Arc<GuestMemory>, irq: impl Fn(bool) + Send + Sync + 'static) -> Self {
        let queues = (0..device.num_queues()).map(|_| SplitQueue::new(device.queue_max_size())).collect();
        let inner = Inner {
            device,
            queues,
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: 0,
            queue_sel: 0,
            interrupt_status: 0,
            config_generation: 0,
        };
        Self { inner: IrqSpinLock::new(inner), mem, irq: Box::new(irq) }
    }

    /// Runs `f` on the device with access to its queues, for host-side
    /// events such as input arriving. Raises the interrupt if `f` used a
    /// buffer.
    pub fn with_device<R>(&self, f: impl FnOnce(&mut D, &mut DeviceCtx<'_>) -> R) -> R {
        let mut s = self.inner.lock();
        let s = &mut *s;
        let mut ctx = DeviceCtx { queues: &mut s.queues, mem: &self.mem, interrupt: false };
        let r = f(&mut s.device, &mut ctx);
        if ctx.interrupt {
            self.raise(s, USED_BUFFER);
        }
        r
    }

    /// Tells the driver the device's config space changed.
    pub fn config_changed(&self) {
        let mut s = self.inner.lock();
        s.config_generation = s.config_generation.wrapping_add(1);
        self.raise(&mut s, CONFIG_CHANGE);
    }

    /// Whether the interrupt line is asserted.
    pub fn irq_pending(&self) -> bool {
        self.inner.lock().interrupt_status != 0
    }

    fn raise(&self, s: &mut Inner<D>, bits: u32) {
        let was = s.interrupt_status;
        s.interrupt_status |= bits;
        if was == 0 {
            (self.irq)(true);
        }
    }

    fn reset(&self, s: &mut Inner<D>) {
        s.device.reset();
        let size = s.device.queue_max_size();
        s.queues.iter_mut().for_each(|q| q.reset(size));
        s.status = 0;
        s.driver_features = 0;
        s.device_features_sel = 0;
        s.driver_features_sel = 0;
        s.queue_sel = 0;
        if s.interrupt_status != 0 {
            s.interrupt_status = 0;
            (self.irq)(false);
        }
    }

    fn read_reg(&self, s: &mut Inner<D>, offset: u64) -> u32 {
        let q = s.queues.get(s.queue_sel as usize);
        match offset as usize {
            MAGIC_VALUE => MAGIC,
            VERSION => VERSION_MODERN,
            DEVICE_ID => s.device.device_id(),
            VENDOR_ID => VENDOR,
            DEVICE_FEATURES => {
                let f = s.device.features() | VERSION_1;
                match s.device_features_sel {
                    0 => f as u32,
                    1 => (f >> 32) as u32,
                    _ => 0,
                }
            }
            QUEUE_NUM_MAX => q.map_or(0, |_| s.device.queue_max_size() as u32),
            QUEUE_READY => q.is_some_and(|q| q.ready) as u32,
            INTERRUPT_STATUS => s.interrupt_status,
            STATUS => s.status,
            CONFIG_GENERATION => s.config_generation,
            _ => 0,
        }
    }

    fn write_reg(&self, s: &mut Inner<D>, offset: u64, v: u32) {
        let sel = s.queue_sel as usize;
        let max = s.device.queue_max_size();
        let q = s.queues.get_mut(sel);
        let set_lo = |a: &mut GuestPhysAddr| a.0 = a.0 & !0xffff_ffff | v as u64;
        let set_hi = |a: &mut GuestPhysAddr| a.0 = a.0 & 0xffff_ffff | (v as u64) << 32;
        match (offset as usize, q) {
            (DEVICE_FEATURES_SEL, _) => s.device_features_sel = v,
            (DRIVER_FEATURES_SEL, _) => s.driver_features_sel = v,
            (DRIVER_FEATURES, _) if s.status & u32::from(status::FEATURES_OK) == 0 => {
                let shift = match s.driver_features_sel {
                    0 => 0,
                    1 => 32,
                    _ => return,
                };
                s.driver_features = s.driver_features & !(0xffff_ffff << shift) | (v as u64) << shift;
            }
            (QUEUE_SEL, _) => s.queue_sel = v,
            (QUEUE_NUM, Some(q)) if !q.ready => q.size = (v as u16).min(max),
            (QUEUE_READY, Some(q)) => q.ready = v & 1 != 0,
            (QUEUE_DESC_LOW, Some(q)) if !q.ready => set_lo(&mut q.desc),
            (QUEUE_DESC_HIGH, Some(q)) if !q.ready => set_hi(&mut q.desc),
            (QUEUE_DRIVER_LOW, Some(q)) if !q.ready => set_lo(&mut q.avail),
            (QUEUE_DRIVER_HIGH, Some(q)) if !q.ready => set_hi(&mut q.avail),
            (QUEUE_DEVICE_LOW, Some(q)) if !q.ready => set_lo(&mut q.used),
            (QUEUE_DEVICE_HIGH, Some(q)) if !q.ready => set_hi(&mut q.used),
            (QUEUE_NOTIFY, _) if s.status & u32::from(status::DRIVER_OK) != 0 => {
                let mut ctx = DeviceCtx { queues: &mut s.queues, mem: &self.mem, interrupt: false };
                s.device.notify(v as usize, &mut ctx);
                if ctx.interrupt {
                    self.raise(s, USED_BUFFER);
                }
            }
            (INTERRUPT_ACK, _) => {
                let was = s.interrupt_status;
                s.interrupt_status &= !v;
                if was != 0 && s.interrupt_status == 0 {
                    (self.irq)(false);
                }
            }
            (STATUS, _) if v == 0 => self.reset(s),
            (STATUS, _) => {
                let mut v = v;
                if v & u32::from(status::FEATURES_OK) != 0 && s.status & u32::from(status::FEATURES_OK) == 0 {
                    let offered = s.device.features() | VERSION_1;
                    let ok = s.driver_features & !offered == 0 && s.driver_features & VERSION_1 != 0;
                    if ok {
                        s.device.ack_features(s.driver_features);
                    } else {
                        v &= !u32::from(status::FEATURES_OK);
                    }
                }
                s.status = v;
            }
            _ => {}
        }
    }
}

impl<D: VirtioDevice> BusDevice for VirtioMmio<D> {
    fn read(&self, offset: u64, data: &mut [u8]) {
        let mut s = self.inner.lock();
        if offset >= CONFIG as u64 {
            s.device.read_config(offset - CONFIG as u64, data);
            return;
        }
        let v = self.read_reg(&mut s, offset & !3);
        let b = v.to_le_bytes();
        let at = (offset & 3) as usize;
        for (i, d) in data.iter_mut().enumerate() {
            *d = b.get(at + i).copied().unwrap_or(0);
        }
    }

    fn write(&self, offset: u64, data: &[u8]) {
        let mut s = self.inner.lock();
        if offset >= CONFIG as u64 {
            s.device.write_config(offset - CONFIG as u64, data);
            return;
        }
        // Registers take aligned 32-bit writes only.
        if offset & 3 != 0 || data.len() != 4 {
            return;
        }
        let v = u32::from_le_bytes(data.try_into().unwrap());
        self.write_reg(&mut s, offset, v);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::virtio::queue::tests::{AVAIL, DESC, USED};

    /// Drives the transport like a guest driver would, up to DRIVER_OK.
    pub(crate) fn bring_up<D: VirtioDevice>(dev: &VirtioMmio<D>, queues: &[(u32, u64)]) {
        let w = |off: usize, v: u32| dev.write(off as u64, &v.to_le_bytes());
        w(STATUS, 0);
        w(STATUS, u32::from(status::ACKNOWLEDGE) | u32::from(status::DRIVER));
        w(DRIVER_FEATURES_SEL, 1);
        w(DRIVER_FEATURES, 1);
        w(STATUS, u32::from(status::ACKNOWLEDGE) | u32::from(status::DRIVER) | u32::from(status::FEATURES_OK));
        assert_ne!(rd(dev, STATUS) & u32::from(status::FEATURES_OK), 0);
        for &(q, base) in queues {
            w(QUEUE_SEL, q);
            w(QUEUE_NUM, 8);
            w(QUEUE_DESC_LOW, (base + DESC) as u32);
            w(QUEUE_DRIVER_LOW, (base + AVAIL) as u32);
            w(QUEUE_DEVICE_LOW, (base + USED) as u32);
            w(QUEUE_READY, 1);
        }
        w(STATUS, u32::from(status::ACKNOWLEDGE) | u32::from(status::DRIVER) | u32::from(status::FEATURES_OK) | u32::from(status::DRIVER_OK));
    }

    pub(crate) fn rd<D: VirtioDevice>(dev: &VirtioMmio<D>, off: usize) -> u32 {
        let mut b = [0u8; 4];
        dev.read(off as u64, &mut b);
        u32::from_le_bytes(b)
    }

    pub(crate) fn notify<D: VirtioDevice>(dev: &VirtioMmio<D>, q: u32) {
        dev.write(QUEUE_NOTIFY as u64, &q.to_le_bytes());
    }

    pub(crate) fn ack<D: VirtioDevice>(dev: &VirtioMmio<D>) {
        let st = rd(dev, INTERRUPT_STATUS);
        dev.write(INTERRUPT_ACK as u64, &st.to_le_bytes());
    }

    struct Dummy;
    impl VirtioDevice for Dummy {
        fn device_id(&self) -> u32 {
            42
        }
        fn features(&self) -> u64 {
            1 << 5
        }
        fn num_queues(&self) -> usize {
            1
        }
        fn read_config(&self, offset: u64, data: &mut [u8]) {
            data.fill(offset as u8);
        }
        fn notify(&mut self, _queue: usize, _ctx: &mut DeviceCtx<'_>) {}
    }

    #[test]
    fn identification_and_negotiation() {
        let dev = VirtioMmio::new(Dummy, Arc::new(GuestMemory::new()), |_| {});
        assert_eq!(rd(&dev, MAGIC_VALUE), MAGIC);
        assert_eq!(rd(&dev, VERSION), 2);
        assert_eq!(rd(&dev, DEVICE_ID), 42);
        assert_eq!(rd(&dev, DEVICE_FEATURES), 1 << 5);
        dev.write(DEVICE_FEATURES_SEL as u64, &1u32.to_le_bytes());
        assert_eq!(rd(&dev, DEVICE_FEATURES), 1, "VERSION_1");
        assert_eq!(rd(&dev, QUEUE_NUM_MAX), 256);
        dev.write(QUEUE_SEL as u64, &1u32.to_le_bytes());
        assert_eq!(rd(&dev, QUEUE_NUM_MAX), 0, "no queue 1");

        // A driver that does not accept VERSION_1 fails negotiation.
        dev.write(STATUS as u64, &(u32::from(status::ACKNOWLEDGE) | u32::from(status::DRIVER)).to_le_bytes());
        dev.write(STATUS as u64, &(u32::from(status::ACKNOWLEDGE) | u32::from(status::DRIVER) | u32::from(status::FEATURES_OK)).to_le_bytes());
        assert_eq!(rd(&dev, STATUS) & u32::from(status::FEATURES_OK), 0);

        bring_up(&dev, &[(0, 0)]);
        assert_eq!(rd(&dev, QUEUE_READY), 1);

        let mut b = [0u8; 2];
        dev.read(CONFIG as u64 + 3, &mut b);
        assert_eq!(b, [3, 3]);

        dev.write(STATUS as u64, &0u32.to_le_bytes());
        assert_eq!(rd(&dev, STATUS), 0);
        assert_eq!(rd(&dev, QUEUE_READY), 0, "reset disables queues");
    }
}
