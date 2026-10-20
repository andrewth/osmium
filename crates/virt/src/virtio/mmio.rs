//! The virtio-mmio transport, version 2 (virtio 1.x §4.2), as a [`BusDevice`].

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_sync::IrqSpinLock;

use super::queue::{DescChain, QueueError, SplitQueue};
use super::{F_VERSION_1, INT_CONFIG, INT_USED_BUFFER, VirtioDevice, status};
use crate::bus::BusDevice;
use crate::memory::{GuestMemory, GuestPhysAddr};

// TODO: switch to the shared constants in osmium_hal::virtio once they land.
const MAGIC_VALUE: u64 = 0x000;
const VERSION: u64 = 0x004;
const DEVICE_ID: u64 = 0x008;
const VENDOR_ID: u64 = 0x00c;
const DEVICE_FEATURES: u64 = 0x010;
const DEVICE_FEATURES_SEL: u64 = 0x014;
const DRIVER_FEATURES: u64 = 0x020;
const DRIVER_FEATURES_SEL: u64 = 0x024;
const QUEUE_SEL: u64 = 0x030;
const QUEUE_NUM_MAX: u64 = 0x034;
const QUEUE_NUM: u64 = 0x038;
const QUEUE_READY: u64 = 0x044;
const QUEUE_NOTIFY: u64 = 0x050;
const INTERRUPT_STATUS: u64 = 0x060;
const INTERRUPT_ACK: u64 = 0x064;
const STATUS: u64 = 0x070;
const QUEUE_DESC_LOW: u64 = 0x080;
const QUEUE_DESC_HIGH: u64 = 0x084;
const QUEUE_DRIVER_LOW: u64 = 0x090;
const QUEUE_DRIVER_HIGH: u64 = 0x094;
const QUEUE_DEVICE_LOW: u64 = 0x0a0;
const QUEUE_DEVICE_HIGH: u64 = 0x0a4;
const CONFIG_GENERATION: u64 = 0x0fc;
const CONFIG: u64 = 0x100;

const MAGIC: u32 = 0x7472_6976;
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
            self.raise(s, INT_USED_BUFFER);
        }
        r
    }

    /// Tells the driver the device's config space changed.
    pub fn config_changed(&self) {
        let mut s = self.inner.lock();
        s.config_generation = s.config_generation.wrapping_add(1);
        self.raise(&mut s, INT_CONFIG);
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
        match offset {
            MAGIC_VALUE => MAGIC,
            VERSION => 2,
            DEVICE_ID => s.device.device_id(),
            VENDOR_ID => VENDOR,
            DEVICE_FEATURES => {
                let f = s.device.features() | F_VERSION_1;
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
        match (offset, q) {
            (DEVICE_FEATURES_SEL, _) => s.device_features_sel = v,
            (DRIVER_FEATURES_SEL, _) => s.driver_features_sel = v,
            (DRIVER_FEATURES, _) if s.status & status::FEATURES_OK == 0 => {
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
            (QUEUE_NOTIFY, _) if s.status & status::DRIVER_OK != 0 => {
                let mut ctx = DeviceCtx { queues: &mut s.queues, mem: &self.mem, interrupt: false };
                s.device.notify(v as usize, &mut ctx);
                if ctx.interrupt {
                    self.raise(s, INT_USED_BUFFER);
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
                if v & status::FEATURES_OK != 0 && s.status & status::FEATURES_OK == 0 {
                    let offered = s.device.features() | F_VERSION_1;
                    let ok = s.driver_features & !offered == 0 && s.driver_features & F_VERSION_1 != 0;
                    if ok {
                        s.device.ack_features(s.driver_features);
                    } else {
                        v &= !status::FEATURES_OK;
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
        if offset >= CONFIG {
            s.device.read_config(offset - CONFIG, data);
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
        if offset >= CONFIG {
            s.device.write_config(offset - CONFIG, data);
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
        let w = |off, v: u32| dev.write(off, &v.to_le_bytes());
        w(STATUS, 0);
        w(STATUS, status::ACKNOWLEDGE | status::DRIVER);
        w(DRIVER_FEATURES_SEL, 1);
        w(DRIVER_FEATURES, 1);
        w(STATUS, status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK);
        assert_ne!(rd(dev, STATUS) & status::FEATURES_OK, 0);
        for &(q, base) in queues {
            w(QUEUE_SEL, q);
            w(QUEUE_NUM, 8);
            w(QUEUE_DESC_LOW, (base + DESC) as u32);
            w(QUEUE_DRIVER_LOW, (base + AVAIL) as u32);
            w(QUEUE_DEVICE_LOW, (base + USED) as u32);
            w(QUEUE_READY, 1);
        }
        w(STATUS, status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK);
    }

    pub(crate) fn rd<D: VirtioDevice>(dev: &VirtioMmio<D>, off: u64) -> u32 {
        let mut b = [0u8; 4];
        dev.read(off, &mut b);
        u32::from_le_bytes(b)
    }

    pub(crate) fn notify<D: VirtioDevice>(dev: &VirtioMmio<D>, q: u32) {
        dev.write(QUEUE_NOTIFY, &q.to_le_bytes());
    }

    pub(crate) fn ack<D: VirtioDevice>(dev: &VirtioMmio<D>) {
        let st = rd(dev, INTERRUPT_STATUS);
        dev.write(INTERRUPT_ACK, &st.to_le_bytes());
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
        dev.write(DEVICE_FEATURES_SEL, &1u32.to_le_bytes());
        assert_eq!(rd(&dev, DEVICE_FEATURES), 1, "VERSION_1");
        assert_eq!(rd(&dev, QUEUE_NUM_MAX), 256);
        dev.write(QUEUE_SEL, &1u32.to_le_bytes());
        assert_eq!(rd(&dev, QUEUE_NUM_MAX), 0, "no queue 1");

        // A driver that does not accept VERSION_1 fails negotiation.
        dev.write(STATUS, &(status::ACKNOWLEDGE | status::DRIVER).to_le_bytes());
        dev.write(STATUS, &(status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK).to_le_bytes());
        assert_eq!(rd(&dev, STATUS) & status::FEATURES_OK, 0);

        bring_up(&dev, &[(0, 0)]);
        assert_eq!(rd(&dev, QUEUE_READY), 1);

        let mut b = [0u8; 2];
        dev.read(CONFIG + 3, &mut b);
        assert_eq!(b, [3, 3]);

        dev.write(STATUS, &0u32.to_le_bytes());
        assert_eq!(rd(&dev, STATUS), 0);
        assert_eq!(rd(&dev, QUEUE_READY), 0, "reset disables queues");
    }
}
