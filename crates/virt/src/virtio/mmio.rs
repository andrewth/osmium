//! The virtio-mmio transport, version 2 (virtio 1.x §4.2), as a [`BusDevice`].
//!
//! # Locking
//!
//! The transport registers (status, feature selection, interrupt status)
//! sit behind an [`IrqSpinLock`] that is held only for register updates. The
//! device and its queues sit behind a second lock that never masks
//! interrupts, so a device's work (a disk read, a frame handed to a NIC
//! backend) runs with the host's interrupts as the caller had them, and
//! a backend may wait for its own interrupt or block. A notify that finds
//! the device busy on another CPU does not wait: it leaves a request that the
//! busy context serves before it lets go of the device.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use osmium_sync::{IrqSpinLock, RawSpinLock, SpinLockGuard};

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
pub struct DeviceCtx<'ctx> {
    queues: &'ctx mut [SplitQueue],
    mem: &'ctx GuestMemory,
    interrupt: bool,
    /// Chains [`pop`](Self::pop) may still return: one queue's worth per
    /// queue for each notify, so a guest that keeps posting cannot hold the
    /// host in a device. What it posts after that waits for its next notify.
    budget: usize,
}

impl<'ctx> DeviceCtx<'ctx> {
    fn new(queues: &'ctx mut [SplitQueue], mem: &'ctx GuestMemory) -> Self {
        let budget = queues.iter().map(|q| q.size as usize).sum();
        Self { queues, mem, interrupt: false, budget }
    }

    /// Guest memory.
    pub fn mem(&self) -> &GuestMemory {
        self.mem
    }

    /// Pops the next chain from queue `q`, if the queue is ready and has one.
    pub fn pop(&mut self, q: usize) -> Option<Result<DescChain, QueueError>> {
        if self.budget == 0 {
            return None;
        }
        let r = self.queues.get_mut(q)?.pop(self.mem)?;
        self.budget -= 1;
        Some(r)
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

/// The transport's own registers.
struct Regs {
    status: u32,
    device_features_sel: u32,
    driver_features_sel: u32,
    driver_features: u64,
    queue_sel: u32,
    interrupt_status: u32,
    config_generation: u32,
    /// Queues (bit `q`) notified while another context held the device,
    /// which that context serves before it lets the device go.
    pending: u64,
}

/// The device and its queues.
struct Work<D> {
    device: D,
    queues: Vec<SplitQueue>,
}

type WorkGuard<'a, D> = SpinLockGuard<'a, Work<D>, osmium_sync::NoGuard>;

/// A virtio device behind a virtio-mmio register window. Place it on the
/// MMIO [`Bus`](crate::Bus) with length [`MMIO_SIZE`].
///
/// `irq` is called with the new level of the device's interrupt line
/// whenever it changes, with local interrupts masked.
///
/// The device's work runs without interrupts masked (see the module
/// documentation). The lock order is the device's, then the registers';
/// [`with_device`](Self::with_device) waits for a device another context
/// is using, so do not call it from an interrupt handler.
pub struct VirtioMmio<D> {
    regs: IrqSpinLock<Regs>,
    work: RawSpinLock<Work<D>>,
    mem: Arc<GuestMemory>,
    irq: Box<dyn Fn(bool) + Send + Sync>,
    /// The device's identity and geometry, which do not change.
    device_id: u32,
    features: u64,
    queue_max: u16,
    num_queues: usize,
}

impl<D: VirtioDevice> VirtioMmio<D> {
    /// Wraps `device`, which accesses the guest through `mem`.
    pub fn new(device: D, mem: Arc<GuestMemory>, irq: impl Fn(bool) + Send + Sync + 'static) -> Self {
        let (device_id, features, queue_max, num_queues) =
            (device.device_id(), device.features() | VERSION_1, device.queue_max_size(), device.num_queues());
        let queues = (0..num_queues).map(|_| SplitQueue::new(queue_max)).collect();
        let regs = Regs {
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: 0,
            queue_sel: 0,
            interrupt_status: 0,
            config_generation: 0,
            pending: 0,
        };
        Self {
            regs: IrqSpinLock::new(regs),
            work: RawSpinLock::new(Work { device, queues }),
            mem,
            irq: Box::new(irq),
            device_id,
            features,
            queue_max,
            num_queues,
        }
    }

    /// Runs `f` on the device with access to its queues, for host-side
    /// events such as input arriving. Raises the interrupt if `f` used a
    /// buffer. Waits while another context uses the device (a guest notify
    /// on another CPU), so it must not be called from an interrupt handler.
    pub fn with_device<R>(&self, f: impl FnOnce(&mut D, &mut DeviceCtx<'_>) -> R) -> R {
        let mut w = self.work.lock();
        let w2 = &mut *w;
        let mut ctx = DeviceCtx::new(&mut w2.queues, &self.mem);
        let r = f(&mut w2.device, &mut ctx);
        if ctx.interrupt {
            self.raise(&mut self.regs.lock(), USED_BUFFER);
        }
        self.release(w);
        r
    }

    /// Tells the driver the device's config space changed.
    pub fn config_changed(&self) {
        let mut s = self.regs.lock();
        s.config_generation = s.config_generation.wrapping_add(1);
        self.raise(&mut s, CONFIG_CHANGE);
    }

    /// Whether the interrupt line is asserted.
    pub fn irq_pending(&self) -> bool {
        self.regs.lock().interrupt_status != 0
    }

    fn raise(&self, s: &mut Regs, bits: u32) {
        let was = s.interrupt_status;
        s.interrupt_status |= bits;
        if was == 0 {
            (self.irq)(true);
        }
    }

    /// The driver notified `queue`: serve it now, or, if another context
    /// holds the device, leave the request for it. Never waits.
    fn notify(&self, queue: u32) {
        {
            let mut s = self.regs.lock();
            if s.status & u32::from(status::DRIVER_OK) == 0 {
                return;
            }
            // A queue the device does not have is ignored.
            if (queue as usize) < self.num_queues.min(64) {
                s.pending |= 1 << queue;
            }
        }
        if let Some(w) = self.work.try_lock() {
            self.release(w);
        }
    }

    /// Lets go of the device, after serving the notifies that arrived while
    /// it was held. The last check for them and the release happen under the
    /// register lock, where a notifier records its request: either this
    /// context sees the request, or the notifier finds the device free.
    fn release(&self, mut w: WorkGuard<'_, D>) {
        loop {
            let bits = {
                let mut s = self.regs.lock();
                let bits = core::mem::take(&mut s.pending);
                if bits == 0 || s.status & u32::from(status::DRIVER_OK) == 0 {
                    drop(w);
                    return;
                }
                bits
            };
            // Each round serves requests the guest made since the last one,
            // each at most one budget's worth: the work is paid for by notifies.
            let w2 = &mut *w;
            let mut used = false;
            for q in (0..64).filter(|q| bits & (1 << q) != 0) {
                let mut ctx = DeviceCtx::new(&mut w2.queues, &self.mem);
                w2.device.notify(q, &mut ctx);
                used |= ctx.interrupt;
            }
            if used {
                self.raise(&mut self.regs.lock(), USED_BUFFER);
            }
        }
    }

    /// Resets the device. Holds both locks.
    fn reset(&self, w: &mut Work<D>, s: &mut Regs) {
        w.device.reset();
        w.queues.iter_mut().for_each(|q| q.reset(self.queue_max));
        s.status = 0;
        s.driver_features = 0;
        s.device_features_sel = 0;
        s.driver_features_sel = 0;
        s.queue_sel = 0;
        s.pending = 0;
        if s.interrupt_status != 0 {
            s.interrupt_status = 0;
            (self.irq)(false);
        }
    }

    fn read_reg(&self, offset: u64) -> u32 {
        if offset as usize == QUEUE_READY {
            // The queues are the device's: lock it first.
            let w = self.work.lock();
            let sel = self.regs.lock().queue_sel as usize;
            let ready = w.queues.get(sel).is_some_and(|q| q.ready);
            self.release(w);
            return ready as u32;
        }
        let s = self.regs.lock();
        let queue_exists = (s.queue_sel as usize) < self.num_queues;
        match offset as usize {
            MAGIC_VALUE => MAGIC,
            VERSION => VERSION_MODERN,
            DEVICE_ID => self.device_id,
            VENDOR_ID => VENDOR,
            DEVICE_FEATURES => match s.device_features_sel {
                0 => self.features as u32,
                1 => (self.features >> 32) as u32,
                _ => 0,
            },
            QUEUE_NUM_MAX if queue_exists => self.queue_max as u32,
            INTERRUPT_STATUS => s.interrupt_status,
            STATUS => s.status,
            CONFIG_GENERATION => s.config_generation,
            _ => 0,
        }
    }

    fn write_reg(&self, offset: u64, v: u32) {
        match offset as usize {
            QUEUE_NOTIFY => return self.notify(v),
            DEVICE_FEATURES_SEL => return self.regs.lock().device_features_sel = v,
            DRIVER_FEATURES_SEL => return self.regs.lock().driver_features_sel = v,
            QUEUE_SEL => return self.regs.lock().queue_sel = v,
            DRIVER_FEATURES => {
                let mut s = self.regs.lock();
                if s.status & u32::from(status::FEATURES_OK) == 0 {
                    let shift = match s.driver_features_sel {
                        0 => 0,
                        1 => 32,
                        _ => return,
                    };
                    s.driver_features = s.driver_features & !(0xffff_ffff << shift) | (v as u64) << shift;
                }
                return;
            }
            INTERRUPT_ACK => {
                let mut s = self.regs.lock();
                let was = s.interrupt_status;
                s.interrupt_status &= !v;
                if was != 0 && s.interrupt_status == 0 {
                    (self.irq)(false);
                }
                return;
            }
            _ => {}
        }
        // The rest change the queues or the device: lock it first.
        let mut w = self.work.lock();
        {
            let mut s = self.regs.lock();
            self.write_work_reg(&mut w, &mut s, offset, v);
        }
        self.release(w);
    }

    /// The registers that reach the device or its queues, with both locks held.
    fn write_work_reg(&self, w: &mut Work<D>, s: &mut Regs, offset: u64, v: u32) {
        let max = self.queue_max;
        let set_lo = |a: &mut GuestPhysAddr| a.0 = a.0 & !0xffff_ffff | v as u64;
        let set_hi = |a: &mut GuestPhysAddr| a.0 = a.0 & 0xffff_ffff | (v as u64) << 32;
        let q = w.queues.get_mut(s.queue_sel as usize);
        match (offset as usize, q) {
            (QUEUE_NUM, Some(q)) if !q.ready => q.size = (v as u16).min(max),
            (QUEUE_READY, Some(q)) => q.ready = v & 1 != 0,
            (QUEUE_DESC_LOW, Some(q)) if !q.ready => set_lo(&mut q.desc),
            (QUEUE_DESC_HIGH, Some(q)) if !q.ready => set_hi(&mut q.desc),
            (QUEUE_DRIVER_LOW, Some(q)) if !q.ready => set_lo(&mut q.avail),
            (QUEUE_DRIVER_HIGH, Some(q)) if !q.ready => set_hi(&mut q.avail),
            (QUEUE_DEVICE_LOW, Some(q)) if !q.ready => set_lo(&mut q.used),
            (QUEUE_DEVICE_HIGH, Some(q)) if !q.ready => set_hi(&mut q.used),
            (STATUS, _) if v == 0 => self.reset(w, s),
            (STATUS, _) => {
                let mut v = v;
                let bit = |b: u8| u32::from(b);
                let step = bit(status::ACKNOWLEDGE) | bit(status::DRIVER);
                // Status bits only accumulate; clearing one takes a reset (write 0).
                if s.status & !v != 0 {
                    return;
                }
                // FEATURES_OK only after ACKNOWLEDGE and DRIVER; DRIVER_OK only
                // after FEATURES_OK was accepted by an earlier write.
                if v & bit(status::FEATURES_OK) != 0 && v & step != step {
                    v &= !bit(status::FEATURES_OK);
                }
                if v & bit(status::DRIVER_OK) != 0 && s.status & bit(status::FEATURES_OK) == 0 {
                    v &= !bit(status::DRIVER_OK);
                }
                if v & u32::from(status::FEATURES_OK) != 0 && s.status & u32::from(status::FEATURES_OK) == 0 {
                    let ok = s.driver_features & !self.features == 0 && s.driver_features & VERSION_1 != 0;
                    if ok {
                        w.device.ack_features(s.driver_features);
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
        if offset >= CONFIG as u64 {
            let w = self.work.lock();
            w.device.read_config(offset - CONFIG as u64, data);
            self.release(w);
            return;
        }
        let v = self.read_reg(offset & !3);
        let b = v.to_le_bytes();
        let at = (offset & 3) as usize;
        for (i, d) in data.iter_mut().enumerate() {
            *d = b.get(at + i).copied().unwrap_or(0);
        }
    }

    fn write(&self, offset: u64, data: &[u8]) {
        if offset >= CONFIG as u64 {
            let mut w = self.work.lock();
            w.device.write_config(offset - CONFIG as u64, data);
            self.release(w);
            return;
        }
        // Registers take aligned 32-bit writes only.
        let &[a, b, c, d] = data else { return };
        if offset & 3 != 0 {
            return;
        }
        let v = u32::from_le_bytes([a, b, c, d]);
        self.write_reg(offset, v);
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
        w(
            STATUS,
            u32::from(status::ACKNOWLEDGE)
                | u32::from(status::DRIVER)
                | u32::from(status::FEATURES_OK)
                | u32::from(status::DRIVER_OK),
        );
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

    /// Records each notify, whether interrupts were masked during it, and
    /// can hold the first one until released.
    struct Probe {
        calls: Arc<std::sync::Mutex<Vec<(usize, bool)>>>,
        entered: Arc<core::sync::atomic::AtomicBool>,
        go: Arc<core::sync::atomic::AtomicBool>,
    }
    impl VirtioDevice for Probe {
        fn device_id(&self) -> u32 {
            42
        }
        fn num_queues(&self) -> usize {
            2
        }
        fn notify(&mut self, queue: usize, _ctx: &mut DeviceCtx<'_>) {
            use core::sync::atomic::Ordering::SeqCst;
            self.calls.lock().unwrap().push((queue, osmium_arch::irq::are_enabled()));
            if !self.entered.swap(true, SeqCst) {
                while !self.go.load(SeqCst) {
                    std::thread::yield_now();
                }
            }
        }
    }

    /// The device's work does not run with interrupts masked, and a notify
    /// that finds the device busy on another CPU returns at once; the busy
    /// context serves it.
    #[test]
    fn notify_runs_unmasked_and_never_waits_for_a_busy_device() {
        use core::sync::atomic::{AtomicBool, Ordering::SeqCst};
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (entered, go) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let probe = Probe { calls: calls.clone(), entered: entered.clone(), go: go.clone() };
        let dev = Arc::new(VirtioMmio::new(probe, Arc::new(GuestMemory::new()), |_| {}));
        bring_up(&dev, &[(0, 0), (1, 0)]);
        let d = dev.clone();
        let vcpu0 = std::thread::spawn(move || notify(&d, 0));
        while !entered.load(SeqCst) {
            std::thread::yield_now();
        }
        // Another vCPU's notify while queue 0 is being served: no wait.
        notify(&dev, 1);
        assert_eq!(*calls.lock().unwrap(), [(0, true)], "not served yet: the device is busy");
        go.store(true, SeqCst);
        vcpu0.join().unwrap();
        assert_eq!(*calls.lock().unwrap(), [(0, true), (1, true)], "served by the busy context, unmasked");
        // Interrupts stay as the caller had them on this thread too.
        notify(&dev, 0);
        assert_eq!(calls.lock().unwrap().last(), Some(&(0, true)));
    }

    #[test]
    fn status_transitions_are_enforced() {
        let dev = VirtioMmio::new(Dummy, Arc::new(GuestMemory::new()), |_| {});
        let st = |v: u8| dev.write(STATUS as u64, &u32::from(v).to_le_bytes());
        let (a, d, f, k) = (status::ACKNOWLEDGE, status::DRIVER, status::FEATURES_OK, status::DRIVER_OK);
        st(a | d | k);
        assert_eq!(rd(&dev, STATUS), u32::from(a | d), "DRIVER_OK needs FEATURES_OK");
        st(f);
        assert_eq!(rd(&dev, STATUS), u32::from(a | d), "bits cannot be cleared; FEATURES_OK needs the earlier steps");
        dev.write(DRIVER_FEATURES_SEL as u64, &1u32.to_le_bytes());
        dev.write(DRIVER_FEATURES as u64, &1u32.to_le_bytes());
        st(a | d | f | k);
        assert_eq!(rd(&dev, STATUS), u32::from(a | d | f), "FEATURES_OK must be accepted by an earlier write");
        st(a | d | f | k);
        assert_eq!(rd(&dev, STATUS), u32::from(a | d | f | k));
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
        dev.write(
            STATUS as u64,
            &(u32::from(status::ACKNOWLEDGE) | u32::from(status::DRIVER) | u32::from(status::FEATURES_OK))
                .to_le_bytes(),
        );
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
