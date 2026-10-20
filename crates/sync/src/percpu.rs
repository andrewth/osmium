use core::cell::{Cell, UnsafeCell};

use osmium_arch::{MAX_CPUS, cpu, irq};

/// One `T` per CPU, selected by `osmium_arch::cpu::current_id`.
///
/// `T` must be `Sync` for the container to be shared, because other CPUs may
/// read any slot with [`PerCpu::get_for`]. For mutable data that only its own
/// CPU touches, use [`PerCpuCell`].
///
/// ```
/// use core::sync::atomic::{AtomicU64, Ordering};
/// use osmium_sync::PerCpu;
///
/// static IRQ_COUNT: PerCpu<AtomicU64> = PerCpu::new([const { AtomicU64::new(0) }; osmium_arch::MAX_CPUS]);
/// IRQ_COUNT.get().fetch_add(1, Ordering::Relaxed);
/// ```
pub struct PerCpu<T> {
    slots: [T; MAX_CPUS],
}

impl<T> PerCpu<T> {
    /// Wraps one value per CPU.
    pub const fn new(slots: [T; MAX_CPUS]) -> Self {
        Self { slots }
    }

    /// Returns this CPU's slot.
    ///
    /// Unless preemption is disabled, the task may migrate right after the
    /// call; the reference stays valid but may then name another CPU's slot.
    #[inline]
    pub fn get(&self) -> &T {
        &self.slots[cpu::current_id()]
    }

    /// Returns the slot of `cpu`.
    #[inline]
    pub fn get_for(&self, cpu: usize) -> &T {
        &self.slots[cpu]
    }

    /// Iterates over all slots.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.slots.iter()
    }
}

/// Mutable per-CPU data that only its own CPU accesses.
///
/// [`PerCpuCell::with`] masks local interrupts for the duration of the
/// closure, so neither an interrupt handler nor a migration can observe the
/// slot mid-update. Re-entering `with` on the same CPU panics instead of
/// creating aliased `&mut`.
pub struct PerCpuCell<T> {
    slots: [Slot<T>; MAX_CPUS],
}

struct Slot<T> {
    busy: Cell<bool>,
    value: UnsafeCell<T>,
}

// SAFETY: each slot is accessed only from its own CPU with interrupts masked,
// and the busy flag rules out re-entrant aliasing. Values may be created on
// one CPU and used on another, hence `T: Send`.
unsafe impl<T: Send> Sync for PerCpuCell<T> {}

impl<T> PerCpuCell<T> {
    /// Wraps one value per CPU.
    pub const fn new(values: [T; MAX_CPUS]) -> Self {
        // `map` is not const; move the values out one by one.
        let values = core::mem::ManuallyDrop::new(values);
        let mut slots: [core::mem::MaybeUninit<Slot<T>>; MAX_CPUS] =
            [const { core::mem::MaybeUninit::uninit() }; MAX_CPUS];
        let mut i = 0;
        while i < MAX_CPUS {
            // SAFETY: each element is read exactly once; `values` is never dropped.
            let v = unsafe { core::ptr::read(&values_ref(&values)[i]) };
            slots[i] = core::mem::MaybeUninit::new(Slot { busy: Cell::new(false), value: UnsafeCell::new(v) });
            i += 1;
        }
        // SAFETY: every element was initialized above, and MaybeUninit<Slot<T>>
        // has the same layout as Slot<T>.
        Self { slots: unsafe { core::mem::transmute_copy(&core::mem::ManuallyDrop::new(slots)) } }
    }

    /// Runs `f` with exclusive access to this CPU's value.
    pub fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        let state = irq::save_and_disable();
        let slot = &self.slots[cpu::current_id()];
        assert!(!slot.busy.replace(true), "PerCpuCell::with re-entered");
        // SAFETY: interrupts are masked and `busy` was clear, so no other
        // reference to this slot exists.
        let r = f(unsafe { &mut *slot.value.get() });
        slot.busy.set(false);
        irq::restore(state);
        r
    }

    /// Returns a raw pointer to this CPU's value.
    ///
    /// For code such as a context switch that must keep using the value
    /// while control leaves the current function. The caller is responsible
    /// for exclusivity.
    pub fn as_ptr(&self) -> *mut T {
        self.slots[cpu::current_id()].value.get()
    }
}

const fn values_ref<T>(v: &core::mem::ManuallyDrop<[T; MAX_CPUS]>) -> &[T; MAX_CPUS] {
    // `Deref` is not const; ManuallyDrop<T> is repr(transparent).
    // SAFETY: same layout.
    unsafe { &*(v as *const core::mem::ManuallyDrop<[T; MAX_CPUS]> as *const [T; MAX_CPUS]) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn slots_follow_cpu_id() {
        static COUNTS: PerCpu<AtomicU32> = PerCpu::new([const { AtomicU32::new(0) }; MAX_CPUS]);
        let t = std::thread::spawn(|| {
            // SAFETY: host simulation; this thread is the only "CPU 3".
            unsafe { cpu::set_current_id(3) };
            COUNTS.get().fetch_add(5, Ordering::Relaxed);
        });
        t.join().unwrap();
        assert_eq!(COUNTS.get_for(3).load(Ordering::Relaxed), 5);
    }

    #[test]
    fn cell_with_mutates() {
        static CELL: PerCpuCell<u64> = PerCpuCell::new([0; MAX_CPUS]);
        let t = std::thread::spawn(|| {
            // SAFETY: host simulation; this thread is the only "CPU 4".
            unsafe { cpu::set_current_id(4) };
            CELL.with(|v| *v += 2);
            CELL.with(|v| *v)
        });
        assert_eq!(t.join().unwrap(), 2);
    }
}
