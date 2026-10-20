use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// A bounded, lock-free, single-producer single-consumer queue.
///
/// The typical use is an interrupt handler producing and a task consuming
/// (UART receive, network descriptors). Producer and consumer handles are
/// obtained once with [`SpscRing::split`], which works on a `static`.
pub struct SpscRing<T, const N: usize> {
    buf: [UnsafeCell<MaybeUninit<T>>; N],
    /// Next slot to read; only the consumer advances it.
    head: AtomicUsize,
    /// Next slot to write; only the producer advances it.
    tail: AtomicUsize,
    split: AtomicBool,
}

// SAFETY: slots between head and tail belong to the consumer, the rest to the
// producer; the indices hand slots over with Release/Acquire.
unsafe impl<T: Send, const N: usize> Sync for SpscRing<T, N> {}

impl<T, const N: usize> SpscRing<T, N> {
    /// Creates an empty ring holding up to `N` items.
    ///
    /// # Panics
    ///
    /// If `N` is zero (at compile time in a `const` context).
    pub const fn new() -> Self {
        assert!(N > 0);
        Self {
            buf: [const { UnsafeCell::new(MaybeUninit::uninit()) }; N],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            split: AtomicBool::new(false),
        }
    }

    /// Returns the producer and consumer handles. Succeeds only once.
    pub fn split(&self) -> Option<(Producer<'_, T, N>, Consumer<'_, T, N>)> {
        if self.split.swap(true, Ordering::AcqRel) {
            return None;
        }
        Some((Producer { ring: self }, Consumer { ring: self }))
    }

    /// Returns the number of queued items.
    pub fn len(&self) -> usize {
        self.tail.load(Ordering::Acquire).wrapping_sub(self.head.load(Ordering::Acquire))
    }

    /// Returns true if no items are queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T, const N: usize> Default for SpscRing<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Drop for SpscRing<T, N> {
    fn drop(&mut self) {
        let (mut head, tail) = (*self.head.get_mut(), *self.tail.get_mut());
        while head != tail {
            // SAFETY: slots in [head, tail) hold initialized items.
            unsafe { self.buf[head % N].get_mut().assume_init_drop() };
            head = head.wrapping_add(1);
        }
    }
}

/// The sending half of an [`SpscRing`].
pub struct Producer<'ring, T, const N: usize> {
    ring: &'ring SpscRing<T, N>,
}

/// The receiving half of an [`SpscRing`].
pub struct Consumer<'ring, T, const N: usize> {
    ring: &'ring SpscRing<T, N>,
}

impl<T, const N: usize> Producer<'_, T, N> {
    /// Queues `item`, or returns it if the ring is full.
    pub fn push(&mut self, item: T) -> Result<(), T> {
        let tail = self.ring.tail.load(Ordering::Relaxed);
        if tail.wrapping_sub(self.ring.head.load(Ordering::Acquire)) == N {
            return Err(item);
        }
        // SAFETY: the slot at `tail` is outside [head, tail), so the consumer
        // does not touch it, and this is the only producer.
        unsafe { (*self.ring.buf[tail % N].get()).write(item) };
        self.ring.tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }
}

impl<T, const N: usize> Consumer<'_, T, N> {
    /// Dequeues the oldest item.
    pub fn pop(&mut self) -> Option<T> {
        let head = self.ring.head.load(Ordering::Relaxed);
        if head == self.ring.tail.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: the slot at `head` is inside [head, tail) and initialized;
        // this is the only consumer.
        let item = unsafe { (*self.ring.buf[head % N].get()).assume_init_read() };
        self.ring.head.store(head.wrapping_add(1), Ordering::Release);
        Some(item)
    }
}

// SAFETY: a handle is the unique owner of its end of the ring.
unsafe impl<T: Send, const N: usize> Send for Producer<'_, T, N> {}
// SAFETY: as above.
unsafe impl<T: Send, const N: usize> Send for Consumer<'_, T, N> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_and_capacity() {
        let ring: SpscRing<u32, 4> = SpscRing::new();
        let (mut p, mut c) = ring.split().unwrap();
        assert!(ring.split().is_none());
        for i in 0..4 {
            p.push(i).unwrap();
        }
        assert_eq!(p.push(9), Err(9));
        assert_eq!(c.pop(), Some(0));
        p.push(4).unwrap();
        assert_eq!((1..5).map(|_| c.pop().unwrap()).collect::<std::vec::Vec<_>>(), [1, 2, 3, 4]);
        assert_eq!(c.pop(), None);
    }

    #[test]
    fn cross_thread() {
        static RING: SpscRing<u64, 16> = SpscRing::new();
        let (mut p, mut c) = RING.split().unwrap();
        let producer = std::thread::spawn(move || {
            for i in 0..100_000u64 {
                while p.push(i).is_err() {}
            }
        });
        let mut expected = 0;
        while expected < 100_000 {
            if let Some(v) = c.pop() {
                assert_eq!(v, expected);
                expected += 1;
            }
        }
        producer.join().unwrap();
    }

    #[test]
    fn drops_leftovers() {
        let ring: SpscRing<std::sync::Arc<()>, 4> = SpscRing::new();
        let item = std::sync::Arc::new(());
        ring.split().unwrap().0.push(item.clone()).unwrap();
        drop(ring);
        assert_eq!(std::sync::Arc::strong_count(&item), 1);
    }
}
