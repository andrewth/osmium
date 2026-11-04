//! A fixed-capacity cache of values by address, for tree blocks and data
//! sectors: lookups by binary search, replacement in the order of insertion.

use alloc::vec::Vec;

use osmium_fs::Errno;

/// Values by `u64` address. All memory is reserved by [`Cache::new`], so that
/// inserting never allocates.
pub(crate) struct Cache<V> {
    /// The entries, in no order; `None` where one was forgotten.
    slots: Vec<Option<(u64, V)>>,
    /// `(address, slot)` of every entry in `slots`, sorted by address.
    index: Vec<(u64, usize)>,
    /// The slot the next insertion replaces once the cache is full.
    hand: usize,
    /// Most entries.
    cap: usize,
}

impl<V: Clone> Cache<V> {
    /// A cache of up to `cap` entries (none if 0); `ENOMEM` if it cannot be reserved.
    pub(crate) fn new(cap: usize) -> Result<Self, Errno> {
        let mut slots = Vec::new();
        let mut index = Vec::new();
        slots.try_reserve_exact(cap).map_err(|_| Errno::ENOMEM)?;
        index.try_reserve_exact(cap).map_err(|_| Errno::ENOMEM)?;
        Ok(Cache { slots, index, hand: 0, cap })
    }

    /// Most entries it holds.
    pub(crate) fn capacity(&self) -> usize {
        self.cap
    }

    /// The value at `addr`.
    pub(crate) fn get(&self, addr: u64) -> Option<V> {
        let i = self.index.binary_search_by_key(&addr, |e| e.0).ok()?;
        let slot = self.index.get(i)?.1;
        self.slots.get(slot)?.as_ref().map(|(_, v)| v.clone())
    }

    /// Keeps `v` as the value at `addr`, replacing the oldest entry if full.
    pub(crate) fn insert(&mut self, addr: u64, v: V) {
        if self.cap == 0 {
            return;
        }
        match self.index.binary_search_by_key(&addr, |e| e.0) {
            Ok(i) => {
                if let Some(slot) = self.index.get(i).and_then(|e| self.slots.get_mut(e.1)) {
                    *slot = Some((addr, v));
                }
            }
            Err(_) => {
                let slot = if self.slots.len() < self.cap {
                    // Reserved by `new`, so this cannot fail.
                    self.slots.push(Some((addr, v)));
                    self.slots.len() - 1
                } else {
                    let s = self.hand % self.cap;
                    self.hand = self.hand.wrapping_add(1);
                    let old = self.slots.get_mut(s).and_then(|e| e.replace((addr, v)));
                    if let Some((old_addr, _)) = old
                        && let Ok(j) = self.index.binary_search_by_key(&old_addr, |e| e.0)
                    {
                        self.index.remove(j);
                    }
                    s
                };
                let at = self.index.partition_point(|e| e.0 < addr);
                self.index.insert(at, (addr, slot));
            }
        }
    }

    /// Drops every entry with an address in `lo..hi`.
    pub(crate) fn forget_range(&mut self, lo: u64, hi: u64) {
        let a = self.index.partition_point(|e| e.0 < lo);
        let b = self.index.partition_point(|e| e.0 < hi);
        for (_, s) in self.index.drain(a..b.max(a)) {
            if let Some(slot) = self.slots.get_mut(s) {
                *slot = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_oldest_and_forgets_ranges() {
        let mut c = Cache::<u32>::new(3).unwrap();
        for (a, v) in [(30, 3), (10, 1), (20, 2)] {
            c.insert(a, v);
        }
        assert_eq!((c.get(10), c.get(20), c.get(30), c.get(40)), (Some(1), Some(2), Some(3), None));
        // Full: the oldest (30) goes.
        c.insert(5, 0);
        assert_eq!((c.get(30), c.get(5), c.get(10)), (None, Some(0), Some(1)));
        // The same address replaces its value in place.
        c.insert(10, 11);
        assert_eq!((c.get(10), c.get(20), c.get(5)), (Some(11), Some(2), Some(0)));
        c.forget_range(6, 20);
        assert_eq!((c.get(10), c.get(20), c.get(5)), (None, Some(2), Some(0)));
        c.forget_range(0, u64::MAX);
        assert_eq!((c.get(5), c.get(20)), (None, None));
        // Still usable, and never past its capacity.
        for a in 0..10 {
            c.insert(a, a as u32);
        }
        assert_eq!((0..10).filter(|&a| c.get(a).is_some()).count(), 3);
        assert_eq!(c.get(9), Some(9));
    }

    #[test]
    fn no_capacity_keeps_nothing() {
        let mut c = Cache::<u8>::new(0).unwrap();
        c.insert(1, 1);
        assert_eq!((c.get(1), c.capacity()), (None, 0));
    }
}
