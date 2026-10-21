//! An intrusive interval tree.

use super::avltree::{insert_retrace, remove_retrace};
use super::bst::{
    Augment, Ptr, TreeLink, child, clear_tree, detach, dir_of, extreme, init_leaf, parent, rd, set_child, step,
};
use super::{Adapter, link_of, value_of};
use core::cell::Cell;
use core::marker::PhantomData;
use core::ops::Range;
use core::ptr::NonNull;

/// Interval tree hook. Embed one in each element of an [`IntervalTree`].
#[repr(C)]
pub struct IntervalLink {
    /// Must stay first: the tree code treats a node pointer as either type.
    tree: TreeLink,
    start: Cell<u64>,
    end: Cell<u64>,
    /// The largest `end` in the subtree rooted here.
    max: Cell<u64>,
}

impl IntervalLink {
    /// Creates an unlinked hook.
    pub const fn new() -> Self {
        Self { tree: TreeLink::new(), start: Cell::new(0), end: Cell::new(0), max: Cell::new(0) }
    }

    /// Whether the element is currently in a tree.
    pub fn is_linked(&self) -> bool {
        self.tree.is_linked()
    }
}

impl Default for IntervalLink {
    fn default() -> Self {
        Self::new()
    }
}

/// An [`Adapter`] that also gives each element's half-open range.
pub trait IntervalAdapter: Adapter<IntervalLink> {
    /// The range `start..end` covered by `value`, with `start < end`. It
    /// must not change while `value` is in a tree.
    fn range(value: &Self::Value) -> Range<u64>;
}

fn il<'a>(n: NonNull<TreeLink>) -> &'a IntervalLink {
    // SAFETY: every node of an interval tree is the first field of a linked `IntervalLink`, which
    // `insert`'s contract keeps valid.
    unsafe { n.cast::<IntervalLink>().as_ref() }
}

fn start(n: NonNull<TreeLink>) -> u64 {
    il(n).start.get()
}

fn end(n: NonNull<TreeLink>) -> u64 {
    il(n).end.get()
}

fn max(n: Option<NonNull<TreeLink>>) -> u64 {
    n.map_or(0, |n| il(n).max.get())
}

/// Keeps `max` current through rotations.
struct MaxEnd;

impl Augment for MaxEnd {
    fn update(n: NonNull<TreeLink>) {
        il(n).max.set(end(n).max(max(child(n, 0))).max(max(child(n, 1))));
    }
}

/// Recomputes `max` from `n` up to the root.
fn update_path(mut n: Ptr) {
    while let Some(c) = n {
        MaxEnd::update(c);
        n = parent(c);
    }
}

fn overlaps(n: NonNull<TreeLink>, qs: u64, qe: u64) -> bool {
    start(n) < qe && qs < end(n)
}

/// The first node in order under `n` that overlaps `qs..qe`.
fn first_overlap(n: Ptr, qs: u64, qe: u64) -> Ptr {
    let n = n?;
    if il(n).max.get() <= qs {
        return None;
    }
    if let Some(f) = first_overlap(child(n, 0), qs, qe) {
        return Some(f);
    }
    if overlaps(n, qs, qe) {
        return Some(n);
    }
    // Everything to the right starts no earlier than `n`.
    if start(n) >= qe { None } else { first_overlap(child(n, 1), qs, qe) }
}

/// The first overlapping node after `n` in order.
fn next_overlap(n: NonNull<TreeLink>, qs: u64, qe: u64) -> Ptr {
    if start(n) >= qe {
        return None;
    }
    if let Some(f) = first_overlap(child(n, 1), qs, qe) {
        return Some(f);
    }
    let mut cur = n;
    loop {
        let p = parent(cur)?;
        if dir_of(cur, p) == 0 {
            if start(p) >= qe {
                return None;
            }
            if overlaps(p, qs, qe) {
                return Some(p);
            }
            if let Some(f) = first_overlap(child(p, 1), qs, qe) {
                return Some(f);
            }
        }
        cur = p;
    }
}

/// A multiset of half-open `u64` ranges, kept as an AVL tree ordered by
/// `(start, end)` and augmented with each subtree's largest end. Finding all
/// `k` ranges that overlap a query takes O(log n + k).
///
/// Ranges may repeat and overlap freely. Typical uses are virtual memory
/// areas and reserved address windows.
pub struct IntervalTree<A: IntervalAdapter> {
    root: Ptr,
    len: usize,
    _adapter: PhantomData<A>,
}

impl<A: IntervalAdapter> IntervalTree<A> {
    /// Creates an empty tree.
    pub const fn new() -> Self {
        Self { root: None, len: 0, _adapter: PhantomData }
    }

    /// Whether the tree has no elements.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Number of linked elements.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Links `value`.
    ///
    /// # Safety
    ///
    /// `value` must stay valid and must not move until it is removed from the
    /// tree or the tree is dropped or cleared.
    ///
    /// # Panics
    ///
    /// If `value` is already linked or its range is empty.
    pub unsafe fn insert(&mut self, value: NonNull<A::Value>) {
        let link = link_of::<IntervalLink, A>(value);
        // SAFETY: the caller guarantees `value` is valid.
        let r = A::range(unsafe { value.as_ref() });
        assert!(r.start < r.end, "empty interval");
        let n = link.cast::<TreeLink>();
        assert!(!rd(n).is_linked(), "element already linked");
        let key = (r.start, r.end, n.as_ptr() as usize);
        let (mut up, mut dir, mut cur) = (None, 0, self.root);
        while let Some(c) = cur {
            up = cur;
            dir = usize::from(key >= (start(c), end(c), c.as_ptr() as usize));
            cur = child(c, dir);
        }
        init_leaf(n);
        let l = il(n);
        l.start.set(r.start);
        l.end.set(r.end);
        l.max.set(r.end);
        match up {
            Some(p) => set_child(p, dir, Some(n)),
            None => self.root = Some(n),
        }
        self.len += 1;
        // Bring every ancestor's `max` up to date before any rotation reads it.
        update_path(up);
        insert_retrace::<MaxEnd>(&mut self.root, n);
    }

    /// Unlinks `value`, returning whether it was linked.
    ///
    /// # Safety
    ///
    /// If `value` is linked, it must be linked in `self`.
    pub unsafe fn remove(&mut self, value: NonNull<A::Value>) -> bool {
        let n = link_of::<IntervalLink, A>(value).cast::<TreeLink>();
        if !rd(n).is_linked() {
            return false;
        }
        let det = detach(&mut self.root, n);
        self.len -= 1;
        update_path(det.parent);
        remove_retrace::<MaxEnd>(&mut self.root, det.parent, det.dir);
        true
    }

    /// Unlinks every element in O(n).
    pub fn clear(&mut self) {
        clear_tree(&mut self.root);
        self.len = 0;
    }

    /// The element with the smallest `(start, end)`.
    pub fn first(&self) -> Option<&A::Value> {
        self.root.map(|r| Self::val(extreme(r, 0)))
    }

    /// Iterates over all elements in ascending `(start, end)` order.
    pub fn iter(&self) -> Iter<'_, A> {
        Iter { next: self.root.map(|r| extreme(r, 0)), _tree: PhantomData }
    }

    /// Iterates, in ascending order, over the elements whose range shares at
    /// least one point with `range`.
    pub fn overlapping(&self, range: Range<u64>) -> Overlapping<'_, A> {
        let next = if range.start < range.end { first_overlap(self.root, range.start, range.end) } else { None };
        Overlapping { next, qs: range.start, qe: range.end, _tree: PhantomData }
    }

    /// Iterates over the elements whose range contains `point`.
    pub fn stabbing(&self, point: u64) -> Overlapping<'_, A> {
        self.overlapping(point..point.saturating_add(1))
    }

    fn val<'a>(n: NonNull<TreeLink>) -> &'a A::Value {
        // SAFETY: linked elements are valid by the `insert` contract.
        unsafe { value_of::<IntervalLink, A>(n.cast()).as_ref() }
    }
}

impl<A: IntervalAdapter> Default for IntervalTree<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: IntervalAdapter> Drop for IntervalTree<A> {
    /// Unlinks the remaining elements so their hooks do not dangle.
    fn drop(&mut self) {
        self.clear();
    }
}

/// Ascending-order iterator over every element of an [`IntervalTree`].
pub struct Iter<'tree, A: IntervalAdapter> {
    next: Ptr,
    _tree: PhantomData<(&'tree IntervalTree<A>, A)>,
}

impl<'tree, A: IntervalAdapter> Iterator for Iter<'tree, A> {
    type Item = &'tree A::Value;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.next?;
        self.next = step(n, 1);
        Some(IntervalTree::<A>::val(n))
    }
}

/// Iterator over the elements of an [`IntervalTree`] overlapping a query.
pub struct Overlapping<'tree, A: IntervalAdapter> {
    next: Ptr,
    qs: u64,
    qe: u64,
    _tree: PhantomData<(&'tree IntervalTree<A>, A)>,
}

impl<'tree, A: IntervalAdapter> Iterator for Overlapping<'tree, A> {
    type Item = &'tree A::Value;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.next?;
        self.next = next_overlap(n, self.qs, self.qe);
        Some(IntervalTree::<A>::val(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;
    use std::vec::Vec;

    struct Iv {
        id: u32,
        start: u64,
        end: u64,
        link: IntervalLink,
    }

    struct ByRange;
    // SAFETY: `offset_of!` of the `IntervalLink` field.
    unsafe impl Adapter<IntervalLink> for ByRange {
        type Value = Iv;
        const OFFSET: usize = offset_of!(Iv, link);
    }
    impl IntervalAdapter for ByRange {
        fn range(v: &Iv) -> Range<u64> {
            v.start..v.end
        }
    }

    fn ivs(ranges: &[(u64, u64)]) -> Vec<Iv> {
        ranges
            .iter()
            .enumerate()
            .map(|(i, &(start, end))| Iv { id: i as u32, start, end, link: IntervalLink::new() })
            .collect()
    }

    fn ids<'a>(it: impl Iterator<Item = &'a Iv>) -> Vec<u32> {
        it.map(|n| n.id).collect()
    }

    /// Asserts parent links, order, balance factors and subtree maxima; returns (height, count).
    fn check(t: &IntervalTree<ByRange>) {
        fn walk(n: NonNull<TreeLink>, up: Ptr, last: &mut Option<(u64, u64)>) -> (i8, usize) {
            assert_eq!(parent(n), up);
            assert!(rd(n).is_linked());
            let (l, lc) = child(n, 0).map_or((0, 0), |c| walk(c, Some(n), last));
            let key = (start(n), end(n));
            assert!(last.is_none_or(|p| p <= key), "out of order");
            *last = Some(key);
            let (r, rc) = child(n, 1).map_or((0, 0), |c| walk(c, Some(n), last));
            assert_eq!(super::super::bst::aux(n), r - l, "stale balance factor");
            assert!((r - l).abs() <= 1, "unbalanced");
            assert_eq!(il(n).max.get(), end(n).max(max(child(n, 0))).max(max(child(n, 1))), "stale max");
            (1 + l.max(r), 1 + lc + rc)
        }
        let count = t.root.map_or(0, |r| walk(r, None, &mut None).1);
        assert_eq!(count, t.len());
    }

    #[test]
    fn overlap_queries() {
        let ns = ivs(&[(10, 20), (15, 30), (0, 5), (40, 50), (25, 26), (10, 20)]);
        let mut t = IntervalTree::<ByRange>::new();
        for n in &ns {
            // SAFETY: `ns` outlives `t` and is not moved.
            unsafe { t.insert(NonNull::from(n)) };
        }
        check(&t);
        assert_eq!(t.first().unwrap().id, 2);
        assert_eq!(ids(t.iter()).len(), 6);
        let mut got = ids(t.overlapping(18..26));
        got.sort();
        assert_eq!(got, [0, 1, 4, 5]);
        // The range ends are exclusive on both sides.
        assert_eq!(ids(t.overlapping(20..25)), [1]);
        assert_eq!(ids(t.overlapping(30..40)), Vec::<u32>::new());
        assert_eq!(ids(t.overlapping(26..27)), [1]);
        assert_eq!(ids(t.stabbing(25)), [1, 4]);
        assert_eq!(ids(t.stabbing(50)), Vec::<u32>::new());
        assert_eq!(ids(t.stabbing(u64::MAX)), Vec::<u32>::new());
        assert_eq!(ids(t.overlapping(5..5)), Vec::<u32>::new());
    }

    #[test]
    fn matches_model_under_random_ops() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed >> 16
        };
        let ns: Vec<Iv> = (0..150)
            .map(|id| {
                let start = rng() % 500;
                Iv { id, start, end: start + 1 + rng() % 80, link: IntervalLink::new() }
            })
            .collect();
        let mut t = IntervalTree::<ByRange>::new();
        for _ in 0..5000 {
            let n = &ns[(rng() % 150) as usize];
            // SAFETY: `ns` outlives `t` and is not moved; every linked node is in `t`.
            unsafe {
                if n.link.is_linked() {
                    assert!(t.remove(NonNull::from(n)));
                } else {
                    t.insert(NonNull::from(n));
                }
            }
            check(&t);
            assert_eq!(t.len(), ns.iter().filter(|n| n.link.is_linked()).count());
            let qs = rng() % 600;
            let qe = qs + rng() % 100;
            let want: Vec<u32> = ns
                .iter()
                .filter(|n| n.link.is_linked() && qs < qe && n.start < qe && qs < n.end)
                .map(|n| n.id)
                .collect();
            let got = t.overlapping(qs..qe).collect::<Vec<_>>();
            assert!(got.windows(2).all(|w| (w[0].start, w[0].end) <= (w[1].start, w[1].end)));
            let mut got = ids(got.into_iter());
            got.sort();
            assert_eq!(got, want);
            let p = rng() % 600;
            let want: Vec<u32> =
                ns.iter().filter(|n| n.link.is_linked() && n.start <= p && p < n.end).map(|n| n.id).collect();
            let mut got = ids(t.stabbing(p));
            got.sort();
            assert_eq!(got, want);
        }
    }

    #[test]
    fn drop_unlinks_and_misuse_panics() {
        let ns = ivs(&[(0, 4), (2, 8)]);
        {
            let mut t = IntervalTree::<ByRange>::new();
            // SAFETY: `ns` outlives `t`.
            unsafe {
                t.insert(NonNull::from(&ns[0]));
                t.insert(NonNull::from(&ns[1]));
            }
            assert!(ns[0].link.is_linked());
        }
        assert!(!ns[0].link.is_linked() && !ns[1].link.is_linked());
        let mut t = IntervalTree::<ByRange>::new();
        // SAFETY: an unlinked element is never in another tree.
        assert!(!unsafe { t.remove(NonNull::from(&ns[0])) });
    }

    #[test]
    #[should_panic(expected = "empty interval")]
    fn empty_range_panics() {
        let ns = ivs(&[(5, 5)]);
        let mut t = IntervalTree::<ByRange>::new();
        // SAFETY: `ns` outlives `t`.
        unsafe { t.insert(NonNull::from(&ns[0])) };
    }
}
