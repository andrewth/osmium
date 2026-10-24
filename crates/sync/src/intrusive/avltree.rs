//! An intrusive AVL tree.

use super::bst::{
    Augment, Bst, Detached, KeyAdapter, Ptr, TreeLink, aux, child, dir_of, parent, rd, rotate_with, set_aux,
};
use core::ops::Deref;
use core::ptr::NonNull;

/// An ordered set of elements that embed a [`TreeLink`], kept balanced as an
/// AVL tree: sibling subtree heights differ by at most one, so lookups are
/// shallower than in a red-black tree at the price of more rotations on
/// removal. Prefer it for read-mostly maps.
///
/// Keys are unique; inserting an element whose key is present fails. Lookup,
/// ordered iteration and size come from [`Bst`] through `Deref`.
pub struct AvlTree<A: KeyAdapter<TreeLink>> {
    bst: Bst<A>,
}

impl<A: KeyAdapter<TreeLink>> AvlTree<A> {
    /// Creates an empty tree.
    pub const fn new() -> Self {
        Self { bst: Bst::new() }
    }

    /// Links `value`, returning `false` (and leaving it unlinked) if an
    /// element with the same key is already present.
    ///
    /// # Safety
    ///
    /// `value` must stay valid and must not move until it is removed from the
    /// tree or the tree is dropped or cleared. Its key must not change while
    /// it is linked.
    ///
    /// # Panics
    ///
    /// If `value` is already linked.
    pub unsafe fn insert(&mut self, value: NonNull<A::Value>) -> bool {
        // SAFETY: forwarded from the caller.
        let Some(z) = (unsafe { self.bst.attach(value) }) else {
            return false;
        };
        insert_retrace::<()>(&mut self.bst.root, z);
        true
    }

    /// Unlinks `value`, returning whether it was linked.
    ///
    /// # Safety
    ///
    /// If `value` is linked, it must be linked in `self`.
    pub unsafe fn remove(&mut self, value: NonNull<A::Value>) -> bool {
        let link = Bst::<A>::link(value);
        if !rd(link).is_linked() {
            return false;
        }
        self.remove_link(link);
        true
    }

    /// Unlinks the element whose key equals `key`.
    pub fn take(&mut self, key: &A::Key) -> Option<NonNull<A::Value>> {
        let link = self.bst.find_node(key)?;
        self.remove_link(link);
        Some(Bst::<A>::value(link))
    }

    /// Unlinks the element with the smallest key.
    pub fn pop_first(&mut self) -> Option<NonNull<A::Value>> {
        let link = self.bst.first_node()?;
        self.remove_link(link);
        Some(Bst::<A>::value(link))
    }

    /// Unlinks the element with the largest key.
    pub fn pop_last(&mut self) -> Option<NonNull<A::Value>> {
        let link = self.bst.last_node()?;
        self.remove_link(link);
        Some(Bst::<A>::value(link))
    }

    /// Unlinks every element in O(n).
    pub fn clear(&mut self) {
        self.bst.clear();
    }

    fn remove_link(&mut self, link: NonNull<TreeLink>) {
        let Detached { parent, dir, .. } = self.bst.detach_node(link);
        remove_retrace::<()>(&mut self.bst.root, parent, dir);
    }
}

impl<A: KeyAdapter<TreeLink>> Default for AvlTree<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: KeyAdapter<TreeLink>> Deref for AvlTree<A> {
    type Target = Bst<A>;

    fn deref(&self) -> &Bst<A> {
        &self.bst
    }
}

/// `aux` is the height of the right subtree minus that of the left, so a
/// subtree that grew or shrank on side `dir` moves it by this much.
pub(super) fn sign(dir: usize) -> i8 {
    if dir == 1 { 1 } else { -1 }
}

/// Fixes `z`, whose subtree on side `dir` is two taller than the other.
/// Returns the node now on top and whether the subtree kept its old height.
fn rebalance<H: Augment>(root: &mut Ptr, z: NonNull<TreeLink>, dir: usize) -> (NonNull<TreeLink>, bool) {
    let s = sign(dir);
    let Some(c) = child(z, dir) else {
        // A heavy side always has a child; only a corrupt tree gets here.
        return (z, true);
    };
    if aux(c) == -s {
        // The heavy child leans the other way: rotate it first.
        let Some(g) = child(c, 1 - dir) else {
            return (z, true);
        };
        let gb = aux(g);
        rotate_with::<H>(root, c, dir);
        rotate_with::<H>(root, z, 1 - dir);
        set_aux(z, if gb == s { -s } else { 0 });
        set_aux(c, if gb == -s { s } else { 0 });
        set_aux(g, 0);
        (g, false)
    } else {
        rotate_with::<H>(root, z, 1 - dir);
        if aux(c) == 0 {
            // Only removal produces a balanced heavy child; the height is unchanged.
            set_aux(z, s);
            set_aux(c, -s);
            (c, true)
        } else {
            set_aux(z, 0);
            set_aux(c, 0);
            (c, false)
        }
    }
}

/// Updates balances upwards after `n` was linked as a leaf.
pub(super) fn insert_retrace<H: Augment>(root: &mut Ptr, mut n: NonNull<TreeLink>) {
    while let Some(p) = parent(n) {
        let d = dir_of(n, p);
        let b = aux(p) + sign(d);
        match b {
            0 => {
                set_aux(p, 0);
                break;
            }
            -1 | 1 => {
                set_aux(p, b);
                n = p;
            }
            _ => {
                rebalance::<H>(root, p, d);
                break;
            }
        }
    }
}

/// Updates balances upwards after the subtree on side `dir` of `p` got one shorter.
pub(super) fn remove_retrace<H: Augment>(root: &mut Ptr, mut p: Ptr, mut dir: usize) {
    while let Some(par) = p {
        let b = aux(par) - sign(dir);
        let top = match b {
            0 => {
                set_aux(par, 0);
                par
            }
            -1 | 1 => {
                set_aux(par, b);
                break;
            }
            _ => {
                let (top, same_height) = rebalance::<H>(root, par, 1 - dir);
                if same_height {
                    break;
                }
                top
            }
        };
        p = parent(top);
        dir = p.map_or(0, |g| dir_of(top, g));
    }
}

#[cfg(test)]
mod tests {
    use super::super::bst::test_support::*;
    use super::*;

    impl Harness for AvlTree<ByKey> {
        fn insert(&mut self, v: NonNull<TestNode>) -> bool {
            // SAFETY: tests keep their node vectors alive and unmoved.
            unsafe { AvlTree::insert(self, v) }
        }
        fn remove(&mut self, v: NonNull<TestNode>) -> bool {
            // SAFETY: tests only remove nodes they inserted here.
            unsafe { AvlTree::remove(self, v) }
        }
        fn take(&mut self, key: u32) -> Option<NonNull<TestNode>> {
            AvlTree::take(self, &key)
        }
        fn pop_first(&mut self) -> Option<NonNull<TestNode>> {
            AvlTree::pop_first(self)
        }
        fn pop_last(&mut self) -> Option<NonNull<TestNode>> {
            AvlTree::pop_last(self)
        }
        fn view(&self) -> &Bst<ByKey> {
            self
        }
        fn check(&self) {
            check_structure(self);
            /// Returns the height of the subtree.
            fn height(n: Ptr) -> i8 {
                let Some(n) = n else { return 0 };
                let (l, r) = (height(child(n, 0)), height(child(n, 1)));
                assert_eq!(aux(n), r - l, "stale balance factor");
                assert!((r - l).abs() <= 1, "unbalanced");
                1 + l.max(r)
            }
            height(self.root);
        }
    }

    #[test]
    fn matches_btreeset_under_random_ops() {
        fuzz(AvlTree::<ByKey>::new());
    }

    #[test]
    fn ascending_inserts_stay_shallow() {
        let ns = nodes(0..1023);
        let mut t = AvlTree::<ByKey>::new();
        for n in &ns {
            // SAFETY: `ns` outlives `t` and is not moved.
            assert!(unsafe { t.insert(NonNull::from(n)) });
        }
        t.check();
        // A perfect tree: 1023 = 2^10 - 1 ascending inserts fill it exactly.
        fn depth(n: Ptr) -> usize {
            n.map_or(0, |n| 1 + depth(child(n, 0)).max(depth(child(n, 1))))
        }
        assert_eq!(depth(t.root), 10);
    }

    #[test]
    fn duplicates_rejected_and_drop_unlinks() {
        let (a, b) = duplicate_and_drop(AvlTree::<ByKey>::new());
        assert!(a.iter().chain(&b).all(|n| !n.link.is_linked()));
    }

    #[test]
    #[should_panic(expected = "already linked")]
    fn double_insert_panics() {
        let ns = nodes(0..1);
        let mut t = AvlTree::<ByKey>::new();
        // SAFETY: `ns` outlives `t`.
        unsafe {
            t.insert(NonNull::from(&ns[0]));
            t.insert(NonNull::from(&ns[0]));
        }
    }
}
