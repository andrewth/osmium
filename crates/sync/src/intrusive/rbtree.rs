//! An intrusive red-black tree.

use super::bst::{Bst, Detached, KeyAdapter, Ptr, TreeLink, aux, child, dir_of, parent, rd, rotate, set_aux};
use core::ops::Deref;
use core::ptr::NonNull;

const RED: i8 = 0;
const BLACK: i8 = 1;

/// An ordered set of elements that embed a [`TreeLink`], kept balanced as a
/// red-black tree: insertion and removal take O(log n) with at most three
/// rotations, which suits write-heavy maps such as address-space trees.
///
/// Keys are unique; inserting an element whose key is present fails. Lookup,
/// ordered iteration and size come from [`Bst`] through `Deref`.
pub struct RbTree<A: KeyAdapter<TreeLink>> {
    bst: Bst<A>,
}

impl<A: KeyAdapter<TreeLink>> RbTree<A> {
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
        insert_fixup(&mut self.bst.root, z);
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
        let Detached { parent, dir, child, aux } = self.bst.detach_node(link);
        if aux == BLACK {
            remove_fixup(&mut self.bst.root, child, parent, dir);
        }
    }
}

impl<A: KeyAdapter<TreeLink>> Default for RbTree<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: KeyAdapter<TreeLink>> Deref for RbTree<A> {
    type Target = Bst<A>;

    fn deref(&self) -> &Bst<A> {
        &self.bst
    }
}

fn is_black(n: Ptr) -> bool {
    n.is_none_or(|n| aux(n) == BLACK)
}

/// Restores the invariants after `z` was linked as a red leaf.
fn insert_fixup(root: &mut Ptr, mut z: NonNull<TreeLink>) {
    while let Some(mut p) = parent(z) {
        if aux(p) == BLACK {
            break;
        }
        let Some(g) = parent(p) else {
            // A red node is never the root: only a corrupt tree gets here.
            break;
        };
        let d = dir_of(p, g);
        let uncle = child(g, 1 - d);
        if let Some(u) = uncle.filter(|&u| aux(u) == RED) {
            set_aux(p, BLACK);
            set_aux(u, BLACK);
            set_aux(g, RED);
            z = g;
            continue;
        }
        if dir_of(z, p) == 1 - d {
            // Inner grandchild: rotate it outward first.
            rotate(root, p, d);
            z = p;
            let Some(np) = parent(z) else { break };
            p = np;
        }
        set_aux(p, BLACK);
        set_aux(g, RED);
        rotate(root, g, 1 - d);
        break;
    }
    if let Some(r) = *root {
        set_aux(r, BLACK);
    }
}

/// Restores the invariants after a black node left the position `dir` of
/// `p`, where `x` now hangs.
fn remove_fixup(root: &mut Ptr, mut x: Ptr, mut p: Ptr, mut d: usize) {
    while let Some(par) = p {
        if !is_black(x) {
            break;
        }
        // A doubly black node has a sibling; only a corrupt tree lacks one.
        let Some(mut w) = child(par, 1 - d) else { break };
        if aux(w) == RED {
            set_aux(w, BLACK);
            set_aux(par, RED);
            rotate(root, par, d);
            let Some(nw) = child(par, 1 - d) else { break };
            w = nw;
        }
        if is_black(child(w, 0)) && is_black(child(w, 1)) {
            set_aux(w, RED);
            x = Some(par);
            p = parent(par);
            d = p.map_or(0, |g| dir_of(par, g));
            continue;
        }
        if is_black(child(w, 1 - d)) {
            let Some(near) = child(w, d) else { break };
            set_aux(near, BLACK);
            set_aux(w, RED);
            rotate(root, w, 1 - d);
            let Some(nw) = child(par, 1 - d) else { break };
            w = nw;
        }
        set_aux(w, aux(par));
        set_aux(par, BLACK);
        if let Some(far) = child(w, 1 - d) {
            set_aux(far, BLACK);
        }
        rotate(root, par, d);
        x = *root;
        break;
    }
    if let Some(x) = x {
        set_aux(x, BLACK);
    }
}

#[cfg(test)]
mod tests {
    use super::super::bst::test_support::*;
    use super::*;

    impl Harness for RbTree<ByKey> {
        fn insert(&mut self, v: NonNull<TestNode>) -> bool {
            // SAFETY: tests keep their node vectors alive and unmoved.
            unsafe { RbTree::insert(self, v) }
        }
        fn remove(&mut self, v: NonNull<TestNode>) -> bool {
            // SAFETY: tests only remove nodes they inserted here.
            unsafe { RbTree::remove(self, v) }
        }
        fn take(&mut self, key: u32) -> Option<NonNull<TestNode>> {
            RbTree::take(self, &key)
        }
        fn pop_first(&mut self) -> Option<NonNull<TestNode>> {
            RbTree::pop_first(self)
        }
        fn pop_last(&mut self) -> Option<NonNull<TestNode>> {
            RbTree::pop_last(self)
        }
        fn view(&self) -> &Bst<ByKey> {
            self
        }
        fn check(&self) {
            check_structure(self);
            /// Returns the black height of the subtree.
            fn black_height(n: Ptr) -> usize {
                let Some(n) = n else { return 1 };
                if aux(n) == RED {
                    assert!(is_black(child(n, 0)) && is_black(child(n, 1)), "red node with a red child");
                }
                let (l, r) = (black_height(child(n, 0)), black_height(child(n, 1)));
                assert_eq!(l, r, "unequal black heights");
                l + usize::from(aux(n) == BLACK)
            }
            assert!(is_black(self.root), "root must be black");
            black_height(self.root);
        }
    }

    #[test]
    fn matches_btreeset_under_random_ops() {
        fuzz(RbTree::<ByKey>::new());
    }

    #[test]
    fn find_ptr_walks_in_key_order_and_can_remove() {
        let ns = nodes([5, 1, 4, 2, 3].into_iter());
        let mut t = RbTree::<ByKey>::new();
        for n in &ns {
            // SAFETY: `ns` outlives `t` and is not moved.
            assert!(unsafe { t.insert(NonNull::from(n)) });
        }
        assert_eq!(key_at(t.first_ptr().unwrap()), 1);
        let p = t.find_ptr(|n| n.key > 2).unwrap();
        assert_eq!(key_at(p), 3);
        // SAFETY: linked in `t`.
        assert!(unsafe { t.remove(p) });
        assert_eq!(t.find_ptr(|n| n.key > 2).map(key_at), Some(4));
        assert!(t.find_ptr(|n| n.key > 9).is_none());
        t.check();
    }

    #[test]
    fn ascending_inserts_stay_shallow() {
        let ns = nodes(0..1024);
        let mut t = RbTree::<ByKey>::new();
        for n in &ns {
            // SAFETY: `ns` outlives `t` and is not moved.
            assert!(unsafe { t.insert(NonNull::from(n)) });
        }
        t.check();
        fn depth(n: Ptr) -> usize {
            n.map_or(0, |n| 1 + depth(child(n, 0)).max(depth(child(n, 1))))
        }
        assert!(depth(t.root) <= 2 * 11);
    }

    #[test]
    fn duplicates_rejected_and_drop_unlinks() {
        let (a, b) = duplicate_and_drop(RbTree::<ByKey>::new());
        assert!(a.iter().chain(&b).all(|n| !n.link.is_linked()));
    }

    #[test]
    #[should_panic(expected = "already linked")]
    fn double_insert_panics() {
        let ns = nodes(0..1);
        let mut t = RbTree::<ByKey>::new();
        // SAFETY: `ns` outlives `t`.
        unsafe {
            t.insert(NonNull::from(&ns[0]));
            t.insert(NonNull::from(&ns[0]));
        }
    }
}
