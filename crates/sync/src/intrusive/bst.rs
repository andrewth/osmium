//! Binary search tree plumbing shared by the red-black and AVL trees.

use super::{Adapter, link_of, value_of};
use core::cell::Cell;
use core::cmp::Ordering;
use core::marker::PhantomData;
use core::ptr::NonNull;

pub(super) type Ptr = Option<NonNull<TreeLink>>;

/// Ordered tree hook, used by both [`RbTree`](super::rbtree::RbTree) and
/// [`AvlTree`](super::avltree::AvlTree). Embed one per tree an element can
/// be in.
pub struct TreeLink {
    parent: Cell<Ptr>,
    child: [Cell<Ptr>; 2],
    linked: Cell<bool>,
    /// Colour for the red-black tree, balance factor for the AVL tree.
    aux: Cell<i8>,
}

impl TreeLink {
    /// Creates an unlinked hook.
    pub const fn new() -> Self {
        Self {
            parent: Cell::new(None),
            child: [Cell::new(None), Cell::new(None)],
            linked: Cell::new(false),
            aux: Cell::new(0),
        }
    }

    /// Whether the element is currently in a tree.
    pub fn is_linked(&self) -> bool {
        self.linked.get()
    }
}

impl Default for TreeLink {
    fn default() -> Self {
        Self::new()
    }
}

/// An [`Adapter`] that also says how to order elements.
pub trait KeyAdapter<L>: Adapter<L> {
    /// The ordering key.
    type Key: Ord + ?Sized;

    /// The key of `value`. It must not change while `value` is in a tree.
    fn key(value: &Self::Value) -> &Self::Key;
}

// Every function below that takes a `NonNull<TreeLink>` relies on one
// invariant: the pointer is a node linked into a tree, and the contract of the
// tree's `insert` keeps linked elements valid and in place.

pub(super) fn rd<'a>(n: NonNull<TreeLink>) -> &'a TreeLink {
    // SAFETY: see the invariant above.
    unsafe { n.as_ref() }
}

fn val<'a, A: KeyAdapter<TreeLink>>(n: NonNull<TreeLink>) -> &'a A::Value {
    // SAFETY: see the invariant above.
    unsafe { value_of::<TreeLink, A>(n).as_ref() }
}

fn key_of<'a, A: KeyAdapter<TreeLink>>(n: NonNull<TreeLink>) -> &'a A::Key
where
    A::Value: 'a,
{
    A::key(val::<A>(n))
}

pub(super) fn parent(n: NonNull<TreeLink>) -> Ptr {
    rd(n).parent.get()
}

pub(super) fn child(n: NonNull<TreeLink>, dir: usize) -> Ptr {
    rd(n).child[dir].get()
}

pub(super) fn aux(n: NonNull<TreeLink>) -> i8 {
    rd(n).aux.get()
}

pub(super) fn set_aux(n: NonNull<TreeLink>, v: i8) {
    rd(n).aux.set(v);
}

/// Which side of `parent` the node `n` hangs on.
pub(super) fn dir_of(n: NonNull<TreeLink>, parent: NonNull<TreeLink>) -> usize {
    usize::from(child(parent, 1) == Some(n))
}

/// Makes `c` the child of `n` on side `dir` and fixes `c`'s parent.
pub(super) fn set_child(n: NonNull<TreeLink>, dir: usize, c: Ptr) {
    rd(n).child[dir].set(c);
    if let Some(c) = c {
        rd(c).parent.set(Some(n));
    }
}

/// Puts `new` where `old` hangs under `parent` (or at the root).
fn replace_child(root: &mut Ptr, parent: Ptr, old: NonNull<TreeLink>, new: Ptr) {
    match parent {
        Some(p) => set_child(p, dir_of(old, p), new),
        None => {
            *root = new;
            if let Some(n) = new {
                rd(n).parent.set(None);
            }
        }
    }
}

/// Per-node data derived from a node's subtree, refreshed whenever a
/// rotation changes what a node's subtree holds.
pub(super) trait Augment {
    /// Recomputes the data of `n` from its children, which must be current.
    fn update(n: NonNull<TreeLink>);
}

impl Augment for () {
    fn update(_: NonNull<TreeLink>) {}
}

/// Lifts the child of `x` on side `1 - dir` above `x`. `dir == 0` is a left rotation.
pub(super) fn rotate(root: &mut Ptr, x: NonNull<TreeLink>, dir: usize) {
    rotate_with::<()>(root, x, dir);
}

/// [`rotate`], then refreshes the two nodes whose subtrees changed.
pub(super) fn rotate_with<H: Augment>(root: &mut Ptr, x: NonNull<TreeLink>, dir: usize) {
    let y = child(x, 1 - dir).expect("rotation needs a child");
    replace_child(root, parent(x), x, Some(y));
    set_child(x, 1 - dir, child(y, dir));
    set_child(y, dir, Some(x));
    H::update(x);
    H::update(y);
}

/// The leftmost (`dir == 0`) or rightmost (`dir == 1`) node under `n`.
pub(super) fn extreme(mut n: NonNull<TreeLink>, dir: usize) -> NonNull<TreeLink> {
    while let Some(c) = child(n, dir) {
        n = c;
    }
    n
}

/// The in-order successor (`dir == 1`) or predecessor (`dir == 0`) of `n`.
pub(super) fn step(n: NonNull<TreeLink>, dir: usize) -> Ptr {
    if let Some(c) = child(n, dir) {
        return Some(extreme(c, 1 - dir));
    }
    let mut n = n;
    loop {
        let p = parent(n)?;
        if child(p, 1 - dir) == Some(n) {
            return Some(p);
        }
        n = p;
    }
}

/// Prepares `n` to be linked as a leaf with a zero `aux`.
pub(super) fn init_leaf(n: NonNull<TreeLink>) {
    reset(n);
    rd(n).linked.set(true);
}

fn reset(n: NonNull<TreeLink>) {
    let l = rd(n);
    l.parent.set(None);
    l.child[0].set(None);
    l.child[1].set(None);
    l.linked.set(false);
    l.aux.set(0);
}

/// Where a structural removal left a hole, for the rebalancing pass.
pub(super) struct Detached {
    /// Parent of the position whose subtree got shorter.
    pub parent: Ptr,
    /// Which side of `parent` that position is on.
    pub dir: usize,
    /// The node now at that position.
    pub child: Ptr,
    /// `aux` of the node that physically left its position: the removed
    /// node, or its successor when it had two children.
    pub aux: i8,
}

/// Unlinks `z` from the tree, keeping the search order.
pub(super) fn detach(root: &mut Ptr, z: NonNull<TreeLink>) -> Detached {
    let zp = parent(z);
    let (zl, zr) = (child(z, 0), child(z, 1));
    let out = if let (Some(_), Some(r)) = (zl, zr) {
        let y = extreme(r, 0);
        let c = child(y, 1);
        let out = if parent(y) == Some(z) {
            Detached { parent: Some(y), dir: 1, child: c, aux: aux(y) }
        } else {
            let yp = parent(y).expect("successor has a parent");
            set_child(yp, 0, c);
            set_child(y, 1, Some(r));
            Detached { parent: Some(yp), dir: 0, child: c, aux: aux(y) }
        };
        replace_child(root, zp, z, Some(y));
        set_child(y, 0, zl);
        set_aux(y, aux(z));
        out
    } else {
        let c = zl.or(zr);
        let out = Detached { parent: zp, dir: zp.map_or(0, |p| dir_of(z, p)), child: c, aux: aux(z) };
        replace_child(root, zp, z, c);
        out
    };
    reset(z);
    out
}

/// Unlinks every node of the tree at `root` in O(n) without rebalancing.
pub(super) fn clear_tree(root: &mut Ptr) {
    let mut cur = root.take();
    while let Some(n) = cur {
        if let Some(c) = child(n, 0).or(child(n, 1)) {
            cur = Some(c);
            continue;
        }
        cur = parent(n);
        if let Some(p) = cur {
            rd(p).child[dir_of(n, p)].set(None);
        }
        reset(n);
    }
}

/// The read-only half of [`RbTree`](super::rbtree::RbTree) and
/// [`AvlTree`](super::avltree::AvlTree): lookup, ordered traversal and size.
pub struct Bst<A: KeyAdapter<TreeLink>> {
    pub(super) root: Ptr,
    len: usize,
    _adapter: PhantomData<A>,
}

impl<A: KeyAdapter<TreeLink>> Bst<A> {
    pub(super) const fn new() -> Self {
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

    /// The element with the smallest key.
    pub fn first(&self) -> Option<&A::Value> {
        self.first_node().map(val::<A>)
    }

    /// The element with the largest key.
    pub fn last(&self) -> Option<&A::Value> {
        self.last_node().map(val::<A>)
    }

    /// The element whose key equals `key`.
    pub fn find(&self, key: &A::Key) -> Option<&A::Value> {
        self.find_node(key).map(val::<A>)
    }

    /// The element with the smallest key that is `>= key`.
    pub fn lower_bound(&self, key: &A::Key) -> Option<&A::Value> {
        let (mut cur, mut best) = (self.root, None);
        while let Some(n) = cur {
            if key <= key_of::<A>(n) {
                best = cur;
                cur = child(n, 0);
            } else {
                cur = child(n, 1);
            }
        }
        best.map(val::<A>)
    }

    /// The element with the largest key that is `<= key`.
    pub fn floor(&self, key: &A::Key) -> Option<&A::Value> {
        let (mut cur, mut best) = (self.root, None);
        while let Some(n) = cur {
            if key_of::<A>(n) <= key {
                best = cur;
                cur = child(n, 1);
            } else {
                cur = child(n, 0);
            }
        }
        best.map(val::<A>)
    }

    /// Iterates in ascending key order.
    pub fn iter(&self) -> TreeIter<'_, A> {
        TreeIter { next: self.first_node(), _tree: PhantomData }
    }

    pub(super) fn find_node(&self, key: &A::Key) -> Ptr {
        let mut cur = self.root;
        while let Some(n) = cur {
            cur = match key.cmp(key_of::<A>(n)) {
                Ordering::Equal => return cur,
                Ordering::Less => child(n, 0),
                Ordering::Greater => child(n, 1),
            };
        }
        None
    }

    pub(super) fn first_node(&self) -> Ptr {
        self.root.map(|r| extreme(r, 0))
    }

    pub(super) fn last_node(&self) -> Ptr {
        self.root.map(|r| extreme(r, 1))
    }

    /// Links `value` as a leaf with `aux == 0`, or returns `None` if the key
    /// is already present.
    ///
    /// # Safety
    ///
    /// `value` must be valid and stay valid and in place while linked.
    ///
    /// # Panics
    ///
    /// If `value` is already linked.
    pub(super) unsafe fn attach(&mut self, value: NonNull<A::Value>) -> Option<NonNull<TreeLink>> {
        let link = link_of::<TreeLink, A>(value);
        assert!(!rd(link).linked.get(), "element already linked");
        // SAFETY: the caller guarantees `value` is valid.
        let key = A::key(unsafe { value.as_ref() });
        let (mut parent, mut dir, mut cur) = (None, 0, self.root);
        while let Some(n) = cur {
            parent = cur;
            dir = match key.cmp(key_of::<A>(n)) {
                Ordering::Equal => return None,
                Ordering::Less => 0,
                Ordering::Greater => 1,
            };
            cur = child(n, dir);
        }
        init_leaf(link);
        match parent {
            Some(p) => set_child(p, dir, Some(link)),
            None => self.root = Some(link),
        }
        self.len += 1;
        Some(link)
    }

    /// Structurally unlinks `link`, which must be in this tree.
    pub(super) fn detach_node(&mut self, link: NonNull<TreeLink>) -> Detached {
        self.len -= 1;
        detach(&mut self.root, link)
    }

    pub(super) fn value(link: NonNull<TreeLink>) -> NonNull<A::Value> {
        value_of::<TreeLink, A>(link)
    }

    pub(super) fn link(value: NonNull<A::Value>) -> NonNull<TreeLink> {
        link_of::<TreeLink, A>(value)
    }

    /// Unlinks every element in O(n) without rebalancing.
    pub(super) fn clear(&mut self) {
        clear_tree(&mut self.root);
        self.len = 0;
    }
}

impl<A: KeyAdapter<TreeLink>> Drop for Bst<A> {
    /// Unlinks the remaining elements so their hooks do not dangle.
    fn drop(&mut self) {
        self.clear();
    }
}

/// Ascending-order iterator over a tree.
pub struct TreeIter<'tree, A: KeyAdapter<TreeLink>> {
    next: Ptr,
    _tree: PhantomData<(&'tree Bst<A>, A)>,
}

impl<'tree, A: KeyAdapter<TreeLink>> Iterator for TreeIter<'tree, A> {
    type Item = &'tree A::Value;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.next?;
        self.next = step(n, 1);
        Some(val::<A>(n))
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;
    use core::mem::offset_of;
    use std::collections::BTreeSet;
    use std::vec::Vec;

    pub struct TestNode {
        pub key: u32,
        pub link: TreeLink,
    }

    pub struct ByKey;
    // SAFETY: `offset_of!` of the `TreeLink` field.
    unsafe impl Adapter<TreeLink> for ByKey {
        type Value = TestNode;
        const OFFSET: usize = offset_of!(TestNode, link);
    }
    impl KeyAdapter<TreeLink> for ByKey {
        type Key = u32;
        fn key(v: &TestNode) -> &u32 {
            &v.key
        }
    }

    pub fn nodes(keys: impl Iterator<Item = u32>) -> Vec<TestNode> {
        keys.map(|key| TestNode { key, link: TreeLink::new() }).collect()
    }

    pub fn key_at(p: NonNull<TestNode>) -> u32 {
        // SAFETY: tests only pass pointers into live node vectors.
        unsafe { p.as_ref().key }
    }

    /// The operations the shared fuzz test needs from a tree.
    pub trait Harness {
        fn insert(&mut self, v: NonNull<TestNode>) -> bool;
        fn remove(&mut self, v: NonNull<TestNode>) -> bool;
        fn take(&mut self, key: u32) -> Option<NonNull<TestNode>>;
        fn pop_first(&mut self) -> Option<NonNull<TestNode>>;
        fn pop_last(&mut self) -> Option<NonNull<TestNode>>;
        fn view(&self) -> &Bst<ByKey>;
        /// Asserts the tree's own balance invariants.
        fn check(&self);
    }

    /// Asserts the parent links, search order and element count.
    pub fn check_structure(t: &Bst<ByKey>) {
        fn walk(n: NonNull<TreeLink>, up: Ptr, lo: Option<u32>, hi: Option<u32>) -> usize {
            assert_eq!(parent(n), up);
            assert!(rd(n).is_linked());
            let k = *key_of::<ByKey>(n);
            assert!(lo.is_none_or(|lo| k > lo) && hi.is_none_or(|hi| k < hi));
            let l = child(n, 0).map_or(0, |c| walk(c, Some(n), lo, Some(k)));
            let r = child(n, 1).map_or(0, |c| walk(c, Some(n), Some(k), hi));
            1 + l + r
        }
        let count = t.root.map_or(0, |r| walk(r, None, None, None));
        assert_eq!(count, t.len());
    }

    pub fn fuzz<T: Harness>(mut t: T) {
        let ns = nodes(0..200);
        let mut model = BTreeSet::new();
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut rng = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 16) as u32
        };
        for _ in 0..6000 {
            let id = rng() % 200;
            match rng() % 16 {
                0 => assert_eq!(t.pop_first().map(key_at), model.pop_first()),
                1 => assert_eq!(t.pop_last().map(key_at), model.pop_last()),
                _ if model.contains(&id) => {
                    model.remove(&id);
                    if rng() % 2 == 0 {
                        assert!(t.remove(NonNull::from(&ns[id as usize])));
                    } else {
                        assert_eq!(t.take(id), Some(NonNull::from(&ns[id as usize])));
                    }
                    assert!(!ns[id as usize].link.is_linked());
                }
                _ => {
                    model.insert(id);
                    assert!(t.insert(NonNull::from(&ns[id as usize])));
                }
            }
            t.check();
            let v = t.view();
            assert_eq!(v.len(), model.len());
            assert!(v.iter().map(|n| n.key).eq(model.iter().copied()));
            assert_eq!(v.first().map(|n| n.key), model.first().copied());
            assert_eq!(v.last().map(|n| n.key), model.last().copied());
            let q = rng() % 210;
            assert_eq!(v.find(&q).map(|n| n.key), model.get(&q).copied());
            assert_eq!(v.lower_bound(&q).map(|n| n.key), model.range(q..).next().copied());
            assert_eq!(v.floor(&q).map(|n| n.key), model.range(..=q).next_back().copied());
        }
    }

    /// Duplicate keys are rejected and leave the rejected element unlinked;
    /// dropping the tree unlinks the rest.
    pub fn duplicate_and_drop<T: Harness>(mut t: T) -> (Vec<TestNode>, Vec<TestNode>) {
        let (a, b) = (nodes(0..8), nodes(4..12));
        for n in &a {
            assert!(t.insert(NonNull::from(n)));
        }
        for n in &b {
            assert_eq!(t.insert(NonNull::from(n)), n.key >= 8);
        }
        assert!(!b[0].link.is_linked());
        t.check();
        drop(t);
        (a, b)
    }
}
