//! Intrusive collections of `Arc`s: the list or tree owns one strong
//! reference to each element it links, and linking never allocates.
//!
//! The links live in the elements (see [`crate::intrusive`]), so putting an
//! element in a collection cannot run out of memory. Create the `Arc` first,
//! where a failure can be reported (see [`crate::fallible`]), and link it
//! later, where it cannot.
//!
//! An element can be in only one collection per link it embeds; linking it
//! twice panics. Neither collection locks: keep one behind a lock, and drop
//! what it hands back (a last reference may free the element) after releasing
//! it.

use alloc::sync::Arc;
use core::ptr::NonNull;

use crate::intrusive::rbtree::RbTree;
use crate::intrusive::{Adapter, KeyAdapter, Link, List, TreeLink};

/// Hands an element's reference to a collection.
fn into_ptr<T>(value: Arc<T>) -> NonNull<T> {
    // SAFETY: `Arc::into_raw` never returns null.
    unsafe { NonNull::new_unchecked(Arc::into_raw(value).cast_mut()) }
}

/// Takes back a reference given with `into_ptr`.
///
/// # Safety
/// `ptr` must have come from `into_ptr`, and been unlinked since.
unsafe fn from_ptr<T>(ptr: NonNull<T>) -> Arc<T> {
    // SAFETY: forwarded contract.
    unsafe { Arc::from_raw(ptr.as_ptr()) }
}

/// A list of `Arc<A::Value>`, linked through the [`Link`] that `A` locates.
pub struct ArcList<A: Adapter<Link>> {
    list: List<A>,
}

// SAFETY: the list holds `Arc`s of values that `push_back` requires to be
// `Send + Sync`, and the links it threads through them are only touched
// through `&mut self` or `&self` of this one list (so under whatever lock
// wraps it). The bound is on `push_back`, not here, so that an element may
// hold a list of its own kind (a process's children).
unsafe impl<A: Adapter<Link>> Send for ArcList<A> {}
// SAFETY: the methods that take `&self` only read the links (and take an
// atomic reference count), so any number of threads may call them at once.
unsafe impl<A: Adapter<Link>> Sync for ArcList<A> {}

impl<A: Adapter<Link>> ArcList<A> {
    /// An empty list.
    pub const fn new() -> Self {
        Self { list: List::new() }
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether the list has no elements.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Links `value` at the back, keeping a reference to it.
    ///
    /// # Panics
    /// If `value` is already linked through this link.
    pub fn push_back(&mut self, value: Arc<A::Value>)
    where
        A::Value: Send + Sync,
    {
        // SAFETY: the list's reference keeps the element alive and in place
        // until it is handed back.
        unsafe { self.list.push_back(into_ptr(value)) }
    }

    /// Unlinks and returns the first element.
    pub fn pop_front(&mut self) -> Option<Arc<A::Value>> {
        // SAFETY: linked elements came from `into_ptr`.
        self.list.pop_front().map(|p| unsafe { from_ptr(p) })
    }

    /// Unlinks `value` and returns the list's reference to it, or `None` if
    /// it was not linked.
    ///
    /// # Safety
    /// If `value` is linked, it must be linked in this list.
    pub unsafe fn remove(&mut self, value: &Arc<A::Value>) -> Option<Arc<A::Value>> {
        let ptr = NonNull::from(&**value);
        // SAFETY: forwarded contract.
        if unsafe { self.list.remove(ptr) } {
            // SAFETY: the element was linked, so the list held a reference.
            Some(unsafe { from_ptr(ptr) })
        } else {
            None
        }
    }

    /// Unlinks the first element for which `pred` holds.
    pub fn remove_first_where(&mut self, pred: impl FnMut(&A::Value) -> bool) -> Option<Arc<A::Value>> {
        let ptr = self.list.find_ptr(pred)?;
        // SAFETY: linked in this list, and came from `into_ptr`.
        unsafe {
            self.list.remove(ptr);
            Some(from_ptr(ptr))
        }
    }

    /// Unlinks the last element for which `pred` holds.
    pub fn remove_last_where(&mut self, pred: impl FnMut(&A::Value) -> bool) -> Option<Arc<A::Value>> {
        let ptr = self.list.rfind_ptr(pred)?;
        // SAFETY: as in `remove_first_where`.
        unsafe {
            self.list.remove(ptr);
            Some(from_ptr(ptr))
        }
    }

    /// A new reference to the first element for which `pred` holds.
    pub fn clone_first_where(&self, pred: impl FnMut(&A::Value) -> bool) -> Option<Arc<A::Value>> {
        let ptr = self.list.find_ptr(pred)?;
        // SAFETY: linked elements came from `into_ptr` and are kept alive by
        // the list's own reference, which this adds to rather than takes.
        unsafe {
            Arc::increment_strong_count(ptr.as_ptr());
            Some(from_ptr(ptr))
        }
    }

    /// The elements, front to back.
    pub fn iter(&self) -> impl Iterator<Item = &A::Value> {
        self.list.iter()
    }

    /// Moves every element into a new list, leaving this one empty.
    pub fn take(&mut self) -> Self {
        core::mem::take(self)
    }
}

impl<A: Adapter<Link>> Default for ArcList<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Adapter<Link>> Drop for ArcList<A> {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

/// An ordered set of `Arc<A::Value>`, linked through the [`TreeLink`] that
/// `A` locates, keyed as `A` says. A key must not change while its element
/// is in the tree.
pub struct ArcTree<A: KeyAdapter<TreeLink>> {
    tree: RbTree<A>,
}

// SAFETY: as for `ArcList`; `insert` has the bound.
unsafe impl<A: KeyAdapter<TreeLink>> Send for ArcTree<A> {}
// SAFETY: as for `ArcList`.
unsafe impl<A: KeyAdapter<TreeLink>> Sync for ArcTree<A> {}

impl<A: KeyAdapter<TreeLink>> ArcTree<A> {
    /// An empty tree.
    pub const fn new() -> Self {
        Self { tree: RbTree::new() }
    }

    /// Number of elements.
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Whether the tree has no elements.
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Links `value`, keeping a reference to it. If an element with the same
    /// key is already there, gives `value` back.
    ///
    /// # Panics
    /// If `value` is already linked through this link.
    pub fn insert(&mut self, value: Arc<A::Value>) -> Result<(), Arc<A::Value>>
    where
        A::Value: Send + Sync,
    {
        let ptr = into_ptr(value);
        // SAFETY: the tree's reference keeps the element alive and in place
        // until it is handed back.
        if unsafe { self.tree.insert(ptr) } {
            Ok(())
        } else {
            // SAFETY: it was not linked, so the reference is still ours.
            Err(unsafe { from_ptr(ptr) })
        }
    }

    /// The element with the smallest key.
    pub fn first(&self) -> Option<&A::Value> {
        self.tree.first()
    }

    /// The element whose key equals `key`.
    pub fn find(&self, key: &A::Key) -> Option<&A::Value> {
        self.tree.find(key)
    }

    /// The element with the largest key that is `<= key`.
    pub fn floor(&self, key: &A::Key) -> Option<&A::Value> {
        self.tree.floor(key)
    }

    /// The element with the smallest key that is `>= key`.
    pub fn lower_bound(&self, key: &A::Key) -> Option<&A::Value> {
        self.tree.lower_bound(key)
    }

    /// A new reference to the element whose key equals `key`.
    pub fn clone_key(&self, key: &A::Key) -> Option<Arc<A::Value>> {
        let ptr = self.tree.find_key_ptr(key)?;
        // SAFETY: as in `ArcList::clone_first_where`.
        unsafe {
            Arc::increment_strong_count(ptr.as_ptr());
            Some(from_ptr(ptr))
        }
    }

    /// Unlinks and returns the element with the smallest key.
    pub fn pop_first(&mut self) -> Option<Arc<A::Value>> {
        // SAFETY: linked elements came from `into_ptr`.
        self.tree.pop_first().map(|p| unsafe { from_ptr(p) })
    }

    /// Unlinks and returns the element whose key equals `key`.
    pub fn take_key(&mut self, key: &A::Key) -> Option<Arc<A::Value>> {
        // SAFETY: as in `pop_first`.
        self.tree.take(key).map(|p| unsafe { from_ptr(p) })
    }

    /// Unlinks the first element, in key order, for which `pred` holds.
    pub fn remove_first_where(&mut self, pred: impl FnMut(&A::Value) -> bool) -> Option<Arc<A::Value>> {
        let ptr = self.tree.find_ptr(pred)?;
        // SAFETY: linked in this tree, and came from `into_ptr`.
        unsafe {
            self.tree.remove(ptr);
            Some(from_ptr(ptr))
        }
    }

    /// The elements in key order.
    pub fn iter(&self) -> impl Iterator<Item = &A::Value> {
        self.tree.iter()
    }

    /// Drops every element.
    pub fn clear(&mut self) {
        while self.pop_first().is_some() {}
    }
}

impl<A: KeyAdapter<TreeLink>> Default for ArcTree<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: KeyAdapter<TreeLink>> Drop for ArcTree<A> {
    fn drop(&mut self) {
        while self.pop_first().is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intrusive::Shared;
    use core::mem::offset_of;

    struct Node {
        key: u32,
        link: Shared<Link>,
        tree: Shared<TreeLink>,
    }

    struct ByLink;
    // SAFETY: `offset_of!` of the `Link` field.
    unsafe impl Adapter<Link> for ByLink {
        type Value = Node;
        const OFFSET: usize = offset_of!(Node, link);
    }

    struct ByKey;
    // SAFETY: `offset_of!` of the `TreeLink` field.
    unsafe impl Adapter<TreeLink> for ByKey {
        type Value = Node;
        const OFFSET: usize = offset_of!(Node, tree);
    }
    impl KeyAdapter<TreeLink> for ByKey {
        type Key = u32;
        fn key(n: &Node) -> &u32 {
            &n.key
        }
    }

    fn node(key: u32) -> Arc<Node> {
        Arc::new(Node { key, link: Shared::new(Link::new()), tree: Shared::new(TreeLink::new()) })
    }

    // SAFETY (tests): every `Node` is linked in only the one list under test.

    #[test]
    fn a_list_owns_one_reference_per_element() {
        let (a, b, c) = (node(1), node(2), node(3));
        let mut l = ArcList::<ByLink>::new();
        for n in [&a, &b, &c] {
            l.push_back(n.clone());
        }
        assert_eq!((l.len(), Arc::strong_count(&a)), (3, 2));
        assert!(Arc::ptr_eq(&l.pop_front().unwrap(), &a));
        assert_eq!(Arc::strong_count(&a), 1);
        // SAFETY: `b` is in `l`; `a` is in no list.
        let (gone_b, gone_a) = unsafe { (l.remove(&b), l.remove(&a)) };
        assert!(Arc::ptr_eq(&gone_b.unwrap(), &b) && gone_a.is_none());
        assert_eq!(l.iter().map(|n| n.key).collect::<alloc::vec::Vec<_>>(), [3]);
        assert!(l.remove_last_where(|n| n.key > 9).is_none());
        drop(l);
        assert_eq!(Arc::strong_count(&c), 1, "dropping the list releases its elements");
        assert!(!c.link.is_linked());
    }

    #[test]
    fn a_list_searches_from_either_end_and_moves_out() {
        let ns: alloc::vec::Vec<_> = (0..4).map(node).collect();
        let mut l = ArcList::<ByLink>::new();
        for n in &ns {
            l.push_back(n.clone());
        }
        assert_eq!(l.remove_first_where(|n| n.key % 2 == 1).unwrap().key, 1);
        assert_eq!(l.remove_last_where(|n| n.key % 2 == 1).unwrap().key, 3);
        let mut moved = l.take();
        assert!(l.is_empty() && moved.len() == 2);
        let two = moved.clone_first_where(|n| n.key == 2).unwrap();
        assert_eq!(Arc::strong_count(&two), 3, "the list's, the vec's and the clone");
        assert_eq!(moved.pop_front().unwrap().key, 0);
    }

    #[test]
    #[should_panic(expected = "already linked")]
    fn linking_twice_panics() {
        let a = node(1);
        let mut l = ArcList::<ByLink>::new();
        l.push_back(a.clone());
        l.push_back(a);
    }

    #[test]
    fn a_tree_orders_by_key_and_rejects_duplicates() {
        let mut t = ArcTree::<ByKey>::new();
        let (a, b, c) = (node(5), node(2), node(9));
        for n in [&a, &b, &c] {
            assert!(t.insert(n.clone()).is_ok());
        }
        let dup = node(5);
        let back = t.insert(dup.clone()).unwrap_err();
        assert!(Arc::ptr_eq(&back, &dup) && !dup.tree.is_linked());
        assert_eq!(t.first().unwrap().key, 2);
        assert_eq!(t.find(&5).unwrap().key, 5);
        let held = t.clone_key(&5).unwrap();
        assert_eq!((held.key, Arc::strong_count(&held)), (5, 3));
        drop(held);
        assert!(Arc::ptr_eq(&t.take_key(&5).unwrap(), &a));
        assert_eq!(t.remove_first_where(|n| n.key > 2).unwrap().key, 9);
        assert_eq!(t.iter().map(|n| n.key).collect::<alloc::vec::Vec<_>>(), [2]);
        drop(t);
        assert_eq!(Arc::strong_count(&b), 1);
        assert!(!b.tree.is_linked());
    }
}
