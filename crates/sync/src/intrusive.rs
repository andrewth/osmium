//! Intrusive linked lists and search trees: the links live inside the
//! elements, so inserting and removing never allocates.
//!
//! An element embeds a [`Link`] (doubly linked, for [`List`]) or an
//! [`SLink`] (singly linked, for [`SList`]) and tells the list where to find
//! it with an [`Adapter`]. The lists do not own their elements: the caller
//! keeps each element alive and at a fixed address while it is linked.
//! [`RbTree`](rbtree::RbTree) and [`AvlTree`](avltree::AvlTree) are ordered sets over
//! elements that embed a [`TreeLink`] and name their key with a [`KeyAdapter`].
//! [`IntervalTree`](interval::IntervalTree) finds the elements whose `u64` ranges overlap a
//! query range. None of the collections does any locking; wrap one in a [`SpinLock`](crate::SpinLock)
//! to share one.

pub mod avltree;
mod bst;
pub mod interval;
pub mod rbtree;

pub use bst::{Bst, KeyAdapter, TreeIter, TreeLink};

use core::cell::Cell;
use core::marker::PhantomData;
use core::ptr::NonNull;

/// Describes where the link of type `L` sits inside a `Value`.
///
/// # Safety
///
/// `OFFSET` must be the byte offset of an `L` field inside `Value`
/// (use [`core::mem::offset_of!`]).
pub unsafe trait Adapter<L> {
    /// The element type that embeds the link.
    type Value;
    /// Byte offset of the link within `Value`.
    const OFFSET: usize;
}

fn link_of<L, A: Adapter<L>>(value: NonNull<A::Value>) -> NonNull<L> {
    // SAFETY: the adapter guarantees the link lies inside the value.
    unsafe { value.byte_add(A::OFFSET).cast() }
}

fn value_of<L, A: Adapter<L>>(link: NonNull<L>) -> NonNull<A::Value> {
    // SAFETY: inverse of `link_of`; the link was derived from a value.
    unsafe { link.byte_sub(A::OFFSET).cast() }
}

/// Doubly linked list hook. Embed one in each element of a [`List`].
pub struct Link {
    prev: Cell<Option<NonNull<Link>>>,
    next: Cell<Option<NonNull<Link>>>,
    linked: Cell<bool>,
}

impl Link {
    /// Creates an unlinked hook.
    pub const fn new() -> Self {
        Self { prev: Cell::new(None), next: Cell::new(None), linked: Cell::new(false) }
    }

    /// Whether the element is currently in a list.
    pub fn is_linked(&self) -> bool {
        self.linked.get()
    }
}

impl Default for Link {
    fn default() -> Self {
        Self::new()
    }
}

/// An intrusive doubly linked list with O(1) insertion and removal at any
/// known element.
pub struct List<A: Adapter<Link>> {
    head: Option<NonNull<Link>>,
    tail: Option<NonNull<Link>>,
    len: usize,
    _adapter: PhantomData<A>,
}

impl<A: Adapter<Link>> List<A> {
    /// Creates an empty list.
    pub const fn new() -> Self {
        Self { head: None, tail: None, len: 0, _adapter: PhantomData }
    }

    /// Whether the list has no elements.
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// Number of linked elements.
    pub fn len(&self) -> usize {
        self.len
    }

    /// The first element.
    pub fn front(&self) -> Option<&A::Value> {
        // SAFETY: linked elements are live by the `push_*` contract.
        self.head.map(|l| unsafe { value_of::<Link, A>(l).as_ref() })
    }

    /// The last element.
    pub fn back(&self) -> Option<&A::Value> {
        // SAFETY: as in `front`.
        self.tail.map(|l| unsafe { value_of::<Link, A>(l).as_ref() })
    }

    /// Links `value` at the front.
    ///
    /// # Safety
    ///
    /// `value` must stay valid and must not move until it is removed from the
    /// list or the list is dropped or cleared.
    ///
    /// # Panics
    ///
    /// If `value` is already linked.
    pub unsafe fn push_front(&mut self, value: NonNull<A::Value>) {
        let link = link_of::<Link, A>(value);
        // SAFETY: the caller guarantees `value` is valid.
        let l = unsafe { link.as_ref() };
        assert!(!l.linked.replace(true), "element already linked");
        l.prev.set(None);
        l.next.set(self.head);
        match self.head {
            // SAFETY: linked elements are valid.
            Some(h) => unsafe { h.as_ref() }.prev.set(Some(link)),
            None => self.tail = Some(link),
        }
        self.head = Some(link);
        self.len += 1;
    }

    /// Links `value` at the back.
    ///
    /// # Safety
    ///
    /// Same as [`push_front`](Self::push_front).
    ///
    /// # Panics
    ///
    /// If `value` is already linked.
    pub unsafe fn push_back(&mut self, value: NonNull<A::Value>) {
        let link = link_of::<Link, A>(value);
        // SAFETY: the caller guarantees `value` is valid.
        let l = unsafe { link.as_ref() };
        assert!(!l.linked.replace(true), "element already linked");
        l.next.set(None);
        l.prev.set(self.tail);
        match self.tail {
            // SAFETY: linked elements are valid.
            Some(t) => unsafe { t.as_ref() }.next.set(Some(link)),
            None => self.head = Some(link),
        }
        self.tail = Some(link);
        self.len += 1;
    }

    /// Unlinks and returns the first element.
    pub fn pop_front(&mut self) -> Option<NonNull<A::Value>> {
        let v = value_of::<Link, A>(self.head?);
        // SAFETY: the element is linked in `self`.
        unsafe { self.remove(v) };
        Some(v)
    }

    /// Unlinks and returns the last element.
    pub fn pop_back(&mut self) -> Option<NonNull<A::Value>> {
        let v = value_of::<Link, A>(self.tail?);
        // SAFETY: the element is linked in `self`.
        unsafe { self.remove(v) };
        Some(v)
    }

    /// Unlinks `value`, returning whether it was linked.
    ///
    /// # Safety
    ///
    /// If `value` is linked, it must be linked in `self` and not in another
    /// list.
    pub unsafe fn remove(&mut self, value: NonNull<A::Value>) -> bool {
        let link = link_of::<Link, A>(value);
        // SAFETY: the caller guarantees `value` is valid.
        let l = unsafe { link.as_ref() };
        if !l.linked.replace(false) {
            return false;
        }
        let (prev, next) = (l.prev.take(), l.next.take());
        match prev {
            // SAFETY: linked neighbours are valid.
            Some(p) => unsafe { p.as_ref() }.next.set(next),
            None => self.head = next,
        }
        match next {
            // SAFETY: as above.
            Some(n) => unsafe { n.as_ref() }.prev.set(prev),
            None => self.tail = prev,
        }
        self.len -= 1;
        true
    }

    /// Unlinks every element.
    pub fn clear(&mut self) {
        while self.pop_front().is_some() {}
    }

    /// Iterates from front to back.
    pub fn iter(&self) -> Iter<'_, A> {
        Iter { next: self.head, _list: PhantomData }
    }
}

impl<A: Adapter<Link>> Default for List<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Adapter<Link>> Drop for List<A> {
    /// Unlinks the remaining elements so their hooks do not dangle.
    fn drop(&mut self) {
        self.clear();
    }
}

/// Front-to-back iterator over a [`List`].
pub struct Iter<'list, A: Adapter<Link>> {
    next: Option<NonNull<Link>>,
    _list: PhantomData<(&'list List<A>, A)>,
}

impl<'list, A: Adapter<Link>> Iterator for Iter<'list, A> {
    type Item = &'list A::Value;

    fn next(&mut self) -> Option<Self::Item> {
        let link = self.next?;
        // SAFETY: the list is borrowed for `'list`, so its elements are linked and valid.
        unsafe {
            self.next = link.as_ref().next.get();
            Some(value_of::<Link, A>(link).as_ref())
        }
    }
}

/// Singly linked list hook. Embed one in each element of an [`SList`].
pub struct SLink {
    next: Cell<Option<NonNull<SLink>>>,
    linked: Cell<bool>,
}

impl SLink {
    /// Creates an unlinked hook.
    pub const fn new() -> Self {
        Self { next: Cell::new(None), linked: Cell::new(false) }
    }

    /// Whether the element is currently in a list.
    pub fn is_linked(&self) -> bool {
        self.linked.get()
    }
}

impl Default for SLink {
    fn default() -> Self {
        Self::new()
    }
}

/// An intrusive singly linked stack: O(1) push and pop at the front, O(n)
/// removal of an arbitrary element.
pub struct SList<A: Adapter<SLink>> {
    head: Option<NonNull<SLink>>,
    _adapter: PhantomData<A>,
}

impl<A: Adapter<SLink>> SList<A> {
    /// Creates an empty list.
    pub const fn new() -> Self {
        Self { head: None, _adapter: PhantomData }
    }

    /// Whether the list has no elements.
    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// The first element.
    pub fn front(&self) -> Option<&A::Value> {
        // SAFETY: linked elements are live by the `push_front` contract.
        self.head.map(|l| unsafe { value_of::<SLink, A>(l).as_ref() })
    }

    /// Links `value` at the front.
    ///
    /// # Safety
    ///
    /// `value` must stay valid and must not move until it is removed from the
    /// list or the list is dropped or cleared.
    ///
    /// # Panics
    ///
    /// If `value` is already linked.
    pub unsafe fn push_front(&mut self, value: NonNull<A::Value>) {
        let link = link_of::<SLink, A>(value);
        // SAFETY: the caller guarantees `value` is valid.
        let l = unsafe { link.as_ref() };
        assert!(!l.linked.replace(true), "element already linked");
        l.next.set(self.head);
        self.head = Some(link);
    }

    /// Unlinks and returns the first element.
    pub fn pop_front(&mut self) -> Option<NonNull<A::Value>> {
        let link = self.head?;
        // SAFETY: linked elements are valid.
        let l = unsafe { link.as_ref() };
        self.head = l.next.take();
        l.linked.set(false);
        Some(value_of::<SLink, A>(link))
    }

    /// Unlinks `value` if it is in this list, walking from the front.
    ///
    /// # Safety
    ///
    /// `value` must be valid.
    pub unsafe fn remove(&mut self, value: NonNull<A::Value>) -> bool {
        let target = link_of::<SLink, A>(value);
        let mut prev: Option<NonNull<SLink>> = None;
        let mut cur = self.head;
        while let Some(c) = cur {
            // SAFETY: linked elements are valid.
            let cl = unsafe { c.as_ref() };
            if c == target {
                match prev {
                    // SAFETY: as above.
                    Some(p) => unsafe { p.as_ref() }.next.set(cl.next.get()),
                    None => self.head = cl.next.get(),
                }
                cl.next.set(None);
                cl.linked.set(false);
                return true;
            }
            prev = cur;
            cur = cl.next.get();
        }
        false
    }

    /// Unlinks every element.
    pub fn clear(&mut self) {
        while self.pop_front().is_some() {}
    }

    /// Iterates from front to back.
    pub fn iter(&self) -> SIter<'_, A> {
        SIter { next: self.head, _list: PhantomData }
    }
}

impl<A: Adapter<SLink>> Default for SList<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Adapter<SLink>> Drop for SList<A> {
    /// Unlinks the remaining elements so their hooks do not dangle.
    fn drop(&mut self) {
        self.clear();
    }
}

/// Front-to-back iterator over an [`SList`].
pub struct SIter<'list, A: Adapter<SLink>> {
    next: Option<NonNull<SLink>>,
    _list: PhantomData<(&'list SList<A>, A)>,
}

impl<'list, A: Adapter<SLink>> Iterator for SIter<'list, A> {
    type Item = &'list A::Value;

    fn next(&mut self) -> Option<Self::Item> {
        let link = self.next?;
        // SAFETY: the list is borrowed for `'list`, so its elements are linked and valid.
        unsafe {
            self.next = link.as_ref().next.get();
            Some(value_of::<SLink, A>(link).as_ref())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::offset_of;
    use std::vec::Vec;

    struct Node {
        id: u32,
        link: Link,
        slink: SLink,
    }

    struct ByLink;
    // SAFETY: `offset_of!` of the `Link` field.
    unsafe impl Adapter<Link> for ByLink {
        type Value = Node;
        const OFFSET: usize = offset_of!(Node, link);
    }

    struct BySLink;
    // SAFETY: `offset_of!` of the `SLink` field.
    unsafe impl Adapter<SLink> for BySLink {
        type Value = Node;
        const OFFSET: usize = offset_of!(Node, slink);
    }

    fn nodes(n: u32) -> Vec<Node> {
        (0..n).map(|id| Node { id, link: Link::new(), slink: SLink::new() }).collect()
    }

    fn ids<'a>(it: impl Iterator<Item = &'a Node>) -> Vec<u32> {
        it.map(|n| n.id).collect()
    }

    #[test]
    fn list_push_pop_order() {
        let ns = nodes(4);
        let mut l = List::<ByLink>::new();
        // SAFETY: `ns` outlives `l` and is not moved.
        unsafe {
            l.push_back(NonNull::from(&ns[1]));
            l.push_back(NonNull::from(&ns[2]));
            l.push_front(NonNull::from(&ns[0]));
            l.push_back(NonNull::from(&ns[3]));
        }
        assert_eq!(l.len(), 4);
        assert_eq!(ids(l.iter()), [0, 1, 2, 3]);
        assert_eq!(l.front().unwrap().id, 0);
        assert_eq!(l.back().unwrap().id, 3);
        // SAFETY: the popped pointers are into `ns`.
        unsafe {
            assert_eq!(l.pop_front().unwrap().as_ref().id, 0);
            assert_eq!(l.pop_back().unwrap().as_ref().id, 3);
        }
        assert_eq!(ids(l.iter()), [1, 2]);
        assert!(!ns[0].link.is_linked());
    }

    #[test]
    fn list_remove_middle_and_ends() {
        let ns = nodes(3);
        let mut l = List::<ByLink>::new();
        // SAFETY: `ns` outlives `l` and is not moved.
        unsafe {
            for n in &ns {
                l.push_back(NonNull::from(n));
            }
            assert!(l.remove(NonNull::from(&ns[1])));
            assert!(!l.remove(NonNull::from(&ns[1])));
            assert_eq!(ids(l.iter()), [0, 2]);
            assert!(l.remove(NonNull::from(&ns[0])));
            assert!(l.remove(NonNull::from(&ns[2])));
        }
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
        assert!(l.pop_front().is_none());
    }

    #[test]
    #[should_panic(expected = "already linked")]
    fn list_double_push_panics() {
        let ns = nodes(1);
        let mut l = List::<ByLink>::new();
        // SAFETY: `ns` outlives `l`.
        unsafe {
            l.push_back(NonNull::from(&ns[0]));
            l.push_back(NonNull::from(&ns[0]));
        }
    }

    #[test]
    fn list_drop_unlinks() {
        let ns = nodes(2);
        {
            let mut l = List::<ByLink>::new();
            // SAFETY: `ns` outlives `l`.
            unsafe {
                l.push_back(NonNull::from(&ns[0]));
                l.push_back(NonNull::from(&ns[1]));
            }
            assert!(ns[0].link.is_linked());
        }
        assert!(!ns[0].link.is_linked() && !ns[1].link.is_linked());
    }

    #[test]
    fn element_in_two_lists_via_different_links() {
        let ns = nodes(2);
        let mut a = List::<ByLink>::new();
        let mut b = SList::<BySLink>::new();
        // SAFETY: `ns` outlives both lists.
        unsafe {
            for n in &ns {
                a.push_back(NonNull::from(n));
                b.push_front(NonNull::from(n));
            }
        }
        assert_eq!(ids(a.iter()), [0, 1]);
        assert_eq!(ids(b.iter()), [1, 0]);
    }

    #[test]
    fn slist_push_pop_remove() {
        let ns = nodes(4);
        let mut s = SList::<BySLink>::new();
        // SAFETY: `ns` outlives `s` and is not moved.
        unsafe {
            for n in &ns {
                s.push_front(NonNull::from(n));
            }
            assert_eq!(ids(s.iter()), [3, 2, 1, 0]);
            assert!(s.remove(NonNull::from(&ns[2])));
            assert!(s.remove(NonNull::from(&ns[3])));
            assert!(s.remove(NonNull::from(&ns[0])));
            assert!(!s.remove(NonNull::from(&ns[0])));
        }
        assert_eq!(ids(s.iter()), [1]);
        assert_eq!(s.front().unwrap().id, 1);
        // SAFETY: the pointer is into `ns`.
        assert_eq!(unsafe { s.pop_front().unwrap().as_ref().id }, 1);
        assert!(s.is_empty() && s.pop_front().is_none());
        assert!(!ns[1].slink.is_linked());
    }
}
