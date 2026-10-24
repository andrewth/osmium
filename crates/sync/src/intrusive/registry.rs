//! A non-owning ordered index over elements that embed a [`TreeLink`].

use core::ptr::NonNull;

use super::rbtree::RbTree;
use super::{KeyAdapter, TreeLink};

/// An ordered set of entries linked through the [`TreeLink`] that `A` locates.
/// It does not own its entries, so an entry must take itself out before it is
/// freed. Not synchronized: keep it behind a lock.
pub struct Registry<A: KeyAdapter<TreeLink>>(RbTree<A>);

// SAFETY: the registry only holds pointers to entries, which are `Sync`, and
// it is only used under a lock.
unsafe impl<A: KeyAdapter<TreeLink>> Send for Registry<A> where A::Value: Sync {}

impl<A: KeyAdapter<TreeLink>> Registry<A> {
    /// An empty registry.
    pub const fn new() -> Self {
        Self(RbTree::new())
    }

    /// Adds `entry`; false (and it stays out) if the key is taken.
    ///
    /// # Safety
    /// `entry` must stay valid and in place until it is removed, and its key
    /// must not change meanwhile.
    pub unsafe fn insert(&mut self, entry: &A::Value) -> bool {
        // SAFETY: forwarded contract.
        unsafe { self.0.insert(NonNull::from(entry)) }
    }

    /// Takes `entry` out if it is in; false if it was not.
    ///
    /// # Safety
    /// If `entry` is linked, it must be linked in this registry.
    pub unsafe fn remove(&mut self, entry: &A::Value) -> bool {
        // SAFETY: forwarded contract.
        unsafe { self.0.remove(NonNull::from(entry)) }
    }

    /// Takes the entry whose key equals `key` out of the index, if there is
    /// one; returns whether there was.
    pub fn take(&mut self, key: &A::Key) -> bool {
        self.0.take(key).is_some()
    }

    /// The entry whose key equals `key`.
    pub fn find(&self, key: &A::Key) -> Option<&A::Value> {
        self.0.find(key)
    }
}

impl<A: KeyAdapter<TreeLink>> Default for Registry<A> {
    fn default() -> Self {
        Self::new()
    }
}
