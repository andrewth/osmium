//! Task queues whose links live in the [`Task`] itself, so queueing a task
//! never allocates: a wake-up, a preemption or a block cannot run out of
//! memory.
//!
//! A linked task is kept alive by one strong reference that the queue holds
//! (see [`osmium_sync::arc`]). A task is in at most one [`TaskList`] at a time: it is either waiting in a
//! [`crate::WaitQueue`] (blocked) or in a run queue (ready), and the waker
//! takes it out of the one before putting it in the other. Run queues
//! ordered by deadline use [`TaskTree`], which has a link of its own.

use alloc::sync::Arc;
use core::cell::UnsafeCell;
use core::mem::offset_of;

use osmium_sync::arc::{ArcList, ArcTree};
use osmium_sync::intrusive::{Adapter, KeyAdapter, Link, TreeLink};

use crate::task::Task;

/// Where [`Task::link`] sits in a [`Task`].
pub(crate) struct ByLink;

// SAFETY: `offset_of!` of a `Link` field of `Task`.
unsafe impl Adapter<Link> for ByLink {
    type Value = Task;
    const OFFSET: usize = offset_of!(Task, link);
}

/// A FIFO of tasks, linked through [`Task::link`].
///
/// Not synchronized: keep it behind a lock. A task that is already linked in
/// a list cannot be pushed (the push panics): that would be a task queued
/// twice, which the scheduler's states rule out.
pub(crate) type TaskList = ArcList<ByLink>;

/// Where [`Task::tree`] sits in a [`Task`], and the key it is ordered by.
pub(crate) struct ByDeadline;

// SAFETY: `offset_of!` of a `TreeLink` field of `Task`.
unsafe impl Adapter<TreeLink> for ByDeadline {
    type Value = Task;
    const OFFSET: usize = offset_of!(Task, tree);
}

impl KeyAdapter<TreeLink> for ByDeadline {
    type Key = (u64, u64);

    fn key(task: &Task) -> &(u64, u64) {
        // SAFETY: the key is only written by `TaskTree::insert`, before the
        // task is linked, and a linked task's key is never changed.
        unsafe { &*task.edf_key.get() }
    }
}

/// Tasks ordered by `(absolute deadline, arrival)`, linked through
/// [`Task::tree`]. Not synchronized: keep it behind a lock.
pub(crate) struct TaskTree {
    tree: ArcTree<ByDeadline>,
}

impl TaskTree {
    pub(crate) const fn new() -> Self {
        Self { tree: ArcTree::new() }
    }

    pub(crate) fn len(&self) -> usize {
        self.tree.len()
    }

    /// The smallest key.
    pub(crate) fn first_key(&self) -> Option<(u64, u64)> {
        self.tree.first().map(|t| *ByDeadline::key(t))
    }

    /// Queues `task` under `key`, which must differ from every key in the tree.
    pub(crate) fn insert(&mut self, task: Arc<Task>, key: (u64, u64)) {
        // SAFETY: the task is not linked, so nothing reads its key.
        unsafe { *task.edf_key.get() = key };
        assert!(self.tree.insert(task).is_ok(), "duplicate run-queue key");
    }

    pub(crate) fn pop_first(&mut self) -> Option<Arc<Task>> {
        self.tree.pop_first()
    }

    /// Takes out the first task, in key order, for which `pred` holds.
    pub(crate) fn remove_first_where(&mut self, pred: impl FnMut(&Task) -> bool) -> Option<Arc<Task>> {
        self.tree.remove_first_where(pred)
    }
}

/// Storage for a key that `Task::edf_key` hands out by reference.
pub(crate) type EdfKey = UnsafeCell<(u64, u64)>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TaskBuilder;

    fn task() -> Arc<Task> {
        TaskBuilder::new("t").build(|| {})
    }

    #[test]
    fn a_list_holds_one_reference_per_task_and_keeps_order() {
        let (a, b, c) = (task(), task(), task());
        let mut l = TaskList::new();
        for t in [&a, &b, &c] {
            l.push_back(t.clone());
        }
        assert_eq!((l.len(), Arc::strong_count(&a)), (3, 2));
        assert!(Arc::ptr_eq(&l.pop_front().unwrap(), &a));
        assert_eq!(Arc::strong_count(&a), 1);
        // The last task for which the predicate holds, not the first.
        let b_id = b.id();
        let taken = l.remove_last_where(|t| t.id() == b_id || t.id() == c.id()).unwrap();
        assert!(Arc::ptr_eq(&taken, &c));
        assert_eq!(l.len(), 1);
        drop(taken);
        // Dropping a list with tasks in it releases them.
        drop(l);
        assert_eq!(Arc::strong_count(&b), 1);
        assert!(!b.link.is_linked());
    }

    #[test]
    fn taking_a_list_moves_every_task() {
        let (a, b) = (task(), task());
        let mut l = TaskList::new();
        l.push_back(a.clone());
        l.push_back(b.clone());
        let mut moved = l.take();
        assert!(l.is_empty());
        assert!(Arc::ptr_eq(&moved.pop_front().unwrap(), &a));
        assert!(Arc::ptr_eq(&moved.pop_front().unwrap(), &b));
        assert!(moved.pop_front().is_none());
    }

    #[test]
    #[should_panic(expected = "already linked")]
    fn a_task_cannot_be_queued_twice() {
        let a = task();
        let mut l = TaskList::new();
        l.push_back(a.clone());
        l.push_back(a);
    }

    #[test]
    fn a_tree_orders_by_key_and_releases_on_drop() {
        let (a, b, c) = (task(), task(), task());
        let mut t = TaskTree::new();
        t.insert(a.clone(), (5, 1));
        t.insert(b.clone(), (2, 2));
        t.insert(c.clone(), (2, 3));
        assert_eq!((t.len(), t.first_key()), (3, Some((2, 2))));
        let b_id = b.id();
        let skipped = t.remove_first_where(|x| x.id() != b_id).unwrap();
        assert!(Arc::ptr_eq(&skipped, &c));
        assert!(Arc::ptr_eq(&t.pop_first().unwrap(), &b));
        drop(t);
        assert_eq!(Arc::strong_count(&a), 1);
        assert!(!a.tree.is_linked());
    }
}
